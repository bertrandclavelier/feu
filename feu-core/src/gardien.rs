// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! Le gardien est l'unique point d'accès au système de fichiers pour les
//! données locales de l'instance Feu — configuration globale, dossiers des
//! foyers, coffres et clés.
//!
//! Il délègue la connaissance de l'arborescence à son [`Carnet`] et
//! orchestre les opérations sur le système de fichiers sans les exposer
//! à l'extérieur du module. Il maintient en mémoire la configuration
//! globale du nœud via [`FeuToml`] — miroir du fichier `feu.toml` sur
//! disque, écrit en dernière étape de chaque opération structurante.
//! Cette centralisation est un invariant de sécurité et de cohérence
//! du protocole.
//!
//! # Convention de nommage
//!
//! Les méthodes suivent une convention grammaticale liée au niveau d'exécution :
//!
//! - **Nom** (`enregistrement_`, `ajout_`…) — méthode d'orchestration : prépare
//!   et délègue à un outil de niveau inférieur.
//! - **Verbe** (`cree_`, `ecrire_`, `ajoute_`…) — méthode d'exécution directe :
//!   réalise elle-même l'opération sans déléguer.

mod carnet;
pub(crate) mod erreur;
mod feu_toml;

use super::cryptographe::trousseau_public::TrousseauPublic;
use crate::cryptographe::flux_chiffre::Finalise;
use carnet::Carnet;
use erreur::{ErreurGardien, ResultGardien};
use feu_toml::FeuToml;
use std::fs::File;
use std::io::Write;

/// Gardien des données locales du nœud Feu.
///
/// Orchestre les opérations sur le système de fichiers via son [`Carnet`]
/// et maintient en mémoire la configuration globale via [`FeuToml`].
/// Aucun autre composant n'accède directement au disque.
pub(crate) struct Gardien {
    carnet: Carnet,
    feu_toml: FeuToml,
}

impl Gardien {
    /// Crée le gardien de [`Feu`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le carnet ne peut pas être initialisé —
    /// notamment si la variable d'environnement `HOME` est absente.
    pub(super) fn new() -> ResultGardien<Self> {
        Ok(Gardien {
            carnet: Carnet::new()?,
            feu_toml: FeuToml::new(),
        })
    }
}

// ── Opérations disque ────────────────────────────────────────────────────────

impl Gardien {
    /// Ancre le nœud vierge sur le disque à partir du trousseau public.
    ///
    /// Délègue à [`Carnet::ecrire_trousseau_public`] la création de l'arborescence
    /// complète et l'écriture de toutes les clés chiffrées. Cette opération
    /// n'est valide que pour un nœud vierge — elle échoue si `~/.feu` existe déjà.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'arborescence existe déjà, ou si une
    /// opération disque échoue.
    pub(super) fn cree_premiere_arborescence(
        &self,
        trousseau_public: &TrousseauPublic,
    ) -> ResultGardien<()> {
        match self.carnet.existe() {
            true => Err(ErreurGardien::Interne(String::from(
                "Une arborescence existe déjà.",
            ))),
            false => {
                // Écriture du trousseau public sur le disque
                self.carnet.ecrire_trousseau_public(&trousseau_public)?;

                Ok(())
            }
        }
    }

    /// Orchestre la persistance de `feu.toml` sur le disque.
    ///
    /// Sérialise la configuration en mémoire via [`FeuToml::toml_en_texte`]
    /// puis délègue l'écriture à [`Carnet::enregistre_feu_toml`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la sérialisation ou l'écriture échoue.
    pub(super) fn enregistrement_feu_toml(&self) -> ResultGardien<()> {
        // Récupération du fichier toml en texte
        let texte = self.feu_toml.toml_en_texte()?;

        // Écriture sur le disque
        self.carnet.enregistre_feu_toml(texte)?;

        Ok(())
    }

    /// Ouvre le fichier de destination `<onion>.feu` en écriture exclusive.
    ///
    /// Délègue au carnet la création du fichier avec les permissions `rw-------` (0o600).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier existe déjà ou si la création échoue.
    pub(super) fn ouverture_fichier_ecriture(&self, onion: &str) -> ResultGardien<File> {
        Ok(self.carnet.ouvre_fichier_ecriture(onion)?)
    }

    /// Archive et chiffre le dossier `<onion>` dans un flux AES-256-GCM-stream.
    ///
    /// Construit une archive tar du dossier `<onion>` en écrivant directement
    /// dans `ecrivain` — un flux chiffré `Write + Finalise`. Les fichiers sont
    /// archivés à la racine (`.`) sans chemin parent.
    /// `finalise()` est appelé après le dernier chunk pour clore le stream AES-GCM.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le dossier `<onion>` est absent, si l'archivage
    /// tar échoue, ou si la finalisation du flux chiffré échoue.
    pub(super) fn creation_archive_chiffree<T: Write + Finalise>(
        &self,
        onion: &str,
        ecrivain: T,
    ) -> ResultGardien<()> {
        if self.carnet.donne_chemin_onion(onion).exists() {
            let mut builder = tar::Builder::new(ecrivain);

            builder.append_dir_all(".", self.carnet.donne_chemin_onion(onion))?;
            let ecrivain = builder.into_inner()?;
            ecrivain.finalise().map_err(|e| ErreurGardien::Interne(e))?;
            Ok(())
        } else {
            return Err(ErreurGardien::Interne(String::from(
                "Impossible de trouver le dossier `onion` correspondant.",
            )));
        }
    }

    /// Supprime le dossier clair `<onion>` après vérification que l'archive existe.
    ///
    /// Contrôle l'existence de `<onion>.feu` avant toute suppression —
    /// garantit qu'on ne supprime pas un dossier non archivé.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'archive `<onion>.feu` est absente
    /// ou si la suppression récursive du dossier échoue.
    pub(super) fn suppression_dossier_onion(&self, onion: &str) -> ResultGardien<()> {
        // Vérification que l'archive existe avant de supprimer le dossier. Sinon impossible
        if self.carnet.donne_chemin_archive(onion).exists() {
            self.carnet.supprime_dossier_onion(onion)?;
            Ok(())
        } else {
            return Err(ErreurGardien::Interne(String::from(
                "Le gardien ne supprimera pas le dossier s'il n'est pas archivé.",
            )));
        }
    }
}
// ── Opérations mémoire ───────────────────────────────────────────────────────

impl Gardien {
    /// Enregistre un nouveau foyer dans la configuration `feu.toml` en mémoire.
    ///
    /// Délègue à [`FeuToml`] l'ajout de l'entrée foyer avec l'adresse `.onion`
    /// fournie par le cryptographe. L'index de dérivation et l'horodatage
    /// sont gérés par [`FeuToml`].
    ///
    /// Cette méthode n'écrit rien sur le disque — appeler ensuite
    /// [`Gardien::enregistrement_feu_toml`] pour persister l'état.
    pub(super) fn ajout_nouveau_foyer_dans_feu_toml(&mut self, onion: String) {
        self.feu_toml.ajoute_nouveau_foyer_dans_feu_toml(onion);
    }
}
