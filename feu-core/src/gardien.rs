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
//! globale du nœud via [`Configuration`] — miroir du fichier `config.feu` sur
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

use super::cryptographe::trousseau_public::TrousseauPublic;
use crate::MAX_FOYERS;
use crate::cryptographe::flux_chiffre::Finalise;
use carnet::Carnet;
use erreur::{ErreurGardien, ResultGardien};
use std::fs::File;
use std::io::Write;

const VERSION_CONFIGURATION: u32 = 1;

/// Configuration globale du nœud — miroir de `config.feu` en mémoire.
///
/// Contient la version du format de fichier, le prochain index de dérivation
/// BIP32, et les adresses `.onion` des `MAX_FOYERS` foyers du nœud.
struct Configuration {
    /// Version du format de `config.feu` — incrémentée à chaque changement
    /// de structure incompatible.
    version: u32,
    /// Prochain index de dérivation BIP32 à attribuer au prochain foyer créé.
    prochain_index: u32,
    /// Adresses `.onion` des foyers — tableau de taille fixe `MAX_FOYERS`.
    adresses_onion: [String; MAX_FOYERS],
}

impl Configuration {
    fn new() -> Self {
        Self {
            version: VERSION_CONFIGURATION,
            prochain_index: 1,
            adresses_onion: std::array::from_fn(|_| String::from("")),
        }
    }

    /// Reconstruit la configuration depuis le contenu textuel de `config.feu`.
    ///
    /// Attend exactement `2 + MAX_FOYERS` lignes : version, prochain_index,
    /// puis une adresse `.onion` par foyer.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `version` ou `prochain_index` ne sont pas des
    /// entiers valides. Panique si le fichier contient moins de lignes qu'attendu.
    fn new_from_string(contenu: &str) -> ResultGardien<Self> {
        let mut lignes: Vec<&str> = contenu.lines().collect();
        let version = lignes.remove(0).parse::<u32>()?;
        let prochain_index = lignes.remove(0).parse::<u32>()?;

        let mut tableau: [String; MAX_FOYERS] = std::array::from_fn(|_| String::from(""));
        for i in 0..MAX_FOYERS {
            tableau[i] = String::from(lignes.remove(0));
        }

        Ok(Self {
            version,
            prochain_index,
            adresses_onion: tableau,
        })
    }

    /// Sérialise la configuration en texte pour écriture dans `config.feu`.
    ///
    /// Format : version, prochain_index, puis chaque adresse `.onion`,
    /// chaque champ séparé par `\n`.
    fn exporte_en_texte(&self) -> String {
        let mut resultat = format!("{}\n{}\n", self.version, self.prochain_index);
        for e in &self.adresses_onion {
            resultat.push_str(e);
            resultat.push_str("\n");
        }
        resultat
    }
}

/// Gardien des données locales du nœud Feu.
///
/// Orchestre les opérations sur le système de fichiers via son [`Carnet`]
/// et maintient en mémoire la configuration globale via [`Configuration`].
/// Aucun autre composant n'accède directement au disque.
pub(crate) struct Gardien {
    carnet: Carnet,
    configuration: Configuration,
}

impl Gardien {
    /// Crée le gardien de [`Feu`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le carnet ne peut pas être initialisé —
    /// notamment si la variable d'environnement `HOME` est absente.
    pub(super) fn new() -> ResultGardien<Self> {
        Ok(Self {
            carnet: Carnet::new()?,
            configuration: Configuration::new(),
        })
    }

    /// Ouvre un nœud Feu existant en chargeant sa configuration depuis `config.feu`.
    ///
    /// Crée le carnet à partir de `HOME`, vérifie que l'arborescence `~/.feu`
    /// existe, lit `config.feu` sur le disque et reconstruit la [`Configuration`] en mémoire.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `HOME` est absente, si l'arborescence `~/.feu`
    /// est introuvable, si `config.feu` est absent ou illisible, ou si son
    /// contenu ne peut pas être parsé.
    pub(super) fn ouvre_nouveau() -> ResultGardien<Self> {
        let carnet = Carnet::new()?;
        if !carnet.existe_arborescence_noeud() {
            return Err(ErreurGardien::Interne(String::from(
                "Aucune arborescence du nœud trouvée",
            )));
        }
        Ok(Self {
            configuration: Configuration::new_from_string(&carnet.ouvre_configuration()?)?,
            carnet,
        })
    }
}

// ── Opérations disque ────────────────────────────────────────────────────────

impl Gardien {
    pub(super) fn existance_arborescence(&self) -> bool {
        self.carnet.existe_arborescence_noeud()
    }
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
        match self.carnet.existe_arborescence_noeud() {
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

    /// Orchestre la persistance de `config.feu` sur le disque.
    ///
    /// Exporte la configuration en mémoire via [`Configuration::exporte_en_texte`]
    /// puis délègue l'écriture à [`Carnet::enregistre_configuration`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'écriture échoue.
    pub(super) fn enregistrement_configuration(&self) -> ResultGardien<()> {
        // Écriture sur le disque
        self.carnet
            .enregistre_configuration(self.configuration.exporte_en_texte())?;

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

    /// Lit les clés du nœud sur le disque et construit un [`TrousseauPublic`] partiel.
    ///
    /// Lit le sel, la clé privée et la clé publique de signature du nœud.
    /// Les foyers sont à ajouter séparément via [`TrousseauPublic::ajoute_trousseau_foyer_public`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si un fichier est absent, illisible ou de taille incorrecte.
    pub(super) fn lecture_pour_creation_trousseau_public(&self) -> ResultGardien<TrousseauPublic> {
        Ok(TrousseauPublic::new(
            self.carnet.lire_pour_donner_sel()?,
            self.carnet.lire_pour_donner_cle_sig_privee()?,
            self.carnet.lire_pour_donner_cle_sig_pub()?,
        ))
    }
}
// ── Opérations mémoire ───────────────────────────────────────────────────────

impl Gardien {
    /// Enregistre l'adresse `.onion` d'un foyer dans la [`Configuration`] en mémoire.
    ///
    /// Écrit l'adresse fournie par le cryptographe à la position `position`
    /// dans le tableau `adresses_onion`.
    ///
    /// Cette méthode n'écrit rien sur le disque — appeler ensuite
    /// [`Gardien::enregistrement_configuration`] pour persister l'état.
    pub(super) fn ajout_nouveau_foyer_dans_configuration(
        &mut self,
        onion: String,
        position: usize,
    ) {
        self.configuration.adresses_onion[position] = onion;
        self.configuration.prochain_index += 1;
    }
}
