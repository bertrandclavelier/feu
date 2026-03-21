// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! Archiviste d'un foyer Feu.
//!
//! L'Archiviste est instancié par [`Feu`](crate::Feu) à l'ouverture d'un foyer
//! et détruit à sa fermeture. Un Archiviste par foyer ouvert.
//!
//! Il est responsable de :
//! - la détection de la première ouverture d'un foyer
//! - la création de l'arborescence interne (`registre/`, `classeur0/` à `classeur4/`)
//! - la création des tiroirs vides et l'écriture des blobs chiffrés dans les classeurs
//!
//! # Invariant de sécurité
//!
//! L'Archiviste ne détient jamais de clés et ne voit jamais d'octets en clair.
//! Il ne connaît pas le Cryptographe. Il manipule uniquement des blobs chiffrés
//! et des hashs — la sécurité est l'affaire exclusive du Cryptographe.
//!
//! # Première ouverture
//!
//! Lors de la première ouverture d'un foyer, `registre/` est absent. L'Archiviste
//! détecte cet état et crée l'arborescence complète. Lors des ouvertures suivantes,
//! il se contente de vérifier l'existence de `registre/` et ne fait rien.
//!
//! # État incohérent
//!
//! Si `registre/` est absent mais qu'au moins un dossier `classeurN/` existe,
//! l'arborescence est dans un état incohérent — [`new`](Archiviste::new) retourne
//! une erreur.
//!
//! # Structure disque d'un foyer ouvert
//!
//! ```text
//! ~/.feu/<onion>/
//!     registre/              ← liens symboliques (v future)
//!     classeur0/
//!         <hash>.dat         ← blob chiffré
//!     classeur1/
//!     ...
//!     classeur4/
//! ```

use data_encoding::HEXLOWER;
use erreur::{ErreurArchiviste, ResultArchiviste};
use std::fs::DirBuilder;
use std::fs::OpenOptions;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use tiroir::Tiroir;

use crate::MAX_CLASSEURS;

pub(super) mod erreur;
pub(crate) mod tiroir;

/// Noms des sous-dossiers de l'arborescence d'un foyer.
const REGISTRE: &str = "registre";
const CLASSEUR: &str = "classeur";

/// Archiviste d'un foyer ouvert.
///
/// Maintient le chemin racine du foyer (`~/.feu/<onion>/`) et son index
/// dans la session. Instancié par [`Feu`](crate::Feu) à l'ouverture du foyer,
/// détruit à la fermeture.
pub(super) struct Archiviste {
    /// Chemin racine du foyer — `~/.feu/<onion>/`.
    racine: PathBuf,
    /// Index du foyer dans la session (0 à `MAX_FOYERS - 1`).
    index: usize,
}

impl Archiviste {
    /// Crée un Archiviste pour le foyer à `racine` et initialise son arborescence
    /// si nécessaire.
    ///
    /// Teste la présence de `registre/` pour déterminer s'il s'agit de la
    /// première ouverture. Si c'est le cas, crée `registre/` et les
    /// `MAX_CLASSEURS` dossiers `classeur0/` à `classeur4/` avec les
    /// permissions `rwx------` (0o700).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'arborescence est incohérente (classeurs présents
    /// sans registre), ou si une opération disque échoue.
    pub(super) fn new(racine: PathBuf, index: usize) -> ResultArchiviste<Self> {
        let archiviste = Self { racine, index };

        if archiviste.teste_arborescence_a_creer_foyer()? {
            Self::creer_dossier(&archiviste.donne_chemin_registre())?;

            for i in 0..MAX_CLASSEURS {
                Self::creer_dossier(&archiviste.donne_chemin_classeur(i))?;
            }
        }
        Ok(archiviste)
    }

    /// Crée et retourne un [`Tiroir`] vide pour le classeur à `index_classeur`.
    ///
    /// Le tiroir est un objet éphémère de transfert — il est destiné à être
    /// rempli par [`Feu`](crate::Feu) puis transmis au Cryptographe pour chiffrement,
    /// avant d'être retourné à l'Archiviste via [`ecrire_blob`](Self::ecrire_blob).
    pub(super) fn donne_tiroir_vide(&self, index_classeur: usize) -> Tiroir {
        Tiroir::new(index_classeur)
    }

    /// Charge le blob chiffré identifié par `hash` depuis le classeur et retourne
    /// un [`Tiroir`] prêt pour le déchiffrement.
    ///
    /// Ouvre `classeurN/<hash>.dat`, lit son contenu dans le tiroir et enregistre
    /// le hash. Le blob contenu est chiffré — c'est le Cryptographe qui le déchiffre.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si aucun fichier ne correspond au `hash` dans le classeur,
    /// ou si la lecture échoue.
    pub(super) fn donne_tiroir_plein(
        &self,
        index_classeur: usize,
        hash: [u8; 32],
    ) -> ResultArchiviste<Tiroir> {
        let chemin = self
            .donne_chemin_classeur(index_classeur)
            .join(format!("{}.dat", HEXLOWER.encode(&hash)));

        let fichier = std::fs::File::open(chemin)?;
        let mut tiroir = Tiroir::new(index_classeur);
        tiroir.definit_hash(hash);
        tiroir.remplir(fichier)?;

        Ok(tiroir)
    }

    /// Retourne le chemin de `registre/` dans le foyer.
    fn donne_chemin_registre(&self) -> PathBuf {
        self.racine.join(REGISTRE)
    }

    /// Retourne le chemin du dossier `classeurN/` à l'`index` donné.
    fn donne_chemin_classeur(&self, index: usize) -> PathBuf {
        self.racine.join(format!("{}{}", CLASSEUR, index))
    }

    /// Détermine si l'arborescence du foyer doit être créée.
    ///
    /// - `registre/` absent, aucun classeur présent → première ouverture → `Ok(true)`
    /// - `registre/` présent → déjà initialisé → `Ok(false)`
    /// - `registre/` absent, classeurs présents → état incohérent → `Err`
    fn teste_arborescence_a_creer_foyer(&self) -> ResultArchiviste<bool> {
        if !self.donne_chemin_registre().exists() && !self.existe_aucun_dossier_classeur() {
            return Err(ErreurArchiviste::Interne(format!(
                "Problème arborescence foyer {}",
                self.index,
            )));
        }
        if !self.donne_chemin_registre().exists() {
            return Ok(true);
        }

        Ok(false)
    }

    /// Retourne `true` si aucun dossier `classeurN/` n'existe dans le foyer.
    fn existe_aucun_dossier_classeur(&self) -> bool {
        for i in 0..MAX_CLASSEURS {
            if self.donne_chemin_classeur(i).exists() {
                return false;
            }
        }
        true
    }
}

//
// Opérations disque
//
impl Archiviste {
    /// Crée un dossier avec les permissions `rwx------` (0o700).
    ///
    /// Crée les dossiers intermédiaires si nécessaire (`recursive`).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la création échoue.
    fn creer_dossier(path: &Path) -> ResultArchiviste<()> {
        DirBuilder::new().mode(0o700).recursive(true).create(path)?;
        Ok(())
    }

    /// Écrit le blob chiffré du tiroir dans le classeur correspondant.
    ///
    /// Construit le chemin de destination à partir de l'index du classeur et du
    /// hash (encodé en hexadécimal minuscule) : `classeurN/<hash>.dat`.
    ///
    /// Le fichier est créé avec `create_new` — l'opération échoue si un blob
    /// portant ce hash existe déjà. Les permissions sont `rw-------` (0o600).
    ///
    /// # Invariant de sécurité
    ///
    /// Le tiroir doit contenir un blob **chiffré** à ce stade. L'Archiviste ne
    /// vérifie pas cet invariant — c'est la responsabilité de l'orchestrateur
    /// [`Feu`](crate::Feu).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le hash est absent du tiroir, si le fichier existe
    /// déjà, ou si une opération disque échoue.
    pub(super) fn ecrire_blob(&self, mut tiroir: Tiroir) -> ResultArchiviste<()> {
        let chemin = self
            .donne_chemin_classeur(tiroir.lire_index_classeur())
            .join(format!("{}.dat", HEXLOWER.encode(&tiroir.lire_hash()?)));

        let fichier = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&chemin)?;

        tiroir.vider(fichier)?;

        Ok(())
    }
}
