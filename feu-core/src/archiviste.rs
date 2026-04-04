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
//! # Structure disque d'un foyer ouvert
//!
//! ```text
//! ~/.feu/<onion>/
//!     registre/
//!         classeur.0  → ../  ← lien symbolique vers la racine du foyer
//!         classeur.1  → ../
//!         ...
//!         classeur.4  → ../
//!     classeur0/
//!         <hash>.dat         ← blob chiffré
//!     classeur1/
//!     ...
//!     classeur4/
//! ```

use erreur::{ErreurArchiviste, ResultArchiviste};
use std::fs;
use std::fs::DirBuilder;
use std::fs::OpenOptions;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use tiroir::Tiroir;

use crate::Anomalie;
use crate::DonneesBlob;
use crate::MAX_CLASSEURS;

const ERR_ARC_001: &str = "Le fichier n'existe pas";

pub(super) mod erreur;
pub(crate) mod tiroir;

/// Noms des sous-dossiers de l'arborescence d'un foyer.
const REGISTRE: &str = "registre";
const CLASSEUR: &str = "classeur";

/// Archiviste d'un foyer ouvert.
///
/// Maintient le chemin racine du foyer (`~/.feu/<onion>/`). Instancié par
/// [`Feu`](crate::Feu) à l'ouverture du foyer, détruit à la fermeture.
pub(super) struct Archiviste {
    /// Chemin racine du foyer — `~/.feu/<onion>/`.
    racine: PathBuf,
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
    /// Retourne une erreur si une opération disque échoue.
    pub(super) fn new(racine: PathBuf) -> ResultArchiviste<Self> {
        let archiviste = Self { racine };

        if !&archiviste.donne_chemin_registre().exists() {
            Self::cree_dossier(&archiviste.donne_chemin_registre())?;

            for i in 0..MAX_CLASSEURS {
                std::os::unix::fs::symlink("../", archiviste.donne_chemin_lien_classeur(i))?;
                Self::cree_dossier(archiviste.donne_chemin_classeur(i).as_ref())?;
            }
        }
        Ok(archiviste)
    }

    // ── Tiroirs ───────────────────────────────────────────────────────────────

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
        hash: &str,
    ) -> ResultArchiviste<Tiroir> {
        let chemin = self.donne_chemin_blob(index_classeur, hash);

        let fichier = std::fs::File::open(chemin)?;
        let mut tiroir = Tiroir::new(index_classeur);
        tiroir.definit_hash(hash);
        tiroir.remplir(fichier)?;

        Ok(tiroir)
    }

    // ── Blobs ─────────────────────────────────────────────────────────────────

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
    pub(super) fn ecrit_blob(&self, mut tiroir: Tiroir) -> ResultArchiviste<()> {
        let chemin = self.donne_chemin_blob(tiroir.lire_index_classeur(), &tiroir.lire_hash()?);

        let fichier = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&chemin)?;

        tiroir.vider(fichier)?;

        Ok(())
    }

    /// Supprime le blob identifié par `hash` dans le classeur à `index_classeur`.
    ///
    /// Vérifie l'existence de `classeurN/<hash>.dat` avant suppression.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier n'existe pas ou si la suppression échoue.
    pub(super) fn supprime_blob(&self, index_classeur: usize, hash: &str) -> ResultArchiviste<()> {
        let chemin = self.donne_chemin_blob(index_classeur, hash);
        if !chemin.exists() {
            return Err(ErreurArchiviste::Interne(String::from(ERR_ARC_001)));
        }
        Ok(std::fs::remove_file(chemin)?)
    }

    /// Indique si un blob identifié par `hash` est présent dans le classeur à `index_classeur`.
    ///
    /// Retourne `true` si `classeurN/<hash>.dat` existe sur le disque, `false` sinon.
    pub(super) fn existe_blob(&self, index_classeur: usize, hash: &str) -> bool {
        self.donne_chemin_blob(index_classeur, hash).exists()
    }

    /// Retourne la liste des hashes de tous les blobs présents dans le classeur à `index_classeur`.
    ///
    /// Parcourt le dossier `classeurN/` et collecte le nom de chaque fichier `.dat`
    /// sans son extension — c'est-à-dire le hash SHA3-256 en hexadécimal minuscule.
    ///
    /// L'ordre des entrées n'est pas garanti — il dépend du système de fichiers.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la lecture du dossier échoue.
    pub(super) fn donne_liste_blobs(&self, index_classeur: usize) -> ResultArchiviste<Vec<String>> {
        let mut liste = Vec::new();
        for element in std::fs::read_dir(self.donne_chemin_classeur(index_classeur))? {
            if let Some(nom) = element?.path().file_stem() {
                liste.push(nom.to_string_lossy().to_string());
            }
        }
        Ok(liste)
    }

    /// Retourne les métadonnées système du blob identifié par `hash` dans le classeur à `index_classeur`.
    ///
    /// Interroge l'OS via [`std::fs::metadata`] — aucun déchiffrement n'est effectué.
    /// `date_creation` est `None` si le système de fichiers ne la supporte pas.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier n'existe pas ou si la lecture des métadonnées échoue.
    pub(super) fn donne_informations_blob(
        &self,
        index_classeur: usize,
        hash: &str,
    ) -> ResultArchiviste<DonneesBlob> {
        let metadata = std::fs::metadata(self.donne_chemin_blob(index_classeur, hash))?;
        let created = metadata.created().ok();

        Ok(DonneesBlob::new(
            metadata.len(),
            created,
            metadata.modified()?,
            metadata.accessed()?,
        ))
    }

    // ── Check-up ──────────────────────────────────────────────────────────────

    pub(super) fn verifier_arborescence_classeurs(&self) -> ResultArchiviste<Vec<Anomalie>> {
        let mut resultat: Vec<Anomalie> = Vec::new();

        if !self.donne_chemin_registre().exists() {
            resultat.push(Anomalie::ElementAbsent(self.donne_chemin_registre()));
        }

        // Pour chaque classeur
        for j in 0..MAX_CLASSEURS {
            if !self.donne_chemin_lien_classeur(j).is_symlink() {
                resultat.push(Anomalie::ElementAbsent(self.donne_chemin_lien_classeur(j)));
            } else if !self.donne_chemin_lien_classeur(j).exists() {
                let chemin_cible = fs::read_link(self.donne_chemin_lien_classeur(j))?;
                resultat.push(Anomalie::ElementAbsent(chemin_cible));
            }
        }
        Ok(resultat)
    }

    // ── Utilitaires privés ────────────────────────────────────────────────────

    fn donne_chemin_registre(&self) -> PathBuf {
        self.racine.join(REGISTRE)
    }

    /// Retourne le chemin du lien symbolique `registre/classeur.N` pour le classeur à `index_classeur`.
    ///
    /// Ce lien est le point d'entrée canonique pour accéder au classeur — il permet
    /// de rediriger les classeurs vers des emplacements arbitraires sans modifier le code.
    fn donne_chemin_lien_classeur(&self, index_classeur: usize) -> PathBuf {
        self.donne_chemin_registre()
            .join(format!("{}.{}", CLASSEUR, index_classeur))
    }

    /// Retourne le chemin du dossier `classeurN/` à l'`index` donné.
    fn donne_chemin_classeur(&self, index_classeur: usize) -> PathBuf {
        self.donne_chemin_lien_classeur(index_classeur)
            .join(format!("{}{}", CLASSEUR, index_classeur))
    }

    /// Retourne le chemin complet du blob `<hash>.dat` dans le classeur à `index_classeur`.
    fn donne_chemin_blob(&self, index_classeur: usize, hash: &str) -> PathBuf {
        self.donne_chemin_classeur(index_classeur)
            .join(format!("{}.dat", hash))
    }

    /// Crée un dossier avec les permissions `rwx------` (0o700).
    ///
    /// Crée les dossiers intermédiaires si nécessaire (`recursive`).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la création échoue.
    fn cree_dossier(path: &Path) -> ResultArchiviste<()> {
        DirBuilder::new().mode(0o700).recursive(true).create(path)?;
        Ok(())
    }
}
