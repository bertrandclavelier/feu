// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Archiviste d'un foyer FeuNoyau.
//!
//! L'Archiviste est instancié par [`FeuNoyau`](crate::FeuNoyau) à l'ouverture d'un foyer
//! et détruit à sa fermeture. Un Archiviste par foyer ouvert.
//!
//! Il est responsable de :
//! - la détection de la première ouverture d'un foyer
//! - la création de l'arborescence interne (`registre/`, `classeur0/` à `classeur4/`)
//! - la création des tiroirs vides et l'écriture des blobs chiffrés dans les classeurs
//!
//! # Invariants de sécurité
//!
//! L'Archiviste ne détient jamais de clés et ne voit jamais d'octets en clair.
//! Il ne connaît pas le Cryptographe. Il manipule uniquement des blobs chiffrés
//! et des hashs — la sécurité est l'affaire exclusive du Cryptographe.
//!
//! # Errors
//!
//! Tout échec du système de fichiers remonte tel quel en
//! [`ErreurFeuNoyau::IoError`] par `?` — c'est ce que désignent les sections
//! `# Errors` qui parlent d'une opération disque. Les variantes `Archiviste*`
//! et [`ErreurFeuNoyau::CheminInexistant`] sont réservées aux anomalies que
//! l'Archiviste constate lui-même, avant de toucher au disque.
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
//! ~/.feu/<braise>/
//!     registre/
//!         classeur.0  → ../  ← lien symbolique vers la racine du foyer
//!         classeur.1  → ../
//!         ...
//!         classeur.4  → ../
//!     classeur0/
//!         <hash>.blob        ← blob chiffré
//!     classeur1/
//!     ...
//!     classeur4/
//! ```

pub(crate) mod tiroir;

use std::{
    fs,
    fs::{DirBuilder, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use data_encoding::HEXLOWER;

use crate::{
    Anomalie, DonneesBlob, ErreurFeuNoyau, IndexClasseur, ResultFeuNoyau,
    archiviste::tiroir::Tiroir,
};

/// Sous-dossier du foyer qui tient le registre des blobs.
const REGISTRE: &str = "registre";

/// Préfixe des sous-dossiers de classeur — `classeur0` à `classeur<MAX-1>`, et
/// `classeur.<index>` dans le registre.
const CLASSEUR: &str = "classeur";

/// Archiviste d'un foyer ouvert.
///
/// Maintient le chemin racine du foyer (`~/.feu/<braise>/`). Instancié par
/// [`FeuNoyau`](crate::FeuNoyau) à l'ouverture du foyer, détruit à la fermeture.
pub(super) struct Archiviste {
    /// Chemin racine du foyer — `~/.feu/<braise>/`.
    racine: PathBuf,
}

impl Archiviste {
    /// Crée un Archiviste pour le foyer à `racine` et initialise son arborescence
    /// si nécessaire.
    ///
    /// Teste la présence de `registre/` pour déterminer s'il s'agit de la
    /// première ouverture. Si c'est le cas, crée `registre/` et les dossiers
    /// `classeur0/` à `classeur4/` avec les permissions `rwx------` (0o700).
    ///
    /// # Errors
    ///
    /// Retourne une erreur si une opération disque échoue.
    pub(super) fn new(racine: PathBuf) -> ResultFeuNoyau<Self> {
        let archiviste = Self { racine };

        if !&archiviste.donne_chemin_registre().exists() {
            Self::creer_dossier_700(&archiviste.donne_chemin_registre())?;

            for index_classeur in IndexClasseur::tous() {
                std::os::unix::fs::symlink(
                    "../",
                    archiviste.donne_chemin_lien_classeur(index_classeur),
                )?;
                Self::creer_dossier_700(&archiviste.donne_chemin_classeur(index_classeur))?;
            }
        }
        Ok(archiviste)
    }

    // ── Tiroirs ───────────────────────────────────────────────────────────────

    /// Crée et retourne un [`Tiroir`] vide.
    ///
    /// Le tiroir est un objet éphémère de transfert — il est destiné à être
    /// rempli par [`FeuNoyau`](crate::FeuNoyau) puis transmis au Cryptographe pour chiffrement,
    /// avant d'être retourné à l'Archiviste via [`ecrit_blob`](Self::ecrit_blob).
    pub(super) fn donne_tiroir_vide() -> Tiroir {
        Tiroir::new()
    }

    /// Charge le blob chiffré identifié par `hash` depuis le classeur et retourne
    /// un [`Tiroir`] prêt pour le déchiffrement.
    ///
    /// Ouvre `classeurN/<hash>.blob` et lit son contenu dans le tiroir. Le blob
    /// contenu est chiffré — c'est le Cryptographe qui le déchiffre.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si aucun fichier ne correspond au `hash` dans le classeur,
    /// ou si la lecture échoue.
    pub(super) fn donne_tiroir_plein(
        &self,
        index_classeur: IndexClasseur,
        hash: &[u8; 32],
    ) -> ResultFeuNoyau<Tiroir> {
        let chemin = self.donne_chemin_blob(index_classeur, hash);

        let fichier = std::fs::File::open(chemin)?;
        let mut tiroir = Tiroir::new();
        tiroir.remplir(fichier)?;

        Ok(tiroir)
    }

    // ── Blobs ─────────────────────────────────────────────────────────────────

    /// Écrit le blob chiffré du tiroir dans le classeur `index_classeur`.
    ///
    /// Construit le chemin de destination à partir de l'index du classeur et du
    /// `hash` (encodé en hexadécimal minuscule) : `classeurN/<hash>.blob`. Le
    /// tiroir ne portant que le contenu, les deux lui sont fournis ici.
    ///
    /// Le fichier est créé avec `create_new` — l'opération échoue si un blob
    /// portant ce hash existe déjà. Les permissions sont `rw-------` (0o600).
    ///
    /// # Invariants de sécurité
    ///
    /// Le tiroir doit contenir un blob **chiffré** à ce stade. L'Archiviste ne
    /// vérifie pas cet invariant — c'est la responsabilité de l'orchestrateur
    /// [`FeuNoyau`](crate::FeuNoyau).
    ///
    /// # Errors
    ///
    /// Propage l'échec de l'écriture — le fichier déjà présent compris, la
    /// création étant exclusive.
    pub(super) fn ecrit_blob(
        &self,
        index_classeur: IndexClasseur,
        hash: &[u8; 32],
        mut tiroir: Tiroir,
    ) -> ResultFeuNoyau<()> {
        let chemin = self.donne_chemin_blob(index_classeur, hash);

        let fichier = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&chemin)?;

        tiroir.envoyer_et_vider(fichier)?;

        Ok(())
    }

    /// Supprime le blob identifié par `hash` dans le classeur à `index_classeur`.
    ///
    /// Vérifie l'existence de `classeurN/<hash>.blob` avant suppression.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuNoyau::CheminInexistant`] si le blob est absent du
    /// classeur, ou propage l'échec de la suppression.
    pub(super) fn supprime_blob(
        &self,
        index_classeur: IndexClasseur,
        hash: &[u8; 32],
    ) -> ResultFeuNoyau<()> {
        let chemin = self.donne_chemin_blob(index_classeur, hash);
        if !chemin.exists() {
            return Err(ErreurFeuNoyau::CheminInexistant(chemin));
        }
        Ok(std::fs::remove_file(chemin)?)
    }

    /// Indique si un blob identifié par `hash` est présent dans le classeur à `index_classeur`.
    ///
    /// Retourne `true` si `classeurN/<hash>.blob` existe sur le disque, `false` sinon.
    pub(super) fn existe_blob(&self, index_classeur: IndexClasseur, hash: &[u8; 32]) -> bool {
        self.donne_chemin_blob(index_classeur, hash).exists()
    }

    /// Retourne la liste des hashes de tous les blobs présents dans le classeur à `index_classeur`.
    ///
    /// Parcourt le dossier `classeurN/` et décode le nom de chaque fichier, qui
    /// porte le hash SHA3-256 du clair en hexadécimal minuscule. Une entrée dont
    /// le nom ne redonne pas 32 octets n'est pas un blob et n'est pas listée.
    ///
    /// L'ordre des entrées n'est pas garanti — il dépend du système de fichiers.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si la lecture du dossier échoue.
    pub(super) fn donne_liste_blobs(
        &self,
        index_classeur: IndexClasseur,
    ) -> ResultFeuNoyau<Vec<[u8; 32]>> {
        let mut liste = Vec::new();
        for element in std::fs::read_dir(self.donne_chemin_classeur(index_classeur))? {
            if let Some(nom) = element?.path().file_stem()
                && let Ok(octets) = HEXLOWER.decode(nom.as_encoded_bytes())
                && let Ok(hash) = <[u8; 32]>::try_from(octets)
            {
                liste.push(hash);
            }
        }
        Ok(liste)
    }

    /// Retourne les métadonnées système du blob identifié par `hash` dans le classeur à `index_classeur`.
    ///
    /// Interroge l'OS via [`std::fs::metadata`] — aucun déchiffrement n'est effectué.
    /// `date_creation` est `None` si le système de fichiers ne la supporte pas.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si le fichier n'existe pas ou si la lecture des métadonnées échoue.
    pub(super) fn donne_informations_blob(
        &self,
        index_classeur: IndexClasseur,
        hash: &[u8; 32],
    ) -> ResultFeuNoyau<DonneesBlob> {
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

    /// Vérifie la présence des éléments structurels du foyer ouvert.
    ///
    /// Contrôle `registre/` et les liens symboliques `registre/classeur.N`,
    /// ainsi que l'existence des cibles de ces liens.
    /// N'inspecte pas le contenu des classeurs — seule la structure est vérifiée.
    ///
    /// # Errors
    ///
    /// Propage l'échec de lecture d'un lien symbolique — un lien présent mais
    /// illisible n'est pas une anomalie de structure mais une panne d'accès.
    pub(super) fn verifier_arborescence_classeurs(&self) -> ResultFeuNoyau<Vec<Anomalie>> {
        let mut resultat: Vec<Anomalie> = Vec::new();

        if !self.donne_chemin_registre().exists() {
            resultat.push(Anomalie::ElementAbsent(self.donne_chemin_registre()));
        }

        for index_classeur in IndexClasseur::tous() {
            if !self.donne_chemin_lien_classeur(index_classeur).is_symlink() {
                resultat.push(Anomalie::ElementAbsent(
                    self.donne_chemin_lien_classeur(index_classeur),
                ));
            } else if !self.donne_chemin_lien_classeur(index_classeur).exists() {
                let chemin_cible = fs::read_link(self.donne_chemin_lien_classeur(index_classeur))?;
                resultat.push(Anomalie::ElementAbsent(chemin_cible));
            }
        }
        Ok(resultat)
    }

    // ── Utilitaires privés ────────────────────────────────────────────────────

    /// Retourne le chemin du dossier `registre/` du foyer.
    fn donne_chemin_registre(&self) -> PathBuf {
        self.racine.join(REGISTRE)
    }

    /// Retourne le chemin du lien symbolique `registre/classeur.N` pour le classeur à `index_classeur`.
    ///
    /// Ce lien est le point d'entrée canonique pour accéder au classeur — il permet
    /// de rediriger les classeurs vers des emplacements arbitraires sans modifier le code.
    fn donne_chemin_lien_classeur(&self, index_classeur: IndexClasseur) -> PathBuf {
        self.donne_chemin_registre()
            .join(format!("{}.{}", CLASSEUR, index_classeur.valeur()))
    }

    /// Retourne le chemin du dossier `classeurN/` du classeur `index_classeur`.
    fn donne_chemin_classeur(&self, index_classeur: IndexClasseur) -> PathBuf {
        self.donne_chemin_lien_classeur(index_classeur)
            .join(format!("{}{}", CLASSEUR, index_classeur.valeur()))
    }

    /// Retourne le chemin complet du blob `<hash>.blob` dans le classeur à `index_classeur`.
    ///
    /// Seul endroit où un hash prend sa forme hexadécimale : elle ne sert qu'à
    /// nommer le fichier, et ne remonte pas dans les signatures.
    fn donne_chemin_blob(&self, index_classeur: IndexClasseur, hash: &[u8; 32]) -> PathBuf {
        self.donne_chemin_classeur(index_classeur)
            .join(format!("{}.blob", HEXLOWER.encode(hash)))
    }

    /// Crée un dossier avec les permissions `rwx------` (0o700).
    ///
    /// Crée les dossiers intermédiaires si nécessaire (`recursive`).
    ///
    /// # Errors
    ///
    /// Retourne une erreur si la création échoue.
    fn creer_dossier_700(path: &Path) -> ResultFeuNoyau<()> {
        DirBuilder::new().mode(0o700).recursive(true).create(path)?;
        Ok(())
    }
}

/// Tests en ligne : le cycle complet d'un blob dans un classeur, de l'écriture
/// à la suppression, sur une arborescence réelle.
#[cfg(test)]
mod tests {
    use std::fs::File;

    use proptest::{prelude::any, prop_assert, prop_assert_eq, prop_assume, proptest};
    use tempfile::TempDir;

    use super::*;
    use crate::TAILLE_CHUNK;

    proptest! {
        /// Deux blobs écrits dans le même classeur s'y retrouvent, s'y relisent
        /// à l'identique et s'en effacent sans laisser de trace.
        ///
        /// Deux plutôt qu'un : l'unicité d'un nom, la liste qui les rend tous les
        /// deux et l'effacement de l'un sans l'autre ne se disent pas sur un blob
        /// seul. Les tailles vont jusqu'à trois fois `TAILLE_CHUNK`, pour que le
        /// découpage du [`Tiroir`] serve réellement.
        #[test]
        fn cycle_blobs(
            source1 in proptest::collection::vec(any::<u8>(), 0..=TAILLE_CHUNK * 3),
            source2 in proptest::collection::vec(any::<u8>(), 0..=TAILLE_CHUNK * 3),
            hash1 in any::<[u8; 32]>(),
            hash2 in any::<[u8; 32]>(),
        ) {
            // Deux hashs égaux feraient échouer le second `ecrit_blob`, qui crée
            // le fichier en exclusif. Le tirage ne les produit jamais, le
            // rétrécissement d'un échec, si.
            prop_assume!(hash1 != hash2);

            let tmp = TempDir::new()?;

            let archiviste = Archiviste::new(tmp.path().to_path_buf())?;

            prop_assert!(archiviste.verifier_arborescence_classeurs()?.is_empty());

            // Le chemin est écrit en dur, indirection du registre comprise :
            // c'est un format sur disque, et le recomposer depuis les constantes
            // du module ferait un test qui compare le code à lui-même.
            prop_assert_eq!(
                archiviste.donne_chemin_blob(IndexClasseur::ZERO, &hash1),
                tmp.path()
                    .join("registre")
                    .join("classeur.0")
                    .join("classeur0")
                    .join(format!("{}.blob", HEXLOWER.encode(&hash1)))
            );

            let mut tiroir = Tiroir::new();
            tiroir.remplir(source1.as_slice())?;
            archiviste.ecrit_blob(IndexClasseur::ZERO, &hash1, tiroir)?;

            prop_assert!(archiviste.existe_blob(IndexClasseur::ZERO, &hash1));

            let mut tiroir = Tiroir::new();
            tiroir.remplir(source2.as_slice())?;
            archiviste.ecrit_blob(IndexClasseur::ZERO, &hash2, tiroir)?;

            prop_assert!(archiviste.existe_blob(IndexClasseur::ZERO, &hash2));

            let liste_blobs = archiviste.donne_liste_blobs(IndexClasseur::ZERO)?;
            prop_assert_eq!(liste_blobs.len(), 2);
            prop_assert!(liste_blobs.contains(&hash1));
            prop_assert!(liste_blobs.contains(&hash2));

            let fichier1 = File::open(archiviste.donne_chemin_blob(IndexClasseur::ZERO, &hash1))?;
            let mut tiroir = Tiroir::new();
            tiroir.remplir(fichier1)?;
            let mut destination1 = Vec::new();
            tiroir.envoyer_et_vider(&mut destination1)?;

            prop_assert_eq!(source1, destination1);

            let fichier2 = File::open(archiviste.donne_chemin_blob(IndexClasseur::ZERO, &hash2))?;
            let mut tiroir = Tiroir::new();
            tiroir.remplir(fichier2)?;
            let mut destination2 = Vec::new();
            tiroir.envoyer_et_vider(&mut destination2)?;

            prop_assert_eq!(source2, destination2);

            archiviste.supprime_blob(IndexClasseur::ZERO, &hash1)?;
            archiviste.supprime_blob(IndexClasseur::ZERO, &hash2)?;

            prop_assert!(archiviste.donne_liste_blobs(IndexClasseur::ZERO)?.is_empty());
            prop_assert!(!archiviste.existe_blob(IndexClasseur::ZERO, &hash1));
            prop_assert!(!archiviste.existe_blob(IndexClasseur::ZERO, &hash2));
        }
    }
}
