// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! Registre des chemins du nœud Feu.
//!
//! Ce module définit [`Carnet`], la mémoire cartographique du gardien.
//! Il maintient le chemin racine du nœud (`~/.feu`) et centralise toutes
//! les opérations sur le système de fichiers : création de l'arborescence,
//! écriture des clés chiffrées sur le disque.
//!
//! Les noms de fichiers du protocole sont définis comme constantes privées
//! au niveau du module — point de vérité unique pour toute l'arborescence.

use super::erreur::{ErreurGardien, ResultGardien};
use crate::MAX_FOYERS;
use crate::cryptographe::trousseaux_publics::{TrousseauPublicComplet, TrousseauPublicFoyer};
use std::env;
use std::fs;
use std::fs::DirBuilder;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const FEU_CONFIGURATION: &str = "config.feu";
const FEU_SEL: &str = "sel.feu";
const CLE_NOEUD_SIG_PRIV: &str = "feu_sig.priv";
const CLE_NOEUD_SIG_PUB: &str = "feu_sig.pub";

// Pour chaque foyer
// La clé symétrique de chiffrement est sous la forme : adresse_onion.cle
const CLE_FOYER_SIG_PRIV: &str = "sig.priv";
const CLE_FOYER_SIG_PUB: &str = "sig.pub";
const CLE_FOYER_CHIF_PRIV: &str = "chif.priv";
const CLE_FOYER_CHIF_PUB: &str = "chif.pub";

// L'enregistrement des classeurs ne sont pas encore pris en compte dans la v0.0.1

/// Registre cartographique du gardien.
///
/// Maintient le chemin racine du nœud et la carte de tous les fichiers
/// du protocole. Point d'accès unique pour toute opération sur
/// l'arborescence `~/.feu`.
pub(super) struct Carnet {
    /// Chemin racine du nœud — `~/.feu`.
    chemin_feu: PathBuf,
}

impl Carnet {
    /// Initialise le registre à partir de la variable d'environnement `HOME`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `HOME` est absente ou contient une valeur
    /// non Unicode.
    pub(super) fn new() -> ResultGardien<Self> {
        Ok(Carnet {
            chemin_feu: PathBuf::from(env::var("HOME")?).join(".feu/"),
        })
    }

    /// Indique si le dossier `~/.feu` existe sur le système de fichiers.
    pub(super) fn existe_arborescence_noeud(&self) -> bool {
        self.chemin_feu.exists()
    }

    /// Donne le chemin du dossier `~/.feu/adresse.onion`
    pub(super) fn donne_chemin_onion(&self, onion: &str) -> PathBuf {
        self.chemin_feu.join(PathBuf::from(onion))
    }

    /// Donne le chemin de l'archive chiffrée `~/.feu/<onion>.feu`.
    pub(super) fn donne_chemin_archive_chiffree(&self, onion: &str) -> PathBuf {
        self.chemin_feu.join(format!("{}.feu", onion))
    }

    /// Donne le chemin de l'archive tar intermédiaire `~/.feu/<onion>.tar`.
    pub(super) fn donne_chemin_archive_tar(&self, onion: &str) -> PathBuf {
        self.chemin_feu.join(format!("{}.tar", onion))
    }

    /// Supprime le dossier `~/.feu/<onion>` et tout son contenu.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le dossier est absent ou si la suppression échoue.
    pub(super) fn supprime_dossier_onion(&self, onion: &str) -> ResultGardien<()> {
        fs::remove_dir_all(self.donne_chemin_onion(onion))?;
        Ok(())
    }

    /// Supprime l'archive chiffrée `~/.feu/<onion>.feu` après extraction.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent ou si la suppression échoue.
    pub(super) fn supprime_archive_foyer_chiffree(&self, onion: &str) -> ResultGardien<()> {
        fs::remove_file(self.donne_chemin_archive_chiffree(onion))?;
        Ok(())
    }

    /// Supprime l'archive tar intermédiaire `~/.feu/<onion>.tar`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent ou si la suppression échoue.
    pub(super) fn supprime_archive_foyer_tar(&self, onion: &str) -> ResultGardien<()> {
        fs::remove_file(self.donne_chemin_archive_tar(onion))?;
        Ok(())
    }

    /// Écrit l'intégralité du trousseau public sur le disque.
    ///
    /// Crée l'arborescence complète du nœud puis écrit chaque fichier de clé :
    ///
    /// - `~/.feu/.cles/sel.feu` — sel Argon2id (en clair)
    /// - `~/.feu/.cles/feu_sig.priv` — clé privée de signature du nœud (chiffrée)
    /// - `~/.feu/.cles/feu_sig.pub` — clé publique de signature du nœud (en clair)
    ///
    /// Pour chaque foyer :
    /// - `~/.feu/.cles/<onion>.cle` — clé symétrique d'archive (chiffrée)
    /// - `~/.feu/<onion>/.cles/sig.priv` — clé privée de signature réseau (chiffrée)
    /// - `~/.feu/<onion>/.cles/sig.pub` — clé publique de signature réseau (en clair)
    /// - `~/.feu/<onion>/.cles/chif.priv` — clé privée de chiffrement réseau (chiffrée)
    /// - `~/.feu/<onion>/.cles/chif.pub` — clé publique de chiffrement réseau (en clair)
    ///
    /// Tous les dossiers sont créés avec les permissions `rwx------` (0o700).
    /// Tous les fichiers sont créés avec les permissions `rw-------` (0o600).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur à la première opération disque qui échoue.
    pub(super) fn ecrire_trousseau_public_complet(
        &self,
        trousseau_public_complet: &TrousseauPublicComplet,
    ) -> ResultGardien<()> {
        Self::creer_dossier(&self.chemin_feu)?;
        Self::creer_dossier(&self.chemin_feu.join(".cles"))?;

        // Écriture du sel
        Self::ecrire_fichier_600(
            &self.chemin_feu.join(".cles").join(FEU_SEL),
            &trousseau_public_complet
                .donne_trousseau_public_noeud()
                .donne_sel(),
        )?;

        // Écriture de la clé privée du nœud
        Self::ecrire_fichier_600(
            &self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PRIV),
            &trousseau_public_complet
                .donne_trousseau_public_noeud()
                .donne_cle_sig_privee(),
        )?;

        // Écriture de la clé publique du nœud
        Self::ecrire_fichier_600(
            &self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PUB),
            &trousseau_public_complet
                .donne_trousseau_public_noeud()
                .donne_cle_sig_pub(),
        )?;

        // Pour chaque foyer
        for i in 0..MAX_FOYERS {
            let foyer = match trousseau_public_complet.donne_trousseau_public_foyer(i) {
                Ok(valeur) => valeur,
                Err(_) => continue,
            };

            let chemin_foyer = &self.chemin_feu.join(foyer.donne_onion()).join(".cles/");

            Self::creer_dossier(chemin_foyer)?;

            // Écriture de la clé symétrique du foyer
            Self::ecrire_fichier_600(
                &self
                    .chemin_feu
                    .join(".cles/")
                    .join(format!("{}{}", foyer.donne_onion(), ".cle")),
                &foyer.donne_cle_chiffrement(),
            )?;

            // Écriture de la paire de clés sig du foyer
            Self::ecrire_fichier_600(
                &chemin_foyer.join(CLE_FOYER_SIG_PRIV),
                &foyer.donne_cle_sig_privee(),
            )?;
            Self::ecrire_fichier_600(
                &chemin_foyer.join(CLE_FOYER_SIG_PUB),
                &foyer.donne_cle_sig_pub(),
            )?;

            // Écriture de la paire de clés chif du foyer
            Self::ecrire_fichier_600(
                &chemin_foyer.join(CLE_FOYER_CHIF_PRIV),
                &foyer.donne_cle_chiff_privee(),
            )?;
            Self::ecrire_fichier_600(
                &chemin_foyer.join(CLE_FOYER_CHIF_PUB),
                &foyer.donne_cle_chiff_pub(),
            )?;

            // Cette version de Feu ne prends pas encore en charge les clés des classeurs
        }

        Ok(())
    }

    /// Lit toutes les clés chiffrées d'un foyer depuis le disque.
    ///
    /// Lit depuis `~/.feu/.cles/<onion>.cle` et `~/.feu/<onion>/.cles/` :
    /// - la clé symétrique de chiffrement (`<onion>.cle`) — 60 octets
    /// - la paire de clés de signature (`sig.priv`, `sig.pub`) — 60 et 32 octets
    /// - la paire de clés de chiffrement (`chif.priv`, `chif.pub`) — 60 et 32 octets
    ///
    /// Les clés privées et symétriques sont retournées chiffrées (AES-256-GCM).
    /// Les clés de classeurs ne sont pas encore prises en charge (v0.0.1).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si un fichier est absent, illisible ou de taille incorrecte.
    pub(super) fn creer_trousseau_public_foyer(
        &self,
        onion: &str,
    ) -> ResultGardien<TrousseauPublicFoyer> {
        let cle_chiffrement = std::fs::read(
            &self
                .chemin_feu
                .join(".cles/")
                .join(format!("{}{}", onion, ".cle")),
        )?
        .try_into()
        .map_err(|_| ErreurGardien::Interne(String::from("Problème lecture fichier.")))?;

        let chemin_foyer = &self.chemin_feu.join(onion).join(".cles/");

        let cle_sig_privee = std::fs::read(chemin_foyer.join(CLE_FOYER_SIG_PRIV))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from("Problème lecture fichier.")))?;

        let cle_sig_pub = std::fs::read(chemin_foyer.join(CLE_FOYER_SIG_PUB))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from("Problème lecture fichier.")))?;

        let cle_chiff_privee = std::fs::read(chemin_foyer.join(CLE_FOYER_CHIF_PRIV))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from("Problème lecture fichier.")))?;

        let cle_chiff_pub = std::fs::read(chemin_foyer.join(CLE_FOYER_CHIF_PUB))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from("Problème lecture fichier.")))?;

        // Cette version de Feu ne prends pas encore en charge les clés des classeurs

        Ok(TrousseauPublicFoyer::new(
            String::from(onion),
            cle_chiffrement,
            cle_sig_privee,
            cle_sig_pub,
            cle_chiff_privee,
            cle_chiff_pub,
        ))
    }

    /// Lit le sel Argon2id depuis `~/.feu/.cles/sel.feu`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent, illisible, ou ne fait pas 16 octets.
    pub(super) fn lire_pour_donner_sel(&self) -> ResultGardien<[u8; 16]> {
        Ok(std::fs::read(&self.chemin_feu.join(".cles").join(FEU_SEL))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from("Problème lecture fichier.")))?)
    }

    /// Lit la clé privée de signature du nœud depuis `~/.feu/.cles/feu_sig.priv`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent, illisible, ou ne fait pas 60 octets.
    pub(super) fn lire_pour_donner_cle_sig_privee(&self) -> ResultGardien<[u8; 60]> {
        Ok(
            std::fs::read(&self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PRIV))?
                .try_into()
                .map_err(|_| ErreurGardien::Interne(String::from("Problème lecture fichier.")))?,
        )
    }

    /// Lit la clé publique de signature du nœud depuis `~/.feu/.cles/feu_sig.pub`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent, illisible, ou ne fait pas 32 octets.
    pub(super) fn lire_pour_donner_cle_sig_pub(&self) -> ResultGardien<[u8; 32]> {
        Ok(
            std::fs::read(&self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PUB))?
                .try_into()
                .map_err(|_| ErreurGardien::Interne(String::from("Problème lecture fichier.")))?,
        )
    }

    /// Lit la clé symétrique de chiffrement d'un foyer depuis `~/.feu/.cles/<onion>.cle`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent, illisible, ou ne fait pas 60 octets.
    pub(super) fn lire_pour_donner_cle_chiffrement_foyer(
        &self,
        onion: &str,
    ) -> ResultGardien<[u8; 60]> {
        Ok(std::fs::read(
            &self
                .chemin_feu
                .join(".cles/")
                .join(format!("{}{}", onion, ".cle")),
        )?
        .try_into()
        .map_err(|_| ErreurGardien::Interne(String::from("Problème lecture fichier.")))?)
    }

    /// Écrit le contenu de `config.feu` sur le disque.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'écriture échoue.
    pub(super) fn enregistre_configuration(&self, configuration: String) -> ResultGardien<()> {
        std::fs::write(self.chemin_feu.join(FEU_CONFIGURATION), configuration)?;

        Ok(())
    }

    /// Lit le contenu de `config.feu` depuis le disque et le retourne en `String`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent ou illisible.
    pub(super) fn ouvre_configuration(&self) -> ResultGardien<String> {
        Ok(std::fs::read_to_string(
            self.chemin_feu.join(FEU_CONFIGURATION),
        )?)
    }

    /// Ouvre le fichier `<onion>.feu` en écriture exclusive avec les permissions `rw-------` (0o600).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier existe déjà ou si la création échoue.
    pub(super) fn ouvre_archive_chiffree_foyer_ecriture(&self, onion: &str) -> ResultGardien<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.donne_chemin_archive_chiffree(onion))?)
    }

    /// Ouvre l'archive `<onion>.feu` en lecture.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent ou illisible.
    pub(super) fn ouvre_archive_chiffree_foyer_lecture(&self, onion: &str) -> ResultGardien<File> {
        Ok(OpenOptions::new()
            .read(true)
            .open(self.donne_chemin_archive_chiffree(onion))?)
    }

    /// Ouvre l'archive tar intermédiaire `<onion>.tar` en lecture.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent ou illisible.
    pub(super) fn ouvre_archive_tar_foyer_lecture(&self, onion: &str) -> ResultGardien<File> {
        Ok(OpenOptions::new()
            .read(true)
            .open(self.donne_chemin_archive_tar(onion))?)
    }

    /// Crée `~/.feu/<onion>.tar` vide en écriture exclusive avec les permissions `rw-------` (0o600).
    ///
    /// Destiné à recevoir les données déchiffrées depuis `<onion>.feu`.
    /// Doit être supprimé après désarchivage via [`supprime_archive_foyer_tar`](Self::supprime_archive_foyer_tar).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier existe déjà ou si la création échoue.
    pub(super) fn ouvre_archive_tar_vide_ecriture(&self, onion: &str) -> ResultGardien<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.donne_chemin_archive_tar(onion))?)
    }

    /// Crée l'archive tar intermédiaire `<onion>.tar` à partir du dossier `<onion>`.
    ///
    /// Ouvre `~/.feu/<onion>.tar` en écriture exclusive (`rw-------`, 0o600),
    /// archive récursivement le dossier `~/.feu/<onion>` à la racine de l'archive (`.`),
    /// puis finalise l'archive via `into_inner()`.
    ///
    /// Ce fichier tar est destiné à être chiffré par le cryptographe immédiatement après.
    /// Il doit être supprimé après chiffrement.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier existe déjà, si la création échoue,
    /// si l'archivage tar échoue, ou si la finalisation échoue.
    pub(super) fn archive_tar_foyer(&self, onion: &str) -> ResultGardien<()> {
        let fichier = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.donne_chemin_archive_tar(onion))?;
        let mut builder = tar::Builder::new(fichier);

        builder.append_dir_all(".", self.donne_chemin_onion(onion))?;
        builder.into_inner()?;
        Ok(())
    }

    /// Extrait l'archive tar intermédiaire `<onion>.tar` vers `~/.feu/<onion>/`.
    ///
    /// Ouvre `<onion>.tar` en lecture et extrait son contenu dans
    /// `~/.feu/<onion>/` — symétrique de [`archive_tar_foyer`](Self::archive_tar_foyer)
    /// qui archive avec `.` comme racine.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `<onion>.tar` est absent, illisible,
    /// ou si l'extraction échoue.
    pub(super) fn desarchive_tar_foyer(&self, onion: &str) -> ResultGardien<()> {
        let mut archive = tar::Archive::new(self.ouvre_archive_tar_foyer_lecture(onion)?);

        archive.unpack(self.donne_chemin_onion(onion))?;
        Ok(())
    }

    /// Crée un dossier avec les permissions `rwx------` (0o700).
    ///
    /// Crée les dossiers intermédiaires si nécessaire (`recursive`).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la création échoue — permissions
    /// insuffisantes, chemin invalide ou erreur d'entrée/sortie.
    fn creer_dossier(path: &Path) -> ResultGardien<()> {
        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&path)?;
        Ok(())
    }

    /// Écrit `contenu` dans `chemin` avec les permissions `rw-------` (0o600).
    ///
    /// Écrit d'abord dans un fichier temporaire `<chemin>.tmp`, puis le renomme
    /// sur la cible — le renommage est atomique sur Unix et écrase l'ancien
    /// fichier s'il existe. Fonctionne à l'initialisation (fichier absent)
    /// comme au changement de mot de passe (fichier existant).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la création du fichier temporaire échoue,
    /// si l'écriture échoue, ou si le renommage échoue.
    fn ecrire_fichier_600(chemin: &Path, contenu: &[u8]) -> ResultGardien<()> {
        let nouveau_chemin = chemin.with_added_extension("tmp");

        let mut fichier = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&nouveau_chemin)?;

        fichier.write_all(contenu)?;

        std::fs::rename(&nouveau_chemin, chemin)?; // rename écrase l'ancien fichier

        Ok(())
    }
}
