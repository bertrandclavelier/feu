// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Registre des chemins du nœud Feu.
//!
//! Ce module définit [`Carnet`], la mémoire cartographique du gardien.
//! Il maintient le chemin racine du nœud (`~/.feu`) et centralise toutes
//! les opérations sur le système de fichiers : création de l'arborescence,
//! écriture des clés chiffrées sur le disque.
//!
//! Les noms de fichiers du protocole sont définis comme constantes privées
//! au niveau du module — point de vérité unique pour toute l'arborescence.

use std::fs;
use std::fs::DirBuilder;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::FeuNoyau;
use crate::cryptographe::trousseaux_publics::{TrousseauPublicComplet, TrousseauPublicFoyer};
use crate::gardien::erreur::{ErreurGardien, ResultGardien};
use crate::{Anomalie, MAX_CLASSEURS, MAX_FOYERS};

const ERR_CAR_001: &str = "CAR-001 > Pas de trousseau public pour le foyer";
const ERR_CAR_002: &str = "CAR-002 > Pas de clé pour le classeur";
const ERR_CAR_003: &str = "CAR-003 > Problème lecture fichier";
const ERR_CAR_004: &str = "CAR-004 > Problème ajout clé classeur dans trousseau_public_foyer";

const FEU_CONFIGURATION: &str = "config.feu";
const FEU_SEL: &str = "sel.feu";
const CLE_NOEUD_SIG_PRIV: &str = "feu_sig.priv";
const CLE_NOEUD_SIG_PUB: &str = "feu_sig.pub";

// Pour chaque foyer
// La clé symétrique de chiffrement est sous la forme : adresse_braise.cle
const CLE_FOYER_SIG_PRIV: &str = "sig.priv";
const CLE_FOYER_SIG_PUB: &str = "sig.pub";
const CLE_FOYER_CHIF_PRIV: &str = "chif.priv";
const CLE_FOYER_CHIF_PUB: &str = "chif.pub";

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
    /// Initialise le registre à partir de [`FeuNoyau::chemin_feu`].
    ///
    /// Le chemin racine `~/.feu` est centralisé dans cette méthode —
    /// voir son implémentation pour le détail de la résolution.
    ///
    /// # Panics
    ///
    /// Panique si la variable d'environnement `HOME` est absente
    /// (propagé depuis `FeuNoyau::chemin_feu`).
    pub(super) fn new() -> ResultGardien<Self> {
        Ok(Carnet {
            chemin_feu: FeuNoyau::chemin_feu(),
        })
    }

    // ── Arborescence ─────────────────────────────────────────────────────────

    /// Retourne le chemin racine du nœud `~/.feu`.
    pub(super) fn donne_chemin_feu(&self) -> PathBuf {
        self.chemin_feu.clone()
    }

    /// Donne le chemin du dossier `~/.feu/adresse.braise`
    pub(super) fn donne_chemin_braise(&self, braise: &str) -> PathBuf {
        self.chemin_feu.join(PathBuf::from(braise))
    }

    /// Donne le chemin de l'archive chiffrée `~/.feu/<braise>.feu`.
    pub(super) fn donne_chemin_archive_chiffree(&self, braise: &str) -> PathBuf {
        self.chemin_feu.join(format!("{}.feu", braise))
    }

    /// Donne le chemin de l'archive tar intermédiaire `~/.feu/<braise>.tar`.
    pub(super) fn donne_chemin_archive_tar(&self, braise: &str) -> PathBuf {
        self.chemin_feu.join(format!("{}.tar", braise))
    }

    /// Indique si le dossier `~/.feu` existe sur le système de fichiers.
    pub(super) fn existe_arborescence_noeud(&self) -> bool {
        self.chemin_feu.exists()
    }

    /// Vérifie la présence des fichiers fixes du nœud.
    ///
    /// Contrôle `~/.feu/`, `.cles/`, `config.feu` et les trois clés du nœud.
    /// N'inspecte pas les foyers — leurs fichiers dépendent de la config,
    /// lue séparément par [`super::Gardien::diagnostic_noeud`].
    pub(super) fn verifier_arborescence_noeud(&self) -> ResultGardien<Vec<Anomalie>> {
        let mut resultat: Vec<Anomalie> = Vec::new();
        if !self.chemin_feu.exists() {
            resultat.push(Anomalie::ElementAbsent(self.chemin_feu.clone()));
        }
        if !self.chemin_feu.join(".cles").exists() {
            resultat.push(Anomalie::ElementAbsent(self.chemin_feu.join(".cles")));
        }
        if !self.chemin_feu.join(".cles").join(FEU_SEL).exists() {
            resultat.push(Anomalie::ElementAbsent(
                self.chemin_feu.join(".cles").join(FEU_SEL),
            ));
        }
        if !self
            .chemin_feu
            .join(".cles")
            .join(CLE_NOEUD_SIG_PRIV)
            .exists()
        {
            resultat.push(Anomalie::ElementAbsent(
                self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PRIV),
            ));
        }
        if !self
            .chemin_feu
            .join(".cles")
            .join(CLE_NOEUD_SIG_PUB)
            .exists()
        {
            resultat.push(Anomalie::ElementAbsent(
                self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PUB),
            ));
        }
        if !self.chemin_feu.join(FEU_CONFIGURATION).exists() {
            resultat.push(Anomalie::ElementAbsent(
                self.chemin_feu.join(FEU_CONFIGURATION),
            ));
        }

        Ok(resultat)
    }

    /// Vérifie la présence des fichiers de clés d'un foyer.
    ///
    /// Contrôle `.cles/`, les paires de signature et de chiffrement,
    /// et les `MAX_CLASSEURS` clés de classeurs.
    /// N'inspecte pas le contenu des classeurs eux-mêmes — seules les clés sont vérifiées.
    pub(super) fn verifier_arborescence_foyer(&self, braise: &str) -> Vec<Anomalie> {
        let mut resultat: Vec<Anomalie> = Vec::new();

        let chemin_cles = self.donne_chemin_braise(braise).join(".cles/");

        if !chemin_cles.exists() {
            resultat.push(Anomalie::ElementAbsent(chemin_cles.clone()));
        }
        if !chemin_cles.join(CLE_FOYER_SIG_PRIV).exists() {
            resultat.push(Anomalie::ElementAbsent(
                chemin_cles.join(CLE_FOYER_SIG_PRIV),
            ));
        }
        if !chemin_cles.join(CLE_FOYER_SIG_PUB).exists() {
            resultat.push(Anomalie::ElementAbsent(chemin_cles.join(CLE_FOYER_SIG_PUB)));
        }
        if !chemin_cles.join(CLE_FOYER_CHIF_PRIV).exists() {
            resultat.push(Anomalie::ElementAbsent(
                chemin_cles.join(CLE_FOYER_CHIF_PRIV),
            ));
        }
        if !chemin_cles.join(CLE_FOYER_CHIF_PUB).exists() {
            resultat.push(Anomalie::ElementAbsent(
                chemin_cles.join(CLE_FOYER_CHIF_PUB),
            ));
        }

        // Pour chaque classeur
        for j in 0..MAX_CLASSEURS {
            let chemin_cle_classeur = chemin_cles.join(format!("classeur{j}.cle"));

            if !chemin_cle_classeur.exists() {
                resultat.push(Anomalie::ElementAbsent(chemin_cle_classeur));
            }
        }

        resultat
    }

    /// Supprime le dossier `~/.feu/<braise>` et tout son contenu.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le dossier est absent ou si la suppression échoue.
    pub(super) fn supprime_dossier_braise(&self, braise: &str) -> ResultGardien<()> {
        fs::remove_dir_all(self.donne_chemin_braise(braise))?;
        Ok(())
    }

    // ── Configuration ─────────────────────────────────────────────────────────

    /// Écrit le contenu de `config.feu` sur le disque.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'écriture échoue.
    pub(super) fn enregistre_configuration(&self, configuration: String) -> ResultGardien<()> {
        Self::ecrire_fichier_600(
            &self.chemin_feu.join(FEU_CONFIGURATION),
            configuration.as_bytes(),
        )?;

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

    // ── Trousseaux ────────────────────────────────────────────────────────────

    /// Écrit l'intégralité du trousseau public sur le disque.
    ///
    /// Crée l'arborescence complète du nœud puis écrit chaque fichier de clé :
    ///
    /// - `~/.feu/.cles/sel.feu` — sel Argon2id (en clair)
    /// - `~/.feu/.cles/feu_sig.priv` — clé privée de signature du nœud (chiffrée)
    /// - `~/.feu/.cles/feu_sig.pub` — clé publique de signature du nœud (en clair)
    ///
    /// Pour chaque foyer :
    /// - `~/.feu/.cles/<braise>.cle` — clé symétrique d'archive (chiffrée)
    /// - `~/.feu/<braise>/.cles/sig.priv` — clé privée de signature réseau (chiffrée)
    /// - `~/.feu/<braise>/.cles/sig.pub` — clé publique de signature réseau (en clair)
    /// - `~/.feu/<braise>/.cles/chif.priv` — clé privée ML-KEM-1024 (chiffrée, 92 o)
    /// - `~/.feu/<braise>/.cles/chif.pub` — clé publique ML-KEM-1024 (en clair, 1568 o)
    /// - `~/.feu/<braise>/.cles/classeur0.cle` à `classeur4.cle` — clés des classeurs (chiffrées)
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
                Err(_) => {
                    return Err(ErreurGardien::Interne(format!("{} {}.", ERR_CAR_001, i,)));
                }
            };

            let chemin_foyer = &self.chemin_feu.join(foyer.donne_braise()).join(".cles/");

            Self::creer_dossier(chemin_foyer)?;

            // Écriture de la clé symétrique du foyer
            Self::ecrire_fichier_600(
                &self
                    .chemin_feu
                    .join(".cles/")
                    .join(format!("{}{}", foyer.donne_braise(), ".cle")),
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

            // Pour chaque classeur
            for j in 0..MAX_CLASSEURS {
                let cle_chiffree = match foyer.donne_cle_chiffrement_classeur(j) {
                    Ok(valeur) => valeur,
                    Err(_) => {
                        return Err(ErreurGardien::Interne(format!("{} {}", ERR_CAR_002, j,)));
                    }
                };

                Self::ecrire_fichier_600(
                    &chemin_foyer.join(format!("classeur{j}.cle")),
                    cle_chiffree,
                )?;
            }
        }

        Ok(())
    }

    /// Lit toutes les clés chiffrées d'un foyer depuis le disque.
    ///
    /// Lit depuis `~/.feu/.cles/<braise>.cle` et `~/.feu/<braise>/.cles/` :
    /// - la clé symétrique de chiffrement (`<braise>.cle`) — 60 octets
    /// - la paire de clés de signature (`sig.priv`, `sig.pub`) — 60 et 2592 octets
    /// - la paire de clés de chiffrement ML-KEM-1024 (`chif.priv`, `chif.pub`) — 92 et 1568 octets
    ///
    /// Les clés privées et symétriques sont retournées chiffrées (AES-256-GCM),
    /// y compris les cinq clés de classeurs (`classeur0.cle` à `classeur4.cle`).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si un fichier est absent, illisible ou de taille incorrecte.
    pub(super) fn creer_trousseau_public_foyer(
        &self,
        braise: &str,
    ) -> ResultGardien<TrousseauPublicFoyer> {
        let cle_chiffrement = std::fs::read(
            self.chemin_feu
                .join(".cles/")
                .join(format!("{}{}", braise, ".cle")),
        )?
        .try_into()
        .map_err(|_| ErreurGardien::Interne(String::from(ERR_CAR_003)))?;

        let chemin_foyer = &self.chemin_feu.join(braise).join(".cles/");

        let cle_sig_privee = std::fs::read(chemin_foyer.join(CLE_FOYER_SIG_PRIV))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from(ERR_CAR_003)))?;

        let cle_sig_pub = std::fs::read(chemin_foyer.join(CLE_FOYER_SIG_PUB))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from(ERR_CAR_003)))?;

        let cle_chiff_privee = std::fs::read(chemin_foyer.join(CLE_FOYER_CHIF_PRIV))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from(ERR_CAR_003)))?;

        let cle_chiff_pub = std::fs::read(chemin_foyer.join(CLE_FOYER_CHIF_PUB))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from(ERR_CAR_003)))?;

        let mut trousseau_public_foyer = TrousseauPublicFoyer::new(
            String::from(braise),
            cle_chiffrement,
            cle_sig_privee,
            cle_sig_pub,
            cle_chiff_privee,
            cle_chiff_pub,
        );

        // Pour chaque classeur
        for j in 0..MAX_CLASSEURS {
            let cle_classeur = std::fs::read(chemin_foyer.join(format!("classeur{j}.cle")))?
                .try_into()
                .map_err(|_| ErreurGardien::Interne(String::from(ERR_CAR_003)))?;
            if trousseau_public_foyer
                .ajoute_cle_chiffrement_classeur(cle_classeur, j)
                .is_err()
            {
                return Err(ErreurGardien::Interne(String::from(ERR_CAR_004)));
            }
        }

        Ok(trousseau_public_foyer)
    }

    /// Lit le sel Argon2id depuis `~/.feu/.cles/sel.feu`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent, illisible, ou ne fait pas 16 octets.
    pub(super) fn lire_pour_donner_sel(&self) -> ResultGardien<[u8; 16]> {
        std::fs::read(self.chemin_feu.join(".cles").join(FEU_SEL))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from(ERR_CAR_003)))
    }

    /// Lit la clé privée de signature du nœud depuis `~/.feu/.cles/feu_sig.priv`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent, illisible, ou ne fait pas 60 octets.
    pub(super) fn lire_pour_donner_cle_sig_privee(&self) -> ResultGardien<[u8; 60]> {
        std::fs::read(self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PRIV))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from(ERR_CAR_003)))
    }

    /// Lit la clé publique de signature du nœud depuis `~/.feu/.cles/feu_sig.pub`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent, illisible, ou ne fait pas 2592 octets.
    pub(super) fn lire_pour_donner_cle_sig_pub(&self) -> ResultGardien<[u8; 2592]> {
        std::fs::read(self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PUB))?
            .try_into()
            .map_err(|_| ErreurGardien::Interne(String::from(ERR_CAR_003)))
    }

    /// Lit la clé symétrique de chiffrement d'un foyer depuis `~/.feu/.cles/<braise>.cle`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent, illisible, ou ne fait pas 60 octets.
    pub(super) fn lire_pour_donner_cle_chiffrement_foyer(
        &self,
        braise: &str,
    ) -> ResultGardien<[u8; 60]> {
        std::fs::read(
            self.chemin_feu
                .join(".cles/")
                .join(format!("{}{}", braise, ".cle")),
        )?
        .try_into()
        .map_err(|_| ErreurGardien::Interne(String::from(ERR_CAR_003)))
    }

    // ── Archives ──────────────────────────────────────────────────────────────

    /// Ouvre le fichier `<braise>.feu` en écriture exclusive avec les permissions `rw-------` (0o600).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier existe déjà ou si la création échoue.
    pub(super) fn ouvre_archive_chiffree_foyer_ecriture(
        &self,
        braise: &str,
    ) -> ResultGardien<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.donne_chemin_archive_chiffree(braise))?)
    }

    /// Ouvre l'archive `<braise>.feu` en lecture.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent ou illisible.
    pub(super) fn ouvre_archive_chiffree_foyer_lecture(&self, braise: &str) -> ResultGardien<File> {
        Ok(OpenOptions::new()
            .read(true)
            .open(self.donne_chemin_archive_chiffree(braise))?)
    }

    /// Ouvre l'archive tar intermédiaire `<braise>.tar` en lecture.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent ou illisible.
    pub(super) fn ouvre_archive_tar_foyer_lecture(&self, braise: &str) -> ResultGardien<File> {
        Ok(OpenOptions::new()
            .read(true)
            .open(self.donne_chemin_archive_tar(braise))?)
    }

    /// Crée `~/.feu/<braise>.tar` vide en écriture exclusive avec les permissions `rw-------` (0o600).
    ///
    /// Destiné à recevoir les données déchiffrées depuis `<braise>.feu`.
    /// Doit être supprimé après désarchivage via [`supprime_archive_foyer_tar`](Self::supprime_archive_foyer_tar).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier existe déjà ou si la création échoue.
    pub(super) fn ouvre_archive_tar_vide_ecriture(&self, braise: &str) -> ResultGardien<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.donne_chemin_archive_tar(braise))?)
    }

    /// Crée l'archive tar intermédiaire `<braise>.tar` à partir du dossier `<braise>`.
    ///
    /// Ouvre `~/.feu/<braise>.tar` en écriture exclusive (`rw-------`, 0o600),
    /// archive récursivement le dossier `~/.feu/<braise>` à la racine de l'archive (`.`),
    /// puis finalise l'archive via `into_inner()`.
    ///
    /// Les liens symboliques sont archivés **tels quels** (`follow_symlinks(false)`) —
    /// les suivre provoquerait une boucle infinie sur les liens `registre/classeur.N → ../`,
    /// qui pointent vers la racine du foyer.
    ///
    /// Ce fichier tar est destiné à être chiffré par le cryptographe immédiatement après.
    /// Il doit être supprimé après chiffrement.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier existe déjà, si la création échoue,
    /// si l'archivage tar échoue, ou si la finalisation échoue.
    pub(super) fn archive_tar_foyer(&self, braise: &str) -> ResultGardien<()> {
        let fichier = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.donne_chemin_archive_tar(braise))?;
        let mut builder = tar::Builder::new(fichier);

        builder.follow_symlinks(false);
        builder.append_dir_all(".", self.donne_chemin_braise(braise))?;
        builder.into_inner()?;
        Ok(())
    }

    /// Extrait l'archive tar intermédiaire `<braise>.tar` vers `~/.feu/<braise>/`.
    ///
    /// Ouvre `<braise>.tar` en lecture et extrait son contenu dans
    /// `~/.feu/<braise>/` — symétrique de [`archive_tar_foyer`](Self::archive_tar_foyer)
    /// qui archive avec `.` comme racine.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `<braise>.tar` est absent, illisible,
    /// ou si l'extraction échoue.
    pub(super) fn desarchive_tar_foyer(&self, braise: &str) -> ResultGardien<()> {
        let mut archive = tar::Archive::new(self.ouvre_archive_tar_foyer_lecture(braise)?);

        archive.unpack(self.donne_chemin_braise(braise))?;
        Ok(())
    }

    /// Supprime l'archive chiffrée `~/.feu/<braise>.feu` après extraction.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent ou si la suppression échoue.
    pub(super) fn supprime_archive_foyer_chiffree(&self, braise: &str) -> ResultGardien<()> {
        fs::remove_file(self.donne_chemin_archive_chiffree(braise))?;
        Ok(())
    }

    /// Supprime l'archive tar intermédiaire `~/.feu/<braise>.tar`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent ou si la suppression échoue.
    pub(super) fn supprime_archive_foyer_tar(&self, braise: &str) -> ResultGardien<()> {
        fs::remove_file(self.donne_chemin_archive_tar(braise))?;
        Ok(())
    }

    // ── Utilitaires privés ────────────────────────────────────────────────────

    /// Crée un dossier avec les permissions `rwx------` (0o700).
    ///
    /// Crée les dossiers intermédiaires si nécessaire (`recursive`).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la création échoue — permissions
    /// insuffisantes, chemin invalide ou erreur d'entrée/sortie.
    fn creer_dossier(path: &Path) -> ResultGardien<()> {
        DirBuilder::new().mode(0o700).recursive(true).create(path)?;
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
    /// Retourne une erreur si l'écriture du fichier temporaire échoue,
    /// ou si le renommage vers la cible échoue.
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
