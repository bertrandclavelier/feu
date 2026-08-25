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
//!
//! # Errors
//!
//! Tout échec du système de fichiers remonte tel quel en
//! [`ErreurFeuNoyau::IoError`] par `?` : les sections `# Errors` qui parlent
//! d'un fichier « absent ou illisible » désignent ce cas. Ne sont nommées que
//! les variantes propres au carnet, quand il constate lui-même l'anomalie.

use std::fs;
use std::fs::DirBuilder;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::Braise;
use crate::ErreurFeuNoyau;
use crate::ResultFeuNoyau;
use crate::cryptographe::trousseaux_publics::{TrousseauPublicComplet, TrousseauPublicFoyer};
use crate::{Anomalie, MAX_CLASSEURS, MAX_FOYERS};

/// Dossier des fichiers de configuration, sous `~/.feu/`.
const FEU_DOSSIER_CONFIG: &str = ".config";

/// Configuration globale du nœud, dans `~/.feu/.config/`.
const FEU_CONFIGURATION: &str = "noyau.feu";

/// Sel Argon2id du nœud, lu avant toute dérivation depuis le mot de passe.
const FEU_SEL: &str = "sel.feu";

/// Clé de signature privée du nœud, chiffrée — signataire des racines.
const CLE_NOEUD_SIG_PRIV: &str = "feu_sig.priv";

/// Clé de signature publique du nœud, en clair : elle sert à vérifier une
/// racine nœud éteint.
const CLE_NOEUD_SIG_PUB: &str = "feu_sig.pub";

// Pour chaque foyer
// La clé symétrique de chiffrement est sous la forme : adresse_braise.cle

/// Clé de signature privée du foyer, chiffrée — dans son dossier `.cles/`.
const CLE_FOYER_SIG_PRIV: &str = "sig.priv";

/// Clé de signature publique du foyer, en clair : elle authentifie ses ENU
/// sans que le foyer soit ouvert.
const CLE_FOYER_SIG_PUB: &str = "sig.pub";

/// Clé de déchiffrement ML-KEM du foyer, chiffrée.
const CLE_FOYER_CHIF_PRIV: &str = "chif.priv";

/// Clé de chiffrement ML-KEM du foyer, en clair : c'est elle qu'un tiers
/// utiliserait pour lui adresser un contenu.
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
    /// Initialise le registre avec le chemin racine du nœud reçu en argument.
    ///
    /// Le `Carnet` ne résout plus lui-même l'emplacement de `~/.feu` : le chemin
    /// lui est fourni par l'appelant, remonté depuis le binaire (`feu-tui`) qui
    /// est le seul à lire l'environnement. Le `Carnet` se contente de le conserver
    /// et d'en dériver tous les chemins de fichiers du nœud.
    pub(super) fn new(chemin_feu: &Path) -> Self {
        Carnet {
            chemin_feu: chemin_feu.to_path_buf(),
        }
    }

    // ── Arborescence ─────────────────────────────────────────────────────────

    /// Retourne le chemin racine du nœud `~/.feu`.
    pub(super) fn donne_chemin_feu(&self) -> PathBuf {
        self.chemin_feu.clone()
    }

    /// Donne le chemin de la configuration du nœud `~/.feu/.config/noyau.feu`.
    fn donne_chemin_configuration(&self) -> PathBuf {
        self.chemin_feu
            .join(FEU_DOSSIER_CONFIG)
            .join(FEU_CONFIGURATION)
    }

    /// Donne le chemin du dossier `~/.feu/adresse.braise`
    pub(super) fn donne_chemin_braise(&self, braise: Braise) -> PathBuf {
        self.chemin_feu.join(PathBuf::from(braise.to_string()))
    }

    /// Donne le chemin de l'archive chiffrée `~/.feu/<braise>.feu`.
    pub(super) fn donne_chemin_archive_chiffree(&self, braise: Braise) -> PathBuf {
        self.chemin_feu.join(format!("{}.feu", braise))
    }

    /// Donne le chemin de l'archive tar intermédiaire `~/.feu/<braise>.tar`.
    pub(super) fn donne_chemin_archive_tar(&self, braise: Braise) -> PathBuf {
        self.chemin_feu.join(format!("{}.tar", braise))
    }

    /// Indique si le dossier `~/.feu` existe sur le système de fichiers.
    pub(super) fn existe_arborescence_noeud(&self) -> bool {
        self.chemin_feu.exists()
    }

    /// Vérifie la présence des fichiers fixes du nœud.
    ///
    /// Contrôle `~/.feu/`, `.config/noyau.feu`, `.cles/` et les trois clés du
    /// nœud.
    /// N'inspecte pas les foyers — leurs fichiers dépendent de la config,
    /// lue séparément par [`super::Gardien::diagnostic_noeud`].
    pub(super) fn verifier_arborescence_noeud(&self) -> Vec<Anomalie> {
        let mut resultat: Vec<Anomalie> = Vec::new();
        if !self.chemin_feu.exists() {
            resultat.push(Anomalie::ElementAbsent(self.donne_chemin_feu()));
        }
        if !self.donne_chemin_configuration().exists() {
            resultat.push(Anomalie::ElementAbsent(self.donne_chemin_configuration()));
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

        resultat
    }

    /// Vérifie la présence des fichiers de clés d'un foyer.
    ///
    /// Contrôle `.cles/`, les paires de signature et de chiffrement,
    /// et les `MAX_CLASSEURS` clés de classeurs.
    /// N'inspecte pas le contenu des classeurs eux-mêmes — seules les clés sont vérifiées.
    pub(super) fn verifier_arborescence_foyer(&self, braise: Braise) -> Vec<Anomalie> {
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
    /// # Errors
    ///
    /// Retourne une erreur si le dossier est absent ou si la suppression échoue.
    pub(super) fn supprime_dossier_braise(&self, braise: Braise) -> ResultFeuNoyau<()> {
        fs::remove_dir_all(self.donne_chemin_braise(braise))?;
        Ok(())
    }

    // ── Configuration ─────────────────────────────────────────────────────────

    /// Écrit le contenu de `noyau.feu` sur le disque.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si l'écriture échoue.
    pub(super) fn enregistre_configuration(&self, configuration: String) -> ResultFeuNoyau<()> {
        Self::ecrire_fichier_600(&self.donne_chemin_configuration(), configuration.as_bytes())?;

        Ok(())
    }

    /// Lit le contenu de `noyau.feu` depuis le disque et le retourne en `String`.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si le fichier est absent ou illisible.
    pub(super) fn ouvre_configuration(&self) -> ResultFeuNoyau<String> {
        Ok(std::fs::read_to_string(self.donne_chemin_configuration())?)
    }

    // ── Trousseaux ────────────────────────────────────────────────────────────

    /// Écrit l'intégralité du trousseau public sur le disque.
    ///
    /// Crée l'arborescence complète du nœud puis écrit chaque fichier de clé :
    /// sel et clés du nœud sous `~/.feu/.cles/`, clés de chaque foyer sous
    /// `~/.feu/<braise>/.cles/`, la clé symétrique d'archive restant à la racine.
    ///
    /// Les clés privées et symétriques partent chiffrées, les publiques et le sel
    /// en clair. Dossiers en `0o700`, fichiers en `0o600`.
    ///
    /// `.config/` est créé vide : rien n'y est écrit ici, et
    /// [`Self::ecrire_fichier_600`] ne crée aucun dossier parent.
    ///
    /// # Errors
    ///
    /// Retourne une erreur à la première opération disque qui échoue.
    pub(super) fn ecrire_trousseau_public_complet(
        &self,
        trousseau_public_complet: &TrousseauPublicComplet,
    ) -> ResultFeuNoyau<()> {
        Self::creer_dossier(&self.chemin_feu)?;
        Self::creer_dossier(&self.chemin_feu.join(FEU_DOSSIER_CONFIG))?;
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
            let foyer = trousseau_public_complet.donne_trousseau_public_foyer(i)?;

            let chemin_foyer = &self
                .chemin_feu
                .join(foyer.donne_braise().to_string())
                .join(".cles/");

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
                        return Err(ErreurFeuNoyau::GardienPasDeClePourClasseur(i, j));
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
    /// # Errors
    ///
    /// Propage l'absence ou l'illisibilité d'un fichier de clé, et retourne
    /// [`ErreurFeuNoyau::GardienTailleFichierInattendue`] si l'un d'eux est lu
    /// mais ne fait pas la taille voulue.
    pub(super) fn creer_trousseau_public_foyer(
        &self,
        braise: Braise,
    ) -> ResultFeuNoyau<TrousseauPublicFoyer> {
        let cle_chiffrement = std::fs::read(
            self.chemin_feu
                .join(".cles/")
                .join(format!("{}{}", braise, ".cle")),
        )?
        .try_into()
        .map_err(|_| {
            ErreurFeuNoyau::GardienTailleFichierInattendue(
                self.chemin_feu
                    .join(".cles/")
                    .join(format!("{}{}", braise, ".cle")),
            )
        })?;

        let chemin_foyer = &self.chemin_feu.join(braise.to_string()).join(".cles/");

        let cle_sig_privee = std::fs::read(chemin_foyer.join(CLE_FOYER_SIG_PRIV))?
            .try_into()
            .map_err(|_| {
                ErreurFeuNoyau::GardienTailleFichierInattendue(
                    chemin_foyer.join(CLE_FOYER_SIG_PRIV),
                )
            })?;

        let cle_sig_pub = std::fs::read(chemin_foyer.join(CLE_FOYER_SIG_PUB))?
            .try_into()
            .map_err(|_| {
                ErreurFeuNoyau::GardienTailleFichierInattendue(chemin_foyer.join(CLE_FOYER_SIG_PUB))
            })?;

        let cle_chiff_privee = std::fs::read(chemin_foyer.join(CLE_FOYER_CHIF_PRIV))?
            .try_into()
            .map_err(|_| {
                ErreurFeuNoyau::GardienTailleFichierInattendue(
                    chemin_foyer.join(CLE_FOYER_CHIF_PRIV),
                )
            })?;

        let cle_chiff_pub = std::fs::read(chemin_foyer.join(CLE_FOYER_CHIF_PUB))?
            .try_into()
            .map_err(|_| {
                ErreurFeuNoyau::GardienTailleFichierInattendue(
                    chemin_foyer.join(CLE_FOYER_CHIF_PUB),
                )
            })?;

        let mut trousseau_public_foyer = TrousseauPublicFoyer::new(
            braise,
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
                .map_err(|_| {
                    ErreurFeuNoyau::GardienTailleFichierInattendue(
                        chemin_foyer.join(format!("classeur{j}.cle")),
                    )
                })?;
            trousseau_public_foyer.ajoute_cle_chiffrement_classeur(cle_classeur, j)?;
        }

        Ok(trousseau_public_foyer)
    }

    /// Lit le sel Argon2id depuis `~/.feu/.cles/sel.feu`.
    ///
    /// # Errors
    ///
    /// Propage l'absence ou l'illisibilité du fichier, et retourne
    /// [`ErreurFeuNoyau::GardienTailleFichierInattendue`] s'il ne fait pas 16 octets.
    pub(super) fn lire_pour_donner_sel(&self) -> ResultFeuNoyau<[u8; 16]> {
        std::fs::read(self.chemin_feu.join(".cles").join(FEU_SEL))?
            .try_into()
            .map_err(|_| {
                ErreurFeuNoyau::GardienTailleFichierInattendue(
                    self.chemin_feu.join(".cles").join(FEU_SEL),
                )
            })
    }

    /// Lit la clé privée de signature du nœud depuis `~/.feu/.cles/feu_sig.priv`.
    ///
    /// # Errors
    ///
    /// Propage l'absence ou l'illisibilité du fichier, et retourne
    /// [`ErreurFeuNoyau::GardienTailleFichierInattendue`] s'il ne fait pas 60 octets.
    pub(super) fn lire_pour_donner_cle_sig_privee(&self) -> ResultFeuNoyau<[u8; 60]> {
        std::fs::read(self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PRIV))?
            .try_into()
            .map_err(|_| {
                ErreurFeuNoyau::GardienTailleFichierInattendue(
                    self.chemin_feu.join(".cles").join(CLE_FOYER_SIG_PRIV),
                )
            })
    }

    /// Lit la clé publique de signature du nœud depuis `~/.feu/.cles/feu_sig.pub`.
    ///
    /// # Errors
    ///
    /// Propage l'absence ou l'illisibilité du fichier, et retourne
    /// [`ErreurFeuNoyau::GardienTailleFichierInattendue`] s'il ne fait pas 2592 octets.
    pub(super) fn lire_pour_donner_cle_sig_pub(&self) -> ResultFeuNoyau<[u8; 2592]> {
        std::fs::read(self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PUB))?
            .try_into()
            .map_err(|_| {
                ErreurFeuNoyau::GardienTailleFichierInattendue(
                    self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PUB),
                )
            })
    }

    /// Lit la clé symétrique de chiffrement d'un foyer depuis `~/.feu/.cles/<braise>.cle`.
    ///
    /// # Errors
    ///
    /// Propage l'absence ou l'illisibilité du fichier, et retourne
    /// [`ErreurFeuNoyau::GardienTailleFichierInattendue`] s'il ne fait pas 60 octets.
    pub(super) fn lire_pour_donner_cle_chiffrement_foyer(
        &self,
        braise: Braise,
    ) -> ResultFeuNoyau<[u8; 60]> {
        std::fs::read(
            self.chemin_feu
                .join(".cles/")
                .join(format!("{}{}", braise, ".cle")),
        )?
        .try_into()
        .map_err(|_| {
            ErreurFeuNoyau::GardienTailleFichierInattendue(
                self.chemin_feu
                    .join(".cles/")
                    .join(format!("{}{}", braise, ".cle")),
            )
        })
    }

    // ── Archives ──────────────────────────────────────────────────────────────

    /// Ouvre le fichier `<braise>.feu` en écriture exclusive avec les permissions `rw-------` (0o600).
    ///
    /// # Errors
    ///
    /// Retourne une erreur si le fichier existe déjà ou si la création échoue.
    pub(super) fn ouvre_archive_chiffree_foyer_ecriture(
        &self,
        braise: Braise,
    ) -> ResultFeuNoyau<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.donne_chemin_archive_chiffree(braise))?)
    }

    /// Ouvre l'archive `<braise>.feu` en lecture.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si le fichier est absent ou illisible.
    pub(super) fn ouvre_archive_chiffree_foyer_lecture(
        &self,
        braise: Braise,
    ) -> ResultFeuNoyau<File> {
        Ok(OpenOptions::new()
            .read(true)
            .open(self.donne_chemin_archive_chiffree(braise))?)
    }

    /// Ouvre l'archive tar intermédiaire `<braise>.tar` en lecture.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si le fichier est absent ou illisible.
    pub(super) fn ouvre_archive_tar_foyer_lecture(&self, braise: Braise) -> ResultFeuNoyau<File> {
        Ok(OpenOptions::new()
            .read(true)
            .open(self.donne_chemin_archive_tar(braise))?)
    }

    /// Crée `~/.feu/<braise>.tar` vide en écriture exclusive avec les permissions `rw-------` (0o600).
    ///
    /// Destiné à recevoir les données déchiffrées depuis `<braise>.feu`.
    /// Doit être supprimé après désarchivage via [`supprime_archive_foyer_tar`](Self::supprime_archive_foyer_tar).
    ///
    /// # Errors
    ///
    /// Retourne une erreur si le fichier existe déjà ou si la création échoue.
    pub(super) fn ouvre_archive_tar_vide_ecriture(&self, braise: Braise) -> ResultFeuNoyau<File> {
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
    /// # Errors
    ///
    /// Retourne une erreur si le fichier existe déjà, si la création échoue,
    /// si l'archivage tar échoue, ou si la finalisation échoue.
    pub(super) fn archive_tar_foyer(&self, braise: Braise) -> ResultFeuNoyau<()> {
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
    /// Le dossier de destination est créé ici, et non laissé à `unpack`. Comme
    /// il est la racine de l'extraction, il ne figure pas parmi les entrées de
    /// l'archive : `unpack` le créerait au `umask` du processus, soit `0o755` en
    /// pratique, là où tout le reste de l'arborescence est en `0o700`. Les
    /// entrées de l'archive, elles, portent leur mode d'origine.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si `<braise>.tar` est absent, illisible,
    /// ou si l'extraction échoue.
    pub(super) fn desarchive_tar_foyer(&self, braise: Braise) -> ResultFeuNoyau<()> {
        let mut archive = tar::Archive::new(self.ouvre_archive_tar_foyer_lecture(braise)?);

        Self::creer_dossier(&self.donne_chemin_braise(braise))?;
        archive.unpack(self.donne_chemin_braise(braise))?;
        Ok(())
    }

    /// Supprime l'archive chiffrée `~/.feu/<braise>.feu` après extraction.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si le fichier est absent ou si la suppression échoue.
    pub(super) fn supprime_archive_foyer_chiffree(&self, braise: Braise) -> ResultFeuNoyau<()> {
        fs::remove_file(self.donne_chemin_archive_chiffree(braise))?;
        Ok(())
    }

    /// Supprime l'archive tar intermédiaire `~/.feu/<braise>.tar`.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si le fichier est absent ou si la suppression échoue.
    pub(super) fn supprime_archive_foyer_tar(&self, braise: Braise) -> ResultFeuNoyau<()> {
        fs::remove_file(self.donne_chemin_archive_tar(braise))?;
        Ok(())
    }

    // ── Utilitaires privés ────────────────────────────────────────────────────

    /// Crée un dossier avec les permissions `rwx------` (0o700).
    ///
    /// Crée les dossiers intermédiaires si nécessaire (`recursive`).
    ///
    /// # Errors
    ///
    /// Retourne une erreur si la création échoue — permissions
    /// insuffisantes, chemin invalide ou erreur d'entrée/sortie.
    fn creer_dossier(path: &Path) -> ResultFeuNoyau<()> {
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
    /// # Errors
    ///
    /// Retourne une erreur si l'écriture du fichier temporaire échoue,
    /// ou si le renommage vers la cible échoue.
    fn ecrire_fichier_600(chemin: &Path, contenu: &[u8]) -> ResultFeuNoyau<()> {
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
