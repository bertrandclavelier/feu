//! Registre des chemins du nœud Feu.
//!
//! Ce module définit [`Carnet`], la mémoire cartographique du gardien.
//! Il maintient le chemin racine du nœud (`~/.feu`) et centralise toutes
//! les opérations sur le système de fichiers : création de l'arborescence,
//! écriture des clés chiffrées sur le disque.
//!
//! Les noms de fichiers du protocole sont définis comme constantes privées
//! au niveau du module — point de vérité unique pour toute l'arborescence.

use super::erreur::ResultGardien;
use crate::cryptographe::trousseau_public::TrousseauPublic;
use std::env;
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

const FEU_TOML: &str = "feu.toml";
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
    pub(super) fn existe(&self) -> bool {
        self.chemin_feu.exists()
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
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur à la première opération disque qui échoue.
    pub(super) fn ecrire_trousseau_public(&self, tp: &TrousseauPublic) -> ResultGardien<()> {
        Self::creer_dossier(&self.chemin_feu)?;
        Self::creer_dossier(&self.chemin_feu.join(".cles"))?;

        // Écriture du sel
        std::fs::write(&self.chemin_feu.join(".cles").join(FEU_SEL), tp.sel)?;

        // Écriture de la clé privée du nœud
        std::fs::write(
            &self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PRIV),
            tp.cle_sig_privee,
        )?;

        // Écriture de la clé publique du nœud
        std::fs::write(
            &self.chemin_feu.join(".cles").join(CLE_NOEUD_SIG_PUB),
            tp.cle_sig_pub,
        )?;

        // Pour chaque foyer
        for foyer in &tp.cles_foyers {
            let chemin_foyer = &self.chemin_feu.join(&foyer.adresse_onion).join(".cles/");

            Self::creer_dossier(chemin_foyer)?;

            // Écriture de la clé symétrique du foyer
            std::fs::write(
                &self
                    .chemin_feu
                    .join(".cles/")
                    .join(format!("{}{}", &foyer.adresse_onion, ".cle")),
                foyer.cle_chiffrement,
            )?;

            // Écriture de la paire de clés sig du foyer
            std::fs::write(chemin_foyer.join(CLE_FOYER_SIG_PRIV), foyer.cle_sig_privee)?;
            std::fs::write(chemin_foyer.join(CLE_FOYER_SIG_PUB), foyer.cle_sig_pub)?;

            // Écriture de la paire de clés chif du foyer
            std::fs::write(
                chemin_foyer.join(CLE_FOYER_CHIF_PRIV),
                foyer.cle_chiff_privee,
            )?;
            std::fs::write(chemin_foyer.join(CLE_FOYER_CHIF_PUB), foyer.cle_chiff_pub)?;

            // Cette version de Feu ne prends pas encore en charge les clés des classeurs
        }

        Ok(())
    }

    /// Écrit le contenu de `feu.toml` sur le disque.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'écriture échoue.
    pub(super) fn enregistre_feu_toml(&self, feu_toml: String) -> ResultGardien<()> {
        // Écriture du fichier feu.toml
        std::fs::write(self.chemin_feu.join(FEU_TOML), feu_toml)?;

        Ok(())
    }
}
