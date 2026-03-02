//! Registre des chemins du nœud Feu.
//!
//! Ce module définit [`Carnet`], la mémoire cartographique de l'intendant.
//! Il maintient le chemin racine du nœud (`~/.feu`) et la carte de tous
//! les fichiers nécessaires au bon fonctionnement du protocole.
//!
//! [`CheminFeu`] encapsule le chemin racine et expose les sous-chemins
//! structurels. [`FichierFeu`] recense exhaustivement chaque fichier géré
//! par Feu — clés du nœud, clés des foyers, configuration. Cette
//! centralisation garantit qu'aucun fichier n'est oublié lors des
//! vérifications d'intégrité de l'arborescence.

use super::erreur::ResultIntendant;
use std::collections::HashMap;
use std::env;
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// Chemin racine du nœud Feu — `~/.feu`.
///
/// Encapsule le `PathBuf` de la racine et expose les sous-chemins
/// structurels de l'arborescence.
struct CheminFeu(PathBuf);

/// Inventaire des fichiers gérés par Feu.
///
/// Chaque variante identifie un fichier précis de l'arborescence.
/// Utilisé comme clé du registre [`Carnet::chemin_fichiers`] pour
/// associer chaque fichier à son `PathBuf` calculé.
#[derive(Hash, Eq, PartialEq)]
enum FichierFeu {
    /// Fichier de configuration globale du nœud.
    ConfigFeu,
    /// Clé privée de signature du nœud.
    CleNoeudSigPriv,
    /// Clé publique de signature du nœud.
    CleNoeudSigPub,

    // Pour chaque foyer
    /// Clé symétrique de chiffrement du foyer.
    CleFoyerChiffSym,
    /// Clé privée de signature du foyer.
    CleFoyerSigPriv,
    /// Clé publique de signature du foyer.
    CleFoyerSigPub,
    /// Clé privée de chiffrement asymétrique du foyer.
    CleFoyerChiffPriv,
    /// Clé publique de chiffrement asymétrique du foyer.
    CleFoyerChiffPub,
    // Le coffre n'est pas pris en compte dans cette version
}

/// Registre cartographique de l'intendant.
///
/// Maintient le chemin racine du nœud et la carte de tous les fichiers
/// du protocole. Point d'accès unique pour toute opération sur
/// l'arborescence `~/.feu`.
pub(super) struct Carnet {
    /// Chemin racine du nœud — `~/.feu`.
    chemin_feu: CheminFeu,
    /// Carte des fichiers du protocole — clé : identifiant, valeur : chemin absolu.
    chemin_fichiers: HashMap<FichierFeu, PathBuf>,
}

impl Carnet {
    /// Initialise le registre à partir de la variable d'environnement `HOME`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `HOME` est absente ou contient une valeur
    /// non Unicode.
    pub(super) fn new() -> ResultIntendant<Self> {
        Ok(Carnet {
            chemin_feu: CheminFeu(PathBuf::from(env::var("HOME")?).join(".feu/")),
            chemin_fichiers: HashMap::new(),
        })
    }

    /// Retourne une référence vers le chemin racine `~/.feu`.
    pub(super) fn donne_chemin_feu(&self) -> &PathBuf {
        &self.chemin_feu.0
    }

    /// Indique si le dossier `~/.feu` existe sur le système de fichiers.
    pub(super) fn existe(&self) -> bool {
        self.chemin_feu.0.exists()
    }

    /// Crée un dossier avec les permissions `rwx------` (0o700).
    ///
    /// Crée les dossiers intermédiaires si nécessaire (`recursive`).
    ///
    /// # Erreurs
    ///
    ///
    /// Retourne une erreur si la création échoue — permissions
    /// insuffisantes, chemin invalide ou erreur d'entrée/sortie.
    pub(super) fn creer_dossier(&self, path: &Path) -> ResultIntendant<()> {
        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&path)?;
        Ok(())
    }
}
