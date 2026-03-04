//! Définit les types d'erreurs du gardien.
//!
//! [`ErreurGardien`] couvre l'ensemble des erreurs pouvant survenir
//! lors des opérations sur le système de fichiers local — lecture,
//! écriture, création de dossiers — et lors de la lecture des
//! variables d'environnement.
//!
//! Ce type est interne à `feu-core` — il n'est jamais exposé directement
//! à l'extérieur du crate. Il remonte vers [`ErreurFeu`] via une
//! conversion explicite en message textuel, préservant ainsi
//! l'encapsulation des détails d'implémentation.
//!
//! # Conversion des erreurs tierces
//!
//! Les trois erreurs tierces — `std::env::VarError`, `std::io::Error` et
//! `toml::ser::Error` — implémentent toutes `std::error::Error`. `#[from]`
//! (thiserror) génère automatiquement leur conversion. Le type original est
//! préservé dans la variante et peut être inspecté ou ré-affiché.

use std::env::VarError;

use thiserror::Error;

pub(crate) type ResultGardien<T> = Result<T, ErreurGardien>;

#[derive(Error, Debug)]
pub(crate) enum ErreurGardien {
    /// Erreur interne générique — portée directement par un message textuel.
    #[error("Le gardien est en galère : {0}")]
    Interne(String),

    /// Erreur émise par `std::env::var()` lors de la lecture d'une variable d'environnement.
    #[error("Le gardien est en galère avec la lecture d'une variable d'environnement : {0}")]
    VarError(#[from] VarError),

    /// Erreur d'entrée/sortie émise par les opérations sur le système de fichiers.
    #[error("Le gardien est en galère avec une opération d'entrée/sortie : {0}")]
    IoError(#[from] std::io::Error),

    /// Erreur de sérialisation TOML émise par la crate `toml`.
    #[error("Le gardien est en galère avec une opération TOML : {0}")]
    TomlError(#[from] toml::ser::Error),
}
