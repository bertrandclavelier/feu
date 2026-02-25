//! Définit les types d'erreurs du cryptographe.
//!
//! [`ErreurCryptographe`] couvre l'ensemble des erreurs pouvant survenir
//! lors des opérations cryptographiques — génération de seed, dérivation
//! de clés, chiffrement et déchiffrement.
//!
//! Ce type est interne à `feu-core` — il n'est jamais exposé directement
//! à l'extérieur du crate. Il remonte vers [`ErreurFeu`] via une
//! conversion explicite en message textuel, préservant ainsi
//! l'encapsulation des détails d'implémentation.
//!
//! # Conversion des erreurs tierces
//!
//! Deux mécanismes coexistent selon que l'erreur source implémente
//! `std::error::Error` ou non.
//!
//! **`#[from]` (thiserror)** — quand l'erreur source implémente
//! `std::error::Error`, thiserror génère automatiquement un `From`.
//! Le type d'erreur original est préservé dans la variante — il peut être
//! inspecté ou ré-affiché. Exemple : `Bip39(#[from] bip39::Error)`.
//!
//! **`From` manuel + `String`** — quand l'erreur source n'implémente PAS
//! `std::error::Error` (cas de `hkdf::InvalidLength`), `#[from]` est
//! inutilisable. La variante stocke alors un `String` issu de `.to_string()`
//! (qui requiert seulement `Display`). Le type original est perdu — seul
//! le message textuel est conservé.

use hkdf::InvalidLength;
use thiserror::Error;

pub(crate) type ResultCryptographe<T> = Result<T, ErreurCryptographe>;

#[derive(Error, Debug)]
pub(crate) enum ErreurCryptographe {
    /// Erreur interne générique — portée directement par un message textuel.
    #[error("Le cryptographe est en galère : {0}")]
    Interne(String),

    /// Erreur émise par `bip39` lors de la génération ou du parsing du mnémonique.
    ///
    /// `bip39::Error` implémente `std::error::Error` — `#[from]` génère
    /// automatiquement la conversion. Le type original est préservé dans la variante.
    #[error("Le cryptographe est en galère avec bip39 : {0}")]
    Bip39(#[from] bip39::Error),

    /// Erreur HKDF — longueur de sortie invalide, stockée en texte.
    ///
    /// `hkdf::InvalidLength` n'implémente pas `std::error::Error`, ce qui rend
    /// `#[from]` inutilisable. La conversion est manuelle (voir `impl From` ci-dessous) :
    /// l'erreur est convertie en `String` via `.to_string()` — le type original est perdu.
    #[error("Le cryptographe est en galère avec Hkdf : {0}")]
    Hkdf(String),
}

impl From<hkdf::InvalidLength> for ErreurCryptographe {
    /// Convertit `hkdf::InvalidLength` en [`ErreurCryptographe::Hkdf`].
    ///
    /// `hkdf::InvalidLength` implémente `Display` mais pas `std::error::Error`.
    /// `.to_string()` suffit pour extraire le message — c'est tout ce qui
    /// peut être récupéré sans le trait bound qu'exige `#[from]`.
    fn from(e: InvalidLength) -> Self {
        ErreurCryptographe::Hkdf(e.to_string())
    }
}
