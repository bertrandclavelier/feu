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

use thiserror::Error;

pub(crate) type _ResultCryptographe<T> = Result<T, ErreurCryptographe>;

#[derive(Error, Debug)]
pub(crate) enum ErreurCryptographe {
    #[error("Le cryptographe est en galère : {0}")]
    _Interne(String),
}
