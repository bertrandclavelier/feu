//! Définit les types d'erreurs de l'intendant.
//!
//! [`ErreurIntendant`] couvre l'ensemble des erreurs pouvant survenir
//! lors des opérations sur le système de fichiers local — lecture,
//! écriture, configuration et gestion des foyers.
//!
//! Ce type est interne à `feu-core` — il n'est jamais exposé directement
//! à l'extérieur du crate. Il remonte vers [`ErreurFeu`] via une
//! conversion explicite en message textuel, préservant ainsi
//! l'encapsulation des détails d'implémentation.

use thiserror::Error;

pub(crate) type _ResultIntendant<T> = Result<T, ErreurIntendant>;

#[derive(Error, Debug)]
pub(crate) enum ErreurIntendant {
    #[error("L'intendant est en galère : {0}")]
    _Interne(String),
}
