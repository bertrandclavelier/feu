//! Définit les types d'erreurs de `feu-core`.
//!
//! [`ErreurFeu`] est l'unique type d'erreur exposé à l'extérieur du crate.
//! Il agrège les erreurs de chaque composant interne — chacun souverain
//! dans la définition de ses propres erreurs — et les fait remonter de
//! manière transparente vers l'appelant.
//!
//! [`ResultFeu<T>`] est l'alias de [`Result<T, ErreurFeu>`] utilisé dans
//! toutes les fonctions publiques de `feu-core`.

use crate::{cryptographe::erreur::ErreurCryptographe, intendant::erreur::ErreurIntendant};
use thiserror::Error;

pub type ResultFeu<T> = Result<T, ErreurFeu>;

#[derive(Error, Debug)]
pub enum ErreurFeu {
    #[error("{0}")]
    Intendant(String),
    #[error("{0}")]
    Cryptographe(String),
}

impl From<ErreurIntendant> for ErreurFeu {
    fn from(e: ErreurIntendant) -> Self {
        ErreurFeu::Intendant(e.to_string())
    }
}

impl From<ErreurCryptographe> for ErreurFeu {
    fn from(e: ErreurCryptographe) -> Self {
        ErreurFeu::Cryptographe(e.to_string())
    }
}
