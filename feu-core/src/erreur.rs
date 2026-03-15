// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! Définit les types d'erreurs de `feu-core`.
//!
//! [`ErreurFeu`] est l'unique type d'erreur exposé à l'extérieur du crate.
//! Il agrège les erreurs de chaque composant interne — chacun souverain
//! dans la définition de ses propres erreurs — et les fait remonter de
//! manière transparente vers l'appelant.
//!
//! [`ResultFeu<T>`] est l'alias de [`Result<T, ErreurFeu>`] utilisé dans
//! toutes les fonctions publiques de `feu-core`.

use crate::{cryptographe::erreur::ErreurCryptographe, gardien::erreur::ErreurGardien};
use thiserror::Error;

pub type ResultFeu<T> = Result<T, ErreurFeu>;

#[derive(Error, Debug)]
pub enum ErreurFeu {
    /// Erreur remontée depuis le gardien — opération disque ou parsing échoué.
    /// Le message textuel provient de [`ErreurGardien`] via `.to_string()`.
    #[error("{0}")]
    Gardien(String),

    /// Erreur remontée depuis le cryptographe — opération cryptographique échouée.
    /// Le message textuel provient de [`ErreurCryptographe`] via `.to_string()`.
    #[error("{0}")]
    Cryptographe(String),

    /// Erreur liée à l'état de [`Feu`](crate::Feu) lui-même — état invalide,
    /// précondition non respectée. Indépendante du gardien et du cryptographe.
    #[error("{0}")]
    Standard(String),
}

impl From<ErreurGardien> for ErreurFeu {
    /// Convertit [`ErreurGardien`] en [`ErreurFeu::Gardien`].
    ///
    /// Le type interne est perdu — seul le message textuel est propagé,
    /// préservant l'encapsulation des détails d'implémentation du gardien.
    fn from(e: ErreurGardien) -> Self {
        ErreurFeu::Gardien(e.to_string())
    }
}

impl From<ErreurCryptographe> for ErreurFeu {
    /// Convertit [`ErreurCryptographe`] en [`ErreurFeu::Cryptographe`].
    ///
    /// Le type interne est perdu — seul le message textuel est propagé,
    /// préservant l'encapsulation des détails d'implémentation du cryptographe.
    fn from(e: ErreurCryptographe) -> Self {
        ErreurFeu::Cryptographe(e.to_string())
    }
}
