// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Définit les types d'erreurs de `feu-noyau`.
//!
//! [`ErreurFeuNoyau`] est l'unique type d'erreur exposé à l'extérieur du crate.
//! Il agrège les erreurs de chaque composant interne — chacun souverain
//! dans la définition de ses propres erreurs — et les fait remonter de
//! manière transparente vers l'appelant.
//!
//! [`ResultFeuNoyau<T>`] est l'alias de [`Result<T, ErreurFeuNoyau>`] utilisé dans
//! toutes les fonctions publiques de `feu-noyau`.

use crate::{
    archiviste::erreur::ErreurArchiviste, cryptographe::erreur::ErreurCryptographe,
    gardien::erreur::ErreurGardien,
};
use thiserror::Error;

pub type ResultFeuNoyau<T> = Result<T, ErreurFeuNoyau>;

#[derive(Error, Debug)]
pub enum ErreurFeuNoyau {
    /// Erreur remontée depuis le gardien — opération disque ou parsing échoué.
    /// Le message textuel provient de [`ErreurGardien`] via `.to_string()`.
    #[error("NOY > {0}")]
    Gardien(String),

    /// Erreur remontée depuis le cryptographe — opération cryptographique échouée.
    /// Le message textuel provient de [`ErreurCryptographe`] via `.to_string()`.
    #[error("NOY > {0}")]
    Cryptographe(String),

    /// Erreur remontée depuis l'archiviste — opération sur l'arborescence d'un foyer échouée.
    /// Le message textuel provient de [`ErreurArchiviste`] via `.to_string()`.
    #[error("NOY > {0}")]
    Archiviste(String),

    /// Erreur liée à l'état de [`FeuNoyau`](crate::FeuNoyau) lui-même — état invalide,
    /// précondition non respectée. Indépendante du gardien et du cryptographe.
    #[error("NOY > {0}")]
    Standard(String),
}

impl From<ErreurGardien> for ErreurFeuNoyau {
    /// Convertit [`ErreurGardien`] en [`ErreurFeuNoyau::Gardien`].
    ///
    /// Le type interne est perdu — seul le message textuel est propagé,
    /// préservant l'encapsulation des détails d'implémentation du gardien.
    fn from(e: ErreurGardien) -> Self {
        ErreurFeuNoyau::Gardien(e.to_string())
    }
}

impl From<ErreurCryptographe> for ErreurFeuNoyau {
    /// Convertit [`ErreurCryptographe`] en [`ErreurFeuNoyau::Cryptographe`].
    ///
    /// Le type interne est perdu — seul le message textuel est propagé,
    /// préservant l'encapsulation des détails d'implémentation du cryptographe.
    fn from(e: ErreurCryptographe) -> Self {
        ErreurFeuNoyau::Cryptographe(e.to_string())
    }
}

impl From<ErreurArchiviste> for ErreurFeuNoyau {
    /// Convertit [`ErreurArchiviste`] en [`ErreurFeuNoyau::Archiviste`].
    ///
    /// Le type interne est perdu — seul le message textuel est propagé,
    /// préservant l'encapsulation des détails d'implémentation de l'archiviste.
    fn from(e: ErreurArchiviste) -> Self {
        ErreurFeuNoyau::Archiviste(e.to_string())
    }
}
