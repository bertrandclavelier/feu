// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Définit les types d'erreurs de `feu-application`.
//!
//! [`ErreurFeuApplication`] est l'unique type d'erreur exposé à l'extérieur du crate.
//! Il reçoit les erreurs de `feu-noyau` et les erreurs propres à la couche applicative,
//! et les expose à `feu-tui` sans laisser traverser les types internes de `feu-noyau`.
//!
//! [`ResultFeuApplication<T>`] est l'alias de [`Result<T, ErreurFeuApplication>`] utilisé dans
//! toutes les fonctions publiques de `feu-application`.

use feu_noyau::ErreurFeuNoyau;
use thiserror::Error;

/// Alias de [`Result`] utilisé par toutes les fonctions publiques de `feu-application`.
pub type ResultFeuApplication<T> = Result<T, ErreurFeuApplication>;

/// Type d'erreur unique exposé par `feu-application`.
///
/// Agrège deux familles de variantes :
///
/// - **Erreurs remontées depuis `feu-noyau`** — encapsulées dans une `String`
///   via `.to_string()`, ce qui préserve l'encapsulation et évite toute fuite
///   de type privé à travers l'API applicative.
/// - **Erreurs propres à la couche applicative** — arguments invalides,
///   préconditions non satisfaites, états internes incohérents.
///
/// Le préfixe `APP >` dans chaque message sert de marqueur de couche lorsque
/// les messages sont encapsulés par la couche de présentation.
#[derive(Error, Debug)]
pub enum ErreurFeuApplication {
    /// Erreur remontée depuis `feu-noyau`.
    /// Le message textuel provient de [`ErreurFeuNoyau`] via `.to_string()`.
    #[error("APP > {0}")]
    FeuNoyau(String),

    /// Erreur propre à la couche applicative — argument invalide, précondition non
    /// satisfaite ou état interne incohérent. Indépendante de `feu-noyau`.
    #[error("APP > {0}")]
    Standard(String),
}

impl From<ErreurFeuNoyau> for ErreurFeuApplication {
    /// Convertit [`ErreurFeuNoyau`] en [`ErreurFeuApplication::FeuNoyau`].
    ///
    /// Le type interne est perdu — seul le message textuel est propagé,
    /// préservant l'encapsulation des détails d'implémentation de `feu-noyau`.
    fn from(e: ErreurFeuNoyau) -> Self {
        ErreurFeuApplication::FeuNoyau(e.to_string())
    }
}
