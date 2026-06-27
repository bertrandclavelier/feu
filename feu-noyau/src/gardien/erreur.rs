// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Définit les types d'erreurs du gardien.
//!
//! [`ErreurGardien`] couvre l'ensemble des erreurs pouvant survenir
//! lors des opérations sur le système de fichiers local — lecture,
//! écriture, création de dossiers.
//!
//! Ce type est interne à `feu-noyau` — il n'est jamais exposé directement
//! à l'extérieur du crate. Il remonte vers [`ErreurFeuNoyau`] via une
//! conversion explicite en message textuel, préservant ainsi
//! l'encapsulation des détails d'implémentation.
//!
//! # Conversion des erreurs tierces
//!
//! Les deux erreurs tierces — `std::io::Error` et `std::num::ParseIntError` —
//! implémentent `std::error::Error`. `#[from]` (thiserror) génère
//! automatiquement leur conversion. Le type original est préservé dans la
//! variante et peut être inspecté ou ré-affiché.
//!
//! La lecture de `$HOME` a été centralisée dans [`FeuNoyau::chemin_feu`] —
//! le `VarError` ne fait donc plus partie de ce type d'erreur.

use thiserror::Error;

pub(crate) type ResultGardien<T> = Result<T, ErreurGardien>;

#[derive(Error, Debug)]
pub(crate) enum ErreurGardien {
    /// Erreur interne générique — portée directement par un message textuel.
    #[error("GAR > {0}")]
    Interne(String),

    /// Erreur d'entrée/sortie émise par les opérations sur le système de fichiers.
    #[error("GAR > IoError > {0}")]
    IoError(#[from] std::io::Error),

    /// Erreur de parsing émise lors de la conversion d'une chaîne en entier.
    #[error("GAR > ParseIntError > {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
}
