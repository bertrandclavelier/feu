// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Définit le type d'erreur du Scribe.
//!
//! [`ErreurScribe`] couvre les erreurs de création du dossier `~/.feu/enu/`.
//! Ce type est interne à `feu-application` — il remonte vers
//! [`ErreurFeuApplication`] via [`From`].
//!
//! # Conversion des erreurs tierces
//!
//! `std::io::Error` implémente `std::error::Error`. `#[from]` (thiserror) génère
//! automatiquement la conversion. Le type original est préservé dans la variante
//! et peut être inspecté ou ré-affiché.

use feu_noyau::ErreurFeuNoyau;
use thiserror::Error;

/// Alias de [`Result`] utilisé par les fonctions du Scribe.
pub(crate) type ResultScribe<T> = Result<T, ErreurScribe>;

/// Erreurs propres au Scribe.
#[derive(Error, Debug)]
pub(crate) enum ErreurScribe {
    /// Erreur remontée depuis `feu-noyau` (signature, empreinte…).
    #[error("SCR > {0}")]
    FeuNoyau(String),

    /// Erreur d'entrée/sortie émise par les opérations sur le système de fichiers.
    #[error("SCR > IoError > {0}")]
    IoError(#[from] std::io::Error),
}

impl From<ErreurFeuNoyau> for ErreurScribe {
    fn from(e: ErreurFeuNoyau) -> Self {
        ErreurScribe::FeuNoyau(e.to_string())
    }
}
