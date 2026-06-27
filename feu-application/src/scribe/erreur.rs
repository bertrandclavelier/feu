// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Définit le type d'erreur du Scribe.
//!
//! [`ErreurScribe`] couvre les trois familles d'échecs du Scribe : la création
//! du dossier `~/.feu/enu/` (I/O), la signature des ENU déléguée à `feu-noyau`,
//! et la (dé)sérialisation des cartes. Ce type est interne à `feu-application` —
//! il remonte vers [`ErreurFeuApplication`] via [`From`].
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
    /// Échec interne au Scribe, hors I/O et hors `feu-noyau` — survient pendant
    /// la (dé)sérialisation d'une ENU.
    ///
    /// Le message porte un code `SCR-NNN` qui identifie la cause précise :
    /// buffer trop court ou discriminant de carte inconnu (`SCR-001`), octets
    /// censés être du texte mais non UTF-8 valide (`SCR-002`).
    #[error("SCR > {0}")]
    Interne(String),

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
