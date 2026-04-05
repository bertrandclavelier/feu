// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! Définit les types d'erreurs de l'archiviste.
//!
//! [`ErreurArchiviste`] couvre les erreurs pouvant survenir lors des
//! opérations sur l'arborescence d'un foyer — lecture, écriture, suppression
//! de blobs, vérification de l'arborescence.
//!
//! Ce type est interne à `feu-core` — il n'est jamais exposé directement
//! à l'extérieur du crate. Il remonte vers [`ErreurFeu`] via une conversion
//! explicite en message textuel, préservant ainsi l'encapsulation des détails
//! d'implémentation de l'archiviste.

use thiserror::Error;

pub(crate) type ResultArchiviste<T> = Result<T, ErreurArchiviste>;

#[derive(Error, Debug)]
pub(crate) enum ErreurArchiviste {
    /// Erreur interne générique — portée directement par un message textuel.
    #[error("ARC > {0}")]
    Interne(String),

    /// Erreur d'entrée/sortie émise par les opérations sur le système de fichiers.
    #[error("ARC > {0}")]
    IoError(#[from] std::io::Error),
}
