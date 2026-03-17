// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

use thiserror::Error;

pub(crate) type ResultArchiviste<T> = Result<T, ErreurArchiviste>;

#[derive(Error, Debug)]
pub(crate) enum ErreurArchiviste {
    /// Erreur interne générique — portée directement par un message textuel.
    #[error("L'archiviste est en galère : {0}")]
    Interne(String),

    /// Erreur d'entrée/sortie émise par les opérations sur le système de fichiers.
    #[error("L'archiviste est en galère avec une opération d'entrée/sortie : {0}")]
    IoError(#[from] std::io::Error),
}
