// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Définit le type d'erreur du Scribe.
//!
//! [`ErreurScribe`] couvre les échecs du Scribe : les opérations disque sur
//! `~/.feu/enu/` et les comptoirs (I/O), la signature des ENU déléguée à
//! `feu-noyau`, et ses propres refus — (dé)sérialisation, authentification,
//! gardes de forme. Ce type est interne à `feu-application` — il remonte vers
//! [`ErreurFeuApplication`](crate::ErreurFeuApplication) via [`From`].
//!
//! **Le flux ne va que dans un sens.** Aucune variante ne porte d'erreur venue
//! de `feu-application` : ce que le Scribe demande à
//! [`SessionApplication`](crate::SessionApplication) lui revient en [`Option`],
//! qu'il traduit en code à lui. Une erreur applicative absorbée ici repartirait
//! d'où elle vient, et l'appelant la lirait affublée des préfixes des deux
//! traversées.
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
    /// Échec interne au Scribe, hors I/O et hors `feu-noyau` — (dé)sérialisation,
    /// authentification, ou garde de forme refusée.
    ///
    /// Le message porte un code qui identifie la cause précise, et son préfixe
    /// dit où la constante est déclarée : `ENU-NNN` dans `scribe/enu.rs`,
    /// `SCR-NNN` dans `scribe.rs`, `COM_D-NNN` dans `scribe/comptoir.rs`. Les
    /// codes eux-mêmes sont documentés un à un sur ces constantes.
    ///
    /// La variante est unique pour toutes : le code voyage dans la chaîne, pas
    /// dans le type. Un appelant ne peut donc les discriminer qu'en lisant le
    /// message — même après la traversée vers
    /// [`ErreurFeuApplication`](crate::ErreurFeuApplication), qui aplatit à son
    /// tour.
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
    /// Aplatit l'erreur du noyau en une chaîne, comme le fait
    /// [`ErreurFeuApplication`](crate::ErreurFeuApplication) à la frontière
    /// suivante : le type d'origine ne survit à aucune des deux traversées.
    fn from(e: ErreurFeuNoyau) -> Self {
        ErreurScribe::FeuNoyau(e.to_string())
    }
}

impl From<walkdir::Error> for ErreurScribe {
    /// Range les échecs de parcours d'un comptoir avec les autres erreurs
    /// disque : `walkdir` ne rapporte que ce que le système de fichiers lui
    /// refuse, et sait se convertir en [`std::io::Error`].
    fn from(e: walkdir::Error) -> Self {
        ErreurScribe::IoError(e.into())
    }
}
