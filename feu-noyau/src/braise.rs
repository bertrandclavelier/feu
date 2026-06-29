// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Adresse `.braise` d'un foyer — newtype rigoureux.
//!
//! [`Braise`] remplace la `String` qui portait l'adresse `.braise`. Elle stocke
//! les [`LONGUEUR_BRAISE`] caractères BASE32 (`a-z2-7`) de l'adresse, **sans**
//! le suffixe `.braise` — ce dernier est réintroduit par l'impl `Display`. Une
//! `Braise` ne peut naître que d'une chaîne validée (`TryFrom<&str>`) : sa simple
//! existence garantit qu'elle est bien formée.
//!
//! L'apport est la **rigueur** (un état mal formé est inconstructible) et
//! l'**ergonomie** (valeur `Copy`, sans allocation), pas la sécurité : la
//! confiance dans une braise vient de sa résolution vers un foyer connu et de la
//! signature, jamais de son type.

use core::fmt;
use std::fmt::{Debug, Display};

use crate::{ErreurFeuNoyau, ResultFeuNoyau};

/// Nombre de caractères d'une adresse `.braise`, hors suffixe.
///
/// 34 octets encodés en BASE32 sans padding donnent 55 caractères (`a-z2-7`).
const LONGUEUR_BRAISE: usize = 55;

/// Adresse `.braise` d'un foyer, bien formée par construction.
///
/// Encapsule les `LONGUEUR_BRAISE` caractères BASE32 de l'adresse, sans le
/// suffixe `.braise`. Se construit via `TryFrom<&str>` (qui valide) et se rend
/// sous sa forme canonique — caractères + `.braise` — via `Display`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Braise([u8; LONGUEUR_BRAISE]);

impl TryFrom<&str> for Braise {
    type Error = ErreurFeuNoyau;

    /// Valide une chaîne et la convertit en [`Braise`].
    ///
    /// La chaîne doit être la forme canonique complète : 55 caractères BASE32
    /// suivis du suffixe `.braise`.
    ///
    /// # Erreurs
    ///
    /// [`ErreurFeuNoyau::BraiseTryFromStr`] si le suffixe manque, si la longueur
    /// n'est pas `LONGUEUR_BRAISE`, ou si un caractère sort de l'alphabet BASE32.
    fn try_from(valeur: &str) -> ResultFeuNoyau<Self> {
        // coupe et exige le suffixe .braise
        let reste = valeur
            .strip_suffix(".braise")
            .ok_or(ErreurFeuNoyau::BraiseTryFromStr)?;

        // 55 caractères, ni plus ni moins
        if reste.len() != LONGUEUR_BRAISE {
            return Err(ErreurFeuNoyau::BraiseTryFromStr);
        }

        // alphabet BASE32 minuscule : a-z et 2-7 (ni 0, 1, 8, 9)
        if !reste
            .bytes()
            .all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7'))
        {
            return Err(ErreurFeuNoyau::BraiseTryFromStr);
        }

        // validé : ASCII et bonne taille → la conversion en tableau ne peut pas échouer
        Ok(Braise(reste.as_bytes().try_into().unwrap()))
    }
}

impl Display for Braise {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // octets garantis ASCII par TryFrom → from_utf8 ne peut pas échouer
        let chars = str::from_utf8(&self.0).unwrap();
        // forme canonique : les 55 caractères suivis du suffixe
        write!(f, "{chars}.braise")
    }
}

impl Debug for Braise {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // délègue au Display, enveloppé du nom du type
        write!(f, "Braise({self})")
    }
}
