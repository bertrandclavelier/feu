// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Types élémentaires du noyau, bien formés par construction.
//!
//! [`Braise`] porte l'adresse `.braise` d'un foyer, [`IndexFoyer`] et
//! [`IndexClasseur`] une position bornée. Aucun ne naît autrement que d'un
//! `TryFrom` qui valide : son existence vaut garantie. Les deux index sont des
//! types distincts et ne se substituent pas l'un à l'autre.
//!
//! L'apport est la **rigueur** (un état mal formé est inconstructible) et
//! l'**ergonomie** (valeurs `Copy`, sans allocation), pas la sécurité : la
//! confiance dans une braise vient de sa résolution vers un foyer connu et de la
//! signature, jamais de son type.

use core::fmt;
use std::fmt::{Debug, Display};

use crate::{ErreurFeuNoyau, MAX_CLASSEURS, MAX_FOYERS, ResultFeuNoyau};

/// Adresse `.braise` d'un foyer, bien formée par construction.
///
/// Encapsule les `Braise::LONGUEUR` caractères BASE32 de l'adresse, sans le
/// suffixe `.braise`. Se construit via `TryFrom<&str>` (qui valide) et se rend
/// sous sa forme canonique — caractères + `.braise` — via `Display`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Braise([u8; Self::LONGUEUR]);

impl Braise {
    /// Nombre de caractères d'une adresse `.braise`, hors suffixe.
    ///
    /// 34 octets encodés en BASE32 sans padding donnent 55 caractères (`a-z2-7`).
    pub(crate) const LONGUEUR: usize = 55;

    /// Braise qui ne désigne aucun foyer — et qui désigne donc **le nœud**.
    ///
    /// Deux emplois. Valeur d'initialisation des tableaux de foyers
    /// (`SessionFoyers`, `Configuration::adresses_braise`), le temps que les
    /// braises réelles soient dérivées. Et surtout **signataire nœud** : la
    /// braise que porte toute racine de l'arborescence ENU, et à quoi
    /// `feu-application` la reconnaît.
    ///
    /// Corps de 55 `a`, valide sans contrôle puisque `a` appartient à l'alphabet
    /// BASE32. Une valeur par défaut plutôt qu'un `Option` : le second imposerait
    /// un déballage à chaque lecture pour un cas qui n'arrive pas, les trois
    /// foyers étant dérivés dès la genèse.
    pub const VIDE: Braise = Braise([b'a'; Self::LONGUEUR]);
}

impl TryFrom<&str> for Braise {
    type Error = ErreurFeuNoyau;

    /// Valide une chaîne et la convertit en [`Braise`].
    ///
    /// La chaîne doit être la forme canonique complète : 55 caractères BASE32
    /// suivis du suffixe `.braise`.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::BraiseErronnee`] si le suffixe manque, si la longueur
    /// n'est pas `Braise::LONGUEUR`, ou si un caractère sort de l'alphabet BASE32.
    fn try_from(valeur: &str) -> ResultFeuNoyau<Self> {
        // coupe et exige le suffixe .braise
        let reste = valeur
            .strip_suffix(".braise")
            .ok_or(ErreurFeuNoyau::BraiseErronnee(valeur.to_string()))?;

        // 55 caractères, ni plus ni moins
        if reste.len() != Self::LONGUEUR {
            return Err(ErreurFeuNoyau::BraiseErronnee(valeur.to_string()));
        }

        // alphabet BASE32 minuscule : a-z et 2-7 (ni 0, 1, 8, 9)
        if !reste
            .bytes()
            .all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7'))
        {
            return Err(ErreurFeuNoyau::BraiseErronnee(valeur.to_string()));
        }

        // validé : ASCII et bonne taille → la conversion en tableau ne peut pas échouer
        Ok(Braise(reste.as_bytes().try_into().unwrap()))
    }
}

impl Display for Braise {
    /// Rend la forme canonique : les caractères stockés, puis le suffixe
    /// `.braise` que le type ne conserve pas.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // octets garantis ASCII par TryFrom → from_utf8 ne peut pas échouer
        let chars = str::from_utf8(&self.0).unwrap();
        write!(f, "{chars}.braise")
    }
}

impl Debug for Braise {
    /// Rend la forme canonique enveloppée du nom du type, le tableau d'octets
    /// nu étant illisible.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // délègue au Display
        write!(f, "Braise({self})")
    }
}

/// Position d'un foyer dans le nœud, bornée par construction.
///
/// Ne naît que d'un `TryFrom<usize>` qui refuse tout index atteignant
/// [`IndexFoyer::NOMBRE`] : indexer un tableau de foyers avec cette valeur reste
/// dans les bornes, sans nouveau contrôle à chaque accès.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IndexFoyer(usize);

impl IndexFoyer {
    /// Nombre de foyers d'un nœud, repris de [`MAX_FOYERS`].
    ///
    /// C'est un cardinal, pas un index : les positions valides s'arrêtent à
    /// `NOMBRE - 1`.
    pub const NOMBRE: usize = MAX_FOYERS;

    /// Retourne la position sous forme d'entier, pour indexer un tableau.
    pub fn valeur(self) -> usize {
        self.0
    }

    /// Retourne les positions valides, dans l'ordre croissant.
    ///
    /// Parcourt les foyers sans repasser par `TryFrom` sur des valeurs dont les
    /// bornes sont déjà connues.
    pub fn tous() -> impl Iterator<Item = Self> {
        (0..Self::NOMBRE).map(Self)
    }
}

impl TryFrom<usize> for IndexFoyer {
    type Error = ErreurFeuNoyau;

    /// Valide un entier et le convertit en [`IndexFoyer`].
    ///
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::IndexFoyerInvalide`] si `index` atteint ou dépasse
    /// [`IndexFoyer::NOMBRE`].
    fn try_from(index: usize) -> ResultFeuNoyau<Self> {
        (index < Self::NOMBRE)
            .then_some(Self(index))
            .ok_or(ErreurFeuNoyau::IndexFoyerInvalide(index))
    }
}

/// Position d'un classeur au sein d'un foyer, bornée par construction.
///
/// Même garantie que [`IndexFoyer`], sur une autre borne : les deux types ne
/// sont pas interchangeables, et un index de classeur ne peut pas désigner un
/// foyer par mégarde.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IndexClasseur(usize);

impl IndexClasseur {
    /// Nombre de classeurs d'un foyer, repris de [`MAX_CLASSEURS`].
    ///
    /// C'est un cardinal, pas un index : les positions valides s'arrêtent à
    /// `NOMBRE - 1`.
    pub const NOMBRE: usize = MAX_CLASSEURS;

    /// Retourne la position sous forme d'entier, pour indexer un tableau.
    pub fn valeur(self) -> usize {
        self.0
    }

    /// Retourne les positions valides, dans l'ordre croissant.
    ///
    /// Parcourt les classeurs sans repasser par `TryFrom` sur des valeurs dont
    /// les bornes sont déjà connues.
    pub fn tous() -> impl Iterator<Item = Self> {
        (0..Self::NOMBRE).map(Self)
    }
}

impl TryFrom<usize> for IndexClasseur {
    type Error = ErreurFeuNoyau;

    /// Valide un entier et le convertit en [`IndexClasseur`].
    ///
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::IndexClasseurInvalide`] si `index` atteint ou dépasse
    /// [`IndexClasseur::NOMBRE`].
    fn try_from(index: usize) -> ResultFeuNoyau<Self> {
        (index < Self::NOMBRE)
            .then_some(Self(index))
            .ok_or(ErreurFeuNoyau::IndexClasseurInvalide(index))
    }
}

/// Tests en ligne de [`Braise`] : la réciprocité de `try_from` et `Display`, et
/// les chaînes que la conversion refuse.
#[cfg(test)]
mod tests {
    use super::*;

    /// `try_from` puis `Display` redonnent la chaîne d'origine : les deux
    /// transformations sont réciproques (composée = identité).
    #[test]
    fn reciprocité_chaine() {
        let corps = "a".repeat(Braise::LONGUEUR);
        let braise = format!("{corps}.braise");

        let b = Braise::try_from(braise.as_str()).unwrap();

        assert_eq!(b.to_string(), braise);
    }

    /// Rejet d'une chaîne dépourvue du suffixe `.braise`.
    #[test]
    fn suffixe_absent() {
        let corps = "a".repeat(Braise::LONGUEUR);

        assert!(matches!(
            Braise::try_from(corps.as_str()).unwrap_err(),
            ErreurFeuNoyau::BraiseErronnee(_)
        ));
    }

    /// Rejet d'un corps plus court que `Braise::LONGUEUR`.
    #[test]
    fn corps_trop_court() {
        let corps = "a".repeat(Braise::LONGUEUR - 2);
        let braise = format!("{corps}.braise");

        assert!(matches!(
            Braise::try_from(braise.as_str()).unwrap_err(),
            ErreurFeuNoyau::BraiseErronnee(_)
        ));
    }

    /// Rejet d'un corps plus long que `Braise::LONGUEUR`.
    #[test]
    fn corps_trop_long() {
        let corps = "a".repeat(Braise::LONGUEUR + 2);
        let braise = format!("{corps}.braise");

        assert!(matches!(
            Braise::try_from(braise.as_str()).unwrap_err(),
            ErreurFeuNoyau::BraiseErronnee(_)
        ));
    }

    /// Rejet d'une majuscule : hors de l'alphabet BASE32 minuscule.
    #[test]
    fn corps_avec_masjuscule() {
        let corps = "a".repeat(Braise::LONGUEUR - 1);
        let braise = format!("A{corps}.braise");

        assert!(matches!(
            Braise::try_from(braise.as_str()).unwrap_err(),
            ErreurFeuNoyau::BraiseErronnee(_)
        ));
    }

    /// Rejet du chiffre `0` : hors de l'alphabet BASE32 (`2-7` seulement).
    #[test]
    fn corps_avec_0() {
        let corps = "a".repeat(Braise::LONGUEUR - 1);
        let braise = format!("0{corps}.braise");

        assert!(matches!(
            Braise::try_from(braise.as_str()).unwrap_err(),
            ErreurFeuNoyau::BraiseErronnee(_)
        ));
    }

    /// Rejet du chiffre `8` : hors de l'alphabet BASE32 (`2-7` seulement).
    #[test]
    fn corps_avec_8() {
        let corps = "a".repeat(Braise::LONGUEUR - 1);
        let braise = format!("8{corps}.braise");

        assert!(matches!(
            Braise::try_from(braise.as_str()).unwrap_err(),
            ErreurFeuNoyau::BraiseErronnee(_)
        ));
    }

    /// Rejet d'un caractère spécial (`@`) : hors de l'alphabet BASE32.
    #[test]
    fn corps_avec_caractere_special() {
        let corps = "a".repeat(Braise::LONGUEUR - 1);
        let braise = format!("@{corps}.braise");

        assert!(matches!(
            Braise::try_from(braise.as_str()).unwrap_err(),
            ErreurFeuNoyau::BraiseErronnee(_)
        ));
    }

    /// Rejet de la chaîne vide (ni suffixe, ni corps).
    #[test]
    fn chaine_vide() {
        let braise = String::from("");

        assert!(matches!(
            Braise::try_from(braise.as_str()).unwrap_err(),
            ErreurFeuNoyau::BraiseErronnee(_)
        ));
    }
}
