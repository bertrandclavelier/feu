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
//! [`IndexClasseur`] une position bornée. Aucun ne se construit sans contrôle :
//! un `TryFrom` qui valide, ou une constante dont la valeur est vérifiée à
//! l'écriture — [`Braise::VIDE`], [`IndexFoyer::ZERO`]. Leur existence vaut
//! garantie. Les deux index sont des types distincts et ne se substituent pas
//! l'un à l'autre.
//!
//! L'apport est la **rigueur** (un état mal formé est inconstructible) et
//! l'**ergonomie** (valeurs `Copy`, sans allocation), pas la sécurité : la
//! confiance dans une braise vient de sa résolution vers un foyer connu et de la
//! signature, jamais de son type.

use core::fmt;
use std::fmt::{Debug, Display};

use crate::{ErreurFeuNoyau, NOMBRE_CLASSEURS, NOMBRE_FOYERS, ResultFeuNoyau};

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
/// Ne naît que de [`IndexFoyer::ZERO`] ou d'un `TryFrom<usize>` qui refuse tout
/// index atteignant [`IndexFoyer::NOMBRE`] : indexer un tableau de foyers avec
/// cette valeur reste dans les bornes, sans nouveau contrôle à chaque accès.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct IndexFoyer(usize);

impl IndexFoyer {
    /// Nombre de foyers d'un nœud.
    ///
    /// C'est un cardinal, pas un index : les positions valides s'arrêtent à
    /// `NOMBRE - 1`.
    pub const NOMBRE: usize = NOMBRE_FOYERS;

    /// Premier foyer du nœud.
    ///
    /// Toujours valide — un nœud compte au moins un foyer —, donc lisible en
    /// `const`, là où `TryFrom` impose un `Result` à déballer.
    pub const ZERO: Self = Self(0);

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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct IndexClasseur(usize);

impl IndexClasseur {
    /// Nombre de classeurs d'un foyer.
    ///
    /// C'est un cardinal, pas un index : les positions valides s'arrêtent à
    /// `NOMBRE - 1`.
    pub const NOMBRE: usize = NOMBRE_CLASSEURS;

    /// Premier classeur du foyer.
    ///
    /// Toujours valide — un foyer compte au moins un classeur —, donc lisible en
    /// `const`, là où `TryFrom` impose un `Result` à déballer.
    pub const ZERO: Self = Self(0);

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

/// Tests en ligne des trois types : la réciprocité de `try_from` et `Display`
/// sur [`Braise`], les valeurs que chaque conversion refuse, et le parcours des
/// index.
#[cfg(test)]
mod tests {
    use proptest::{prop_assert, prop_assert_eq, prop_assume, proptest};

    use super::*;

    proptest! {
            /// Toute adresse bien formée ressort identique : sur l'alphabet entier,
            /// `try_from` et `Display` restent réciproques.
            #[test]
            fn reciprocité_chaine(corps in "[a-z2-7]{55}") {
                let adresse = format!("{corps}.braise");

                let braise = Braise::try_from(adresse.as_str()).unwrap();

                prop_assert_eq!(braise.to_string(), adresse);
            }

            /// Aucune chaîne, valide ou non, ne fait paniquer la conversion : les
            /// `unwrap` du chemin de validation restent hors d'atteinte.
            #[test]
            fn jamais_de_panique(chaine in ".{0,80}") {

                let _ = Braise::try_from(chaine.as_str());
            }

            /// Rejet d'un caractère hors alphabet BASE32, à n'importe quelle position.
            #[test]
            fn hors_alphabet(corps in "[a-z2-7]{55}", pos in 0..55usize, intrus in "[^a-z2-7]") {
                let mut corps = corps;
                corps.replace_range(pos..pos + 1, &intrus);
                let adresse = format!("{corps}.braise");

                prop_assert!(Braise::try_from(adresse.as_str()).is_err());
            }

            /// Rejet de tout corps dont la longueur n'est pas `Braise::LONGUEUR`.
            #[test]
            fn longueur_erronee(corps in "[a-z2-7]{0,120}") {
                prop_assume!(corps.len() != Braise::LONGUEUR);
                let adresse = format!("{corps}.braise");

                prop_assert!(Braise::try_from(adresse.as_str()).is_err());
            }

            /// Rejet de tout suffixe autre que `.braise`, absence comprise.
            #[test]
            fn suffixe_erroné(corps in "[a-z2-7]{55}", suffixe in "[a-z.]{0,8}") {
                prop_assume!(suffixe != ".braise");
                let adresse = format!("{corps}{suffixe}");
                prop_assert!(Braise::try_from(adresse.as_str()).is_err());
            }
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

    /// `Braise::VIDE`, construite sans passer par `TryFrom`, est bien formée.
    #[test]
    fn braise_vide() {
        assert!(Braise::try_from(Braise::VIDE.to_string().as_str()).is_ok());
    }

    proptest! {

        /// Rejet de tout entier atteignant ou dépassant `IndexFoyer::NOMBRE`.
        #[test]
        fn index_foyer_hors_bornes(n in IndexFoyer::NOMBRE..) {
            prop_assert!(IndexFoyer::try_from(n).is_err());
        }

        /// Rejet de tout entier atteignant ou dépassant `IndexClasseur::NOMBRE`.
        #[test]
        fn index_classeur_hors_bornes(n in IndexClasseur::NOMBRE..) {
            prop_assert!(IndexClasseur::try_from(n).is_err());
        }
    }

    /// `tous()` rend les positions valides dans l'ordre croissant, à partir de zéro.
    #[test]
    fn index_foyer_tous() {
        assert_eq!(IndexFoyer::tous().count(), IndexFoyer::NOMBRE);

        for (i, index_foyer) in IndexFoyer::tous().enumerate() {
            assert_eq!(index_foyer.valeur(), i);
        }
    }

    /// `tous()` rend les positions valides dans l'ordre croissant, à partir de zéro.
    #[test]
    fn index_classeur_tous() {
        assert_eq!(IndexClasseur::tous().count(), IndexClasseur::NOMBRE);

        for (i, index_classeur) in IndexClasseur::tous().enumerate() {
            assert_eq!(index_classeur.valeur(), i);
        }
    }
}
