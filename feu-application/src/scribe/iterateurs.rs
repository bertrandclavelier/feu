// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Parcours d'une arborescence ENU.
//!
//! Deux axes : [`Descendants`] descend l'espace par les `hashs_enu`,
//! [`RacinesAnterieures`] remonte le temps par la méta `_racine`. Ils se
//! composent, et **naviguent sans jamais construire** — ni signature, ni
//! écriture.
//!
//! **Le descendant ne vérifie aucune signature**, pas même au départ :
//! l'arborescence étant un DAG de Merkle, recalculer le hash de la carte à
//! chaque pas chaîne l'intégrité de toute la descendance. **C'est ce qui permet
//! de parcourir un arbre foyer fermé** — les blobs, eux, restent illisibles.
//!
//! **Le remontant authentifie chaque pas** : il ne traverse que des racines,
//! signées par le nœud, dont la clé est connue dès l'allumage.
//!
//! Les deux rendent des [`Fiche`] — une vue, jamais une marque de confiance.
//! Parcours **paresseux** et sans cache.

use std::path::Path;

use data_encoding::HEXLOWER;
use feu_noyau::Braise;

use crate::{
    ErreurFeuApplication, ResultFeuApplication, SessionApplication, fiche::Fiche, scribe::enu::Enu,
};

/// Descend une arborescence ENU depuis une racine donnée, en profondeur d'abord.
///
/// Suit les `hashs_enu` de chaque [`Carte::Repertoire`](crate::Carte) ; les
/// feuilles sont rendues sans rien ouvrir. Aucun cycle possible.
///
/// **Profondeur d'abord**, par une pile, dans l'ordre trié du `BTreeSet` :
/// l'ordre dans lequel une arborescence se lit.
///
/// **Chaque item porte sa profondeur**, qui ne peut pas vivre dans la [`Fiche`] :
/// dans un DAG, la même ENU se rencontre à deux profondeurs.
///
/// **Les doublons sont conservés** — qui veut un inventaire déduplique chez lui,
/// l'inverse perdrait la structure réelle. Aucune session n'entre ici.
pub struct Descendants<'a> {
    /// Dossier `enu/` où sont lus les fichiers, propriété du
    /// [`Scribe`](super::Scribe).
    chemin_enu: &'a Path,
    /// Hashs restant à charger, chacun avec sa profondeur. Pile vide = parcours
    /// terminé.
    a_visiter: Vec<(usize, [u8; 32])>,
}

impl<'a> Iterator for Descendants<'a> {
    /// L'erreur est celle de l'API publique : `Descendants` traverse la
    /// frontière du crate, et [`ErreurFeuApplication`]
    /// est le seul type d'erreur qu'il expose.
    type Item = ResultFeuApplication<(usize, Fiche)>;

    /// Charge l'ENU suivante, empile ses enfants s'il y en a, et rend sa fiche
    /// avec sa profondeur.
    ///
    /// Le hash tiré de la pile vient de la carte du parent, déjà vérifiée : le
    /// comparer à l'empreinte recalculée ajoute un maillon à la chaîne
    /// d'intégrité.
    ///
    /// **Un échec de chargement n'arrête pas le parcours** : l'erreur est rendue
    /// comme un item et la pile reste intacte. Seule la branche fautive est
    /// perdue, faute de connaître ses enfants. L'appelant qui préfère s'arrêter
    /// au premier échec écrit `collect::<Result<Vec<_>, _>>()`.
    fn next(&mut self) -> Option<Self::Item> {
        let (profondeur, hash) = self.a_visiter.pop()?;

        match Enu::charger_sans_verification_signature(self.chemin_enu, &hash) {
            Err(e) => Some(Err(e)),

            Ok(enu) => {
                if let Some(hashs_enu) = enu.carte().hashs_enu() {
                    self.a_visiter
                        .extend(hashs_enu.iter().rev().map(|hash| (profondeur + 1, *hash)));
                }

                Some(Ok((profondeur, Fiche::new(&enu))))
            }
        }
    }
}

impl<'a> Descendants<'a> {
    /// Prépare le parcours sans rien lire — seul `next` déclenche un chargement.
    ///
    /// **Le point de départ n'est ni authentifié ni contrôlé**, par choix : c'est
    /// ce qui permet de descendre un arbre dont le foyer est fermé, et le premier
    /// `next` dira de toute façon si l'empreinte ne retombe pas sur `hash_carte`.
    ///
    /// **L'ENU de départ fait partie du parcours**, à la profondeur 0 : un
    /// chargement de plus contre un sous-arbre couvert en entier, ce qu'exige
    /// l'inventaire des foyers avant un retrait.
    ///
    /// `pub(crate)` parce que `chemin_enu` est privé au
    /// [`Scribe`](super::Scribe) : l'emplacement du dépôt ne sort pas du crate.
    pub(crate) fn new(chemin_enu: &'a Path, hash_carte: &[u8; 32]) -> Self {
        Self {
            chemin_enu,
            a_visiter: Vec::from([(0, *hash_carte)]),
        }
    }
}

/// Remonte les racines du nœud, de la plus récente vers la genèse.
///
/// Suit la méta `_racine`, par laquelle chaque racine désigne celle qu'elle a
/// remplacée : une liste chaînée, ni file ni déduplication, contrairement au DAG
/// de [`Descendants`].
///
/// **La racine de départ fait partie du parcours** — le nom dit l'axe, pas une
/// garantie d'antériorité du premier item.
///
/// L'arrêt se fait sur la genèse, dont la méta `_racine` est **vide, pas
/// absente**.
pub struct RacinesAnterieures<'a> {
    /// Dossier `enu/` où sont lus les fichiers, propriété du
    /// [`Scribe`](super::Scribe).
    chemin_enu: &'a Path,
    /// Session interrogée à chaque pas pour authentifier la racine chargée.
    session: &'a SessionApplication,
    /// Racine restant à charger. `None` = parcours terminé, que ce soit par la
    /// genèse ou par un échec.
    hash_suivant: Option<[u8; 32]>,
}

impl<'a> Iterator for RacinesAnterieures<'a> {
    /// L'erreur est celle de l'API publique, comme pour [`Descendants`].
    type Item = ResultFeuApplication<Fiche>;

    /// Rend la racine suivante, ou l'échec rencontré en la chargeant.
    ///
    /// **Une erreur termine le parcours**, contrairement au descendant qui perd
    /// une branche et continue sur sa file. Rien à décider ici : la racine
    /// précédente n'est connue que par la méta de celle qu'on n'a pas pu lire,
    /// il n'y a donc plus de chaîne à suivre. `take` vide le champ avant le
    /// chargement — l'arrêt en découle sans une ligne de plus.
    fn next(&mut self) -> Option<Self::Item> {
        let hash = self.hash_suivant.take()?;

        Some(self.charge_et_avance(&hash))
    }
}

impl<'a> RacinesAnterieures<'a> {
    /// Prépare le parcours sans rien lire ni rien vérifier.
    ///
    /// **Infaillible, comme [`Descendants::new`]** : il n'y a pas de point de
    /// départ à authentifier, `charge_et_avance` chargeant la racine de
    /// `hash_carte` par [`Enu::charger`](super::enu::Enu) au premier `next`, avec
    /// les mêmes contrôles qu'aux suivantes. Le hash n'est pas davantage
    /// contrôlé : s'il ne correspond pas à sa carte, le chargement le dira.
    ///
    /// `pub(crate)` pour la même raison que [`Descendants::new`] — `chemin_enu`
    /// est un champ privé du [`Scribe`](super::Scribe).
    pub(crate) fn new(
        chemin_enu: &'a Path,
        session: &'a SessionApplication,
        hash_carte: &[u8; 32],
    ) -> Self {
        Self {
            chemin_enu,
            session,
            hash_suivant: Some(*hash_carte),
        }
    }

    /// Charge la racine de `hash` et arme le pas suivant à partir de sa méta
    /// `_racine`.
    ///
    /// Existe parce que `next` ne peut pas porter de `?` : il rend un
    /// `Option<Result<…>>`, où l'opérateur propagerait l'absence et non l'échec.
    ///
    /// Deux contrôles s'ajoutent à [`Enu::charger`](super::enu::Enu) : braise vide
    /// et méta `_racine` présente — une ENU de contenu atteinte par ce chemin
    /// serait une anomalie de la chaîne des versions.
    ///
    /// `hash_suivant` n'est réarmé que si la méta est non vide, la genèse
    /// terminant ainsi le parcours au tour suivant.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeEnuRacineAttendue`] si la racine
    /// n'en est pas une ou si sa méta `_racine` n'est pas un hash de 32 octets,
    /// [`ErreurFeuApplication::DecodeError`] si elle n'est pas de l'hexadécimal,
    /// et propage les refus de [`Enu::charger`](super::enu::Enu).
    fn charge_et_avance(&mut self, hash: &[u8; 32]) -> ResultFeuApplication<Fiche> {
        let enu = Enu::charger(self.chemin_enu, self.session, hash)?;

        if enu.braise() != Braise::VIDE {
            return Err(ErreurFeuApplication::ScribeEnuRacineAttendue);
        }
        let Some(hash_string) = enu.carte().metas().get("_racine") else {
            return Err(ErreurFeuApplication::ScribeEnuRacineAttendue);
        };
        if !hash_string.is_empty() {
            self.hash_suivant = Some(
                HEXLOWER
                    .decode(hash_string.as_bytes())?
                    .try_into()
                    .map_err(|_| ErreurFeuApplication::ScribeEnuRacineAttendue)?,
            )
        }

        Ok(Fiche::new(&enu))
    }
}
