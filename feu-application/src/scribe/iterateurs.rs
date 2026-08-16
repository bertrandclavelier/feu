// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Parcours d'une arborescence ENU.
//!
//! Deux axes, deux itérateurs : [`Descendants`] descend l'espace en suivant les
//! `hashs_enu` d'une arborescence, [`RacinesAnterieures`] remonte le temps de
//! racine en racine par la méta `_racine`. Ils se composent — le descendant
//! lancé sur chaque racine rendue par le remontant dit ce que contenait l'arbre
//! à cette version-là.
//!
//! Ces itérateurs **naviguent, ils ne construisent jamais**. Ils ne signent
//! rien, n'écrivent rien, ne remontent aucune modification : les fonctions qui
//! bâtissent l'arborescence ([`remplacer`](super::enu::Enu) et la greffe
//! d'enfants) ou la déposent sur le disque gardent leur récursion, parce
//! qu'elles portent un état de construction qu'un parcours ne peut pas porter.
//!
//! **Le descendant ne vérifie aucune signature**, pas même celle de son point de
//! départ. Il ne recalcule à chaque pas que le hash de la carte
//! ([`Enu::integre`](super::enu::Enu)) : l'arborescence est un DAG de Merkle,
//! une carte de répertoire portant les `hashs_enu` de ses enfants. Vérifier le
//! hash annoncé à chaque descente chaîne donc l'intégrité de toute la
//! descendance à la carte de départ, sans une seule vérification ML-DSA-87 — ce
//! qui rend praticable l'usage visé, ouvrir beaucoup d'ENU pour afficher une
//! arborescence.
//!
//! **C'est ce qui permet de parcourir un arbre foyer fermé.** Une ENU de contenu
//! est signée par son foyer, dont la session ne détient la clé publique qu'après
//! une ouverture : exiger une authentification, ne serait-ce qu'au départ,
//! interdirait de descendre quoi que ce soit sans ouvrir le foyer. Le parcours
//! est une navigation, pas un accès au contenu — les blobs, eux, restent
//! illisibles.
//!
//! **Les deux itérateurs rendent des [`Fiche`]** : l'ENU du pas courant est
//! projetée puis relâchée, sa signature ne quitte pas le crate. Rien de ce qui
//! sort n'engage un blob — lecture, suppression, description, retrait rechargent
//! l'ENU et la repassent par [`Enu::authentique`](super::enu::Enu). La fiche est
//! une vue, pas une marque de confiance : celle-ci vient de la vérification, pas
//! de l'encapsulation. La `braise` reste hors garantie, couverte ni par le hash
//! ni par la signature.
//!
//! **Le remontant, lui, authentifie chaque pas** ([`Enu::charger`](super::enu::Enu)).
//! Ce qu'il traverse n'est pas de la même nature : des racines, toutes signées
//! par le nœud, dont la session tient la clé publique dès l'allumage — là où le
//! descendant croise des ENU de foyers, possiblement fermés, et bien plus
//! nombreuses. Rien ne lui coûte donc ce que le descendant a écarté.
//!
//! Le parcours est **paresseux** : rien n'est lu avant l'appel à `next`, et
//! l'itérateur ne conserve aucune des fiches qu'il a rendues. Qui veut la
//! collection appelle `collect`, qui cherche une entrée s'arrête en chemin sans
//! avoir payé le reste de l'arbre. Aucun cache ici : sa cohérence serait à tenir
//! sans rien savoir de l'usage.

use std::{collections::VecDeque, path::Path};

use data_encoding::HEXLOWER;
use feu_noyau::BRAISE_VIDE;

use crate::scribe::enu::Enu;
use crate::{ErreurFeuApplication, ResultFeuApplication, SessionApplication, fiche::Fiche};

/// Descend une arborescence ENU depuis une racine donnée, en largeur d'abord.
///
/// Suit les `hashs_enu` de chaque [`Carte::Repertoire`](crate::Carte) rencontrée.
/// Les feuilles ([`Carte::Donnee`](crate::Carte), [`Carte::Texte`](crate::Carte))
/// n'ouvrent rien : elles sont rendues et le parcours continue. Aucun cycle
/// n'est possible, le hash d'une ENU dérivant de son contenu.
///
/// **Largeur d'abord** : `a_visiter` est une file, les enfants passent après
/// tous les nœuds déjà en attente. L'ordre est déterministe — les `hashs_enu`
/// viennent d'un `BTreeSet`, donc triés, et rien d'autre n'influe sur la
/// séquence.
///
/// **Les doublons sont conservés.** L'arborescence est un DAG : un sous-arbre
/// identique peut être l'enfant de plusieurs répertoires, et il sera alors rendu
/// une fois par parent. C'est le flux le plus général — l'appelant qui veut un
/// inventaire déduplique avec un ensemble des hashs déjà vus, alors qu'un flux
/// déjà dédupliqué aurait perdu pour de bon la structure réelle de l'arbre.
///
/// La durée de vie `'a` est celle du dossier emprunté : un `Descendants` ne peut
/// pas survivre au Scribe dont il tient le chemin. Aucune session n'entre ici,
/// ni à la construction ni pendant le parcours — rien n'y consulte de clé.
pub struct Descendants<'a> {
    /// Dossier `enu/` où sont lus les fichiers, propriété du
    /// [`Scribe`](super::Scribe).
    chemin_enu: &'a Path,
    /// Hashs restant à charger, en attente. File vide = parcours terminé.
    a_visiter: VecDeque<[u8; 32]>,
}

impl<'a> Iterator for Descendants<'a> {
    /// L'erreur est celle de l'API publique : `Descendants` traverse la
    /// frontière du crate, et [`ErreurFeuApplication`](crate::ErreurFeuApplication)
    /// est le seul type d'erreur qu'il expose.
    type Item = ResultFeuApplication<Fiche>;

    /// Charge l'ENU suivante, empile ses enfants s'il y en a, et rend sa fiche.
    ///
    /// Le hash tiré de la file vient de la carte du parent, déjà vérifiée : c'est
    /// lui que `Enu::charger_sans_verification_signature`
    /// compare à l'empreinte recalculée, et le maillon de plus dans la chaîne
    /// d'intégrité. Aucune signature n'est vérifiée ici.
    ///
    /// **Un échec de chargement n'arrête pas le parcours** : l'erreur est rendue
    /// comme un item ordinaire et la file reste intacte pour le pas suivant.
    /// C'est ce que permet la forme `Option<Result<…>>` — seul `None` termine,
    /// le `Result` ne parle que de l'élément courant. L'appelant qui préfère
    /// s'arrêter au premier échec l'obtient sans une ligne de code ici, avec
    /// `collect::<Result<Vec<_>, _>>()`.
    ///
    /// Sur erreur, la branche est perdue : sans la carte, il n'y a pas d'enfants
    /// à connaître. Le reste de l'arbre, lui, continue d'être parcouru.
    ///
    /// Une feuille rend `None` et n'ouvre rien : ce n'est pas un incident de
    /// parcours, et `Carte::hashs_enu` le dit sans fabriquer d'erreur ni cloner
    /// l'ensemble.
    fn next(&mut self) -> Option<Self::Item> {
        let hash = self.a_visiter.pop_front()?;

        match Enu::charger_sans_verification_signature(self.chemin_enu, &hash) {
            Err(e) => Some(Err(e)),

            Ok(enu) => {
                if let Some(hashs_enu) = enu.carte().hashs_enu() {
                    self.a_visiter.extend(hashs_enu);
                }

                Some(Ok(Fiche::new(&enu)))
            }
        }
    }
}

impl<'a> Descendants<'a> {
    /// Prépare le parcours sans rien lire — seul `next` déclenche un chargement.
    ///
    /// **Le point de départ n'est pas authentifié**, par choix : c'est ce qui
    /// permet de descendre un arbre dont le foyer est fermé, l'usage visé. Une
    /// fiche n'engage rien sur les blobs — pour en manipuler un, l'ENU est
    /// rechargée et authentifiée.
    ///
    /// Son intégrité n'est pas davantage contrôlée : le chargement du premier pas
    /// compare l'empreinte recalculée à `hash_carte`, et le vérifier d'avance
    /// n'avancerait l'erreur que d'un tour, au prix d'un `Result` sur une
    /// construction qui pose deux champs.
    ///
    /// **L'ENU de départ fait partie du parcours** : son hash est le premier de
    /// la file, elle sera donc relue avant d'être rendue. Le coût est un
    /// chargement de plus ; en échange le parcours couvre réellement tout le
    /// sous-arbre, racine comprise, ce dont a besoin qui veut inventorier les
    /// foyers d'un arbre avant de le retirer.
    ///
    /// `pub(crate)` et non `pub` : `chemin_enu` est un champ privé du
    /// [`Scribe`](super::Scribe), qu'aucun appelant extérieur ne peut fournir —
    /// l'emplacement du dépôt sur le disque n'a pas à sortir du crate. Le point
    /// d'entrée public est une commande de [`FeuApplication`](crate::FeuApplication).
    pub(crate) fn new(chemin_enu: &'a Path, hash_carte: &[u8; 32]) -> Self {
        Self {
            chemin_enu,
            a_visiter: VecDeque::from([*hash_carte]),
        }
    }
}

/// Remonte les racines du nœud, de la plus récente vers la genèse.
///
/// Suit la méta `_racine`, que chaque racine porte pour désigner celle qu'elle a
/// remplacée. C'est une liste chaînée, pas un arbre : un seul successeur par pas,
/// ni file ni déduplication — le contraire de [`Descendants`], qui parcourt un
/// DAG et doit tenir plusieurs branches en attente.
///
/// **La racine de départ fait partie du parcours**, comme chez [`Descendants`] :
/// elle est rechargée avant d'être rendue. Le nom dit l'axe du parcours, pas une
/// garantie que le premier item soit antérieur à quoi que ce soit.
///
/// Le parcours s'arrête sur la genèse, que rien ne précède : sa méta `_racine`
/// est **vide, pas absente** (`Enu::new_racine`, cas `None`).
///
/// La durée de vie `'a` couvre les deux emprunts : un `RacinesAnterieures` ne
/// survit ni au Scribe dont il tient le chemin, ni à la session dont il tire la
/// clé de vérification à chaque pas.
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
    /// Tient tout le travail de `next`, qui ne peut pas l'écrire lui-même : `?`
    /// ne s'applique qu'à un type de retour homogène, et `next` rend un
    /// `Option<Result<…>>` où il propagerait l'absence, pas l'échec.
    ///
    /// Deux contrôles s'ajoutent à ceux de [`Enu::charger`](super::enu::Enu) :
    /// braise vide et méta `_racine` présente. Une ENU de contenu atteinte par
    /// ce chemin serait une anomalie de la chaîne des versions, pas un contenu à
    /// rendre.
    ///
    /// `hash_suivant` n'est réarmé que si la méta est non vide — vide, c'est la
    /// genèse, et le champ reste `None`, ce qui termine le parcours au tour
    /// suivant.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::ScribeEnuRacineAttendue`] si la racine
    /// n'en est pas une ou si sa méta `_racine` n'est pas un hash de 32 octets,
    /// [`ErreurFeuApplication::DecodeError`] si elle n'est pas de l'hexadécimal,
    /// et propage les refus de [`Enu::charger`](super::enu::Enu).
    fn charge_et_avance(&mut self, hash: &[u8; 32]) -> ResultFeuApplication<Fiche> {
        let enu = Enu::charger(self.chemin_enu, self.session, hash)?;

        if enu.braise() != BRAISE_VIDE {
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
