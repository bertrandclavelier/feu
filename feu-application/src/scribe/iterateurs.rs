// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Parcours d'une arborescence ENU.
//!
//! Ces itérateurs **naviguent, ils ne construisent jamais**. Ils ne signent
//! rien, n'écrivent rien, ne remontent aucune modification : les fonctions qui
//! bâtissent l'arborescence ([`remplacer`](super::enu::Enu) et la greffe
//! d'enfants) ou la déposent sur le disque gardent leur récursion, parce
//! qu'elles portent un état de construction qu'un parcours ne peut pas porter.
//!
//! Chaque pas passe par [`Enu::charger`](super::enu::Enu), donc **chaque ENU
//! rendue est authentifiée** — hash de carte recalculé et signature vérifiée
//! contre la clé publique du signataire tenue par la
//! [`SessionApplication`]. Un parcours ne rend jamais un contenu non vérifié.
//!
//! Le parcours est **paresseux** : rien n'est lu avant l'appel à `next`, et
//! l'itérateur ne conserve aucune des ENU qu'il a rendues. Qui veut la
//! collection appelle `collect`, qui cherche une entrée s'arrête en chemin sans
//! avoir payé le reste de l'arbre. Aucun cache ici : sa cohérence serait à tenir
//! sans rien savoir de l'usage.

use std::{collections::VecDeque, path::Path};

use crate::{Enu, ResultFeuApplication, SessionApplication};

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
/// La durée de vie `'a` est celle des deux emprunts : un `Descendants` ne peut
/// pas survivre à la session dont il tire les clés de vérification.
pub struct Descendants<'a> {
    /// Dossier `enu/` où sont lus les fichiers, propriété du
    /// [`Scribe`](super::Scribe).
    chemin_enu: &'a Path,
    /// Session interrogée à chaque pas pour authentifier l'ENU chargée.
    session: &'a SessionApplication,
    /// Hashs restant à charger, en attente. File vide = parcours terminé.
    a_visiter: VecDeque<[u8; 32]>,
}

impl<'a> Iterator for Descendants<'a> {
    /// L'erreur est celle de l'API publique : `Descendants` traverse la
    /// frontière du crate, et [`ErreurFeuApplication`](crate::ErreurFeuApplication)
    /// est le seul type d'erreur qu'il expose.
    type Item = ResultFeuApplication<Enu>;

    /// Charge l'ENU suivante et empile ses enfants s'il y en a.
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

        match Enu::charger(self.chemin_enu, self.session, &hash) {
            Err(e) => Some(Err(e)),

            Ok(enu) => {
                if let Some(hashs_enu) = enu.carte().hashs_enu() {
                    self.a_visiter.extend(hashs_enu);
                }

                Some(Ok(enu))
            }
        }
    }
}

impl<'a> Descendants<'a> {
    /// Prépare le parcours sans rien lire — seul `next` déclenche un chargement.
    ///
    /// **L'ENU de départ fait partie du parcours** : son hash est le premier de
    /// la file, elle sera donc rechargée et réauthentifiée avant d'être rendue.
    /// Le coût est un chargement de plus ; en échange le parcours couvre
    /// réellement tout le sous-arbre, racine comprise, ce dont a besoin qui
    /// veut inventorier les foyers d'un arbre avant de le retirer.
    ///
    /// `pub(crate)` et non `pub` : `chemin_enu` est un champ privé du
    /// [`Scribe`](super::Scribe), qu'aucun appelant extérieur ne peut fournir —
    /// l'emplacement du dépôt sur le disque n'a pas à sortir du crate. Le point
    /// d'entrée public est une commande de [`FeuApplication`](crate::FeuApplication).
    pub(crate) fn new(chemin_enu: &'a Path, session: &'a SessionApplication, enu: &Enu) -> Self {
        Self {
            chemin_enu,
            session,
            a_visiter: VecDeque::from([enu.hash_carte()]),
        }
    }
}
