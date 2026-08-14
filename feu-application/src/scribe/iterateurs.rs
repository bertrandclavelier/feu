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
//! **Le parcours ne vérifie aucune signature.** Il n'authentifie que son point
//! de départ, puis ne recalcule à chaque pas que le hash de la carte
//! ([`Enu::integre`](super::enu::Enu)) : l'arborescence est un DAG de Merkle,
//! une carte de répertoire portant les `hashs_enu` de ses enfants. Partir d'une
//! ENU authentifiée et vérifier le hash annoncé à chaque descente chaîne donc
//! l'intégrité de toute la descendance, pour **une** vérification ML-DSA-87 au
//! lieu d'une par ENU traversée — ce qui rend praticable l'usage visé, ouvrir
//! beaucoup d'ENU pour afficher une arborescence.
//!
//! **Une ENU rendue par un itérateur n'engage donc rien.** Tout ce qui agit sur
//! un blob — lecture, suppression, description, retrait sur le disque — la
//! repasse par [`Enu::authentique`](super::enu::Enu). Il n'existe pas de type
//! distinct pour la marquer : la confiance vient de la vérification, pas de
//! l'encapsulation. La `braise` reste hors garantie, couverte ni par le hash ni
//! par la signature.
//!
//! Le parcours est **paresseux** : rien n'est lu avant l'appel à `next`, et
//! l'itérateur ne conserve aucune des ENU qu'il a rendues. Qui veut la
//! collection appelle `collect`, qui cherche une entrée s'arrête en chemin sans
//! avoir payé le reste de l'arbre. Aucun cache ici : sa cohérence serait à tenir
//! sans rien savoir de l'usage.

use std::{collections::VecDeque, path::Path};

use crate::{Enu, ErreurFeuApplication, ResultFeuApplication, SessionApplication};

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
/// pas survivre au Scribe dont il tient le chemin. La session
/// n'est requise qu'à la construction, pour authentifier le point de départ —
/// les pas suivants ne consultent aucune clé, l'itérateur n'a donc rien à en
/// retenir.
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
    type Item = ResultFeuApplication<Enu>;

    /// Charge l'ENU suivante et empile ses enfants s'il y en a.
    ///
    /// Le hash tiré de la file vient de la carte du parent, déjà vérifiée : c'est
    /// lui que [`Enu::charger_sans_verification_signature`](super::enu::Enu)
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

                Some(Ok(enu))
            }
        }
    }
}

impl<'a> Descendants<'a> {
    /// Authentifie le point de départ, puis prépare le parcours sans rien lire —
    /// seul `next` déclenche un chargement.
    ///
    /// **C'est ici que se paie la seule vérification de signature du parcours**, et
    /// elle n'est pas optionnelle : le chaînage de Merkle ne vaut que par son
    /// origine. Sans elle, un appelant pourrait relancer un parcours depuis une
    /// ENU issue d'un parcours précédent, et toute la descendance serait chaînée
    /// à un point que rien n'a jamais authentifié. Le hash de l'enveloppe est
    /// vérifié d'abord — c'est lui qui amorce la file, il ne peut pas mentir sur
    /// la carte qui vient d'être signée.
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
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::ScribeEnuNonIntegre`] si l'enveloppe ne
    /// s'accorde pas avec sa carte, [`ErreurFeuApplication::ScribeEnuNonAuthentique`]
    /// si la signature n'est pas validée, et propage les refus de
    /// [`Enu::authentique`](super::enu::Enu) — braise inconnue, foyer sans clé.
    pub(crate) fn new(
        chemin_enu: &'a Path,
        session: &'a SessionApplication,
        enu: &Enu,
    ) -> ResultFeuApplication<Self> {
        if !enu.integre(&enu.hash_carte()) {
            return Err(ErreurFeuApplication::ScribeEnuNonIntegre);
        }
        if !enu.authentique(session)? {
            return Err(ErreurFeuApplication::ScribeEnuNonAuthentique);
        }

        Ok(Self {
            chemin_enu,
            a_visiter: VecDeque::from([enu.hash_carte()]),
        })
    }
}
