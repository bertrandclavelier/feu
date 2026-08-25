// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! État des comptoirs du [`Scribe`], porté sur le disque.
//!
//! Un comptoir survit à la fermeture de Feu : on relance, on le retrouve, on
//! peut le fermer. Ce module tient le miroir en mémoire du fichier, comme le
//! gardien de `feu-noyau` tient celui de `noyau.feu`.
//!
//! De quoi rouvrir un comptoir, rien de plus : un dépôt donne son identifiant,
//! son dossier et sa destination, le comptoir de travail son dossier et le
//! `hash_carte` de la racine sortie. L'arbre est adressé par contenu, ce hash
//! suffit donc à recharger l'ENU et à en refaire une [`Fiche`](super::Fiche).

use std::path::PathBuf;

use crate::{Scribe, scribe::VERSION_CONFIGURATION};

/// Miroir en mémoire du fichier de configuration du [`Scribe`].
///
/// Les comptoirs y sont des tuples et non des types nommés, par symétrie avec
/// le miroir de [`SessionApplication`](crate::SessionApplication), qui porte le
/// même découpage.
///
/// `Debug` et `PartialEq` ne servent qu'aux assertions des tests.
#[derive(Debug, PartialEq)]
struct Configuration {
    /// Version du format du fichier, écrite en tête et relue au chargement.
    version: u32,
    /// Un comptoir de dépôt ouvert par entrée : identifiant, dossier, foyer et
    /// classeur de destination.
    comptoirs_depot: Vec<(usize, PathBuf, usize, usize)>,
    /// Dossier du comptoir de travail et `hash_carte` de la racine sortie, au
    /// plus un — [`Option`] comme le champ du [`Scribe`] qu'il reflète.
    comptoir_travail: Option<(PathBuf, [u8; 32])>,
}

impl Configuration {
    /// Relève l'état des comptoirs du [`Scribe`].
    ///
    /// L'ordre des dépôts suit celui de la `HashMap`, donc aucun : chaque
    /// entrée porte son identifiant, la relecture n'a pas à s'y fier.
    fn new(scribe: &Scribe) -> Self {
        let comptoirs_depot: Vec<_> = scribe
            .comptoirs_depot
            .iter()
            .map(|(index, comptoir)| {
                (
                    *index,
                    comptoir.chemin().clone(),
                    comptoir.index_foyer(),
                    comptoir.index_classeur(),
                )
            })
            .collect();

        let comptoir_travail = scribe.comptoir_travail.as_ref().map(|comptoir| {
            (
                comptoir.chemin().clone(),
                comptoir.fiche_racine().hash_carte(),
            )
        });

        Self {
            version: VERSION_CONFIGURATION,
            comptoirs_depot,
            comptoir_travail,
        }
    }
}
