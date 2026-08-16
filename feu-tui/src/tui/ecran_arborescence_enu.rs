// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Écran d'arborescence des ENU.
//!
//! Le circuit est complet — `Tab` y mène depuis le pilotage, `R` demande
//! l'arbre au cœur, qui le renvoie et qu'on garde —, mais **rien n'est encore
//! dessiné** : l'écran affiche un carré vide. Le raccordement d'abord, le
//! contenu ensuite.
//!
//! **Le chargement est explicite, jamais automatique.** Arriver sur l'écran ne
//! déclenche rien : le parcours lit un fichier par ENU de l'arbre, et ce coût
//! se décide. En contrepartie l'arbre survit aux allers-retours par `Tab`, et
//! peut donc être périmé — un dépôt crée une nouvelle racine que l'écran ne
//! voit pas tant que `R` n'est pas rappuyé.
//!
//! Les transitions `vers_*` du pilotage n'ont pas d'équivalent ici : `Tab`
//! suffit à entrer, et `passer_ecran_suivant` tient le cycle.

use feu_application::fiche::Fiche;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    widgets::Block,
};

use crate::tui::{EtatTui, rendu::Dimensions};

/// Dimensions du carré de l'écran, identiques à celles du pilotage.
///
/// Le cadre ne bouge pas d'un écran de travail à l'autre : `Tab` change ce qui
/// est dedans, pas la fenêtre.
const DIMENSIONS_ECRAN_ENU: Dimensions = Dimensions {
    largeur: 70,
    hauteur: 35,
};

/// Ce que l'écran d'arborescence retient d'une frame à l'autre.
///
/// L'arbre chargé pour l'instant ; le curseur, les nœuds dépliés et le
/// défilement viendront ici.
pub(super) struct EtatArborescenceEnu {
    /// Le dernier arbre reçu du cœur, à plat et en largeur d'abord.
    ///
    /// `None` ne veut pas dire « arbre vide » mais **jamais demandé** — c'est
    /// lui qui distingue l'écran au premier abord d'un nœud sans contenu, et
    /// qui décidera lequel des deux messages afficher.
    pub(super) arborescence_enus: Option<Vec<Fiche>>,
}

impl EtatArborescenceEnu {
    /// État initial : aucun chargement demandé.
    pub(super) fn new() -> Self {
        Self {
            arborescence_enus: None,
        }
    }
}

/// Dessine le cadre de l'écran, vide.
///
/// L'état est reçu mais pas encore lu — l'arbre est chargé, rien ne l'affiche
/// : c'est le seul morceau qui manque. La signature est celle qu'attend
/// [`super::rendu::dessiner`] et ne changera pas.
pub(super) fn dessiner_ecran_arborescence_enu(frame: &mut Frame, _etat_tui: &EtatTui) {
    let lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(DIMENSIONS_ECRAN_ENU.hauteur),
        Constraint::Fill(1),
    ])
    .split(frame.area());

    let colonnes = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(DIMENSIONS_ECRAN_ENU.largeur),
        Constraint::Fill(1),
    ])
    .split(lignes[1]);

    frame.render_widget(Block::bordered(), colonnes[1]);
}
