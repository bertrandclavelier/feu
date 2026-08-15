// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Écran d'arborescence des ENU.
//!
//! **Squelette** : le chemin qui y mène est établi — `Tab` l'atteint depuis le
//! pilotage et y revient —, mais l'écran ne dessine qu'un carré vide et ne
//! porte aucune donnée. Brancher d'abord, remplir ensuite : ce qui reste à
//! faire est le contenu, pas le raccordement.
//!
//! Il n'a donc aucune commande à lui, et n'expose que le strict nécessaire au
//! branchement — un état vide, une fonction de dessin. Les transitions `vers_*`
//! du pilotage n'ont pas d'équivalent ici : `Tab` suffit à entrer, et
//! `passer_ecran_suivant` tient le cycle.

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

/// Ce que l'écran d'arborescence retient d'une frame à l'autre — rien encore.
///
/// Struct unité le temps du branchement. L'arbre chargé, le curseur, les
/// nœuds dépliés et le défilement viendront ici.
pub(super) struct EtatArborescenceEnu;

/// Dessine le cadre de l'écran, vide.
///
/// L'état est reçu mais pas encore lu : la signature est celle qu'attend
/// [`super::rendu::dessiner`], et elle ne changera pas quand il y aura quelque
/// chose à afficher.
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
