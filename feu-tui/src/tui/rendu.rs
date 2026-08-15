// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Aiguillage du rendu, et ce que tous les écrans partagent.
//!
//! [`dessiner`] est le point d'entrée unique, appelé à chaque frame : il ne
//! dessine rien lui-même et passe la main au module de l'écran actif. Le reste
//! du module tient le peu de vocabulaire visuel commun — la couleur d'accent
//! et le type [`Dimensions`].
//!
//! Fonction libre plutôt que méthode sur [`crate::tui::Ecran`] : la définition
//! de l'état reste dans [`crate::tui`], les opérations qui le lisent vivent
//! ici, et d'autres — capture pour tests, inspection — peuvent s'y ajouter
//! sans alourdir le module d'état.

use ratatui::{Frame, style::Color};

use crate::tui::{
    ecran_arborescence_enu::dessiner_ecran_arborescence_enu,
    ecran_pilotage::dessiner_ecran_pilotage,
};

use super::{Ecran, EtatTui};

/// Couleur d'accent unique de l'interface — orange `#FF5A1F`.
///
/// Chevron de l'invite, pastilles allumées, cadres des écrans pilotés par le
/// cœur, messages d'erreur. Aucune autre couleur n'est introduite : la
/// hiérarchie visuelle repose sur la casse et le gras.
pub(crate) const COULEUR_ACCENT: Color = Color::Rgb(255, 90, 31);

/// Paire largeur/hauteur en cellules terminal, pour dimensionner les zones
/// rectangulaires centrées dans le frame.
///
/// Une cellule n'est pas carrée : elle est typiquement deux fois plus haute
/// que large. Les valeurs sont donc choisies pour un rendu *visuellement*
/// équilibré, pas pour un ratio géométrique.
pub(crate) struct Dimensions {
    /// Nombre de colonnes.
    pub(crate) largeur: u16,
    /// Nombre de lignes.
    pub(crate) hauteur: u16,
}

/// Dessine le frame courant, en passant la main au module de l'écran actif.
///
/// L'état lui est transmis entier : un écran lit ses propres données mais
/// aussi du transversal — messages éphémères, buffer de saisie —, et c'est
/// ici qu'il est disponible d'un bloc.
pub(crate) fn dessiner(frame: &mut Frame, etat_tui: &EtatTui) {
    match &etat_tui.ecran {
        Ecran::Pilotage => dessiner_ecran_pilotage(frame, etat_tui),
        Ecran::ArborescenceEnu => dessiner_ecran_arborescence_enu(frame, etat_tui),
    }
}
