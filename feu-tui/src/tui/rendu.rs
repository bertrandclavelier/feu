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
//! du module tient le vocabulaire visuel commun — la couleur d'accent, les
//! caractères d'interface et le type [`Dimensions`].
//!
//! # Les caractères
//!
//! Tout caractère qui vaut comme **symbole** est nommé ici, et nulle part
//! ailleurs — les lettres accentuées des textes affichés n'en sont pas, elles
//! restent dans leurs phrases. Un symbole écrit en toutes lettres dans un
//! écran échapperait aux trois contrôles ci-dessous, et au remplacement du jeu
//! entier.
//!
//! **Une seule cellule chacun.** Ratatui mesure ses colonnes avec
//! `unicode-width`, qui rend 1 pour tous ceux retenus ; un caractère plus large
//! décalerait la ligne et, de proche en proche, la bordure du carré.
//!
//! **Aucune propriété `Emoji` ni `Extended_Pictographic`.** Un terminal peut
//! rendre en présentation emoji les caractères qui les portent — sur deux
//! cellules, donc hors du compte de Ratatui. C'est ce qui écarte `▶` (U+25B6)
//! et `▪` (U+25AA), tous deux emoji, au profit de voisins qui ne le sont pas.
//!
//! **Présents dans WGL4** quand c'est possible — le jeu commun à toute police
//! monospace. Les triangles `▾ ▸ ▻` en sortent : les équivalents WGL4 `▼ ►`
//! ont d'abord été retenus, puis écartés comme trop lourds à l'écran.
//!
//! Les symboles d'arborescence forment une grammaire : la forme dit la famille
//! — triangle pour un répertoire, point pour une donnée, barres pour un texte
//! — et l'orientation du triangle dit l'état du pli.
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

pub(crate) const GUIDE_TUYAU: &str = "│";

pub(crate) const SYMBOLE_RACINE: &str = "⌂";
pub(crate) const SYMBOLE_REPERTOIRE_DEPLIE: &str = "▾";
pub(crate) const SYMBOLE_REPERTOIRE_REPLIE: &str = "▸";
pub(crate) const SYMBOLE_REPERTOIRE_VIDE: &str = "▻";
pub(crate) const SYMBOLE_DONNEE: &str = "•";
pub(crate) const SYMBOLE_TEXTE: &str = "≡";

pub(crate) const PASTILLE_ALLUMEE: &str = "●";
pub(crate) const PASTILLE_ETEINTE: &str = "○";

pub(crate) const CHEVRON_INVITE: &str = "›";
pub(crate) const CURSEUR: &str = "▌";
pub(crate) const MASQUE_MOT_DE_PASSE: &str = "•";
pub(crate) const SEPARATEUR: &str = "·";

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
