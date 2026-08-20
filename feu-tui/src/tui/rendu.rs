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
//! caractères d'interface, le type [`Dimensions`] — et [`carre_principal`], la
//! fenêtre que les écrans de travail se partagent.
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

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Tabs},
};

use crate::tui::{
    ecran_arborescence_disque::dessiner_ecran_arborescence_disque,
    ecran_arborescence_enu::dessiner_ecran_arborescence_enu,
    ecran_pilotage::dessiner_ecran_pilotage,
};

use super::{Ecran, EtatTui};

/// Dimensions du carré commun aux écrans de travail.
///
/// Ratio 70 × 35 pour compenser la hauteur des cellules terminal et obtenir un
/// rendu visuellement carré.
///
/// Une seule paire pour tous : la fenêtre ne bouge pas d'un écran à l'autre,
/// `h` et `l` changent ce qui est dedans. Ici plutôt que dans un module
/// d'écran, où deux constantes égales avaient fini par se répondre.
const DIMENSIONS_ECRAN_PRINCIPAL: Dimensions = Dimensions {
    largeur: 70,
    hauteur: 35,
};

/// Couleur d'accent unique de l'interface — orange `#FF5A1F`.
///
/// Chevron de l'invite, pastilles allumées, cadres des écrans pilotés par le
/// cœur, messages d'erreur, marque de sélection et triangles de pli de
/// l'arborescence. Aucune autre couleur n'est introduite : la hiérarchie
/// visuelle repose sur la casse et le gras.
pub(crate) const COULEUR_ACCENT: Color = Color::Rgb(255, 90, 31);

pub(crate) const GUIDE_TUYAU: &str = "│";

/// Découpe d'un onglet dans la bordure haute, et trait qui les relie.
///
/// Les trois connecteurs du même jeu que [`GUIDE_TUYAU`] : posés sur le trait,
/// ils le referment de part et d'autre du titre au lieu d'y laisser un trou.
const ONGLET_LIAISON: &str = "─";

pub(crate) const SYMBOLE_RACINE: &str = "⌂";
pub(crate) const SYMBOLE_REPERTOIRE_DEPLIE: &str = "▾";
pub(crate) const SYMBOLE_REPERTOIRE_REPLIE: &str = "▸";
pub(crate) const SYMBOLE_REPERTOIRE_VIDE: &str = "▻";
pub(crate) const SYMBOLE_DONNEE: &str = "•";
pub(crate) const SYMBOLE_TEXTE: &str = "≡";

/// Marque de l'entrée retenue, dans sa colonne en tête de ligne.
///
/// L'astérisque est le geste des explorateurs de fichiers en terminal, où il
/// signale l'entrée marquée. ASCII, donc hors de toute question de police, et
/// distinct des symboles d'arborescence : il désigne un choix de
/// l'utilisateur, pas une nature d'entrée.
pub(crate) const MARQUE_SELECTION: &str = "*";

pub(crate) const PASTILLE_ALLUMEE: &str = "●";
pub(crate) const PASTILLE_ETEINTE: &str = "○";

pub(crate) const CHEVRON_INVITE: &str = "›";
pub(crate) const CURSEUR: &str = "▌";
pub(crate) const MASQUE_MOT_DE_PASSE: &str = "•";
pub(crate) const SEPARATEUR: &str = "·";

/// Longueur maximale d'un libellé affiché, ellipse comprise.
///
/// Comptée en caractères, jamais en octets. Partagée par les deux
/// arborescences, qui bornent chacune leurs noms dans leur `libelle` : un nom
/// d'ENU et un nom de fichier tiennent dans le même carré, la borne n'a pas de
/// raison d'y différer.
pub(crate) const MAX_LONGUEUR_MOT: usize = 30;

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
///
/// **En `&mut`**, ce qui surprend d'un rendu. Un `StatefulWidget` de Ratatui
/// écrit dans son état au moment d'être dessiné : lui seul connaît alors la
/// hauteur de sa zone et le nombre d'items, donc lui seul peut borner une
/// sélection et poser un défilement. L'écran d'arborescence des ENU en dépend ;
/// le pilotage et l'arborescence du disque gardent un `&EtatTui`, le reborrow
/// étant automatique.
pub(crate) fn dessiner(frame: &mut Frame, etat_tui: &mut EtatTui) {
    match &etat_tui.ecran {
        Ecran::Pilotage => dessiner_ecran_pilotage(frame, etat_tui),
        Ecran::ArborescenceEnu => dessiner_ecran_arborescence_enu(frame, etat_tui),
        Ecran::ArborescenceDisque => dessiner_ecran_arborescence_disque(frame, etat_tui),
    }
}

/// Centre la fenêtre des écrans de travail, la dessine, et rend sa zone.
///
/// Le cadre est le même pour tous les écrans de travail : l'écrire une fois est
/// ce qui garantit qu'il ne saute pas quand `h` et `l` passent de l'un à
/// l'autre.
///
/// **Rend le rectangle bordure comprise, et non l'intérieur** : la marge de
/// découpe appartient à l'écran.
///
/// **Les onglets sont posés sur le trait bas**, où ils écrasent la bordure : ils
/// appartiennent au cadre et ne coûtent aucune ligne intérieure. Leur ordre est
/// celui des touches `h` et `l`, sans quoi ils mentiraient. Les modales du
/// pilotage ne passent pas par ici.
pub(crate) fn carre_principal(frame: &mut Frame, ecran: &Ecran) -> Rect {
    let lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(DIMENSIONS_ECRAN_PRINCIPAL.hauteur),
        Constraint::Fill(1),
    ])
    .split(frame.area());

    let colonnes = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(DIMENSIONS_ECRAN_PRINCIPAL.largeur),
        Constraint::Fill(1),
    ])
    .split(lignes[1]);

    frame.render_widget(Block::bordered(), colonnes[1]);

    let zone = Rect {
        x: colonnes[1].x + 3,
        y: colonnes[1].bottom() - 1,
        width: colonnes[1].width.saturating_sub(6),
        height: 1,
    };

    frame.render_widget(
        Tabs::new([" ENU ", " Pilotage ", " Disque "])
            .select(match ecran {
                Ecran::ArborescenceEnu => 0,
                Ecran::Pilotage => 1,
                Ecran::ArborescenceDisque => 2,
            })
            .divider(ONGLET_LIAISON.repeat(2))
            .padding("", "")
            .highlight_style(Style::default().fg(COULEUR_ACCENT)),
        zone,
    );
    colonnes[1]
}
