// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Rendu de l'interface textuelle.
//!
//! Seul responsable du dessin — aucune logique d'état n'y réside.
//! [`dessiner`] est le point d'entrée unique, appelé à chaque frame ;
//! il délègue à une fonction spécialisée selon l'[`crate::tui::Ecran`] actif.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Block;

use crate::tui::{COULEUR_ACCENT, Ecran, EtatTui};

/// Dessine le frame courant en fonction de l'écran actif.
///
/// Point d'entrée unique du rendu — appelé à chaque itération de la boucle
/// principale. Délègue à une fonction spécialisée selon [`EtatTui::ecran`].
pub(crate) fn dessiner(frame: &mut Frame, etat_tui: &EtatTui) {
    match etat_tui.ecran {
        Ecran::Normal => dessiner_ecran_normal(frame),
    }
}

/// Dessine le carré normal : cadre à angles droits, invite centrée.
///
/// Largeur nominale 62 cellules, hauteur 31 — ratio compensant la hauteur
/// des cellules terminal pour obtenir un rendu visuellement carré.
fn dessiner_ecran_normal(frame: &mut Frame) {
    // Carré centré : 62×31 pour compenser le ratio largeur/hauteur des cellules terminal.
    let lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(31), // carré
        Constraint::Fill(1),
    ])
    .split(frame.area());

    let colonnes = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(62), // carré
        Constraint::Fill(1),
    ])
    .split(lignes[1]);

    frame.render_widget(Block::bordered(), colonnes[1]);

    // Découpage à l'intérieur de la bordure pour ne pas l'écraser.
    let carre = colonnes[1].inner(Margin {
        horizontal: 1,
        vertical: 1,
    });

    let carre_lignes = Layout::vertical([
        Constraint::Length(1), // ligne de pastilles
        Constraint::Fill(1),
        Constraint::Length(1), // Espace affichage erreur
        Constraint::Length(2), // Espace vide
        Constraint::Length(1), // invite
        Constraint::Length(3), // Espace vide
        Constraint::Fill(1),
    ])
    .split(carre);

    let ligne_pastilles = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Fill(1),
        Constraint::Length(10),
    ])
    .split(carre_lignes[0]);

    frame.render_widget(
        Span::styled("●", Style::default().fg(COULEUR_ACCENT)),
        ligne_pastilles[0].inner(Margin {
            horizontal: 1,
            vertical: 0,
        }),
    );

    let pastilles_foyers = Line::from(vec![
        Span::styled("●", Style::default().fg(COULEUR_ACCENT)),
        Span::raw(" "),
        Span::raw("○"),
        Span::raw(" "),
        Span::raw("○"),
    ])
    .right_aligned();

    frame.render_widget(
        pastilles_foyers,
        ligne_pastilles[2].inner(Margin {
            horizontal: 1,
            vertical: 0,
        }),
    );

    let affichage_erreur = Line::from(vec![Span::styled(
        "NOY > APP > Ceci est un essai d'affichage d'erreur",
        Style::default().fg(COULEUR_ACCENT),
    )])
    .centered();

    frame.render_widget(affichage_erreur, carre_lignes[2]);

    let invite = Line::from(vec![
        Span::raw("feu "),
        Span::styled("›", Style::default().fg(COULEUR_ACCENT)),
    ]);

    frame.render_widget(
        invite,
        carre_lignes[4].inner(Margin {
            horizontal: 10,
            vertical: 0,
        }),
    );
}
