// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Écran d'arborescence du disque : la place du futur sélecteur de fichiers.
//!
//! `l` y mène depuis le pilotage, dont il est le voisin de droite ; `h` en
//! revient. C'est aujourd'hui **un écran vide** : le cadre, les onglets et les
//! deux lignes de message, rien d'autre. Aucune touche ne lui est propre — la
//! table des commandes ne lui ajoute rien (cf.
//! [`crate::tui::commandes::CommandesActives::new`]).
//!
//! Le manque qu'il vient combler est écrit ailleurs : `CHEMIN_COMPTOIR_DEPOT`,
//! dans [`crate::tui`], tient en dur la place d'un chemin que l'utilisateur ne
//! peut désigner nulle part.
//!
//! **Aucun état ne lui est attaché** : il ne retient rien d'une frame à
//! l'autre, et n'a donc pas de pendant à `EtatArborescenceEnu` dans
//! [`crate::tui::EtatTui`]. Un `struct` vide y aurait été un champ jamais lu ;
//! il s'écrira le jour où l'écran aura quelque chose à retenir.
//!
//! La découpe verticale est celle de [`super::ecran_arborescence_enu`] à
//! l'identique — les deux écrans doivent poser leurs messages sur la même
//! ligne, sans quoi le texte sauterait en changeant d'onglet.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Margin},
    style::Style,
    text::{Line, Span},
};

use crate::tui::{
    EtatTui,
    rendu::{COULEUR_ACCENT, carre_principal},
};

/// Dessine le cadre de l'écran du disque et les messages éphémères.
///
/// Le carré est celui des autres écrans de travail, dessiné par
/// [`super::rendu::carre_principal`] ; ne reste ici que la marge de découpe.
/// La zone `Fill` est celle de l'arborescence à venir, aujourd'hui laissée
/// blanche : elle est réservée par la découpe pour que les lignes fixes du bas
/// tombent déjà à leur place définitive.
///
/// En `&EtatTui`, comme le pilotage : aucun `StatefulWidget` n'écrit ici, donc
/// rien n'impose l'emprunt mutable de [`super::rendu::dessiner`].
pub(super) fn dessiner_ecran_arborescence_disque(frame: &mut Frame, etat_tui: &EtatTui) {
    let carre = carre_principal(frame, &etat_tui.ecran).inner(Margin {
        horizontal: 4,
        vertical: 2,
    });

    let carre_lignes = Layout::vertical([
        Constraint::Length(1), // [0] respiration
        Constraint::Fill(1),   // [1] arborescence
        Constraint::Length(2), // [2] respiration
        Constraint::Length(1), // [3] message d'erreur
        Constraint::Length(1), // [4] message d'aide
    ])
    .split(carre);

    // [3] message d'erreur
    if let Some(message) = etat_tui.message_erreur() {
        let affichage_erreur = Line::from(vec![Span::styled(
            message,
            Style::default().fg(COULEUR_ACCENT),
        )])
        .centered();

        frame.render_widget(affichage_erreur, carre_lignes[3]); // [3]
    }

    // [4] message d'aide
    if let Some(message) = etat_tui.message_aide() {
        let affichage_commande = Line::from(vec![
            Span::styled(" <", Style::default().fg(COULEUR_ACCENT)),
            Span::raw(message),
            Span::styled(">", Style::default().fg(COULEUR_ACCENT)),
        ]);

        frame.render_widget(affichage_commande, carre_lignes[4]); // [4]
    }
}
