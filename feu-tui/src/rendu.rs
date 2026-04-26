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
//!
//! [`dessiner`] est une fonction libre plutôt qu'une méthode `impl Ecran` pour
//! séparer la définition de l'état (dans [`crate::tui`]) des opérations sur cet
//! état. Cette séparation permet d'envisager d'autres opérations sur
//! [`crate::tui::EtatTui`] — capture pour tests, inspection — sans alourdir le
//! module d'état.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType};
use secrecy::{ExposeSecret, SecretString};

use crate::tui::{COULEUR_ACCENT, Ecran, EtatTui};

/// Dessine le frame courant en fonction de l'écran actif.
///
/// Point d'entrée unique du rendu — appelé à chaque itération de la boucle
/// principale. Délègue à une fonction spécialisée selon [`EtatTui::ecran`].
///
/// Fonction libre plutôt que méthode de [`Ecran`] : certains écrans lisent
/// des champs transversaux de [`EtatTui`] (ex. [`crate::tui::EtatTui::message_erreur`],
/// [`crate::tui::EtatTui::buffer_saisie`]) que seule cette fonction reçoit en entier.
/// Maintenir [`crate::tui`] comme module d'état pur requiert que les opérations
/// de rendu vivent ici.
pub(crate) fn dessiner(frame: &mut Frame, etat_tui: &EtatTui) {
    match &etat_tui.ecran {
        Ecran::Normal => dessiner_ecran_normal(frame, etat_tui),
        Ecran::SaisieMdp => dessiner_ecran_saisie_mdp(frame, etat_tui),
        Ecran::AffichageSeed { seed, rappel } => {
            dessiner_ecran_affichage_seed(frame, seed, *rappel)
        }
    }
}

/// Dessine l'écran normal : cadre à angles droits, pastilles, invite et erreur éventuelle.
///
/// Déclenché par [`Ecran::Normal`]. Lit [`crate::tui::EtatTui::message_erreur`]
/// — champ transversal survivant aux transitions d'écran — et l'affiche centré
/// s'il est `Some`.
///
/// Actuellement toujours appelé avec [`crate::tui::ModeSaisie::Normal`] ;
/// accueillera le prompt de commande lorsque [`crate::tui::ModeSaisie::Insertion`]
/// sera utilisé sur cet écran.
///
/// Largeur nominale 70 cellules, hauteur 35 — ratio compensant la hauteur
/// des cellules terminal pour obtenir un rendu visuellement carré.
/// Les pastilles nœud et foyers sont provisoirement hardcodées.
fn dessiner_ecran_normal(frame: &mut Frame, etat_tui: &EtatTui) {
    // Carré centré : 70×35 pour compenser le ratio largeur/hauteur des cellules terminal.
    let lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(35), // carré
        Constraint::Fill(1),
    ])
    .split(frame.area());

    let colonnes = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(70), // carré
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

    // Pastille du noeud
    let span: Span;
    if etat_tui.session_application.is_some() {
        span = Span::styled("●", Style::default().fg(COULEUR_ACCENT));
    } else {
        span = Span::raw("○");
    }
    frame.render_widget(
        span,
        ligne_pastilles[0].inner(Margin {
            horizontal: 1,
            vertical: 0,
        }),
    );

    // Pastilles des foyers

    if let Some(session) = &etat_tui.session_application {
        let donne_span_foyer = |i| -> Span {
            if session.etat_foyer(i).unwrap() {
                Span::styled("●", Style::default().fg(COULEUR_ACCENT))
            } else {
                Span::raw("○ ")
            }
        };
        let mut vecteur_span = Vec::<Span>::new();
        for i in 0..session.nombre_foyers {
            vecteur_span.push(donne_span_foyer(i));
        }

        let pastilles_foyers = Line::from(vecteur_span).right_aligned();

        frame.render_widget(
            pastilles_foyers,
            ligne_pastilles[2].inner(Margin {
                horizontal: 1,
                vertical: 0,
            }),
        );
    }

    if let Some(message) = etat_tui.message_erreur() {
        let affichage_erreur = Line::from(vec![Span::styled(
            message,
            Style::default().fg(COULEUR_ACCENT),
        )])
        .centered();

        frame.render_widget(affichage_erreur, carre_lignes[2]);
    }

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

/// Dessine l'écran de saisie du mot de passe : cadre arrondi orange, points de masquage et aide.
///
/// Déclenché par [`Ecran::SaisieMdp`], toujours associé à [`crate::tui::ModeSaisie::Insertion`].
/// Lit la longueur de [`crate::tui::EtatTui::buffer_saisie`] pour afficher les points `•` —
/// le contenu réel n'est jamais rendu. Largeur 55, hauteur 11.
fn dessiner_ecran_saisie_mdp(frame: &mut Frame, etat_tui: &EtatTui) {
    let lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(11),
        Constraint::Fill(1),
    ])
    .split(frame.area());

    let colonnes = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(55),
        Constraint::Fill(1),
    ])
    .split(lignes[1]);

    let bordure = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(COULEUR_ACCENT));
    frame.render_widget(bordure, colonnes[1]);

    let zone_interieure = colonnes[1].inner(Margin {
        horizontal: 1,
        vertical: 1,
    });

    let zone_interieure_lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1), // Titre
        Constraint::Length(1), // Espace vide
        Constraint::Length(1), // Saisie
        Constraint::Length(1), // Espace vide
        Constraint::Length(1), // Texte aide
        Constraint::Fill(1),
    ])
    .split(zone_interieure);

    let titre = Line::from(vec![Span::raw("Mot de passe Feu")]).centered();

    frame.render_widget(titre, zone_interieure_lignes[1]);

    let saisie = Line::from(vec![Span::raw("•".repeat(etat_tui.buffer_saisie.len()))]).centered();

    frame.render_widget(saisie, zone_interieure_lignes[3]);

    let texte_aide =
        Line::from(vec![Span::raw("Entrée pour valider · Échap pour annuler")]).centered();

    frame.render_widget(texte_aide, zone_interieure_lignes[5]);
}

/// Dessine l'écran d'affichage de la seed : cadre arrondi orange, mots en 3 colonnes, rappel et aide.
///
/// Déclenché par [`Ecran::AffichageSeed`], toujours associé à [`crate::tui::ModeSaisie::Information`].
/// Hauteur variable selon le nombre de mots (`n` lignes de 3 colonnes).
/// Quand `rappel` est `true`, affiche en orange un message invitant à confirmer
/// la copie des mots avant de poursuivre.
fn dessiner_ecran_affichage_seed(frame: &mut Frame, seed: &Vec<SecretString>, rappel: bool) {
    let n = seed.len().div_ceil(3) as u16;

    let lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(n + 10),
        Constraint::Fill(1),
    ])
    .split(frame.area());

    let colonnes = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(55),
        Constraint::Fill(1),
    ])
    .split(lignes[1]);

    let bordure = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(COULEUR_ACCENT));
    frame.render_widget(bordure, colonnes[1]);

    let zone_interieure = colonnes[1].inner(Margin {
        horizontal: 1,
        vertical: 1,
    });

    let zone_interieure_lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1), // Titre
        Constraint::Length(2), // Espace vide
        Constraint::Length(n), // Seed
        Constraint::Length(1), // Espace vide
        Constraint::Length(1), // Texte rappel
        Constraint::Length(1), // Texte aide
        Constraint::Fill(1),
    ])
    .split(zone_interieure);

    let titre = Line::from(vec![Span::raw("Seed générée")]).centered();

    frame.render_widget(titre, zone_interieure_lignes[1]);

    let lignes_seed =
        Layout::vertical(vec![Constraint::Length(1); n as usize]).split(zone_interieure_lignes[3]);

    for i in 0..(n as usize) {
        let colonnes_seed = Layout::horizontal([
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
        ])
        .split(lignes_seed[i]);

        frame.render_widget(
            Line::from(vec![Span::raw(seed[i * 3].expose_secret())]),
            colonnes_seed[0],
        );
        frame.render_widget(
            Line::from(vec![Span::raw(seed[(i * 3) + 1].expose_secret())]),
            colonnes_seed[1],
        );
        frame.render_widget(
            Line::from(vec![Span::raw(seed[(i * 3) + 2].expose_secret())]),
            colonnes_seed[2],
        );
    }

    if rappel {
        let affichage_rappel = Line::from(vec![Span::styled(
            format!("As-tu bien copié les {} mots de la seed ?", seed.len()),
            Style::default().fg(COULEUR_ACCENT),
        )])
        .centered();
        frame.render_widget(affichage_rappel, zone_interieure_lignes[5]);
    }

    let texte_aide = Line::from(vec![Span::raw("Appuyer sur Entrée pour continuer")]).centered();

    frame.render_widget(texte_aide, zone_interieure_lignes[6]);
}
