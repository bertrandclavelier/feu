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
use ratatui::layout::{Alignment, Constraint, Layout, Margin};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph};
use secrecy::{ExposeSecret, SecretString};

use crate::tui::ModeSaisie;

use super::{Ecran, EtatTui};

/// Couleur d'accent unique de l'interface — orange `#FF5A1F`.
///
/// Utilisée pour le chevron de l'invite, les pastilles allumées, les cadres
/// des écrans noyau et les messages d'erreur. Aucune autre couleur n'est
/// introduite : la hiérarchie visuelle repose sur la casse et le gras.
pub(crate) const COULEUR_ACCENT: Color = Color::Rgb(255, 90, 31);

/// Paire largeur/hauteur en cellules terminal, utilisée pour dimensionner
/// les zones rectangulaires centrées dans le frame.
///
/// Une cellule terminal n'est pas carrée : elle est typiquement deux fois
/// plus haute que large. Les valeurs concrètes sont donc choisies pour
/// donner un rendu *visuellement* équilibré, pas un ratio géométrique 1:1.
struct Dimensions {
    largeur: u16,
    hauteur: u16,
}

/// Dimensions nominales du carré principal de l'écran normal.
///
/// Ratio 70 × 35 choisi pour compenser la hauteur des cellules terminal et
/// obtenir un rendu visuellement carré.
const DIMENSIONS_ECRAN_NORMAL: Dimensions = Dimensions {
    largeur: 70,
    hauteur: 35,
};

/// Dimensions nominales du cadre arrondi de l'écran de saisie du mot de passe.
///
/// Plus étroit et beaucoup moins haut que l'écran normal : la rupture
/// visuelle (taille + cadre arrondi orange) marque qu'un écran piloté par
/// le noyau a pris la main.
const DIMENSIONS_ECRAN_SAISIE_MDP: Dimensions = Dimensions {
    largeur: 55,
    hauteur: 11,
};

/// Dimensions de base du cadre arrondi de l'écran d'affichage de la seed.
///
/// La `hauteur` ici est une hauteur *fixe* (titre, espaces, rappel, aide)
/// à laquelle s'ajoute dynamiquement le nombre de lignes nécessaires pour
/// afficher la seed sur trois colonnes — soit `ceil(seed.len() / 3)`. La
/// hauteur réelle de l'écran est donc `hauteur + n`, calculée au rendu.
const DIMENSIONS_ECRAN_AFFICHAGE_SEED: Dimensions = Dimensions {
    largeur: 55,
    hauteur: 10,
};

/// Dimensions du cadre arrondi de l'écran d'information générique.
///
/// Contrairement à [`DIMENSIONS_ECRAN_AFFICHAGE_SEED`], la `hauteur` est ici
/// *fixe* : le cadre ne s'étire pas avec le contenu, qui est centré
/// verticalement par deux zones de remplissage. Conséquence : le corps du
/// message ne peut dépasser `hauteur − 6` lignes — les 6 retranchées étant les
/// 2 bordures, le titre, les 2 espaces et la ligne d'aide — sans être tronqué
/// silencieusement (soit 9 lignes pour la `hauteur` actuelle de 15). À garder
/// court : ce n'est pas un écran défilable.
const DIMENSIONS_ECRAN_AFFICHAGE_INFORMATION: Dimensions = Dimensions {
    largeur: 60,
    hauteur: 15,
};

/// Nombre de colonnes sur lesquelles la seed est affichée.
///
/// Sert au calcul de `n = ceil(seed.len() / NOMBRE_COLONNES_SEED)` — le nombre
/// de lignes nécessaires pour disposer la seed — ainsi qu'à l'indexation des
/// mots et à la borne de la boucle interne dans le rendu. Seul le découpage
/// horizontal `Constraint::Ratio(1, 3)` × 3 reste codé en dur ; modifier cette
/// constante impose donc d'adapter aussi le découpage.
const NOMBRE_COLONNES_SEED: usize = 3;

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
        Ecran::AffichageInformation { titre, information } => {
            dessiner_ecran_affichage_information(frame, titre, information)
        }
    }
}

/// Dessine l'écran normal : cadre à angles droits, pastilles, invite et éléments éphémères.
///
/// Déclenché par [`Ecran::Normal`], utilisé avec [`crate::tui::ModeSaisie::Normal`]
/// (commandes) et [`crate::tui::ModeSaisie::Insertion`] (prompts de commande tels
/// qu'`OuvrirFoyer`).
///
/// L'invite est construite dynamiquement à chaque frame :
/// `feu[/foy.N][/cla.M] › [prompt] [buffer]▌` — les segments entre crochets
/// ne sont présents que selon la position courante et le mode :
/// - `/foy.N` apparaît dès que [`crate::tui::PositionCourante::foyer`] est `Some` ;
/// - `/cla.M` apparaît dès que [`crate::tui::PositionCourante::classeur`] est `Some` ;
/// - le curseur `▌` n'apparaît qu'en [`crate::tui::ModeSaisie::Insertion`].
///
/// Le préfixe `feu[/foy.N][/cla.M]` joue le rôle de fil d'Ariane : il rappelle
/// à l'utilisateur où il est positionné dans la pseudo-arborescence.
///
/// Les pastilles reflètent l'état réel : nœud via `session_application`,
/// foyers via `etat_foyer`. Les messages éphémères (`message_erreur` et
/// `message_aide`) sont affichés s'ils sont `Some`.
fn dessiner_ecran_normal(frame: &mut Frame, etat_tui: &EtatTui) {
    let lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(DIMENSIONS_ECRAN_NORMAL.hauteur),
        Constraint::Fill(1),
    ])
    .split(frame.area());

    let colonnes = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(DIMENSIONS_ECRAN_NORMAL.largeur),
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
        Constraint::Length(1), // espace affichage erreur
        Constraint::Length(2), // espace vide
        Constraint::Length(1), // invite
        Constraint::Length(2), // espace vide
        Constraint::Fill(1),
        Constraint::Length(1), // ligne affichage commande
    ])
    .split(carre);

    let ligne_pastilles = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Fill(1),
        Constraint::Length(10),
    ])
    .split(carre_lignes[0]);

    // Pastille du noeud
    let span = if etat_tui.session_application.is_some() {
        Span::styled("●", Style::default().fg(COULEUR_ACCENT))
    } else {
        Span::raw("○")
    };
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
            if session.etat_foyer(i).unwrap_or(false) {
                Span::styled("● ", Style::default().fg(COULEUR_ACCENT))
            } else {
                Span::raw("○ ")
            }
        };
        let vecteur_span: Vec<Span> = (0..session.nombre_foyers).map(donne_span_foyer).collect();

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

    let mut spans_invite = vec![Span::raw("feu")];
    if let Some(index) = etat_tui.position_courante.foyer {
        spans_invite.push(Span::raw(format!("/foy.{index}")));
    }
    if let Some(index) = etat_tui.position_courante.classeur {
        spans_invite.push(Span::raw(format!("/cla.{index}")));
    }
    spans_invite.extend([
        Span::styled(" › ", Style::default().fg(COULEUR_ACCENT)),
        Span::raw(etat_tui.prompt.clone()),
        Span::raw(" "),
        Span::raw(etat_tui.buffer_saisie.clone()),
    ]);

    if matches!(etat_tui.mode_saisie, ModeSaisie::Insertion) {
        spans_invite.push(Span::raw("▌"));
    }

    frame.render_widget(
        Line::from(spans_invite),
        carre_lignes[4].inner(Margin {
            horizontal: 10,
            vertical: 0,
        }),
    );

    if let Some(message) = etat_tui.message_aide() {
        let affichage_commande = Line::from(vec![
            Span::styled(" <", Style::default().fg(COULEUR_ACCENT)),
            Span::raw(message),
            Span::styled(">", Style::default().fg(COULEUR_ACCENT)),
        ]);

        frame.render_widget(affichage_commande, carre_lignes[7]);
    }
}

/// Dessine l'écran de saisie du mot de passe : cadre arrondi orange, points de masquage et aide.
///
/// Déclenché par [`Ecran::SaisieMdp`], toujours associé à [`crate::tui::ModeSaisie::Insertion`].
/// Lit la longueur de [`crate::tui::EtatTui::buffer_saisie`] pour afficher les points `•` et
/// le compteur de caractères saisis dans le titre — le contenu réel du buffer n'est jamais rendu.
fn dessiner_ecran_saisie_mdp(frame: &mut Frame, etat_tui: &EtatTui) {
    let lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(DIMENSIONS_ECRAN_SAISIE_MDP.hauteur),
        Constraint::Fill(1),
    ])
    .split(frame.area());

    let colonnes = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(DIMENSIONS_ECRAN_SAISIE_MDP.largeur),
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
        Constraint::Length(1), // titre
        Constraint::Length(1), // espace vide
        Constraint::Length(1), // saisie
        Constraint::Length(1), // espace vide
        Constraint::Length(1), // texte aide
        Constraint::Fill(1),
    ])
    .split(zone_interieure);

    let titre = Line::from(vec![Span::raw(format!(
        "Mot de passe Feu     |{}|",
        etat_tui.buffer_saisie.len()
    ))])
    .centered();

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
fn dessiner_ecran_affichage_seed(frame: &mut Frame, seed: &[SecretString], rappel: bool) {
    let n = seed.len().div_ceil(NOMBRE_COLONNES_SEED) as u16;

    let lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(n + DIMENSIONS_ECRAN_AFFICHAGE_SEED.hauteur),
        Constraint::Fill(1),
    ])
    .split(frame.area());

    let colonnes = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(DIMENSIONS_ECRAN_AFFICHAGE_SEED.largeur),
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
        Constraint::Length(1), // titre
        Constraint::Length(2), // espace vide
        Constraint::Length(n), // seed
        Constraint::Length(1), // espace vide
        Constraint::Length(1), // texte rappel
        Constraint::Length(1), // texte aide
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

        for j in 0..NOMBRE_COLONNES_SEED {
            if i * NOMBRE_COLONNES_SEED + j < seed.len() {
                frame.render_widget(
                    Line::from(vec![Span::raw(format!(
                        "  {:02} · {}",
                        i * NOMBRE_COLONNES_SEED + j + 1,
                        seed[i * NOMBRE_COLONNES_SEED + j].expose_secret()
                    ))]),
                    colonnes_seed[j],
                );
            }
        }
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

/// Dessine l'écran d'information générique : cadre arrondi orange, titre, paragraphe centré et aide.
///
/// Déclenché par [`Ecran::AffichageInformation`], associé à [`crate::tui::ModeSaisie::Information`].
/// Le `titre` est rendu en accent orange et gras (cf. [`COULEUR_ACCENT`]) ; le
/// corps `information` en paragraphe centré, sans style.
/// La hauteur de la zone du paragraphe est dérivée du nombre de lignes de
/// `information` (`str::lines`) ; le cadre, lui, reste de hauteur fixe
/// (cf. [`DIMENSIONS_ECRAN_AFFICHAGE_INFORMATION`]) — un contenu plus haut que
/// la place disponible est tronqué sans avertissement.
fn dessiner_ecran_affichage_information(frame: &mut Frame, titre: &str, information: &str) {
    let lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(DIMENSIONS_ECRAN_AFFICHAGE_INFORMATION.hauteur),
        Constraint::Fill(1),
    ])
    .split(frame.area());

    let colonnes = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(DIMENSIONS_ECRAN_AFFICHAGE_INFORMATION.largeur),
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

    let n = information.lines().count() as u16;

    let zone_interieure_lignes = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1), // titre
        Constraint::Length(1), // espace vide
        Constraint::Length(n), // paragraphe d'information
        Constraint::Length(1), // espace vide
        Constraint::Length(1), // texte aide
        Constraint::Fill(1),
    ])
    .split(zone_interieure);

    let ligne_titre = Line::from(vec![Span::styled(
        titre,
        Style::default()
            .fg(COULEUR_ACCENT)
            .add_modifier(Modifier::BOLD),
    )])
    .centered();

    frame.render_widget(ligne_titre, zone_interieure_lignes[1]);

    let paragraphe = Paragraph::new(information).alignment(Alignment::Center);

    frame.render_widget(paragraphe, zone_interieure_lignes[3]);

    let texte_aide = Line::from(vec![Span::raw("Entrée pour continuer")]).centered();

    frame.render_widget(texte_aide, zone_interieure_lignes[5]);
}
