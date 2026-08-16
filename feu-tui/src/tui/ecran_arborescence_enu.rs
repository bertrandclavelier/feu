// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Écran d'arborescence des ENU.
//!
//! `Tab` y mène depuis le pilotage, `R` demande l'arbre au cœur, qui le renvoie
//! prêt à dessiner : une entrée par ligne, décalée de sa profondeur. Ni curseur,
//! ni dépliage, ni défilement — un arbre plus haut que le carré est **coupé en
//! bas sans le dire**.
//!
//! **La forme retenue est l'arbre repliable**, non une liste par niveau : c'est
//! le repli, pas la mise en page, qui rend un dépôt réel lisible — un dossier de
//! build tient alors sur une ligne au lieu de remplir l'écran. Il vient donc
//! avant le reste.
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
    layout::{Constraint, Layout, Margin},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph},
};

use crate::tui::{
    EtatTui,
    rendu::{COULEUR_ACCENT, Dimensions},
};

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
    /// Le dernier arbre reçu du cœur, à plat et prêt à dessiner : l'ordre est
    /// celui de l'affichage, la profondeur son décalage.
    ///
    /// `None` ne veut pas dire « arbre vide » mais **jamais demandé** — c'est
    /// lui qui distingue l'écran au premier abord d'un nœud sans contenu, et
    /// qui décidera lequel des deux messages afficher.
    pub(super) arborescence_enus: Option<Vec<(usize, Fiche)>>,
}

impl EtatArborescenceEnu {
    /// État initial : aucun chargement demandé.
    pub(super) fn new() -> Self {
        Self {
            arborescence_enus: None,
        }
    }
}

/// Dessine le cadre, son titre, l'arbre et les messages éphémères.
///
/// Le carré est découpé comme celui du pilotage — bordure rendue d'abord, puis
/// `inner` pour ne pas l'écraser. L'arbre prend le `Fill`, ce qui reste est
/// fixe : le titre en haut, les deux messages en bas.
///
/// L'arbre arrive dans l'ordre de l'affichage, chaque entrée précédée de sa
/// profondeur : le rendu n'a plus qu'à répéter le motif d'indentation autant de
/// fois, ligne par ligne. Le `Paragraph` les empile depuis le haut et coupe ce
/// qui dépasse, faute de défilement.
///
/// L'`Option` distingue **jamais demandé** — l'invite à taper `R` — de l'arbre
/// reçu. Le troisième cas, un arbre réduit à sa seule racine, n'est pas encore
/// séparé du second.
pub(super) fn dessiner_ecran_arborescence_enu(frame: &mut Frame, etat_tui: &EtatTui) {
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

    // Découpage à l'intérieur de la bordure pour ne pas l'écraser.
    let carre = colonnes[1].inner(Margin {
        horizontal: 1,
        vertical: 1,
    });

    let carre_lignes = Layout::vertical([
        Constraint::Length(1), // Titre
        Constraint::Fill(1),   // Arbre
        Constraint::Length(1), // Séparation
        Constraint::Length(1), // message d'erreur
        Constraint::Length(1), // message d'aide
    ])
    .split(carre);

    let ligne_titre = Line::from(vec![Span::styled(
        "Arborescence des ENU",
        Style::default()
            .fg(COULEUR_ACCENT)
            .add_modifier(Modifier::BOLD),
    )])
    .centered();

    frame.render_widget(ligne_titre, carre_lignes[0]);

    if let Some(message) = etat_tui.message_erreur() {
        let affichage_erreur = Line::from(vec![Span::styled(
            message,
            Style::default().fg(COULEUR_ACCENT),
        )])
        .centered();

        frame.render_widget(affichage_erreur, carre_lignes[3]);
    }
    if let Some(message) = etat_tui.message_aide() {
        let affichage_commande = Line::from(vec![
            Span::styled(" <", Style::default().fg(COULEUR_ACCENT)),
            Span::raw(message),
            Span::styled(">", Style::default().fg(COULEUR_ACCENT)),
        ]);

        frame.render_widget(affichage_commande, carre_lignes[4]);
    }

    match &etat_tui.etat_arborescence_enu.arborescence_enus {
        None => {
            let zone_message = Layout::vertical([
                Constraint::Fill(1),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .split(carre_lignes[1]);

            let texte = Line::from(vec![Span::raw("'R' pour charger l'arborescence")]).centered();
            frame.render_widget(texte, zone_message[1]);
        }
        Some(arborescence_enu) => {
            let lignes = arborescence_enu
                .iter()
                .map(|(profondeur, fiche)| {
                    Line::from(format!("{}{}", "| ".repeat(*profondeur), libelle(fiche)))
                })
                .collect::<Vec<Line>>();

            frame.render_widget(Paragraph::new(lignes), carre_lignes[1]);
        }
    }
}

/// Ce qui s'affiche à droite de l'indentation, pour une entrée de l'arbre.
///
/// **Point de passage unique du nom vers l'écran, et donc là où il est
/// assaini.** Un nom de fichier Unix accepte tout sauf `/` et l'octet nul :
/// `nom_fichier_valide` ne refuse que le vide, le séparateur et les composants
/// spéciaux, un retour à la ligne ou une séquence d'échappement peut donc
/// arriver jusqu'ici et casser le carré. Les caractères de contrôle sont
/// remplacés plutôt que supprimés — deux noms distincts ne doivent pas devenir
/// identiques à l'écran, et le `?` montre l'anomalie au lieu de la masquer.
///
/// **Une racine se reconnaît à sa méta `_racine`**, non à sa position : elle est
/// la seule entrée sans méta `nom`, mais la reconnaître par ce qu'elle porte
/// tient même si le parcours part un jour d'ailleurs que du sommet.
///
/// Le hash a été écarté comme repli : le dépôt pose toujours `nom`, une entrée
/// qui en manque relève de l'anomalie, et huit caractères d'hexadécimal ne
/// l'expliqueraient à personne.
fn libelle(fiche: &Fiche) -> String {
    match fiche.carte().metas().get("nom") {
        Some(nom) => nom
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect::<String>(),
        None => {
            if fiche.carte().metas().get("_racine").is_some() {
                return String::from("(racine)");
            }
            String::from("(sans nom)")
        }
    }
}
