// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Écran de pilotage : l'usage courant, et les trois modales qu'il ouvre.
//!
//! Saisie du mot de passe, affichage de la seed, information générique : les
//! trois naissent d'une commande émise depuis cet écran. Leur fermeture y
//! revient donc sans avoir à retenir d'où elle venait.
//!
//! [`EcranPilotage`] dit lequel des quatre est dessiné et porte, dans chaque
//! variante, les données que le rendu lui demandera — elles disparaissent avec
//! l'écran quitté, ce qui borne la durée de vie des mots de la seed.
//!
//! Le module tient tout ce qui concerne cet écran : son état, ses transitions,
//! son dessin. Les transitions s'écrivent en `impl EtatTui` parce qu'elles
//! posent aussi [`Ecran`], [`ModeSaisie`] et [`ValidationBufferSaisie`], qui
//! appartiennent à [`EtatTui`] ; chaque écran apporte ainsi les siennes sans
//! que la boucle principale ait à connaître ses variantes.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Margin},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph},
};
use secrecy::{ExposeSecret, SecretString};

use crate::tui::{
    Ecran, EtatTui, ModeSaisie, ValidationBufferSaisie,
    ecran_arborescence_enu::libelle,
    rendu::{
        CHEVRON_INVITE, COULEUR_ACCENT, CURSEUR, Dimensions, MASQUE_MOT_DE_PASSE, PASTILLE_ALLUMEE,
        PASTILLE_ETEINTE, SEPARATEUR, SYMBOLE_RACINE,
    },
};

/// Dimensions du carré de l'écran principal.
///
/// Ratio 70 × 35 pour compenser la hauteur des cellules terminal et obtenir un
/// rendu visuellement carré.
const DIMENSIONS_ECRAN_PRINCIPAL: Dimensions = Dimensions {
    largeur: 70,
    hauteur: 35,
};

/// Dimensions du cadre de saisie du mot de passe.
///
/// Plus étroit et bien moins haut que l'écran principal : avec le cadre
/// arrondi orange, la rupture visuelle marque que le cœur a pris la main.
const DIMENSIONS_ECRAN_SAISIE_MDP: Dimensions = Dimensions {
    largeur: 55,
    hauteur: 11,
};

/// Dimensions de base du cadre d'affichage de la seed.
///
/// La `hauteur` ne couvre que le fixe — titre, espaces, rappel, aide. Le rendu
/// y ajoute les lignes de mots, `ceil(seed.len() / 3)`.
const DIMENSIONS_ECRAN_AFFICHAGE_SEED: Dimensions = Dimensions {
    largeur: 55,
    hauteur: 10,
};

/// Dimensions du cadre d'information générique.
///
/// Hauteur *fixe*, contrairement à [`DIMENSIONS_ECRAN_AFFICHAGE_SEED`] : le
/// cadre ne s'étire pas, le contenu est centré entre deux remplissages. Le
/// message ne peut donc dépasser `hauteur − 6` lignes — deux bordures, titre,
/// deux espaces, aide —, soit 9 aujourd'hui. Rien ne défile ici.
const DIMENSIONS_ECRAN_AFFICHAGE_INFORMATION: Dimensions = Dimensions {
    largeur: 60,
    hauteur: 15,
};

/// Nombre de colonnes sur lesquelles la seed est affichée.
///
/// Sert au nombre de lignes, à l'indexation des mots et à la borne de la
/// boucle. Le découpage horizontal `Constraint::Ratio(1, 3)` × 3, lui, reste
/// en dur : changer cette constante impose de l'adapter aussi.
const NOMBRE_COLONNES_SEED: usize = 3;

/// Lequel des quatre écrans du pilotage est dessiné.
///
/// Privé au module : la boucle principale ne connaît que [`Ecran::Pilotage`],
/// et n'atteint ces variantes que par les transitions déclarées plus bas.
enum EcranPilotage {
    /// Carré à angles droits — état de repos : pastilles, invite, éphémères.
    ///
    /// Le seul des quatre à traverser plusieurs [`ModeSaisie`] : `Normal` pour
    /// le dispatch des commandes, `Insertion` quand l'invite porte un prompt.
    Principal,

    /// Cadre arrondi orange — le cœur attend le mot de passe.
    ///
    /// Toujours avec [`ModeSaisie::Insertion`] et
    /// [`ValidationBufferSaisie::EnvoiMdp`].
    SaisieMdp,

    /// Cadre arrondi orange — la seed vient d'être générée.
    ///
    /// Toujours avec [`ModeSaisie::Information`]. Les mots ne vivent que dans
    /// cette variante : quitter l'écran les détruit.
    AffichageSeed {
        /// Les mots à recopier. `SecretString` les tient hors de tout `Debug`
        /// et les efface à la destruction ; seul le rendu les expose.
        seed: Vec<SecretString>,
        /// Passe à `true` à la première pression d'Entrée, ce qui affiche la
        /// demande de confirmation ; la seconde ferme l'écran.
        rappel: bool,
    },

    /// Cadre arrondi orange — écran d'information réutilisable.
    ///
    /// Toute information textuelle à présenter hors du flux normal passe par
    /// là, son contenu venant de l'appelant. Il est affiché **en clair** :
    /// rien de sensible n'y transite — une seed, une clé ou une adresse
    /// `.braise` relèvent d'un écran dédié.
    AffichageInformation {
        /// Titre affiché centré en haut du cadre.
        titre: String,
        /// Corps du message, rendu en paragraphe centré ; chaque `\n` délimite
        /// une ligne affichée.
        information: String,
    },
}

/// Position de navigation dans la pseudo-arborescence foyer → classeur.
///
/// Curseur de présentation : il ne déclenche aucune action métier, mais entre
/// dans [`super::commandes::CommandesActives::new`], qui en tire les touches
/// actives et y capture l'index que porte
/// [`super::commandes::Commande::PilotageFermerFoyer`].
///
/// Trois niveaux, encodés par la combinaison des deux `Option` : racine (deux
/// `None`), dans un foyer (`foyer` seul), dans un classeur (les deux). Le type
/// n'interdit pas la quatrième combinaison — l'invariant *« un classeur
/// implique un foyer »* est tenu par les transitions de
/// [`super::Tui::saisie_mode_normal`].
///
/// Fermer le foyer où l'on est positionné ramène aussitôt à la racine. Comme
/// c'est l'unique chemin de fermeture, l'invariant tient en cascade :
/// l'extinction du nœud, qui exige tous les foyers fermés, trouve toujours la
/// position déjà à la racine.
pub(super) struct PositionCourante {
    /// Index 1-based du foyer, `None` à la racine.
    ///
    /// Posé depuis la racine — la table n'expose la touche que pour les foyers
    /// effectivement ouverts. Effacé par `Backspace` ou par la fermeture du
    /// foyer.
    pub(super) foyer: Option<usize>,

    /// Index 1-based du classeur, `None` si l'on n'y est pas descendu.
    ///
    /// La table expose `1`-`9` dans la limite de `nombre_classeurs` : un
    /// classeur ne s'ouvre pas, tous les indices valides sont accessibles.
    /// Effacé par `Backspace` ou par la fermeture du foyer.
    pub(super) classeur: Option<usize>,
}

/// Tout ce que l'écran de pilotage retient d'une frame à l'autre.
///
/// Champ de [`EtatTui`], à côté de ce qui est commun à tous les écrans. Ce qui
/// descend ici est ce dont aucun autre écran ne saurait quoi faire.
pub(super) struct EtatPilotage {
    /// Lequel des quatre écrans est affiché.
    ecran_pilotage: EcranPilotage,
    /// Où l'utilisateur est positionné, lu par l'invite et par la table des
    /// commandes.
    pub(super) position_courante: PositionCourante,
}

impl EtatPilotage {
    /// État initial : écran principal, position à la racine.
    pub(super) fn new() -> Self {
        Self {
            ecran_pilotage: EcranPilotage::Principal,
            position_courante: PositionCourante {
                foyer: None,
                classeur: None,
            },
        }
    }
}

/// Les transitions qui mènent aux écrans du pilotage, ou en reviennent.
///
/// Elles posent d'un seul geste les champs qui doivent rester cohérents entre
/// eux — écran, sous-écran, mode de saisie, destination du buffer. L'appelant
/// n'a ni à les connaître ni à les ordonner : la boucle principale se contente
/// d'appeler la transition qui correspond à l'événement reçu.
impl EtatTui {
    /// Le cœur réclame le mot de passe.
    pub(super) fn vers_saisie_mdp(&mut self) {
        self.ecran = Ecran::Pilotage;
        self.etat_pilotage.ecran_pilotage = EcranPilotage::SaisieMdp;
        self.mode_saisie = ModeSaisie::Insertion;
        self.validation_buffer_saisie = ValidationBufferSaisie::EnvoiMdp;
    }

    /// La seed vient d'être générée et doit être recopiée.
    ///
    /// Les mots sont pris par valeur : ils n'existent plus que dans la
    /// variante, et le retour à l'écran principal les emporte.
    pub(super) fn vers_affichage_seed(&mut self, seed: Vec<SecretString>) {
        self.ecran = Ecran::Pilotage;
        self.etat_pilotage.ecran_pilotage = EcranPilotage::AffichageSeed {
            seed,
            rappel: false,
        };
        self.mode_saisie = ModeSaisie::Information;
    }

    /// Présente un message à l'utilisateur, composé par l'appelant.
    ///
    /// L'écran ne connaît aucun contenu : c'est ce qui le laisse servir à
    /// l'à-propos comme à ce qui viendra ensuite.
    pub(super) fn vers_affichage_information(&mut self, titre: String, information: String) {
        self.ecran = Ecran::Pilotage;
        self.etat_pilotage.ecran_pilotage =
            EcranPilotage::AffichageInformation { titre, information };
        self.mode_saisie = ModeSaisie::Information;
    }

    /// Referme ce qui était ouvert et rend la main au dispatch des commandes.
    ///
    /// Unique chemin de retour, sans écran d'origine à mémoriser : les trois
    /// modales ne s'ouvrent que depuis le pilotage.
    pub(super) fn vers_ecran_principal(&mut self) {
        self.ecran = Ecran::Pilotage;
        self.etat_pilotage.ecran_pilotage = EcranPilotage::Principal;
        self.mode_saisie = ModeSaisie::Normal;
    }

    /// Traite la pression d'Entrée en [`ModeSaisie::Information`].
    ///
    /// Retourne `true` quand la seed vient d'être confirmée, seul cas où le
    /// cœur attend une réponse — l'envoi reste à la boucle, qui seule tient le
    /// connecteur. La seed se déroule en deux temps, les autres écrans
    /// d'information se ferment d'un coup : l'appelant n'a pas à savoir lequel
    /// est affiché.
    pub(super) fn entree_mode_information(&mut self) -> bool {
        match &mut self.etat_pilotage.ecran_pilotage {
            // Première pression : la confirmation s'affiche, l'écran reste.
            EcranPilotage::AffichageSeed {
                rappel: rappel @ false,
                ..
            } => {
                *rappel = true;
                false
            }
            // Seconde pression : la seed part avec la variante, le cœur est prévenu.
            EcranPilotage::AffichageSeed { .. } => {
                self.vers_ecran_principal();
                true
            }
            _ => {
                self.vers_ecran_principal();
                false
            }
        }
    }
}

/// Dessine celui des quatre écrans du pilotage qui est actif.
///
/// Appelée par [`super::rendu::dessiner`], à qui [`EcranPilotage`] reste
/// invisible. Chaque fonction spécialisée reçoit `etat_tui` entier ou les
/// seules données de sa variante, selon qu'elle lit ou non du transversal.
pub(super) fn dessiner_ecran_pilotage(frame: &mut Frame, etat_tui: &EtatTui) {
    match &etat_tui.etat_pilotage.ecran_pilotage {
        EcranPilotage::Principal => dessiner_ecran_principal(frame, etat_tui),
        EcranPilotage::SaisieMdp => dessiner_ecran_saisie_mdp(frame, etat_tui),
        EcranPilotage::AffichageSeed { seed, rappel } => {
            dessiner_ecran_affichage_seed(frame, seed, *rappel)
        }
        EcranPilotage::AffichageInformation { titre, information } => {
            dessiner_ecran_affichage_information(frame, titre, information)
        }
    }
}

/// Cadre à angles droits, pastilles, invite et messages éphémères.
///
/// L'invite est reconstruite à chaque frame :
/// `feu[/foy.N][/cla.M] › [prompt] [buffer]▌` — les segments entre crochets
/// suivent [`PositionCourante`], le curseur n'apparaît qu'en
/// [`ModeSaisie::Insertion`]. Ce préfixe est le fil d'Ariane de la
/// pseudo-arborescence.
///
/// Les pastilles lisent l'état réel du nœud et des foyers dans la session ;
/// les messages éphémères ne s'affichent que tant qu'ils sont posés.
///
/// Trois lignes échappent à cette règle des éphémères : le dépôt ouvert, l'ENU
/// retenue et le chemin retenu, qui restent tant qu'une autre marque ne les
/// remplace pas. Seule celle de l'ENU est écrite aujourd'hui ; les deux autres
/// attendent le comptoir de dépôt et l'écran d'arborescence du disque.
///
/// **Leurs trois hauteurs sont réservées dès maintenant**, marquées ou non :
/// c'est ce qui empêche le reste du carré de sauter d'une ligne à la première
/// marque, et ce qui fixe la place de chacune — l'ordre des trois ne dépendra
/// jamais de ce qui est rempli.
///
/// Les commentaires `[n]` du corps renvoient à l'index de la ligne dans
/// `carre_lignes` : le layout est long, et une ligne dessinée loin de sa
/// déclaration se retrouve autrement à l'œil.
fn dessiner_ecran_principal(frame: &mut Frame, etat_tui: &EtatTui) {
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

    // Découpage à l'intérieur de la bordure pour ne pas l'écraser.
    let carre = colonnes[1].inner(Margin {
        horizontal: 4,
        vertical: 1,
    });

    let carre_lignes = Layout::vertical([
        Constraint::Length(1), // [0] ligne de pastilles
        Constraint::Fill(1),   // [1]
        Constraint::Length(1), // [2] message d'erreur
        Constraint::Length(2), // [3] respiration
        Constraint::Length(1), // [4] invite
        Constraint::Length(2), // [5] respiration
        Constraint::Length(1), // [6] affichage dépôt
        Constraint::Length(1), // [7] enu sélectionnée
        Constraint::Length(1), // [8] chemin sélectionné
        Constraint::Fill(1),   // [9]
        Constraint::Length(1), // [10] affichage commandes
        Constraint::Length(1), // [11] pied
    ])
    .split(carre);

    let ligne_pastilles = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Fill(1),
        Constraint::Length(10),
    ])
    .split(carre_lignes[0]);

    // [0] ligne pastilles
    // Pastille du noeud
    let span = if etat_tui.session_application.is_some() {
        Span::styled(PASTILLE_ALLUMEE, Style::default().fg(COULEUR_ACCENT))
    } else {
        Span::raw(PASTILLE_ETEINTE)
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
                Span::styled(
                    format!("{PASTILLE_ALLUMEE} "),
                    Style::default().fg(COULEUR_ACCENT),
                )
            } else {
                Span::raw(format!("{PASTILLE_ETEINTE} "))
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

    // [2] message erreur
    if let Some(message) = etat_tui.message_erreur() {
        let affichage_erreur = Line::from(vec![Span::styled(
            message,
            Style::default().fg(COULEUR_ACCENT),
        )])
        .centered();

        frame.render_widget(affichage_erreur, carre_lignes[2]); // [2]
    }

    // [4] invite
    let mut spans_invite = vec![Span::raw("feu")];
    if let Some(index) = etat_tui.etat_pilotage.position_courante.foyer {
        spans_invite.push(Span::raw(format!("/foy.{index}")));
    }
    if let Some(index) = etat_tui.etat_pilotage.position_courante.classeur {
        spans_invite.push(Span::raw(format!("/cla.{index}")));
    }
    spans_invite.extend([
        Span::styled(
            format!(" {CHEVRON_INVITE} "),
            Style::default().fg(COULEUR_ACCENT),
        ),
        Span::raw(etat_tui.prompt.clone()),
        Span::raw(" "),
        Span::raw(etat_tui.buffer_saisie.clone()),
    ]);

    if matches!(etat_tui.mode_saisie, ModeSaisie::Insertion) {
        spans_invite.push(Span::raw(CURSEUR));
    }

    frame.render_widget(
        Line::from(spans_invite),
        carre_lignes[4].inner(Margin {
            horizontal: 10,
            vertical: 0,
        }),
    );

    // [7] enu sélectionnée
    if let Some(fiche) = &etat_tui.enu_selectionnee {
        let nom = match libelle(fiche) {
            // La racine n'a pas de nom : son symbole en tient lieu.
            nom if nom.is_empty() => String::from(SYMBOLE_RACINE),
            nom => nom,
        };

        let ligne = Line::from(vec![
            Span::styled(
                format!("ENU {CHEVRON_INVITE} "),
                Style::default().fg(COULEUR_ACCENT),
            ),
            Span::raw(nom),
        ]);
        frame.render_widget(ligne, carre_lignes[7]);
    }

    // [10] affichage commandes
    if let Some(message) = etat_tui.message_aide() {
        let affichage_commande = Line::from(vec![
            Span::styled(" <", Style::default().fg(COULEUR_ACCENT)),
            Span::raw(message),
            Span::styled(">", Style::default().fg(COULEUR_ACCENT)),
        ]);

        frame.render_widget(affichage_commande, carre_lignes[10]);
    }
}

/// Cadre arrondi orange, points de masquage et aide.
///
/// Seule la *longueur* du buffer est lue — pour les points `•` et le compteur
/// du titre. Le mot de passe lui-même n'est jamais rendu.
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

    let saisie = Line::from(vec![Span::raw(
        MASQUE_MOT_DE_PASSE.repeat(etat_tui.buffer_saisie.len()),
    )])
    .centered();
    frame.render_widget(saisie, zone_interieure_lignes[3]);

    let texte_aide = Line::from(vec![Span::raw(format!(
        "Entrée pour valider {SEPARATEUR} Échap pour annuler"
    ))])
    .centered();

    frame.render_widget(texte_aide, zone_interieure_lignes[5]);
}

/// Cadre arrondi orange, mots numérotés en trois colonnes, rappel et aide.
///
/// Seule fonction de dessin à hauteur variable : `n` lignes de trois colonnes,
/// selon le nombre de mots. Le `rappel` ajoute la demande de confirmation.
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
                        "  {:02} {SEPARATEUR} {}",
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

/// Cadre arrondi orange, titre en accent, paragraphe centré et aide.
///
/// La zone du paragraphe s'ajuste au nombre de lignes du message, mais le
/// cadre garde sa hauteur fixe : au-delà de ce qu'il tient, le contenu est
/// tronqué sans avertissement (cf. [`DIMENSIONS_ECRAN_AFFICHAGE_INFORMATION`]).
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
