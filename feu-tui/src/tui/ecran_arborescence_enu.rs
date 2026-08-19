// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Écran d'arborescence des ENU : on y navigue, on y plie, on y choisit.
//!
//! `h` y mène depuis le pilotage, `R` demande l'arbre au cœur, qui le renvoie
//! prêt à dessiner : une entrée par ligne, décalée de sa profondeur. `j` et `k`
//! déplacent le curseur, `Entrée` replie ou déplie un répertoire, `m` retient
//! l'ENU sous le curseur dans [`crate::tui::EtatTui::enu_selectionnee`] — d'où
//! le pilotage la lira — et `x` l'y efface.
//!
//! Chaque ligne porte la colonne de marque, un guide par niveau, le symbole de
//! la carte, puis le nom. Le guide est le même à tous les niveaux : le cœur
//! envoie une profondeur, pas une fratrie, et distinguer le dernier enfant d'un
//! `└` demanderait de reconstruire après coup une information que le parcours a
//! jetée.
//!
//! **La forme retenue est l'arbre repliable**, non une liste par niveau : c'est
//! le repli, pas la mise en page, qui rend un dépôt réel lisible — un dossier de
//! build tient alors sur une ligne au lieu de remplir l'écran.
//!
//! # Trois états, trois portées
//!
//! L'arbre reçu ne change jamais : il est le parcours tel que le cœur l'a
//! rendu, à plat, entièrement déplié. Ce qui varie vit à côté, et chaque pièce
//! a sa portée propre.
//!
//! - **Le pli** ([`EtatArborescenceEnu::deplies`]) dit *quelles lignes
//!   existent*. C'est notre affaire, propre aux ENU, et
//!   [`EtatArborescenceEnu::lignes_visibles`] en tire la liste affichable.
//! - **Le curseur** (un [`ListState`]) dit *laquelle est sélectionnée* et
//!   *lesquelles tiennent dans le carré*. C'est de la mécanique de liste,
//!   vraie de n'importe quel contenu, et Ratatui la tient entière — d'où
//!   l'absence de tout champ de défilement ici.
//! - **La marque**, elle, ne vit pas dans cet écran : elle traverse la TUI et
//!   se range dans [`crate::tui::EtatTui`].
//!
//! Les deux premières se superposent sans se connaître, ce qui vaut au
//! [`ListState`] de n'avoir jamais à savoir ce qu'est un répertoire.
//!
//! **Le chargement est explicite, jamais automatique.** Arriver sur l'écran ne
//! déclenche rien : le parcours lit un fichier par ENU de l'arbre, et ce coût
//! se décide. En contrepartie l'arbre survit aux allers-retours entre écrans, et
//! peut donc être périmé — un dépôt crée une nouvelle racine que l'écran ne
//! voit pas tant que `R` n'est pas rappuyé.
//!
//! Les transitions `vers_*` du pilotage n'ont pas d'équivalent ici : `h` suffit
//! à entrer, et `passer_ecran_precedent` tient l'ordre des écrans.

use std::collections::HashSet;

use feu_application::{Carte, fiche::Fiche};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Margin},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListState},
};

use crate::tui::{
    EtatTui,
    rendu::{
        COULEUR_ACCENT, GUIDE_TUYAU, MARQUE_SELECTION, SYMBOLE_DONNEE, SYMBOLE_RACINE,
        SYMBOLE_REPERTOIRE_DEPLIE, SYMBOLE_REPERTOIRE_REPLIE, SYMBOLE_REPERTOIRE_VIDE,
        SYMBOLE_TEXTE, carre_principal,
    },
};

/// Longueur maximale d'un libellé affiché, ellipse comprise.
///
/// Comptée en caractères, jamais en octets. Le pourquoi de la borne est dans
/// [`libelle`], seul endroit qui l'applique.
const MAX_LONGUEUR_MOT: usize = 30;

/// Ce que l'écran d'arborescence retient d'une frame à l'autre.
///
/// L'arbre reçu, ce qui en est déplié, et où pointe le curseur — les trois
/// portées décrites en tête de module. Tous les champs sont privés : le seul
/// chemin vers eux passe par les méthodes ci-dessous, et le rendu, qui vit
/// dans ce fichier, les lit directement.
pub(super) struct EtatArborescenceEnu {
    /// Le dernier arbre reçu du cœur, à plat et prêt à dessiner : l'ordre est
    /// celui de l'affichage, la profondeur son décalage.
    ///
    /// `None` ne veut pas dire « arbre vide » mais **jamais demandé** — c'est
    /// lui qui distingue l'écran au premier abord d'un nœud sans contenu, et
    /// qui décidera lequel des deux messages afficher.
    arborescence_enus: Option<Vec<(usize, Fiche)>>,

    /// Les index de [`Self::arborescence_enus`] dont le sous-arbre est montré.
    ///
    /// **Les dépliés, non les repliés** : le défaut est fermé, un dépôt réel ne
    /// tiendrait pas à l'écran autrement. L'ensemble part donc avec le seul
    /// index `0`, la racine, sans quoi l'arbre s'afficherait sur une ligne.
    ///
    /// **L'identité d'un nœud est sa position dans le `Vec`, pas son
    /// `hash_carte`.** L'arborescence est un DAG et le parcours conserve les
    /// doublons : deux répertoires peuvent partager un sous-arbre identique,
    /// donc le même hash, et les replier ensemble alors que l'utilisateur n'en
    /// a désigné qu'un. La position, elle, désigne une occurrence et une seule.
    ///
    /// Le prix de ce choix est qu'un rechargement rend l'ensemble caduc — les
    /// index de l'ancien arbre ne veulent rien dire dans le nouveau. Cf.
    /// [`Self::recevoir_arborescence_enus`].
    deplies: HashSet<usize>,

    /// Ligne sélectionnée et défilement, tenus par Ratatui.
    ///
    /// Le [`ListState`] compte des rangs dans la liste **visible**, pas des
    /// index de l'arbre : replier un nœud sous le curseur ne le déplace donc
    /// pas. Toute lecture repasse par [`Self::lignes_visibles`] pour retrouver
    /// l'index brut.
    ///
    /// Il ne connaît ni le nombre d'items ni la hauteur du carré avant le
    /// rendu : c'est `render_stateful_widget` qui borne la sélection et ajuste
    /// l'offset, ce qui explique le `&mut EtatTui` du dessin. `select_next`
    /// peut donc déborder d'une frappe, corrigé à la frame suivante — les
    /// `get()` de ce module absorbent l'intervalle.
    curseur: ListState,
}

impl EtatArborescenceEnu {
    /// État initial : aucun chargement demandé.
    ///
    /// La racine est inscrite dépliée et le curseur posé sur la première ligne
    /// alors qu'il n'y a pas d'arbre — les deux valeurs n'ont d'effet qu'à
    /// l'arrivée du premier, et les poser ici évite un état intermédiaire où
    /// l'écran afficherait un arbre sans savoir où pointer.
    pub(super) fn new() -> Self {
        Self {
            arborescence_enus: None,
            deplies: HashSet::from([0]),
            curseur: ListState::default().with_selected(Some(0)),
        }
    }

    /// Remplace l'arbre affiché par celui que le cœur vient d'envoyer.
    ///
    /// **Ni les plis ni le curseur ne sont remis à leur état d'arrivée**, et
    /// les index qu'ils portent désignent alors d'autres nœuds : un `R` de
    /// rafraîchissement laisse dépliés des rangs qui ne correspondent plus, et
    /// le curseur retombe où il était. Rien n'en panique — le rendu borne la
    /// sélection, les lectures passent par `get` —, l'affichage est seulement
    /// arbitraire. Laissé tel quel le 18 août 2026, le temps de voir ce que
    /// donne l'usage réel ; à reprendre en posant ici `deplies` à `{0}` et le
    /// curseur à zéro, en même temps que l'arbre.
    pub(super) fn recevoir_arborescence_enus(&mut self, arborescence_enus: Vec<(usize, Fiche)>) {
        self.arborescence_enus = Some(arborescence_enus);
    }

    /// Les index de l'arbre à dessiner, dans l'ordre, plis appliqués.
    ///
    /// Recalculée à chaque appel plutôt que tenue à jour : elle est une
    /// fonction de l'arbre et de [`Self::deplies`], et un cache serait un
    /// troisième état à garder cohérent avec les deux autres. Le rendu comme le
    /// clavier l'appellent, et doivent voir la même chose.
    ///
    /// Le parcours du cœur est en profondeur d'abord : les descendants d'un
    /// nœud le suivent immédiatement et sont exactement les lignes plus
    /// profondes que lui, jusqu'à la première qui ne l'est plus. Replier revient
    /// donc à sauter d'un bloc, sans jamais remonter aux parents ni consulter le
    /// moindre hash.
    ///
    /// Boucle `while` et index tenu à la main : le pas dépend des données —
    /// sauter un sous-arbre de taille inconnue —, ce qu'un `for` ne sait pas
    /// faire. Les plis imbriqués tombent sans cas particulier, un nœud déplié
    /// à l'intérieur d'un replié n'étant jamais atteint.
    ///
    /// Arbre jamais chargé : liste vide, et non une erreur. L'écran a déjà son
    /// message d'invite, et les touches qui l'appellent n'ont alors rien à
    /// faire.
    pub(super) fn lignes_visibles(&self) -> Vec<usize> {
        let Some(arbre) = &self.arborescence_enus else {
            return Vec::new();
        };
        let mut visibles = Vec::new();
        let mut i = 0;
        while i < arbre.len() {
            visibles.push(i);
            let profondeur = arbre[i].0;
            i += 1;
            if !self.deplies.contains(&(i - 1)) {
                while i < arbre.len() && arbre[i].0 > profondeur {
                    i += 1;
                }
            }
        }

        visibles
    }

    /// Descend le curseur d'une ligne visible.
    ///
    /// Aucune borne ici : `select_next` ignore la longueur de la liste, et
    /// c'est le rendu qui ramène la sélection dans les clous à la frame
    /// suivante — cf. [`Self::curseur`]. Reprendre le calcul serait le faire
    /// deux fois, et deux fois différemment.
    pub(super) fn descendre_curseur(&mut self) {
        self.curseur.select_next();
    }

    /// Remonte le curseur d'une ligne visible.
    ///
    /// `select_previous` s'arrête de lui-même à zéro, la sélection étant un
    /// `usize`.
    pub(super) fn monter_curseur(&mut self) {
        self.curseur.select_previous();
    }

    /// Replie ou déplie le répertoire sous le curseur.
    ///
    /// Trois sorties silencieuses avant d'agir : pas d'arbre, pas de
    /// sélection, ou une sélection hors de la liste visible — cette dernière
    /// couvre le débordement d'une frappe décrit sur [`Self::curseur`].
    ///
    /// **Seuls les répertoires peuplés basculent.** Un `matches!` avec garde
    /// écarte les feuilles et les répertoires vides : les laisser entrer ne
    /// changerait rien à l'affichage, mais [`Self::deplies`] se remplirait
    /// d'index sans effet. Le court-circuit du `&&` fait que `remove` n'est
    /// même pas tenté sur eux.
    ///
    /// « Si on ne peut pas le retirer, on l'ajoute » : `HashSet::remove` rend
    /// `false` quand l'index était absent, ce qui est exactement la condition
    /// d'insertion. Une bascule en une expression, sans lecture préalable.
    pub(super) fn basculer_pli(&mut self) {
        let Some(arborescence_enus) = &self.arborescence_enus else {
            return;
        };
        let Some(curseur) = self.curseur.selected() else {
            return;
        };
        let Some(index) = self.lignes_visibles().get(curseur).copied() else {
            return;
        };

        if matches!(arborescence_enus[index].1.carte(), Carte::Repertoire { hashs_enu, .. } if !hashs_enu.is_empty())
            && !self.deplies.remove(&index)
        {
            self.deplies.insert(index);
        }
    }

    /// La fiche sous le curseur, à ranger dans
    /// [`crate::tui::EtatTui::enu_selectionnee`].
    ///
    /// `None` dans les mêmes trois cas que [`Self::basculer_pli`], d'où les
    /// trois `?` — la forme condensée du même filtre, permise ici par le type
    /// de retour.
    ///
    /// Rend un clone, et pas une référence : la marque survit à l'arbre dont
    /// elle est tirée, qu'un `R` remplacera. Le clone est celui d'une [`Fiche`],
    /// donc sans la signature de 4 627 octets, qui ne quitte jamais
    /// `feu-application`.
    ///
    /// Aucune vérification sur ce qui est retenu : toute entrée peut l'être,
    /// répertoire, donnée ou racine. C'est la commande qui la consommera qui
    /// dira si elle lui convient.
    pub(super) fn donne_enu_a_marquer(&self) -> Option<Fiche> {
        let arborescence_enus = self.arborescence_enus.as_ref()?;
        let index = self
            .lignes_visibles()
            .get(self.curseur.selected()?)
            .copied()?;

        Some(arborescence_enus[index].1.clone())
    }
}

/// Dessine l'arbre et les messages éphémères.
///
/// Le carré est celui du pilotage, dessiné par
/// [`super::rendu::carre_principal`] ; ne reste ici que la marge de découpe,
/// plus haute que la sienne. L'arbre prend le `Fill`, ce qui reste est fixe :
/// une respiration en haut, deux en bas, puis les deux lignes de message.
///
/// Les messages sont rendus hors du `match` sur l'arbre : ils traversent la
/// TUI et ne dépendent pas du chargement, si bien qu'une erreur reçue avant
/// tout `R` reste lisible sur l'écran d'invite.
///
/// L'arbre arrive dans l'ordre de l'affichage, chaque entrée précédée de sa
/// profondeur : le rendu n'a plus qu'à répéter le motif d'indentation autant de
/// fois, ligne par ligne. Il ne dessine que ce que
/// [`EtatArborescenceEnu::lignes_visibles`] lui désigne.
///
/// **Une [`List`], et non un `Paragraph`** : le défilement et la borne de la
/// sélection viennent avec, et la barre du curseur traverse toute la largeur
/// au lieu de s'arrêter à la fin du nom. C'est ce qui impose le `&mut EtatTui`
/// — un `StatefulWidget` écrit dans son état au moment du rendu, seul instant
/// où la hauteur du carré et le nombre d'items sont connus.
///
/// La colonne de marque ouvre chaque ligne, large de deux cellules qu'une ENU
/// soit retenue ou non : l'arbre reste immobile quand la marque se pose. La
/// comparaison porte sur le `hash_carte`, si bien qu'une ENU présente à deux
/// endroits d'un DAG est marquée aux deux — c'est la même, la montrer une seule
/// fois mentirait.
///
/// L'`Option` distingue **jamais demandé** — l'invite à taper `R` — de l'arbre
/// reçu. Le troisième cas, un arbre réduit à sa seule racine, n'est pas encore
/// séparé du second.
pub(super) fn dessiner_ecran_arborescence_enu(frame: &mut Frame, etat_tui: &mut EtatTui) {
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

    // [1] arborescence
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
            let lignes = etat_tui
                .etat_arborescence_enu
                .lignes_visibles()
                .iter()
                .map(|i| {
                    let (profondeur, fiche) = &arborescence_enu[*i];

                    // Colonne de marque, large de deux cellules qu'une fiche
                    // soit retenue ou non : c'est elle qui garde l'arbre
                    // immobile quand la marque se pose ou se retire.
                    let marquee = etat_tui
                        .enu_selectionnee
                        .as_ref()
                        .is_some_and(|selectionnee| {
                            selectionnee.hash_carte() == fiche.hash_carte()
                        });

                    Line::from(vec![
                        Span::styled(
                            if marquee {
                                format!("{MARQUE_SELECTION} ")
                            } else {
                                String::from("  ")
                            },
                            Style::default().fg(COULEUR_ACCENT),
                        ),
                        Span::styled(
                            format!("{GUIDE_TUYAU} ").repeat(*profondeur),
                            Style::default().add_modifier(Modifier::DIM),
                        ),
                        symbole(fiche, etat_tui.etat_arborescence_enu.deplies.contains(i)),
                        Span::raw(" "),
                        Span::raw(libelle(fiche)),
                    ])
                })
                .collect::<Vec<Line>>();

            let liste = List::new(lignes)
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

            frame.render_stateful_widget(
                liste,
                carre_lignes[1],
                &mut etat_tui.etat_arborescence_enu.curseur,
            );
        }
    }
}

/// Le nom affiché d'une entrée, à droite de son symbole.
///
/// **Point de passage unique du nom vers l'écran, et donc là où il est
/// assaini.** Un nom de fichier Unix accepte tout sauf `/` et l'octet nul :
/// `nom_fichier_valide` ne refuse que le vide, le séparateur et les composants
/// spéciaux, un retour à la ligne ou une séquence d'échappement peut donc
/// arriver jusqu'ici et casser le carré. Les caractères de contrôle sont
/// remplacés plutôt que supprimés — deux noms distincts ne doivent pas devenir
/// identiques à l'écran, et le `?` montre l'anomalie au lieu de la masquer.
///
/// **Le nom est borné à [`MAX_LONGUEUR_MOT`]**, le dernier caractère portant
/// l'ellipse. Le `Paragraph` couperait de toute façon à droite : la limite est
/// là pour que la coupe se voie, et pour qu'un nom à rallonge ne masque pas les
/// lignes voisines. Comptée en caractères et non en octets — un accent en pèse
/// deux, et trancher un `&str` au milieu de l'un d'eux paniquerait.
///
/// **Une racine se reconnaît à sa méta `_racine`**, non à sa position : elle est
/// la seule entrée sans méta `nom`, mais la reconnaître par ce qu'elle porte
/// tient même si le parcours part un jour d'ailleurs que du sommet. Elle rend
/// une chaîne vide — son symbole la désigne déjà, un mot n'apprendrait rien.
///
/// Le hash a été écarté comme repli : le dépôt pose toujours `nom`, une entrée
/// qui en manque relève de l'anomalie, et huit caractères d'hexadécimal ne
/// l'expliqueraient à personne.
///
/// `pub(super)` parce que l'écran de pilotage l'appelle pour afficher l'ENU
/// retenue : le même nom, assaini et borné de la même façon, sur les deux
/// écrans. Un écran qui en importe un autre reste une entorse — sa place est
/// `rendu.rs`, avec le reste du vocabulaire commun, et le déménagement est noté
/// dans `a_faire.md`.
pub(super) fn libelle(fiche: &Fiche) -> String {
    match fiche.carte().metas().get("nom") {
        Some(nom) => {
            let mut libelle = String::from(nom);
            if libelle.chars().count() > MAX_LONGUEUR_MOT {
                libelle = libelle
                    .chars()
                    .take(MAX_LONGUEUR_MOT - 1)
                    .collect::<String>();
                libelle.push('…');
            }

            libelle
                .chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect::<String>()
        }
        None => {
            if fiche.carte().metas().get("_racine").is_some() {
                return String::new();
            }
            String::from("(sans nom)")
        }
    }
}

/// Le symbole qui précède le libellé, d'après la variante de [`Carte`], prêt à
/// poser dans la ligne.
///
/// **Un [`Span`] et non un `&str`** : la forme et la couleur du symbole
/// relèvent de la même décision, et les rendre ensemble évite que l'appelant
/// rejoue le `match` pour savoir quoi styler.
///
/// **Seuls les deux triangles pliables portent [`COULEUR_ACCENT`]** : ce sont
/// eux qui disent qu'il y a quelque chose à ouvrir ou à fermer. Le répertoire
/// vide reste au premier plan neutre — il ne répond à aucun pli —, comme la
/// racine et les feuilles.
///
/// La racine est une [`Carte::Repertoire`] comme une autre, seule sa méta
/// `_racine` la distingue, et elle est testée avant le pli parce que son
/// symbole dit *ce qu'elle est*, ce qu'aucun triangle ne dirait — elle seule
/// n'a pas de nom à afficher.
///
/// Un répertoire vide reçoit le sien : le déplier ne montrerait rien, et lui
/// laisser la marque des répertoires peuplés promettrait un contenu.
///
/// L'orientation du triangle dit l'état du pli, d'où le `deplie` en second
/// argument : la carte seule ne peut pas le savoir, il vit dans
/// [`EtatArborescenceEnu::deplies`]. Un répertoire vide l'ignore — il n'a pas
/// d'état de pli, seulement rien à montrer.
fn symbole(fiche: &Fiche, deplie: bool) -> Span<'static> {
    let symbole = match fiche.carte() {
        Carte::Donnee { .. } => SYMBOLE_DONNEE,
        Carte::Texte { .. } => SYMBOLE_TEXTE,
        Carte::Repertoire {
            metas, hashs_enu, ..
        } => {
            if metas.get("_racine").is_some() {
                SYMBOLE_RACINE
            } else if hashs_enu.is_empty() {
                SYMBOLE_REPERTOIRE_VIDE
            } else if deplie {
                SYMBOLE_REPERTOIRE_DEPLIE
            } else {
                SYMBOLE_REPERTOIRE_REPLIE
            }
        }
    };
    if symbole == SYMBOLE_REPERTOIRE_DEPLIE || symbole == SYMBOLE_REPERTOIRE_REPLIE {
        Span::styled(symbole, Style::default().fg(COULEUR_ACCENT))
    } else {
        Span::raw(symbole)
    }
}
