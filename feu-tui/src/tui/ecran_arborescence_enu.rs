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

use crate::{
    erreur::{ErreurFeuTui, ResultFeuTui},
    tui::{
        EtatTui,
        rendu::{
            COULEUR_ACCENT, GUIDE_TUYAU, MARQUE_SELECTION, MAX_LONGUEUR_MOT, SYMBOLE_DONNEE,
            SYMBOLE_RACINE, SYMBOLE_REPERTOIRE_DEPLIE, SYMBOLE_REPERTOIRE_REPLIE,
            SYMBOLE_REPERTOIRE_VIDE, SYMBOLE_TEXTE, carre_principal,
        },
    },
};

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
    /// `None` ne veut pas dire « arbre vide » mais **rien à montrer** : jamais
    /// demandé, ou invalidé par un dépôt. C'est lui qui distingue l'écran d'un
    /// nœud sans contenu, et il porte le même appel au `R` dans les deux cas.
    arborescence_enus: Option<Vec<(usize, Fiche)>>,

    /// Les index de [`Self::arborescence_enus`] dont le sous-arbre est montré.
    ///
    /// **Les dépliés, non les repliés** : le défaut est fermé, un dépôt réel ne
    /// tiendrait pas à l'écran. L'ensemble part avec le seul index `0`.
    ///
    /// **L'identité d'un nœud est sa position, pas son `hash_carte`** :
    /// l'arborescence étant un DAG, deux répertoires partageant un sous-arbre
    /// portent le même hash et se replieraient ensemble.
    ///
    /// Prix de ce choix : un rechargement rend l'ensemble caduc.
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
    /// **Recalculée à chaque appel** : elle est fonction de l'arbre et de
    /// [`Self::deplies`], un cache serait un troisième état à tenir cohérent.
    ///
    /// Le parcours étant en profondeur d'abord, les descendants d'un nœud sont
    /// exactement les lignes plus profondes qui le suivent : replier revient à
    /// sauter un bloc, sans remonter aux parents ni lire un hash. D'où la boucle
    /// `while`, dont le pas dépend des données.
    ///
    /// Arbre jamais chargé : liste vide, pas une erreur.
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
    /// Trois refus avant d'agir, chacun portant sa variante : pas d'arbre, pas
    /// de sélection, sélection hors de la liste visible.
    ///
    /// **Seuls les répertoires peuplés basculent** : laisser entrer les feuilles
    /// ne changerait rien à l'affichage mais remplirait [`Self::deplies`] d'index
    /// sans effet.
    ///
    /// « Si on ne peut pas le retirer, on l'ajoute » : `HashSet::remove` rend
    /// `false` quand l'index était absent, exactement la condition d'insertion.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuTui::EnuSansArborescence`] si aucun arbre n'a été demandé.
    /// [`ErreurFeuTui::EnuSansCurseur`] si rien n'est sélectionné.
    /// [`ErreurFeuTui::EnuSelectionHorsListe`] si le curseur dépasse les lignes visibles.
    pub(super) fn basculer_pli(&mut self) -> ResultFeuTui<()> {
        let Some(arborescence_enus) = &self.arborescence_enus else {
            return Err(ErreurFeuTui::EnuSansArborescence);
        };
        let Some(curseur) = self.curseur.selected() else {
            return Err(ErreurFeuTui::EnuSansCurseur);
        };
        let Some(index) = self.lignes_visibles().get(curseur).copied() else {
            return Err(ErreurFeuTui::EnuSelectionHorsListe);
        };

        if matches!(arborescence_enus[index].1.carte(), Carte::Repertoire { hashs_enu, .. } if !hashs_enu.is_empty())
            && !self.deplies.remove(&index)
        {
            self.deplies.insert(index);
        }

        Ok(())
    }

    /// La fiche sous le curseur, à ranger dans
    /// [`crate::tui::EtatTui::enu_selectionnee`].
    ///
    /// `None` dans les mêmes trois cas que [`Self::basculer_pli`], d'où les trois
    /// `?`.
    ///
    /// Rend un **clone** : la marque survit à l'arbre dont elle est tirée, qu'un
    /// `R` remplacera.
    ///
    /// Aucune vérification sur ce qui est retenu — c'est la commande qui la
    /// consommera qui dira si elle lui convient.
    pub(super) fn donne_enu_a_marquer(&self) -> Option<Fiche> {
        let arborescence_enus = self.arborescence_enus.as_ref()?;
        let index = self
            .lignes_visibles()
            .get(self.curseur.selected()?)
            .copied()?;

        Some(arborescence_enus[index].1.clone())
    }

    /// Jette l'arbre affiché, qu'un dépôt vient de rendre faux.
    ///
    /// Les fiches qu'il portait désignent des ENU sorties de l'arbre courant, et
    /// une commande qui en recevrait une serait refusée. L'écran retombe sur son
    /// appel au `R`, plutôt que de recharger d'office : le parcours coûte, et
    /// rien ne dit que l'utilisateur veut le revoir tout de suite.
    ///
    /// Ni les plis ni le curseur ne sont touchés — voir
    /// [`Self::recevoir_arborescence_enus`], qui les laisse déjà tels quels.
    pub(super) fn vider_arborescence(&mut self) {
        self.arborescence_enus = None;
    }
}

/// Dessine l'arbre et les messages éphémères.
///
/// Le carré vient de [`super::rendu::carre_principal`] ; ne reste ici que la
/// marge de découpe. Les messages sont rendus **hors du `match` sur l'arbre** :
/// une erreur reçue avant tout `R` reste lisible sur l'écran d'invite.
///
/// L'arbre arrive dans l'ordre de l'affichage, chaque entrée précédée de sa
/// profondeur : le rendu répète le motif d'indentation, sans rien reconstruire.
///
/// **Une [`List`], et non un `Paragraph`** : défilement et borne de sélection
/// viennent avec. D'où le `&mut EtatTui`, écrit au moment du rendu.
///
/// La colonne de marque est large de deux cellules qu'une ENU soit retenue ou
/// non : l'arbre reste immobile quand la marque se pose.
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
/// assaini.** Un nom Unix n'interdit que `/` et l'octet nul : un retour à la
/// ligne peut arriver jusqu'ici et casser le carré. Les caractères de contrôle
/// sont **remplacés, pas supprimés** — deux noms distincts ne doivent pas
/// devenir identiques à l'écran.
///
/// **Borné à [`MAX_LONGUEUR_MOT`]**, ellipse comprise, compté en caractères et
/// non en octets : trancher un `&str` au milieu d'un accent paniquerait.
///
/// **Une racine se reconnaît à sa méta `_racine`**, non à sa position, et rend
/// une chaîne vide — son symbole la désigne déjà.
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
/// **Un [`Span`] et non un `&str`** : forme et couleur relèvent de la même
/// décision, l'appelant n'a pas à rejouer le `match` pour styler.
///
/// **Seuls les deux triangles pliables portent [`COULEUR_ACCENT`]** : eux seuls
/// disent qu'il y a quelque chose à ouvrir. Le répertoire vide reçoit un symbole
/// propre — lui laisser celui des peuplés promettrait un contenu.
///
/// La racine est testée avant le pli : son symbole dit *ce qu'elle est*, ce
/// qu'aucun triangle ne dirait. L'orientation du triangle, elle, dit l'état du
/// pli, d'où le `deplie` en second argument.
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
