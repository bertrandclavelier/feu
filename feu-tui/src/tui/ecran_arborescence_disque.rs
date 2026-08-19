// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Écran d'arborescence du disque : le sélecteur de fichiers.
//!
//! `l` y mène depuis le pilotage, dont il est le voisin de droite ; `h` en
//! revient. On y navigue à `j` et `k`, `Entrée` ouvre ou ferme un répertoire,
//! `R` relit celui sous le curseur, `m` retient son chemin dans
//! [`crate::tui::EtatTui::chemin_selectionne`] — d'où le pilotage le lira — et
//! `x` l'y efface. Mêmes touches que sur l'écran des ENU, pour les mêmes
//! gestes.
//!
//! Le manque qu'il vient combler est écrit ailleurs : `CHEMIN_COMPTOIR_DEPOT`,
//! dans [`crate::tui`], tient en dur la place d'un chemin que l'utilisateur ne
//! peut désigner nulle part.
//!
//! # Un arbre qui se construit, là où celui des ENU se masque
//!
//! [`EtatArborescenceDisque::lignes`] contient **exactement ce qui est
//! dessiné**, pas le disque parcouru : ouvrir un répertoire y insère ses
//! enfants, fermer les retire. D'où l'absence de tout `lignes_visibles` — la
//! liste est déjà la liste — et le `deplie` porté par chaque ligne plutôt qu'un
//! ensemble d'index à côté : chaque insertion décale ce qui suit, et des index
//! tenus ailleurs deviendraient faux au premier dépli.
//!
//! Le prix est qu'un répertoire refermé est relu quand on le rouvre. Il est nul
//! en local, et il achète l'absence de tout cache à tenir d'accord avec le
//! disque.
//!
//! **La lecture se fait ici, pas dans le cœur.** Un sélecteur de fichiers
//! collecte une intention ; c'est ce qu'on en fait — ouvrir un comptoir — qui
//! regarde `feu-application`. Un dépli est une lecture d'un seul niveau sur une
//! frappe : rien qui justifie de traverser le canal, ni de loger un explorateur
//! de fichiers dans la couche métier.
//!
//! **L'arbre n'est jamais rafraîchi tout seul.** Ce qu'on voit est l'état de
//! chaque répertoire à l'instant où il a été ouvert ; `R` est ce qui remet une
//! branche à jour. Surveiller le disque demanderait un observateur et un canal
//! de plus, pour un écran qu'on ne regarde que par intermittence.
//!
//! La découpe verticale est celle de [`super::ecran_arborescence_enu`] à
//! l'identique — les deux écrans doivent poser leurs messages sur la même
//! ligne, sans quoi le texte sauterait en changeant d'onglet.

use std::{
    fs::read_dir,
    path::{Path, PathBuf},
};

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
        COULEUR_ACCENT, GUIDE_TUYAU, MARQUE_SELECTION, MAX_LONGUEUR_MOT, SYMBOLE_DONNEE,
        SYMBOLE_REPERTOIRE_DEPLIE, SYMBOLE_REPERTOIRE_REPLIE, carre_principal,
    },
};

/// Une ligne de l'arbre, telle qu'elle sera dessinée.
///
/// Le nom affiché n'y figure pas : il est dans le chemin, et [`libelle`] l'en
/// tire au rendu. Le tenir en double serait un second état à garder d'accord
/// avec le premier.
struct LigneDisque {
    /// Chemin absolu de l'entrée — son identité, et de quoi la relire.
    chemin: PathBuf,
    /// Décalage à l'affichage, et surtout ce qui délimite un sous-arbre : les
    /// descendants d'une ligne sont ceux qui la suivent tant qu'ils sont plus
    /// profonds qu'elle (cf. [`EtatArborescenceDisque::replier`]).
    profondeur: usize,
    /// Lu à `is_dir`, qui suit les liens symboliques : un lien vers un dossier
    /// s'ouvre comme le dossier.
    est_repertoire: bool,
    /// Vrai quand les enfants de cette ligne sont présents dans la liste.
    deplie: bool,
}

/// Ce que l'écran du disque retient d'une frame à l'autre.
///
/// Deux champs, et rien de plus : la liste est déjà l'affichage, et le curseur
/// est tenu par Ratatui.
pub(super) struct EtatArborescenceDisque {
    /// L'arbre tel qu'il est dessiné, dans l'ordre, une entrée par ligne — cf.
    /// l'entête du module pour la raison de cette forme.
    lignes: Vec<LigneDisque>,

    /// Ligne sélectionnée et défilement, tenus par Ratatui.
    ///
    /// Il compte des rangs dans [`Self::lignes`], qui sont directement les
    /// index de l'arbre — aucune conversion, contrairement à l'écran des ENU où
    /// la liste visible est un sous-ensemble.
    ///
    /// Il ne connaît ni le nombre d'items ni la hauteur du carré avant le
    /// rendu, ce qui explique le `&mut EtatTui` du dessin : `select_next` peut
    /// déborder d'une frappe, corrigé à la frame suivante — les `get()` de ce
    /// module absorbent l'intervalle.
    curseur: ListState,
}

impl EtatArborescenceDisque {
    /// État initial : la racine seule, fermée.
    ///
    /// `~` est posé comme une ligne ordinaire, et l'écran n'a donc pas d'état
    /// « rien chargé » à distinguer : arriver dessus montre déjà quelque chose,
    /// sans avoir rien lu du disque.
    ///
    /// Le chemin vient du binaire, jamais de l'environnement lu ici — cf. le
    /// commentaire d'entrée de `main`.
    pub(super) fn new(chemin_home: &Path) -> Self {
        let lignes = vec![LigneDisque {
            chemin: PathBuf::from(chemin_home),
            profondeur: 0,
            est_repertoire: true,
            deplie: false,
        }];
        Self {
            lignes,
            curseur: ListState::default().with_selected(Some(0)),
        }
    }

    /// Descend le curseur d'une ligne.
    ///
    /// Aucune borne ici : `select_next` ignore la longueur de la liste, et
    /// c'est le rendu qui ramène la sélection dans les clous à la frame
    /// suivante — cf. [`Self::curseur`].
    pub(super) fn descendre_curseur(&mut self) {
        self.curseur.select_next();
    }

    /// Remonte le curseur d'une ligne.
    ///
    /// `select_previous` s'arrête de lui-même à zéro, la sélection étant un
    /// `usize`.
    pub(super) fn monter_curseur(&mut self) {
        self.curseur.select_previous();
    }

    /// Relit du disque le répertoire ouvert sous le curseur.
    ///
    /// Le seul moyen de voir un fichier déposé depuis un autre programme :
    /// l'arbre ne se rafraîchit jamais seul. Replier puis déplier suffit — le
    /// premier jette la tranche, le second la relit —, sans une ligne de code
    /// propre au rafraîchissement.
    ///
    /// **La branche sous le curseur, et non l'arbre entier ni le parent** :
    /// recharger plus haut jetterait les plis ouverts des répertoires frères,
    /// que rien ne rétablirait. Ce qui disparaît ici est ce qu'on a demandé à
    /// relire.
    ///
    /// Le test sur `est_repertoire` est redondant — `deplie` ne peut être vrai
    /// que sur un répertoire — et le reste : l'invariant est écrit plutôt que
    /// supposé.
    pub(super) fn recharger(&mut self) {
        let Some(curseur) = self.curseur.selected() else {
            return;
        };
        let Some(ligne) = self.lignes.get(curseur) else {
            return;
        };
        if ligne.est_repertoire && ligne.deplie {
            self.replier(curseur);
            self.deplier(curseur);
        }
    }

    /// Ouvre ou ferme le répertoire sous le curseur.
    ///
    /// **Seule porte d'entrée depuis le clavier**, et donc le seul endroit qui
    /// vérifie : deux sorties silencieuses — pas de sélection, sélection hors
    /// de la liste, ce dernier couvrant le débordement d'une frappe décrit sur
    /// [`Self::curseur`] — puis le refus des lignes qui ne sont pas des
    /// répertoires. [`Self::deplier`] et [`Self::replier`] ne retestent rien :
    /// elles reçoivent un index déjà validé.
    ///
    /// `deplie` n'est pas une condition mais l'aiguillage : il dit laquelle des
    /// deux appeler.
    pub(super) fn basculer_pli(&mut self) {
        let Some(curseur) = self.curseur.selected() else {
            return;
        };
        let Some(ligne) = self.lignes.get(curseur) else {
            return;
        };
        if !ligne.est_repertoire {
            return;
        }

        if ligne.deplie {
            self.replier(curseur);
        } else {
            self.deplier(curseur);
        }
    }

    /// Lit un niveau du disque et insère ses entrées sous la ligne `index`.
    ///
    /// **Un seul niveau par appel** : c'est ce qui borne le coût d'une frappe
    /// et rend l'arbre paresseux. Un parcours récursif depuis `~` lirait le
    /// disque entier.
    ///
    /// Trois précautions dans la lecture. Le chemin est cloné et la profondeur
    /// copiée avant tout : la suite mute `lignes`, et l'emprunt sur la ligne
    /// source ne peut pas courir jusque-là. Les entrées en erreur sont
    /// écartées par `flatten` — une entrée peut disparaître entre l'ouverture
    /// du répertoire et sa lecture, ce n'est pas une raison de perdre les
    /// autres. Un `read_dir` en échec, lui, laisse la ligne fermée : un
    /// répertoire illisible se comporte comme un répertoire vide, faute d'un
    /// type d'erreur propre à `feu-tui` par où le signaler.
    ///
    /// **Les entrées cachées sont écartées**, `~` en étant rempli — `.config`,
    /// `.cargo`, `.local` noieraient ce que l'utilisateur cherche. Les montrer
    /// un jour demandera de relire les répertoires déjà ouverts, donc une
    /// bascule et non un simple filtre au rendu.
    ///
    /// Le tri se fait en deux passes plutôt qu'en une comparaison composée :
    /// par chemin d'abord, puis les répertoires en tête (`!est_repertoire`,
    /// puisque `false` précède `true`). Le tri de Rust étant stable, la
    /// première passe survit à la seconde à l'intérieur de chaque groupe. Trier
    /// sur le chemin entier revient à trier sur le nom, tous partageant le même
    /// parent. C'est l'ordre des octets, donc majuscules et accents ne se
    /// rangent pas comme dans un dictionnaire — suffisant pour s'y retrouver.
    ///
    /// L'insertion est un `splice` sur une plage vide, et non une boucle
    /// d'`insert` : chacun décalerait le précédent, et les enfants sortiraient
    /// en ordre inverse.
    fn deplier(&mut self, index: usize) {
        let LigneDisque {
            chemin,
            profondeur,
            est_repertoire: _,
            deplie: _,
        } = self.lignes.get(index).unwrap();

        let chemin = chemin.clone();
        let profondeur = *profondeur;

        let Ok(entrees) = read_dir(&chemin) else {
            return;
        };

        let mut lignes_temp = Vec::new();
        for entree in entrees.flatten() {
            let chemin = entree.path();
            if entree.file_name().as_encoded_bytes().starts_with(b".") {
                continue;
            }

            let ligne = LigneDisque {
                est_repertoire: chemin.is_dir(),
                chemin,
                profondeur: profondeur + 1,
                deplie: false,
            };
            lignes_temp.push(ligne);
        }

        lignes_temp.sort_by(|a, b| a.chemin.cmp(&b.chemin));
        lignes_temp.sort_by_key(|l| !l.est_repertoire);

        self.lignes.splice(index + 1..index + 1, lignes_temp);

        self.lignes[index].deplie = true;
    }

    /// Retire de la liste tout le sous-arbre de la ligne `index`.
    ///
    /// Ses descendants sont exactement les lignes qui la suivent tant qu'elles
    /// sont plus profondes qu'elle : la première qui ne l'est plus borne le
    /// bloc. Aucun chemin n'est comparé, aucun parent n'est remonté.
    ///
    /// Boucle `while` et index tenu à la main, comme dans
    /// [`super::ecran_arborescence_enu::EtatArborescenceEnu::lignes_visibles`] :
    /// le pas dépend des données, ce qu'un `for` ne sait pas faire.
    ///
    /// **`fin` se calcule entièrement avant de muter.** Supprimer au fil du
    /// parcours décalerait ce qui suit et fausserait les index restants.
    ///
    /// Les plis imbriqués tombent sans cas particulier : un sous-répertoire
    /// ouvert est dans la tranche, il part avec elle. Rouvrir la ligne le
    /// retrouvera fermé, l'arbre ne gardant en mémoire que ce qu'il affiche.
    fn replier(&mut self, index: usize) {
        let profondeur = self.lignes[index].profondeur;

        let mut fin = index + 1;
        while fin < self.lignes.len() && self.lignes[fin].profondeur > profondeur {
            fin += 1;
        }

        self.lignes.drain(index + 1..fin);
        self.lignes[index].deplie = false;
    }

    /// Le chemin sous le curseur, à ranger dans
    /// [`crate::tui::EtatTui::chemin_selectionne`].
    ///
    /// `None` dans les deux premiers cas de [`Self::basculer_pli`], d'où les
    /// deux `?` — la forme condensée du même filtre, permise ici par le type de
    /// retour.
    ///
    /// Aucune vérification sur ce qui est retenu : fichier comme répertoire.
    /// C'est la commande qui le consommera qui dira s'il lui convient — un
    /// comptoir attend un dossier, un dépôt d'ENU attendra un fichier.
    ///
    /// Rend un clone : la marque survit au repli de la branche dont elle est
    /// tirée.
    pub(super) fn donne_chemin_a_marquer(&self) -> Option<PathBuf> {
        let curseur = self.curseur.selected()?;

        Some(self.lignes.get(curseur)?.chemin.clone())
    }
}

/// Dessine l'arborescence du disque et les messages éphémères.
///
/// Le carré est celui des autres écrans de travail, dessiné par
/// [`super::rendu::carre_principal`] ; ne reste ici que la marge de découpe.
/// L'arbre prend le `Fill`, ce qui reste est fixe : les respirations et les
/// deux lignes de message, à la même hauteur que sur l'écran des ENU.
///
/// Le `Vec` de lignes est déjà ce qu'il faut dessiner — un pli ne masque rien,
/// il retire —, donc le rendu le parcourt tel quel : la profondeur de chaque
/// ligne donne son indentation, son état donne son symbole.
///
/// **En `&mut EtatTui`** : le [`ListState`] est écrit au moment du rendu, seul
/// instant où la hauteur du carré et le nombre d'items sont connus. C'est lui
/// qui borne la sélection et pose le défilement.
///
/// La colonne de marque ouvre chaque ligne, large de deux cellules qu'un chemin
/// soit retenu ou non : l'arbre reste immobile quand la marque se pose. La
/// comparaison porte sur le chemin entier, qui est l'identité d'une entrée —
/// une seule ligne peut donc être marquée.
///
/// Rien n'est prévu pour une liste vide : la racine est toujours là.
pub(super) fn dessiner_ecran_arborescence_disque(frame: &mut Frame, etat_tui: &mut EtatTui) {
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

    // [1] arborescence
    let mut lignes_a_afficher = Vec::new();
    for ligne in &etat_tui.etat_arborescence_disque.lignes {
        let marquee = etat_tui
            .chemin_selectionne
            .as_ref()
            .is_some_and(|selectionne| selectionne == &ligne.chemin);

        let l = Line::from(vec![
            Span::styled(
                if marquee {
                    format!("{MARQUE_SELECTION} ")
                } else {
                    String::from("  ")
                },
                Style::default().fg(COULEUR_ACCENT),
            ),
            Span::styled(
                format!("{GUIDE_TUYAU} ").repeat(ligne.profondeur),
                Style::default().add_modifier(Modifier::DIM),
            ),
            symbole(ligne),
            Span::raw(" "),
            Span::raw(libelle(ligne)),
        ]);

        lignes_a_afficher.push(l);
    }

    let liste = List::new(lignes_a_afficher)
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_stateful_widget(
        liste,
        carre_lignes[1],
        &mut etat_tui.etat_arborescence_disque.curseur,
    );

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

/// Le nom affiché d'une ligne, à droite de son symbole.
///
/// **Point de passage unique du nom du disque vers l'écran, et donc là où il
/// est assaini.** Un nom de fichier Unix n'interdit que `/` et l'octet nul :
/// un retour à la ligne ou une séquence d'échappement peut arriver jusqu'ici et
/// casser le carré. Les caractères de contrôle sont remplacés plutôt que
/// supprimés — deux noms distincts ne doivent pas devenir identiques à l'écran.
///
/// La longueur est bornée à [`MAX_LONGUEUR_MOT`], ellipse comprise, et comptée
/// en caractères et non en octets. Un nom long est le cas courant, pas le cas
/// tordu : un export daté ou un PDF téléchargé déborde vite d'un carré de
/// 70 colonnes.
///
/// `to_string_lossy` traite les noms non UTF-8, que le disque accepte : les
/// octets invalides deviennent `U+FFFD`. L'entrée reste désignable, son chemin
/// n'étant jamais reconstruit depuis ce texte.
///
/// L'`unwrap` sur `file_name` ne tombe que sur la racine `/`, qui n'entre dans
/// l'arbre que si `HOME` la vaut.
fn libelle(ligne: &LigneDisque) -> String {
    let nom = ligne.chemin.file_name().unwrap().to_string_lossy();

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

/// Le symbole en tête de ligne : la nature de l'entrée, et l'état de son pli.
///
/// Trois cas là où l'écran des ENU en a plus : le disque ne distingue ni les
/// textes des données — rien ici ne lit un fichier —, ni les répertoires vides
/// des répertoires fermés, ce qui demanderait de lire chacun d'eux pour
/// dessiner une ligne.
fn symbole(ligne: &LigneDisque) -> Span<'static> {
    if !ligne.est_repertoire {
        Span::raw(SYMBOLE_DONNEE)
    } else if ligne.deplie {
        Span::styled(
            SYMBOLE_REPERTOIRE_DEPLIE,
            Style::default().fg(COULEUR_ACCENT),
        )
    } else {
        Span::styled(
            SYMBOLE_REPERTOIRE_REPLIE,
            Style::default().fg(COULEUR_ACCENT),
        )
    }
}
