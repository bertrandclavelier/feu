// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Filtrage contextuel des commandes utilisateur.
//!
//! Ce module fournit l'abstraction qui sépare *quelles touches sont actives*
//! de *ce qu'elles font*. La boucle clavier de [`crate::tui::Tui`] n'a plus
//! à connaître ni les raccourcis hardcodés, ni les conditions sous lesquelles
//! ils sont valides — elle interroge simplement [`CommandesActives`] et
//! dispatche la [`Commande`] retournée, ou ne fait rien.
//!
//! # Modèle
//!
//! Une [`Commande`] est une intention métier ; un tuple
//! `(KeyCode, KeyModifiers)` est sa liaison clavier. La table
//! [`CommandesActives`] mappe les liaisons aux commandes effectivement
//! disponibles dans le contexte courant.
//!
//! Le sens du mapping — touche → commande — est dicté par le chemin chaud :
//! sur chaque frappe, la TUI doit retrouver la commande correspondante en O(1).
//!
//! # Cartographie clavier
//!
//! Trois touches sont actives partout, quel que soit l'écran : `h` et `l`
//! passent d'un écran à l'autre, `?` liste ce qui est actif. Le reste dépend de
//! l'écran — sur les deux arborescences, `R` charge ou rafraîchit l'arbre, `j`
//! et `k` déplacent le curseur, `Entrée` plie ou déplie un répertoire, `m`
//! retient ce qui est sous le curseur (une ENU, ou un chemin du disque) et `x`
//! lève la marque ; les cas ci-dessous sont ceux du pilotage.
//!
//! Deux autres y sont omises pour ne pas alourdir la liste : `!` affiche
//! l'à-propos en toute circonstance, `r` retire l'ENU marquée sous le chemin
//! marqué, dès que le nœud est allumé et que les deux marques existent.
//!
//! - **Nœud éteint, racine** : `a` allume le nœud, `q` quitte Feu.
//! - **Nœud allumé, racine, aucun foyer ouvert** : `e` éteint le nœud, `o`
//!   ouvre un foyer (saisie du numéro à suivre).
//! - **Nœud allumé, racine, au moins un foyer ouvert** : `o` ouvre un foyer
//!   (si la capacité maximale n'est pas atteinte) ; `0`-`9` entrent dans le
//!   foyer correspondant *s'il est ouvert*. Pas de `e` tant qu'un foyer est
//!   ouvert.
//! - **Nœud allumé, au moins un foyer ouvert, où que l'on soit** : `c` ferme un
//!   comptoir de dépôt dès qu'il en existe un et qu'une ENU répertoire est
//!   marquée.
//! - **Nœud allumé, dans un foyer** : `f` ferme le foyer courant ; `0`-`9`
//!   entrent dans le classeur correspondant (dans la limite de
//!   `nombre_classeurs`) ; `Backspace` remonte à la racine ; `o` ouvre un
//!   foyer si la capacité libre le permet.
//! - **Nœud allumé, dans un classeur** : `f` ferme le foyer parent ;
//!   `Backspace` remonte au foyer ; `o` ouvre un foyer si la capacité libre
//!   le permet ; `d` ouvre un comptoir de dépôt vers ce classeur, au chemin
//!   marqué sur l'écran du disque. Les autres commandes propres aux classeurs
//!   s'ajouteront ici.
//!
//! Touches *ignorées* dans tous les autres cas — pas d'erreur, pas d'effet,
//! pas de feedback. Une touche absente de la table n'a aucune existence du
//! point de vue de la TUI.
//!
//! Les index sont ceux du noyau, à partir de zéro : la touche *est* l'index,
//! mappé en `KeyCode::Char((b'0' + index) as char)`. D'où la borne `0`-`9`, qui
//! n'est pas une capacité métier — au-delà de la dixième position le mapping
//! n'aurait plus de caractère. Le noyau (`MAX_FOYERS = 3`, `MAX_CLASSEURS = 5`)
//! reste largement en deçà.
//!
//! # Asymétrie ouverture / fermeture
//!
//! Ouvrir un foyer demande une saisie d'index ([`Commande::PilotageOuvrirFoyer`])
//! parce qu'on ne peut pas naviguer vers un foyer qui n'existe pas encore.
//! Fermer un foyer ne demande pas de saisie ([`Commande::PilotageFermerFoyer`]) :
//! l'index est capturé depuis la position courante au moment où la table est
//! construite, donc on ferme toujours *le foyer où l'on est positionné*. Le
//! geste est *naviguer puis fermer* : `2` puis `f` ferme le foyer 2. Cette
//! asymétrie reflète la nature des actions : création (index explicite
//! obligatoire) vs suppression (cible contextuelle suffit).
//!
//! # Reconstruction déclarative
//!
//! La table est reconstruite intégralement à chaque changement d'état pertinent
//! via [`CommandesActives::new`], qui lit l'état de l'interface et en déduit
//! les commandes actives à partir d'un jeu de règles simples. Aucune mutation
//! incrémentale, aucun état caché : la sortie de `new` est une fonction pure
//! de son entrée.
//!
//! Ce choix maintient l'invariant fondamental — *la table reflète toujours
//! l'état courant* — sans qu'aucun chemin du code n'ait à coupler une
//! transition métier (ouverture d'un foyer, extinction du nœud, changement
//! d'écran) avec la mutation correspondante de la table. La reconstruction est
//! déclenchée depuis [`crate::tui::Tui::lancer`] à deux points : à la réception
//! d'une session, et après chaque commande dispatchée en mode normal.
//!
//! # Filtrage strict
//!
//! Présence dans la table ⇔ effet réel possible dans le contexte courant. Une
//! touche absente n'a aucun effet ; une touche présente déclenche toujours
//! quelque chose.
//!
//! Cette homogénéité tient à ce que l'état entier est en entrée : la table sait
//! quel écran est affiché, sur quel foyer pointe le `f`, ou si la touche `0`
//! doit entrer dans un foyer ouvert ou dans un classeur valide.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyModifiers};
use feu_application::Carte;

use crate::tui::{Ecran, EtatTui};

/// Intention métier déclenchée par une frappe clavier.
///
/// Découple la liaison clavier (un tuple `(KeyCode, KeyModifiers)`) de l'action
/// effective : la même commande peut être liée à plusieurs touches, ou changer
/// de touche, sans toucher au code de dispatch dans
/// [`crate::tui::Tui::saisie_mode_normal`].
///
/// La présence d'une variante dans la table [`CommandesActives`] est entièrement
/// dictée par les conditions énumérées ci-dessous — voir [`CommandesActives::new`]
/// pour l'implémentation des règles.
pub(super) enum Commande {
    /// Ouvre ou ferme le répertoire sous le curseur — `Entrée`, sur l'écran du
    /// disque.
    ///
    /// Seule des `Disque*` à toucher au disque : ouvrir lit un niveau. Le refus
    /// hors d'un répertoire est laissé à `basculer_pli`, la table ne sachant
    /// pas ce que désigne la ligne courante.
    DisqueBasculerPli,

    /// Descend le curseur d'une ligne — `j`, sur l'écran du disque.
    ///
    /// Pure navigation TUI, comme [`Commande::DisqueMonterCurseur`] : rien
    /// n'est lu, ni du disque ni du cœur. Toutes les lignes de la liste sont
    /// visibles, le curseur n'a donc rien à sauter.
    DisqueDescendreCurseur,

    /// Retient le chemin sous le curseur — `m`, sur l'écran du disque.
    ///
    /// Pendant de [`Commande::EnuMarquer`], dont elle partage le geste et
    /// l'emplacement unique : [`crate::tui::EtatTui::chemin_selectionne`], levé
    /// par [`Commande::SupprimerSelection`]. Fichier comme répertoire — ce qui
    /// consommera le chemin dira s'il lui convient.
    DisqueMarquer,

    /// Relit le répertoire ouvert sous le curseur — `R`, sur l'écran du disque.
    ///
    /// `R` comme sur l'écran des ENU, où elle charge et rafraîchit l'arbre. La
    /// portée diffère : ici une seule branche, celle sous le curseur —
    /// recharger plus haut jetterait les plis ouverts des répertoires frères.
    ///
    /// L'arbre du disque ne se met jamais à jour seul : sans cette touche, un
    /// fichier déposé depuis un autre programme resterait invisible.
    DisqueRechargerRepertoire,

    /// Remonte le curseur d'une ligne — `k`, sur l'écran du disque.
    DisqueMonterCurseur,

    /// Passe à l'écran de travail suivant — `l`.
    ///
    /// `h` et `l` plutôt que `Tab` : le déplacement latéral de vim, même registre
    /// que `j` et `k` sur l'arborescence.
    ///
    /// Toujours active — c'est le seul chemin entre les écrans. La table dit
    /// *quand* on peut changer d'écran, jamais *vers lequel* : les écrans étant
    /// rangés en ligne et non en cycle, elle reste liée sur le dernier, où elle
    /// ne déplace rien.
    EcranSuivant,

    /// Revient à l'écran de travail précédent — `h`.
    ///
    /// Pendant de [`Commande::EcranSuivant`] : mêmes conditions, même partage
    /// des rôles avec `passer_ecran_precedent`, et pas de bouclage non plus —
    /// sur le premier écran, elle ne déplace rien.
    EcranPrecedent,

    /// Lève la marque de l'écran courant — `x`, sur les deux arborescences.
    ///
    /// **Une seule commande pour deux marques** : l'ENU et le chemin ne peuvent
    /// pas être visés en même temps, l'écran affiché disant lequel des deux.
    /// C'est `supprimer_selection` qui le lit, pas la table — deux variantes
    /// distinctes n'apporteraient qu'un doublon.
    ///
    /// Pure navigation TUI, comme les `Enu*` et les `Disque*` : les deux
    /// marques ne vivent que dans [`crate::tui::EtatTui`], les lever ne demande
    /// rien au cœur. Sans elle, [`Commande::EnuMarquer`] et
    /// [`Commande::DisqueMarquer`] ne pourraient que déplacer leur marque,
    /// jamais rendre le choix vide.
    SupprimerSelection,

    /// Replie ou déplie le répertoire sous le curseur — `Entrée`, sur l'écran
    /// d'arborescence.
    ///
    /// Pure navigation TUI, comme les trois `Enu*` qui suivent : rien n'est
    /// demandé au cœur, l'arbre en mémoire ne bouge pas, seul change ce qui en
    /// est montré.
    ///
    /// La bascule est refusée hors d'un répertoire peuplé — une feuille n'a
    /// rien à cacher, et un répertoire vide ne révélerait rien. Le tri se fait
    /// dans `basculer_pli` plutôt qu'ici : la table ignore la carte de la ligne
    /// courante, qu'il faudrait rouvrir à chaque frappe pour le savoir.
    EnuBasculerPli,

    /// Charge l'arborescence des ENU du nœud — `R`, sur son écran.
    ///
    /// Le chargement est explicite, jamais déclenché par l'arrivée sur l'écran :
    /// il lit un fichier par ENU de l'arbre, un coût que l'utilisateur doit
    /// décider de payer. Ce qui a déjà été chargé survit aux allers-retours
    /// entre écrans — la même touche rafraîchit.
    ///
    /// Émet [`crate::connecteurs::MessageTuiCoeur::ChargementArborescenceEnu`],
    /// qui ne porte rien : le cœur tient la racine de départ.
    EnuChargerArborescence,

    /// Descend le curseur d'une ligne visible — `j`, sur l'écran d'arborescence.
    ///
    /// `j` et `k` plutôt que les flèches : l'écran est un explorateur de
    /// fichiers, et c'en est le geste. Les lignes masquées par un pli sont
    /// sautées d'elles-mêmes, le curseur ne connaissant que la liste affichée.
    EnuDescendreCurseur,

    /// Retient l'ENU sous le curseur — `m`, sur l'écran d'arborescence.
    ///
    /// `m` pour *mark*, le poseur de marque de vim. Sans argument : il n'y a
    /// qu'un emplacement, [`crate::tui::EtatTui::enu_selectionnee`], et un
    /// registre nommé ne se justifierait qu'à partir de plusieurs.
    ///
    /// La marque **remplace** la précédente, et seule [`Commande::SupprimerSelection`]
    /// la lève : c'est le choix que les commandes du pilotage consommeront, pas
    /// une sélection éphémère.
    EnuMarquer,

    /// Remonte le curseur d'une ligne visible — `k`, pendant de
    /// [`Commande::EnuDescendreCurseur`].
    EnuMonterCurseur,

    /// Affiche l'aide contextuelle listant les touches actuellement actives.
    ///
    /// Toujours active : `?` fonctionne quel que soit l'état du nœud et la
    /// position courante — c'est la seule porte d'entrée pour découvrir les
    /// autres commandes accessibles à un instant donné.
    ///
    /// Le bras d'exécution dans [`crate::tui::Tui::saisie_mode_normal`] délègue
    /// à [`CommandesActives::liste_commandes_actives`] le formatage de la liste
    /// et la pose dans [`crate::tui::EtatTui::message_aide`] (compte à rebours
    /// court — cf. [`crate::tui::EtatTui::ajouter_message_aide`]).
    ListeCommandesActives,

    /// Demande l'allumage du nœud — émet [`crate::connecteurs::MessageTuiCoeur::AllumageNoeud`].
    ///
    /// Active uniquement lorsque le nœud est éteint (`session_application` à `None`).
    /// Le succès de l'allumage est signalé via
    /// [`crate::connecteurs::MessageCoeurTui::EnvoiSessionApplication`], qui déclenche
    /// la reconstruction de la table : la variante disparaît alors au profit des
    /// commandes du nœud allumé.
    PilotageAllumerNoeud,

    /// Affiche l'écran « à propos » : identité du programme, version, licence, copyright.
    ///
    /// Active sur le pilotage en toute circonstance — quel que soit l'état du
    /// nœud et la position courante —, mais sur lui seul : elle ouvre une
    /// modale qui se referme sur cet écran, l'activer ailleurs ferait changer
    /// d'écran sans retour. Méta-commande purement informationnelle, elle ne
    /// touche ni au nœud ni aux foyers.
    ///
    /// Le bras d'exécution dans [`crate::tui::Tui::saisie_mode_normal`] bascule
    /// sur l'écran d'information du pilotage ; l'utilisateur en sort par Entrée
    /// (cf. [`crate::tui::ModeSaisie::Information`]).
    PilotageAPropos,

    /// Affecte directement la position courante, côté classeur.
    ///
    /// Pure navigation TUI, sans message au cœur. `Some(index)` descend d'un
    /// foyer vers un de ses classeurs, `None` remonte au foyer parent.
    ///
    /// Liée aux touches `0`-`9` dans un foyer, dans la limite de
    /// `nombre_classeurs`, et à `Backspace` dans un classeur.
    PilotageChangerPositionClasseur(Option<usize>),

    /// Affecte directement la position courante, côté foyer.
    ///
    /// Pure navigation TUI, sans message au cœur. `Some(index)` descend de la
    /// racine vers un foyer ouvert, `None` y remonte.
    ///
    /// Liée à `0`-`9` à la racine, **uniquement pour les foyers effectivement
    /// ouverts**, et à `Backspace` dans un foyer.
    PilotageChangerPositionFoyer(Option<usize>),

    /// Demande l'extinction du nœud — émet [`crate::connecteurs::MessageTuiCoeur::ExtinctionNoeud`].
    ///
    /// Active uniquement lorsque le nœud est allumé **et** qu'aucun foyer n'est
    /// ouvert. La couche application refuse de toute façon l'extinction tant qu'un
    /// foyer est ouvert — l'erreur remonterait via
    /// [`crate::connecteurs::MessageCoeurTui::AffichageErreur`] —, mais le filtrage
    /// par contexte évite à l'utilisateur de la déclencher pour rien.
    PilotageEteindreNoeud,

    /// Ferme le comptoir de dépôt ouvert — émet
    /// [`crate::connecteurs::MessageTuiCoeur::FermetureComptoirDepot`].
    ///
    /// Active dès qu'un comptoir est ouvert et qu'une ENU **répertoire** est
    /// marquée, quelle que soit la position courante.
    ///
    /// **Rien ici ne vérifie que les foyers en jeu sont ouverts**, alors que le
    /// Scribe les exige : une touche qui s'évanouit renseigne moins que l'erreur
    /// qui nomme le foyer à rouvrir. La variante ne porte pas non plus
    /// d'identifiant — le bras d'exécution bascule en saisie pour le collecter.
    PilotageFermerComptoirDepot,

    /// Ferme le foyer dont l'index est porté par la variante — émet
    /// [`crate::connecteurs::MessageTuiCoeur::FermetureFoyer`].
    ///
    /// L'index est **capturé depuis la position courante**, sans saisie : le geste
    /// est *naviguer dans le foyer puis le fermer*. L'asymétrie avec
    /// [`Commande::PilotageOuvrirFoyer`] est délibérée.
    ///
    /// Le dispatch remet ensuite la position à la racine, et comme c'est l'unique
    /// chemin de fermeture, l'invariant tient jusqu'à l'extinction.
    PilotageFermerFoyer(usize),

    /// Ouvre un comptoir de dépôt à destination du foyer et du classeur portés
    /// — émet
    /// [`crate::connecteurs::MessageTuiCoeur::OuvertureComptoir`].
    ///
    /// Active dans un classeur, marque de chemin posée : c'est le seul contexte
    /// où les deux index sont connus, capturés depuis la position courante sans
    /// saisie.
    ///
    /// Le chemin est formé au dispatch, sous-dossier `{fN.cM}depot_feu` de la
    /// marque : **c'est lui le comptoir, jamais le dossier marqué**, que le cœur
    /// crée puis supprime à la fermeture. Son nom porte la destination, ce qui le
    /// rend unique par couple foyer-classeur.
    PilotageOuvrirComptoirDepot(usize, usize),

    /// Prépare l'ouverture d'un foyer — bascule l'invite en mode saisie pour collecter le numéro.
    ///
    /// Active uniquement lorsque le nœud est allumé **et** qu'au moins une place
    /// reste libre (`nombre_foyers_ouverts < nombre_foyers`). La saisie du numéro
    /// et l'envoi de [`crate::connecteurs::MessageTuiCoeur::OuvertureFoyer`] sont
    /// gérés par `saisie_mode_insertion` une fois le buffer validé.
    PilotageOuvrirFoyer,

    /// Demande l'arrêt propre de l'application — émet [`crate::connecteurs::MessageTuiCoeur::Quitter`].
    ///
    /// Active uniquement lorsque le nœud est éteint, par symétrie avec
    /// [`Commande::PilotageAllumerNoeud`]. Cette contrainte garantit qu'aucun foyer n'est
    /// ouvert au moment de l'arrêt — l'extinction elle-même exige que tous les
    /// foyers soient fermés. La touche `q` est silencieusement ignorée tant que
    /// le nœud est allumé : l'utilisateur doit d'abord l'éteindre.
    PilotageQuitter,

    /// Matérialise l'arborescence de l'ENU marquée dans un dossier de l'OS
    /// — émet [`crate::connecteurs::MessageTuiCoeur::RetraitLectureSeule`].
    ///
    /// Active nœud allumé **et** les deux marques posées. Seule commande à les
    /// consommer ensemble, et seule à ne pas dépendre de la position courante —
    /// un retrait vise un sous-arbre.
    ///
    /// Le chemin est formé au dispatch, sous-dossier `retrait_feu_{hash court}`
    /// de la marque : **c'est lui le dossier de sortie, jamais le dossier
    /// marqué**, le cœur refusant d'écrire dans un dossier existant.
    ///
    /// **Les foyers fermés ne sont pas filtrés ici**, comme pour
    /// [`Commande::PilotageFermerComptoirDepot`].
    PilotageRetraitLectureSeule,
}

/// Table de dispatch des commandes actives dans le contexte courant.
///
/// Encapsule un `HashMap<(KeyCode, KeyModifiers), Commande>` derrière une API
/// restreinte — lookup et formatage de l'aide : le conteneur interne peut
/// changer sans traverser la frontière du module.
///
/// **Immuable une fois construite**, et intégralement reconstruite à chaque
/// changement d'état pertinent : réception d'une session, et après chaque
/// commande dispatchée.
pub(super) struct CommandesActives(HashMap<(KeyCode, KeyModifiers), Commande>);

impl CommandesActives {
    /// Table sans aucune liaison — rien ne répond au clavier.
    ///
    /// Sert le temps d'un instant à [`crate::tui::EtatTui::new`] : la table
    /// étant une fonction de l'état, elle ne peut être construite qu'une fois
    /// l'état complet, donc après lui. Elle est remplacée dans la foulée.
    pub(super) fn vide() -> Self {
        Self(HashMap::new())
    }

    /// Construit la table qui reflète l'état courant de l'interface.
    ///
    /// Fonction pure de [`crate::tui::EtatTui`] — aucun état caché. Prendre
    /// l'état entier plutôt que les morceaux qu'elle lit laisse les règles
    /// s'ouvrir à d'autres dimensions sans changer sa signature ni ses appels.
    ///
    /// Ne pose ici que les trois touches valables partout — `h` et `l`
    /// basculent d'écran, `?` liste ce qui est actif —, puis délègue à l'écran
    /// courant : tout le reste dépend de ce qui est affiché, et un écran n'a
    /// pas à connaître les touches d'un autre.
    ///
    /// # Filtrage strict
    ///
    /// Toute touche présente déclenche un effet réel dans le contexte courant ;
    /// toute touche absente est ignorée silencieusement. Aucune n'est « activée
    /// en bloc » pour être rejetée à l'exécution.
    pub(crate) fn new(etat_tui: &EtatTui) -> Self {
        let mut commandes_actives: HashMap<(KeyCode, KeyModifiers), Commande> = HashMap::new();

        commandes_actives.insert(
            (KeyCode::Char('l'), KeyModifiers::NONE),
            Commande::EcranSuivant,
        );
        commandes_actives.insert(
            (KeyCode::Char('h'), KeyModifiers::NONE),
            Commande::EcranPrecedent,
        );
        commandes_actives.insert(
            (KeyCode::Char('?'), KeyModifiers::NONE),
            Commande::ListeCommandesActives,
        );

        match etat_tui.ecran {
            Ecran::Pilotage => Self::new_ecran_pilotage(etat_tui, &mut commandes_actives),
            Ecran::ArborescenceEnu => Self::new_ecran_enu(&mut commandes_actives),
            Ecran::ArborescenceDisque => Self::new_ecran_disque(&mut commandes_actives),
        }

        Self(commandes_actives)
    }

    /// Ajoute à la table les touches propres à l'écran de pilotage.
    ///
    /// Chaque variante de [`Commande`] documente ses propres conditions ; ne se
    /// lit ici que ce qui les traverse.
    ///
    /// `!` n'est pas remontée avec `h`, `l` et `?` : elle ouvre une modale du
    /// pilotage, qui se referme sur lui — l'activer ailleurs ferait changer
    /// d'écran sans retour.
    ///
    /// La borne `0`-`9` n'est pas une capacité métier : la touche **est** l'index,
    /// ce qui ne tient pas au-delà de la dixième position. Le noyau reste
    /// largement en deçà.
    fn new_ecran_pilotage(
        etat_tui: &EtatTui,
        commandes_actives: &mut HashMap<(KeyCode, KeyModifiers), Commande>,
    ) {
        if let Some(session) = &etat_tui.session_application {
            if etat_tui.chemin_selectionne.is_some() && etat_tui.enu_selectionnee.is_some() {
                commandes_actives.insert(
                    (KeyCode::Char('r'), KeyModifiers::NONE),
                    Commande::PilotageRetraitLectureSeule,
                );
            }

            if session.nombre_foyers_ouverts() == 0 {
                commandes_actives.insert(
                    (KeyCode::Char('e'), KeyModifiers::NONE),
                    Commande::PilotageEteindreNoeud,
                );
            }
            if session.nombre_foyers_ouverts() < session.nombre_foyers {
                commandes_actives.insert(
                    (KeyCode::Char('o'), KeyModifiers::NONE),
                    Commande::PilotageOuvrirFoyer,
                );
            }
            if session.nombre_foyers_ouverts() > 0 {
                if !session.comptoirs_depot_ouverts().is_empty()
                    && let Some(enu) = &etat_tui.enu_selectionnee
                    && matches!(enu.carte(), Carte::Repertoire { .. })
                {
                    commandes_actives.insert(
                        (KeyCode::Char('c'), KeyModifiers::NONE),
                        Commande::PilotageFermerComptoirDepot,
                    );
                }
                match (
                    etat_tui.etat_pilotage.position_courante.foyer,
                    etat_tui.etat_pilotage.position_courante.classeur,
                ) {
                    (None, _) => {
                        for (i, etat) in session.etat_foyers().iter().enumerate() {
                            if *etat && i < 10 {
                                commandes_actives.insert(
                                    (KeyCode::Char((b'0' + i as u8) as char), KeyModifiers::NONE),
                                    Commande::PilotageChangerPositionFoyer(Some(i)),
                                );
                            }
                        }
                    }
                    (Some(index), None) => {
                        commandes_actives.insert(
                            (KeyCode::Char('f'), KeyModifiers::NONE),
                            Commande::PilotageFermerFoyer(index),
                        );
                        commandes_actives.insert(
                            (KeyCode::Backspace, KeyModifiers::NONE),
                            Commande::PilotageChangerPositionFoyer(None),
                        );

                        for i in 0..session.nombre_classeurs {
                            if i < 10 {
                                commandes_actives.insert(
                                    (KeyCode::Char((b'0' + i as u8) as char), KeyModifiers::NONE),
                                    Commande::PilotageChangerPositionClasseur(Some(i)),
                                );
                            }
                        }
                    }
                    (Some(index_foyer), Some(index_classeur)) => {
                        commandes_actives.insert(
                            (KeyCode::Char('f'), KeyModifiers::NONE),
                            Commande::PilotageFermerFoyer(index_foyer),
                        );
                        commandes_actives.insert(
                            (KeyCode::Backspace, KeyModifiers::NONE),
                            Commande::PilotageChangerPositionClasseur(None),
                        );
                        if etat_tui.chemin_selectionne.is_some() {
                            commandes_actives.insert(
                                (KeyCode::Char('d'), KeyModifiers::NONE),
                                Commande::PilotageOuvrirComptoirDepot(index_foyer, index_classeur),
                            );
                        }
                    }
                }
            }
        } else {
            commandes_actives.insert(
                (KeyCode::Char('a'), KeyModifiers::NONE),
                Commande::PilotageAllumerNoeud,
            );
            commandes_actives.insert(
                (KeyCode::Char('q'), KeyModifiers::NONE),
                Commande::PilotageQuitter,
            );
        }

        commandes_actives.insert(
            (KeyCode::Char('!'), KeyModifiers::NONE),
            Commande::PilotageAPropos,
        );
    }

    /// Ajoute à la table les touches propres à l'écran d'arborescence.
    ///
    /// Aucune condition, d'où l'absence d'`etat_tui` en paramètre.
    ///
    /// **Ces touches échappent au filtrage strict** de [`Self::new`] : présentes
    /// même sans arbre chargé, elles n'y font rien. Écart assumé — leur poser une
    /// condition demanderait de recalculer les lignes visibles à chaque frappe,
    /// pour un cas que l'utilisateur ne distingue pas d'une touche inactive.
    ///
    /// `R` reste active nœud éteint, seule touche d'ici à s'adresser au cœur :
    /// elle revient alors en erreur affichée, ce qui dit pourquoi rien ne vient.
    ///
    /// `R` est une majuscule, donc `KeyModifiers::SHIFT` : le lookup étant une
    /// égalité exacte sur le tuple, s'en écarter rendrait la touche muette.
    fn new_ecran_enu(commandes_actives: &mut HashMap<(KeyCode, KeyModifiers), Commande>) {
        commandes_actives.insert(
            (KeyCode::Char('R'), KeyModifiers::SHIFT),
            Commande::EnuChargerArborescence,
        );
        commandes_actives.insert(
            (KeyCode::Char('j'), KeyModifiers::NONE),
            Commande::EnuDescendreCurseur,
        );
        commandes_actives.insert(
            (KeyCode::Char('k'), KeyModifiers::NONE),
            Commande::EnuMonterCurseur,
        );
        commandes_actives.insert(
            (KeyCode::Char('m'), KeyModifiers::NONE),
            Commande::EnuMarquer,
        );
        commandes_actives.insert(
            (KeyCode::Char('x'), KeyModifiers::NONE),
            Commande::SupprimerSelection,
        );
        commandes_actives.insert(
            (KeyCode::Enter, KeyModifiers::NONE),
            Commande::EnuBasculerPli,
        );
    }

    /// Ajoute à la table les touches propres à l'écran du disque.
    ///
    /// **Aucune condition, contrairement au pilotage** : toutes sont actives en
    /// permanence, y compris nœud éteint. Naviguer sur le disque ne demande
    /// rien au cœur, et le chemin retenu doit pouvoir l'être avant d'allumer.
    /// D'où l'absence d'`etat_tui` en paramètre, que prend `new_ecran_pilotage`.
    ///
    /// Les mêmes touches que sur l'écran des ENU, pour les mêmes gestes — un
    /// seul jeu à retenir. `x` y est même la commande commune,
    /// [`Commande::SupprimerSelection`], qui lève l'une ou l'autre marque selon
    /// l'écran courant.
    fn new_ecran_disque(commandes_actives: &mut HashMap<(KeyCode, KeyModifiers), Commande>) {
        commandes_actives.insert(
            (KeyCode::Char('R'), KeyModifiers::SHIFT),
            Commande::DisqueRechargerRepertoire,
        );
        commandes_actives.insert(
            (KeyCode::Char('j'), KeyModifiers::NONE),
            Commande::DisqueDescendreCurseur,
        );
        commandes_actives.insert(
            (KeyCode::Char('k'), KeyModifiers::NONE),
            Commande::DisqueMonterCurseur,
        );
        commandes_actives.insert(
            (KeyCode::Char('m'), KeyModifiers::NONE),
            Commande::DisqueMarquer,
        );
        commandes_actives.insert(
            (KeyCode::Char('x'), KeyModifiers::NONE),
            Commande::SupprimerSelection,
        );
        commandes_actives.insert(
            (KeyCode::Enter, KeyModifiers::NONE),
            Commande::DisqueBasculerPli,
        );
    }

    /// Retourne la commande liée à une touche dans le contexte courant, `None` si absente.
    ///
    /// Point d'entrée du dispatch clavier : une touche absente de la table ne
    /// déclenche rien — le filtrage par contexte est entièrement implicite.
    pub(super) fn get(&self, touche: &(KeyCode, KeyModifiers)) -> Option<&Commande> {
        self.0.get(touche)
    }

    /// Retourne une chaîne énumérant les touches actives, séparées par des espaces.
    ///
    /// Le caractère lui-même, ou son symbole pour les deux touches nommées de la
    /// table. Tout autre `KeyCode` est ignoré : une touche muette dans l'aide
    /// vaut mieux qu'un nom illisible.
    ///
    /// **L'ordre suit l'itération du `HashMap`**, non déterministe d'un appel à
    /// l'autre. L'aide sert à repérer ce qui est actif, pas à être lue deux
    /// fois.
    pub(super) fn liste_commandes_actives(&self) -> String {
        let mut liste_commandes = String::new();

        for (key_code, _) in self.0.keys() {
            match key_code {
                KeyCode::Char(c) => liste_commandes.push_str(&format!(" '{c}'")),

                KeyCode::Backspace => liste_commandes.push_str(" '⌫'"),

                KeyCode::Enter => liste_commandes.push_str(" '⏎'"),

                _ => {}
            }
        }
        liste_commandes
    }
}
