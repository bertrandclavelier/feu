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
//! l'à-propos en toute circonstance, `r` dès que le nœud est allumé.
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
    /// `h` et `l` plutôt que `Tab` : le déplacement latéral de vim, dans le
    /// même registre que `j` et `k` sur l'arborescence, et les écrans se
    /// parcourent désormais dans les deux sens.
    ///
    /// Toujours active, quel que soit l'écran et l'état du nœud : c'est le seul
    /// chemin entre les écrans, et rien ne justifierait de l'y enfermer. Aucun
    /// message au cœur, aucun effet métier.
    ///
    /// L'ordre est tenu par `passer_ecran_suivant` : la table dit *quand* on
    /// peut changer d'écran, jamais *vers lequel*. Les écrans étant rangés en
    /// ligne et non en cycle, la commande reste liée sur le dernier d'entre
    /// eux, où elle ne déplace rien.
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
    /// Pure navigation TUI — aucun message vers le cœur, aucun effet métier.
    /// `Some(index)` pose la position à `Some(index)` (descente d'un foyer vers
    /// un de ses classeurs) ; `None` la repose à `None` (remontée du classeur
    /// vers son foyer parent).
    ///
    /// Active uniquement quand l'utilisateur est positionné dans un foyer ou
    /// dans un classeur :
    /// - dans un foyer (`classeur = None`), liée aux touches `0`-`9` dans la
    ///   limite de `nombre_classeurs` — descente ;
    /// - dans un classeur (`classeur = Some(_)`), liée à `Backspace` —
    ///   remontée.
    PilotageChangerPositionClasseur(Option<usize>),

    /// Affecte directement la position courante, côté foyer.
    ///
    /// Pure navigation TUI — aucun message vers le cœur, aucun effet métier.
    /// `Some(index)` pose la position à `Some(index)` (descente de la racine
    /// vers un foyer ouvert) ; `None` la repose à `None` (remontée du foyer
    /// vers la racine).
    ///
    /// Active selon la position courante :
    /// - à la racine (`foyer = None`), liée à `0`-`9` *uniquement pour les
    ///   foyers effectivement ouverts* (la table consulte
    ///   [`feu_application::SessionApplication::etat_foyers`] pour ne pas
    ///   exposer les positions fermées) — descente ;
    /// - dans un foyer (`foyer = Some(_)`, `classeur = None`), liée à
    ///   `Backspace` — remontée à la racine.
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
    /// Active dès qu'un comptoir est ouvert et qu'une ENU répertoire est
    /// marquée — les deux que la fermeture réclame —, quelle que soit la
    /// position courante : ce qu'on ferme ne dépend pas d'où l'on est. La marque
    /// doit être un répertoire parce que la greffe y ajoute des enfants ; le
    /// Scribe le revérifie, la table ne fait que ne pas proposer l'impossible.
    ///
    /// La commande ne porte pas d'identifiant : plusieurs comptoirs pouvant être
    /// ouverts, le bras d'exécution bascule en saisie pour le collecter, et le
    /// valide contre
    /// [`feu_application::SessionApplication::comptoirs_depot_ouverts`].
    PilotageFermerComptoirDepot,

    /// Ferme le foyer dont l'index est porté par la variante — émet
    /// [`crate::connecteurs::MessageTuiCoeur::FermetureFoyer`].
    ///
    /// Active uniquement lorsque l'utilisateur est positionné dans un foyer ou
    /// dans un classeur. L'index est *capturé* depuis la position courante au
    /// moment où la table est construite ; aucune saisie, donc. Le geste
    /// typique est *naviguer dans le foyer (`0`-`9`) puis le fermer (`f`)*.
    ///
    /// L'asymétrie avec [`Commande::PilotageOuvrirFoyer`], qui passe par une saisie,
    /// est délibérée : on ne peut pas naviguer vers un foyer qui n'existe pas
    /// encore, alors que la fermeture agit sur celui où l'on est.
    ///
    /// Le bras d'exécution dans [`crate::tui::Tui::saisie_mode_normal`] remet
    /// la position à la racine après émission — on ne peut plus être *dans* un
    /// foyer qu'on vient de fermer. Comme c'est l'unique chemin de fermeture,
    /// l'invariant tient en cascade : à l'extinction du nœud, qui exige tous
    /// les foyers fermés, la position y est nécessairement déjà.
    PilotageFermerFoyer(usize),

    /// Ouvre un comptoir de dépôt à destination du foyer et du classeur portés
    /// — émet
    /// [`crate::connecteurs::MessageTuiCoeur::OuvertureComptoir`].
    ///
    /// Active uniquement quand l'utilisateur est positionné dans un classeur :
    /// c'est le seul contexte où les deux index que réclame la commande
    /// applicative sont connus, capturés depuis la position courante au moment
    /// où la table est construite. Aucune saisie, donc — même geste que
    /// [`Commande::PilotageFermerFoyer`].
    ///
    /// La variante ne porte que les deux index : le chemin est formé au dispatch
    /// dans [`crate::tui::Tui::saisie_mode_normal`], en joignant à
    /// [`crate::tui::EtatTui::chemin_selectionne`] — marqué par `m` sur l'écran
    /// d'arborescence disque — un sous-dossier `{fN.cM}depot_feu`. C'est ce
    /// sous-dossier qui est le comptoir, jamais le dossier marqué : le cœur crée
    /// le premier et le supprime à la fermeture, quand le second appartient à
    /// l'utilisateur. Son nom porte la destination, ce qui le rend unique par
    /// couple foyer-classeur — deux comptoirs identiques depuis la même marque
    /// se heurteraient.
    ///
    /// D'où la condition d'entrée dans la table : une marque de chemin posée. La
    /// table n'a donc rien à dire sur *où* déposer, seulement sur *quand* c'est
    /// possible.
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

    /// Matérialise l'arborescence de la dernière racine dans un dossier de l'OS
    /// — émet [`crate::connecteurs::MessageTuiCoeur::RetraitLectureSeule`].
    ///
    /// Active dès que le nœud est allumé, sans autre condition : le retrait part
    /// de la dernière racine, que le cœur va chercher lui-même, et ne lit donc
    /// ni la position courante ni l'état des foyers. Seule commande du nœud
    /// allumé dans ce cas — les autres dépendent toutes de l'une ou de l'autre.
    ///
    /// Elle peut malgré tout échouer à l'exécution : le déchiffrement d'un blob
    /// exige que le foyer signataire soit ouvert, et la table ne le vérifie pas.
    /// C'est la seule entorse au filtrage strict décrit dans
    /// [`CommandesActives::new`] — parcourir l'arbre pour dresser la liste des
    /// foyers requis demande un itérateur qui n'existe pas encore. L'erreur
    /// remonte en [`crate::connecteurs::MessageCoeurTui::AffichageErreur`].
    PilotageRetraitLectureSeule,
}

/// Table de dispatch des commandes actives dans le contexte courant.
///
/// Encapsule un `HashMap<(KeyCode, KeyModifiers), Commande>` pour exposer une
/// API restreinte : lookup par touche via [`get`](Self::get) et formatage de
/// l'aide via [`liste_commandes_actives`](Self::liste_commandes_actives). Le
/// conteneur interne reste invisible — toute évolution de structure ne
/// traverse pas la frontière du module.
///
/// La table est immuable une fois construite : elle est intégralement
/// reconstruite par [`new`](Self::new) à chaque changement d'état pertinent,
/// directement depuis [`crate::tui::Tui::lancer`] (réception d'une nouvelle
/// session) et [`crate::tui::Tui::saisie_mode_normal`] (après chaque commande
/// dispatchée).
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
    /// Les règles, vues d'ensemble — chaque variante de [`Commande`] documente
    /// les siennes en détail :
    ///
    /// - nœud éteint → `PilotageAllumerNoeud`, `PilotageQuitter` ;
    /// - nœud allumé → `PilotageRetraitLectureSeule` sans condition,
    ///   `PilotageEteindreNoeud` si aucun foyer n'est ouvert,
    ///   `PilotageOuvrirFoyer` s'il reste une place ;
    /// - au moins un foyer ouvert, la navigation suit la position courante :
    ///   à la racine, `0`-`9` entrent dans les foyers ouverts ; dans un foyer,
    ///   `f` le ferme, `Backspace` remonte, `0`-`9` descendent dans les
    ///   classeurs ; dans un classeur, `f` ferme le foyer parent, `Backspace`
    ///   remonte et `d` ouvre un comptoir de dépôt. `c` en ferme un depuis
    ///   n'importe quelle position, si la session en porte et qu'une ENU
    ///   répertoire est marquée ;
    /// - `!` dans tous les cas.
    ///
    /// `!` n'est pas remontée avec `h`, `l` et `?` : elle ouvre une modale du
    /// pilotage, qui se referme sur lui — l'activer ailleurs ferait changer
    /// d'écran sans retour.
    ///
    /// La borne `0`-`9` n'est pas une capacité métier : la touche est l'index
    /// lui-même, mappé en `KeyCode::Char((b'0' + index) as char)`, ce qui ne
    /// tient pas au-delà de la dixième position. Le noyau (`MAX_FOYERS = 3`,
    /// `MAX_CLASSEURS = 5`) reste largement en deçà.
    fn new_ecran_pilotage(
        etat_tui: &EtatTui,
        commandes_actives: &mut HashMap<(KeyCode, KeyModifiers), Commande>,
    ) {
        if let Some(session) = &etat_tui.session_application {
            commandes_actives.insert(
                (KeyCode::Char('r'), KeyModifiers::NONE),
                Commande::PilotageRetraitLectureSeule,
            );

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
    /// Cinq, et aucune condition : `R` charge ou rafraîchit, `j` et `k`
    /// déplacent le curseur, `Entrée` plie ou déplie, `m` retient l'ENU sous le
    /// curseur.
    ///
    /// **Ces quatre dernières échappent au filtrage strict** décrit dans
    /// [`Self::new`] : elles sont présentes même sans arbre chargé, où elles ne
    /// font rien. C'est un écart assumé — leur poser une condition demanderait
    /// de recalculer les lignes visibles à chaque frappe, et de couvrir par des
    /// tests un cas que l'utilisateur ne peut pas distinguer d'une touche
    /// inactive. Elles ne peuvent pas échouer, seulement rester sans effet ; la
    /// méthode appelée sort alors sur un `None`.
    ///
    /// Ne reçoit pas l'état, contrairement à
    /// [`Self::new_ecran_pilotage`](CommandesActives::new_ecran_pilotage) :
    /// c'est la conséquence directe de ce qui précède.
    ///
    /// `R` est une majuscule, donc `KeyModifiers::SHIFT` — le lookup étant une
    /// égalité exacte sur le tuple, l'oublier rendrait la touche muette. Les
    /// minuscules `j`, `k` et `m` prennent `NONE`, et s'en tenir à
    /// `KeyModifiers::SHIFT` par symétrie les rendrait muettes de la même façon.
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
    /// Chaque touche est rendue entre guillemets simples : le caractère lui-même
    /// (`'a'`, `'1'`…), ou un glyphe pour la seule touche nommée de la table,
    /// `'⌫'`. Tout autre `KeyCode` est ignoré, `Entrée` comprise : une touche
    /// muette dans l'aide vaut mieux qu'un nom illisible.
    ///
    /// Alimente [`crate::tui::EtatTui::message_aide`] via
    /// [`Commande::ListeCommandesActives`].
    ///
    /// L'ordre suit l'itération du `HashMap`, *non déterministe d'un appel à
    /// l'autre*. Compromis assumé : l'aide sert à repérer ce qui est actif, pas
    /// à être lue deux fois. L'ordre stable viendra avec l'enrichissement du
    /// module — libellés par commande, regroupement par catégorie.
    pub(super) fn liste_commandes_actives(&self) -> String {
        let mut liste_commandes = String::new();

        for (key_code, _) in self.0.keys() {
            match key_code {
                KeyCode::Char(c) => liste_commandes.push_str(&format!(" '{c}'")),

                KeyCode::Backspace => liste_commandes.push_str(" '⌫'"),
                _ => {}
            }
        }
        liste_commandes
    }
}
