// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! État de l'interface et boucle principale.
//!
//! Ce module centralise l'état entre deux frames ([`EtatTui`]) et orchestre
//! la boucle dessin → événement → mise à jour via [`Tui::lancer`].
//! Le rendu est entièrement délégué à [`rendu`].
//!
//! La boucle tourne en continu via `poll(50ms)` : elle ne bloque jamais plus de
//! 50 ms, ce qui permet de consulter le canal cœur→TUI à chaque itération via
//! `try_recv`. Les événements clavier et les messages du cœur sont traités de
//! façon désynchronisée — la TUI n'attend aucune réponse du cœur.
//!
//! La communication avec le thread cœur passe par [`crate::connecteurs::ConnecteurVersCoeur`],
//! dont [`Tui`] est propriétaire.
//!
//! Les commandes accessibles à un instant donné sont filtrées par le contexte
//! via [`commandes::CommandesActives`] — la boucle clavier ne connaît aucun
//! raccourci hardcodé, elle dispatche ce que la table lui retourne.
//!
//! # Modèle d'interaction
//!
//! L'état courant se lit sur trois axes orthogonaux qui évoluent
//! indépendamment.
//!
//! [`Ecran`] désigne l'écran de travail affiché, et rien d'autre : ce qu'il
//! contient, ses sous-écrans compris, appartient à son module — voir
//! [`ecran_pilotage`] et [`ecran_arborescence_enu`]. `Tab` passe de l'un à
//! l'autre, en cycle. [`ModeSaisie`] décide comment les touches sont
//! interprétées : `Normal` (dispatch via la table de commandes), `Insertion`
//! (accumulation dans un buffer, validation par Entrée), `Information`
//! (avancement par Entrée uniquement). [`commandes::CommandesActives`] enfin
//! liste les touches actives, reconstruite à chaque changement de session ou
//! de position.
//!
//! Ce module ne connaît donc aucun écran de l'intérieur. Chacun apporte dans
//! son fichier son état, son rendu et les transitions qui y mènent — celles-ci
//! s'écrivant en `impl EtatTui`, puisqu'elles posent aussi le mode de saisie.
//!
//! Le geste typique au clavier : `a` allume le nœud, mot de passe, seed
//! validée par deux pressions d'Entrée ; `o` ouvre un foyer (saisie du
//! numéro), `1`-`9` entrent dans un foyer ouvert puis dans un de ses
//! classeurs, `d` y ouvre un comptoir de dépôt et `c` le ferme, `r` retire
//! l'arborescence sur le disque, `Backspace` remonte d'un niveau, `f` ferme le
//! foyer où l'on est, `e` éteint quand tous les foyers sont fermés, `q` quitte
//! quand le nœud est éteint, `!` affiche l'à-propos. Sur l'écran
//! d'arborescence, `R` charge ou rafraîchit l'arbre. `Tab` et `?` sont les
//! seules à valoir partout — changer d'écran, et lister ce qui y est actif.

mod commandes;
mod ecran_arborescence_enu;
mod ecran_pilotage;
mod rendu;

use std::{
    path::PathBuf,
    sync::mpsc::TryRecvError,
    time::{Duration, Instant},
};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use feu_application::SessionApplication;
use ratatui::DefaultTerminal;
use secrecy::SecretString;

use crate::{
    connecteurs::{ConnecteurVersCoeur, MessageCoeurTui, MessageTuiCoeur},
    tui::{ecran_arborescence_enu::EtatArborescenceEnu, ecran_pilotage::EtatPilotage},
};
use commandes::{Commande, CommandesActives};

/// Emplacement du dossier de dépôt, en dur le temps de brancher la TUI.
///
/// Le comptoir n'a pas encore d'où tirer un chemin : ni sélecteur de fichiers,
/// ni saisie, ni navigation dans l'arborescence du disque. Cette constante tient
/// la place de ce que l'utilisateur désignera. À retirer dès qu'un chemin peut
/// venir de lui.
///
/// `env!` est résolu **à la compilation** : la valeur est une chaîne littérale
/// figée dans le binaire, pas une lecture de l'environnement à l'exécution. Le
/// `$HOME` retenu est donc celui de la machine qui compile — sans portée sur du
/// provisoire, et c'est ce qui garde tout chemin personnel hors des sources,
/// `workspace/` étant public.
///
/// Elle est lue au dispatch de [`Commande::PilotageOuvrirComptoirDepot`], qui ne porte
/// que les deux index : le chemin ne traverse pas la table des commandes.
/// Son pendant pour le retrait est `CHEMIN_COMPTOIR_RETRAIT` (module
/// `connecteurs`), posé là où le cœur le lit.
const CHEMIN_COMPTOIR_DEPOT: &str = concat!(env!("HOME"), "/Desktop/depot");

/// Axe de rendu : quel écran de travail est dessiné à chaque frame.
///
/// Pur sélecteur — les variantes ne portent aucune donnée. Chaque écran garde
/// les siennes dans son module, ce qui laisse cet enum stable quand l'un
/// d'eux s'enrichit, et vaut au `match` de [`rendu::dessiner`] d'être
/// exhaustif sans rien savoir d'eux.
///
/// Orthogonal à [`ModeSaisie`] : un même écran traverse plusieurs modes.
/// Fusionner les deux axes recouperait le rendu et l'interprétation des
/// touches, deux responsabilités indépendantes.
enum Ecran {
    /// L'usage courant du nœud, et les modales qu'il ouvre — cf.
    /// [`ecran_pilotage`].
    Pilotage,

    /// L'arborescence des ENU du nœud — cf. [`ecran_arborescence_enu`].
    ///
    /// Branché mais vide : seul le chemin qui y mène est établi, son contenu
    /// viendra ensuite.
    ArborescenceEnu,
}

/// Axe d'interprétation des touches clavier — indépendant de l'écran affiché.
///
/// Transversal à [`Ecran`] : un même écran traverse plusieurs modes selon son
/// état. Le mode est posé par la transition qui mène à l'écran, pas déduit de
/// lui — ce qui laisse la boucle clavier dispatcher sans jamais consulter
/// [`EtatTui::ecran`].
enum ModeSaisie {
    /// Touches dispatchées via [`EtatTui::commandes_actives`] : la table
    /// indique quelle commande exécuter, ou rien si la touche n'y figure pas.
    Normal,

    /// Touches accumulées dans [`EtatTui::buffer_saisie`] ; Entrée valide, Échap annule.
    ///
    /// Sert au mot de passe comme aux prompts de commande. Ce qu'il advient du
    /// buffer à la validation est porté par [`ValidationBufferSaisie`], jamais
    /// par l'écran.
    Insertion,

    /// Entrée (sans modificateur) avance l'écran courant — toute autre touche est ignorée.
    ///
    /// L'écran seul sait ce qu'« avancer » veut dire, et si le cœur doit en
    /// être averti (cf. `entree_mode_information`).
    Information,
}

/// Destination du contenu de [`EtatTui::buffer_saisie`] à la validation (Entrée).
///
/// Posé avant de basculer en [`ModeSaisie::Insertion`] par ce qui déclenche la
/// saisie, consommé et remis à [`Self::Rien`] par `saisie_mode_insertion` —
/// qui n'a ainsi pas à connaître l'écran courant pour décider quoi émettre.
///
/// La fermeture d'un foyer ne passe pas par là : elle agit sur le foyer où
/// l'on est positionné, sans rien demander (cf. [`Commande::PilotageFermerFoyer`]).
enum ValidationBufferSaisie {
    /// Le buffer est vidé sans envoyer de message au cœur.
    ///
    /// État de repos restauré après chaque validation ou annulation.
    Rien,

    /// Le buffer est transmis comme [`crate::connecteurs::MessageTuiCoeur::EnvoieMdp`] au thread cœur.
    EnvoiMdp,

    /// Le buffer est interprété comme un numéro de foyer (base 1) et envoyé via
    /// [`crate::connecteurs::MessageTuiCoeur::OuvertureFoyer`].
    ///
    /// Posé par [`Tui::saisie_mode_normal`] sur dispatch de
    /// [`Commande::PilotageOuvrirFoyer`]. À la validation, le buffer est parsé en
    /// `usize` et l'index doit être strictement positif ; sinon un message
    /// d'erreur est affiché et aucun message n'est envoyé au cœur. La
    /// conversion en index base 0 reste à la charge du connecteur cœur.
    OuvertureFoyer,
}

/// État courant de l'interface entre deux frames.
///
/// Deux natures s'y côtoient. **Le transversal**, à plat ici : la session, les
/// deux axes ([`Ecran`], [`ModeSaisie`]), la table des commandes, la mécanique
/// de saisie (`prompt`, `buffer_saisie`, [`ValidationBufferSaisie`]) et les
/// messages éphémères. Il survit aux changements d'écran, et c'est la raison
/// d'être de sa place : une erreur née pendant la saisie du mot de passe doit
/// rester lisible sur l'écran qui suit. **Le propre à un écran**, dans un
/// champ par écran — aujourd'hui `etat_pilotage` — dont le module de cet écran
/// est seul à connaître le contenu.
///
/// Aucun état applicatif n'est retenu hors de `session_application` : ce que le
/// nœud sait, la TUI le lit dans le clone qu'elle reçoit, elle n'en garde pas
/// de copie à resynchroniser.
///
/// Les méthodes de ce type ne sont pas toutes ici : chaque module d'écran
/// ajoute en `impl EtatTui` les transitions qui mènent au sien.
struct EtatTui {
    /// Session applicative courante — `None` quand le nœud est éteint.
    ///
    /// Peuplé par [`crate::connecteurs::MessageCoeurTui::EnvoiSessionApplication`]
    /// dans la boucle principale, qui affecte directement le payload reçu.
    /// `None` signifie nœud éteint (pastilles éteintes) — état initial, ou
    /// résultat d'une extinction réussie ; `Some(_)` signifie nœud allumé.
    /// Pas de booléen séparé — la présence du clone est la preuve que l'allumage
    /// a réussi, son absence celle de l'extinction.
    session_application: Option<SessionApplication>,

    /// Écran actuellement affiché — détermine la fonction de rendu appelée.
    ecran: Ecran,

    /// Mode de saisie courant — détermine l'interprétation des touches.
    mode_saisie: ModeSaisie,

    /// Ce que l'écran de pilotage retient — son sous-écran et la position
    /// courante. Opaque d'ici : seul son module en lit le contenu.
    etat_pilotage: EtatPilotage,

    /// Ce que l'écran d'arborescence retient — rien encore, l'écran ayant été
    /// branché avant d'avoir un contenu. Clippy le signale comme jamais lu tant
    /// qu'il reste vide.
    etat_arborescence_enu: EtatArborescenceEnu,

    /// Table de dispatch touche → commande, filtrée par le contexte courant.
    ///
    /// Source de vérité unique : une touche absente ne déclenche rien, point —
    /// la boucle n'a aucun cas particulier à traiter.
    ///
    /// Reconstruite intégralement à la réception d'une session et après chaque
    /// commande dispatchée. Fonction pure de l'état, donc sans mutation
    /// incrémentale ni risque de la voir diverger de ce qu'elle décrit.
    commandes_actives: CommandesActives,

    /// Ce que l'on fait du buffer à la validation — positionné avant de passer en [`ModeSaisie::Insertion`].
    validation_buffer_saisie: ValidationBufferSaisie,

    /// Dernier message d'erreur et son compte à rebours en secondes.
    ///
    /// Le tuple garantit que texte et durée sont posés et effacés ensemble —
    /// d'où les accesseurs [`EtatTui::message_erreur`] et
    /// [`EtatTui::ajouter_message_erreur`], jamais l'affectation directe.
    ///
    /// À plat ici pour survivre aux transitions d'écran : une erreur née pendant
    /// la saisie du mot de passe doit rester visible sur l'écran qui suit.
    /// Effacé quand le compte à rebours atteint zéro (cf. [`EtatTui::decremente_temps`]).
    message_erreur: (Option<String>, u8),

    /// Dernier message éphémère à destination de l'utilisateur, et son compte
    /// à rebours en secondes. Même mécanique que [`EtatTui::message_erreur`],
    /// accesseurs compris.
    ///
    /// Alimenté aujourd'hui par [`Commande::ListeCommandesActives`], qui y
    /// dépose la liste formatée des touches actives. Durée volontairement
    /// courte — 2 s contre 5 pour une erreur : une aide doit disparaître vite.
    message_aide: (Option<String>, u8),

    /// Libellé affiché en regard du buffer pendant une saisie.
    ///
    /// Posé par [`Tui::saisie_mode_normal`] au moment de basculer en
    /// [`ModeSaisie::Insertion`] (par exemple `"ouvre"` pour
    /// [`Commande::PilotageOuvrirFoyer`]) ; vidé par `saisie_mode_insertion` à la
    /// validation comme à l'annulation, en miroir de [`Self::buffer_saisie`].
    prompt: String,

    /// Accumulateur de la saisie en [`ModeSaisie::Insertion`], vidé après
    /// chaque validation ou annulation.
    ///
    /// À plat ici parce que l'accumulation ne dépend pas de l'écran :
    /// `saisie_mode_insertion` n'a jamais à consulter [`EtatTui::ecran`].
    buffer_saisie: String,
}

impl EtatTui {
    /// État initial : nœud éteint, écran de pilotage, mode normal.
    ///
    /// La table des commandes se construit en deux temps — vide d'abord,
    /// puisqu'elle est une fonction de l'état qui n'existe pas encore, remplie
    /// aussitôt après (cf. [`CommandesActives::vide`]).
    fn new() -> Self {
        let mut etat_tui = Self {
            session_application: None,
            ecran: Ecran::Pilotage,
            mode_saisie: ModeSaisie::Normal,
            etat_pilotage: EtatPilotage::new(),
            etat_arborescence_enu: EtatArborescenceEnu::new(),
            commandes_actives: CommandesActives::vide(),
            validation_buffer_saisie: ValidationBufferSaisie::Rien,
            message_erreur: (None, 0),
            message_aide: (None, 0),
            prompt: String::new(),
            buffer_saisie: String::new(),
        };
        etat_tui.commandes_actives = CommandesActives::new(&etat_tui);

        etat_tui
    }

    /// Retourne le texte du message d'erreur courant, `None` si aucun.
    ///
    /// Expose uniquement le texte — le compte à rebours est un détail interne.
    fn message_erreur(&self) -> &Option<String> {
        &self.message_erreur.0
    }

    /// Pose un message d'erreur avec un compte à rebours de 5 secondes.
    ///
    /// Toujours appelé à la place d'une affectation directe : garantit que
    /// texte et durée sont posés atomiquement et ne peuvent pas se désynchroniser.
    fn ajouter_message_erreur(&mut self, message_erreur: String) {
        self.message_erreur.0 = Some(message_erreur);
        self.message_erreur.1 = 5;
    }

    /// Retourne le texte du message d'aide courant, `None` si aucun.
    ///
    /// Expose uniquement le texte — le compte à rebours est un détail interne.
    fn message_aide(&self) -> &Option<String> {
        &self.message_aide.0
    }

    /// Pose un message d'aide avec un compte à rebours de 2 secondes.
    ///
    /// Toujours appelé à la place d'une affectation directe : garantit que
    /// texte et durée sont posés atomiquement et ne peuvent pas se désynchroniser.
    fn ajouter_message_aide(&mut self, message_aide: String) {
        self.message_aide.0 = Some(message_aide);
        self.message_aide.1 = 2;
    }

    /// Décrémente d'une seconde tous les comptes à rebours des éléments éphémères.
    ///
    /// Appelé par [`Tui::lancer`] toutes les secondes via une `horloge: Instant`.
    /// Quand le compte à rebours d'un élément atteint zéro, l'élément est effacé.
    ///
    /// Éléments éphémères gérés actuellement :
    /// - [`EtatTui::message_erreur`] — durée 5 s ;
    /// - [`EtatTui::message_aide`] — durée 2 s.
    ///
    /// Les prochains éléments (indicateurs d'activité…) s'ajouteront ici,
    /// chacun avec son propre compteur ; la boucle principale n'a pas à changer.
    fn decremente_temps(&mut self) {
        // Message erreur
        if self.message_erreur.1 > 0 {
            self.message_erreur.1 -= 1;
            if self.message_erreur.1 == 0 {
                self.message_erreur.0 = None;
            }
        }

        // Message aide
        if self.message_aide.1 > 0 {
            self.message_aide.1 -= 1;
            if self.message_aide.1 == 0 {
                self.message_aide.0 = None;
            }
        }
    }

    /// Passe à l'écran de travail suivant, en cycle.
    ///
    /// Le seul endroit qui connaisse l'ordre des écrans — la table des
    /// commandes dit quand basculer, pas vers quoi. Ici plutôt que dans un
    /// module d'écran : aucun d'eux ne sait ce qui le suit.
    ///
    /// Rien à poser d'autre que [`EtatTui::ecran`] : chaque écran de travail
    /// s'entre en [`ModeSaisie::Normal`], mode dans lequel on est forcément
    /// déjà puisque la table n'y est consultée que là.
    fn passer_ecran_suivant(&mut self) {
        match self.ecran {
            Ecran::Pilotage => {
                self.ecran = Ecran::ArborescenceEnu;
            }
            Ecran::ArborescenceEnu => {
                self.ecran = Ecran::Pilotage;
            }
        }
    }
}

/// Orchestre la boucle principale et le rendu.
///
/// Possède l'état de l'interface ([`EtatTui`]) et le connecteur vers le
/// thread cœur ([`crate::connecteurs::ConnecteurVersCoeur`]). Coordonne à
/// chaque itération de la boucle : rendu via [`rendu::dessiner`],
/// décrémentation périodique des éléments éphémères, traitement des
/// événements clavier, et dépouillement non bloquant du canal cœur→TUI.
pub(crate) struct Tui {
    /// L'état que la boucle dessine, fait évoluer, et transmet au rendu.
    etat_tui: EtatTui,
    /// L'extrémité TUI des deux canaux — seul chemin vers le nœud.
    connecteur_vers_coeur: ConnecteurVersCoeur,
}

impl Tui {
    /// Crée une instance de [`Tui`] avec l'état initial.
    pub(crate) fn new(connecteur_vers_coeur: ConnecteurVersCoeur) -> Self {
        Self {
            etat_tui: EtatTui::new(),
            connecteur_vers_coeur,
        }
    }

    /// Boucle principale : dessine, traite les événements clavier, lit le canal cœur.
    ///
    /// Chaque itération :
    /// 1. Dessin du frame courant.
    /// 2. Avance d'une seconde les comptes à rebours via [`EtatTui::decremente_temps`]
    ///    si `horloge` indique qu'une seconde s'est écoulée depuis la dernière impulsion.
    ///    `horloge` est le seul `Instant` de la boucle — [`EtatTui`] ne manipule que
    ///    des entiers, pas du temps.
    /// 3. `poll(50ms)` — si un événement clavier est disponible, dispatch selon
    ///    [`EtatTui::mode_saisie`] : mode normal (lookup dans
    ///    [`EtatTui::commandes_actives`] et exécution de la commande retournée),
    ///    insertion (accumulation dans le buffer, Entrée → validation,
    ///    Échap → annulation), ou information (Entrée → avancement de l'écran courant).
    /// 4. `try_recv` non bloquant sur le canal cœur→TUI : pose le message
    ///    d'erreur, appelle la transition qui correspond au message reçu
    ///    (`AttenteMdp`, `EnvoiSeed`), ou remplace la session et reconstruit
    ///    [`EtatTui::commandes_actives`] — le payload à `None` (extinction)
    ///    suffisant à tout éteindre d'un coup. La déconnexion du thread cœur
    ///    est signalée comme une erreur ordinaire.
    pub(crate) fn lancer(&mut self, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
        let mut horloge = Instant::now();
        loop {
            terminal.draw(|frame| rendu::dessiner(frame, &self.etat_tui))?;

            if horloge.elapsed() >= Duration::from_secs(1) {
                self.etat_tui.decremente_temps();
                horloge = Instant::now();
            }

            if crossterm::event::poll(Duration::from_millis(50))? {
                match self.etat_tui.mode_saisie {
                    ModeSaisie::Normal => {
                        if !self.saisie_mode_normal()? {
                            break;
                        }
                    }
                    ModeSaisie::Insertion => self.saisie_mode_insertion()?,
                    ModeSaisie::Information => self.saisie_mode_information()?,
                }
            }

            match self.connecteur_vers_coeur.recepteur().try_recv() {
                Err(TryRecvError::Empty) => {}

                Err(TryRecvError::Disconnected) => {
                    self.etat_tui
                        .ajouter_message_erreur(String::from("Thread déconnecté"));
                }

                Ok(message) => match message {
                    MessageCoeurTui::AffichageErreur(m) => self.etat_tui.ajouter_message_erreur(m),
                    MessageCoeurTui::AttenteMdp => {
                        self.etat_tui.vers_saisie_mdp();
                    }
                    MessageCoeurTui::EnvoiArborescenceEnu(arborescence_enus) => {
                        self.etat_tui.etat_arborescence_enu.arborescence_enus =
                            Some(arborescence_enus);
                    }
                    MessageCoeurTui::EnvoiSeed(seed) => {
                        self.etat_tui.vers_affichage_seed(seed);
                    }
                    MessageCoeurTui::EnvoiSessionApplication(session_application) => {
                        self.etat_tui.session_application = session_application;
                        self.etat_tui.commandes_actives = CommandesActives::new(&self.etat_tui);
                    }
                },
            }
        }
        Ok(())
    }

    /// Lit le prochain événement crossterm et retourne la touche si c'est un `Press`.
    ///
    /// Retourne `Some((code, modifiers))` uniquement sur [`KeyEventKind::Press`].
    /// Tout autre événement — relâchement de touche, redimensionnement de fenêtre,
    /// focus, souris — retourne `None` sans déclencher d'action.
    ///
    /// Ce helper centralise le filtrage en un seul endroit : les trois méthodes
    /// `saisie_mode_*` s'en servent et ne peuvent plus réagir par inadvertance à
    /// un événement non clavier.
    ///
    /// [`KeyModifiers`] est inclus dans le retour pour permettre les raccourcis
    /// avec modificateur (Ctrl, Alt…) à mesure que les commandes s'étoffent.
    /// Les appels qui n'ont besoin que du code ignorent les modificateurs avec `_`.
    fn lire_touche() -> std::io::Result<Option<(KeyCode, KeyModifiers)>> {
        match crossterm::event::read()? {
            Event::Key(KeyEvent {
                code,
                modifiers,
                kind: KeyEventKind::Press,
                ..
            }) => Ok(Some((code, modifiers))),
            _ => Ok(None),
        }
    }

    /// Traite une touche en mode [`ModeSaisie::Normal`] : dispatch via [`CommandesActives`].
    ///
    /// La logique se déroule en trois filtres successifs : [`Self::lire_touche`]
    /// écarte les événements non clavier ; le lookup dans
    /// [`EtatTui::commandes_actives`] écarte les touches non liées dans le
    /// contexte courant ; le `match` final mappe chaque [`Commande`] à son
    /// effet — envoi de message au cœur, bascule en [`ModeSaisie::Insertion`]
    /// pour les commandes qui collectent un argument, ou affichage de l'aide.
    ///
    /// Aucun raccourci n'est hardcodé ici : ajouter une commande consiste à
    /// étendre l'enum [`Commande`], à enrichir les règles de
    /// [`CommandesActives::new`] pour qu'elle insère la liaison dans les
    /// contextes voulus, et à ajouter un bras au `match`. La logique de
    /// filtrage par contexte reste entièrement dans [`commandes`].
    ///
    /// Une fois la commande dispatchée, [`EtatTui::commandes_actives`] est
    /// reconstruite via [`CommandesActives::new`] : la position courante ou
    /// l'écran ont pu changer, et la table doit refléter le nouveau contexte
    /// avant la prochaine frappe.
    ///
    /// Retourne `false` pour signaler à la boucle principale de s'arrêter
    /// (déclenché par [`Commande::PilotageQuitter`]).
    fn saisie_mode_normal(&mut self) -> std::io::Result<bool> {
        if let Some(touche) = Self::lire_touche()?
            && let Some(commande) = self.etat_tui.commandes_actives.get(&touche)
        {
            match commande {
                Commande::EcranSuivant => {
                    self.etat_tui.passer_ecran_suivant();
                }
                Commande::EnuChargerArborescence => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::ChargementArborescenceEnu);
                }
                Commande::ListeCommandesActives => {
                    self.etat_tui.ajouter_message_aide(
                        self.etat_tui.commandes_actives.liste_commandes_actives(),
                    );
                }
                Commande::PilotageAllumerNoeud => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::AllumageNoeud);
                }
                Commande::PilotageAPropos => {
                    let titre = String::from("Feu");
                    let information = format!(
                        "Version {} · GPL-3.0-or-later\n\n\
                             © 2026 Bertrand CLAVELIER\n\n",
                        env!("CARGO_PKG_VERSION")
                    );

                    self.etat_tui.vers_affichage_information(titre, information);
                }
                Commande::PilotageChangerPositionClasseur(index) => {
                    self.etat_tui.etat_pilotage.position_courante.classeur = *index;
                }
                Commande::PilotageChangerPositionFoyer(index) => {
                    self.etat_tui.etat_pilotage.position_courante.foyer = *index;
                }
                Commande::PilotageEteindreNoeud => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::ExtinctionNoeud);
                }
                Commande::PilotageFermerComptoirDepot => {
                    if let Some(session) = &self.etat_tui.session_application {
                        let index_comptoir = session
                            .comptoirs_depot_ouverts()
                            .first()
                            .expect("commande active quand au moins un élément");
                        self.connecteur_vers_coeur.envoyer_message_tui_coeur(
                            MessageTuiCoeur::FermetureComptoirDepot(*index_comptoir),
                        );
                    }
                }
                Commande::PilotageFermerFoyer(index) => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::FermetureFoyer(*index));
                    self.etat_tui.etat_pilotage.position_courante.foyer = None;
                    self.etat_tui.etat_pilotage.position_courante.classeur = None;
                }
                Commande::PilotageOuvrirComptoirDepot(index_foyer, index_classeur) => {
                    self.connecteur_vers_coeur.envoyer_message_tui_coeur(
                        MessageTuiCoeur::OuvertureComptoir(
                            PathBuf::from(CHEMIN_COMPTOIR_DEPOT),
                            *index_foyer,
                            *index_classeur,
                        ),
                    );
                }
                Commande::PilotageOuvrirFoyer => {
                    self.etat_tui.prompt = String::from("ouvre");
                    self.etat_tui.mode_saisie = ModeSaisie::Insertion;
                    self.etat_tui.validation_buffer_saisie = ValidationBufferSaisie::OuvertureFoyer;
                }
                Commande::PilotageQuitter => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::Quitter);
                    return Ok(false);
                }
                Commande::PilotageRetraitLectureSeule => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::RetraitLectureSeule);
                }
            }

            self.etat_tui.commandes_actives = CommandesActives::new(&self.etat_tui);
        }

        Ok(true)
    }

    /// Traite une touche en mode [`ModeSaisie::Insertion`] : accumulation dans le buffer.
    ///
    /// Seules les frappes sans modificateur (`KeyModifiers::NONE`) sont traitées —
    /// un `Ctrl+Entrée` n'est pas une validation, un `Ctrl+C` n'est pas un caractère.
    ///
    /// À la validation (Entrée), consulte [`EtatTui::validation_buffer_saisie`] pour
    /// décider quel message envoyer au cœur :
    /// - [`ValidationBufferSaisie::EnvoiMdp`] → transmission directe en
    ///   [`SecretString`] ;
    /// - [`ValidationBufferSaisie::OuvertureFoyer`] → parsing du buffer en
    ///   `usize` et garde `index > 0` avant émission ; en cas d'échec, un message
    ///   d'erreur est affiché et aucun message n'est envoyé au cœur ;
    /// - [`ValidationBufferSaisie::Rien`] → no-op (état hors-saisie indue).
    ///
    /// Quel que soit le bras pris, l'écran revient à son état de repos, la
    /// destination du buffer à [`ValidationBufferSaisie::Rien`], et `prompt`
    /// comme `buffer_saisie` sont vidés — sans jamais consulter l'écran
    /// courant.
    ///
    /// À l'annulation (Échap), vide buffer et prompt, restaure l'écran et le mode,
    /// puis envoie [`MessageTuiCoeur::Annulation`] — utile aux attentes bloquantes
    /// côté cœur (cf. l'implémentation de `demander_mdp` sur
    /// [`crate::connecteurs::ConnecteurVersTui`]).
    fn saisie_mode_insertion(&mut self) -> std::io::Result<()> {
        match Self::lire_touche()? {
            Some((KeyCode::Char(c), KeyModifiers::NONE)) => {
                self.etat_tui.buffer_saisie.push(c);
            }
            Some((KeyCode::Backspace, KeyModifiers::NONE)) => {
                self.etat_tui.buffer_saisie.pop();
            }
            Some((KeyCode::Enter, KeyModifiers::NONE)) => {
                self.etat_tui.vers_ecran_principal();
                match self.etat_tui.validation_buffer_saisie {
                    ValidationBufferSaisie::EnvoiMdp => {
                        self.connecteur_vers_coeur.envoyer_message_tui_coeur(
                            MessageTuiCoeur::EnvoieMdp(SecretString::from(
                                self.etat_tui.buffer_saisie.clone(),
                            )),
                        );
                    }
                    ValidationBufferSaisie::OuvertureFoyer => {
                        let index_result: Result<usize, _> =
                            self.etat_tui.buffer_saisie.trim().parse();
                        if let Ok(index) = index_result
                            && index > 0
                        {
                            self.connecteur_vers_coeur
                                .envoyer_message_tui_coeur(MessageTuiCoeur::OuvertureFoyer(index));
                        } else {
                            self.etat_tui
                                .ajouter_message_erreur(String::from("Numéro de foyer invalide"));
                        }
                    }
                    ValidationBufferSaisie::Rien => {}
                }
                self.etat_tui.validation_buffer_saisie = ValidationBufferSaisie::Rien;
                self.etat_tui.prompt.clear();
                self.etat_tui.buffer_saisie.clear();
            }
            Some((KeyCode::Esc, KeyModifiers::NONE)) => {
                self.etat_tui.prompt.clear();
                self.etat_tui.buffer_saisie.clear();
                self.etat_tui.vers_ecran_principal();
                self.connecteur_vers_coeur
                    .envoyer_message_tui_coeur(MessageTuiCoeur::Annulation);
            }
            _ => {}
        }
        Ok(())
    }

    /// Traite une touche en mode [`ModeSaisie::Information`] : avancement sur Entrée uniquement.
    ///
    /// Seule `Entrée` sans modificateur est active — tout autre événement est
    /// ignoré, pour qu'un redimensionnement de fenêtre ou un clic souris ne
    /// fasse pas progresser l'écran sans geste de l'utilisateur.
    ///
    /// Ce qu'« avancer » signifie revient à l'écran affiché ; cette méthode ne
    /// garde que ce qu'elle seule peut faire — prévenir le cœur, dont elle
    /// tient le connecteur.
    fn saisie_mode_information(&mut self) -> std::io::Result<()> {
        if let Some((KeyCode::Enter, KeyModifiers::NONE)) = Self::lire_touche()?
            && self.etat_tui.entree_mode_information()
        {
            self.connecteur_vers_coeur
                .envoyer_message_tui_coeur(MessageTuiCoeur::SeedBienRecue);
        }
        Ok(())
    }
}
