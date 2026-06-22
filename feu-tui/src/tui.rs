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
//! L'état courant se lit sur quatre axes orthogonaux qui évoluent indépendamment.
//!
//! [`Ecran`] décide quelle famille visuelle est dessinée : carré normal pour
//! l'usage courant, cadres arrondis orange pour les écrans pilotés par le cœur
//! (saisie du mot de passe, affichage de la seed). [`ModeSaisie`] décide
//! comment les touches sont interprétées : `Normal` (dispatch via la table de
//! commandes), `Insertion` (accumulation dans un buffer, validation par Entrée),
//! `Information` (avancement par Entrée uniquement). [`PositionCourante`]
//! décrit où l'utilisateur est dans la pseudo-arborescence foyer → classeur,
//! affichée en fil d'Ariane dans l'invite et lue par
//! [`commandes::CommandesActives`] pour décider quelles touches activer.
//! [`commandes::CommandesActives`] enfin liste les touches actives,
//! reconstruite à chaque changement de session ou de position courante.
//!
//! Le geste utilisateur typique au clavier : `a` pour allumer le nœud, mot de
//! passe, seed validée par deux pressions d'Entrée, puis `o` pour ouvrir un
//! foyer (saisie du numéro), `1`-`9` pour entrer dans un foyer ouvert puis
//! dans un de ses classeurs, `Backspace` pour remonter d'un niveau, `f` pour
//! fermer le foyer où l'on est positionné, `e` pour éteindre quand tous les
//! foyers sont fermés, `q` pour quitter quand le nœud est éteint. À tout
//! moment `?` affiche la liste des touches actives dans le contexte courant.

mod commandes;
mod rendu;

use std::{
    sync::mpsc::TryRecvError,
    time::{Duration, Instant},
};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use feu_application::SessionApplication;
use ratatui::DefaultTerminal;
use secrecy::SecretString;

use crate::connecteurs::{ConnecteurVersCoeur, MessageCoeurTui, MessageTuiCoeur};
use commandes::{Commande, CommandesActives};

/// Axe de rendu : détermine quelle famille visuelle est dessinée à chaque frame.
///
/// Chaque variante porte les données propres à son écran — [`Ecran::AffichageSeed`]
/// embarque les mots directement, garantissant que le rendu dispose de tout ce
/// dont il a besoin sans interroger d'autre partie de l'état. Le compilateur
/// garantit l'exhaustivité du `match` dans [`rendu::dessiner`].
///
/// Orthogonal à [`ModeSaisie`] : un même écran peut traverser plusieurs modes.
/// [`Ecran::Normal`] sera utilisé avec les trois modes à mesure que les commandes
/// s'étoffent. Fusionner ces deux axes recouperait le rendu et l'interprétation
/// des touches, deux responsabilités indépendantes.
pub(crate) enum Ecran {
    /// Carré centré à angles droits — état de repos de l'interface.
    ///
    /// Utilisé avec [`ModeSaisie::Normal`] pour le dispatch des commandes filtrées
    /// par contexte, et avec [`ModeSaisie::Insertion`] lorsque l'invite porte un
    /// prompt de commande (numéro de foyer pour [`Commande::OuvrirFoyer`]).
    /// Accueillera également [`ModeSaisie::Information`] à mesure que des
    /// confirmations contextuelles s'ajouteront.
    Normal,

    /// Cadre arrondi orange centré — affiché quand le cœur demande un mot de passe.
    ///
    /// Toujours associé à [`ModeSaisie::Insertion`] et [`ValidationBufferSaisie::EnvoiMdp`].
    /// Déclenché par [`crate::connecteurs::MessageCoeurTui::AttenteMdp`].
    SaisieMdp,

    /// Cadre arrondi orange centré — affiché après génération de la seed.
    ///
    /// Toujours associé à [`ModeSaisie::Information`].
    /// Déclenché par [`crate::connecteurs::MessageCoeurTui::EnvoiSeed`].
    /// `rappel` passe à `true` à la première pression d'Entrée pour afficher le message de confirmation.
    AffichageSeed {
        seed: Vec<SecretString>,
        rappel: bool,
    },
}

/// Axe d'interprétation des touches clavier — indépendant de l'écran affiché.
///
/// Transversal à [`Ecran`] : un même écran peut traverser plusieurs modes selon
/// son état. [`Ecran::Normal`] traverse aujourd'hui `Normal` (dispatch des
/// commandes filtrées par contexte) et `Insertion` (saisie d'un argument de
/// commande, par exemple un numéro de foyer) ; il accueillera `Information`
/// quand des confirmations contextuelles seront ajoutées.
/// Fusionner cet axe avec [`Ecran`] recouperait l'interprétation des touches et
/// la logique de rendu, deux responsabilités indépendantes.
pub(crate) enum ModeSaisie {
    /// Touches dispatchées via [`EtatTui::commandes_actives`] : la table
    /// indique quelle commande exécuter, ou rien si la touche n'y figure pas.
    Normal,

    /// Touches accumulées dans [`EtatTui::buffer_saisie`] ; Entrée valide, Échap annule.
    ///
    /// Utilisé par [`Ecran::SaisieMdp`] pour le mot de passe et par [`Ecran::Normal`]
    /// pour les prompts de commande (numéro de foyer). La destination du buffer à la
    /// validation est portée par [`ValidationBufferSaisie`].
    Insertion,

    /// Entrée (sans modificateur) avance l'état de l'écran courant — toute autre touche est ignorée.
    ///
    /// Utilisé par [`Ecran::AffichageSeed`] : première pression d'Entrée déclenche le rappel,
    /// deuxième pression envoie [`crate::connecteurs::MessageTuiCoeur::SeedBienRecue`].
    Information,
}

/// Destination du contenu de [`EtatTui::buffer_saisie`] à la validation (Entrée).
///
/// Positionné avant de basculer en [`ModeSaisie::Insertion`] par le bras qui
/// déclenche la saisie — réception de [`crate::connecteurs::MessageCoeurTui::AttenteMdp`]
/// pour [`Self::EnvoiMdp`], dispatch d'une commande [`Commande::OuvrirFoyer`]
/// pour [`Self::OuvertureFoyer`].
/// Consommé et remis à [`Self::Rien`] par `saisie_mode_insertion`, qui n'a ainsi
/// pas à connaître l'écran courant pour décider quoi émettre.
///
/// La fermeture d'un foyer ne passe pas par ce mécanisme : elle est immédiate
/// depuis le foyer où l'on est positionné (cf. [`Commande::FermerFoyer`]),
/// l'index étant capturé depuis [`EtatTui::position_courante`] au moment de la
/// construction de la table des commandes actives.
pub(crate) enum ValidationBufferSaisie {
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
    /// [`Commande::OuvrirFoyer`]. À la validation, le buffer est parsé en
    /// `usize` et l'index doit être strictement positif ; sinon un message
    /// d'erreur est affiché et aucun message n'est envoyé au cœur. La
    /// conversion en index base 0 reste à la charge du connecteur cœur.
    OuvertureFoyer,
}

/// Position de navigation dans la pseudo-arborescence foyer → classeur.
///
/// Sépare la navigation TUI des commandes noyau : la position est purement un
/// curseur de présentation, elle ne déclenche aucune action métier en elle-même.
/// Elle est en revanche une entrée de [`CommandesActives::new`] — le contexte
/// de navigation conditionne quelles touches sont actives, et l'index porté
/// par [`Commande::FermerFoyer`] est capturé depuis cette position au moment
/// de la construction de la table.
///
/// # Niveaux et invariants
///
/// Trois niveaux successifs, encodés par la combinaison des deux `Option` :
/// - racine : `foyer = None`, `classeur = None` ;
/// - dans un foyer : `foyer = Some(i)`, `classeur = None` ;
/// - dans un classeur : `foyer = Some(i)`, `classeur = Some(j)`.
///
/// L'invariant *« `classeur = Some(_)` implique `foyer = Some(_)` »* est tenu
/// par la logique de transition (cf. les bras `ChangerPositionFoyer` et
/// `ChangerPositionClasseur` dans [`Tui::saisie_mode_normal`]) plutôt que par
/// le type.
///
/// # Réconciliation avec la session
///
/// La position courante doit toujours rester cohérente avec la session du nœud :
/// si l'utilisateur ferme le foyer où il est positionné, la position est
/// immédiatement remise à la racine au moment où la commande de fermeture est
/// émise. Comme [`Commande::FermerFoyer`] est l'unique chemin de fermeture
/// d'un foyer, l'invariant tient en cascade : à l'extinction du nœud (qui exige
/// que tous les foyers soient fermés), la position est nécessairement déjà à la
/// racine.
pub(crate) struct PositionCourante {
    /// Index 1-based du foyer où l'utilisateur est positionné, `None` à la racine.
    ///
    /// Posé par [`Commande::ChangerPositionFoyer(Some(_))`](Commande::ChangerPositionFoyer)
    /// depuis la racine — la table n'expose la touche que pour les foyers
    /// effectivement ouverts dans la session courante. Effacé par
    /// [`Commande::ChangerPositionFoyer(None)`](Commande::ChangerPositionFoyer)
    /// (Backspace depuis le niveau foyer) ou par [`Commande::FermerFoyer`]
    /// (qui ramène la position complète à la racine).
    foyer: Option<usize>,

    /// Index 1-based du classeur où l'utilisateur est positionné, `None` si l'on
    /// n'est pas descendu jusqu'à un classeur.
    ///
    /// Posé par [`Commande::ChangerPositionClasseur(Some(_))`](Commande::ChangerPositionClasseur)
    /// depuis un foyer — la table expose les touches `1`-`9` dans la limite de
    /// `nombre_classeurs` (aucune notion d'« ouverture » pour les classeurs
    /// aujourd'hui : tous les indices valides sont accessibles). Effacé par
    /// [`Commande::ChangerPositionClasseur(None)`](Commande::ChangerPositionClasseur)
    /// (Backspace depuis le niveau classeur) ou par [`Commande::FermerFoyer`].
    classeur: Option<usize>,
}

/// État courant de l'interface entre deux frames.
///
/// Regroupe dix dimensions orthogonales dont aucune ne peut être absorbée
/// par une autre :
/// - `session_application` : clone de la session reçu après chaque commande mutante,
///   `None` quand le nœud est éteint ;
/// - [`Ecran`] : quoi dessiner ;
/// - [`ModeSaisie`] : comment interpréter les touches ;
/// - [`PositionCourante`] : où l'utilisateur est positionné dans la
///   pseudo-arborescence foyer → classeur, indépendant de l'écran et du mode ;
/// - `commandes_actives` : quelles touches déclenchent quelle commande dans le
///   contexte courant ;
/// - [`ValidationBufferSaisie`] : quoi émettre lors de la validation du buffer ;
/// - `message_erreur` : transversal aux écrans, porte le texte et son compte à
///   rebours d'effacement automatique (cf. [`EtatTui::decremente_temps`]) ;
/// - `message_aide` : message éphémère destiné à l'utilisateur (aujourd'hui
///   alimenté par `?` qui liste les commandes actives), même mécanisme que
///   `message_erreur` mais durée plus courte ;
/// - `prompt` : libellé affiché en regard du buffer pendant une saisie
///   ([`ModeSaisie::Insertion`]) ;
/// - `buffer_saisie` : accumulateur de saisie, aveugle à l'écran courant.
pub(crate) struct EtatTui {
    /// Session applicative courante — `None` quand le nœud est éteint.
    ///
    /// Peuplé par [`crate::connecteurs::MessageCoeurTui::EnvoiSessionApplication`]
    /// dans la boucle principale, qui affecte directement le payload reçu.
    /// `None` signifie nœud éteint (pastilles éteintes) — état initial, ou
    /// résultat d'une extinction réussie ; `Some(_)` signifie nœud allumé.
    /// Pas de booléen séparé — la présence du clone est la preuve que l'allumage
    /// a réussi, son absence celle de l'extinction.
    pub(crate) session_application: Option<SessionApplication>,

    /// Écran actuellement affiché — détermine la fonction de rendu appelée.
    pub(crate) ecran: Ecran,

    /// Mode de saisie courant — détermine l'interprétation des touches.
    pub(crate) mode_saisie: ModeSaisie,

    /// Position de navigation TUI — racine, foyer, ou foyer + classeur.
    ///
    /// Curseur de présentation, indépendant de l'écran et du mode. Affiché en
    /// fil d'Ariane dans l'invite (`feu/foy.N/cla.M ›`) et lu par
    /// [`CommandesActives::new`] pour décider quelles touches activer ; l'index
    /// foyer est capturé dans [`Commande::FermerFoyer`] au moment de la
    /// construction de la table.
    pub(crate) position_courante: PositionCourante,

    /// Table de dispatch touche → commande, filtrée par le contexte courant.
    ///
    /// Source de vérité unique pour les commandes accessibles à un instant donné :
    /// une touche absente de la table ne déclenche rien, point. Le filtrage par
    /// contexte n'a donc aucun cas particulier à gérer dans la boucle.
    ///
    /// Reconstruite intégralement à chaque changement d'état pertinent via
    /// [`CommandesActives::new`] : à la réception d'une nouvelle session dans
    /// [`Tui::lancer`] ([`crate::connecteurs::MessageCoeurTui::EnvoiSessionApplication`])
    /// et après chaque commande dispatchée par [`Tui::saisie_mode_normal`].
    /// La sortie est une fonction pure de l'état — aucune mutation incrémentale,
    /// aucun risque de désynchronisation entre la table, l'état applicatif et
    /// la position courante.
    commandes_actives: CommandesActives,

    /// Ce que l'on fait du buffer à la validation — positionné avant de passer en [`ModeSaisie::Insertion`].
    pub(crate) validation_buffer_saisie: ValidationBufferSaisie,

    /// Dernier message d'erreur et son compte à rebours en secondes.
    ///
    /// Champ privé — accès en lecture via [`EtatTui::message_erreur`],
    /// écriture via [`EtatTui::ajouter_message_erreur`].
    /// Le tuple garantit que texte et durée sont toujours posés et effacés ensemble.
    ///
    /// À plat dans [`EtatTui`] pour survivre aux transitions d'écran : une erreur née
    /// pendant [`Ecran::SaisieMdp`] doit rester visible sur l'écran qui suit sa fermeture.
    /// Effacé automatiquement quand le compte à rebours atteint zéro via [`EtatTui::decremente_temps`].
    message_erreur: (Option<String>, u8),

    /// Dernier message éphémère à destination de l'utilisateur, et son compte
    /// à rebours en secondes.
    ///
    /// Champ privé — accès en lecture via [`EtatTui::message_aide`],
    /// écriture via [`EtatTui::ajouter_message_aide`].
    ///
    /// Aujourd'hui alimenté par le bras d'exécution de
    /// [`Commande::ListeCommandesActives`], qui y dépose la liste formatée des
    /// touches actives. Durée volontairement courte (2 s contre 5 s pour les
    /// erreurs) : un message d'aide doit disparaître vite pour ne pas
    /// encombrer l'écran. Effacé automatiquement quand le compte à rebours
    /// atteint zéro via [`EtatTui::decremente_temps`].
    message_aide: (Option<String>, u8),

    /// Libellé affiché en regard du buffer pendant une saisie.
    ///
    /// Posé par [`Tui::saisie_mode_normal`] au moment de basculer en
    /// [`ModeSaisie::Insertion`] (par exemple `"ouvre"` pour
    /// [`Commande::OuvrirFoyer`]) ; vidé par `saisie_mode_insertion` à la
    /// validation comme à l'annulation, en miroir de [`Self::buffer_saisie`].
    pub(crate) prompt: String,

    /// Accumulateur de la saisie en mode [`ModeSaisie::Insertion`]. Vidé après chaque validation ou annulation.
    ///
    /// À plat dans [`EtatTui`] parce que la boucle d'accumulation est indépendante de l'écran :
    /// `saisie_mode_insertion` n'a pas à `match` sur [`EtatTui::ecran`] pour accumuler les frappes.
    pub(crate) buffer_saisie: String,
}

impl EtatTui {
    /// Crée un [`EtatTui`] en état initial : écran normal.
    fn new() -> Self {
        Self {
            session_application: None,
            ecran: Ecran::Normal,
            mode_saisie: ModeSaisie::Normal,
            position_courante: PositionCourante {
                foyer: None,
                classeur: None,
            },
            commandes_actives: CommandesActives::new(
                &None,
                &PositionCourante {
                    foyer: None,
                    classeur: None,
                },
            ),
            validation_buffer_saisie: ValidationBufferSaisie::Rien,
            message_erreur: (None, 0),
            message_aide: (None, 0),
            prompt: String::new(),
            buffer_saisie: String::new(),
        }
    }

    /// Retourne le texte du message d'erreur courant, `None` si aucun.
    ///
    /// Expose uniquement le texte — le compte à rebours est un détail interne.
    pub(crate) fn message_erreur(&self) -> &Option<String> {
        &self.message_erreur.0
    }

    /// Pose un message d'erreur avec un compte à rebours de 5 secondes.
    ///
    /// Toujours appelé à la place d'une affectation directe : garantit que
    /// texte et durée sont posés atomiquement et ne peuvent pas se désynchroniser.
    pub(crate) fn ajouter_message_erreur(&mut self, message_erreur: String) {
        self.message_erreur.0 = Some(message_erreur);
        self.message_erreur.1 = 5;
    }

    /// Retourne le texte du message d'aide courant, `None` si aucun.
    ///
    /// Expose uniquement le texte — le compte à rebours est un détail interne.
    pub(crate) fn message_aide(&self) -> &Option<String> {
        &self.message_aide.0
    }

    /// Pose un message d'aide avec un compte à rebours de 2 secondes.
    ///
    /// Toujours appelé à la place d'une affectation directe : garantit que
    /// texte et durée sont posés atomiquement et ne peuvent pas se désynchroniser.
    pub(crate) fn ajouter_message_aide(&mut self, message_aide: String) {
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
}

/// Orchestre la boucle principale et le rendu.
///
/// Possède l'état de l'interface ([`EtatTui`]) et le connecteur vers le
/// thread cœur ([`crate::connecteurs::ConnecteurVersCoeur`]). Coordonne à
/// chaque itération de la boucle : rendu via [`rendu::dessiner`],
/// décrémentation périodique des éléments éphémères, traitement des
/// événements clavier, et dépouillement non bloquant du canal cœur→TUI.
pub(crate) struct Tui {
    etat_tui: EtatTui,
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
    /// 4. `try_recv` non bloquant sur le canal cœur→TUI : met à jour
    ///    [`EtatTui::message_erreur`] sur [`MessageCoeurTui::AffichageErreur`],
    ///    bascule sur [`Ecran::SaisieMdp`] sur [`MessageCoeurTui::AttenteMdp`],
    ///    bascule sur [`Ecran::AffichageSeed`] sur [`MessageCoeurTui::EnvoiSeed`],
    ///    met à jour [`EtatTui::session_application`] et reconstruit
    ///    [`EtatTui::commandes_actives`] via [`CommandesActives::new`] sur
    ///    [`MessageCoeurTui::EnvoiSessionApplication`], ou signale la
    ///    déconnexion du thread cœur.
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
                        self.etat_tui.ecran = Ecran::SaisieMdp;
                        self.etat_tui.mode_saisie = ModeSaisie::Insertion;
                        self.etat_tui.validation_buffer_saisie = ValidationBufferSaisie::EnvoiMdp;
                    }
                    MessageCoeurTui::EnvoiSeed(seed) => {
                        self.etat_tui.ecran = Ecran::AffichageSeed {
                            seed,
                            rappel: false,
                        };
                        self.etat_tui.mode_saisie = ModeSaisie::Information;
                    }
                    MessageCoeurTui::EnvoiSessionApplication(session_application) => {
                        self.etat_tui.session_application = session_application;
                        self.etat_tui.commandes_actives = CommandesActives::new(
                            &self.etat_tui.session_application,
                            &self.etat_tui.position_courante,
                        );
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
    /// reconstruite via [`CommandesActives::new`] : la position courante a pu
    /// changer (`ChangerPositionFoyer`, `ChangerPositionClasseur`, `FermerFoyer`)
    /// et la table doit refléter le nouveau contexte avant la prochaine frappe.
    ///
    /// Retourne `false` pour signaler à la boucle principale de s'arrêter
    /// (déclenché par [`Commande::Quitter`]).
    fn saisie_mode_normal(&mut self) -> std::io::Result<bool> {
        if let Some(touche) = Self::lire_touche()?
            && let Some(commande) = self.etat_tui.commandes_actives.get(&touche)
        {
            match commande {
                Commande::AllumerNoeud => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::AllumageNoeud);
                }
                Commande::ChangerPositionClasseur(index) => {
                    self.etat_tui.position_courante.classeur = *index;
                }
                Commande::ChangerPositionFoyer(index) => {
                    self.etat_tui.position_courante.foyer = *index;
                }
                Commande::EteindreNoeud => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::ExtinctionNoeud);
                }
                Commande::FermerFoyer(index) => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::FermetureFoyer(*index));
                    self.etat_tui.position_courante.foyer = None;
                    self.etat_tui.position_courante.classeur = None;
                }
                Commande::ListeCommandesActives => {
                    self.etat_tui.ajouter_message_aide(
                        self.etat_tui.commandes_actives.liste_commandes_actives(),
                    );
                }
                Commande::OuvrirFoyer => {
                    self.etat_tui.prompt = String::from("ouvre");
                    self.etat_tui.mode_saisie = ModeSaisie::Insertion;
                    self.etat_tui.validation_buffer_saisie = ValidationBufferSaisie::OuvertureFoyer;
                }
                Commande::Quitter => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::Quitter);
                    return Ok(false);
                }
            }

            self.etat_tui.commandes_actives = CommandesActives::new(
                &self.etat_tui.session_application,
                &self.etat_tui.position_courante,
            );
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
    /// Quel que soit le bras pris, l'écran repasse à [`Ecran::Normal`], le mode à
    /// [`ModeSaisie::Normal`], la destination du buffer à
    /// [`ValidationBufferSaisie::Rien`], et `prompt` comme `buffer_saisie` sont
    /// vidés. `saisie_mode_insertion` n'a jamais à connaître l'écran courant.
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
                self.etat_tui.ecran = Ecran::Normal;
                self.etat_tui.mode_saisie = ModeSaisie::Normal;
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
                self.etat_tui.ecran = Ecran::Normal;
                self.etat_tui.mode_saisie = ModeSaisie::Normal;
                self.connecteur_vers_coeur
                    .envoyer_message_tui_coeur(MessageTuiCoeur::Annulation);
            }
            _ => {}
        }
        Ok(())
    }

    /// Traite une touche en mode [`ModeSaisie::Information`] : avancement sur Entrée uniquement.
    ///
    /// Seule `Entrée` sans modificateur est active — tout autre événement est ignoré.
    /// Ce choix est intentionnel : il évite qu'un redimensionnement de fenêtre ou un
    /// clic souris ne fasse progresser l'écran de seed sans action explicite de l'utilisateur.
    ///
    /// Première pression d'Entrée : pose `rappel = true` dans [`Ecran::AffichageSeed`]
    /// pour afficher le message de confirmation.
    /// Deuxième pression d'Entrée : retour à [`Ecran::Normal`] +
    /// envoi de [`MessageTuiCoeur::SeedBienRecue`].
    fn saisie_mode_information(&mut self) -> std::io::Result<()> {
        if let Some((KeyCode::Enter, KeyModifiers::NONE)) = Self::lire_touche()?
            && let Ecran::AffichageSeed { seed: _, rappel } = &mut self.etat_tui.ecran
        {
            if *rappel {
                self.etat_tui.ecran = Ecran::Normal;
                self.etat_tui.mode_saisie = ModeSaisie::Normal;
                self.connecteur_vers_coeur
                    .envoyer_message_tui_coeur(MessageTuiCoeur::SeedBienRecue);
            } else {
                *rappel = true;
            }
        }

        Ok(())
    }
}
