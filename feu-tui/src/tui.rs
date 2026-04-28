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
    /// Actuellement utilisé avec [`ModeSaisie::Normal`] ; accueillera
    /// [`ModeSaisie::Insertion`] pour les futurs prompts de commande, et
    /// [`ModeSaisie::Information`] pour les futures confirmations.
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
/// son état. [`Ecran::Normal`] sera utilisé avec les trois — commandes filtrées
/// par contexte en `Normal`, saisie de commande en `Insertion`, et confirmations
/// en `Information`.
/// Fusionner cet axe avec [`Ecran`] recouperait l'interprétation des touches et
/// la logique de rendu, deux responsabilités indépendantes.
pub(crate) enum ModeSaisie {
    /// Touches dispatchées via [`EtatTui::commandes_actives`] : la table
    /// indique quelle commande exécuter, ou rien si la touche n'y figure pas.
    Normal,

    /// Touches accumulées dans [`EtatTui::buffer_saisie`] ; Entrée valide, Échap annule.
    ///
    /// Sera également utilisé par [`Ecran::Normal`] lorsqu'il portera un prompt de commande.
    Insertion,

    /// Entrée (sans modificateur) avance l'état de l'écran courant — toute autre touche est ignorée.
    ///
    /// Utilisé par [`Ecran::AffichageSeed`] : première pression d'Entrée déclenche le rappel,
    /// deuxième pression envoie [`crate::connecteurs::MessageTuiCoeur::SeedBienRecue`].
    Information,
}

/// Destination du contenu de [`EtatTui::buffer_saisie`] à la validation (Entrée).
///
/// Positionné avant de basculer en [`ModeSaisie::Insertion`] par le gestionnaire
/// du message reçu — aujourd'hui [`crate::connecteurs::MessageCoeurTui::AttenteMdp`]
/// pose [`ValidationBufferSaisie::EnvoiMdp`].
/// Consommé et remis à [`ValidationBufferSaisie::Rien`] par `saisie_mode_insertion`,
/// qui n'a ainsi pas à connaître l'écran courant pour décider quoi émettre.
pub(crate) enum ValidationBufferSaisie {
    /// Le buffer est vidé sans envoyer de message au cœur.
    Rien,

    /// Le buffer est transmis comme [`crate::connecteurs::MessageTuiCoeur::EnvoieMdp`] au thread cœur.
    EnvoiMdp,

    OuvertureFoyer,
}

/// État courant de l'interface entre deux frames.
///
/// Regroupe sept dimensions orthogonales dont aucune ne peut être absorbée
/// par une autre :
/// - `session_application` : clone de la session reçu après chaque commande mutante ;
/// - [`Ecran`] : quoi dessiner ;
/// - [`ModeSaisie`] : comment interpréter les touches ;
/// - `commandes_actives` : quelles touches déclenchent quelle commande dans le contexte courant ;
/// - [`ValidationBufferSaisie`] : quoi émettre lors de la validation du buffer ;
/// - `buffer_saisie` : accumulateur de saisie, aveugle à l'écran courant ;
/// - `message_erreur` : transversal aux écrans, porte le texte et son compte
///   à rebours d'effacement automatique (cf. [`EtatTui::decremente_temps`]).
pub(crate) struct EtatTui {
    /// Session applicative courante — `None` tant que le nœud n'a pas été allumé.
    ///
    /// Peuplé par [`crate::connecteurs::MessageCoeurTui::EnvoiSessionApplication`]
    /// dans la boucle principale. `None` signifie nœud éteint (pastilles éteintes) ;
    /// `Some(_)` signifie nœud allumé. Pas de booléen séparé — la présence du clone
    /// est la preuve que l'allumage a réussi.
    pub(crate) session_application: Option<SessionApplication>,

    /// Écran actuellement affiché — détermine la fonction de rendu appelée.
    pub(crate) ecran: Ecran,

    /// Mode de saisie courant — détermine l'interprétation des touches.
    pub(crate) mode_saisie: ModeSaisie,

    /// Table de dispatch touche → commande, filtrée par le contexte courant.
    ///
    /// Source de vérité unique pour les commandes accessibles à un instant donné :
    /// une touche absente de la table ne déclenche rien, point. Le filtrage par
    /// contexte n'a donc aucun cas particulier à gérer dans la boucle — il suffit
    /// d'ajouter ou retirer des entrées via [`CommandesActives::desactiver`]
    /// au moment où le contexte change.
    ///
    /// Évolue par mutations incrémentales plutôt que par reconstruction : chaque
    /// transition d'état (allumage, ouverture de foyer…) ne touche que les commandes
    /// concernées, ce qui rend les transitions explicites et auditables.
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

    /// Dernière confirmation de commande et son compte à rebours en secondes.
    ///
    /// Champ privé — accès en lecture via [`EtatTui::message_commande`],
    /// écriture via [`EtatTui::ajouter_message_commande`].
    ///
    /// Durée volontairement courte (2 s contre 5 s pour les erreurs) : une
    /// confirmation visuelle doit disparaître vite pour ne pas encombrer l'écran.
    /// Effacé automatiquement quand le compte à rebours atteint zéro via [`EtatTui::decremente_temps`].
    message_commande: (Option<String>, u8),

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
            commandes_actives: CommandesActives::new(),
            validation_buffer_saisie: ValidationBufferSaisie::Rien,
            message_erreur: (None, 0),
            message_commande: (None, 0),
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

    /// Retourne le texte de la confirmation de commande courante, `None` si aucune.
    ///
    /// Expose uniquement le texte — le compte à rebours est un détail interne.
    pub(crate) fn message_commande(&self) -> &Option<String> {
        &self.message_commande.0
    }

    /// Pose une confirmation de commande avec un compte à rebours de 2 secondes.
    ///
    /// Toujours appelé à la place d'une affectation directe : garantit que
    /// texte et durée sont posés atomiquement et ne peuvent pas se désynchroniser.
    pub(crate) fn ajouter_message_commande(&mut self, message_commande: String) {
        self.message_commande.0 = Some(message_commande);
        self.message_commande.1 = 2;
    }

    /// Décrémente d'une seconde tous les comptes à rebours des éléments éphémères.
    ///
    /// Appelé par [`Tui::lancer`] toutes les secondes via une `horloge: Instant`.
    /// Quand le compte à rebours d'un élément atteint zéro, l'élément est effacé.
    ///
    /// Éléments éphémères gérés actuellement :
    /// - [`EtatTui::message_erreur`] — durée 5 s ;
    /// - [`EtatTui::message_commande`] — durée 2 s.
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

        // Message commande
        if self.message_commande.1 > 0 {
            self.message_commande.1 -= 1;
            if self.message_commande.1 == 0 {
                self.message_commande.0 = None;
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
    ///    met à jour [`EtatTui::session_application`] sur [`MessageCoeurTui::EnvoiSessionApplication`],
    ///    ou signale la déconnexion du thread cœur.
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
                        self.etat_tui.session_application = Some(session_application);
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
    /// effet — envoi de message au cœur, mutation de la table pour les
    /// commandes à usage unique, ou affichage de l'aide.
    ///
    /// Aucun raccourci n'est hardcodé ici : ajouter une commande consiste à
    /// étendre l'enum [`Commande`], à insérer la liaison dans
    /// [`CommandesActives::new`] (ou via une future activation contextuelle)
    /// et à ajouter un bras au `match`. La logique de filtrage par contexte
    /// reste entièrement dans [`commandes`].
    ///
    /// Retourne `false` pour signaler à la boucle principale de s'arrêter
    /// (déclenché par [`Commande::Quitter`]).
    fn saisie_mode_normal(&mut self) -> std::io::Result<bool> {
        if let Some(touche) = Self::lire_touche()? {
            if let Some(commande) = self.etat_tui.commandes_actives.get(&touche) {
                let libelle = commande.afficher();
                match commande {
                    Commande::AllumerNoeud => {
                        self.connecteur_vers_coeur
                            .envoyer_message_tui_coeur(MessageTuiCoeur::AllumageNoeud);
                        self.etat_tui
                            .commandes_actives
                            .desactiver(Commande::AllumerNoeud);
                        self.etat_tui.commandes_actives.ajouter(
                            (KeyCode::Char('o'), KeyModifiers::NONE),
                            Commande::OuvrirFoyer,
                        );
                    }
                    // TODO: brancher l'affichage de l'aide contextuelle.
                    Commande::ListeCommandesActives => {}
                    Commande::OuvrirFoyer => {
                        self.etat_tui.prompt = String::from("ouvre");
                        self.etat_tui.mode_saisie = ModeSaisie::Insertion;
                        self.etat_tui.validation_buffer_saisie =
                            ValidationBufferSaisie::OuvertureFoyer;
                    }
                    Commande::Quitter => {
                        self.connecteur_vers_coeur
                            .envoyer_message_tui_coeur(MessageTuiCoeur::Quitter);
                        return Ok(false);
                    }
                }
                self.etat_tui.ajouter_message_commande(libelle);
            }
        }

        Ok(true)
    }

    /// Traite une touche en mode [`ModeSaisie::Insertion`] : accumulation dans le buffer.
    ///
    /// Seules les frappes sans modificateur (`KeyModifiers::NONE`) sont traitées —
    /// un `Ctrl+Entrée` n'est pas une validation, un `Ctrl+C` n'est pas un caractère.
    ///
    /// À la validation (Entrée), consulte [`EtatTui::validation_buffer_saisie`] pour
    /// décider quel message envoyer au cœur, puis remet l'écran à [`Ecran::Normal`],
    /// le mode à [`ModeSaisie::Normal`] et [`EtatTui::validation_buffer_saisie`] à
    /// [`ValidationBufferSaisie::Rien`]. `saisie_mode_insertion` n'a jamais à
    /// connaître l'écran courant.
    /// À l'annulation (Échap), vide le buffer et envoie [`MessageTuiCoeur::Annulation`].
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
                        if let Ok(index) = index_result {
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
        match Self::lire_touche()? {
            Some((KeyCode::Enter, KeyModifiers::NONE)) => {
                if let Ecran::AffichageSeed { seed: _, rappel } = &mut self.etat_tui.ecran {
                    if *rappel {
                        self.etat_tui.ecran = Ecran::Normal;
                        self.etat_tui.mode_saisie = ModeSaisie::Normal;
                        self.connecteur_vers_coeur
                            .envoyer_message_tui_coeur(MessageTuiCoeur::SeedBienRecue);
                    } else {
                        *rappel = true;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}
