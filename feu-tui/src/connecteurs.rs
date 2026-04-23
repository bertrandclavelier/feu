// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Canaux de communication entre le thread TUI et le thread cœur.
//!
//! Ce module définit le protocole de messages ([`MessageTuiCoeur`],
//! [`MessageCoeurTui`]) et les deux connecteurs qui en sont les extrémités :
//!
//! - [`ConnecteurVersTui`] vit dans le thread cœur. Il possède [`FeuApplication`]
//!   et la boucle de dispatch des commandes reçues depuis la TUI. Il implémente
//!   [`feu_application::InterfaceFeuApplication`] pour les interactions bloquantes
//!   (saisie du mot de passe, affichage de la seed).
//! - [`ConnecteurVersCoeur`] vit dans le thread TUI. Il expose les méthodes de
//!   haut niveau à la boucle ratatui : envoyer une commande au thread cœur,
//!   recevoir un événement cœur de façon non bloquante.
//!
//! Aucun état n'est partagé entre les deux threads — toute communication
//! transite par ces canaux typés.

use feu_application::{FeuApplication, InterfaceFeuApplication};
use secrecy::SecretString;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::{JoinHandle, spawn};

/// Messages envoyés du thread cœur vers le thread TUI.
pub(super) enum MessageCoeurTui {
    /// Une commande a échoué — la TUI doit afficher le message d'erreur.
    AffichageErreur(String),

    /// Le cœur a besoin du mot de passe — la TUI doit basculer sur l'écran de saisie.
    AttenteMdp,
}

/// Messages envoyés du thread TUI vers le thread cœur.
pub(super) enum MessageTuiCoeur {
    /// Lance l'initialisation ou l'allumage du nœud via [`FeuApplication`].
    AllumageNoeud,

    /// Mot de passe saisi par l'utilisateur, en réponse à [`MessageCoeurTui::AttenteMdp`].
    EnvoieMdp(SecretString),

    /// L'utilisateur a annulé la saisie en cours (Échap). Débloque le thread cœur en attente.
    Annulation,

    /// Demande d'arrêt propre : le thread cœur doit terminer sa boucle.
    Quitter,
}

/// Connecteur du thread cœur — reçoit les commandes de la TUI et pilote [`FeuApplication`].
///
/// Possède les deux extrémités du canal TUI↔cœur et l'instance de
/// [`FeuApplication`]. La boucle de dispatch vit dans [`lancer_thread_coeur`](Self::lancer_thread_coeur).
///
/// Implémente [`InterfaceFeuApplication`] : chaque méthode envoie un
/// [`MessageCoeurTui`] à la TUI et attend la réponse correspondante sur le
/// canal entrant. Cette implémentation est utilisée lors des interactions
/// bloquantes (saisie du mot de passe, affichage de la seed).
pub(super) struct ConnecteurVersTui {
    emetteur: Sender<MessageCoeurTui>,
    recepteur: Receiver<MessageTuiCoeur>,
}

impl ConnecteurVersTui {
    /// Crée un [`ConnecteurVersTui`] à partir des extrémités de canaux fournies par `main`.
    pub(super) fn new(
        emetteur: Sender<MessageCoeurTui>,
        recepteur: Receiver<MessageTuiCoeur>,
    ) -> Self {
        Self {
            emetteur,
            recepteur,
        }
    }

    /// Envoie un message au thread TUI.
    ///
    /// L'erreur est ignorée volontairement : si le canal est déjà fermé,
    /// le thread TUI est déjà terminé — l'objectif est atteint.
    pub(super) fn envoyer_message_coeur_tui(&self, message_coeur_tui: MessageCoeurTui) {
        let _ = self.emetteur.send(message_coeur_tui);
    }

    /// Spawne le thread cœur et retourne sa poignée.
    ///
    /// Crée [`FeuApplication`], consomme le connecteur (`self`) et transfère
    /// la propriété de l'ensemble au thread. La boucle interne dispatche chaque
    /// [`MessageTuiCoeur`] vers la commande applicative correspondante et se
    /// termine proprement sur [`MessageTuiCoeur::Quitter`] ou fermeture du canal.
    ///
    /// La poignée retournée permet à `main` d'attendre la fin propre du thread
    /// via `.join()` — aucun thread orphelin.
    pub(super) fn lancer_thread_coeur(mut self) -> JoinHandle<()> {
        let mut feu_application = FeuApplication::new();
        spawn(move || {
            loop {
                match self.recepteur.recv() {
                    Ok(MessageTuiCoeur::AllumageNoeud) => {
                        if let Err(e) = feu_application.commande_allumage_noeud(&mut self, None) {
                            self.envoyer_message_coeur_tui(MessageCoeurTui::AffichageErreur(
                                e.to_string(),
                            ));
                        }
                    }
                    Ok(MessageTuiCoeur::Quitter) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        })
    }
}

impl InterfaceFeuApplication for ConnecteurVersTui {
    fn demander_mdp(&self) -> Option<SecretString> {
        self.envoyer_message_coeur_tui(MessageCoeurTui::AttenteMdp);

        loop {
            match self.recepteur.recv() {
                Ok(MessageTuiCoeur::EnvoieMdp(mdp)) => {
                    return Some(mdp);
                }
                Ok(MessageTuiCoeur::Annulation) => {
                    return None;
                }
                _ => {}
            }
        }
    }

    fn recevoir_seed(&mut self, mots: &[&str]) {
        let _ = mots;
        todo!();
    }

    fn confirmer_enregistrement_seed(&self) -> bool {
        true
    }
}

/// Connecteur du thread TUI — parle vers le cœur.
///
/// Expose les commandes de haut niveau à la boucle ratatui.
/// Permet également de recevoir les événements remontés par le cœur
/// via un `try_recv` non bloquant à chaque frame.
pub(super) struct ConnecteurVersCoeur {
    emetteur: Sender<MessageTuiCoeur>,
    recepteur: Receiver<MessageCoeurTui>,
}

impl ConnecteurVersCoeur {
    /// Crée un [`ConnecteurVersCoeur`] à partir des extrémités de canaux fournies par `main`.
    pub(super) fn new(
        emetteur: Sender<MessageTuiCoeur>,
        recepteur: Receiver<MessageCoeurTui>,
    ) -> Self {
        Self {
            emetteur,
            recepteur,
        }
    }

    /// Retourne une référence au récepteur cœur→TUI pour lecture non bloquante.
    ///
    /// Utilisé par la boucle ratatui via [`try_recv`](Receiver::try_recv) à chaque frame.
    pub(super) fn recepteur(&self) -> &Receiver<MessageCoeurTui> {
        &self.recepteur
    }

    /// Envoie un message au thread cœur.
    ///
    /// L'erreur est ignorée volontairement : si le canal est déjà fermé,
    /// le thread cœur est déjà terminé — l'objectif est atteint.
    pub(super) fn envoyer_message_tui_coeur(&self, message_tui_coeur: MessageTuiCoeur) {
        let _ = self.emetteur.send(message_tui_coeur);
    }
}
