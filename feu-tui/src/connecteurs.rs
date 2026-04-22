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
//! [`ConnecteurVersTui`] vit dans le thread cœur et implémente
//! [`feu_application::InterfaceFeuApplication`] ; [`ConnecteurVersCoeur`]
//! vit dans le thread TUI et expose les commandes de haut niveau à la boucle
//! ratatui.
//!
//! Aucun état n'est partagé entre les deux threads — toute communication
//! transite par ces canaux typés.

use feu_application::InterfaceFeuApplication;
use secrecy::SecretString;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::{JoinHandle, spawn};

/// Messages envoyés du thread cœur vers le thread TUI.
pub(super) enum MessageCoeurTui {
    /// Le cœur a besoin du mot de passe — la TUI doit basculer en saisie.
    DemandeMdp,
}

/// Messages envoyés du thread TUI vers le thread cœur.
pub(super) enum MessageTuiCoeur {
    /// Demande d'arrêt propre : le thread cœur doit terminer sa boucle.
    Arreter,
}

/// Connecteur du thread cœur — parle vers la TUI.
///
/// Implémente [`InterfaceFeuApplication`] de façon synchrone : chaque
/// méthode envoie un [`MessageCoeurTui`] à la TUI et attend la réponse
/// correspondante sur le canal entrant.
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

    /// Spawne le thread cœur et retourne sa poignée.
    ///
    /// Consomme le connecteur (`self`) : la propriété des canaux est transférée
    /// au thread. La poignée retournée permet à `main` d'attendre la fin propre
    /// du thread via `.join()`.
    pub(super) fn lancer_thread_coeur(self) -> JoinHandle<()> {
        spawn(move || {
            loop {
                match self.recepteur.recv() {
                    Ok(MessageTuiCoeur::Arreter) => break,
                    Err(_) => break,
                }
            }
        })
    }
}

impl InterfaceFeuApplication for ConnecteurVersTui {
    fn demander_mdp(&self) -> Option<SecretString> {
        None
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

    /// Envoie le signal d'arrêt au thread cœur.
    ///
    /// L'erreur est ignorée volontairement : si le canal est déjà fermé,
    /// le thread cœur est déjà terminé — l'objectif est atteint.
    pub(super) fn arreter_thread_coeur(&self) {
        let _ = self.emetteur.send(MessageTuiCoeur::Arreter);
    }
}
