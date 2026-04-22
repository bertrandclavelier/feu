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
//! Le rendu est entièrement délégué à [`crate::rendu`].
//!
//! La boucle tourne en continu via `poll(50ms)` : elle ne bloque jamais plus de
//! 50 ms, ce qui permet de consulter le canal cœur→TUI à chaque itération via
//! `try_recv`. Les événements clavier et les messages du cœur sont traités de
//! façon désynchronisée — la TUI ne attend aucune réponse du cœur.
//!
//! La communication avec le thread cœur passe par [`crate::connecteurs::ConnecteurVersCoeur`],
//! dont [`Tui`] est propriétaire.

use std::{sync::mpsc::TryRecvError, time::Duration};

use crate::{MessageCoeurTui, MessageTuiCoeur, connecteurs::ConnecteurVersCoeur, rendu};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{DefaultTerminal, style::Color};

pub(crate) const COULEUR_ACCENT: Color = Color::Rgb(255, 90, 31);

/// Détermine quelle famille visuelle est rendue à chaque frame.
/// [`Ecran::Normal`] correspond au carré à angles droits ; les variantes
/// à venir déclenchent l'écran noyau à cadre arrondi orange.
pub(crate) enum Ecran {
    /// Carré centré à angles droits — état par défaut de l'interface.
    Normal,
}

/// État courant de l'interface entre deux frames.
pub(crate) struct EtatTui {
    /// Écran actuellement affiché — détermine la fonction de rendu appelée.
    pub(crate) ecran: Ecran,
    /// Dernier message d'erreur reçu du thread cœur. `None` si aucune erreur.
    /// Affiché à chaque frame tant qu'il est `Some` — non effacé automatiquement.
    pub(crate) message_erreur: Option<String>,
}

impl EtatTui {
    /// Crée un [`EtatTui`] en état initial : écran normal.
    fn new() -> Self {
        Self {
            ecran: Ecran::Normal,
            message_erreur: None,
        }
    }
}

/// Orchestre la boucle principale et le rendu.
///
/// Possède l'état de l'interface ([`EtatTui`]) et le connecteur vers le
/// thread cœur ([`crate::connecteurs::ConnecteurVersCoeur`]). Coordonne
/// les deux opérations répétées à chaque frame : dessin via
/// [`crate::rendu::dessiner`], puis lecture de l'événement clavier suivant.
pub(super) struct Tui {
    etat_tui: EtatTui,
    connecteur_vers_coeur: ConnecteurVersCoeur,
}

impl Tui {
    /// Crée une instance de [`Tui`] avec l'état initial.
    pub(super) fn new(connecteur_vers_coeur: ConnecteurVersCoeur) -> Self {
        Self {
            etat_tui: EtatTui::new(),
            connecteur_vers_coeur,
        }
    }

    /// Boucle principale : dessine, traite les événements clavier, lit le canal cœur.
    ///
    /// Chaque itération :
    /// 1. Dessin du frame courant.
    /// 2. `poll(50ms)` — si un événement clavier est disponible, dispatch selon
    ///    l'écran actif : `a` envoie [`MessageTuiCoeur::AllumerNoeud`], `q` envoie
    ///    [`MessageTuiCoeur::Quitter`] et sort.
    /// 3. `try_recv` non bloquant sur le canal cœur→TUI : met à jour
    ///    [`EtatTui::message_erreur`] sur [`MessageCoeurTui::AffichageErreur`],
    ///    ou signale la déconnexion du thread cœur.
    pub(super) fn lancer(&mut self, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
        loop {
            terminal.draw(|frame| rendu::dessiner(frame, &self.etat_tui))?;
            if crossterm::event::poll(Duration::from_millis(50))? {
                match crossterm::event::read()? {
                    Event::Key(KeyEvent {
                        code: KeyCode::Char('a'),
                        kind: KeyEventKind::Press,
                        ..
                    }) => {
                        self.connecteur_vers_coeur
                            .envoyer_message_tui_coeur(MessageTuiCoeur::AllumerNoeud);
                    }

                    Event::Key(KeyEvent {
                        code: KeyCode::Char('q'),
                        kind: KeyEventKind::Press,
                        ..
                    }) => {
                        self.connecteur_vers_coeur
                            .envoyer_message_tui_coeur(crate::MessageTuiCoeur::Quitter);
                        break;
                    }

                    _ => {}
                }
            }

            match self.connecteur_vers_coeur.recepteur().try_recv() {
                Err(TryRecvError::Empty) => {}

                Err(TryRecvError::Disconnected) => {
                    self.etat_tui.message_erreur = Some(String::from("Thread déconnecté"))
                }

                Ok(message) => match message {
                    MessageCoeurTui::AffichageErreur(m) => self.etat_tui.message_erreur = Some(m),
                },
            }
        }
        Ok(())
    }
}
