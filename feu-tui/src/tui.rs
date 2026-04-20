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
//! [`FeuApplication`] est instancié ici et alimenté à mesure que l'interface
//! progresse dans son cycle de vie.

use crate::rendu;
use feu_application::{FeuApplication, InterfaceFeuApplication};
use ratatui::{DefaultTerminal, style::Color};
use secrecy::SecretString;

pub(crate) const COULEUR_ACCENT: Color = Color::Rgb(255, 90, 31);

struct RecepteurApplication();

impl InterfaceFeuApplication for RecepteurApplication {
    fn demander_mdp(&self) -> Option<SecretString> {
        None
    }

    #[allow(unused_variables)]
    fn recevoir_seed(&mut self, mots: &[&str]) {
        todo!();
    }

    fn confirmer_enregistrement_seed(&self) -> bool {
        true
    }
}

/// Écran actif de l'interface.
///
/// Détermine quelle famille visuelle est rendue à chaque frame.
/// [`Ecran::Normal`] correspond au carré à angles droits ; les variantes
/// à venir déclenchent l'écran noyau à cadre arrondi orange.
pub(crate) enum Ecran {
    /// Carré centré à angles droits — état par défaut de l'interface.
    Normal,
}

/// État courant de l'interface entre deux frames.
pub(crate) struct EtatTui {
    /// Indique si la boucle principale doit se terminer à la prochaine itération.
    quitter: bool,
    /// Écran actuellement affiché — détermine la fonction de rendu appelée.
    pub(crate) ecran: Ecran,
}

impl EtatTui {
    /// Crée un [`EtatTui`] en état initial : écran normal, sortie non demandée.
    fn new() -> Self {
        Self {
            quitter: false,
            ecran: Ecran::Normal,
        }
    }
}

/// Orchestre la boucle principale et le rendu.
///
/// Possède l'état de l'interface ([`EtatTui`]) et l'instance applicative
/// ([`FeuApplication`]). Coordonne les deux opérations répétées à chaque
/// frame : dessin via [`crate::rendu::dessiner`], puis lecture de l'événement
/// clavier suivant.
pub(super) struct Tui {
    etat_tui: EtatTui,
    _feu_application: FeuApplication<RecepteurApplication>,
}

impl Tui {
    /// Crée une instance de [`Tui`] avec l'état initial.
    pub(super) fn new() -> Self {
        Self {
            etat_tui: EtatTui::new(),
            _feu_application: FeuApplication::new(RecepteurApplication()),
        }
    }

    /// Boucle principale : dessine, attend un événement clavier, met à jour l'état.
    ///
    /// Tourne jusqu'à ce que [`EtatTui::quitter`] soit `true`. Le dessin précède
    /// systématiquement l'attente — le terminal affiche toujours un état cohérent
    /// avant de bloquer.
    pub(super) fn lancer(&mut self, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
        loop {
            terminal.draw(|frame| rendu::dessiner(frame, &self.etat_tui))?;
            if crossterm::event::read()?.is_key_press() {
                self.etat_tui.quitter = true;
            }

            if self.etat_tui.quitter {
                break;
            }
        }
        Ok(())
    }
}
