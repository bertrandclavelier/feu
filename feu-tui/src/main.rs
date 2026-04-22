// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Point d'entrée du binaire `feu-tui`.
//!
//! Initialise le terminal via [`ratatui::run`], instancie [`tui::Tui`]
//! et délègue l'intégralité de la boucle événementielle à [`tui::Tui::lancer`].
//! Toute la logique réside dans [`tui`] et [`rendu`] — ce fichier ne fait
//! qu'amorcer l'exécution.

use std::io::Error;
use std::sync::mpsc::channel;
use tui::Tui;

use crate::connecteurs::{
    ConnecteurVersCoeur, ConnecteurVersTui, MessageCoeurTui, MessageTuiCoeur,
};

mod connecteurs;
mod rendu;
mod tui;

fn main() -> Result<(), Error> {
    // Canal Tui -> Coeur
    let (emetteur_tui_coeur, recepteur_tui_coeur) = channel::<MessageTuiCoeur>();

    // Canal Coeur -> Tui
    let (emetteur_coeur_tui, recepteur_coeur_tui) = channel::<MessageCoeurTui>();

    // Connecteurs
    let connecteur_vers_coeur = ConnecteurVersCoeur::new(emetteur_tui_coeur, recepteur_coeur_tui);
    let connecteur_vers_tui = ConnecteurVersTui::new(emetteur_coeur_tui, recepteur_tui_coeur);

    let poignee_thread_coeur = connecteur_vers_tui.lancer_thread_coeur();

    let mut tui = Tui::new(connecteur_vers_coeur);
    ratatui::run(|terminal| tui.lancer(terminal))?;

    // Empêcher que le thread coeur soit tué avaznt d'avoir fini
    let _ = poignee_thread_coeur.join();

    Ok(())
}
