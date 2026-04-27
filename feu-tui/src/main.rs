// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Point d'entrée du binaire `feu-tui`.
//!
//! Monte l'architecture à deux threads :
//! - le thread principal exécute la boucle TUI via [`tui::Tui::lancer`] ;
//! - le thread cœur est spawné par [`connecteurs::ConnecteurVersTui::lancer_thread_coeur`]
//!   et pilote [`feu_application::FeuApplication`].
//!
//! Les deux threads communiquent via deux canaux `mpsc` typés, créés ici et
//! distribués aux connecteurs. Ce fichier ne fait qu'amorcer l'exécution —
//! toute la logique réside dans [`connecteurs`] et [`tui`], ce dernier
//! orchestrant ses propres sous-modules de rendu et de commandes.
//!
//! En cas de panique du thread cœur, le processus sort avec le code 1.
//! Le terminal est restauré automatiquement par le guard de [`ratatui::run`]
//! même si la TUI panique avant ce point.

mod connecteurs;
mod tui;

use std::io::Error;
use std::sync::mpsc::channel;

use crate::connecteurs::{
    ConnecteurVersCoeur, ConnecteurVersTui, MessageCoeurTui, MessageTuiCoeur,
};
use crate::tui::Tui;

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

    // join() retourne Err si le thread cœur a paniqué.
    // Dans ce cas on sort en erreur plutôt qu'en succès silencieux.
    if poignee_thread_coeur.join().is_err() {
        std::process::exit(1);
    }

    Ok(())
}
