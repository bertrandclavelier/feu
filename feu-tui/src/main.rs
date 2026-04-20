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
use tui::Tui;

mod rendu;
mod tui;

fn main() -> Result<(), Error> {
    let mut tui = Tui::new();
    ratatui::run(|terminal| tui.lancer(terminal))?;
    Ok(())
}
