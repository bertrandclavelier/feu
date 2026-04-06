// DEPRECATED — feu-cli n'est plus maintenu.
// Conservé temporairement pour tests avant suppression définitive.
//
// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! Point d'entrée du binaire `feu-cli`.
//!
//! Lance le REPL interactif via [`InterfaceCli::lancer`].

mod interface_cli;
use interface_cli::InterfaceCli;

fn main() {
    InterfaceCli::lancer();
}
