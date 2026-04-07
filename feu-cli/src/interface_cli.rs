// DEPRECATED — feu-cli n'est plus maintenu.
// Conservé temporairement pour tests avant suppression définitive.
//
// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Interface CLI de FeuNoyau — point d'entrée interactif et canal de communication
//! entre l'utilisateur et [`feu_noyau`].
//!
//! **Interface temporaire de test.** Ce module n'est pas destiné à rester.
//! Il sert à exercer les primitives du noyau en cours de développement.
//! L'implémentation de [`InterfaceFeuNoyau`] est délibérément minimale
//! (affichage debug, saisie stdin brute).
//!
//! Ce module remplit deux rôles distincts :
//!
//! - [`InterfaceCli`] implémente [`InterfaceFeuNoyau`], condition nécessaire
//!   à la création d'une instance de [`FeuNoyau`]. Elle assure l'affichage vers
//!   stdout, la remontée des erreurs vers stderr, la collecte des saisies
//!   depuis stdin et la saisie sécurisée des mots de passe via [`rpassword`].
//!
//! - [`InterfaceCli::lancer`] initialise le REPL interactif : affichage du
//!   logo, création de l'instance [`FeuNoyau`], puis boucle de lecture des
//!   commandes via [`rustyline`] jusqu'à la commande `quitter` ou un signal
//!   de fin (Ctrl+C, Ctrl+D).
//!
//! Les erreurs d'interface sont gérées localement — chaque méthode traite
//! ses propres échecs et retourne une valeur de repli si nécessaire. Aucune
//! erreur d'interface ne remonte vers [`feu_noyau`], dont la responsabilité
//! se limite à la logique du protocole. Ce choix est assumé : une interface
//! CLI étant simple par nature, les points de défaillance sont peu nombreux
//! et connus — chacun se traite efficacement au cas par cas.

mod commandes;
use colored::Colorize;
use feu_application::{FeuApplication, InterfaceFeuApplication};
use rpassword::read_password;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::io;
use std::io::BufRead;
use std::process;

/// Canal d'entrée/sortie de FeuNoyau en mode CLI.
#[derive(Clone)]
pub(super) struct InterfaceCli {}

/// Signal retourné par chaque commande à la boucle REPL.
enum SuiteCommandes {
    /// La session continue — lire la prochaine commande.
    Continuer,
    /// La session se termine — quitter la boucle REPL.
    Quitter,
}

impl InterfaceCli {
    /// Point d'entrée du REPL de FeuNoyau.
    ///
    /// Affiche le logo et initialise l'instance [`FeuNoyau`] avec une [`InterfaceCli`]
    /// en mode d'affichage normal, puis ouvre la boucle interactive via
    /// [`rustyline`].
    ///
    /// Chaque itération lit une commande sur l'invite `> `, l'enregistre dans
    /// l'historique de session et la dispatche vers [`FeuNoyau`]. La boucle se termine
    /// sur la commande `quitter` ou sur un signal de fin (Ctrl+C, Ctrl+D).
    ///
    /// # Erreurs
    ///
    /// L'échec d'initialisation de [`rustyline`] est irrécupérable —
    /// le programme se termine avec le code de sortie `1` et un message sur stderr.
    /// Les erreurs de saisie en cours de session sont signalées sur stderr et
    /// n'interrompent pas la boucle.
    pub(super) fn lancer() {
        println!(
            "{}",
            r#"

             ███████╗███████╗██╗   ██╗
             ██╔════╝██╔════╝██║   ██║
             █████╗  █████╗  ██║   ██║
             ██╔══╝  ██╔══╝  ██║   ██║
             ██║     ███████╗╚██████╔╝
             ╚═╝     ╚══════╝ ╚═════╝
        
                Copyright (C) 2026
        Bertrand CLAVELIER — Licence GPL v3.0

"#
            .truecolor(255, 90, 31)
        );

        let interface_cli = Self {};
        let mut feu = FeuApplication::new(interface_cli).unwrap();

        let mut rustyline = match DefaultEditor::new() {
            Ok(valeur) => valeur,
            Err(e) => {
                eprintln!("Erreur d'initialisation de rustyline : {e}");
                process::exit(1);
            }
        };

        let invite = format!("{} ", "›".truecolor(255, 90, 31).bold());

        loop {
            match rustyline.readline(&invite) {
                Ok(ligne) => {
                    let ligne = ligne.trim().to_string();

                    if ligne.is_empty() {
                        continue;
                    }

                    if let Err(e) = rustyline.add_history_entry(&ligne) {
                        eprintln!("Commande annulée. Erreur d'ajout à l'historique {e}");
                        continue;
                    }

                    let mut parties = ligne.splitn(3, ' ');
                    let commande = parties.next().unwrap_or("");
                    let argument1 = parties.next().unwrap_or("");
                    let argument2 = parties.next().unwrap_or("").trim();

                    match commandes::traite_commande(&mut feu, commande, argument1, argument2) {
                        SuiteCommandes::Continuer => continue,
                        SuiteCommandes::Quitter => break,
                    }
                }

                Err(ReadlineError::Interrupted) => break, // Ctrl+C
                Err(ReadlineError::Eof) => break,         // Ctrl+D
                Err(e) => {
                    eprintln!("Commande annulée. Erreur de saisie rustyline : {e}");
                    continue;
                }
            }
        }

        println!("Au revoir !");
    }
}

impl InterfaceFeuApplication for InterfaceCli {
    fn afficher(&self, message: &str) {
        println!("{message}");
    }

    fn demander(&self, question: &str) -> String {
        println!("{question}");
        let stdin = io::stdin();
        let mut entree = String::new();

        match stdin.lock().read_line(&mut entree) {
            Ok(_) => entree.trim().to_string(),
            Err(e) => {
                eprintln!("[FEU-CLI] erreur d'entrée utilisateur : {}", e);
                String::new()
            }
        }
    }

    fn demander_mdp(&self, question: &str) -> String {
        println!("{question}");
        match read_password() {
            Ok(mdp) => mdp,
            Err(e) => {
                eprintln!(
                    "[FEU-CLI] erreur d'entrée du mot de passe par l'utilisateur : {}",
                    e
                );
                String::new()
            }
        }
    }
}
