//! Interface CLI de Feu — point d'entrée interactif et canal de communication
//! entre l'utilisateur et [`feu_core`].
//!
//! Ce module remplit deux rôles distincts :
//!
//! - [`InterfaceCli`] implémente [`InterfaceFeuCore`], condition nécessaire
//!   à la création d'une instance de [`Feu`]. Elle assure l'affichage vers
//!   stdout, la remontée des erreurs vers stderr, la collecte des saisies
//!   depuis stdin et la saisie sécurisée des mots de passe via [`rpassword`].
//!
//! - [`InterfaceCli::lancer`] initialise le REPL interactif : affichage du
//!   logo, création de l'instance [`Feu`], puis boucle de lecture des
//!   commandes via [`rustyline`] jusqu'à la commande `quitter` ou un signal
//!   de fin (Ctrl+C, Ctrl+D).
//!
//! Les erreurs d'interface sont gérées localement — chaque méthode traite
//! ses propres échecs et retourne une valeur de repli si nécessaire. Aucune
//! erreur d'interface ne remonte vers [`feu_core`], dont la responsabilité
//! se limite à la logique du protocole. Ce choix est assumé : une interface
//! CLI étant simple par nature, les points de défaillance sont peu nombreux
//! et connus — chacun se traite efficacement au cas par cas.

mod commandes;
use colored::Colorize;
use feu_core::Feu;
use feu_core::InterfaceFeuCore;
use rpassword::read_password;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::io;
use std::io::BufRead;
use std::process;

/// Canal d'entrée/sortie de Feu en mode CLI.
pub(super) struct InterfaceCli {
    /// Niveau de verbosité de l'affichage.
    mode_affichage: ModeAffichage,
}

enum ModeAffichage {
    Minimal,
    Normal,
    Maximal,
}

enum SuiteCommandes {
    Continuer,
    Quitter,
}

impl InterfaceCli {
    /// Point d'entrée du REPL de Feu.
    ///
    /// Affiche le logo et initialise l'instance [`Feu`] avec une [`InterfaceCli`]
    /// en mode d'affichage normal, puis ouvre la boucle interactive via
    /// [`rustyline`].
    ///
    /// Chaque itération lit une commande sur l'invite `> `, l'enregistre dans
    /// l'historique de session et la dispatche vers [`Feu`]. La boucle se termine
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
"#
            .truecolor(255, 90, 31)
        );

        let interface_cli = Self {
            mode_affichage: ModeAffichage::Normal,
        };
        let mut feu = Feu::new(interface_cli);

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

                    let mut parties = ligne.splitn(2, ' ');
                    let commande = parties.next().unwrap_or("");
                    let arguments = parties.next().unwrap_or("").trim();

                    match commandes::traite_commande(&mut feu, commande, arguments) {
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

impl InterfaceFeuCore for InterfaceCli {
    fn afficher_min(&self, message: &str) {
        println!("{message}");
    }

    fn afficher(&self, message: &str) {
        match self.mode_affichage {
            ModeAffichage::Normal | ModeAffichage::Maximal => {
                println!("{message}");
            }
            _ => {}
        }
    }

    fn afficher_max(&self, message: &str) {
        if let ModeAffichage::Maximal = self.mode_affichage {
            println!("{message}");
        }
    }

    fn afficher_erreur(&self, message: &str) {
        eprintln!("{message}");
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
