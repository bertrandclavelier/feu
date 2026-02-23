//! Implémente [`InterfaceFeuCore`] pour la ligne de commande —
//! condition nécessaire à la création d'une instance de [`Feu`].
//! Assure l'affichage vers stdout, la remontée des erreurs vers stderr,
//! la collecte des saisies utilisateur depuis stdin et la saisie
//! sécurisée des mots de passe avec masquage de la saisie.
//!
//! Les erreurs d'interface sont gérées localement — chaque méthode
//! traite ses propres échecs et retourne une valeur de repli si
//! nécessaire. Aucune erreur d'interface ne remonte vers `feu-core`.
//! Ce choix maintient une séparation nette des responsabilités :
//! `feu-core` gère la logique du protocole, `feu-cli` gère
//! l'interaction avec l'utilisateur — chacun souverain dans son domaine.
//! Une interface CLI étant simple par nature, le nombre d'erreurs
//! possibles est limité et se traite efficacement au cas par cas.

use feu_core::InterfaceFeuCore;
use rpassword::read_password;
use std::io;
use std::io::BufRead;

/// Interface CLI de Feu.
pub(crate) struct InterfaceCli {
    /// Niveau de verbosité de l'affichage.
    mode_affichage: ModeAffichage,
}

enum ModeAffichage {
    Minimal,
    Normal,
    Maximal,
}

impl InterfaceCli {
    /// Crée une nouvelle InterfaceCLi avec un mode d'affichage normal.
    pub(crate) fn new() -> Self {
        Self {
            mode_affichage: ModeAffichage::Normal,
        }
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
