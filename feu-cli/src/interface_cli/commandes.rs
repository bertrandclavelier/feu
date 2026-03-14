// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! Traitement des commandes du REPL de Feu.
//!
//! Reçoit les commandes saisies par l'utilisateur, les dispatche
//! vers les méthodes correspondantes de [`Feu`] et signale à la boucle
//! REPL si elle doit continuer ou se terminer.
//!
//! Les commandes inconnues sont signalées à l'utilisateur sans interrompre
//! la session.

use feu_core::{Feu, MAX_FOYERS};

use super::SuiteCommandes;

/// Dispatche une commande vers [`Feu`].
///
/// Retourne [`SuiteCommandes::Continuer`] pour poursuivre la session,
/// [`SuiteCommandes::Quitter`] pour la terminer.
pub(super) fn traite_commande(
    feu: &mut Feu<super::InterfaceCli>,
    commande: &str,
    arguments: &str,
) -> SuiteCommandes {
    match (commande, arguments) {
        ("allume", _) => {
            if let Err(e) = feu.commande_allumage_noeud() {
                eprintln!("Erreur d'allumage du nœud : {}", e)
            }
            SuiteCommandes::Continuer
        }
        ("eteins", _) => {
            if let Err(e) = feu.commande_extinction_noeud() {
                eprintln!("Erreur d'extinction du nœud : {}", e)
            }
            SuiteCommandes::Continuer
        }

        ("ferme", _) => {
            match arguments.parse::<usize>() {
                Ok(i) => {
                    if let Err(e) = &feu.commande_fermeture_foyer_index(i) {
                        eprintln!("Impossible de fermer le foyer {} : {}", i, e);
                    }
                }
                Err(_) => eprintln!("Argument invalide : {}", arguments),
            }
            SuiteCommandes::Continuer
        }
        ("initialise", _) => {
            if let Err(e) = feu.commande_initialise_noeud_vierge() {
                eprintln!("Erreur d'initialisation du nœud : {}", e)
            }
            SuiteCommandes::Continuer
        }
        ("liste", "-C") => {
            liste_commandes();
            SuiteCommandes::Continuer
        }
        ("liste", "-F") => {
            affiche_liste_foyers(&feu.commande_liste_foyers());
            SuiteCommandes::Continuer
        }
        ("ouvre", _) => {
            match arguments.parse::<usize>() {
                Ok(i) => {
                    if let Err(e) = feu.commande_ouverture_foyer(i) {
                        eprintln!("Impossible d'ouvrir le foyer {} : {}", i, e);
                    }
                }
                Err(_) => eprintln!("Argument invalide : {}", arguments),
            }
            SuiteCommandes::Continuer
        }
        ("quitte", _) => {
            if feu.commande_quitter_feu() {
                SuiteCommandes::Quitter
            } else {
                eprintln!("Le noeud doit être éteint avant de quitter");
                SuiteCommandes::Continuer
            }
        }
        ("version", _) => {
            feu.commande_affiche_version();
            SuiteCommandes::Continuer
        }
        (_, _) => {
            println!("Commande inconnue.");
            SuiteCommandes::Continuer
        }
    }
}

/// Fonction qui affiche la liste des commandes disponibles
fn liste_commandes() {
    println!("Commandes disponibles :");
    println!("{:<12} | allume le noeud", "allume");
    println!("{:<12} | éteint le noeud", "eteins");
    println!("{:<12} | ferme le foyer d'index `i`", "ferme `i`");
    println!("{:<12} | initialise un nœud vierge", "initialise");
    println!("{:<12} | liste les commandes disponibles", "liste -C");
    println!("{:<12} | liste les foyers et leur état", "liste -F");
    println!("{:<12} | ouvre le foyer d'index `i`", "ouvre `i`");
    println!("{:<12} | quitte Feu", "quitte");
    println!("{:<12} | affiche la version de `Feu`", "version");
}

/// Convertit un booléen d'état en libellé lisible.
fn conversion_bool_statut(b: bool) -> String {
    if b {
        String::from("Allumé")
    } else {
        String::from("Éteint")
    }
}

/// Affiche le tableau des foyers avec leur index, état et adresse `.onion`.
fn affiche_liste_foyers(t: &[(bool, String); MAX_FOYERS]) {
    println!("Liste des foyers et leur état (allumé/éteint)");
    for i in 0..MAX_FOYERS {
        println!(
            "{:<5} | {:<10} | {}",
            i,
            conversion_bool_statut(t[i].0),
            t[i].1
        );
    }
}
