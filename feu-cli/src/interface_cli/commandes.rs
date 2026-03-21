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
use data_encoding::HEXLOWER;

/// Dispatche une commande vers [`Feu`].
///
/// Retourne [`SuiteCommandes::Continuer`] pour poursuivre la session,
/// [`SuiteCommandes::Quitter`] pour la terminer.
pub(super) fn traite_commande(
    feu: &mut Feu<super::InterfaceCli>,
    commande: &str,
    argument1: &str,
    argument2: &str,
) -> SuiteCommandes {
    match (commande, argument1, argument2) {
        ("allume", _, _) => {
            if let Err(e) = feu.commande_allumage_noeud() {
                eprintln!("Erreur d'allumage du nœud => {}", e)
            }
            SuiteCommandes::Continuer
        }
        ("change", "mdp", _) => {
            if let Err(e) = feu.commande_changement_mdp() {
                eprintln!("Erreur de changement de mdp => {}", e)
            }
            SuiteCommandes::Continuer
        }
        // Commande de test — foyer 0, classeur 0, chemin absolu obligatoire
        ("depot", _, _) => {
            match std::fs::File::open(argument1) {
                Err(e) => eprintln!("Erreur fichier => {}", e),
                Ok(fichier) => match feu.commande_depot_donnees(0, 0, fichier) {
                    Err(e) => {
                        eprintln!("Erreur dépôt => {}", e);
                    }
                    Ok(hash) => {
                        println!(
                            "Voici le hash du fichier déposé : {}",
                            HEXLOWER.encode(&hash)
                        );
                    }
                },
            }
            SuiteCommandes::Continuer
        }
        ("eteins", _, _) => {
            if let Err(e) = feu.commande_extinction_noeud() {
                eprintln!("Erreur d'extinction du nœud => {}", e)
            }
            SuiteCommandes::Continuer
        }

        ("ferme", _, _) => {
            match argument1.parse::<usize>() {
                Ok(i) => {
                    if let Err(e) = &feu.commande_fermeture_foyer_index(i) {
                        eprintln!("Impossible de fermer le foyer {} => {}", i, e);
                    }
                }
                Err(_) => eprintln!("Argument invalide => {}", argument1),
            }
            SuiteCommandes::Continuer
        }
        ("initialise", _, _) => {
            if let Err(e) = feu.commande_initialise_noeud_vierge() {
                eprintln!("Erreur d'initialisation du nœud => {}", e)
            }
            SuiteCommandes::Continuer
        }
        ("lire", _, _) => {
            match std::fs::File::create(argument1) {
                Err(e) => eprintln!("Erreur fichier => {}", e),
                Ok(fichier) => {
                    let mut hash_decode = [0u8; 32];
                    HEXLOWER
                        .decode_mut(argument2.as_bytes(), &mut hash_decode)
                        .unwrap();
                    match feu.commande_lecture_donnees(0, 0, hash_decode, fichier) {
                        Err(e) => {
                            eprintln!("Erreur lecture => {}", e);
                        }
                        Ok(_) => {
                            println!("Fichier enregistré");
                        }
                    }
                }
            }
            SuiteCommandes::Continuer
        }
        ("liste", "-C", _) => {
            liste_commandes();
            SuiteCommandes::Continuer
        }
        ("liste", "-F", _) => {
            match &feu.commande_liste_foyers() {
                Ok(valeur) => affiche_liste_foyers(valeur),
                Err(e) => {
                    eprintln!("Erreur d'affiche des foyers => {}", e);
                }
            }

            SuiteCommandes::Continuer
        }
        ("ouvre", _, _) => {
            match argument1.parse::<usize>() {
                Ok(i) => {
                    if let Err(e) = feu.commande_ouverture_foyer(i) {
                        eprintln!("Impossible d'ouvrir le foyer {} => {}", i, e);
                    }
                }
                Err(_) => eprintln!("Argument invalide => {}", argument1),
            }
            SuiteCommandes::Continuer
        }
        ("quitte", _, _) => {
            if feu.commande_quitter_feu() {
                SuiteCommandes::Quitter
            } else {
                eprintln!("Le noeud doit être éteint avant de quitter");
                SuiteCommandes::Continuer
            }
        }
        ("version", _, _) => {
            feu.commande_affiche_version();
            SuiteCommandes::Continuer
        }
        (_, _, _) => {
            println!("Commande inconnue.");
            SuiteCommandes::Continuer
        }
    }
}

/// Affiche la liste des commandes disponibles avec leur description.
fn liste_commandes() {
    println!("Commandes disponibles :");
    println!("{:<15} | allume le noeud", "allume");
    println!("{:<15} | change le mdp", "change mdp");
    println!(
        "{:<15} | dépose un fichier dans le classeur 0 du foyer 0 (test)",
        "depot `chemin`"
    );
    println!("{:<15} | éteint le noeud", "eteins");
    println!("{:<15} | ferme le foyer d'index `i`", "ferme `i`");
    println!("{:<15} | initialise un nœud vierge", "initialise");
    println!("{:<15} | lire fichier", "lire `chemin_dest` `hash`");
    println!("{:<15} | liste les commandes disponibles", "liste -C");
    println!("{:<15} | liste les foyers et leur état", "liste -F");
    println!("{:<15} | ouvre le foyer d'index `i`", "ouvre `i`");
    println!("{:<15} | quitte Feu", "quitte");
    println!("{:<15} | affiche la version de `Feu`", "version");
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
    for (i, e) in t.iter().enumerate() {
        println!("{:<5} | {:<10} | {}", i, conversion_bool_statut(e.0), e.1);
    }
}
