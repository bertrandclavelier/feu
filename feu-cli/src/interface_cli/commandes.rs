//! Traitement des commandes du REPL de Feu.
//!
//! Reçoit les commandes saisies par l'utilisateur, les dispatche
//! vers les méthodes correspondantes de [`Feu`] et signale à la boucle
//! REPL si elle doit continuer ou se terminer.
//!
//! Les commandes inconnues sont signalées à l'utilisateur sans interrompre
//! la session.

use feu_core::Feu;

use super::SuiteCommandes;

/// Dispatche une commande vers [`Feu`].
///
/// Retourne [`SuiteCommandes::Continuer`] pour poursuivre la session,
/// [`SuiteCommandes::Quitter`] pour la terminer.
pub(super) fn traite_commande(
    feu: &Feu<super::InterfaceCli>,
    commande: &str,
    _arguments: &str,
) -> SuiteCommandes {
    match commande {
        "liste" => {
            liste_commande();
            SuiteCommandes::Continuer
        }
        "quitter" => SuiteCommandes::Quitter,
        "version" => {
            feu.affiche_version();
            SuiteCommandes::Continuer
        }
        _ => {
            println!("Commande inconnue.");
            SuiteCommandes::Continuer
        }
    }
}

/// Fonction qui affiche la liste des commandes disponibles
fn liste_commande() {
    println!("Commandes disponibles :");
    println!("{:<12} | liste les commandes disponibles", "liste");
    println!("{:<12} | affiche la version de `Feu`", "version");
}
