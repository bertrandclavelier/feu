//! `feu-core` est le cœur du protocole Feu.
//!
//! Il expose une interface unique — la structure [`Feu`] — qui orchestre
//! l'ensemble des composants internes : l'intendant, gardien des données
//! locales, et le cryptographe, garant de la sécurité cryptographique.
//!
//! Aucun composant interne n'est accessible directement depuis l'extérieur
//! du crate. Toute interaction avec Feu passe par [`Feu`] — cette
//! centralisation est un invariant de sécurité fondamental du protocole.

mod cryptographe;
mod erreur;
mod intendant;

use cryptographe::Cryptographe;
use intendant::Intendant;

pub use erreur::ErreurFeu;
pub use erreur::ResultFeu;

/// Contrat de communication entre `feu-core` et toute interface utilisateur.
///
/// Ce trait définit le canal d'échange entre le cœur du protocole et sa
/// couche de présentation — CLI, TUI ou web. Chaque implémentation est
/// libre de définir son niveau de verbosité : `afficher_min` garantit
/// l'affichage de l'essentiel, `afficher` couvre le flux standard,
/// `afficher_max` expose le détail pour les modes bavards.
/// `afficher_erreur` signale tout échec à l'utilisateur.
/// `demander` collecte une réponse interactive, `demander_mdp` collecte
/// un mot de passe en masquant la saisie.
pub trait InterfaceFeuCore {
    /// Affiche un message essentiel — visible dans tous les modes.
    fn afficher_min(&self, message: &str);

    /// Affiche un message standard — visible en mode standard et max.
    fn afficher(&self, message: &str);

    /// Affiche un message détaillé — visible uniquement en mode max.
    fn afficher_max(&self, message: &str);

    /// Affiche un message d'erreur.
    fn afficher_erreur(&self, message: &str);

    /// Collecte une réponse de l'utilisateur.
    /// Retourne une chaîne vide en cas d'erreur de lecture.
    fn demander(&self, question: &str) -> String;

    /// Collecte un mot de passe en masquant la saisie.
    /// Retourne une chaîne vide en cas d'erreur de lecture.
    fn demander_mdp(&self, question: &str) -> String;
}

/// Point d'entrée unique du protocole Feu.
///
/// Orchestre [`Intendant`] et [`Cryptographe`] sans exposer leurs
/// détails d'implémentation. Paramétrique sur `I: InterfaceFeuCore` —
/// toute communication utilisateur est déléguée à l'interface injectée
/// à la création, garantissant une séparation totale entre logique
/// du protocole et couche de présentation.
pub struct Feu<I: InterfaceFeuCore> {
    /// Canal de communication avec l'interface utilisateur.
    interface_feu_core: I,

    /// Gardien des données locales — fichiers, foyers, configuration.
    intendant: Intendant,

    /// Gardien de la sécurité cryptographique — clés, chiffrement, seed.
    cryptographe: Cryptographe,
}

impl<I: InterfaceFeuCore> Feu<I> {
    /// Crée l'instance de [`Feu`] avec tout son personnel
    pub fn new(interface_feu_core: I) -> Self {
        Feu {
            interface_feu_core,
            intendant: Intendant::new(),
            cryptographe: Cryptographe::new(),
        }
    }

    /// Méthode qui affiche le numéro de version de 'feu-core'
    pub fn affiche_version(&self) {
        self.interface_feu_core.afficher_min(&format!(
            "{} version {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));
    }

    /// Méthode qui initialise un nœud Feu à partir de zéro
    pub fn initialise_noeud_vierge(&mut self) {
        // Le cryptographe génère les clés nécessaires au fonctionnement d'un nouveau nœud
        if let Err(e) = self
            .cryptographe
            .initialise_noeud_from_nouvelle_seed(&self.interface_feu_core)
        {
            self.interface_feu_core.afficher_erreur(&format!(
                "Feu ›› Le cryptographe a eu des soucis pour générer les clés à 
            mettre dans son trousseau : {}",
                e
            ));
        }
    }
}
