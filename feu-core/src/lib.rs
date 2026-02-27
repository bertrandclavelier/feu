//! `feu-core` est le cœur du protocole Feu.
//!
//! Il expose une interface unique — la structure [`Feu`] — qui orchestre
//! l'ensemble des composants internes : l'intendant, gardien des données
//! locales, et le cryptographe, garant de la sécurité cryptographique.
//!
//! Aucun composant interne n'est accessible directement depuis l'extérieur
//! du crate. Toute interaction avec Feu passe par [`Feu`] — cette
//! centralisation est un invariant de sécurité fondamental du protocole.
//!
//! # Plateformes supportées
//!
//! Linux et macOS uniquement. Le protocole repose sur des primitives
//! Unix — système de fichiers, variables d'environnement, permissions —
//! qui n'ont pas d'équivalent direct sous Windows.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("feu-core only supports Linux and macOS.");

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
    /// Crée une instance de [`Feu`] prête à l'emploi.
    ///
    /// Initialise l'intendant et le cryptographe avec leur état par défaut.
    /// L'interface fournie sera utilisée pour toutes les interactions
    /// utilisateur ultérieures.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'intendant ne peut pas être initialisé —
    /// notamment si la variable d'environnement `HOME` est absente ou si
    /// le dossier `~/.feu` ne peut pas être créé.
    pub fn new(interface_feu_core: I) -> ResultFeu<Self> {
        Ok(Self {
            interface_feu_core,
            intendant: Intendant::new()?,
            cryptographe: Cryptographe::new(),
        })
    }

    /// Affiche la version de `feu-core` via l'interface.
    ///
    /// Le message est émis au niveau `afficher_min` — il est donc visible
    /// dans tous les modes de verbosité.
    pub fn affiche_version(&self) {
        self.interface_feu_core.afficher_min(&format!(
            "{} version {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));
    }

    /// Initialise un nœud Feu vierge.
    ///
    /// Enchaîne trois étapes séquentielles, chacune conditionnée au
    /// succès de la précédente :
    ///
    /// 1. Crée l'arborescence `~/.feu` et ses sous-dossiers via l'intendant.
    /// 2. Génère les clés cryptographiques du nœud via le cryptographe.
    /// 3. Enregistre les clés dans l'arborescence *(non encore implémenté)*.
    ///
    /// En cas d'échec à l'une des étapes, l'erreur est signalée via
    /// l'interface et l'initialisation est abandonnée sans paniquer.
    pub fn initialise_noeud_vierge(&mut self) {
        match self.intendant.cree_premiere_arborescence() {
            Err(e) => {
                self.interface_feu_core.afficher_erreur(&format!(
                    "Feu ›› L'intendant a eu des soucis pour créer la première arborescence : {}",
                    e
                ));
            }
            Ok(_) => {
                // Le cryptographe génère les clés nécessaires au fonctionnement d'un nouveau nœud
                if let Err(e) = self
                    .cryptographe
                    .initialise_noeud_from_nouvelle_seed(&self.interface_feu_core)
                {
                    self.interface_feu_core.afficher_erreur(&format!(
                        "Feu ›› Le cryptographe a eu des soucis pour générer \
                        les clés à mettre dans son trousseau : {}",
                        e
                    ));
                }
            }
        }
    }
}
