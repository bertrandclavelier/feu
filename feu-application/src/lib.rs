//! Couche applicative du protocole Feu.
//!
//! `feu-application` est l'unique consommateur de `feu-noyau` dans le workspace.
//! Elle orchestre les commandes du noyau, valide les préconditions et expose
//! une API stable vers la couche de présentation.
//!
//! # Architecture
//!
//! `feu-noyau` communique avec l'extérieur via `InterfaceFeuNoyau` — il
//! délègue les interactions utilisateur (`demander`, `demander_mdp`) et émet
//! des notifications d'état (clés publiques). Pour brancher `feu-noyau` sur
//! une interface applicative sans créer de dépendance circulaire, un
//! `AdaptateurNoyau` privé implémente `InterfaceFeuNoyau` et délègue à une
//! copie de l'interface fournie par l'appelant.
//!
//! [`FeuApplication`] possède :
//! - `feu_noyau` — instance du noyau, avec l'adaptateur comme interface
//! - `interface_feu_application` — accès direct à l'interface pour les
//!   notifications et mises à jour de session après chaque commande

pub use erreur::{ErreurFeuApplication, ResultFeuApplication};
use feu_noyau::{FeuNoyau, InterfaceFeuNoyau};

mod commandes;
mod erreur;

/// Contrat entre `feu-application` et la couche de présentation.
///
/// Trois catégories de méthodes :
/// - **Sorties** — `afficher` : cas délibéré pour la seed mnémotechnique, transmise
///   directement avant zéroïsation sans passer par une couche intermédiaire.
/// - **Entrées** — collecte bloquante d'une saisie utilisateur (`demander`, `demander_mdp`).
/// - **Notifications** — à venir : clés publiques, état de session, etc.
pub trait InterfaceFeuApplication {
    /// Transmet un message à afficher immédiatement — usage réservé à la seed
    /// mnémotechnique, transmise avant zéroïsation sans intermédiaire.
    fn afficher(&self, message: &str);
    /// Collecte une réponse de l'utilisateur.
    /// Retourne une chaîne vide en cas d'erreur de lecture.
    fn demander(&self, question: &str) -> String;

    /// Collecte un mot de passe en masquant la saisie.
    /// Retourne une chaîne vide en cas d'erreur de lecture.
    fn demander_mdp(&self, question: &str) -> String;
}

/// Pont entre [`FeuNoyau`] et [`InterfaceFeuApplication`].
///
/// Implémente [`InterfaceFeuNoyau`] en déléguant chaque appel à l'interface
/// applicative qu'il possède. Privé — la couche de présentation n'en a pas connaissance.
#[derive(Clone)]
struct AdaptateurNoyau<I: InterfaceFeuApplication> {
    /// Interface applicative — délégation de toutes les interactions noyau.
    interface_feu_application: I,
}

impl<I: InterfaceFeuApplication> AdaptateurNoyau<I> {
    /// Crée un adaptateur à partir d'une instance de [`InterfaceFeuApplication`].
    fn new(interface_feu_application: I) -> Self {
        Self {
            interface_feu_application,
        }
    }
}

impl<I: InterfaceFeuApplication> InterfaceFeuNoyau for AdaptateurNoyau<I> {
    fn afficher(&self, message: &str) {
        self.interface_feu_application.afficher(message);
    }
    fn demander(&self, question: &str) -> String {
        self.interface_feu_application.demander(question)
    }

    fn demander_mdp(&self, question: &str) -> String {
        self.interface_feu_application.demander_mdp(question)
    }

    /// Reçoit la clé publique de signature du nœud.
    /// À implémenter : transmettre via [`InterfaceFeuApplication`].
    fn recevoir_cle_publique_noeud(&self, _cle_publique_sig_noeud: [u8; 32]) {
        todo!();
    }

    /// Reçoit les clés publiques de signature et de chiffrement d'un foyer.
    /// À implémenter : transmettre via [`InterfaceFeuApplication`].
    fn recevoir_cles_publiques_foyer(
        &self,
        _index_foyer: usize,
        _cle_publique_sig: [u8; 32],
        _cle_publique_chif: [u8; 32],
    ) {
        todo!();
    }
}

/// Point d'entrée unique de `feu-application`.
///
/// Orchestre les commandes du noyau, valide les préconditions et expose une API
/// stable vers la couche de présentation. Toute interaction avec `feu-noyau` passe par cette
/// structure — jamais directement depuis la couche de présentation.
pub struct FeuApplication<I: InterfaceFeuApplication> {
    /// Instance du noyau — l'adaptateur fait le pont entre noyau et interface.
    feu_noyau: FeuNoyau<AdaptateurNoyau<I>>,

    /// Accès direct à l'interface pour les notifications post-commande.
    interface_feu_application: I,
}

impl<I: InterfaceFeuApplication + Clone> FeuApplication<I> {
    /// Crée une instance de [`FeuApplication`] prête à l'emploi.
    ///
    /// `interface_feu_application` est clonée : une copie est donnée à
    /// l'adaptateur (utilisée par le noyau pour les interactions bloquantes),
    /// l'originale est conservée par [`FeuApplication`] pour les notifications
    /// post-commande.
    /// Crée une instance de [`FeuApplication`] prête à l'emploi.
    ///
    /// `interface_feu_application` est clonée : une copie est donnée à
    /// l'adaptateur (utilisée par le noyau pour les interactions bloquantes),
    /// l'originale est conservée par [`FeuApplication`] pour les notifications
    /// post-commande.
    ///
    /// Délègue à [`FeuNoyau::new`] qui détecte automatiquement si le nœud
    /// doit être initialisé ou allumé. Les erreurs noyau sont propagées
    /// via [`ErreurFeuApplication::FeuNoyau`].
    pub fn new(interface_feu_application: I) -> ResultFeuApplication<Self> {
        Ok(Self {
            feu_noyau: FeuNoyau::new(AdaptateurNoyau::new(interface_feu_application.clone()))?,
            interface_feu_application,
        })
    }
}
