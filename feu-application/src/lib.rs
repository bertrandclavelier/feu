//! Couche applicative du protocole Feu.
//!
//! `feu-application` est l'unique consommateur de `feu-noyau` dans le workspace.
//! Elle orchestre les commandes du noyau, valide les préconditions et expose
//! une API stable vers la couche de présentation.
//!
//! # Architecture
//!
//! `feu-noyau` communique avec l'extérieur via `InterfaceFeuNoyau` — passée
//! en paramètre à chaque commande, jamais stockée dans la struct. Ce choix
//! évite toute dépendance circulaire et supprime le besoin de cloner l'interface.
//!
//! Le pont entre les deux couches est [`RecepteurNoyau`] : une struct éphémère,
//! créée pour la durée d'un appel noyau, qui implémente `InterfaceFeuNoyau` en
//! déléguant les interactions à l'interface applicative et en écrivant les
//! notifications directement dans [`SessionApplication`].
//!
//! [`FeuApplication`] possède :
//! - `feu_noyau` — instance du noyau
//! - `interface_feu_application` — canal vers la couche de présentation
//! - `session` — état applicatif mis à jour à chaque commande noyau

pub use erreur::{ErreurFeuApplication, ResultFeuApplication};
use feu_noyau::{FeuNoyau, InterfaceFeuNoyau};
pub use session::SessionApplication;

mod commandes;
pub mod erreur;
mod session;

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

/// Pont éphémère entre [`FeuNoyau`] et la couche applicative.
///
/// Créé pour la durée d'un seul appel noyau, puis droppé. Remplit deux rôles :
/// - délègue les interactions bloquantes (`demander`, `demander_mdp`, `afficher`)
///   à l'interface applicative
/// - écrit les notifications d'état (clés publiques, état des foyers) directement
///   dans [`SessionApplication`]
///
/// Privé — la couche de présentation n'en a pas connaissance.
struct RecepteurNoyau<'a, 'b> {
    session_application: &'a mut SessionApplication,
    interface_feu_application: &'b mut dyn InterfaceFeuApplication,
}

impl<'a, 'b> RecepteurNoyau<'a, 'b> {
    fn new(
        session_application: &'a mut SessionApplication,
        interface_feu_application: &'b mut dyn InterfaceFeuApplication,
    ) -> Self {
        Self {
            session_application,
            interface_feu_application,
        }
    }
}

impl InterfaceFeuNoyau for RecepteurNoyau<'_, '_> {
    fn afficher(&self, message: &str) {
        self.interface_feu_application.afficher(message);
    }
    fn demander(&self, question: &str) -> String {
        self.interface_feu_application.demander(question)
    }

    fn demander_mdp(&self, question: &str) -> String {
        self.interface_feu_application.demander_mdp(question)
    }

    fn recevoir_onion_foyer(&mut self, index_foyer: usize, onion: &str) {
        self.session_application
            .definit_onion_foyer(index_foyer, String::from(onion));
    }

    fn recevoir_etat_foyer(&mut self, index_foyer: usize, etat: bool) {
        self.session_application
            .definit_etat_foyer(index_foyer, etat);
    }

    /// Stocke la clé publique de signature du nœud dans la session.
    ///
    /// Appelée par le noyau à l'allumage, après lecture du trousseau public.
    fn recevoir_cle_publique_noeud(&mut self, cle_publique_sig_noeud: [u8; 32]) {
        self.session_application
            .definit_cle_publique_sig_noeud(cle_publique_sig_noeud);
    }

    /// Stocke les clés publiques de signature et de chiffrement d'un foyer dans la session.
    ///
    /// Appelée par le noyau à l'ouverture du foyer, après lecture du trousseau public.
    fn recevoir_cles_publiques_foyer(
        &mut self,
        index_foyer: usize,
        cle_publique_sig: [u8; 32],
        cle_publique_chif: [u8; 32],
    ) {
        self.session_application
            .definit_cle_publique_sig_foyer(index_foyer, cle_publique_sig);
        self.session_application
            .definit_cle_publique_chif_foyer(index_foyer, cle_publique_chif);
    }
}

/// Point d'entrée unique de `feu-application`.
///
/// Orchestre les commandes du noyau, valide les préconditions et expose une API
/// stable vers la couche de présentation. Toute interaction avec `feu-noyau` passe par cette
/// structure — jamais directement depuis la couche de présentation.
pub struct FeuApplication<I: InterfaceFeuApplication> {
    /// Instance du noyau — les commandes reçoivent un [`RecepteurNoyau`] éphémère à chaque appel.
    feu_noyau: FeuNoyau,

    /// Accès direct à l'interface pour les notifications post-commande.
    interface_feu_application: I,

    session: SessionApplication,
}

impl<I: InterfaceFeuApplication> FeuApplication<I> {
    /// Crée une instance de [`FeuApplication`] prête à l'emploi.
    ///
    /// Crée la session, construit un [`RecepteurNoyau`] éphémère le temps de
    /// l'appel à [`FeuNoyau::new`], puis le droppe — libérant les emprunts
    /// sur `session` et `interface_feu_application` avant la construction de `Self`.
    ///
    /// [`FeuNoyau::new`] détecte automatiquement si le nœud doit être initialisé
    /// ou allumé. Les erreurs noyau sont propagées via [`ErreurFeuApplication::FeuNoyau`].
    pub fn new(mut interface_feu_application: I) -> ResultFeuApplication<Self> {
        let mut session = SessionApplication::new();

        let feu_noyau = {
            let mut recepteur_noyau =
                RecepteurNoyau::new(&mut session, &mut interface_feu_application);
            FeuNoyau::new(&mut recepteur_noyau)?
        };

        Ok(Self {
            feu_noyau,
            interface_feu_application,
            session,
        })
    }
}
