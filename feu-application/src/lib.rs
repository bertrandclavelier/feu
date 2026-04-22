//! Couche applicative du protocole Feu.
//!
//! `feu-application` est l'unique consommateur de `feu-noyau` dans le workspace.
//! Elle orchestre les commandes du noyau, valide les préconditions et expose
//! une API stable vers la couche de présentation.
//!
//! # Architecture
//!
//! Les deux interfaces suivent le même principe : passée en paramètre à chaque
//! commande qui en a besoin, jamais stockée dans une struct. Ce choix supprime
//! tout problème de propriété et aligne `feu-application` sur le modèle de
//! `feu-noyau`.
//!
//! - [`InterfaceFeuNoyau`] est implémentée par [`RecepteurNoyau`], pont éphémère
//!   créé pour la durée d'un appel noyau. Il délègue les interactions bloquantes
//!   à [`InterfaceFeuApplication`] et écrit les notifications d'état directement
//!   dans [`SessionApplication`].
//! - [`InterfaceFeuApplication`] est fournie par la couche de présentation à
//!   chaque commande qui nécessite une interaction utilisateur
//!   (`commande_allumage_noeud`, `commande_ouverture_foyer`, etc.).
//!
//! # Cycle de vie
//!
//! [`FeuApplication`] suit un cycle en deux phases :
//! 1. **Construction** — [`FeuApplication::new`] crée la struct avec le noyau absent (`None`).
//! 2. **Allumage** — [`commande_allumage_noeud`](FeuApplication::commande_allumage_noeud)
//!    initialise ou allume le noyau. Toutes les autres commandes retournent
//!    [`ErreurFeuApplication::NoeudEteint`] si cette étape n'a pas été franchie.
//!
//! [`FeuApplication`] possède :
//! - `feu_noyau` — `Option<FeuNoyau>` : `None` jusqu'à `commande_allumage_noeud`
//! - `session` — état applicatif mis à jour à chaque commande noyau

pub use erreur::{ErreurFeuApplication, ResultFeuApplication};
use feu_noyau::{FeuNoyau, InterfaceFeuNoyau};
use secrecy::SecretString;
pub use session::SessionApplication;

mod commandes;
pub mod erreur;
mod session;

/// Contrat entre `feu-application` et la couche de présentation.
///
/// Sous-ensemble de [`InterfaceFeuNoyau`] exposé à la couche de présentation.
/// Le pont interne délègue ces trois méthodes à l'interface applicative ; les
/// notifications d'état (clés publiques, foyers) sont écrites directement dans
/// [`SessionApplication`] sans passer par ce trait.
pub trait InterfaceFeuApplication {
    /// Collecte le mot de passe Feu en masquant la saisie.
    ///
    /// Retourne `None` en cas d'erreur de lecture. Le mot de passe est
    /// encapsulé dans [`SecretString`] dès réception et zéroïsé au drop.
    fn demander_mdp(&self) -> Option<SecretString>;

    /// Transmet les mots de la seed mnémotechnique BIP39 à afficher.
    ///
    /// Appelée une seule fois à l'initialisation. Les `&str` empruntent
    /// la mémoire du noyau — toute copie est à la charge de l'interface.
    fn recevoir_seed(&mut self, mots: &[&str]);

    /// Demande confirmation que la seed a bien été enregistrée.
    ///
    /// Retourne `false` pour interrompre l'initialisation.
    fn confirmer_enregistrement_seed(&self) -> bool;
}

/// Pont éphémère entre [`FeuNoyau`] et la couche applicative.
///
/// Créé pour la durée d'un seul appel noyau, puis droppé. Remplit deux rôles :
/// - délègue les interactions bloquantes (`demander_mdp`, `recevoir_seed`,
///   `confirmer_enregistrement_seed`) à l'interface applicative
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
    fn demander_mdp(&self) -> Option<SecretString> {
        self.interface_feu_application.demander_mdp()
    }

    fn recevoir_seed(&mut self, mots: &[&str]) {
        self.interface_feu_application.recevoir_seed(mots);
    }

    fn confirmer_enregistrement_seed(&self) -> bool {
        self.interface_feu_application
            .confirmer_enregistrement_seed()
    }

    /// Enregistre l'adresse `.onion` d'un foyer dans la session applicative.
    ///
    /// Appelée par le noyau à l'allumage pour chaque foyer connu, et à
    /// l'initialisation pour chaque foyer créé.
    fn recevoir_onion_foyer(&mut self, index_foyer: usize, onion: &str) {
        self.session_application
            .definit_onion_foyer(index_foyer, String::from(onion));
    }

    /// Met à jour l'état d'ouverture d'un foyer dans la session applicative.
    ///
    /// Appelée par le noyau à la fin d'une ouverture ou d'une fermeture réussie.
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
pub struct FeuApplication {
    /// Instance du noyau — `None` jusqu'à [`commande_allumage_noeud`](FeuApplication::commande_allumage_noeud).
    /// Les commandes reçoivent un [`RecepteurNoyau`] éphémère à chaque appel ; elles retournent
    /// [`ErreurFeuApplication::NoeudEteint`] si le noyau n'est pas encore allumé.
    feu_noyau: Option<FeuNoyau>,

    session: SessionApplication,
}

impl FeuApplication {
    /// Crée une instance de [`FeuApplication`] sans noyau.
    ///
    /// Initialise la session. Le noyau est absent (`None`) —
    /// appeler [`commande_allumage_noeud`](Self::commande_allumage_noeud) est nécessaire
    /// avant toute autre commande.
    pub fn new() -> Self {
        let session = SessionApplication::new();

        Self {
            feu_noyau: None,
            session,
        }
    }
}
