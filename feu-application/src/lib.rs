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
//! Le pont entre les deux couches est une struct interne éphémère (`RecepteurNoyau`),
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
use secrecy::{SecretBox, SecretString};
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
    /// Crée la session, construit le pont interne éphémère le temps de l'appel
    /// à [`FeuNoyau::new`], puis le droppe — libérant les emprunts sur `session`
    /// et `interface_feu_application` avant la construction de `Self`.
    ///
    /// `seed_bytes` est transmis directement à [`FeuNoyau::new`] : passer `None`
    /// génère une nouvelle seed (comportement par défaut), passer `Some(seed)` initialise
    /// le nœud depuis une seed existante. Voir [`FeuNoyau::new`] pour les contraintes.
    ///
    /// [`FeuNoyau::new`] détecte automatiquement si le nœud doit être initialisé
    /// ou allumé. Les erreurs noyau sont propagées via [`ErreurFeuApplication::FeuNoyau`].
    pub fn new(
        seed_bytes: Option<SecretBox<[u8; 64]>>,
        mut interface_feu_application: I,
    ) -> ResultFeuApplication<Self> {
        let mut session = SessionApplication::new();

        let feu_noyau = {
            let mut recepteur_noyau =
                RecepteurNoyau::new(&mut session, &mut interface_feu_application);
            FeuNoyau::new(seed_bytes, &mut recepteur_noyau)?
        };

        Ok(Self {
            feu_noyau,
            interface_feu_application,
            session,
        })
    }
}
