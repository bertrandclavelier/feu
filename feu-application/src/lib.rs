// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

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
//! - [`InterfaceFeuNoyau`] est implémentée par `RecepteurNoyau`, pont éphémère
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

use crate::scribe::Scribe;

mod commandes;
pub mod erreur;
mod scribe;
mod session;

/// Contrat entre [`FeuApplication`] et la couche de présentation.
///
/// Regroupe les interactions bloquantes déléguées par le pont interne
/// (`demander_mdp`, `recevoir_seed`, `confirmer_enregistrement_seed`) et la
/// notification d'état émise après chaque commande mutante
/// (`recevoir_session_application`). Les notifications d'état internes au noyau
/// (clés publiques, adresses `.braise`) sont écrites directement dans
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

    /// Notifie la couche de présentation d'un changement d'état applicatif.
    ///
    /// Appelée par [`FeuApplication`] à la fin de chaque commande qui mute
    /// [`SessionApplication`], une fois la session dans un état cohérent.
    /// Un seul appel par commande — jamais en cours de mutation, jamais depuis
    /// les setters de session.
    ///
    /// Le payload distingue deux cas :
    /// - `Some(session)` — clone cohérent de l'état applicatif après une commande
    ///   mutante réussie (allumage, ouverture/fermeture de foyer…).
    /// - `None` — extinction du nœud : la couche de présentation doit traiter
    ///   cela comme une remise à zéro et oublier toute donnée applicative.
    ///
    /// La couche de présentation est libre d'en faire ce qu'elle veut :
    /// l'envoyer sur un canal, le stocker, l'ignorer.
    fn recevoir_session_application(&self, session_application: Option<SessionApplication>);
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

    /// Enregistre l'adresse `.braise` d'un foyer dans la session applicative.
    ///
    /// Appelée par le noyau à l'allumage pour chaque foyer connu, et à
    /// l'initialisation pour chaque foyer créé.
    fn recevoir_braise_foyer(&mut self, index_foyer: usize, braise: &str) {
        self.session_application
            .definit_braise_foyer(index_foyer, String::from(braise));
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
    fn recevoir_cle_publique_noeud(&mut self, cle_publique_sig_noeud: [u8; 2592]) {
        self.session_application
            .definit_cle_publique_sig_noeud(cle_publique_sig_noeud);
    }

    /// Stocke les clés publiques de signature et de chiffrement d'un foyer dans la session.
    ///
    /// Appelée par le noyau à l'ouverture du foyer, après lecture du trousseau public.
    fn recevoir_cles_publiques_foyer(
        &mut self,
        index_foyer: usize,
        cle_publique_sig: [u8; 2592],
        cle_publique_chif: [u8; 1568],
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

    scribe: Scribe,
}

impl FeuApplication {
    /// Crée une instance de [`FeuApplication`] sans noyau.
    ///
    /// Initialise la session. Le noyau est absent (`None`) —
    /// appeler [`commande_allumage_noeud`](Self::commande_allumage_noeud) est nécessaire
    /// avant toute autre commande.
    pub fn new() -> Self {
        Self {
            feu_noyau: None,
            session: SessionApplication::new(),
            scribe: Scribe::new(),
        }
    }
}

impl Default for FeuApplication {
    /// Délègue à [`FeuApplication::new`].
    fn default() -> Self {
        Self::new()
    }
}
