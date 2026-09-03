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
//!   chaque commande qui a besoin d'elle — pour une interaction utilisateur
//!   (`commande_allumage_noeud`) ou pour la seule notification de session
//!   (`commande_ouverture_comptoir_depot`). Toujours par emprunt partagé : le
//!   trait n'a que des méthodes `&self`.
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
//! - `chemin_feu` — racine du nœud, reçue du binaire et distribuée au Scribe
//!   puis au noyau
//! - `feu_noyau` — `Option<FeuNoyau>` : `None` jusqu'à `commande_allumage_noeud`
//! - `session` — état applicatif mis à jour à chaque commande noyau
//! - `scribe` — tenant de la couche ENU, champ plein activé à l'allumage

use std::path::{Path, PathBuf};

pub use erreur::{ErreurFeuApplication, ResultFeuApplication};
use feu_noyau::{Braise, FeuNoyau, InterfaceFeuNoyau};
pub use feu_noyau::{IndexClasseur, IndexFoyer};
use secrecy::SecretString;
pub use session::SessionApplication;

use self::scribe::Scribe;
/// Ce que la couche ENU laisse voir au dehors : la carte, jamais l'enveloppe.
///
/// `Enu` reste privée au crate. Les crates consommatrices reçoivent des
/// [`Fiche`](fiche::Fiche) — mêmes champs sans la signature — et les redonnent
/// telles quelles ; c'est ici, et ici seulement, qu'une ENU est rechargée depuis
/// le disque et authentifiée avant d'agir.
///
/// [`Carte`] est en revanche un `enum` public dont les variantes exposent leurs
/// champs, ce qui permet de descendre l'arborescence en lisant les `hashs_enu`
/// d'une [`Carte::Repertoire`]. La confiance ne vient pas de l'encapsulation
/// mais de la vérification de la signature à chaque chargement.
pub use self::scribe::carte::Carte;
pub use self::scribe::fiche;
/// Parcours d'arborescence exposés à la couche de présentation.
///
/// Les deux types sont publics parce qu'ils apparaissent dans la signature des
/// commandes qui les rendent. Ni l'un ni l'autre ne se construit de l'extérieur :
/// leurs `new` sont `pub(crate)` et réclament le chemin du dossier `enu/`, que
/// le Scribe ne laisse pas sortir.
pub use self::scribe::iterateurs::{Descendants, RacinesAnterieures};

pub mod erreur;
mod lib_commandes;
mod scribe;
mod session;

/// Contrat entre [`FeuApplication`] et la couche de présentation.
///
/// Regroupe les interactions bloquantes déléguées par le pont interne et la
/// notification d'état émise après chaque commande mutante. Ce que le noyau
/// écrit lui-même dans [`SessionApplication`] — clés publiques, braises — ne
/// passe pas par ici.
///
/// Toutes les méthodes prennent `&self` : le trait demande de **transmettre**,
/// pas de retenir. Qui veut stocker prend une mutabilité intérieure à sa charge
/// plutôt que d'imposer l'exclusivité à tous.
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
    fn recevoir_seed(&self, mots: &[&str]);

    /// Demande confirmation que la seed a bien été enregistrée.
    ///
    /// Retourne `false` pour interrompre l'initialisation.
    fn confirmer_enregistrement_seed(&self) -> bool;

    /// Notifie la couche de présentation d'un changement d'état applicatif.
    ///
    /// Appelée à la fin de chaque commande mutante, session déjà cohérente : un
    /// seul appel par commande, jamais en cours de mutation ni depuis un setter.
    ///
    /// `Some(session)` porte un clone de l'état applicatif ; `None` dit
    /// l'extinction du nœud, que la présentation doit traiter comme une remise à
    /// zéro. Elle en fait ensuite ce qu'elle veut.
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
    /// Le miroir à tenir : c'est ici qu'atterrissent les notifications du noyau.
    session_application: &'a mut SessionApplication,
    /// L'interface de la couche de présentation, à qui les interactions
    /// bloquantes sont repassées telles quelles.
    interface_feu_application: &'b dyn InterfaceFeuApplication,
}

impl<'a, 'b> RecepteurNoyau<'a, 'b> {
    /// Assemble le pont pour la durée d'un appel noyau.
    ///
    /// Les deux emprunts viennent de [`FeuApplication`] et de la couche de
    /// présentation ; ils ne sont pas retenus au-delà de l'appel, ce qui est la
    /// raison d'être du pont.
    ///
    /// Seule la session est prise en mutable — le pont y écrit ce que le noyau
    /// lui notifie. L'interface, elle, n'est que sollicitée : ses quatre
    /// méthodes prennent `&self`, un emprunt partagé suffit à les appeler,
    /// y compris depuis les méthodes `&mut self` que réclame
    /// [`InterfaceFeuNoyau`].
    fn new(
        session_application: &'a mut SessionApplication,
        interface_feu_application: &'b dyn InterfaceFeuApplication,
    ) -> Self {
        Self {
            session_application,
            interface_feu_application,
        }
    }
}

impl InterfaceFeuNoyau for RecepteurNoyau<'_, '_> {
    /// Délègue la saisie du mot de passe à l'interface applicative.
    fn demander_mdp(&self) -> Option<SecretString> {
        self.interface_feu_application.demander_mdp()
    }

    /// Délègue l'affichage de la seed à l'interface applicative.
    ///
    /// Les `&str` restent empruntés au noyau : le pont ne les copie pas.
    fn recevoir_seed(&mut self, mots: &[&str]) {
        self.interface_feu_application.recevoir_seed(mots);
    }

    /// Délègue la confirmation d'enregistrement de la seed à l'interface
    /// applicative.
    fn confirmer_enregistrement_seed(&self) -> bool {
        self.interface_feu_application
            .confirmer_enregistrement_seed()
    }

    /// Enregistre l'adresse `.braise` d'un foyer dans la session applicative.
    ///
    /// Appelée par le noyau à l'allumage pour chaque foyer connu, et à
    /// l'initialisation pour chaque foyer créé.
    fn recevoir_braise_foyer(&mut self, index_foyer: IndexFoyer, braise: Braise) {
        self.session_application
            .definit_braise_foyer(index_foyer, braise);
    }

    /// Met à jour l'état d'ouverture d'un foyer dans la session applicative.
    ///
    /// Appelée par le noyau à la fin d'une ouverture ou d'une fermeture réussie.
    fn recevoir_etat_foyer(&mut self, index_foyer: IndexFoyer, etat: bool) {
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
        index_foyer: IndexFoyer,
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
    /// Chemin racine du nœud (`~/.feu` en usage nominal), reçu du binaire à la
    /// construction. Détenu ici puis distribué à ses deux consommateurs — le
    /// [`Scribe`] et, à l'allumage, [`FeuNoyau`] — pour qu'aucune couche sous la
    /// présentation ne lise l'environnement.
    chemin_feu: PathBuf,

    /// Instance du noyau — `None` jusqu'à [`commande_allumage_noeud`](FeuApplication::commande_allumage_noeud).
    /// Les commandes reçoivent un [`RecepteurNoyau`] éphémère à chaque appel ; elles retournent
    /// [`ErreurFeuApplication::NoeudEteint`] si le noyau n'est pas encore allumé.
    feu_noyau: Option<FeuNoyau>,

    /// État applicatif de la session — miroir lisible de ce que détiennent le
    /// noyau et le Scribe. Cloné vers la couche de présentation après chaque
    /// commande mutante, remplacé par une session neuve à l'extinction.
    session: SessionApplication,

    /// Tenant de la couche ENU. Champ plein et non `Option` : construit avec
    /// [`FeuApplication`], il porte lui-même la marque de son activation, que
    /// l'allumage pose après le noyau dont son amorce a besoin.
    scribe: Scribe,
}

impl FeuApplication {
    /// Crée une instance de [`FeuApplication`] sans noyau.
    ///
    /// Initialise la session. Le noyau est absent (`None`) —
    /// appeler [`commande_allumage_noeud`](Self::commande_allumage_noeud) est nécessaire
    /// avant toute autre commande.
    ///
    /// `chemin_feu` est le chemin racine du nœud (`~/.feu` en usage nominal),
    /// fourni par le binaire. Il est conservé et distribué au scribe dès
    /// maintenant, puis au [`FeuNoyau`] à l'allumage.
    pub fn new(chemin_feu: &Path) -> Self {
        Self {
            chemin_feu: chemin_feu.to_path_buf(),
            feu_noyau: None,
            session: SessionApplication::new(),
            scribe: Scribe::new(chemin_feu),
        }
    }
}

/// Tests que `tests/application.rs` ne peut pas porter : ils constatent des
/// champs privés, sur un état que la couche de présentation ne reçoit jamais.
#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use feu_noyau::{Braise, IndexClasseur};
    use tempfile::TempDir;

    use super::*;

    /// Implémentation d'[`InterfaceFeuApplication`] pour les tests.
    ///
    /// Répond par des valeurs fixes — aucune interaction réelle n'est possible sous
    /// test. Enveloppée dans un [`RecepteurNoyau`] réel, elle laisse le vrai pont
    /// remplir la [`SessionApplication`] exactement comme en production.
    ///
    /// Retient la dernière session notifiée. C'est le seul moyen d'observer
    /// [`recevoir_session_application`](InterfaceFeuApplication::recevoir_session_application)
    /// depuis un test : là où `feu-tui` pousse le payload sur un canal et le stocke
    /// dans le thread d'en face, un test n'a pas de second thread et doit le garder
    /// sur place.
    ///
    /// `pub(crate)` — partagée avec `scribe/tests.rs`.
    pub(crate) struct InterfaceTest {
        /// Servi à chaque `demander_mdp`. Ouverture et fermeture d'un foyer doivent
        /// voir le même, sinon le déchiffrement échoue.
        mot_de_passe: SecretString,

        /// Dernière session notifiée. `RefCell` parce que le trait notifie sous
        /// `&self` : l'écriture ne peut venir que d'une mutabilité intérieure.
        session_application: RefCell<Option<SessionApplication>>,
    }

    impl InterfaceTest {
        /// Construit l'interface avec le mot de passe qu'elle servira.
        pub(crate) fn new(mot_de_passe: &str) -> Self {
            Self {
                mot_de_passe: SecretString::from(mot_de_passe),
                session_application: RefCell::new(None),
            }
        }

        /// Clone de la dernière session notifiée — `None` tant que rien n'a été
        /// notifié, et de nouveau `None` après extinction.
        pub(crate) fn session_application(&self) -> Option<SessionApplication> {
            self.session_application.borrow().clone()
        }
    }

    impl InterfaceFeuApplication for InterfaceTest {
        /// Sert toujours le même mot de passe : ouverture et fermeture d'un foyer
        /// doivent le voir identique, sinon le déchiffrement échoue.
        fn demander_mdp(&self) -> Option<SecretString> {
            Some(self.mot_de_passe.clone())
        }

        /// Jetée : aucun test n'a besoin de relire la seed. La retenir demanderait
        /// un second champ que rien ne consulterait.
        fn recevoir_seed(&self, _mots: &[&str]) {}

        /// Confirme toujours — sans quoi l'initialisation du noyau s'interromprait.
        fn confirmer_enregistrement_seed(&self) -> bool {
            true
        }

        /// Retient la session notifiée, seul état que l'interface conserve : c'est
        /// par elle que les tests constatent ce qu'une commande a publié.
        fn recevoir_session_application(&self, session_application: Option<SessionApplication>) {
            *self.session_application.borrow_mut() = session_application;
        }
    }

    /// Cycle de vie complet du nœud par les commandes — du refus avant allumage
    /// au teardown après extinction.
    ///
    /// L'état est constaté sur la session **reçue par [`InterfaceTest`]** tant
    /// qu'elle existe : une assertion qui passe prouve alors que la commande a
    /// notifié, et que le payload portait l'état d'après. Le teardown fait
    /// exception — l'extinction notifie `None`, il ne reste que les champs.
    ///
    /// Un comptoir est laissé ouvert à l'extinction, qui passe outre et l'annule.
    #[test]
    fn cycle_feu_application() -> ResultFeuApplication<()> {
        let tmp = TempDir::new().unwrap();
        let chemin_feu = tmp.path().join(".feu");
        let chemin_depot = tmp.path().join("depot");

        let interface_test = InterfaceTest::new("mot de passe");

        let mut app = FeuApplication::new(&chemin_feu);
        assert!(interface_test.session_application().is_none());

        // Nœud éteint : toute commande qui le suppose allumé se refuse d'emblée.
        assert!(matches!(
            app.commande_ouverture_comptoir_depot(
                &interface_test,
                &chemin_depot,
                IndexFoyer::ZERO,
                IndexClasseur::ZERO
            ),
            Err(ErreurFeuApplication::NoeudEteint)
        ));
        assert!(matches!(
            app.commande_derniere_enu_racine(),
            Err(ErreurFeuApplication::NoeudEteint)
        ));
        assert!(matches!(
            app.commande_chargement_enu(&[0u8; 32]),
            Err(ErreurFeuApplication::NoeudEteint)
        ));

        app.commande_allumage_noeud(&interface_test, None)?;

        assert_ne!(
            interface_test
                .session_application()
                .unwrap()
                .braise_foyer(IndexFoyer::ZERO),
            Braise::VIDE
        );

        app.commande_ouverture_foyer(&interface_test, IndexFoyer::ZERO)?;
        assert!(
            interface_test
                .session_application()
                .unwrap()
                .etat_foyer(IndexFoyer::ZERO)
        );

        app.commande_ouverture_comptoir_depot(
            &interface_test,
            &chemin_depot,
            IndexFoyer::ZERO,
            IndexClasseur::ZERO,
        )?;

        // L'extinction bute d'abord sur le foyer 0, encore ouvert.
        assert!(matches!(
            app.commande_extinction_noeud(&interface_test),
            Err(ErreurFeuApplication::AuMoinsUnFoyerOuvert)
        ));

        app.commande_fermeture_foyer(&interface_test, IndexFoyer::ZERO)?;
        assert!(
            !interface_test
                .session_application()
                .unwrap()
                .etat_foyer(IndexFoyer::ZERO)
        );

        assert!(app.commande_extinction_noeud(&interface_test).is_ok());
        assert!(interface_test.session_application().is_none());
        assert!(matches!(
            app.commande_chargement_enu(&[0u8; 32]),
            Err(ErreurFeuApplication::NoeudEteint)
        ));

        // Plus rien à tirer de la session notifiée, désormais `None` : le teardown
        // ne se constate que sur les champs.
        assert_eq!(app.session.braise_foyer(IndexFoyer::ZERO), Braise::VIDE);
        assert_eq!(app.session.cle_publique_sig_noeud(), [0u8; 2592]);
        assert_eq!(
            app.session.cle_publique_sig_foyer(IndexFoyer::ZERO),
            [0u8; 2592]
        );
        assert!(app.session.foyers_fermes());
        assert!(!app.scribe.est_actif());

        Ok(())
    }
}
