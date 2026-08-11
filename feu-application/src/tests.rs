// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Tests d'intégration de la crate, du point de vue de qui la consomme.
//!
//! Ces tests pilotent [`FeuApplication`] par ses seules `commande_*`, comme le
//! fait `feu-tui` : rien n'est appelé en direct sur le noyau, la session ou le
//! Scribe. C'est le contrat public de la crate qui est éprouvé, et lui seul.
//!
//! Ils se distinguent en cela de `scribe/tests.rs`, qui éprouve l'intégration du
//! Scribe en le consommant comme le fait `feu-application` — appels directs à
//! `ouverture_comptoir_depot`, `greffe_enfants`, `Enu::charger`… Un même cycle
//! peut donc apparaître des deux côtés : ici pour prouver qu'une commande le
//! câble, là pour éprouver le comportement câblé.
//!
//! Les constats, eux, lisent les champs privés de [`FeuApplication`] : le noyau
//! libéré, la session remise à zéro, le Scribe désactivé n'ont pas d'accesseur
//! public, et n'ont pas à en avoir — un consommateur n'a rien à faire de ces
//! états. D'où un `mod` interne plutôt qu'un crate de test dans `tests/` : on
//! agit par l'API publique, on constate par l'intérieur.

use std::{
    cell::RefCell,
    fs::{File, read_to_string, write},
};

use feu_noyau::BRAISE_VIDE;
use rand::{Rng, distributions::Alphanumeric};
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
    fn demander_mdp(&self) -> Option<SecretString> {
        Some(self.mot_de_passe.clone())
    }

    // Jetée : aucun test n'a besoin de relire la seed. La retenir demanderait un
    // second champ que rien ne consulterait.
    fn recevoir_seed(&self, _mots: &[&str]) {}

    // Sans confirmation, l'initialisation du noyau s'interromprait.
    fn confirmer_enregistrement_seed(&self) -> bool {
        true
    }

    fn recevoir_session_application(&self, session_application: Option<SessionApplication>) {
        *self.session_application.borrow_mut() = session_application;
    }
}

/// Chaîne alphanumérique aléatoire de `n` caractères, pour nommer et remplir
/// les fichiers de test.
///
/// `pub(crate)` — partagée avec `scribe/tests.rs`.
pub(crate) fn chaine_aleatoire(n: usize) -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}

/// Écrit dans `destination` un fichier au nom et au contenu aléatoires, et
/// rend les deux.
///
/// Les rendre tous les deux est ce qui permet de retrouver le fichier après
/// coup sans rien relire du disque : le nom se compare à la méta `nom` de
/// l'ENU, le contenu au clair déchiffré du blob.
pub(crate) fn nouveau_fichier(
    destination: &Path,
    nombre_caracteres: usize,
) -> ResultFeuApplication<(String, String)> {
    let nom_fichier = chaine_aleatoire(10);
    let contenu = chaine_aleatoire(nombre_caracteres);

    write(destination.join(&nom_fichier), contenu.clone()).unwrap();

    Ok((nom_fichier, contenu))
}

/// Cycle de vie complet du nœud par les commandes — allumage, ouverture de
/// foyer, ouverture de comptoir, extinction.
///
/// **Notification.** L'état est constaté sur la session reçue par
/// [`InterfaceTest`], jamais sur celle de [`FeuApplication`] : une assertion qui
/// passe prouve alors deux choses d'un coup — la commande a notifié, et le
/// payload portait l'état d'après. La braise non vide après l'allumage est
/// choisie pour ça : « foyers fermés » serait tout aussi vrai d'une session
/// neuve, et laisserait passer une notification vide.
///
/// **Garde.** [`commande_extinction_noeud`](FeuApplication::commande_extinction_noeud)
/// refuse tant qu'un foyer est ouvert, accepte une fois refermé. Les deux
/// moitiés comptent — un refus systématique passerait la première.
///
/// **Teardown.** La session notifiée vaut `None` après extinction et ne prouve
/// plus rien : les derniers constats passent par les champs. La doc de la
/// commande promet qu'aucune donnée applicative ne survit — braise et clés
/// publiques sont donc vérifiées une à une, pas seulement `feu_noyau = None`.
/// Le Scribe ferme la liste : `desactivation` est appelée en dernier, rien en
/// amont n'en dépend, sans cette assertion la supprimer ne casserait rien.
///
/// Le comptoir est ouvert puis **laissé ouvert** : l'extinction passe malgré
/// lui et l'annule, comme le documente
/// [`commande_ouverture_comptoir_depot`](FeuApplication::commande_ouverture_comptoir_depot).
/// Les fichiers déposés ne sont pas touchés pour autant, jamais ingérés.
#[test]
fn cycle_feu_application() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_depot = tmp.path().join("depot");

    let mut interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);
    assert!(interface_test.session_application().is_none());

    app.commande_allumage_noeud(&mut interface_test, None)?;
    assert_ne!(
        interface_test
            .session_application()
            .unwrap()
            .braise_foyer(0)?,
        BRAISE_VIDE
    );

    app.commande_ouverture_foyer(&mut interface_test, 0)?;
    assert!(
        interface_test
            .session_application()
            .unwrap()
            .etat_foyer(0)?,
    );

    app.commande_ouverture_comptoir_depot(chemin_depot, 0, 0)?;

    assert!(matches!(
        app.commande_extinction_noeud(&mut interface_test),
        Err(ErreurFeuApplication::AuMoinsUnFoyerOuvert)
    ));

    app.commande_fermeture_foyer(&mut interface_test, 0)?;
    assert!(
        !interface_test
            .session_application()
            .unwrap()
            .etat_foyer(0)?,
    );

    assert!(app.commande_extinction_noeud(&mut interface_test).is_ok());
    assert!(interface_test.session_application().is_none());

    // Plus rien à tirer de la session notifiée, désormais `None` : le teardown
    // ne se constate que sur les champs.
    assert_eq!(app.session.braise_foyer(0)?, BRAISE_VIDE);
    assert_eq!(app.session.cle_publique_sig_noeud(), [0u8; 2592]);
    assert_eq!(app.session.cle_publique_sig_foyer(0)?, [0u8; 2592]);
    assert!(app.session.foyers_fermes());
    assert!(!app.scribe.est_actif());

    Ok(())
}

/// Un fichier déposé par comptoir se relit à l'identique après extinction et
/// rallumage du nœud — nom et contenu.
///
/// Seul test qui **rallume**. Tout le reste de la suite vit dans un unique
/// allumage et ne prouve donc rien du disque : ce qu'il observe pourrait tenir
/// à un état gardé en mémoire. Ici l'instance est détruite entre les deux
/// moitiés, et la seconde ne repart que de `chemin_feu`.
///
/// **Racine.** L'assertion tient en deux temps. `assert_ne!` établit que ce que
/// `.DERNIERE_RACINE` désigne après rallumage est la racine d'*après* dépôt, et
/// non l'origine — sans quoi le test pourrait survivre à une greffe jamais
/// écrite sur disque. Le compte d'enfants à un ajoute que l'ancienne racine ne
/// s'y trouve pas : elle se chaîne par la méta `_racine`, pas comme enfant.
///
/// **Dépôt à la racine**, sans imbrication : la descente tient alors en un seul
/// [`commande_chargement_enu`](FeuApplication::commande_chargement_enu) jusqu'à
/// la [`Carte::Donnee`], et le test reste centré sur la survie de la donnée. Le
/// cas imbriqué relève du retrait, éprouvé côté Scribe.
#[test]
fn cycle_depot_extinction_rallumage() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_depot = tmp.path().join("depot");

    let mut interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&mut interface_test, None)?;

    app.commande_ouverture_foyer(&mut interface_test, 0)?;

    let index_comptoir = app.commande_ouverture_comptoir_depot(chemin_depot.clone(), 0, 0)?;
    assert_eq!(index_comptoir, 0);

    let (nom_fichier, contenu) = nouveau_fichier(&chemin_depot, 100)?;

    let enu_racine = app.commande_derniere_enu_racine()?;

    app.commande_fermeture_comptoir_depot(index_comptoir, &enu_racine)?;

    // le dossier physique du comptoir disparaît avec son rangement
    assert!(!chemin_depot.exists());

    app.commande_fermeture_foyer(&mut interface_test, 0)?;

    app.commande_extinction_noeud(&mut interface_test)?;

    // `drop` explicite : le shadowing seul garderait la première instance en vie
    // jusqu'à la fin du test, et le rallumage ne prouverait plus rien du disque
    drop(app);
    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&mut interface_test, None)?;

    app.commande_ouverture_foyer(&mut interface_test, 0)?;

    let nouvelle_racine = app.commande_derniere_enu_racine()?;

    assert_ne!(nouvelle_racine, enu_racine);
    assert_eq!(nouvelle_racine.carte().hashs_enu()?.len(), 1);

    let enu_rechargee = app
        .commande_chargement_enu(nouvelle_racine.carte().hashs_enu()?.first().unwrap())?
        .unwrap();

    assert_eq!(
        enu_rechargee.carte().metas().get("nom").unwrap(),
        &nom_fichier
    );

    // `create` et non `open` : la destination n'existe pas encore et doit être
    // ouverte en écriture, `commande_chargement_blob` réclamant un `Write`
    let chemin_relecture = tmp.path().join("relecture");
    let fichier = File::create(&chemin_relecture).unwrap();

    app.commande_chargement_blob(&enu_rechargee, &fichier)?;

    let contenu_relu = read_to_string(&chemin_relecture).unwrap();

    assert_eq!(contenu, contenu_relu);

    app.commande_fermeture_foyer(&mut interface_test, 0)?;

    app.commande_extinction_noeud(&mut interface_test)?;

    Ok(())
}
