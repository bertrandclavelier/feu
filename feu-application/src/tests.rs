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
//! Ils se distinguent en cela de `scribe/tests.rs`, qui appelle le Scribe en
//! direct — `greffe_enfants`, `Enu::charger`, `Enu::remplacer`…
//!
//! **Ce fichier prend ce qui y tombe sans montage supplémentaire** : un test
//! écrit ici prouve le comportement **et** son câblage.
//!
//! Les constats, eux, lisent les champs privés — noyau libéré, session remise à
//! zéro, Scribe désactivé n'ont pas d'accesseur public et n'ont pas à en avoir.
//! D'où un `mod` interne : on agit par l'API publique, on constate par
//! l'intérieur.
//!
//! # Non testé, délibérément
//!
//! `ScribeCarteMalFormee`, branche d'un `else` immédiat. Les `From`, `Display`
//! et accesseurs de champ, passe-plats. Le pont `RecepteurNoyau`, exercé de
//! biais — rien ne se signerait sans lui. Le contrat de notification, prouvé par
//! chaque assertion portant sur la session reçue. Huit des vingt-cinq commandes
//! publiques, dont `feu-noyau` éprouve déjà le comportement.

use std::{
    cell::RefCell,
    collections::HashSet,
    fs::{File, create_dir, read_to_string, remove_dir, write},
    mem::forget,
};

use data_encoding::HEXLOWER;
use feu_noyau::{BRAISE_VIDE, MAX_CLASSEURS, MAX_FOYERS};
use rand::{Rng, distributions::Alphanumeric};
use tempfile::TempDir;
use walkdir::WalkDir;

use crate::fiche::Fiche;

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

/// Chaîne alphanumérique aléatoire de `n` caractères, pour nommer et remplir
/// les fichiers de test.
///
/// `pub(crate)` — partagée avec `scribe/tests.rs`.
fn chaine_aleatoire(n: usize) -> String {
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
fn nouveau_fichier(destination: &Path, nombre_caracteres: usize) -> (String, String) {
    let nom_fichier = chaine_aleatoire(10);
    let contenu = chaine_aleatoire(nombre_caracteres);

    write(destination.join(&nom_fichier), contenu.clone()).unwrap();

    (nom_fichier, contenu)
}

/// Crée dans `destination` un dossier au nom aléatoire et rend son chemin.
///
/// Pendant de [`nouveau_fichier`], qui rend nom et contenu : ici le chemin
/// suffit — un dossier n'a rien à comparer après coup, il n'est qu'un endroit
/// où continuer à écrire.
fn nouveau_dossier(destination: &Path) -> PathBuf {
    let chemin = destination.join(chaine_aleatoire(10));

    create_dir(&chemin).unwrap();

    chemin
}

/// Peuple `chemin` d'une arborescence à trois niveaux : un fichier et un
/// dossier à la racine, ce dossier contenant lui-même un fichier et un
/// dossier, jusqu'à un troisième niveau ne contenant qu'un fichier.
///
/// Le Scribe traite différemment les enfants directs du comptoir (`depth == 1`)
/// et les sous-arbres plus profonds : la structure exerce les deux. Le
/// sous-dossier sert une seconde fois, sans rapport avec la profondeur — il est
/// la seule source d'`EnuR` signée sous une braise de foyer, la racine du nœud
/// portant `BRAISE_VIDE`.
///
/// Noms et contenus aléatoires : deux appels dans un même test ne se marchent
/// pas dessus.
fn remplir_dossier(chemin: &Path) -> ResultFeuApplication<()> {
    // Niveau 1
    // fichier 1
    nouveau_fichier(chemin, 100);

    // Dossier 1
    let chemin_dossier1 = nouveau_dossier(chemin);

    // Niveau 2
    // fichier 2
    nouveau_fichier(&chemin_dossier1, 100);

    // dossier 2
    let chemin_dossier2 = nouveau_dossier(&chemin_dossier1);

    // Niveau 3
    // fichier 3
    nouveau_fichier(&chemin_dossier2, 100);

    Ok(())
}

/// Dépose un dossier vide `documents` sous la racine du nœud et rend sa
/// [`Fiche`], en laissant le foyer 0 ouvert.
///
/// Seule voie par les commandes pour obtenir une EnuR : rien ne forge un
/// répertoire à la main, il naît d'un dossier réel importé par un comptoir de
/// dépôt. Or la racine du nœud ne peut pas servir de racine à un comptoir de
/// travail, qui exige donc ce préalable.
///
/// Le foyer reste ouvert : l'ouverture d'un comptoir de travail sort le
/// sous-arbre, ce qu'un foyer fermé refuse. À l'appelant de le fermer avant
/// l'extinction du nœud.
fn deposer_repertoire_sous_racine(
    app: &mut FeuApplication,
    interface_test: &InterfaceTest,
) -> ResultFeuApplication<Fiche> {
    let tmp = TempDir::new().unwrap();
    let chemin_comptoir_depot = tmp.path().join("comptoir_depot");

    let fiche_racine = Fiche::new(&app.scribe.derniere_enu_racine(&app.session)?);

    app.commande_ouverture_foyer(interface_test, 0)?;

    let index_comptoir =
        app.commande_ouverture_comptoir_depot(interface_test, &chemin_comptoir_depot, 0, 0)?;

    let chemin = chemin_comptoir_depot.join("documents");
    create_dir(&chemin)?;

    app.commande_fermeture_comptoir_depot(interface_test, index_comptoir, &fiche_racine)?;

    // le dossier vide est devenu l'unique EnuR enfant de la nouvelle racine
    let racine = app.commande_derniere_enu_racine()?;
    for h in racine.carte().hashs_enu().into_iter().flatten() {
        let fiche = app.commande_chargement_enu(h)?.unwrap();
        if fiche.carte().metas()["nom"] == "documents" {
            return Ok(fiche);
        }
    }
    panic!("le dossier déposé est introuvable sous la racine")
}

/// Relit récursivement `chemin` en un ensemble `(chemin relatif, contenu)`,
/// un par fichier — les dossiers n'ont pas d'entrée propre, leur chemin relatif
/// dans celui de leurs fichiers suffit à les distinguer.
///
/// Sert à comparer deux arborescences sans dépendre de l'ordre de parcours,
/// notamment le contenu d'un comptoir avant fermeture face à celui d'un
/// retrait après coup — l'ordre des enfants dans l'arbre ENU suit les hashs,
/// pas les noms.
fn lire_arborescence(chemin: &Path) -> ResultFeuApplication<HashSet<(PathBuf, String)>> {
    let mut resultat = HashSet::new();

    for entree in WalkDir::new(chemin).min_depth(1) {
        let entree = entree.unwrap();

        if entree.file_type().is_file() {
            let chemin_relatif = entree.path().strip_prefix(chemin).unwrap().to_path_buf();
            let contenu = read_to_string(entree.path()).unwrap();
            resultat.insert((chemin_relatif, contenu));
        }
    }

    Ok(resultat)
}

/// Cycle de vie complet du nœud par les commandes — du refus avant allumage
/// au teardown après extinction.
///
/// L'état est constaté sur la session **reçue par [`InterfaceTest`]**, jamais
/// sur celle de [`FeuApplication`] : une assertion qui passe prouve alors que la
/// commande a notifié, et que le payload portait l'état d'après.
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
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_depot, 0, 0),
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
            .braise_foyer(0)
            .unwrap(),
        BRAISE_VIDE
    );

    app.commande_ouverture_foyer(&interface_test, 0)?;
    assert!(
        interface_test
            .session_application()
            .unwrap()
            .etat_foyer(0)
            .unwrap(),
    );

    app.commande_ouverture_comptoir_depot(&interface_test, &chemin_depot, 0, 0)?;

    // L'extinction bute d'abord sur le foyer 0, encore ouvert.
    assert!(matches!(
        app.commande_extinction_noeud(&interface_test),
        Err(ErreurFeuApplication::AuMoinsUnFoyerOuvert)
    ));

    app.commande_fermeture_foyer(&interface_test, 0)?;
    assert!(
        !interface_test
            .session_application()
            .unwrap()
            .etat_foyer(0)
            .unwrap(),
    );

    assert!(app.commande_extinction_noeud(&interface_test).is_ok());
    assert!(interface_test.session_application().is_none());
    assert!(matches!(
        app.commande_chargement_enu(&[0u8; 32]),
        Err(ErreurFeuApplication::NoeudEteint)
    ));

    // Plus rien à tirer de la session notifiée, désormais `None` : le teardown
    // ne se constate que sur les champs.
    assert_eq!(app.session.braise_foyer(0).unwrap(), BRAISE_VIDE);
    assert_eq!(app.session.cle_publique_sig_noeud(), [0u8; 2592]);
    assert_eq!(app.session.cle_publique_sig_foyer(0).unwrap(), [0u8; 2592]);
    assert!(app.session.foyers_fermes());
    assert!(!app.scribe.est_actif());

    Ok(())
}

/// Un fichier déposé par comptoir se relit à l'identique après extinction et
/// rallumage du nœud — nom et contenu.
///
/// **Seul test qui rallume sur des données déposées** — `persistance_comptoir_depot`
/// et `persistance_comptoir_travail` rallument aussi, mais ne portent que sur
/// l'état des comptoirs. Ici l'instance est détruite entre les deux moitiés, et
/// la seconde ne repart que de `chemin_feu`.
#[test]
fn cycle_depot_extinction_rallumage() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_depot = tmp.path().join("depot");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let index_comptoir =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_depot, 0, 0)?;
    assert_eq!(index_comptoir, 0);

    let (nom_fichier, contenu) = nouveau_fichier(&chemin_depot, 100);

    let enu_racine = app.commande_derniere_enu_racine()?;

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine)?;

    // le dossier physique du comptoir disparaît avec son rangement
    assert!(!chemin_depot.exists());

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    // `drop` explicite : le shadowing seul garderait la première instance en vie
    // jusqu'à la fin du test, et le rallumage ne prouverait plus rien du disque
    drop(app);
    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let nouvelle_racine = app.commande_derniere_enu_racine()?;

    assert_ne!(nouvelle_racine, enu_racine);
    assert_eq!(nouvelle_racine.carte().hashs_enu().unwrap().len(), 1);

    let enu_rechargee = app
        .commande_chargement_enu(
            nouvelle_racine
                .carte()
                .hashs_enu()
                .unwrap()
                .first()
                .unwrap(),
        )?
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

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Cycle de vie d'un blob désigné par sa seule ENU — présence, informations,
/// suppression — et ce qu'il advient de l'ENU quand le blob n'est plus là.
///
/// **Le sujet est la fin** : `existence_blob` faux et `chargement_enu` encore
/// `Some` sur le même hash — le blob est parti, l'arborescence est intacte.
/// C'est leur simultanéité qui prouve le décalage.
///
/// Éprouve au passage la braise inconnue, qu'une racine seule peut produire sans
/// forger d'ENU, et la taille du chiffré, strictement supérieure au clair.
#[test]
fn cycle_vie_blob() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_depot = tmp.path().join("depot");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let index_comptoir =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_depot, 0, 0)?;
    assert_eq!(index_comptoir, 0);

    nouveau_fichier(&chemin_depot, 100);

    let enu_racine = app.commande_derniere_enu_racine()?;

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine)?;

    let nouvelle_racine = app.commande_derniere_enu_racine()?;

    let enu_rechargee = app
        .commande_chargement_enu(
            nouvelle_racine
                .carte()
                .hashs_enu()
                .unwrap()
                .first()
                .unwrap(),
        )?
        .unwrap();

    assert!(app.commande_existence_blob(&enu_rechargee)?);

    let taille_blob = app
        .commande_informations_blob(&enu_rechargee)?
        .donne_taille();

    // Le chiffré pèse plus que les cent caractères déposés.
    assert!(taille_blob > 100);

    // Un hash inconnu rend une absence, pas une erreur.
    assert!(matches!(app.commande_chargement_enu(&[0u8; 32]), Ok(None)));

    // La racine du nœud porte `BRAISE_VIDE`, qu'aucun foyer ne résout.
    assert!(matches!(
        app.commande_existence_blob(&enu_racine),
        Err(ErreurFeuApplication::ScribeBraiseInconnue)
    ));

    // Le blob part, sa carte reste : c'est ce décalage que le test vise.
    app.commande_suppression_blob(&enu_rechargee)?;

    assert!(!app.commande_existence_blob(&enu_rechargee)?);

    assert!(
        app.commande_chargement_enu(&enu_rechargee.hash_carte())?
            .is_some()
    );

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Les gardes du comptoir de dépôt, dans l'ordre où elles se posent.
///
/// Les index sont validés à l'ouverture, qui les fige ; la fermeture oppose
/// trois refus, dont le seul rattrapable — foyer refermé entre-temps.
///
/// Établit aussi que le **miroir de session suit le Scribe** sur chacun de ces
/// chemins : présent tant que le comptoir l'est, parti dès qu'il l'a lâché.
#[test]
fn cycle_ouverture_fermeture_comptoir() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let dossier_temporaire = TempDir::new().unwrap();

    let enu_racine = app.commande_derniere_enu_racine()?;

    //
    // Premier dépôt vide
    //
    let chemin_comptoir1 = dossier_temporaire.path().join("comptoir_depot1");

    assert!(matches!(
        app.commande_ouverture_comptoir_depot(
            &interface_test,
            &chemin_comptoir1,
            MAX_FOYERS + 1,
            0
        ),
        Err(ErreurFeuApplication::ScribeIndexFoyerInvalide(_))
    ));
    assert!(matches!(
        app.commande_ouverture_comptoir_depot(
            &interface_test,
            &chemin_comptoir1,
            0,
            MAX_CLASSEURS + 1
        ),
        Err(ErreurFeuApplication::ScribeIndexClasseurInvalide(_))
    ));

    let index_comptoir =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir1, 0, 0)?;
    assert_eq!(index_comptoir, 0);
    assert!(
        app.session
            .comptoirs_depot_ouverts()
            .contains_key(&index_comptoir)
    );

    app.commande_fermeture_foyer(&interface_test, 0)?;

    assert!(matches!(
        app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine),
        Err(ErreurFeuApplication::ScribeFoyerFerme(_))
    ));
    // le foyer fermé tombe avant le retrait : l'identifiant reste des deux côtés, sans
    // quoi la retentative qui suit n'aurait plus rien à désigner
    assert!(
        app.session
            .comptoirs_depot_ouverts()
            .contains_key(&index_comptoir)
    );

    app.commande_ouverture_foyer(&interface_test, 0)?;

    // L'index 1 n'a jamais été attribué : le Scribe ne connaît que le zéro.
    assert!(matches!(
        app.commande_fermeture_comptoir_depot(&interface_test, 1, &enu_racine),
        Err(ErreurFeuApplication::ScribeIndexComptoirInconnu(_))
    ));

    // Le dossier du comptoir est effacé sous les pieds du Scribe.
    remove_dir(&chemin_comptoir1).unwrap();

    assert!(matches!(
        app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine),
        Err(ErreurFeuApplication::ScribeDossierDepotIntrouvable(_))
    ));
    // le dossier disparu est constaté après le retrait : le Scribe a lâché le comptoir, la
    // session l'a lâché avec lui, sur un chemin qui rend pourtant une erreur
    assert!(app.session.comptoirs_depot_ouverts().is_empty());

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    assert!(app.session.comptoirs_depot_ouverts().is_empty());

    Ok(())
}

/// Aller-retour complet dépôt par comptoir → retrait, sur une arborescence à
/// plusieurs niveaux : ce qui ressort est exactement ce qui est entré.
///
/// Couvre dans l'ordre le comptoir vide, qui ne bouge pas la racine et rend son
/// identifiant au suivant, le dépôt d'une arborescence à trois niveaux, le refus
/// d'un retrait vers un dossier existant, le retrait nominal — comparé en
/// ensembles, l'ordre de parcours n'étant pas garanti — et l'ENU répertoire
/// passée à une commande blob.
///
/// **Ce dernier refus tient ici et nulle part ailleurs** : il lui faut une carte
/// répertoire signée sous une **braise de foyer**, que seul un dépôt imbriqué
/// produit — la racine, elle, tombe plus tôt sur sa braise inconnue.
#[test]
fn cycle_depot_retrait_simple() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let dossier_temporaire = TempDir::new().unwrap();

    let enu_racine = app.commande_derniere_enu_racine()?;

    //
    // Premier dépôt vide
    //
    let chemin_comptoir1 = dossier_temporaire.path().join("comptoir_depot1");

    let index_comptoir1 =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir1, 0, 0)?;

    // Fermeture comptoir vide
    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir1, &enu_racine)?;

    let deuxieme_enu_racine = app.commande_derniere_enu_racine()?;

    // Pas de nouvelle racine
    assert_eq!(enu_racine, deuxieme_enu_racine);

    //
    // Deuxième dépôt non vide
    //
    let chemin_comptoir2 = dossier_temporaire.path().join("comptoir_depot2");

    let index_comptoir2 =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir2, 0, 0)?;
    assert_eq!(index_comptoir2, 0);

    remplir_dossier(&chemin_comptoir2)?;

    let arborescence_origine = lire_arborescence(&chemin_comptoir2)?;

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir2, &enu_racine)?;

    let deuxieme_enu_racine = app.commande_derniere_enu_racine()?;

    assert_eq!(
        deuxieme_enu_racine.carte().metas().get("_racine"),
        Some(&HEXLOWER.encode(&enu_racine.hash_carte()))
    );

    //
    // Premier retrait avec un chemin déjà existant
    //
    let dossier_temporaire2 = TempDir::new().unwrap();

    assert!(matches!(
        app.commande_retrait_lecture_seule(dossier_temporaire2.path(), &deuxieme_enu_racine),
        Err(ErreurFeuApplication::ScribeDossierDejaExistant(_))
    ));

    //
    // Deuxième retrait avec un chemin correct
    //
    let chemin_retrait = dossier_temporaire.path().join("retrait");

    app.commande_retrait_lecture_seule(&chemin_retrait, &deuxieme_enu_racine)?;

    let arborescence_relue = lire_arborescence(&chemin_retrait)?;

    // Les deux arborescences doivent être identiques
    assert_eq!(arborescence_origine, arborescence_relue);

    // Récupération de l'EnuR sous la racine
    let hashs = &mut deuxieme_enu_racine.carte().hashs_enu().unwrap().clone();
    assert_eq!(hashs.len(), 2);

    let enu1 = app
        .commande_chargement_enu(&hashs.pop_first().unwrap())?
        .unwrap();
    let enu2 = app
        .commande_chargement_enu(&hashs.pop_first().unwrap())?
        .unwrap();

    // Des deux ENU sous la racine, l'EnuR est celle dont la carte est répertoire.
    let enur = if matches!(
        enu1.carte(),
        Carte::Repertoire {
            metas: _,
            tags: _,
            hashs_enu: _
        }
    ) {
        enu1
    } else {
        enu2
    };

    // Une commande blob refuse une carte répertoire.
    assert!(matches!(
        app.commande_existence_blob(&enur),
        Err(ErreurFeuApplication::ScribeEnuDAttendue)
    ));

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Aller-retour de deux `EnuT` **homonymes** déposées à la racine du nœud —
/// dépôt, relecture des cartes, puis matérialisation sur disque.
///
/// **Deux dépôts, trois racines** : le second part de la racine rendue *après*
/// le premier, faute de quoi le premier texte finirait orphelin.
///
/// **Foyer 1 sous une racine signée par le nœud** : les deux braises relevées
/// distinguent le foyer du texte de celui du répertoire d'accueil.
///
/// **Le suffixe est posé au dépôt, pas au retrait** : le second texte porte
/// déjà `test_1` en méta. Rien ne dit lequel des deux hashs sort en premier,
/// d'où la comparaison par ensembles.
///
/// Couvre aussi la carte texte, branche du retrait jamais atteinte ailleurs.
#[test]
fn cycle_enu_texte() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 1)?;

    let enu_racine = app.commande_derniere_enu_racine()?;

    app.commande_depot_enu_texte(&enu_racine, 1, "test", "enu test 1")?;
    let deuxieme_enu_racine = app.commande_derniere_enu_racine()?;
    app.commande_depot_enu_texte(&deuxieme_enu_racine, 1, "test", "enu test 2")?;
    let troisieme_enu_racine = app.commande_derniere_enu_racine()?;

    let hashs = &mut troisieme_enu_racine.carte().hashs_enu().unwrap().clone();
    assert_eq!(hashs.len(), 2);

    let enu1 = app
        .commande_chargement_enu(&hashs.pop_first().unwrap())?
        .unwrap();
    let enu2 = app
        .commande_chargement_enu(&hashs.pop_first().unwrap())?
        .unwrap();

    let Carte::Texte {
        metas: metas1,
        tags: _,
        contenu: contenu1,
    } = enu1.carte()
    else {
        panic!()
    };
    let Carte::Texte {
        metas: metas2,
        tags: _,
        contenu: contenu2,
    } = enu2.carte()
    else {
        panic!()
    };

    let noms = HashSet::from([metas1["nom"].as_str(), metas2["nom"].as_str()]);
    assert_eq!(noms, HashSet::from(["test", "test_1"]));

    // Les deux textes portent la braise du foyer 1, pas celle de leur racine.
    assert_eq!(enu1.braise(), app.session.braise_foyer(1).unwrap());
    assert_eq!(enu2.braise(), app.session.braise_foyer(1).unwrap());

    let contenus = HashSet::from([contenu1.as_str(), contenu2.as_str()]);
    assert_eq!(contenus, HashSet::from(["enu test 1", "enu test 2"]));

    // Un dépôt sous une `EnuT` est refusé : l'accueil est réservé aux racines.
    assert!(matches!(
        app.commande_depot_enu_texte(&enu1, 1, "test", "enu test 3"),
        Err(ErreurFeuApplication::ScribeEnuRAttendue)
    ));

    let chemin_retrait = tmp.path().join("retrait");
    app.commande_retrait_lecture_seule(&chemin_retrait, &troisieme_enu_racine)?;

    // Homonymes sur disque : le second sort suffixé.
    let mut contenus = [
        read_to_string(chemin_retrait.join("test")).unwrap(),
        read_to_string(chemin_retrait.join("test_1")).unwrap(),
    ];
    contenus.sort();

    assert_eq!(contenus, ["enu test 1", "enu test 2"]);

    app.commande_fermeture_foyer(&interface_test, 1)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Le parcours descendant rend tout le sous-arbre, sa forme et ses profondeurs,
/// **foyer fermé**.
///
/// Le nœud est éteint et rallumé avant le moindre parcours : refermer le foyer
/// n'aurait pas suffi, sa clé publique survivant à la fermeture.
///
/// La forme de l'arbre est établie en relançant un parcours sur chaque ENU
/// rendue — la suite triée des tailles de sous-arbres vaut `[1, 1, 1, 2, 4, 6]`,
/// une seule forme derrière. Les profondeurs triées valent `[0, 1, 1, 2, 2, 3]`.
///
/// **N'établit pas l'ordre du parcours** : l'arbre est une chaîne, où un parcours
/// en largeur produirait la même séquence.
#[test]
fn descendants() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    let enu_racine = app.commande_derniere_enu_racine()?;

    let descendants: Vec<(usize, Fiche)> =
        app.commande_descendants(&enu_racine)?.flatten().collect();
    assert_eq!(descendants.len(), 1);
    assert_eq!(descendants[0].0, 0);

    let fiche = &descendants[0].1;

    assert_eq!(fiche.hash_carte(), enu_racine.hash_carte());

    app.commande_ouverture_foyer(&interface_test, 1)?;

    let dossier_temporaire = TempDir::new().unwrap();

    let chemin_comptoir = dossier_temporaire.path().join("comptoir_depot");

    let index_comptoir =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir, 1, 0)?;

    remplir_dossier(&chemin_comptoir)?;

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine)?;

    // Extinction plutôt que simple fermeture : la session repart vierge, sans la
    // clé publique du foyer qu'une fermeture aurait laissée en place.
    app.commande_fermeture_foyer(&interface_test, 1)?;
    app.commande_extinction_noeud(&interface_test)?;
    app.commande_allumage_noeud(&interface_test, None)?;
    let deuxieme_enu_racine = app.commande_derniere_enu_racine()?;

    let descendants: Vec<(usize, Fiche)> = app
        .commande_descendants(&deuxieme_enu_racine)?
        .flatten()
        .collect();

    let mut profondeurs: Vec<usize> = descendants
        .iter()
        .map(|(profondeur, _)| *profondeur)
        .collect();

    profondeurs.sort();

    assert_eq!(profondeurs, [0, 1, 1, 2, 2, 3]);

    // Taille du sous-arbre de chaque ENU rendue, dans l'ordre du parcours.
    let mut tailles: Vec<usize> = descendants
        .iter()
        .map(|(_, fiche)| app.commande_descendants(fiche).unwrap().count())
        .collect();

    // Triées, les mêmes tailles fixent la forme de l'arbre.
    tailles.sort();

    assert_eq!(tailles, [1, 1, 1, 2, 4, 6]);

    assert_eq!(descendants[0].0, 0);
    assert_eq!(
        descendants[0].1.hash_carte(),
        deuxieme_enu_racine.hash_carte()
    );

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Le parcours remontant suit la chaîne des racines jusqu'à la genèse.
///
/// Sur un nœud neuf, un seul item — la genèse, qui prouve la terminaison. Après
/// dix dépôts, onze racines, chaînées paire à paire par leur méta `_racine` :
/// c'est ce chaînage qui distingue le parcours d'une lecture du dossier `enu/`.
///
/// **Le nombre d'enfants décroît de dix à zéro**, ce qui établit le sens de la
/// remontée pour bien moins cher qu'un descendant par racine.
#[test]
fn racines_anterieures() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    let enu_racine = app.commande_derniere_enu_racine()?;

    let racines: Vec<ResultFeuApplication<Fiche>> =
        app.commande_racines_anterieures(&enu_racine)?.collect();
    assert_eq!(racines.len(), 1);

    let enu = racines[0].as_ref().unwrap();
    assert_eq!(enu, &enu_racine);

    app.commande_ouverture_foyer(&interface_test, 1)?;

    // Chaque dépôt remplace la racine du nœud et allonge la chaîne d'un maillon.
    for i in 0..10 {
        let enu_racine = app.commande_derniere_enu_racine()?;
        app.commande_depot_enu_texte(&enu_racine, 1, &format!("fichier{}", i), "contenu")?;
    }

    app.commande_fermeture_foyer(&interface_test, 1)?;

    let enu_racine = app.commande_derniere_enu_racine()?;
    let racines: Vec<Fiche> = app
        .commande_racines_anterieures(&enu_racine)?
        .flatten()
        .collect();

    assert_eq!(racines.len(), 11);

    // Chaque racine désigne la suivante par sa méta `_racine`, en hexadécimal.
    for paire in racines.windows(2) {
        assert_eq!(
            paire[0].carte().metas()["_racine"],
            HEXLOWER.encode(&paire[1].hash_carte())
        );
    }

    assert!(racines.last().unwrap().carte().metas()["_racine"].is_empty());

    // Un texte de plus à chaque version : la décroissance dit le sens du parcours.
    let nombre_filles: Vec<_> = racines
        .iter()
        .map(|enu| enu.carte().hashs_enu().unwrap().len())
        .collect();

    assert_eq!(nombre_filles, [10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

    app.commande_extinction_noeud(&interface_test)?;
    Ok(())
}

/// Un foyer laissé ouvert par une terminaison brutale se referme par
/// [`FeuApplication::commande_secours_fermeture_foyer`], et redevient ouvrable
/// ensuite.
///
/// L'état instable est monté par [`forget`](std::mem::forget), qui reproduit ce
/// que laisse un processus tué. Un second foyer, sain, reste utilisable pendant
/// ce temps. Chaque constat lit la session notifiée : le secours doit la publier
/// comme n'importe quelle commande.
#[test]
fn secours_fermeture_foyer() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 1)?;

    // Terminaison brutale : aucun `Drop` ne passe, le dossier clair survit.
    forget(app);

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    // Le foyer 0, intact, s'ouvre malgré le foyer 1 resté en vrac.
    app.commande_ouverture_foyer(&interface_test, 0)?;

    assert!(
        !interface_test
            .session_application()
            .unwrap()
            .etat_foyer(1)
            .unwrap(),
    );

    // L'archive `.feu`, consommée à la première ouverture, ne peut plus se rouvrir.
    assert!(matches!(
        app.commande_ouverture_foyer(&interface_test, 1),
        Err(ErreurFeuApplication::FeuNoyau(_))
    ));

    app.commande_secours_fermeture_foyer(&interface_test, 1)?;

    assert!(
        !interface_test
            .session_application()
            .unwrap()
            .etat_foyer(1)
            .unwrap(),
    );

    // La réparation se prouve ici : le foyer 1 s'ouvre de nouveau.
    app.commande_ouverture_foyer(&interface_test, 1)?;

    assert!(
        interface_test
            .session_application()
            .unwrap()
            .etat_foyer(1)
            .unwrap(),
    );

    app.commande_fermeture_foyer(&interface_test, 0)?;
    app.commande_fermeture_foyer(&interface_test, 1)?;
    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// La garde du retrait refuse tant qu'un foyer du sous-arbre est fermé, et rend
/// la main sans avoir rien écrit.
///
/// Deux foyers alimentent le même arbre : la liste rendue nomme exactement ceux
/// qui manquent, et se réduit à mesure qu'on les rouvre.
///
/// **Seul test dont le sous-arbre mêle plusieurs braises.** Partout ailleurs
/// tout est ouvert, et la pré-passe passerait même si elle ne regardait que la
/// racine.
#[test]
fn retrait_foyer_ferme() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;
    app.commande_ouverture_foyer(&interface_test, 1)?;

    let dossier_temporaire = TempDir::new().unwrap();

    let enu_racine = app.commande_derniere_enu_racine()?;

    // Le premier dépôt est signé sous le foyer 0.
    let chemin_comptoir = dossier_temporaire.path().join("comptoir_depot");

    let index_comptoir =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir, 0, 0)?;

    remplir_dossier(&chemin_comptoir)?;

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine)?;

    let deuxieme_enu_racine = app.commande_derniere_enu_racine()?;

    // Le second est signé sous le foyer 1, greffé sur la racine rendue par le premier.
    let chemin_comptoir2 = dossier_temporaire.path().join("comptoir_depot2");

    let index_comptoir2 =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir2, 1, 0)?;

    remplir_dossier(&chemin_comptoir2)?;

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir2, &deuxieme_enu_racine)?;

    let troisieme_enu_racine = app.commande_derniere_enu_racine()?;

    // Les deux foyers refermés : plus une braise du sous-arbre ne se résout.
    app.commande_fermeture_foyer(&interface_test, 0)?;
    app.commande_fermeture_foyer(&interface_test, 1)?;

    // Chemin encore inexistant : le dossier ne doit naître que d'un retrait abouti.
    let dossier_temporaire2 = TempDir::new().unwrap();
    let chemin_retrait = dossier_temporaire2.path().join("retrait");

    let Err(ErreurFeuApplication::ScribeFoyersFermes(liste_fermes)) =
        app.commande_retrait_lecture_seule(&chemin_retrait, &troisieme_enu_racine)
    else {
        panic!("Le retrait aurait dû renvoyer une erreur");
    };

    assert_eq!(liste_fermes, vec![0, 1]);
    assert!(!chemin_retrait.exists());

    // Un seul foyer rouvert : la liste se réduit à celui qui manque encore.
    app.commande_ouverture_foyer(&interface_test, 0)?;

    let Err(ErreurFeuApplication::ScribeFoyersFermes(liste_fermes)) =
        app.commande_retrait_lecture_seule(&chemin_retrait, &troisieme_enu_racine)
    else {
        panic!("Le retrait aurait dû renvoyer une erreur");
    };

    assert_eq!(liste_fermes, vec![1]);
    assert!(!chemin_retrait.exists());

    // Les deux foyers ouverts, le retrait passe : la garde ne refuse pas à tort.
    app.commande_ouverture_foyer(&interface_test, 1)?;

    app.commande_retrait_lecture_seule(&chemin_retrait, &troisieme_enu_racine)?;

    app.commande_fermeture_foyer(&interface_test, 0)?;
    app.commande_fermeture_foyer(&interface_test, 1)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Déposer sous une racine qui n'est plus la dernière est refusé, et ne produit
/// aucune version.
///
/// La voie `BRAISE_VIDE` de `greffe_enfants` : sans le refus, la nouvelle racine
/// repartirait d'une carte périmée et perdrait tout ce qui a été déposé depuis.
#[test]
fn depot_dans_racine_perimee() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let enu_racine1 = app.commande_derniere_enu_racine()?;

    // Ce dépôt fait de enu_racine1 une racine périmée.
    app.commande_depot_enu_texte(&enu_racine1, 0, "enu texte 1", "test")?;

    let enu_racine2 = app.commande_derniere_enu_racine()?;

    assert!(matches!(
        app.commande_depot_enu_texte(&enu_racine1, 0, "enu texte 2", "test"),
        Err(ErreurFeuApplication::ScribeRacinePerimee)
    ));

    let enu_racine3 = app.commande_derniere_enu_racine()?;

    assert_eq!(enu_racine3.hash_carte(), enu_racine2.hash_carte());

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Déposer sous un répertoire de foyer sorti de l'arbre courant est refusé, et
/// ne produit aucune version.
///
/// L'autre voie de `greffe_enfants`, celle qui passe par [`Enu::remplacer`] :
/// la cible absente laissait forger une racine identique à la précédente, un
/// maillon mort dans la lignée des `_racine`.
#[test]
fn depot_dans_enur_perimee() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let enu_racine1 = app.commande_derniere_enu_racine()?;

    let dossier_temporaire = TempDir::new().unwrap();
    let chemin_comptoir = dossier_temporaire.path().join("comptoir_depot");

    let index_comptoir =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir, 0, 0)?;

    // Un dossier et rien d'autre : la racine n'aura qu'un enfant, le répertoire
    // de foyer que le test vise.
    create_dir(chemin_comptoir.join("test")).unwrap();

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine1)?;

    let enu_racine2 = app.commande_derniere_enu_racine()?;

    let fiche = app
        .commande_chargement_enu(enu_racine2.carte().hashs_enu().unwrap().first().unwrap())
        .unwrap()
        .unwrap();

    // Ce dépôt remplace le répertoire : la fiche en main sort de l'arbre.
    app.commande_depot_enu_texte(&fiche, 0, "enu texte 1", "test")?;

    let enu_racine3 = app.commande_derniere_enu_racine()?;

    assert!(matches!(
        app.commande_depot_enu_texte(&fiche, 0, "enu texte 2", "test"),
        Err(ErreurFeuApplication::ScribeRemplacementSansEffet)
    ));

    let enu_racine4 = app.commande_derniere_enu_racine()?;

    assert_eq!(enu_racine3.hash_carte(), enu_racine4.hash_carte());

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// L'ouverture d'un comptoir de travail sort le sous-arbre et retient le
/// dossier avec sa racine, que la session donne à lire.
///
/// La sortie elle-même n'est pas éprouvée ici : elle est celle du retrait, que
/// [`cycle_depot_retrait_simple`] couvre avec du contenu.
#[test]
fn ouverture_comptoir_travail_normal() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_comptoir = tmp.path().join("comptoir");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    let fiche_racine = deposer_repertoire_sous_racine(&mut app, &interface_test)?;

    app.commande_ouverture_comptoir_travail(&interface_test, &chemin_comptoir, &fiche_racine)?;

    assert!(chemin_comptoir.exists());

    let (chemin, fiche) = app.session.comptoir_travail_ouvert().unwrap();

    assert_eq!(chemin, &chemin_comptoir);
    assert_eq!(fiche.hash_carte(), fiche_racine.hash_carte());

    app.commande_fermeture_foyer(&interface_test, 0)?;
    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Un comptoir de dépôt ouvert interdit l'ouverture du comptoir de travail.
///
/// La garde tombe avant le retrait : le dossier de travail n'est pas créé.
#[test]
fn ouverture_comptoir_travail_depot_deja_ouvert() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_comptoir_depot = tmp.path().join("comptoir_depot");
    let chemin_comptoir_travail = tmp.path().join("comptoir_travail");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    let fiche_racine = deposer_repertoire_sous_racine(&mut app, &interface_test)?;

    app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir_depot, 0, 0)?;

    assert!(matches!(
        app.commande_ouverture_comptoir_travail(
            &interface_test,
            &chemin_comptoir_travail,
            &fiche_racine,
        ),
        Err(ErreurFeuApplication::ScribeComptoirDepotOuvert)
    ));

    app.commande_fermeture_foyer(&interface_test, 0)?;
    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Comptoir de travail ouvert, plus rien ne s'ouvre — ni un second comptoir de
/// travail, ni un comptoir de dépôt — et plus rien ne s'écrit : dépôt de texte
/// et suppression de blob sont refusés eux aussi.
///
/// La suppression vise la racine, qui n'a pas de blob : c'est le refus du verrou
/// qui remonte, donc il tombe avant la résolution de la cible.
#[test]
fn exclusivite_comptoir_travail() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_comptoir_travail1 = tmp.path().join("comptoir_travail1");
    let chemin_comptoir_travail2 = tmp.path().join("comptoir_travail2");
    let chemin_comptoir_depot = tmp.path().join("comptoir_depot");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    let fiche_racine = deposer_repertoire_sous_racine(&mut app, &interface_test)?;

    app.commande_ouverture_comptoir_travail(
        &interface_test,
        &chemin_comptoir_travail1,
        &fiche_racine,
    )?;

    assert!(matches!(
        app.commande_ouverture_comptoir_travail(
            &interface_test,
            &chemin_comptoir_travail2,
            &fiche_racine,
        ),
        Err(ErreurFeuApplication::ScribeComptoirTravailOuvert)
    ));

    assert!(matches!(
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir_depot, 0, 0),
        Err(ErreurFeuApplication::ScribeComptoirTravailOuvert)
    ));

    assert!(matches!(
        app.commande_depot_enu_texte(&fiche_racine, 0, "test", "contenu de test"),
        Err(ErreurFeuApplication::ScribeComptoirTravailOuvert)
    ));

    assert!(matches!(
        app.commande_suppression_blob(&fiche_racine),
        Err(ErreurFeuApplication::ScribeComptoirTravailOuvert)
    ));

    app.commande_fermeture_foyer(&interface_test, 0)?;
    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Les comptoirs de dépôt survivent à la perte de l'instance : `scribe.feu` les
/// porte, et le rallumage sur une application neuve les rend au miroir de
/// session avec leurs identifiants et leurs destinations.
#[test]
fn persistance_comptoir_depot() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_comptoir_depot1 = tmp.path().join("comptoir_depot1");
    let chemin_comptoir_depot2 = tmp.path().join("comptoir_depot2");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);
    app.commande_allumage_noeud(&interface_test, None)?;

    let id1 =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir_depot1, 1, 0)?;
    let id2 =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir_depot2, 0, 1)?;

    drop(app);

    let mut app = FeuApplication::new(&chemin_feu);
    app.commande_allumage_noeud(&interface_test, None)?;

    let comptoir1_relu = app.session.comptoirs_depot_ouverts().get(&id1).unwrap();
    let comptoir2_relu = app.session.comptoirs_depot_ouverts().get(&id2).unwrap();

    assert_eq!(comptoir1_relu.0, chemin_comptoir_depot1);
    assert_eq!(comptoir2_relu.0, chemin_comptoir_depot2);
    assert_eq!(comptoir1_relu.1, 1);
    assert_eq!(comptoir2_relu.1, 0);
    assert_eq!(comptoir1_relu.2, 0);
    assert_eq!(comptoir2_relu.2, 1);

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Le comptoir de travail survit à la perte de l'instance : `scribe.feu` retient
/// son chemin et sa racine sortie, que le rallumage relit et rend au miroir de
/// session, la fiche revenant égale à celle qui l'a ouvert.
#[test]
fn persistance_comptoir_travail() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_comptoir_travail = tmp.path().join("comptoir_travail");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);
    app.commande_allumage_noeud(&interface_test, None)?;

    let fiche_racine = deposer_repertoire_sous_racine(&mut app, &interface_test)?;

    app.commande_ouverture_comptoir_travail(
        &interface_test,
        &chemin_comptoir_travail,
        &fiche_racine,
    )?;

    app.commande_fermeture_foyer(&interface_test, 0)?;
    drop(app);

    let mut app = FeuApplication::new(&chemin_feu);
    app.commande_allumage_noeud(&interface_test, None)?;

    let comptoir_travail = app.session.comptoir_travail_ouvert().unwrap();

    assert_eq!(comptoir_travail.0, chemin_comptoir_travail);
    assert_eq!(comptoir_travail.1, fiche_racine);

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}
