// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Tests des comptoirs, pilotés par les seules `commande_*`.
//!
//! Ce qui sert aux deux cibles vit dans `commun`, que chacune déclare pour
//! elle-même.

use std::fs::{File, create_dir, read_to_string, remove_dir, remove_dir_all, write};

use data_encoding::HEXLOWER;
use feu_application::{
    Carte, ErreurFeuApplication, FeuApplication, ResultFeuApplication, fiche::Fiche,
};
use feu_noyau::{MAX_CLASSEURS, MAX_FOYERS};
use tempfile::TempDir;

use crate::commun::{
    InterfaceTest, donne_fiche_descendant, lire_arborescence, nouveau_fichier, remplir_dossier,
};

mod commun;

/// Dépose un dossier vide `documents` sous la racine du nœud et rend sa
/// [`Fiche`].
///
/// Seule voie par les commandes vers une EnuR, la racine du nœud étant refusée
/// comme racine de comptoir de travail. Le foyer 0 doit être ouvert.
fn deposer_repertoire_sous_racine(
    app: &mut FeuApplication,
    interface_test: &InterfaceTest,
) -> ResultFeuApplication<Fiche> {
    let tmp = TempDir::new().unwrap();
    let chemin_comptoir_depot = tmp.path().join("comptoir_depot");

    let fiche_racine = app.commande_derniere_enu_racine()?;

    let index_comptoir =
        app.commande_ouverture_comptoir_depot(interface_test, &chemin_comptoir_depot, 0, 0)?;

    let chemin = chemin_comptoir_depot.join("documents");
    create_dir(&chemin)?;

    app.commande_fermeture_comptoir_depot(interface_test, index_comptoir, &fiche_racine)?;

    let racine = app.commande_derniere_enu_racine()?;

    Ok(donne_fiche_descendant(app.commande_descendants(&racine)?, "documents").unwrap())
}

/// Les gardes du comptoir de dépôt, dans l'ordre où elles se posent.
///
/// Établit aussi que le miroir de session suit le Scribe : présent tant que le
/// comptoir l'est, parti dès qu'il l'a lâché.
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
        interface_test
            .session_application()
            .unwrap()
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
        interface_test
            .session_application()
            .unwrap()
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

    app.commande_fermeture_foyer(&interface_test, 0)?;

    // L'erreur à commande_fermeture_comptoir_depot empêche l'envoie de la nouvelle session
    // il faut attendre une nouvelle commande réussie qui refait un envoi de session
    assert!(
        interface_test
            .session_application()
            .unwrap()
            .comptoirs_depot_ouverts()
            .is_empty()
    );

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Aller-retour complet dépôt par comptoir → retrait, sur une arborescence à
/// plusieurs niveaux : ce qui ressort est exactement ce qui est entré.
///
/// Le refus d'une commande blob sur une carte répertoire tient ici et nulle part
/// ailleurs — il lui faut une EnuR signée sous braise de foyer.
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

    remplir_dossier(&chemin_comptoir2);

    let arborescence_origine = lire_arborescence(&chemin_comptoir2);

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

    let arborescence_relue = lire_arborescence(&chemin_retrait);

    // Les deux arborescences doivent être identiques
    assert_eq!(arborescence_origine, arborescence_relue);

    let fiche =
        donne_fiche_descendant(app.commande_descendants(&deuxieme_enu_racine)?, "dossier_1")
            .unwrap();

    // Une commande blob refuse une carte répertoire.
    assert!(matches!(
        app.commande_existence_blob(&fiche),
        Err(ErreurFeuApplication::ScribeEnuDAttendue)
    ));

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

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let racine_comptoir = deposer_repertoire_sous_racine(&mut app, &interface_test)?;

    app.commande_ouverture_comptoir_travail(&interface_test, &chemin_comptoir, &racine_comptoir)?;

    assert!(chemin_comptoir.exists());

    let session = interface_test.session_application().unwrap();
    let (chemin, fiche) = session.comptoir_travail_ouvert().unwrap();

    assert_eq!(chemin, &chemin_comptoir);
    assert_eq!(fiche.hash_carte(), racine_comptoir.hash_carte());

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

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let racine_comptoir = deposer_repertoire_sous_racine(&mut app, &interface_test)?;

    app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir_depot, 0, 0)?;

    assert!(matches!(
        app.commande_ouverture_comptoir_travail(
            &interface_test,
            &chemin_comptoir_travail,
            &racine_comptoir,
        ),
        Err(ErreurFeuApplication::ScribeComptoirDepotOuvert)
    ));

    app.commande_fermeture_foyer(&interface_test, 0)?;
    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Comptoir de travail ouvert, plus rien ne s'ouvre ni ne s'écrit : second
/// comptoir, dépôt de texte et suppression de blob sont tous refusés.
///
/// La suppression vise la racine, qui n'a pas de blob — c'est bien le verrou
/// qui remonte, avant toute résolution de cible.
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

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let racine_comptoir = deposer_repertoire_sous_racine(&mut app, &interface_test)?;

    app.commande_ouverture_comptoir_travail(
        &interface_test,
        &chemin_comptoir_travail1,
        &racine_comptoir,
    )?;

    assert!(matches!(
        app.commande_ouverture_comptoir_travail(
            &interface_test,
            &chemin_comptoir_travail2,
            &racine_comptoir,
        ),
        Err(ErreurFeuApplication::ScribeComptoirTravailOuvert)
    ));

    assert!(matches!(
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir_depot, 0, 0),
        Err(ErreurFeuApplication::ScribeComptoirTravailOuvert)
    ));

    assert!(matches!(
        app.commande_depot_enu_texte(&racine_comptoir, 0, "test", "contenu de test"),
        Err(ErreurFeuApplication::ScribeComptoirTravailOuvert)
    ));

    assert!(matches!(
        app.commande_suppression_blob(&racine_comptoir),
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

    let session = interface_test.session_application().unwrap();
    let comptoir1_relu = session.comptoirs_depot_ouverts().get(&id1).unwrap();
    let comptoir2_relu = session.comptoirs_depot_ouverts().get(&id2).unwrap();

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

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let racine_comptoir = deposer_repertoire_sous_racine(&mut app, &interface_test)?;

    app.commande_ouverture_comptoir_travail(
        &interface_test,
        &chemin_comptoir_travail,
        &racine_comptoir,
    )?;

    app.commande_fermeture_foyer(&interface_test, 0)?;
    drop(app);

    let mut app = FeuApplication::new(&chemin_feu);
    app.commande_allumage_noeud(&interface_test, None)?;

    let session = interface_test.session_application().unwrap();
    let comptoir_travail = session.comptoir_travail_ouvert().unwrap();

    assert_eq!(comptoir_travail.0, chemin_comptoir_travail);
    assert_eq!(comptoir_travail.1, racine_comptoir);

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Cinq temps sur le même sous-arbre profond : dépôt, fermeture sans
/// changement, modification en profondeur, création récursive, suppression.
///
/// Les bannières du corps disent ce que chacun établit.
#[test]
fn fermeture_depot_travail() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;

    //
    // 1. Une première arborescence, déposée par comptoir de dépôt
    //
    let dossier_temporaire = TempDir::new().unwrap();

    let enu_racine = app.commande_derniere_enu_racine()?;

    let chemin_comptoir = dossier_temporaire.path().join("comptoir_depot");

    let index_comptoir =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_comptoir, 0, 0)?;

    remplir_dossier(&chemin_comptoir);

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine)?;

    let derniere_enu_racine = app.commande_derniere_enu_racine()?;

    //
    // 2. Comptoir de travail ouvert puis refermé sans rien changer
    //
    // `dossier_1` est la seule EnuR sous la racine : la racine du nœud elle-même
    // est refusée comme racine de comptoir de travail.
    let racine_comptoir =
        donne_fiche_descendant(app.commande_descendants(&derniere_enu_racine)?, "dossier_1")
            .unwrap();

    let chemin_comptoir = dossier_temporaire.path().join("comptoir_travail");

    app.commande_ouverture_comptoir_travail(&interface_test, &chemin_comptoir, &racine_comptoir)?;
    app.commande_fermeture_comptoir_travail(&interface_test)?;

    let derniere_enu_racine_2 = app.commande_derniere_enu_racine()?;

    // rien touché : pas de nouvelle racine
    assert_eq!(derniere_enu_racine, derniere_enu_racine_2);

    //
    // 3. Comptoir de travail ouvert pour réécrire `fichier_3`, tout en bas
    //
    // Relevée avant la modification : cette branche ne sera pas touchée.
    let fiche_fichier_2 = donne_fiche_descendant(
        app.commande_descendants(&derniere_enu_racine_2)?,
        "fichier_2",
    )
    .unwrap();

    app.commande_ouverture_comptoir_travail(&interface_test, &chemin_comptoir, &racine_comptoir)?;
    let contenu_fichier_3 = nouveau_fichier(&chemin_comptoir.join("dossier_2"), "fichier_3", 50);
    app.commande_fermeture_comptoir_travail(&interface_test)?;

    let derniere_enu_racine_3 = app.commande_derniere_enu_racine()?;

    // un fichier modifié tout en bas remonte jusqu'à la racine
    assert_ne!(derniere_enu_racine_2, derniere_enu_racine_3);

    let fiche_fichier_2bis = donne_fiche_descendant(
        app.commande_descendants(&derniere_enu_racine_3)?,
        "fichier_2",
    )
    .unwrap();

    // la branche intacte est réemployée telle quelle, pas re-signée
    assert_eq!(fiche_fichier_2, fiche_fichier_2bis);

    let fiche_fichier_3 = donne_fiche_descendant(
        app.commande_descendants(&derniere_enu_racine_3)?,
        "fichier_3",
    )
    .unwrap();

    let chemin_relecture = dossier_temporaire.path().join("relecture");
    let fichier = File::create(&chemin_relecture).unwrap();

    app.commande_chargement_blob(&fiche_fichier_3, &fichier)?;

    // le blob pointé par la nouvelle fiche porte le contenu réécrit
    assert_eq!(
        contenu_fichier_3,
        read_to_string(&chemin_relecture).unwrap()
    );

    //
    // 4. Comptoir de travail ouvert pour remplir `dossier_2` de neuf
    //
    // Cette étape duplique les noms fixes de `remplir_dossier` dans l'arbre :
    // après elle, plus aucune recherche par nom des étapes précédentes ne
    // rendrait la bonne fiche. D'où sa place en dernier.
    let racine_comptoir = donne_fiche_descendant(
        app.commande_descendants(&derniere_enu_racine_3)?,
        "dossier_1",
    )
    .unwrap();

    app.commande_ouverture_comptoir_travail(&interface_test, &chemin_comptoir, &racine_comptoir)?;
    remplir_dossier(&chemin_comptoir.join("dossier_2"));
    app.commande_fermeture_comptoir_travail(&interface_test)?;

    let derniere_enu_racine_4 = app.commande_derniere_enu_racine()?;

    // l'arborescence neuve est là entière : la création a récursé
    let fiche_dossier_2 = donne_fiche_descendant(
        app.commande_descendants(&derniere_enu_racine_4)?,
        "dossier_2",
    )
    .unwrap();
    let fiche_dossier_1 =
        donne_fiche_descendant(app.commande_descendants(&fiche_dossier_2)?, "dossier_1").unwrap();
    let fiche_dossier_2bis =
        donne_fiche_descendant(app.commande_descendants(&fiche_dossier_1)?, "dossier_2").unwrap();

    assert!(
        donne_fiche_descendant(app.commande_descendants(&fiche_dossier_2bis)?, "fichier_3")
            .is_some()
    );

    //
    // 5. Comptoir de travail ouvert pour effacer `dossier_2`
    //
    let racine_comptoir = donne_fiche_descendant(
        app.commande_descendants(&derniere_enu_racine_4)?,
        "dossier_1",
    )
    .unwrap();
    app.commande_ouverture_comptoir_travail(&interface_test, &chemin_comptoir, &racine_comptoir)?;

    remove_dir_all(chemin_comptoir.join("dossier_2")).unwrap();
    app.commande_fermeture_comptoir_travail(&interface_test)?;

    let derniere_enu_racine_5 = app.commande_derniere_enu_racine()?;

    // effacé du disque, il n'est plus référencé nulle part — et il emporte tout
    // ce que le temps 4 avait créé dessous
    assert!(
        donne_fiche_descendant(
            app.commande_descendants(&derniere_enu_racine_5)?,
            "dossier_2"
        )
        .is_none()
    );

    // la branche voisine, elle, survit : sa fiche est celle d'avant
    assert_eq!(
        donne_fiche_descendant(
            app.commande_descendants(&derniere_enu_racine_5)?,
            "fichier_2"
        )
        .unwrap(),
        fiche_fichier_2
    );

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Un texte réécrit dans le comptoir reste un texte et garde ses métas : la
/// descente reconstruit une carte neuve plutôt que de basculer en donnée.
#[test]
fn fermeture_depot_travail_avec_enu_texte() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    let dossier_temporaire = TempDir::new().unwrap();

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let fiche_racine_depot = deposer_repertoire_sous_racine(&mut app, &interface_test)?;

    app.commande_depot_enu_texte(&fiche_racine_depot, 0, "note", "contenu de test")?;

    let enu_racine = app.commande_derniere_enu_racine()?;
    let chemin_comptoir = dossier_temporaire.path().join("comptoir_travail");

    let fiche_racine_comptoir =
        donne_fiche_descendant(app.commande_descendants(&enu_racine)?, "documents").unwrap();
    app.commande_ouverture_comptoir_travail(
        &interface_test,
        &chemin_comptoir,
        &fiche_racine_comptoir,
    )?;

    write(chemin_comptoir.join("note"), "contenu modifie").unwrap();
    app.commande_fermeture_comptoir_travail(&interface_test)?;

    let enu_racine_2 = app.commande_derniere_enu_racine()?;
    let fiche_note =
        donne_fiche_descendant(app.commande_descendants(&enu_racine_2)?, "note").unwrap();

    let Carte::Texte { contenu, .. } = fiche_note.carte() else {
        panic!("l'ENU n'est plus un texte")
    };
    assert_eq!(contenu, "contenu modifie");
    assert_eq!(fiche_note.carte().metas()["nom"], "note");

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}
