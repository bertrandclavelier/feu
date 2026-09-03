// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Tests de la crate, du point de vue de qui la consomme.
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
//! Les constats passent par le même contrat : la [`SessionApplication`] que
//! l'interface reçoit à chaque notification, les accesseurs qu'elle expose, et
//! le retour des commandes.
//!
//! # Non testé, délibérément
//!
//! `ScribeCarteMalFormee`, branche d'un `else` immédiat. Les `From`, `Display`
//! et accesseurs de champ, passe-plats. Le pont `RecepteurNoyau`, exercé de
//! biais — rien ne se signerait sans lui. Le contrat de notification, prouvé par
//! chaque assertion portant sur la session reçue. Huit des vingt-cinq commandes
//! publiques, dont `feu-noyau` éprouve déjà le comportement.

use std::{
    collections::HashSet,
    fs::{File, create_dir, read_to_string},
    mem::forget,
};

use data_encoding::HEXLOWER;
use feu_application::{fiche::Fiche, *};
use feu_noyau::{IndexClasseur, IndexFoyer};
use tempfile::TempDir;

use crate::commun::{InterfaceTest, donne_fiche_descendant, nouveau_fichier, remplir_dossier};

mod commun;

/// Un fichier déposé par comptoir se relit à l'identique après extinction et
/// rallumage : le nom par la méta, le contenu par le blob.
///
/// Seul test dont l'instance est détruite entre les deux moitiés, la seconde ne
/// repartant que de `chemin_feu`.
#[test]
fn cycle_depot_extinction_rallumage() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_depot = tmp.path().join("depot");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, IndexFoyer::ZERO)?;

    let index_comptoir = app.commande_ouverture_comptoir_depot(
        &interface_test,
        &chemin_depot,
        IndexFoyer::ZERO,
        IndexClasseur::ZERO,
    )?;
    assert_eq!(index_comptoir, 0);

    let contenu = nouveau_fichier(&chemin_depot, "fichier", 100);

    let enu_racine = app.commande_derniere_enu_racine()?;

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine)?;

    // le dossier physique du comptoir disparaît avec son rangement
    assert!(!chemin_depot.exists());

    app.commande_fermeture_foyer(&interface_test, IndexFoyer::ZERO)?;

    app.commande_extinction_noeud(&interface_test)?;

    // `drop` explicite : le shadowing seul garderait la première instance en vie
    // jusqu'à la fin du test, et le rallumage ne prouverait plus rien du disque
    drop(app);
    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, IndexFoyer::ZERO)?;

    let nouvelle_racine = app.commande_derniere_enu_racine()?;

    assert_ne!(nouvelle_racine, enu_racine);
    assert_eq!(nouvelle_racine.carte().hashs_enu().unwrap().len(), 1);

    let fiche_rechargee =
        donne_fiche_descendant(app.commande_descendants(&nouvelle_racine)?, "fichier").unwrap();

    // `create` et non `open` : la destination n'existe pas encore et doit être
    // ouverte en écriture, `commande_chargement_blob` réclamant un `Write`
    let chemin_relecture = tmp.path().join("relecture");
    let fichier = File::create(&chemin_relecture).unwrap();

    app.commande_chargement_blob(&fiche_rechargee, &fichier)?;

    let contenu_relu = read_to_string(&chemin_relecture).unwrap();

    assert_eq!(contenu, contenu_relu);

    app.commande_fermeture_foyer(&interface_test, IndexFoyer::ZERO)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Cycle de vie d'un blob désigné par sa seule ENU — présence, informations,
/// suppression.
///
/// Le sujet est la fin : `existence_blob` faux et `chargement_enu` encore `Some`
/// sur le même hash, le blob parti et l'arborescence intacte.
#[test]
fn cycle_vie_blob() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_depot = tmp.path().join("depot");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, IndexFoyer::ZERO)?;

    let index_comptoir = app.commande_ouverture_comptoir_depot(
        &interface_test,
        &chemin_depot,
        IndexFoyer::ZERO,
        IndexClasseur::ZERO,
    )?;
    assert_eq!(index_comptoir, 0);

    nouveau_fichier(&chemin_depot, "fichier", 100);

    let enu_racine = app.commande_derniere_enu_racine()?;

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine)?;

    let nouvelle_racine = app.commande_derniere_enu_racine()?;

    let fiche_rechargee =
        donne_fiche_descendant(app.commande_descendants(&nouvelle_racine)?, "fichier").unwrap();

    assert!(app.commande_existence_blob(&fiche_rechargee)?);

    let taille_blob = app
        .commande_informations_blob(&fiche_rechargee)?
        .donne_taille();

    // Le chiffré pèse plus que les cent caractères déposés.
    assert!(taille_blob > 100);

    // Un hash inconnu rend une absence, pas une erreur.
    assert!(matches!(app.commande_chargement_enu(&[0u8; 32]), Ok(None)));

    // La racine du nœud porte `Braise::VIDE`, qu'aucun foyer ne résout.
    assert!(matches!(
        app.commande_existence_blob(&enu_racine),
        Err(ErreurFeuApplication::ScribeBraiseInconnue)
    ));

    // Le blob part, sa carte reste : c'est ce décalage que le test vise.
    app.commande_suppression_blob(&fiche_rechargee)?;

    assert!(!app.commande_existence_blob(&fiche_rechargee)?);

    assert!(
        app.commande_chargement_enu(&fiche_rechargee.hash_carte())?
            .is_some()
    );

    app.commande_fermeture_foyer(&interface_test, IndexFoyer::ZERO)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Aller-retour de deux `EnuT` homonymes déposées à la racine du nœud — dépôt,
/// relecture des cartes, puis matérialisation sur disque.
///
/// Le suffixe est posé au dépôt, pas au retrait : le second texte porte déjà
/// `test_1` en méta. Rien ne dit lequel sort en premier, d'où les ensembles.
#[test]
fn cycle_enu_texte() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

    let enu_racine = app.commande_derniere_enu_racine()?;

    app.commande_depot_enu_texte(&enu_racine, IndexFoyer::try_from(1)?, "test", "enu test 1")?;
    let deuxieme_enu_racine = app.commande_derniere_enu_racine()?;
    app.commande_depot_enu_texte(
        &deuxieme_enu_racine,
        IndexFoyer::try_from(1)?,
        "test",
        "enu test 2",
    )?;
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
    assert_eq!(
        enu1.braise(),
        interface_test
            .session_application()
            .unwrap()
            .braise_foyer(IndexFoyer::try_from(1)?)
    );
    assert_eq!(
        enu2.braise(),
        interface_test
            .session_application()
            .unwrap()
            .braise_foyer(IndexFoyer::try_from(1)?)
    );

    let contenus = HashSet::from([contenu1.as_str(), contenu2.as_str()]);
    assert_eq!(contenus, HashSet::from(["enu test 1", "enu test 2"]));

    // Un dépôt sous une `EnuT` est refusé : l'accueil est réservé aux racines.
    assert!(matches!(
        app.commande_depot_enu_texte(&enu1, IndexFoyer::try_from(1)?, "test", "enu test 3"),
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

    app.commande_fermeture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Le parcours descendant rend tout le sous-arbre, sa forme et ses profondeurs,
/// foyer fermé — le nœud est même rallumé, la clé publique survivant à une
/// simple fermeture.
///
/// N'établit pas l'ordre du parcours : sur cette chaîne, un parcours en largeur
/// donnerait la même séquence.
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

    app.commande_ouverture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

    let dossier_temporaire = TempDir::new().unwrap();

    let chemin_comptoir = dossier_temporaire.path().join("comptoir_depot");

    let index_comptoir = app.commande_ouverture_comptoir_depot(
        &interface_test,
        &chemin_comptoir,
        IndexFoyer::try_from(1)?,
        IndexClasseur::ZERO,
    )?;

    remplir_dossier(&chemin_comptoir);

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine)?;

    // Extinction plutôt que simple fermeture : la session repart vierge, sans la
    // clé publique du foyer qu'une fermeture aurait laissée en place.
    app.commande_fermeture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;
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
/// C'est le chaînage par la méta `_racine` qui le distingue d'une lecture du
/// dossier `enu/`, et le nombre d'enfants décroissant qui en donne le sens.
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

    app.commande_ouverture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

    // Chaque dépôt remplace la racine du nœud et allonge la chaîne d'un maillon.
    for i in 0..10 {
        let enu_racine = app.commande_derniere_enu_racine()?;
        app.commande_depot_enu_texte(
            &enu_racine,
            IndexFoyer::try_from(1)?,
            &format!("fichier{}", i),
            "contenu",
        )?;
    }

    app.commande_fermeture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

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
/// que laisse un processus tué. Un second foyer, sain, reste utilisable.
#[test]
fn secours_fermeture_foyer() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

    // Terminaison brutale : aucun `Drop` ne passe, le dossier clair survit.
    forget(app);

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    // Le foyer 0, intact, s'ouvre malgré le foyer 1 resté en vrac.
    app.commande_ouverture_foyer(&interface_test, IndexFoyer::ZERO)?;

    assert!(
        !interface_test
            .session_application()
            .unwrap()
            .etat_foyer(IndexFoyer::try_from(1)?),
    );

    // L'archive `.feu`, consommée à la première ouverture, ne peut plus se rouvrir.
    assert!(matches!(
        app.commande_ouverture_foyer(&interface_test, IndexFoyer::try_from(1)?),
        Err(ErreurFeuApplication::FeuNoyau(_))
    ));

    app.commande_secours_fermeture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

    assert!(
        !interface_test
            .session_application()
            .unwrap()
            .etat_foyer(IndexFoyer::try_from(1)?),
    );

    // La réparation se prouve ici : le foyer 1 s'ouvre de nouveau.
    app.commande_ouverture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

    assert!(
        interface_test
            .session_application()
            .unwrap()
            .etat_foyer(IndexFoyer::try_from(1)?),
    );

    app.commande_fermeture_foyer(&interface_test, IndexFoyer::ZERO)?;
    app.commande_fermeture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;
    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// La garde du retrait refuse tant qu'un foyer du sous-arbre est fermé, et rend
/// la main sans avoir rien écrit.
///
/// Seul test dont le sous-arbre mêle plusieurs braises : la liste rendue nomme
/// exactement ceux qui manquent, et se réduit à mesure qu'on les rouvre.
#[test]
fn retrait_foyer_ferme() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, IndexFoyer::ZERO)?;
    app.commande_ouverture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

    let dossier_temporaire = TempDir::new().unwrap();

    let enu_racine = app.commande_derniere_enu_racine()?;

    // Le premier dépôt est signé sous le foyer 0.
    let chemin_comptoir = dossier_temporaire.path().join("comptoir_depot");

    let index_comptoir = app.commande_ouverture_comptoir_depot(
        &interface_test,
        &chemin_comptoir,
        IndexFoyer::ZERO,
        IndexClasseur::ZERO,
    )?;

    remplir_dossier(&chemin_comptoir);

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine)?;

    let deuxieme_enu_racine = app.commande_derniere_enu_racine()?;

    // Le second est signé sous le foyer 1, greffé sur la racine rendue par le premier.
    let chemin_comptoir2 = dossier_temporaire.path().join("comptoir_depot2");

    let index_comptoir2 = app.commande_ouverture_comptoir_depot(
        &interface_test,
        &chemin_comptoir2,
        IndexFoyer::try_from(1)?,
        IndexClasseur::ZERO,
    )?;

    remplir_dossier(&chemin_comptoir2);

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir2, &deuxieme_enu_racine)?;

    let troisieme_enu_racine = app.commande_derniere_enu_racine()?;

    // Les deux foyers refermés : plus une braise du sous-arbre ne se résout.
    app.commande_fermeture_foyer(&interface_test, IndexFoyer::ZERO)?;
    app.commande_fermeture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

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
    app.commande_ouverture_foyer(&interface_test, IndexFoyer::ZERO)?;

    let Err(ErreurFeuApplication::ScribeFoyersFermes(liste_fermes)) =
        app.commande_retrait_lecture_seule(&chemin_retrait, &troisieme_enu_racine)
    else {
        panic!("Le retrait aurait dû renvoyer une erreur");
    };

    assert_eq!(liste_fermes, vec![1]);
    assert!(!chemin_retrait.exists());

    // Les deux foyers ouverts, le retrait passe : la garde ne refuse pas à tort.
    app.commande_ouverture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

    app.commande_retrait_lecture_seule(&chemin_retrait, &troisieme_enu_racine)?;

    app.commande_fermeture_foyer(&interface_test, IndexFoyer::ZERO)?;
    app.commande_fermeture_foyer(&interface_test, IndexFoyer::try_from(1)?)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Déposer sous une racine qui n'est plus la dernière est refusé, et ne produit
/// aucune version.
///
/// La voie `Braise::VIDE` de `greffe_enfants` : sans le refus, la nouvelle racine
/// repartirait d'une carte périmée et perdrait tout ce qui a été déposé depuis.
#[test]
fn depot_dans_racine_perimee() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, IndexFoyer::ZERO)?;

    let enu_racine1 = app.commande_derniere_enu_racine()?;

    // Ce dépôt fait de enu_racine1 une racine périmée.
    app.commande_depot_enu_texte(&enu_racine1, IndexFoyer::ZERO, "enu texte 1", "test")?;

    let enu_racine2 = app.commande_derniere_enu_racine()?;

    assert!(matches!(
        app.commande_depot_enu_texte(&enu_racine1, IndexFoyer::ZERO, "enu texte 2", "test"),
        Err(ErreurFeuApplication::ScribeRacinePerimee)
    ));

    let enu_racine3 = app.commande_derniere_enu_racine()?;

    assert_eq!(enu_racine3.hash_carte(), enu_racine2.hash_carte());

    app.commande_fermeture_foyer(&interface_test, IndexFoyer::ZERO)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Déposer sous un répertoire de foyer sorti de l'arbre courant est refusé, et
/// ne produit aucune version.
///
/// L'autre voie de `greffe_enfants`, par [`Enu::remplacer`] : la cible absente
/// laissait forger une racine identique à la précédente.
#[test]
fn depot_dans_enur_perimee() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, IndexFoyer::ZERO)?;

    let enu_racine1 = app.commande_derniere_enu_racine()?;

    let dossier_temporaire = TempDir::new().unwrap();
    let chemin_comptoir = dossier_temporaire.path().join("comptoir_depot");

    let index_comptoir = app.commande_ouverture_comptoir_depot(
        &interface_test,
        &chemin_comptoir,
        IndexFoyer::ZERO,
        IndexClasseur::ZERO,
    )?;

    // Un dossier et rien d'autre : la racine n'aura qu'un enfant, le répertoire
    // de foyer que le test vise.
    create_dir(chemin_comptoir.join("test")).unwrap();

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine1)?;

    let enu_racine2 = app.commande_derniere_enu_racine()?;

    let fiche = donne_fiche_descendant(app.commande_descendants(&enu_racine2)?, "test").unwrap();

    // Ce dépôt remplace le répertoire : la fiche en main sort de l'arbre.
    app.commande_depot_enu_texte(&fiche, IndexFoyer::ZERO, "enu texte 1", "test")?;

    let enu_racine3 = app.commande_derniere_enu_racine()?;

    assert!(matches!(
        app.commande_depot_enu_texte(&fiche, IndexFoyer::ZERO, "enu texte 2", "test"),
        Err(ErreurFeuApplication::ScribeRemplacementSansEffet)
    ));

    let enu_racine4 = app.commande_derniere_enu_racine()?;

    assert_eq!(enu_racine3.hash_carte(), enu_racine4.hash_carte());

    app.commande_fermeture_foyer(&interface_test, IndexFoyer::ZERO)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}
