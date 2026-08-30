// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Tests des comptoirs, pilotés par les seules `commande_*`.
//!
//! Ouverture, exclusivité et persistance du comptoir de travail, et
//! persistance du comptoir de dépôt à travers une extinction.
//!
//! Le harnais vient du module parent : `use super::*` donne `InterfaceTest`
//! et les fabriques de fichiers.

use super::*;

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

    let fiche_racine = app.commande_derniere_enu_racine()?;

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

    let session = interface_test.session_application().unwrap();
    let (chemin, fiche) = session.comptoir_travail_ouvert().unwrap();

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

    let session = interface_test.session_application().unwrap();
    let comptoir_travail = session.comptoir_travail_ouvert().unwrap();

    assert_eq!(comptoir_travail.0, chemin_comptoir_travail);
    assert_eq!(comptoir_travail.1, fiche_racine);

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}
