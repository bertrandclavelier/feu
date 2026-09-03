// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Tests des comptoirs : l'état qu'ils portent sur le disque et les transitions
//! entre dépôt et travail.
//!
//! Le décor vient du module parent, dont ce module hérite les fonctions de
//! montage : une pile réelle est nécessaire, un comptoir se refermant sur des
//! ENU signées.

use super::*;

/// Un [`Scribe`] sans comptoir donne un miroir qui se sauvegarde, et qui
/// redonne [`Comptoirs::Vide`].
#[test]
fn cycle_configuration_comptoirs_vide() -> ResultFeuApplication<()> {
    let (_tmp, _, _, noyau, scribe, session) = cree_noyau_et_foyer_ouvert();

    assert!(matches!(scribe.comptoirs, Comptoirs::Vide));

    let configuration = Configuration::new(&scribe);
    configuration.sauvegarder(&scribe.chemin_configuration)?;
    let configuration = Configuration::charger(&scribe.chemin_configuration)?;

    assert!(matches!(
        configuration.vers_comptoirs(&scribe.chemin_enu)?,
        Comptoirs::Vide
    ));

    fermer_foyer(noyau, session);

    Ok(())
}

/// Deux comptoirs de dépôt traversent le miroir sans rien perdre : identifiant
/// attribué, chemin, foyer et classeur de destination.
///
/// Chemins et destinations diffèrent d'un comptoir à l'autre, sans quoi une
/// interversion des deux passerait inaperçue. Aucun dossier n'est créé : seule
/// la valeur voyage.
#[test]
fn cycle_configuration_comptoirs_depot() -> ResultFeuApplication<()> {
    let (tmp, chemin_enu, _, noyau, mut scribe, session) = cree_noyau_et_foyer_ouvert();

    assert!(matches!(scribe.comptoirs, Comptoirs::Vide));

    let chemin1 = tmp.path().join("comptoir1");
    let comptoir1 = ComptoirDepot::new(
        chemin1,
        IndexFoyer::try_from(1)?,
        IndexClasseur::try_from(2)?,
    );
    let index1 = scribe.comptoirs.ajouter_comptoir_depot(comptoir1.clone())?;

    assert!(matches!(scribe.comptoirs, Comptoirs::Depot(_)));

    let chemin2 = tmp.path().join("comptoir2");
    let comptoir2 = ComptoirDepot::new(
        chemin2,
        IndexFoyer::try_from(2)?,
        IndexClasseur::try_from(4)?,
    );
    let index2 = scribe.comptoirs.ajouter_comptoir_depot(comptoir2.clone())?;

    let configuration = Configuration::new(&scribe);
    configuration.sauvegarder(&scribe.chemin_configuration)?;
    let configuration = Configuration::charger(&scribe.chemin_configuration)?;

    let comptoirs_relus = configuration.vers_comptoirs(&chemin_enu)?;

    if let Comptoirs::Depot(comptoirs_relus) = comptoirs_relus {
        assert_eq!(comptoirs_relus.len(), 2);

        let comptoir1_relu = comptoirs_relus.get(&index1).unwrap();
        let comptoir2_relu = comptoirs_relus.get(&index2).unwrap();

        assert_eq!(comptoir1.chemin(), comptoir1_relu.chemin());
        assert_eq!(comptoir2.chemin(), comptoir2_relu.chemin());
        assert_eq!(comptoir1.index_foyer(), comptoir1_relu.index_foyer());
        assert_eq!(comptoir2.index_foyer(), comptoir2_relu.index_foyer());
        assert_eq!(comptoir1.index_classeur(), comptoir1_relu.index_classeur());
        assert_eq!(comptoir2.index_classeur(), comptoir2_relu.index_classeur());
    } else {
        panic!("Attendu Comptoirs::Depot");
    }

    fermer_foyer(noyau, session);

    Ok(())
}

/// Le comptoir de travail traverse le miroir avec sa fiche racine, que
/// [`Configuration::vers_comptoirs`] refait en relisant l'ENU sur le disque.
///
/// D'où la pile : la fiche vient d'une ENU réellement signée, la seule qui
/// puisse être relue depuis son `hash_carte`.
#[test]
fn cycle_configuration_comptoirs_travail() -> ResultFeuApplication<()> {
    let (tmp, chemin_enu, _, noyau, mut scribe, session) = cree_noyau_et_foyer_ouvert();

    assert!(matches!(scribe.comptoirs, Comptoirs::Vide));

    let fiche = Fiche::new(&scribe.derniere_enu_racine(&session)?);

    let chemin = tmp.path().join("comptoir");
    let comptoir = ComptoirTravail::new(chemin, fiche);

    scribe
        .comptoirs
        .ajouter_comptoir_travail(comptoir.clone())?;

    assert!(matches!(scribe.comptoirs, Comptoirs::Travail(_)));

    let configuration = Configuration::new(&scribe);
    configuration.sauvegarder(&scribe.chemin_configuration)?;
    let configuration = Configuration::charger(&scribe.chemin_configuration)?;

    let comptoirs_relus = configuration.vers_comptoirs(&chemin_enu)?;

    if let Comptoirs::Travail(comptoir_travail_relu) = comptoirs_relus {
        assert_eq!(comptoir.chemin(), comptoir_travail_relu.chemin());
        assert_eq!(
            comptoir.fiche_racine(),
            comptoir_travail_relu.fiche_racine()
        );
    } else {
        panic!("Attendu Comptoirs::Travail");
    }

    fermer_foyer(noyau, session);

    Ok(())
}

/// Les transitions de [`Comptoirs`] : premier dépôt ouvert, exclusion mutuelle
/// des deux sortes de comptoirs, retour à [`Comptoirs::Vide`] au dernier
/// retrait.
///
/// Le comptoir de travail réclame une fiche racine, donc une ENU signée : c'est
/// ce qui tient ce test ici plutôt qu'en ligne dans `comptoirs.rs`.
#[test]
fn transition_comptoirs() -> ResultFeuApplication<()> {
    let (tmp, _, _, noyau, mut scribe, session) = cree_noyau_et_foyer_ouvert();

    assert!(matches!(scribe.comptoirs, Comptoirs::Vide));

    let chemin1 = tmp.path().join("comptoir1");
    let comptoir_depot = ComptoirDepot::new(
        chemin1,
        IndexFoyer::try_from(1)?,
        IndexClasseur::try_from(2)?,
    );
    let index_comptoir = scribe
        .comptoirs
        .ajouter_comptoir_depot(comptoir_depot.clone())?;

    assert!(matches!(scribe.comptoirs, Comptoirs::Depot(_)));

    let chemin2 = tmp.path().join("comptoir2");
    let fiche = Fiche::new(&scribe.derniere_enu_racine(&session)?);
    let comptoir_travail = ComptoirTravail::new(chemin2, fiche);

    assert!(matches!(
        scribe
            .comptoirs
            .ajouter_comptoir_travail(comptoir_travail.clone()),
        Err(ErreurFeuApplication::ScribeComptoirDepotOuvert)
    ));

    scribe.comptoirs.retirer_comptoir_depot(index_comptoir)?;

    assert!(matches!(scribe.comptoirs, Comptoirs::Vide));

    scribe
        .comptoirs
        .ajouter_comptoir_travail(comptoir_travail)?;

    assert!(matches!(scribe.comptoirs, Comptoirs::Travail(_)));

    assert!(matches!(
        scribe.comptoirs.ajouter_comptoir_depot(comptoir_depot),
        Err(ErreurFeuApplication::ScribeComptoirTravailOuvert)
    ));

    scribe.comptoirs.retirer_comptoir_travail()?;

    assert!(matches!(scribe.comptoirs, Comptoirs::Vide));

    fermer_foyer(noyau, session);

    Ok(())
}
