// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Tests des modifications d'une arborescence ENU : déplacement, suppression,
//! renommage, changement de foyer et tags.
//!
//! Le décor vient du module parent, dont ce module hérite les fonctions de
//! montage : une pile réelle est nécessaire, chaque modification re-signant les
//! ENU du chemin et posant une nouvelle racine.

use super::*;

/// Remonter une ENU de son dossier vers la racine la déplace sans rien perdre :
/// l'arbre relu en entier la montre sous la racine, ses sœurs restant sous le
/// dossier re-signé.
///
/// Le parent étant sous la destination, c'est la branche où l'ajout précède
/// le retrait.
#[test]
fn deplacement_enu_vers_ancetre() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enu1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);
    let enu2 = creer_enu_donnee(&chemin_enu, &noyau, &session, 2u8);
    let enu3 = creer_enu_donnee(&chemin_enu, &noyau, &session, 3u8);
    let fiche1 = Fiche::new(&enu1);
    let fiche2 = Fiche::new(&enu2);
    let fiche3 = Fiche::new(&enu3);

    let enur = creer_enu_repertoire(
        &chemin_enu,
        &noyau,
        &session,
        "dossier",
        &[&enu1, &enu2, &enu3],
    );

    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[enur.hash_carte()])?;

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    scribe.deplace_enu(
        &noyau,
        &session,
        &Fiche::new(&enur),
        &fiche1,
        &Fiche::new(&enu_racine),
    )?;

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let arborescence = scribe
        .donne_descendants(&enu_racine.hash_carte())
        .collect::<ResultFeuApplication<Vec<_>>>()?;

    assert_eq!(arborescence.len(), 5);
    assert!(arborescence.contains(&(1, fiche1)));
    assert!(arborescence.contains(&(2, fiche2)));
    assert!(arborescence.contains(&(2, fiche3)));

    fermer_foyer(noyau, session);

    Ok(())
}

/// Déplacer une ENU vers un dossier frère la retire de son ancien parent et
/// l'ajoute à la destination, chaque dossier relu depuis le dernier arbre.
///
/// Le parent n'étant pas sous la destination, c'est la branche où le retrait
/// précède l'ajout.
#[test]
fn deplacement_enu_vers_frere() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enu1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);
    let enu2 = creer_enu_donnee(&chemin_enu, &noyau, &session, 2u8);
    let enu3 = creer_enu_donnee(&chemin_enu, &noyau, &session, 3u8);
    let fiche1 = Fiche::new(&enu1);
    let fiche2 = Fiche::new(&enu2);
    let fiche3 = Fiche::new(&enu3);

    let enur1 = creer_enu_repertoire(
        &chemin_enu,
        &noyau,
        &session,
        "dossier1",
        &[&enu1, &enu2, &enu3],
    );

    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[enur1.hash_carte()])?;

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enur2 = creer_enu_repertoire(&chemin_enu, &noyau, &session, "dossier2", &[]);
    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[enur2.hash_carte()])?;

    scribe.deplace_enu(
        &noyau,
        &session,
        &Fiche::new(&enur1),
        &fiche1,
        &Fiche::new(&enur2),
    )?;

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let arborescence = scribe
        .donne_descendants(&enu_racine.hash_carte())
        .collect::<ResultFeuApplication<Vec<_>>>()?;

    assert_eq!(arborescence.len(), 6);

    let (_, fiche_dossier1) = arborescence
        .iter()
        .find(|(_, fiche)| fiche.carte().metas().get("nom").map(String::as_str) == Some("dossier1"))
        .unwrap();
    let (_, fiche_dossier2) = arborescence
        .iter()
        .find(|(_, fiche)| fiche.carte().metas().get("nom").map(String::as_str) == Some("dossier2"))
        .unwrap();

    let arborescence_dossier1 = scribe
        .donne_descendants(&fiche_dossier1.hash_carte())
        .collect::<ResultFeuApplication<Vec<_>>>()?;
    let arborescence_dossier2 = scribe
        .donne_descendants(&fiche_dossier2.hash_carte())
        .collect::<ResultFeuApplication<Vec<_>>>()?;

    assert_eq!(arborescence_dossier1.len(), 3);
    assert!(arborescence_dossier1.contains(&(1, fiche2)));
    assert!(arborescence_dossier1.contains(&(1, fiche3)));

    assert_eq!(arborescence_dossier2.len(), 2);
    assert!(arborescence_dossier2.contains(&(1, fiche1)));

    fermer_foyer(noyau, session);

    Ok(())
}

/// Déplacer un dossier dans lui-même ou dans l'un de ses descendants est
/// refusé avant toute écriture : la dernière racine reste celle d'avant.
#[test]
fn deplacement_enu_vers_enfant() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enur2 = creer_enu_repertoire(&chemin_enu, &noyau, &session, "dossier2", &[]);
    let enur1 = creer_enu_repertoire(&chemin_enu, &noyau, &session, "dossier1", &[&enur2]);
    let fiche1 = Fiche::new(&enur1);
    let fiche2 = Fiche::new(&enur2);

    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[enur1.hash_carte()])?;

    let nouvelle_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert!(matches!(
        scribe.deplace_enu(
            &noyau,
            &session,
            &Fiche::new(&nouvelle_enu_racine),
            &fiche1,
            &fiche1
        ),
        Err(ErreurFeuApplication::ScribeDestinationDescendante)
    ));
    assert!(matches!(
        scribe.deplace_enu(
            &noyau,
            &session,
            &Fiche::new(&nouvelle_enu_racine),
            &fiche1,
            &fiche2
        ),
        Err(ErreurFeuApplication::ScribeDestinationDescendante)
    ));

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert_eq!(nouvelle_enu_racine.hash_carte(), enu_racine.hash_carte());

    fermer_foyer(noyau, session);

    Ok(())
}

/// Un parent qui n'est plus dans le dernier arbre fait échouer le déplacement
/// avant toute écriture : la dernière racine reste celle d'avant.
///
/// La cible et la destination sont à jour ; seul le parent est une version
/// antérieure du dossier, d'avant un premier déplacement.
#[test]
fn deplacement_enu_parent_perime() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enu1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);
    let enu2 = creer_enu_donnee(&chemin_enu, &noyau, &session, 2u8);
    let enur1 = creer_enu_repertoire(&chemin_enu, &noyau, &session, "dossier1", &[&enu1, &enu2]);
    let fiche_enud1 = Fiche::new(&enu1);
    let fiche_enud2 = Fiche::new(&enu2);
    let fiche_enur1 = Fiche::new(&enur1);

    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[enur1.hash_carte()])?;

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    scribe.deplace_enu(
        &noyau,
        &session,
        &fiche_enur1,
        &fiche_enud1,
        &Fiche::new(&enu_racine),
    )?;

    let nouvelle_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert!(matches!(
        scribe.deplace_enu(
            &noyau,
            &session,
            &fiche_enur1,
            &fiche_enud2,
            &Fiche::new(&nouvelle_enu_racine),
        ),
        Err(ErreurFeuApplication::ScribeRemplacementSansEffet)
    ));

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert_eq!(nouvelle_enu_racine.hash_carte(), enu_racine.hash_carte());

    fermer_foyer(noyau, session);

    Ok(())
}

/// Une destination qui est une racine antérieure fait échouer le déplacement
/// avant toute écriture : la dernière racine reste celle d'avant.
#[test]
fn deplacement_enu_racine_perime() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enu1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);
    let enur1 = creer_enu_repertoire(&chemin_enu, &noyau, &session, "dossier1", &[&enu1]);
    let fiche_enud1 = Fiche::new(&enu1);
    let fiche_enur1 = Fiche::new(&enur1);

    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[enur1.hash_carte()])?;

    let nouvelle_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert!(matches!(
        scribe.deplace_enu(
            &noyau,
            &session,
            &fiche_enur1,
            &fiche_enud1,
            &Fiche::new(&enu_racine), // Une racine antérieure, et non la dernière.
        ),
        Err(ErreurFeuApplication::ScribeRacinePerimee)
    ));

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert_eq!(nouvelle_enu_racine.hash_carte(), enu_racine.hash_carte());

    fermer_foyer(noyau, session);

    Ok(())
}

/// Supprimer une ENU d'un dossier la retire de l'arbre relu en entier, sa
/// sœur restant sous le dossier re-signé.
///
/// Le parent n'étant pas la racine, c'est la branche où il est re-signé puis
/// greffé par [`Enu::remplacer`].
#[test]
fn suppression_enu_dans_dossier() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enu1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);
    let enu2 = creer_enu_donnee(&chemin_enu, &noyau, &session, 2u8);
    let enur1 = creer_enu_repertoire(&chemin_enu, &noyau, &session, "dossier1", &[&enu1, &enu2]);
    let fiche_enud1 = Fiche::new(&enu1);
    let fiche_enud2 = Fiche::new(&enu2);
    let fiche_enur1 = Fiche::new(&enur1);

    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[enur1.hash_carte()])?;

    scribe.supprime_enu(&noyau, &session, &fiche_enur1, &fiche_enud1)?;

    let nouvelle_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let arborescence = scribe
        .donne_descendants(&nouvelle_enu_racine.hash_carte())
        .collect::<ResultFeuApplication<Vec<_>>>()?;

    assert_eq!(arborescence.len(), 3);
    assert!(!arborescence.contains(&(2, fiche_enud1)));
    assert!(arborescence.contains(&(2, fiche_enud2)));

    fermer_foyer(noyau, session);

    Ok(())
}

/// Un dossier parent qui n'est plus dans le dernier arbre fait échouer la
/// suppression avant toute écriture : la dernière racine reste celle d'avant.
#[test]
fn suppression_enu_dans_dossier_perime() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enu1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);
    let enu2 = creer_enu_donnee(&chemin_enu, &noyau, &session, 2u8);
    let enur1 = creer_enu_repertoire(&chemin_enu, &noyau, &session, "dossier1", &[&enu1, &enu2]);
    let fiche_enud1 = Fiche::new(&enu1);
    let fiche_enud2 = Fiche::new(&enu2);
    let fiche_enur1 = Fiche::new(&enur1);

    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[enur1.hash_carte()])?;

    scribe.supprime_enu(&noyau, &session, &fiche_enur1, &fiche_enud1)?;

    let nouvelle_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert!(matches!(
        scribe.supprime_enu(&noyau, &session, &fiche_enur1, &fiche_enud2),
        Err(ErreurFeuApplication::ScribeRemplacementSansEffet)
    ));

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert_eq!(nouvelle_enu_racine.hash_carte(), enu_racine.hash_carte());

    fermer_foyer(noyau, session);

    Ok(())
}

/// Supprimer un enfant direct de la racine pose une nouvelle racine sans lui,
/// son frère restant en place.
///
/// Le parent étant la racine du nœud, c'est la branche où sa carte passe
/// directement à [`Enu::new_racine`].
#[test]
fn suppression_enu_dans_racine() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);
    let enu2 = creer_enu_donnee(&chemin_enu, &noyau, &session, 2u8);
    let fiche_enud1 = Fiche::new(&enu1);
    let fiche_enud2 = Fiche::new(&enu2);

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;
    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[fiche_enud1.hash_carte()])?;
    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;
    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[fiche_enud2.hash_carte()])?;

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    scribe.supprime_enu(&noyau, &session, &Fiche::new(&enu_racine), &fiche_enud1)?;

    let nouvelle_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let arborescence = scribe
        .donne_descendants(&nouvelle_enu_racine.hash_carte())
        .collect::<ResultFeuApplication<Vec<_>>>()?;

    assert_eq!(arborescence.len(), 2);
    assert!(!arborescence.contains(&(1, fiche_enud1)));
    assert!(arborescence.contains(&(1, fiche_enud2)));

    fermer_foyer(noyau, session);

    Ok(())
}

/// Une racine qui n'est plus la dernière, prise pour parent, fait échouer la
/// suppression avant toute écriture : la dernière racine reste celle d'avant.
#[test]
fn suppression_enu_dans_racine_perimee() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);
    let enu2 = creer_enu_donnee(&chemin_enu, &noyau, &session, 2u8);
    let fiche_enud1 = Fiche::new(&enu1);
    let fiche_enud2 = Fiche::new(&enu2);

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;
    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[fiche_enud1.hash_carte()])?;
    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;
    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[fiche_enud2.hash_carte()])?;

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    scribe.supprime_enu(&noyau, &session, &Fiche::new(&enu_racine), &fiche_enud1)?;

    let nouvelle_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert!(matches!(
        scribe.supprime_enu(&noyau, &session, &Fiche::new(&enu_racine), &fiche_enud2),
        Err(ErreurFeuApplication::ScribeRacinePerimee)
    ));

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert_eq!(nouvelle_enu_racine.hash_carte(), enu_racine.hash_carte());

    fermer_foyer(noyau, session);

    Ok(())
}
