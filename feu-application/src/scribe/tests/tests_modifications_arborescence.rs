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
