// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Tests d'intégration du Scribe : cycle de vie disque des ENU, barrière de
//! confiance de `charger`, tenue de l'arborescence — racine du nœud,
//! remplacements, greffe d'enfants — et état des comptoirs porté sur le disque.
//!
//! Le Scribe y est consommé par appels directs, sur des composants montés à la
//! main — pendant de `src/tests.rs`, qui éprouve la crate par son contrat
//! public.
//!
//! **Ce fichier garde ce que `src/tests.rs` n'atteindrait qu'en se bâtissant un
//! décor exprès.** Quand le test du haut coûte le même décor, il prend tout : il
//! prouve en plus le câblage.
//!
//! Une pile réelle est montée — noyau allumé, foyer ouvert, scribe activé —
//! seule façon de signer une ENU puis d'éprouver sa relecture authentifiée. D'où
//! un `mod` sous `scribe` : les fonctions couvertes sont `pub(super)`, donc
//! invisibles depuis un crate de test externe.
//!
//! Un troisième emplacement existe, les `mod tests` en ligne, pour ce qui se
//! prouve **sans monter de pile**. Le critère est la pile, pas la visibilité.

use std::{collections::BTreeSet, fs::write};

use data_encoding::HEXLOWER;
use tempfile::TempDir;

use crate::{RecepteurNoyau, tests::InterfaceTest};

use super::*;

/// Monte le décor commun à tous les tests et le rend à l'appelant.
///
/// Le `TempDir` est retourné en premier : il doit rester vivant côté test,
/// sinon son `Drop` effacerait le dossier avant même l'exécution. Le décor
/// laisse un foyer ouvert (clé privée en mémoire), sans quoi aucune ENU ne
/// pourrait être signée.
fn cree_noyau_et_foyer_ouvert() -> (
    TempDir,
    PathBuf,
    PathBuf,
    FeuNoyau,
    Scribe,
    SessionApplication,
) {
    let tmp = TempDir::new().unwrap();
    // Sous-chemin encore inexistant : le noyau l'initialise lui-même. Lui passer
    // un dossier déjà créé le ferait basculer en « ouverture d'un nœud existant ».
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");
    let mut session = SessionApplication::new();

    let mut recepteur = RecepteurNoyau::new(&mut session, &interface_test);

    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut recepteur).unwrap();
    let mut scribe = Scribe::new(&chemin_feu);

    noyau.ouverture_foyer(&mut recepteur, 0).unwrap();

    // Après l'ouverture du foyer, et non avant comme en production : `recepteur`
    // emprunte `session` en mutable, et `activation` en veut une aussi — deux
    // emprunts mutables ne coexistent pas. Celui du récepteur n'est libéré qu'à
    // son dernier usage, ici `ouverture_foyer`. L'ordre est sans effet — une
    // racine est signée par le nœud, aucun foyer n'a besoin d'être ouvert.
    scribe.activation(&noyau, &mut session).unwrap();

    (
        tmp,
        scribe.chemin_enu.clone(),
        scribe.chemin_derniere_racine.clone(),
        noyau,
        scribe,
        session,
    )
}

/// Referme le foyer et consomme le décor en fin de test.
///
/// Le noyau refuse d'être détruit avec un foyer encore ouvert : sans cet appel,
/// son `Drop` provoquerait un panic. Prend `noyau` et `session` par valeur car
/// plus rien ne les utilise ensuite.
fn fermer_foyer(mut noyau: FeuNoyau, mut session: SessionApplication) {
    let interface = InterfaceTest::new("mot de passe");
    let mut recepteur = RecepteurNoyau::new(&mut session, &interface);
    noyau.fermeture_foyer(&mut recepteur, 0).unwrap();
}

/// Signe une ENU de test sur le foyer 0.
///
/// Carte Donnée minimale : le contenu est indifférent aux comportements
/// éprouvés ici (enveloppe, signature), agnostiques à la variante de carte.
fn creer_enu_donnee(
    chemin_enu: &Path,
    noyau: &FeuNoyau,
    session: &SessionApplication,
    marqueur: u8,
) -> Enu {
    let carte = Carte::new_donnee([marqueur; 32]);

    let enu = Enu::new(carte, noyau, session, session.braise_foyer(0).unwrap()).unwrap();
    enu.sauvegarder(chemin_enu).unwrap();

    enu
}

/// Signe une EnuR de test sur le foyer 0, portant les `enfants` donnés.
///
/// Signée sous une braise de foyer, et non sous celle du nœud : c'est ce qui
/// l'oriente vers la branche non triviale de `Scribe::greffe_enfants`, celle qui
/// re-signe et remonte le chemin. Une racine, elle, porte `BRAISE_VIDE`.
fn creer_enu_repertoire(
    chemin_enu: &Path,
    noyau: &FeuNoyau,
    session: &SessionApplication,
    enfants: &[&Enu],
) -> Enu {
    let carte = Carte::new_repertoire(enfants.iter().map(|e| e.hash_carte()).collect());

    let enu = Enu::new(carte, noyau, session, session.braise_foyer(0).unwrap()).unwrap();
    enu.sauvegarder(chemin_enu).unwrap();

    enu
}

/// Cycle de vie disque d'une ENU : sauvegarde, relecture authentifiée
/// (round-trip) puis suppression.
#[test]
fn cycle_disque_enu() {
    let (_tmp, chemin_enu, _, noyau, _, session) = cree_noyau_et_foyer_ouvert();

    let enu = creer_enu_donnee(&chemin_enu, &noyau, &session, 0u8);

    assert!(enu.chemin(&chemin_enu).exists());

    let enu2 = Enu::charger(&chemin_enu, &session, &enu.hash_carte()).unwrap();

    assert_eq!(enu, enu2);

    enu.supprimer(&chemin_enu).unwrap();

    assert!(!enu.chemin(&chemin_enu).exists());

    fermer_foyer(noyau, session);
}

/// Barrière de confiance : une ENU dont la signature a été altérée sur le
/// disque est rejetée par `charger`.
///
/// Prouve que la vérification de signature est réellement branchée — ce qu'un
/// round-trip nominal, où tout est sain, ne peut pas distinguer d'un `charger`
/// qui ne vérifierait rien. Depuis que le parcours s'en passe, c'est aussi le
/// seul test qui prouve que `charger` fait plus que
/// `charger_sans_verification_signature`.
#[test]
fn falsification_avant_chargement_enu() {
    let (_tmp, chemin_enu, _, noyau, _, session) = cree_noyau_et_foyer_ouvert();

    let enu = creer_enu_donnee(&chemin_enu, &noyau, &session, 0u8);

    let mut octets = read(enu.chemin(&chemin_enu)).unwrap();
    // Octet dans la zone de signature (elle débute à 62 + 32 = 94). XOR 0xFF
    // garantit une modification, là où une inversion de bits laisserait un
    // octet palindrome inchangé.
    octets[97] ^= 0xFF;

    write(enu.chemin(&chemin_enu), octets).unwrap();

    // La carte n'est pas touchée : le hash passe, et seule la signature peut
    // faire échouer le chargement. Toute autre variante ici dirait que le refus
    // vient d'ailleurs.
    assert!(matches!(
        Enu::charger(&chemin_enu, &session, &enu.hash_carte()),
        Err(ErreurFeuApplication::ScribeEnuNonAuthentique)
    ));

    fermer_foyer(noyau, session);
}

/// Barrière de confiance : une ENU dont la braise a été altérée sur le disque
/// est rejetée par `charger`.
///
/// La braise reste bien formée mais ne résout plus vers aucun foyer. Le refus
/// tombe donc en amont de la signature, sur le routage vers la clé — d'où une
/// variante distincte de celle du test précédent.
#[test]
fn falsification_braise_avant_chargement_enu() {
    let (_tmp, chemin_enu, _, noyau, _, session) = cree_noyau_et_foyer_ouvert();

    let enu = creer_enu_donnee(&chemin_enu, &noyau, &session, 0u8);

    let mut octets = read(enu.chemin(&chemin_enu)).unwrap();
    // Octet du corps de la braise, remplacé par un autre caractère de l'alphabet
    // BASE32 : la braise reste bien formée (sinon le refus tomberait dès la
    // désérialisation) mais ne désigne plus aucun foyer de la session.
    octets[0] = if octets[0] == b'a' { b'b' } else { b'a' };

    write(enu.chemin(&chemin_enu), octets).unwrap();

    assert!(matches!(
        Enu::charger(&chemin_enu, &session, &enu.hash_carte()),
        Err(ErreurFeuApplication::ScribeBraiseInconnue)
    ));

    fermer_foyer(noyau, session);
}

/// Cycle de vie de la racine du nœud, sur les trois fonctions qui la portent.
///
/// - `activation` : amorce de l'arborescence à la genèse (dossier `enu/`,
///   racine origine signée nœud, symlink `.DERNIERE_RACINE`), puis saut de
///   cette amorce à une réactivation — prouvé par l'égalité des deux racines
///   chargées : une nouvelle amorce donnerait une date différente.
/// - `desactivation` : bascule `est_actif`.
/// - `new_racine` : les deux cas — genèse (`None`, répertoire vide + `_racine`)
///   et racine de suite (`Some(carte)`), avec repointage atomique du symlink
///   éprouvé via un `charger` qui suit le lien vers la racine courante.
#[test]
fn cycle_racine() {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, mut scribe, mut session) =
        cree_noyau_et_foyer_ouvert();

    // Test 1ère activation
    assert!(scribe.est_actif);
    assert!(chemin_enu.is_dir());
    assert!(chemin_derniere_racine.is_symlink());

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session).unwrap();

    assert!(enu_racine.authentique(&session).unwrap());

    assert_eq!(
        enu_racine.carte().metas().get_key_value("_racine"),
        Some((&"_racine".to_string(), &"".to_string()))
    );

    // 2e activation
    scribe.desactivation();
    assert!(!scribe.est_actif);
    scribe.activation(&noyau, &mut session).unwrap();
    assert!(scribe.est_actif);

    let enu_racine_2 = Enu::charger_derniere_racine(&chemin_derniere_racine, &session).unwrap();

    assert_eq!(enu_racine, enu_racine_2);

    // Nouvelle racine
    let mut carte = Carte::new_repertoire(BTreeSet::from([[0u8; 32]]));
    carte.ajout_meta("_racine", "valeur qui devrait être écrasée");

    Enu::new_racine(
        &noyau,
        &session,
        &chemin_enu,
        &chemin_derniere_racine,
        Some(carte.clone()),
    )
    .unwrap();

    let enu_racine_3 = Enu::charger_derniere_racine(&chemin_derniere_racine, &session).unwrap();

    // la méta posée par l'appelant est écrasée : new_racine impose le hash
    // de la racine qu'elle remplace
    assert_eq!(
        enu_racine_3.carte().metas().get("_racine"),
        Some(&HEXLOWER.encode(&enu_racine_2.hash_carte()))
    );

    // le reste de la carte fournie est conservé tel quel
    assert_eq!(
        enu_racine_3.carte().hashs_enu().unwrap(),
        &BTreeSet::from([[0u8; 32]])
    );

    fermer_foyer(noyau, session);
}

/// Éprouve [`Enu::remplacer`] sur trois substitutions, de la plus triviale à la
/// plus profonde.
///
/// Le remplacement sans effet est refusé ; la racine comme cible est le cas de
/// base de la récursion ; une cible en profondeur force la reconstruction et la
/// re-signature de chaque répertoire du chemin. Établit au passage que les
/// versions précédentes ne sont pas supprimées.
#[test]
fn cycle_remplacements() {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, _, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session).unwrap();

    // garde : remplacement de même hash de carte que la racine courante → refus
    assert!(matches!(
        Enu::remplacer(
            &chemin_enu,
            &chemin_derniere_racine,
            &enu_racine.hash_carte(),
            &enu_racine,
            &noyau,
            &session
        ),
        Err(ErreurFeuApplication::ScribeRemplacementSansEffet)
    ));

    // Première arborescence : deux niveaux de répertoires foyer (enur_1 → enur_2
    // → enur_3), avec des feuilles à chaque étage.
    let enur_3 = creer_enu_repertoire(&chemin_enu, &noyau, &session, &[]);
    let enud_2 = creer_enu_donnee(&chemin_enu, &noyau, &session, 2u8);
    let enur_2 = creer_enu_repertoire(&chemin_enu, &noyau, &session, &[&enud_2, &enur_3]);
    let enud_1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);
    let enur_1 = creer_enu_repertoire(&chemin_enu, &noyau, &session, &[&enur_2, &enud_1]);

    // cible = la racine (vide) : cas de base, la carte de enur_1 devient le sommet
    Enu::remplacer(
        &chemin_enu,
        &chemin_derniere_racine,
        &enu_racine.hash_carte(),
        &enur_1,
        &noyau,
        &session,
    )
    .unwrap();

    let nouvelle_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session).unwrap();

    assert_eq!(
        nouvelle_racine.carte().metas().get("_racine"),
        Some(&HEXLOWER.encode(&enu_racine.hash_carte()))
    );

    let h = nouvelle_racine.carte().hashs_enu().unwrap();
    assert_eq!(h.len(), 2);
    assert!(h.contains(&enur_2.hash_carte()) && h.contains(&enud_1.hash_carte()));

    assert_eq!(
        Enu::charger(&chemin_enu, &session, &enur_2.hash_carte()).unwrap(),
        enur_2
    );
    assert_eq!(
        Enu::charger(&chemin_enu, &session, &enud_1.hash_carte()).unwrap(),
        enud_1
    );

    let h2 = enur_2.carte().hashs_enu().unwrap();
    assert_eq!(h2.len(), 2);
    assert!(h2.contains(&enud_2.hash_carte()) && h2.contains(&enur_3.hash_carte()));

    assert_eq!(
        Enu::charger(&chemin_enu, &session, &enud_2.hash_carte()).unwrap(),
        enud_2
    );

    assert_eq!(
        Enu::charger(&chemin_enu, &session, &enur_3.hash_carte()).unwrap(),
        enur_3
    );

    // Greffe en profondeur : enur_3 (niveau 2, sous enur_2) est remplacé par
    // enu_depot. La récursion doit reconstruire et re-signer enur_2 au-dessus.
    let derniere_enu = creer_enu_donnee(&chemin_enu, &noyau, &session, 9u8);
    let enu_depot = creer_enu_repertoire(&chemin_enu, &noyau, &session, &[&derniere_enu]);

    Enu::remplacer(
        &chemin_enu,
        &chemin_derniere_racine,
        &enur_3.hash_carte(),
        &enu_depot,
        &noyau,
        &session,
    )
    .unwrap();

    let nouvelle_racine2 = Enu::charger_derniere_racine(&chemin_derniere_racine, &session).unwrap();

    assert_eq!(
        nouvelle_racine2.carte().metas().get("_racine"),
        Some(&HEXLOWER.encode(&nouvelle_racine.hash_carte()))
    );

    // enur_2 reconstruit a un nouveau hash, inconnu du test : on le retrouve par
    // élimination — l'enfant du sommet qui n'est pas enud_1 (branche inchangée).
    let mut h = nouvelle_racine2.carte().hashs_enu().unwrap().clone();
    assert_eq!(h.len(), 2);
    h.remove(&enud_1.hash_carte());
    let hash_enur_2n = h.first().unwrap();

    let enur_2n = Enu::charger(&chemin_enu, &session, hash_enur_2n).unwrap();

    let h2 = enur_2n.carte().hashs_enu().unwrap();

    assert!(h2.contains(&enu_depot.hash_carte())); // le greffon est là
    assert!(h2.contains(&enud_2.hash_carte())); // enud_2 conservé
    assert!(!h2.contains(&enur_3.hash_carte()));

    // versions précédentes non supprimées : ancien répertoire et ancien sommet
    // restent sur disque (historique des versions)
    assert!(enur_2.chemin(&chemin_enu).exists());
    assert!(nouvelle_racine.chemin(&chemin_enu).exists());

    fermer_foyer(noyau, session);
}

/// Greffe à même le sommet du nœud — la branche `BRAISE_VIDE` de
/// `Scribe::greffe_enfants`, qui forge une nouvelle racine par `Enu::new_racine`
/// au lieu de reconstruire un chemin sous un foyer.
///
/// **Deux greffes successives** : la première part de la genèse, dont la carte
/// est vide ; la seconde d'une racine peuplée, et prouve l'*union*.
///
/// Chacune vérifie le chaînage — sans quoi une genèse fraîche passerait pour une
/// greffe réussie —, le cardinal **et** la présence de chaque enfant, et le
/// changement de `hash_carte` du sommet.
#[test]
fn greffe_enfants_racine() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enu1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);
    let enu2 = creer_enu_donnee(&chemin_enu, &noyau, &session, 2u8);
    let enu3 = creer_enu_donnee(&chemin_enu, &noyau, &session, 3u8);

    scribe.greffe_enfants(
        &noyau,
        &session,
        &enu_racine,
        &[enu1.hash_carte(), enu2.hash_carte(), enu3.hash_carte()],
    )?;

    let deuxieme_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    // La deuxieme racine pointe vers la première
    assert_eq!(
        deuxieme_enu_racine.carte().metas().get("_racine"),
        Some(&HEXLOWER.encode(&enu_racine.hash_carte()))
    );

    assert_eq!(deuxieme_enu_racine.carte().hashs_enu().unwrap().len(), 3);
    assert!(
        deuxieme_enu_racine
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu1.hash_carte())
    );
    assert!(
        deuxieme_enu_racine
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu2.hash_carte())
    );
    assert!(
        deuxieme_enu_racine
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu3.hash_carte())
    );

    // La deuxieme racine est différente de la première
    assert_ne!(enu_racine.hash_carte(), deuxieme_enu_racine.hash_carte());

    let enu4 = creer_enu_donnee(&chemin_enu, &noyau, &session, 4u8);

    scribe.greffe_enfants(&noyau, &session, &deuxieme_enu_racine, &[enu4.hash_carte()])?;

    let troisieme_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    // La troisieme racine pointe vers la deuxième
    assert_eq!(
        troisieme_enu_racine.carte().metas().get("_racine"),
        Some(&HEXLOWER.encode(&deuxieme_enu_racine.hash_carte()))
    );

    assert_eq!(troisieme_enu_racine.carte().hashs_enu().unwrap().len(), 4);
    assert!(
        troisieme_enu_racine
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu1.hash_carte())
    );
    assert!(
        troisieme_enu_racine
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu2.hash_carte())
    );
    assert!(
        troisieme_enu_racine
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu3.hash_carte())
    );
    assert!(
        troisieme_enu_racine
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu4.hash_carte())
    );

    // La troisieme racine est différente de la deuxieme
    assert_ne!(
        deuxieme_enu_racine.hash_carte(),
        troisieme_enu_racine.hash_carte()
    );

    fermer_foyer(noyau, session);

    Ok(())
}

/// Greffe sous un répertoire de foyer — la branche non triviale de
/// `Scribe::greffe_enfants`, celle qui re-signe l'EnuR sous sa propre braise
/// puis remonte jusqu'au sommet par `Enu::remplacer`.
///
/// L'EnuR doit être **réellement accrochée** sous la racine : `remplacer` la
/// retrouve en descendant depuis `.DERNIERE_RACINE`, une EnuR seulement présente
/// sur le disque serait introuvable. La greffe en forge ensuite une nouvelle, si
/// bien que la variable du test désigne une version périmée.
///
/// Vérifie l'union des cinq enfants, la **braise inchangée** — en changer
/// déplacerait silencieusement un contenu d'un foyer vers un autre — et la
/// remontée jusqu'au sommet.
#[test]
fn greffe_enfants() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enu1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);
    let enu2 = creer_enu_donnee(&chemin_enu, &noyau, &session, 2u8);
    let enu3 = creer_enu_donnee(&chemin_enu, &noyau, &session, 3u8);

    let enur = creer_enu_repertoire(&chemin_enu, &noyau, &session, &[&enu1, &enu2, &enu3]);

    // décor : accroche l'EnuR sous le sommet, faute de quoi `remplacer` ne la
    // trouverait pas en descendant depuis `.DERNIERE_RACINE`. Voie déjà éprouvée
    // par greffe_enfants_racine.
    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[enur.hash_carte()])?;

    let enu4 = creer_enu_donnee(&chemin_enu, &noyau, &session, 4u8);
    let enu5 = creer_enu_donnee(&chemin_enu, &noyau, &session, 5u8);

    scribe.greffe_enfants(
        &noyau,
        &session,
        &enur,
        &[enu4.hash_carte(), enu5.hash_carte()],
    )?;

    let troisieme_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    // l'EnuR reconstruite a remplacé l'ancienne sous le sommet, elle ne s'y est
    // pas ajoutée : le fils unique est donc sa version courante
    assert_eq!(troisieme_enu_racine.carte().hashs_enu().unwrap().len(), 1);

    let nouvelle_enur = Enu::charger(
        &chemin_enu,
        &session,
        troisieme_enu_racine
            .carte()
            .hashs_enu()
            .unwrap()
            .first()
            .unwrap(),
    )?;

    // greffer ne déplace pas : le contenu reste sous le foyer d'origine
    assert_eq!(nouvelle_enur.braise(), enur.braise());

    // les trois enfants d'origine survivent aux deux greffés
    assert_eq!(nouvelle_enur.carte().hashs_enu().unwrap().len(), 5);

    assert!(
        nouvelle_enur
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu1.hash_carte())
    );
    assert!(
        nouvelle_enur
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu2.hash_carte())
    );
    assert!(
        nouvelle_enur
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu3.hash_carte())
    );
    assert!(
        nouvelle_enur
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu4.hash_carte())
    );
    assert!(
        nouvelle_enur
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu5.hash_carte())
    );

    fermer_foyer(noyau, session);

    Ok(())
}

/// Greffe sans effet : re-greffer un enfant déjà présent ne produit aucune
/// version.
///
/// La carte étant un ensemble, un hash déjà là est absorbé sans rien changer, et
/// forger malgré tout une racine allongerait la lignée d'un maillon identique.
/// Le cas n'est pas théorique : un même fichier redéposé produit le même
/// `hash_carte`.
///
/// L'égalité porte sur les ENU **entières**, pas sur leur `hash_carte` : une
/// racine re-forgée à contenu identique se trahirait par sa date et sa
/// signature.
#[test]
fn greffe_enfants_doublon() -> ResultFeuApplication<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enu1 = creer_enu_donnee(&chemin_enu, &noyau, &session, 1u8);

    scribe.greffe_enfants(&noyau, &session, &enu_racine, &[enu1.hash_carte()])?;

    let deuxieme_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert_eq!(
        deuxieme_enu_racine.carte().metas().get("_racine"),
        Some(&HEXLOWER.encode(&enu_racine.hash_carte()))
    );

    scribe.greffe_enfants(&noyau, &session, &deuxieme_enu_racine, &[enu1.hash_carte()])?;

    let troisieme_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert_eq!(deuxieme_enu_racine, troisieme_enu_racine);
    assert_eq!(troisieme_enu_racine.carte().hashs_enu().unwrap().len(), 1);
    assert!(
        troisieme_enu_racine
            .carte()
            .hashs_enu()
            .unwrap()
            .contains(&enu1.hash_carte())
    );

    fermer_foyer(noyau, session);

    Ok(())
}

/// Deux appels successifs pour le même nom dans le même dossier : le premier
/// obtient le nom nu, chaque appel suivant un suffixe incrémental — tant que
/// le chemin retourné reste occupé par l'appelant entre deux appels.
#[test]
fn chemin_libre_suffixe_les_homonymes() {
    let tmp = TempDir::new().unwrap();

    // rien n'existe : le nom nu
    let chemin1 = Scribe::chemin_libre(tmp.path(), "photo.jpg");
    assert_eq!(chemin1, tmp.path().join("photo.jpg"));

    write(&chemin1, "premier").unwrap();

    // le nom nu est pris : suffixe _1
    let chemin2 = Scribe::chemin_libre(tmp.path(), "photo.jpg");
    assert_eq!(chemin2, tmp.path().join("photo.jpg_1"));

    write(&chemin2, "second").unwrap();

    // les deux pris : suffixe _2
    let chemin3 = Scribe::chemin_libre(tmp.path(), "photo.jpg");
    assert_eq!(chemin3, tmp.path().join("photo.jpg_2"));
}

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
    let comptoir1 = ComptoirDepot::new(chemin1, 1, 2);
    let index1 = scribe.comptoirs.ajouter_comptoir_depot(comptoir1.clone())?;

    assert!(matches!(scribe.comptoirs, Comptoirs::Depot(_)));

    let chemin2 = tmp.path().join("comptoir2");
    let comptoir2 = ComptoirDepot::new(chemin2, 3, 4);
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
/// ce qui tient ce test ici plutôt qu'en ligne dans `comptoir.rs`.
#[test]
fn transition_comptoirs() -> ResultFeuApplication<()> {
    let (tmp, _, _, noyau, mut scribe, session) = cree_noyau_et_foyer_ouvert();

    assert!(matches!(scribe.comptoirs, Comptoirs::Vide));

    let chemin1 = tmp.path().join("comptoir1");
    let comptoir_depot = ComptoirDepot::new(chemin1, 1, 2);
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
