// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Tests d'intégration du Scribe : cycle de vie disque des ENU et barrière de
//! confiance de `charger`.
//!
//! Ces tests montent une pile réelle — noyau allumé depuis une seed neuve dans
//! un `TempDir`, foyer ouvert, scribe activé — plutôt que des composants isolés :
//! seule une pile complète permet de signer une ENU puis d'éprouver sa relecture
//! authentifiée. Ils vivent dans un `mod` sous `scribe`, et non dans un dossier
//! `tests/`, parce que les fonctions couvertes (`Enu::sauvegarder`, `charger`,
//! `supprimer`…) sont `pub(super)` : invisibles depuis un crate de test externe.

use std::{collections::BTreeSet, fs::write};

use data_encoding::HEXLOWER;
use secrecy::SecretString;
use tempfile::TempDir;

use crate::{InterfaceFeuApplication, RecepteurNoyau};

use super::*;

/// Implémentation minimale d'[`InterfaceFeuApplication`] pour les tests.
///
/// Répond par des valeurs fixes et déterministes — aucune interaction réelle
/// n'est possible sous test. Enveloppée dans un [`RecepteurNoyau`] réel, elle
/// laisse le vrai pont remplir la [`SessionApplication`] (braise, clés publiques)
/// exactement comme en production. Struct sans état : réinstanciable à volonté,
/// notamment pour le teardown.
struct InterfaceTest;

impl InterfaceFeuApplication for InterfaceTest {
    // Constante : la fermeture du foyer doit retrouver le mot de passe qui a
    // servi à l'ouvrir, sinon le déchiffrement échoue.
    fn demander_mdp(&self) -> Option<secrecy::SecretString> {
        Some(SecretString::from("motdepasse"))
    }

    fn recevoir_seed(&mut self, _mots: &[&str]) {}

    // Sans confirmation, l'initialisation du noyau s'interromprait.
    fn confirmer_enregistrement_seed(&self) -> bool {
        true
    }

    fn recevoir_session_application(&self, _session_application: Option<SessionApplication>) {}
}

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

    let mut interface_test = InterfaceTest;
    let mut session = SessionApplication::new();

    let mut recepteur = RecepteurNoyau::new(&mut session, &mut interface_test);

    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut recepteur).unwrap();
    let mut scribe = Scribe::new(&chemin_feu);
    scribe.activation(&noyau).unwrap();

    noyau.ouverture_foyer(&mut recepteur, 0).unwrap();

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
    let mut interface = InterfaceTest;
    let mut recepteur = RecepteurNoyau::new(&mut session, &mut interface);
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
/// disque est rejetée par `charger` (`ENU-003`).
///
/// Prouve que la vérification de signature est réellement branchée — ce qu'un
/// round-trip nominal, où tout est sain, ne peut pas distinguer d'un `charger`
/// qui ne vérifierait rien.
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

    // Cibler ENU-003 : d'autres causes (braise inconnue, désérialisation)
    // sortent aussi en `Interne` — seul ce code prouve le rejet par la signature.
    assert!(matches!(
        Enu::charger(&chemin_enu, &session, &enu.hash_carte()),
        Err(ErreurScribe::Interne(m)) if m.contains("ENU-003")
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
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, mut scribe, session) =
        cree_noyau_et_foyer_ouvert();

    // Test 1ère activation
    assert!(scribe.est_actif);
    assert!(chemin_enu.is_dir());
    assert!(chemin_derniere_racine.is_symlink());

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session).unwrap();
    let octets_carte = enu_racine.carte().vers_octets();

    assert!(
        FeuNoyau::verification_signature(
            session.cle_publique_sig_noeud(),
            enu_racine.signature_carte(),
            &octets_carte
        )
        .unwrap()
    );

    assert_eq!(
        enu_racine.carte().metas().get_key_value("_racine"),
        Some((&"_racine".to_string(), &"".to_string()))
    );

    // 2e activation
    scribe.desactivation();
    assert!(!scribe.est_actif);
    scribe.activation(&noyau).unwrap();
    assert!(scribe.est_actif);

    let enu_racine_2 = Enu::charger_derniere_racine(&chemin_derniere_racine, &session).unwrap();

    assert_eq!(enu_racine, enu_racine_2);

    // Nouvelle racine
    let mut carte = Carte::new_repertoire(BTreeSet::from([[0u8; 32]]));
    let hash_str = &HEXLOWER.encode(&enu_racine_2.hash_carte());
    carte.ajout_meta("_racine", hash_str);

    Enu::new_racine(
        &noyau,
        &chemin_enu,
        &chemin_derniere_racine,
        Some(carte.clone()),
    )
    .unwrap();

    let enu_racine_3 = Enu::charger_derniere_racine(&chemin_derniere_racine, &session).unwrap();

    assert_eq!(&carte, enu_racine_3.carte());

    fermer_foyer(noyau, session);
}

/// Éprouve [`Enu::remplacer`] sur trois substitutions, de la plus triviale à la
/// plus profonde.
///
/// - **Garde `ENU-007`** : refuser un remplacement dont la carte est déjà celle
///   de la racine courante — aucune nouvelle version à produire.
/// - **Cible = la racine** : cas de base de la récursion — le sommet (vide, issu
///   de la genèse) est remplacé par une arborescence entière, dont la carte
///   devient le nouveau sommet nœud, lignée `_racine` posée.
/// - **Cible en profondeur** : substituer un nœud à deux niveaux force la
///   reconstruction et la re-signature (sous braise foyer) de chaque répertoire
///   du chemin jusqu'au sommet. Le répertoire intermédiaire reconstruit ayant un
///   nouveau hash, on le retrouve par élimination parmi les enfants du sommet et
///   on vérifie qu'il porte le greffon. On vérifie enfin que les versions
///   précédentes ne sont pas supprimées (historique).
#[test]
fn cycle_remplacements() {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, _, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session).unwrap();

    // garde : remplacement de même hash de carte que la racine courante → refus
    assert!(matches!(
        Enu::remplacer(&chemin_enu, &chemin_derniere_racine,  &enu_racine.hash_carte(), &enu_racine, &noyau, &session),
        Err(ErreurScribe::Interne(m)) if m.contains("ENU-007")
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
    let mut h = nouvelle_racine2.carte().hashs_enu().unwrap();
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
