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
fn creer_enu(noyau: &FeuNoyau, session: &SessionApplication) -> Enu {
    let hash_donnee = [0u8; 32];
    let carte = Carte::new_donnee(hash_donnee);

    Enu::new(carte, noyau, session, session.braise_foyer(0).unwrap()).unwrap()
}

/// Cycle de vie disque d'une ENU : sauvegarde, relecture authentifiée
/// (round-trip) puis suppression.
#[test]
fn cycle_disque_enu() {
    let (_tmp, chemin_enu, _, noyau, _, session) = cree_noyau_et_foyer_ouvert();

    let enu = creer_enu(&noyau, &session);

    enu.sauvegarder(&chemin_enu).unwrap();
    let nom_fichier = format!("{}.enu", HEXLOWER.encode(&enu.hash_carte()));
    let chemin = chemin_enu.join(nom_fichier);

    assert!(chemin.exists());

    let enu2 = Enu::charger(&chemin, &session).unwrap();

    assert_eq!(enu, enu2);

    enu.supprimer(&chemin_enu).unwrap();

    assert!(!chemin.exists());

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

    let enu = creer_enu(&noyau, &session);

    enu.sauvegarder(&chemin_enu).unwrap();
    let nom_fichier = format!("{}.enu", HEXLOWER.encode(&enu.hash_carte()));
    let chemin = chemin_enu.join(nom_fichier);

    let mut octets = read(&chemin).unwrap();
    // Octet dans la zone de signature (elle débute à 62 + 32 = 94). XOR 0xFF
    // garantit une modification, là où une inversion de bits laisserait un
    // octet palindrome inchangé.
    octets[97] ^= 0xFF;

    write(&chemin, octets).unwrap();

    // Cibler ENU-003 : d'autres causes (braise inconnue, désérialisation)
    // sortent aussi en `Interne` — seul ce code prouve le rejet par la signature.
    assert!(matches!(
        Enu::charger(&chemin, &session),
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

    let enu_racine = Enu::charger(&chemin_derniere_racine, &session).unwrap();
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

    let enu_racine_2 = Enu::charger(&chemin_derniere_racine, &session).unwrap();

    assert_eq!(enu_racine, enu_racine_2);

    // Nouvelle racine
    let mut carte = Carte::new_repertoire(BTreeSet::from([[0u8; 32]]));
    let hash_str = &HEXLOWER.encode(&enu_racine_2.hash_carte());
    carte.ajout_meta("_racine", hash_str);

    let nouvelle_racine =
        Enu::new_racine(&noyau, &chemin_enu, &chemin_derniere_racine, Some(carte)).unwrap();

    let enu_racine_3 = Enu::charger(&chemin_derniere_racine, &session).unwrap();

    assert_eq!(nouvelle_racine, enu_racine_3);

    fermer_foyer(noyau, session);
}
