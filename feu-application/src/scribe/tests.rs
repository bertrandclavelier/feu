// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Tests d'intégration du Scribe : cycle de vie disque des ENU, barrière de
//! confiance de `charger`, et tenue de l'arborescence — racine du nœud,
//! remplacements, greffe d'enfants, dépôt.
//!
//! Ces tests montent une pile réelle — noyau allumé depuis une seed neuve dans
//! un `TempDir`, foyer ouvert, scribe activé — plutôt que des composants isolés :
//! seule une pile complète permet de signer une ENU puis d'éprouver sa relecture
//! authentifiée. Ils vivent dans un `mod` sous `scribe`, et non dans un dossier
//! `tests/`, parce que les fonctions couvertes (`Enu::sauvegarder`, `charger`,
//! `supprimer`…) sont `pub(super)` : invisibles depuis un crate de test externe.
//!
//! Les tests portant sur une même fonction se répartissent le travail plutôt que
//! de le répéter : un test éprouve le comportement d'une fonction, un autre se
//! contente de prouver qu'un appelant l'invoque. La doc de chacun dit lequel des
//! deux rôles il tient.

use std::{
    collections::{BTreeSet, HashSet},
    fs::{create_dir, write},
};

use data_encoding::HEXLOWER;
use rand::{Rng, distributions::Alphanumeric};
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

    noyau.ouverture_foyer(&mut recepteur, 0).unwrap();

    // Après l'ouverture du foyer, et non avant comme en production : `recepteur`
    // emprunte `session` en mutable, or `activation` en veut une référence
    // partagée. L'emprunt n'est libéré qu'au dernier usage du récepteur, ici
    // `ouverture_foyer`. L'ordre est sans effet — une racine est signée par le
    // nœud, aucun foyer n'a besoin d'être ouvert.
    scribe.activation(&noyau, &session).unwrap();

    (
        tmp,
        scribe.chemin_enu.clone(),
        scribe.chemin_derniere_racine.clone(),
        noyau,
        scribe,
        session,
    )
}

/// Peuple `chemin` d'une arborescence à trois niveaux : un fichier et un
/// dossier à la racine, ce dossier contenant lui-même un fichier et un
/// dossier, jusqu'à un troisième niveau ne contenant qu'un fichier.
///
/// Sert à éprouver [`Scribe::fermeture_comptoir_depot`], qui traite
/// différemment les enfants directs du comptoir (`depth == 1`) et les
/// sous-arbres plus profonds (`depth > 1`) : la structure doit donc exercer
/// les deux cas.
///
/// Noms et contenus sont aléatoires, ce qui permet d'appeler la fonction
/// plusieurs fois dans un même test sans collision entre les arborescences
/// produites.
///
/// # Erreurs
///
/// Propage toute erreur d'E/S — dossier déjà présent, permissions.
fn remplir_dossier(chemin: &Path) -> ResultScribe<()> {
    let chaine_aleatoire = |n: usize| -> String {
        rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(n)
            .map(char::from)
            .collect()
    };

    // Niveau 1
    // fichier 1
    write(chemin.join(chaine_aleatoire(10)), chaine_aleatoire(100))?;

    // Dossier 1
    let chemin_dossier1 = chemin.join(chaine_aleatoire(10));
    create_dir(&chemin_dossier1)?;

    // Niveau 2
    // fichier 2
    write(
        chemin_dossier1.join(chaine_aleatoire(10)),
        chaine_aleatoire(100),
    )?;

    // dossier 2
    let chemin_dossier2 = chemin_dossier1.join(chaine_aleatoire(10));
    create_dir(&chemin_dossier2)?;

    // Niveau 3
    // fichier 3
    write(
        chemin_dossier2.join(chaine_aleatoire(10)),
        chaine_aleatoire(100),
    )?;

    Ok(())
}

/// Relit récursivement `chemin` en un ensemble `(chemin relatif, contenu)`,
/// un par fichier — les dossiers n'ont pas d'entrée propre, leur chemin relatif
/// dans celui de leurs fichiers suffit à les distinguer.
///
/// Sert à comparer deux arborescences sans dépendre de l'ordre de parcours,
/// notamment le contenu d'un comptoir avant fermeture face à celui d'un
/// retrait après coup — l'ordre des enfants dans l'arbre ENU suit les hashs,
/// pas les noms.
fn lire_arborescence(chemin: &Path) -> ResultScribe<HashSet<(PathBuf, String)>> {
    let mut resultat = HashSet::new();

    for entree in WalkDir::new(chemin).min_depth(1) {
        let entree = entree?;

        if entree.file_type().is_file() {
            let chemin_relatif = entree.path().strip_prefix(chemin).unwrap().to_path_buf();
            let contenu = std::fs::read_to_string(entree.path())?;
            resultat.insert((chemin_relatif, contenu));
        }
    }

    Ok(resultat)
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
    scribe.activation(&noyau, &session).unwrap();
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
        BTreeSet::from([[0u8; 32]])
    );

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

/// Greffe à même le sommet du nœud — la branche `BRAISE_VIDE` de
/// `Scribe::greffe_enfants`, qui forge une nouvelle racine par `Enu::new_racine`
/// au lieu de reconstruire un chemin sous un foyer.
///
/// Deux greffes successives, parce qu'elles n'éprouvent pas la même chose : la
/// première part de la racine de genèse, dont la carte est **vide** — les
/// enfants greffés sont alors les seuls ; la seconde part d'une racine déjà
/// peuplée et prouve l'*union*, à savoir que les trois enfants précédents
/// survivent à l'arrivée du quatrième.
///
/// Chaque greffe vérifie :
///
/// - **chaînage** : la méta `_racine` du nouveau sommet pointe vers celui qu'il
///   remplace — sans quoi une racine de genèse fraîche, elle aussi valide et
///   signée nœud, passerait pour une greffe réussie ;
/// - **enfants** : cardinal attendu *et* présence de chacun. Le cardinal seul
///   laisserait passer une substitution, la présence seule un hash parasite ;
/// - **nouveau sommet** : le `hash_carte` a changé, donc la racine a bien été
///   re-forgée et `.DERNIERE_RACINE` repointé, plutôt que l'ancienne complétée
///   en place.
#[test]
fn greffe_enfants_racine() -> ResultScribe<()> {
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

    assert_eq!(deuxieme_enu_racine.carte().hashs_enu()?.len(), 3);
    assert!(
        deuxieme_enu_racine
            .carte()
            .hashs_enu()?
            .contains(&enu1.hash_carte())
    );
    assert!(
        deuxieme_enu_racine
            .carte()
            .hashs_enu()?
            .contains(&enu2.hash_carte())
    );
    assert!(
        deuxieme_enu_racine
            .carte()
            .hashs_enu()?
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

    assert_eq!(troisieme_enu_racine.carte().hashs_enu()?.len(), 4);
    assert!(
        troisieme_enu_racine
            .carte()
            .hashs_enu()?
            .contains(&enu1.hash_carte())
    );
    assert!(
        troisieme_enu_racine
            .carte()
            .hashs_enu()?
            .contains(&enu2.hash_carte())
    );
    assert!(
        troisieme_enu_racine
            .carte()
            .hashs_enu()?
            .contains(&enu3.hash_carte())
    );
    assert!(
        troisieme_enu_racine
            .carte()
            .hashs_enu()?
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
/// L'EnuR doit être réellement accrochée sous la racine avant la greffe : c'est
/// en descendant depuis `.DERNIERE_RACINE` que `remplacer` la retrouve, et une
/// EnuR seulement présente sur le disque serait introuvable. Le décor emprunte
/// donc la branche `BRAISE_VIDE`, déjà éprouvée par [`greffe_enfants_racine`].
///
/// La greffe ne modifie pas l'EnuR : elle en forge une nouvelle, de carte
/// augmentée, donc de `hash_carte` différent. La variable `enur` du test désigne
/// dès lors une version périmée — la version courante se retrouve comme unique
/// enfant du sommet reconstruit.
///
/// Le test vérifie :
///
/// - **union** : les cinq enfants — les trois d'origine conservés, les deux
///   greffés ajoutés. C'est le comportement propre à cette branche, la racine
///   de genèse partant nécessairement d'une carte vide ;
/// - **braise inchangée** : la nouvelle EnuR reste signée sous le foyer de
///   l'ancienne. Une greffe qui changerait de braise déplacerait silencieusement
///   un contenu d'un foyer vers un autre — l'invariant du tiroir l'interdit ;
/// - **remontée** : le sommet a été reconstruit et n'a toujours qu'un enfant,
///   la nouvelle EnuR ayant remplacé l'ancienne au lieu de s'y ajouter.
#[test]
fn greffe_enfants() -> ResultScribe<()> {
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
    assert_eq!(troisieme_enu_racine.carte().hashs_enu()?.len(), 1);

    let nouvelle_enur = Enu::charger(
        &chemin_enu,
        &session,
        troisieme_enu_racine.carte().hashs_enu()?.first().unwrap(),
    )?;

    // greffer ne déplace pas : le contenu reste sous le foyer d'origine
    assert_eq!(nouvelle_enur.braise(), enur.braise());

    // les trois enfants d'origine survivent aux deux greffés
    assert_eq!(nouvelle_enur.carte().hashs_enu()?.len(), 5);

    assert!(
        nouvelle_enur
            .carte()
            .hashs_enu()?
            .contains(&enu1.hash_carte())
    );
    assert!(
        nouvelle_enur
            .carte()
            .hashs_enu()?
            .contains(&enu2.hash_carte())
    );
    assert!(
        nouvelle_enur
            .carte()
            .hashs_enu()?
            .contains(&enu3.hash_carte())
    );
    assert!(
        nouvelle_enur
            .carte()
            .hashs_enu()?
            .contains(&enu4.hash_carte())
    );
    assert!(
        nouvelle_enur
            .carte()
            .hashs_enu()?
            .contains(&enu5.hash_carte())
    );

    fermer_foyer(noyau, session);

    Ok(())
}

/// Greffe sans effet : re-greffer un enfant déjà présent ne produit aucune
/// version.
///
/// La carte étant un ensemble, un hash déjà là est absorbé sans rien changer.
/// Forger malgré tout une nouvelle racine allongerait la lignée des `_racine`
/// d'un maillon identique au précédent — d'où la sortie anticipée de
/// `greffe_enfants` lorsque la carte augmentée égale celle de départ.
///
/// Le cas n'est pas théorique : le comptoir reforge la carte d'un fichier à
/// partir de son contenu et de son nom, si bien qu'un même fichier redéposé
/// produit le même `hash_carte`.
///
/// La première greffe n'est pas là pour être vérifiée — `greffe_enfants_racine`
/// s'en charge — mais pour **établir le décor** : son contrôle de chaînage
/// prouve qu'une version a bien été produite. Sans lui, l'égalité qui suit
/// passerait tout aussi bien si rien n'avait jamais fonctionné.
///
/// L'égalité porte sur les ENU **entières**, pas sur leur `hash_carte` : une
/// racine re-forgée à contenu identique se trahirait par sa date et par sa
/// signature, qu'une comparaison de cartes seules laisserait passer.
#[test]
fn greffe_enfants_doublon() -> ResultScribe<()> {
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
    assert_eq!(troisieme_enu_racine.carte().hashs_enu()?.len(), 1);
    assert!(
        troisieme_enu_racine
            .carte()
            .hashs_enu()?
            .contains(&enu1.hash_carte())
    );

    fermer_foyer(noyau, session);

    Ok(())
}

/// Dépôt d'une EnuT à la **racine du nœud** — la branche `BRAISE_VIDE` de
/// `Scribe::depot_enu_texte`, qui greffe à même le sommet via `Enu::new_racine`.
///
/// L'EnuT est forgée en double côté test : le `hash_carte` étant l'empreinte de
/// la seule carte (ni la braise, ni la date, ni la signature n'y entrent), cette
/// copie locale sert d'oracle pour retrouver sur le disque celle qu'a déposée le
/// Scribe, qui ne rend rien. Seules les **cartes** sont comparables — deux
/// enveloppes du même contenu diffèrent par leur date et par leur signature,
/// non déterministe.
///
/// Le test couvre, dans l'ordre :
///
/// - **refus `ENU-004`** : une `Carte::Texte` passée comme racine de dépôt n'est
///   pas un répertoire. Son contenu diffère volontairement de celui du dépôt
///   nominal — même texte, même carte, donc même fichier, et l'écriture faite
///   avant l'échec masquerait celle du dépôt réussi ;
/// - **dépôt nominal** : l'EnuT est sur le disque, authentifiée par `charger`,
///   signée sous la braise du foyer demandé, et son contenu est intact ;
/// - **délégation de la greffe** : son `hash_carte` figure parmi les enfants du
///   sommet courant. Une seule assertion, et non l'inspection complète du
///   nouveau sommet : le comportement de `greffe_enfants` est éprouvé par ses
///   propres tests, il n'y a ici qu'à prouver que le dépôt l'appelle. Sans elle,
///   supprimer cet appel laisserait l'EnuT sur le disque, orpheline et
///   inatteignable depuis la racine, sans qu'aucun test ne bronche.
#[test]
fn depot_enu_texte() -> ResultScribe<()> {
    let (_tmp, chemin_enu, chemin_derniere_racine, noyau, scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let enu_texte = Enu::new(
        Carte::new_texte("test", "contenu de test")?,
        &noyau,
        &session,
        session.braise_foyer(0)?,
    )?;

    // L'Enu de dépôt n'est pas une EnuR
    assert!(
        matches!(scribe.depot_enu_texte(&noyau, &session, &enu_texte, 0, "test", "ce n'est pas une EnuR"), Err(ErreurScribe::Interne(m)) if m.contains("ENU-004"))
    );

    // Dépôt à la racine du noeud
    scribe.depot_enu_texte(&noyau, &session, &enu_racine, 0, "test", "contenu de test")?;

    let enu_texte_relue = Enu::charger(&chemin_enu, &session, &enu_texte.hash_carte())?;

    assert_eq!(enu_texte_relue.braise(), session.braise_foyer(0)?);
    assert_eq!(enu_texte.carte(), enu_texte_relue.carte());

    let nouvelle_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    // témoin du câblage : le dépôt délègue bien la greffe, dont le comportement
    // propre est éprouvé par greffe_enfants_racine
    assert!(
        nouvelle_enu_racine
            .carte()
            .hashs_enu()?
            .contains(&enu_texte.hash_carte())
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

/// Cycle complet dépôt par comptoir → retrait, sur `fermeture_comptoir_depot`
/// et `retrait_lecture_seule` — jusqu'ici le plus gros trou de couverture du
/// fichier.
///
/// Dans l'ordre :
///
/// - **comptoir vide** : fermé sans greffe, la racine du nœud ne bouge pas ;
/// - **dépôt réel** : arborescence à trois niveaux (voir [`remplir_dossier`]),
///   déposée puis greffée sous la racine du nœud ; la nouvelle racine chaîne
///   bien vers l'ancienne via la méta `"_racine"` ;
/// - **`SCR-002`** : retrait visé sur un dossier déjà existant, refusé ;
/// - **retrait nominal** : l'arborescence relue depuis le disque après retrait
///   est identique (chemins relatifs + contenus, comparés en ensembles pour
///   ignorer l'ordre de parcours) à celle déposée dans le comptoir — capturée
///   *avant* la fermeture, qui supprime le dossier du comptoir.
#[test]
fn cycle_depot_retrait_simple() -> ResultScribe<()> {
    let (_tmp, _, chemin_derniere_racine, mut noyau, mut scribe, session) =
        cree_noyau_et_foyer_ouvert();

    let enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    let dossier_temporaire = TempDir::new().unwrap();

    //
    // Premier dépôt vide
    //
    let chemin_comptoir1 = dossier_temporaire.path().join("comptoir_depot1");

    let index_comptoir1 = scribe.ouverture_comptoir_depot(chemin_comptoir1.to_path_buf(), 0, 0)?;
    assert_eq!(index_comptoir1, 0);

    // Fermeture comptoir vide
    scribe.fermeture_comptoir_depot(&mut noyau, &session, index_comptoir1, &enu_racine)?;

    let deuxieme_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    // Pas de nouvelle racine
    assert_eq!(enu_racine, deuxieme_enu_racine);

    //
    // Deuxième dépôt non vide
    //
    let chemin_comptoir2 = dossier_temporaire.path().join("comptoir_depot2");

    let index_comptoir2 = scribe.ouverture_comptoir_depot(chemin_comptoir2.to_path_buf(), 0, 0)?;
    assert_eq!(index_comptoir2, 1);

    remplir_dossier(&chemin_comptoir2)?;

    let arborescence_origine = lire_arborescence(&chemin_comptoir2)?;

    scribe.fermeture_comptoir_depot(&mut noyau, &session, index_comptoir2, &enu_racine)?;

    let deuxieme_enu_racine = Enu::charger_derniere_racine(&chemin_derniere_racine, &session)?;

    assert_eq!(
        deuxieme_enu_racine.carte().metas().get("_racine"),
        Some(&HEXLOWER.encode(&enu_racine.hash_carte()))
    );

    //
    // Premier retrait avec un chemin déjà existant
    //
    let dossier_temporaire2 = TempDir::new().unwrap();

    assert!(matches!(
        scribe.retrait_lecture_seule(
            &mut noyau,
            &session,
            dossier_temporaire2.path(),
            &deuxieme_enu_racine
        ),
        Err(ErreurScribe::Interne(m)) if m.contains("SCR-002")));

    //
    // Deuxième retrait avec un chemin correct
    //
    let chemin_retrait = dossier_temporaire.path().join("retrait");

    scribe.retrait_lecture_seule(&mut noyau, &session, &chemin_retrait, &deuxieme_enu_racine)?;

    let arborescence_relue = lire_arborescence(&chemin_retrait)?;

    // Les deux arborescences doivent être identiques
    assert_eq!(arborescence_origine, arborescence_relue);

    fermer_foyer(noyau, session);

    Ok(())
}
