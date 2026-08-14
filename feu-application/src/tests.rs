// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Tests d'intégration de la crate, du point de vue de qui la consomme.
//!
//! Ces tests pilotent [`FeuApplication`] par ses seules `commande_*`, comme le
//! fait `feu-tui` : rien n'est appelé en direct sur le noyau, la session ou le
//! Scribe. C'est le contrat public de la crate qui est éprouvé, et lui seul.
//!
//! Ils se distinguent en cela de `scribe/tests.rs`, qui appelle le Scribe en
//! direct — `greffe_enfants`, `Enu::charger`, `Enu::remplacer`…
//!
//! **Ce fichier prend ce qui y tombe sans montage supplémentaire** : un test
//! écrit ici prouve le comportement **et** son câblage, le même écrit en bas ne
//! prouve que le premier. Mais atteignable ne suffit pas — une garde interne
//! dont les portes publiques sont déjà connues câblées reste en bas plutôt que
//! de se faire bâtir un décor exprès.
//!
//! Les constats, eux, lisent les champs privés de [`FeuApplication`] : le noyau
//! libéré, la session remise à zéro, le Scribe désactivé n'ont pas d'accesseur
//! public, et n'ont pas à en avoir — un consommateur n'a rien à faire de ces
//! états. D'où un `mod` interne plutôt qu'un crate de test dans `tests/` : on
//! agit par l'API publique, on constate par l'intérieur.
//!
//! # Non testé, délibérément
//!
//! `SCR-003`, branche d'un `else` immédiat. Les `From`, `Display`
//! et accesseurs de champ, passe-plats. Le pont `RecepteurNoyau`, exercé de
//! biais — rien ne se signerait sans lui. Le contrat de notification, prouvé par
//! chaque assertion portant sur la session reçue. Neuf des vingt-trois commandes
//! publiques, dont `feu-noyau` éprouve déjà le comportement.

use std::{
    cell::RefCell,
    collections::HashSet,
    fs::{File, create_dir, read_to_string, remove_dir, write},
};

use data_encoding::HEXLOWER;
use feu_noyau::{BRAISE_VIDE, MAX_CLASSEURS, MAX_FOYERS};
use rand::{Rng, distributions::Alphanumeric};
use tempfile::TempDir;
use walkdir::WalkDir;

use super::*;

/// Implémentation d'[`InterfaceFeuApplication`] pour les tests.
///
/// Répond par des valeurs fixes — aucune interaction réelle n'est possible sous
/// test. Enveloppée dans un [`RecepteurNoyau`] réel, elle laisse le vrai pont
/// remplir la [`SessionApplication`] exactement comme en production.
///
/// Retient la dernière session notifiée. C'est le seul moyen d'observer
/// [`recevoir_session_application`](InterfaceFeuApplication::recevoir_session_application)
/// depuis un test : là où `feu-tui` pousse le payload sur un canal et le stocke
/// dans le thread d'en face, un test n'a pas de second thread et doit le garder
/// sur place.
///
/// `pub(crate)` — partagée avec `scribe/tests.rs`.
pub(crate) struct InterfaceTest {
    /// Servi à chaque `demander_mdp`. Ouverture et fermeture d'un foyer doivent
    /// voir le même, sinon le déchiffrement échoue.
    mot_de_passe: SecretString,

    /// Dernière session notifiée. `RefCell` parce que le trait notifie sous
    /// `&self` : l'écriture ne peut venir que d'une mutabilité intérieure.
    session_application: RefCell<Option<SessionApplication>>,
}

impl InterfaceTest {
    /// Construit l'interface avec le mot de passe qu'elle servira.
    pub(crate) fn new(mot_de_passe: &str) -> Self {
        Self {
            mot_de_passe: SecretString::from(mot_de_passe),
            session_application: RefCell::new(None),
        }
    }

    /// Clone de la dernière session notifiée — `None` tant que rien n'a été
    /// notifié, et de nouveau `None` après extinction.
    pub(crate) fn session_application(&self) -> Option<SessionApplication> {
        self.session_application.borrow().clone()
    }
}

impl InterfaceFeuApplication for InterfaceTest {
    /// Sert toujours le même mot de passe : ouverture et fermeture d'un foyer
    /// doivent le voir identique, sinon le déchiffrement échoue.
    fn demander_mdp(&self) -> Option<SecretString> {
        Some(self.mot_de_passe.clone())
    }

    /// Jetée : aucun test n'a besoin de relire la seed. La retenir demanderait
    /// un second champ que rien ne consulterait.
    fn recevoir_seed(&self, _mots: &[&str]) {}

    /// Confirme toujours — sans quoi l'initialisation du noyau s'interromprait.
    fn confirmer_enregistrement_seed(&self) -> bool {
        true
    }

    /// Retient la session notifiée, seul état que l'interface conserve : c'est
    /// par elle que les tests constatent ce qu'une commande a publié.
    fn recevoir_session_application(&self, session_application: Option<SessionApplication>) {
        *self.session_application.borrow_mut() = session_application;
    }
}

/// Chaîne alphanumérique aléatoire de `n` caractères, pour nommer et remplir
/// les fichiers de test.
///
/// `pub(crate)` — partagée avec `scribe/tests.rs`.
fn chaine_aleatoire(n: usize) -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}

/// Écrit dans `destination` un fichier au nom et au contenu aléatoires, et
/// rend les deux.
///
/// Les rendre tous les deux est ce qui permet de retrouver le fichier après
/// coup sans rien relire du disque : le nom se compare à la méta `nom` de
/// l'ENU, le contenu au clair déchiffré du blob.
fn nouveau_fichier(destination: &Path, nombre_caracteres: usize) -> (String, String) {
    let nom_fichier = chaine_aleatoire(10);
    let contenu = chaine_aleatoire(nombre_caracteres);

    write(destination.join(&nom_fichier), contenu.clone()).unwrap();

    (nom_fichier, contenu)
}

/// Crée dans `destination` un dossier au nom aléatoire et rend son chemin.
///
/// Pendant de [`nouveau_fichier`], qui rend nom et contenu : ici le chemin
/// suffit — un dossier n'a rien à comparer après coup, il n'est qu'un endroit
/// où continuer à écrire.
fn nouveau_dossier(destination: &Path) -> PathBuf {
    let chemin = destination.join(chaine_aleatoire(10));

    create_dir(&chemin).unwrap();

    chemin
}

/// Peuple `chemin` d'une arborescence à trois niveaux : un fichier et un
/// dossier à la racine, ce dossier contenant lui-même un fichier et un
/// dossier, jusqu'à un troisième niveau ne contenant qu'un fichier.
///
/// Le Scribe traite différemment les enfants directs du comptoir (`depth == 1`)
/// et les sous-arbres plus profonds : la structure exerce les deux. Le
/// sous-dossier sert une seconde fois, sans rapport avec la profondeur — il est
/// la seule source d'`EnuR` signée sous une braise de foyer, la racine du nœud
/// portant `BRAISE_VIDE`.
///
/// Noms et contenus aléatoires : deux appels dans un même test ne se marchent
/// pas dessus.
fn remplir_dossier(chemin: &Path) -> ResultFeuApplication<()> {
    // Niveau 1
    // fichier 1
    nouveau_fichier(chemin, 100);

    // Dossier 1
    let chemin_dossier1 = nouveau_dossier(chemin);

    // Niveau 2
    // fichier 2
    nouveau_fichier(&chemin_dossier1, 100);

    // dossier 2
    let chemin_dossier2 = nouveau_dossier(&chemin_dossier1);

    // Niveau 3
    // fichier 3
    nouveau_fichier(&chemin_dossier2, 100);

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
fn lire_arborescence(chemin: &Path) -> ResultFeuApplication<HashSet<(PathBuf, String)>> {
    let mut resultat = HashSet::new();

    for entree in WalkDir::new(chemin).min_depth(1) {
        let entree = entree.unwrap();

        if entree.file_type().is_file() {
            let chemin_relatif = entree.path().strip_prefix(chemin).unwrap().to_path_buf();
            let contenu = read_to_string(entree.path()).unwrap();
            resultat.insert((chemin_relatif, contenu));
        }
    }

    Ok(resultat)
}

/// Cycle de vie complet du nœud par les commandes — du refus avant allumage
/// au teardown après extinction.
///
/// **Notification.** L'état est constaté sur la session reçue par
/// [`InterfaceTest`], jamais sur celle de [`FeuApplication`] : une assertion qui
/// passe prouve alors deux choses d'un coup — la commande a notifié, et le
/// payload portait l'état d'après. La braise non vide après l'allumage est
/// choisie pour ça : « foyers fermés » serait tout aussi vrai d'une session
/// neuve, et laisserait passer une notification vide.
///
/// **Gardes.** [`commande_extinction_noeud`](FeuApplication::commande_extinction_noeud)
/// refuse tant qu'un foyer est ouvert, accepte une fois refermé — les deux
/// moitiés comptent, un refus systématique passerait la première.
///
/// [`ErreurFeuApplication::NoeudEteint`] n'est éprouvée que sur les trois
/// commandes qui gardent sur l'activation du Scribe : leur refus est une ligne
/// ajoutée exprès, que rien d'autre ne retient. Ailleurs il tombe du `ok_or` sur
/// `feu_noyau`, sans quoi la commande ne compilerait pas. La plus importante est
/// [`commande_chargement_enu`](FeuApplication::commande_chargement_enu) : sans
/// elle, un hash inconnu sur un nœud éteint répondrait `Ok(None)` — le refus se
/// déguiserait en résultat.
///
/// **Teardown.** La session notifiée vaut `None` après extinction : les derniers
/// constats passent par les champs. La commande promet qu'aucune donnée
/// applicative ne survit, braise et clés publiques sont donc vérifiées une à
/// une. Le Scribe ferme la liste — `desactivation` est appelée en dernier, rien
/// n'en dépend, sans cette assertion la supprimer ne casserait rien. Le refus
/// qui la précède le constate de l'extérieur, sur une seule des trois gardes :
/// elles lisent un unique drapeau `est_actif`.
///
/// Le comptoir est ouvert puis **laissé ouvert** : l'extinction passe malgré
/// lui et l'annule, comme le documente
/// [`commande_ouverture_comptoir_depot`](FeuApplication::commande_ouverture_comptoir_depot).
/// Les fichiers déposés ne sont pas touchés pour autant, jamais ingérés.
#[test]
fn cycle_feu_application() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_depot = tmp.path().join("depot");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);
    assert!(interface_test.session_application().is_none());

    assert!(matches!(
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_depot, 0, 0),
        Err(ErreurFeuApplication::NoeudEteint)
    ));
    assert!(matches!(
        app.commande_derniere_enu_racine(),
        Err(ErreurFeuApplication::NoeudEteint)
    ));
    assert!(matches!(
        app.commande_chargement_enu(&[0u8; 32]),
        Err(ErreurFeuApplication::NoeudEteint)
    ));

    app.commande_allumage_noeud(&interface_test, None)?;
    assert_ne!(
        interface_test
            .session_application()
            .unwrap()
            .braise_foyer(0)
            .unwrap(),
        BRAISE_VIDE
    );

    app.commande_ouverture_foyer(&interface_test, 0)?;
    assert!(
        interface_test
            .session_application()
            .unwrap()
            .etat_foyer(0)
            .unwrap(),
    );

    app.commande_ouverture_comptoir_depot(&interface_test, &chemin_depot, 0, 0)?;

    assert!(matches!(
        app.commande_extinction_noeud(&interface_test),
        Err(ErreurFeuApplication::AuMoinsUnFoyerOuvert)
    ));

    app.commande_fermeture_foyer(&interface_test, 0)?;
    assert!(
        !interface_test
            .session_application()
            .unwrap()
            .etat_foyer(0)
            .unwrap(),
    );

    assert!(app.commande_extinction_noeud(&interface_test).is_ok());
    assert!(interface_test.session_application().is_none());
    assert!(matches!(
        app.commande_chargement_enu(&[0u8; 32]),
        Err(ErreurFeuApplication::NoeudEteint)
    ));

    // Plus rien à tirer de la session notifiée, désormais `None` : le teardown
    // ne se constate que sur les champs.
    assert_eq!(app.session.braise_foyer(0).unwrap(), BRAISE_VIDE);
    assert_eq!(app.session.cle_publique_sig_noeud(), [0u8; 2592]);
    assert_eq!(app.session.cle_publique_sig_foyer(0).unwrap(), [0u8; 2592]);
    assert!(app.session.foyers_fermes());
    assert!(!app.scribe.est_actif());

    Ok(())
}

/// Un fichier déposé par comptoir se relit à l'identique après extinction et
/// rallumage du nœud — nom et contenu.
///
/// Seul test qui **rallume**. Tout le reste de la suite vit dans un unique
/// allumage et ne prouve donc rien du disque : ce qu'il observe pourrait tenir
/// à un état gardé en mémoire. Ici l'instance est détruite entre les deux
/// moitiés, et la seconde ne repart que de `chemin_feu`.
///
/// **Racine.** L'assertion tient en deux temps. `assert_ne!` établit que ce que
/// `.DERNIERE_RACINE` désigne après rallumage est la racine d'*après* dépôt, et
/// non l'origine — sans quoi le test pourrait survivre à une greffe jamais
/// écrite sur disque. Le compte d'enfants à un ajoute que l'ancienne racine ne
/// s'y trouve pas : elle se chaîne par la méta `_racine`, pas comme enfant.
///
/// **Dépôt à la racine**, sans imbrication : la descente tient alors en un seul
/// [`commande_chargement_enu`](FeuApplication::commande_chargement_enu) jusqu'à
/// la [`Carte::Donnee`], et le test reste centré sur la survie de la donnée. Le
/// cas imbriqué relève de [`cycle_depot_retrait_simple`].
#[test]
fn cycle_depot_extinction_rallumage() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_depot = tmp.path().join("depot");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let index_comptoir =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_depot, 0, 0)?;
    assert_eq!(index_comptoir, 0);

    let (nom_fichier, contenu) = nouveau_fichier(&chemin_depot, 100);

    let enu_racine = app.commande_derniere_enu_racine()?;

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine)?;

    // le dossier physique du comptoir disparaît avec son rangement
    assert!(!chemin_depot.exists());

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    // `drop` explicite : le shadowing seul garderait la première instance en vie
    // jusqu'à la fin du test, et le rallumage ne prouverait plus rien du disque
    drop(app);
    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let nouvelle_racine = app.commande_derniere_enu_racine()?;

    assert_ne!(nouvelle_racine, enu_racine);
    assert_eq!(nouvelle_racine.carte().hashs_enu()?.len(), 1);

    let enu_rechargee = app
        .commande_chargement_enu(nouvelle_racine.carte().hashs_enu()?.first().unwrap())?
        .unwrap();

    assert_eq!(
        enu_rechargee.carte().metas().get("nom").unwrap(),
        &nom_fichier
    );

    // `create` et non `open` : la destination n'existe pas encore et doit être
    // ouverte en écriture, `commande_chargement_blob` réclamant un `Write`
    let chemin_relecture = tmp.path().join("relecture");
    let fichier = File::create(&chemin_relecture).unwrap();

    app.commande_chargement_blob(&enu_rechargee, &fichier)?;

    let contenu_relu = read_to_string(&chemin_relecture).unwrap();

    assert_eq!(contenu, contenu_relu);

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Cycle de vie d'un blob désigné par sa seule ENU — présence, informations,
/// suppression — et ce qu'il advient de l'ENU quand le blob n'est plus là.
///
/// **Le sujet est la fin.** `existence_blob` faux et `chargement_enu` encore
/// `Some` sur le même hash : le blob est parti, l'arborescence est intacte.
/// [`commande_suppression_blob`](FeuApplication::commande_suppression_blob)
/// retire le `.dat` sans rien retirer de l'arbre — comportement documenté sur
/// les deux commandes, jamais éprouvé jusqu'ici. Pris isolément, aucun des deux
/// constats ne dit rien : le premier prouve une suppression réussie, le second
/// une ENU lisible. C'est leur simultanéité qui est le décalage.
///
/// **Test à part**, et non greffé dans [`cycle_depot_extinction_rallumage`] qui
/// monte pourtant le même décor : la suppression est destructrice, tout constat
/// de persistance placé après elle serait faux. L'ordre des deux deviendrait un
/// invariant tacite, et un échec ne dirait plus lequel a lâché.
///
/// **`SCR-004`** — la racine porte `BRAISE_VIDE`, absente des braises de la
/// session. C'est la seule braise inconnue qu'un appelant puisse produire sans
/// forger d'ENU : les trois braises de foyer restent résolvables tant que le
/// nœud est allumé, fermer un foyer ne touche pas `braise_foyers`. Passée par
/// [`commande_existence_blob`](FeuApplication::commande_existence_blob), la
/// moins chère des quatre portes sur `index_et_hash_blob` — ni destination à
/// fournir, ni emprunt mutable. Le code se lit dans le message, `From<ErreurScribe>`
/// aplatissant la variante en `String` à la frontière.
///
/// **Taille** strictement supérieure au clair, jamais égale : le blob est
/// chiffré, nonce et tag s'ajoutent à chaque chunk. Les dates de
/// [`DonneesBlob`] sont écartées — `donne_date_creation` rend un `Option` que
/// tous les systèmes de fichiers ne renseignent pas.
///
/// Le `Ok(None)` sur hash inconnu tient ici parce qu'il s'oppose au `Some`
/// obtenu deux lignes plus haut. Seul, il ne prouverait rien.
#[test]
fn cycle_vie_blob() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");
    let chemin_depot = tmp.path().join("depot");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 0)?;

    let index_comptoir =
        app.commande_ouverture_comptoir_depot(&interface_test, &chemin_depot, 0, 0)?;
    assert_eq!(index_comptoir, 0);

    nouveau_fichier(&chemin_depot, 100);

    let enu_racine = app.commande_derniere_enu_racine()?;

    app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine)?;

    let nouvelle_racine = app.commande_derniere_enu_racine()?;

    let enu_rechargee = app
        .commande_chargement_enu(nouvelle_racine.carte().hashs_enu()?.first().unwrap())?
        .unwrap();

    assert!(app.commande_existence_blob(&enu_rechargee)?);

    let taille_blob = app
        .commande_informations_blob(&enu_rechargee)?
        .donne_taille();

    assert!(taille_blob > 100);

    assert!(matches!(app.commande_chargement_enu(&[0u8; 32]), Ok(None)));

    assert!(matches!(
        app.commande_existence_blob(&enu_racine),
        Err(ErreurFeuApplication::ScribeBraiseInconnue)
    ));

    app.commande_suppression_blob(&enu_rechargee)?;

    assert!(!app.commande_existence_blob(&enu_rechargee)?);

    assert!(
        app.commande_chargement_enu(&enu_rechargee.hash_carte())?
            .is_some()
    );

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Les gardes du comptoir de dépôt, dans l'ordre où elles se posent.
///
/// À l'ouverture, les deux index sont validés contre leurs bornes de
/// compilation — `SCR-006` et `SCR-009` — parce qu'un comptoir les fige :
/// admis ici, ils condamneraient toutes ses fermetures.
///
/// À la fermeture, trois refus. `SCR-001` d'abord : un identifiant que rien n'a
/// distribué. Puis deux états que l'ouverture ne pouvait pas prévoir — foyer
/// refermé entre-temps (`SCR-008`, seul refus rattrapable : le foyer rouvert, la
/// même fermeture repart, ce que la suite du test exerce) et dossier disparu du
/// disque (`SCR-007`, constaté après le retrait du comptoir, donc sans reprise).
///
/// Établit aussi que le miroir de session suit le Scribe sur chacun de ces
/// chemins : présent tant que le comptoir l'est, parti dès qu'il l'a lâché. Ces
/// quatre assertions sont ce qui interdit au miroir de se remettre à diverger.
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
        app.session
            .comptoirs_depot_ouverts()
            .contains(&index_comptoir)
    );

    app.commande_fermeture_foyer(&interface_test, 0)?;

    assert!(matches!(
        app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine),
        Err(ErreurFeuApplication::ScribeFoyerFerme(_))
    ));
    // SCR-008 tombe avant le retrait : l'identifiant reste des deux côtés, sans
    // quoi la retentative qui suit n'aurait plus rien à désigner
    assert!(
        app.session
            .comptoirs_depot_ouverts()
            .contains(&index_comptoir)
    );

    app.commande_ouverture_foyer(&interface_test, 0)?;

    assert!(matches!(
        app.commande_fermeture_comptoir_depot(&interface_test, 1, &enu_racine),
        Err(ErreurFeuApplication::ScribeIndexComptoirInconnu(_))
    ));

    remove_dir(&chemin_comptoir1).unwrap();

    assert!(matches!(
        app.commande_fermeture_comptoir_depot(&interface_test, index_comptoir, &enu_racine),
        Err(ErreurFeuApplication::ScribeDossierDepotIntrouvable(_))
    ));
    // SCR-007 est constaté après le retrait : le Scribe a lâché le comptoir, la
    // session l'a lâché avec lui, sur un chemin qui rend pourtant une erreur
    assert!(app.session.comptoirs_depot_ouverts().is_empty());

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    assert!(app.session.comptoirs_depot_ouverts().is_empty());

    Ok(())
}

/// Aller-retour complet dépôt par comptoir → retrait, sur une arborescence à
/// plusieurs niveaux : ce qui ressort est exactement ce qui est entré.
///
/// **Venu de `scribe/tests.rs`**, où il appelait `fermeture_comptoir_depot` et
/// `retrait_lecture_seule` en direct. Il y était né par nécessité : aucune
/// commande ne produisait alors d'[`Enu`], que les deux fonctions réclament.
/// [`commande_derniere_enu_racine`](FeuApplication::commande_derniere_enu_racine)
/// l'a levée, et les deux commandes n'étant que des passe-plats, rien ne restait
/// hors d'atteinte d'en haut — le double n'a pas été gardé.
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
///   *avant* la fermeture, qui supprime le dossier du comptoir ;
/// - **`SCR-005`** : le répertoire de niveau 1 passé à une commande blob, qui
///   n'y trouve aucun `hash_donnee`.
///
/// **`SCR-005` tient ici et nulle part ailleurs.** Il lui faut une [`Enu`] qui
/// franchisse la première garde de `index_et_hash_blob` pour buter sur la
/// seconde : une `Carte::Repertoire` signée sous une **braise de foyer**. La
/// racine ne convient pas, elle porte `BRAISE_VIDE` et tombe sur `SCR-004`
/// avant. Seul un dépôt imbriqué en produit une.
///
/// Le répertoire se retrouve parmi les deux enfants de la racine, l'autre étant
/// le fichier de niveau 1. Les deux hashs se tirent d'**un seul** `BTreeSet`
/// gardé en variable : `hashs_enu` le rend par valeur, deux appels successifs
/// rendraient chacun leur propre plus petit élément, donc deux fois la même ENU.
/// Le `assert_eq!` sur son cardinal fixe l'hypothèse et cède franchement si
/// [`remplir_dossier`] change de forme, là où la sélection se contenterait de
/// choisir mal.
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
    assert_eq!(index_comptoir2, 1);

    remplir_dossier(&chemin_comptoir2)?;

    let arborescence_origine = lire_arborescence(&chemin_comptoir2)?;

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

    let arborescence_relue = lire_arborescence(&chemin_retrait)?;

    // Les deux arborescences doivent être identiques
    assert_eq!(arborescence_origine, arborescence_relue);

    // Récupération de l'EnuR sous la racine
    let hashs = &mut deuxieme_enu_racine.carte().hashs_enu().unwrap();
    assert_eq!(hashs.len(), 2);

    let enu1 = app
        .commande_chargement_enu(&hashs.pop_first().unwrap())?
        .unwrap();
    let enu2 = app
        .commande_chargement_enu(&hashs.pop_first().unwrap())?
        .unwrap();

    let enur = if matches!(
        enu1.carte(),
        Carte::Repertoire {
            metas: _,
            tags: _,
            hashs_enu: _
        }
    ) {
        enu1
    } else {
        enu2
    };

    assert!(matches!(
        app.commande_existence_blob(&enur),
        Err(ErreurFeuApplication::ScribeEnuDAttendue)
    ));

    app.commande_fermeture_foyer(&interface_test, 0)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}

/// Aller-retour de deux `EnuT` **homonymes** déposées à la racine du nœud —
/// dépôt, relecture des cartes, puis matérialisation sur disque.
///
/// Venu de `scribe/tests.rs`, où il n'éprouvait que le dépôt. L'`EnuT` que
/// l'ancien test forgeait en double, faute que `depot_enu_texte` rende quoi que
/// ce soit, n'a plus lieu d'être : les hashs se lisent dans la racine et
/// [`commande_chargement_enu`](FeuApplication::commande_chargement_enu) rend
/// l'[`Enu`] déjà authentifiée. Le retrait, lui, est nouveau.
///
/// **Deux dépôts, trois racines.** Le second part de la racine rendue *après* le
/// premier : greffé sous une racine périmée, il reconstruirait un sommet issu de
/// l'originale et le premier texte finirait orphelin, hors de l'arbre. Le
/// `assert_eq!` sur le cardinal des enfants attrape cette erreur.
///
/// **Foyer 1**, alors que la racine est signée par le nœud : les deux braises
/// relevées distinguent le foyer du texte de celui du répertoire d'accueil. Un
/// `depot_enu_texte` qui signerait sous la braise de la destination passerait
/// toutes les autres assertions.
///
/// **Contenus tous différents**, non par souci de lisibilité : deux textes
/// identiques au même nom donneraient la même carte, donc le même `hash_carte`,
/// donc **une seule** ENU dans le `BTreeSet` de la racine — plus d'homonymes à
/// retirer. Le troisième, celui du refus `ENU-004`, répond à autre chose :
/// l'`EnuT` est sauvegardée avant que la greffe n'échoue, et reprendre un texte
/// déjà déposé écraserait son fichier.
///
/// Le test couvre, dans l'ordre :
///
/// - **dépôt nominal** : les deux `EnuT` sont sous le sommet, authentifiées,
///   signées sous la braise du foyer demandé, nom et contenu intacts ;
/// - **refus `ENU-004`** : une `Carte::Texte` passée comme racine de dépôt n'est
///   pas un répertoire ;
/// - **retrait, branche `Carte::Texte`** : jamais exécutée jusqu'ici, le
///   comptoir ne produisant que `Donnee` et `Repertoire`. Le contenu embarqué
///   est écrit sans passer par le noyau ;
/// - **retrait, homonymes** : `chemin_libre` était éprouvé isolément, jamais
///   branché dans la récursion. Les deux fichiers sortent en `test` et `test_1`.
///
/// Deux comparaisons contournent l'ordre des hashs, qui ne suit ni celui des
/// dépôts ni celui des noms : un ensemble pour les contenus des cartes, un tri
/// pour ceux relus sur disque. Les deux `read_to_string` suffisent par ailleurs
/// à établir le suffixage — l'absence de `test_1` les ferait paniquer.
#[test]
fn cycle_enu_texte() -> ResultFeuApplication<()> {
    let tmp = TempDir::new().unwrap();
    let chemin_feu = tmp.path().join(".feu");

    let interface_test = InterfaceTest::new("mot de passe");

    let mut app = FeuApplication::new(&chemin_feu);

    app.commande_allumage_noeud(&interface_test, None)?;

    app.commande_ouverture_foyer(&interface_test, 1)?;

    let enu_racine = app.commande_derniere_enu_racine()?;

    app.commande_depot_enu_texte(&enu_racine, 1, "test", "enu test 1")?;
    let deuxieme_enu_racine = app.commande_derniere_enu_racine()?;
    app.commande_depot_enu_texte(&deuxieme_enu_racine, 1, "test", "enu test 2")?;
    let troisieme_enu_racine = app.commande_derniere_enu_racine()?;

    let hashs = &mut troisieme_enu_racine.carte().hashs_enu().unwrap();
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
    assert_eq!(metas1["nom"], "test");
    assert_eq!(metas2["nom"], "test");
    assert_eq!(enu1.braise(), app.session.braise_foyer(1).unwrap());
    assert_eq!(enu2.braise(), app.session.braise_foyer(1).unwrap());

    let contenus = HashSet::from([contenu1.as_str(), contenu2.as_str()]);
    assert_eq!(contenus, HashSet::from(["enu test 1", "enu test 2"]));

    assert!(matches!(
        app.commande_depot_enu_texte(&enu1, 1, "test", "enu test 3"),
        Err(ErreurFeuApplication::ScribeEnuRAttendue)
    ));

    let chemin_retrait = tmp.path().join("retrait");
    app.commande_retrait_lecture_seule(&chemin_retrait, &troisieme_enu_racine)?;

    let mut contenus = [
        read_to_string(chemin_retrait.join("test")).unwrap(),
        read_to_string(chemin_retrait.join("test_1")).unwrap(),
    ];
    contenus.sort();

    assert_eq!(contenus, ["enu test 1", "enu test 2"]);

    app.commande_fermeture_foyer(&interface_test, 1)?;

    app.commande_extinction_noeud(&interface_test)?;

    Ok(())
}
