// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Tests de bout en bout du noyau.
//!
//! Une pile réelle est montée dans un `TempDir` — seed neuve, dérivation des
//! clés post-quantiques, arborescence sur disque, chiffrement effectif — plutôt
//! que des composants isolés. Seule une pile complète permet d'éprouver ce qui
//! fait la valeur du noyau : qu'une donnée confiée à un foyer se retrouve
//! intacte après extinction, et qu'elle reste hors de portée de qui n'a pas le
//! mot de passe.
//!
//! Sept tests, chacun repartant d'un nœud neuf.
//!
//! Les assertions portent sur ce que le noyau **rend observable**, jamais sur
//! son état interne : les rappels à l'interface, que [`InterfaceTest`]
//! enregistre, les valeurs et erreurs de retour, et les fichiers laissés sur le
//! disque, dont les chemins se déduisent de la seule braise.

use std::{
    fs::{
        File, create_dir, read_dir, read_to_string, remove_dir, remove_dir_all, remove_file,
        symlink_metadata, write,
    },
    mem::forget,
    os::unix::fs::PermissionsExt,
};

use tempfile::TempDir;

use super::*;

/// Implémentation d'[`InterfaceFeuNoyau`] qui enregistre tout ce qu'elle reçoit.
///
/// Là où un double muet suffirait à satisfaire le trait, celle-ci conserve
/// chaque valeur remontée par le noyau — seed, braises, états d'ouverture, clés
/// publiques — parce que ces valeurs *sont* la matière des assertions : le noyau
/// ne s'observe que par ce qu'il notifie.
///
/// Les réponses aux questions bloquantes ([`demander_mdp`](InterfaceFeuNoyau::demander_mdp),
/// [`confirmer_enregistrement_seed`](InterfaceFeuNoyau::confirmer_enregistrement_seed))
/// sont fixes et déterministes : aucune interaction réelle n'est possible sous
/// test.
#[derive(Debug, PartialEq)]
struct InterfaceTest {
    mot_de_passe: String,
    seed: Vec<String>,
    braises: [Braise; MAX_FOYERS],
    etats: [bool; MAX_FOYERS],
    cle_publique_noeud: Option<[u8; 2592]>,
    cles_pub_sig: [Option<[u8; 2592]>; MAX_FOYERS],
    cles_pub_chif: [Option<[u8; 1568]>; MAX_FOYERS],
}

impl InterfaceTest {
    /// Construit une interface vierge, dans l'état d'avant tout rappel.
    ///
    /// Les valeurs neutres — [`BRAISE_VIDE`], foyers fermés, clés absentes — ne
    /// sont pas de simples valeurs par défaut : elles permettent de distinguer
    /// un rappel reçu d'un rappel jamais émis, ce dont le test se sert pour
    /// situer chaque notification dans le cycle de vie du noyau.
    fn new(mot_de_passe: &str) -> Self {
        Self {
            mot_de_passe: String::from(mot_de_passe),
            seed: Vec::new(),
            braises: [BRAISE_VIDE; MAX_FOYERS],
            etats: [false; MAX_FOYERS],
            cle_publique_noeud: None,
            cles_pub_sig: [None; MAX_FOYERS],
            cles_pub_chif: [None; MAX_FOYERS],
        }
    }
}

impl InterfaceFeuNoyau for InterfaceTest {
    // Constant : le mot de passe est redemandé à chaque allumage du nœud et à
    // chaque ouverture de foyer, deux fois lors d'un changement. Le figer fait
    // concorder toutes ces saisies ; en faire varier la valeur d'une interface
    // à l'autre est ce qu'éprouve `cycle_mot_de_passe`.
    fn demander_mdp(&self) -> Option<SecretString> {
        Some(SecretString::from(self.mot_de_passe.clone()))
    }

    fn recevoir_seed(&mut self, mots: &[&str]) {
        for e in mots {
            self.seed.push(String::from(*e));
        }
    }

    // Un refus ferait échouer la création du nœud sur
    // `CryptographeSeedNonConfirmee`, avant même que le moindre foyer existe.
    fn confirmer_enregistrement_seed(&self) -> bool {
        true
    }

    fn recevoir_braise_foyer(&mut self, index_foyer: usize, braise: Braise) {
        self.braises[index_foyer] = braise;
    }

    fn recevoir_etat_foyer(&mut self, index_foyer: usize, etat: bool) {
        self.etats[index_foyer] = etat;
    }

    fn recevoir_cle_publique_noeud(&mut self, cle_publique_sig_noeud: [u8; 2592]) {
        self.cle_publique_noeud = Some(cle_publique_sig_noeud);
    }

    fn recevoir_cles_publiques_foyer(
        &mut self,
        index_foyer: usize,
        cle_publique_sig: [u8; 2592],
        cle_publique_chif: [u8; 1568],
    ) {
        self.cles_pub_sig[index_foyer] = Some(cle_publique_sig);
        self.cles_pub_chif[index_foyer] = Some(cle_publique_chif);
    }
}

/// Vérifie que tout dossier sous `racine` est en `0o700` et tout fichier en
/// `0o600` — les deux seuls modes que le noyau pose, sans exception.
///
/// Un parcours plutôt qu'une liste de chemins : la règle est uniforme, et rien
/// ne doit y échapper parce qu'un fichier serait apparu depuis. C'est ainsi
/// qu'a été trouvé le dossier de foyer laissé au `umask` par `unpack`.
///
/// Les liens symboliques sont écartés sans être suivis : `registre/classeur.N`
/// pointe vers la racine du foyer, et y descendre ferait boucler le parcours.
fn verifie_permissions(racine: &Path) {
    let mode = |c: &Path| symlink_metadata(c).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(racine), 0o700, "{}", racine.display());

    for entree in read_dir(racine).unwrap() {
        let chemin = entree.unwrap().path();

        if chemin.is_symlink() {
            continue;
        }

        if chemin.is_dir() {
            verifie_permissions(&chemin);
        } else {
            assert_eq!(mode(&chemin), 0o600, "{}", chemin.display());
        }
    }
}

/// Un blob déposé dans chacun des trois foyers se relit à l'identique après que
/// le noyau a été détruit puis reconstruit, braises et clé publique de nœud
/// retrouvées à partir du seul mot de passe, et s'efface ensuite sans trace.
///
/// Établit au passage l'unicité d'un blob dans un foyer, la relecture d'un
/// contenu dépassant [`TAILLE_CHUNK`], et les permissions aux trois états
/// stables du nœud.
#[test]
fn cycle_vie_noyau() -> ResultFeuNoyau<()> {
    let tmp = TempDir::new().unwrap();

    let chemin_feu = tmp.path().join(".feu");

    let chemin_donnees = tmp.path().join("fichier.txt");

    let contenu: String = (0..1000)
        .map(|i| format!("ligne {i:04} du blob de test\n"))
        .collect();

    write(&chemin_donnees, &contenu).unwrap();
    let mut hash_blob = String::new();

    let mut interface = InterfaceTest::new("mot de passe");

    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut interface)?;

    assert!(interface.cle_publique_noeud.is_some());

    for i in 0..MAX_FOYERS {
        assert!(!interface.etats[i]);
        assert!(interface.braises[i] != BRAISE_VIDE);

        noyau.ouverture_foyer(&mut interface, i)?;

        // Les clés publiques du foyer ne remontent qu'ici : elles n'existent
        // qu'une fois le foyer désarchivé, un foyer fermé n'étant qu'une archive
        // chiffrée. Les asserter avant l'ouverture échouerait.
        assert!(interface.etats[i]);
        assert!(interface.cles_pub_sig[i].is_some());
        assert!(interface.cles_pub_chif[i].is_some());

        // Chaque dépôt exige une source neuve : `remplir` lit jusqu'à EOF, un
        // handle réutilisé ne rendrait plus qu'un blob vide.
        let source_donnees = File::open(&chemin_donnees).unwrap();
        (hash_blob, _) = noyau.depot_blob(i, 0, &source_donnees)?;

        // Même contenu, autre classeur demandé : le blob ne doit pas être
        // dupliqué, et le dépôt rendre le classeur 0 où il réside déjà. Le hash
        // identique le confirme — il ne dépend que du clair, jamais de la clé du
        // classeur sous laquelle il vient d'être chiffré.
        let source_donnees = File::open(&chemin_donnees).unwrap();
        let (hash_blob2, index) = noyau.depot_blob(i, 1, &source_donnees)?;

        assert_eq!(noyau.liste_blobs(i, 0)?.len(), 1);
        assert_eq!(noyau.liste_blobs(i, 0)?.first().unwrap(), &hash_blob);
        assert_eq!(noyau.liste_blobs(i, 1)?.len(), 0);

        assert_eq!(index, 0);
        assert_eq!(hash_blob, hash_blob2);

        noyau.fermeture_foyer(&mut interface, i)?;

        assert!(!interface.etats[i]);
    }

    // Extinction explicite : le second noyau doit tout retrouver du disque et du
    // mot de passe, sans rien hériter du premier resté vivant.
    drop(noyau);

    let mut interface2 = InterfaceTest::new("mot de passe");
    let mut noyau2 = FeuNoyau::new(&chemin_feu, None, &mut interface2)?;

    verifie_permissions(&chemin_feu);

    // Comparaison champ à champ, et non des deux interfaces entières : elles
    // n'ont pas vécu la même histoire. `interface2` n'a reçu ni la seed — émise
    // à la seule création du nœud — ni les clés publiques de foyer, qui
    // attendent une ouverture. Braises et clé de nœud sont les deux rappels
    // communs aux deux allumages, et portent l'invariant qui compte : la
    // dérivation depuis la seed est reproductible.
    assert_eq!(interface.cle_publique_noeud, interface2.cle_publique_noeud);
    assert_eq!(interface.braises, interface2.braises);

    for i in 0..MAX_FOYERS {
        // Recréé à chaque tour pour tronquer : `vider` écrit à la position
        // courante, un handle partagé concaténerait les lectures successives.
        let fichier_recuperation = File::create(tmp.path().join("temp")).unwrap();

        noyau2.ouverture_foyer(&mut interface2, i)?;

        noyau2.lecture_blob(i, &hash_blob, &fichier_recuperation)?;

        let contenu_recupere = read_to_string(tmp.path().join("temp")).unwrap();

        assert_eq!(contenu, contenu_recupere);

        // Classeur 0 : celui que le premier dépôt a rendu, et où le second a
        // laissé le blob.
        noyau2.suppression_blob(i, &hash_blob)?;

        assert!(!noyau2.existence_blob(i, &hash_blob)?);
        assert!(matches!(
            noyau2.lecture_blob(i, &hash_blob, &fichier_recuperation),
            Err(ErreurFeuNoyau::BlobIntrouvable(_))
        ));
    }

    verifie_permissions(&chemin_feu);

    for i in 0..MAX_FOYERS {
        noyau2.fermeture_foyer(&mut interface2, i)?;

        assert!(!interface2.etats[i]);
    }

    verifie_permissions(&chemin_feu);

    Ok(())
}

/// Après un changement de mot de passe, l'ancien n'ouvre plus rien et le nouveau
/// ouvre tout — aux deux points où le mot de passe est saisi.
///
/// Les deux points de saisie — allumage du nœud, ouverture d'un foyer — sont
/// éprouvés séparément. Établit en outre qu'une ouverture refusée ne coûte
/// rien.
#[test]
fn cycle_mot_de_passe() -> ResultFeuNoyau<()> {
    let tmp = TempDir::new().unwrap();

    let chemin_feu = tmp.path().join(".feu");

    let mut interface = InterfaceTest::new("mot de passe");

    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut interface)?;

    // `changement_mdp` exige les trois foyers ouverts — leurs clés doivent être
    // en mémoire pour être rechiffrées, sinon `AuMoinsUnFoyerFerme`.
    for i in 0..MAX_FOYERS {
        noyau.ouverture_foyer(&mut interface, i)?;
    }

    // Le nouveau mot de passe est porté par une interface distincte : le
    // changement le collecte par deux appels à `demander_mdp` et les exige
    // égaux, ce qu'une interface à mot de passe fixe satisfait par construction.
    let mut interface2 = InterfaceTest::new("nouveau mot de passe");

    noyau.changement_mdp(&mut interface2)?;

    // L'interface passée ici est indifférente : la fermeture rechiffre avec les
    // clés déjà en mémoire et ne redemande jamais le mot de passe.
    for i in 0..MAX_FOYERS {
        noyau.fermeture_foyer(&mut interface, i)?;
    }

    // Extinction explicite : ce qui suit doit tout relire du disque, sans
    // bénéficier du trousseau que le premier noyau gardait en mémoire.
    drop(noyau);

    // Premier point de saisie : l'ancien mot de passe ne déverrouille plus les
    // clés du nœud, l'allumage échoue avant tout accès aux foyers. La variante
    // seule suffit à situer la panne dans la crypto — discriminer plus finement
    // demanderait de s'appuyer sur le `Display` d'`aes-gcm`, hors du contrôle
    // de Feu.
    let mut interface = InterfaceTest::new("mot de passe");

    assert!(matches!(
        FeuNoyau::new(&chemin_feu, None, &mut interface),
        Err(ErreurFeuNoyau::AesGcm(_))
    ));

    let mut interface2 = InterfaceTest::new("nouveau mot de passe");

    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut interface2)?;

    // L'état d'un foyer se lit sur le disque, et ce triplet le fixe : dossier
    // clair s'il est ouvert, archive `.feu` s'il est fermé, jamais les deux — et
    // jamais de `.tar`, qui ne survit à aucune opération, réussie ou non. Il est
    // rejoué après chaque transition qui suit.
    for i in 0..MAX_FOYERS {
        assert!(!chemin_feu.join(interface2.braises[i].to_string()).is_dir());
        assert!(
            chemin_feu
                .join(format!("{}.feu", interface2.braises[i]))
                .exists()
        );
        assert!(
            !chemin_feu
                .join(format!("{}.tar", interface2.braises[i]))
                .exists()
        );
    }

    noyau.ouverture_foyer(&mut interface2, 0)?;

    assert!(chemin_feu.join(interface2.braises[0].to_string()).is_dir());
    assert!(
        !chemin_feu
            .join(format!("{}.feu", interface2.braises[0]))
            .exists()
    );
    assert!(
        !chemin_feu
            .join(format!("{}.tar", interface2.braises[0]))
            .exists()
    );

    noyau.fermeture_foyer(&mut interface2, 0)?;

    assert!(!chemin_feu.join(interface2.braises[0].to_string()).is_dir());
    assert!(
        chemin_feu
            .join(format!("{}.feu", interface2.braises[0]))
            .exists()
    );
    assert!(
        !chemin_feu
            .join(format!("{}.tar", interface2.braises[0]))
            .exists()
    );

    // Second point de saisie : nœud allumé avec le bon mot de passe, foyer 0
    // refermé juste avant. L'échec ne peut donc venir que de l'ancien mot de
    // passe présenté à l'ouverture.
    assert!(matches!(
        noyau.ouverture_foyer(&mut interface, 0),
        Err(ErreurFeuNoyau::AesGcm(_))
    ));

    assert!(!chemin_feu.join(interface2.braises[0].to_string()).is_dir());
    assert!(
        chemin_feu
            .join(format!("{}.feu", interface2.braises[0]))
            .exists()
    );
    assert!(
        !chemin_feu
            .join(format!("{}.tar", interface2.braises[0]))
            .exists()
    );

    // Le refus n'a rien laissé derrière lui : un `.tar` résiduel ferait échouer
    // cette réouverture sur son existence, avant même la saisie du mot de passe.
    noyau.ouverture_foyer(&mut interface2, 0)?;
    noyau.fermeture_foyer(&mut interface2, 0)?;

    Ok(())
}

/// Chaque opération refusée à un appelant qui s'y prend mal rend la variante
/// d'erreur qui nomme la cause, et non une erreur générique.
///
/// Les cas sont réunis dans un test unique parce qu'ils partagent la seule chose
/// coûteuse ici — le montage d'un nœud et l'Argon2id de ses ouvertures. Ils
/// s'enchaînent sur le même foyer, chacun le laissant dans l'état qu'attend le
/// suivant.
///
/// [`ErreurFeuNoyau::IndexFoyerInvalide`] et
/// [`ErreurFeuNoyau::IndexClasseurInvalide`] en sont absentes délibérément :
/// c'est une comparaison de borne répétée à l'entrée d'une dizaine de méthodes,
/// sans logique qu'un test puisse prendre en défaut.
#[test]
fn erreurs_usage() -> ResultFeuNoyau<()> {
    let tmp = TempDir::new().unwrap();

    let chemin_feu = tmp.path().join(".feu");

    let mut interface = InterfaceTest::new("mot de passe");

    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut interface)?;

    // Tous les foyers sont fermés à l'allumage : le refus de fermer est le seul
    // qui s'éprouve sans rien préparer.
    assert!(matches!(
        noyau.fermeture_foyer(&mut interface, 0),
        Err(ErreurFeuNoyau::FoyerFerme(i)) if i == 0
    ));

    noyau.ouverture_foyer(&mut interface, 0)?;

    assert!(matches!(
        noyau.ouverture_foyer(&mut interface, 0),
        Err(ErreurFeuNoyau::FoyerDejaOuvert(i)) if i == 0
    ));

    // Un seul foyer ouvert sur les trois : le rechiffrement du trousseau exige
    // que toutes les clés soient en mémoire, il refuse d'en laisser une derrière.
    assert!(matches!(
        noyau.changement_mdp(&mut interface),
        Err(ErreurFeuNoyau::AuMoinsUnFoyerFerme)
    ));

    // Hash bien formé — 64 caractères, la longueur d'un SHA3-256 en hexadécimal
    // — mais qu'aucun classeur ne détient. Le foyer doit rester ouvert : la
    // garde d'état passe avant le balayage, et le refuserait en premier.
    let hash = "1".repeat(64);

    let fichier_recuperation = File::create(tmp.path().join("temp")).unwrap();

    assert!(matches!(
        noyau.lecture_blob(0, &hash, &fichier_recuperation),
        Err(ErreurFeuNoyau::BlobIntrouvable(i)) if i == 0
    ));

    noyau.fermeture_foyer(&mut interface, 0)?;

    let chemin_donnees = tmp.path().join("fichier.txt");
    let contenu = "contenu de test";
    write(&chemin_donnees, contenu).unwrap();

    // Le foyer vient d'être refermé. La garde est centralisée dans
    // `archiviste_foyer_ouvert` : l'éprouver sur le dépôt vaut pour toutes les
    // opérations qui en dépendent.
    let source_donnees = File::open(&chemin_donnees).unwrap();
    assert!(matches!(
        noyau.depot_blob(0, 0, &source_donnees),
        Err(ErreurFeuNoyau::FoyerFerme(i)) if i == 0
    ));

    // Une clé factice suffit : la borne est contrôlée à l'entrée, avant que la
    // clé serve à quoi que ce soit.
    let message = vec![0u8; MAX_TAILLE_SIGNATURE + 1];

    assert!(matches!(
        noyau.signature_noeud(&message),
        Err(ErreurFeuNoyau::TailleMaxDepasseeSignature(_))
    ));

    let message = vec![0u8; MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE + 1];
    let cle = [1u8; 1568];

    assert!(matches!(
        noyau.chiffrement_asymetrique(&cle, &message),
        Err(ErreurFeuNoyau::TailleMaxDepasseeChiffrementAsymetrique(_))
    ));

    drop(noyau);

    // L'arborescence est là, sur le disque : c'est elle qui rend la seed
    // illégitime, et le refus tombe avant même qu'elle soit examinée — deux mots
    // suffisent à le montrer.
    let seed = SecretString::from("mot1 mot2");

    assert!(matches!(
        FeuNoyau::new(&chemin_feu, Some(seed), &mut interface),
        Err(ErreurFeuNoyau::SeedRefuseeNoeudExistant)
    ));

    Ok(())
}

/// Abandonner un [`FeuNoyau`] qui détient un foyer ouvert fait paniquer son
/// `Drop`, plutôt que de laisser un dossier de foyer en clair sur le disque.
///
/// Le message n'est vérifié que par sa première moitié : l'invariant tient à ce
/// que la panique survienne, pas à la formulation qui l'accompagne.
///
/// La panique est laissée au harnais plutôt que rattrapée par `catch_unwind` :
/// le test s'arrête donc ici, ce qu'assume [`fermeture_secours`] en remontant le
/// même état par `forget`, sans passer par le `Drop`.
#[test]
#[should_panic(expected = "Les foyers n'étaient pas tous fermés")]
fn drop_foyer_ouvert() {
    let tmp = TempDir::new().unwrap();

    let chemin_feu = tmp.path().join(".feu");

    let mut interface = InterfaceTest::new("mot de passe");

    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut interface).unwrap();

    noyau.ouverture_foyer(&mut interface, 0).unwrap();
}

/// Un foyer laissé ouvert par une terminaison anormale se referme par
/// [`secours_fermeture_foyer`](FeuNoyau::secours_fermeture_foyer), et la donnée
/// qu'il détenait se relit ensuite à l'identique.
///
/// L'état est monté par `forget`, qui laisse sur le disque ce que laisse une
/// terminaison brutale. Le second volet éprouve le refus : clé retirée du
/// dossier clair, le secours doit renoncer plutôt qu'archiver un foyer amputé.
#[test]
fn fermeture_secours() -> ResultFeuNoyau<()> {
    let tmp = TempDir::new().unwrap();

    let chemin_feu = tmp.path().join(".feu");

    let chemin_donnees = tmp.path().join("fichier.txt");

    let contenu = "contenu de test";

    write(&chemin_donnees, contenu).unwrap();

    let mut interface = InterfaceTest::new("mot de passe");

    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut interface)?;

    noyau.ouverture_foyer(&mut interface, 0)?;
    let source_donnees = File::open(&chemin_donnees).unwrap();
    let (hash_blob, _) = noyau.depot_blob(0, 0, &source_donnees)?;

    forget(noyau);

    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut interface)?;

    assert!(matches!(
        noyau.ouverture_foyer(&mut interface, 0),
        Err(ErreurFeuNoyau::IoError(_))
    ));

    noyau.secours_fermeture_foyer(&mut interface, 0)?;
    noyau.ouverture_foyer(&mut interface, 0)?;

    let fichier_recuperation = File::create(tmp.path().join("temp")).unwrap();

    noyau.lecture_blob(0, &hash_blob, &fichier_recuperation)?;

    let contenu_recupere = read_to_string(tmp.path().join("temp")).unwrap();

    assert_eq!(contenu, contenu_recupere);

    forget(noyau);

    // Le `.cles/` du foyer, à ne pas confondre avec celui du nœud : celui-ci vit
    // dans le dossier clair, et n'importe laquelle de ses neuf clés suffit à
    // faire échouer le diagnostic préalable au secours.
    remove_file(
        chemin_feu
            .join(interface.braises[0].to_string())
            .join(".cles")
            .join("sig.priv"),
    )
    .unwrap();

    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut interface)?;

    assert!(matches!(
        noyau.secours_fermeture_foyer(&mut interface, 0),
        Err(ErreurFeuNoyau::FermetureSecoursFoyerImpossible)
    ));

    Ok(())
}

/// La seed suffit à tout reconstruire : effacé jusqu'au dernier fichier, le nœud
/// renaît d'elle avec les mêmes clés, et une donnée déposée ensuite survit à un
/// démarrage de secours.
///
/// Le déterminisme est prouvé par une signature produite avant l'effacement et
/// vérifiée après — seule la vérification engage la clé privée. Les braises sont
/// contrôlées à part, descendant d'une autre branche de dérivation.
#[test]
fn cycle_demarrage_seed() -> ResultFeuNoyau<()> {
    let tmp = TempDir::new().unwrap();

    let chemin_feu = tmp.path().join(".feu");
    let message = "message à signer";

    let chemin_donnees = tmp.path().join("fichier.txt");
    let contenu = "contenu de test";
    write(&chemin_donnees, contenu).unwrap();

    let mut interface = InterfaceTest::new("mot de passe");

    let noyau = FeuNoyau::new(&chemin_feu, None, &mut interface)?;

    let seed = SecretString::from(interface.seed.join(" "));
    let braises = interface.braises;

    let message_signe = noyau.signature_noeud(message.as_bytes())?;

    // Table rase : sans cet effacement, une seed fournie à `new` serait refusée
    // sur une arborescence existante.
    drop(noyau);
    remove_dir_all(&chemin_feu).unwrap();

    // Renaissance depuis la seed seule.
    let mut interface = InterfaceTest::new("mot de passe");
    let mut noyau = FeuNoyau::new(&chemin_feu, Some(seed.clone()), &mut interface)?;

    assert!(FeuNoyau::verification_signature(
        interface.cle_publique_noeud.unwrap(),
        message_signe,
        message.as_bytes(),
    )?);

    // Une donnée confiée au nœud reconstruit — c'est elle qui devra survivre au
    // secours plus bas.
    noyau.ouverture_foyer(&mut interface, 0)?;

    let source_donnees = File::open(&chemin_donnees).unwrap();
    let (hash_blob, _) = noyau.depot_blob(0, 0, &source_donnees)?;

    noyau.fermeture_foyer(&mut interface, 0)?;

    // Nœud amputé de la clé privée de signature : plus rien ne s'allume.
    remove_file(chemin_feu.join(".cles").join("feu_sig.priv")).unwrap();

    assert!(matches!(
        FeuNoyau::new(&chemin_feu, None, &mut interface),
        Err(ErreurFeuNoyau::IoError(_))
    ));

    // Le secours réécrit le disque : aucune instance ne doit rester en vie.
    drop(noyau);

    let mut interface = InterfaceTest::new("mot de passe");
    FeuNoyau::demarrage_secours(&chemin_feu, seed.clone(), &mut interface)?;

    let mut interface = InterfaceTest::new("mot de passe");
    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut interface)?;

    let braises2 = interface.braises;

    assert_eq!(braises, braises2);

    assert!(FeuNoyau::verification_signature(
        interface.cle_publique_noeud.unwrap(),
        message_signe,
        message.as_bytes(),
    )?);

    noyau.ouverture_foyer(&mut interface, 0)?;

    let fichier_recuperation = File::create(tmp.path().join("temp")).unwrap();

    noyau.lecture_blob(0, &hash_blob, &fichier_recuperation)?;

    let contenu_recupere = read_to_string(tmp.path().join("temp")).unwrap();

    assert_eq!(contenu, contenu_recupere);

    noyau.fermeture_foyer(&mut interface, 0)?;

    Ok(())
}

/// Chaque dégât infligé à l'arborescence remonte l'anomalie qui le nomme, et
/// désigne le fichier en cause.
///
/// Les états sont fabriqués sur le disque, faute de pouvoir les atteindre par le
/// noyau sans panne matérielle. Un seul représentant est pris pour la famille
/// [`Anomalie::ElementAbsent`].
#[test]
fn diagnostic_noeud() -> ResultFeuNoyau<()> {
    let tmp = TempDir::new().unwrap();

    let chemin_feu = tmp.path().join(".feu");

    let mut interface = InterfaceTest::new("mot de passe");
    let noyau = FeuNoyau::new(&chemin_feu, None, &mut interface)?;

    let anomalies = FeuNoyau::diagnostic_noeud(&chemin_feu);

    // 1 — nœud neuf : la référence dont chaque dégât suivant s'écarte.
    assert_eq!(anomalies.len(), 0);

    // 2 — une archive intermédiaire n'a aucune raison d'exister au repos.
    let chemin = chemin_feu.join(format!("{}.tar", interface.braises[0]));
    File::create(&chemin).unwrap();

    let anomalies = FeuNoyau::diagnostic_noeud(&chemin_feu);

    assert_eq!(anomalies.len(), 1);
    assert!(matches!(
        anomalies.first().unwrap(),
        Anomalie::ArchiveIntermediaireResiduelle(m) if m == &chemin
    ));

    remove_file(&chemin).unwrap();

    // 3 — le dossier clair rejoint l'archive : la fermeture s'est arrêtée entre
    // le chiffrement et l'effacement du clair.
    let chemin = chemin_feu.join(format!("{}", interface.braises[0]));
    create_dir(&chemin).unwrap();

    let anomalies = FeuNoyau::diagnostic_noeud(&chemin_feu);

    assert_eq!(anomalies.len(), 1);
    assert!(matches!(
        anomalies.first().unwrap(),
        Anomalie::FoyerClairEtArchive(m) if m == &chemin
    ));

    remove_dir(&chemin).unwrap();

    // 4 — la clé du foyer vit au niveau du nœud, donc reste visible foyer fermé.
    // Elle n'est pas restaurée : l'étape suivante s'accommode de son absence.
    let chemin = chemin_feu
        .join(".cles")
        .join(format!("{}.cle", interface.braises[0]));

    remove_file(&chemin).unwrap();

    let anomalies = FeuNoyau::diagnostic_noeud(&chemin_feu);

    assert_eq!(anomalies.len(), 1);
    assert!(matches!(
        anomalies.first().unwrap(),
        Anomalie::ElementAbsent(c) if c == &chemin
    ));

    // 5 — la config doit rester lisible pour que son parsing échoue ; la
    // supprimer donnerait une absence. Le compte retombe à un parce que la
    // boucle sur les foyers est court-circuitée, masquant l'anomalie de
    // l'étape 4.
    write(
        chemin_feu.join(".config").join("noyau.feu"),
        "n'importe quoi",
    )
    .unwrap();

    let anomalies = FeuNoyau::diagnostic_noeud(&chemin_feu);

    assert_eq!(anomalies.len(), 1);
    assert!(matches!(
        anomalies.first().unwrap(),
        Anomalie::ConfigurationIllisible
    ));

    drop(noyau);

    Ok(())
}
