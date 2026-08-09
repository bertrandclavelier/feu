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
//! Deux cycles, chacun repartant d'un nœud neuf. [`cycle_vie_noyau`] suit
//! l'allumage, le dépôt et la relecture après rallumage ;
//! [`cycle_mot_de_passe`] éprouve le rechiffrement du trousseau et le rejet de
//! l'ancien mot de passe.
//!
//! Les assertions portent sur ce que le noyau **rend observable**, jamais sur
//! son état interne : les rappels à l'interface — [`InterfaceTest`] les
//! enregistre pour les rendre lisibles depuis le test —, les valeurs et erreurs
//! de retour, et les fichiers laissés sur le disque, dont les chemins se
//! déduisent de la seule braise.

use std::fs::{File, read_to_string, write};

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

    // Un refus ferait échouer la création du nœud sur `ERR_CRY_004`, avant même
    // que le moindre foyer existe.
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

/// Un blob déposé dans chacun des trois foyers se relit à l'identique après que
/// le noyau a été détruit puis reconstruit, braises et clé publique de nœud
/// retrouvées à partir du seul mot de passe.
///
/// Établit au passage l'unicité d'un blob dans un foyer : redéposé dans un autre
/// classeur, il n'est pas dupliqué et le dépôt rend celui qui le détient déjà.
#[test]
fn cycle_vie_noyau() -> ResultFeuNoyau<()> {
    let tmp = TempDir::new().unwrap();

    let chemin_feu = tmp.path().join(".feu");

    let chemin_donnees = tmp.path().join("fichier.txt");
    let contenu = "Contenu de test à mettre dans un foyer.";
    write(&chemin_donnees, contenu).unwrap();
    let mut hash_donnees = String::new();

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
        (hash_donnees, _) = noyau.depot_donnees(i, 0, &source_donnees)?;

        // Même contenu, autre classeur demandé : le blob ne doit pas être
        // dupliqué, et le dépôt rendre le classeur 0 où il réside déjà. Le hash
        // identique le confirme — il ne dépend que du clair, jamais de la clé du
        // classeur sous laquelle il vient d'être chiffré.
        let source_donnees = File::open(&chemin_donnees).unwrap();
        let (hash_donnees2, index) = noyau.depot_donnees(i, 1, &source_donnees)?;

        assert_eq!(index, 0);
        assert_eq!(hash_donnees, hash_donnees2);

        noyau.fermeture_foyer(&mut interface, i)?;

        assert!(!interface.etats[i]);
    }

    // Extinction explicite : le second noyau doit tout retrouver du disque et du
    // mot de passe, sans rien hériter du premier resté vivant.
    drop(noyau);

    let mut interface2 = InterfaceTest::new("mot de passe");
    let mut noyau2 = FeuNoyau::new(&chemin_feu, None, &mut interface2)?;

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

        noyau2.lecture_donnees(i, &hash_donnees, &fichier_recuperation)?;

        let contenu_recupere = read_to_string(tmp.path().join("temp")).unwrap();

        assert_eq!(contenu, contenu_recupere);

        noyau2.fermeture_foyer(&mut interface2, i)?;

        assert!(!interface2.etats[i]);
    }
    Ok(())
}

/// Après un changement de mot de passe, l'ancien n'ouvre plus rien et le nouveau
/// ouvre tout — aux deux points où le mot de passe est saisi.
///
/// Le mot de passe est demandé deux fois dans la vie d'un foyer : à l'allumage
/// du nœud, pour déverrouiller les clés, puis à chaque
/// [`ouverture_foyer`](FeuNoyau::ouverture_foyer), pour déchiffrer l'archive.
/// Les deux dérivent leur clé éphémère du même Argon2id, mais empruntent des
/// chemins distincts : le test éprouve les deux plutôt que d'inférer l'un de
/// l'autre.
///
/// Établit en outre qu'une ouverture refusée ne coûte rien : l'arborescence
/// reste celle d'un foyer fermé, et le bon mot de passe rouvre ensuite
/// normalement.
#[test]
fn cycle_mot_de_passe() -> ResultFeuNoyau<()> {
    let tmp = TempDir::new().unwrap();

    let chemin_feu = tmp.path().join(".feu");

    let mut interface = InterfaceTest::new("mot de passe");

    let mut noyau = FeuNoyau::new(&chemin_feu, None, &mut interface)?;

    // `changement_mdp` exige les trois foyers ouverts — leurs clés doivent être
    // en mémoire pour être rechiffrées, sinon `TousFoyersNonOuverts`.
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
        Err(ErreurFeuNoyau::Cryptographe(_))
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
        Err(ErreurFeuNoyau::Cryptographe(_))
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
