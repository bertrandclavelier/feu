//! Trousseau cryptographique du cryptographe.
//!
//! Ce module gère le stockage en mémoire de l'ensemble des secrets actifs
//! d'une session Feu : mot de passe, clés de signature et de chiffrement
//! par foyer.
//!
//! Toutes les données sensibles sont zéroïsées à la destruction via le
//! crate `zeroize`. Le cycle de vie des secrets peut aussi être géré
//! manuellement par appel explicite à `.zeroize()`.
//!
//! Ce module est strictement interne au module `cryptographe` —
//! aucune structure n'est accessible depuis l'extérieur.
//!
//! # État initial
//!
//! À l'instanciation, le trousseau est vide : `mdp` et
//! `paire_signature_noeud` sont à `None`, `cles_foyers` est un vecteur
//! vide. Les champs sont peuplés au fil du cycle de vie de la session.
//!
//! # Invariant
//!
//! Un [`TrousseauFoyer`] est toujours complet à l'insertion — toutes ses
//! clés sont générées avant d'être ajoutées au trousseau.
//!
//! # Structure
//!
//! - [`Trousseau`] — conteneur principal de la session active
//! - [`TrousseauFoyer`] — clés opérationnelles d'un foyer ouvert
//! - [`PaireClesSignature`] — paire de clés de signature Ed25519
//! - [`PaireClesChiffrement`] — paire de clés de chiffrement X25519
//! - [`CleSymetrique`] — clé symétrique zéroïsée à la destruction
//! - [`MotDePasse`] — secret textuel zéroïsé

use super::erreur::ResultCryptographe;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use slip10_ed25519::derive_ed25519_private_key;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE: &str = "feu-foyer-symetrique";
const CHAINE_A_SIGNER_POUR_PAIRE_SIGNATURE: &str = "feu-foyer-paire-signature";
const CHAINE_A_SIGNER_POUR_PAIRE_CHIFFREMENT: &str = "feu-foyer-paire-chiffrement";
const CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE_CLASSEUR: &str = "feu-foyer-classeur";

#[derive(Zeroize, ZeroizeOnDrop)]
struct CleSymetrique([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
struct MotDePasse(String);

struct PaireClesSignature {
    privee: SigningKey,
    publique: VerifyingKey,
}

struct PaireClesChiffrement {
    privee: StaticSecret,
    publique: PublicKey,
}

struct TrousseauFoyer {
    cle_chiffrement: CleSymetrique,
    paire_signature: PaireClesSignature,
    paire_chiffrement: PaireClesChiffrement,
    cles_chiffrement_classeurs: Vec<CleSymetrique>,
}

pub(super) struct Trousseau {
    mdp: Option<MotDePasse>,
    paire_signature_noeud: Option<PaireClesSignature>,
    cles_foyers: Vec<TrousseauFoyer>,
}

impl Trousseau {
    /// Crée un trousseau vide.
    pub(super) fn new() -> Self {
        Self {
            mdp: None,
            paire_signature_noeud: None,
            cles_foyers: Vec::new(),
        }
    }

    /// Dérive et enregistre dans le trousseau la paire de clés de signature du nœud.
    ///
    /// Le chemin de dérivation SLIP-0010 utilisé est `m/0'`.
    /// La clé brute intermédiaire est zéroïsée immédiatement après usage.
    pub(super) fn ajouter_paire_noeud(&mut self, seed_bytes: &[u8; 64]) {
        // Dérivation m/0' pour obtenir la clé brute
        let mut cle_brute = derive_ed25519_private_key(seed_bytes, &[0]);

        // Transformation de la clé brute en paire de clés de signature
        let cle_privee = SigningKey::from_bytes(&cle_brute);
        cle_brute.zeroize();
        let cle_publique = cle_privee.verifying_key();

        // Enregistrement de la paire dans le trousseau
        self.paire_signature_noeud = Some(PaireClesSignature {
            privee: cle_privee,
            publique: cle_publique,
        });
    }

    /// Dérive et enregistre dans le trousseau l'ensemble des clés d'un foyer.
    ///
    /// À partir de `seed_bytes` et de `index_foyer`, dérive via SLIP-0010
    /// une clé mère (`m/index_foyer'`), puis en tire par signature + HKDF-SHA256 :
    ///
    /// - une clé symétrique de chiffrement du foyer
    /// - une paire de clés Ed25519 de signature
    /// - une paire de clés X25519 de chiffrement asymétrique
    /// - cinq clés symétriques pour les classeurs (`feu-foyer-classeur1` à `5`)
    ///
    /// Toutes les clés brutes intermédiaires sont zéroïsées après usage.
    pub(super) fn ajouter_trousseau_foyer(
        &mut self,
        seed_bytes: &[u8; 64],
        index_foyer: u32,
    ) -> ResultCryptographe<()> {
        // Dérivation m/index_foyer' pour la clé brute du foyer
        let mut cle_brute = derive_ed25519_private_key(seed_bytes, &[index_foyer]);

        // transformation de la clé brute en clé privée de signature (seule celle-ci est nécessaire pour signer)
        let cle_privee = SigningKey::from_bytes(&cle_brute);
        cle_brute.zeroize();

        //Création de la clé symetrique de foyer
        let cle_chiffrement = CleSymetrique(Trousseau::genere_cle_brute_from_signature(
            &cle_privee,
            CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE,
        )?);

        // Création de la paire de clés signature du foyer
        let mut cle_brute = Trousseau::genere_cle_brute_from_signature(
            &cle_privee,
            CHAINE_A_SIGNER_POUR_PAIRE_SIGNATURE,
        )?;

        let cle_privee_asymetrique = SigningKey::from_bytes(&cle_brute);
        cle_brute.zeroize();
        let cle_publique = cle_privee_asymetrique.verifying_key();

        let paire_signature = PaireClesSignature {
            privee: cle_privee_asymetrique,
            publique: cle_publique,
        };

        // Création de la paire de clés chiffrement du foyer
        let mut cle_brute = Trousseau::genere_cle_brute_from_signature(
            &cle_privee,
            CHAINE_A_SIGNER_POUR_PAIRE_CHIFFREMENT,
        )?;
        let cle_privee_asymetrique = StaticSecret::from(cle_brute);
        cle_brute.zeroize();
        let cle_publique = PublicKey::from(&cle_privee_asymetrique);

        let paire_chiffrement = PaireClesChiffrement {
            privee: cle_privee_asymetrique,
            publique: cle_publique,
        };

        // Création des clés de chiffrement des 5 premiers classeurs
        let mut cles_chiffrement_classeurs: Vec<CleSymetrique> = Vec::new();
        for i in 1..=5 {
            cles_chiffrement_classeurs.push(CleSymetrique(
                Trousseau::genere_cle_brute_from_signature(
                    &cle_privee,
                    &format!(
                        "{}{i}",
                        CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE_CLASSEUR
                    ),
                )?,
            ));
        }

        // enregistrement de toutes ces clés dans un trousseau_foyer
        self.cles_foyers.push(TrousseauFoyer {
            cle_chiffrement,
            paire_signature,
            paire_chiffrement,
            cles_chiffrement_classeurs,
        });
        Ok(())
    }

    /// Dérive 32 octets de matière clé à partir d'une signature Ed25519.
    ///
    /// Signe `label` avec `cle_privee`, soumet la signature à HKDF-SHA256
    /// et retourne les 32 octets résultants. La signature intermédiaire
    /// est zéroïsée immédiatement après l'étape d'extraction.
    fn genere_cle_brute_from_signature(
        cle_privee: &SigningKey,
        texte: &str,
    ) -> ResultCryptographe<[u8; 32]> {
        let mut sig = cle_privee.sign(texte.as_bytes()).to_bytes();
        let hkdf = Hkdf::<Sha256>::new(None, &sig);
        sig.zeroize();
        let mut cle_brute = [0u8; 32];
        hkdf.expand(b"", &mut cle_brute)?;

        Ok(cle_brute)
    }
}
