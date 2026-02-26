//! Trousseau cryptographique du cryptographe.
//!
//! Ce module gère le stockage en mémoire de l'ensemble des secrets actifs
//! d'une session Feu : mot de passe, clés de signature et de chiffrement
//! par foyer.
//!
//! Ce module est strictement interne au module `cryptographe` —
//! aucune structure n'est accessible depuis l'extérieur.
//!
//! # Stratégie de protection des secrets
//!
//! Deux mécanismes complémentaires sont utilisés selon les contraintes de
//! l'écosystème :
//!
//! - [`SecretBox<T>`] (crate `secrecy`) : wrapping explicite des secrets dont
//!   le type implémente [`Zeroize`]. L'accès au contenu est volontairement
//!   contraint à [`expose_secret()`] / [`expose_secret_mut()`], rendant toute
//!   manipulation visible à la lecture du code. La mémoire est zéroïsée à la
//!   destruction.
//!
//! - `ZeroizeOnDrop` (crate `zeroize`) : utilisé pour [`SigningKey`]
//!   (ed25519-dalek), dont le type n'implémente pas [`Zeroize`] et ne peut
//!   donc pas être encapsulé dans [`SecretBox`]. La mémoire est garantie
//!   zéroïsée à la destruction par l'implémentation interne d'ed25519-dalek,
//!   mais `.zeroize()` ne peut pas être appelé manuellement.
//!
//! # Clés brutes intermédiaires
//!
//! Toute clé brute (`[u8; 32]` ou `[u8; 64]`) produite lors de dérivations
//! est encapsulée immédiatement dans [`SecretBox`]. Les blocs de scope `{ }`
//! sont utilisés pour forcer la destruction anticipée dès qu'une clé n'est
//! plus nécessaire.
//!
//! # Évolution envisagée
//!
//! Pour une version production, remplacer [`SecretBox`] par la crate `secrets`
//! qui ajoute le memory locking (`mlock`) — empêche l'OS de paginer les secrets
//! vers le disque (swap). L'interface est proche, la migration serait localisée
//! à ce module.
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
//! - [`PaireClesSignature`] — paire de clés Ed25519 ; `privee` protégée par
//!   `ZeroizeOnDrop` (exception : `SigningKey` n'implémente pas `Zeroize`)
//! - [`PaireClesChiffrement`] — paire de clés X25519 ; `privee` dans
//!   `SecretBox<StaticSecret>`
//! - [`CleSymetrique`] — clé symétrique dans `SecretBox<[u8; 32]>`
//! - [`MotDePasse`] — secret textuel dans `SecretBox<String>`

use super::erreur::ResultCryptographe;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use sha2::Sha256;
use slip10_ed25519::derive_ed25519_private_key;
use x25519_dalek::{PublicKey, StaticSecret};

const CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE: &str = "feu-foyer-symetrique";
const CHAINE_A_SIGNER_POUR_PAIRE_SIGNATURE: &str = "feu-foyer-paire-signature";
const CHAINE_A_SIGNER_POUR_PAIRE_CHIFFREMENT: &str = "feu-foyer-paire-chiffrement";
const CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE_CLASSEUR: &str = "feu-foyer-classeur";

struct CleSymetrique(SecretBox<[u8; 32]>);

struct MotDePasse(SecretBox<String>);

struct PaireClesSignature {
    // SigningKey n'implémente pas Zeroize (contrainte d'ed25519-dalek v2) —
    // SecretBox impossible. La mémoire est zéroïsée à la destruction via
    // ZeroizeOnDrop, garanti par ed25519-dalek avec le feature "zeroize".
    privee: SigningKey,
    publique: VerifyingKey,
}

struct PaireClesChiffrement {
    privee: SecretBox<StaticSecret>,
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
    pub(super) fn ajouter_paire_noeud(&mut self, seed_bytes: &SecretBox<[u8; 64]>) {
        let cle_privee: SigningKey;

        // Bloc encadrant la portée de cle_brute
        {
            // Dérivation m/0' pour obtenir la clé brute
            let cle_brute = SecretBox::new(Box::new(derive_ed25519_private_key(
                seed_bytes.expose_secret(),
                &[0],
            )));

            // Transformation de la clé brute en paire de clés de signature
            cle_privee = SigningKey::from_bytes(cle_brute.expose_secret());
        }

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
        seed_bytes: &SecretBox<[u8; 64]>,
        index_foyer: u32,
    ) -> ResultCryptographe<()> {
        let cle_privee: SigningKey;

        // Bloc encadrant la portée de cle_brute
        {
            // Dérivation m/index_foyer' pour la clé brute du foyer
            let cle_brute = SecretBox::new(Box::new(derive_ed25519_private_key(
                seed_bytes.expose_secret(),
                &[index_foyer],
            )));

            // transformation de la clé brute en clé privée de signature (seule celle-ci est nécessaire pour signer)
            cle_privee = SigningKey::from_bytes(&cle_brute.expose_secret());
        }

        //Création de la clé symetrique de foyer
        let cle_chiffrement = CleSymetrique(Trousseau::genere_cle_brute_from_signature(
            &cle_privee,
            CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE,
        )?);

        let cle_privee_asymetrique: SigningKey;

        // Bloc encadrant la portée de cle_brute
        {
            // Création de la paire de clés signature du foyer
            let cle_brute = Trousseau::genere_cle_brute_from_signature(
                &cle_privee,
                CHAINE_A_SIGNER_POUR_PAIRE_SIGNATURE,
            )?;

            cle_privee_asymetrique = SigningKey::from_bytes(&cle_brute.expose_secret());
        }

        let cle_publique = cle_privee_asymetrique.verifying_key();

        let paire_signature = PaireClesSignature {
            privee: cle_privee_asymetrique,
            publique: cle_publique,
        };

        let cle_privee_asymetrique: SecretBox<StaticSecret>;

        // Bloc encadrant la portée de cle_brute
        {
            // Création de la paire de clés chiffrement du foyer
            let cle_brute = Trousseau::genere_cle_brute_from_signature(
                &cle_privee,
                CHAINE_A_SIGNER_POUR_PAIRE_CHIFFREMENT,
            )?;
            cle_privee_asymetrique =
                SecretBox::new(Box::new(StaticSecret::from(*cle_brute.expose_secret())));
        }

        let cle_publique = PublicKey::from(cle_privee_asymetrique.expose_secret());

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
    ) -> ResultCryptographe<SecretBox<[u8; 32]>> {
        let mut sig = SecretBox::new(Box::new(cle_privee.sign(texte.as_bytes()).to_bytes()));
        let hkdf = Hkdf::<Sha256>::new(None, sig.expose_secret_mut());

        let mut cle_brute = SecretBox::new(Box::new([0u8; 32]));
        hkdf.expand(b"", cle_brute.expose_secret_mut())?;

        Ok(cle_brute)
    }
}
