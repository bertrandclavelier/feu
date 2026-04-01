// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

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
//! `paire_signature_noeud` sont à `None`, `trousseaux_foyers` est un tableau fixe
//! de `None`. Les champs sont peuplés au fil du cycle de vie de la session.
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
//! - `cle_chiffrement` — clé symétrique dans `SecretBox<[u8; 32]>` (pas de newtype)
//! - `mdp` — mot de passe dans `Option<SecretBox<String>>` (pas de newtype)
//! - `sel` — sel Argon2id dans `Option<[u8; 16]>` (pas secret — dérivé de manière déterministe
//!   depuis la clé privée du nœud, re-dérivable depuis la seed en cas de perte du disque)
//! - `cle_ephemere` — clé AES-256-GCM dérivée du mot de passe via Argon2id,
//!   dans `Option<SecretBox<[u8; 32]>>` — présente uniquement le temps du
//!   chiffrement des clés, effacée dès que le trousseau persistable est constitué.

use crate::MAX_CLASSEURS;
use crate::MAX_FOYERS;

use super::erreur::ErreurCryptographe;
use super::erreur::ResultCryptographe;
use super::trousseaux_publics::{
    TrousseauPublicComplet, TrousseauPublicFoyer, TrousseauPublicNoeud,
};

use aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use data_encoding::BASE32;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use sha3::{Digest, Sha3_256};
use slip10_ed25519::derive_ed25519_private_key;
use std::io::{Read, Write};
use x25519_dalek::{PublicKey, StaticSecret};

const CHAINE_A_SIGNER_POUR_SEL: &str = "feu-noeud-sel";
const CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE: &str = "feu-foyer-symetrique";
const CHAINE_A_SIGNER_POUR_PAIRE_SIGNATURE: &str = "feu-foyer-paire-signature";
const CHAINE_A_SIGNER_POUR_PAIRE_CHIFFREMENT: &str = "feu-foyer-paire-chiffrement";
const CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE_CLASSEUR: &str = "feu-foyer-classeur";

const CHUNK_SIZE: usize = 4096;

/// Paire de clés Ed25519 d'un foyer — signature réseau et dérivation de l'adresse `.onion`.
///
/// `privee` est protégée par `ZeroizeOnDrop` (ed25519-dalek, feature `zeroize`) —
/// `SigningKey` n'implémente pas `Zeroize`, `SecretBox` est donc inutilisable.
/// La zéroïsation est garantie à la destruction, mais ne peut pas être déclenchée manuellement.
struct PaireClesSignature {
    // SigningKey n'implémente pas Zeroize (contrainte d'ed25519-dalek v2) —
    // SecretBox impossible. La mémoire est zéroïsée à la destruction via
    // ZeroizeOnDrop, garanti par ed25519-dalek avec le feature "zeroize".
    privee: SigningKey,
    publique: VerifyingKey,
}

/// Paire de clés X25519 d'un foyer — chiffrement réseau asymétrique.
///
/// `privee` est encapsulée dans [`SecretBox`] — zéroïsée automatiquement au `Drop`.
struct PaireClesChiffrement {
    privee: SecretBox<StaticSecret>,
    publique: PublicKey,
}

/// Clés opérationnelles d'un foyer ouvert, maintenues en mémoire pour la durée de la session.
///
/// Contient l'adresse `.onion`, la clé symétrique d'archive, la paire de signature réseau,
/// la paire de chiffrement réseau et les clés des classeurs. Toutes les clés privées et
/// symétriques sont encapsulées dans [`SecretBox`] ou protégées par `ZeroizeOnDrop`.
struct TrousseauFoyer {
    onion: String,
    cle_chiffrement: SecretBox<[u8; 32]>,
    paire_signature: PaireClesSignature,
    paire_chiffrement: PaireClesChiffrement,
    cles_chiffrement_classeurs: [Option<SecretBox<[u8; 32]>>; MAX_CLASSEURS],
}

impl TrousseauFoyer {
    /// Dérive l'adresse `.onion` Tor v3 du foyer depuis sa clé publique de signature.
    ///
    /// Implémente le standard Tor v3 (rend-spec-v3) :
    ///
    /// ```text
    /// CHECKSUM = SHA3-256(b".onion checksum" || PUBKEY || [0x03])[..2]
    /// ADRESSE  = BASE32(PUBKEY || CHECKSUM || [0x03]).to_lowercase() + ".onion"
    /// ```
    ///
    /// # Étapes
    ///
    /// 1. **Buffer checksum (48 octets)** — concatène le préfixe Tor fixe
    ///    `b".onion checksum"` (15 octets), la clé publique Ed25519 (32 octets)
    ///    et l'octet de version `0x03` (1 octet).
    ///
    /// 2. **Checksum (2 octets)** — SHA3-256 du buffer ; seuls les 2 premiers
    ///    octets sont conservés. Ce checksum permet de détecter les fautes de
    ///    frappe dans l'adresse.
    ///
    /// 3. **Buffer final (35 octets)** — concatène la clé publique (32 octets),
    ///    le checksum (2 octets) et l'octet de version `0x03` (1 octet).
    ///
    /// 4. **Encodage** — BASE32 du buffer final, mis en minuscules, suivi
    ///    du suffixe `.onion`. Produit une adresse de 62 caractères
    ///    (56 caractères base32 + 6 pour `.onion`).
    ///
    /// SHA3-256 est utilisé ici en cohérence avec le reste du protocole Feu,
    /// qui retient SHA3-256 comme unique primitive de hashage.
    fn derive_adresse_onion(cle: VerifyingKey) -> String {
        // 1. Buffer checksum (48 octets)
        let mut buf = Vec::new();
        buf.extend_from_slice(b".onion checksum");
        buf.extend_from_slice(cle.as_bytes());
        buf.push(0x03);

        // 2. Checksum (2 octets)
        let hash = Sha3_256::digest(&buf);
        let checksum = &hash[..2];

        // 3. Buffer final (35 octets)
        let mut data = Vec::new();
        data.extend_from_slice(cle.as_bytes());
        data.extend_from_slice(checksum);
        data.push(0x03);

        // 4. Encodage
        format!("{}.onion", BASE32.encode(&data).to_lowercase())
    }

    /// Retourne une référence à la clé symétrique de chiffrement du foyer.
    fn donne_cle_chiffrement(&self) -> &SecretBox<[u8; 32]> {
        &self.cle_chiffrement
    }

    /// Retourne une référence à la clé privée X25519 de chiffrement du foyer.
    fn donne_cle_privee_chiffrement(&self) -> &SecretBox<StaticSecret> {
        &self.paire_chiffrement.privee
    }

    fn donne_cle_privee_signature(&self) -> &SigningKey {
        &self.paire_signature.privee
    }
}

/// Conteneur principal des secrets cryptographiques d'une session active.
///
/// Maintient en mémoire : le mot de passe, la clé éphémère, le sel Argon2id,
/// la paire de signature du nœud, et les trousseaux des foyers ouverts.
/// Toutes les clés privées et symétriques sont encapsulées dans [`SecretBox`]
/// ou protégées par `ZeroizeOnDrop`.
pub(super) struct Trousseau {
    mdp: Option<SecretBox<String>>,
    cle_ephemere: Option<SecretBox<[u8; 32]>>,
    sel: Option<[u8; 16]>,
    paire_signature_noeud: Option<PaireClesSignature>,
    trousseaux_foyers: [Option<TrousseauFoyer>; MAX_FOYERS],
}

//
// Construction
//
impl Trousseau {
    /// Crée un trousseau vide.
    pub(super) fn new() -> Self {
        Self {
            mdp: None,
            cle_ephemere: None,
            sel: None,
            paire_signature_noeud: None,
            trousseaux_foyers: std::array::from_fn(|_| None),
        }
    }

    /// Retourne la clé de chiffrement AES-256-GCM du classeur `index_classeur` du foyer `index_foyer`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer ou le classeur est absent du trousseau.
    fn donne_cle_chiffrement_classeur(
        &self,
        index_foyer: usize,
        index_classeur: usize,
    ) -> ResultCryptographe<&SecretBox<[u8; 32]>> {
        let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer] else {
            return Err(ErreurCryptographe::Interne(String::from(
                "Pas trousseau foyer",
            )));
        };

        let Some(cle_classeur) = &trousseau_foyer.cles_chiffrement_classeurs[index_classeur] else {
            return Err(ErreurCryptographe::Interne(String::from(
                "Pas de clé du classeur",
            )));
        };
        Ok(cle_classeur)
    }

    /// Retourne la clé privée X25519 du foyer à la position `index_foyer`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer est absent du trousseau.
    fn donne_cle_privee_chiffrement_foyer(
        &self,
        index_foyer: usize,
    ) -> ResultCryptographe<&SecretBox<StaticSecret>> {
        let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer] else {
            return Err(ErreurCryptographe::Interne(String::from(
                "Pas trousseau foyer",
            )));
        };

        Ok(trousseau_foyer.donne_cle_privee_chiffrement())
    }

    fn donne_cle_privee_signature_foyer(
        &self,
        index_foyer: usize,
    ) -> ResultCryptographe<&SigningKey> {
        let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer] else {
            return Err(ErreurCryptographe::Interne(String::from(
                "Pas trousseau foyer",
            )));
        };

        Ok(trousseau_foyer.donne_cle_privee_signature())
    }

    fn donne_cle_privee_signature_noeud(&self) -> ResultCryptographe<&SigningKey> {
        let Some(paire_signature_noeud) = &self.paire_signature_noeud else {
            return Err(ErreurCryptographe::Interne(String::from(
                "Pas de clés signature nœud",
            )));
        };

        Ok(&paire_signature_noeud.privee)
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
    /// À partir de `seed_bytes` et de `position`, dérive via SLIP-0010
    /// une clé mère (`m/(position+1)'`), puis en tire par signature + HKDF-SHA3-256 :
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
        position: usize,
    ) -> ResultCryptographe<()> {
        // L'index de dérivation est position + 1
        let index_foyer = (position + 1) as u32;

        let cle_privee: SigningKey;

        // Bloc encadrant la portée de cle_brute
        {
            // Dérivation m/index_foyer' pour la clé brute du foyer
            let cle_brute = SecretBox::new(Box::new(derive_ed25519_private_key(
                seed_bytes.expose_secret(),
                &[index_foyer],
            )));

            // Clé mère du foyer — sert à dériver toutes les sous-clés du foyer
            cle_privee = SigningKey::from_bytes(cle_brute.expose_secret());
        }

        // Clé symétrique de chiffrement du foyer
        let cle_chiffrement = Trousseau::genere_cle_brute_from_signature(
            &cle_privee,
            CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE,
        )?;

        let cle_sign_priv: SigningKey;

        // Bloc encadrant la portée de cle_brute
        {
            // Création de la paire de clés signature du foyer
            let cle_brute = Trousseau::genere_cle_brute_from_signature(
                &cle_privee,
                CHAINE_A_SIGNER_POUR_PAIRE_SIGNATURE,
            )?;

            cle_sign_priv = SigningKey::from_bytes(cle_brute.expose_secret());
        }

        let cle_sig_pub = cle_sign_priv.verifying_key();

        let paire_signature = PaireClesSignature {
            privee: cle_sign_priv,
            publique: cle_sig_pub,
        };

        let cle_chiff_priv: SecretBox<StaticSecret>;

        // Bloc encadrant la portée de cle_brute
        {
            // Création de la paire de clés chiffrement du foyer
            let cle_brute = Trousseau::genere_cle_brute_from_signature(
                &cle_privee,
                CHAINE_A_SIGNER_POUR_PAIRE_CHIFFREMENT,
            )?;
            cle_chiff_priv =
                SecretBox::new(Box::new(StaticSecret::from(*cle_brute.expose_secret())));
        }

        let cle_chiff_pub = PublicKey::from(cle_chiff_priv.expose_secret());

        let paire_chiffrement = PaireClesChiffrement {
            privee: cle_chiff_priv,
            publique: cle_chiff_pub,
        };

        // Création des clés de chiffrement des 5 premiers classeurs
        let mut cles_chiffrement_classeurs: [Option<SecretBox<[u8; 32]>>; MAX_CLASSEURS] =
            std::array::from_fn(|_| None);
        for (i, e) in cles_chiffrement_classeurs.iter_mut().enumerate() {
            *e = Some(Trousseau::genere_cle_brute_from_signature(
                &cle_privee,
                &format!(
                    "{}{}",
                    CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE_CLASSEUR,
                    i + 1,
                ),
            )?);
        }

        // enregistrement de toutes les clés dans un TrousseauFoyer
        let trousseau_foyer = TrousseauFoyer {
            onion: TrousseauFoyer::derive_adresse_onion(paire_signature.publique),
            cle_chiffrement,
            paire_signature,
            paire_chiffrement,
            cles_chiffrement_classeurs,
        };

        // Ajout du TrousseauFoyer dans le trousseau
        if position >= MAX_FOYERS {
            return Err(ErreurCryptographe::Interne(String::from(
                "Problème index tableau.",
            )));
        }
        self.trousseaux_foyers[position] = Some(trousseau_foyer);

        Ok(())
    }

    /// Dérive le sel Argon2id depuis la clé privée du nœud et l'enregistre dans le trousseau.
    ///
    /// Signe [`CHAINE_A_SIGNER_POUR_SEL`] avec la clé privée du nœud — signature
    /// déterministe Ed25519 (RFC 8032) — et retient les 16 premiers octets de la
    /// signature (64 octets). Le sel n'est pas secret et sera stocké en clair sur
    /// le disque aux côtés des clés chiffrées.
    ///
    /// Cette dérivation déterministe garantit que le sel est toujours reconstituable
    /// depuis la seed, même en cas de perte des données disque.
    ///
    /// # Prérequis
    ///
    /// La paire de signature du nœud doit être présente dans le trousseau.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la paire de signature du nœud est absente.
    pub(super) fn genere_sel(&mut self) -> ResultCryptographe<()> {
        match &self.paire_signature_noeud {
            Some(valeur) => {
                let sig = valeur
                    .privee
                    .sign(CHAINE_A_SIGNER_POUR_SEL.as_bytes())
                    .to_bytes();

                let mut sel = [0u8; 16];
                sel.copy_from_slice(&sig[..16]);
                self.sel = Some(sel);
                Ok(())
            }
            None => Err(ErreurCryptographe::Interne(String::from(
                "Problème de génération du sel.",
            ))),
        }
    }

    /// Dérive 32 octets de matière clé à partir d'une signature Ed25519.
    ///
    /// Signe `texte` avec `cle_privee`, soumet la signature à HKDF-SHA3-256
    /// et retourne les 32 octets résultants. La signature intermédiaire
    /// est zéroïsée immédiatement après l'étape d'extraction.
    fn genere_cle_brute_from_signature(
        cle_privee: &SigningKey,
        texte: &str,
    ) -> ResultCryptographe<SecretBox<[u8; 32]>> {
        let mut sig = SecretBox::new(Box::new(cle_privee.sign(texte.as_bytes()).to_bytes()));
        let hkdf = Hkdf::<Sha3_256>::new(None, sig.expose_secret_mut());

        let mut cle_brute = SecretBox::new(Box::new([0u8; 32]));
        hkdf.expand(b"", cle_brute.expose_secret_mut())?;

        Ok(cle_brute)
    }

    fn signature_generique_ed25519(cle_privee: &SigningKey, octets_a_signer: &[u8]) -> [u8; 64] {
        cle_privee.sign(octets_a_signer).to_bytes()
    }

    pub(super) fn signe_avec_cle_noeud(
        &self,
        octets_a_signer: &[u8],
    ) -> ResultCryptographe<[u8; 64]> {
        Ok(Self::signature_generique_ed25519(
            self.donne_cle_privee_signature_noeud()?,
            octets_a_signer,
        ))
    }

    pub(super) fn signe_avec_cle_foyer(
        &self,
        index_foyer: usize,
        octets_a_signer: &[u8],
    ) -> ResultCryptographe<[u8; 64]> {
        Ok(Self::signature_generique_ed25519(
            self.donne_cle_privee_signature_foyer(index_foyer)?,
            octets_a_signer,
        ))
    }
}

//
// Gestion des secrets éphémères
//
impl Trousseau {
    /// Définit le mot de passe du trousseau.
    ///
    /// `mot` est un [`SecretBox<String>`] déjà construit par l'appelant —
    /// la méthode se contente de le stocker. Tout mot de passe précédemment
    /// défini est remplacé et zéroïsé au drop.
    pub(super) fn definit_mdp(&mut self, mot: SecretBox<String>) {
        self.mdp = Some(mot);
    }

    /// Efface le mot de passe du trousseau.
    ///
    /// Met `mdp` à `None` — la destruction du [`SecretBox<String>`] déclenche
    /// la zéroïsation automatique de la mémoire.
    pub(super) fn efface_mdp(&mut self) {
        self.mdp = None;
    }

    /// Définit le sel Argon2id du trousseau.
    ///
    /// Doit être appelé avant [`derive_cle_ephemere`](Self::derive_cle_ephemere)
    /// qui en a besoin pour dériver la clé éphémère.
    pub(super) fn definit_sel(&mut self, sel: [u8; 16]) {
        self.sel = Some(sel);
    }

    /// Dérive la clé éphémère AES-256-GCM depuis le mot de passe et le sel du trousseau.
    ///
    /// Utilise Argon2id (RFC 9106) avec les paramètres par défaut de la crate
    /// `argon2` (conformes aux recommandations minimales de la RFC 9106) :
    /// mémoire = 19 456 Kio (19 MiB), itérations = 2, parallélisme = 1.
    /// Ces paramètres sont intentionnellement conservateurs pour v0.0.1 —
    /// ils seront réévalués dans une version ultérieure.
    /// Produit 32 octets de matière clé à partir du mot de passe et du sel. La clé
    /// résultante est encapsulée dans [`SecretBox`] et stockée dans `cle_ephemere`.
    ///
    /// Cette clé sert uniquement à chiffrer les clés privées via [`chiffre_cle`] —
    /// elle doit être effacée dès que le trousseau persistable est constitué.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le mot de passe ou le sel est absent du trousseau,
    /// ou si la dérivation Argon2id échoue.
    pub(super) fn derive_cle_ephemere(&mut self) -> ResultCryptographe<()> {
        let argon2 = Argon2::default();

        let mut buffer = SecretBox::new(Box::new([0u8; 32]));

        match (&self.mdp, self.sel) {
            (Some(valeur1), Some(valeur2)) => {
                argon2.hash_password_into(
                    valeur1.expose_secret().as_bytes(),
                    &valeur2,
                    buffer.expose_secret_mut(),
                )?;
                self.cle_ephemere = Some(buffer);
                Ok(())
            }
            (_, _) => Err(ErreurCryptographe::Interne(String::from(
                "Pas de mot de passe",
            ))),
        }
    }

    /// Efface la clé éphémère du trousseau.
    ///
    /// Met `cle_ephemere` à `None` — la destruction du [`SecretBox<[u8; 32]>`] déclenche
    /// la zéroïsation automatique de la mémoire.
    pub(super) fn efface_cle_ephemere(&mut self) {
        self.cle_ephemere = None;
    }
}

//
// Chiffrement / déchiffrement des clés
//
impl Trousseau {
    /// Chiffre une clé privée ou symétrique de 32 octets avec AES-256-GCM.
    ///
    /// Utilise la clé éphémère du trousseau comme clé AES-256-GCM. Un nonce
    /// aléatoire de 12 octets est généré via [`OsRng`] à chaque appel —
    /// il garantit l'unicité du chiffrement sans être secret.
    ///
    /// Le cipher [`Aes256Gcm`] zéroïse son planning de clé interne à la
    /// destruction grâce à la feature `zeroize` de la crate `aes-gcm` —
    /// aucune copie de la clé éphémère ne subsiste après l'appel.
    ///
    /// Le résultat de 60 octets est structuré comme suit :
    /// ```text
    /// [0..12]  nonce (12 octets)
    /// [12..60] ciphertext + auth tag (32 + 16 octets)
    /// ```
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé éphémère est absente du trousseau
    /// ou si le chiffrement AES-256-GCM échoue.
    pub(super) fn chiffre_cle(&self, cle: &[u8; 32]) -> ResultCryptographe<[u8; 60]> {
        match &self.cle_ephemere {
            None => Err(ErreurCryptographe::Interne(String::from(
                "Problème de chiffrement des clés.",
            ))),
            Some(valeur) => Ok(
                Self::chiffrement_generique_avec_cle(valeur.expose_secret(), cle)?
                    .try_into()
                    .map_err(|_| ErreurCryptographe::Interne(String::from("Erreur chiffrement")))?,
            ),
        }
    }

    /// Chiffre un blob avec la clé AES-256-GCM du classeur désigné.
    ///
    /// Récupère la clé de chiffrement du classeur `index_classeur` du foyer
    /// `index_foyer` depuis le trousseau, puis délègue à
    /// [`chiffrement_generique_avec_cle`](Self::chiffrement_generique_avec_cle).
    ///
    /// Le résultat est structuré comme suit :
    /// ```text
    /// [0..12]   nonce (12 octets)
    /// [12..]    ciphertext + auth tag
    /// ```
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer ou le classeur est absent du trousseau,
    /// ou si le chiffrement AES-256-GCM échoue.
    pub(super) fn chiffre_blob(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        blob: &[u8],
    ) -> ResultCryptographe<Vec<u8>> {
        Self::chiffrement_generique_avec_cle(
            self.donne_cle_chiffrement_classeur(index_foyer, index_classeur)?
                .expose_secret(),
            blob,
        )
    }

    /// Déchiffre une clé de 60 octets (`nonce || ciphertext || tag`) avec AES-256-GCM.
    ///
    /// Extrait le nonce des 12 premiers octets, déchiffre les 48 octets restants
    /// (`ciphertext` de 32 octets + `auth tag` de 16 octets) et retourne les
    /// 32 octets en clair. Si le mot de passe est incorrect, la vérification
    /// de l'auth tag AES-GCM échoue — c'est le mécanisme de vérification du mot de passe.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé éphémère est absente, si l'auth tag est invalide
    /// (mot de passe incorrect), ou si la conversion du résultat en `[u8; 32]` échoue.
    pub(super) fn dechiffre_cle(&self, cle: &[u8; 60]) -> ResultCryptographe<SecretBox<[u8; 32]>> {
        match &self.cle_ephemere {
            None => Err(ErreurCryptographe::Interne(String::from(
                "Problème de chiffrement des clés.",
            ))),
            Some(valeur) => {
                let resultat = Self::dechiffrement_generique_avec_cle(valeur.expose_secret(), cle)?
                    .try_into()
                    .map_err(|_| {
                        ErreurCryptographe::Interne(String::from("Erreur déchiffrement"))
                    })?;
                Ok(SecretBox::new(Box::new(resultat)))
            }
        }
    }

    /// Déchiffre un blob chiffré avec la clé AES-256-GCM du classeur désigné.
    ///
    /// Récupère la clé du classeur `index_classeur` du foyer `index_foyer`
    /// depuis le trousseau, puis délègue à
    /// [`dechiffrement_generique_avec_cle`](Self::dechiffrement_generique_avec_cle).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer ou le classeur est absent du trousseau,
    /// ou si le déchiffrement AES-256-GCM échoue.
    pub(super) fn dechiffre_blob(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        blob: &[u8],
    ) -> ResultCryptographe<Vec<u8>> {
        Self::dechiffrement_generique_avec_cle(
            self.donne_cle_chiffrement_classeur(index_foyer, index_classeur)?
                .expose_secret(),
            blob,
        )
    }
}

//
// Export — génération du trousseau public
//
impl TrousseauFoyer {
    /// Crée un [`TrousseauFoyer`] avec les clés principales du foyer.
    ///
    /// Les slots de classeurs sont initialisés à `None` — ils sont peuplés
    /// après construction via [`ajoute_cle_classeur`](Self::ajoute_cle_classeur).
    fn new(
        onion: String,
        cle_chiffrement: SecretBox<[u8; 32]>,
        paire_signature: PaireClesSignature,
        paire_chiffrement: PaireClesChiffrement,
    ) -> Self {
        Self {
            onion,
            cle_chiffrement,
            paire_signature,
            paire_chiffrement,
            cles_chiffrement_classeurs: std::array::from_fn(|_| None),
        }
    }

    /// Insère la clé de chiffrement d'un classeur à l'`index` donné.
    ///
    /// Appelée après [`new`](Self::new) pour peupler les slots de classeurs
    /// un par un. L'accès est direct — l'appelant garantit que `index < MAX_CLASSEURS`.
    fn ajoute_cle_classeur(&mut self, cle_classeur: SecretBox<[u8; 32]>, index: usize) {
        self.cles_chiffrement_classeurs[index] = Some(cle_classeur);
    }

    /// Chiffre toutes les clés du foyer et produit le [`TrousseauPublicFoyer`] persistable.
    ///
    /// Délègue le chiffrement AES-256-GCM de chaque clé à [`Trousseau::chiffre_cle`].
    /// Les clés publiques sont copiées en clair.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le chiffrement d'une clé échoue — clé éphémère
    /// absente du trousseau ou échec AES-256-GCM.
    fn genere_trousseau_public_foyer(
        &self,
        trousseau: &Trousseau,
    ) -> ResultCryptographe<TrousseauPublicFoyer> {
        let mut trousseau_public_foyer = TrousseauPublicFoyer::new(
            self.onion.clone(),
            trousseau.chiffre_cle(self.cle_chiffrement.expose_secret())?,
            trousseau.chiffre_cle(self.paire_signature.privee.as_bytes())?,
            self.paire_signature.publique.to_bytes(),
            trousseau.chiffre_cle(self.paire_chiffrement.privee.expose_secret().as_bytes())?,
            self.paire_chiffrement.publique.to_bytes(),
        );

        for i in 0..MAX_CLASSEURS {
            if let Some(cle) = &self.cles_chiffrement_classeurs[i] {
                trousseau_public_foyer.ajoute_cle_chiffrement_classeur(
                    trousseau.chiffre_cle(cle.expose_secret())?,
                    i,
                )?;
            } else {
                return Err(ErreurCryptographe::Interne(String::from(
                    "Erreur génération du trousseau foyer public",
                )));
            }
        }

        Ok(trousseau_public_foyer)
    }
}

impl Trousseau {
    /// Chiffre l'ensemble des secrets du trousseau et produit le [`TrousseauPublicComplet`] persistable.
    ///
    /// Construit d'abord un [`TrousseauPublicNoeud`] avec les clés du nœud, puis délègue
    /// le chiffrement de chaque foyer à [`TrousseauFoyer::genere_trousseau_public_foyer`].
    /// Le sel est inclus en clair — il est re-dérivable depuis la seed en cas de perte du disque.
    ///
    /// # Prérequis
    ///
    /// La clé éphémère doit être présente dans le trousseau. Elle est produite par
    /// [`derive_cle_ephemere`](Self::derive_cle_ephemere) et doit être effacée
    /// par l'appelant après usage.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le sel ou la paire de signature du nœud est absente,
    /// ou si le chiffrement d'une clé échoue.
    pub(super) fn genere_trousseau_public_complet(
        &self,
    ) -> ResultCryptographe<TrousseauPublicComplet> {
        match (self.sel, &self.paire_signature_noeud) {
            (Some(valeur1), Some(valeur2)) => {
                let trousseau_public_noeud = TrousseauPublicNoeud::new(
                    valeur1,
                    self.chiffre_cle(valeur2.privee.as_bytes())?,
                    *valeur2.publique.as_bytes(),
                );

                let mut trousseau_public_complet =
                    TrousseauPublicComplet::new(trousseau_public_noeud);
                for i in 0..MAX_FOYERS {
                    if let Some(trousseau_foyer) = &self.trousseaux_foyers[i] {
                        trousseau_public_complet.ajoute_trousseau_foyer_public(
                            trousseau_foyer.genere_trousseau_public_foyer(self)?,
                            i,
                        )?;
                    }
                }

                Ok(trousseau_public_complet)
            }
            (_, _) => Err(ErreurCryptographe::Interne(String::from(
                "Problème génération du trousseau public.",
            ))),
        }
    }
}

//
// Import — chargement depuis le trousseau public
//
impl Trousseau {
    /// Reconstruit la paire de signature du nœud à partir d'un [`TrousseauPublicNoeud`].
    ///
    /// Déchiffre la clé privée de signature du nœud et reconstitue la paire Ed25519
    /// en mémoire. Le déchiffrement échoue si le mot de passe est incorrect —
    /// c'est le mécanisme de vérification du mot de passe dans Feu.
    ///
    /// Les clés des foyers ne sont pas chargées ici — chaque foyer est
    /// déchiffré séparément via [`trousseau_public_foyer_vers_trousseau_foyer`](Self::trousseau_public_foyer_vers_trousseau_foyer).
    ///
    /// # Prérequis
    ///
    /// Le sel et la clé éphémère doivent être présents dans le trousseau —
    /// chargés respectivement par [`definit_sel`](Self::definit_sel) et
    /// [`derive_cle_ephemere`](Self::derive_cle_ephemere).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le déchiffrement échoue ou si la clé publique
    /// ne peut pas être reconstruite depuis les octets lus.
    pub(super) fn trousseau_public_noeud_vers_trousseau(
        &mut self,
        trousseau_public_noeud: &TrousseauPublicNoeud,
    ) -> ResultCryptographe<()> {
        let cle_dechiffree = self.dechiffre_cle(&trousseau_public_noeud.donne_cle_sig_privee())?;
        let cle_pub = trousseau_public_noeud.donne_cle_sig_pub();

        self.paire_signature_noeud = Some(PaireClesSignature {
            privee: SigningKey::from_bytes(cle_dechiffree.expose_secret()),
            publique: VerifyingKey::from_bytes(&cle_pub).map_err(|_| {
                ErreurCryptographe::Interne(String::from("Erreur récupération de clé."))
            })?,
        });
        Ok(())
    }

    /// Déchiffre et charge les clés d'un foyer dans le trousseau à partir d'un [`TrousseauPublicFoyer`].
    ///
    /// Déchiffre la clé symétrique, la paire de signature Ed25519, la paire de chiffrement X25519
    /// et les cinq clés de classeurs avec la clé éphémère, puis enregistre le [`TrousseauFoyer`]
    /// résultant à l'`index` donné. L'adresse `.onion` est lue depuis le [`TrousseauPublicFoyer`].
    ///
    /// # Prérequis
    ///
    /// La clé éphémère doit être présente dans le trousseau —
    /// dérivée préalablement via [`derive_cle_ephemere`](Self::derive_cle_ephemere).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé éphémère est absente, si le déchiffrement d'une clé
    /// échoue, ou si la reconstruction d'une clé publique depuis ses octets échoue.
    pub(super) fn trousseau_public_foyer_vers_trousseau_foyer(
        &mut self,
        trousseau_public_foyer: &TrousseauPublicFoyer,
        index: usize,
    ) -> ResultCryptographe<()> {
        let cle_chiffrement =
            self.dechiffre_cle(&trousseau_public_foyer.donne_cle_chiffrement())?;

        let cle_sig_priv = self.dechiffre_cle(&trousseau_public_foyer.donne_cle_sig_privee())?;
        let cle_sig_pub = trousseau_public_foyer.donne_cle_sig_pub();

        let paire_signature = PaireClesSignature {
            privee: SigningKey::from_bytes(cle_sig_priv.expose_secret()),
            publique: VerifyingKey::from_bytes(&cle_sig_pub).map_err(|_| {
                ErreurCryptographe::Interne(String::from("Erreur récupération de clé."))
            })?,
        };

        let cle_chiff_priv =
            self.dechiffre_cle(&trousseau_public_foyer.donne_cle_chiff_privee())?;
        let cle_chiff_pub = trousseau_public_foyer.donne_cle_chiff_pub();

        let paire_chiffrement = PaireClesChiffrement {
            privee: SecretBox::new(Box::new(StaticSecret::from(
                *cle_chiff_priv.expose_secret(),
            ))),
            publique: PublicKey::from(cle_chiff_pub),
        };

        let mut trousseau_foyer = TrousseauFoyer::new(
            String::from(trousseau_public_foyer.donne_onion()),
            cle_chiffrement,
            paire_signature,
            paire_chiffrement,
        );

        for j in 0..MAX_CLASSEURS {
            let cle_classeur =
                self.dechiffre_cle(trousseau_public_foyer.donne_cle_chiffrement_classeur(j)?)?;
            trousseau_foyer.ajoute_cle_classeur(cle_classeur, j);
        }
        self.trousseaux_foyers[index] = Some(trousseau_foyer);

        Ok(())
    }

    /// Chiffre un flux de données du foyer à la position `index`.
    ///
    /// Récupère la clé symétrique du foyer dans le trousseau et délègue
    /// le chiffrement à [`chiffre_avec_cle`](Self::chiffre_avec_cle).
    ///
    /// # Prérequis
    ///
    /// Le foyer à l'`index` donné doit être présent dans le trousseau —
    /// c'est-à-dire que le foyer doit être ouvert.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si aucun foyer n'est chargé à cet index,
    /// ou si le chiffrement AES-GCM-stream échoue.
    pub(super) fn chiffre_avec_cle_foyer(
        &self,
        index: usize,
        source: &mut impl Read,
        destination: &mut impl Write,
    ) -> ResultCryptographe<()> {
        if let Some(trousseau_foyer) = &self.trousseaux_foyers[index] {
            self.chiffre_avec_cle(
                trousseau_foyer.donne_cle_chiffrement().expose_secret(),
                source,
                destination,
            )?;
            return Ok(());
        }
        Err(ErreurCryptographe::Interne(String::from(
            "Pas de trousseau pour cet index",
        )))
    }

    /// Déchiffre un flux de données d'un foyer à partir de sa clé symétrique chiffrée.
    ///
    /// `cle_chiffree` est la clé symétrique du foyer telle que lue sur disque
    /// (`nonce || ciphertext || tag`, 60 octets). Elle est déchiffrée avec la
    /// clé éphémère du trousseau, puis utilisée pour déchiffrer le flux
    /// AES-256-GCM-stream depuis `source` vers `destination`.
    ///
    /// # Prérequis
    ///
    /// La clé éphémère doit être présente dans le trousseau —
    /// dérivée via [`derive_cle_ephemere`](Self::derive_cle_ephemere).
    /// Cette méthode est conçue pour l'ouverture d'un foyer : le foyer
    /// n'a pas besoin d'être dans le trousseau.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé éphémère est absente, si le déchiffrement
    /// de `cle_chiffree` échoue (auth tag invalide — mot de passe incorrect),
    /// ou si le déchiffrement du flux AES-GCM-stream échoue.
    pub(super) fn dechiffre_avec_cle_foyer(
        &self,
        cle_chiffree: &[u8; 60],
        source: &mut impl Read,
        destination: &mut impl Write,
    ) -> ResultCryptographe<()> {
        self.dechiffre_avec_cle(
            self.dechiffre_cle(cle_chiffree)?.expose_secret(),
            source,
            destination,
        )?;
        Ok(())
    }
}

//
// Chiffrement de flux
//
impl Trousseau {
    /// Chiffre un flux d'octets avec AES-256-GCM-stream.
    ///
    /// Génère un nonce aléatoire de 7 octets (écrit en tête de `destination`),
    /// puis traite `source` par chunks de [`CHUNK_SIZE`] octets via un look-ahead
    /// à deux buffers : quand le second `read` retourne 0, le premier buffer est
    /// le dernier chunk — `encrypt_last` est appelé, terminant le stream sans
    /// sentinel vide.
    ///
    /// # Format du flux chiffré
    ///
    /// ```text
    /// [0..7]  nonce (7 octets)
    /// [7..]   chunks chiffrés : n octets plaintext → n + 16 octets ciphertext
    ///         (16 octets = auth tag AES-GCM par chunk)
    /// ```
    ///
    /// # Dettes techniques
    ///
    /// - **Copie pile** : `buffer1 = buffer2` copie `CHUNK_SIZE` octets sur la pile
    ///   à chaque itération, y compris les octets non valides au-delà de `n2`.
    ///
    /// - **Short-read** : `read()` peut légalement retourner `n < CHUNK_SIZE` pour
    ///   un chunk non-final. Le chunk chiffré aura la taille `n + 16` au lieu de
    ///   `CHUNK_SIZE + 16`, et le déchiffreur devra lire exactement `n + 16` octets
    ///   pour ce chunk — ce qui dépend du comportement du lecteur sous-jacent.
    ///   Pour les fichiers réguliers sur disque, ce cas ne se produit pas en pratique.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si une opération d'entrée/sortie échoue ou si le
    /// chiffrement AES-GCM-stream échoue.
    fn chiffre_avec_cle(
        &self,
        cle_chiffrement: &[u8; 32],
        source: &mut impl Read,
        destination: &mut impl Write,
    ) -> ResultCryptographe<()> {
        // Génération du nonce aléatoire
        let mut nonce = [0u8; 7];
        OsRng.fill_bytes(&mut nonce);

        // Création du StreamEncryptor
        let key = Key::<Aes256Gcm>::from_slice(cle_chiffrement);
        let cipher = Aes256Gcm::new(key);
        let mut encryptor = EncryptorBE32::from_aead(cipher, nonce.as_slice().into());

        // Écriture du nonce en tête du fichier
        destination.write_all(&nonce)?;

        let mut buffer1 = [0u8; CHUNK_SIZE];
        let mut buffer2 = [0u8; CHUNK_SIZE];

        let mut n1 = source.read(&mut buffer1)?;
        loop {
            let n2 = source.read(&mut buffer2)?;
            if n2 == 0 {
                // buffer1 dernier chunk de taille n1
                let last_chunk = encryptor.encrypt_last(&buffer1[..n1])?;
                destination.write_all(&last_chunk)?;
                break;
            }
            let chunk = encryptor.encrypt_next(&buffer1[..n1])?;
            destination.write_all(&chunk)?;
            buffer1 = buffer2;
            n1 = n2;
        }

        Ok(())
    }

    /// Déchiffre un flux AES-256-GCM-stream produit par [`chiffre_avec_cle`](Self::chiffre_avec_cle).
    ///
    /// Lit le nonce de 7 octets en tête via `read_exact`, puis traite les chunks
    /// chiffrés via un look-ahead à deux buffers symétrique à `chiffre_avec_cle` :
    /// `decrypt_last` est déclenché quand le second `read` retourne 0.
    ///
    /// Chaque buffer de déchiffrement est dimensionné à `CHUNK_SIZE + 16` octets
    /// (plaintext + auth tag AES-GCM).
    ///
    /// # Dettes techniques
    ///
    /// Mêmes dettes que [`chiffre_avec_cle`](Self::chiffre_avec_cle) —
    /// copie pile et short-read symétrique.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la lecture du nonce échoue, si une opération
    /// d'entrée/sortie échoue, ou si la vérification de l'auth tag AES-GCM échoue
    /// (données corrompues ou clé incorrecte).
    fn dechiffre_avec_cle(
        &self,
        cle_chiffrement: &[u8; 32],
        source: &mut impl Read,
        destination: &mut impl Write,
    ) -> ResultCryptographe<()> {
        // Récupération du nonce
        let mut nonce = [0u8; 7];
        source.read_exact(&mut nonce)?;

        // Création du StreamDecryptor
        let key = Key::<Aes256Gcm>::from_slice(cle_chiffrement);
        let cipher = Aes256Gcm::new(key);
        let mut decryptor = DecryptorBE32::from_aead(cipher, nonce.as_slice().into());

        let mut buffer1 = [0u8; CHUNK_SIZE + 16];
        let mut buffer2 = [0u8; CHUNK_SIZE + 16];

        let mut n1 = source.read(&mut buffer1)?;
        loop {
            let n2 = source.read(&mut buffer2)?;
            if n2 == 0 {
                // buffer1 dernier chunk de taille n1
                let last_chunk = decryptor.decrypt_last(&buffer1[..n1])?;
                destination.write_all(&last_chunk)?;
                break;
            }
            let chunk = decryptor.decrypt_next(&buffer1[..n1])?;
            destination.write_all(&chunk)?;
            buffer1 = buffer2;
            n1 = n2;
        }

        Ok(())
    }

    /// Chiffre `contenu` avec AES-256-GCM et une clé fournie directement.
    ///
    /// Utilisé pour les cas où la clé est dérivée à l'extérieur du trousseau
    /// (ECIES, chiffrement de blobs). Pour les clés du trousseau, préférer
    /// [`chiffre_cle`](Self::chiffre_cle) ou [`chiffre_blob`](Self::chiffre_blob).
    ///
    /// Un nonce aléatoire de 12 octets est généré via [`OsRng`] à chaque appel.
    ///
    /// # Format de sortie
    ///
    /// ```text
    /// [0..12]  nonce (12 octets)
    /// [12..]   ciphertext + auth tag (16 octets)
    /// ```
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le chiffrement AES-256-GCM échoue.
    pub(super) fn chiffrement_generique_avec_cle(
        cle_chiffrement: &[u8; 32],
        contenu: &[u8],
    ) -> ResultCryptographe<Vec<u8>> {
        // Conversion de la clé de chiffrement brute en Key<Aes256Gcm>
        let key = Key::<Aes256Gcm>::from_slice(cle_chiffrement);

        // Création du cipher à partir de key
        let cipher = Aes256Gcm::new(key);

        // Génération aléatoire du nonce de 12 octets
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        // Chiffrement du contenu
        let contenu_chiffre = cipher.encrypt(Nonce::from_slice(&nonce), contenu.as_ref())?;

        // Création du résultat
        let mut resultat = Vec::new();
        resultat.extend_from_slice(&nonce);
        resultat.extend_from_slice(&contenu_chiffre);

        Ok(resultat)
    }

    /// Déchiffre `contenu` avec AES-256-GCM et une clé fournie directement.
    ///
    /// Attendu au format `nonce (12 octets) || ciphertext || auth tag (16 octets)`.
    /// Réciproque de [`chiffrement_generique_avec_cle`](Self::chiffrement_generique_avec_cle).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la vérification de l'auth tag AES-GCM échoue
    /// (clé incorrecte ou données corrompues).
    pub(super) fn dechiffrement_generique_avec_cle(
        cle_chiffrement: &[u8; 32],
        contenu: &[u8],
    ) -> ResultCryptographe<Vec<u8>> {
        // Conversion de la clé éphémère brute en Key<Aes256Gcm>
        let key = Key::<Aes256Gcm>::from_slice(cle_chiffrement);

        // Création du cipher à partir de key
        let cipher = Aes256Gcm::new(key);

        // Déchiffrement de la clé
        let contenu_dechiffre =
            cipher.decrypt(Nonce::from_slice(&contenu[0..12]), &contenu[12..])?;

        Ok(contenu_dechiffre)
    }

    /// Calcule le secret partagé X25519 entre la clé privée du foyer et la clé éphémère publique.
    ///
    /// Effectue le ECDH : `secret_partagé = clé_privée_foyer × clé_éphémère_publique`.
    /// Le secret est extrait dans un [`SecretBox<[u8; 32]>`] immédiatement —
    /// le [`SharedSecret`] sort de scope sans persistance.
    ///
    /// Utilisé dans le schéma ECIES pour le déchiffrement asymétrique.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer à `index_foyer` est absent du trousseau.
    pub(super) fn recuperation_secret_partage(
        &self,
        index_foyer: usize,
        cle_ephemere_publique: &[u8; 32],
    ) -> ResultCryptographe<SecretBox<[u8; 32]>> {
        let cle_publique = PublicKey::from(*cle_ephemere_publique);

        let secret_partage = SecretBox::new(Box::new(
            *self
                .donne_cle_privee_chiffrement_foyer(index_foyer)?
                .expose_secret()
                .diffie_hellman(&cle_publique)
                .as_bytes(),
        ));

        Ok(secret_partage)
    }
}
