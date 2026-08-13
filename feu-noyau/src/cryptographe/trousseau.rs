// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

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
//!   (ml-dsa) et [`DecapsulationKey1024`] (ml-kem), dont les types
//!   n'implémentent pas [`Zeroize`] et ne peuvent donc pas être encapsulés
//!   dans [`SecretBox`]. La mémoire est garantie zéroïsée à la destruction par
//!   l'implémentation interne de la crate, mais `.zeroize()` ne peut pas être
//!   appelé manuellement.
//!
//! # Clés brutes intermédiaires
//!
//! Toute clé brute (`[u8; 32]` ou `[u8; 64]`) produite lors de dérivations
//! est encapsulée immédiatement dans [`SecretBox`]. Les blocs de scope `{ }`
//! sont utilisés pour forcer la destruction anticipée dès qu'une clé n'est
//! plus nécessaire.
//!
//! # État initial
//!
//! À l'instanciation, le trousseau est vide : `mdp`, `cle_ephemere`, `sel` et
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
//! - [`PaireClesSignature`] — paire de clés ML-DSA-87 ; `privee` protégée par
//!   `ZeroizeOnDrop` (exception : `SigningKey` n'implémente pas `Zeroize`)
//! - [`PaireClesChiffrement`] — paire de clés ML-KEM-1024 ; `privee` protégée par
//!   `ZeroizeOnDrop` (exception : `DecapsulationKey` n'implémente pas `Zeroize`)
//! - `cle_chiffrement` — clé symétrique dans `SecretBox<[u8; 32]>` (pas de newtype)
//! - `mdp` — mot de passe dans `Option<SecretString>`, alias de
//!   `SecretBox<str>` dans `secrecy` (pas de newtype)
//! - `sel` — sel Argon2id dans `Option<[u8; 16]>` (pas secret — dérivé de manière déterministe
//!   depuis la seed par HKDF, re-dérivable en cas de perte du disque)
//! - `cle_ephemere` — clé AES-256-GCM dérivée du mot de passe via Argon2id,
//!   dans `Option<SecretBox<[u8; 32]>>` — présente uniquement le temps du
//!   chiffrement des clés, effacée dès que le trousseau persistable est constitué.

use crate::Braise;
use crate::ErreurFeuNoyau;
use crate::MAX_CLASSEURS;
use crate::MAX_FOYERS;
use crate::ResultFeuNoyau;

use super::trousseaux_publics::{
    TrousseauPublicComplet, TrousseauPublicFoyer, TrousseauPublicNoeud,
};

use aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use data_encoding::BASE32_NOPAD;
use hkdf::Hkdf;
use ml_dsa::{Keypair, MlDsa87, Signer, SigningKey, VerifyingKey};
use ml_kem::Decapsulate;
use ml_kem::ml_kem_1024::Ciphertext as Ciphertext1024;
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024, KeyExport, Seed};
use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::SecretString;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use sha3::{Digest, Sha3_256};
use std::io::{Read, Write};

// ── Labels de dérivation HKDF ────────────────────────────────────────────────
//
// AVERTISSEMENT — élément primordial du protocole Feu, à ne JAMAIS modifier.
//
// Ces labels sont le seul mécanisme de séparation de domaine de la dérivation
// (passés en `info` de HKDF, voir `derive_depuis_seed`). Ils font partie du
// format persistant : changer, renommer ou réordonner la valeur d'un seul label
// re-dérive la clé correspondante et rend TOUS les trousseaux existants
// définitivement illisibles. Toute évolution impose une migration explicite des
// données — jamais une simple édition.
//
// Leur unicité garantit l'absence de collision entre clés ; elle se vérifie à
// l'œil, d'où des chaînes lisibles plutôt qu'opaques.
const LABEL_DERIVATION_SEL: &str = "feu/noeud/sel";
const LABEL_DERIVATION_SIGNATURE_NOEUD: &str = "feu/noeud/signature";
const LABEL_DERIVATION_SIGNATURE_FOYER: &str = "feu/foyer/signature";
const LABEL_DERIVATION_CHIFFREMENT_SYMETRIQUE_FOYER: &str = "feu/foyer/symetrique";
const LABEL_DERIVATION_CHIFFREMENT_FOYER: &str = "feu/foyer/chiffrement";
const LABEL_DERIVATION_BRAISE_FOYER: &str = "feu/foyer/braise";
const LABEL_DERIVATION_CHIFFREMENT_SYMETRIQUE_CLASSEUR: &str = "feu/classeur/symetrique";

// ── Constantes d'implémentation ──────────────────────────────────────────────

const CHUNK_SIZE: usize = 4096;

/// Paire de clés ML-DSA-87 de signature d'un foyer.
///
/// `privee` est protégée par `ZeroizeOnDrop` (ml-dsa, feature `zeroize`) —
/// `SigningKey` n'implémente pas `Zeroize`, `SecretBox` est donc inutilisable.
/// La zéroïsation est garantie à la destruction, mais ne peut pas être déclenchée manuellement.
struct PaireClesSignature {
    // SigningKey n'implémente pas Zeroize (contrainte de ml-dsa) —
    // SecretBox impossible. La mémoire est zéroïsée à la destruction via
    // ZeroizeOnDrop, garanti par ml-dsa avec le feature "zeroize".
    privee: SigningKey<MlDsa87>,
    publique: VerifyingKey<MlDsa87>,
}

/// Paire de clés ML-KEM-1024 d'un foyer — chiffrement réseau asymétrique post-quantique.
///
/// `privee` est protégée par `ZeroizeOnDrop` (ml-kem, feature `zeroize`) —
/// `DecapsulationKey` n'implémente pas `Zeroize`, `SecretBox` est donc inutilisable.
/// La zéroïsation est garantie à la destruction, mais ne peut pas être déclenchée manuellement.
struct PaireClesChiffrement {
    // DecapsulationKey n'implémente que ZeroizeOnDrop (ml-kem feature "zeroize") —
    // SecretBox impossible, comme pour SigningKey. La clé privée ML-KEM-1024 est
    // stockée sous forme de seed 64 o (sérialisation recommandée par la crate).
    privee: DecapsulationKey1024,
    publique: EncapsulationKey1024,
}

/// Clés opérationnelles d'un foyer ouvert, maintenues en mémoire pour la durée de la session.
///
/// Contient l'adresse `.braise`, la clé symétrique d'archive, la paire
/// de signature, la paire de chiffrement réseau et les clés des classeurs. Toutes les
/// clés privées et symétriques sont encapsulées dans [`SecretBox`] ou protégées par `ZeroizeOnDrop`.
struct TrousseauFoyer {
    braise: Braise,
    cle_chiffrement: SecretBox<[u8; 32]>,
    paire_signature: PaireClesSignature,
    paire_chiffrement: PaireClesChiffrement,
    cles_chiffrement_classeurs: [Option<SecretBox<[u8; 32]>>; MAX_CLASSEURS],
}

impl TrousseauFoyer {
    /// Crée un [`TrousseauFoyer`] avec les clés principales du foyer.
    ///
    /// Les slots de classeurs sont initialisés à `None` — ils sont peuplés
    /// après construction via [`ajoute_cle_classeur`](Self::ajoute_cle_classeur).
    fn new(
        braise: Braise,
        cle_chiffrement: SecretBox<[u8; 32]>,
        paire_signature: PaireClesSignature,
        paire_chiffrement: PaireClesChiffrement,
    ) -> Self {
        Self {
            braise,
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
    /// Délègue le chiffrement AES-256-GCM de chaque clé à [`Trousseau::chiffre_cle`]
    /// (clés de 32 octets) ou [`Trousseau::chiffre_seed`] (seed ML-KEM-1024 de 64 octets).
    /// Les clés publiques sont copiées en clair.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le chiffrement d'une clé échoue — clé éphémère
    /// absente du trousseau ou échec AES-256-GCM.
    fn genere_trousseau_public_foyer(
        &self,
        trousseau: &Trousseau,
    ) -> ResultFeuNoyau<TrousseauPublicFoyer> {
        let mut trousseau_public_foyer = TrousseauPublicFoyer::new(
            self.braise,
            trousseau.chiffre_cle(self.cle_chiffrement.expose_secret())?,
            trousseau.chiffre_cle(&self.paire_signature.privee.to_seed().into())?,
            self.paire_signature.publique.encode().into(),
            trousseau.chiffre_seed(
                self.paire_chiffrement
                    .privee
                    .to_seed()
                    .ok_or(ErreurFeuNoyau::CryptographeSeedMlKemIntrouvable)?
                    .as_ref(),
            )?,
            self.paire_chiffrement.publique.to_bytes().into(),
        );

        for i in 0..MAX_CLASSEURS {
            if let Some(cle) = &self.cles_chiffrement_classeurs[i] {
                trousseau_public_foyer.ajoute_cle_chiffrement_classeur(
                    trousseau.chiffre_cle(cle.expose_secret())?,
                    i,
                )?;
            } else {
                return Err(ErreurFeuNoyau::CryptographeCleChiffrementClasseurAbstente(
                    i,
                ));
            }
        }

        Ok(trousseau_public_foyer)
    }

    /// Retourne une référence à la clé symétrique de chiffrement du foyer.
    fn donne_cle_chiffrement(&self) -> &SecretBox<[u8; 32]> {
        &self.cle_chiffrement
    }

    /// Retourne une référence à la clé privée ML-KEM-1024 de chiffrement du foyer.
    fn donne_cle_privee_chiffrement(&self) -> &DecapsulationKey1024 {
        &self.paire_chiffrement.privee
    }

    /// Retourne une référence à la clé privée ML-DSA-87 de signature du foyer.
    fn donne_cle_privee_signature(&self) -> &SigningKey<MlDsa87> {
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
    mdp: Option<SecretString>,
    cle_ephemere: Option<SecretBox<[u8; 32]>>,
    sel: Option<[u8; 16]>,
    paire_signature_noeud: Option<PaireClesSignature>,
    trousseaux_foyers: [Option<TrousseauFoyer>; MAX_FOYERS],
}

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

    /// Indique si un mot de passe est actuellement présent dans le trousseau.
    ///
    /// Utilisé par [`Cryptographe::genere_trousseau_a_partir_seed`] pour déterminer
    /// si la collecte du mot de passe doit être déclenchée ou non.
    pub(super) fn mdp_existe(&self) -> bool {
        self.mdp.is_some()
    }

    // ── Initialisation ───────────────────────────────────────────────────────

    /// Dérive et enregistre dans le trousseau la paire de clés de signature du nœud.
    ///
    /// La clé privée ML-DSA-87 est dérivée de la seed par HKDF-SHA3-256, en
    /// passant le label `feu/noeud/signature` comme `info` — ce qui sépare son
    /// domaine de dérivation de celui des clés de foyer.
    /// La clé brute intermédiaire est portée par un `SecretBox`, zéroïsé en fin
    /// d'instruction.
    pub(super) fn ajouter_paire_noeud(
        &mut self,
        seed_bytes: &SecretBox<[u8; 64]>,
    ) -> ResultFeuNoyau<()> {
        let cle_privee = SigningKey::<MlDsa87>::from_seed(
            Self::derive_depuis_seed::<32>(seed_bytes, LABEL_DERIVATION_SIGNATURE_NOEUD)?
                .expose_secret()
                .into(),
        );

        let cle_publique = cle_privee.verifying_key();

        // Enregistrement de la paire dans le trousseau
        self.paire_signature_noeud = Some(PaireClesSignature {
            privee: cle_privee,
            publique: cle_publique,
        });

        Ok(())
    }

    /// Dérive et enregistre dans le trousseau l'ensemble du matériau d'un foyer.
    ///
    /// À partir de `seed_bytes` et de `position`, dérive par HKDF-SHA3-256 le
    /// matériau du foyer. Chaque élément est tiré d'un `info` distinct, combinant
    /// un label dédié et l'index du foyer (`position + 1`) — ce qui sépare le
    /// domaine de dérivation de chaque élément et de chaque foyer :
    ///
    /// - la braise, identifiant public du foyer — pas une clé (`feu/foyer/braise`)
    /// - une clé symétrique de chiffrement du foyer (`feu/foyer/symetrique`)
    /// - une paire de clés ML-DSA-87 de signature (`feu/foyer/signature`)
    /// - une paire de clés ML-KEM-1024 de chiffrement asymétrique (`feu/foyer/chiffrement`)
    /// - cinq clés symétriques de classeur (`feu/classeur/symetrique`, suffixée de l'index du classeur)
    ///
    /// Toutes les clés brutes intermédiaires sont portées par des `SecretBox` et
    /// zéroïsées dès qu'elles ne sont plus nécessaires.
    pub(super) fn ajouter_trousseau_foyer(
        &mut self,
        seed_bytes: &SecretBox<[u8; 64]>,
        position: usize,
    ) -> ResultFeuNoyau<()> {
        // L'index de dérivation est position + 1
        let index_foyer = (position + 1) as u32;

        // Paire de clés signature du foyer
        let cle_sig_priv = SigningKey::<MlDsa87>::from_seed(
            Self::derive_depuis_seed::<32>(
                seed_bytes,
                &format!("{}/{}", LABEL_DERIVATION_SIGNATURE_FOYER, index_foyer),
            )?
            .expose_secret()
            .into(),
        );

        let cle_sig_pub = cle_sig_priv.verifying_key();

        let paire_signature = PaireClesSignature {
            privee: cle_sig_priv,
            publique: cle_sig_pub,
        };

        // Clé symétrique de chiffrement du foyer
        let cle_chiffrement = Self::derive_depuis_seed::<32>(
            seed_bytes,
            &format!(
                "{}/{}",
                LABEL_DERIVATION_CHIFFREMENT_SYMETRIQUE_FOYER, index_foyer
            ),
        )?;

        // Paire de clés chiffrement foyer
        let cle_chiff_priv = {
            let seed_brute = Self::derive_depuis_seed::<64>(
                seed_bytes,
                &format!("{}/{}", LABEL_DERIVATION_CHIFFREMENT_FOYER, index_foyer),
            )?;
            DecapsulationKey1024::from_seed(Seed::from(*seed_brute.expose_secret()))
        };

        let cle_chiff_pub = cle_chiff_priv.encapsulation_key().clone();

        let paire_chiffrement = PaireClesChiffrement {
            privee: cle_chiff_priv,
            publique: cle_chiff_pub,
        };

        // Création des clés de chiffrement des 5 premiers classeurs
        let mut cles_chiffrement_classeurs: [Option<SecretBox<[u8; 32]>>; MAX_CLASSEURS] =
            std::array::from_fn(|_| None);
        for (i, e) in cles_chiffrement_classeurs.iter_mut().enumerate() {
            *e = Some(Self::derive_depuis_seed::<32>(
                seed_bytes,
                &format!(
                    "{}/{}/{}",
                    LABEL_DERIVATION_CHIFFREMENT_SYMETRIQUE_CLASSEUR,
                    index_foyer,
                    i + 1
                ),
            )?);
        }

        // Braise : identifiant public du foyer, 32 octets dérivés directement de la
        // seed via un label dédié — donc indépendants de toute clé. Contrairement à
        // l'onion qu'elle remplace, elle ne dépend d'aucun schéma cryptographique et
        // reste stable à travers les migrations (p. ex. la montée ML-KEM-768 → 1024
        // en v0.0.4 ne change aucune braise).
        let braise_brute = Self::derive_depuis_seed::<32>(
            seed_bytes,
            &format!("{}/{}", LABEL_DERIVATION_BRAISE_FOYER, index_foyer),
        )?;

        // Checksum de 2 octets accolé à la braise : repère une faute de frappe à la
        // relecture de l'adresse. Le préfixe de domaine empêche ce checksum d'être
        // valide hors de ce contexte (séparation de domaine).
        let mut buf = Vec::new();
        buf.extend_from_slice(b"feu/braise/checksum");
        buf.extend_from_slice(braise_brute.expose_secret());
        let checksum = &Sha3_256::digest(&buf)[..2];

        let mut data = braise_brute.expose_secret().to_vec();
        data.extend_from_slice(checksum);

        // BASE32_NOPAD : alphabet `a-z2-7` sans padding `=`, l'adresse est donc
        // utilisable telle quelle comme nom de dossier (34 octets → 55 caractères).
        let braise = format!("{}{}", BASE32_NOPAD.encode(&data).to_lowercase(), ".braise");
        let braise = Braise::try_from(braise.as_str())?;

        // enregistrement de toutes les clés dans un TrousseauFoyer
        let trousseau_foyer = TrousseauFoyer {
            braise,
            cle_chiffrement,
            paire_signature,
            paire_chiffrement,
            cles_chiffrement_classeurs,
        };

        // Ajout du TrousseauFoyer dans le trousseau
        if position >= MAX_FOYERS {
            return Err(ErreurFeuNoyau::IndexFoyerInvalide(position));
        }
        self.trousseaux_foyers[position] = Some(trousseau_foyer);

        Ok(())
    }

    /// Dérive le sel Argon2id depuis la seed et l'enregistre dans le trousseau.
    ///
    /// Tire 16 octets par HKDF-SHA3-256 avec le label `feu/noeud/sel` — la même
    /// primitive que toutes les autres clés du trousseau. Le sel n'est pas secret
    /// et sera stocké en clair sur le disque aux côtés des clés chiffrées.
    ///
    /// La dérivation est déterministe : le sel est toujours reconstituable depuis
    /// la seed, même en cas de perte des données disque.
    ///
    /// # Pourquoi depuis la seed et non par signature
    ///
    /// Une variante antérieure dérivait le sel en signant une chaîne fixe avec la
    /// clé du nœud. Tirer le sel directement de la seed supprime trois fragilités :
    /// aucune dépendance à la présence préalable de la clé du nœud, aucune
    /// réutilisation de la clé de signature pour un usage étranger, et surtout
    /// aucune dépendance au déterminisme de la primitive de signature — la
    /// migration vers ML-DSA (v0.0.4, signature déterministe en place, mode
    /// *hedged* possible demain) ne risque donc pas de rendre le sel non
    /// reproductible.
    pub(super) fn genere_sel(&mut self, seed_bytes: &SecretBox<[u8; 64]>) -> ResultFeuNoyau<()> {
        self.sel = Some(
            *Self::derive_depuis_seed::<16>(seed_bytes, LABEL_DERIVATION_SEL)?.expose_secret(),
        );

        Ok(())
    }

    // ── Mot de passe et clé éphémère ─────────────────────────────────────────

    /// Définit le mot de passe du trousseau.
    ///
    /// `mot` est un [`SecretString`] déjà construit par l'appelant —
    /// la méthode se contente de le stocker. Tout mot de passe précédemment
    /// défini est remplacé et zéroïsé au drop.
    pub(super) fn definit_mdp(&mut self, mot: SecretString) {
        self.mdp = Some(mot);
    }

    /// Efface le mot de passe du trousseau.
    ///
    /// Met `mdp` à `None` — la destruction du [`SecretString`] déclenche
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
    pub(super) fn derive_cle_ephemere(&mut self) -> ResultFeuNoyau<()> {
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
            (None, _) => Err(ErreurFeuNoyau::CryptographeMotDePasseAbsent),
            (_, None) => Err(ErreurFeuNoyau::CryptographeSelAbsent),
        }
    }

    /// Efface la clé éphémère du trousseau.
    ///
    /// Met `cle_ephemere` à `None` — la destruction du [`SecretBox<[u8; 32]>`] déclenche
    /// la zéroïsation automatique de la mémoire.
    pub(super) fn efface_cle_ephemere(&mut self) {
        self.cle_ephemere = None;
    }

    // ── Signature ────────────────────────────────────────────────────────────

    /// Signe des octets avec la clé privée ML-DSA-87 du nœud.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé de signature du nœud est absente du trousseau.
    pub(super) fn signe_avec_cle_noeud(
        &self,
        octets_a_signer: &[u8],
    ) -> ResultFeuNoyau<[u8; 4627]> {
        Ok(Self::signe_octets(
            self.donne_cle_privee_signature_noeud()?,
            octets_a_signer,
        ))
    }

    /// Signe des octets avec la clé privée ML-DSA-87 du foyer à la position `index_foyer`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer est absent du trousseau.
    pub(super) fn signe_avec_cle_foyer(
        &self,
        index_foyer: usize,
        octets_a_signer: &[u8],
    ) -> ResultFeuNoyau<[u8; 4627]> {
        Ok(Self::signe_octets(
            self.donne_cle_privee_signature_foyer(index_foyer)?,
            octets_a_signer,
        ))
    }

    // ── Chiffrement ──────────────────────────────────────────────────────────

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
    pub(super) fn chiffre_cle(&self, cle: &[u8; 32]) -> ResultFeuNoyau<[u8; 60]> {
        match &self.cle_ephemere {
            None => Err(ErreurFeuNoyau::CryptographeCleEphemereAbsente),
            Some(valeur) => Ok(
                Self::chiffrement_generique_avec_cle(valeur.expose_secret(), cle)?
                    .try_into()
                    .map_err(|_| ErreurFeuNoyau::CryptographeTailleSortieInattendue)?,
            ),
        }
    }

    /// Chiffre une seed ML-KEM-1024 de 64 octets avec AES-256-GCM.
    ///
    /// Variante de [`chiffre_cle`](Self::chiffre_cle) pour la clé privée de
    /// chiffrement, sérialisée sous forme de seed 64 octets — `chiffre_cle` est
    /// verrouillée sur 32 octets. Le mécanisme est identique : clé éphémère du
    /// trousseau, nonce aléatoire de 12 octets via [`OsRng`] à chaque appel.
    ///
    /// Le résultat de 92 octets est structuré comme suit :
    /// ```text
    /// [0..12]  nonce (12 octets)
    /// [12..92] ciphertext + auth tag (64 + 16 octets)
    /// ```
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé éphémère est absente du trousseau
    /// ou si le chiffrement AES-256-GCM échoue.
    pub(super) fn chiffre_seed(&self, cle: &[u8; 64]) -> ResultFeuNoyau<[u8; 92]> {
        match &self.cle_ephemere {
            None => Err(ErreurFeuNoyau::CryptographeCleEphemereAbsente),
            Some(valeur) => Ok(
                Self::chiffrement_generique_avec_cle(valeur.expose_secret(), cle)?
                    .try_into()
                    .map_err(|_| ErreurFeuNoyau::CryptographeTailleSortieInattendue)?,
            ),
        }
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
    pub(super) fn dechiffre_cle(&self, cle: &[u8; 60]) -> ResultFeuNoyau<SecretBox<[u8; 32]>> {
        match &self.cle_ephemere {
            None => Err(ErreurFeuNoyau::CryptographeCleEphemereAbsente),
            Some(valeur) => {
                let resultat = Self::dechiffrement_generique_avec_cle(valeur.expose_secret(), cle)?
                    .try_into()
                    .map_err(|_| ErreurFeuNoyau::CryptographeTailleSortieInattendue)?;
                Ok(SecretBox::new(Box::new(resultat)))
            }
        }
    }

    /// Déchiffre une seed ML-KEM-1024 de 92 octets (`nonce || ciphertext || tag`) avec AES-256-GCM.
    ///
    /// Réciproque de [`chiffre_seed`](Self::chiffre_seed) — variante 64 octets de
    /// [`dechiffre_cle`](Self::dechiffre_cle). Extrait le nonce des 12 premiers
    /// octets, déchiffre les 80 octets restants (`ciphertext` de 64 octets +
    /// `auth tag` de 16 octets) et retourne les 64 octets en clair dans un
    /// [`SecretBox`]. Un auth tag invalide signale un mot de passe incorrect.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé éphémère est absente, si l'auth tag est invalide
    /// (mot de passe incorrect), ou si la conversion du résultat en `[u8; 64]` échoue.
    pub(super) fn dechiffre_seed(&self, cle: &[u8; 92]) -> ResultFeuNoyau<SecretBox<[u8; 64]>> {
        match &self.cle_ephemere {
            None => Err(ErreurFeuNoyau::CryptographeCleEphemereAbsente),
            Some(valeur) => {
                let resultat = Self::dechiffrement_generique_avec_cle(valeur.expose_secret(), cle)?
                    .try_into()
                    .map_err(|_| ErreurFeuNoyau::CryptographeTailleSortieInattendue)?;
                Ok(SecretBox::new(Box::new(resultat)))
            }
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
    ) -> ResultFeuNoyau<Vec<u8>> {
        Self::chiffrement_generique_avec_cle(
            self.donne_cle_chiffrement_classeur(index_foyer, index_classeur)?
                .expose_secret(),
            blob,
        )
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
    ) -> ResultFeuNoyau<Vec<u8>> {
        Self::dechiffrement_generique_avec_cle(
            self.donne_cle_chiffrement_classeur(index_foyer, index_classeur)?
                .expose_secret(),
            blob,
        )
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
        index_foyer: usize,
        source: &mut impl Read,
        destination: &mut impl Write,
    ) -> ResultFeuNoyau<()> {
        if let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer] {
            self.chiffre_avec_cle(
                trousseau_foyer.donne_cle_chiffrement().expose_secret(),
                source,
                destination,
            )?;
            return Ok(());
        }
        Err(ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent(
            index_foyer,
        ))
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
    ) -> ResultFeuNoyau<()> {
        self.dechiffre_avec_cle(
            self.dechiffre_cle(cle_chiffree)?.expose_secret(),
            source,
            destination,
        )?;
        Ok(())
    }

    /// Chiffre `contenu` avec AES-256-GCM et une clé fournie directement.
    ///
    /// Utilisé pour les cas où la clé est dérivée à l'extérieur du trousseau
    /// (chiffrement asymétrique KEM, chiffrement de blobs). Pour les clés du trousseau, préférer
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
    ) -> ResultFeuNoyau<Vec<u8>> {
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
    ) -> ResultFeuNoyau<Vec<u8>> {
        // Conversion de la clé éphémère brute en Key<Aes256Gcm>
        let key = Key::<Aes256Gcm>::from_slice(cle_chiffrement);

        // Création du cipher à partir de key
        let cipher = Aes256Gcm::new(key);

        // Déchiffrement de la clé
        let contenu_dechiffre =
            cipher.decrypt(Nonce::from_slice(&contenu[0..12]), &contenu[12..])?;

        Ok(contenu_dechiffre)
    }

    /// Récupère le secret partagé ML-KEM-1024 par décapsulation.
    ///
    /// Décapsule le `ciphertext` (1568 octets) avec la clé privée du foyer
    /// et retourne le secret partagé de 32 octets dans un [`SecretBox`].
    ///
    /// Utilisé dans le schéma de chiffrement asymétrique post-quantique.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer à `index_foyer` est absent du trousseau.
    pub(super) fn recuperation_secret_partage(
        &self,
        index_foyer: usize,
        ciphertext: &Ciphertext1024,
    ) -> ResultFeuNoyau<SecretBox<[u8; 32]>> {
        let secret_partage = self
            .donne_cle_privee_chiffrement_foyer(index_foyer)?
            .decapsulate(ciphertext);

        Ok(SecretBox::new(Box::new(secret_partage.into())))
    }

    // ── Trousseaux publics ────────────────────────────────────────────────────

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
    pub(super) fn genere_trousseau_public_complet(&self) -> ResultFeuNoyau<TrousseauPublicComplet> {
        match (self.sel, &self.paire_signature_noeud) {
            (Some(valeur1), Some(valeur2)) => {
                let trousseau_public_noeud = TrousseauPublicNoeud::new(
                    valeur1,
                    self.chiffre_cle(&valeur2.privee.to_seed().into())?,
                    valeur2.publique.encode().into(),
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
            (None, _) => Err(ErreurFeuNoyau::CryptographeSelAbsent),
            (_, None) => Err(ErreurFeuNoyau::CryptographePaireSignatureNoeudAbsente),
        }
    }

    /// Reconstruit la paire de signature du nœud à partir d'un [`TrousseauPublicNoeud`].
    ///
    /// Déchiffre la seed privée de signature du nœud et reconstitue la paire ML-DSA-87
    /// en mémoire — la clé publique est re-dérivée depuis la privée, et non lue sur
    /// disque. Le déchiffrement échoue si le mot de passe est incorrect —
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
    /// Retourne une erreur si le déchiffrement échoue.
    pub(super) fn trousseau_public_noeud_vers_trousseau(
        &mut self,
        trousseau_public_noeud: &TrousseauPublicNoeud,
    ) -> ResultFeuNoyau<()> {
        let cle_dechiffree = self.dechiffre_cle(&trousseau_public_noeud.donne_cle_sig_privee())?;

        let cle_sig_priv = SigningKey::<MlDsa87>::from_seed(cle_dechiffree.expose_secret().into());
        let cle_sig_pub = cle_sig_priv.verifying_key();

        self.paire_signature_noeud = Some(PaireClesSignature {
            privee: cle_sig_priv,
            publique: cle_sig_pub,
        });

        Ok(())
    }

    /// Déchiffre et charge les clés d'un foyer dans le trousseau à partir d'un [`TrousseauPublicFoyer`].
    ///
    /// Déchiffre la clé symétrique, la paire de signature ML-DSA-87, la paire de chiffrement ML-KEM-1024
    /// et les cinq clés de classeurs avec la clé éphémère, puis enregistre le [`TrousseauFoyer`]
    /// résultant à l'`index` donné. La braise (identifiant du foyer) est lue depuis le [`TrousseauPublicFoyer`].
    ///
    /// # Prérequis
    ///
    /// La clé éphémère doit être présente dans le trousseau —
    /// dérivée préalablement via [`derive_cle_ephemere`](Self::derive_cle_ephemere).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé éphémère est absente ou si le déchiffrement d'une clé
    /// échoue. Les clés publiques de signature et de chiffrement sont re-dérivées depuis
    /// leurs privées, et non lues sur disque.
    pub(super) fn trousseau_public_foyer_vers_trousseau_foyer(
        &mut self,
        trousseau_public_foyer: &TrousseauPublicFoyer,
        index: usize,
    ) -> ResultFeuNoyau<()> {
        let cle_chiffrement =
            self.dechiffre_cle(&trousseau_public_foyer.donne_cle_chiffrement())?;

        let cle_dechiffree = self.dechiffre_cle(&trousseau_public_foyer.donne_cle_sig_privee())?;
        let cle_sig_priv = SigningKey::<MlDsa87>::from_seed(cle_dechiffree.expose_secret().into());

        let paire_signature = PaireClesSignature {
            publique: cle_sig_priv.verifying_key(),
            privee: cle_sig_priv,
        };

        let cle_brute = self.dechiffre_seed(&trousseau_public_foyer.donne_cle_chiff_privee())?;
        let cle_chiff_priv =
            DecapsulationKey1024::from_seed(Seed::from(*cle_brute.expose_secret()));

        let paire_chiffrement = PaireClesChiffrement {
            publique: cle_chiff_priv.encapsulation_key().clone(),
            privee: cle_chiff_priv,
        };

        let mut trousseau_foyer = TrousseauFoyer::new(
            trousseau_public_foyer.donne_braise(),
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

    // ── Utilitaires privés ────────────────────────────────────────────────────

    /// Retourne la clé de chiffrement AES-256-GCM du classeur `index_classeur` du foyer `index_foyer`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer ou le classeur est absent du trousseau.
    fn donne_cle_chiffrement_classeur(
        &self,
        index_foyer: usize,
        index_classeur: usize,
    ) -> ResultFeuNoyau<&SecretBox<[u8; 32]>> {
        let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer] else {
            return Err(ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent(
                index_foyer,
            ));
        };

        let Some(cle_classeur) = &trousseau_foyer.cles_chiffrement_classeurs[index_classeur] else {
            return Err(ErreurFeuNoyau::CryptographeCleChiffrementClasseurAbstente(
                index_classeur,
            ));
        };
        Ok(cle_classeur)
    }

    /// Retourne la clé privée ML-KEM-1024 du foyer à la position `index_foyer`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer est absent du trousseau.
    fn donne_cle_privee_chiffrement_foyer(
        &self,
        index_foyer: usize,
    ) -> ResultFeuNoyau<&DecapsulationKey1024> {
        let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer] else {
            return Err(ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent(
                index_foyer,
            ));
        };

        Ok(trousseau_foyer.donne_cle_privee_chiffrement())
    }

    /// Retourne la clé privée ML-DSA-87 de signature du foyer à la position `index_foyer`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer est absent du trousseau.
    fn donne_cle_privee_signature_foyer(
        &self,
        index_foyer: usize,
    ) -> ResultFeuNoyau<&SigningKey<MlDsa87>> {
        let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer] else {
            return Err(ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent(
                index_foyer,
            ));
        };

        Ok(trousseau_foyer.donne_cle_privee_signature())
    }

    /// Retourne la clé privée ML-DSA-87 de signature du nœud.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la paire de signature du nœud est absente du trousseau.
    fn donne_cle_privee_signature_noeud(&self) -> ResultFeuNoyau<&SigningKey<MlDsa87>> {
        let Some(paire_signature_noeud) = &self.paire_signature_noeud else {
            return Err(ErreurFeuNoyau::CryptographePaireSignatureNoeudAbsente);
        };

        Ok(&paire_signature_noeud.privee)
    }

    /// Dérive `N` octets de matériau clé depuis la seed master par HKDF-SHA3-256.
    ///
    /// Primitive de dérivation unique du trousseau : chaque clé du protocole descend
    /// directement de la seed, isolée par un `label` distinct passé en `info` HKDF.
    /// C'est ce label — et non une clé mère intermédiaire — qui sépare les domaines
    /// de dérivation, sans collision possible entre clés. Le résultat est encapsulé
    /// dans un [`SecretBox`], zéroïsé à sa destruction.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'expansion HKDF échoue (taille `N` invalide).
    fn derive_depuis_seed<const N: usize>(
        seed: &SecretBox<[u8; 64]>,
        label: &str,
    ) -> ResultFeuNoyau<SecretBox<[u8; N]>> {
        let hkdf = Hkdf::<Sha3_256>::new(None, seed.expose_secret());

        let mut cle_brute = SecretBox::new(Box::new([0u8; N]));
        hkdf.expand(label.as_bytes(), cle_brute.expose_secret_mut())?;

        Ok(cle_brute)
    }

    /// Signe `octets_a_signer` avec une clé privée ML-DSA-87 et retourne la
    /// signature encodée (4627 octets).
    ///
    /// Helper interne factorisant la signature du nœud et du foyer — seule la
    /// clé privée employée diffère entre les deux appelants.
    fn signe_octets(cle_privee: &SigningKey<MlDsa87>, octets_a_signer: &[u8]) -> [u8; 4627] {
        cle_privee.sign(octets_a_signer).encode().into()
    }

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
    ) -> ResultFeuNoyau<()> {
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
    ) -> ResultFeuNoyau<()> {
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
}

// Couvert ici : la dérivation des clés depuis la seed, le chiffrement
// symétrique AES-256-GCM, et le rejet d'un mauvais mot de passe.
//
// `chiffre_cle`, `chiffre_seed` et `chiffre_blob` n'ont pas de test propre :
// toutes délèguent à `chiffrement_generique_avec_cle`, seul endroit où le
// chiffrement a réellement lieu. Elles ne font que choisir la clé et resserrer
// le type de sortie — les tester séparément reviendrait à tester trois fois le
// même chemin de code.
//
// Non couvert ici, car impossible à exercer sans écrire sur le disque :
//
// - le chiffrement de flux par chunks (`chiffre_avec_cle` et sa réciproque),
//   employé pour les archives de foyer ;
// - la persistance des trousseaux publics (`genere_trousseau_public_complet`
//   et les `trousseau_public_*_vers_*`).
//
// Ces deux mécanismes relèvent des tests d'intégration.
#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::ResultFeuNoyau;

    use super::*;

    /// Vérifie qu'une même seed redonne toujours exactement le même matériau.
    ///
    /// C'est l'invariant sur lequel repose `demarrage_secours` : reconstruire un
    /// nœud à partir de la seed doit rendre les mêmes clés et les mêmes braises.
    /// S'il cède, les données déjà déposées deviennent illisibles et les foyers
    /// changent d'adresse.
    #[test]
    fn derivation_deterministe_meme_seed() -> ResultFeuNoyau<()> {
        let seed = SecretBox::new(Box::new([0x42; 64]));

        // Les trois appels reproduisent la séquence de
        // `Cryptographe::genere_trousseau_a_partir_seed` — sel et matériau des
        // foyers sortent tous de la seed, par des labels HKDF distincts.

        // Génération trousseau 1
        let mut trousseau1 = Trousseau::new();
        trousseau1.genere_sel(&seed)?;
        trousseau1.ajouter_paire_noeud(&seed)?;
        for i in 0..MAX_FOYERS {
            trousseau1.ajouter_trousseau_foyer(&seed, i)?;
        }

        // Génération trousseau 2
        let mut trousseau2 = Trousseau::new();
        trousseau2.genere_sel(&seed)?;
        trousseau2.ajouter_paire_noeud(&seed)?;
        for i in 0..MAX_FOYERS {
            trousseau2.ajouter_trousseau_foyer(&seed, i)?;
        }

        assert_eq!(
            trousseau1.sel.as_ref().unwrap(),
            trousseau2.sel.as_ref().unwrap()
        );

        assert_eq!(
            trousseau1.donne_cle_privee_signature_noeud()?,
            trousseau2.donne_cle_privee_signature_noeud()?
        );

        for i in 0..MAX_FOYERS {
            let trousseau_foyer1 = trousseau1.trousseaux_foyers[i].as_ref().unwrap();
            let trousseau_foyer2 = trousseau2.trousseaux_foyers[i].as_ref().unwrap();

            assert_eq!(trousseau_foyer1.braise, trousseau_foyer2.braise);
            assert_eq!(
                trousseau_foyer1.donne_cle_privee_signature(),
                trousseau_foyer2.donne_cle_privee_signature()
            );
            assert_eq!(
                trousseau_foyer1.donne_cle_privee_chiffrement(),
                trousseau_foyer2.donne_cle_privee_chiffrement()
            );
            assert_eq!(
                trousseau_foyer1.donne_cle_chiffrement().expose_secret(),
                trousseau_foyer2.donne_cle_chiffrement().expose_secret(),
            );

            for j in 0..MAX_CLASSEURS {
                let cle1 = trousseau_foyer1.cles_chiffrement_classeurs[j]
                    .as_ref()
                    .unwrap();
                let cle2 = trousseau_foyer2.cles_chiffrement_classeurs[j]
                    .as_ref()
                    .unwrap();

                assert_eq!(cle1.expose_secret(), cle2.expose_secret());
            }
        }

        Ok(())
    }

    /// Vérifie que deux seeds distinctes ne partagent aucun élément dérivé.
    ///
    /// Sel, clés du nœud, clés et braises de chaque foyer : rien ne doit
    /// coïncider entre deux nœuds nés de seeds différentes.
    #[test]
    fn derivation_deterministe_seeds_differentes() -> ResultFeuNoyau<()> {
        // Contrepartie du test précédent : une dérivation qui ignorerait la seed
        // serait parfaitement « déterministe », mais rendrait le même matériau
        // pour tous les nœuds. Seules deux seeds distinctes attrapent ce cas.
        let seed1 = SecretBox::new(Box::new([0x42; 64]));
        let seed2 = SecretBox::new(Box::new([0x43; 64]));

        // Génération trousseau 1
        let mut trousseau1 = Trousseau::new();
        trousseau1.genere_sel(&seed1)?;
        trousseau1.ajouter_paire_noeud(&seed1)?;
        for i in 0..MAX_FOYERS {
            trousseau1.ajouter_trousseau_foyer(&seed1, i)?;
        }

        // Génération trousseau 2
        let mut trousseau2 = Trousseau::new();
        trousseau2.genere_sel(&seed2)?;
        trousseau2.ajouter_paire_noeud(&seed2)?;
        for i in 0..MAX_FOYERS {
            trousseau2.ajouter_trousseau_foyer(&seed2, i)?;
        }

        assert_ne!(
            trousseau1.sel.as_ref().unwrap(),
            trousseau2.sel.as_ref().unwrap()
        );

        assert_ne!(
            trousseau1.donne_cle_privee_signature_noeud()?,
            trousseau2.donne_cle_privee_signature_noeud()?
        );

        for i in 0..MAX_FOYERS {
            let trousseau_foyer1 = trousseau1.trousseaux_foyers[i].as_ref().unwrap();
            let trousseau_foyer2 = trousseau2.trousseaux_foyers[i].as_ref().unwrap();

            assert_ne!(trousseau_foyer1.braise, trousseau_foyer2.braise);
            assert_ne!(
                trousseau_foyer1.donne_cle_privee_signature(),
                trousseau_foyer2.donne_cle_privee_signature()
            );
            assert_ne!(
                trousseau_foyer1.donne_cle_privee_chiffrement(),
                trousseau_foyer2.donne_cle_privee_chiffrement()
            );
            assert_ne!(
                trousseau_foyer1.donne_cle_chiffrement().expose_secret(),
                trousseau_foyer2.donne_cle_chiffrement().expose_secret(),
            );

            for j in 0..MAX_CLASSEURS {
                let cle1 = trousseau_foyer1.cles_chiffrement_classeurs[j]
                    .as_ref()
                    .unwrap();
                let cle2 = trousseau_foyer2.cles_chiffrement_classeurs[j]
                    .as_ref()
                    .unwrap();

                assert_ne!(cle1.expose_secret(), cle2.expose_secret());
            }
        }

        Ok(())
    }

    /// Vérifie le cycle chiffrement/déchiffrement AES-256-GCM.
    ///
    /// `chiffrement_generique_avec_cle` est le point de passage unique de tout
    /// le chiffrement symétrique du trousseau : `chiffre_cle`, `chiffre_seed` et
    /// `chiffre_blob` y délèguent, en ne changeant que la clé fournie et le type
    /// de sortie. Le tester une fois les couvre tous les trois.
    #[test]
    fn cycle_chiffrement_dechiffrement_generique() -> ResultFeuNoyau<()> {
        let cle = [0x11u8; 32];
        let contenu = b"contenu de test";

        let chiffre1 = Trousseau::chiffrement_generique_avec_cle(&cle, contenu)?;
        let chiffre2 = Trousseau::chiffrement_generique_avec_cle(&cle, contenu)?;

        let dechiffre1 = Trousseau::dechiffrement_generique_avec_cle(&cle, &chiffre1)?;
        let dechiffre2 = Trousseau::dechiffrement_generique_avec_cle(&cle, &chiffre2)?;

        // Le nonce est tiré d'`OsRng` à chaque appel : deux chiffrements du même
        // contenu ne peuvent pas coïncider. Un nonce figé briserait AES-GCM.
        assert_ne!(chiffre1, chiffre2);
        assert_eq!(dechiffre1, dechiffre2);
        assert_eq!(dechiffre1, contenu);

        Ok(())
    }

    /// Vérifie qu'un mot de passe incorrect fait échouer le déchiffrement.
    ///
    /// C'est le mécanisme réel de vérification du mot de passe Feu : aucun mot
    /// de passe n'est stocké, ni en clair ni en hash. La clé éphémère est
    /// dérivée par Argon2id du mot de passe et du sel — un mot de passe erroné
    /// donne une clé différente, et AES-GCM rejette l'auth tag.
    #[test]
    fn mauvais_mot_de_passe() -> ResultFeuNoyau<()> {
        let mut trousseau = Trousseau::new();
        trousseau.definit_sel([0x22; 16]);
        trousseau.definit_mdp(SecretString::from("bon mot de passe"));
        trousseau.derive_cle_ephemere()?;

        let cle = [0x32; 32];

        let cle_chiffree = trousseau.chiffre_cle(&cle)?;

        // Témoin : établit que le déchiffrement fonctionne avec le bon mot de
        // passe. Sans lui, l'échec attendu plus bas pourrait venir d'un
        // chiffrement raté plutôt que du changement de mot de passe.
        let cle_dechiffree = trousseau.dechiffre_cle(&cle_chiffree)?;

        assert_eq!(&cle, cle_dechiffree.expose_secret());

        // Le sel reste inchangé : seul le mot de passe varie, donc seule la clé
        // éphémère change.
        trousseau.definit_mdp(SecretString::from("mauvais mot de passe"));
        trousseau.derive_cle_ephemere()?;

        assert!(trousseau.dechiffre_cle(&cle_chiffree).is_err());

        Ok(())
    }

    /// Vérifie que chaque dérivation produit une clé distincte de toutes les autres.
    ///
    /// Preuve de la séparation de domaine HKDF : chaque clé est tirée d'un `info`
    /// qui lui est propre — label, index du foyer, et index du classeur le cas
    /// échéant. Un label dupliqué ferait collisionner deux clés, et deux foyers
    /// partageraient alors leur matériau.
    #[test]
    fn derivation_cles_distinctes() -> ResultFeuNoyau<()> {
        // Un ensemble par famille : seules des valeurs de même nature et de même
        // taille peuvent réellement collisionner. Confronter une clé symétrique
        // de 32 octets à une clé publique de plusieurs milliers ne prouverait
        // rien.
        let seed = SecretBox::new(Box::new([0x11; 64]));

        // Génération trousseau
        let mut trousseau = Trousseau::new();
        trousseau.ajouter_paire_noeud(&seed)?;
        for i in 0..MAX_FOYERS {
            trousseau.ajouter_trousseau_foyer(&seed, i)?;
        }

        let mut cles_publiques_signature_vues = HashSet::new();
        assert!(
            cles_publiques_signature_vues.insert(
                trousseau
                    .paire_signature_noeud
                    .as_ref()
                    .unwrap()
                    .publique
                    .encode()
            )
        );

        let mut cles_chiffrement_vues = HashSet::new();
        let mut cles_publiques_chiffrement_vues = HashSet::new();

        for i in 0..MAX_FOYERS {
            let trousseau_foyer = trousseau.trousseaux_foyers[i].as_ref().unwrap();

            assert!(
                cles_publiques_signature_vues
                    .insert(trousseau_foyer.paire_signature.publique.encode())
            );

            assert!(
                cles_publiques_chiffrement_vues
                    .insert(trousseau_foyer.paire_chiffrement.publique.to_bytes())
            );

            assert!(
                cles_chiffrement_vues
                    .insert(*trousseau_foyer.donne_cle_chiffrement().expose_secret())
            );

            for j in 0..MAX_CLASSEURS {
                let cle = trousseau_foyer.cles_chiffrement_classeurs[j]
                    .as_ref()
                    .unwrap();

                assert!(cles_chiffrement_vues.insert(*cle.expose_secret()));
            }
        }

        assert_eq!(cles_publiques_signature_vues.len(), MAX_FOYERS + 1);

        assert_eq!(cles_publiques_chiffrement_vues.len(), MAX_FOYERS);

        assert_eq!(
            cles_chiffrement_vues.len(),
            MAX_FOYERS * MAX_CLASSEURS + MAX_FOYERS
        );

        Ok(())
    }
}
