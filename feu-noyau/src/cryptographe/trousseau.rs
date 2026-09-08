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
//!   le type implémente `Zeroize`. L'accès au contenu est volontairement
//!   contraint à `expose_secret()` / `expose_secret_mut()`, rendant toute
//!   manipulation visible à la lecture du code. La mémoire est zéroïsée à la
//!   destruction.
//!
//! - `ZeroizeOnDrop` (crate `zeroize`) : utilisé pour [`SigningKey`]
//!   (ml-dsa) et [`DecapsulationKey1024`] (ml-kem), dont les types
//!   n'implémentent pas `Zeroize` et ne peuvent donc pas être encapsulés
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
//! # Invariants
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

use std::io::{Read, Write};

use aead_stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::Argon2;
use data_encoding::BASE32_NOPAD;
use hkdf::Hkdf;
use ml_dsa::{Keypair, MlDsa87, Signer, SigningKey, VerifyingKey};
use ml_kem::{
    Decapsulate, DecapsulationKey1024, EncapsulationKey1024, KeyExport, Seed,
    ml_kem_1024::Ciphertext as Ciphertext1024,
};
use rand::{RngCore, rngs::OsRng};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use sha3::{Digest, Sha3_256};

use super::trousseaux_publics::{
    TrousseauPublicComplet, TrousseauPublicFoyer, TrousseauPublicNoeud,
};
use crate::{Braise, ErreurFeuNoyau, IndexClasseur, IndexFoyer, ResultFeuNoyau};

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
/// Sel Argon2id du nœud.
const LABEL_DERIVATION_SEL: &str = "feu/noeud/sel";

/// Paire ML-DSA-87 du nœud, signataire des racines.
const LABEL_DERIVATION_SIGNATURE_NOEUD: &str = "feu/noeud/signature";

/// Paire ML-DSA-87 d'un foyer, signataire de ses ENU.
const LABEL_DERIVATION_SIGNATURE_FOYER: &str = "feu/foyer/signature";

/// Clé AES-256 qui chiffre l'archive `.feu` du foyer.
const LABEL_DERIVATION_CHIFFREMENT_SYMETRIQUE_FOYER: &str = "feu/foyer/symetrique";

/// Paire ML-KEM-1024 d'un foyer, destinataire d'un chiffrement asymétrique.
const LABEL_DERIVATION_CHIFFREMENT_FOYER: &str = "feu/foyer/chiffrement";

/// Adresse `.braise` du foyer — un identifiant, pas une clé, mais dérivé du
/// même secret pour être retrouvé depuis la seule seed.
const LABEL_DERIVATION_BRAISE_FOYER: &str = "feu/foyer/braise";

/// Clé AES-256 qui chiffre les blobs d'un classeur — une par classeur.
const LABEL_DERIVATION_CHIFFREMENT_SYMETRIQUE_CLASSEUR: &str = "feu/classeur/symetrique";

// ── Constantes d'implémentation ──────────────────────────────────────────────

/// Taille des tranches du chiffrement en flux — 4 Kio.
///
/// Un foyer entier passe par ce tampon plutôt que par la mémoire : sa taille
/// n'est pas bornée.
const CHUNK_SIZE: usize = 4096;

/// Paire de clés ML-DSA-87 de signature d'un foyer.
///
/// `privee` est protégée par `ZeroizeOnDrop` (ml-dsa, feature `zeroize`) : la
/// zéroïsation est garantie à la destruction, sans pouvoir être déclenchée
/// manuellement. `SigningKey` n'implémentant pas `Zeroize`, `SecretBox` lui est
/// inapplicable — sans conséquence, l'effacement étant déjà couvert.
struct PaireClesSignature {
    /// Signe une carte d'ENU ou un message.
    privee: SigningKey<MlDsa87>,
    /// Publiée en clair : elle vérifie une signature sans ouvrir le foyer.
    publique: VerifyingKey<MlDsa87>,
}

/// Paire de clés ML-KEM-1024 d'un foyer — chiffrement réseau asymétrique post-quantique.
///
/// `privee` est protégée par `ZeroizeOnDrop` (ml-kem, feature `zeroize`) : la
/// zéroïsation est garantie à la destruction, sans pouvoir être déclenchée
/// manuellement. `DecapsulationKey` n'implémentant pas `Zeroize`, `SecretBox`
/// lui est inapplicable — sans conséquence, l'effacement étant déjà couvert.
///
/// Au stockage, `privee` sort sous forme de seed de 64 octets, sérialisation
/// recommandée par la crate.
struct PaireClesChiffrement {
    /// Décapsule le secret partagé d'un message reçu.
    privee: DecapsulationKey1024,
    /// Publiée en clair : c'est elle qu'un tiers encapsule pour écrire au foyer.
    publique: EncapsulationKey1024,
}

/// Clés opérationnelles d'un foyer ouvert, maintenues en mémoire pour la durée de la session.
///
/// Contient l'adresse `.braise`, la clé symétrique d'archive, la paire
/// de signature, la paire de chiffrement réseau et les clés des classeurs. Toutes les
/// clés privées et symétriques sont encapsulées dans [`SecretBox`] ou protégées par `ZeroizeOnDrop`.
struct TrousseauFoyer {
    /// Adresse `.braise` du foyer, qui le désigne sur le disque.
    braise: Braise,
    /// Clé AES-256 de l'archive `.feu`.
    cle_chiffrement: SecretBox<[u8; 32]>,
    /// Paire ML-DSA-87 signataire des ENU du foyer.
    paire_signature: PaireClesSignature,
    /// Paire ML-KEM-1024 du foyer, sans emploi tant qu'il n'y a pas de réseau.
    paire_chiffrement: PaireClesChiffrement,
    /// Une clé AES-256 par classeur, `None` tant que le classeur n'a pas servi :
    /// la dérivation n'a lieu qu'au premier blob déposé.
    cles_chiffrement_classeurs: [Option<SecretBox<[u8; 32]>>; IndexClasseur::NOMBRE],
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

    /// Insère la clé de chiffrement du classeur `index_classeur`.
    ///
    /// Appelée après [`new`](Self::new) pour peupler les slots de classeurs un
    /// par un. L'écriture est directe et sans garde : [`IndexClasseur`] borne
    /// l'index par construction.
    fn ajoute_cle_classeur(
        &mut self,
        cle_classeur: SecretBox<[u8; 32]>,
        index_classeur: IndexClasseur,
    ) {
        self.cles_chiffrement_classeurs[index_classeur.valeur()] = Some(cle_classeur);
    }

    /// Chiffre toutes les clés du foyer et produit le [`TrousseauPublicFoyer`] persistable.
    ///
    /// Délègue le chiffrement AES-256-GCM de chaque clé à [`Trousseau::chiffre_cle`]
    /// (clés de 32 octets) ou [`Trousseau::chiffre_seed`] (seed ML-KEM-1024 de 64 octets).
    /// Les clés publiques sont copiées en clair.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si le chiffrement d'une clé échoue — clé éphémère
    /// absente du trousseau ou échec AES-256-GCM, et
    /// [`ErreurFeuNoyau::CryptographeCleChiffrementClasseurAbstente`] si l'un des
    /// classeurs n'a pas de clé.
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

        for index_classeur in IndexClasseur::tous() {
            if let Some(cle) = &self.cles_chiffrement_classeurs[index_classeur.valeur()] {
                trousseau_public_foyer.ajoute_cle_chiffrement_classeur(
                    trousseau.chiffre_cle(cle.expose_secret())?,
                    index_classeur,
                );
            } else {
                return Err(ErreurFeuNoyau::CryptographeCleChiffrementClasseurAbstente(
                    index_classeur.valeur(),
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
    /// Mot de passe du nœud, retenu le temps de la session : il faut le
    /// représenter à chaque dérivation.
    mdp: Option<SecretString>,
    /// Clé tirée du mot de passe par Argon2id, qui déverrouille les clés du
    /// nœud. Effacée dès que possible sur les chemins qui la posent.
    cle_ephemere: Option<SecretBox<[u8; 32]>>,
    /// Sel Argon2id relu de `sel.feu`, sans quoi la clé éphémère ne se retrouve
    /// pas.
    sel: Option<[u8; 16]>,
    /// Paire ML-DSA-87 du nœud, chargée à l'allumage.
    paire_signature_noeud: Option<PaireClesSignature>,
    /// Un trousseau par foyer ouvert, `None` pour les autres : c'est ce champ
    /// qui porte l'état d'ouverture côté secrets.
    trousseaux_foyers: [Option<TrousseauFoyer>; IndexFoyer::NOMBRE],
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
    /// Utilisé par [`genere_trousseau_a_partir_seed`](super::Cryptographe::genere_trousseau_a_partir_seed) pour déterminer
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
    ///
    /// # Errors
    ///
    /// Propage l'échec de [`Self::derive_depuis_seed`].
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
    /// Braise, clé symétrique, paire ML-DSA-87, paire ML-KEM-1024 et cinq clés de
    /// classeur sont dérivées de `seed_bytes` par HKDF-SHA3-256. Chaque élément
    /// est tiré d'un `info` distinct — label dédié plus index du foyer —, ce qui
    /// sépare les domaines de dérivation entre éléments comme entre foyers.
    ///
    /// Les clés brutes intermédiaires sont portées par des `SecretBox` et
    /// zéroïsées dès qu'elles ne servent plus.
    ///
    /// # Errors
    ///
    /// Propage l'échec de [`Self::derive_depuis_seed`], et
    /// [`ErreurFeuNoyau::BraiseErronnee`] si la braise dérivée est refusée par
    /// `Braise::try_from`.
    pub(super) fn ajouter_trousseau_foyer(
        &mut self,
        seed_bytes: &SecretBox<[u8; 64]>,
        index_foyer: IndexFoyer,
    ) -> ResultFeuNoyau<()> {
        // Les labels de dérivation numérotent les foyers à partir de 1, quand
        // IndexFoyer part de 0.
        let index_derivation_foyer = index_foyer.valeur() + 1;

        // Paire de clés signature du foyer
        let cle_sig_priv = SigningKey::<MlDsa87>::from_seed(
            Self::derive_depuis_seed::<32>(
                seed_bytes,
                &format!("{LABEL_DERIVATION_SIGNATURE_FOYER}/{index_derivation_foyer}"),
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
            &format!("{LABEL_DERIVATION_CHIFFREMENT_SYMETRIQUE_FOYER}/{index_derivation_foyer}"),
        )?;

        // Paire de clés chiffrement foyer
        let cle_chiff_priv = {
            let seed_brute = Self::derive_depuis_seed::<64>(
                seed_bytes,
                &format!("{LABEL_DERIVATION_CHIFFREMENT_FOYER}/{index_derivation_foyer}"),
            )?;
            DecapsulationKey1024::from_seed(Seed::from(*seed_brute.expose_secret()))
        };

        let cle_chiff_pub = cle_chiff_priv.encapsulation_key().clone();

        let paire_chiffrement = PaireClesChiffrement {
            privee: cle_chiff_priv,
            publique: cle_chiff_pub,
        };

        // Une clé de chiffrement par classeur, les labels les numérotant eux
        // aussi à partir de 1.
        let mut cles_chiffrement_classeurs: [Option<SecretBox<[u8; 32]>>; IndexClasseur::NOMBRE] =
            std::array::from_fn(|_| None);
        for (i, e) in cles_chiffrement_classeurs.iter_mut().enumerate() {
            let index_derivation_classeur = i + 1;
            *e = Some(Self::derive_depuis_seed::<32>(
                seed_bytes,
                &format!(
                    "{LABEL_DERIVATION_CHIFFREMENT_SYMETRIQUE_CLASSEUR}/{index_derivation_foyer}/{index_derivation_classeur}"
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
            &format!("{LABEL_DERIVATION_BRAISE_FOYER}/{index_derivation_foyer}"),
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

        self.trousseaux_foyers[index_foyer.valeur()] = Some(trousseau_foyer);

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
    ///
    /// # Errors
    ///
    /// Propage l'échec de [`Self::derive_depuis_seed`].
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
    /// Cette clé sert uniquement à chiffrer les clés privées via [`Self::chiffre_cle`] —
    /// elle doit être effacée dès que le trousseau persistable est constitué.
    ///
    /// # Errors
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
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::CryptographePaireSignatureNoeudAbsente`] si la clé de
    /// signature du nœud n'est pas chargée.
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
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent`] si le foyer n'est
    /// pas ouvert.
    pub(super) fn signe_avec_cle_foyer(
        &self,
        index_foyer: IndexFoyer,
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
    /// # Errors
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
    /// # Errors
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
    /// # Errors
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
    /// # Errors
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
    /// # Errors
    ///
    /// Retourne une erreur si le foyer ou le classeur est absent du trousseau,
    /// ou si le chiffrement AES-256-GCM échoue.
    pub(super) fn chiffre_blob(
        &self,
        index_foyer: IndexFoyer,
        index_classeur: IndexClasseur,
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
    /// # Errors
    ///
    /// Retourne une erreur si le foyer ou le classeur est absent du trousseau,
    /// ou si le déchiffrement AES-256-GCM échoue.
    pub(super) fn dechiffre_blob(
        &self,
        index_foyer: IndexFoyer,
        index_classeur: IndexClasseur,
        blob: &[u8],
    ) -> ResultFeuNoyau<Vec<u8>> {
        Self::dechiffrement_generique_avec_cle(
            self.donne_cle_chiffrement_classeur(index_foyer, index_classeur)?
                .expose_secret(),
            blob,
        )
    }

    /// Chiffre un flux de données du foyer à la position `index_foyer`.
    ///
    /// Récupère la clé symétrique du foyer dans le trousseau et délègue
    /// le chiffrement à [`chiffre_avec_cle`](Self::chiffre_avec_cle).
    ///
    /// # Prérequis
    ///
    /// Le foyer à la position `index_foyer` doit être présent dans le
    /// trousseau — c'est-à-dire qu'il doit être ouvert.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent`] si le foyer n'est
    /// pas ouvert, ou une erreur si le chiffrement AES-GCM-stream échoue.
    pub(super) fn chiffre_avec_cle_foyer(
        &self,
        index_foyer: IndexFoyer,
        source: &mut impl Read,
        destination: &mut impl Write,
    ) -> ResultFeuNoyau<()> {
        if let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer.valeur()] {
            Self::chiffre_avec_cle(
                trousseau_foyer.donne_cle_chiffrement().expose_secret(),
                source,
                destination,
            )?;
            return Ok(());
        }
        Err(ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent(
            index_foyer.valeur(),
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
    /// # Errors
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
        Self::dechiffre_avec_cle(
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
    /// # Errors
    ///
    /// Retourne une erreur si le chiffrement AES-256-GCM échoue.
    pub(super) fn chiffrement_generique_avec_cle(
        cle_chiffrement: &[u8; 32],
        contenu: &[u8],
    ) -> ResultFeuNoyau<Vec<u8>> {
        // Conversion de la clé de chiffrement brute en Key<Aes256Gcm>
        let key = <&Key<Aes256Gcm>>::from(cle_chiffrement);

        // Création du cipher à partir de key
        let cipher = Aes256Gcm::new(key);

        // Génération aléatoire du nonce de 12 octets
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        // Chiffrement du contenu
        let contenu_chiffre = cipher.encrypt(&Nonce::from(nonce), contenu.as_ref())?;

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
    /// # Errors
    ///
    /// Retourne une erreur si la vérification de l'auth tag AES-GCM échoue
    /// (clé incorrecte ou données corrompues).
    pub(super) fn dechiffrement_generique_avec_cle(
        cle_chiffrement: &[u8; 32],
        contenu: &[u8],
    ) -> ResultFeuNoyau<Vec<u8>> {
        // Conversion de la clé éphémère brute en Key<Aes256Gcm>
        let key = <&Key<Aes256Gcm>>::from(cle_chiffrement);

        // Création du cipher à partir de key
        let cipher = Aes256Gcm::new(key);

        // Déchiffrement de la clé
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&contenu[0..12]);
        let contenu_dechiffre = cipher.decrypt(&Nonce::from(nonce), &contenu[12..])?;

        Ok(contenu_dechiffre)
    }

    /// Récupère le secret partagé ML-KEM-1024 par décapsulation.
    ///
    /// Décapsule le `ciphertext` (1568 octets) avec la clé privée du foyer
    /// et retourne le secret partagé de 32 octets dans un [`SecretBox`].
    ///
    /// Utilisé dans le schéma de chiffrement asymétrique post-quantique.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent`] si le foyer n'est
    /// pas ouvert.
    pub(super) fn recuperation_secret_partage(
        &self,
        index_foyer: IndexFoyer,
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
    /// # Errors
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
                for index_foyer in IndexFoyer::tous() {
                    if let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer.valeur()] {
                        trousseau_public_complet.ajoute_trousseau_foyer_public(
                            trousseau_foyer.genere_trousseau_public_foyer(self)?,
                            index_foyer,
                        );
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
    /// # Errors
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
    /// résultant à la position `index_foyer`. La braise (identifiant du foyer) est
    /// lue depuis le [`TrousseauPublicFoyer`].
    ///
    /// # Prérequis
    ///
    /// La clé éphémère doit être présente dans le trousseau —
    /// dérivée préalablement via [`derive_cle_ephemere`](Self::derive_cle_ephemere).
    ///
    /// # Errors
    ///
    /// Retourne une erreur si la clé éphémère est absente ou si le déchiffrement d'une clé
    /// échoue. Les clés publiques de signature et de chiffrement sont re-dérivées depuis
    /// leurs privées, et non lues sur disque.
    pub(super) fn trousseau_public_foyer_vers_trousseau_foyer(
        &mut self,
        trousseau_public_foyer: &TrousseauPublicFoyer,
        index_foyer: IndexFoyer,
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

        for index_classeur in IndexClasseur::tous() {
            let cle_classeur = self.dechiffre_cle(
                trousseau_public_foyer.donne_cle_chiffrement_classeur(index_classeur)?,
            )?;
            trousseau_foyer.ajoute_cle_classeur(cle_classeur, index_classeur);
        }
        self.trousseaux_foyers[index_foyer.valeur()] = Some(trousseau_foyer);

        Ok(())
    }

    // ── Utilitaires privés ────────────────────────────────────────────────────

    /// Retourne la clé de chiffrement AES-256-GCM du classeur `index_classeur` du foyer `index_foyer`.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent`] si le foyer n'est
    /// pas ouvert, [`ErreurFeuNoyau::CryptographeCleChiffrementClasseurAbstente`]
    /// si sa clé de classeur manque.
    fn donne_cle_chiffrement_classeur(
        &self,
        index_foyer: IndexFoyer,
        index_classeur: IndexClasseur,
    ) -> ResultFeuNoyau<&SecretBox<[u8; 32]>> {
        let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer.valeur()] else {
            return Err(ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent(
                index_foyer.valeur(),
            ));
        };

        let Some(cle_classeur) =
            &trousseau_foyer.cles_chiffrement_classeurs[index_classeur.valeur()]
        else {
            return Err(ErreurFeuNoyau::CryptographeCleChiffrementClasseurAbstente(
                index_classeur.valeur(),
            ));
        };
        Ok(cle_classeur)
    }

    /// Retourne la clé privée ML-KEM-1024 du foyer à la position `index_foyer`.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent`] si le foyer n'est
    /// pas ouvert.
    fn donne_cle_privee_chiffrement_foyer(
        &self,
        index_foyer: IndexFoyer,
    ) -> ResultFeuNoyau<&DecapsulationKey1024> {
        let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer.valeur()] else {
            return Err(ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent(
                index_foyer.valeur(),
            ));
        };

        Ok(trousseau_foyer.donne_cle_privee_chiffrement())
    }

    /// Retourne la clé privée ML-DSA-87 de signature du foyer à la position `index_foyer`.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent`] si le foyer n'est
    /// pas ouvert.
    fn donne_cle_privee_signature_foyer(
        &self,
        index_foyer: IndexFoyer,
    ) -> ResultFeuNoyau<&SigningKey<MlDsa87>> {
        let Some(trousseau_foyer) = &self.trousseaux_foyers[index_foyer.valeur()] else {
            return Err(ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent(
                index_foyer.valeur(),
            ));
        };

        Ok(trousseau_foyer.donne_cle_privee_signature())
    }

    /// Retourne la clé privée ML-DSA-87 de signature du nœud.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::CryptographePaireSignatureNoeudAbsente`] si la paire du
    /// nœud n'est pas chargée.
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
    /// # Errors
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
    /// # Errors
    ///
    /// Retourne une erreur si une opération d'entrée/sortie échoue ou si le
    /// chiffrement AES-GCM-stream échoue.
    fn chiffre_avec_cle(
        cle_chiffrement: &[u8; 32],
        source: &mut impl Read,
        destination: &mut impl Write,
    ) -> ResultFeuNoyau<()> {
        // Génération du nonce aléatoire
        let mut nonce = [0u8; 7];
        OsRng.fill_bytes(&mut nonce);

        // Création du StreamEncryptor
        let key = <&Key<Aes256Gcm>>::from(cle_chiffrement);
        let cipher = Aes256Gcm::new(key);
        let mut encryptor = EncryptorBE32::from_aead(cipher, (&nonce).into());

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
    /// # Errors
    ///
    /// Retourne une erreur si la lecture du nonce échoue, si une opération
    /// d'entrée/sortie échoue, ou si la vérification de l'auth tag AES-GCM échoue
    /// (données corrompues ou clé incorrecte).
    fn dechiffre_avec_cle(
        cle_chiffrement: &[u8; 32],
        source: &mut impl Read,
        destination: &mut impl Write,
    ) -> ResultFeuNoyau<()> {
        // Récupération du nonce
        let mut nonce = [0u8; 7];
        source.read_exact(&mut nonce)?;

        // Création du StreamDecryptor
        let key = <&Key<Aes256Gcm>>::from(cle_chiffrement);
        let cipher = Aes256Gcm::new(key);
        let mut decryptor = DecryptorBE32::from_aead(cipher, (&nonce).into());

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
// Ces deux mécanismes relèvent des tests de bout en bout de
// `tests/cycle_de_vie.rs`.
/// Tests en ligne : le déterminisme de la dérivation depuis une graine, le
/// cycle de chiffrement générique et le refus d'un mauvais mot de passe.
#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;
    use proptest::{
        prelude::{ProptestConfig, any},
        prop_assert, prop_assert_eq, prop_assert_ne, prop_assume, proptest,
    };

    use super::*;
    use crate::{Cryptographe, ResultFeuNoyau};

    proptest! {
        /// Vérifie que deux labels distincts ne dérivent jamais le même matériau.
        ///
        /// C'est la séparation de domaine HKDF elle-même : le label est passé en
        /// `info`, et lui seul sépare les clés d'une même seed. Le test tombe si
        /// `expand` cesse de le consommer, une collision réelle sur 32 octets étant
        /// hors de portée.
        #[test]
        fn derivation_labels_distincts(
            octets in any::<[u8; 64]>(),
            label1 in "[a-z0-9/]{1,32}",
            label2 in "[a-z0-9/]{1,32}",
        ) {
            prop_assume!(label1 != label2);

            let seed = SecretBox::new(Box::new(octets));

            // Les deux tailles employées par le protocole : 32 octets pour les clés
            // symétriques, les seeds ML-DSA et les braises, 64 pour la seed ML-KEM.
            let cle32_1 = Trousseau::derive_depuis_seed::<32>(&seed, &label1)?;
            let cle32_2 = Trousseau::derive_depuis_seed::<32>(&seed, &label2)?;

            prop_assert_ne!(cle32_1.expose_secret(), cle32_2.expose_secret());

            let cle64_1 = Trousseau::derive_depuis_seed::<64>(&seed, &label1)?;
            let cle64_2 = Trousseau::derive_depuis_seed::<64>(&seed, &label2)?;

            prop_assert_ne!(cle64_1.expose_secret(), cle64_2.expose_secret());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Vérifie qu'une même seed redonne toujours exactement le même matériau.
        ///
        /// C'est l'invariant sur lequel repose `demarrage_secours` : reconstruire un
        /// nœud à partir de la seed doit rendre les mêmes clés et les mêmes braises.
        /// S'il cède, les données déjà déposées deviennent illisibles et les foyers
        /// changent d'adresse.
        #[test]
        fn derivation_deterministe_meme_seed(octets in any::<[u8; 64]>()) {
            let seed = SecretBox::new(Box::new(octets));

            // Les trois appels reproduisent la séquence de
            // `Cryptographe::genere_trousseau_a_partir_seed` — sel et matériau des
            // foyers sortent tous de la seed, par des labels HKDF distincts.

            // Génération trousseau 1
            let mut trousseau1 = Trousseau::new();
            trousseau1.genere_sel(&seed)?;
            trousseau1.ajouter_paire_noeud(&seed)?;
            for index_foyer in IndexFoyer::tous() {
                trousseau1.ajouter_trousseau_foyer(&seed, index_foyer)?;
            }

            // Génération trousseau 2
            let mut trousseau2 = Trousseau::new();
            trousseau2.genere_sel(&seed)?;
            trousseau2.ajouter_paire_noeud(&seed)?;
            for index_foyer in IndexFoyer::tous() {
                trousseau2.ajouter_trousseau_foyer(&seed, index_foyer)?;
            }

            prop_assert_eq!(
                trousseau1.sel.as_ref().unwrap(),
                trousseau2.sel.as_ref().unwrap()
            );

            prop_assert_eq!(
                trousseau1.donne_cle_privee_signature_noeud()?,
                trousseau2.donne_cle_privee_signature_noeud()?
            );

            for index_foyer in IndexFoyer::tous() {
                let trousseau_foyer1 = trousseau1.trousseaux_foyers[index_foyer.valeur()]
                    .as_ref()
                    .unwrap();
                let trousseau_foyer2 = trousseau2.trousseaux_foyers[index_foyer.valeur()]
                    .as_ref()
                    .unwrap();

                prop_assert_eq!(trousseau_foyer1.braise, trousseau_foyer2.braise);
                prop_assert_eq!(
                    trousseau_foyer1.donne_cle_privee_signature(),
                    trousseau_foyer2.donne_cle_privee_signature()
                );
                prop_assert_eq!(
                    trousseau_foyer1.donne_cle_privee_chiffrement(),
                    trousseau_foyer2.donne_cle_privee_chiffrement()
                );
                prop_assert_eq!(
                    trousseau_foyer1.donne_cle_chiffrement().expose_secret(),
                    trousseau_foyer2.donne_cle_chiffrement().expose_secret(),
                );

                for index_classeur in IndexClasseur::tous() {
                    let cle1 = trousseau_foyer1.cles_chiffrement_classeurs[index_classeur.valeur()]
                        .as_ref()
                        .unwrap();
                    let cle2 = trousseau_foyer2.cles_chiffrement_classeurs[index_classeur.valeur()]
                        .as_ref()
                        .unwrap();

                    prop_assert_eq!(cle1.expose_secret(), cle2.expose_secret());
                }
            }

        }

        /// Vérifie que deux seeds distinctes ne partagent aucun élément dérivé.
        ///
        /// Sel, clés du nœud, clés et braises de chaque foyer : rien ne doit
        /// coïncider entre deux nœuds nés de seeds différentes.
        #[test]
        fn derivation_deterministe_seeds_differentes(
            octets1 in any::<[u8; 64]>(),
            octets2 in any::<[u8; 64]>(),
            )  {
            let seed1 = SecretBox::new(Box::new(octets1));
            let seed2 = SecretBox::new(Box::new(octets2));

            // Contrepartie du test précédent : une dérivation qui ignorerait la seed
            // serait parfaitement « déterministe », mais rendrait le même matériau
            // pour tous les nœuds. Seules deux seeds distinctes attrapent ce cas.
            prop_assume!(octets1 != octets2);

            // Génération trousseau 1
            let mut trousseau1 = Trousseau::new();
            trousseau1.genere_sel(&seed1)?;
            trousseau1.ajouter_paire_noeud(&seed1)?;
            for index_foyer in IndexFoyer::tous() {
                trousseau1.ajouter_trousseau_foyer(&seed1, index_foyer)?;
            }

            // Génération trousseau 2
            let mut trousseau2 = Trousseau::new();
            trousseau2.genere_sel(&seed2)?;
            trousseau2.ajouter_paire_noeud(&seed2)?;
            for index_foyer in IndexFoyer::tous() {
                trousseau2.ajouter_trousseau_foyer(&seed2, index_foyer)?;
            }

            prop_assert_ne!(
                trousseau1.sel.as_ref().unwrap(),
                trousseau2.sel.as_ref().unwrap()
            );

            prop_assert_ne!(
                trousseau1.donne_cle_privee_signature_noeud()?,
                trousseau2.donne_cle_privee_signature_noeud()?
            );

            for index_foyer in IndexFoyer::tous() {
                let trousseau_foyer1 = trousseau1.trousseaux_foyers[index_foyer.valeur()]
                    .as_ref()
                    .unwrap();
                let trousseau_foyer2 = trousseau2.trousseaux_foyers[index_foyer.valeur()]
                    .as_ref()
                    .unwrap();

                prop_assert_ne!(trousseau_foyer1.braise, trousseau_foyer2.braise);
                prop_assert_ne!(
                    trousseau_foyer1.donne_cle_privee_signature(),
                    trousseau_foyer2.donne_cle_privee_signature()
                );
                prop_assert_ne!(
                    trousseau_foyer1.donne_cle_privee_chiffrement(),
                    trousseau_foyer2.donne_cle_privee_chiffrement()
                );
                prop_assert_ne!(
                    trousseau_foyer1.donne_cle_chiffrement().expose_secret(),
                    trousseau_foyer2.donne_cle_chiffrement().expose_secret(),
                );

                for index_classeur in IndexClasseur::tous() {
                    let cle1 = trousseau_foyer1.cles_chiffrement_classeurs[index_classeur.valeur()]
                        .as_ref()
                        .unwrap();
                    let cle2 = trousseau_foyer2.cles_chiffrement_classeurs[index_classeur.valeur()]
                        .as_ref()
                        .unwrap();

                    prop_assert_ne!(cle1.expose_secret(), cle2.expose_secret());
                }
            }

        }
    }

    /// Vérifie que le protocole de dérivation rend aujourd'hui ce qu'il rendait
    /// hier, de la phrase mnémonique aux clés de classeur.
    ///
    /// Les tests de déterminisme qui précèdent comparent le code à lui-même : ils
    /// resteraient verts si une montée de version changeait la dérivation. Seules des
    /// valeurs gravées attrapent ce cas, et chaque assertion nomme son sujet — un
    /// rouge dit lequel des maillons a bougé.
    ///
    /// Seed, sel, clés brutes et braises ont été recalculées par une implémentation
    /// indépendante ; les clés publiques et la signature, faute de seconde
    /// implémentation, gravent l'état actuel. Le test détecte un changement, il ne
    /// prouve pas une justesse.
    #[test]
    fn derivation_vecteurs_figes() -> ResultFeuNoyau<()> {
        /// Phrase mnémonique BIP39 française du vecteur — 24 mots tirés au hasard une
        /// fois pour toutes, et qui ne protègent aucun nœud réel. Sa valeur n'a
        /// aucune importance, sa fixité en a toute.
        const PHRASE_SEED_VECTEUR: &str = concat!(
            "succès émeraude inspirer hygiène cadeau débrider dragon aspect ",
            "biopsie torse dégivrer calvaire verdure infini épitaphe survie ",
            "jovial peluche bolide astuce écharpe esquiver gentil venimeux"
        );

        /// Seed brute attendue pour [`PHRASE_SEED_VECTEUR`] — 64 octets en
        /// hexadécimal, recalculés par PBKDF2-HMAC-SHA512 hors du code éprouvé.
        const SEED_BRUTE_VECTEUR: &str = concat!(
            "6a540ec41828b126bc6fb42c25e95cfd1cd1bdf26fa62b95ebcdb10c2032f012",
            "d19ae06e96575b4801eba4b0b77dde4431b5d893ec2097caafd4b5676ed118c9"
        );

        /// Sel Argon2id attendu — label `feu/noeud/sel`, 16 octets.
        const SEL_VECTEUR: &str = "03daad2ae70d874b4c7882368c829ff4";

        /// Mot de passe que le vecteur donne à Argon2id.
        const MOT_DE_PASSE_VECTEUR: &str = "mot de passe du vecteur";

        /// Clé éphémère attendue pour [`MOT_DE_PASSE_VECTEUR`] et [`SEL_VECTEUR`].
        ///
        /// `derive_cle_ephemere` appelle `Argon2::default()` : ses paramètres
        /// appartiennent à la crate, et les voir changer rendrait tout trousseau
        /// existant indéchiffrable. Cette valeur est ce qui le verrait.
        const CLE_EPHEMERE_VECTEUR: &str =
            "16decdd2c3348f323d23ff1a22877bd004390688a7dd18a102586f4d2f7c55a6";

        /// Seed ML-DSA-87 du nœud — label `feu/noeud/signature`.
        const CLE_SIGNATURE_NOEUD_VECTEUR: &str =
            "e7e295c7c23f499688bde64fb45236424aa569f22512b11492ffd8cbdebc0dc2";

        /// SHA3-256 de la clé publique de signature du nœud, encodée sur 2592 octets.
        const HASH_CLE_PUBLIQUE_NOEUD_VECTEUR: &str =
            "49ddfd12fe5e19cdbe49a81b882ae0ebb3b111a76a77e65db70e28897a925a97";

        /// Message que le vecteur fait signer au nœud.
        const MESSAGE_SIGNE_VECTEUR: &[u8] = b"vecteur de test Feu";

        /// SHA3-256 de la signature du nœud sur [`MESSAGE_SIGNE_VECTEUR`].
        ///
        /// `sign` passe par `raw_sign_deterministic` : sans aléa, la signature est
        /// comparable, et elle engage clé privée, algorithme et encodage à la fois.
        const HASH_SIGNATURE_NOEUD_VECTEUR: &str =
            "db6102830a7e451d8849e9cb1e0a3aa04369631a5473f9c6a899f9731ddb18c6";

        /// Seeds ML-DSA-87 des foyers — labels `feu/foyer/signature/1..3`.
        const CLES_SIGNATURE_FOYERS_VECTEUR: [&str; IndexFoyer::NOMBRE] = [
            "1e9a62c1c7185690f285c420dfccd10250ed743c451ae619a5b12baaf1446e59",
            "d45ac63421aed2bd1136c265e5eb439f6adb19c03df8507c56f8e38ab7a6a256",
            "c0643a11f8f6d382fe62e85dbd078a556aa0b883c49572d2b74281c857483bb9",
        ];

        /// SHA3-256 des clés publiques de signature des foyers.
        const HASHS_CLES_PUBLIQUES_SIGNATURE_FOYERS_VECTEUR: [&str; IndexFoyer::NOMBRE] = [
            "7089469031dd753055cf68aac32f66e0e8addb79860ce5fc02596a8b9a175d04",
            "8bc7a8c4b6d00ce0d58e5a016121a38c722b44ff756328794fcdd8e781e46753",
            "1a51d8fbdae3cf83d347e3e1d7a5828dd7bdf4bdb7b45d7bfa1ebab4ff631ccf",
        ];

        /// Clés AES-256 des foyers — labels `feu/foyer/symetrique/1..3`.
        const CLES_SYMETRIQUES_FOYERS_VECTEUR: [&str; IndexFoyer::NOMBRE] = [
            "4f2bb9cfc5faa67b2e564d51531cce437bf6835d2a07b8ba8893f26c13c05173",
            "8e96aaf3edee3df32d8ea4bbf16ec1c7e00695109e535ec481ab3b313719e493",
            "c3e64e502198fc3004541f72f866349d2846e1983fa9969a8f8ec65e2446f597",
        ];

        /// Seeds ML-KEM-1024 des foyers — labels `feu/foyer/chiffrement/1..3`,
        /// 64 octets chacune.
        const SEEDS_CHIFFREMENT_FOYERS_VECTEUR: [&str; IndexFoyer::NOMBRE] = [
            concat!(
                "9fe64e6f6a85fa9a0b5e3bbc8066342f213316175016e042e9bc1b0dbdd7846b",
                "c39fa38b966b2d58c52d650ddbec460ab919e26ff6ceba352d154d926b3b7039"
            ),
            concat!(
                "35264ce79ec66dfca6efc5ef15df256f3843cfeb01714762b825d14d09a65483",
                "f94ed98bffad4c652aff76fe0387d3ddbc1b54205d5fc8176e622b2649b9e3a6"
            ),
            concat!(
                "48cb066803dc114a472c6e4ab29dd6b7b28aa55ce9e6e10b729d1572a62ce5df",
                "2da0ad74f640da9e30d907a403303c1587453724f45d659d96ef0b533c6b8e02"
            ),
        ];

        /// SHA3-256 des clés publiques de chiffrement des foyers, encodées sur
        /// 1568 octets.
        const HASHS_CLES_PUBLIQUES_CHIFFREMENT_FOYERS_VECTEUR: [&str; IndexFoyer::NOMBRE] = [
            "40e0eab7f46f15f3e2da1d3cacfd02591d8badffe9217a1829fb0a7898a05601",
            "613a421b98be177ad291864b749dcaa55ea10ad8532af8b0efa06f7350b54378",
            "15cd3617654a5b37ca958b9b0d58c6f85b5232fc2a7bc12825199ac7e1e7eb65",
        ];

        /// Braises des foyers — labels `feu/foyer/braise/1..3`, checksum et encodage
        /// base32 compris.
        const BRAISES_VECTEUR: [&str; IndexFoyer::NOMBRE] = [
            "5eggx5ircwbgrhxi5yecmi7n56m7dejewhiwhsbb6rcbygz6i5xa7ty.braise",
            "txlajgxgjn3pfiatjexui4xobipfv5apba33xkgzkucbvm4vwbgoy2i.braise",
            "dfb5mtd64bs37t4ero4mjv4yggyvo2ywxhh7koz3s7daov6jybbatea.braise",
        ];

        /// Clés AES-256 des classeurs — labels `feu/classeur/symetrique/f/c`,
        /// rangées par foyer puis par classeur.
        const CLES_CLASSEURS_VECTEUR: [[&str; IndexClasseur::NOMBRE]; IndexFoyer::NOMBRE] = [
            [
                "3dd07ff225358c48b34c5da0e7a17c8ed0e95a47624c3d91948624b1ad53a9b7",
                "6f5bf8cdf23cc39be82cd59fe7483905434ebe82d3f729594d40801594fa3e40",
                "0aaba555ed6f1c53622e99d17410b7012eaf82d54d386bfe31ab4384363579e8",
                "841f19efcecde7e40d4ccf76d8fd72d99e60202195ed8fccbca7209ddfcb6ba0",
                "6fc288baec3f5feea425e0d1d522ff15797be16f176f4217e4e7d575467747c0",
            ],
            [
                "5d59bd4532bc5671c5a03e001207b4d08ed42845fbd527f3753f8f0b3b2fddba",
                "0c37cc462a4f6850cbbf1a632023c924d29fe659760db35a693958702002dc23",
                "ae58011d052f27a5cdb69d1e7ebf5aceac375ac7ea60345c8414194bc458d597",
                "1d86b316bf0aa0247fb907a8afbffd51c9b7700f239cd51deca54238181deddc",
                "db4285516df54bcc3f4fc74682d7e50d2cf2f06cc5c9e1cbcc8fc9de8ce80a32",
            ],
            [
                "19cef49a1cbcc13811ee9315d314da5c665d3f2429c0c8d71a5c4dc7e877bf49",
                "c6737f1bf1a929e9d688b8b861d936bfdeaa4d28b0d36bdf7d5965b8e122ab3f",
                "754c63ecbe3f96b33da3fd537f28d0d4c1c38a756e50004224f8d38f1f08c92f",
                "1639c3c4785efa5a8177e9b4357920fc389a86d98830746aa288dd706609ed78",
                "5ace1c0eb345686421759d358ab833dfc701890185d8204e1107ecee3fcf3ec3",
            ],
        ];

        let seed = Cryptographe::genere_seed_brute(SecretString::from(PHRASE_SEED_VECTEUR))?;

        assert_eq!(HEXLOWER.encode(seed.expose_secret()), SEED_BRUTE_VECTEUR);

        // Génération trousseau
        let mut trousseau = Trousseau::new();
        trousseau.genere_sel(&seed)?;
        trousseau.ajouter_paire_noeud(&seed)?;
        for index_foyer in IndexFoyer::tous() {
            trousseau.ajouter_trousseau_foyer(&seed, index_foyer)?;
        }

        assert_eq!(HEXLOWER.encode(&trousseau.sel.unwrap()), SEL_VECTEUR);

        // La clé éphémère prolonge la chaîne du vecteur : elle naît du sel qu'on
        // vient de vérifier, et d'un mot de passe figé.
        trousseau.definit_mdp(SecretString::from(MOT_DE_PASSE_VECTEUR));
        trousseau.derive_cle_ephemere()?;

        assert_eq!(
            HEXLOWER.encode(trousseau.cle_ephemere.as_ref().unwrap().expose_secret()),
            CLE_EPHEMERE_VECTEUR
        );

        let paire_noeud = trousseau.paire_signature_noeud.as_ref().unwrap();

        assert_eq!(
            HEXLOWER.encode(&<[u8; 32]>::from(paire_noeud.privee.to_seed())),
            CLE_SIGNATURE_NOEUD_VECTEUR
        );

        assert_eq!(
            HEXLOWER.encode(&Sha3_256::digest(paire_noeud.publique.encode())),
            HASH_CLE_PUBLIQUE_NOEUD_VECTEUR
        );

        assert_eq!(
            HEXLOWER.encode(&Sha3_256::digest(
                trousseau.signe_avec_cle_noeud(MESSAGE_SIGNE_VECTEUR)?
            )),
            HASH_SIGNATURE_NOEUD_VECTEUR
        );

        for index_foyer in IndexFoyer::tous() {
            let foyer = index_foyer.valeur();
            let trousseau_foyer = trousseau.trousseaux_foyers[foyer].as_ref().unwrap();

            assert_eq!(
                trousseau_foyer.braise.to_string(),
                BRAISES_VECTEUR[foyer],
                "braise du foyer {foyer}"
            );

            assert_eq!(
                HEXLOWER.encode(&<[u8; 32]>::from(
                    trousseau_foyer.paire_signature.privee.to_seed()
                )),
                CLES_SIGNATURE_FOYERS_VECTEUR[foyer],
                "seed de signature du foyer {foyer}"
            );

            assert_eq!(
                HEXLOWER.encode(&Sha3_256::digest(
                    trousseau_foyer.paire_signature.publique.encode()
                )),
                HASHS_CLES_PUBLIQUES_SIGNATURE_FOYERS_VECTEUR[foyer],
                "clé publique de signature du foyer {foyer}"
            );

            assert_eq!(
                HEXLOWER.encode(trousseau_foyer.donne_cle_chiffrement().expose_secret()),
                CLES_SYMETRIQUES_FOYERS_VECTEUR[foyer],
                "clé symétrique du foyer {foyer}"
            );

            assert_eq!(
                HEXLOWER.encode(
                    trousseau_foyer
                        .paire_chiffrement
                        .privee
                        .to_seed()
                        .unwrap()
                        .as_ref()
                ),
                SEEDS_CHIFFREMENT_FOYERS_VECTEUR[foyer],
                "seed de chiffrement du foyer {foyer}"
            );

            assert_eq!(
                HEXLOWER.encode(&Sha3_256::digest(
                    trousseau_foyer.paire_chiffrement.publique.to_bytes()
                )),
                HASHS_CLES_PUBLIQUES_CHIFFREMENT_FOYERS_VECTEUR[foyer],
                "clé publique de chiffrement du foyer {foyer}"
            );

            for index_classeur in IndexClasseur::tous() {
                let classeur = index_classeur.valeur();

                assert_eq!(
                    HEXLOWER.encode(
                        trousseau_foyer.cles_chiffrement_classeurs[classeur]
                            .as_ref()
                            .unwrap()
                            .expose_secret()
                    ),
                    CLES_CLASSEURS_VECTEUR[foyer][classeur],
                    "clé du classeur {classeur} du foyer {foyer}"
                );
            }
        }

        Ok(())
    }

    /// Vérifie que le format du chiffrement symétrique n'a pas bougé.
    ///
    /// Le vecteur ne va que dans un sens : `chiffrement_generique_avec_cle` tire son
    /// nonce d'`OsRng`, seul un tampon gravé peut donc figer quelque chose. Avec le
    /// cycle qui l'accompagne, les deux sens sont tenus — un découpage modifié
    /// laisserait le cycle vert, mais rendrait ce tampon illisible.
    ///
    /// Il gèle la place et la taille du nonce, l'ordre `nonce || ciphertext || tag`
    /// et AES-256-GCM. Les flux de foyer, eux, demanderaient des kilo-octets en dur.
    #[test]
    fn dechiffrement_vecteur_fige() -> ResultFeuNoyau<()> {
        /// Clé AES-256 du vecteur, tirée au hasard une fois pour toutes.
        const CLE_VECTEUR: &str =
            "e76dbae9fcc0012ee611523f792cd0d9fb343a0dba01673324d629cea2c19766";

        /// Tampon tel que le rend `chiffrement_generique_avec_cle` : nonce de
        /// 12 octets, ciphertext de la longueur du clair, auth tag de 16 octets.
        const TAMPON_VECTEUR: &str = concat!(
            "d976de7ce456feeed03c1463e829a19af800f514a4aad42cd2d8f7de53deda",
            "cda736fa97f1516ec10e07eb"
        );

        /// Clair attendu au bout du déchiffrement.
        const CLAIR_VECTEUR: &[u8] = b"contenu de test";

        let cle: [u8; 32] = HEXLOWER
            .decode(CLE_VECTEUR.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();

        let tampon = HEXLOWER.decode(TAMPON_VECTEUR.as_bytes()).unwrap();

        assert_eq!(
            Trousseau::dechiffrement_generique_avec_cle(&cle, &tampon)?,
            CLAIR_VECTEUR
        );

        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        /// Vérifie le cycle chiffrement/déchiffrement AES-256-GCM.
        ///
        /// `chiffrement_generique_avec_cle` est le point de passage unique de tout
        /// le chiffrement symétrique du trousseau : `chiffre_cle`, `chiffre_seed` et
        /// `chiffre_blob` y délèguent, en ne changeant que la clé fournie et le type
        /// de sortie. Le tester une fois les couvre tous les trois.
        ///
        /// Clé et contenu sont tirés sur tout leur domaine, contenu vide compris —
        /// AES-GCM n'y produit que l'auth tag, sans un octet de texte chiffré.
        #[test]
        fn cycle_chiffrement_dechiffrement_generique(
                cle in any::<[u8; 32]>(),
                contenu in any::<Vec<u8>>(),

            ) {

            let chiffre1 = Trousseau::chiffrement_generique_avec_cle(&cle, &contenu)?;
            let chiffre2 = Trousseau::chiffrement_generique_avec_cle(&cle, &contenu)?;

            let dechiffre1 = Trousseau::dechiffrement_generique_avec_cle(&cle, &chiffre1)?;
            let dechiffre2 = Trousseau::dechiffrement_generique_avec_cle(&cle, &chiffre2)?;

            // Le nonce est tiré d'`OsRng` à chaque appel : deux chiffrements du même
            // contenu ne peuvent pas coïncider. Un nonce figé briserait AES-GCM.
            prop_assert_ne!(chiffre1, chiffre2);
            prop_assert_eq!(&dechiffre1, &dechiffre2);
            prop_assert_eq!(dechiffre1, contenu);

        }

        /// Vérifie le cycle chiffrement/déchiffrement du flux AES-256-GCM.
        ///
        /// C'est la couche qui chiffre l'archive `.feu` d'un foyer, la seule à
        /// travailler par tranches : un foyer n'a pas de taille bornée. Le domaine
        /// dépasse [`CHUNK_SIZE`] à dessein — en deçà, tout tient dans le premier
        /// tampon et le look-ahead qui reconnaît le dernier chunk n'est jamais
        /// parcouru. Le contenu est une suite d'octets quelconques, ce qui passe ici
        /// étant une archive `tar`.
        #[test]
        fn cycle_chiffrement_dechiffrement_flux(
                cle in any::<[u8; 32]>(),
                contenu in proptest::collection::vec(any::<u8>(), 0..9000),
            ) {

            let mut source = &contenu[..];
            let mut contenu_chiffre = Vec::new();
            Trousseau::chiffre_avec_cle(&cle, &mut source, &mut contenu_chiffre)?;

            let mut source = &contenu_chiffre[..];
            let mut sortie = Vec::new();
            Trousseau::dechiffre_avec_cle(&cle, &mut source, &mut sortie)?;

            prop_assert_eq!(sortie, contenu);
        }

        /// Vérifie qu'un mot de passe incorrect fait échouer le déchiffrement.
        ///
        /// C'est le mécanisme réel de vérification du mot de passe Feu : aucun mot
        /// de passe n'est stocké, ni en clair ni en hash. La clé éphémère est
        /// dérivée par Argon2id du mot de passe et du sel — un mot de passe erroné
        /// donne une clé différente, et AES-GCM rejette l'auth tag.
        ///
        /// Sel, mots de passe et clé sont tirés sur leur domaine ; `prop_assume`
        /// écarte le seul cas sans rejet légitime, deux mots de passe identiques.
        /// Chaque cas coûtant deux passes Argon2id de 19 Mio, leur nombre reste bas.
        #[test]
        fn mauvais_mot_de_passe(
            sel in any::<[u8; 16]>(),
            mdp in "[a-z0-9/]{0,30}",
            mauvais_mdp in "[a-z0-9/]{0,30}",
            cle in any::<[u8; 32]>(),
        ) {

            prop_assume!(mdp != mauvais_mdp);

            let mut trousseau = Trousseau::new();
            trousseau.definit_sel(sel);
            trousseau.definit_mdp(SecretString::from(mdp));
            trousseau.derive_cle_ephemere()?;

            let cle_chiffree = trousseau.chiffre_cle(&cle)?;

            // Témoin : établit que le déchiffrement fonctionne avec le bon mot de
            // passe. Sans lui, l'échec attendu plus bas pourrait venir d'un
            // chiffrement raté plutôt que du changement de mot de passe.
            let cle_dechiffree = trousseau.dechiffre_cle(&cle_chiffree)?;

            prop_assert_eq!(&cle, cle_dechiffree.expose_secret());

            // Le sel reste inchangé : seul le mot de passe varie, donc seule la clé
            // éphémère change.
            trousseau.definit_mdp(SecretString::from(mauvais_mdp));
            trousseau.derive_cle_ephemere()?;

            prop_assert!(trousseau.dechiffre_cle(&cle_chiffree).is_err());

        }
    }
}
