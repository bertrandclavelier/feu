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
//! `paire_signature_noeud` sont à `None`, `cles_foyers` est un `HashMap`
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
//! - `mdp` — mot de passe dans `Option<SecretBox<String>>` (pas de newtype)
//! - `sel` — sel Argon2id dans `Option<[u8; 16]>` (pas secret — dérivé de manière déterministe
//!   depuis la clé privée du nœud, re-dérivable depuis la seed en cas de perte du disque)
//! - `cle_ephemere` — clé AES-256-GCM dérivée du mot de passe via Argon2id,
//!   dans `Option<SecretBox<[u8; 32]>>` — présente uniquement le temps du
//!   chiffrement des clés, effacée dès que le trousseau persistable est constitué.

use super::erreur::ErreurCryptographe;
use super::erreur::ResultCryptographe;
use super::trousseau_public::{TrousseauFoyerPublic, TrousseauPublic};
use aead::stream::EncryptorBE32;
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
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use x25519_dalek::{PublicKey, StaticSecret};

const CHAINE_A_SIGNER_POUR_SEL: &str = "feu-noeud-sel";
const CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE: &str = "feu-foyer-symetrique";
const CHAINE_A_SIGNER_POUR_PAIRE_SIGNATURE: &str = "feu-foyer-paire-signature";
const CHAINE_A_SIGNER_POUR_PAIRE_CHIFFREMENT: &str = "feu-foyer-paire-chiffrement";
const CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE_CLASSEUR: &str = "feu-foyer-classeur";

struct CleSymetrique(SecretBox<[u8; 32]>);

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
    fn derive_adresse_onion(&self) -> String {
        // 1. Buffer checksum (48 octets)
        let mut buf = Vec::new();
        buf.extend_from_slice(b".onion checksum");
        buf.extend_from_slice(self.paire_signature.publique.as_bytes());
        buf.push(0x03);

        // 2. Checksum (2 octets)
        let hash = Sha3_256::digest(&buf);
        let checksum = &hash[..2];

        // 3. Buffer final (35 octets)
        let mut data = Vec::new();
        data.extend_from_slice(self.paire_signature.publique.as_bytes());
        data.extend_from_slice(checksum);
        data.push(0x03);

        // 4. Encodage
        format!("{}.onion", BASE32.encode(&data).to_lowercase())
    }
}

pub(super) struct Trousseau {
    mdp: Option<SecretBox<String>>,
    cle_ephemere: Option<SecretBox<[u8; 32]>>,
    sel: Option<[u8; 16]>,
    paire_signature_noeud: Option<PaireClesSignature>,
    cles_foyers: HashMap<String, TrousseauFoyer>,
}

//
// Constructeur et initialisation du trousseau
//
impl Trousseau {
    /// Crée un trousseau vide.
    pub(super) fn new() -> Self {
        Self {
            mdp: None,
            cle_ephemere: None,
            sel: None,
            paire_signature_noeud: None,
            cles_foyers: HashMap::new(),
        }
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

    /// Dérive la clé éphémère AES-256-GCM depuis le mot de passe et le sel du trousseau.
    ///
    /// Utilise Argon2id (RFC 9106) avec les paramètres par défaut pour produire
    /// 32 octets de matière clé à partir du mot de passe et du sel. La clé
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
    /// une clé mère (`m/index_foyer'`), puis en tire par signature + HKDF-SHA3-256 :
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

            // Clé mère du foyer — sert à dériver toutes les sous-clés du foyer
            cle_privee = SigningKey::from_bytes(&cle_brute.expose_secret());
        }

        // Clé symétrique de chiffrement du foyer
        let cle_chiffrement = CleSymetrique(Trousseau::genere_cle_brute_from_signature(
            &cle_privee,
            CHAINE_A_SIGNER_POUR_CHIFFREMENT_SYMETRIQUE,
        )?);

        let cle_sign_priv: SigningKey;

        // Bloc encadrant la portée de cle_brute
        {
            // Création de la paire de clés signature du foyer
            let cle_brute = Trousseau::genere_cle_brute_from_signature(
                &cle_privee,
                CHAINE_A_SIGNER_POUR_PAIRE_SIGNATURE,
            )?;

            cle_sign_priv = SigningKey::from_bytes(&cle_brute.expose_secret());
        }

        let cle_publique = cle_sign_priv.verifying_key();

        let paire_signature = PaireClesSignature {
            privee: cle_sign_priv,
            publique: cle_publique,
        };

        let cle_chif_priv: SecretBox<StaticSecret>;

        // Bloc encadrant la portée de cle_brute
        {
            // Création de la paire de clés chiffrement du foyer
            let cle_brute = Trousseau::genere_cle_brute_from_signature(
                &cle_privee,
                CHAINE_A_SIGNER_POUR_PAIRE_CHIFFREMENT,
            )?;
            cle_chif_priv =
                SecretBox::new(Box::new(StaticSecret::from(*cle_brute.expose_secret())));
        }

        let cle_publique = PublicKey::from(cle_chif_priv.expose_secret());

        let paire_chiffrement = PaireClesChiffrement {
            privee: cle_chif_priv,
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

        // enregistrement de toutes les clés dans un TrousseauFoyer
        let trousseau_foyer = TrousseauFoyer {
            cle_chiffrement,
            paire_signature,
            paire_chiffrement,
            cles_chiffrement_classeurs,
        };

        // Ajout du TrousseauFoyer dans le trousseau
        self.cles_foyers
            .insert(trousseau_foyer.derive_adresse_onion(), trousseau_foyer);

        Ok(())
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
}

//
// Gestion mot de passe, clé éphémère et chiffrement
//
impl Trousseau {
    /// Efface le mot de passe du trousseau.
    ///
    /// Met `mdp` à `None` — la destruction du [`SecretBox<String>`] déclenche
    /// la zéroïsation automatique de la mémoire.
    pub(super) fn efface_mdp(&mut self) {
        self.mdp = None;
    }

    /// Définit le mot de passe du trousseau.
    ///
    /// `mot` est un [`SecretBox<String>`] déjà construit par l'appelant —
    /// la méthode se contente de le stocker. Tout mot de passe précédemment
    /// défini est remplacé et zéroïsé au drop.
    pub(super) fn definit_mdp(&mut self, mot: SecretBox<String>) {
        self.mdp = Some(mot);
    }

    /// Efface la clé éphémère du trousseau.
    ///
    /// Met `cle_ephemere` à `None` — la destruction du [`SecretBox<[u8; 32]>`] déclenche
    /// la zéroïsation automatique de la mémoire.
    pub(super) fn efface_cle_ephemere(&mut self) {
        self.cle_ephemere = None;
    }

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
            Some(valeur) => {
                // Conversion de la clé éphémère brute en Key<Aes256Gcm>
                let key = Key::<Aes256Gcm>::from_slice(valeur.expose_secret());

                // Création du cipher à partir de key
                let cipher = Aes256Gcm::new(key);

                // Génération aléatoire du nonce de 12 octets
                let mut nonce = [0u8; 12];
                OsRng.fill_bytes(&mut nonce);

                // Chiffrement de la clé
                let cle_chiffree = cipher.encrypt(Nonce::from_slice(&nonce), cle.as_ref())?;

                // Création du résultat
                let mut resultat = [0u8; 60];
                resultat[0..12].copy_from_slice(&nonce);
                resultat[12..60].copy_from_slice(&cle_chiffree);

                Ok(resultat)
            }
        }
    }
}

//
// Génération du trousseau public
//
impl TrousseauFoyer {
    /// Chiffre toutes les clés du foyer et produit le [`TrousseauFoyerPublic`] persistable.
    ///
    /// Délègue le chiffrement AES-256-GCM de chaque clé à [`Trousseau::chiffre_cle`].
    /// Les clés publiques sont copiées en clair.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le chiffrement d'une clé échoue — clé éphémère
    /// absente du trousseau ou échec AES-256-GCM.
    fn genere_trousseau_foyer_public(
        &self,
        trousseau: &Trousseau,
    ) -> ResultCryptographe<TrousseauFoyerPublic> {
        let mut trousseau_foyer_public = TrousseauFoyerPublic::new(
            trousseau.chiffre_cle(self.cle_chiffrement.0.expose_secret())?,
            trousseau.chiffre_cle(self.paire_signature.privee.as_bytes())?,
            self.paire_signature.publique.to_bytes(),
            trousseau.chiffre_cle(self.paire_chiffrement.privee.expose_secret().as_bytes())?,
            self.paire_chiffrement.publique.to_bytes(),
        );

        for e in &self.cles_chiffrement_classeurs {
            trousseau_foyer_public
                .ajoute_cle_chiffrement_classeur(trousseau.chiffre_cle(e.0.expose_secret())?);
        }

        Ok(trousseau_foyer_public)
    }
}

impl Trousseau {
    /// Chiffre l'ensemble des secrets du trousseau et produit le [`TrousseauPublic`] persistable.
    ///
    /// Chiffre les clés du nœud puis délègue le chiffrement de chaque foyer à
    /// [`TrousseauFoyer::genere_trousseau_foyer_public`]. Le sel est inclus en clair
    /// dans le résultat pour faciliter le déchiffrement en usage courant — il est
    /// re-dérivable depuis la seed en cas de perte du disque.
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
    pub(super) fn genere_trousseau_public(&self) -> ResultCryptographe<TrousseauPublic> {
        match (self.sel, &self.paire_signature_noeud) {
            (Some(valeur1), Some(valeur2)) => {
                let mut trousseau_public = TrousseauPublic::new(
                    valeur1,
                    self.chiffre_cle(valeur2.privee.as_bytes())?,
                    *valeur2.publique.as_bytes(),
                );

                for (_, foyer) in &self.cles_foyers {
                    trousseau_public.ajoute_trousseau_foyer_public(
                        foyer.derive_adresse_onion(),
                        foyer.genere_trousseau_foyer_public(&self)?,
                    );
                }

                Ok(trousseau_public)
            }
            (_, _) => Err(ErreurCryptographe::Interne(String::from(
                "Problème génération du trousseau public.",
            ))),
        }
    }
}

/*
// Partie StreamEncryptor
impl Trousseau {

    pub(super) fn cree_stream_encryptor(&self, onion, &str, fichier: File) -> ResultCryptographe<ChiffreurStream> {

// Génération du nonce aléatoire
        let mut none = [0u8; 7];
        OsRng.fill_bytes(&mut none);

        // Écriture du nonce en tête du fichier
        fichier.write_all(&none)?;

        // Création du StreamEncryptor
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        Ok(())

    }
}
*/
