// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Le cryptographe est le gardien de la sécurité cryptographique de FeuNoyau.
//!
//! Il est l'unique composant autorisé à manipuler des données en clair —
//! toute opération de chiffrement, de déchiffrement ou de dérivation de
//! clés passe exclusivement par lui.
//!
//! Il a en charge la génération des seeds BIP39, la dérivation HKDF-SHA3-256
//! des clés nœud et foyer depuis la seed, ainsi que la génération des clés
//! symétrique, de signature (Ed25519) et de chiffrement (ML-KEM-768) par foyer.
//! Il maintient en mémoire le trousseau — l'unique endroit où les clés
//! privées et la clé symétrique existent en clair.
//!
//! # Cycle de vie des secrets
//!
//! Les données sensibles transitant dans ce module (`Mnemonic`, `phrase_seed`)
//! sont encapsulées dans [`SecretBox`] / [`SecretString`] dès leur création. L'accès au contenu
//! est explicitement contraint à [`expose_secret()`], rendant toute
//! manipulation visible à la lecture du code.
//!
//! Des blocs de scope `{ }` limitent la durée de vie de chaque secret au
//! strict nécessaire — la destruction du [`SecretBox`] ou de la [`SecretString`]
//! déclenche la zéroïsation automatique de la mémoire.
//!
//! Rien n'est écrit sur le disque depuis ce module — c'est le rôle du
//! gardien.
//!
//! # Invariant de sécurité
//!
//! Aucun autre composant de FeuNoyau n'accède directement aux clés ou aux
//! données en clair. Cette centralisation est un invariant fondamental
//! du protocole.

pub(super) mod erreur;
mod trousseau;
pub(crate) mod trousseaux_publics;

use bip39::{Language, Mnemonic};
use data_encoding::HEXLOWER;
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use ml_kem::Encapsulate;
use ml_kem::EncapsulationKey768;
use ml_kem::ml_kem_768::Ciphertext as Ciphertext768;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use sha3::{Digest, Sha3_256};
use std::io::{Read, Write};

use crate::InterfaceFeuNoyau;
use crate::MAX_FOYERS;
use crate::cryptographe::erreur::{ErreurCryptographe, ResultCryptographe};
use crate::cryptographe::trousseau::Trousseau;
use crate::cryptographe::trousseaux_publics::{
    TrousseauPublicComplet, TrousseauPublicFoyer, TrousseauPublicNoeud,
};

const NOMBRE_MOTS_SEED: usize = 12;
const INFO_HKDF_CHIFFREMENT_ASYMETRIQUE: &str = "feu-chiffrement-asymetrique";

const ERR_CRY_001: &str = "CRY-001 > Données corrompues après déchiffrement";
const ERR_CRY_002: &str = "CRY-002 > Erreur déchiffrement";
const ERR_CRY_003: &str = "CRY-003 > Erreur définition mot de passe";
const ERR_CRY_004: &str = "CRY-004 > Problème enregistrement seed";

/// Gardien de la sécurité cryptographique du nœud.
///
/// Encapsule l'unique [`Trousseau`] qui contient les clés en clair. Toutes les
/// opérations de chiffrement, de déchiffrement, de dérivation et de signature
/// passent par ce composant — c'est l'unique frontière entre les secrets et le
/// reste du code.
pub(super) struct Cryptographe {
    /// Trousseau en mémoire — contient les clés en clair protégées par
    /// [`SecretBox`]/[`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop).
    trousseau: Trousseau,
}

impl Cryptographe {
    /// Crée le cryptographe de [`FeuNoyau`].
    pub(super) fn new() -> Self {
        Cryptographe {
            trousseau: Trousseau::new(),
        }
    }

    // ── Initialisation ───────────────────────────────────────────────────────

    /// Génère une nouvelle seed BIP39 et initialise le trousseau pour un nouveau nœud.
    ///
    /// Enchaîne les opérations suivantes :
    ///
    /// 1. Génère la seed mnémonique (12 mots, français) et la transmet à `interface`.
    /// 2. Demande confirmation que la seed a bien été notée — interrompt si refus.
    /// 3. Collecte et vérifie un nouveau mot de passe (deux saisies concordantes).
    /// 4. Dérive et enregistre dans le trousseau de manière déterministe les clés du nœud,
    ///    des foyers et le sel Argon2id via [`genere_trousseau_a_partir_seed`](Self::genere_trousseau_a_partir_seed).
    ///
    /// La seed est zéroïsée avant le retour. Rien n'est écrit sur le disque —
    /// c'est le rôle du gardien.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la génération du mnémonique BIP39 échoue, si la
    /// confirmation de la seed est refusée, si la saisie du mot de passe échoue,
    /// ou si la dérivation des clés d'un foyer échoue.
    pub(super) fn initialise_noeud_a_partir_nouvelle_seed(
        &mut self,
        interface: &mut impl InterfaceFeuNoyau,
    ) -> ResultCryptographe<()> {
        // Bloc encadrant la portée de phrase_seed
        {
            let phrase_seed: SecretString;

            // Bloc encadrant la portée de mnemonic
            {
                let mnemonic = SecretBox::new(Box::new(Mnemonic::generate_in(
                    Language::French,
                    NOMBRE_MOTS_SEED,
                )?));

                let mots: Vec<&str> = mnemonic.expose_secret().words().collect();
                interface.recevoir_seed(&mots);

                if !interface.confirmer_enregistrement_seed() {
                    return Err(ErreurCryptographe::Interne(String::from(ERR_CRY_004)));
                }
                phrase_seed = SecretString::from(mnemonic.expose_secret().to_string());
            }

            self.initialise_noeud_a_partir_seed_existante(interface, phrase_seed)?;
        }
        Ok(())
    }

    /// Initialise le trousseau pour un nœud vierge à partir d'une seed BIP39 fournie.
    ///
    /// Variante de [`initialise_noeud_a_partir_nouvelle_seed`](Self::initialise_noeud_a_partir_nouvelle_seed)
    /// pour le cas où la seed est déjà connue de l'appelant (restauration depuis seed existante).
    ///
    /// Enchaîne deux opérations séquentielles :
    ///
    /// 1. Collecte et vérifie le nouveau mot de passe (deux saisies concordantes).
    /// 2. Dérive et enregistre dans le trousseau les clés du nœud, des foyers et le sel Argon2id via
    ///    [`genere_trousseau_a_partir_seed`](Self::genere_trousseau_a_partir_seed).
    ///
    /// `phrase_seed` est consommée par la fonction — elle est zéroïsée à son retour.
    /// Rien n'est écrit sur le disque — c'est le rôle du gardien.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la saisie du mot de passe échoue, si le parsing de
    /// la phrase BIP39 échoue, si la dérivation des clés d'un foyer échoue, ou si
    /// la dérivation du sel échoue.
    pub(super) fn initialise_noeud_a_partir_seed_existante(
        &mut self,
        interface: &mut impl InterfaceFeuNoyau,
        phrase_seed: SecretString,
    ) -> ResultCryptographe<()> {
        self.initialisation_nouveau_mdp(interface)?;

        self.genere_trousseau_a_partir_seed(interface, phrase_seed)?;

        Ok(())
    }

    /// Dérive et enregistre dans le trousseau toutes les clés du nœud et des foyers.
    ///
    /// À partir de `phrase_seed`, parse la phrase mnémotechnique BIP39, puis dérive
    /// de manière déterministe et enregistre dans le trousseau :
    /// - la paire de clés de signature du nœud (`m/0'`)
    /// - les clés de signature, de chiffrement, symétriques et de classeurs de chaque
    ///   foyer (`m/1'` à `m/MAX_FOYERS'`)
    ///
    /// Si aucun mot de passe n'est présent dans le trousseau, en collecte un via
    /// `interface` (saisie unique, sans confirmation) — c'est le cas de
    /// [`demarrage_secours`](super::FeuNoyau::demarrage_secours). Si un mot de passe est déjà
    /// présent (positionné au préalable par l'appelant), la saisie est ignorée.
    ///
    /// Génère également le sel Argon2id de manière déterministe depuis la clé privée du nœud.
    ///
    /// `phrase_seed` est consommée par la fonction — elle est zéroïsée à son retour.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la collecte du mot de passe échoue, si le parsing de
    /// la phrase BIP39 échoue, si la dérivation des clés d'un foyer échoue, ou si
    /// la génération du sel échoue.
    pub(super) fn genere_trousseau_a_partir_seed(
        &mut self,
        interface: &mut impl InterfaceFeuNoyau,
        phrase_seed: SecretString,
    ) -> ResultCryptographe<()> {
        if !self.trousseau.mdp_existe() {
            self.demande_mdp(interface)?;
        }

        let mnemonic = Mnemonic::parse_in(Language::French, phrase_seed.expose_secret())?;
        let seed_bytes = SecretBox::new(Box::new(mnemonic.to_seed(""))); // passphrase vide

        // Ajoute la paire de clés du nœud au trousseau à partir de la seed

        self.trousseau.ajouter_paire_noeud(&seed_bytes)?;

        // Ajoute les trousseaux des MAX_FOYERS
        for i in 0..MAX_FOYERS {
            self.trousseau.ajouter_trousseau_foyer(&seed_bytes, i)?;
        }

        // Génère le sel et le met dans le trousseau
        self.trousseau.genere_sel()?;

        Ok(())
    }

    /// Déverrouille le trousseau à partir d'un [`TrousseauPublicNoeud`] existant.
    ///
    /// Enchaîne quatre opérations séquentielles :
    ///
    /// 1. Collecte le mot de passe Feu via l'interface.
    /// 2. Charge le sel depuis le [`TrousseauPublicNoeud`] fourni.
    /// 3. Dérive la clé éphémère AES-256-GCM via Argon2id(mot de passe, sel).
    /// 4. Tente de déchiffrer la clé privée de signature du nœud — un mot de passe
    ///    incorrect provoque un échec AES-GCM (auth tag invalide) qui est propagé
    ///    comme erreur. C'est le mécanisme de vérification du mot de passe.
    ///
    /// Le mot de passe et la clé éphémère sont effacés avant le retour.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la dérivation Argon2id échoue, si le mot de passe
    /// est incorrect, ou si la reconstruction de la clé de signature échoue.
    pub(super) fn recoit_trousseau_public_noeud(
        &mut self,
        trousseau_public_noeud: &TrousseauPublicNoeud,
        interface: &impl InterfaceFeuNoyau,
    ) -> ResultCryptographe<()> {
        self.demande_mdp(interface)?;
        self.trousseau
            .definit_sel(trousseau_public_noeud.donne_sel());
        self.derivation_cle_ephemere()?;

        self.trousseau
            .trousseau_public_noeud_vers_trousseau(trousseau_public_noeud)?;

        self.efface_mdp_et_cle_ephemere();

        Ok(())
    }

    /// Déchiffre et charge les clés d'un foyer dans le trousseau.
    ///
    /// Déchiffre toutes les clés privées et symétriques du [`TrousseauPublicFoyer`]
    /// fourni avec la clé éphémère et les enregistre dans le trousseau à la position
    /// `index`. L'adresse `.onion` est lue depuis le [`TrousseauPublicFoyer`].
    /// Le mot de passe et la clé éphémère sont effacés avant le retour.
    ///
    /// # Prérequis
    ///
    /// La clé éphémère doit être présente dans le trousseau.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé éphémère est absente ou si le déchiffrement
    /// d'une clé échoue.
    pub(super) fn recoit_trousseau_public_foyer(
        &mut self,
        trousseau_public_foyer: TrousseauPublicFoyer,
        index_foyer: usize,
    ) -> ResultCryptographe<()> {
        self.trousseau
            .trousseau_public_foyer_vers_trousseau_foyer(&trousseau_public_foyer, index_foyer)?;

        self.efface_mdp_et_cle_ephemere();

        Ok(())
    }

    /// Déchiffre et charge les clés d'un foyer sans session ouverte préalable.
    ///
    /// Variante de [`recoit_trousseau_public_foyer`](Self::recoit_trousseau_public_foyer)
    /// pour le mode secours : collecte le mot de passe et dérive la clé éphémère
    /// avant le déchiffrement, car aucun allumage de foyer n'a eu lieu.
    ///
    /// Enchaîne trois opérations séquentielles :
    ///
    /// 1. Collecte le mot de passe et dérive la clé éphémère Argon2id.
    /// 2. Déchiffre les clés du foyer via `recoit_trousseau_public_foyer`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la dérivation de la clé éphémère échoue ou si
    /// le déchiffrement d'une clé échoue (mot de passe incorrect).
    pub(super) fn secours_recoit_trousseau_public_foyer(
        &mut self,
        trousseau_public_foyer: TrousseauPublicFoyer,
        index_foyer: usize,
        interface: &impl InterfaceFeuNoyau,
    ) -> ResultCryptographe<()> {
        self.demande_mdp(interface)?;
        self.derivation_cle_ephemere()?;

        self.recoit_trousseau_public_foyer(trousseau_public_foyer, index_foyer)?;

        Ok(())
    }

    /// Produit le trousseau public chiffré à partir des clés du trousseau en mémoire.
    ///
    /// Enchaîne trois opérations séquentielles :
    ///
    /// 1. Dérive la clé éphémère AES-256-GCM depuis le mot de passe et le sel.
    /// 2. Chiffre toutes les clés du trousseau via [`Trousseau::genere_trousseau_public`].
    /// 3. Efface le mot de passe et la clé éphémère du trousseau.
    ///
    /// # Prérequis
    ///
    /// Le mot de passe et le sel doivent être présents dans le trousseau —
    /// définis par [`initialise_noeud_a_partir_nouvelle_seed`](Self::initialise_noeud_a_partir_nouvelle_seed),
    /// [`initialise_noeud_a_partir_seed_existante`](Self::initialise_noeud_a_partir_seed_existante),
    /// ou [`genere_trousseau_a_partir_seed`](Self::genere_trousseau_a_partir_seed).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la dérivation de la clé éphémère ou le chiffrement
    /// d'une clé échoue.
    pub(super) fn donne_trousseau_public_complet(
        &mut self,
    ) -> ResultCryptographe<TrousseauPublicComplet> {
        self.derivation_cle_ephemere()?;

        let resultat = self.trousseau.genere_trousseau_public_complet()?;

        self.efface_mdp_et_cle_ephemere();

        Ok(resultat)
    }

    // ── Mot de passe ─────────────────────────────────────────────────────────

    /// Collecte un nouveau mot de passe et rechiffre l'intégralité du trousseau.
    ///
    /// 1. Collecte le nouveau mot de passe (deux saisies avec vérification).
    /// 2. Dérive une nouvelle clé éphémère Argon2id avec le sel existant.
    /// 3. Rechiffre toutes les clés (nœud + foyers) et produit un nouveau trousseau public.
    /// 4. Efface le mot de passe et la clé éphémère de la mémoire.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la dérivation ou le chiffrement échoue.
    pub(super) fn changement_mdp(
        &mut self,
        interface: &impl InterfaceFeuNoyau,
    ) -> ResultCryptographe<TrousseauPublicComplet> {
        self.initialisation_nouveau_mdp(interface)?;
        self.trousseau.derive_cle_ephemere()?;
        let trousseau_public_complet = self.trousseau.genere_trousseau_public_complet()?;
        self.trousseau.efface_cle_ephemere();
        self.trousseau.efface_mdp();

        Ok(trousseau_public_complet)
    }

    // ── Blobs ─────────────────────────────────────────────────────────────────

    /// Chiffre un flux de données du foyer à la position `index`.
    ///
    /// Délègue directement à [`Trousseau::chiffre_avec_cle_foyer`] —
    /// la clé symétrique est lue depuis le trousseau en mémoire.
    ///
    /// # Prérequis
    ///
    /// Le foyer à l'`index` donné doit être ouvert — ses clés doivent être
    /// présentes dans le trousseau.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si aucun foyer n'est chargé à cet index,
    /// ou si le chiffrement AES-GCM-stream échoue.
    pub(super) fn donne_flux_chiffrement_foyer(
        &self,
        index: usize,
        source: &mut impl Read,
        destination: &mut impl Write,
    ) -> ResultCryptographe<()> {
        self.trousseau
            .chiffre_avec_cle_foyer(index, source, destination)?;
        Ok(())
    }

    /// Déchiffre un flux de données d'un foyer fermé.
    ///
    /// Enchaîne trois opérations séquentielles :
    ///
    /// 1. Collecte le mot de passe Feu via `interface`.
    /// 2. Dérive la clé éphémère Argon2id.
    /// 3. Déchiffre `cle_chiffree` (clé symétrique du foyer, 60 octets lus sur disque)
    ///    avec la clé éphémère, puis déchiffre le flux AES-256-GCM-stream.
    ///
    /// La clé éphémère **n'est pas effacée** à l'issue de cette méthode —
    /// elle reste disponible pour le chargement des clés du foyer via
    /// [`recoit_trousseau_public_foyer`](Self::recoit_trousseau_public_foyer),
    /// qui l'effacera en fin d'opération.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la dérivation Argon2id échoue, si le déchiffrement
    /// de `cle_chiffree` échoue (auth tag invalide — mot de passe incorrect),
    /// ou si le déchiffrement du flux AES-GCM-stream échoue.
    pub(super) fn donne_flux_dechiffrement_foyer(
        &mut self,
        cle_chiffree: &[u8; 60],
        source: &mut impl Read,
        destination: &mut impl Write,
        interface: &impl InterfaceFeuNoyau,
    ) -> ResultCryptographe<()> {
        self.demande_mdp(interface)?;
        self.derivation_cle_ephemere()?;
        self.trousseau
            .dechiffre_avec_cle_foyer(cle_chiffree, source, destination)?;
        Ok(())
    }

    /// Calcule le hash SHA3-256 du blob en clair et le chiffre avec la clé du classeur.
    ///
    /// Le hash est calculé **avant** chiffrement — il sert d'identifiant
    /// content-addressable pour le stockage dans le classeur.
    ///
    /// Retourne un tuple `(blob_chiffré, hash)`. Le blob chiffré est structuré
    /// comme suit : `nonce (12 octets) || ciphertext || auth tag (16 octets)`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer ou le classeur à l'index donné est absent
    /// du trousseau, ou si le chiffrement AES-256-GCM échoue.
    pub(super) fn chiffrement_blob(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        blob: &[u8],
    ) -> ResultCryptographe<(Vec<u8>, String)> {
        let hash: [u8; 32] = Sha3_256::digest(blob).into();
        Ok((
            self.trousseau
                .chiffre_blob(index_foyer, index_classeur, blob)?,
            HEXLOWER.encode(&hash),
        ))
    }

    /// Déchiffre un blob et vérifie son intégrité via son hash SHA3-256.
    ///
    /// Déchiffre `blob` avec la clé AES-256-GCM du classeur désigné, puis
    /// recalcule le hash SHA3-256 du résultat. Si le hash recalculé ne correspond
    /// pas à `hash`, la donnée est considérée corrompue et une erreur est retournée.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer ou le classeur est absent du trousseau,
    /// si le déchiffrement AES-256-GCM échoue, ou si le hash du clair ne
    /// correspond pas à `hash` (donnée corrompue).
    pub(super) fn dechiffrement_blob(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
        blob: &[u8],
    ) -> ResultCryptographe<Vec<u8>> {
        let blob_dechiffre = self
            .trousseau
            .dechiffre_blob(index_foyer, index_classeur, blob)?;

        let nouveau_hash: [u8; 32] = Sha3_256::digest(&blob_dechiffre).into();

        let mut hash_decode = [0u8; 32];
        HEXLOWER.decode_mut(hash.as_bytes(), &mut hash_decode)?;
        if nouveau_hash != hash_decode {
            return Err(erreur::ErreurCryptographe::Interne(String::from(
                ERR_CRY_001,
            )));
        }

        Ok(blob_dechiffre)
    }

    // ── Chiffrement asymétrique ───────────────────────────────────────────────

    /// Chiffre des octets à destination d'un nœud identifié par sa clé publique ML-KEM-768.
    ///
    /// Implémente le schéma KEM + HKDF + AES-256-GCM :
    ///
    /// 1. Reconstruit la clé publique ML-KEM-768 depuis les 1184 octets.
    /// 2. Encapsulation ML-KEM-768 : produit un ciphertext (1088 o) et un secret partagé (32 o).
    /// 3. Dérive une clé AES-256-GCM via HKDF-SHA3-256 sur le secret partagé.
    /// 4. Chiffre `octets_a_chiffrer` avec AES-256-GCM (nonce aléatoire).
    ///
    /// # Format de sortie
    ///
    /// ```text
    /// [0..1088]    ciphertext ML-KEM-768 (1088 octets)
    /// [1088..1100] nonce AES-GCM (12 octets)
    /// [1100..]     ciphertext + auth tag (16 octets)
    /// ```
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé publique est invalide, si la dérivation HKDF
    /// ou le chiffrement AES-256-GCM échoue.
    pub(super) fn chiffrement_asymetrique(
        &self,
        cle_publique_destinataire: &[u8; 1184],
        octets_a_chiffrer: &[u8],
    ) -> ResultCryptographe<Vec<u8>> {
        // Reconstruit la clé publique ML-KEM-768 depuis les octets
        let ek = EncapsulationKey768::new(cle_publique_destinataire.into())
            .map_err(|_| ErreurCryptographe::Interne(String::from(ERR_CRY_002)))?;

        // Encapsulation → (ciphertext 1088 o, secret partagé 32 o)
        let (ciphertext, secret_partage) = ek.encapsulate();
        let secret_partage = SecretBox::new(Box::new(<[u8; 32]>::from(secret_partage)));

        // HKDF -> clé AES
        let hkdf = Hkdf::<Sha3_256>::new(None, secret_partage.expose_secret());
        let mut cle_brute = SecretBox::new(Box::new([0u8; 32]));
        hkdf.expand(
            INFO_HKDF_CHIFFREMENT_ASYMETRIQUE.as_bytes(),
            cle_brute.expose_secret_mut(),
        )?;

        // Résultat : ciphertext_kem (1088 o) || nonce || ciphertext AES
        let mut resultat: Vec<u8> = Vec::new();
        resultat.extend_from_slice(ciphertext.as_ref());
        resultat.extend(Trousseau::chiffrement_generique_avec_cle(
            cle_brute.expose_secret(),
            octets_a_chiffrer,
        )?);

        Ok(resultat)
    }

    /// Déchiffre un message chiffré par [`chiffrement_asymetrique`](Self::chiffrement_asymetrique).
    ///
    /// Implémente le schéma KEM + HKDF + AES-256-GCM, côté destinataire :
    ///
    /// 1. Extrait le ciphertext ML-KEM-768 `[0..1088]`.
    /// 2. Décapsulation avec la clé privée du foyer → secret partagé (32 o).
    /// 3. Dérive la clé AES-256-GCM via HKDF-SHA3-256 sur le secret partagé.
    /// 4. Déchiffre `[1088..]` avec AES-256-GCM.
    ///
    /// # Format d'entrée
    ///
    /// ```text
    /// [0..1088]    ciphertext ML-KEM-768 (1088 octets)
    /// [1088..1100] nonce AES-GCM (12 octets)
    /// [1100..]     ciphertext + auth tag (16 octets)
    /// ```
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le ciphertext KEM est invalide,
    /// si le foyer est absent du trousseau, si la dérivation HKDF échoue,
    /// ou si le déchiffrement AES-256-GCM échoue.
    pub(super) fn dechiffrement_asymetrique(
        &self,
        index_foyer: usize,
        octets_a_dechiffrer: &[u8],
    ) -> ResultCryptographe<Vec<u8>> {
        // Extrait le ciphertext KEM (1088 o)
        let ciphertext: &Ciphertext768 = octets_a_dechiffrer
            .get(0..1088)
            .ok_or_else(|| ErreurCryptographe::Interne(String::from(ERR_CRY_002)))?
            .try_into()
            .map_err(|_| ErreurCryptographe::Interne(String::from(ERR_CRY_002)))?;

        // Décapsulation → secret partagé
        let secret_partage = self
            .trousseau
            .recuperation_secret_partage(index_foyer, ciphertext)?;

        // Dérive la clé AES-256-GCM depuis le secret partagé
        let hkdf = Hkdf::<Sha3_256>::new(None, secret_partage.expose_secret());
        let mut cle_brute = SecretBox::new(Box::new([0u8; 32]));
        hkdf.expand(
            INFO_HKDF_CHIFFREMENT_ASYMETRIQUE.as_bytes(),
            cle_brute.expose_secret_mut(),
        )?;

        Trousseau::dechiffrement_generique_avec_cle(
            cle_brute.expose_secret(),
            &octets_a_dechiffrer[1088..],
        )
    }

    // ── Signature ─────────────────────────────────────────────────────────────

    /// Signe des octets avec la clé privée Ed25519 du nœud.
    ///
    /// Délègue directement à [`Trousseau::signe_avec_cle_noeud`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé de signature du nœud est absente du trousseau.
    pub(super) fn signature_noeud(&self, octets_a_signer: &[u8]) -> ResultCryptographe<[u8; 64]> {
        self.trousseau.signe_avec_cle_noeud(octets_a_signer)
    }

    /// Signe des octets avec la clé privée Ed25519 du foyer à la position `index_foyer`.
    ///
    /// Délègue directement à [`Trousseau::signe_avec_cle_foyer`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer est absent du trousseau.
    pub(super) fn signature_foyer(
        &self,
        index_foyer: usize,
        octets_a_signer: &[u8],
    ) -> ResultCryptographe<[u8; 64]> {
        self.trousseau
            .signe_avec_cle_foyer(index_foyer, octets_a_signer)
    }

    /// Vérifie une signature Ed25519.
    ///
    /// Retourne `true` si `signature` est une signature valide de `octets_signes`
    /// produite par la clé privée correspondant à `cle_publique`, `false` sinon.
    ///
    /// Utilise `verify_strict` pour résister aux attaques par malléabilité de signature.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `cle_publique` ne forme pas un point Ed25519 valide.
    pub(super) fn verification_signature(
        cle_publique: [u8; 32],
        signature: [u8; 64],
        octets_signes: &[u8],
    ) -> ResultCryptographe<bool> {
        let signature_reconstruite = ed25519_dalek::Signature::from_bytes(&signature);
        let cle = VerifyingKey::from_bytes(&cle_publique)?;
        Ok(cle
            .verify_strict(octets_signes, &signature_reconstruite)
            .is_ok())
    }

    // ── Utilitaires privés ────────────────────────────────────────────────────

    /// Demande un nouveau mot de passe à l'utilisateur et le stocke dans le trousseau.
    ///
    /// Sollicite deux saisies successives via `interface`. Si elles diffèrent,
    /// l'utilisateur est invité à recommencer — la boucle se répète jusqu'à
    /// ce que les deux entrées correspondent.
    ///
    /// Le mot de passe est encapsulé dans [`SecretBox`] dès réception et
    /// remplace tout mot de passe précédemment défini (l'ancien est zéroïsé
    /// automatiquement au remplacement).
    fn initialisation_nouveau_mdp(
        &mut self,
        interface: &impl InterfaceFeuNoyau,
    ) -> ResultCryptographe<()> {
        if let (Some(mdp), Some(mdp2)) = (interface.demander_mdp(), interface.demander_mdp())
            && mdp.expose_secret() == mdp2.expose_secret()
        {
            self.trousseau.definit_mdp(mdp);
            return Ok(());
        }

        Err(ErreurCryptographe::Interne(String::from(ERR_CRY_003)))
    }

    /// Collecte le mot de passe Feu via l'interface et le stocke dans le trousseau.
    ///
    /// Le mot de passe est encapsulé dans [`SecretBox`] dès réception.
    /// Il doit être effacé via [`efface_mdp_et_cle_ephemere`](Self::efface_mdp_et_cle_ephemere)
    /// dès qu'il n'est plus nécessaire.
    fn demande_mdp(&mut self, interface: &impl InterfaceFeuNoyau) -> ResultCryptographe<()> {
        if let Some(mdp) = interface.demander_mdp() {
            self.trousseau.definit_mdp(mdp);
            return Ok(());
        }

        Err(ErreurCryptographe::Interne(String::from(ERR_CRY_003)))
    }

    /// Dérive la clé éphémère AES-256-GCM depuis le mot de passe et le sel du trousseau.
    ///
    /// Délègue à [`Trousseau::derive_cle_ephemere`]. La clé éphémère doit être
    /// effacée via [`efface_mdp_et_cle_ephemere`](Self::efface_mdp_et_cle_ephemere)
    /// dès qu'elle n'est plus nécessaire.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le mot de passe ou le sel est absent, ou si la
    /// dérivation Argon2id échoue.
    fn derivation_cle_ephemere(&mut self) -> ResultCryptographe<()> {
        self.trousseau.derive_cle_ephemere()?;
        Ok(())
    }

    /// Efface le mot de passe et la clé éphémère du trousseau.
    ///
    /// Doit être appelé dès que les opérations nécessitant ces secrets sont terminées.
    /// La destruction des [`SecretBox`] déclenche la zéroïsation automatique de la mémoire.
    fn efface_mdp_et_cle_ephemere(&mut self) {
        self.trousseau.efface_mdp();
        self.trousseau.efface_cle_ephemere();
    }
}
