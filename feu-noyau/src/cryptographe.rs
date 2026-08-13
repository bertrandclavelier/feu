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
//! symétrique, de signature (ML-DSA-87) et de chiffrement (ML-KEM-1024) par foyer.
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

mod trousseau;
pub(crate) mod trousseaux_publics;

use bip39::{Language, Mnemonic};
use data_encoding::HEXLOWER;
use hkdf::Hkdf;
use ml_dsa::{MlDsa87, Signature, Verifier, VerifyingKey};
use ml_kem::ml_kem_1024::Ciphertext as Ciphertext1024;
use ml_kem::{Encapsulate, EncapsulationKey1024};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use sha3::{Digest, Sha3_256};
use std::io::{Read, Write};

use crate::cryptographe::trousseau::Trousseau;
use crate::cryptographe::trousseaux_publics::{
    TrousseauPublicComplet, TrousseauPublicFoyer, TrousseauPublicNoeud,
};
use crate::{ErreurFeuNoyau, MAX_FOYERS};
use crate::{InterfaceFeuNoyau, ResultFeuNoyau};

const NOMBRE_MOTS_SEED: usize = 24;
const INFO_HKDF_CHIFFREMENT_ASYMETRIQUE: &str = "feu-chiffrement-asymetrique";

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
    /// 1. Génère la seed mnémonique (24 mots, français) et la transmet à `interface`.
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
    ) -> ResultFeuNoyau<()> {
        // Bloc encadrant la portée de phrase_seed
        {
            let phrase_seed: SecretString;

            // Bloc encadrant la portée de mnemonic
            {
                // `Mnemonic` est déjà `ZeroizeOnDrop` (bip39, feature `zeroize`) :
                // le `SecretBox` n'est pas requis pour la zéroïsation, il sert à
                // porter la seed derrière un accès gardé (`expose_secret`) le temps
                // du callback d'affichage/confirmation. Ailleurs (parse_in), un
                // `Mnemonic` nu est donc tout aussi sûr.
                let mnemonic = SecretBox::new(Box::new(Mnemonic::generate_in(
                    Language::French,
                    NOMBRE_MOTS_SEED,
                )?));

                let mots: Vec<&str> = mnemonic.expose_secret().words().collect();
                interface.recevoir_seed(&mots);

                if !interface.confirmer_enregistrement_seed() {
                    return Err(ErreurFeuNoyau::CryptographeSeedNonConfirmee);
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
    ) -> ResultFeuNoyau<()> {
        self.initialisation_nouveau_mdp(interface)?;

        self.genere_trousseau_a_partir_seed(interface, phrase_seed)?;

        Ok(())
    }

    /// Dérive et enregistre dans le trousseau toutes les clés du nœud et des foyers.
    ///
    /// À partir de `phrase_seed`, parse la phrase mnémotechnique BIP39, puis dérive
    /// de manière déterministe par HKDF-SHA3-256 et enregistre dans le trousseau :
    /// - la paire de clés de signature du nœud (label `feu/noeud/signature`)
    /// - les clés de signature, de chiffrement, symétriques et de classeurs de chaque
    ///   foyer (labels `feu/foyer/*` suffixés de l'index du foyer)
    ///
    /// Si aucun mot de passe n'est présent dans le trousseau, en collecte un via
    /// `interface` (saisie unique, sans confirmation) — c'est le cas de
    /// [`demarrage_secours`](super::FeuNoyau::demarrage_secours). Si un mot de passe est déjà
    /// présent (positionné au préalable par l'appelant), la saisie est ignorée.
    ///
    /// Génère également le sel Argon2id de manière déterministe depuis la seed
    /// par HKDF-SHA3-256 (label `feu/noeud/sel`).
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
    ) -> ResultFeuNoyau<()> {
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
        self.trousseau.genere_sel(&seed_bytes)?;

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
    ) -> ResultFeuNoyau<()> {
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
    /// `index`. L'adresse `.braise` est lue depuis le [`TrousseauPublicFoyer`].
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
    ) -> ResultFeuNoyau<()> {
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
    ) -> ResultFeuNoyau<()> {
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
    ) -> ResultFeuNoyau<TrousseauPublicComplet> {
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
    ) -> ResultFeuNoyau<TrousseauPublicComplet> {
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
    ) -> ResultFeuNoyau<()> {
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
    ) -> ResultFeuNoyau<()> {
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
    ) -> ResultFeuNoyau<(Vec<u8>, String)> {
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
    /// Cette comparaison n'est pas redondante avec l'auth tag AES-GCM, contrairement
    /// à ce qu'elle peut laisser croire. L'auth tag atteste que le contenu n'a pas
    /// été modifié, pas qu'il s'agit du contenu demandé : le chiffrement se fait
    /// sans données associées, donc rien ne lie un blob au hash sous lequel il est
    /// rangé. Deux blobs d'un même classeur, chiffrés avec la même clé, sont
    /// interchangeables aux yeux d'AES-GCM. Le hash est ce qui les distingue —
    /// c'est aussi lui qui fonde l'adressage par contenu du classeur.
    ///
    /// Aucun test ne couvre cette branche : la comparaison se réduit à un `!=`
    /// entre deux tableaux de 32 octets, sans logique à prendre en défaut, et le
    /// seul scénario qui l'atteint sans buter d'abord sur l'auth tag est la
    /// permutation de deux blobs du même classeur du même foyer. Ailleurs, les
    /// clés diffèrent et le déchiffrement échoue avant.
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
    ) -> ResultFeuNoyau<Vec<u8>> {
        let blob_dechiffre = self
            .trousseau
            .dechiffre_blob(index_foyer, index_classeur, blob)?;

        let nouveau_hash: [u8; 32] = Sha3_256::digest(&blob_dechiffre).into();

        let mut hash_decode = [0u8; 32];
        HEXLOWER.decode_mut(hash.as_bytes(), &mut hash_decode)?;
        if nouveau_hash != hash_decode {
            return Err(ErreurFeuNoyau::CryptographeHashBlobDiscordant);
        }

        Ok(blob_dechiffre)
    }

    // ── Chiffrement asymétrique ───────────────────────────────────────────────

    /// Chiffre des octets à destination d'un nœud identifié par sa clé publique ML-KEM-1024.
    ///
    /// Implémente le schéma KEM + HKDF + AES-256-GCM :
    ///
    /// 1. Reconstruit la clé publique ML-KEM-1024 depuis les 1568 octets.
    /// 2. Encapsulation ML-KEM-1024 : produit un ciphertext (1568 o) et un secret partagé (32 o).
    /// 3. Dérive une clé AES-256-GCM via HKDF-SHA3-256 sur le secret partagé.
    /// 4. Chiffre `octets_a_chiffrer` avec AES-256-GCM (nonce aléatoire).
    ///
    /// # Format de sortie
    ///
    /// ```text
    /// [0..1568]    ciphertext ML-KEM-1024 (1568 octets)
    /// [1568..1580] nonce AES-GCM (12 octets)
    /// [1580..]     ciphertext + auth tag (16 octets)
    /// ```
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé publique est invalide, si la dérivation HKDF
    /// ou le chiffrement AES-256-GCM échoue.
    pub(super) fn chiffrement_asymetrique(
        &self,
        cle_publique_destinataire: &[u8; 1568],
        octets_a_chiffrer: &[u8],
    ) -> ResultFeuNoyau<Vec<u8>> {
        // Reconstruit la clé publique ML-KEM-1024 depuis les octets
        let ek = EncapsulationKey1024::new(cle_publique_destinataire.into())
            .map_err(|_| ErreurFeuNoyau::CryptographeClePubliqueChiffrementInvalide)?;

        // Encapsulation → (ciphertext 1568 o, secret partagé 32 o)
        let (ciphertext, secret_partage) = ek.encapsulate();
        let secret_partage = SecretBox::new(Box::new(<[u8; 32]>::from(secret_partage)));

        // HKDF -> clé AES
        let hkdf = Hkdf::<Sha3_256>::new(None, secret_partage.expose_secret());
        let mut cle_brute = SecretBox::new(Box::new([0u8; 32]));
        hkdf.expand(
            INFO_HKDF_CHIFFREMENT_ASYMETRIQUE.as_bytes(),
            cle_brute.expose_secret_mut(),
        )?;

        // Résultat : ciphertext_kem (1568 o) || nonce || ciphertext AES
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
    /// 1. Extrait le ciphertext ML-KEM-1024 `[0..1568]`.
    /// 2. Décapsulation avec la clé privée du foyer → secret partagé (32 o).
    /// 3. Dérive la clé AES-256-GCM via HKDF-SHA3-256 sur le secret partagé.
    /// 4. Déchiffre `[1568..]` avec AES-256-GCM.
    ///
    /// # Format d'entrée
    ///
    /// ```text
    /// [0..1568]    ciphertext ML-KEM-1024 (1568 octets)
    /// [1568..1580] nonce AES-GCM (12 octets)
    /// [1580..]     ciphertext + auth tag (16 octets)
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
    ) -> ResultFeuNoyau<Vec<u8>> {
        // Extrait le ciphertext KEM (1568 o)
        let ciphertext: &Ciphertext1024 = octets_a_dechiffrer
            .get(0..1568)
            .ok_or(ErreurFeuNoyau::CryptographeCiphertextMlKemInvalide)?
            .try_into()
            .map_err(|_| ErreurFeuNoyau::CryptographeCiphertextMlKemInvalide)?;

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
            &octets_a_dechiffrer[1568..],
        )
    }

    // ── Signature ─────────────────────────────────────────────────────────────

    /// Signe des octets avec la clé privée ML-DSA-87 du nœud.
    ///
    /// Délègue directement à [`Trousseau::signe_avec_cle_noeud`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé de signature du nœud est absente du trousseau.
    pub(super) fn signature_noeud(&self, octets_a_signer: &[u8]) -> ResultFeuNoyau<[u8; 4627]> {
        self.trousseau.signe_avec_cle_noeud(octets_a_signer)
    }

    /// Signe des octets avec la clé privée ML-DSA-87 du foyer à la position `index_foyer`.
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
    ) -> ResultFeuNoyau<[u8; 4627]> {
        self.trousseau
            .signe_avec_cle_foyer(index_foyer, octets_a_signer)
    }

    /// Vérifie une signature ML-DSA-87.
    ///
    /// Retourne `true` si `signature` est une signature valide de `octets_signes`
    /// produite par la clé privée correspondant à `cle_publique`, `false` sinon.
    ///
    /// Une signature bien encodée mais invalide retourne `false` ; un encodage mal
    /// formé est en revanche rejeté par une erreur (voir ci-dessous). La clé publique,
    /// de taille fixe, se décode sans faillir.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `signature` n'est pas un encodage ML-DSA-87 valide.
    pub(super) fn verification_signature(
        cle_publique: [u8; 2592],
        signature: [u8; 4627],
        octets_signes: &[u8],
    ) -> ResultFeuNoyau<bool> {
        let signature = Signature::<MlDsa87>::decode(&signature.into())
            .ok_or(ErreurFeuNoyau::CryptographeSignatureMlDsaMalFormee)?;
        let cle_publique = VerifyingKey::<MlDsa87>::decode(&cle_publique.into());

        Ok(cle_publique.verify(octets_signes, &signature).is_ok())
    }

    /// Calcule l'empreinte SHA3-256 des octets fournis.
    ///
    /// Retourne un tableau de 32 octets. Fonction pure, sans état.
    pub(super) fn empreinte(octets: &[u8]) -> [u8; 32] {
        Sha3_256::digest(octets).into()
    }

    // ── Utilitaires privés ────────────────────────────────────────────────────

    /// Demande un nouveau mot de passe à l'utilisateur et le stocke dans le trousseau.
    ///
    /// Sollicite deux saisies successives via `interface` et échoue si elles
    /// diffèrent : la reprise appartient à l'appelant, pas à cette fonction.
    ///
    /// Le mot de passe est encapsulé dans [`SecretBox`] dès réception et
    /// remplace tout mot de passe précédemment défini (l'ancien est zéroïsé
    /// automatiquement au remplacement).
    fn initialisation_nouveau_mdp(
        &mut self,
        interface: &impl InterfaceFeuNoyau,
    ) -> ResultFeuNoyau<()> {
        let (Some(mdp), Some(mdp2)) = (interface.demander_mdp(), interface.demander_mdp()) else {
            return Err(ErreurFeuNoyau::CryptographeMotDePasseNonSaisi);
        };
        if mdp.expose_secret() != mdp2.expose_secret() {
            return Err(ErreurFeuNoyau::CryptographeMotsDePasseDiscordants);
        }
        self.trousseau.definit_mdp(mdp);

        Ok(())
    }

    /// Collecte le mot de passe Feu via l'interface et le stocke dans le trousseau.
    ///
    /// Le mot de passe est encapsulé dans [`SecretBox`] dès réception.
    /// Il doit être effacé via [`efface_mdp_et_cle_ephemere`](Self::efface_mdp_et_cle_ephemere)
    /// dès qu'il n'est plus nécessaire.
    fn demande_mdp(&mut self, interface: &impl InterfaceFeuNoyau) -> ResultFeuNoyau<()> {
        if let Some(mdp) = interface.demander_mdp() {
            self.trousseau.definit_mdp(mdp);
            return Ok(());
        }

        Err(ErreurFeuNoyau::CryptographeMotDePasseNonSaisi)
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
    fn derivation_cle_ephemere(&mut self) -> ResultFeuNoyau<()> {
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

// Couvert ici : les deux primitives de bout en bout, la signature ML-DSA-87 et
// le chiffrement asymétrique ML-KEM-1024. Rien ne les prouvait jusqu'ici, alors
// que le protocole ENU repose entièrement dessus.
//
// `empreinte` n'a pas de test propre : elle ne fait qu'appeler SHA3-256, déjà
// testé dans sa crate. Un test ici ne vérifierait que l'absence de faute de
// frappe dans une ligne. Même raisonnement pour la garde d'intégrité de
// `dechiffrement_blob`, dont la doc porte le détail.
//
// Non couvert ici, car exige une `InterfaceFeuNoyau` et le disque :
//
// - l'initialisation du nœud (`initialise_noeud_a_partir_*`), qui passe par
//   les saisies de seed et de mot de passe ;
// - le rechargement des trousseaux publics (`recoit_trousseau_public_*`) et le
//   `changement_mdp` ;
// - les flux de chiffrement des archives de foyer (`donne_flux_*`), qui
//   délèguent au chiffrement par chunks de `Trousseau`.
//
// Tous relèvent des tests d'intégration.
#[cfg(test)]
mod tests {
    use super::*;

    /// Monte un cryptographe utilisable et rend son [`TrousseauPublicComplet`].
    ///
    /// Le mot de passe et le sel n'ont ici aucun rôle propre : ils ne servent
    /// qu'à rendre possible `donne_trousseau_public_complet`, qui dérive une
    /// clé éphémère Argon2id. Or c'est l'unique chemin d'accès aux clés
    /// publiques depuis ce module — les accesseurs de [`Trousseau`] sont privés
    /// au sien. Posés directement plutôt que collectés, ils dispensent les
    /// tests d'une [`InterfaceFeuNoyau`] factice.
    ///
    /// Deux foyers sont dérivés, pas un : chaque test a besoin d'une seconde
    /// identité pour son cas négatif — clé de vérification étrangère pour la
    /// signature, index de déchiffrement étranger pour le chiffrement
    /// asymétrique. Retirer le foyer 1 les ferait passer sans plus rien
    /// prouver.
    ///
    /// Appelable une seule fois par cryptographe : `donne_trousseau_public_complet`
    /// efface le mot de passe avant de rendre la main. Les clés privées, elles,
    /// restent en place — signature et déchiffrement fonctionnent après.
    fn monte_cryptographe_de_test(
        cryptographe: &mut Cryptographe,
    ) -> ResultFeuNoyau<TrousseauPublicComplet> {
        let seed = SecretBox::new(Box::new([0x22; 64]));
        cryptographe
            .trousseau
            .definit_mdp(SecretString::from("mot de passe"));
        cryptographe.trousseau.definit_sel([0x33; 16]);
        cryptographe.trousseau.ajouter_paire_noeud(&seed)?;
        cryptographe.trousseau.ajouter_trousseau_foyer(&seed, 0)?;
        cryptographe.trousseau.ajouter_trousseau_foyer(&seed, 1)?;

        cryptographe.donne_trousseau_public_complet()
    }

    /// Vérifie le cycle signature/vérification ML-DSA-87, pour le nœud et pour
    /// un foyer.
    ///
    /// Rien ne prouvait jusqu'ici que la primitive de signature était
    /// correctement câblée — or tout le protocole ENU repose dessus : c'est
    /// elle qui atteste l'origine d'un message. Une vérification qui rendrait
    /// systématiquement `true` passerait aujourd'hui inaperçue.
    ///
    /// Les deux cas négatifs portent chacun une propriété distincte, aucun
    /// n'est le doublon de l'autre :
    /// - clé publique étrangère (foyer 1 pour une signature du foyer 0) — la
    ///   signature est liée à la clé, les foyers ne se couvrent pas entre eux ;
    /// - message altéré — la signature est liée au contenu, on ne peut pas
    ///   signer une chose et en transmettre une autre.
    ///
    /// La branche [`ErreurFeuNoyau::CryptographeSignatureMlDsaMalFormee`]
    /// reste volontairement non couverte : altérer les octets d'une signature
    /// donne tantôt `Ok(false)`, tantôt `Err`, selon l'octet touché et l'étape
    /// du décodage ML-DSA qu'il fait échouer. Un test non déterministe coûte
    /// plus qu'il ne prouve — d'où l'altération portée sur le message.
    #[test]
    fn cycle_signature_verification() -> ResultFeuNoyau<()> {
        let mut cryptographe = Cryptographe::new();
        let trousseau_public = monte_cryptographe_de_test(&mut cryptographe)?;

        let message = b"message a signer et verifier";

        // Cas nominal du nœud. Sa clé de signature suit un chemin de dérivation
        // distinct de celui des foyers : la couvrir séparément n'est pas un
        // doublon.
        let signature = cryptographe.signature_noeud(message)?;

        assert!(Cryptographe::verification_signature(
            trousseau_public
                .donne_trousseau_public_noeud()
                .donne_cle_sig_pub(),
            signature,
            message
        )?);

        // Cas nominal d'un foyer. Cette signature sert aussi de témoin aux deux
        // cas négatifs qui suivent : seule la clé de vérification, puis le
        // message, y changent — l'échec ne peut donc venir que de là.
        let signature = cryptographe.signature_foyer(0, message)?;

        assert!(Cryptographe::verification_signature(
            trousseau_public
                .donne_trousseau_public_foyer(0)?
                .donne_cle_sig_pub(),
            signature,
            message
        )?);

        // Clé publique d'un autre foyer, signature et message inchangés.
        assert!(!Cryptographe::verification_signature(
            trousseau_public
                .donne_trousseau_public_foyer(1)?
                .donne_cle_sig_pub(),
            signature,
            message
        )?);

        // Bonne clé, bonne signature, message amputé de son dernier octet.
        let message_altere = b"message a signer et verifie";

        assert!(!Cryptographe::verification_signature(
            trousseau_public
                .donne_trousseau_public_foyer(0)?
                .donne_cle_sig_pub(),
            signature,
            message_altere
        )?);

        Ok(())
    }

    /// Vérifie le cycle chiffrement/déchiffrement asymétrique ML-KEM-1024.
    ///
    /// La chaîne encapsulation ML-KEM → dérivation HKDF-SHA3-256 → AES-256-GCM
    /// est assemblée à la main dans `chiffrement_asymetrique`, puis refaite en
    /// miroir dans `dechiffrement_asymetrique`. Rien ne garantissait que les
    /// deux moitiés s'accordaient — même label HKDF, même découpe du format de
    /// sortie. C'est le round-trip qui l'établit.
    ///
    /// Le cas négatif rend une **erreur**, non un `false`, et elle ne vient pas
    /// d'où on l'attendrait : ML-KEM ne rejette jamais un ciphertext (rejet
    /// implicite). Décapsuler avec la mauvaise clé privée réussit et rend un
    /// secret partagé pseudo-aléatoire, sans broncher. C'est l'auth tag
    /// AES-GCM, un cran plus loin, qui refuse.
    ///
    /// `is_err()` suffit, sans inspection de la variante : `dechiffrement_asymetrique`
    /// n'a que deux causes d'échec, et le foyer 1 étant présent dans le
    /// trousseau monté, celle du foyer absent est exclue par construction. Le
    /// round-trip qui précède sert de témoin — il attribue l'échec au
    /// changement d'index plutôt qu'à un chiffrement raté. C'est cette
    /// combinaison, pas la seule assertion, qui rend le test concluant.
    #[test]
    fn cycle_chiffrement_dechiffrement_asymetrique() -> ResultFeuNoyau<()> {
        let mut cryptographe = Cryptographe::new();

        let trousseau_public = monte_cryptographe_de_test(&mut cryptographe)?;

        let message = b"message a chiffrer et dechiffrer";

        // En usage réel, l'expéditeur est un nœud tiers. Ici le même
        // cryptographe chiffre et déchiffre : `chiffrement_asymetrique` ne
        // consomme que la clé publique du destinataire, aucun secret de
        // l'expéditeur n'entre dans le schéma — un second cryptographe
        // n'apporterait rien au test.
        let message_chiffre = cryptographe.chiffrement_asymetrique(
            &trousseau_public
                .donne_trousseau_public_foyer(0)?
                .donne_cle_chiff_pub(),
            message,
        )?;

        assert_eq!(
            cryptographe.dechiffrement_asymetrique(0, &message_chiffre)?,
            message
        );

        // Même ciphertext, index du foyer 1 : seul le foyer 0 détient la clé
        // privée capable d'en retrouver le bon secret partagé.
        assert!(
            cryptographe
                .dechiffrement_asymetrique(1, &message_chiffre)
                .is_err()
        );

        Ok(())
    }
}
