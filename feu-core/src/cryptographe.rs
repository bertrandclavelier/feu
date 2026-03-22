// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! Le cryptographe est le gardien de la sécurité cryptographique de Feu.
//!
//! Il est l'unique composant autorisé à manipuler des données en clair —
//! toute opération de chiffrement, de déchiffrement ou de dérivation de
//! clés passe exclusivement par lui.
//!
//! Il a en charge la génération des seeds BIP39, la dérivation SLIP-0010
//! des clés nœud et foyer, ainsi que la génération des clés symétrique,
//! de signature (Ed25519) et de chiffrement (X25519) par foyer.
//! Il maintient en mémoire le trousseau — l'unique endroit où les clés
//! privées et la clé symétrique existent en clair.
//!
//! # Cycle de vie des secrets
//!
//! Les données sensibles transitant dans ce module (`Mnemonic`, `seed_bytes`)
//! sont encapsulées dans [`SecretBox`] dès leur création. L'accès au contenu
//! est explicitement contraint à [`expose_secret()`], rendant toute
//! manipulation visible à la lecture du code.
//!
//! Des blocs de scope `{ }` limitent la durée de vie de chaque secret au
//! strict nécessaire — la destruction du [`SecretBox`] déclenche la
//! zéroïsation automatique de la mémoire.
//!
//! Rien n'est écrit sur le disque depuis ce module — c'est le rôle du
//! gardien.
//!
//! # Invariant de sécurité
//!
//! Aucun autre composant de Feu n'accède directement aux clés ou aux
//! données en clair. Cette centralisation est un invariant fondamental
//! du protocole.

use crate::MAX_FOYERS;

use super::InterfaceFeuCore;
use bip39::{Language, Mnemonic};
use data_encoding::HEXLOWER;
use erreur::ResultCryptographe;
use secrecy::{ExposeSecret, SecretBox};
use sha3::{Digest, Sha3_256};
use std::io::{Read, Write};
use trousseau::Trousseau;
use trousseaux_publics::{TrousseauPublicComplet, TrousseauPublicFoyer, TrousseauPublicNoeud};

mod trousseau;
pub(crate) mod trousseaux_publics;

pub(super) mod erreur;

pub(super) struct Cryptographe {
    trousseau: Trousseau,
}

//
// Construction
//
impl Cryptographe {
    /// Crée le cryptographe de [`Feu`].
    pub(super) fn new() -> Self {
        Cryptographe {
            trousseau: Trousseau::new(),
        }
    }
}

//
// Interface publique
//
impl Cryptographe {
    /// Génère une nouvelle seed BIP39 et initialise le trousseau pour un nouveau nœud.
    ///
    /// La seed mnémonique (12 mots, français) est affichée via `interface` une seule
    /// fois — l'utilisateur doit la noter avant de continuer.
    ///
    /// À partir de la seed, dérive et enregistre dans le trousseau de manière déterministe :
    /// - la paire de clés de signature du nœud (`m/0'`)
    /// - l'ensemble des clés de chaque foyer (`m/1'` à `m/MAX_FOYERS'`)
    ///
    /// La seed est zéroïsée avant le retour. Rien n'est écrit sur le disque —
    /// c'est le rôle du gardien.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la génération du mnémonique BIP39 échoue ou si
    /// la dérivation des clés d'un foyer échoue.
    pub(super) fn initialise_noeud_from_nouvelle_seed(
        &mut self,
        interface: &impl InterfaceFeuCore,
    ) -> ResultCryptographe<()> {
        self.initialisation_nouveau_mdp(interface);

        // Bloc encadrant la portée de seed_bytes
        {
            let seed_bytes: SecretBox<[u8; 64]>;

            // Bloc encadrant la portée de mnemonic
            {
                let mnemonic =
                    SecretBox::new(Box::new(Mnemonic::generate_in(Language::French, 12)?));

                interface.afficher(
                    "Cryptographe ›› ATTENTION ! La seed ci-après ne sera affichée qu'une
        seule fois avant d'être détruite. Elle doit impérativement être notée et mise en sécurité.",
                );
                for (i, mot) in mnemonic.expose_secret().words().enumerate() {
                    interface.afficher(&format!("{i:<2}- {mot}"));
                }

                seed_bytes = SecretBox::new(Box::new(mnemonic.expose_secret().to_seed(""))); // passphrase vide
            }

            // Ajoute la paire de clés du nœud au trousseau à partir de la seed
            self.trousseau.ajouter_paire_noeud(&seed_bytes);
            interface.afficher(
                "Cryptographe ›› La paire de clés signature du nœud Feu a été générée et mise
            dans mon trousseau.",
            );

            // Ajoute les trousseaux des MAX_FOYERS
            for i in 0..MAX_FOYERS {
                self.trousseau.ajouter_trousseau_foyer(&seed_bytes, i)?;
            }
            interface.afficher(&format!(
                "Cryptographe ›› Toutes les clés nécessaires au fonctionnement des {} foyers ont été générées et mises dans mon trousseau.",
                MAX_FOYERS
            ));

            // Génère le sel et le met dans le trousseau
            self.trousseau.genere_sel()?;
        }
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
    /// définis au cours de [`initialise_noeud_from_nouvelle_seed`](Self::initialise_noeud_from_nouvelle_seed).
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
        interface: &impl InterfaceFeuCore,
    ) -> ResultCryptographe<()> {
        self.demande_mdp(interface);
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
        index: usize,
    ) -> ResultCryptographe<()> {
        self.trousseau
            .trousseau_public_foyer_vers_trousseau_foyer(&trousseau_public_foyer, index)?;

        self.efface_mdp_et_cle_ephemere();

        Ok(())
    }

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
    // La clé éphémère **n'est pas effacée** à l'issue de cette méthode —
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
        interface: &impl InterfaceFeuCore,
    ) -> ResultCryptographe<()> {
        self.demande_mdp(interface);
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
                "Donnée corrompue après déchiffrement",
            )));
        }

        Ok(blob_dechiffre)
    }
}

//
// Helpers internes — gestion des secrets éphémères
//
impl Cryptographe {
    /// Demande un nouveau mot de passe à l'utilisateur et le stocke dans le trousseau.
    ///
    /// Sollicite deux saisies successives via `interface`. Si elles diffèrent,
    /// l'utilisateur est invité à recommencer — la boucle se répète jusqu'à
    /// ce que les deux entrées correspondent.
    ///
    /// Le mot de passe est encapsulé dans [`SecretBox`] dès réception et
    /// remplace tout mot de passe précédemment défini (l'ancien est zéroïsé
    /// automatiquement au remplacement).
    fn initialisation_nouveau_mdp(&mut self, interface: &impl InterfaceFeuCore) {
        loop {
            let mdp = SecretBox::new(Box::new(
                interface.demander_mdp("Entrez un nouveau mot de passe :"),
            ));
            let mdp2 = SecretBox::new(Box::new(
                interface.demander_mdp("Entrez de nouveau le mot de passe :"),
            ));

            if mdp.expose_secret() == mdp2.expose_secret() {
                self.trousseau.definit_mdp(mdp);
                break;
            } else {
                interface.afficher("Les deux entrées sont différentes. Recommencez...");
            }
        }
    }

    /// Collecte un nouveau mot de passe et rechiffre l'intégralité du trousseau.
    ///
    /// 1. Collecte le nouveau mot de passe (deux saisies avec vérification).
    /// 2. Dérive une nouvelle clé éphémère Argon2id avec le sel existant.
    /// 3. Rechiffre toutes les clés (nœud + foyers) — produit un nouveau trousseau public.
    /// 4. Efface le mot de passe et la clé éphémère de la mémoire.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la dérivation ou le chiffrement échoue.
    pub(super) fn changement_mdp(
        &mut self,
        interface: &impl InterfaceFeuCore,
    ) -> ResultCryptographe<TrousseauPublicComplet> {
        self.initialisation_nouveau_mdp(interface);
        self.trousseau.derive_cle_ephemere()?;
        let trousseau_public_complet = self.trousseau.genere_trousseau_public_complet()?;
        self.trousseau.efface_cle_ephemere();
        self.trousseau.efface_mdp();

        Ok(trousseau_public_complet)
    }

    /// Collecte le mot de passe Feu via l'interface et le stocke dans le trousseau.
    ///
    /// Le mot de passe est encapsulé dans [`SecretBox`] dès réception.
    /// Il doit être effacé via [`efface_mdp_et_cle_ephemere`](Self::efface_mdp_et_cle_ephemere)
    /// dès qu'il n'est plus nécessaire.
    fn demande_mdp(&mut self, interface: &impl InterfaceFeuCore) {
        let mdp = SecretBox::new(Box::new(interface.demander_mdp("Entrez le mot de passe :")));

        self.trousseau.definit_mdp(mdp);
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
