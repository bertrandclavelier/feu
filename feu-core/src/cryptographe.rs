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
use crate::cryptographe::flux_chiffre::Finalise;

use super::InterfaceFeuCore;
use aes_gcm::aead::KeyInit;
use aes_gcm::{Aes256Gcm, Key};
use bip39::{Language, Mnemonic};
use erreur::ResultCryptographe;
use flux_chiffre::{EcritureChiffree, LectureDechiffree};
use secrecy::{ExposeSecret, SecretBox};
use std::fs::File;
use std::io::{Read, Write};

use trousseau::Trousseau;
use trousseaux_publics::{TrousseauPublicComplet, TrousseauPublicFoyer, TrousseauPublicNoeud};

pub(crate) mod flux_chiffre;
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

        let resultat = self.trousseau.genere_trousseau_public()?;

        self.efface_mdp_et_cle_ephemere();

        Ok(resultat)
    }

    /// Crée un flux d'écriture chiffré AES-256-GCM-stream pour le foyer `onion`.
    ///
    /// Délègue la création de l'encrypteur à [`Trousseau::cree_stream_encryptor`] et
    /// retourne un [`EcritureChiffree`] prêt à recevoir les données à chiffrer.
    /// Le nonce est écrit en tête du fichier par [`EcritureChiffree`].
    ///
    /// # Prérequis
    ///
    /// Le foyer identifié par `onion` doit être présent dans le trousseau.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le foyer est introuvable ou si la création du flux échoue.
    pub(super) fn donne_ecriture_chiffree(
        &self,
        onion: &str,
        fichier: File,
    ) -> ResultCryptographe<impl Write + Finalise> {
        let (encryptor, nonce) = self.trousseau.cree_stream_encryptor(onion)?;

        Ok(EcritureChiffree::new(fichier, encryptor, nonce)?)
    }

    /// Crée un flux de lecture déchiffré AES-256-GCM-stream pour un foyer.
    ///
    /// Déchiffre la clé symétrique du foyer (`cle`) avec la clé éphémère du trousseau,
    /// construit le cipher AES-256-GCM correspondant et retourne un [`LectureDechiffree`]
    /// prêt à lire l'archive `<onion>.feu`. Le nonce est lu en tête du fichier.
    ///
    /// # Prérequis
    ///
    /// Le mot de passe doit pouvoir être collecté via `interface` — la clé éphémère
    /// est dérivée en interne avant le déchiffrement.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la dérivation de la clé éphémère échoue, si le déchiffrement
    /// de la clé symétrique échoue, ou si la lecture du nonce en tête de fichier échoue.
    pub(super) fn donne_lecture_dechiffree(
        &mut self,
        fichier: File,
        cle: [u8; 60],
        interface: &impl InterfaceFeuCore,
    ) -> ResultCryptographe<impl Read> {
        self.demande_mdp(interface);
        self.derivation_cle_ephemere()?;

        let cle_dechiffree = self.trousseau.dechiffre_cle(&cle)?;
        let key = Key::<Aes256Gcm>::from_slice(cle_dechiffree.expose_secret());
        let cipher = Aes256Gcm::new(key);

        Ok(LectureDechiffree::new(fichier, cipher)?)
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
