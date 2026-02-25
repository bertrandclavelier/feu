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
//! privées et la clé symétrique existent en clair. Le trousseau est
//! intégralement effacé à la fermeture du foyer.
//!
//! Aucun autre composant de Feu n'accède directement aux clés ou aux
//! données en clair — cette centralisation est un invariant de sécurité
//! fondamental du protocole.

use super::InterfaceFeuCore;
use bip39::{Language, Mnemonic};
use erreur::ResultCryptographe;
use trousseau::Trousseau;
use zeroize::Zeroize;

mod trousseau;

pub(crate) mod erreur;

pub(crate) struct Cryptographe {
    trousseau: Trousseau,
}

impl Cryptographe {
    /// Crée le cryptographe de [`Feu`].
    pub(crate) fn new() -> Self {
        Cryptographe {
            trousseau: Trousseau::new(),
        }
    }

    /// Génère une nouvelle seed BIP39 et initialise le trousseau pour un nouveau nœud.
    ///
    /// La seed mnémonique (12 mots, français) est affichée via `interface` une seule
    /// fois — l'utilisateur doit la noter avant de continuer.
    ///
    /// À partir de la seed, dérive et enregistre dans le trousseau de manière déterministe :
    /// - la paire de clés de signature du nœud (`m/0'`)
    /// - l'ensemble des clés du premier foyer (`m/1'`)
    ///
    /// La seed est zéroïsée avant le retour. Rien n'est écrit sur le disque —
    /// c'est le rôle de l'intendant.
    pub(crate) fn initialise_noeud_from_nouvelle_seed(
        &mut self,
        interface: &impl InterfaceFeuCore,
    ) -> ResultCryptographe<()> {
        let mnemonic = Mnemonic::generate_in(Language::French, 12)?;

        interface.afficher_min(
            "Cryptographe ›› ATTENTION ! La seed ci-après ne sera affichée qu'une
        seule fois avant d'être détruite. Elle doit impérativement être notée et mise en sécurité.",
        );
        for (i, mot) in mnemonic.words().enumerate() {
            interface.afficher_min(&format!("{i:<2}- {mot}"));
        }

        let mut seed_bytes: [u8; 64] = mnemonic.to_seed(""); // passphrase vide

        // ajoute la paire de clé noeud au trousseau à partir de la seed
        self.trousseau.ajouter_paire_noeud(&seed_bytes);
        interface.afficher(
            "Cryptographe ›› La paire de clés signature du nœud Feu a été générée et mise
            dans mon trousseau.",
        );

        // ajoute le trousseau du premier foyer à partir de la seed
        self.trousseau.ajouter_trousseau_foyer(&seed_bytes, 1)?;
        interface.afficher(
            "Cryptographe ›› Toutes les clés nécessaires au fonctionnement d'un premier foyer
            ont été générées et mises dans mon trousseau..",
        );

        seed_bytes.zeroize();
        Ok(())
    }
}
