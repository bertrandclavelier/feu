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
//! Rien n'est écrit sur le disque depuis ce module — c'est le rôle de
//! l'intendant.
//!
//! # Invariant de sécurité
//!
//! Aucun autre composant de Feu n'accède directement aux clés ou aux
//! données en clair. Cette centralisation est un invariant fondamental
//! du protocole.

use super::InterfaceFeuCore;
use bip39::{Language, Mnemonic};
use erreur::ResultCryptographe;
use secrecy::{ExposeSecret, SecretBox};
use trousseau::Trousseau;

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
    ///
    /// # Retour
    ///
    /// L'adresse `.onion` du premier foyer, dérivée de sa clé publique de signature.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la génération du mnémonique BIP39 échoue ou si
    /// la dérivation des clés du premier foyer échoue.
    pub(crate) fn initialise_noeud_from_nouvelle_seed(
        &mut self,
        interface: &impl InterfaceFeuCore,
    ) -> ResultCryptographe<String> {
        let onion: String;

        // Bloc encadrant la portée de seed_bytes
        {
            let seed_bytes: SecretBox<[u8; 64]>;

            // Bloc encadrant la portée de mnemonic
            {
                let mnemonic =
                    SecretBox::new(Box::new(Mnemonic::generate_in(Language::French, 12)?));

                interface.afficher_min(
                    "Cryptographe ›› ATTENTION ! La seed ci-après ne sera affichée qu'une
        seule fois avant d'être détruite. Elle doit impérativement être notée et mise en sécurité.",
                );
                for (i, mot) in mnemonic.expose_secret().words().enumerate() {
                    interface.afficher_min(&format!("{i:<2}- {mot}"));
                }

                seed_bytes = SecretBox::new(Box::new(mnemonic.expose_secret().to_seed(""))); // passphrase vide
            }

            // Ajoute la paire de clés du nœud au trousseau à partir de la seed
            self.trousseau.ajouter_paire_noeud(&seed_bytes);
            interface.afficher(
                "Cryptographe ›› La paire de clés signature du nœud Feu a été générée et mise
            dans mon trousseau.",
            );

            // Ajoute le trousseau du premier foyer et retourne son adresse .onion
            onion = self.trousseau.ajouter_trousseau_foyer(&seed_bytes, 1)?;
            interface.afficher(
                "Cryptographe ›› Toutes les clés nécessaires au fonctionnement d'un premier foyer
            ont été générées et mises dans mon trousseau.",
            );
        }
        Ok(onion)
    }

    /// Demande un nouveau mot de passe à l'utilisateur et le stocke dans le trousseau.
    ///
    /// Sollicite deux saisies successives via `interface`. Si elles diffèrent,
    /// l'utilisateur est invité à recommencer — la boucle se répète jusqu'à
    /// ce que les deux entrées correspondent.
    ///
    /// Le mot de passe est encapsulé dans [`SecretBox`] dès réception et
    /// remplace tout mot de passe précédemment défini (l'ancien est zéroïsé
    /// automatiquement au remplacement).
    pub(super) fn nouveau_mdp(&mut self, interface: &impl InterfaceFeuCore) {
        loop {
            let mdp = SecretBox::new(Box::new(interface.demander_mdp("Entrez un nouveau mot de passe :")));
            let mdp2 = SecretBox::new(Box::new(interface.demander_mdp("Entrez de nouveau le mot de passe :")));

            match mdp.expose_secret() == mdp2.expose_secret() {
                true => {
                    self.trousseau.definit_mdp(mdp);
                    break;
                }
                false => {
                    interface.afficher_min("Les deux entrées sont différentes. Recommencez...");
                }
            }
        }
        
    }
}
