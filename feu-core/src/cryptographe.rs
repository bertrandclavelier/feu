//! Le cryptographe est le gardien de la sécurité cryptographique de Feu.
//!
//! Il est l'unique composant autorisé à manipuler des données en clair —
//! toute opération de chiffrement, de déchiffrement ou de dérivation de
//! clés passe exclusivement par lui.
//!
//! Il a en charge la génération des seeds BIP39, la dérivation de la
//! paire maître via SLIP-0010 et des paires filles signature (Ed25519)
//! et chiffrement (X25519). Il maintient en mémoire le trousseau —
//! l'unique endroit où les clés privées et la clé symétrique existent
//! en clair. Le trousseau est intégralement effacé à la fermeture du foyer.
//!
//! Aucun autre composant de Feu n'accède directement aux clés ou aux
//! données en clair — cette centralisation est un invariant de sécurité
//! fondamental du protocole.

use trousseau::Trousseau;

mod trousseau;

pub(crate) mod erreur;

pub(crate) struct Cryptographe {
    trousseau: Trousseau,
}

impl Cryptographe {
    /// Crée le cryptographe de [`Feu`]
    pub(crate) fn new() -> Self {
        Cryptographe {
            trousseau: Trousseau::new(),
        }
    }
}
