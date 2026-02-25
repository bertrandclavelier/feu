//! Trousseau cryptographique du cryptographe.
//!
//! Ce module gère le stockage en mémoire de l'ensemble des secrets actifs
//! d'une session Feu : mot de passe, clés de signature et de chiffrement
//! par foyer.
//!
//! Toutes les données sensibles sont zéroïsées à la destruction via le
//! crate `zeroize`. Le cycle de vie des secrets peut aussi être géré
//! manuellement par appel explicite à `.zeroize()`.
//!
//! Ce module est strictement interne au module `cryptographe` —
//! aucune structure n'est accessible depuis l'extérieur.
//!
//! # État initial
//!
//! À l'instanciation, le trousseau est vide : `mdp` et
//! `paire_signature_noeud` sont à `None`, `cles_foyers` est un vecteur
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
//! - [`PaireCles`] — paire de clés asymétriques (privée + publique)
//! - [`Cle`] — clé cryptographique brute zéroïsée
//! - [`MotDePasse`] — secret textuel zéroïsé (mot de passe, seed)

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct Cle(Vec<u8>);

#[derive(Zeroize, ZeroizeOnDrop)]
struct MotDePasse(String);

struct PaireCles {
    privee: Cle,
    publique: Cle,
}

struct TrousseauFoyer {
    cle_chiffrement: Cle,
    paire_signature: PaireCles,
    paire_chiffrement: PaireCles,
    cles_chiffrement_classeurs: Vec<Cle>,
}

pub(super) struct Trousseau {
    mdp: Option<MotDePasse>,
    paire_signature_noeud: Option<PaireCles>,
    cles_foyers: Vec<TrousseauFoyer>,
}

impl Trousseau {
    /// Fonction qui crée un trousseau vide.
    pub(super) fn new() -> Self {
        Self {
            mdp: None,
            paire_signature_noeud: None,
            cles_foyers: Vec::new(),
        }
    }
}
