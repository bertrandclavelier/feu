//! `feu-core` est le cœur du protocole Feu.
//!
//! Il expose une interface unique — la structure [`Feu`] — qui orchestre
//! l'ensemble des composants internes : l'intendant, gardien des données
//! locales, et le cryptographe, garant de la sécurité cryptographique.
//!
//! Aucun composant interne n'est accessible directement depuis l'extérieur
//! du crate. Toute interaction avec Feu passe par [`Feu`] — cette
//! centralisation est un invariant de sécurité fondamental du protocole.

mod cryptographe;
mod erreur;
mod intendant;

use cryptographe::Cryptographe;
use intendant::Intendant;

pub use erreur::ErreurFeu;
pub use erreur::ResultFeu;

pub struct Feu {
    intendant: Intendant,
    cryptographe: Cryptographe,
}

impl Feu {
    /// Crée l'instance de [`Feu`] avec tout son personnel
    pub fn new() -> Self {
        Feu {
            intendant: Intendant::new(),
            cryptographe: Cryptographe::new(),
        }
    }
}
