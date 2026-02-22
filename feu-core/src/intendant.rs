//! L'intendant est le gardien des affaires internes de l'instance Feu.
//! Il est l'unique point d'accès au système de fichiers pour tout ce qui
//! concerne les données locales — configuration globale (`feu.toml`),
//! dossiers des foyers, coffres, registres et clés.
//!
//! Il maintient en mémoire la configuration globale et l'ensemble des
//! foyers actifs. Cette centralisation est un invariant de sécurité et
//! de cohérence du protocole.

pub(crate) mod erreur;

pub(crate) struct Intendant {}

impl Intendant {
    /// Crée l'intendant de [`Feu`]
    pub(crate) fn new() -> Self {
        Intendant {}
    }
}
