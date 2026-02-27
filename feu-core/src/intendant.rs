//! L'intendant est le gardien des données locales de l'instance Feu.
//!
//! Il est l'unique point d'accès au système de fichiers pour tout ce qui
//! concerne les données locales — configuration globale, dossiers des
//! foyers, coffres et clés.
//!
//! Il délègue la connaissance de l'arborescence à son [`Carnet`] et
//! orchestre les opérations sur le système de fichiers sans les exposer
//! à l'extérieur du module. Cette centralisation est un invariant de
//! sécurité et de cohérence du protocole.

mod carnet;
pub(crate) mod erreur;

use carnet::Carnet;
use erreur::{ErreurIntendant, ResultIntendant};

/// Gardien des données locales du nœud Feu.
///
/// Orchestre les opérations sur le système de fichiers via son [`Carnet`].
/// Aucun autre composant n'accède directement au disque.
pub(crate) struct Intendant {
    carnet: Carnet,
}

impl Intendant {
    /// Crée l'intendant de [`Feu`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le registre ne peut pas être initialisé —
    /// notamment si la variable d'environnement `HOME` est absente.
    pub(crate) fn new() -> ResultIntendant<Self> {
        Ok(Intendant {
            carnet: Carnet::new()?,
        })
    }

    /// Crée la première arborescence du nœud Feu sur le système de fichiers.
    ///
    /// Crée `~/.feu` et ses sous-dossiers structurels avec les permissions
    /// `rwx------` (0o700). Cette opération n'est valide que pour un nœud
    /// vierge — elle échoue si l'arborescence existe déjà.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'arborescence existe déjà, ou si une
    /// opération de création de dossier échoue.
    pub(super) fn cree_premiere_arborescence(&self) -> ResultIntendant<()> {
        match self.carnet.existe() {
            true => Err(ErreurIntendant::Interne(String::from(
                "Une arborescence existe déjà.",
            ))),
            false => {
                self.carnet.creer_dossier(&self.carnet.donne_chemin_feu())?;
                self.carnet.creer_dossier(&self.carnet.donne_chemin_feu().join(".cles"))?;
                self.carnet.creer_dossier(&self.carnet.donne_chemin_feu().join("foyer1"))?;
                self.carnet.creer_dossier(&self.carnet.donne_chemin_feu().join("foyer1/.cles"))?;
                
                Ok(())
            }
        }
    }
}
