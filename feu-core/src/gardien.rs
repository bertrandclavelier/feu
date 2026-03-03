//! Le gardien est l'unique point d'accès au système de fichiers pour les
//! données locales de l'instance Feu — configuration globale, dossiers des
//! foyers, coffres et clés.
//!
//! Il délègue la connaissance de l'arborescence à son [`Carnet`] et
//! orchestre les opérations sur le système de fichiers sans les exposer
//! à l'extérieur du module. Il maintient en mémoire la configuration
//! globale du nœud via [`FeuToml`] — miroir du fichier `feu.toml` sur
//! disque, écrit en dernière étape de chaque opération structurante.
//! Cette centralisation est un invariant de sécurité et de cohérence
//! du protocole.
//!
//! # Convention de nommage
//!
//! Les méthodes suivent une convention de verbe pour distinguer leur domaine :
//!
//! - `creer_` / `ecrire_` / `sauvegarder_` — opérations sur le disque
//! - `ajouter_` / `mettre_a_jour_` — opérations en mémoire uniquement

mod carnet;
pub(crate) mod erreur;
mod feu_toml;

use super::cryptographe::trousseau_public::TrousseauPublic;
use carnet::Carnet;
use erreur::{ErreurGardien, ResultGardien};
use feu_toml::FeuToml;

/// Gardien des données locales du nœud Feu.
///
/// Orchestre les opérations sur le système de fichiers via son [`Carnet`]
/// et maintient en mémoire la configuration globale via [`FeuToml`].
/// Aucun autre composant n'accède directement au disque.
pub(crate) struct Gardien {
    carnet: Carnet,
    feu_toml: FeuToml,
}

impl Gardien {
    /// Crée le gardien de [`Feu`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le carnet ne peut pas être initialisé —
    /// notamment si la variable d'environnement `HOME` est absente.
    pub(crate) fn new() -> ResultGardien<Self> {
        Ok(Gardien {
            carnet: Carnet::new()?,
            feu_toml: FeuToml::new(),
        })
    }
}

// ── Opérations disque ────────────────────────────────────────────────────────

impl Gardien {
    /// Ancre le nœud vierge sur le disque à partir du trousseau public.
    ///
    /// Délègue à [`Carnet::ecrire_trousseau_public`] la création de l'arborescence
    /// complète et l'écriture de toutes les clés chiffrées. Cette opération
    /// n'est valide que pour un nœud vierge — elle échoue si `~/.feu` existe déjà.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'arborescence existe déjà, ou si une
    /// opération disque échoue.
    pub(super) fn cree_premiere_arborescence(
        &self,
        trousseau_public: TrousseauPublic,
    ) -> ResultGardien<()> {
        match self.carnet.existe() {
            true => Err(ErreurGardien::Interne(String::from(
                "Une arborescence existe déjà.",
            ))),
            false => {
                // Écriture du trousseau public sur le disque
                self.carnet.ecrire_trousseau_public(trousseau_public)?;

                Ok(())
            }
        }
    }
}

// ── Opérations mémoire ───────────────────────────────────────────────────────

impl Gardien {
    /// Enregistre un nouveau foyer dans la configuration `feu.toml` en mémoire.
    ///
    /// Délègue à [`FeuToml`] l'ajout de l'entrée foyer avec l'adresse `.onion`
    /// fournie par le cryptographe. L'index de dérivation et l'horodatage
    /// sont gérés par [`FeuToml`].
    ///
    /// Cette méthode n'écrit rien sur le disque — la persistance est assurée
    /// en dernière étape par la sauvegarde de `feu.toml` *(non encore implémentée)*.
    pub(super) fn ajoute_nouveau_foyer_dans_feu_toml(&mut self, onion: String) {
        self.feu_toml.ajouter_nouveau_foyer(onion);
    }
}
