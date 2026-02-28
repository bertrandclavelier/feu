//! L'intendant est le gardien des données locales de l'instance Feu.
//!
//! Il est l'unique point d'accès au système de fichiers pour tout ce qui
//! concerne les données locales — configuration globale, dossiers des
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
mod feu_toml;
pub(crate) mod erreur;

use carnet::Carnet;
use erreur::{ErreurIntendant, ResultIntendant};
use feu_toml::FeuToml;

/// Gardien des données locales du nœud Feu.
///
/// Orchestre les opérations sur le système de fichiers via son [`Carnet`]
/// et maintient en mémoire la configuration globale via [`FeuToml`].
/// Aucun autre composant n'accède directement au disque.
pub(crate) struct Intendant {
    carnet: Carnet,
    feu_toml: FeuToml,
}

impl Intendant {
    /// Crée l'intendant de [`Feu`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le carnet ne peut pas être initialisé —
    /// notamment si la variable d'environnement `HOME` est absente.
    pub(crate) fn new() -> ResultIntendant<Self> {
        Ok(Intendant {
            carnet: Carnet::new()?,
            feu_toml: FeuToml::new(),
        })
    }
}

// ── Opérations disque ────────────────────────────────────────────────────────

impl Intendant {
    /// Crée la structure de dossiers globale du nœud Feu sur le système de fichiers.
    ///
    /// Crée `~/.feu` et `~/.feu/.cles` avec les permissions `rwx------` (0o700).
    /// Cette opération n'est valide que pour un nœud vierge — elle échoue
    /// si l'arborescence existe déjà.
    ///
    /// Les dossiers des foyers ne sont pas créés ici — chaque foyer est
    /// ajouté individuellement après la génération de ses clés.
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

                Ok(())
            }
        }
    }

    /// Crée l'arborescence d'un nouveau foyer sur le système de fichiers.
    ///
    /// Crée `~/.feu/<onion>/` et `~/.feu/<onion>/.cles/` avec les permissions
    /// `rwx------` (0o700). Les deux dossiers sont créés en un seul appel
    /// grâce au mode récursif de [`Carnet::creer_dossier`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la création échoue — permissions insuffisantes,
    /// chemin invalide ou erreur d'entrée/sortie.
    pub(super) fn cree_arborescence_nouveau_foyer(&self, onion: &str) -> ResultIntendant<()> {
        self.carnet.creer_dossier(&self.carnet.donne_chemin_feu().join(onion).join(".cles"))?;
        Ok(())
    }
}

// ── Opérations mémoire ───────────────────────────────────────────────────────

impl Intendant {
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
