//! Représentation en mémoire du fichier de configuration `feu.toml`.
//!
//! [`FeuToml`] est le miroir exact de la structure TOML sur disque.
//! Il est chargé en mémoire au démarrage et maintenu à jour tout au
//! long de la session. Chaque modification est écrite de manière
//! atomique sur le disque par l'[`Intendant`](super::Intendant).
//!
//! # Cycle de vie
//!
//! ## Initialisation d'un nœud vierge
//! [`FeuToml::new`] crée la structure initiale — sans foyer. Le premier
//! foyer est ajouté explicitement via [`FeuToml::ajouter_foyer`] après
//! la génération des clés cryptographiques.
//!
//! ## Ouverture d'un nœud existant
//! La structure est désérialisée depuis `feu.toml` via [`serde`]
//! *(non encore implémenté)*.

/// Version du format de `feu.toml`.
///
/// Incrémentée à chaque changement de structure incompatible,
/// pour permettre la détection et la migration des anciens formats.
const FORMAT_VERSION: u32 = 1;

use serde::{Deserialize, Serialize};
use chrono::Utc;

/// Métadonnées du fichier `feu.toml` — section `[meta]`.
#[derive(Deserialize, Serialize)]
struct Meta {
    format_version: u32,
    cree_le: String,
}

impl Meta {
    /// Crée les métadonnées pour un nœud vierge.
    ///
    /// Enregistre la version courante du format et l'horodatage
    /// de création en UTC au format RFC 3339.
    fn new() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            cree_le: Utc::now().to_rfc3339(),
        }
    }
}

/// État global du nœud — section `[feu]`.
///
/// `prochain_index` est l'index de dérivation BIP32 à attribuer
/// au prochain foyer créé. Il est incrémenté à chaque nouveau foyer.
#[derive(Deserialize, Serialize)]
struct Feu {
    prochain_index: u32,
}

impl Feu {
    /// Crée l'état initial : le prochain foyer recevra l'index 1.
    fn new() -> Self {
        Self { prochain_index: 1 }
    }
}

/// Représentation d'un foyer — entrée `[[foyer]]`.
///
/// Un foyer est identifié par son adresse `.onion`, dérivée de la clé
/// de signature courante. L'`index_courant` est l'index de dérivation
/// BIP32 utilisé pour générer cette clé. Les `index_revoques` conservent
/// les anciens index dont les clés ont été révoquées.
#[derive(Deserialize, Serialize)]
struct Foyer {
    cree_le: String,
    index_courant: u32,
    index_revoques: Vec<u32>,
    onion: String,
}

impl Foyer {
    /// Crée un foyer à partir de son index de dérivation et de son adresse `.onion`.
    ///
    /// La liste des index révoqués est vide à la création.
    pub(super) fn new(index_courant: u32, onion: String) -> Self {
        Self {
            cree_le: Utc::now().to_rfc3339(),
            index_courant,
            index_revoques: Vec::new(),
            onion,
        }
    }
}

/// Miroir en mémoire de `feu.toml`.
///
/// Agrège les trois sections du fichier : `[meta]`, `[feu]` et `[[foyer]]`.
/// Le champ `foyers` est renommé `foyer` à la sérialisation pour correspondre
/// à la syntaxe TOML des tableaux de tables (`[[foyer]]`).
#[derive(Deserialize, Serialize)]
pub(super) struct FeuToml {
    meta: Meta,
    feu: Feu,
    #[serde(rename = "foyer")]
    foyers: Vec<Foyer>,
}

impl FeuToml {
    /// Crée la structure initiale pour un nœud vierge.
    ///
    /// La liste des foyers est vide à ce stade — le premier foyer
    /// doit être ajouté via [`ajouter_foyer`](Self::ajouter_foyer)
    /// après la génération des clés cryptographiques.
    pub(super) fn new() -> Self {
        Self {
            meta: Meta::new(),
            feu: Feu::new(),
            foyers: Vec::new(),
        }
    }

    /// Ajoute un foyer à la liste.
    pub(super) fn ajouter_foyer(&mut self, foyer: Foyer) {
        self.foyers.push(foyer);
    }
}
