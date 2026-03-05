// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! Représentation en mémoire du fichier de configuration `feu.toml`.
//!
//! [`FeuToml`] est le miroir exact de la structure TOML sur disque.
//! Il est chargé en mémoire au démarrage et maintenu à jour tout au
//! long de la session. Chaque modification est écrite de manière
//! atomique sur le disque par le [`Gardien`](super::Gardien).
//!
//! # Cycle de vie
//!
//! ## Initialisation d'un nœud vierge
//! [`FeuToml::new`] crée la structure initiale — sans foyer. Le premier
//! foyer est ajouté explicitement via [`FeuToml::ajoute_nouveau_foyer_dans_feu_toml`] après
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

use super::erreur::ResultGardien;
use chrono::Utc;
use serde::{Deserialize, Serialize};

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
    /// doit être ajouté via [`ajoute_nouveau_foyer_dans_feu_toml`](Self::ajoute_nouveau_foyer_dans_feu_toml)
    /// après la génération des clés cryptographiques.
    pub(super) fn new() -> Self {
        Self {
            meta: Meta::new(),
            feu: Feu::new(),
            foyers: Vec::new(),
        }
    }

    /// Enregistre un nouveau foyer dans la liste.
    ///
    /// Attribue au foyer l'index de dérivation courant (`prochain_index`),
    /// enregistre l'adresse `.onion` fournie par le cryptographe et horodate
    /// la création en UTC au format RFC 3339. L'index est incrémenté après
    /// l'ajout pour préparer le prochain foyer.
    pub(super) fn ajoute_nouveau_foyer_dans_feu_toml(&mut self, onion: String) {
        self.foyers.push(Foyer {
            cree_le: Utc::now().to_rfc3339(),
            index_courant: self.feu.prochain_index,
            index_revoques: Vec::new(),
            onion,
        });
        self.feu.prochain_index += 1;
    }

    /// Sérialise la structure en texte TOML.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la sérialisation échoue.
    pub(super) fn toml_en_texte(&self) -> ResultGardien<String> {
        Ok(toml::to_string(self)?)
    }
}
