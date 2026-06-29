// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Comptoir de dépôt — point d'entrée unique pour injecter des données
//! dans Feu via un dossier du système de fichiers.
//!
//! Un [`ComptoirDepot`] est un dossier OS que le [`Scribe`] ouvre puis
//! referme. Chaque comptoir est associé à un foyer et un classeur de
//! destination. L'OS est l'interface : l'utilisateur (ou un script, un
//! agent IA) écrit librement dans le dossier, et Feu le parcourt à la
//! fermeture pour tout ranger.

use std::{
    fs::{DirBuilder, remove_dir_all},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
};

use crate::scribe::erreur::{ErreurScribe, ResultScribe};

/// Le dossier existe déjà — un comptoir ne peut pas écraser un dossier
/// existant.
const ERR_COM_D_001: &str = "COM_D-001 > Le dossier existe déjà";

/// Dossier OS servant de point de dépôt.
///
/// Créé à l'ouverture par [`ouvrir`](ComptoirDepot::ouvrir), parcouru à la
/// fermeture par le [`Scribe`]. Chaque comptoir est lié à un foyer et un
/// classeur de destination pour ses données.
pub(super) struct ComptoirDepot {
    /// Chemin du dossier sur le système de fichiers.
    chemin: PathBuf,
    /// Index du foyer propriétaire de ce comptoir.
    index_foyer: usize,
    /// Index du classeur de destination des données déposées.
    index_classeur: usize,
}

impl ComptoirDepot {
    /// Construit un [`ComptoirDepot`] sans créer le dossier physique.
    ///
    /// Le dossier n'est pas créé ici — appeler [`ouvrir`](ComptoirDepot::ouvrir)
    /// pour le rendre utilisable.
    pub(super) fn new(chemin: PathBuf, index_foyer: usize, index_classeur: usize) -> Self {
        Self {
            chemin,
            index_foyer,
            index_classeur,
        }
    }

    /// Retourne le chemin du dossier physique.
    pub(super) fn chemin(&self) -> &PathBuf {
        &self.chemin
    }

    /// Retourne l'index du foyer de destination des données.
    pub(super) fn index_foyer(&self) -> usize {
        self.index_foyer
    }

    /// Retourne l'index du classeur de destination des données.
    pub(super) fn index_classeur(&self) -> usize {
        self.index_classeur
    }

    /// Crée le dossier physique avec les permissions `rwx------` (0o700).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le dossier existe déjà ou si la création
    /// échoue (permissions insuffisantes, système de fichiers en lecture
    /// seule).
    pub(super) fn ouvrir(&self) -> ResultScribe<()> {
        if self.chemin.exists() {
            return Err(ErreurScribe::Interne(String::from(ERR_COM_D_001)));
        }
        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&self.chemin)?;

        Ok(())
    }

    /// Supprime le dossier physique du comptoir et tout son contenu résiduel.
    ///
    /// Appelée par le [`Scribe`] à la fermeture, une fois les fichiers parcourus
    /// et déposés. Récursive ([`remove_dir_all`]) : le dossier disparaît avec ce
    /// qu'il reste dedans.
    ///
    /// # Erreurs
    ///
    /// Propage une [`ErreurScribe::IoError`] si le dossier est absent ou si la
    /// suppression échoue.
    pub(super) fn supprimer(&self) -> ResultScribe<()> {
        remove_dir_all(&self.chemin)?;

        Ok(())
    }
}
