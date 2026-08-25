// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Comptoirs — les dossiers du système de fichiers par lesquels les données
//! franchissent la frontière de Feu, dans un sens ou dans l'autre.
//!
//! L'OS est l'interface. Un [`ComptoirDepot`] fait entrer : l'utilisateur (ou
//! un script, un agent IA) y écrit librement, et Feu parcourt le dossier à la
//! fermeture pour le ranger sous un foyer et un classeur. Un
//! [`ComptoirTravail`] fait ressortir : le sous-arbre d'une ENU est matérialisé
//! sur le disque pour y être modifié, et le comptoir retient la racine sortie.
//!
//! Les deux sont ouverts puis refermés par le [`Scribe`](super::Scribe), à qui
//! appartient tout ce qui touche au contenu du dossier.

use std::{
    fs::{DirBuilder, remove_dir_all},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
};

use crate::{ErreurFeuApplication, ResultFeuApplication, fiche::Fiche};

/// Dossier OS servant de point de dépôt.
///
/// Créé à l'ouverture par [`ouvrir`](ComptoirDepot::ouvrir), parcouru à la
/// fermeture par le [`Scribe`](super::Scribe). Chaque comptoir est lié à un foyer et un
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
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeDossierDejaExistant`] si le
    /// chemin est déjà pris — un comptoir n'écrase pas un dossier existant.
    /// Propage [`ErreurFeuApplication::IoError`] si la création échoue
    /// (permissions insuffisantes, système de fichiers en lecture seule).
    pub(super) fn ouvrir(&self) -> ResultFeuApplication<()> {
        if self.chemin.exists() {
            return Err(ErreurFeuApplication::ScribeDossierDejaExistant(
                self.chemin.clone(),
            ));
        }
        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&self.chemin)?;

        Ok(())
    }

    /// Supprime le dossier physique du comptoir et tout son contenu résiduel.
    ///
    /// Appelée par le [`Scribe`](super::Scribe) à la fermeture, une fois les fichiers parcourus
    /// et déposés. Récursive ([`remove_dir_all`]) : le dossier disparaît avec ce
    /// qu'il reste dedans.
    ///
    /// # Errors
    ///
    /// Propage [`ErreurFeuApplication::IoError`] si le dossier est absent ou si
    /// la suppression échoue.
    pub(super) fn supprimer(&self) -> ResultFeuApplication<()> {
        remove_dir_all(&self.chemin)?;

        Ok(())
    }
}

/// Dossier OS portant un sous-arbre d'ENU sorti pour être modifié.
///
/// Le [`Scribe`](super::Scribe) n'en tient qu'un. De l'état de départ, le
/// comptoir ne retient que la racine : l'arbre entier se redescend depuis elle,
/// et la fermeture aura de quoi le comparer au dossier.
pub(super) struct ComptoirTravail {
    /// Chemin du dossier sur le système de fichiers.
    chemin: PathBuf,
    /// ENU racine dont le sous-arbre a été sorti dans le dossier.
    fiche_racine: Fiche,
}

impl ComptoirTravail {
    /// Construit un [`ComptoirTravail`] sans toucher au système de fichiers.
    ///
    /// Aucun pendant de [`ComptoirDepot::ouvrir`] ici : le dossier est celui que
    /// la sortie du sous-arbre vient de créer, il existe déjà.
    pub(super) fn new(chemin: PathBuf, fiche_racine: Fiche) -> Self {
        Self {
            chemin,
            fiche_racine,
        }
    }

    /// Retourne le chemin du dossier physique.
    pub(super) fn chemin(&self) -> &PathBuf {
        &self.chemin
    }

    /// Retourne la fiche de la racine sortie.
    pub(super) fn fiche_racine(&self) -> Fiche {
        self.fiche_racine.clone()
    }

    /// Supprime le dossier physique du comptoir et tout son contenu résiduel.
    ///
    /// Récursive ([`remove_dir_all`]) : ce que l'utilisateur a laissé dans le
    /// dossier disparaît avec lui.
    ///
    /// # Errors
    ///
    /// Propage [`ErreurFeuApplication::IoError`] si le dossier est absent ou si
    /// la suppression échoue.
    pub(super) fn supprimer(&self) -> ResultFeuApplication<()> {
        remove_dir_all(&self.chemin)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Tests en ligne : ce qui se prouve sans monter de pile.
    //!
    //! Un comptoir n'est qu'un dossier de l'OS et quelques champs — il ne
    //! signe rien, ne chiffre rien, n'a besoin ni de noyau allumé ni de foyer
    //! ouvert. Un `TempDir` suffit, là où `src/scribe/tests.rs` monte une pile
    //! réelle pour éprouver l'enveloppe et sa signature.
    //!
    //! Le **rangement** du contenu d'un comptoir n'est pas ici : il appartient à
    //! [`Scribe::fermeture_comptoir_depot`](super::super::Scribe), donc au haut.
    //!
    //! [`ComptoirTravail`] n'a **pas** de test en ligne : ne créant pas son
    //! dossier, il n'a ni refus d'écraser ni permissions à éprouver, et le reste
    //! rendrait ses champs. Son ouverture est éprouvée par `src/tests.rs`.

    use std::{fs::metadata, os::unix::fs::PermissionsExt};

    use tempfile::TempDir;

    use crate::ResultFeuApplication;

    use super::*;

    /// Cycle de vie d'un [`ComptoirDepot`] : le dossier n'existe qu'entre
    /// `ouvrir` et `supprimer`, en `0o700`, et ces deux-là refusent l'un le
    /// chemin déjà pris, l'autre le dossier déjà absent.
    #[test]
    fn cycle_comptoir_depot() -> ResultFeuApplication<()> {
        let tmp = TempDir::new()?;

        // Création du chemin et du comptoir
        let chemin = tmp.path().to_path_buf().join("test_comptoir_depot");
        let comptoir = ComptoirDepot::new(chemin.clone(), 2, 5);

        // Le dossier n'existe pas encore
        assert!(!comptoir.chemin().exists());

        // Création du dossier
        comptoir.ouvrir()?;

        assert!(comptoir.chemin().exists());

        let mode = metadata(comptoir.chemin())?.permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        // On peut pas créer un comptoir sur le même chemin
        assert!(matches!(
            comptoir.ouvrir(),
            Err(ErreurFeuApplication::ScribeDossierDejaExistant(_))
        ));

        // Suppression du dossier
        comptoir.supprimer()?;

        // Le dossier n'existe plus
        assert!(!comptoir.chemin().exists());

        // Erreur quand on veut supprimer le comptoir déjà supprimé
        assert!(comptoir.supprimer().is_err());

        Ok(())
    }
}
