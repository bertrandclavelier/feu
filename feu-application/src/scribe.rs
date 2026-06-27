// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Scribe — tenue du dossier `~/.feu/enu/`.
//!
//! Le [`Scribe`] est le tenant applicatif de la couche ENU dans
//! `feu-application`. Il crée et maintient le dossier `enu/` à la racine
//! du nœud (`~/.feu/enu/`), **pas** dans un foyer. Ce choix permet de
//! consulter, naviguer et indexer les ENU même quand tous les foyers
//! sont fermés — les ENU sont en clair, leur intégrité est garantie par
//! la signature, pas par le chiffrement.
//!
//! Le Scribe est activé à l'allumage du nœud et désactivé à son extinction.
//! Il ignore ce qu'est un foyer : la résolution du blob (trouver le `.dat`
//! correspondant à un `hash_donnee`) est ailleurs.

pub(super) mod erreur;

use std::{fs::DirBuilder, os::unix::fs::DirBuilderExt, path::PathBuf};

use feu_noyau::FeuNoyau;

use crate::scribe::erreur::ResultScribe;

/// Tenant de la couche ENU — créé et maintient `~/.feu/enu/`.
///
/// Activé à l'allumage du nœud, désactivé à l'extinction. Le dossier
/// `enu/` est créé avec les permissions `rwx------` (0o700), cohérent
/// avec le reste de `~/.feu/`.
pub(super) struct Scribe {
    /// `true` si le Scribe a été activé (nœud allumé).
    est_actif: bool,
    /// Chemin racine du nœud `~/.feu` — résolu une fois à la construction.
    chemin_feu: PathBuf,
}

impl Scribe {
    /// Construit un [`Scribe`] inactif.
    ///
    /// Le chemin `~/.feu` est résolu une fois via [`FeuNoyau::chemin_feu`]
    /// et stocké — pas de relecture de `$HOME` à chaque utilisation.
    pub(super) fn new() -> Self {
        Self {
            est_actif: false,
            chemin_feu: FeuNoyau::chemin_feu(),
        }
    }

    /// Active le Scribe et crée le dossier `~/.feu/enu/` s'il est absent.
    ///
    /// Appelé par [`commande_allumage_noeud`](crate::FeuApplication::commande_allumage_noeud)
    /// après que le noyau a été allumé avec succès. Si le dossier `enu/` existe
    /// déjà (allumages ultérieurs), la création est sautée.
    ///
    /// Le dossier est créé avec les permissions `rwx------` (0o700).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la création du dossier échoue (permissions
    /// insuffisantes, système de fichiers en lecture seule).
    pub(super) fn activation(&mut self) -> ResultScribe<()> {
        self.est_actif = true;

        if !self.donne_chemin_dossier_enu().exists() {
            DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(self.donne_chemin_dossier_enu())?;
        }

        Ok(())
    }

    /// Désactive le Scribe.
    ///
    /// Appelé par [`commande_extinction_noeud`](crate::FeuApplication::commande_extinction_noeud).
    /// Ne supprime pas le dossier `enu/` — les ENU survivent à l'extinction.
    pub(super) fn desactivation(&mut self) {
        self.est_actif = false;
    }

    /// Retourne le chemin `~/.feu/enu/`.
    fn donne_chemin_dossier_enu(&self) -> PathBuf {
        self.chemin_feu.join("enu/")
    }
}
