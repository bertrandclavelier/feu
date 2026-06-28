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

mod comptoir;
mod enu;
pub(super) mod erreur;

use data_encoding::HEXLOWER;
use std::{
    collections::HashMap,
    fs::{DirBuilder, read},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
};

use feu_noyau::FeuNoyau;
use walkdir::WalkDir;

use crate::{
    SessionApplication,
    scribe::{
        comptoir::ComptoirDepot,
        enu::{Carte, Enu},
        erreur::{ErreurScribe, ResultScribe},
    },
};

/// L'ID fourni ne correspond à aucun comptoir de dépôt actif dans
/// [`Scribe::comptoirs_depot`].
const ERR_SCR_001: &str = "SCR-001 > Index du comptoir invalide";
/// Aucune entrée de répertoire trouvée pendant le parcours — comptoir vide
/// ou parcours interrompu avant d'atteindre le dossier racine.
const ERR_SCR_002: &str = "SCR-002 > Dépôt de données incomplet";

/// Tenant de la couche ENU — créé et maintient `~/.feu/enu/`.
///
/// Activé à l'allumage du nœud, désactivé à l'extinction. Le dossier
/// `enu/` est créé avec les permissions `rwx------` (0o700), cohérent
/// avec le reste de `~/.feu/`.
pub(super) struct Scribe {
    /// `true` si le Scribe a été activé (nœud allumé).
    est_actif: bool,

    /// Comptoirs de dépôt actifs, indexés par leur identifiant.
    comptoirs_depot: HashMap<usize, ComptoirDepot>,

    /// Prochain identifiant disponible pour un nouveau comptoir.
    prochain_id: usize,
}

impl Scribe {
    /// Construit un [`Scribe`] inactif.
    ///
    /// Le chemin `~/.feu` est résolu une fois via [`FeuNoyau::chemin_feu`]
    /// et stocké — pas de relecture de `$HOME` à chaque utilisation.
    pub(super) fn new() -> Self {
        Self {
            est_actif: false,
            comptoirs_depot: HashMap::new(),
            prochain_id: 0,
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

        if !donne_chemin_dossier_enu().exists() {
            DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(donne_chemin_dossier_enu())?;
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

    /// Ouvre un comptoir de dépôt au chemin donné.
    ///
    /// Crée le dossier physique sur le système de fichiers, l'enregistre
    /// dans [`comptoirs_depot`](Self::comptoirs_depot) et retourne son
    /// identifiant.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le dossier existe déjà ou ne peut pas être
    /// créé.
    pub(super) fn ouverture_comptoir_depot(
        &mut self,
        chemin: PathBuf,
        index_foyer: usize,
        index_classeur: usize,
    ) -> ResultScribe<usize> {
        let comptoir = ComptoirDepot::new(chemin, index_foyer, index_classeur);
        comptoir.ouvrir()?; // on s'assure qu'on peut l'ouvrir avant de le garder
        //
        self.comptoirs_depot.insert(self.prochain_id, comptoir);
        self.prochain_id += 1;

        Ok(self.prochain_id - 1)
    }

    /// Ferme un comptoir de dépôt et enregistre son contenu sous forme d'ENU.
    ///
    /// Parcourt le dossier en bottom-up avec [`WalkDir::contents_first`],
    /// dépose chaque fichier dans le classeur associé au comptoir via
    /// [`FeuNoyau::depot_donnees`], crée et signe les ENU correspondantes
    /// (CarteDonnée pour les fichiers, CarteRépertoire pour les dossiers),
    /// et les sauvegarde dans `~/.feu/enu/`.
    ///
    /// Le nom de chaque fichier et dossier est conservé comme métadonnée
    /// `"nom"` dans la carte. Le dossier racine du comptoir porte en plus la
    /// métadonnée `"_racine"` (valeur vide).
    ///
    /// # Retour
    ///
    /// Le [`hash_carte`](Enu::hash_carte) de l'ENUr racine du comptoir.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] (`SCR-001`) si l'ID du comptoir est
    /// invalide, [`ErreurScribe::Interne`] (`SCR-002`) si le comptoir est vide,
    /// et propage toute erreur de lecture ou dépôt.
    pub(super) fn fermeture_comptoir_depot(
        &mut self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        index_comptoir: usize,
    ) -> ResultScribe<[u8; 32]> {
        let Some(comptoir) = self.comptoirs_depot.remove(&index_comptoir) else {
            return Err(ErreurScribe::Interne(String::from(ERR_SCR_001)));
        };

        let mut enfants: HashMap<PathBuf, Vec<[u8; 32]>> = HashMap::new();

        for entree in WalkDir::new(comptoir.chemin()).contents_first(true) {
            let entree = entree?;
            let chemin_entree = entree.path().to_path_buf();

            // si c'est un fichier
            if entree.file_type().is_file() {
                let contenu = read(&chemin_entree)?;

                let hash_fichier = noyau.depot_donnees(
                    comptoir.index_foyer(),
                    comptoir.index_classeur(),
                    &contenu[..],
                )?;

                let hash_fichier: [u8; 32] = HEXLOWER
                    .decode(hash_fichier.as_bytes())
                    .map_err(|e| ErreurScribe::Interne(format!("hex invalide : {e}")))?
                    .try_into()
                    .unwrap();

                let mut carte = Carte::new_donnee(hash_fichier);
                carte.ajout_meta_carte("nom", &entree.file_name().to_string_lossy().to_string());

                let enu = Enu::new(
                    carte,
                    &noyau,
                    comptoir.index_foyer(),
                    String::from(session.braise_foyer(comptoir.index_foyer())?),
                )?;

                enu.sauvegarder()?;

                let hash_carte = enu.hash_carte();
                let parent = entree.path().parent().unwrap().to_path_buf();
                enfants.entry(parent).or_default().push(hash_carte);
            }

            // si c'est un répertoire
            if entree.file_type().is_dir() {
                let hashs = enfants.remove(&chemin_entree).unwrap_or_default();

                let mut carte = Carte::new_repertoire(hashs.into_iter().collect());

                carte.ajout_meta_carte("nom", &entree.file_name().to_string_lossy().to_string());

                if entree.depth() == 0 {
                    carte.ajout_meta_carte("_racine", "");
                }

                let enu = Enu::new(
                    carte,
                    &noyau,
                    comptoir.index_foyer(),
                    String::from(session.braise_foyer(comptoir.index_foyer())?),
                )?;

                enu.sauvegarder()?;

                let hash_carte = enu.hash_carte();
                if entree.depth() > 0 {
                    let parent = entree.path().parent().unwrap().to_path_buf();
                    enfants.entry(parent).or_default().push(hash_carte);
                }
                if entree.depth() == 0 {
                    return Ok(hash_carte);
                }
            }
        }

        Err(ErreurScribe::Interne(String::from(ERR_SCR_002)))
    }
}

/// Retourne le chemin `~/.feu/enu/`.
fn donne_chemin_dossier_enu() -> PathBuf {
    FeuNoyau::chemin_feu().join("enu/")
}
