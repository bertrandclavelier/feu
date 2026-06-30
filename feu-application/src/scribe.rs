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
pub mod enu;
pub(super) mod erreur;

use data_encoding::HEXLOWER;
use std::{
    collections::HashMap,
    fs::{DirBuilder, read, read_dir},
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

    /// Ferme un comptoir de dépôt : greffe son contenu sous `enu_racine_depot`,
    /// puis propage la nouvelle racine de dépôt jusqu'à `enu_racine_noeud`.
    ///
    /// Parcourt le dossier en bottom-up (`contents_first(true)`) : chaque
    /// fichier est déposé dans le classeur du comptoir via
    /// [`FeuNoyau::depot_donnees`], puis encapsulé dans une ENU signée de
    /// type [`Carte::Donnee`]. Chaque répertoire devient une
    /// [`Carte::Repertoire`] référençant ses enfants par leur `hash_carte`.
    /// Toutes les ENU produites sont sauvegardées dans `~/.feu/enu/`.
    ///
    /// Le nom de chaque entrée (fichier ou dossier) est conservé comme
    /// métadonnée `"nom"`. L'ENU racine enrichie reçoit la métadonnée
    /// `"_racine"` (valeur vide).
    ///
    /// Les entrées directement à la racine du comptoir (`depth == 1`) sont
    /// ajoutées comme enfants directs de `enu_racine_depot`. Les entrées plus
    /// profondes (`depth > 1`) forment des sous-arbres autonomes dont la
    /// racine devient enfant de `enu_racine_depot`. Le dossier physique du comptoir
    /// est supprimé en fin de traitement. Un comptoir vide est simplement
    /// supprimé sans modifier `enu_racine_depot`.
    ///
    /// # Retour
    ///
    /// La nouvelle ENU racine du nœud, après propagation — identique à
    /// `enu_racine_noeud` si le comptoir était vide.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] (`SCR-001`) si l'ID du comptoir est
    /// invalide. Propage toute erreur d'E/S, de dépôt de données ou de signature
    /// — y compris l'échec de signature si un foyer du chemin reconstruit par
    /// [`Enu::remplacer`] est fermé.
    pub(super) fn fermeture_comptoir_depot(
        &mut self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        index_comptoir: usize,
        enu_racine_depot: &Enu,
        enu_racine_noeud: &Enu,
    ) -> ResultScribe<Enu> {
        let Some(comptoir) = self.comptoirs_depot.remove(&index_comptoir) else {
            return Err(ErreurScribe::Interne(String::from(ERR_SCR_001)));
        };

        // foyer/classeur de destination, constants pour tout le comptoir
        let braise = session.braise_foyer(comptoir.index_foyer())?;

        let dir = read_dir(comptoir.chemin())?;
        if dir.count() == 0 {
            // comptoir vide : rien à greffer, le nœud est inchangé
            comptoir.supprimer()?;

            return Ok(enu_racine_noeud.clone());
        }

        // depth 1 → enfants directs du dépôt ; plus profond → rattachés à leur parent
        let mut nouveaux_enfants: Vec<[u8; 32]> = Vec::new();
        let mut enfants: HashMap<PathBuf, Vec<[u8; 32]>> = HashMap::new();

        // bottom-up : un dossier est traité après ses enfants, dont il référence les hashs
        for entree in WalkDir::new(comptoir.chemin()).contents_first(true) {
            let entree = entree?;
            if entree.depth() == 0 {
                // depth 0 = le comptoir lui-même : on greffe son contenu, pas lui
                continue;
            }
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
                carte.ajout_meta("nom", &entree.file_name().to_string_lossy().to_string());

                let enu = Enu::new(carte, noyau, session, braise)?;

                enu.sauvegarder()?;

                let hash_carte = enu.hash_carte();

                if entree.depth() == 1 {
                    nouveaux_enfants.push(hash_carte);
                } else {
                    let parent = entree.path().parent().unwrap().to_path_buf();
                    enfants.entry(parent).or_default().push(hash_carte);
                }
            }

            // si c'est un répertoire
            if entree.file_type().is_dir() {
                let hashs = enfants.remove(&chemin_entree).unwrap_or_default();

                let mut carte = Carte::new_repertoire(hashs.into_iter().collect());

                carte.ajout_meta("nom", &entree.file_name().to_string_lossy().to_string());

                let enu = Enu::new(carte, noyau, session, braise)?;

                enu.sauvegarder()?;

                let hash_carte = enu.hash_carte();
                if entree.depth() == 1 {
                    nouveaux_enfants.push(hash_carte);
                } else {
                    let parent = entree.path().parent().unwrap().to_path_buf();
                    enfants.entry(parent).or_default().push(hash_carte);
                }
            }
        }

        // greffe : le contenu de premier niveau devient enfant du dépôt
        let mut nouvelle_carte = enu_racine_depot.carte().clone();

        nouvelle_carte.ajout_meta("_racine", "");
        for h in &nouveaux_enfants {
            nouvelle_carte.ajout_hash_donnee(h)?;
        }

        let nouvelle_enu_racine_depot =
            Enu::new(nouvelle_carte, noyau, session, enu_racine_depot.braise())?;

        nouvelle_enu_racine_depot.sauvegarder()?;

        // remonte la nouvelle racine de dépôt jusqu'à la racine du nœud
        let racine_finale = Enu::remplacer(
            enu_racine_noeud,
            &enu_racine_depot.hash_carte(),
            &nouvelle_enu_racine_depot,
            noyau,
            session,
        )?;

        comptoir.supprimer()?;

        Ok(racine_finale)
    }
}

/// Retourne le chemin `~/.feu/enu/`.
fn donne_chemin_dossier_enu() -> PathBuf {
    FeuNoyau::chemin_feu().join("enu/")
}
