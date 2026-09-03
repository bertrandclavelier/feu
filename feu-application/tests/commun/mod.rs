// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Ce que les deux cibles de test de la crate ont en commun.
//!
//! Chaque cible le déclare par un `mod commun;` et en compile sa propre copie.
//! Aucune n'en consomme la totalité, d'où le `#![allow(dead_code)]`.

#![allow(dead_code)]
use std::{
    cell::RefCell,
    collections::HashSet,
    fs::{create_dir, read_to_string, write},
    path::{Path, PathBuf},
};

use feu_application::{Descendants, InterfaceFeuApplication, SessionApplication, fiche::Fiche};
use rand::{Rng, distributions::Alphanumeric};
use secrecy::SecretString;
use walkdir::WalkDir;

/// Implémentation d'[`InterfaceFeuApplication`] pour les tests.
///
/// Répond par des valeurs fixes et retient la dernière [`SessionApplication`]
/// notifiée — seul moyen d'observer ce qu'une commande a publié.
pub(crate) struct InterfaceTest {
    /// Servi à chaque `demander_mdp`. Ouverture et fermeture d'un foyer doivent
    /// voir le même, sinon le déchiffrement échoue.
    mot_de_passe: SecretString,

    /// Dernière session notifiée. `RefCell` parce que le trait notifie sous
    /// `&self` : l'écriture ne peut venir que d'une mutabilité intérieure.
    session_application: RefCell<Option<SessionApplication>>,
}

impl InterfaceTest {
    /// Construit l'interface avec le mot de passe qu'elle servira.
    pub(crate) fn new(mot_de_passe: &str) -> Self {
        Self {
            mot_de_passe: SecretString::from(mot_de_passe),
            session_application: RefCell::new(None),
        }
    }

    /// Clone de la dernière session notifiée — `None` tant que rien n'a été
    /// notifié, et de nouveau `None` après extinction.
    pub(crate) fn session_application(&self) -> Option<SessionApplication> {
        self.session_application.borrow().clone()
    }
}

impl InterfaceFeuApplication for InterfaceTest {
    /// Sert toujours le même mot de passe : ouverture et fermeture d'un foyer
    /// doivent le voir identique, sinon le déchiffrement échoue.
    fn demander_mdp(&self) -> Option<SecretString> {
        Some(self.mot_de_passe.clone())
    }

    /// Jetée : aucun test n'a besoin de relire la seed. La retenir demanderait
    /// un second champ que rien ne consulterait.
    fn recevoir_seed(&self, _mots: &[&str]) {}

    /// Confirme toujours — sans quoi l'initialisation du noyau s'interromprait.
    fn confirmer_enregistrement_seed(&self) -> bool {
        true
    }

    /// Retient la session notifiée, seul état que l'interface conserve : c'est
    /// par elle que les tests constatent ce qu'une commande a publié.
    fn recevoir_session_application(&self, session_application: Option<SessionApplication>) {
        *self.session_application.borrow_mut() = session_application;
    }
}

/// Chaîne alphanumérique aléatoire de `n` caractères.
pub(crate) fn chaine_aleatoire(n: usize) -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}

/// Écrit `nom` dans `destination`, garni de `nombre_caracteres` aléatoires, et
/// rend ce contenu — de quoi le comparer au clair déchiffré du blob.
pub(crate) fn nouveau_fichier(destination: &Path, nom: &str, nombre_caracteres: usize) -> String {
    let contenu = chaine_aleatoire(nombre_caracteres);

    write(destination.join(nom), contenu.clone()).unwrap();

    contenu
}

/// Peuple `chemin` sur trois niveaux, aux noms fixes : `fichier_1` et
/// `dossier_1`, puis `fichier_2` et `dossier_2` dedans, enfin `fichier_3`.
///
/// Contenus aléatoires, pour que deux appels ne se confondent pas.
pub(crate) fn remplir_dossier(chemin: &Path) {
    nouveau_fichier(chemin, "fichier_1", 100);

    let chemin_dossier1 = chemin.join("dossier_1");
    create_dir(&chemin_dossier1).unwrap();

    nouveau_fichier(&chemin_dossier1, "fichier_2", 100);

    let chemin_dossier2 = chemin_dossier1.join("dossier_2");
    create_dir(&chemin_dossier2).unwrap();

    nouveau_fichier(&chemin_dossier2, "fichier_3", 100);
}

/// Relit récursivement `chemin` en un ensemble `(chemin relatif, contenu)`, un
/// par fichier — de quoi comparer deux arborescences sans dépendre de l'ordre.
pub(crate) fn lire_arborescence(chemin: &Path) -> HashSet<(PathBuf, String)> {
    let mut resultat = HashSet::new();

    for entree in WalkDir::new(chemin).min_depth(1) {
        let entree = entree.unwrap();

        if entree.file_type().is_file() {
            let chemin_relatif = entree.path().strip_prefix(chemin).unwrap().to_path_buf();
            let contenu = read_to_string(entree.path()).unwrap();
            resultat.insert((chemin_relatif, contenu));
        }
    }

    resultat
}

/// Rend la [`Fiche`] du premier descendant dont la méta `nom` vaut `nom`.
///
/// La racine du nœud n'a pas cette méta : elle ne sort jamais par mégarde.
pub(crate) fn donne_fiche_descendant(descendants: Descendants<'_>, nom: &str) -> Option<Fiche> {
    descendants
        .flatten()
        .map(|(_, fiche)| fiche)
        .find(|fiche| fiche.carte().metas().get("nom").is_some_and(|n| n == nom))
}
