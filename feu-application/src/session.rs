// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! État applicatif de la session courante.
//!
//! [`SessionApplication`] centralise tout ce que `feu-application` doit
//! mémoriser entre les commandes : capacités du noyau, adresses et états
//! des foyers, clés publiques reçues via l'interface du noyau.
//!
//! Cette struct est peuplée par le pont interne vers le noyau pendant
//! l'exécution de chaque commande — jamais directement par la couche de
//! présentation.

use crate::erreur::{ErreurFeuApplication, ResultFeuApplication};
use feu_noyau::{
    MAX_CLASSEURS, MAX_FOYERS, MAX_TAILLE_BLOB, MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE,
    MAX_TAILLE_SIGNATURE,
};

/// État applicatif de la session courante.
///
/// Regroupe les capacités du noyau (limites de taille, nombre de foyers) et
/// l'état dynamique de la session (adresses onion, états d'ouverture, clés
/// publiques). Peuplé à l'allumage et mis à jour à chaque ouverture/fermeture
/// de foyer.
///
/// # Invariant
///
/// Les champs `nombre_foyers`, `nombre_classeurs` et `max_taille_*` sont des
/// constantes dérivées de `MAX_*` du noyau. Ils ne changent pas en cours de session.
#[derive(Clone)]
pub struct SessionApplication {
    /// Nombre maximum de foyers — dérivé de [`MAX_FOYERS`].
    pub nombre_foyers: usize,
    /// Nombre maximum de classeurs par foyer — dérivé de [`MAX_CLASSEURS`].
    pub nombre_classeurs: usize,
    /// Taille maximum d'un blob en octets — dérivée de [`MAX_TAILLE_BLOB`].
    pub max_taille_blob: usize,
    /// Taille maximum d'un message à chiffrer asymétriquement.
    pub max_taille_chiffrement_asymetrique: usize,
    /// Taille maximum d'un message à signer.
    pub max_taille_signature: usize,
    /// Adresses `.onion` des foyers — indexées par position.
    onion_foyers: [String; MAX_FOYERS],
    /// État d'ouverture de chaque foyer — `true` si ouvert.
    etat_foyers: [bool; MAX_FOYERS],
    /// Clé publique de signature Ed25519 du nœud — reçue à l'allumage.
    cle_publique_sig_noeud: [u8; 32],
    /// Clés publiques de signature Ed25519 des foyers — reçues à l'ouverture.
    cle_publique_sig_foyers: [[u8; 32]; MAX_FOYERS],
    /// Clés publiques de chiffrement ML-KEM-768 des foyers — reçues à l'ouverture.
    cle_publique_chif_foyers: [[u8; 1184]; MAX_FOYERS],
}

impl SessionApplication {
    /// Crée une session vide : capacités initialisées depuis les constantes noyau,
    /// foyers fermés, clés à zéro. Les clés sont peuplées par le pont interne
    /// vers le noyau lors de la construction de `FeuApplication`.
    pub fn new() -> Self {
        Self {
            nombre_foyers: MAX_FOYERS,
            nombre_classeurs: MAX_CLASSEURS,
            max_taille_blob: MAX_TAILLE_BLOB,
            max_taille_chiffrement_asymetrique: MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE,
            max_taille_signature: MAX_TAILLE_SIGNATURE,
            onion_foyers: std::array::from_fn(|_| String::new()),
            etat_foyers: std::array::from_fn(|_| false),
            cle_publique_sig_noeud: [0u8; 32],
            cle_publique_sig_foyers: std::array::from_fn(|_| [0u8; 32]),
            cle_publique_chif_foyers: std::array::from_fn(|_| [0u8; 1184]),
        }
    }

    /// Retourne l'adresse `.onion` du foyer à la position `index_foyer`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `index_foyer >= MAX_FOYERS`.
    pub fn onion_foyer(&self, index_foyer: usize) -> ResultFeuApplication<&str> {
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuApplication::Standard(String::from(
                "index_foyer trop élevé",
            )));
        }
        Ok(&self.onion_foyers[index_foyer])
    }

    /// Enregistre l'adresse `.onion` du foyer à la position `index_foyer`.
    ///
    /// Appelé par [`RecepteurNoyau`] lors de l'allumage du nœud.
    pub(crate) fn definit_onion_foyer(&mut self, index_foyer: usize, onion: String) {
        self.onion_foyers[index_foyer] = onion;
    }

    /// Retourne une vue immuable sur le tableau des états d'ouverture des foyers.
    ///
    /// Permet à l'appelant d'itérer pour repérer les positions ouvertes sans
    /// connaître `MAX_FOYERS` ni passer par [`Self::etat_foyer`] index par index.
    /// Préserve l'encapsulation : le tableau reste privé en écriture, seul
    /// `feu-application` peut le muter via `definit_etat_foyer`.
    pub fn etat_foyers(&self) -> &[bool] {
        &self.etat_foyers
    }

    /// Retourne l'état d'ouverture du foyer à la position `index_foyer`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `index_foyer >= MAX_FOYERS`.
    pub fn etat_foyer(&self, index_foyer: usize) -> ResultFeuApplication<bool> {
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuApplication::Standard(String::from(
                "index_foyer trop élevé",
            )));
        }
        Ok(self.etat_foyers[index_foyer])
    }

    /// Indique si tous les foyers sont fermés.
    ///
    /// Retourne `true` quand chaque entrée d'`etat_foyers` est à `false` —
    /// état initial de la session ou résultat d'une fermeture exhaustive.
    /// Court-circuite à la première ouverture rencontrée.
    ///
    /// Précondition utilisée par
    /// [`commande_extinction_noeud`](crate::FeuApplication::commande_extinction_noeud)
    /// pour refuser l'extinction tant qu'un foyer est ouvert.
    pub fn foyers_fermes(&self) -> bool {
        self.etat_foyers.iter().all(|&b| !b)
    }

    /// Retourne le nombre de foyers actuellement ouverts.
    ///
    /// Itère sur `etat_foyers` et compte les entrées à `true`. Complément de
    /// [`foyers_fermes`](Self::foyers_fermes) : quand
    /// [`foyers_fermes`](Self::foyers_fermes) répond à la précondition de
    /// [`commande_extinction_noeud`](crate::FeuApplication::commande_extinction_noeud),
    /// `nombre_foyers_ouverts` alimente la couche de présentation pour décider,
    /// par exemple, quelles touches activer dans la table de dispatch.
    pub fn nombre_foyers_ouverts(&self) -> usize {
        self.etat_foyers.iter().filter(|&&b| b).count()
    }

    /// Met à jour l'état d'ouverture du foyer à la position `index_foyer`.
    ///
    /// Appelé par [`RecepteurNoyau`] après ouverture ou fermeture d'un foyer.
    pub(crate) fn definit_etat_foyer(&mut self, index_foyer: usize, etat: bool) {
        self.etat_foyers[index_foyer] = etat;
    }

    /// Enregistre la clé publique de signature Ed25519 du nœud.
    ///
    /// Appelé par [`RecepteurNoyau`] à l'allumage du nœud.
    pub(crate) fn definit_cle_publique_sig_noeud(&mut self, cle: [u8; 32]) {
        self.cle_publique_sig_noeud = cle;
    }

    /// Retourne la clé publique de signature Ed25519 du nœud.
    pub fn cle_publique_sig_noeud(&self) -> [u8; 32] {
        self.cle_publique_sig_noeud
    }

    /// Retourne la clé publique de signature Ed25519 du foyer à la position `index_foyer`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `index_foyer >= MAX_FOYERS`.
    pub fn cle_publique_sig_foyer(&self, index_foyer: usize) -> ResultFeuApplication<[u8; 32]> {
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuApplication::Standard(String::from(
                "index_foyer trop élevé",
            )));
        }
        Ok(self.cle_publique_sig_foyers[index_foyer])
    }

    /// Enregistre la clé publique de signature Ed25519 du foyer.
    ///
    /// Appelé par [`RecepteurNoyau`] à l'ouverture du foyer.
    pub(crate) fn definit_cle_publique_sig_foyer(&mut self, index_foyer: usize, cle: [u8; 32]) {
        self.cle_publique_sig_foyers[index_foyer] = cle;
    }

    /// Retourne la clé publique de chiffrement ML-KEM-768 du foyer à la position `index_foyer`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `index_foyer >= MAX_FOYERS`.
    pub fn cle_publique_chif_foyer(&self, index_foyer: usize) -> ResultFeuApplication<[u8; 1184]> {
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuApplication::Standard(String::from(
                "index_foyer trop élevé",
            )));
        }
        Ok(self.cle_publique_chif_foyers[index_foyer])
    }

    /// Enregistre la clé publique de chiffrement ML-KEM-768 du foyer.
    ///
    /// Appelé par [`RecepteurNoyau`] à l'ouverture du foyer.
    pub(crate) fn definit_cle_publique_chif_foyer(&mut self, index_foyer: usize, cle: [u8; 1184]) {
        self.cle_publique_chif_foyers[index_foyer] = cle;
    }
}

impl Default for SessionApplication {
    /// Délègue à [`SessionApplication::new`].
    fn default() -> Self {
        Self::new()
    }
}
