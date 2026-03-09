// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! Représentation persistable du trousseau cryptographique.
//!
//! Ce module définit les structures sérialisables du trousseau — versions
//! "publiques" des clés, où chaque secret est chiffré avec AES-256-GCM
//! avant d'être stocké sur le disque.
//!
//! Aucune donnée sensible n'est stockée en clair : seul le sel Argon2id
//! et les clés publiques (Ed25519, X25519) apparaissent sans chiffrement.
//! Ces structures sont destinées à être écrites sur le disque par le gardien.

use super::erreur::{ErreurCryptographe, ResultCryptographe};
use crate::{MAX_CLASSEURS, MAX_FOYERS};

/// Représentation persistable des clés d'un foyer Feu.
///
/// Toutes les clés privées et symétriques sont chiffrées avec AES-256-GCM.
/// Chaque champ chiffré suit le format :
/// `[nonce (12 o.) | ciphertext + tag (48 o.)]` — soit 60 octets au total.
pub(crate) struct TrousseauFoyerPublic {
    pub(crate) cle_chiffrement: [u8; 60], // chiffrée
    pub(crate) cle_sig_privee: [u8; 60],  // chiffrée
    pub(crate) cle_sig_pub: [u8; 32],
    pub(crate) cle_chiff_privee: [u8; 60], // chiffrée
    pub(crate) cle_chiff_pub: [u8; 32],

    pub(crate) cles_chiffrement_classeurs: [Option<[u8; 60]>; MAX_CLASSEURS], // chiffrées
}

impl TrousseauFoyerPublic {
    /// Crée un [`TrousseauFoyerPublic`] avec un tableau de classeurs vide.
    ///
    /// Les clés de classeur sont ajoutées après construction via
    /// [`ajoute_cle_chiffrement_classeur`](Self::ajoute_cle_chiffrement_classeur)
    /// en précisant la `position` dans le tableau (0-indexé).
    pub(crate) fn new(
        cle_chiffrement: [u8; 60],
        cle_sig_privee: [u8; 60],
        cle_sig_pub: [u8; 32],
        cle_chiff_privee: [u8; 60],
        cle_chiff_pub: [u8; 32],
    ) -> Self {
        Self {
            cle_chiffrement,
            cle_sig_privee,
            cle_sig_pub,
            cle_chiff_privee,
            cle_chiff_pub,

            cles_chiffrement_classeurs: std::array::from_fn(|_| None),
        }
    }

    /// Insère une clé de chiffrement de classeur chiffrée à la `position` donnée.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `position >= MAX_CLASSEURS`.
    pub(crate) fn ajoute_cle_chiffrement_classeur(
        &mut self,
        cle: [u8; 60],
        position: usize,
    ) -> ResultCryptographe<()> {
        if position >= self.cles_chiffrement_classeurs.len() {
            return Err(ErreurCryptographe::Interne(String::from(
                "Erreur Ajout classeur chiffré",
            )));
        }
        self.cles_chiffrement_classeurs[position] = Some(cle);
        Ok(())
    }
}

/// Représentation persistable du trousseau complet d'un nœud Feu.
///
/// Contient les clés du nœud et l'ensemble des trousseau de foyers.
/// Le sel Argon2id est stocké en clair — il est nécessaire pour re-dériver
/// la clé éphémère lors du déchiffrement des clés privées.
pub(crate) struct TrousseauPublic {
    pub(crate) sel: [u8; 16],

    pub(crate) cle_sig_privee: [u8; 60], // chiffrée
    pub(crate) cle_sig_pub: [u8; 32],

    pub(crate) cles_foyers: [Option<(String, TrousseauFoyerPublic)>; MAX_FOYERS],
}

impl TrousseauPublic {
    /// Crée un [`TrousseauPublic`] avec un tableau de foyers vide.
    ///
    /// Les foyers sont ajoutés après construction via
    /// [`ajoute_trousseau_foyer_public`](Self::ajoute_trousseau_foyer_public)
    /// en précisant la `position` dans le tableau (0-indexé).
    pub(crate) fn new(sel: [u8; 16], cle_sig_privee: [u8; 60], cle_sig_pub: [u8; 32]) -> Self {
        Self {
            sel,
            cle_sig_privee,
            cle_sig_pub,
            cles_foyers: std::array::from_fn(|_| None),
        }
    }

    /// Insère le trousseau public d'un foyer à la `position` donnée.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `position >= MAX_FOYERS`.
    pub(crate) fn ajoute_trousseau_foyer_public(
        &mut self,
        onion: String,
        trousseau: TrousseauFoyerPublic,
        position: usize,
    ) -> ResultCryptographe<()> {
        if position >= self.cles_foyers.len() {
            return Err(ErreurCryptographe::Interne(String::from(
                "Erreur ajout trousseau foyer public",
            )));
        }
        self.cles_foyers[position] = Some((onion, trousseau));
        Ok(())
    }
}
