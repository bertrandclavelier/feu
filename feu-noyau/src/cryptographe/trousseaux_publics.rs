// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Représentation persistable du trousseau cryptographique.
//!
//! Ce module définit les structures sérialisables du trousseau — versions
//! "publiques" des clés, où chaque secret est chiffré avec AES-256-GCM
//! avant d'être stocké sur le disque.
//!
//! Aucune donnée sensible n'est stockée en clair : seul le sel Argon2id
//! et les clés publiques (ML-DSA-87, ML-KEM-1024) apparaissent sans chiffrement.
//! Ces structures sont destinées à être écrites sur le disque par le gardien.

use crate::{Braise, ErreurFeuNoyau, MAX_CLASSEURS, MAX_FOYERS, ResultFeuNoyau};

/// Représentation persistable des clés d'un foyer Feu.
///
/// Toutes les clés privées et symétriques sont chiffrées avec AES-256-GCM.
/// Chaque champ chiffré suit le format :
/// `[nonce (12 o.) | ciphertext + tag (16 o.)]` — 28 + plaintext octets au total.
/// La plupart des clés font 32 o (→ 60 o chiffrées). La seed ML-KEM-1024 (privée)
/// fait 64 o (→ 92 o chiffrées).
pub(crate) struct TrousseauPublicFoyer {
    braise: Braise,

    cle_chiffrement: [u8; 60], // chiffrée
    cle_sig_privee: [u8; 60],  // chiffrée
    cle_sig_pub: [u8; 2592],
    cle_chiff_privee: [u8; 92], // chiffrée
    cle_chiff_pub: [u8; 1568],

    cles_chiffrement_classeurs: [Option<[u8; 60]>; MAX_CLASSEURS], // chiffrées
}

impl TrousseauPublicFoyer {
    /// Crée un [`TrousseauPublicFoyer`] avec le tableau de classeurs vide.
    ///
    /// Les clés de classeur sont ajoutées après construction via
    /// [`ajoute_cle_chiffrement_classeur`](Self::ajoute_cle_chiffrement_classeur).
    pub(crate) fn new(
        braise: Braise,
        cle_chiffrement: [u8; 60],
        cle_sig_privee: [u8; 60],
        cle_sig_pub: [u8; 2592],
        cle_chiff_privee: [u8; 92],
        cle_chiff_pub: [u8; 1568],
    ) -> Self {
        Self {
            braise,
            cle_chiffrement,
            cle_sig_privee,
            cle_sig_pub,
            cle_chiff_privee,
            cle_chiff_pub,
            cles_chiffrement_classeurs: [None; MAX_CLASSEURS],
        }
    }

    /// Retourne l'adresse `.braise` du foyer.
    pub(crate) fn donne_braise(&self) -> Braise {
        self.braise
    }

    /// Retourne la clé symétrique AES-256-GCM du foyer — chiffrée, 60 octets.
    pub(crate) fn donne_cle_chiffrement(&self) -> [u8; 60] {
        self.cle_chiffrement
    }

    /// Retourne la clé privée de signature ML-DSA-87 du foyer — seed chiffrée, 60 octets.
    pub(crate) fn donne_cle_sig_privee(&self) -> [u8; 60] {
        self.cle_sig_privee
    }

    /// Retourne la clé publique de signature ML-DSA-87 du foyer — 2592 octets.
    pub(crate) fn donne_cle_sig_pub(&self) -> [u8; 2592] {
        self.cle_sig_pub
    }

    /// Retourne la clé privée de chiffrement ML-KEM-1024 du foyer — chiffrée, 92 octets.
    pub(crate) fn donne_cle_chiff_privee(&self) -> [u8; 92] {
        self.cle_chiff_privee
    }

    /// Retourne la clé publique de chiffrement ML-KEM-1024 du foyer — 1568 octets.
    pub(crate) fn donne_cle_chiff_pub(&self) -> [u8; 1568] {
        self.cle_chiff_pub
    }

    /// Retourne la clé de chiffrement AES-256-GCM du classeur à l'`index` donné — chiffrée, 60 octets.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si aucune clé n'est présente à cet index.
    pub(crate) fn donne_cle_chiffrement_classeur(
        &self,
        index_classeur: usize,
    ) -> ResultFeuNoyau<&[u8; 60]> {
        if index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeuNoyau::IndexClasseurInvalide(index_classeur));
        }
        if let Some(cle) = &self.cles_chiffrement_classeurs[index_classeur] {
            Ok(cle)
        } else {
            Err(ErreurFeuNoyau::CryptographeCleChiffrementClasseurAbstente(
                index_classeur,
            ))
        }
    }

    /// Insère la clé de chiffrement d'un classeur à l'`index` donné — chiffrée, 60 octets.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `index >= MAX_CLASSEURS`.
    pub(crate) fn ajoute_cle_chiffrement_classeur(
        &mut self,
        cle: [u8; 60],
        index_classeur: usize,
    ) -> ResultFeuNoyau<()> {
        if index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeuNoyau::IndexClasseurInvalide(index_classeur));
        }
        self.cles_chiffrement_classeurs[index_classeur] = Some(cle);
        Ok(())
    }
}

/// Représentation persistable des clés du nœud Feu.
///
/// Contient la paire de signature du nœud et le sel Argon2id.
/// Le sel est stocké en clair — il est re-dérivable depuis la seed en cas de perte du disque.
pub(crate) struct TrousseauPublicNoeud {
    sel: [u8; 16],

    cle_sig_privee: [u8; 60], // chiffrée
    cle_sig_pub: [u8; 2592],
}

impl TrousseauPublicNoeud {
    /// Crée un [`TrousseauPublicNoeud`].
    pub(crate) fn new(sel: [u8; 16], cle_sig_privee: [u8; 60], cle_sig_pub: [u8; 2592]) -> Self {
        Self {
            sel,
            cle_sig_privee,
            cle_sig_pub,
        }
    }

    /// Retourne le sel Argon2id du nœud — 16 octets, non chiffré.
    pub(crate) fn donne_sel(&self) -> [u8; 16] {
        self.sel
    }

    /// Retourne la clé privée de signature ML-DSA-87 du nœud — seed chiffrée, 60 octets.
    pub(crate) fn donne_cle_sig_privee(&self) -> [u8; 60] {
        self.cle_sig_privee
    }

    /// Retourne la clé publique de signature ML-DSA-87 du nœud — 2592 octets.
    pub(crate) fn donne_cle_sig_pub(&self) -> [u8; 2592] {
        self.cle_sig_pub
    }
}

/// Représentation persistable du trousseau complet d'un nœud Feu.
///
/// Agrège un [`TrousseauPublicNoeud`] et l'ensemble des [`TrousseauPublicFoyer`].
/// Utilisé lors de l'initialisation pour écrire l'intégralité des clés sur le disque en une passe.
pub(crate) struct TrousseauPublicComplet {
    trousseau_public_noeud: TrousseauPublicNoeud,
    trousseaux_publics_foyers: [Option<TrousseauPublicFoyer>; MAX_FOYERS],
}

impl TrousseauPublicComplet {
    /// Crée un [`TrousseauPublicComplet`] avec le tableau de foyers vide.
    ///
    /// Les foyers sont ajoutés après construction via
    /// [`ajoute_trousseau_foyer_public`](Self::ajoute_trousseau_foyer_public).
    pub(crate) fn new(trousseau_public_noeud: TrousseauPublicNoeud) -> Self {
        Self {
            trousseau_public_noeud,
            trousseaux_publics_foyers: std::array::from_fn(|_| None),
        }
    }

    /// Retourne une référence au [`TrousseauPublicNoeud`].
    pub(crate) fn donne_trousseau_public_noeud(&self) -> &TrousseauPublicNoeud {
        &self.trousseau_public_noeud
    }

    /// Retourne une référence au [`TrousseauPublicFoyer`] à l'`index` donné.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si aucun foyer n'est présent à cet index.
    pub(crate) fn donne_trousseau_public_foyer(
        &self,
        index_foyer: usize,
    ) -> ResultFeuNoyau<&TrousseauPublicFoyer> {
        if let Some(trousseau) = &self.trousseaux_publics_foyers[index_foyer] {
            Ok(trousseau)
        } else {
            Err(ErreurFeuNoyau::CryptographeTrousseauFoyerAbsent(
                index_foyer,
            ))
        }
    }

    /// Insère un [`TrousseauPublicFoyer`] à l'`index` donné.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `index >= MAX_FOYERS`.
    pub(crate) fn ajoute_trousseau_foyer_public(
        &mut self,
        trousseau_public_foyer: TrousseauPublicFoyer,
        index_foyer: usize,
    ) -> ResultFeuNoyau<()> {
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuNoyau::IndexFoyerInvalide(index_foyer));
        }
        self.trousseaux_publics_foyers[index_foyer] = Some(trousseau_public_foyer);
        Ok(())
    }
}
