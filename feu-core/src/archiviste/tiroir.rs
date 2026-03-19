// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

use super::{ErreurArchiviste, ResultArchiviste};
use crate::MAX_TAILLE_BLOB;
use crate::TAILLE_CHUNK;
use std::io::Read;
use zeroize::Zeroize;

/// Objet de transfert éphémère entre l'Archiviste et le Cryptographe.
///
/// Le tiroir transporte un blob depuis la source jusqu'au classeur en passant
/// par le Cryptographe. Il est créé vide par l'Archiviste, rempli en clair par
/// [`Feu`](crate::Feu), chiffré par le Cryptographe, puis retourné à l'Archiviste
/// pour écriture sur disque.
///
/// # Cycle de vie
///
/// ```text
/// Archiviste → Feu : tiroir vide
/// Feu : remplir_tiroir(source)        ← blob en clair
/// Feu → Cryptographe : lire_blob()
/// Cryptographe → Feu : blob chiffré + hash
/// Feu : remplace_blob() + definit_hash()
/// Feu → Archiviste : ecrire_blob(tiroir)  ← blob chiffré
/// ```
///
/// # Invariants
///
/// - La taille du blob est bornée à [`MAX_TAILLE_BLOB`] — toute tentative de
///   dépasser cette limite retourne une erreur immédiate.
/// - `lire_hash` retourne une erreur si le hash n'a pas encore été défini.
pub(crate) struct Tiroir {
    index_classeur: usize,
    blob: Vec<u8>,
    hash: Option<[u8; 32]>,
}

impl Tiroir {
    pub(super) fn new(index_classeur: usize) -> Self {
        Self {
            index_classeur,
            blob: Vec::new(),
            hash: None,
        }
    }

    /// Lit les octets de `source` et les accumule dans le blob du tiroir.
    ///
    /// Lit par chunks de [`TAILLE_CHUNK`] octets. Retourne une erreur immédiate
    /// si le total dépasse [`MAX_TAILLE_BLOB`] — aucun octet supplémentaire n'est lu.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le tiroir n'est pas vide, si la lecture de `source`
    /// échoue, ou si la taille dépasse [`MAX_TAILLE_BLOB`].
    pub(crate) fn remplir_tiroir(&mut self, mut source: impl Read) -> ResultArchiviste<()> {
        if !self.blob.is_empty() {
            return Err(ErreurArchiviste::Interne(String::from(
                "Le tiroir n'est pas vide",
            )));
        }

        let mut chunk = [0u8; TAILLE_CHUNK];

        loop {
            let n = source.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if self.blob.len() + n > MAX_TAILLE_BLOB {
                return Err(ErreurArchiviste::Interne(String::from(
                    "Dépassement MAX_TAILLE_BLOB",
                )));
            }
            self.blob.extend_from_slice(&chunk[0..n]);
        }

        Ok(())
    }

    /// Retourne le contenu du blob sous forme de slice.
    pub(crate) fn lire_blob(&self) -> &[u8] {
        &self.blob
    }

    /// Zéroïse le blob courant puis le remplace par `nouveau_blob`.
    ///
    /// Utilisé par [`Feu`](crate::Feu) pour substituer le blob en clair par
    /// le blob chiffré retourné par le Cryptographe. Le blob en clair est
    /// zéroïsé avant remplacement — aucun octet sensible ne subsiste en mémoire.
    pub(crate) fn remplace_blob(&mut self, nouveau_blob: Vec<u8>) {
        self.blob.zeroize();
        self.blob = nouveau_blob;
    }

    /// Enregistre le hash SHA3-256 du blob en clair dans le tiroir.
    ///
    /// Doit être appelé après chiffrement, avant [`ecrire_blob`](super::Archiviste::ecrire_blob).
    /// Le hash est calculé sur le clair — il sert de nom de fichier dans le classeur.
    pub(crate) fn definit_hash(&mut self, hash: [u8; 32]) {
        self.hash = Some(hash);
    }

    /// Retourne le hash SHA3-256 du blob en clair.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si [`definit_hash`](Self::definit_hash) n'a pas encore été appelé.
    pub(crate) fn lire_hash(&self) -> ResultArchiviste<[u8; 32]> {
        let Some(hash) = self.hash else {
            return Err(ErreurArchiviste::Interne(String::from("Pas de hash")));
        };
        Ok(hash)
    }

    /// Retourne l'index du classeur de destination.
    pub(crate) fn lire_index_classeur(&self) -> usize {
        self.index_classeur
    }
}
