// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Objet de transfert éphémère entre l'Archiviste et le Cryptographe.
//!
//! [`Tiroir`] transporte un blob depuis sa source jusqu'à son classeur en
//! passant par le Cryptographe. Il est créé vide par l'Archiviste, rempli
//! en clair par [`FeuNoyau`](crate::FeuNoyau), chiffré par le Cryptographe, puis
//! retourné à l'Archiviste pour écriture sur disque.
//!
//! Le blob en clair est zéroïsé dès qu'il est remplacé par le blob chiffré —
//! aucun octet sensible ne subsiste en mémoire après chiffrement.

use std::io::{Read, Write};

use zeroize::Zeroize;

use crate::{ErreurFeuNoyau, IndexClasseur, MAX_TAILLE_BLOB, ResultFeuNoyau, TAILLE_CHUNK};

/// Objet de transfert éphémère entre l'Archiviste et le Cryptographe.
///
/// Le tiroir transporte un blob depuis la source jusqu'au classeur en passant
/// par le Cryptographe. Il est créé vide par l'Archiviste, rempli en clair par
/// [`FeuNoyau`](crate::FeuNoyau), chiffré par le Cryptographe, puis retourné à l'Archiviste
/// pour écriture sur disque.
///
/// # Cycle de vie
///
/// ```text
/// Archiviste → FeuNoyau : tiroir vide
/// FeuNoyau : remplir(source)               ← blob en clair
/// FeuNoyau → Cryptographe : lire_blob()
/// Cryptographe → FeuNoyau : blob chiffré + hash
/// FeuNoyau : remplace_blob() + definit_hash()
/// FeuNoyau → Archiviste : ecrit_blob(tiroir)   ← blob chiffré
/// ```
///
/// # Invariants
///
/// - La taille du blob est bornée à [`MAX_TAILLE_BLOB`] — toute tentative de
///   dépasser cette limite retourne une erreur immédiate.
/// - `lire_hash` retourne une erreur si le hash n'a pas encore été défini.
pub(crate) struct Tiroir {
    /// Le classeur de destination, fixé à la construction.
    index_classeur: IndexClasseur,
    /// Le contenu, clair à l'aller, chiffré au retour — le tiroir ne distingue
    /// pas les deux, c'est l'étape du cycle qui le dit.
    blob: Vec<u8>,
    /// Hash du clair, `None` tant que le Cryptographe ne l'a pas posé.
    hash: Option<[u8; 32]>,
}

impl Tiroir {
    /// Crée un [`Tiroir`] vide pour le classeur à `index_classeur`.
    ///
    /// Le blob est vide et le hash absent — prêt à être rempli via [`remplir`](Self::remplir).
    pub(super) fn new(index_classeur: IndexClasseur) -> Self {
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
    /// # Errors
    ///
    /// Retourne [`ErreurFeuNoyau::ArchivisteTiroirBlobNonvide`] si le tiroir
    /// détient déjà un blob, [`ErreurFeuNoyau::TailleMaxDepasseeBlob`] si le
    /// total atteint [`MAX_TAILLE_BLOB`], ou propage l'échec de lecture de
    /// `source`.
    pub(crate) fn remplir(&mut self, mut source: impl Read) -> ResultFeuNoyau<()> {
        if !self.blob.is_empty() {
            return Err(ErreurFeuNoyau::ArchivisteTiroirBlobNonvide);
        }

        let mut chunk = [0u8; TAILLE_CHUNK];

        loop {
            let n = source.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if self.blob.len() + n > MAX_TAILLE_BLOB {
                return Err(crate::ErreurFeuNoyau::TailleMaxDepasseeBlob(
                    self.blob.len() + n,
                ));
            }
            self.blob.extend_from_slice(&chunk[0..n]);
        }

        Ok(())
    }

    /// Écrit le contenu du tiroir dans `destination` et zéroïse le blob.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si l'écriture dans `destination` échoue.
    pub(crate) fn vider(&mut self, mut destination: impl Write) -> ResultFeuNoyau<()> {
        destination.write_all(&self.blob)?;
        self.blob.zeroize();
        Ok(())
    }

    /// Retourne le contenu du blob sous forme de slice.
    pub(crate) fn lire_blob(&self) -> &[u8] {
        &self.blob
    }

    /// Zéroïse le blob courant puis le remplace par `nouveau_blob`.
    ///
    /// Utilisé par [`FeuNoyau`](crate::FeuNoyau) pour substituer le blob en clair par
    /// le blob chiffré retourné par le Cryptographe. Le blob en clair est
    /// zéroïsé avant remplacement — aucun octet sensible ne subsiste en mémoire.
    pub(crate) fn remplace_blob(&mut self, nouveau_blob: Vec<u8>) {
        self.blob.zeroize();
        self.blob = nouveau_blob;
    }

    /// Enregistre le hash SHA3-256 du blob en clair dans le tiroir.
    ///
    /// Doit être appelé après chiffrement, avant [`ecrit_blob`](super::Archiviste::ecrit_blob).
    /// Le hash est calculé sur le clair — il sert de nom de fichier dans le classeur.
    pub(crate) fn definit_hash(&mut self, hash: &[u8; 32]) {
        self.hash = Some(*hash);
    }

    /// Retourne le hash SHA3-256 du blob en clair.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si [`definit_hash`](Self::definit_hash) n'a pas encore été appelé.
    pub(crate) fn lire_hash(&self) -> ResultFeuNoyau<[u8; 32]> {
        let Some(hash) = &self.hash else {
            return Err(ErreurFeuNoyau::ArchivisteTiroirSansHash);
        };

        Ok(*hash)
    }

    /// Retourne l'index du classeur de destination.
    pub(crate) fn lire_index_classeur(&self) -> IndexClasseur {
        self.index_classeur
    }
}
