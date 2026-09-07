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
//! Il ne porte que le contenu : ni le classeur de destination, ni le hash, qui
//! sont des arguments de [`ecrit_blob`](super::Archiviste::ecrit_blob).

use std::io::{Read, Write};

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use zeroize::Zeroize;

use crate::{ErreurFeuNoyau, MAX_TAILLE_BLOB, ResultFeuNoyau, TAILLE_CHUNK};

/// Tampon de transfert d'un blob, effacé de la mémoire à sa destruction.
///
/// Le contenu est clair à l'aller et chiffré au retour — le tiroir ne distingue
/// pas les deux, c'est l'étape du cycle qui le dit. La [`SecretBox`] lui apporte
/// la zéroïsation à la destruction et interdit un `Debug` distrait.
///
/// # Cycle de vie
///
/// ```text
/// Archiviste → FeuNoyau : tiroir vide
/// FeuNoyau : remplir(source)                          ← blob en clair
/// FeuNoyau → Cryptographe : lire_blob()
/// Cryptographe → FeuNoyau : blob chiffré + hash
/// FeuNoyau : remplace_blob()
/// FeuNoyau → Archiviste : ecrit_blob(classeur, hash, tiroir)  ← blob chiffré
/// ```
///
/// # Invariants
///
/// La taille du blob est bornée à [`MAX_TAILLE_BLOB`] — toute tentative de
/// dépasser cette limite retourne une erreur immédiate.
pub(crate) struct Tiroir(SecretBox<Vec<u8>>);

impl Tiroir {
    /// Crée un [`Tiroir`] vide, prêt à être rempli par [`remplir`](Self::remplir).
    pub(super) fn new() -> Self {
        Self(SecretBox::new(Box::new(Vec::new())))
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
        let blob = self.0.expose_secret_mut();

        if !blob.is_empty() {
            return Err(ErreurFeuNoyau::ArchivisteTiroirBlobNonvide);
        }

        let mut chunk = [0u8; TAILLE_CHUNK];

        loop {
            let n = source.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if blob.len() + n > MAX_TAILLE_BLOB {
                return Err(crate::ErreurFeuNoyau::TailleMaxDepasseeBlob(blob.len() + n));
            }
            blob.extend_from_slice(&chunk[0..n]);
        }

        Ok(())
    }

    /// Écrit le contenu du tiroir dans `destination`, puis zéroïse le blob.
    ///
    /// La zéroïsation est immédiate et ne dépend pas de la destruction du
    /// tiroir : le contenu ne survit pas à l'écriture.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si l'écriture dans `destination` échoue.
    pub(crate) fn envoyer_et_vider(&mut self, mut destination: impl Write) -> ResultFeuNoyau<()> {
        destination.write_all(self.0.expose_secret())?;
        self.0.zeroize();

        Ok(())
    }

    /// Retourne le contenu du blob sous forme de slice.
    pub(crate) fn lire_blob(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Zéroïse le blob courant puis le remplace par `nouveau_blob`.
    ///
    /// Utilisé par [`FeuNoyau`](crate::FeuNoyau) pour substituer le blob en clair par
    /// le blob chiffré retourné par le Cryptographe. Le blob en clair est
    /// zéroïsé avant remplacement — aucun octet sensible ne subsiste en mémoire.
    pub(crate) fn remplace_blob(&mut self, nouveau_blob: Vec<u8>) {
        self.0.zeroize();
        *self.0.expose_secret_mut() = nouveau_blob;
    }
}
