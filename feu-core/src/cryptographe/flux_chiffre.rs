// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! Flux de chiffrement et déchiffrement par streaming.
//!
//! Ce module fournit les adaptateurs de flux chiffrés utilisés pour lire et
//! écrire des données chiffrées en AES-256-GCM sans charger l'intégralité du
//! contenu en mémoire.
//!
//! # Écriture chiffrée
//!
//! [`EcritureChiffree`] implémente [`std::io::Write`] — tout appelant qui
//! produit des données via `Write` (par exemple `tar::Builder`) peut les
//! chiffrer à la volée en écrivant dans une instance de cette struct.
//!
//! Le nonce de 7 octets est écrit en tête du fichier à la construction.
//! Les chunks sont chiffrés par `encrypt_next` au fil des appels à `write()`.
//! L'appelant doit appeler [`EcritureChiffree::finalise`] en fin de flux pour
//! clore le stream AES-GCM-SIV et écrire le tag final.
//!
//! # Structure
//!
//! - [`EcritureChiffree`] — adaptateur `Write` chiffrant vers un [`std::fs::File`]

use super::erreur::ResultCryptographe;
use aead::stream::EncryptorBE32;
use aes_gcm::Aes256Gcm;
use std::fs::File;
use std::io::Write;

pub(crate) trait Finalise {
    fn finalise(self) -> Result<(), String>;
}

pub(super) struct EcritureChiffree {
    fichier: File,
    encryptor: EncryptorBE32<Aes256Gcm>,
}

impl EcritureChiffree {
    /// Construit un flux d'écriture chiffré.
    ///
    /// Écrit `nonce` en tête de `fichier` avant tout chunk de données —
    /// le nonce doit être transmis hors bande au destinataire pour permettre
    /// le déchiffrement.
    ///
    /// `encryptor` est produit par [`super::Trousseau::cree_stream_encryptor`]
    /// qui génère également le nonce depuis la clé du foyer.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'écriture du nonce en tête du fichier échoue.
    pub(super) fn new(
        mut fichier: File,
        encryptor: EncryptorBE32<Aes256Gcm>,
        nonce: [u8; 7],
    ) -> ResultCryptographe<Self> {
        // Écriture du nonce en tête du fichier
        fichier.write_all(&nonce)?;
        Ok(Self { fichier, encryptor })
    }
}

impl Finalise for EcritureChiffree {
    /// Clôt le flux chiffré et écrit le tag final dans le fichier.
    ///
    /// Consomme `self` — après appel, [`EcritureChiffree`] n'est plus utilisable.
    /// Doit être appelé exactement une fois, après le dernier chunk de données.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le chiffrement du chunk final échoue ou si
    /// l'écriture dans le fichier échoue.
    fn finalise(mut self) -> Result<(), String> {
        let last_chunk = self
            .encryptor
            .encrypt_last(b"".as_ref())
            .map_err(|e| e.to_string())?;

        self.fichier
            .write_all(&last_chunk)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

impl Write for EcritureChiffree {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let chunk_chiffre = self
            .encryptor
            .encrypt_next(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        self.fichier.write_all(&chunk_chiffre)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(self.fichier.flush()?)
    }
}
