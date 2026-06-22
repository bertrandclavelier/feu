// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Définit les types d'erreurs du cryptographe.
//!
//! [`ErreurCryptographe`] couvre l'ensemble des erreurs pouvant survenir
//! lors des opérations cryptographiques — génération de seed, dérivation
//! de clés, chiffrement et déchiffrement.
//!
//! Ce type est interne à `feu-noyau` — il n'est jamais exposé directement
//! à l'extérieur du crate. Il remonte vers [`ErreurFeuNoyau`] via une
//! conversion explicite en message textuel, préservant ainsi
//! l'encapsulation des détails d'implémentation.
//!
//! # Conversion des erreurs tierces
//!
//! Deux mécanismes coexistent selon que l'erreur source implémente
//! `std::error::Error` ou non.
//!
//! **`#[from]` (thiserror)** — quand l'erreur source implémente
//! `std::error::Error`, thiserror génère automatiquement un `From`.
//! Le type d'erreur original est préservé dans la variante — il peut être
//! inspecté ou ré-affiché. Exemple : `Bip39(#[from] bip39::Error)`.
//!
//! **`From` manuel + `String`** — quand l'erreur source n'implémente PAS
//! `std::error::Error`, `#[from]` est inutilisable. La variante stocke alors
//! un `String` extrait par `.to_string()`. Le type original est perdu — seul
//! le message textuel est conservé. Trois cas ici :
//!
//! - `hkdf::InvalidLength` : implémente `Display` mais pas `std::error::Error` —
//!   `.to_string()` suffit.
//! - `aes_gcm::Error` : implémente `Display` mais pas `std::error::Error` —
//!   `.to_string()` suffit.
//! - `data_encoding::DecodePartial` : n'implémente ni `Display` ni
//!   `std::error::Error` — le message est extrait de son champ `error: DecodeError`
//!   qui, lui, implémente `Display`.

use aes_gcm::Error;
use data_encoding::DecodePartial;
use hkdf::InvalidLength;
use std::io::Error as ErreurIO;
use thiserror::Error;

pub(crate) type ResultCryptographe<T> = Result<T, ErreurCryptographe>;

#[derive(Error, Debug)]
pub(crate) enum ErreurCryptographe {
    /// Erreur interne générique — portée directement par un message textuel.
    #[error("CRY > {0}")]
    Interne(String),

    /// Erreur émise par `bip39` lors de la génération ou du parsing du mnémonique.
    ///
    /// `bip39::Error` implémente `std::error::Error` — `#[from]` génère
    /// automatiquement la conversion. Le type original est préservé dans la variante.
    #[error("CRY > {0}")]
    Bip39(#[from] bip39::Error),

    /// Erreur HKDF — longueur de sortie invalide, stockée en texte.
    ///
    /// `hkdf::InvalidLength` n'implémente pas `std::error::Error`, ce qui rend
    /// `#[from]` inutilisable. La conversion est manuelle (voir `impl From` ci-dessous) :
    /// l'erreur est convertie en `String` via `.to_string()` — le type original est perdu.
    #[error("CRY > {0}")]
    Hkdf(String),

    /// Erreur Argon2id — dérivation de la clé éphémère depuis le mot de passe.
    ///
    /// `argon2::Error` implémente `std::error::Error` (feature `std`) — `#[from]`
    /// génère automatiquement la conversion. Le type original est préservé dans
    /// la variante.
    #[error("CRY > {0}")]
    Argon2(#[from] argon2::Error),

    /// Erreur AES-256-GCM — chiffrement ou déchiffrement d'une clé.
    ///
    /// `aes_gcm::Error` n'implémente pas `std::error::Error`, ce qui rend
    /// `#[from]` inutilisable. La conversion est manuelle (voir `impl From` ci-dessous) :
    /// l'erreur est convertie en `String` via `.to_string()` — le type original est perdu.
    #[error("CRY > {0}")]
    AesGcm(String),

    /// Erreur d'entrée/sortie — lecture ou écriture de fichier.
    ///
    /// `std::io::Error` implémente `std::error::Error` — `#[from]` génère
    /// automatiquement la conversion. Le type original est préservé dans la variante.
    #[error("CRY > {0}")]
    Io(#[from] ErreurIO),

    /// Erreur de décodage hexadécimal — décodage partiel ou caractère invalide.
    ///
    /// `data_encoding::DecodePartial` n'implémente ni `std::error::Error` ni
    /// `Display`, ce qui rend `#[from]` inutilisable. La conversion est manuelle
    /// (voir `impl From` ci-dessous) : le message est extrait du champ `error`
    /// (de type `DecodeError`, qui implémente `Display`) — le type original est perdu.
    #[error("CRY > {0}")]
    DecodePartial(String),

    #[error("CRY > {0}")]
    SignatureError(#[from] ed25519_dalek::SignatureError),
}

impl From<DecodePartial> for ErreurCryptographe {
    /// Convertit `data_encoding::DecodePartial` en [`ErreurCryptographe::DecodePartial`].
    ///
    /// `DecodePartial` n'implémente ni `Display` ni `std::error::Error`.
    /// Le message est extrait de son champ `error: DecodeError` qui implémente
    /// `Display` — c'est la seule information récupérable sans le trait bound
    /// qu'exige `#[from]`.
    fn from(e: DecodePartial) -> Self {
        ErreurCryptographe::DecodePartial(e.error.to_string())
    }
}

impl From<hkdf::InvalidLength> for ErreurCryptographe {
    /// Convertit `hkdf::InvalidLength` en [`ErreurCryptographe::Hkdf`].
    ///
    /// `hkdf::InvalidLength` implémente `Display` mais pas `std::error::Error`.
    /// `.to_string()` suffit pour extraire le message — c'est tout ce qui
    /// peut être récupéré sans le trait bound qu'exige `#[from]`.
    fn from(e: InvalidLength) -> Self {
        ErreurCryptographe::Hkdf(e.to_string())
    }
}

impl From<aes_gcm::Error> for ErreurCryptographe {
    /// Convertit `aes_gcm::Error` en [`ErreurCryptographe::AesGcm`].
    ///
    /// `aes_gcm::Error` implémente `Display` mais pas `std::error::Error`.
    /// `.to_string()` suffit pour extraire le message — c'est tout ce qui
    /// peut être récupéré sans le trait bound qu'exige `#[from]`.
    fn from(e: Error) -> Self {
        ErreurCryptographe::AesGcm(e.to_string())
    }
}
