// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Définit les types d'erreurs de `feu-noyau`.
//!
//! [`ErreurFeuNoyau`] est l'unique type d'erreur exposé à l'extérieur du crate.
//! Il agrège les erreurs de chaque composant interne — chacun souverain
//! dans la définition de ses propres erreurs — et les fait remonter de
//! manière transparente vers l'appelant.
//!
//! [`ResultFeuNoyau<T>`] est l'alias de [`Result<T, ErreurFeuNoyau>`] utilisé dans
//! toutes les fonctions publiques de `feu-noyau`.

use crate::{
    archiviste::erreur::ErreurArchiviste, cryptographe::erreur::ErreurCryptographe,
    gardien::erreur::ErreurGardien,
};
use thiserror::Error;

/// Alias de [`Result`] utilisé par toutes les fonctions publiques de `feu-noyau`.
pub type ResultFeuNoyau<T> = Result<T, ErreurFeuNoyau>;

/// Type d'erreur unique exposé par `feu-noyau`.
///
/// Agrège deux familles de variantes :
///
/// - **Erreurs remontées d'un composant interne** (`Gardien`, `Cryptographe`,
///   `Archiviste`) — le type interne est encapsulé dans une `String` via
///   `.to_string()`, ce qui préserve l'encapsulation des détails
///   d'implémentation et évite toute fuite de type privé à travers l'API.
/// - **Erreurs propres à l'orchestration du noyau** — préconditions non
///   satisfaites, index hors bornes, état de session incohérent.
///
/// Le préfixe `NOY >` dans chaque message sert de marqueur de couche lorsque
/// les messages sont encapsulés par la couche applicative (`feu-application`).
#[derive(Error, Debug)]
pub enum ErreurFeuNoyau {
    /// Erreur remontée depuis le gardien — opération disque ou parsing échoué.
    /// Le message textuel provient du type d'erreur interne du gardien via `.to_string()`.
    #[error("NOY > {0}")]
    Gardien(String),

    /// Erreur remontée depuis le cryptographe — opération cryptographique échouée.
    /// Le message textuel provient du type d'erreur interne du cryptographe via `.to_string()`.
    #[error("NOY > {0}")]
    Cryptographe(String),

    /// Erreur remontée depuis l'archiviste — opération sur l'arborescence d'un foyer échouée.
    /// Le message textuel provient du type d'erreur interne de l'archiviste via `.to_string()`.
    #[error("NOY > {0}")]
    Archiviste(String),

    /// Un index de foyer ou de classeur fourni par l'appelant est hors bornes
    /// (`>= MAX_FOYERS` ou `>= MAX_CLASSEURS`).
    #[error("NOY > Index foyer ou classeur invalide")]
    IndexInvalide,

    /// Le nœud est déjà initialisé — une seed ne peut pas être fournie à [`FeuNoyau::new`]
    /// quand l'arborescence existe déjà.
    #[error("NOY > Nœud déjà initialisé — fourniture d'une seed impossible")]
    InitialisationNoeudImpossible,

    /// Tentative d'ouvrir un foyer déjà marqué comme ouvert dans la session.
    #[error("NOY > Impossible d'ouvrir un foyer déjà ouvert")]
    FoyerDejaOuvert,

    /// Opération nécessitant un foyer ouvert appelée sur un foyer fermé —
    /// les clés du trousseau ne sont pas disponibles en mémoire.
    #[error("NOY > Opération impossible sur foyer fermé")]
    FoyerFerme,

    /// Opération requérant que **tous** les foyers soient ouverts — typiquement
    /// un changement de mot de passe qui rechiffre l'intégralité du trousseau.
    #[error("NOY > Tous les foyers doivent être ouverts pour cette opération")]
    TousFoyersNonOuverts,

    /// État interne incohérent : un foyer est marqué ouvert dans la session
    /// mais l'emplacement correspondant d'`archivistes` est `None`. Ne devrait
    /// jamais se produire — signale un bug d'orchestration.
    #[error("NOY > Foyer ouvert sans archiviste (état interne incohérent)")]
    ArchivisteIndisponible,

    /// Taille de message dépassée pour une opération bornée :
    /// [`MAX_TAILLE_BLOB`](crate::MAX_TAILLE_BLOB),
    /// [`MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE`](crate::MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE)
    /// ou [`MAX_TAILLE_SIGNATURE`](crate::MAX_TAILLE_SIGNATURE).
    #[error("NOY > Dépassement taille autorisée pour cette opération")]
    TailleMaxDepassee,

    /// Le diagnostic préalable à une fermeture en secours a détecté une
    /// anomalie — le dossier clair du foyer n'est pas dans un état suffisant
    /// pour que la reconstruction du trousseau puisse aboutir.
    #[error("NOY > Check-up négatif pour fermeture en secours du foyer")]
    FermetureSecoursFoyerImpossible,

    /// L'adresse `.onion` fournie ou résolue depuis un index ne correspond
    /// à aucun foyer connu de la session.
    #[error("NOY > Adresse onion inconnue")]
    OnionIntrouvable,
}

impl From<ErreurGardien> for ErreurFeuNoyau {
    /// Convertit une erreur interne du gardien en [`ErreurFeuNoyau::Gardien`].
    ///
    /// Le type interne est perdu — seul le message textuel est propagé,
    /// préservant l'encapsulation des détails d'implémentation du gardien.
    fn from(e: ErreurGardien) -> Self {
        ErreurFeuNoyau::Gardien(e.to_string())
    }
}

impl From<ErreurCryptographe> for ErreurFeuNoyau {
    /// Convertit une erreur interne du cryptographe en [`ErreurFeuNoyau::Cryptographe`].
    ///
    /// Le type interne est perdu — seul le message textuel est propagé,
    /// préservant l'encapsulation des détails d'implémentation du cryptographe.
    fn from(e: ErreurCryptographe) -> Self {
        ErreurFeuNoyau::Cryptographe(e.to_string())
    }
}

impl From<ErreurArchiviste> for ErreurFeuNoyau {
    /// Convertit une erreur interne de l'archiviste en [`ErreurFeuNoyau::Archiviste`].
    ///
    /// Le type interne est perdu — seul le message textuel est propagé,
    /// préservant l'encapsulation des détails d'implémentation de l'archiviste.
    fn from(e: ErreurArchiviste) -> Self {
        ErreurFeuNoyau::Archiviste(e.to_string())
    }
}
