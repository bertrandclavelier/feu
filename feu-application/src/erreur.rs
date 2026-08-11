// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Définit les types d'erreurs de `feu-application`.
//!
//! [`ErreurFeuApplication`] est l'unique type d'erreur exposé à l'extérieur du crate.
//! Il reçoit les erreurs de `feu-noyau` et les erreurs propres à la couche applicative,
//! et les expose à `feu-tui` sans laisser traverser les types internes de `feu-noyau`.
//!
//! [`ResultFeuApplication<T>`] est l'alias de [`Result<T, ErreurFeuApplication>`] utilisé dans
//! toutes les fonctions publiques de `feu-application`.

use feu_noyau::ErreurFeuNoyau;
use thiserror::Error;

use crate::scribe::erreur::ErreurScribe;

/// Alias de [`Result`] utilisé par toutes les fonctions publiques de `feu-application`.
pub type ResultFeuApplication<T> = Result<T, ErreurFeuApplication>;

/// Type d'erreur unique exposé par `feu-application`.
///
/// Agrège deux familles de variantes :
///
/// - **Erreurs remontées d'une couche inférieure** — `feu-noyau` et le Scribe,
///   encapsulées dans une `String` via `.to_string()`, ce qui préserve
///   l'encapsulation et évite toute fuite de type privé à travers l'API
///   applicative.
/// - **Préconditions de la couche applicative** — nœud éteint, foyer encore
///   ouvert. Elles sont **typées, sans charge utile** : ce sont des états que la
///   couche de présentation reconnaît pour décider quoi proposer, pas des
///   messages qu'elle se contenterait d'afficher.
///
/// Pas de variante fourre-tout : une précondition qui n'entre dans aucune des
/// deux existantes en réclame une nouvelle, nommée.
///
/// Le préfixe `APP >` dans chaque message sert de marqueur de couche lorsque
/// les messages sont encapsulés par la couche de présentation.
#[derive(Error, Debug)]
pub enum ErreurFeuApplication {
    /// Erreur remontée depuis `feu-noyau`.
    /// Le message textuel provient de [`ErreurFeuNoyau`] via `.to_string()`.
    #[error("APP > {0}")]
    FeuNoyau(String),

    /// Erreur remontée depuis le Scribe (couche ENU).
    /// Le message textuel provient de `ErreurScribe` via `.to_string()`.
    #[error("APP > {0}")]
    Scribe(String),

    /// Le noyau n'a pas encore été allumé via [`commande_allumage_noeud`](crate::FeuApplication::commande_allumage_noeud).
    #[error("APP > Le nœud doit être allumé")]
    NoeudEteint,

    /// Au moins un foyer est encore ouvert — l'extinction du nœud est refusée.
    ///
    /// Levée par
    /// [`commande_extinction_noeud`](crate::FeuApplication::commande_extinction_noeud)
    /// quand au moins un état d'`etat_foyers` est à `true`. Les foyers doivent
    /// tous être fermés avant que le nœud puisse être éteint — l'extinction ne
    /// déclenche aucune fermeture implicite.
    #[error("APP > Tous les foyers doivent être fermés")]
    AuMoinsUnFoyerOuvert,
}

impl From<ErreurFeuNoyau> for ErreurFeuApplication {
    /// Convertit [`ErreurFeuNoyau`] en [`ErreurFeuApplication::FeuNoyau`].
    ///
    /// Le type interne est perdu — seul le message textuel est propagé,
    /// préservant l'encapsulation des détails d'implémentation de `feu-noyau`.
    fn from(e: ErreurFeuNoyau) -> Self {
        ErreurFeuApplication::FeuNoyau(e.to_string())
    }
}

impl From<ErreurScribe> for ErreurFeuApplication {
    /// Aplatit toute erreur du Scribe en une chaîne, comme le fait déjà
    /// `From<ErreurFeuNoyau>`.
    ///
    /// Conséquence à connaître avant de typer une erreur côté Scribe : la
    /// variante ne survit pas à la frontière. Un appelant ne peut pas
    /// distinguer un `SCR-004` d'un `SCR-005` autrement qu'en lisant le
    /// message.
    fn from(e: ErreurScribe) -> Self {
        ErreurFeuApplication::Scribe(e.to_string())
    }
}
