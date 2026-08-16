// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Ce qu'une interface voit d'une ENU.
//!
//! Une [`Fiche`] est une `Enu` privée de sa signature : de quoi afficher une
//! entrée et la redésigner, rien de plus. L'interface n'a aucune vérification à
//! faire — elle affiche et demande des actions —, et la signature ML-DSA-87 de
//! 4 627 octets n'a donc aucune raison de quitter cette crate, ni une par ENU de
//! parcourir un canal et de rester en mémoire côté interface.
//!
//! Le retour se fait par le `hash_carte` : le stockage étant adressé par
//! contenu, il suffit à recharger la vraie `Enu` depuis le disque, à la
//! repasser par `Enu::authentique` et à agir. C'est toujours la crate qui
//! garantit, jamais la fiche.

use feu_noyau::Braise;

use crate::scribe::enu::{Carte, Enu};

/// Vue d'une `Enu` destinée à sortir de la crate.
///
/// Porte tous les champs d'une `Enu` sauf `signature_carte`. La `braise` est
/// gardée pour situer l'entrée dans son foyer — non couverte par le hash ni par
/// la signature, elle vaut pour l'affichage, pas pour décider.
///
/// `Debug` et `PartialEq` ne servent qu'aux assertions des tests.
#[derive(Debug, PartialEq)]
pub struct Fiche {
    /// Adresse `.braise` du signataire, telle que l'ENU la portait.
    braise: Braise,
    /// SHA3-256 de la carte — identifiant qui permet de retrouver l'ENU.
    hash_carte: [u8; 32],
    /// Timestamp Unix de mise sous enveloppe.
    date: u64,
    /// La carte entière, seule source de ce qu'il y a à dessiner : sa variante
    /// (donnée, texte, répertoire), ses métas, ses tags, et les `hashs_enu` qui
    /// portent la structure de l'arbre.
    carte: Carte,
}

impl Fiche {
    /// Projette une [`Enu`] chargée.
    ///
    /// `pub(crate)` : une fiche se reçoit et se rend, elle ne se fabrique pas
    /// depuis l'extérieur.
    pub(crate) fn new(enu: &Enu) -> Self {
        Self {
            braise: enu.braise(),
            hash_carte: enu.hash_carte(),
            date: enu.date(),
            carte: enu.carte().clone(),
        }
    }

    /// Cf. la réserve du type : indice d'affichage, hors garantie.
    pub fn braise(&self) -> Braise {
        self.braise
    }

    /// L'identifiant à renvoyer pour agir sur l'entrée.
    pub fn hash_carte(&self) -> [u8; 32] {
        self.hash_carte
    }

    /// Date de mise sous enveloppe, à mettre en forme par l'appelant.
    pub fn date(&self) -> u64 {
        self.date
    }

    /// Emprunt : le rendu repasse à chaque frame, une carte porte des `String`
    /// et des collections, un clone par lecture serait payé en boucle.
    pub fn carte(&self) -> &Carte {
        &self.carte
    }
}
