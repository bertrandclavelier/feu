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

use std::path::PathBuf;

use crate::{
    Braise, MAX_CLASSEURS, MAX_FOYERS, MAX_TAILLE_BLOB, MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE,
    MAX_TAILLE_SIGNATURE, cryptographe::erreur::ErreurCryptographe,
};
use thiserror::Error;

/// Alias de [`Result`] utilisé par toutes les fonctions publiques de `feu-noyau`.
pub type ResultFeuNoyau<T> = Result<T, ErreurFeuNoyau>;

/// Type d'erreur unique exposé par `feu-noyau`.
///
/// Les variantes internes viennent d'abord, par ordre alphabétique — c'est le
/// seul ordre qui dise sans ambiguïté où insérer la suivante. Elles couvrent les
/// préconditions non satisfaites, les index hors bornes et les états incohérents.
/// Seul le `Cryptographe` garde encore un type d'erreur propre, aplati ici en
/// `String` via `.to_string()` pour ne pas faire fuir un type privé à travers
/// l'API — le gardien et l'archiviste, eux, lèvent directement leurs variantes.
///
/// Les variantes externes ferment la liste : elles portent l'erreur d'un type
/// étranger au lieu de la traduire.
///
/// Le préfixe `NOY >` dans chaque message sert de marqueur de couche lorsque
/// les messages sont encapsulés par la couche applicative (`feu-application`).
#[derive(Error, Debug)]
pub enum ErreurFeuNoyau {
    /// Foyer marqué ouvert dans la session alors que son emplacement
    /// d'`archivistes` est `None` — état incohérent, signale un bug interne.
    #[error("NOY > Foyer {0} ouvert sans archiviste (état interne incohérent)")]
    ArchivisteIndisponible(usize),

    /// Remplissage demandé sur un tiroir qui détient déjà un blob — un tiroir ne
    /// se remplit qu'une fois, la seconde écriture masquerait la première.
    #[error("NOY > Le blob dans le tiroir de l'archiviste est non vide")]
    ArchivisteTiroirBlobNonvide,

    /// Hash lu avant que `definit_hash` l'ait posé : le blob n'a pas encore été
    /// empreinté, il n'y a rien à rendre.
    #[error("NOY > Le tiroir de l'archiviste n'a pas de hash")]
    ArchivisteTiroirSansHash,

    /// Opération requérant que **tous** les foyers soient ouverts — typiquement
    /// un changement de mot de passe qui rechiffre l'intégralité du trousseau.
    #[error("NOY > Tous les foyers doivent être ouverts pour cette opération")]
    AuMoinsUnFoyerFerme,

    /// Aucun classeur du foyer ne détient le hash cherché — le foyer, lui, est
    /// valide et ouvert, vérifié avant le balayage.
    #[error("NOY > Blob introuvable dans le foyer {0}")]
    BlobIntrouvable(usize),

    /// Chaîne mal formée soumise à `Braise::try_from` — suffixe absent, longueur
    /// ou alphabet invalides. Portée pour inspection, jamais affichée.
    #[error("NOY > Adresse braise mal formée")]
    BraiseErronnee(String),

    /// Chemin attendu sur le disque et absent, fichier comme dossier. Porté pour
    /// inspection, jamais affiché : un chemin absolu nomme le compte utilisateur.
    #[error("NOY > Fichier ou dossier inexistant")]
    CheminInexistant(PathBuf),

    /// Erreur remontée depuis le cryptographe — opération cryptographique échouée.
    /// Le message textuel provient du type d'erreur interne du cryptographe via `.to_string()`.
    #[error("NOY > {0}")]
    Cryptographe(String),

    /// Dossier clair du foyer trop abîmé pour que la reconstruction du trousseau
    /// aboutisse — le diagnostic préalable a relevé au moins une anomalie.
    #[error("NOY > Diagnostic impossible pour fermeture en secours du foyer")]
    FermetureSecoursFoyerImpossible,

    /// Tentative d'ouvrir un foyer déjà marqué comme ouvert dans la session.
    #[error("NOY > Le foyer {0} est déjà ouvert")]
    FoyerDejaOuvert(usize),

    /// Opération nécessitant un foyer ouvert appelée sur un foyer fermé —
    /// les clés du trousseau ne sont pas disponibles en mémoire.
    #[error("NOY > Opération impossible sur foyer {0} fermé")]
    FoyerFerme(usize),

    /// Création d'arborescence demandée alors que le nœud existe déjà sur le
    /// disque — l'écraser détruirait les foyers en place.
    #[error("NOY > L'arborescence du nœud existe déjà")]
    GardienArborescenceNoeudDejaExistante,

    /// Aucune arborescence de nœud sous le chemin donné : rien à allumer, il
    /// faut d'abord créer le nœud.
    #[error("NOY > Manque arborescence nœud")]
    GardienArborescenceNoeudManquante,

    /// Suppression du dossier clair refusée faute de `<braise>.feu` — sans
    /// archive, effacer le dossier perdrait le foyer.
    #[error("NOY > L'archive chiffrée est inexistante")]
    GardienArchiveChiffreeInexistante,

    /// `config.feu` compte moins de `2 + MAX_FOYERS` lignes : version, prochain
    /// index ou braise de foyer manquants.
    #[error("NOY > Il manque au moins un élément dans config.feu")]
    GardienConfigManqueAuMoinsUnElement,

    /// Le trousseau public du foyer ne détient pas de clé pour ce classeur —
    /// porte le foyer puis le classeur.
    #[error("NOY > Foyer {0} : pas de clé pour le classeur {1}")]
    GardienPasDeClePourClasseur(usize, usize),

    /// Aucun trousseau public disponible pour ce foyer au moment de l'écrire
    /// sur le disque.
    #[error("NOY > Le foyer {0} n'a pas de trousseau public")]
    GardienPasDeTrousseauFoyer(usize),

    /// Échec de l'ajout d'une clé de classeur au trousseau public du foyer.
    /// La braise est portée pour inspection, jamais affichée : c'est une adresse.
    #[error("NOY > Problème d'ajout de clé pour le classeur {1}")]
    GardienProblemeAjoutCleClasseur(Braise, usize),

    /// Braise de `config.feu` que `Braise::try_from` refuse — le fichier est
    /// lisible, c'est son contenu qui est corrompu.
    #[error("NOY > Problème d'encodage de la braise")]
    GardienProblemeEncodageBraise,

    /// Fichier de clé lu sans erreur mais dont la taille ne correspond pas à
    /// celle attendue. Le chemin est porté pour inspection, jamais affiché.
    #[error("NOY > Taille de fichier inattendue")]
    GardienTailleFichierInattendue(PathBuf),

    /// Index de classeur hors bornes (`>= MAX_CLASSEURS`), à l'intérieur d'un
    /// foyer par ailleurs valide.
    #[error("NOY > Index classeur invalide : {0} (max {max})", max = MAX_CLASSEURS - 1)]
    IndexClasseurInvalide(usize),

    /// Index de foyer hors bornes (`>= MAX_FOYERS`). Porte la valeur reçue :
    /// c'est une donnée d'appel, jamais un secret.
    #[error("NOY > Index foyer invalide : {0} (max {max})", max = MAX_FOYERS - 1)]
    IndexFoyerInvalide(usize),

    /// Seed passée à [`crate::FeuNoyau::new`] alors que l'arborescence existe :
    /// c'est la restauration qui est refusée, pas l'allumage du nœud.
    #[error("NOY > Seed refusée : le nœud existe déjà")]
    SeedRefuseeNoeudExistant,

    /// Blob plus grand que [`MAX_TAILLE_BLOB`], borne posée au remplissage du
    /// tiroir. Porte la taille atteinte.
    #[error("NOY > Blob trop grand : {0} octets (max {max} octets)", max = MAX_TAILLE_BLOB - 1)]
    TailleMaxDepasseeBlob(usize),

    /// Message à chiffrer plus grand que [`MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE`].
    /// Porte la taille reçue, seule information non déductible du nom.
    #[error("NOY > Message à chiffrer trop grand : {0} octets (max {max} octets)", max = MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE - 1)]
    TailleMaxDepasseeChiffrementAsymetrique(usize),

    /// Message chiffré plus grand que la limite du clair augmentée du surcoût
    /// KEM — 1568 octets de ciphertext, 12 de nonce, 16 de tag.
    #[error("NOY > Message à déchiffrer trop grand : {0} octets (max {max} octets)", max = MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE + 1595)]
    TailleMaxDepasseeDechiffrementAsymetrique(usize),

    /// Message à signer plus grand que [`MAX_TAILLE_SIGNATURE`], que la clé
    /// engagée soit celle du nœud ou celle d'un foyer — cause et borne communes.
    #[error("NOY > Message à signer trop grand : {0} octets (max {max} octets)", max = MAX_TAILLE_SIGNATURE - 1)]
    TailleMaxDepasseeSignature(usize),

    /// Échec d'entrée-sortie remonté tel quel par `?` : le variant porte
    /// l'erreur système au lieu de la traduire.
    #[error("IoError > {0}")]
    IoError(#[from] std::io::Error),

    /// Version ou prochain index de `config.feu` illisibles comme entiers,
    /// remontés tels quels par `?`.
    #[error("ParseIntError > {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
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
