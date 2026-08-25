// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Définit les types d'erreurs de `feu-noyau`.
//!
//! [`ErreurFeuNoyau`] est l'unique type d'erreur du crate — non seulement à sa
//! frontière, mais partout à l'intérieur : gardien, archiviste et cryptographe
//! lèvent directement ses variantes. Aucun module ne définit plus les siennes,
//! et rien n'est donc traduit ni aplati en route.
//!
//! Ce choix succède à des types par module dont les erreurs finissaient toutes
//! en `String` à la sortie : la cause exacte se perdait à la frontière, là où
//! elle est précisément utile. Le prix en est un catalogue unique et long, dont
//! l'ordre alphabétique tient lieu de plan.
//!
//! [`ResultFeuNoyau<T>`] est l'alias de [`Result<T, ErreurFeuNoyau>`] utilisé
//! par toutes les fonctions du crate, publiques comme internes.

use std::path::PathBuf;

use crate::{
    MAX_CLASSEURS, MAX_FOYERS, MAX_TAILLE_BLOB, MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE,
    MAX_TAILLE_SIGNATURE,
};
use data_encoding::DecodePartial;
use hkdf::InvalidLength;
use thiserror::Error;

/// Alias de [`Result`] utilisé par toutes les fonctions publiques de `feu-noyau`.
pub type ResultFeuNoyau<T> = Result<T, ErreurFeuNoyau>;

/// Type d'erreur unique exposé par `feu-noyau`.
///
/// Les variantes **internes** viennent d'abord, par ordre alphabétique — le seul
/// ordre qui dise sans ambiguïté où insérer la suivante. Leur préfixe nomme le
/// composant qui les lève quand le cas lui est propre.
///
/// Les variantes **externes** ferment la liste et portent l'erreur d'une crate
/// tierce plutôt que de la traduire, par `#[from]` quand le type source le
/// permet. Le préfixe `NOY >` des messages marque la couche une fois l'erreur
/// encapsulée par `feu-application`.
///
/// **Aucune charge utile n'est sensible** : une braise ou un chemin absolu est
/// porté pour inspection, jamais affiché.
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

    /// Message chiffré dont les 1568 premiers octets ne forment pas un
    /// ciphertext ML-KEM-1024 exploitable — message tronqué ou mal formé.
    #[error("NOY > Ciphertext ML-KEM invalide")]
    CryptographeCiphertextMlKemInvalide,

    /// Ce classeur n'a pas de clé de chiffrement, des deux côtés du miroir :
    /// trousseau privé en mémoire comme trousseau public sur le disque.
    #[error("NOY > Clé de chiffrement du classeur {0} absente du trousseau")]
    CryptographeCleChiffrementClasseurAbstente(usize),

    /// Opération sur le trousseau demandée avant la soumission du mot de passe :
    /// la clé éphémère qui chiffre et déchiffre toutes les autres est absente.
    #[error("NOY > Clé éphémère absente du trousseau")]
    CryptographeCleEphemereAbsente,

    /// Clé publique ML-KEM-1024 du destinataire que la crate refuse : les 1568
    /// octets fournis ne forment pas une clé d'encapsulation valide.
    #[error("NOY > Clé publique de chiffrement invalide")]
    CryptographeClePubliqueChiffrementInvalide,

    /// Hash SHA3-256 du blob déchiffré différent de celui demandé : le
    /// déchiffrement a réussi, mais le contenu rendu n'est pas le bon.
    #[error("NOY > Données corrompues après déchiffrement")]
    CryptographeHashBlobDiscordant,

    /// Dérivation de la clé éphémère tentée sans mot de passe : l'interface n'en
    /// a pas fourni, ou le trousseau a été purgé depuis.
    #[error("NOY > Mot de passe absent du trousseau")]
    CryptographeMotDePasseAbsent,

    /// Saisie du mot de passe annulée : l'interface n'a rien rendu, l'opération
    /// s'arrête à la demande de l'utilisateur.
    #[error("NOY > Saisie du mot de passe annulée")]
    CryptographeMotDePasseNonSaisi,

    /// Les deux saisies de définition du mot de passe ne concordent pas — la
    /// seconde sert justement à écarter une faute de frappe sur la première.
    #[error("NOY > Les deux mots de passe ne correspondent pas")]
    CryptographeMotsDePasseDiscordants,

    /// Paire de signature ML-DSA-87 du nœud absente du trousseau : elle n'est
    /// reconstruite qu'à l'allumage, mot de passe vérifié.
    #[error("NOY > Paire de signature du nœud absente du trousseau")]
    CryptographePaireSignatureNoeudAbsente,

    /// Clé privée ML-KEM-1024 dont la seed n'est pas extractible, alors que le
    /// trousseau public doit la stocker sous forme de seed chiffrée.
    #[error("NOY > Seed ML-KEM introuvable dans la clé privée")]
    CryptographeSeedMlKemIntrouvable,

    /// Seed générée puis rejetée : l'utilisateur n'a pas confirmé l'avoir notée,
    /// la création du nœud est abandonnée à sa demande.
    #[error("NOY > Seed non confirmée, création du nœud abandonnée")]
    CryptographeSeedNonConfirmee,

    /// Dérivation de la clé éphémère tentée sans sel Argon2id, qu'il vienne du
    /// disque ou de la seed — sans lui, Argon2id n'a pas de quoi travailler.
    #[error("NOY > Sel Argon2id absent du trousseau")]
    CryptographeSelAbsent,

    /// Les 4627 octets soumis ne forment pas un encodage ML-DSA-87 décodable :
    /// signature illisible, à distinguer d'une signature lue et jugée fausse.
    #[error("NOY > Signature ML-DSA mal formée")]
    CryptographeSignatureMlDsaMalFormee,

    /// Buffer de taille imprévue en sortie d'AES-256-GCM : l'opération a réussi,
    /// c'est sa longueur qui ne tient pas dans le tableau attendu.
    #[error("NOY > Taille inattendue en sortie de chiffrement")]
    CryptographeTailleSortieInattendue,

    /// Aucun trousseau pour ce foyer : le foyer est fermé, ses clés ne sont pas
    /// en mémoire — ou son emplacement du trousseau public est vide.
    #[error("NOY > Le foyer {0} n'a pas de trousseau")]
    CryptographeTrousseauFoyerAbsent(usize),

    /// Foyer hors de l'état qui justifie un secours : soit il est déjà marqué
    /// ouvert dans la session, soit son dossier clair est trop abîmé pour que la
    /// reconstruction du trousseau aboutisse.
    #[error("NOY > Fermeture de secours impossible")]
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

    /// `noyau.feu` compte moins de `2 + MAX_FOYERS` lignes : version, prochain
    /// index ou braise de foyer manquants.
    #[error("NOY > Il manque au moins un élément dans noyau.feu")]
    GardienConfigManqueAuMoinsUnElement,

    /// Le trousseau public du foyer ne détient pas de clé pour ce classeur —
    /// porte le foyer puis le classeur.
    #[error("NOY > Foyer {0} : pas de clé pour le classeur {1}")]
    GardienPasDeClePourClasseur(usize, usize),

    /// Braise de `noyau.feu` que `Braise::try_from` refuse — le fichier est
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
    #[error("NOY > Blob trop grand : {0} octets (max {max} octets)", max = MAX_TAILLE_BLOB )]
    TailleMaxDepasseeBlob(usize),

    /// Message à chiffrer plus grand que [`MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE`].
    /// Porte la taille reçue, seule information non déductible du nom.
    #[error("NOY > Message à chiffrer trop grand : {0} octets (max {max} octets)", max = MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE )]
    TailleMaxDepasseeChiffrementAsymetrique(usize),

    /// Message chiffré plus grand que la limite du clair augmentée du surcoût
    /// KEM — 1568 octets de ciphertext, 12 de nonce, 16 de tag.
    #[error("NOY > Message à déchiffrer trop grand : {0} octets (max {max} octets)", max = MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE + 1596)]
    TailleMaxDepasseeDechiffrementAsymetrique(usize),

    /// Message à signer plus grand que [`MAX_TAILLE_SIGNATURE`], que la clé
    /// engagée soit celle du nœud ou celle d'un foyer — cause et borne communes.
    #[error("NOY > Message à signer trop grand : {0} octets (max {max} octets)", max = MAX_TAILLE_SIGNATURE )]
    TailleMaxDepasseeSignature(usize),

    /// Échec d'entrée-sortie remonté tel quel par `?` : le variant porte
    /// l'erreur système au lieu de la traduire.
    #[error("NOY > IoError > {0}")]
    IoError(#[from] std::io::Error),

    /// Version ou prochain index de `noyau.feu` illisibles comme entiers,
    /// remontés tels quels par `?`.
    #[error("NOY > ParseIntError > {0}")]
    ParseIntError(#[from] std::num::ParseIntError),

    /// Erreur émise par `bip39` lors de la génération ou du parsing du mnémonique.
    ///
    /// `bip39::Error` implémente `std::error::Error` — `#[from]` génère
    /// automatiquement la conversion. Le type original est préservé dans la variante.
    #[error("NOY > Bip39 > {0}")]
    Bip39(#[from] bip39::Error),

    /// Erreur HKDF — longueur de sortie invalide, stockée en texte.
    ///
    /// `hkdf::InvalidLength` n'implémente pas `std::error::Error`, ce qui rend
    /// `#[from]` inutilisable. La conversion est manuelle (voir `impl From` ci-dessous) :
    /// l'erreur est convertie en `String` via `.to_string()` — le type original est perdu.
    #[error("NOY > Hkdf > {0}")]
    Hkdf(String),

    /// Erreur Argon2id — dérivation de la clé éphémère depuis le mot de passe.
    ///
    /// `argon2::Error` implémente `std::error::Error` (feature `std`) — `#[from]`
    /// génère automatiquement la conversion. Le type original est préservé dans
    /// la variante.
    #[error("NOY > Argon2 > {0}")]
    Argon2(#[from] argon2::Error),

    /// Erreur AES-256-GCM — chiffrement ou déchiffrement d'une clé.
    ///
    /// `aes_gcm::Error` n'implémente pas `std::error::Error`, ce qui rend
    /// `#[from]` inutilisable. La conversion est manuelle (voir `impl From` ci-dessous) :
    /// l'erreur est convertie en `String` via `.to_string()` — le type original est perdu.
    #[error("NOY > AesGcm > {0}")]
    AesGcm(String),

    /// Erreur de décodage hexadécimal — décodage partiel ou caractère invalide.
    ///
    /// `data_encoding::DecodePartial` n'implémente ni `std::error::Error` ni
    /// `Display`, ce qui rend `#[from]` inutilisable. La conversion est manuelle
    /// (voir `impl From` ci-dessous) : le message est extrait du champ `error`
    /// (de type `DecodeError`, qui implémente `Display`) — le type original est perdu.
    #[error("NOY > DecodePartial > {0}")]
    DecodePartial(String),
}

impl From<DecodePartial> for ErreurFeuNoyau {
    /// Convertit `data_encoding::DecodePartial` en [`ErreurFeuNoyau::DecodePartial`].
    ///
    /// `DecodePartial` n'implémente ni `Display` ni `std::error::Error`.
    /// Le message est extrait de son champ `error: DecodeError` qui implémente
    /// `Display` — c'est la seule information récupérable sans le trait bound
    /// qu'exige `#[from]`.
    fn from(e: DecodePartial) -> Self {
        ErreurFeuNoyau::DecodePartial(e.error.to_string())
    }
}

impl From<hkdf::InvalidLength> for ErreurFeuNoyau {
    /// Convertit `hkdf::InvalidLength` en [`ErreurFeuNoyau::Hkdf`].
    ///
    /// `hkdf::InvalidLength` implémente `Display` mais pas `std::error::Error`.
    /// `.to_string()` suffit pour extraire le message — c'est tout ce qui
    /// peut être récupéré sans le trait bound qu'exige `#[from]`.
    fn from(e: InvalidLength) -> Self {
        ErreurFeuNoyau::Hkdf(e.to_string())
    }
}

impl From<aes_gcm::Error> for ErreurFeuNoyau {
    /// Convertit `aes_gcm::Error` en [`ErreurFeuNoyau::AesGcm`].
    ///
    /// `aes_gcm::Error` implémente `Display` mais pas `std::error::Error`.
    /// `.to_string()` suffit pour extraire le message — c'est tout ce qui
    /// peut être récupéré sans le trait bound qu'exige `#[from]`.
    fn from(e: aes_gcm::Error) -> Self {
        ErreurFeuNoyau::AesGcm(e.to_string())
    }
}
