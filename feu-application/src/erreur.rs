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

use std::path::PathBuf;

use feu_noyau::{ErreurFeuNoyau, MAX_CLASSEURS, MAX_FOYERS};
use thiserror::Error;

use crate::scribe::enu::MAX_TAILLE_TEXTE;

/// Alias de [`Result`] utilisé par toutes les fonctions publiques de `feu-application`.
pub type ResultFeuApplication<T> = Result<T, ErreurFeuApplication>;

/// Type d'erreur unique exposé par `feu-application`.
///
/// Les variantes **internes** viennent d'abord, par ordre alphabétique — le seul
/// ordre qui dise où insérer la suivante. Ce sont des états que la présentation
/// reconnaît pour décider quoi proposer, pas des messages à afficher.
///
/// Les variantes **externes** ferment la liste et portent l'erreur d'une crate
/// tierce, par `#[from]` quand le type source le permet. [`ErreurFeuNoyau`] fait
/// exception, aplatie en `String` : aucun type du noyau ne traverse l'API.
///
/// **Pas de variante fourre-tout.** Le préfixe `APP >` marque la couche.
///
/// **Aucune charge utile n'est sensible** : un chemin absolu est porté pour
/// inspection, jamais affiché.
#[derive(Error, Debug)]
pub enum ErreurFeuApplication {
    /// Extinction du nœud refusée : au moins un foyer est encore ouvert, et
    /// l'extinction ne déclenche aucune fermeture implicite.
    #[error("APP > Tous les foyers doivent être fermés")]
    AuMoinsUnFoyerOuvert,

    /// Le noyau n'a pas encore été allumé via [`commande_allumage_noeud`](crate::FeuApplication::commande_allumage_noeud).
    #[error("APP > Le nœud doit être allumé")]
    NoeudEteint,

    /// La braise portée par une ENU ne résout vers aucun foyer de la session —
    /// sans lui, pas de foyer à qui demander le déchiffrement.
    #[error("APP > Braise inconnue")]
    ScribeBraiseInconnue,

    /// Les octets lus ne forment pas une carte. Le message énumère les trois
    /// défauts possibles sans dire lequel est tombé — un seul refus pour tous.
    #[error("APP > Carte mal formée : buffer trop court, discriminant inconnu ou octets résiduels")]
    ScribeCarteMalFormee,

    /// Le chemin visé est déjà un dossier — ouverture de comptoir comme retrait
    /// créent le leur, jamais dans un dossier existant. Porté, jamais affiché.
    #[error("APP > Le dossier existe déjà")]
    ScribeDossierDejaExistant(PathBuf),

    /// Dossier du dépôt disparu du disque, constaté avant le parcours plutôt que
    /// laissé à `read_dir`. Chemin porté, jamais affiché.
    #[error("APP > Dossier du dépôt introuvable")]
    ScribeDossierDepotIntrouvable(PathBuf),

    /// La carte n'est pas une `Carte::Donnee` : elle ne référence aucun blob,
    /// il n'y a donc rien à charger ni à décrire.
    #[error("APP > Ce doit être une EnuD")]
    ScribeEnuDAttendue,

    /// Signature de la carte non validée : signataire inconnu de la session ou
    /// signature invalide, sans distinguer — foyer fermé et falsification aussi.
    #[error("APP > ENU non authentique")]
    ScribeEnuNonAuthentique,

    /// L'empreinte recalculée de la carte ne vaut pas le hash attendu : corruption
    /// ou substitution, l'ENU n'est pas celle que son parent désignait.
    #[error("APP > ENU non intègre")]
    ScribeEnuNonIntegre,

    /// L'ENU n'est pas une racine du nœud — braise non vide ou méta `_racine`
    /// absente. Le sommet de l'arbre appartient toujours au nœud.
    #[error("APP > Ce doit être une racine du nœud")]
    ScribeEnuRacineAttendue,

    /// La carte n'est pas une `Carte::Repertoire` : ni enfants à lire ou à
    /// ajouter, ni arborescence à ouvrir depuis elle.
    #[error("APP > Ce doit être une EnuR")]
    ScribeEnuRAttendue,

    /// Foyer de destination du comptoir fermé depuis son ouverture. Gardé ici
    /// pour échouer avant la lecture des fichiers, sous une erreur qui le nomme.
    #[error("APP > Opération impossible sur foyer {0} fermé")]
    ScribeFoyerFerme(usize),

    /// Foyers signataires du sous-arbre encore fermés, relevés avant la moindre
    /// écriture. Tous sont à ouvrir : les nommer évite de les découvrir un par un.
    #[error("APP > Foyers à ouvrir : {liste}", liste = .0.iter().map(usize::to_string).collect::<Vec<_>>().join(", "))]
    ScribeFoyersFermes(Vec<usize>),

    /// Index de classeur hors bornes, refusé à l'ouverture du comptoir : l'index
    /// y est figé, un comptoir hors bornes échouerait à chaque fermeture.
    #[error("APP > Index classeur invalide : {0} (max {max})", max = MAX_CLASSEURS - 1)]
    ScribeIndexClasseurInvalide(usize),

    /// Aucun comptoir de dépôt actif sous cet index : la clé est absente de
    /// `comptoirs_depot`, pas hors bornes — rien à fermer.
    #[error("APP > Index comptoir inconnu : {0}")]
    ScribeIndexComptoirInconnu(usize),

    /// Index de foyer hors bornes, vérifié par le Scribe avant d'engager le
    /// noyau. Porte la valeur reçue : c'est une donnée d'appel, jamais un secret.
    #[error("APP > Index foyer invalide : {0} (max {max})", max = MAX_FOYERS - 1)]
    ScribeIndexFoyerInvalide(usize),

    /// La carte ne porte pas de méta `"nom"` : rien pour la matérialiser sur le
    /// système de fichiers au retrait.
    #[error("APP > La carte n'a pas de méta nom")]
    ScribeMetaNomAbsente,

    /// Nom refusé comme composant de chemin — vide, contenant un séparateur, ou
    /// valant `.` / `..` : un `Path::join` en sortirait ou l'écraserait.
    #[error("APP > Nom de fichier invalide")]
    ScribeNomFichierInvalide,

    /// Le contenu proposé en remplacement porte le même `hash_carte` que la
    /// dernière racine : la substitution n'aurait rien à produire.
    #[error("APP > Le contenu est déjà la racine")]
    ScribeRemplacementSansEffet,

    /// Contenu textuel plus grand que `MAX_TAILLE_TEXTE` : la carte est refusée
    /// avant mise sous enveloppe, plutôt que de buter sur le plafond du noyau.
    #[error("APP > Texte trop grand : {0} octets (max {max} octets)", max = MAX_TAILLE_TEXTE)]
    ScribeTailleMaxDepasseeTexte(usize),

    /// Décodage hexadécimal du hash rendu par `depot_blob`, remonté tel quel
    /// par `?` : la variante porte l'erreur au lieu de la traduire.
    #[error("APP > DecodeError > {0}")]
    DecodeError(#[from] data_encoding::DecodeError),

    /// Erreur remontée depuis `feu-noyau`.
    /// Le message textuel provient de [`ErreurFeuNoyau`] via `.to_string()`.
    #[error("APP > {0}")]
    FeuNoyau(String),

    /// Échec d'entrée-sortie remonté tel quel par `?` : la variante porte
    /// l'erreur système au lieu de la traduire.
    #[error("APP > IoError > {0}")]
    IoError(#[from] std::io::Error),

    /// Champ texte de l'enveloppe qui n'est pas de l'UTF-8 valide, remonté tel
    /// quel par `?` : la variante porte l'erreur au lieu de la traduire.
    #[error("APP > Utf8Error > {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    /// Échec de parcours d'un comptoir, remonté tel quel par `?` : `walkdir` ne
    /// rapporte que ce que le système de fichiers lui refuse.
    #[error("APP > WalkDirError > {0}")]
    WalkDirError(#[from] walkdir::Error),
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
