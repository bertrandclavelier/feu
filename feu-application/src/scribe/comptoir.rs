// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Comptoirs — les dossiers du système de fichiers par lesquels les données
//! franchissent la frontière de Feu, dans un sens ou dans l'autre.
//!
//! L'OS est l'interface. Un [`ComptoirDepot`] fait entrer : l'utilisateur (ou
//! un script, un agent IA) y écrit librement, et Feu parcourt le dossier à la
//! fermeture pour le ranger sous un foyer et un classeur. Un
//! [`ComptoirTravail`] fait ressortir : le sous-arbre d'une ENU est matérialisé
//! sur le disque pour y être modifié, et le comptoir retient la racine sortie.
//!
//! Les deux sont ouverts puis refermés par le [`Scribe`], à qui appartient tout
//! ce qui touche au contenu du dossier. [`Comptoirs`] tient l'état de ce qui est
//! ouvert et porte, à lui seul, les transitions.

use std::{collections::HashMap, fs::remove_dir_all, path::PathBuf};

use crate::{ErreurFeuApplication, ResultFeuApplication, Scribe, fiche::Fiche};

/// Classeur où sont rangés les blobs recréés à la fermeture d'un comptoir de
/// travail.
///
/// Un choix arbitraire, et sans portée : une ENU désigne sa donnée par le couple
/// `(foyer, hash)`, jamais par un classeur, que le noyau retrouve en balayant.
/// Le comptoir n'a donc pas à en mémoriser un à l'ouverture.
pub(super) const CLASSEUR_DEFAUT_COMPTOIR_TRAVAIL: usize = 0;

/// État des comptoirs ouverts : aucun, des dépôts, ou un travail.
///
/// Les trois cas s'excluent, et c'est le type qui l'impose : aucune variante ne
/// porte un [`ComptoirDepot`] et un [`ComptoirTravail`] ensemble, si bien que
/// l'exclusivité n'a pas de garde à écrire. [`Depot`](Comptoirs::Depot) n'est
/// jamais vide — le dernier retrait ramène à [`Vide`](Comptoirs::Vide).
pub(super) enum Comptoirs {
    /// Aucun comptoir ouvert.
    Vide,
    /// Les comptoirs de dépôt ouverts, indexés par identifiant.
    Depot(HashMap<usize, ComptoirDepot>),
    /// L'unique comptoir de travail.
    Travail(ComptoirTravail),
}

impl Comptoirs {
    /// Rend le comptoir de dépôt portant `index_comptoir`.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuApplication::ScribeIndexComptoirInconnu`] si l'identifiant est
    /// absent, comme lorsque aucun comptoir de dépôt n'est ouvert : l'appelant
    /// n'a rien à tirer de la distinction.
    pub(super) fn donne_comptoir_depot(
        &self,
        index_comptoir: usize,
    ) -> ResultFeuApplication<&ComptoirDepot> {
        match self {
            Self::Depot(comptoirs_depot) => comptoirs_depot.get(&index_comptoir),
            Self::Vide | Self::Travail(_) => None,
        }
        .ok_or(ErreurFeuApplication::ScribeIndexComptoirInconnu(
            index_comptoir,
        ))
    }

    /// Enregistre `comptoir_depot` et rend l'identifiant qui lui est attribué.
    ///
    /// L'identifiant suit le plus grand déjà pris : celui d'un comptoir refermé
    /// ne ressert que si rien de plus grand n'est resté ouvert.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuApplication::ScribeComptoirDejaAjoute`] si un comptoir de
    /// dépôt occupe déjà ce chemin.
    /// [`ErreurFeuApplication::ScribeComptoirTravailOuvert`] si le comptoir de
    /// travail occupe la place.
    pub(super) fn ajouter_comptoir_depot(
        &mut self,
        comptoir_depot: ComptoirDepot,
    ) -> ResultFeuApplication<usize> {
        match self {
            Self::Vide => {
                let mut comptoirs_depot = HashMap::new();
                comptoirs_depot.insert(0, comptoir_depot);
                *self = Self::Depot(comptoirs_depot);

                Ok(0)
            }

            Self::Depot(comptoirs_depot) => {
                if comptoirs_depot
                    .values()
                    .any(|c| c.chemin() == comptoir_depot.chemin())
                {
                    return Err(ErreurFeuApplication::ScribeComptoirDejaAjoute);
                }
                let prochain_id = comptoirs_depot.keys().max().map_or(0, |index| index + 1);
                comptoirs_depot.insert(prochain_id, comptoir_depot);

                Ok(prochain_id)
            }

            Self::Travail(_) => Err(ErreurFeuApplication::ScribeComptoirTravailOuvert),
        }
    }

    /// Retire le comptoir de dépôt portant `index_comptoir` et le rend.
    ///
    /// Le dossier n'est pas touché : la valeur rendue porte de quoi le parcourir
    /// puis le supprimer.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuApplication::ScribeIndexComptoirInconnu`] si l'identifiant est
    /// absent, comme lorsque aucun comptoir de dépôt n'est ouvert.
    pub(super) fn retirer_comptoir_depot(
        &mut self,
        index_comptoir: usize,
    ) -> ResultFeuApplication<ComptoirDepot> {
        match self {
            Self::Depot(comptoirs_depot) => {
                let retire = comptoirs_depot.remove(&index_comptoir);
                if comptoirs_depot.is_empty() {
                    *self = Self::Vide;
                }
                retire
            }

            Self::Vide | Self::Travail(_) => None,
        }
        .ok_or(ErreurFeuApplication::ScribeIndexComptoirInconnu(
            index_comptoir,
        ))
    }

    /// Rend le comptoir de travail ouvert.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuApplication::ScribePasComptoirTravailOuvert`] si aucun ne l'est
    /// — des comptoirs de dépôt ouverts donnent la même réponse.
    pub(super) fn donne_comptoir_travail(&self) -> ResultFeuApplication<&ComptoirTravail> {
        match self {
            Self::Travail(comptoir_travail) => Ok(comptoir_travail),
            Self::Vide | Self::Depot(_) => {
                Err(ErreurFeuApplication::ScribePasComptoirTravailOuvert)
            }
        }
    }

    /// Enregistre `comptoir_travail`, qui exige la place pour lui seul.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuApplication::ScribeComptoirDepotOuvert`] si des comptoirs de
    /// dépôt sont ouverts.
    /// [`ErreurFeuApplication::ScribeComptoirTravailOuvert`] si un comptoir de
    /// travail l'est déjà.
    pub(super) fn ajouter_comptoir_travail(
        &mut self,
        comptoir_travail: ComptoirTravail,
    ) -> ResultFeuApplication<()> {
        match self {
            Self::Vide => {
                *self = Self::Travail(comptoir_travail);

                Ok(())
            }
            Self::Depot(_) => Err(ErreurFeuApplication::ScribeComptoirDepotOuvert),

            Self::Travail(_) => Err(ErreurFeuApplication::ScribeComptoirTravailOuvert),
        }
    }

    /// Retire le comptoir de travail et le rend, ramenant à
    /// [`Vide`](Comptoirs::Vide).
    ///
    /// Le dossier n'est pas touché : la valeur rendue porte de quoi le supprimer.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuApplication::ScribePasComptoirTravailOuvert`] si aucun comptoir
    /// de travail n'est ouvert.
    pub(super) fn retirer_comptoir_travail(&mut self) -> ResultFeuApplication<ComptoirTravail> {
        match self {
            Self::Travail(comptoir_travail) => {
                let comptoir = comptoir_travail.clone();
                *self = Self::Vide;

                Ok(comptoir)
            }

            Self::Vide | Self::Depot(_) => {
                Err(ErreurFeuApplication::ScribePasComptoirTravailOuvert)
            }
        }
    }
}

/// Dossier OS servant de point de dépôt.
///
/// Créé à l'ouverture par [`ouvrir`](ComptoirDepot::ouvrir), parcouru à la
/// fermeture par le [`Scribe`]. Chaque comptoir est lié à un foyer et un
/// classeur de destination pour ses données.
///
/// `Clone` ne sert qu'aux tests, qui gardent la valeur donnée à
/// [`Comptoirs::ajouter_comptoir_depot`] pour la comparer à celle qui revient.
#[derive(Clone)]
pub(super) struct ComptoirDepot {
    /// Chemin du dossier sur le système de fichiers.
    chemin: PathBuf,
    /// Index du foyer propriétaire de ce comptoir.
    index_foyer: usize,
    /// Index du classeur de destination des données déposées.
    index_classeur: usize,
}

impl ComptoirDepot {
    /// Construit un [`ComptoirDepot`] sans créer le dossier physique.
    ///
    /// Le dossier n'est pas créé ici — appeler [`ouvrir`](ComptoirDepot::ouvrir)
    /// pour le rendre utilisable.
    pub(super) fn new(chemin: PathBuf, index_foyer: usize, index_classeur: usize) -> Self {
        Self {
            chemin,
            index_foyer,
            index_classeur,
        }
    }

    /// Retourne le chemin du dossier physique.
    pub(super) fn chemin(&self) -> &PathBuf {
        &self.chemin
    }

    /// Retourne l'index du foyer de destination des données.
    pub(super) fn index_foyer(&self) -> usize {
        self.index_foyer
    }

    /// Retourne l'index du classeur de destination des données.
    pub(super) fn index_classeur(&self) -> usize {
        self.index_classeur
    }

    /// Crée le dossier physique avec les permissions `rwx------` (0o700).
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeDossierDejaExistant`] si le
    /// chemin est déjà pris — un comptoir n'écrase pas un dossier existant.
    /// Propage [`ErreurFeuApplication::IoError`] si la création échoue
    /// (permissions insuffisantes, système de fichiers en lecture seule).
    pub(super) fn ouvrir(&self) -> ResultFeuApplication<()> {
        if self.chemin.exists() {
            return Err(ErreurFeuApplication::ScribeDossierDejaExistant(
                self.chemin.clone(),
            ));
        }
        Scribe::creer_dossier_700(&self.chemin)?;

        Ok(())
    }

    /// Supprime le dossier physique du comptoir et tout son contenu résiduel.
    ///
    /// Appelée par le [`Scribe`] à la fermeture, une fois les fichiers parcourus
    /// et déposés. Récursive ([`remove_dir_all`]) : le dossier disparaît avec ce
    /// qu'il reste dedans.
    ///
    /// # Errors
    ///
    /// Propage [`ErreurFeuApplication::IoError`] si le dossier est absent ou si
    /// la suppression échoue.
    pub(super) fn supprimer(&self) -> ResultFeuApplication<()> {
        remove_dir_all(&self.chemin)?;

        Ok(())
    }
}

/// Dossier OS portant un sous-arbre d'ENU sorti pour être modifié.
///
/// Le [`Scribe`] n'en tient qu'un. De l'état de départ, le comptoir ne retient
/// que la racine : l'arbre entier se redescend depuis elle, et la fermeture aura
/// de quoi le comparer au dossier.
#[derive(Clone)]
pub(super) struct ComptoirTravail {
    /// Chemin du dossier sur le système de fichiers.
    chemin: PathBuf,
    /// ENU racine dont le sous-arbre a été sorti dans le dossier.
    fiche_racine: Fiche,
}

impl ComptoirTravail {
    /// Construit un [`ComptoirTravail`] sans toucher au système de fichiers.
    ///
    /// Aucun pendant de [`ComptoirDepot::ouvrir`] ici : le dossier est celui que
    /// la sortie du sous-arbre vient de créer, il existe déjà.
    pub(super) fn new(chemin: PathBuf, fiche_racine: Fiche) -> Self {
        Self {
            chemin,
            fiche_racine,
        }
    }

    /// Retourne le chemin du dossier physique.
    pub(super) fn chemin(&self) -> &PathBuf {
        &self.chemin
    }

    /// Retourne la fiche de la racine sortie.
    pub(super) fn fiche_racine(&self) -> Fiche {
        self.fiche_racine.clone()
    }

    /// Supprime le dossier physique du comptoir et tout son contenu résiduel.
    ///
    /// Récursive ([`remove_dir_all`]) : ce que l'utilisateur a laissé dans le
    /// dossier disparaît avec lui.
    ///
    /// # Errors
    ///
    /// Propage [`ErreurFeuApplication::IoError`] si le dossier est absent ou si
    /// la suppression échoue.
    pub(super) fn supprimer(&self) -> ResultFeuApplication<()> {
        remove_dir_all(&self.chemin)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Tests en ligne : ce qui se prouve sans monter de pile.
    //!
    //! Un comptoir n'est qu'un dossier de l'OS et quelques champs — il ne
    //! signe rien, ne chiffre rien, n'a besoin ni de noyau allumé ni de foyer
    //! ouvert. Un `TempDir` suffit quand le disque est en jeu, un chemin
    //! fabriqué sinon, là où `src/scribe/tests.rs` monte une pile réelle pour
    //! éprouver l'enveloppe et sa signature.
    //!
    //! Le **rangement** du contenu d'un comptoir n'est pas ici : il appartient à
    //! [`Scribe::fermeture_comptoir_depot`](super::super::Scribe), donc au haut.
    //!
    //! [`ComptoirTravail`] n'a **pas** de test en ligne : ne créant pas son
    //! dossier, il n'a ni refus d'écraser ni permissions à éprouver, et le reste
    //! rendrait ses champs. Son ouverture est éprouvée par `src/tests.rs`.

    use std::{fs::metadata, os::unix::fs::PermissionsExt};

    use tempfile::TempDir;

    use crate::ResultFeuApplication;

    use super::*;

    /// Cycle de vie d'un [`ComptoirDepot`] : le dossier n'existe qu'entre
    /// `ouvrir` et `supprimer`, en `0o700`, et ces deux-là refusent l'un le
    /// chemin déjà pris, l'autre le dossier déjà absent.
    #[test]
    fn cycle_comptoir_depot() -> ResultFeuApplication<()> {
        let tmp = TempDir::new()?;

        // Création du chemin et du comptoir
        let chemin = tmp.path().to_path_buf().join("comptoir_depot");
        let comptoir = ComptoirDepot::new(chemin.clone(), 2, 5);

        // Le dossier n'existe pas encore
        assert!(!comptoir.chemin().exists());

        // Création du dossier
        comptoir.ouvrir()?;

        assert!(comptoir.chemin().exists());

        let mode = metadata(comptoir.chemin())?.permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        // On peut pas créer un comptoir sur le même chemin
        assert!(matches!(
            comptoir.ouvrir(),
            Err(ErreurFeuApplication::ScribeDossierDejaExistant(_))
        ));

        // Suppression du dossier
        comptoir.supprimer()?;

        // Le dossier n'existe plus
        assert!(!comptoir.chemin().exists());

        // Erreur quand on veut supprimer le comptoir déjà supprimé
        assert!(comptoir.supprimer().is_err());

        Ok(())
    }

    /// Un identifiant libéré ne ressert que par le haut : retirer le plus grand
    /// le rend disponible, retirer un autre laisse son numéro perdu, et le
    /// dernier retrait, qui ramène à [`Vide`](Comptoirs::Vide), repart de 0.
    #[test]
    fn id_comptoir_depot() -> ResultFeuApplication<()> {
        let chemin = PathBuf::from("chemin_test");

        let chemin1 = chemin.join("comptoir_depot1");
        let comptoir1 = ComptoirDepot::new(chemin1, 1, 2);
        let chemin2 = chemin.join("comptoir_depot2");
        let comptoir2 = ComptoirDepot::new(chemin2, 2, 1);
        let chemin3 = chemin.join("comptoir_depot3");
        let comptoir3 = ComptoirDepot::new(chemin3, 0, 1);
        let chemin4 = chemin.join("comptoir_depot4");
        let comptoir4 = ComptoirDepot::new(chemin4, 1, 0);
        let chemin5 = chemin.join("comptoir_depot5");
        let comptoir5 = ComptoirDepot::new(chemin5, 2, 1);

        let mut comptoirs = Comptoirs::Vide;

        // ajout id1
        let id1 = comptoirs.ajouter_comptoir_depot(comptoir1)?;
        assert_eq!(id1, 0);

        // ajout id2
        let id2 = comptoirs.ajouter_comptoir_depot(comptoir2)?;
        assert_eq!(id2, 1);

        // suppression id1
        comptoirs.retirer_comptoir_depot(id1)?;

        // ajout id3
        let id3 = comptoirs.ajouter_comptoir_depot(comptoir3)?;
        assert_eq!(id3, 2);

        // suppression id3
        comptoirs.retirer_comptoir_depot(id3)?;

        // ajout id4
        let id4 = comptoirs.ajouter_comptoir_depot(comptoir4)?;
        assert_eq!(id4, 2);

        // vide comptoirs
        comptoirs.retirer_comptoir_depot(id2)?;
        comptoirs.retirer_comptoir_depot(id4)?;

        assert_eq!(comptoirs.ajouter_comptoir_depot(comptoir5)?, 0);

        Ok(())
    }

    /// Deux comptoirs de dépôt ne partagent pas un chemin, sans qu'aucun dossier
    /// existe : la garde porte sur l'état, pas sur le disque.
    #[test]
    fn ajout_comptoir_meme_chemin() -> ResultFeuApplication<()> {
        let chemin = PathBuf::from("chemin_test");

        let chemin1 = chemin.join("comptoir_depot1");
        let comptoir1 = ComptoirDepot::new(chemin1.clone(), 1, 2);
        let comptoir1bis = ComptoirDepot::new(chemin1, 0, 1);
        let chemin2 = chemin.join("comptoir_depot2");
        let comptoir2 = ComptoirDepot::new(chemin2, 2, 1);

        let mut comptoirs = Comptoirs::Vide;

        comptoirs.ajouter_comptoir_depot(comptoir1)?;

        assert!(matches!(
            comptoirs.ajouter_comptoir_depot(comptoir1bis),
            Err(ErreurFeuApplication::ScribeComptoirDejaAjoute)
        ));

        assert_eq!(comptoirs.ajouter_comptoir_depot(comptoir2)?, 1);

        Ok(())
    }
}
