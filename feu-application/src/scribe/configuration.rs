// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! État des comptoirs du [`Scribe`], porté sur le disque.
//!
//! Un comptoir survit à la fermeture de Feu : on relance, on le retrouve, on
//! peut le fermer. Ce module tient le miroir en mémoire du fichier, comme le
//! gardien de `feu-noyau` tient celui de `noyau.feu`.
//!
//! De quoi rouvrir un comptoir, rien de plus : un dépôt donne son identifiant,
//! son dossier et sa destination, le comptoir de travail son dossier et le
//! `hash_carte` de la racine sortie. L'arbre est adressé par contenu, ce hash
//! suffit donc à relire l'ENU et à en refaire une [`Fiche`] — sans vérifier sa
//! signature, une restauration n'étant que du parcours.

use std::{
    collections::HashMap,
    ffi::OsString,
    fs::read_to_string,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};

use data_encoding::HEXLOWER;

use crate::{
    ErreurFeuApplication, ResultFeuApplication, Scribe,
    fiche::Fiche,
    scribe::{ComptoirDepot, ComptoirTravail, Comptoirs, VERSION_CONFIGURATION, enu::Enu},
};

/// Miroir en mémoire du fichier de configuration du [`Scribe`].
///
/// Les comptoirs y sont des tuples et non des types nommés, par symétrie avec
/// le miroir de [`SessionApplication`](crate::SessionApplication), qui porte le
/// même découpage. Les deux sortes y cohabitent, là où [`Comptoirs`] les exclut :
/// le fichier relu n'est pas maîtrisé, et [`Self::vers_comptoirs`] tranche à sa
/// place — c'est la seule sortie vers l'état vivant.
///
/// `Debug` et `PartialEq` ne servent qu'aux assertions des tests.
#[derive(Debug, PartialEq)]
pub(super) struct Configuration {
    /// Version du format du fichier, écrite en tête et relue au chargement.
    version: u32,
    /// Un comptoir de dépôt ouvert par entrée : identifiant, dossier, foyer et
    /// classeur de destination.
    comptoirs_depot: Vec<(usize, PathBuf, usize, usize)>,
    /// Dossier du comptoir de travail et `hash_carte` de la racine sortie, au
    /// plus un.
    comptoir_travail: Option<(PathBuf, [u8; 32])>,
}

impl Configuration {
    /// Relève l'état des comptoirs du [`Scribe`].
    ///
    /// L'ordre des dépôts suit celui de la `HashMap`, donc aucun : chaque
    /// entrée porte son identifiant, la relecture n'a pas à s'y fier.
    pub(super) fn new(scribe: &Scribe) -> Self {
        match &scribe.comptoirs {
            Comptoirs::Vide => Self {
                version: VERSION_CONFIGURATION,
                comptoirs_depot: Vec::new(),
                comptoir_travail: None,
            },

            Comptoirs::Depot(comptoirs_depot) => {
                let comptoirs_depot: Vec<_> = comptoirs_depot
                    .iter()
                    .map(|(index, comptoir)| {
                        (
                            *index,
                            comptoir.chemin().clone(),
                            comptoir.index_foyer(),
                            comptoir.index_classeur(),
                        )
                    })
                    .collect();

                Self {
                    version: VERSION_CONFIGURATION,
                    comptoirs_depot,
                    comptoir_travail: None,
                }
            }

            Comptoirs::Travail(comptoir_travail) => {
                let comptoir_travail = (
                    comptoir_travail.chemin().clone(),
                    comptoir_travail.fiche_racine().hash_carte(),
                );

                Self {
                    version: VERSION_CONFIGURATION,
                    comptoirs_depot: Vec::new(),
                    comptoir_travail: Some(comptoir_travail),
                }
            }
        }
    }

    /// Refait les comptoirs du miroir, dans la variante que leur nombre impose.
    ///
    /// Aucun dossier n'est touché : ceux des comptoirs relus sont déjà sur le
    /// disque, seul l'état en mémoire est à reconstruire. La racine sortie est
    /// relue par [`Enu::charger_sans_verification_signature`] : la [`Fiche`]
    /// restaurée sert à afficher et à situer, jamais à décider, les vérifications
    /// de signature ayant lieu à la fermeture du comptoir.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeConfigComptoirsIncompatibles`] si
    /// le miroir porte des dépôts et un travail à la fois, que [`Comptoirs`] ne
    /// représente pas ensemble : le cas suppose un fichier corrompu, que
    /// [`Configuration::new`] ne peut pas produire, et n'a donc pas de test
    /// dédié. Propage les erreurs de
    /// [`Enu::charger_sans_verification_signature`] : ENU absente du disque,
    /// illisible ou non intègre. L'échec est fatal — [`Scribe::activation`] le
    /// remonte, le Scribe reste inactif et Feu ne démarre pas.
    pub(super) fn vers_comptoirs(&self, chemin_enu: &Path) -> ResultFeuApplication<Comptoirs> {
        let comptoirs_depot: HashMap<_, _> = self
            .comptoirs_depot
            .iter()
            .map(|donnees| {
                (
                    donnees.0,
                    ComptoirDepot::new(donnees.1.clone(), donnees.2, donnees.3),
                )
            })
            .collect();

        let comptoir_travail = if let Some(comptoir_travail) = &self.comptoir_travail {
            let fiche = Fiche::new(&Enu::charger_sans_verification_signature(
                chemin_enu,
                &comptoir_travail.1,
            )?);

            Some(ComptoirTravail::new(comptoir_travail.0.clone(), fiche))
        } else {
            None
        };

        match (comptoirs_depot, comptoir_travail) {
            (comptoirs_depot, None) if comptoirs_depot.is_empty() => Ok(Comptoirs::Vide),
            (comptoirs_depot, None) => Ok(Comptoirs::Depot(comptoirs_depot)),
            (comptoirs_depot, Some(comptoir_travail)) if comptoirs_depot.is_empty() => {
                Ok(Comptoirs::Travail(comptoir_travail))
            }
            _ => Err(ErreurFeuApplication::ScribeConfigComptoirsIncompatibles),
        }
    }

    /// Écrit le miroir dans `scribe.feu`, en `0o600` et par renommage atomique.
    ///
    /// # Errors
    ///
    /// Propage [`ErreurFeuApplication::IoError`] si le dossier `.config/` est
    /// absent ou si l'écriture échoue.
    pub(super) fn sauvegarder(&self, chemin_configuration: &Path) -> ResultFeuApplication<()> {
        Scribe::ecrire_fichier_600(chemin_configuration, self.exporte_en_texte().as_bytes())
    }

    /// Relit `scribe.feu` et en refait un miroir en mémoire.
    ///
    /// # Errors
    ///
    /// Propage [`ErreurFeuApplication::IoError`] si le fichier est absent ou
    /// illisible, et les erreurs de [`Self::importe_depuis_texte`] sur son contenu.
    pub(super) fn charger(chemin_configuration: &Path) -> ResultFeuApplication<Self> {
        Self::importe_depuis_texte(&read_to_string(chemin_configuration)?)
    }

    /// Reconstruit le miroir depuis le contenu textuel de `scribe.feu`.
    ///
    /// Les champs sont pris ligne à ligne : aucun compte préalable, le fichier
    /// annonce son nombre de dépôts et la fin manquante se voit sur place.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeConfigVersionIncompatible`] si la
    /// version lue n'est pas celle du binaire,
    /// [`ErreurFeuApplication::ScribeConfigManqueAuMoinsUnElement`] si une ligne
    /// attendue manque, [`ErreurFeuApplication::ScribeConfigHashMalForme`] si le
    /// `hash_carte` ne fait pas 32 octets, et propage
    /// [`ErreurFeuApplication::ParseIntError`] ou
    /// [`ErreurFeuApplication::DecodeError`] sur une ligne mal formée.
    fn importe_depuis_texte(contenu: &str) -> ResultFeuApplication<Self> {
        let mut lignes = contenu.lines();

        let version = lignes
            .next()
            .ok_or(ErreurFeuApplication::ScribeConfigManqueAuMoinsUnElement)?
            .parse::<u32>()?;

        if version != VERSION_CONFIGURATION {
            return Err(ErreurFeuApplication::ScribeConfigVersionIncompatible(
                version,
            ));
        }

        let nombre_comptoirs_depot = lignes
            .next()
            .ok_or(ErreurFeuApplication::ScribeConfigManqueAuMoinsUnElement)?
            .parse::<u32>()?;

        let mut comptoirs_depot: Vec<(usize, PathBuf, usize, usize)> = Vec::new();
        for _ in 0..nombre_comptoirs_depot {
            let index_comptoir = lignes
                .next()
                .ok_or(ErreurFeuApplication::ScribeConfigManqueAuMoinsUnElement)?
                .parse::<usize>()?;

            let ligne = lignes
                .next()
                .ok_or(ErreurFeuApplication::ScribeConfigManqueAuMoinsUnElement)?;
            let chemin = PathBuf::from(OsString::from_vec(HEXLOWER.decode(ligne.as_bytes())?));

            let index_foyer = lignes
                .next()
                .ok_or(ErreurFeuApplication::ScribeConfigManqueAuMoinsUnElement)?
                .parse::<usize>()?;

            let index_classeur = lignes
                .next()
                .ok_or(ErreurFeuApplication::ScribeConfigManqueAuMoinsUnElement)?
                .parse::<usize>()?;

            comptoirs_depot.push((index_comptoir, chemin, index_foyer, index_classeur));
        }

        let chemin_comptoir = lignes
            .next()
            .ok_or(ErreurFeuApplication::ScribeConfigManqueAuMoinsUnElement)?;

        let comptoir_travail = if chemin_comptoir == "None" {
            None
        } else {
            let chemin = PathBuf::from(OsString::from_vec(
                HEXLOWER.decode(chemin_comptoir.as_bytes())?,
            ));

            let ligne = lignes
                .next()
                .ok_or(ErreurFeuApplication::ScribeConfigManqueAuMoinsUnElement)?;

            let hash: [u8; 32] = HEXLOWER
                .decode(ligne.as_bytes())?
                .try_into()
                .map_err(|_| ErreurFeuApplication::ScribeConfigHashMalForme)?;

            Some((chemin, hash))
        };

        Ok(Self {
            version,
            comptoirs_depot,
            comptoir_travail,
        })
    }

    /// Sérialise le miroir en texte pour `scribe.feu`, un champ par ligne.
    ///
    /// Les chemins passent en hexadécimal : un chemin Unix peut porter des
    /// octets non-UTF8 ou un `\n`, que le découpage en lignes ne supporterait
    /// pas. L'absence de comptoir de travail s'écrit `None`, qui n'est pas un
    /// encodage hexadécimal valide et ne peut donc pas être un chemin.
    fn exporte_en_texte(&self) -> String {
        let resultat = format!("{}\n{}\n", self.version, self.comptoirs_depot.len());

        let mut resultat = self
            .comptoirs_depot
            .iter()
            .map(|comptoir| {
                format!(
                    "{}\n{}\n{}\n{}\n",
                    comptoir.0,
                    HEXLOWER.encode(comptoir.1.as_os_str().as_bytes()),
                    comptoir.2,
                    comptoir.3
                )
            })
            .fold(resultat, |mut cumul, ligne| {
                cumul.push_str(&ligne);
                cumul
            });

        match &self.comptoir_travail {
            Some(comptoir) => {
                resultat.push_str(&HEXLOWER.encode(comptoir.0.as_os_str().as_bytes()));
                resultat.push('\n');
                resultat.push_str(&HEXLOWER.encode(&comptoir.1));
                resultat.push('\n');
            }
            None => {
                resultat.push_str("None");
                resultat.push('\n');
            }
        }

        resultat
    }
}

/// Tests en ligne : l'aller-retour entre le miroir et son texte.
///
/// Le format est du texte ligne à ligne, sans dépendance au reste de Feu —
/// exporter puis réimporter suffit à l'éprouver, et un `TempDir` couvre le
/// passage par le disque.
#[cfg(test)]
mod tests {
    use std::{fs::metadata, os::unix::fs::PermissionsExt};

    use tempfile::TempDir;

    use super::*;

    /// Une configuration vide, sans dépôt ni comptoir de travail, se relit
    /// identique après export.
    #[test]
    fn cycle_config_texte_config_1() -> ResultFeuApplication<()> {
        let configuration = Configuration {
            version: 1,
            comptoirs_depot: Vec::new(),
            comptoir_travail: None,
        };

        let texte = configuration.exporte_en_texte();

        let configuration_importee = Configuration::importe_depuis_texte(&texte)?;

        assert_eq!(configuration, configuration_importee);

        Ok(())
    }

    /// Trois comptoirs de dépôt survivent à l'aller-retour, identifiants et
    /// chemins compris.
    #[test]
    fn cycle_config_texte_config_2() -> ResultFeuApplication<()> {
        let configuration = Configuration {
            version: 1,
            comptoirs_depot: Vec::from([
                (1, PathBuf::from("test1"), 0, 0),
                (2, PathBuf::from("test2"), 0, 0),
                (3, PathBuf::from("test3"), 0, 0),
            ]),
            comptoir_travail: None,
        };

        let texte = configuration.exporte_en_texte();

        let configuration_importee = Configuration::importe_depuis_texte(&texte)?;

        assert_eq!(configuration, configuration_importee);

        Ok(())
    }

    /// Le comptoir de travail seul se relit identique, `hash_carte` compris —
    /// la ligne hexadécimale redonne bien les 32 octets.
    #[test]
    fn cycle_config_texte_config_3() -> ResultFeuApplication<()> {
        let configuration = Configuration {
            version: 1,
            comptoirs_depot: Vec::new(),
            comptoir_travail: Some((PathBuf::from("test"), [1u8; 32])),
        };

        let texte = configuration.exporte_en_texte();

        let configuration_importee = Configuration::importe_depuis_texte(&texte)?;

        assert_eq!(configuration, configuration_importee);

        Ok(())
    }

    /// Dépôts et comptoir de travail réunis se relisent identiques : la fin des
    /// dépôts ne déborde pas sur les lignes du comptoir de travail. Le miroir
    /// les porte ensemble ; leur refus appartient à
    /// [`Configuration::vers_comptoirs`].
    #[test]
    fn cycle_config_texte_config_4() -> ResultFeuApplication<()> {
        let configuration = Configuration {
            version: 1,
            comptoirs_depot: Vec::from([
                (1, PathBuf::from("test1"), 0, 0),
                (2, PathBuf::from("test2"), 0, 0),
                (3, PathBuf::from("test3"), 0, 0),
            ]),
            comptoir_travail: Some((PathBuf::from("test"), [1u8; 32])),
        };

        let texte = configuration.exporte_en_texte();

        let configuration_importee = Configuration::importe_depuis_texte(&texte)?;

        assert_eq!(configuration, configuration_importee);

        Ok(())
    }

    /// Un chemin non-UTF8, légal sous Unix, se relit octet pour octet : c'est ce
    /// que l'encodage hexadécimal apporte sur `to_string_lossy`, qui l'aurait
    /// remplacé par des U+FFFD.
    #[test]
    fn cycle_config_texte_config_5() -> ResultFeuApplication<()> {
        let configuration = Configuration {
            version: 1,
            comptoirs_depot: Vec::from([
                (1, PathBuf::from(OsString::from_vec(vec![0xff, 0xfe])), 0, 0),
                (2, PathBuf::from(OsString::from_vec(vec![0xff, 0xfe])), 0, 0),
            ]),
            comptoir_travail: Some((
                PathBuf::from(OsString::from_vec(vec![0xff, 0xfe])),
                [1u8; 32],
            )),
        };

        let texte = configuration.exporte_en_texte();

        let configuration_importee = Configuration::importe_depuis_texte(&texte)?;

        assert_eq!(configuration, configuration_importee);

        Ok(())
    }

    /// Le passage par le disque conserve la configuration et pose `scribe.feu`
    /// en `0o600`.
    #[test]
    fn cycle_sauvegarde_chargement() -> ResultFeuApplication<()> {
        let tmp = TempDir::new()?;
        let chemin = tmp.path().join("scribe.feu");

        let configuration = Configuration {
            version: 1,
            comptoirs_depot: Vec::from([
                (1, PathBuf::from("test1"), 0, 0),
                (2, PathBuf::from("test2"), 0, 0),
                (3, PathBuf::from("test3"), 0, 0),
            ]),
            comptoir_travail: Some((PathBuf::from("test"), [1u8; 32])),
        };

        configuration.sauvegarder(&chemin)?;

        let mode = metadata(&chemin)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let configuration_chargee = Configuration::charger(&chemin)?;

        assert_eq!(configuration, configuration_chargee);

        Ok(())
    }
}
