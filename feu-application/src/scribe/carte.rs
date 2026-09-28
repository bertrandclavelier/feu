// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Cartes : le contenu métier d'une ENU.
//!
//! Une [`Carte`] porte une donnée (CaD), un texte (CaT) ou un répertoire
//! (CaR), avec les métadonnées et les tags communs aux trois. Sa forme
//! sérialisée ([`Carte::vers_octets`]) est ce que l'enveloppe hash et signe.
//!
//! L'`enum` est public et ses variantes ouvertes, pour que les couches
//! supérieures discriminent par `match` plutôt que par des accesseurs à
//! [`Option<T>`]. Forger une carte au dehors reste sans effet : seule une
//! enveloppe l'écrit dans `enu/`, et constructeurs comme mutateurs restent
//! `pub(super)`. La confiance vient de la vérification du hash et de la
//! signature au chargement, pas de l'encapsulation.
//!
//! Deux métas sont posées par la crate : `"nom"` ([`Carte::nom`]) et `"date"`
//! ([`Carte::date`]). Les porter là plutôt que dans l'enveloppe les fait entrer
//! dans le hash et sous la signature.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::from_utf8,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{ErreurFeuApplication, ResultFeuApplication};

/// Plafond du contenu d'une [`Carte::Texte`], en octets UTF-8.
///
/// Bien en deçà du plafond de signature du noyau
/// ([`feu_noyau::MAX_TAILLE_SIGNATURE`], 64 kio) : la marge absorbe l'en-tête
/// de la carte sérialisée sans avoir à le calculer. **Borne incluse** : la garde
/// est un `>` strict, une taille étant une quantité et non un index.
pub(crate) const MAX_TAILLE_TEXTE: usize = 1024 * 60;

/// Contenu métier enveloppé par une `Enu`.
///
/// Métadonnées et tags sont des collections ordonnées ([`BTreeMap<K, V>`],
/// [`BTreeSet<T>`]) : le hash se calcule sur leur sérialisation, qui doit être
/// reproductible.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Carte {
    /// CaD — référence un blob stocké dans un classeur.
    Donnee {
        /// Métadonnées structurées clé → valeur.
        metas: BTreeMap<String, String>,
        /// Tags libres.
        tags: BTreeSet<String>,
        /// Hash SHA3-256 du blob (également le nom du fichier `.blob`).
        hash_blob: [u8; 32],
    },

    /// CaT — texte brut embarqué dans la carte, borné à la construction.
    Texte {
        /// Métadonnées structurées clé → valeur.
        metas: BTreeMap<String, String>,
        /// Tags libres.
        tags: BTreeSet<String>,
        /// Texte brut transporté par la carte.
        contenu: String,
    },

    /// CaR — répertoire, référence ses enfants par leur `hash_carte`.
    Repertoire {
        /// Métadonnées structurées clé → valeur.
        metas: BTreeMap<String, String>,
        /// Tags libres.
        tags: BTreeSet<String>,
        /// `hash_carte` des ENU enfants — ils portent à eux seuls la
        /// structure de l'arbre.
        hashs_enu: BTreeSet<[u8; 32]>,
    },
}

impl Carte {
    /// Pose la méta `"date"` — timestamp Unix en secondes, en décimal.
    ///
    /// Appelée par les seuls constructeurs : c'est la date de création de
    /// l'entrée, non de sa dernière modification, et une carte reconstruite
    /// depuis une autre en hérite.
    ///
    /// Une horloge antérieure au 1ᵉʳ janvier 1970 donne une date nulle plutôt
    /// qu'une panique : une date impossible désigne l'horloge de la machine, pas
    /// un défaut de Feu.
    pub(super) fn horodatee(mut self) -> Self {
        self.ajout_meta(
            "date",
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs()
                .to_string(),
        );

        self
    }

    /// Construit une [`Carte::Donnee`] — référence un blob dans un
    /// classeur.
    ///
    /// Horodatée à la construction (voir [`Self::horodatee`]).
    pub(super) fn new_donnee(hash_blob: [u8; 32]) -> Self {
        Self::Donnee {
            metas: BTreeMap::new(),
            tags: BTreeSet::new(),
            hash_blob,
        }
        .horodatee()
    }

    /// Construit une [`Carte::Texte`] — le texte est embarqué directement dans
    /// la carte, sans blob ni classeur.
    ///
    /// Horodatée à la construction (voir [`Self::horodatee`]).
    ///
    /// Le contenu est borné à [`MAX_TAILLE_TEXTE`] (en octets UTF-8), vérifié ici
    /// plutôt qu'au plafond de signature du noyau, pour échouer proprement.
    ///
    /// Le `nom` est posé en méta `"nom"` : c'est lui qui nommera le fichier au
    /// retrait. Venant de l'appelant et non du système de fichiers, il est validé
    /// dès la construction ([`Self::nom_fichier_valide`]).
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeTailleMaxDepasseeTexte`] si
    /// `contenu` dépasse [`MAX_TAILLE_TEXTE`], ou
    /// [`ErreurFeuApplication::ScribeNomFichierInvalide`] si `nom` est refusé
    /// comme composant de chemin.
    pub(super) fn new_texte(nom: &str, contenu: &str) -> ResultFeuApplication<Self> {
        if contenu.len() > MAX_TAILLE_TEXTE {
            return Err(ErreurFeuApplication::ScribeTailleMaxDepasseeTexte(
                contenu.len(),
            ));
        }

        if !Self::nom_fichier_valide(nom) {
            return Err(ErreurFeuApplication::ScribeNomFichierInvalide);
        }

        let mut carte = Self::Texte {
            metas: BTreeMap::new(),
            tags: BTreeSet::new(),
            contenu: contenu.to_string(),
        };
        carte.ajout_meta("nom", nom);

        Ok(carte.horodatee())
    }

    /// Construit une [`Carte::Repertoire`] — référence des ENU enfants
    /// par leur `hash_carte`.
    ///
    /// Horodatée à la construction (voir [`Self::horodatee`]).
    pub(super) fn new_repertoire(hashs_enu: BTreeSet<[u8; 32]>) -> Self {
        Self::Repertoire {
            metas: BTreeMap::new(),
            tags: BTreeSet::new(),
            hashs_enu,
        }
        .horodatee()
    }

    /// Retourne les métadonnées structurées, communes aux trois variantes.
    ///
    /// Évite de répéter le `match` chez l'appelant pour un champ présent dans
    /// les trois variantes.
    pub fn metas(&self) -> &BTreeMap<String, String> {
        match self {
            Self::Donnee {
                metas,
                tags: _,
                hash_blob: _,
            }
            | Self::Texte {
                metas,
                tags: _,
                contenu: _,
            }
            | Self::Repertoire {
                metas,
                tags: _,
                hashs_enu: _,
            } => metas,
        }
    }

    /// Retourne les `hash_carte` des ENU enfants — `None` sur une carte qui
    /// n'est pas un répertoire.
    ///
    /// L'absence n'est pas un incident — une feuille est le cas normal d'un
    /// parcours —, d'où l'[`Option<T>`] plutôt qu'un refus. Elle distingue en outre
    /// la feuille du répertoire réellement vide, qu'un ensemble vide
    /// confondrait.
    ///
    /// Rend une référence : le parcours traverse tous les répertoires de l'arbre,
    /// un clone par pas serait payé pour rien.
    pub fn hashs_enu(&self) -> Option<&BTreeSet<[u8; 32]>> {
        match self {
            Self::Repertoire {
                metas: _,
                tags: _,
                hashs_enu,
            } => Some(hashs_enu),
            Self::Donnee {
                metas: _,
                tags: _,
                hash_blob: _,
            }
            | Self::Texte {
                metas: _,
                tags: _,
                contenu: _,
            } => None,
        }
    }

    /// Retourne les `hash_carte` des ENU enfants en écriture — `None` sur une
    /// carte qui n'est pas un répertoire.
    pub(crate) fn mut_hashs_enu(&mut self) -> Option<&mut BTreeSet<[u8; 32]>> {
        match self {
            Self::Repertoire {
                metas: _,
                tags: _,
                hashs_enu,
            } => Some(hashs_enu),
            Self::Donnee {
                metas: _,
                tags: _,
                hash_blob: _,
            }
            | Self::Texte {
                metas: _,
                tags: _,
                contenu: _,
            } => None,
        }
    }

    /// Retourne les tags libres, communs aux trois variantes.
    ///
    /// Même raison que [`Carte::metas`] : un champ présent partout n'a pas à
    /// être extrait par un `match` à chaque lecture.
    pub fn tags(&self) -> &BTreeSet<String> {
        match self {
            Self::Donnee {
                metas: _,
                tags,
                hash_blob: _,
            }
            | Self::Texte {
                metas: _,
                tags,
                contenu: _,
            }
            | Self::Repertoire {
                metas: _,
                tags,
                hashs_enu: _,
            } => tags,
        }
    }

    /// Retourne le nom de l'entrée (méta `"nom"`).
    ///
    /// Aucune validation à la lecture : tout nom est validé à son écriture.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeMetaNomAbsente`] si la méta
    /// `"nom"` est absente.
    pub(super) fn nom(&self) -> ResultFeuApplication<String> {
        let Some(nom) = self.metas().get("nom") else {
            return Err(ErreurFeuApplication::ScribeMetaNomAbsente);
        };

        Ok(nom.clone())
    }

    /// Retourne la date de création de la carte — timestamp Unix en secondes.
    ///
    /// La méta est posée par les trois constructeurs : son absence signale une
    /// carte mal formée.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeMetaDateAbsente`] si la méta
    /// `"date"` est absente, et propage [`ErreurFeuApplication::ParseIntError`]
    /// si sa valeur n'est pas un entier décimal.
    pub fn date(&self) -> ResultFeuApplication<u64> {
        let Some(date) = self.metas().get("date") else {
            return Err(ErreurFeuApplication::ScribeMetaDateAbsente);
        };

        Ok(date.parse::<u64>()?)
    }

    /// Dit si `nom` est un composant de chemin unique et inoffensif.
    ///
    /// Empêche un nom d'entraîner l'écriture hors du dossier de retrait, pas un
    /// filtre d'affichage : elle écarte le vide, tout séparateur `/` (le seul,
    /// le protocole étant Unix-only) et les deux composants spéciaux `.` / `..`.
    /// Les noms cachés (`.bashrc`) restent acceptés — seule l'égalité stricte
    /// avec `.` ou `..` est refusée.
    pub(super) fn nom_fichier_valide(nom: &str) -> bool {
        !nom.is_empty() && !nom.contains('/') && nom != "." && nom != ".."
    }

    /// Ajoute une métadonnée structurée à la carte.
    ///
    /// Une clé déjà présente voit sa valeur écrasée.
    pub(super) fn ajout_meta(&mut self, cle: &str, valeur: &str) {
        let cle = String::from(cle);
        let valeur = String::from(valeur);

        match self {
            Self::Donnee {
                metas,
                tags: _,
                hash_blob: _,
            }
            | Self::Texte {
                metas,
                tags: _,
                contenu: _,
            }
            | Self::Repertoire {
                metas,
                tags: _,
                hashs_enu: _,
            } => {
                metas.insert(cle, valeur);
            }
        }
    }

    /// Ajoute un tag libre à la carte.
    ///
    /// Un tag déjà présent est ignoré, sans erreur.
    pub(super) fn ajout_tag(&mut self, tag: &str) {
        let tag = String::from(tag);
        match self {
            Self::Donnee {
                metas: _,
                tags,
                hash_blob: _,
            }
            | Self::Texte {
                metas: _,
                tags,
                contenu: _,
            }
            | Self::Repertoire {
                metas: _,
                tags,
                hashs_enu: _,
            } => {
                tags.insert(tag);
            }
        }
    }

    /// Retire un tag de la carte.
    ///
    /// Symétrique de [`Self::ajout_tag`], jusqu'au silence : un tag absent
    /// laisse la carte intacte, sans le dire.
    pub(super) fn retrait_tag(&mut self, tag: &str) {
        match self {
            Self::Donnee {
                metas: _,
                tags,
                hash_blob: _,
            }
            | Self::Texte {
                metas: _,
                tags,
                contenu: _,
            }
            | Self::Repertoire {
                metas: _,
                tags,
                hashs_enu: _,
            } => {
                tags.remove(tag);
            }
        }
    }

    /// Ajoute le `hash_carte` d'une ENU enfant à un répertoire.
    ///
    /// Un doublon est ignoré, sans erreur.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeEnuRAttendue`] si la carte n'est
    /// pas un répertoire : une [`Carte::Donnee`] ou une [`Carte::Texte`] n'a
    /// pas d'enfants.
    pub(super) fn ajout_hash_enu(&mut self, hash: &[u8; 32]) -> ResultFeuApplication<()> {
        if let Carte::Repertoire {
            metas: _,
            tags: _,
            hashs_enu,
        } = self
        {
            hashs_enu.insert(*hash);
            Ok(())
        } else {
            Err(ErreurFeuApplication::ScribeEnuRAttendue)
        }
    }

    /// Sérialise la carte en octets canoniques.
    ///
    /// Format : discriminant `u8` (0x00=CaD, 0x01=CaT, 0x02=CaR), métadonnées,
    /// tags, puis les champs spécifiques à chaque variante. Le résultat est
    /// déterministe : même carte → mêmes octets → même hash.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeCarteMalFormee`] si une longueur
    /// dépasse `u32::MAX` : refuser plutôt que tronquer en silence.
    pub(super) fn vers_octets(&self) -> ResultFeuApplication<Vec<u8>> {
        let mut resultat = Vec::new();
        match self {
            Carte::Donnee {
                metas,
                tags,
                hash_blob,
            } => {
                resultat.push(0x00);
                metas_vers_octets(&mut resultat, metas)?;
                tags_vers_octets(&mut resultat, tags)?;
                resultat.extend(hash_blob);
            }
            Carte::Texte {
                metas,
                tags,
                contenu,
            } => {
                resultat.push(0x01);
                metas_vers_octets(&mut resultat, metas)?;
                tags_vers_octets(&mut resultat, tags)?;
                let c = contenu.as_bytes();
                resultat.extend(&(c.len() as u64).to_be_bytes());
                resultat.extend(c);
            }
            Carte::Repertoire {
                metas,
                tags,
                hashs_enu,
            } => {
                resultat.push(0x02);
                metas_vers_octets(&mut resultat, metas)?;
                tags_vers_octets(&mut resultat, tags)?;
                let nombre = u32::try_from(hashs_enu.len())
                    .map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?;
                resultat.extend(&nombre.to_be_bytes());
                for h in hashs_enu {
                    resultat.extend(h);
                }
            }
        }
        Ok(resultat)
    }

    /// Désérialise une carte depuis ses octets canoniques.
    ///
    /// Format attendu : discriminant `u8`, métadonnées (via [`octets_vers_metas`]),
    /// tags (via [`octets_vers_tags`]), puis contenu spécifique à la variante
    /// (32 o de hash, `u64` de longueur + texte, ou `u32` de cardinal + 32 o
    /// par hash). Inverse de [`Carte::vers_octets`].
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeCarteMalFormee`] sur un buffer
    /// trop court, un discriminant inconnu ou des octets restants une fois la
    /// variante lue, et [`ErreurFeuApplication::Utf8Error`] si un texte, une
    /// clé ou une valeur n'est pas de l'UTF-8 valide.
    pub(super) fn octets_vers_carte(octets: &[u8]) -> ResultFeuApplication<Carte> {
        let (mut octets, reste) = prendre_octets(octets, 1)?;

        let (metas, reste) = octets_vers_metas(reste)?;
        let (tags, mut reste) = octets_vers_tags(reste)?;
        match octets[0] {
            0 => {
                let (hash, reste) = prendre_octets(reste, 32)?;
                let hash_blob: [u8; 32] = hash
                    .try_into()
                    .map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?;

                if !reste.is_empty() {
                    return Err(ErreurFeuApplication::ScribeCarteMalFormee);
                }

                Ok(Carte::Donnee {
                    metas,
                    tags,
                    hash_blob,
                })
            }
            1 => {
                (octets, reste) = prendre_octets(reste, 8)?;
                let entete = octets
                    .try_into()
                    .map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?;
                let longueur = usize::try_from(u64::from_be_bytes(entete))
                    .map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?;

                (octets, reste) = prendre_octets(reste, longueur)?;

                let contenu = from_utf8(octets)?.to_string();

                if !reste.is_empty() {
                    return Err(ErreurFeuApplication::ScribeCarteMalFormee);
                }

                Ok(Carte::Texte {
                    metas,
                    tags,
                    contenu,
                })
            }

            2 => {
                (octets, reste) = prendre_octets(reste, 4)?;
                let n_hashs = u32::from_be_bytes(
                    octets
                        .try_into()
                        .map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?,
                );

                let mut hashs_enu = BTreeSet::new();

                for _ in 0..n_hashs {
                    (octets, reste) = prendre_octets(reste, 32)?;
                    let hash: [u8; 32] = octets
                        .try_into()
                        .map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?;
                    hashs_enu.insert(hash);
                }

                if !reste.is_empty() {
                    return Err(ErreurFeuApplication::ScribeCarteMalFormee);
                }

                Ok(Carte::Repertoire {
                    metas,
                    tags,
                    hashs_enu,
                })
            }

            _ => Err(ErreurFeuApplication::ScribeCarteMalFormee),
        }
    }
}

/// Écrit les tags dans le buffer au format canonique.
///
/// `u32 nb_tags`, puis pour chaque tag `u32 len_utf8` suivi des octets UTF-8.
///
/// # Errors
///
/// Retourne [`ErreurFeuApplication::ScribeCarteMalFormee`] si une longueur
/// dépasse `u32::MAX`.
fn tags_vers_octets(buf: &mut Vec<u8>, tags: &BTreeSet<String>) -> ResultFeuApplication<()> {
    let nombre =
        u32::try_from(tags.len()).map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?;
    buf.extend(&nombre.to_be_bytes());

    for tag in tags {
        let b = tag.as_bytes();
        let longueur =
            u32::try_from(b.len()).map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?;
        buf.extend(&longueur.to_be_bytes());
        buf.extend(b);
    }

    Ok(())
}

/// Désérialise un `BTreeSet<String>` de tags depuis le format canonique.
///
/// Format : `u32` nb_tags, puis pour chaque tag `u32` len_utf8 suivi des octets
/// UTF-8. Retourne les tags et le reste du buffer non consommé.
///
/// # Errors
///
/// Retourne [`ErreurFeuApplication::ScribeCarteMalFormee`] si le buffer est
/// trop court, [`ErreurFeuApplication::Utf8Error`] si un tag n'est pas de
/// l'UTF-8 valide.
fn octets_vers_tags(octets: &[u8]) -> ResultFeuApplication<(BTreeSet<String>, &[u8])> {
    let mut tags = BTreeSet::new();
    let (mut octets, mut reste) = prendre_octets(octets, 4)?;
    let n_tags = u32::from_be_bytes(
        octets
            .try_into()
            .map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?,
    );

    for _ in 0..n_tags {
        (octets, reste) = prendre_octets(reste, 4)?;
        let longueur = u32::from_be_bytes(
            octets
                .try_into()
                .map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?,
        );

        (octets, reste) = prendre_octets(reste, longueur as usize)?;

        tags.insert(from_utf8(octets)?.to_string());
    }

    Ok((tags, reste))
}

/// Écrit les métadonnées dans le buffer au format canonique.
///
/// `u32 nb_metas`, puis pour chaque paire `u32 len_cle`, clé UTF-8,
/// `u32 len_valeur`, valeur UTF-8, dans l'ordre alphabétique des clés.
///
/// # Errors
///
/// Retourne [`ErreurFeuApplication::ScribeCarteMalFormee`] si une longueur
/// dépasse `u32::MAX`.
fn metas_vers_octets(
    buf: &mut Vec<u8>,
    metas: &BTreeMap<String, String>,
) -> ResultFeuApplication<()> {
    let nombre =
        u32::try_from(metas.len()).map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?;
    buf.extend(&nombre.to_be_bytes());

    for (cle, valeur) in metas {
        let cle = cle.as_bytes();
        let valeur = valeur.as_bytes();
        let longueur_cle =
            u32::try_from(cle.len()).map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?;
        buf.extend(&longueur_cle.to_be_bytes());
        buf.extend(cle);
        let longueur_valeur =
            u32::try_from(valeur.len()).map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?;
        buf.extend(&longueur_valeur.to_be_bytes());
        buf.extend(valeur);
    }

    Ok(())
}

/// Désérialise un `BTreeMap<String, String>` de métadonnées depuis le format
/// canonique.
///
/// Format : `u32` nb_metas, puis pour chaque paire `u32` len_cle, clé UTF-8,
/// `u32` len_valeur, valeur UTF-8. Retourne les métadonnées et le reste du
/// buffer non consommé.
///
/// # Errors
///
/// Retourne [`ErreurFeuApplication::ScribeCarteMalFormee`] si le buffer est
/// trop court, [`ErreurFeuApplication::Utf8Error`] si une clé ou une valeur
/// n'est pas de l'UTF-8 valide.
fn octets_vers_metas(octets: &[u8]) -> ResultFeuApplication<(BTreeMap<String, String>, &[u8])> {
    let mut metas = BTreeMap::new();
    let (mut octets, mut reste) = prendre_octets(octets, 4)?;
    let n_metas = u32::from_be_bytes(
        octets
            .try_into()
            .map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?,
    );

    for _ in 0..n_metas {
        (octets, reste) = prendre_octets(reste, 4)?;
        let longueur = u32::from_be_bytes(
            octets
                .try_into()
                .map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?,
        );

        (octets, reste) = prendre_octets(reste, longueur as usize)?;
        let cle = from_utf8(octets)?.to_string();

        (octets, reste) = prendre_octets(reste, 4)?;
        let longueur = u32::from_be_bytes(
            octets
                .try_into()
                .map_err(|_| ErreurFeuApplication::ScribeCarteMalFormee)?,
        );

        (octets, reste) = prendre_octets(reste, longueur as usize)?;
        let valeur = from_utf8(octets)?.to_string();

        metas.insert(cle, valeur);
    }

    Ok((metas, reste))
}

/// Extrait les `n` premiers octets du buffer.
///
/// `pub(super)` : [`super::enu`] la partage pour découper l'en-tête de
/// l'enveloppe, dont les champs sont eux aussi de taille connue.
///
/// # Errors
///
/// Retourne [`ErreurFeuApplication::ScribeCarteMalFormee`] si le buffer compte
/// moins de `n` octets.
pub(super) fn prendre_octets(buf: &[u8], n: usize) -> ResultFeuApplication<(&[u8], &[u8])> {
    if buf.len() < n {
        return Err(ErreurFeuApplication::ScribeCarteMalFormee);
    }
    Ok((&buf[0..n], &buf[n..]))
}

/// Tests en ligne : ce qui se prouve sans monter de pile.
///
/// Une carte n'est que des octets et des collections ordonnées : la forger
/// à la main suffit, rien ici ne signe ni ne chiffre. L'aller-retour par le
/// format canonique et les gardes de construction — taille du texte, nom de
/// fichier — s'éprouvent donc au plus près du code qui les tient.
///
/// Mettre une carte sous enveloppe signée demande au contraire un noyau
/// allumé et un foyer ouvert : ces tests-là sont dans `src/scribe/tests.rs`.
#[cfg(test)]
mod tests {
    use proptest::{
        collection::{btree_map, btree_set, vec},
        prelude::any,
        prop_assert, prop_assert_eq, prop_assume, property_test,
    };

    use super::*;

    /// Tout buffer se coupe en `n` octets pris et un reste qui, recollés, le
    /// redonnent ; au-delà de sa longueur, rejet en
    /// [`ErreurFeuApplication::ScribeCarteMalFormee`].
    #[property_test]
    fn prendre_octets_aleatoires(
        #[strategy = vec(any::<u8>(), 0..16)] octets: Vec<u8>,
        #[strategy = 0..20usize] n: usize,
    ) {
        if n <= octets.len() {
            let (octets_pris, octets_reste) = prendre_octets(octets.as_slice(), n)?;

            prop_assert_eq!(octets_pris.len(), n);
            prop_assert_eq!([octets_pris, octets_reste].concat(), octets);
        } else {
            prop_assert!(matches!(
                prendre_octets(octets.as_slice(), n),
                Err(ErreurFeuApplication::ScribeCarteMalFormee)
            ));
        }
    }

    /// Tout ensemble de tags survit à l'aller-retour par le format canonique,
    /// sans octet restant.
    #[property_test]
    fn tags_aleatoires_vers_octets(
        #[strategy = btree_set(".{0,20}", 0..=10)] tags: BTreeSet<String>,
    ) {
        let mut octets = Vec::new();
        tags_vers_octets(&mut octets, &tags)?;
        let (tags_retour, reste) = octets_vers_tags(&octets)?;

        prop_assert_eq!(tags_retour, tags);
        prop_assert!(reste.is_empty());
    }

    /// Toute table de métadonnées survit à l'aller-retour par le format
    /// canonique, sans octet restant.
    #[property_test]
    fn metas_aleatoires_vers_octets(
        #[strategy = btree_map(".{0,20}", ".{0,20}", 0..=10)] metas: BTreeMap<String, String>,
    ) {
        let mut octets = Vec::new();
        metas_vers_octets(&mut octets, &metas)?;
        let (metas_retour, reste) = octets_vers_metas(&octets)?;

        prop_assert_eq!(metas_retour, metas);
        prop_assert!(reste.is_empty());
    }

    /// Toute [`Carte::Donnee`] ressort identique de l'aller-retour par ses octets.
    #[property_test]
    fn carte_donnee_aleatoire_vers_octets(
        #[strategy = btree_set(".{0,20}", 0..=10)] tags: BTreeSet<String>,
        #[strategy = btree_map(".{0,20}", ".{0,20}", 0..=10)] metas: BTreeMap<String, String>,
        hash_blob: [u8; 32],
    ) {
        let carte = Carte::Donnee {
            metas,
            tags,
            hash_blob,
        };

        let octets = carte.vers_octets()?;
        let carte_retour = Carte::octets_vers_carte(&octets)?;

        prop_assert_eq!(carte, carte_retour);
    }

    /// Toute [`Carte::Texte`] ressort identique de l'aller-retour par ses octets.
    #[property_test]
    fn carte_texte_aleatoire_vers_octets(
        #[strategy = btree_set(".{0,20}", 0..=10)] tags: BTreeSet<String>,
        #[strategy = btree_map(".{0,20}", ".{0,20}", 0..=10)] metas: BTreeMap<String, String>,
        #[strategy = ".{0,500}"] contenu: String,
    ) {
        let carte = Carte::Texte {
            metas,
            tags,
            contenu,
        };

        let octets = carte.vers_octets()?;
        let carte_retour = Carte::octets_vers_carte(&octets)?;

        prop_assert_eq!(carte, carte_retour);
    }

    /// Toute [`Carte::Repertoire`] ressort identique de l'aller-retour par ses
    /// octets.
    #[property_test]
    fn carte_repertoire_aleatoire_vers_octets(
        #[strategy = btree_set(".{0,20}", 0..=10)] tags: BTreeSet<String>,
        #[strategy = btree_map(".{0,20}", ".{0,20}", 0..=10)] metas: BTreeMap<String, String>,
        #[strategy = btree_set(any::<[u8; 32]>(), 0..=10)] hashs_enu: BTreeSet<[u8; 32]>,
    ) {
        let carte = Carte::Repertoire {
            metas,
            tags,
            hashs_enu,
        };

        let octets = carte.vers_octets()?;
        let carte_retour = Carte::octets_vers_carte(&octets)?;

        prop_assert_eq!(carte, carte_retour);
    }

    /// Aucun buffer, bien ou mal formé, ne fait paniquer le décodage : les
    /// longueurs lues dans les octets ne débordent jamais du buffer.
    #[property_test]
    fn carte_malformee_octets_aleatoires(#[strategy = vec(any::<u8>(), 0..1000)] octets: Vec<u8>) {
        let _ = Carte::octets_vers_carte(octets.as_slice());
    }

    /// Toute carte coupée avant son dernier octet est refusée : le décodage
    /// consomme exactement tout le buffer, aucun préfixe strict n'est valide.
    #[property_test]
    fn carte_malformee_octets_tronques(
        #[strategy = btree_set(".{0,20}", 0..=10)] tags: BTreeSet<String>,
        #[strategy = btree_map(".{0,20}", ".{0,20}", 0..=10)] metas: BTreeMap<String, String>,
        hash_blob: [u8; 32],
        #[strategy = ".{0,500}"] contenu: String,
        #[strategy = btree_set(any::<[u8; 32]>(), 0..=10)] hashs_enu: BTreeSet<[u8; 32]>,
        #[strategy = 0..3u8] variante: u8,
        position: proptest::sample::Index,
    ) {
        let carte = match variante {
            0 => Carte::Donnee {
                metas,
                tags,
                hash_blob,
            },
            1 => Carte::Texte {
                metas,
                tags,
                contenu,
            },
            _ => Carte::Repertoire {
                metas,
                tags,
                hashs_enu,
            },
        };
        let octets = carte.vers_octets()?;
        let n = position.index(octets.len());
        let tronques = &octets[..n];

        prop_assert!(Carte::octets_vers_carte(tronques).is_err());
    }

    /// Une carte dont un octet est remplacé par une valeur quelconque ne fait
    /// jamais paniquer le décodage, qu'il en sorte une erreur ou une carte.
    #[property_test]
    fn carte_malformee_octet_altere(
        #[strategy = btree_set(".{0,20}", 0..=10)] tags: BTreeSet<String>,
        #[strategy = btree_map(".{0,20}", ".{0,20}", 0..=10)] metas: BTreeMap<String, String>,
        hash_blob: [u8; 32],
        #[strategy = ".{0,500}"] contenu: String,
        #[strategy = btree_set(any::<[u8; 32]>(), 0..=10)] hashs_enu: BTreeSet<[u8; 32]>,
        #[strategy = 0..3u8] variante: u8,
        position: proptest::sample::Index,
        #[strategy = 0..=255u8] masque: u8,
    ) {
        let carte = match variante {
            0 => Carte::Donnee {
                metas,
                tags,
                hash_blob,
            },
            1 => Carte::Texte {
                metas,
                tags,
                contenu,
            },
            _ => Carte::Repertoire {
                metas,
                tags,
                hashs_enu,
            },
        };
        let mut octets = carte.vers_octets()?;
        let n = position.index(octets.len());
        octets[n] = masque;

        let _ = Carte::octets_vers_carte(octets.as_slice());
    }

    /// Toute carte suivie d'octets en trop est refusée : une carte n'a
    /// qu'une suite d'octets, donc qu'un hash.
    #[property_test]
    fn carte_malformee_octets_ajoutes(
        #[strategy = btree_set(".{0,20}", 0..=10)] tags: BTreeSet<String>,
        #[strategy = btree_map(".{0,20}", ".{0,20}", 0..=10)] metas: BTreeMap<String, String>,
        hash_blob: [u8; 32],
        #[strategy = ".{0,500}"] contenu: String,
        #[strategy = btree_set(any::<[u8; 32]>(), 0..=10)] hashs_enu: BTreeSet<[u8; 32]>,
        #[strategy = 0..3u8] variante: u8,
        #[strategy = vec(any::<u8>(), 1..=100)] octets_ajoutes: Vec<u8>,
    ) {
        let carte = match variante {
            0 => Carte::Donnee {
                metas,
                tags,
                hash_blob,
            },
            1 => Carte::Texte {
                metas,
                tags,
                contenu,
            },
            _ => Carte::Repertoire {
                metas,
                tags,
                hashs_enu,
            },
        };
        let octets = carte.vers_octets()?;

        prop_assert!(matches!(
            Carte::octets_vers_carte([octets, octets_ajoutes].concat().as_slice()),
            Err(ErreurFeuApplication::ScribeCarteMalFormee)
        ));
    }

    /// Tout nom non vide sans `/`, hors `.` et `..` exacts, est accepté.
    #[property_test]
    fn nom_fichier_aleatoire_valide(#[strategy = "[^/]{1,50}"] nom: String) {
        prop_assume!(nom != "." && nom != "..");
        prop_assert!(Carte::nom_fichier_valide(&nom));
    }

    /// Un `/` substitué à n'importe quel caractère d'un nom le fait refuser.
    #[property_test]
    fn nom_fichier_altere(
        #[strategy = "[^/]{1,50}"] nom: String,
        position: proptest::sample::Index,
    ) {
        let mut caracteres: Vec<char> = nom.chars().collect();
        let i = position.index(caracteres.len());
        caracteres[i] = '/';

        prop_assert!(!Carte::nom_fichier_valide(
            &caracteres.into_iter().collect::<String>()
        ));
    }

    /// Refus des trois noms entiers interdits : vide, `.` et `..`.
    #[test]
    fn noms_fichiers_invalides() {
        assert!(!Carte::nom_fichier_valide(""));
        assert!(!Carte::nom_fichier_valide("."));
        assert!(!Carte::nom_fichier_valide(".."));
    }

    /// Acceptation des noms qui commencent par des points sans être `.` ni
    /// `..` : le refus porte sur l'égalité stricte, pas sur le préfixe.
    #[test]
    fn noms_fichiers_valides() {
        assert!(Carte::nom_fichier_valide(".test"));
        assert!(Carte::nom_fichier_valide("..test"));
    }

    /// Une [`Carte::Donnee`] garde son hash de blob, refuse
    /// [`Carte::ajout_hash_enu`] et rend par les accesseurs communs les tags et
    /// métas qu'on lui ajoute.
    #[test]
    fn carte_donnee() {
        let hash_blob = [0u8; 32];
        let mut carte = Carte::new_donnee(hash_blob);

        assert!(matches!(
            carte.ajout_hash_enu(&hash_blob),
            Err(ErreurFeuApplication::ScribeEnuRAttendue)
        ));

        if let Carte::Donnee {
            metas: _,
            tags: _,
            hash_blob: h,
        } = &carte
        {
            assert_eq!(h, &hash_blob);
        }

        assert!(carte.tags().is_empty());
        assert!(carte.metas().contains_key("date"));
        assert_eq!(carte.metas().len(), 1);

        carte.ajout_tag("tag1");
        carte.ajout_tag("tag2");

        assert_eq!(carte.tags().len(), 2);
        assert!(carte.tags().contains("tag1") && carte.tags().contains("tag2"));

        carte.ajout_meta("meta1", "valeur1");
        carte.ajout_meta("meta2", "valeur2");

        assert_eq!(carte.metas().len(), 3);
        assert!(carte.metas().contains_key("meta1") && carte.metas().contains_key("meta2"));
    }

    /// Une [`Carte::Texte`] garde son contenu et sa méta `"nom"`, refuse
    /// [`Carte::ajout_hash_enu`] et rend par les accesseurs communs les tags et
    /// métas qu'on lui ajoute.
    #[test]
    fn carte_texte() -> ResultFeuApplication<()> {
        let hash_blob = [0u8; 32];
        let mut carte = Carte::new_texte("Test", "Contenu court de test")?;

        assert!(matches!(
            carte.ajout_hash_enu(&hash_blob),
            Err(ErreurFeuApplication::ScribeEnuRAttendue)
        ));

        if let Carte::Texte {
            metas: _,
            tags: _,
            contenu: c,
        } = &carte
        {
            assert_eq!(c, "Contenu court de test");
        }

        assert!(carte.tags().is_empty() && carte.metas().get("nom").is_some());

        carte.ajout_tag("tag1");
        carte.ajout_tag("tag2");

        assert_eq!(carte.tags().len(), 2);
        assert!(carte.tags().contains("tag1") && carte.tags().contains("tag2"));

        carte.ajout_meta("meta1", "valeur1");
        carte.ajout_meta("meta2", "valeur2");

        assert_eq!(carte.metas().len(), 4);
        assert!(carte.metas().contains_key("meta1") && carte.metas().contains_key("meta2"));

        Ok(())
    }

    /// Un contenu qui dépasse [`MAX_TAILLE_TEXTE`] d'un octet est refusé par
    /// [`Carte::new_texte`].
    #[test]
    fn carte_texte_trop_grande() {
        let contenu = "a".repeat(MAX_TAILLE_TEXTE + 1);

        assert!(matches!(
            Carte::new_texte("test", &contenu),
            Err(ErreurFeuApplication::ScribeTailleMaxDepasseeTexte(_))
        ));
    }

    /// Un nom contenant un `/` est refusé dès [`Carte::new_texte`], avant
    /// qu'aucun retrait ne puisse le matérialiser. Un seul cas suffit : la règle
    /// a ses propres tests.
    #[test]
    fn carte_texte_mauvais_nom() {
        assert!(matches!(
            Carte::new_texte("te/st", "contenu"),
            Err(ErreurFeuApplication::ScribeNomFichierInvalide)
        ));
    }

    /// Une [`Carte::Repertoire`] reçoit ses hashs enfants par
    /// [`Carte::ajout_hash_enu`] et rend par les accesseurs communs les tags et
    /// métas qu'on lui ajoute.
    #[test]
    fn carte_repertoire() -> ResultFeuApplication<()> {
        let hash_blob1 = [0u8; 32];
        let hash_blob2 = [1u8; 32];
        let mut carte = Carte::new_repertoire(BTreeSet::new());

        if let Carte::Repertoire {
            metas: _,
            tags: _,
            hashs_enu: h,
        } = &carte
        {
            assert!(h.is_empty());
        }

        carte.ajout_hash_enu(&hash_blob1)?;
        carte.ajout_hash_enu(&hash_blob2)?;

        if let Carte::Repertoire {
            metas: _,
            tags: _,
            hashs_enu: h,
        } = &carte
        {
            assert_eq!(h.len(), 2);
        }

        assert!(carte.tags().is_empty());
        assert!(carte.metas().contains_key("date"));
        assert_eq!(carte.metas().len(), 1);

        carte.ajout_tag("tag1");
        carte.ajout_tag("tag2");

        assert_eq!(carte.tags().len(), 2);
        assert!(carte.tags().contains("tag1") && carte.tags().contains("tag2"));

        carte.ajout_meta("meta1", "valeur1");
        carte.ajout_meta("meta2", "valeur2");

        assert_eq!(carte.metas().len(), 3);
        assert!(carte.metas().contains_key("meta1") && carte.metas().contains_key("meta2"));

        Ok(())
    }
}
