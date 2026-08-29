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
//! sérialisée ([`Carte::vers_octets`]) est ce que l'enveloppe hash et signe :
//! d'où les collections ordonnées, seules à rendre le résultat reproductible.
//!
//! L'`enum` est public et ses variantes ouvertes, pour que les couches
//! supérieures discriminent par `match` plutôt que par des accesseurs à
//! [`Option`]. Forger une carte au dehors reste sans effet : seule une
//! enveloppe l'écrit dans `enu/`, et constructeurs comme mutateurs restent
//! `pub(super)`. La confiance vient de la vérification du hash et de la
//! signature au chargement, pas de l'encapsulation.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::from_utf8,
};

use crate::{ErreurFeuApplication, ResultFeuApplication};

/// Plafond du contenu d'une [`Carte::Texte`], en octets UTF-8.
///
/// Bornée volontairement bien en deçà du plafond de signature du noyau
/// ([`MAX_TAILLE_SIGNATURE`](feu_noyau::MAX_TAILLE_SIGNATURE), 64 kio) : la
/// marge restante absorbe l'en-tête de la carte sérialisée (discriminant,
/// métadonnées, tags, préfixe de longueur) sans avoir à le calculer finement.
/// 60 kio reste très large pour du texte brut.
///
/// **Borne incluse** : 61440 octets passent, la garde est un `>` strict. Une
/// taille est une quantité, pas un cardinal d'index — le `>=` de `MAX_FOYERS` et
/// `MAX_CLASSEURS`, où l'index valide s'arrête à MAX-1, ne s'applique pas ici.
pub(crate) const MAX_TAILLE_TEXTE: usize = 1024 * 60;

/// Contenu métier enveloppé par une `Enu`.
///
/// Trois variantes — Donnée (CaD), Texte (CaT), Répertoire (CaR) —, toutes
/// porteuses de métadonnées structurées et de tags libres. Les deux
/// collections sont ordonnées ([`BTreeMap`], [`BTreeSet`]) : le hash se calcule
/// sur leur sérialisation, qui doit être reproductible.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Carte {
    /// CaD — référence un blob stocké dans un classeur.
    Donnee {
        /// Métadonnées structurées clé → valeur.
        metas: BTreeMap<String, String>,
        /// Tags libres.
        tags: BTreeSet<String>,
        /// Hash SHA3-256 du blob (également le nom du fichier `.dat`).
        hash_blob: [u8; 32],
    },

    /// CaT — texte brut embarqué directement dans la carte. Sa taille est
    /// bornée à la construction (voir `new_texte`).
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
    /// Construit une [`Carte::Donnee`] — référence un blob dans un
    /// classeur.
    pub(super) fn new_donnee(hash_blob: [u8; 32]) -> Self {
        Self::Donnee {
            metas: BTreeMap::new(),
            tags: BTreeSet::new(),
            hash_blob,
        }
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
            } => metas,
            Self::Texte {
                metas,
                tags: _,
                contenu: _,
            } => metas,
            Self::Repertoire {
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
    /// parcours —, d'où l'[`Option`] plutôt qu'un refus. Elle distingue en outre
    /// la feuille du répertoire réellement vide, qu'un ensemble vide
    /// confondrait.
    ///
    /// Rend une référence : le parcours traverse tous les répertoires de l'arbre,
    /// un clone par pas serait payé pour rien.
    pub(crate) fn hashs_enu(&self) -> Option<&BTreeSet<[u8; 32]>> {
        match self {
            Self::Donnee {
                metas: _,
                tags: _,
                hash_blob: _,
            } => None,
            Self::Texte {
                metas: _,
                tags: _,
                contenu: _,
            } => None,
            Self::Repertoire {
                metas: _,
                tags: _,
                hashs_enu,
            } => Some(hashs_enu),
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
            } => tags,
            Self::Texte {
                metas: _,
                tags,
                contenu: _,
            } => tags,
            Self::Repertoire {
                metas: _,
                tags,
                hashs_enu: _,
            } => tags,
        }
    }

    /// Retourne le nom de l'entrée (méta `"nom"`), validé comme composant de
    /// chemin.
    ///
    /// Point de passage obligé avant de matérialiser une carte sur le système
    /// de fichiers (retrait) : le nom vient d'une ENU lue sur disque, et même
    /// signé il reste une entrée non fiable pour un `Path::join` — un nom
    /// absolu **remplacerait** le chemin cible, un `..` en sortirait. La
    /// validation ([`Self::nom_fichier_valide`]) garantit un composant unique
    /// et inoffensif.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeMetaNomAbsente`] si la méta
    /// `"nom"` est absente, ou
    /// [`ErreurFeuApplication::ScribeNomFichierInvalide`] si le nom est refusé
    /// comme composant de chemin.
    pub(super) fn nom_fichier(&self) -> ResultFeuApplication<String> {
        let Some(nom) = self.metas().get("nom") else {
            return Err(ErreurFeuApplication::ScribeMetaNomAbsente);
        };

        if !Self::nom_fichier_valide(nom) {
            return Err(ErreurFeuApplication::ScribeNomFichierInvalide);
        }

        Ok(nom.to_string())
    }

    /// `true` si `nom` est un composant de chemin unique et inoffensif.
    ///
    /// Empêche un nom d'entraîner l'écriture hors du dossier de retrait, pas un
    /// filtre d'affichage : elle écarte le vide, tout séparateur `/` (le seul,
    /// le protocole étant Unix-only) et les deux composants spéciaux `.` / `..`.
    /// Les noms cachés (`.bashrc`) restent acceptés — seule l'égalité stricte
    /// avec `.` ou `..` est refusée.
    fn nom_fichier_valide(nom: &str) -> bool {
        !nom.is_empty() && !nom.contains('/') && nom != "." && nom != ".."
    }

    /// Construit une [`Carte::Texte`] — le texte est embarqué directement dans
    /// la carte, sans blob ni classeur.
    ///
    /// Le contenu est borné à [`MAX_TAILLE_TEXTE`] (mesuré en octets UTF-8) : la
    /// vérification a lieu ici, avant toute mise sous enveloppe, pour échouer
    /// proprement plutôt que de buter sur le plafond de signature du noyau.
    ///
    /// Le `nom` est posé en méta `"nom"` — comme pour les entrées d'un comptoir
    /// de dépôt, c'est lui qui nommera le fichier au retrait. Contrairement à
    /// elles, il ne vient pas du système de fichiers mais de l'appelant : il est
    /// donc validé dès la construction ([`Self::nom_fichier_valide`]), pour
    /// refuser d'emblée une carte qu'aucun retrait ne saurait matérialiser.
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

        let mut enu = Self::Texte {
            metas: BTreeMap::new(),
            tags: BTreeSet::new(),
            contenu: contenu.to_string(),
        };
        enu.ajout_meta("nom", nom);

        Ok(enu)
    }

    /// Construit une [`Carte::Repertoire`] — référence des ENU enfants
    /// par leur `hash_carte`.
    pub(super) fn new_repertoire(hashs_enu: BTreeSet<[u8; 32]>) -> Self {
        Self::Repertoire {
            metas: BTreeMap::new(),
            tags: BTreeSet::new(),
            hashs_enu,
        }
    }

    /// Ajoute une métadonnée structurée à la carte.
    ///
    /// Insère la paire `(cle, valeur)` dans le [`BTreeMap`] de métadonnées.
    /// Si la clé existe déjà, sa valeur est écrasée.
    pub(super) fn ajout_meta(&mut self, cle: &str, valeur: &str) {
        let cle = String::from(cle);
        let valeur = String::from(valeur);

        match self {
            Self::Donnee {
                metas,
                tags: _,
                hash_blob: _,
            } => {
                metas.insert(cle, valeur);
            }
            Self::Texte {
                metas,
                tags: _,
                contenu: _,
            } => {
                metas.insert(cle, valeur);
            }
            Self::Repertoire {
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
    /// Insère le tag dans le [`BTreeSet`] de tags. Les doublons sont
    /// silencieusement ignorés.
    pub(super) fn ajout_tag(&mut self, tag: &str) {
        let tag = String::from(tag);
        match self {
            Self::Donnee {
                metas: _,
                tags,
                hash_blob: _,
            } => {
                tags.insert(tag);
            }
            Self::Texte {
                metas: _,
                tags,
                contenu: _,
            } => {
                tags.insert(tag);
            }
            Self::Repertoire {
                metas: _,
                tags,
                hashs_enu: _,
            } => {
                tags.insert(tag);
            }
        }
    }

    /// Ajoute le `hash_carte` d'une ENU enfant à un répertoire.
    ///
    /// Insère `hash` dans le [`BTreeSet`] `hashs_enu` de la
    /// [`Carte::Repertoire`]. Un doublon est silencieusement ignoré ;
    /// l'ordre déterministe du set préserve la reproductibilité du hash.
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
    pub(super) fn vers_octets(&self) -> Vec<u8> {
        let mut resultat = Vec::new();
        match self {
            Carte::Donnee {
                metas,
                tags,
                hash_blob,
            } => {
                resultat.push(0x00);
                metas_vers_octets(&mut resultat, metas);
                tags_vers_octets(&mut resultat, tags);
                resultat.extend(hash_blob);
            }
            Carte::Texte {
                metas,
                tags,
                contenu,
            } => {
                resultat.push(0x01);
                metas_vers_octets(&mut resultat, metas);
                tags_vers_octets(&mut resultat, tags);
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
                metas_vers_octets(&mut resultat, metas);
                tags_vers_octets(&mut resultat, tags);
                resultat.extend(&(hashs_enu.len() as u32).to_be_bytes());
                for h in hashs_enu {
                    resultat.extend(h);
                }
            }
        }
        resultat
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
                let hash_blob: [u8; 32] = hash.try_into().unwrap(); // pas d'erreur possible

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
                let longueur = u64::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

                (octets, reste) = prendre_octets(reste, longueur as usize)?;

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
                let n_hashs = u32::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

                let mut hashs_enu = BTreeSet::new();

                for _ in 0..n_hashs {
                    (octets, reste) = prendre_octets(reste, 32)?;
                    let hash: [u8; 32] = octets.try_into().unwrap(); // pas d'erreur possible
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

/// Écrit les tags dans le buffer au format canonique :
/// `u32 nb_tags` puis pour chaque tag `u32 len_utf8` suivi des octets UTF-8.
fn tags_vers_octets(buf: &mut Vec<u8>, tags: &BTreeSet<String>) {
    buf.extend(&(tags.len() as u32).to_be_bytes());

    for tag in tags {
        let b = tag.as_bytes();
        buf.extend(&(b.len() as u32).to_be_bytes());
        buf.extend(b);
    }
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
    let n_tags = u32::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

    for _ in 0..n_tags {
        (octets, reste) = prendre_octets(reste, 4)?;
        let longueur = u32::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

        (octets, reste) = prendre_octets(reste, longueur as usize)?;

        tags.insert(from_utf8(octets)?.to_string());
    }

    Ok((tags, reste))
}

/// Écrit les métadonnées dans le buffer au format canonique :
/// `u32 nb_metas` puis pour chaque paire `u32 len_cle`, clé UTF-8, `u32
/// len_valeur`, valeur UTF-8. Ordre de parcours : celui du BTreeMap
/// (alphabétique par clé).
fn metas_vers_octets(buf: &mut Vec<u8>, metas: &BTreeMap<String, String>) {
    buf.extend(&(metas.len() as u32).to_be_bytes());

    for (cle, valeur) in metas {
        let cle = cle.as_bytes();
        let valeur = valeur.as_bytes();
        buf.extend(&(cle.len() as u32).to_be_bytes());
        buf.extend(cle);
        buf.extend(&(valeur.len() as u32).to_be_bytes());
        buf.extend(valeur);
    }
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
    let n_metas = u32::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

    for _ in 0..n_metas {
        (octets, reste) = prendre_octets(reste, 4)?;
        let longueur = u32::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

        (octets, reste) = prendre_octets(reste, longueur as usize)?;
        let cle = from_utf8(octets)?.to_string();

        (octets, reste) = prendre_octets(reste, 4)?;
        let longueur = u32::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

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

#[cfg(test)]
mod tests {
    //! Tests en ligne : ce qui se prouve sans monter de pile.
    //!
    //! Une carte n'est que des octets et des collections ordonnées : la forger
    //! à la main suffit, rien ici ne signe ni ne chiffre. L'aller-retour par le
    //! format canonique et les gardes de construction — taille du texte, nom de
    //! fichier — s'éprouvent donc au plus près du code qui les tient.
    //!
    //! Mettre une carte sous enveloppe signée demande au contraire un noyau
    //! allumé et un foyer ouvert : ces tests-là sont dans `src/scribe/tests.rs`.

    use super::*;

    // --- prendre_octets ---

    /// Buffer exactement de la bonne taille → extraction complète, reste vide.
    #[test]
    fn prendre_octets_reste_vide() -> ResultFeuApplication<()> {
        let octets: &[u8] = &[1, 2, 3];
        let (octets_pris, reste) = prendre_octets(octets, 3)?;

        assert_eq!(octets, octets_pris);
        assert_eq!(reste, &[]);

        Ok(())
    }

    /// Buffer plus grand que la demande → extraction des n premiers, reste non
    /// vide.
    #[test]
    fn prendre_octets_reste_non_vide() -> ResultFeuApplication<()> {
        let octets: &[u8] = &[1, 2, 3, 4, 5, 6];
        let (octets_pris, reste) = prendre_octets(octets, 2)?;

        assert_eq!(octets_pris, &octets[0..2]);
        assert_eq!(reste, &octets[2..]);

        Ok(())
    }

    /// Buffer trop court → [`ErreurFeuApplication::ScribeCarteMalFormee`].
    #[test]
    fn prendre_octets_trop_court() {
        let octets: &[u8] = &[1, 2, 3];

        assert!(matches!(
            prendre_octets(octets, 5),
            Err(ErreurFeuApplication::ScribeCarteMalFormee)
        ));
    }

    /// Demande de 0 octets → extrait vide, reste = buffer entier.
    #[test]
    fn prendre_octets_vide() -> ResultFeuApplication<()> {
        let octets: &[u8] = &[1, 2, 3];
        let (octets_pris, reste) = prendre_octets(octets, 0)?;

        assert_eq!(reste, octets);
        assert_eq!(octets_pris, &[]);

        Ok(())
    }

    // --- Tags et métadonnées ---

    /// Round-trip balise vide : 0 tag → octets → 0 tag, reste vide.
    #[test]
    fn tags_vide_vers_octets() -> ResultFeuApplication<()> {
        let tags = BTreeSet::new();
        let mut octets = Vec::new();

        tags_vers_octets(&mut octets, &tags);
        let (tags_retour, reste) = octets_vers_tags(&octets)?;

        assert!(tags_retour.is_empty());
        assert!(reste.is_empty());

        Ok(())
    }

    /// Round-trip balise unique.
    #[test]
    fn tags_unique_vers_octets() -> ResultFeuApplication<()> {
        let tags = BTreeSet::from([String::from("tag1")]);
        let mut octets = Vec::new();

        tags_vers_octets(&mut octets, &tags);
        let (tags_retour, reste) = octets_vers_tags(&octets)?;

        assert_eq!(tags_retour, tags);
        assert!(reste.is_empty());

        Ok(())
    }

    /// Round-trip balises multiples, ordre BTreeSet (déterminé).
    #[test]
    fn tags_multi_vers_octets() -> ResultFeuApplication<()> {
        let tags = BTreeSet::from([String::from("z"), String::from("b"), String::from("a")]);
        let mut octets = Vec::new();

        tags_vers_octets(&mut octets, &tags);
        let (tags_retour, reste) = octets_vers_tags(&octets)?;

        assert_eq!(tags_retour, tags);
        assert!(reste.is_empty());

        Ok(())
    }

    /// Round-trip métadonnées vides : 0 paire → octets → 0 paire, reste vide.
    #[test]
    fn metas_vide_vers_octets() -> ResultFeuApplication<()> {
        let metas = BTreeMap::new();
        let mut octets = Vec::new();

        metas_vers_octets(&mut octets, &metas);
        let (metas_retour, reste) = octets_vers_metas(&octets)?;

        assert!(metas_retour.is_empty());
        assert!(reste.is_empty());

        Ok(())
    }

    /// Round-trip métadonnée unique : une paire clé/valeur préservée.
    #[test]
    fn metas_unique_vers_octets() -> ResultFeuApplication<()> {
        let metas = BTreeMap::from([(String::from("clé1"), String::from("valeur1"))]);
        let mut octets = Vec::new();

        metas_vers_octets(&mut octets, &metas);
        let (metas_retour, reste) = octets_vers_metas(&octets)?;

        assert_eq!(metas, metas_retour);
        assert!(reste.is_empty());

        Ok(())
    }

    /// Round-trip métadonnées multiples : tri par clé (ordre BTreeMap) préservé.
    #[test]
    fn metas_multi_vers_octets() -> ResultFeuApplication<()> {
        let metas = BTreeMap::from([
            (String::from("clé5"), String::from("valeur5")),
            (String::from("clé1"), String::from("valeur1")),
            (String::from("clé2"), String::from("valeur2")),
        ]);
        let mut octets = Vec::new();

        metas_vers_octets(&mut octets, &metas);
        let (metas_retour, reste) = octets_vers_metas(&octets)?;

        assert_eq!(metas, metas_retour);
        assert!(reste.is_empty());

        Ok(())
    }

    // --- Cartes ---

    /// Round-trip CaD : metas + tags + hash → octets → même carte.
    #[test]
    fn carte_donnee_vers_octets() -> ResultFeuApplication<()> {
        let metas = BTreeMap::from([
            (String::from("clé1"), String::from("valeur1")),
            (String::from("clé2"), String::from("valeur2")),
        ]);
        let tags = BTreeSet::from([String::from("tag1"), String::from("tag2")]);
        let hash_blob: [u8; 32] = std::array::from_fn(|i| i as u8);

        let carte = Carte::Donnee {
            metas,
            tags,
            hash_blob,
        };

        let octets = carte.vers_octets();
        let carte_retour = Carte::octets_vers_carte(&octets)?;

        assert_eq!(carte, carte_retour);

        Ok(())
    }

    /// Round-trip CaT : metas + tags + texte → octets → même carte.
    #[test]
    fn carte_texte_vers_octets() -> ResultFeuApplication<()> {
        let metas = BTreeMap::from([
            (String::from("clé1"), String::from("valeur1")),
            (String::from("clé2"), String::from("valeur2")),
        ]);
        let tags = BTreeSet::from([String::from("tag1"), String::from("tag2")]);
        let contenu = String::from("Contenu de la carte");

        let carte = Carte::Texte {
            metas,
            tags,
            contenu,
        };

        let octets = carte.vers_octets();
        let carte_retour = Carte::octets_vers_carte(&octets)?;

        assert_eq!(carte, carte_retour);

        Ok(())
    }

    /// Round-trip CaR : metas + tags + 2 hashs enfants → octets → même carte.
    #[test]
    fn carte_repertoire_vers_octets() -> ResultFeuApplication<()> {
        let metas = BTreeMap::from([
            (String::from("clé1"), String::from("valeur1")),
            (String::from("clé2"), String::from("valeur2")),
        ]);
        let tags = BTreeSet::from([String::from("tag1"), String::from("tag2")]);
        let hash1: [u8; 32] = std::array::from_fn(|i| i as u8);
        let hash2: [u8; 32] = std::array::from_fn(|i| (i * 2) as u8);

        let hashs_enu = BTreeSet::from([hash1, hash2]);

        let carte = Carte::Repertoire {
            metas,
            tags,
            hashs_enu,
        };

        let octets = carte.vers_octets();
        let carte_retour = Carte::octets_vers_carte(&octets)?;

        assert_eq!(carte, carte_retour);

        Ok(())
    }

    /// Cycle complet sur `Carte::Donnee` : hash conservé à la construction,
    /// refus de `ajout_hash_enu` (`ScribeEnuRAttendue`), tags et metas insérés
    /// puis relus via les accesseurs communs.
    #[test]
    fn carte_donnee() -> ResultFeuApplication<()> {
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

        assert!(carte.tags().is_empty() && carte.metas().is_empty());

        carte.ajout_tag("tag1");
        carte.ajout_tag("tag2");

        assert_eq!(carte.tags().len(), 2);
        assert!(carte.tags().contains("tag1") && carte.tags().contains("tag2"));

        carte.ajout_meta("meta1", "valeur1");
        carte.ajout_meta("meta2", "valeur2");

        assert_eq!(carte.metas().len(), 2);
        assert!(carte.metas().contains_key("meta1") && carte.metas().contains_key("meta2"));

        Ok(())
    }

    /// Cycle complet sur `Carte::Texte` : contenu conservé et méta `"nom"`
    /// posée dès la construction, refus de `ajout_hash_enu`
    /// (`ScribeEnuRAttendue`),
    /// tags et metas insérés puis relus via les accesseurs communs.
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

        assert_eq!(carte.metas().len(), 3);
        assert!(carte.metas().contains_key("meta1") && carte.metas().contains_key("meta2"));

        Ok(())
    }

    /// Contenu dépassant `MAX_TAILLE_TEXTE` d'un octet → refus
    /// (`ScribeTailleMaxDepasseeTexte`).
    #[test]
    fn carte_texte_trop_grande() -> ResultFeuApplication<()> {
        let contenu = "a".repeat(MAX_TAILLE_TEXTE + 1);

        assert!(matches!(
            Carte::new_texte("test", &contenu),
            Err(ErreurFeuApplication::ScribeTailleMaxDepasseeTexte(_))
        ));

        Ok(())
    }

    /// Nom contenant un séparateur de chemin → refus
    /// (`ScribeNomFichierInvalide`).
    ///
    /// Éprouve la validation à la **construction**, distincte de celle de
    /// `nom_fichier` (couverte par le test du même nom) : `new_texte` reçoit son
    /// nom de l'appelant, pas du disque, et refuse d'emblée une carte qu'aucun
    /// retrait ne saurait matérialiser. Un seul cas suffit ici — les deux
    /// chemins partagent `nom_fichier_valide`, éprouvé exhaustivement ailleurs.
    #[test]
    fn carte_texte_mauvais_nom() {
        assert!(matches!(
            Carte::new_texte("te/st", "contenu"),
            Err(ErreurFeuApplication::ScribeNomFichierInvalide)
        ));
    }

    /// Cycle complet sur `Carte::Repertoire` : hashs enfants insérés via
    /// `ajout_hash_enu`, tags et metas insérés puis relus via les
    /// accesseurs communs.
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

        assert!(carte.tags().is_empty() && carte.metas().is_empty());

        carte.ajout_tag("tag1");
        carte.ajout_tag("tag2");

        assert_eq!(carte.tags().len(), 2);
        assert!(carte.tags().contains("tag1") && carte.tags().contains("tag2"));

        carte.ajout_meta("meta1", "valeur1");
        carte.ajout_meta("meta2", "valeur2");

        assert_eq!(carte.metas().len(), 2);
        assert!(carte.metas().contains_key("meta1") && carte.metas().contains_key("meta2"));

        Ok(())
    }

    /// Validation du nom par `nom_fichier`, sur ses deux refus et son corpus
    /// accepté.
    ///
    /// Les refus : méta absente, nom vide, toute forme de `/`, et `.` comme `..`
    /// **exacts**.
    ///
    /// Les cas acceptés portent tous des points sans être ces composants —
    /// `.test`, `..test`, `test..` — et distinguent l'égalité stricte d'un
    /// `starts_with` qui rejetterait un fichier caché. Le nom rendu est vérifié,
    /// pas seulement l'absence d'erreur : la garde ne doit rien réécrire.
    #[test]
    fn nom_fichier() -> ResultFeuApplication<()> {
        let hash_blob = [0u8; 32];

        let mut carte = Carte::new_donnee(hash_blob);

        // Pas de meta nom
        assert!(matches!(
            carte.nom_fichier(),
            Err(ErreurFeuApplication::ScribeMetaNomAbsente)
        ));

        // Nom vide
        carte.ajout_meta("nom", "");

        assert!(matches!(
            carte.nom_fichier(),
            Err(ErreurFeuApplication::ScribeNomFichierInvalide)
        ));

        // Nom commence par '/'
        carte.ajout_meta("nom", "/azerty");

        assert!(matches!(
            carte.nom_fichier(),
            Err(ErreurFeuApplication::ScribeNomFichierInvalide)
        ));

        // Nom contient '/'
        carte.ajout_meta("nom", "aa/bbb");

        assert!(matches!(
            carte.nom_fichier(),
            Err(ErreurFeuApplication::ScribeNomFichierInvalide)
        ));

        // Nom contient plusieurs '/'
        carte.ajout_meta("nom", "/aa/bbb/");

        assert!(matches!(
            carte.nom_fichier(),
            Err(ErreurFeuApplication::ScribeNomFichierInvalide)
        ));

        // Nom termine par '/'
        carte.ajout_meta("nom", "azerty/");

        assert!(matches!(
            carte.nom_fichier(),
            Err(ErreurFeuApplication::ScribeNomFichierInvalide)
        ));

        // Nom est '.'
        carte.ajout_meta("nom", ".");

        assert!(matches!(
            carte.nom_fichier(),
            Err(ErreurFeuApplication::ScribeNomFichierInvalide)
        ));

        // Nom est '..'
        carte.ajout_meta("nom", "..");

        assert!(matches!(
            carte.nom_fichier(),
            Err(ErreurFeuApplication::ScribeNomFichierInvalide)
        ));

        // Nom débute par '.'
        carte.ajout_meta("nom", ".test");
        assert_eq!(carte.nom_fichier()?, ".test");

        // Nom termine par '.'
        carte.ajout_meta("nom", "test.");
        assert_eq!(carte.nom_fichier()?, "test.");

        // Nom contient '.'
        carte.ajout_meta("nom", "test.2");
        assert_eq!(carte.nom_fichier()?, "test.2");

        // Nom débute par '..'
        carte.ajout_meta("nom", "..test");
        assert_eq!(carte.nom_fichier()?, "..test");

        // Nom termine par '..'
        carte.ajout_meta("nom", "test..");
        assert_eq!(carte.nom_fichier()?, "test..");

        // Nom contient '..'
        carte.ajout_meta("nom", "test..2");
        assert_eq!(carte.nom_fichier()?, "test..2");

        // Nom contient '.' et '..'
        carte.ajout_meta("nom", ".te.st..test.te.st..");
        assert_eq!(carte.nom_fichier()?, ".te.st..test.te.st..");

        Ok(())
    }
}
