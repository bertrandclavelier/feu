// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Types ENU : enveloppes et cartes.
//!
//! Une [`Enu`] est une enveloppe signée contenant une [`Carte`]. La carte
//! porte le contenu métier (données, texte, répertoire). L'enveloppe ajoute
//! l'identité (hash), l'authenticité (signature ML-DSA-87) et la braise du
//! foyer signataire.
//!
//! Les types ENU sont **content-addressed** : le hash de la carte sert de nom
//! de fichier sur disque (`<hash_hex>.enu`). Aucune carte n'a de nom stable.

use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

use feu_noyau::FeuNoyau;

use crate::scribe::erreur::ResultScribe;

/// Enveloppe Numérique Universelle.
///
/// Le `hash_carte` (SHA3-256 de la carte sérialisée) est le nom du fichier
/// dans `~/.feu/enu/`. La `signature_carte` (ML-DSA-87) couvre la carte
/// sérialisée directement. La `date` est le timestamp Unix de mise sous
/// enveloppe. La `braise` identifie le foyer signataire pour la vérification.
pub(super) struct Enu {
    /// Adresse `.braise` du foyer signataire (non couverte par le hash ni la
    /// signature — métadonnée de routage).
    braise: String,

    /// SHA3-256 de la carte sérialisée.
    hash_carte: [u8; 32],
    /// Signature ML-DSA-87 de la carte sérialisée (taille fixe, 4627 o).
    signature_carte: [u8; 4627],
    /// Timestamp Unix de mise sous enveloppe (non couvert par la signature).
    date: u64,

    carte: Carte,
}

impl Enu {
    /// Crée une ENU signée.
    ///
    /// Hash la carte (`creation_empreinte`), la signe avec la clé du foyer
    /// (`signature_foyer`), horodate. Le foyer doit être ouvert.
    ///
    /// La taille de la carte sérialisée est limitée à
    /// [`MAX_TAILLE_SIGNATURE`] (64 kio) par le noyau.
    pub(super) fn new(
        carte: Carte,
        feu_noyau: &FeuNoyau,
        index_foyer: usize,
        braise: String,
    ) -> ResultScribe<Self> {
        let octets_carte = carte.vers_octets();
        Ok(Self {
            braise,
            hash_carte: FeuNoyau::creation_empreinte(&octets_carte),
            signature_carte: feu_noyau.signature_foyer(index_foyer, &octets_carte)?,
            date: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Horloge système antérieure à 1970")
                .as_secs(),
            carte,
        })
    }

    /// Sérialise l'enveloppe pour écriture disque.
    ///
    /// Format : `braise` (u16 len + UTF-8) | `hash_carte` (32 o) |
    /// `signature_carte` (4627 o) | `date` (u64 BE) | carte (délègue à
    /// [`Carte::vers_octets`]).
    fn vers_octets(&self) -> Vec<u8> {
        let mut resultat = Vec::new();

        let b = self.braise.as_bytes();
        resultat.extend(&(b.len() as u16).to_be_bytes());
        resultat.extend(b);
        resultat.extend(self.hash_carte);
        resultat.extend(self.signature_carte);
        resultat.extend(&self.date.to_be_bytes());
        resultat.extend(self.carte.vers_octets());

        resultat
    }
}

/// Carte : contenu métier d'une ENU.
///
/// Trois variantes — Donnée (CaD), Texte (CaT), Répertoire (CaR).
/// Chaque variante porte un `BTreeSet<String>` de tags.
/// Les `BTreeSet` garantissent l'ordre déterministe nécessaire au hash.
pub(super) enum Carte {
    /// CaD — référence un blob stocké dans un classeur.
    Donnee {
        tags: BTreeSet<String>,
        /// Hash SHA3-256 du blob (également le nom du fichier `.dat`).
        hash_donnee: [u8; 32],
    },

    /// CaT — texte brut, pas de limite de taille en v0.0.5.
    Texte {
        tags: BTreeSet<String>,
        contenu: String,
    },

    /// CaR — répertoire, référence ses enfants par leur `hash_carte`.
    Repertoire {
        tags: BTreeSet<String>,
        /// Hash des ENU enfants. L'ordre [`BTreeSet`] assure la reproductibilité
        /// du hash de cette carte.
        hashs_enu: BTreeSet<[u8; 32]>,
    },
}

impl Carte {
    /// Écrit les tags dans le buffer au format canonique :
    /// `u16 nb_tags` puis pour chaque tag `u16 len_utf8` suivi des octets UTF-8.
    fn tags_vers_octets(buf: &mut Vec<u8>, tags: &BTreeSet<String>) {
        buf.extend(&(tags.len() as u16).to_be_bytes());
        for tag in tags {
            let b = tag.as_bytes();
            buf.extend(&(b.len() as u16).to_be_bytes());
            buf.extend(b);
        }
    }

    /// Sérialise la carte en bytes canoniques.
    ///
    /// Format : discriminant `u8` (0x00=CaD, 0x01=CaT, 0x02=CaR), tags, puis
    /// les champs spécifiques à chaque variant. Le résultat est déterministe :
    /// même carte → mêmes octets → même hash.
    fn vers_octets(&self) -> Vec<u8> {
        let mut resultat = Vec::new();
        match self {
            Carte::Donnee { tags, hash_donnee } => {
                resultat.push(0x00);
                Self::tags_vers_octets(&mut resultat, tags);
                resultat.extend(hash_donnee);
            }
            Carte::Texte { tags, contenu } => {
                resultat.push(0x01);
                Self::tags_vers_octets(&mut resultat, tags);
                let c = contenu.as_bytes();
                resultat.extend(&(c.len() as u64).to_be_bytes());
                resultat.extend(c);
            }
            Carte::Repertoire { tags, hashs_enu } => {
                resultat.push(0x02);
                Self::tags_vers_octets(&mut resultat, tags);
                resultat.extend(&(hashs_enu.len() as u16).to_be_bytes());
                for h in hashs_enu {
                    resultat.extend(h);
                }
            }
        }
        resultat
    }
}
