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
//!
//! # Modèle de confiance
//!
//! Le hash et la signature couvrent **uniquement la carte sérialisée**, jamais
//! la braise ni la date — qui restent des métadonnées malléables (routage,
//! horodatage indicatif). La désérialisation reconstruit les champs sans
//! revérifier le hash ni la signature : tant qu'une ENU vient du disque, elle
//! n'est pas digne de confiance avant que l'appelant ait recalculé le hash de
//! sa carte et validé la signature contre la braise annoncée.
//!
//! # Couplage avec la braise du noyau
//!
//! Le format sérialisé suppose une braise de **62 octets exactement**
//! (55 caractères BASE32 + suffixe `.braise`). Cette longueur est figée par
//! `feu-noyau` ; c'est ce qui autorise à la stocker sans préfixe de taille.
//! Toute évolution de l'adresse `.braise` côté noyau doit être répercutée
//! ici, faute de quoi le format casse sans erreur de compilation.

use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

use feu_noyau::FeuNoyau;

use crate::scribe::erreur::{ErreurScribe, ResultScribe};

/// Le buffer est trop court ou contient un discriminant inconnu.
const ERR_SCR_001: &str = "SCR-001 > Problème désérialisation";
/// Les octets censés être du texte ne sont pas du UTF-8 valide.
const ERR_SCR_002: &str = "SCR-002 > UTF-8 invalide";

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
    /// Format : `braise` (62 o UTF-8) | `hash_carte` (32 o) |
    /// `signature_carte` (4627 o) | `date` (u64 BE) | carte (délègue à
    /// [`Carte::vers_octets`]).
    fn vers_octets(&self) -> Vec<u8> {
        let mut resultat = Vec::new();

        resultat.extend(self.braise.as_bytes());
        resultat.extend(self.hash_carte);
        resultat.extend(self.signature_carte);
        resultat.extend(&self.date.to_be_bytes());
        resultat.extend(self.carte.vers_octets());

        resultat
    }

    /// Désérialise une ENU depuis ses octets canoniques.
    ///
    /// Format attendu : `braise` (62 o) | `hash_carte` (32 o) |
    /// `signature_carte` (4627 o) | `date` (u64 BE) | carte (via
    /// [`Carte::octets_vers_carte`]). Inverse de [`Enu::vers_octets`].
    ///
    /// Ne valide **que la structure**, pas l'authenticité : le hash n'est pas
    /// recalculé et la signature n'est pas vérifiée. Une ENU issue du disque
    /// reste donc non fiable tant que l'appelant n'a pas fait ces deux contrôles.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] si le buffer est trop court
    /// (`SCR-001`), si le discriminant de carte est inconnu (`SCR-001`) ou si un
    /// champ texte n'est pas du UTF-8 valide (`SCR-002`).
    fn octets_vers_enu(octets: &[u8]) -> ResultScribe<Enu> {
        let (mut octets, mut reste) = prendre_octets(octets, 62)?;
        let braise = str::from_utf8(octets)
            .map_err(|_| ErreurScribe::Interne(String::from(ERR_SCR_002)))?
            .to_string();

        (octets, reste) = prendre_octets(reste, 32)?;
        let hash_carte: [u8; 32] = octets.try_into().unwrap(); // pas d'erreur possible

        (octets, reste) = prendre_octets(reste, 4627)?;
        let signature_carte: [u8; 4627] = octets.try_into().unwrap(); // pas d'erreur possible

        (octets, reste) = prendre_octets(reste, 8)?;
        let date = u64::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

        let carte = Carte::octets_vers_carte(reste)?;

        Ok(Self {
            braise,
            hash_carte,
            signature_carte,
            date,
            carte,
        })
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
                tags_vers_octets(&mut resultat, tags);
                resultat.extend(hash_donnee);
            }
            Carte::Texte { tags, contenu } => {
                resultat.push(0x01);
                tags_vers_octets(&mut resultat, tags);
                let c = contenu.as_bytes();
                resultat.extend(&(c.len() as u64).to_be_bytes());
                resultat.extend(c);
            }
            Carte::Repertoire { tags, hashs_enu } => {
                resultat.push(0x02);
                tags_vers_octets(&mut resultat, tags);
                resultat.extend(&(hashs_enu.len() as u16).to_be_bytes());
                for h in hashs_enu {
                    resultat.extend(h);
                }
            }
        }
        resultat
    }

    /// Désérialise une carte depuis ses octets canoniques.
    ///
    /// Format attendu : discriminant `u8`, tags (via [`octets_vers_tags`]), puis
    /// contenu spécifique au variant (32 o hash, `u64` len + texte, ou `u16` nb
    /// hashs + 32o × n). Inverse de [`Carte::vers_octets`].
    fn octets_vers_carte(octets: &[u8]) -> ResultScribe<Carte> {
        let (mut octets, reste) = prendre_octets(octets, 1)?;

        let (tags, mut reste) = octets_vers_tags(reste)?;

        match octets[0] {
            0 => {
                let (hash, _) = prendre_octets(reste, 32)?;
                let hash_donnee: [u8; 32] = hash.try_into().unwrap(); // pas d'erreur possible

                Ok(Carte::Donnee { tags, hash_donnee })
            }
            1 => {
                (octets, reste) = prendre_octets(reste, 8)?;
                let longueur = u64::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

                (octets, _) = prendre_octets(reste, longueur as usize)?;

                let contenu = str::from_utf8(octets)
                    .map_err(|_| ErreurScribe::Interne(String::from(ERR_SCR_002)))?
                    .to_string();

                Ok(Carte::Texte { tags, contenu })
            }

            2 => {
                (octets, reste) = prendre_octets(reste, 2)?;
                let n_hashs = u16::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

                let mut hashs_enu = BTreeSet::new();

                for _ in 0..n_hashs {
                    (octets, reste) = prendre_octets(reste, 32)?;
                    let hash: [u8; 32] = octets.try_into().unwrap(); // pas d'erreur possible
                    hashs_enu.insert(hash);
                }

                Ok(Carte::Repertoire { tags, hashs_enu })
            }

            _ => Err(ErreurScribe::Interne(String::from(ERR_SCR_001))),
        }
    }
}

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

/// Désérialise un `BTreeSet<String>` de tags depuis le format canonique.
///
/// Format : `u16` nb_tags, puis pour chaque tag `u16` len_utf8 suivi des octets
/// UTF-8. Retourne les tags et le reste du buffer non consommé.
fn octets_vers_tags(octets: &[u8]) -> ResultScribe<(BTreeSet<String>, &[u8])> {
    let mut tags = BTreeSet::new();
    let (mut octets, mut reste) = prendre_octets(octets, 2)?;
    let n_tags = u16::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

    for _ in 0..n_tags {
        (octets, reste) = prendre_octets(reste, 2)?;
        let longueur = u16::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

        (octets, reste) = prendre_octets(reste, longueur as usize)?;

        tags.insert(
            str::from_utf8(octets)
                .map_err(|_| ErreurScribe::Interne(String::from(ERR_SCR_002)))?
                .to_string(),
        );
    }

    Ok((tags, reste))
}

/// Extrait les `n` premiers octets du buffer.
///
/// Retourne `(extrait, reste)` ou une erreur si le buffer est trop court.
fn prendre_octets(buf: &[u8], n: usize) -> ResultScribe<(&[u8], &[u8])> {
    if buf.len() < n {
        return Err(ErreurScribe::Interne(String::from(ERR_SCR_001)));
    }
    Ok((&buf[0..n], &buf[n..]))
}
