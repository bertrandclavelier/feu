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

use data_encoding::HEXLOWER;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{OpenOptions, read},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use feu_noyau::FeuNoyau;

use crate::{
    SessionApplication,
    scribe::erreur::{ErreurScribe, ResultScribe},
};

/// Le buffer est trop court, porte un discriminant de carte inconnu, ou laisse
/// des octets résiduels après désérialisation.
const ERR_ENU_001: &str = "ENU-001 > Problème désérialisation";
/// Les octets censés être du texte ne sont pas du UTF-8 valide.
const ERR_ENU_002: &str = "ENU-002 > UTF-8 invalide";
/// L'ENU lue sur disque n'a pas pu être authentifiée : signataire inconnu de la
/// session, signature invalide, ou hash de carte ne correspondant pas.
const ERR_ENU_003: &str = "ENU-003 > Problème ouverture ENU";

/// Enveloppe Numérique Universelle.
///
/// Le `hash_carte` (SHA3-256 de la carte sérialisée) est le nom du fichier
/// dans `~/.feu/enu/`. La `signature_carte` (ML-DSA-87) couvre la carte
/// sérialisée directement. La `date` est le timestamp Unix de mise sous
/// enveloppe. La `braise` identifie le foyer signataire pour la vérification.
#[derive(PartialEq, Eq, Debug)]
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

    /// Écrit l'ENU sur disque sous `~/.feu/enu/<hash_carte_hex>.enu`.
    ///
    /// Le nom du fichier est l'empreinte hexadécimale de la carte
    /// (content-addressing) : une carte donnée vise toujours le même fichier,
    /// indépendamment de l'enveloppe qui la transporte. Le fichier est créé en
    /// mode `0o600` (lecture/écriture réservées au propriétaire) et en
    /// `create_new`, qui refuse d'écraser un fichier existant.
    ///
    /// Conséquence du content-addressing : ré-envelopper une carte déjà
    /// sauvegardée vise le même nom de fichier — l'écriture échoue alors, même
    /// si la nouvelle enveloppe diffère par sa `date` ou sa `signature` (ces
    /// champs ne participent pas au nom).
    ///
    /// # Erreurs
    ///
    /// Propage une [`ErreurScribe::IoError`] si le dossier `~/.feu/enu/` est
    /// absent, si une ENU de même empreinte existe déjà, ou sur tout autre
    /// échec d'écriture.
    pub(super) fn sauvegarder(&self) -> ResultScribe<()> {
        let nom_fichier = format!("{}.enu", HEXLOWER.encode(&self.hash_carte));
        let chemin = crate::scribe::donne_chemin_dossier_enu().join(nom_fichier);

        let mut fichier = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(chemin)?;

        fichier.write_all(&self.vers_octets())?;

        Ok(())
    }

    /// Charge **et authentifie** une ENU depuis le disque.
    ///
    /// Là où [`Enu::octets_vers_enu`] ne valide que la structure, cette méthode
    /// reconstruit l'enveloppe puis franchit la frontière de confiance : elle ne
    /// renvoie une ENU que si les trois conditions suivantes sont réunies.
    ///
    /// 1. La `braise` annoncée désigne un foyer connu de la session.
    /// 2. La signature ML-DSA-87 est valide pour la clé publique de ce foyer.
    /// 3. Le hash recalculé de la carte égale le `hash_carte` stocké.
    ///
    /// Une enveloppe au signataire inconnu, falsifiée ou corrompue ne passe
    /// jamais cette barrière. Rappel du modèle de confiance : `braise` et `date`
    /// restant hors signature, leur intégrité n'est pas garantie — seules
    /// l'identité et l'authenticité de la **carte** le sont.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] (`ENU-003`) si l'ENU n'est pas
    /// authentifiable, et propage toute erreur d'E/S
    /// ([`ErreurScribe::IoError`]), de désérialisation ou cryptographique
    /// ([`ErreurScribe::FeuNoyau`]) rencontrée en chemin.
    pub(super) fn charger(chemin: PathBuf, session: &SessionApplication) -> ResultScribe<Enu> {
        let enu = Self::octets_vers_enu(&read(&chemin)?)?;
        let octets_carte = enu.carte.vers_octets();

        if let Some(index_foyer) = session.braise_vers_index(&enu.braise) {
            if FeuNoyau::verification_signature(
                session.cle_publique_sig_foyer(index_foyer)?,
                enu.signature_carte,
                &octets_carte,
            )? && FeuNoyau::creation_empreinte(&octets_carte) == enu.hash_carte
            {
                return Ok(enu);
            }
        }
        Err(ErreurScribe::Interne(String::from(ERR_ENU_003)))
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
    /// (`ENU-001`), si le discriminant de carte est inconnu (`ENU-001`) ou si un
    /// champ texte n'est pas du UTF-8 valide (`ENU-002`).
    fn octets_vers_enu(octets: &[u8]) -> ResultScribe<Enu> {
        let (mut octets, mut reste) = prendre_octets(octets, 62)?;
        let braise = str::from_utf8(octets)
            .map_err(|_| ErreurScribe::Interne(String::from(ERR_ENU_002)))?
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
/// Chaque variante porte des métadonnées structurées (`BTreeMap<String, String>`)
/// et des tags libres (`BTreeSet<String>`). L'ordre déterministe des deux
/// collections est nécessaire au calcul du hash.
#[derive(PartialEq, Eq, Debug)]
pub(super) enum Carte {
    /// CaD — référence un blob stocké dans un classeur.
    Donnee {
        metas: BTreeMap<String, String>,
        tags: BTreeSet<String>,
        /// Hash SHA3-256 du blob (également le nom du fichier `.dat`).
        hash_donnee: [u8; 32],
    },

    /// CaT — texte brut, pas de limite de taille en v0.0.5.
    Texte {
        metas: BTreeMap<String, String>,
        tags: BTreeSet<String>,
        contenu: String,
    },

    /// CaR — répertoire, référence ses enfants par leur `hash_carte`.
    Repertoire {
        metas: BTreeMap<String, String>,
        tags: BTreeSet<String>,
        /// Hash des ENU enfants. L'ordre [`BTreeSet`] assure la reproductibilité
        /// du hash de cette carte.
        hashs_enu: BTreeSet<[u8; 32]>,
    },
}

impl Carte {
    /// Construit une [`Carte::Donnee`] — référence un blob dans un
    /// classeur.
    pub(super) fn new_donnee(
        metas: BTreeMap<String, String>,
        tags: BTreeSet<String>,
        hash_donnee: [u8; 32],
    ) -> Self {
        Self::Donnee {
            metas,
            tags,
            hash_donnee,
        }
    }

    /// Construit une [`Carte::Texte`] — contient directement le texte.
    pub(super) fn new_texte(
        metas: BTreeMap<String, String>,
        tags: BTreeSet<String>,
        contenu: String,
    ) -> Self {
        Self::Texte {
            metas,
            tags,
            contenu,
        }
    }

    /// Construit une [`Carte::Repertoire`] — référence des ENU enfants
    /// par leur `hash_carte`.
    pub(super) fn new_repertoire(
        metas: BTreeMap<String, String>,
        tags: BTreeSet<String>,
        hashs_enu: BTreeSet<[u8; 32]>,
    ) -> Self {
        Self::Repertoire {
            metas,
            tags,
            hashs_enu,
        }
    }

    /// Sérialise la carte en bytes canoniques.
    ///
    /// Format : discriminant `u8` (0x00=CaD, 0x01=CaT, 0x02=CaR), métadonnées,
    /// tags, puis les champs spécifiques à chaque variant. Le résultat est
    /// déterministe : même carte → mêmes octets → même hash.
    fn vers_octets(&self) -> Vec<u8> {
        let mut resultat = Vec::new();
        match self {
            Carte::Donnee {
                metas,
                tags,
                hash_donnee,
            } => {
                resultat.push(0x00);
                metas_vers_octets(&mut resultat, metas);
                tags_vers_octets(&mut resultat, tags);
                resultat.extend(hash_donnee);
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
    /// tags (via [`octets_vers_tags`]), puis contenu spécifique au variant (32 o
    /// hash, `u64` len + texte, ou `u32` nb hashs + 32o × n). Inverse de
    /// [`Carte::vers_octets`].
    fn octets_vers_carte(octets: &[u8]) -> ResultScribe<Carte> {
        let (mut octets, reste) = prendre_octets(octets, 1)?;

        let (metas, reste) = octets_vers_metas(reste)?;
        let (tags, mut reste) = octets_vers_tags(reste)?;
        match octets[0] {
            0 => {
                let (hash, reste) = prendre_octets(reste, 32)?;
                let hash_donnee: [u8; 32] = hash.try_into().unwrap(); // pas d'erreur possible

                if !reste.is_empty() {
                    return Err(ErreurScribe::Interne(String::from(ERR_ENU_001)));
                }

                Ok(Carte::Donnee {
                    metas,
                    tags,
                    hash_donnee,
                })
            }
            1 => {
                (octets, reste) = prendre_octets(reste, 8)?;
                let longueur = u64::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

                (octets, reste) = prendre_octets(reste, longueur as usize)?;

                let contenu = str::from_utf8(octets)
                    .map_err(|_| ErreurScribe::Interne(String::from(ERR_ENU_002)))?
                    .to_string();

                if !reste.is_empty() {
                    return Err(ErreurScribe::Interne(String::from(ERR_ENU_001)));
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
                    return Err(ErreurScribe::Interne(String::from(ERR_ENU_001)));
                }

                Ok(Carte::Repertoire {
                    metas,
                    tags,
                    hashs_enu,
                })
            }

            _ => Err(ErreurScribe::Interne(String::from(ERR_ENU_001))),
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
fn octets_vers_tags(octets: &[u8]) -> ResultScribe<(BTreeSet<String>, &[u8])> {
    let mut tags = BTreeSet::new();
    let (mut octets, mut reste) = prendre_octets(octets, 4)?;
    let n_tags = u32::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

    for _ in 0..n_tags {
        (octets, reste) = prendre_octets(reste, 4)?;
        let longueur = u32::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

        (octets, reste) = prendre_octets(reste, longueur as usize)?;

        tags.insert(
            str::from_utf8(octets)
                .map_err(|_| ErreurScribe::Interne(String::from(ERR_ENU_002)))?
                .to_string(),
        );
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
fn octets_vers_metas(octets: &[u8]) -> ResultScribe<(BTreeMap<String, String>, &[u8])> {
    let mut metas = BTreeMap::new();
    let (mut octets, mut reste) = prendre_octets(octets, 4)?;
    let n_metas = u32::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

    for _ in 0..n_metas {
        (octets, reste) = prendre_octets(reste, 4)?;
        let longueur = u32::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

        (octets, reste) = prendre_octets(reste, longueur as usize)?;
        let cle = str::from_utf8(octets)
            .map_err(|_| ErreurScribe::Interne(String::from(ERR_ENU_002)))?
            .to_string();

        (octets, reste) = prendre_octets(reste, 4)?;
        let longueur = u32::from_be_bytes(octets.try_into().unwrap()); // pas d'erreur possible

        (octets, reste) = prendre_octets(reste, longueur as usize)?;
        let valeur = str::from_utf8(octets)
            .map_err(|_| ErreurScribe::Interne(String::from(ERR_ENU_002)))?
            .to_string();

        metas.insert(cle, valeur);
    }

    Ok((metas, reste))
}

/// Extrait les `n` premiers octets du buffer.
///
/// Retourne `(extrait, reste)` ou une erreur si le buffer est trop court.
fn prendre_octets(buf: &[u8], n: usize) -> ResultScribe<(&[u8], &[u8])> {
    if buf.len() < n {
        return Err(ErreurScribe::Interne(String::from(ERR_ENU_001)));
    }
    Ok((&buf[0..n], &buf[n..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- prendre_octets ---

    /// Buffer exactement de la bonne taille → extraction complète, reste vide.
    #[test]
    fn prendre_octets_reste_vide() -> ResultScribe<()> {
        let octets: &[u8] = &[1, 2, 3];
        let (octets_pris, reste) = prendre_octets(octets, 3)?;

        assert_eq!(octets, octets_pris);
        assert_eq!(reste, &[]);

        Ok(())
    }

    /// Buffer plus grand que la demande → extraction des n premiers, reste non
    /// vide.
    #[test]
    fn prendre_octets_reste_non_vide() -> ResultScribe<()> {
        let octets: &[u8] = &[1, 2, 3, 4, 5, 6];
        let (octets_pris, reste) = prendre_octets(octets, 2)?;

        assert_eq!(octets_pris, &octets[0..2]);
        assert_eq!(reste, &octets[2..]);

        Ok(())
    }

    /// Buffer trop court → [`ErreurScribe::Interne`].
    #[test]
    fn prendre_octets_trop_court() {
        let octets: &[u8] = &[1, 2, 3];

        assert!(matches!(
            prendre_octets(octets, 5),
            Err(ErreurScribe::Interne(_))
        ));
    }

    /// Demande de 0 octets → extrait vide, reste = buffer entier.
    #[test]
    fn prendre_octets_vide() -> ResultScribe<()> {
        let octets: &[u8] = &[1, 2, 3];
        let (octets_pris, reste) = prendre_octets(octets, 0)?;

        assert_eq!(reste, octets);
        assert_eq!(octets_pris, &[]);

        Ok(())
    }

    // --- Tags ---

    /// Round-trip balise vide : 0 tag → octets → 0 tag, reste vide.
    #[test]
    fn tags_vide_vers_octets() -> ResultScribe<()> {
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
    fn tags_unique_vers_octets() -> ResultScribe<()> {
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
    fn tags_multi_vers_octets() -> ResultScribe<()> {
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
    fn metas_vide_vers_octets() -> ResultScribe<()> {
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
    fn metas_unique_vers_octets() -> ResultScribe<()> {
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
    fn metas_multi_vers_octets() -> ResultScribe<()> {
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
    fn carte_donnee_vers_octets() -> ResultScribe<()> {
        let metas = BTreeMap::from([
            (String::from("clé1"), String::from("valeur1")),
            (String::from("clé2"), String::from("valeur2")),
        ]);
        let tags = BTreeSet::from([String::from("tag1"), String::from("tag2")]);
        let hash_donnee: [u8; 32] = std::array::from_fn(|i| i as u8);

        let carte = Carte::Donnee {
            metas,
            tags,
            hash_donnee,
        };

        let octets = carte.vers_octets();
        let carte_retour = Carte::octets_vers_carte(&octets)?;

        assert_eq!(carte, carte_retour);

        Ok(())
    }

    /// Round-trip CaT : metas + tags + texte → octets → même carte.
    #[test]
    fn carte_texte_vers_octets() -> ResultScribe<()> {
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
    fn carte_repertoire_vers_octets() -> ResultScribe<()> {
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

    // --- ENU ---

    /// Round-trip complet : Enu → octets → Enu, tous champs identiques.
    #[test]
    fn enu_vers_octets_et_retour() -> ResultScribe<()> {
        let braise = String::from("aaaaabbbbbcccccdddddeeeeefffffggggghhhhhiiiiijjjjjkkkkk.braise");

        let hash_carte: [u8; 32] = std::array::from_fn(|i| i as u8);
        let signature_carte = [0u8; 4627];
        let date: u64 = 1234567890;

        let metas = BTreeMap::from([
            (String::from("clé1"), String::from("valeur1")),
            (String::from("clé2"), String::from("valeur2")),
        ]);
        let tags = BTreeSet::from([String::from("tag1"), String::from("tag2")]);
        let hash_donnee: [u8; 32] = std::array::from_fn(|i| i as u8);

        let carte = Carte::Donnee {
            metas,
            tags,
            hash_donnee,
        };

        let enu = Enu {
            braise,
            hash_carte,
            signature_carte,
            date,
            carte,
        };

        let octets = enu.vers_octets();
        let enu_retour = Enu::octets_vers_enu(&octets)?;

        assert_eq!(enu, enu_retour);

        Ok(())
    }
}
