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
//! signataire. Deux signataires possibles : un **foyer** (ENU de contenu,
//! braise du foyer) ou le **nœud** lui-même (racines de l'arborescence,
//! braise sentinelle [`BRAISE_VIDE`] — voir [`Enu::new_racine`]).
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
//!
//! # Exposition publique
//!
//! [`Enu`] et [`Carte`] sont exposés en **lecture seule** à toutes les crates
//! du workspace via [`crate::Enu`] et [`crate::Carte`] (réexportés depuis
//! `lib.rs`).
//!
//! - **`Enu`** — champs privés, accesseurs publics. Seule la crate
//!   `feu-application` peut construire une enveloppe ([`Enu::new`] pour le
//!   contenu signé foyer, [`Enu::new_racine`] pour les racines signées nœud —
//!   tous deux `pub(super)`) ou la persister sur disque ([`Enu::sauvegarder`],
//!   `pub(super)`). Une [`Enu`] lue depuis l'extérieur a obligatoirement
//!   transité par [`Enu::charger`] (`pub(super)`) qui valide le hash et la
//!   signature — son intégrité cryptographique est garantie.
//!   Construire une [`Enu`] directement depuis l'extérieur est impossible
//!   (champs privés, pas de `new` public).
//!
//! - **`Carte`** — enum publique avec champs accessibles en pattern matching.
//!   Ce choix délibéré permet aux couches supérieures (TUI, futures API) de
//!   discriminer proprement les variantes (`match carte { Carte::Donnee { .. }
//!   => ... }`) sans passer par des getters à `Option`. Il rend techniquement
//!   possible la construction d'une [`Carte`] arbitraire depuis l'extérieur,
//!   mais cela ne constitue pas une menace : une carte sans enveloppe signée
//!   ne peut pas être sauvegardée dans `enu/` (seul [`Enu::sauvegarder`] le
//!   fait, et il est `pub(super)`). Les constructeurs ([`Carte::new_donnee`],
//!   [`Carte::new_texte`], [`Carte::new_repertoire`]) et les mutateurs
//!   ([`Carte::ajout_meta`], [`Carte::ajout_tag`],
//!   [`Carte::ajout_hash_donnee`]) restent `pub(super)`.
//!
//!   Les accesseurs [`Carte::metas`] et [`Carte::tags`] sont maintenus parce
//!   qu'ils évitent de répéter le match sur les trois variantes pour des
//!   champs communs. Les getters spécifiques (`hash_donnee()`, `contenu()`,
//!   `hashs_enu()`) ont été supprimés — le pattern matching les rend
//!   redondants.

use data_encoding::HEXLOWER;
use std::fs::rename;
use std::os::unix::fs::symlink;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{OpenOptions, read, remove_file},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use feu_noyau::{BRAISE_VIDE, Braise, FeuNoyau};

use crate::{
    SessionApplication,
    scribe::erreur::{ErreurScribe, ResultScribe},
};

/// Plafond du contenu d'une [`Carte::Texte`], en octets UTF-8.
///
/// Bornée volontairement bien en deçà du plafond de signature du noyau
/// (`MAX_TAILLE_SIGNATURE`, 64 kio) : la marge restante absorbe l'en-tête de la
/// carte sérialisée (discriminant, métadonnées, tags, préfixe de longueur) sans
/// avoir à le calculer finement. 60 kio reste très large pour du texte brut.
const MAX_TAILLE_TEXTE: usize = 1024 * 60;

/// Le buffer est trop court, porte un discriminant de carte inconnu, ou laisse
/// des octets résiduels après désérialisation.
const ERR_ENU_001: &str = "ENU-001 > Problème désérialisation";
/// Les octets censés être du texte ne sont pas du UTF-8 valide.
const ERR_ENU_002: &str = "ENU-002 > UTF-8 invalide";
/// L'ENU lue sur disque n'a pas pu être authentifiée : signataire inconnu de la
/// session, signature invalide, ou hash de carte ne correspondant pas.
const ERR_ENU_003: &str = "ENU-003 > Problème ouverture ENU";
/// La carte ciblée n'est pas une [`Carte::Repertoire`] : impossible d'y
/// ajouter le hash d'une ENU enfant.
const ERR_ENU_004: &str = "ENU-004 > Ce n'est pas une EnuR";

/// Les 62 octets censés porter l'adresse `.braise` ne forment pas une braise
/// bien formée, ou la braise annoncée n'identifie aucun foyer de la session.
const ERR_ENU_005: &str = "ENU-005 > Braise incorrecte";

/// Le contenu textuel dépasse [`MAX_TAILLE_TEXTE`] : la [`Carte::Texte`] est
/// refusée avant même d'être mise sous enveloppe et signée.
const ERR_ENU_006: &str = "ENU-006 > Texte pour EnuT trop long";

const ERR_ENU_007: &str = "ENU-007 > Problème Enu racine ou remplacement";

/// Enveloppe Numérique Universelle.
///
/// Le `hash_carte` (SHA3-256 de la carte sérialisée) est le nom du fichier
/// dans `~/.feu/enu/`. La `signature_carte` (ML-DSA-87) couvre la carte
/// sérialisée directement. La `date` est le timestamp Unix de mise sous
/// enveloppe. La `braise` identifie le signataire pour la vérification :
/// l'adresse d'un foyer, ou [`BRAISE_VIDE`] quand le signataire est le nœud
/// (racines de l'arborescence).
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Enu {
    /// Adresse `.braise` du signataire — un foyer, ou [`BRAISE_VIDE`] pour une
    /// racine signée par le nœud (non couverte par le hash ni la signature —
    /// métadonnée de routage).
    braise: Braise,

    /// SHA3-256 de la carte sérialisée.
    hash_carte: [u8; 32],
    /// Signature ML-DSA-87 de la carte sérialisée (taille fixe, 4627 o).
    signature_carte: [u8; 4627],
    /// Timestamp Unix de mise sous enveloppe (non couvert par la signature).
    date: u64,

    carte: Carte,
}

impl Enu {
    /// Crée une ENU signée pour le foyer désigné par `braise`.
    ///
    /// Hash la carte (`creation_empreinte`), la signe avec la clé du foyer,
    /// horodate, et conserve la braise comme métadonnée de routage. Le foyer
    /// doit être ouvert — sa clé privée doit être présente en mémoire.
    ///
    /// La braise est résolue en position via [`SessionApplication::braise_vers_index`] :
    /// c'est la frontière où la couche application traduit son adresse `.braise`
    /// en `index_foyer`, seule monnaie comprise par le noyau (qui signe via
    /// `signature_foyer`). La taille de la carte sérialisée est limitée à
    /// [`MAX_TAILLE_SIGNATURE`] (64 kio) par le noyau.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] (`ENU-005`) si la braise n'identifie
    /// aucun foyer de la session. Propage toute erreur de signature du noyau —
    /// notamment si le foyer est fermé ou si la carte dépasse
    /// [`MAX_TAILLE_SIGNATURE`].
    pub(super) fn new(
        carte: Carte,
        feu_noyau: &FeuNoyau,
        session: &SessionApplication,
        braise: Braise,
    ) -> ResultScribe<Self> {
        let Some(index_foyer) = session.braise_vers_index(braise) else {
            return Err(ErreurScribe::Interne(String::from(ERR_ENU_005)));
        };

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

    /// Forge une racine du nœud, la sauvegarde et repointe le sommet courant.
    ///
    /// Une racine est signée par le **nœud** ([`FeuNoyau::signature_noeud`]),
    /// non par un foyer — le sommet de l'arbre appartient au nœud. Sa braise
    /// vaut [`BRAISE_VIDE`], sentinelle qui marque un signataire nœud (aucun
    /// foyer réel ne la porte) et oriente [`Enu::charger`] vers la clé publique
    /// de signature du nœud.
    ///
    /// Le paramètre `carte` distingue les deux usages :
    ///
    /// - `None` — **genèse** : un [`Carte::Repertoire`] vide portant `_racine`
    ///   = `""` (racine sans parent, arborescence initiale vide). Le marqueur
    ///   distingue aussi cette carte d'un répertoire de contenu vide, qui
    ///   aurait sinon le même hash content-addressed.
    /// - `Some(carte)` — le nouveau sommet reconstruit, fourni par l'appelant
    ///   (typiquement [`Enu::remplacer`]). La carte **doit** porter la méta
    ///   `_racine` (valeur = hash de la racine précédente), sans quoi
    ///   [`Enu::charger`] ne la reconnaîtra pas comme racine et la rejettera.
    ///
    /// Après signature, l'ENU est sauvegardée, puis le symlink
    /// `_DERNIERE_RACINE` est repointé sur elle de façon atomique (lien
    /// temporaire puis `rename`). L'ENU forgée est retournée.
    ///
    /// Le nœud doit être allumé (sa clé de signature disponible) ; aucun foyer
    /// n'a besoin d'être ouvert pour signer une racine.
    ///
    /// # Erreurs
    ///
    /// Propage toute erreur de signature du nœud, de sauvegarde de l'ENU, ou de
    /// pose du symlink.
    pub(super) fn new_racine(
        feu_noyau: &FeuNoyau,
        chemin_enu: &Path,
        carte: Option<Carte>,
    ) -> ResultScribe<Enu> {
        let carte = {
            if let Some(carte) = carte {
                carte
            } else {
                let mut carte = Carte::new_repertoire(BTreeSet::new());
                carte.ajout_meta("_racine", "");
                carte
            }
        };

        let octets_carte = carte.vers_octets();

        let enu_racine = Self {
            braise: BRAISE_VIDE,
            hash_carte: FeuNoyau::creation_empreinte(&octets_carte),
            signature_carte: feu_noyau.signature_noeud(&octets_carte)?,
            date: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Horloge système antérieure à 1970")
                .as_secs(),
            carte,
        };

        let chemin = enu_racine.sauvegarder(chemin_enu)?;

        // repointage atomique : le lien temporaire est renommé par-dessus
        // l'ancien (rename POSIX) — `_DERNIERE_RACINE` n'est jamais absent ni
        // à moitié posé, même si le processus est coupé entre les deux appels.
        // La cible est relative (nom de fichier seul) : le lien survit à un
        // déplacement de `~/.feu`.
        let tmp = chemin_enu.join("_DERNIERE_RACINE.tmp");
        let lien = chemin_enu.join("_DERNIERE_RACINE");

        symlink(chemin.file_name().unwrap(), &tmp)?;
        rename(tmp, lien)?;

        Ok(enu_racine)
    }

    /// Retourne l'adresse `.braise` du signataire — un foyer, ou
    /// [`BRAISE_VIDE`] pour une racine signée par le nœud.
    ///
    /// Métadonnée de routage, hors hash et hors signature : sa valeur n'est pas
    /// authentifiée (voir le modèle de confiance du module).
    pub fn braise(&self) -> Braise {
        self.braise
    }

    /// Retourne le hash SHA3-256 de la carte — identifiant content-addressed
    /// de l'ENU, également utilisé comme nom de fichier dans `~/.feu/enu/`.
    pub fn hash_carte(&self) -> [u8; 32] {
        self.hash_carte
    }

    /// Retourne la signature ML-DSA-87 de la carte (4627 octets).
    pub fn signature_carte(&self) -> [u8; 4627] {
        self.signature_carte
    }

    /// Retourne le timestamp Unix de mise sous enveloppe.
    ///
    /// Non couvert par la signature ni le hash — métadonnée indicative.
    pub fn date(&self) -> u64 {
        self.date
    }

    /// Retourne une référence à la [`Carte`] transportée par l'enveloppe.
    pub fn carte(&self) -> &Carte {
        &self.carte
    }

    /// Écrit l'ENU sur disque sous `~/.feu/enu/<hash_carte_hex>.enu`.
    ///
    /// Le nom du fichier est l'empreinte hexadécimale de la carte
    /// (content-addressing) : une carte donnée vise toujours le même fichier,
    /// indépendamment de l'enveloppe qui la transporte. Le fichier est créé en
    /// mode `0o600` (lecture/écriture réservées au propriétaire).
    ///
    /// **Idempotent.** Si le fichier existe déjà, l'écriture est shuntée et la
    /// méthode renvoie son chemin sans rien réécrire : le nom étant le hash de
    /// la carte, un fichier de même nom encode forcément la même carte — il n'y
    /// a rien à réécrire. Une `date` ou une `signature` différentes dans la
    /// nouvelle enveloppe sont sans incidence : ces champs ne participent ni au
    /// hash ni au nom. Un contenu identique n'est donc stocké qu'une fois et
    /// peut être référencé par autant d'ENU que nécessaire (déduplication à
    /// l'échelle du nœud).
    ///
    /// # Retour
    ///
    /// Le chemin du fichier `.enu` — existant ou nouvellement créé. Utile pour
    /// l'appelant qui a besoin de le désigner ensuite, par exemple pour y faire
    /// pointer le symlink de la dernière racine.
    ///
    /// # Erreurs
    ///
    /// Propage une [`ErreurScribe::IoError`] si le dossier `~/.feu/enu/` est
    /// absent ou sur tout autre échec d'écriture.
    pub(super) fn sauvegarder(&self, chemin_enu: &Path) -> ResultScribe<PathBuf> {
        let nom_fichier = format!("{}.enu", HEXLOWER.encode(&self.hash_carte));
        let chemin = chemin_enu.join(nom_fichier);

        if !chemin.exists() {
            let mut fichier = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&chemin)?;

            fichier.write_all(&self.vers_octets())?;
        }

        Ok(chemin)
    }

    /// Supprime le fichier `.enu` de cette ENU du disque.
    ///
    /// Sans appelant de production depuis que [`Enu::remplacer`] conserve les
    /// anciens sommets (historique des versions) : seul un test l'exerce
    /// aujourd'hui, d'où le `#[allow(dead_code)]`. Elle servira au futur
    /// chantier de ménage (reset), qui élague les versions abandonnées.
    ///
    /// # Erreurs
    ///
    /// Propage une [`ErreurScribe::IoError`] si le fichier est absent ou si la
    /// suppression échoue.
    #[allow(dead_code)]
    pub(super) fn supprimer(&self, chemin_enu: &Path) -> ResultScribe<()> {
        let nom_fichier = format!("{}.enu", HEXLOWER.encode(&self.hash_carte));
        let chemin = chemin_enu.join(nom_fichier);

        remove_file(&chemin)?;

        Ok(())
    }

    /// Charge **et authentifie** une ENU depuis le disque.
    ///
    /// Là où [`Enu::octets_vers_enu`] ne valide que la structure, cette méthode
    /// reconstruit l'enveloppe puis franchit la frontière de confiance. Le
    /// signataire est déterminé par la `braise` — le champ de routage qui
    /// annonce qui a signé — et la clé de vérification en découle :
    ///
    /// - **Racine du nœud** — braise [`BRAISE_VIDE`] : le nœud est le
    ///   signataire, la signature est validée contre [`cle_publique_sig_noeud`].
    ///   Sa carte porte par ailleurs la méta `_racine` (marqueur de racine dans
    ///   l'arbre des versions).
    /// - **Contenu** — braise d'un foyer connu de la session : la clé publique
    ///   de ce foyer valide la signature.
    ///
    /// Dans les deux cas, une condition commune s'ajoute : le hash recalculé de
    /// la carte doit égaler le `hash_carte` stocké — sans quoi le nom
    /// content-addressed de l'ENU mentirait sur son contenu (le `hash_carte`
    /// est hors signature).
    ///
    /// La `braise` restant hors signature, la falsifier ne peut que router vers
    /// la mauvaise clé et faire **échouer** la vérification — jamais faire
    /// accepter une ENU. C'est le modèle de confiance du module : la braise est
    /// un indice de routage, la signature est le contrôle. Une enveloppe au
    /// signataire inconnu, falsifiée ou corrompue ne passe jamais la barrière.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] (`ENU-003`) si l'ENU n'est pas
    /// authentifiable, et propage toute erreur d'E/S
    /// ([`ErreurScribe::IoError`]), de désérialisation ou cryptographique
    /// ([`ErreurScribe::FeuNoyau`]) rencontrée en chemin.
    pub(super) fn charger(chemin: &Path, session: &SessionApplication) -> ResultScribe<Enu> {
        let enu = Self::octets_vers_enu(&read(chemin)?)?;
        let octets_carte = enu.carte.vers_octets();

        // racine du nœud : braise sentinelle → vérification contre la clé du nœud
        if enu.braise == BRAISE_VIDE
            && enu.carte().metas().contains_key("_racine")
            && FeuNoyau::verification_signature(
                session.cle_publique_sig_noeud(),
                enu.signature_carte,
                &octets_carte,
            )?
            && FeuNoyau::creation_empreinte(&octets_carte) == enu.hash_carte
        {
            return Ok(enu);
        }

        // ENU de contenu : la braise doit résoudre vers un foyer connu de la session
        if let Some(index_foyer) = session.braise_vers_index(enu.braise)
            && FeuNoyau::verification_signature(
                session.cle_publique_sig_foyer(index_foyer)?,
                enu.signature_carte,
                &octets_carte,
            )?
            && FeuNoyau::creation_empreinte(&octets_carte) == enu.hash_carte
        {
            return Ok(enu);
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

        resultat.extend(self.braise.to_string().as_bytes());
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
    /// (`ENU-001`), si le discriminant de carte est inconnu (`ENU-001`), si un
    /// champ texte n'est pas du UTF-8 valide (`ENU-002`), ou si les 62 octets de
    /// braise ne forment pas une adresse `.braise` bien formée (`ENU-005`).
    fn octets_vers_enu(octets: &[u8]) -> ResultScribe<Enu> {
        let (mut octets, mut reste) = prendre_octets(octets, 62)?;
        let braise = Braise::try_from(
            str::from_utf8(octets).map_err(|_| ErreurScribe::Interne(String::from(ERR_ENU_002)))?,
        )
        .map_err(|_| ErreurScribe::Interne(String::from(ERR_ENU_005)))?;

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

    /// Remplace une ENU dans l'arbre du nœud et produit la version suivante.
    ///
    /// Point d'entrée de la substitution. `racine` est le sommet courant de
    /// l'arborescence (celui pointé par `_DERNIERE_RACINE`). La fonction
    /// délègue à [`Self::remplacer_recursif`] la descente dans l'arbre et la
    /// reconstruction du chemin, puis forge le nouveau sommet via
    /// [`Enu::new_racine`] : sa carte est celle remontée par la récursion,
    /// avec la méta `_racine` mise au **hash de l'ancien sommet** — c'est le
    /// maillon de la lignée des versions, capturé avant la descente. La
    /// signature (nœud), la sauvegarde et le repointage du symlink
    /// `_DERNIERE_RACINE` sont portés par `new_racine`.
    ///
    /// Poser la lignée **ici, une seule fois**, et non dans la récursion, est
    /// délibéré : [`Self::remplacer_recursif`] reconstruit *chaque* répertoire
    /// du chemin et ne sait pas lequel est le sommet — seul le point d'entrée
    /// le sait. L'écrasement de l'ancienne valeur de `_racine` (héritée de la
    /// carte clonée) fait avancer la chaîne d'un cran.
    ///
    /// L'ancien sommet n'est **pas** supprimé : c'est la version précédente de
    /// l'arborescence, conservée pour l'historique (chaîne des `_racine`).
    ///
    /// # Retour
    ///
    /// La nouvelle ENU racine du nœud — nouveau sommet de l'arborescence,
    /// pointé par `_DERNIERE_RACINE`.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] (`ENU-007`) si `remplacement` est
    /// identique à `racine`. Propage les erreurs de
    /// [`Self::remplacer_recursif`] (E/S, authentification, signature —
    /// notamment si un foyer du chemin reconstruit est fermé) et de
    /// [`Enu::new_racine`] (signature du nœud, sauvegarde, symlink).
    pub(super) fn remplacer(
        chemin_enu: &Path,
        racine: &Enu,
        hash_a_remplacer: &[u8; 32],
        remplacement: &Enu,
        noyau: &FeuNoyau,
        session: &SessionApplication,
    ) -> ResultScribe<Enu> {
        if racine == remplacement {
            return Err(ErreurScribe::Interne(ERR_ENU_007.to_string()));
        }

        // capturé avant la descente : `racine` est ensuite masquée par le
        // sommet reconstruit, dont le hash n'est pas celui du parent
        let hash_ancienne_racine = racine.hash_carte();

        let racine = Self::remplacer_recursif(
            chemin_enu,
            racine,
            hash_a_remplacer,
            remplacement,
            noyau,
            session,
        )?;

        let mut nouvelle_carte = racine.carte().clone();
        nouvelle_carte.ajout_meta("_racine", &HEXLOWER.encode(&hash_ancienne_racine));

        let nouvelle_racine = Enu::new_racine(noyau, chemin_enu, Some(nouvelle_carte))?;

        Ok(nouvelle_racine)
    }

    /// Cœur récursif de [`Self::remplacer`] : substitue la cible et reconstruit
    /// le chemin jusqu'au sommet du sous-arbre, **sans** poser la lignée
    /// `_racine` (réservée au point d'entrée).
    ///
    /// Mise à jour **immuable** et content-addressed : `racine` n'est jamais
    /// modifiée en place. La fonction descend récursivement dans les
    /// [`Carte::Repertoire`] à la recherche de l'ENU dont le `hash_carte` vaut
    /// `hash_a_remplacer`. Lorsqu'elle la trouve, elle y substitue
    /// `remplacement`, puis reconstruit chaque répertoire situé sur le chemin
    /// entre la racine et le nœud remplacé (métadonnées et tags conservés),
    /// avec un traitement selon le signataire :
    ///
    /// - **Répertoire de contenu** (braise d'un foyer) — re-signé sous sa
    ///   propre braise ([`Enu::braise`]) et sauvegardé dans `~/.feu/enu/`.
    ///   Chaque répertoire reste ainsi signé par le foyer qui le possède —
    ///   c'est ce qui autorise un arbre mêlant plusieurs foyers.
    /// - **Sommet du nœud** (braise [`BRAISE_VIDE`]) — **ni re-signé, ni
    ///   sauvegardé** ici : la signature est du ressort du nœud, pas d'un
    ///   foyer, et c'est [`Self::remplacer`] qui la pose via
    ///   [`Enu::new_racine`]. La récursion renvoie alors une ENU
    ///   **temporaire** : clone du sommet dont seule la carte est à jour —
    ///   son `hash_carte` et sa signature, périmés, ne doivent pas être lus.
    ///
    /// Comme le `hash_carte` d'un répertoire dépend du hash de ses enfants,
    /// modifier une feuille fait remonter de nouveaux hashs jusqu'au sommet.
    ///
    /// Corollaire du modèle mixte : **tout foyer présent sur le chemin
    /// reconstruit doit être ouvert**, sans quoi la re-signature de son
    /// répertoire échoue.
    ///
    /// # Retour
    ///
    /// La racine du sous-arbre après substitution — éventuellement l'ENU
    /// temporaire décrite ci-dessus si cette racine est le sommet du nœud ;
    /// un clone inchangé de `racine` si la cible est absente du sous-arbre.
    ///
    /// # Erreurs
    ///
    /// Propage les erreurs de [`Enu::charger`] (E/S, authentification) sur
    /// chaque enfant visité, et les erreurs de signature de [`Enu::new`] —
    /// notamment lorsqu'un foyer du chemin est fermé.
    fn remplacer_recursif(
        chemin_enu: &Path,
        racine: &Enu,
        hash_a_remplacer: &[u8; 32],
        remplacement: &Enu,
        noyau: &FeuNoyau,
        session: &SessionApplication,
    ) -> ResultScribe<Enu> {
        // cible atteinte : on substitue, la remontée s'arrête ici
        if racine.hash_carte() == *hash_a_remplacer {
            return Ok(remplacement.clone());
        }

        // sinon : descente récursive dans chaque sous-répertoire
        if let Carte::Repertoire {
            metas,
            tags,
            ref mut hashs_enu,
        } = racine.carte.clone()
        {
            let mut modifie = false;
            for h in &hashs_enu.clone() {
                let nom_fichier = format!("{}.enu", HEXLOWER.encode(h));
                let chemin = chemin_enu.join(nom_fichier);

                let enu_enfant = Self::charger(&chemin, session)?;

                let enu_enfant_modifie = Self::remplacer_recursif(
                    chemin_enu,
                    &enu_enfant,
                    hash_a_remplacer,
                    remplacement,
                    noyau,
                    session,
                )?;

                // un enfant a changé → on échange son hash dans ce dossier
                if enu_enfant_modifie.hash_carte() != enu_enfant.hash_carte() {
                    hashs_enu.remove(&enu_enfant.hash_carte());
                    hashs_enu.insert(enu_enfant_modifie.hash_carte());
                    modifie = true;
                }
            }
            if modifie {
                // dossier reconstruit : mêmes métas et tags, hashs enfants à jour
                let mut carte = Carte::new_repertoire(hashs_enu.clone());
                for (cle, valeur) in &metas {
                    carte.ajout_meta(cle, valeur);
                }
                for t in &tags {
                    carte.ajout_tag(t);
                }

                // sommet du nœud : la signature appartient au nœud, pas à un
                // foyer — c'est `remplacer` qui la posera via `new_racine`.
                // ENU temporaire : seule sa carte est à jour, hash et signature
                // périmés → ne jamais la sauvegarder ni la faire sortir de
                // `remplacer`.
                if racine.braise() == BRAISE_VIDE {
                    let mut enu_temp = racine.clone();
                    enu_temp.carte = carte;
                    return Ok(enu_temp);
                }

                // répertoire de contenu : re-signé sous SA braise (arbre
                // multi-foyers), sauvegardé — le chemin reconstruit doit
                // exister sur disque avant que le nouveau sommet le référence
                let nouvelle_enu = Enu::new(carte, noyau, session, racine.braise())?;
                nouvelle_enu.sauvegarder(chemin_enu)?;

                return Ok(nouvelle_enu);
            }
        }
        // cible absente de ce sous-arbre : racine renvoyée inchangée
        Ok(racine.clone())
    }
}

/// Carte : contenu métier d'une ENU.
///
/// Trois variantes — Donnée (CaD), Texte (CaT), Répertoire (CaR).
/// Chaque variante porte des métadonnées structurées (`BTreeMap<String, String>`)
/// et des tags libres (`BTreeSet<String>`). L'ordre déterministe des deux
/// collections est nécessaire au calcul du hash.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Carte {
    /// CaD — référence un blob stocké dans un classeur.
    Donnee {
        /// Métadonnées structurées clé → valeur (ordre déterministe pour le hash).
        metas: BTreeMap<String, String>,
        /// Tags libres (ordre déterministe pour le hash).
        tags: BTreeSet<String>,
        /// Hash SHA3-256 du blob (également le nom du fichier `.dat`).
        hash_donnee: [u8; 32],
    },

    /// CaT — texte brut embarqué directement dans la carte. Sa taille est
    /// bornée à la construction (voir le constructeur `new_texte`).
    Texte {
        /// Métadonnées structurées clé → valeur (ordre déterministe pour le hash).
        metas: BTreeMap<String, String>,
        /// Tags libres (ordre déterministe pour le hash).
        tags: BTreeSet<String>,
        /// Texte brut transporté par la carte.
        contenu: String,
    },

    /// CaR — répertoire, référence ses enfants par leur `hash_carte`.
    Repertoire {
        /// Métadonnées structurées clé → valeur (ordre déterministe pour le hash).
        metas: BTreeMap<String, String>,
        /// Tags libres (ordre déterministe pour le hash).
        tags: BTreeSet<String>,
        /// Hash des ENU enfants. L'ordre [`BTreeSet`] assure la reproductibilité
        /// du hash de cette carte.
        hashs_enu: BTreeSet<[u8; 32]>,
    },
}

impl Carte {
    /// Construit une [`Carte::Donnee`] — référence un blob dans un
    /// classeur.
    pub(super) fn new_donnee(hash_donnee: [u8; 32]) -> Self {
        Self::Donnee {
            metas: BTreeMap::new(),
            tags: BTreeSet::new(),
            hash_donnee,
        }
    }

    /// Retourne les métadonnées structurées, communes aux trois variantes.
    ///
    /// Un [`BTreeMap`] clé → valeur. L'ordre itératif est déterministe
    /// (lexicographique sur les clés), condition nécessaire au calcul de hash.
    pub fn metas(&self) -> &BTreeMap<String, String> {
        match self {
            Self::Donnee {
                metas,
                tags: _,
                hash_donnee: _,
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

    /// Retourne les tags libres, communs aux trois variantes.
    ///
    /// Un [`BTreeSet`] de chaînes. L'ordre itératif est déterministe
    /// (lexicographique), condition nécessaire au calcul de hash.
    pub fn tags(&self) -> &BTreeSet<String> {
        match self {
            Self::Donnee {
                metas: _,
                tags,
                hash_donnee: _,
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

    /// Construit une [`Carte::Texte`] — le texte est embarqué directement dans
    /// la carte, sans blob ni classeur.
    ///
    /// Le contenu est borné à [`MAX_TAILLE_TEXTE`] (mesuré en octets UTF-8) : la
    /// vérification a lieu ici, avant toute mise sous enveloppe, pour échouer
    /// proprement plutôt que de buter sur le plafond de signature du noyau.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] (`ENU-006`) si `contenu` dépasse
    /// [`MAX_TAILLE_TEXTE`].
    pub(super) fn new_texte(contenu: &str) -> ResultScribe<Self> {
        if contenu.len() > MAX_TAILLE_TEXTE {
            return Err(ErreurScribe::Interne(String::from(ERR_ENU_006)));
        }

        Ok(Self::Texte {
            metas: BTreeMap::new(),
            tags: BTreeSet::new(),
            contenu: contenu.to_string(),
        })
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
                hash_donnee: _,
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
                hash_donnee: _,
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
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] (`ENU-004`) si la carte n'est pas un
    /// répertoire : une [`Carte::Donnee`] ou une [`Carte::Texte`] n'a pas
    /// d'enfants.
    pub(super) fn ajout_hash_donnee(&mut self, hash: &[u8; 32]) -> ResultScribe<()> {
        if let Carte::Repertoire {
            metas: _,
            tags: _,
            hashs_enu,
        } = self
        {
            hashs_enu.insert(*hash);
            Ok(())
        } else {
            Err(ErreurScribe::Interne(String::from(ERR_ENU_004)))
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
        let braise =
            Braise::try_from("aaaaabbbbbcccccdddddeeeeefffffggggghhhhhiiiiijjjjjkkkkk.braise")
                .unwrap();

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

    /// Cycle complet sur `Carte::Donnee` : hash conservé à la construction,
    /// refus de `ajout_hash_donnee` (`ERR_ENU_004`), tags et metas insérés
    /// puis relus via les accesseurs communs.
    #[test]
    fn carte_donnee() -> ResultScribe<()> {
        let hash_donnee = [0u8; 32];
        let mut carte = Carte::new_donnee(hash_donnee);

        assert!(matches!(
            carte.ajout_hash_donnee(&hash_donnee),
            Err(ErreurScribe::Interne(_))
        ));

        if let Carte::Donnee {
            metas: _,
            tags: _,
            hash_donnee: h,
        } = &carte
        {
            assert_eq!(h, &hash_donnee);
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

    /// Cycle complet sur `Carte::Texte` : contenu conservé à la construction,
    /// refus de `ajout_hash_donnee` (`ERR_ENU_004`), tags et metas insérés
    /// puis relus via les accesseurs communs.
    #[test]
    fn carte_texte() -> ResultScribe<()> {
        let hash_donnee = [0u8; 32];
        let mut carte = Carte::new_texte("Contenu court de test")?;

        assert!(matches!(
            carte.ajout_hash_donnee(&hash_donnee),
            Err(ErreurScribe::Interne(_))
        ));

        if let Carte::Texte {
            metas: _,
            tags: _,
            contenu: c,
        } = &carte
        {
            assert_eq!(c, "Contenu court de test");
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

    /// Contenu dépassant `MAX_TAILLE_TEXTE` d'un octet → refus (`ERR_ENU_006`).
    #[test]
    fn carte_texte_trop_grande() -> ResultScribe<()> {
        let contenu = "a".repeat(MAX_TAILLE_TEXTE + 1);

        assert!(matches!(
            Carte::new_texte(&contenu),
            Err(ErreurScribe::Interne(_))
        ));

        Ok(())
    }

    /// Cycle complet sur `Carte::Repertoire` : hashs enfants insérés via
    /// `ajout_hash_donnee`, tags et metas insérés puis relus via les
    /// accesseurs communs.
    #[test]
    fn carte_repertoire() -> ResultScribe<()> {
        let hash_donnee1 = [0u8; 32];
        let hash_donnee2 = [1u8; 32];
        let mut carte = Carte::new_repertoire(BTreeSet::new());

        if let Carte::Repertoire {
            metas: _,
            tags: _,
            hashs_enu: h,
        } = &carte
        {
            assert!(h.is_empty());
        }

        carte.ajout_hash_donnee(&hash_donnee1)?;
        carte.ajout_hash_donnee(&hash_donnee2)?;

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
}
