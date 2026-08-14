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
//! [`BRAISE_VIDE`] — voir [`Enu::new_racine`]).
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
//!   [`Carte::ajout_hash_enu`]) restent `pub(super)`.
//!
//!   Les accesseurs [`Carte::metas`] et [`Carte::tags`], communs aux trois
//!   variantes, sont maintenus : ils évitent de répéter le match pour des
//!   champs présents partout. L'accesseur `hashs_enu()` ne concerne que la
//!   variante [`Carte::Repertoire`] et rend donc une [`Option`] : `None` sur une
//!   `Donnee` ou une `Texte`, ce qui distingue la feuille du répertoire
//!   réellement vide. Les getters `hash_donnee()` et `contenu()`, eux, ont été
//!   supprimés — le pattern matching les rend redondants.

use data_encoding::HEXLOWER;
use std::fs::rename;
use std::os::unix::fs::symlink;
use std::str::from_utf8;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{OpenOptions, read, remove_file},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use feu_noyau::{BRAISE_VIDE, Braise, FeuNoyau};

use crate::{ErreurFeuApplication, ResultFeuApplication, SessionApplication};

/// Plafond du contenu d'une [`Carte::Texte`], en octets UTF-8.
///
/// Bornée volontairement bien en deçà du plafond de signature du noyau
/// (`MAX_TAILLE_SIGNATURE`, 64 kio) : la marge restante absorbe l'en-tête de la
/// carte sérialisée (discriminant, métadonnées, tags, préfixe de longueur) sans
/// avoir à le calculer finement. 60 kio reste très large pour du texte brut.
///
/// **Borne incluse** : 61440 octets passent, la garde est un `>` strict. Une
/// taille est une quantité, pas un cardinal d'index — le `>=` de `MAX_FOYERS` et
/// `MAX_CLASSEURS`, où l'index valide s'arrête à MAX-1, ne s'applique pas ici.
pub(crate) const MAX_TAILLE_TEXTE: usize = 1024 * 60;

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
    /// [`MAX_TAILLE_SIGNATURE`](feu_noyau::MAX_TAILLE_SIGNATURE) (64 kio) par le noyau.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::ScribeBraiseInconnue`] si la braise
    /// n'identifie aucun foyer de la session. Propage toute erreur de signature
    /// du noyau — notamment si le foyer est fermé ou si la carte dépasse
    /// [`MAX_TAILLE_SIGNATURE`](feu_noyau::MAX_TAILLE_SIGNATURE).
    pub(super) fn new(
        carte: Carte,
        feu_noyau: &FeuNoyau,
        session: &SessionApplication,
        braise: Braise,
    ) -> ResultFeuApplication<Self> {
        let Some(index_foyer) = session.braise_vers_index(braise) else {
            return Err(ErreurFeuApplication::ScribeBraiseInconnue);
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
    /// vaut [`BRAISE_VIDE`], qu'aucun foyer réel ne porte : c'est ce qui oriente
    /// [`Enu::charger`] vers la clé publique de signature du nœud.
    ///
    /// Le paramètre `carte` distingue les deux usages :
    ///
    /// - `None` — **genèse** : un [`Carte::Repertoire`] vide portant `_racine`
    ///   = `""`, la marque « pas de racine précédente » qui termine la chaîne.
    ///   Le symlink n'existe pas encore à cet instant : il n'y a rien à lire, et
    ///   c'est cet appel qui le pose. Le marqueur distingue aussi cette carte
    ///   d'un répertoire de contenu vide, qui aurait sinon le même hash
    ///   content-addressed.
    /// - `Some(carte)` — le nouveau sommet reconstruit, fourni par l'appelant
    ///   (typiquement [`Enu::remplacer`] ou une greffe directe sous la racine).
    ///   La méta `_racine` est **posée ici**, avec le hash de la racine courante
    ///   lue via `chemin_derniere_racine` — une valeur que l'appelant aurait
    ///   placée est écrasée. Le chaînage des versions est ainsi tenu au seul
    ///   endroit qui repointe le symlink, plutôt que confié à chaque appelant :
    ///   une carte sans `_racine` produisait une racine que [`Enu::charger`]
    ///   rejette, faute décelable seulement à la relecture suivante.
    ///
    /// `session` ne sert qu'à cette relecture (authentification de la racine
    /// courante) : aucun foyer n'est sollicité.
    ///
    /// Après signature, l'ENU est sauvegardée, puis le symlink pointé par
    /// `chemin_derniere_racine` (`.DERNIERE_RACINE`, fourni par le
    /// [`Scribe`](crate::scribe::Scribe)) est repointé sur elle de façon atomique
    /// (lien temporaire puis `rename`). L'ENU forgée n'est **pas** retournée :
    /// elle vit désormais sur disque et c'est le symlink qui la désigne — un
    /// appelant qui en a besoin la relit via [`Enu::charger_derniere_racine`].
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
        session: &SessionApplication,
        chemin_enu: &Path,
        chemin_derniere_racine: &Path,
        carte: Option<Carte>,
    ) -> ResultFeuApplication<()> {
        let carte = {
            if let Some(mut carte) = carte {
                let derniere_racine_noeud =
                    Enu::charger_derniere_racine(chemin_derniere_racine, session)?;

                carte.ajout_meta(
                    "_racine",
                    &HEXLOWER.encode(&derniere_racine_noeud.hash_carte()),
                );

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
        // l'ancien (rename POSIX) — `.DERNIERE_RACINE` n'est jamais absent ni
        // à moitié posé, même si le processus est coupé entre les deux appels.
        // La cible est relative (nom de fichier seul) : le lien survit à un
        // déplacement de `~/.feu`.
        //
        // Le temporaire est dérivé de la cible, pas recalculé : garantit qu'il
        // en est le voisin exact (même dossier, même nom + `.tmp`), condition du
        // `rename` atomique. `with_extension` *ajoute* `.tmp` au lieu de le
        // substituer, car le point de tête de `.DERNIERE_RACINE` n'est pas vu
        // comme une extension par `Path`.
        let tmp = chemin_derniere_racine.with_extension("tmp");

        symlink(chemin.file_name().unwrap(), &tmp)?;
        rename(tmp, chemin_derniere_racine)?;

        Ok(())
    }

    /// Chemin du fichier `.enu` de cette enveloppe sous `chemin_enu`.
    ///
    /// Raccourci sur [`Self::hash_carte_vers_chemin`] à partir du hash de la
    /// carte : le nom du fichier *étant* ce hash (content-addressing), une ENU
    /// désigne toujours le même fichier, quelle que soit l'enveloppe qui la
    /// transporte.
    pub(super) fn chemin(&self, chemin_enu: &Path) -> PathBuf {
        Self::hash_carte_vers_chemin(&self.hash_carte(), chemin_enu)
    }

    /// Construit le chemin `<hash_carte_hex>.enu` sous `chemin_enu`.
    ///
    /// Seul endroit où s'écrit la règle de nommage content-addressed (empreinte
    /// hexadécimale + extension `.enu`). [`Self::sauvegarder`],
    /// [`Self::supprimer`] et [`Self::charger`] passent tous par ici : aucune
    /// divergence de nommage ne peut ainsi s'installer entre l'écriture d'une
    /// ENU et sa relecture.
    pub(super) fn hash_carte_vers_chemin(hash_carte: &[u8; 32], chemin_enu: &Path) -> PathBuf {
        let nom_fichier = format!("{}.enu", HEXLOWER.encode(hash_carte));
        chemin_enu.join(nom_fichier)
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
    /// Propage [`ErreurFeuApplication::IoError`] si le dossier `~/.feu/enu/`
    /// est absent ou sur tout autre échec d'écriture.
    pub(super) fn sauvegarder(&self, chemin_enu: &Path) -> ResultFeuApplication<PathBuf> {
        let chemin = self.chemin(chemin_enu);

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
    /// Propage [`ErreurFeuApplication::IoError`] si le fichier est absent ou si
    /// la suppression échoue.
    #[allow(dead_code)]
    pub(super) fn supprimer(&self, chemin_enu: &Path) -> ResultFeuApplication<()> {
        let chemin = self.chemin(chemin_enu);

        remove_file(&chemin)?;

        Ok(())
    }

    /// Charge **et authentifie** une ENU depuis le disque.
    ///
    /// L'ENU est localisée par content-addressing : `hash_carte` reconstruit son
    /// nom de fichier `<hash>.enu` sous `chemin_enu` (via
    /// [`Self::hash_carte_vers_chemin`]) — la désigner par son hash, c'est déjà
    /// affirmer quel contenu on attend, que la vérification finale confirme ou
    /// dément. Là où [`Enu::octets_vers_enu`] ne valide que la structure, cette
    /// méthode reconstruit l'enveloppe puis franchit la frontière de confiance. Le
    /// signataire est déterminé par la `braise` — le champ de routage qui
    /// annonce qui a signé — et la clé de vérification en découle :
    ///
    /// - **Racine du nœud** — braise [`BRAISE_VIDE`] : le nœud est le
    ///   signataire, la signature est validée contre [`cle_publique_sig_noeud`](SessionApplication::cle_publique_sig_noeud).
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
    /// Retourne [`ErreurFeuApplication::ScribeEnuNonAuthentifiee`] si l'ENU
    /// n'est pas authentifiable, et propage toute erreur d'E/S
    /// ([`ErreurFeuApplication::IoError`]), de désérialisation ou
    /// cryptographique ([`ErreurFeuApplication::FeuNoyau`]) rencontrée en chemin.
    pub(super) fn charger(
        chemin_enu: &Path,
        session: &SessionApplication,
        hash_carte: &[u8; 32],
    ) -> ResultFeuApplication<Enu> {
        let chemin = Self::hash_carte_vers_chemin(hash_carte, chemin_enu);

        let enu = Self::octets_vers_enu(&read(chemin)?)?;
        let octets_carte = enu.carte.vers_octets();

        // racine du nœud : BRAISE_VIDE → vérification contre la clé du nœud
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
            && let Some(cle_publique) = session.cle_publique_sig_foyer(index_foyer)
            && FeuNoyau::verification_signature(cle_publique, enu.signature_carte, &octets_carte)?
            && FeuNoyau::creation_empreinte(&octets_carte) == enu.hash_carte
        {
            return Ok(enu);
        }

        Err(ErreurFeuApplication::ScribeEnuNonAuthentifiee)
    }

    /// Charge et authentifie la racine **courante** du nœud, atteinte par le
    /// symlink `.DERNIERE_RACINE` (`chemin_derniere_racine`).
    ///
    /// Entrée distincte de [`Self::charger`] pour une raison structurelle :
    /// cette dernière localise une ENU par son `hash_carte`, or le hash de la
    /// racine courante est précisément ce qu'on ignore — seul le symlink la
    /// désigne. Le lien est donc lu directement (il est suivi jusqu'au fichier
    /// cible).
    ///
    /// Volontairement **plus stricte** que [`Self::charger`] : elle n'authentifie
    /// que le cas racine nœud (braise [`BRAISE_VIDE`] + méta `_racine`, signature
    /// du nœud, hash de carte concordant) et rejette tout le reste. Le sommet de
    /// l'arbre appartient toujours au nœud ; une braise de foyer à cet endroit
    /// serait une anomalie, pas un contenu à accepter.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::ScribeEnuNonAuthentifiee`] si la cible
    /// n'est pas une racine nœud authentique, et propage toute erreur d'E/S, de
    /// désérialisation ou cryptographique
    /// ([`ErreurFeuApplication::FeuNoyau`]) rencontrée en chemin.
    pub(super) fn charger_derniere_racine(
        chemin_derniere_racine: &Path,
        session: &SessionApplication,
    ) -> ResultFeuApplication<Enu> {
        let enu = Self::octets_vers_enu(&read(chemin_derniere_racine)?)?;
        let octets_carte = enu.carte.vers_octets();

        // racine du nœud : BRAISE_VIDE → vérification contre la clé du nœud
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

        Err(ErreurFeuApplication::ScribeEnuNonAuthentifiee)
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
    /// Retourne [`ErreurFeuApplication::ScribeCarteMalFormee`] si le buffer est
    /// trop court ou si le discriminant de carte est inconnu, et propage
    /// [`ErreurFeuApplication::Utf8Error`] sur un champ texte qui n'est pas de
    /// l'UTF-8 valide. Les 62 octets de braise mal formés remontent du noyau en
    /// [`ErreurFeuApplication::FeuNoyau`], via `Braise::try_from`.
    fn octets_vers_enu(octets: &[u8]) -> ResultFeuApplication<Enu> {
        let (mut octets, mut reste) = prendre_octets(octets, 62)?;
        let braise = Braise::try_from(from_utf8(octets)?)?;

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

    /// Remplace une ENU de l'arbre du nœud et produit la version suivante.
    ///
    /// Un « chercher-remplacer » par hash : cherche, dans l'arborescence
    /// courante (le sommet pointé par `.DERNIERE_RACINE`), l'ENU dont le
    /// `hash_carte` vaut `hash_a_remplacer`, et lui substitue `remplacement`.
    ///
    /// - `hash_a_remplacer` — la **cible**, une ENU déjà **présente dans
    ///   l'arbre**. Si aucune ENU ne porte ce hash, l'arbre reste inchangé
    ///   (seule une nouvelle génération à l'identique est produite).
    /// - `remplacement` — la **nouvelle** ENU qui prend sa place ; elle doit
    ///   déjà être sauvegardée sur disque (cette fonction ne l'écrit pas).
    ///
    /// Le `hash_carte` d'un répertoire dépendant de ses enfants, la substitution
    /// fait remonter de nouveaux hashs : chaque répertoire du chemin cible →
    /// racine est reconstruit ([`Self::remplacer_recursif`]), puis un nouveau
    /// sommet est forgé, signé par le nœud et posé sur `.DERNIERE_RACINE`
    /// ([`Enu::new_racine`]).
    ///
    /// La méta `_racine` du nouveau sommet — maillon de la lignée des versions —
    /// n'est pas posée ici : [`Enu::new_racine`] s'en charge, en relisant le
    /// symlink. Rien dans la descente ne le repointe (`remplacer_recursif` ne
    /// reçoit même pas son chemin), la valeur lue après reconstruction est donc
    /// bien celle du sommet remplacé.
    ///
    /// L'ancien sommet et les anciens répertoires du chemin ne sont **pas**
    /// supprimés : ce sont les versions précédentes, conservées pour
    /// l'historique (chaîne des `_racine`).
    ///
    /// # Retour
    ///
    /// Rien : le nouveau sommet devient la cible de `.DERNIERE_RACINE`. Un
    /// appelant qui en a besoin le relit via [`Self::charger_derniere_racine`].
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::ScribeRemplacementSansEffet`] si
    /// `remplacement` est identique (même hash de carte) à la racine courante.
    /// Propage les erreurs de [`Self::remplacer_recursif`] (E/S,
    /// authentification, signature — notamment si un foyer du chemin
    /// reconstruit est fermé) et de [`Enu::new_racine`].
    pub(super) fn remplacer(
        chemin_enu: &Path,
        chemin_derniere_racine: &Path,
        hash_a_remplacer: &[u8; 32],
        remplacement: &Enu,
        noyau: &FeuNoyau,
        session: &SessionApplication,
    ) -> ResultFeuApplication<()> {
        let racine = Enu::charger_derniere_racine(chemin_derniere_racine, session)?;

        if racine.hash_carte() == remplacement.hash_carte() {
            return Err(ErreurFeuApplication::ScribeRemplacementSansEffet);
        }

        let racine = Self::remplacer_recursif(
            chemin_enu,
            &racine,
            hash_a_remplacer,
            remplacement,
            noyau,
            session,
        )?;

        let nouvelle_carte = racine.carte().clone();

        Enu::new_racine(
            noyau,
            session,
            chemin_enu,
            chemin_derniere_racine,
            Some(nouvelle_carte),
        )?;

        Ok(())
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
    ) -> ResultFeuApplication<Enu> {
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
                let enu_enfant = Self::charger(chemin_enu, session, h)?;

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

    /// Retourne les hashs des ENU enfants — `None` sur une carte qui n'est pas
    /// un répertoire.
    ///
    /// Contrairement à [`Self::metas`] et [`Self::tags`], communs aux trois
    /// variantes, les enfants n'existent que pour un répertoire. L'absence n'est
    /// pas un incident — une feuille est le cas normal d'un parcours —, d'où
    /// l'[`Option`] plutôt qu'un refus qu'un appelant devrait tester puis jeter.
    /// Le `None` distingue par ailleurs la feuille du répertoire réellement vide,
    /// que renvoyer un ensemble vide confondrait.
    ///
    /// Rend une référence : le parcours descendant traverse tous les répertoires
    /// de l'arbre, un clone par pas y serait payé pour rien.
    ///
    /// `pub(crate)` — ce qui sort de la crate sort par une `commande_*`, pas par
    /// un accesseur.
    pub(crate) fn hashs_enu(&self) -> Option<&BTreeSet<[u8; 32]>> {
        match self {
            Self::Donnee {
                metas: _,
                tags: _,
                hash_donnee: _,
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
    /// # Erreurs
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
    /// # Erreurs
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

    /// Sérialise la carte en bytes canoniques.
    ///
    /// Format : discriminant `u8` (0x00=CaD, 0x01=CaT, 0x02=CaR), métadonnées,
    /// tags, puis les champs spécifiques à chaque variant. Le résultat est
    /// déterministe : même carte → mêmes octets → même hash.
    pub(super) fn vers_octets(&self) -> Vec<u8> {
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
    fn octets_vers_carte(octets: &[u8]) -> ResultFeuApplication<Carte> {
        let (mut octets, reste) = prendre_octets(octets, 1)?;

        let (metas, reste) = octets_vers_metas(reste)?;
        let (tags, mut reste) = octets_vers_tags(reste)?;
        match octets[0] {
            0 => {
                let (hash, reste) = prendre_octets(reste, 32)?;
                let hash_donnee: [u8; 32] = hash.try_into().unwrap(); // pas d'erreur possible

                if !reste.is_empty() {
                    return Err(ErreurFeuApplication::ScribeCarteMalFormee);
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
/// Retourne `(extrait, reste)` ou une erreur si le buffer est trop court.
fn prendre_octets(buf: &[u8], n: usize) -> ResultFeuApplication<(&[u8], &[u8])> {
    if buf.len() < n {
        return Err(ErreurFeuApplication::ScribeCarteMalFormee);
    }
    Ok((&buf[0..n], &buf[n..]))
}

#[cfg(test)]
mod tests {
    //! Tests en ligne : ce qui se prouve sans monter de pile.
    //!
    //! Le format canonique et les gardes de forme, éprouvés sur des octets et
    //! des cartes forgés à la main — aucune signature, donc aucun noyau. C'est
    //! la moitié de ce module qui ne franchit pas la barrière de confiance.
    //!
    //! L'autre moitié est dans `src/scribe/tests.rs` : tout ce qui touche à
    //! l'enveloppe signée ([`Enu::new`], [`Enu::charger`], [`Enu::remplacer`])
    //! y monte un noyau allumé et un foyer ouvert, seule façon de signer puis de
    //! relire une ENU authentifiée.

    use crate::ResultFeuApplication;

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

    // --- Tags ---

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

    // --- ENU ---

    /// Round-trip complet : Enu → octets → Enu, tous champs identiques.
    #[test]
    fn enu_vers_octets_et_retour() -> ResultFeuApplication<()> {
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
    /// refus de `ajout_hash_enu` (`ScribeEnuRAttendue`), tags et metas insérés
    /// puis relus via les accesseurs communs.
    #[test]
    fn carte_donnee() -> ResultFeuApplication<()> {
        let hash_donnee = [0u8; 32];
        let mut carte = Carte::new_donnee(hash_donnee);

        assert!(matches!(
            carte.ajout_hash_enu(&hash_donnee),
            Err(ErreurFeuApplication::ScribeEnuRAttendue)
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

    /// Cycle complet sur `Carte::Texte` : contenu conservé et méta `"nom"`
    /// posée dès la construction, refus de `ajout_hash_enu`
    /// (`ScribeEnuRAttendue`),
    /// tags et metas insérés puis relus via les accesseurs communs.
    #[test]
    fn carte_texte() -> ResultFeuApplication<()> {
        let hash_donnee = [0u8; 32];
        let mut carte = Carte::new_texte("Test", "Contenu court de test")?;

        assert!(matches!(
            carte.ajout_hash_enu(&hash_donnee),
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

        carte.ajout_hash_enu(&hash_donnee1)?;
        carte.ajout_hash_enu(&hash_donnee2)?;

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
    /// - `ScribeMetaNomAbsente` : méta `"nom"` absente — éprouvé en premier,
    ///   sur une carte neuve, seul moment où elle l'est.
    /// - `ScribeNomFichierInvalide` : vide, et toute forme de `/` (en tête, au
    ///   milieu, en queue, multiple) — le nom vient d'une ENU lue sur disque, un
    ///   `/` en tête remplacerait le chemin cible d'un `join` au lieu de s'y
    ///   ajouter.
    /// - `ScribeNomFichierInvalide` : `.` et `..` **exacts**, les deux
    ///   composants spéciaux.
    ///
    /// Les cas acceptés portent tous des points sans être ces composants
    /// (`.test`, `..test`, `test..`, `test..2`…) : ils distinguent l'égalité
    /// stricte d'un `starts_with` ou d'un `contains`, qui rejetterait à tort des
    /// noms légitimes — un fichier caché en particulier. On y vérifie le nom
    /// rendu, pas seulement l'absence d'erreur : la garde ne doit rien réécrire.
    ///
    /// Une seule carte traverse le test, la méta `"nom"` étant écrasée à chaque
    /// cas (`BTreeMap::insert`).
    #[test]
    fn nom_fichier() -> ResultFeuApplication<()> {
        let hash_donnee = [0u8; 32];

        let mut carte = Carte::new_donnee(hash_donnee);

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
