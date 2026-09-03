// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Enveloppes ENU.
//!
//! Une [`Enu`] est une enveloppe signée transportant une [`Carte`], qui porte
//! le contenu métier (voir [`super::carte`]). L'enveloppe ajoute l'identité
//! (hash), l'authenticité (signature ML-DSA-87) et la braise du signataire.
//! Deux signataires possibles : un **foyer** (ENU de contenu, braise du foyer)
//! ou le **nœud** lui-même (racines de l'arborescence, [`Braise::VIDE`] — voir
//! [`Enu::new_racine`]).
//!
//! Les ENU sont **content-addressed** : le hash de la carte sert de nom de
//! fichier sur disque (`<hash_hex>.enu`). Aucune carte n'a de nom stable.
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
//! # Exposition
//!
//! [`Enu`] ne quitte pas la crate : la couche de présentation reçoit des
//! [`Fiche`](crate::fiche::Fiche), mêmes champs sans la signature. Champs
//! privés, pas de `new` public, et construction ([`Enu::new`],
//! [`Enu::new_racine`]) comme persistance ([`Enu::sauvegarder`]) en
//! `pub(super)`.
//!
//! Toute [`Enu`] relue du disque passe par un chargement `pub(super)` :
//! [`Enu::charger`] et [`Enu::charger_derniere_racine`] valident le hash **et**
//! la signature, [`Enu::charger_sans_verification_signature`] — réservé au
//! parcours — seulement le hash annoncé par la carte du parent. Ce qui sort
//! d'un parcours n'engage donc rien tant qu'il n'a pas repassé
//! [`Enu::authentique`], barrière de toute action sur un blob.

use std::{
    collections::BTreeSet,
    fs::{read, remove_file, rename},
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    str::from_utf8,
    time::{SystemTime, UNIX_EPOCH},
};

use data_encoding::HEXLOWER;
use feu_noyau::{Braise, FeuNoyau};

use crate::{
    ErreurFeuApplication, ResultFeuApplication, Scribe, SessionApplication,
    scribe::carte::{Carte, prendre_octets},
};

/// Enveloppe Numérique Universelle.
///
/// Le `hash_carte` (SHA3-256 de la carte sérialisée) est le nom du fichier
/// dans `~/.feu/enu/`. La `signature_carte` (ML-DSA-87) couvre la carte
/// sérialisée directement. La `date` est le timestamp Unix de mise sous
/// enveloppe. La `braise` identifie le signataire pour la vérification :
/// l'adresse d'un foyer, ou [`Braise::VIDE`] quand le signataire est le nœud
/// (racines de l'arborescence).
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Enu {
    /// Adresse `.braise` du signataire — un foyer, ou [`Braise::VIDE`] pour une
    /// racine signée par le nœud (non couverte par le hash ni la signature —
    /// métadonnée de routage).
    braise: Braise,

    /// SHA3-256 de la carte sérialisée.
    hash_carte: [u8; 32],
    /// Signature ML-DSA-87 de la carte sérialisée (taille fixe, 4627 o).
    signature_carte: [u8; 4627],
    /// Timestamp Unix de mise sous enveloppe (non couvert par la signature).
    date: u64,

    /// Le contenu enveloppé, seule partie couverte par `hash_carte` et par la
    /// signature.
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
    /// # Errors
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

    /// Rend une copie de l'ENU portant `nom` en méta `"nom"`, re-signée.
    ///
    /// La carte est clonée et sa méta écrasée : le sous-arbre d'un répertoire
    /// renommé reste intact, seuls le `hash_carte` et la signature changent. La
    /// braise est conservée, donc le foyer d'origine doit être ouvert.
    ///
    /// Ne sauvegarde ni ne greffe, comme [`Self::new`] : c'est à l'appelant de
    /// sauvegarder la copie et de raccrocher son hash.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeBraiseInconnue`] si la braise
    /// n'identifie aucun foyer de la session — cas d'une racine du nœud, qui
    /// porte [`Braise::VIDE`]. Propage toute erreur de signature du noyau.
    pub(super) fn renommer(
        &self,
        nom: &str,
        noyau: &FeuNoyau,
        session: &SessionApplication,
    ) -> ResultFeuApplication<Enu> {
        let mut carte = self.carte().clone();
        carte.ajout_meta("nom", nom);

        Enu::new(carte, noyau, session, self.braise)
    }

    /// Forge une racine du nœud, la sauvegarde et repointe le sommet courant.
    ///
    /// Signée par le **nœud**, non par un foyer : sa braise vaut [`Braise::VIDE`],
    /// ce qui oriente [`Enu::charger`] vers la clé du nœud.
    ///
    /// `carte` à `None` forge la **genèse**, dont la méta `_racine` vaut `""` :
    /// fin de chaîne, et ce qui la distingue d'un répertoire vide ordinaire.
    ///
    /// `Some(carte)` reçoit un sommet reconstruit, et **la méta `_racine` est
    /// posée ici**, écrasant celle de l'appelant : le chaînage se tient au seul
    /// endroit qui repointe le symlink.
    ///
    /// Le symlink est repointé atomiquement, et l'ENU n'est **pas** rendue.
    ///
    /// # Errors
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
            braise: Braise::VIDE,
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
    /// [`Braise::VIDE`] pour une racine signée par le nœud.
    ///
    /// Métadonnée de routage, hors hash et hors signature : sa valeur n'est pas
    /// authentifiée (voir le modèle de confiance du module).
    pub(crate) fn braise(&self) -> Braise {
        self.braise
    }

    /// Retourne le hash SHA3-256 de la carte — identifiant content-addressed
    /// de l'ENU, également utilisé comme nom de fichier dans `~/.feu/enu/`.
    pub(crate) fn hash_carte(&self) -> [u8; 32] {
        self.hash_carte
    }

    /// Retourne le timestamp Unix de mise sous enveloppe.
    ///
    /// Non couvert par la signature ni le hash — métadonnée indicative.
    pub(crate) fn date(&self) -> u64 {
        self.date
    }

    /// Retourne une référence à la [`Carte`] transportée par l'enveloppe.
    pub(crate) fn carte(&self) -> &Carte {
        &self.carte
    }

    /// Recalcule l'empreinte de la carte et la compare au hash attendu.
    ///
    /// Seule garantie du parcours, qui ne vérifie aucune signature : le hash
    /// attendu vient de la carte du parent, et le chaînage Merkle porte alors
    /// l'intégrité de proche en proche à partir du point de départ. Lui passer le
    /// `hash_carte` de l'enveloppe elle-même ne prouve rien de tel — un fichier
    /// forgé s'accorde avec lui-même ; ça ne vaut que là où la signature suit,
    /// pour établir que le hash annoncé désigne bien la carte authentifiée.
    pub(crate) fn integre(&self, hash_attendu: &[u8; 32]) -> bool {
        let hash = FeuNoyau::creation_empreinte(&self.carte.vers_octets());

        &hash == hash_attendu
    }

    /// Vérifie la signature de la carte contre la clé publique de son signataire.
    ///
    /// La `braise` route vers cette clé : [`Braise::VIDE`] plus la méta `_racine`
    /// désignent le nœud, toute autre valeur un foyer connu de la session. Hors
    /// signature, elle ne peut que router vers la mauvaise clé et faire échouer
    /// la vérification — jamais faire accepter une ENU.
    ///
    /// Barrière de tout ce qui engage : lecture, suppression ou description d'un
    /// blob, retrait sur le disque. Le parcours, lui, s'en passe et ne s'appuie
    /// que sur [`Self::integre`].
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeBraiseInconnue`] si la braise ne
    /// résout vers aucun foyer de la session,
    /// [`ErreurFeuApplication::ScribeIndexFoyerInvalide`] si ce foyer ne livre
    /// aucune clé, et propage l'erreur cryptographique du noyau. Une signature
    /// simplement invalide est un `Ok(false)`, à l'appelant d'en faire un refus.
    pub(crate) fn authentique(&self, session: &SessionApplication) -> ResultFeuApplication<bool> {
        if self.braise == Braise::VIDE && self.carte.metas().contains_key("_racine") {
            Ok(FeuNoyau::verification_signature(
                session.cle_publique_sig_noeud(),
                self.signature_carte,
                &self.carte.vers_octets(),
            )?)
        } else {
            let Some(index_foyer) = session.braise_vers_index(self.braise) else {
                return Err(ErreurFeuApplication::ScribeBraiseInconnue);
            };
            let Some(cle) = session.cle_publique_sig_foyer(index_foyer) else {
                return Err(ErreurFeuApplication::ScribeIndexFoyerInvalide(index_foyer));
            };

            Ok(FeuNoyau::verification_signature(
                cle,
                self.signature_carte,
                &self.carte.vers_octets(),
            )?)
        }
    }

    /// Écrit l'ENU sur disque sous `~/.feu/enu/<hash_carte_hex>.enu`.
    ///
    /// Le nom du fichier est l'empreinte hexadécimale de la carte
    /// (content-addressing) : une carte donnée vise toujours le même fichier,
    /// indépendamment de l'enveloppe qui la transporte. L'écriture passe par
    /// [`Scribe::ecrire_fichier_600`] — `0o600` et pose atomique, sans quoi un
    /// arrêt brutal laisserait une ENU tronquée sous un nom de hash valide, que
    /// l'idempotence ci-dessous ne réécrirait jamais.
    ///
    /// **Idempotent.** Si le fichier existe déjà, l'écriture est shuntée : le nom
    /// étant le hash de la carte, un même nom encode la même carte, que `date` et
    /// `signature` ne touchent pas — d'où une déduplication à l'échelle du nœud.
    ///
    /// # Retour
    ///
    /// Le chemin du fichier `.enu` — existant ou nouvellement créé. Utile pour
    /// l'appelant qui a besoin de le désigner ensuite, par exemple pour y faire
    /// pointer le symlink de la dernière racine.
    ///
    /// # Errors
    ///
    /// Propage [`ErreurFeuApplication::IoError`] si le dossier `~/.feu/enu/`
    /// est absent ou sur tout autre échec d'écriture.
    pub(super) fn sauvegarder(&self, chemin_enu: &Path) -> ResultFeuApplication<PathBuf> {
        let chemin = self.chemin(chemin_enu);

        if !chemin.exists() {
            Scribe::ecrire_fichier_600(&chemin, &self.vers_octets())?;
        }

        Ok(chemin)
    }

    /// Supprime le fichier `.enu` de cette ENU du disque.
    ///
    /// Sans appelant de production depuis que [`Enu::remplacer`] conserve les
    /// anciens sommets : seul un test l'exerce, d'où le `#[allow(dead_code)]`.
    ///
    /// # Errors
    ///
    /// Propage [`ErreurFeuApplication::IoError`] si le fichier est absent ou si
    /// la suppression échoue.
    #[allow(dead_code)]
    pub(super) fn supprimer(&self, chemin_enu: &Path) -> ResultFeuApplication<()> {
        let chemin = self.chemin(chemin_enu);

        remove_file(&chemin)?;

        Ok(())
    }

    /// Charge **et authentifie** une ENU depuis le disque : le chargement complet,
    /// hash puis signature.
    ///
    /// Elle n'ajoute qu'une ligne à
    /// [`Self::charger_sans_verification_signature`] — la barrière
    /// [`Self::authentique`] — mais c'est cette ligne qui sépare les deux
    /// usages : navigation d'un côté, action de l'autre.
    ///
    /// La `braise` restant hors signature, la falsifier ne peut que router vers
    /// la mauvaise clé et faire **échouer** la vérification — jamais faire
    /// accepter une ENU.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeEnuNonAuthentique`] si la signature
    /// n'est pas validée, propage les refus de [`Self::authentique`] — braise
    /// inconnue, foyer sans clé — et ceux du chargement qu'elle enveloppe.
    pub(super) fn charger(
        chemin_enu: &Path,
        session: &SessionApplication,
        hash_carte: &[u8; 32],
    ) -> ResultFeuApplication<Enu> {
        let enu = Enu::charger_sans_verification_signature(chemin_enu, hash_carte)?;

        if !enu.authentique(session)? {
            return Err(ErreurFeuApplication::ScribeEnuNonAuthentique);
        }

        Ok(enu)
    }

    /// Charge une ENU en ne vérifiant que son intégrité — **jamais sa signature**.
    ///
    /// Le `hash_carte` localise le fichier **et** dit quel contenu on attend :
    /// [`Self::integre`] le confirme sur l'empreinte recalculée. Le nom du
    /// fichier, lui, ne prouve rien.
    ///
    /// Réservé au **parcours**, où le hash attendu vient de la carte du parent et
    /// où le chaînage de Merkle porte l'intégrité de proche en proche. Ce qui en
    /// sort n'engage rien tant que [`Self::authentique`] n'est pas repassée — le
    /// nom est long à dessein.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeEnuNonIntegre`] si la carte lue ne
    /// donne pas le hash attendu, et propage toute erreur d'E/S
    /// ([`ErreurFeuApplication::IoError`]) ou de désérialisation.
    pub(super) fn charger_sans_verification_signature(
        chemin_enu: &Path,
        hash_carte: &[u8; 32],
    ) -> ResultFeuApplication<Enu> {
        let chemin = Self::hash_carte_vers_chemin(hash_carte, chemin_enu);

        let enu = Self::octets_vers_enu(&read(chemin)?)?;

        if !enu.integre(hash_carte) {
            return Err(ErreurFeuApplication::ScribeEnuNonIntegre);
        }

        Ok(enu)
    }

    /// Charge et authentifie la racine **courante** du nœud, atteinte par le
    /// symlink `.DERNIERE_RACINE` (`chemin_derniere_racine`).
    ///
    /// Entrée distincte de [`Self::charger`], qui localise par `hash_carte` : ici
    /// ce hash est précisément ce qu'on ignore, seul le symlink désigne la cible.
    ///
    /// Volontairement **plus stricte** : braise [`Braise::VIDE`] et méta `_racine`
    /// sont exigées, quand [`Self::authentique`] s'en sert seulement pour router
    /// vers la clé du nœud.
    ///
    /// Faute de hash attendu, [`Self::integre`] porte sur celui de l'enveloppe :
    /// seul il n'établit rien, mais la signature couvre la carte, et les deux
    /// ensemble prouvent que le hash annoncé désigne la carte authentifiée.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeEnuRacineAttendue`] si la cible
    /// n'est pas une racine du nœud, [`ErreurFeuApplication::ScribeEnuNonIntegre`]
    /// si l'enveloppe ne s'accorde pas avec sa carte,
    /// [`ErreurFeuApplication::ScribeEnuNonAuthentique`] si la signature n'est pas
    /// validée, et propage toute erreur d'E/S, de désérialisation ou
    /// cryptographique ([`ErreurFeuApplication::FeuNoyau`]) rencontrée en chemin.
    pub(super) fn charger_derniere_racine(
        chemin_derniere_racine: &Path,
        session: &SessionApplication,
    ) -> ResultFeuApplication<Enu> {
        let enu = Self::octets_vers_enu(&read(chemin_derniere_racine)?)?;

        if enu.braise != Braise::VIDE || !enu.carte.metas().contains_key("_racine") {
            return Err(ErreurFeuApplication::ScribeEnuRacineAttendue);
        }
        if !enu.integre(&enu.hash_carte()) {
            return Err(ErreurFeuApplication::ScribeEnuNonIntegre);
        }
        if !enu.authentique(session)? {
            return Err(ErreurFeuApplication::ScribeEnuNonAuthentique);
        }

        Ok(enu)
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
    /// # Errors
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
    /// Un « chercher-remplacer » par hash dans l'arborescence courante.
    /// `remplacement` doit déjà être sauvegardée. Une cible absente est refusée
    /// plutôt que de produire une version identique à la précédente.
    ///
    /// Le `hash_carte` d'un répertoire dépendant de ses enfants, la substitution
    /// fait remonter de nouveaux hashs jusqu'à un sommet signé par le nœud, dont
    /// [`Enu::new_racine`] pose la méta `_racine` en relisant le symlink.
    ///
    /// Les anciennes versions **ne sont pas supprimées**.
    ///
    /// # Retour
    ///
    /// Rien : le nouveau sommet devient la cible de `.DERNIERE_RACINE`. Un
    /// appelant qui en a besoin le relit via [`Self::charger_derniere_racine`].
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeRemplacementSansEffet`] si la
    /// substitution laisse l'arbre inchangé — cible absente, ou remplacement déjà
    /// en place.
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
        let racine_depart = Enu::charger_derniere_racine(chemin_derniere_racine, session)?;

        let racine = Self::remplacer_recursif(
            chemin_enu,
            &racine_depart,
            hash_a_remplacer,
            remplacement,
            noyau,
            session,
        )?;

        // Si la cible est absente de l'arbre de la dernière racine, la récursion
        // rend le départ inchangé — et une nouvelle racine n'apporterait qu'un
        // maillon mort à la lignée des `_racine`.
        if racine.carte() == racine_depart.carte() {
            return Err(ErreurFeuApplication::ScribeRemplacementSansEffet);
        }

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
    /// Mise à jour **immuable** : `racine` n'est jamais modifiée en place, chaque
    /// répertoire du chemin est reconstruit, métas et tags conservés.
    ///
    /// Un **répertoire de foyer** est re-signé sous sa propre braise — ce qui
    /// autorise un arbre mêlant plusieurs foyers — et **tout foyer du chemin doit
    /// donc être ouvert**. Le **sommet du nœud**, lui, n'est ni re-signé ni
    /// sauvegardé : la récursion rend une ENU **temporaire**, dont le
    /// `hash_carte` et la signature, périmés, ne doivent pas être lus.
    ///
    /// # Retour
    ///
    /// La racine du sous-arbre après substitution — éventuellement l'ENU
    /// temporaire décrite ci-dessus si cette racine est le sommet du nœud ;
    /// un clone inchangé de `racine` si la cible est absente du sous-arbre.
    ///
    /// # Errors
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
                if racine.braise() == Braise::VIDE {
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

/// Tests en ligne : ce qui se prouve sans monter de pile.
///
/// Une seule chose relève d'ici : l'aller-retour de l'enveloppe par son
/// format canonique, sur une ENU forgée à la main. La désérialisation ne
/// vérifiant ni le hash ni la signature, des octets quelconques suffisent
/// à l'éprouver. Le format de la carte transportée se teste dans le module
/// `carte`, qui le tient.
///
/// Tout ce qui signe ou authentifie ([`Enu::new`], [`Enu::charger`],
/// [`Enu::remplacer`]) est dans `src/scribe/tests.rs`, qui monte un noyau
/// allumé et un foyer ouvert.
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::ResultFeuApplication;

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
        let hash_blob: [u8; 32] = std::array::from_fn(|i| i as u8);

        let carte = Carte::Donnee {
            metas,
            tags,
            hash_blob,
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
