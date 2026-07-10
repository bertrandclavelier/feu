// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Scribe — tenue du dossier `~/.feu/enu/`.
//!
//! Le [`Scribe`] est le tenant applicatif de la couche ENU dans
//! `feu-application`. Il crée et maintient le dossier `enu/` à la racine
//! du nœud (`~/.feu/enu/`), **pas** dans un foyer. Ce choix permet de
//! consulter, naviguer et indexer les ENU même quand tous les foyers
//! sont fermés — les ENU sont en clair, leur intégrité est garantie par
//! la signature, pas par le chiffrement.
//!
//! Le Scribe est activé à l'allumage du nœud et désactivé à son extinction.
//! Il ignore ce qu'est un foyer : la résolution du blob (trouver le `.dat`
//! correspondant à un `hash_donnee`) est ailleurs.

mod comptoir;
pub mod enu;
pub(super) mod erreur;

#[cfg(test)]
mod tests;

use data_encoding::HEXLOWER;
use std::{
    collections::HashMap,
    fs::{DirBuilder, OpenOptions, read, read_dir},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use feu_noyau::FeuNoyau;
use walkdir::WalkDir;

use crate::{
    SessionApplication,
    scribe::{
        comptoir::ComptoirDepot,
        enu::{Carte, Enu},
        erreur::{ErreurScribe, ResultScribe},
    },
};

/// L'ID fourni ne correspond à aucun comptoir de dépôt actif dans
/// [`Scribe::comptoirs_depot`].
const ERR_SCR_001: &str = "SCR-001 > Index du comptoir invalide";
/// Le chemin visé par un retrait est déjà un dossier — le retrait refuse
/// d'écrire dans un dossier existant, il crée toujours le sien.
const ERR_SCR_002: &str = "SCR-002 > Le dossier existe déjà";
/// L'ENU fournie comme racine de retrait n'est pas une `EnuR`
/// ([`Carte::Repertoire`]) : seul un répertoire peut ouvrir une arborescence.
const ERR_SCR_003: &str = "SCR-003 > Ce doit être une EnuR";
/// La braise de l'ENU n'identifie aucun foyer de la session — impossible de
/// résoudre l'`index_foyer` nécessaire à la lecture du blob.
const ERR_SCR_004: &str = "SCR-004 > Braise inconnue";

/// Tenant de la couche ENU — créé et maintient `~/.feu/enu/`.
///
/// Activé à l'allumage du nœud, désactivé à l'extinction. Le dossier
/// `enu/` est créé avec les permissions `rwx------` (0o700), cohérent
/// avec le reste de `~/.feu/`.
pub(super) struct Scribe {
    /// `true` si le Scribe a été activé (nœud allumé).
    est_actif: bool,

    /// Chemin du dossier des ENU — `~/.feu/enu/`, dérivé du chemin racine reçu à
    /// la construction.
    chemin_enu: PathBuf,

    /// Chemin du symlink `.DERNIERE_RACINE` — le sommet courant de
    /// l'arborescence, dans `enu/`. Dérivé une fois à la construction et
    /// transmis à [`Enu::new_racine`] / [`Enu::remplacer`], qui le repointent
    /// atomiquement à chaque nouvelle racine. Le Scribe est ainsi la source
    /// unique de cet emplacement.
    chemin_derniere_racine: PathBuf,

    /// Comptoirs de dépôt actifs, indexés par leur identifiant.
    comptoirs_depot: HashMap<usize, ComptoirDepot>,

    /// Prochain identifiant disponible pour un nouveau comptoir.
    prochain_id: usize,
}

impl Scribe {
    /// Construit un [`Scribe`] inactif.
    ///
    /// `chemin_feu` est le chemin racine du nœud (`~/.feu` en usage nominal),
    /// reçu de [`FeuApplication`]. Le Scribe en dérive une fois pour toutes le
    /// chemin de son dossier `enu/` (`chemin_enu`) — aucune relecture de
    /// l'environnement à l'usage.
    pub(super) fn new(chemin_feu: &Path) -> Self {
        Self {
            est_actif: false,
            chemin_enu: chemin_feu.join("enu/"),
            chemin_derniere_racine: chemin_feu.join("enu/").join(".DERNIERE_RACINE"),
            comptoirs_depot: HashMap::new(),
            prochain_id: 0,
        }
    }

    /// Active le Scribe et, à la première activation, amorce l'arborescence.
    ///
    /// Appelé par [`commande_allumage_noeud`](crate::FeuApplication::commande_allumage_noeud)
    /// après que le noyau a été allumé avec succès. Si le dossier `enu/` est
    /// absent (tout premier allumage du nœud), il est créé en `rwx------`
    /// (0o700), puis la **racine origine** est forgée et posée en sommet
    /// courant via [`Enu::new_racine`] (carte `None` : répertoire vide, signé
    /// par le nœud, symlink `.DERNIERE_RACINE` pointé dessus). `feu_noyau` est
    /// requis pour cette signature de genèse.
    ///
    /// Aux allumages ultérieurs (`enu/` déjà présent), cette amorce est sautée.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la création du dossier, la signature de la racine
    /// origine, sa sauvegarde ou la pose du symlink échoue.
    pub(super) fn activation(&mut self, feu_noyau: &FeuNoyau) -> ResultScribe<()> {
        self.est_actif = true;

        if !&self.chemin_enu.exists() {
            DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&self.chemin_enu)?;

            Enu::new_racine(
                feu_noyau,
                &self.chemin_enu,
                &self.chemin_derniere_racine,
                None,
            )?;
        }

        Ok(())
    }

    /// Désactive le Scribe.
    ///
    /// Appelé par [`commande_extinction_noeud`](crate::FeuApplication::commande_extinction_noeud).
    /// Ne supprime pas le dossier `enu/` — les ENU survivent à l'extinction.
    pub(super) fn desactivation(&mut self) {
        self.est_actif = false;
    }

    /// Ouvre un comptoir de dépôt au chemin donné.
    ///
    /// Crée le dossier physique sur le système de fichiers, l'enregistre
    /// dans [`comptoirs_depot`](Self::comptoirs_depot) et retourne son
    /// identifiant.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le dossier existe déjà ou ne peut pas être
    /// créé.
    pub(super) fn ouverture_comptoir_depot(
        &mut self,
        chemin: PathBuf,
        index_foyer: usize,
        index_classeur: usize,
    ) -> ResultScribe<usize> {
        let comptoir = ComptoirDepot::new(chemin, index_foyer, index_classeur);
        comptoir.ouvrir()?; // on s'assure qu'on peut l'ouvrir avant de le garder
        //
        self.comptoirs_depot.insert(self.prochain_id, comptoir);
        self.prochain_id += 1;

        Ok(self.prochain_id - 1)
    }

    /// Ferme un comptoir de dépôt : greffe son contenu sous `enu_racine_depot`,
    /// puis propage la nouvelle racine de dépôt jusqu'à la racine du nœud.
    ///
    /// Parcourt le dossier en bottom-up (`contents_first(true)`) : chaque
    /// fichier est déposé dans le classeur du comptoir via
    /// [`FeuNoyau::depot_donnees`], puis encapsulé dans une ENU signée de
    /// type [`Carte::Donnee`]. Chaque répertoire devient une
    /// [`Carte::Repertoire`] référençant ses enfants par leur `hash_carte`.
    /// Toutes les ENU produites sont sauvegardées dans `~/.feu/enu/`.
    ///
    /// Le nom de chaque entrée (fichier ou dossier) est conservé comme
    /// métadonnée `"nom"`. Le marquage de la racine du nœud (`"_racine"`) n'est
    /// **pas** posé ici : il l'est par [`Enu::remplacer`] sur le sommet final,
    /// lors de la propagation jusqu'à la racine du nœud.
    ///
    /// Les entrées directement à la racine du comptoir (`depth == 1`) sont
    /// ajoutées comme enfants directs de `enu_racine_depot`. Les entrées plus
    /// profondes (`depth > 1`) forment des sous-arbres autonomes dont la
    /// racine devient enfant de `enu_racine_depot`. Le dossier physique du comptoir
    /// est supprimé en fin de traitement. Un comptoir vide est simplement
    /// supprimé sans modifier `enu_racine_depot`.
    ///
    /// # Retour
    ///
    /// Rien : le nouveau sommet du nœud est signé, sauvegardé et devient la
    /// cible de `.DERNIERE_RACINE`. Un comptoir vide laisse la racine courante
    /// inchangée. L'appelant qui a besoin de la racine à jour la relit via
    /// [`Enu::charger_derniere_racine`].
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] (`SCR-001`) si l'ID du comptoir est
    /// invalide. Propage toute erreur d'E/S, de dépôt de données ou de signature
    /// — y compris l'échec de signature si un foyer du chemin reconstruit par
    /// [`Enu::remplacer`] est fermé.
    pub(super) fn fermeture_comptoir_depot(
        &mut self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        index_comptoir: usize,
        enu_racine_depot: &Enu,
    ) -> ResultScribe<()> {
        let Some(comptoir) = self.comptoirs_depot.remove(&index_comptoir) else {
            return Err(ErreurScribe::Interne(String::from(ERR_SCR_001)));
        };

        // foyer/classeur de destination, constants pour tout le comptoir
        let braise = session.braise_foyer(comptoir.index_foyer())?;

        let dir = read_dir(comptoir.chemin())?;
        if dir.count() == 0 {
            // comptoir vide : rien à greffer, le nœud est inchangé
            comptoir.supprimer()?;

            return Ok(());
        }

        // depth 1 → enfants directs du dépôt ; plus profond → rattachés à leur parent
        let mut nouveaux_enfants: Vec<[u8; 32]> = Vec::new();
        let mut enfants: HashMap<PathBuf, Vec<[u8; 32]>> = HashMap::new();

        // bottom-up : un dossier est traité après ses enfants, dont il référence les hashs
        for entree in WalkDir::new(comptoir.chemin()).contents_first(true) {
            let entree = entree?;
            if entree.depth() == 0 {
                // depth 0 = le comptoir lui-même : on greffe son contenu, pas lui
                continue;
            }
            let chemin_entree = entree.path().to_path_buf();

            // si c'est un fichier
            if entree.file_type().is_file() {
                let contenu = read(&chemin_entree)?;

                let hash_fichier = noyau.depot_donnees(
                    comptoir.index_foyer(),
                    comptoir.index_classeur(),
                    &contenu[..],
                )?;

                let hash_fichier: [u8; 32] = HEXLOWER
                    .decode(hash_fichier.as_bytes())
                    .map_err(|e| ErreurScribe::Interne(format!("hex invalide : {e}")))?
                    .try_into()
                    .unwrap();

                let mut carte = Carte::new_donnee(hash_fichier);
                carte.ajout_meta("nom", entree.file_name().to_string_lossy().as_ref());

                let enu = Enu::new(carte, noyau, session, braise)?;

                enu.sauvegarder(&self.chemin_enu)?;

                let hash_carte = enu.hash_carte();

                if entree.depth() == 1 {
                    nouveaux_enfants.push(hash_carte);
                } else {
                    let parent = entree.path().parent().unwrap().to_path_buf();
                    enfants.entry(parent).or_default().push(hash_carte);
                }
            }

            // si c'est un répertoire
            if entree.file_type().is_dir() {
                let hashs = enfants.remove(&chemin_entree).unwrap_or_default();

                let mut carte = Carte::new_repertoire(hashs.into_iter().collect());

                carte.ajout_meta("nom", entree.file_name().to_string_lossy().as_ref());

                let enu = Enu::new(carte, noyau, session, braise)?;

                enu.sauvegarder(&self.chemin_enu)?;

                let hash_carte = enu.hash_carte();
                if entree.depth() == 1 {
                    nouveaux_enfants.push(hash_carte);
                } else {
                    let parent = entree.path().parent().unwrap().to_path_buf();
                    enfants.entry(parent).or_default().push(hash_carte);
                }
            }
        }

        // greffe : le contenu de premier niveau devient enfant du dépôt
        let mut nouvelle_carte = enu_racine_depot.carte().clone();

        for h in &nouveaux_enfants {
            nouvelle_carte.ajout_hash_donnee(h)?;
        }

        let nouvelle_enu_racine_depot =
            Enu::new(nouvelle_carte, noyau, session, enu_racine_depot.braise())?;

        nouvelle_enu_racine_depot.sauvegarder(&self.chemin_enu)?;

        // remonte la nouvelle racine de dépôt jusqu'à la racine du nœud
        Enu::remplacer(
            &self.chemin_enu,
            &self.chemin_derniere_racine,
            &enu_racine_depot.hash_carte(),
            &nouvelle_enu_racine_depot,
            noyau,
            session,
        )?;

        comptoir.supprimer()?;

        Ok(())
    }

    /// Dépose un texte dans un foyer en l'accrochant sous `enu_racine_depot`,
    /// puis propage la nouvelle racine de dépôt jusqu'à la racine du nœud.
    ///
    /// Variante allégée de [`Self::fermeture_comptoir_depot`] : pas de comptoir,
    /// pas de blob, pas de classeur. Le texte est embarqué dans une
    /// [`Carte::Texte`] (bornée à `MAX_TAILLE_TEXTE`, nommée par la méta `"nom"`
    /// — validée à la construction), mise sous enveloppe signée
    /// — l'`EnuT` — et sauvegardée dans `~/.feu/enu/`. Son `hash_carte` est
    /// ensuite ajouté aux enfants de `enu_racine_depot`, qui est reconstruit,
    /// re-signé sous sa propre braise et sauvegardé à son tour. Comme le
    /// `hash_carte` d'un répertoire dépend de ses enfants, cette nouvelle racine
    /// de dépôt est enfin remontée via [`Enu::remplacer`] jusqu'à produire une
    /// nouvelle racine de nœud.
    ///
    /// L'`EnuT` comme le répertoire d'accueil sont signés sous la braise de
    /// `enu_racine_depot` : le texte appartient au foyer qui possède le
    /// répertoire de destination. Ce foyer — et tout foyer présent sur le chemin
    /// remonté par [`Enu::remplacer`] — doit donc être ouvert.
    ///
    /// # Retour
    ///
    /// Rien : le nouveau sommet du nœud est signé, sauvegardé et devient la
    /// cible de `.DERNIERE_RACINE` ; l'appelant qui en a besoin le relit via
    /// [`Enu::charger_derniere_racine`].
    ///
    /// # Erreurs
    ///
    /// Propage [`ErreurScribe::Interne`] si le texte dépasse `MAX_TAILLE_TEXTE`
    /// (`ENU-006`) ou si `nom` est refusé comme composant de chemin (`ENU-009`)
    /// — les deux via [`Carte::new_texte`] — ou si `enu_racine_depot` n'est pas
    /// un répertoire (`ENU-004`, via `ajout_hash_donnee`), ainsi que toute erreur
    /// d'E/S, d'authentification ou de signature — notamment si un foyer du
    /// chemin reconstruit est fermé.
    pub(super) fn depot_enu_texte(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        enu_racine_depot: &Enu,
        nom: &str,
        contenu: &str,
    ) -> ResultScribe<()> {
        let enu_texte = Enu::new(
            Carte::new_texte(nom, contenu)?,
            noyau,
            session,
            enu_racine_depot.braise(),
        )?;

        enu_texte.sauvegarder(&self.chemin_enu)?;

        let mut nouvelle_carte = enu_racine_depot.carte().clone();

        nouvelle_carte.ajout_hash_donnee(&enu_texte.hash_carte())?;

        let nouvelle_enu_racine_depot =
            Enu::new(nouvelle_carte, noyau, session, enu_racine_depot.braise())?;

        nouvelle_enu_racine_depot.sauvegarder(&self.chemin_enu)?;

        // remonte la nouvelle racine de dépôt jusqu'à la racine du nœud
        Enu::remplacer(
            &self.chemin_enu,
            &self.chemin_derniere_racine,
            &enu_racine_depot.hash_carte(),
            &nouvelle_enu_racine_depot,
            noyau,
            session,
        )?;

        Ok(())
    }

    /// Matérialise l'arborescence d'une `EnuR` dans un dossier OS, en lecture
    /// seule — opération inverse du dépôt par comptoir.
    ///
    /// Crée `chemin_retrait` (0o700) puis y reconstruit récursivement ce que
    /// décrit `enu_r` : chaque [`Carte::Donnee`] redevient un fichier (blob
    /// déchiffré via le noyau), chaque [`Carte::Texte`] un fichier portant son
    /// contenu embarqué, chaque [`Carte::Repertoire`] un sous-dossier. Chaque
    /// enfant est chargé **et authentifié** ([`Enu::charger`]) avant d'être
    /// écrit.
    ///
    /// **Lecture seule, sans reprise.** Contrairement au comptoir de dépôt,
    /// aucun état n'est retenu et aucune « fermeture » ne relira le dossier :
    /// Feu écrit puis s'en désintéresse — d'où une simple méthode, sans type
    /// comptoir dédié. Le dossier appartient ensuite à l'utilisateur.
    ///
    /// `enu_r` est traitée comme le dossier de sortie lui-même : son éventuel
    /// nom est ignoré, seuls ses enfants sont matérialisés — la récursion ne
    /// voit jamais la racine, qui peut donc être le sommet du nœud (sans méta
    /// `"nom"`).
    ///
    /// Tout foyer signataire d'une `Donnee` rencontrée doit être **ouvert**
    /// (déchiffrement du blob) ; naviguer les répertoires, eux, ne demande
    /// aucune ouverture.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] si `chemin_retrait` est un dossier
    /// existant (`SCR-002`) ou si `enu_r` n'est pas un répertoire (`SCR-003`).
    /// Propage les erreurs de la descente : authentification d'un enfant,
    /// nom absent ou invalide (`ENU-008`/`ENU-009`), braise inconnue
    /// (`SCR-004`), E/S et lecture de blob (foyer fermé, blob introuvable).
    pub(super) fn retrait_lecture_seule(
        &self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        chemin_retrait: &Path,
        enu_r: &Enu,
    ) -> ResultScribe<()> {
        if chemin_retrait.is_dir() {
            return Err(ErreurScribe::Interne(String::from(ERR_SCR_002)));
        }
        let Carte::Repertoire {
            metas: _,
            tags: _,
            hashs_enu,
        } = enu_r.carte()
        else {
            return Err(ErreurScribe::Interne(String::from(ERR_SCR_003)));
        };

        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(chemin_retrait)?;

        // la racine est le dossier de sortie : on matérialise ses enfants,
        // jamais elle — la récursion ne reçoit que des entrées nommées
        for h in hashs_enu {
            let enu = Enu::charger(&self.chemin_enu, session, h)?;
            self.retrait_lecture_seule_recursif(noyau, session, chemin_retrait, &enu)?;
        }

        Ok(())
    }

    /// Cœur récursif de [`Self::retrait_lecture_seule`] : matérialise **une**
    /// entrée nommée dans un dossier parent existant.
    ///
    /// Invariant d'entrée : `enu_courante` est un enfant — jamais la racine du
    /// retrait — et porte donc une méta `"nom"`, validée comme composant de
    /// chemin par [`Carte::nom_fichier`] avant tout `join`. Le chemin final
    /// passe par [`Self::chemin_libre`] : deux enfants homonymes d'un même
    /// répertoire coexistent par suffixage au lieu d'entrer en collision.
    ///
    /// Par variante :
    ///
    /// - [`Carte::Donnee`] — la braise résout l'`index_foyer` (elle seule en a
    ///   besoin), puis [`FeuNoyau::lecture_donnees`] retrouve le classeur du
    ///   blob, le déchiffre et écrit le clair directement dans le fichier de
    ///   sortie (0o600). Le `File` est consommé par l'appel — flush et
    ///   fermeture au drop, rien à reprendre ensuite.
    /// - [`Carte::Texte`] — le contenu embarqué est écrit tel quel, sans
    ///   passage par le noyau.
    /// - [`Carte::Repertoire`] — sous-dossier créé (0o700), puis récursion sur
    ///   chaque enfant chargé et authentifié.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurScribe::Interne`] si le nom est absent ou invalide
    /// (`ENU-008`/`ENU-009`) ou si la braise d'une `Donnee` est inconnue de la
    /// session (`SCR-004`). Propage les erreurs d'E/S, d'authentification d'un
    /// enfant ([`Enu::charger`]) et de lecture de blob — notamment foyer fermé
    /// ou blob introuvable.
    fn retrait_lecture_seule_recursif(
        &self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        chemin_courant: &Path,
        enu_courante: &Enu,
    ) -> ResultScribe<()> {
        // nom validé (anti-traversée) avant tout join, quelle que soit la variante
        let nom_fichier = enu_courante.carte().nom_fichier()?;

        match enu_courante.carte() {
            Carte::Donnee {
                metas: _,
                tags: _,
                hash_donnee,
            } => {
                // seule la lecture du blob exige un foyer : résolution ici,
                // pas en tête — un répertoire n'en a pas besoin
                let Some(index_foyer) = session.braise_vers_index(enu_courante.braise()) else {
                    return Err(ErreurScribe::Interne(String::from(ERR_SCR_004)));
                };

                let chemin = Self::chemin_libre(chemin_courant, &nom_fichier);

                let fichier = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&chemin)?;

                // le noyau écrit le clair directement dans le fichier, qui est
                // consommé — fermé au drop, aucun suivi ensuite
                noyau.lecture_donnees(index_foyer, &HEXLOWER.encode(hash_donnee), fichier)?;
            }
            Carte::Texte {
                metas: _,
                tags: _,
                contenu,
            } => {
                let chemin = Self::chemin_libre(chemin_courant, &nom_fichier);

                let mut fichier = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&chemin)?;

                // contenu en clair dans la carte : écriture directe, sans noyau
                fichier.write_all(contenu.as_bytes())?;
            }
            Carte::Repertoire {
                metas: _,
                tags: _,
                hashs_enu,
            } => {
                let chemin = Self::chemin_libre(chemin_courant, &nom_fichier);
                DirBuilder::new()
                    .mode(0o700)
                    .recursive(true)
                    .create(&chemin)?;

                for h in hashs_enu {
                    let enu = Enu::charger(&self.chemin_enu, session, h)?;
                    self.retrait_lecture_seule_recursif(noyau, session, &chemin, &enu)?;
                }
            }
        }
        Ok(())
    }

    /// Retourne un chemin encore libre pour `nom` dans `parent` : le chemin nu,
    /// ou suffixé `nom_1`, `nom_2`… si déjà pris.
    ///
    /// Deux enfants d'un même répertoire peuvent porter la même méta `"nom"`
    /// (les hashs sont uniques, pas les noms) : sans suffixage, le second
    /// fichier échouerait sur `create_new` et deux dossiers homonymes
    /// **fusionneraient silencieusement** (`DirBuilder` récursif ne signale pas
    /// l'existant). Le suffixe s'ajoute en fin de nom, après l'extension —
    /// simplicité assumée.
    ///
    /// Pas de course possible entre le test et la création : le retrait est la
    /// seule écriture dans ce dossier, qu'il vient de créer.
    fn chemin_libre(parent: &Path, nom: &str) -> PathBuf {
        let mut chemin_candidat = parent.join(nom);
        let mut i = 1;
        while chemin_candidat.exists() {
            chemin_candidat = parent.join(format!("{nom}_{i}"));
            i += 1;
        }

        chemin_candidat
    }
}
