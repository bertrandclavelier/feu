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
//!
//! Un nœud ne contient que deux sortes de fichiers : les ENU, tenues ici, et
//! les **blobs** — les contenus chiffrés rangés dans les classeurs des foyers.
//!
//! Le Scribe ne descend pas jusqu'au blob : trouver le `.dat` correspondant à un
//! `hash_blob`, le déchiffrer, le supprimer sont l'affaire du noyau. Il fait
//! la charnière — traduire une ENU en index de foyer et en empreinte de blob
//! (voir [`Scribe::index_et_hash_blob`]) — pour que ses appelants ne désignent
//! jamais une donnée autrement que par la [`Fiche`] de son ENU.

pub(crate) mod carte;
mod comptoirs;
mod configuration;
mod enu;
pub mod fiche;
pub mod iterateurs;
mod scribe_comptoirs;

#[cfg(test)]
mod tests;

use std::{
    fs::{DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use data_encoding::HEXLOWER;
use feu_noyau::{DonneesBlob, FeuNoyau};

use crate::{
    ErreurFeuApplication, ResultFeuApplication, SessionApplication,
    fiche::Fiche,
    scribe::{
        carte::Carte,
        comptoirs::{CLASSEUR_DEFAUT_COMPTOIR_TRAVAIL, ComptoirDepot, ComptoirTravail, Comptoirs},
        configuration::Configuration,
        enu::Enu,
        iterateurs::{Descendants, RacinesAnterieures},
    },
};

/// Version du format de `scribe.feu`, écrite en tête et relue au chargement.
const VERSION_CONFIGURATION: u32 = 1;

/// État des comptoirs du Scribe, dans `~/.feu/.config/`.
const SCRIBE_CONFIGURATION: &str = "scribe.feu";

/// Tenant de la couche ENU — créé et maintient `~/.feu/enu/`.
///
/// Activé à l'allumage du nœud, désactivé à l'extinction. Le dossier
/// `enu/` est créé avec les permissions `rwx------` (0o700), cohérent
/// avec le reste de `~/.feu/`.
pub(crate) struct Scribe {
    /// `true` si le Scribe a été activé (nœud allumé).
    ///
    /// Le Scribe est un champ plein, pas un `Option` : construit avant le noyau
    /// dont son amorce a besoin, il porte lui-même la marque de sa mise en
    /// service. Ne gouverne pas l'amorce, idempotente par l'existence de `enu/`.
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

    /// Chemin de `scribe.feu`, dérivé une fois à la construction comme les
    /// deux précédents. Le dossier `.config/` est celui du nœud, où
    /// `feu-noyau` pose déjà sa propre configuration.
    chemin_configuration: PathBuf,

    /// Comptoirs ouverts, dépôts et travail réunis sous un seul champ.
    ///
    /// Leur exclusivité tient au type et non à des gardes : [`Comptoirs`] ne sait
    /// pas représenter les deux sortes en même temps.
    comptoirs: Comptoirs,
}

impl Scribe {
    /// Construit un [`Scribe`] inactif.
    ///
    /// `chemin_feu` est le chemin racine du nœud (`~/.feu` en usage nominal),
    /// reçu de [`FeuApplication`](crate::FeuApplication). Le Scribe en dérive une fois pour toutes le
    /// chemin de son dossier `enu/` (`chemin_enu`) — aucune relecture de
    /// l'environnement à l'usage.
    pub(crate) fn new(chemin_feu: &Path) -> Self {
        Self {
            est_actif: false,
            chemin_enu: chemin_feu.join("enu/"),
            chemin_derniere_racine: chemin_feu.join("enu/").join(".DERNIERE_RACINE"),
            chemin_configuration: chemin_feu.join(".config/").join(SCRIBE_CONFIGURATION),
            comptoirs: Comptoirs::Vide,
        }
    }

    /// Indique si le Scribe est en service.
    ///
    /// Sert de précondition aux commandes qui ne dépendent que de lui.
    pub(crate) fn est_actif(&self) -> bool {
        self.est_actif
    }

    /// Charge le sommet courant en suivant `.DERNIERE_RACINE`.
    ///
    /// Le Scribe étant seul à connaître l'emplacement du lien, il est le seul à
    /// pouvoir le résoudre pour un appelant qui ne veut que l'ENU.
    ///
    /// # Errors
    ///
    /// Propage les erreurs de [`Enu::charger_derniere_racine`] : lien absent,
    /// lecture, authentification.
    pub(crate) fn derniere_enu_racine(
        &self,
        session: &SessionApplication,
    ) -> ResultFeuApplication<Enu> {
        Enu::charger_derniere_racine(&self.chemin_derniere_racine, session)
    }

    /// Charge l'ENU de `hash` et en rend la [`Fiche`] — `None` si aucun fichier
    /// ne lui correspond.
    ///
    /// L'existence est testée avant le chargement pour que l'absence ne se
    /// confonde pas avec un échec d'authentification : [`Enu::charger`] refuse
    /// de la même façon une ENU manquante et une ENU altérée, alors que les deux
    /// n'appellent pas la même réaction.
    ///
    /// La fenêtre entre le test et la lecture est assumée. Une ENU qui
    /// disparaîtrait entre les deux ressortirait en erreur d'E/S plutôt qu'en
    /// `None` — cas sans portée, aucun appelant de production ne supprime d'ENU.
    ///
    /// # Errors
    ///
    /// Propage les erreurs de [`Enu::charger`] : lecture, authentification.
    pub(crate) fn charge_enu(
        &self,
        session: &SessionApplication,
        hash: &[u8; 32],
    ) -> ResultFeuApplication<Option<Fiche>> {
        if !Enu::hash_carte_vers_chemin(hash, &self.chemin_enu).exists() {
            return Ok(None);
        }

        Ok(Some(Fiche::new(&Enu::charger(
            &self.chemin_enu,
            session,
            hash,
        )?)))
    }

    /// Traduit une ENU en ce que le noyau attend : l'index du foyer et
    /// l'empreinte du blob.
    ///
    /// Charnière entre deux ignorances : le Scribe ne sait pas ce qu'est un
    /// foyer, le noyau ne sait pas ce qu'est une ENU. D'où des appelants qui
    /// désignent une donnée par sa seule ENU, sans recomposer un couple
    /// foyer/hash qu'ils pourraient former incohérent.
    ///
    /// Facteur commun des quatre fonctions de blob. **Rien n'est authentifié
    /// ici** : les quatre rechargent l'ENU par [`Enu::charger`].
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeBraiseInconnue`] si la
    /// braise ne résout vers aucun foyer de la session, et
    /// [`ErreurFeuApplication::ScribeEnuDAttendue`] si la carte n'est pas une
    /// [`Carte::Donnee`] et ne référence donc aucun blob.
    fn index_et_hash_blob(
        &self,
        session: &SessionApplication,
        enu: &Enu,
    ) -> ResultFeuApplication<(usize, [u8; 32])> {
        let Some(index) = session.braise_vers_index(enu.braise()) else {
            return Err(ErreurFeuApplication::ScribeBraiseInconnue);
        };

        let Carte::Donnee {
            metas: _,
            tags: _,
            hash_blob,
        } = enu.carte()
        else {
            return Err(ErreurFeuApplication::ScribeEnuDAttendue);
        };

        Ok((index, *hash_blob))
    }

    /// Déchiffre le blob référencé par `fiche` et écrit le clair dans
    /// `destination`.
    ///
    /// Le Scribe ne sait pas déchiffrer, c'est l'affaire du noyau : il ne fait
    /// ici que résoudre la cible par [`index_et_hash_blob`](Self::index_et_hash_blob),
    /// puis passer la main. Le hash lui est transmis en hexadécimal, forme sous
    /// laquelle le noyau nomme ses blobs.
    ///
    /// # Errors
    ///
    /// Propage les refus du chargement de l'ENU (lecture, authentification) et
    /// les deux de [`index_et_hash_blob`](Self::index_et_hash_blob), puis les erreurs du
    /// noyau : foyer fermé, blob introuvable, déchiffrement, donnée corrompue.
    pub(crate) fn charge_blob(
        &self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        fiche: &Fiche,
        destination: impl Write,
    ) -> ResultFeuApplication<()> {
        let (index, hash_blobs) = self.index_et_hash_blob(
            session,
            &Enu::charger(&self.chemin_enu, session, &fiche.hash_carte())?,
        )?;

        noyau.lecture_blob(index, &HEXLOWER.encode(&hash_blobs), destination)?;

        Ok(())
    }

    /// Supprime le blob référencé par `fiche`, sans toucher à l'ENU.
    ///
    /// Jumelle de [`charge_blob`](Self::charge_blob) : même résolution de
    /// cible, seul l'appel noyau qui suit diffère.
    ///
    /// L'ENU survit à son blob. Rien ici ne la retire de l'arborescence, où elle
    /// continue de référencer un fichier absent.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeComptoirTravailOuvert`] si le
    /// comptoir de travail est ouvert — rien n'est supprimé. Propage ensuite les
    /// refus du chargement de l'ENU (lecture, authentification) et les deux de
    /// [`index_et_hash_blob`](Self::index_et_hash_blob), puis les erreurs du
    /// noyau : foyer fermé, blob introuvable, suppression disque.
    pub(crate) fn supprime_blob(
        &self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        fiche: &Fiche,
    ) -> ResultFeuApplication<()> {
        if matches!(self.comptoirs, Comptoirs::Travail(_)) {
            return Err(ErreurFeuApplication::ScribeComptoirTravailOuvert);
        }
        let (index, hash_blobs) = self.index_et_hash_blob(
            session,
            &Enu::charger(&self.chemin_enu, session, &fiche.hash_carte())?,
        )?;

        noyau.suppression_blob(index, &HEXLOWER.encode(&hash_blobs))?;

        Ok(())
    }

    /// Indique si le blob référencé par `fiche` est présent dans son foyer.
    ///
    /// Même résolution de cible que [`charge_blob`](Self::charge_blob), sans
    /// rien ouvrir : la question porte sur la présence du `.dat`, pas sur son
    /// contenu. Une ENU peut survivre à son blob (voir
    /// [`supprime_blob`](Self::supprime_blob)) — c'est ce que cette méthode
    /// permet de détecter.
    ///
    /// # Errors
    ///
    /// Propage les refus du chargement de l'ENU (lecture, authentification) et
    /// les deux de [`index_et_hash_blob`](Self::index_et_hash_blob), puis les erreurs du
    /// noyau : foyer fermé. Un blob absent est un `Ok(false)`.
    pub(crate) fn existence_blob(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        fiche: &Fiche,
    ) -> ResultFeuApplication<bool> {
        let (index, hash_blobs) = self.index_et_hash_blob(
            session,
            &Enu::charger(&self.chemin_enu, session, &fiche.hash_carte())?,
        )?;

        Ok(noyau.existence_blob(index, &HEXLOWER.encode(&hash_blobs))?)
    }

    /// Retourne les métadonnées système du blob référencé par `fiche` — taille,
    /// dates.
    ///
    /// Renseigne sur le fichier, jamais sur son contenu : rien n'est déchiffré.
    ///
    /// # Errors
    ///
    /// Propage les refus du chargement de l'ENU (lecture, authentification) et
    /// les deux de [`index_et_hash_blob`](Self::index_et_hash_blob), puis les erreurs du
    /// noyau : foyer fermé, blob introuvable — ici une erreur, contrairement à
    /// [`existence_blob`](Self::existence_blob).
    pub(crate) fn informations_blob(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        fiche: &Fiche,
    ) -> ResultFeuApplication<DonneesBlob> {
        let (index, hash_blobs) = self.index_et_hash_blob(
            session,
            &Enu::charger(&self.chemin_enu, session, &fiche.hash_carte())?,
        )?;

        Ok(noyau.informations_blob(index, &HEXLOWER.encode(&hash_blobs))?)
    }

    /// Active le Scribe : amorce l'arborescence au tout premier allumage, puis
    /// rouvre les comptoirs laissés par l'allumage précédent.
    ///
    /// `enu/` absent signifie tout premier allumage : le dossier est créé en
    /// `0o700` et la **racine origine** — répertoire vide signé par le nœud — est
    /// posée en sommet courant. Le noyau est requis pour cette signature de
    /// genèse, la session seulement transmise. Ensuite, l'amorce est sautée.
    ///
    /// `scribe.feu` présent, les comptoirs y sont relus : le Scribe les reprend
    /// et la session en reçoit le miroir. Rien d'autre n'est à restaurer, les
    /// identifiants se déduisant des comptoirs eux-mêmes.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si la création du dossier, la signature de la racine
    /// origine, sa sauvegarde ou la pose du symlink échoue, et propage celles de
    /// [`Configuration::charger`] comme de [`Configuration::vers_comptoirs`] —
    /// relecture de la racine sortie, et refus d'un `scribe.feu` portant des
    /// dépôts et un travail à la fois. Le Scribe reste alors inactif : le
    /// drapeau n'est posé qu'en sortie réussie.
    pub(crate) fn activation(
        &mut self,
        feu_noyau: &FeuNoyau,
        session: &mut SessionApplication,
    ) -> ResultFeuApplication<()> {
        if !&self.chemin_enu.exists() {
            Self::creer_dossier_700(&self.chemin_enu)?;

            Enu::new_racine(
                feu_noyau,
                session,
                &self.chemin_enu,
                &self.chemin_derniere_racine,
                None,
            )?;
        }

        if self.chemin_configuration.exists() {
            let configuration = Configuration::charger(&self.chemin_configuration)?;

            self.comptoirs = configuration.vers_comptoirs(&self.chemin_enu)?;

            match &self.comptoirs {
                Comptoirs::Vide => {}

                Comptoirs::Depot(comptoirs_depot) => {
                    for (index, comptoir) in comptoirs_depot {
                        session.mut_comptoirs_depot_ouverts().insert(
                            *index,
                            (
                                comptoir.chemin().clone(),
                                comptoir.index_foyer(),
                                comptoir.index_classeur(),
                            ),
                        );
                    }
                }

                Comptoirs::Travail(comptoir_travail) => {
                    session.definit_comptoir_travail_ouvert(
                        comptoir_travail.chemin().clone(),
                        comptoir_travail.fiche_racine(),
                    );
                }
            }
        }

        self.est_actif = true;

        Ok(())
    }

    /// Écrit l'état courant des comptoirs dans `scribe.feu`.
    ///
    /// Appelée à chaque ouverture et à chaque fermeture de comptoir, une fois le
    /// Scribe et le miroir de session à jour : le fichier suit la mémoire,
    /// jamais l'inverse.
    ///
    /// # Errors
    ///
    /// Propage les erreurs de [`Configuration::sauvegarder`] : dossier
    /// `.config/` absent, écriture ou renommage refusés.
    fn sauvegarder_configuration(&self) -> ResultFeuApplication<()> {
        let configuration = Configuration::new(self);
        configuration.sauvegarder(&self.chemin_configuration)?;

        Ok(())
    }

    /// Désactive le Scribe et oublie les comptoirs ouverts, dépôts et travail.
    ///
    /// Appelé par [`commande_extinction_noeud`](crate::FeuApplication::commande_extinction_noeud).
    /// Ne supprime rien sur le disque : ni `enu/`, dont les ENU survivent à
    /// l'extinction, ni les dossiers des comptoirs, qui portent des fichiers de
    /// l'utilisateur jamais ingérés. `scribe.feu` n'est pas réécrit non plus :
    /// la prochaine activation y retrouve les comptoirs et les rouvre.
    pub(crate) fn desactivation(&mut self) {
        self.est_actif = false;
        self.comptoirs = Comptoirs::Vide;
    }

    /// Dépose un texte dans un foyer en l'accrochant sous `enu_racine_depot`,
    /// puis propage la nouvelle racine de dépôt jusqu'à la racine du nœud.
    ///
    /// Variante allégée de [`Self::fermeture_comptoir_depot`] : ni comptoir, ni
    /// blob, ni classeur. Le texte est embarqué dans une [`Carte::Texte`], bornée
    /// et nommée, mise sous enveloppe signée, sauvegardée puis greffée.
    ///
    /// Seule voie possible pour une `EnuT` : un texte n'existe pas comme fichier,
    /// il ne peut donc pas passer par un comptoir.
    ///
    /// La signature se fait sous la braise d'`index_foyer`, pas sous celle du
    /// répertoire d'accueil : ce foyer-là doit être ouvert en plus de ceux
    /// qu'exige la greffe.
    ///
    /// # Retour
    ///
    /// Rien : le nouveau sommet du nœud est signé, sauvegardé et devient la
    /// cible de `.DERNIERE_RACINE` ; l'appelant qui en a besoin le relit via
    /// [`Enu::charger_derniere_racine`].
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeComptoirTravailOuvert`] si le
    /// comptoir de travail est ouvert : il verrouille l'arborescence, et le refus
    /// tombe avant toute écriture. Propage ensuite
    /// [`ErreurFeuApplication::ScribeTailleMaxDepasseeTexte`] si le
    /// texte dépasse `MAX_TAILLE_TEXTE`, ou
    /// [`ErreurFeuApplication::ScribeNomFichierInvalide`] si `nom` est refusé
    /// comme composant de chemin — les deux via [`Carte::new_texte`] —, ou
    /// [`ErreurFeuApplication::ScribeEnuRAttendue`] si `fiche_racine_depot` ne
    /// désigne pas un répertoire (via `ajout_hash_enu`), ou
    /// [`ErreurFeuApplication::ScribeIndexFoyerInvalide`] si `index_foyer` sort
    /// des bornes. Propage toute erreur d'E/S, d'authentification ou de
    /// signature — notamment si un foyer du chemin reconstruit est fermé.
    pub(crate) fn depot_enu_texte(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        fiche_racine_depot: &Fiche,
        index_foyer: usize,
        nom: &str,
        contenu: &str,
    ) -> ResultFeuApplication<()> {
        if matches!(self.comptoirs, Comptoirs::Travail(_)) {
            return Err(ErreurFeuApplication::ScribeComptoirTravailOuvert);
        }
        let Some(braise) = session.braise_foyer(index_foyer) else {
            return Err(ErreurFeuApplication::ScribeIndexFoyerInvalide(index_foyer));
        };

        let enu_racine_depot =
            Enu::charger(&self.chemin_enu, session, &fiche_racine_depot.hash_carte())?;

        let enu_texte = Enu::new(Carte::new_texte(nom, contenu)?, noyau, session, braise)?;

        enu_texte.sauvegarder(&self.chemin_enu)?;

        self.greffe_enfants(noyau, session, &enu_racine_depot, &[enu_texte.hash_carte()])?;

        Ok(())
    }

    /// Fabrique un parcours descendant à partir de `hash_carte`.
    ///
    /// Le Scribe est seul à connaître `chemin_enu` et ne le laisse pas sortir :
    /// il fournit l'itérateur déjà armé plutôt qu'un accesseur au chemin, comme
    /// il le fait déjà pour [`Self::charge_enu`]. L'emplacement du dépôt sur le
    /// disque reste un détail interne.
    ///
    /// Aucune lecture disque ici — le premier chargement n'a lieu qu'au premier
    /// `next`. Aucune session non plus : le descendant ne vérifie pas la
    /// signature du point de départ, ce qui lui permet de parcourir un arbre dont
    /// le foyer est fermé.
    pub(crate) fn donne_descendants<'a>(&'a self, hash_carte: &[u8; 32]) -> Descendants<'a> {
        Descendants::new(&self.chemin_enu, hash_carte)
    }

    /// Fabrique un parcours remontant à partir de `hash_carte`.
    ///
    /// Même raison d'être que [`Self::donne_descendants`] : le Scribe arme
    /// l'itérateur plutôt que de laisser sortir `chemin_enu`. Infaillible comme
    /// lui — [`RacinesAnterieures`] ne vérifie rien à la construction, chaque
    /// racine étant authentifiée au moment où elle est chargée.
    pub(crate) fn donne_racines_anterieures<'a>(
        &'a self,
        session: &'a SessionApplication,
        hash_carte: &[u8; 32],
    ) -> RacinesAnterieures<'a> {
        RacinesAnterieures::new(&self.chemin_enu, session, hash_carte)
    }

    /// Crée `path` et ses parents manquants en `rwx------` (0o700).
    ///
    /// Recopiée de `feu-noyau` plutôt que partagée : deux appelants ne valent
    /// pas une crate commune, et un test relit les permissions de chaque côté.
    ///
    /// # Errors
    ///
    /// Propage [`ErreurFeuApplication::IoError`] si la création échoue.
    pub(crate) fn creer_dossier_700(path: &Path) -> ResultFeuApplication<()> {
        DirBuilder::new().mode(0o700).recursive(true).create(path)?;
        Ok(())
    }

    /// Écrit `contenu` dans `chemin` en `rw-------` (0o600).
    ///
    /// Passe par `<chemin>.tmp` puis renomme : le renommage est atomique sur
    /// Unix et écrase la cible, donc jamais de fichier à moitié écrit. Un `.tmp`
    /// laissé par un arrêt brutal est retiré d'abord, sans quoi `create_new`
    /// refuserait toute sauvegarde ultérieure.
    ///
    /// Recopiée de `feu-noyau`, comme [`Self::creer_dossier_700`].
    ///
    /// # Errors
    ///
    /// Propage [`ErreurFeuApplication::IoError`] si l'écriture du fichier
    /// temporaire échoue ou si le renommage vers la cible échoue.
    pub(crate) fn ecrire_fichier_600(chemin: &Path, contenu: &[u8]) -> ResultFeuApplication<()> {
        let nouveau_chemin = chemin.with_added_extension("tmp");

        let _ = std::fs::remove_file(&nouveau_chemin); // résidu d'un crash précédent

        let mut fichier = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&nouveau_chemin)?;

        fichier.write_all(contenu)?;

        std::fs::rename(&nouveau_chemin, chemin)?; // rename écrase l'ancien fichier

        Ok(())
    }
}
