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
//! `hash_donnee`, le déchiffrer, le supprimer sont l'affaire du noyau. Il fait
//! la charnière — traduire une ENU en index de foyer et en empreinte de blob
//! (voir [`Scribe::index_et_hash_blob`]) — pour que ses appelants ne désignent
//! jamais une donnée autrement que par la [`Fiche`] de son ENU.

pub(crate) mod carte;
mod comptoir;
mod configuration;
mod enu;
pub mod fiche;
pub mod iterateurs;

#[cfg(test)]
mod tests;

use data_encoding::HEXLOWER;
use std::{
    collections::{BTreeSet, HashMap},
    fs::{DirBuilder, OpenOptions, read, read_dir},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use feu_noyau::{BRAISE_VIDE, DonneesBlob, FeuNoyau, MAX_CLASSEURS, MAX_FOYERS};
use walkdir::WalkDir;

use crate::{
    ErreurFeuApplication, ResultFeuApplication, SessionApplication,
    fiche::Fiche,
    scribe::{
        carte::Carte,
        comptoir::{ComptoirDepot, ComptoirTravail, Comptoirs},
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
pub(super) struct Scribe {
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
    pub(super) fn new(chemin_feu: &Path) -> Self {
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
    pub(super) fn est_actif(&self) -> bool {
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
    pub(super) fn derniere_enu_racine(
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
    pub(super) fn charge_enu(
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
            hash_donnee,
        } = enu.carte()
        else {
            return Err(ErreurFeuApplication::ScribeEnuDAttendue);
        };

        Ok((index, *hash_donnee))
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
    pub(super) fn charge_blob(
        &self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        fiche: &Fiche,
        destination: impl Write,
    ) -> ResultFeuApplication<()> {
        let (index, hash_donnees) = self.index_et_hash_blob(
            session,
            &Enu::charger(&self.chemin_enu, session, &fiche.hash_carte())?,
        )?;

        noyau.lecture_blob(index, &HEXLOWER.encode(&hash_donnees), destination)?;

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
    pub(super) fn supprime_blob(
        &self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        fiche: &Fiche,
    ) -> ResultFeuApplication<()> {
        if matches!(self.comptoirs, Comptoirs::Travail(_)) {
            return Err(ErreurFeuApplication::ScribeComptoirTravailOuvert);
        }
        let (index, hash_donnees) = self.index_et_hash_blob(
            session,
            &Enu::charger(&self.chemin_enu, session, &fiche.hash_carte())?,
        )?;

        noyau.suppression_blob(index, &HEXLOWER.encode(&hash_donnees))?;

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
    pub(super) fn existence_blob(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        fiche: &Fiche,
    ) -> ResultFeuApplication<bool> {
        let (index, hash_donnees) = self.index_et_hash_blob(
            session,
            &Enu::charger(&self.chemin_enu, session, &fiche.hash_carte())?,
        )?;

        Ok(noyau.existence_blob(index, &HEXLOWER.encode(&hash_donnees))?)
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
    pub(super) fn informations_blob(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        fiche: &Fiche,
    ) -> ResultFeuApplication<DonneesBlob> {
        let (index, hash_donnees) = self.index_et_hash_blob(
            session,
            &Enu::charger(&self.chemin_enu, session, &fiche.hash_carte())?,
        )?;

        Ok(noyau.informations_blob(index, &HEXLOWER.encode(&hash_donnees))?)
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
    pub(super) fn activation(
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
    pub(super) fn desactivation(&mut self) {
        self.est_actif = false;
        self.comptoirs = Comptoirs::Vide;
    }

    /// Ouvre un comptoir de dépôt au chemin donné.
    ///
    /// Crée le dossier, l'enregistre dans [`Comptoirs`] et rend son identifiant.
    /// Les deux index sont validés ici contre des bornes de compilation : le
    /// comptoir les porte ensuite jusqu'à sa fermeture, qui n'a plus à en douter.
    ///
    /// `session` est mutable pour recevoir le même identifiant à la ligne
    /// suivante, avec sa destination : le Scribe tient les comptoirs, la session
    /// les rend lisibles hors de la crate, et les deux se remplissent donc ici.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeComptoirTravailOuvert`] si le
    /// comptoir de travail est ouvert, qui leur est exclusif. Retourne
    /// [`ErreurFeuApplication::ScribeIndexFoyerInvalide`] ou
    /// [`ErreurFeuApplication::ScribeIndexClasseurInvalide`] si l'index sort des
    /// bornes, et propage l'échec de création du dossier — notamment s'il existe
    /// déjà — comme celui de [`Self::sauvegarder_configuration`], qui survient
    /// le comptoir déjà ouvert et inscrit.
    pub(super) fn ouverture_comptoir_depot(
        &mut self,
        session: &mut SessionApplication,
        chemin: &Path,
        index_foyer: usize,
        index_classeur: usize,
    ) -> ResultFeuApplication<usize> {
        if matches!(self.comptoirs, Comptoirs::Travail(_)) {
            return Err(ErreurFeuApplication::ScribeComptoirTravailOuvert);
        }
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuApplication::ScribeIndexFoyerInvalide(index_foyer));
        }
        if index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeuApplication::ScribeIndexClasseurInvalide(
                index_classeur,
            ));
        }

        let comptoir = ComptoirDepot::new(chemin.to_path_buf(), index_foyer, index_classeur);
        // ouvert avant d'être gardé : un comptoir enregistré mais sans dossier
        // distribuerait un identifiant que la fermeture ne saurait pas honorer
        comptoir.ouvrir()?;

        let index_comptoir = self.comptoirs.ajouter_comptoir_depot(comptoir)?;

        session.mut_comptoirs_depot_ouverts().insert(
            index_comptoir,
            (chemin.to_path_buf(), index_foyer, index_classeur),
        );

        self.sauvegarder_configuration()?;

        Ok(index_comptoir)
    }

    /// Ouvre le comptoir de travail : sort le sous-arbre de `fiche_racine` dans
    /// `chemin`, puis retient l'un et l'autre.
    ///
    /// La sortie est celle de [`Self::retrait_lecture_seule`], gardes comprises.
    /// Les deux exclusivités se vérifient avant elle, donc avant toute écriture.
    ///
    /// **L'enregistrement clôt l'ouverture, il ne l'amorce pas** : un comptoir
    /// inscrit sur une sortie interrompue ferait passer les fichiers manquants
    /// pour des suppressions voulues, là où un dossier à demi sorti n'est rien.
    ///
    /// `session` est mutable pour recevoir le miroir du comptoir, comme à
    /// l'ouverture d'un dépôt.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeComptoirDepotOuvert`] si un dépôt
    /// est ouvert, [`ErreurFeuApplication::ScribeComptoirTravailOuvert`] si un
    /// comptoir de travail l'est déjà — rien n'est écrit dans les deux cas. Puis
    /// propage les erreurs du retrait : foyers requis fermés, dossier de sortie
    /// déjà existant, `fiche_racine` qui n'est pas un répertoire, nom absent ou
    /// invalide, authentification, E/S et lecture de blob. Puis l'échec de
    /// [`Self::sauvegarder_configuration`], le comptoir déjà inscrit.
    pub(super) fn ouverture_comptoir_travail(
        &mut self,
        noyau: &mut FeuNoyau,
        session: &mut SessionApplication,
        chemin: &Path,
        fiche_racine: &Fiche,
    ) -> ResultFeuApplication<()> {
        if matches!(self.comptoirs, Comptoirs::Depot(_)) {
            return Err(ErreurFeuApplication::ScribeComptoirDepotOuvert);
        }
        if matches!(self.comptoirs, Comptoirs::Travail(_)) {
            return Err(ErreurFeuApplication::ScribeComptoirTravailOuvert);
        }

        self.retrait_lecture_seule(noyau, session, chemin, fiche_racine)?;

        self.comptoirs
            .ajouter_comptoir_travail(ComptoirTravail::new(
                chemin.to_path_buf(),
                fiche_racine.clone(),
            ))?;

        session.definit_comptoir_travail_ouvert(chemin.to_path_buf(), fiche_racine.clone());

        self.sauvegarder_configuration()?;

        Ok(())
    }

    /// Ferme un comptoir de dépôt : greffe son contenu sous `enu_racine_depot`,
    /// puis propage la nouvelle racine de dépôt jusqu'à la racine du nœud.
    ///
    /// Parcourt le dossier en bottom-up : chaque fichier devient un blob puis une
    /// ENU signée, chaque répertoire une [`Carte::Repertoire`]. Le dossier est
    /// ensuite supprimé ; un comptoir vide ne greffe rien.
    ///
    /// **Le classeur demandé n'est pas garanti, et l'écart n'est remonté nulle
    /// part** : une donnée déjà présente ailleurs dans le foyer y reste.
    ///
    /// Le comptoir quitte le Scribe puis la session dès les gardes passées — d'où
    /// le `&mut` sur un paramètre que le reste ne fait que lire. Les deux retraits
    /// sont collés : une garde glissée entre eux rendrait la session menteuse.
    ///
    /// # Retour
    ///
    /// Rien : le nouveau sommet du nœud est signé, sauvegardé et devient la
    /// cible de `.DERNIERE_RACINE`. Un comptoir vide laisse la racine courante
    /// inchangée. L'appelant qui a besoin de la racine à jour la relit via
    /// [`Enu::charger_derniere_racine`].
    ///
    /// # Errors
    ///
    /// Quatre refus, dont deux laissent une seconde chance :
    /// [`ErreurFeuApplication::ScribeEnuRAttendue`], racine de dépôt qui n'est
    /// pas un répertoire — greffer des enfants sous une donnée n'a pas de sens,
    /// et le refus tombe avant tout dépôt de blob, donc l'utilisateur en désigne
    /// une autre et retente. [`ErreurFeuApplication::ScribeFoyerFerme`], levée
    /// pour **deux foyers distincts** : celui du comptoir, qui reçoit les blobs,
    /// et celui de la racine de dépôt, qui signe la greffe — l'un peut être
    /// ouvert sans l'autre. Le second est sauté quand la racine de dépôt est
    /// celle du nœud, signée nœud et sans foyer : sa braise ne désigne alors
    /// rien. Ces refus laissent le comptoir enregistré, la fermeture se retente
    /// une fois le ou les foyers rouverts.
    /// [`ErreurFeuApplication::ScribeIndexFoyerInvalide`] sort au même endroit,
    /// mais ne couvre ici que le `None` de
    /// [`SessionApplication::braise_foyer`], que la validation d'index à
    /// l'ouverture rend inatteignable.
    ///
    /// Les deux autres sont sans retour :
    /// [`ErreurFeuApplication::ScribeIndexComptoirInconnu`], et
    /// [`ErreurFeuApplication::ScribeDossierDepotIntrouvable`], constaté après
    /// le retrait — il n'y a plus de comptoir à refermer.
    ///
    /// Propage ensuite toute erreur d'E/S, de dépôt de données ou de signature —
    /// y compris l'échec de signature si un foyer du chemin reconstruit par
    /// [`Enu::remplacer`] est fermé. Elles surviennent toutes après le retrait :
    /// le dossier reste sur le disque avec ce qui n'a pas été ingéré, à
    /// l'utilisateur de le reprendre. `scribe.feu`, réécrit en sortie réussie
    /// seulement, y garde alors le comptoir : la prochaine activation le rouvre
    /// sur ce dossier.
    pub(super) fn fermeture_comptoir_depot(
        &mut self,
        noyau: &mut FeuNoyau,
        session: &mut SessionApplication,
        index_comptoir: usize,
        fiche_racine_depot: &Fiche,
    ) -> ResultFeuApplication<()> {
        let enu_racine_depot =
            Enu::charger(&self.chemin_enu, session, &fiche_racine_depot.hash_carte())?;

        if !matches!(enu_racine_depot.carte(), Carte::Repertoire { .. }) {
            return Err(ErreurFeuApplication::ScribeEnuRAttendue);
        }

        let comptoir = self.comptoirs.donne_comptoir_depot(index_comptoir)?;

        let Some(braise) = session.braise_foyer(comptoir.index_foyer()) else {
            return Err(ErreurFeuApplication::ScribeIndexFoyerInvalide(
                comptoir.index_foyer(),
            ));
        };

        if !session.etat_foyers()[comptoir.index_foyer()] {
            return Err(ErreurFeuApplication::ScribeFoyerFerme(
                comptoir.index_foyer(),
            ));
        }

        if let Some(index) = session.braise_vers_index(enu_racine_depot.braise())
            && !session.etat_foyers()[index]
        {
            return Err(ErreurFeuApplication::ScribeFoyerFerme(index));
        }

        let comptoir = self.comptoirs.retirer_comptoir_depot(index_comptoir)?;

        session
            .mut_comptoirs_depot_ouverts()
            .remove(&index_comptoir);

        if !comptoir.chemin().exists() {
            return Err(ErreurFeuApplication::ScribeDossierDepotIntrouvable(
                comptoir.chemin().clone(),
            ));
        }

        let dir = read_dir(comptoir.chemin())?;
        if dir.count() == 0 {
            // comptoir vide : rien à greffer, le nœud est inchangé
            comptoir.supprimer()?;

            self.sauvegarder_configuration()?;

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

                let (hash_fichier, _) = noyau.depot_blob(
                    comptoir.index_foyer(),
                    comptoir.index_classeur(),
                    &contenu[..],
                )?;

                // le noyau nomme ses blobs par l'hexadécimal d'un SHA3-256 :
                // 32 octets une fois décodés, la conversion ne peut pas échouer
                let hash_fichier: [u8; 32] = HEXLOWER
                    .decode(hash_fichier.as_bytes())?
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

        self.greffe_enfants(noyau, session, &enu_racine_depot, &nouveaux_enfants)?;

        comptoir.supprimer()?;

        self.sauvegarder_configuration()?;

        Ok(())
    }

    /// Accroche des ENU déjà signées sous `enu_racine_depot`, puis remonte
    /// jusqu'à un nouveau sommet du nœud.
    ///
    /// **Point de passage unique de tout dépôt**, comptoir comme ENU isolée. Les
    /// enfants arrivent signés et sauvegardés ; seuls l'accueil et ce qui le
    /// surplombe sont touchés ici, et tout foyer du chemin doit être ouvert.
    ///
    /// # Les deux voies
    ///
    /// L'accueil décide, et lui seul, qui signe le sommet :
    ///
    /// - **racine du nœud**, reconnue à sa braise vide — [`Enu::new_racine`]
    ///   forge directement la version suivante, signée *nœud* ;
    /// - **répertoire de foyer** — [`Enu::new`] le re-signe sous sa braise, puis
    ///   [`Enu::remplacer`] le substitue dans l'arbre et remonte jusqu'à un
    ///   `new_racine`.
    ///
    /// Dans les deux cas l'accueil doit appartenir à l'arbre courant : une racine
    /// périmée ou un répertoire qui n'y est plus sont refusés.
    ///
    /// # Greffe sans effet
    ///
    /// Si la carte augmentée égale celle de départ, la méthode rend `Ok(())`
    /// sans rien forger : les hashs étaient tous déjà présents — la carte est un
    /// ensemble — ou la liste était vide. Produire une version pour un contenu
    /// identique n'ajouterait qu'un maillon mort à la lignée des `_racine`. Le
    /// cas se présente réellement lorsqu'un même fichier est redéposé par le
    /// comptoir : contenu et nom inchangés donnent la même carte, donc le même
    /// `hash_carte` — écarté d'entrée, sans quoi son nom entrerait en collision
    /// avec lui-même et le ferait renommer.
    ///
    /// L'appelant ne peut pas distinguer ce cas d'une greffe effective. Aucun
    /// n'en a besoin aujourd'hui ; le jour où l'un d'eux le demandera, ce sera
    /// au type de retour de le dire.
    ///
    /// # Invariants
    ///
    /// **Deux enfants d'un même répertoire ne portent jamais le même nom.** La
    /// garantie tient ici, seul endroit où une ENU devient enfant : un nouveau
    /// venu dont le nom est déjà pris est greffé sous une copie renommée
    /// ([`Self::nom_libre`]), l'occupant restant intact — son foyer peut être
    /// fermé, et l'original devient orphelin comme toute version remplacée. Plus
    /// bas dans l'arbre, l'unicité vient du système de fichiers qui a nommé le
    /// comptoir. Toute ENU a donc un chemin unique, ce dont dépend
    /// [`Self::retrait_lecture_seule_recursif`].
    ///
    /// Un enfant sans nom est refusé plutôt que greffé en silence : aucune voie
    /// de dépôt n'en produit, mais le refus rappelle l'obligation à qui forge une
    /// ENU à la main.
    ///
    /// Cette méthode intervient **en fin de chaîne** — les blobs sont déposés,
    /// les ENU signées et sauvegardées. Refuser à ce stade invaliderait un
    /// travail déjà accompli sans moyen de le défaire ; elle absorbe donc les
    /// cas dégénérés au lieu de les rejeter — sauf l'accueil sorti de l'arbre
    /// courant, dont la greffe ampute l'arbre ou n'ajoute qu'un maillon mort :
    /// quelques ENU orphelines coûtent moins cher. Les appelants gardent en
    /// amont :
    /// [`Self::fermeture_comptoir_depot`] sort avant l'appel si le comptoir est
    /// vide, [`Self::depot_enu_texte`] passe toujours exactement un hash.
    ///
    /// Seul le verrou du comptoir de travail y refuse : toute greffe passe par
    /// ici, c'est donc le filet des voies qui n'auraient pas gardé en amont.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeComptoirTravailOuvert`] si le
    /// comptoir de travail est ouvert. Retourne
    /// [`ErreurFeuApplication::ScribeEnuRAttendue`] si
    /// `enu_racine_depot` n'est pas un répertoire, et
    /// [`ErreurFeuApplication::ScribeRacinePerimee`] si c'est une racine qui
    /// n'est plus la dernière, ou
    /// [`ErreurFeuApplication::ScribeRemplacementSansEffet`] si c'est un
    /// répertoire absent de l'arbre courant. Retourne
    /// [`ErreurFeuApplication::ScribeMetaNomAbsente`] ou
    /// [`ErreurFeuApplication::ScribeNomFichierInvalide`] si un enfant, en place
    /// ou greffé, n'a pas de nom exploitable. Propage toute erreur d'E/S,
    /// d'authentification ou de signature — notamment un foyer fermé sur le
    /// chemin remonté.
    fn greffe_enfants(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        enu_racine_depot: &Enu,
        hashs_nouveaux_enfants: &[[u8; 32]],
    ) -> ResultFeuApplication<()> {
        if matches!(self.comptoirs, Comptoirs::Travail(_)) {
            return Err(ErreurFeuApplication::ScribeComptoirTravailOuvert);
        }

        let mut nouvelle_carte = enu_racine_depot.carte().clone();

        // les noms déjà portés par les enfants de l'accueil, seuls à pouvoir
        // entrer en collision avec un nouveau venu
        let mut nom_enfants = BTreeSet::new();
        for h in enu_racine_depot.carte().hashs_enu().into_iter().flatten() {
            let enu = Enu::charger_sans_verification_signature(&self.chemin_enu, h)?;
            nom_enfants.insert(enu.carte().nom_fichier()?);
        }

        for h in hashs_nouveaux_enfants {
            // une ENU déjà enfant entrerait en collision avec son propre nom :
            // l'écarter ici garde le redépôt à l'identique sans effet
            if enu_racine_depot
                .carte()
                .hashs_enu()
                .is_some_and(|h_enu| h_enu.contains(h))
            {
                continue;
            }

            let enu = Enu::charger_sans_verification_signature(&self.chemin_enu, h)?;
            let nom = enu.carte().nom_fichier()?;

            // nom libre : l'ENU se greffe telle quelle. Sinon c'est une copie
            // renommée qui se greffe, l'occupant n'étant jamais touché.
            if nom_enfants.insert(nom.clone()) {
                nouvelle_carte.ajout_hash_enu(h)?;
            } else {
                let nom = Self::nom_libre(&nom_enfants, &nom);
                let enu_renommee = enu.renommer(&nom, noyau, session)?;
                enu_renommee.sauvegarder(&self.chemin_enu)?;
                nom_enfants.insert(nom);
                nouvelle_carte.ajout_hash_enu(&enu_renommee.hash_carte())?;
            }
        }

        // Si contenu identique
        if nouvelle_carte == *enu_racine_depot.carte() {
            return Ok(());
        }

        // Si dépôt à la racine — seule une racine du nœud porte BRAISE_VIDE
        if enu_racine_depot.braise() == BRAISE_VIDE {
            // Si la racine est périmée — repartir d'une ancienne amputerait
            // l'arbre de tout ce qui a été déposé depuis
            let derniere_racine = self.derniere_enu_racine(session)?;
            if enu_racine_depot.hash_carte() != derniere_racine.hash_carte() {
                return Err(ErreurFeuApplication::ScribeRacinePerimee);
            }
            Enu::new_racine(
                noyau,
                session,
                &self.chemin_enu,
                &self.chemin_derniere_racine,
                Some(nouvelle_carte),
            )?;
        } else {
            // Si dépôt plus bas dans l'arborescence
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
        }
        Ok(())
    }

    /// Dépose une ENU déjà signée sous `enu_racine_depot` : sauvegarde dans
    /// `~/.feu/enu/`, puis greffe via [`Self::greffe_enfants`].
    ///
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
    pub(super) fn depot_enu_texte(
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

    /// Matérialise l'arborescence d'une `EnuR` dans un dossier OS, en lecture
    /// seule — opération inverse du dépôt par comptoir.
    ///
    /// Crée `chemin_retrait` en `0o700` puis y reconstruit ce que décrit `enu_r`,
    /// chaque enfant **authentifié** avant écriture. **Sans reprise** : le dossier
    /// appartient ensuite à l'utilisateur.
    ///
    /// L'ENU de `fiche_r` **est** le dossier de sortie : son nom est ignoré, elle
    /// peut donc être le sommet du nœud.
    ///
    /// **Tout foyer du sous-arbre doit être ouvert**, et [`Self::foyers_requis`]
    /// le vérifie avant le chargement de `fiche_r` — sans quoi un foyer fermé
    /// sortait en falsification apparente. Le sous-arbre est donc lu deux fois.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeFoyersFermes`] si un seul foyer
    /// requis manque — aucune écriture n'a eu lieu, l'appel se retente une fois
    /// les foyers rouverts. Puis
    /// [`ErreurFeuApplication::ScribeEnuNonAuthentique`] si le chargement de
    /// `fiche_r` ne passe pas la barrière,
    /// [`ErreurFeuApplication::ScribeDossierDejaExistant`] si `chemin_retrait`
    /// est un dossier existant, ou [`ErreurFeuApplication::ScribeEnuRAttendue`]
    /// si ce n'est pas un répertoire. Propage les erreurs de la descente :
    /// authentification d'un enfant, nom absent ou invalide, E/S et lecture de
    /// blob (blob introuvable).
    pub(super) fn retrait_lecture_seule(
        &self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        chemin_retrait: &Path,
        fiche_r: &Fiche,
    ) -> ResultFeuApplication<()> {
        let foyers_fermes: Vec<usize> = self
            .foyers_requis(session, &fiche_r.hash_carte())?
            .into_iter()
            .filter(|index| !session.etat_foyers()[*index])
            .collect();

        if !foyers_fermes.is_empty() {
            return Err(ErreurFeuApplication::ScribeFoyersFermes(foyers_fermes));
        }

        let enu_r = Enu::charger(&self.chemin_enu, session, &fiche_r.hash_carte())?;

        if chemin_retrait.is_dir() {
            return Err(ErreurFeuApplication::ScribeDossierDejaExistant(
                chemin_retrait.to_path_buf(),
            ));
        }
        let Carte::Repertoire {
            metas: _,
            tags: _,
            hashs_enu,
        } = enu_r.carte()
        else {
            return Err(ErreurFeuApplication::ScribeEnuRAttendue);
        };

        Self::creer_dossier_700(chemin_retrait)?;

        // la racine est le dossier de sortie : on matérialise ses enfants,
        // jamais elle — la récursion ne reçoit que des entrées nommées
        for h in hashs_enu {
            let enu = Enu::charger(&self.chemin_enu, session, h)?;
            self.retrait_lecture_seule_recursif(noyau, session, chemin_retrait, &enu)?;
        }

        Ok(())
    }

    /// Inventorie les foyers dont dépend le sous-arbre de `hash_carte`.
    ///
    /// Pré-passe de [`Self::retrait_lecture_seule`], qui répond avant la moindre
    /// écriture là où la descente ne le découvrirait qu'à mi-chemin.
    ///
    /// **Toutes les cartes comptent**, pas seulement les [`Carte::Donnee`] : un
    /// répertoire de foyer fermé arrête le retrait aussi sûrement qu'une donnée.
    ///
    /// L'inventaire se fait **tous foyers fermés**, [`Descendants`] ne vérifiant
    /// aucune signature. Une braise qui ne résout vers aucun foyer est écartée
    /// sans erreur : c'est la racine du nœud.
    ///
    /// # Errors
    ///
    /// Propage l'échec de chargement d'une ENU du parcours — le premier arrête
    /// l'inventaire, `collect` court-circuitant sur `Err`. Une ENU illisible est
    /// de toute façon un retrait qui échouera.
    fn foyers_requis(
        &self,
        session: &SessionApplication,
        hash_carte: &[u8; 32],
    ) -> ResultFeuApplication<BTreeSet<usize>> {
        self.donne_descendants(hash_carte)
            .filter_map(|item| match item {
                Err(e) => Some(Err(e)),
                Ok((_, fiche)) => session.braise_vers_index(fiche.braise()).map(Ok),
            })
            .collect()
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
    pub(super) fn donne_descendants<'a>(&'a self, hash_carte: &[u8; 32]) -> Descendants<'a> {
        Descendants::new(&self.chemin_enu, hash_carte)
    }

    /// Fabrique un parcours remontant à partir de `hash_carte`.
    ///
    /// Même raison d'être que [`Self::donne_descendants`] : le Scribe arme
    /// l'itérateur plutôt que de laisser sortir `chemin_enu`. Infaillible comme
    /// lui — [`RacinesAnterieures`] ne vérifie rien à la construction, chaque
    /// racine étant authentifiée au moment où elle est chargée.
    pub(super) fn donne_racines_anterieures<'a>(
        &'a self,
        session: &'a SessionApplication,
        hash_carte: &[u8; 32],
    ) -> RacinesAnterieures<'a> {
        RacinesAnterieures::new(&self.chemin_enu, session, hash_carte)
    }

    /// Cœur récursif de [`Self::retrait_lecture_seule`] : matérialise **une**
    /// entrée nommée dans un dossier parent existant.
    ///
    /// Invariant d'entrée : `enu_courante` est un enfant, jamais la racine, et
    /// porte donc une méta `"nom"` — validée comme composant de chemin avant tout
    /// `join`. Aucun test de collision : l'unicité des noms au sein d'un
    /// répertoire est tenue à la greffe ([`Self::greffe_enfants`]), le retrait
    /// joint le nom sans sonder le dossier de sortie.
    ///
    /// Seule [`Carte::Donnee`] passe par le noyau, qui écrit le clair directement
    /// dans le fichier de sortie — le `File` est consommé par l'appel.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::ScribeMetaNomAbsente`] ou
    /// [`ErreurFeuApplication::ScribeNomFichierInvalide`] selon que le nom est
    /// absent ou refusé. Propage les erreurs d'E/S, d'authentification
    /// d'un enfant ([`Enu::charger`]) et de lecture de blob — notamment foyer
    /// fermé ou blob introuvable.
    fn retrait_lecture_seule_recursif(
        &self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        chemin_courant: &Path,
        enu_courante: &Enu,
    ) -> ResultFeuApplication<()> {
        // nom validé avant tout join — il vient du disque et pourrait sinon
        // faire écrire hors du dossier de retrait, quelle que soit la variante
        let nom_fichier = enu_courante.carte().nom_fichier()?;

        let chemin = chemin_courant.join(&nom_fichier);

        match enu_courante.carte() {
            Carte::Donnee {
                metas: _,
                tags: _,
                hash_donnee,
            } => {
                // seule la lecture du blob exige un foyer : résolution ici,
                // pas en tête — un répertoire n'en a pas besoin
                let index_foyer = session
                    .braise_vers_index(enu_courante.braise())
                    .expect("Braise déjà validée avant d'atteindre ce point : Enu::authentique sur la racine du retrait, Enu::charger sur chaque enfant");

                let fichier = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&chemin)?;

                // le noyau écrit le clair directement dans le fichier, qui est
                // consommé — fermé au drop, aucun suivi ensuite
                noyau.lecture_blob(index_foyer, &HEXLOWER.encode(hash_donnee), fichier)?;
            }
            Carte::Texte {
                metas: _,
                tags: _,
                contenu,
            } => {
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
                Self::creer_dossier_700(&chemin)?;

                for h in hashs_enu {
                    let enu = Enu::charger(&self.chemin_enu, session, h)?;
                    self.retrait_lecture_seule_recursif(noyau, session, &chemin, &enu)?;
                }
            }
        }
        Ok(())
    }

    /// Rend un nom absent de `noms_existants` : `nom` tel quel, ou suffixé
    /// `nom_1`, `nom_2`… s'il est déjà pris.
    ///
    /// Les hashs d'un répertoire sont uniques, pas les noms de ses enfants :
    /// [`Self::greffe_enfants`] s'en sert pour les départager. Le suffixe
    /// s'ajoute en fin de nom, après l'extension — simplicité assumée.
    ///
    /// N'insère rien : l'appelant tient le jeu de noms et l'alimente.
    fn nom_libre(noms_existants: &BTreeSet<String>, nom: &str) -> String {
        let mut nom_candidat = String::from(nom);
        let mut i = 1;
        while noms_existants.contains(&nom_candidat) {
            nom_candidat = format!("{nom}_{i}");
            i += 1;
        }

        nom_candidat
    }

    /// Crée `path` et ses parents manquants en `rwx------` (0o700).
    ///
    /// Recopiée de `feu-noyau` plutôt que partagée : deux appelants ne valent
    /// pas une crate commune, et un test relit les permissions de chaque côté.
    ///
    /// # Errors
    ///
    /// Propage [`ErreurFeuApplication::IoError`] si la création échoue.
    pub(super) fn creer_dossier_700(path: &Path) -> ResultFeuApplication<()> {
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
    pub(super) fn ecrire_fichier_600(chemin: &Path, contenu: &[u8]) -> ResultFeuApplication<()> {
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
