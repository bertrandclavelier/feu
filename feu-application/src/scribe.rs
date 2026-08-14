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
//! jamais une donnée autrement que par son ENU.

mod comptoir;
pub mod enu;
pub mod iterateurs;

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

use feu_noyau::{BRAISE_VIDE, DonneesBlob, FeuNoyau, MAX_CLASSEURS, MAX_FOYERS};
use walkdir::WalkDir;

use crate::{
    ErreurFeuApplication, ResultFeuApplication, SessionApplication,
    scribe::{
        comptoir::ComptoirDepot,
        enu::{Carte, Enu},
        iterateurs::Descendants,
    },
};

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

    /// Comptoirs de dépôt actifs, indexés par leur identifiant.
    comptoirs_depot: HashMap<usize, ComptoirDepot>,

    /// Prochain identifiant disponible pour un nouveau comptoir.
    ///
    /// Jamais remis à zéro, pas même à l'extinction : un identifiant distribué
    /// avant elle ne peut ainsi désigner aucun comptoir neuf, il échoue en
    /// [`ErreurFeuApplication::ScribeIndexComptoirInconnu`] au lieu d'en
    /// atteindre un autre.
    prochain_id: usize,
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
            comptoirs_depot: HashMap::new(),
            prochain_id: 0,
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
    /// # Erreurs
    ///
    /// Propage les erreurs de [`Enu::charger_derniere_racine`] : lien absent,
    /// lecture, authentification.
    pub(super) fn derniere_enu_racine(
        &self,
        session: &SessionApplication,
    ) -> ResultFeuApplication<Enu> {
        Enu::charger_derniere_racine(&self.chemin_derniere_racine, session)
    }

    /// Charge l'ENU de `hash` — `None` si aucun fichier ne lui correspond.
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
    /// # Erreurs
    ///
    /// Propage les erreurs de [`Enu::charger`] : lecture, authentification.
    pub(super) fn charge_enu(
        &self,
        session: &SessionApplication,
        hash: &[u8; 32],
    ) -> ResultFeuApplication<Option<Enu>> {
        if !Enu::hash_carte_vers_chemin(hash, &self.chemin_enu).exists() {
            return Ok(None);
        }

        Ok(Some(Enu::charger(&self.chemin_enu, session, hash)?))
    }

    /// Traduit une ENU en ce que le noyau attend : l'index du foyer et
    /// l'empreinte du blob.
    ///
    /// Le Scribe ignore ce qu'est un foyer, le noyau ignore ce qu'est une ENU.
    /// Cette fonction est la charnière : la braise devient un index par
    /// [`SessionApplication::braise_vers_index`], la carte livre son
    /// `hash_donnee`. C'est ce qui permet aux appelants de ne désigner une
    /// donnée que par son ENU, sans jamais recomposer un couple foyer/hash —
    /// qu'ils pourraient former incohérent.
    ///
    /// Facteur commun des quatre fonctions de blob — [`charge_blob`](Self::charge_blob),
    /// [`supprime_blob`](Self::supprime_blob), [`existence_blob`](Self::existence_blob)
    /// et [`informations_blob`](Self::informations_blob) — qui ne diffèrent que
    /// par l'appel noyau qui suit. Les tenir ensemble ici garantit qu'elles ne
    /// divergeront pas sur la façon de résoudre leur cible.
    ///
    /// **C'est aussi la barrière d'authenticité de ces quatre-là.** Une ENU peut
    /// venir d'un parcours, qui ne vérifie aucune signature : elle est donc
    /// repassée par [`Enu::authentique`] avant que quoi que ce soit ne parte vers
    /// le noyau. Ici et pas dans chacune des quatre — aucune ne peut l'oublier,
    /// et celle qui s'ajoutera plus tard l'aura sans y penser. Le contrôle vient
    /// en tête, avant la résolution de braise, qu'il couvre déjà.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::ScribeEnuNonAuthentique`] si la signature
    /// n'est pas validée, [`ErreurFeuApplication::ScribeBraiseInconnue`] si la
    /// braise ne résout vers aucun foyer de la session, et
    /// [`ErreurFeuApplication::ScribeEnuDAttendue`] si la carte n'est pas une
    /// [`Carte::Donnee`] et ne référence donc aucun blob.
    fn index_et_hash_blob(
        &self,
        session: &SessionApplication,
        enu: &Enu,
    ) -> ResultFeuApplication<(usize, [u8; 32])> {
        if !enu.authentique(session)? {
            return Err(ErreurFeuApplication::ScribeEnuNonAuthentique);
        }
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

    /// Déchiffre le blob référencé par `enu` et écrit le clair dans
    /// `destination`.
    ///
    /// Le Scribe ne sait pas déchiffrer, c'est l'affaire du noyau : il ne fait
    /// ici que résoudre la cible par [`index_et_hash_blob`](Self::index_et_hash_blob),
    /// puis passer la main. Le hash lui est transmis en hexadécimal, forme sous
    /// laquelle le noyau nomme ses blobs.
    ///
    /// # Erreurs
    ///
    /// Propage les trois refus de
    /// [`index_et_hash_blob`](Self::index_et_hash_blob), puis les erreurs du
    /// noyau : foyer fermé, blob introuvable, déchiffrement, donnée corrompue.
    pub(super) fn charge_blob(
        &self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        enu: &Enu,
        destination: impl Write,
    ) -> ResultFeuApplication<()> {
        let (index, hash_donnees) = self.index_et_hash_blob(session, enu)?;

        noyau.lecture_blob(index, &HEXLOWER.encode(&hash_donnees), destination)?;

        Ok(())
    }

    /// Supprime le blob référencé par `enu`, sans toucher à l'ENU.
    ///
    /// Jumelle de [`charge_blob`](Self::charge_blob) : même résolution de
    /// cible, seul l'appel noyau qui suit diffère.
    ///
    /// L'ENU survit à son blob. Rien ici ne la retire de l'arborescence, où elle
    /// continue de référencer un fichier absent.
    ///
    /// # Erreurs
    ///
    /// Propage les trois refus de
    /// [`index_et_hash_blob`](Self::index_et_hash_blob), puis les erreurs du
    /// noyau : foyer fermé, blob introuvable, suppression disque.
    pub(super) fn supprime_blob(
        &self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        enu: &Enu,
    ) -> ResultFeuApplication<()> {
        let (index, hash_donnees) = self.index_et_hash_blob(session, enu)?;

        noyau.suppression_blob(index, &HEXLOWER.encode(&hash_donnees))?;

        Ok(())
    }

    /// Indique si le blob référencé par `enu` est présent dans son foyer.
    ///
    /// Même résolution de cible que [`charge_blob`](Self::charge_blob), sans
    /// rien ouvrir : la question porte sur la présence du `.dat`, pas sur son
    /// contenu. Une ENU peut survivre à son blob (voir
    /// [`supprime_blob`](Self::supprime_blob)) — c'est ce que cette méthode
    /// permet de détecter.
    ///
    /// # Erreurs
    ///
    /// Propage les trois refus de
    /// [`index_et_hash_blob`](Self::index_et_hash_blob), puis les erreurs du
    /// noyau : foyer fermé. Un blob absent est un `Ok(false)`.
    pub(super) fn existence_blob(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        enu: &Enu,
    ) -> ResultFeuApplication<bool> {
        let (index, hash_donnees) = self.index_et_hash_blob(session, enu)?;

        Ok(noyau.existence_blob(index, &HEXLOWER.encode(&hash_donnees))?)
    }

    /// Retourne les métadonnées système du blob référencé par `enu` — taille,
    /// dates.
    ///
    /// Renseigne sur le fichier, jamais sur son contenu : rien n'est déchiffré.
    ///
    /// # Erreurs
    ///
    /// Propage les trois refus de
    /// [`index_et_hash_blob`](Self::index_et_hash_blob), puis les erreurs du
    /// noyau : foyer fermé, blob introuvable — ici une erreur, contrairement à
    /// [`existence_blob`](Self::existence_blob).
    pub(super) fn informations_blob(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        enu: &Enu,
    ) -> ResultFeuApplication<DonneesBlob> {
        let (index, hash_donnees) = self.index_et_hash_blob(session, enu)?;

        Ok(noyau.informations_blob(index, &HEXLOWER.encode(&hash_donnees))?)
    }

    /// Active le Scribe et, à la première activation, amorce l'arborescence.
    ///
    /// Appelé par [`commande_allumage_noeud`](crate::FeuApplication::commande_allumage_noeud)
    /// après que le noyau a été allumé avec succès. Si le dossier `enu/` est
    /// absent (tout premier allumage du nœud), il est créé en `rwx------`
    /// (0o700), puis la **racine origine** est forgée et posée en sommet
    /// courant via [`Enu::new_racine`] (carte `None` : répertoire vide, signé
    /// par le nœud, symlink `.DERNIERE_RACINE` pointé dessus). `feu_noyau` est
    /// requis pour cette signature de genèse ; `session` n'est que transmis à
    /// [`Enu::new_racine`], qui n'en fait rien dans le cas `None` — il n'y a pas
    /// encore de racine précédente à relire.
    ///
    /// Aux allumages ultérieurs (`enu/` déjà présent), cette amorce est sautée.
    ///
    /// Point d'accroche du travail que le Scribe aurait à mener à chaque
    /// allumage : hors du `if`, que seule la genèse franchit.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la création du dossier, la signature de la racine
    /// origine, sa sauvegarde ou la pose du symlink échoue. Le Scribe reste
    /// alors inactif : le drapeau n'est posé qu'en sortie réussie.
    pub(super) fn activation(
        &mut self,
        feu_noyau: &FeuNoyau,
        session: &SessionApplication,
    ) -> ResultFeuApplication<()> {
        if !&self.chemin_enu.exists() {
            DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&self.chemin_enu)?;

            Enu::new_racine(
                feu_noyau,
                session,
                &self.chemin_enu,
                &self.chemin_derniere_racine,
                None,
            )?;
        }

        self.est_actif = true;

        Ok(())
    }

    /// Désactive le Scribe et oublie les comptoirs de dépôt ouverts.
    ///
    /// Appelé par [`commande_extinction_noeud`](crate::FeuApplication::commande_extinction_noeud).
    /// Ne supprime rien sur le disque : ni `enu/`, dont les ENU survivent à
    /// l'extinction, ni les dossiers des comptoirs, qui portent des fichiers de
    /// l'utilisateur jamais ingérés.
    pub(super) fn desactivation(&mut self) {
        self.est_actif = false;
        self.comptoirs_depot.clear();
    }

    /// Ouvre un comptoir de dépôt au chemin donné.
    ///
    /// Crée le dossier physique sur le système de fichiers, l'enregistre
    /// dans [`comptoirs_depot`](Self::comptoirs_depot) et retourne son
    /// identifiant.
    ///
    /// Les deux index sont validés ici, contre des bornes de compilation : le
    /// comptoir les porte ensuite jusqu'à sa fermeture, qui n'a plus à en
    /// douter.
    ///
    /// `session` est prise en mutable pour y inscrire le même identifiant, à la
    /// ligne qui suit l'enregistrement. Le Scribe tient les comptoirs, la
    /// session les rend lisibles hors de la crate : les deux se remplissent
    /// donc ici, où l'identifiant vient d'être formé.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::ScribeIndexFoyerInvalide`] ou
    /// [`ErreurFeuApplication::ScribeIndexClasseurInvalide`] si l'index sort des
    /// bornes, et propage l'échec de création du dossier — notamment s'il existe
    /// déjà.
    pub(super) fn ouverture_comptoir_depot(
        &mut self,
        session: &mut SessionApplication,
        chemin: &Path,
        index_foyer: usize,
        index_classeur: usize,
    ) -> ResultFeuApplication<usize> {
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

        self.comptoirs_depot.insert(self.prochain_id, comptoir);
        self.prochain_id += 1;

        session
            .mut_comptoirs_depot_ouverts()
            .insert(self.prochain_id - 1);

        Ok(self.prochain_id - 1)
    }

    /// Ferme un comptoir de dépôt : greffe son contenu sous `enu_racine_depot`,
    /// puis propage la nouvelle racine de dépôt jusqu'à la racine du nœud.
    ///
    /// Parcourt le dossier en bottom-up (`contents_first(true)`) : chaque
    /// fichier est déposé dans le classeur du comptoir via
    /// [`FeuNoyau::depot_blob`], puis encapsulé dans une ENU signée de
    /// type [`Carte::Donnee`]. Chaque répertoire devient une
    /// [`Carte::Repertoire`] référençant ses enfants par leur `hash_carte`.
    /// Toutes les ENU produites sont sauvegardées dans `~/.feu/enu/`.
    ///
    /// Le classeur du comptoir n'est qu'une demande : si la donnée existe déjà
    /// dans un autre classeur du foyer, [`FeuNoyau::depot_blob`] l'y laisse et
    /// rend l'index réel. Le traitement se poursuit sans rien changer et l'ENU
    /// produite reste valable — elle référence un hash, pas un emplacement —
    /// mais l'écart n'est **remonté nulle part** : le classeur réel est ignoré
    /// ici, et le comptoir croira avoir déposé dans le sien.
    ///
    /// Le nom de chaque entrée (fichier ou dossier) est conservé comme
    /// métadonnée `"nom"`. Le marquage de la racine du nœud (`"_racine"`) n'est
    /// **pas** posé ici : il l'est par [`Enu::new_racine`] sur le sommet final.
    ///
    /// L'accrochage sous `enu_racine_depot` et la remontée jusqu'au sommet sont
    /// délégués à [`Self::greffe_enfants`], qui traite les deux destinations
    /// possibles selon le signataire du répertoire d'accueil.
    ///
    /// Les entrées directement à la racine du comptoir (`depth == 1`) sont
    /// ajoutées comme enfants directs de `enu_racine_depot`. Les entrées plus
    /// profondes (`depth > 1`) forment des sous-arbres autonomes dont la
    /// racine devient enfant de `enu_racine_depot`. Le dossier physique du comptoir
    /// est supprimé en fin de traitement. Un comptoir vide est simplement
    /// supprimé sans modifier `enu_racine_depot`.
    ///
    /// Le comptoir est retiré de [`comptoirs_depot`](Self::comptoirs_depot) dès
    /// les gardes passées : au-delà, la fermeture est un aller simple, et son
    /// identifiant ne désigne plus rien.
    ///
    /// Il sort de `session` à la ligne suivante, d'où le `&mut` sur un paramètre
    /// que le reste de la fonction ne fait que lire. Les deux retraits sont
    /// collés parce que ce qui les sépare finit toujours par grandir : une garde
    /// glissée entre eux rendrait la session menteuse sur un chemin d'erreur,
    /// sans que rien ne le signale.
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
    /// Trois refus, dont un seul laisse une seconde chance :
    /// [`ErreurFeuApplication::ScribeFoyerFerme`], foyer de destination fermé
    /// depuis l'ouverture — le comptoir est encore enregistré, la fermeture se
    /// retente une fois le foyer rouvert.
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
    /// l'utilisateur de le reprendre.
    pub(super) fn fermeture_comptoir_depot(
        &mut self,
        noyau: &mut FeuNoyau,
        session: &mut SessionApplication,
        index_comptoir: usize,
        enu_racine_depot: &Enu,
    ) -> ResultFeuApplication<()> {
        let Some(comptoir) = self.comptoirs_depot.get(&index_comptoir) else {
            return Err(ErreurFeuApplication::ScribeIndexComptoirInconnu(
                index_comptoir,
            ));
        };

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

        // `None` inatteignable : le `get` d'entrée a réussi et rien entre les
        // deux ne touche à la map. Un refus plutôt qu'un `expect`, au cas où une
        // garde future s'y glisserait.
        let Some(comptoir) = self.comptoirs_depot.remove(&index_comptoir) else {
            return Err(ErreurFeuApplication::ScribeIndexComptoirInconnu(
                index_comptoir,
            ));
        };
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

        self.greffe_enfants(noyau, session, enu_racine_depot, &nouveaux_enfants)?;

        comptoir.supprimer()?;

        Ok(())
    }

    /// Accroche des ENU déjà signées sous `enu_racine_depot`, puis propage la
    /// nouvelle racine de dépôt jusqu'à la racine du nœud.
    ///
    /// Point de passage unique des deux voies de dépôt : le comptoir y greffe
    /// les N entrées de son premier niveau, un dépôt unitaire un seul hash. Les
    /// enfants sont supposés **déjà signés et sauvegardés** dans `~/.feu/enu/` —
    /// cette méthode ne touche qu'au répertoire d'accueil et à ce qui le
    /// surplombe.
    ///
    /// Le `hash_carte` d'un répertoire dépendant de ses enfants, enrichir la
    /// carte d'accueil en produit une nouvelle version, et la modification
    /// remonte de proche en proche jusqu'à un nouveau sommet du nœud.
    ///
    /// Deux destinations, selon le signataire de `enu_racine_depot` — c'est
    /// l'unique endroit où se décide qui signe le sommet :
    ///
    /// - **répertoire d'un foyer** — reconstruit avec ses nouveaux enfants,
    ///   re-signé sous sa propre braise, puis remonté par [`Enu::remplacer`] ;
    /// - **racine du nœud** ([`BRAISE_VIDE`], que seule une racine porte) — la
    ///   greffe se fait à même le sommet : sa carte enrichie repart directement
    ///   en [`Enu::new_racine`], qui la signe *nœud*. Passer par [`Enu::new`]
    ///   échouerait en [`ErreurFeuApplication::ScribeBraiseInconnue`] — cette
    ///   braise ne désigne aucun foyer — et
    ///   re-signer une racine sous un foyer serait un contresens : le sommet
    ///   appartient au nœud, quel que soit le foyer qui reçoit les contenus.
    ///
    /// Tout foyer présent sur le chemin reconstruit doit être **ouvert**, sa
    /// re-signature l'exigeant.
    ///
    /// # Greffe sans effet
    ///
    /// Si la carte augmentée égale celle de départ, la méthode rend `Ok(())`
    /// sans rien forger : les hashs étaient tous déjà présents — la carte est un
    /// ensemble — ou la liste était vide. Produire une version pour un contenu
    /// identique n'ajouterait qu'un maillon mort à la lignée des `_racine`. Le
    /// cas se présente réellement lorsqu'un même fichier est redéposé par le
    /// comptoir : contenu et nom inchangés donnent la même carte, donc le même
    /// `hash_carte`.
    ///
    /// L'appelant ne peut pas distinguer ce cas d'une greffe effective. Aucun
    /// n'en a besoin aujourd'hui ; le jour où l'un d'eux le demandera, ce sera
    /// au type de retour de le dire.
    ///
    /// # Invariants tenus par les appelants
    ///
    /// Cette méthode intervient **en fin de chaîne** — les blobs sont déposés,
    /// les ENU signées et sauvegardées. Refuser à ce stade invaliderait un
    /// travail déjà accompli sans moyen de le défaire ; elle absorbe donc les
    /// cas dégénérés au lieu de les rejeter. Les appelants gardent en amont :
    /// [`Self::fermeture_comptoir_depot`] sort avant l'appel si le comptoir est
    /// vide, [`Self::depot_enu`] passe toujours exactement un hash.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::ScribeEnuRAttendue`] si
    /// `enu_racine_depot` n'est pas un répertoire. Propage toute erreur d'E/S,
    /// d'authentification ou de signature — notamment un foyer fermé sur le
    /// chemin remonté.
    fn greffe_enfants(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        enu_racine_depot: &Enu,
        hashs_nouveaux_enfants: &[[u8; 32]],
    ) -> ResultFeuApplication<()> {
        let mut nouvelle_carte = enu_racine_depot.carte().clone();

        for h in hashs_nouveaux_enfants {
            nouvelle_carte.ajout_hash_enu(h)?;
        }

        if nouvelle_carte == *enu_racine_depot.carte() {
            return Ok(());
        }

        if enu_racine_depot.braise() == BRAISE_VIDE {
            Enu::new_racine(
                noyau,
                session,
                &self.chemin_enu,
                &self.chemin_derniere_racine,
                Some(nouvelle_carte),
            )?;
        } else {
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
    /// Voie unitaire du dépôt, par opposition à celle du comptoir : une ENU à
    /// la fois, quelle que soit sa carte. Elle ne signe rien — le foyer
    /// signataire a été fixé par l'appelant en construisant l'enveloppe.
    ///
    /// # Erreurs
    ///
    /// Propage les erreurs de sauvegarde et celles de [`Self::greffe_enfants`].
    fn depot_enu(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        enu_racine_depot: &Enu,
        enu: &Enu,
    ) -> ResultFeuApplication<()> {
        enu.sauvegarder(&self.chemin_enu)?;

        self.greffe_enfants(noyau, session, enu_racine_depot, &[enu.hash_carte()])?;

        Ok(())
    }

    /// Dépose un texte dans un foyer en l'accrochant sous `enu_racine_depot`,
    /// puis propage la nouvelle racine de dépôt jusqu'à la racine du nœud.
    ///
    /// Variante allégée de [`Self::fermeture_comptoir_depot`] : pas de comptoir,
    /// pas de blob, pas de classeur. Le texte est embarqué dans une
    /// [`Carte::Texte`] (bornée à `MAX_TAILLE_TEXTE`, nommée par la méta `"nom"`
    /// — validée à la construction), mise sous enveloppe signée — l'`EnuT` —
    /// puis confiée à [`Self::depot_enu`], qui la sauvegarde et la greffe.
    ///
    /// Elle survit à l'existence de [`Self::depot_enu`], plus général, parce
    /// qu'elle est la **seule** voie pour une `EnuT` : un texte n'existe pas
    /// comme fichier, il ne peut donc pas passer par un comptoir de dépôt.
    ///
    /// L'`EnuT` est signée sous la braise d'`index_foyer`, pas sous celle du
    /// répertoire d'accueil. Le foyer du texte doit donc être ouvert, en plus
    /// de ceux qu'exige la greffe.
    ///
    /// # Retour
    ///
    /// Rien : le nouveau sommet du nœud est signé, sauvegardé et devient la
    /// cible de `.DERNIERE_RACINE` ; l'appelant qui en a besoin le relit via
    /// [`Enu::charger_derniere_racine`].
    ///
    /// # Erreurs
    ///
    /// Propage [`ErreurFeuApplication::ScribeTailleMaxDepasseeTexte`] si le
    /// texte dépasse `MAX_TAILLE_TEXTE`, ou
    /// [`ErreurFeuApplication::ScribeNomFichierInvalide`] si `nom` est refusé
    /// comme composant de chemin — les deux via [`Carte::new_texte`] —, ou
    /// [`ErreurFeuApplication::ScribeEnuRAttendue`] si `enu_racine_depot` n'est
    /// pas un répertoire (via `ajout_hash_enu`), ou
    /// [`ErreurFeuApplication::ScribeIndexFoyerInvalide`] si `index_foyer` sort
    /// des bornes. Propage toute erreur d'E/S, d'authentification ou de
    /// signature — notamment si un foyer du chemin reconstruit est fermé.
    pub(super) fn depot_enu_texte(
        &self,
        noyau: &FeuNoyau,
        session: &SessionApplication,
        enu_racine_depot: &Enu,
        index_foyer: usize,
        nom: &str,
        contenu: &str,
    ) -> ResultFeuApplication<()> {
        let Some(braise) = session.braise_foyer(index_foyer) else {
            return Err(ErreurFeuApplication::ScribeIndexFoyerInvalide(index_foyer));
        };

        let enu_texte = Enu::new(Carte::new_texte(nom, contenu)?, noyau, session, braise)?;

        self.depot_enu(noyau, session, enu_racine_depot, &enu_texte)?;

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
    /// écrit, et `enu_r` elle-même passe par [`Enu::authentique`] en tête : elle
    /// vient de l'appelant, qui a pu la tirer d'un parcours. Le retrait engage —
    /// il écrit sur le disque — il n'a donc rien à gagner au chargement rapide.
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
    /// Retourne [`ErreurFeuApplication::ScribeEnuNonAuthentique`] si `enu_r` ne
    /// passe pas la barrière, [`ErreurFeuApplication::ScribeDossierDejaExistant`]
    /// si `chemin_retrait` est un dossier existant, ou
    /// [`ErreurFeuApplication::ScribeEnuRAttendue`] si `enu_r` n'est pas un
    /// répertoire. Propage les erreurs de la descente : authentification d'un
    /// enfant, nom absent ou invalide, E/S et lecture de blob (foyer fermé,
    /// blob introuvable).
    pub(super) fn retrait_lecture_seule(
        &self,
        noyau: &mut FeuNoyau,
        session: &SessionApplication,
        chemin_retrait: &Path,
        enu_r: &Enu,
    ) -> ResultFeuApplication<()> {
        if !enu_r.authentique(session)? {
            return Err(ErreurFeuApplication::ScribeEnuNonAuthentique);
        }
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

    /// Fabrique un parcours descendant à partir de `enu`.
    ///
    /// Le Scribe est seul à connaître `chemin_enu` et ne le laisse pas sortir :
    /// il fournit l'itérateur déjà armé plutôt qu'un accesseur au chemin, comme
    /// il le fait déjà pour [`Self::charge_enu`]. L'emplacement du dépôt sur le
    /// disque reste un détail interne.
    ///
    /// Aucune lecture disque ici — le premier chargement n'a lieu qu'au premier
    /// `next`. La construction n'est pas pour autant gratuite : elle authentifie
    /// le point de départ, sans quoi le chaînage du parcours partirait de rien.
    ///
    /// # Erreurs
    ///
    /// Propage les refus de [`Descendants::new`] : ENU de départ non intègre, non
    /// authentique, braise inconnue ou foyer sans clé.
    pub(super) fn donne_descendants<'a>(
        &'a self,
        session: &'a SessionApplication,
        enu: &Enu,
    ) -> ResultFeuApplication<Descendants<'a>> {
        Descendants::new(&self.chemin_enu, session, enu)
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
    ///   besoin, déjà garanti par [`Enu::charger`] sur `enu_courante`), puis
    ///   [`FeuNoyau::lecture_blob`] retrouve le classeur du blob, le
    ///   déchiffre et écrit le clair directement dans le fichier de sortie
    ///   (0o600). Le `File` est consommé par l'appel — flush et fermeture au
    ///   drop, rien à reprendre ensuite.
    /// - [`Carte::Texte`] — le contenu embarqué est écrit tel quel, sans
    ///   passage par le noyau.
    /// - [`Carte::Repertoire`] — sous-dossier créé (0o700), puis récursion sur
    ///   chaque enfant chargé et authentifié.
    ///
    /// # Erreurs
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

                let chemin = Self::chemin_libre(chemin_courant, &nom_fichier);

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
