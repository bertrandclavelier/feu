// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! État applicatif de la session courante.
//!
//! [`SessionApplication`] centralise tout ce que `feu-application` doit
//! mémoriser entre les commandes : capacités du noyau, adresses et états
//! des foyers, clés publiques reçues via l'interface du noyau, et les
//! comptoirs de dépôt ouverts.
//!
//! Cette struct est peuplée pendant l'exécution des commandes — par le pont
//! interne vers le noyau pour ce qui vient de lui, par le [`Scribe`] pour les
//! comptoirs de dépôt. Écrit ici qui détient l'original, jamais la couche de
//! présentation.
//!
//! Une commande y touche malgré tout, mais en bloc et non par champ :
//! l'extinction du nœud remplace la session entière par une session neuve. Rien
//! n'y survit, donc rien n'y ment.
//!
//! [`Scribe`]: crate::scribe::Scribe
//!
//! # Le porteur, pas la source
//!
//! La session ne détient rien en propre : chaque champ redit un état dont
//! l'autorité est ailleurs — le noyau pour les clés et les foyers, le Scribe
//! pour les comptoirs. Elle existe parce que cette autorité n'est pas
//! transportable : le noyau ne franchit pas la frontière de la crate, le Scribe
//! non plus, alors qu'un clone de la session part vers la couche de présentation
//! après chaque commande mutante.
//!
//! C'est ce qui la rend lisible de l'extérieur sans rien exposer de l'intérieur,
//! et ce qui impose sa contrepartie : tout état recopié ici se met à jour à
//! l'endroit exact où l'original change, dans la même fonction et sans rien
//! entre les deux. Un miroir tenu de plus loin finirait par mentir sur un
//! chemin d'erreur.
//!
//! # Aucune erreur
//!
//! Aucun accesseur de [`SessionApplication`] ne rend de `Result` ni d'[`Option`]
//! indexée : [`IndexFoyer`] borne la position par construction, tout foyer
//! désigné existe. Seule [`Self::braise_vers_index`] rend une [`Option`], parce
//! qu'une braise peut n'appartenir à aucun foyer.
//!
//! La session ne peut donc pas faire remonter d'erreur applicative dans une
//! couche qui la consomme, ni celle-ci la lui renvoyer aplatie de ses préfixes.

use std::{collections::BTreeMap, path::PathBuf};

use feu_noyau::{
    Braise, IndexClasseur, IndexFoyer, MAX_TAILLE_BLOB, MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE,
    MAX_TAILLE_SIGNATURE,
};

use crate::fiche::Fiche;

/// État applicatif de la session courante.
///
/// Regroupe les limites de taille du noyau et l'état dynamique de la session
/// (adresses braise, états d'ouverture, clés publiques, comptoirs de dépôt
/// ouverts). Peuplé à l'allumage, puis mis à jour à chaque ouverture ou
/// fermeture de foyer et de comptoir.
///
/// # Invariants
///
/// Les champs `max_taille_*` sont des constantes reprises du noyau. Ils ne
/// changent pas en cours de session. Le nombre de foyers et de classeurs n'est
/// pas recopié ici : il est porté par [`IndexFoyer`] et [`IndexClasseur`].
#[derive(Clone)]
pub struct SessionApplication {
    /// Taille maximum d'un blob en octets — dérivée de [`MAX_TAILLE_BLOB`].
    pub max_taille_blob: usize,
    /// Taille maximum d'un message à chiffrer asymétriquement.
    pub max_taille_chiffrement_asymetrique: usize,
    /// Taille maximum d'un message à signer.
    pub max_taille_signature: usize,
    /// Adresses `.braise` des foyers — indexées par position.
    braise_foyers: [Braise; IndexFoyer::NOMBRE],
    /// État d'ouverture de chaque foyer — `true` si ouvert.
    etat_foyers: [bool; IndexFoyer::NOMBRE],
    /// Clé publique de signature ML-DSA-87 du nœud — reçue à l'allumage.
    cle_publique_sig_noeud: [u8; 2592],
    /// Clés publiques de signature ML-DSA-87 des foyers — reçues à l'ouverture.
    cle_publique_sig_foyers: [[u8; 2592]; IndexFoyer::NOMBRE],
    /// Clés publiques de chiffrement ML-KEM-1024 des foyers — reçues à l'ouverture.
    cle_publique_chif_foyers: [[u8; 1568]; IndexFoyer::NOMBRE],
    /// Comptoirs de dépôt ouverts — miroir lisible de ceux que le Scribe
    /// détient : identifiant, puis dossier, foyer et classeur de destination.
    /// Le Scribe seul les connaît, et un identifiant nu n'apprendrait rien à la
    /// présentation.
    ///
    /// Une [`BTreeMap`] porte l'unicité de l'identifiant par le type, et son
    /// ordre trié est celui des ouvertures, les identifiants venant d'un
    /// compteur croissant.
    comptoirs_depot_ouverts: BTreeMap<usize, (PathBuf, IndexFoyer, IndexClasseur)>,

    /// Comptoir de travail ouvert — miroir de celui que tient le Scribe.
    ///
    /// Les éléments plutôt que le comptoir lui-même, qui reste interne : le
    /// chemin dit où l'utilisateur travaille, la [`Fiche`] nomme la racine
    /// sortie.
    comptoir_travail_ouvert: Option<(PathBuf, Fiche)>,
}

impl SessionApplication {
    /// Crée une session vide : capacités initialisées depuis les constantes
    /// noyau, foyers fermés, braises et clés à zéro.
    ///
    /// Rien n'est lu du disque ni du noyau ici. Le remplissage vient ensuite du
    /// pont interne, à l'allumage puis à chaque ouverture de foyer — d'où des
    /// tableaux entièrement littéraux : les cinq sont des valeurs de départ,
    /// jamais des valeurs de travail.
    ///
    /// Une clé à zéro n'est donc pas une clé, et `braise_foyers` rempli de
    /// [`Braise::VIDE`] ne désigne aucun foyer — l'état d'une session neuve se
    /// distingue par ce que le noyau n'y a pas encore écrit.
    pub fn new() -> Self {
        Self {
            max_taille_blob: MAX_TAILLE_BLOB,
            max_taille_chiffrement_asymetrique: MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE,
            max_taille_signature: MAX_TAILLE_SIGNATURE,
            braise_foyers: [Braise::VIDE; IndexFoyer::NOMBRE],
            etat_foyers: [false; IndexFoyer::NOMBRE],
            cle_publique_sig_noeud: [0u8; 2592],
            cle_publique_sig_foyers: [[0u8; 2592]; IndexFoyer::NOMBRE],
            cle_publique_chif_foyers: [[0u8; 1568]; IndexFoyer::NOMBRE],
            comptoirs_depot_ouverts: BTreeMap::new(),
            comptoir_travail_ouvert: None,
        }
    }

    /// Retourne l'adresse `.braise` du foyer à la position `index_foyer`.
    ///
    /// Réciproque de [`Self::braise_vers_index`]. Aucune [`Option`] :
    /// [`IndexFoyer`] borne la position, tout foyer désigné existe.
    pub fn braise_foyer(&self, index_foyer: IndexFoyer) -> Braise {
        self.braise_foyers[index_foyer.valeur()]
    }

    /// Résout une adresse `.braise` en position de foyer.
    ///
    /// Retourne `Some(index_foyer)` si la braise est celle d'un foyer connu dans
    /// la session, `None` si l'adresse est inconnue. Permet de retrouver la clé
    /// publique de signature d'un foyer à partir de la braise lue dans une ENU.
    pub fn braise_vers_index(&self, braise: Braise) -> Option<IndexFoyer> {
        IndexFoyer::tous().find(|index_foyer| self.braise_foyers[index_foyer.valeur()] == braise)
    }

    /// Enregistre l'adresse `.braise` du foyer à la position `index_foyer`.
    ///
    /// Appelé par `RecepteurNoyau` lors de l'allumage du nœud.
    pub(crate) fn definit_braise_foyer(&mut self, index_foyer: IndexFoyer, braise: Braise) {
        self.braise_foyers[index_foyer.valeur()] = braise;
    }

    /// Retourne une vue immuable sur le tableau des états d'ouverture des foyers.
    ///
    /// Permet à l'appelant d'itérer pour repérer les positions ouvertes sans
    /// passer par [`Self::etat_foyer`] index par index.
    /// Préserve l'encapsulation : le tableau reste privé en écriture, seul
    /// `feu-application` peut le muter via `definit_etat_foyer`.
    pub fn etat_foyers(&self) -> &[bool] {
        &self.etat_foyers
    }

    /// Retourne l'état d'ouverture du foyer à la position `index_foyer`.
    pub fn etat_foyer(&self, index_foyer: IndexFoyer) -> bool {
        self.etat_foyers[index_foyer.valeur()]
    }

    /// Indique si tous les foyers sont fermés.
    ///
    /// Retourne `true` quand chaque entrée d'`etat_foyers` est à `false` —
    /// état initial de la session ou résultat d'une fermeture exhaustive.
    /// Court-circuite à la première ouverture rencontrée.
    ///
    /// Précondition utilisée par
    /// [`commande_extinction_noeud`](crate::FeuApplication::commande_extinction_noeud)
    /// pour refuser l'extinction tant qu'un foyer est ouvert.
    pub fn foyers_fermes(&self) -> bool {
        self.etat_foyers.iter().all(|&b| !b)
    }

    /// Retourne le nombre de foyers actuellement ouverts.
    ///
    /// Complément de [`foyers_fermes`](Self::foyers_fermes), qui répond à une
    /// précondition : ce compte-ci sert la couche de présentation, qui a besoin
    /// du nombre et pas seulement du booléen.
    pub fn nombre_foyers_ouverts(&self) -> usize {
        self.etat_foyers.iter().filter(|&&b| b).count()
    }

    /// Met à jour l'état d'ouverture du foyer à la position `index_foyer`.
    ///
    /// Appelé par `RecepteurNoyau` après ouverture ou fermeture d'un foyer.
    pub(crate) fn definit_etat_foyer(&mut self, index_foyer: IndexFoyer, etat: bool) {
        self.etat_foyers[index_foyer.valeur()] = etat;
    }

    /// Enregistre la clé publique de signature ML-DSA-87 du nœud.
    ///
    /// Appelé par `RecepteurNoyau` à l'allumage du nœud.
    pub(crate) fn definit_cle_publique_sig_noeud(&mut self, cle: [u8; 2592]) {
        self.cle_publique_sig_noeud = cle;
    }

    /// Retourne la clé publique de signature ML-DSA-87 du nœud.
    pub fn cle_publique_sig_noeud(&self) -> [u8; 2592] {
        self.cle_publique_sig_noeud
    }

    /// Retourne la clé publique de signature ML-DSA-87 du foyer à la position
    /// `index_foyer`.
    ///
    /// Interrogée par `Enu::charger` après résolution de la braise : c'est la
    /// clé contre laquelle une ENU de contenu est authentifiée.
    pub fn cle_publique_sig_foyer(&self, index_foyer: IndexFoyer) -> [u8; 2592] {
        self.cle_publique_sig_foyers[index_foyer.valeur()]
    }

    /// Enregistre la clé publique de signature ML-DSA-87 du foyer.
    ///
    /// Appelé par `RecepteurNoyau` à l'ouverture du foyer.
    pub(crate) fn definit_cle_publique_sig_foyer(
        &mut self,
        index_foyer: IndexFoyer,
        cle: [u8; 2592],
    ) {
        self.cle_publique_sig_foyers[index_foyer.valeur()] = cle;
    }

    /// Retourne la clé publique de chiffrement ML-KEM-1024 du foyer à la
    /// position `index_foyer`.
    pub fn cle_publique_chif_foyer(&self, index_foyer: IndexFoyer) -> [u8; 1568] {
        self.cle_publique_chif_foyers[index_foyer.valeur()]
    }

    /// Enregistre la clé publique de chiffrement ML-KEM-1024 du foyer.
    ///
    /// Appelé par `RecepteurNoyau` à l'ouverture du foyer.
    pub(crate) fn definit_cle_publique_chif_foyer(
        &mut self,
        index_foyer: IndexFoyer,
        cle: [u8; 1568],
    ) {
        self.cle_publique_chif_foyers[index_foyer.valeur()] = cle;
    }

    /// Retourne les comptoirs de dépôt ouverts, indexés par identifiant.
    ///
    /// Par référence : la présentation reçoit déjà une [`SessionApplication`]
    /// clonée entière après chaque commande mutante, une copie de plus
    /// n'ajouterait rien. Aucune [`Option`] : la table existe toujours, vide
    /// quand aucun comptoir n'est ouvert.
    pub fn comptoirs_depot_ouverts(
        &self,
    ) -> &BTreeMap<usize, (PathBuf, IndexFoyer, IndexClasseur)> {
        &self.comptoirs_depot_ouverts
    }

    /// Retourne la table des comptoirs ouverts en écriture.
    ///
    /// Un accès mutable en bloc plutôt que trois setters — `insert`, `remove` et
    /// `clear` sont ceux de la [`BTreeMap`], les redéclarer ici n'ajouterait
    /// qu'un niveau de délégation.
    ///
    /// Appelé par le Scribe seul, aux deux lignes où il ajoute et retire un
    /// comptoir de sa propre table. C'est ce voisinage qui tient le miroir :
    /// aucun chemin d'erreur ne passe entre les deux écritures.
    pub(crate) fn mut_comptoirs_depot_ouverts(
        &mut self,
    ) -> &mut BTreeMap<usize, (PathBuf, IndexFoyer, IndexClasseur)> {
        &mut self.comptoirs_depot_ouverts
    }

    /// Retourne le dossier du comptoir de travail et sa racine, s'il est ouvert.
    pub fn comptoir_travail_ouvert(&self) -> Option<&(PathBuf, Fiche)> {
        self.comptoir_travail_ouvert.as_ref()
    }

    /// Inscrit le comptoir de travail dans la session.
    ///
    /// Appelée par le Scribe à l'instant où il enregistre le sien — c'est ce
    /// voisinage qui tient le miroir, comme pour les comptoirs de dépôt.
    pub(crate) fn definit_comptoir_travail_ouvert(&mut self, chemin: PathBuf, fiche_racine: Fiche) {
        self.comptoir_travail_ouvert = Some((chemin, fiche_racine));
    }

    /// Efface le comptoir de travail du miroir.
    ///
    /// Appelée par le Scribe à l'instant où il retire le sien, comme
    /// [`Self::definit_comptoir_travail_ouvert`] à l'ouverture.
    pub(crate) fn ferme_comptoir_travail(&mut self) {
        self.comptoir_travail_ouvert = None;
    }
}

impl Default for SessionApplication {
    /// Délègue à [`SessionApplication::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Tests en ligne : ce qui se prouve sans monter de pile.
///
/// Troisième emplacement de la crate, après `src/tests.rs` (la crate par ses
/// `commande_*`) et `src/scribe/tests.rs` (le Scribe en direct). Ces deux-là
/// montent un noyau réel dans un `TempDir` ; ici, [`SessionApplication`] est
/// un porteur d'état pur — une session neuve et deux setters suffisent.
///
/// Ce qui touche à la session **à travers une commande** relève du haut, pas
/// d'ici : ce fichier n'éprouve que le comptage et les bornes.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResultFeuApplication;

    /// Deux foyers ouverts sur trois, lus par les deux accesseurs.
    ///
    /// Seul cet état panaché sépare un `all` d'un `any`. Le compte relevé dès
    /// la session neuve attrape un `filter` inversé.
    #[test]
    fn etat_foyers() -> ResultFeuApplication<()> {
        let mut session = SessionApplication::new();

        assert_eq!(session.nombre_foyers_ouverts(), 0);
        assert!(session.foyers_fermes());

        session.definit_etat_foyer(IndexFoyer::ZERO, true);
        assert_eq!(session.nombre_foyers_ouverts(), 1);
        session.definit_etat_foyer(IndexFoyer::try_from(1)?, true);
        assert_eq!(session.nombre_foyers_ouverts(), 2);

        assert!(!session.foyers_fermes());

        Ok(())
    }
}
