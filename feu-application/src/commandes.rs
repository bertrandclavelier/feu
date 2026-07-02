// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuApplication.
//
// FeuApplication is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuApplication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuApplication. If not, see <https://www.gnu.org/licenses/>.

//! Commandes exposées par [`FeuApplication`] vers la couche de présentation.
//!
//! Chaque méthode `commande_*` est un point d'entrée stable : elle valide
//! les préconditions, construit un [`RecepteurNoyau`] éphémère si l'appel
//! noyau en a besoin, délègue à [`FeuNoyau`] et propage les erreurs via
//! [`ErreurFeuApplication`].
//!
//! Les commandes qui nécessitent une interaction utilisateur (saisie du mot de
//! passe, affichage de la seed) reçoivent `interface_feu_application : &mut impl
//! InterfaceFeuApplication` en paramètre — l'interface n'est pas stockée dans
//! [`FeuApplication`], elle est fournie à l'appel, comme [`InterfaceFeuNoyau`]
//! l'est dans `feu-noyau`.
//!
//! Les commandes qui ne modifient pas l'état du noyau (`existence_blob`,
//! `informations_blob`, signatures, diagnostic…) prennent `&self` ;
//! les autres prennent `&mut self`.

use std::{io::Write, path::PathBuf};

use feu_noyau::{Anomalie, DonneesBlob, FeuNoyau};

use crate::scribe::enu::Enu;

use super::*;

impl FeuApplication {
    /// Initialise ou allume le nœud et stocke l'instance dans [`FeuApplication`].
    ///
    /// Délègue à [`FeuNoyau::new`] qui détecte automatiquement l'état du nœud :
    /// initialisation si `~/.feu` est absent, allumage sinon.
    ///
    /// `interface_feu_application` est utilisée pour collecter le mot de passe et,
    /// à l'initialisation, transmettre et confirmer la seed mnémotechnique.
    ///
    /// `phrase_seed` : `None` génère une nouvelle seed BIP39 à l'initialisation ;
    /// `Some(phrase)` restaure un nœud depuis une phrase existante. Sans effet à l'allumage —
    /// retourne une erreur si fournie alors que l'arborescence existe déjà.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les fichiers de clés sont absents ou corrompus, si
    /// le mot de passe est incorrect, ou si `phrase_seed` est fournie alors que le
    /// nœud existe déjà.
    pub fn commande_allumage_noeud(
        &mut self,
        interface_feu_application: &mut impl InterfaceFeuApplication,
        phrase_seed: Option<SecretString>,
    ) -> ResultFeuApplication<()> {
        self.feu_noyau = Some({
            let mut recepteur_noyau =
                RecepteurNoyau::new(&mut self.session, interface_feu_application);
            FeuNoyau::new(&self.chemin_feu, phrase_seed, &mut recepteur_noyau)?
        });

        interface_feu_application.recevoir_session_application(Some(self.session.clone()));

        self.scribe.activation()?;

        Ok(())
    }

    /// Éteint le nœud : libère [`FeuNoyau`] et réinitialise [`SessionApplication`].
    ///
    /// Symétrique de [`commande_allumage_noeud`](Self::commande_allumage_noeud).
    /// Effectue dans l'ordre :
    /// 1. Vérifie qu'aucun foyer n'est ouvert.
    /// 2. Libère le noyau (`feu_noyau = None`) — efface les clés privées en mémoire.
    /// 3. Réinitialise la session pour qu'aucune donnée applicative ne survive
    ///    à l'extinction (clés publiques, adresses `.braise`, états).
    /// 4. Notifie la couche de présentation avec `recevoir_session_application(None)`.
    ///
    /// L'extinction n'écrit rien sur disque : les archives chiffrées des foyers
    /// ont déjà été produites par les fermetures préalables.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::AuMoinsUnFoyerOuvert`] si au moins un foyer
    /// est encore ouvert ; [`ErreurFeuApplication::NoeudEteint`] si le nœud n'a
    /// pas été allumé.
    pub fn commande_extinction_noeud(
        &mut self,
        interface_feu_application: &mut impl InterfaceFeuApplication,
    ) -> ResultFeuApplication<()> {
        if !self.session.foyers_fermes() {
            return Err(ErreurFeuApplication::AuMoinsUnFoyerOuvert);
        }
        if self.feu_noyau.is_none() {
            return Err(ErreurFeuApplication::NoeudEteint);
        }

        self.feu_noyau = None;
        self.session = SessionApplication::new();
        interface_feu_application.recevoir_session_application(None);

        self.scribe.desactivation();

        Ok(())
    }

    /// Change le mot de passe FeuNoyau et réécrit le trousseau public chiffré.
    ///
    /// Prérequis noyau : tous les foyers doivent être ouverts.
    ///
    /// `interface_feu_application` est utilisée pour collecter l'ancien et le
    /// nouveau mot de passe.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si un foyer est fermé, si la saisie échoue,
    /// ou si l'écriture du trousseau public échoue.
    pub fn commande_changement_mdp(
        &mut self,
        interface_feu_application: &mut impl InterfaceFeuApplication,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;
        let mut recepteur = RecepteurNoyau::new(&mut self.session, interface_feu_application);
        noyau.changement_mdp(&mut recepteur)?;

        Ok(())
    }

    /// Ouvre le foyer désigné par `index_foyer`.
    ///
    /// Déchiffre l'archive du foyer, charge les clés en mémoire et instancie
    /// l'Archiviste. Les clés publiques du foyer sont transmises à la session
    /// via le pont interne vers le noyau.
    ///
    /// `interface_feu_application` est utilisée pour collecter le mot de passe.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'index est invalide, si le foyer est déjà ouvert,
    /// si le mot de passe est incorrect, ou si une opération disque échoue.
    pub fn commande_ouverture_foyer(
        &mut self,
        interface_feu_application: &mut impl InterfaceFeuApplication,
        index_foyer: usize,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        let mut recepteur = RecepteurNoyau::new(&mut self.session, interface_feu_application);

        noyau.ouverture_foyer(&mut recepteur, index_foyer)?;

        interface_feu_application.recevoir_session_application(Some(self.session.clone()));

        Ok(())
    }

    /// Ferme le foyer désigné par `index_foyer`.
    ///
    /// Chiffre et archive les données du foyer, efface les clés du trousseau
    /// en mémoire et marque le foyer comme fermé dans la session.
    ///
    /// `interface_feu_application` est utilisée pour collecter le mot de passe.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'index est invalide, si le foyer n'est pas ouvert,
    /// ou si une opération disque échoue.
    pub fn commande_fermeture_foyer(
        &mut self,
        interface_feu_application: &mut impl InterfaceFeuApplication,
        index_foyer: usize,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        let mut recepteur = RecepteurNoyau::new(&mut self.session, interface_feu_application);
        noyau.fermeture_foyer(&mut recepteur, index_foyer)?;

        interface_feu_application.recevoir_session_application(Some(self.session.clone()));

        Ok(())
    }

    /// Ferme en mode secours le foyer désigné par `index_foyer`.
    ///
    /// À utiliser lorsque Feu s'est terminé anormalement avec un foyer ouvert :
    /// le dossier clair est toujours sur disque mais le trousseau a été perdu.
    /// Recharge les clés depuis le dossier clair, puis archive et chiffre le
    /// foyer comme une fermeture normale.
    ///
    /// `interface_feu_application` est utilisée pour collecter le mot de passe.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'index est invalide, si le diagnostic du foyer
    /// détecte une anomalie, si le mot de passe est incorrect, ou si une
    /// opération disque échoue.
    pub fn commande_secours_fermeture_foyer(
        &mut self,
        interface_feu_application: &mut impl InterfaceFeuApplication,
        index_foyer: usize,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        let mut recepteur = RecepteurNoyau::new(&mut self.session, interface_feu_application);
        noyau.secours_fermeture_foyer(&mut recepteur, index_foyer)?;

        interface_feu_application.recevoir_session_application(Some(self.session.clone()));

        Ok(())
    }

    /// Dépose un texte dans un foyer : crée une `EnuT` (une [`Enu`] portant une
    /// `Carte::Texte`), l'accroche sous `enu_racine_depot`, puis propage la
    /// nouvelle racine jusqu'à `enu_racine_noeud`.
    ///
    /// Le texte est embarqué dans la carte (aucun blob, aucun classeur) et borné
    /// en taille. Le détail du rangement est porté par le Scribe.
    ///
    /// # Retour
    ///
    /// La nouvelle ENU racine du nœud, après propagation.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : texte trop long, répertoire d'accueil
    /// invalide, E/S ou signature (notamment si un foyer du chemin reconstruit
    /// est fermé).
    pub fn commande_depot_enu_texte(
        &mut self,
        enu_racine_depot: &Enu,
        enu_racine_noeud: &Enu,
        contenu: &str,
    ) -> ResultFeuApplication<Enu> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(self.scribe.depot_enu_texte(
            noyau,
            &self.session,
            enu_racine_depot,
            enu_racine_noeud,
            contenu,
        )?)
    }

    /// Ouvre un comptoir de dépôt et retourne son identifiant.
    ///
    /// Crée un dossier au `chemin` donné, où l'utilisateur (ou un script, un
    /// agent) dépose librement les fichiers à injecter dans le classeur
    /// `index_classeur` du foyer `index_foyer`. Le contenu n'est rangé et
    /// chiffré qu'à la fermeture, via
    /// [`commande_fermeture_comptoir_depot`](Self::commande_fermeture_comptoir_depot).
    ///
    /// # Retour
    ///
    /// L'identifiant du comptoir, à conserver pour le refermer.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le dossier existe déjà ou ne peut pas être créé.
    pub fn commande_ouverture_comptoir_depot(
        &mut self,
        chemin: PathBuf,
        index_foyer: usize,
        index_classeur: usize,
    ) -> ResultFeuApplication<usize> {
        Ok(self
            .scribe
            .ouverture_comptoir_depot(chemin, index_foyer, index_classeur)?)
    }

    /// Ferme un comptoir de dépôt : range son contenu, le greffe sous
    /// `enu_racine_depot`, puis propage la nouvelle racine jusqu'à `enu_racine_noeud`.
    ///
    /// Parcourt le dossier du comptoir, dépose chaque fichier chiffré dans le
    /// classeur de destination, encapsule fichiers et sous-dossiers dans des ENU
    /// signées, puis ajoute le tout comme enfants de `enu_racine_depot`. Le dossier
    /// physique du comptoir est supprimé à l'issue ; le détail du rangement est
    /// porté par le Scribe.
    ///
    /// # Retour
    ///
    /// La nouvelle ENU racine du nœud — `enu_racine_noeud` inchangé si le
    /// comptoir était vide.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : comptoir invalide, E/S, dépôt de données
    /// ou signature (notamment si un foyer du chemin reconstruit est fermé).
    pub fn commande_fermeture_comptoir_depot(
        &mut self,
        index_comptoir: usize,
        enu_racine_depot: &Enu,
        enu_racine_noeud: &Enu,
    ) -> ResultFeuApplication<Enu> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(self.scribe.fermeture_comptoir_depot(
            noyau,
            &self.session,
            index_comptoir,
            enu_racine_depot,
            enu_racine_noeud,
        )?)
    }

    /// Lit et déchiffre un blob depuis un classeur d'un foyer ouvert.
    ///
    /// Déchiffre `<hash>.dat` avec la clé du classeur (AES-256-GCM) et écrit
    /// le clair dans `destination`. L'intégrité est doublement vérifiée : par le
    /// tag d'authentification AES-GCM, puis par recalcul du hash SHA3-256 du clair,
    /// qui doit correspondre à `hash` — une divergence est traitée comme une
    /// donnée corrompue et retourne une erreur.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont invalides, si le foyer n'est pas ouvert,
    /// si le blob est introuvable, si le déchiffrement échoue, ou si le hash recalculé
    /// ne correspond pas à `hash` (donnée corrompue).
    pub fn commande_lecture_donnees(
        &mut self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
        destination: impl Write,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        noyau.lecture_donnees(index_foyer, index_classeur, hash, destination)?;
        Ok(())
    }

    /// Supprime un blob d'un classeur d'un foyer ouvert.
    ///
    /// Supprime le fichier `<hash>.dat` sur disque. L'opération est irréversible.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont invalides, si le foyer n'est pas ouvert,
    /// ou si la suppression disque échoue.
    pub fn commande_suppression_donnees(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        noyau.suppression_donnees(index_foyer, index_classeur, hash)?;

        Ok(())
    }

    /// Retourne la liste des hashes des blobs présents dans un classeur d'un foyer ouvert.
    ///
    /// L'ordre n'est pas garanti — dépend de l'ordre de lecture du système de fichiers.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont invalides, si le foyer n'est pas ouvert,
    /// ou si la lecture du dossier échoue.
    pub fn commande_liste_blobs(
        &self,
        index_foyer: usize,
        index_classeur: usize,
    ) -> ResultFeuApplication<Vec<String>> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(noyau.liste_blobs(index_foyer, index_classeur)?)
    }

    /// Indique si un blob est présent dans un classeur d'un foyer ouvert.
    ///
    /// Retourne `true` si `classeurN/<hash>.dat` existe sur disque, `false` sinon.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont invalides ou si le foyer n'est pas ouvert.
    pub fn commande_existence_blob(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
    ) -> ResultFeuApplication<bool> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(noyau.existence_blob(index_foyer, index_classeur, hash)?)
    }

    /// Retourne les métadonnées système d'un blob (taille, dates d'accès et de modification).
    ///
    /// Voir [`DonneesBlob`] pour le détail des champs.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont invalides, si le foyer n'est pas ouvert,
    /// ou si le blob est introuvable.
    pub fn commande_information_blob(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
    ) -> ResultFeuApplication<DonneesBlob> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(noyau.informations_blob(index_foyer, index_classeur, hash)?)
    }

    /// Chiffre des octets à destination d'un nœud identifié par sa clé publique ML-KEM-1024.
    ///
    /// Schéma KEM + HKDF + AES-256-GCM. La clé privée du nœud local
    /// n'intervient pas — seule la clé publique du destinataire est nécessaire.
    /// La taille des données est limitée à `MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la taille dépasse la limite ou si le chiffrement échoue.
    pub fn commande_chiffrement_asymetrique(
        &self,
        cle_publique_destinataire: &[u8; 1568],
        octets_a_chiffrer: &[u8],
    ) -> ResultFeuApplication<Vec<u8>> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(noyau.chiffrement_asymetrique(cle_publique_destinataire, octets_a_chiffrer)?)
    }

    /// Déchiffre un message chiffré à destination du foyer désigné.
    ///
    /// Réciproque de [`commande_chiffrement_asymetrique`](Self::commande_chiffrement_asymetrique) —
    /// utilise la clé privée ML-KEM-1024 du foyer, qui doit être ouverte.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'index est invalide, si le foyer n'est pas ouvert,
    /// si la taille dépasse la limite, ou si le déchiffrement échoue.
    pub fn commande_dechiffrement_asymetrique(
        &self,
        index_foyer: usize,
        octets_a_dechiffrer: &[u8],
    ) -> ResultFeuApplication<Vec<u8>> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(noyau.dechiffrement_asymetrique(index_foyer, octets_a_dechiffrer)?)
    }

    /// Signe des octets avec la clé privée ML-DSA-87 du nœud.
    ///
    /// La clé de signature du nœud est l'identité cryptographique racine —
    /// elle signe les IdNU et tout acte engageant le nœud dans sa globalité.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la clé privée du nœud n'est pas disponible.
    pub fn commande_signature_noeud(
        &self,
        octets_a_signer: &[u8],
    ) -> ResultFeuApplication<[u8; 4627]> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(noyau.signature_noeud(octets_a_signer)?)
    }

    /// Signe des octets avec la clé privée ML-DSA-87 du foyer désigné.
    ///
    /// Le foyer doit être ouvert — sa clé privée de signature doit être présente
    /// dans le trousseau.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'index est invalide, si le foyer n'est pas ouvert,
    /// ou si la clé privée est absente.
    pub fn commande_signature_foyer(
        &self,
        index_foyer: usize,
        octets_a_signer: &[u8],
    ) -> ResultFeuApplication<[u8; 4627]> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(noyau.signature_foyer(index_foyer, octets_a_signer)?)
    }

    /// Vérifie une signature ML-DSA-87.
    ///
    /// Retourne `true` si `signature` est une signature valide de `octets_signes`
    /// produite par la clé privée correspondant à `cle_publique`, `false` sinon.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur uniquement si le noyau signale une anomalie interne —
    /// un échec de vérification cryptographique retourne `false`, pas une erreur.
    pub fn commande_verification_signature(
        &self,
        cle_publique: [u8; 2592],
        signature: [u8; 4627],
        octets_signes: &[u8],
    ) -> ResultFeuApplication<bool> {
        Ok(FeuNoyau::verification_signature(
            cle_publique,
            signature,
            octets_signes,
        )?)
    }

    /// Diagnostique la présence et la cohérence des fichiers du nœud.
    ///
    /// Utilisable nœud éteint : le diagnostic s'appuie sur le seul chemin racine,
    /// pas sur une instance de [`FeuNoyau`] allumée. Retourne la liste des
    /// anomalies détectées ; vide si tout est en ordre. Ne peut pas échouer.
    pub fn commande_diagnostic_noeud(&self) -> Vec<Anomalie> {
        FeuNoyau::diagnostic_noeud(&self.chemin_feu)
    }

    /// Diagnostique la présence et la cohérence des fichiers d'un foyer.
    ///
    /// Retourne la liste des anomalies détectées pour le foyer désigné ;
    /// vide si tout est en ordre.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'index est invalide ou si le diagnostic échoue.
    pub fn commande_diagnostic_foyer(
        &self,
        index_foyer: usize,
    ) -> ResultFeuApplication<Vec<Anomalie>> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(noyau.diagnostic_foyer(index_foyer)?)
    }
}
