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
//! noyau en a besoin, délègue à [`FeuNoyau`] ou au [`Scribe`](crate::scribe::Scribe)
//! et propage les erreurs via [`ErreurFeuApplication`].
//!
//! La précondition commune est l'allumage : hors `commande_allumage_noeud`,
//! `commande_verification_signature` et `commande_diagnostic_noeud`, toute
//! commande retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint.
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
//!
//! # Les cinq parties
//!
//! Le fichier suit cet ordre, du socle vers ce qu'il porte. Rustdoc, lui,
//! reclasse tout par ordre alphabétique : ces parties ne se lisent que dans la
//! source, d'où ce sommaire.
//!
//! 1. **Gestion du foyer** — allumage, extinction, mot de passe, cycle des
//!    foyers, diagnostic. L'état que tout le reste suppose.
//! 2. **Cryptographie** — chiffrement asymétrique, signatures, vérification.
//!    Des primitives sur les octets de l'appelant, sans lien avec le stockage.
//! 3. **Dépôt et retrait** — comptoir et retrait en lecture seule, les deux sens
//!    du passage entre un dossier de l'OS et le nœud, par arborescences entières.
//! 4. **Blobs** — chargement, suppression, existence, informations : le contenu
//!    chiffré, un fichier à la fois.
//! 5. **ENU** — dernière racine, chargement par hash, dépôt d'un texte court.
//!    La structure, sans quoi la partie 4 n'aurait rien à désigner.
//!
//! # Désigner une donnée
//!
//! Un nœud ne contient que deux sortes de fichiers : les **ENU**, qui portent
//! la structure et les métadonnées, et les **blobs**, qui portent les contenus
//! chiffrés dans les classeurs. « Blob » est le terme officiel du projet pour
//! ces derniers.
//!
//! **Au dépôt**, l'appelant donne le foyer et le classeur : rien n'existe
//! encore, il n'y a pas d'autre façon de dire où ranger.
//!
//! **Ensuite, tout passe par l'ENU, sans exception.** Charger, supprimer,
//! interroger un blob se fait en fournissant son [`Enu`], jamais un couple
//! foyer/hash — l'ENU porte les deux (braise et `hash_donnee`), et les tenir
//! ensemble interdit d'en former une paire incohérente. Pas d'ENU, pas de
//! donnée.
//!
//! Rien ici n'accepte donc un hash de blob, ni n'en énumère : de l'extérieur,
//! les seuls hashs qui ouvrent quelque chose sont ceux des ENU
//! ([`commande_chargement_enu`](FeuApplication::commande_chargement_enu)). Celui d'un
//! blob reste lisible dans une [`Carte::Donnee`], mais il n'identifie que le
//! fichier — il ne le désigne pas.

use std::io::Write;

use feu_noyau::{Anomalie, DonneesBlob, FeuNoyau};

use crate::scribe::enu::Enu;

use super::*;

impl FeuApplication {
    //
    // 1. Gestion du foyer
    //
    // Allumage et extinction du nœud, cycle des foyers, diagnostic. Tout le
    // reste du fichier suppose cet état posé.
    //

    /// Initialise ou allume le nœud et stocke l'instance dans [`FeuApplication`].
    ///
    /// Délègue à [`FeuNoyau::new`] qui détecte automatiquement l'état du nœud :
    /// initialisation si `~/.feu` est absent, allumage sinon. Active ensuite le
    /// Scribe — qui, à la toute première activation, amorce l'arborescence ENU
    /// (racine origine signée par le nœud, symlink `.DERNIERE_RACINE`).
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
        let feu_noyau = {
            let mut recepteur_noyau =
                RecepteurNoyau::new(&mut self.session, interface_feu_application);
            FeuNoyau::new(&self.chemin_feu, phrase_seed, &mut recepteur_noyau)?
        };

        // le Scribe est activé avant de ranger le noyau dans `self` : l'amorce
        // de l'arborescence (signature de la racine origine) a besoin d'une
        // référence au noyau, plus simple à prendre tant qu'il est local
        self.scribe.activation(&feu_noyau, &self.session)?;

        self.feu_noyau = Some(feu_noyau);

        interface_feu_application.recevoir_session_application(Some(self.session.clone()));

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

    //
    // 2. Cryptographie
    //
    // Primitives offertes telles quelles à l'appelant, sur des octets qu'il
    // fournit. Rien ici ne touche à l'arborescence ni aux classeurs.
    //

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

    //
    // 3. Dépôt et retrait
    //
    // Les deux sens du passage entre un dossier de l'OS et le nœud. Seules
    // commandes qui traitent une arborescence entière d'un bloc.
    //

    /// Ouvre un comptoir de dépôt et retourne son identifiant.
    ///
    /// Crée un dossier au `chemin` donné, où l'utilisateur (ou un script, un
    /// agent) dépose librement les fichiers à injecter dans le classeur
    /// `index_classeur` du foyer `index_foyer`. Le contenu n'est rangé et
    /// chiffré qu'à la fermeture, via
    /// [`commande_fermeture_comptoir_depot`](Self::commande_fermeture_comptoir_depot).
    ///
    /// Ne demandant rien au noyau, sa garde porte sur l'activation du Scribe.
    /// Elle refuse malgré tout nœud éteint : la fermeture, elle, exige le noyau
    /// — un comptoir ouvert sans lui resterait sur le disque, intraitable.
    ///
    /// # Retour
    ///
    /// L'identifiant du comptoir, à conserver pour le refermer — valable tant
    /// que le nœud reste allumé, l'extinction l'annulant définitivement.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : dossier déjà existant ou impossible à
    /// créer.
    pub fn commande_ouverture_comptoir_depot(
        &mut self,
        chemin: &Path,
        index_foyer: usize,
        index_classeur: usize,
    ) -> ResultFeuApplication<usize> {
        if !self.scribe.est_actif() {
            return Err(ErreurFeuApplication::NoeudEteint);
        }

        Ok(self
            .scribe
            .ouverture_comptoir_depot(chemin, index_foyer, index_classeur)?)
    }

    /// Ferme un comptoir de dépôt : range son contenu, le greffe sous
    /// `enu_racine_depot`, puis propage la nouvelle racine jusqu'à la racine du nœud.
    ///
    /// Parcourt le dossier du comptoir, dépose chaque fichier chiffré dans le
    /// classeur de destination, encapsule fichiers et sous-dossiers dans des ENU
    /// signées, puis ajoute le tout comme enfants de `enu_racine_depot`. Le dossier
    /// physique du comptoir est supprimé à l'issue ; le détail du rangement est
    /// porté par le Scribe.
    ///
    /// # Retour
    ///
    /// Rien : le nouveau sommet du nœud devient la cible de `.DERNIERE_RACINE`,
    /// la racine courante restant inchangée si le comptoir était vide.
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
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe.fermeture_comptoir_depot(
            noyau,
            &self.session,
            index_comptoir,
            enu_racine_depot,
        )?;

        Ok(())
    }

    /// Matérialise l'arborescence d'une `EnuR` dans un dossier OS, en lecture
    /// seule — opération inverse du dépôt par comptoir.
    ///
    /// Crée le dossier `chemin_retrait` (qui ne doit pas exister) et y
    /// reconstruit ce que décrit `enu_r` : fichiers depuis les blobs déchiffrés
    /// et les textes embarqués, sous-dossiers depuis les répertoires. Chaque ENU
    /// est authentifiée avant d'être écrite. Le détail est porté par le Scribe.
    ///
    /// Sans reprise : Feu écrit le dossier puis s'en désintéresse — aucune
    /// fermeture, rien n'est réinjecté dans le nœud. Tout foyer signataire d'un
    /// blob rencontré doit être **ouvert** pour le déchiffrement.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : dossier de sortie déjà existant, `enu_r`
    /// qui n'est pas un répertoire, nom absent ou invalide, braise inconnue,
    /// authentification, E/S ou lecture de blob (foyer fermé, blob introuvable).
    pub fn commande_retrait_lecture_seule(
        &mut self,
        chemin_retrait: &Path,
        enu_r: &Enu,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe
            .retrait_lecture_seule(noyau, &self.session, chemin_retrait, enu_r)?;

        Ok(())
    }

    //
    // 4. Blobs
    //
    // Le contenu chiffré, un fichier à la fois. Les quatre commandes désignent
    // leur cible par la seule `Enu`, comme le pose le « Désigner une donnée »
    // du module.
    //

    /// Lit et déchiffre le blob désigné par `enu`, et écrit le clair dans
    /// `destination`.
    ///
    /// Dernier maillon de la descente ouverte par
    /// [`commande_derniere_enu_racine`](Self::commande_derniere_enu_racine) :
    /// une [`Carte::Donnee`] ne porte que l'empreinte du blob, jamais ses
    /// octets. L'ENU suffit à la retrouver — sa braise donne le foyer, sa carte
    /// donne le hash. Rien n'est demandé à l'appelant qu'il aurait à extraire
    /// lui-même, et aucun couple foyer/hash incohérent ne peut être formé.
    ///
    /// Le classeur, lui, reste découvert par le noyau (balayage sur le hash,
    /// content-addressed). L'intégrité est doublement vérifiée : par le tag
    /// d'authentification AES-GCM, puis par recalcul du hash SHA3-256 du clair.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : braise ne résolvant vers aucun foyer
    /// (`SCR-004`), carte qui n'est pas une [`Carte::Donnee`] (`SCR-005`), foyer
    /// fermé, blob introuvable, déchiffrement, ou hash recalculé divergent —
    /// donnée corrompue.
    pub fn commande_chargement_blob(
        &mut self,
        enu: &Enu,
        destination: impl Write,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe
            .charge_blob(noyau, &self.session, enu, destination)?;

        Ok(())
    }

    /// Supprime le blob désigné par `enu` — le fichier `<hash>.dat` sur disque.
    /// L'opération est irréversible.
    ///
    /// Symétrique de
    /// [`commande_chargement_blob`](Self::commande_chargement_blob) et
    /// désignant sa cible de la même façon : par l'ENU seule, dont la braise
    /// donne le foyer et la carte le hash. Le classeur est découvert par
    /// balayage côté noyau, l'appelant n'a donc rien à en connaître.
    ///
    /// Ne touche pas à l'ENU elle-même, qui continue de référencer un blob
    /// désormais absent.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : braise ne résolvant vers aucun foyer
    /// (`SCR-004`), carte qui n'est pas une [`Carte::Donnee`] (`SCR-005`), foyer
    /// fermé, blob introuvable, ou échec de la suppression disque.
    pub fn commande_suppression_blob(&mut self, enu: &Enu) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe.supprime_blob(noyau, &self.session, enu)?;

        Ok(())
    }

    /// Indique si le blob désigné par `enu` est présent sur disque.
    ///
    /// Une ENU peut survivre à son blob :
    /// [`commande_suppression_blob`](Self::commande_suppression_blob) retire le
    /// `.dat` sans toucher à l'arborescence. C'est ce décalage que cette
    /// commande permet de constater, sans rien déchiffrer.
    ///
    /// L'absence est un `Ok(false)` — la question admet « non » pour réponse.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : braise ne résolvant vers aucun foyer
    /// (`SCR-004`), carte qui n'est pas une [`Carte::Donnee`] (`SCR-005`), foyer
    /// fermé.
    pub fn commande_existence_blob(&self, enu: &Enu) -> ResultFeuApplication<bool> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(self.scribe.existence_blob(noyau, &self.session, enu)?)
    }

    /// Retourne les métadonnées système du blob désigné par `enu` — taille,
    /// dates d'accès et de modification.
    ///
    /// Voir [`DonneesBlob`] pour le détail des champs. Renseigne sur le fichier,
    /// jamais sur son contenu : rien n'est déchiffré.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : braise ne résolvant vers aucun foyer
    /// (`SCR-004`), carte qui n'est pas une [`Carte::Donnee`] (`SCR-005`), foyer
    /// fermé, blob introuvable — ici une erreur, contrairement à
    /// [`commande_existence_blob`](Self::commande_existence_blob).
    pub fn commande_informations_blob(&self, enu: &Enu) -> ResultFeuApplication<DonneesBlob> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        Ok(self.scribe.informations_blob(noyau, &self.session, enu)?)
    }

    //
    // 5. ENU
    //
    // La structure : le sommet, la descente d'un cran, et le dépôt d'un texte
    // court porté par l'ENU elle-même. C'est ce qui rend la partie 4 adressable.
    //

    /// Retourne le sommet courant de l'arborescence, authentifié.
    ///
    /// Avec [`commande_chargement_enu`](Self::commande_chargement_enu), forme la porte
    /// d'entrée de la couche ENU : celle-ci donne le point de départ, l'autre
    /// permet la descente. Aucune autre commande ne produit d'[`Enu`] — sans
    /// elles, [`commande_fermeture_comptoir_depot`](Self::commande_fermeture_comptoir_depot)
    /// et [`commande_retrait_lecture_seule`](Self::commande_retrait_lecture_seule),
    /// qui en réclament une, restaient inappelables depuis la présentation.
    ///
    /// Ne demande rien au noyau : la racine se lit sur le disque. Sa garde porte
    /// donc sur l'activation du Scribe, pas sur la présence du noyau.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : lien `.DERNIERE_RACINE` absent, lecture,
    /// authentification.
    pub fn commande_derniere_enu_racine(&self) -> ResultFeuApplication<Enu> {
        if !self.scribe.est_actif() {
            return Err(ErreurFeuApplication::NoeudEteint);
        }

        Ok(self.scribe.derniere_enu_racine(&self.session)?)
    }

    /// Charge l'[`Enu`] désignée par `hash`, authentifiée — `None` si aucune ne
    /// porte ce hash.
    ///
    /// Assure la descente de l'arborescence : une [`Carte::Repertoire`] ne
    /// référence ses enfants que par leur hash, à recharger un à un depuis le
    /// sommet obtenu par
    /// [`commande_derniere_enu_racine`](Self::commande_derniere_enu_racine).
    ///
    /// L'absence est un `None` et non une erreur : le hash vient de l'appelant,
    /// ne pas le trouver est une réponse. Les erreurs restent réservées à ce qui
    /// a mal tourné — lecture ou authentification. C'est ce qui rend la garde
    /// nécessaire : sans elle, un hash inconnu sur un nœud éteint répondrait
    /// `Ok(None)`, réponse normale d'un nœud qui n'est pas allumé.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : lecture, authentification.
    pub fn commande_chargement_enu(&self, hash: &[u8; 32]) -> ResultFeuApplication<Option<Enu>> {
        if !self.scribe.est_actif() {
            return Err(ErreurFeuApplication::NoeudEteint);
        }

        Ok(self.scribe.charge_enu(&self.session, hash)?)
    }

    /// Dépose un texte dans un foyer : crée une `EnuT` (une [`Enu`] portant une
    /// `Carte::Texte`), l'accroche sous `enu_racine_depot`, puis propage la
    /// nouvelle racine jusqu'à la racine du nœud.
    ///
    /// Le texte est embarqué dans la carte (aucun blob, aucun classeur) et borné
    /// en taille. `nom` nommera le fichier lors d'un retrait sur disque — il est
    /// validé comme composant de chemin dès la construction. Le détail du
    /// rangement est porté par le Scribe.
    ///
    /// `index_foyer` désigne le foyer sous la braise duquel le texte est signé ;
    /// `enu_racine_depot` peut être un répertoire de foyer ou la racine du nœud.
    /// Tout foyer concerné — celui du texte, celui du répertoire d'accueil s'il
    /// en a un, ceux du chemin remonté — doit être ouvert.
    ///
    /// # Retour
    ///
    /// Rien : le nouveau sommet du nœud devient la cible de `.DERNIERE_RACINE`.
    ///
    /// # Erreurs
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : texte trop long, nom invalide,
    /// `index_foyer` hors bornes, répertoire d'accueil invalide, E/S ou
    /// signature (notamment si un foyer du chemin reconstruit est fermé).
    pub fn commande_depot_enu_texte(
        &mut self,
        enu_racine_depot: &Enu,
        index_foyer: usize,
        nom: &str,
        contenu: &str,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe.depot_enu_texte(
            noyau,
            &self.session,
            enu_racine_depot,
            index_foyer,
            nom,
            contenu,
        )?;

        Ok(())
    }
}
