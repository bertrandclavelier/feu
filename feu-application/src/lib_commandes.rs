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
//! noyau en a besoin, délègue à [`FeuNoyau`] ou au [`Scribe`]
//! et propage les erreurs via [`ErreurFeuApplication`].
//!
//! La précondition commune est l'allumage : hors `commande_allumage_noeud`,
//! `commande_verification_signature` et `commande_diagnostic_noeud`, toute
//! commande retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint.
//!
//! L'interface n'est pas stockée dans [`FeuApplication`] mais fournie à l'appel,
//! comme [`InterfaceFeuNoyau`] dans `feu-noyau`. Elle sert à deux choses :
//! l'interaction utilisateur et la notification de session après mutation — une
//! commande peut n'avoir que la seconde.
//!
//! Les commandes qui ne modifient pas l'état du noyau prennent `&self`, les
//! autres `&mut self`.
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
//! 5. **ENU** — dernière racine, chargement par hash, dépôt d'un texte court,
//!    et les deux parcours (descendance, versions antérieures). La structure,
//!    sans quoi la partie 4 n'aurait rien à désigner.
//!
//! # Désigner une donnée
//!
//! Un nœud ne contient que des **ENU**, qui portent structure et métadonnées, et
//! des **blobs**, contenus chiffrés rangés dans les classeurs.
//!
//! **Au dépôt**, l'appelant donne foyer et classeur : rien n'existe encore, il
//! n'y a pas d'autre façon de dire où ranger.
//!
//! **Ensuite, tout passe par l'ENU, sans exception.** Charger, supprimer,
//! interroger un blob se fait par sa [`Fiche`], jamais par un
//! couple foyer/hash : la carte porte les deux, et les tenir ensemble interdit
//! d'en former une paire incohérente. Le hash d'un blob identifie un fichier, il
//! ne le désigne pas.

use std::io::Write;

use feu_noyau::{Anomalie, DonneesBlob, FeuNoyau, IndexClasseur};

use super::*;
use crate::{
    fiche::Fiche,
    scribe::iterateurs::{Descendants, RacinesAnterieures},
};

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
    /// # Errors
    ///
    /// Retourne une erreur si les fichiers de clés sont absents ou corrompus, si
    /// le mot de passe est incorrect, ou si `phrase_seed` est fournie alors que le
    /// nœud existe déjà.
    pub fn commande_allumage_noeud(
        &mut self,
        interface_feu_application: &impl InterfaceFeuApplication,
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
        self.scribe.activation(&feu_noyau, &mut self.session)?;

        self.feu_noyau = Some(feu_noyau);

        interface_feu_application.recevoir_session_application(Some(self.session.clone()));

        Ok(())
    }

    /// Éteint le nœud : libère [`FeuNoyau`] et réinitialise [`SessionApplication`].
    ///
    /// Symétrique de [`commande_allumage_noeud`](Self::commande_allumage_noeud) :
    /// libère le noyau — donc les clés privées en mémoire —, remet la session à
    /// neuf et désactive le Scribe.
    ///
    /// Les deux moitiés du miroir des comptoirs tombent dans la même commande :
    /// la session neuve vide la liste avant que le Scribe n'oublie la sienne.
    ///
    /// N'écrit rien sur disque : les archives chiffrées ont déjà été produites
    /// par les fermetures préalables.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::AuMoinsUnFoyerOuvert`] si au moins un foyer
    /// est encore ouvert ; [`ErreurFeuApplication::NoeudEteint`] si le nœud n'a
    /// pas été allumé.
    pub fn commande_extinction_noeud(
        &mut self,
        interface_feu_application: &impl InterfaceFeuApplication,
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
    /// **Seule commande de foyer qui ne notifie pas la session** : les clés
    /// publiques ne changent pas, seul le chiffrement qui les protège est
    /// refait, et le miroir reste donc exact.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si un foyer est fermé, si la saisie échoue,
    /// ou si l'écriture du trousseau public échoue.
    pub fn commande_changement_mdp(
        &mut self,
        interface_feu_application: &impl InterfaceFeuApplication,
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
    /// # Errors
    ///
    /// Retourne une erreur si le foyer est déjà ouvert, si le mot de passe est
    /// incorrect, ou si une opération disque échoue.
    pub fn commande_ouverture_foyer(
        &mut self,
        interface_feu_application: &impl InterfaceFeuApplication,
        index_foyer: IndexFoyer,
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
    /// # Errors
    ///
    /// Retourne une erreur si le foyer n'est pas ouvert, ou si une opération
    /// disque échoue.
    pub fn commande_fermeture_foyer(
        &mut self,
        interface_feu_application: &impl InterfaceFeuApplication,
        index_foyer: IndexFoyer,
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
    /// # Errors
    ///
    /// Retourne une erreur si le foyer est marqué ouvert, si le diagnostic du
    /// foyer détecte une anomalie, si le mot de passe est incorrect, ou si une
    /// opération disque échoue.
    pub fn commande_secours_fermeture_foyer(
        &mut self,
        interface_feu_application: &impl InterfaceFeuApplication,
        index_foyer: IndexFoyer,
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
    /// # Errors
    ///
    /// Retourne une erreur si le diagnostic échoue.
    pub fn commande_diagnostic_foyer(
        &self,
        index_foyer: IndexFoyer,
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
    /// # Errors
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
    /// # Errors
    ///
    /// Retourne une erreur si le foyer n'est pas ouvert, si la taille dépasse la
    /// limite, ou si le déchiffrement échoue.
    pub fn commande_dechiffrement_asymetrique(
        &self,
        index_foyer: IndexFoyer,
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
    /// # Errors
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
    /// # Errors
    ///
    /// Retourne une erreur si le foyer n'est pas ouvert, ou si la clé privée est
    /// absente.
    pub fn commande_signature_foyer(
        &self,
        index_foyer: IndexFoyer,
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
    /// # Errors
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
    /// Le Scribe l'inscrit au passage dans la session, dont cette commande envoie
    /// un clone : le retour direct sert l'appelant qui enchaîne, la session celui
    /// qui affiche.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : comptoir de travail ouvert
    /// ([`ErreurFeuApplication::ScribeComptoirTravailOuvert`]), qui leur est
    /// exclusif, dossier déjà existant
    /// ([`ErreurFeuApplication::ScribeDossierDejaExistant`]) ou impossible à
    /// créer. Un échec ne laisse aucun identifiant dans la session — sauf celui
    /// de l'écriture de `scribe.feu`, qui survient le comptoir déjà ouvert. Rien
    /// n'est notifié.
    pub fn commande_ouverture_comptoir_depot(
        &mut self,
        interface_feu_application: &impl InterfaceFeuApplication,
        chemin: &Path,
        index_foyer: IndexFoyer,
        index_classeur: IndexClasseur,
    ) -> ResultFeuApplication<usize> {
        if !self.scribe.est_actif() {
            return Err(ErreurFeuApplication::NoeudEteint);
        }

        let index_comptoir = self.scribe.ouverture_comptoir_depot(
            &mut self.session,
            chemin,
            index_foyer,
            index_classeur,
        )?;

        interface_feu_application.recevoir_session_application(Some(self.session.clone()));

        Ok(index_comptoir)
    }

    /// Ferme un comptoir de dépôt : range son contenu, le greffe sous
    /// `fiche_racine_depot`, puis propage la nouvelle racine jusqu'à la racine du nœud.
    ///
    /// Parcourt le dossier du comptoir, dépose chaque fichier chiffré dans le
    /// classeur de destination, encapsule fichiers et sous-dossiers dans des ENU
    /// signées, puis ajoute le tout comme enfants de `fiche_racine_depot`. Le dossier
    /// physique du comptoir est supprimé à l'issue ; le détail du rangement est
    /// porté par le Scribe.
    ///
    /// # Retour
    ///
    /// Rien : le nouveau sommet du nœud devient la cible de `.DERNIERE_RACINE`,
    /// la racine courante restant inchangée si le comptoir était vide.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : comptoir inconnu
    /// ([`ErreurFeuApplication::ScribeIndexComptoirInconnu`]), dossier du
    /// comptoir disparu ([`ErreurFeuApplication::ScribeDossierDepotIntrouvable`]),
    /// foyer de destination fermé ([`ErreurFeuApplication::ScribeFoyerFerme`]),
    /// racine d'accueil qui
    /// n'est plus la dernière ([`ErreurFeuApplication::ScribeRacinePerimee`]),
    /// répertoire d'accueil absent de l'arbre courant
    /// ([`ErreurFeuApplication::ScribeRemplacementSansEffet`]), E/S, dépôt de
    /// données ou signature (notamment si un foyer du chemin reconstruit est
    /// fermé).
    ///
    /// Seul le foyer fermé est rattrapable : l'identifiant y reste valable, et
    /// la fermeture se retente une fois le foyer rouvert. Tout autre échec
    /// consomme le comptoir et laisse son dossier à l'utilisateur.
    ///
    /// La session suit le sort du comptoir, pas celui de la commande : le Scribe
    /// l'en retire à l'instant où il le lâche lui-même. Le foyer fermé et la
    /// braise introuvable tombent avant ce point et y laissent donc
    /// l'identifiant — ce que la retentative exige. Les échecs plus tardifs
    /// l'ont déjà emporté, le comptoir n'existant plus nulle part.
    pub fn commande_fermeture_comptoir_depot(
        &mut self,
        interface_feu_application: &impl InterfaceFeuApplication,
        index_comptoir: usize,
        fiche_racine_depot: &Fiche,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe.fermeture_comptoir_depot(
            noyau,
            &mut self.session,
            index_comptoir,
            fiche_racine_depot,
        )?;

        interface_feu_application.recevoir_session_application(Some(self.session.clone()));

        Ok(())
    }

    /// Ouvre le comptoir de travail : matérialise le sous-arbre de
    /// `fiche_racine` dans `chemin`, que Feu retient jusqu'à sa fermeture.
    ///
    /// Le dossier est celui du retrait en lecture seule, aux mêmes conditions —
    /// il ne doit pas exister, et tout foyer du sous-arbre doit être ouvert.
    /// Ce qui s'y ajoute est la mémoire du comptoir, que la session rend lisible
    /// à la présentation.
    ///
    /// **Un seul comptoir de travail**, et aucun comptoir de dépôt ouvert en
    /// même temps.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint,
    /// [`ErreurFeuApplication::ScribeComptoirDepotOuvert`] ou
    /// [`ErreurFeuApplication::ScribeComptoirTravailOuvert`] si l'exclusivité
    /// n'est pas tenue. Propage ensuite les erreurs du Scribe : foyers requis
    /// fermés ([`ErreurFeuApplication::ScribeFoyersFermes`], avant toute
    /// écriture), dossier déjà existant, `fiche_racine` qui ne désigne pas un
    /// répertoire, nom absent ou invalide, authentification, E/S ou lecture de
    /// blob. Aucun comptoir n'est retenu si la sortie échoue.
    pub fn commande_ouverture_comptoir_travail(
        &mut self,
        interface_feu_application: &impl InterfaceFeuApplication,
        chemin: &Path,
        fiche_racine: &Fiche,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe
            .ouverture_comptoir_travail(noyau, &mut self.session, chemin, fiche_racine)?;

        interface_feu_application.recevoir_session_application(Some(self.session.clone()));

        Ok(())
    }

    /// Ferme le comptoir de travail ouvert : le sous-arbre est reconstruit
    /// depuis le dossier, qui fait autorité, puis remplace l'ancien.
    ///
    /// Ce qui n'a pas changé sur le disque est réemployé tel quel — même ENU,
    /// même braise, mêmes tags. Une entrée effacée disparaît de l'arbre, une
    /// entrée nouvelle rejoint le foyer de son répertoire d'accueil.
    ///
    /// Le dossier de travail est supprimé une fois le remplacement passé ; un
    /// échec en chemin laisse comptoir et dossier en place.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint,
    /// [`ErreurFeuApplication::ScribePasComptoirTravailOuvert`] si aucun
    /// comptoir de travail n'est ouvert,
    /// [`ErreurFeuApplication::ScribeDossierTravailIntrouvable`] si son dossier
    /// a disparu et [`ErreurFeuApplication::ScribeFoyersFermes`] si un foyer du
    /// sous-arbre est fermé — les trois avant toute écriture. Propage ensuite
    /// les erreurs du Scribe : E/S, dépôt de blob, signature, texte édité trop
    /// grand ou non UTF-8.
    pub fn commande_fermeture_comptoir_travail(
        &mut self,
        interface_feu_application: &impl InterfaceFeuApplication,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe
            .fermeture_comptoir_travail(noyau, &mut self.session)?;

        interface_feu_application.recevoir_session_application(Some(self.session.clone()));

        Ok(())
    }

    /// Matérialise l'arborescence d'une `EnuR` dans un dossier OS, en lecture
    /// seule — opération inverse du dépôt par comptoir.
    ///
    /// Crée le dossier `chemin_retrait`, qui ne doit pas exister, et y reconstruit
    /// ce que décrit `fiche_r` : fichiers depuis les blobs et les textes
    /// embarqués, sous-dossiers depuis les répertoires, chaque ENU authentifiée
    /// avant écriture.
    ///
    /// Sans reprise : Feu écrit puis s'en désintéresse, rien n'est réinjecté.
    ///
    /// **Tout foyer du sous-arbre doit être ouvert** — signature des ENU,
    /// déchiffrement des blobs. Le Scribe en dresse la liste avant d'écrire et
    /// refuse d'un bloc s'il en manque.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : foyers requis fermés
    /// ([`ErreurFeuApplication::ScribeFoyersFermes`], qui les nomme tous, avant
    /// toute écriture), dossier de sortie déjà existant, `fiche_r` qui ne désigne
    /// pas un répertoire, nom absent ou invalide, braise inconnue,
    /// authentification, E/S ou lecture de blob (blob introuvable).
    pub fn commande_retrait_lecture_seule(
        &mut self,
        chemin_retrait: &Path,
        fiche_r: &Fiche,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe
            .retrait_lecture_seule(noyau, &self.session, chemin_retrait, fiche_r)?;

        Ok(())
    }

    //
    // 4. Blobs
    //
    // Le contenu chiffré, un fichier à la fois. Les quatre commandes désignent
    // leur cible par la seule `Fiche`, comme le pose le « Désigner une donnée »
    // du module.
    //

    /// Lit et déchiffre le blob désigné par `fiche`, et écrit le clair dans
    /// `destination`.
    ///
    /// Une [`Carte::Donnee`] ne porte que l'empreinte du blob : la fiche suffit à
    /// le retrouver, sa braise donnant le foyer et sa carte le hash — aucun couple
    /// foyer/hash incohérent ne peut être formé.
    ///
    /// Le classeur reste découvert par le noyau. L'intégrité est doublement
    /// vérifiée : tag AES-GCM, puis recalcul du hash SHA3-256 du clair.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : braise ne résolvant vers aucun foyer
    /// ([`ErreurFeuApplication::ScribeBraiseInconnue`]), carte qui n'est pas une
    /// [`Carte::Donnee`] ([`ErreurFeuApplication::ScribeEnuDAttendue`]), foyer
    /// fermé, blob introuvable, déchiffrement, ou hash recalculé divergent —
    /// donnée corrompue.
    pub fn commande_chargement_blob(
        &mut self,
        fiche: &Fiche,
        destination: impl Write,
    ) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe
            .charge_blob(noyau, &self.session, fiche, destination)?;

        Ok(())
    }

    /// Supprime le blob désigné par `fiche` — le fichier `<hash>.dat` sur disque.
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
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : comptoir de travail ouvert
    /// ([`ErreurFeuApplication::ScribeComptoirTravailOuvert`]), braise ne
    /// résolvant vers aucun foyer
    /// ([`ErreurFeuApplication::ScribeBraiseInconnue`]), carte qui n'est pas une
    /// [`Carte::Donnee`] ([`ErreurFeuApplication::ScribeEnuDAttendue`]), foyer
    /// fermé, blob introuvable, ou échec de la suppression disque.
    pub fn commande_suppression_blob(&mut self, fiche: &Fiche) -> ResultFeuApplication<()> {
        let noyau = self
            .feu_noyau
            .as_mut()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe.supprime_blob(noyau, &self.session, fiche)?;

        Ok(())
    }

    /// Indique si le blob désigné par `fiche` est présent sur disque.
    ///
    /// Une ENU peut survivre à son blob :
    /// [`commande_suppression_blob`](Self::commande_suppression_blob) retire le
    /// `.dat` sans toucher à l'arborescence. C'est ce décalage que cette
    /// commande permet de constater, sans rien déchiffrer.
    ///
    /// L'absence est un `Ok(false)` — la question admet « non » pour réponse.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : braise ne résolvant vers aucun foyer
    /// ([`ErreurFeuApplication::ScribeBraiseInconnue`]), carte qui n'est pas une
    /// [`Carte::Donnee`] ([`ErreurFeuApplication::ScribeEnuDAttendue`]), foyer
    /// fermé.
    pub fn commande_existence_blob(&self, fiche: &Fiche) -> ResultFeuApplication<bool> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe.existence_blob(noyau, &self.session, fiche)
    }

    /// Retourne les métadonnées système du blob désigné par `fiche` — taille,
    /// dates d'accès et de modification.
    ///
    /// Voir [`DonneesBlob`] pour le détail des champs. Renseigne sur le fichier,
    /// jamais sur son contenu : rien n'est déchiffré.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : braise ne résolvant vers aucun foyer
    /// ([`ErreurFeuApplication::ScribeBraiseInconnue`]), carte qui n'est pas une
    /// [`Carte::Donnee`] ([`ErreurFeuApplication::ScribeEnuDAttendue`]), foyer
    /// fermé, blob introuvable — ici une erreur, contrairement à
    /// [`commande_existence_blob`](Self::commande_existence_blob).
    pub fn commande_informations_blob(&self, fiche: &Fiche) -> ResultFeuApplication<DonneesBlob> {
        let noyau = self
            .feu_noyau
            .as_ref()
            .ok_or(ErreurFeuApplication::NoeudEteint)?;

        self.scribe.informations_blob(noyau, &self.session, fiche)
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
    /// permet la descente. Ce sont les deux seules à produire une fiche sans en
    /// recevoir une — les parcours, eux, partent d'une fiche existante. Sans
    /// elles, [`commande_fermeture_comptoir_depot`](Self::commande_fermeture_comptoir_depot)
    /// et [`commande_retrait_lecture_seule`](Self::commande_retrait_lecture_seule),
    /// qui en réclament une, restaient inappelables depuis la présentation.
    ///
    /// Ne demande rien au noyau : la racine se lit sur le disque. Sa garde porte
    /// donc sur l'activation du Scribe, pas sur la présence du noyau.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : lien `.DERNIERE_RACINE` absent, lecture,
    /// authentification.
    pub fn commande_derniere_enu_racine(&self) -> ResultFeuApplication<Fiche> {
        if !self.scribe.est_actif() {
            return Err(ErreurFeuApplication::NoeudEteint);
        }

        Ok(Fiche::new(&self.scribe.derniere_enu_racine(&self.session)?))
    }

    /// Charge l'ENU désignée par `hash`, authentifiée — `None` si aucune ne
    /// porte ce hash.
    ///
    /// Assure la descente : une [`Carte::Repertoire`] ne référence ses enfants que
    /// par leur hash.
    ///
    /// L'absence est un `None`, pas une erreur — le hash vient de l'appelant, ne
    /// pas le trouver est une réponse. D'où la garde : sans elle, un hash inconnu
    /// sur un nœud éteint rendrait `Ok(None)`, réponse d'un nœud allumé.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : lecture, authentification.
    pub fn commande_chargement_enu(&self, hash: &[u8; 32]) -> ResultFeuApplication<Option<Fiche>> {
        if !self.scribe.est_actif() {
            return Err(ErreurFeuApplication::NoeudEteint);
        }

        self.scribe.charge_enu(&self.session, hash)
    }

    /// Dépose un texte dans un foyer : crée une `EnuT` (une ENU portant une
    /// `Carte::Texte`), l'accroche sous `fiche_racine_depot`, puis propage la
    /// nouvelle racine jusqu'à la racine du nœud.
    ///
    /// Le texte est embarqué dans la carte — aucun blob, aucun classeur — et borné
    /// en taille ; `nom` nommera le fichier au retrait, validé comme composant de
    /// chemin dès la construction.
    ///
    /// `index_foyer` est le foyer signataire, `fiche_racine_depot` un répertoire
    /// de foyer ou la racine du nœud. Tout foyer concerné, y compris ceux du
    /// chemin remonté, doit être ouvert.
    ///
    /// # Retour
    ///
    /// Rien : le nouveau sommet du nœud devient la cible de `.DERNIERE_RACINE`.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud est éteint, et
    /// propage les erreurs du Scribe : comptoir de travail ouvert
    /// ([`ErreurFeuApplication::ScribeComptoirTravailOuvert`]), qui verrouille
    /// l'arborescence, texte trop long
    /// ([`ErreurFeuApplication::ScribeTailleMaxDepasseeTexte`]), nom invalide
    /// ([`ErreurFeuApplication::ScribeNomFichierInvalide`]), répertoire
    /// d'accueil invalide ([`ErreurFeuApplication::ScribeEnuRAttendue`]), racine
    /// d'accueil qui n'est plus la dernière
    /// ([`ErreurFeuApplication::ScribeRacinePerimee`]), répertoire d'accueil
    /// absent de l'arbre courant
    /// ([`ErreurFeuApplication::ScribeRemplacementSansEffet`]), E/S ou signature
    /// (notamment si un foyer du chemin reconstruit est fermé).
    pub fn commande_depot_enu_texte(
        &self,
        fiche_racine_depot: &Fiche,
        index_foyer: IndexFoyer,
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
            fiche_racine_depot,
            index_foyer,
            nom,
            contenu,
        )?;

        Ok(())
    }

    /// Rend un itérateur sur tout le sous-arbre situé sous `fiche`, celle-ci
    /// comprise.
    ///
    /// Chaque item est la [`Fiche`] d'une ENU **intègre mais non authentifiée**,
    /// avec sa profondeur, ou l'erreur rencontrée en la chargeant — un échec ne
    /// met pas fin au parcours. La descendance tient par le chaînage de Merkle,
    /// ce qui rend praticable un arbre entier ; voir [`Descendants`] pour l'ordre
    /// et les doublons.
    ///
    /// **Aucun foyer n'a besoin d'être ouvert** : afficher une arborescence est
    /// une navigation, et rien de ce qui en sort ne donne accès aux blobs.
    /// L'emprunt de `&self` court tant que vit l'itérateur.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud n'est pas
    /// allumé — seul refus possible. Une enveloppe qui ne s'accorde pas avec sa
    /// carte se voit au premier `next`, rendue comme item.
    pub fn commande_descendants<'a>(
        &'a self,
        fiche: &Fiche,
    ) -> ResultFeuApplication<Descendants<'a>> {
        if !self.scribe.est_actif() {
            return Err(ErreurFeuApplication::NoeudEteint);
        }

        Ok(self.scribe.donne_descendants(&fiche.hash_carte()))
    }

    /// Rend un itérateur sur les racines du nœud, de `fiche` jusqu'à la genèse,
    /// celle-ci comprise.
    ///
    /// Répond à « qu'y avait-il avant ? » : chaque item est la [`Fiche`] d'une
    /// racine **authentifiée**. Composé avec
    /// [`commande_descendants`](Self::commande_descendants), il dit ce que l'arbre
    /// contenait à cette version-là.
    ///
    /// Un échec met fin au parcours : la lignée est une chaîne, et la racine
    /// précédente n'est connue que par celle qu'on vient de lire.
    ///
    /// Aucun foyer n'a besoin d'être ouvert : les racines sont signées par le
    /// nœud, dont la session tient la clé publique dès l'allumage.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuApplication::NoeudEteint`] si le nœud n'est pas
    /// allumé — sans la clé publique du nœud, chaque racine échouerait en
    /// authentification, ce qui ne dirait pas à l'appelant ce qui manque.
    pub fn commande_racines_anterieures<'a>(
        &'a self,
        fiche: &Fiche,
    ) -> ResultFeuApplication<RacinesAnterieures<'a>> {
        if !self.scribe.est_actif() {
            return Err(ErreurFeuApplication::NoeudEteint);
        }

        Ok(self
            .scribe
            .donne_racines_anterieures(&self.session, &fiche.hash_carte()))
    }
}
