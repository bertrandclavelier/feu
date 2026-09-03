// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! `feu-noyau` est le cœur du protocole Feu.
//!
//! Il expose une interface unique — la structure [`FeuNoyau`] — qui orchestre
//! l'ensemble des composants internes :
//!
//! - le **gardien**, responsable des données locales du nœud (fichiers, clés,
//!   configuration, archivage/désarchivage chiffré des foyers) ;
//! - le **cryptographe**, garant de la sécurité cryptographique (trousseau,
//!   clés, chiffrement symétrique et asymétrique, signatures, dérivation) ;
//! - les **archivistes**, un par foyer ouvert, responsables de l'arborescence
//!   interne d'un foyer (registre + classeurs) et de l'écriture/lecture des
//!   blobs chiffrés.
//!
//! Aucun composant interne n'est accessible directement depuis l'extérieur
//! du crate. Toute interaction avec le noyau passe par [`FeuNoyau`] — cette
//! centralisation est un invariant de sécurité fondamental du protocole.
//!
//! # Plateformes supportées
//!
//! Linux et macOS uniquement. Le protocole repose sur des primitives
//! Unix — système de fichiers, variables d'environnement, permissions —
//! qui n'ont pas d'équivalent direct sous Windows.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("feu-noyau only supports Linux and macOS.");

mod archiviste;
mod cryptographe;
mod erreur;
mod gardien;
mod types;

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use secrecy::SecretString;
pub use types::{Braise, IndexClasseur, IndexFoyer};

pub use crate::erreur::{ErreurFeuNoyau, ResultFeuNoyau};
use crate::{archiviste::Archiviste, cryptographe::Cryptographe, gardien::Gardien};

/// Nombre de foyers d'un nœud — exposé au dehors par [`IndexFoyer::NOMBRE`].
const NOMBRE_FOYERS: usize = 3;

/// Nombre de classeurs d'un foyer — exposé au dehors par [`IndexClasseur::NOMBRE`].
const NOMBRE_CLASSEURS: usize = 5;

/// Taille maximum d'un blob — 512 Mio.
///
/// **Borne incluse**, comme les deux `MAX_TAILLE_*` qui suivent : un blob de
/// cette taille exacte passe, la garde est un `>` strict. Une taille est une
/// quantité, pas un cardinal d'index — le `>=` de [`IndexFoyer::NOMBRE`] et
/// [`IndexClasseur::NOMBRE`], où l'index valide s'arrête à `NOMBRE - 1`, ne
/// s'applique pas ici.
pub const MAX_TAILLE_BLOB: usize = 512 * 1024 * 1024;

/// Taille maximum d'un message à chiffrer via ML-KEM-1024 + AES-256-GCM — 1 Mio.
///
/// Borne incluse. Le déchiffrement accepte la même valeur augmentée du surcoût
/// KEM (1596 octets), sans quoi un message chiffré à la taille maximale ne
/// serait pas déchiffrable.
pub const MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE: usize = 1024 * 1024;

/// Taille maximum d'un message à signer — 64 Kio.
///
/// Borne incluse.
pub const MAX_TAILLE_SIGNATURE: usize = 64 * 1024;

/// Taille du tampon de lecture d'un blob — 8 Kio.
///
/// Le [`Tiroir`](archiviste::tiroir::Tiroir) lit sa source par tranches de cette
/// taille plutôt que d'un coup : un blob va jusqu'à [`MAX_TAILLE_BLOB`], que la
/// pile ne tiendrait pas.
pub(crate) const TAILLE_CHUNK: usize = 8 * 1024;

/// Contrat de communication entre `feu-noyau` et toute interface utilisateur.
///
/// Canal d'échange entre le cœur du protocole et sa couche de présentation —
/// CLI, TUI ou application. Deux sens.
///
/// **Entrées** : `demander_mdp`. Collecter le mot de passe est une
/// responsabilité du noyau, seul à savoir quand il en a besoin, ce qui réduit
/// sa fenêtre d'exposition en mémoire.
///
/// **Notifications** : seed à l'initialisation, clé publique du nœud à
/// l'allumage, clés publiques des foyers à leur ouverture — ce que l'interface
/// ne peut pas observer autrement. Elle en fait ce qu'elle veut.
pub trait InterfaceFeuNoyau {
    /// Collecte le mot de passe Feu en masquant la saisie.
    ///
    /// Retourne `None` en cas d'erreur de lecture (stdin fermé, terminal
    /// non interactif). Le noyau retourne une erreur immédiatement — la
    /// politique de retry est à la charge de la couche appelante.
    ///
    /// Le mot de passe est encapsulé dans [`SecretString`] dès réception
    /// et zéroïsé automatiquement au drop.
    fn demander_mdp(&self) -> Option<SecretString>;

    /// Transmet les mots de la seed mnémotechnique BIP39 à l'interface.
    ///
    /// Appelée une seule fois à l'initialisation du nœud, avant zéroïsation
    /// de la seed. Les `&str` empruntent directement la mémoire de la
    /// [`Mnemonic`](bip39::Mnemonic) — aucune copie n'est effectuée par le noyau.
    /// L'interface est responsable de l'affichage et de toute copie temporaire.
    fn recevoir_seed(&mut self, mots: &[&str]);

    /// Demande à l'interface de confirmer que la seed a bien été enregistrée.
    ///
    /// Appelée immédiatement après [`recevoir_seed`](Self::recevoir_seed),
    /// tant que la seed est encore en mémoire. Si `false`, le noyau interrompt
    /// l'initialisation. L'interface décide du mode de confirmation — ressaisie,
    /// case à cocher, ou autre.
    fn confirmer_enregistrement_seed(&self) -> bool;

    /// Notifie l'interface de l'adresse `.braise` d'un foyer.
    ///
    /// Appelée à l'allumage du nœud pour chaque foyer présent dans
    /// `noyau.feu`, et à l'initialisation pour chaque foyer créé. Permet à
    /// l'interface de construire un index stable `index_foyer → braise` sans
    /// avoir à inspecter la configuration elle-même.
    fn recevoir_braise_foyer(&mut self, index_foyer: IndexFoyer, braise: Braise);

    /// Notifie l'interface d'un changement d'état d'ouverture d'un foyer.
    ///
    /// Appelée à la fin d'une ouverture ou d'une fermeture réussie — `etat`
    /// est `true` quand le foyer vient d'être ouvert, `false` quand il vient
    /// d'être fermé. L'interface peut ainsi refléter en temps réel l'état
    /// d'ouverture sans interroger le noyau.
    fn recevoir_etat_foyer(&mut self, index_foyer: IndexFoyer, etat: bool);

    /// Notifie l'interface de la clé publique de signature du nœud.
    ///
    /// Appelée à l'allumage du nœud, après lecture du trousseau public
    /// depuis le disque. Cette clé ML-DSA-87 est l'identité cryptographique
    /// du nœud.
    fn recevoir_cle_publique_noeud(&mut self, cle_publique_sig_noeud: [u8; 2592]);

    /// Notifie l'interface des clés publiques d'un foyer à son ouverture.
    ///
    /// Appelée après lecture du trousseau public du foyer depuis le disque,
    /// avant chargement des clés privées en mémoire.
    /// - `cle_publique_sig` — clé de signature ML-DSA-87 du foyer.
    /// - `cle_publique_chif` — clé de chiffrement ML-KEM-1024 du foyer.
    fn recevoir_cles_publiques_foyer(
        &mut self,
        index_foyer: IndexFoyer,
        cle_publique_sig: [u8; 2592],
        cle_publique_chif: [u8; 1568],
    );
}

/// Métadonnées système d'un blob chiffré.
///
/// Restitue les informations fournies par l'OS sur le fichier `.dat` correspondant
/// au blob. Les données sont brutes — aucune conversion n'est effectuée par le noyau.
pub struct DonneesBlob {
    /// Taille du `.dat` en octets — celle du chiffré, donc supérieure au clair.
    taille: u64,
    /// `None` sur les systèmes qui ne la tiennent pas : Linux n'a pas de date de
    /// création portable.
    date_creation: Option<SystemTime>,
    /// Dernière écriture du `.dat`.
    date_derniere_modification: SystemTime,
    /// Dernière lecture du `.dat`.
    date_dernier_acces: SystemTime,
}

/// Anomalie détectée lors d'un diagnostic du nœud ou d'un foyer.
///
/// Retournée dans un [`Vec`] par [`FeuNoyau::diagnostic_noeud`] et
/// [`FeuNoyau::diagnostic_foyer`] — un vecteur vide signifie que la cible
/// diagnostiquée est dans un état nominal.
pub enum Anomalie {
    /// Un fichier ou dossier attendu est absent du système de fichiers.
    ElementAbsent(PathBuf),
    /// `noyau.feu` est présent mais son contenu ne peut pas être parsé.
    ConfigurationIllisible,

    /// Une archive `.tar` subsiste alors qu'elle n'est qu'une forme de passage
    /// entre le dossier clair d'un foyer et son archive chiffrée. Sa présence
    /// au repos atteste d'une ouverture ou d'une fermeture interrompue. Le
    /// fichier ne porte aucune donnée qui ne soit ailleurs : il se supprime.
    ArchiveIntermediaireResiduelle(PathBuf),

    /// Un foyer existe à la fois en clair et sous forme chiffrée : la fermeture
    /// a chiffré l'archive puis échoué avant d'effacer le dossier clair. Le
    /// chemin porté est celui du dossier clair — l'archive est complète, et le
    /// clair est le seul des deux qu'on puisse supprimer sans rien perdre.
    FoyerClairEtArchive(PathBuf),
}

impl DonneesBlob {
    /// Construit un [`DonneesBlob`] à partir des métadonnées collectées par l'Archiviste.
    pub(crate) fn new(
        taille: u64,
        date_creation: Option<SystemTime>,
        date_derniere_modification: SystemTime,
        date_dernier_acces: SystemTime,
    ) -> Self {
        Self {
            taille,
            date_creation,
            date_derniere_modification,
            date_dernier_acces,
        }
    }

    /// Retourne la taille du blob en octets.
    pub fn donne_taille(&self) -> u64 {
        self.taille
    }

    /// Retourne la date de création du fichier, si le système de fichiers la supporte.
    ///
    /// `None` sur les systèmes où `created()` n'est pas disponible (certains Linux).
    pub fn donne_date_creation(&self) -> Option<SystemTime> {
        self.date_creation
    }

    /// Retourne la date de dernière modification du fichier.
    pub fn donne_date_derniere_modification(&self) -> SystemTime {
        self.date_derniere_modification
    }

    /// Retourne la date de dernier accès au fichier.
    pub fn donne_date_dernier_acces(&self) -> SystemTime {
        self.date_dernier_acces
    }
}

/// État d'un foyer dans la session courante.
struct Foyer {
    /// Adresse `.braise` du foyer, dérivée à l'allumage et fixe ensuite.
    braise: Braise,
    /// `true` entre l'ouverture et la fermeture : le dossier clair existe et les
    /// clés sont en mémoire.
    est_ouvert: bool,
}

impl Foyer {
    /// Crée un [`Foyer`] avec l'adresse `.braise` et l'état d'ouverture fournis.
    fn new(braise: Braise, est_ouvert: bool) -> Self {
        Self { braise, est_ouvert }
    }
}

/// État de la session courante — foyers ouverts et leurs adresses `.braise`.
///
/// Maintient pour chaque foyer un [`Foyer`] (adresse `.braise` et état
/// d'ouverture) indexé par position. L'index est partagé avec
/// `Configuration::adresses_braise` et le trousseau cryptographique — c'est
/// le point de vérité unique pour relier un foyer à son adresse et à son
/// état d'ouverture.
struct SessionFoyers {
    /// État et adresse de chaque foyer.
    foyers: [Foyer; IndexFoyer::NOMBRE],
}

impl SessionFoyers {
    /// Crée une session vide : tous les foyers sont fermés et sans adresse.
    fn new() -> Self {
        Self {
            foyers: std::array::from_fn(|_| Foyer {
                braise: Braise::VIDE,
                est_ouvert: false,
            }),
        }
    }

    /// Retourne `true` si aucun foyer n'est ouvert.
    fn est_tout_ferme(&self) -> bool {
        for e in &self.foyers {
            if e.est_ouvert {
                return false;
            }
        }
        true
    }

    /// Retourne `true` si tous les foyers sont ouverts.
    fn est_tout_ouvert(&self) -> bool {
        for e in &self.foyers {
            if !e.est_ouvert {
                return false;
            }
        }
        true
    }

    /// Remplace le tableau des foyers par celui fourni.
    ///
    /// Utilisé à l'allumage pour peupler la session avec les adresses
    /// lues depuis `noyau.feu`.
    fn definition_foyers(
        &mut self,
        interface: &mut impl InterfaceFeuNoyau,
        t: [(bool, Braise); IndexFoyer::NOMBRE],
    ) {
        for index_foyer in IndexFoyer::tous() {
            interface.recevoir_braise_foyer(index_foyer, t[index_foyer.valeur()].1);
            self.foyers[index_foyer.valeur()] =
                Foyer::new(t[index_foyer.valeur()].1, t[index_foyer.valeur()].0);
        }
    }

    /// Retourne l'adresse `.braise` du foyer à la position `index_foyer`.
    fn index_vers_braise(&self, index_foyer: IndexFoyer) -> Braise {
        self.foyers[index_foyer.valeur()].braise
    }

    /// Indique si le foyer à la position `index_foyer` est ouvert.
    ///
    /// L'accès est direct et sans garde : [`IndexFoyer`] borne la position par
    /// construction.
    fn est_ouvert(&self, index_foyer: IndexFoyer) -> bool {
        self.foyers[index_foyer.valeur()].est_ouvert
    }

    /// Marque le foyer à la position `index_foyer` comme ouvert (`true`) ou
    /// fermé (`false`).
    ///
    /// Même accès direct que [`est_ouvert`](Self::est_ouvert), la borne étant
    /// tenue par le type.
    fn change_statut(&mut self, index_foyer: IndexFoyer, valeur: bool) {
        self.foyers[index_foyer.valeur()].est_ouvert = valeur;
    }
}

/// Point d'entrée unique du protocole FeuNoyau.
///
/// Orchestre `Gardien`, `Cryptographe` et les `Archiviste`s (un par foyer
/// ouvert) sans exposer leurs détails d'implémentation. Toute communication
/// utilisateur est déléguée à une implémentation de [`InterfaceFeuNoyau`]
/// injectée à chaque appel, garantissant une séparation totale entre la
/// logique du protocole et la couche de présentation.
pub struct FeuNoyau {
    /// État de la session courante — foyers ouverts et leurs adresses `.braise`.
    session: SessionFoyers,
    /// Gardien des données locales — fichiers, foyers, configuration.
    /// Présent et actif pour toute la durée de vie du nœud.
    gardien: Gardien,

    /// Garant de la sécurité cryptographique — clés, chiffrement, seed.
    /// Présent et actif pour toute la durée de vie du nœud.
    cryptographe: Cryptographe,

    /// Un Archiviste par foyer ouvert — `None` si le foyer est fermé.
    /// Instancié à l'ouverture du foyer, détruit à la fermeture.
    archivistes: [Option<Archiviste>; IndexFoyer::NOMBRE],
}

impl Drop for FeuNoyau {
    /// Filet de sécurité : panic si des foyers sont encore ouverts à la destruction.
    ///
    /// Le chemin normal est que la couche de présentation ferme tous les foyers
    /// avant de quitter. Ce `drop` ne fait pas de cleanup — il garantit uniquement
    /// qu'une sortie silencieuse avec des foyers ouverts est impossible.
    ///
    /// # Dettes techniques
    ///
    /// Si le programme s'est terminé anormalement avec des foyers ouverts, les
    /// dossiers clairs restent sur le disque et les archives `.feu` sont absentes.
    /// Le nœud reste utilisable au redémarrage, mais l'ouverture de ces foyers
    /// échouera. [`FeuNoyau::diagnostic_noeud`] permet de détecter cet état ;
    /// [`FeuNoyau::secours_fermeture_foyer`] permet de le réparer en
    /// refermant proprement le foyer depuis son dossier clair.
    fn drop(&mut self) {
        if !self.session.est_tout_ferme() {
            panic!("Les foyers n'étaient pas tous fermés avant de quitter");
        }
    }
}

impl FeuNoyau {
    /// Crée une instance de [`FeuNoyau`] prête à l'emploi — nœud allumé, foyers fermés.
    ///
    /// L'existence de `~/.feu` décide seule entre initialisation et allumage : la
    /// première dérive les clés depuis une seed neuve ou depuis `phrase_seed`,
    /// crée l'arborescence et referme les foyers ; le second relit `noyau.feu` et
    /// déchiffre la clé privée du nœud avec le mot de passe collecté.
    ///
    /// `chemin_feu` est le chemin racine du nœud, fourni par l'appelant : le noyau
    /// ne lit jamais l'environnement, ce qui permet de l'enraciner dans un dossier
    /// temporaire pour les tests.
    ///
    /// `phrase_seed` est une phrase BIP39 de 12, 15, 18, 21 ou 24 mots, séparés par
    /// des blancs quelconques et normalisés en NFKD ; Feu en génère de 24.
    ///
    /// # Errors
    ///
    /// Retourne une [`ErreurFeuNoyau`] si `noyau.feu` est illisible, si un
    /// fichier de clé est absent ou corrompu, ou si le mot de passe est
    /// incorrect. Retourne [`ErreurFeuNoyau::SeedRefuseeNoeudExistant`] si
    /// `phrase_seed` est fournie alors que l'arborescence existe déjà. Si `phrase_seed`
    /// est fournie, retourne une erreur si le compte de mots est invalide, si un mot
    /// est absent du dictionnaire BIP39 français, ou si le checksum est incorrect.
    pub fn new(
        chemin_feu: &Path,
        phrase_seed: Option<SecretString>,
        interface_feu_noyau: &mut impl InterfaceFeuNoyau,
    ) -> ResultFeuNoyau<Self> {
        let mut gardien = Gardien::new(chemin_feu);

        if gardien.existence_arborescence() {
            if phrase_seed.is_some() {
                return Err(ErreurFeuNoyau::SeedRefuseeNoeudExistant);
            }

            let gardien = Gardien::ouvre_nouveau(chemin_feu)?;
            let mut cryptographe = Cryptographe::new();

            let trousseau_public_noeud = &gardien.lecture_pour_creation_trousseau_public_noeud()?;

            interface_feu_noyau
                .recevoir_cle_publique_noeud(trousseau_public_noeud.donne_cle_sig_pub());

            cryptographe
                .recoit_trousseau_public_noeud(trousseau_public_noeud, interface_feu_noyau)?;

            let mut session = SessionFoyers::new();
            session.definition_foyers(
                interface_feu_noyau,
                gardien.creation_tableau_session_foyers(),
            );
            Ok(Self {
                session,
                gardien,
                cryptographe,
                archivistes: std::array::from_fn(|_| None),
            })
        } else {
            let mut cryptographe = Cryptographe::new();

            // 1- LE CRYPTOGRAPHE TRAVAILLE EN MÉMOIRE

            // Le cryptographe génère les clés nécessaires au fonctionnement d'un nouveau nœud
            match phrase_seed {
                None => {
                    cryptographe.initialise_noeud_a_partir_nouvelle_seed(interface_feu_noyau)?;
                }
                Some(valeur) => {
                    cryptographe
                        .initialise_noeud_a_partir_seed_existante(interface_feu_noyau, valeur)?;
                }
            }
            // Le cryptographe génère le trousseau public pour le gardien
            let trousseau_public_complet = cryptographe.donne_trousseau_public_complet()?;

            // Propagation de la clé publique de signature du nœud, comme à
            // l'allumage (branche ci-dessus). Contrairement aux clés de foyer —
            // poussées à l'ouverture d'un foyer — la clé du nœud n'a pas d'autre
            // point d'injection : sans cet appel, la première session après
            // genèse garderait une clé nœud à zéro et toute vérification d'une
            // racine (signée nœud) échouerait.
            interface_feu_noyau.recevoir_cle_publique_noeud(
                trousseau_public_complet
                    .donne_trousseau_public_noeud()
                    .donne_cle_sig_pub(),
            );

            // 2- LE GARDIEN TRAVAILLE SUR LE DISQUE

            gardien.cree_premiere_arborescence(&trousseau_public_complet)?;

            let mut session = SessionFoyers::new();

            // Ajout de chaque foyer dans la configuration
            for index_foyer in IndexFoyer::tous() {
                let braise = trousseau_public_complet
                    .donne_trousseau_public_foyer(index_foyer)?
                    .donne_braise();
                gardien.ajout_nouveau_foyer_dans_configuration(braise, index_foyer);
                session.foyers[index_foyer.valeur()] = Foyer::new(braise, true);
                interface_feu_noyau.recevoir_braise_foyer(index_foyer, braise);
            }

            // Enregistrement de noyau.feu
            gardien.enregistrement_configuration()?;

            let mut noyau = Self {
                session,
                gardien,
                cryptographe,
                archivistes: std::array::from_fn(|_| None),
            };

            // Fermeture des foyers
            for index_foyer in IndexFoyer::tous() {
                noyau.fermeture_foyer(interface_feu_noyau, index_foyer)?;
            }

            Ok(noyau)
        }
    }

    /// Répare l'arborescence d'un nœud existant en régénérant toutes ses clés depuis
    /// une seed BIP39 fournie.
    ///
    /// À utiliser quand des fichiers de clés ont disparu mais que les archives
    /// `.feu` sont intactes : la dérivation étant déterministe, la même seed rend
    /// les mêmes clés, le même sel et les mêmes braises.
    ///
    /// Le mot de passe est redemandé à chaque foyer et doit être celui de la
    /// dernière fermeture, dont les archives dépendent.
    ///
    /// Les clés root sont écrites en **deux passes**, de part et d'autre de
    /// l'ouverture des foyers, dont les dossiers n'existent pas avant. Répare le
    /// disque et rend la main — l'appelant enchaîne sur [`FeuNoyau::new`].
    ///
    /// # Format de `phrase_seed`
    ///
    /// `phrase_seed` est une phrase mnémotechnique BIP39 : mots en minuscules séparés
    /// par des espaces (tout blanc accepté — espaces multiples tolérés). Comptes
    /// valides : 12, 15, 18, 21 ou 24 mots. Feu génère des seeds de 24 mots.
    /// La normalisation NFKD est appliquée automatiquement avant validation.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si le compte de mots est invalide, si un mot est absent
    /// du dictionnaire BIP39 français, si le checksum est incorrect, si une opération
    /// disque échoue, ou si l'ouverture ou la fermeture d'un foyer échoue. En cas
    /// d'erreur en cours de traitement, certains foyers peuvent rester désarchivés
    /// sur le disque.
    pub fn demarrage_secours(
        chemin_feu: &Path,
        phrase_seed: SecretString,
        interface_feu_noyau: &mut impl InterfaceFeuNoyau,
    ) -> ResultFeuNoyau<()> {
        let mut gardien = Gardien::new(chemin_feu);

        let mut cryptographe = Cryptographe::new();

        cryptographe.genere_trousseau_a_partir_seed(interface_feu_noyau, phrase_seed)?;

        let trousseau_public_complet = cryptographe.donne_trousseau_public_complet()?;

        let mut session = SessionFoyers::new();

        // Ajout de chaque foyer dans la configuration
        for index_foyer in IndexFoyer::tous() {
            let braise = trousseau_public_complet
                .donne_trousseau_public_foyer(index_foyer)?
                .donne_braise();
            gardien.ajout_nouveau_foyer_dans_configuration(braise, index_foyer);
            session.foyers[index_foyer.valeur()] = Foyer::new(braise, false);
        }

        // Enregistrement de noyau.feu
        gardien.enregistrement_configuration()?;

        let mut noyau = Self {
            session,
            gardien,
            cryptographe,
            archivistes: std::array::from_fn(|_| None),
        };

        // Première passe : écrit les fichiers root .cles/ (dont <braise>.cle) nécessaires
        // à l'ouverture des foyers. L'échec partiel est ignoré — <braise>/ n'existe pas
        // encore, les clés de classeurs seront écrites par la deuxième passe.
        let _ = noyau
            .gardien
            .ecriture_trousseau_public_complet(&trousseau_public_complet);

        for index_foyer in IndexFoyer::tous() {
            noyau.ouverture_foyer(interface_feu_noyau, index_foyer)?;
        }

        noyau
            .gardien
            .ecriture_trousseau_public_complet(&trousseau_public_complet)?;

        // Fermeture des foyers
        for index_foyer in IndexFoyer::tous() {
            noyau.fermeture_foyer(interface_feu_noyau, index_foyer)?;
        }

        Ok(())
    }

    // ── Nœud ─────────────────────────────────────────────────────────────────

    /// Change le mot de passe du nœud et rechiffre l'intégralité du trousseau.
    ///
    /// Tous les foyers doivent être ouverts — leurs clés doivent être en mémoire
    /// pour être rechiffrées avec le nouveau mot de passe.
    ///
    /// **Phase mémoire — cryptographe**
    /// 1. Collecte le nouveau mot de passe (deux saisies avec vérification).
    /// 2. Dérive une nouvelle clé éphémère Argon2id avec le sel existant.
    /// 3. Rechiffre toutes les clés (nœud + foyers) avec la nouvelle clé éphémère.
    /// 4. Efface le mot de passe et la clé éphémère de la mémoire.
    ///
    /// **Phase disque — gardien**
    /// 5. Réécrit atomiquement tous les fichiers de clés sur le disque.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuNoyau::AuMoinsUnFoyerFerme`] si un seul foyer est
    /// fermé, ou propage l'échec du rechiffrement et des opérations disque.
    pub fn changement_mdp(
        &mut self,
        interface_feu_noyau: &mut impl InterfaceFeuNoyau,
    ) -> ResultFeuNoyau<()> {
        if !self.session.est_tout_ouvert() {
            return Err(ErreurFeuNoyau::AuMoinsUnFoyerFerme);
        }

        let trousseau_public_complet = self.cryptographe.changement_mdp(interface_feu_noyau)?;
        self.gardien
            .ecriture_trousseau_public_complet(&trousseau_public_complet)?;
        Ok(())
    }

    // ── Foyers ───────────────────────────────────────────────────────────────

    /// Ouvre un foyer FeuNoyau existant : déchiffre l'archive, charge les clés en mémoire
    /// et initialise l'Archiviste du foyer.
    ///
    /// L'Archiviste est instancié en fin de parcours et crée `registre/` et les
    /// cinq classeurs à la première ouverture seulement — ensuite il constate
    /// leur présence et ne fait rien.
    ///
    /// # Archive `.tar` intermédiaire
    ///
    /// Un `.tar` laissé derrière une erreur rend le foyer impossible à rouvrir,
    /// même avec le bon mot de passe : il est créé en mode exclusif, la
    /// tentative suivante échoue donc sur son existence. Les deux étapes qui
    /// peuvent échouer alors qu'il existe le suppriment avant de propager.
    ///
    /// L'échec de cette suppression est ignoré — le fichier peut avoir déjà
    /// disparu, et c'est l'erreur d'origine qui renseigne l'appelant.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuNoyau::FoyerDejaOuvert`] si le foyer l'est déjà,
    /// [`ErreurFeuNoyau::AesGcm`] si le mot de passe est incorrect — l'auth tag
    /// ne valide pas —, ou propage l'échec d'une opération disque.
    ///
    /// # Avertissement sécurité
    ///
    /// Si une erreur survient entre la dérivation de la clé éphémère (étape 2) et
    /// son effacement (étape 8), le mot de passe et la clé éphémère restent en
    /// mémoire. Un mécanisme de drop guard sera introduit pour garantir l'effacement
    /// sur tous les chemins d'erreur.
    ///
    /// Par ailleurs, si une erreur survient **après** l'extraction du dossier
    /// clair mais avant que le foyer ne soit marqué comme ouvert, le dossier
    /// clair reste sur disque sans archive associée — état que
    /// [`diagnostic_noeud`](Self::diagnostic_noeud) détecte et que
    /// [`secours_fermeture_foyer`](Self::secours_fermeture_foyer)
    /// permet de réparer.
    pub fn ouverture_foyer(
        &mut self,
        interface_feu_noyau: &mut impl InterfaceFeuNoyau,
        index_foyer: IndexFoyer,
    ) -> ResultFeuNoyau<()> {
        let braise = self.session.index_vers_braise(index_foyer);

        if self.session.est_ouvert(index_foyer) {
            return Err(ErreurFeuNoyau::FoyerDejaOuvert(index_foyer.valeur()));
        }

        let (cle, mut source, mut destination) = self
            .gardien
            .preparation_desarchivage_chiffre_foyer(braise)?;

        // Cas courant : mot de passe erroné ou saisie annulée. Le `.tar` a déjà
        // été créé — vide, puisque rien n'y a été écrit.
        if let Err(e) = self.cryptographe.donne_flux_dechiffrement_foyer(
            &cle,
            &mut source,
            &mut destination,
            interface_feu_noyau,
        ) {
            let _ = self.gardien.suppression_archive_foyer_tar(braise);
            return Err(e);
        }

        // Un échec en cours d'extraction laisse le `.tar` derrière lui.
        if let Err(e) = self.gardien.desarchivage_chiffre_foyer(braise) {
            let _ = self.gardien.suppression_archive_foyer_tar(braise);
            return Err(e);
        };

        let trousseau_public_foyer = self.gardien.creation_trousseau_foyer_public(braise)?;

        interface_feu_noyau.recevoir_cles_publiques_foyer(
            index_foyer,
            trousseau_public_foyer.donne_cle_sig_pub(),
            trousseau_public_foyer.donne_cle_chiff_pub(),
        );

        self.cryptographe
            .recoit_trousseau_public_foyer(trousseau_public_foyer, index_foyer)?;

        // Instanciation de l'archiviste — crée l'arborescence classeurs/registre
        // à la première ouverture, ne fait rien lors des ouvertures suivantes.
        self.archivistes[index_foyer.valeur()] =
            Some(Archiviste::new(self.gardien.donne_chemin_braise(braise))?);

        self.session.change_statut(index_foyer, true);
        interface_feu_noyau.recevoir_etat_foyer(index_foyer, true);
        Ok(())
    }

    /// Ferme le foyer à la position `index_foyer` — opération inverse de
    /// [`ouverture_foyer`](Self::ouverture_foyer).
    ///
    /// Réarchive le dossier clair du foyer en une archive `.feu` chiffrée, efface
    /// toute trace en clair du disque et libère les ressources mémoire associées.
    /// L'Archiviste est détruit au passage, son dossier venant de disparaître.
    ///
    /// # Invariants de sécurité
    ///
    /// À la fin de l'opération, aucune donnée du foyer ne subsiste en clair sur
    /// le disque : seule demeure l'archive `.feu` chiffrée.
    ///
    /// # Fichiers laissés par une erreur
    ///
    /// `.tar` et `.feu` sont tous deux créés en mode exclusif : l'un ou l'autre
    /// laissé derrière une erreur rendrait le foyer infermable, y compris par
    /// [`secours_fermeture_foyer`](Self::secours_fermeture_foyer) qui repasse
    /// ici. Les deux étapes qui peuvent échouer avant la fin du chiffrement les
    /// suppriment donc avant de propager.
    ///
    /// Le filet s'arrête là volontairement. Une fois le chiffrement abouti, le
    /// `.feu` est l'unique forme persistante du foyer et le dossier clair va
    /// disparaître : supprimer le `.feu` sur une erreur ultérieure détruirait
    /// les données.
    ///
    /// Aucun test ne couvre ces deux chemins : les atteindre suppose une panne
    /// disque, qu'aucun mauvais usage ne provoque.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuNoyau::FoyerFerme`] si le foyer l'est déjà, ou propage
    /// l'échec du chiffrement et des opérations disque.
    pub fn fermeture_foyer(
        &mut self,
        interface_feu_noyau: &mut impl InterfaceFeuNoyau,
        index_foyer: IndexFoyer,
    ) -> ResultFeuNoyau<()> {
        let braise = self.session.index_vers_braise(index_foyer);

        if !self.session.est_ouvert(index_foyer) {
            return Err(ErreurFeuNoyau::FoyerFerme(index_foyer.valeur()));
        }

        let (mut source, mut destination) =
            match self.gardien.preparation_archivage_chiffre_foyer(braise) {
                Ok(fichiers) => fichiers,
                Err(e) => {
                    let _ = self.gardien.suppression_archive_foyer_tar(braise);
                    let _ = self.gardien.suppression_archive_foyer_chiffree(braise);

                    return Err(e);
                }
            };

        if let Err(e) = self.cryptographe.donne_flux_chiffrement_foyer(
            index_foyer,
            &mut source,
            &mut destination,
        ) {
            let _ = self.gardien.suppression_archive_foyer_tar(braise);
            let _ = self.gardien.suppression_archive_foyer_chiffree(braise);

            return Err(e);
        };

        self.gardien.suppression_archive_foyer_tar(braise)?;
        self.gardien.suppression_dossier_braise(braise)?;

        // Destruction de l'archiviste — le dossier du foyer est déjà supprimé.
        self.archivistes[index_foyer.valeur()] = None;

        self.session.change_statut(index_foyer, false);
        interface_feu_noyau.recevoir_etat_foyer(index_foyer, false);

        Ok(())
    }

    /// Ferme un foyer en mode secours — sans que ses clés soient en mémoire.
    ///
    /// Utilisé lorsque Feu s'est terminé anormalement alors qu'un foyer était
    /// ouvert : le dossier clair du foyer est toujours sur disque mais le
    /// trousseau a été perdu. Sans ce mécanisme, le foyer serait inutilisable —
    /// `ouverture_foyer` attend une archive `.feu` qui n'existe pas, et
    /// `fermeture_foyer` requiert les clés en mémoire.
    ///
    /// Les clés sont relues depuis le dossier clair, puis le foyer est marqué
    /// ouvert — prérequis de la fermeture standard, à laquelle tout le reste est
    /// délégué.
    ///
    /// # Prérequis
    ///
    /// Le dossier clair `<braise>/` doit exister sur disque et être intact —
    /// le diagnostic vérifie la présence de toutes les clés nécessaires. Le foyer
    /// doit aussi être marqué fermé dans la session : ouvert, ses clés sont en
    /// mémoire et c'est [`fermeture_foyer`](Self::fermeture_foyer) qui s'applique.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuNoyau::FermetureSecoursFoyerImpossible`] si le foyer est marqué
    /// ouvert ou si le diagnostic préalable relève une anomalie,
    /// [`ErreurFeuNoyau::AesGcm`] si le mot de passe est incorrect, ou propage
    /// l'échec d'une opération disque.
    pub fn secours_fermeture_foyer(
        &mut self,
        interface_feu_noyau: &mut impl InterfaceFeuNoyau,
        index_foyer: IndexFoyer,
    ) -> ResultFeuNoyau<()> {
        let braise = self.session.index_vers_braise(index_foyer);
        if self.session.est_ouvert(index_foyer) || !self.gardien.diagnostic_foyer(braise).is_empty()
        {
            return Err(ErreurFeuNoyau::FermetureSecoursFoyerImpossible);
        }

        self.cryptographe.secours_recoit_trousseau_public_foyer(
            self.gardien.creation_trousseau_foyer_public(braise)?,
            index_foyer,
            interface_feu_noyau,
        )?;

        self.session.change_statut(index_foyer, true);
        self.fermeture_foyer(interface_feu_noyau, index_foyer)?;

        Ok(())
    }

    // ── BLOBS ──────────────────────────────────────────────────────────────

    /// Stocke un blob dans un classeur d'un foyer ouvert, sans jamais le dupliquer.
    ///
    /// Le clair est lu par chunks dans un tiroir, haché et chiffré sous la clé du
    /// classeur **demandé**, puis tous les classeurs du foyer sont balayés : si
    /// l'un détient déjà ce hash, son index est rendu sans rien écrire et le
    /// chiffré préparé est abandonné.
    ///
    /// # Unicité dans le foyer
    ///
    /// Une ENU référence une donnée par le couple `(foyer, hash)` — le classeur
    /// n'y figure pas, et [`lecture_blob`](Self::lecture_blob) le retrouve
    /// en balayant. Deux copies du même blob dans deux classeurs resteraient
    /// donc parfaitement lisibles, le hash désignant un contenu et non un
    /// fichier ; mais [`suppression_blob`](Self::suppression_blob), qui
    /// vise un classeur nommé, n'en effacerait qu'une et laisserait l'autre
    /// lisible. Le balayage de l'étape 5 écarte le cas à la source : un hash
    /// donné n'existe qu'à un seul endroit du foyer.
    ///
    /// La contrepartie est que **le classeur demandé n'est pas garanti**. Si le
    /// blob se trouve déjà ailleurs, il y reste, chiffré sous la clé de son
    /// classeur d'origine et non sous celle qui vient d'être employée à
    /// l'étape 4. D'où le second membre du retour, qui dit où la donnée réside
    /// réellement.
    ///
    /// # Invariants de sécurité
    ///
    /// Le blob en clair ne transite que dans le tiroir et n'est jamais écrit sur
    /// le disque. L'Archiviste ne reçoit le tiroir qu'après chiffrement.
    ///
    /// # Retour
    ///
    /// Le couple `(hash, classeur)` : le hash SHA3-256 du blob en clair —
    /// identifiant content-addressable à conserver pour relire la donnée via
    /// [`lecture_blob`](Self::lecture_blob) — et l'index du classeur qui
    /// détient le blob, celui demandé ou celui où il résidait déjà.
    ///
    /// # Errors
    ///
    /// Délègue à `archiviste_foyer_ouvert` le foyer fermé
    /// ([`ErreurFeuNoyau::FoyerFerme`]) et l'Archiviste manquant
    /// ([`ErreurFeuNoyau::ArchivisteIndisponible`]). Vient ensuite
    /// [`ErreurFeuNoyau::TailleMaxDepasseeBlob`] si `source` dépasse
    /// [`MAX_TAILLE_BLOB`]. Propage enfin l'échec du chiffrement et de l'écriture.
    pub fn depot_blob(
        &mut self,
        index_foyer: IndexFoyer,
        index_classeur: IndexClasseur,
        source: impl Read,
    ) -> ResultFeuNoyau<([u8; 32], IndexClasseur)> {
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        let mut tiroir = archiviste.donne_tiroir_vide(index_classeur);
        tiroir.remplir(source)?;
        let (blob_chiffre, hash) =
            self.cryptographe
                .chiffrement_blob(index_foyer, index_classeur, tiroir.lire_blob())?;

        if let Some(index_classeur) = IndexClasseur::tous()
            .find(|&index_classeur| archiviste.existe_blob(index_classeur, &hash))
        {
            return Ok((hash, index_classeur));
        }

        tiroir.remplace_blob(blob_chiffre);
        tiroir.definit_hash(&hash);
        archiviste.ecrit_blob(tiroir)?;
        Ok((hash, index_classeur))
    }

    /// Lit et déchiffre un blob d'un foyer ouvert, sans en connaître le classeur.
    ///
    /// Le classeur est **découvert** en balayant le foyer : l'adressage étant fait
    /// sur le hash du clair, l'appelant connaît le `hash` mais pas l'emplacement.
    /// Un blob ne résidant jamais dans deux classeurs d'un même foyer, le premier
    /// trouvé est le bon, et sa clé est celle sous laquelle il a été chiffré.
    ///
    /// L'intégrité est vérifiée après déchiffrement — le hash SHA3-256 du clair
    /// doit retomber sur `hash` — avant l'écriture dans `destination`.
    ///
    /// # Invariants de sécurité
    ///
    /// Le blob en clair ne transite que dans le tiroir et n'est jamais écrit sur
    /// le disque. Le tiroir est zéroïsé après vidage.
    ///
    /// # Errors
    ///
    /// La validation du foyer est déléguée à `archiviste_foyer_ouvert`, appelé en
    /// tête : c'est lui qui teste le foyer fermé
    /// ([`ErreurFeuNoyau::FoyerFerme`]) et l'Archiviste manquant
    /// ([`ErreurFeuNoyau::ArchivisteIndisponible`]) — tout cela **avant** le
    /// balayage. Vient ensuite [`ErreurFeuNoyau::BlobIntrouvable`] si aucun
    /// classeur du foyer ne détient `hash`. Propage enfin l'absence du
    /// Cryptographe, l'échec de déchiffrement ou de vérification d'intégrité, et
    /// l'échec d'écriture dans `destination`.
    pub fn lecture_blob(
        &mut self,
        index_foyer: IndexFoyer,
        hash: &[u8; 32],
        destination: impl Write,
    ) -> ResultFeuNoyau<()> {
        // Valide le foyer (bornes, ouverture, archiviste) et remonte la cause
        // précise avant tout balayage.
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        // Classeur inconnu de l'appelant (nommage content-addressed) : on balaie
        // le foyer. `unwrap_or(false)` est ici sans conséquence — le foyer étant
        // déjà validé, `existence_blob` ne peut plus échouer sur ces index ;
        // l'absence réelle du blob dans tous les classeurs donne BlobIntrouvable.
        let index_classeur = IndexClasseur::tous()
            .find(|&index_classeur| archiviste.existe_blob(index_classeur, hash))
            .ok_or(ErreurFeuNoyau::BlobIntrouvable(index_foyer.valeur()))?;

        let mut tiroir = archiviste.donne_tiroir_plein(index_classeur, hash)?;

        tiroir.remplace_blob(self.cryptographe.dechiffrement_blob(
            index_foyer,
            index_classeur,
            hash,
            tiroir.lire_blob(),
        )?);

        tiroir.vider(destination)?;

        Ok(())
    }

    /// Supprime un blob d'un foyer ouvert, sans en connaître le classeur.
    ///
    /// Supprime le fichier `classeurN/<hash>.dat` via l'Archiviste du foyer.
    /// L'opération est irréversible.
    ///
    /// Le classeur est **découvert** par balayage, comme dans
    /// [`lecture_blob`](Self::lecture_blob) et pour la même raison :
    /// l'appelant connaît le `hash` du clair, pas l'emplacement. Un même blob ne
    /// résidant jamais dans deux classeurs d'un même foyer, le premier trouvé
    /// est le bon.
    ///
    /// # Errors
    ///
    /// Délègue à `archiviste_foyer_ouvert` le foyer fermé
    /// ([`ErreurFeuNoyau::FoyerFerme`]) et l'Archiviste manquant
    /// ([`ErreurFeuNoyau::ArchivisteIndisponible`]) — avant le balayage, dont
    /// l'échec donne [`ErreurFeuNoyau::BlobIntrouvable`]. Propage enfin l'échec
    /// de la suppression disque.
    pub fn suppression_blob(&self, index_foyer: IndexFoyer, hash: &[u8; 32]) -> ResultFeuNoyau<()> {
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        let index_classeur = IndexClasseur::tous()
            .find(|&index_classeur| archiviste.existe_blob(index_classeur, hash))
            .ok_or(ErreurFeuNoyau::BlobIntrouvable(index_foyer.valeur()))?;

        archiviste.supprime_blob(index_classeur, hash)?;

        Ok(())
    }

    /// Retourne la liste des hashes des blobs présents dans un classeur d'un foyer ouvert.
    ///
    /// Délègue à l'Archiviste du foyer, qui parcourt le dossier `classeurN/` et
    /// décode le nom de chaque fichier `.dat`, en écartant ce qui n'est pas un
    /// hash de 32 octets.
    ///
    /// L'ordre des hashes retournés n'est pas garanti.
    ///
    /// # Errors
    ///
    /// Délègue à `archiviste_foyer_ouvert` le foyer fermé
    /// ([`ErreurFeuNoyau::FoyerFerme`]) et l'Archiviste manquant
    /// ([`ErreurFeuNoyau::ArchivisteIndisponible`]). Propage enfin l'échec de la
    /// lecture du dossier.
    pub fn liste_blobs(
        &self,
        index_foyer: IndexFoyer,
        index_classeur: IndexClasseur,
    ) -> ResultFeuNoyau<Vec<[u8; 32]>> {
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        archiviste.donne_liste_blobs(index_classeur)
    }

    /// Rend le classeur d'un foyer ouvert qui détient le blob identifié par
    /// `hash`.
    ///
    /// Permet aux couches supérieures de situer un blob sans avoir à le lire —
    /// donc sans déchiffrement. Le balayage est celui de
    /// [`lecture_blob`](Self::lecture_blob) : un blob ne résidant jamais dans
    /// deux classeurs d'un même foyer, le premier trouvé est le bon.
    ///
    /// L'absence est un `Ok(None)`, jamais une erreur : la question posée admet
    /// « nulle part » pour réponse. Les erreurs sont réservées à ce qui empêche
    /// de répondre — foyer fermé, Archiviste manquant.
    ///
    /// # Errors
    ///
    /// Délègue à `archiviste_foyer_ouvert` le foyer fermé
    /// ([`ErreurFeuNoyau::FoyerFerme`]) et l'Archiviste manquant
    /// ([`ErreurFeuNoyau::ArchivisteIndisponible`]).
    pub fn existence_blob(
        &self,
        index_foyer: IndexFoyer,
        hash: &[u8; 32],
    ) -> ResultFeuNoyau<Option<IndexClasseur>> {
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        Ok(IndexClasseur::tous()
            .find(|index_classeur| archiviste.existe_blob(*index_classeur, hash)))
    }

    /// Retourne les métadonnées système d'un blob, sans en connaître le
    /// classeur.
    ///
    /// Délègue à l'Archiviste du foyer désigné — voir [`DonneesBlob`] pour le
    /// détail des champs. Le classeur est découvert par balayage, comme dans
    /// [`lecture_blob`](Self::lecture_blob).
    ///
    /// Contrairement à [`existence_blob`](Self::existence_blob), l'absence est
    /// ici une erreur : on a demandé les métadonnées d'un blob, pas s'il s'en
    /// trouvait un.
    ///
    /// # Errors
    ///
    /// Délègue à `archiviste_foyer_ouvert` le foyer fermé et l'Archiviste
    /// manquant. Retourne [`ErreurFeuNoyau::BlobIntrouvable`] si
    /// aucun classeur ne détient `hash`.
    pub fn informations_blob(
        &self,
        index_foyer: IndexFoyer,
        hash: &[u8; 32],
    ) -> ResultFeuNoyau<DonneesBlob> {
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        let index_classeur = IndexClasseur::tous()
            .find(|&index_classeur| archiviste.existe_blob(index_classeur, hash))
            .ok_or(ErreurFeuNoyau::BlobIntrouvable(index_foyer.valeur()))?;

        archiviste.donne_informations_blob(index_classeur, hash)
    }

    // ── Chiffrement asymétrique ───────────────────────────────────────────────

    /// Chiffre des octets à destination d'un nœud identifié par sa clé publique ML-KEM-1024.
    ///
    /// Délègue au cryptographe qui implémente le schéma KEM + HKDF + AES-256-GCM.
    /// Aucune clé privée du trousseau n'est utilisée — seule la clé publique du
    /// destinataire est nécessaire.
    ///
    /// La taille des données est limitée à [`MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE`] —
    /// l'intégralité du clair et du ciphertext sont chargés en mémoire.
    ///
    /// # Format de sortie
    ///
    /// Le vecteur retourné concatène, dans cet ordre :
    /// le ciphertext ML-KEM-1024 (1568 octets), le nonce AES-GCM (12 octets),
    /// le ciphertext, puis le tag d'authentification AES-GCM (16 octets).
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuNoyau::TailleMaxDepasseeChiffrementAsymetrique`] si la
    /// taille dépasse [`MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE`], ou propage l'échec
    /// du chiffrement.
    pub fn chiffrement_asymetrique(
        &self,
        cle_publique_destinataire: &[u8; 1568],
        octets_a_chiffrer: &[u8],
    ) -> ResultFeuNoyau<Vec<u8>> {
        if octets_a_chiffrer.len() > MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE {
            return Err(ErreurFeuNoyau::TailleMaxDepasseeChiffrementAsymetrique(
                octets_a_chiffrer.len(),
            ));
        }

        self.cryptographe
            .chiffrement_asymetrique(cle_publique_destinataire, octets_a_chiffrer)
    }

    /// Déchiffre un message chiffré à destination de ce foyer.
    ///
    /// Réciproque de [`chiffrement_asymetrique`](Self::chiffrement_asymetrique) —
    /// délègue au cryptographe qui effectue la décapsulation ML-KEM-1024 + HKDF + AES-256-GCM.
    /// La clé privée ML-KEM-1024 du foyer doit être présente dans le trousseau,
    /// ce qui requiert que le foyer soit ouvert.
    ///
    /// La taille des données est limitée à [`MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE`] + 1596 octets
    /// (surcoût du schéma KEM : 1568 ciphertext KEM + 12 nonce + 16 auth tag).
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuNoyau::FoyerFerme`] si le foyer n'est pas ouvert,
    /// [`ErreurFeuNoyau::TailleMaxDepasseeDechiffrementAsymetrique`] si la taille
    /// dépasse la limite, ou propage l'échec du déchiffrement.
    pub fn dechiffrement_asymetrique(
        &self,
        index_foyer: IndexFoyer,
        octets_a_dechiffrer: &[u8],
    ) -> ResultFeuNoyau<Vec<u8>> {
        if !self.session.foyers[index_foyer.valeur()].est_ouvert {
            return Err(ErreurFeuNoyau::FoyerFerme(index_foyer.valeur()));
        }
        if octets_a_dechiffrer.len() > MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE + 1596 {
            return Err(ErreurFeuNoyau::TailleMaxDepasseeDechiffrementAsymetrique(
                octets_a_dechiffrer.len(),
            ));
        }

        self.cryptographe
            .dechiffrement_asymetrique(index_foyer, octets_a_dechiffrer)
    }

    // ── Signature ────────────────────────────────────────────────────────────

    /// Signe des octets avec la clé privée de signature ML-DSA-87 du nœud.
    ///
    /// La clé de signature du nœud (label `feu/noeud/signature`) est l'identité
    /// cryptographique racine — elle signe les IdNU et tout acte engageant le
    /// nœud dans sa globalité.
    ///
    /// La taille des données est limitée à [`MAX_TAILLE_SIGNATURE`] —
    /// cette fonction est destinée aux structures légères (IdNU, ENU),
    /// pas aux blobs de données.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuNoyau::TailleMaxDepasseeSignature`] si la taille
    /// dépasse [`MAX_TAILLE_SIGNATURE`], ou propage l'échec de la signature.
    pub fn signature_noeud(&self, octets_a_signer: &[u8]) -> ResultFeuNoyau<[u8; 4627]> {
        if octets_a_signer.len() > MAX_TAILLE_SIGNATURE {
            return Err(ErreurFeuNoyau::TailleMaxDepasseeSignature(
                octets_a_signer.len(),
            ));
        }

        self.cryptographe.signature_noeud(octets_a_signer)
    }

    /// Signe des octets avec la clé privée de signature ML-DSA-87 du foyer.
    ///
    /// La clé de signature du foyer (label `feu/foyer/signature/{index}`)
    /// authentifie les ENU et les échanges réseau du foyer.
    /// Le foyer doit être ouvert — sa clé privée doit être présente en mémoire.
    ///
    /// La taille des données est limitée à [`MAX_TAILLE_SIGNATURE`] —
    /// cette fonction est destinée aux structures légères (IdNU, ENU),
    /// pas aux blobs de données.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuNoyau::FoyerFerme`] si le foyer n'est pas ouvert,
    /// [`ErreurFeuNoyau::TailleMaxDepasseeSignature`] si la taille dépasse
    /// [`MAX_TAILLE_SIGNATURE`], ou propage l'échec de la signature.
    pub fn signature_foyer(
        &self,
        index_foyer: IndexFoyer,
        octets_a_signer: &[u8],
    ) -> ResultFeuNoyau<[u8; 4627]> {
        if !self.session.foyers[index_foyer.valeur()].est_ouvert {
            return Err(ErreurFeuNoyau::FoyerFerme(index_foyer.valeur()));
        }
        if octets_a_signer.len() > MAX_TAILLE_SIGNATURE {
            return Err(ErreurFeuNoyau::TailleMaxDepasseeSignature(
                octets_a_signer.len(),
            ));
        }

        self.cryptographe
            .signature_foyer(index_foyer, octets_a_signer)
    }

    /// Vérifie une signature ML-DSA-87.
    ///
    /// Retourne `Ok(true)` si `signature` est valide pour `octets_signes` avec
    /// `cle_publique`, `Ok(false)` sinon.
    ///
    /// # Errors
    ///
    /// Retourne [`ErreurFeuNoyau::CryptographeSignatureMlDsaMalFormee`] si
    /// `signature` n'est pas un encodage ML-DSA-87 décodable.
    pub fn verification_signature(
        cle_publique: [u8; 2592],
        signature: [u8; 4627],
        octets_signes: &[u8],
    ) -> ResultFeuNoyau<bool> {
        Cryptographe::verification_signature(cle_publique, signature, octets_signes)
    }

    /// Calcule l'empreinte SHA3-256 des octets fournis.
    ///
    /// Délégation interne au `Cryptographe`. Exposée pour les couches
    /// supérieures (Scribe) qui ont besoin de hasher sans importer `sha3`.
    pub fn creation_empreinte(octets: &[u8]) -> [u8; 32] {
        Cryptographe::empreinte(octets)
    }

    // ── Diagnostic ───────────────────────────────────────────────────────────

    /// Diagnostique l'état du nœud sans modifier quoi que ce soit.
    ///
    /// Vérifie la présence de tous les fichiers nécessaires pour allumer le nœud
    /// et ouvrir ses foyers : arborescence `~/.feu`, `.config/noyau.feu`, `.cles/`,
    /// clés du nœud, archives et clés de chaque foyer connu.
    ///
    /// Fonction associée — utilisable sans nœud allumé, notamment pour
    /// diagnostiquer pourquoi [`FeuNoyau::new`] échoue. `chemin_feu` est le chemin
    /// racine du nœud à inspecter (`~/.feu` en usage nominal), fourni par
    /// l'appelant.
    ///
    /// # Retour
    ///
    /// Un vecteur vide si le nœud est dans un état nominal ; la liste des
    /// anomalies détectées sinon. Ne peut pas échouer : l'inspection se limite à
    /// des tests de présence et une config illisible est signalée comme une
    /// anomalie ([`Anomalie::ConfigurationIllisible`]), pas comme une erreur.
    ///
    /// Le diagnostic répond à ce que le disque porte, non à la santé d'un nœud
    /// en cours d'usage : appelé pendant qu'un foyer est ouvert, il signale
    /// l'archive absente. C'est ce même signal dont
    /// [`secours_fermeture_foyer`](Self::secours_fermeture_foyer) se sert pour
    /// reconnaître un foyer à réparer.
    pub fn diagnostic_noeud(chemin_feu: &Path) -> Vec<Anomalie> {
        let gardien = Gardien::new(chemin_feu);

        gardien.diagnostic_noeud()
    }

    /// Diagnostique l'état d'un foyer ouvert sans modifier quoi que ce soit.
    ///
    /// Vérifie la présence des clés du foyer et des clés de classeurs sur disque,
    /// ainsi que l'arborescence interne : dossier `registre/` et liens symboliques
    /// vers les classeurs.
    ///
    /// Complète [`FeuNoyau::diagnostic_noeud`] qui couvre l'état du foyer fermé
    /// (archive et clés). Cette commande requiert le foyer ouvert pour accéder
    /// à l'arborescence interne.
    ///
    /// # Retour
    ///
    /// `Ok(vec![])` si le foyer est dans un état nominal.
    /// `Ok(vec![...])` avec la liste des anomalies détectées sinon.
    ///
    /// # Errors
    ///
    /// La validation du foyer est déléguée à `archiviste_foyer_ouvert`, appelé en
    /// tête : foyer fermé ([`ErreurFeuNoyau::FoyerFerme`]) et Archiviste manquant
    /// ([`ErreurFeuNoyau::ArchivisteIndisponible`]). Propage ensuite l'échec des
    /// opérations disque.
    pub fn diagnostic_foyer(&self, index_foyer: IndexFoyer) -> ResultFeuNoyau<Vec<Anomalie>> {
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        let mut resultat = self
            .gardien
            .diagnostic_foyer(self.session.index_vers_braise(index_foyer));

        resultat.extend(archiviste.verifier_arborescence_classeurs()?);

        Ok(resultat)
    }

    /// L'Archiviste du foyer, après les trois vérifications qui le conditionnent.
    ///
    /// Point de passage unique de toute opération sur un blob : sans lui, chaque
    /// appelant répéterait les mêmes gardes avant d'atteindre le même champ.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuNoyau::FoyerFerme`] si le foyer l'est, et
    /// [`ErreurFeuNoyau::ArchivisteIndisponible`] si le foyer est marqué ouvert
    /// sans Archiviste — état qui ne devrait pas survenir.
    fn archiviste_foyer_ouvert(&self, index_foyer: IndexFoyer) -> ResultFeuNoyau<&Archiviste> {
        if !self.session.foyers[index_foyer.valeur()].est_ouvert {
            return Err(ErreurFeuNoyau::FoyerFerme(index_foyer.valeur()));
        }
        let Some(archiviste) = &self.archivistes[index_foyer.valeur()] else {
            return Err(ErreurFeuNoyau::ArchivisteIndisponible(index_foyer.valeur()));
        };
        Ok(archiviste)
    }
}
