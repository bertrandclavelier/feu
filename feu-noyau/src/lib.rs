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
mod braise;
mod cryptographe;
mod erreur;
mod gardien;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use secrecy::SecretString;

use crate::archiviste::Archiviste;
use crate::cryptographe::Cryptographe;
pub use crate::erreur::{ErreurFeuNoyau, ResultFeuNoyau};
use crate::gardien::Gardien;
pub use braise::{BRAISE_VIDE, Braise};

/// Nombre maximum de foyers dans le nœud.
pub const MAX_FOYERS: usize = 3;
/// Nombre maximum de classeurs par foyer.
pub const MAX_CLASSEURS: usize = 5;
/// Taille maximum d'un blob — 512 Mio.
pub const MAX_TAILLE_BLOB: usize = 512 * 1024 * 1024;

/// Taille maximum d'un message à chiffrer via ML-KEM-1024 + AES-256-GCM — 1 Mio.
pub const MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE: usize = 1024 * 1024;

/// Taille maximum d'un message à signer — 64 Kio.
pub const MAX_TAILLE_SIGNATURE: usize = 64 * 1024;

pub(crate) const TAILLE_CHUNK: usize = 8 * 1024;

/// Contrat de communication entre `feu-noyau` et toute interface utilisateur.
///
/// Ce trait définit le canal d'échange entre le cœur du protocole et sa
/// couche de présentation — CLI, TUI ou application. Il remplit deux rôles :
///
/// **Entrées** — le noyau collecte ce dont il a besoin pour opérer :
/// `demander_mdp` pour les mots de passe. La collecte du mot de passe est
/// une responsabilité du noyau : il est le seul à savoir quand et pourquoi
/// en avoir besoin, ce qui minimise la fenêtre d'exposition en mémoire.
///
/// **Notifications d'état** — le noyau informe l'interface des changements
/// d'état significatifs qu'elle ne peut pas observer autrement : seed
/// mnémotechnique à l'initialisation, clé publique du nœud à l'allumage,
/// clés publiques des foyers à leur ouverture.
/// L'interface fait ce qu'elle veut de ces informations — les stocker, les
/// afficher, les transmettre au réseau.
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
    /// `config.feu`, et à l'initialisation pour chaque foyer créé. Permet à
    /// l'interface de construire un index stable `index_foyer → braise` sans
    /// avoir à inspecter la configuration elle-même.
    fn recevoir_braise_foyer(&mut self, index_foyer: usize, braise: Braise);

    /// Notifie l'interface d'un changement d'état d'ouverture d'un foyer.
    ///
    /// Appelée à la fin d'une ouverture ou d'une fermeture réussie — `etat`
    /// est `true` quand le foyer vient d'être ouvert, `false` quand il vient
    /// d'être fermé. L'interface peut ainsi refléter en temps réel l'état
    /// d'ouverture sans interroger le noyau.
    fn recevoir_etat_foyer(&mut self, index_foyer: usize, etat: bool);

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
        index_foyer: usize,
        cle_publique_sig: [u8; 2592],
        cle_publique_chif: [u8; 1568],
    );
}

/// Métadonnées système d'un blob chiffré.
///
/// Restitue les informations fournies par l'OS sur le fichier `.dat` correspondant
/// au blob. Les données sont brutes — aucune conversion n'est effectuée par le noyau.
pub struct DonneesBlob {
    taille: u64,
    date_creation: Option<SystemTime>,
    date_derniere_modification: SystemTime,
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
    /// `config.feu` est présent mais son contenu ne peut pas être parsé.
    ConfigurationIllisible,
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
    braise: Braise,
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
    foyers: [Foyer; MAX_FOYERS],
}

impl SessionFoyers {
    /// Crée une session vide : tous les foyers sont fermés et sans adresse.
    fn new() -> Self {
        Self {
            foyers: std::array::from_fn(|_| Foyer {
                braise: BRAISE_VIDE,
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
    /// lues depuis `config.feu`.
    fn definition_foyers(
        &mut self,
        interface: &mut impl InterfaceFeuNoyau,
        t: [(bool, Braise); MAX_FOYERS],
    ) {
        for (i, foyer) in self.foyers.iter_mut().enumerate() {
            interface.recevoir_braise_foyer(i, t[i].1);
            *foyer = Foyer::new(t[i].1, t[i].0);
        }
    }

    /// Retourne l'adresse `.braise` du foyer à la position `index`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `index >= MAX_FOYERS`.
    fn index_vers_braise(&self, index_foyer: usize) -> ResultFeuNoyau<Braise> {
        if index_foyer >= MAX_FOYERS {
            Err(ErreurFeuNoyau::BraiseIntrouvable)
        } else {
            Ok(self.foyers[index_foyer].braise)
        }
    }

    /// Indique si le foyer à la position `index_foyer` est ouvert.
    ///
    /// L'index n'est pas contrôlé ici : les méthodes publiques valident la borne
    /// `< MAX_FOYERS` en tête d'appel. Un index hors borne provoque une panique.
    fn est_ouvert(&self, index_foyer: usize) -> ResultFeuNoyau<bool> {
        Ok(self.foyers[index_foyer].est_ouvert)
    }

    /// Marque le foyer à la position `index_foyer` comme ouvert (`true`) ou
    /// fermé (`false`).
    ///
    /// Même contrat d'index que [`est_ouvert`](Self::est_ouvert) : la borne est
    /// supposée déjà validée par l'appelant.
    fn change_statut(&mut self, index_foyer: usize, valeur: bool) -> ResultFeuNoyau<()> {
        self.foyers[index_foyer].est_ouvert = valeur;

        Ok(())
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
    archivistes: [Option<Archiviste>; MAX_FOYERS],
}

impl Drop for FeuNoyau {
    /// Filet de sécurité : panic si des foyers sont encore ouverts à la destruction.
    ///
    /// Le chemin normal est que la couche de présentation ferme tous les foyers
    /// avant de quitter. Ce `drop` ne fait pas de cleanup — il garantit uniquement
    /// qu'une sortie silencieuse avec des foyers ouverts est impossible.
    ///
    /// # Dette technique
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
    /// Détecte automatiquement l'état du nœud en vérifiant l'existence de l'arborescence
    /// `~/.feu`. Selon le cas, exécute l'initialisation ou l'allumage. Dans les deux cas,
    /// retourne un [`FeuNoyau`] pleinement opérationnel avec le nœud allumé et tous les
    /// foyers fermés.
    ///
    /// `chemin_feu` est le chemin racine du nœud (`~/.feu` en usage nominal). Le
    /// noyau ne lit jamais l'environnement lui-même : l'emplacement lui est fourni
    /// par l'appelant, ce qui permet notamment de l'enraciner dans un dossier
    /// temporaire pour les tests.
    ///
    /// # Initialisation (première utilisation — arborescence absente)
    ///
    /// **Phase mémoire — cryptographe**
    /// 1. Génère une nouvelle seed BIP39 (si `phrase_seed` est `None`) ou utilise la phrase
    ///    mnémotechnique fournie, collecte le mot de passe et dérive les clés du nœud, des foyers et le sel.
    /// 2. Produit le trousseau public complet.
    ///
    /// **Phase disque — gardien**
    /// 3. Crée l'arborescence globale `~/.feu` et les arborescences de chaque foyer.
    /// 4. Enregistre les `MAX_FOYERS` adresses `.braise` dans `config.feu`.
    ///
    /// **Fermeture**
    /// 5. Ferme chaque foyer — archive, chiffre et supprime le dossier clair.
    ///
    /// # Allumage (utilisations suivantes — arborescence présente)
    ///
    /// **Phase disque — gardien**
    /// 1. Charge `config.feu` et lit le trousseau public du nœud depuis `~/.feu/.cles/`.
    ///
    /// **Phase mémoire — cryptographe**
    /// 2. Collecte le mot de passe via l'interface.
    /// 3. Dérive la clé éphémère Argon2id et déchiffre la clé privée du nœud.
    /// 4. Notifie l'interface de la clé publique de signature du nœud.
    ///
    /// # Format de `phrase_seed`
    ///
    /// `phrase_seed` est une phrase mnémotechnique BIP39 : mots en minuscules séparés
    /// par des espaces (tout blanc accepté — espaces multiples tolérés). Comptes
    /// valides : 12, 15, 18, 21 ou 24 mots. Feu génère des seeds de 24 mots.
    /// La normalisation NFKD est appliquée automatiquement avant validation.
    ///
    /// # Erreurs
    ///
    /// Retourne une [`ErreurFeuNoyau`] si `config.feu` est illisible, si un
    /// fichier de clé est absent ou corrompu, ou si le mot de passe est
    /// incorrect. Retourne [`ErreurFeuNoyau::InitialisationNoeudImpossible`] si
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
                return Err(ErreurFeuNoyau::InitialisationNoeudImpossible);
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

            // 2- LE GARDIEN TRAVAILLE SUR LE DISQUE

            gardien.cree_premiere_arborescence(&trousseau_public_complet)?;

            let mut session = SessionFoyers::new();

            // Ajout des MAX_FOYERS foyers dans la configuration
            for i in 0..MAX_FOYERS {
                let braise = trousseau_public_complet
                    .donne_trousseau_public_foyer(i)?
                    .donne_braise();
                gardien.ajout_nouveau_foyer_dans_configuration(braise, i);
                session.foyers[i] = Foyer::new(braise, true);
                interface_feu_noyau.recevoir_braise_foyer(i, braise);
            }

            // Enregistrement de config.feu
            gardien.enregistrement_configuration()?;

            let mut noyau = Self {
                session,
                gardien,
                cryptographe,
                archivistes: std::array::from_fn(|_| None),
            };

            // Fermeture des foyers
            for i in 0..MAX_FOYERS {
                noyau.fermeture_foyer(interface_feu_noyau, i)?;
            }

            Ok(noyau)
        }
    }

    /// Répare l'arborescence d'un nœud existant en régénérant toutes ses clés depuis
    /// une seed BIP39 fournie.
    ///
    /// À utiliser quand des fichiers de clés ont été supprimés ou corrompus mais que
    /// les archives `.feu` des foyers sont intactes. La dérivation des clés est
    /// déterministe — la même seed produit exactement les mêmes clés, le même sel et
    /// les mêmes adresses `.braise`.
    ///
    /// Le mot de passe original est demandé à plusieurs reprises : une première fois
    /// pour chiffrer les fichiers de clés, puis une fois par foyer pour désarchiver
    /// (comportement identique à [`ouverture_foyer`](Self::ouverture_foyer) standard).
    /// Il doit correspondre à celui utilisé lors de la dernière fermeture des foyers,
    /// car les archives ont été chiffrées avec ce mot de passe.
    ///
    /// Enchaîne les opérations suivantes :
    ///
    /// 1. Régénère toutes les clés en mémoire, collecte le mot de passe original et dérive
    ///    le sel via `genere_trousseau_a_partir_seed`.
    /// 2. Produit le trousseau public chiffré (efface mot de passe et clé éphémère).
    /// 3. Recrée `config.feu` avec les adresses `.braise` dérivées.
    /// 4. **Première passe** — écrit les fichiers root `~/.feu/.cles/` (dont `<braise>.cle`)
    ///    nécessaires à l'ouverture des foyers. Les erreurs sont ignorées — les répertoires
    ///    `<braise>/` n'existent pas encore, les clés de classeurs seront écrites à la passe suivante.
    /// 5. Ouvre chaque foyer — désarchive et charge les clés en mémoire.
    /// 6. **Deuxième passe** — écrit l'intégralité du trousseau public, y compris les
    ///    clés de classeurs dans `~/.feu/<braise>/.cles/`.
    /// 7. Ferme chaque foyer — archive le dossier clair (avec les nouvelles `.cles/`) et
    ///    supprime le dossier clair.
    ///
    /// Retourne `()` — la fonction répare le disque et rend la main. L'appelant doit
    /// ensuite invoquer [`FeuNoyau::new`] pour démarrer normalement.
    ///
    /// # Format de `phrase_seed`
    ///
    /// `phrase_seed` est une phrase mnémotechnique BIP39 : mots en minuscules séparés
    /// par des espaces (tout blanc accepté — espaces multiples tolérés). Comptes
    /// valides : 12, 15, 18, 21 ou 24 mots. Feu génère des seeds de 24 mots.
    /// La normalisation NFKD est appliquée automatiquement avant validation.
    ///
    /// # Erreurs
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

        // Ajout des MAX_FOYERS foyers dans la configuration
        for i in 0..MAX_FOYERS {
            let braise = trousseau_public_complet
                .donne_trousseau_public_foyer(i)?
                .donne_braise();
            gardien.ajout_nouveau_foyer_dans_configuration(braise, i);
            session.foyers[i] = Foyer::new(braise, false);
        }

        // Enregistrement de config.feu
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

        for i in 0..MAX_FOYERS {
            noyau.ouverture_foyer(interface_feu_noyau, i)?;
        }

        noyau
            .gardien
            .ecriture_trousseau_public_complet(&trousseau_public_complet)?;

        // Fermeture des foyers
        for i in 0..MAX_FOYERS {
            noyau.fermeture_foyer(interface_feu_noyau, i)?;
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
    /// # Erreurs
    ///
    /// Retourne une erreur si un foyer n'est pas ouvert ou si une opération disque échoue.
    pub fn changement_mdp(
        &mut self,
        interface_feu_noyau: &mut impl InterfaceFeuNoyau,
    ) -> ResultFeuNoyau<()> {
        if !self.session.est_tout_ouvert() {
            return Err(ErreurFeuNoyau::TousFoyersNonOuverts);
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
    /// Enchaîne six phases séquentielles :
    ///
    /// **Vérifications préalables**
    /// 1. Vérifie que `index < MAX_FOYERS` et que le foyer n'est pas déjà ouvert.
    ///
    /// **Phase mémoire — cryptographe**
    /// 2. Collecte le mot de passe FeuNoyau et dérive la clé éphémère Argon2id.
    /// 3. Déchiffre la clé symétrique du foyer (`<braise>.cle`) avec la clé éphémère.
    /// 4. Crée un flux de lecture déchiffré AES-256-GCM-stream.
    ///
    /// **Phase disque — gardien**
    /// 5. Extrait l'archive `<braise>.feu` dans `~/.feu/` via le flux déchiffré.
    ///    Supprime l'archive après extraction.
    /// 6. Lit les clés chiffrées du foyer depuis le dossier extrait.
    ///
    /// **Phase mémoire — cryptographe**
    /// 7. Déchiffre et charge les clés du foyer dans le trousseau.
    /// 8. Efface le mot de passe et la clé éphémère.
    ///
    /// **Archiviste**
    /// 9. Instancie l'Archiviste du foyer. À la première ouverture, crée l'arborescence
    ///    `registre/` et `classeur0/` à `classeur4/`. Lors des ouvertures suivantes,
    ///    l'Archiviste détecte la présence de `registre/` et ne fait rien.
    ///
    /// **SessionFoyers**
    /// 10. Marque le foyer comme ouvert.
    ///
    /// # Erreurs
    ///
    /// Retourne une [`ErreurFeuNoyau`] si l'index est invalide, si le foyer est déjà
    /// ouvert, si le mot de passe est incorrect, ou si une opération disque échoue.
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
        index_foyer: usize,
    ) -> ResultFeuNoyau<()> {
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        let braise = self.session.index_vers_braise(index_foyer)?;

        if self.session.est_ouvert(index_foyer)? {
            return Err(ErreurFeuNoyau::FoyerDejaOuvert);
        }

        let (cle, mut source, mut destination) = self
            .gardien
            .preparation_desarchivage_chiffre_foyer(braise)?;

        self.cryptographe.donne_flux_dechiffrement_foyer(
            &cle,
            &mut source,
            &mut destination,
            interface_feu_noyau,
        )?;

        self.gardien.desarchivage_chiffre_foyer(braise)?;
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
        self.archivistes[index_foyer] =
            Some(Archiviste::new(self.gardien.donne_chemin_braise(braise))?);

        self.session.change_statut(index_foyer, true)?;
        interface_feu_noyau.recevoir_etat_foyer(index_foyer, true);
        Ok(())
    }

    /// Ferme le foyer à la position `index_foyer` — opération inverse de
    /// [`ouverture_foyer`](Self::ouverture_foyer).
    ///
    /// Réarchive le dossier clair du foyer en une archive `.feu` chiffrée, efface
    /// toute trace en clair du disque et libère les ressources mémoire associées.
    ///
    /// Enchaîne sept étapes séquentielles :
    ///
    /// 1. Valide l'index du foyer.
    /// 2. Vérifie que le foyer est bien ouvert.
    /// 3. Prépare l'archivage : produit le flux source (dossier clair) et la
    ///    destination (archive chiffrée) via le Gardien.
    /// 4. Chiffre le dossier du foyer dans l'archive `.feu` via le Cryptographe.
    /// 5. Supprime l'archive `.tar` intermédiaire et le dossier clair du disque.
    /// 6. Détruit l'Archiviste du foyer — son dossier vient d'être supprimé.
    /// 7. Marque le foyer comme fermé dans la session et notifie la couche de
    ///    présentation.
    ///
    /// # Invariant de sécurité
    ///
    /// À la fin de l'opération, aucune donnée du foyer ne subsiste en clair sur
    /// le disque : seule demeure l'archive `.feu` chiffrée.
    ///
    /// # Erreurs
    ///
    /// Retourne une [`ErreurFeuNoyau`] si l'index est invalide, si le foyer est
    /// déjà fermé, si le chiffrement échoue, ou si une opération disque échoue.
    pub fn fermeture_foyer(
        &mut self,
        interface_feu_noyau: &mut impl InterfaceFeuNoyau,
        index_foyer: usize,
    ) -> ResultFeuNoyau<()> {
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        let braise = self.session.index_vers_braise(index_foyer)?;

        if !self.session.est_ouvert(index_foyer)? {
            return Err(ErreurFeuNoyau::FoyerFerme);
        }

        let (mut source, mut destination) =
            self.gardien.preparation_archivage_chiffre_foyer(braise)?;

        self.cryptographe.donne_flux_chiffrement_foyer(
            index_foyer,
            &mut source,
            &mut destination,
        )?;

        self.gardien.suppression_archive_foyer_tar(braise)?;
        self.gardien.suppression_dossier_braise(braise)?;

        // Destruction de l'archiviste — le dossier du foyer est déjà supprimé.
        self.archivistes[index_foyer] = None;

        self.session.change_statut(index_foyer, false)?;
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
    /// Enchaîne cinq étapes séquentielles :
    ///
    /// 1. Valide l'index du foyer.
    /// 2. Effectue un diagnostic de l'arborescence — rejette si une anomalie est détectée.
    /// 3. Collecte le mot de passe, dérive la clé éphémère et déchiffre les clés
    ///    du foyer depuis le dossier clair.
    /// 4. Marque le foyer comme ouvert dans la session — prérequis de la fermeture.
    /// 5. Déclenche la fermeture standard : archive et chiffre le dossier, détruit
    ///    l'archiviste, supprime le dossier clair.
    ///
    /// # Prérequis
    ///
    /// Le dossier clair `<braise>/` doit exister sur disque et être intact —
    /// le diagnostic vérifie la présence de toutes les clés nécessaires.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'index est invalide, si le diagnostic détecte une
    /// anomalie, si le mot de passe est incorrect, ou si une opération disque échoue.
    pub fn secours_fermeture_foyer(
        &mut self,
        interface_feu_noyau: &mut impl InterfaceFeuNoyau,
        index_foyer: usize,
    ) -> ResultFeuNoyau<()> {
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        let braise = self.session.index_vers_braise(index_foyer)?;
        if !self.gardien.diagnostic_foyer(braise).is_empty() {
            return Err(ErreurFeuNoyau::FermetureSecoursFoyerImpossible);
        }

        self.cryptographe.secours_recoit_trousseau_public_foyer(
            self.gardien.creation_trousseau_foyer_public(braise)?,
            index_foyer,
            interface_feu_noyau,
        )?;

        self.session.change_statut(index_foyer, true)?;
        self.fermeture_foyer(interface_feu_noyau, index_foyer)?;

        Ok(())
    }

    // ── Données ──────────────────────────────────────────────────────────────

    /// Stocke un blob dans un classeur d'un foyer ouvert.
    ///
    /// Orchestre six opérations séquentielles :
    ///
    /// 1. Valide les index et l'état du foyer.
    /// 2. Crée un tiroir vide via l'Archiviste du foyer.
    /// 3. Lit `source` dans le tiroir par chunks — erreur si la taille dépasse
    ///    [`MAX_TAILLE_BLOB`].
    /// 4. Calcule le hash SHA3-256 du clair et chiffre le blob avec la clé du
    ///    classeur (AES-256-GCM) via le Cryptographe.
    /// 5. Si un blob portant ce hash existe déjà dans le classeur, retourne le
    ///    hash en silence sans réécriture — invariant content-addressable.
    /// 6. Écrit le blob chiffré dans `classeurN/<hash>.dat` via l'Archiviste.
    ///
    /// # Invariants de sécurité
    ///
    /// Le blob en clair ne transite que dans le tiroir et n'est jamais écrit sur
    /// le disque. L'Archiviste ne reçoit le tiroir qu'après chiffrement.
    ///
    /// # Retour
    ///
    /// Retourne le hash SHA3-256 du blob en clair — identifiant content-addressable
    /// à conserver pour relire la donnée via [`lecture_donnees`](Self::lecture_donnees).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont invalides, si le foyer n'est pas
    /// ouvert, si le Cryptographe ou l'Archiviste est absent, si la lecture de
    /// `source` échoue, si la taille dépasse [`MAX_TAILLE_BLOB`], si le chiffrement
    /// échoue, ou si l'écriture disque échoue.
    pub fn depot_donnees(
        &mut self,
        index_foyer: usize,
        index_classeur: usize,
        source: impl Read,
    ) -> ResultFeuNoyau<String> {
        if index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        let mut tiroir = archiviste.donne_tiroir_vide(index_classeur);
        tiroir.remplir(source)?;
        let (blob_chiffre, hash) =
            self.cryptographe
                .chiffrement_blob(index_foyer, index_classeur, tiroir.lire_blob())?;

        if archiviste.existe_blob(index_classeur, &hash) {
            return Ok(hash);
        }

        tiroir.remplace_blob(blob_chiffre);
        tiroir.definit_hash(&hash);
        archiviste.ecrit_blob(tiroir)?;
        Ok(hash)
    }

    /// Lit et déchiffre un blob depuis un classeur d'un foyer ouvert.
    ///
    /// Orchestre trois opérations séquentielles :
    ///
    /// 1. Charge le blob chiffré depuis `classeurN/<hash>.dat` via l'Archiviste du foyer.
    /// 2. Déchiffre le blob avec la clé du classeur (AES-256-GCM) et vérifie son
    ///    intégrité — le hash SHA3-256 du clair doit correspondre à `hash`.
    /// 3. Écrit le blob en clair dans `destination` via le tiroir, puis zéroïse le clair.
    ///
    /// # Invariants de sécurité
    ///
    /// Le blob en clair ne transite que dans le tiroir et n'est jamais écrit sur
    /// le disque. Le tiroir est zéroïsé après vidage.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont invalides, si le foyer n'est pas
    /// ouvert, si le Cryptographe ou l'Archiviste est absent, si aucun fichier
    /// ne correspond au `hash`, si le déchiffrement ou la vérification d'intégrité
    /// échoue, ou si l'écriture dans `destination` échoue.
    pub fn lecture_donnees(
        &mut self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
        destination: impl Write,
    ) -> ResultFeuNoyau<()> {
        if index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

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

    /// Supprime un blob d'un classeur d'un foyer ouvert.
    ///
    /// Supprime le fichier `classeurN/<hash>.dat` via l'Archiviste du foyer.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont invalides, si le foyer n'est pas
    /// ouvert, si l'Archiviste est absent, ou si aucun fichier ne correspond
    /// au `hash` dans le classeur.
    pub fn suppression_donnees(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
    ) -> ResultFeuNoyau<()> {
        if index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        archiviste.supprime_blob(index_classeur, hash)?;
        Ok(())
    }

    /// Retourne la liste des hashes des blobs présents dans un classeur d'un foyer ouvert.
    ///
    /// Délègue à l'Archiviste du foyer, qui parcourt le dossier `classeurN/` et
    /// collecte les noms de fichiers sans extension `.dat`.
    ///
    /// L'ordre des hashes retournés n'est pas garanti.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont invalides, si le foyer n'est pas
    /// ouvert, si l'Archiviste est absent, ou si la lecture du dossier échoue.
    pub fn liste_blobs(
        &self,
        index_foyer: usize,
        index_classeur: usize,
    ) -> ResultFeuNoyau<Vec<String>> {
        if index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        Ok(archiviste.donne_liste_blobs(index_classeur)?)
    }

    /// Indique si un blob est présent dans un classeur d'un foyer ouvert.
    ///
    /// Retourne `true` si `classeurN/<hash>.dat` existe, `false` sinon.
    /// Permet aux couches supérieures d'interroger l'existence d'un blob
    /// sans avoir à le lire.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont invalides, si le foyer n'est pas
    /// ouvert, ou si l'Archiviste est absent.
    pub fn existence_blob(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
    ) -> ResultFeuNoyau<bool> {
        if index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        Ok(archiviste.existe_blob(index_classeur, hash))
    }

    /// Retourne les métadonnées système d'un blob.
    ///
    /// Délègue à l'Archiviste du foyer désigné — voir [`DonneesBlob`] pour le détail des champs.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont hors bornes,
    /// si le foyer n'est pas ouvert, ou si le blob est introuvable.
    pub fn informations_blob(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
    ) -> ResultFeuNoyau<DonneesBlob> {
        if index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        Ok(archiviste.donne_informations_blob(index_classeur, hash)?)
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
    /// # Erreurs
    ///
    /// Retourne une erreur si la taille dépasse
    /// [`MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE`], ou si le chiffrement échoue.
    pub fn chiffrement_asymetrique(
        &self,
        cle_publique_destinataire: &[u8; 1568],
        octets_a_chiffrer: &[u8],
    ) -> ResultFeuNoyau<Vec<u8>> {
        if octets_a_chiffrer.len() >= MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE {
            return Err(ErreurFeuNoyau::TailleMaxDepassee);
        }

        Ok(self
            .cryptographe
            .chiffrement_asymetrique(cle_publique_destinataire, octets_a_chiffrer)?)
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
    /// # Erreurs
    ///
    /// Retourne une erreur si l'index est invalide,
    /// si le foyer n'est pas ouvert, si la taille dépasse la limite,
    /// ou si le déchiffrement échoue.
    pub fn dechiffrement_asymetrique(
        &self,
        index_foyer: usize,
        octets_a_dechiffrer: &[u8],
    ) -> ResultFeuNoyau<Vec<u8>> {
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeuNoyau::FoyerFerme);
        }
        if octets_a_dechiffrer.len() >= MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE + 1596 {
            return Err(ErreurFeuNoyau::TailleMaxDepassee);
        }

        Ok(self
            .cryptographe
            .dechiffrement_asymetrique(index_foyer, octets_a_dechiffrer)?)
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
    /// # Erreurs
    ///
    /// Retourne une erreur si la taille
    /// dépasse [`MAX_TAILLE_SIGNATURE`], ou si la signature échoue.
    pub fn signature_noeud(&self, octets_a_signer: &[u8]) -> ResultFeuNoyau<[u8; 4627]> {
        if octets_a_signer.len() >= MAX_TAILLE_SIGNATURE {
            return Err(ErreurFeuNoyau::TailleMaxDepassee);
        }

        Ok(self.cryptographe.signature_noeud(octets_a_signer)?)
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
    /// # Erreurs
    ///
    /// Retourne une erreur si l'index est invalide,
    /// si le foyer n'est pas ouvert, si la taille dépasse [`MAX_TAILLE_SIGNATURE`],
    /// ou si la signature échoue.
    pub fn signature_foyer(
        &self,
        index_foyer: usize,
        octets_a_signer: &[u8],
    ) -> ResultFeuNoyau<[u8; 4627]> {
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeuNoyau::FoyerFerme);
        }
        if octets_a_signer.len() >= MAX_TAILLE_SIGNATURE {
            return Err(ErreurFeuNoyau::TailleMaxDepassee);
        }

        Ok(self
            .cryptographe
            .signature_foyer(index_foyer, octets_a_signer)?)
    }

    /// Vérifie une signature ML-DSA-87.
    ///
    /// Retourne `Ok(true)` si `signature` est valide pour `octets_signes` avec
    /// `cle_publique`, `Ok(false)` sinon.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `signature` n'est pas un encodage ML-DSA-87 valide.
    pub fn verification_signature(
        cle_publique: [u8; 2592],
        signature: [u8; 4627],
        octets_signes: &[u8],
    ) -> ResultFeuNoyau<bool> {
        Ok(Cryptographe::verification_signature(
            cle_publique,
            signature,
            octets_signes,
        )?)
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
    /// et ouvrir ses foyers : arborescence `~/.feu`, `config.feu`, `.cles/`,
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
    /// # Erreurs
    ///
    /// Retourne une erreur si l'index est invalide,
    /// ou si le foyer n'est pas ouvert.
    pub fn diagnostic_foyer(&self, index_foyer: usize) -> ResultFeuNoyau<Vec<Anomalie>> {
        let archiviste = self.archiviste_foyer_ouvert(index_foyer)?;

        let mut resultat = self
            .gardien
            .diagnostic_foyer(self.session.index_vers_braise(index_foyer)?);

        resultat.extend(archiviste.verifier_arborescence_classeurs()?);

        Ok(resultat)
    }

    fn archiviste_foyer_ouvert(&self, index_foyer: usize) -> ResultFeuNoyau<&Archiviste> {
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeuNoyau::IndexInvalide);
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeuNoyau::FoyerFerme);
        }
        let Some(archiviste) = &self.archivistes[index_foyer] else {
            return Err(ErreurFeuNoyau::ArchivisteIndisponible);
        };
        Ok(archiviste)
    }
}
