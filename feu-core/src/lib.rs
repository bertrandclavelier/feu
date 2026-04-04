// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of Feu.
//
// Feu is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// Feu is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with Feu. If not, see <https://www.gnu.org/licenses/>.

//! `feu-core` est le cœur du protocole Feu.
//!
//! Il expose une interface unique — la structure [`Feu`] — qui orchestre
//! l'ensemble des composants internes : le gardien, responsable des données
//! locales, et le cryptographe, garant de la sécurité cryptographique.
//!
//! Aucun composant interne n'est accessible directement depuis l'extérieur
//! du crate. Toute interaction avec Feu passe par [`Feu`] — cette
//! centralisation est un invariant de sécurité fondamental du protocole.
//!
//! # Plateformes supportées
//!
//! Linux et macOS uniquement. Le protocole repose sur des primitives
//! Unix — système de fichiers, variables d'environnement, permissions —
//! qui n'ont pas d'équivalent direct sous Windows.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("feu-core only supports Linux and macOS.");

use archiviste::Archiviste;
use cryptographe::Cryptographe;
use ed25519_dalek::VerifyingKey;
use gardien::Gardien;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::SystemTime;

pub use erreur::ErreurFeu;
pub use erreur::ResultFeu;

mod archiviste;
mod cryptographe;
mod erreur;
mod gardien;

/// Nombre maximum de foyers dans le nœud
pub const MAX_FOYERS: usize = 3;
/// Nombre maximum de classeurs par foyer.
pub const MAX_CLASSEURS: usize = 5;
/// Taille maximum d'un blob
pub const MAX_TAILLE_BLOB: usize = 512 * 1024 * 1024;

pub const MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE: usize = 1024 * 1024;

pub const MAX_TAILLE_SIGNATURE: usize = 64 * 1024;

pub(crate) const TAILLE_CHUNK: usize = 8 * 1024;

/// Contrat de communication entre `feu-core` et toute interface utilisateur.
///
/// Ce trait définit le canal d'échange entre le cœur du protocole et sa
/// couche de présentation — CLI, TUI ou application. Il remplit deux rôles :
///
/// **Entrées** — le noyau collecte ce dont il a besoin pour opérer :
/// `demander` pour les réponses interactives, `demander_mdp` pour les mots
/// de passe (masqués). La collecte du mot de passe est une responsabilité
/// du noyau : il est le seul à savoir quand et pourquoi en avoir besoin.
///
/// **Notifications d'état** — le noyau informe l'interface des changements
/// d'état significatifs qu'elle ne peut pas observer autrement : clé publique
/// du nœud à l'allumage, clés publiques des foyers à leur ouverture.
/// L'interface fait ce qu'elle veut de ces informations — les stocker, les
/// afficher, les transmettre au réseau.
///
/// `afficher` et `afficher_erreur` sont présentes pour la phase de test
/// (v0.0.2) et ont vocation à disparaître du trait — la couche de présentation
/// n'a pas à dépendre du noyau pour ses messages.
pub trait InterfaceFeuCore {
    /// Affiche un message informatif.
    fn afficher(&self, message: &str);

    /// Affiche un message d'erreur.
    fn afficher_erreur(&self, message: &str);

    /// Collecte une réponse de l'utilisateur.
    /// Retourne une chaîne vide en cas d'erreur de lecture.
    fn demander(&self, question: &str) -> String;

    /// Collecte un mot de passe en masquant la saisie.
    /// Retourne une chaîne vide en cas d'erreur de lecture.
    fn demander_mdp(&self, question: &str) -> String;

    /// Notifie l'interface de la clé publique de signature du nœud.
    ///
    /// Appelée à l'allumage du nœud, après lecture du trousseau public
    /// depuis le disque. Cette clé Ed25519 est l'identité cryptographique
    /// du nœud — socle de l'IdNU à venir.
    fn recevoir_cle_publique_noeud(&self, cle_publique_sig_noeud: [u8; 32]);

    /// Notifie l'interface des clés publiques d'un foyer à son ouverture.
    ///
    /// Appelée après lecture du trousseau public du foyer depuis le disque,
    /// avant chargement des clés privées en mémoire.
    /// - `cle_publique_sig` — clé de signature Ed25519 du foyer.
    /// - `cle_publique_chif` — clé de chiffrement X25519 du foyer.
    fn recevoir_cles_publiques_foyer(
        &self,
        index_foyer: usize,
        cle_publique_sig: [u8; 32],
        cle_publique_chif: [u8; 32],
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

/// Anomalie détectée lors d'un check-up du nœud.
///
/// Retournée dans un [`Vec`] par [`Feu::commande_check_up_noeud`] —
/// un vecteur vide signifie que le nœud est dans un état nominal.
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
    onion: String,
    est_ouvert: bool,
}

impl Foyer {
    /// Crée un [`Foyer`] avec l'adresse `.onion` et l'état d'ouverture fournis.
    fn new(onion: String, est_ouvert: bool) -> Self {
        Self { onion, est_ouvert }
    }
}

/// État de la session courante — foyers ouverts et leurs adresses `.onion`.
///
/// Maintient pour chaque foyer un tuple `(ouvert, onion)` indexé par
/// position. L'index est partagé avec `Configuration::adresses_onion`
/// et le trousseau cryptographique — c'est le point de vérité unique
/// pour relier un foyer à son adresse et à son état d'ouverture.
struct Session {
    /// `true` si le nœud est allumé (trousseau déverrouillé), `false` sinon.
    noeud: bool,
    /// État et adresse de chaque foyer — `(ouvert, adresse_onion)`.
    foyers: [Foyer; MAX_FOYERS],
}

impl Session {
    /// Crée une session vide : tous les foyers sont fermés et sans adresse.
    fn new() -> Self {
        Self {
            noeud: false,
            foyers: std::array::from_fn(|_| Foyer {
                onion: String::from(""),
                est_ouvert: false,
            }),
        }
    }

    /// Retourne l'état et l'adresse de chaque foyer sous forme de tableau.
    ///
    /// Chaque élément est un tuple `(ouvert, adresse_onion)`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le nœud n'est pas allumé.
    fn donne_liste_foyers(&self) -> ResultFeu<[(bool, String); MAX_FOYERS]> {
        if !self.noeud {
            return Err(ErreurFeu::Standard(String::from(
                "Le nœud doit être allumé.",
            )));
        }
        let mut tableau: [(bool, String); MAX_FOYERS] =
            std::array::from_fn(|_| (false, String::from("")));
        for (i, e) in tableau.iter_mut().enumerate() {
            *e = (self.foyers[i].est_ouvert, self.foyers[i].onion.clone());
        }
        Ok(tableau)
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
    fn definition_foyers(&mut self, t: [(bool, String); MAX_FOYERS]) {
        for (i, foyer) in self.foyers.iter_mut().enumerate() {
            *foyer = Foyer::new(t[i].1.clone(), t[i].0);
        }
    }

    /// Retourne l'adresse `.onion` du foyer à la position `index`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `index >= MAX_FOYERS`.
    fn index_vers_onion(&self, index: usize) -> ResultFeu<&str> {
        if index >= MAX_FOYERS {
            Err(ErreurFeu::Standard(String::from(
                "Adresse onion introuvable",
            )))
        } else {
            Ok(&self.foyers[index].onion)
        }
    }

    /// Retourne la position d'un foyer à partir de son adresse `.onion`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'adresse n'est pas trouvée dans la session.
    fn onion_vers_index(&self, onion: &str) -> ResultFeu<usize> {
        for index in 0..MAX_FOYERS {
            if self.foyers[index].onion == onion {
                return Ok(index);
            }
        }
        Err(ErreurFeu::Standard(String::from("Index introuvable")))
    }

    /// Indique si le foyer identifié par `onion` est actuellement ouvert.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'adresse n'est pas trouvée dans la session.
    fn onion_est_ouvert(&self, onion: &str) -> ResultFeu<bool> {
        Ok(self.foyers[self.onion_vers_index(onion)?].est_ouvert)
    }

    /// Modifie le statut d'ouverture du foyer identifié par `onion`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'adresse n'est pas trouvée dans la session.
    fn change_statut_onion(&mut self, onion: &str, valeur: bool) -> ResultFeu<()> {
        self.foyers[self.onion_vers_index(onion)?].est_ouvert = valeur;

        Ok(())
    }

    /// Modifie le statut d'allumage du nœud.
    fn change_statut_noeud(&mut self, etat: bool) {
        self.noeud = etat;
    }
}

/// Point d'entrée unique du protocole Feu.
///
/// Orchestre `Gardien` et `Cryptographe` sans exposer leurs
/// détails d'implémentation. Paramétrique sur `I: InterfaceFeuCore` —
/// toute communication utilisateur est déléguée à l'interface injectée
/// à la création, garantissant une séparation totale entre logique
/// du protocole et couche de présentation.
pub struct Feu<I: InterfaceFeuCore> {
    /// Canal de communication avec l'interface utilisateur.
    interface_feu_core: I,

    /// État de la session — foyers ouverts et leurs adresses `.onion`.
    session: Session,

    /// Gardien des données locales — fichiers, foyers, configuration.
    /// `None` tant que le nœud n'a pas été initialisé.
    gardien: Option<Gardien>,

    /// Gardien de la sécurité cryptographique — clés, chiffrement, seed.
    /// `None` tant que le nœud n'a pas été initialisé.
    cryptographe: Option<Cryptographe>,

    /// Un Archiviste par foyer ouvert — `None` si le foyer est fermé.
    /// Instancié à l'ouverture du foyer, détruit à la fermeture.
    archivistes: [Option<Archiviste>; MAX_FOYERS],
}

impl<I: InterfaceFeuCore> Drop for Feu<I> {
    /// Filet de sécurité : panic si le nœud n'a pas été éteint proprement.
    ///
    /// Le chemin normal d'arrêt est [`Feu::commande_extinction_noeud`] suivi
    /// de [`Feu::commande_quitter_feu`]. Ce `drop` ne fait pas de cleanup —
    /// il garantit uniquement qu'une sortie silencieuse avec des foyers ouverts
    /// est impossible.
    fn drop(&mut self) {
        if self.session.noeud {
            panic!("Le noeud n'était pas éteint avant de quitter");
        }
    }
}

impl<I: InterfaceFeuCore> Feu<I> {
    /// Crée une instance de [`Feu`] prête à l'emploi.
    ///
    /// Le gardien et le cryptographe ne sont pas encore actifs à ce stade —
    /// ils sont initialisés lors d'un appel ultérieur à
    /// [`commande_initialise_noeud_vierge`](Self::commande_initialise_noeud_vierge)
    /// ou [`commande_allumage_noeud`](Self::commande_allumage_noeud).
    /// L'interface fournie sera utilisée pour toutes les interactions
    /// utilisateur ultérieures.
    pub fn new(interface_feu_core: I) -> Self {
        Self {
            interface_feu_core,
            session: Session::new(),
            gardien: None,
            cryptographe: None,
            archivistes: std::array::from_fn(|_| None),
        }
    }

    /// Indique si le nœud est prêt à être quitté.
    ///
    /// Retourne `true` si le nœud est éteint, `false` s'il est encore allumé.
    /// C'est à l'interface d'interpréter ce retour — quitter la boucle REPL,
    /// afficher un message d'erreur, etc.
    pub fn commande_quitter_feu(&self) -> bool {
        !self.session.noeud
    }

    /// Affiche la version de `feu-core` via l'interface.
    pub fn commande_affiche_version(&self) {
        self.interface_feu_core.afficher(&format!(
            "{} version {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));
    }

    /// Initialise un nœud Feu vierge.
    ///
    /// Enchaîne deux phases séquentielles. Tout le travail cryptographique
    /// est achevé en mémoire avant le premier accès disque — aucune donnée
    /// n'est écrite en cas d'erreur dans la phase mémoire.
    ///
    /// **Phase mémoire — cryptographe**
    /// 1. Collecte le mot de passe Feu.
    /// 2. Génère la seed BIP39 et dérive les clés du nœud et des `MAX_FOYERS` foyers.
    /// 3. Dérive le sel Argon2id et chiffre les clés — produit le trousseau public.
    ///
    /// **Phase disque — gardien**
    /// 4. Crée l'arborescence globale `~/.feu` et `~/.feu/.cles`.
    /// 5. Crée l'arborescence de chaque foyer `~/.feu/<onion>/.cles`.
    /// 6. Enregistre les `MAX_FOYERS` foyers dans `config.feu` et écrit sur le disque.
    /// 7. Peuple la session avec les adresses `.onion` et marque chaque foyer comme ouvert.
    /// 8. Pour chaque foyer : archive et chiffre le dossier — produit `<onion>.feu`.
    /// 9. Supprime chaque dossier clair `<onion>` après vérification de l'archive.
    /// 10. Droppe le gardien et le cryptographe — le nœud est éteint à l'issue.
    ///
    /// # Erreurs
    ///
    /// Retourne une [`ErreurFeu`] à la première étape qui échoue.
    /// Le gardien et le cryptographe sont intégrés à `self` avant l'étape 7 —
    /// un échec à cette étape laisse `self` dans un état partiellement initialisé.
    ///
    /// # Dette technique
    ///
    /// Si [`commande_fermeture_foyer`](Self::commande_fermeture_foyer) échoue,
    /// `self.gardien` et `self.cryptographe` sont déjà assignés et `config.feu`
    /// est écrit sur le disque. Un mécanisme de rollback est nécessaire pour
    /// garantir l'atomicité complète de l'initialisation.
    pub fn commande_initialise_noeud_vierge(&mut self) -> ResultFeu<()> {
        // Création du gardien et du cryptographe
        let mut gardien = Gardien::new()?;
        let mut cryptographe = Cryptographe::new();

        if gardien.existence_arborescence() {
            return Err(ErreurFeu::Standard(String::from(
                "Une arborescence existe déjà.",
            )));
        }

        // 1- LE CRYPTOGRAPHE TRAVAILLE EN MÉMOIRE

        // Le cryptographe génère les clés nécessaires au fonctionnement d'un nouveau nœud
        cryptographe.initialise_noeud_from_nouvelle_seed(&self.interface_feu_core)?;

        // Le cryptographe génère le trousseau public pour le gardien
        let trousseau_public_complet = cryptographe.donne_trousseau_public_complet()?;

        // 2- LE GARDIEN TRAVAILLE SUR LE DISQUE

        gardien.cree_premiere_arborescence(&trousseau_public_complet)?;

        // Ajout des MAX_FOYERS foyers dans la configuration
        for i in 0..MAX_FOYERS {
            let onion = String::from(
                trousseau_public_complet
                    .donne_trousseau_public_foyer(i)?
                    .donne_onion(),
            );
            gardien.ajout_nouveau_foyer_dans_configuration(onion.clone(), i);
            self.session.foyers[i] = Foyer::new(onion, true);
        }

        // Enregistrement de config.feu
        gardien.enregistrement_configuration()?;

        // Toutes les étapes ont réussi : on les intègre à la structure
        // pour une utilisation lors de la fermeture du foyer.
        self.gardien = Some(gardien);
        self.cryptographe = Some(cryptographe);

        // Fermeture des foyers
        for i in 0..MAX_FOYERS {
            self.commande_fermeture_foyer(&self.session.foyers[i].onion.clone())?;
        }

        // On remercie le gardien et le cryptographe
        self.gardien = None;
        self.cryptographe = None;
        Ok(())
    }

    /// Allume un nœud Feu existant et déverrouille le trousseau cryptographique.
    ///
    /// Enchaîne deux phases séquentielles :
    ///
    /// **Phase disque — gardien**
    /// 1. Vérifie l'existence de l'arborescence `~/.feu` et charge `config.feu`.
    /// 2. Lit le sel et la clé de signature du nœud depuis `~/.feu/.cles/`.
    ///
    /// **Phase mémoire — cryptographe**
    /// 3. Collecte le mot de passe Feu via l'interface.
    /// 4. Dérive la clé éphémère AES-256-GCM via Argon2id(mot de passe, sel).
    /// 5. Tente de déchiffrer la clé privée de signature du nœud — si le mot
    ///    de passe est incorrect, le déchiffrement AES-GCM échoue et l'erreur
    ///    est propagée. C'est le mécanisme de vérification du mot de passe.
    /// 6. Efface le mot de passe et la clé éphémère de la mémoire.
    /// 7. Peuple la session avec les adresses `.onion` des foyers lues depuis
    ///    `config.feu` — tous les foyers sont marqués éteints à ce stade.
    /// 8. Marque le nœud comme actif dans la session.
    ///
    /// Les foyers ne sont pas déchiffrés à cette étape — chaque foyer est
    /// allumé explicitement via une commande dédiée.
    ///
    /// # Erreurs
    ///
    /// Retourne une [`ErreurFeu`] si le nœud est déjà allumé, si l'arborescence
    /// `~/.feu` est introuvable, si `config.feu` est absent ou illisible, si un
    /// fichier de clé est absent ou de taille incorrecte, ou si le mot de passe
    /// est incorrect.
    pub fn commande_allumage_noeud(&mut self) -> ResultFeu<()> {
        if self.session.noeud {
            return Err(ErreurFeu::Standard(String::from(
                "Le nœud est déjà allumé.",
            )));
        }

        let gardien = Gardien::ouvre_nouveau()?;
        let mut cryptographe = Cryptographe::new();

        let trousseau_public_noeud = &gardien.lecture_pour_creation_trousseau_public_noeud()?;

        self.interface_feu_core
            .recevoir_cle_publique_noeud(trousseau_public_noeud.donne_cle_sig_pub());

        cryptographe
            .recoit_trousseau_public_noeud(trousseau_public_noeud, &self.interface_feu_core)?;

        self.session
            .definition_foyers(gardien.creation_tableau_session_foyers());

        self.gardien = Some(gardien);
        self.cryptographe = Some(cryptographe);

        self.session.change_statut_noeud(true);
        Ok(())
    }

    /// Éteint le nœud Feu et libère le gardien et le cryptographe.
    ///
    /// Toutes les clés en mémoire sont supprimées avec le drop du cryptographe.
    /// La session est marquée comme inactive.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si au moins un foyer est encore ouvert — tous les
    /// foyers doivent être fermés avant d'éteindre le nœud.
    pub fn commande_extinction_noeud(&mut self) -> ResultFeu<()> {
        if !self.session.est_tout_ferme() {
            return Err(ErreurFeu::Standard(String::from(
                "Tous les foyers doivent être fermés.",
            )));
        }
        self.gardien = None;
        self.cryptographe = None;

        self.session.change_statut_noeud(false);

        Ok(())
    }

    /// Ouvre un foyer Feu existant : déchiffre l'archive, charge les clés en mémoire
    /// et initialise l'Archiviste du foyer.
    ///
    /// Enchaîne six phases séquentielles :
    ///
    /// **Vérifications préalables**
    /// 1. Vérifie que `index < MAX_FOYERS` et que le foyer n'est pas déjà ouvert.
    ///
    /// **Phase mémoire — cryptographe**
    /// 2. Collecte le mot de passe Feu et dérive la clé éphémère Argon2id.
    /// 3. Déchiffre la clé symétrique du foyer (`<onion>.cle`) avec la clé éphémère.
    /// 4. Crée un flux de lecture déchiffré AES-256-GCM-stream.
    ///
    /// **Phase disque — gardien**
    /// 5. Extrait l'archive `<onion>.feu` dans `~/.feu/` via le flux déchiffré.
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
    /// **Session**
    /// 10. Marque le foyer comme ouvert.
    ///
    /// # Erreurs
    ///
    /// Retourne une [`ErreurFeu`] si l'index est invalide, si le foyer est déjà
    /// ouvert, si le gardien ou le cryptographe est absent, si le mot de passe est
    /// incorrect, ou si une opération disque échoue.
    ///
    /// # Avertissement sécurité
    ///
    /// Si une erreur survient entre la dérivation de la clé éphémère (étape 2) et
    /// son effacement (étape 8), le mot de passe et la clé éphémère restent en
    /// mémoire. Un mécanisme de drop guard sera introduit pour garantir l'effacement
    /// sur tous les chemins d'erreur.
    pub fn commande_ouverture_foyer(&mut self, index_foyer: usize) -> ResultFeu<()> {
        if !self.session.noeud {
            return Err(ErreurFeu::Standard(String::from(
                "Le nœud doit être allumé.",
            )));
        }

        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeu::Standard(String::from("Index foyer trop élevé.")));
        }
        let onion = self.session.index_vers_onion(index_foyer)?;

        if self.session.onion_est_ouvert(onion)? {
            return Err(ErreurFeu::Standard(String::from(
                "Le foyer est déjà ouvert.",
            )));
        }

        match (&mut self.gardien, &mut self.cryptographe) {
            (Some(g), Some(c)) => {
                let (cle, mut source, mut destination) =
                    g.preparation_desarchivage_chiffre_foyer(onion)?;

                c.donne_flux_dechiffrement_foyer(
                    &cle,
                    &mut source,
                    &mut destination,
                    &self.interface_feu_core,
                )?;

                g.desarchivage_chiffre_foyer(onion)?;
                let trousseau_public_foyer = g.creation_trousseau_foyer_public(onion)?;

                self.interface_feu_core.recevoir_cles_publiques_foyer(
                    index_foyer,
                    trousseau_public_foyer.donne_cle_sig_pub(),
                    trousseau_public_foyer.donne_cle_chiff_pub(),
                );

                c.recoit_trousseau_public_foyer(trousseau_public_foyer, index_foyer)?;

                // Instanciation de l'archiviste — crée l'arborescence classeurs/registre
                // à la première ouverture, ne fait rien lors des ouvertures suivantes.
                self.archivistes[index_foyer] = Some(Archiviste::new(g.donne_chemin_onion(onion))?);

                self.session.foyers[index_foyer].est_ouvert = true;
                Ok(())
            }
            (_, _) => Err(ErreurFeu::Standard(String::from(
                "Gardien et/ou cryptographe absent",
            ))),
        }
    }

    /// Ferme un foyer à partir de son index dans la session.
    ///
    /// Résout l'index en adresse `.onion` puis délègue à
    /// [`commande_fermeture_foyer`](Self::commande_fermeture_foyer).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `index >= MAX_FOYERS` ou si la fermeture échoue.
    pub fn commande_fermeture_foyer_index(&mut self, index: usize) -> ResultFeu<()> {
        let onion = String::from(self.session.index_vers_onion(index)?);
        self.commande_fermeture_foyer(&onion)?;
        Ok(())
    }

    /// Archive et chiffre le dossier d'un foyer, détruit l'Archiviste, puis supprime
    /// le dossier clair.
    ///
    /// Orchestre quatre opérations séquentielles :
    /// 1. Ouvre le fichier de destination `<onion>.feu` en écriture.
    /// 2. Crée l'archive tar chiffrée AES-256-GCM-stream du dossier `<onion>`.
    ///    L'archive inclut `registre/`, `classeur0/` à `classeur4/` et leur contenu.
    /// 3. Supprime le dossier clair `<onion>` après vérification que l'archive existe.
    /// 4. Détruit l'Archiviste du foyer.
    ///
    /// # Prérequis
    ///
    /// Le gardien et le cryptographe doivent être initialisés dans `self`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le gardien ou le cryptographe est absent,
    /// si la création de l'archive échoue, ou si la suppression du dossier échoue.
    pub fn commande_fermeture_foyer(&mut self, onion: &str) -> ResultFeu<()> {
        if !self.session.onion_est_ouvert(onion)? {
            return Err(ErreurFeu::Standard(String::from(
                "Le foyer n'est pas ouvert.",
            )));
        }

        match (&self.gardien, &self.cryptographe) {
            (Some(gardien), Some(cryptographe)) => {
                let (mut source, mut destination) =
                    gardien.preparation_archivage_chiffre_foyer(onion)?;

                cryptographe.donne_flux_chiffrement_foyer(
                    self.session.onion_vers_index(onion)?,
                    &mut source,
                    &mut destination,
                )?;

                gardien.suppression_archive_foyer_tar(onion)?;
                gardien.suppression_dossier_onion(onion)?;

                // Destruction de l'archiviste — le dossier du foyer est déjà supprimé.
                self.archivistes[self.session.onion_vers_index(onion)?] = None;

                self.session.change_statut_onion(onion, false)?;

                Ok(())
            }
            (_, _) => Err(ErreurFeu::Standard(String::from(
                "Le gardien et/ou le cryptographe est absent.",
            ))),
        }
    }

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
    /// Retourne une erreur si un foyer n'est pas ouvert, si le gardien ou le
    /// cryptographe est absent, ou si une opération disque échoue.
    pub fn commande_changement_mdp(&mut self) -> ResultFeu<()> {
        if !self.session.est_tout_ouvert() {
            return Err(ErreurFeu::Standard(String::from(
                "Tous les foyers doivent être ouverts.",
            )));
        }

        match (&mut self.gardien, &mut self.cryptographe) {
            (Some(gardien), Some(cryptographe)) => {
                let trousseau_public_complet =
                    cryptographe.changement_mdp(&self.interface_feu_core)?;
                gardien.ecriture_trousseau_public_complet(&trousseau_public_complet)?;
                Ok(())
            }
            (_, _) => Err(ErreurFeu::Standard(String::from(
                "Le gardien et/ou le cryptographe est absent.",
            ))),
        }
    }

    /// Retourne l'état courant des foyers de la session.
    ///
    /// Chaque élément du tableau est un tuple `(ouvert, adresse_onion)`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le nœud n'est pas allumé.
    pub fn commande_liste_foyers(&self) -> ResultFeu<[(bool, String); MAX_FOYERS]> {
        self.session.donne_liste_foyers()
    }

    /// Stocke un blob dans un classeur d'un foyer ouvert.
    ///
    /// Orchestre cinq opérations séquentielles :
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
    /// à conserver pour relire la donnée via [`commande_lecture_donnees`](Self::commande_lecture_donnees).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si les index sont invalides, si le foyer n'est pas
    /// ouvert, si le Cryptographe ou l'Archiviste est absent, si la lecture de
    /// `source` échoue, si la taille dépasse [`MAX_TAILLE_BLOB`], si le chiffrement
    /// échoue, ou si l'écriture disque échoue.
    pub fn commande_depot_donnees(
        &mut self,
        index_foyer: usize,
        index_classeur: usize,
        source: impl Read,
    ) -> ResultFeu<String> {
        if index_foyer >= MAX_FOYERS || index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeu::Standard(String::from("Index incorrect")));
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeu::Standard(String::from(
                "Le foyer doit être ouvert",
            )));
        }
        let Some(cryptographe) = &self.cryptographe else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver le cryptographe.",
            )));
        };
        let Some(archiviste) = &self.archivistes[index_foyer] else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver l'archiviste.",
            )));
        };

        let mut tiroir = archiviste.donne_tiroir_vide(index_classeur);
        tiroir.remplir(source)?;
        let (blob_chiffre, hash) =
            cryptographe.chiffrement_blob(index_foyer, index_classeur, tiroir.lire_blob())?;

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
    pub fn commande_lecture_donnees(
        &mut self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
        destination: impl Write,
    ) -> ResultFeu<()> {
        if index_foyer >= MAX_FOYERS || index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeu::Standard(String::from("Index incorrect")));
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeu::Standard(String::from(
                "Le foyer doit être ouvert",
            )));
        }
        let Some(cryptographe) = &self.cryptographe else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver le cryptographe.",
            )));
        };
        let Some(archiviste) = &self.archivistes[index_foyer] else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver l'archiviste.",
            )));
        };

        let mut tiroir = archiviste.donne_tiroir_plein(index_classeur, hash)?;

        tiroir.remplace_blob(cryptographe.dechiffrement_blob(
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
    pub fn commande_suppression_donnees(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
    ) -> ResultFeu<()> {
        if index_foyer >= MAX_FOYERS || index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeu::Standard(String::from("Index incorrect")));
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeu::Standard(String::from(
                "Le foyer doit être ouvert",
            )));
        }
        let Some(archiviste) = &self.archivistes[index_foyer] else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver l'archiviste.",
            )));
        };

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
    pub fn commande_liste_blobs(
        &self,
        index_foyer: usize,
        index_classeur: usize,
    ) -> ResultFeu<Vec<String>> {
        if index_foyer >= MAX_FOYERS || index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeu::Standard(String::from("Index incorrect")));
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeu::Standard(String::from(
                "Le foyer doit être ouvert",
            )));
        }
        let Some(archiviste) = &self.archivistes[index_foyer] else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver l'archiviste.",
            )));
        };

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
    pub fn commande_blob_existe(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
    ) -> ResultFeu<bool> {
        if index_foyer >= MAX_FOYERS || index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeu::Standard(String::from("Index incorrect")));
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeu::Standard(String::from(
                "Le foyer doit être ouvert",
            )));
        }
        let Some(archiviste) = &self.archivistes[index_foyer] else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver l'archiviste.",
            )));
        };

        Ok(archiviste.existe_blob(index_classeur, hash))
    }

    /// Chiffre des octets à destination d'un nœud identifié par sa clé publique X25519.
    ///
    /// Délègue au cryptographe qui implémente le schéma ECIES X25519 + AES-256-GCM.
    /// Aucune clé privée du trousseau n'est utilisée — seule la clé publique du
    /// destinataire est nécessaire.
    ///
    /// La taille des données est limitée à [`MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE`] —
    /// l'intégralité du clair et du ciphertext sont chargés en mémoire.
    ///
    /// # Format de sortie
    ///
    /// Voir [`Cryptographe::chiffrement_asymetrique`] pour le détail du format.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le nœud n'est pas allumé, si la taille dépasse
    /// [`MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE`], ou si le chiffrement échoue.
    pub fn commande_chiffrement_asymetrique(
        &self,
        cle_publique_destinataire: &[u8; 32],
        octets_a_chiffrer: &[u8],
    ) -> ResultFeu<Vec<u8>> {
        if !self.session.noeud {
            return Err(ErreurFeu::Standard(String::from(
                "Le nœud doit être allumé.",
            )));
        }
        if octets_a_chiffrer.len() >= MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE {
            return Err(ErreurFeu::Standard(String::from(
                "Dépassement taille pour chiffrement asymétrique",
            )));
        }
        let Some(cryptographe) = &self.cryptographe else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver le cryptographe.",
            )));
        };

        Ok(cryptographe.chiffrement_asymetrique(cle_publique_destinataire, octets_a_chiffrer)?)
    }

    /// Déchiffre un message chiffré à destination de ce foyer.
    ///
    /// Réciproque de [`commande_chiffrement_asymetrique`](Self::commande_chiffrement_asymetrique) —
    /// délègue au cryptographe qui effectue le ECDH X25519 + HKDF + AES-256-GCM.
    /// La clé privée X25519 du foyer doit être présente dans le trousseau,
    /// ce qui requiert que le foyer soit ouvert.
    ///
    /// La taille des données est limitée à [`MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE`] + 60 octets
    /// (surcoût du schéma ECIES : 32 clé éphémère + 12 nonce + 16 auth tag).
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le nœud n'est pas allumé, si l'index est invalide,
    /// si le foyer n'est pas ouvert, si la taille dépasse la limite,
    /// ou si le déchiffrement échoue.
    pub fn commande_dechiffrement_asymetrique(
        &self,
        index_foyer: usize,
        octets_a_dechiffrer: &[u8],
    ) -> ResultFeu<Vec<u8>> {
        if !self.session.noeud {
            return Err(ErreurFeu::Standard(String::from(
                "Le nœud doit être allumé.",
            )));
        }
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeu::Standard(String::from("Index foyer incorrect")));
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeu::Standard(String::from(
                "Le foyer doit être ouvert",
            )));
        }
        if octets_a_dechiffrer.len() >= MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE + 60 {
            return Err(ErreurFeu::Standard(String::from(
                "Dépassement taille pour déchiffrement asymétrique",
            )));
        }
        let Some(cryptographe) = &self.cryptographe else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver le cryptographe.",
            )));
        };

        Ok(cryptographe.dechiffrement_asymetrique(index_foyer, octets_a_dechiffrer)?)
    }

    /// Signe des octets avec la clé privée de signature Ed25519 du nœud.
    ///
    /// La clé de signature du nœud (`m/0'`) est l'identité cryptographique
    /// racine — elle signe les IdNU et tout acte engageant le nœud dans
    /// sa globalité.
    ///
    /// La taille des données est limitée à [`MAX_TAILLE_SIGNATURE`] —
    /// cette fonction est destinée aux structures légères (IdNU, ENU),
    /// pas aux blobs de données.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le nœud n'est pas allumé, si la taille
    /// dépasse [`MAX_TAILLE_SIGNATURE`], ou si le cryptographe est absent.
    pub fn commande_signature_noeud(&self, octets_a_signer: &[u8]) -> ResultFeu<[u8; 64]> {
        if !self.session.noeud {
            return Err(ErreurFeu::Standard(String::from(
                "Le nœud doit être allumé.",
            )));
        }
        if octets_a_signer.len() >= MAX_TAILLE_SIGNATURE {
            return Err(ErreurFeu::Standard(String::from(
                "Dépassement taille pour signature",
            )));
        }
        let Some(cryptographe) = &self.cryptographe else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver le cryptographe.",
            )));
        };

        Ok(cryptographe.signature_noeud(octets_a_signer)?)
    }

    /// Signe des octets avec la clé privée de signature Ed25519 du foyer.
    ///
    /// La clé de signature du foyer (`m/index'`, message `"feu-foyer-paire-signature"`)
    /// authentifie les ENU et les échanges réseau du foyer.
    /// Le foyer doit être ouvert — sa clé privée doit être présente en mémoire.
    ///
    /// La taille des données est limitée à [`MAX_TAILLE_SIGNATURE`] —
    /// cette fonction est destinée aux structures légères (IdNU, ENU),
    /// pas aux blobs de données.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le nœud n'est pas allumé, si l'index est invalide,
    /// si le foyer n'est pas ouvert, si la taille dépasse [`MAX_TAILLE_SIGNATURE`],
    /// ou si le cryptographe est absent.
    pub fn commande_signature_foyer(
        &self,
        index_foyer: usize,
        octets_a_signer: &[u8],
    ) -> ResultFeu<[u8; 64]> {
        if !self.session.noeud {
            return Err(ErreurFeu::Standard(String::from(
                "Le nœud doit être allumé.",
            )));
        }
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeu::Standard(String::from("Index foyer incorrect")));
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeu::Standard(String::from(
                "Le foyer doit être ouvert",
            )));
        }
        if octets_a_signer.len() >= MAX_TAILLE_SIGNATURE {
            return Err(ErreurFeu::Standard(String::from(
                "Dépassement taille pour signature",
            )));
        }
        let Some(cryptographe) = &self.cryptographe else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver le cryptographe.",
            )));
        };

        Ok(cryptographe.signature_foyer(index_foyer, octets_a_signer)?)
    }

    /// Vérifie une signature Ed25519.
    ///
    /// Retourne `Ok(true)` si `signature` est valide pour `octets_signes` avec
    /// `cle_publique`, `Ok(false)` sinon.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le nœud n'est pas allumé.
    pub fn commande_verification_signature(
        &self,
        cle_publique: VerifyingKey,
        signature: [u8; 64],
        octets_signes: &[u8],
    ) -> ResultFeu<bool> {
        if !self.session.noeud {
            return Err(ErreurFeu::Standard(String::from(
                "Le nœud doit être allumé.",
            )));
        }

        Ok(Cryptographe::verification_signature(
            cle_publique,
            signature,
            octets_signes,
        ))
    }

    /// Retourne les métadonnées système d'un blob.
    ///
    /// Délègue à l'Archiviste du foyer désigné — voir [`DonneesBlob`] pour le détail des champs.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le nœud n'est pas allumé, si les index sont hors bornes,
    /// si le foyer n'est pas ouvert, ou si le blob est introuvable.
    pub fn commande_informations_blob(
        &self,
        index_foyer: usize,
        index_classeur: usize,
        hash: &str,
    ) -> ResultFeu<DonneesBlob> {
        if !self.session.noeud {
            return Err(ErreurFeu::Standard(String::from(
                "Le nœud doit être allumé.",
            )));
        }
        if index_foyer >= MAX_FOYERS || index_classeur >= MAX_CLASSEURS {
            return Err(ErreurFeu::Standard(String::from("Index incorrect")));
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeu::Standard(String::from(
                "Le foyer doit être ouvert",
            )));
        }
        let Some(archiviste) = &self.archivistes[index_foyer] else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver l'archiviste.",
            )));
        };

        Ok(archiviste.donne_informations_blob(index_classeur, hash)?)
    }

    /// Diagnostique l'état du nœud sans modifier quoi que ce soit.
    ///
    /// Vérifie la présence de tous les fichiers nécessaires pour allumer le nœud
    /// et ouvrir ses foyers : arborescence `~/.feu`, `config.feu`, `.cles/`,
    /// clés du nœud, archives et clés de chaque foyer connu.
    ///
    /// Fonction associée — utilisable sans nœud allumé, notamment pour
    /// diagnostiquer pourquoi [`Feu::commande_allumer`] échoue.
    ///
    /// # Retour
    ///
    /// `Ok(vec![])` si le nœud est dans un état nominal.
    /// `Ok(vec![...])` avec la liste des anomalies détectées sinon.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la variable d'environnement `HOME` est absente.
    pub fn commande_check_up_noeud() -> ResultFeu<Vec<Anomalie>> {
        let gardien = Gardien::new()?;

        Ok(gardien.check_up_noeud()?)
    }

    /// Diagnostique l'état d'un foyer ouvert sans modifier quoi que ce soit.
    ///
    /// Vérifie la présence des clés du foyer et des clés de classeurs sur disque,
    /// ainsi que l'arborescence interne : dossier `registre/` et liens symboliques
    /// vers les classeurs.
    ///
    /// Complète [`Feu::commande_check_up_noeud`] qui couvre l'état du foyer fermé
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
    /// Retourne une erreur si le nœud n'est pas allumé, si l'index est invalide,
    /// ou si le foyer n'est pas ouvert.
    pub fn commande_check_up_foyer(&self, index_foyer: usize) -> ResultFeu<Vec<Anomalie>> {
        if !self.session.noeud {
            return Err(ErreurFeu::Standard(String::from(
                "Le nœud doit être allumé.",
            )));
        }
        if index_foyer >= MAX_FOYERS {
            return Err(ErreurFeu::Standard(String::from("Index incorrect")));
        }
        if !self.session.foyers[index_foyer].est_ouvert {
            return Err(ErreurFeu::Standard(String::from(
                "Le foyer doit être ouvert",
            )));
        }
        let Some(gardien) = &self.gardien else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver le gardien.",
            )));
        };
        let Some(archiviste) = &self.archivistes[index_foyer] else {
            return Err(ErreurFeu::Standard(String::from(
                "Impossible de trouver l'archiviste.",
            )));
        };

        let mut resultat = gardien.check_up_foyer(self.session.index_vers_onion(index_foyer)?);

        resultat.extend(archiviste.verifier_arborescence_classeurs()?);

        Ok(resultat)
    }
}
