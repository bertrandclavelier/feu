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

use cryptographe::Cryptographe;
use gardien::Gardien;

pub use erreur::ErreurFeu;
pub use erreur::ResultFeu;

mod cryptographe;
mod erreur;
mod gardien;

pub const MAX_FOYERS: usize = 3;
pub const MAX_CLASSEURS: usize = 5;

/// Contrat de communication entre `feu-core` et toute interface utilisateur.
///
/// Ce trait définit le canal d'échange entre le cœur du protocole et sa
/// couche de présentation — CLI, TUI ou web. `feu-core` émet des messages
/// via `afficher` et `afficher_erreur` sans présumer du niveau de verbosité —
/// c'est l'interface qui décide de ce qu'elle affiche et comment.
/// `demander` collecte une réponse interactive, `demander_mdp` collecte
/// un mot de passe en masquant la saisie.
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
    foyers: [(bool, String); MAX_FOYERS],
}

impl Session {
    /// Crée une session vide : tous les foyers sont fermés et sans adresse.
    fn new() -> Self {
        Self {
            noeud: false,
            foyers: std::array::from_fn(|_| (false, String::from(""))),
        }
    }

    /// Remplace le tableau des foyers par celui fourni.
    ///
    /// Utilisé à l'allumage pour peupler la session avec les adresses
    /// lues depuis `config.feu`.
    fn definition_foyers(&mut self, t: [(bool, String); MAX_FOYERS]) {
        self.foyers = t;
    }

    /// Retourne l'adresse `.onion` du foyer à la position `indice`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `indice >= MAX_FOYERS`.
    #[allow(dead_code)]
    fn indice_vers_onion(&self, indice: usize) -> ResultFeu<&str> {
        if indice >= MAX_FOYERS {
            Err(ErreurFeu::Standard(String::from(
                "Adresse onion introuvable",
            )))
        } else {
            Ok(&self.foyers[indice].1)
        }
    }

    /// Retourne la position d'un foyer à partir de son adresse `.onion`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'adresse n'est pas trouvée dans la session.
    fn onion_vers_indice(&self, onion: &str) -> ResultFeu<usize> {
        for i in 0..MAX_FOYERS {
            if self.foyers[i].1 == onion {
                return Ok(i);
            }
        }
        Err(ErreurFeu::Standard(String::from("Indice introuvable")))
    }

    /// Indique si le foyer identifié par `onion` est actuellement ouvert.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'adresse n'est pas trouvée dans la session.
    fn onion_est_ouvert(&self, onion: &str) -> ResultFeu<bool> {
        let indice = self.onion_vers_indice(onion)?;

        Ok(self.foyers[indice].0)
    }

    /// Modifie le statut d'ouverture du foyer identifié par `onion`.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'adresse n'est pas trouvée dans la session.
    fn change_statut_onion(&mut self, onion: &str, valeur: bool) -> ResultFeu<()> {
        let indice = self.onion_vers_indice(onion)?;

        self.foyers[indice].0 = valeur;

        Ok(())
    }

    /// Modifie le statut d'allumage du nœud.
    fn change_statut_noeud(&mut self, etat: bool) {
        self.noeud = etat;
    }
}

/// Point d'entrée unique du protocole Feu.
///
/// Orchestre [`Gardien`] et [`Cryptographe`] sans exposer leurs
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
        }
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

        if gardien.existance_arborescence() {
            return Err(ErreurFeu::Standard(String::from(
                "Une arborescence existe déjà.",
            )));
        }

        // 1- LE CRYPTOGRAPHE TRAVAILLE EN MÉMOIRE

        // Le cryptographe demande à l'utilisateur de définir un mot de passe 'Feu'
        cryptographe.nouveau_mdp(&self.interface_feu_core);

        // Le cryptographe génère les clés nécessaires au fonctionnement d'un nouveau nœud
        cryptographe.initialise_noeud_from_nouvelle_seed(&self.interface_feu_core)?;

        // Le cryptographe génère le trousseau public pour le gardien
        let trousseau_public = cryptographe.genere_trousseau_public()?;

        // 2- LE GARDIEN TRAVAILLE SUR LE DISQUE

        gardien.cree_premiere_arborescence(&trousseau_public)?;

        // Ajout des MAX_FOYERS foyers dans la configuration
        let mut cles: [String; MAX_FOYERS] = std::array::from_fn(|_| String::from(""));
        for i in 0..MAX_FOYERS {
            cles[i] = match &trousseau_public.cles_foyers[i] {
                Some((c, _)) => {
                    gardien.ajout_nouveau_foyer_dans_configuration(c.clone(), i);
                    self.session.foyers[i] = (true, c.clone());
                    c.clone()
                }
                None => {
                    return Err(ErreurFeu::Gardien(String::from(
                        "Erreur de récupération du .onion.",
                    )));
                }
            };
        }

        // Enregistrement de config.feu
        gardien.enregistrement_configuration()?;

        // Toutes les étapes ont réussi : on les intègre à la structure
        // pour une utilisation lors de la fermeture du foyer.
        self.gardien = Some(gardien);
        self.cryptographe = Some(cryptographe);

        // Fermeture des foyers
        for i in 0..MAX_FOYERS {
            self.commande_fermeture_foyer(&cles[i])?;
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
            return Err(ErreurFeu::Standard(String::from("Le nœud est déjà allumé")));
        }

        let gardien = Gardien::ouvre_nouveau()?;
        let mut cryptographe = Cryptographe::new();

        cryptographe.ouverture_trousseau(
            &gardien.lecture_pour_creation_trousseau_public()?,
            &self.interface_feu_core,
        )?;

        self.session
            .definition_foyers(gardien.creation_tableau_session_foyers());

        self.gardien = Some(gardien);
        self.cryptographe = Some(cryptographe);

        self.session.change_statut_noeud(true);
        Ok(())
    }

    /// Archive et chiffre le dossier d'un foyer, puis supprime le dossier clair.
    ///
    /// Orchestre trois opérations séquentielles :
    /// 1. Ouvre le fichier de destination `<onion>.feu` en écriture.
    /// 2. Crée l'archive tar chiffrée AES-256-GCM-stream du dossier `<onion>`.
    /// 3. Supprime le dossier clair `<onion>` après vérification que l'archive existe.
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
                // Demande au gardien d'ouvrir un fichier en écriture
                let fichier = gardien.ouverture_fichier_ecriture(onion)?;

                // Demande au cryptographe de créer un flux chiffré à transmettre au gardien
                // pour créer l'archive chiffrée
                gardien.creation_archive_chiffree(
                    onion,
                    cryptographe.creation_ecriture_chiffree(onion, fichier)?,
                )?;
                // Demande au gardien de supprimer le dossier `onion` en vérifant qu'une archive existe
                gardien.suppression_dossier_onion(onion)?;

                // Marque le foyer comme fermé dans la session
                self.session.change_statut_onion(onion, false)?;

                Ok(())
            }
            (_, _) => Err(ErreurFeu::Gardien(String::from("Le gardien est absent."))),
        }
    }

    /// Retourne l'état courant des foyers de la session.
    ///
    /// Chaque élément du tableau est un tuple `(allumé, adresse_onion)`.
    /// Les adresses sont vides tant que le nœud n'a pas été allumé.
    pub fn commande_liste_foyers(&self) -> [(bool, String); MAX_FOYERS] {
        self.session.foyers.clone()
    }
}
