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
/// Nombre maximum de classeurs par foyer.
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

struct Foyer {
    onion: String,
    est_ouvert: bool,
}

impl Foyer {
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
    fn donne_liste_foyers(&self) -> [(bool, String); MAX_FOYERS] {
        let mut tableau: [(bool, String); MAX_FOYERS] =
            std::array::from_fn(|_| (false, String::from("")));
        for i in 0..MAX_FOYERS {
            tableau[i] = (self.foyers[i].est_ouvert, self.foyers[i].onion.clone());
        }
        tableau
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
        for i in 0..MAX_FOYERS {
            self.foyers[i] = Foyer::new(t[i].1.clone(), t[i].0);
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

        cryptographe.recoit_trousseau_public_noeud(
            &gardien.lecture_pour_creation_trousseau_public_noeud()?,
            &self.interface_feu_core,
        )?;

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

    /// Ouvre un foyer Feu existant : déchiffre l'archive et charge les clés en mémoire.
    ///
    /// Enchaîne cinq phases séquentielles :
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
    /// **Session**
    /// 9. Marque le foyer comme ouvert.
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
    pub fn commande_ouverture_foyer(&mut self, index: usize) -> ResultFeu<()> {
        if !self.session.noeud {
            return Err(ErreurFeu::Standard(String::from(
                "Le nœud doit être allumé.",
            )));
        }

        if index >= MAX_FOYERS {
            return Err(ErreurFeu::Standard(String::from("Index foyer trop élevé.")));
        }
        let onion = self.session.index_vers_onion(index)?;

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

                c.recoit_trousseau_public_foyer(trousseau_public_foyer, index)?;

                self.session.foyers[index].est_ouvert = true;
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

    /// Archive et chiffre le dossier d'un foyer, puis supprime le dossier clair
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
                let (mut source, mut destination) =
                    gardien.preparation_archivage_chiffre_foyer(onion)?;

                cryptographe.donne_flux_chiffrement_foyer(
                    self.session.onion_vers_index(onion)?,
                    &mut source,
                    &mut destination,
                )?;

                gardien.suppression_archive_foyer_tar(onion)?;
                gardien.suppression_dossier_onion(onion)?;

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
    /// Chaque élément du tableau est un tuple `(allumé, adresse_onion)`.
    /// Les adresses sont vides tant que le nœud n'a pas été allumé.
    pub fn commande_liste_foyers(&self) -> [(bool, String); MAX_FOYERS] {
        self.session.donne_liste_foyers().clone()
    }
}
