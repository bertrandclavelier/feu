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

mod cryptographe;
mod erreur;
mod gardien;

use cryptographe::Cryptographe;
use gardien::Gardien;

pub use erreur::ErreurFeu;
pub use erreur::ResultFeu;

/// Contrat de communication entre `feu-core` et toute interface utilisateur.
///
/// Ce trait définit le canal d'échange entre le cœur du protocole et sa
/// couche de présentation — CLI, TUI ou web. Chaque implémentation est
/// libre de définir son niveau de verbosité : `afficher_min` garantit
/// l'affichage de l'essentiel, `afficher` couvre le flux standard,
/// `afficher_max` expose le détail pour les modes bavards.
/// `afficher_erreur` signale tout échec à l'utilisateur.
/// `demander` collecte une réponse interactive, `demander_mdp` collecte
/// un mot de passe en masquant la saisie.
pub trait InterfaceFeuCore {
    /// Affiche un message essentiel — visible dans tous les modes.
    fn afficher_min(&self, message: &str);

    /// Affiche un message standard — visible en mode standard et max.
    fn afficher(&self, message: &str);

    /// Affiche un message détaillé — visible uniquement en mode max.
    fn afficher_max(&self, message: &str);

    /// Affiche un message d'erreur.
    fn afficher_erreur(&self, message: &str);

    /// Collecte une réponse de l'utilisateur.
    /// Retourne une chaîne vide en cas d'erreur de lecture.
    fn demander(&self, question: &str) -> String;

    /// Collecte un mot de passe en masquant la saisie.
    /// Retourne une chaîne vide en cas d'erreur de lecture.
    fn demander_mdp(&self, question: &str) -> String;
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
    /// [`initialise_noeud_vierge`](Self::initialise_noeud_vierge).
    /// L'interface fournie sera utilisée pour toutes les interactions
    /// utilisateur ultérieures.
    pub fn new(interface_feu_core: I) -> Self {
        Self {
            interface_feu_core,
            gardien: None,
            cryptographe: None,
        }
    }

    /// Affiche la version de `feu-core` via l'interface.
    ///
    /// Le message est émis au niveau `afficher_min` — il est donc visible
    /// dans tous les modes de verbosité.
    pub fn affiche_version(&self) {
        self.interface_feu_core.afficher_min(&format!(
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
    /// 2. Génère la seed BIP39 et dérive les clés du nœud et du premier foyer.
    /// 3. Dérive le sel Argon2id et chiffre les clés — produit le trousseau public.
    ///
    /// **Phase disque — gardien**
    /// 4. Crée l'arborescence globale `~/.feu` et `~/.feu/.cles`.
    /// 5. Crée l'arborescence du premier foyer `~/.feu/<onion>/.cles`.
    /// 6. Enregistre le foyer dans `feu.toml` et écrit sur le disque.
    /// 7. Archive et chiffre le dossier du foyer — produit `<onion>.feu`.
    /// 8. Supprime le dossier clair `<onion>` après vérification de l'archive.
    /// 9. Droppe le gardien et le cryptographe — le nœud est éteint à l'issue.
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
    /// `self.gardien` et `self.cryptographe` sont déjà assignés et `feu.toml`
    /// est écrit sur le disque. Un mécanisme de rollback est nécessaire pour
    /// garantir l'atomicité complète de l'initialisation.
    pub fn initialise_noeud_vierge(&mut self) -> ResultFeu<()> {
        // Création du gardien et du cryptographe
        let mut gardien = Gardien::new()?;
        let mut cryptographe = Cryptographe::new();

        // 1- LE CRYPTOGRAPHE TRAVAILLE EN MÉMOIRE

        // Le cryptographe demande à l'utilisateur de définir un mot de passe 'Feu'
        cryptographe.nouveau_mdp(&self.interface_feu_core);

        // Le cryptographe génère les clés nécessaires au fonctionnement d'un nouveau nœud
        cryptographe.initialise_noeud_from_nouvelle_seed(&self.interface_feu_core)?;

        // Le cryptographe génère le trousseau public pour le gardien
        let trousseau_public = cryptographe.genere_trousseau_public()?;

        // 2- LE GARDIEN TRAVAILLE SUR LE DISQUE

        gardien.cree_premiere_arborescence(&trousseau_public)?;

        // Ajout du SEUL foyer dans FeuToml (on est sûr qu'il y en a un)
        let cle = match trousseau_public.cles_foyers.iter().next() {
            Some((c, _)) => {
                gardien.ajout_nouveau_foyer_dans_feu_toml(c.clone());
                c.clone()
            }
            None => {
                return Err(ErreurFeu::Gardien(String::from(
                    "Erreur de récupération du .onion.",
                )));
            }
        };

        // Enregistrement de feu.toml
        gardien.enregistrement_feu_toml()?;

        // Toutes les étapes ont réussi : on les intègre à la structure
        // pour une utilisation lors de la fermeture du foyer.
        self.gardien = Some(gardien);
        self.cryptographe = Some(cryptographe);

        // Fermeture du foyer
        self.commande_fermeture_foyer(&cle)?;

        // On remercie le gardien et le cryptographe
        self.gardien = None;
        self.cryptographe = None;
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
    pub fn commande_fermeture_foyer(&self, onion: &str) -> ResultFeu<()> {
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
                Ok(())
            }
            (_, _) => Err(ErreurFeu::Gardien(String::from("Le gardien est absent."))),
        }
    }
}
