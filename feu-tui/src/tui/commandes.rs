// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Filtrage contextuel des commandes utilisateur.
//!
//! Ce module fournit l'abstraction qui sépare *quelles touches sont actives*
//! de *ce qu'elles font*. La boucle clavier de [`crate::tui::Tui`] n'a plus
//! à connaître ni les raccourcis hardcodés, ni les conditions sous lesquelles
//! ils sont valides — elle interroge simplement [`CommandesActives`] et
//! dispatche la [`Commande`] retournée, ou ne fait rien.
//!
//! # Modèle
//!
//! Une [`Commande`] est une intention métier ; un tuple
//! `(KeyCode, KeyModifiers)` est sa liaison clavier. La table
//! [`CommandesActives`] mappe les liaisons aux commandes effectivement
//! disponibles dans le contexte courant.
//!
//! Le sens du mapping — touche → commande — est dicté par le chemin chaud :
//! sur chaque frappe, la TUI doit retrouver la commande correspondante en O(1).
//! La direction inverse (toutes les touches d'une commande donnée) reste
//! accessible en O(n) via [`HashMap::retain`] dans
//! [`CommandesActives::desactiver`] — opération rare, déclenchée
//! uniquement aux transitions de contexte.
//!
//! # Évolution du contexte
//!
//! La table évolue par mutations incrémentales. Chaque transition d'état
//! métier (allumage du nœud, ouverture d'un foyer…) ne touche que les
//! entrées concernées, sans reconstruction. Ce choix garde les transitions
//! explicites — chaque appel à [`CommandesActives::desactiver`]
//! ou son futur pendant d'activation matérialise une étape du cycle de vie
//! de l'interface.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyModifiers};

/// Intention métier déclenchée par une frappe clavier.
///
/// Découple la liaison clavier (un tuple `(KeyCode, KeyModifiers)`) de l'action
/// effective : la même commande peut être liée à plusieurs touches, ou changer
/// de touche, sans toucher au code de dispatch dans
/// [`crate::tui::Tui::saisie_mode_normal`].
///
/// `PartialEq` est dérivé pour permettre la suppression par valeur via
/// [`CommandesActives::desactiver`].
#[derive(PartialEq)]
pub(super) enum Commande {
    /// Demande l'allumage du nœud — émet [`crate::connecteurs::MessageTuiCoeur::AllumageNoeud`].
    ///
    /// Désactivée après la première utilisation : l'allumage est non répétable,
    /// la commande disparaît de la table dès que le message est envoyé au cœur.
    /// Le bras dispatch active simultanément [`Commande::OuvrirFoyer`] dans la table
    /// — l'ouverture de foyer n'a de sens qu'une fois le nœud allumé.
    AllumerNoeud,

    /// Prépare la fermeture d'un foyer — symétrique de [`Commande::OuvrirFoyer`].
    ///
    /// Activée par [`crate::tui::Tui`] au moment de l'allumage du nœud.
    /// La saisie du numéro et l'envoi de [`crate::connecteurs::MessageTuiCoeur::FermetureFoyer`]
    /// sont gérés par `saisie_mode_insertion` une fois le buffer validé.
    FermerFoyer,

    /// Affiche l'aide contextuelle listant les commandes actuellement disponibles.
    ///
    /// Toujours active : `?` doit fonctionner quel que soit l'état du nœud.
    ListeCommandesActives,

    /// Prépare l'ouverture d'un foyer — bascule l'invite en mode saisie pour collecter le numéro.
    ///
    /// Activée par [`crate::tui::Tui`] au moment de l'allumage du nœud, désactivée à l'extinction.
    /// La saisie du numéro et l'envoi de [`crate::connecteurs::MessageTuiCoeur::OuvertureFoyer`]
    /// sont gérés par `saisie_mode_insertion` une fois le buffer validé.
    OuvrirFoyer,

    /// Demande l'arrêt propre de l'application — émet [`crate::connecteurs::MessageTuiCoeur::Quitter`].
    ///
    /// Toujours active : l'utilisateur doit pouvoir sortir à tout moment.
    Quitter,
}

impl Commande {
    /// Retourne un libellé lisible à afficher comme accusé de réception.
    ///
    /// Utilisé par [`crate::tui::EtatTui::ajouter_message_commande`] pour afficher
    /// un retour visuel éphémère après chaque frappe reconnue. Le libellé est
    /// volontairement court : il confirme que la touche a été interprétée comme
    /// la commande attendue, sans préjuger du résultat — succès ou échec
    /// remonteront ensuite via [`crate::connecteurs::MessageCoeurTui::AffichageErreur`]
    /// ou les pastilles d'état.
    pub(crate) fn afficher(&self) -> String {
        match &self {
            Self::AllumerNoeud => String::from("Allume nœud"),
            Self::FermerFoyer => String::from("Fermeture foyer"),
            Self::ListeCommandesActives => String::from("Liste commandes actives"),
            Self::OuvrirFoyer => String::from("Ouverture foyer"),
            Self::Quitter => String::from("Quitte Feu"),
        }
    }
}

/// Table de dispatch des commandes actives dans le contexte courant.
///
/// Encapsule un `HashMap<(KeyCode, KeyModifiers), Commande>` pour exposer une
/// API restreinte : lookup par touche via [`get`](Self::get), mutation contrôlée
/// par [`desactiver`](Self::desactiver). Le conteneur
/// interne reste invisible — toute évolution de structure ne traverse pas la
/// frontière du module.
///
/// La table est instanciée une fois dans [`crate::tui::EtatTui::new`] et
/// évolue par mutations incrémentales tout au long de la session ; aucune
/// reconstruction n'est nécessaire.
pub(super) struct CommandesActives(HashMap<(KeyCode, KeyModifiers), Commande>);

impl CommandesActives {
    /// Crée la table avec les commandes disponibles au lancement de la TUI.
    ///
    /// Trois commandes sont actives au démarrage : allumage du nœud (`a`),
    /// affichage de l'aide (`?`) et sortie (`q`). À mesure que des
    /// fonctionnalités s'ajouteront (ouverture de foyer, signature, écriture
    /// de blob…), elles seront insérées ici si elles sont disponibles dès le
    /// démarrage, ou plus tard via une future méthode d'activation lorsque
    /// le contexte le permet.
    pub(super) fn new() -> Self {
        let mut commandes_actives: HashMap<(KeyCode, KeyModifiers), Commande> = HashMap::new();
        commandes_actives.insert(
            (KeyCode::Char('a'), KeyModifiers::NONE),
            Commande::AllumerNoeud,
        );
        commandes_actives.insert((KeyCode::Char('q'), KeyModifiers::NONE), Commande::Quitter);
        commandes_actives.insert(
            (KeyCode::Char('?'), KeyModifiers::NONE),
            Commande::ListeCommandesActives,
        );

        Self(commandes_actives)
    }

    /// Retourne la commande liée à une touche dans le contexte courant, `None` si absente.
    ///
    /// Point d'entrée du dispatch clavier : une touche absente de la table ne
    /// déclenche rien — le filtrage par contexte est entièrement implicite.
    pub(super) fn get(&self, touche: &(KeyCode, KeyModifiers)) -> Option<&Commande> {
        self.0.get(touche)
    }

    /// Ajoute ou remplace la liaison d'une touche vers une commande.
    ///
    /// Pendant de [`desactiver`](Self::desactiver) pour les activations contextuelles :
    /// une commande indisponible au démarrage (ex. [`Commande::OuvrirFoyer`], qui
    /// requiert un nœud allumé) est insérée ici au moment où le contexte le permet,
    /// sans reconstruire la table.
    pub(super) fn ajouter(&mut self, touche: (KeyCode, KeyModifiers), commande: Commande) {
        self.0.insert(touche, commande);
    }

    /// Retire toutes les liaisons clavier associées à une commande donnée.
    ///
    /// Utilise [`HashMap::retain`] : la suppression par valeur est intrinsèquement
    /// O(n) puisqu'un `HashMap` n'indexe que les clés. Le coût reste négligeable
    /// — la table compte une poignée d'entrées et l'opération n'est invoquée
    /// qu'aux transitions de contexte, jamais sur le chemin chaud du clavier.
    ///
    /// Conçue pour que la même commande puisse, à terme, être liée à plusieurs
    /// touches (raccourci principal + alias) sans changer cette signature : un
    /// seul appel suffit à toutes les retirer.
    pub(super) fn desactiver(&mut self, commande: Commande) {
        self.0.retain(|_, v| *v != commande);
    }
}
