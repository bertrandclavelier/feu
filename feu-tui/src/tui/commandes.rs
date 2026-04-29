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
//!
//! # Reconstruction déclarative
//!
//! La table est reconstruite intégralement à chaque changement d'état pertinent
//! via [`CommandesActives::new`], qui prend l'état courant en paramètres et
//! déduit les commandes actives à partir d'un jeu de règles simples. Aucune
//! mutation incrémentale, aucun état caché : la sortie de `new` est une
//! fonction pure de ses entrées.
//!
//! Ce choix maintient l'invariant fondamental — *la table reflète toujours
//! l'état courant* — sans qu'aucun chemin du code n'ait à se rappeler de
//! coupler une transition métier (ouverture d'un foyer, extinction du nœud)
//! avec la mutation correspondante de la table. La reconstruction est
//! déclenchée par [`crate::tui::EtatTui::recalculer_commandes_actives`]
//! aux points où l'état change : aujourd'hui à la réception d'un
//! [`crate::connecteurs::MessageCoeurTui::EnvoiSessionApplication`], demain
//! aux changements de navigation TUI lorsque l'arborescence
//! foyer/classeur sera introduite.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyModifiers};

/// Intention métier déclenchée par une frappe clavier.
///
/// Découple la liaison clavier (un tuple `(KeyCode, KeyModifiers)`) de l'action
/// effective : la même commande peut être liée à plusieurs touches, ou changer
/// de touche, sans toucher au code de dispatch dans
/// [`crate::tui::Tui::saisie_mode_normal`].
///
/// La présence d'une variante dans la table [`CommandesActives`] est entièrement
/// dictée par les conditions énumérées ci-dessous — voir [`CommandesActives::new`]
/// pour l'implémentation des règles.
pub(super) enum Commande {
    /// Demande l'allumage du nœud — émet [`crate::connecteurs::MessageTuiCoeur::AllumageNoeud`].
    ///
    /// Active uniquement lorsque le nœud est éteint (`session_application` à `None`).
    /// Le succès de l'allumage est signalé via
    /// [`crate::connecteurs::MessageCoeurTui::EnvoiSessionApplication`], qui déclenche
    /// la reconstruction de la table : `AllumerNoeud` disparaît alors au profit des
    /// commandes du nœud allumé.
    AllumerNoeud,

    /// Demande l'extinction du nœud — émet [`crate::connecteurs::MessageTuiCoeur::ExtinctionNoeud`].
    ///
    /// Active uniquement lorsque le nœud est allumé **et** qu'aucun foyer n'est
    /// ouvert. La couche application refuse de toute façon l'extinction tant qu'un
    /// foyer est ouvert — l'erreur remonterait via
    /// [`crate::connecteurs::MessageCoeurTui::AffichageErreur`] —, mais le filtrage
    /// par contexte évite à l'utilisateur de la déclencher pour rien.
    EteindreNoeud,

    /// Prépare la fermeture d'un foyer — symétrique de [`Commande::OuvrirFoyer`].
    ///
    /// Active uniquement lorsque le nœud est allumé **et** qu'au moins un foyer est
    /// ouvert. Bascule l'invite en [`crate::tui::ModeSaisie::Insertion`] pour
    /// collecter le numéro ; la saisie et l'envoi de
    /// [`crate::connecteurs::MessageTuiCoeur::FermetureFoyer`] sont gérés par
    /// `saisie_mode_insertion` une fois le buffer validé.
    FermerFoyer,

    /// Affiche l'aide contextuelle listant les commandes actuellement disponibles.
    ///
    /// Toujours active : `?` doit fonctionner quel que soit l'état du nœud — c'est
    /// la seule porte d'entrée pour découvrir les autres commandes accessibles à
    /// un instant donné.
    ListeCommandesActives,

    /// Prépare l'ouverture d'un foyer — bascule l'invite en mode saisie pour collecter le numéro.
    ///
    /// Active uniquement lorsque le nœud est allumé **et** qu'au moins une place
    /// reste libre (`nombre_foyers_ouverts < nombre_foyers`). La saisie du numéro
    /// et l'envoi de [`crate::connecteurs::MessageTuiCoeur::OuvertureFoyer`] sont
    /// gérés par `saisie_mode_insertion` une fois le buffer validé.
    OuvrirFoyer,

    /// Demande l'arrêt propre de l'application — émet [`crate::connecteurs::MessageTuiCoeur::Quitter`].
    ///
    /// Active uniquement lorsque le nœud est éteint, par symétrie avec
    /// [`Commande::AllumerNoeud`]. Cette contrainte garantit qu'aucun foyer n'est
    /// ouvert au moment de l'arrêt — l'extinction elle-même exige que tous les
    /// foyers soient fermés. La touche `q` est silencieusement ignorée tant que
    /// le nœud est allumé : l'utilisateur doit d'abord l'éteindre.
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
            Self::EteindreNoeud => String::from("Extinction du nœud"),
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
/// API restreinte : lookup par touche via [`get`](Self::get). Le conteneur
/// interne reste invisible — toute évolution de structure ne traverse pas la
/// frontière du module.
///
/// La table est immuable une fois construite : elle est intégralement
/// reconstruite par [`new`](Self::new) à chaque changement d'état pertinent,
/// orchestré depuis [`crate::tui::EtatTui::recalculer_commandes_actives`].
pub(super) struct CommandesActives(HashMap<(KeyCode, KeyModifiers), Commande>);

impl CommandesActives {
    /// Construit la table reflétant l'état décrit par les paramètres.
    ///
    /// Fonction pure — la sortie ne dépend que des entrées, aucun état caché.
    /// Les règles d'activation sont expliquées sur chaque variante de [`Commande`] ;
    /// résumées :
    ///
    /// - nœud éteint → `AllumerNoeud`, `Quitter` ;
    /// - nœud allumé sans foyer ouvert → `EteindreNoeud`, `OuvrirFoyer` ;
    /// - nœud allumé avec au moins un foyer ouvert → `OuvrirFoyer` (si capacité libre), `FermerFoyer` ;
    /// - dans tous les cas → `ListeCommandesActives`.
    ///
    /// `nombre_foyers_max` n'est consulté que si `noeud_allume` vaut `true` ;
    /// l'instanciation initiale dans [`crate::tui::EtatTui::new`] passe `0` à
    /// titre de sentinelle, faute d'accès à `MAX_FOYERS` côté TUI — la valeur
    /// effective est fournie par `SessionApplication::nombre_foyers` dès la
    /// première reconstruction post-allumage.
    pub(super) fn new(
        noeud_allume: bool,
        nombre_foyers_ouverts: usize,
        nombre_foyers_max: usize,
    ) -> Self {
        let mut commandes_actives: HashMap<(KeyCode, KeyModifiers), Commande> = HashMap::new();

        if !noeud_allume {
            commandes_actives.insert(
                (KeyCode::Char('a'), KeyModifiers::NONE),
                Commande::AllumerNoeud,
            );
            commandes_actives.insert((KeyCode::Char('q'), KeyModifiers::NONE), Commande::Quitter);
        } else {
            if nombre_foyers_ouverts == 0 {
                commandes_actives.insert(
                    (KeyCode::Char('e'), KeyModifiers::NONE),
                    Commande::EteindreNoeud,
                );
            }
            if nombre_foyers_ouverts < nombre_foyers_max {
                commandes_actives.insert(
                    (KeyCode::Char('o'), KeyModifiers::NONE),
                    Commande::OuvrirFoyer,
                );
            }
            if nombre_foyers_ouverts > 0 {
                commandes_actives.insert(
                    (KeyCode::Char('f'), KeyModifiers::NONE),
                    Commande::FermerFoyer,
                );
            }
        }

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
}
