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
//! # Cartographie clavier
//!
//! Touches actives selon le contexte :
//!
//! - **Nœud éteint** : `a` allume le nœud, `q` quitte Feu.
//! - **Nœud allumé, racine, aucun foyer ouvert** : `e` éteint, `o` ouvre un
//!   foyer (saisie du numéro).
//! - **Nœud allumé, au moins un foyer ouvert** : `o` ouvre un foyer
//!   (si la capacité maximale n'est pas atteinte) ; `1`-`5` entrent dans le
//!   foyer correspondant s'il est ouvert ; `Backspace` remonte d'un niveau ;
//!   `f` ferme le foyer où l'on est positionné.
//! - **Dans un foyer** : mêmes touches que ci-dessus, plus `1`-`5` qui entrent
//!   dans le classeur correspondant (dans la limite de `nombre_classeurs`).
//! - **Dans un classeur** : `Backspace` remonte au foyer ; les commandes
//!   contextuelles aux classeurs viendront s'y greffer à mesure de leur ajout.
//! - **À tout moment** : `?` affiche les commandes actives (à venir).
//!
//! Touches *ignorées* dans tous les autres cas — pas d'erreur, pas d'effet,
//! pas de feedback. Une touche absente de la table n'a aucune existence du
//! point de vue de la TUI.
//!
//! # Asymétrie ouverture / fermeture
//!
//! Ouvrir un foyer demande une saisie d'index ([`Commande::OuvrirFoyer`])
//! parce qu'on ne peut pas naviguer vers un foyer qui n'existe pas encore.
//! Fermer un foyer ne demande pas de saisie ([`Commande::FermerFoyerCourant`])
//! parce qu'on ferme *celui où l'on est positionné* — l'index est porté par le
//! contexte. Le geste utilisateur de fermeture est donc *naviguer puis fermer* :
//! `3` puis `f` ferme le foyer 3. Cette asymétrie reflète la nature des
//! actions : création (index explicite obligatoire) vs suppression (cible
//! contextuelle suffit).
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
//! [`crate::connecteurs::MessageCoeurTui::EnvoiSessionApplication`].
//!
//! # Granularité du filtrage : commandes noyau vs navigation TUI
//!
//! Toutes les commandes ne se filtrent pas avec la même rigueur, parce qu'elles
//! n'ont pas la même nature.
//!
//! Les **commandes noyau** ([`Commande::AllumerNoeud`], [`Commande::EteindreNoeud`],
//! [`Commande::OuvrirFoyer`], [`Commande::FermerFoyerCourant`],
//! [`Commande::Quitter`]) déclenchent un message vers le thread cœur et ont un
//! effet métier visible. Elles sont strictement filtrées : présence dans la
//! table ⇔ effet réel possible. Une touche noyau qu'on activerait alors qu'elle
//! ne peut rien faire tromperait l'utilisateur.
//!
//! Les **commandes de navigation TUI** ([`Commande::PositionSuivante`],
//! [`Commande::PositionPrecedente`]) ne sortent pas de la TUI : elles déplacent
//! un curseur dans la pseudo-arborescence foyer → classeur. Elles sont activées
//! plus largement : `1`-`5` sont insérées en bloc dès qu'un foyer est ouvert,
//! sans regarder finement ni l'état de chaque foyer ni la position courante.
//! Le bras d'exécution écarte silencieusement les transitions invalides (foyer
//! fermé, classeur hors borne, descente depuis un classeur). Aucun effet
//! visible : pas de message d'erreur, pas de modification du fil d'Ariane —
//! l'utilisateur ne peut pas confondre avec une action réussie.
//!
//! Cette dérogation au contrat strict est délibérée : filtrer la navigation
//! aussi finement exigerait de passer la position courante en paramètre de
//! [`CommandesActives::new`] et de reconstruire la table à chaque mutation de
//! position, sans bénéfice observable côté utilisateur.

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

    /// Ferme immédiatement le foyer où l'utilisateur est positionné — émet
    /// [`crate::connecteurs::MessageTuiCoeur::FermetureFoyer`].
    ///
    /// Active uniquement lorsque le nœud est allumé **et** qu'au moins un foyer
    /// est ouvert. L'index est porté par [`crate::tui::EtatTui::position_courante`]
    /// et n'est donc pas saisi : le geste utilisateur est *naviguer dans le foyer
    /// (`1`-`5`) puis le fermer (`f`)*. Aucun mode insertion, aucun parsing.
    ///
    /// L'asymétrie avec [`Commande::OuvrirFoyer`] (qui passe par une saisie) est
    /// délibérée : on ne peut pas naviguer vers un foyer qui n'existe pas encore,
    /// donc l'ouverture exige un index explicite ; tandis que la fermeture agit
    /// sur le foyer courant, l'index est porté par le contexte.
    ///
    /// Le bras d'exécution dans [`crate::tui::Tui::saisie_mode_normal`] remet
    /// [`crate::tui::EtatTui::position_courante`] à la racine après émission du
    /// message — l'utilisateur ne peut plus être *dans* un foyer qu'il vient
    /// de fermer. Comme c'est l'unique chemin de fermeture, l'invariant tient
    /// en cascade : à l'extinction du nœud (qui exige tous les foyers fermés),
    /// la position est nécessairement déjà à la racine.
    FermerFoyerCourant,

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

    /// Remonte d'un niveau dans la pseudo-arborescence foyer → classeur.
    ///
    /// Active dès qu'un foyer est ouvert (la touche `Backspace` n'a aucun sens
    /// avant). Trois transitions possibles selon
    /// [`crate::tui::EtatTui::position_courante`] :
    /// - dans un classeur → revient au foyer parent ;
    /// - dans un foyer → revient à la racine ;
    /// - à la racine → no-op (rien à remonter).
    ///
    /// Pure navigation TUI : aucun message n'est envoyé au cœur, aucune
    /// modification d'état métier. C'est l'analogue du `..` d'un explorateur
    /// de fichiers.
    PositionPrecedente,

    /// Descend d'un niveau dans la pseudo-arborescence foyer → classeur,
    /// vers l'élément d'index `1`-based porté par la variante.
    ///
    /// Active dès qu'un foyer est ouvert (l'usage le plus naturel : entrer
    /// dans un foyer pour ensuite y agir). Liée aux touches `1` à `5` —
    /// l'index correspond au caractère pressé.
    ///
    /// La descente n'est posée que si l'index est cohérent avec le niveau cible :
    /// - depuis la racine → le foyer ciblé doit être effectivement *ouvert*
    ///   (`session.etat_foyer(index - 1) == Ok(true)`) ;
    /// - depuis un foyer → l'index doit être dans `[1, nombre_classeurs]` (les
    ///   classeurs n'ont pas de notion d'« ouverture » au stade actuel) ;
    /// - depuis un classeur → no-op (pas de niveau plus profond aujourd'hui).
    ///
    /// Validation à l'exécution plutôt que dans la table : le filtrage fin par
    /// foyer ouvert / borne classeur dépend de la position courante, qui n'est
    /// pas (encore) un paramètre de [`CommandesActives::new`]. La table active
    /// `1`-`5` *en bloc* dès qu'un foyer est ouvert, le bras d'exécution écarte
    /// silencieusement les indices invalides — pas de message d'erreur, pas de
    /// conséquence métier, l'utilisateur ne voit rien.
    PositionSuivante(usize),

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
            Self::FermerFoyerCourant => String::from("Fermeture foyer"),
            Self::ListeCommandesActives => String::from("Liste commandes actives"),
            Self::OuvrirFoyer => String::from("Ouverture foyer"),
            Self::PositionPrecedente => String::from("Position précédente"),
            Self::PositionSuivante(_) => String::from("Position suivante"),
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
    /// - nœud allumé avec au moins un foyer ouvert → `OuvrirFoyer` (si capacité libre),
    ///   `FermerFoyerCourant`, navigation `PositionSuivante(1..=5)` et
    ///   `PositionPrecedente` ;
    /// - dans tous les cas → `ListeCommandesActives`.
    ///
    /// `nombre_foyers_max` n'est consulté que si `noeud_allume` vaut `true` ;
    /// l'instanciation initiale dans [`crate::tui::EtatTui::new`] passe `0` à
    /// titre de sentinelle, faute d'accès à `MAX_FOYERS` côté TUI — la valeur
    /// effective est fournie par `SessionApplication::nombre_foyers` dès la
    /// première reconstruction post-allumage.
    ///
    /// # Granularité du filtrage
    ///
    /// Les **commandes noyau** (`AllumerNoeud`, `EteindreNoeud`, `OuvrirFoyer`,
    /// `FermerFoyerCourant`, `Quitter`) sont strictement filtrées : si la table
    /// les contient, leur déclenchement a un effet métier, et inversement les
    /// touches sans effet possible sont retirées pour ne pas tromper l'utilisateur.
    ///
    /// Les **commandes de navigation TUI** (`PositionSuivante`, `PositionPrecedente`)
    /// sont activées plus largement : `1`-`5` apparaissent dès qu'au moins un
    /// foyer est ouvert, sans regarder finement l'état de chacun ni la position
    /// courante. Le bras d'exécution écarte silencieusement les transitions
    /// invalides (foyer fermé, classeur hors borne, descente depuis un classeur).
    /// Choix justifié par la nature *muette* de la navigation : un appui sur une
    /// touche sans effet ne change ni l'état métier ni l'affichage — l'utilisateur
    /// ne peut pas le confondre avec une action réussie. Filtrer ces touches plus
    /// finement exigerait de passer la position courante en paramètre et de
    /// reconstruire la table à chaque mutation de position, sans bénéfice observable.
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
            if nombre_foyers_ouverts > 0 {
                commandes_actives.insert(
                    (KeyCode::Char('1'), KeyModifiers::NONE),
                    Commande::PositionSuivante(1),
                );
                commandes_actives.insert(
                    (KeyCode::Char('2'), KeyModifiers::NONE),
                    Commande::PositionSuivante(2),
                );
                commandes_actives.insert(
                    (KeyCode::Char('3'), KeyModifiers::NONE),
                    Commande::PositionSuivante(3),
                );
                commandes_actives.insert(
                    (KeyCode::Char('4'), KeyModifiers::NONE),
                    Commande::PositionSuivante(4),
                );
                commandes_actives.insert(
                    (KeyCode::Char('5'), KeyModifiers::NONE),
                    Commande::PositionSuivante(5),
                );
                commandes_actives.insert(
                    (KeyCode::Backspace, KeyModifiers::NONE),
                    Commande::PositionPrecedente,
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
                    Commande::FermerFoyerCourant,
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
