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
//! Touches actives selon le contexte. Deux touches sont toujours actives, quel
//! que soit l'état du nœud et la position : `?` liste les touches courantes et
//! `!` affiche l'écran « à propos ». Toutes deux sont omises ci-dessous pour ne
//! pas alourdir.
//!
//! - **Nœud éteint, racine** : `a` allume le nœud, `q` quitte Feu.
//! - **Nœud allumé, racine, aucun foyer ouvert** : `e` éteint le nœud, `o`
//!   ouvre un foyer (saisie du numéro à suivre).
//! - **Nœud allumé, racine, au moins un foyer ouvert** : `o` ouvre un foyer
//!   (si la capacité maximale n'est pas atteinte) ; `1`-`9` entrent dans le
//!   foyer correspondant *s'il est ouvert*. Pas de `e` tant qu'un foyer est
//!   ouvert.
//! - **Nœud allumé, dans un foyer** : `f` ferme le foyer courant ; `1`-`9`
//!   entrent dans le classeur correspondant (dans la limite de
//!   `nombre_classeurs`) ; `Backspace` remonte à la racine ; `o` ouvre un
//!   foyer si la capacité libre le permet.
//! - **Nœud allumé, dans un classeur** : `f` ferme le foyer parent ;
//!   `Backspace` remonte au foyer ; `o` ouvre un foyer si la capacité libre
//!   le permet. Les commandes propres aux classeurs s'ajouteront ici.
//!
//! Touches *ignorées* dans tous les autres cas — pas d'erreur, pas d'effet,
//! pas de feedback. Une touche absente de la table n'a aucune existence du
//! point de vue de la TUI.
//!
//! La borne `1`-`9` (et non `1`-max) reflète le fait que les positions sont
//! mappées sur les caractères ASCII `'1'` à `'9'` : au-delà de la dixième
//! position le mapping deviendrait incohérent. Aujourd'hui les capacités du
//! noyau (`MAX_FOYERS = 3`, `MAX_CLASSEURS = 5`) restent largement en deçà.
//!
//! # Asymétrie ouverture / fermeture
//!
//! Ouvrir un foyer demande une saisie d'index ([`Commande::OuvrirFoyer`])
//! parce qu'on ne peut pas naviguer vers un foyer qui n'existe pas encore.
//! Fermer un foyer ne demande pas de saisie ([`Commande::FermerFoyer`]) :
//! l'index est capturé depuis [`crate::tui::EtatTui::position_courante`] au
//! moment où la table est construite, donc on ferme toujours *le foyer où
//! l'on est positionné*. Le geste utilisateur est *naviguer puis fermer* :
//! `3` puis `f` ferme le foyer 3. Cette asymétrie reflète la nature des
//! actions : création (index explicite obligatoire) vs suppression (cible
//! contextuelle suffit).
//!
//! # Reconstruction déclarative
//!
//! La table est reconstruite intégralement à chaque changement d'état pertinent
//! via [`CommandesActives::new`], qui prend la session applicative et la
//! position courante et déduit les commandes actives à partir d'un jeu de
//! règles simples. Aucune mutation incrémentale, aucun état caché : la sortie
//! de `new` est une fonction pure de ses entrées.
//!
//! Ce choix maintient l'invariant fondamental — *la table reflète toujours
//! l'état courant* — sans qu'aucun chemin du code n'ait à se rappeler de
//! coupler une transition métier (ouverture d'un foyer, extinction du nœud,
//! déplacement de la position) avec la mutation correspondante de la table.
//! La reconstruction est déclenchée depuis [`crate::tui::Tui::lancer`] à deux
//! points : à la réception d'un
//! [`crate::connecteurs::MessageCoeurTui::EnvoiSessionApplication`] (changement
//! d'état applicatif) et après chaque commande dispatchée en mode normal
//! (changement potentiel de position courante).
//!
//! # Filtrage strict
//!
//! Toutes les commandes sont filtrées strictement : présence dans la table ⇔
//! effet réel possible dans le contexte courant. Une touche absente n'a aucun
//! effet ; une touche présente déclenche systématiquement quelque chose.
//!
//! Cette homogénéité est permise par le fait que la position courante fait
//! partie des entrées de [`CommandesActives::new`] : la table sait, par
//! exemple, sur quel foyer pointe le `f` ou si la touche `1` doit entrer dans
//! un foyer ouvert ou dans un classeur valide. Aucune commande n'est exposée
//! « en bloc » avec un filtrage à l'exécution.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyModifiers};
use feu_application::SessionApplication;

use crate::tui::PositionCourante;

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

    /// Affiche l'écran « à propos » : identité du programme, version, licence, copyright.
    ///
    /// Toujours active, comme [`Commande::ListeCommandesActives`] : `!` fonctionne
    /// quel que soit l'état du nœud et la position courante. Méta-commande
    /// purement informationnelle — aucun effet métier, elle ne touche ni au nœud
    /// ni aux foyers.
    ///
    /// Le bras d'exécution dans [`crate::tui::Tui::saisie_mode_normal`] bascule
    /// l'écran sur [`crate::tui::Ecran::AffichageInformation`] ; l'utilisateur en
    /// sort par Entrée (cf. [`crate::tui::ModeSaisie::Information`]).
    APropos,

    /// Affecte directement [`crate::tui::PositionCourante::classeur`] à la valeur portée.
    ///
    /// Pure navigation TUI — aucun message vers le cœur, aucun effet métier.
    /// `Some(index)` pose la position à `Some(index)` (descente d'un foyer vers
    /// un de ses classeurs) ; `None` la repose à `None` (remontée du classeur
    /// vers son foyer parent).
    ///
    /// Active uniquement quand l'utilisateur est positionné dans un foyer ou
    /// dans un classeur :
    /// - dans un foyer (`classeur = None`), liée aux touches `1`-`9` dans la
    ///   limite de `nombre_classeurs` — descente ;
    /// - dans un classeur (`classeur = Some(_)`), liée à `Backspace` —
    ///   remontée.
    ChangerPositionClasseur(Option<usize>),

    /// Affecte directement [`crate::tui::PositionCourante::foyer`] à la valeur portée.
    ///
    /// Pure navigation TUI — aucun message vers le cœur, aucun effet métier.
    /// `Some(index)` pose la position à `Some(index)` (descente de la racine
    /// vers un foyer ouvert) ; `None` la repose à `None` (remontée du foyer
    /// vers la racine).
    ///
    /// Active selon la position courante :
    /// - à la racine (`foyer = None`), liée à `1`-`9` *uniquement pour les
    ///   foyers effectivement ouverts* (la table consulte
    ///   [`feu_application::SessionApplication::etat_foyers`] pour ne pas
    ///   exposer les positions fermées) — descente ;
    /// - dans un foyer (`foyer = Some(_)`, `classeur = None`), liée à
    ///   `Backspace` — remontée à la racine.
    ChangerPositionFoyer(Option<usize>),

    /// Demande l'extinction du nœud — émet [`crate::connecteurs::MessageTuiCoeur::ExtinctionNoeud`].
    ///
    /// Active uniquement lorsque le nœud est allumé **et** qu'aucun foyer n'est
    /// ouvert. La couche application refuse de toute façon l'extinction tant qu'un
    /// foyer est ouvert — l'erreur remonterait via
    /// [`crate::connecteurs::MessageCoeurTui::AffichageErreur`] —, mais le filtrage
    /// par contexte évite à l'utilisateur de la déclencher pour rien.
    EteindreNoeud,

    /// Ferme le foyer dont l'index (base 1) est porté par la variante — émet
    /// [`crate::connecteurs::MessageTuiCoeur::FermetureFoyer`].
    ///
    /// Active uniquement lorsque l'utilisateur est positionné dans un foyer ou
    /// dans un classeur. L'index est *capturé* depuis
    /// [`crate::tui::EtatTui::position_courante`] au moment où la table est
    /// construite ; il n'y a donc pas de saisie utilisateur. Le geste typique
    /// est *naviguer dans le foyer (`1`-`9`) puis le fermer (`f`)*.
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
    FermerFoyer(usize),

    /// Affiche l'aide contextuelle listant les touches actuellement actives.
    ///
    /// Toujours active : `?` fonctionne quel que soit l'état du nœud et la
    /// position courante — c'est la seule porte d'entrée pour découvrir les
    /// autres commandes accessibles à un instant donné.
    ///
    /// Le bras d'exécution dans [`crate::tui::Tui::saisie_mode_normal`] délègue
    /// à [`CommandesActives::liste_commandes_actives`] le formatage de la liste
    /// et la pose dans [`crate::tui::EtatTui::message_aide`] (compte à rebours
    /// court — cf. [`crate::tui::EtatTui::ajouter_message_aide`]).
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

/// Table de dispatch des commandes actives dans le contexte courant.
///
/// Encapsule un `HashMap<(KeyCode, KeyModifiers), Commande>` pour exposer une
/// API restreinte : lookup par touche via [`get`](Self::get) et formatage de
/// l'aide via [`liste_commandes_actives`](Self::liste_commandes_actives). Le
/// conteneur interne reste invisible — toute évolution de structure ne
/// traverse pas la frontière du module.
///
/// La table est immuable une fois construite : elle est intégralement
/// reconstruite par [`new`](Self::new) à chaque changement d'état pertinent,
/// directement depuis [`crate::tui::Tui::lancer`] (réception d'une nouvelle
/// session) et [`crate::tui::Tui::saisie_mode_normal`] (après chaque commande
/// dispatchée).
pub(super) struct CommandesActives(HashMap<(KeyCode, KeyModifiers), Commande>);

impl CommandesActives {
    /// Construit la table reflétant la session applicative et la position courante.
    ///
    /// Fonction pure — la sortie ne dépend que des entrées, aucun état caché.
    /// Chaque variante de [`Commande`] documente ses propres conditions
    /// d'activation ; les règles, vues d'ensemble :
    ///
    /// - `session_application = None` (nœud éteint) → `AllumerNoeud`, `Quitter` ;
    /// - `Some(session)` (nœud allumé) :
    ///   - `EteindreNoeud` si `nombre_foyers_ouverts == 0` ;
    ///   - `OuvrirFoyer` si `nombre_foyers_ouverts < nombre_foyers` ;
    ///   - si `nombre_foyers_ouverts > 0`, le bloc « navigation » dépend de
    ///     `position_courante` :
    ///     - racine → `1`-`9` mappés sur les foyers ouverts via
    ///       `ChangerPositionFoyer(Some(_))` ;
    ///     - dans un foyer → `f` ferme via `FermerFoyer(index)`, `Backspace`
    ///       remonte via `ChangerPositionFoyer(None)`, `1`-`9` descendent
    ///       dans les classeurs via `ChangerPositionClasseur(Some(_))` ;
    ///     - dans un classeur → `f` ferme le foyer parent via
    ///       `FermerFoyer(index)`, `Backspace` remonte via
    ///       `ChangerPositionClasseur(None)` ;
    /// - dans tous les cas → `ListeCommandesActives`.
    ///
    /// La borne `1`-`9` n'est pas un choix de capacité métier : elle reflète
    /// le mapping `KeyCode::Char((b'0' + n) as char)` qui ne tient pas au-delà
    /// de la dixième position. Les capacités du noyau (`MAX_FOYERS = 3`,
    /// `MAX_CLASSEURS = 5`) restent largement en deçà.
    ///
    /// # Filtrage strict
    ///
    /// Toute touche présente dans la table déclenche un effet réel dans le
    /// contexte courant ; toute touche absente est ignorée silencieusement.
    /// Le filtrage tient compte à la fois de la session (état des foyers,
    /// capacité libre) et de la position courante (depuis quel niveau
    /// l'utilisateur navigue) — pas de touche « activée en bloc » avec un
    /// rejet à l'exécution.
    pub(super) fn new(
        session_application: &Option<SessionApplication>,
        position_courante: &PositionCourante,
    ) -> Self {
        let mut commandes_actives: HashMap<(KeyCode, KeyModifiers), Commande> = HashMap::new();

        if let Some(session) = session_application {
            if session.nombre_foyers_ouverts() == 0 {
                commandes_actives.insert(
                    (KeyCode::Char('e'), KeyModifiers::NONE),
                    Commande::EteindreNoeud,
                );
            }
            if session.nombre_foyers_ouverts() < session.nombre_foyers {
                commandes_actives.insert(
                    (KeyCode::Char('o'), KeyModifiers::NONE),
                    Commande::OuvrirFoyer,
                );
            }
            if session.nombre_foyers_ouverts() > 0 {
                match (position_courante.foyer, position_courante.classeur) {
                    (None, _) => {
                        for (i, etat) in session.etat_foyers().iter().enumerate() {
                            if *etat && i < 9 {
                                commandes_actives.insert(
                                    (
                                        KeyCode::Char((b'0' + (i + 1) as u8) as char),
                                        KeyModifiers::NONE,
                                    ),
                                    Commande::ChangerPositionFoyer(Some(i + 1)),
                                );
                            }
                        }
                    }
                    (Some(index), None) => {
                        commandes_actives.insert(
                            (KeyCode::Char('f'), KeyModifiers::NONE),
                            Commande::FermerFoyer(index),
                        );
                        commandes_actives.insert(
                            (KeyCode::Backspace, KeyModifiers::NONE),
                            Commande::ChangerPositionFoyer(None),
                        );

                        for i in 0..session.nombre_classeurs {
                            if i < 9 {
                                commandes_actives.insert(
                                    (
                                        KeyCode::Char((b'0' + (i + 1) as u8) as char),
                                        KeyModifiers::NONE,
                                    ),
                                    Commande::ChangerPositionClasseur(Some(i + 1)),
                                );
                            }
                        }
                    }
                    (Some(index), Some(_)) => {
                        commandes_actives.insert(
                            (KeyCode::Char('f'), KeyModifiers::NONE),
                            Commande::FermerFoyer(index),
                        );
                        commandes_actives.insert(
                            (KeyCode::Backspace, KeyModifiers::NONE),
                            Commande::ChangerPositionClasseur(None),
                        );
                    }
                }
            }
        } else {
            commandes_actives.insert(
                (KeyCode::Char('a'), KeyModifiers::NONE),
                Commande::AllumerNoeud,
            );
            commandes_actives.insert((KeyCode::Char('q'), KeyModifiers::NONE), Commande::Quitter);
        }

        commandes_actives.insert(
            (KeyCode::Char('?'), KeyModifiers::NONE),
            Commande::ListeCommandesActives,
        );

        commandes_actives.insert((KeyCode::Char('!'), KeyModifiers::NONE), Commande::APropos);

        Self(commandes_actives)
    }

    /// Retourne la commande liée à une touche dans le contexte courant, `None` si absente.
    ///
    /// Point d'entrée du dispatch clavier : une touche absente de la table ne
    /// déclenche rien — le filtrage par contexte est entièrement implicite.
    pub(super) fn get(&self, touche: &(KeyCode, KeyModifiers)) -> Option<&Commande> {
        self.0.get(touche)
    }

    /// Retourne une chaîne énumérant les touches actives, séparées par des espaces.
    ///
    /// Format : chaque caractère imprimable est entouré de guillemets simples
    /// (`'a'`, `'1'`…), `Backspace` par le glyphe entre guillemets `'⌫'`. Les autres
    /// `KeyCode` (non utilisés par la table aujourd'hui) seraient ignorés.
    ///
    /// Appelée par le bras d'exécution de [`Commande::ListeCommandesActives`]
    /// pour alimenter [`crate::tui::EtatTui::message_aide`].
    ///
    /// L'ordre des touches dans la chaîne suit l'itération du `HashMap`
    /// interne, *non déterministe d'un appel à l'autre*. Compromis temporaire :
    /// l'aide reste utilisable pour repérer ce qui est actif, mais l'ordre
    /// stable sera traité quand le module sera enrichi (libellés par commande,
    /// regroupement par catégorie).
    pub(super) fn liste_commandes_actives(&self) -> String {
        let mut liste_commandes = String::new();

        for (key_code, _) in self.0.keys() {
            match key_code {
                KeyCode::Char(c) => liste_commandes.push_str(&format!(" '{c}'")),

                KeyCode::Backspace => liste_commandes.push_str(" '⌫'"),
                _ => {}
            }
        }
        liste_commandes
    }
}
