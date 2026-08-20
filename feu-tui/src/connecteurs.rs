// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Canaux de communication entre le thread TUI et le thread cœur.
//!
//! Ce module définit le protocole de messages ([`MessageTuiCoeur`],
//! [`MessageCoeurTui`]) et les deux connecteurs qui en sont les extrémités :
//!
//! - [`ConnecteurVersTui`] vit dans le thread cœur. Il possède [`FeuApplication`]
//!   et la boucle de dispatch des commandes reçues depuis la TUI. Il implémente
//!   [`feu_application::InterfaceFeuApplication`] pour les interactions bloquantes
//!   (saisie du mot de passe, affichage de la seed) et la notification de session
//!   après chaque commande mutante ([`MessageCoeurTui::EnvoiSessionApplication`]).
//! - [`ConnecteurVersCoeur`] vit dans le thread TUI. Il expose les méthodes de
//!   haut niveau à la boucle ratatui : envoyer une commande au thread cœur,
//!   recevoir un événement cœur de façon non bloquante.
//!
//! Aucun état n'est partagé entre les deux threads — toute communication
//! transite par ces canaux typés.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::thread::{JoinHandle, spawn};

use feu_application::fiche::Fiche;
use feu_application::{FeuApplication, InterfaceFeuApplication, SessionApplication};
use secrecy::SecretString;

/// Emplacement du dossier de retrait, en dur le temps de brancher la TUI.
///
/// L'utilisateur n'a encore aucun moyen de désigner où retirer, contrairement au
/// dépôt qui part du chemin marqué sur l'écran d'arborescence disque. `env!` est
/// résolu **à la compilation** : la valeur est une chaîne littérale figée dans
/// le binaire, jamais une lecture de l'environnement à l'exécution. C'est ce qui
/// garde tout chemin personnel hors des sources, `workspace/` étant public.
///
/// Elle vit ici et non dans la table des commandes : le retrait n'a pas d'index
/// à capturer dans la position courante, la TUI n'a donc rien à transmettre et
/// le cœur lit le chemin lui-même.
///
/// Le nom étant fixe, un second retrait échoue tant que le dossier précédent
/// n'est pas supprimé à la main — l'erreur remonte en
/// [`MessageCoeurTui::AffichageErreur`].
const CHEMIN_COMPTOIR_RETRAIT: &str = concat!(env!("HOME"), "/Desktop/retrait");

/// Messages envoyés du thread cœur vers le thread TUI.
// `EnvoiSessionApplication` est bien plus grosse que les autres variantes
// (`SessionApplication`, dont la taille est irréductible). On assume l'écart
// plutôt que de boxer : ce canal ne transporte que de rares messages
// événementiels (allumage, ouverture/fermeture de foyer ou de comptoir,
// erreur), jamais en rafale. Le surcoût mémoire est sans effet observable ; l'indirection serait
// de la complexité gratuite.
#[allow(clippy::large_enum_variant)]
pub(crate) enum MessageCoeurTui {
    /// Une commande a échoué — la TUI doit afficher le message d'erreur.
    ///
    /// Émis par [`ConnecteurVersTui`] sur erreur de [`FeuApplication`] ;
    /// consommé par la boucle [`crate::tui::Tui::lancer`] qui pose
    /// le message d'erreur de la TUI.
    AffichageErreur(String),

    /// Le cœur a besoin du mot de passe — la TUI doit basculer sur l'écran de saisie.
    ///
    /// Émis par [`ConnecteurVersTui::demander_mdp`] ; la TUI bascule sur son
    /// écran de saisie, en mode insertion, le buffer destiné au mot de passe.
    AttenteMdp,

    /// L'arborescence demandée, à plat — la TUI la garde jusqu'au prochain
    /// chargement.
    ///
    /// Émis par le bras `ChargementArborescenceEnu` de
    /// [`ConnecteurVersTui::lancer_thread_coeur`], en réponse à une demande
    /// explicite de l'utilisateur.
    ///
    /// Le `Vec` est le parcours en profondeur de l'arbre, racine comprise,
    /// chaque fiche précédée de sa profondeur. C'est l'ordre de l'affichage et
    /// son décalage : la TUI n'a rien à reconstruire, elle indente et dessine.
    EnvoiArborescenceEnu(Vec<(usize, Fiche)>),

    /// La seed vient d'être générée — la TUI doit basculer sur l'écran d'affichage.
    ///
    /// Émis par [`ConnecteurVersTui::recevoir_seed`] ; la TUI bascule sur son
    /// écran d'affichage, en mode information.
    EnvoiSeed(Vec<SecretString>),

    /// Session applicative mise à jour — la TUI doit rafraîchir son état.
    ///
    /// Émis par [`ConnecteurVersTui::recevoir_session_application`] après chaque
    /// commande de [`feu_application::FeuApplication`] qui mute la session.
    /// Le payload est forwardé tel quel :
    /// - `Some(session)` — clone cohérent après une commande mutante réussie ;
    /// - `None` — extinction du nœud, la TUI repasse à l'état initial.
    ///
    /// Consommé par la boucle [`crate::tui::Tui::lancer`] qui affecte directement
    /// la session que la TUI détient à la valeur reçue.
    EnvoiSessionApplication(Option<SessionApplication>),
}

/// Messages envoyés du thread TUI vers le thread cœur.
pub(crate) enum MessageTuiCoeur {
    /// Lance l'initialisation ou l'allumage du nœud via [`FeuApplication`].
    ///
    /// Émis par [`crate::tui::Tui`] sur frappe `a` en mode normal ;
    /// consommé par la boucle de [`ConnecteurVersTui::lancer_thread_coeur`] qui appelle
    /// [`FeuApplication::commande_allumage_noeud`].
    AllumageNoeud,

    /// Demande l'extinction du nœud — symétrique de [`Self::AllumageNoeud`].
    ///
    /// Émis par [`crate::tui::Tui`] sur frappe `e` en mode normal ;
    /// consommé par la boucle de [`ConnecteurVersTui::lancer_thread_coeur`] qui appelle
    /// [`FeuApplication::commande_extinction_noeud`]. L'erreur éventuelle (foyer
    /// encore ouvert, nœud déjà éteint) est propagée via
    /// [`MessageCoeurTui::AffichageErreur`].
    ExtinctionNoeud,

    /// Demande le chargement de l'arborescence des ENU du nœud.
    ///
    /// Émis par [`crate::tui::Tui`] sur dispatch de
    /// `EnuChargerArborescence` — la variante ne porte rien : le bras enchaîne
    /// [`FeuApplication::commande_derniere_enu_racine`] puis
    /// [`FeuApplication::commande_descendants`], et c'est donc le cœur qui
    /// décide d'où partir. Rien ne remonte de la TUI, ce qui évite au canal de
    /// transporter une ENU entière et sa signature de 4 627 octets.
    ///
    /// La réponse est [`MessageCoeurTui::EnvoiArborescenceEnu`] ; l'erreur, en
    /// [`MessageCoeurTui::AffichageErreur`].
    ChargementArborescenceEnu,

    /// Mot de passe saisi par l'utilisateur, en réponse à [`MessageCoeurTui::AttenteMdp`].
    ///
    /// Émis par [`crate::tui::Tui`] lors de la validation du buffer de saisie ;
    /// débloque [`ConnecteurVersTui::demander_mdp`] qui retourne le mot de passe
    /// à [`FeuApplication`].
    EnvoieMdp(SecretString),

    /// Demande la fermeture du comptoir de dépôt dont l'identifiant est porté.
    ///
    /// La variante porte l'identifiant du comptoir, saisi par l'utilisateur et
    /// validé contre [`SessionApplication::comptoirs_depot_ouverts`], et l'ENU
    /// sous laquelle greffer ce qu'il contient — celle que la TUI tient pour
    /// sélectionnée. C'est le seul message où le choix de la racine de dépôt
    /// remonte de l'utilisateur plutôt que du cœur.
    ///
    /// Émis par [`crate::tui::Tui`] à la validation du buffer de saisie ;
    /// consommé par [`ConnecteurVersTui::lancer_thread_coeur`] qui appelle
    /// [`FeuApplication::commande_fermeture_comptoir_depot`].
    FermetureComptoirDepot(usize, Fiche),

    /// Demande la fermeture du foyer à l'index donné.
    ///
    /// Émis par [`crate::tui::Tui`] sur dispatch de `PilotageFermerFoyer` —
    /// l'index est capturé depuis la position courante, sans saisie ;
    /// consommé par [`ConnecteurVersTui::lancer_thread_coeur`] qui appelle
    /// [`feu_application::FeuApplication::commande_fermeture_foyer`].
    FermetureFoyer(usize),

    /// Demande l'ouverture du foyer à l'index donné.
    ///
    /// Émis par [`crate::tui::Tui`] à la validation du buffer de saisie ;
    /// consommé par [`ConnecteurVersTui::lancer_thread_coeur`] qui appelle
    /// [`feu_application::FeuApplication::commande_ouverture_foyer`].
    OuvertureFoyer(usize),

    /// Demande l'ouverture d'un comptoir de dépôt au chemin porté, vers le foyer
    /// puis le classeur portés.
    ///
    /// Le chemin est celui du dossier **à créer**, sous-dossier de la marque
    /// posée par l'utilisateur — le cœur refuse un chemin déjà pris.
    ///
    /// Émis par [`crate::tui::Tui`] sur dispatch de `PilotageOuvrirComptoirDepot`
    /// — les deux index sont capturés depuis la position courante, sans saisie ;
    /// consommé par [`ConnecteurVersTui::lancer_thread_coeur`] qui appelle
    /// [`FeuApplication::commande_ouverture_comptoir_depot`]. L'identifiant rendu
    /// est ignoré : la commande l'inscrit déjà dans la session.
    ///
    /// Le chemin traverse le canal plutôt que d'être connu du cœur : la TUI est
    /// seule à décider où le dossier apparaît, le cœur ne fait que l'y créer.
    OuvertureComptoir(PathBuf, usize, usize),

    /// Demande la matérialisation de la dernière racine dans un dossier de l'OS.
    ///
    /// Émis par [`crate::tui::Tui`] sur dispatch de la commande
    /// `PilotageRetraitLectureSeule` — la variante ne porte rien : le chemin est
    /// [`CHEMIN_COMPTOIR_RETRAIT`], lu ici, et la racine est demandée au même
    /// endroit. Le bras enchaîne
    /// [`FeuApplication::commande_derniere_enu_racine`] puis
    /// [`FeuApplication::commande_retrait_lecture_seule`] ; l'erreur de l'une
    /// comme de l'autre est propagée via [`MessageCoeurTui::AffichageErreur`].
    RetraitLectureSeule,

    /// L'utilisateur a confirmé l'enregistrement de la seed — débloque le thread cœur en attente.
    ///
    /// Émis par [`crate::tui::Tui`] à la deuxième frappe en mode information ;
    /// débloque [`ConnecteurVersTui::recevoir_seed`].
    SeedBienRecue,

    /// L'utilisateur a annulé la saisie en cours (Échap).
    ///
    /// Émis par [`crate::tui::Tui`] sur Échap en mode insertion, quelle que
    /// soit la destination prévue pour le buffer.
    /// Sa réception côté cœur dépend du contexte :
    /// - pendant un [`Self::EnvoieMdp`] attendu, débloque [`ConnecteurVersTui::demander_mdp`]
    ///   qui retourne `None` à [`FeuApplication`] ;
    /// - hors attente bloquante (ex. saisie d'un numéro de foyer), le message est ignoré
    ///   par la boucle de dispatch — la TUI a déjà rétabli son état local.
    Annulation,

    /// Demande d'arrêt propre : le thread cœur doit terminer sa boucle.
    ///
    /// Émis par [`crate::tui::Tui`] sur frappe `q` en mode normal ;
    /// consommé par la boucle de [`ConnecteurVersTui::lancer_thread_coeur`].
    Quitter,
}

/// Connecteur du thread cœur — reçoit les commandes de la TUI et pilote [`FeuApplication`].
///
/// Possède les deux extrémités du canal TUI↔cœur et l'instance de [`FeuApplication`].
/// La boucle de dispatch vit dans [`lancer_thread_coeur`](Self::lancer_thread_coeur).
///
/// La propriété de [`FeuApplication`] lui est confiée parce qu'il est le seul composant
/// à implémenter [`InterfaceFeuApplication`] — les interactions bloquantes du noyau
/// (mot de passe, seed) doivent être servies par le même objet qui tient les canaux,
/// faute de quoi les appels bloquants et les envois de messages se retrouveraient
/// dans des contextes séparés sans moyen de se synchroniser.
pub(crate) struct ConnecteurVersTui {
    emetteur: Sender<MessageCoeurTui>,
    recepteur: Receiver<MessageTuiCoeur>,
}

impl ConnecteurVersTui {
    /// Crée un [`ConnecteurVersTui`] à partir des extrémités de canaux fournies par `main`.
    pub(crate) fn new(
        emetteur: Sender<MessageCoeurTui>,
        recepteur: Receiver<MessageTuiCoeur>,
    ) -> Self {
        Self {
            emetteur,
            recepteur,
        }
    }

    /// Envoie un message au thread TUI.
    ///
    /// L'erreur est ignorée volontairement : si le canal est déjà fermé,
    /// le thread TUI est déjà terminé — l'objectif est atteint.
    pub(crate) fn envoyer_message_coeur_tui(&self, message_coeur_tui: MessageCoeurTui) {
        let _ = self.emetteur.send(message_coeur_tui);
    }

    /// Spawne le thread cœur et retourne sa poignée.
    ///
    /// Crée [`FeuApplication`], consomme le connecteur (`self`) et transfère
    /// la propriété de l'ensemble au thread.
    ///
    /// La boucle de dispatch liste **exhaustivement** chaque variante de
    /// [`MessageTuiCoeur`] — aucun `_ => {}`. Ce choix est structurel : toute
    /// variante ajoutée à l'enum à l'avenir (requête de signature, écriture de
    /// blob…) provoque une erreur de compilation tant qu'elle n'est pas traitée
    /// ici. Le compilateur devient le filet de sécurité contre les commandes
    /// silencieusement ignorées.
    ///
    /// Chaque bras déclenche la commande correspondante de [`FeuApplication`] et
    /// propage l'erreur éventuelle via [`MessageCoeurTui::AffichageErreur`]. Les
    /// index de foyer et de classeur traversent le canal tels quels : la TUI
    /// numérote comme le noyau, à partir de zéro, aucune conversion ici.
    ///
    /// [`MessageTuiCoeur::OuvertureComptoir`] est le seul bras dont la commande
    /// rend autre chose que `()`, et pourtant il s'écrit comme les autres, en
    /// `if let Err` : l'identifiant rendu est déjà inscrit dans la session, que
    /// la même commande envoie.
    ///
    /// [`MessageTuiCoeur::EnvoieMdp`], [`MessageTuiCoeur::SeedBienRecue`] et
    /// [`MessageTuiCoeur::Annulation`] ont un corps vide : hors-protocole dans
    /// le contexte de la boucle principale (ils ne peuvent arriver ici que si
    /// une attente bloquante a été contournée), ils sont ignorés — mais
    /// explicitement, pas par défaut.
    ///
    /// La boucle se termine sur [`MessageTuiCoeur::Quitter`] ou fermeture du
    /// canal (`Err`). La poignée retournée permet à `main` d'attendre la fin
    /// propre du thread via `.join()` — aucun thread orphelin.
    ///
    /// `chemin_feu` est le chemin racine du nœud, calculé par `main` (seul point
    /// de lecture de l'environnement) et transmis à [`FeuApplication::new`].
    pub(crate) fn lancer_thread_coeur(self, chemin_feu: &Path) -> JoinHandle<()> {
        let mut feu_application = FeuApplication::new(chemin_feu);
        spawn(move || {
            loop {
                match self.recepteur.recv() {
                    Ok(MessageTuiCoeur::AllumageNoeud) => {
                        if let Err(e) = feu_application.commande_allumage_noeud(&self, None) {
                            self.envoyer_message_coeur_tui(MessageCoeurTui::AffichageErreur(
                                e.to_string(),
                            ));
                        }
                    }
                    Ok(MessageTuiCoeur::ChargementArborescenceEnu) => {
                        match feu_application.commande_derniere_enu_racine() {
                            Err(e) => self.envoyer_message_coeur_tui(
                                MessageCoeurTui::AffichageErreur(e.to_string()),
                            ),
                            Ok(enu_racine) => {
                                match feu_application.commande_descendants(&enu_racine) {
                                    Err(e) => self.envoyer_message_coeur_tui(
                                        MessageCoeurTui::AffichageErreur(e.to_string()),
                                    ),
                                    Ok(descendants) => {
                                        self.envoyer_message_coeur_tui(
                                            MessageCoeurTui::EnvoiArborescenceEnu(
                                                descendants
                                                    .collect::<Result<Vec<(usize, Fiche)>, _>>()
                                                    .unwrap(),
                                            ),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Ok(MessageTuiCoeur::ExtinctionNoeud) => {
                        if let Err(e) = feu_application.commande_extinction_noeud(&self) {
                            self.envoyer_message_coeur_tui(MessageCoeurTui::AffichageErreur(
                                e.to_string(),
                            ));
                        }
                    }
                    Ok(MessageTuiCoeur::Quitter) => break,
                    Ok(MessageTuiCoeur::EnvoieMdp(_)) => {}
                    Ok(MessageTuiCoeur::FermetureFoyer(index_foyer)) => {
                        if let Err(e) = feu_application.commande_fermeture_foyer(&self, index_foyer)
                        {
                            self.envoyer_message_coeur_tui(MessageCoeurTui::AffichageErreur(
                                e.to_string(),
                            ));
                        }
                    }
                    Ok(MessageTuiCoeur::OuvertureFoyer(index_foyer)) => {
                        if let Err(e) = feu_application.commande_ouverture_foyer(&self, index_foyer)
                        {
                            self.envoyer_message_coeur_tui(MessageCoeurTui::AffichageErreur(
                                e.to_string(),
                            ));
                        }
                    }
                    Ok(MessageTuiCoeur::OuvertureComptoir(
                        chemin_comptoir_depot,
                        index_foyer,
                        index_classeur,
                    )) => {
                        if let Err(e) = feu_application.commande_ouverture_comptoir_depot(
                            &self,
                            &chemin_comptoir_depot,
                            index_foyer,
                            index_classeur,
                        ) {
                            self.envoyer_message_coeur_tui(MessageCoeurTui::AffichageErreur(
                                e.to_string(),
                            ));
                        }
                    }
                    Ok(MessageTuiCoeur::FermetureComptoirDepot(index_comptoir, fiche)) => {
                        if let Err(e) = feu_application.commande_fermeture_comptoir_depot(
                            &self,
                            index_comptoir,
                            &fiche,
                        ) {
                            self.envoyer_message_coeur_tui(MessageCoeurTui::AffichageErreur(
                                e.to_string(),
                            ));
                        }
                    }
                    Ok(MessageTuiCoeur::RetraitLectureSeule) => {
                        if let Err(e) =
                            feu_application
                                .commande_derniere_enu_racine()
                                .and_then(|enu| {
                                    feu_application.commande_retrait_lecture_seule(
                                        &PathBuf::from(CHEMIN_COMPTOIR_RETRAIT),
                                        &enu,
                                    )
                                })
                        {
                            self.envoyer_message_coeur_tui(MessageCoeurTui::AffichageErreur(
                                e.to_string(),
                            ));
                        }
                    }
                    Ok(MessageTuiCoeur::SeedBienRecue) => {}
                    Ok(MessageTuiCoeur::Annulation) => {}
                    Err(_) => break,
                }
            }
        })
    }
}

impl InterfaceFeuApplication for ConnecteurVersTui {
    /// Envoie [`MessageCoeurTui::AttenteMdp`] et bloque jusqu'à l'une des trois issues :
    /// [`MessageTuiCoeur::EnvoieMdp`] (retourne le mot de passe),
    /// [`MessageTuiCoeur::Annulation`] (retourne `None`),
    /// ou fermeture du canal — TUI morte — (retourne également `None`).
    /// Les autres messages reçus pendant l'attente sont ignorés : hors-protocole
    /// dans ce contexte, ils ne peuvent pas être dispatchés depuis ici.
    fn demander_mdp(&self) -> Option<SecretString> {
        self.envoyer_message_coeur_tui(MessageCoeurTui::AttenteMdp);

        loop {
            match self.recepteur.recv() {
                Ok(MessageTuiCoeur::EnvoieMdp(mdp)) => {
                    return Some(mdp);
                }
                Ok(MessageTuiCoeur::Annulation) => {
                    return None;
                }

                Err(_) => {
                    return None;
                }
                _ => {}
            }
        }
    }

    /// Envoie [`MessageCoeurTui::EnvoiSeed`] et bloque jusqu'à l'une des deux issues :
    /// [`MessageTuiCoeur::SeedBienRecue`] (retour normal),
    /// ou fermeture du canal — TUI morte — (retour anticipé sans erreur).
    /// Les autres messages reçus pendant l'attente sont ignorés : hors-protocole
    /// dans ce contexte, ils ne peuvent pas être dispatchés depuis ici.
    fn recevoir_seed(&self, mots: &[&str]) {
        self.envoyer_message_coeur_tui(MessageCoeurTui::EnvoiSeed(
            mots.iter()
                .map(|s| SecretString::from(s.to_string()))
                .collect(),
        ));
        loop {
            match self.recepteur.recv() {
                Ok(MessageTuiCoeur::SeedBienRecue) => return,

                Err(_) => return,
                _ => {}
            }
        }
    }

    /// Toujours `true` — la confirmation se joue sur l'écran d'affichage de la
    /// seed, côté TUI.
    fn confirmer_enregistrement_seed(&self) -> bool {
        true
    }

    /// Forwarde la session vers le thread TUI via [`MessageCoeurTui::EnvoiSessionApplication`].
    ///
    /// Appelée par [`feu_application::FeuApplication`] à la fin de chaque commande
    /// qui mute la session — `Some(session)` après une commande mutante réussie,
    /// `None` à l'extinction du nœud. Le payload est transmis tel quel : aucune
    /// transformation, aucune politique côté connecteur.
    /// L'erreur d'envoi est ignorée : canal fermé = TUI déjà terminée.
    fn recevoir_session_application(&self, session_application: Option<SessionApplication>) {
        self.envoyer_message_coeur_tui(MessageCoeurTui::EnvoiSessionApplication(
            session_application,
        ));
    }
}

/// Connecteur du thread TUI — pendant de [`ConnecteurVersTui`] dans l'autre thread.
///
/// Les deux connecteurs sont les deux extrémités du même protocole, chacun vivant
/// dans son propre thread et ne partageant aucun état.
/// Expose les commandes de haut niveau à la boucle ratatui et permet de recevoir
/// les événements remontés par le cœur via un `try_recv` non bloquant à chaque frame.
pub(crate) struct ConnecteurVersCoeur {
    emetteur: Sender<MessageTuiCoeur>,
    recepteur: Receiver<MessageCoeurTui>,
}

impl ConnecteurVersCoeur {
    /// Crée un [`ConnecteurVersCoeur`] à partir des extrémités de canaux fournies par `main`.
    pub(crate) fn new(
        emetteur: Sender<MessageTuiCoeur>,
        recepteur: Receiver<MessageCoeurTui>,
    ) -> Self {
        Self {
            emetteur,
            recepteur,
        }
    }

    /// Retourne une référence au récepteur cœur→TUI pour lecture non bloquante.
    ///
    /// Utilisé par la boucle ratatui via [`try_recv`](Receiver::try_recv) à chaque frame.
    pub(crate) fn recepteur(&self) -> &Receiver<MessageCoeurTui> {
        &self.recepteur
    }

    /// Envoie un message au thread cœur.
    ///
    /// L'erreur est ignorée volontairement : si le canal est déjà fermé,
    /// le thread cœur est déjà terminé — l'objectif est atteint.
    pub(crate) fn envoyer_message_tui_coeur(&self, message_tui_coeur: MessageTuiCoeur) {
        let _ = self.emetteur.send(message_tui_coeur);
    }
}
