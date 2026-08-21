// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! État de l'interface et boucle principale.
//!
//! Ce module centralise l'état entre deux frames ([`EtatTui`]) et orchestre
//! la boucle dessin → événement → mise à jour via [`Tui::lancer`].
//! Le rendu est entièrement délégué à [`rendu`].
//!
//! La boucle tourne en continu via `poll(50ms)` : elle ne bloque jamais plus de
//! 50 ms, ce qui permet de consulter le canal cœur→TUI à chaque itération via
//! `try_recv`. Les événements clavier et les messages du cœur sont traités de
//! façon désynchronisée — la TUI n'attend aucune réponse du cœur.
//!
//! La communication avec le thread cœur passe par [`crate::connecteurs::ConnecteurVersCoeur`],
//! dont [`Tui`] est propriétaire.
//!
//! Les commandes accessibles à un instant donné sont filtrées par le contexte
//! via [`commandes::CommandesActives`] — la boucle clavier ne connaît aucun
//! raccourci hardcodé, elle dispatche ce que la table lui retourne.
//!
//! # Modèle d'interaction
//!
//! L'état courant se lit sur trois axes orthogonaux qui évoluent
//! indépendamment.
//!
//! [`Ecran`] désigne l'écran de travail affiché, et rien d'autre : ce qu'il
//! contient, ses sous-écrans compris, appartient à son module — voir
//! [`ecran_pilotage`], [`ecran_arborescence_enu`] et
//! [`ecran_arborescence_disque`]. `h` et `l` passent de l'un à l'autre, en
//! ligne et non en cycle. [`ModeSaisie`] décide comment les touches sont
//! interprétées : `Normal` (dispatch via la table de commandes),
//! `Insertion` (accumulation dans un buffer, validation par Entrée), `Information`
//! (avancement par Entrée uniquement). [`commandes::CommandesActives`] enfin
//! liste les touches actives, reconstruite à chaque changement de session ou
//! de position.
//!
//! Ce module ne connaît donc aucun écran de l'intérieur. Chacun apporte dans
//! son fichier son état, son rendu et les transitions qui y mènent — celles-ci
//! s'écrivant en `impl EtatTui`, puisqu'elles posent aussi le mode de saisie.
//!
//! Le geste typique au clavier : `a` allume le nœud, mot de passe, seed
//! validée par deux pressions d'Entrée ; `o` ouvre un foyer (saisie du
//! numéro), `0`-`9` entrent dans un foyer ouvert puis dans un de ses
//! classeurs, `d` y ouvre un comptoir de dépôt et `c` le ferme, `r` retire
//! l'arborescence sur le disque, `Backspace` remonte d'un niveau, `f` ferme le
//! foyer où l'on est, `e` éteint quand tous les foyers sont fermés, `q` quitte
//! quand le nœud est éteint, `!` affiche l'à-propos. Sur les deux écrans
//! d'arborescence, les mêmes touches font les mêmes gestes : `R` charge ou
//! rafraîchit, `j` et `k` déplacent le curseur, `Entrée` plie ou déplie un
//! répertoire, `m` retient ce qui est sous le curseur — une ENU d'un côté, un
//! chemin de l'autre — et `x` lève la marque. `h`, `l` et `?` sont les seules à
//! valoir partout — changer d'écran dans un sens ou dans l'autre, et lister ce
//! qui y est actif.

mod commandes;
mod ecran_arborescence_disque;
mod ecran_arborescence_enu;
mod ecran_pilotage;
mod rendu;

use std::{
    path::{Path, PathBuf},
    sync::mpsc::TryRecvError,
    time::{Duration, Instant},
};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use feu_application::{SessionApplication, fiche::Fiche};
use ratatui::DefaultTerminal;
use secrecy::SecretString;

use crate::{
    connecteurs::{ConnecteurVersCoeur, MessageCoeurTui, MessageTuiCoeur},
    erreur::{ErreurFeuTui, ResultFeuTui},
    tui::{
        ecran_arborescence_disque::EtatArborescenceDisque,
        ecran_arborescence_enu::EtatArborescenceEnu, ecran_pilotage::EtatPilotage,
    },
};
use commandes::{Commande, CommandesActives};

/// Axe de rendu : quel écran de travail est dessiné à chaque frame.
///
/// Pur sélecteur — les variantes ne portent aucune donnée. Chaque écran garde
/// les siennes dans son module, ce qui laisse cet enum stable quand l'un
/// d'eux s'enrichit, et vaut au `match` de [`rendu::dessiner`] d'être
/// exhaustif sans rien savoir d'eux.
///
/// Orthogonal à [`ModeSaisie`] : un même écran traverse plusieurs modes.
/// Fusionner les deux axes recouperait le rendu et l'interprétation des
/// touches, deux responsabilités indépendantes.
enum Ecran {
    /// L'usage courant du nœud, et les modales qu'il ouvre — cf.
    /// [`ecran_pilotage`].
    Pilotage,

    /// L'arborescence des ENU du nœud, où l'on navigue, plie et marque — cf.
    /// [`ecran_arborescence_enu`].
    ArborescenceEnu,

    /// L'arborescence du disque depuis le dossier personnel, où l'on navigue,
    /// plie et marque un chemin — cf. [`ecran_arborescence_disque`].
    ArborescenceDisque,
}

/// Axe d'interprétation des touches clavier — indépendant de l'écran affiché.
///
/// Transversal à [`Ecran`] : un même écran traverse plusieurs modes selon son
/// état. Le mode est posé par la transition qui mène à l'écran, pas déduit de
/// lui — ce qui laisse la boucle clavier dispatcher sans jamais consulter
/// [`EtatTui::ecran`].
enum ModeSaisie {
    /// Touches dispatchées via [`EtatTui::commandes_actives`] : la table
    /// indique quelle commande exécuter, ou rien si la touche n'y figure pas.
    Normal,

    /// Touches accumulées dans [`EtatTui::buffer_saisie`] ; Entrée valide, Échap annule.
    ///
    /// Sert au mot de passe comme aux prompts de commande. Ce qu'il advient du
    /// buffer à la validation est porté par [`ValidationBufferSaisie`], jamais
    /// par l'écran.
    Insertion,

    /// Entrée (sans modificateur) avance l'écran courant — toute autre touche est ignorée.
    ///
    /// L'écran seul sait ce qu'« avancer » veut dire, et si le cœur doit en
    /// être averti (cf. `entree_mode_information`).
    Information,
}

/// Destination du contenu de [`EtatTui::buffer_saisie`] à la validation (Entrée).
///
/// Posé avant de basculer en [`ModeSaisie::Insertion`] par ce qui déclenche la
/// saisie, consommé et remis à [`Self::Rien`] par `saisie_mode_insertion` —
/// qui n'a ainsi pas à connaître l'écran courant pour décider quoi émettre.
///
/// La fermeture d'un foyer ne passe pas par là : elle agit sur le foyer où
/// l'on est positionné, sans rien demander (cf. [`Commande::PilotageFermerFoyer`]).
enum ValidationBufferSaisie {
    /// Le buffer est vidé sans envoyer de message au cœur.
    ///
    /// État de repos restauré après chaque validation ou annulation.
    Rien,

    /// Le buffer est transmis comme [`crate::connecteurs::MessageTuiCoeur::EnvoieMdp`] au thread cœur.
    EnvoiMdp,

    /// Le buffer est interprété comme un identifiant de comptoir et envoyé via
    /// [`crate::connecteurs::MessageTuiCoeur::FermetureComptoirDepot`], avec
    /// l'ENU sélectionnée.
    ///
    /// Posé par [`Tui::saisie_mode_normal`] sur dispatch de
    /// [`Commande::PilotageFermerComptoirDepot`]. À la validation, l'identifiant
    /// doit figurer parmi les comptoirs ouverts de la session ; sinon un message
    /// d'erreur est affiché et rien n'est envoyé au cœur.
    FermetureComptoirDepot,

    /// Le buffer est interprété comme un numéro de foyer et envoyé via
    /// [`crate::connecteurs::MessageTuiCoeur::OuvertureFoyer`].
    ///
    /// Posé par [`Tui::saisie_mode_normal`] sur dispatch de
    /// [`Commande::PilotageOuvrirFoyer`]. À la validation, seul le format entier
    /// est vérifié ; la validité de l'index est tranchée par le noyau.
    OuvertureFoyer,

    /// Le buffer est interprété comme un numéro de foyer et envoyé via
    /// [`crate::connecteurs::MessageTuiCoeur::SecoursFermetureFoyer`].
    ///
    /// Posé par [`Tui::saisie_mode_normal`] sur dispatch de
    /// [`Commande::PilotageSecoursFermetureFoyer`]. À la validation, seul le
    /// format entier est vérifié ; l'index et l'état du foyer sont tranchés par
    /// le noyau.
    SecoursFermetureFoyer,
}

/// État courant de l'interface entre deux frames.
///
/// Deux natures s'y côtoient. **Le transversal**, à plat ici, survit aux
/// changements d'écran — une erreur née pendant la saisie du mot de passe doit
/// rester lisible sur l'écran qui suit. **Le propre à un écran** vit dans un
/// champ par écran, dont son module est seul à connaître le contenu.
///
/// Aucun état applicatif n'est retenu hors de `session_application` : la TUI lit
/// le clone qu'elle reçoit et n'en garde pas de copie à resynchroniser.
///
/// Les méthodes ne sont pas toutes ici : chaque module d'écran ajoute en
/// `impl EtatTui` les transitions qui mènent au sien.
struct EtatTui {
    /// Session applicative courante — `None` quand le nœud est éteint.
    ///
    /// Peuplé par [`crate::connecteurs::MessageCoeurTui::EnvoiSessionApplication`]
    /// dans la boucle principale, qui affecte directement le payload reçu.
    /// `None` signifie nœud éteint (pastilles éteintes) — état initial, ou
    /// résultat d'une extinction réussie ; `Some(_)` signifie nœud allumé.
    /// Pas de booléen séparé — la présence du clone est la preuve que l'allumage
    /// a réussi, son absence celle de l'extinction.
    session_application: Option<SessionApplication>,

    /// Écran actuellement affiché — détermine la fonction de rendu appelée.
    ecran: Ecran,

    /// Mode de saisie courant — détermine l'interprétation des touches.
    mode_saisie: ModeSaisie,

    /// Ce que l'écran de pilotage retient — son sous-écran et la position
    /// courante. Opaque d'ici : seul son module en lit le contenu.
    etat_pilotage: EtatPilotage,

    /// Ce que l'écran d'arborescence retient — l'arbre chargé, les nœuds
    /// dépliés et le curseur. Opaque d'ici, comme [`Self::etat_pilotage`] :
    /// seul son module en lit le contenu.
    etat_arborescence_enu: EtatArborescenceEnu,

    /// Ce que l'écran d'arborescence du disque retient — l'arbre construit
    /// jusqu'ici et le curseur. Opaque d'ici, comme ses deux voisins.
    etat_arborescence_disque: EtatArborescenceDisque,

    /// L'ENU que l'utilisateur a retenue, `None` tant qu'il n'en a marqué
    /// aucune.
    ///
    /// **Transversal, et c'est tout son intérêt** : la marque se pose sur l'écran
    /// d'arborescence et se consomme sur celui du pilotage. Avec
    /// [`Self::chemin_selectionne`], elle résout toute action sans qu'aucune
    /// commande n'ait à nommer sa cible.
    ///
    /// Une [`Fiche`] entière plutôt que son `hash_carte`, que réclament les
    /// commandes. **Rien ne l'efface** : un rechargement la laisse en place,
    /// quitte à désigner une ENU absente du nouveau parcours.
    enu_selectionnee: Option<Fiche>,

    /// Le chemin que l'utilisateur a retenu sur l'écran du disque, `None` tant
    /// qu'il n'en a marqué aucun.
    ///
    /// Transversal pour la même raison que [`Self::enu_selectionnee`] : la
    /// marque se pose sur l'écran du disque et se lit sur celui du pilotage,
    /// qui l'affiche.
    ///
    /// Un chemin, et non le contenu du fichier : il désigne, il ne charge rien.
    /// Il peut donc désigner ce qui n'existe plus — rien ne surveille le
    /// disque —, ce que verra la commande qui le consommera.
    chemin_selectionne: Option<PathBuf>,

    /// Table de dispatch touche → commande, filtrée par le contexte courant.
    ///
    /// Source de vérité unique : une touche absente ne déclenche rien, point —
    /// la boucle n'a aucun cas particulier à traiter.
    ///
    /// Reconstruite intégralement à la réception d'une session et après chaque
    /// commande dispatchée. Fonction pure de l'état, donc sans mutation
    /// incrémentale ni risque de la voir diverger de ce qu'elle décrit.
    commandes_actives: CommandesActives,

    /// Ce que l'on fait du buffer à la validation — positionné avant de passer en [`ModeSaisie::Insertion`].
    validation_buffer_saisie: ValidationBufferSaisie,

    /// Dernier message d'erreur et son compte à rebours en secondes.
    ///
    /// Le tuple garantit que texte et durée sont posés et effacés ensemble —
    /// d'où les accesseurs [`EtatTui::message_erreur`] et
    /// [`EtatTui::ajouter_message_erreur`], jamais l'affectation directe.
    ///
    /// À plat ici pour survivre aux transitions d'écran : une erreur née pendant
    /// la saisie du mot de passe doit rester visible sur l'écran qui suit.
    /// Effacé quand le compte à rebours atteint zéro (cf. [`EtatTui::decremente_temps`]).
    message_erreur: (Option<String>, u8),

    /// Dernier message éphémère à destination de l'utilisateur, et son compte
    /// à rebours en secondes. Même mécanique que [`EtatTui::message_erreur`],
    /// accesseurs compris.
    ///
    /// Alimenté aujourd'hui par [`Commande::ListeCommandesActives`], qui y
    /// dépose la liste formatée des touches actives. Durée volontairement
    /// courte — 2 s contre 5 pour une erreur : une aide doit disparaître vite.
    message_aide: (Option<String>, u8),

    /// Libellé affiché en regard du buffer pendant une saisie.
    ///
    /// Posé par [`Tui::saisie_mode_normal`] au moment de basculer en
    /// [`ModeSaisie::Insertion`] (par exemple `"ouvre"` pour
    /// [`Commande::PilotageOuvrirFoyer`]) ; vidé par `saisie_mode_insertion` à la
    /// validation comme à l'annulation, en miroir de [`Self::buffer_saisie`].
    prompt: String,

    /// Accumulateur de la saisie en [`ModeSaisie::Insertion`], vidé après
    /// chaque validation ou annulation.
    ///
    /// À plat ici parce que l'accumulation ne dépend pas de l'écran :
    /// `saisie_mode_insertion` n'a jamais à consulter [`EtatTui::ecran`].
    buffer_saisie: String,
}

impl EtatTui {
    /// État initial : nœud éteint, écran de pilotage, mode normal.
    ///
    /// La table des commandes se construit en deux temps — vide d'abord,
    /// puisqu'elle est une fonction de l'état qui n'existe pas encore, remplie
    /// aussitôt après (cf. [`CommandesActives::vide`]).
    ///
    /// `chemin_home` ne fait que traverser, vers l'écran du disque qui en fait
    /// la racine de son arbre.
    fn new(chemin_home: &Path) -> Self {
        let mut etat_tui = Self {
            session_application: None,
            ecran: Ecran::Pilotage,
            mode_saisie: ModeSaisie::Normal,
            etat_pilotage: EtatPilotage::new(),
            etat_arborescence_enu: EtatArborescenceEnu::new(),
            etat_arborescence_disque: EtatArborescenceDisque::new(chemin_home),
            enu_selectionnee: None,
            chemin_selectionne: None,
            commandes_actives: CommandesActives::vide(),
            validation_buffer_saisie: ValidationBufferSaisie::Rien,
            message_erreur: (None, 0),
            message_aide: (None, 0),
            prompt: String::new(),
            buffer_saisie: String::new(),
        };
        etat_tui.commandes_actives = CommandesActives::new(&etat_tui);

        etat_tui
    }

    /// Retourne le texte du message d'erreur courant, `None` si aucun.
    ///
    /// Expose uniquement le texte — le compte à rebours est un détail interne.
    fn message_erreur(&self) -> &Option<String> {
        &self.message_erreur.0
    }

    /// Pose un message d'erreur avec un compte à rebours de 5 secondes.
    ///
    /// Toujours appelé à la place d'une affectation directe : garantit que
    /// texte et durée sont posés atomiquement et ne peuvent pas se désynchroniser.
    fn ajouter_message_erreur(&mut self, message_erreur: String) {
        self.message_erreur.0 = Some(message_erreur);
        self.message_erreur.1 = 5;
    }

    /// Retourne le texte du message d'aide courant, `None` si aucun.
    ///
    /// Expose uniquement le texte — le compte à rebours est un détail interne.
    fn message_aide(&self) -> &Option<String> {
        &self.message_aide.0
    }

    /// Pose un message d'aide avec un compte à rebours de 2 secondes.
    ///
    /// Toujours appelé à la place d'une affectation directe : garantit que
    /// texte et durée sont posés atomiquement et ne peuvent pas se désynchroniser.
    fn ajouter_message_aide(&mut self, message_aide: String) {
        self.message_aide.0 = Some(message_aide);
        self.message_aide.1 = 2;
    }

    /// Décrémente d'une seconde tous les comptes à rebours des éléments éphémères.
    ///
    /// Appelé par [`Tui::lancer`] toutes les secondes via une `horloge: Instant`.
    /// Quand le compte à rebours d'un élément atteint zéro, l'élément est effacé.
    ///
    /// Éléments éphémères gérés actuellement :
    /// - [`EtatTui::message_erreur`] — durée 5 s ;
    /// - [`EtatTui::message_aide`] — durée 2 s.
    ///
    /// Les prochains éléments (indicateurs d'activité…) s'ajouteront ici,
    /// chacun avec son propre compteur ; la boucle principale n'a pas à changer.
    fn decremente_temps(&mut self) {
        // Message erreur
        if self.message_erreur.1 > 0 {
            self.message_erreur.1 -= 1;
            if self.message_erreur.1 == 0 {
                self.message_erreur.0 = None;
            }
        }

        // Message aide
        if self.message_aide.1 > 0 {
            self.message_aide.1 -= 1;
            if self.message_aide.1 == 0 {
                self.message_aide.0 = None;
            }
        }
    }

    /// Passe à l'écran de travail suivant, s'il y en a un.
    ///
    /// Seul endroit qui connaisse l'ordre des écrans — la table dit quand
    /// basculer, pas vers quoi. Ici plutôt que dans un module d'écran : aucun
    /// d'eux ne sait ce qui le suit.
    ///
    /// **Rangés en ligne, pas en cycle** : le disque est le dernier, et son bras
    /// vide est l'écriture de cette borne. L'ordre est celui des onglets.
    fn passer_ecran_suivant(&mut self) {
        match self.ecran {
            Ecran::Pilotage => {
                self.ecran = Ecran::ArborescenceDisque;
            }
            Ecran::ArborescenceEnu => {
                self.ecran = Ecran::Pilotage;
            }
            Ecran::ArborescenceDisque => {}
        }
    }

    /// Revient à l'écran de travail précédent, s'il y en a un.
    ///
    /// Pendant de [`EtatTui::passer_ecran_suivant`], dont il partage la raison
    /// de vivre ici : l'ordre des écrans n'est écrit qu'à cet endroit, et il
    /// faut le lire dans les deux sens pour le connaître. L'arborescence des
    /// ENU est la première, d'où son bras vide.
    fn passer_ecran_precedent(&mut self) {
        match self.ecran {
            Ecran::Pilotage => {
                self.ecran = Ecran::ArborescenceEnu;
            }
            Ecran::ArborescenceEnu => {}
            Ecran::ArborescenceDisque => {
                self.ecran = Ecran::Pilotage;
            }
        }
    }

    /// Lève la marque de l'écran courant, sans rien demander au cœur.
    ///
    /// Ni [`EtatTui::enu_selectionnee`] ni [`EtatTui::chemin_selectionne`] n'ont
    /// jamais été envoyées au nœud : les reposer à `None` est tout ce qu'il y a
    /// à faire.
    ///
    /// **La garde sur l'écran ne double pas la table** : `x` est une seule
    /// commande, active sur les deux arborescences, et c'est ici que se décide
    /// laquelle des deux marques elle vise. Depuis un troisième écran, elle ne
    /// lèverait rien.
    fn supprimer_selection(&mut self) {
        if matches!(self.ecran, Ecran::ArborescenceEnu) {
            self.enu_selectionnee = None;
        }
        if matches!(self.ecran, Ecran::ArborescenceDisque) {
            self.chemin_selectionne = None;
        }
    }
}

/// Orchestre la boucle principale et le rendu.
///
/// Possède l'état de l'interface ([`EtatTui`]) et le connecteur vers le
/// thread cœur ([`crate::connecteurs::ConnecteurVersCoeur`]). Coordonne à
/// chaque itération de la boucle : rendu via [`rendu::dessiner`],
/// décrémentation périodique des éléments éphémères, traitement des
/// événements clavier, et dépouillement non bloquant du canal cœur→TUI.
pub(crate) struct Tui {
    /// L'état que la boucle dessine, fait évoluer, et transmet au rendu.
    etat_tui: EtatTui,
    /// L'extrémité TUI des deux canaux — seul chemin vers le nœud.
    connecteur_vers_coeur: ConnecteurVersCoeur,
}

impl Tui {
    /// Crée une instance de [`Tui`] avec l'état initial.
    ///
    /// `chemin_home` ne sert qu'à l'écran du disque, qui en fait la racine de
    /// son arbre. Il est traversé plutôt que lu sur place : `main` est le seul
    /// point de lecture de l'environnement dans tout Feu.
    pub(crate) fn new(connecteur_vers_coeur: ConnecteurVersCoeur, chemin_home: &Path) -> Self {
        Self {
            etat_tui: EtatTui::new(chemin_home),
            connecteur_vers_coeur,
        }
    }

    /// Boucle principale : dessine, traite les événements clavier, lit le canal cœur.
    ///
    /// `horloge` est le seul `Instant` de la boucle : [`EtatTui`] ne manipule que
    /// des entiers, jamais du temps.
    ///
    /// Une session reçue à `None` — extinction — suffit à tout éteindre d'un
    /// coup. La déconnexion du thread cœur est signalée comme une erreur
    /// ordinaire.
    ///
    /// **C'est ici que les deux natures d'erreur se séparent** :
    /// [`ErreurFeuTui::Io`] sort du programme, tout le reste s'affiche et la
    /// boucle continue — les `saisie_mode_*` ignorent laquelle elles remontent.
    ///
    /// # Errors
    ///
    /// L'`std::io::Error` du dessin, du `poll`, ou celui qu'une saisie remonte.
    pub(crate) fn lancer(&mut self, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
        let mut horloge = Instant::now();
        loop {
            terminal.draw(|frame| rendu::dessiner(frame, &mut self.etat_tui))?;

            if horloge.elapsed() >= Duration::from_secs(1) {
                self.etat_tui.decremente_temps();
                horloge = Instant::now();
            }

            if crossterm::event::poll(Duration::from_millis(50))? {
                match self.etat_tui.mode_saisie {
                    ModeSaisie::Normal => match self.saisie_mode_normal() {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(ErreurFeuTui::Io(erreur)) => return Err(erreur),
                        Err(erreur) => self.etat_tui.ajouter_message_erreur(erreur.to_string()),
                    },
                    ModeSaisie::Insertion => match self.saisie_mode_insertion() {
                        Ok(()) => {}
                        Err(ErreurFeuTui::Io(erreur)) => return Err(erreur),
                        Err(erreur) => self.etat_tui.ajouter_message_erreur(erreur.to_string()),
                    },
                    ModeSaisie::Information => match self.saisie_mode_information() {
                        Ok(()) => {}
                        Err(ErreurFeuTui::Io(erreur)) => return Err(erreur),
                        Err(erreur) => self.etat_tui.ajouter_message_erreur(erreur.to_string()),
                    },
                }
            }

            match self.connecteur_vers_coeur.recepteur().try_recv() {
                Err(TryRecvError::Empty) => {}

                Err(TryRecvError::Disconnected) => {
                    self.etat_tui
                        .ajouter_message_erreur(String::from("Thread déconnecté"));
                }

                Ok(message) => match message {
                    MessageCoeurTui::AffichageErreur(m) => self.etat_tui.ajouter_message_erreur(m),
                    MessageCoeurTui::AttenteMdp => {
                        self.etat_tui.vers_saisie_mdp();
                    }
                    MessageCoeurTui::EnvoiArborescenceEnu(arborescence_enus) => {
                        self.etat_tui
                            .etat_arborescence_enu
                            .recevoir_arborescence_enus(arborescence_enus);
                    }
                    MessageCoeurTui::EnvoiSeed(seed) => {
                        self.etat_tui.vers_affichage_seed(seed);
                    }
                    MessageCoeurTui::EnvoiSessionApplication(session_application) => {
                        self.etat_tui.session_application = session_application;
                        self.etat_tui.commandes_actives = CommandesActives::new(&self.etat_tui);
                    }
                },
            }
        }
        Ok(())
    }

    /// Lit le prochain événement crossterm et retourne la touche si c'est un `Press`.
    ///
    /// Retourne `Some((code, modifiers))` uniquement sur [`KeyEventKind::Press`].
    /// Tout autre événement — relâchement de touche, redimensionnement de fenêtre,
    /// focus, souris — retourne `None` sans déclencher d'action.
    ///
    /// Ce helper centralise le filtrage en un seul endroit : les trois méthodes
    /// `saisie_mode_*` s'en servent et ne peuvent plus réagir par inadvertance à
    /// un événement non clavier.
    ///
    /// [`KeyModifiers`] est inclus dans le retour pour permettre les raccourcis
    /// avec modificateur (Ctrl, Alt…) à mesure que les commandes s'étoffent.
    /// Les appels qui n'ont besoin que du code ignorent les modificateurs avec `_`.
    fn lire_touche() -> std::io::Result<Option<(KeyCode, KeyModifiers)>> {
        match crossterm::event::read()? {
            Event::Key(KeyEvent {
                code,
                modifiers,
                kind: KeyEventKind::Press,
                ..
            }) => Ok(Some((code, modifiers))),
            _ => Ok(None),
        }
    }

    /// Traite une touche en mode [`ModeSaisie::Normal`] : dispatch via [`CommandesActives`].
    ///
    /// Trois filtres successifs : les événements non clavier, les touches non
    /// liées dans le contexte courant, puis le `match` qui mappe chaque
    /// [`Commande`] à son effet.
    ///
    /// **Aucun raccourci n'est hardcodé ici** : ajouter une commande, c'est
    /// étendre l'enum, enrichir les règles de [`CommandesActives::new`] et
    /// ajouter un bras. Le filtrage par contexte reste dans [`commandes`].
    ///
    /// La table est reconstruite après chaque dispatch : la position ou l'écran
    /// ont pu changer. Rend `false` pour arrêter la boucle principale.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuTui::Io`] si le terminal ne rend plus d'événement.
    /// [`ErreurFeuTui::TuiAucunCheminSelectionne`] si `d` ou `r` s'exécute sans chemin marqué.
    /// [`ErreurFeuTui::TuiAucuneEnuSelectionnee`] si `r` s'exécute sans ENU marquée.
    /// Les variantes `Disque*` et `Enu*`, propagées par les deux arborescences.
    fn saisie_mode_normal(&mut self) -> ResultFeuTui<bool> {
        if let Some(touche) = Self::lire_touche()?
            && let Some(commande) = self.etat_tui.commandes_actives.get(&touche)
        {
            match commande {
                Commande::DisqueBasculerPli => {
                    self.etat_tui.etat_arborescence_disque.basculer_pli()?;
                }
                Commande::DisqueRechargerRepertoire => {
                    self.etat_tui.etat_arborescence_disque.recharger()?;
                }
                Commande::DisqueDescendreCurseur => {
                    self.etat_tui.etat_arborescence_disque.descendre_curseur();
                }
                Commande::DisqueMarquer => {
                    self.etat_tui.chemin_selectionne = self
                        .etat_tui
                        .etat_arborescence_disque
                        .donne_chemin_a_marquer();
                }
                Commande::DisqueMonterCurseur => {
                    self.etat_tui.etat_arborescence_disque.monter_curseur();
                }
                Commande::EcranSuivant => {
                    self.etat_tui.passer_ecran_suivant();
                }
                Commande::EcranPrecedent => {
                    self.etat_tui.passer_ecran_precedent();
                }
                Commande::SupprimerSelection => {
                    self.etat_tui.supprimer_selection();
                }
                Commande::EnuBasculerPli => {
                    self.etat_tui.etat_arborescence_enu.basculer_pli()?;
                }
                Commande::EnuChargerArborescence => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::ChargementArborescenceEnu);
                }
                Commande::EnuDescendreCurseur => {
                    self.etat_tui.etat_arborescence_enu.descendre_curseur();
                }
                Commande::EnuMarquer => {
                    self.etat_tui.enu_selectionnee =
                        self.etat_tui.etat_arborescence_enu.donne_enu_a_marquer();
                }
                Commande::EnuMonterCurseur => {
                    self.etat_tui.etat_arborescence_enu.monter_curseur();
                }
                Commande::ListeCommandesActives => {
                    self.etat_tui.ajouter_message_aide(
                        self.etat_tui.commandes_actives.liste_commandes_actives(),
                    );
                }
                Commande::PilotageAllumerNoeud => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::AllumageNoeud);
                }
                Commande::PilotageAPropos => {
                    let titre = String::from("Feu");
                    let information = format!(
                        "Version {} · GPL-3.0-or-later\n\n\
                             © 2026 Bertrand CLAVELIER\n\n",
                        env!("CARGO_PKG_VERSION")
                    );

                    self.etat_tui.vers_affichage_information(titre, information);
                }
                Commande::PilotageChangerPositionClasseur(index) => {
                    self.etat_tui.etat_pilotage.position_courante.classeur = *index;
                }
                Commande::PilotageChangerPositionFoyer(index) => {
                    self.etat_tui.etat_pilotage.position_courante.foyer = *index;
                }
                Commande::PilotageEteindreNoeud => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::ExtinctionNoeud);
                }
                Commande::PilotageFermerComptoirDepot => {
                    self.etat_tui.prompt = String::from("ferme comptoir dépôt");
                    self.etat_tui.mode_saisie = ModeSaisie::Insertion;
                    self.etat_tui.validation_buffer_saisie =
                        ValidationBufferSaisie::FermetureComptoirDepot;
                }
                Commande::PilotageFermerFoyer(index) => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::FermetureFoyer(*index));
                    self.etat_tui.etat_pilotage.position_courante.foyer = None;
                    self.etat_tui.etat_pilotage.position_courante.classeur = None;
                }
                Commande::PilotageOuvrirComptoirDepot(index_foyer, index_classeur) => {
                    let Some(chemin) = self.etat_tui.chemin_selectionne.as_ref() else {
                        return Err(ErreurFeuTui::TuiAucunCheminSelectionne);
                    };
                    self.connecteur_vers_coeur.envoyer_message_tui_coeur(
                        MessageTuiCoeur::OuvertureComptoir(
                            chemin.join(format!("f{index_foyer}.c{index_classeur}_depot_feu")),
                            *index_foyer,
                            *index_classeur,
                        ),
                    );
                }
                Commande::PilotageOuvrirFoyer => {
                    self.etat_tui.prompt = String::from("ouvre");
                    self.etat_tui.mode_saisie = ModeSaisie::Insertion;
                    self.etat_tui.validation_buffer_saisie = ValidationBufferSaisie::OuvertureFoyer;
                }
                Commande::PilotageQuitter => {
                    self.connecteur_vers_coeur
                        .envoyer_message_tui_coeur(MessageTuiCoeur::Quitter);
                    return Ok(false);
                }
                Commande::PilotageRetraitLectureSeule => {
                    let Some(chemin) = self.etat_tui.chemin_selectionne.as_ref() else {
                        return Err(ErreurFeuTui::TuiAucunCheminSelectionne);
                    };
                    let Some(fiche) = self.etat_tui.enu_selectionnee.as_ref() else {
                        return Err(ErreurFeuTui::TuiAucuneEnuSelectionnee);
                    };
                    let hash = fiche.hash_carte();
                    self.connecteur_vers_coeur.envoyer_message_tui_coeur(
                        MessageTuiCoeur::RetraitLectureSeule(
                            chemin.join(format!(
                                "retrait_feu_{:02x}{:02x}{:02x}{:02x}",
                                hash[0], hash[1], hash[2], hash[3]
                            )),
                            fiche.clone(),
                        ),
                    );
                }
                Commande::PilotageSecoursFermetureFoyer => {
                    self.etat_tui.prompt = String::from("secours fermeture foyer");
                    self.etat_tui.mode_saisie = ModeSaisie::Insertion;
                    self.etat_tui.validation_buffer_saisie =
                        ValidationBufferSaisie::SecoursFermetureFoyer;
                }
            }

            self.etat_tui.commandes_actives = CommandesActives::new(&self.etat_tui);
        }

        Ok(true)
    }

    /// Traite une touche en mode [`ModeSaisie::Insertion`] : accumulation dans le buffer.
    ///
    /// Seules les frappes sans modificateur (`KeyModifiers::NONE`) sont traitées —
    /// un `Ctrl+Entrée` n'est pas une validation, un `Ctrl+C` n'est pas un caractère.
    ///
    /// À la validation, [`EtatTui::validation_buffer_saisie`] décide quel message
    /// envoyer — chaque variante y documente sa garde.
    ///
    /// **L'état est remis au repos avant toute vérification**, la saisie clonée
    /// d'abord : c'est ce qui garantit qu'un buffer refusé ne laisse derrière lui
    /// ni prompt ni saisie ratée. **Sans jamais consulter l'écran courant.**
    ///
    /// À l'annulation, [`MessageTuiCoeur::Annulation`] part vers le cœur, ce dont
    /// dépendent ses attentes bloquantes.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuTui::Io`] si le terminal ne rend plus d'événement.
    /// [`ErreurFeuTui::TuiAucuneEnuSelectionnee`] si la fermeture d'un comptoir est validée sans marque.
    /// [`ErreurFeuTui::TuiNoeudEteint`] si la commande demande une session absente.
    /// [`ErreurFeuTui::TuiEntreeNonEntier`] si la saisie n'est pas un entier.
    /// [`ErreurFeuTui::TuiIndexComptoirInvalide`] si aucun comptoir de dépôt ne porte cet index.
    fn saisie_mode_insertion(&mut self) -> ResultFeuTui<()> {
        match Self::lire_touche()? {
            Some((KeyCode::Char(c), KeyModifiers::NONE)) => {
                self.etat_tui.buffer_saisie.push(c);
            }

            Some((KeyCode::Backspace, KeyModifiers::NONE)) => {
                self.etat_tui.buffer_saisie.pop();
            }

            Some((KeyCode::Enter, KeyModifiers::NONE)) => {
                let saisie = self.etat_tui.buffer_saisie.clone();

                self.etat_tui.prompt.clear();
                self.etat_tui.buffer_saisie.clear();
                self.etat_tui.vers_ecran_principal();

                match self.etat_tui.validation_buffer_saisie {
                    ValidationBufferSaisie::EnvoiMdp => {
                        self.connecteur_vers_coeur.envoyer_message_tui_coeur(
                            MessageTuiCoeur::EnvoieMdp(SecretString::from(saisie)),
                        );
                    }

                    ValidationBufferSaisie::FermetureComptoirDepot => {
                        let Some(enu) = self.etat_tui.enu_selectionnee.as_ref() else {
                            return Err(ErreurFeuTui::TuiAucuneEnuSelectionnee);
                        };
                        let Some(session) = self.etat_tui.session_application.as_ref() else {
                            return Err(ErreurFeuTui::TuiNoeudEteint);
                        };
                        let Ok(index) = saisie.trim().parse() else {
                            return Err(ErreurFeuTui::TuiEntreeNonEntier);
                        };

                        if !session.comptoirs_depot_ouverts().contains_key(&index) {
                            return Err(ErreurFeuTui::TuiIndexComptoirInvalide(index));
                        }
                        self.connecteur_vers_coeur.envoyer_message_tui_coeur(
                            MessageTuiCoeur::FermetureComptoirDepot(index, enu.clone()),
                        );
                    }

                    ValidationBufferSaisie::OuvertureFoyer => {
                        let Ok(index) = saisie.trim().parse() else {
                            return Err(ErreurFeuTui::TuiEntreeNonEntier);
                        };
                        self.connecteur_vers_coeur
                            .envoyer_message_tui_coeur(MessageTuiCoeur::OuvertureFoyer(index));
                    }

                    ValidationBufferSaisie::Rien => {}

                    ValidationBufferSaisie::SecoursFermetureFoyer => {
                        let Ok(index) = saisie.trim().parse() else {
                            return Err(ErreurFeuTui::TuiEntreeNonEntier);
                        };

                        self.connecteur_vers_coeur.envoyer_message_tui_coeur(
                            MessageTuiCoeur::SecoursFermetureFoyer(index),
                        );
                    }
                }
                self.etat_tui.validation_buffer_saisie = ValidationBufferSaisie::Rien;
            }

            Some((KeyCode::Esc, KeyModifiers::NONE)) => {
                self.etat_tui.prompt.clear();
                self.etat_tui.buffer_saisie.clear();
                self.etat_tui.vers_ecran_principal();

                self.connecteur_vers_coeur
                    .envoyer_message_tui_coeur(MessageTuiCoeur::Annulation);
            }
            _ => {}
        }
        Ok(())
    }

    /// Traite une touche en mode [`ModeSaisie::Information`] : avancement sur Entrée uniquement.
    ///
    /// Seule `Entrée` sans modificateur est active — tout autre événement est
    /// ignoré, pour qu'un redimensionnement de fenêtre ou un clic souris ne
    /// fasse pas progresser l'écran sans geste de l'utilisateur.
    ///
    /// Ce qu'« avancer » signifie revient à l'écran affiché ; cette méthode ne
    /// garde que ce qu'elle seule peut faire — prévenir le cœur, dont elle
    /// tient le connecteur.
    ///
    /// # Errors
    ///
    /// [`ErreurFeuTui::Io`] si le terminal ne rend plus d'événement, seule
    /// possible ici : rien n'y est vérifié que la touche.
    fn saisie_mode_information(&mut self) -> ResultFeuTui<()> {
        if let Some((KeyCode::Enter, KeyModifiers::NONE)) = Self::lire_touche()?
            && self.etat_tui.entree_mode_information()
        {
            self.connecteur_vers_coeur
                .envoyer_message_tui_coeur(MessageTuiCoeur::SeedBienRecue);
        }
        Ok(())
    }
}
