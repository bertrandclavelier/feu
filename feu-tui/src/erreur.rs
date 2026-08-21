// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuTui.
//
// FeuTui is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuTui is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuTui. If not, see <https://www.gnu.org/licenses/>.

//! Les échecs que la couche terminal sait nommer.
//!
//! Un seul type porte les deux natures qui remontent la boucle : celles que
//! l'utilisateur lit et corrige, et l'échec d'entrée-sortie du terminal, qui
//! ne s'affiche nulle part puisque plus rien ne s'affiche. Le tri se fait
//! chez l'appelant, sur la variante.

use thiserror::Error;

/// Résultat de la couche terminal, [`ErreurFeuTui`] en erreur.
pub(crate) type ResultFeuTui<T> = Result<T, ErreurFeuTui>;

/// Les erreurs de `feu-tui`, une variante par échec nommable.
#[derive(Error, Debug)]
pub(crate) enum ErreurFeuTui {
    /// `read_dir` échoue sur une ligne pourtant répertoire : droits refusés,
    /// chemin disparu ou démonté depuis le dépliage de son parent.
    #[error("TUI > Disque : répertoire illisible")]
    DisqueRepertoireIllisible,

    /// Inatteignable tant que le curseur naît à `Some(0)` et n'est jamais
    /// remis à `None` : écrite pour ne pas dépendre de cet invariant.
    #[error("TUI > Disque : pas de curseur sélectionné")]
    DisqueSansCurseur,

    /// Le curseur a débordé d'une frappe, avant que le rendu ne le borne.
    #[error("TUI > Disque : sélection hors de la liste")]
    DisqueSelectionHorsListe,

    /// `Entrée` sur un fichier, qui n'a rien à déplier.
    #[error("TUI > Disque : sélection pas un répertoire")]
    DisqueSelectionPasRepertoire,

    /// `Entrée` avant tout `R` : l'arbre n'a jamais été demandé au cœur.
    #[error("TUI > Enu : pas d'arborescence")]
    EnuSansArborescence,

    /// Pendant de [`Self::DisqueSansCurseur`], et inatteignable pour la même
    /// raison.
    #[error("TUI > Enu : pas de curseur sélectionné")]
    EnuSansCurseur,

    /// Le curseur désigne un rang que les plis courants ne rendent plus visible.
    #[error("TUI > Enu : sélection hors de la liste")]
    EnuSelectionHorsListe,

    /// `r` ou la fermeture d'un comptoir, sans marque posée par `m`.
    #[error("TUI > aucune Enu sélectionnée")]
    TuiAucuneEnuSelectionnee,

    /// `d` ou `r`, sans chemin marqué sur l'écran du disque.
    #[error("TUI > aucun chemin sélectionné")]
    TuiAucunCheminSelectionne,

    /// La saisie validée devait être un index et ne s'analyse pas en entier.
    #[error("TUI > Ce n'est pas un nombre entier")]
    TuiEntreeNonEntier,

    /// Aucun comptoir de dépôt ouvert ne porte l'index saisi.
    #[error("TUI > {0} : Index comptoir invalide")]
    TuiIndexComptoirInvalide(usize),

    /// Le nœud s'est éteint entre l'affichage de la commande et sa validation.
    #[error("TUI > Le nœud doit être allumé")]
    TuiNoeudEteint,

    /// Terminal injoignable : seule variante à ne pas s'afficher dans la TUI,
    /// puisque plus rien ne s'y affiche. Elle remonte jusqu'à `main`.
    #[error("TUI > {0}")]
    Io(#[from] std::io::Error),
}
