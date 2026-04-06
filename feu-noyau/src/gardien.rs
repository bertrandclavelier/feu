// Copyright (C) 2026 Bertrand CLAVELIER
//
// This file is part of FeuNoyau.
//
// FeuNoyau is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// FeuNoyau is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with FeuNoyau. If not, see <https://www.gnu.org/licenses/>.

//! Le gardien est l'unique point d'accès au système de fichiers pour les
//! données locales de l'instance FeuNoyau — configuration globale, dossiers des
//! foyers, coffres et clés.
//!
//! Il délègue la connaissance de l'arborescence à son [`Carnet`] et
//! orchestre les opérations sur le système de fichiers sans les exposer
//! à l'extérieur du module. Il maintient en mémoire la configuration
//! globale du nœud via [`Configuration`] — miroir du fichier `config.feu` sur
//! disque, écrit en dernière étape de chaque opération structurante.
//! Cette centralisation est un invariant de sécurité et de cohérence
//! du protocole.

mod carnet;
pub(super) mod erreur;

use super::cryptographe::trousseaux_publics::{
    TrousseauPublicComplet, TrousseauPublicFoyer, TrousseauPublicNoeud,
};
use crate::Anomalie;
use crate::MAX_FOYERS;
use carnet::Carnet;
use erreur::{ErreurGardien, ResultGardien};
use std::fs::File;
use std::path::PathBuf;

const VERSION_CONFIGURATION: u32 = 1;

const ERR_GAR_001: &str = "GAR-001 > Aucune arborescence du nœud trouvée";
const ERR_GAR_002: &str = "GAR-002 > Une arborescence existe déjà";
const ERR_GAR_003: &str = "GAR-003 > Suppression du dossier impossible s'il n'est pas archivé";

/// Configuration globale du nœud — miroir de `config.feu` en mémoire.
///
/// Contient la version du format de fichier, le prochain index de dérivation
/// BIP32, et les adresses `.onion` des `MAX_FOYERS` foyers du nœud.
struct Configuration {
    /// Version du format de `config.feu` — incrémentée à chaque changement
    /// de structure incompatible.
    version: u32,
    /// Prochain index de dérivation BIP32 à attribuer au prochain foyer créé.
    prochain_index: u32,
    /// Adresses `.onion` des foyers — tableau de taille fixe `MAX_FOYERS`.
    adresses_onion: [String; MAX_FOYERS],
}

impl Configuration {
    /// Crée une configuration vide avec les valeurs initiales.
    ///
    /// `version` est `VERSION_CONFIGURATION`, `prochain_index` est `1` —
    /// la dérivation BIP32 du premier foyer commence à l'index `1` (`m/1'`).
    /// Les adresses `.onion` sont toutes vides.
    fn new() -> Self {
        Self {
            version: VERSION_CONFIGURATION,
            prochain_index: 1,
            adresses_onion: std::array::from_fn(|_| String::from("")),
        }
    }

    /// Reconstruit la configuration depuis le contenu textuel de `config.feu`.
    ///
    /// Attend exactement `2 + MAX_FOYERS` lignes : version, prochain_index,
    /// puis une adresse `.onion` par foyer.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `version` ou `prochain_index` ne sont pas des
    /// entiers valides. Panique si le fichier contient moins de lignes qu'attendu.
    fn new_from_string(contenu: &str) -> ResultGardien<Self> {
        let mut lignes: Vec<&str> = contenu.lines().collect();
        let version = lignes.remove(0).parse::<u32>()?;
        let prochain_index = lignes.remove(0).parse::<u32>()?;

        let mut tableau: [String; MAX_FOYERS] = std::array::from_fn(|_| String::from(""));
        for e in tableau.iter_mut() {
            *e = String::from(lignes.remove(0));
        }

        Ok(Self {
            version,
            prochain_index,
            adresses_onion: tableau,
        })
    }

    /// Sérialise la configuration en texte pour écriture dans `config.feu`.
    ///
    /// Format : version, prochain_index, puis chaque adresse `.onion`,
    /// chaque champ séparé par `\n`.
    fn exporte_en_texte(&self) -> String {
        let mut resultat = format!("{}\n{}\n", self.version, self.prochain_index);
        for e in &self.adresses_onion {
            resultat.push_str(e);
            resultat.push('\n');
        }
        resultat
    }

    /// Retourne le tableau des adresses `.onion` des foyers.
    fn donne_adresses_onion(&self) -> &[String] {
        &self.adresses_onion
    }
}

/// Gardien des données locales du nœud Feu.
///
/// Orchestre les opérations sur le système de fichiers via son [`Carnet`]
/// et maintient en mémoire la configuration globale via [`Configuration`].
/// Aucun autre composant n'accède directement au disque.
pub(super) struct Gardien {
    carnet: Carnet,
    configuration: Configuration,
}

impl Gardien {
    /// Crée le gardien de [`FeuNoyau`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le carnet ne peut pas être initialisé —
    /// notamment si la variable d'environnement `HOME` est absente.
    pub(super) fn new() -> ResultGardien<Self> {
        Ok(Self {
            carnet: Carnet::new()?,
            configuration: Configuration::new(),
        })
    }

    /// Ouvre un nœud Feu existant en chargeant sa configuration depuis `config.feu`.
    ///
    /// Crée le carnet à partir de `HOME`, vérifie que l'arborescence `~/.feu`
    /// existe, lit `config.feu` sur le disque et reconstruit la [`Configuration`] en mémoire.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si `HOME` est absente, si l'arborescence `~/.feu`
    /// est introuvable, si `config.feu` est absent ou illisible, ou si son
    /// contenu ne peut pas être parsé.
    pub(super) fn ouvre_nouveau() -> ResultGardien<Self> {
        let carnet = Carnet::new()?;
        if !carnet.existe_arborescence_noeud() {
            return Err(ErreurGardien::Interne(String::from(ERR_GAR_001)));
        }
        Ok(Self {
            configuration: Configuration::new_from_string(&carnet.ouvre_configuration()?)?,
            carnet,
        })
    }

    // ── Arborescence ─────────────────────────────────────────────────────────

    /// Indique si l'arborescence `~/.feu` existe sur le système de fichiers.
    pub(super) fn existence_arborescence(&self) -> bool {
        self.carnet.existe_arborescence_noeud()
    }

    /// Construit le tableau de session des foyers depuis la configuration en mémoire.
    ///
    /// Retourne un tableau de `MAX_FOYERS` tuples `(false, adresse_onion)` —
    /// tous les foyers sont marqués éteints à l'allumage du nœud.
    pub(super) fn creation_tableau_session_foyers(&self) -> [(bool, String); MAX_FOYERS] {
        let mut t: [(bool, String); MAX_FOYERS] =
            std::array::from_fn(|_| (false, String::from("")));

        for (i, e) in t.iter_mut().enumerate() {
            *e = (false, self.configuration.adresses_onion[i].clone());
        }

        t
    }

    /// Retourne le chemin du dossier `~/.feu/<onion>`.
    pub(super) fn donne_chemin_onion(&self, onion: &str) -> PathBuf {
        self.carnet.donne_chemin_onion(onion)
    }

    /// Ancre le nœud vierge sur le disque à partir du trousseau public.
    ///
    /// Délègue à [`Carnet::ecrire_trousseau_public`] la création de l'arborescence
    /// complète et l'écriture de toutes les clés chiffrées. Cette opération
    /// n'est valide que pour un nœud vierge — elle échoue si `~/.feu` existe déjà.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'arborescence existe déjà, ou si une
    /// opération disque échoue.
    pub(super) fn cree_premiere_arborescence(
        &self,
        trousseau_public_complet: &TrousseauPublicComplet,
    ) -> ResultGardien<()> {
        match self.carnet.existe_arborescence_noeud() {
            true => Err(ErreurGardien::Interne(String::from(ERR_GAR_002))),
            false => {
                // Écriture du trousseau public sur le disque
                self.carnet
                    .ecrire_trousseau_public_complet(trousseau_public_complet)?;

                Ok(())
            }
        }
    }

    /// Supprime le dossier clair `<onion>` après vérification que l'archive existe.
    ///
    /// Contrôle l'existence de `<onion>.feu` avant toute suppression —
    /// garantit qu'on ne supprime pas un dossier non archivé.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'archive `<onion>.feu` est absente
    /// ou si la suppression récursive du dossier échoue.
    pub(super) fn suppression_dossier_onion(&self, onion: &str) -> ResultGardien<()> {
        // Vérification que l'archive existe avant de supprimer le dossier. Sinon impossible
        if self.carnet.donne_chemin_archive_chiffree(onion).exists() {
            self.carnet.supprime_dossier_onion(onion)?;
            Ok(())
        } else {
            Err(ErreurGardien::Interne(String::from(ERR_GAR_003)))
        }
    }

    // ── Configuration ─────────────────────────────────────────────────────────

    /// Orchestre la persistance de `config.feu` sur le disque.
    ///
    /// Exporte la configuration en mémoire via [`Configuration::exporte_en_texte`]
    /// puis délègue l'écriture à [`Carnet::enregistre_configuration`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'écriture échoue.
    pub(super) fn enregistrement_configuration(&self) -> ResultGardien<()> {
        self.carnet
            .enregistre_configuration(self.configuration.exporte_en_texte())?;

        Ok(())
    }

    /// Enregistre l'adresse `.onion` d'un foyer dans la [`Configuration`] en mémoire.
    ///
    /// Écrit l'adresse fournie par le cryptographe à la position `position`
    /// dans le tableau `adresses_onion`.
    ///
    /// Cette méthode n'écrit rien sur le disque — appeler ensuite
    /// [`Gardien::enregistrement_configuration`] pour persister l'état.
    pub(super) fn ajout_nouveau_foyer_dans_configuration(
        &mut self,
        onion: String,
        position: usize,
    ) {
        self.configuration.adresses_onion[position] = onion;
        self.configuration.prochain_index += 1;
    }

    // ── Trousseaux ────────────────────────────────────────────────────────────

    /// Réécrit le trousseau public complet sur le disque.
    ///
    /// Délègue à [`Carnet::ecrire_trousseau_public_complet`]. Les fichiers
    /// existants sont écrasés atomiquement — utilisé lors du changement de
    /// mot de passe.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si une opération disque échoue.
    pub(super) fn ecriture_trousseau_public_complet(
        &self,
        trousseau_public_complet: &TrousseauPublicComplet,
    ) -> ResultGardien<()> {
        self.carnet
            .ecrire_trousseau_public_complet(trousseau_public_complet)?;
        Ok(())
    }

    /// Lit les clés du nœud sur le disque et construit un [`TrousseauPublicNoeud`].
    ///
    /// Lit le sel, la clé privée et la clé publique de signature du nœud.
    /// Les foyers sont gérés séparément dans [`TrousseauPublicComplet`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si un fichier est absent, illisible ou de taille incorrecte.
    pub(super) fn lecture_pour_creation_trousseau_public_noeud(
        &self,
    ) -> ResultGardien<TrousseauPublicNoeud> {
        Ok(TrousseauPublicNoeud::new(
            self.carnet.lire_pour_donner_sel()?,
            self.carnet.lire_pour_donner_cle_sig_privee()?,
            self.carnet.lire_pour_donner_cle_sig_pub()?,
        ))
    }

    /// Lit les clés chiffrées d'un foyer sur le disque et construit un [`TrousseauPublicFoyer`].
    ///
    /// Délègue la lecture au carnet. Les clés lues sont toujours chiffrées —
    /// elles seront déchiffrées par le cryptographe.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si un fichier de clé est absent, illisible ou de taille incorrecte.
    pub(super) fn creation_trousseau_foyer_public(
        &self,
        onion: &str,
    ) -> ResultGardien<TrousseauPublicFoyer> {
        self.carnet.creer_trousseau_public_foyer(onion)
    }

    // ── Archives ──────────────────────────────────────────────────────────────

    /// Prépare les deux flux nécessaires à l'archivage chiffré d'un foyer.
    ///
    /// Enchaîne trois opérations :
    ///
    /// 1. Crée l'archive tar intermédiaire `<onion>.tar` depuis le dossier `<onion>`.
    /// 2. Ouvre `<onion>.tar` en lecture — source du chiffrement.
    /// 3. Crée `<onion>.feu` en écriture exclusive — destination du chiffrement.
    ///
    /// Le tuple retourné `(source, destination)` est passé directement au cryptographe
    /// via [`Cryptographe::donne_flux_chiffrement_foyer`].
    /// `<onion>.tar` doit être supprimé après chiffrement.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si la création du tar échoue, si `<onion>.feu` existe déjà,
    /// ou si une opération disque échoue.
    pub(super) fn preparation_archivage_chiffre_foyer(
        &self,
        onion: &str,
    ) -> ResultGardien<(File, File)> {
        self.carnet.archive_tar_foyer(onion)?;

        Ok((
            self.carnet.ouvre_archive_tar_foyer_lecture(onion)?,
            self.carnet.ouvre_archive_chiffree_foyer_ecriture(onion)?,
        ))
    }

    /// Prépare les éléments nécessaires au déchiffrement d'un foyer.
    ///
    /// Lit depuis le disque et ouvre les fichiers dans l'ordre attendu par
    /// [`Cryptographe::donne_flux_dechiffrement_foyer`] :
    ///
    /// 1. La clé symétrique chiffrée depuis `~/.feu/.cles/<onion>.cle` — 60 octets.
    /// 2. L'archive chiffrée `<onion>.feu` en lecture — source du déchiffrement.
    /// 3. Un fichier `<onion>.tar` vide en écriture — destination du déchiffrement.
    ///
    /// Après déchiffrement, appeler [`extraction_dechiffree_foyer`](Self::extraction_dechiffree_foyer)
    /// pour extraire le tar et nettoyer les fichiers intermédiaires.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si un fichier de clé est absent ou de taille incorrecte,
    /// si `<onion>.feu` est absent, ou si la création de `<onion>.tar` échoue.
    pub(super) fn preparation_desarchivage_chiffre_foyer(
        &self,
        onion: &str,
    ) -> ResultGardien<([u8; 60], File, File)> {
        Ok((
            self.carnet.lire_pour_donner_cle_chiffrement_foyer(onion)?,
            self.carnet.ouvre_archive_chiffree_foyer_lecture(onion)?,
            self.carnet.ouvre_archive_tar_vide_ecriture(onion)?,
        ))
    }

    /// Extrait l'archive tar déchiffrée et supprime les fichiers intermédiaires.
    ///
    /// Enchaîne trois opérations séquentielles :
    ///
    /// 1. Extrait `<onion>.tar` vers `~/.feu/<onion>/`.
    /// 2. Supprime `<onion>.tar`.
    /// 3. Supprime `<onion>.feu`.
    ///
    /// Doit être appelé immédiatement après [`Cryptographe::donne_flux_dechiffrement_foyer`].
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si l'extraction échoue ou si la suppression d'un
    /// fichier intermédiaire échoue.
    pub(super) fn desarchivage_chiffre_foyer(&self, onion: &str) -> ResultGardien<()> {
        self.carnet.desarchive_tar_foyer(onion)?;
        self.carnet.supprime_archive_foyer_tar(onion)?;
        self.carnet.supprime_archive_foyer_chiffree(onion)?;
        Ok(())
    }

    /// Supprime l'archive tar intermédiaire `<onion>.tar` après chiffrement.
    ///
    /// Doit être appelé immédiatement après [`preparation_archivage_chiffre_foyer`](Self::preparation_archivage_chiffre_foyer)
    /// et le chiffrement — le `.tar` est un fichier temporaire qui ne doit pas
    /// persister sur le disque.
    ///
    /// # Erreurs
    ///
    /// Retourne une erreur si le fichier est absent ou si la suppression échoue.
    pub(super) fn suppression_archive_foyer_tar(&self, onion: &str) -> ResultGardien<()> {
        self.carnet.supprime_archive_foyer_tar(onion)?;

        Ok(())
    }

    // ── Check-up ──────────────────────────────────────────────────────────────

    /// Orchestre le diagnostic complet du nœud.
    ///
    /// Délègue la vérification de l'arborescence au carnet, puis tente de lire
    /// et parser `config.feu` pour vérifier les fichiers de chaque foyer connu.
    /// Si la config est illisible, les foyers ne peuvent pas être vérifiés —
    /// `ConfigurationIllisible` est ajoutée et la boucle foyers est ignorée.
    pub(super) fn check_up_noeud(&self) -> ResultGardien<Vec<Anomalie>> {
        let mut resultat = self.carnet.verifier_arborescence_noeud()?;

        match self.carnet.ouvre_configuration() {
            Err(_) => {
                // Déjà traité par verifier_arborescence_noeud()
            }
            Ok(valeur) => match Configuration::new_from_string(&valeur) {
                Err(_) => resultat.push(Anomalie::ConfigurationIllisible),

                Ok(configuration) => {
                    // Pour chaque foyer
                    for element in configuration.donne_adresses_onion() {
                        if !self
                            .carnet
                            .donne_chemin_feu()
                            .join(".cles/")
                            .join(format!("{}{}", element, ".cle"))
                            .exists()
                        {
                            resultat.push(Anomalie::ElementAbsent(
                                self.carnet
                                    .donne_chemin_feu()
                                    .join(".cles/")
                                    .join(format!("{}{}", element, ".cle")),
                            ));
                        }
                        if !self
                            .carnet
                            .donne_chemin_feu()
                            .join(format!("{}{}", element, ".feu"))
                            .exists()
                        {
                            resultat.push(Anomalie::ElementAbsent(
                                self.carnet
                                    .donne_chemin_feu()
                                    .join(format!("{}{}", element, ".feu")),
                            ));
                        }
                    }
                }
            },
        }
        Ok(resultat)
    }

    /// Vérifie la présence des fichiers d'un foyer ouvert.
    ///
    /// Délègue la vérification de l'arborescence interne au carnet.
    pub(super) fn check_up_foyer(&self, onion: &str) -> Vec<Anomalie> {
        self.carnet.verifier_arborescence_foyer(onion)
    }
}
