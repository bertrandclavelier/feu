//! Représentation persistable du trousseau cryptographique.
//!
//! Ce module définit les structures sérialisables du trousseau — versions
//! "publiques" des clés, où chaque secret est chiffré avec AES-256-GCM
//! avant d'être stocké sur le disque.
//!
//! Aucune donnée sensible n'est stockée en clair : seul le sel Argon2id
//! et les clés publiques (Ed25519, X25519) apparaissent sans chiffrement.
//! Ces structures sont destinées à être écrites sur le disque par le gardien.

/// Représentation persistable des clés d'un foyer Feu.
///
/// Toutes les clés privées et symétriques sont chiffrées avec AES-256-GCM.
/// Chaque champ chiffré suit le format :
/// `[nonce (12 o.) | ciphertext + tag (48 o.)]` — soit 60 octets au total.
pub(crate) struct TrousseauFoyerPublic {
    pub(crate) adresse_onion: String,
    pub(crate) cle_chiffrement: [u8; 60], // chiffrée
    pub(crate) cle_sig_privee: [u8; 60],  // chiffrée
    pub(crate) cle_sig_pub: [u8; 32],
    pub(crate) cle_chiff_privee: [u8; 60], // chiffrée
    pub(crate) cle_chiff_pub: [u8; 32],

    pub(crate) cles_chiffrement_classeurs: Vec<[u8; 60]>, // chiffrées
}

impl TrousseauFoyerPublic {
    /// Crée un [`TrousseauFoyerPublic`] sans clés de classeur.
    ///
    /// Les clés de classeur sont ajoutées après construction via
    /// [`ajoute_cle_chiffrement_classeur`](Self::ajoute_cle_chiffrement_classeur).
    pub(crate) fn new(
        adresse_onion: String,
        cle_chiffrement: [u8; 60],
        cle_sig_privee: [u8; 60],
        cle_sig_pub: [u8; 32],
        cle_chiff_privee: [u8; 60],
        cle_chiff_pub: [u8; 32],
    ) -> Self {
        Self {
            adresse_onion,
            cle_chiffrement,
            cle_sig_privee,
            cle_sig_pub,
            cle_chiff_privee,
            cle_chiff_pub,

            cles_chiffrement_classeurs: Vec::new(),
        }
    }

    /// Ajoute une clé de chiffrement de classeur chiffrée.
    pub(crate) fn ajoute_cle_chiffrement_classeur(&mut self, cle: [u8; 60]) {
        self.cles_chiffrement_classeurs.push(cle);
    }
}

/// Représentation persistable du trousseau complet d'un nœud Feu.
///
/// Contient les clés du nœud et l'ensemble des trousseau de foyers.
/// Le sel Argon2id est stocké en clair — il est nécessaire pour re-dériver
/// la clé éphémère lors du déchiffrement des clés privées.
pub(crate) struct TrousseauPublic {
    pub(crate) sel: [u8; 16],

    pub(crate) cle_sig_privee: [u8; 60], // chiffrée
    pub(crate) cle_sig_pub: [u8; 32],

    pub(crate) cles_foyers: Vec<TrousseauFoyerPublic>,
}

impl TrousseauPublic {
    /// Crée un [`TrousseauPublic`] sans foyers.
    ///
    /// Les foyers sont ajoutés après construction via
    /// [`ajoute_trousseau_foyer_public`](Self::ajoute_trousseau_foyer_public).
    pub(crate) fn new(sel: [u8; 16], cle_sig_privee: [u8; 60], cle_sig_pub: [u8; 32]) -> Self {
        Self {
            sel,
            cle_sig_privee,
            cle_sig_pub,
            cles_foyers: Vec::new(),
        }
    }

    /// Ajoute le trousseau public d'un foyer.
    pub(crate) fn ajoute_trousseau_foyer_public(&mut self, trousseau: TrousseauFoyerPublic) {
        self.cles_foyers.push(trousseau);
    }
}
