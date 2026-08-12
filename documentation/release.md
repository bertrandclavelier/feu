# Feu — Release v0.0.5

> **Date :** 12 août 2026
> **Statut :** cinquième release
> **Licence :** GNU General Public License v3.0 ou ultérieure (GPL-3.0-or-later)
> **Photo technique** — ce document décrit l'état réel du code, pas les intentions de conception.

---

## Résumé

Cinquième version. Deux chantiers l'occupent entièrement.

**L'intégration des ENU** — les Enveloppes Numériques Universelles, jusqu'ici absentes du code, sont posées et branchées de bout en bout. Une couche applicative neuve, le **Scribe**, tient une arborescence d'enveloppes signées qui référence, nomme et organise les blobs du nœud. Elle est pilotable depuis la TUI : un dossier est rempli puis refermé pour déposer, l'arborescence est matérialisée sur le disque pour retirer. Le noyau accompagne le mouvement — type `Braise`, API recentrée sur l'index, blobs désignés par leur seul hash.

**Les tests** — le code n'en comportait aucun. Il en compte 61, **intégrés aux crates** plutôt que rangés dans un dossier `tests/` externe : 24 pour `feu-noyau`, 37 pour `feu-application`, du format canonique d'une carte au cycle de vie complet du nœud.

La cryptographie ne bouge pas : ML-DSA-87, ML-KEM-1024, HKDF-SHA3-256, AES-256-GCM, SHA3-256, Argon2id. Toujours aucun réseau, aucun IdNU, aucune condition, aucun relais, aucun paquet.

---

## Périmètre

**Ce qui change en v0.0.5 :**

- **ENU** — enveloppe signée `Enu` + carte `Carte` (Donnée, Texte, Répertoire), content-addressed, sérialisation maison, signature ML-DSA-87 sur la carte. Exposées en lecture seule.
- **Arborescence ENU** — racines signées par le nœud (`BRAISE_VIDE`), chaînées par la méta `_racine`, sommet courant désigné par le symlink `.DERNIERE_RACINE`, posé à la genèse.
- **Comptoir de dépôt** — dossier OS ouvert puis refermé ; contenu rangé en blobs + ENU, greffé sous la racine du nœud.
- **Retrait en lecture seule** — matérialisation de l'arborescence d'une ENUr dans un dossier OS, sans reprise.
- **Accès aux blobs par l'ENU** — chargement, suppression, existence, informations, sans désigner ni foyer ni classeur.
- **`Braise`** — newtype `Braise([u8; 55])` dans `feu-noyau`, remplace la `String` partout ; `BRAISE_VIDE` désigne le signataire nœud et sert de valeur d'initialisation.
- **API du noyau** — recentrée sur l'index ; blobs renommés (`depot_blob`, `lecture_blob`, `suppression_blob`, `existence_blob`, `informations_blob`), le dépôt rend `(hash, classeur)` et garantit l'unicité d'un hash dans le foyer.
- **Chemin racine injecté** — le binaire lit `$HOME`, toutes les couches en aval reçoivent le chemin en paramètre.
- **Diagnostic** — deux nouvelles anomalies (`ArchiveIntermediaireResiduelle`, `FoyerClairEtArchive`), quatre contrôles par foyer.
- **Correctifs** — nettoyage des archives `.tar`/`.feu` résiduelles sur les chemins d'erreur d'ouverture/fermeture ; dossier de foyer créé en 0o700 ; clé publique du nœud propagée à la genèse.
- **TUI** — comptoir de dépôt (`d` ouvre depuis un classeur, `c` ferme), retrait de la dernière racine (`r`).
- **Tests** — 61 tests là où il n'y en avait aucun, en `#[cfg(test)] mod tests` dans les crates ; `tempfile` et `rand` en dépendances de test.

**Ce qui reste inchangé depuis la v0.0.4 :**

- Cryptographie : ML-DSA-87 (signature), ML-KEM-1024 (chiffrement asymétrique), HKDF-SHA3-256 (dérivation), AES-256-GCM, SHA3-256, Argon2id. Labels de dérivation, tailles, formats de clés identiques.
- Gardien / Cryptographe / Archiviste — mêmes responsabilités.
- Cycle de vie nœud et foyer (initialisation, allumage, ouverture, fermeture, archivage chiffré, secours).
- Structure disque des foyers (classeurs, registre, archives `.feu`, `config.feu`).
- Écran « à propos » (`!`), navigation TUI, table de commandes contextuelle.

**Ce qui n'existe pas :**

- Réseau (Tor, gossip protocol).
- IdNU, conditions, registre de conditions, relais, paquets.
- Itérateurs ENU (descendant, remontant) — la navigation programmatique de l'arborescence n'est pas exposée.
- Désignation d'un dossier de dépôt ou de retrait par l'utilisateur — les deux chemins sont en dur dans le binaire.
- Vérification préalable des foyers requis avant un retrait — l'échec survient en cours d'écriture.
- Ménage des versions d'ENU abandonnées (`Enu::supprimer` n'a pas d'appelant de production).
- Export/import de classeurs, révocation de foyer.

---

## Architecture

Trois crates, empilées en couches strictes. Chaque couche ne connaît que celle immédiatement en dessous.

```
┌────────────────────────────────────────────┐
│  feu-tui        présentation (TUI Ratatui)  │  binaire, deux threads
├────────────────────────────────────────────┤
│  feu-application  orchestration applicative │  unique consommateur du noyau
│                   + Scribe (couche ENU)     │
├────────────────────────────────────────────┤
│  feu-noyau        cœur du protocole         │  Gardien · Cryptographe · Archiviste
└────────────────────────────────────────────┘
```

- **`feu-noyau`** expose la structure `FeuNoyau`. Aucun composant interne n'est accessible de l'extérieur.
- **`feu-application`** est l'**unique** consommateur de `feu-noyau`. Elle héberge désormais le **Scribe**, tenant de la couche ENU.
- **`feu-tui`** est un binaire qui consomme `feu-application`.

### Le noyau — composants internes

`FeuNoyau` orchestre trois composants, dont la répartition ne change pas :

- **Gardien** — unique point d'accès au système de fichiers. Délègue la connaissance de l'arborescence à son `Carnet`, maintient la `Configuration` en mémoire (miroir de `config.feu`).
- **Cryptographe** — unique composant autorisé à manipuler des données en clair. Maintient les clés déchiffrées dans son `Trousseau`, et leur représentation persistable — secrets chiffrés, clés publiques en clair — dans ses trousseaux publics, seule forme que le Gardien écrit sur le disque.
- **Archiviste** — un par foyer ouvert, gère l'arborescence interne d'un foyer (registre + classeurs). Ne détient jamais de clés, ne voit jamais d'octets en clair. Transfert des blobs via le **Tiroir** (zéroïsation).

### Le Scribe — nouvelle couche applicative

Le **Scribe** (`feu-application/src/scribe/`) est le tenant de la couche ENU. Il crée et maintient le dossier `~/.feu/enu/` — à la racine du nœud, pas dans un foyer, pour que les ENU restent navigables même foyers fermés (elles sont en clair, leur intégrité est garantie par la signature, pas par le chiffrement). Il est activé à l'allumage et désactivé à l'extinction.

Il fait la charnière entre deux mondes qui s'ignorent : **le noyau ne sait pas ce qu'est une ENU, le Scribe ne sait pas ce qu'est un foyer**. Une ENU est traduite en ce que le noyau attend (index de foyer + empreinte de blob), et inversement.

Un nœud ne contient que deux sortes de fichiers : les **ENU**, tenues par le Scribe, et les **blobs**, tenus par le noyau dans les classeurs.

---

## `feu-noyau`

### `InterfaceFeuNoyau`

Contrat entre le noyau et son appelant direct (`feu-application`). Sept méthodes ; les adresses `.braise` y sont désormais portées par le type `Braise` :

| Méthode | Rôle |
|---|---|
| `demander_mdp` | Collecte d'un mot de passe masqué (`Option<SecretString>`) |
| `recevoir_seed` | Transmet les mots de la seed BIP39 à l'initialisation, avant zéroïsation |
| `confirmer_enregistrement_seed` | Demande confirmation que la seed est enregistrée ; `false` interrompt l'init |
| `recevoir_braise_foyer` | Notifie la braise d'un foyer (`Braise`) |
| `recevoir_etat_foyer` | Notifie un changement d'état d'ouverture d'un foyer |
| `recevoir_cle_publique_noeud` | Notifie la clé publique ML-DSA-87 du nœud à l'allumage (2 592 o) |
| `recevoir_cles_publiques_foyer` | Notifie les clés ML-DSA-87 (2 592 o) + ML-KEM-1024 (1 568 o) d'un foyer à son ouverture |

### API publique de `FeuNoyau`

| Méthode | Rôle | Mutabilité |
|---|---|---|
| `new` | Initialise ou allume le nœud | associée |
| `demarrage_secours` | Répare l'arborescence depuis une seed | associée |
| `changement_mdp` | Change le mot de passe et rechiffre le trousseau (tous foyers ouverts) | `&mut self` |
| `ouverture_foyer` | Déchiffre l'archive, charge les clés, instancie l'Archiviste | `&mut self` |
| `fermeture_foyer` | Archive, chiffre, détruit l'Archiviste, supprime le dossier clair | `&mut self` |
| `secours_fermeture_foyer` | Ferme un foyer resté ouvert après arrêt anormal | `&mut self` |
| `depot_blob` | Stocke un blob (unicité dans le foyer), rend `(hash, classeur)` | `&mut self` |
| `lecture_blob` | Déchiffre un blob vers une destination, classeur découvert par balayage | `&mut self` |
| `suppression_blob` | Supprime un blob, classeur découvert par balayage | `&self` |
| `liste_blobs` | Liste les hashes d'un classeur | `&self` |
| `existence_blob` | Teste l'existence d'un blob, quel qu'en soit le classeur | `&self` |
| `informations_blob` | Métadonnées système d'un blob (`DonneesBlob`) | `&self` |
| `chiffrement_asymetrique` | ML-KEM-1024 + HKDF + AES-256-GCM | `&self` |
| `dechiffrement_asymetrique` | Déchiffre un message KEM (foyer ouvert) | `&self` |
| `signature_noeud` | Signe avec la clé du nœud (4 627 o) | `&self` |
| `signature_foyer` | Signe avec la clé d'un foyer ouvert (4 627 o) | `&self` |
| `verification_signature` | Vérifie une signature ML-DSA-87 | associée |
| `creation_empreinte` | SHA3-256 d'octets — exposée pour la couche ENU | associée |
| `diagnostic_noeud` | Diagnostic de présence des fichiers du nœud, **sans** `Result` | associée |
| `diagnostic_foyer` | Diagnostic d'un foyer ouvert | `&self` |

Les blobs sont désormais désignés **par leur hash seul**, le classeur étant découvert par balayage : `depot_blob`, `lecture_blob`, `suppression_blob`, `existence_blob` et `informations_blob` ne prennent plus d'`index_classeur` là où il n'est pas indispensable. Cette évolution accompagne l'ENU, qui référence une donnée par le couple `(foyer, hash)` — le classeur n'y figure pas. `depot_blob` garantit en contrepartie l'**unicité d'un hash dans un foyer** : il balaie avant d'écrire et, si le blob existe déjà, rend le classeur réel sans rien dupliquer.

`diagnostic_noeud` rend désormais un `Vec<Anomalie>` et ne peut pas échouer. Deux variantes s'ajoutent à `Anomalie` :

- `ArchiveIntermediaireResiduelle(PathBuf)` — un `.tar` subsiste au repos, signe d'une ouverture/fermeture interrompue ;
- `FoyerClairEtArchive(PathBuf)` — un foyer existe à la fois en clair et en `.feu` ; l'archive est complète, le clair se supprime.

### Contraintes d'état

Préconditions vérifiées avant tout effet :
- `changement_mdp` : tous les foyers ouverts.
- `ouverture_foyer` : index valide, foyer non déjà ouvert.
- `fermeture_foyer` / `secours_fermeture_foyer` : foyer ouvert / diagnostic sans anomalie.
- Blobs : foyer ouvert ; `depot_blob` exige en outre un `index_classeur` valide.
- `dechiffrement_asymetrique`, `signature_foyer` : foyer ouvert. `chiffrement_asymetrique`, `signature_noeud` : nœud allumé.

Un `Drop` sur `FeuNoyau` **panique** si des foyers sont encore ouverts à la destruction.

---

## `feu-application`

### La couche ENU

#### `Enu` — l'enveloppe

```
Enu {
    braise: Braise,             // signataire (foyer) ou BRAISE_VIDE (nœud)
    hash_carte: [u8; 32],       // SHA3-256 de la carte sérialisée
    signature_carte: [u8; 4627],// ML-DSA-87 de la carte sérialisée
    date: u64,                  // timestamp Unix
    carte: Carte,
}
```

Le hash et la signature couvrent **uniquement la carte sérialisée**, jamais la braise ni la date — qui restent des métadonnées malléables (routage, horodatage indicatif). Deux signataires possibles : un **foyer** (ENU de contenu, braise du foyer) ou le **nœud** lui-même (`BRAISE_VIDE`, réservée aux racines de l'arborescence).

Le **modèle de confiance** est porté par le chargement : `Enu::charger` relit l'enveloppe depuis le disque puis vérifie, selon la braise annoncée, la signature contre la clé publique du nœud ou du foyer, **et** que le hash recalculé de la carte égale le `hash_carte` stocké. La braise restant hors signature, la falsifier ne peut que router vers la mauvaise clé et faire **échouer** la vérification — jamais faire accepter une ENU.

`Enu` est exposé **en lecture seule** : champs privés, accesseurs publics, constructeurs `pub(super)`. Construire une enveloppe depuis l'extérieur est impossible ; une `Enu` venue de l'extérieur a nécessairement transité par `Enu::charger`, qui garantit son intégrité.

#### `Carte` — le contenu

Trois variantes, chacune portant des métadonnées structurées (`BTreeMap<String, String>`) et des tags libres (`BTreeSet<String>`), collections à ordre déterministe pour le hash :

| Variante | Champs propres | Rôle |
|---|---|---|
| `Donnee` (CaD) | `hash_donnee: [u8; 32]` | référence un blob par l'empreinte de son clair — jamais par son classeur |
| `Texte` (CaT) | `contenu: String` | texte brut embarqué, borné à 60 kio, nommé par la méta `"nom"` |
| `Repertoire` (CaR) | `hashs_enu: BTreeSet<[u8; 32]>` | référence ses enfants par leur `hash_carte` |

Une enveloppe prend le nom de sa carte : **ENUd** pour une donnée, **ENUt** pour un texte, **ENUr** pour un répertoire. Les messages d'erreur du code emploient la graphie `EnuD` / `EnuT` / `EnuR` (`SCR-003 > Ce doit être une EnuR`).

`Carte` est l'inverse d'`Enu` : un `enum` public dont les variantes exposent leurs champs. C'est ce qui permet à un consommateur de descendre l'arborescence en lisant les `hashs_enu` d'une `Carte::Repertoire`. La confiance ne vient pas de l'encapsulation mais de la vérification de la signature à chaque chargement.

#### Sérialisation

Format maison, sans crate, en deux passes. L'**enveloppe** s'écrit : `braise` (62 o UTF-8) · `hash_carte` (32 o) · `signature_carte` (4 627 o) · `date` (u64 BE) · carte. La **carte** s'écrit : discriminant `u8` (0x00 CaD, 0x01 CaT, 0x02 CaR) · métadonnées · tags · champs propres (hash 32 o pour CaD ; `u64` longueur + UTF-8 pour CaT ; `u32` nombre + 32 o × n pour CaR). La sérialisation est déterministe : même carte → mêmes octets → même hash.

#### Persistance et arborescence

- **Content-addressing** — le nom du fichier est le hash hexadécimal de la carte : `~/.feu/enu/<hash_hex>.enu`. Une carte donnée vise toujours le même fichier. `Enu::sauvegarder` est **idempotent** : si le fichier existe, rien n'est réécrit — un contenu identique n'est stocké qu'une fois et peut être référencé par autant d'ENU que nécessaire.
- **Racines** — le sommet de l'arborescence est signé par le **nœud** (`BRAISE_VIDE`), jamais par un foyer. `Enu::new_racine` pose la méta `_racine` (hash de la racine précédente, ou `""` à la genèse) puis repointe atomiquement le symlink `.DERNIERE_RACINE` (lien temporaire puis `rename`, cible relative au nom de fichier). À la toute première activation, une racine origine est forgée.
- **`Enu::remplacer`** — un « chercher-remplacer » par hash dans l'arborescence courante : substitue une ENU, reconstruit les répertoires du chemin cible → racine (re-signés sous leur braise pour les répertoires de contenu, signés nœud pour le sommet), puis pose un nouveau sommet. Les anciens sommets et répertoires sont **conservés** — ce sont les versions précédentes de la lignée `_racine`. `Enu::supprimer` existe mais n'a pas d'appelant de production (futur ménage).

### Le Scribe — opérations

| Fonction | Rôle |
|---|---|
| `activation` / `desactivation` | Crée `enu/` (0o700) et amorce la genèse au premier allumage ; oublie les comptoirs à l'extinction |
| `derniere_enu_racine` | Charge le sommet courant en suivant `.DERNIERE_RACINE` |
| `charge_enu` | Charge l'ENU de `hash` — `None` si absente |
| `ouverture_comptoir_depot` / `fermeture_comptoir_depot` | Ouvre/ferme un comptoir de dépôt |
| `depot_enu_texte` | Dépose un texte (ENUt) dans un foyer |
| `retrait_lecture_seule` | Matérialise l'arborescence d'une ENUr dans un dossier OS |
| `charge_blob` / `supprime_blob` / `existence_blob` / `informations_blob` | Accès aux blobs par l'ENU |

**Comptoir de dépôt.** `ouverture_comptoir_depot` crée le dossier, valide les index foyer/classeur, l'enregistre et l'inscrit dans la session. `fermeture_comptoir_depot` parcourt le dossier **bottom-up** (`walkdir`) : chaque fichier est déposé via `FeuNoyau::depot_blob` puis enveloppé dans une `Carte::Donnee` signée ; chaque répertoire devient une `Carte::Repertoire` référençant ses enfants. Le nom de chaque entrée est conservé en méta `"nom"`. Les nouvelles ENU sont greffées sous une racine de dépôt (`greffe_enfants`), et la modification remonte jusqu'à un nouveau sommet du nœud. Le dossier du comptoir est supprimé à la fin ; un comptoir vide laisse la racine inchangée.

Le **classeur demandé n'est pas garanti** : si la donnée existe déjà ailleurs dans le foyer, le noyau l'y laisse et l'ENU reste valable (elle référence un hash, pas un emplacement) — mais l'écart n'est remonté nulle part.

**Retrait.** `retrait_lecture_seule` crée le dossier de sortie (qui ne doit pas exister) puis reconstruit récursivement ce que décrit l'ENUr : chaque `Donnee` redevient un fichier (blob déchiffré), chaque `Texte` un fichier portant son contenu, chaque `Repertoire` un sous-dossier. Chaque enfant est chargé **et authentifié** avant d'être écrit. Le nom est validé comme composant de chemin (`nom_fichier`), et deux homonymes coexistent par suffixage (`chemin_libre`). Tout foyer signataire d'une `Donnee` rencontrée doit être ouvert.

### `SessionApplication`

La session porte désormais l'état utile à la présentation : capacités du noyau, braises et états des foyers, clés publiques, et les **comptoirs de dépôt ouverts** (`BTreeSet<usize>`, miroir de ce que le Scribe détient). Les accesseurs indexés rendent des `Option` — un index hors bornes est une absence, pas une erreur. S'ajoutent `nombre_foyers_ouverts` et `foyers_fermes`, lus par la TUI pour filtrer les commandes.

### `InterfaceFeuApplication`

Contrat entre `feu-application` et sa couche de présentation, symétrique d'`InterfaceFeuNoyau`. Quatre méthodes, toutes en `&self` : `demander_mdp`, `recevoir_seed`, `confirmer_enregistrement_seed`, et `recevoir_session_application` — cette dernière appelée une seule fois par commande mutante, la session dans un état cohérent, jamais depuis un setter. En interne, un `RecepteurNoyau` éphémère (privé) fait le pont vers le noyau le temps d'un appel : il délègue les interactions bloquantes à l'interface et écrit lui-même les notifications d'état dans la session.

### Commandes

Réordonnées en cinq parties (foyer, cryptographie, dépôt-retrait, blobs, ENU). La précondition commune est l'allumage : hors `commande_allumage_noeud`, `commande_verification_signature` et `commande_diagnostic_noeud`, toute commande rend `ErreurFeuApplication::NoeudEteint` nœud éteint.

| Commande | Rôle |
|---|---|
| `commande_allumage_noeud` / `commande_extinction_noeud` | Initialise/allume puis éteint le nœud |
| `commande_changement_mdp` | Change le mot de passe |
| `commande_ouverture_foyer` / `commande_fermeture_foyer` / `commande_secours_fermeture_foyer` | Cycle des foyers |
| `commande_diagnostic_noeud` / `commande_diagnostic_foyer` | Diagnostics |
| `commande_chiffrement_asymetrique` / `commande_dechiffrement_asymetrique` | ML-KEM-1024 |
| `commande_signature_noeud` / `commande_signature_foyer` / `commande_verification_signature` | Signatures ML-DSA-87 |
| `commande_ouverture_comptoir_depot` / `commande_fermeture_comptoir_depot` | Comptoir de dépôt |
| `commande_retrait_lecture_seule` | Retrait sur disque |
| `commande_chargement_blob` / `commande_suppression_blob` / `commande_existence_blob` / `commande_informations_blob` | Blobs, par l'ENU seule |
| `commande_derniere_enu_racine` / `commande_chargement_enu` | Sommet et descente de l'arborescence |
| `commande_depot_enu_texte` | Dépôt d'un texte court (ENUt) |

Chaque commande qui mute la session notifie la présentation via `recevoir_session_application(Option<SessionApplication>)` — `Some(session)` après mutation, `None` à l'extinction.

---

## `feu-tui`

Interface terminal sur Ratatui et crossterm. **Deux threads** : le principal tient la boucle TUI, le second pilote `FeuApplication`. Ils communiquent par deux canaux `mpsc` typés (`MessageTuiCoeur`, `MessageCoeurTui`) créés dans `main.rs` et confiés à deux connecteurs. Une panique du thread cœur sort en code 1 ; le terminal est restauré par le guard de `ratatui::run`.

La table de commandes contextuelle (`CommandesActives`) s'enrichit de trois gestes :

- **`d`** — ouvre un comptoir de dépôt depuis le classeur courant (foyer et classeur capturés de la position courante, chemin en dur `CHEMIN_COMPTOIR_DEPOT`). Active tant qu'aucun comptoir n'est ouvert.
- **`c`** — ferme le comptoir ouvert. Prend la place de `d` dans la table dès qu'un comptoir l'est.
- **`r`** — retire la dernière racine sur le disque (`CHEMIN_COMPTOIR_RETRAIT`, en dur). Active dès que le nœud est allumé.

Les comptoirs ouverts sont lus dans la session, plus dans un état TUI local : la TUI ne retient rien entre deux envois. `r` est la seule entorse au filtrage strict — elle est active sans que la table vérifie les foyers requis, faute d'itérateur pour les dresser ; l'échec remonte en erreur.

Quatre écrans, inchangés : `Normal` (carré à angles droits), `SaisieMdp` (cadre orange arrondi, mot de passe masqué), `AffichageSeed` (mots en trois colonnes), `AffichageInformation` (message générique — l'écran « à propos » sur `!`).

Le binaire (`main.rs`) est le seul point de lecture de `$HOME` : le chemin racine est résolu au bord du programme puis injecté vers l'application, le noyau et le Scribe.

---

## Gestion d'erreurs

Une chaîne de conversion `From` par couche. Chaque couche encapsule l'erreur de la couche inférieure dans une `String` — le type interne est perdu, seul le message textuel remonte. La couche ENU ajoute un maillon.

| Type | Crate | Préfixe | Variantes notables |
|---|---|---|---|
| `ErreurFeuNoyau` | `feu-noyau` | `NOY >` | `Gardien`, `Cryptographe`, `Archiviste` (String) ; `IndexInvalide`, `FoyerFerme`, `TousFoyersNonOuverts`, `BraiseIntrouvable`, `BraiseTryFromStr`, `BlobIntrouvable`, `TailleMaxDepassee`, … |
| `ErreurScribe` | `feu-application` (interne) | `SCR >` | `Interne(String)`, `FeuNoyau(String)`, `IoError` |
| `ErreurFeuApplication` | `feu-application` | `APP >` | `FeuNoyau(String)`, `Scribe(String)`, `NoeudEteint`, `AuMoinsUnFoyerOuvert` |

Les refus du Scribe voyagent dans la chaîne, pas dans le type, sous des codes documentés : `ENU-NNN` (`scribe/enu.rs`), `SCR-NNN` (`scribe.rs`), et l'unique `COM_D-001` (`scribe/comptoir.rs`, dossier de comptoir déjà présent). Codes notables :

| Code | Sens |
|---|---|
| `ENU-003` | ENU non authentifiable (signataire inconnu, signature ou hash invalides) |
| `ENU-004` | carte ciblée non répertoire |
| `ENU-006` / `ENU-009` | texte trop long / nom refusé comme composant de chemin |
| `ENU-008` | méta `"nom"` absente |
| `SCR-001` / `SCR-007` / `SCR-008` | comptoir invalide / dossier disparu / foyer fermé |
| `SCR-002` / `SCR-003` | dossier de retrait déjà présent / racine non répertoire |
| `SCR-004` / `SCR-005` | braise inconnue / carte non donnée |
| `SCR-006` / `SCR-009` | index foyer / classeur hors bornes |

Seul `SCR-008` laisse retenter la fermeture du comptoir ; tout autre échec le consomme et laisse le dossier à l'utilisateur.

---

## Tests

61 tests, tous **intégrés aux crates** en `#[cfg(test)] mod tests`. Le dossier `tests/` externe a été écarté : l'essentiel des cibles utiles est `pub(super)` ou `pub(crate)` — `Enu::sauvegarder`, `Enu::charger`, les fonctions du Scribe — donc invisible depuis un crate de test séparé.

| Emplacement | Nb | Objet |
|---|---|---|
| `feu-noyau/src/tests.rs` | 7 | Cycles de vie du nœud par le contrat public : allumage, mot de passe, erreurs d'usage, fermeture en secours, démarrage depuis la seed, diagnostic, panique du `Drop` foyer ouvert |
| `feu-noyau/src/braise.rs` | 9 | `TryFrom<&str>` : réciprocité, suffixe, longueur, alphabet BASE32 |
| `feu-noyau/src/cryptographe/trousseau.rs` | 5 | Déterminisme de la dérivation, distinction des clés, cycle de chiffrement, mauvais mot de passe |
| `feu-noyau/src/cryptographe.rs` | 2 | Cycles signature/vérification et chiffrement/déchiffrement asymétrique |
| `feu-noyau/src/gardien.rs` | 1 | Cycle de `config.feu` |
| `feu-application/src/tests.rs` | 6 | La crate par ses seules `commande_*` : cycle applicatif, persistance à travers extinction/rallumage, vie d'un blob, comptoir, dépôt→retrait, ENU texte |
| `feu-application/src/scribe/tests.rs` | 9 | Ce qui exige une pile réelle : cycle disque d'une ENU, falsification de signature et de braise, cycle de racine, remplacements, greffe |
| `feu-application/src/scribe/enu.rs` | 20 | Sérialisation canonique (octets attendus, aller-retour) et gardes de forme des cartes |
| `feu-application/src/session.rs` | 1 | Comptage des états de foyers |
| `feu-application/src/scribe/comptoir.rs` | 1 | Cycle de vie disque d'un comptoir |

**Trois étages.** `src/tests.rs` éprouve la crate depuis son contrat public, comme le fait son consommateur réel. `scribe/tests.rs` garde ce que le contrat public n'atteindrait qu'en se bâtissant un décor exprès — l'enveloppe et sa signature, la barrière de confiance de `charger`, la tenue de l'arborescence. Les `mod tests` en ligne prennent ce qui se prouve sans monter de pile. **Le critère est la pile, pas la visibilité** : dès qu'un test exige un noyau allumé et un foyer ouvert, il quitte le module en ligne. À décor égal, le test du haut prend tout — il prouve en plus le câblage ; deux tests du Scribe sont remontés à ce titre.

Les tests d'intégration montent une pile réelle : noyau allumé depuis une seed neuve dans un `TempDir`, foyer ouvert, Scribe activé, l'interface de la couche (`InterfaceFeuNoyau` ou `InterfaceFeuApplication`) implémentée par un `InterfaceTest` qui collecte les notifications. Aucun mock de la cryptographie ni du disque.

`feu-tui` n'a aucun test — la présentation reste éprouvée à la main.

---

## Cryptographie

Aucune primitive ne change en v0.0.5. La cryptographie est purement post-quantique côté asymétrique ; les primitives symétriques et de hachage (AES-256-GCM, SHA3-256, Argon2id) restent en place, leur sécurité effective post-Grover étant jugée suffisante (~128 bits).

### Mode logiciel

La seed et les clés dérivées existent exclusivement en mémoire. La seed est zéroïsée après dérivation. Rien n'est jamais stocké en clair sur le disque. Ce mode logiciel est un substitut temporaire au dispositif matériel cible.

### Dérivation des clés

La seed BIP39 (24 mots, 256 bits d'entropie étalés sur 64 o, dictionnaire français) est la racine absolue. **Une seule primitive** (`derive_depuis_seed`) produit, de manière **déterministe** par HKDF-SHA3-256, tout matériau dont le protocole a besoin. Chaque clé descend **directement** de la seed, isolée par un **label unique** passé en `info` HKDF — aucune clé mère intermédiaire, aucune collision possible.

```
seed master (64 o)
   └─ HKDF-SHA3-256(IKM = seed, salt = ∅, info = label) → graine → keygen
```

HKDF est appelé avec `salt = None` (sel zéro de 32 octets, RFC 5869 §2.2). La séparation de domaine est entièrement portée par le paramètre `info`.

**Arbre des labels** — grammaire uniforme `feu/<portée>/<rôle>[/index…]`, séparateur `/` :

```
Nœud
  ├─ sel Argon2id           "feu/noeud/sel"                   → 16 o bruts
  └─ signature              "feu/noeud/signature"             → ML-DSA-87

Foyer i (i = position + 1, position = 0..MAX_FOYERS, donc i = 1..3)
  ├─ braise (identifiant)   "feu/foyer/braise/{i}"            → 32 o bruts
  ├─ signature              "feu/foyer/signature/{i}"         → ML-DSA-87
  ├─ symétrique foyer       "feu/foyer/symetrique/{i}"        → AES-256-GCM
  └─ chiffrement            "feu/foyer/chiffrement/{i}"       → ML-KEM-1024

Classeur j du foyer i (j = 1..5)
  └─ symétrique classeur    "feu/classeur/symetrique/{i}/{j}" → AES-256-GCM
```

Les labels font partie du format persistant : les modifier rend tous les trousseaux existants définitivement illisibles.

**Graine et keygen.** La graine fait 32 o (`derive_depuis_seed::<32>`), sauf pour la paire ML-KEM-1024 dont la seed fait 64 o et le sel Argon2id qui fait 16 o. Keygen : `SigningKey::<MlDsa87>::from_seed` pour la signature, `DecapsulationKey1024::from_seed` pour le chiffrement, clé AES-256-GCM directe pour le symétrique, octets bruts pour le sel et la braise (non secrets).

### Sel Argon2id

Dérivé de façon déterministe depuis la seed par HKDF-SHA3-256, label `feu/noeud/sel`. 16 octets, stockés en clair — toujours recalculable depuis la seed, jamais dépendant d'une clé.

### Protection des clés au repos

Argon2id(mot de passe, sel) → clé éphémère AES-256-GCM (32 o). Toutes les clés privées et symétriques sont chiffrées avec cette clé éphémère. La clé éphémère et le mot de passe sont zéroïsés dès le trousseau constitué.

Paramètres Argon2id effectifs (défauts de la crate, conformes aux recommandations minimales RFC 9106) : m_cost 19 456 KiB, t_cost 2 itérations, p_cost 1 thread.

### Signature ML-DSA-87

Signature purement post-quantique (FIPS 204, niveau 5 ≈ AES-256). Deux niveaux :

- **Nœud** (label `feu/noeud/signature`) — clé racine, signe les actes engageant le nœud dans sa globalité : les **racines de l'arborescence ENU** en v0.0.5.
- **Foyer** (label `feu/foyer/signature/{i}`) — authentifie ce qui appartient au foyer : les **ENU de contenu**.

La signature est **déterministe** avec l'implémentation `ml-dsa` 0.1 — pour une même clé et un même message, la signature est identique. Le protocole ne s'appuie pas sur ce déterminisme (le sel en a été découplé précisément pour cette raison).

Tailles : seed privée 32 o (stockée chiffrée : 60 o), clé publique 2 592 o, signature 4 627 o. Données limitées à `MAX_TAILLE_SIGNATURE` (64 Kio) — réservé aux structures légères, ce que respecte la carte d'une ENU.

### Chiffrement asymétrique ML-KEM-1024

Schéma **KEM + HKDF + AES-256-GCM** purement post-quantique (FIPS 203, niveau 5). ML-KEM-1024 est un mécanisme d'encapsulation de clé, pas un chiffrement de message direct. Côté émetteur :

1. Reconstruit la clé publique ML-KEM-1024 depuis les 1 568 octets.
2. **Encapsulation** → ciphertext KEM (1 568 o) + secret partagé (32 o).
3. Dérive une clé AES-256-GCM via HKDF-SHA3-256 sur le secret partagé (`info = "feu-chiffrement-asymetrique"`).
4. Chiffre le message avec AES-256-GCM (nonce aléatoire de 12 o).
5. Zéroïse le secret partagé et la clé dérivée.

Côté destinataire, la **décapsulation** avec la clé privée retrouve le secret partagé.

**Format de l'enveloppe asymétrique :**

```
[0..1568]    ciphertext ML-KEM-1024 (1 568 o)
[1568..1580] nonce AES-GCM (12 o)
[1580..]     ciphertext + auth tag (16 o)
```

Soit un surcoût fixe de **1 596 o**. Tailles : seed privée 64 o (stockée chiffrée : 92 o), clé publique 1 568 o. Données limitées à `MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE` (1 Mio) — l'intégralité du message est en mémoire ; la vérification amont borne à `MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE + 1596` côté déchiffrement.

Cette primitive attend le réseau : elle est exposée par le noyau et pilotée par une commande, mais aucun écran de la TUI ne l'appelle.

### Braise — identité du foyer

La **braise** est l'identifiant public et invariant d'un foyer, dérivé directement de la seed par HKDF-SHA3-256 avec le label `feu/foyer/braise/{i}`, **indépendamment de toute clé cryptographique** : elle survit à toute migration de primitive.

**Encodage de l'adresse `.braise` :**

```
checksum = SHA3-256("feu/braise/checksum" || braise)[..2]        (2 o)
adresse  = BASE32_NOPAD(braise || checksum).to_lowercase() + ".braise"
```

- **Checksum (2 o)** — détecte une faute de frappe. Le préfixe de domaine empêche le checksum d'être valide hors de ce contexte.
- **BASE32_NOPAD** — alphabet `a-z2-7`, sans padding : l'adresse est utilisable telle quelle comme nom de dossier. 34 o → 55 caractères.
- **Suffixe `.braise`** — marqueur de type. Adresse finale : 62 caractères.

La braise est l'identifiant du foyer de bout en bout : clé de `config.feu`, nom du dossier `~/.feu/<braise>/`, nom des archives `<braise>.feu` et `<braise>.tar`, signataire annoncé d'une ENU.

**Nouveauté v0.0.5 :** elle est portée par le newtype `Braise([u8; 55])`, qui stocke les 55 caractères BASE32 sans le suffixe (réintroduit par `Display`) et ne peut naître que d'une chaîne validée par `TryFrom<&str>` — longueur, alphabet, suffixe. La `String` a disparu de toutes les signatures. `BRAISE_VIDE` (55 fois `a`) désigne le signataire nœud et sert de valeur d'initialisation des tableaux de braises — session neuve, configuration avant lecture. **Aucun foyer réel ne la porte**, et c'est précisément ce qui permet de l'employer comme aiguillage de vérification : une ENU qui l'annonce est vérifiée contre la clé du nœud.

### Chiffrement symétrique des blobs

Chaque classeur possède sa propre clé AES-256-GCM (32 o), dérivée et stockée chiffrée sur le disque. Le chiffrement d'un blob produit `nonce (12 o) || ciphertext || auth tag (16 o)`. Le hash SHA3-256 est calculé sur le clair **avant** chiffrement — il sert d'identifiant content-addressable, et c'est lui que porte une `Carte::Donnee`.

### Double chiffrement

Un blob est protégé par deux couches :

1. **Chiffrement classeur** (foyer ouvert) — AES-256-GCM avec clé dédiée au classeur. Permanent.
2. **Chiffrement archive** (foyer fermé) — AES-256-GCM-stream avec clé symétrique du foyer. Le dossier entier du foyer est compressé en tar puis chiffré en `.feu`.

Les ENU ne sont couvertes par aucune des deux : elles vivent en clair hors des foyers, leur intégrité venant de la signature.

### Zéroïsation des secrets

Deux mécanismes complémentaires :

- `SecretBox<T>` (crate `secrecy`) — wrapping explicite des secrets dont le type implémente `Zeroize`. L'accès est contraint à `expose_secret()` / `expose_secret_mut()`.
- `ZeroizeOnDrop` (crate `zeroize`) — pour `SigningKey<MlDsa87>` et `DecapsulationKey1024`, dont les types n'implémentent pas `Zeroize`.

Le Tiroir zéroïse le blob en clair lors du remplacement par le blob chiffré et lors du vidage. Les features `zeroize` sont activées sur `aes-gcm`, `bip39`, `ml-dsa` et `ml-kem`.

### Séparation des fonctions cryptographiques

| Algorithme | Fonction | Usage |
|---|---|---|
| ML-DSA-87 | Signature post-quantique | Clé de nœud (racines ENU), signature du foyer (ENU de contenu) |
| ML-KEM-1024 | Encapsulation de clé post-quantique | Chiffrement asymétrique réseau |
| AES-256-GCM | Chiffrement symétrique authentifié | Archives de foyer, protection des clés au repos, chiffrement des blobs, chiffrement KEM |
| Argon2id | Dérivation depuis mot de passe | Protection du trousseau sur le disque |
| HKDF-SHA3-256 | Dérivation de clé | Production de toutes les clés depuis la seed, dérivation de clé KEM |
| SHA3-256 | Hachage | Identifiants content-addressable des blobs et des cartes, checksum des adresses `.braise` |

---

## Structure disque

Racine : `~/.feu/`, résolue par le binaire puis injectée. Permissions : dossiers `rwx------` (0o700), fichiers `rw-------` (0o600). Toutes les écritures de fichiers de clés sont atomiques : écriture dans `<chemin>.tmp` (0o600), puis `rename` sur la cible.

La structure des foyers ne change pas ; le dossier `enu/` s'y ajoute.

### Nœud, foyers fermés

```
~/.feu/
├── config.feu                    ← configuration globale (en clair)
├── .cles/
│   ├── sel.feu                   ← sel Argon2id, 16 o (en clair)
│   ├── feu_sig.priv              ← clé privée de signature du nœud (chiffrée, 60 o)
│   ├── feu_sig.pub               ← clé publique de signature du nœud (en clair, 2 592 o)
│   ├── <braise1>.cle             ← clé symétrique d'archive foyer 1 (chiffrée, 60 o)
│   ├── <braise2>.cle             ← clé symétrique d'archive foyer 2 (chiffrée, 60 o)
│   └── <braise3>.cle             ← clé symétrique d'archive foyer 3 (chiffrée, 60 o)
├── <braise1>.feu                 ← archive chiffrée foyer 1
├── <braise2>.feu                 ← archive chiffrée foyer 2
├── <braise3>.feu                 ← archive chiffrée foyer 3
└── enu/                          ← arborescence ENU (voir plus bas)
```

### Foyer ouvert

L'archive `.feu` est absente. Le dossier est extrait à sa place (créé en 0o700 avant extraction) :

```
~/.feu/
└── <braise>/
    ├── .cles/
    │   ├── sig.priv              ← clé privée de signature du foyer (chiffrée, 60 o)
    │   ├── sig.pub               ← clé publique de signature du foyer (en clair, 2 592 o)
    │   ├── chif.priv             ← clé privée ML-KEM-1024 (chiffrée, 92 o)
    │   ├── chif.pub              ← clé publique ML-KEM-1024 (en clair, 1 568 o)
    │   └── classeur0.cle … classeur4.cle  ← clés AES-256-GCM des classeurs (chiffrées, 60 o)
    ├── registre/
    │   └── classeur.0 … classeur.4  → ../  ← liens symboliques vers la racine du foyer
    ├── classeur0/
    │   └── <hash>.dat            ← blob chiffré AES-256-GCM
    └── classeur1/ … classeur4/
```

### Arborescence ENU

```
~/.feu/enu/
├── .DERNIERE_RACINE              ← symlink vers le sommet courant (cible relative)
└── <hash_hex>.enu                ← une ENU par carte, nom = empreinte SHA3-256
```

`enu/` est créé en 0o700 à la première activation du Scribe, hors de tout foyer : les ENU restent lisibles foyers fermés. Les fichiers `.enu` sont écrits en 0o600 et jamais réécrits — le nom étant le hash, un contenu identique n'est stocké qu'une fois. Aucune ENU n'est effacée par le fonctionnement normal : les sommets et répertoires remplacés restent sur le disque, atteignables par la chaîne `_racine`. Le symlink `.DERNIERE_RACINE` est repointé atomiquement (lien temporaire puis `rename`).

### Format de `config.feu`

Fichier texte, `2 + MAX_FOYERS` lignes :

```
<version>
<prochain_index>
<adresse_braise_foyer_0>
<adresse_braise_foyer_1>
<adresse_braise_foyer_2>
```

`version` = `1`. `prochain_index` vaut `4` après initialisation (incrémenté d'une unité par foyer créé, soit 1 + 3 = 4). Il est réservé pour la révocation future d'un foyer : quand un slot est révoqué, il reçoit le prochain index de dérivation disponible, ce qui produit une nouvelle braise. Le nombre de foyers reste fixe.

### Format des clés sur disque

| Type | Taille | Structure |
|---|---|---|
| Clé privée 32 o (signature, symétrique) | 60 o | `nonce (12) ‖ ciphertext (32) ‖ tag (16)` |
| Clé privée 64 o (ML-KEM-1024 seed) | 92 o | `nonce (12) ‖ ciphertext (64) ‖ tag (16)` |
| Clé publique signature (ML-DSA-87) | 2 592 o | brute, en clair |
| Clé publique chiffrement (ML-KEM-1024) | 1 568 o | brute, en clair |
| Sel Argon2id | 16 o | brut, en clair |

Chiffrement AES-256-GCM, nonce aléatoire à chaque écriture.

### Format des blobs

Fichier `<hash>.dat` dans `classeurN/`. Contenu : `nonce (12 o) || ciphertext || auth tag (16 o)`. Le hash (nom de fichier) est le SHA3-256 en hexadécimal minuscule du blob **en clair**. Un même hash n'apparaît qu'une fois dans un foyer, tous classeurs confondus.

### Format d'une ENU sur disque

Fichier `<hash_carte_hex>.enu` dans `enu/`, en clair. Contenu : `braise (62 o UTF-8) ‖ hash_carte (32 o) ‖ signature_carte (4 627 o) ‖ date (u64 BE) ‖ carte sérialisée`. Surcoût fixe de **4 729 o** par enveloppe.

### Archive du foyer

Fermeture : dossier → `.tar` → chiffrement AES-256-GCM-stream → `.feu`. Ouverture : `.feu` → déchiffrement → `.tar` → extraction. Les archives intermédiaires `.tar` et `.feu` sont supprimées après usage, y compris **sur les chemins d'erreur** depuis la v0.0.5 ; un `.tar` résiduel au repos est signalé par le diagnostic.

**Format binaire de l'archive `.feu` :**

```
[nonce 7 o] [chunk_1] [chunk_2] ... [chunk_n]
```

Chaque chunk : `plaintext (≤ CHUNK_SIZE o) + tag AES-GCM (16 o)`. `CHUNK_SIZE = 4096`.

---

## Constantes

| Constante | Valeur | Rôle |
|---|---|---|
| `MAX_FOYERS` | 3 | Nombre de foyers par nœud |
| `MAX_CLASSEURS` | 5 | Nombre de classeurs par foyer |
| `MAX_TAILLE_BLOB` | 512 Mio | Taille maximum d'un blob en clair |
| `MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE` | 1 Mio | Taille maximum d'un message à chiffrer via ML-KEM-1024 |
| `MAX_TAILLE_SIGNATURE` | 64 Kio | Taille maximum d'un message à signer |
| `LONGUEUR_BRAISE` | 55 | Caractères BASE32 d'une braise, hors suffixe `.braise` (interne à `braise.rs`) |
| `MAX_TAILLE_TEXTE` | 60 Kio | Plafond du contenu d'une `Carte::Texte` (interne à `scribe/enu.rs`) |
| `TAILLE_CHUNK` | 8 192 o | Granularité de lecture d'un blob par le Tiroir (`pub(crate)`) |
| `NOMBRE_MOTS_SEED` | 24 | Mots de la seed BIP39 (interne au cryptographe) |
| `CHUNK_SIZE` | 4 096 o | Taille des chunks du stream AES-256-GCM des archives `.feu` (interne au cryptographe) |

---

## Plateformes supportées

Linux et macOS uniquement. Le noyau repose sur des primitives Unix (permissions `mode`, liens symboliques, `rename` atomique) et lève une erreur de compilation sur toute autre plateforme. Seul le binaire lit l'environnement, pour résoudre `$HOME`.

---

## Environnement technique

**Edition Rust :** 2024. Version `0.0.5` et licence `GPL-3.0-or-later` définies au niveau workspace. Le lint `missing_docs = "warn"` est actif sur toutes les crates.

### Dépendances `feu-noyau`

| Crate | Usage |
|---|---|
| `aes-gcm` (`std`, `zeroize`) | Chiffrement AES-256-GCM des clés, blobs et archives |
| `aead` (`stream`) | Chiffrement stream (`EncryptorBE32` / `DecryptorBE32`) |
| `argon2` (`std`) | Dérivation Argon2id depuis le mot de passe |
| `bip39` (`rand`, `french`, `zeroize`) | Génération seed BIP39, dictionnaire français |
| `ml-dsa` (`zeroize`, `getrandom`) | Signature ML-DSA-87 (FIPS 204) |
| `ml-kem` (`zeroize`, `getrandom`) | Encapsulation ML-KEM-1024 (FIPS 203) |
| `hkdf` | Dérivation HKDF-SHA3-256 |
| `sha3` | SHA3-256 (HKDF, braise, hash content-addressable) |
| `secrecy` | `SecretBox<T>` — zéroïsation automatique au `Drop` |
| `zeroize` | `Zeroize`, `ZeroizeOnDrop` |
| `tar` | Archivage/extraction des dossiers de foyer |
| `data-encoding` (`alloc`) | BASE32_NOPAD (adresses `.braise`), HEXLOWER (hashes) |
| `rand` | Génération de nonces aléatoires (`OsRng`) |
| `thiserror` | Dérivation des types d'erreur |

Dev-dépendance : `tempfile` (dossiers temporaires des tests).

### Dépendances `feu-application`

| Crate | Usage |
|---|---|
| `feu-noyau` | Dépendance locale (chemin relatif) |
| `secrecy` | `SecretString` pour le mot de passe et la phrase seed |
| `thiserror` | Dérivation de `ErreurFeuApplication` et `ErreurScribe` |
| `data-encoding` | HEXLOWER (noms de fichiers ENU, hashes de blobs) |
| `walkdir` | Parcours bottom-up du comptoir de dépôt |

Dev-dépendances : `tempfile` (dossiers temporaires), `rand` (contenus aléatoires).

### Dépendances `feu-tui`

| Crate | Usage |
|---|---|
| `feu-application` | Dépendance locale (chemin relatif) |
| `ratatui` | Rendu de l'interface terminal |
| `crossterm` | Événements clavier, gestion du terminal |
| `secrecy` | `SecretString` (mot de passe, mots de la seed) |

---

## Standards cryptographiques

| Standard | Objet |
|---|---|
| BIP39 | Seed mnémonique (24 mots, 256 bits) |
| NIST FIPS 203 | ML-KEM — Module-Lattice-based Key Encapsulation Mechanism |
| NIST FIPS 204 | ML-DSA — Module-Lattice-based Digital Signature Algorithm |
| RFC 5869 | HKDF — dérivation de clé basée sur HMAC |
| NIST FIPS 202 | SHA3-256 — Keccak |
| RFC 9106 | Argon2id — dérivation de clé depuis mot de passe |
| NIST SP 800-38D | AES-256-GCM — chiffrement authentifié |

---

## Garanties de sécurité

1. **La seed est la racine absolue** — tout dérive d'elle. En mode logiciel, elle est détruite en mémoire après dérivation. 24 mots, 256 bits d'entropie.
2. **Toutes les clés sont dérivables depuis la seed** — la perte des clés est récupérable par ressaisie de la seed. Les archives chiffrées, les blobs et les ENU doivent être sauvegardés séparément.
3. **Une clé, un usage** — ML-DSA-87 (signature), ML-KEM-1024 (chiffrement), AES-256-GCM (symétrique) sont strictement séparés. La séparation de domaine est structurelle (labels HKDF), pas conventionnelle.
4. **Résistance post-quantique** — toutes les primitives asymétriques sont de niveau NIST 5 (≈ AES-256). Les primitives symétriques conservent ~128 bits de sécurité post-Grover.
5. **Les clés en clair n'existent qu'en mémoire** — sur le disque, toutes les clés privées et symétriques sont chiffrées. Exception connue : un crash pendant la fermeture d'un foyer peut laisser un `.tar` non chiffré dans `~/.feu/` — le diagnostic le signale désormais.
6. **Gardien / Cryptographe** — le disque et le clair ne se rencontrent jamais dans le même composant.
7. **L'Archiviste ne voit jamais de clair** — uniquement des blobs chiffrés et des hashes. Le Tiroir zéroïse le blob en clair dès son remplacement par le chiffré, et à chaque vidage.
8. **Double chiffrement des blobs** — clé de classeur (permanent), puis clé d'archive du foyer (à la fermeture).
9. **Stratification stricte** — la présentation ne touche jamais le noyau : tout passe par `feu-application`.
10. **Identité stable** — la braise est indépendante de toute clé cryptographique ; elle survit à toute migration de primitive. L'adresse de transport future n'y sera pas liée : se tromper d'adresse ne coûte rien, la donnée se vérifie contre son hash et n'est lisible que par son destinataire.
11. **L'intégrité avant la lecture** — une ENU n'est jamais consommée sans que son hash soit recalculé et sa signature vérifiée contre la clé du signataire annoncé (`Enu::charger`). La désérialisation seule ne valide que la structure.
12. **La braise n'est pas une autorité** — hors hash et hors signature, elle n'est qu'un indice de routage : la falsifier fait échouer la vérification, jamais accepter une enveloppe.
13. **Le nom de fichier est borné** — toute entrée matérialisée sur disque passe par `nom_fichier_valide` (refus du vide, de `/`, de `.`/`..`) avant tout `Path::join` ; un nom lisible depuis une ENU ne peut pas faire écrire hors du dossier de retrait.
14. **Les ENU sont lisibles foyers fermés** — en clair sur disque, leur confidentialité est nulle mais leur intégrité est signée ; c'est ce qui autorise la navigation hors ouverture.
15. **Déduplication** — un même contenu (même hash de carte, même hash de blob) n'est stocké qu'une fois ; le dépôt d'un blob déjà présent ne duplique rien.
