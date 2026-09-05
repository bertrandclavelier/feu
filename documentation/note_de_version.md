# Feu — Note de version v0.0.7

> **Date :** 5 septembre 2026
> **Statut :** septième version
> **Licence :** GNU General Public License v3.0 ou ultérieure (GPL-3.0-or-later)
> **Photo technique** — ce document décrit l'état réel du code, pas les intentions de conception.

---

## Résumé

Septième version, qui ouvre le **comptoir de travail** : le sous-arbre d'une ENU répertoire est matérialisé sur le disque pour y être modifié, puis Feu le reprend et le re-dépose à la fermeture. Un verrou d'instance réserve le nœud à un seul Feu.

La cryptographie ne bouge pas : ML-DSA-87, ML-KEM-1024, HKDF-SHA3-256, AES-256-GCM, SHA3-256, Argon2id, mêmes labels de dérivation et mêmes formats de clés. Gardien, Cryptographe et Archiviste gardent leurs responsabilités ; le cycle de vie du nœud et des foyers, comme la structure disque des foyers, ne bouge pas davantage.

---

## Périmètre

**Ce que couvre la v0.0.7 :**

- **Comptoir de travail** — ouverture et fermeture côté Scribe, câblées dans la TUI sur la touche `T`, avec une ligne d'état tant qu'il est ouvert.
- **Comptoirs** — dépôts et travail réunis sous un enum `Comptoirs` dont les variantes s'excluent : l'exclusivité tient au type, sans garde à écrire. Leur état est sérialisé dans `.config/scribe.feu` et rouvert à l'allumage.
- **Index typés** — `IndexFoyer` et `IndexClasseur`, bornés par construction, remontés jusqu'à la TUI : aucune garde de bornes à l'usage, le type les tient. L'arborescence des ENU affiche le couple `foyer·classeur` de chaque entrée.
- **Hashs de blob** — portés en `[u8; 32]` dans toute l'API du noyau ; `existence_blob` rend le classeur (`Option<IndexClasseur>`).
- **ENU** — `Carte` extraite dans son module, unicité des noms d'enfants tenue au dépôt (`greffe_enfants`), date de création en méta `"date"` de la carte, version du format sérialisé (`VERSION_ENU`).
- **Scribe** — éclaté en modules d'`impl`, imports normalisés.
- **Dépendances** — cohorte RustCrypto montée (`aes-gcm` 0.11, `argon2` 0.6, `hkdf` 0.13, `sha3` 0.11, `aead` 0.6) ; le chiffrement stream déporté dans `aead-stream`.
- **Tests** — bout-en-bout du noyau et de l'application sortis en crates externes `tests/`, couverture des comptoirs.
- **Verrou d'instance** — un seul Feu à la fois sur un nœud, par un verrou consultatif posé à l'allumage.

**Ce qui n'existe pas :**

- Réseau (Tor, gossip protocol).
- IdNU, conditions, registre de conditions, relais, paquets.
- Export/import de classeurs, révocation de foyer.
- Modification des tags et des ENU texte depuis la TUI.
- Rafraîchissement automatique des arborescences affichées : le chargement (`R`) reste explicite. La fermeture d'un comptoir de dépôt vide l'arbre des ENU et la marque plutôt que de les rafraîchir ; celle du comptoir de travail les laisse en l'état, bien qu'elle change la racine tout autant. L'arborescence du disque, elle, ne suit aucun changement extérieur.

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

`feu-noyau` n'expose que la structure `FeuNoyau`, aucun composant interne. `feu-application` en est l'**unique** consommateur et héberge le Scribe. `feu-tui` est un binaire qui consomme `feu-application`. Chaque crate porte son type d'erreur — `ErreurFeuNoyau`, `ErreurFeuApplication`, `ErreurFeuTui`.

### Le noyau — composants internes

`FeuNoyau` orchestre trois composants :

- **Gardien** — unique point d'accès au système de fichiers. Délègue la connaissance de l'arborescence à son `Carnet`, maintient la `Configuration` en mémoire (miroir de `noyau.feu`).
- **Cryptographe** — unique composant autorisé à manipuler des données en clair. Maintient les clés déchiffrées dans son `Trousseau`, et leur représentation persistable — secrets chiffrés, clés publiques en clair — dans ses trousseaux publics, seule forme que le Gardien écrit sur le disque.
- **Archiviste** — un par foyer ouvert, gère l'arborescence interne d'un foyer (registre + classeurs). Ne détient jamais de clés, ne voit jamais d'octets en clair.

Un blob ne passe de l'Archiviste au Cryptographe que par le **Tiroir** : un conteneur de transport interne au noyau, qui porte le contenu, l'index de son classeur et son hash, et qui **zéroïse le clair** dès qu'il est remplacé par le chiffré. Il ne sort jamais de `feu-noyau`.

### Le Scribe — couche applicative ENU

Le **Scribe** (`feu-application/src/scribe/`) crée et maintient `~/.feu/enu/` — à la racine du nœud, pas dans un foyer, pour que les ENU restent navigables foyers fermés : elles sont en clair, leur intégrité venant de la signature et non du chiffrement. Il est activé à l'allumage, désactivé à l'extinction.

Il fait la charnière entre deux mondes qui s'ignorent : **le noyau ne sait pas ce qu'est une ENU, le Scribe ne sait pas ce qu'est un foyer**. Une ENU est traduite en ce que le noyau attend — index de foyer, empreinte de blob —, et inversement. Un nœud ne contient que ces deux sortes de fichiers : les ENU, tenues par le Scribe, et les blobs, tenus par le noyau dans les classeurs.

---

## `feu-noyau`

### `InterfaceFeuNoyau`

Contrat entre le noyau et son appelant direct (`feu-application`). Sept méthodes ; les adresses `.braise` y sont portées par le type `Braise`, les positions par `IndexFoyer` :

| Méthode | Rôle |
|---|---|
| `demander_mdp` | Collecte d'un mot de passe masqué (`Option<SecretString>`) |
| `recevoir_seed` | Transmet les mots de la seed BIP39 à l'initialisation, avant zéroïsation |
| `confirmer_enregistrement_seed` | Demande confirmation que la seed est enregistrée ; `false` interrompt l'init |
| `recevoir_braise_foyer` | Notifie l'adresse `.braise` d'un foyer (`IndexFoyer`, `Braise`) |
| `recevoir_etat_foyer` | Notifie un changement d'état d'ouverture d'un foyer (`IndexFoyer`) |
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
| `depot_blob` | Stocke un blob (unicité dans le foyer), rend `([u8; 32], IndexClasseur)` | `&mut self` |
| `lecture_blob` | Déchiffre un blob vers une destination, classeur découvert par balayage | `&mut self` |
| `suppression_blob` | Supprime un blob, classeur découvert par balayage | `&self` |
| `liste_blobs` | Liste les hashes (`[u8; 32]`) d'un classeur | `&self` |
| `existence_blob` | Rend le classeur qui détient un blob, quel qu'il soit | `&self` |
| `informations_blob` | Métadonnées système d'un blob (`DonneesBlob`) | `&self` |
| `chiffrement_asymetrique` | ML-KEM-1024 + HKDF + AES-256-GCM | `&self` |
| `dechiffrement_asymetrique` | Déchiffre un message KEM (foyer ouvert) | `&self` |
| `signature_noeud` | Signe avec la clé du nœud (4 627 o) | `&self` |
| `signature_foyer` | Signe avec la clé d'un foyer ouvert (4 627 o) | `&self` |
| `verification_signature` | Vérifie une signature ML-DSA-87 | associée |
| `creation_empreinte` | SHA3-256 d'octets — exposée pour la couche ENU | associée |
| `diagnostic_noeud` | Diagnostic de présence des fichiers du nœud, **sans** `Result` | associée |
| `diagnostic_foyer` | Diagnostic d'un foyer ouvert | `&self` |

Les blobs sont désignés **par leur hash seul**, un `[u8; 32]`, le classeur étant découvert par balayage : `depot_blob`, `lecture_blob`, `suppression_blob`, `existence_blob` et `informations_blob` prennent le hash sans `index_classeur`. L'ENU, qui référence une donnée par le couple `(foyer, hash)`, ne porte pas le classeur. `existence_blob` rend un `Option<IndexClasseur>` — l'absence est une réponse, pas une erreur. `depot_blob` garantit en contrepartie l'**unicité d'un hash dans un foyer** : il balaie avant d'écrire et, si le blob existe déjà, rend le classeur réel sans rien dupliquer.

### Index typés

`IndexFoyer` et `IndexClasseur` (`types.rs`, réexportés avec `Braise`) portent une position bornée par construction : ils ne naissent que de leur constante `ZERO` ou d'un `TryFrom<usize>` qui refuse tout index atteignant `NOMBRE`. Indexer un tableau avec ces valeurs reste dans les bornes, sans nouveau contrôle à chaque accès. Les deux types sont distincts — un index de classeur ne peut pas désigner un foyer. `NOMBRE` (cardinal : 3 foyers, 5 classeurs) est exposé par le type ; `valeur()` rend la position nue, `tous()` itère les positions valides, et `Ord`/`PartialOrd` permettent le tri — `foyers_requis` rend ainsi un `BTreeSet<IndexFoyer>`.

### Verrou d'instance

`FeuNoyau::new` pose un verrou consultatif dans `~/.feu/verrou` (`Gardien::verrouille_noeud`), fichier ouvert en `0o600` puis verrouillé par `try_lock`. Le descripteur reste ouvert tant que le nœud est allumé : un second Feu qui ouvre le même fichier échoue (`GardienNoeudDejaAllume`). Le verrou tombe à la fermeture du descripteur, donc à l'extinction du nœud comme à la mort du processus — arrêt brutal compris, rien à nettoyer à la main.

### Fermeture de secours d'un foyer

`secours_fermeture_foyer` répond à l'arrêt anormal de Feu avec un foyer ouvert : le dossier clair `<braise>/` est encore sur disque, mais le trousseau — donc les clés — a été perdu. Ni `ouverture_foyer` (qui attend une archive `.feu` absente) ni `fermeture_foyer` (qui exige les clés en mémoire) ne peut alors refermer le foyer.

La méthode relit les clés depuis le dossier clair, marque le foyer ouvert — prérequis de la fermeture standard — puis **délègue tout le reste à `fermeture_foyer`**. Deux prérequis la gardent :

- le foyer doit être **marqué fermé** dans la session — ouvert, ses clés sont en mémoire et c'est la fermeture standard qui s'applique ;
- le **diagnostic du dossier clair** doit être sans anomalie — un dossier trop abîmé empêcherait la reconstruction du trousseau.

Les deux refus sont fondus en une seule variante, `FermetureSecoursFoyerImpossible`. Le test mémoire passe avant tout accès disque.

### Diagnostic

Deux fonctions, l'une sans instance, l'autre sur un foyer ouvert :

- `diagnostic_noeud(chemin_feu)` — associée, utilisable **sans nœud allumé** (notamment pour comprendre pourquoi `new` échoue). Vérifie `~/.feu`, `.config/noyau.feu`, `.cles/`, les clés du nœud, archives et clés de chaque foyer connu. Rend un `Vec<Anomalie>`, **sans `Result`** : l'inspection se limite à des tests de présence, et une config illisible est une anomalie (`ConfigurationIllisible`), pas une erreur.
- `diagnostic_foyer(index_foyer)` — complète le précédent sur le foyer ouvert : clés du foyer, clés de classeurs, `registre/` et liens symboliques.

`Anomalie` compte quatre variantes :

- `ElementAbsent(PathBuf)` — un fichier ou dossier attendu manque ;
- `ConfigurationIllisible` — `noyau.feu` présent mais illisible ;
- `ArchiveIntermediaireResiduelle(PathBuf)` — un `.tar` subsiste au repos, signe d'une ouverture/fermeture interrompue ;
- `FoyerClairEtArchive(PathBuf)` — un foyer existe à la fois en clair et en `.feu` ; l'archive est complète, le clair se supprime.

`secours_fermeture_foyer` se sert du diagnostic du Gardien sur le dossier clair : la moindre anomalie l'arrête, un foyer trop abîmé ne pouvant plus rendre son trousseau.

### Contraintes d'état

Préconditions vérifiées avant tout effet :
- `changement_mdp` : tous les foyers ouverts (`AuMoinsUnFoyerFerme`).
- `ouverture_foyer` : foyer non déjà ouvert (`FoyerDejaOuvert`).
- `fermeture_foyer` : foyer ouvert (`FoyerFerme`).
- `secours_fermeture_foyer` : foyer marqué fermé **et** dossier clair sans anomalie (`FermetureSecoursFoyerImpossible`).
- Blobs : foyer ouvert.
- `dechiffrement_asymetrique`, `signature_foyer` : foyer ouvert. `chiffrement_asymetrique`, `signature_noeud` : nœud allumé.

Un `Drop` sur `FeuNoyau` **panique** si des foyers sont encore ouverts à la destruction.

---

## `feu-application`

### La couche ENU

#### `Enu` — l'enveloppe

```
Enu {
    version: u32,               // format sérialisé (VERSION_ENU = 1)
    braise: Braise,             // signataire (foyer) ou Braise::VIDE (nœud)
    hash_carte: [u8; 32],       // SHA3-256 de la carte sérialisée
    signature_carte: [u8; 4627],// ML-DSA-87 de la carte sérialisée
    carte: Carte,
}
```

Le hash et la signature couvrent **uniquement la carte sérialisée**, jamais la braise ni la version — qui restent des métadonnées malléables (routage, format sérialisé). L'horodatage vit dans la carte, en méta `"date"`, donc sous la signature. Deux signataires possibles : un **foyer** (ENU de contenu, braise du foyer) ou le **nœud** lui-même (`Braise::VIDE`, réservée aux racines de l'arborescence).

Le **modèle de confiance** est porté par le chargement. `Enu::charger` relit l'enveloppe puis vérifie, selon la braise annoncée, la signature contre la clé publique du nœud ou du foyer, **et** que le hash recalculé de la carte égale le `hash_carte` stocké. La braise restant hors signature, la falsifier ne peut que router vers la mauvaise clé et faire **échouer** la vérification — jamais faire accepter une ENU.

`Enu` est **privée au crate**. Elle n'est pas réexportée depuis `lib.rs` : l'extérieur ne reçoit que des `Fiche` (voir plus bas). Les deux chargements restent `pub(super)` — `charger` (hash **et** signature), et `charger_sans_verification_signature` (hash seul, réservé au parcours). La barrière d'authenticité `authentique` est repassée par tout ce qui agit sur un blob.

#### `Carte` — le contenu

Trois variantes, chacune portant des métadonnées structurées (`BTreeMap<String, String>`) et des tags libres (`BTreeSet<String>`), collections à ordre déterministe pour le hash :

| Variante | Champs propres | Rôle |
|---|---|---|
| `Donnee` (CaD) | `hash_blob: [u8; 32]` | référence un blob par l'empreinte de son clair — jamais par son classeur |
| `Texte` (CaT) | `contenu: String` | texte brut embarqué, borné à 60 kio, nommé par la méta `"nom"` |
| `Repertoire` (CaR) | `hashs_enu: BTreeSet<[u8; 32]>` | référence ses enfants par leur `hash_carte` |

Une enveloppe prend le nom de sa carte : **ENUd** pour une donnée, **ENUt** pour un texte, **ENUr** pour un répertoire. Les messages d'erreur du code emploient la graphie `EnuD` / `EnuT` / `EnuR` (`Ce doit être une EnuR`).

`Carte` vit dans son propre module (`scribe/carte.rs`) et est l'inverse d'`Enu` : un `enum` public dont les variantes exposent leurs champs. C'est ce qui permet à un consommateur de descendre l'arborescence en lisant les `hashs_enu` d'une `Carte::Repertoire`. `hashs_enu()` rend une **`Option`** plutôt qu'une erreur sur une feuille : une feuille est le cas normal d'un parcours, et l'`Option` distingue la feuille du répertoire réellement vide.

Deux métas sont posées par la crate : `"nom"` (`Carte::nom`, qui valide le composant de chemin) et `"date"` (`Carte::date`, timestamp Unix de création, posée par les trois constructeurs). Les porter dans la carte, plutôt que dans l'enveloppe, les fait entrer dans le hash et sous la signature.

#### Sérialisation

Format maison, sans crate, en deux passes. L'**enveloppe** s'écrit : `version` (u32 BE) · `braise` (62 o UTF-8) · `hash_carte` (32 o) · `signature_carte` (4 627 o) · carte. La **carte** s'écrit : discriminant `u8` (0x00 CaD, 0x01 CaT, 0x02 CaR) · métadonnées · tags · champs propres (hash 32 o pour CaD ; `u64` longueur + UTF-8 pour CaT ; `u32` nombre + 32 o × n pour CaR). La sérialisation est déterministe : même carte → mêmes octets → même hash.

#### Persistance et arborescence

- **Content-addressing** — le nom du fichier est le hash hexadécimal de la carte : `~/.feu/enu/<hash_hex>.enu`. Une carte donnée vise toujours le même fichier. `Enu::sauvegarder` est **idempotent** : si le fichier existe, rien n'est réécrit — un contenu identique n'est stocké qu'une fois et peut être référencé par autant d'ENU que nécessaire. La méta `"date"` étant dans la carte, deux cartes de même contenu construites à deux instants portent deux noms.
- **Racines** — le sommet de l'arborescence est signé par le **nœud** (`Braise::VIDE`), jamais par un foyer. `Enu::new_racine` pose la méta `_racine` (hash de la racine précédente, ou `""` à la genèse) puis repointe atomiquement le symlink `.DERNIERE_RACINE` (lien temporaire puis `rename`, cible relative au nom de fichier). À la toute première activation, une racine origine est forgée.
- **`Enu::remplacer`** — un « chercher-remplacer » par hash dans l'arborescence courante : substitue une ENU, reconstruit les répertoires du chemin cible → racine (re-signés sous leur braise pour les répertoires de contenu, signés nœud pour le sommet), puis pose un nouveau sommet. Les anciens sommets et répertoires sont **conservés** — ce sont les versions précédentes de la lignée `_racine`. `Enu::supprimer` existe mais n'a aucun appelant de production.

### `Fiche` — la vue publique d'une ENU

L'interface ne voit jamais `Enu`. Elle reçoit des **`Fiche`** (`scribe/fiche.rs`) : les mêmes champs **sans la signature ni la version** — `braise`, `hash_carte`, `carte` — et elle les rend telles quelles. Les 4 627 octets de signature n'ont ainsi aucune raison de traverser un canal ni de rester en mémoire côté interface.

Une fiche se reçoit et se rend, elle ne se fabrique pas : `Fiche::new` est `pub(crate)`. Le retour se fait par le `hash_carte`, qui suffit à recharger la vraie `Enu` et à la repasser par `authentique` avant d'agir. C'est toujours la crate qui garantit, jamais la fiche — sa `braise`, hors signature, ne vaut que pour l'affichage.

### Itérateurs

Deux parcours exposés par `commandes`, tous deux **paresseux**, **sans cache**, et **sans rien construire** — ni signature, ni écriture. Ils rendent des `Fiche`.

#### `Descendants` — l'espace, en profondeur d'abord

Descend l'arborescence par les `hashs_enu` de chaque `Carte::Repertoire`. Une **pile** (`Vec<(usize, [u8; 32])>`, `pop` par l'arrière, enfants empilés en `.rev()`) impose la profondeur d'abord, dans l'ordre trié du `BTreeSet`. Chaque item porte sa **profondeur**, qui ne peut pas vivre dans la `Fiche` : dans un DAG, la même ENU se rencontre à deux profondeurs.

- `Item = ResultFeuApplication<(usize, Fiche)>` ;
- le **point de départ fait partie du parcours** (profondeur 0) ;
- **les doublons sont conservés** — qui veut un inventaire déduplique chez lui ;
- **aucune signature n'est vérifiée**, pas même au départ : l'arborescence étant un DAG de Merkle, recalculer le hash de la carte à chaque pas (`charger_sans_verification_signature`) chaîne l'intégrité de toute la descendance. C'est ce qui permet de parcourir un arbre **foyer fermé** — les blobs, eux, restent illisibles ;
- un échec de chargement est rendu **comme un item**, sans interrompre le parcours : seule la branche fautive est perdue, faute de connaître ses enfants.

#### `RacinesAnterieures` — le temps, de la dernière racine à la genèse

Remonte les racines du nœud par la méta `_racine` : une liste chaînée, ni file ni déduplication. La racine de départ fait partie du parcours. L'arrêt se fait sur la **genèse**, dont la méta `_racine` est **vide, pas absente**.

- `Item = ResultFeuApplication<Fiche>` ;
- **chaque pas est authentifié** (`Enu::charger`, donc hash **et** signature contre la clé du nœud) : le remontant ne traverse que des racines signées par le nœud ;
- **une erreur termine le parcours**, contrairement au descendant : la racine précédente n'est connue que par la méta de celle qu'on n'a pas pu lire, il n'y a plus de chaîne à suivre (`take` vide le champ avant le chargement).

### Le Scribe — opérations

| Fonction | Rôle |
|---|---|
| `activation` / `desactivation` | Crée `enu/` (0o700) et amorce la genèse au premier allumage, puis rouvre les comptoirs de `scribe.feu` ; oublie les comptoirs à l'extinction |
| `derniere_enu_racine` | Charge le sommet courant en suivant `.DERNIERE_RACINE` |
| `charge_enu` | Charge l'ENU de `hash` et en rend la `Fiche` — `None` si absente |
| `ouverture_comptoir_depot` / `fermeture_comptoir_depot` | Ouvre/ferme un comptoir de dépôt |
| `ouverture_comptoir_travail` / `fermeture_comptoir_travail` | Ouvre/ferme le comptoir de travail |
| `depot_enu_texte` | Dépose un texte (ENUt), puis le greffe |
| `greffe_enfants` | Point de passage unique de tout dépôt : accroche les ENU et remonte au sommet |
| `retrait_lecture_seule` | Matérialise l'arborescence d'une ENUr dans un dossier OS |
| `charge_blob` / `supprime_blob` / `existence_blob` / `informations_blob` | Accès aux blobs par la `Fiche` de leur ENU |
| `donne_descendants` / `donne_racines_anterieures` | Arme les deux itérateurs sans laisser sortir `chemin_enu` |
| `foyers_requis` | Dresse les foyers signataires d'un sous-arbre (pré-passe du retrait) |

**Comptoir de dépôt.** `ouverture_comptoir_depot` valide les index, crée le dossier et l'enregistre sous un identifiant qui suit le plus grand déjà pris — un identifiant libéré peut resservir, mais jamais pendant qu'un plus grand est ouvert. L'identifiant et sa destination sont recopiés dans la session (`BTreeMap<usize, (PathBuf, IndexFoyer, IndexClasseur)>`). `fermeture_comptoir_depot` reçoit en outre l'**ENU d'accueil** (la `Fiche` marquée), sous laquelle greffer. Le parcours est **bottom-up** (`walkdir`) : chaque fichier est déposé via `FeuNoyau::depot_blob` puis enveloppé dans une `Carte::Donnee` signée ; chaque répertoire devient une `Carte::Repertoire` référençant ses enfants. Le nom de chaque entrée est conservé en méta `"nom"`. Le dossier du comptoir est supprimé à la fin ; un comptoir vide laisse la racine inchangée.

Le **classeur demandé n'est pas garanti** : si la donnée existe déjà ailleurs dans le foyer, le noyau l'y laisse et l'ENU reste valable (elle référence un hash, pas un emplacement) — mais l'écart n'est remonté nulle part.

**Comptoir de travail.** `ouverture_comptoir_travail` refuse d'abord la racine du nœud (`ScribeRacineNoeudInterdite`, que la fermeture ne saurait re-signer), puis tout comptoir déjà ouvert, avant de sortir le sous-arbre par `retrait_lecture_seule` — gardes comprises. **L'enregistrement clôt l'ouverture, il ne l'amorce pas** : un dossier à demi sorti n'est rien pour Feu, là où un comptoir inscrit ferait passer les fichiers manquants pour des suppressions voulues. `fermeture_comptoir_travail` compare le dossier à l'arbre sorti : ce qui n'a pas bougé est réemployé tel quel (même ENU, braise, métas et tags), une entrée modifiée est re-signée sous la braise qu'elle remplace, une entrée nouvelle rejoint celle de son accueil, une entrée effacée disparaît — ne rien référencer **est** la suppression. Le disque fait autorité ; `foyers_requis` dresse les foyers signataires avant toute écriture (`ScribeFoyersFermes`). Le résultat substitue l'ancien sous-arbre par `Enu::remplacer` ; le dossier n'est supprimé qu'une fois le remplacement passé, un échec laissant comptoir et dossier en place.

**Dépôt.** Les deux voies — comptoir et ENU isolée — convergent vers `greffe_enfants`, seul endroit où se décide qui signe le nouveau sommet. Les enfants y arrivent **déjà signés et sauvegardés** ; seuls l'accueil et ce qui le surplombe sont touchés. L'accueil décide :

- **une racine du nœud**, reconnue à sa braise vide — `Enu::new_racine` forge directement la version suivante, signée *nœud* ;
- **un répertoire de foyer** — `Enu::new` le re-signe sous sa braise, puis `Enu::remplacer` le substitue dans l'arbre et remonte jusqu'à un `new_racine`.

Si la carte augmentée égale celle de départ, rien n'est forgé et la méthode rend `Ok(())` : les hashs étaient déjà tous présents (la carte est un ensemble) ou la liste était vide. Le cas se produit réellement quand un même fichier est redéposé par le comptoir.

**L'unicité des noms d'enfants tient ici, au dépôt.** Un nouveau venu dont le nom est déjà pris par un enfant de l'accueil est greffé sous une copie renommée (`nom_libre`, suffixe `nom_1`, `nom_2`…) — l'occupant restant intact, son foyer pouvant être fermé. Plus bas dans l'arbre, l'unicité vient du système de fichiers qui a nommé le comptoir ; le retrait joint donc le nom sans sonder le dossier de sortie.

**L'accueil doit appartenir à l'arbre courant**, et chaque voie le vérifie. Une racine qui n'est plus la dernière est refusée (`ScribeRacinePerimee`) : la version qu'elle produirait repartirait d'une carte périmée et perdrait tout ce qui a été déposé depuis. Un répertoire absent de l'arbre l'est aussi (`ScribeRemplacementSansEffet`) : la substitution ne trouve pas sa cible et n'ajouterait qu'un maillon mort à la lignée `_racine`.

**Retrait.** `retrait_lecture_seule` dresse d'abord `foyers_requis` : le `BTreeSet` des foyers signataires du sous-arbre, par un `Descendants` (toutes cartes comptent, pas seulement les `Donnee` — un répertoire de foyer fermé arrête aussi sûrement qu'une donnée). Tout foyer fermé **refuse le retrait avant la moindre écriture** (`ScribeFoyersFermes`, qui les nomme tous). Ensuite seulement, le dossier de sortie (qui ne doit pas exister) est créé et chaque enfant **chargé et authentifié** avant d'être écrit ; le nom est validé comme composant de chemin (`Carte::nom`). Une braise qui ne résout vers aucun foyer est écartée de l'inventaire : c'est la racine du nœud.

### `SessionApplication`

La session porte l'état utile à la présentation : capacités du noyau, braises et états des foyers, clés publiques, et les comptoirs ouverts — les dépôts en `BTreeMap<usize, (PathBuf, IndexFoyer, IndexClasseur)>` (identifiant → dossier, foyer, classeur), le comptoir de travail en `Option<(PathBuf, Fiche)>`. Le nombre de foyers et de classeurs n'est pas recopié : il est porté par `IndexFoyer` et `IndexClasseur`. Les accesseurs indexés rendent une valeur nue — un index hors bornes est impossible par construction — et seule `braise_vers_index` rend une `Option`. S'ajoutent `nombre_foyers_ouverts` et `foyers_fermes`, lus par la TUI pour filtrer les commandes.

### `InterfaceFeuApplication`

Contrat entre `feu-application` et sa couche de présentation, symétrique d'`InterfaceFeuNoyau`. Quatre méthodes, toutes en `&self` : `demander_mdp`, `recevoir_seed`, `confirmer_enregistrement_seed`, et `recevoir_session_application` — cette dernière appelée une seule fois par commande mutante, la session dans un état cohérent, jamais depuis un setter. En interne, un `RecepteurNoyau` éphémère (privé) fait le pont vers le noyau le temps d'un appel : il délègue les interactions bloquantes à l'interface et écrit lui-même les notifications d'état dans la session.

### Commandes

Vingt-sept commandes, en cinq parties (foyer, cryptographie, dépôt-retrait, blobs, ENU). La précondition commune est l'allumage : hors `commande_allumage_noeud`, `commande_verification_signature` et `commande_diagnostic_noeud`, toute commande rend `ErreurFeuApplication::NoeudEteint` nœud éteint.

| Commande | Rôle |
|---|---|
| `commande_allumage_noeud` / `commande_extinction_noeud` | Initialise/allume puis éteint le nœud |
| `commande_changement_mdp` | Change le mot de passe |
| `commande_ouverture_foyer` / `commande_fermeture_foyer` / `commande_secours_fermeture_foyer` | Cycle des foyers |
| `commande_diagnostic_noeud` / `commande_diagnostic_foyer` | Diagnostics |
| `commande_chiffrement_asymetrique` / `commande_dechiffrement_asymetrique` | ML-KEM-1024 |
| `commande_signature_noeud` / `commande_signature_foyer` / `commande_verification_signature` | Signatures ML-DSA-87 |
| `commande_ouverture_comptoir_depot` / `commande_fermeture_comptoir_depot` | Comptoirs de dépôt, plusieurs à la fois |
| `commande_ouverture_comptoir_travail` / `commande_fermeture_comptoir_travail` | Comptoir de travail, unique et exclusif |
| `commande_retrait_lecture_seule` | Retrait sur disque, gardé par les foyers requis |
| `commande_chargement_blob` / `commande_suppression_blob` / `commande_existence_blob` / `commande_informations_blob` | Blobs, désignés par la `Fiche` de leur ENU |
| `commande_derniere_enu_racine` / `commande_chargement_enu` | Sommet et descente de l'arborescence |
| `commande_depot_enu_texte` | Dépôt d'un texte court (ENUt) |
| `commande_descendants` / `commande_racines_anterieures` | Les deux parcours |

Chaque commande qui mute la session notifie la présentation via `recevoir_session_application(Option<SessionApplication>)` — `Some(session)` après mutation, `None` à l'extinction. `commande_changement_mdp` est la seule commande de foyer à ne pas notifier : les clés publiques ne changent pas, le miroir reste exact.

---

## `feu-tui`

Interface terminal sur Ratatui et crossterm. **Deux threads** : le principal tient la boucle TUI, le second pilote `FeuApplication`. Ils communiquent par deux canaux `mpsc` typés (`MessageTuiCoeur`, `MessageCoeurTui`) créés dans `main.rs` et confiés à deux connecteurs. Une panique du thread cœur sort en code 1 ; le terminal est restauré par le guard de `ratatui::run`. `main` reste le seul point de lecture de `$HOME` : il résout `chemin_home` (racine de l'écran du disque) et `chemin_feu` (racine du nœud) au bord du programme.

### Trois écrans de travail à onglets

Un module par écran (`ecran_pilotage`, `ecran_arborescence_enu`, `ecran_arborescence_disque`), chacun tenant son état, son rendu et ses transitions. `Ecran` est un pur sélecteur sans données. Les onglets sont portés par la bordure basse du cadre commun (`rendu::carre_principal`), l'actif en couleur d'accent. `h` et `l` passent d'un écran à l'autre, **en ligne et non en cycle** : `ArborescenceEnu` → `Pilotage` → `ArborescenceDisque`.

- **Pilotage** — l'usage courant, et ses trois modales : saisie du mot de passe (cadre orange arrondi), affichage de la seed (trois colonnes), information générique (l'à-propos sur `!`). Une ligne d'état y affiche les comptoirs ouverts : `Dépôts ›` puis la liste `id.{fN.cM}`, ou `Comptoir travail ›` puis le chemin.
- **Arborescence des ENU** — l'arbre du nœud, chargé par `R` (le cœur répond par un `Vec<(usize, Fiche, Option<IndexClasseur>)>` à plat, déjà en profondeur d'abord), rendu indenté de la profondeur avec, en tête de chaque ligne, le couple `foyer·classeur`, puis une colonne de marque, un guide par niveau et un symbole par carte. Repliable : `Entrée` plie/déplie un répertoire peuplé.
- **Arborescence du disque** — depuis `$HOME`, construite un niveau à la fois (`read_dir`), repliable, triée (chemin puis répertoires en tête), sans rafraîchissement automatique (`R` recharge la branche sous le curseur). La lecture du disque vit dans `feu-tui`, pas dans le cœur.

Sur les deux arborescences, les mêmes touches font les mêmes gestes : `R` charge ou rafraîchit, `j`/`k` déplacent le curseur, `Entrée` plie ou déplie, `m` retient ce qui est sous le curseur — une `Fiche` d'un côté, un `PathBuf` de l'autre —, `x` lève la marque.

### Marques et actions

Deux marques **transversales** vivent dans `EtatTui` : `enu_selectionnee: Option<Fiche>` et `chemin_selectionne: Option<PathBuf>`. L'une se pose sur l'écran des ENU, l'autre sur celui du disque, et toutes deux se consomment sur le pilotage. `x` est une seule commande (`SupprimerSelection`), l'écran affiché disant laquelle des deux marques elle vise.

- **`d`** — ouvre un comptoir de dépôt depuis un classeur, **au chemin marqué** : le comptoir est le sous-dossier `fN.cM_depot_feu` de la marque (par exemple `f0.c0_depot_feu`), jamais le dossier marqué lui-même. Son nom porte sa destination, ce qui le rend unique par couple foyer-classeur.
- **`c`** — ferme un comptoir de dépôt : l'identifiant est saisi et validé contre la session, l'ENU d'accueil est la marque ENU (il faut une `Carte::Repertoire`). Fermer un comptoir vide la marque et l'arbre affiché.
- **`T`** — ouvre le comptoir de travail sur l'ENU répertoire marquée, au sous-dossier `travail_feu` du chemin marqué, et le ferme dès qu'il est ouvert — une seule touche pour les deux sens, les conditions étant complémentaires. La fermeture, elle, ne touche ni la marque ni l'arbre affiché, qui désigne pourtant une racine remplacée : `R` le recharge.
- **`r`** — retire l'ENU marquée **au chemin marqué** : le dossier de sortie est le sous-dossier `retrait_feu_<8 caractères hex>`, les quatre premiers octets du `hash_carte`. Active dès que les deux marques sont posées.
- **`S`** — fermeture de secours d'un foyer (saisie du numéro). Active dès que le nœud est allumé, sans autre condition : l'état qui appelle un secours ne se lit pas dans la session, seul le noyau le constate.

Les foyers fermés ne sont pas filtrés par la table pour `c`, `r` et `T` : une touche qui s'évanouit renseigne moins que l'erreur qui nomme le foyer à rouvrir.

### Gestion des erreurs dans la boucle

`ErreurFeuTui` (`feu-tui/src/erreur.rs`) porte les deux natures qui remontent la boucle : les refus que l'utilisateur lit et corrige, et l'échec d'entrée-sortie du terminal, qui ne s'affiche nulle part puisque plus rien ne s'affiche. C'est la **variante** qui trie, pas le texte, et le tri se fait dans `Tui::lancer` : **seul `Io` sort vers `main`**, toute autre variante devient un message à l'écran et **la boucle continue**. Les trois `saisie_mode_*` rendent un `ResultFeuTui` sans distinguer les deux natures. Plus aucun `unwrap` faillible dans la TUI ; les gardes contre la panique ont quitté la table au profit de l'erreur nommée.

---

## Gestion d'erreurs

Un seul type d'erreur par crate : aucun type interne de module, aucune erreur en `String` à l'intérieur d'une crate.

| Type | Crate | Variantes | Notes |
|---|---|---|---|
| `ErreurFeuNoyau` | `feu-noyau` | 47 | levée partout, jusqu'à la frontière, sans type de module |
| `ErreurFeuApplication` | `feu-application` | 36 | unique type exposé ; reçoit `ErreurFeuNoyau` aplatie en `String` |
| `ErreurFeuTui` | `feu-tui` (`pub(crate)`) | 14 | seules les siennes ; `Io` sort, le reste s'affiche |

La règle de nommage est commune : des **variantes nommées par le fait**, pas par le module ni par un code séquentiel. Les variantes **internes** viennent d'abord, par ordre alphabétique — le seul ordre qui dise où insérer la suivante —, le préfixe du nom rappelant le composant qui lève quand le cas lui est propre. Les variantes **externes** ferment la liste et portent l'erreur d'une crate tierce, par `#[from]` quand le type source implémente `std::error::Error` ; sinon la conversion est manuelle (`.to_string()`), le type original étant perdu.

### `ErreurFeuNoyau`

Les variantes internes couvrent l'état du nœud et des foyers (`AuMoinsUnFoyerFerme`, `FoyerDejaOuvert`, `FoyerFerme`, `FermetureSecoursFoyerImpossible`, `SeedRefuseeNoeudExistant`), les index et les bornes (`IndexFoyerInvalide`, `IndexClasseurInvalide`, les quatre `TailleMaxDepassee*`), et ce qui est propre à un composant (`Gardien*` — dont le verrou déjà tenu, `Cryptographe*`, `ArchivisteIndisponible`, `BlobIntrouvable`, `BraiseErronnee`, `CheminInexistant`). Variantes externes : `IoError`, `ParseIntError`, `Bip39`, `Argon2` (par `#[from]`) ; `Hkdf(String)`, `AesGcm(String)`, `DecodePartial(String)` (conversion manuelle, les types sources n'implémentant pas `std::error::Error`). Aucune charge utile n'est sensible : une braise ou un chemin absolu est porté pour inspection, jamais affiché.

### `ErreurFeuApplication`

Deux variantes hors Scribe — `AuMoinsUnFoyerOuvert`, `NoeudEteint` — puis les `Scribe*` : forme d'une carte (`ScribeEnuDAttendue`, `ScribeEnuRAttendue`, `ScribeEnuRacineAttendue`, `ScribeCarteMalFormee`, `ScribeMetaNomAbsente`, `ScribeMetaDateAbsente`), confiance (`ScribeEnuNonAuthentique`, `ScribeEnuNonIntegre`, `ScribeBraiseInconnue`), comptoirs (`ScribeComptoirDepotOuvert`, `ScribeComptoirTravailOuvert`, `ScribePasComptoirTravailOuvert`, `ScribeComptoirDejaAjoute`, `ScribeIndexComptoirInconnu`, `ScribeRacineNoeudInterdite`, les quatre `ScribeConfig*`), disque (`ScribeDossierDejaExistant`, `ScribeDossierDepotIntrouvable`, `ScribeDossierTravailIntrouvable`, `ScribeNomFichierInvalide`, `ScribeTailleMaxDepasseeTexte`), état des foyers (`ScribeFoyerFerme`, `ScribeFoyersFermes`) et place dans l'arbre (`ScribeRacinePerimee`, `ScribeRemplacementSansEffet`). Variantes externes : `DecodeError`, `FeuNoyau(String)` (le type du noyau est aplati : aucun type interne ne traverse l'API), `IoError`, `ParseIntError`, `Utf8Error`, `WalkDirError`.

### `ErreurFeuTui`

Une variante par échec nommable de la couche terminal : sept portent le préfixe de l'écran qui les lève (`Disque*`, `Enu*` — curseur absent, sélection hors liste, arbre non chargé, entrée qui n'est pas un répertoire), six le préfixe `Tui*` pour ce qui manque au moment d'agir (marque, nœud allumé, entier valide, index de comptoir, index de foyer — la saisie étant le dernier endroit où un nombre quelconque existe encore), et `Io` ferme la liste. Le préfixe des messages marque la couche : `NOY >`, `APP >`, `TUI >`.

### Séparation des erreurs et du flux

Le cœur (`ConnecteurVersTui`) transforme tout échec de `FeuApplication` en `MessageCoeurTui::AffichageErreur(String)` : **aucune erreur applicative n'arrête le thread**. Seuls `Quitter` et la fermeture du canal rompent sa boucle. Côté TUI, le message est posé par `EtatTui::ajouter_message_erreur`, avec un compte à rebours de cinq secondes.

---

## Tests

86 tests, `cargo test` les passe tous.

| Emplacement | Nb | Objet |
|---|---|---|
| `feu-noyau/tests/cycle_de_vie.rs` | 7 | Cycles de vie du nœud par le contrat public : allumage, mot de passe, erreurs d'usage, fermeture en secours, démarrage depuis la seed, diagnostic, panique du `Drop` foyer ouvert |
| `feu-noyau/src/types.rs` | 9 | `TryFrom<&str>` de `Braise` : réciprocité, suffixe, longueur, alphabet BASE32 |
| `feu-noyau/src/cryptographe/trousseau.rs` | 5 | Déterminisme de la dérivation, distinction des clés, cycle de chiffrement, mauvais mot de passe |
| `feu-noyau/src/cryptographe.rs` | 2 | Cycles signature/vérification et chiffrement/déchiffrement asymétrique |
| `feu-noyau/src/gardien.rs` | 1 | Cycle de `noyau.feu` |
| `feu-application/tests/application.rs` | 9 | La crate par ses seules `commande_*` : cycle applicatif, vie d'un blob, ENU texte, parcours, secours, retrait foyer fermé, dépôt sous racine ou ENUr périmée |
| `feu-application/tests/comptoirs.rs` | 9 | Les comptoirs, par le contrat public : cycle dépôt, ouverture/fermeture du travail, exclusivité, persistance |
| `feu-application/src/scribe/tests.rs` | 8 | Ce qui exige une pile réelle : cycle disque d'une ENU, falsification de signature et de braise, cycle de racine, remplacements, greffe |
| `feu-application/src/scribe/tests/tests_comptoirs.rs` | 4 | Cycles disque des comptoirs et transitions de `Comptoirs` |
| `feu-application/src/scribe/carte.rs` | 19 | Sérialisation canonique (octets attendus, aller-retour) et gardes de forme des cartes |
| `feu-application/src/scribe/configuration.rs` | 6 | Cycle de `scribe.feu` |
| `feu-application/src/scribe/comptoirs.rs` | 3 | Cycle disque d'un comptoir, identifiants, unicité des chemins |
| `feu-application/src/scribe/enu.rs` | 1 | Aller-retour de l'enveloppe par son format canonique |
| `feu-application/src/scribe/scribe_comptoirs.rs` | 1 | `nom_libre`, le suffixage des homonymes |
| `feu-application/src/session.rs` | 1 | Comptage des états de foyers |
| `feu-application/src/lib.rs` | 1 | Cycle de vie constaté sur les champs privés |

**Trois emplacements.** Les `tests/` externes pilotent la crate par son seul contrat public, comme le fait son consommateur réel — pour `feu-noyau`, c'est le compilateur qui tient l'inaccessibilité des composants internes, et non la seule discipline d'écriture. Les `mod tests` en ligne éprouvent ce qui se prouve sans monter de pile (une carte n'est que des octets et des collections ordonnées). Entre les deux, `src/scribe/tests.rs` garde ce que le contrat public n'atteindrait qu'en se bâtissant un décor exprès — l'enveloppe et sa signature, la barrière de confiance de `charger`, la tenue de l'arborescence. **Le critère est la pile, pas la visibilité** : dès qu'un test exige un noyau allumé et un foyer ouvert, il quitte le module en ligne.

Les tests d'intégration montent une pile réelle : noyau allumé depuis une seed neuve dans un `TempDir`, foyer ouvert, Scribe activé, l'interface de la couche (`InterfaceFeuNoyau` ou `InterfaceFeuApplication`) implémentée par un `InterfaceTest` qui collecte les notifications. Aucun mock de la cryptographie ni du disque.

`feu-tui` n'a aucun test — la présentation reste éprouvée à la main.

---

## Cryptographie

La cryptographie est purement post-quantique côté asymétrique ; les primitives symétriques et de hachage (AES-256-GCM, SHA3-256, Argon2id) restent en place, leur sécurité effective post-Grover étant jugée suffisante (~128 bits).

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

Foyer i (i = position + 1, position = 0..IndexFoyer::NOMBRE, donc i = 1..3)
  ├─ braise (identifiant)   "feu/foyer/braise/{i}"            → 32 o bruts
  ├─ signature              "feu/foyer/signature/{i}"         → ML-DSA-87
  ├─ symétrique foyer       "feu/foyer/symetrique/{i}"        → AES-256-GCM
  └─ chiffrement            "feu/foyer/chiffrement/{i}"       → ML-KEM-1024

Classeur j du foyer i (j = 1..IndexClasseur::NOMBRE, donc j = 1..5)
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

- **Nœud** (label `feu/noeud/signature`) — clé racine, signe les actes engageant le nœud dans sa globalité : les **racines de l'arborescence ENU**.
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

La braise est l'identifiant du foyer de bout en bout : clé de `noyau.feu`, nom du dossier `~/.feu/<braise>/`, nom des archives `<braise>.feu` et `<braise>.tar`, signataire annoncé d'une ENU.

Elle est portée par le newtype `Braise([u8; 55])`, qui stocke les 55 caractères BASE32 sans le suffixe (réintroduit par `Display`) et ne peut naître que d'une chaîne validée par `TryFrom<&str>` — longueur, alphabet, suffixe. `Braise::VIDE` (55 fois `a`) désigne le signataire nœud et sert de valeur d'initialisation des tableaux de braises. **Aucun foyer réel ne la porte**, et c'est précisément ce qui permet de l'employer comme aiguillage de vérification : une ENU qui l'annonce est vérifiée contre la clé du nœud.

### Chiffrement symétrique des blobs

Chaque classeur possède sa propre clé AES-256-GCM (32 o), dérivée et stockée chiffrée sur le disque. Le hash SHA3-256 est calculé sur le clair **avant** chiffrement — il sert d'identifiant content-addressable, et c'est lui que porte une `Carte::Donnee`.

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

### Nœud, foyers fermés

```
~/.feu/
├── verrou                       ← verrou d'instance, fichier vide (tenu nœud allumé)
├── .config/
│   ├── noyau.feu                ← configuration globale du nœud (en clair)
│   └── scribe.feu               ← état des comptoirs du Scribe (en clair)
├── .cles/
│   ├── sel.feu                  ← sel Argon2id, 16 o (en clair)
│   ├── feu_sig.priv             ← clé privée de signature du nœud (chiffrée, 60 o)
│   ├── feu_sig.pub              ← clé publique de signature du nœud (en clair, 2 592 o)
│   ├── <braise1>.cle            ← clé symétrique d'archive foyer 1 (chiffrée, 60 o)
│   ├── <braise2>.cle            ← clé symétrique d'archive foyer 2 (chiffrée, 60 o)
│   └── <braise3>.cle            ← clé symétrique d'archive foyer 3 (chiffrée, 60 o)
├── <braise1>.feu                ← archive chiffrée foyer 1
├── <braise2>.feu                ← archive chiffrée foyer 2
├── <braise3>.feu                ← archive chiffrée foyer 3
└── enu/                         ← arborescence ENU (voir plus bas)
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

### Format de `noyau.feu`

Fichier texte, `2 + IndexFoyer::NOMBRE` lignes, dans `~/.feu/.config/` :

```
<version>
<prochain_index>
<adresse_braise_foyer_0>
<adresse_braise_foyer_1>
<adresse_braise_foyer_2>
```

`version` = `1`. `prochain_index` vaut `4` après initialisation (incrémenté d'une unité par foyer créé, soit `1 + IndexFoyer::NOMBRE = 4`). Il est réservé pour la révocation future d'un foyer : quand un slot est révoqué, il reçoit le prochain index de dérivation disponible, ce qui produit une nouvelle braise. Le nombre de foyers reste fixe.

### Format de `scribe.feu`

Fichier texte, un champ par ligne, dans `~/.feu/.config/` : la version en tête, le nombre de comptoirs de dépôt, puis pour chacun l'identifiant, le chemin, le foyer et le classeur ; vient ensuite le comptoir de travail — son chemin et le `hash_carte` de la racine sortie — ou `None`. Les chemins passent en hexadécimal : un chemin Unix peut porter des octets non-UTF8 ou un `\n`, que le découpage en lignes ne supporterait pas.

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

Fichier `<hash_carte_hex>.enu` dans `enu/`, en clair. Contenu : `version (u32 BE) ‖ braise (62 o UTF-8) ‖ hash_carte (32 o) ‖ signature_carte (4 627 o) ‖ carte sérialisée`. En-tête fixe de 4 725 octets, puis la carte.

### Archive du foyer

Fermeture : dossier → `.tar` → chiffrement AES-256-GCM-stream → `.feu`. Ouverture : `.feu` → déchiffrement → `.tar` → extraction. Les archives intermédiaires `.tar` et `.feu` sont supprimées après usage, y compris **sur les chemins d'erreur** ; un `.tar` résiduel au repos est signalé par le diagnostic.

**Format binaire de l'archive `.feu` :**

```
[nonce 7 o] [chunk_1] [chunk_2] ... [chunk_n]
```

Chaque chunk : `plaintext (≤ CHUNK_SIZE o) + tag AES-GCM (16 o)`. `CHUNK_SIZE = 4096`.

---

## Constantes

| Constante | Valeur | Rôle |
|---|---|---|
| `IndexFoyer::NOMBRE` | 3 | Nombre de foyers par nœud |
| `IndexClasseur::NOMBRE` | 5 | Nombre de classeurs par foyer |
| `MAX_TAILLE_BLOB` | 512 Mio | Taille maximum d'un blob en clair |
| `MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE` | 1 Mio | Taille maximum d'un message à chiffrer via ML-KEM-1024 |
| `MAX_TAILLE_SIGNATURE` | 64 Kio | Taille maximum d'un message à signer |
| `Braise::LONGUEUR` | 55 | Caractères BASE32 d'une braise, hors suffixe `.braise` (interne à `types.rs`) |
| `MAX_TAILLE_TEXTE` | 60 Kio | Plafond du contenu d'une `Carte::Texte` (interne à `scribe/carte.rs`) |
| `VERSION_ENU` | 1 | Version du format sérialisé d'une ENU (interne à `scribe/enu.rs`) |
| `TAILLE_CHUNK` | 8 192 o | Granularité de lecture d'un blob par le Tiroir (`pub(crate)`) |
| `NOMBRE_MOTS_SEED` | 24 | Mots de la seed BIP39 (interne au cryptographe) |
| `CHUNK_SIZE` | 4 096 o | Taille des chunks du stream AES-256-GCM des archives `.feu` (interne au cryptographe) |

---

## Plateformes supportées

Linux et macOS uniquement. Le noyau repose sur des primitives Unix (permissions `mode`, liens symboliques, `rename` atomique) et lève une erreur de compilation sur toute autre plateforme. Seul le binaire lit l'environnement, pour résoudre `$HOME`.

---

## Environnement technique

**Edition Rust :** 2024. Version `0.0.7` et licence `GPL-3.0-or-later` définies au niveau workspace. Le lint `missing_docs = "warn"` est actif sur toutes les crates.

### Dépendances `feu-noyau`

| Crate | Usage |
|---|---|
| `aes-gcm` (`zeroize`) | Chiffrement AES-256-GCM des clés, blobs et archives |
| `aead` | Trait AEAD et initialisation des chiffreurs |
| `aead-stream` (`alloc`) | Chiffrement stream (`EncryptorBE32` / `DecryptorBE32`) des archives |
| `argon2` (`kdf`) | Dérivation Argon2id depuis le mot de passe |
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
| `thiserror` | Dérivation du type d'erreur |

Dev-dépendance : `tempfile` (dossiers temporaires des tests).

### Dépendances `feu-application`

| Crate | Usage |
|---|---|
| `feu-noyau` | Dépendance locale (chemin relatif) |
| `secrecy` | `SecretString` pour le mot de passe et la phrase seed |
| `thiserror` | Dérivation de `ErreurFeuApplication` |
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
| `thiserror` | Dérivation d'`ErreurFeuTui` |

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
5. **Les clés en clair n'existent qu'en mémoire.** Exception connue : un crash pendant la fermeture d'un foyer peut laisser un `.tar` non chiffré dans `~/.feu/` — le diagnostic le signale, le secours le répare.
6. **Gardien / Cryptographe** — le disque et le clair ne se rencontrent jamais dans le même composant.
7. **L'Archiviste ne voit jamais de clair** — uniquement des blobs chiffrés et des hashes. Le Tiroir zéroïse le blob en clair dès son remplacement par le chiffré, et à chaque vidage.
8. **Double chiffrement des blobs** — clé de classeur (permanent), puis clé d'archive du foyer (à la fermeture).
9. **Stratification stricte** — la présentation ne touche jamais le noyau : tout passe par `feu-application`.
10. **Identité stable** — la braise survit à toute migration de primitive, et l'adresse de transport future ne lui sera pas liée : se tromper d'adresse ne coûte rien, la donnée se vérifie contre son hash et n'est lisible que par son destinataire.
11. **L'intégrité avant la lecture** — une ENU n'est jamais consommée sans que son hash soit recalculé et sa signature vérifiée contre la clé du signataire annoncé (`Enu::charger`). La désérialisation seule ne valide que la structure.
12. **La braise n'est pas une autorité** — hors hash et hors signature, elle n'est qu'un indice de routage : la falsifier fait échouer la vérification, jamais accepter une enveloppe.
13. **Le nom de fichier est borné** — toute entrée matérialisée sur disque passe par la validation du composant de chemin (refus du vide, de `/`, de `.`/`..`) avant tout `Path::join` ; un nom lisible depuis une ENU ne peut pas faire écrire hors du dossier de retrait.
14. **Les ENU sont lisibles foyers fermés** — en clair sur disque, leur confidentialité est nulle mais leur intégrité est signée ; c'est ce qui autorise la navigation hors ouverture.
15. **Déduplication** — un même contenu (même hash de carte, même hash de blob) n'est stocké qu'une fois ; le dépôt d'un blob déjà présent ne duplique rien.
16. **Un seul Feu sur un nœud** — deux instances écriraient sur les mêmes archives et le même `scribe.feu` ; le verrou d'instance le rend impossible, et le système le relâche seul si le processus meurt.
