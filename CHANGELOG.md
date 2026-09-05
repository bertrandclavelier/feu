# Changelog

Toutes les versions de Feu, de la plus récente à la plus ancienne.

Aucune version n'a été déployée : les ruptures de format sont assumées d'une
version à l'autre, et les données d'une version antérieure ne sont pas reprises.

La photo technique complète de la version courante vit dans
[documentation/note_de_version.md](documentation/note_de_version.md). Les notes
des versions antérieures restent atteignables à leur tag, par exemple
`git show v0.0.4:documentation/releases/v0_0_4_release.md` ou
`git show v0.0.5:documentation/release.md` — le fichier a porté trois noms.

---

## v0.0.7 — 5 septembre 2026

Version du **comptoir de travail** : le sous-arbre d'une ENU répertoire sort en
clair dans un dossier, on l'y modifie librement, et Feu le reprend à la
fermeture — le disque fait alors autorité. Deux autres chantiers la portent : la
persistance des comptoirs, et les bornes portées par les types.

- **Comptoir de travail** : ouverture et fermeture côté Scribe, câblées dans la
  TUI sur la touche `T`. Ce qui n'a pas bougé sur le disque est réemployé tel
  quel — même ENU, même signature ; une entrée effacée disparaît de l'arbre, une
  entrée nouvelle rejoint le foyer de son accueil. Un seul comptoir de travail à
  la fois, et jamais avec un comptoir de dépôt ouvert : l'exclusivité est portée
  par l'enum `Comptoirs`, pas par une garde à écrire.
- **Comptoirs persistants** : leur état est sérialisé dans `.config/scribe.feu`
  et rouvert à l'allumage.
- **Verrou d'instance** : un seul Feu à la fois sur un nœud. Le verrou est posé
  à l'allumage dans `~/.feu/verrou` et relâché par le système à la mort du
  processus — rien à nettoyer après un arrêt brutal.
- **Index typés** : `IndexFoyer` et `IndexClasseur`, bornés par construction,
  remontés jusqu'à la TUI ; les gardes de bornes disparaissent au profit du
  type, et les cardinaux sont portés par `IndexFoyer::NOMBRE` et
  `IndexClasseur::NOMBRE`. L'arborescence des ENU affiche le foyer et le
  classeur de chaque entrée.
- **Hashs de blob en `[u8; 32]`** dans toute l'API du noyau ; `existence_blob`
  rend le classeur qui détient le blob plutôt qu'un booléen.
- **ENU** : `Carte` extraite dans son module, date de création en méta de la
  carte — donc sous la signature —, version du format sérialisé, et unicité des
  noms d'enfants tenue au dépôt plutôt qu'au retrait.
- **Cohorte RustCrypto montée** (`aes-gcm` 0.11, `argon2` 0.6, `hkdf` 0.13,
  `sha3` 0.11) ; le chiffrement stream des archives vient d'`aead-stream`.
- **86 tests**, contre 67 : les bout-en-bout du noyau et de l'application passent
  en crates externes `tests/`, où c'est le compilateur qui tient l'inaccessibilité
  des composants internes.
- Cryptographie inchangée. Toujours aucun réseau.

## v0.0.6 — 22 août 2026

Première version dont la chaîne fonctionne de bout en bout : un utilisateur
ouvre un foyer, y dépose une arborescence, la ressort, la parcourt, sans quitter
la TUI. Trois chantiers la portent — la refonte de la gestion des erreurs, les comptoirs de dépôt et le
retrait en lecture seule, et le câblage de la TUI.

- **Gestion des erreurs refondue** : un seul type par crate — `ErreurFeuNoyau`
  (46 variantes), `ErreurFeuApplication` (26), `ErreurFeuTui` (13). Les types de
  module et les codes numérotés (`GAR-*`, `SCR-NNN`, `ENU-NNN`…) disparaissent au
  profit de variantes nommées. La TUI structure les siennes sans jamais
  interrompre sa boucle : seule une panne du terminal sort du programme.
- **Itérateurs ENU** : `Descendants` (profondeur d'abord, sans vérification de
  signature, doublons conservés) et `RacinesAnterieures` (remonte les racines
  jusqu'à la genèse), parcourables foyers fermés.
- **`Enu` privée, `Fiche` en frontière** : la présentation ne manipule plus que
  des fiches — l'enveloppe, sans sa signature, rechargée et authentifiée avant
  toute action.
- **Comptoirs multiples** : plusieurs comptoirs simultanés, désignés par leur
  chemin et par leur ENU d'accueil, identifiés par un compteur jamais remis à
  zéro.
- **Retrait gardé** : refusé d'un bloc si un foyer signataire du sous-arbre est
  fermé — la liste des foyers à ouvrir est dressée avant toute écriture.
- **Fermeture de secours câblée** jusqu'à la TUI (touche `S`).
- **TUI à trois écrans de travail** : pilotage, arborescence des ENU,
  arborescence du disque — navigation `h`/`l`, plis, marquage `m`/`x`, dépôt
  `d` et retrait `r` sur les marques posées.
- **Dépôt gardé** : refusé sous une ENU d'accueil sortie de l'arbre courant.
  Déposer sous une racine périmée produisait jusque-là une version amputée de
  tout ce qui avait été déposé depuis, sans la moindre erreur.
- **67 tests**, contre 61, tous intégrés aux crates.
- Cryptographie inchangée. Toujours aucun réseau.

## v0.0.5 — 12 août 2026

Intégration des ENU, les Enveloppes Numériques Universelles, jusque-là absentes
du code. Une couche applicative neuve, le **Scribe**, tient une arborescence
d'enveloppes signées qui nomme et organise les blobs du nœud sans jamais les
toucher. Second chantier de la version : le code ne comportait aucun test, il en
compte 61.

- **ENU** : enveloppe signée `Enu` et carte `Carte` (Donnée, Texte, Répertoire),
  content-addressed, signature ML-DSA-87 sur la carte, sérialisation maison.
  Exposées en lecture seule.
- **Arborescence** tenue à la racine du nœud, donc lisible foyers fermés :
  racines signées par le nœud, chaînées par la méta `_racine`, sommet courant
  désigné par le symlink `.DERNIERE_RACINE`.
- **Comptoir de dépôt** : un dossier est rempli puis refermé, son contenu est
  rangé en blobs et en ENU, puis greffé sous la racine du nœud. Piloté depuis la
  TUI (`d` ouvre depuis un classeur, `c` ferme).
- **Retrait en lecture seule** : matérialisation de l'arborescence d'une ENUr
  dans un dossier OS, sans reprise (`r`).
- **Accès aux blobs par l'ENU seule**, sans désigner ni foyer ni classeur.
- **Type `Braise`** dans le noyau (`[u8; 55]`), qui remplace la `String` partout ;
  API recentrée sur l'index, dépôt garantissant l'unicité d'un hash dans le foyer.
- **61 tests** là où il n'y en avait aucun, 24 pour `feu-noyau` et 37 pour
  `feu-application`, intégrés aux crates plutôt que dans un dossier `tests/`.
- Cryptographie inchangée. Toujours aucun réseau.

## v0.0.4 — 26 juin 2026

Migration cryptographique : le noyau passe à une cryptographie **purement
post-quantique**, chaque primitive étant remplacée. Le noyau est stable sur ce
plan, aucun changement de primitive n'est prévu. La couche applicative et la TUI
sont fonctionnellement inchangées.

- **Signature** : Ed25519 → ML-DSA-87 (FIPS 204, niveau 5).
- **Chiffrement asymétrique** : X25519/ECIES → ML-KEM-1024 (FIPS 203, niveau 5).
- **Dérivation** : SLIP-0010 → HKDF-SHA3-256 directe depuis la seed, chaque clé
  isolée par un label unique. Plus aucune clé mère intermédiaire.
- **Seed** : 12 → 24 mots (256 bits d'entropie), aligné sur le niveau 5. La
  restauration reste acceptée pour 12, 15, 18, 21 ou 24 mots.
- **Identité du foyer** : adresse `.onion` → adresse `.braise` (62 caractères),
  dérivée directement de la seed et indépendante de toute clé. L'onion redevient
  ce qu'elle est, une adresse de transport jetable que le noyau ignore.
- Sel Argon2id dérivé par HKDF depuis la seed, découplé de la signature du nœud.
- Écran « à propos » dans la TUI (touche `!`) : version, licence, copyright.
- **Rupture** : les formats de clés ayant changé de taille, les trousseaux
  v0.0.3 sont définitivement illisibles.

## v0.0.3 — 22 juin 2026

Restructuration architecturale, **sans aucune nouvelle fonctionnalité métier**.
L'objectif est de poser des fondations stables avant d'aborder le réseau et les
couches hautes du protocole. Le noyau reste le même : mêmes primitives, même
structure disque, mêmes garanties.

- Workspace réorganisé de deux crates en **trois** : `feu-noyau`,
  `feu-application`, `feu-tui`, empilées en couches strictes.
- `feu-core` renommé `feu-noyau`, code fonctionnellement identique.
- `feu-cli` (CLI Rustyline) supprimée, remplacée par **`feu-tui`** (Ratatui, deux
  threads).
- **`feu-application`** intercalée entre le noyau et la présentation, unique
  consommateur du noyau : elle orchestre les commandes, valide les préconditions
  et tient l'état de session.
- `InterfaceFeuNoyau` refondue : les méthodes d'affichage provisoires disparaissent
  au profit d'un modèle de notification *push*.
- API publique du noyau renommée, le préfixe `commande_` passant à
  `feu-application`.
- Contrainte de longueur minimale du mot de passe retirée.
- **Limite assumée** : toutes les fonctions du noyau ne sont pas encore câblées à
  la TUI, qui ne pilote que le cycle de vie du nœud, celui des foyers et la
  navigation.

## v0.0.2 — 5 avril 2026

Le nœud gère un cycle de vie complet des données : dépôt, lecture, suppression et
listage de blobs chiffrés, rangés dans des classeurs à clés individuelles.

- **Archiviste** : gestionnaire de l'arborescence interne d'un foyer ouvert
  (registre, classeurs, blobs). Il ne détient jamais de clé et ne voit jamais
  d'octets en clair.
- **Stockage content-addressable** : le hash SHA3-256 du clair sert
  d'identifiant, ce qui rend le dépôt idempotent.
- **Classeurs**, cinq par foyer, chiffrés en AES-256-GCM avec une clé dédiée
  chacun, stockée sur disque et rechargée à l'ouverture du foyer.
- **Registre** : liens symboliques par foyer vers les classeurs.
- **Chiffrement asymétrique** ECIES (X25519 + HKDF-SHA3-256 + AES-256-GCM).
- **Signature Ed25519** pour le nœud et pour le foyer, vérifiée en
  `verify_strict` pour résister à la malléabilité.
- **Tiroir** : objet de transfert éphémère entre Archiviste et Cryptographe, avec
  zéroïsation.
- **Diagnostics** de présence des fichiers structurels du nœud et des foyers,
  sans modification.

## v0.0.1 — 14 mars 2026

Première version fonctionnelle. Elle pose les fondations cryptographiques et le
cycle de vie local du nœud, derrière une CLI persistante. Aucune donnée
utilisateur, aucun classeur, aucune ENU.

- **Seed BIP39** de 12 mots, dictionnaire français.
- **Dérivation hiérarchique SLIP-0010** de toutes les clés, nœud et trois foyers.
- **Stockage chiffré** des clés privées et symétriques (Argon2id + AES-256-GCM).
- **Cycle de vie des foyers** : ouverture et fermeture sous forme d'archives
  chiffrées (AES-256-GCM-stream).
- **Changement de mot de passe** avec rechiffrement atomique du trousseau.
- Interface CLI persistante (Rustyline), sur deux crates : `feu-core` et
  `feu-cli`.
- Foyers en nombre fixe, créés à l'initialisation, ni ajout ni suppression ensuite.
