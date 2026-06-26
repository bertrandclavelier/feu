# Feu — Release v0.0.4

> **Date :** 26 juin 2026
> **Statut :** quatrième release
> **Licence :** GNU General Public License v3.0 ou ultérieure (GPL-3.0-or-later)
> **Photo technique** — ce document décrit l'état réel du code, pas les intentions de conception.

---

## Résumé

Quatrième version. **Release de migration cryptographique : passage du noyau à une cryptographie purement post-quantique.** Toute donnée chiffrée par Feu résiste à un futur calculateur quantique. Le noyau est stable sur ce plan — aucun changement de primitive cryptographique n'est à prévoir.

Chaque primitive du noyau a été remplacée :
- **Signature :** Ed25519 → ML-DSA-87 (FIPS 204, niveau 5 ≈ AES-256)
- **Chiffrement asymétrique :** X25519/ECIES → ML-KEM-1024 (FIPS 203, niveau 5)
- **Dérivation :** SLIP-0010 → HKDF-SHA3-256 direct depuis la seed
- **Identité du foyer :** adresse `.onion` → adresse `.braise` (dérivée directement de la seed, indépendante de toute clé)

La seed passe de **12 à 24 mots** (256 bits d'entropie), alignée sur le niveau de sécurité 5.

La couche applicative et la TUI sont fonctionnellement inchangées. La restructuration en trois crates de la v0.0.3 est préservée. Aucun réseau, aucune ENU, IdNU, condition, relais ou paquet.

---

## Périmètre

**Ce qui change en v0.0.4 (migration post-quantique) :**

- Seed BIP39 : 24 mots (256 bits), français. Restauration acceptée pour 12, 15, 18, 21 ou 24 mots.
- Dérivation HKDF-SHA3-256 directe depuis la seed (64 o) — chaque clé descend directement de la seed, isolée par un label unique passé en `info` HKDF.
- Abandon de SLIP-0010 — dépendance `slip10_ed25519` retirée, plus aucune clé mère intermédiaire.
- Signature ML-DSA-87 — signatures de 4 627 o, clés publiques de 2 592 o.
- Chiffrement asymétrique ML-KEM-1024 — schéma KEM + HKDF + AES-256-GCM. Clés publiques de 1 568 o, enveloppes chiffrées avec un surcoût de 1 596 o.
- Identité foyer : adresse `.braise` (62 caractères), dérivée directement de la seed par HKDF (`feu/foyer/braise/{i}`), encodée en base32 avec checksum SHA3-256. Remplace l'adresse `.onion`.
- Vision réseau actée : l'onion est une adresse de transport jetable, sans lien avec la seed ni l'identité du foyer. Ni le noyau ni l'application ne la connaissent.
- Sel Argon2id désormais dérivé par HKDF depuis la seed (`feu/noeud/sel`) — découplé de la signature du nœud.
- Écran « à propos » dans la TUI (touche `!`), affichant la version (via `CARGO_PKG_VERSION`), la licence et le copyright.

**Ce qui reste inchangé depuis la v0.0.3 :**

- Architecture en trois crates : `feu-noyau`, `feu-application`, `feu-tui`.
- Gardien / Cryptographe / Archiviste — mêmes responsabilités, même séparation.
- Cycle de vie nœud (initialisation, allumage) et foyer (ouverture, fermeture, archivage chiffré).
- Stockage content-addressable par classeurs (SHA3-256), double chiffrement des blobs.
- Diagnostics de présence des fichiers du nœud et des foyers.
- Démarrage en secours (réparation depuis seed) et fermeture en secours d'un foyer.
- Changement de mot de passe avec rechiffrement atomique du trousseau.
- Chiffrement symétrique et hachage inchangés : AES-256-GCM, SHA3-256, Argon2id.
- Toute la structure disque, aux noms de dossiers/fichiers près (`<onion>` → `<braise>`).

**Ce qui n'existe pas :**

- Réseau (Tor, gossip protocol).
- ENU (ENUd, ENUt, ENUr), IdNU.
- Conditions, registre de conditions.
- Relais, paquets.
- Export/import de classeurs.
- Révocation de foyer (direction actée, non implémentée).
- Pilotage depuis la TUI des opérations de données, de signature, de chiffrement asymétrique, de diagnostic et de changement de mot de passe (identique à v0.0.3).
- Compatibilité ascendante avec les trousseaux v0.0.3 — les formats de clés ayant changé de taille, les données antérieures sont définitivement illisibles. Acceptable au stade actuel (pas de déploiement).

---

## Architecture

Trois crates, empilées en couches strictes. Chaque couche ne connaît que celle immédiatement en dessous. Inchangé depuis la v0.0.3.

```
┌────────────────────────────────────────────┐
│  feu-tui        présentation (TUI Ratatui)  │  binaire, deux threads
├────────────────────────────────────────────┤
│  feu-application  orchestration applicative │  unique consommateur du noyau
├────────────────────────────────────────────┤
│  feu-noyau        cœur du protocole         │  Gardien · Cryptographe · Archiviste
└────────────────────────────────────────────┘
```

- **`feu-noyau`** expose la structure `FeuNoyau`. Aucun composant interne n'est accessible depuis l'extérieur du crate.
- **`feu-application`** est l'**unique** consommateur de `feu-noyau` dans le workspace.
- **`feu-tui`** est un binaire qui consomme `feu-application` et pilote le terminal.

### Le noyau — composants internes

Inchangés depuis la v0.0.2. `FeuNoyau` orchestre :

- **Gardien** — unique point d'accès au système de fichiers. Délègue la connaissance de l'arborescence à son `Carnet`, maintient la `Configuration` en mémoire (miroir de `config.feu`).
- **Cryptographe** — unique composant autorisé à manipuler des données en clair. Maintient les clés déchiffrées dans son `Trousseau`.
- **Archiviste** — un par foyer ouvert, gère l'arborescence interne d'un foyer (registre + classeurs). Ne détient jamais de clés, ne voit jamais d'octets en clair. Transfert des blobs via le **Tiroir** (zéroïsation).

La séparation Gardien/Cryptographe reste la décision architecturale fondatrice : le disque et la mémoire en clair ne se rencontrent jamais dans le même composant.

---

## `feu-noyau`

### `InterfaceFeuNoyau`

Contrat entre le noyau et son appelant direct (`feu-application`). Sept méthodes :

| Méthode | Rôle |
|---|---|
| `demander_mdp` | Collecte d'un mot de passe masqué (`Option<SecretString>`) |
| `recevoir_seed` | Transmet les mots de la seed BIP39 à l'initialisation, avant zéroïsation |
| `confirmer_enregistrement_seed` | Demande confirmation que la seed est enregistrée ; `false` interrompt l'init |
| `recevoir_braise_foyer` | Notifie l'adresse `.braise` d'un foyer (allumage et init) |
| `recevoir_etat_foyer` | Notifie un changement d'état d'ouverture d'un foyer (ouverture/fermeture) |
| `recevoir_cle_publique_noeud` | Notifie la clé publique ML-DSA-87 du nœud à l'allumage (2 592 o) |
| `recevoir_cles_publiques_foyer` | Notifie les clés ML-DSA-87 (2 592 o) + ML-KEM-1024 (1 568 o) d'un foyer à son ouverture |

`recevoir_braise_foyer` remplace `recevoir_onion_foyer` de la v0.0.3. Les signatures et tailles de `recevoir_cle_publique_noeud` et `recevoir_cles_publiques_foyer` reflètent le passage à ML-DSA-87 et ML-KEM-1024.

### API publique de `FeuNoyau`

`FeuNoyau` est le point d'entrée unique. Son API est fonctionnellement identique à la v0.0.3 — seuls les types cryptographiques changent de taille.

| Méthode | Rôle | Mutabilité |
|---|---|---|
| `new` | Initialise (arborescence absente) **ou** allume (présente) le nœud. `Option<SecretString>` : nouvelle seed ou phrase fournie | associée |
| `demarrage_secours` | Répare l'arborescence d'un nœud existant depuis une seed (réécriture en deux passes) | associée |
| `changement_mdp` | Change le mot de passe et rechiffre tout le trousseau (exige tous les foyers ouverts) | `&mut self` |
| `ouverture_foyer` | Déchiffre l'archive, charge les clés, instancie l'Archiviste | `&mut self` |
| `fermeture_foyer_index` | Archive, chiffre, détruit l'Archiviste, supprime le dossier clair | `&mut self` |
| `secours_fermeture_foyer_index` | Ferme un foyer resté ouvert après arrêt anormal (recharge depuis le dossier clair) | `&mut self` |
| `depot_donnees` | Stocke un blob dans un classeur (chiffrement, hash, idempotence) | `&mut self` |
| `lecture_donnees` | Déchiffre un blob vers une destination | `&mut self` |
| `suppression_donnees` | Supprime un blob | `&self` |
| `liste_blobs` | Liste les hashes d'un classeur | `&self` |
| `existence_blob` | Teste l'existence d'un blob | `&self` |
| `informations_blob` | Métadonnées système d'un blob (`DonneesBlob`) | `&self` |
| `chiffrement_asymetrique` | Chiffre des octets via ML-KEM-1024 + HKDF + AES-256-GCM | `&self` |
| `dechiffrement_asymetrique` | Déchiffre un message KEM (foyer ouvert) | `&self` |
| `signature_noeud` | Signe avec la clé ML-DSA-87 du nœud — signature de 4 627 o | `&self` |
| `signature_foyer` | Signe avec la clé ML-DSA-87 d'un foyer (foyer ouvert) — signature de 4 627 o | `&self` |
| `verification_signature` | Vérifie une signature ML-DSA-87 (clé pub 2 592 o, signature 4 627 o) | `&self` |
| `diagnostic_noeud` | Diagnostic de présence des fichiers du nœud (sans modification) | associée |
| `diagnostic_foyer` | Diagnostic d'un foyer ouvert (clés, registre, liens) | `&self` |

`new` détecte automatiquement l'état du nœud : si `~/.feu` est absent, il initialise (génère ou restaure la seed, crée l'arborescence, ferme les foyers) ; sinon il allume (charge la configuration, déverrouille le trousseau).

Un `Drop` sur `FeuNoyau` **panique** si des foyers sont encore ouverts à la destruction.

### Contraintes d'état

Identiques à la v0.0.3 :
- `changement_mdp` : tous les foyers doivent être ouverts.
- `ouverture_foyer` : index valide, foyer non déjà ouvert.
- `fermeture_foyer_index` : foyer ouvert.
- `secours_fermeture_foyer_index` : diagnostic du foyer sans anomalie, dossier clair présent.
- Opérations de données : foyer ouvert, index de classeur valide.
- `dechiffrement_asymetrique`, `signature_foyer` : foyer ouvert. `chiffrement_asymetrique`, `signature_noeud` : nœud allumé.

---

## `feu-application`

Couche d'orchestration. Fonctionnellement inchangée depuis la v0.0.3. `FeuApplication` détient l'instance du noyau et l'état applicatif, valide les préconditions et expose une API stable (les `commande_*`) à la présentation.

Les types de `SessionApplication` reflètent les nouvelles tailles cryptographiques :
- clé publique de signature du nœud : 2 592 o
- clés publiques de signature des foyers : 2 592 o
- clés publiques de chiffrement des foyers : 1 568 o
- adresses `.braise` remplacent les adresses `.onion`

`RecepteurNoyau` route `recevoir_braise_foyer` vers `SessionApplication` (comme il le faisait pour `recevoir_onion_foyer`). Le reste de la mécanique — `InterfaceFeuApplication`, `SessionApplication`, cycle de vie, commandes — est inchangé.

### Commandes

| Commande | Rôle |
|---|---|
| `commande_allumage_noeud` | Initialise ou allume le nœud |
| `commande_extinction_noeud` | Éteint le nœud (exige tous les foyers fermés) |
| `commande_changement_mdp` | Change le mot de passe |
| `commande_ouverture_foyer` / `commande_fermeture_foyer` | Ouvre / ferme un foyer |
| `commande_secours_fermeture_foyer` | Ferme en secours un foyer resté ouvert |
| `commande_depot_donnees` / `commande_lecture_donnees` / `commande_suppression_donnees` | Cycle de vie des blobs |
| `commande_liste_blobs` / `commande_existence_blob` / `commande_information_blob` | Interrogation des blobs |
| `commande_chiffrement_asymetrique` / `commande_dechiffrement_asymetrique` | ML-KEM-1024 |
| `commande_signature_noeud` / `commande_signature_foyer` / `commande_verification_signature` | Signatures ML-DSA-87 |
| `commande_diagnostic_noeud` / `commande_diagnostic_foyer` | Diagnostics |

---

## `feu-tui`

Interface terminal sur Ratatui et crossterm, architecture à deux threads. Inchangée depuis la v0.0.3, à l'ajout près de l'écran « à propos » :

- **Touche `!`** — toujours active, quel que soit le contexte.
- Affiche un écran d'information (60×15) : titre « Feu », version via `env!("CARGO_PKG_VERSION")`, licence GPL-3.0-or-later, copyright.
- La sortie de l'écran se fait via la touche Entrée (mode `Information`).

Le reste — connecteurs, protocole de messages, boucle TUI, table de commandes contextuelle, navigation dans la pseudo-arborescence — est identique à la v0.0.3. Les opérations de données, signatures, chiffrement asymétrique, diagnostics et changement de mot de passe existent dans `feu-application` mais ne sont toujours pas câblés dans la TUI.

---

## Gestion d'erreurs

Chaîne de conversion `From` par couche inchangée. Chaque couche encapsule l'erreur de la couche inférieure dans une `String` via `.to_string()` — le type interne est perdu, seul le message textuel remonte.

| Type | Crate | Préfixe | Variantes notables |
|---|---|---|---|
| `ErreurFeuNoyau` | `feu-noyau` | `NOY >` | `Gardien`, `Cryptographe`, `Archiviste` (String) ; `IndexInvalide`, `FoyerDejaOuvert`, `FoyerFerme`, `TousFoyersNonOuverts`, `TailleMaxDepassee`, `BraiseIntrouvable`, … |
| `ErreurFeuApplication` | `feu-application` | `APP >` | `FeuNoyau(String)`, `Standard(String)`, `NoeudEteint`, `AuMoinsUnFoyerOuvert` |

`BraiseIntrouvable` remplace `OnionIntrouvable` de la v0.0.3. Au sein du noyau, les erreurs internes (`ErreurGardien`, `ErreurCryptographe`, `ErreurArchiviste`) sont inchangées.

---

## Cryptographie

La cryptographie est **intégralement refondue** dans cette release. Toutes les primitives asymétriques et le chemin de dérivation ont été remplacés par des équivalents post-quantiques. Les primitives symétriques et de hachage (AES-256-GCM, SHA3-256, Argon2id) restent en place — leur sécurité effective post-Grover est jugée suffisante (~128 bits).

### Mode logiciel

La seed et les clés dérivées existent exclusivement en mémoire. La seed est zéroïsée après dérivation. Rien n'est jamais stocké en clair sur le disque. Ce mode logiciel est un substitut temporaire au hardware wallet cible.

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

**Graine et keygen.** La graine fait 32 o (`derive_depuis_seed::<32>`), sauf pour la paire de chiffrement ML-KEM-1024 dont la seed fait 64 o (`derive_depuis_seed::<64>`) et le sel Argon2id qui fait 16 o (`derive_depuis_seed::<16>`).

| Usage | Keygen depuis la graine |
|---|---|
| Signature | `SigningKey::<MlDsa87>::from_seed` |
| Chiffrement | `DecapsulationKey1024::from_seed` (seed 64 o) |
| Symétrique | clé AES-256-GCM directe |
| Sel Argon2id | octets bruts (non secret, stocké en clair) |
| Braise | octets bruts encodés (identifiant public, non secret) |

### Sel Argon2id

Dérivé de façon déterministe depuis la seed par HKDF-SHA3-256, label `feu/noeud/sel`. 16 octets, stockés en clair — toujours recalculable depuis la seed.

Ce mécanisme remplace l'ancienne dérivation par signature du nœud, qui créait trois fragilités : dépendance à la présence préalable de la clé du nœud, réutilisation de la clé de signature pour un usage étranger, et dépendance au déterminisme de la primitive de signature (une signature ML-DSA en mode *hedged* aurait rendu le sel non reproductible).

### Protection des clés au repos

Argon2id(mot de passe, sel) → clé éphémère AES-256-GCM (32 o). Toutes les clés privées et symétriques sont chiffrées avec cette clé éphémère. La clé éphémère et le mot de passe sont zéroïsés dès le trousseau constitué.

Paramètres Argon2id effectifs (défauts de la crate, conformes aux recommandations minimales RFC 9106) :

| Paramètre | Valeur |
|---|---|
| m_cost | 19 456 KiB |
| t_cost | 2 itérations |
| p_cost | 1 thread |

### Signature ML-DSA-87

Signature purement post-quantique (FIPS 204, niveau 5 ≈ AES-256). Deux niveaux :

- **Nœud** (label `feu/noeud/signature`) — clé racine, signe les actes engageant le nœud dans sa globalité (IdNU, etc.).
- **Foyer** (label `feu/foyer/signature/{i}`) — authentifie les échanges du foyer (ENU, etc.).

La signature est **déterministe** avec l'implémentation `ml-dsa` 0.1 — pour une même clé et un même message, la signature est identique. Le protocole ne s'appuie pas sur ce déterminisme (le sel en a été découplé précisément pour cette raison).

Tailles :
- Seed privée : 32 o (stockée chiffrée : 60 o)
- Clé publique : 2 592 o
- Signature : 4 627 o

Taille des données limitée à `MAX_TAILLE_SIGNATURE` (64 Kio) — réservée aux structures légères.

### Chiffrement asymétrique ML-KEM-1024

Schéma **KEM + HKDF + AES-256-GCM** purement post-quantique (FIPS 203, niveau 5). ML-KEM-1024 est un mécanisme d'encapsulation de clé, pas un chiffrement de message direct. Le processus côté émetteur :

1. Reconstruit la clé publique ML-KEM-1024 depuis les 1 568 octets.
2. **Encapsulation** ML-KEM-1024 → ciphertext KEM (1 568 o) + secret partagé (32 o).
3. Dérive une clé AES-256-GCM via HKDF-SHA3-256 sur le secret partagé (`info = "feu-chiffrement-asymetrique"`).
4. Chiffre le message avec AES-256-GCM (nonce aléatoire de 12 o).
5. Zéroïse le secret partagé et la clé dérivée.

Côté destinataire, la **décapsulation** avec la clé privée ML-KEM-1024 retrouve le secret partagé.

**Format de l'enveloppe asymétrique :**

```
[0..1568]    ciphertext ML-KEM-1024 (1 568 o)
[1568..1580] nonce AES-GCM (12 o)
[1580..]     ciphertext + auth tag (16 o)
```

Soit un surcoût fixe de **1 596 o** par rapport au clair.

Tailles :
- Seed privée : 64 o (stockée chiffrée : 92 o)
- Clé publique : 1 568 o

Taille des données limitée à `MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE` (1 Mio) — l'intégralité du message est en mémoire. La vérification amont dans `FeuNoyau` borne à `MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE + 1596` côté déchiffrement.

### Braise — identité du foyer

La **braise** est l'identifiant public et invariant d'un foyer. Sa forme textuelle est l'adresse `.braise` (62 caractères).

Elle est dérivée directement de la seed par HKDF-SHA3-256 avec le label `feu/foyer/braise/{i}`, **indépendamment de toute clé cryptographique**. Contrairement à l'ancienne adresse `.onion` (qui dérivait de la clé publique Ed25519 du foyer), la braise survit à toute migration de primitive — la montée ML-KEM-768 → 1024 en v0.0.4 n'a changé aucune braise.

**Dérivation :**

```
seed master (64 o)
   └─ HKDF-SHA3-256(info = "feu/foyer/braise/{i}") → 32 o bruts (la braise)
```

**Encodage de l'adresse `.braise` :**

```
checksum = SHA3-256("feu/braise/checksum" || braise)[..2]        (2 o)
adresse  = BASE32_NOPAD(braise || checksum).to_lowercase() + ".braise"
```

- **Checksum (2 o)** — détecte une faute de frappe. Le préfixe de domaine `feu/braise/checksum` empêche le checksum d'être valide hors de ce contexte.
- **BASE32_NOPAD** — alphabet `a-z2-7`, sans padding `=` : l'adresse est utilisable telle quelle comme nom de dossier. 34 o → 55 caractères.
- **Suffixe `.braise`** — marqueur de type. Adresse finale : 62 caractères (`55 + ".braise"`).

La braise est l'identifiant unique du foyer de bout en bout : clé de `config.feu`, nom du dossier `~/.feu/<braise>/`, nom des archives `<braise>.feu` et `<braise>.tar`.

### Chiffrement symétrique des blobs

Inchangé. Chaque classeur possède sa propre clé AES-256-GCM (32 o), dérivée et stockée chiffrée sur le disque. Le chiffrement d'un blob produit : `nonce (12 o) || ciphertext || auth tag (16 o)`. Le hash SHA3-256 est calculé sur le clair **avant** chiffrement — il sert d'identifiant content-addressable.

### Double chiffrement

Inchangé. Un blob est protégé par deux couches :

1. **Chiffrement classeur** (foyer ouvert) — AES-256-GCM avec clé dédiée au classeur. Permanent.
2. **Chiffrement archive** (foyer fermé) — AES-256-GCM-stream avec clé symétrique du foyer. Le dossier entier du foyer est compressé en tar puis chiffré en `.feu`.

### Zéroïsation des secrets

Deux mécanismes complémentaires (inchangés, adaptés aux nouveaux types) :

- `SecretBox<T>` (crate `secrecy`) — wrapping explicite des secrets dont le type implémente `Zeroize`. L'accès au contenu est contraint à `expose_secret()` / `expose_secret_mut()`.
- `ZeroizeOnDrop` (crate `zeroize`) — utilisé pour `SigningKey<MlDsa87>` (ml-dsa) et `DecapsulationKey1024` (ml-kem), dont les types n'implémentent pas `Zeroize` et ne peuvent pas être encapsulés dans `SecretBox`.

Le Tiroir zéroïse le blob en clair lors du remplacement par le blob chiffré (`remplace_blob`) et lors du vidage (`vider`).

Les features `zeroize` sont activées sur `aes-gcm`, `bip39`, `ml-dsa` et `ml-kem`.

### Séparation des fonctions cryptographiques

| Algorithme | Fonction | Usage |
|---|---|---|
| ML-DSA-87 | Signature post-quantique | Clé de nœud, signature du foyer |
| ML-KEM-1024 | Encapsulation de clé post-quantique | Chiffrement asymétrique réseau |
| AES-256-GCM | Chiffrement symétrique authentifié | Archives de foyer, protection des clés au repos, chiffrement des blobs, chiffrement KEM |
| Argon2id | Dérivation depuis mot de passe | Protection du trousseau sur le disque |
| HKDF-SHA3-256 | Dérivation de clé | Production de toutes les clés depuis la seed, dérivation de clé KEM |
| SHA3-256 | Hashage | Identifiants content-addressable des blobs, checksum des adresses `.braise` |

---

## Structure disque

Racine : `~/.feu/`. Permissions : dossiers `rwx------` (0o700), fichiers `rw-------` (0o600). Toutes les écritures de fichiers de clés sont atomiques : écriture dans `<chemin>.tmp` (0o600), puis `rename` sur la cible.

La structure est identique à la v0.0.3, aux noms près : `<braise>` remplace `<onion>`.

### Foyer fermé

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
└── <braise3>.feu                 ← archive chiffrée foyer 3
```

### Foyer ouvert

L'archive `.feu` est absente. Le dossier est extrait à sa place :

```
~/.feu/
└── <braise>/
    ├── .cles/
    │   ├── sig.priv              ← clé privée de signature réseau (chiffrée, 60 o)
    │   ├── sig.pub               ← clé publique de signature réseau (en clair, 2 592 o)
    │   ├── chif.priv             ← clé privée ML-KEM-1024 (chiffrée, 92 o)
    │   ├── chif.pub              ← clé publique ML-KEM-1024 (en clair, 1 568 o)
    │   ├── classeur0.cle         ← clé AES-256-GCM du classeur 0 (chiffrée, 60 o)
    │   ├── classeur1.cle         ← clé AES-256-GCM du classeur 1 (chiffrée, 60 o)
    │   ├── classeur2.cle         ← clé AES-256-GCM du classeur 2 (chiffrée, 60 o)
    │   ├── classeur3.cle         ← clé AES-256-GCM du classeur 3 (chiffrée, 60 o)
    │   └── classeur4.cle         ← clé AES-256-GCM du classeur 4 (chiffrée, 60 o)
    ├── registre/
    │   ├── classeur.0  → ../       ← lien symbolique vers la racine du foyer
    │   ├── classeur.1  → ../
    │   ├── classeur.2  → ../
    │   ├── classeur.3  → ../
    │   └── classeur.4  → ../
    ├── classeur0/
    │   └── <hash>.dat            ← blob chiffré AES-256-GCM
    ├── classeur1/
    ├── classeur2/
    ├── classeur3/
    └── classeur4/
```

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

Inchangé. Fichier `<hash>.dat` dans `classeurN/`. Contenu : `nonce (12 o) || ciphertext || auth tag (16 o)`. Le hash (nom de fichier) est le SHA3-256 en hexadécimal minuscule du blob **en clair**.

### Archive du foyer

Inchangé. Fermeture : dossier → `.tar` → chiffrement AES-256-GCM-stream → `.feu`. Ouverture : `.feu` → déchiffrement → `.tar` → extraction. Les archives intermédiaires `.tar` et `.feu` sont supprimées après usage.

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
| `TAILLE_CHUNK` | 8 192 o | Granularité de lecture d'un blob par le Tiroir (en mémoire), `pub(crate)` |
| `NOMBRE_MOTS_SEED` | 24 | Nombre de mots de la seed BIP39 (constante privée au cryptographe) |
| `CHUNK_SIZE` | 4 096 o | Taille des chunks du stream AES-256-GCM des archives `.feu` (constante privée au cryptographe) |

---

## Plateformes supportées

Linux et macOS uniquement. Le noyau repose sur des primitives Unix (permissions, liens symboliques, `rename` atomique, variables d'environnement) et lève une erreur de compilation sur toute autre plateforme.

---

## Environnement technique

**Edition Rust :** 2024. Version `0.0.4` et licence `GPL-3.0-or-later` définies au niveau workspace. Le lint `missing_docs = "warn"` est actif sur toutes les crates.

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

**Dépendances retirées** depuis la v0.0.3 : `ed25519-dalek`, `x25519-dalek`, `slip10_ed25519`.

### Dépendances `feu-application`

| Crate | Usage |
|---|---|
| `feu-noyau` | Dépendance locale (chemin relatif) |
| `secrecy` | `SecretString` pour le mot de passe et la phrase seed |
| `thiserror` | Dérivation de `ErreurFeuApplication` |

### Dépendances `feu-tui`

| Crate | Usage |
|---|---|
| `feu-application` | Dépendance locale (chemin relatif) |
| `ratatui` | Rendu de l'interface terminal |
| `crossterm` | Événements clavier, gestion du terminal |
| `secrecy` | `SecretString` (mot de passe, mots de la seed) |

---

## Standards cryptographiques

| Standard | Objet | Référence |
|---|---|---|
| BIP39 | Seed mnémonique (24 mots, 256 bits) | bitcoin/bips/bip-0039 |
| NIST FIPS 203 | ML-KEM — Module-Lattice-based Key Encapsulation Mechanism | NIST FIPS 203 |
| NIST FIPS 204 | ML-DSA — Module-Lattice-based Digital Signature Algorithm | NIST FIPS 204 |
| RFC 5869 | HKDF — dérivation de clé basée sur HMAC | IETF RFC 5869 |
| NIST FIPS 202 | SHA3-256 — Keccak | NIST FIPS 202 |
| RFC 9106 | Argon2id — dérivation de clé depuis mot de passe | IETF RFC 9106 |
| NIST SP 800-38D | AES-256-GCM — chiffrement authentifié | NIST SP 800-38D |

---

## Garanties de sécurité

1. **La seed est la racine absolue** — tout dérive d'elle. En mode logiciel, elle est détruite en mémoire après dérivation. 24 mots, 256 bits d'entropie.
2. **Toutes les clés sont dérivables depuis la seed** — la perte des clés est récupérable par ressaisie de la seed. Les archives chiffrées et les blobs doivent être sauvegardés séparément.
3. **Une clé, un usage** — ML-DSA-87 (signature), ML-KEM-1024 (chiffrement), AES-256-GCM (symétrique) sont strictement séparés. La séparation de domaine est structurelle (labels HKDF), pas conventionnelle.
4. **Résistance post-quantique** — toutes les primitives asymétriques sont de niveau NIST 5 (≈ AES-256). Les primitives symétriques (AES-256-GCM, SHA3-256, Argon2id) conservent ~128 bits de sécurité post-Grover.
5. **Les clés en clair n'existent qu'en mémoire** — sur le disque, toutes les clés privées et symétriques sont chiffrées. Exception connue : un crash pendant la fermeture d'un foyer peut laisser un `.tar` non chiffré dans `~/.feu/`.
6. **Gardien / Cryptographe** — le disque et le clair ne se rencontrent jamais dans le même composant.
7. **L'Archiviste ne voit jamais de clair** — uniquement des blobs chiffrés et des hashes.
8. **Le Tiroir zéroïse** — le blob en clair est zéroïsé dès remplacement par le chiffré, et à chaque vidage.
9. **Double chiffrement des blobs** — clé de classeur (permanent), puis clé d'archive du foyer (à la fermeture).
10. **Stratification stricte** — la présentation (`feu-tui`) ne touche jamais le noyau directement : tout passe par `feu-application`.
11. **Identité stable** — la braise est indépendante de toute clé cryptographique ; elle survit à toute migration de primitive.
12. **Adresse réseau jetable** — l'adresse de transport (`.onion` future) n'est pas liée à la seed ni à l'identité du foyer. Se tromper d'adresse ne coûte rien : la donnée se vérifie contre son hash et n'est lisible que par son destinataire.
