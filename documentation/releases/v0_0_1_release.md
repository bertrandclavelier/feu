# Feu — Release v0.0.1

> **Date :** 14 mars 2026
> **Statut :** première release
> **Licence :** GNU General Public License v3.0 ou ultérieure (GPL-3.0-or-later)
> **Photo technique** — ce document décrit l'état réel du code, pas les intentions de conception.

---

## Résumé

Première version fonctionnelle de Feu. Interface CLI persistante. Cycle de vie complet d'un nœud et de ses foyers locaux : initialisation depuis une seed BIP39, dérivation déterministe de l'ensemble des clés, ouverture et fermeture des foyers sous forme d'archives chiffrées, changement de mot de passe.

Aucun réseau. Aucune donnée utilisateur. Aucun classeur, registre ou ENU.

---

## Périmètre

Cette version pose les fondations cryptographiques et le cycle de vie local du nœud.

**Ce qui est implémenté :**

- Génération d'une seed BIP39 (12 mots, dictionnaire français)
- Dérivation hiérarchique SLIP-0010 de toutes les clés (nœud + 3 foyers)
- Stockage chiffré des clés privées et symétriques (Argon2id + AES-256-GCM)
- Ouverture/fermeture des foyers (archivage chiffré AES-256-GCM-stream)
- Changement de mot de passe avec rechiffrement atomique du trousseau
- Interface CLI persistante (Rustyline)

**Ce qui n'existe pas encore :**

- Réseau (Tor, gossip protocol)
- Classeurs, registre
- ENU (ENUd, ENUt, ENUr), IdNU
- Tiroir
- Relais, paquets

Les foyers sont créés en nombre fixe (`MAX_FOYERS = 3`) à l'initialisation. Aucune création ni suppression après coup.

---

## Architecture

Deux crates, séparation stricte entre logique et interface.

**`feu-core`** — logique du protocole, exposée via la structure `Feu<I>`. Aucun composant interne n'est accessible depuis l'extérieur.

**`feu-cli`** — interface CLI construite avec Rustyline. Implémente le trait `InterfaceFeuCore` et dispatche les commandes vers `feu-core`.

### Composants internes de `feu-core`

`Feu<I: InterfaceFeuCore>` est le point d'entrée unique. Il orchestre deux composants :

- **Gardien** — unique point d'accès au système de fichiers. Délègue la connaissance de l'arborescence à son `Carnet`. Maintient la configuration en mémoire via `Configuration`.
- **Cryptographe** — unique composant autorisé à manipuler des données en clair. Maintient les clés déchiffrées dans son `Trousseau`.

Cette séparation Gardien/Cryptographe est la décision architecturale fondatrice : le disque et la mémoire en clair ne se rencontrent jamais dans le même composant. L'isolation des surfaces d'attaque est structurelle, pas conventionnelle.

Le transfert de données entre les deux composants passe par une couche intermédiaire : **`TrousseauPublicNoeud`** et **`TrousseauPublicFoyer`** (module `cryptographe/trousseaux_publics.rs`). Ces structures encapsulent les clés sous forme chiffrée (`[u8; 60]` par clé) prêtes à l'écriture disque, ou lues depuis le disque avant déchiffrement. Le Gardien ne manipule que ces représentations opaques — jamais les clés en clair.

**`Session`** — état courant : nœud allumé ou non, état et adresse `.onion` de chaque foyer.

### Trait `InterfaceFeuCore`

Contrat entre `feu-core` et toute interface utilisateur. Quatre méthodes : affichage, affichage d'erreur, saisie texte, saisie mot de passe. Toute interface (CLI, GUI, tests) implémente ce trait.

### Gestion d'erreurs

Trois types d'erreur distincts, un par couche, construits avec la crate `thiserror` :

- `ErreurFeu` (`src/erreur.rs`) — erreurs exposées par l'API publique de `Feu<I>`
- `ErreurGardien` (`gardien/erreur.rs`) — erreurs filesystem et parsing
- `ErreurCryptographe` (`cryptographe/erreur.rs`) — erreurs cryptographiques (Argon2id, AES-GCM, HKDF, Ed25519)

Chaque couche expose ses conversions `From` vers la couche supérieure pour permettre la propagation avec `?`. `hkdf::InvalidLength` ne satisfaisant pas `std::error::Error`, sa conversion est implémentée manuellement.

---

## Commandes

| Commande | Description |
|---|---|
| `initialise` | Initialise un nœud vierge — `~/.feu` doit être absent |
| `allume` | Charge la configuration et déverrouille le trousseau |
| `eteins` | Éteint le nœud — exige que tous les foyers soient fermés |
| `ouvre <n>` | Ouvre le foyer d'index `n` (0 à MAX_FOYERS-1) |
| `ferme <n>` | Ferme le foyer d'index `n` |
| `change mdp` | Change le mot de passe et rechiffre le trousseau |
| `liste -F` | Affiche l'état et l'adresse `.onion` de chaque foyer |
| `liste -C` | Affiche la liste des commandes disponibles |
| `version` | Affiche la version de `feu-core` |
| `quitte` | Quitte le programme — exige que le nœud soit éteint |

### Contraintes d'état

- `eteins` : tous les foyers doivent être fermés.
- `ouvre` : le nœud doit être allumé, le foyer non déjà ouvert.
- `ferme` : le foyer doit être ouvert.
- `change mdp` : tous les foyers doivent être ouverts (clés en mémoire).
- `quitte` : le nœud doit être éteint. Un `Drop` sur `Feu` panique si `session.noeud == true` — filet de sécurité contre toute sortie non contrôlée.

---

## Cryptographie

### Mode logiciel

La v0.0.1 fonctionne en mode logiciel. L'architecture cible repose sur un hardware wallet, mais cette version reproduit le même processus de dérivation entièrement en mémoire : la seed et la clé maître SLIP-0010 sont générées, utilisées pour dériver l'ensemble des clés, puis détruites. Elles ne sont jamais stockées sur le disque.

Ce mode garantit la compatibilité avec l'intégration hardware wallet future — seule la source de dérivation changera, pas l'architecture.

### Dérivation des clés

La seed BIP39 (12 mots, dictionnaire français) est la racine absolue. L'arbre de dérivation est volontairement plat — un seul niveau de profondeur sépare le nœud des foyers. Toute la diversification se fait par le message signé.

1. **Seed BIP39** → **clé maître SLIP-0010** (label `"ed25519 seed"`) → détruite après dérivation.
2. **Clé du nœud** — chemin `m/0'` (Ed25519, dérivation durcie). Clé privée stockée chiffrée sur le disque.
3. **Clés de chaque foyer** — chemin `m/i'` (index 1 à MAX_FOYERS). La clé `m/i'` signe des messages normalisés ; chaque signature (64 octets) est passée à HKDF-SHA3-256 pour produire la clé opérationnelle.

HKDF est appelé avec `salt = None` (remplacé par un sel zéro de 32 octets, RFC 5869 §2.2) et `info = b""` (vide). La différentiation des clés opérationnelles est entièrement portée par le **message signé** (IKM), pas par le paramètre info.

| Message signé | Dérivation | Usage |
|---|---|---|
| `"feu-foyer-symetrique"` | HKDF → clé AES-256-GCM (32 octets) | Chiffrement de l'archive du foyer |
| `"feu-foyer-paire-signature"` | HKDF → seed Ed25519 → paire de clés | Signature réseau, dérivation de l'adresse `.onion` |
| `"feu-foyer-paire-chiffrement"` | HKDF → seed Ed25519 → conversion X25519 | Chiffrement réseau |
| `"feu-foyer-classeur1"` à `"feu-foyer-classeur5"` | HKDF → clé AES-256-GCM (32 octets) | Classeurs (dérivées puis détruites — non stockées en v0.0.1) |

Les clés de classeurs sont dérivées à l'initialisation pour valider la chaîne complète, puis effacées. Leur stockage sera traité lors de l'implémentation des classeurs.

### Sel Argon2id

Dérivé de façon déterministe : la clé privée du nœud signe le label `"feu-noeud-sel"`, les 16 premiers octets de la signature constituent le sel. Stocké en clair — toujours recalculable depuis la seed.

### Protection des clés au repos

Argon2id(mot de passe, sel) → clé éphémère AES-256-GCM (32 octets). Toutes les clés privées et symétriques sont chiffrées avec cette clé éphémère. La clé éphémère et le mot de passe sont zéroïsés dès le trousseau constitué.

Paramètres Argon2id effectifs (défaults de la crate, conformes aux recommandations minimales RFC 9106) :

| Paramètre | Valeur |
|---|---|
| m_cost | 19 456 KiB |
| t_cost | 2 itérations |
| p_cost | 1 thread |

### Zéroïsation des secrets

Les secrets en mémoire sont zéroïsés automatiquement au `Drop` via la crate `secrecy` (`SecretBox<[u8; N]>`). Les features `zeroize` sont activées sur les crates `aes-gcm`, `ed25519-dalek` et `bip39`. Le mot de passe et la clé éphémère sont stockés dans des `Option<SecretBox<...>>` mis à `None` explicitement après usage, déclenchant la zéroïsation immédiate.

### Adresse `.onion`

Dérivée de la clé publique de signature réseau du foyer selon le standard Tor v3 : `base32(clé_publique || checksum_SHA3-256 || version)`. C'est l'identifiant unique du foyer — nom du dossier et des archives sur le disque.

### Séparation des fonctions cryptographiques

| Algorithme | Fonction | Usage |
|---|---|---|
| Ed25519 | Signature | Clé de nœud (signature des IdNU à venir), signature réseau du foyer |
| X25519 | Échange de clés | Chiffrement réseau (non utilisé en v0.0.1) |
| AES-256-GCM | Chiffrement symétrique authentifié | Archives de foyer, protection des clés au repos |
| Argon2id | Dérivation depuis mot de passe | Protection du trousseau sur le disque |
| HKDF-SHA3-256 | Dérivation de clé | Production des clés opérationnelles depuis les signatures |

---

## Structure disque

Racine : `~/.feu/`. Permissions : dossiers `rwx------` (0o700), fichiers `rw-------` (0o600). Toutes les écritures de fichiers de clés sont atomiques : écriture dans `<chemin>.tmp` (0o600), puis `rename` sur la cible.

### Foyer fermé

```
~/.feu/
├── config.feu                    ← configuration globale (en clair)
├── .cles/
│   ├── sel.feu                   ← sel Argon2id, 16 octets (en clair)
│   ├── feu_sig.priv              ← clé privée de signature du nœud (chiffrée)
│   ├── feu_sig.pub               ← clé publique de signature du nœud (en clair)
│   ├── <onion1>.cle              ← clé symétrique d'archive foyer 1 (chiffrée)
│   ├── <onion2>.cle              ← clé symétrique d'archive foyer 2 (chiffrée)
│   └── <onion3>.cle              ← clé symétrique d'archive foyer 3 (chiffrée)
├── <onion1>.feu                  ← archive chiffrée foyer 1
├── <onion2>.feu                  ← archive chiffrée foyer 2
└── <onion3>.feu                  ← archive chiffrée foyer 3
```

### Foyer ouvert

L'archive `.feu` est absente. Le dossier est extrait à sa place :

```
~/.feu/
└── <onion>/
    └── .cles/
        ├── sig.priv              ← clé privée de signature réseau (chiffrée)
        ├── sig.pub               ← clé publique de signature réseau (en clair)
        ├── chif.priv             ← clé privée de chiffrement réseau (chiffrée)
        └── chif.pub              ← clé publique de chiffrement réseau (en clair)
```

### Format de `config.feu`

Fichier texte, `2 + MAX_FOYERS` lignes :

```
<version>
<prochain_index>
<adresse_onion_foyer_0>
<adresse_onion_foyer_1>
<adresse_onion_foyer_2>
```

`version` = `1`. `prochain_index` vaut `4` après initialisation (incrémenté d'une unité par foyer créé, soit 1 + 3 = 4). Il est réservé pour la révocation d'une IdNU ou d'une adresse `.onion` : quand un slot de foyer est révoqué (par choix ou compromission), il reçoit le prochain index de dérivation disponible, ce qui produit de nouvelles clés et une nouvelle adresse. Le nombre de foyers reste fixe. Non utilisé dans cette version.

### Format des clés sur disque

Clés chiffrées : 60 octets = `nonce (12) || ciphertext (32) || tag (16)`. Chiffrement AES-256-GCM, nonce aléatoire à chaque écriture.

Clés publiques : 32 octets bruts.

Sel Argon2id : 16 octets bruts, en clair.

### Archive du foyer

Fermeture : dossier → `.tar` → chiffrement AES-256-GCM-stream → `.feu`. L'archive `.tar` intermédiaire est supprimée après chiffrement.

Ouverture : `.feu` → déchiffrement AES-256-GCM-stream → `.tar` → extraction. L'archive `.feu` et le `.tar` sont supprimés après extraction.

**Format binaire de l'archive `.feu` :**

```
[nonce 7 octets] [chunk_1] [chunk_2] ... [chunk_n]
```

Chaque chunk : `plaintext (≤ 4096 octets) + tag AES-GCM (16 octets)` = au plus 4112 octets. Le nonce fait 7 octets (contrainte de la crate `aead/stream`, `EncryptorBE32`). `CHUNK_SIZE = 4096`.

**Nuance de sécurité :** le `.tar` est créé dans `~/.feu/` (même répertoire que les archives `.feu`), avec permissions 0o600. En cas de crash entre sa création et sa suppression, un `.tar` non chiffré contenant les données du foyer peut persister sur le disque.

---

## Changement de mot de passe

Exige que tous les foyers soient ouverts — toutes les clés doivent être en mémoire pour être rechiffrées.

Séquence : saisie du nouveau mot de passe (deux fois, avec vérification), dérivation Argon2id avec le sel existant, rechiffrement de toutes les clés (nœud + foyers), zéroïsation du mot de passe et de la clé éphémère, réécriture atomique de tous les fichiers de clés sur le disque. Le sel n'est pas modifié.

**Limitation v0.0.1 :** `change mdp` n'est fonctionnel que dans la session d'initialisation, avant toute fermeture de foyer. Après un cycle `ferme` / `ouvre`, les clés de classeurs ne sont pas rechargées depuis le disque — elles sont absentes du trousseau en mémoire. Le rechiffrement échoue. Cette limitation sera levée lors de l'implémentation des classeurs (v0.0.2+).

---

## Constantes

| Constante | Valeur | Rôle |
|---|---|---|
| `MAX_FOYERS` | 3 | Nombre de foyers par nœud, fixé à l'initialisation |
| `MAX_CLASSEURS` | 5 | Nombre de classeurs par foyer (dérivés puis détruits — non utilisés en v0.0.1) |

---

## Plateformes supportées

Linux et macOS uniquement. Le protocole repose sur des primitives Unix (permissions, `rename` atomique, variables d'environnement). Une erreur de compilation est levée sur toute autre plateforme.

---

## Environnement technique

**Edition Rust :** 2024.

### Dépendances `feu-core`

| Crate | Usage |
|---|---|
| `aes-gcm` (feature `zeroize`) | Chiffrement AES-256-GCM des clés et archives |
| `aead` (feature `stream`) | Chiffrement stream (`EncryptorBE32` / `DecryptorBE32`) |
| `argon2` (feature `std`) | Dérivation Argon2id depuis le mot de passe |
| `bip39` (features `rand`, `french`, `zeroize`) | Génération seed BIP39, dictionnaire français |
| `ed25519-dalek` (feature `zeroize`) | Paires de clés Ed25519, signature déterministe |
| `x25519-dalek` (feature `static_secrets`) | Paires de clés X25519 |
| `hkdf` | Dérivation HKDF-SHA3-256 |
| `sha3` | SHA3-256 (HKDF, adresses `.onion`) |
| `slip10_ed25519` | Dérivation hiérarchique SLIP-0010 Ed25519 |
| `secrecy` | `SecretBox<T>` — zéroïsation automatique au `Drop` |
| `tar` | Archivage/extraction des dossiers de foyer |
| `data-encoding` | Encodage BASE32 pour les adresses `.onion` |
| `rand` | Génération de nonces aléatoires (`OsRng`) |
| `thiserror` | Dérivation des types d'erreur |

### Dépendances `feu-cli`

| Crate | Usage |
|---|---|
| `rustyline` | Édition de ligne REPL avec historique |
| `rpassword` | Saisie mot de passe sans écho |
| `colored` | Mise en forme colorée de la sortie |

---

## Standards cryptographiques

| Standard | Objet | Référence |
|---|---|---|
| BIP39 | Seed mnémonique (12 mots) | bitcoin/bips/bip-0039 |
| SLIP-0010 | Dérivation hiérarchique Ed25519 (hardened uniquement) | satoshilabs/slips/slip-0010 |
| RFC 8032 | Ed25519 — signature déterministe | IETF RFC 8032, section 5.1 |
| RFC 7748 | X25519 — échange de clés, mapping birationnel Edwards↔Montgomery | IETF RFC 7748 |
| RFC 5869 | HKDF — dérivation de clé basée sur HMAC | IETF RFC 5869 |
| RFC 9106 | Argon2id — dérivation de clé depuis mot de passe | IETF RFC 9106 |
| NIST SP 800-38D | AES-256-GCM — chiffrement authentifié | NIST SP 800-38D |
| NIST FIPS 202 | SHA3-256 — primitive de hashage unique du protocole | NIST FIPS 202 |
| Tor v3 | Dérivation adresse `.onion` depuis clé publique Ed25519 | torspec/rend-spec-v3.txt |

---

## Garanties de sécurité

1. **La seed est la racine absolue** — tout dérive d'elle. En mode logiciel, elle est détruite en mémoire après dérivation.
2. **Toutes les clés sont dérivables depuis la seed** — la perte des clés est récupérable par ressaisie de la seed. Les archives chiffrées doivent être sauvegardées séparément.
3. **Une clé, un usage** — signature (Ed25519), échange de clés (X25519) et chiffrement symétrique (AES-256-GCM) sont strictement séparés.
4. **Les clés en clair n'existent qu'en mémoire** — sur le disque, toutes les clés privées et symétriques sont chiffrées. En cas de crash, aucun secret ne persiste. Exception : un crash pendant la fermeture d'un foyer peut laisser un fichier `.tar` non chiffré dans `~/.feu/`.
5. **Gardien/Cryptographe** — le disque et les données en clair ne se rencontrent jamais dans le même composant.

