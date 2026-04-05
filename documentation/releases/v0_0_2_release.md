# Feu — Release v0.0.2

> **Date :** 5 avril 2026
> **Statut :** deuxième release
> **Licence :** GNU General Public License v3.0 ou ultérieure (GPL-3.0-or-later)
> **Photo technique** — ce document décrit l'état réel du code, pas les intentions de conception.

---

## Résumé

Deuxième version. Introduit l'Archiviste, le stockage content-addressable par classeurs, le chiffrement asymétrique ECIES, la signature Ed25519 (nœud et foyer), la vérification de signature avec résistance à la malléabilité, et le diagnostic de santé du nœud et des foyers.

Le nœud gère désormais un cycle de vie complet des données : dépôt, lecture, suppression, listage de blobs chiffrés dans des classeurs avec clés individuelles. Les clés de classeurs sont stockées sur disque et rechargées à chaque ouverture de foyer.

Aucun réseau. Aucun ENU, IdNU, condition, relais ou paquet.

---

## Périmètre

**Ce qui est ajouté en v0.0.2 :**

- Archiviste — gestionnaire de l'arborescence interne d'un foyer ouvert (registre, classeurs, blobs)
- Tiroir — objet de transfert éphémère avec zéroïsation entre Archiviste et Cryptographe
- Stockage content-addressable — hash SHA3-256 du clair comme identifiant, idempotence du dépôt
- Classeurs (5 par foyer) — chiffrement AES-256-GCM par classeur avec clé dédiée
- Registre — liens symboliques `registre/classeur.N → ../classeurN/` par foyer
- Clés de classeurs sur disque — `classeur0.cle` à `classeur4.cle` dans `<onion>/.cles/`
- Chiffrement asymétrique — schéma ECIES X25519 + HKDF-SHA3-256 + AES-256-GCM
- Signature Ed25519 — nœud (`m/0'`) et foyer (`m/index'`)
- Vérification de signature — `verify_strict` pour résistance à la malléabilité
- Check-up nœud — diagnostic de présence des fichiers structurels sans modification
- Check-up foyer — diagnostic des clés, du registre et des liens symboliques
- Exposition des clés publiques — `recevoir_cle_publique_noeud` et `recevoir_cles_publiques_foyer` via `InterfaceFeuCore`
- Métadonnées blob — `DonneesBlob` (taille, dates système)
- Anomalies — `Anomalie::ElementAbsent`, `Anomalie::ConfigurationIllisible`

**Ce qui existait déjà en v0.0.1 et reste fonctionnel :**

- Génération seed BIP39, dérivation SLIP-0010
- Cycle de vie nœud (initialisation, allumage, extinction)
- Cycle de vie foyer (ouverture, fermeture, archivage chiffré)
- Changement de mot de passe avec rechiffrement atomique
- Interface CLI persistante (Rustyline)

**Ce qui n'existe pas :**

- Réseau (Tor, gossip protocol)
- ENU (ENUd, ENUt, ENUr), IdNU
- Conditions, registre de conditions
- Relais, paquets
- Export/import de classeurs

---

## Architecture

Deux crates, séparation stricte entre logique et interface.

**`feu-core`** — logique du protocole, exposée via la structure `Feu<I>`. Aucun composant interne n'est accessible depuis l'extérieur.

**`feu-cli`** — interface CLI de test construite avec Rustyline. Implémente le trait `InterfaceFeuCore` et dispatche les commandes vers `feu-core`.

### Composants internes de `feu-core`

`Feu<I: InterfaceFeuCore>` est le point d'entrée unique. Il orchestre trois composants :

- **Gardien** — unique point d'accès au système de fichiers. Délègue la connaissance de l'arborescence à son `Carnet`. Maintient la configuration en mémoire via `Configuration`.
- **Cryptographe** — unique composant autorisé à manipuler des données en clair. Maintient les clés déchiffrées dans son `Trousseau`.
- **Archiviste** — gestionnaire de l'arborescence interne d'un foyer ouvert. Un Archiviste par foyer ouvert, instancié à l'ouverture, détruit à la fermeture. Ne détient jamais de clés et ne voit jamais d'octets en clair.

La séparation Gardien/Cryptographe est la décision architecturale fondatrice : le disque et la mémoire en clair ne se rencontrent jamais dans le même composant. L'isolation des surfaces d'attaque est structurelle, pas conventionnelle.

Le transfert de données entre les composants passe par deux couches intermédiaires :

- **Trousseaux publics** (`cryptographe/trousseaux_publics.rs`) — `TrousseauPublicNoeud`, `TrousseauPublicFoyer`, `TrousseauPublicComplet`. Encapsulent les clés sous forme chiffrée (`[u8; 60]` par clé) prêtes à l'écriture disque, ou lues depuis le disque avant déchiffrement. Le Gardien ne manipule que ces représentations opaques.
- **Tiroir** (`archiviste/tiroir.rs`) — objet de transfert éphémère entre Archiviste et Cryptographe. Transporte un blob depuis sa source jusqu'à son classeur en passant par le Cryptographe. Le blob en clair est zéroïsé dès remplacement par le blob chiffré.

**`Session`** — état courant : nœud allumé ou non, état et adresse `.onion` de chaque foyer.

**`Foyer`** — état d'un foyer dans la session : adresse `.onion` et booléen d'ouverture.

---

## `InterfaceFeuCore`

Contrat entre `feu-core` et toute interface utilisateur. Six méthodes :

| Méthode | Rôle |
|---|---|
| `afficher` | Affichage informatif (provisoire) |
| `afficher_erreur` | Affichage d'erreur (provisoire) |
| `demander` | Collecte d'une réponse utilisateur |
| `demander_mdp` | Collecte d'un mot de passe masqué |
| `recevoir_cle_publique_noeud` | Notification : clé publique Ed25519 du nœud à l'allumage |
| `recevoir_cles_publiques_foyer` | Notification : clé Ed25519 + clé X25519 du foyer à l'ouverture |

`afficher` et `afficher_erreur` sont provisoires — afficher depuis le noyau est conceptuellement incorrect.

`recevoir_cle_publique_noeud` transmet la clé publique de signature Ed25519 du nœud. Le nœud n'expose qu'une clé de signature, pas de clé de chiffrement — choix architectural délibéré.

`recevoir_cles_publiques_foyer` transmet la clé de signature Ed25519 et la clé de chiffrement X25519 du foyer à son ouverture.

---

## Gestion d'erreurs

Quatre types d'erreur distincts, un par couche, construits avec la crate `thiserror` :

- `ErreurFeu` (`src/erreur.rs`) — erreurs exposées par l'API publique de `Feu<I>`. Quatre variantes : `Gardien`, `Cryptographe`, `Archiviste`, `Standard`.
- `ErreurGardien` (`gardien/erreur.rs`) — erreurs filesystem et parsing.
- `ErreurCryptographe` (`cryptographe/erreur.rs`) — erreurs cryptographiques (Argon2id, AES-GCM, HKDF, Ed25519, décodage hexadécimal).
- `ErreurArchiviste` (`archiviste/erreur.rs`) — erreurs sur l'arborescence du foyer. Deux variantes : `Interne` (message textuel), `IoError` (entrée/sortie).

Chaque couche expose ses conversions `From` vers `ErreurFeu` pour permettre la propagation avec `?`. Le type interne est perdu — seul le message textuel est propagé, préservant l'encapsulation. `hkdf::InvalidLength`, `aes_gcm::Error` et `data_encoding::DecodePartial` ne satisfont pas `std::error::Error` — leurs conversions vers `ErreurCryptographe` sont implémentées manuellement.

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
| `depose <chemin>` | Dépose un fichier dans le classeur 0 du foyer 0 |
| `lire <dest> <hash>` | Déchiffre et écrit un blob dans `<dest>` (foyer 0, classeur 0) |
| `supprime <hash>` | Supprime un blob du classeur 0 du foyer 0 |
| `liste -F` | Affiche l'état et l'adresse `.onion` de chaque foyer |
| `liste -C` | Affiche la liste des commandes disponibles |
| `version` | Affiche la version de `feu-core` |
| `quitte` | Quitte le programme — exige que le nœud soit éteint |

### Commandes du noyau non exposées par la CLI de test

L'API publique de `Feu<I>` expose des commandes que la CLI de test n'utilise pas :

| Méthode | Description |
|---|---|
| `commande_chiffrement_asymetrique` | Chiffre des octets via ECIES X25519 |
| `commande_dechiffrement_asymetrique` | Déchiffre un message ECIES |
| `commande_signature_noeud` | Signe avec la clé du nœud |
| `commande_signature_foyer` | Signe avec la clé d'un foyer |
| `commande_verification_signature` | Vérifie une signature Ed25519 (`verify_strict`) |
| `commande_check_up_noeud` | Diagnostic du nœud (fonction associée) |
| `commande_check_up_foyer` | Diagnostic d'un foyer ouvert |
| `commande_blob_existe` | Teste l'existence d'un blob dans un classeur |
| `commande_liste_blobs` | Liste les hashes d'un classeur |
| `commande_informations_blob` | Métadonnées système d'un blob |

### Contraintes d'état

- `eteins` : tous les foyers doivent être fermés.
- `ouvre` : le nœud doit être allumé, le foyer non déjà ouvert.
- `ferme` : le foyer doit être ouvert.
- `change mdp` : tous les foyers doivent être ouverts (clés en mémoire).
- `quitte` : le nœud doit être éteint. Un `Drop` sur `Feu` panique si `session.noeud == true` — filet de sécurité contre toute sortie non contrôlée.
- Toutes les commandes données (dépôt, lecture, suppression, liste, existence, informations) : le foyer doit être ouvert.
- Chiffrement asymétrique : le nœud doit être allumé. Le foyer n'a pas besoin d'être ouvert pour chiffrer (seule la clé publique du destinataire est requise), mais doit être ouvert pour déchiffrer (clé privée X25519 nécessaire).
- Signature nœud : le nœud doit être allumé. Signature foyer : le foyer doit être ouvert.
- Vérification de signature : le nœud doit être allumé.
- Check-up nœud : fonction associée, utilisable sans nœud allumé.
- Check-up foyer : le nœud doit être allumé et le foyer ouvert.

---

## Cryptographie

### Mode logiciel

L'architecture cible repose sur un hardware wallet. Cette version reproduit le même processus de dérivation entièrement en mémoire : la seed et la clé maître SLIP-0010 sont générées, utilisées pour dériver l'ensemble des clés, puis détruites. Elles ne sont jamais stockées sur le disque.

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
| `"feu-foyer-classeur1"` à `"feu-foyer-classeur5"` | HKDF → clé AES-256-GCM (32 octets) | Clés de classeurs — stockées chiffrées sur le disque |

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

### Chiffrement symétrique des blobs

Chaque classeur possède sa propre clé AES-256-GCM (32 octets), dérivée et stockée chiffrée sur le disque. Le chiffrement d'un blob produit : `nonce (12 octets) || ciphertext || auth tag (16 octets)`. Le hash SHA3-256 est calculé sur le clair **avant** chiffrement — il sert d'identifiant content-addressable.

L'idempotence du dépôt est assurée : si un blob portant le même hash existe déjà dans le classeur, le hash est retourné silencieusement sans réécriture.

### Double chiffrement

Un blob est protégé par deux couches :

1. **Chiffrement classeur** (foyer ouvert) — AES-256-GCM avec clé dédiée au classeur. Permanent : le blob est stocké chiffré dans `classeurN/<hash>.dat`.
2. **Chiffrement archive** (foyer fermé) — AES-256-GCM-stream avec clé symétrique du foyer. Le dossier entier du foyer (incluant les blobs déjà chiffrés) est compressé en tar puis chiffré en `.feu`.

### Chiffrement asymétrique (ECIES)

Schéma ECIES sur X25519, pour chiffrer des données à destination d'un foyer identifié par sa clé publique X25519 :

1. Génère une paire X25519 éphémère.
2. ECDH : `secret_partagé = clé_éphémère_privée × clé_pub_destinataire`.
3. Dérive une clé AES-256-GCM via HKDF-SHA3-256 (`info = "feu-chiffrement-asymetrique"`).
4. Chiffre avec AES-256-GCM (nonce aléatoire).
5. Zéroïse le secret partagé et la clé dérivée.

Format de sortie :

```
[0..32]  clé éphémère publique X25519
[32..44] nonce AES-GCM (12 octets)
[44..]   ciphertext + auth tag (16 octets)
```

Taille limitée à `MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE` (1 Mio) — l'intégralité du message est en mémoire.

### Signature Ed25519

Deux niveaux de signature :

- **Nœud** (`m/0'`) — clé racine, signe les actes engageant le nœud dans sa globalité.
- **Foyer** (`m/index'`, message `"feu-foyer-paire-signature"`) — authentifie les échanges du foyer.

Taille limitée à `MAX_TAILLE_SIGNATURE` (64 Kio) — destiné aux structures légères.

La vérification utilise `verify_strict` (ed25519-dalek) — résistance aux attaques par malléabilité de signature.

### Zéroïsation des secrets

Deux mécanismes complémentaires :

- `SecretBox<T>` (crate `secrecy`) — wrapping explicite des secrets dont le type implémente `Zeroize`. L'accès au contenu est contraint à `expose_secret()` / `expose_secret_mut()`.
- `ZeroizeOnDrop` (crate `zeroize`) — utilisé pour `SigningKey` (ed25519-dalek), dont le type n'implémente pas `Zeroize` et ne peut pas être encapsulé dans `SecretBox`.

Les features `zeroize` sont activées sur `aes-gcm`, `ed25519-dalek` et `bip39`. Le mot de passe et la clé éphémère sont stockés dans des `Option<SecretBox<...>>` mis à `None` explicitement après usage.

Le Tiroir zéroïse le blob en clair lors du remplacement par le blob chiffré (`remplace_blob`) et lors du vidage (`vider`).

### Adresse `.onion`

Dérivée de la clé publique de signature réseau du foyer selon le standard Tor v3 : `base32(clé_publique || checksum_SHA3-256 || version)`. C'est l'identifiant unique du foyer — nom du dossier et des archives sur le disque.

### Séparation des fonctions cryptographiques

| Algorithme | Fonction | Usage |
|---|---|---|
| Ed25519 | Signature | Clé de nœud, signature réseau du foyer |
| X25519 | Échange de clés | Chiffrement ECIES, clé de chiffrement réseau du foyer |
| AES-256-GCM | Chiffrement symétrique authentifié | Archives de foyer, protection des clés au repos, chiffrement des blobs, chiffrement ECIES |
| Argon2id | Dérivation depuis mot de passe | Protection du trousseau sur le disque |
| HKDF-SHA3-256 | Dérivation de clé | Production des clés opérationnelles depuis les signatures, dérivation de clé ECIES |
| SHA3-256 | Hashage | Identifiants content-addressable des blobs, adresses `.onion` |

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
    ├── .cles/
    │   ├── sig.priv              ← clé privée de signature réseau (chiffrée)
    │   ├── sig.pub               ← clé publique de signature réseau (en clair)
    │   ├── chif.priv             ← clé privée de chiffrement réseau (chiffrée)
    │   ├── chif.pub              ← clé publique de chiffrement réseau (en clair)
    │   ├── classeur0.cle         ← clé AES-256-GCM du classeur 0 (chiffrée)
    │   ├── classeur1.cle         ← clé AES-256-GCM du classeur 1 (chiffrée)
    │   ├── classeur2.cle         ← clé AES-256-GCM du classeur 2 (chiffrée)
    │   ├── classeur3.cle         ← clé AES-256-GCM du classeur 3 (chiffrée)
    │   └── classeur4.cle         ← clé AES-256-GCM du classeur 4 (chiffrée)
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

Les liens symboliques du registre pointent tous vers `../` (racine du foyer). Le chemin effectif d'un classeur est résolu en deux étapes : `registre/classeur.N` → `../` → `classeurN/`, soit `registre/classeur.N/classeurN/`. L'archivage tar préserve les liens tels quels (`follow_symlinks(false)`) — les suivre provoquerait une boucle infinie car ils pointent vers le dossier parent qui contient le registre lui-même.

### Format de `config.feu`

Fichier texte, `2 + MAX_FOYERS` lignes :

```
<version>
<prochain_index>
<adresse_onion_foyer_0>
<adresse_onion_foyer_1>
<adresse_onion_foyer_2>
```

`version` = `1`. `prochain_index` vaut `4` après initialisation (incrémenté d'une unité par foyer créé, soit 1 + 3 = 4). Il est réservé pour la révocation d'une adresse `.onion` : quand un slot de foyer est révoqué, il reçoit le prochain index de dérivation disponible, ce qui produit de nouvelles clés et une nouvelle adresse. Le nombre de foyers reste fixe.

### Format des clés sur disque

Clés chiffrées : 60 octets = `nonce (12) || ciphertext (32) || tag (16)`. Chiffrement AES-256-GCM, nonce aléatoire à chaque écriture.

Clés publiques : 32 octets bruts.

Sel Argon2id : 16 octets bruts, en clair.

### Format des blobs

Fichier `<hash>.dat` dans `classeurN/`. Le contenu est : `nonce (12 octets) || ciphertext || auth tag (16 octets)`. Le hash (nom de fichier) est le SHA3-256 en hexadécimal minuscule du blob **en clair**.

### Archive du foyer

Fermeture : dossier → `.tar` → chiffrement AES-256-GCM-stream → `.feu`. L'archive `.tar` intermédiaire est supprimée après chiffrement.

Ouverture : `.feu` → déchiffrement AES-256-GCM-stream → `.tar` → extraction. L'archive `.feu` et le `.tar` sont supprimés après extraction.

**Format binaire de l'archive `.feu` :**

```
[nonce 7 octets] [chunk_1] [chunk_2] ... [chunk_n]
```

Chaque chunk : `plaintext (≤ TAILLE_CHUNK octets) + tag AES-GCM (16 octets)`. Le nonce fait 7 octets (contrainte de la crate `aead/stream`, `EncryptorBE32`). `TAILLE_CHUNK = 8192`.

**Nuance de sécurité :** le `.tar` est créé dans `~/.feu/` (même répertoire que les archives `.feu`), avec permissions 0o600. En cas de crash entre sa création et sa suppression, un `.tar` non chiffré contenant les données du foyer peut persister sur le disque.

---

## Changement de mot de passe

Exige que tous les foyers soient ouverts — toutes les clés doivent être en mémoire pour être rechiffrées.

Séquence : saisie du nouveau mot de passe (deux fois, avec vérification), dérivation Argon2id avec le sel existant, rechiffrement de toutes les clés (nœud + foyers + classeurs), zéroïsation du mot de passe et de la clé éphémère, réécriture atomique de tous les fichiers de clés sur le disque. Le sel n'est pas modifié.

---

## Constantes

| Constante | Valeur | Rôle |
|---|---|---|
| `MAX_FOYERS` | 3 | Nombre de foyers par nœud, fixé à l'initialisation |
| `MAX_CLASSEURS` | 5 | Nombre de classeurs par foyer |
| `MAX_TAILLE_BLOB` | 512 Mio (536 870 912 octets) | Taille maximum d'un blob en clair |
| `MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE` | 1 Mio (1 048 576 octets) | Taille maximum d'un message ECIES |
| `MAX_TAILLE_SIGNATURE` | 64 Kio (65 536 octets) | Taille maximum d'un message à signer |
| `TAILLE_CHUNK` | 8 192 octets | Taille des chunks stream AES-GCM |

---

## Plateformes supportées

Linux et macOS uniquement. Le protocole repose sur des primitives Unix (permissions, liens symboliques, `rename` atomique, variables d'environnement). Une erreur de compilation est levée sur toute autre plateforme.

---

## Environnement technique

**Edition Rust :** 2024.

### Dépendances `feu-core`

| Crate | Usage |
|---|---|
| `aes-gcm` (features `std`, `zeroize`) | Chiffrement AES-256-GCM des clés, blobs et archives |
| `aead` (feature `stream`) | Chiffrement stream (`EncryptorBE32` / `DecryptorBE32`) |
| `argon2` (feature `std`) | Dérivation Argon2id depuis le mot de passe |
| `bip39` (features `rand`, `french`, `zeroize`) | Génération seed BIP39, dictionnaire français |
| `ed25519-dalek` (feature `zeroize`) | Paires de clés Ed25519, signature déterministe, vérification stricte |
| `x25519-dalek` (feature `static_secrets`) | Paires de clés X25519, ECDH |
| `hkdf` | Dérivation HKDF-SHA3-256 |
| `sha3` | SHA3-256 (HKDF, adresses `.onion`, hash content-addressable) |
| `slip10_ed25519` | Dérivation hiérarchique SLIP-0010 Ed25519 |
| `secrecy` | `SecretBox<T>` — zéroïsation automatique au `Drop` |
| `zeroize` | `Zeroize`, `ZeroizeOnDrop` — zéroïsation du Tiroir et des `SigningKey` |
| `tar` | Archivage/extraction des dossiers de foyer |
| `data-encoding` | Encodage BASE32 (adresses `.onion`), encodage HEXLOWER (hashes) |
| `rand` | Génération de nonces aléatoires (`OsRng`) |
| `thiserror` | Dérivation des types d'erreur |

### Dépendances `feu-cli`

| Crate | Usage |
|---|---|
| `rustyline` | Édition de ligne REPL avec historique |
| `rpassword` | Saisie mot de passe sans écho |
| `colored` | Mise en forme colorée de la sortie |
| `data-encoding` | Encodage HEXLOWER (affichage des hashes dans la CLI) |
| `feu-core` | Dépendance locale (chemin relatif) |

---

## Standards cryptographiques

| Standard | Objet | Référence |
|---|---|---|
| BIP39 | Seed mnémonique (12 mots) | bitcoin/bips/bip-0039 |
| SLIP-0010 | Dérivation hiérarchique Ed25519 (hardened uniquement) | satoshilabs/slips/slip-0010 |
| RFC 8032 | Ed25519 — signature déterministe, vérification stricte | IETF RFC 8032, section 5.1 |
| RFC 7748 | X25519 — échange de clés (ECIES), mapping birationnel Edwards↔Montgomery | IETF RFC 7748 |
| RFC 5869 | HKDF — dérivation de clé basée sur HMAC | IETF RFC 5869 |
| RFC 9106 | Argon2id — dérivation de clé depuis mot de passe | IETF RFC 9106 |
| NIST SP 800-38D | AES-256-GCM — chiffrement authentifié | NIST SP 800-38D |
| NIST FIPS 202 | SHA3-256 — hashage des blobs, adresses `.onion`, HKDF | NIST FIPS 202 |
| Tor v3 | Dérivation adresse `.onion` depuis clé publique Ed25519 | torspec/rend-spec-v3.txt |

---

## Garanties de sécurité

1. **La seed est la racine absolue** — tout dérive d'elle. En mode logiciel, elle est détruite en mémoire après dérivation.
2. **Toutes les clés sont dérivables depuis la seed** — la perte des clés est récupérable par ressaisie de la seed. Les archives chiffrées et les blobs doivent être sauvegardés séparément.
3. **Une clé, un usage** — signature (Ed25519), échange de clés (X25519) et chiffrement symétrique (AES-256-GCM) sont strictement séparés.
4. **Les clés en clair n'existent qu'en mémoire** — sur le disque, toutes les clés privées et symétriques sont chiffrées. En cas de crash, aucun secret ne persiste. Exception : un crash pendant la fermeture d'un foyer peut laisser un fichier `.tar` non chiffré dans `~/.feu/`.
5. **Gardien/Cryptographe** — le disque et les données en clair ne se rencontrent jamais dans le même composant.
6. **L'Archiviste ne voit jamais de clair** — il manipule uniquement des blobs chiffrés et des hashes. Il ne détient aucune clé.
7. **Le Tiroir zéroïse** — le blob en clair est zéroïsé dès remplacement par le chiffré, et à chaque vidage.
8. **Double chiffrement des blobs** — chaque blob est protégé par sa clé de classeur (permanent), puis par la clé d'archive du foyer (à la fermeture).
