# Feu — Release v0.0.3

> **Date :** 22 juin 2026
> **Statut :** troisième release
> **Licence :** GNU General Public License v3.0 ou ultérieure (GPL-3.0-or-later)
> **Photo technique** — ce document décrit l'état réel du code, pas les intentions de conception.

---

## Résumé

Troisième version. **Release de restructuration : aucune nouvelle fonctionnalité métier.** L'objectif est de poser des fondations architecturales stables avant d'avancer sur le réseau et les couches supérieures du protocole.

Le workspace passe de **deux crates** (`feu-core` + `feu-cli`) à **trois** :

- **`feu-noyau`** — l'ancien `feu-core`, renommé. Le cœur du protocole. Fonctionnellement identique à la v0.0.2, à des ajustements près (voir plus bas).
- **`feu-application`** — nouvelle couche applicative. Unique consommateur de `feu-noyau`, elle orchestre les commandes, valide les préconditions et maintient l'état applicatif de session.
- **`feu-tui`** — nouvelle interface TUI (Ratatui), à deux threads, qui remplace la CLI de test Rustyline (`feu-cli`).

Le **noyau reste le même** : mêmes primitives cryptographiques, même structure disque, mêmes garanties de sécurité. Les ajustements portent sur la surface d'API (renommages, modèle de notification *push* à la place des appels d'affichage provisoires) et sur quelques fonctions de réparation et de diagnostic explicitées.

**Toutes les fonctionnalités du noyau ne sont pas pilotables depuis la TUI** : ce n'était pas l'objectif de cette release. La TUI ne câble aujourd'hui que l'allumage/extinction du nœud, l'ouverture/fermeture de foyer et la navigation. Le dépôt de données, les signatures, le chiffrement asymétrique, les diagnostics et le changement de mot de passe existent dans `feu-application` mais ne sont pas encore reliés à l'interface.

Aucun réseau. Aucun ENU, IdNU, condition, relais ou paquet.

---

## Périmètre

**Ce qui change en v0.0.3 (restructuration) :**

- Workspace réorganisé en trois crates : `feu-noyau`, `feu-application`, `feu-tui`.
- `feu-core` → `feu-noyau` (renommage, code fonctionnellement identique).
- `feu-cli` (CLI Rustyline) supprimée, remplacée par `feu-tui` (TUI Ratatui à deux threads).
- Nouvelle couche `feu-application` intercalée entre le noyau et la présentation.
- `InterfaceFeuNoyau` refondue : suppression des méthodes d'affichage provisoires (`afficher`, `afficher_erreur`, `demander`), adoption d'un modèle de notification *push* (`recevoir_seed`, `confirmer_enregistrement_seed`, `recevoir_onion_foyer`, `recevoir_etat_foyer`).
- API publique du noyau renommée : les méthodes perdent le préfixe `commande_` (porté désormais par `feu-application`). Exemple : `commande_depot_donnees` du noyau v0.0.2 devient `depot_donnees`.
- Contrainte de longueur minimale du mot de passe retirée du noyau (zéro contrainte, ni noyau ni TUI).

**Ce qui reste du noyau v0.0.2 (inchangé) :**

- Gardien / Cryptographe / Archiviste — mêmes responsabilités, même séparation.
- Génération seed BIP39, dérivation SLIP-0010, arbre de dérivation plat.
- Cycle de vie nœud (initialisation, allumage) et foyer (ouverture, fermeture, archivage chiffré).
- Stockage content-addressable par classeurs (SHA3-256), double chiffrement des blobs.
- Chiffrement asymétrique ECIES X25519, signatures Ed25519 (nœud et foyer), vérification stricte.
- Diagnostics de présence des fichiers du nœud et des foyers.
- Démarrage en secours (réparation depuis seed) et fermeture en secours d'un foyer.
- Changement de mot de passe avec rechiffrement atomique du trousseau.
- Toute la cryptographie et toute la structure disque (détaillées dans les sections dédiées plus bas).

**Ce qui n'existe pas :**

- Réseau (Tor, gossip protocol).
- ENU (ENUd, ENUt, ENUr), IdNU.
- Conditions, registre de conditions.
- Relais, paquets.
- Export/import de classeurs.
- Pilotage depuis la TUI des opérations de données, de signature, de chiffrement asymétrique, de diagnostic et de changement de mot de passe.

---

## Architecture

Trois crates, empilées en couches strictes. Chaque couche ne connaît que celle immédiatement en dessous.

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
- **`feu-application`** est l'**unique** consommateur de `feu-noyau` dans le workspace. La présentation ne touche jamais directement le noyau.
- **`feu-tui`** est un binaire qui consomme `feu-application` et pilote le terminal.

Cette stratification est l'apport principal de la v0.0.3 : elle isole le protocole (`feu-noyau`), sa logique d'orchestration (`feu-application`) et son rendu (`feu-tui`) dans des unités de compilation séparées, ouvrant la voie à d'autres présentations (une autre interface, un accès programmatique) sans toucher au cœur.

### Le noyau — composants internes

Inchangés depuis la v0.0.2. `FeuNoyau` orchestre :

- **Gardien** — unique point d'accès au système de fichiers. Délègue la connaissance de l'arborescence à son `Carnet`, maintient la `Configuration` en mémoire (miroir de `config.feu`).
- **Cryptographe** — unique composant autorisé à manipuler des données en clair. Maintient les clés déchiffrées dans son `Trousseau`.
- **Archiviste** — un par foyer ouvert, gère l'arborescence interne d'un foyer (registre + classeurs). Ne détient jamais de clés, ne voit jamais d'octets en clair. Transfert des blobs via le **Tiroir** (zéroïsation).

La séparation Gardien/Cryptographe reste la décision architecturale fondatrice : le disque et la mémoire en clair ne se rencontrent jamais dans le même composant.

---

## `feu-noyau`

### `InterfaceFeuNoyau` (refondue)

Contrat entre le noyau et son appelant direct (`feu-application`). Le modèle a changé : les anciennes méthodes d'affichage provisoires (`afficher`, `afficher_erreur`, `demander`), conceptuellement incorrectes — afficher depuis le noyau n'est pas son rôle — sont supprimées au profit de **notifications d'état poussées** vers l'appelant.

| Méthode | Rôle |
|---|---|
| `demander_mdp` | Collecte d'un mot de passe masqué (`Option<SecretString>`) |
| `recevoir_seed` | Transmet les mots de la seed BIP39 à l'initialisation, avant zéroïsation |
| `confirmer_enregistrement_seed` | Demande confirmation que la seed est enregistrée ; `false` interrompt l'init |
| `recevoir_onion_foyer` | Notifie l'adresse `.onion` d'un foyer (allumage et init) |
| `recevoir_etat_foyer` | Notifie un changement d'état d'ouverture d'un foyer (ouverture/fermeture) |
| `recevoir_cle_publique_noeud` | Notifie la clé publique Ed25519 du nœud à l'allumage |
| `recevoir_cles_publiques_foyer` | Notifie les clés Ed25519 + X25519 d'un foyer à son ouverture |

Le trait remplit **deux rôles distincts**, et c'est cette distinction qui guide sa conception :

- **Entrées** — le noyau réclame ce dont il a besoin et **attend la réponse** : le mot de passe (`demander_mdp`) et la confirmation d'enregistrement de la seed (`confirmer_enregistrement_seed`, qui peut interrompre l'initialisation). C'est le noyau qui décide *quand* et *pourquoi* réclamer le mot de passe, parce qu'il est le seul à le savoir. Ce choix minimise la fenêtre d'exposition du secret en mémoire — l'appelant ne détient jamais le mot de passe plus longtemps que l'instant de la saisie, et n'a pas à anticiper les besoins du noyau.
- **Notifications poussées** — les cinq autres méthodes (`recevoir_seed`, `recevoir_onion_foyer`, `recevoir_etat_foyer`, `recevoir_cle_publique_noeud`, `recevoir_cles_publiques_foyer`) retournent `()` : le noyau **pousse** une information au moment exact où elle devient disponible, sans rien attendre en retour. Ce sont des changements que l'appelant ne pourrait pas observer autrement (seed à l'initialisation, adresses `.onion`, états d'ouverture, clés publiques). L'appelant en fait ce qu'il veut — les stocker, les afficher, les ignorer ; le noyau, lui, ne suppose rien de la nature de la présentation.

**Principe de conception commun aux deux interfaces du workspace** : l'interface est **passée en paramètre** à chaque méthode qui en a besoin, jamais stockée dans une struct. `FeuNoyau` ne possède pas son `InterfaceFeuNoyau` ; il le reçoit à l'appel et le rend à la fin. Ce choix supprime tout problème de propriété et de durée de vie (pas de `lifetime` ni de générique à porter dans la structure), et garantit que le protocole reste totalement découplé de sa couche de présentation — un même `FeuNoyau` peut être piloté par des interfaces différentes au fil de ses appels.

### API publique de `FeuNoyau`

`FeuNoyau` est le point d'entrée unique. Ses méthodes ont perdu le préfixe `commande_` (déplacé dans `feu-application`).

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
| `chiffrement_asymetrique` | Chiffre des octets via ECIES X25519 | `&self` |
| `dechiffrement_asymetrique` | Déchiffre un message ECIES (foyer ouvert) | `&self` |
| `signature_noeud` | Signe avec la clé du nœud (`m/0'`) | `&self` |
| `signature_foyer` | Signe avec la clé d'un foyer (foyer ouvert) | `&self` |
| `verification_signature` | Vérifie une signature Ed25519 (`verify_strict`) | `&self` |
| `diagnostic_noeud` | Diagnostic de présence des fichiers du nœud (sans modification) | associée |
| `diagnostic_foyer` | Diagnostic d'un foyer ouvert (clés, registre, liens) | `&self` |

`new` détecte automatiquement l'état du nœud : si `~/.feu` est absent, il initialise (génère ou restaure la seed, crée l'arborescence, ferme les foyers) ; sinon il allume (charge la configuration, déverrouille le trousseau).

Un `Drop` sur `FeuNoyau` **panique** si des foyers sont encore ouverts à la destruction — filet de sécurité contre toute sortie silencieuse laissant un dossier clair sur le disque.

### Contraintes d'état (inchangées)

- `changement_mdp` : tous les foyers doivent être ouverts (clés en mémoire).
- `ouverture_foyer` : index valide, foyer non déjà ouvert.
- `fermeture_foyer_index` : foyer ouvert.
- `secours_fermeture_foyer_index` : diagnostic du foyer sans anomalie, dossier clair présent.
- Opérations de données : foyer ouvert, index de classeur valide.
- `dechiffrement_asymetrique`, `signature_foyer` : foyer ouvert. `chiffrement_asymetrique`, `signature_noeud` : nœud allumé.

---

## `feu-application`

Couche d'orchestration, introduite en v0.0.3. `FeuApplication` détient l'instance du noyau et l'état applicatif, valide les préconditions et expose une API stable (les `commande_*`) à la présentation.

### Rôle et choix de conception

`feu-application` est **l'unique consommateur de `feu-noyau`** dans le workspace : aucune autre crate n'a le droit d'appeler le noyau directement. Cet invariant — *toute interaction avec `feu-noyau` passe par `FeuApplication`* — est ce qui donne son sens à la couche. Il concentre en un seul endroit :

- **la validation des préconditions applicatives** avant de toucher au noyau (par exemple : refuser l'extinction tant qu'un foyer est ouvert, ou rejeter toute commande tant que le nœud n'est pas allumé via `ErreurFeuApplication::NoeudEteint`) ;
- **la traduction des erreurs** du noyau vers un type stable (`ErreurFeuApplication`) qui ne laisse fuiter aucun détail interne ;
- **la tenue de l'état applicatif de session** (`SessionApplication`), que le noyau ne maintient pas pour la présentation.

Ce point de passage unique est aussi un **point d'ancrage** : c'est depuis `FeuApplication` que d'autres crates pourront être branchées par la suite selon les besoins du protocole (un sous-système réseau, par exemple), chacune orchestrée au même endroit, derrière la même API stable, sans que la présentation ni le noyau aient à changer. La couche existe précisément pour absorber cette croissance future sans la diffuser dans le reste du workspace.

Enfin, `feu-application` est volontairement **synchrone et ignorante de tout contexte concurrent** : elle est écrite comme si elle tournait seule. C'est la couche de présentation (`feu-tui`) qui l'enveloppe dans un thread (voir la section `feu-tui` plus bas). Cette séparation est ce qui permet de la tester seule et de la réutiliser sous une autre présentation.

### Cycle de vie

`FeuApplication` suit un cycle en deux phases :

1. **Construction** — `FeuApplication::new` crée la struct avec le noyau absent (`feu_noyau: None`).
2. **Allumage** — `commande_allumage_noeud` initialise ou allume le noyau. Toutes les autres commandes retournent `ErreurFeuApplication::NoeudEteint` tant que cette étape n'a pas été franchie.

```rust
pub struct FeuApplication {
    feu_noyau: Option<FeuNoyau>,   // None jusqu'à l'allumage
    session: SessionApplication,
}
```

### `InterfaceFeuApplication`

Contrat entre `FeuApplication` et la présentation. Regroupe les interactions utilisateur déléguées et la notification d'état :

| Méthode | Rôle |
|---|---|
| `demander_mdp` | Collecte du mot de passe (`Option<SecretString>`) |
| `recevoir_seed` | Transmet les mots de la seed à afficher |
| `confirmer_enregistrement_seed` | Demande confirmation de l'enregistrement de la seed |
| `recevoir_session_application` | Notifie un changement d'état applicatif (`Option<SessionApplication>`) |

**Pourquoi seulement quatre méthodes**, alors que `InterfaceFeuNoyau` en compte sept ? Parce que les notifications fines du noyau (adresses `.onion`, états d'ouverture, clés publiques) ne remontent **pas** jusqu'à la présentation : elles sont absorbées au passage dans `SessionApplication` (voir `RecepteurNoyau` ci-dessous). La présentation n'a donc pas besoin de les recevoir une par une — elle reçoit, en fin de commande, un **instantané cohérent et complet** de la session via `recevoir_session_application`. Les trois autres méthodes sont les interactions que seule la présentation peut servir : saisir le mot de passe, afficher la seed, confirmer son enregistrement.

**Le modèle de notification est un *push* via le trait**, et non un getter exposé sur `FeuApplication`. Trois raisons :

- un getter forcerait la présentation à interroger l'état à chaque frame — un couplage temporel inutile ;
- le trait est déjà le seul point de contact avec la présentation : y placer la notification garde `feu-application` aveugle à la nature de cette présentation (TUI, ou autre) ;
- ajouter un canal directement dans `FeuApplication` violerait le principe « l'interface est passée à l'appel, jamais stockée ».

`recevoir_session_application` est appelée **une seule fois** à la fin de chaque commande qui mute la session, une fois `self.session` dans un état cohérent — jamais en cours de mutation, jamais depuis les setters. Le payload est un `Option<SessionApplication>` : `Some(clone)` après une commande mutante réussie, `None` à l'extinction du nœud (la présentation doit alors tout oublier). Le `Clone` (dérivé) est ce qui permet à l'instantané de franchir la frontière de thread vers la présentation sans `Arc` ni `Mutex` — une copie isolée, immuable du point de vue du receveur.

### `RecepteurNoyau` — pont interne

`RecepteurNoyau` est la pièce d'articulation entre les deux interfaces — c'est l'un des choix de conception structurants de la v0.0.3. C'est un pont **éphémère**, construit pour la durée d'un seul appel noyau puis détruit. Il emprunte à la fois `&mut SessionApplication` et `&mut dyn InterfaceFeuApplication`, et implémente `InterfaceFeuNoyau` : c'est donc lui que `FeuNoyau` reçoit comme interface, sans jamais voir la présentation directement.

Son rôle est de **router** les sept méthodes de `InterfaceFeuNoyau` selon leur destination — le critère n'est pas « entrée ou notification », mais « cela concerne-t-il l'utilisateur, ou n'est-ce qu'une donnée d'état ? » :

- les **trois méthodes qui requièrent l'utilisateur** (`demander_mdp` pour la saisie, `recevoir_seed` pour l'affichage, `confirmer_enregistrement_seed` pour la confirmation) sont **déléguées** à `InterfaceFeuApplication`, car seule la présentation peut les servir ;
- les **quatre méthodes qui ne transportent que des données d'état** (`recevoir_onion_foyer`, `recevoir_etat_foyer`, `recevoir_cle_publique_noeud`, `recevoir_cles_publiques_foyer`) sont **écrites directement** dans `SessionApplication`, sans déranger la présentation.

Concrètement, les données d'état s'accumulent dans la session pendant l'exécution de la commande, et `FeuApplication` n'en publie le résultat consolidé qu'une seule fois, à la fin, via `recevoir_session_application`. La présentation reçoit ainsi un état cohérent, jamais une succession d'événements partiels.

`RecepteurNoyau` est privé : la présentation n'en a pas connaissance. Il illustre le principe « l'interface est passée, jamais stockée » poussé jusqu'au bout — il est recréé à chaque appel précisément pour ne pas avoir à vivre dans `FeuApplication` entre deux commandes.

### `SessionApplication`

État applicatif de session, dérive `Clone`. Centralise tout ce que la couche doit mémoriser entre les commandes :

- capacités du noyau, dérivées des constantes `MAX_*` (nombre de foyers, de classeurs, tailles maximales) ;
- adresses `.onion` et états d'ouverture de chaque foyer ;
- clé publique de signature du nœud ;
- clés publiques de signature (Ed25519) et de chiffrement (X25519) de chaque foyer.

Les setters sont `pub(crate)` (seul `RecepteurNoyau` les appelle), les getters sont publics.

### Commandes

| Commande | Rôle |
|---|---|
| `commande_allumage_noeud` | Initialise ou allume le nœud |
| `commande_extinction_noeud` | Éteint le nœud (exige tous les foyers fermés), libère le noyau, réinitialise la session |
| `commande_changement_mdp` | Change le mot de passe |
| `commande_ouverture_foyer` / `commande_fermeture_foyer` | Ouvre / ferme un foyer |
| `commande_secours_fermeture_foyer` | Ferme en secours un foyer resté ouvert |
| `commande_depot_donnees` / `commande_lecture_donnees` / `commande_suppression_donnees` | Cycle de vie des blobs |
| `commande_liste_blobs` / `commande_existence_blob` / `commande_information_blob` | Interrogation des blobs |
| `commande_chiffrement_asymetrique` / `commande_dechiffrement_asymetrique` | ECIES X25519 |
| `commande_signature_noeud` / `commande_signature_foyer` / `commande_verification_signature` | Signatures Ed25519 |
| `commande_diagnostic_noeud` / `commande_diagnostic_foyer` | Diagnostics |

`commande_extinction_noeud` est l'opération symétrique de l'allumage, introduite dans cette release au niveau applicatif : elle vérifie qu'aucun foyer n'est ouvert, met `feu_noyau` à `None` (efface les clés privées en mémoire), réinitialise `SessionApplication` et notifie la présentation avec `recevoir_session_application(None)`. Elle n'écrit rien sur disque.

---

## `feu-tui`

Interface terminal construite sur **Ratatui** et **crossterm**. Remplace la CLI Rustyline de test des versions précédentes.

### Architecture à deux threads

**Pourquoi deux threads.** `feu-noyau` et `feu-application` sont écrits de façon strictement **synchrone** : quand le noyau a besoin du mot de passe, il appelle `demander_mdp()` et **attend** la valeur de retour au milieu de sa pile d'appel. Or une TUI exige l'inverse : sa boucle doit tourner **en permanence** pour redessiner et lire le clavier. Sur un seul fil d'exécution, ces deux besoins sont incompatibles — appeler l'API synchrone du cœur depuis la boucle de rendu la **gèle**, et la gèle précisément au moment où il faudrait redessiner pour saisir le mot de passe réclamé : l'interface se fige en attendant une réponse qu'elle ne peut plus produire.

La séparation en deux threads dénoue ce nœud : le **thread cœur** a le droit de bloquer (c'est son rôle), le **thread TUI** ne bloque jamais et continue de dessiner. Le connecteur traduit l'appel synchrone bloquant du cœur en « envoi d'un message à la TUI + attente sur un canal » : c'est *son* thread qui bloque, pas l'interface. `feu-application` et `feu-noyau` n'en savent rien — ils croient appeler une interface ordinaire. La concurrence est entièrement encapsulée dans la couche TUI, derrière la façade synchrone qu'est `InterfaceFeuApplication`. Ce choix se généralise à d'éventuels sous-systèmes bloquants ultérieurs (le réseau), chacun caché derrière sa propre façade synchrone, sans imposer de runtime asynchrone au noyau.

`main` monte deux threads communiquant par deux canaux `mpsc` typés, sans aucun état partagé :

- le **thread principal** exécute la boucle TUI (`Tui::lancer`) ;
- le **thread cœur** (spawné par `ConnecteurVersTui::lancer_thread_coeur`) pilote `FeuApplication`.

```
        MessageTuiCoeur  →
 [Tui]  ───────────────────  [FeuApplication]
        ←  MessageCoeurTui
```

À la sortie, `main` attend le thread cœur via `join()` ; un `panic` du thread cœur fait sortir le processus avec le code 1. Le terminal est restauré par le guard de `ratatui::run`.

### Connecteurs et protocole de messages

- **`ConnecteurVersTui`** vit dans le thread cœur. Il possède `FeuApplication` et implémente `InterfaceFeuApplication`. Sa boucle de dispatch traite **exhaustivement** chaque variante de `MessageTuiCoeur` (aucun `_ => {}`) : toute variante ajoutée à l'avenir provoque une erreur de compilation tant qu'elle n'est pas traitée.
- **`ConnecteurVersCoeur`** vit dans le thread TUI. Il expose l'envoi de commandes et la lecture non bloquante (`try_recv`) du canal cœur→TUI à chaque frame.

`MessageTuiCoeur` (TUI → cœur) : `AllumageNoeud`, `ExtinctionNoeud`, `EnvoieMdp`, `OuvertureFoyer(usize)`, `FermetureFoyer(usize)`, `SeedBienRecue`, `Annulation`, `Quitter`.

`MessageCoeurTui` (cœur → TUI) : `AffichageErreur(String)`, `AttenteMdp`, `EnvoiSeed(Vec<SecretString>)`, `EnvoiSessionApplication(Option<SessionApplication>)`.

> Les index de foyer transitent en **base 1** (valeur saisie/affichée par l'utilisateur) ; la conversion en base 0 est faite par le connecteur cœur (`index_foyer - 1`) juste avant l'appel à `FeuApplication`.

### Boucle et désynchronisation

La boucle TUI tourne en continu via `poll(50 ms)` : elle ne bloque jamais plus de 50 ms, dépouille le canal cœur→TUI à chaque itération via `try_recv`, et décrémente une fois par seconde les comptes à rebours des éléments éphémères (messages d'erreur, messages d'aide). Les deux threads sont désynchronisés — la TUI n'attend aucune réponse du cœur, sauf les attentes bloquantes explicites côté cœur (`demander_mdp`, `recevoir_seed`).

### Modèle d'interaction — quatre axes orthogonaux

L'état de l'interface (`EtatTui`) se lit sur quatre axes indépendants :

- **`Ecran`** — quelle famille visuelle est dessinée : `Normal` (carré à angles droits), `SaisieMdp` (cadre arrondi orange piloté par le cœur), `AffichageSeed` (cadre arrondi orange, mots en 3 colonnes).
- **`ModeSaisie`** — comment les touches sont interprétées : `Normal` (dispatch via la table de commandes), `Insertion` (accumulation dans un buffer, Entrée valide, Échap annule), `Information` (Entrée seule fait avancer l'écran).
- **`PositionCourante`** — où l'utilisateur se situe dans la pseudo-arborescence foyer → classeur, affichée en fil d'Ariane dans l'invite (`feu/foy.N/cla.M ›`). Trois niveaux : racine, dans un foyer, dans un classeur.
- **`CommandesActives`** — quelles touches sont actives dans le contexte courant.

### Table de commandes contextuelle déclarative

`Commande` représente une intention métier ; `CommandesActives` encapsule une `HashMap<(KeyCode, KeyModifiers), Commande>`. La boucle clavier ne connaît **aucun raccourci hardcodé** : elle interroge la table et dispatche ce qu'elle retourne, ou ne fait rien.

La table est une **fonction pure** de l'état : `CommandesActives::new(&Option<SessionApplication>, &PositionCourante)` la reconstruit intégralement à chaque changement d'état pertinent (réception d'une nouvelle session, ou après chaque commande dispatchée). Pas de mutation incrémentale, pas d'état caché, pas de risque de désynchronisation entre la table, la session et la position.

**Filtrage strict** : présence dans la table ⇔ effet réel possible. Une touche présente déclenche systématiquement quelque chose ; une touche absente est ignorée silencieusement (pas d'erreur, pas de feedback).

Cartographie clavier selon le contexte (`?` toujours actif, liste les touches courantes) :

| Contexte | Touches actives |
|---|---|
| Nœud éteint, racine | `a` allume · `q` quitte |
| Nœud allumé, aucun foyer ouvert | `e` éteint · `o` ouvre un foyer |
| Nœud allumé, ≥ 1 foyer ouvert, racine | `o` ouvre (si capacité libre) · `1`-`9` entrent dans un foyer **ouvert** |
| Dans un foyer | `f` ferme le foyer courant · `1`-`9` entrent dans un classeur · `⌫` remonte · `o` ouvre |
| Dans un classeur | `f` ferme le foyer parent · `⌫` remonte · `o` ouvre |

**Asymétrie ouverture / fermeture** : ouvrir demande une saisie d'index (`OuvrirFoyer` — on ne peut pas naviguer vers un foyer qui n'existe pas), fermer n'en demande pas (`FermerFoyer(index)` capture l'index depuis la position courante au moment de la construction de la table). Le geste est *naviguer puis fermer* : `3` puis `f` ferme le foyer 3.

La borne `1`-`9` (et non `1`-max) reflète le mapping sur les caractères ASCII `'1'`..`'9'` ; les capacités réelles du noyau (`MAX_FOYERS = 3`, `MAX_CLASSEURS = 5`) restent largement en deçà.

### Ce que la TUI pilote — et ce qu'elle ne pilote pas encore

**Câblé** dans la TUI : allumage du nœud, extinction, ouverture de foyer (avec saisie du numéro), fermeture de foyer, saisie du mot de passe, affichage et confirmation de la seed, navigation dans la pseudo-arborescence.

**Non câblé** (exposé par `feu-application` mais sans liaison clavier) : dépôt / lecture / suppression / liste de blobs, chiffrement et déchiffrement asymétriques, signatures, vérification de signature, diagnostics, changement de mot de passe, fermeture en secours. C'était délibéré : l'objectif de cette release était la restructuration, pas l'exhaustivité de l'interface.

---

## Gestion d'erreurs

Une chaîne de conversion `From` par couche, toutes construites avec `thiserror`. Chaque couche encapsule l'erreur de la couche inférieure dans une `String` via `.to_string()` — le type interne est perdu, seul le message textuel remonte, ce qui préserve l'encapsulation.

| Type | Crate | Préfixe de message | Variantes notables |
|---|---|---|---|
| `ErreurFeuNoyau` | `feu-noyau` | `NOY >` | `Gardien`, `Cryptographe`, `Archiviste` (String) ; `IndexInvalide`, `FoyerDejaOuvert`, `FoyerFerme`, `TousFoyersNonOuverts`, `TailleMaxDepassee`, `OnionIntrouvable`, … |
| `ErreurFeuApplication` | `feu-application` | `APP >` | `FeuNoyau(String)`, `Standard(String)`, `NoeudEteint`, `AuMoinsUnFoyerOuvert` |

Au sein du noyau, les erreurs internes (`ErreurGardien`, `ErreurCryptographe`, `ErreurArchiviste`) sont elles-mêmes agrégées dans `ErreurFeuNoyau`. Les préfixes de couche (`NOY >`, `APP >`) servent de marqueurs lorsqu'un message est encapsulé par la couche supérieure : un message remonté du noyau jusqu'à la TUI porte la trace de son origine.

`feu-tui` ne définit pas de type d'erreur métier : il affiche le message reçu via `MessageCoeurTui::AffichageErreur` dans `EtatTui::message_erreur` (compte à rebours de 5 s).

---

## Cryptographie

La cryptographie est inchangée par rapport à la v0.0.2, à une exception près : la **suppression de la contrainte de longueur minimale du mot de passe** dans le cryptographe — aucune contrainte n'est plus imposée, ni dans le noyau ni dans la TUI.

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

Paramètres Argon2id effectifs (défauts de la crate, conformes aux recommandations minimales RFC 9106) :

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

Taille limitée à `MAX_TAILLE_SIGNATURE` (64 Kio) : réservée aux structures légères.

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

Inchangée par rapport à la v0.0.2. Racine : `~/.feu/`. Permissions : dossiers `rwx------` (0o700), fichiers `rw-------` (0o600). Toutes les écritures de fichiers de clés sont atomiques : écriture dans `<chemin>.tmp` (0o600), puis `rename` sur la cible.

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

Chaque chunk : `plaintext (≤ CHUNK_SIZE octets) + tag AES-GCM (16 octets)`. Le nonce fait 7 octets (contrainte de la crate `aead/stream`, `EncryptorBE32`). `CHUNK_SIZE = 4096` — constante privée au cryptographe, à ne pas confondre avec `TAILLE_CHUNK` (8192), qui est la granularité de lecture d'un blob par le Tiroir.

**Nuance de sécurité :** le `.tar` est créé dans `~/.feu/` (même répertoire que les archives `.feu`), avec permissions 0o600. En cas de crash entre sa création et sa suppression, un `.tar` non chiffré contenant les données du foyer peut persister sur le disque.

---

## Constantes

| Constante | Valeur | Rôle |
|---|---|---|
| `MAX_FOYERS` | 3 | Nombre de foyers par nœud |
| `MAX_CLASSEURS` | 5 | Nombre de classeurs par foyer |
| `MAX_TAILLE_BLOB` | 512 Mio | Taille maximum d'un blob en clair |
| `MAX_TAILLE_CHIFFREMENT_ASYMETRIQUE` | 1 Mio | Taille maximum d'un message ECIES |
| `MAX_TAILLE_SIGNATURE` | 64 Kio | Taille maximum d'un message à signer |
| `TAILLE_CHUNK` | 8 192 octets | Granularité de lecture d'un blob par le Tiroir (en mémoire), `pub(crate)` |
| `CHUNK_SIZE` | 4 096 octets | Taille des chunks du stream AES-256-GCM des archives `.feu` (constante privée au cryptographe) |

---

## Plateformes supportées

Linux et macOS uniquement. Le noyau repose sur des primitives Unix (permissions, liens symboliques, `rename` atomique, variables d'environnement) et lève une erreur de compilation sur toute autre plateforme.

---

## Environnement technique

**Edition Rust :** 2024. Version `0.0.3` et licence `GPL-3.0-or-later` définies au niveau workspace, comme le lint `missing_docs = "warn"`.

### Dépendances `feu-noyau`

| Crate | Usage |
|---|---|
| `aes-gcm` (`std`, `zeroize`) | Chiffrement AES-256-GCM des clés, blobs et archives |
| `aead` (`stream`) | Chiffrement stream (`EncryptorBE32` / `DecryptorBE32`) |
| `argon2` (`std`) | Dérivation Argon2id depuis le mot de passe |
| `bip39` (`rand`, `french`, `zeroize`) | Génération seed BIP39, dictionnaire français |
| `ed25519-dalek` (`zeroize`) | Paires Ed25519, signature déterministe, vérification stricte |
| `x25519-dalek` (`static_secrets`) | Paires X25519, ECDH |
| `hkdf` | Dérivation HKDF-SHA3-256 |
| `sha3` | SHA3-256 (HKDF, adresses `.onion`, hash content-addressable) |
| `slip10_ed25519` | Dérivation hiérarchique SLIP-0010 Ed25519 |
| `secrecy` | `SecretBox<T>` — zéroïsation automatique au `Drop` |
| `zeroize` | `Zeroize`, `ZeroizeOnDrop` |
| `tar` | Archivage/extraction des dossiers de foyer |
| `data-encoding` (`alloc`) | BASE32 (adresses `.onion`), HEXLOWER (hashes) |
| `rand` | Génération de nonces aléatoires (`OsRng`) |
| `thiserror` | Dérivation des types d'erreur |

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
| BIP39 | Seed mnémonique (12 mots) | bitcoin/bips/bip-0039 |
| SLIP-0010 | Dérivation hiérarchique Ed25519 (hardened) | satoshilabs/slips/slip-0010 |
| RFC 8032 | Ed25519 — signature déterministe, vérification stricte | IETF RFC 8032 §5.1 |
| RFC 7748 | X25519 — échange de clés (ECIES) | IETF RFC 7748 |
| RFC 5869 | HKDF — dérivation de clé | IETF RFC 5869 |
| RFC 9106 | Argon2id — dérivation depuis mot de passe | IETF RFC 9106 |
| NIST SP 800-38D | AES-256-GCM — chiffrement authentifié | NIST SP 800-38D |
| NIST FIPS 202 | SHA3-256 | NIST FIPS 202 |
| Tor v3 | Dérivation adresse `.onion` | torspec/rend-spec-v3.txt |

---

## Garanties de sécurité

1. **La seed est la racine absolue** — tout dérive d'elle ; en mode logiciel, elle est détruite en mémoire après dérivation.
2. **Toutes les clés sont dérivables depuis la seed** — la perte des clés est récupérable par ressaisie de la seed (archives et blobs à sauvegarder séparément).
3. **Une clé, un usage** — Ed25519 (signature), X25519 (échange), AES-256-GCM (chiffrement symétrique) strictement séparés.
4. **Les clés en clair n'existent qu'en mémoire** — sur le disque, tout est chiffré. Exception connue : un crash pendant la fermeture d'un foyer peut laisser un `.tar` non chiffré dans `~/.feu/`.
5. **Gardien / Cryptographe** — le disque et le clair ne se rencontrent jamais dans le même composant.
6. **L'Archiviste ne voit jamais de clair** — uniquement des blobs chiffrés et des hashes.
7. **Le Tiroir zéroïse** — le blob en clair est zéroïsé dès remplacement par le chiffré, et à chaque vidage.
8. **Double chiffrement des blobs** — clé de classeur (permanent), puis clé d'archive du foyer (à la fermeture).
9. **Stratification stricte** *(nouveau en v0.0.3)* — la présentation (`feu-tui`) ne touche jamais le noyau directement : tout passe par `feu-application`. Le noyau n'affiche plus rien lui-même (suppression des méthodes d'affichage provisoires) ; il **pousse** des notifications d'état que la couche supérieure est libre d'utiliser. L'extinction du nœud (`commande_extinction_noeud`) libère le noyau et efface l'état applicatif, ne laissant aucune donnée applicative survivre.
