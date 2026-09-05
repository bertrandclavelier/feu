# F E U

### 24 mots, un nœud, tout son numérique.

**Livre blanc**
**Date : 5 septembre 2026**

*Le 17 février 2026, nouvel an chinois marquant le début de l'année du Cheval de Feu, naît le projet Feu.*

---

## Manifeste

Depuis plusieurs décennies, des systèmes cryptographiques et des protocoles décentralisés ont prouvé leur robustesse : le chiffrement asymétrique, les réseaux en oignon, les chaînes de blocs, les protocoles de rumeur. Ces outils sont matures, éprouvés, disponibles. Pourtant, la décentralisation du web reste marginale.

Le problème n'est pas technologique. Les briques existent. Ce qui manque, c'est un assemblage accessible — un outil unifié qui les met au service de chacun.

À partir des années 2000, la numérisation de la vie quotidienne s'accélère : recherche, réseaux sociaux, commerce, communication. La donnée personnelle devient un sous-produit automatique de chaque interaction numérique. Les grandes plateformes transforment ces données en profit — services gratuits en échange d'une exploitation systématique. L'utilisateur n'est plus le client, il est la matière première.

Cette accumulation massive a rendu possible l'émergence des grands modèles de langage, entraînés sur des milliards de contenus produits par des humains, souvent sans consentement explicite. L'enjeu reste entier : plus les données sont abondantes et fiables, plus les modèles sont performants. Notre production numérique collective est devenue une ressource industrielle.

Dans un registre différent, cette même centralisation permet la surveillance de masse et la manipulation de l'information. Nos données restent éparpillées sur des serveurs centralisés, lisibles par leurs gestionnaires, soumises à des juridictions que nous ne choisissons pas.

Feu propose une alternative : que chaque individu devienne le dépositaire souverain de ses propres données. Non pas en s'opposant à l'existant, mais en s'y intégrant. Feu peut référencer une donnée sur un serveur mail, un cloud, une API — ou la rapatrier dans un espace chiffré et souverain. On peut l'utiliser seul pour organiser ses données, le mettre en réseau pour le partage, ou les deux. Feu ne remplace rien. Il agrège l'existant pour le faire fonctionner de manière unifiée et décentralisée sans inventer un énième réseau.

Si chaque individu contrôle ses données, les communautés peuvent reconquérir leur autonomie numérique, les institutions peuvent bâtir sur des fondations équitables, et la connaissance circule sans surveillance.

Mais la décentralisation n'est pas un produit. C'est une pratique. Elle demande d'apprendre à posséder ses clés, à gérer ses espaces, à comprendre la valeur de ce qu'on partage. Feu repose sur une conviction : la possession d'une clé cryptographique personnelle — idéalement enfermée dans un dispositif matériel dédié — deviendra la norme du numérique.

Notre souveraineté numérique tient en 24 mots !

---

## 1. 24 mots, un nœud, des foyers

Tout commence par une seule graine cryptographique : la **seed**. Une liste de 24 mots, conforme au standard BIP39 — le même qui sécurise des milliards d'euros en cryptomonnaies depuis plus d'une décennie. Feu retient 24 mots pour une entropie de 256 bits, alignée sur le niveau de sécurité maximal des primitives post-quantiques sous-jacentes. La restauration depuis des seeds de 12, 15, 18 ou 21 mots reste acceptée. Cette seed n'est jamais stockée par Feu, jamais transmise — sa conservation hors ligne appartient à l'utilisateur. Elle est la clé absolue du système, tout en découle.

La seed est générée localement, sans serveur, sans tiers, sans accès au réseau. L'utilisateur crée seul son identité, ses clés et ses adresses réseau — aucune inscription, aucune autorisation, aucune dépendance extérieure. L'identité existe dès que les 24 mots sont générés.

Depuis cette seed, Feu dérive un **nœud** : la racine logique de toute l'identité numérique de l'utilisateur. Le nœud est lié à la seed, pas à une machine — réinstaller Feu ailleurs avec la même seed reconstitue le même nœud. Il est unique, irrévocable, et constitue la preuve cryptographique que tout ce qui suit lui appartient.

Du nœud naissent les **foyers** — des instances indépendantes, chacune avec ses propres clés, sa propre adresse réseau, son propre espace chiffré. Un foyer par contexte de vie : un pour l'identité publique, un pour le cercle privé, un pour un projet professionnel. Chaque foyer est isolé des autres — la compromission de l'un n'affecte pas les autres. Et chacun peut être révoqué, renouvelé, migré, sans toucher au reste.

L'architecture cible repose sur un **dispositif matériel dédié**, à l'image des portefeuilles matériels de cryptomonnaie : il génère la seed, la conserve et garde les clés maîtres du nœud dans un environnement inviolable, hors de l'ordinateur. La seed et les clés maîtres ne quittent jamais le matériel. Cette garantie est physique, pas logicielle.

Le dispositif ne remplace pas les 24 mots. Un appareil casse, se perd, se vole : les mots, eux, conservés hors ligne par l'utilisateur, redonnent le nœud entier sur un autre dispositif. Le matériel protège l'usage quotidien de la seed ; les mots protègent de la perte du matériel. Les deux vont ensemble.

La version actuelle gère l'ensemble du processus cryptographique en logiciel, selon le même schéma de dérivation.

Toutes les clés sont dérivables depuis la seed. La perte de la machine n'entraîne aucune perte de clés — les archives chiffrées, elles, doivent être sauvegardées séparément. La résilience des données repose sur la réplication des classeurs, pas sur la seed seule. Seule la perte de la seed est fatale — et cette responsabilité appartient à l'utilisateur, comme dans tout écosystème cryptographique sérieux.

---

## 2. L'identité numérique universelle

L'**IdNU** est la carte d'identité cryptographique d'un foyer. Signée par la clé privée du nœud (ML-DSA-87, post-quantique), elle prouve l'appartenance du foyer à l'identité racine.

Elle contient :

- L'adresse `.braise` du foyer — dérivée directement de la seed, permanente et immuable
- La clé publique du nœud — pour vérifier la signature de l'IdNU elle-même
- La clé publique de signature du foyer (ML-DSA-87) — pour vérifier les ENU qu'il émet
- La clé publique de chiffrement réseau ML-KEM-1024 — pour recevoir des messages chiffrés
- La date d'émission et la date d'expiration
- Optionnellement un pseudonyme ou un nom de domaine
- La signature de l'ensemble par la clé privée du nœud

Rien n'est obligatoire au-delà du minimum cryptographique. Chacun définit son niveau d'exposition, de l'anonymat total à l'identité publique vérifiable.

### Péremption et renouvellement

L'IdNU a une durée de validité configurable par l'utilisateur. À échéance, le propriétaire doit émettre une nouvelle IdNU — même à contenu identique, la date d'expiration est mise à jour et la signature renouvelée avec la clé privée du nœud. C'est un acte conscient et délibéré.

Une IdNU expirée signale un foyer potentiellement compromis : le réseau cesse immédiatement tout échange avec lui. Un attaquant ayant compromis les clés du foyer ne peut pas produire une IdNU fraîche — il n'a pas la clé du nœud. Sa capacité d'usurpation expire avec la dernière IdNU légitime.

Pour un foyer qui sommeille, la situation est différente — à sa réactivation, l'utilisateur est invité à re-signer son IdNU. Une fois propagée par gossip, le foyer redevient progressivement acceptable sur le réseau. L'utilisateur calibre sa période de renouvellement selon son modèle de sécurité : fréquente pour une exposition élevée, espacée pour un usage confidentiel avec le dispositif matériel en coffre-fort.

### Validation par un foyer tiers

Un tiers qui reçoit une IdNU vérifie quatre choses : que l'adresse `.braise` déclarée est bien formée — son checksum la valide sans rien connaître de la seed —, que la signature de l'IdNU est valide avec la clé publique du nœud qu'elle annonce, que l'IdNU n'est pas expirée, et que le foyer répond bien à son adresse réseau. Nul ne peut recalculer une braise sans la seed dont elle dérive : c'est la signature du nœud, et elle seule, qui atteste que cette braise est bien la sienne.

Au premier contact, le tiers fait confiance au canal Tor (chiffrement de bout en bout). C'est le modèle TOFU — Trust On First Use. Aux contacts suivants, il vérifie la continuité : même clé publique de nœud que l'IdNU précédemment stockée.

### Pont DNS

Un **pont DNS** permet de lier un nom de domaine classique à un foyer. Le propriétaire déclare le domaine dans son IdNU ; un champ TXT dans le DNS pointe vers la **braise**. La vérification est bidirectionnelle. Le pont désigne l'identité du foyer, jamais son adresse de transport : celle-ci peut changer autant de fois que nécessaire sans qu'on touche au DNS, la résolution vers l'adresse courante étant l'affaire du réseau. Une identité Feu peut ainsi être découverte par un simple nom de domaine — sans renoncer à l'infrastructure décentralisée qui la porte.

### Révocation

Si un foyer est compromis, le propriétaire dérive un nouveau jeu de clés au prochain index disponible (ressaisie de la seed). Nouvelle adresse `.braise`, nouvelle IdNU, signée par le même nœud. La nouvelle IdNU fait office de révocation de l'ancienne. Les contacts qui avaient l'ancienne IdNU voient apparaître la nouvelle, signée par le même nœud, et comprennent que le foyer a migré.

### Ce que l'IdNU n'est pas

L'IdNU n'est pas une preuve d'identité civile. Elle prouve une continuité cryptographique — ce foyer appartient à ce nœud, ce nœud a toujours la même seed. L'association avec une personne physique est hors protocole.

Côté architecture, l'IdNU est une donnée comme les autres : un blob stocké dans un classeur, décrit par une ENUd. Elle circule sur le réseau comme un paquet ordinaire.

---

## 3. L'enveloppe numérique universelle

Sous Unix, tout est fichier. Sous Feu, tout est **ENU**.

L'ENU est l'unité fondamentale du protocole. Une structure légère — quelques milliers d'octets, l'essentiel étant la signature — faite de deux parties : une **carte**, qui décrit ou contient la donnée, et une **enveloppe** qui la scelle. La carte porte le sens : type, métadonnées, tags, et selon le type le hash d'une donnée, un texte, ou les hashs d'autres ENU. L'enveloppe porte le hash de la carte, la signature de la carte (ML-DSA-87, post-quantique), la braise du signataire et la version du format.

Le sceau ne couvre que la carte. La braise et la version du format restent hors signature : routage pour l'une, lecture du fichier pour l'autre, malléables par nature. La date, elle, est une métadonnée de la carte : elle est scellée avec elle. Falsifier la braise ne fait qu'aiguiller la vérification vers la mauvaise clé — donc échouer. Une enveloppe n'est jamais lue sans que son hash soit recalculé et sa signature vérifiée.

L'ENU est **immuable** : le hash de la carte est le nom du fichier, donc modifier une carte, c'est créer une autre ENU. L'ancienne ne disparaît pas pour autant — voir « Une arborescence qui garde ses versions » plus bas.

Deux niveaux d'adressage : le hash de la carte identifie l'enveloppe, le hash de la donnée à l'intérieur identifie le contenu. On trouve l'enveloppe par le hash de sa carte, on trouve la donnée par le hash qu'elle contient.

Trois types d'ENU couvrent tous les besoins :

**Donnée (ENUd)** — Associée à un fichier, elle porte le hash de la donnée qu'elle décrit, et ses métadonnées : nom, créateur, date, tags, type. Elle ne sait pas *où* se trouve le fichier — ni dans quel classeur, ni même sur quelle machine. Elle sait *ce qu'il est*. Quand la donnée est dans un foyer, la braise du signataire suffit à la retrouver : le noyau la sert quel que soit le classeur qui l'héberge.

Quand la donnée est externe (serveur mail, cloud, API), le hash reste la référence — c'est lui qui dit que le fichier récupéré est bien celui que l'enveloppe décrit — et une métadonnée porte son adresse. Le noyau n'intervient pas : résoudre une URL, s'authentifier auprès d'un service, rapatrier un fichier sont l'affaire des couches supérieures. Une même donnée peut ainsi être décrite avant d'être possédée, puis rapatriée sans que son enveloppe change de sens.

**Texte (ENUt)** — Autoporteuse : elle contient directement un texte court — message, note, mémo. Aucune dépendance externe.

**Dossier (ENUr)** — Contient les hashs de cartes d'autres ENU (pas les hashs des données). Elle permet de créer des arborescences, des groupes, des collections. C'est l'enveloppe qui est référencée — l'ENUr organise des enveloppes, pas des fichiers.

### Séparation noyau / ENU

Les ENU ne vivent pas dans le noyau. Le noyau est une boîte noire qui gère des octets chiffrés : on lui pousse des octets, il chiffre, range, et retourne un hash. On donne un hash, il retourne des octets. On donne des octets à signer, il retourne une signature. C'est tout.

La couche ENU vit au-dessus. Elle reçoit le hash du noyau, construit la carte (type, hash de la donnée, métadonnées), demande au noyau de la signer, et stocke elle-même l'enveloppe dans un dossier dédié `enu/`, **à la racine du nœud — hors de tout foyer**. Ce dossier est en clair : les ENU sont signées, leur intégrité est garantie par la signature, pas par le chiffrement.

Cet emplacement est un choix de fond. Un foyer se ferme, et fermé il n'est plus qu'une archive chiffrée : ce qu'il contient devient inatteignable. Si les enveloppes vivaient dedans, on ne pourrait plus rien consulter ni chercher sans tout ouvrir. Hors des foyers, elles restent navigables en permanence — on parcourt son catalogue, on cherche, on organise, et l'on n'ouvre un foyer qu'au moment de toucher une donnée. La confidentialité protège les données ; la signature protège le catalogue.

Les ENU sont la couche vivante du système. On les crée, on les réorganise, on les publie — sans jamais toucher aux données elles-mêmes, auxquelles elles se contentent de donner du sens. Plusieurs ENUr peuvent référencer les mêmes ENUd (par leurs hashs de carte) pour construire des vues différentes : un même ensemble de photos organisé par date, par lieu, par projet — autant de structures que nécessaire, sans jamais dupliquer une donnée.

L'identité elle-même n'échappe pas au modèle. Une IdNU est décrite par une ENUd. Les contacts sont des ENUd récupérées sur le réseau. Les groupes d'utilisateurs sont des ENUr. Aucun mécanisme dédié, aucune exception : l'identité et les groupes sont des données comme les autres.

### Une arborescence qui garde ses versions

Les enveloppes ne forment pas un tas. Elles s'organisent en arborescence sous une **racine** — une ENUr particulière, signée non par un foyer mais par le **nœud** lui-même. C'est la seule signature de ce niveau : la racine engage le nœud dans sa globalité, alors que chaque enveloppe de contenu n'engage que le foyer qui l'a produite. Un symlink désigne le sommet courant ; c'est le seul point d'entrée, et il suffit à retrouver tout le reste.

Comme une ENU est immuable, réorganiser ne modifie rien : on reconstruit. Déplacer une photo, renommer un dossier, ajouter un fichier produit de nouvelles enveloppes pour les répertoires du chemin concerné, jusqu'à un nouveau sommet. Chaque racine porte le hash de la précédente. Le sommet courant est donc le dernier maillon d'une **lignée** qu'on peut remonter indéfiniment.

Rien n'est effacé au passage. Les anciens sommets restent, et avec eux l'arborescence telle qu'elle était. Feu n'a pas de fonction d'historique : il en a un parce qu'une ENU immuable ne se modifie pas, elle se remplace — l'ancienne version est toujours là. C'est l'effacement qui demanderait un travail explicite : un élagage des branches mortes, décidé par l'utilisateur le jour où la place sur le disque compte, jamais un comportement automatique du protocole.

### Exemple local — Alice organise ses photos

Alice stocke une photo. Le noyau chiffre, écrit le blob dans `classeur1/`, retourne `hash_photo`. La couche ENU crée une carte Donnée : hash de la donnée = `hash_photo`, métadonnées (nom, date, tags "vacances", "2026"). Le hash de la carte est calculé sur ce contenu, la carte est signée par le foyer, et l'enveloppe est écrite dans `enu/` sous le nom de ce hash.

Alice veut organiser par projet. La couche ENU crée une ENUr "Vacances 2026" contenant les hashs de plusieurs ENUd — signée, stockée dans `enu/`, greffée sous la racine. Pour créer une deuxième vue — "Meilleures photos" — une autre ENUr est créée, référençant les mêmes hashs. La photo n'existe qu'une fois dans le classeur. Les ENUd n'existent qu'une fois dans `enu/` : le nom du fichier étant le hash, deux enveloppes identiques sont le même fichier. Seules les ENUr se multiplient pour offrir des vues différentes.

Pour modifier la photo (recadrage), Alice récupère le blob (déchiffrement), modifie, re-stocke. Nouveau hash de donnée, donc nouvelle carte, donc nouvelle ENUd. Les ENUr qui référençaient l'ancienne sont reconstruites avec le nouveau hash, de proche en proche jusqu'à un nouveau sommet. L'ancienne ENUd n'est pas supprimée : elle sort de l'arborescence courante mais reste atteignable par le sommet précédent — la photo d'avant recadrage est toujours là, et son enveloppe dit encore ce qu'elle était.

### Exemple réseau — Alice partage avec Bob

Alice veut partager la photo avec Bob. Elle associe une condition à la donnée dans le registre : `registre/<hash_photo>.1 → <hash_condition>`, où la condition est `Braise(bob)`.

Alice publie un paquet sur le réseau (couche réseau, hors noyau). Le paquet contient l'ENUd — le hash de la carte, le hash de la photo, les métadonnées, la signature d'Alice. Il ne contient pas la photo, juste l'enveloppe. Le paquet circule par le gossip protocol de foyer en foyer.

Bob reçoit le paquet. Il lit l'ENUd, vérifie la signature avec la clé publique d'Alice (publiée dans son IdNU), et recalcule le hash de la carte pour le confronter à celui que l'enveloppe annonce. L'enveloppe est authentique. Il veut la photo. Il contacte le foyer d'Alice via Tor (adresse `.onion`).

Le foyer d'Alice reçoit la requête : « je veux `hash_photo`, je suis Bob ». Le noyau cherche dans le registre : `<hash_photo>.1` existe, la cible donne `<hash_condition>`. Le noyau évalue la condition : `Braise(bob)`, le demandeur est Bob — condition remplie. Le noyau déchiffre le blob (clé du classeur), le rechiffre pour Bob (ML-KEM-1024, clé publique tirée de l'IdNU de Bob), et le sert.

Bob déchiffre avec sa clé privée ML-KEM-1024. Il vérifie le hash contre celui contenu dans l'ENUd — la donnée est authentique et correspond à l'enveloppe reçue. Il stocke la photo dans son propre classeur, et peut créer sa propre ENUd s'il le souhaite.

Le noyau d'Alice n'a jamais entendu parler d'ENU, de Bob, ni de photos. Il a stocké des octets, évalué une condition, signé, chiffré, déchiffré. Le reste appartient aux couches supérieures.

---

## 4. Le foyer et les classeurs

Le foyer est l'espace souverain de l'utilisateur. Il contient les classeurs (données chiffrées) et le registre (contrôle d'accès). Les enveloppes, elles, vivent à la racine du nœud — hors des foyers, pour rester lisibles quand ceux-ci sont fermés.

```
~/.feu/
    .cles/                          ← clés du nœud et clés d'archive des foyers
    .config/                        ← configuration du nœud
    verrou                          ← verrou d'instance : un seul Feu à la fois
    <braise>/                       ← un foyer ouvert
        .cles/                      ← clés du foyer et des classeurs, chiffrées
        classeur0/
            <hash>.dat              ← blob chiffré
        classeur1/
        classeur2/
        classeur3/
        classeur4/
        registre/
            <hash_donnée>.N  →  <hash_condition>
    <braise>.feu                    ← un foyer fermé : archive chiffrée
    enu/
        .DERNIERE_RACINE            ← symlink vers le sommet courant
        <hash_carte>.enu            ← ENU signée, en clair
```

Le foyer est organisé en **classeurs** : des compartiments distincts, chacun chiffré par sa propre clé dérivée de la seed. Documents personnels dans un classeur, archives professionnelles dans un autre, communications dans un troisième. La compromission d'un classeur n'expose que son contenu — les autres restent intacts. C'est le principe de compartimentation appliqué au chiffrement.

Le foyer est la seule unité qui s'ouvre et se ferme. Un classeur n'a pas de cycle de vie — c'est un répertoire dont le contenu est chiffré par sa propre clé, point. À la fermeture du foyer, le noyau archive l'intégralité du dossier en tar puis le chiffre. À l'ouverture, chemin inverse : déchiffrement, extraction, les blobs dans les classeurs restent chiffrés. Ajouter ou supprimer un classeur ne change rien au mécanisme de fermeture. Les deux couches sont étanches par construction.

### Export et import

Le noyau permet d'exporter un classeur sous forme d'archive. Les blobs étant déjà chiffrés par la clé du classeur, l'archive est opaque — illisible sans la seed. Ce qui en est fait ensuite (copie sur disque externe, envoi vers un tiers, synchronisation) est hors périmètre du noyau.

L'import est le scénario de récupération. En cas de perte du nœud : la seed est ressaisie, toutes les clés sont redérivées, les archives de classeurs sont importées. Le noyau parcourt les blobs, déchiffre ceux qui sont des conditions, lit le hash de la donnée conditionnée dans chaque condition, et reconstruit les liens symboliques du registre. Les clés se redérivent, les données s'importent, le registre se reconstruit — restent à sauvegarder les classeurs et le dossier `enu/`, qui ne se redérive de rien : il porte l'organisation, et une enveloppe perdue est un sens perdu, pas une donnée perdue.

---

## 5. Le registre

Le **registre** est le contrôle d'accès du système. C'est un répertoire de liens symboliques dans le foyer — pas une structure de données, pas un fichier, une convention du système de fichiers.

Pour chaque donnée soumise à une condition d'accès, un lien symbolique existe dans `registre/` :

```
registre/<hash_donnée>.N  →  <hash_condition>
```

Le nom du lien porte deux informations : le hash de la donnée et le numéro du classeur où elle se trouve (via l'extension `.N`). La cible du lien est le hash de la condition d'accès. La condition elle-même est un blob chiffré dans un classeur — une donnée comme une autre, adressée par son hash.

Pas de lien = pas de condition. La donnée existe dans son classeur, accessible par le propriétaire comme n'importe quel blob. Le registre n'intervient pas. Le lien n'est créé que lorsqu'une condition est explicitement posée sur une donnée — que ce soit pour un tiers (accès réseau) ou pour le propriétaire lui-même (coffre-fort temporel, restriction volontaire).

### Conditions

Une **condition** est une expression booléenne composable, immuable, stockée comme un blob chiffré dans un classeur — une donnée comme une autre, adressée par son hash. Elle porte dans son contenu le hash de la donnée qu'elle conditionne — ce qui permet de reconstruire le registre à partir des classeurs seuls.

Les variantes de base : `Tout` (toujours vrai), `Rien` (toujours faux), `Braise` (demandeur spécifique, identifié par sa braise), `Avant` (limite temporelle), `AvecPreuve` (preuve cryptographique fournie par un tiers). Les opérateurs `Et`, `Ou`, `Non` permettent de composer n'importe quelle règle.

La variante `AvecPreuve` est le mécanisme d'extension du noyau. Le noyau ne se connecte jamais à un service extérieur — il évalue des preuves qu'on lui présente. Une couche supérieure (plugin, oracle, agent) peut vérifier une transaction Bitcoin, valider un certificat, ou interroger une API, puis fournir au noyau une preuve signée. Le noyau vérifie la signature de la preuve et l'accepte ou la refuse. Seules les preuves signées par un oracle explicitement autorisé par le propriétaire sont acceptées — chaque foyer définit ses propres sources de confiance. Le mécanisme d'autorisation et de validation des oracles est un sujet de conception à détailler ultérieurement.

Exemples : accès réservé à Alice — `Braise(alice)`. Accès réservé à Alice ou Bob avant le 1er janvier 2027 — `Et(Ou(Braise(alice), Braise(bob)), Avant(2027-01-01))`. S'interdire l'accès à ses propres données après une date — `Avant(2025-12-31)`, appliqué par le propriétaire sur ses propres blobs.

Une condition est immuable. Pour modifier une règle d'accès, on crée une nouvelle condition et on met à jour le lien dans le registre. L'ancienne condition devient orpheline.

Une même condition peut être réutilisée par plusieurs données — le hash est le même si le contenu est identique. Un seul blob dans le classeur, plusieurs liens dans le registre pointant vers le même hash.

### Flux de consultation

On reçoit un hash de donnée. Le noyau cherche dans `registre/` un lien portant ce hash comme nom. Si trouvé : `readlink` donne le hash de la condition, l'extension donne le classeur de la donnée. Le noyau localise la condition dans les classeurs, la déchiffre, l'évalue. Si la condition est remplie, il sert la donnée depuis le bon classeur. Si la condition n'est pas remplie, accès refusé. Si pas de lien : pas de condition — pour le propriétaire en local, la donnée est servie directement ; pour un tiers distant, l'absence de condition signifie que la donnée n'est pas partagée.

Le noyau évalue les conditions sans exception — y compris pour le propriétaire. Une condition posée par le propriétaire sur ses propres données s'applique à lui aussi.

### Contrôle d'accès

Le contrôle d'accès dans Feu repose sur trois niveaux : le chiffrement des classeurs (seul le propriétaire déchiffre), la condition du registre (le noyau évalue avant de servir), et le chiffrement des paquets réseau (seul le destinataire déchiffre). Le chiffrement *est* le contrôle d'accès.

Un simple `rm` du lien symbolique suffit à couper instantanément l'accès à une donnée conditionnée, même si l'ENU correspondante circule encore sur le réseau. Kill switch immédiat.

---

## 6. Centralisation locale

Feu permet de référencer n'importe quelle donnée accessible : fichier local, serveur de fichiers, messagerie, cloud, API. L'ENUd porte le hash de la donnée et son adresse en métadonnée — donc tant que la donnée existe et n'est pas modifiée, l'enveloppe qui la décrit reste valide, et le hash le prouve au moment de la récupérer. C'est déjà un catalogue unifié de tout son numérique, indépendant des plateformes, et consultable sans ouvrir un seul foyer.

La philosophie du projet encourage à aller plus loin : rapatrier ses données dans un espace souverain. Télécharger ses fichiers distants, les stocker chiffrés dans le foyer, conserver la copie d'origine en source secondaire. Feu ne remplace aucun service existant. Il les relie et les abstrait derrière une interface unifiée : l'ENU.

---

## 7. Le réseau

Chaque foyer Feu est un service caché sur le réseau Tor. Pas d'adresse IP exposée, pas de NAT à configurer, chiffrement de bout en bout natif. L'adresse `.onion` est l'adresse de transport — jetable, elle peut changer sans que l'identité du foyer change. L'identité du foyer, c'est la **braise** — permanente, dérivée de la seed, indépendante du réseau.

### Propagation

Les ENU circulent par la **rumeur** : un protocole de propagation où chaque foyer transmet périodiquement à quelques pairs aléatoires. L'information se propage de proche en proche. En quelques cycles, l'ensemble du réseau est informé.

Les ENU voyagent dans des **paquets** — des enveloppes réseau qui ajoutent les informations de transport et un référencement libre en mots-clés. Le paquet transporte les enveloppes, jamais les données elles-mêmes. Un paquet peut être public (lisible par tous) ou privé (chiffré pour un destinataire spécifique avec sa clé publique ML-KEM-1024, que lui seul peut ouvrir).

### Accès à une donnée

Un tiers qui reçoit une ENUd par la rumeur connaît le hash de la donnée et la braise du foyer émetteur (ainsi que son adresse `.onion` de transport, propagée avec le paquet). Pour obtenir la donnée, il contacte le foyer via Tor. Le flux est détaillé dans l'exemple réseau de la section 3.

### Relais et déni plausible

Le **relais** est l'espace réseau du foyer. Les paquets publiés par le propriétaire y cohabitent avec ceux qu'il propage pour d'autres. Lorsque les paquets sont chiffrés, il est impossible de distinguer les uns des autres. Le degré de déni plausible dépend du volume de paquets chiffrés relayés pour d'autres foyers — plus le relais est actif, plus l'attribution est difficile.

Chaque foyer qui relaie un paquet peut enrichir son référencement avec ses propres mots-clés. L'index de recherche est distribué et subjectif. Pas d'algorithme central, pas de classement imposé. Chaque foyer est son propre moteur de recherche.

### Délais

La combinaison Tor et rumeur engendre des délais de propagation de l'ordre de quelques minutes. C'est le prix d'un anonymat et d'une confidentialité sans compromis. Pour la grande majorité des usages — partage de fichiers, messagerie asynchrone, publication de contenu —, ces délais sont largement acceptables.

**Limite honnête** : une fois qu'un destinataire a téléchargé une donnée, elle lui appartient. Feu ne prétend pas contrôler ce qui a déjà été partagé. C'est la réalité du numérique, et le protocole l'assume.

---

## 8. Perspectives

### Intelligence artificielle

Les ENU sont structurées, typées, signées et légères — un format naturellement lisible par les agents IA. Feu renverse le modèle actuel : au lieu de laisser les systèmes d'IA aspirer les données sans consentement, c'est l'utilisateur qui choisit ce qu'il publie et le distribue à ses conditions. Les agents se greffent sur le réseau comme consommateurs de paquets. Le protocole n'a pas besoin de s'adapter à eux — il est déjà conçu pour ça.

Un modèle de langage exécuté localement peut analyser et enrichir le référencement des paquets du foyer, améliorant leur visibilité sur le réseau sans qu'aucune donnée ne quitte la machine. Feu n'est pas une plateforme IA. Il est l'infrastructure sur laquelle une IA souveraine devient possible.

### Protocoles d'agents

Les agents IA communiquent désormais via des protocoles standardisés — MCP, Agent-to-Agent — qui définissent comment un agent expose des outils et des données à un autre. Un foyer Feu est une implémentation naturelle de ce modèle : une surface d'exposition contrôlée, des données structurées en ENU, un accès chiffré par identité. L'agent accède à ce que le foyer publie, rien de plus. La souveraineté s'étend aux interactions machine-à-machine.

### Sauvegarde décentralisée

Un classeur exporté est une archive opaque — chiffrée par sa propre clé, illisible sans la seed. Cette propriété ouvre une perspective naturelle : confier ses sauvegardes au réseau Feu lui-même. Un foyer peut envoyer ses archives de classeurs à des foyers tiers — amis, famille, pairs de confiance — qui les stockent sans pouvoir les lire ni les altérer. La résilience des données repose alors sur le réseau lui-même, sans dépendance à un service de stockage centralisé. Chaque foyer qui héberge une archive pour un autre contribue à la robustesse collective du réseau.

### Cryptomonnaies et preuve de paternité

La seed BIP39 étant la racine commune de toutes les dérivations, un foyer Feu est nativement compatible avec tout écosystème de cryptomonnaies reposant sur le même standard : l'adresse BTC se dérive de la même seed, par le chemin BIP32 qui lui est propre, sans aucune clé supplémentaire à conserver. Un foyer qui publie son adresse dans son IdNU devient payable par tout tiers capable de le découvrir — au besoin depuis un simple nom de domaine, via le pont DNS.

Le noyau ne se connecte jamais à la blockchain. La vérification d'une transaction est assurée par une couche supérieure (plugin, oracle, agent) qui fournit au noyau une preuve cryptographique via la condition `AvecPreuve`. Le paiement devient une condition d'accès comme une autre — composable avec `Braise`, `Avant`, `Et`, `Ou`. Le contrôle d'accès par paiement est un cas particulier du registre, sans dépendance extérieure dans le noyau.

Ce mécanisme ouvre des perspectives : rémunération automatique lors de l'accès à des données publiées, micro-transactions entre foyers, commerce décentralisé.

Inscrire le hash de la carte d'une ENU sur une blockchain publique constitue un horodatage irréfutable. À cette date, cette donnée existait et était signée par cette identité. La preuve de paternité en découle naturellement — une fonctionnalité optionnelle destinée aux cas où la paternité a une valeur juridique ou commerciale.

---

## 9. Les six garanties

L'architecture de Feu repose sur six garanties. Elles ne sont pas des objectifs — elles découlent mécaniquement des choix du protocole.

1. **Souveraineté en 24 mots.** Vingt-quatre mots suffisent à dériver l'intégralité d'une vie numérique — clés, identités, foyers, adresses réseau. Aucune autorité extérieure, aucun serveur, aucun tiers. La seed est la seule dépendance, et la seule chose qu'aucune sauvegarde ne remplace : les données et les enveloppes, elles, se répliquent.

2. **Chiffré par défaut, clair par exception.** Les données sont chiffrées au repos dans les classeurs, chiffrées en transit sur le réseau, chiffrées dans l'archive du foyer. Les ENU sont en clair mais signées — leur intégrité repose sur la signature, pas sur le chiffrement. Les clés en clair n'existent qu'en mémoire, le temps d'une opération. Le disque ne voit jamais de secret en clair.

3. **Compartimenté par construction.** Chaque classeur a sa propre clé. Chaque foyer a ses propres clés. La compromission d'un compartiment n'affecte pas les autres. La séparation gardien/cryptographe garantit que le disque et les données en clair ne se rencontrent jamais dans le même composant.

4. **Privé par défaut, partagé par acte explicite.** Aucune donnée n'est accessible à un tiers tant qu'un lien n'est pas créé dans le registre. Le partage est un acte conscient. La suppression du lien coupe l'accès instantanément.

5. **Reconstructible depuis la seed.** Les clés se redérivent, les classeurs s'importent, le registre se reconstruit depuis les conditions. Seuls les classeurs et le dossier `enu/` doivent être sauvegardés : les données et le sens qu'on leur a donné. La perte de la machine n'est pas la perte du nœud.

6. **Identité périssable.** L'IdNU expire. Un foyer qui ne renouvelle pas son identité est considéré comme potentiellement compromis par le réseau. La fenêtre d'usurpation est bornée par la péremption.

---

## Glossaire

**Feu** — Protocole de souveraineté numérique personnelle. Désigne à la fois le projet, le logiciel et le réseau formé par l'ensemble des foyers connectés.

**Noyau** — Couche fondamentale du protocole. Gère les clés, le chiffrement, le stockage content-addressable et l'évaluation des conditions. Ne connaît que des octets et des hashs — toute sémantique (ENU, IdNU, réseau) vit au-dessus.

**Nœud** — Racine logique de l'identité, liée à la seed. Réinstaller Feu sur une autre machine avec la même seed reconstitue le même nœud. Un nœud gère un ou plusieurs foyers.

**Foyer** — Instance opérationnelle d'un nœud. Chaque foyer dispose de son propre jeu de clés, de son propre espace chiffré et de sa propre adresse réseau. Un foyer est un service caché sur le réseau Tor.

**Braise** — Identifiant public et invariant d'un foyer. Dérivé directement de la seed, indépendant de toute clé cryptographique. Adresse textuelle `.braise` (ex. `k7x4…wq.braise`). Stable à vie, survit à toute migration de primitive.

**Seed** — Graine cryptographique (standard BIP39) de 24 mots, 256 bits d'entropie. Racine absolue de toutes les clés, identités et foyers. Jamais stockée par le logiciel — les mots sont conservés hors ligne par l'utilisateur. Perdre sa seed, c'est perdre son nœud.

**Dispositif matériel** — Appareil dédié, à l'image des portefeuilles matériels de cryptomonnaie, qui génère la seed et garde les clés maîtres du nœud hors de l'ordinateur. Architecture cible de Feu.

**IdNU** — Identité Numérique Universelle. Carte d'identité cryptographique d'un foyer, signée par la clé de nœud. Périssable — elle expire et doit être renouvelée périodiquement.

**ENU** — Enveloppe Numérique Universelle. Structure légère, signée et immuable qui décrit ou contient une donnée. Faite d'une **carte** (le sens : type, métadonnées, contenu ou référence) et d'une enveloppe qui la scelle. Identifiée par le hash de sa carte, qui est aussi son nom de fichier. Trois types : Donnée (ENUd), Texte (ENUt), Dossier (ENUr). Stockée en clair dans le dossier `enu/`, à la racine du nœud — hors des foyers, donc lisible même foyers fermés.

**Racine** — ENUr signée par le nœud, sommet de l'arborescence des enveloppes. Chaque racine porte le hash de la précédente : la lignée des racines est l'historique du nœud, conservé par construction.

**Classeur** — Compartiment chiffré du foyer, possédant sa propre clé dérivée de la seed. Contient des blobs chiffrés adressés par hash (données et conditions). Exportable sous forme d'archive opaque pour la sauvegarde.

**Registre** — Répertoire de liens symboliques dans le foyer. Chaque lien associe le hash d'une donnée (et son classeur) au hash de sa condition d'accès. Reconstructible depuis les classeurs.

**Condition** — Expression booléenne composable et immuable définissant une règle d'accès. Stockée comme un blob chiffré dans un classeur. Variantes : `Tout`, `Rien`, `Braise`, `Avant`, `AvecPreuve`, `Et`, `Ou`, `Non`.

**Relais** — Espace réseau du foyer. Contient les paquets publiés et ceux propagés pour d'autres foyers. Le degré de déni plausible dépend du volume de paquets chiffrés relayés — plus le relais est actif, plus l'attribution est difficile.

**Paquet** — Enveloppe de transport réseau contenant une ou plusieurs ENU. Peut être public ou privé (chiffré pour un destinataire spécifique).

**Rumeur** — Protocole de propagation (gossip protocol) par lequel les foyers échangent les paquets de proche en proche.

**Pont DNS** — Mécanisme liant un nom de domaine classique à un foyer via un champ TXT dans le DNS.
