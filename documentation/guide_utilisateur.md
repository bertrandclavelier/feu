# Feu — guide utilisateur

> **Date :** 22 août 2026
> **Version :** v0.0.6

Ce guide vous emmène de l'installation au premier dépôt-retrait complet. Il ne
dit pas tout, juste de quoi commencer sans se perdre.

## 1. Ce que fait Feu

Feu stocke et organise vos données de manière sécurisée et versionnée, avec des
primitives cryptographiques post-quantiques.

Il travaille dans trois espaces distincts, et tout l'usage consiste à passer de
l'un à l'autre.

**Les blobs** — le seul endroit où Feu range vos données, chiffrées dans des
classeurs. Elles y restent chiffrées en permanence : on ne déchiffre qu'au
moment précis où on en a besoin.

**Les enveloppes** — l'espace ENU, la pierre angulaire de Feu. Toujours en
clair, toujours signées, elles portent le hash de leur contenu et la continuité
de l'arborescence : ce qui est un fichier, ce qui est un dossier, comment tout
s'emboîte. En clair, donc consultables foyers fermés — vous parcourez votre
catalogue sans rien déchiffrer ; signées et hashées, donc leur intégrité est
vérifiable sans être cachée. Ce n'est pas tout à fait une arborescence mais un
**DAG** — un graphe orienté sans cycle : une même donnée peut être rangée à
plusieurs endroits sans être dupliquée. Et **rien n'est jamais écrasé** —
chaque modification ajoute une version, l'ancienne reste atteignable.

**Le clair** — ce que vous sortez de Feu pour le lire ou le modifier, dans un
dossier ordinaire, **sous votre responsabilité**. Pendant ce temps, la donnée
reste chiffrée dans Feu : ce que vous avez sous les yeux n'en est qu'une copie
lisible.

## 2. La structure

Un nœud possède **trois foyers**, chacun contenant **cinq classeurs**. Les
foyers sont indépendants : vous les ouvrez et les fermez comme vous voulez, l'un
sans l'autre. Ouvrir un foyer ne déchiffre rien — les blobs restent chiffrés,
un par un, dans leurs classeurs ; cela vous donne accès à son arborescence, pas
à son contenu. À la fermeture, le foyer entier est archivé en un seul fichier,
lui-même chiffré : il n'en reste qu'un `.feu` sur le disque.

## 3. Installation

```sh
git clone https://git.clavelier.me/bertrand/feu.git
cd feu
cargo build --release
cargo run --release -p feu-tui
```

Prérequis : Rust ≥ 1.98, Linux ou macOS. Aucune autre dépendance. Chaque
`cargo run` ouvre sur l'écran de pilotage, nœud éteint.

Feu écrit tout dans `~/.feu/` — clés, archives de foyers, enveloppes — et
nulle part ailleurs. Sur votre système, il n'existe que ce dossier et le binaire
compilé : aucun fichier de configuration, aucun service, aucune écriture hors
de là. Supprimer `~/.feu/` remet Feu à zéro.

## 4. Les trois écrans

L'interface tient sur trois écrans, en onglets dans la bordure basse du cadre :

| gauche | milieu | droite |
|---|---|---|
| **ENU** | **Pilotage** | **Disque** |

`l` avance d'un écran vers la droite, `h` revient vers la gauche. C'est une
ligne, pas une boucle : arrivé au bout, la touche ne déplace plus rien. L'onglet
actif est en couleur.

Les trois écrans jouent des rôles complémentaires :

- **l'écran ENU** sert à choisir l'enveloppe sur laquelle agir ;
- **l'écran disque** sert à choisir le chemin où Feu lira ou écrira ;
- **le pilotage** est l'endroit où l'on déclenche, avec ces deux choix en main.

## 5. Détail de chaque écran

### Pilotage — le cœur

Les touches, selon l'endroit et l'état :

```
?  !  a  e  o  f  S  d  c  r  q  0–9  Backspace
```

<br>

<p align="center">
  <img src="img/feu_pilotage_v0.0.6.png" alt="L'écran de pilotage" width="480">
</p>

<br>

En haut du cadre, une ligne de **pastilles** dit l'état sans qu'on ait rien à
demander. À gauche, celle du nœud : `●` allumé, `○` éteint. À droite, une
pastille par foyer, dans l'ordre des numéros — `●` pour un foyer ouvert, `○`
pour un foyer fermé. Les pastilles allumées sont en couleur. C'est là qu'on
vérifie, avant de quitter, qu'il ne reste rien d'ouvert.

Sur la capture : nœud allumé, foyer 0 fermé, foyers 1 et 2 ouverts. L'invite
`feu/foy.2/cla.4 ›` dit où l'on se trouve — dans le classeur 4 du foyer 2.
En dessous, les trois lignes d'état : un comptoir ouvert (`Dépôts › 0.{f2.c4}`),
l'ENU marquée (`ENU › doc`) et le chemin marqué (`Chemin › …`). Les onglets
sont sur la bordure basse, l'actif en couleur.

**`?` d'abord.** Il liste les touches réellement actives ici et maintenant :
elles dépendent de l'état du nœud, du foyer où vous êtes, et des marques
posées. Une touche absente de cette liste ne fait rien.

L'ordre dans lequel les choses s'enchaînent :

1. **`a` allume le nœud.** La toute première fois, Feu génère une seed de 24
   mots, l'affiche — notez-la, elle seule permet de tout retrouver — puis vous
   fait définir un mot de passe. Ensuite, `a` ne demande plus que ce mot de
   passe.
2. **`o` ouvre un foyer** (`0`, `1` ou `2`), mot de passe à l'appui. Rien ne se
   dépose sans un foyer ouvert : c'est lui qui signe.
3. **`0`–`2` puis `0`–`4` vous positionnent** dans un foyer puis dans un
   classeur ; `Backspace` remonte d'un cran.
4. **`d` ouvre un comptoir de dépôt** vers ce classeur — mais il faut avoir
   marqué un chemin sur l'écran du disque, c'est là que le comptoir sera créé.
5. **`c` ferme le comptoir** et range son contenu. Il faut avoir marqué l'ENU
   sous laquelle greffer sur l'écran des ENU ; la première fois, c'est la
   racine, seule chose que l'arbre contienne.
6. **`r` retire** l'ENU marquée au chemin marqué.
7. **`f`, `e`, `q`** referment le foyer, éteignent le nœud, quittent — dans cet
   ordre. `S` répare un foyer resté ouvert après un arrêt brutal.

### Arborescence des ENU — vos données

C'est ici que se parcourt le DAG des enveloppes, et qu'on choisit celle sur
laquelle agir. Les enveloppes se lisent foyers fermés — mais **le nœud doit
être allumé** pour les charger.

- `R` charge l'arbre, et le recharge ensuite.
- `j` / `k` descendent et remontent, `Entrée` ouvre ou referme un dossier.
- `m` marque l'ENU sous le curseur, `x` efface la marque.

<br>

<p align="center">
  <img src="img/feu_enu_v0.0.6.png" alt="L'arborescence des ENU" width="480">
</p>

<br>

Chaque ligne porte un symbole qui dit ce qu'elle est : `⌂` la racine du nœud,
`▾` un répertoire déplié, `▸` un répertoire replié, `▻` un répertoire vide, `•`
une donnée, `≡` un texte. Les traits verticaux relient chaque entrée à son
parent, un par niveau de profondeur.

La ligne surlignée est le curseur ; l'astérisque en colonne de gauche est la
marque, posée ici sur `test2`. Sur la capture, `test3` et `exercises` sont des
répertoires repliés : `Entrée` les ouvrirait.

**Rien ne se met à jour tout seul, et c'est voulu** : parcourir l'arbre coûte,
et Feu ne le refait pas dans votre dos. Après un dépôt, l'arbre affiché est
d'ailleurs vidé — il vient de changer. `R` le remonte.

La marque posée ici est reprise sur l'écran de pilotage, où elle se consomme.

### Arborescence du disque — vos chemins

Votre système de fichiers, depuis le dossier personnel. Mêmes gestes :

- `R` recharge la branche sous le curseur.
- `j` / `k` descendent et remontent, `Entrée` ouvre ou referme un dossier.
- `m` marque le chemin sous le curseur, `x` efface la marque.

Là non plus, rien ne se rafraîchit seul : Feu ne surveille pas le disque.

La marque posée ici est reprise sur l'écran de pilotage, où elle se consomme.

## 6. Un parcours complet

Le même enchaînement, mais écran par écran et avec ce que vous verrez.

1. **Pilotage** — `a`, puis `o` et `0`.
2. **Disque** (`l`) — `j`/`k` et `Entrée` jusqu'au dossier d'accueil, puis `m`.
3. **Pilotage** (`h`) — `0` pour entrer dans le foyer, `0` pour le classeur,
   puis `d`. Un dossier `f0.c0_depot_feu` apparaît dans votre chemin marqué :
   copiez-y les fichiers à déposer. La ligne `Dépôts › 0.{f0.c0}` s'affiche.
4. **ENU** (`h`) — `R` pour charger l'arbre, `m` sur la racine.
5. **Pilotage** (`l`) — `c`, puis le numéro du comptoir (`0`). Feu lit le
   dossier, chiffre chaque fichier, l'enveloppe et le greffe sous la marque.
6. **ENU** — l'arbre a été vidé, il vient de changer : `R` le recharge, `m` sur
   le répertoire à ressortir.
7. **Pilotage** — `r`. Un dossier `retrait_feu_` suivi de huit caractères
   reçoit l'arborescence en clair, à côté du comptoir.
8. **Pilotage** — `f`, `e`, `q`.

## 7. Ce qui peut surprendre

- **Tout est numéroté à partir de zéro** : les foyers vont de `0` à `2`, les
  classeurs de `0` à `4`, et le premier comptoir ouvert porte le numéro `0`.
  C'est l'indice interne du système, montré tel quel plutôt que décalé pour
  l'affichage.
- **Le mot de passe est redemandé à chaque ouverture de foyer.** Feu ne le
  garde pas en mémoire entre deux opérations.
- **Le nœud doit être allumé pour charger les ENU**, même si les enveloppes
  sont lisibles foyers fermés.
- **Ne quittez jamais Feu brutalement avec un foyer ouvert** — Ctrl-C, fenêtre
  fermée, machine éteinte. Vos données ne sont pas exposées pour autant : les
  blobs restent chiffrés, un par un, comme toujours. Mais le foyer resterait
  déployé au lieu d'être archivé et rechiffré, et Feu ne saurait plus le
  rouvrir : c'est le seul état incorrect qu'il puisse atteindre. Si cela arrive,
  rien de grave : relancez, allumez le nœud et utilisez `S`, la fermeture de
  secours prévue pour ce cas.
- **La sortie propre est `f`, puis `e`, puis `q`.** `e` refuse tant qu'un foyer
  est ouvert, et `q` n'apparaît que nœud éteint.
- **Retrait refusé** : si un foyer signataire du sous-arbre est fermé, `r`
  échoue en le nommant. Ouvrez-le, retentez.
- **Ne touchez pas à l'arborescence de `~/.feu/`** à la main. Pour repartir sur
  une base neuve, supprimez le dossier entier et relancez : Feu recommence à
  zéro, nouvelle seed comprise.
- **C'est une version de test.** N'y rangez aucune donnée à laquelle vous
  tenez.
