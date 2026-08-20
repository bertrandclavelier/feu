# Feu

🇬🇧 [English version](README.en.md)

### 24 mots, un nœud, tout ton numérique.

Feu est un nœud personnel de souveraineté numérique : un schéma de dérivation déterministe et un format d'enveloppes signées. Depuis une unique seed BIP39, il dérive l'ensemble des clés cryptographiques nécessaires à la gestion d'identités multiples (foyers), au chiffrement local des données et à leur contrôle d'accès. Les données sont organisées par des **ENU** — des enveloppes signées, en clair, qui les nomment et les rangent en arborescence sans jamais les toucher.

L'architecture cible repose sur un dispositif matériel dédié, à l'image des portefeuilles matériels de cryptomonnaie, qui génère la seed et garde les clés maîtres du nœud hors de l'ordinateur. La version actuelle gère l'ensemble du processus cryptographique en logiciel, selon le même schéma de dérivation.

---

## Où en est Feu

Projet en développement actif. Fonctionnel localement, sans réseau.

### v0.0.5 — 12 août 2026

Intégration des ENU, les Enveloppes Numériques Universelles, jusque-là absentes du code. Une couche applicative neuve, le **Scribe**, tient une arborescence d'enveloppes signées qui nomme et organise les blobs du nœud sans jamais les toucher. Second chantier de la version : le code ne comportait aucun test, il en compte 61.

- **ENU** : enveloppe signée `Enu` et carte `Carte` (Donnée, Texte, Répertoire), content-addressed, signature ML-DSA-87 sur la carte. Exposées en lecture seule.
- **Arborescence** tenue à la racine du nœud, donc lisible foyers fermés : racines signées par le nœud, chaînées entre elles, sommet courant désigné par un symlink.
- **Comptoir de dépôt** : un dossier est rempli puis refermé, son contenu est rangé en blobs et en ENU, puis greffé sous la racine du nœud. Piloté depuis la TUI.
- **Retrait en lecture seule** : matérialisation de l'arborescence d'une ENUr dans un dossier OS, sans reprise.
- **Accès aux blobs par l'ENU seule**, sans désigner ni foyer ni classeur.
- **Type `Braise`** dans le noyau, qui remplace la `String` partout ; API recentrée sur l'index.
- **61 tests** là où il n'y en avait aucun, intégrés aux crates.
- Cryptographie inchangée. Toujours aucun réseau.

Les versions antérieures sont dans le [changelog](CHANGELOG.md).

---

## Prérequis

- Rust ≥ 1.97.1 (édition 2024)
- Linux ou macOS
- Aucune dépendance système supplémentaire

---

## Installation et lancement

```sh
git clone https://git.clavelier.me/bertrand/feu.git
cd feu
cargo build --release
cargo run --release -p feu-tui
```

Le dépôt de référence est sur Forgejo. [GitHub](https://github.com/bertrandclavelier/feu) n'en est qu'un miroir sortant : rien n'y est reçu, ni issue ni contribution.

---

## Plateformes

Linux et macOS uniquement.

---

## Documentation

- [Livre blanc](documentation/livre_blanc.md) — vision et architecture de Feu
- [Note de release](documentation/release.md) — détails techniques de la version courante

---

## Signaler un problème, proposer une idée

Tout le suivi se passe sur la forge, sur le dépôt de référence :
[git.clavelier.me/bertrand/feu](https://git.clavelier.me/bertrand/feu/issues).
Ouvrir un ticket demande un compte, que chacun peut créer librement en confirmant
une adresse mail.

Les propositions y ont autant leur place que les bugs : une idée, une objection
de conception, un usage auquel je n'ai pas pensé. Les contributions de code, en
revanche, ne sont pas ouvertes à ce jour.

---

## Suivre le projet

Les annonces et l'avancement sont publiés sur le Fediverse par
[@bertrand@social.clavelier.me](https://social.clavelier.me/@bertrand), sous **#FeuApp**.

---

## Licence

[GPL-3.0](LICENSE)
