# Feu

🇬🇧 [English version](README.en.md)

### 24 mots, un nœud, tout ton numérique.

Feu est un nœud personnel de souveraineté numérique : un schéma de dérivation déterministe et un format d'enveloppes signées. Depuis une unique seed BIP39, il dérive l'ensemble des clés cryptographiques nécessaires à la gestion d'identités multiples (foyers), au chiffrement local des données et à leur contrôle d'accès. Les données sont organisées par des **ENU** — des enveloppes signées, en clair, qui les nomment et les rangent en arborescence sans jamais les toucher.

L'architecture cible repose sur un dispositif matériel dédié, à l'image des portefeuilles matériels de cryptomonnaie, qui génère la seed et garde les clés maîtres du nœud hors de l'ordinateur. La version actuelle gère l'ensemble du processus cryptographique en logiciel, selon le même schéma de dérivation.

---

## Où en est Feu

Projet en développement actif. Fonctionnel localement, sans réseau.

### v0.0.7 — 5 septembre 2026

Version du comptoir de travail : le sous-arbre d'une ENU sort en clair dans un dossier, on l'y modifie librement, et Feu le reprend à la fermeture — le disque fait alors autorité.

- **Comptoir de travail** : ouvert et refermé depuis la TUI sur une seule touche. Ce qui n'a pas bougé est réemployé tel quel, une entrée effacée disparaît de l'arbre, une entrée nouvelle le rejoint. Un seul à la fois, et jamais avec un comptoir de dépôt ouvert.
- **Comptoirs persistants** : leur état survit à l'extinction et se rouvre à l'allumage.
- **Verrou d'instance** : un seul Feu à la fois sur un nœud, le système relâchant le verrou même après un arrêt brutal.
- **Index typés** : une position dans le nœud est bornée par son type, de bout en bout ; l'arborescence des ENU montre où chaque entrée est rangée.
- **ENU** : date de création sous la signature, version du format sérialisé, unicité des noms d'enfants tenue au dépôt.
- **86 tests**, contre 67, dont les bout-en-bout passés en crates externes.
- Cryptographie inchangée, cohorte RustCrypto montée. Toujours aucun réseau.

Les versions antérieures sont dans le [changelog](CHANGELOG.md).

---

## Prérequis

- Rust ≥ 1.98.0 (édition 2024)
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

Feu s'ouvre sur son écran de pilotage, nœud éteint. Le
[guide utilisateur](documentation/guide_utilisateur.md) prend le relais ici :
les trois écrans, les touches, et un premier dépôt-retrait de bout en bout.

Le dépôt de référence est sur Forgejo. [GitHub](https://github.com/bertrandclavelier/feu) n'en est qu'un miroir sortant : rien n'y est reçu, ni issue ni contribution.

---

## Plateformes

Linux et macOS uniquement.

---

## Documentation

- [Guide utilisateur](documentation/guide_utilisateur.md) — de l'installation au premier dépôt-retrait
- [Livre blanc](documentation/livre_blanc.md) — vision et architecture de Feu
- [Note de version](documentation/note_de_version.md) — détails techniques de la version courante

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
