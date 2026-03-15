# Feu

### 12 mots, un nœud, tout ton numérique.

Feu est un protocole de souveraineté numérique personnelle. Depuis une unique seed BIP39, il dérive de manière déterministe l'ensemble des clés cryptographiques nécessaires à la gestion d'identités multiples (foyers), au chiffrement local des données et à leur contrôle d'accès. L'architecture cible repose sur un hardware wallet comme trousseau souverain. La version actuelle gère l'ensemble du processus cryptographique en logiciel, selon le même schéma de dérivation.

---

## Statut

Projet en phase de conception et de développement initial.

**v0.0.1** — Fondations cryptographiques et cycle de vie local. Interface CLI persistante, initialisation d'un nœud depuis une seed, dérivation hiérarchique SLIP-0010, ouverture et fermeture de foyers sous forme d'archives chiffrées. Aucun réseau, aucune donnée utilisateur.

---

## Prérequis

- Rust ≥ 1.85.0 (édition 2024)
- Linux ou macOS
- Aucune dépendance système supplémentaire

---

## Installation et lancement

```sh
git clone <url-du-dépôt>
cd workspace
cargo build --release
cargo run --release -p feu-cli
```

---

## Plateformes

Linux et macOS uniquement.

---

## Documentation

- [Livre blanc](documentation/livre_blanc.md) — vision et architecture du protocole
- [Release v0.0.1](documentation/releases/v0_0_1_release.md) — détails techniques de la version courante

---

## Licence

[GPL-3.0](LICENSE)
