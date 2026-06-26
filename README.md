# Feu

### 24 mots, un nœud, tout ton numérique.

Feu est un protocole de souveraineté numérique personnelle. Depuis une unique seed BIP39, il dérive de manière déterministe l'ensemble des clés cryptographiques nécessaires à la gestion d'identités multiples (foyers), au chiffrement local des données et à leur contrôle d'accès. L'architecture cible repose sur un hardware wallet comme trousseau souverain. La version actuelle gère l'ensemble du processus cryptographique en logiciel, selon le même schéma de dérivation.

---

## Statut

Projet en développement actif. Fonctionnel localement, sans réseau.

**v0.0.4** — Migration post-quantique : signatures ML-DSA-87, chiffrement asymétrique ML-KEM-1024, dérivation HKDF-SHA3-256 directe depuis la seed (abandon de SLIP-0010), identité foyer par adresse `.braise` (découplée de l'ancienne `.onion`), seed 24 mots. Noyau stable sur le plan cryptographique. Toujours aucun réseau.

**v0.0.3** — Restructuration architecturale : workspace réorganisé en trois crates (`feu-noyau`, `feu-application`, `feu-tui`), nouvelle interface TUI (Ratatui) en remplacement de la CLI. Aucune nouvelle fonctionnalité métier. Toujours aucun réseau.

**v0.0.2** — Stockage chiffré de données structuré en classeurs, signatures, vérification de signatures, dépôt idempotent, diagnostics de présence des fichiers. Toujours aucun réseau.

**v0.0.1** — Fondations cryptographiques et cycle de vie local. Interface CLI persistante, initialisation d'un nœud depuis une seed, ouverture et fermeture de foyers sous forme d'archives chiffrées. Aucun réseau, aucune donnée utilisateur.

---

## Prérequis

- Rust ≥ 1.85.0 (édition 2024)
- Linux ou macOS
- Aucune dépendance système supplémentaire

---

## Installation et lancement

```sh
git clone https://github.com/bertrandclavelier/feu.git
cd feu
cargo build --release
cargo run --release -p feu-tui
```

---

## Plateformes

Linux et macOS uniquement.

---

## Documentation

- [Livre blanc](documentation/livre_blanc.md) — vision et architecture du protocole
- [Release v0.0.4](documentation/releases/v0_0_4_release.md) — détails techniques de la version courante
- [Release v0.0.3](documentation/releases/v0_0_3_release.md)
- [Release v0.0.2](documentation/releases/v0_0_2_release.md)
- [Release v0.0.1](documentation/releases/v0_0_1_release.md)

---

## Licence

[GPL-3.0](LICENSE)
