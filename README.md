# Feu

### 24 mots, un nœud, tout ton numérique.

Feu est un protocole de souveraineté numérique personnelle. Depuis une unique seed BIP39, il dérive de manière déterministe l'ensemble des clés cryptographiques nécessaires à la gestion d'identités multiples (foyers), au chiffrement local des données et à leur contrôle d'accès. Les données sont organisées par des **ENU** — des enveloppes signées, en clair, qui les nomment et les rangent en arborescence sans jamais les toucher.

L'architecture cible repose sur un dispositif matériel dédié, à l'image des portefeuilles matériels de cryptomonnaie, qui génère la seed et garde les clés maîtres du nœud hors de l'ordinateur. La version actuelle gère l'ensemble du processus cryptographique en logiciel, selon le même schéma de dérivation.

---

## Statut

Projet en développement actif. Fonctionnel localement, sans réseau.

**v0.0.5** — Intégration des ENU : arborescence d'enveloppes signées (ML-DSA-87) tenue à la racine du nœud, donc lisible foyers fermés. Dépôt d'un dossier entier par comptoir et retrait en lecture seule, pilotés depuis la TUI. Accès aux blobs par l'ENU seule, sans désigner ni foyer ni classeur. Type `Braise` dans le noyau. 61 tests, intégrés aux crates. Toujours aucun réseau.

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

- [Livre blanc](documentation/livre_blanc.md) — vision et architecture du protocole
- [Note de release](documentation/release.md) — détails techniques de la version courante

---

## Suivre le projet

Les annonces et l'avancement sont publiés sur le Fediverse par
[@bertrand@social.clavelier.me](https://social.clavelier.me/@bertrand), sous **#FeuApp**.

---

## Licence

[GPL-3.0](LICENSE)
