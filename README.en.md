# Feu

🇫🇷 [Version française](README.md)

### 24 words, one node, your whole digital life.

Feu is a personal node for digital sovereignty: a deterministic derivation scheme and a signed-envelope format. From a single BIP39 seed, it derives every cryptographic key needed to manage multiple identities (*foyers*, households), to encrypt data locally and to control access to it. Data is organised by **ENUs** — signed envelopes, kept in the clear, that name it and arrange it into a tree without ever touching it.

The target architecture relies on dedicated hardware, along the lines of a cryptocurrency hardware wallet, which generates the seed and keeps the node's master keys off the computer. The current version performs the whole cryptographic process in software, following the same derivation scheme.

---

## Where Feu stands

Under active development. Working locally, with no networking.

### v0.0.5 — 12 August 2026

Integration of ENUs — *Enveloppes Numériques Universelles*, Universal Digital Envelopes — which were absent from the code until now. A new application layer, the **Scribe**, maintains a tree of signed envelopes that names and organises the node's blobs without ever touching them. The version's second undertaking: the code had no tests at all, it now has 61.

- **ENU**: signed envelope `Enu` and card `Carte` (Data, Text, Directory), content-addressed, ML-DSA-87 signature over the card. Exposed read-only.
- **Tree** held at the node's root, therefore readable with every *foyer* closed: roots signed by the node, chained together, current head designated by a symlink.
- **Deposit counter**: a directory is filled, then closed; its contents are stored as blobs and ENUs, then grafted under the node's root. Driven from the TUI.
- **Read-only withdrawal**: materialising the tree of a directory ENU into an OS folder, with no path back in.
- **Blob access through the ENU alone**, without naming either a *foyer* or a binder.
- **`Braise` type** in the core, replacing `String` throughout; API refocused on the index.
- **61 tests** where there were none, integrated into the crates.
- Cryptography unchanged. Still no networking.

Earlier versions are in the [changelog](CHANGELOG.md) (French).

---

## Requirements

- Rust ≥ 1.97.1 (2024 edition)
- Linux or macOS
- No additional system dependencies

---

## Install and run

```sh
git clone https://git.clavelier.me/bertrand/feu.git
cd feu
cargo build --release
cargo run --release -p feu-tui
```

The reference repository is on Forgejo. [GitHub](https://github.com/bertrandclavelier/feu) is an outgoing mirror only: nothing is received there, neither issues nor contributions.

---

## Platforms

Linux and macOS only.

---

## Documentation

Both documents are in French.

- [White paper](documentation/livre_blanc.md) — the vision and architecture of Feu
- [Release notes](documentation/release.md) — technical details of the current version

---

## Reporting a problem, suggesting an idea

All tracking happens on the forge, on the reference repository:
[git.clavelier.me/bertrand/feu](https://git.clavelier.me/bertrand/feu/issues).
Opening an issue requires an account, which anyone can create freely by
confirming an email address.

Suggestions belong there as much as bugs: an idea, a design objection, a use case
I have not thought of. Code contributions, however, are not open at this time.

---

## Following the project

Announcements and progress are published on the Fediverse by
[@bertrand@social.clavelier.me](https://social.clavelier.me/@bertrand), under **#FeuApp**.

Posts are in French.

---

## Licence

[GPL-3.0](LICENSE)
