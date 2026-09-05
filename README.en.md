# Feu

🇫🇷 [Version française](README.md)

### 24 words, one node, your whole digital life.

Feu is a personal node for digital sovereignty: a deterministic derivation scheme and a signed-envelope format. From a single BIP39 seed, it derives every cryptographic key needed to manage multiple identities (*foyers*, households), to encrypt data locally and to control access to it. Data is organised by **ENUs** — signed envelopes, kept in the clear, that name it and arrange it into a tree without ever touching it.

The target architecture relies on dedicated hardware, along the lines of a cryptocurrency hardware wallet, which generates the seed and keeps the node's master keys off the computer. The current version performs the whole cryptographic process in software, following the same derivation scheme.

---

## Where Feu stands

Under active development. Working locally, with no networking.

### v0.0.7 — 5 September 2026

The work counter version: the subtree of an ENU is written out in the clear into a folder, edited freely there, and taken back by Feu on closing — the disk then holds the authority.

- **Work counter**: opened and closed from the TUI with a single key. Whatever has not moved is reused as is, an entry deleted disappears from the tree, a new one joins it. Only one at a time, and never alongside an open deposit counter.
- **Persistent counters**: their state outlives shutdown and is reopened when the node is lit.
- **Single instance**: one Feu at a time on a node, the system releasing the lock even after an abrupt shutdown.
- **Typed indices**: a position inside the node is bounded by its type, end to end; the ENU tree shows where each entry is stored.
- **ENUs**: creation date under the signature, serialised format version, and uniqueness of sibling names enforced on deposit.
- **86 tests**, up from 67, the end-to-end ones moved into external crates.
- Cryptography unchanged, RustCrypto cohort upgraded. Still no networking.

Earlier versions are in the [changelog](CHANGELOG.md) (French).

---

## Requirements

- Rust ≥ 1.98.0 (2024 edition)
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

Feu opens on its control screen, node off. The
[user guide](documentation/guide_utilisateur.md) (French) takes over from
there: the three screens, the keys, and a first deposit and withdrawal end to
end.

The reference repository is on Forgejo. [GitHub](https://github.com/bertrandclavelier/feu) is an outgoing mirror only: nothing is received there, neither issues nor contributions.

---

## Platforms

Linux and macOS only.

---

## Documentation

All three are in French — this README is the only English page.

- [User guide](documentation/guide_utilisateur.md) — from install to a first deposit and withdrawal
- [White paper](documentation/livre_blanc.md) — the vision and architecture of Feu
- [Release notes](documentation/note_de_version.md) — technical details of the current version

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
