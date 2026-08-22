# Feu

🇫🇷 [Version française](README.md)

### 24 words, one node, your whole digital life.

Feu is a personal node for digital sovereignty: a deterministic derivation scheme and a signed-envelope format. From a single BIP39 seed, it derives every cryptographic key needed to manage multiple identities (*foyers*, households), to encrypt data locally and to control access to it. Data is organised by **ENUs** — signed envelopes, kept in the clear, that name it and arrange it into a tree without ever touching it.

The target architecture relies on dedicated hardware, along the lines of a cryptocurrency hardware wallet, which generates the seed and keeps the node's master keys off the computer. The current version performs the whole cryptographic process in software, following the same derivation scheme.

---

## Where Feu stands

Under active development. Working locally, with no networking.

### v0.0.6 — 22 August 2026

The first version whose chain works end to end: a user opens a *foyer*, deposits a tree into it, takes it back out and browses it, without leaving the TUI. Three undertakings carry it — the overhaul of error handling, deposit counters and read-only withdrawal, and the wiring of the TUI.

- **Error handling overhauled**: a single type per crate, with variants named after the fact they report. The TUI structures its own without ever interrupting its loop — only a terminal failure exits the program.
- **A TUI with three working screens**: control, ENU tree, disk tree. Navigation, folding, and marking either an ENU or a path.
- **Multiple counters**: several deposits open at once, each designated by its path and by the ENU to graft under.
- **Guarded withdrawal**: refused outright if a *foyer* that signed part of the subtree is closed, the list of *foyers* to open being drawn up before any writing.
- **Tree traversals**: descending and ascending, both usable with every *foyer* closed.
- **`Enu` made private, `Fiche` at the boundary**: the presentation layer now handles only cards — the envelope without its signature.
- **Emergency closing** of a *foyer* left open after an abrupt shutdown, reachable from the TUI.
- **67 tests**, up from 61.
- Cryptography unchanged. Still no networking.

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
