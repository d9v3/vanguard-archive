---
name: verifier
description: Tout vérifier avant un commit de Sentinel — mise en forme, tests Linux, clippy sur les quatre cibles, tests Windows sous Wine, scripts générés. À lancer après toute modification du code Rust ou des scripts, avant de committer.
---

Lance dans cet ordre ; au premier échec, corrige puis reprends depuis le début :

1. `cargo fmt --check` (sinon `cargo fmt`).
2. `cargo test`.
3. `cargo clippy -q --all-targets --target <cible>` pour x86_64-unknown-linux-musl, x86_64-pc-windows-gnu,
   aarch64-apple-darwin et x86_64-apple-darwin : zéro remarque.
4. Tests Windows sous Wine (commande dans CLAUDE.md), avec un WINEPREFIX jetable dans le dossier temporaire de la
   session. La première fois, Wine prépare ce dossier (une minute).
5. Si un script généré a changé : commandes shell par `bash -n -c`, PowerShell par pwsh (voir .claude/rules/windows.md).

Pièges :
- Un test qui passe sous Linux peut ne pas compiler pour macOS ou Windows (`#[cfg]`) : les quatre clippy comptent.
- Ne pas lancer de test qui modifie la machine (sudo, services, registre de HKLM) : seulement des clés jetables
  de HKCU sous Wine.

Rends compte en une ligne par étape : tests passés par système, remarques clippy, ce qui n'a pas pu être lancé.
