#!/bin/bash
# Compile netscan pour ce Mac à partir du code source de la clé (installe Rust si besoin, ~5 min la première fois).
set -e
cd "$(dirname "$0")"
if ! command -v cargo >/dev/null && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
  echo "Installation de Rust (outil de compilation)…"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
export PATH="$HOME/.cargo/bin:$PATH"
# On compile dans un dossier local : plus rapide que sur la clé, et exFAT n'aime pas les milliers de petits fichiers.
DEST="$HOME/Library/Caches/netscan-build"
cargo build --release --manifest-path ../source/Cargo.toml --target-dir "$DEST" --config 'build.target="'"$(rustc -vV | sed -n 's/host: //p')"'"'
cp "$DEST"/*/release/netscan ./netscan
echo "netscan compilé pour ce Mac."
