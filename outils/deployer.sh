#!/usr/bin/env bash
# Compile netscan (Linux statique + Windows), l'installe localement et met à jour la clé USB NETSCAN si elle est branchée.
#   outils/deployer.sh                 compiler puis déployer
#   outils/deployer.sh --sans-compiler copier les dernières versions compilées (utilisé au branchement de la clé)
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

LINUX=target/x86_64-unknown-linux-musl/release/netscan
WINDOWS=target/x86_64-pc-windows-gnu/release/netscan.exe

if [[ ${1:-} != --sans-compiler ]]; then
  cargo build --release --target x86_64-unknown-linux-musl
  cargo build --release --target x86_64-pc-windows-gnu
fi
install -Dm755 "$LINUX" "$HOME/.cargo/bin/netscan"

CLE=$(find "/run/media/$USER" -maxdepth 2 -name netscan.cle -printf '%h\n' 2>/dev/null | head -1)
if [[ -z $CLE ]]; then
  echo "Clé NETSCAN non branchée : elle sera mise à jour au prochain branchement."
  exit 0
fi

mkdir -p "$CLE"/{Linux,Windows,donnees,source}
cp -f "$LINUX" "$CLE/Linux/netscan"
[[ -f $WINDOWS ]] && cp -f "$WINDOWS" "$CLE/Windows/netscan.exe"
# Version macOS retirée (tag git avec-macos) : son dossier ne reste pas sur la clé.
rm -rf "$CLE/macOS"
cp -f outils/LISEZMOI.txt "$CLE/LISEZMOI.txt"
# Code source complet (avec l'historique git) pour continuer le développement depuis n'importe quel ordinateur.
# exFAT ne garde ni droits ni liens : -rt suffit, --modify-window tolère sa précision de 2 s.
rsync -rt --delete --modify-window=2 --exclude /target/ ./ "$CLE/source/"
sync
echo "Clé NETSCAN à jour : $CLE ($(./"$LINUX" --version))"
# Une seule notification à l'écran : la suivante (lancement manuel puis service déclenché par la compilation) la remplace.
if command -v notify-send >/dev/null; then
  ID_FICHIER="${XDG_RUNTIME_DIR:-/tmp}/netscan-notification.id"
  ID=$(cat "$ID_FICHIER" 2>/dev/null || echo 0)
  notify-send -p -r "$ID" -a netscan -i netscan "Clé NETSCAN à jour" "$(./"$LINUX" --version)" >"$ID_FICHIER" || true
fi
