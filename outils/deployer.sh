#!/usr/bin/env bash
# Compile sentinel (Linux statique + Windows), l'installe localement et met à jour la clé USB SENTINEL si elle est branchée.
#   outils/deployer.sh                 compiler puis déployer
#   outils/deployer.sh --sans-compiler copier les dernières versions compilées (utilisé au branchement de la clé)
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

LINUX=target/x86_64-unknown-linux-musl/release/sentinel
WINDOWS=target/x86_64-pc-windows-gnu/release/sentinel.exe

# Un seul déploiement à la fois : le service déclenché par la compilation attend la fin du lancement manuel.
exec 9>"${XDG_RUNTIME_DIR:-/tmp}/sentinel-deployer.lock"
if [[ ${1:-} == --sans-compiler ]]; then
  # Le service part dès que le binaire Linux est écrit, alors que Windows compile encore :
  # attendre que cargo ait fini (3 s sans cargo, 15 min au plus) pour ne copier qu'une fois.
  for ((calme = 0, tours = 0; calme < 3 && tours < 900; tours++)); do
    if pgrep -x cargo >/dev/null; then calme=0; else calme=$((calme + 1)); fi
    sleep 1
  done
fi
flock 9

if [[ ${1:-} != --sans-compiler ]]; then
  cargo build --release --target x86_64-unknown-linux-musl
  cargo build --release --target x86_64-pc-windows-gnu
fi
install -Dm755 "$LINUX" "$HOME/.cargo/bin/sentinel"
# Sauvegarde hors de la maison : les commits partent vers le dépôt privé GitHub (sans bloquer s'il n'y a pas d'Internet).
if git remote get-url origin >/dev/null 2>&1; then
  timeout 30 git push -q origin HEAD 2>/dev/null && echo "Code envoyé sur GitHub." || echo "GitHub injoignable : le code partira au prochain déploiement."
fi
# Ancien nom (netscan, jusqu'à 0.10.0) : reste une commande, qui lance sentinel.
ln -sfn sentinel "$HOME/.cargo/bin/netscan"

CLE=$(find "/run/media/$USER" -maxdepth 2 \( -name sentinel.cle -o -name netscan.cle \) -printf '%h\n' 2>/dev/null | head -1)
if [[ -z $CLE ]]; then
  echo "Clé SENTINEL non branchée : elle sera mise à jour au prochain branchement."
  exit 0
fi

mkdir -p "$CLE"/{Linux,Windows,donnees,source}
# Clé préparée sous l'ancien nom : témoin et programmes renommés (l'étiquette du volume, elle, demande root).
[[ -f $CLE/netscan.cle ]] && mv -f "$CLE/netscan.cle" "$CLE/sentinel.cle"
rm -f "$CLE/Linux/netscan" "$CLE/Windows/netscan.exe"
cp -f "$LINUX" "$CLE/Linux/sentinel"
[[ -f $WINDOWS ]] && cp -f "$WINDOWS" "$CLE/Windows/sentinel.exe"
# Version macOS retirée (tag git avec-macos) : son dossier ne reste pas sur la clé.
rm -rf "$CLE/macOS"
cp -f outils/LISEZMOI.txt "$CLE/LISEZMOI.txt"
cp -f outils/README.txt "$CLE/README.txt"
# Code source complet (avec l'historique git) pour continuer le développement depuis n'importe quel ordinateur.
# exFAT ne garde ni droits ni liens : -rt suffit, --modify-window tolère sa précision de 2 s.
rsync -rt --delete --modify-window=2 --exclude /target/ ./ "$CLE/source/"
sync
echo "Clé SENTINEL à jour : $CLE ($(./"$LINUX" --version))"
# Une seule notification par version copiée : le lancement manuel et le service qui le suit copient les mêmes
# binaires. (Remplacer la notification ne suffit pas : la barre l'oublie dès que la bulle a disparu.)
EMPREINTE_FICHIER="${XDG_RUNTIME_DIR:-/tmp}/sentinel-notification.empreinte"
EMPREINTE=$({ cat "$LINUX" "$WINDOWS" 2>/dev/null || true; } | sha256sum)
if command -v notify-send >/dev/null && [[ $(cat "$EMPREINTE_FICHIER" 2>/dev/null) != "$EMPREINTE" ]]; then
  notify-send -a sentinel -i sentinel "Clé SENTINEL à jour" "$(./"$LINUX" --version)" || true
  echo "$EMPREINTE" >"$EMPREINTE_FICHIER"
fi
