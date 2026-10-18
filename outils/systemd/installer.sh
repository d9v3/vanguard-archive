#!/usr/bin/env bash
# Installe (ou réinstalle) sur le PC de développement les unités systemd de l'utilisateur qui tiennent la clé USB à
# jour : gardien-compilation.path (après chaque compilation) lance gardien-copie.service, et gardien-cle.service part
# au branchement de la clé. Celles de l'ancien nom (sentinel-…) sont retirées : elles pointaient vers des fichiers
# renommés.
#   outils/systemd/installer.sh
set -euo pipefail
cd "$(dirname "$0")"
UNITES="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
# Les unités lancent %h/Projects/sentinel/outils/deployer.sh (%h : dossier personnel) : le dépôt doit être là.
if [[ $(cd ../.. && pwd -P) != $(cd "$HOME/Projects/sentinel" 2>/dev/null && pwd -P) ]]; then
  echo "Attention : les unités lancent ~/Projects/sentinel/outils/deployer.sh, pas celui de $(cd ../.. && pwd)." >&2
fi

for ancienne in sentinel-compilation.path sentinel-cle.service sentinel-copie.service; do
  systemctl --user disable --now "$ancienne" >/dev/null 2>&1 || true
  rm -f "$UNITES/$ancienne" "$UNITES"/*.wants/"$ancienne"
done
systemctl --user link "$PWD/gardien-copie.service" >/dev/null
systemctl --user enable "$PWD/gardien-cle.service" >/dev/null
systemctl --user enable --now "$PWD/gardien-compilation.path" >/dev/null
systemctl --user daemon-reload
echo "Unités installées : gardien-compilation.path, gardien-copie.service, gardien-cle.service."
