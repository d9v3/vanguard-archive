#!/usr/bin/env bash
# Installe (ou réinstalle) sur le PC de développement les unités systemd de l'utilisateur qui tiennent la clé USB à
# jour : gardien-compilation.path (après chaque compilation) lance gardien-copie.service, et gardien-cle.service part
# au branchement de la clé. Les images Linux de la clé (outils/images-cle.sh) : gardien-images.timer les cherche
# chaque semaine, gardien-images-cle.service les copie au branchement.
#   outils/systemd/installer.sh
set -euo pipefail
cd "$(dirname "$0")"
UNITES="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
# Les unités lancent %h/Projects/gardien/outils/deployer.sh (%h : dossier personnel) : le dépôt doit être là.
if [[ $(cd ../.. && pwd -P) != $(cd "$HOME/Projects/gardien" 2>/dev/null && pwd -P) ]]; then
  echo "Attention : les unités lancent ~/Projects/gardien/outils/deployer.sh, pas celui de $(cd ../.. && pwd)." >&2
fi

# Réinstallation (dépôt déplacé, unités changées) : les liens d'avant sont retirés, puis refaits.
for unite in gardien-copie.service gardien-cle.service gardien-compilation.path gardien-images.service \
  gardien-images.timer gardien-images-cle.service; do
  systemctl --user disable "$unite" >/dev/null 2>&1 || true
  rm -f "$UNITES/$unite" "$UNITES"/*.wants/"$unite"
done
systemctl --user link "$PWD/gardien-copie.service" >/dev/null
systemctl --user enable "$PWD/gardien-cle.service" >/dev/null
systemctl --user enable --now "$PWD/gardien-compilation.path" >/dev/null
systemctl --user link "$PWD/gardien-images.service" >/dev/null
systemctl --user enable --now "$PWD/gardien-images.timer" >/dev/null
systemctl --user enable "$PWD/gardien-images-cle.service" >/dev/null
systemctl --user daemon-reload
echo "Unités installées : gardien-compilation.path, gardien-copie.service, gardien-cle.service, gardien-images.timer,"
echo "gardien-images.service, gardien-images-cle.service."
