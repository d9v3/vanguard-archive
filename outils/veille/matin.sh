#!/usr/bin/env bash
# Le rappel du matin de la veille continue (vanguard-veille-matin.timer, 08 h 30) : la notification de la nuit est
# renvoyée une fois si elle n'a pas été marquée vue. Rien si tout était vert.
#   matin.sh          renvoie la notification en attente, une seule fois
#   matin.sh --vu     la marque vue (plus de rappel)
set -uo pipefail
source "$(dirname "$0")/commun.sh"

A_LIRE=$VEILLE/a-lire
if [[ ${1:-} == --vu ]]; then
  rm -f "$A_LIRE"
  exit 0
fi
[[ -f $A_LIRE ]] || exit 0
titre=$(sed -n 1p "$A_LIRE")
corps=$(sed -n 2p "$A_LIRE")
rm -f "$A_LIRE"
notify-send -a Vanguard -i vanguard -u critical "${titre:-Vanguard veille} (rappel)" \
  "$corps — rapport : $VEILLE/$JOUR.md" 2>/dev/null || true
