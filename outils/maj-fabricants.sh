#!/usr/bin/env bash
# Met à jour assets/oui.tsv (préfixe MAC → fabricant) depuis la liste que Wireshark tire chaque jour des registres
# IEEE : blocs MA-L (6 chiffres hexadécimaux), MA-M (7) et MA-S (9), ces deux derniers très utilisés par les objets
# connectés. Le site de l'IEEE refuse les téléchargements automatiques (erreur 418).
#   outils/maj-fabricants.sh
set -euo pipefail
cd "$(dirname "$0")/.."
TEMP=$(mktemp)
trap 'rm -f "$TEMP" "$TEMP.tsv"' EXIT
curl -fsSL --max-time 120 -o "$TEMP" https://www.wireshark.org/download/automated/data/manuf
# « C4:34:6B<tab>HewlettPacka<tab>Hewlett Packard », « 00:55:DA:00/28<tab>… » : nom long s'il existe.
grep -v '^#' "$TEMP" | awk -F'\t' '
  NF >= 2 {
    split($1, a, "/"); gsub(/[: ]/, "", a[1])
    longueur = a[2] == "" ? 6 : a[2] == 28 ? 7 : a[2] == 36 ? 9 : 0
    nom = NF >= 3 && $3 != "" ? $3 : $2
    gsub(/^ +| +$/, "", nom)
    if (longueur && nom != "") print toupper(substr(a[1], 1, longueur)) "\t" nom
  }' | LC_ALL=C sort -u -t$'\t' -k1,1 >"$TEMP.tsv"
# Garde-fou : une page d'erreur ou une liste tronquée ne remplace pas la base.
NB=$(wc -l <"$TEMP.tsv")
if ((NB < 40000)); then
  echo "Liste des fabricants suspecte ($NB lignes) : assets/oui.tsv inchangé." >&2
  exit 1
fi
mv "$TEMP.tsv" assets/oui.tsv
echo "Fabricants : $NB préfixes."
