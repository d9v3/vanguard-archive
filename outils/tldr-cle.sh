#!/usr/bin/env bash
# Met les archives de tldr-pages (anglais, français) dans un dossier de la clé : lancé depuis la clé, Vanguard a ses
# 30 000 exemples dès le premier lancement, même sur un ordinateur sans Internet (src/guide/tldr.rs lit la plus
# récente de sa copie et de celle de la clé). Le projet refait ses archives chaque jour : une archive de moins d'un
# jour est gardée telle quelle. Sans Internet, la copie de cet ordinateur sert si elle est plus récente ; une page
# d'erreur ou une archive tronquée ne remplace jamais la bonne.
#   outils/tldr-cle.sh <dossier>       (deployer.sh : <clé>/tldr)
set -euo pipefail
cd "$(dirname "$0")/.."
DOSSIER=${1:?"usage : outils/tldr-cle.sh <dossier>"}
ADRESSE=https://github.com/tldr-pages/tldr/releases/latest/download
# La copie que le guide télécharge sur cet ordinateur (reseau::dossier_local).
LOCAL="${XDG_DATA_HOME:-$HOME/.local/share}/vanguard/tldr"
mkdir -p "$DOSSIER"
TEMP=$(mktemp -d)
# Une copie interrompue (clé pleine, script arrêté) ne laisse pas de .nouveau tronqué qui occupe la clé : le
# manifeste de deployer.sh l'enregistrerait.
trap 'rm -rf "$TEMP"; rm -f "$DOSSIER"/tldr-pages.*.zip.nouveau' EXIT

# Garde-fou : une archive zip intacte, avec au moins $2 pages (l'anglais en a environ 7 600, le français 1 100).
lisible() {
  python3 -I - "$1" "$2" <<'FIN'
import sys, zipfile
try:
    with zipfile.ZipFile(sys.argv[1]) as z:
        if z.testzip() is not None:
            sys.exit(1)
        pages = sum(1 for n in z.namelist() if n.endswith(".md") and "/" in n)
except (OSError, zipfile.BadZipFile):
    sys.exit(1)
sys.exit(0 if pages >= int(sys.argv[2]) else 1)
FIN
}

echec=0
for langue in en fr; do
  nom="tldr-pages.$langue.zip"
  fin="$DOSSIER/$nom"
  minimum=$([[ $langue == en ]] && echo 5000 || echo 500)
  if [[ -n $(find "$fin" -mmin -1440 2>/dev/null) ]]; then
    continue
  fi
  if curl -fsL --max-time 120 --max-filesize $((40 << 20)) -o "$TEMP/$nom" "$ADRESSE/$nom" &&
    lisible "$TEMP/$nom" "$minimum"; then
    source="$TEMP/$nom"
  elif [[ -f $LOCAL/$nom && $LOCAL/$nom -nt $fin ]] && lisible "$LOCAL/$nom" "$minimum"; then
    # Sans Internet : la copie de cet ordinateur, avec sa date, qui dit son âge au guide.
    source="$LOCAL/$nom"
  else
    echo "tldr-pages ($langue) : rien de neuf à copier, la clé garde son archive." >&2
    continue
  fi
  # Copie à côté, puis renommage : une clé retirée pendant la copie ne laisse pas une archive à moitié écrite. Une copie
  # qui échoue (clé pleine) laisse la clé avec son archive, et l'autre langue est quand même essayée ; le code de
  # sortie le dit à deployer.sh.
  if ! cp -p "$source" "$fin.nouveau"; then
    rm -f "$fin.nouveau"
    echo "tldr-pages ($langue) : la copie a échoué, la clé garde son archive." >&2
    echec=1
    continue
  fi
  mv -f "$fin.nouveau" "$fin"
  echo "tldr-pages ($langue) : archive de la clé à jour."
done
exit "$echec"
