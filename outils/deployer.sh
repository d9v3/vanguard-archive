#!/usr/bin/env bash
# Compile sentinel (Linux statique + Windows), l'installe localement et met à jour la clé USB SENTINEL si elle est branchée.
#   outils/deployer.sh                 compiler puis déployer
#   outils/deployer.sh --branchement   au branchement de la clé : récupérer la dernière version de GitHub, la
#                                      compiler si elle est nouvelle, puis copier
#   outils/deployer.sh --sans-compiler copier les dernières versions compilées (après chaque compilation)
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

LINUX=target/x86_64-unknown-linux-musl/release/sentinel
WINDOWS=target/x86_64-pc-windows-gnu/release/sentinel.exe
# Commit dont viennent les binaires compilés : on ne recompile pas une version déjà compilée.
COMMIT_COMPILE=target/.commit-compile
MODE=${1:-}

compiler() {
  # Liste des fabricants de plus d'un mois : on la rafraîchit avant de compiler (elle est intégrée au programme), et
  # elle part dans son propre commit. Sans Internet, on garde l'ancienne.
  if [[ -n $(find assets/oui.tsv -mtime +30) ]] && outils/maj-fabricants.sh; then
    if ! git diff --quiet -- assets/oui.tsv; then
      git commit -q -m "Fabricants : liste du $(date +%F)" -- assets/oui.tsv && echo "Liste des fabricants mise à jour."
    else
      touch assets/oui.tsv
    fi
  fi
  cargo build --release --target x86_64-unknown-linux-musl
  cargo build --release --target x86_64-pc-windows-gnu
  git rev-parse HEAD >"$COMMIT_COMPILE"
}

# Un seul déploiement à la fois : le service déclenché par la compilation attend la fin du lancement manuel.
exec 9>"${XDG_RUNTIME_DIR:-/tmp}/sentinel-deployer.lock"
if [[ $MODE == --sans-compiler ]]; then
  # Le service part dès que le binaire Linux est écrit, alors que Windows compile encore :
  # attendre que cargo ait fini (3 s sans cargo, 15 min au plus) pour ne copier qu'une fois.
  for ((calme = 0, tours = 0; calme < 3 && tours < 900; tours++)); do
    if pgrep -x cargo >/dev/null; then calme=0; else calme=$((calme + 1)); fi
    sleep 1
  done
fi
flock 9

VENU_DE_GITHUB=""
if [[ $MODE == --branchement ]]; then
  # Dernière version de GitHub (code modifié depuis un autre ordinateur, puis poussé). Récupérée seulement sans
  # risque : aucun changement local en cours, et un historique qui ne fait qu'avancer. Sans Internet : on continue.
  if timeout 30 git fetch -q origin 2>/dev/null; then
    DISTANT=$(git rev-parse '@{upstream}' 2>/dev/null || true)
    if [[ -n $DISTANT && $DISTANT != $(git rev-parse HEAD) ]]; then
      if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
        echo "GitHub a une version plus récente, mais des changements locaux sont en cours : rien de récupéré."
      elif git merge-base --is-ancestor HEAD "$DISTANT"; then
        git merge -q --ff-only "$DISTANT" && VENU_DE_GITHUB=1 && echo "Dernière version récupérée de GitHub."
      else
        echo "GitHub et ce PC ont chacun des commits que l'autre n'a pas : rien de récupéré (à fusionner à la main)."
      fi
    fi
  else
    echo "GitHub injoignable : copie de la version locale."
  fi
  if [[ ! -f $LINUX || $(cat "$COMMIT_COMPILE" 2>/dev/null) != $(git rev-parse HEAD) ]]; then
    compiler
  fi
elif [[ $MODE != --sans-compiler ]]; then
  compiler
fi
install -Dm755 "$LINUX" "$HOME/.cargo/bin/sentinel"
# Sauvegarde hors de la maison : les commits partent vers le dépôt privé GitHub (sans bloquer s'il n'y a pas d'Internet).
if git remote get-url origin >/dev/null 2>&1; then
  timeout 30 git push -q origin HEAD 2>/dev/null && echo "Code envoyé sur GitHub." || echo "GitHub injoignable : le code partira au prochain déploiement."
fi
# Ancien nom (netscan, jusqu'à 0.10.0) : reste une commande, qui lance sentinel.
ln -sfn sentinel "$HOME/.cargo/bin/netscan"
# Icône du lanceur (Sentinel.desktop : Icon=sentinel) : rendu du trou noir (outils/icone.py), une image par taille
# de 16 à 512 px, pour que la barre et le lanceur n'aient pas à réduire eux-mêmes la plus grande.
ICONES="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
# Les anciennes icônes SVG passeraient avant le PNG : on les retire.
rm -f "$ICONES"/{scalable,256x256,16x16,24x24,32x32}/apps/sentinel.svg
for png in assets/icones/sentinel-*.png; do
  t=${png##*-}
  t=${t%.png}
  install -Dm644 "$png" "$ICONES/${t}x$t/apps/sentinel.png"
done
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -qtf "$ICONES" || true

# Erreurs du journal de sentinel (plantages, PowerShell en échec…) : celles de cet ordinateur et celles que la clé
# rapporte des autres sont gardées dans retours/, puis envoyées en tickets GitHub avec gh (un ticket par erreur, les
# répétitions en commentaire ; outils/journal-vers-github.py). Sans Internet, elles attendent le déploiement suivant.
RETOURS="${XDG_DATA_HOME:-$HOME/.local/share}/sentinel/retours"
rapatrier_journal() { # $1 : journal à vider, $2 : d'où il vient
  [[ -s $1 ]] || return 0
  mkdir -p "$RETOURS"
  local nb
  nb=$(grep -c '^== ' "$1" || true)
  cat "$1" >>"$RETOURS/journal-erreurs.txt"
  cat "$1" >>"$RETOURS/a-envoyer-github.txt"
  : >"$1"
  echo "Journal $2 : $nb erreur(s) rapatriée(s) dans $RETOURS/journal-erreurs.txt"
  command -v notify-send >/dev/null &&
    notify-send -a sentinel -i sentinel "Sentinel : $nb erreur(s) rapportée(s) ($2)" "$RETOURS/journal-erreurs.txt" || true
}
envoyer_journal() {
  [[ -s $RETOURS/a-envoyer-github.txt ]] && command -v gh >/dev/null || return 0
  timeout 300 python3 outils/journal-vers-github.py "$RETOURS/a-envoyer-github.txt" ||
    echo "Journal : envoi sur GitHub impossible, il repartira au prochain déploiement."
}
# Sans clé branchée, sentinel écrit son journal dans son dossier de cet ordinateur.
rapatrier_journal "${XDG_DATA_HOME:-$HOME/.local/share}/sentinel/journal-erreurs.txt" "de cet ordinateur"
envoyer_journal

CLE=$(find "/run/media/$USER" -maxdepth 2 \( -name sentinel.cle -o -name netscan.cle \) -printf '%h\n' 2>/dev/null | head -1)
if [[ -z $CLE ]]; then
  echo "Clé SENTINEL non branchée : elle sera mise à jour au prochain branchement."
  exit 0
fi

# Partition SENTINELLOG (la seule modifiable sur les autres ordinateurs) : elle se monte en même temps que SENTINEL,
# parfois une seconde après. Son journal d'erreurs est rapatrié ici puis vidé, pour améliorer sentinel.
JOURNAL=""
for _ in {1..10}; do
  JOURNAL=$(findmnt -nro TARGET -S LABEL=SENTINELLOG 2>/dev/null | head -1 || true)
  [[ -n $JOURNAL ]] && break
  sleep 1
done
if [[ -n $JOURNAL ]]; then
  touch "$JOURNAL/sentinel-journal.cle"
  rapatrier_journal "$JOURNAL/journal-erreurs.txt" "de la clé"
  envoyer_journal
fi

mkdir -p "$CLE"/{Linux,Windows,donnees,source}
# Clé préparée sous l'ancien nom : témoin et programmes renommés (l'étiquette du volume, elle, demande root).
[[ -f $CLE/netscan.cle ]] && mv -f "$CLE/netscan.cle" "$CLE/sentinel.cle"
rm -f "$CLE/Linux/netscan" "$CLE/Windows/netscan.exe"
# Empreinte de cet ordinateur (SHA-1 de /etc/machine-id) : partout ailleurs, sentinel remonte la clé en lecture seule
# sous Linux (src/protection.rs).
printf '%s' "$(cat /etc/machine-id)" | sha1sum | cut -d' ' -f1 >"$CLE/sentinel.cle"
cp -f "$LINUX" "$CLE/Linux/sentinel"
[[ -f $WINDOWS ]] && cp -f "$WINDOWS" "$CLE/Windows/sentinel.exe"
# Version macOS : compilée sur un Mac de GitHub (.github/workflows/macos.yml, chaque nuit si le code a changé),
# récupérée ici quand une compilation plus récente a réussi. Sans Internet ou sans gh : on garde la dernière.
MAC=target/macos
if command -v gh >/dev/null; then
  RUN=$(timeout 20 gh run list --workflow macos.yml --branch "$(git rev-parse --abbrev-ref HEAD)" --status success \
    --limit 1 --json databaseId,headSha -q '.[0] | "\(.databaseId) \(.headSha)"' 2>/dev/null || true)
  if [[ -n $RUN && ${RUN#* } != $(cat "$MAC/commit.txt" 2>/dev/null) ]]; then
    rm -rf "$MAC.nouveau"
    if timeout 120 gh run download "${RUN%% *}" -n sentinel-macos -D "$MAC.nouveau" >/dev/null 2>&1; then
      rm -rf "$MAC" && mv "$MAC.nouveau" "$MAC" && echo "Version macOS récupérée de GitHub (commit ${RUN#* })."
    fi
  fi
fi
if [[ -f $MAC/sentinel ]]; then
  mkdir -p "$CLE/macOS"
  cp -f "$MAC/sentinel" "$CLE/macOS/sentinel"
  cp -f "outils/cle/Lancer Sentinel.command" "$CLE/"
fi
# macOS écrit dès le branchement (index Spotlight, journal des changements, corbeille) : ces témoins l'en
# dispensent, la clé reste propre même avant que sentinel la protège.
touch "$CLE/.metadata_never_index" "$CLE/.Trashes"
mkdir -p "$CLE/.fseventsd" && touch "$CLE/.fseventsd/no_log"
cp -f outils/LISEZMOI.txt "$CLE/LISEZMOI.txt"
cp -f outils/README.txt "$CLE/README.txt"
# Avis de licence des bibliothèques incluses dans les binaires (MIT, Apache… demandent de les joindre).
python3 outils/licences-tierces.py >/dev/null
cp -f LICENSE "$CLE/LICENSE.txt"
cp -f LICENCES-TIERCES.txt "$CLE/LICENCES-TIERCES.txt"
# Icône et nom du lecteur dans l'Explorateur, lanceurs à la racine. (Windows ne lance plus rien tout seul depuis une
# clé USB, depuis Windows 7 ; GNOME, lui, propose de lancer autorun.sh.)
cp -f assets/sentinel.ico "$CLE/sentinel.ico"
cp -f outils/cle/autorun.inf outils/cle/autorun.sh "outils/cle/Lancer Sentinel.bat" "$CLE/"
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
  notify-send -a sentinel -i sentinel "Clé SENTINEL à jour${VENU_DE_GITHUB:+ (depuis GitHub)}" "$(./"$LINUX" --version)" || true
  echo "$EMPREINTE" >"$EMPREINTE_FICHIER"
fi
