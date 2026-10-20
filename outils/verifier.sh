#!/usr/bin/env bash
# Tout vérifier en une commande, avant un commit ou une livraison : mise en forme, clippy sur les quatre cibles, tests
# Linux et Windows (sous Wine), les tests Linux refaits sans Internet, scripts PowerShell, shell et Python, liens
# internes, textes français et anglais.
# Chaque cible de compilation a sa chaîne (clippy, puis ses tests) et les quatre tournent en même temps : cargo garde
# un dossier par cible, elles ne s'attendent presque pas. À la fin, une ligne par étape ; le code de sortie dit si tout
# est vert.
#   outils/verifier.sh               tout
#   outils/verifier.sh --rapide      mise en forme, clippy et tests Linux seulement
#   outils/verifier.sh --sans-wine   tout, sauf les tests Windows
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

MODE=${1:-}
WINE=${VANGUARD_WINE:-$HOME/.local/share/Steam/compatibilitytools.d/GE-Proton11-9-x86_64/files/bin/wine}
PWSH=${VANGUARD_PWSH:-$HOME/.cache/vanguard-dev/pwsh/pwsh}
# Journaux et préfixe Wine hors de /tmp, dont le quota est partagé par les sessions ; retirés à la fin.
TRAVAIL=$(mktemp -d "$HOME/.cache/vanguard-dev/verifier.XXXX")
trap 'rm -rf "$TRAVAIL"' EXIT
DEBUT=$SECONDS

# Une étape : sa commande, son journal, son état (« ok 41 » ou « echec 41 », en secondes).
etape() {
  local nom=$1 debut=$SECONDS
  shift
  if "$@" >"$TRAVAIL/$nom.log" 2>&1; then
    echo "ok $((SECONDS - debut))" >"$TRAVAIL/$nom.etat"
  else
    echo "echec $((SECONDS - debut))" >"$TRAVAIL/$nom.etat"
    return 1
  fi
}

# YARA-X (par wasmtime) compile un petit fichier C : musl-gcc pour Linux, le gcc de MinGW pour Windows, clang pour les
# cibles Mac, qu'il vise sans les outils d'Apple (outils/mac-entetes) ; clippy n'assemble jamais le programme.
clippy() {
  case $1 in
    *-apple-darwin)
      local v=${1//-/_}
      env "CC_$v=clang" "CFLAGS_$v=-ffreestanding -nostdlibinc -I$PWD/outils/mac-entetes" \
        cargo clippy -q --all-targets --target "$1" -- -D warnings ;;
    *) cargo clippy -q --all-targets --target "$1" -- -D warnings ;;
  esac
}

# Les compilateurs C qu'il faut ici, dits d'emblée plutôt qu'au milieu d'une compilation.
for outil in musl-gcc x86_64-w64-mingw32-gcc clang; do
  command -v "$outil" >/dev/null || echo "⚠ $outil manque (Arch : musl, mingw-w64-gcc, clang) : la compilation de YARA-X échouera."
done

tests_wine() {
  local prefixe resultat
  prefixe=$(mktemp -d "$TRAVAIL/wine.XXXX")
  WINEPREFIX=$prefixe WINEDEBUG=-all CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=$WINE \
    cargo test -q --target x86_64-pc-windows-gnu
  resultat=$?
  # Le serveur de Wine survit quelques secondes aux tests et écrit encore dans le préfixe : arrêté avant le ménage.
  WINEPREFIX=$prefixe "${WINE%/*}/wineserver" -k 2>/dev/null
  WINEPREFIX=$prefixe "${WINE%/*}/wineserver" -w 2>/dev/null
  return "$resultat"
}

scripts_powershell() {
  local erreurs=0 f
  for f in outils/test-windows/*.ps1; do
    "$PWSH" -NoProfile -NonInteractive -Command \
      "\$e = \$null; \$t = \$null; [void][System.Management.Automation.Language.Parser]::ParseFile('$PWD/$f', [ref]\$t, [ref]\$e); if (\$e.Count) { \$e | ForEach-Object { '$f : ' + \$_.Message }; exit 1 }" ||
      erreurs=$((erreurs + 1))
  done
  ((erreurs == 0))
}

# Toute la suite Linux refaite sans Internet : dans un espace réseau vide (unshare -rn, sans root ; la boucle locale
# seule, remontée), VANGUARD_HORS_LIGNE posé pour les essais qui le demandent. Chaque outil doit s'y arrêter de
# lui-même et dire pourquoi. Sans espaces de noms d'utilisateur (noyau qui les refuse), l'étape n'est pas lancée.
hors_ligne() {
  unshare -rn true 2>/dev/null || { echo "espaces de noms d'utilisateur indisponibles"; return 2; }
  unshare -rn sh -c 'ip link set lo up && VANGUARD_HORS_LIGNE=1 exec cargo test -q --offline'
}

scripts_shell() { find outils -name '*.sh' -print0 | xargs -0 -n1 bash -n; }

# Analysés sans être compilés sur disque : py_compile laisserait des __pycache__ dans outils/.
scripts_python() {
  find outils -name '*.py' -print0 |
    xargs -0 python3 -c 'import ast, sys; [ast.parse(open(f, encoding="utf-8").read(), f) for f in sys.argv[1:]]'
}

# Les textes affichés comparés à master : un texte perdu ou nouveau se voit avant le commit. Sur master, rien à
# comparer.
textes() {
  [[ $(git rev-parse HEAD) == $(git rev-parse master 2>/dev/null) ]] && { echo "sur master"; return 0; }
  python3 "$HOME/.cache/vanguard-dev/outils-dp40/textes.py"
}

if ! etape mise-en-forme cargo fmt --check; then
  echo "✖ mise en forme : lancer cargo fmt"
  sed -n '1,20p' "$TRAVAIL/mise-en-forme.log"
  exit 1
fi

{
  etape clippy-linux clippy x86_64-unknown-linux-musl && etape tests-linux cargo test -q &&
    if [[ $MODE != --rapide ]]; then etape tests-hors-ligne hors_ligne; fi
} &
if [[ $MODE != --rapide ]]; then
  if [[ $MODE == --sans-wine ]]; then
    etape clippy-windows clippy x86_64-pc-windows-gnu &
  else
    { etape clippy-windows clippy x86_64-pc-windows-gnu && etape tests-windows tests_wine; } &
  fi
  etape clippy-macos-arm clippy aarch64-apple-darwin &
  etape clippy-macos-intel clippy x86_64-apple-darwin &
  etape powershell scripts_powershell &
  etape shell scripts_shell &
  etape python scripts_python &
  etape liens python3 outils/liens.py --hors-ligne &
  etape textes textes &
fi
wait

# Les tests laissent chacun un dossier jetable (reseau::dossier_local sous cfg(test)) : ceux dont le processus est fini
# partent.
for d in /tmp/vanguard-tests-*; do
  [[ -d $d ]] && ! kill -0 "${d##*-}" 2>/dev/null && rm -rf "$d"
done

# Nombre de tests passés, lu dans « test result: ok. 313 passed ».
passes() { grep -o 'ok\. [0-9]* passed' "$TRAVAIL/$1.log" 2>/dev/null | awk '{s += $2} END {print s + 0}'; }

ECHECS=0
ligne() {
  local nom=$1 libelle=$2 etat duree
  [[ -f $TRAVAIL/$nom.etat ]] || { printf '  · %-34s non lancé\n' "$libelle"; return; }
  read -r etat duree <"$TRAVAIL/$nom.etat"
  if [[ $etat == ok ]]; then
    printf '  ✔ %-34s %4s s\n' "$libelle" "$duree"
  else
    ECHECS=$((ECHECS + 1))
    printf '  ✖ %-34s %4s s\n' "$libelle" "$duree"
    tail -n 25 "$TRAVAIL/$nom.log" | sed 's/^/      /'
  fi
}

echo
ligne mise-en-forme "mise en forme"
ligne clippy-linux "clippy Linux"
ligne tests-linux "tests Linux ($(passes tests-linux))"
if [[ $MODE != --rapide ]]; then
  ligne tests-hors-ligne "tests Linux sans Internet ($(passes tests-hors-ligne))"
  ligne clippy-windows "clippy Windows"
  [[ $MODE == --sans-wine ]] || ligne tests-windows "tests Windows sous Wine ($(passes tests-windows))"
  ligne clippy-macos-arm "clippy macOS Apple Silicon"
  ligne clippy-macos-intel "clippy macOS Intel"
  ligne powershell "scripts PowerShell"
  ligne shell "scripts shell"
  ligne python "scripts Python"
  ligne liens "liens internes"
  ligne textes "textes FR/EN"
  [[ -f $TRAVAIL/textes.log ]] && grep -E '^(perdues|nouvelles) : \[[^]]' "$TRAVAIL/textes.log" | cut -c1-200 | sed 's/^/      /'
fi
DUREE=$((SECONDS - DEBUT))
if ((ECHECS)); then
  echo "$ECHECS étape(s) en échec, en $((DUREE / 60)) min $((DUREE % 60)) s."
  exit 1
fi
echo "Tout est vert, en $((DUREE / 60)) min $((DUREE % 60)) s."
