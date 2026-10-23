#!/usr/bin/env bash
# Fuzzing des lecteurs de données venues d'ailleurs (cargo-fuzz, libFuzzer, chaîne nightly) : le banc de fuzz/, hors
# de la compilation de Vanguard. Trop long pour outils/verifier.sh : à lancer à la main, après avoir touché à un
# lecteur, ou une nuit entière. Le corpus (ce que le fuzzer a appris) et les plantages restent hors du dépôt, dans
# ~/.cache/vanguard-dev/fuzz/ ; les graines de départ, aux valeurs inventées, sont dans fuzz/graines/.
#   outils/fuzz.sh                  toutes les cibles, 60 s chacune
#   outils/fuzz.sh igd              une cible
#   outils/fuzz.sh tout 600         toutes, 10 min chacune
# Prérequis : rustup toolchain install nightly --profile minimal ; cargo install --locked cargo-fuzz.
# Un plantage : corriger le module, ajouter un test de non-régression avec la donnée trouvée (le fichier de
# plantages/<cible>/), puis relancer la cible.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

CIBLES=(plist http_local dns_client chronologie igd courriel_mime pe_version tar mfsa degzip_controle zip)
QUOI=${1:-tout}
DUREE=${2:-60}
FUZZ=${VANGUARD_FUZZ:-$HOME/.cache/vanguard-dev/fuzz}

usage() {
  # "${CIBLES[*]}" joint les cibles par le premier caractère d'IFS.
  local IFS='|'
  echo "usage : outils/fuzz.sh [tout|${CIBLES[*]}] [secondes par cible, 60 par défaut]" >&2
  exit 2
}
[[ $DUREE =~ ^[1-9][0-9]*$ ]] || usage
case $QUOI in
  tout) liste=("${CIBLES[@]}") ;;
  *) [[ " ${CIBLES[*]} " == *" $QUOI "* ]] || usage; liste=("$QUOI") ;;
esac
command -v cargo-fuzz >/dev/null || { echo "✖ cargo-fuzz absent : cargo install --locked cargo-fuzz" >&2; exit 2; }
rustup toolchain list | grep -q '^nightly' ||
  { echo "✖ chaîne nightly absente : rustup toolchain install nightly --profile minimal" >&2; exit 2; }

ECHECS=0
for c in "${liste[@]}"; do
  corpus=$FUZZ/corpus/$c
  plantages=$FUZZ/plantages/$c
  journal=$FUZZ/$c.log
  mkdir -p "$corpus" "$plantages"
  echo "▶ $c, $DUREE s"
  # Le premier dossier reçoit ce que le fuzzer découvre ; les graines ne sont que lues. Compilé hors du dépôt, avec
  # les vérifications de débordement (comme la version publiée) et AddressSanitizer, par défaut chez cargo-fuzz.
  if cargo +nightly fuzz run --fuzz-dir fuzz --target-dir "$FUZZ/cible" "$c" "$corpus" "fuzz/graines/$c" -- \
    -max_total_time="$DUREE" -artifact_prefix="$plantages/" -print_final_stats=1 >"$journal" 2>&1; then
    executions=$(grep -o 'stat::number_of_executed_units: *[0-9]*' "$journal" | grep -o '[0-9]*$')
    couverture=$(grep -o 'cov: [0-9]*' "$journal" | tail -n1 | grep -o '[0-9]*$')
    printf '  ✔ %-12s %s exécutions, couverture %s, corpus de %s entrées\n' "$c" "${executions:-?}" \
      "${couverture:-?}" "$(find "$corpus" -type f | wc -l)"
  else
    ECHECS=$((ECHECS + 1))
    echo "  ✖ $c : plantage ou erreur de compilation (journal : $journal ; données : $plantages/)"
    grep -E '^(thread .* panicked|==[0-9]+==ERROR|SUMMARY|error)' "$journal" | head -n 5 | sed 's/^/      /'
  fi
done
((ECHECS == 0)) || { echo "$ECHECS cible(s) en échec."; exit 1; }
echo "Aucun plantage."
