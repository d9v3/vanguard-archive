#!/usr/bin/env bash
# Failles connues des programmes compilés, lues dans la liste de leurs dépendances, versions comprises, que chacun
# porte (cargo auditable build, section .dep-v0) : cargo audit bin ne lit que le programme, pas le code source, comme
# le ferait quiconque l'a téléchargé. Les avis sont traités comme par cargo deny (deny.toml) : une faille, une
# bibliothèque abandonnée ou au code défaillant (unsound) arrête tout, une version retirée de crates.io (yanked) est
# seulement signalée, et les seules exceptions sont celles de deny.toml, où est leur preuve. Un programme sans sa liste
# est refusé : cargo audit n'en retrouverait qu'une partie (messages de panique) et pourrait dire vert à tort. La liste
# vient de cargo metadata : elle compte parfois une dépendance facultative qui n'est pas compilée (9 de plus que cargo
# tree pour Linux comme pour Windows, le 21 oct. 2026), d'où au pire une alerte de trop, jamais une de moins.
#   outils/failles-programmes.sh <programme>...
# Lancé par outils/deployer.sh après chaque compilation, et par la CI sur les programmes qu'elle compile (ci.yml,
# macos.yml). Sans Internet : la base RustSec du dernier téléchargement, et c'est dit.
set -euo pipefail
RACINE=$(cd "$(dirname "$0")/.." && pwd)

if (($# == 0)); then
  echo "outils/failles-programmes.sh <programme>..." >&2
  exit 2
fi
if ! command -v cargo-audit >/dev/null; then
  echo "✖ cargo-audit absent : cargo install cargo-audit --locked" >&2
  exit 1
fi

OPTIONS=(--color never --deny unmaintained --deny unsound)
# Les exceptions de deny.toml, par leur identifiant RustSec. Une exception d'une autre forme (toute une bibliothèque)
# n'a pas d'équivalent pour cargo audit : refusée plutôt que perdue en route.
EXCEPTIONS=$(python3 -I -c '
import sys
import tomllib

with open(sys.argv[1], "rb") as f:
    exceptions = tomllib.load(f).get("advisories", {}).get("ignore", [])
for e in exceptions:
    ident = e if isinstance(e, str) else e.get("id")
    if not ident:
        sys.exit(f"exception de deny.toml sans identifiant RustSec, sans équivalent pour cargo audit : {e}")
    print(ident)
' "$RACINE/deny.toml")
for id in $EXCEPTIONS; do
  OPTIONS+=(--ignore "$id")
done
if [[ -n ${VANGUARD_HORS_LIGNE:-} ]] || ! curl -fsI --max-time 5 https://github.com >/dev/null 2>&1; then
  OPTIONS+=(--no-fetch --stale)
  echo "⚠ sans Internet : base RustSec du dernier téléchargement, qui ignore les failles publiées depuis"
fi

CODE=0
SORTIE=$(cargo audit "${OPTIONS[@]}" bin "$@" 2>&1) || CODE=$?
# « Found 'cargo auditable' data in <programme> (N dependencies) » : la liste complète a été lue. (Sans tableau vide :
# le bash 3.2 d'un Mac le refuse sous set -u.)
liste_lue() { grep -qF "'cargo auditable' data in $1 (" <<<"$SORTIE"; }
SANS_LISTE=0
for programme in "$@"; do
  liste_lue "$programme" || SANS_LISTE=1
done
if ((CODE != 0 || SANS_LISTE)); then
  printf '%s\n' "$SORTIE"
  for programme in "$@"; do
    liste_lue "$programme" ||
      echo "✖ $programme : sans la liste de ses dépendances (à recompiler par cargo auditable build)"
  done
  if ((CODE != 0)); then
    echo "✖ cargo audit : failles connues ou vérification impossible (voir ci-dessus). Une faille se corrige en mettant"
    echo "  la dépendance à jour ; une exception ne s'admet que dans deny.toml, avec sa preuve."
  fi
  echo "Ces programmes ne partent nulle part."
  exit 1
fi
# Les avertissements qui ne bloquent pas (version retirée de crates.io) restent visibles.
grep -q '^warning' <<<"$SORTIE" && printf '%s\n' "$SORTIE"
for programme in "$@"; do
  nombre=$(grep -F "'cargo auditable' data in $programme (" <<<"$SORTIE" |
    sed -n 's/.*(\([0-9]*\) dependencies).*/\1/p')
  echo "✔ $programme : $nombre dépendances listées, aucune faille connue"
done
if [[ -n $EXCEPTIONS ]]; then
  echo "  exceptions de deny.toml : $(printf '%s\n' "$EXCEPTIONS" | paste -sd, - | sed 's/,/, /g')"
fi
