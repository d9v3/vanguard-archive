#!/usr/bin/env bash
# Failles connues des programmes compilés, lues dans la liste de leurs dépendances, versions comprises, que chacun
# porte (cargo auditable build, section .dep-v0) : cargo audit bin ne lit que le programme, pas le code source, comme
# le ferait quiconque l'a téléchargé. Les avis sont traités comme par cargo deny (deny.toml) : une faille, une
# bibliothèque abandonnée ou au code défaillant (unsound), un avis « notice » arrête tout ; une version retirée de
# crates.io (yanked), elle, est seulement signalée. Les seules exceptions sont celles de deny.toml, où est leur preuve :
# cargo audit lit aussi le .cargo/audit.toml du dossier courant (à défaut, celui de ~/.cargo) et ajoute ses exceptions
# sans le dire ; il tourne donc dans un dossier à lui, dont l'audit.toml vide masque les autres. Un programme sans sa
# liste est refusé : cargo audit n'en retrouverait qu'une partie (messages de panique) et pourrait dire vert à tort. Un
# programme universel de macOS, que cargo audit ne lit pas tel quel, est vérifié moitié par moitié. La liste vient de
# cargo metadata : elle compte parfois une dépendance facultative qui n'est pas compilée (9 de plus que cargo tree pour
# Linux comme pour Windows, le 21 oct. 2026), d'où au pire une alerte de trop, jamais une de moins. cargo-audit est
# celui de la CI (.github/workflows/ci.yml) : le même jugement ici et là-bas.
#   outils/failles-programmes.sh <programme>...
#   outils/failles-programmes.sh --outil   cargo-audit seulement (présent, version de la CI), avant une compilation
# Lancé par outils/deployer.sh (après chaque compilation, et sur la version macOS avant de la copier sur la clé), par
# outils/publier-version.sh sur les trois programmes qu'il publie, et par la CI sur ceux qu'elle compile (ci.yml,
# macos.yml). Sans Internet : la base RustSec du dernier téléchargement, et c'est dit.
set -euo pipefail
RACINE=$(cd "$(dirname "$0")/.." && pwd)

if (($# == 0)); then
  echo "outils/failles-programmes.sh <programme>... (ou --outil)" >&2
  exit 2
fi
# Une autre version de cargo-audit pourrait juger autrement que la CI : celle qu'elle pose (tool: …,cargo-audit@X).
ATTENDUE=$(sed -n 's/.*cargo-audit@\([0-9][0-9.]*\).*/\1/p' "$RACINE/.github/workflows/ci.yml" | head -1)
PRESENTE=$(cargo-audit --version 2>/dev/null | awk '{ print $2 }' || true)
if [[ -z $ATTENDUE ]]; then
  echo "✖ version de cargo-audit introuvable dans .github/workflows/ci.yml (tool: …,cargo-audit@X)" >&2
  exit 1
fi
if [[ $PRESENTE != "$ATTENDUE" ]]; then
  echo "✖ cargo-audit ${PRESENTE:-absent} ici, $ATTENDUE dans la CI (.github/workflows/ci.yml) : il faut le même." >&2
  echo "  cargo install cargo-audit --locked --version $ATTENDUE" >&2
  exit 1
fi
if [[ $1 == --outil ]]; then
  exit 0
fi

OPTIONS=(--color never --deny unmaintained --deny unsound)
# Les exceptions de deny.toml, par leur identifiant RustSec (outils/exceptions-rustsec.py, qui les donne aussi à
# outils/verifier.sh) ; une exception d'une autre forme y est refusée plutôt que perdue en route.
EXCEPTIONS=$(python3 -I "$RACINE/outils/exceptions-rustsec.py")
for id in $EXCEPTIONS; do
  OPTIONS+=(--ignore "$id")
done
if [[ -n ${VANGUARD_HORS_LIGNE:-} ]] || ! curl -fsI --max-time 5 https://github.com >/dev/null 2>&1; then
  OPTIONS+=(--no-fetch --stale)
  echo "⚠ sans Internet : base RustSec du dernier téléchargement, qui ignore les failles publiées depuis"
fi

# Le dossier de cargo audit, retiré à la fin. cargo-audit y est lancé lui-même, sans passer par cargo, qui lirait la
# configuration de ce dossier et de ses parents (/tmp compris), alias de commandes compris.
TRAVAIL=$(mktemp -d "${TMPDIR:-/tmp}/failles-programmes.XXXXXX")
trap 'rm -rf "$TRAVAIL"' EXIT
mkdir "$TRAVAIL/.cargo"
echo "# outils/failles-programmes.sh : aucune exception ici, seulement celles de deny.toml (--ignore)." \
  >"$TRAVAIL/.cargo/audit.toml"

# Un programme universel de macOS (en-tête « fat », gros-boutiste) : chaque moitié écrite à part, une ligne
# « architecture<tab>chemin » par moitié ; rien pour un autre programme. Une classe Java a la même magie, mais ses
# quatre octets suivants disent sa version (45 et plus), pas un nombre de moitiés.
MOITIES='
import struct
import sys
from pathlib import Path

chemin, dossier = Path(sys.argv[1]), Path(sys.argv[2])
try:
    donnees = chemin.read_bytes()
except OSError:
    sys.exit()
magie, nombre = struct.unpack_from(">II", donnees) if len(donnees) >= 8 else (0, 0)
if magie not in (0xCAFEBABE, 0xCAFEBABF) or not 0 < nombre < 20:
    sys.exit()
forme, taille = (">iiIII", 20) if magie == 0xCAFEBABE else (">iiQQII", 32)
noms = {0x01000007: "x86_64", 0x0100000C: "arm64"}
dossier.mkdir()
for i in range(nombre):
    cpu, _, debut, longueur = struct.unpack_from(forme, donnees, 8 + i * taille)[:4]
    nom = noms.get(cpu, f"cpu-{cpu:#x}")
    moitie = dossier / f"{i}-{chemin.name}-{nom}"
    moitie.write_bytes(donnees[debut:debut + longueur])
    print(f"{nom}\t{moitie}")
'
# Chaque programme par son chemin complet (cargo audit tourne dans son dossier à lui), sous son nom pour l'affichage.
# (Pas de tableau vide : le bash 3.2 d'un Mac le refuse sous set -u.)
NOMS=()
CHEMINS=()
n=0
for programme in "$@"; do
  if [[ ! -f $programme ]]; then
    echo "✖ $programme : introuvable. Ces programmes ne partent nulle part."
    exit 1
  fi
  case $programme in
    /*) chemin=$programme ;;
    *) chemin=$PWD/$programme ;;
  esac
  n=$((n + 1))
  moities=$(python3 -I -c "$MOITIES" "$chemin" "$TRAVAIL/$n") ||
    { echo "✖ $programme : programme universel illisible. Ces programmes ne partent nulle part."; exit 1; }
  if [[ -z $moities ]]; then
    NOMS+=("$programme")
    CHEMINS+=("$chemin")
  else
    while IFS=$'\t' read -r architecture moitie; do
      NOMS+=("$programme ($architecture)")
      CHEMINS+=("$moitie")
    done <<<"$moities"
  fi
done

CODE=0
SORTIE=$(cd "$TRAVAIL" && cargo-audit audit "${OPTIONS[@]}" bin "${CHEMINS[@]}" 2>&1) || CODE=$?
# « Found 'cargo auditable' data in <programme> (N dependencies) » : la liste complète a été lue.
liste_lue() { grep -qF "'cargo auditable' data in $1 (" <<<"$SORTIE"; }
SANS_LISTE=0
for ((i = 0; i < ${#CHEMINS[@]}; i++)); do
  liste_lue "${CHEMINS[i]}" || SANS_LISTE=1
done
# Les avis que cargo audit ne compte qu'en avertissement (« Warning: notice ») et que cargo deny refuse : tous, sauf
# une version retirée de crates.io. Il n'a pas d'option pour refuser une « notice » ; l'abandon et le code défaillant
# sont déjà refusés plus haut (--deny), et le sont encore ici.
AVIS=$(awk '$1 == "Warning:" && $2 != "yanked" { n++ } END { print n + 0 }' <<<"$SORTIE")
if ((CODE != 0 || SANS_LISTE || AVIS)); then
  printf '%s\n' "$SORTIE"
  for ((i = 0; i < ${#CHEMINS[@]}; i++)); do
    liste_lue "${CHEMINS[i]}" ||
      echo "✖ ${NOMS[i]} : sans la liste de ses dépendances (à recompiler par cargo auditable build)"
  done
  if ((CODE != 0 || AVIS)); then
    echo "✖ cargo audit : failles connues, avis que cargo deny refuse (abandon, code défaillant, notice) ou"
    echo "  vérification impossible (voir ci-dessus). Une faille se corrige en mettant la dépendance à jour ; une"
    echo "  exception ne s'admet que dans deny.toml, avec sa preuve."
  fi
  echo "Ces programmes ne partent nulle part."
  exit 1
fi
# Les avertissements qui ne bloquent pas (version retirée de crates.io) restent visibles.
grep -q '^warning' <<<"$SORTIE" && printf '%s\n' "$SORTIE"
for ((i = 0; i < ${#CHEMINS[@]}; i++)); do
  nombre=$(grep -F "'cargo auditable' data in ${CHEMINS[i]} (" <<<"$SORTIE" |
    sed -n 's/.*(\([0-9]*\) dependencies).*/\1/p')
  echo "✔ ${NOMS[i]} : $nombre dépendances listées, aucune faille connue"
done
if [[ -n $EXCEPTIONS ]]; then
  echo "  exceptions de deny.toml : $(printf '%s\n' "$EXCEPTIONS" | paste -sd, - | sed 's/,/, /g')"
fi
