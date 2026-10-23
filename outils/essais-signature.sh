#!/usr/bin/env bash
# Essais de outils/signer-versions.sh, avec des clés d'essai et de faux programmes, dans un dossier jetable : rien de
# la vraie clé de signature n'est lu, rien n'est publié.
#   1. derniere.txt et derniere.txt.sig sont identiques, à l'octet, à ceux du script de master (la version que les
#      copies déjà installées, 0.85.0 et d'avant, savent lire) : mêmes programmes, même clé, Ed25519 déterministe.
#      L'historique des versions est un fichier à part : ce que lisent ces copies ne change pas.
#   2. L'historique signé grandit d'une version à l'autre, la plus récente en tête, et commence au manifeste signé de
#      la version d'avant quand il n'y a pas encore d'historique.
#   3. Un historique d'avant signé par une autre clé est refusé : rien ne s'ajoute à un historique douteux.
#   4. Sans rien d'avant ni --premier (un téléchargement raté chez publier-version.sh), rien n'est signé : l'historique
#      ne repart pas de zéro avant que les pages d'avant soient effacées.
# Lancé par outils/verifier.sh ; code 77 (sauté) sans la branche master ici (clone partiel) ou sans openssl.
#   outils/essais-signature.sh
set -uo pipefail
cd "$(dirname "$0")/.."
DEPOT=$PWD

command -v openssl >/dev/null || { echo "openssl absent"; exit 77; }
git rev-parse --verify -q 'master^{commit}' >/dev/null || { echo "pas de branche master ici : rien à comparer"; exit 77; }
mkdir -p "$HOME/.cache/vanguard-dev"
T=$(mktemp -d "$HOME/.cache/vanguard-dev/essais-signature.XXXX")
trap 'rm -rf "$T"' EXIT
ECHECS=0
ok() { echo "  ✔ $*"; }
ko() { echo "  ✖ $*"; ECHECS=$((ECHECS + 1)); }

# Deux clés d'essai, gravées dans un faux github.rs comme le vrai les grave (32 octets en décimal).
for nom in principale secours autre; do
  openssl genpkey -algorithm ed25519 -out "$T/$nom.pem" 2>/dev/null || { echo "openssl sans Ed25519"; exit 77; }
done
gravee() {
  openssl pkey -in "$T/$1.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | od -An -tu1 | tr -s ' \n' ' ' |
    sed 's/^ //; s/ $//; s/ /, /g'
}
# Un dépôt factice : le script à essayer, le faux github.rs, un Cargo.toml à la version voulue.
banc() { # $1 : dossier, $2 : script, $3 : version de Cargo.toml
  mkdir -p "$1/outils" "$1/src/mise_a_jour"
  cp "$2" "$1/outils/signer-versions.sh"
  printf 'const CLE_PUBLIQUE: [u8; 32] = [\n    %s,\n];\nconst CLE_SECOURS: [u8; 32] = [\n    %s,\n];\n' \
    "$(gravee principale)" "$(gravee secours)" >"$1/src/mise_a_jour/github.rs"
  printf '[package]\nname = "vanguard"\nversion = "%s"\n' "$3" >"$1/Cargo.toml"
}
# Trois faux programmes à la forme attendue (ELF x86-64, PE x86-64, Mach-O universel arm64 + x86_64), avec leur
# version gravée.
programmes() { # $1 : dossier, $2 : version gravée
  mkdir -p "$1"
  local v="VANGUARD-VERSION:$2;"
  { printf '\x7fELF\x02\x01'; head -c 12 /dev/zero; printf '\x3e\x00'; printf 'linux %s' "$v"; } >"$1/vanguard-linux-x86_64"
  { printf 'MZ'; head -c 58 /dev/zero; printf '\x40\x00\x00\x00'; printf 'PE\x00\x00\x64\x86'; printf 'windows %s' "$v"; } \
    >"$1/vanguard-windows-x86_64.exe"
  { printf '\xca\xfe\xba\xbe\x00\x00\x00\x02'; printf '\x01\x00\x00\x0c'; head -c 16 /dev/zero
    printf '\x01\x00\x00\x07'; head -c 16 /dev/zero; printf 'macos %s' "$v"; } >"$1/vanguard-macos"
}
signer() { # $1 : banc, $2 : dossier des programmes, puis les options ; la sortie gardée dans $2.log
  VANGUARD_CLE_VERSIONS=$T/${CLE:-principale}.pem bash "$1/outils/signer-versions.sh" "${@:3}" "$2" </dev/null \
    >"$2.log" 2>&1
}
# Une signature sous ce domaine, par la clé principale d'essai.
signe() { # $1 : fichier, $2 : domaine
  { printf '%s\n' "$2"; cat "$1"; } >"$T/message"
  openssl pkey -in "$T/principale.pem" -pubout -out "$T/publique.pem" 2>/dev/null
  openssl pkeyutl -verify -pubin -inkey "$T/publique.pem" -rawin -in "$T/message" -sigfile "$1.sig" >/dev/null 2>&1
}

git show master:outils/signer-versions.sh >"$T/ancien.sh"
banc "$T/ancien" "$T/ancien.sh" 0.86.0
banc "$T/nouveau" "$DEPOT/outils/signer-versions.sh" 0.86.0
programmes "$T/v86-ancien" 0.86.0+1792600000
cp -r "$T/v86-ancien" "$T/v86"
signer "$T/ancien" "$T/v86-ancien" || { ko "script de master : $(tail -n 1 "$T/v86-ancien.log")"; }
if signer "$T/nouveau" "$T/v86" --premier; then
  if cmp -s "$T/v86/derniere.txt" "$T/v86-ancien/derniere.txt" &&
    cmp -s "$T/v86/derniere.txt.sig" "$T/v86-ancien/derniere.txt.sig"; then
    ok "derniere.txt et sa signature identiques à l'octet à ceux du script de master (ce que lit la 0.85.0)"
  else
    ko "derniere.txt ou sa signature diffèrent de ceux du script de master"
  fi
  signe "$T/v86/historique.txt" 'vanguard-historique 1' && ok "historique signé sous son propre domaine" ||
    ko "signature de l'historique"
  signe "$T/v86/historique.txt" 'vanguard-versions 1' && ko "l'historique se vérifie sous le domaine du manifeste" ||
    ok "une signature de l'historique ne vaut pas pour un manifeste"
  cmp -s "$T/v86/historique.txt" "$T/v86/derniere.txt" && ok "sans historique d'avant, il commence à cette version" ||
    ko "premier historique : $(head -c 200 "$T/v86/historique.txt")"
else
  ko "nouveau script : $(tail -n 3 "$T/v86.log")"
fi

# La version suivante reprend l'historique d'avant ; une troisième, elle aussi.
banc "$T/nouveau87" "$DEPOT/outils/signer-versions.sh" 0.87.0
programmes "$T/v87" 0.87.0+1792700000
mkdir -p "$T/v87/avant" && cp "$T/v86/historique.txt" "$T/v86/historique.txt.sig" "$T/v87/avant/"
if signer "$T/nouveau87" "$T/v87" && [[ $(grep -c '^version ' "$T/v87/historique.txt") == 2 ]] &&
  [[ $(head -n 1 "$T/v87/historique.txt") == "version 0.87.0+1792700000" ]] && signe "$T/v87/historique.txt" 'vanguard-historique 1'; then
  ok "l'historique reprend celui d'avant, la version la plus récente en tête"
else
  ko "historique de la version suivante : $(tail -n 2 "$T/v87.log")"
fi
# Sa forme, que lit src/mise_a_jour/github.rs (lire_historique) : « version … » en tête de chaque bloc, puis trois
# champs par programme, rien d'autre.
awk 'NR == 1 && !/^version / { exit 1 } /^version / { next } NF != 3 { exit 1 }' "$T/v87/historique.txt" &&
  ok "forme de l'historique : celle que lit github.rs" || ko "forme de l'historique"

# Pas encore d'historique publié (la 0.85.0) : il commence au manifeste signé de la version d'avant.
banc "$T/nouveau88" "$DEPOT/outils/signer-versions.sh" 0.88.0
programmes "$T/v88" 0.88.0+1792800000
mkdir -p "$T/v88/avant" && cp "$T/v86/derniere.txt" "$T/v86/derniere.txt.sig" "$T/v88/avant/"
if signer "$T/nouveau88" "$T/v88" && [[ $(grep -c '^version ' "$T/v88/historique.txt") == 2 ]]; then
  ok "sans historique d'avant, il reprend le manifeste signé de la version d'avant"
else
  ko "historique commencé au manifeste d'avant : $(tail -n 2 "$T/v88.log")"
fi

# Un historique d'avant signé par une autre clé : refusé, rien n'est signé.
programmes "$T/v89" 0.88.0+1792900000
mkdir -p "$T/v89/avant" && cp "$T/v87/historique.txt" "$T/v89/avant/"
{ printf '%s\n' 'vanguard-historique 1'; cat "$T/v89/avant/historique.txt"; } >"$T/message"
openssl pkeyutl -sign -inkey "$T/autre.pem" -rawin -in "$T/message" -out "$T/v89/avant/historique.txt.sig" 2>/dev/null
if signer "$T/nouveau88" "$T/v89"; then
  ko "un historique d'avant signé par une autre clé a été repris"
elif grep -q "historique d'avant mal signé" "$T/v89.log"; then
  ok "un historique d'avant signé par une autre clé est refusé"
else
  ko "refus pour une autre raison : $(tail -n 1 "$T/v89.log")"
fi

# Rien d'avant, sans --premier : un téléchargement raté, pas une première fois. Refusé, rien n'est signé.
programmes "$T/v90" 0.88.0+1793000000
if signer "$T/nouveau88" "$T/v90"; then
  ko "sans rien d'avant ni --premier, un historique d'une seule version a été signé"
elif grep -q "ni historique ni manifeste d'avant" "$T/v90.log" && [[ ! -e $T/v90/historique.txt.sig ]]; then
  ok "sans rien d'avant ni --premier : refusé, rien n'est signé"
else
  ko "refus pour une autre raison : $(tail -n 1 "$T/v90.log")"
fi

((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
echo "Signature des versions : tout est juste."
