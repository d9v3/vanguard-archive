#!/usr/bin/env bash
# Signe la version publiée pour la mise à jour depuis GitHub : derniere.txt (la version gravée, puis l'empreinte
# SHA-256 et la taille du programme de chaque système) et derniere.txt.sig (Ed25519, clé privée de cet ordinateur).
# Vanguard n'installe qu'un programme décrit par un manifeste que la clé principale ou la clé de secours a signé
# (src/mise_a_jour/github.rs : CLE_PUBLIQUE, CLE_SECOURS).
#   outils/signer-versions.sh DOSSIER             DOSSIER : celui de publier-version.sh, avec les trois programmes
#   outils/signer-versions.sh --secours DOSSIER   signé par la clé de secours (la principale perdue ou volée)
#   outils/signer-versions.sh --cle [--secours]   la clé publique, sous la forme que github.rs grave
# La clé privée ne quitte jamais cet ordinateur : ni GitHub, ni la clé USB. Chiffrée (« BEGIN ENCRYPTED PRIVATE KEY »,
# voir la commande de chiffrement donnée à l'auteur), sa phrase est demandée une fois par signature, dans le terminal
# ou par zenity, puis passée à openssl par un descripteur : ni la phrase ni la clé en clair ne touchent le disque.
set -euo pipefail
cd "$(dirname "$0")/.."

SECOURS=
ARGS=()
for a in "$@"; do
  case $a in
    --secours) SECOURS=1 ;;
    *) ARGS+=("$a") ;;
  esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

if [[ -n $SECOURS ]]; then
  CLE=${VANGUARD_CLE_SECOURS:-$HOME/.config/vanguard-dev/versions-secours-ed25519.pem}
  GRAVEE=CLE_SECOURS
else
  CLE=${VANGUARD_CLE_VERSIONS:-$HOME/.config/vanguard-dev/versions-ed25519.pem}
  GRAVEE=CLE_PUBLIQUE
fi
# Le préfixe du message signé, le même que DOMAINE dans github.rs.
DOMAINE='vanguard-versions 1'

erreur() { echo "✖ $*" >&2; exit 1; }
[[ -r $CLE ]] || erreur "clé de signature absente : $CLE"
# La clé de secours vit hors ligne, loin de la principale : en clair, la moindre copie (instantané de /home,
# sauvegarde) les mettrait côte à côte et un seul vol donnerait les deux. Chiffrée seulement.
if [[ -n $SECOURS ]] && ! grep -q 'BEGIN ENCRYPTED PRIVATE KEY' "$CLE"; then
  erreur "clé de secours en clair, refusée : la chiffrer (openssl pkcs8 -topk8 -v2 aes-256-cbc) et la garder hors ligne"
fi

# La phrase d'une clé chiffrée, demandée une seule fois : chaque appel d'openssl la relit par le descripteur 3, un
# tube (jamais un fichier, ni la ligne de commande que ps montrerait).
PHRASE=
if grep -q 'BEGIN ENCRYPTED PRIVATE KEY' "$CLE"; then
  if [[ -t 0 ]]; then
    read -rs -p "Phrase de la clé de signature ($(basename "$CLE")) : " PHRASE
    echo >&2
  elif command -v zenity >/dev/null && [[ -n ${WAYLAND_DISPLAY:-}${DISPLAY:-} ]]; then
    PHRASE=$(zenity --password --title "Vanguard : signer la version" 2>/dev/null) || erreur "signature annulée"
  else
    erreur "clé chiffrée, et ni terminal ni zenity pour demander sa phrase"
  fi
  [[ -n $PHRASE ]] || erreur "phrase vide : rien n'est signé"
fi
# openssl avec la clé privée : « -passin fd:3 » seulement si elle est chiffrée (une clé en clair n'en veut pas).
avec_cle() {
  if [[ -n $PHRASE ]]; then
    "$@" -passin fd:3 3< <(printf '%s' "$PHRASE")
  else
    "$@"
  fi
}

# La clé publique (PEM), tirée une fois de la clé privée : une phrase fausse s'arrête ici, avant toute signature.
PUBLIQUE_PEM=$(avec_cle openssl pkey -in "$CLE" -pubout 2>/dev/null) || erreur "clé illisible (phrase fausse ?) : $CLE"
publique() { openssl pkey -pubin -pubout -outform DER <<<"$PUBLIQUE_PEM" | tail -c 32 | od -An -tu1 | tr -s ' \n' ' ' |
  sed 's/^ //; s/ $//'; }

if [[ ${1:-} == --cle ]]; then
  publique | sed 's/ /, /g'
  exit 0
fi
D=${1:?usage : outils/signer-versions.sh [--secours] DOSSIER | --cle [--secours]}

# La clé privée doit être celle dont github.rs grave la clé publique : sinon, chaque Vanguard refuserait la version.
gravee=$(sed -n "/^const $GRAVEE:/,/^];/p" src/mise_a_jour/github.rs | tail -n +2 | grep -oE '[0-9]+' | tr '\n' ' ' |
  sed 's/ $//')
[[ -n $gravee && $gravee == "$(publique)" ]] || erreur "la clé privée ne correspond pas à $GRAVEE de src/mise_a_jour/github.rs"

# Les octets de FICHIER de DEBUT à DEBUT+N, en hexadécimal collé.
octets() { od -An -tx1 -v -j "$2" -N "$3" "$1" | tr -d ' \n'; }
# Un entier de 4 octets petit-boutiste lu à DEBUT.
entier_le() { local h; h=$(octets "$1" "$2" 4); echo $((16#${h:6:2}${h:4:2}${h:2:2}${h:0:2})); }

# Chaque programme est-il bien celui de son système ? Le Mac vient d'un runner de GitHub, et c'est la clé de l'auteur
# qui le signe : au moins sa forme se vérifie ici (Mach-O universel, Apple Silicon et Intel, rien d'autre), comme
# celle des deux autres (ELF x86-64, PE x86-64), avant que la signature ne s'y engage.
architecture_attendue() {
  local systeme=$1 f=$2 h pe
  case $systeme in
    linux-x86_64)
      # ELF, 64 bits, petit-boutiste ; e_machine (octet 18) = 0x3e, x86-64.
      [[ $(octets "$f" 0 6) == 7f454c460201 && $(octets "$f" 18 2) == 3e00 ]]
      ;;
    windows-x86_64)
      # « MZ », puis l'en-tête PE à l'adresse lue en 0x3c : « PE\0\0 », machine 0x8664.
      [[ $(octets "$f" 0 2) == 4d5a ]] || return 1
      pe=$(entier_le "$f" 60)
      [[ $(octets "$f" "$pe" 6) == 504500006486 ]]
      ;;
    macos)
      # Mach-O universel (0xcafebabe, gros-boutiste) à deux architectures : arm64 (0x0100000c) et x86_64
      # (0x01000007), dans n'importe quel ordre.
      h=$(octets "$f" 0 48)
      [[ ${h:0:16} == cafebabe00000002 ]] || return 1
      local a=${h:16:8} b=${h:56:8}
      [[ "$a $b" == "0100000c 01000007" || "$a $b" == "01000007 0100000c" ]]
      ;;
    *) return 1 ;;
  esac
}

declare -A FICHIERS=([linux-x86_64]=vanguard-linux-x86_64 [windows-x86_64]=vanguard-windows-x86_64.exe [macos]=vanguard-macos)
version=
for systeme in linux-x86_64 windows-x86_64 macos; do
  f=$D/${FICHIERS[$systeme]}
  [[ -f $f ]] || erreur "programme absent : $f"
  architecture_attendue "$systeme" "$f" || erreur "$f n'est pas un programme $systeme (forme ou architecture)"
  v=$(grep -aoE 'VANGUARD-VERSION:[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+;' "$f" | head -1 | sed 's/^VANGUARD-VERSION://; s/;$//')
  [[ -n $v ]] || erreur "pas de version gravée dans $f"
  # Les trois viennent du même commit : même numéro, même date. Sinon, l'un d'eux n'est pas de cette version.
  [[ -z $version || $v == "$version" ]] || erreur "versions différentes : $version et $v ($f)"
  version=$v
done
# La version gravée est celle de Cargo.toml : un programme d'une autre version ne se signe pas sous ce numéro.
cargo=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[[ ${version%%+*} == "$cargo" ]] || erreur "version gravée $version, Cargo.toml dit $cargo"

{
  echo "version $version"
  for systeme in linux-x86_64 windows-x86_64 macos; do
    f=$D/${FICHIERS[$systeme]}
    echo "$systeme $(sha256sum "$f" | cut -d' ' -f1) $(stat -c %s "$f")"
  done
} >"$D/derniere.txt"

message=$(mktemp "$D/.message.XXXX")
publique_pem=$(mktemp "$D/.publique.XXXX")
trap 'rm -f "$message" "$publique_pem"' EXIT
{ printf '%s\n' "$DOMAINE"; cat "$D/derniere.txt"; } >"$message"
printf '%s\n' "$PUBLIQUE_PEM" >"$publique_pem"
avec_cle openssl pkeyutl -sign -inkey "$CLE" -rawin -in "$message" -out "$D/derniere.txt.sig"
PHRASE=
# Revérifiée avec la clé publique seule, comme le fera Vanguard.
openssl pkeyutl -verify -pubin -inkey "$publique_pem" -rawin -in "$message" \
  -sigfile "$D/derniere.txt.sig" >/dev/null || erreur "la signature ne se vérifie pas"
echo "Version $version signée ($GRAVEE) : $D/derniere.txt et derniere.txt.sig"
