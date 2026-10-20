#!/usr/bin/env bash
# Signe la version publiée pour la mise à jour depuis GitHub : derniere.txt (la version gravée, puis l'empreinte
# SHA-256 et la taille du programme de chaque système) et derniere.txt.sig (Ed25519, clé privée de cet ordinateur).
# Vanguard n'installe qu'un programme décrit par un manifeste que cette clé a signé (src/mise_a_jour/github.rs).
#   outils/signer-versions.sh DOSSIER   DOSSIER : celui de publier-version.sh, avec les trois programmes
#   outils/signer-versions.sh --cle     la clé publique, sous la forme que github.rs grave (CLE_PUBLIQUE)
# La clé privée ne quitte jamais cet ordinateur : ni GitHub, ni la clé USB (sauvegardée avec /home par restic).
set -euo pipefail
cd "$(dirname "$0")/.."

CLE=${VANGUARD_CLE_VERSIONS:-$HOME/.config/vanguard-dev/versions-ed25519.pem}
# Le préfixe du message signé, le même que DOMAINE dans github.rs.
DOMAINE='vanguard-versions 1'

erreur() { echo "✖ $*" >&2; exit 1; }
[[ -r $CLE ]] || erreur "clé de signature absente : $CLE"
publique() { openssl pkey -in "$CLE" -pubout -outform DER | tail -c 32 | od -An -tu1 | tr -s ' \n' ' ' | sed 's/^ //; s/ $//'; }

if [[ ${1:-} == --cle ]]; then
  publique | sed 's/ /, /g'
  exit 0
fi
D=${1:?usage : outils/signer-versions.sh DOSSIER | --cle}

# La clé privée doit être celle dont github.rs grave la clé publique : sinon, chaque Vanguard refuserait la version.
gravee=$(sed -n '/^const CLE_PUBLIQUE/,/^];/p' src/mise_a_jour/github.rs | tail -n +2 | grep -oE '[0-9]+' | tr '\n' ' ' |
  sed 's/ $//')
[[ $gravee == "$(publique)" ]] || erreur "la clé privée ne correspond pas à CLE_PUBLIQUE de src/mise_a_jour/github.rs"

declare -A FICHIERS=([linux-x86_64]=vanguard-linux-x86_64 [windows-x86_64]=vanguard-windows-x86_64.exe [macos]=vanguard-macos)
version=
for systeme in linux-x86_64 windows-x86_64 macos; do
  f=$D/${FICHIERS[$systeme]}
  [[ -f $f ]] || erreur "programme absent : $f"
  v=$(grep -aoE 'VANGUARD-VERSION:[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+;' "$f" | head -1 | sed 's/^VANGUARD-VERSION://; s/;$//')
  [[ -n $v ]] || erreur "pas de version gravée dans $f"
  # Les trois viennent du même commit : même numéro, même date. Sinon, l'un d'eux n'est pas de cette version.
  [[ -z $version || $v == "$version" ]] || erreur "versions différentes : $version et $v ($f)"
  version=$v
done

{
  echo "version $version"
  for systeme in linux-x86_64 windows-x86_64 macos; do
    f=$D/${FICHIERS[$systeme]}
    echo "$systeme $(sha256sum "$f" | cut -d' ' -f1) $(stat -c %s "$f")"
  done
} >"$D/derniere.txt"

message=$(mktemp "$D/.message.XXXX")
trap 'rm -f "$message"' EXIT
{ printf '%s\n' "$DOMAINE"; cat "$D/derniere.txt"; } >"$message"
openssl pkeyutl -sign -inkey "$CLE" -rawin -in "$message" -out "$D/derniere.txt.sig"
# Revérifiée avec la clé publique seule, comme le fera Vanguard.
openssl pkeyutl -verify -pubin -inkey <(openssl pkey -in "$CLE" -pubout) -rawin -in "$message" \
  -sigfile "$D/derniere.txt.sig" >/dev/null || erreur "la signature ne se vérifie pas"
echo "Version $version signée : $D/derniere.txt et derniere.txt.sig"
