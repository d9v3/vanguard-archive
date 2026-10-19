#!/usr/bin/env bash
# Images Linux de la clé de secours, tenues à jour toutes seules : Arch Linux (qui installe aussi Omarchy, par sa
# commande officielle après archinstall), Debian et Fedora en installateurs par Internet, et SystemRescue (réparer,
# sauver des fichiers, tester la mémoire).
#   outils/images-cle.sh --chercher     dernières versions téléchargées dans le cache et vérifiées (minuterie
#                                       hebdomadaire gardien-images.timer) ; une image mal signée est effacée
#   outils/images-cle.sh --verifier     revérifie signature et empreinte des images du cache
#   outils/images-cle.sh --cle [POINT]  met à jour sur la clé GARDIEN les images qu'elle a déjà : la nouvelle version
#                                       copiée, puis l'ancienne retirée (au branchement : gardien-images-cle.service)
#   outils/images-cle.sh --toutes POINT pose aussi celles qui manquent (nouvelle clé : cle-secours.sh --ecrire)
#   outils/images-cle.sh --menu POINT   réécrit ventoy/ventoy.json d'après les images de ISO/
#   outils/images-cle.sh --etat         ce qui est dans le cache et sur la clé
# Chaque image est vérifiée par la signature de son projet, avec une clé fixée ici (outils/cles-images/ et les
# empreintes ci-dessous) : jamais une clé lue sur le serveur qui sert l'image, qu'un serveur piégé fournirait avec
# son image. Une nouvelle clé (Fedora en change à chaque version) arrive avec une mise à jour de Gardien ; d'ici là,
# l'image est refusée et la notification le dit. Windows 11 et la récupération de macOS restent à part
# (cle-secours.sh) : Microsoft ne donne qu'un lien de 24 heures, et la récupération de macOS télécharge macOS
# elle-même.
set -euo pipefail
cd "$(dirname "$0")/.."

CACHE=${GARDIEN_IMAGES:-${XDG_CACHE_HOME:-$HOME/.cache}/gardien/images-cle}
CLES=$PWD/outils/cles-images
MIO=$((1024 * 1024))
# Place gardée sur la clé pour Gardien, sa base et ses rapports.
MARGE_MIO=512
# Ordre de copie quand la place manque : la plus utile d'abord.
SORTES=(systemrescue arch debian fedora)

# Clés principales qui signent les images de chaque projet. Arch : celle de son responsable des images (trousseau
# archlinux-keyring, « PGP fingerprint » de archlinux.org/download). Debian : « Debian CD signing key »
# (debian.org/CD/verify). Fedora : une clé par version, 43 à 46 (fedoraproject.org/fedora.gpg et le paquet
# fedora-repos). SystemRescue : celle de son auteur (system-rescue.org/security).
declare -A SIGNATAIRES=(
  [arch]="3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C"
  [debian]="DF9B9C49EAA9298432589D76DA87E80D6294BE9B 10460DAD76165AD81FBC0CE9988021A964E6EA7D"
  [fedora]="C6E7F081CF80E13146676E88829B606631645531 36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6
            4F50A6114CD5C6976A7F1179655A4B02F577861E D924B10D3E810DABDD8B56B596E7E91491211FCE"
  [systemrescue]="0FF11AF081E98345594812037091115F8320B897"
)
# Noms des images de chaque sorte : les anciennes versions se reconnaissent sur la clé et dans le cache.
declare -A MOTIFS=(
  [arch]='archlinux-*-x86_64.iso'
  [debian]='debian-*-amd64-netinst.iso'
  [fedora]='Fedora-Everything-netinst-x86_64-*.iso'
  [systemrescue]='systemrescue-*-amd64.iso'
)
declare -A NOMS=([arch]="Arch Linux" [debian]=Debian [fedora]=Fedora [systemrescue]=SystemRescue)

erreur() { echo "✖ $*" >&2; exit 1; }
lire() { curl -fsSL --retry 3 --connect-timeout 20 --max-time 120 "$1"; }
avertir() { # titre texte
  command -v notify-send >/dev/null && notify-send -a Gardien -i gardien "$1" "$2" || true
}

# --- Dernières versions ----------------------------------------------------------------------------------------------
# Chaque fonction écrit « nom_de_l_image adresse_du_dossier » : le dossier de cette version précise, pour que l'image
# et sa signature viennent de la même version même si une nouvelle sort pendant le téléchargement.

derniere_arch() {
  local nom
  nom=$(lire https://geo.mirror.pkgbuild.com/iso/latest/ |
    grep -oE 'archlinux-[0-9]{4}\.[0-9]{2}\.[0-9]{2}-x86_64\.iso' | sort -u | tail -1)
  [[ -n $nom ]] || return 1
  local date=${nom#archlinux-}
  echo "$nom https://geo.mirror.pkgbuild.com/iso/${date%-x86_64.iso}/"
}

derniere_debian() {
  local nom
  nom=$(lire https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/ |
    grep -oE 'debian-[0-9]+(\.[0-9]+)*-amd64-netinst\.iso' | sort -uV | tail -1)
  [[ -n $nom ]] || return 1
  local version=${nom#debian-}
  echo "$nom https://cdimage.debian.org/debian-cd/${version%-amd64-netinst.iso}/amd64/iso-cd/"
}

# Fedora : la plus récente des versions publiées (pas les bêtas, rangées dans releases/test/).
derniere_fedora() {
  lire https://fedoraproject.org/releases.json | python3 -I -c '
import json, sys
images = [r["link"] for r in json.load(sys.stdin)
          if r.get("arch") == "x86_64" and r.get("variant") == "Everything" and "/releases/test/" not in r["link"]
          and r["link"].rsplit("/", 1)[-1].startswith("Fedora-Everything-netinst-x86_64-")
          and r["link"].endswith(".iso")]
def version(lien):
    v = lien.rsplit("/", 1)[-1].removeprefix("Fedora-Everything-netinst-x86_64-").removesuffix(".iso")
    return [int(x) for x in v.replace("-", ".").split(".") if x.isdigit()]
if images:
    lien = max(images, key=version)
    dossier, nom = lien.rsplit("/", 1)
    print(nom, dossier.replace("://download.fedoraproject.org/", "://dl.fedoraproject.org/") + "/")
' | grep . || return 1
}

derniere_systemrescue() {
  local version
  version=$(lire https://www.system-rescue.org/Download/ | grep -oE 'systemrescue-[0-9]+(\.[0-9]+)*-amd64\.iso' |
    sed 's/^systemrescue-//; s/-amd64\.iso$//' | sort -uV | tail -1)
  [[ -n $version ]] || return 1
  echo "systemrescue-$version-amd64.iso https://fastly-cdn.system-rescue.org/releases/$version/"
}

# Fichiers de signature à télécharger avec l'image (noms dans le dossier de la version).
signatures() { # sorte nom
  case $1 in
    arch) echo "$2.sig" ;;
    systemrescue) echo "$2.asc" ;;
    debian) echo "SHA512SUMS SHA512SUMS.sign" ;;
    fedora)
      local v=${2#Fedora-Everything-netinst-x86_64-}
      echo "Fedora-Everything-${v%.iso}-x86_64-CHECKSUM"
      ;;
  esac
}

# --- Vérification ----------------------------------------------------------------------------------------------------

# La signature est-elle d'une des clés principales attendues pour cette sorte ? Le trousseau est jetable, dans le
# cache (pas dans /tmp, au quota partagé), et ne contient que la clé du projet.
signe_par() { # sorte statut_gpg
  local f
  for f in ${SIGNATAIRES[$1]}; do
    grep -q "^\[GNUPG:\] VALIDSIG .* $f\$" <<<"$2" && return 0
  done
  return 1
}

# Vérifie une image et ses signatures, rangées dans un même dossier. Code 0 si tout est bon ; sinon la raison sur la
# sortie d'erreur.
verifier_image() { # sorte dossier nom
  local sorte=$1 d=$2 nom=$3 trousseau statut attendue
  trousseau=$(mktemp -d "$CACHE/.trousseau.XXXX")
  chmod 700 "$trousseau"
  gpg --homedir "$trousseau" --quiet --import "$CLES/$sorte.asc" 2>/dev/null
  case $sorte in
    arch | systemrescue)
      local sig
      sig=$(signatures "$sorte" "$nom")
      statut=$(gpg --homedir "$trousseau" --status-fd 1 --verify "$d/$sig" "$d/$nom" 2>/dev/null || true)
      ;;
    debian)
      statut=$(gpg --homedir "$trousseau" --status-fd 1 --verify "$d/SHA512SUMS.sign" "$d/SHA512SUMS" 2>/dev/null ||
        true)
      attendue=$(awk -v n="$nom" '$2 == n || $2 == "*" n {print $1}' "$d/SHA512SUMS")
      ;;
    fedora)
      # La liste signée en clair : seules les lignes que gpg a vérifiées (sa sortie) sont lues, pas le fichier.
      local liste
      liste=$(signatures fedora "$nom")
      statut=$(gpg --homedir "$trousseau" --status-fd 1 --output "$trousseau/liste" --decrypt "$d/$liste" \
        2>/dev/null || true)
      attendue=$(sed -n "s/^SHA256 ($nom) = \([0-9a-f]\{64\}\)\$/\1/p" "$trousseau/liste" 2>/dev/null || true)
      ;;
  esac
  rm -rf "$trousseau"
  if ! signe_par "$sorte" "$statut"; then
    if grep -q '^\[GNUPG:\] \(NO_PUBKEY\|ERRSIG\)' <<<"$statut"; then
      echo "signée par une clé que Gardien ne connaît pas encore (une mise à jour de Gardien l'apportera)" >&2
    else
      echo "signature absente ou fausse" >&2
    fi
    return 1
  fi
  case $sorte in
    debian)
      [[ $attendue =~ ^[0-9a-f]{128}$ && $(sha512sum "$d/$nom" | cut -d' ' -f1) == "$attendue" ]] ||
        { echo "empreinte différente de la liste signée" >&2; return 1; }
      ;;
    fedora)
      [[ $attendue =~ ^[0-9a-f]{64}$ && $(sha256sum "$d/$nom" | cut -d' ' -f1) == "$attendue" ]] ||
        { echo "empreinte différente de la liste signée" >&2; return 1; }
      ;;
  esac
}

# L'image vérifiée d'une sorte dans le cache : celle qui a son empreinte (.sha256), écrite seulement après
# vérification.
image_prete() { # sorte
  local f
  for f in "$CACHE"/${MOTIFS[$1]}; do
    [[ -f $f && -f $f.sha256 ]] && { echo "$f"; return 0; }
  done
  return 1
}

# --- Cache : télécharger et vérifier ----------------------------------------------------------------------------------

chercher() {
  mkdir -p "$CACHE"
  local sorte ligne nom url neuves=() echecs=() joignables=0
  for sorte in "${SORTES[@]}"; do
    if ! ligne=$("derniere_$sorte" 2>/dev/null); then
      echo "· ${NOMS[$sorte]} : dernière version introuvable (pas d'Internet, ou site changé)"
      continue
    fi
    joignables=$((joignables + 1))
    read -r nom url <<<"$ligne"
    if [[ -f $CACHE/$nom && -f $CACHE/$nom.sha256 ]]; then
      echo "✔ ${NOMS[$sorte]} : $nom, déjà prête"
      continue
    fi
    echo "↓ ${NOMS[$sorte]} : $nom"
    local neuf=$CACHE/.nouveau-$sorte f raison
    rm -rf "$neuf"
    mkdir -p "$neuf"
    if ! curl -fL --retry 3 --connect-timeout 20 --progress-bar -o "$neuf/$nom" "$url$nom"; then
      rm -rf "$neuf"
      echecs+=("${NOMS[$sorte]} : téléchargement interrompu")
      continue
    fi
    for f in $(signatures "$sorte" "$nom"); do
      lire "$url$f" >"$neuf/$f" || true
    done
    if raison=$(verifier_image "$sorte" "$neuf" "$nom" 2>&1); then
      # Rangée avec ses signatures (pour --verifier), puis son empreinte, le témoin d'une image vérifiée.
      for f in $(signatures "$sorte" "$nom"); do mv -f "$neuf/$f" "$CACHE/$nom.${f##*.}"; done
      mv -f "$neuf/$nom" "$CACHE/$nom"
      sha256sum "$CACHE/$nom" | cut -d' ' -f1 >"$CACHE/$nom.sha256.part"
      mv -f "$CACHE/$nom.sha256.part" "$CACHE/$nom.sha256"
      # Les versions d'avant de cette sorte, avec leurs signatures.
      for f in "$CACHE"/${MOTIFS[$sorte]}; do
        [[ -f $f && $f != "$CACHE/$nom" ]] && rm -f "$f" "$f".*
      done
      echo "✔ ${NOMS[$sorte]} : $nom vérifiée (signature du projet)"
      neuves+=("$nom")
    else
      echecs+=("${NOMS[$sorte]} : $raison, image effacée")
      echo "✖ ${NOMS[$sorte]} : $raison ; image effacée"
    fi
    rm -rf "$neuf"
  done
  if ((${#neuves[@]})); then
    avertir "Clé GARDIEN : nouvelles images prêtes" \
      "$(printf '%s\n' "${neuves[@]}")
Elles iront sur la clé à son prochain branchement."
  fi
  if ((${#echecs[@]})); then
    avertir "Clé GARDIEN : image refusée" "$(printf '%s\n' "${echecs[@]}")"
    return 1
  fi
  ((joignables > 0)) || echo "Rien de vérifié : nouvel essai à la prochaine minuterie."
}

# Revérifie chaque image prête du cache avec les signatures gardées à côté.
verifier_cache() {
  local sorte image tout=0
  for sorte in "${SORTES[@]}"; do
    if ! image=$(image_prete "$sorte"); then
      echo "  ✖ ${NOMS[$sorte]} : pas d'image prête (outils/images-cle.sh --chercher)"
      tout=1
      continue
    fi
    local d nom f raison
    d=$(mktemp -d "$CACHE/.verification.XXXX")
    nom=${image##*/}
    ln -s "$image" "$d/$nom"
    for f in $(signatures "$sorte" "$nom"); do
      [[ -f $image.${f##*.} ]] && ln -s "$image.${f##*.}" "$d/$f"
    done
    if raison=$(verifier_image "$sorte" "$d" "$nom" 2>&1); then
      echo "  ✔ ${NOMS[$sorte]} : $nom (signature du projet)"
    else
      echo "  ✖ ${NOMS[$sorte]} : $nom, $raison"
      tout=1
    fi
    rm -rf "$d"
  done
  return $tout
}

# --- Clé ------------------------------------------------------------------------------------------------------------

# La clé GARDIEN montée (témoin gardien.cle), comme deployer.sh la cherche.
point_cle() {
  find "/run/media/$USER" -maxdepth 2 -name gardien.cle \
    -printf '%h\n' 2>/dev/null | head -1
}

# Empreinte d'un fichier de la clé lu sur la clé même, pas dans la mémoire où la copie vient de passer (O_DIRECT,
# sinon une lecture ordinaire).
empreinte_sur_cle() { # fichier
  { dd if="$1" iflag=direct bs=4M status=none 2>/dev/null || cat "$1"; } | sha256sum | cut -d' ' -f1
}

libre_mio() { df --output=avail -B1M "$1" | tail -1 | tr -d ' '; }
taille_mio() { echo $((($(stat -c %s "$1") + MIO - 1) / MIO)); }

# Copie les images neuves sur la clé : sous un nom temporaire (que Ventoy ne montre pas), relue, puis renommée ;
# l'ancienne version n'est retirée qu'après. Si la place manque, l'ancienne est retirée d'abord (la clé reste
# démarrable avec les autres images). Le même verrou que deployer.sh : les deux partent au branchement.
copier_sur_cle() { # point (facultatif), toutes (facultatif : aussi les sortes absentes de la clé)
  local point=${1:-} toutes=${2:-}
  [[ -n $point ]] || point=$(point_cle)
  [[ -n $point && -d $point ]] || { echo "Clé GARDIEN non branchée : rien à copier."; return 0; }
  exec 9>"${XDG_RUNTIME_DIR:-/tmp}/gardien-deployer.lock"
  flock 9
  local iso=$point/ISO sorte image nom copiees=() manque=() echecs=()
  mkdir -p "$iso"
  # Copies interrompues (clé retirée en route) : jamais montrées par Ventoy, retirées ici.
  find "$iso" -maxdepth 1 -name '.*.part' -delete
  for sorte in "${SORTES[@]}"; do
    image=$(image_prete "$sorte") || continue
    nom=${image##*/}
    if [[ -f $iso/$nom && $(stat -c %s "$iso/$nom") == "$(stat -c %s "$image")" ]]; then
      continue
    fi
    local anciennes=() a anciennes_mio=0 besoin
    while IFS= read -r -d '' a; do
      anciennes+=("$a")
      anciennes_mio=$((anciennes_mio + $(taille_mio "$a")))
    done < <(find "$iso" -maxdepth 1 -iname "${MOTIFS[$sorte]}" ! -name "$nom" -print0)
    # Au branchement, seulement ce que la clé a déjà : on ne remplit pas une clé qu'on n'a pas préparée pour ça.
    if [[ -z $toutes && ! -f $iso/$nom ]] && ((${#anciennes[@]} == 0)); then
      continue
    fi
    besoin=$(($(taille_mio "$image") + MARGE_MIO))
    if (($(libre_mio "$point") < besoin)); then
      if (($(libre_mio "$point") + anciennes_mio < besoin)); then
        manque+=("${NOMS[$sorte]} (il manque $((besoin - $(libre_mio "$point") - anciennes_mio)) Mio)")
        continue
      fi
      rm -f "${anciennes[@]}"
      anciennes=()
    fi
    echo "→ ${NOMS[$sorte]} : $nom sur la clé…"
    avertir "Clé GARDIEN : copie de ${NOMS[$sorte]}" "Ne retire pas la clé avant la fin (une ou deux minutes)."
    local part=$iso/.$nom.part
    if ! cp "$image" "$part" || ! sync "$part" || [[ $(empreinte_sur_cle "$part") != "$(cat "$image.sha256")" ]]; then
      rm -f "$part"
      echecs+=("${NOMS[$sorte]} : copie différente de l'image vérifiée, retirée")
      continue
    fi
    mv -f "$part" "$iso/$nom"
    ((${#anciennes[@]})) && rm -f "${anciennes[@]}"
    copiees+=("$nom")
  done
  menu "$point"
  sync -f "$point/ventoy/ventoy.json"
  if ((${#copiees[@]})); then
    avertir "Clé GARDIEN : images à jour" "$(printf '%s\n' "${copiees[@]}")"
  fi
  if ((${#manque[@]})); then
    avertir "Clé GARDIEN : pas la place" "$(printf '%s\n' "${manque[@]}")"
  fi
  if ((${#echecs[@]})); then
    avertir "Clé GARDIEN : copie ratée" "$(printf '%s\n' "${echecs[@]}")"
    return 1
  fi
}

# ventoy.json : Ventoy ne cherche que dans ISO/ (pas dans les dossiers de Gardien), menu en français, un nom clair pour
# chaque image présente. Écrit à côté puis renommé : une clé retirée en route garde l'ancien menu.
menu() { # point
  local point=$1
  mkdir -p "$point/ventoy"
  find "$point/ISO" -maxdepth 1 -type f -iname '*.iso' -printf '%f\n' 2>/dev/null | sort | python3 -I -c '
import fnmatch, json, sys
noms = [
    (["Win11*.iso", "Windows11*.iso"], "Windows 11 (secours, si le PC ne propose pas WIN11)"),
    (["archlinux-*.iso"], "Arch Linux : installer par Internet (Omarchy aussi, voir LISEZMOI)"),
    (["debian-*-netinst.iso"], "Debian : installer par Internet"),
    (["Fedora-Everything-netinst-*.iso"], "Fedora : installer par Internet"),
    (["systemrescue-*.iso"], "SystemRescue : réparer, sauver des fichiers, tester la mémoire"),
    (["omarchy-*.iso"], "Omarchy (Linux) : installer"),
]
alias = []
for image in sys.stdin.read().split("\n"):
    for motifs, nom in noms:
        if image and any(fnmatch.fnmatch(image.lower(), m.lower()) for m in motifs):
            alias.append({"image": "/ISO/" + image, "alias": nom})
            break
print(json.dumps({"control": [{"VTOY_DEFAULT_SEARCH_ROOT": "/ISO"}, {"VTOY_MENU_LANGUAGE": "fr_FR"}],
                  "menu_alias": alias}, ensure_ascii=False, indent=2))
' >"$point/ventoy/ventoy.json.part"
  mv -f "$point/ventoy/ventoy.json.part" "$point/ventoy/ventoy.json"
}

etat() {
  local sorte image point
  echo "Cache ($CACHE) :"
  for sorte in "${SORTES[@]}"; do
    if image=$(image_prete "$sorte"); then echo "  ✔ ${NOMS[$sorte]} : ${image##*/}"
    else echo "  · ${NOMS[$sorte]} : rien de prêt"; fi
  done
  point=$(point_cle)
  if [[ -z $point ]]; then
    echo "Clé GARDIEN : pas branchée."
    return
  fi
  echo "Clé ($point/ISO, $(libre_mio "$point") Mio libres) :"
  local f
  for f in "$point"/ISO/*.iso; do
    [[ -f $f ]] || continue
    local statut="" s
    for s in "${SORTES[@]}"; do
      # shellcheck disable=SC2053 # motif voulu
      if [[ ${f##*/} == ${MOTIFS[$s]} ]]; then
        image=$(image_prete "$s" || true)
        if [[ -z $image ]]; then statut="(rien dans le cache pour comparer)"
        elif [[ ${image##*/} == "${f##*/}" ]]; then statut="à jour"
        else statut="ancienne : ${image##*/} ira au prochain branchement"; fi
      fi
    done
    echo "  ${f##*/} $statut"
  done
}

case ${1:-} in
  --chercher) chercher ;;
  --verifier) verifier_cache ;;
  --cle) copier_sur_cle "${2:-}" ;;
  --toutes) copier_sur_cle "${2:?point de montage de la clé}" toutes ;;
  --menu) menu "${2:?point de montage de la clé}" ;;
  --etat) etat ;;
  *) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
