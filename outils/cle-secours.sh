#!/usr/bin/env bash
# Clé de secours : la clé GARDIEN démarre aussi les ordinateurs, pour réparer ou réinstaller Linux, Windows et macOS.
#   1 GARDIEN     partition de Ventoy, exFAT : Gardien comme avant (témoin gardien.cle), et ses images dans ISO/ :
#                 Windows 11 (installer, réparer), Omarchy (installer), SystemRescue (réparer, sauver des fichiers,
#                 tester la mémoire). Attribut GPT « lecture seule » (bit 60) : Windows la monte en lecture seule.
#   2 VTOYEFI     32 Mio, démarrage de Ventoy (UEFI) ; ne jamais y toucher.
#   3 GARDIENLOG  64 Mio, exFAT, modifiable partout : le journal des erreurs (src/journal.rs).
#   4 MACOS       HFS+ : la récupération de macOS, téléchargée chez Apple (BaseSystem), pour les Mac Intel.
# Ventoy (GPL-3.0) démarre les images posées dans la partition 1 ; il exige d'y rester, suivi de sa partition
# VTOYEFI, et laisse ajouter les nôtres dans la place réservée en fin de clé (-r).
#
# PRÉPARATION : rien n'est écrit sur un disque sans --ecrire, qui EFFACE la clé (après une sauvegarde).
#   outils/cle-secours.sh --plan [/dev/sdX]           la disposition, la place, les commandes ; rien n'est lancé
#   outils/cle-secours.sh --essai [DOSSIER_IMAGES]    la disposition jouée sur une image de disque, sans root
#   outils/cle-secours.sh --telecharger DOSSIER       télécharge les images et les vérifie
#   outils/cle-secours.sh --verifier DOSSIER          vérifie les images : empreintes, signatures
#   outils/cle-secours.sh --ecrire /dev/sdX DOSSIER   sauvegarde, EFFACE et refait la clé (root : une fenêtre pkexec)
# Windows 11 se télécharge à la main chez Microsoft (lien valable 24 h) : --telecharger dit comment.
set -euo pipefail
cd "$(dirname "$0")/.."

VENTOY=1.1.18
VENTOY_SHA256=d86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54
SYSRESCUE=13.02
SYSRESCUE_SHA256=ad4d670b72859d887c7960142a9a9d36a3e50446694a035e254442f65d6e7572
# Clé de l'auteur de SystemRescue : empreinte de la clé principale, que la signature doit désigner.
SYSRESCUE_CLE=0FF11AF081E98345594812037091115F8320B897
OMARCHY=4.0.5
# Empreinte publiée avec la version sur GitHub (basecamp/omarchy), pas sur le site qui sert l'image.
OMARCHY_SHA256=73fd4334f1f67b19cd8a5589f9363173fc3aec07c0a59f198833eaddb66877a1
OPENCORE=1.0.8
MACRECOVERY_SHA256=3023a9b4ca79a5255d93c00f25ab5df37e6f938b729b797d9ecea56184b17aff
# Récupération de macOS : Monterey par défaut, la plus récente des Mac Intel sans puce T2 (2015 à 2017), qui
# démarrent sur une clé sans réglage ; les Mac T2 (2018 à 2020) le refusent tant qu'on ne l'a pas permis dans
# Utilitaire Sécurité au démarrage. Autre version : GARDIEN_MACOS_CARTE (identifiants de macrecovery).
MACOS_CARTE=${GARDIEN_MACOS_CARTE:-Mac-E43C1C25D4880AD6}
MIO=$((1024 * 1024))
JOURNAL_MIO=64
VTOYEFI_MIO=32
# Taille de la récupération de Monterey (volume HFS+ de 2,68 Gio) arrondie ; mesurée sur l'image quand elle est là.
MACOS_MIO_ESTIME=2816
TYPE_DONNEES=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
TYPE_EFI=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
TYPE_HFS=48465300-0000-11AA-AA11-00306543ECAC

erreur() { echo "✖ $*" >&2; exit 1; }

# Nom d'une partition : /dev/sdb → /dev/sdb1, /dev/mmcblk0 → /dev/mmcblk0p1.
partition() { if [[ $1 =~ [0-9]$ ]]; then echo "${1}p$2"; else echo "$1$2"; fi; }

# --- Images -------------------------------------------------------------------------------------------------------

fichier_windows() { find "$1" -maxdepth 1 -iname 'Win11*.iso' -print -quit; }
fichier_macos() { echo "$1/macos/BaseSystem.dmg"; }

empreinte_ok() { # fichier empreinte_attendue
  [[ -f $1 ]] || return 1
  [[ $(sha256sum "$1" | cut -d' ' -f1) == "$2" ]]
}

# Signature de SystemRescue : dans un trousseau jetable, et par la clé attendue (la clé principale du signataire).
signature_systemrescue() { # dossier
  local trousseau
  trousseau=$(mktemp -d)
  gpg --homedir "$trousseau" --quiet --import "$1/systemrescue-cle.pem" 2>/dev/null
  local etat
  etat=$(gpg --homedir "$trousseau" --status-fd 1 --verify "$1/systemrescue-$SYSRESCUE-amd64.iso.asc" \
    "$1/systemrescue-$SYSRESCUE-amd64.iso" 2>/dev/null || true)
  rm -rf "$trousseau"
  # VALIDSIG <empreinte de la sous-clé> … <empreinte de la clé principale>
  grep -q "^\[GNUPG:\] VALIDSIG .* $SYSRESCUE_CLE\$" <<<"$etat"
}

# Volume HFS+ de la récupération de macOS dans l'image d'Apple : (nom dans l'image, taille en octets).
volume_macos() { # BaseSystem.dmg
  # Colonnes de 7z : [date heure] attributs taille taille_compressée nom.
  7z l -tdmg "$1" 2>/dev/null | awk '$NF ~ /\.hfs$/ && $(NF-2) ~ /^[0-9]+$/ {print $NF, $(NF-2); exit}'
}

verifier() { # dossier
  local d=$1 tout=0
  echo "Images de $d :"
  if empreinte_ok "$d/ventoy-$VENTOY-linux.tar.gz" "$VENTOY_SHA256"; then echo "  ✔ Ventoy $VENTOY"
  else echo "  ✖ Ventoy $VENTOY absent ou différent"; tout=1; fi
  if empreinte_ok "$d/systemrescue-$SYSRESCUE-amd64.iso" "$SYSRESCUE_SHA256" && signature_systemrescue "$d"; then
    echo "  ✔ SystemRescue $SYSRESCUE (empreinte et signature de son auteur)"
  else echo "  ✖ SystemRescue $SYSRESCUE absent, différent ou mal signé"; tout=1; fi
  if empreinte_ok "$d/omarchy-$OMARCHY.iso" "$OMARCHY_SHA256"; then echo "  ✔ Omarchy $OMARCHY"
  else echo "  ✖ Omarchy $OMARCHY absent ou différent"; tout=1; fi
  local windows
  windows=$(fichier_windows "$d")
  if [[ -z $windows ]]; then
    echo "  ✖ Windows 11 absent (voir --telecharger)"; tout=1
  elif [[ -z ${GARDIEN_WINDOWS_SHA256:-} ]]; then
    echo "  ✖ Windows 11 pas vérifié : GARDIEN_WINDOWS_SHA256=<empreinte publiée par Microsoft pour cette langue>"
    tout=1
  elif empreinte_ok "$windows" "${GARDIEN_WINDOWS_SHA256,,}"; then echo "  ✔ Windows 11 ($(basename "$windows"))"
  else echo "  ✖ Windows 11 différent de l'empreinte de Microsoft"; tout=1; fi
  # macOS : macrecovery a vérifié l'image au téléchargement (liste des morceaux signée par Apple) ; on revérifie
  # avec sa propre fonction.
  if [[ -f $(fichier_macos "$d") ]] && empreinte_ok "$d/macrecovery.py" "$MACRECOVERY_SHA256" &&
    python3 -I -c 'import importlib.util as u, sys
s = u.spec_from_file_location("macrecovery", sys.argv[1]); m = u.module_from_spec(s); s.loader.exec_module(m)
m.verify_image(sys.argv[2], sys.argv[3])' "$d/macrecovery.py" "$(fichier_macos "$d")" "$d/macos/BaseSystem.chunklist" \
      >/dev/null 2>&1 && [[ -n $(volume_macos "$(fichier_macos "$d")") ]]; then
    echo "  ✔ Récupération de macOS (signée par Apple)"
  else echo "  ✖ Récupération de macOS absente ou pas vérifiée"; tout=1; fi
  return $tout
}

telecharger() { # dossier
  local d=$1
  mkdir -p "$d/macos"
  local recuperer=(curl -fL --retry 3 --progress-bar)
  empreinte_ok "$d/ventoy-$VENTOY-linux.tar.gz" "$VENTOY_SHA256" ||
    "${recuperer[@]}" -o "$d/ventoy-$VENTOY-linux.tar.gz" \
      "https://github.com/ventoy/Ventoy/releases/download/v$VENTOY/ventoy-$VENTOY-linux.tar.gz"
  local sr="https://fastly-cdn.system-rescue.org/releases/$SYSRESCUE/systemrescue-$SYSRESCUE-amd64.iso"
  empreinte_ok "$d/systemrescue-$SYSRESCUE-amd64.iso" "$SYSRESCUE_SHA256" ||
    "${recuperer[@]}" -o "$d/systemrescue-$SYSRESCUE-amd64.iso" "$sr"
  "${recuperer[@]}" -o "$d/systemrescue-$SYSRESCUE-amd64.iso.asc" "$sr.asc"
  "${recuperer[@]}" -o "$d/systemrescue-cle.pem" \
    https://www.system-rescue.org/security/signing-keys/gnupg-pubkey-fdupoux-20210704-v001.pem
  empreinte_ok "$d/omarchy-$OMARCHY.iso" "$OMARCHY_SHA256" ||
    "${recuperer[@]}" -o "$d/omarchy-$OMARCHY.iso" "https://iso.omarchy.org/omarchy-$OMARCHY.iso"
  # macrecovery (OpenCorePkg, licence BSD) demande l'image de récupération aux serveurs d'Apple et la vérifie.
  "${recuperer[@]}" -o "$d/macrecovery.py" \
    "https://raw.githubusercontent.com/acidanthera/OpenCorePkg/$OPENCORE/Utilities/macrecovery/macrecovery.py"
  empreinte_ok "$d/macrecovery.py" "$MACRECOVERY_SHA256" || erreur "macrecovery.py n'est pas celui attendu."
  [[ -f $(fichier_macos "$d") ]] ||
    python3 -I "$d/macrecovery.py" -b "$MACOS_CARTE" -m 00000000000000000 -o "$d/macos" download
  cat <<EOF

Windows 11 se télécharge à la main (Microsoft ne donne qu'un lien valable 24 heures) :
  1. https://www.microsoft.com/fr-fr/software-download/windows11, section « Télécharger l'image disque
     (ISO) de Windows 11 pour les appareils x64 » : « Windows 11 (multi-edition ISO for x64 devices) ».
  2. La langue (celle de l'ordinateur à réinstaller), puis le lien 64 bits : enregistrer le fichier
     Win11_….iso dans $d.
  3. Recopier l'empreinte SHA256 de cette langue, dans le tableau « Vérifier votre téléchargement » de la
     même page, puis : GARDIEN_WINDOWS_SHA256=<empreinte> $0 --verifier $d
EOF
  verifier "$d" || true
}

# --- Disposition ----------------------------------------------------------------------------------------------------

# Place réservée par Ventoy en fin de clé : le journal, macOS, et 2 Mio d'alignement et de table GPT de secours.
reserve_mio() { echo $((JOURNAL_MIO + $1 + 2)); }

# Taille de la partition macOS : le volume d'Apple arrondi au multiple de 64 Mio au-dessus.
macos_mio() { # dossier (facultatif)
  local volume
  volume=$([[ -n ${1:-} && -f $(fichier_macos "$1") ]] && volume_macos "$(fichier_macos "$1")" || true)
  if [[ -n $volume ]]; then
    local blocs=$(((${volume#* } + 64 * MIO - 1) / (64 * MIO)))
    echo $((blocs * 64))
  else
    echo "$MACOS_MIO_ESTIME"
  fi
}

# Partitions 3 et 4, ajoutées dans la place réservée, pour sfdisk --append.
partitions_ajoutees() { # macos_mio
  printf 'size=%dMiB, type=%s, name="GARDIENLOG"\n' "$JOURNAL_MIO" "$TYPE_DONNEES"
  printf 'size=%dMiB, type=%s, name="MACOS"\n' "$1" "$TYPE_HFS"
}

plan() { # disque (facultatif), dossier (facultatif)
  local disque=${1:-/dev/sdX} octets macos
  octets=$([[ -b $disque ]] && lsblk -bdno SIZE "$disque" || echo 31037849600)
  macos=$(macos_mio "${2:-}")
  local reserve gardien
  reserve=$(reserve_mio "$macos")
  gardien=$((octets / MIO - 1 - VTOYEFI_MIO - reserve))
  cat <<EOF
Clé de $(numfmt --to=iec-i --suffix=o --format='%.1f' "$octets") ($disque), table GPT :
  1 GARDIEN     $(printf '%6d' "$gardien") Mio  exFAT, Ventoy + Gardien + ISO/ (lecture seule sous Windows)
  2 VTOYEFI     $(printf '%6d' "$VTOYEFI_MIO") Mio  FAT, démarrage de Ventoy
  3 GARDIENLOG  $(printf '%6d' "$JOURNAL_MIO") Mio  exFAT, journal des erreurs
  4 MACOS       $(printf '%6d' "$macos") Mio  HFS+, récupération de macOS (Mac Intel)

Dans GARDIEN : Gardien ~50 Mio, Windows 11 ~7 500 Mio (7,9 Go), Omarchy $OMARCHY 6 156 Mio (6,45 Go),
SystemRescue $SYSRESCUE 1 318 Mio : ~15 000 Mio, il reste ~$(((gardien - 15000) / 1024)) Gio.

Commandes de --ecrire (rien n'est lancé ici) :
  sauvegarde de la clé montée     → ${XDG_DATA_HOME:-$HOME/.local/share}/gardien/sauvegarde-cle-<date>/
  pkexec (une fenêtre)            → sh Ventoy2Disk.sh -I -g -r $reserve -L GARDIEN $disque
                                    sfdisk --append $disque   (GARDIENLOG $JOURNAL_MIO Mio, MACOS $macos Mio)
                                    mkfs.exfat -L GARDIENLOG $(partition "$disque" 3)
                                    7z e -so -tdmg BaseSystem.dmg <volume>.hfs | dd of=$(partition "$disque" 4)
                                    sfdisk --part-attrs $disque 1 GUID:60
  sans root                       → témoins, ISO/ et ventoy/ventoy.json, base remise, deployer.sh --sans-compiler
EOF
}

# ventoy.json : Ventoy ne cherche que dans ISO/ (pas dans les dossiers de Gardien), menu en français, noms clairs.
ventoy_json() { # nom_windows
  cat <<EOF
{
  "control": [
    { "VTOY_DEFAULT_SEARCH_ROOT": "/ISO" },
    { "VTOY_MENU_LANGUAGE": "fr_FR" }
  ],
  "menu_alias": [
    { "image": "/ISO/$1", "alias": "Windows 11 : installer ou réparer" },
    { "image": "/ISO/omarchy-$OMARCHY.iso", "alias": "Omarchy (Linux) : installer" },
    { "image": "/ISO/systemrescue-$SYSRESCUE-amd64.iso", "alias": "SystemRescue : réparer, sauver des fichiers, tester la mémoire" }
  ]
}
EOF
}

# --- Essai sur une image de disque (aucun disque réel, aucun root) ---------------------------------------------------

essai() { # dossier d'images (facultatif : la récupération de macOS y est écrite pour de vrai)
  local images=${1:-} dossier image octets=31037849600
  dossier=$(mktemp -d "${TMPDIR:-/tmp}/gardien-cle-secours.XXXX")
  image=$dossier/cle.img
  truncate -s "$octets" "$image"
  local macos reserve gardien
  macos=$(macos_mio "$images")
  reserve=$(reserve_mio "$macos")
  gardien=$((octets / MIO - 1 - VTOYEFI_MIO - reserve))
  # Ce que fait Ventoy2Disk.sh -g -r : partition 1 au premier Mio, VTOYEFI juste après, la place réservée au bout.
  sfdisk --quiet --label gpt "$image" <<EOF
start=2048, size=${gardien}MiB, type=$TYPE_DONNEES, name="Ventoy"
size=${VTOYEFI_MIO}MiB, type=$TYPE_EFI, name="VTOYEFI"
EOF
  # Puis ce que fait --ecrire : les partitions 3 et 4 dans la place réservée, la lecture seule de la 1.
  partitions_ajoutees "$macos" | sfdisk --quiet --append "$image"
  sfdisk --quiet --part-attrs "$image" 1 GUID:60
  local debut3 debut4 taille4
  debut3=$(sfdisk --json "$image" | python3 -c 'import json,sys; print(json.load(sys.stdin)["partitiontable"]["partitions"][2]["start"])')
  debut4=$(sfdisk --json "$image" | python3 -c 'import json,sys; print(json.load(sys.stdin)["partitiontable"]["partitions"][3]["start"])')
  taille4=$(sfdisk --json "$image" | python3 -c 'import json,sys; print(json.load(sys.stdin)["partitiontable"]["partitions"][3]["size"])')
  truncate -s "${JOURNAL_MIO}M" "$dossier/journal.img"
  mkfs.exfat -L GARDIENLOG "$dossier/journal.img" >/dev/null
  dd if="$dossier/journal.img" of="$image" bs=1M seek="$((debut3 * 512))" oflag=seek_bytes conv=notrunc,sparse status=none
  if [[ -n $images && -f $(fichier_macos "$images") ]]; then
    local volume
    volume=$(volume_macos "$(fichier_macos "$images")")
    ((${volume#* } <= taille4 * 512)) || erreur "le volume de macOS ne tient pas dans sa partition"
    7z e -so -tdmg "$(fichier_macos "$images")" "${volume% *}" 2>/dev/null |
      dd of="$image" bs=4M seek="$((debut4 * 512))" oflag=seek_bytes conv=notrunc,sparse status=none
  fi
  echo "Image d'essai : $image"
  sfdisk --dump "$image" | sed 's/^/  /'
  echo "Partition 3 : $(blkid -p -O "$((debut3 * 512))" -o export "$image" | grep -E '^(TYPE|LABEL)=' | tr '\n' ' ')"
  if [[ -n $images && -f $(fichier_macos "$images") ]]; then
    echo "Partition 4 : $(blkid -p -O "$((debut4 * 512))" -o export "$image" | grep -E '^(TYPE|LABEL)=' | tr '\n' ' ')"
  fi
  echo "(à effacer après lecture : rm -r $dossier)"
}

# --- Écriture de la clé ----------------------------------------------------------------------------------------------

# Partie root, lancée par pkexec : Ventoy, partitions 3 et 4, formatage, macOS, lecture seule. Le disque est
# revérifié ici (même numéro de série, même taille) : entre la question et la fenêtre de mot de passe, une autre
# clé a pu prendre son nom.
racine() { # disque serie octets dossier macos_mio
  local disque=$1 serie=$2 octets=$3 d=$4 macos=$5
  [[ $(lsblk -dno RM,TRAN "$disque" | tr -s ' ') == "1 usb" ]] || erreur "$disque n'est plus une clé USB."
  [[ $(lsblk -dno SERIAL "$disque") == "$serie" && $(lsblk -bdno SIZE "$disque") == "$octets" ]] ||
    erreur "$disque n'est plus la clé choisie."
  local tmp
  tmp=$(mktemp -d)
  # Ventoy2Disk.sh va tourner en root : l'archive est recopiée ici, hors d'atteinte du compte, et c'est cette copie
  # qui est vérifiée puis ouverte. La vérification faite avant la fenêtre pkexec ne suffit pas : le fichier a pu
  # changer depuis.
  cp "$d/ventoy-$VENTOY-linux.tar.gz" "$tmp/ventoy.tar.gz"
  if ! empreinte_ok "$tmp/ventoy.tar.gz" "$VENTOY_SHA256"; then
    rm -rf "$tmp"
    erreur "l'archive de Ventoy n'est plus celle vérifiée : abandon, rien n'a été effacé."
  fi
  tar -xzf "$tmp/ventoy.tar.gz" -C "$tmp"
  # Ventoy demande deux fois s'il peut tout effacer : la question a déjà été posée, en clair, avant. -L : le nom
  # GARDIEN, que Gardien et deployer.sh cherchent (avec le témoin gardien.cle).
  (cd "$tmp/ventoy-$VENTOY" && printf 'y\ny\n' | sh Ventoy2Disk.sh -I -g -r "$(reserve_mio "$macos")" -L GARDIEN \
    "$disque")
  udevadm settle
  partitions_ajoutees "$macos" | sfdisk --append "$disque"
  udevadm settle
  mkfs.exfat -L GARDIENLOG "$(partition "$disque" 3)"
  local volume
  volume=$(volume_macos "$(fichier_macos "$d")")
  7z e -so -tdmg "$(fichier_macos "$d")" "${volume% *}" | dd of="$(partition "$disque" 4)" bs=4M conv=fsync status=progress
  sfdisk --part-attrs "$disque" 1 GUID:60
  sync
  rm -rf "$tmp"
}

# Le bureau monte souvent les nouvelles partitions tout seul : on prend le point de montage, ou on monte.
monter() { # partition
  local point
  for _ in {1..10}; do
    point=$(findmnt -nro TARGET -S "$1" | head -1 || true)
    [[ -n $point ]] && echo "$point" && return
    udisksctl mount -b "$1" >/dev/null 2>&1 || sleep 1
  done
  return 1
}

ecrire() { # disque dossier
  local disque=$1 d=$2
  [[ -b $disque && $(lsblk -dno RM,TRAN "$disque" | tr -s ' ') == "1 usb" ]] ||
    erreur "$disque n'est pas une clé USB amovible : abandon."
  for outil in sfdisk mkfs.exfat 7z gpg pkexec udisksctl; do
    command -v "$outil" >/dev/null || erreur "il manque $outil."
  done
  verifier "$d" || erreur "toutes les images doivent être vérifiées avant d'effacer la clé."
  plan "$disque" "$d"
  lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINTS "$disque"
  read -rp "Tout le contenu de $disque va être effacé. Taper EFFACER pour continuer : " reponse
  [[ $reponse == EFFACER ]] || exit 1
  # Sauvegarde de ce qui est monté (la base donnees/ surtout), puis démontage. Sans ISO/ : une clé de secours déjà
  # faite y garde ~15 Go d'images, qui se retéléchargent.
  local sauvegarde
  sauvegarde="${XDG_DATA_HOME:-$HOME/.local/share}/gardien/sauvegarde-cle-$(date +%Y%m%d-%H%M%S)"
  while read -r part point; do
    if [[ -n $point ]]; then
      mkdir -p "$sauvegarde/$part"
      find "$point" -mindepth 1 -maxdepth 1 ! -name ISO -exec cp -r {} "$sauvegarde/$part/" \;
    fi
    udisksctl unmount -b "/dev/$part" >/dev/null 2>&1 || true
  done < <(lsblk -lnpo NAME,MOUNTPOINT "$disque" | tail -n +2 | sed 's|^/dev/||')
  [[ -d $sauvegarde ]] && echo "Sauvegarde : $sauvegarde"
  local macos
  macos=$(macos_mio "$d")
  pkexec --keep-cwd "$PWD/outils/cle-secours.sh" --racine "$disque" "$(lsblk -dno SERIAL "$disque")" \
    "$(lsblk -bdno SIZE "$disque")" "$(realpath "$d")" "$macos"
  udevadm settle
  local cle journal
  cle=$(monter "$(partition "$disque" 1)") || erreur "partition GARDIEN impossible à monter."
  journal=$(monter "$(partition "$disque" 3)") || erreur "partition GARDIENLOG impossible à monter."
  touch "$cle/gardien.cle" "$journal/gardien-journal.cle"
  mkdir -p "$cle/ISO" "$cle/ventoy"
  local windows
  windows=$(fichier_windows "$d")
  cp "$windows" "$d/omarchy-$OMARCHY.iso" "$d/systemrescue-$SYSRESCUE-amd64.iso" "$cle/ISO/"
  ventoy_json "$(basename "$windows")" >"$cle/ventoy/ventoy.json"
  local ancienne
  ancienne=$(find "$sauvegarde" -maxdepth 2 -type d -name donnees -print -quit 2>/dev/null || true)
  [[ -n $ancienne ]] && cp -r "$ancienne" "$cle/" && echo "Base remise sur la clé : $ancienne"
  sync
  outils/deployer.sh --sans-compiler
  lsblk -o NAME,SIZE,FSTYPE,LABEL,PARTLABEL,MOUNTPOINTS "$disque"
}

case ${1:-} in
  --plan) plan "${2:-}" "${3:-}" ;;
  --essai) essai "${2:-}" ;;
  --telecharger) telecharger "${2:?dossier des images}" ;;
  --verifier) verifier "${2:?dossier des images}" ;;
  --ecrire) ecrire "${2:?disque, par exemple /dev/sdb}" "${3:?dossier des images vérifiées}" ;;
  --racine) [[ $EUID -eq 0 ]] || erreur "--racine se lance par pkexec, depuis --ecrire."; racine "${@:2}" ;;
  *) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
