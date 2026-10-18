#!/usr/bin/env bash
# Clé de secours : la clé GARDIEN démarre aussi les ordinateurs, pour réparer ou réinstaller Linux, Windows et macOS.
#   1 GARDIEN     partition de Ventoy, exFAT : Gardien comme avant (témoin gardien.cle), et ses images dans ISO/ :
#                 Omarchy (installer), SystemRescue (réparer, sauver des fichiers, tester la mémoire), et Windows 11 en
#                 secours s'il reste la place. Attribut GPT « lecture seule » (bit 60) : Windows la monte en lecture
#                 seule.
#   2 VTOYEFI     32 Mio, démarrage de Ventoy (UEFI) ; ne jamais y toucher.
#   3 GARDIENLOG  64 Mio, exFAT, modifiable partout : le journal des erreurs (src/journal.rs).
#   4 MACOS       HFS+ : la récupération de macOS, téléchargée chez Apple (BaseSystem), pour les Mac Intel.
#   5 WIN11       FAT32 : l'installation de Windows 11, qui démarre d'elle-même (menu de démarrage du PC), Secure Boot
#                 actif, sans ajouter de clé (MOK) au PC comme Ventoy le demande. install.wim y est découpé en morceaux
#                 de moins de 4 Go (limite d'un fichier en FAT32) par wimlib ; l'installation de Windows les relit.
# Ventoy (GPL-3.0) démarre les images posées dans la partition 1 ; il exige d'y rester, suivi de sa partition
# VTOYEFI, et laisse ajouter les nôtres dans la place réservée en fin de clé (-r).
#
# PRÉPARATION : rien n'est écrit sur un disque sans --ecrire, qui EFFACE la clé (après une sauvegarde).
#   outils/cle-secours.sh --plan [/dev/sdX] [DOSSIER] la disposition, la place, les commandes ; rien n'est lancé
#   outils/cle-secours.sh --essai [DOSSIER_IMAGES]    la disposition jouée sur une image de disque, sans root
#   outils/cle-secours.sh --telecharger DOSSIER       télécharge les images et les vérifie
#   outils/cle-secours.sh --verifier DOSSIER          vérifie les images, et la partition WIN11 si elle est montée
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
# Taille des images (versions ci-dessus) ; Windows 11 : l'ISO multi-édition, de 7,2 à 7,9 Go selon la langue.
OMARCHY_MIO=6156
SYSRESCUE_MIO=1318
WINDOWS_ISO_MIO_ESTIME=7534
# Partition WIN11 sans l'image sous la main : de quoi tenir l'ISO la plus grosse.
WINDOWS_MIO_ESTIME=8192
# Morceaux de install.wim : 3800 Mio, sous la limite d'un fichier en FAT32 (4 Gio moins un octet).
MORCEAU_MIO=3800
FAT32_MAX=4294967295
# Place gardée dans GARDIEN pour Gardien lui-même, sa base et ses rapports, avant d'y mettre Windows en secours.
MARGE_GARDIEN_MIO=512
TYPE_DONNEES=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
TYPE_EFI=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
TYPE_HFS=48465300-0000-11AA-AA11-00306543ECAC

erreur() { echo "✖ $*" >&2; exit 1; }

# Nom d'une partition : /dev/sdb → /dev/sdb1, /dev/mmcblk0 → /dev/mmcblk0p1.
partition() { if [[ $1 =~ [0-9]$ ]]; then echo "${1}p$2"; else echo "$1$2"; fi; }

# Taille d'un fichier en Mio (arrondie au-dessus), ou la valeur donnée s'il manque.
taille_mio() { # fichier valeur_par_defaut
  if [[ -f $1 ]]; then echo $((($(stat -c %s "$1") + MIO - 1) / MIO)); else echo "$2"; fi
}

# --- Images -------------------------------------------------------------------------------------------------------

# L'image de Windows : « Win11_25H2_French_x64.iso » autrefois, « Windows11_Client_x64_fr-ca_….iso » maintenant.
fichier_windows() { find "$1" -maxdepth 1 \( -iname 'Win11*.iso' -o -iname 'Windows11*.iso' \) -print -quit; }
fichier_macos() { echo "$1/macos/BaseSystem.dmg"; }

empreinte_ok() { # fichier empreinte_attendue
  [[ -f $1 ]] || return 1
  [[ $(sha256sum "$1" | cut -d' ' -f1) == "$2" ]]
}

# Empreinte attendue de l'image de Windows, celle que Microsoft publie pour cette langue : GARDIEN_WINDOWS_SHA256,
# sinon le fichier <image>.sha256 posé à côté (sa première ligne). Vide si aucune des deux, ou si ce n'en est pas une.
empreinte_windows() { # image
  local e=${GARDIEN_WINDOWS_SHA256:-}
  if [[ -z $e && -f $1.sha256 ]]; then e=$(awk 'NR == 1 {print $1}' "$1.sha256"); fi
  e=${e,,}
  if [[ $e =~ ^[0-9a-f]{64}$ ]]; then echo "$e"; fi
}

# Fichiers d'une image ISO : « taille<TAB>chemin », sans les dossiers ni les images de démarrage que 7z montre dans
# [BOOT]. Une entrée est lue en entier avant d'être écrite : selon le format, 7z donne sa taille avant de dire que
# c'est un dossier (Folder, Attributes ou Mode).
fichiers_iso() { # image
  7z l -slt -ba "$1" 2>/dev/null | awk '
    function sortir() {
      if (chemin != "" && !dossier && taille != "" && chemin !~ /^\[BOOT\]/) print taille "\t" chemin
    }
    /^Path = / { sortir(); chemin = substr($0, 8); dossier = 0; taille = "" }
    /^Folder = \+/ || /^Attributes = D/ || /^Mode = d/ { dossier = 1 }
    /^Size = [0-9]+$/ { taille = substr($0, 8) }
    END { sortir() }'
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

# Partition WIN11 comparée à l'image : chaque fichier (sauf install.wim) présent à la même taille, les morceaux .swm
# à la taille préparée et lisibles par wimlib, le démarrage UEFI là, et rien au-delà de 4 Go (limite de FAT32).
verifier_windows() { # point_de_montage image dossier_des_morceaux (facultatif)
  local win=$1 iso=$2 prep=${3:-} faux=0 taille chemin
  if [[ ! -f $win/efi/boot/bootx64.efi ]]; then
    echo "  ✖ WIN11 : pas de efi/boot/bootx64.efi, le PC ne pourra pas la démarrer"
    faux=1
  fi
  local manquants=0 fichiers=0
  while IFS=$'\t' read -r taille chemin; do
    [[ $chemin =~ (^|/)install\.wim$ ]] && continue
    fichiers=$((fichiers + 1))
    [[ -f $win/$chemin && $(stat -c %s "$win/$chemin") == "$taille" ]] || manquants=$((manquants + 1))
  done < <(fichiers_iso "$iso")
  if ((fichiers == 0)); then
    echo "  ✖ WIN11 : l'image de Windows ne se lit pas"
    faux=1
  elif ((manquants > 0)); then
    echo "  ✖ WIN11 : $manquants fichier(s) sur $fichiers absent(s) ou d'une autre taille que dans l'image"
    faux=1
  else
    echo "  ✔ WIN11 : les $fichiers fichiers de l'image, à la bonne taille"
  fi
  if fichiers_iso "$iso" | grep -q $'\t''sources/install\.wim$'; then
    local morceaux=("$win"/sources/install*.swm)
    if [[ ! -f ${morceaux[0]} ]]; then
      echo "  ✖ WIN11 : install.wim n'y est pas (morceaux sources/install*.swm absents)"
      faux=1
    else
      local differents=0 m
      if [[ -n $prep ]]; then
        for m in "$prep"/install*.swm; do
          [[ -f $win/sources/${m##*/} && $(stat -c %s "$win/sources/${m##*/}") == "$(stat -c %s "$m")" ]] ||
            differents=$((differents + 1))
        done
        [[ $(find "$win/sources" -maxdepth 1 -iname 'install*.swm' | wc -l) == "$(find "$prep" -maxdepth 1 \
          -name 'install*.swm' | wc -l)" ]] || differents=$((differents + 1))
      fi
      if ((differents > 0)); then
        echo "  ✖ WIN11 : les morceaux de install.wim ne sont pas ceux préparés"
        faux=1
      elif ! command -v wimlib-imagex >/dev/null; then
        echo "  · WIN11 : ${#morceaux[@]} morceau(x) de install.wim ; wimlib absent, leur contenu n'est pas relu"
      elif wimlib-imagex info "$win/sources/install.swm" >/dev/null 2>&1; then
        echo "  ✔ WIN11 : install.wim en ${#morceaux[@]} morceau(x), lisible par wimlib"
      else
        echo "  ✖ WIN11 : wimlib ne relit pas sources/install.swm"
        faux=1
      fi
    fi
  fi
  if [[ -n $(find "$win" -type f -size +4194303k -print -quit) ]]; then
    echo "  ✖ WIN11 : un fichier dépasse 4 Go, ce que FAT32 ne garde pas"
    faux=1
  fi
  return $faux
}

verifier() { # dossier [cle : aussi la partition WIN11, si elle est montée]
  local d=$1 avec_cle=${2:-} tout=0
  echo "Images de $d :"
  if empreinte_ok "$d/ventoy-$VENTOY-linux.tar.gz" "$VENTOY_SHA256"; then echo "  ✔ Ventoy $VENTOY"
  else echo "  ✖ Ventoy $VENTOY absent ou différent"; tout=1; fi
  if empreinte_ok "$d/systemrescue-$SYSRESCUE-amd64.iso" "$SYSRESCUE_SHA256" && signature_systemrescue "$d"; then
    echo "  ✔ SystemRescue $SYSRESCUE (empreinte et signature de son auteur)"
  else echo "  ✖ SystemRescue $SYSRESCUE absent, différent ou mal signé"; tout=1; fi
  if empreinte_ok "$d/omarchy-$OMARCHY.iso" "$OMARCHY_SHA256"; then echo "  ✔ Omarchy $OMARCHY"
  else echo "  ✖ Omarchy $OMARCHY absent ou différent"; tout=1; fi
  local windows attendue
  windows=$(fichier_windows "$d")
  attendue=$([[ -n $windows ]] && empreinte_windows "$windows" || true)
  if [[ -z $windows ]]; then
    echo "  ✖ Windows 11 absent (voir --telecharger)"; tout=1
  elif [[ -z $attendue ]]; then
    echo "  ✖ Windows 11 pas vérifié : il faut l'empreinte publiée par Microsoft pour cette langue, dans"
    echo "    GARDIEN_WINDOWS_SHA256=<empreinte> ou dans le fichier $(basename "$windows").sha256 à côté de l'image"
    tout=1
  elif empreinte_ok "$windows" "$attendue"; then echo "  ✔ Windows 11 ($(basename "$windows"))"
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
  # La partition WIN11 d'une clé déjà faite, si elle est montée : comparée à l'image (seulement à la demande, pas
  # avant d'effacer : la clé à refaire peut garder une version plus ancienne de Windows).
  if [[ -n $avec_cle ]]; then
    local win
    win=$(findmnt -no TARGET -S LABEL=WIN11 2>/dev/null | head -1 || true)
    if [[ -z $win ]]; then
      echo "Partition WIN11 : pas montée, non vérifiée."
    elif [[ -z $windows ]]; then
      echo "Partition WIN11 ($win) : pas d'image de Windows à laquelle la comparer, non vérifiée."
    else
      echo "Partition WIN11 ($win) :"
      local prep=""
      [[ -n $attendue && -d $d/windows-${attendue:0:16} ]] && prep=$d/windows-${attendue:0:16}
      verifier_windows "$win" "$windows" "$prep" || tout=1
    fi
  fi
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
  1. https://www.microsoft.com/fr-ca/software-download/windows11, section « Télécharger l'image disque
     (ISO) de Windows 11 pour les appareils x64 » : « Windows 11 (multi-edition ISO for x64 devices) ».
  2. La langue : « Français canadien » par défaut (ou celle des ordinateurs à réinstaller), puis le lien
     64 bits : enregistrer l'image (Windows11_….iso ou Win11_….iso) dans $d.
  3. L'empreinte SHA256 de cette langue, dans le tableau « Vérifier votre téléchargement » de la même page :
     dans un fichier <image>.sha256 à côté de l'image (une ligne), ou GARDIEN_WINDOWS_SHA256=<empreinte>
     devant la commande. Puis : $0 --verifier $d
  4. wimlib, qui découpe install.wim pour la partition FAT32 : sudo pacman -S wimlib (ou le paquet wimlib de
     la distribution).
EOF
  verifier "$d" || true
}

# --- Disposition ----------------------------------------------------------------------------------------------------

# Place réservée par Ventoy en fin de clé : le journal, macOS, Windows, et 2 Mio d'alignement et de table GPT de
# secours.
reserve_mio() { echo $((JOURNAL_MIO + $1 + $2 + 2)); } # macos_mio windows_mio

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

# Taille de la partition WIN11 : le contenu de l'image, plus 5 % et 256 Mio (tables de FAT32, en-têtes des morceaux
# de install.wim, pilotes ajoutés plus tard), arrondie au multiple de 64 Mio au-dessus. Estimée sans l'image, ou si
# elle ne se lit pas (encore en téléchargement).
windows_mio() { # dossier (facultatif)
  local iso octets
  iso=$([[ -n ${1:-} && -d ${1:-} ]] && fichier_windows "$1" || true)
  octets=0
  [[ -n $iso ]] && { octets=$(fichiers_iso "$iso" | awk -F'\t' '{s += $1} END {printf "%d\n", s}') || octets=0; }
  if ((octets < 1024 * MIO)); then
    echo "$WINDOWS_MIO_ESTIME"
  else
    local mio=$((octets / MIO + octets / MIO / 20 + 256))
    echo $(((mio + 63) / 64 * 64))
  fi
}

# Partitions 3, 4 et 5, ajoutées dans la place réservée, pour sfdisk --append.
partitions_ajoutees() { # macos_mio windows_mio
  printf 'size=%dMiB, type=%s, name="GARDIENLOG"\n' "$JOURNAL_MIO" "$TYPE_DONNEES"
  printf 'size=%dMiB, type=%s, name="MACOS"\n' "$1" "$TYPE_HFS"
  printf 'size=%dMiB, type=%s, name="WIN11"\n' "$2" "$TYPE_DONNEES"
}

# La place de GARDIEN : d'abord Gardien et sa base (marge), Omarchy et SystemRescue ; Windows en secours ensuite,
# s'il tient (c'est la première image laissée de côté). Une ligne pour --plan ; code 1 si même Linux ne tient pas.
place_gardien() { # gardien_mio iso_windows_mio
  local libre=$(($1 - MARGE_GARDIEN_MIO - OMARCHY_MIO - SYSRESCUE_MIO))
  if ((libre < 0)); then
    echo "✖ Clé trop petite : il manque $((-libre)) Mio pour Gardien, Omarchy et SystemRescue."
    return 1
  elif ((libre >= $2)); then
    echo "Windows 11 aussi dans ISO/, en secours ($2 Mio) : il restera ~$(((libre - $2) / 1024)) Gio."
  else
    echo "Pas la place pour Windows 11 en secours dans ISO/ (il manque $(($2 - libre)) Mio) : il ne démarrera que"
    echo "par sa partition WIN11. Il restera ~$((libre / 1024)) Gio."
  fi
}

plan() { # disque (facultatif), dossier (facultatif)
  local disque=${1:-/dev/sdX} d=${2:-} octets macos windows iso_windows
  octets=$([[ -b $disque ]] && lsblk -bdno SIZE "$disque" || echo 31037849600)
  macos=$(macos_mio "$d")
  windows=$(windows_mio "$d")
  iso_windows=$(taille_mio "$([[ -n $d && -d $d ]] && fichier_windows "$d" || true)" "$WINDOWS_ISO_MIO_ESTIME")
  local reserve gardien
  reserve=$(reserve_mio "$macos" "$windows")
  gardien=$((octets / MIO - 1 - VTOYEFI_MIO - reserve))
  cat <<EOF
Clé de $(numfmt --to=iec-i --suffix=o --format='%.1f' "$octets") ($disque), table GPT :
  1 GARDIEN     $(printf '%6d' "$gardien") Mio  exFAT, Ventoy + Gardien + ISO/ (lecture seule sous Windows)
  2 VTOYEFI     $(printf '%6d' "$VTOYEFI_MIO") Mio  FAT, démarrage de Ventoy
  3 GARDIENLOG  $(printf '%6d' "$JOURNAL_MIO") Mio  exFAT, journal des erreurs
  4 MACOS       $(printf '%6d' "$macos") Mio  HFS+, récupération de macOS (Mac Intel)
  5 WIN11       $(printf '%6d' "$windows") Mio  FAT32, installation de Windows 11 (démarre seule, Secure Boot actif)

Dans GARDIEN : Gardien et sa base ($MARGE_GARDIEN_MIO Mio gardés), Omarchy $OMARCHY $OMARCHY_MIO Mio, SystemRescue
$SYSRESCUE $SYSRESCUE_MIO Mio.
$(place_gardien "$gardien" "$iso_windows" || true)

Commandes de --ecrire (rien n'est lancé ici) :
  avant d'effacer                 → images vérifiées ; install.wim découpé en morceaux de $MORCEAU_MIO Mio
                                    (wimlib-imagex split), à côté des images, et relu (wimlib-imagex verify)
  sauvegarde de la clé montée     → ${XDG_DATA_HOME:-$HOME/.local/share}/gardien/sauvegarde-cle-<date>/
                                    (sans ISO/, ni les partitions MACOS et WIN11 : elles se refont)
  pkexec (une fenêtre)            → sh Ventoy2Disk.sh -I -g -r $reserve -L GARDIEN $disque
                                    sfdisk --append $disque   (GARDIENLOG, MACOS, WIN11)
                                    mkfs.exfat -L GARDIENLOG $(partition "$disque" 3)
                                    7z e -so -tdmg BaseSystem.dmg <volume>.hfs | dd of=$(partition "$disque" 4)
                                    mkfs.fat -F 32 -n WIN11 $(partition "$disque" 5)
                                    sfdisk --part-attrs $disque 1 GUID:60
  sans root                       → témoins, ISO/ et ventoy/ventoy.json ; WIN11 : 7z x de l'image sans
                                    install.wim, ses morceaux .swm, vérification, démontage ; base remise,
                                    deployer.sh --sans-compiler
EOF
}

# ventoy.json : Ventoy ne cherche que dans ISO/ (pas dans les dossiers de Gardien), menu en français, noms clairs.
ventoy_json() { # nom de l'image de Windows dans ISO/ (vide : pas copiée, faute de place)
  local windows=""
  if [[ -n ${1:-} ]]; then
    windows="    { \"image\": \"/ISO/$1\", \"alias\": \"Windows 11 (secours, si le PC ne propose pas WIN11)\" },"$'\n'
  fi
  cat <<EOF
{
  "control": [
    { "VTOY_DEFAULT_SEARCH_ROOT": "/ISO" },
    { "VTOY_MENU_LANGUAGE": "fr_FR" }
  ],
  "menu_alias": [
${windows}    { "image": "/ISO/omarchy-$OMARCHY.iso", "alias": "Omarchy (Linux) : installer" },
    { "image": "/ISO/systemrescue-$SYSRESCUE-amd64.iso", "alias": "SystemRescue : réparer, sauver des fichiers, tester la mémoire" }
  ]
}
EOF
}

# --- Windows dans sa partition FAT32 ----------------------------------------------------------------------------------

# install.wim découpé en morceaux (.swm) de moins de 4 Go, une fois pour toutes, à côté des images : avant d'effacer
# quoi que ce soit (une erreur arrête tout sans rien perdre), et réutilisé tant que l'image de Windows est la même
# (son empreinte dans le nom du dossier). Écrit le chemin du dossier.
preparer_windows() { # dossier
  local d=$1 iso attendue prep
  iso=$(fichier_windows "$d")
  attendue=$(empreinte_windows "$iso")
  [[ -n $attendue ]] || erreur "l'image de Windows doit être vérifiée avant d'être préparée."
  prep=$d/windows-${attendue:0:16}
  if [[ -f $prep/pret ]]; then echo "$prep"; return; fi
  # FAT32 ne garde pas un fichier de 4 Go ou plus : seul install.wim est découpé, rien d'autre ne doit dépasser.
  local trop
  trop=$(fichiers_iso "$iso" | awk -F'\t' -v max="$FAT32_MAX" '$1 > max && $2 !~ /(^|\/)install\.wim$/ {print $2}')
  [[ -z $trop ]] || erreur "l'image de Windows a un fichier de 4 Go ou plus, autre que install.wim : $trop
  (une image faite par l'outil de création de média a install.esd : prendre l'ISO de la page de Microsoft)."
  rm -rf "$prep"
  mkdir -p "$prep"
  if fichiers_iso "$iso" | grep -q $'\t''sources/install\.wim$'; then
    echo "Windows : install.wim découpé en morceaux de $MORCEAU_MIO Mio (quelques minutes)…" >&2
    7z e -y -o"$prep" "$iso" 'sources/install.wim' >/dev/null
    [[ -f $prep/install.wim ]] || erreur "install.wim ne s'extrait pas de l'image de Windows."
    wimlib-imagex split "$prep/install.wim" "$prep/install.swm" "$MORCEAU_MIO" >&2
    rm -f "$prep/install.wim"
    wimlib-imagex verify "$prep/install.swm" --ref="$prep/install*.swm" >&2 ||
      erreur "les morceaux de install.wim ne se relisent pas."
  fi
  touch "$prep/pret"
  echo "$prep"
}

# Partition WIN11 : l'image de Windows sans install.wim (7z), puis ses morceaux préparés, puis tout est revérifié.
remplir_windows() { # point_de_montage image dossier_des_morceaux
  local win=$1 iso=$2 prep=$3
  echo "Partition WIN11 : copie de Windows 11 (quelques minutes)…"
  7z x -y -o"$win" "$iso" '-x![BOOT]' '-xr!install.wim' >/dev/null
  if compgen -G "$prep/install*.swm" >/dev/null; then
    cp "$prep"/install*.swm "$win/sources/"
  fi
  sync
  verifier_windows "$win" "$iso" "$prep" || erreur "la partition WIN11 ne correspond pas à l'image de Windows."
}

# --- Essai sur une image de disque (aucun disque réel, aucun root) ---------------------------------------------------

# Début et taille (en secteurs) d'une partition de l'image : debut_taille image numéro.
debut_taille() {
  sfdisk --json "$1" | python3 -c 'import json, sys
p = json.load(sys.stdin)["partitiontable"]["partitions"][int(sys.argv[1]) - 1]
print(p["start"], p["size"])' "$2"
}

essai() { # dossier d'images (facultatif : la récupération de macOS y est écrite pour de vrai, l'image de Windows lue)
  local images=${1:-} dossier image octets=31037849600
  # Dans le cache, pas dans /tmp : /tmp est souvent en mémoire, avec un quota trop petit pour une clé de 29 Gio
  # (l'image est creuse, mais la récupération de macOS y est écrite pour de vrai).
  mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}/gardien-dev"
  dossier=$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/gardien-dev/cle-secours-essai.XXXX")
  image=$dossier/cle.img
  truncate -s "$octets" "$image"
  local macos windows reserve gardien
  macos=$(macos_mio "$images")
  windows=$(windows_mio "$images")
  reserve=$(reserve_mio "$macos" "$windows")
  gardien=$((octets / MIO - 1 - VTOYEFI_MIO - reserve))
  # Ce que fait Ventoy2Disk.sh -g -r : partition 1 au premier Mio, VTOYEFI juste après, la place réservée au bout.
  sfdisk --quiet --label gpt "$image" <<EOF
start=2048, size=${gardien}MiB, type=$TYPE_DONNEES, name="Ventoy"
size=${VTOYEFI_MIO}MiB, type=$TYPE_EFI, name="VTOYEFI"
EOF
  # Puis ce que fait --ecrire : les partitions 3, 4 et 5 dans la place réservée, la lecture seule de la 1.
  partitions_ajoutees "$macos" "$windows" | sfdisk --quiet --append "$image"
  sfdisk --quiet --part-attrs "$image" 1 GUID:60
  local debut3 debut4 taille4 debut5 taille5
  read -r debut3 _ < <(debut_taille "$image" 3)
  read -r debut4 taille4 < <(debut_taille "$image" 4)
  read -r debut5 taille5 < <(debut_taille "$image" 5)
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
  # FAT32 formatée dans l'image même, à sa place : mkfs.fat --offset, sans monter ni root (taille en blocs d'1 Kio).
  # Il prévient que l'image continue après la partition (table GPT de secours) : seule une erreur est montrée.
  mkfs.fat -F 32 -n WIN11 --offset="$debut5" "$image" "$((taille5 / 2))" >/dev/null 2>"$dossier/mkfs.txt" ||
    { cat "$dossier/mkfs.txt" >&2; erreur "mkfs.fat n'a pas formaté la partition WIN11 de l'image."; }
  echo "Image d'essai : $image"
  sfdisk --dump "$image" | sed 's/^/  /'
  local n debut
  for n in 3 4 5; do
    read -r debut _ < <(debut_taille "$image" "$n")
    [[ $n == 4 && ! (-n $images && -f $(fichier_macos "$images")) ]] && continue
    echo "Partition $n : $(blkid -p -O "$((debut * 512))" -o export "$image" | grep -E '^(TYPE|LABEL|VERSION)=' |
      tr '\n' ' ')"
  done
  echo
  plan "" "$images" | sed -n '/^Dans GARDIEN/,/^$/p' | sed '/^$/d'
  # La copie dans la FAT32 : avec mtools (mcopy écrit dans l'image sans la monter), sinon elle n'est pas essayée.
  if command -v mcopy >/dev/null; then
    echo "WIN11 : fichier d'essai copié par mcopy dans la FAT32 de l'image, puis relu :"
    echo "gardien" >"$dossier/essai.txt"
    mcopy -i "$image@@$((debut5 * 512))" "$dossier/essai.txt" ::/
    mdir -i "$image@@$((debut5 * 512))" ::/ | sed 's/^/  /'
  else
    echo "WIN11 : mtools absent, la copie dans la FAT32 n'est pas essayée ici (seulement son formatage)."
  fi
  local iso
  iso=$([[ -n $images && -d $images ]] && fichier_windows "$images" || true)
  if [[ -n $iso ]]; then
    local trop
    trop=$(fichiers_iso "$iso" | awk -F'\t' -v max="$FAT32_MAX" '$1 > max && $2 !~ /(^|\/)install\.wim$/ {print $2}')
    echo "Image de Windows ($(basename "$iso")) : partition WIN11 de $windows Mio ;" \
      "$([[ -z $trop ]] && echo "aucun fichier de 4 Go ou plus hors install.wim" || echo "✖ trop gros : $trop")."
    command -v wimlib-imagex >/dev/null ||
      echo "  wimlib absent : le découpage de install.wim n'est pas essayé (sudo pacman -S wimlib)."
  fi
  echo "(à effacer après lecture : rm -r $dossier)"
}

# --- Écriture de la clé ----------------------------------------------------------------------------------------------

# Partie root, lancée par pkexec : Ventoy, partitions 3 à 5, formatage, macOS, lecture seule. Le disque est
# revérifié ici (même numéro de série, même taille) : entre la question et la fenêtre de mot de passe, une autre
# clé a pu prendre son nom.
racine() { # disque serie octets dossier macos_mio windows_mio
  local disque=$1 serie=$2 octets=$3 d=$4 macos=$5 windows=$6
  [[ $macos =~ ^[0-9]+$ && $windows =~ ^[0-9]+$ ]] || erreur "tailles de partitions incomprises."
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
  (cd "$tmp/ventoy-$VENTOY" && printf 'y\ny\n' | sh Ventoy2Disk.sh -I -g -r "$(reserve_mio "$macos" "$windows")" \
    -L GARDIEN "$disque")
  udevadm settle
  # Le bureau monte tout seul les partitions neuves de Ventoy (VTOYEFI, GARDIEN) : sfdisk refuse alors un disque
  # « utilisé ». On démonte, on ajoute les partitions sans relire tout le disque (--no-reread), et le noyau les prend
  # par partx, ce qu'il accepte même si le bureau remonte une partition entre-temps.
  demonter_partitions "$disque"
  partitions_ajoutees "$macos" "$windows" | sfdisk --no-reread --append "$disque"
  partx -u "$disque"
  udevadm settle
  local n
  for n in 3 4 5; do liberer "$(partition "$disque" "$n")"; done
  mkfs.exfat -L GARDIENLOG "$(partition "$disque" 3)"
  local volume
  volume=$(volume_macos "$(fichier_macos "$d")")
  7z e -so -tdmg "$(fichier_macos "$d")" "${volume% *}" | dd of="$(partition "$disque" 4)" bs=4M conv=fsync status=progress
  mkfs.fat -F 32 -n WIN11 "$(partition "$disque" 5)"
  sfdisk --no-reread --part-attrs "$disque" 1 GUID:60
  sync
  rm -rf "$tmp"
}

# Partie root : démonte les partitions d'un disque que le bureau a montées.
demonter_partitions() { # disque
  local part
  while read -r part; do
    if findmnt -rno TARGET -S "$part" >/dev/null; then umount "$part"; fi
  done < <(lsblk -lnpo NAME "$1" | tail -n +2)
}

# Partie root : une partition neuve, démontée si le bureau l'a montée, et vidée des signatures d'un ancien système
# de fichiers resté à cet endroit de la clé (le bureau pourrait sinon la monter pendant qu'on l'écrit).
liberer() { # partition
  if findmnt -rno TARGET -S "$1" >/dev/null; then umount "$1"; fi
  wipefs -aq "$1"
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
  for outil in sfdisk mkfs.exfat mkfs.fat 7z gpg pkexec udisksctl; do
    command -v "$outil" >/dev/null || erreur "il manque $outil."
  done
  command -v wimlib-imagex >/dev/null ||
    erreur "il manque wimlib-imagex, qui découpe install.wim pour la partition FAT32 : sudo pacman -S wimlib."
  verifier "$d" || erreur "toutes les images doivent être vérifiées avant d'effacer la clé."
  # Tout ce qui peut échouer se fait avant d'effacer : la place, puis le découpage de install.wim.
  local octets macos windows reserve gardien
  octets=$(lsblk -bdno SIZE "$disque")
  macos=$(macos_mio "$d")
  windows=$(windows_mio "$d")
  reserve=$(reserve_mio "$macos" "$windows")
  gardien=$((octets / MIO - 1 - VTOYEFI_MIO - reserve))
  place_gardien "$gardien" "$(taille_mio "$(fichier_windows "$d")" "$WINDOWS_ISO_MIO_ESTIME")" >/dev/null ||
    erreur "clé trop petite pour Gardien, Omarchy et SystemRescue (voir --plan) : rien n'a été effacé."
  local prep
  prep=$(preparer_windows "$d")
  plan "$disque" "$d"
  lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINTS "$disque"
  read -rp "Tout le contenu de $disque va être effacé. Taper EFFACER pour continuer : " reponse
  [[ $reponse == EFFACER ]] || exit 1
  # Sauvegarde de ce qui est monté (la base donnees/ surtout), puis démontage. Sans ISO/ (une clé de secours déjà
  # faite y garde ~15 Go d'images, qui se retéléchargent), ni les partitions MACOS et WIN11, qui se refont.
  local sauvegarde part point
  sauvegarde="${XDG_DATA_HOME:-$HOME/.local/share}/gardien/sauvegarde-cle-$(date +%Y%m%d-%H%M%S)"
  while read -r part; do
    point=$(findmnt -no TARGET -S "$part" | head -1 || true)
    case $(lsblk -no PARTLABEL "$part") in
      VTOYEFI | MACOS | WIN11) ;;
      *)
        if [[ -n $point ]]; then
          mkdir -p "$sauvegarde/${part##*/}"
          find "$point" -mindepth 1 -maxdepth 1 ! -name ISO -exec cp -r {} "$sauvegarde/${part##*/}/" \;
        fi
        ;;
    esac
    udisksctl unmount -b "$part" >/dev/null 2>&1 || true
  done < <(lsblk -lnpo NAME "$disque" | tail -n +2)
  [[ -d $sauvegarde ]] && echo "Sauvegarde : $sauvegarde"
  pkexec --keep-cwd "$PWD/outils/cle-secours.sh" --racine "$disque" "$(lsblk -dno SERIAL "$disque")" \
    "$octets" "$(realpath "$d")" "$macos" "$windows"
  udevadm settle
  local cle journal win
  cle=$(monter "$(partition "$disque" 1)") || erreur "partition GARDIEN impossible à monter."
  journal=$(monter "$(partition "$disque" 3)") || erreur "partition GARDIENLOG impossible à monter."
  win=$(monter "$(partition "$disque" 5)") || erreur "partition WIN11 impossible à monter."
  touch "$cle/gardien.cle" "$journal/gardien-journal.cle"
  mkdir -p "$cle/ISO" "$cle/ventoy"
  local windows_iso
  windows_iso=$(fichier_windows "$d")
  remplir_windows "$win" "$windows_iso" "$prep"
  udisksctl unmount -b "$(partition "$disque" 5)" >/dev/null
  cp "$d/omarchy-$OMARCHY.iso" "$d/systemrescue-$SYSRESCUE-amd64.iso" "$cle/ISO/"
  # Windows aussi dans ISO/, en secours pour un PC dont le menu ne propose pas WIN11, s'il reste la place : c'est
  # la première image laissée de côté.
  local nom_windows="" libre
  libre=$(($(df --output=avail -B1M "$cle" | tail -1)))
  if ((libre - MARGE_GARDIEN_MIO >= $(taille_mio "$windows_iso" "$WINDOWS_ISO_MIO_ESTIME"))); then
    cp "$windows_iso" "$cle/ISO/" && nom_windows=$(basename "$windows_iso")
  else
    echo "Pas la place pour Windows 11 en secours dans ISO/ : il démarre par sa partition WIN11 seulement."
  fi
  ventoy_json "$nom_windows" >"$cle/ventoy/ventoy.json"
  # La base donnees/ : celle de cette sauvegarde, sinon celle de la plus récente sauvegarde qui en a une. Une passe
  # interrompue après l'effacement laisse une clé vide, dont la sauvegarde suivante n'a plus de base.
  local ancienne
  ancienne=$(find "$sauvegarde" -maxdepth 2 -type d -name donnees -print -quit 2>/dev/null || true)
  [[ -n $ancienne ]] || ancienne=$(find "${sauvegarde%/*}" -maxdepth 3 -type d \
    \( -path '*/sauvegarde-cle-*/donnees' -o -path '*/sauvegarde-cle-*/*/donnees' \) 2>/dev/null | sort -r | head -1)
  if [[ -n $ancienne ]]; then
    cp -r "$ancienne" "$cle/" && echo "Base remise sur la clé : $ancienne"
  else
    echo "Aucune base donnees/ trouvée dans les sauvegardes : la clé démarre sans base."
  fi
  sync
  outils/deployer.sh --sans-compiler
  lsblk -o NAME,SIZE,FSTYPE,LABEL,PARTLABEL,MOUNTPOINTS "$disque"
}

case ${1:-} in
  --plan) plan "${2:-}" "${3:-}" ;;
  --essai) essai "${2:-}" ;;
  --telecharger) telecharger "${2:?dossier des images}" ;;
  --verifier) verifier "${2:?dossier des images}" cle ;;
  --ecrire) ecrire "${2:?disque, par exemple /dev/sdb}" "${3:?dossier des images vérifiées}" ;;
  --racine) [[ $EUID -eq 0 ]] || erreur "--racine se lance par pkexec, depuis --ecrire."; racine "${@:2}" ;;
  *) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
