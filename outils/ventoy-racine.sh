#!/bin/bash
# Partie root de la mise à jour de Ventoy sur la clé VANGUARD, qui n'efface rien : Ventoy2Disk.sh -u ne réécrit que son
# démarrage (les secteurs d'avant la partition 1) et la partition VTOYEFI. Installée une fois en fichier de root
# (outils/cle-secours.sh --installer-racine : /usr/local/libexec/vanguard/ventoy-racine, root:root), puis lancée par
# pkexec par ce chemin, que la fenêtre du mot de passe affiche : le compte ne peut ni la remplacer ni la modifier, comme
# le programme élevé sous Windows (src/machine/windows/eleve.rs). Tout ce qui décide est donc ici : la version épinglée
# et l'empreinte de son archive ; la clé, revérifiée avant chaque écriture (clé USB amovible aux partitions de Ventoy,
# jamais le disque du système, même numéro de série et même taille qu'au moment de la proposition) ; la version déjà
# sur la clé, lue par Ventoy2Disk.sh -l (qui n'écrit rien), qui doit être plus ancienne que l'épingle. Du compte, seule
# l'archive vient : recopiée dans un dossier de root, puis vérifiée par son empreinte.
# outils/cle-secours.sh lit l'épingle et les vérifications de la clé dans ce fichier : une épingle changée demande de
# réinstaller, et rien n'est proposé tant que la partie installée n'est pas celle du dépôt.
#   pkexec /usr/local/libexec/vanguard/ventoy-racine /dev/sdX NUMÉRO_DE_SÉRIE TAILLE_EN_OCTETS ARCHIVE
# Code de sortie : 0 Ventoy écrit, 3 rien à faire (la clé a cette version ou une plus récente), 1 refus ou échec.
set -euo pipefail

VENTOY=1.1.18
VENTOY_SHA256=d86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54
# La partition VTOYEFI de Ventoy fait toujours 32 Mio.
VTOYEFI_OCTETS=$((32 * 1024 * 1024))
RIEN_A_FAIRE=3

erreur() { echo "✖ $*" >&2; exit 1; }

# Nom d'une partition : /dev/sdb → /dev/sdb1, /dev/mmcblk0 → /dev/mmcblk0p1.
partition() { if [[ $1 =~ [0-9]$ ]]; then echo "${1}p$2"; else echo "$1$2"; fi; }

empreinte_ok() { # fichier empreinte_attendue
  [[ -f $1 ]] || return 1
  [[ $(sha256sum "$1" | cut -d' ' -f1) == "$2" ]]
}

# a est-elle une version plus ancienne que b (1.1.10 avant 1.1.18) ?
plus_ancienne() { [[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1) == "$1" ]]; }

# Un périphérique bloc ; à part pour que les essais (outils/essais-cle.sh) simulent un disque.
bloc() { [[ -b $1 ]]; }

# Le disque peut-il recevoir la mise à jour de Ventoy ? Une clé USB amovible, partition 1 VANGUARD (exFAT) et 2
# VTOYEFI de Ventoy (FAT de 32 Mio), rien de chiffré ni de LVM, aucune partition montée ailleurs que sous /run/media
# ni en swap, et pas le disque par où passe le système (/, /boot, /usr, /var, /home). Sinon la raison, et code 1.
# Lancé avant de proposer, puis en root avant d'écrire.
cle_ventoy() { # disque
  local disque=$1 p1 p2 point m source
  if [[ -z $disque ]] || ! bloc "$disque" || [[ $(lsblk -dno TYPE "$disque" 2>/dev/null) != disk ]]; then
    echo "${disque:-la clé} n'est pas un disque"
    return 1
  fi
  if [[ $(lsblk -dno RM,TRAN "$disque" | tr -s ' ') != "1 usb" ]]; then
    echo "$disque n'est pas une clé USB amovible"
    return 1
  fi
  if [[ -z $(lsblk -dno SERIAL "$disque") ]]; then
    echo "$disque n'a pas de numéro de série : rien ne la distinguerait d'une autre clé qui prendrait son nom"
    return 1
  fi
  p1=$(partition "$disque" 1)
  p2=$(partition "$disque" 2)
  if ! bloc "$p1" || [[ $(lsblk -dno LABEL "$p1") != VANGUARD || $(lsblk -dno FSTYPE "$p1") != exfat ]]; then
    echo "la partition 1 de $disque n'est pas VANGUARD (exFAT)"
    return 1
  fi
  if ! bloc "$p2" || [[ $(lsblk -dno LABEL "$p2") != VTOYEFI || $(lsblk -dno PARTLABEL "$p2") != VTOYEFI ||
    $(lsblk -dno FSTYPE "$p2") != vfat || $(lsblk -bdno SIZE "$p2") != "$VTOYEFI_OCTETS" ]]; then
    echo "la partition 2 de $disque n'est pas VTOYEFI, celle de Ventoy"
    return 1
  fi
  if lsblk -lnpo TYPE "$disque" | awk '$1 != "disk" && $1 != "part" {t = 1} END {exit !t}'; then
    echo "$disque porte un volume chiffré, LVM ou RAID : pas une clé de secours"
    return 1
  fi
  while IFS= read -r point; do
    if [[ -n $point && $point != /run/media/* ]]; then
      echo "une partition de $disque est montée sur $point"
      return 1
    fi
  done < <(lsblk -lnpo MOUNTPOINTS "$disque")
  if swapon --show=NAME --noheadings 2>/dev/null |
    awk -v d="$disque" '$1 ~ "^" d "p?[0-9]*$" {t = 1} END {exit !t}'; then
    echo "une partition de $disque sert de swap"
    return 1
  fi
  for m in / /boot /usr /var /home; do
    source=$(findmnt -nvo SOURCE "$m" 2>/dev/null | head -1 || true)
    [[ -n $source ]] || continue
    if lsblk -spnlo NAME,TYPE "$source" 2>/dev/null | awk -v d="$disque" '$1 == d && $2 == "disk" {t = 1} END {exit !t}'
    then
      echo "$disque porte $m : c'est le disque du système"
      return 1
    fi
  done
}

# Toujours la même clé : même numéro de série, même taille. Retirée, elle ne répond plus ; un autre disque qui a pris
# son nom n'a pas son numéro de série. Sans numéro de série, rien ne la distinguerait : refusé.
meme_cle() { # disque serie octets
  [[ -n $2 && $(lsblk -dno SERIAL "$1" 2>/dev/null) == "$2" && $(lsblk -bdno SIZE "$1" 2>/dev/null) == "$3" ]]
}

# Version de Ventoy sur la clé, lue par le Ventoy de l'archive vérifiée : Ventoy2Disk.sh -l lit VTOYEFI sans la monter
# ni rien écrire. Vide si elle ne se lit pas.
version_sur_cle() { # dossier_de_ventoy disque
  { (cd "$1" && sh Ventoy2Disk.sh -l "$2") 2>&1 || true; } |
    awk -F': *' '/^Ventoy Version in Disk:/ && v == "" {v = $2} END {print v}'
}

mettre_a_jour() { # disque serie octets archive
  local disque=$1 serie=$2 octets=$3 archive=$4 raison tmp dossier sur_cle attributs apres code=0
  echo "$(date '+%F %T') Ventoy $VENTOY sur $disque (numéro de série ${serie:-aucun}, $octets octets), archive $archive"
  [[ $octets =~ ^[0-9]+$ ]] || erreur "taille de la clé incomprise : rien n'a été écrit."
  raison=$(cle_ventoy "$disque") || erreur "$raison : rien n'a été écrit."
  meme_cle "$disque" "$serie" "$octets" ||
    erreur "$disque n'est plus la clé proposée (ou n'a pas de numéro de série) : rien n'a été écrit."
  tmp=$(mktemp -d)
  # Le dossier de root ne reste pas derrière, même après une erreur ; son nom est pris tout de suite (tmp est locale).
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  # Le chemin vient du compte : 64 Mio lus au plus (l'archive en fait 16), en une minute au plus ; une copie tronquée
  # ou autre ne passe pas l'empreinte.
  timeout 60 head -c $((64 * 1024 * 1024)) -- "$archive" >"$tmp/ventoy.tar.gz" 2>/dev/null || true
  empreinte_ok "$tmp/ventoy.tar.gz" "$VENTOY_SHA256" ||
    erreur "l'archive n'est pas celle de Ventoy $VENTOY (empreinte épinglée) : rien n'a été écrit."
  tar -xzf "$tmp/ventoy.tar.gz" -C "$tmp" --no-same-owner
  dossier=$tmp/ventoy-$VENTOY
  [[ $(cat "$dossier/ventoy/version" 2>/dev/null) == "$VENTOY" ]] ||
    erreur "l'archive ne contient pas Ventoy $VENTOY : rien n'a été écrit."
  # Seulement vers une version plus récente : une mise à jour lancée à la main sur une clé plus à jour que l'épingle, ou
  # demandée par un script qui ne serait plus celui du dépôt, ne ramène jamais la clé en arrière.
  sur_cle=$(version_sur_cle "$dossier" "$disque")
  [[ $sur_cle =~ ^[0-9]+(\.[0-9]+)*$ ]] ||
    erreur "version de Ventoy sur la clé pas lue (Ventoy2Disk.sh -l) : rien n'a été écrit."
  if ! plus_ancienne "$sur_cle" "$VENTOY"; then
    echo "Ventoy $sur_cle sur la clé, pas plus ancien que $VENTOY : rien n'a été écrit."
    exit "$RIEN_A_FAIRE"
  fi
  # La lecture seule de VANGUARD sous Windows (attribut GPT 60) : Ventoy réécrit la table GPT (vtoycli gpt -f) ; si
  # l'attribut de la partition 1 a changé, il est remis comme avant.
  attributs=$(sfdisk --part-attrs "$disque" 1) || erreur "attributs de la partition 1 pas lus : rien n'a été écrit."
  # Revérifiée juste avant d'écrire : lire l'archive et la version a pris quelques secondes.
  meme_cle "$disque" "$serie" "$octets" || erreur "$disque n'est plus la clé proposée : rien n'a été écrit."
  echo "$(date '+%T') Ventoy2Disk.sh -u $disque : $sur_cle → $VENTOY (attributs de la partition 1 :" \
    "${attributs:-aucun})"
  # De Ventoy2Disk.sh -u à la lecture seule remise, l'écriture va au bout : coupée pendant VTOYEFI, la version ne se
  # lit plus et un nouveau -u est refusé (seul --ecrire, qui efface, referait la clé) ; coupée avant les attributs, la
  # lecture seule resterait perdue (la clé à jour, rien ne la remettrait). pkexec laisse la partie root dans le groupe
  # de processus du terminal, que Ctrl-C, Ctrl-\ et sa fermeture (SIGHUP) atteignent, comme le SIGTERM d'une fin de
  # session : ignorés jusque-là, par les enfants aussi (SIG_IGN passe fork et exec). Ventoy tourne en plus dans sa
  # propre session (setsid, attendu par -w), hors d'atteinte du terminal même si un de ses programmes remettait Ctrl-C
  # par défaut (un programme C le peut toujours, bash aussi par « trap - INT »). Le même Ctrl-C tue le tee du compte :
  # ce que dit Ventoy va dans un fichier (un tube sans lecteur arrêterait celui qui y écrit), et SIGPIPE ignoré, une
  # sortie ratée vers le compte n'arrête pas la suite.
  # Ventoy demande une fois s'il peut mettre à jour : les deux versions ont été dites avant la fenêtre du mot de passe,
  # et revérifiées ici.
  trap '' INT QUIT TERM HUP PIPE
  (cd "$dossier" && printf 'y\n' | setsid -w sh Ventoy2Disk.sh -u "$disque") >"$tmp/sortie-u" 2>&1 || code=$?
  sed 's/\x1b\[[0-9;]*m//g' "$tmp/sortie-u" || true
  udevadm settle || true
  # Ventoy écrit par le nom du disque, et la table GPT se relit et se réécrit par ce même nom : seulement si c'est
  # encore la même clé (retirée pendant la mise à jour, un autre disque a pu prendre son nom).
  meme_cle "$disque" "$serie" "$octets" || erreur "$disque n'est plus la clé (retirée pendant la mise à jour ?) : \
attributs de la partition 1 pas revérifiés. À relancer, la clé branchée."
  apres=$(sfdisk --part-attrs "$disque" 1) || erreur "attributs de la partition 1 pas relus après Ventoy."
  if [[ $apres != "$attributs" ]]; then
    meme_cle "$disque" "$serie" "$octets" || erreur "$disque n'est plus la clé : attributs pas remis."
    echo "Attributs de la partition 1 changés par Ventoy : remis à ${attributs:-aucun}." || true
    sfdisk --no-reread --part-attrs "$disque" 1 "$attributs" || code=1
  fi
  trap - INT QUIT TERM HUP PIPE
  if [[ -f $dossier/log.txt ]]; then sed 's/^/  log.txt de Ventoy : /' "$dossier/log.txt"; fi
  ((code == 0)) || erreur "Ventoy2Disk.sh -u a échoué (code $code)."
  echo "$(date '+%T') Ventoy $VENTOY écrit sur $disque."
}

# Lancée par pkexec : root seulement, sans rien garder du compte d'où elle vient (ni son PATH, ni son dossier). Lue par
# source (cle-secours.sh, essais) : les fonctions et l'épingle seulement.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  [[ $EUID -eq 0 && $# -eq 4 ]] || erreur "se lance en root par pkexec, depuis outils/cle-secours.sh --ventoy-maj."
  export PATH=/usr/bin:/bin:/usr/sbin:/sbin
  umask 077
  cd /
  mettre_a_jour "$@"
fi
