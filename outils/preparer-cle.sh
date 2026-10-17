#!/usr/bin/env bash
# Prépare une clé USB SENTINEL : EFFACE la clé, puis la découpe en deux partitions exFAT (table GPT).
#   SENTINEL      programmes, guides, base, code source. Attribut GPT « lecture seule » (bit 60) : Windows la monte
#                 en lecture seule, la clé ne peut pas être modifiée sur l'ordinateur d'un autre. Linux ignore cet
#                 attribut : sur ce PC, elle reste modifiable et deployer.sh la met à jour comme avant.
#   SENTINEL-LOG  64 Mio, modifiable partout : journal-erreurs.txt (voir src/journal.rs), rapatrié par deployer.sh.
# Sans sudo : udisks autorise l'utilisateur connecté à modifier une clé amovible.
#   outils/preparer-cle.sh /dev/sdX
# Le contenu actuel de la clé est d'abord sauvegardé dans ~/.local/share/sentinel/sauvegarde-cle-<date>/,
# puis sa base (donnees/) est remise sur la nouvelle partition.
set -euo pipefail
cd "$(dirname "$0")/.."

DISQUE=${1:?usage : outils/preparer-cle.sh /dev/sdX}
NOM=$(basename "$DISQUE")
OBJET=/org/freedesktop/UDisks2/block_devices/$NOM
DONNEES_GPT=ebd0a0a2-b9e5-4433-87c0-68b6b72699c7
LECTURE_SEULE=$((1 << 60))
JOURNAL_OCTETS=$((64 * 1024 * 1024))
MIO=$((1024 * 1024))

[[ $(lsblk -dno RM,TRAN "$DISQUE" | tr -s ' ') == "1 usb" ]] || {
  echo "$DISQUE n'est pas une clé USB amovible : abandon."
  exit 1
}
lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINTS "$DISQUE"
read -rp "Tout le contenu de $DISQUE va être effacé. Taper EFFACER pour continuer : " reponse
[[ $reponse == EFFACER ]] || exit 1

# Sauvegarde de ce qui est monté (la base donnees/ surtout ; le reste se recopie).
SAUVEGARDE="${XDG_DATA_HOME:-$HOME/.local/share}/sentinel/sauvegarde-cle-$(date +%Y%m%d-%H%M%S)"
while read -r part point; do
  [[ -n $point ]] || continue
  mkdir -p "$SAUVEGARDE/$part"
  cp -r "$point/." "$SAUVEGARDE/$part/"
  udisksctl unmount -b "/dev/$part" >/dev/null
done < <(lsblk -lnpo NAME,MOUNTPOINT "$DISQUE" | tail -n +2 | sed 's|^/dev/||')
[[ -d $SAUVEGARDE ]] && echo "Sauvegarde : $SAUVEGARDE"

udisks() { busctl call --timeout=120 org.freedesktop.UDisks2 "$@"; }
# Table GPT neuve (les anciennes signatures sont effacées).
udisks "$OBJET" org.freedesktop.UDisks2.Block Format 'sa{sv}' gpt 0
TAILLE=$(busctl get-property org.freedesktop.UDisks2 "$OBJET" org.freedesktop.UDisks2.Block Size | awk '{print $2}')
# 1 Mio au début (alignement), 1 Mio à la fin (copie de la table GPT), 64 Mio pour le journal.
TAILLE_SENTINEL=$(((TAILLE - 2 * MIO - JOURNAL_OCTETS) / MIO * MIO))
creer() { # offset taille nom
  udisks "$OBJET" org.freedesktop.UDisks2.PartitionTable CreatePartitionAndFormat 'ttssa{sv}sa{sv}' \
    "$1" "$2" "$DONNEES_GPT" "$3" 0 exfat 1 label s "$3" | awk -F'"' '{print $2}'
}
P1=$(creer "$MIO" "$TAILLE_SENTINEL" SENTINEL)
P2=$(creer $((MIO + TAILLE_SENTINEL)) 0 SENTINEL-LOG)
busctl call org.freedesktop.UDisks2 "$P1" org.freedesktop.UDisks2.Partition SetFlags 'ta{sv}' "$LECTURE_SEULE" 0
udevadm settle

CLE=$(udisksctl mount -b "/dev/$(basename "$P1")" | sed 's/.* at //')
JOURNAL=$(udisksctl mount -b "/dev/$(basename "$P2")" | sed 's/.* at //')
touch "$CLE/sentinel.cle" "$JOURNAL/sentinel-journal.cle"
for ancienne in "$SAUVEGARDE"/*/donnees; do
  [[ -d $ancienne ]] && cp -r "$ancienne" "$CLE/" && echo "Base remise sur la clé : $ancienne"
done
outils/deployer.sh --sans-compiler
lsblk -o NAME,SIZE,FSTYPE,LABEL,PARTLABEL,MOUNTPOINTS "$DISQUE"
echo "Attribut lecture seule (Windows) : $(udisksctl info -b "/dev/$(basename "$P1")" | awk '/Flags:/{print $2}')"
