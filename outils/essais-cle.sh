#!/usr/bin/env bash
# Essais des outils de la clé VANGUARD (images-cle.sh, cle-secours.sh, ventoy-racine.sh, menage-dev.sh), sans rien
# toucher de l'ordinateur. Tout se passe dans un espace de noms à part (unshare -rmn : sans root ni Internet) où
# /run/media et /run/user sont cachés par des tmpfs : ni la vraie clé, ni la session (D-Bus, notifications) n'y sont
# plus. Une fausse clé (un tmpfs de la taille voulue), un faux cache d'images, de faux notify-send, aria2c, pkexec et
# curl, un PATH sans udisksctl, sudo, systemctl, sfdisk ni mkfs ; les disques (lsblk, sfdisk…) sont simulés par des
# fonctions, dans les scripts lus par source : aucun vrai disque n'est ouvert. Lancé par outils/verifier.sh ; code 77
# (sauté) sans espaces de noms d'utilisateur.
#   outils/essais-cle.sh
set -uo pipefail
cd "$(dirname "$0")/.."
DEPOT=$PWD

if [[ -z ${ESSAIS_CLE_DEDANS:-} ]]; then
  # La raison d'un essai sauté en première ligne : verifier.sh la montre.
  unshare -rmn true 2>/dev/null || { echo "espaces de noms d'utilisateur indisponibles"; exit 77; }
  # Le seul essai avec le vrai compte : la partie root refuse de tourner sans root (elle s'arrête avant tout le reste).
  sortie=$(bash outils/ventoy-racine.sh /dev/sdz SERIE 1 /nulle-part 2>&1)
  if [[ $? == 1 && $sortie == *"se lance en root par pkexec"* ]]; then
    echo "  ✔ partie root : refusée sans root"
  else
    echo "  ✖ partie root : lancée sans root ($sortie)"
    exit 1
  fi
  ESSAIS_CLE_DEDANS=1 ESSAIS_CLE_UID=$(id -u) exec unshare -rmn --propagation private bash "$0" "$@"
fi

# --- Le banc ---------------------------------------------------------------------------------------------------------

[[ $(awk 'NR == 1 {print ($1 == 0 && $2 != 0) ? "oui" : "non"}' /proc/self/uid_map) == oui ]] ||
  { echo "pas dans un espace de noms d'utilisateur à part : abandon"; exit 1; }
for d in /run/media "/run/user/$ESSAIS_CLE_UID"; do
  [[ -d $d ]] || continue
  /usr/bin/mount -t tmpfs -o size=1M tmpfs "$d" || { echo "$d pas caché : abandon"; exit 1; }
  [[ $(findmnt -no FSTYPE -M "$d" | tail -1) == tmpfs && -z $(ls -A "$d") ]] ||
    { echo "$d pas caché : abandon"; exit 1; }
done

mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}/vanguard-dev"
# Sous vanguard-dev/essai-* : un banc resté là (essais tués) part au ménage de la semaine (outils/menage-dev.sh).
BANC=$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/vanguard-dev/essai-cle.XXXX") || exit 1
nettoyer() {
  cd / || return
  findmnt -rno TARGET | grep "^$BANC/" | sort -r | xargs -r -n1 /usr/bin/umount 2>/dev/null
  rm -rf "$BANC"
}
trap nettoyer EXIT
mkdir -p "$BANC"/{bin,faux,maison,xdg-cache,etat,run,donnees,config,tmp,cache,disque,aria2}

# Rien du vrai compte : dossiers, session, Internet (déjà coupé). Le témoin de la clé est cherché sous /run/media/$USER.
export BANC USER=alice HOME=$BANC/maison XDG_CACHE_HOME=$BANC/xdg-cache XDG_STATE_HOME=$BANC/etat \
  XDG_RUNTIME_DIR=$BANC/run XDG_DATA_HOME=$BANC/donnees XDG_CONFIG_HOME=$BANC/config TMPDIR=$BANC/tmp \
  VANGUARD_IMAGES=$BANC/cache VANGUARD_RACINE=$BANC/libexec/vanguard/ventoy-racine
unset DBUS_SESSION_BUS_ADDRESS DISPLAY WAYLAND_DISPLAY VANGUARD_VTOYEFI VANGUARD_WIN11 ESSAIS_CLE_DEDANS

# Les commandes du système, sauf celles qui touchent un disque, un montage, root, systemd, la session ou Internet.
find /usr/bin -maxdepth 1 \( -type f -o -type l \) ! -name udisksctl ! -name pkexec ! -name sudo ! -name sudoedit \
  ! -name su ! -name doas ! -name run0 ! -name systemctl ! -name systemd-run ! -name notify-send ! -name aria2c \
  ! -name curl ! -name wget ! -name gdbus ! -name busctl ! -name dbus-send ! -name sfdisk ! -name sgdisk \
  ! -name parted ! -name fdisk ! -name gdisk ! -name wipefs ! -name partx ! -name losetup ! -name mount \
  ! -name umount ! -name udevadm ! -name 'mkfs*' ! -name mkexfatfs ! -name mke2fs ! -name sync \
  -exec ln -s -t "$BANC/bin" {} +

cat >"$BANC/faux/notify-send" <<'FIN'
#!/usr/bin/env bash
# Faux notify-send : chaque appel noté dans $BANC/notifications.log (arguments séparés par « | »). Comme le vrai
# (libnotify 0.8) : -p écrit le numéro de la notification ; avec -A, il attend la réponse. ESSAI_CLIC : default (un
# clic, « default » écrit), ferme (fermée sans clic), sinon il attend comme une notification laissée là (Ctrl-C : il la
# ferme et sort sans erreur ; tué par timeout, il ne dit rien). ESSAI_SERIE_APRES_CLIC : une autre clé prend le nom du
# disque pendant la proposition.
printf '%s|' "$@" >>"$BANC/notifications.log"
echo >>"$BANC/notifications.log"
attendre="" numero=""
for a in "$@"; do case $a in -A | --action | --action=*) attendre=1 ;; -p | --print-id) numero=1 ;; esac; done
n=$(($(cat "$BANC/notifications.id" 2>/dev/null || echo 0) + 1))
echo "$n" >"$BANC/notifications.id"
[[ -z $numero ]] || echo "$n"
[[ -n $attendre ]] || exit 0
[[ -z ${ESSAI_SERIE_APRES_CLIC:-} ]] || echo "$ESSAI_SERIE_APRES_CLIC" >"$BANC/disque/serie"
case ${ESSAI_CLIC:-attend} in
  default) echo default; exit 0 ;;
  ferme) exit 0 ;;
esac
sleep 60 &
attente=$!
trap 'kill $attente 2>/dev/null; exit 0' INT
trap 'kill $attente 2>/dev/null; exit 143' TERM
wait $attente
FIN

cat >"$BANC/faux/aria2c" <<'FIN'
#!/usr/bin/env bash
# Faux aria2c : chaque appel noté dans $BANC/aria2c.log (l'image, et « reprise » si l'image commencée était là). Son
# comportement pour chaque image dans $BANC/aria2/<image> : partiel (4 Kio de plus et un .aria2), lent (attend ; Ctrl-C
# ou TERM : arrêt propre), sinon aucune source. Code 7 dans tous les cas, comme le vrai sans image finie.
dir="" torrent=""
for a in "$@"; do case $a in --dir=*) dir=${a#--dir=} ;; --*) ;; *) torrent=$a ;; esac; done
nom=$(basename "${torrent%.torrent}")
etat=debut
[[ -s $dir/$nom ]] && etat=reprise
echo "$nom $etat" >>"$BANC/aria2c.log"
case $(cat "$BANC/aria2/$nom" 2>/dev/null) in
  partiel) head -c 4096 /dev/urandom >>"$dir/$nom"; : >"$dir/$nom.aria2" ;;
  lent)
    sleep 60 &
    p=$!
    trap 'kill $p 2>/dev/null; exit 7' INT TERM
    wait $p
    ;;
esac
exit 7
FIN

cat >"$BANC/faux/pkexec" <<'FIN'
#!/usr/bin/env bash
# Faux pkexec : ses arguments notés dans $BANC/pkexec.log. ESSAI_PKEXEC : lance (exécute la commande, seulement
# /usr/bin/install vers le banc : --installer-racine), reussi (0, et le faux VTOYEFI dit la version ESSAI_VERSION), un
# code (126, 127, 3…) ; sinon 0, sans rien lancer.
printf '%s\n' "$*" >>"$BANC/pkexec.log"
case ${ESSAI_PKEXEC:-0} in
  lance)
    [[ $1 == /usr/bin/install && ${!#} == "$BANC"/* ]] || { echo "faux pkexec : refusé ($*)" >&2; exit 1; }
    exec "$@"
    ;;
  reussi)
    [[ $VANGUARD_VTOYEFI == "$BANC"/* ]] || exit 1
    sed -i "s/VENTOY_VERSION=\"[0-9.]*\"/VENTOY_VERSION=\"$ESSAI_VERSION\"/" "$VANGUARD_VTOYEFI/grub/grub.cfg"
    ;;
  *) exit "${ESSAI_PKEXEC:-0}" ;;
esac
FIN

cat >"$BANC/faux/sync" <<'FIN'
#!/usr/bin/env bash
# Faux sync : ESSAI_SYNC=echec fait échouer celui d'une copie en cours (.part), comme une clé qui lâche.
if [[ ${ESSAI_SYNC:-} == echec && ${!#} == *.part ]]; then exit 1; fi
exec /usr/bin/sync "$@"
FIN
printf '#!/bin/sh\necho "curl: (6) pas d'"'"'Internet dans les essais" >&2\nexit 6\n' >"$BANC/faux/curl"
printf '#!/bin/sh\nexit 0\n' >"$BANC/faux/udevadm"
chmod +x "$BANC"/faux/*
export PATH=$BANC/faux:$BANC/bin

# Une fausse clé /dev/sdz, lue par source après le script essayé : USB amovible, VANGUARD (exFAT) et VTOYEFI (32 Mio) de
# Ventoy ; son numéro de série, sa taille, ses attributs GPT et sa version de Ventoy dans $BANC/disque/. Les écritures
# (sfdisk, Ventoy2Disk.sh -u) y sont notées, jamais faites.
cat >"$BANC/simul-disque.sh" <<'FIN'
D=/dev/sdz
bloc() { [[ $1 == "$D" || $1 == "${D}1" || $1 == "${D}2" ]]; }
lsblk() {
  case "$*" in
    "-dno TYPE $D") echo disk ;;
    "-dno RM,TRAN $D") echo "1 usb" ;;
    "-dno SERIAL $D") cat "$BANC/disque/serie" 2>/dev/null ;;
    "-bdno SIZE $D") cat "$BANC/disque/taille" 2>/dev/null ;;
    "-dno LABEL ${D}1") echo VANGUARD ;;
    "-dno FSTYPE ${D}1") echo exfat ;;
    "-dno LABEL ${D}2" | "-dno PARTLABEL ${D}2") echo VTOYEFI ;;
    "-dno FSTYPE ${D}2") echo vfat ;;
    "-bdno SIZE ${D}2") echo 33554432 ;;
    "-lnpo TYPE $D") printf 'disk\npart\npart\n' ;;
    "-lnpo MOUNTPOINTS $D") printf '\n/run/media/alice/VANGUARD\n\n' ;;
    "-lnpo NAME $D") printf '%s\n' "$D" "${D}1" "${D}2" ;;
    *" $D" | *" ${D}"[0-9]) echo "lsblk simulé : $* inconnu" >&2; return 1 ;;
    *) command lsblk "$@" ;;
  esac
}
sfdisk() {
  case "$*" in
    "--part-attrs $D 1") cat "$BANC/disque/attributs" ;;
    "--no-reread --part-attrs $D 1 "*)
      echo "${!#}" >"$BANC/disque/attributs"
      echo "sfdisk $*" >>"$BANC/disque/ecritures"
      ;;
    *) echo "sfdisk simulé : $* refusé" >&2; return 1 ;;
  esac
}
FIN

# Disque, archive de Ventoy (fausse, 9.9.9 : son empreinte remplace l'épingle dans les essais de la partie root), partie
# root installée (une copie de celle du dépôt : dans l'espace de noms, les fichiers du compte sont à root).
cle_simulee() { # version de Ventoy sur la clé
  printf 'SERIE-A\n' >"$BANC/disque/serie"
  printf '31037849600\n' >"$BANC/disque/taille"
  printf 'GUID:60\n' >"$BANC/disque/attributs"
  printf '%s\n' "$1" >"$BANC/disque/ventoy"
  rm -f "$BANC/disque/ecritures" "$BANC/pkexec.log" "$BANC/notifications.log" "$BANC/notifications.id"
  rm -rf "$BANC/etat"
  mkdir -p "$BANC/vtoyefi/grub"
  printf 'set VENTOY_VERSION="%s"\n' "$1" >"$BANC/vtoyefi/grub/grub.cfg"
}
mkdir -p "$BANC/archive/ventoy-9.9.9/ventoy"
echo 9.9.9 >"$BANC/archive/ventoy-9.9.9/ventoy/version"
cat >"$BANC/archive/ventoy-9.9.9/Ventoy2Disk.sh" <<'FIN'
# Faux Ventoy2Disk.sh : -l dit la version de la fausse clé ; -u lit la réponse, note l'écriture et pose la version
# 9.9.9. ESSAI_U=retire : la clé est retirée pendant (plus de numéro de série) ; attributs : Ventoy les change.
case $1 in
  -l) echo "*****"; echo "Ventoy Version in Disk: $(cat "$BANC/disque/ventoy")"; echo "Disk Partition Style  : GPT" ;;
  -u)
    read -r r
    echo "Ventoy2Disk.sh -u $2 ($r)" >>"$BANC/disque/ecritures"
    echo 9.9.9 >"$BANC/disque/ventoy"
    case ${ESSAI_U:-} in retire) : >"$BANC/disque/serie" ;; attributs) : >"$BANC/disque/attributs" ;; esac
    ;;
esac
FIN
tar -czf "$BANC/ventoy-9.9.9.tar.gz" -C "$BANC/archive" ventoy-9.9.9
FAUSSE_SHA256=$(sha256sum "$BANC/ventoy-9.9.9.tar.gz" | cut -d' ' -f1)
install -D -m 0755 outils/ventoy-racine.sh "$VANGUARD_RACINE"
EPINGLE=$(sed -n 's/^VENTOY=//p' outils/ventoy-racine.sh)

# Pseudo-terminal : la commande lancée, Ctrl-C au bout de $1 s ; « fin <secondes> <signal|code> » au plus $2 s après.
# Lancés en arrière-plan (verifier.sh), les essais héritent d'un Ctrl-C ignoré, qu'aucun script ne peut rétablir : il
# est rendu à la commande, comme dans un terminal.
cat >"$BANC/pty.py" <<'FIN'
import os, pty, select, signal, sys, time
apres, plus = float(sys.argv[1]), float(sys.argv[2])
pid, fd = pty.fork()
if pid == 0:
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGQUIT, signal.SIG_DFL)
    os.execvp(sys.argv[3], sys.argv[3:])
sortie, debut, envoye, etat = b"", time.time(), None, None
while etat is None and time.time() - debut < apres + plus:
    if envoye is None and time.time() - debut >= apres:
        os.write(fd, b"\x03")
        envoye = time.time()
    if select.select([fd], [], [], 0.05)[0]:
        try:
            sortie += os.read(fd, 65536)
        except OSError:
            pass
    fini, statut = os.waitpid(pid, os.WNOHANG)
    if fini:
        etat = statut
if etat is None:
    os.killpg(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    print("fin jamais")
else:
    quoi = f"signal{os.WTERMSIG(etat)}" if os.WIFSIGNALED(etat) else f"code{os.WEXITSTATUS(etat)}"
    print(f"fin {time.time() - (envoye or debut):.1f} {quoi}")
sys.stdout.write(sortie.decode("utf-8", "replace"))
FIN

ESSAIS=0
ECHECS=0
voir() { # libellé commande… : la commande doit réussir ; code 1 sinon (pour montrer le détail)
  ESSAIS=$((ESSAIS + 1))
  if "${@:2}"; then
    echo "  ✔ $1"
    return 0
  fi
  ECHECS=$((ECHECS + 1))
  echo "  ✖ $1"
  return 1
}
dit() { grep -qF -- "$2" "$1" 2>/dev/null; } # fichier texte
pas_dit() { ! grep -qF -- "$2" "$1" 2>/dev/null; }
montrer() { sed 's/^/      | /' "$1"; } # le détail d'un essai raté

# --- Partie root (ventoy-racine.sh lue par source, disque simulé, fausse archive) -----------------------------------

partie_root() { # arguments de mettre_a_jour… : son code de sortie, sa sortie dans $BANC/sortie
  (
    source outils/ventoy-racine.sh
    VENTOY=9.9.9 VENTOY_SHA256=${ESSAI_SHA256:-$FAUSSE_SHA256}
    source "$BANC/simul-disque.sh"
    mettre_a_jour "$@"
  ) >"$BANC/sortie" 2>&1
}
ecrit() { dit "$BANC/disque/ecritures" "$1"; }
rien_ecrit() { [[ ! -s $BANC/disque/ecritures ]]; }

echo "Partie root de la mise à jour de Ventoy :"
cle_simulee 1.1.10
partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "clé plus ancienne : Ventoy2Disk.sh -u, réponse « y », code 0" \
  eval '((code == 0)) && ecrit "Ventoy2Disk.sh -u /dev/sdz (y)" && ! ecrit sfdisk' || montrer "$BANC/sortie"

cle_simulee 9.9.9
partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "clé déjà à la version épinglée : rien d'écrit, code 3" eval '((code == 3)) && rien_ecrit' ||
  montrer "$BANC/sortie"
cle_simulee 10.0.1
partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "clé plus récente que l'épingle : jamais ramenée en arrière (code 3)" eval '((code == 3)) && rien_ecrit' ||
  montrer "$BANC/sortie"

cle_simulee 1.1.10
partie_root /dev/sdz SERIE-B 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "autre numéro de série que celui de la proposition : refus, rien d'écrit" \
  eval '((code == 1)) && rien_ecrit && dit "$BANC/sortie" "n'"'"'est plus la clé proposée"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_U=retire partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "clé retirée pendant Ventoy2Disk.sh -u : table GPT pas touchée, et c'est dit" \
  eval '((code == 1)) && ! ecrit sfdisk && pas_dit "$BANC/sortie" "changés par Ventoy" &&
    dit "$BANC/sortie" "retirée pendant la mise à jour"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_U=attributs partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "attributs changés par Ventoy : la lecture seule (GUID:60) remise" \
  eval '((code == 0)) && ecrit "sfdisk --no-reread --part-attrs /dev/sdz 1 GUID:60"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_SHA256=0000000000000000000000000000000000000000000000000000000000000000 partie_root /dev/sdz SERIE-A 31037849600 \
  "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "archive autre que celle épinglée : refus avant Ventoy" eval '((code == 1)) && rien_ecrit' ||
  montrer "$BANC/sortie"

cle_simulee ""
partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "version de la clé illisible : refus" eval '((code == 1)) && rien_ecrit' || montrer "$BANC/sortie"

cle_simulee 1.1.10
: >"$BANC/disque/serie"
partie_root /dev/sdz "" 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "clé sans numéro de série : refus" eval '((code == 1)) && rien_ecrit' || montrer "$BANC/sortie"

# --- Proposition et mise à jour, côté compte (cle-secours.sh lue par source) ----------------------------------------

compte() { # commande… dans cle-secours.sh, la fausse clé /dev/sdz branchée : sortie dans $BANC/sortie
  (
    source outils/cle-secours.sh
    source "$BANC/simul-disque.sh"
    point_cle() { echo "$BANC/point"; }
    disque_de() { echo /dev/sdz; }
    archive_ventoy() { echo "$BANC/ventoy-9.9.9.tar.gz"; }
    "$@"
  ) >"$BANC/sortie" 2>&1
}
export VANGUARD_VTOYEFI=$BANC/vtoyefi
RACINE=$VANGUARD_RACINE

echo "Proposition de Ventoy et --ventoy-maj :"
cle_simulee 1.1.10
ESSAI_CLIC=default ESSAI_PKEXEC=reussi ESSAI_VERSION=$EPINGLE compte verifier_ventoy "$BANC/point"
voir "notification à cliquer : action « default », urgence critique (le serveur d'Omarchy n'a pas de bouton)" \
  dit "$BANC/notifications.log" "|-u|critical|-p|-A|default=Mettre à jour|" || montrer "$BANC/notifications.log"
voir "un clic : la partie root installée lancée par pkexec, sur la clé de la proposition" \
  dit "$BANC/pkexec.log" "$RACINE /dev/sdz SERIE-A 31037849600 $BANC/ventoy-9.9.9.tar.gz" || montrer "$BANC/sortie"
voir "puis la version relue sur la clé, et dite" dit "$BANC/sortie" "✔ Ventoy $EPINGLE sur la clé" ||
  montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_CLIC=default ESSAI_SERIE_APRES_CLIC=SERIE-B compte verifier_ventoy "$BANC/point"
voir "une autre clé a pris son nom pendant la proposition : rien n'est lancé, et c'est dit" \
  eval '[[ ! -s $BANC/pkexec.log ]] && dit "$BANC/notifications.log" "Ventoy pas mis à jour"' || montrer "$BANC/sortie"

cle_simulee 1.1.99
compte ventoy_maj
voir "--ventoy-maj sur une clé plus récente que l'épingle : rien à faire, pas de mot de passe demandé" \
  eval '[[ ! -s $BANC/pkexec.log ]] && dit "$BANC/sortie" "déjà sur la clé"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_CLIC=default VANGUARD_RACINE=$BANC/absente/ventoy-racine compte verifier_ventoy "$BANC/point"
voir "partie root pas installée : rien de proposé, la notification dit comment l'installer" \
  eval '[[ ! -s $BANC/pkexec.log ]] && pas_dit "$BANC/notifications.log" "|-A|" &&
    dit "$BANC/notifications.log" "--installer-racine"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
cp outils/ventoy-racine.sh "$BANC/autre-racine"
echo "# modifiée" >>"$BANC/autre-racine"
VANGUARD_RACINE=$BANC/autre-racine compte ventoy_maj
voir "partie root installée différente de celle du dépôt : refus" \
  eval '[[ ! -s $BANC/pkexec.log ]] && dit "$BANC/sortie" "pas celle du dépôt"' || montrer "$BANC/sortie"
cle_simulee 1.1.10
cp outils/ventoy-racine.sh "$BANC/autre-racine"
chmod 0777 "$BANC/autre-racine"
VANGUARD_RACINE=$BANC/autre-racine compte ventoy_maj
voir "partie root modifiable par d'autres que root : refus" \
  eval '[[ ! -s $BANC/pkexec.log ]] && dit "$BANC/sortie" "d'"'"'autres que root"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_PKEXEC=lance VANGUARD_RACINE=$BANC/libexec2/vanguard/ventoy-racine compte installer_racine
voir "--installer-racine : copie en fichier de root par install, identique, 755" \
  eval 'dit "$BANC/pkexec.log" "/usr/bin/install -D -o root -g root -m 0755 $DEPOT/outils/ventoy-racine.sh" &&
    cmp -s outils/ventoy-racine.sh "$BANC/libexec2/vanguard/ventoy-racine" &&
    [[ $(stat -c %a "$BANC/libexec2/vanguard/ventoy-racine") == 755 ]]' || montrer "$BANC/sortie"

echo "Notification à cliquer (proposer) :"
cle_simulee 1.1.10
debut=$SECONDS
ESSAI_CLIC=attend compte proposer 1 "Titre" "Texte" "Sans réponse à temps" "Mettre à jour"
voir "pas de réponse dans le délai : rien de choisi, la notification remplacée par une ordinaire qui le dit" \
  eval '[[ ! -s $BANC/sortie ]] && ((SECONDS - debut < 10)) &&
    dit "$BANC/notifications.log" "|-r|1|--|Titre|Sans réponse à temps|" &&
    [[ $(grep -c "|-A|" "$BANC/notifications.log") == 1 ]]' || montrer "$BANC/notifications.log"
cle_simulee 1.1.10
ESSAI_CLIC=ferme compte proposer 5 "Titre" "Texte" "Sans réponse" "Mettre à jour"
voir "fermée sans clic : rien de choisi, rien de remplacé" \
  eval '[[ ! -s $BANC/sortie && $(wc -l <"$BANC/notifications.log") == 1 ]]' || montrer "$BANC/notifications.log"

echo "Ctrl-C (lancé à la main, dans un terminal) :"
cle_simulee 1.1.10
python3 -I "$BANC/pty.py" 1.5 10 env ESSAI_CLIC=attend bash -c 'source outils/cle-secours.sh
  source "$BANC/simul-disque.sh"; disque_de() { echo /dev/sdz; }
  archive_ventoy() { echo "$BANC/ventoy-9.9.9.tar.gz"; }
  verifier_ventoy "$BANC/point"; echo APRÈS' "$DEPOT/outils/essais-cle.sh" >"$BANC/sortie" 2>&1
voir "pendant la proposition de Ventoy : arrêt aussitôt, rien d'autre de lancé" \
  eval 'grep -qE "^fin [0-9]\.[0-9] signal2$" "$BANC/sortie" && pas_dit "$BANC/sortie" APRÈS &&
    [[ ! -s $BANC/pkexec.log ]]' || montrer "$BANC/sortie"
mkdir -p "$BANC/pty"
echo lent >"$BANC/aria2/kali-linux-2026.3-live-everything-amd64.iso"
echo torrent >"$BANC/pty/kali-linux-2026.3-live-everything-amd64.iso.torrent"
python3 -I "$BANC/pty.py" 1.5 10 bash -c 'source outils/images-cle.sh; verifier_image() { return 0; }
  telecharger kali https://exemple.invalid/ kali-linux-2026.3-live-everything-amd64.iso "$BANC/pty" || true
  echo APRÈS' "$DEPOT/outils/essais-cle.sh" >"$BANC/sortie" 2>&1
voir "pendant le torrent de Kali : aria2c arrêté, le script aussi (pas de repli lancé)" \
  eval 'grep -qE "^fin [0-9]\.[0-9] signal2$" "$BANC/sortie" && pas_dit "$BANC/sortie" APRÈS' || montrer "$BANC/sortie"

# --- Images (images-cle.sh) ------------------------------------------------------------------------------------------

echo "Images de la clé :"
USER=bob bash outils/images-cle.sh --cle >"$BANC/sortie" 2>&1
code=$?
voir "sans /run/media/\$USER : « rien à copier », sans erreur" \
  eval '((code == 0)) && dit "$BANC/sortie" "non branchée : rien à copier"' || montrer "$BANC/sortie"
USER=bob bash outils/images-cle.sh --etat >"$BANC/sortie" 2>&1
code=$?
voir "--etat sans /run/media/\$USER : « pas branchée », sans erreur" \
  eval '((code == 0)) && dit "$BANC/sortie" "pas branchée"' || montrer "$BANC/sortie"

# Une fausse Kali de 8 Mio : avec les 512 Mio gardés, la nouvelle (520 Mio) ne tient sur la clé de 524 Mio que si
# l'ancienne part d'abord, comme la vraie Kali sur la vraie clé.
mkdir -p "$BANC/cache5" "$BANC/cle5"
/usr/bin/mount -t tmpfs -o size=524M tmpfs "$BANC/cle5"
mkdir -p "$BANC/cle5/ISO"
IMAGE5=$BANC/cache5/kali-linux-2026.3-live-everything-amd64.iso
head -c $((8 * 1024 * 1024)) /dev/urandom >"$IMAGE5"
sha256sum "$IMAGE5" | cut -d' ' -f1 >"$IMAGE5.sha256"
NEUVE=$BANC/cle5/ISO/kali-linux-2026.3-live-everything-amd64.iso
PART=$BANC/cle5/ISO/.kali-linux-2026.3-live-everything-amd64.iso.part
copier() { VANGUARD_IMAGES=$BANC/cache5 bash outils/images-cle.sh --cle "$BANC/cle5" >"$BANC/sortie" 2>&1; }
head -c 100000 /dev/urandom >"$PART"
copier
code=$?
voir "copie de Kali interrompue (clé retirée), plus aucune Kali sur la clé : refaite au passage suivant" \
  eval '((code == 0)) && cmp -s "$NEUVE" "$IMAGE5" && [[ ! -e $PART ]]' || montrer "$BANC/sortie"
rm -f "$NEUVE"
head -c $((8 * 1024 * 1024)) /dev/urandom >"$BANC/cle5/ISO/kali-linux-2026.2-live-everything-amd64.iso"
rm -f "$BANC/notifications.log"
ESSAI_SYNC=echec copier
code=$?
voir "copie ratée après le retrait de l'ancienne (faute de place) : sa trace reste, vide" \
  eval '((code == 1)) && [[ -f $PART && ! -s $PART ]] && ! compgen -G "$BANC/cle5/ISO/kali-*.iso" >/dev/null &&
    dit "$BANC/notifications.log" "copie ratée"' || montrer "$BANC/sortie"
copier
code=$?
voir "et la copie se refait au passage suivant" \
  eval '((code == 0)) && cmp -s "$NEUVE" "$IMAGE5"' || montrer "$BANC/sortie"
/usr/bin/umount "$BANC/cle5"

# Kali dont la dernière version n'a aucune source : la précédente est prise à sa place, et son torrent reprend.
mkdir -p "$BANC/cache7/.nouveau-kali-2026.1"
echo vieux >"$BANC/cache7/.nouveau-kali-2026.1/kali-linux-2026.1-live-everything-amd64.iso"
echo partiel >"$BANC/aria2/kali-linux-2026.2-live-everything-amd64.iso"
rm -f "$BANC/aria2/kali-linux-2026.3-live-everything-amd64.iso" "$BANC/aria2c.log"
chercher_kali() {
  (
    source outils/images-cle.sh
    for s in arch debian fedora systemrescue omarchy; do eval "derniere_$s() { return 1; }"; done
    derniere_kali() { echo "kali-linux-2026.3-live-everything-amd64.iso https://exemple.invalid/kali-2026.3/"; }
    precedente_kali() { echo "kali-linux-2026.2-live-everything-amd64.iso https://exemple.invalid/kali-2026.2/"; }
    lire() { echo "faux $1"; }
    verifier_image() { return 0; }
    chercher
  ) >>"$BANC/sortie7" 2>&1
}
VANGUARD_IMAGES=$BANC/cache7 chercher_kali
VANGUARD_IMAGES=$BANC/cache7 chercher_kali
voir "Kali : le torrent de la précédente, prise à la place de la dernière, reprend à la recherche suivante" \
  eval '[[ $(tail -1 "$BANC/aria2c.log") == "kali-linux-2026.2-live-everything-amd64.iso reprise" ]] &&
    [[ ! -e $BANC/cache7/.nouveau-kali-2026.3 ]] &&
    [[ -s $BANC/cache7/.nouveau-kali-2026.2/kali-linux-2026.2-live-everything-amd64.iso ]]' ||
  { montrer "$BANC/aria2c.log"; montrer "$BANC/sortie7"; }
voir "Kali : le torrent d'une version qui ne servira plus est retiré" \
  eval '[[ ! -e $BANC/cache7/.nouveau-kali-2026.1 ]]'

# --- Ménage (menage-dev.sh) ------------------------------------------------------------------------------------------

echo "Ménage du développement :"
I=$BANC/xdg6/vanguard/images-cle
mkdir -p "$I/.nouveau-kali-2026.3" "$I/.nouveau-kali-2026.1" "$I/.nouveau-arch"
for f in "$I/.nouveau-kali-2026.3/kali-linux-2026.3-live-everything-amd64.iso" \
  "$I/.nouveau-kali-2026.1/kali-linux-2026.1-live-everything-amd64.iso" \
  "$I/.nouveau-arch/archlinux-2026.11.01-x86_64.iso"; do
  head -c 4096 /dev/urandom >"$f"
done
: >"$I/.nouveau-kali-2026.3/kali-linux-2026.3-live-everything-amd64.iso.aria2"
: >"$I/.nouveau-kali-2026.3/kali-linux-2026.3-live-everything-amd64.iso.torrent"
: >"$I/.nouveau-kali-2026.1/kali-linux-2026.1-live-everything-amd64.iso.torrent"
find "$I/.nouveau-kali-2026.3" "$I/.nouveau-arch" -exec touch -d '7 days ago' {} +
find "$I/.nouveau-kali-2026.1" -exec touch -d '40 days ago' {} +
XDG_CACHE_HOME=$BANC/xdg6 bash outils/menage-dev.sh --voir >"$BANC/sortie" 2>&1
voir "torrent de Kali en cours (7 jours) gardé pour reprendre ; un curl interrompu et un torrent abandonné partent" \
  eval 'pas_dit "$BANC/sortie" ".nouveau-kali-2026.3" && dit "$BANC/sortie" ".nouveau-arch" &&
    dit "$BANC/sortie" ".nouveau-kali-2026.1" && [[ -d $I/.nouveau-arch ]]' || montrer "$BANC/sortie"

echo "$ESSAIS essais, $ECHECS en échec."
((ECHECS == 0))
