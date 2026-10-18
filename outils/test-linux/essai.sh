#!/bin/bash
# Essai complet de Gardien sur ce PC Linux, sans rien modifier de durable : données dans un dossier jetable
# (XDG_DATA_HOME), clé USB cachée (USER fictif), aucune correction ni installation acceptée. Le réseau scanné est
# celui de la maison. Sorties, codes de retour et vérifications vont dans le dossier de résultats.
#   outils/test-linux/essai.sh [programme gardien] [dossier de résultats]
set -u
GARDIEN=${1:-$HOME/.cargo/bin/gardien}
RES=${2:-$(mktemp -d /tmp/gardien-essai-XXXX)}
mkdir -p "$RES"
RES=$(cd "$RES" && pwd)
BAC=$(mktemp -d /tmp/gardien-bac-XXXX)
export GARDIEN_LANG=fr XDG_DATA_HOME="$BAC/donnees"
JOURNAL="$RES/journal.txt"

# Le journal garde le détail (relu par le rapport HTML) ; l'écran montre une ligne par commande ou vérification.
note() { echo "$*" >>"$JOURNAL"; printf '      \033[90m%s\033[0m\n' "$*"; }
titre() { echo "=== $* ===" >>"$JOURNAL"; printf '\n  \033[1;31mTEST DE GARDIEN\033[0m  \033[90m%s\033[0m\n' "$*"; }
bilan() {
  local ok bug
  ok=$(grep -c '^OK' "$JOURNAL")
  bug=$(grep -c '^ÉCHEC' "$JOURNAL")
  echo "=== Fin : $ok vérification(s) OK, $bug échec(s) ===" >>"$JOURNAL"
  printf '\n  ──────────────────────────────────────────────────────────\n'
  if [ "$bug" = 0 ]; then printf '  \033[32m✓ Tout est passé : %s vérification(s) réussie(s).\033[0m\n' "$ok"
  else printf '  \033[31m✗ %s problème(s) ; %s vérification(s) réussie(s).\033[0m\n' "$bug" "$ok"; fi
}
section() { echo "--- $*" >>"$JOURNAL"; printf '\n  \033[1;36m▸ %s\033[0m\n' "$*"; }
ecran_commande() { # ecran_commande <code> <secondes> <arguments…>
  local code=$1 duree=$2
  shift 2
  local texte="gardien $*"
  [ $# = 0 ] && texte="gardien (menu)"
  texte=$(echo "$texte" | sed -E 's#[^ ]*/([^/ ]+)#\1#g')
  [ ${#texte} -gt 58 ] && texte="${texte:0:57}…"
  if [ "$code" = 0 ]; then
    printf '      %-60s \033[32m✓\033[0m \033[90m%4s s\033[0m\n' "$texte" "$duree"
  else
    printf '      %-60s \033[31m✗ code %s\033[0m \033[90m%4s s\033[0m\n' "$texte" "$code" "$duree"
  fi
}

# lancer <nom> <secondes> <entrée> <arguments…> : clé USB cachée (USER fictif), données jetables.
lancer() {
  local nom=$1 secondes=$2 entree=$3
  shift 3
  local debut=$SECONDS
  printf '%b' "$entree" | USER=essai timeout "$secondes" "$GARDIEN" "$@" >"$RES/$nom.txt" 2>&1
  local code=$?
  echo "gardien $* -> code $code, $((SECONDS - debut)) s$([ $code = 124 ] && echo ' (DÉLAI DÉPASSÉ)') · $nom.txt" >>"$JOURNAL"
  ecran_commande "$code" "$((SECONDS - debut))" "$@"
}

verifier() {
  local d=$1
  shift
  if "$@" >/dev/null 2>&1; then
    echo "OK      $d" >>"$JOURNAL"
    printf '      \033[32m✓\033[0m %s\n' "$d"
  else
    echo "ÉCHEC   $d" >>"$JOURNAL"
    printf '      \033[31m✗ %s\033[0m\n' "$d"
  fi
}

titre "Essai complet de Gardien ($("$GARDIEN" --version)) sur $(. /etc/os-release && echo "$PRETTY_NAME")"
lancer version 10 '' --version
lancer aide 10 '' --help

section "Audit"
lancer machine 300 '' machine
lancer machine-json 300 '' machine --json
verifier "audit JSON lisible" python3 -c "import json; json.load(open('$RES/machine-json.txt'))"
verifier "aucune vérification impossible" python3 -c "
import json,sys; a=json.load(open('$RES/machine-json.txt'))
bad=[c['categorie']+': '+c['message'] for c in a['constats'] if not c['verifie']]
print('\n'.join(bad)); sys.exit(1 if bad else 0)"

section "Diagnostic"
lancer diagnostic 120 '' diagnostic
verifier "diagnostic : section MATÉRIEL" grep -q 'MATÉRIEL' "$RES/diagnostic.txt"
verifier "diagnostic : copie texte enregistrée" bash -c "ls '$XDG_DATA_HOME'/gardien/diagnostic-*.txt"

section "Intégrité (référence, vérification)"
lancer integrite-reference 120 '' integrite
lancer integrite-verification 120 '' integrite
verifier "intégrité : 2e passage identique" grep -qi 'identique' "$RES/integrite-verification.txt"

section "Réseau de la maison, ports de ce PC, connexion"
lancer reseau 300 '' reseau
lancer reseau-json 300 '' reseau --json
verifier "scan JSON lisible" python3 -c "import json; json.load(open('$RES/reseau-json.txt'))"
lancer local 300 '' reseau 127.0.0.1
lancer connexion 180 '' connexion
BOX=$(python3 -c "
import json; r=json.load(open('$RES/reseau-json.txt'))
print(next((h['ip'] for h in r['hotes'] if h.get('role')=='passerelle'), ''))" 2>/dev/null)
if [ -n "$BOX" ]; then
  lancer nommer 60 '' nommer "$BOX" box de test
  lancer nommer-retrait 60 '' nommer "$BOX"
  verifier "nommer : surnom donné" grep -q 'box de test' "$RES/nommer.txt"
fi

section "Bilan complet en texte"
lancer complet 600 '' complet --texte

section "Menu : chaque groupe ouvert puis refermé, puis q ; entrée fermée"
lancer menu 60 '4\n\n5\n\n6\n\n7\n\nq\n'
for g in 'Cette machine' 'Réseau et Internet' 'Antivirus et protection' 'Installer et jouer'; do
  verifier "menu : groupe « $g »" grep -q "$g" "$RES/menu.txt"
done
debut=$SECONDS
USER=essai timeout 10 "$GARDIEN" </dev/null >"$RES/menu-eof.txt" 2>&1
verifier "menu : quitte quand l'entrée est fermée" test $? -ne 124

section "Mots de passe fuités (pseudo-terminal : saisie sans écho)"
python3 -I "$(dirname "$0")/../test-commun/mot-de-passe-pty.py" "$GARDIEN" >"$RES/motdepasse.txt" 2>&1
verifier "mot de passe : « password » trouvé dans des fuites" grep -qE 'Trouvé [0-9 ]+ fois' "$RES/motdepasse.txt"
verifier "mot de passe : jamais affiché" bash -c "! grep -q 'Mot de passe : password' '$RES/motdepasse.txt'"

section "Réparer (liste), mises à jour (sans rien installer), logiciels, gaming, courriel refusé"
lancer reparer 60 '\n' reparer
lancer maj 600 'n\nn\nn\nn\nn\n' maj
lancer logiciels-liste 120 '' logiciels --liste
verifier "logiciels : au moins 20 proposés" python3 -c "import re, sys; t = open('$RES/logiciels-liste.txt', encoding='utf-8').read(); sys.exit(len(re.findall(r'(?m)^ +(?:\x1b\[[0-9;]*m)?[✔·]', t)) < 20)"
lancer logiciels 60 '\n' logiciels
lancer nettoyer-liste 120 '' nettoyer --liste
verifier "nettoyer : place à gagner mesurée, rien effacé" grep -qiE 'rien n.a été effacé|nothing was deleted' "$RES/nettoyer-liste.txt"
verifier "logiciels : menu affiché" grep -qE 'Pack de départ|Starter pack' "$RES/logiciels.txt"
lancer gaming 60 '\n' gaming
lancer courriel 60 'test@example.com\nn\n' courriel

section "Données : sauvegarde puis restauration"
lancer sauvegarder 60 '' sauvegarder "$RES/sauvegarde.json"
lancer restaurer 60 '' restaurer "$RES/sauvegarde.json"
verifier "sauvegarde écrite" test -s "$RES/sauvegarde.json"

section "Surveillance : minuterie systemd activée puis retirée"
lancer surveillance-on 60 '' surveillance on
verifier "minuterie activée" systemctl --user is-enabled gardien-surveillance.timer
lancer surveillance-off 60 '' surveillance off
verifier "minuterie retirée" bash -c '! systemctl --user is-enabled gardien-surveillance.timer'

section "Bac à sable (bubblewrap)"
cat >"$RES/bac.sh" <<'EOF'
#!/bin/sh
ls /home >/dev/null 2>&1 && [ -n "$(ls -A /home 2>/dev/null)" ] && echo "LECTURE_MAISON_POSSIBLE" || echo "dossier personnel invisible"
echo x >/etc/gardien-intrus 2>/dev/null && echo "ECRITURE_SYSTEME_POSSIBLE" || echo "système en lecture seule"
(exec 3<>/dev/tcp/1.1.1.1/443) 2>/dev/null && echo "RESEAU_POSSIBLE" || echo "réseau coupé"
echo "fin du programme isolé"
EOF
sed -i '1s|/bin/sh|/bin/bash|' "$RES/bac.sh"
chmod +x "$RES/bac.sh"
lancer isoler 60 '' isoler "$RES/bac.sh"
verifier "bac : programme lancé" grep -q 'fin du programme isolé' "$RES/isoler.txt"
verifier "bac : dossier personnel invisible" bash -c "! grep -q LECTURE_MAISON_POSSIBLE '$RES/isoler.txt'"
verifier "bac : système en lecture seule" bash -c "! grep -q ECRITURE_SYSTEME_POSSIBLE '$RES/isoler.txt'"
verifier "bac : réseau coupé" bash -c "! grep -q RESEAU_POSSIBLE '$RES/isoler.txt'"

section "Antivirus : dossier avec le fichier test EICAR (ClamAV), quarantaine refusée"
mkdir -p "$BAC/av"
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' >"$BAC/av/eicar.com"
lancer antivirus 600 'n\nn\nn\n' antivirus "$BAC/av"
verifier "antivirus : EICAR détecté" grep -qi 'eicar' "$RES/antivirus.txt"
verifier "antivirus : fichier laissé en place (quarantaine refusée)" test -f "$BAC/av/eicar.com"

section "Clé USB simulée (espace de noms) : lecture seule respectée, journal d'erreurs"
mkdir -p "$BAC/cle/Linux" "$BAC/cle/donnees" "$BAC/log"
cp "$GARDIEN" "$BAC/cle/Linux/gardien"
touch "$BAC/cle/gardien.cle" "$BAC/log/gardien-journal.cle"
unshare -rm bash -c "
  mount -t tmpfs none /run/media/$(id -un) 2>/dev/null || exit 3
  mkdir /run/media/$(id -un)/GARDIEN /run/media/$(id -un)/GARDIENLOG
  mount --bind '$BAC/cle' /run/media/$(id -un)/GARDIEN && mount -o remount,bind,ro /run/media/$(id -un)/GARDIEN
  mount --bind '$BAC/log' /run/media/$(id -un)/GARDIENLOG
  cd / && /run/media/$(id -un)/GARDIEN/Linux/gardien reseau 999.1.1.1
  printf 'q\n' | /run/media/$(id -un)/GARDIEN/Linux/gardien
" >"$RES/cle.txt" 2>&1
verifier "clé protégée : rien écrit dessus" bash -c "[ -z \"\$(ls -A '$BAC/cle/donnees')\" ]"
verifier "clé protégée : menu « protégée en écriture »" grep -q 'protégée en écriture' "$RES/cle.txt"
verifier "journal : erreur notée" grep -q 'cible invalide' "$BAC/log/journal-erreurs.txt"
verifier "journal : rien de personnel" bash -c "! grep -q \"$(id -un)\" '$BAC/log/journal-erreurs.txt'"

rm -rf "$BAC"
bilan
# Rapport HTML au même style que celui du test Windows, ouvert dans le navigateur s'il y a un écran.
RAPPORT=$(python3 -I "$(dirname "$0")/../test-commun/rapport.py" "$RES")
echo "Rapport : $RAPPORT"
if [ -n "${WAYLAND_DISPLAY:-}${DISPLAY:-}" ] && [ -z "${GARDIEN_ESSAI_SANS_NAVIGATEUR:-}" ]; then
  xdg-open "$RAPPORT" >/dev/null 2>&1 &
fi
