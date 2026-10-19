#!/bin/bash
# Essai complet de Vanguard sur un vrai Mac (celui de GitHub, voir .github/workflows/macos.yml, option
# « essai_complet »). Chaque commande est lancée sans interaction (réponses fournies), avec un délai maximal ;
# sorties, codes de retour et vérifications vont dans le dossier de résultats, téléchargé ensuite.
#   outils/test-macos/essai.sh <programme vanguard> <dossier de résultats>
# Pas de scan du réseau local : celui de GitHub ne nous appartient pas (seulement 127.0.0.1).
set -u
VANGUARD=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
RES=$2
mkdir -p "$RES"
RES=$(cd "$RES" && pwd)
export VANGUARD_LANG=fr
JOURNAL="$RES/journal.txt"

# Le journal garde le détail (relu par le rapport HTML) ; l'écran montre une ligne par commande ou vérification.
note() { echo "$*" >>"$JOURNAL"; printf '      \033[90m%s\033[0m\n' "$*"; }
titre() { echo "=== $* ===" >>"$JOURNAL"; printf '\n  \033[1;31mTEST DE VANGUARD\033[0m  \033[90m%s\033[0m\n' "$*"; }
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
  local texte="vanguard $*"
  [ $# = 0 ] && texte="vanguard (menu)"
  texte=$(echo "$texte" | sed -E 's#[^ ]*/([^/ ]+)#\1#g')
  [ ${#texte} -gt 58 ] && texte="${texte:0:57}…"
  if [ "$code" = 0 ]; then
    printf '      %-60s \033[32m✓\033[0m \033[90m%4s s\033[0m\n' "$texte" "$duree"
  else
    printf '      %-60s \033[31m✗ code %s\033[0m \033[90m%4s s\033[0m\n' "$texte" "$code" "$duree"
  fi
}
# macOS n'a pas la commande timeout : perl s'en charge (alarme puis exec).
delai() { perl -e 'alarm shift; exec @ARGV' "$@"; }

# lancer <nom> <secondes> <entrée> <arguments…> : sortie dans <nom>.txt, code et durée dans le journal.
lancer() {
  local nom=$1 secondes=$2 entree=$3
  shift 3
  local debut=$SECONDS
  printf '%b' "$entree" | delai "$secondes" "$VANGUARD" "$@" >"$RES/$nom.txt" 2>&1
  local code=$?
  echo "vanguard $* -> code $code, $((SECONDS - debut)) s$([ $code = 142 ] && echo ' (DÉLAI DÉPASSÉ)') · $nom.txt" >>"$JOURNAL"
  ecran_commande "$code" "$((SECONDS - debut))" "$@"
}

verifier() { # verifier <description> <commande…>
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

titre "Essai complet de Vanguard sur macOS $(sw_vers -productVersion) ($(uname -m))"
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

section "Intégrité (référence, vérification, modification détectée)"
lancer integrite-reference 60 '' integrite
lancer integrite-verification 60 '' integrite
echo "# essai Vanguard $(date)" >>~/.zshrc
lancer integrite-modification 60 '' integrite
verifier "intégrité : ~/.zshrc modifié repéré" grep -q 'zshrc' "$RES/integrite-modification.txt"

section "Ports de cette machine"
lancer local 300 '' reseau 127.0.0.1
lancer local-json 300 '' reseau 127.0.0.1 --json

section "Connexion"
lancer connexion 180 '' connexion

section "Menu : chaque groupe ouvert puis refermé, puis q"
lancer menu 60 '4\n\n5\n\n6\n\n7\n\nq\n'
verifier "menu : sous-menus affichés" grep -q 'Antivirus' "$RES/menu.txt"

section "Mots de passe fuités (pseudo-terminal : saisie sans écho)"
python3 -I "$(dirname "$0")/../test-commun/mot-de-passe-pty.py" "$VANGUARD" >"$RES/motdepasse.txt" 2>&1
verifier "mot de passe : « password » trouvé dans des fuites" grep -qE 'Trouvé [0-9 ]+ fois' "$RES/motdepasse.txt"
verifier "mot de passe : jamais affiché" bash -c "! grep -q 'Mot de passe : password' '$RES/motdepasse.txt'"

section "Réparer (liste), mises à jour (sans rien installer), logiciels, gaming"
lancer reparer 60 '\n' reparer
lancer maj 400 'n\nn\nn\nn\n' maj
verifier "maj : jamais « --install --all » (installerait une nouvelle version majeure)" bash -c "! grep -q -- '--install --all' '$RES/maj.txt'"
lancer logiciels-liste 120 '' logiciels --liste
verifier "logiciels : au moins 20 proposés" python3 -c "import re, sys; t = open('$RES/logiciels-liste.txt', encoding='utf-8').read(); sys.exit(len(re.findall(r'(?m)^ +(?:\x1b\[[0-9;]*m)?[✔·]', t)) < 20)"
lancer logiciels 60 '\n' logiciels
lancer nettoyer-liste 120 '' nettoyer --liste
verifier "nettoyer : place à gagner mesurée, rien effacé" grep -qiE 'rien n.a été effacé|nothing was deleted' "$RES/nettoyer-liste.txt"
verifier "logiciels : menu affiché" grep -qE 'Pack de départ|Starter pack' "$RES/logiciels.txt"
lancer gaming 60 '\n' gaming

section "Données : sauvegarde puis restauration"
lancer sauvegarder 60 '' sauvegarder "$RES/sauvegarde.json"
lancer restaurer 60 '' restaurer "$RES/sauvegarde.json"
verifier "sauvegarde écrite" test -s "$RES/sauvegarde.json"

section "Courriel (refus de l'envoi)"
lancer courriel 60 'test@example.com\nn\n' courriel

section "Surveillance : agent launchd"
lancer surveillance-on 60 '' surveillance on
verifier "agent launchd chargé" launchctl print "gui/$(id -u)/com.vanguard.surveillance"
lancer surveillance-off 60 '' surveillance off
verifier "agent launchd retiré" bash -c "! launchctl print gui/$(id -u)/com.vanguard.surveillance"

section "Bac à sable (sandbox-exec)"
ESSAI_BAC="$RES/bac.sh"
cat >"$ESSAI_BAC" <<'EOF'
#!/bin/sh
ls "$HOME" >/dev/null 2>&1 && echo "LECTURE_MAISON_POSSIBLE" || echo "lecture maison refusée"
echo x >"$HOME/vanguard-bac-intrus" 2>/dev/null && echo "ECRITURE_MAISON_POSSIBLE" || echo "écriture maison refusée"
curl -s -m 5 https://example.com >/dev/null 2>&1 && echo "RESEAU_POSSIBLE" || echo "réseau refusé"
echo "fin du programme isolé"
EOF
chmod +x "$ESSAI_BAC"
lancer isoler 60 '' isoler "$ESSAI_BAC"
verifier "bac : programme lancé" grep -q 'fin du programme isolé' "$RES/isoler.txt"
verifier "bac : dossier personnel illisible" bash -c "! grep -q LECTURE_MAISON_POSSIBLE '$RES/isoler.txt'"
verifier "bac : écriture refusée" bash -c "! grep -q ECRITURE_MAISON_POSSIBLE '$RES/isoler.txt'"
verifier "bac : réseau coupé" bash -c "! grep -q RESEAU_POSSIBLE '$RES/isoler.txt'"

section "Antivirus : installation de ClamAV par Vanguard, puis analyse d'un dossier avec le fichier test EICAR"
ESSAI_AV="$RES/dossier-antivirus"
mkdir -p "$ESSAI_AV"
# Le fichier de test standard des antivirus (inoffensif), écrit en deux morceaux.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' >"$ESSAI_AV/eicar.com"
lancer antivirus 900 'o\nn\nn\nn\n' antivirus "$ESSAI_AV"
verifier "antivirus : EICAR détecté" grep -qi 'eicar' "$RES/antivirus.txt"
verifier "antivirus : message « NULL X509 store » de ClamAV masqué" bash -c "! grep -q 'ERROR: NULL X509' '$RES/antivirus.txt'"
verifier "antivirus : refus de la quarantaine annoncé" grep -q 'Rien n.a été fait' "$RES/antivirus.txt"

section "Clé USB simulée (images disque exFAT) : protection et journal d'erreurs"
CLE_IMG="$RES/cle.dmg"
LOG_IMG="$RES/log.dmg"
hdiutil create -quiet -size 64m -fs ExFAT -volname VANGUARD "$CLE_IMG"
hdiutil create -quiet -size 16m -fs ExFAT -volname VANGUARDLOG "$LOG_IMG"
hdiutil attach -quiet "$CLE_IMG"
hdiutil attach -quiet "$LOG_IMG"
mkdir -p /Volumes/VANGUARD/macOS /Volumes/VANGUARD/donnees
cp "$VANGUARD" /Volumes/VANGUARD/macOS/vanguard
# Empreinte d'un autre ordinateur : ce Mac n'est pas celui du propriétaire, la clé doit être protégée.
echo 0000000000000000000000000000000000000000 >/Volumes/VANGUARD/vanguard.cle
touch /Volumes/VANGUARDLOG/vanguard-journal.cle
note "$(mount | grep VANGUARD)"
(cd / && printf '' | delai 120 /Volumes/VANGUARD/macOS/vanguard reseau 999.1.1.1 >"$RES/cle-protection.txt" 2>&1)
note "$(mount | grep VANGUARD)"
verifier "clé : remontée en lecture seule" bash -c "mount | grep ' on /Volumes/VANGUARD ' | grep -q read-only"
verifier "clé : écriture refusée" bash -c "! touch /Volumes/VANGUARD/essai-ecriture"
verifier "clé : VANGUARDLOG toujours modifiable" touch /Volumes/VANGUARDLOG/essai-ecriture
verifier "journal : erreur notée" grep -q 'cible invalide' /Volumes/VANGUARDLOG/journal-erreurs.txt
verifier "journal : rien de personnel" bash -c "! grep -q \"$USER\" /Volumes/VANGUARDLOG/journal-erreurs.txt"
cp /Volumes/VANGUARDLOG/journal-erreurs.txt "$RES/journal-erreurs-cle.txt" 2>/dev/null
# Le menu doit dire la clé protégée.
(cd / && printf 'q\n' | delai 60 /Volumes/VANGUARD/macOS/vanguard >"$RES/cle-menu.txt" 2>&1)
verifier "menu : « protégée en écriture »" grep -q 'protégée en écriture' "$RES/cle-menu.txt"
hdiutil detach -quiet /Volumes/VANGUARD || hdiutil detach -force -quiet /Volumes/VANGUARD
hdiutil detach -quiet /Volumes/VANGUARDLOG || hdiutil detach -force -quiet /Volumes/VANGUARDLOG
rm -f "$CLE_IMG" "$LOG_IMG"

bilan
# Rapport HTML au même style que celui du test Windows (dans l'artefact « essai-macos »).
python3 -I "$(dirname "$0")/../test-commun/rapport.py" "$RES"
