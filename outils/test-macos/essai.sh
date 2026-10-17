#!/bin/bash
# Essai complet de sentinel sur un vrai Mac (celui de GitHub, voir .github/workflows/macos.yml, option
# « essai_complet »). Chaque commande est lancée sans interaction (réponses fournies), avec un délai maximal ;
# sorties, codes de retour et vérifications vont dans le dossier de résultats, téléchargé ensuite.
#   outils/test-macos/essai.sh <programme sentinel> <dossier de résultats>
# Pas de scan du réseau local : celui de GitHub ne nous appartient pas (seulement 127.0.0.1).
set -u
SENTINEL=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
RES=$2
mkdir -p "$RES"
RES=$(cd "$RES" && pwd)
export SENTINEL_LANG=fr
JOURNAL="$RES/journal.txt"

note() { echo "$*" | tee -a "$JOURNAL"; }
# macOS n'a pas la commande timeout : perl s'en charge (alarme puis exec).
delai() { perl -e 'alarm shift; exec @ARGV' "$@"; }

# lancer <nom> <secondes> <entrée> <arguments…> : sortie dans <nom>.txt, code et durée dans le journal.
lancer() {
  local nom=$1 secondes=$2 entree=$3
  shift 3
  local debut=$SECONDS
  printf '%b' "$entree" | delai "$secondes" "$SENTINEL" "$@" >"$RES/$nom.txt" 2>&1
  local code=$?
  note "sentinel $* -> code $code, $((SECONDS - debut)) s$([ $code = 142 ] && echo ' (DÉLAI DÉPASSÉ)')"
}

verifier() { # verifier <description> <commande…>
  local d=$1
  shift
  if "$@" >/dev/null 2>&1; then note "OK      $d"; else note "ÉCHEC   $d"; fi
}

note "=== Essai complet de sentinel sur macOS $(sw_vers -productVersion) ($(uname -m)) ==="
lancer version 10 '' --version
lancer aide 10 '' --help

note "--- Audit"
lancer machine 300 '' machine
lancer machine-json 300 '' machine --json
verifier "audit JSON lisible" python3 -c "import json; json.load(open('$RES/machine-json.txt'))"
verifier "aucune vérification impossible" python3 -c "
import json,sys; a=json.load(open('$RES/machine-json.txt'))
bad=[c['categorie']+': '+c['message'] for c in a['constats'] if not c['verifie']]
print('\n'.join(bad)); sys.exit(1 if bad else 0)"

note "--- Diagnostic"
lancer diagnostic 120 '' diagnostic
verifier "diagnostic : section MATÉRIEL" grep -q 'MATÉRIEL' "$RES/diagnostic.txt"

note "--- Intégrité (référence, vérification, modification détectée)"
lancer integrite-reference 60 '' integrite
lancer integrite-verification 60 '' integrite
echo "# essai sentinel $(date)" >>~/.zshrc
lancer integrite-modification 60 '' integrite
verifier "intégrité : ~/.zshrc modifié repéré" grep -q 'zshrc' "$RES/integrite-modification.txt"

note "--- Ports de cette machine"
lancer local 300 '' reseau 127.0.0.1
lancer local-json 300 '' reseau 127.0.0.1 --json

note "--- Connexion"
lancer connexion 180 '' connexion

note "--- Menu : chaque groupe ouvert puis refermé, puis q"
lancer menu 60 '4\n\n5\n\n6\n\n7\n\nq\n'
verifier "menu : sous-menus affichés" grep -q 'Antivirus' "$RES/menu.txt"

note "--- Mots de passe fuités (pseudo-terminal : saisie sans écho)"
python3 -I "$(dirname "$0")/../test-commun/mot-de-passe-pty.py" "$SENTINEL" >"$RES/motdepasse.txt" 2>&1
verifier "mot de passe : « password » trouvé dans des fuites" grep -qE 'Trouvé [0-9 ]+ fois' "$RES/motdepasse.txt"
verifier "mot de passe : jamais affiché" bash -c "! grep -q 'Mot de passe : password' '$RES/motdepasse.txt'"

note "--- Réparer (liste), mises à jour (sans rien installer), logiciels, gaming"
lancer reparer 60 '\n' reparer
lancer maj 400 'n\nn\nn\nn\n' maj
verifier "maj : jamais « --install --all » (installerait une nouvelle version majeure)" bash -c "! grep -q -- '--install --all' '$RES/maj.txt'"
lancer logiciels 60 '\n' logiciels
lancer gaming 60 '\n' gaming

note "--- Données : sauvegarde puis restauration"
lancer sauvegarder 60 '' sauvegarder "$RES/sauvegarde.json"
lancer restaurer 60 '' restaurer "$RES/sauvegarde.json"
verifier "sauvegarde écrite" test -s "$RES/sauvegarde.json"

note "--- Courriel (refus de l'envoi)"
lancer courriel 60 'test@example.com\nn\n' courriel

note "--- Surveillance : agent launchd"
lancer surveillance-on 60 '' surveillance on
verifier "agent launchd chargé" launchctl print "gui/$(id -u)/com.sentinel.surveillance"
lancer surveillance-off 60 '' surveillance off
verifier "agent launchd retiré" bash -c "! launchctl print gui/$(id -u)/com.sentinel.surveillance"

note "--- Bac à sable (sandbox-exec)"
ESSAI_BAC="$RES/bac.sh"
cat >"$ESSAI_BAC" <<'EOF'
#!/bin/sh
ls "$HOME" >/dev/null 2>&1 && echo "LECTURE_MAISON_POSSIBLE" || echo "lecture maison refusée"
echo x >"$HOME/sentinel-bac-intrus" 2>/dev/null && echo "ECRITURE_MAISON_POSSIBLE" || echo "écriture maison refusée"
curl -s -m 5 https://example.com >/dev/null 2>&1 && echo "RESEAU_POSSIBLE" || echo "réseau refusé"
echo "fin du programme isolé"
EOF
chmod +x "$ESSAI_BAC"
lancer isoler 60 '' isoler "$ESSAI_BAC"
verifier "bac : programme lancé" grep -q 'fin du programme isolé' "$RES/isoler.txt"
verifier "bac : dossier personnel illisible" bash -c "! grep -q LECTURE_MAISON_POSSIBLE '$RES/isoler.txt'"
verifier "bac : écriture refusée" bash -c "! grep -q ECRITURE_MAISON_POSSIBLE '$RES/isoler.txt'"
verifier "bac : réseau coupé" bash -c "! grep -q RESEAU_POSSIBLE '$RES/isoler.txt'"

note "--- Antivirus : installation de ClamAV par sentinel, puis analyse d'un dossier avec le fichier test EICAR"
ESSAI_AV="$RES/dossier-antivirus"
mkdir -p "$ESSAI_AV"
# Le fichier de test standard des antivirus (inoffensif), écrit en deux morceaux.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' >"$ESSAI_AV/eicar.com"
lancer antivirus 900 'o\nn\nn\nn\n' antivirus "$ESSAI_AV"
verifier "antivirus : EICAR détecté" grep -qi 'eicar' "$RES/antivirus.txt"
verifier "antivirus : message « NULL X509 store » de ClamAV masqué" bash -c "! grep -q 'NULL X509' '$RES/antivirus.txt'"
verifier "antivirus : refus de la quarantaine annoncé" grep -q 'Rien n.a été fait' "$RES/antivirus.txt"

note "--- Clé USB simulée (images disque exFAT) : protection et journal d'erreurs"
CLE_IMG="$RES/cle.dmg"
LOG_IMG="$RES/log.dmg"
hdiutil create -quiet -size 64m -fs ExFAT -volname SENTINEL "$CLE_IMG"
hdiutil create -quiet -size 16m -fs ExFAT -volname SENTINELLOG "$LOG_IMG"
hdiutil attach -quiet "$CLE_IMG"
hdiutil attach -quiet "$LOG_IMG"
mkdir -p /Volumes/SENTINEL/macOS /Volumes/SENTINEL/donnees
cp "$SENTINEL" /Volumes/SENTINEL/macOS/sentinel
# Empreinte d'un autre ordinateur : ce Mac n'est pas celui du propriétaire, la clé doit être protégée.
echo 0000000000000000000000000000000000000000 >/Volumes/SENTINEL/sentinel.cle
touch /Volumes/SENTINELLOG/sentinel-journal.cle
note "$(mount | grep SENTINEL)"
(cd / && printf '' | delai 120 /Volumes/SENTINEL/macOS/sentinel reseau 999.1.1.1 >"$RES/cle-protection.txt" 2>&1)
note "$(mount | grep SENTINEL)"
verifier "clé : remontée en lecture seule" bash -c "mount | grep ' on /Volumes/SENTINEL ' | grep -q read-only"
verifier "clé : écriture refusée" bash -c "! touch /Volumes/SENTINEL/essai-ecriture"
verifier "clé : SENTINELLOG toujours modifiable" touch /Volumes/SENTINELLOG/essai-ecriture
verifier "journal : erreur notée" grep -q 'cible invalide' /Volumes/SENTINELLOG/journal-erreurs.txt
verifier "journal : rien de personnel" bash -c "! grep -q \"$USER\" /Volumes/SENTINELLOG/journal-erreurs.txt"
cp /Volumes/SENTINELLOG/journal-erreurs.txt "$RES/journal-erreurs-cle.txt" 2>/dev/null
# Le menu doit dire la clé protégée.
(cd / && printf 'q\n' | delai 60 /Volumes/SENTINEL/macOS/sentinel >"$RES/cle-menu.txt" 2>&1)
verifier "menu : « protégée en écriture »" grep -q 'protégée en écriture' "$RES/cle-menu.txt"
hdiutil detach -quiet /Volumes/SENTINEL || hdiutil detach -force -quiet /Volumes/SENTINEL
hdiutil detach -quiet /Volumes/SENTINELLOG || hdiutil detach -force -quiet /Volumes/SENTINELLOG
rm -f "$CLE_IMG" "$LOG_IMG"

note "=== Fin : $(grep -c '^OK' "$JOURNAL") vérification(s) OK, $(grep -c '^ÉCHEC' "$JOURNAL") échec(s) ==="
