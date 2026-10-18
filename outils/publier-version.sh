#!/usr/bin/env bash
# Publie la version de Cargo.toml sur GitHub (page « Releases ») : les trois programmes, sous des noms fixes que le
# README relie (…/releases/latest/download/<nom>), et leurs empreintes SHA-256. À lancer après outils/deployer.sh,
# quand la version est compilée et poussée. La version macOS vient d'un Mac de GitHub (.github/workflows/macos.yml) :
# compilée pour ce commit si elle manque, en quelques minutes.
#   outils/publier-version.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
# Le nom du programme, avec sa majuscule (« Gardien ») : titre de la page de la version.
NOM=$(sed -n 's/^name = "\(.*\)"/\1/p' Cargo.toml | head -1)
NOM=${NOM^}
TAG="v$VERSION"
COMMIT=$(git rev-parse HEAD)
LINUX=target/x86_64-unknown-linux-musl/release/gardien
WINDOWS=target/x86_64-pc-windows-gnu/release/gardien.exe

# Les programmes publiés doivent être ceux de ce commit, et ce commit celui de GitHub : la page de la version y
# renvoie, et le Mac de GitHub compile la tête de master.
if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
  echo "Des changements ne sont pas committés : rien de publié."
  exit 1
fi
if [[ $(cat target/.commit-compile 2>/dev/null) != "$COMMIT" || ! -f $LINUX || ! -f $WINDOWS ]]; then
  echo "Les programmes compilés ne viennent pas de ce commit : lancer d'abord outils/deployer.sh."
  exit 1
fi
git fetch -q origin
if [[ $(git rev-parse origin/master) != "$COMMIT" ]]; then
  echo "Ce commit n'est pas la tête de master sur GitHub : lancer d'abord outils/deployer.sh."
  exit 1
fi
if gh release view "$TAG" >/dev/null 2>&1; then
  echo "La version $TAG est déjà publiée."
  exit 0
fi
# Aucun lien mort, avant d'attendre le Mac : les téléchargements du README (…/releases/latest/download/<nom>) visent
# les fichiers de cette version, qui sera la dernière (outils/liens.py).
python3 outils/liens.py --version gardien-windows-x86_64.exe gardien-linux-x86_64 gardien-macos SHA256SUMS.txt ||
  { echo "Liens : rien de publié."; exit 1; }

DOSSIER=$(mktemp -d)
trap 'rm -rf "$DOSSIER"' EXIT
cp "$LINUX" "$DOSSIER/gardien-linux-x86_64"
cp "$WINDOWS" "$DOSSIER/gardien-windows-x86_64.exe"

RUN=$(gh run list --workflow macos.yml --commit "$COMMIT" --status success --limit 1 --json databaseId -q '.[0].databaseId // ""')
if [[ -z $RUN ]]; then
  echo "Compilation macOS de ce commit sur un Mac de GitHub (quelques minutes)…"
  gh workflow run macos.yml --ref master
  for _ in {1..30}; do
    RUN=$(gh run list --workflow macos.yml --commit "$COMMIT" --limit 1 --json databaseId -q '.[0].databaseId // ""')
    [[ -n $RUN ]] && break
    sleep 5
  done
  [[ -n $RUN ]] || { echo "La compilation macOS n'a pas démarré : rien de publié."; exit 1; }
  gh run watch "$RUN" --exit-status >/dev/null || { echo "La compilation macOS a échoué : rien de publié."; exit 1; }
fi
gh run download "$RUN" -n gardien-macos -D "$DOSSIER/mac" >/dev/null
cp "$DOSSIER/mac/gardien" "$DOSSIER/gardien-macos"
(cd "$DOSSIER" && sha256sum gardien-windows-x86_64.exe gardien-linux-x86_64 gardien-macos >SHA256SUMS.txt)

# Ce qui change : le commit de la version (« … (v0.49.0) ») ; son titre en tête des notes, ses puces dessous (sans
# les lignes de co-auteur).
CHANGEMENT=$(git log --format=%s --grep="(v$VERSION)" -1 | sed -E 's/ \(v[0-9.]+\)$//')
DETAILS=$(git log --format=%b --grep="(v$VERSION)" -1 | grep -viE '^(co-authored-by|signed-off-by):' || true)
NOTES="**${CHANGEMENT:-$NOM $VERSION}**
${DETAILS:+
$DETAILS
}
Télécharge le programme de ton système :
- **Windows** : \`gardien-windows-x86_64.exe\`, double-clic. Il n'est pas signé : SmartScreen peut avertir
  (« Informations complémentaires » puis « Exécuter quand même »).
- **Linux** : \`gardien-linux-x86_64\` (toutes les distributions), \`chmod +x\` puis lancer dans un terminal.
- **macOS** (Apple Silicon et Intel) : \`gardien-macos\`, puis \`xattr -d com.apple.quarantine gardien-macos\` et
  lancer dans le Terminal.

Empreintes SHA-256 : \`SHA256SUMS.txt\` (\`sha256sum -c SHA256SUMS.txt\`).

---

Download the program for your system: \`gardien-windows-x86_64.exe\` (Windows, unsigned: SmartScreen may warn, “More
info” then “Run anyway”), \`gardien-linux-x86_64\` (any distribution: \`chmod +x\`, then run it in a terminal),
\`gardien-macos\` (Apple Silicon and Intel: \`xattr -d com.apple.quarantine gardien-macos\`, then run it in Terminal).
SHA-256 checksums: \`SHA256SUMS.txt\`."

# Rien de personnel dans la page de la version ni dans les programmes : chemins du dossier personnel, nom dans les
# métadonnées du .exe… (outils/confidentialite.py).
printf '%s\n' "$NOTES" | python3 outils/confidentialite.py --texte || { echo "Notes de la version : rien de publié."; exit 1; }
printf '%s\n' "$NOTES" | python3 outils/liens.py --texte || { echo "Liens des notes : rien de publié."; exit 1; }
python3 outils/confidentialite.py --binaire "$DOSSIER/gardien-windows-x86_64.exe" "$DOSSIER/gardien-linux-x86_64" \
  "$DOSSIER/gardien-macos" || { echo "Programmes : rien de publié."; exit 1; }
gh release create "$TAG" --target "$COMMIT" --title "$NOM $VERSION" --notes "$NOTES" \
  "$DOSSIER/gardien-windows-x86_64.exe" "$DOSSIER/gardien-linux-x86_64" "$DOSSIER/gardien-macos" "$DOSSIER/SHA256SUMS.txt"
echo "Version $TAG publiée : $(gh release view "$TAG" --json url -q .url)"
command -v notify-send >/dev/null &&
  notify-send -a Gardien -i gardien "$NOM $VERSION publiée sur GitHub" "Page de la version : les trois programmes et leurs empreintes." || true

# La version macOS publiée est gardée comme une compilation récupérée (outils/deployer.sh ne la redemande pas) et
# copiée sur la clé si elle est branchée : sinon la clé garderait celle d'avant jusqu'au déploiement suivant.
rm -rf target/macos && mkdir -p target/macos && cp "$DOSSIER/mac/"* target/macos/
CLE=$(find "/run/media/$USER" -maxdepth 2 \( -name gardien.cle -o -name sentinel.cle -o -name netscan.cle \) -printf '%h\n' 2>/dev/null | head -1)
if [[ -n $CLE && -d $CLE/macOS ]] && cp -f target/macos/gardien "$CLE/macOS/gardien" && sync; then
  echo "Version macOS $VERSION copiée sur la clé."
fi
