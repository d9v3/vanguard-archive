#!/usr/bin/env bash
# Publie la version de Cargo.toml sur GitHub (page « Releases ») : les trois programmes, sous des noms fixes que le
# README relie (…/releases/latest/download/<nom>), et leurs empreintes SHA-256. À lancer après outils/deployer.sh,
# quand la version est compilée et poussée. La version macOS vient d'un Mac de GitHub (.github/workflows/macos.yml) :
# compilée pour ce commit si elle manque, en quelques minutes. Les notes reprennent toutes les versions déployées depuis
# la page précédente : outils/deployer.sh ne publie pas chaque 0.x.y.
#   outils/publier-version.sh           publier la version de Cargo.toml
#   outils/publier-version.sh --notes   montrer les notes qu'elle aurait, sans rien publier
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

# Les commits « … (vX.Y.Z) » depuis la dernière page publiée, le plus récent en tête, un seul par version (le plus
# récent : un commit de version ajouté après coup remplace le titre d'avant) ; sans page d'avant (ou si elle manque
# ici), celui de cette version seulement.
versions() {
  local precedente
  precedente=$(gh release view --json tagName -q .tagName 2>/dev/null || true)
  if [[ -n $precedente && $precedente != "$TAG" ]] && git rev-parse -q --verify "$precedente^{commit}" >/dev/null; then
    git log --format='%H %s' "$precedente..HEAD"
  else
    git log --format='%H %s' --grep="(v$VERSION)" -1
  fi | grep -E ' \(v[0-9]+\.[0-9]+\.[0-9]+\)$' | awk '{ v = $NF } !vu[v]++' || true
}

# Ce qui change, version par version : le titre de son commit, ses puces dessous (sans les lignes de co-auteur). Une
# seule version : son titre en gras, comme avant ; plusieurs : un titre « X.Y.Z : … » chacune. Puis comment
# télécharger.
notes() {
  local lignes nombre sha sujet puces
  lignes=$(versions)
  nombre=$(grep -c . <<<"$lignes" || true)
  [[ $nombre -gt 0 ]] || printf '**%s %s**\n\n' "$NOM" "$VERSION"
  while read -r sha sujet; do
    [[ -n $sha ]] || continue
    puces=$(git log -1 --format=%b "$sha" | grep -viE '^(co-authored-by|signed-off-by|claude-session):' || true)
    puces=$(sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' <<<"$puces")
    if [[ $nombre -gt 1 ]]; then
      printf '### %s : %s\n\n' "$(sed -E 's/.* \(v([0-9.]+)\)$/\1/' <<<"$sujet")" "${sujet% (v*)}"
    else
      printf '**%s**\n\n' "${sujet% (v*)}"
    fi
    [[ -z $puces ]] || printf '%s\n\n' "$puces"
  done <<<"$lignes"
  printf '%s\n' "$TELECHARGER"
}

TELECHARGER="Télécharge le programme de ton système :
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

if [[ ${1:-} == --notes ]]; then
  git fetch -q --tags origin 2>/dev/null || true
  notes
  exit 0
fi

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
git fetch -q --tags origin
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

# Une compilation macOS de ce commit qui a vraiment produit le programme : une exécution de nuit sautée (code
# inchangé) réussit aussi, sans rien produire.
avec_programme() {
  local id
  for id in $(gh run list --workflow macos.yml --commit "$COMMIT" --status success --limit 10 --json databaseId \
    -q '.[].databaseId'); do
    if [[ -n $(gh api "repos/{owner}/{repo}/actions/runs/$id/artifacts" \
      -q '.artifacts[] | select(.name == "gardien-macos" and (.expired | not)) | .name') ]]; then
      echo "$id"
      return
    fi
  done
}
RUN=$(avec_programme)
if [[ -z $RUN ]]; then
  echo "Compilation macOS de ce commit sur un Mac de GitHub (quelques minutes)…"
  # Les exécutions déjà là pour ce commit (une nuit sautée, par exemple) ne sont pas celle qu'on attend.
  AVANT=$(gh run list --workflow macos.yml --commit "$COMMIT" --limit 20 --json databaseId -q '.[].databaseId')
  gh workflow run macos.yml --ref master
  for _ in {1..30}; do
    RUN=$(gh run list --workflow macos.yml --commit "$COMMIT" --event workflow_dispatch --limit 1 --json databaseId \
      -q '.[0].databaseId // ""')
    [[ -n $RUN ]] && ! grep -qx -- "$RUN" <<<"$AVANT" && break
    RUN=""
    sleep 5
  done
  [[ -n $RUN ]] || { echo "La compilation macOS n'a pas démarré : rien de publié."; exit 1; }
  gh run watch "$RUN" --exit-status >/dev/null || { echo "La compilation macOS a échoué : rien de publié."; exit 1; }
fi
gh run download "$RUN" -n gardien-macos -D "$DOSSIER/mac" >/dev/null
cp "$DOSSIER/mac/gardien" "$DOSSIER/gardien-macos"
(cd "$DOSSIER" && sha256sum gardien-windows-x86_64.exe gardien-linux-x86_64 gardien-macos >SHA256SUMS.txt)

NOTES=$(notes)

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
CLE=$(find "/run/media/$USER" -maxdepth 2 -name gardien.cle -printf '%h\n' 2>/dev/null | head -1)
if [[ -n $CLE && -d $CLE/macOS ]] && cp -f target/macos/gardien "$CLE/macOS/gardien" && sync; then
  echo "Version macOS $VERSION copiée sur la clé."
  # Le manifeste de la clé, écrit par deployer.sh avant cette copie, la reprend : sinon le bilan suivant dirait le
  # programme macOS remplacé.
  ./"$LINUX" manifeste --ecrire "$CLE" || echo "Manifeste de la clé non réécrit : relancer outils/deployer.sh."
fi
