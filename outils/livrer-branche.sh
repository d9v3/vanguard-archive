#!/usr/bin/env bash
# Livre la publication du jour, une branche déjà commitée (commit de version « … (vX.Y.Z) » en tête) : rebase sur
# master, passage sur le Mac de GitHub, vérification complète pendant qu'il compile, fusion rapide dans master,
# déploiement (outils/deployer.sh : binaire, clé, VM, GitHub, page pour une 0.x.0), puis ménage de la branche et du
# worktree. S'arrête à la première étape en échec, sans rien fusionner.
#   outils/livrer-branche.sh <branche> <worktree>
# GARDIEN_INTERMEDIAIRE=1 : version intermédiaire d'une série, sans passage sur le Mac (seule la dernière y passe).
set -euo pipefail
BRANCHE=$1
ARBRE=$2
# L'arbre principal (master), où se font la fusion et le déploiement : celui qui porte le .git commun.
DEPOT=$(dirname "$(git -C "$ARBRE" rev-parse --path-format=absolute --git-common-dir)")
export CARGO_TARGET_DIR=$DEPOT/target
JOURNAUX=$HOME/.cache/gardien-dev

cd "$ARBRE"
[[ -z $(git status --porcelain) ]] || { echo "✖ $ARBRE a des changements non commités"; exit 1; }
git rebase -q master
COMMIT=$(git rev-parse HEAD)
# Le Mac de GitHub d'abord, la vérification d'ici pendant qu'il compile (3 min 30 d'attente sinon perdues) ; une
# vérification en échec annule la compilation.
ID=""
if [[ -z ${GARDIEN_INTERMEDIAIRE:-} ]]; then
  # Rien de personnel ne part sur GitHub, même sur une branche de passage.
  python3 outils/confidentialite.py --plage origin/master "$BRANCHE" || { echo "✖ détail personnel : rien n'est envoyé"; exit 1; }
  echo "· Mac de GitHub lancé"
  git push -q origin "$BRANCHE" || { echo "✖ branche refusée par GitHub (déjà là avec un autre historique ?)"; exit 1; }
  # Le passage lancé ici, et pas un autre : celui de ce commit, absent avant la demande. Prendre le dernier passage
  # de la branche après une attente fixe pouvait tomber sur un ancien, ou sur aucun, et la fusion partait alors sans
  # attendre le Mac.
  AVANT=$(gh run list --workflow macos.yml --commit "$COMMIT" --limit 20 --json databaseId -q '.[].databaseId')
  gh workflow run macos.yml --ref "$BRANCHE" >/dev/null
  for _ in {1..30}; do
    ID=$(gh run list --workflow macos.yml --commit "$COMMIT" --event workflow_dispatch --limit 1 --json databaseId \
      -q '.[0].databaseId // ""')
    [[ -n $ID ]] && ! grep -qx -- "$ID" <<<"$AVANT" && break
    ID=""
    sleep 5
  done
  [[ -n $ID ]] || { echo "✖ le Mac de GitHub n'a pas démarré : rien n'est fusionné"; exit 1; }
fi
echo "· vérification complète"
if ! outils/verifier.sh >"$JOURNAUX/verif-$BRANCHE.log" 2>&1; then
  tail -30 "$JOURNAUX/verif-$BRANCHE.log"
  [[ -z $ID ]] || gh run cancel "$ID" >/dev/null 2>&1 || true
  exit 1
fi
if [[ -n $ID ]]; then
  echo "· attente du Mac de GitHub"
  gh run watch "$ID" --exit-status --interval 20 >/dev/null 2>&1 || { echo "✖ Mac de GitHub en échec : gh run view $ID --log-failed"; exit 1; }
fi
echo "· fusion et déploiement"
cd "$DEPOT"
git merge -q --ff-only "$BRANCHE"
git push -q origin --delete "$BRANCHE" 2>/dev/null || true
git worktree remove "$ARBRE"
# Fusionnée à l'instant (fusion rapide) : -D, car -d refuse une branche qui suit origin/master pas encore à jour.
git merge-base --is-ancestor "$BRANCHE" master && git branch -q -D "$BRANCHE"
outils/deployer.sh >"$JOURNAUX/deploiement-$BRANCHE.log" 2>&1 || { tail -30 "$JOURNAUX/deploiement-$BRANCHE.log"; exit 1; }
grep -E "Clé GARDIEN|publiée|sans page|Durées" "$JOURNAUX/deploiement-$BRANCHE.log" | tail -4
