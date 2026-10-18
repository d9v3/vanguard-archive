---
name: livrer
description: Livrer une version de Gardien — numéro de version, commit, intégration dans master, déploiement (binaire, clé USB, GitHub) puis les mises à jour qui suivent chaque version. À lancer quand une modification est finie et que /verifier passe.
---

1. Version dans Cargo.toml : correctif 0.x.y+1, fonction 0.x+1.0. Regarde d'abord celle de master
   (`git show master:Cargo.toml`) : une autre session a pu l'avancer. Puis `cargo build` (Cargo.lock suit).
2. `git add` de tes propres fichiers seulement, puis un commit en français : ce qui change et pourquoi, une puce
   par sujet, avec la ligne Co-Authored-By. Vérifie avec `git show --stat HEAD`.
3. Rebase sur master, puis `git -C <arbre principal> merge --ff-only <branche>`. Si l'arbre principal a des
   changements non committés d'une autre session sur les mêmes fichiers : arrête-toi et demande.
4. `outils/deployer.sh` : compile, refait les captures du README (nouvelle version : commit à part), installe,
   pousse sur GitHub, met la clé à jour si elle est branchée. Si les captures n'ont pas pu se faire, le dire. Rien
   n'est poussé si un détail personnel paraît ou si un lien est mort (`outils/liens.py`) : corriger, puis relancer.
   Un lien douteux montré : l'ouvrir (WebFetch) ; bon mais refusé aux programmes, l'ajouter à `outils/liens.txt`.
5. Page de la version (Releases) : `deployer.sh` la publie tout seul à la fin d'une nouvelle version
   (`outils/publier-version.sh` : trois programmes, empreintes, notes tirées du commit de la version, version
   macOS compilée sur un Mac de GitHub puis copiée sur la clé, notification). S'il l'a ratée, il dit pourquoi :
   corriger, puis relancer `outils/publier-version.sh`.
6. Mises à jour qui suivent chaque version :
   - page du dépôt : toute seule après chaque envoi (`outils/github.py` applique `.github/depot.json` : description
     et version, lien du journal, sujets, options). Si les fonctions ont changé, réécrire la description dans
     `.github/depot.json`, en anglais, 350 caractères au plus avec la version ;
   - journal du projet (document Claude) : ligne d'historique, version en tête, fonctions, pistes ;
   - liste des fonctions : README.md, README.en.md, outils/LISEZMOI.txt, outils/README.txt ; tableau Structure de
     CONTRIBUTING.md et CONTRIBUTING.en.md si un module change.
7. Compte rendu : la version, ce qui a changé, ce qui est vérifié, ce qui ne l'est pas encore (Windows réel,
   Mac réel…).
