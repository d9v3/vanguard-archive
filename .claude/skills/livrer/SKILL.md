---
name: livrer
description: Livrer une version de Sentinel — numéro de version, commit, intégration dans master, déploiement (binaire, clé USB, GitHub) puis les mises à jour qui suivent chaque version. À lancer quand une modification est finie et que /verifier passe.
---

1. Version dans Cargo.toml : correctif 0.x.y+1, fonction 0.x+1.0. Regarde d'abord celle de master
   (`git show master:Cargo.toml`) : une autre session a pu l'avancer. Puis `cargo build` (Cargo.lock suit).
2. `git add` de tes propres fichiers seulement, puis un commit en français : ce qui change et pourquoi, une puce
   par sujet, avec la ligne Co-Authored-By. Vérifie avec `git show --stat HEAD`.
3. Rebase sur master, puis `git -C <arbre principal> merge --ff-only <branche>`. Si l'arbre principal a des
   changements non committés d'une autre session sur les mêmes fichiers : arrête-toi et demande.
4. `outils/deployer.sh` : compile, installe, pousse sur GitHub, met la clé à jour si elle est branchée.
5. Mises à jour qui suivent chaque version :
   - description GitHub (`gh repo edit --description`) si les fonctions ont changé : français puis anglais,
     350 caractères au plus ; le crochet pre-push met la version à la fin ;
   - lien du dépôt (`--homepage`) : le journal du projet ;
   - journal du projet (document Claude) : ligne d'historique, version en tête, fonctions, pistes ;
   - liste des fonctions : README.md, README.en.md, outils/LISEZMOI.txt, outils/README.txt.
6. Compte rendu : la version, ce qui a changé, ce qui est vérifié, ce qui ne l'est pas encore (Windows réel,
   Mac réel…).
