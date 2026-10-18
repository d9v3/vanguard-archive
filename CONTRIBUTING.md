# Développer Gardien

**Français** · [English](CONTRIBUTING.en.md)

Le code, ses commentaires et ses noms internes sont en français ; chaque texte montré à l'utilisateur existe dans les
deux langues (`tr!("fr", "en")` dans `src/langue.rs`).

Avec Claude Code : `CLAUDE.md` donne les commandes et les règles du projet, `/verifier` et `/livrer`
(`.claude/skills/`) vérifient tout et livrent une version ; un crochet remet en forme le Rust après chaque
modification. Sur GitHub, `@claude` dans un ticket ou une demande de fusion le fait répondre, et chaque ticket
« journal » est analysé tout seul (`.github/workflows/claude*.yml`, à activer une fois avec `/install-github-app`).

## Structure

| Fichier | Rôle |
|---|---|
| `src/main.rs` | menu et sous-commandes |
| `src/ui.rs` | couleurs, titres, cadres, barres, lignes coupées et alignées dans 76 colonnes |
| `src/selection.rs` | menus et listes à cocher au clavier (flèches, Entrée, Échap ou Retour arrière) |
| `src/langue.rs` | choix de la langue et macros de traduction |
| `src/machine/mod.rs` | types communs, affichage, exécution parallèle des vérifications |
| `src/machine/linux/`, `src/machine/windows/`, `src/machine/macos/` | audit propre à chaque système, un fichier par thème |
| `src/machine/dns.rs`, `certificats.rs`, `extensions.rs`, `sante.rs` | vérifications communes aux trois systèmes |
| `src/corriger.rs` | application guidée des correctifs |
| `src/reseau.rs`, `src/scan.rs` | scan réseau (TCP connect, sans root), ARP, carnets des réseaux |
| `src/risk.rs` | base de connaissances des ports et niveaux de risque |
| `src/connexion.rs` | test de connexion pour le jeu |
| `src/antivirus.rs` | ClamAV / Defender, quarantaine |
| `src/surveillance.rs` | minuterie systemd / Planificateur de tâches / agent launchd, notifications |
| `src/rapport.rs`, `src/historique.rs` | rapport HTML, historique des bilans, courbe des notes |
| `src/reparer.rs`, `src/maj.rs`, `src/gaming/` | réparations, mises à jour, gaming |
| `src/optimiser/` | réglages de confidentialité, de performance et de confort, avec annulation exacte |
| `src/nettoyer/` | nettoyage : éléments par système, place mesurée avant et après |
| `src/logiciels/` | logiciels à installer : catalogue vérifié (`catalogue.rs`), état et installation par système |
| `src/fuites.rs`, `src/donnees.rs` | mots de passe fuités, sauvegarde des données |
| `assets/oui.tsv` | fabricants par préfixe MAC (liste IEEE), rangés en tableaux triés à la compilation (`build.rs`) |
| `assets/icones/`, `assets/gardien.ico` | le logo, calculé par `outils/icone.py` |
| `LICENCES-TIERCES.txt` | avis de licence des bibliothèques incluses (`outils/licences-tierces.py`) |

## Compiler, tester, déployer

Prérequis : `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu` et `mingw-w64-gcc`.

```sh
outils/deployer.sh     # compile Linux (musl, statique) + Windows, installe en local, pousse sur GitHub, met à jour la clé
```

Tests : `cargo test` (Linux, dans un dossier de données jetable : jamais les vraies données de l'ordinateur) ; tests
Windows sous Wine (`cargo test --target x86_64-pc-windows-gnu` avec un lanceur Wine) ; `cargo clippy --all-targets`
sur les quatre cibles (Linux, Windows, `aarch64-apple-darwin`, `x86_64-apple-darwin`), en mode strict (pedantic),
sans remarque ; `cargo fmt --check`. Les fonctions internes sont testées dans leur module ; `tests/programme.rs` lance
le vrai programme comme le ferait quelqu'un (aide dans les deux langues, menus quittés, listes, refus respectés, audit
et scan de 127.0.0.1 en JSON), avec un dossier personnel jetable, sans la clé ni la session de l'utilisateur. Essais
complets : `outils/test-linux/essai.sh`, `outils/test-macos/essai.sh` (sur
un Mac de GitHub) et, dans la machine virtuelle Windows, `TESTER-GARDIEN.bat` (déposé par `deployer.sh`).

macOS : compilé et testé sur un Mac de GitHub (`.github/workflows/macos.yml`, programme universel Apple Silicon +
Intel), chaque nuit si le code a changé ou à la demande (`gh workflow run macos.yml`). `deployer.sh` récupère la
dernière compilation réussie pour la clé.

Intégration continue (`.github/workflows/ci.yml`) : à chaque envoi sur GitHub, la mise en forme, clippy sans
remarque sur les quatre cibles et les tests, sous Linux ; sur un vrai Windows (PowerShell, registre), chaque nuit si
le code a changé, à chaque demande de fusion et à la demande (`gh workflow run ci.yml`). Pas Windows ni Mac à chaque
envoi : sur un dépôt privé, leurs minutes comptent double et dix fois.

## Captures d'écran et image de partage

`outils/captures.py` refait les captures du README (`assets/captures/`, en français et en anglais) et l'image de
partage du dépôt (`assets/partage.png`). `deployer.sh` le lance à chaque nouvelle version, puisque le menu montre son
numéro, et commite les images à part.

Gardien y tourne pour de vrai, dans un pseudo-terminal de 80 colonnes, depuis une fausse clé et sur une copie des
données : rien de vrai n'est touché. Le nom du réseau devient « Salon » ; adresses MAC (préfixe du fabricant gardé),
adresses IP (un réseau inventé, longueurs et ordre gardés), noms d'appareils et dossiers du compte sont remplacés, au
hasard à chaque passe ; du bilan de la machine, seul un extrait sans rien de personnel est montré. Puis le garde-fou
de confidentialité relit chaque image : si un détail de la maison restait visible, aucune n'est écrite.

```sh
uv run --no-project --with pyte python outils/captures.py [programme] [--connexion | --sans-connexion]
```

## Confidentialité

`outils/confidentialite.py` empêche qu'un détail personnel parte sur GitHub. Il est lancé tout seul : à chaque commit
(lignes ajoutées, noms de fichiers, auteur, message), avant chaque envoi par `deployer.sh`, avant chaque page de
version (notes et programmes compilés), avant chaque ticket du journal et avant d'écrire les captures. Une fois par
copie du dépôt :

```sh
git config core.hooksPath outils/hooks                                     # crochets pre-commit et commit-msg
git config user.email "<id>+<compte>@users.noreply.github.com"            # commits sans ton courriel
```

Ce qui est personnel est lu sur l'ordinateur, jamais écrit dans le dépôt : `~/.config/gardien-dev/confidentiel.txt`
(une expression par ligne : nom, courriels, adresse…), l'identité Git globale, le dossier personnel, les appareils et
adresses MAC de la base de Gardien, les réseaux Wi-Fi enregistrés. `python3 outils/confidentialite.py --depot` relit
tout le dépôt et son historique. Dans les tests, des valeurs inventées : adresses MAC au préfixe du fabricant gardé,
réseau « Salon », compte « alice ».

Rust garde le chemin des bibliothèques dans les programmes (`/home/<compte>/.cargo/registry/…`) : pour publier une
version, compiler avec `rustflags = ["--remap-path-prefix=/home/<compte>=~"]` dans `~/.cargo/config.toml`
(`publier-version.sh` refuse un programme qui contient encore le dossier personnel).

## Publier une version

`outils/publier-version.sh` crée la page de la version sur GitHub (Releases) avec les trois programmes
(`gardien-windows-x86_64.exe`, `gardien-linux-x86_64`, `gardien-macos`) et leurs empreintes SHA-256 ; les liens de
téléchargement du README pointent toujours vers la dernière.

## La clé USB

La clé (exFAT, étiquette `GARDIEN`, fichier témoin `gardien.cle`) contient `Linux/`, `Windows/`, `macOS/`, `donnees/`
(base des appareils, portable), `source/` (ce dépôt) et le guide en deux langues (`LISEZMOI.txt`, `README.txt`, tirés
de `outils/`). L'historique des bilans et la quarantaine restent sur chaque ordinateur.

Sur le PC de développement, elle se met à jour toute seule (unités systemd dans `outils/systemd/`, installées par
`outils/systemd/installer.sh`) : après chaque compilation (`gardien-copie.service`), et à chaque branchement avec la
dernière version de GitHub, compilée si elle est nouvelle (`gardien-cle.service`, `deployer.sh --branchement`).

La clé a deux partitions : `GARDIEN`, en lecture seule partout sauf sur l'ordinateur du propriétaire (attribut GPT
respecté par Windows ; sous Linux et macOS, Gardien la remonte lui-même en lecture seule), et `GARDIENLOG`, qui ne
reçoit que le journal des erreurs, anonymisé. `outils/preparer-cle.sh` prépare une nouvelle clé.

## Erreurs et plantages

Gardien les note sans rien de personnel (sur la clé, ou dans son dossier quand la clé n'est pas branchée). Au
déploiement, `deployer.sh` les rapatrie et `outils/journal-vers-github.py` en fait des tickets GitHub (étiquette
« journal ») avec `gh` : un ticket par erreur, les répétitions en commentaire. Aucun mot de passe GitHub dans le
programme ni sur la clé.

## Anciens noms

Gardien s'est appelé netscan (jusqu'à 0.10) puis Sentinel (jusqu'à 0.50). Il reprend ce que ces noms ont laissé sur un
ordinateur : dossier des données (renommé une fois), clé et partition du journal (témoins `sentinel.cle`,
`sentinel-journal.cle`, étiquettes `SENTINEL` et `SENTINELLOG`), surveillance (minuterie, tâche planifiée, agent
launchd), règles du pare-feu, fichiers posés dans `/etc`, sauvegardes, variables `SENTINEL_LANG` et
`SENTINEL_HIBP_CLE`. Les commandes `sentinel` et `netscan` lancent `gardien`.
