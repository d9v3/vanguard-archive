<img src="assets/icones/sentinel-256.png" alt="Logo de Sentinel : un trou noir" width="128" align="right">

# Sentinel

**Français** · [English](README.en.md)

**Sécurise et optimise ton ordinateur et ton réseau, depuis une clé USB.**
Sentinel vérifie ta machine et tous les appareils de ton réseau, explique chaque problème en français clair, et le
corrige après ton accord. Linux, Windows et macOS, sans installation, en français ou en anglais.

**Systèmes pris en charge** — Windows 10 et 11 ; macOS 12 et plus récents (Apple Silicon et Intel, encore jamais
essayé sur un vrai Mac hors des tests automatiques) ; Linux : Arch et dérivées (Omarchy, Manjaro, EndeavourOS, CachyOS),
Debian, Ubuntu, Mint, Pop!_OS, Fedora (et RHEL, Rocky, Nobara), openSUSE, ainsi que les systèmes atomiques
(Bazzite, Silverblue, Kinoite, Bluefin, Aeon). Sentinel reconnaît la distribution et propose ses propres commandes :
`omarchy update` / `omarchy pkg add` sous Omarchy, `ujust update` sur Bazzite, `rpm-ostree` ou `transactional-update`
sur un système atomique, sinon pacman, apt, dnf ou zypper.

![Menu de Sentinel](assets/captures/menu.png)

## Ce que fait Sentinel

**Bilan de sécurité** — une note de A à F, puis chaque problème avec sa correction.
- Pare-feu, ports ouverts (TCP et UDP), mises à jour et failles connues, chiffrement du disque, Secure Boot,
  verrouillage de l'écran, comptes, SSH, sudo, durcissement du noyau, sauvegardes.
- Ce qui se cache : programmes lancés au démarrage, tâches planifiées, préchargement de bibliothèques, programmes
  privilégiés modifiés.
- DNS réellement utilisé (et réponses inventées), certificats racine ajoutés (interception du HTTPS), extensions de
  navigateur qui lisent tous les sites.
- Santé : espace disque, état SMART des disques (sans root), batterie, températures.
- Ce qui n'a pas pu être vérifié est dit, jamais compté comme sain.

**Réseau local** — tous les appareils, leur fabricant, leurs ports ouverts (TCP, et UDP : SNMP, NetBIOS, UPnP,
DNS, mDNS) et leurs risques ; les nouveaux venus
signalés, un carnet par réseau (chez toi, chez chaque ami), des surnoms (« imprimante HP ») ; les ports que des
appareils ont ouverts vers Internet sur la box par UPnP (lecture seule, avec miniupnpc sous Linux).

![Scan du réseau local](assets/captures/reseau.png)

**Connexion pour le jeu** — ping, gigue, pertes, débit et bufferbloat (le lag quand quelqu'un télécharge), avec un
verdict critère par critère et des conseils.

![Test de connexion](assets/captures/connexion.png)

**Diagnostic de l'ordinateur** — le premier réflexe d'un dépannage : matériel, système, et les problèmes récents
(erreurs du journal et programmes plantés sous Linux ; écrans bleus, arrêts brutaux et plantages sous Windows ;
paniques du noyau et rapports de plantage sous macOS), avec
une copie texte enregistrée sur la clé.

**Optimiser** — des réglages de confidentialité, de performance et de confort, écrits pour Sentinel. Sous Windows :
télémétrie au minimum, publicités et suivi coupés, Recall sans captures d'écran, extensions des fichiers visibles, pas
de lancement automatique des clés USB, démarrage rapide, menu complet au clic droit. Sous Linux : entretien du SSD,
taille du journal, rapports envoyés par GNOME ou Ubuntu. Sous macOS : publicités, analyses, pas de .DS_Store sur les
clés. Chaque réglage montre son état et s'annule exactement : la valeur d'avant est notée, puis remise. Aucun
n'affaiblit la sécurité.

**Nettoyer le système** — une liste à cocher de ce qui prend de la place sans servir : paquets téléchargés et devenus
inutiles, anciennes versions des Snap, Flatpak inutilisés, compilations AUR, vieux caches, miniatures, vieux journaux,
rapports de plantage (Linux) ; fichiers temporaires, cache de Windows Update et de l'optimisation de distribution,
anciens composants (Windows) ; vieux caches, Homebrew, Xcode, instantanés locaux (macOS). La place que libère chaque
élément est mesurée avant, ce qui se refait seul est coché d'office, la corbeille jamais ; la place libre relue après
dit ce qui a vraiment été gagné.

**Et aussi**
- Corrections appliquées seulement après confirmation, avec un point de restauration créé automatiquement avant
  (snapper ou timeshift sous Linux, point de restauration Windows, instantané Time Machine sous macOS) ; sous
  Windows, chacune est un script lisible.
- Mises à jour de tout d'un coup : système, programmes, pilotes, firmware.
- Logiciels : les meilleurs de chaque usage, libres pour la plupart, rangés en 8 catégories (navigateurs et
  courriel, messagerie et partage, sécurité et vie privée, bureautique, vidéo et musique, images et création, outils
  système, programmation) et un pack de départ (Firefox, Bitwarden, VLC, LibreOffice, 7-Zip) : liste à cocher, déjà
  installés reconnus, installation depuis la source officielle qui vérifie chaque téléchargement (winget, paquets de
  la distribution ou Flathub, Homebrew).
- Réparations : Internet, navigation détournée, pare-feu, disque, disque plein, nettoyage approfondi, Windows Update
  bloqué, fichiers système, heure.
- Antivirus : ClamAV (Linux, macOS) ou Microsoft Defender (Windows), sur l'ordinateur ou sur une clé USB / un dossier
  choisi, avec les pièges des vers de clé (raccourci qui imite un dossier, autorun.inf, scripts).
- Bac à sable : lancer un programme inconnu sans réseau, système en lecture seule, dossier personnel invisible
  (bubblewrap ou firejail sous Linux, Windows Sandbox sous Windows, sandbox-exec sous macOS).
- Intégrité des fichiers critiques (comptes, sudo, SSH, PAM, cron, services, démarrage automatique) : empreintes
  BLAKE3, ce qui a changé depuis la référence, et surveillance en direct.
- Mots de passe fuités : vérifiés par Have I Been Pwned sans jamais envoyer le mot de passe (5 caractères de son
  empreinte seulement) ; fuites d'adresse courriel, après ton accord (l'adresse est envoyée au service).
- Surveillance toutes les heures : notification si un appareil inconnu arrive, si un port s'ouvre, si la note de
  la machine baisse, ou si la box semble usurpée (adresse MAC partagée ou changée : usurpation ARP).
- Rapport HTML avec la courbe des notes, et ce qui a changé depuis le bilan précédent.
- Gaming : sous Windows, composants pour les jeux et réglages de Windows ; sous Linux, Steam, pilotes Vulkan 32 et
  64 bits selon la carte, GameMode, MangoHud, Gamescope, Wine, Lutris, Heroic, ProtonUp-Qt, vm.max_map_count, ntsync ;
  sous macOS, Steam et Heroic.

Sentinel ne coupe jamais une connexion à distance en cours (Bureau à distance, SSH). À n'utiliser que sur ton propre
réseau, ou un réseau que tu as le droit d'auditer.

## Démarrer

- **Depuis la clé** : `Linux/sentinel` (dans un terminal : `./sentinel`), `Windows/sentinel.exe` (double-clic) ou
  `Lancer Sentinel.command` sous macOS (double-clic, le Terminal s'ouvre).
  Le guide de la clé est dans `LISEZMOI.txt` (français) et `README.txt` (anglais).
- **Installé** : lancer `sentinel` ouvre le menu. Choisir **1** (bilan complet), puis **2** (corriger).

Chaque entrée du menu existe aussi en commande :

| Commande | Rôle |
|---|---|
| `sentinel complet [--html] [--texte]` | bilan complet : machine + réseau ; `--texte` l'affiche en texte simple (mode urgence) |
| `sentinel corriger` | corriger les problèmes trouvés |
| `sentinel machine [--json]` | audit de cette machine |
| `sentinel reseau [cible] [-p courants\|tous\|22,80,8000-8100] [--json]` | scan du réseau ou d'un appareil |
| `sentinel connexion` | test de connexion pour le jeu |
| `sentinel nettoyer [--liste]` | nettoyer le système ; `--liste` : la place à gagner, sans rien effacer |
| `sentinel logiciels [--liste] [--recommandes]` | logiciels à installer par catégorie ; `--liste` : leur état, sans rien installer |
| `sentinel diagnostic` | diagnostic de l'ordinateur : matériel, système, plantages et erreurs récents |
| `sentinel antivirus [--complet] [dossier]` | analyse antivirus (ordinateur, ou une clé / un dossier) |
| `sentinel motdepasse` | mots de passe fuités |
| `sentinel isoler <fichier>` | lancer un programme inconnu dans un bac à sable (bubblewrap ou firejail, Windows Sandbox) |
| `sentinel courriel` | fuites d'adresse courriel (XposedOrNot, ou Have I Been Pwned avec `SENTINEL_HIBP_CLE`) |
| `sentinel integrite [--accepter] [--temps-reel]` | intégrité des fichiers critiques (empreintes BLAKE3), en direct possible |
| `sentinel maj` | mises à jour |
| `sentinel reparer` | réparations et nettoyage |
| `sentinel surveillance on\|off` | surveillance horaire |
| `sentinel nommer <ip\|mac> <surnom>` | nommer un appareil |
| `sentinel sauvegarder [fichier]`, `sentinel restaurer <fichier>` | sauvegarde des données |
| `sentinel gaming` | paquets et réglages pour jouer (Windows et Linux) |

**Langue** : celle du système (français ou anglais). Pour forcer : `SENTINEL_LANG=fr` ou `SENTINEL_LANG=en`. Les
commandes ont aussi un nom anglais (`full`, `audit`, `fix`, `network`, `connection`, `apps`, `diag`, `password`,
`sandbox`, `email`, `integrity`, `update`, `repair`, `monitor`, `name`, `backup`, `restore`).

## Pour les développeurs

Avec Claude Code : `CLAUDE.md` donne les commandes et les règles du projet, `/verifier` et `/livrer`
(`.claude/skills/`) vérifient tout et livrent une version ; un crochet remet en forme le Rust après chaque
modification. Sur GitHub, `@claude` dans un ticket ou une demande de fusion le fait répondre, et chaque ticket
« journal » est analysé tout seul (`.github/workflows/claude*.yml`, à activer une fois avec `/install-github-app`).

### Structure

| Fichier | Rôle |
|---|---|
| `src/main.rs` | menu et sous-commandes |
| `src/ui.rs` | couleurs, titres, cadres, barres |
| `src/selection.rs` | menus et listes à cocher au clavier (flèches, Entrée, Échap) |
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
| `LICENCES-TIERCES.txt` | avis de licence des bibliothèques incluses (`outils/licences-tierces.py`) |

### Compiler et déployer

Prérequis : `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu` et `mingw-w64-gcc`.

```sh
outils/deployer.sh     # compile Linux (musl, statique) + Windows, installe en local, pousse sur GitHub, met à jour la clé
```

Tests : `cargo test` (Linux) ; tests Windows sous Wine (`cargo test --target x86_64-pc-windows-gnu` avec un lanceur
Wine) ; `cargo clippy --all-targets` sur les quatre cibles (Linux, Windows, `aarch64-apple-darwin`,
`x86_64-apple-darwin`), en mode strict (pedantic), sans remarque ; `cargo fmt --check`.

macOS : compilé et testé sur un Mac de GitHub (`.github/workflows/macos.yml`, programme universel Apple Silicon +
Intel), chaque nuit si le code a changé ou à la demande (`gh workflow run macos.yml`). `deployer.sh` récupère la
dernière compilation réussie pour la clé.

Intégration continue (`.github/workflows/ci.yml`) : à chaque envoi sur GitHub, la mise en forme, clippy sans
remarque sur les quatre cibles et les tests, sous Linux ; sur un vrai Windows (PowerShell, registre), chaque nuit si
le code a changé, à chaque demande de fusion et à la demande (`gh workflow run ci.yml`). Pas Windows ni Mac à chaque
envoi : sur un dépôt privé, leurs minutes comptent double et dix fois.

### La clé USB

La clé (exFAT, étiquette `SENTINEL`, fichier témoin `sentinel.cle`) contient `Linux/`, `Windows/`, `macOS/`, `donnees/` (base des
appareils, portable), `source/` (ce dépôt) et le guide en deux langues (`LISEZMOI.txt`, `README.txt`, tirés de
`outils/`). L'historique des bilans et la quarantaine restent sur chaque ordinateur.

Sur le PC de développement, elle se met à jour toute seule (unités systemd dans `outils/systemd/`) : après chaque
compilation (`sentinel-copie.service`), et à chaque branchement avec la dernière version de GitHub, compilée si elle
est nouvelle (`sentinel-cle.service`, `deployer.sh --branchement`).

La clé a deux partitions : `SENTINEL`, en lecture seule partout sauf sur l'ordinateur du propriétaire (attribut GPT
respecté par Windows ; sous Linux et macOS, Sentinel la remonte lui-même en lecture seule), et `SENTINELLOG`, qui ne
reçoit que le journal des erreurs, anonymisé. `outils/preparer-cle.sh` prépare une nouvelle clé.

Erreurs et plantages : Sentinel les note sans rien de personnel (sur la clé, ou dans son dossier quand la clé n'est pas
branchée). Au déploiement, `deployer.sh` les rapatrie et `outils/journal-vers-github.py` en fait des tickets GitHub
(étiquette « journal ») avec `gh` : un ticket par erreur, les répétitions en commentaire. Aucun mot de passe GitHub
dans le programme ni sur la clé.

## Licence

© 2026 d9v3. Sentinel est un logiciel libre : tu peux le redistribuer et le modifier selon les termes de la
[licence publique générale GNU](LICENSE) (GPL), version 3 ou toute version ultérieure. Il est fourni sans aucune
garantie. Une version modifiée que tu distribues doit rester sous cette licence, avec son code source.

Les bibliothèques incluses gardent leurs propres licences (MIT, Apache-2.0, BSD, ISC…) : voir `LICENCES-TIERCES.txt`.
