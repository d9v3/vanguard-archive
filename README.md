# Sentinel

**Le bilan de sécurité de ton ordinateur et de ton réseau, sur une clé USB.**
Sentinel vérifie ta machine et tous les appareils de ton réseau, explique chaque problème en français clair, et le
corrige après ton accord. Linux et Windows, sans installation, en français ou en anglais.

*Portable security check for your computer and your home network: Linux and Windows, French or English.*

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

**Réseau local** — tous les appareils, leur fabricant, leurs ports ouverts et leurs risques ; les nouveaux venus
signalés, un carnet par réseau (chez toi, chez chaque ami), des surnoms (« imprimante HP ») ; les ports que des
appareils ont ouverts vers Internet sur la box par UPnP (lecture seule, avec miniupnpc sous Linux).

![Scan du réseau local](assets/captures/reseau.png)

**Connexion pour le jeu** — ping, gigue, pertes, débit et bufferbloat (le lag quand quelqu'un télécharge), avec un
verdict critère par critère et des conseils.

![Test de connexion](assets/captures/connexion.png)

**Et aussi**
- Corrections appliquées seulement après confirmation, avec un point de restauration créé automatiquement avant
  (snapper ou timeshift sous Linux, point de restauration Windows) ; sous Windows, chacune est un script lisible.
- Mises à jour de tout d'un coup : système, programmes, pilotes, firmware.
- Réparations : Internet, navigation détournée, pare-feu, disque, disque plein, nettoyage approfondi, Windows Update
  bloqué, fichiers système, heure.
- Antivirus : ClamAV (Linux) ou Microsoft Defender (Windows).
- Intégrité des fichiers critiques (comptes, sudo, SSH, PAM, cron, services, démarrage automatique) : empreintes
  BLAKE3, ce qui a changé depuis la référence, et surveillance en direct.
- Mots de passe fuités : vérifiés par Have I Been Pwned sans jamais envoyer le mot de passe (5 caractères de son
  empreinte seulement) ; fuites d'adresse courriel, après ton accord (l'adresse est envoyée au service).
- Surveillance toutes les heures : notification si un appareil inconnu arrive, si un port s'ouvre, si la note de
  la machine baisse, ou si la box semble usurpée (adresse MAC partagée ou changée : usurpation ARP).
- Rapport HTML avec la courbe des notes, et ce qui a changé depuis le bilan précédent.
- Gaming (Windows) : composants pour les jeux et réglages de Windows.

Sentinel ne coupe jamais une connexion à distance en cours (Bureau à distance, SSH). À n'utiliser que sur ton propre
réseau, ou un réseau que tu as le droit d'auditer.

## Démarrer

- **Depuis la clé** : `Linux/sentinel` (dans un terminal : `./sentinel`) ou `Windows/sentinel.exe` (double-clic).
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
| `sentinel antivirus [--complet]` | analyse antivirus |
| `sentinel motdepasse` | mots de passe fuités |
| `sentinel courriel` | fuites d'adresse courriel (XposedOrNot, ou Have I Been Pwned avec `SENTINEL_HIBP_CLE`) |
| `sentinel integrite [--accepter] [--temps-reel]` | intégrité des fichiers critiques (empreintes BLAKE3), en direct possible |
| `sentinel maj` | mises à jour |
| `sentinel reparer` | réparations et nettoyage |
| `sentinel surveillance on\|off` | surveillance horaire |
| `sentinel nommer <ip\|mac> <surnom>` | nommer un appareil |
| `sentinel sauvegarder [fichier]`, `sentinel restaurer <fichier>` | sauvegarde des données |
| `sentinel gaming` | gaming (Windows) |

**Langue** : celle du système (français ou anglais). Pour forcer : `SENTINEL_LANG=fr` ou `SENTINEL_LANG=en`. Les
commandes ont aussi un nom anglais (`full`, `audit`, `fix`, `network`, `connection`, `password`, `update`, `repair`,
`monitor`, `name`, `backup`, `restore`).

## Pour les développeurs

### Structure

| Fichier | Rôle |
|---|---|
| `src/main.rs` | menu et sous-commandes |
| `src/ui.rs` | couleurs, titres, cadres, barres |
| `src/machine/mod.rs` | types communs, affichage, exécution parallèle des vérifications |
| `src/machine/linux/`, `src/machine/windows/` | audit propre à chaque système, un fichier par thème |
| `src/machine/dns.rs`, `certificats.rs`, `extensions.rs`, `sante.rs` | vérifications communes aux deux systèmes |
| `src/corriger.rs` | application guidée des correctifs |
| `src/reseau.rs`, `src/scan.rs` | scan réseau (TCP connect, sans root), ARP, carnets des réseaux |
| `src/risk.rs` | base de connaissances des ports et niveaux de risque |
| `src/connexion.rs` | test de connexion pour le jeu |
| `src/antivirus.rs` | ClamAV / Defender, quarantaine |
| `src/surveillance.rs` | minuterie systemd / Planificateur de tâches, notifications |
| `src/rapport.rs`, `src/historique.rs` | rapport HTML, historique des bilans, courbe des notes |
| `src/reparer.rs`, `src/maj.rs`, `src/gaming.rs` | réparations, mises à jour, gaming (Windows) |
| `src/fuites.rs`, `src/donnees.rs` | mots de passe fuités, sauvegarde des données |
| `assets/oui.tsv` | fabricants par préfixe MAC (liste IEEE) |

### Compiler et déployer

Prérequis : `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu` et `mingw-w64-gcc`.

```sh
outils/deployer.sh     # compile Linux (musl, statique) + Windows, installe en local, pousse sur GitHub, met à jour la clé
```

Tests : `cargo test` (Linux) ; tests Windows sous Wine (`cargo test --target x86_64-pc-windows-gnu` avec un lanceur
Wine) ; `cargo clippy --all-targets` sur les deux cibles, en mode strict (pedantic), sans remarque ; `cargo fmt --check`.

### La clé USB

La clé (exFAT, étiquette `SENTINEL`, fichier témoin `sentinel.cle`) contient `Linux/`, `Windows/`, `donnees/` (base des
appareils, portable), `source/` (ce dépôt) et le guide en deux langues (`LISEZMOI.txt`, `README.txt`, tirés de
`outils/`). L'historique des bilans et la quarantaine restent sur chaque ordinateur.

Sur le PC de développement, elle se met à jour toute seule (unités systemd dans `outils/systemd/`) : après chaque
compilation (`sentinel-copie.service`), et à chaque branchement avec la dernière version de GitHub, compilée si elle
est nouvelle (`sentinel-cle.service`, `deployer.sh --branchement`).

La version macOS a été retirée après la v0.9.7 (jamais testée sur un vrai Mac) : `git checkout avec-macos` la retrouve.
