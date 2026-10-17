# netscan

Outil de sécurité en Rust, en français, pour Linux et Windows :

- **Audit de la machine**
  - Linux (Arch, Debian, Ubuntu, Mint, Fedora, openSUSE) : pare-feu et sa politique, ports TCP/UDP exposés,
    ports Docker qui contournent le pare-feu, SSH (y compris lancé par socket), mises à jour (pacman, apt, dnf,
    zypper, Flatpak, Snap, AUR, firmware), redémarrage en attente, chiffrement du volume système, Secure Boot,
    verrouillage de l'écran, durcissement du noyau, AppArmor/SELinux, sauvegardes, setuid et PATH suspects,
    clés SSH (droits, phrase de passe), comptes UID 0, Wi-Fi, services en échec.
  - Windows : pare-feu, Defender, SMBv1, Bureau à distance (jamais coupé depuis une session à distance), UAC,
    BitLocker, Windows Update, compte invité, ports exposés, Wi-Fi.
  - Ce qui ne peut pas être vérifié est dit (« impossible de vérifier »), jamais compté comme sain ; sans pare-feu
    vérifié, pas de note.
- **Corrections** proposées pour chaque problème ; appliquées seulement après confirmation (sudo / UAC). Sous Windows,
  chaque correction est un script `.ps1` lisible, gardé comme trace.
- **Scan du réseau local** : appareils, fabricant (base IEEE intégrée), surnoms, ports ouverts, services reconnus à
  leur bannière, risques ; un carnet par réseau (box + nom du Wi-Fi), nouveaux appareils et ports, appareils absents.
- **Mises à jour** (`netscan maj`, touche `u` du menu) : tout ce qui doit être à jour, vérifié d'un coup puis installé
  après accord.
  - Linux : paquets, Flatpak, Snap, AUR, firmware (fwupd), pilotes DKMS compilés pour chaque noyau installé
    (NVIDIA…), noyau chargé.
  - Windows : Windows Update (correctifs, .NET, Defender) et ses pilotes, redémarrage en attente, signatures de
    Defender, programmes (winget), périphériques sans pilote, âge du pilote de la carte graphique.
    « Tout installer » passe par une seule fenêtre administrateur.
- **Réparer** : réseau, fichiers système (SFC/DISM), disque (SMART, btrfs scrub, Repair-Volume), disque plein,
  mises à jour bloquées (pacman, apt, dnf, zypper, Windows Update), services en échec, heure ; chaque réparation est montrée
  puis confirmée, et celles qui couperaient une connexion à distance en cours sont refusées.
- **Antivirus** : ClamAV (Linux) ou Microsoft Defender (Windows), quarantaine, revue des programmes au démarrage.
- **Surveillance** horaire avec notification si un appareil inconnu rejoint le réseau.
- **Rapport HTML** autonome et daté.

Sans argument, `netscan` ouvre un menu. Sous-commandes : `complet [--html]`, `machine [--json]`, `corriger`,
`reseau [cible] [-p courants|tous|22,80,8000-8100] [--json]`, `antivirus [--complet]`, `surveillance on|off`,
`maj`, `reparer`, `gaming` (Windows), `sauvegarder [fichier]`, `restaurer <fichier>`, `nommer <ip|mac> <surnom>`.

À n'utiliser que sur un réseau qui t'appartient ou que tu as le droit d'auditer.

## Structure

| Fichier | Rôle |
|---|---|
| `src/main.rs` | menu et sous-commandes |
| `src/machine/` | audit local : types communs (`mod.rs`) + `linux.rs`, `windows.rs` |
| `src/corriger.rs` | application guidée des correctifs |
| `src/reseau.rs`, `src/scan.rs` | scan réseau (TCP connect, sans root), ARP, historique |
| `src/risk.rs` | base de connaissances des ports et niveaux de risque |
| `src/antivirus.rs` | ClamAV / Defender, quarantaine, démarrage automatique |
| `src/surveillance.rs` | systemd timer / Planificateur de tâches + notifications |
| `src/rapport.rs` | rapport HTML |
| `assets/oui.tsv` | fabricants par préfixe MAC (liste IEEE) |

## Compilation et clé USB

```sh
outils/deployer.sh     # compile Linux (musl, statique) + Windows, installe en local, met à jour la clé NETSCAN
```

La clé (exFAT, étiquette `NETSCAN`, fichier témoin `netscan.cle`) contient `Linux/`, `Windows/`, `donnees/` (base portable) et `source/`.
Elle est mise à jour automatiquement à chaque compilation et à chaque branchement (unités systemd dans `outils/systemd/`).

Tests : `cargo test` (Linux) ; vérification croisée : `cargo clippy --target x86_64-pc-windows-gnu` ; tests Windows sous Wine.

La version macOS a été retirée après la v0.9.7 (jamais testée sur un vrai Mac) : `git checkout avec-macos` la retrouve.

Prérequis de compilation : `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu` et `mingw-w64-gcc`.
