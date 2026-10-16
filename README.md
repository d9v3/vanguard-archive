# netscan

Outil de sécurité en Rust, en français, pour Linux, Windows et macOS :

- **Audit de la machine** : pare-feu, services exposés, mises à jour, chiffrement du disque, SSH, comptes, Wi-Fi…
  (Defender, SMBv1, RDP, UAC, BitLocker sous Windows ; FileVault, Gatekeeper, SIP sous macOS).
- **Corrections** proposées pour chaque problème ; appliquées seulement après confirmation (sudo / UAC).
- **Scan du réseau local** : appareils, fabricant (base IEEE intégrée), ports ouverts, risques, et détection
  des nouveaux appareils ou ports depuis les scans précédents.
- **Antivirus** : ClamAV (Linux/macOS) ou Microsoft Defender (Windows), quarantaine, revue des programmes au démarrage.
- **Surveillance** horaire avec notification si un appareil inconnu rejoint le réseau.
- **Rapport HTML** autonome.

Sans argument, `netscan` ouvre un menu. Sous-commandes : `complet [--html]`, `machine [--json]`, `corriger`,
`reseau [cible] [-p courants|tous|22,80,8000-8100] [--json]`, `antivirus [--complet]`, `surveillance on|off`.

À n'utiliser que sur un réseau qui t'appartient ou que tu as le droit d'auditer.

## Structure

| Fichier | Rôle |
|---|---|
| `src/main.rs` | menu et sous-commandes |
| `src/machine/` | audit local : types communs (`mod.rs`) + `linux.rs`, `windows.rs`, `macos.rs` |
| `src/corriger.rs` | application guidée des correctifs |
| `src/reseau.rs`, `src/scan.rs` | scan réseau (TCP connect, sans root), ARP, historique |
| `src/risk.rs` | base de connaissances des ports et niveaux de risque |
| `src/antivirus.rs` | ClamAV / Defender, quarantaine, démarrage automatique |
| `src/surveillance.rs` | systemd timer / LaunchAgent / Planificateur de tâches + notifications |
| `src/rapport.rs` | rapport HTML |
| `assets/oui.tsv` | fabricants par préfixe MAC (liste IEEE) |

## Compilation et clé USB

```sh
outils/deployer.sh     # compile Linux (musl, statique) + Windows, installe en local, met à jour la clé NETSCAN
```

La clé (exFAT, étiquette `NETSCAN`, fichier témoin `netscan.cle`) contient `Linux/`, `Windows/`, `macOS/`
(compilé sur le Mac au premier lancement), `donnees/` (base portable) et `source/`.
Elle est mise à jour automatiquement à chaque compilation et à chaque branchement (unités systemd dans `outils/systemd/`).

Prérequis de compilation : `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu` et `mingw-w64-gcc`.
