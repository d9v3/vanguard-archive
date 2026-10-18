<img src="assets/icones/sentinel-256.png" alt="Sentinel logo: a black hole" width="128" align="right">

# Sentinel

[Français](README.md) · **English**

**Secures and optimizes your computer and your network, from a USB key.**
Sentinel checks your machine and every device on your network, explains each problem in plain language, and fixes
it once you agree. Linux, Windows and macOS, nothing to install, in French or English.

**Supported systems** — Windows 10 and 11; macOS 12 and later (Apple Silicon and Intel, not yet tried on a real Mac
outside the automated tests); Linux: Arch and derivatives (Omarchy, Manjaro, EndeavourOS, CachyOS), Debian, Ubuntu,
Mint, Pop!_OS, Fedora (and RHEL, Rocky, Nobara), openSUSE, as well as atomic systems (Bazzite, Silverblue, Kinoite,
Bluefin, Aeon). Sentinel recognizes the distribution and offers its own commands: `omarchy update` /
`omarchy pkg add` on Omarchy, `ujust update` on Bazzite, `rpm-ostree` or `transactional-update` on an atomic system,
otherwise pacman, apt, dnf or zypper.

![Sentinel menu](assets/captures/menu.png)

## What Sentinel does

**Security check** — a grade from A to F, then each problem with its fix.
- Firewall, open ports (TCP and UDP), updates and known vulnerabilities, disk encryption, Secure Boot, screen lock,
  accounts, SSH, sudo, kernel hardening, backups.
- What hides: programs started at boot, scheduled tasks, library preloading, modified privileged programs.
- The DNS actually used (and forged answers), added root certificates (HTTPS interception), browser extensions that
  read every site.
- Health: disk space, SMART status of the disks (without root), battery, temperatures.
- What could not be checked is said so, never counted as healthy.

**Local network** — every device, its manufacturer, its open ports (TCP, and UDP: SNMP, NetBIOS, UPnP, DNS, mDNS)
and its risks; newcomers flagged, one notebook per network (at home, at each friend's), nicknames ("HP printer");
the ports that devices opened to the Internet on the router through UPnP (read-only, with miniupnpc on Linux).

![Local network scan](assets/captures/reseau.png)

**Connection for gaming** — ping, jitter, loss, speed and bufferbloat (the lag when someone downloads), with a
verdict criterion by criterion and advice.

![Connection test](assets/captures/connexion.png)

**Computer diagnostic** — the first step of any troubleshooting: hardware, system, and recent problems (journal
errors and crashed programs on Linux; blue screens, sudden shutdowns and crashes on Windows; kernel panics and crash
reports on macOS), with a text copy saved on the key.

**Optimize** — privacy, performance and comfort settings written for Sentinel. On Windows: telemetry kept to a
minimum, ads and tracking off, Recall without screen snapshots, file extensions shown, no autorun from USB drives,
fast startup, full right-click menu. On Linux: SSD maintenance, journal size, reports sent by GNOME or Ubuntu. On
macOS: ads, analytics, no .DS_Store on drives. Each setting shows its state and is undone exactly: the previous value
is recorded, then put back. None of them weakens security.

**And also**
- Fixes applied only after confirmation, with a restore point created automatically beforehand (snapper or
  timeshift on Linux, Windows restore point, Time Machine snapshot on macOS); on Windows, each one is a readable
  script.
- Update everything at once: system, programs, drivers, firmware.
- Essential software for a new PC or a friend's (browsers, VLC, 7-Zip, LibreOffice, Bitwarden, Thunderbird, Discord,
  OBS, GIMP, Notepad++, PowerToys): winget, distribution packages, Flatpak or Homebrew.
- Repairs: Internet, hijacked browsing, firewall, disk, full disk, deep cleaning, stuck Windows Update, system files,
  clock.
- Antivirus: ClamAV (Linux, macOS) or Microsoft Defender (Windows), on the computer or on a chosen USB key / folder,
  with the tricks of USB worms (shortcut posing as a folder, autorun.inf, scripts).
- Sandbox: run an unknown program without network, with a read-only system and an invisible home folder (bubblewrap
  or firejail on Linux, Windows Sandbox on Windows, sandbox-exec on macOS).
- Integrity of critical files (accounts, sudo, SSH, PAM, cron, services, autostart): BLAKE3 fingerprints, what changed
  since the reference, and live monitoring.
- Leaked passwords: checked with Have I Been Pwned without ever sending the password (only 5 characters of its hash);
  email address leaks, after your consent (the address is sent to the service).
- Hourly monitoring: a notification if an unknown device shows up, if a port opens, if the machine's grade drops, or
  if the router seems spoofed (shared or changed MAC address: ARP spoofing).
- HTML report with the grade history curve, and what changed since the previous check.
- Gaming: on Windows, game components and Windows settings; on Linux, Steam, 32- and 64-bit Vulkan drivers for your
  graphics card, GameMode, MangoHud, Gamescope, Wine, Lutris, Heroic, ProtonUp-Qt, vm.max_map_count, ntsync; on
  macOS, Steam and Heroic.

Sentinel never cuts a remote connection in use (Remote Desktop, SSH). Only use it on your own network, or a network
you are allowed to audit.

## Getting started

- **From the key**: `Linux/sentinel` (in a terminal: `./sentinel`), `Windows/sentinel.exe` (double-click) or
  `Lancer Sentinel.command` on macOS (double-click, Terminal opens).
  The key's guide is in `README.txt` (English) and `LISEZMOI.txt` (French).
- **Installed**: running `sentinel` opens the menu. Choose **1** (full check), then **2** (fix).

Each menu entry is also a command:

| Command | Purpose |
|---|---|
| `sentinel full [--html] [--text]` | full check: machine + network; `--text` shows it as plain text (emergency mode) |
| `sentinel fix` | fix the problems found |
| `sentinel audit [--json]` | audit of this machine |
| `sentinel network [target] [-p common\|all\|22,80,8000-8100] [--json]` | scan the network or one device |
| `sentinel connection` | connection test for gaming |
| `sentinel apps` | essential software to install (winget, distribution packages or Flatpak) |
| `sentinel diag` | computer diagnostic: hardware, system, recent crashes and errors |
| `sentinel antivirus [--complet] [folder]` | antivirus scan (computer, or a key / a folder) |
| `sentinel password` | leaked passwords |
| `sentinel sandbox <file>` | run an unknown program in a sandbox (bubblewrap or firejail, Windows Sandbox) |
| `sentinel email` | email address leaks (XposedOrNot, or Have I Been Pwned with `SENTINEL_HIBP_CLE`) |
| `sentinel integrity [--accept] [--live]` | integrity of critical files (BLAKE3 fingerprints), live if wanted |
| `sentinel update` | updates |
| `sentinel repair` | repairs and cleaning |
| `sentinel monitor on\|off` | hourly monitoring |
| `sentinel name <ip\|mac> <nickname>` | name a device |
| `sentinel backup [file]`, `sentinel restore <file>` | data backup |
| `sentinel gaming` | packages and settings for gaming (Windows and Linux) |

**Language**: the system's (French or English). To force it: `SENTINEL_LANG=en` or `SENTINEL_LANG=fr`. The commands
also keep their French names (`complet`, `machine`, `corriger`, `reseau`, `connexion`, `logiciels`, `diagnostic`,
`motdepasse`, `isoler`, `courriel`, `integrite`, `maj`, `reparer`, `surveillance`, `nommer`, `sauvegarder`,
`restaurer`).

## For developers

The code, its comments and its internal names are in French; every text shown to the user exists in both languages
(`tr!("fr", "en")` in `src/langue.rs`).

### Layout

| File | Purpose |
|---|---|
| `src/main.rs` | menu and subcommands |
| `src/ui.rs` | colors, titles, frames, bars |
| `src/selection.rs` | keyboard menus and checklists (arrows, Enter, Esc) |
| `src/langue.rs` | language choice and translation macros |
| `src/machine/mod.rs` | shared types, display, parallel execution of the checks |
| `src/machine/linux/`, `src/machine/windows/`, `src/machine/macos/` | per-system audit, one file per topic |
| `src/machine/dns.rs`, `certificats.rs`, `extensions.rs`, `sante.rs` | checks shared by the three systems |
| `src/corriger.rs` | guided application of fixes |
| `src/reseau.rs`, `src/scan.rs` | network scan (TCP connect, without root), ARP, network notebooks |
| `src/risk.rs` | knowledge base of ports and risk levels |
| `src/connexion.rs` | connection test for gaming |
| `src/antivirus.rs` | ClamAV / Defender, quarantine |
| `src/surveillance.rs` | systemd timer / Task Scheduler / launchd agent, notifications |
| `src/rapport.rs`, `src/historique.rs` | HTML report, check history, grade curve |
| `src/reparer.rs`, `src/maj.rs`, `src/gaming/` | repairs, updates, gaming |
| `src/optimiser/` | privacy, performance and comfort settings, with exact undo |
| `src/fuites.rs`, `src/donnees.rs` | leaked passwords, data backup |
| `assets/oui.tsv` | manufacturers by MAC prefix (IEEE list) |
| `LICENCES-TIERCES.txt` | license notices of the included libraries (`outils/licences-tierces.py`) |

### Build and deploy

Requirements: `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu` and `mingw-w64-gcc`.

```sh
outils/deployer.sh     # builds Linux (musl, static) + Windows, installs locally, pushes to GitHub, updates the key
```

Tests: `cargo test` (Linux); Windows tests under Wine (`cargo test --target x86_64-pc-windows-gnu` with a Wine
runner); `cargo clippy --all-targets` on the four targets (Linux, Windows, `aarch64-apple-darwin`,
`x86_64-apple-darwin`), in strict mode (pedantic), without any warning; `cargo fmt --check`.

macOS: built and tested on a GitHub Mac (`.github/workflows/macos.yml`, universal Apple Silicon + Intel binary),
every night if the code changed or on demand (`gh workflow run macos.yml`). `deployer.sh` fetches the latest
successful build for the key.

### The USB key

The key (exFAT, label `SENTINEL`, marker file `sentinel.cle`) holds `Linux/`, `Windows/`, `macOS/`, `donnees/`
(device database, portable), `source/` (this repository) and the guide in two languages (`README.txt`,
`LISEZMOI.txt`, taken from `outils/`). The check history and the quarantine stay on each computer.

On the development PC, it updates itself (systemd units in `outils/systemd/`): after each build
(`sentinel-copie.service`), and each time it is plugged in, with the latest version from GitHub, built if it is new
(`sentinel-cle.service`, `deployer.sh --branchement`).

The key has two partitions: `SENTINEL`, read-only everywhere except on its owner's computer (GPT attribute honored
by Windows; on Linux and macOS, Sentinel remounts it read-only itself), and `SENTINELLOG`, which only receives the
error log, anonymized. `outils/preparer-cle.sh` prepares a new key.

Errors and crashes: Sentinel records them with nothing personal (on the key, or in its folder when the key is not
plugged in). On deployment, `deployer.sh` brings them back and `outils/journal-vers-github.py` turns them into GitHub
issues (label “journal”) with `gh`: one issue per error, repeats as comments. No GitHub password in the program or on
the key.

## License

© 2026 d9v3. Sentinel is free software: you can redistribute it and modify it under the terms of the
[GNU General Public License](LICENSE) (GPL), version 3 or any later version. It comes with no warranty. A modified
version you distribute must stay under this license, with its source code.

The included libraries keep their own licenses (MIT, Apache-2.0, BSD, ISC…): see `LICENCES-TIERCES.txt`.
