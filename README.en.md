<p align="center">
  <img src="assets/icones/gardien-256.png" alt="Gardien logo: a shield open on a black hole" width="150">
</p>

<h1 align="center">Gardien</h1>

<p align="center"><a href="README.md">Français</a> · <b>English</b></p>

<p align="center">
  <b>Secures and optimizes your computer and your network, from a USB key.</b><br>
  Gardien (French for “guardian”) checks your machine and every device on your network, explains each problem in
  plain language,<br>and fixes it once you agree. Linux, Windows and macOS, nothing to install, in English or French.
</p>

![Gardien's security check: a grade from A to F, each problem explained with its fix](assets/captures/bilan-en.png)

## At a glance

- **A security check graded from A to F**: firewall, updates, encryption, open ports, backups… Each problem is
  explained simply, with its fix.
- **Your whole network**: every device, its manufacturer, its open ports and its risks; newcomers are flagged.
- **Nothing changes without your consent**: a restore point first, and every setting is undone exactly.
- **One USB key for all your computers**, and your friends': it write-protects itself anywhere but at home.

## Getting started

**Download** (latest version): [Windows](../../releases/latest/download/gardien-windows-x86_64.exe) ·
[Linux](../../releases/latest/download/gardien-linux-x86_64) · [macOS](../../releases/latest/download/gardien-macos)
— or the whole [releases page](../../releases/latest), with the SHA-256 checksums.

- **Windows**: double-click the program. It is not signed: SmartScreen may warn (“More info”, then “Run anyway”).
- **Linux**: `chmod +x gardien-linux-x86_64`, then `./gardien-linux-x86_64` in a terminal (any distribution, nothing
  to install).
- **macOS**: copied from the Internet, the program is blocked the first time: `xattr -d com.apple.quarantine
  gardien-macos`, then `./gardien-macos` in Terminal.
- **From the USB key**: `Windows/gardien.exe`, `Linux/gardien`, or `Lancer Gardien.command` on macOS; the key's guide
  is in `README.txt`.

In the menu, choose **1** (full check), then **2** (fix). Arrows, Enter, and Esc or Backspace to go back.

> Gardien was called Sentinel up to version 0.50: the `sentinel` command still starts Gardien, and its data,
> monitoring and key are carried over as they are.

## In pictures

<table>
  <tr>
    <td width="50%"><img src="assets/captures/menu-en.png" alt="Gardien's menu"><br><sub>The menu: last check,
    connection, key plugged in.</sub></td>
    <td width="50%"><img src="assets/captures/rapport-en.png" alt="Gardien's HTML report"><br><sub>The HTML report and
    the grade history.</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="assets/captures/reseau-en.png" alt="Local network scan"><br><sub>The network: every
    device, its ports and what deserves a look.</sub></td>
    <td width="50%"><img src="assets/captures/connexion-en.png" alt="Connection test for gaming"><br><sub>The
    connection for gaming: ping, jitter, speed, bufferbloat.</sub></td>
  </tr>
</table>

<sub>Screenshots retaken at each version, on a copy of the data; the home's addresses and names are masked.</sub>

## Supported systems

| System | Versions |
|---|---|
| Windows | 10 and 11 |
| macOS | 12 and later, Apple Silicon and Intel (tested on GitHub's Macs, not yet on a real Mac) |
| Linux | Arch and derivatives (Omarchy, Manjaro, EndeavourOS, CachyOS), Debian, Ubuntu, Mint, Pop!_OS, Fedora (and RHEL, Rocky, Nobara), openSUSE |
| Atomic Linux | Bazzite, Silverblue, Kinoite, Bluefin, Aeon |

Gardien recognizes the distribution and offers its own commands: `omarchy update` / `omarchy pkg add` on Omarchy,
`ujust update` on Bazzite, `rpm-ostree` or `transactional-update` on an atomic system, otherwise pacman, apt, dnf or
zypper.

## What Gardien does

**Security check** — a grade from A to F, then each problem with its fix.
- Firewall, open ports (TCP and UDP), updates and known vulnerabilities, disk encryption, Secure Boot, screen lock,
  accounts, SSH, sudo, kernel hardening (on macOS: sealed system volume, enforced code signing, library
  validation, added extensions), badly protected secret files, backups.
- What hides: programs started at boot, scheduled tasks, library preloading, modified privileged programs.
- The DNS actually used (and forged answers), added root certificates (HTTPS interception), browser extensions that
  read every site.
- Health: disk space, SMART status of the disks (without root), battery, temperatures.
- What could not be checked is said so, never counted as healthy.

**Local network** — every device, its manufacturer, its open ports (TCP, and UDP: SNMP, NetBIOS, UPnP, DNS, mDNS)
and its risks; newcomers flagged, one notebook per network (at home, at each friend's), nicknames ("HP printer");
the ports that devices opened to the Internet on the router through UPnP (read-only, with miniupnpc on Linux).

**Connection for gaming** — ping, jitter, loss, speed and bufferbloat (the lag when someone downloads), with a
verdict criterion by criterion and advice.

**Computer diagnostic** — the first step of any troubleshooting: hardware, system, and recent problems (journal
errors and crashed programs on Linux; blue screens, sudden shutdowns and crashes on Windows; kernel panics and crash
reports on macOS), with a text copy saved on the key.

**Optimize** — privacy, performance and comfort settings written for Gardien. On Windows: telemetry kept to a
minimum, ads and tracking off, Recall without screen snapshots, file extensions shown, no autorun from USB drives,
fast startup, full right-click menu. On Linux: SSD maintenance, journal size, reports sent by GNOME or Ubuntu. On
macOS: ads, analytics, no .DS_Store on drives. Each setting shows its state and is undone exactly: the previous value
is recorded, then put back. None of them weakens security.

**Clean up the system** — a checklist of what takes space for nothing: downloaded and unneeded packages, old Snap
versions, unused Flatpak runtimes, AUR builds, old caches, thumbnails, old logs, crash reports (Linux); temporary
files, Windows Update and Delivery Optimization caches, old components (Windows); old caches, Homebrew, Xcode, local
snapshots (macOS). The space each item frees is measured first, what rebuilds itself is checked by default, the trash
never; the free space read again afterwards tells what was really gained.

**And also**
- Fixes applied only after confirmation, with a restore point created automatically beforehand (snapper or
  timeshift on Linux, Windows restore point, Time Machine snapshot on macOS); on Windows, each one is a readable
  script.
- Update everything at once: system, programs, drivers, firmware.
- Software: the best program for each use, mostly open source, in 8 categories (browsers and email, messaging and
  sharing, security and privacy, office, video and music, images and design, system tools, programming) plus a
  starter pack (Firefox, Bitwarden, VLC, LibreOffice, 7-Zip): checklist, installed ones recognized, installation from
  the official source that checks each download (winget, distribution packages or Flathub, Homebrew).
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
  macOS, Rosetta 2, Steam, Heroic, Epic Games, GOG Galaxy, Prism Launcher and the Metal frame counter.

Gardien never cuts a remote connection in use (Remote Desktop, SSH). Only use it on your own network, or a network
you are allowed to audit.

## Commands

Each menu entry is also a command:

| Command | Purpose |
|---|---|
| `gardien full [--html] [--text]` | full check: machine + network; `--text` shows it as plain text (emergency mode) |
| `gardien fix` | fix the problems found |
| `gardien audit [--json]` | audit of this machine |
| `gardien network [target] [-p common\|all\|22,80,8000-8100] [--json]` | scan the network or one device |
| `gardien connection` | connection test for gaming |
| `gardien clean [--list]` | clean up the system; `--list`: the space to gain, deleting nothing |
| `gardien apps [--list] [--recommended]` | software to install by category; `--list`: their state, installing nothing |
| `gardien diag` | computer diagnostic: hardware, system, recent crashes and errors |
| `gardien antivirus [--complet] [folder]` | antivirus scan (computer, or a key / a folder) |
| `gardien password` | leaked passwords |
| `gardien sandbox <file>` | run an unknown program in a sandbox (bubblewrap or firejail, Windows Sandbox) |
| `gardien email` | email address leaks (XposedOrNot, or Have I Been Pwned with `GARDIEN_HIBP_CLE`) |
| `gardien integrity [--accept] [--live]` | integrity of critical files (BLAKE3 fingerprints), live if wanted |
| `gardien update` | updates |
| `gardien repair` | repairs and cleaning |
| `gardien monitor on\|off` | hourly monitoring |
| `gardien name <ip\|mac> <nickname>` | name a device |
| `gardien backup [file]`, `gardien restore <file>` | data backup |
| `gardien gaming` | packages and settings for gaming (Windows and Linux) |

**Language**: the system's (English or French). To force it: `GARDIEN_LANG=en` or `GARDIEN_LANG=fr`. The commands
also keep their French names (`complet`, `machine`, `corriger`, `reseau`, `connexion`, `logiciels`, `diagnostic`,
`motdepasse`, `isoler`, `courriel`, `integrite`, `maj`, `reparer`, `surveillance`, `nommer`, `sauvegarder`,
`restaurer`, `nettoyer`).

## Development

Building, testing, deploying, the USB key, the error journal: see [CONTRIBUTING.en.md](CONTRIBUTING.en.md).
A security flaw in Gardien? Report it privately: see [SECURITY.md](SECURITY.md#security).

## License

© 2026 d9v3. Gardien is free software: you can redistribute it and modify it under the terms of the
[GNU General Public License](LICENSE) (GPL), version 3 or any later version. It comes with no warranty. A modified
version you distribute must stay under this license, with its source code.

The included libraries keep their own licenses (MIT, Apache-2.0, BSD, ISC…): see `LICENCES-TIERCES.txt`.
