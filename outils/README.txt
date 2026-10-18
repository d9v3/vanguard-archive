GARDIEN — portable security check (machine + network + antivirus + fixes)
==========================================================================
Version française : LISEZMOI.txt

This USB key holds the program for Linux, Windows and macOS, its database and its source code.

  Linux/gardien        Linux (any distribution, nothing to install)
                        Double-click autorun.sh, or in a terminal (outside the key):  <key>/Linux/gardien
  Windows/gardien.exe  Windows 10/11: double-click (or "Lancer Gardien.bat" at the root).
  macOS/gardien        macOS 12 and later (Apple Silicon and Intel): double-click "Lancer Gardien.command" at the
                        root (Terminal opens).
  autorun.sh            Linux: GNOME offers to run it when the key is plugged in; otherwise double-click or ./autorun.sh
  donnees/              Device database (one notebook per network: yours, each friend's) and the latest
                        report (rapport.html, and rapport.md as plain text, readable without a browser). It travels with the key: any Gardien that sees the key plugged in uses it. On another
                        computer the key is protected: the database is read there, and what is added stays on that computer.
  source/               Full source code (Rust) with its git history.
  gardien.cle          Marker file that makes the key recognized: do not delete it.

How to run each version, command line included (Terminal, PowerShell, Command Prompt): README.txt in the
Linux, Windows and macOS folders.

Protection: the key has two parts. GARDIEN (everything above) is read-only on Windows, and on Linux and macOS
Gardien remounts it read-only itself at startup: another computer cannot modify the program. Only its owner's computer
can write to it. GARDIENLOG, small and writable, only holds journal-erreurs.txt: the errors met
(version, system, message), without user name, computer name or home folder. Back on the owner's computer, they
become GitHub issues, to improve Gardien. Windows
never starts anything by itself from a USB key (protection against viruses since Windows 7): double-click it.

To start: run Gardien, choose "1. Full check", then "2. Fix".

Menu (↑ ↓ to select, Enter to run, Esc or Backspace to go back; or the number, then Enter)
  1  Full check (machine + network), with what changed since the previous check
  2  Fix the problems found (each fix is shown, then confirmed)
  3  Detailed report (browser), with the grade history

  4  This machine ›
       Security audit · Updates (system, programs, drivers, firmware)
       Repair and clean up (Internet, hijacked browsing, firewall, disk full, stuck updates…)
       Diagnostic (hardware, recent crashes and errors, text copy on the key)
       Critical file integrity (accounts, sudo, SSH, startup; live: gardien integrite --temps-reel)
  5  Network and Internet ›
       Scan the network · Deep scan of one device · Name a device ("HP printer")
       Hourly monitoring (unknown device, problem on this machine, router impersonation)
       Connection test for gaming (ping, jitter, speed, bufferbloat)
  6  Antivirus and protection ›
       Quick scan · Full scan of the home folder
       USB drive or folder, with USB worm traps (fake shortcuts, autorun)
       Sandbox: run an unknown program with no network, away from your files
       Passwords: have they leaked? (only 5 characters of their fingerprint are sent)
       Email address: has it leaked? (sent to the search service, after your consent)
  7  Install and play ›
       Software: the best ones, mostly open source, by category (browsers, passwords, office, video,
       design, system tools…) plus a starter pack, from the official source
       Gaming (Windows: Visual C++, DirectX…; Linux: Steam, Vulkan, GameMode, MangoHud, Wine, Lutris…;
       macOS: Rosetta 2, Steam, Heroic, Epic, GOG, Prism, Metal counter)
  8  Optimize ›
       Clean up the system (caches, temporary files, packages, trash…: the space of each, to check)
       Recommended settings, in one go · Privacy (telemetry, ads, tracking, Recall…)
       Performance and reliability (fast startup, SSD…) · Comfort and files (file extensions shown,
       no autorun from USB drives, full right-click menu…) · Put everything back
       Each setting shows its state and is undone exactly: the previous value is put back.
  9  Data: back up or restore (nicknames, network history)
  q  Quit
  Shortcuts from earlier versions, in the main menu: u updates, r repair, o diagnostic, i integrity,
  n name, c connection, a USB drive, b sandbox, p passwords, e email, l software, g gaming, d data.

The check covers, among others: firewall, open ports, updates, encryption, accounts, programs started at
boot, DNS, added root certificates, browser extensions, disk and battery health.

Language: French or English, following the system. To force English:
  Linux:   GARDIEN_LANG=en ./gardien
  Windows: in the command prompt, set GARDIEN_LANG=en then gardien.exe
  macOS:   GARDIEN_LANG=en <key>/macOS/gardien

Good to know
  - Fixes are never applied without your consent. On Windows, each one is first written to a readable
    script (its path is shown) and asks for administrator approval.
  - Before the first fix, update or repair that changes the system, a restore point is created automatically
    (snapper or timeshift on Linux, a restore point on Windows, a local Time Machine snapshot on macOS).
  - If you help someone connected remotely (Remote Desktop, SSH), Gardien never cuts that access.
  - The program is not signed: SmartScreen may warn ("More info" > "Run anyway") and Microsoft Defender may
    flag it, because it scans ports. The source code is on the key.
  - macOS: run from the key, Gardien opens without a warning. Copied from the Internet or AirDrop, macOS blocks it
    ("unidentified developer"): right-click > Open, or System Settings > Privacy & Security > "Open Anyway".
    Antivirus, software and gaming go through Homebrew (offered if missing).
  - Kept on each computer, never on the key: the check history and the antivirus quarantine (so malware
    never travels on the key).

Gardien is free software (GNU GPL v3 or later, see LICENSE.txt), provided without warranty.
The libraries it includes are listed in LICENCES-TIERCES.txt.

Use it only on your own network, or one you are allowed to audit.
