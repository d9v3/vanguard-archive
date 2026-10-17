SENTINEL — portable security check (machine + network + antivirus + fixes)
==========================================================================
Version française : LISEZMOI.txt

This USB key holds the program for Linux and Windows, its database and its source code.

  Linux/sentinel        Linux (any distribution, nothing to install)
                        Double-click autorun.sh, or in a terminal (outside the key):  <key>/Linux/sentinel
  Windows/sentinel.exe  Windows 10/11: double-click (or "Lancer Sentinel.bat" at the root).
  autorun.sh            Linux: GNOME offers to run it when the key is plugged in; otherwise double-click or ./autorun.sh
  donnees/              Device database (one notebook per network: yours, each friend's) and the latest
                        report (rapport.html, and rapport.md as plain text, readable without a browser). It travels with the key: any Sentinel that sees the key plugged in uses it. On another
                        computer the key is protected: the database is read there, and what is added stays on that computer.
  source/               Full source code (Rust) with its git history.
  sentinel.cle          Marker file that makes the key recognized: do not delete it.

Protection: the key has two parts. SENTINEL (everything above) is read-only on Windows, and on Linux Sentinel
remounts it read-only itself at startup: another computer cannot modify the program. Only its owner's computer
can write to it. SENTINELLOG, small and writable, only holds journal-erreurs.txt: the errors met
(version, system, message), without user name, computer name or home folder, to improve Sentinel. Windows
never starts anything by itself from a USB key (protection against viruses since Windows 7): double-click it.

To start: run Sentinel, choose "1. Full check", then "2. Fix".

Menu
  1  Full check (machine + network), with what changed since the previous check
  2  Fix the problems found (each fix is shown, then confirmed)
  3  Detailed report (browser), with the grade history

  4  This machine ›
       Security audit · Updates (system, programs, drivers, firmware)
       Repair and clean up (Internet, hijacked browsing, firewall, disk full, stuck updates…)
       Diagnostic (hardware, recent crashes and errors, text copy on the key)
       Critical file integrity (accounts, sudo, SSH, startup; live: sentinel integrite --temps-reel)
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
       Essential software (browser, VLC, 7-Zip, LibreOffice, Bitwarden…: new PC or a friend's)
       Gaming (Windows: Visual C++, DirectX…; Linux: Steam, Vulkan, GameMode, MangoHud, Wine, Lutris…)
  8  Data: back up or restore (nicknames, network history)
  q  Quit
  Shortcuts from earlier versions, in the main menu: u updates, r repair, o diagnostic, i integrity,
  n name, c connection, a USB drive, b sandbox, p passwords, e email, l software, g gaming, d data.

The check covers, among others: firewall, open ports, updates, encryption, accounts, programs started at
boot, DNS, added root certificates, browser extensions, disk and battery health.

Language: French or English, following the system. To force English:
  Linux:   SENTINEL_LANG=en ./sentinel
  Windows: in the command prompt, set SENTINEL_LANG=en then sentinel.exe

Good to know
  - Fixes are never applied without your consent. On Windows, each one is first written to a readable
    script (its path is shown) and asks for administrator approval.
  - Before the first fix, update or repair that changes the system, a restore point is created automatically
    (snapper or timeshift on Linux, a restore point on Windows).
  - If you help someone connected remotely (Remote Desktop, SSH), Sentinel never cuts that access.
  - The program is not signed: SmartScreen may warn ("More info" > "Run anyway") and Microsoft Defender may
    flag it, because it scans ports. The source code is on the key.
  - Kept on each computer, never on the key: the check history and the antivirus quarantine (so malware
    never travels on the key).

Sentinel is free software (GNU GPL v3 or later, see LICENSE.txt), provided without warranty.
The libraries it includes are listed in LICENCES-TIERCES.txt.

Use it only on your own network, or one you are allowed to audit.
