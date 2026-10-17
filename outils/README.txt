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
  3  Audit this machine              4  Scan the local network     5  Deep scan of one device
  6  Antivirus: quick scan           7  Antivirus: full scan of the home folder
  8  Detailed report (browser), with the grade history
  9  Hourly monitoring: notification when an unknown device shows up, a problem appears on this machine,
     or someone seems to impersonate the router (ARP spoofing)
  o  Computer diagnostic: hardware, system, recent crashes and errors (text copy on the key)
  l  Essential software: browser, VLC, 7-Zip, LibreOffice, Bitwarden… (for a new PC or a friend's)
  u  Updates: system, programs, drivers, firmware
  r  Repair: Internet, hijacked browsing, firewall, antivirus, disk, disk full,
     deep cleanup, stuck updates, system files, time
  g  Gaming: packages and settings for gaming (Windows: Visual C++, DirectX…; Linux: Steam, Vulkan drivers,
     GameMode, MangoHud, Gamescope, Wine, Lutris, Heroic, ntsync…)
  c  Connection test for gaming: ping, jitter, speed, bufferbloat
  p  Passwords: have they leaked? (only 5 characters of their fingerprint are sent)
  e  Email address: has it leaked? (the address is sent to the search service, after your consent)
  b  Sandbox: run an unknown program with no network, away from your files
  i  Critical file integrity (accounts, sudo, SSH, startup…): what changed since the reference;
     live with "sentinel integrite --temps-reel"
  n  Name a device ("HP printer")
  d  Data: back up or restore (nicknames, network history)
  q  Quit

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

Use it only on your own network, or one you are allowed to audit.
