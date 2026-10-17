SENTINEL — portable security check (machine + network + antivirus + fixes)
==========================================================================
Version française : LISEZMOI.txt

This USB key holds the program for Linux and Windows, its database and its source code.

  Linux/sentinel        Linux (any distribution, nothing to install)
                        Open a terminal in this folder, then:  ./sentinel
  Windows/sentinel.exe  Windows 10/11: double-click.
  donnees/              Device database (one notebook per network: yours, each friend's) and the latest
                        HTML report. It travels with the key: any Sentinel that sees the key plugged in uses it.
  source/               Full source code (Rust) with its git history.
  sentinel.cle          Marker file that makes the key recognized: do not delete it.

To start: run Sentinel, choose "1. Full check", then "2. Fix".

Menu
  1  Full check (machine + network), with what changed since the previous check
  2  Fix the problems found (each fix is shown, then confirmed)
  3  Audit this machine              4  Scan the local network     5  Deep scan of one device
  6  Antivirus: quick scan           7  Antivirus: full scan of the home folder
  8  Detailed report (browser), with the grade history
  9  Hourly network monitoring (notification when an unknown device shows up)
  u  Updates: system, programs, drivers, firmware
  r  Repair: Internet, hijacked browsing, firewall, antivirus, disk, disk full,
     deep cleanup, stuck updates, system files, time
  g  Gaming (Windows): components for games and Windows settings
  c  Connection test for gaming: ping, jitter, speed, bufferbloat
  p  Passwords: have they leaked? (only 5 characters of their fingerprint are sent)
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
  - If you help someone connected remotely (Remote Desktop, SSH), Sentinel never cuts that access.
  - The program is not signed: SmartScreen may warn ("More info" > "Run anyway") and Microsoft Defender may
    flag it, because it scans ports. The source code is on the key.
  - Kept on each computer, never on the key: the check history and the antivirus quarantine (so malware
    never travels on the key).

Use it only on your own network, or one you are allowed to audit.
