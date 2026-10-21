# Version history

*[Français](CHANGELOG.md)*

What each day brought to Vanguard, most recent first. Since October 19, 2026, Vanguard has a single release a day,
gathering the day's work. Only the latest version has its download page; every version keeps its tag in the
repository (`git checkout v0.62.0`, for example), to be rebuilt if needed.

## October 21, 2026, evening: version 0.84

- **Threat blocking, in one click.** Each threat found offers "Block": the action is shown, carried out after your
  consent, written down in "What Vanguard changed" and undone exactly by `vanguard blocking undo` (only stopping a
  program cannot be undone). Depending on the threat: the program stopped then quarantined, the connection closed at
  the firewall (ufw, nftables, Windows Firewall, pf), a launch removed from startup, Windows' vulnerable driver
  blocklist turned on (effective after a restart), an AI server's port closed to the network, an AI agent set back to
  asking before it acts. Antivirus and protection › Threat blocking menu, or `vanguard blocking`.
- **Active protection, which blocks what is certain.** Accepted once, it blocks by itself what leaves no doubt, then
  lets you know: a file whose fingerprint is in MalwareBazaar, a known attack tool running, a connection to a known
  command server (Feodo Tracker, ThreatFox). What is doubtful stays an alert with its button. It runs during the check
  and in the hourly monitoring. Four categories (programs, connections, startup and drivers, AI agents), each off, one
  click, or automatic for programs and connections. As administrator, it blocks nothing by itself: its settings can be
  written by any program of the account, and what is certain is offered with one click there.
- **Never a block that would do more harm than the threat**: not Vanguard, not a system program or a critical process,
  not a remote session in progress (SSH, Remote Desktop, RustDesk, AnyDesk, Tailscale…), not a local address or a
  public DNS; an interpreter (python3, PowerShell) is never quarantined, at most the script it runs. Without the
  rights needed, nothing is done halfway.
- **Settings, all in one place** (This machine › Settings, "s" in the main menu, or `vanguard settings`): language,
  emojis, working without the Internet, hourly monitoring, monthly check-up, learned alerts, blocking and extension
  restrictions. Each change shows the previous value and the command to put it back; language, emojis and working
  without the Internet stay chosen from one launch to the next (VANGUARD_LANG, VANGUARD_EMOJI and VANGUARD_HORS_LIGNE
  always win).
- **Extensions: your own programs in Vanguard, without touching its code** (menu 12 Extensions,
  `vanguard extensions`). A plugin is a folder with a `plugin.toml` manifest, added once from a folder or a .zip
  archive (`vanguard plugin add`); a lab script is a file dropped as it is (`vanguard lab`), to try an idea quickly.
  Their findings are shown apart, never count in the grade, and go into a separate section of the HTML report with
  `--report`. To write a plugin in Rust: the `extensions/sdk` library, with no dependency, and a complete example.
- **An extension is checked before it runs.** Before your consent, its whole folder or archive is scanned (YARA,
  MalwareBazaar fingerprints) and every file hashed (SHA-256): a file changed, added or removed, and it must be
  approved again. The checked copy is what runs, without access to the terminal, with a bounded time and output, and
  everything it started is stopped at the end; an archive cannot write anything outside its folder. On Linux,
  `--isolated` runs it without network, the home folder hidden. A manifest can only ask for full trust or to run with
  the check or the monitoring: it is granted by a separate question, and the consent falls at the slightest change. As
  administrator, nothing in the extensions folder lifts a safeguard: nothing there runs by itself, and each run is
  asked for. The **Restrictions** switch (Extensions › 3, Settings, or for a single plugin or script) turns these
  safeguards off for what is yours; one thing stays: the extensions folder must be yours, closed to other accounts.
- **YARA-X 1.22.0**, which fixes eight known flaws in wasmtime, the library YARA runs on, one of them on Apple silicon
  Macs. Every library used is now checked at each version and every night (cargo deny): known flaws, licenses
  compatible with the GPL, origin (crates.io only). The two remaining advisories, with no published fix, come from
  YARA-X and do not apply to the way Vanguard uses it (the reason is written down).
- **Calculations checked in the released version** (ANSSI guide, LANG-ARITH): a number that overflows on hostile data
  (a size read in a network packet, a log, a Windows program) stops the check concerned instead of silently wrapping
  to zero and skewing what follows; the rest of the check goes on.
- **Security review.** An attack tool is certain only by the name of the program itself: an argument that looks like
  it (python3 sharphound_parser.py) is only a doubt. The program is checked again at the very moment it is stopped
  (its number could have passed to another one). The ufw rule that closes a port goes before the allow rules, and the
  port is reported closed only once checked. In automatic mode, an address where another account has an established
  connection is never blocked. An unreadable settings file (settings, blocking, extensions) is set aside as it is,
  never silently overwritten.

## October 21, 2026, evening: version 0.83

- **Live threat hunting.** A successful sign-in from an address that had just failed at least ten passwords: a guessed
  password, reported as critical (sshd's log on Linux; on Windows, as administrator, the security log for Remote
  Desktop and shares, and OpenSSH's log; macOS: not checked). A bounded or overlong read is reported as partial, never
  as safe without a caveat. Suspicious running programs: known offensive tool (Mimikatz, Rubeus, SharpHound, LaZagne,
  XMRig…), command line that downloads or hides what it runs, program started from Downloads, a temporary folder or
  the recycle bin; of the line, only the program and the pattern are shown, never a secret written around them.
- **Incident timeline** in `vanguard evidence` (CHRONOLOGIE.txt): what the collection read with a date, put back in
  time order over the last 7 days, with the MITRE ATT&CK technique when it is obvious: accepted or refused sign-ins,
  sudo, created accounts, added services and tasks, cleared logs, Defender detections, recent files that matter. A log
  that does not go back the whole week says why.
- **Windows' hidden doors and kernel drivers**: the DLLs Windows loads by itself (LSA packages, AppCertDlls, print
  monitors, time providers, Winsock catalog); drivers stored where nothing installed puts one, or known to be
  vulnerable (the LOLDrivers list, once a week). Read-only, without PowerShell.
- **Program memory** (`vanguard memory`, on demand): the 308 YARA rules applied to the memory of running programs,
  where "fileless" malware lives, on Linux and Windows (macOS: not checked). The memory of LSASS and protected
  processes is never read, nothing read is kept, and what could not be read is said.
- **AI agents**: a local AI server (Ollama, LM Studio, ComfyUI) open to the network without a password; an agent set
  to do everything without asking, an MCP server started without a pinned version, reached without encryption or with
  a key written in clear text, in the settings of Claude Code, Claude Desktop, Cursor, VS Code, Windsurf and Gemini
  CLI (the key's name only, never its value).
- **Windows fixes without PowerShell**: fourteen hardening settings from a closed list (WDigest, Remote Desktop NLA,
  NTLMv2 only, LLMNR, WPAD, UAC…) applied by Vanguard itself, relaunched as administrator: Windows' prompt names
  Vanguard, the restore point comes first and the previous value is recorded to undo exactly; only Enter or yes
  applies. Mixed with a fix outside the list, they go through the script, as before.
- **Check my backup**: a copy rewritten after the backup (newer than its original, and different), as by ransomware
  encrypting the backup disk, is reported as damaged; it passed as "changed since".
- **Command guide: 1,085 commands**, including Vanguard's own for defending and troubleshooting, and how to check by
  hand what the new rules report.
- **More accurate.** On Windows, Vanguard run as administrator believed it had no rights (Windows refused the reading
  of its elevation, which Wine accepted): `vanguard evidence` left the security log out there, and the administrator
  window for fixes closed without doing anything. A YARA scan thread that crashed made the scan conclude "clean"
  without reading its files: they are now reported as not scanned. Without journalctl, the evidence also takes the
  last rotated /var/log file (auth.log.1…). In what starts by itself on Linux, "nc -e" is caught inside ( … ), after ;
  or & and behind a path, and so is a downloaded script piped to ash, to "sudo -p x sh", to "sudo -s" or to su. The
  guard against a DLL placed next to the program is required at build time: it could disappear.

## October 21, 2026: version 0.82

- **Network audit, domain by domain** (`vanguard network-audit`). Six grades: Internet exposure (ports opened by
  UPnP, read by a UPnP client written in Rust), Wi-Fi (encryption, WPS, neighbouring networks, read through nl80211
  on Linux and the Windows Wi-Fi API), device separation (connected devices on the computers' network, rogue DHCP
  server, ARP integrity), DNS and certificates, connected devices, computers. What could not be checked is said and
  never counts as safe: without enough checked domains, no grade.
- **Windows read without PowerShell.** Accounts, startup, scheduled tasks, shares, Defender, BitLocker, Windows
  Update, disk health and slowness are read through Windows APIs (registry, WMI, COM). The check is faster and works
  even when PowerShell is blocked; PowerShell is only a fallback.
- **macOS and Linux read without commands.** On macOS, settings are read by a plist reader written for Vanguard; on
  Linux, through /proc, /sys and system files.
- **Router and connected devices** (`vanguard iot`): router model and software, HTTP-only administration, cameras,
  printers, NAS, and a reminder to change their default password. The only request sent to a device is SNMP
  "describe yourself", with the factory read password "public": it is announced on screen.
- **A relative's computer** (`vanguard relative`): three questions, the check, a plain-words summary and a page to
  leave them.
- **Privacy check** (`vanguard permissions`): who can use location, contacts, camera and microphone, on all three
  systems.
- **Backups truly read back** (`vanguard check-backup`) and a **monitoring dashboard** in the browser
  (`vanguard dashboard`).
- **Browser passwords** (`vanguard browser-passwords`): counted and their protection described, never read or sent;
  each browser's built-in check is pointed to.
- **Canadian Shield** offered among the fast DNS: CIRA's public DNS, which blocks malicious sites.
- **Windows: a DLL placed next to Vanguard is no longer loaded.** The program only takes its libraries from System32
  (PE DependentLoadFlags), even when run from a USB key or Downloads; deployment refuses a program without this guard.
- **PowerShell in a hidden window** in an automatic start: reported as information, no longer as an alert.
- **A security review** fixed many false "safe" results; the features page now publishes itself with each version
  (https://d9v3.github.io/vanguard-beta/).

## October 20, 2026: version 0.81

- **Linux, the check sees further.** ICMP redirects accepted (IPv4 and IPv6) and source address filtering off,
  fixed in `99-vanguard.conf` without ever loosening an interface set to strict; user namespaces open to every
  program (information only: Flatpak, Chrome and Steam need them); command folders (PATH, sudo's) that other
  accounts can change, where a fake command would take the real one's place; no lockout after wrong passwords,
  passwords shorter than 8 characters (PAM).
- **SSH.** Forwarded ports open to the whole network (`GatewayPorts`), forwarded X11 display, too many password
  attempts per connection; fixed by reloading sshd, which cuts no connection in progress. Broken algorithms (SHA-1
  key exchange, CBC, 3DES, arcfour, MD5, DSA) reopened in the configuration, read in the exact order of its Includes:
  removed by a line in `00-vanguard.conf`, checked by `sshd -t` before the reload.
- **Windows.** Automatic proxy discovery (WPAD), through which a device on public Wi-Fi can divert browsing; no
  account lockout after wrong passwords (fixed like Windows 11: 10 attempts, 10 minutes); minimum password length.
  An account that does not require a password is described as it is (“accepts an empty password”) and is
  fixed from Vanguard: a password becomes required, the current one does not change.
- **macOS.** Automatic proxy discovery on; command folders open to all; XProtect definitions, the built-in
  antivirus, too old; configuration profiles installed outside company management (adware uses them to force a
  proxy, a DNS or a certificate).
- **Command guide: 1,040 commands** (98 more), mostly for security and troubleshooting: lynis, SUID programs, locked
  accounts, ClamAV, gpg signatures, WireGuard, certificates, service exposure, needrestart, sbctl, dnf
  needs-restarting; on Windows, public or private network, shared folders, TPM chip, a program's signature, wiping
  free space, memory test; on macOS, what starts by itself, camera, microphone and screen access, a file's
  fingerprint, traffic per program; on Omarchy, 60 more commands: firmware, keyrings and clock that block an update,
  orphan packages, pacman's cache, FIDO2 key, SSH server and docker group to turn off, network and speed, sharing
  with LocalSend, screen captures and text, brightness, boot screen, web apps, games and services to install,
  factory reset. The tldr-pages examples are also renewed by the monitoring and the monthly check-up, without
  opening the guide.
- **Secrets in git projects.** Vanguard reads the history of the home folder's projects, where a password, API key
  or token written once stays, even when deleted later: keys recognized by their shape (AWS, GitHub, GitLab, Google,
  Stripe, Slack…), private keys, passwords in an address or in the code; gitleaks, when installed, adds its rules. No
  secret is shown or kept.
- **YARA with nothing to install.** The 308 rules are applied by YARA-X (VirusTotal's YARA engine in Rust, BSD
  license), compiled into Vanguard on Linux, Windows and macOS: no engine to install or offer any more, and four
  files read at once. A file over 256 MB or taking more than 30 s to scan is reported, never counted as clean. The
  program grows from about 10 to 25 MB.
- **Fingerprint antivirus, everywhere, even from the USB drive.** The YARA scan also compares every file it reads
  with MalwareBazaar's SHA-256 fingerprints (abuse.ch, public domain): a file listed there is that exact malware, no
  doubt possible, offered for quarantine. The full list updates once a week, the last 48 hours every day; offline,
  the saved copy is used, and with no copy, that is said.
- **Recognized open source tools, when installed.** “Flaws in Docker images”: trivy tells the known serious or
  critical flaws in Docker or Podman images; when missing, Vanguard offers to install it with the system's tool. After failed SSH logins, the
  check tells whether fail2ban, sshguard or CrowdSec already blocks the addresses that keep trying.
- **Windows, the classic backdoors.** A debugger set on a sign-in screen accessibility program (IFEO,
  SilentProcessExit), sethc or utilman replaced by cmd, Winlogon's Shell or Userinit hijacked, AppInit_DLLs, WMI
  subscriptions that run a command: in the check, tracked by the monitoring, fixed when the original state is known
  exactly, otherwise the steps to follow. And the event logs of the last 7 days: bursts of wrong passwords from the
  network, security log cleared, accounts created, suspicious services installed; without administrator rights, the
  security log is reported unreadable, never healthy.
- **Linux, the signs of a rootkit.** Hidden processes, programs running without a file (memfd, deleted, started from
  /tmp or /dev/shm), a kernel module that hides or unknown unsigned modules, a network card in promiscuous mode; read
  from /proc and /sys in a few milliseconds. No automatic fix: the steps to follow, with rkhunter and chkrootkit as a
  second opinion.
- **Name poisoner unmasked.** During the network scan, without slowing it down, Vanguard asks over LLMNR, NetBIOS and
  mDNS for a random name that does not exist: the device that answers is a tool like Responder, which steals the
  network's Windows passwords. High alert, and a notification from the hourly monitoring.
- **Collect the traces** (Troubleshoot, `vanguard evidence`, and first step of “After an infection”, ticked by
  default; with ransomware or a remote control, right after cutting the Internet, which cannot wait). Before cleaning up, what a specialist will want to see, in a dated folder on the key or in Vanguard's
  folder: processes with their program's SHA-256 fingerprint, connections, what starts by itself, the check as JSON,
  accounts, logs of the last 7 days, recent files; a README and a manifest that `sha256sum -c` checks. Read-only,
  nothing is sent; Vanguard warns that the folder holds personal data.
- **“Who talks to the Internet?” recognizes botnet command servers**: Feodo Tracker and ThreatFox lists (abuse.ch),
  with the malware's name, optional abuse.ch key (unavailable or too old: said, never counted as empty); the DNS
  cache too: a program that asked for a known command
  server's name shows up, even once the connection is closed. Other accounts' connections are compared too; a server
  found leads to “After an infection”, Internet cut first. Hourly monitoring warns when a program talks to a known
  command server. And the account's temporary folder is recognized wherever it is (a moved TEMP let a program
  started from there go unnoticed).
- **Update from GitHub, without the key.** “Update Vanguard” takes the latest published version, and the main menu
  announces it. Nothing is taken on trust: each version is signed with Ed25519 on the author's computer, and Vanguard
  refuses a badly signed manifest, a version that is not newer, or a program whose size, fingerprint or version are
  not the signed ones. Someone who took over the GitHub account could not get anything else installed. The programs
  are published separately (d9v3/vanguard-officiel), the code in d9v3/vanguard-beta.
- **HTTPS client in Rust**: lists, registries, leaks, tldr, speed test and blocklists without curl; redirects over
  HTTPS only. The program grows by 2 to 3 MB.
- **Read directly from the system**: connections, processes, rights and account, the traces' registry and event logs,
  without ss, tasklist, taskkill, whoami, pgrep, id or PowerShell; faster, and nothing depends on Windows' language.
  Without rights, the security log is reported unchecked (before, it passed as healthy without being read).
- **Windows cleanup**: paths written in full, never the current folder when a variable such as TEMP is empty
 ; the print queue empties safely.
- **More accurate and safer.** On Windows, an account without a Startup folder no longer makes every file in the
  current folder look like a “suspicious shortcut” (a false high alert, especially when run from the key); the last
  quick commands (notifications, df on a dead network volume…) have a time limit and no longer freeze the
  monitoring; the list of known keys no longer loses a note when two are written at once.
- **Rescue key: the Omarchy installer** in the boot menu, next to Arch, Debian, Fedora and SystemRescue:
  complete, no Internet needed, kept up to date like them and checked with the key that signs Omarchy's packages.
- **For testing**: the program's PowerShell scripts parsed and replayed with pwsh at each check, in a sandbox
  closed to the system;
  Windows virtual machine test that counts skipped steps, compares each run with the previous one and
  checks the 0.79 settings; scripts dropped from Linux and run by the VM with its consent.
- **Independent review before the release**: an account with an empty password that a fix would have shown as
  healthy, an SSH attempt limit strict enough to lock the door, a `chmod` that would have broken `/tmp` put in PATH;
  fixed.

## October 19, 2026, evening: version 0.78

- **New name: Vanguard**, with its logo, a V as a shield and a padlock. On a computer where it already ran,
  nothing is lost: data, automatic backup, shortcut and settings follow the new name by themselves.
- **A much faster check.** On Linux, from 7 seconds to under one: commands are no longer awaited in fixed 50 ms
  pauses, packages are verified in parallel, Wi-Fi no longer waits for a new scan. On Windows, about ten fewer PowerShell
  launches: firewall, UAC, Remote Desktop and screen lock read straight from the registry, listening ports
  read with netstat and tasklist.
- **Windows.** MSI packages installed with system rights, Defender cloud protection off, exploit protection off (DEP,
  ASLR, CFG, SEHOP), Windows Update turned off (service or policy), services with unquoted paths in a folder anyone
  can change; a suspended or pending BitLocker no longer counts as encrypted.
- **Linux and macOS.** Session that opens by itself without an encrypted disk (GDM, SDDM, LightDM), root programs'
  memory readable after a crash, kernel magic keys; unencrypted Time Machine backup, Mac Remote Login accepting root
  or accounts without a password.
- **More accurate.** Included SSH configuration files read, open Wi-Fi networks better recognized, a DNS on this computer also measured
  on a new site (its memory answered in under a millisecond), dnf-automatic that
  only downloads, APT settings read in their order, complete English interface, decimal numbers written the French way in French,
  long messages broken between two words, never in the middle of one; on Windows, a firewall with no readable profile
  no longer counts as checked (no grade), and Remote Desktop turned on by a group policy is recognized; a VPN
  interface is no longer taken for the local network.
- **Network scan twice as fast** (from 20 to 8-10 seconds on a network of eleven devices): the router is asked
  about UPnP from the start, in the background (it takes up to 8 seconds to answer), and TCP ports, UDP ports and
  device names are looked up at the same time. Same probes, nothing removed.
- **Command guide redone.** One entry per system: Omarchy, Arch, Fedora, Debian and Ubuntu, other Linux, Windows 11,
  macOS; each distribution has its introduction, its “Step by step” guides (update, install, free up space, repair,
  firewall, NVIDIA, new release…) and its programs, then those common to Linux; Windows 11 and macOS have theirs too
  (repair Windows, network, security, slowness, Time Machine…), all systems too (SSH key, git); over twenty more
  programs common to Linux (time, kernel, Wi-Fi, network diagnosis, accounts, sound, printers, UEFI boot…), openSUSE
  and Docker; 942 commands. You type what you are looking for and commands show up as you type; each one has its
  page, to copy it, or run it here when it only reads (its output scrolls in Vanguard, Esc stops it).
- **Over 30,000 more commands**: the tldr-pages examples (CC BY 4.0 license), downloaded automatically every week and
  already on the key (even without Internet, the guide has them from the first launch); to copy only. In every
  search, what starts with the typed word comes first.
- **Safer: the key recognized by its token.** A volume carrying a VANGUARD key marker is no longer the key for
  that: from its local copy (monitoring, maintenance, shortcut), Vanguard reads and writes only a key it was started
  from or one this computer knows (`vanguard.jeton` token written at deployment, log partition included); an unknown
  volume is said so in the menu and ignored. The key's record has its reference here: changed outside Vanguard, or
  back without its protection, it is neither read nor rewritten and the check says so (`vanguard manifeste
  --accepter` when intended).
- **Word prediction in every menu** and checklist: the end of the most likely word shows in grey, Tab completes it.
- **Deeper check.** Platform security according to fwupd (HSI level: TPM, BIOS protection, IOMMU), kernel lockdown and
  module signing, BPF, auditd; on Windows, PowerShell script logging, Credential Guard (Enterprise, Education),
  Sysmon. Deep scan of a device: service versions with nmap when installed. The new rules have a stable identifier
  (“vanguard rules”).
- **Safer.** The sandbox no longer reaches the system bus or Docker; on Windows, the fix script is checked just before
  it runs as administrator (a script changed in the meantime does not run); Vanguard's data is reserved for your
  account. Automatic backup recognizes its disk by its identifier (UUID), no longer by its name: another disk with
  the same name no longer receives your files. Any text from elsewhere (device, file or printer name) goes through a
  single protection before entering a command, and a test checks it across the whole code.
- **Vanguard updates itself from the key.** The copy placed on a computer (monitoring, maintenance, shortcut) did not
  follow the key: started from a newer key, Vanguard says so in the menu, and the update happens after your consent
  (9.9 or `vanguard self-update`), read back and compared before replacing the old one; never to an older version,
  and never from a key that is merely plugged in.
- **A single release a day.** This history groups versions by day; only the latest keeps its download page, and
  GitHub's Mac now compiles once per release.

## October 19, 2026: versions 0.62 to 0.77

- **A much fuller check on Windows.** LM or NTLMv1 network authentication, LM hashes, share signing and guest
  access, accounts listed anonymously, SMBv1 client, Remote Registry, UAC that no longer asks, PowerShell execution
  policy, Office macros all allowed, overly broad Defender exclusions, Secure Boot, WDigest, LSA protection,
  PowerShell 2, SmartScreen, memory integrity, paused updates, and screen lock.
- **Linux and macOS.** Automatic security updates, kernel settings (pipes and files in /tmp, processor counters),
  SSH client that does not check servers, SSH server that accepts accounts without a password, sudo that never asks
  for the password again, cups-browsed open to the network, X11 display open to everyone, open Wi-Fi networks that
  reconnect by themselves.
- **Everywhere.** New administrators and hijacked browsing (forced proxy, hosts file) reported; computer clock, end
  of support of the system, forgotten accounts, passwords kept by the browser, sensitive files lying around.
- **New tools.** Automatic backup, hacked account, report to leave behind, desktop shortcut, and "What Vanguard
  changed": every fix is logged and dated, and the HTML report sums it up.
- **Caution.** The key's partitions are no longer offered as a disk; Check my key and Time Machine more careful;
  booby-trapped disk names refused in automatic backups.

## October 18, 2026: versions 0.52 to 0.61

- **Step-by-step troubleshooting** (network, security, upkeep, after an infection, new or departing computer),
  command guide and learning.
- **New defenses.** Fake technician and remote takeover, shares open to everyone, Windows Defender blocks,
  ransomware decoy files, Bluetooth, watched Downloads folder, reversible quarantine, camera and microphone.
- **Vanguard checks itself**: key manifest, dependency flaws every night, check a copy, check my key, encrypted key
  data, "My computers".
- **Comfort.** Startup programs, scrolling menus, search in checklists, copy a command from the guide, aligned
  emojis, booby-trapped names made harmless on screen.
- **Lighter code, arranged like the menu**, with the same behavior; fewer false alarms.

## October 17, 2026: versions 0.9.5 to 0.51

- **Vanguard gets its name**, with its shield logo and a redone presentation.
- **Wider check.** DNS and root certificates, browser extensions and security settings, computer health, leaked
  passwords and email addresses, hidden persistence, known package flaws, erased logs, integrity of critical files,
  ARP spoofing of the router, ports opened to the Internet through UPnP.
- **Tools.** Updates for the whole system, drivers included; Repair and deep cleanup; Optimize, with settings that
  undo exactly; gaming on Windows and Linux; computer diagnosis; essential software; sandbox for unknown programs;
  connection test for gaming.
- **Follow-up.** Changes since the last check and grade curve, monitoring of this machine, emergency text report,
  automatic restore point before every fix.
- **USB key** write-protected, error log, antivirus for a key; French and English everywhere; keyboard menus
  (arrows, Enter, Esc); parallel check, three times faster; macOS on par with Linux and Windows.

## October 16, 2026: versions 0.2 to 0.9.4

- **First versions.** Local network scan and device database, check of Linux (Docker, firewall, UDP, SSH keys, screen
  lock, hardened kernel, AppArmor or SELinux, backups, sudo) and Windows.
- **Repair menu** for Linux, Windows and macOS.
- **Reliability.** No failed command taken for "all is well" anymore, timeouts on commands, safe device database; a
  Remote Desktop session in use is never cut.
