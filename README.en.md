<h1 align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="assets/banniere-blanche.png"><img src="assets/banniere-noire.png" alt="Vanguard" width="600"></picture></h1>

<p align="center"><a href="README.md">Français</a> · <b>English</b></p>

<p align="center">
  <b>Cyber defense for your home, from a USB key.</b><br>
  Vanguard checks your machine and every device on your network, explains each threat in plain language,<br>
  and fixes it once you agree; when something stops working, it helps you troubleshoot too.<br>
  Linux, Windows and macOS, nothing to install, in English or French.
</p>

![Vanguard's security check: a grade from A to F, each problem explained with its fix](assets/captures/bilan-en.png)

## At a glance

- **A home's threats, one by one**: what the router exposes to the Internet, an intruder on the Wi-Fi, a vulnerable
  connected device, an infected computer, a hijacked DNS or certificate, scams. Each problem is explained simply,
  with its fix.
- **A security check graded from A to F**: firewall, updates, encryption, open ports, backups…
- **Your whole network**: every device, its manufacturer, its open ports and its risks; newcomers are flagged.
- **Nothing changes without your consent**: a restore point first, and every setting is undone exactly.
- **And troubleshooting**: diagnostic, everyday problems step by step, slowness, a relative's computer, repairs.
- **One USB key for all your computers**, and your friends': it write-protects itself anywhere but at home.

In the menu, choose **1** (full check), then **2** (fix). Arrows, Enter, and Esc or Backspace to go back.

## What Vanguard does

| Threat or area | What Vanguard does |
|---|---|
| **The check** | A grade from A to F on everything below, and also: firewall, updates and known vulnerabilities, encryption, accounts, SSH, shares open to everyone, clock, end of support, forgotten accounts, disk health… Each problem is explained, with its fix, applied once you agree. |
| **Exposure to the Internet** | The ports the router opens to the Internet (UPnP), this computer's open ports and firewall, the home's address on a blocklist, the router's admin page over HTTP only. |
| **Intruders on the Wi-Fi** | Every device on the network, its manufacturer, its open ports and its risks; newcomers flagged every hour, with a dashboard in the browser; the Wi-Fi's protection (WEP, WPA2, WPA3), the fake access point copying its name, Bluetooth devices paired recently. |
| **Connected devices** | The router and the devices on the network (cameras, printers, NAS, TVs, smart home…) recognized, with their default password to change; hidden cameras, in a rental or at someone's place. |
| **Infected computer** | Antivirus, 308 YARA rules and over a million fingerprints of known malware (MalwareBazaar), decoy files against ransomware, Windows Defender blocking, what starts in secret, backdoors and rootkit signs, suspicious event logs, connections to known botnet servers, a password thief like Responder unmasked, integrity of critical files, flaws in Docker images (trivy, when installed), reversible quarantine, and the traces collected before cleaning up. |
| **Hijacked DNS and certificates** | The DNS really in use (and made-up answers), added root certificates (HTTPS interception), a forced proxy and sites redirected by the hosts file, automatic proxy discovery (WPAD), browser extensions that read every site. |
| **Scams and remote control** | Tech-support scam (remote control tools), dangerous links checked without opening them, downloaded files checked, leaked passwords and email addresses, hacked account, a sandbox for an unknown program. |
| **Data and privacy** | Automatic backup and check my backup (really read back), copy my files (checked copy) and check a copy, privacy check (who can access location, contacts, camera and microphone), camera and microphone, browser passwords without protection, sensitive files lying around, secrets forgotten in git project history, key data protected by a passphrase. |
| **Troubleshooting** | Computer diagnostic, everyday problems step by step (Internet, Wi-Fi, slowness, sound, printer, full disk), after an infection, new computer, computer leaving, a relative's computer, “Why is it slow?”, computer specs, report to leave behind, repairs. |
| **Optimizing, software and gaming** | Privacy and performance settings undone exactly, a cleanup checklist with the space gained measured, startup programs; the best software in 8 categories, from its official source, and updating everything at once; connection for gaming (ping, jitter, loss, speed and bufferbloat, compared with your habits), crowded Wi-Fi, NAT type, fastest DNS (without removing a DNS that protects you), settings for gaming. |
| **Follow-up and tools** | HTML report with the grade curve, monthly check-up, learning on your computer, what Vanguard changed (each fix, dated); check my drive (fake drives, speed), my computers (tracked by the key), shortcut on this computer, Vanguard updated from the key or from GitHub (versions signed by the author), command guide, search in every menu. |

<details>
<summary><b>The details, threat by threat</b></summary>

#### The check, graded from A to F

**Security check** — a grade from A to F, then each problem with its fix.

- Firewall, open ports (TCP and UDP), updates and known vulnerabilities, disk encryption, Secure Boot, screen lock,
  accounts (and their lockout after wrong passwords, minimum length: Linux, Windows), automatic proxy discovery
  (WPAD: Windows, macOS), SSH (and its failed login attempts, from the Internet or from home, and a client that does
  not check servers; forwarded ports open to the network, forwarded X11 display, too many password attempts; broken
  algorithms, SHA-1, CBC, 3DES, MD5 or DSA, reopened in sshd, removed after `sshd -t` without cutting any
  connection), sudo, groups worth root (docker, lxd, libvirt, disk), command folders other accounts can change,
  kernel hardening (on Linux: ICMP redirects in IPv4 and IPv6, impossible source addresses, user namespaces open to
  all; on macOS: sealed system volume, enforced code signing, library validation, added extensions), badly protected
  secret files, backups, file shares open to everyone (Samba, NFS, Windows shares, macOS File Sharing: the
  password-less access is closed after your consent, named accounts keep theirs).
- Clock set automatically; end of support: Windows 10 and the Windows 11 or macOS versions that no longer get fixes,
  programs abandoned by their publisher (Flash, Java 7, Office 2016…), browsers that no longer update; forgotten
  accounts (active but unused for six months); new administrators.
- Windows: WDigest (passwords in clear text in memory), Local Security Authority protection, PowerShell 2.0, Remote
  Assistance, automatic sign-in (and password in clear text in the registry), SmartScreen off, account control off
  for remote connections, memory integrity, paused updates, LM or NTLMv1 network authentication, share signing,
  PowerShell running any script, UAC that asks nothing, guest access to shares, accounts listed without a password,
  Secure Boot, suspended BitLocker, Defender cloud protection off, overly broad Defender exclusions, Office macros
  all allowed, passwords kept as LM hashes, Remote Registry, SMBv1 client, MSI installs with system rights, services
  with unquoted paths, exploit protection off, Windows Update turned off; Linux: automatic security updates, session
  that opens by itself without an encrypted disk; macOS: unencrypted Time Machine backup.
- Health: disk space, SMART status of the disks (without root), battery, temperatures.
- What could not be checked is said, never counted as healthy.
- The check reads what it checks by itself, without starting a program for each reading: on Windows, the accounts,
  the Run keys and the Startup folder (Windows functions and the registry, PowerShell as a fallback); on macOS, the settings,
  launchd agents, the version, the Mac's name, free space and administrators (plists read directly, instead of
  defaults, plutil, sw_vers, sysctl, scutil or df). Faster, and fewer ways to fail.
- Fixes applied only after confirmation, with a restore point created automatically beforehand (snapper or
  timeshift on Linux, Windows restore point, Time Machine snapshot on macOS); on Windows, each one is a readable
  script.

#### Exposure to the Internet and the home network

**Local network** — every device, its manufacturer, its open ports (TCP, and UDP: SNMP, NetBIOS, UPnP, DNS, mDNS)
and its risks; newcomers flagged, one notebook per network (at home, at each friend's), nicknames ("HP printer");
the ports that devices opened to the Internet on the router through UPnP (read-only, with miniupnpc on Linux).
After your consent, the home's Internet address is looked up in four blocklists (Spamhaus, SpamCop, DroneBL, PSBL):
listed for spam or attacks, a device is probably infected. During the scan, Vanguard also asks for a name that does
not exist (LLMNR, NetBIOS, mDNS): nobody legitimate answers, and the device that does is a poisoner like Responder,
which steals the network's Windows passwords; the hourly monitoring flags it too.

#### Intruders on the Wi-Fi

- Wi-Fi: the network's protection (WEP, WPA2, WPA3), and fake access points ("evil twin") that copy its name without
  a password to lure devices; on Linux, saved open networks that reconnect by themselves.
- Bluetooth: computer visible all the time, and devices paired less than a week ago (a keyboard paired by someone
  else types whatever it wants).
- Hourly monitoring: a notification if an unknown device shows up, if a port opens, if the machine's grade drops, if
  the router seems spoofed (shared or changed MAC address: ARP spoofing), or if a program or a disguised file lands
  in Downloads (to check before opening it; nothing is blocked). Its dashboard, a local page opened in the browser:
  its state, the alerts day by day (kept even when the night's notification is gone), the devices that showed up and
  the connections to botnet servers. Nothing is sent.

#### Connected devices

**Router and connected devices** — after the scan, or later from the last scan kept (`vanguard iot`), what the router
says about itself (often its model and software version), an admin page over HTTP only, and the cameras, printers,
NAS, TVs, speakers, consoles and smart home devices, recognized by their manufacturer, name, ports and
announcements. For the router, cameras, printers and NAS, the advice to change the default password: nothing more is
probed and no password is tried.

**Hidden cameras** — in a rental or at someone's place, the devices on the network that look like cameras (maker,
video stream, ONVIF), without turning anything off or watching anything.

#### Infected computer

**Against ransomware and malware** — decoy files: a decoy text file and PDF in Documents, Pictures and Desktop,
which nobody has a reason to touch. Ransomware that encrypts or renames them triggers a critical alert, at each
check and hourly through monitoring, with what to do; placed and removed after your consent. And a YARA scan: 308
ReversingLabs rules that recognize whole families (ransomware, password stealers, trojans, backdoors…), alongside
the antivirus, applied by YARA-X, compiled into Vanguard: nothing to install. Each file read is also compared with
MalwareBazaar's SHA-256 fingerprints (abuse.ch, over a million known malware samples): there, it is that very
program, beyond doubt. The full list is downloaded once a week (about 43 MB), the last 48 hours once a day; offline,
the saved copy is used, and with no copy at all, it says so. What the antivirus or YARA finds can go into a reversible quarantine: the file is made unusable and noted, then put back exactly in its place if it was a false
positive.

**Windows Defender blocking** — Vanguard blocks nothing itself: after your consent, it turns on what Windows blocks
from its kernel and protects against being turned off. Attack surface reduction rules (password theft from memory,
vulnerable drivers, booby-trapped Office documents and attachments), network protection against dangerous sites,
unwanted software, controlled folder access against ransomware. Each rule is named before you agree and is undone
exactly; those that would block Vanguard on its USB drive or troubleshooting are never turned on, and nothing is
offered when another antivirus replaces Defender.

**Collect the traces** — after an infection, before cleaning up or reinstalling: what a specialist will want to
see, kept in a dated folder on the VANGUARD key (or in this computer's Vanguard folder), in the order it vanishes.
Processes (with their program's SHA-256 fingerprint), current connections, what starts by itself, the check as JSON,
accounts, logs of the last 7 days (as .evtx on Windows), recent files from risky places (described, not copied);
LISEZMOI.txt, in French and English, tells what each file holds and what could not be read, MANIFESTE.txt gives
their fingerprints (`sha256sum -c MANIFESTE.txt`). Read-only: nothing is stopped, moved or sent. The folder holds
personal data, to hand only to someone you trust. It is also the first step of “After an infection”, ticked by
default: cutting the network or cleaning up erases these traces. With ransomware or a remote control still connected to
the Internet, cutting comes first: every minute counts.

**Recognized open source tools, when installed** — Vanguard runs them and explains what they find, without
changing anything; when missing, it offers to install them with the system's tool. trivy tells the known serious or
critical flaws in Docker or Podman images: an image does not update by itself. And when someone fails SSH logins, the check tells whether fail2ban,
sshguard or CrowdSec already blocks the addresses that keep trying.

- What hides: programs started at boot, scheduled tasks, library preloading, modified privileged programs. On
  Windows, the classic backdoors: a debugger set on a sign-in screen accessibility program (IFEO, SilentProcessExit),
  sethc or utilman (Sticky Keys, Ease of Access) replaced by cmd, Winlogon's Shell or Userinit hijacked, AppInit_DLLs,
  WMI subscriptions that run a command; tracked by the monitoring, fixed when the original state is known exactly.
  On Linux, the signs of a rootkit: hidden processes, programs running without a file (memfd, deleted, started from
  /tmp), a kernel module that hides or unknown unsigned modules, a network card in promiscuous mode (it listens to
  the whole network).
- Windows event logs, over the last 7 days: bursts of wrong passwords from the network (Remote Desktop, shares),
  security log cleared, accounts created, services installed from a temporary folder or that start an interpreter.
  The security log can only be read as administrator: without that right, it is said.
- Antivirus: ClamAV (Linux, macOS) or Microsoft Defender (Windows), on the computer or on a chosen USB key / folder,
  with the tricks of USB worms (shortcut posing as a folder, autorun.inf, scripts).
- Integrity of critical files (accounts, sudo, SSH, PAM, cron, services, autostart): BLAKE3 fingerprints, what changed
  since the reference, and live monitoring.
- Who talks to the Internet?: each program's current connections, with the server's name; a program started from a
  temporary folder or Downloads, a remote access tool's port, a server without a name or a known botnet command
  server (Feodo Tracker and ThreatFox lists, abuse.ch; a free, optional abuse.ch key adds ThreatFox's official
  access) are flagged. Read-only: nothing is cut.
- Vanguard also distrusts itself: at startup, it says whether a library is injected into every program of the
  session (LD_PRELOAD, DYLD_INSERT_LIBRARIES, AppInit_DLLs: one from a system package, like GameMode, is mere
  information) and whether it runs as root for no reason, since its results go through there. In the check: the
  hourly monitoring you had turned on and that disappeared (malware first cuts what watches it), and the check
  history rewritten afterwards (each check carries the previous one's checksum). Each night the code has changed, CI
  builds Vanguard twice and checks that the program is identical down to the byte.

#### Hijacked DNS and certificates

- The DNS actually used (and forged answers), added root certificates (HTTPS interception), browser extensions that
  read every site.
- Hijacked browsing (forced proxy, sites redirected by the hosts file).

#### Scams and remote control

- Is someone controlling my PC?: the tech-support scam (“your computer is infected”) gets a remote control tool
  installed. Vanguard looks for AnyDesk, TeamViewer, RustDesk, Quick Assist, Splashtop, UltraViewer… installed (and
  since when), started at boot, running or simply sitting in Downloads; it explains what to do (cut the Internet, tell
  the bank, change passwords) and removes them after your consent. A running program is never cut without a second,
  explicit consent: the person helping may be connected through it. In the check too (“Remote access”).
- Is this link dangerous?: a link you received, checked without ever opening it (disguised letters, misleading
  subdomain, imitated brand, link shortener, raw IP address); after your consent, the domain's age and three public
  lists of dangerous sites (URLhaus, Spamhaus, SURBL). Only the domain name leaves the computer.
- Check a downloaded file: its checksum compared with the one the site publishes (pasted, or a SHA256SUMS next to
  it), its name and content (double extension, program disguised as a document), then YARA and the antivirus.
- Sandbox: run an unknown program without network, with a read-only system and an invisible home folder (bubblewrap
  or firejail on Linux, Windows Sandbox on Windows, sandbox-exec on macOS).
- Leaked passwords: checked with Have I Been Pwned without ever sending the password (only 5 characters of its hash);
  email address leaks, after your consent (the address is sent to the service).

#### Data and privacy

**Automatic backup** — set up with the system's tool (Déjà Dup or a daily rsync copy on Linux, Time Machine, File
History on Windows), to an external disk, after your consent and undoable. **Check my backup**: the rsync copy
really read back from the disk, random files compared with their original; an original changed since is not counted
as an error, a copy that differs from an unchanged original means a disk losing data. For Time Machine, Déjà Dup and
File History, which keep their backups in their own format, how to restore one file. Nothing is written or deleted.

**Copy my files** — Documents, Pictures, Desktop, Videos and Music to an external disk, before a risky repair or a
reinstall: space is checked first, each file is read back and compared with the original (BLAKE3 fingerprint),
nothing is deleted or overwritten, and an interrupted copy resumes where it stopped. **Check a copy**, later, is the
restore test: files spread over the whole copy are read back from the disk and compared with their original; a disk
that loses data shows up before the day you need it.

**Protect the key's data** — the key's device record (names, MAC addresses, nicknames) encrypted by a passphrase
(XChaCha20-Poly1305, passphrase derived by Argon2id), against a lost or lent key. At home, nothing changes: the data
key is kept on the owner's computer. Elsewhere, Vanguard asks for the passphrase, or goes on without the record. The
report and the diagnostic are no longer written to the key. On request, reversible, with a backup offered first; the
check reports a record left in clear.

**Secrets in git projects** — Vanguard reads the history of the git projects in the home folder: a password, API
key or token written once stays there, even when deleted later. Its own rules recognize keys by their shape (AWS,
GitHub, GitLab, Google, Stripe, Slack…), private keys, passwords in an address or written in the code; gitleaks, when
installed, adds its own. No secret is shown or kept.

**Camera and microphone: who uses them?** — on Windows, each program that used the camera or the microphone, and the
last time (a program started from a temporary folder or Downloads is flagged); on Linux, what holds them right now.
Read-only. **Privacy check**: the apps that can access location, contacts, camera and microphone, and their last use
when the system records it (the permission store on Windows, Flatpak and Snap on Linux, the macOS permission
database, readable with Full Disk Access). Nothing is removed: what to do is given, and what could not be read is
said to be unchecked.

- Passwords saved in the browser without protection, sensitive files lying around (passwords or keys in clear text),
  missing backup with its set-up offered.

#### Troubleshooting

**Computer diagnostic** — the first step of any troubleshooting: hardware, system, and recent problems (journal
errors and crashed programs on Linux; blue screens, sudden shutdowns and crashes on Windows; kernel panics and crash
reports on macOS), with a text copy saved on the key.

**Troubleshoot step by step** — everyday problems, handled the way someone who knows would: no Internet, Wi-Fi
dropping, slow computer, no sound, printer not working, disk full. Two or three questions, then Vanguard checks by
itself (address, router, Internet, DNS; Wi-Fi signal; sound service and selected output; print queue and printer on
the network; disk space) and suggests the right repair or the right tool, always with your consent. And three
journeys for the big moments: **after an infection** (the traces kept first, then what is urgent depending on the
sign, the check of what may have been installed, the scans in order, then the passwords to change, email first);
**new computer** (updates, encryption, backups, starter pack, privacy, in order); **computer leaving**, sold or given
(verified copy first, accounts signed out, BitLocker or FileVault key set aside, secure wipe by the system's tool,
TPM chip cleared). Vanguard never wipes anything itself. And **my account was hacked**: take back control through the
official page, then password, two-step verification, sessions signed out, and a check that this computer did not give
the password away. Slow **since an update**: the latest updates, dated, and how to go back. And **a relative's
computer** (`vanguard relative`): three questions (who uses it, why you were asked to look at it, and whether their
network may be looked at, only with their consent), the check, then a summary in everyday words, ordered by the
answers: what is left to do first, what is fine next. The tools that match the reason (slowness, antivirus, fake
technician), the fixes one by one, and the page to leave behind, with tips chosen for the person.

**Report to leave behind** — a simple page for the person you just helped: their grade, what is left to do from the most
to the least serious, what is fine and three habits; put on their Desktop, to read or print.

**Why is it slow?** — a two-second snapshot: what keeps the processor, memory and disk busy, program by program;
how long startup takes and what delays it; the programs started at login and their weight. Those that work for a
while then calm down (antivirus scanning, indexing, updates) are named as such. Startup programs are removed from
there, after your consent: they stay installed, and each removal is undone exactly (`vanguard startup`).

**Computer specs** — model, motherboard, BIOS, processor, memory (modules, type, speed), graphics card and driver,
disks: what you are asked on the phone or to buy a part. Serial numbers are shown on screen only, never written.

- Repairs: Internet, hijacked browsing, firewall, disk, full disk, deep cleaning, stuck Windows Update, system files,
  clock.

#### Optimizing, software and gaming

**Optimize** — privacy, performance and comfort settings written for Vanguard. On Windows: telemetry kept to a
minimum, ads and tracking off, Recall without screen snapshots, file extensions shown, no autorun from USB drives,
fast startup, full right-click menu. On Linux: SSD maintenance, journal size, reports sent by GNOME or Ubuntu. On
macOS: ads, analytics, no .DS_Store on drives. Each setting shows its state and is undone exactly: the previous value
is recorded, then put back. None of them weakens security.

**Clean up the system** — a checklist of what takes space for nothing: downloaded and unneeded packages, old Snap
versions, unused Flatpak runtimes, AUR builds, old caches, thumbnails, old logs, crash reports (Linux); temporary
files, Windows Update and Delivery Optimization caches, old components (Windows); old caches, Homebrew, Xcode, local
snapshots (macOS). The space each item frees is measured first, what rebuilds itself is checked by default, the trash
never; the free space read again afterwards tells what was really gained.

**Connection for gaming** — ping, jitter, loss, speed and bufferbloat (the lag when someone downloads), with a
verdict criterion by criterion and advice.

**Wi-Fi, NAT and DNS** — crowded Wi-Fi: nearby networks by channel, and the freest channel to set on the
router; the NAT type for gaming (open, moderate or strict, as consoles show it), double NAT and provider-shared
address included; the fastest DNS, measured here, offered only if it does not replace a DNS that protects you
(NextDNS, encrypted, filtering), and undoable.

- Update everything at once: system, programs, drivers, firmware.
- Software: the best program for each use, mostly open source, in 8 categories (browsers and email, messaging and
  sharing, security and privacy, office, video and music, images and design, system tools, programming) plus a
  starter pack (Firefox, Bitwarden, VLC, LibreOffice, 7-Zip): checklist, installed ones recognized, installation from
  the official source that checks each download (winget, distribution packages or Flathub, Homebrew).
- Gaming: on Windows, game components and Windows settings; on Linux, Steam, 32- and 64-bit Vulkan drivers for your
  graphics card, GameMode, MangoHud, Gamescope, Wine, Lutris, Heroic, ProtonUp-Qt, vm.max_map_count, ntsync; on
  macOS, Rosetta 2, Steam, Heroic, Epic Games, GOG Galaxy, Prism Launcher and the Metal frame counter.

#### Follow-up and tools

**Learning** — Vanguard learns on your computer, sending nothing. An alert you declare normal for you ("i" when it is
offered as a fix) drops to information for 90 days, or until it gets worse; each connection test is compared with
your habits on the same network; a known device that suddenly seems all closed (asleep) is checked again more
patiently. "What Vanguard has learned" shows everything and lets you forget.

**Check my drive** — does a USB stick or an external disk hold what it claims? Fake drives (a 16 GB chip sold as
“1 TB”) accept everything and return garbage beyond their real size. After your consent, Vanguard writes recognizable
content into the free space, reads it all back bypassing the computer's memory, measures the write and read speeds,
then erases everything; the files already on the drive are not touched. Quick (a quarter of the free space) or full
(all of it, the only proof); never on the VANGUARD key or the system disk.

**My computers** — each full check run with the VANGUARD key notes the computer there: nickname (“system · model”,
renamable), grade, remaining problems (their category and level only, the five worst), date of the last check. The
table travels on the key's VANGUARDLOG partition, without computer name, account, address or Wi-Fi name; it never
goes to GitHub.

**Shortcut on this computer** — Vanguard copied here and started with one click.

**Command guide** — the useful commands of Omarchy, Arch, Fedora, Debian and Ubuntu (and other Linux), Windows 11,
macOS, and the ones typed the same way everywhere (Vanguard, ping, nslookup, ssh, curl, git…), each one explained; ⚠
marks the ones that change something. Each distribution has its introduction, its “Step by step” guides (update,
install, free up space, repair, firewall, NVIDIA drivers, new release…), its programs (pacman, dnf, apt, SELinux,
AppArmor…), then those common to Linux; Windows 11 and macOS have their step-by-step guides too (repair Windows,
network, security, slowness, Time Machine…). You type what you are looking for: commands show up as you type, and Tab completes the word. Each command
has its page: copy it, to type it here or on the computer of the person you help, or run it here when it only reads;
its output scrolls in Vanguard, and Esc stops it. Every system can be read everywhere (Windows commands from Linux,
for example), and the guide tells when a program is missing on this computer. On top of that, the examples of
[tldr-pages](https://tldr.sh) (CC BY 4.0 license): over 30,000 community commands for Linux, Windows, macOS and
others. The guide downloads them by itself, at most once a week, so do the monitoring and the monthly check-up (without
opening the guide, once it has used them), and the key brings them along: run from the key, it
has them from the first launch, even without Internet. They can be searched and copied, but never run from here,
since Vanguard has not checked them.

- Monthly check-up: one notification a month with the machine's grade, waiting updates, the space a cleanup would
  free and new problems; nothing is changed.
- HTML report with the grade history curve, and what changed since the previous check.
- Check Vanguard itself: its version, the date of its last commit and its SHA-256 checksum, to compare with the
  release page (Vanguard is not signed: this comparison is what proves it is genuine). A copy older than six months
  says so in the menu. And the key manifest: at deployment, the checksum of every file on the key is kept on your
  computer; back from someone's place, the check names what was added, replaced or removed (a planted autorun, a
  replaced program). Data, ISO images and the Ventoy menu, which change normally, are not compared. Each key has
  its own reference (recognized by its volume identifier): a second VANGUARD key does not pass for a modified one.
- Update itself: from a newer VANGUARD key, or, without a key, from GitHub. The published programs have their own
  repository there, [vanguard-officiel](https://github.com/d9v3/vanguard-officiel), next to the code's; the latest
  version is described by a manifest signed with Ed25519 on the author's computer, whose public key Vanguard carries.
  A badly signed manifest, an older version, a program whose size or checksum differs: refused. The menu announces a
  newer version; nothing is installed without your consent.
- Search in every menu and checklist: type a word (wifi, disk, dns, update…), only the lines containing it stay,
  whatever the accents or capitals; the end of the most likely word shows in grey, and Tab completes it. In the main
  menu, it also finds each tool of the submenus, and each page and each command of the guide.

</details>

Vanguard never cuts a remote connection in use (Remote Desktop, SSH). Only use it on your own network, or a network
you are allowed to audit.

## In pictures

<table>
  <tr>
    <td width="50%"><img src="assets/captures/menu-en.png" alt="Vanguard's menu"><br><sub>The menu: last check,
    connection, key plugged in.</sub></td>
    <td width="50%"><img src="assets/captures/rapport-en.png" alt="Vanguard's HTML report"><br><sub>The HTML report and
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

Vanguard recognizes the distribution and offers its own commands: `omarchy update` / `omarchy pkg add` on Omarchy,
`ujust update` on Bazzite, `rpm-ostree` or `transactional-update` on an atomic system, otherwise pacman, apt, dnf or
zypper.

## Commands

Each menu entry is also a command.

<details>
<summary><b>All the commands</b></summary>

| Command | Purpose |
|---|---|
| `vanguard full [--html] [--text]` | full check: machine + network; `--text` shows it as plain text (emergency mode) |
| `vanguard fix` | fix the problems found |
| `vanguard audit [--json]` | audit of this machine |
| `vanguard rules` | the check rules declared for this system: identifier, subject, references |
| `vanguard network [target] [-p common\|all\|22,80,8000-8100] [--json]` | scan the network or one device |
| `vanguard connection` | connection test for gaming |
| `vanguard clean [--list]` | clean up the system; `--list`: the space to gain, deleting nothing |
| `vanguard apps [--list] [--recommended]` | software to install by category; `--list`: their state, installing nothing |
| `vanguard diag` | computer diagnostic: hardware, system, recent crashes and errors |
| `vanguard troubleshoot [subject]` | troubleshoot step by step: `internet`, `wifi`, `slow`, `sound`, `printer`, `disk`, `infection`, `new`, `leaving`, `account`, `evidence`, `relative` |
| `vanguard evidence [folder]` | collect the traces after an infection, before cleaning up: processes, connections, startup, accounts, logs, recent files, in a dated folder with their SHA-256 fingerprints (read-only) |
| `vanguard slow` | why it is slow: processor, memory, disk, startup, programs at login |
| `vanguard startup` | startup programs: remove or put them back, after your consent; each removal is undone exactly |
| `vanguard changes` | what Vanguard changed: each fix run here, its date and its result |
| `vanguard handout` | report to leave behind: a simple page for the person you helped |
| `vanguard relative` | a relative's computer: three questions, the check, a summary in plain words, the fixes, the page to leave behind with its tips |
| `vanguard auto-backup [--undo]` | automatic backup to an external disk, with the system's tool |
| `vanguard shortcut [on\|off]` | shortcut on this computer |
| `vanguard self-update` | update Vanguard on this computer, from the key or from GitHub (versions signed by the author) |
| `vanguard specs [--json]` | computer specs; `--json` without the serial numbers |
| `vanguard copy-files [destination]` | copy my files to an external disk, checked copy |
| `vanguard check-drive [folder]` | check my drive: real capacity, speeds, bad blocks (writes into the free space after your consent, then erases) |
| `vanguard check-copy [folder]` | check a copy: read back from the disk and compared with the originals (restore test) |
| `vanguard check-backup` | check my backup: the rsync backup read back, random files compared with their original (read-only) |
| `vanguard antivirus [--full] [folder]` | antivirus scan (computer, or a key / a folder) |
| `vanguard yara [--full] [folder]` | YARA scan: 308 rules for malware families, and MalwareBazaar's fingerprints |
| `vanguard decoys [--remove]` | decoy files against ransomware: place them, check them, remove them |
| `vanguard harden` | Windows Defender blocking: ASR rules, network protection, unwanted software, controlled folder access; each after your consent, undoable (Windows) |
| `vanguard blocklists` | the home's Internet address on a blocklist? (after your consent) |
| `vanguard channels` | crowded Wi-Fi: nearby networks by channel, and the freest channel |
| `vanguard nat` | NAT type for gaming: open, moderate or strict |
| `vanguard cameras` | hidden cameras on the network (rental, someone else's place) |
| `vanguard iot` | router and connected devices from the last scan kept: the router's model, cameras, printers, NAS… and their default password (nothing is probed) |
| `vanguard fast-dns` | fastest DNS, measured here and undoable; a DNS that protects you is kept |
| `vanguard learned` | what Vanguard has learned: your habits, your choices, and forgetting them |
| `vanguard password` | leaked passwords |
| `vanguard sandbox <file>` | run an unknown program in a sandbox (bubblewrap or firejail, Windows Sandbox) |
| `vanguard email` | email address leaks (XposedOrNot, or Have I Been Pwned with `VANGUARD_HIBP_CLE`) |
| `vanguard outbound` | who talks to the Internet: each program's connections (read-only) |
| `vanguard self-check` | check Vanguard itself: version, build date, SHA-256 checksum to compare with the release page; on the owner's key, the key manifest |
| `vanguard camera-mic` | camera and microphone: who uses them? (read-only) |
| `vanguard permissions` | privacy check: who can access location, contacts, camera and microphone (read-only) |
| `vanguard quarantine` | the isolated files, to put back in their place or to delete |
| `vanguard secrets` | secrets forgotten in the history of git projects (and gitleaks, if installed; read-only) |
| `vanguard containers` | known flaws in Docker or Podman images (trivy, if installed; read-only) |
| `vanguard remote-access` | is someone controlling my PC? remote control tools (tech-support scam), removed after consent |
| `vanguard link <address>` | is this link dangerous? (checked without opening it; online after your consent) |
| `vanguard check-file <file> [checksum]` | check a downloaded file: checksum, name and content, YARA, antivirus |
| `vanguard integrity [--accept] [--live]` | integrity of critical files (BLAKE3 fingerprints), live if wanted |
| `vanguard update` | updates |
| `vanguard repair` | repairs and cleaning |
| `vanguard monitor on\|off` | hourly monitoring |
| `vanguard dashboard [--no-open]` | monitoring dashboard: a local page opened in the browser; `--no-open` only writes it |
| `vanguard maintenance [on\|off]` | monthly check-up; without an argument: what it would say now |
| `vanguard name <ip\|mac> <nickname>` | name a device |
| `vanguard backup [file]`, `vanguard restore <file>` | data backup |
| `vanguard gaming` | packages and settings for gaming (Windows and Linux) |
| `vanguard guide [system\|program\|words]` | command guide: a system (`omarchy`, `arch`, `fedora`, `debian`, `windows`, `macos`, `all`, or `linux` for the common programs, or `tldr`), a program (`winget`, `systemctl`…) or words to look for (`dns cache`) |

</details>

**Language**: the system's (English or French). To force it: `VANGUARD_LANG=en` or `VANGUARD_LANG=fr`. The commands
also keep their French names (`complet`, `machine`, `corriger`, `reseau`, `connexion`, `logiciels`, `diagnostic`,
`motdepasse`, `isoler`, `courriel`, `integrite`, `maj`, `reparer`, `surveillance`, `nommer`, `sauvegarder`,
`restaurer`, `nettoyer`, `pieges`, `durcir`, `listes-noires`, `appris`, `entretien`, `sortantes`, `lien`,
`verifier-fichier`, `canaux`, `dns-rapide`, `traces`, `acces`, `tableau`, `verifier-sauvegarde`, `objets`, `proche`).

**Emojis**: in the old Windows console (command prompt or PowerShell outside Windows Terminal, common on Windows 10),
which draws them badly and shifts the menus, 💡 and 🔧 become → and +. `VANGUARD_EMOJI=0` removes them everywhere,
`VANGUARD_EMOJI=1` keeps them everywhere.

## Development

Building, testing, deploying, the USB key, the error journal: see [CONTRIBUTING.en.md](CONTRIBUTING.en.md).
A security flaw in Vanguard? Report it privately: see [SECURITY.md](SECURITY.md#security).

## License

© 2026 d9v3. Vanguard is free software: you can redistribute it and modify it under the terms of the
[GNU General Public License](LICENSE) (GPL), version 3 or any later version. It comes with no warranty. A modified
version you distribute must stay under this license, with its source code.

The included libraries keep their own licenses (MIT, Apache-2.0, BSD, ISC…): see `LICENCES-TIERCES.txt`.
