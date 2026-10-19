# Version history

*[Français](CHANGELOG.md)*

What each day brought to Vanguard, most recent first. Since October 19, 2026, Vanguard has a single release a day,
gathering the day's work. Only the latest version has its download page; every version keeps its tag in the
repository (`git checkout v0.62.0`, for example), to be rebuilt if needed.

## October 20, 2026: version 0.78

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
  only downloads, APT settings read in their order, complete English interface, decimal numbers written the French way in French.
- **Command guide redone.** One entry per system: Omarchy, Arch, Fedora, Debian and Ubuntu, other Linux, Windows 11,
  macOS; each distribution has its introduction, its “Step by step” guides (update, install, free up space, repair,
  firewall, NVIDIA, new release…) and its programs, then those common to Linux; Windows 11 and macOS have theirs too
  (repair Windows, network, security, slowness, Time Machine…), all systems too (SSH key, git); over twenty more
  programs common to Linux (time, kernel, Wi-Fi, network diagnosis, accounts, sound, printers, UEFI boot…), openSUSE
  and Docker; 942 commands. You type what you are looking for and commands show up as you type; each one has its
  page, to copy it, or run it here when it only reads (its output scrolls in Vanguard, Esc stops it).
- **Over 30,000 more commands**: the tldr-pages examples (CC BY 4.0 license), downloaded by themselves every week and
  already on the key (even without Internet, the guide has them from the first launch); to copy only. In every
  search, what starts with the typed word comes first.
- **Word prediction in every menu** and checklist: the end of the most likely word shows in grey, Tab completes it.
- **Deeper check.** Platform security according to fwupd (HSI level: TPM, BIOS protection, IOMMU), kernel lockdown and
  module signing, BPF, auditd; on Windows, PowerShell script logging, Credential Guard (Enterprise, Education),
  Sysmon. Deep scan of a device: service versions with nmap when installed. The new rules have a stable identifier
  (“vanguard rules”).
- **Safer.** The sandbox no longer reaches the system bus or Docker; on Windows, the fix script is checked just before
  it runs as administrator (a script changed in the meantime does not run); Vanguard's data is reserved to your
  account.
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
