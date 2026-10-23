# Version history

*[Français](CHANGELOG.md)*

What each day brought to Vanguard, most recent first. Since October 19, 2026, Vanguard has, as a rule, a single release
a day, gathering the day's work; October 21 had two, 0.82 in the morning and 0.84 in the evening, which takes over 0.83,
delivered just before it. Only the latest version has its download page; every version keeps its tag in the repository
(`git checkout v0.62.0`, for example), to be rebuilt if needed.

## Next version

- **Public Wi-Fi mode: four weaknesses closed.** On Linux, the mode's table also closes transit coming from the Wi-Fi
  adapter: a published container port (Docker, podman, k3s), which goes through DNAT then `forward` and never `input`,
  can no longer be reached from the public network (tried in namespaces of its own). On Windows, the Public category
  counts among what closes incoming connections: a network left Private, a company network or an unreadable category
  leaves the mode “on, incoming open”, and a setting that cannot be re-read shows as not verified, never ✔. On Linux, a
  DNS, encrypted DNS, mDNS or LLMNR undone by a program of the account (NetworkManager allows it without a password)
  shows in the check (Medium), on the menu line and in its header, with a way to put it back. DNS is no longer kept as
  “already encrypted and filtering” when only one of its servers filters: they must all filter, otherwise the Shield is
  set; the check no longer says such a DNS blocks dangerous sites either.
- **Attack campaign no. 2: eight weaknesses closed.** “Put everything back” never replays a command text read from
  changements.jsonl (which any program of the account can write): each block is undone by the commands rebuilt from
  its typed fields, like a single undo, and an unrecognized block is refused and shown instead of running as
  administrator. The event log is read with an overall bound (months, bytes, events), most recent first, and says what
  it did not read; files placed under the names of future months (2099…) do not count there, are no longer followed
  by writing nor counted by pruning, and no longer push the real current month out of the read and the traces: they
  are reported. formula.json, cask.json and endoflife.date are read as a stream, with a cap on entries: a small
  hostile file no longer makes the program allocate gigabytes. The attachment name of a suspicious email goes filtered
  (direction marks, control characters) into the result, the log and the report, and so does every written finding
  message. A software inventory that hits a bound (subkeys, entries in a folder, 20,000 programs, many keys without a
  name) is not verified, never silently truncated. Tool results (examens/*.json) are sealed: a “nothing found”
  rewritten outside Vanguard shows as not verified, never green. The nightly watch no longer deposits into the VM the
  program of a branch written by the AI (to run after review, `vm-tester.sh --branche`), and only passes the subject,
  file and line of a proposal to the AI that fixes.
- **Check rule parity: SSH and Defender on Windows, passwords, startup and persistence on macOS, one reference per rule,
  one time limit per rule.** Windows gains the OpenSSH server (service, %ProgramData%\ssh configuration, password
  sign-in, administrators_authorized_keys rights, read in Rust: registry, WMI, files and their rights) and the keys in
  %USERPROFILE%\.ssh (no passphrase, readable by others), WIN-SSH-001 and 002; the check re-reads the Defender
  protections that “harden” turns on (ASR rules, network protection, PUA, controlled folders, WIN-ANV-003): a protection
  Vanguard set and that was later turned off is a high alert, the basic blocking, network protection and PUA are
  offered, each fix can be undone. macOS gains the password policy and account lockout (pwpolicy, MAC-CPT-002), startup
  security (bputil or T2 chip, MAC-DEM-001), login and background items (sfltool, as administrator, MAC-PRS-002), login
  hooks and authorization plugins (MAC-PRS-003). Catch-all rules are split: Windows hardening into five (WIN-DUR-001 to
  005), plus Windows Update off or paused (WIN-MAJ-003) and automatic sign-in (WIN-SES-002); sysctl settings into three
  (LNX-NOY-003, LNX-NOY-007, LNX-RES-003), whose fixes append to the file instead of overwriting each other. Every
  machine rule cites at least one CIS, Microsoft or ANSSI reference (required by a test for all three systems), also
  given in the check's JSON (“reference”). A software inventory, kept sealed on the computer and never sent, tells for a
  week each program installed since the last check (COM-LOG-001). Finally, each rule has its time limit (10 min, 30 for
  updates): one that exceeds it is reported as not checked, the others go on. None of this has run on a real Windows or
  a real Mac yet: tests under Wine, clippy for macOS. What is said is accurate: an inventory erased or changed outside
  Vanguard no longer hides what was installed meanwhile (everything is reported again), an update whose displayed name
  carries the version (“Tool 1.3 (x64)”) is no longer new software, and a source that cannot be read (silent Flatpak,
  unreadable ~/Applications) makes the check not verified instead of forgetting its programs, reported as “new”
  later; programs of other open Windows sessions no longer count. Defender: a protection set by a check fix and later
  turned off is high, like one set by Optimize; nothing is said to “block” while real-time protection is off, nor
  healthy when nothing blocks. OpenSSH: an uninstalled server whose configuration stayed is not applicable,
  administrators_authorized_keys open to others is medium when StrictModes (the default) makes it refused, critical
  without it, and its files are bounded before being read. macOS: root's settings unreadable without sudo make the
  login hook not verified, never “no hook” again. A “this is normal” choice on the old grouped Linux kernel alert
  applies to the three new ones; at the first check after the update, the history may still show it fixed then new.

- **A linked, sealed event log.** Alerts, the evidence recorded before each action, blocks, quarantines and fixes,
  their undoing, alerts declared normal and version changes go into a single log (evenements/YYYY-MM.jsonl, on this
  computer only), append-only: each line carries the fingerprint of the previous one, the head is sealed, and so is
  each closed month, 13 months and 20 MB at most. A removed, changed or added line shows; an end that no longer
  matches is recorded in the log itself. A botnet server's alert, the evidence, the block and its undoing are linked
  (`vanguard events --incident <id>`), and a block can no longer be recorded without its evidence. The monitoring
  dashboard and the incident traces read this log (and the old one, which an earlier version still writes); a flaw
  from the KEV catalog is critical there. Spyware, outdated software and suspicious email return a result
  (`--json`), kept for the report (“Latest tool examinations”); errors from blocking, quarantine and the versions
  seen have a stable code. A broken chain is reported by the security check; neither a future month planted by hand
  nor a clock running ahead empties the history, and a full month refuses to write rather than become unreadable.
- **Check-up fixes can be undone, one by one.** Before each fix (Linux, Windows, macOS), Vanguard reads the previous
  state of what it changes (sysctl or sshd file written by Vanguard, kernel settings, service, network time, rights
  of a personal file, registry value, preference) and notes it, sealed, in reglages.json, like Optimize; each value
  is checked against a closed list before being put back as administrator. “What Vanguard changed” undoes a fix
  marked “undoable”, then reads the state back: restored, or not (and why). A fix whose previous state cannot be
  read is called “not undoable” before it is applied; one that turns a protection back on (firewall, antivirus,
  BitLocker, UAC, SELinux, Gatekeeper) is never undone. “Put everything back” now undoes check-up fixes, Optimize,
  Gaming, blocks and public Wi-Fi mode, from the most recent to the oldest, in one administrator request. Gaming
  settings go through the same mechanism: their notes in jeux.json, which was not sealed, are taken over without
  loss.
- **Undoing never reopens what a fix closed.** A note for the sysctl and sshd files Vanguard writes is put back
  only if it holds the safe values Vanguard writes there (“ptrace_scope = 0”, “PermitRootLogin yes” or an added weak
  algorithm are refused), and their content is shown before the question; a note aimed at UAC is refused on
  Windows. jeux.json is taken over only once, never over an adopted reglages.json. Fixes from the same “[a]ll”
  that touch the same file share one note: undoing one marks them all undone. Two notes on the same target undone
  together are both put back, without a false ✖. A service enabled but stopped is said not undoable rather than
  falsely restored, and fixed ~/.ssh rights can be undone.
- **Vanguard better withstands attacks on itself** (attack campaign of Oct. 23, 18 weaknesses fixed, each with its
  test). The backup key can revoke a stolen main key (“revoque principale” at the end of the manifest, which 0.85
  copies still read): kept in the sealed state, the main key is never accepted again, and the highest version seen
  starts over. The signed Mac program only comes from a master build, without cache. As root, a program in a folder
  others can change is no longer replaced. State files are read only when they are plain files of bounded size (a
  named pipe froze monitoring forever); deleted along with the seals, they are “unknown” and everything is said again,
  and the check says the seals were remade; real-time, its reminder, the audit, the sites and the gateway already
  reported are sealed (a pause set by another program no longer pauses anything); a critical file changed again is
  notified again; writing no longer follows links, and root no longer writes into an account's folder. Undoing a block
  never replays a command read back from the log: it is rebuilt from the noted address, port or value. The USB key:
  its Ventoy menu and ISO images (by size) enter the manifest, and a recognized key whose serial number changed is
  reported. Local network: UPnP is read only at the gateway (a device claiming to be the router is reported), never
  towards this machine or another host, and listening goes on after an oversized datagram; DNS is also tested on
  randomly drawn names. The MalwareBazaar list is only unpacked up to its announced size, and the sshd log only counts
  lines written by root. A second pass against these fixes closed their bypasses: a VANGUARD key without a reference,
  where other keys have theirs, is a medium warning (changing its token too no longer brings it down to information),
  and only a reference carrying its token accuses it of a changed identifier (an unreadable identifier no longer
  accuses anything); an updated 0.85 no longer looks like deleted seals, and deleting the history along with them no
  longer makes a first pass; the time of the last look at Downloads and the unblocked threats already reported are
  sealed; undoing only puts back a copy of Claude Code settings made by Vanguard; “put back as before” for the gaming
  settings only rewrites as root what Vanguard puts in /etc; the quarantine no longer follows links and root no longer
  writes into an account's folder there; UPnP listening no longer counts oversized datagrams; the ThreatFox export is
  bounded like the MalwareBazaar list; and a tag named master no longer reuses a cache on the Mac.
- **A problem recognized by its rule and its object, no longer by its translated text.** Open ports, suspicious
  autostarts, browser extensions, forgotten accounts or new administrators, stalkerware, remote control tools,
  outdated software and the VANGUARD key's record now carry a key (“LNX-RES-001|port:8080/tcp:python3”): switching
  language no longer brings back an alert marked as normal, no longer shows “new” problems in the history and
  re-notifies nothing in the monitoring. Earlier choices are found by their text, then completed with their key; a
  choice only covers its object (another program on the same port, another outdated version come back). On macOS, a
  launch agent is recognized by its file and what it launches, on Linux each suspicious autostart line by its
  fingerprint: a rewritten command or a line added to an already reported file is never silenced by an earlier choice.
  One choice per key, the most recent. Monitoring re-notifies an alert that gets worse without changing key (an
  extension that gains access to all sites); the history no longer shows “fixed” then “new” for software whose version
  changes while still out of date. The inventory of state files gains the device record, its locks, the takeover of an
  earlier version and the traces folder, and its test also reads the data folder's variables. The history keeps its
  first checksum unchanged and gains a second one, covering the keys and the network audit grades: a key is never
  outside a checksum, and a check without it is called not checked, compared on its text. The check's JSON gains
  `objet`, `cle` and `etat` (healthy, not applicable, not checked with its reason, problem).
- **A rule that returns nothing says “not checked”, never a silence read as healthy** (outside a list of tolerated
  rules that can only shrink). Wi-Fi is no longer silent when NetworkManager is missing (iwd, systemd-networkd):
  without a card, “nothing to judge”; with a card, not checked. On Windows, a network that netsh hides for lack of
  location access is called not checked; on macOS, unreadable stealth mode and Remote Login too. Only reading the
  firewall itself decides whether the grade holds: unreadable stealth mode no longer removes it on its own. Without
  NetworkManager, an unreadable network card list (/sys/class/net) gives “not checked”, never “no Wi-Fi card”. A “not
  applicable” finding no longer counts among the checks for the grade's reliability. `vanguard rules` also shows the
  network audit rules and the tools: a single registry of identifiers, checked by the tests, with the inventory of
  state files from which the seals take the list to protect.
- **Evidence before the action, and what Vanguard did in the traces.** Before stopping a program, quarantining a file
  or blocking an address, including on its own at night, Vanguard records what the action will erase: the program,
  its command line, its parent, its account, the file's SHA-256 fingerprint, the current connections. What cannot be
  read is noted "not possible (reason)", and the block happens anyway. The evidence is kept with the block ("What
  Vanguard changed" summarizes it); the quarantine keeps each file's fingerprint. "vanguard traces" now includes what
  Vanguard saw and did (07-vanguard.txt): its alerts, its blocks and quarantines with their evidence, and threads that
  link the alert, the evidence and the action about the same program or address; these landmarks enter the timeline,
  and Vanguard's state files are copied as they are so the MANIFEST covers them. A single path leads to the
  quarantine: the antivirus and YARA ones are now noted and undone with "vanguard blocking undo", like blocking's.
  The watcher judges programs with the same sources as blocking: it also recognizes MalwareBazaar's known
  fingerprints (those of the last 48 hours, the full list does not fit in its memory). Installing ClamAV or a
  third-party tool is noted like any fix.
  **"This is normal" for monitoring, the watcher and blocking.** An alert that keeps coming back for no reason (a
  development tool started from /tmp, a known device) can be declared normal for 90 days in What Vanguard has
  learned, and a threat offered for blocking with "i". The choice is about what the alert is about (the program, the
  address, the device), not its text, and is forgotten in the same place. The list is sealed: changed outside
  Vanguard, it silences nothing.
  **Optimize's previous values are sealed and checked.** reglages.json, whose values are put back as administrator to
  undo a setting, is sealed like Vanguard's state: rewritten by another program, it is no longer trusted (it is set
  aside, intact, and nothing from it is restored). Each value is also checked when put back: a known service state, a
  boolean, a number, IP addresses, a simple word; a value of any other form brings back the fresh-system one, written
  in the program.
  **Reviewed and tightened before release.** "This is normal" no longer silences a certain threat, and the alert of
  its block is never silenced; it keeps a program's reason and script (declaring python3 normal for a command that
  downloads no longer silences python3 running something else); an alert is offered only if its kind matches its
  key, and what it designates is shown before choosing. A reglages.json accepted without a seal is no longer resealed
  on reading: the check-up keeps saying so. The same file downloaded again after a quarantine is offered for
  blocking again. A file deleted from the Quarantine menu, or after a ClamAV scan, reads "deleted" in the traces,
  with its fingerprint recorded. Traces run with sudo read the data of the account that ran them, and a named pipe
  or a link in place of a state file no longer blocks them. The watcher no longer gets stuck on a file that does not
  respond (not hashed, reported as not checked); on Windows, the evidence no longer waits more than 3 seconds for WMI
  before stopping; a reused process number is no longer described in the evidence.
- **Public Wi-Fi mode** (`vanguard public-wifi`, Network and Internet › Public Wi-Fi mode). Turn it on when arriving
  at a café, a hotel or an airport, turn it off when leaving: the computer no longer accepts any connection from that
  network (an SSH session already open stays), file sharing and the announcement of its name are off (on macOS, the
  firewall closes sharing; Bonjour and AirDrop stay), and the DNS switches to the Canadian Shield “Protected”,
  encrypted on Linux when systemd-resolved answers (a resolver on the computer, such as NextDNS, or a DNS already
  encrypted and filtering, is kept). Incoming connections that could not be closed (no nft, unreadable firewall) are
  stated in the menu and the check, never “everything in place”. On Linux, a separate nftables table and services
  masked until restart, then mDNS, LLMNR and encrypted DNS on the public network's profile only; on Windows, Public
  category, firewall Public profile closed to incoming connections, NetBIOS off, in a single administrator prompt; on
  macOS, firewall set to “block all” and stealth mode. Each change is shown with its previous value, noted and sealed
  before the first command; turning off puts everything back in reverse order, read back, even after a crash or a
  restart (the menu and the check say so). A state changed outside Vanguard is never put back: safe shutdown instead,
  which only removes Vanguard's table. A firewall found off is turned on and never turned off again. `vanguard
  public-wifi portal` reopens the network's login page: encrypted DNS is relaxed until Enter, ten minutes at most, and
  the next launch makes it strict again if Vanguard was closed before. Nothing is sent to recognize a public network:
  a suggestion only. Tried on Linux (table set then removed in a separate namespace, previews); Windows and macOS:
  compiled and partly tested, not yet tried on a real system, nor encrypted DNS on a real public network.

- **Small safety fixes.** On Windows, system programs (netstat, netsh, powercfg, wevtutil, tasklist, schtasks,
  ipconfig, cmd, PowerShell…) are started by their path in System32, asked from Windows itself: a fake program of the
  same name placed next to Vanguard (Downloads) or in the current folder can no longer hide a port, a process or a
  setting; cmd no longer searches its current folder, and a test refuses any new start by bare name. The vulnerable
  drivers list (LOLDrivers) is only replaced by an answer that really is one: an error page no longer stops the check
  for a week. On macOS, a download's hash is computed in Rust, without md5 or shasum, and the Privacy check
  reads the permissions database with Vanguard's SQLite reader, without /usr/bin/sqlite3. Clean up: “Downloaded
  packages” is no longer recommended without paccache, and says it erases what lets you roll back. The menu,
  `--help` and the launcher use the showcase tagline (“Portable cyber defense for endpoints and networks”). Dead
  code removed and lighter dependencies (one crate less on Windows, fewer features compiled for reqwest, tokio and
  futures): 9 to 14 fewer libraries depending on the system.

- **Spyware.** `vanguard spyware` (or `logiciels-espions`; Antivirus and protection menu, last) looks for signs of
  spyware planted by someone close: current connections and recently asked names going to known spyware servers and
  sites (list from the Échap association, CC-BY 4.0, downloaded when used and kept a day, never embedded), known
  monitoring software installed or running (FlexiSPY, Spyrix, Refog, Ardamax…; parental control and employee
  monitoring called normal if installed on purpose), programs reading the keyboard (Linux: /dev/input; recognized:
  compositor, key remappers, Steam, OBS), Input Monitoring, Accessibility and Screen Recording permissions (macOS, read
  by a SQLite reader written for Vanguard). Everything is read in Rust, without external commands. Read-only: nothing
  is removed, since whoever planted it could notice; the screen says to keep screenshots and ask for help first. What
  could not be checked is counted, and the verdict is never “no spyware”. In the full check too, without network.
- **Outdated software.** `vanguard outdated-software` (or `logiciels-perimes`; Antivirus and protection menu, last; in
  the full check on Windows and macOS) compares the installed version of browsers (Chrome, Extended channel included,
  Edge, Firefox and ESR, Brave), Office, Acrobat and Reader, Java, 7-Zip, PuTTY and Slack with the latest published:
  public files from the publishers, endoflife.date and Homebrew (formula.json, also taken on Windows for 7-Zip and
  PuTTY, whose formulae follow upstream), downloaded in full once a day, the same for everyone (the list of your
  software never leaves; Settings › Software versions to turn it off). Version read in the file itself (a reader of .exe
  version resources written for Vanguard, Info.plist, Homebrew Cellar folder), all accounts as administrator;
  per-account Slack in its version folder, not its launcher. Firefox: each exploited flaw in CISA's catalog checked
  against your version (Mozilla security advisories); Edge Stable likewise, from the flaws Microsoft says each version
  fixes; a version older than the fix is critical. The others: the number of exploited flaws of the product in the
  catalog, without concluding for your version (Slack embeds Chromium, but its flaws do not carry over to it). What has
  no source (Edge Extended Stable, Acrobat 2020 and 2024, App Store) is said not checked, as is a Slack answer of an
  unexpected form (its API is undocumented), a disabled or deprecated Homebrew formula, or an Edge flaw list of another
  form; a browser that cannot be compared keeps the 60-days-without-update check, which leaves end of support. On Linux, the command points to the package manager. The zip reader (command guide) drops
  an entry whose content does not have the announced size, which could exceed its limit; gzip and zip join the fuzzing
  bench.
- **Update chain of trust.** A backup key, kept offline, also signs releases (if the main key is lost or stolen,
  updates go on); the main key can be encrypted, its passphrase asked once per release (`outils/signer-versions.sh`,
  `--secours`). Vanguard remembers the highest signed version already seen and refuses an older manifest; a latest
  signed version older than 45 days is no longer called “up to date”, but not verified. The macOS program is checked
  before it is signed (commit, checksum from its build log, universal Mach-O, version). The monitoring's local copy
  goes through the update path (never to an older version), and a new copy is tried before it replaces the old one
  (Linux and macOS).
- **Vanguard's state sealed.** `appris.json`, `integrite.json`, `surveillance-botnets.txt` and the versions already
  seen carry a BLAKE3 checksum: changed outside Vanguard (by a program trying to silence its alert), they no longer
  count and the check says so (COM-ETA-001); damaged, they never silence an alert.
- **Chain of trust, second review.** A copy here newer than the latest version signed on GitHub (installed from
  the key) no longer shows “nothing newer” but “not verified”: an old manifest may have been put back. A clock
  running behind no longer makes an old manifest look fresh: “not verified”. Deleting `sceaux.json` no longer makes
  the state files silently accepted as they are: they stay “adopted”, reported by the check (COM-ETA-001), and the
  versions already seen are then not trusted; the integrity reference is still used for comparing (a difference
  with it is still a difference, and moving to a new version does not stop monitoring), never remade without
  consent. The machine state from the last monitoring pass and the list of changes already reported by integrity
  monitoring are sealed too.
  `signer-versions.sh --secours` refuses an unencrypted backup key.
- **CI.** `/dev/root` read by its device number like findmnt, enable links of vanished systemd units left out like
  systemctl, local HTTP client time bound adjusted for Windows; `claude-journal.yml` analysis only.
- **Quality and delivery.** `outils/verifier.sh` builds the fuzzing bench and spends a few seconds on each target (two
  more: the SQLite reader and the Échap YAML list); CI spends five minutes per target every night. Tests that cannot
  run on a computer (missing tool, root of a namespace) say they were “skipped”: `verifier.sh` counts them next to the
  passed tests and gives their reasons. The text check and a keyboard test of the menus, in a real pseudo-terminal,
  are in the repository. CI runs `verifier.sh` itself (a single logic), the real distributions count, Windows runs on
  each push, and the delivered .exe (MinGW) is tried on a real Windows. A release page is only published if the VM ran
  that very .exe, and an .exe without its manifest (UTF-8, asInvoker) no longer builds. A single table of tools for
  the menu and the command line, compared by tests with the README, `--help`, the key's manual and the Structure
  table; `vanguard optimize` (including `undo`) joins the command line, and the help of the watcher, dangerous sites
  and latest flaws finds its command again. Signed version history: `vanguard self-check [program]` also checks a copy
  that is no longer the latest, changing nothing for copies already installed. Pinned Rust toolchain
  (`rust-toolchain.toml`) and a shared build recipe (`outils/compiler-version.sh`): two builds in two folders give the
  same program. Extensions: isolation on macOS too (sandbox-exec), and author checked by an Ed25519 signature of the
  folder, whose key is kept at approval. Windows test program down from 520 to 314 MB. A green that checked nothing no
  longer passes: under `verifier.sh --seulement` (the nightly CI audit), a skipped or unrun step fails and an unknown
  step name is refused (tried by `outils/essais-verifier.sh`); tests skipped on the real Windows and the Mac of CI are
  counted and shown; a fuzzing bench without targets fails; without `.github/hors-code.txt`, the night tests Windows
  and the Mac instead of skipping them. A failed download of the previous signed history no longer restarts it from
  scratch before deleting the previous pages: nothing is signed or published (`signer-versions.sh --premier` for the
  very first time). `vanguard self-check` run without a terminal no longer asks about the history, which quit before
  the final warning, and 0.85 is no longer said to be missing from the history. Isolation on macOS: no `open`, Apple
  Events, clipboard or plugged-in disks (/Volumes), through which an extension left the sandbox (profile not checked
  on a Mac).
- **Common base, no duplicates.** What all of Vanguard shares lives in `src/socle/`, once, tested once: Vanguard's
  folder, atomic write and lock (out of the network module), cache of downloaded lists (out of abuse.ch), an IP
  address's scope per the RFCs, home folder, Linux and macOS processes, JSON with comments, os-release,
  fingerprints; the package inventory leaves Gaming for `machine/linux/paquets.rs`, and `sha1_smol` and the
  hand-written MD5 give way to RustCrypto's sha1 and md-5, already pulled in by YARA-X (no extra crate). Some copies
  were wrong: an SSH attempt logged as “::ffff:192.168.1.5” looked like it came from the Internet; a Chrome policy
  with “1, // comment” before “}” was called unreadable; a held package had no version; a folder or a
  non-executable file with the same name passed for an installed program before a sudo command; an empty HOME made
  reads and writes start from the current folder. An unreadable /proc no longer counts as checked (spyware,
  keyboard readers, camera, remote control), and a /proc mounted with hidepid is reported. Threat lists and tldr
  are written by the atomic write (on Windows, Defender holding the old copy kept it in place). Run keys are read
  one way, the safest: “Is someone controlling my PC?” and “Spyware” also see RunOnce and malformed names, and
  “Spyware” reports an unreadable key. The check-up reads Wi-Fi through nl80211 and wlanapi, like the network
  audit (nmcli and netsh as fallbacks), and judges saved open networks the same way it does: the protection kept
  is the one Windows negotiated (a WPA2/WPA3 access point joined in WPA2 stays WPA2), two access points with the
  same name and different protections, with no known transmitter, defer to nmcli, and NetworkManager profiles are
  also read from /run (netplan) and /usr/lib, with nmcli as a fallback when a file is refused.

## October 22, 2026, evening: version 0.85

- **Release repository renamed** `d9v3/vanguard-update` (formerly vanguard-officiel). The old address redirects:
  Vanguard copies already installed still update.
- **Is this email a scam?** `vanguard suspicious-email <file.eml>` (Antivirus and protection menu, last) reads a saved
  email without opening anything: no link followed, no image loaded, no attachment run. It looks at the real sender
  (display name imitating a brand or hiding another address, replies sent elsewhere, look-alike domain), the SPF,
  DKIM and DMARC result written by the receiving provider — never one a sender slips further down, and a “pass” only
  counts when it surely comes from the provider —, each link (shown text against real address, offline link check,
  links rewritten by Safe Links unwrapped), the attachments (program, double extension, macros, web page, disk image,
  shortcut, password-protected archive, PDF that runs code) written under a neutral name in a disposable folder for
  YARA and the antivirus, never opened. After your consent, only the domain names leave the computer for their age
  and the public lists. MIME parsing written for Vanguard, bounded in size, depth and number of parts (a trapped email
  is marked incomplete, never said to be read). An Outlook .msg: the steps to save it as .eml. The verdict is never
  “safe”, and says what could not be checked.
- **The watcher (Linux).** Between two hourly monitoring runs, a program or a connection lasting a few minutes went
  unnoticed. The watcher, off by default and turned on only after its unit is shown (`vanguard watcher on`, or the
  Network and Internet menu), listens to two streams that Linux 6.6 and later opens to ordinary accounts: each
  program started, even one of a few milliseconds, and each TCP or UDP connection as it closes. Programs are judged
  as in the check (known offensive tool, command that downloads or hides what it runs, with their lineage:
  “npm → node → sh”), connections against the botnet command servers already downloaded; what is serious goes to
  the dashboard and as a notification, at a bounded rate. It stops nothing, without root or code loaded into the
  kernel. A program gone before it could be read is counted as such, never judged safe; the program of a closed
  connection is not known. The check says whether it is off, on, or on but stopped.
- **Remove Vanguard from this computer.** `vanguard uninstall` (Data menu) finds everything Vanguard placed here,
  without a register: the hourly monitoring, the monthly check-up, the automatic backup, the watcher (its unit
  recognised by its mark: a unit of the same name placed by someone else stays), the decoy files, the shortcut and its
  icon, the program copy, and what a version from before the name change had left. Everything is shown with what
  will be done, then checked; the data folder (device record, history, learning, quarantine) is never checked by default
  and asks for a second consent. Changes made to the system are first undone by their own tools, or said with the
  command that undoes them; the USB key is never touched. At the end: what was removed, kept, and what failed or could
  not be checked. No administrator rights.
- **Shortcut removed with its icon** (Linux): `shortcut off` left the icon behind; it goes too, if it is really
  Vanguard's.
- **Monitoring that no longer runs is said.** The check-up verifies that the program started by the hourly monitoring
  and by the monthly check-up still exists (and rsync for the backup), not only the task, and says how to put it back.
- **Missed runs caught up.** Turned on now, monitoring catches up a missed hour on Windows (computer off or asleep) and
  runs five minutes after sign-in; on Linux, it catches up on wake-up the hour missed during sleep and runs five
  minutes after sign-in; on macOS, right at sign-in. Monitoring already in place is not changed silently: the
  check-up says it is "from an earlier version", and `vanguard monitor on` updates it.
- **Enforced anti-phishing protection turned off, seen.** A Chrome, Chromium, Brave, Edge or Firefox policy (a file
  in /etc on Linux, the registry on Windows, policies.json), read the way the browser reads it, that turns off Safe
  Browsing overrides Settings, which can no longer turn it back on: unwanted software uses this. The check-up says so,
  with where to remove it; a merely recommended policy counts as long as the person has not chosen. Unreadable browser
  settings or policies no longer pass for protection turned on.
- **A DNS that does not block dangerous sites is said.** The check-up reports it (information) and points to "Fastest
  DNS", where CIRA's Canadian Shield "Protected" or Quad9 is set in one choice, undoable. Nothing is said when a DNS
  already protects, or when nothing can tell (NextDNS, Pi-hole).
- **Latest exploited flaws** (`vanguard latest-flaws [--days N]`). Those CISA added to its catalog in the last days
  (7 by default), newest first, with those used by ransomware; on Arch, those affecting a package on this computer
  first. The check-up also gives the date an exploited flaw was added.
- **Actively exploited flaws first** (Linux, Arch). The CVEs of known flaws in installed packages are compared with
  CISA's KEV catalog (flaws with a known real attack), downloaded whole: the software list does not leave the computer.
  An exploited flaw makes the finding critical and comes first, even without a published fix; without the catalog, it
  is said. A flaw in a package with a program listening on the network (a service through its systemd unit, without
  root rights) comes first, at least high. Hourly monitoring notifies a new critical flaw (exploited, or critical for the distribution); the others,
  which change every day, stay in the check-up.
- **Dangerous sites blocked** (`vanguard dangerous-sites on|off`). URLhaus hosts and ThreatFox command server domains
  (abuse.ch key) are sent nowhere (0.0.0.0 and ::) by the hosts file, after your consent and with administrator
  rights. Vanguard's block sits between two dated markers: `off` removes it exactly, the rest of the file never
  changes. Writing checks the checksum of the prepared file and of the hosts file read at the start: nothing is
  written if either changed in between. The check-up says when the list is more than a week old. On Windows, 5,000
  names at most (beyond that, the DNS client slows down); elsewhere, 20,000. In the Protection menu, with "Latest
  exploited flaws"; `uninstall` reminds you to remove them first.
- **Site that distributes malware, reported.** The names this computer asked for (DNS cache: no rights needed on
  Windows, root on Linux) are compared with URLhaus hosts, with the abuse.ch key: "Who talks to the Internet?" shows
  it, and hourly monitoring notifies it once (antivirus scan, downloaded files). Without the list, it is said; the exact
  name only, so as not to accuse a whole host.
- **Frozen Feodo Tracker list, said.** abuse.ch has not updated its botnet server list since March 4, 2026 (a single
  address). Without ThreatFox (no abuse.ch key), it was the only list read, and nothing said it was frozen: "Who talks
  to the Internet?", the check-up, blocking and the watcher now say so among what could not be checked. Its addresses
  still count; with the key, ThreatFox follows the same botnets up to date.

## October 22, 2026: version 0.84.1

- **AI servers open to the network, now seen on Macs too.** The rule that spots a local AI server (Ollama, LM Studio,
  llama.cpp…) reachable from the network now reads the Mac's listening ports; until now it was always reported as not
  checked on macOS. Programs are named in full: a name cut at nine characters was not recognized, and an open server
  would have passed as safe. Each socket keeps the program of its own address: an AI server open to the Wi-Fi is no
  longer hidden by another program holding the same port on the machine itself. Without administrator rights, only
  the current account's programs are named, and "no AI server" says so; if lsof does not answer, the rule stays not
  checked. Threat blocking benefits too.
- **Forced SSH login, on Macs.** With no sshd, neither listening on port 22 or on the ssh port of /etc/services, nor
  running (a Homebrew sshd on another port), nor started by a launchd plist, there is nothing to read and Vanguard
  says so, instead of marking the rule not checked at every check-up; with one, the rule stays not checked (macOS's
  unified log is not read), never safe.
- **Test benches without an abuse.ch key.** On GitHub's Mac, on Linux and in the Windows VM, the YARA scan passes when
  Vanguard reports the MalwareBazaar fingerprints as not checked for lack of a key, and the exact-fingerprint match is
  tried on a copy laid down for the test, then removed: nothing depends any more on the lists closed on October 21.
- **Presentation.** Vanguard now presents itself as portable cyber defense for endpoints and networks (README,
  features page, repository description, files on the key), in professional wording: the router, the local network,
  the public Internet address. The GitHub Pages features page is rebuilt at each release
  again: it had stayed at 0.82, the program being launched by a relative path from another folder.

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
  emojis, working without the Internet, real-time protection, hourly monitoring, monthly check-up, learned alerts,
  blocking, extension restrictions and the abuse.ch key. Each change shows the previous value and the command to put it back; learned alerts and blocking open
  their own screen ("What Vanguard has learned", Threat blocking). Language, emojis and working without the Internet
  stay chosen from one launch to the next (VANGUARD_LANG, VANGUARD_EMOJI and VANGUARD_HORS_LIGNE always win).
- **Vanguard's real-time protection turns off, for a while or until turned back on** (Settings, or `vanguard settings
  real-time no --for 1h|4h`): the hourly monitoring and the active protection of blocking stop at once, after your
  consent and the list of what stops, without their settings changing. It comes back by itself when the time is up;
  while it is off, this is said again at the top of the menu and on its Monitoring and Blocking lines, in each check-up
  (with no effect on the grade), in "Who talks to the Internet?", in blocking and on the monitoring dashboard, by a
  notification at the first run then every day, and in the monthly check-up: a program that turned it off quietly would
  be seen. Defender, the firewall and UAC are never touched, and a block already made stays in place.
- **Extensions: your own programs in Vanguard, without touching its code** (menu 12 Extensions,
  `vanguard extensions`). A plugin is a folder with a `plugin.toml` manifest, added once from a folder or a .zip
  archive (`vanguard plugin add`); a lab script is a file dropped as it is (`vanguard lab`), to try an idea quickly.
  Their findings are shown apart, never count in the grade, and go into a separate section of the HTML report with
  `--report`. To write a plugin in Rust: the `extensions/sdk` library, with no dependency, and a complete example.
- **An extension is checked before it runs.** Before your consent, its whole folder or archive is scanned (YARA,
  MalwareBazaar fingerprints) and every file hashed (SHA-256): a file changed, added or removed, and it must be approved
  again. The checked copy is what runs, without access to the terminal, with a bounded time and output: beyond them, it
  is stopped along with everything it started; on Linux, what it leaves behind is stopped as well when it ends by
  itself. An archive cannot write anything outside its folder. On Linux, `--isolated` runs it without network, the home
  folder hidden. A manifest can only ask for full trust or to run with the check or the monitoring: it is granted by a
  separate question, and the consent falls at the slightest change. As administrator, nothing in the extensions folder
  lifts a safeguard: nothing there runs by itself, and each run is asked for. The **Restrictions** switch
  (Extensions › 3, Settings, or for a single plugin or script) turns these safeguards off for what is yours; one thing
  stays: the extensions folder must be yours, closed to other accounts.
- **YARA-X 1.22.0**, which fixes eight known flaws in wasmtime, the library YARA runs on, one of them on Apple silicon
  Macs. Every library used is now checked at each version and every night (cargo deny): known flaws, licenses
  compatible with the GPL, origin (crates.io only). The two remaining advisories, with no published fix, come from
  YARA-X and do not apply to the way Vanguard uses it (the reason is written down).
- **Calculations checked in the released version** (ANSSI guide, LANG-ARITH): a number that overflows on hostile data
  (a size read in a network packet, a log, a Windows program) stops the check concerned instead of silently wrapping
  to zero and skewing what follows; the rest of the check goes on.
- **abuse.ch lists with your key.** On October 21, abuse.ch closed its public lists: MalwareBazaar, URLhaus and
  ThreatFox now require a free key, created at auth.abuse.ch. Vanguard takes it in Settings or in "Who talks to the
  Internet?", keeps it on this computer (readable by the account only), shows it only masked and never writes it in a
  displayed address or a log. Without a key, or with a refused key, these lists are reported as not checked, never as
  clean; Feodo Tracker stays keyless.
- **Linux read without extra commands.** A D-Bus client written for Vanguard reads failed services, boot time and disk
  health (UDisks2), instead of systemctl, systemd-analyze and busctl; GNOME settings and Flatpak app permissions are
  read from their files (GVDB); the systemd journal and its compressed data (zstd) are read in Rust, with journalctl and
  pacman kept as fallbacks. On macOS, administrator accounts are read through the system library, without dscl.
- **Each released program carries the list of its dependencies** (cargo auditable): anyone can check it against known
  flaws with `cargo audit bin`, and a known flaw stops the release. cargo audit joins cargo deny in every check, and
  unsound code is refused across the whole dependency tree.
- **Hostile input put to the test**: property tests on the readers of data that comes from elsewhere (router, DNS, HTTP,
  DHCP lease, logs, AI agent settings, Windows drivers and events) and a fuzzing bench. Two crashes found and fixed: an
  outsized date in a macOS lease, and a nested "cmd /c" that overflowed the stack. File size sums are bounded, a file
  that crashes the YARA scan is still matched against the fingerprints, and a DNS measurement whose thread crashes is
  reported as not checked.
- **Rescue key tools**: the key keeps itself up to date even when it stays plugged in (program and images every day,
  new images looked for on the 1st and the 15th, each download announced), Ventoy is checked on the key and its update
  offered, then done without erasing anything after the password; Windows 11 is flagged past six months.
- **Reporting a flaw**: SECURITY.md says how (GitHub's private reporting), what to include, and what follows the fix
  (a published security advisory, a CVE if the flaw warrants one).
- **Security review.** An attack tool is certain only by the name of the program itself: a script run by an interpreter
  that bears the tool's exact name (python3 laZagne.py) is only a doubt, and a name that merely starts like the tool
  (python3 sharphound_parser.py) is no longer reported. The program is checked again at the very moment it is stopped
  (its number could have passed to another one). The ufw rule that closes a port goes before the allow rules, and the
  port is reported closed only once checked. In automatic mode, an address where another account has an established
  connection is never blocked. An unreadable settings file (settings, blocking, extensions) is first copied aside, as it
  is, before being rewritten; for extensions, nothing is written until it could be set aside.

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
