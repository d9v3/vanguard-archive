# Developing Vanguard

[Français](CONTRIBUTING.md) · **English**

The code, its comments and its internal names are in French; every text shown to the user exists in both languages
(`tr!("fr", "en")` in `src/langue.rs`).

With Claude Code: `CLAUDE.md` gives the project's commands and rules, `/verifier` and `/livrer` (`.claude/skills/`)
check everything and ship a version; a hook reformats Rust after each edit. On GitHub, `@claude` in an issue or a
pull request gets an answer, and each “journal” issue is analyzed automatically (`.github/workflows/claude*.yml`, to
turn on once with `/install-github-app`).

## Layout

| File | Purpose |
|---|---|
| `src/main.rs` | menu and subcommands |
| `src/ui.rs` | colors, titles, frames, bars, lines wrapped and aligned within 76 columns |
| `src/selection.rs` | keyboard menus and checklists (arrows, Enter, Esc or Backspace), word search in menus |
| `src/prediction.rs` | prediction of the word being typed, the same in every menu: its end in grey, Tab completes it |
| `src/langue.rs` | language choice and translation macros |
| `src/machine/mod.rs` | shared types, display, parallel execution of the checks |
| `src/machine/regles.rs` | registry of check rules: each one is declared where it is written (`inventory::submit!`), with a stable identifier (“LNX-PLT-001”); `vanguard rules` lists them |
| `src/machine/linux/plateforme.rs` | platform security according to fwupd (HSI), kernel lockdown, BPF, user namespaces, auditd: the first rules of the registry |
| `src/machine/linux/`, `src/machine/windows/`, `src/machine/macos/` | per-system audit, one file per topic; on Windows, accounts (NetUserEnum, group S-1-5-32-544) and startup (Run keys through winreg, .lnk shortcuts read in Rust) without PowerShell, which stays as a fallback |
| `src/plist.rs` | reader for Apple plists, XML and binary (“bplist00”), instead of defaults and plutil; bounded against a hostile file (size, depth, number of values, looping references) |
| `src/machine/windows/portes.rs`, `evenements.rs` | classic backdoors (debugger on a sign-in screen accessibility program through IFEO or SilentProcessExit, sethc and utilman replaced, Winlogon's Shell and Userinit, AppInit_DLLs, WMI subscriptions), fixed when the original state is known; event logs of the last 7 days (bursts of wrong passwords from the network, security log cleared, accounts created, suspicious services) |
| `src/machine/linux/dissimulation.rs`, `algorithmes_ssh.rs` | rootkit signs read from /proc and /sys: hidden processes, programs without a file (memfd, deleted, /tmp), a kernel module that hides, unknown unsigned modules, a card in promiscuous mode; broken sshd algorithms (configuration read in Include order), removed through `00-vanguard.conf` after `sshd -t` |
| `src/machine/dns.rs`, `certificats.rs`, `extensions.rs`, `partages.rs`, `sante.rs`, `wifi.rs`, `bluetooth.rs` | checks shared by the three systems (partages.rs: file shares open to everyone; bluetooth.rs: visible computer, recently paired devices) |
| `src/machine/unix.rs` | checks shared by Linux and macOS: secret files, sudo |
| `src/machine/heure.rs`, `fin_de_support.rs`, `comptes_oublies.rs`, `mots_de_passe.rs`, `sensibles.rs` | clock set automatically; system, abandoned programs and browsers without updates; unused accounts; unprotected browser passwords; sensitive files lying around |
| `src/changements.rs` | what Vanguard changed: each fix run by `machine::appliquer_chacune`, noted on the computer |
| `src/sauvegarde.rs`, `src/raccourci.rs`, `src/mise_a_jour.rs`, `src/a_laisser.rs` | guided automatic backup (Déjà Dup or rsync, Time Machine, File History) and check my backup (the rsync copy read back without cache, random files compared with their original; a newer original is not an error); shortcut on this computer; updating its copy from the key (version engraved in the program, read without running it) or from GitHub (`mise_a_jour/github.rs`: Ed25519-signed manifest published in d9v3/vanguard-officiel, the program's size, checksum and version checked); report to leave with the person you helped |
| `src/corriger.rs` | guided application of fixes |
| `src/reseau/mod.rs`, `src/reseau/scan.rs` | network scan (TCP connect, without root), ARP, network notebooks |
| `src/reseau/nmap.rs` | service versions with nmap -sV, when installed: deep scan of a local network device, on the ports already found open |
| `src/reseau/empoisonnement.rs` | name poisoner (Responder): a random name that does not exist, asked over LLMNR, NetBIOS and mDNS during the scan; the device that answers both tries is flagged (packets written and read in Rust) |
| `src/risk.rs` | knowledge base of ports and risk levels |
| `src/reseau/connexion.rs` | connection test for gaming |
| `src/protection/antivirus.rs` | ClamAV / Defender, quarantine |
| `src/protection/yara.rs`, `src/protection/pieges.rs` | YARA scan (bundled rules, YARA-X compiled into the program); decoy files against ransomware |
| `src/protection/empreintes.rs` | MalwareBazaar SHA-256 fingerprints (abuse.ch, CC0): full list every week (zip archive), recent ones every day, kept in Vanguard's folder and sorted; the YARA scan looks up every file it reads |
| `src/protection/outil.rs`, `src/protection/secrets_git.rs`, `src/protection/conteneurs.rs` | secrets in git project history (Vanguard's rules, plus gitleaks when present); open source tools run when installed, installation offered otherwise (trivy on Docker or Podman images) |
| `src/reseau/surveillance.rs` | systemd timer / Task Scheduler / launchd agent, notifications |
| `src/reseau/tableau.rs` | monitoring dashboard: alert log (bounded in number and age), single-file local HTML page (state, alerts by day, new devices, connections to botnets) |
| `src/rapport.rs`, `src/historique.rs` | HTML report, check history, grade curve |
| `src/reparer.rs`, `src/maj.rs`, `src/gaming/` | repairs, updates, gaming |
| `src/optimiser/` | privacy, performance and comfort settings, with exact undo; startup programs (`demarrage.rs`); Windows Defender blocking: ASR rules, network protection, PUA, controlled folder access (`defender.rs`) |
| `src/nettoyer/` | cleanup: items per system, space measured before and after |
| `src/logiciels/` | software to install: checked catalog (`catalogue.rs`), state and installation per system |
| `src/protection/fuites.rs`, `src/donnees.rs` | leaked passwords, data backup |
| `src/protection/cle.rs` | USB drive protection on Linux and macOS: partition remounted read-only away from the owner's computer |
| `src/guide/` | command guide: one file per system (`arch.rs`, `omarchy.rs`, `fedora.rs`, `debian.rs`: each distribution's programs and step-by-step guides; `linux.rs`: programs common to all, and openSUSE; `windows.rs`, `macos.rs`, `tous.rs`), menus and search (`mod.rs`), commands run here (`lancement.rs`), tldr-pages examples downloaded every week and copied to the key at deployment (`tldr.rs`, `outils/tldr-cle.sh`) |
| `src/apprentissage.rs` | what Vanguard learns here: alerts declared normal (appris.json), habits |
| `src/reseau/listes_noires.rs` | the home's Internet address in blocklists (DNSBL), after consent |
| `src/entretien.rs` | monthly check-up: grade, updates, space, new problems, in one notification |
| `src/protection/sortantes.rs` | who talks to the Internet: established connections by program (ss, PowerShell, lsof), reverse DNS; botnet command servers (Feodo Tracker, list kept like URLhaus's) |
| `src/protection/environnement.rs` | at startup: library injected into the session (LD_PRELOAD, DYLD, AppInit_DLLs), judged like preloading |
| `src/protection/manifeste.rs` | check Vanguard itself (version, commit date, SHA-256) and key manifest (BLAKE3 checksums kept on the owner's computer, one reference per key, compared in the check) |
| `src/protection/cles_connues.rs` | VANGUARD keys known to this computer (`vanguard.jeton` token written at deployment, `cles-connues.json`); per key, the checksum of the record as Vanguard wrote it and its protection: a record changed outside Vanguard is neither read nor rewritten |
| `src/protection/distance.rs` | is someone controlling my PC? remote control tools (installed, at boot, running, downloaded), in the check and as a guided walkthrough |
| `src/protection/lien.rs` | is this link dangerous? local check (punycode, imitated brands…), then RDAP, URLhaus, Spamhaus DBL, SURBL |
| `src/protection/telechargement.rs` | check a downloaded file: checksum by the system's tool, name and content, YARA and antivirus; programs landing in Downloads, for monitoring |
| `src/protection/quarantaine.rs`, `src/protection/camera.rs` | reversible quarantine (antivirus, YARA): isolate, put back exactly, delete; camera and microphone: who uses them (registry on Windows, /dev/video and pactl on Linux) |
| `src/protection/acces.rs` | privacy check: apps that can access location, contacts, camera and microphone (ConsentStore on Windows, Flatpak and Snap on Linux, TCC.db on macOS); read-only |
| `src/reseau/canaux.rs`, `src/reseau/nat.rs` | crowded Wi-Fi (nearby networks by channel); NAT type (home-made STUN client) |
| `src/dns_rapide.rs` | fastest DNS: measurement, protecting DNS kept, setting undone through `optimiser/` |
| `src/reseau/cameras.rs` | hidden cameras: maker, RTSP stream, ONVIF discovery (WS-Discovery), web page |
| `src/reseau/objets.rs` | router and connected devices: what the router announces (SNMP, UPnP, web header), admin over HTTP only, devices recognized by maker, name, ports and announcements; default-password advice, never checked (no attempt, nothing more probed); scan section and `vanguard iot` from the notebook |
| `src/depanner/` | troubleshoot step by step: the paths (`mod.rs`), network and Wi-Fi (`reseau.rs`), sound (`son.rs`), printer (`imprimante.rs`), after an infection (`infection.rs`), new computer (`nouveau.rs`), computer leaving (`depart.rs`), hacked account (`compte.rs`), a relative's computer (`proche.rs`: three questions, a summary of five points at most ordered by the answers, tips for the page to leave behind), slow since an update (`depuis_maj.rs`) |
| `src/traces/` | collect the traces: processes with their SHA-256, network, startup, JSON check, accounts, logs of the last 7 days, recent files, then LISEZMOI and MANIFESTE (`sha256sum -c` format), in a dated folder; shared part (`mod.rs`), per system (`linux.rs`, `windows.rs`, `macos.rs`, `unix.rs`); read-only |
| `src/lenteur.rs`, `src/fiche.rs` | why it is slow (two-sample snapshot, startup); computer specs |
| `src/copier.rs` | copy my files to an external disk: checked copy (BLAKE3), resume, never overwrites; check a copy (restore test) |
| `src/verifier_cle.rs` | check my drive: real capacity, speeds and bad blocks, written into the free space and read back without cache, then erased |
| `src/passage.rs` | takeover of what a version from before the name change left (data, timers, shortcut, firewall rules); to be removed at 1.0 |
| `src/ordinateurs.rs` | my computers: each computer's visit noted on VANGUARDLOG (categories and levels only) |
| `src/chiffrement.rs` | protected key data: encrypted record (XChaCha20-Poly1305), data key kept by the owner and wrapped by the passphrase (Argon2id) |
| `assets/oui.tsv` | manufacturers by MAC prefix (IEEE list), stored as sorted tables at compile time (`build.rs`) |
| `assets/yara/` | ReversingLabs YARA rules (MIT license), gathered by `outils/maj-yara.sh` |
| `assets/banniere-blanche.png`, `assets/banniere-noire.png`, `assets/icones/`, `assets/vanguard.ico` | the banner (no background, one per GitHub theme) and the icon (the V), drawn cell by cell in the terminal banner's lettering by `outils/icone.py` |
| `LICENCES-TIERCES.txt` | license notices of the included libraries (`outils/licences-tierces.py`) |

### Adding a check rule

A rule is written in its topic's file and declared there, with no central list:

```rust
inventory::submit! {
    crate::machine::regles::Regle {
        id: "LNX-NOY-002",                 // system, area, number: stable, never reused
        systeme: crate::machine::regles::Os::Linux,
        sujet: ("BPF réservé à root", "BPF reserved for root"),
        references: &["kernel.org : unprivileged_bpf_disabled"],
        verifier: || bpf().into_iter().collect(),
    }
}
```

The check runs it in parallel with the others, in rank order (`rang`: 10 for the firewall, 100 and up for the system,
500 and up for the common rules), and each of its findings carries its identifier up to the JSON report. The checks
from before the registry are declared in their system's `regles.rs` and in `src/machine/regles_communes.rs`; a new one
is better declared next to its check, with the `regle!` macro.
The judgment is written separately (`juger_…`, reading nothing from the system), to be tested on made-up data.

## Build, test, deploy

Requirements: `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu`, `musl` (musl-gcc), `mingw-w64-gcc`
and `clang`: YARA-X compiles a little C for each target (clang for clippy on the Mac targets, see
`outils/verifier.sh`).

```sh
outils/deployer.sh     # builds Linux (musl, static) + Windows, installs locally, pushes to GitHub, updates the key
```

Slow check? `VANGUARD_CHRONO=1 vanguard audit --json >/dev/null` gives each check's time (they run at the same time:
the slowest one sets the duration).

Tests: `cargo test` (Linux, in a throwaway data folder: never the computer's real data); Windows tests under Wine
(`cargo test --target x86_64-pc-windows-gnu` with a Wine runner); `cargo clippy --all-targets` on the four targets
(Linux, Windows, `aarch64-apple-darwin`, `x86_64-apple-darwin`), in strict mode (pedantic), without any warning;
`cargo fmt --check`. Internal functions are tested in their module; `tests/programme.rs` runs the real program the
way a person would (help in both languages, menus left, lists, refusals respected, audit and scan of 127.0.0.1 in
JSON), with a throwaway home folder, without the user's key or session. Full runs: `outils/test-linux/essai.sh`, `outils/test-macos/essai.sh` (on a GitHub Mac) and, in
the Windows virtual machine, `TESTER-VANGUARD.bat` (dropped there by `deployer.sh`).

macOS: built and tested on a GitHub Mac (`.github/workflows/macos.yml`, universal Apple Silicon + Intel binary),
every night if the code changed or on demand (`gh workflow run macos.yml`). `deployer.sh` fetches the latest
successful build for the key.

Continuous integration (`.github/workflows/ci.yml`): on each push to GitHub, formatting, clippy without warnings on
the four targets and the tests, on Linux; on a real Windows (PowerShell, registry), every night if the code changed,
on each pull request and on demand (`gh workflow run ci.yml`). Not Windows or Mac on each push: on a private
repository, their minutes count double and tenfold.

Dead links: `outils/liens.py` opens every link of the repository (documentation, the program's code except tests,
scripts, licenses) and checks the internal links of the Markdown pages: target file, heading of an anchor, downloads
of the latest release. It runs by itself before each push by `deployer.sh` and before each release page; CI checks
the internal links (`--hors-ligne`). A dead link stops the push, a doubtful one (a site refusing programs, a server
down) is only shown. Links that cannot be opened as they are (an API endpoint, a namespace) are described in
`outils/liens.txt`.

## Screenshots and social preview

`outils/captures.py` retakes the README screenshots (`assets/captures/`, in French and English) and the repository's
social preview (`assets/partage.png`). `deployer.sh` runs it for each published version, since the menu shows its
number, and commits the images separately.

Vanguard really runs there, in an 80-column pseudo-terminal, from a fake key and on a copy of the data: nothing real is
touched. The network becomes “Salon”; MAC addresses (vendor prefix kept), IP addresses (a made-up network, lengths and
order kept), device names and the account's folders are replaced, at random on each run; only an excerpt of the
machine check with nothing personal in it is shown. Then the privacy guard rereads each image: if a detail of the
home is still visible, none is written.

```sh
uv run --no-project --with pyte python outils/captures.py [program] [--connexion | --sans-connexion]
```

## Privacy

`outils/confidentialite.py` keeps personal details from reaching GitHub. It runs by itself: on each commit (added
lines, file names, author, message), before each push by `deployer.sh`, before each release page (notes and compiled
programs), before each journal issue and before writing the screenshots. Once per copy of the repository:

```sh
git config core.hooksPath outils/hooks                                     # pre-commit and commit-msg hooks
git config user.email "<id>+<account>@users.noreply.github.com"           # commits without your email
```

What is personal is read on the computer, never written in the repository: `~/.config/vanguard-dev/confidentiel.txt`
(one phrase per line: name, emails, address…), the global Git identity, the home folder, the devices and MAC
addresses of Vanguard's database, the saved Wi-Fi networks. Other people's data (the key visits friends, and their
error journal comes back here) is recognized by its shape: account of a home folder, email, Windows SID; a journal
issue is masked before it is sent, MAC and IP addresses included. On GitHub, the CI runs it again on the commits of
each push and each pull request (`--generique --plage`): only data recognized by its shape, without the identity of the
machine running it. `python3 outils/confidentialite.py --depot`
rereads the whole repository and its history. In tests, made-up values: MAC addresses keeping the vendor prefix,
network “Salon”, accounts “alice”, “bob”, “Zoé”, “Jean Dupont”, emails `@example.com`.

Rust keeps the libraries' path in the programs (`/home/<account>/.cargo/registry/…`): to publish a version, build
with `rustflags = ["--remap-path-prefix=/home/<account>=~"]` in `~/.cargo/config.toml` (`publier-version.sh` refuses
a program that still contains the home folder).

## Publishing a version

`outils/publier-version.sh` creates the version's GitHub release with the three programs
(`vanguard-windows-x86_64.exe`, `vanguard-linux-x86_64`, `vanguard-macos`), their SHA-256 checksums and, as notes, the
commit of each version since the previous release (title and bullets), the newest first; the README's download
links always point to the latest one. `--notes` shows these notes without publishing anything.

Every version goes to the key, the VM and GitHub (the code), but not every one gets a release: `deployer.sh`
publishes a 0.x.0 by itself, and a 0.x.y only with `deployer.sh --publier` (an important fix). Fewer releases mean
fewer Mac minutes on GitHub, and fewer new programs that Defender and SmartScreen do not know yet; nothing is lost,
since the next release takes over the versions before it. GitHub's Mac builds at night when the code changed, and
for each release: the key's macOS version can lag behind the other two, and the deployment says so. After each push,
it also updates the repository page (`outils/github.py`): English description followed by the latest published
version, link, topics and options, written in `.github/depot.json`. Only the social preview image is changed by hand (Settings > Social preview).

## The USB key

The key (exFAT, label `VANGUARD`, marker file `vanguard.cle`) holds `Linux/`, `Windows/`, `macOS/`, `donnees/` (device
database, portable), `source/` (this repository) and the guide in two languages (`README.txt`, `LISEZMOI.txt`, taken
from `outils/`). The check history and the quarantine stay on each computer.

On the development PC, it updates itself (systemd units in `outils/systemd/`, installed by
`outils/systemd/installer.sh`): after each build (`vanguard-copie.service`), and each time it is plugged in, with the
latest version from GitHub, built if it is new (`vanguard-cle.service`, `deployer.sh --branchement`).

The key has two partitions: `VANGUARD`, read-only everywhere except on its owner's computer (GPT attribute honored by
Windows; on Linux and macOS, Vanguard remounts it read-only itself), and `VANGUARDLOG`, which only receives the error
log, anonymized. `outils/preparer-cle.sh` prepares a new key.

In preparation, a rescue key that also boots computers: `outils/cle-secours.sh`. Ventoy boots the Omarchy
installer, Arch, Debian and Fedora as network installers, SystemRescue (and Windows 11 as a fallback), kept up
to date by `outils/images-cle.sh` (each project's signature checked, weekly timer, copy on plug-in); a FAT32 `WIN11` partition installs Windows 11 with Secure Boot on,
without adding a key to the PC (`install.wim` split by wimlib under the 4 GB limit); an HFS+ partition holds the macOS
recovery of Intel Macs; `VANGUARD` and `VANGUARDLOG` as before. `--plan` and `--essai` (on a disk image) touch no disk;
only `--ecrire` erases the key.

## Errors and crashes

Vanguard records them with nothing personal (on the key, or in its folder when the key is not plugged in). On
deployment, `deployer.sh` brings them back and `outils/journal-vers-github.py` turns them into GitHub issues (label
“journal”) with `gh`: one issue per error, repeats as comments. No GitHub password in the program or on the key.
