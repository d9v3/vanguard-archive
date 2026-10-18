# Developing Gardien

[Français](CONTRIBUTING.md) · **English**

The code, its comments and its internal names are in French; every text shown to the user exists in both languages
(`tr!("fr", "en")` in `src/langue.rs`).

With Claude Code: `CLAUDE.md` gives the project's commands and rules, `/verifier` and `/livrer` (`.claude/skills/`)
check everything and ship a version; a hook reformats Rust after each edit. On GitHub, `@claude` in an issue or a
pull request gets an answer, and each “journal” issue is analyzed by itself (`.github/workflows/claude*.yml`, to
turn on once with `/install-github-app`).

## Layout

| File | Purpose |
|---|---|
| `src/main.rs` | menu and subcommands |
| `src/ui.rs` | colors, titles, frames, bars, lines wrapped and aligned within 76 columns |
| `src/selection.rs` | keyboard menus and checklists (arrows, Enter, Esc or Backspace), word search in menus |
| `src/langue.rs` | language choice and translation macros |
| `src/machine/mod.rs` | shared types, display, parallel execution of the checks |
| `src/machine/linux/`, `src/machine/windows/`, `src/machine/macos/` | per-system audit, one file per topic |
| `src/machine/dns.rs`, `certificats.rs`, `extensions.rs`, `sante.rs`, `wifi.rs` | checks shared by the three systems |
| `src/corriger.rs` | guided application of fixes |
| `src/reseau.rs`, `src/scan.rs` | network scan (TCP connect, without root), ARP, network notebooks |
| `src/risk.rs` | knowledge base of ports and risk levels |
| `src/connexion.rs` | connection test for gaming |
| `src/antivirus.rs` | ClamAV / Defender, quarantine |
| `src/yara.rs`, `src/pieges.rs` | YARA scan (bundled rules, system engine); decoy files against ransomware |
| `src/surveillance.rs` | systemd timer / Task Scheduler / launchd agent, notifications |
| `src/rapport.rs`, `src/historique.rs` | HTML report, check history, grade curve |
| `src/reparer.rs`, `src/maj.rs`, `src/gaming/` | repairs, updates, gaming |
| `src/optimiser/` | privacy, performance and comfort settings, with exact undo |
| `src/nettoyer/` | cleanup: items per system, space measured before and after |
| `src/logiciels/` | software to install: checked catalog (`catalogue.rs`), state and installation per system |
| `src/fuites.rs`, `src/donnees.rs` | leaked passwords, data backup |
| `src/guide/` | command guide: one file per system (`linux.rs`, `windows.rs`, `macos.rs`, `tous.rs`), menus and search (`mod.rs`) |
| `src/apprentissage.rs` | what Gardien learns here: alerts declared normal (appris.json), habits |
| `src/listes_noires.rs` | the home's Internet address in blocklists (DNSBL), after consent |
| `src/entretien.rs` | monthly check-up: grade, updates, space, new problems, in one notification |
| `src/alertes.rs` | alerts on the phone through ntfy: random topic, messages without IP or MAC |
| `src/sortantes.rs` | who talks to the Internet: established connections by program (ss, PowerShell, lsof), reverse DNS |
| `src/lien.rs` | is this link dangerous? local check (punycode, imitated brands…), then RDAP, URLhaus, Spamhaus DBL, SURBL |
| `src/telechargement.rs` | check a downloaded file: checksum by the system's tool, name and content, YARA and antivirus |
| `src/canaux.rs`, `src/nat.rs` | crowded Wi-Fi (nearby networks by channel); NAT type (home-made STUN client) |
| `src/dns_rapide.rs` | fastest DNS: measurement, protecting DNS kept, setting undone through `optimiser/` |
| `src/cameras.rs` | hidden cameras: maker, RTSP stream, ONVIF discovery (WS-Discovery), web page |
| `assets/oui.tsv` | manufacturers by MAC prefix (IEEE list), stored as sorted tables at compile time (`build.rs`) |
| `assets/yara/` | ReversingLabs YARA rules (MIT license), gathered by `outils/maj-yara.sh` |
| `assets/icones/`, `assets/gardien.ico` | the logo, computed by `outils/icone.py` |
| `LICENCES-TIERCES.txt` | license notices of the included libraries (`outils/licences-tierces.py`) |

## Build, test, deploy

Requirements: `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu` and `mingw-w64-gcc`.

```sh
outils/deployer.sh     # builds Linux (musl, static) + Windows, installs locally, pushes to GitHub, updates the key
```

Tests: `cargo test` (Linux, in a throwaway data folder: never the computer's real data); Windows tests under Wine
(`cargo test --target x86_64-pc-windows-gnu` with a Wine runner); `cargo clippy --all-targets` on the four targets
(Linux, Windows, `aarch64-apple-darwin`, `x86_64-apple-darwin`), in strict mode (pedantic), without any warning;
`cargo fmt --check`. Internal functions are tested in their module; `tests/programme.rs` runs the real program the
way a person would (help in both languages, menus left, lists, refusals respected, audit and scan of 127.0.0.1 in
JSON), with a throwaway home folder, without the user's key or session. Full runs: `outils/test-linux/essai.sh`, `outils/test-macos/essai.sh` (on a GitHub Mac) and, in
the Windows virtual machine, `TESTER-GARDIEN.bat` (dropped there by `deployer.sh`).

macOS: built and tested on a GitHub Mac (`.github/workflows/macos.yml`, universal Apple Silicon + Intel binary),
every night if the code changed or on demand (`gh workflow run macos.yml`). `deployer.sh` fetches the latest
successful build for the key.

Continuous integration (`.github/workflows/ci.yml`): on each push to GitHub, formatting, clippy without warnings on
the four targets and the tests, on Linux; on a real Windows (PowerShell, registry), every night if the code changed,
on each pull request and on demand (`gh workflow run ci.yml`). Not Windows or Mac on each push: on a private
repository, their minutes count double and ten times.

Dead links: `outils/liens.py` opens every link of the repository (documentation, the program's code except tests,
scripts, licences) and checks the internal links of the Markdown pages: target file, heading of an anchor, downloads
of the latest release. It runs by itself before each push by `deployer.sh` and before each release page; CI checks
the internal links (`--hors-ligne`). A dead link stops the push, a doubtful one (a site refusing programs, a server
down) is only shown. Links that cannot be opened as they are (an API endpoint, a namespace) are described in
`outils/liens.txt`.

## Screenshots and social preview

`outils/captures.py` retakes the README screenshots (`assets/captures/`, in French and English) and the repository's
social preview (`assets/partage.png`). `deployer.sh` runs it for each new version, since the menu shows its number,
and commits the images separately.

Gardien really runs there, in an 80-column pseudo-terminal, from a fake key and on a copy of the data: nothing real is
touched. The network becomes “Salon”; MAC addresses (vendor prefix kept), IP addresses (a made-up network, lengths and
order kept), device names and the account's folders are replaced, at random on each run; only an excerpt of the
machine check with nothing personal in it is shown. Then the privacy guard rereads each image: if a detail of the
home were still visible, none is written.

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

What is personal is read on the computer, never written in the repository: `~/.config/gardien-dev/confidentiel.txt`
(one phrase per line: name, emails, address…), the global Git identity, the home folder, the devices and MAC
addresses of Gardien's database, the saved Wi-Fi networks. Other people's data (the key visits friends, and their
error journal comes back here) is recognized by its shape: account of a home folder, email, Windows SID; a journal
issue is masked before it is sent, MAC and IP addresses included. `python3 outils/confidentialite.py --depot`
rereads the whole repository and its history. In tests, made-up values: MAC addresses keeping the vendor prefix,
network “Salon”, accounts “alice”, “bob”, “Zoé”, “Jean Dupont”, emails `@example.com`.

Rust keeps the libraries' path in the programs (`/home/<account>/.cargo/registry/…`): to publish a version, build
with `rustflags = ["--remap-path-prefix=/home/<account>=~"]` in `~/.cargo/config.toml` (`publier-version.sh` refuses
a program that still contains the home folder).

## Publishing a version

`outils/publier-version.sh` creates the version's GitHub release with the three programs
(`gardien-windows-x86_64.exe`, `gardien-linux-x86_64`, `gardien-macos`), their SHA-256 checksums and, as notes, the
version's commit (title and bullets); the README's download links always point to the latest one. `deployer.sh`
runs it by itself at the end of the deployment of a new version. After each push, it also updates the repository
page (`outils/github.py`): English description followed by the version, link, topics and options, written in
`.github/depot.json`. Only the social preview image is changed by hand (Settings > Social preview).

## The USB key

The key (exFAT, label `GARDIEN`, marker file `gardien.cle`) holds `Linux/`, `Windows/`, `macOS/`, `donnees/` (device
database, portable), `source/` (this repository) and the guide in two languages (`README.txt`, `LISEZMOI.txt`, taken
from `outils/`). The check history and the quarantine stay on each computer.

On the development PC, it updates itself (systemd units in `outils/systemd/`, installed by
`outils/systemd/installer.sh`): after each build (`gardien-copie.service`), and each time it is plugged in, with the
latest version from GitHub, built if it is new (`gardien-cle.service`, `deployer.sh --branchement`).

The key has two partitions: `GARDIEN`, read-only everywhere except on its owner's computer (GPT attribute honored by
Windows; on Linux and macOS, Gardien remounts it read-only itself), and `GARDIENLOG`, which only receives the error
log, anonymized. `outils/preparer-cle.sh` prepares a new key.

In preparation, a rescue key that also boots computers: `outils/cle-secours.sh` (Ventoy for Windows 11, Omarchy and
SystemRescue, an HFS+ partition for the macOS recovery of Intel Macs, `GARDIEN` and `GARDIENLOG` as before).
`--plan` and `--essai` (on a disk image) touch no disk; only `--ecrire` erases the key.

## Errors and crashes

Gardien records them with nothing personal (on the key, or in its folder when the key is not plugged in). On
deployment, `deployer.sh` brings them back and `outils/journal-vers-github.py` turns them into GitHub issues (label
“journal”) with `gh`: one issue per error, repeats as comments. No GitHub password in the program or on the key.

## Former names

Gardien was called netscan (up to 0.10), then Sentinel (up to 0.50). It takes over what those names left on a
computer: data folder (renamed once), key and journal partition (`sentinel.cle`, `sentinel-journal.cle` markers,
`SENTINEL` and `SENTINELLOG` labels), monitoring (timer, scheduled task, launchd agent), firewall rules, files placed
in `/etc`, backups, the `SENTINEL_LANG` and `SENTINEL_HIBP_CLE` variables. The `sentinel` and `netscan` commands start
`gardien`.
