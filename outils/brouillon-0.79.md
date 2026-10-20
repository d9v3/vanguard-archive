# Brouillon du paragraphe 0.79 de CHANGELOG.md et CHANGELOG.en.md

À relire, puis à coller en tête des deux fichiers au moment de `/livrer`, et à retirer ensuite (ce fichier n'est pas
fait pour être publié). Date à ajuster au jour de la publication. Les lignes marquées ⟨branche 0.79⟩ viennent du
travail resté sur l'ordinateur (branche `0.79`), décrit seulement d'après le résumé de la session : à vérifier contre
`git log` avant de coller.

À faire avant `/livrer` : installer `musl`, `clang` et `mingw-w64-gcc` (YARA-X compile un peu de C), et mettre à jour
la ligne clippy de CLAUDE.md : `outils/verifier.sh` passe aux cibles Mac `CC_<cible>=clang` et
`CFLAGS_<cible>=-ffreestanding -nostdlibinc -I outils/mac-entetes` (laissé tel quel ici : CLAUDE.md a une
modification en cours sur l'ordinateur).

---

## 20 octobre 2026 : version 0.79

- **Linux, le bilan voit plus loin.** Redirections ICMP acceptées (IPv4 et IPv6) et filtre des adresses d'origine
  coupé, corrigés dans `99-vanguard.conf` sans jamais relâcher une interface réglée en strict ; espaces de noms
  ouverts à tous les programmes (une information : Flatpak, Chrome et Steam en ont besoin) ; dossiers de commandes
  (PATH, celui de sudo) que d'autres comptes peuvent modifier, où une fausse commande prendrait la place de la vraie ;
  pas de blocage après des mots de passe faux, mots de passe de moins de 8 caractères (PAM).
- **SSH.** Ports renvoyés ouverts à tout le réseau (`GatewayPorts`), affichage X11 renvoyé, trop d'essais de mot de
  passe par connexion ; corrigés par un rechargement de sshd, qui ne coupe aucune connexion en cours. Algorithmes
  cassés (SHA-1 pour l'échange de clés, CBC, 3DES, arcfour, MD5, DSA) rouverts dans la configuration, lue dans
  l'ordre exact des Include : retirés par une ligne de `00-vanguard.conf`, vérifiée par `sshd -t` avant le
  rechargement.
- **Windows.** Recherche automatique du proxy (WPAD), par laquelle un appareil d'un Wi-Fi public peut détourner la
  navigation ; aucun blocage des comptes après des mots de passe faux (corrigé comme Windows 11 : 10 essais,
  10 minutes) ; longueur minimale des mots de passe. Un compte sans mot de passe exigé est décrit tel qu'il est
  (« accepte un mot de passe vide ») ⟨branche 0.79⟩, avec la marche à suivre pour lui en donner un.
- **macOS.** Découverte automatique du proxy allumée ; dossiers de commandes ouverts à tous.
- **Guide des commandes : 980 commandes** (38 de plus), surtout pour la sécurité et le dépannage : lynis, programmes
  SUID, comptes bloqués, ClamAV, signatures gpg, WireGuard, certificats, exposition des services, needrestart, sbctl,
  dnf needs-restarting ; sous Windows, réseau public ou privé, dossiers partagés, puce TPM, signature d'un programme,
  effacement de l'espace libre, test de la mémoire ; sous macOS, ce qui se lance tout seul, accès à la caméra, au
  micro et à l'écran, empreinte d'un fichier, trafic par programme. Les exemples de tldr-pages se renouvellent aussi
  pendant la surveillance et l'entretien du mois, sans ouvrir le guide.
- **Secrets dans les projets git.** Vanguard relit l'historique des projets du dossier personnel, où un mot de passe,
  une clé d'API ou un jeton écrit un jour reste, même effacé ensuite : clés reconnues à leur forme (AWS, GitHub,
  GitLab, Google, Stripe, Slack…), clés privées, mots de passe dans une adresse ou dans le code ; gitleaks, s'il est
  installé, ajoute ses règles. Aucun secret n'est affiché ni gardé.
- **YARA sans rien installer.** Les 308 règles sont appliquées par YARA-X (le moteur YARA en Rust de VirusTotal,
  licence BSD), compilé dans Vanguard sous Linux, Windows et macOS : plus de moteur à installer ni à proposer, et
  quatre fichiers lus à la fois. Un fichier de plus de 256 Mo ou plus long que 30 s à analyser est dit, jamais compté
  comme sain. Le programme passe d'environ 10 à 25 Mo.
- **Outils libres reconnus, s'ils sont installés.** « Failles des images Docker » : trivy dit les failles connues,
  graves ou critiques, des images Docker ou Podman ; absent, Vanguard propose de l'installer par l'outil du système. Après
  des connexions SSH ratées, le bilan dit si fail2ban, sshguard ou CrowdSec bloque déjà les adresses qui insistent.
- **Windows, les portes dérobées classiques.** Débogueur posé sur un programme d'accessibilité de l'écran de
  connexion (IFEO, SilentProcessExit), sethc ou utilman remplacés par cmd, Shell ou Userinit de Winlogon détournés,
  AppInit_DLLs, abonnements WMI qui lancent une commande : au bilan, suivis par la surveillance, corrigés quand
  l'état d'origine est connu exactement, sinon la marche à suivre. Et les journaux d'événements des 7 derniers
  jours : rafales de mots de passe faux par le réseau, journal de sécurité effacé, comptes créés, services installés
  suspects ; sans droits administrateur, le journal de sécurité est dit illisible, jamais sain.
- **Linux, les signes d'un rootkit.** Processus cachés, programmes qui tournent sans fichier (memfd, effacés, lancés
  depuis /tmp ou /dev/shm), module du noyau qui se cache ou modules non signés inconnus, carte réseau en mode
  promiscuité ; lus dans /proc et /sys en quelques millisecondes. Pas de correction automatique : la marche à suivre,
  avec rkhunter et chkrootkit en deuxième avis.
- **Empoisonneur de noms démasqué.** Pendant le scan du réseau, sans le ralentir, Vanguard demande en LLMNR, NetBIOS
  et mDNS un nom tiré au hasard, qui n'existe pas : l'appareil qui y répond est un outil comme Responder, qui vole
  les mots de passe Windows du réseau. Alerte élevée, et notification de la surveillance horaire.
- **Collecter les traces** (Dépanner, `vanguard traces`, et première étape d'« Après une infection », cochée
  d'office). Avant de nettoyer, ce qu'un spécialiste voudra voir, dans un dossier daté sur la clé ou dans le dossier
  de Vanguard : processus avec l'empreinte SHA-256 de leur programme, connexions, ce qui se lance tout seul, bilan en
  JSON, comptes, journaux des 7 derniers jours, fichiers récents ; un LISEZMOI et un MANIFESTE que `sha256sum -c`
  vérifie. Lecture seule, rien n'est envoyé ; Vanguard prévient que le dossier contient des données personnelles.
- **« Qui parle à Internet ? »** reconnaît les serveurs de commande de botnets (liste de Feodo Tracker, abuse.ch ;
  indisponible ou trop vieille, c'est dit, jamais comptée comme vide), et le dossier temporaire du compte où qu'il
  soit (un TEMP déplacé laissait passer un programme lancé de là).
- **Nettoyage de Windows** : chemins écrits en entier, jamais le dossier courant quand une variable comme TEMP est
  vide ⟨branche 0.79⟩ ; la file d'impression se vide sans risque ⟨branche 0.79⟩.
- **Pour les tests** : scripts PowerShell du programme analysés et rejoués avec pwsh à chaque vérification
  ⟨branche 0.79⟩ ; test de la machine virtuelle Windows qui compte les étapes sautées, compare chaque passe à la
  précédente ⟨branche 0.79⟩ et vérifie les réglages de la 0.79 ; scripts déposés depuis Linux et lancés par la VM
  sur son accord ⟨branche 0.79⟩.
- **Relecture indépendante avant la publication** : un compte au mot de passe vide qu'une correction aurait fait
  passer pour sain, une limite d'essais SSH trop stricte qui pouvait fermer la porte, un `chmod` qui aurait cassé
  `/tmp` mis dans le PATH ; corrigés.

---

## October 20, 2026: version 0.79

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
  An account that does not require a password is described as it is (“accepts an empty password”) ⟨0.79 branch⟩,
  with the steps to give it one.
- **macOS.** Automatic proxy discovery on; command folders open to all.
- **Command guide: 980 commands** (38 more), mostly for security and troubleshooting: lynis, SUID programs, locked
  accounts, ClamAV, gpg signatures, WireGuard, certificates, service exposure, needrestart, sbctl, dnf
  needs-restarting; on Windows, public or private network, shared folders, TPM chip, a program's signature, wiping
  free space, memory test; on macOS, what starts by itself, camera, microphone and screen access, a file's
  fingerprint, traffic per program. The tldr-pages examples are also renewed by the monitoring and the monthly
  check-up, without opening the guide.
- **Secrets in git projects.** Vanguard reads the history of the home folder's projects, where a password, API key
  or token written once stays, even when deleted later: keys recognized by their shape (AWS, GitHub, GitLab, Google,
  Stripe, Slack…), private keys, passwords in an address or in the code; gitleaks, when installed, adds its rules. No
  secret is shown or kept.
- **YARA with nothing to install.** The 308 rules are applied by YARA-X (VirusTotal's YARA engine in Rust, BSD
  license), compiled into Vanguard on Linux, Windows and macOS: no engine to install or offer any more, and four
  files read at once. A file over 256 MB or taking more than 30 s to scan is reported, never counted as clean. The
  program grows from about 10 to 25 MB.
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
  default). Before cleaning up, what a specialist will want to see, in a dated folder on the key or in Vanguard's
  folder: processes with their program's SHA-256 fingerprint, connections, what starts by itself, the check as JSON,
  accounts, logs of the last 7 days, recent files; a README and a manifest that `sha256sum -c` checks. Read-only,
  nothing is sent; Vanguard warns that the folder holds personal data.
- **“Who talks to the Internet?”** recognizes botnet command servers (Feodo Tracker's list, abuse.ch; when
  unavailable or too old, it says so, never counts it as empty), and the account's temporary folder wherever it is (a
  moved TEMP let a program started from there go unnoticed).
- **Windows cleanup**: paths written in full, never the current folder when a variable such as TEMP is empty
  ⟨0.79 branch⟩; the print queue empties safely ⟨0.79 branch⟩.
- **For testing**: the program's PowerShell scripts parsed and replayed with pwsh at each check ⟨0.79 branch⟩;
  Windows virtual machine test that counts skipped steps, compares each run with the previous one ⟨0.79 branch⟩ and
  checks the 0.79 settings; scripts dropped from Linux and run by the VM with its consent ⟨0.79 branch⟩.
- **Independent review before the release**: an account with an empty password that a fix would have shown as
  healthy, an SSH attempt limit strict enough to lock the door, a `chmod` that would have broken `/tmp` put in PATH;
  fixed.
