# Brouillon du paragraphe 0.79 de CHANGELOG.md et CHANGELOG.en.md

À relire, puis à coller en tête des deux fichiers au moment de `/livrer`, et à retirer ensuite (ce fichier n'est pas
fait pour être publié). Date à ajuster au jour de la publication. Les lignes marquées ⟨branche 0.79⟩ viennent du
travail resté sur l'ordinateur (branche `0.79`), décrit seulement d'après le résumé de la session : à vérifier contre
`git log` avant de coller.

---

## 20 octobre 2026 : version 0.79

- **Linux, le bilan voit plus loin.** Redirections ICMP acceptées (IPv4 et IPv6) et filtre des adresses d'origine
  coupé, corrigés dans `99-vanguard.conf` sans jamais relâcher une interface réglée en strict ; espaces de noms
  ouverts à tous les programmes (une information : Flatpak, Chrome et Steam en ont besoin) ; dossiers de commandes
  (PATH, celui de sudo) que d'autres comptes peuvent modifier, où une fausse commande prendrait la place de la vraie ;
  pas de blocage après des mots de passe faux, mots de passe de moins de 8 caractères (PAM).
- **SSH.** Ports renvoyés ouverts à tout le réseau (`GatewayPorts`), affichage X11 renvoyé, trop d'essais de mot de
  passe par connexion ; corrigés par un rechargement de sshd, qui ne coupe aucune connexion en cours.
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
- **« Qui parle à Internet ? »** reconnaît le dossier temporaire du compte où qu'il soit (un TEMP déplacé laissait
  passer un programme lancé de là).
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
  attempts per connection; fixed by reloading sshd, which cuts no connection in progress.
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
- **“Who talks to the Internet?”** recognizes the account's temporary folder wherever it is (a moved TEMP let a
  program started from there go unnoticed).
- **Windows cleanup**: paths written in full, never the current folder when a variable such as TEMP is empty
  ⟨0.79 branch⟩; the print queue empties safely ⟨0.79 branch⟩.
- **For testing**: the program's PowerShell scripts parsed and replayed with pwsh at each check ⟨0.79 branch⟩;
  Windows virtual machine test that counts skipped steps, compares each run with the previous one ⟨0.79 branch⟩ and
  checks the 0.79 settings; scripts dropped from Linux and run by the VM with its consent ⟨0.79 branch⟩.
- **Independent review before the release**: an account with an empty password that a fix would have shown as
  healthy, an SSH attempt limit strict enough to lock the door, a `chmod` that would have broken `/tmp` put in PATH;
  fixed.
