//! Guide : les commandes communes à toutes les distributions de Linux, puis ce que plusieurs partagent (ufw,
//! firewalld) et openSUSE, rangé dans « Autres Linux ». Chaque distribution a son fichier (arch, omarchy, fedora,
//! debian).

use super::{Obstacle, Programme, changer, voir};

/// Les programmes de toutes les distributions : chaque Linux du guide les montre après les siens.
pub const COMMUNS: &[Programme] = &[
    Programme {
        nom: "systemctl",
        role: ("services : état, démarrage", "services: status, start, stop"),
        executable: "systemctl",
        commandes: &[
            voir("systemctl --failed", "Les services en échec.", "Failed services."),
            voir(
                "systemctl status <service>",
                "État d'un service, avec ses dernières lignes de journal.",
                "A service's status, with its latest log lines.",
            ),
            voir(
                "systemctl list-units --type=service --state=running",
                "Les services qui tournent.",
                "Running services.",
            ),
            voir(
                "systemctl list-timers",
                "Les minuteries : ce qui se lance tout seul, et quand.",
                "Timers: what starts by itself, and when.",
            ),
            voir(
                "systemctl --user status <service>",
                "Un service de ta session plutôt que du système.",
                "A service of your session rather than of the system.",
            ),
            changer(
                "sudo systemctl restart <service>",
                "Redémarre un service.",
                "Restarts a service.",
            ),
            changer(
                "sudo systemctl enable --now <service>",
                "Lance un service et le garde au démarrage.",
                "Starts a service and keeps it at boot.",
            ),
            changer(
                "sudo systemctl disable --now <service>",
                "Arrête un service et le retire du démarrage.",
                "Stops a service and removes it from boot.",
            ),
            changer(
                "sudo systemctl daemon-reload",
                "Relit les fichiers des services après une modification.",
                "Reloads the service files after a change.",
            ),
            voir(
                "systemd-analyze blame",
                "Ce qui ralentit le démarrage, du plus lent au plus rapide.",
                "What slows down boot, slowest first.",
            ),
        ],
    },
    Programme {
        nom: "journalctl, coredumpctl",
        role: ("journaux, plantages", "logs, crashes"),
        executable: "journalctl",
        commandes: &[
            voir(
                "journalctl -b -p err",
                "Les erreurs depuis le démarrage (avec sudo si le journal du système ne s'affiche pas).",
                "Errors since boot (with sudo if the system log does not show).",
            ),
            voir(
                "journalctl -b -1 -p warning",
                "Les avertissements du démarrage précédent : après un plantage ou un gel.",
                "Warnings from the previous boot: after a crash or a freeze.",
            ),
            voir(
                "journalctl -f",
                "Le journal en direct (Ctrl-C pour arrêter).",
                "The log, live (Ctrl-C to stop).",
            ),
            voir(
                "journalctl -u <service> -n 50",
                "Les 50 dernières lignes d'un service.",
                "A service's last 50 lines.",
            ),
            voir(
                "journalctl -k -b",
                "Les messages du noyau : pilotes, matériel, disques.",
                "Kernel messages: drivers, hardware, disks.",
            ),
            voir(
                "journalctl --since \"1 hour ago\"",
                "Tout ce qui s'est passé depuis une heure.",
                "Everything from the last hour.",
            ),
            voir(
                "journalctl --list-boots",
                "Les démarrages enregistrés.",
                "Recorded boots.",
            ),
            voir(
                "journalctl --disk-usage",
                "La place prise par les journaux.",
                "The space taken by the logs.",
            ),
            changer(
                "sudo journalctl --vacuum-time=2weeks",
                "Efface les journaux de plus de deux semaines.",
                "Deletes logs older than two weeks.",
            ),
            voir(
                "coredumpctl list",
                "Les programmes qui ont planté, avec la date.",
                "Programs that crashed, with the date.",
            ),
            voir(
                "coredumpctl info <programme>",
                "Le détail du dernier plantage de ce programme.",
                "Details of this program's last crash.",
            ),
        ],
    },
    Programme {
        nom: "flatpak",
        role: ("applications Flatpak", "Flatpak apps"),
        executable: "flatpak",
        commandes: &[
            voir(
                "flatpak list --app",
                "Les applications Flatpak installées.",
                "Installed Flatpak apps.",
            ),
            changer("flatpak update", "Les met à jour.", "Updates them."),
            voir(
                "flatpak search <mot>",
                "Cherche une application (Flathub).",
                "Searches for an app (Flathub).",
            ),
            changer(
                "flatpak install flathub <id>",
                "Installe une application (ex. org.mozilla.firefox).",
                "Installs an app (e.g. org.mozilla.firefox).",
            ),
            changer(
                "flatpak uninstall <id>",
                "Désinstalle une application.",
                "Removes an app.",
            ),
            changer(
                "flatpak uninstall --unused",
                "Retire les bibliothèques qui ne servent plus.",
                "Removes libraries no longer used.",
            ),
            voir(
                "flatpak info --show-permissions <id>",
                "Ce qu'une application a le droit de faire : fichiers, réseau, caméra…",
                "What an app is allowed to do: files, network, camera…",
            ),
        ],
    },
    Programme {
        nom: "ip, ss",
        role: ("adresses, routes, ports ouverts", "addresses, routes, open ports"),
        executable: "ip",
        commandes: &[
            voir(
                "ip -br a",
                "L'adresse de chaque carte réseau, en bref.",
                "Each network card's address, in brief.",
            ),
            voir(
                "ip route",
                "Les routes : « default via » donne l'adresse de la box.",
                "Routes: “default via” gives the router's address.",
            ),
            voir(
                "ip neigh",
                "Les appareils vus récemment sur le réseau (table ARP).",
                "Devices recently seen on the network (ARP table).",
            ),
            voir(
                "ip -s link",
                "Les compteurs de chaque carte : octets, erreurs, pertes.",
                "Each card's counters: bytes, errors, drops.",
            ),
            voir(
                "ss -tulpn",
                "Les ports en écoute et leur programme (avec sudo : tous les programmes).",
                "Listening ports and their program (with sudo: every program).",
            ),
            voir(
                "ss -tp",
                "Les connexions TCP en cours et leur programme.",
                "Current TCP connections and their program.",
            ),
        ],
    },
    Programme {
        nom: "nmcli",
        role: ("Wi-Fi et connexions", "Wi-Fi and connections"),
        executable: "nmcli",
        commandes: &[
            voir(
                "nmcli device status",
                "L'état de chaque carte réseau.",
                "Each network card's state.",
            ),
            voir(
                "nmcli device wifi list",
                "Les Wi-Fi à portée, avec leur signal et leur sécurité.",
                "Wi-Fi networks in range, with their signal and security.",
            ),
            voir(
                "nmcli connection show",
                "Les connexions enregistrées.",
                "Saved connections.",
            ),
            changer(
                "nmcli --ask device wifi connect \"<nom>\"",
                "Se connecte à un Wi-Fi ; le mot de passe est demandé.",
                "Connects to a Wi-Fi network; the password is asked.",
            ),
            changer(
                "nmcli networking off && nmcli networking on",
                "Coupe puis rallume tout le réseau.",
                "Turns all networking off, then on again.",
            ),
        ],
    },
    Programme {
        nom: "resolvectl",
        role: ("DNS (systemd-resolved)", "DNS (systemd-resolved)"),
        executable: "resolvectl",
        commandes: &[
            voir(
                "resolvectl status",
                "Les serveurs DNS de chaque carte réseau.",
                "Each network card's DNS servers.",
            ),
            voir(
                "resolvectl query <site>",
                "L'adresse d'un site, et le serveur DNS qui a répondu.",
                "A site's address, and the DNS server that answered.",
            ),
            changer(
                "sudo resolvectl flush-caches",
                "Vide le cache DNS.",
                "Clears the DNS cache.",
            ),
        ],
    },
    Programme {
        nom: "lsblk, df, du",
        role: ("disques, partitions, place", "disks, partitions, space"),
        executable: "lsblk",
        commandes: &[
            voir(
                "lsblk -f",
                "Disques et partitions : système de fichiers, place, montage.",
                "Disks and partitions: file system, space, mount point.",
            ),
            voir(
                "lsblk -d -o NAME,SIZE,MODEL,ROTA",
                "Le modèle de chaque disque (ROTA 0 : SSD).",
                "Each disk's model (ROTA 0: SSD).",
            ),
            voir("df -h", "La place libre sur chaque disque.", "Free space on each disk."),
            voir(
                "du -sh * | sort -h",
                "La taille de chaque dossier ici, du plus petit au plus gros.",
                "The size of each folder here, smallest first.",
            ),
            voir(
                "sudo du -xh --max-depth=2 / | sort -h | tail -20",
                "Les 20 plus gros dossiers du système.",
                "The system's 20 largest folders.",
            ),
        ],
    },
    Programme {
        nom: "smartctl",
        role: ("santé des disques (smartmontools)", "disk health (smartmontools)"),
        executable: "smartctl",
        commandes: &[
            voir(
                "sudo smartctl -H /dev/<disque>",
                "Le verdict de santé d'un disque (PASSED : bon). Son nom, sda ou nvme0n1, vient de lsblk.",
                "A disk's health verdict (PASSED: good). Its name, sda or nvme0n1, comes from lsblk.",
            ),
            voir(
                "sudo smartctl -a /dev/<disque>",
                "Tout : heures d'usage, secteurs réalloués, usure, erreurs.",
                "Everything: hours of use, reallocated sectors, wear, errors.",
            ),
            voir(
                "sudo smartctl -t short /dev/<disque>",
                "Lance un court test du disque (2 minutes), lu ensuite avec -a.",
                "Starts a short disk self-test (2 minutes), read afterwards with -a.",
            ),
        ],
    },
    Programme {
        nom: "btrfs, fsck",
        role: ("vérifier un système de fichiers", "check a file system"),
        executable: "fsck",
        commandes: &[
            voir(
                "sudo btrfs filesystem usage /",
                "La vraie place libre sur btrfs (df peut se tromper).",
                "The real free space on btrfs (df can be wrong).",
            ),
            voir(
                "sudo btrfs device stats /",
                "Les erreurs de lecture et d'écriture vues sur le disque.",
                "Read and write errors seen on the disk.",
            ),
            changer(
                "sudo btrfs scrub start -B /",
                "Relit et vérifie toutes les données ; répare ce qui peut l'être.",
                "Rereads and checks all the data; repairs what can be repaired.",
            ),
            changer(
                "sudo fsck -f /dev/<partition>",
                "Vérifie et répare une partition NON montée, depuis une clé de secours ; jamais une partition en service.",
                "Checks and repairs an UNMOUNTED partition, from a rescue USB; never a partition in use.",
            ),
        ],
    },
    Programme {
        nom: "snapper, timeshift",
        role: ("instantanés du système", "system snapshots"),
        executable: "snapper",
        commandes: &[
            voir(
                "sudo snapper list",
                "Les instantanés (Omarchy, openSUSE) ; on revient à l'un d'eux depuis le menu de démarrage.",
                "Snapshots (Omarchy, openSUSE); you go back to one from the boot menu.",
            ),
            changer(
                "sudo snapper create --description \"<texte>\"",
                "Crée un instantané avant une manipulation risquée.",
                "Creates a snapshot before a risky operation.",
            ),
            voir(
                "sudo timeshift --list",
                "Les instantanés de Timeshift (Mint, Ubuntu).",
                "Timeshift snapshots (Mint, Ubuntu).",
            ),
            changer(
                "sudo timeshift --create --comments \"<texte>\"",
                "Crée un instantané avec Timeshift.",
                "Creates a snapshot with Timeshift.",
            ),
            changer(
                "sudo timeshift --restore",
                "Revient à un instantané (il est demandé lequel).",
                "Goes back to a snapshot (asks which one).",
            ),
        ],
    },
    Programme {
        nom: "hostnamectl, lspci, inxi",
        role: ("système et matériel", "system and hardware"),
        executable: "hostnamectl",
        commandes: &[
            voir(
                "hostnamectl",
                "Le nom de l'ordinateur, le système, le noyau, le modèle.",
                "The computer's name, system, kernel, model.",
            ),
            voir(
                "cat /etc/os-release",
                "La distribution et sa version exactes.",
                "The exact distribution and version.",
            ),
            voir("uname -r", "La version du noyau.", "The kernel version."),
            voir(
                "lscpu",
                "Le processeur : modèle, cœurs, fréquences.",
                "The processor: model, cores, frequencies.",
            ),
            voir(
                "lspci -k",
                "Les cartes internes (graphique, réseau, son) et le pilote de chacune.",
                "Internal cards (graphics, network, sound) and each one's driver.",
            ),
            voir("lsusb", "Les appareils USB branchés.", "Plugged-in USB devices."),
            voir(
                "inxi -Fxz",
                "Tout le matériel d'un coup, à copier dans un forum ; -z masque ce qui est personnel.",
                "All the hardware at once, to paste in a forum; -z hides what is personal.",
            ),
        ],
    },
    Programme {
        nom: "sensors, upower",
        role: ("températures, batterie", "temperatures, battery"),
        executable: "sensors",
        commandes: &[
            voir(
                "sensors",
                "Les températures et les ventilateurs (lm_sensors).",
                "Temperatures and fans (lm_sensors).",
            ),
            voir(
                "upower -i $(upower -e | grep BAT)",
                "La batterie : charge, usure (energy-full face à energy-full-design).",
                "The battery: charge, wear (energy-full versus energy-full-design).",
            ),
        ],
    },
    Programme {
        nom: "fwupdmgr",
        role: ("mises à jour du firmware", "firmware updates"),
        executable: "fwupdmgr",
        commandes: &[
            voir(
                "fwupdmgr get-devices",
                "Les appareils dont le firmware se met à jour : BIOS, SSD, station d'accueil…",
                "Devices whose firmware can be updated: BIOS, SSD, dock…",
            ),
            voir(
                "fwupdmgr refresh",
                "Télécharge la liste des firmwares récents.",
                "Downloads the list of recent firmware.",
            )
            .sauf(Obstacle::Administrateur),
            voir(
                "fwupdmgr get-updates",
                "Les mises à jour de firmware disponibles.",
                "Available firmware updates.",
            ),
            changer(
                "fwupdmgr update",
                "Les installe ; un redémarrage peut suivre.",
                "Installs them; a restart may follow.",
            ),
        ],
    },
    Programme {
        nom: "top, ps, kill",
        role: ("programmes en marche, mémoire", "running programs, memory"),
        executable: "ps",
        commandes: &[
            voir(
                "top",
                "Les programmes en direct (q pour quitter ; htop, s'il est installé, est plus lisible).",
                "Programs, live (q to quit; htop, if installed, is easier to read).",
            )
            .sauf(Obstacle::PleinEcran),
            voir(
                "ps aux --sort=-%mem | head",
                "Ceux qui prennent le plus de mémoire.",
                "The ones using the most memory.",
            ),
            voir(
                "ps aux --sort=-%cpu | head",
                "Ceux qui prennent le plus de processeur.",
                "The ones using the most CPU.",
            ),
            voir(
                "free -h",
                "La mémoire vive utilisée et libre, et le swap.",
                "Used and free memory, and swap.",
            ),
            voir(
                "pgrep -a <nom>",
                "Trouve un programme en marche par son nom, avec son numéro (PID).",
                "Finds a running program by name, with its number (PID).",
            ),
            changer(
                "kill <PID>",
                "Demande à un programme de se fermer.",
                "Asks a program to close.",
            ),
            changer(
                "kill -9 <PID>",
                "Le force à se fermer : il perd ce qui n'est pas enregistré.",
                "Forces it to close: it loses what is not saved.",
            ),
            changer(
                "pkill <nom>",
                "Ferme tous les programmes de ce nom.",
                "Closes every program with this name.",
            ),
        ],
    },
    Programme {
        nom: "sudo, chmod, chown",
        role: ("comptes et droits", "accounts and permissions"),
        executable: "sudo",
        commandes: &[
            voir(
                "id",
                "Ton compte et tes groupes (wheel ou sudo : administrateur).",
                "Your account and groups (wheel or sudo: administrator).",
            ),
            voir(
                "sudo -l",
                "Ce que tu as le droit de faire avec sudo.",
                "What you are allowed to do with sudo.",
            ),
            voir(
                "who",
                "Qui est connecté en ce moment, sur l'écran ou à distance.",
                "Who is logged in right now, on screen or remotely.",
            ),
            voir(
                "ls -l <fichier>",
                "Les droits d'un fichier : rwx pour toi, ton groupe, les autres.",
                "A file's permissions: rwx for you, your group, the others.",
            ),
            changer(
                "chmod 600 <fichier>",
                "Rend un fichier lisible par toi seul (clé, mot de passe).",
                "Makes a file readable by you only (key, password).",
            ),
            changer(
                "sudo chown -R $USER: <dossier>",
                "Te rend propriétaire d'un dossier, après un sudo de trop.",
                "Makes you the owner of a folder, after one sudo too many.",
            ),
            changer("passwd", "Change ton mot de passe.", "Changes your password."),
        ],
    },
    Programme {
        nom: "find, grep",
        role: ("chercher fichiers et textes", "find files and text"),
        executable: "find",
        commandes: &[
            voir(
                "find ~ -iname \"*<mot>*\"",
                "Cherche un fichier par son nom dans ton dossier personnel.",
                "Finds a file by name in your home folder.",
            ),
            voir(
                "find ~ -type f -size +1G",
                "Les fichiers de plus de 1 Go.",
                "Files larger than 1 GB.",
            ),
            voir(
                "find ~ -type f -mtime -1",
                "Les fichiers modifiés depuis 24 heures.",
                "Files changed in the last 24 hours.",
            ),
            voir(
                "grep -rni \"<texte>\" <dossier>",
                "Cherche un texte dans les fichiers d'un dossier.",
                "Searches for text in a folder's files.",
            ),
            voir(
                "journalctl -b | grep -i <mot>",
                "Filtre ce qu'une commande affiche (ici le journal) : seules les lignes avec ce mot restent.",
                "Filters what a command shows (here the log): only the lines with this word stay.",
            ),
        ],
    },
    Programme {
        nom: "rsync",
        role: ("copier, sauvegarder des dossiers", "copy, back up folders"),
        executable: "rsync",
        commandes: &[
            changer(
                "rsync -a --info=progress2 <source>/ <destination>/",
                "Copie un dossier entier ; relancée, elle ne recopie que ce qui manque.",
                "Copies a whole folder; run again, it only copies what is missing.",
            ),
            voir(
                "rsync -a --delete --dry-run <source>/ <destination>/",
                "Montre ce qu'un miroir exact effacerait ; sans --dry-run, il l'efface vraiment.",
                "Shows what an exact mirror would delete; without --dry-run, it really deletes it.",
            ),
        ],
    },
];

/// openSUSE, et ce que le guide ne range pas à part : les programmes communs y suffisent.
pub const AUTRES: &[Programme] = &[ZYPPER, FIREWALLD];

/// Les paquets d'openSUSE.
const ZYPPER: Programme = Programme {
    nom: "zypper",
    role: ("paquets : openSUSE", "packages: openSUSE"),
    executable: "zypper",
    commandes: &[
        changer(
            "sudo zypper refresh && sudo zypper update",
            "Met à jour openSUSE Leap.",
            "Updates openSUSE Leap.",
        ),
        changer(
            "sudo zypper dup",
            "Met à jour Tumbleweed, jusqu'à sa dernière version.",
            "Updates Tumbleweed, up to its latest snapshot.",
        ),
        changer(
            "sudo zypper install <paquet>",
            "Installe un paquet.",
            "Installs a package.",
        ),
        changer(
            "sudo zypper remove <paquet>",
            "Désinstalle un paquet.",
            "Removes a package.",
        ),
        voir("zypper search <mot>", "Cherche un paquet.", "Searches for a package."),
        voir(
            "zypper list-updates",
            "Les mises à jour disponibles.",
            "Available updates.",
        ),
        voir(
            "zypper list-patches --category security",
            "Les correctifs de sécurité qui manquent.",
            "Missing security patches.",
        ),
    ],
};

/// Le pare-feu d'Ubuntu, de Mint et d'Omarchy.
pub(super) const UFW: Programme = Programme {
    nom: "ufw",
    role: ("pare-feu (Ubuntu, Mint, Omarchy)", "firewall (Ubuntu, Mint, Omarchy)"),
    executable: "ufw",
    commandes: &[
        voir(
            "sudo ufw status verbose",
            "L'état du pare-feu et ses règles.",
            "The firewall's state and rules.",
        ),
        changer(
            "sudo ufw enable",
            "Active le pare-feu ; les connexions entrantes sont refusées par défaut.",
            "Turns the firewall on; incoming connections are refused by default.",
        ),
        changer(
            "sudo ufw allow <port>/tcp",
            "Ouvre un port en entrée.",
            "Opens an incoming port.",
        ),
        changer(
            "sudo ufw deny <port>/tcp",
            "Bloque un port en entrée.",
            "Blocks an incoming port.",
        ),
        changer(
            "sudo ufw delete allow <port>/tcp",
            "Retire la règle qui ouvrait ce port.",
            "Removes the rule that opened this port.",
        ),
        voir(
            "sudo ufw status numbered",
            "Les règles, numérotées.",
            "The rules, numbered.",
        ),
        changer(
            "sudo ufw delete <numéro>",
            "Retire la règle de ce numéro.",
            "Removes the rule with this number.",
        ),
        changer(
            "sudo ufw default deny incoming",
            "Refuse par défaut tout ce qui entre.",
            "Refuses everything coming in by default.",
        ),
        changer("sudo ufw allow ssh", "Ouvre SSH (port 22).", "Opens SSH (port 22)."),
        changer(
            "sudo ufw limit ssh",
            "Ouvre SSH en freinant les essais de mot de passe à la chaîne.",
            "Opens SSH while slowing down repeated password attempts.",
        ),
        changer(
            "sudo ufw allow from <adresse>",
            "Laisse entrer ce qui vient d'une adresse ou d'un réseau (192.168.1.0/24).",
            "Lets in what comes from an address or a network (192.168.1.0/24).",
        ),
        changer(
            "sudo ufw logging on",
            "Note les connexions bloquées dans le journal.",
            "Logs the blocked connections.",
        ),
    ],
};

/// Le pare-feu de Fedora et d'openSUSE.
pub(super) const FIREWALLD: Programme = Programme {
    nom: "firewall-cmd",
    role: ("pare-feu firewalld (Fedora, SUSE)", "firewalld firewall (Fedora, SUSE)"),
    executable: "firewall-cmd",
    commandes: &[
        voir(
            "firewall-cmd --state",
            "Le pare-feu tourne-t-il ?",
            "Is the firewall running?",
        ),
        voir(
            "firewall-cmd --list-all",
            "La zone par défaut : services et ports ouverts.",
            "The default zone: open services and ports.",
        ),
        changer(
            "sudo firewall-cmd --permanent --add-port=<port>/tcp",
            "Ouvre un port en entrée, pris en compte après --reload.",
            "Opens an incoming port, applied after --reload.",
        ),
        changer(
            "sudo firewall-cmd --reload",
            "Applique les règles enregistrées.",
            "Applies the saved rules.",
        ),
        changer(
            "sudo systemctl enable --now firewalld",
            "Rallume firewalld s'il a été arrêté.",
            "Turns firewalld back on if it was stopped.",
        ),
        voir(
            "firewall-cmd --get-active-zones",
            "Les zones actives, et les cartes réseau de chacune.",
            "The active zones, and the network cards of each.",
        ),
        voir(
            "firewall-cmd --get-default-zone",
            "La zone par défaut (souvent public, ou FedoraWorkstation).",
            "The default zone (often public, or FedoraWorkstation).",
        ),
        voir(
            "firewall-cmd --list-services",
            "Les services ouverts dans la zone par défaut.",
            "The services open in the default zone.",
        ),
        voir(
            "firewall-cmd --get-services",
            "Les noms de services connus (ssh, http, samba…).",
            "The known service names (ssh, http, samba…).",
        ),
        changer(
            "sudo firewall-cmd --permanent --add-service=<service>",
            "Ouvre un service pour de bon (puis --reload).",
            "Opens a service for good (then --reload).",
        ),
        changer(
            "sudo firewall-cmd --permanent --remove-service=<service>",
            "Referme un service (puis --reload).",
            "Closes a service again (then --reload).",
        ),
    ],
};
