//! Guide : les commandes qui s'écrivent pareil sous Linux, Windows et macOS, Gardien en tête. Sous Windows, ssh, scp,
//! curl et tar sont fournis depuis Windows 10 (2018).

use super::{Programme, changer, traduite, voir};

pub const PROGRAMMES: &[Programme] = &[
    Programme {
        nom: "gardien",
        role: ("Gardien en ligne de commande", "Gardien from the command line"),
        executable: "",
        commandes: &[
            traduite(
                "gardien",
                "gardien",
                "Le menu. Depuis la clé : <clé>/Linux/gardien, <clé>\\Windows\\gardien.exe, <clé>/macOS/gardien.",
                "The menu. From the key: <key>/Linux/gardien, <key>\\Windows\\gardien.exe, <key>/macOS/gardien.",
                false,
            ),
            traduite(
                "gardien complet",
                "gardien full",
                "Bilan complet : cette machine, puis le réseau.",
                "Full check: this machine, then the network.",
                false,
            ),
            traduite(
                "gardien corriger",
                "gardien fix",
                "Corrige les problèmes trouvés, chacun montré puis accepté.",
                "Fixes the problems found, each one shown, then accepted.",
                true,
            ),
            traduite(
                "gardien reseau",
                "gardien network",
                "Les appareils du réseau, leurs ports ouverts, ce qui a changé.",
                "The network's devices, their open ports, what changed.",
                false,
            ),
            traduite(
                "gardien reseau <ip> -p tous",
                "gardien network <ip> -p all",
                "Tous les ports d'un appareil.",
                "Every port of one device.",
                false,
            ),
            traduite(
                "gardien maj",
                "gardien update",
                "Mises à jour : système, programmes, pilotes, firmware, après accord.",
                "Updates: system, programs, drivers, firmware, after your consent.",
                true,
            ),
            traduite(
                "gardien reparer",
                "gardien repair",
                "Réparations courantes : Internet, disque, mises à jour bloquées…",
                "Common repairs: Internet, disk, stuck updates…",
                true,
            ),
            traduite(
                "gardien nettoyer --liste",
                "gardien clean --list",
                "La place que le nettoyage libérerait, sans rien effacer.",
                "The space a cleanup would free, deleting nothing.",
                false,
            ),
            traduite(
                "gardien antivirus <dossier>",
                "gardien antivirus <folder>",
                "Analyse un dossier ou une clé USB.",
                "Scans a folder or a USB drive.",
                false,
            ),
            traduite(
                "gardien connexion",
                "gardien connection",
                "Test de connexion : ping, gigue, débit, bufferbloat.",
                "Connection test: ping, jitter, speed, bufferbloat.",
                false,
            ),
            traduite(
                "gardien diagnostic",
                "gardien diag",
                "Le matériel, les plantages et les erreurs récents.",
                "Hardware, recent crashes and errors.",
                false,
            ),
            traduite(
                "gardien motdepasse",
                "gardien password",
                "Tes mots de passe ont-ils fuité ? Seuls 5 caractères de leur empreinte partent.",
                "Have your passwords leaked? Only 5 characters of their fingerprint are sent.",
                false,
            ),
            traduite(
                "gardien isoler <programme>",
                "gardien sandbox <program>",
                "Lance un programme inconnu dans un bac à sable, sans réseau.",
                "Runs an unknown program in a sandbox, with no network.",
                false,
            ),
            traduite(
                "gardien guide <mot>",
                "gardien guide <word>",
                "Ce guide : un système, un programme ou un mot à chercher.",
                "This guide: a system, a program or a word to look for.",
                false,
            ),
            traduite(
                "gardien --help",
                "gardien --help",
                "Toutes les commandes de Gardien et leurs options.",
                "Every Gardien command and its options.",
                false,
            ),
        ],
    },
    Programme {
        nom: "ping",
        role: ("un appareil répond-il ?", "does a device answer?"),
        executable: "ping",
        commandes: &[
            voir(
                "ping <box>",
                "La box répond-elle ? Son adresse : ip route, ipconfig, ou les réglages du réseau.",
                "Does the router answer? Its address: ip route, ipconfig, or the network settings.",
            ),
            voir(
                "ping 1.1.1.1",
                "Internet répond-il ? Une adresse, sans passer par le DNS (Ctrl-C pour arrêter).",
                "Does the Internet answer? An address, bypassing DNS (Ctrl-C to stop).",
            ),
            voir(
                "ping <site>",
                "Et par son nom ? Si l'adresse répond mais pas le nom, c'est le DNS.",
                "And by name? If the address answers but not the name, it is DNS.",
            ),
        ],
    },
    Programme {
        nom: "nslookup",
        role: ("DNS : l'adresse d'un nom", "DNS: a name's address"),
        executable: "nslookup",
        commandes: &[
            voir(
                "nslookup <site>",
                "L'adresse d'un site d'après ton DNS.",
                "A site's address according to your DNS.",
            ),
            voir(
                "nslookup <site> 1.1.1.1",
                "La même chose avec un autre DNS : deux réponses différentes, ton DNS est en panne ou détourné.",
                "The same with another DNS: two different answers, your DNS is broken or hijacked.",
            ),
        ],
    },
    Programme {
        nom: "ssh, scp, ssh-keygen",
        role: ("connexions à distance (OpenSSH)", "remote connections (OpenSSH)"),
        executable: "ssh",
        commandes: &[
            voir(
                "ssh <utilisateur>@<adresse>",
                "Ouvre une session sur un autre ordinateur.",
                "Opens a session on another computer.",
            ),
            voir(
                "ssh -p <port> <utilisateur>@<adresse>",
                "Sur un autre port que 22.",
                "On a port other than 22.",
            ),
            voir(
                "ssh -v <utilisateur>@<adresse>",
                "Raconte la connexion en détail, pour voir où elle échoue.",
                "Tells the connection in detail, to see where it fails.",
            ),
            changer(
                "scp <fichier> <utilisateur>@<adresse>:<dossier>",
                "Copie un fichier vers un autre ordinateur.",
                "Copies a file to another computer.",
            ),
            changer(
                "scp <utilisateur>@<adresse>:<fichier> .",
                "Rapatrie un fichier ici.",
                "Brings a file back here.",
            ),
            changer(
                "ssh-keygen -t ed25519",
                "Crée une clé SSH ; donne-lui une phrase de passe.",
                "Creates an SSH key; give it a passphrase.",
            ),
            voir(
                "ssh-keygen -lf <fichier>",
                "L'empreinte d'une clé (son fichier .pub).",
                "A key's fingerprint (its .pub file).",
            ),
            changer(
                "ssh-keygen -R <adresse>",
                "Oublie l'empreinte d'un serveur, seulement s'il a été réinstallé : sinon, quelqu'un se fait peut-être passer pour lui.",
                "Forgets a server's fingerprint, only if it was reinstalled: otherwise, someone may be impersonating it.",
            ),
        ],
    },
    Programme {
        nom: "curl",
        role: ("sites et téléchargements", "websites and downloads"),
        executable: "curl",
        commandes: &[
            voir(
                "curl -I https://<site>",
                "Le site répond-il ? Son code (200 : OK). Sous Windows PowerShell 5.1, taper curl.exe.",
                "Does the site answer? Its code (200: OK). In Windows PowerShell 5.1, type curl.exe.",
            ),
            voir(
                "curl https://ifconfig.me",
                "Ton adresse IP publique, celle qu'Internet voit.",
                "Your public IP address, the one the Internet sees.",
            ),
            changer(
                "curl -LO https://<site>/<fichier>",
                "Télécharge un fichier ici.",
                "Downloads a file here.",
            ),
        ],
    },
    Programme {
        nom: "tar",
        role: ("archives compressées", "compressed archives"),
        executable: "tar",
        commandes: &[
            changer(
                "tar -czf <archive>.tar.gz <dossier>",
                "Met un dossier dans une archive compressée.",
                "Puts a folder in a compressed archive.",
            ),
            changer(
                "tar -xzf <archive>.tar.gz",
                "Décompresse une archive ici.",
                "Extracts an archive here.",
            ),
            voir(
                "tar -tzf <archive>.tar.gz",
                "Le contenu d'une archive, sans la décompresser.",
                "An archive's contents, without extracting it.",
            ),
        ],
    },
    Programme {
        nom: "git",
        role: ("les versions d'un projet", "a project's versions"),
        executable: "git",
        commandes: &[
            changer(
                "git clone <adresse>",
                "Copie un projet (un dépôt) ici.",
                "Copies a project (a repository) here.",
            ),
            voir(
                "git status",
                "Ce qui a changé dans le projet.",
                "What changed in the project.",
            ),
            voir(
                "git diff",
                "Le détail de ces changements.",
                "The details of these changes.",
            ),
            voir(
                "git log --oneline -10",
                "Les 10 derniers enregistrements (commits).",
                "The last 10 commits.",
            ),
            changer(
                "git add <fichier>",
                "Prépare un fichier pour le prochain enregistrement.",
                "Stages a file for the next commit.",
            ),
            changer(
                "git commit -m \"<texte>\"",
                "Enregistre les changements préparés, avec une phrase qui les décrit.",
                "Records the staged changes, with a sentence describing them.",
            ),
            changer(
                "git pull",
                "Récupère les nouveautés du projet.",
                "Gets the project's news.",
            ),
            changer(
                "git switch -c <nom>",
                "Crée une branche et s'y place.",
                "Creates a branch and switches to it.",
            ),
        ],
    },
    Programme {
        nom: "whoami, hostname",
        role: ("ton compte, cet ordinateur", "your account, this computer"),
        executable: "whoami",
        commandes: &[
            voir(
                "whoami",
                "Le compte avec lequel tu travailles.",
                "The account you are working with.",
            ),
            voir("hostname", "Le nom de cet ordinateur.", "This computer's name."),
        ],
    },
];
