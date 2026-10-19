//! Guide : les commandes qui s'écrivent pareil sous Linux, Windows et macOS, Vanguard en tête. Sous Windows, ssh, scp,
//! curl et tar sont fournis depuis Windows 10 (2018).

use super::{Programme, changer, traduite, voir};

pub const PROGRAMMES: &[Programme] = &[
    Programme {
        nom: "vanguard",
        role: ("Vanguard en ligne de commande", "Vanguard from the command line"),
        executable: "",
        commandes: &[
            traduite(
                "vanguard",
                "vanguard",
                "Le menu. Depuis la clé : <clé>/Linux/vanguard, <clé>\\Windows\\vanguard.exe, <clé>/macOS/vanguard.",
                "The menu. From the key: <key>/Linux/vanguard, <key>\\Windows\\vanguard.exe, <key>/macOS/vanguard.",
                false,
            ),
            traduite(
                "vanguard complet",
                "vanguard full",
                "Bilan complet : cette machine, puis le réseau.",
                "Full check: this machine, then the network.",
                false,
            ),
            traduite(
                "vanguard corriger",
                "vanguard fix",
                "Corrige les problèmes trouvés, chacun montré puis accepté.",
                "Fixes the problems found, each one shown, then accepted.",
                true,
            ),
            traduite(
                "vanguard reseau",
                "vanguard network",
                "Les appareils du réseau, leurs ports ouverts, ce qui a changé.",
                "The network's devices, their open ports, what changed.",
                false,
            ),
            traduite(
                "vanguard reseau <ip> -p tous",
                "vanguard network <ip> -p all",
                "Tous les ports d'un appareil.",
                "Every port of one device.",
                false,
            ),
            traduite(
                "vanguard maj",
                "vanguard update",
                "Mises à jour : système, programmes, pilotes, firmware, après accord.",
                "Updates: system, programs, drivers, firmware, after your consent.",
                true,
            ),
            traduite(
                "vanguard reparer",
                "vanguard repair",
                "Réparations courantes : Internet, disque, mises à jour bloquées…",
                "Common repairs: Internet, disk, stuck updates…",
                true,
            ),
            traduite(
                "vanguard nettoyer --liste",
                "vanguard clean --list",
                "La place que le nettoyage libérerait, sans rien effacer.",
                "The space a cleanup would free, deleting nothing.",
                false,
            ),
            traduite(
                "vanguard antivirus <dossier>",
                "vanguard antivirus <folder>",
                "Analyse un dossier ou une clé USB.",
                "Scans a folder or a USB drive.",
                false,
            ),
            traduite(
                "vanguard connexion",
                "vanguard connection",
                "Test de connexion : ping, gigue, débit, bufferbloat.",
                "Connection test: ping, jitter, speed, bufferbloat.",
                false,
            ),
            traduite(
                "vanguard diagnostic",
                "vanguard diag",
                "Le matériel, les plantages et les erreurs récents.",
                "Hardware, recent crashes and errors.",
                false,
            ),
            traduite(
                "vanguard motdepasse",
                "vanguard password",
                "Tes mots de passe ont-ils fuité ? Seuls 5 caractères de leur empreinte partent.",
                "Have your passwords leaked? Only 5 characters of their hash are sent.",
                false,
            ),
            traduite(
                "vanguard isoler <programme>",
                "vanguard sandbox <program>",
                "Lance un programme inconnu dans un bac à sable, sans réseau.",
                "Runs an unknown program in a sandbox, with no network.",
                false,
            ),
            traduite(
                "vanguard guide <mot>",
                "vanguard guide <word>",
                "Ce guide : un système, un programme ou un mot à chercher.",
                "This guide: a system, a program or a word to look for.",
                false,
            ),
            traduite(
                "vanguard --help",
                "vanguard --help",
                "Toutes les commandes de Vanguard et leurs options.",
                "Every Vanguard command and its options.",
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
                "Shows each step of the connection, to see where it fails.",
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
            voir(
                "ssh -G <adresse>",
                "Les réglages qu'ssh utiliserait pour ce serveur.",
                "The settings ssh would use for this server.",
            ),
            voir(
                "ssh-keygen -F <adresse>",
                "Ce serveur est-il déjà connu (known_hosts) ?",
                "Is this server already known (known_hosts)?",
            ),
            changer(
                "ssh -L 8080:localhost:80 <utilisateur>@<adresse>",
                "Un tunnel : le port 80 du serveur, ouvert ici sur le 8080.",
                "A tunnel: the server's port 80, opened here on 8080.",
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
            voir(
                "curl -v https://<site>",
                "Toute la conversation : chiffrement, en-têtes, redirections.",
                "The whole conversation: encryption, headers, redirects.",
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
                "Gets the project's latest changes.",
            ),
            changer(
                "git switch -c <nom>",
                "Crée une branche et s'y place.",
                "Creates a branch and switches to it.",
            ),
            voir(
                "git log --graph --oneline --all -20",
                "L'historique de toutes les branches, en dessin.",
                "The history of all branches, as a drawing.",
            ),
            voir(
                "git branch -a",
                "Les branches, locales et distantes.",
                "Branches, local and remote.",
            ),
            voir(
                "git remote -v",
                "D'où vient le projet, et où il s'envoie.",
                "Where the project comes from, and where it is sent.",
            ),
            changer("git push", "Envoie tes enregistrements.", "Sends your commits."),
            changer(
                "git stash",
                "Met de côté les changements en cours…",
                "Puts the current changes aside…",
            ),
            changer("git stash pop", "…et les reprend.", "…and takes them back."),
            changer(
                "git restore <fichier>",
                "Annule les changements d'un fichier : ils sont perdus.",
                "Undoes a file's changes: they are lost.",
            ),
            voir("git show <id>", "Le détail d'un enregistrement.", "A commit's details."),
            voir(
                "git blame <fichier>",
                "Qui a écrit chaque ligne d'un fichier, et quand.",
                "Who wrote each line of a file, and when.",
            ),
            changer(
                "git config --global user.name \"<nom>\"",
                "Ton nom dans les enregistrements.",
                "Your name in commits.",
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
    Programme {
        nom: "docker",
        role: ("conteneurs (Docker)", "containers (Docker)"),
        executable: "docker",
        commandes: &[
            voir("docker ps", "Les conteneurs qui tournent.", "Running containers."),
            voir(
                "docker ps -a",
                "Tous les conteneurs, arrêtés compris.",
                "All containers, stopped ones included.",
            ),
            voir("docker images", "Les images téléchargées.", "Downloaded images."),
            voir(
                "docker logs --tail 50 <nom>",
                "Les dernières lignes du journal d'un conteneur.",
                "The latest log lines of a container.",
            ),
            voir(
                "docker stats --no-stream",
                "Le processeur et la mémoire de chaque conteneur.",
                "Each container's processor and memory.",
            ),
            voir(
                "docker system df",
                "La place prise par Docker.",
                "Space taken by Docker.",
            ),
            changer(
                "docker compose up -d",
                "Lance les services du projet (compose.yaml), en arrière-plan.",
                "Starts the project's services (compose.yaml), in the background.",
            ),
            changer("docker compose down", "Les arrête.", "Stops them."),
            changer(
                "docker exec -it <nom> sh",
                "Ouvre un terminal dans un conteneur.",
                "Opens a terminal inside a container.",
            ),
            changer(
                "docker system prune",
                "Retire conteneurs arrêtés, réseaux et images inutiles.",
                "Removes stopped containers, networks and unused images.",
            ),
        ],
    },
];

/// Les marches à suivre de tous les systèmes : chaque étape est une commande expliquée, dans l'ordre.
pub const PAS_A_PAS: &[Programme] = &[
    Programme {
        nom: "Pas à pas : clé SSH",
        role: ("se connecter sans mot de passe", "connect without a password"),
        executable: "ssh",
        commandes: &[
            changer(
                "ssh-keygen -t ed25519",
                "Crée ta paire de clés ; protège-la par une phrase de passe.",
                "Creates your key pair; protect it with a passphrase.",
            ),
            voir(
                "cat $HOME/.ssh/id_ed25519.pub",
                "Ta clé publique, la seule à donner : une ligne qui commence par ssh-ed25519.",
                "Your public key, the only one to give out: a line starting with ssh-ed25519.",
            ),
            changer(
                "scp $HOME/.ssh/id_ed25519.pub <utilisateur>@<adresse>:",
                "La copie sur le serveur…",
                "Copies it to the server…",
            ),
            changer(
                "ssh <utilisateur>@<adresse> \"cat id_ed25519.pub >> .ssh/authorized_keys\"",
                "…et l'y ajoute aux clés autorisées.",
                "…and adds it there to the authorized keys.",
            ),
            voir(
                "ssh <utilisateur>@<adresse>",
                "Connecte-toi : plus de mot de passe du serveur, seulement ta phrase de passe.",
                "Connect: no more server password, only your passphrase.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : git",
        role: ("récupérer, modifier, envoyer", "get, change, send"),
        executable: "git",
        commandes: &[
            changer("git clone <adresse>", "Récupère un projet.", "Gets a project."),
            changer(
                "git switch -c <nom>",
                "Une branche pour ton travail.",
                "A branch for your work.",
            ),
            voir("git status", "Ce que tu as changé.", "What you changed."),
            changer("git add <fichier>", "Prépare tes changements…", "Stages your changes…"),
            changer(
                "git commit -m \"<texte>\"",
                "…et les enregistre, avec un message.",
                "…and commits them, with a message.",
            ),
            changer(
                "git pull --rebase",
                "Reprend les nouveautés des autres par-dessus.",
                "Takes the others' changes underneath yours.",
            ),
            changer("git push -u origin <nom>", "Envoie ta branche.", "Sends your branch."),
        ],
    },
];
