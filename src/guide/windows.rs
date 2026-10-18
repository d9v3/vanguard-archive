//! Guide : les commandes de Windows 10 et 11, par programme. Toutes se tapent dans PowerShell (le terminal par
//! défaut) ; les programmes classiques (ipconfig, sfc, netsh…) marchent aussi dans l'invite de commandes.

use super::{Programme, changer, voir};

pub const PROGRAMMES: &[Programme] = &[
    Programme {
        nom: "winget",
        role: ("installer, mettre à jour", "install, update"),
        executable: "winget",
        commandes: &[
            voir(
                "winget upgrade",
                "Les programmes qui ont une mise à jour.",
                "Programs that have an update.",
            ),
            changer("winget upgrade --all", "Les met tous à jour.", "Updates them all."),
            voir(
                "winget search <nom>",
                "Cherche un programme ; son identifiant est dans la colonne Id.",
                "Searches for a program; its identifier is in the Id column.",
            ),
            changer(
                "winget install --id <id> --exact",
                "Installe un programme par son identifiant (ex. Mozilla.Firefox).",
                "Installs a program by its identifier (e.g. Mozilla.Firefox).",
            ),
            changer(
                "winget uninstall --id <id> --exact",
                "Désinstalle un programme.",
                "Uninstalls a program.",
            ),
            voir("winget list", "Les programmes installés.", "Installed programs."),
            voir(
                "winget export -o apps.json",
                "La liste des programmes installés, pour les réinstaller ailleurs.",
                "The list of installed programs, to reinstall them elsewhere.",
            ),
            changer(
                "winget import -i apps.json",
                "Réinstalle les programmes de cette liste.",
                "Reinstalls the programs in that list.",
            ),
        ],
    },
    Programme {
        nom: "ms-settings",
        role: ("ouvrir une page des Paramètres", "open a Settings page"),
        executable: "",
        commandes: &[
            voir(
                "start ms-settings:windowsupdate",
                "Ouvre Windows Update.",
                "Opens Windows Update.",
            ),
            voir(
                "start ms-settings:network-status",
                "Ouvre l'état du réseau, avec la réinitialisation du réseau.",
                "Opens network status, with network reset.",
            ),
            voir(
                "start ms-settings:windowsdefender",
                "Ouvre Sécurité Windows.",
                "Opens Windows Security.",
            ),
            voir(
                "start ms-settings:storagesense",
                "Ouvre le stockage : ce qui prend la place.",
                "Opens storage: what takes up the space.",
            ),
            voir(
                "start ms-settings:appsfeatures",
                "Ouvre la liste des applications installées.",
                "Opens the list of installed apps.",
            ),
            voir(
                "start ms-settings:startupapps",
                "Ouvre les applications lancées au démarrage.",
                "Opens startup apps.",
            ),
            voir(
                "start ms-settings:troubleshoot",
                "Ouvre les utilitaires de résolution des problèmes.",
                "Opens the troubleshooters.",
            ),
        ],
    },
    Programme {
        nom: "sfc, DISM",
        role: ("réparer Windows (administrateur)", "repair Windows (administrator)"),
        executable: "sfc",
        commandes: &[
            changer(
                "sfc /scannow",
                "Vérifie les fichiers de Windows et remplace ceux qui sont abîmés.",
                "Checks Windows files and replaces the damaged ones.",
            ),
            voir(
                "DISM /Online /Cleanup-Image /ScanHealth",
                "Vérifie l'image de Windows, sans rien réparer.",
                "Checks the Windows image, repairing nothing.",
            ),
            changer(
                "DISM /Online /Cleanup-Image /RestoreHealth",
                "Répare l'image de Windows : à lancer avant sfc quand sfc n'y arrive pas.",
                "Repairs the Windows image: run it before sfc when sfc cannot.",
            ),
            changer(
                "DISM /Online /Cleanup-Image /StartComponentCleanup",
                "Fait de la place : retire les anciennes versions des composants.",
                "Frees space: removes old versions of components.",
            ),
        ],
    },
    Programme {
        nom: "chkdsk",
        role: ("erreurs et réparation du disque", "disk errors and repair"),
        executable: "chkdsk",
        commandes: &[
            voir(
                "chkdsk C:",
                "Cherche les erreurs du disque C:, sans rien réparer.",
                "Looks for errors on disk C:, repairing nothing.",
            ),
            changer(
                "chkdsk C: /f",
                "Répare les erreurs ; pour C:, au prochain redémarrage.",
                "Repairs the errors; for C:, at the next restart.",
            ),
            changer(
                "chkdsk C: /r",
                "Répare aussi les secteurs défectueux (plusieurs heures).",
                "Also repairs bad sectors (several hours).",
            ),
        ],
    },
    Programme {
        nom: "ipconfig",
        role: ("adresses, box, DNS", "addresses, router, DNS"),
        executable: "ipconfig",
        commandes: &[
            voir(
                "ipconfig /all",
                "Adresse, box (passerelle), DNS et adresse MAC de chaque carte réseau.",
                "Address, router (gateway), DNS and MAC address of each network card.",
            ),
            changer("ipconfig /flushdns", "Vide le cache DNS.", "Clears the DNS cache."),
            changer(
                "ipconfig /release",
                "Rend l'adresse donnée par la box (le réseau se coupe).",
                "Gives back the address from the router (the network goes down).",
            ),
            changer(
                "ipconfig /renew",
                "Redemande une adresse à la box.",
                "Asks the router for a new address.",
            ),
            voir(
                "ipconfig /displaydns",
                "Les noms trouvés récemment par le DNS.",
                "Names recently resolved by DNS.",
            ),
        ],
    },
    Programme {
        nom: "netsh",
        role: ("Wi-Fi, pare-feu, pile réseau", "Wi-Fi, firewall, network stack"),
        executable: "netsh",
        commandes: &[
            voir(
                "netsh wlan show interfaces",
                "Le Wi-Fi connecté : signal, débit, canal, sécurité.",
                "The connected Wi-Fi: signal, speed, channel, security.",
            ),
            voir(
                "netsh wlan show profiles",
                "Les Wi-Fi enregistrés.",
                "Saved Wi-Fi networks.",
            ),
            voir(
                "netsh wlan show profile name=\"<nom>\" key=clear",
                "Le mot de passe d'un Wi-Fi enregistré (administrateur).",
                "A saved Wi-Fi network's password (administrator).",
            ),
            voir(
                "netsh wlan show wlanreport",
                "Rapport des connexions Wi-Fi des derniers jours, en HTML (administrateur).",
                "Report of the last days' Wi-Fi connections, in HTML (administrator).",
            ),
            voir(
                "netsh advfirewall show allprofiles",
                "L'état du pare-feu pour chaque profil.",
                "The firewall's state for each profile.",
            ),
            changer(
                "netsh winsock reset",
                "Remet à zéro le catalogue des connexions réseau ; redémarrer ensuite.",
                "Resets the network connection catalog; restart afterwards.",
            ),
            changer(
                "netsh int ip reset",
                "Remet à zéro les réglages TCP/IP ; redémarrer ensuite.",
                "Resets the TCP/IP settings; restart afterwards.",
            ),
        ],
    },
    Programme {
        nom: "PowerShell : réseau",
        role: ("cartes, connexions, DNS", "cards, connections, DNS"),
        executable: "",
        commandes: &[
            voir(
                "Get-NetIPConfiguration",
                "Le résumé de chaque carte réseau : adresse, box, DNS.",
                "Each network card's summary: address, router, DNS.",
            ),
            voir(
                "Get-NetAdapter",
                "Les cartes réseau, leur état et leur vitesse.",
                "Network cards, their state and speed.",
            ),
            voir(
                "Test-NetConnection <site> -Port 443",
                "Le site répond-il, et sur ce port ?",
                "Does the site answer, and on this port?",
            ),
            voir(
                "Resolve-DnsName <site>",
                "L'adresse d'un site d'après le DNS.",
                "A site's address according to DNS.",
            ),
            voir(
                "Get-NetTCPConnection -State Listen",
                "Les ports en écoute sur cet ordinateur.",
                "Listening ports on this computer.",
            ),
            changer(
                "Restart-NetAdapter -Name \"<nom>\"",
                "Coupe puis rallume une carte réseau (administrateur ; son nom : Get-NetAdapter).",
                "Turns a network card off and on (administrator; its name: Get-NetAdapter).",
            ),
        ],
    },
    Programme {
        nom: "tracert, pathping",
        role: ("le chemin jusqu'à un site", "the path to a site"),
        executable: "tracert",
        commandes: &[
            voir(
                "tracert <site>",
                "Le chemin jusqu'à un site, routeur par routeur.",
                "The path to a site, router by router.",
            ),
            voir(
                "pathping <site>",
                "Le même chemin, avec les pertes à chaque étape (quelques minutes).",
                "The same path, with the losses at each hop (a few minutes).",
            ),
        ],
    },
    Programme {
        nom: "PowerShell : Defender",
        role: ("antivirus Microsoft Defender", "Microsoft Defender antivirus"),
        executable: "",
        commandes: &[
            voir(
                "Get-MpComputerStatus",
                "L'état de l'antivirus : protection en temps réel, date des signatures.",
                "Antivirus status: real-time protection, signature date.",
            ),
            changer(
                "Update-MpSignature",
                "Met à jour les signatures.",
                "Updates the signatures.",
            ),
            changer(
                "Start-MpScan -ScanType QuickScan",
                "Analyse rapide ; ce qui est trouvé part en quarantaine.",
                "Quick scan; what is found goes to quarantine.",
            ),
            changer(
                "Start-MpScan -ScanType FullScan",
                "Analyse complète (longue).",
                "Full scan (long).",
            ),
            changer(
                "Start-MpScan -ScanType CustomScan -ScanPath <dossier>",
                "Analyse un dossier ou une clé USB.",
                "Scans a folder or a USB drive.",
            ),
            voir(
                "Get-MpThreatDetection",
                "Les menaces trouvées récemment.",
                "Recently found threats.",
            ),
            changer(
                "Start-MpWDOScan",
                "Redémarre et analyse avant que Windows démarre : contre les virus qui se cachent.",
                "Restarts and scans before Windows starts: against malware that hides.",
            ),
        ],
    },
    Programme {
        nom: "PowerShell : services",
        role: ("services et programmes en marche", "services and running programs"),
        executable: "",
        commandes: &[
            voir(
                "Get-Service | Where-Object Status -eq Running",
                "Les services qui tournent.",
                "Running services.",
            ),
            voir("Get-Service <nom>", "L'état d'un service.", "A service's state."),
            changer(
                "Restart-Service <nom>",
                "Redémarre un service (administrateur).",
                "Restarts a service (administrator).",
            ),
            voir(
                "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
                "Les 10 programmes qui ont pris le plus de processeur.",
                "The 10 programs that used the most CPU.",
            ),
            voir(
                "Get-Process | Sort-Object WS -Descending | Select-Object -First 10",
                "Les 10 qui prennent le plus de mémoire.",
                "The 10 using the most memory.",
            ),
            changer(
                "Stop-Process -Name <nom>",
                "Ferme un programme (nom sans .exe) ; il perd ce qui n'est pas enregistré.",
                "Closes a program (name without .exe); it loses what is not saved.",
            ),
        ],
    },
    Programme {
        nom: "tasklist, taskkill",
        role: ("programmes en marche", "running programs"),
        executable: "tasklist",
        commandes: &[
            voir("tasklist", "Les programmes en marche.", "Running programs."),
            voir(
                "tasklist /svc",
                "Les services portés par chaque programme.",
                "The services hosted by each program.",
            ),
            changer(
                "taskkill /IM <programme>.exe /F",
                "Force un programme figé à se fermer.",
                "Forces a frozen program to close.",
            ),
        ],
    },
    Programme {
        nom: "systeminfo, msinfo32, dxdiag",
        role: ("système et matériel", "system and hardware"),
        executable: "systeminfo",
        commandes: &[
            voir(
                "systeminfo",
                "Version de Windows, date d'installation, mémoire, correctifs.",
                "Windows version, install date, memory, hotfixes.",
            ),
            voir(
                "winver",
                "La version exacte de Windows, dans une fenêtre.",
                "The exact Windows version, in a window.",
            ),
            voir(
                "msinfo32",
                "Informations système : matériel, pilotes, démarrage sécurisé.",
                "System Information: hardware, drivers, Secure Boot.",
            ),
            voir(
                "dxdiag",
                "Carte graphique, DirectX, son : à joindre à une demande d'aide pour un jeu.",
                "Graphics card, DirectX, sound: attach it to a help request for a game.",
            ),
            voir(
                "Get-CimInstance Win32_BIOS",
                "La version du BIOS et le numéro de série.",
                "The BIOS version and the serial number.",
            ),
        ],
    },
    Programme {
        nom: "powercfg",
        role: ("batterie, veille, énergie", "battery, sleep, power"),
        executable: "powercfg",
        commandes: &[
            voir(
                "powercfg /batteryreport",
                "Rapport de la batterie en HTML (usure, autonomie), écrit dans le dossier courant.",
                "Battery report in HTML (wear, runtime), written to the current folder.",
            ),
            voir(
                "powercfg /requests",
                "Ce qui empêche la mise en veille (administrateur).",
                "What prevents sleep (administrator).",
            ),
            voir(
                "powercfg /lastwake",
                "Ce qui a réveillé l'ordinateur la dernière fois.",
                "What woke the computer up last time.",
            ),
            voir(
                "powercfg /energy",
                "Diagnostic de l'énergie en HTML, après une minute d'observation (administrateur).",
                "Power diagnostics in HTML, after a minute of watching (administrator).",
            ),
            changer(
                "powercfg /hibernate off",
                "Coupe la veille prolongée et rend la place de hiberfil.sys ; coupe aussi le démarrage rapide.",
                "Turns hibernation off and frees hiberfil.sys space; also turns off fast startup.",
            ),
        ],
    },
    Programme {
        nom: "PowerShell : disques",
        role: ("santé et place des disques", "disk health and space"),
        executable: "",
        commandes: &[
            voir(
                "Get-PhysicalDisk | Format-Table FriendlyName, MediaType, HealthStatus",
                "Chaque disque, son type (SSD, HDD) et sa santé.",
                "Each disk, its type (SSD, HDD) and health.",
            ),
            voir(
                "Get-PhysicalDisk | Get-StorageReliabilityCounter",
                "Usure, température et erreurs de chaque disque (administrateur).",
                "Each disk's wear, temperature and errors (administrator).",
            ),
            voir(
                "Get-Volume",
                "La place libre de chaque lecteur.",
                "Free space on each drive.",
            ),
            voir(
                "Repair-Volume -DriveLetter C -Scan",
                "Cherche les erreurs du disque C: sans le bloquer (administrateur).",
                "Looks for errors on C: without locking it (administrator).",
            ),
            voir(
                "Optimize-Volume -DriveLetter C -Analyze -Verbose",
                "Le disque a-t-il besoin d'être optimisé (TRIM, défragmentation) ?",
                "Does the drive need optimizing (TRIM, defragmentation)?",
            ),
            voir(
                "diskmgmt.msc",
                "La gestion des disques, dans une fenêtre.",
                "Disk Management, in a window.",
            ),
        ],
    },
    Programme {
        nom: "manage-bde",
        role: ("chiffrement BitLocker", "BitLocker encryption"),
        executable: "manage-bde",
        commandes: &[
            voir(
                "manage-bde -status",
                "Le chiffrement BitLocker de chaque lecteur (administrateur).",
                "BitLocker encryption of each drive (administrator).",
            ),
            voir(
                "manage-bde -protectors -get C:",
                "La clé de récupération de C: (administrateur) : à garder ailleurs que sur ce PC.",
                "C:'s recovery key (administrator): keep it somewhere other than this PC.",
            ),
        ],
    },
    Programme {
        nom: "Get-WinEvent, perfmon",
        role: ("erreurs, plantages, fiabilité", "errors, crashes, reliability"),
        executable: "",
        commandes: &[
            voir(
                "Get-WinEvent -FilterHashtable @{LogName='System';Level=2} -MaxEvents 20",
                "Les 20 dernières erreurs du système.",
                "The last 20 system errors.",
            ),
            voir(
                "Get-WinEvent -FilterHashtable @{LogName='System';Id=41} -MaxEvents 5",
                "Les arrêts brutaux : coupure de courant, écran bleu, gel.",
                "Unexpected shutdowns: power cut, blue screen, freeze.",
            ),
            voir(
                "perfmon /rel",
                "Le moniteur de fiabilité : plantages et erreurs, jour par jour.",
                "Reliability Monitor: crashes and errors, day by day.",
            ),
            voir(
                "eventvwr",
                "L'Observateur d'événements, dans une fenêtre.",
                "Event Viewer, in a window.",
            ),
        ],
    },
    Programme {
        nom: "rstrui, Checkpoint-Computer",
        role: ("points de restauration", "restore points"),
        executable: "rstrui",
        commandes: &[
            changer(
                "rstrui",
                "Ramène le système à un point de restauration (fenêtre).",
                "Brings the system back to a restore point (window).",
            ),
            voir(
                "Get-ComputerRestorePoint",
                "Les points de restauration (administrateur).",
                "Restore points (administrator).",
            ),
            changer(
                "Checkpoint-Computer -Description \"<texte>\"",
                "Crée un point de restauration (administrateur ; un toutes les 24 heures au plus).",
                "Creates a restore point (administrator; at most one every 24 hours).",
            ),
        ],
    },
    Programme {
        nom: "shutdown",
        role: ("redémarrer, éteindre, dépanner", "restart, shut down, troubleshoot"),
        executable: "shutdown",
        commandes: &[
            changer("shutdown /r /t 0", "Redémarre tout de suite.", "Restarts right away."),
            changer(
                "shutdown /r /o /t 0",
                "Redémarre vers le dépannage : mode sans échec, restauration, réparation du démarrage.",
                "Restarts into troubleshooting: safe mode, restore, startup repair.",
            ),
            changer(
                "shutdown /s /t 0",
                "Éteint complètement, sans le démarrage rapide.",
                "Shuts down completely, without fast startup.",
            ),
        ],
    },
    Programme {
        nom: "Get-LocalUser, net user",
        role: ("comptes et administrateurs", "accounts and administrators"),
        executable: "",
        commandes: &[
            voir(
                "Get-LocalUser",
                "Les comptes de l'ordinateur, actifs ou non.",
                "The computer's accounts, enabled or not.",
            ),
            voir(
                "Get-LocalGroupMember -SID S-1-5-32-544",
                "Les comptes administrateurs, dans toutes les langues de Windows.",
                "Administrator accounts, in every Windows language.",
            ),
            voir(
                "net user <nom>",
                "Un compte en détail : dernière connexion, mot de passe…",
                "An account in detail: last logon, password…",
            ),
            changer(
                "net user <nom> /active:no",
                "Désactive un compte sans l'effacer (administrateur).",
                "Disables an account without deleting it (administrator).",
            ),
        ],
    },
    Programme {
        nom: "Get-ScheduledTask, msconfig",
        role: ("ce qui se lance au démarrage", "what starts at boot"),
        executable: "",
        commandes: &[
            voir(
                "Get-CimInstance Win32_StartupCommand | Format-List Name, Command",
                "Les programmes lancés à l'ouverture de session.",
                "Programs started at sign-in.",
            ),
            voir(
                "Get-ScheduledTask | Where-Object State -ne Disabled",
                "Les tâches planifiées actives.",
                "Active scheduled tasks.",
            ),
            voir(
                "taskmgr",
                "Le Gestionnaire des tâches (Ctrl+Maj+Échap), avec la page du démarrage.",
                "Task Manager (Ctrl+Shift+Esc), with its startup page.",
            ),
            voir(
                "msconfig",
                "Configuration du système : démarrage sélectif, mode sans échec (fenêtre).",
                "System Configuration: selective startup, safe mode (window).",
            ),
        ],
    },
    Programme {
        nom: "Get-ChildItem, robocopy",
        role: ("chercher et copier des fichiers", "find and copy files"),
        executable: "",
        commandes: &[
            voir(
                "Get-ChildItem -Recurse -Filter \"*<mot>*\"",
                "Cherche un fichier par son nom, ici et dans les sous-dossiers.",
                "Finds a file by name, here and in the subfolders.",
            ),
            voir(
                "Select-String -Path *.txt -Pattern \"<texte>\"",
                "Cherche un texte dans des fichiers.",
                "Searches for text in files.",
            ),
            changer(
                "robocopy <source> <destination> /E /Z",
                "Copie un dossier entier ; reprend où elle s'était arrêtée.",
                "Copies a whole folder; resumes where it stopped.",
            ),
            voir(
                "explorer .",
                "Ouvre le dossier courant dans l'Explorateur.",
                "Opens the current folder in File Explorer.",
            ),
        ],
    },
];
