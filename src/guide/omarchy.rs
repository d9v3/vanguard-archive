//! Guide : Omarchy, c'est-à-dire Arch Linux avec le bureau Hyprland tout réglé : ses commandes, puis pacman, yay et
//! ufw, partagés avec Arch.

use super::{Obstacle, Programme, changer, voir};

pub const PROGRAMMES: &[Programme] = &[
    OMARCHY_CLI,
    APPARENCE,
    MATERIEL,
    super::arch::PACMAN,
    super::arch::YAY,
    super::linux::UFW,
];

/// Les marches à suivre : chaque étape est une commande expliquée, dans l'ordre.
pub const PAS_A_PAS: &[Programme] = &[
    Programme {
        nom: "Pas à pas : mettre à jour",
        role: ("omarchy update, puis redémarrer", "omarchy update, then restart"),
        executable: "omarchy",
        commandes: &[
            voir(
                "omarchy update available",
                "Une nouvelle version d'Omarchy est-elle sortie ?",
                "Is a new Omarchy version out?",
            ),
            changer(
                "omarchy update",
                "Met tout à jour (Omarchy, paquets, AUR), avec un instantané pris avant.",
                "Updates everything (Omarchy, packages, AUR), with a snapshot taken first.",
            ),
            voir(
                "omarchy update analyze logs",
                "Cherche les pannes connues dans le journal de cette mise à jour.",
                "Looks for known failures in this update's log.",
            ),
            voir(
                "pacman -Q linux && uname -r",
                "Le noyau installé, puis celui qui tourne : s'ils diffèrent, redémarre.",
                "The installed kernel, then the running one: if they differ, restart.",
            ),
            changer(
                "omarchy system reboot",
                "Redémarre en fermant proprement les fenêtres.",
                "Restarts after closing the windows cleanly.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : dépanner",
        role: ("Wi-Fi, son, barre, instantané", "Wi-Fi, sound, bar, snapshot"),
        executable: "omarchy",
        commandes: &[
            voir(
                "omarchy debug --print --no-sudo",
                "Les informations utiles pour demander de l'aide (matériel, versions, journaux).",
                "The useful information to ask for help (hardware, versions, logs).",
            )
            .sauf(Obstacle::Fichier),
            changer(
                "omarchy restart wifi",
                "Le Wi-Fi ne marche plus : le débloque et le relance.",
                "Wi-Fi stopped working: unblocks and restarts it.",
            ),
            changer(
                "omarchy restart audio",
                "Plus de son : relance le son et les cartes son USB bloquées.",
                "No sound: restarts audio and stuck USB sound cards.",
            ),
            changer(
                "omarchy restart bluetooth",
                "Le Bluetooth ne répond plus : le débloque et le relance.",
                "Bluetooth no longer answers: unblocks and restarts it.",
            ),
            changer(
                "omarchy restart shell",
                "La barre ou le menu ne répondent plus : les relance.",
                "The bar or menu no longer answer: restarts them.",
            ),
            changer(
                "omarchy refresh config <fichier>",
                "Un réglage cassé : remet ce fichier par défaut (le tien gardé en copie).",
                "A broken setting: resets this file to default (yours kept as a copy).",
            ),
            changer(
                "omarchy snapshot restore",
                "En dernier recours : revient à un instantané d'avant la panne (aussi au démarrage, dans Limine).",
                "Last resort: goes back to a snapshot from before the problem (also at boot, in Limine).",
            ),
        ],
    },
];

/// La commande omarchy : mises à jour, paquets, instantanés, dépannage.
const OMARCHY_CLI: Programme = Programme {
    nom: "omarchy",
    role: ("Omarchy : mises à jour, réglages", "Omarchy: updates, settings"),
    executable: "omarchy",
    commandes: &[
        changer(
            "omarchy update",
            "Met à jour Omarchy et le système, instantané et migrations compris.",
            "Updates Omarchy and the system, snapshot and migrations included.",
        ),
        voir(
            "omarchy update available",
            "Une nouvelle version d'Omarchy est-elle sortie ?",
            "Is a new Omarchy version out?",
        ),
        voir(
            "omarchy update analyze logs",
            "Cherche les pannes connues dans le journal de la dernière mise à jour.",
            "Looks for known failures in the last update's log.",
        ),
        changer(
            "omarchy pkg add <paquet>",
            "Installe un paquet s'il manque.",
            "Installs a package if it is missing.",
        ),
        changer(
            "omarchy pkg drop <paquet>",
            "Désinstalle un paquet.",
            "Removes a package.",
        ),
        changer(
            "omarchy snapshot create",
            "Crée un instantané du système (snapper).",
            "Creates a system snapshot (snapper).",
        ),
        changer(
            "omarchy snapshot restore",
            "Revient à un instantané.",
            "Goes back to a snapshot.",
        ),
        changer(
            "omarchy restart wifi",
            "Débloque et relance le Wi-Fi.",
            "Unblocks and restarts Wi-Fi.",
        ),
        changer(
            "omarchy restart audio",
            "Relance le son, et les cartes son USB bloquées.",
            "Restarts audio, and stuck USB sound cards.",
        ),
        changer(
            "omarchy restart bluetooth",
            "Débloque et relance le Bluetooth.",
            "Unblocks and restarts Bluetooth.",
        ),
        changer(
            "omarchy restart shell",
            "Relance la barre d'Omarchy.",
            "Restarts the Omarchy bar.",
        ),
        voir(
            "omarchy debug --print --no-sudo",
            "Les informations de dépannage, à joindre à une demande d'aide (relis-les avant).",
            "Troubleshooting information, to attach to a help request (read it first).",
        )
        .sauf(Obstacle::Fichier),
        voir(
            "omarchy commands",
            "Toutes les commandes d'Omarchy.",
            "Every Omarchy command.",
        ),
        changer(
            "omarchy pkg install",
            "Choisit des paquets à installer dans une liste filtrée au clavier.",
            "Picks packages to install from a list filtered as you type.",
        ),
        changer(
            "omarchy pkg aur install",
            "Pareil pour les paquets de l'AUR.",
            "Same for AUR packages.",
        ),
        changer(
            "omarchy pkg remove",
            "Choisit des paquets à retirer.",
            "Picks packages to remove.",
        ),
        voir(
            "omarchy channel current",
            "Le canal des mises à jour d'Omarchy : stable, rc, edge ou dev.",
            "Omarchy's update channel: stable, rc, edge or dev.",
        ),
        changer(
            "omarchy channel set stable",
            "Revient au canal stable.",
            "Goes back to the stable channel.",
        ),
        changer(
            "omarchy refresh config <fichier>",
            "Remet un fichier de réglages d'Omarchy par défaut ; le tien est gardé en copie.",
            "Resets an Omarchy settings file to default; yours is kept as a copy.",
        ),
        changer(
            "omarchy reinstall configs",
            "Remet TOUS les réglages d'Omarchy par défaut : tes changements sont perdus.",
            "Resets ALL Omarchy settings to default: your changes are lost.",
        ),
        changer(
            "omarchy reinstall pkgs",
            "Réinstalle tous les paquets d'Omarchy.",
            "Reinstalls all Omarchy packages.",
        ),
        changer(
            "omarchy setup security sshd",
            "Installe le serveur SSH, ouvre le pare-feu et autorise une clé.",
            "Installs the SSH server, opens the firewall and authorizes a key.",
        ),
        changer(
            "omarchy setup security fingerprint",
            "Le lecteur d'empreintes pour sudo, polkit et le verrouillage.",
            "The fingerprint reader for sudo, polkit and the lock screen.",
        ),
        changer(
            "omarchy hibernation setup",
            "Met en place la veille prolongée (espace d'échange et reprise au démarrage).",
            "Sets up hibernation (swap space and resume at boot).",
        ),
        changer(
            "omarchy system lock",
            "Verrouille l'ordinateur et éteint l'écran.",
            "Locks the computer and turns the screen off.",
        ),
        changer(
            "omarchy system reboot",
            "Redémarre en fermant proprement les fenêtres.",
            "Restarts after closing the windows cleanly.",
        ),
    ],
};

/// Thèmes, polices et confort de l'écran.
const APPARENCE: Programme = Programme {
    nom: "omarchy theme, font, toggle",
    role: ("thèmes, polices, écran", "themes, fonts, screen"),
    executable: "omarchy",
    commandes: &[
        voir("omarchy theme list", "Les thèmes disponibles.", "Available themes."),
        voir("omarchy theme current", "Le thème actuel.", "The current theme."),
        changer(
            "omarchy theme set <nom>",
            "Change de thème partout : bureau, terminal, éditeur.",
            "Switches theme everywhere: desktop, terminal, editor.",
        ),
        changer(
            "omarchy theme install <adresse>",
            "Installe un thème depuis un dépôt git.",
            "Installs a theme from a git repository.",
        ),
        changer(
            "omarchy theme update",
            "Met à jour les thèmes installés depuis git.",
            "Updates the themes installed from git.",
        ),
        changer(
            "omarchy theme bg next",
            "Passe au fond d'écran suivant du thème.",
            "Moves to the theme's next background.",
        ),
        voir(
            "omarchy font list",
            "Les polices à chasse fixe disponibles.",
            "Available monospace fonts.",
        ),
        voir("omarchy font current", "La police actuelle.", "The current font."),
        changer(
            "omarchy font set <nom>",
            "Change la police du terminal et du bureau.",
            "Changes the terminal and desktop font.",
        ),
        changer(
            "omarchy toggle nightlight",
            "Allume ou éteint la lumière du soir (moins de bleu).",
            "Turns the night light (less blue) on or off.",
        ),
        changer(
            "omarchy toggle idle",
            "Garde l'écran allumé, ou le laisse à nouveau se mettre en veille.",
            "Keeps the screen on, or lets it sleep again.",
        ),
        changer(
            "omarchy toggle notification silencing",
            "Coupe ou rétablit les notifications (ne pas déranger).",
            "Silences or restores notifications (do not disturb).",
        ),
    ],
};

/// Le matériel vu par Omarchy.
const MATERIEL: Programme = Programme {
    nom: "omarchy hw, drive, battery",
    role: ("matériel, disques, énergie", "hardware, disks, power"),
    executable: "omarchy",
    commandes: &[
        voir(
            "omarchy battery status",
            "La batterie : pourcentage, et ce que l'ordinateur consomme ou charge.",
            "The battery: percentage, and what the computer draws or charges.",
        ),
        voir(
            "omarchy drive info <disque>",
            "Taille, modèle et points de montage d'un disque (/dev/nvme0n1…).",
            "Size, model and mount points of a disk (/dev/nvme0n1…).",
        ),
        changer(
            "omarchy drive password",
            "Change la phrase de chiffrement d'un disque.",
            "Changes a disk's encryption passphrase.",
        ),
        voir(
            "omarchy powerprofiles list",
            "Les profils d'énergie disponibles.",
            "Available power profiles.",
        ),
        changer(
            "omarchy powerprofiles set ac performance",
            "Le profil performance quand l'ordinateur est branché, gardé ensuite.",
            "The performance profile when plugged in, kept afterwards.",
        ),
        changer(
            "omarchy bluetooth power off",
            "Éteint le Bluetooth, et s'en souvient au démarrage.",
            "Turns Bluetooth off, and remembers it at boot.",
        ),
        changer(
            "omarchy dns Cloudflare",
            "Passe le DNS à Cloudflare ; omarchy dns DHCP revient à celui de la box.",
            "Switches DNS to Cloudflare; omarchy dns DHCP goes back to the router's.",
        ),
        changer(
            "omarchy restart trackpad",
            "Relance le pavé tactile qui ne répond plus.",
            "Restarts a touchpad that no longer responds.",
        ),
    ],
};
