//! Gaming sous Linux : les paquets de base pour jouer (Steam, pilotes Vulkan 32 et 64 bits, GameMode, MangoHud,
//! Gamescope, Wine, Lutris, Heroic, ProtonUp-Qt, règles des manettes) et deux réglages utiles (vm.max_map_count,
//! module ntsync). Le pilote NVIDIA lui-même n'est jamais installé ici : une erreur casse l'affichage ; seules ses
//! bibliothèques 32 bits le sont quand il est déjà en place.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use super::annulation::Valeur;
use super::{Element, element, proposer};
use crate::commande::sh_chaine;
use crate::machine::linux::natif::present;
use crate::machine::linux::paquets::{flatpak_installe, installer_flatpak, installes_parmi, noms_installes};
use crate::machine::linux::{Paquets, natif};
use crate::ui::*;

/// Fabricant de la carte graphique principale, lu dans /sys (sans lspci).
#[derive(Debug, PartialEq, Clone, Copy)]
enum Carte {
    Nvidia,
    Amd,
    Intel,
    Inconnue,
}

fn carte_graphique() -> Carte {
    let mut trouvee = Carte::Inconnue;
    for e in std::fs::read_dir("/sys/class/drm").into_iter().flatten().flatten() {
        let fabricant = std::fs::read_to_string(e.path().join("device/vendor")).unwrap_or_default();
        match fabricant.trim() {
            // Une carte dédiée l'emporte sur la puce graphique intégrée du processeur.
            "0x10de" => return Carte::Nvidia,
            "0x1002" => trouvee = Carte::Amd,
            "0x8086" if trouvee == Carte::Inconnue => trouvee = Carte::Intel,
            _ => {}
        }
    }
    trouvee
}

fn reussit(cmd: &str, args: &[&str]) -> bool {
    crate::commande::lancer(Command::new(cmd).args(args), 20).is_some_and(|r| r.code == Some(0))
}

/// Le module `nom` existe-t-il pour le noyau en service (ce que vérifiait `modinfo`) ? Il est soit compilé dans le
/// noyau (modules.builtin), soit un fichier .ko listé dans modules.dep. `None` si aucune des deux listes ne se lit.
fn module_existe(nom: &str) -> Option<bool> {
    let version = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let version = version.trim();
    ["/lib/modules", "/usr/lib/modules"].iter().find_map(|d| {
        let dossier = Path::new(d).join(version);
        let listes: Vec<String> = ["modules.builtin", "modules.dep"]
            .iter()
            .filter_map(|f| std::fs::read_to_string(dossier.join(f)).ok())
            .collect();
        (!listes.is_empty()).then(|| listes.iter().any(|l| module_dans(l, nom)))
    })
}

/// Une ligne de modules.builtin (« kernel/drivers/misc/ntsync.ko ») ou de modules.dep (« kernel/…/ntsync.ko.zst:
/// dépendances ») : le nom du module est celui du fichier, sans « .ko » ni compression. Le noyau tient « - » et
/// « _ » pour le même caractère dans un nom de module.
fn module_dans(liste: &str, nom: &str) -> bool {
    let normal = |n: &str| n.replace('-', "_");
    let cherche = normal(nom);
    liste.lines().any(|l| {
        let fichier = l
            .split(':')
            .next()
            .unwrap_or_default()
            .rsplit('/')
            .next()
            .unwrap_or_default();
        fichier
            .split_once(".ko")
            .is_some_and(|(module, reste)| (reste.is_empty() || reste.starts_with('.')) && normal(module) == cherche)
    })
}

/// Un composant en paquets de la distribution : `None` si la distribution n'en a pas de nom connu.
fn composant(
    gestion: Paquets,
    connus: Option<&HashSet<String>>,
    titre: &str,
    pourquoi: &str,
    noms: (&[&str], &[&str], &[&str], &[&str]),
) -> Option<Element> {
    let paquets = match gestion {
        Paquets::Pacman => noms.0,
        Paquets::Apt => noms.1,
        Paquets::Dnf => noms.2,
        Paquets::Zypper => noms.3,
    };
    if paquets.is_empty() {
        return None;
    }
    Some(element(
        titre,
        pourquoi,
        Some(installes_parmi(connus, gestion, paquets)),
        vec![gestion.installer(&paquets.join(" "))],
    ))
}

/// Dépôt multilib d'Arch (paquets 32 bits) : section [multilib] présente et non commentée.
fn multilib_actif(pacman_conf: &str) -> bool {
    pacman_conf.lines().any(|l| l.trim() == "[multilib]")
}

fn composants(gestion: Paquets) -> Vec<Element> {
    // La base des paquets lue une fois pour tous les composants.
    let noms = noms_installes(gestion);
    let connus = noms.as_ref();
    let mut l = Vec::new();
    // Paquets 32 bits : Steam et la plupart des jeux en ont besoin.
    match gestion {
        Paquets::Pacman => l.push(element(
            tr!(
                "Dépôt multilib (paquets 32 bits)",
                "multilib repository (32-bit packages)"
            ),
            tr!(
                "Steam et la plupart des jeux Windows ont besoin des bibliothèques 32 bits. Le système se met à jour en même temps, comme Arch le demande.",
                "Steam and most Windows games need the 32-bit libraries. The system is updated at the same time, as Arch requires."
            ),
            Some(multilib_actif(
                &std::fs::read_to_string("/etc/pacman.conf").unwrap_or_default(),
            )),
            vec![
                r"sudo sed -i '/^#\[multilib\]/,/^#Include/ s/^#//' /etc/pacman.conf".into(),
                // « pacman -Sy » seul, suivi des installations, ferait une mise à jour partielle : des paquets neufs sur
                // des bibliothèques anciennes, ce qu'Arch interdit. La base relue s'accompagne de la mise à jour.
                if crate::machine::linux::omarchy() { "omarchy update" } else { "sudo pacman -Syu" }.into(),
            ],
        )),
        Paquets::Apt => l.push(element(
            tr!(
                "Architecture i386 (paquets 32 bits)",
                "i386 architecture (32-bit packages)"
            ),
            tr!(
                "Steam et la plupart des jeux Windows ont besoin des bibliothèques 32 bits.",
                "Steam and most Windows games need the 32-bit libraries."
            ),
            // /var/lib/dpkg/arch tient la liste des architectures ; dpkg en secours, quand le fichier manque.
            Some(natif::architectures_dpkg().map_or_else(
                || {
                    crate::commande::lancer(Command::new("dpkg").arg("--print-foreign-architectures"), 10)
                        .is_some_and(|r| r.sortie.contains("i386"))
                },
                |a| a.iter().any(|x| x == "i386"),
            )),
            vec!["sudo dpkg --add-architecture i386".into(), "sudo apt-get update".into()],
        )),
        _ => {}
    }
    // Steam : paquet de la distribution, ou Flatpak là où il n'y en a pas de simple.
    match gestion {
        Paquets::Pacman | Paquets::Apt => l.extend(composant(
            gestion,
            connus,
            "Steam",
            tr!(
                "La bibliothèque de jeux, avec Proton pour lancer les jeux Windows.",
                "The game library, with Proton to run Windows games."
            ),
            (&["steam"], &["steam-installer"], &[], &[]),
        )),
        _ => l.push(element(
            "Steam (Flatpak)",
            tr!(
                "La bibliothèque de jeux, avec Proton pour lancer les jeux Windows.",
                "The game library, with Proton to run Windows games."
            ),
            Some(flatpak_installe("com.valvesoftware.Steam")),
            installer_flatpak("com.valvesoftware.Steam"),
        )),
    }
    // Pilotes Vulkan 32 et 64 bits selon la carte (DXVK et VKD3D traduisent DirectX en Vulkan).
    let vulkan = tr!(
        "Les jeux Windows passent par Vulkan (DXVK, VKD3D) : il faut le pilote Vulkan en 64 et en 32 bits.",
        "Windows games go through Vulkan (DXVK, VKD3D): the Vulkan driver is needed in 64 and 32 bits."
    );
    match (gestion, carte_graphique()) {
        (Paquets::Pacman, Carte::Nvidia) => {
            if installes_parmi(connus, gestion, &["nvidia-utils"]) {
                l.extend(composant(
                    gestion,
                    connus,
                    tr!("Vulkan NVIDIA 32 bits", "NVIDIA Vulkan 32-bit"),
                    vulkan,
                    (&["lib32-nvidia-utils", "lib32-vulkan-icd-loader"], &[], &[], &[]),
                ));
            } else {
                let mut el = element(
                    tr!("Pilote NVIDIA", "NVIDIA driver"),
                    tr!(
                        "Pilote absent : installe-le avec l'outil de ta distribution (sous Omarchy, il est installé d'office).",
                        "Driver missing: install it with your distribution's tool (Omarchy installs it by default)."
                    ),
                    Some(false),
                    Vec::new(),
                );
                el.deconseille = Some(tr!(
                    "à installer avec l'outil de ta distribution",
                    "install it with your distribution's tool"
                ));
                l.push(el);
            }
        }
        (Paquets::Pacman, Carte::Amd) => l.extend(composant(
            gestion,
            connus,
            "Vulkan AMD (RADV)",
            vulkan,
            (
                &[
                    "vulkan-radeon",
                    "lib32-vulkan-radeon",
                    "vulkan-icd-loader",
                    "lib32-vulkan-icd-loader",
                ],
                &[],
                &[],
                &[],
            ),
        )),
        (Paquets::Pacman, Carte::Intel) => l.extend(composant(
            gestion,
            connus,
            "Vulkan Intel",
            vulkan,
            (
                &[
                    "vulkan-intel",
                    "lib32-vulkan-intel",
                    "vulkan-icd-loader",
                    "lib32-vulkan-icd-loader",
                ],
                &[],
                &[],
                &[],
            ),
        )),
        (Paquets::Apt | Paquets::Dnf | Paquets::Zypper, Carte::Amd | Carte::Intel) => l.extend(composant(
            gestion,
            connus,
            "Vulkan (Mesa)",
            vulkan,
            (
                &[],
                &[
                    "mesa-vulkan-drivers",
                    "mesa-vulkan-drivers:i386",
                    "libvulkan1",
                    "libvulkan1:i386",
                ],
                &[
                    "mesa-vulkan-drivers",
                    "mesa-vulkan-drivers.i686",
                    "vulkan-loader",
                    "vulkan-loader.i686",
                ],
                &["libvulkan_radeon", "libvulkan_intel", "libvulkan1"],
            ),
        )),
        _ => {}
    }
    l.extend(composant(
        gestion,
        connus,
        "GameMode",
        tr!(
            "Donne la priorité au jeu (processeur, carte graphique) pendant qu'il tourne.",
            "Gives the game priority (processor, graphics card) while it runs."
        ),
        (
            &["gamemode", "lib32-gamemode"],
            &["gamemode"],
            &["gamemode"],
            &["gamemode"],
        ),
    ));
    l.extend(composant(
        gestion,
        connus,
        "MangoHud",
        tr!(
            "Affiche en jeu les images par seconde, les températures et la charge.",
            "Shows frames per second, temperatures and load in game."
        ),
        (
            &["mangohud", "lib32-mangohud"],
            &["mangohud"],
            &["mangohud"],
            &["mangohud"],
        ),
    ));
    l.extend(composant(
        gestion,
        connus,
        "Gamescope",
        tr!(
            "Fenêtre de jeu dédiée (mise à l'échelle, limite d'images, HDR), celle du Steam Deck.",
            "Dedicated game window (scaling, frame limit, HDR), the one used on the Steam Deck."
        ),
        (&["gamescope"], &["gamescope"], &["gamescope"], &["gamescope"]),
    ));
    l.extend(composant(
        gestion,
        connus,
        "Wine + winetricks",
        tr!(
            "Pour les jeux et lanceurs hors Steam (Battle.net, Ubisoft…).",
            "For games and launchers outside Steam (Battle.net, Ubisoft…)."
        ),
        (
            &["wine", "winetricks"],
            &["wine", "winetricks"],
            &["wine", "winetricks"],
            &["wine", "winetricks"],
        ),
    ));
    l.extend(composant(
        gestion,
        connus,
        "Lutris",
        tr!(
            "Installe et lance les jeux hors Steam (Battle.net, EA, Ubisoft, émulateurs).",
            "Installs and runs games outside Steam (Battle.net, EA, Ubisoft, emulators)."
        ),
        (&["lutris"], &["lutris"], &["lutris"], &["lutris"]),
    ));
    if !present("flatpak") {
        l.extend(composant(
            gestion,
            connus,
            tr!("Flatpak (pour Heroic et ProtonUp-Qt)", "Flatpak (for Heroic and ProtonUp-Qt)"),
            tr!(
                "Magasin d'applications de toutes les distributions : Heroic (Epic, GOG) et ProtonUp-Qt s'y installent sans mot de passe.",
                "App store for every distribution: Heroic (Epic, GOG) and ProtonUp-Qt install from it without a password."
            ),
            (&["flatpak"], &["flatpak"], &["flatpak"], &["flatpak"]),
        ));
    }
    if present("flatpak") {
        l.push(element(
            "Heroic Games Launcher (Flatpak)",
            tr!(
                "Les jeux Epic Games et GOG, avec Proton.",
                "Epic Games and GOG games, with Proton."
            ),
            Some(flatpak_installe("com.heroicgameslauncher.hgl")),
            installer_flatpak("com.heroicgameslauncher.hgl"),
        ));
        let maison = crate::socle::maison();
        let ge_proton = std::fs::read_dir(maison.join(".local/share/Steam/compatibilitytools.d"))
            .into_iter()
            .flatten()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("GE-Proton"));
        l.push(element(
            "ProtonUp-Qt (Flatpak)",
            tr!(
                "Installe et met à jour GE-Proton, souvent meilleur que Proton pour les jeux récents.",
                "Installs and updates GE-Proton, often better than Proton for recent games."
            ),
            Some(ge_proton || flatpak_installe("net.davidotek.pupgui2")),
            installer_flatpak("net.davidotek.pupgui2"),
        ));
    }
    // Règles udev des manettes (Steam, PlayStation, Xbox) : le paquet steam d'Arch les fournit déjà.
    l.extend(composant(
        gestion,
        connus,
        tr!("Règles des manettes", "Controller rules"),
        tr!(
            "Permet aux jeux de reconnaître les manettes (Steam, PlayStation, Xbox, Switch).",
            "Lets games recognize controllers (Steam, PlayStation, Xbox, Switch)."
        ),
        (&[], &["steam-devices"], &["steam-devices"], &[]),
    ));
    l
}

/// Les fichiers de Vanguard, à son nom : jamais 80-gamer.conf ou ntsync.conf, que la personne ou sa distribution ont pu
/// écrire avant lui et qu'il écraserait sans pouvoir les rendre.
const SYSCTL_JEUX: &str = "/etc/sysctl.d/80-vanguard-jeux.conf";
const NTSYNC_CONF: &str = "/etc/modules-load.d/vanguard-ntsync.conf";

/// Les valeurs d'un réglage telles qu'elles sont maintenant : notées avant de l'appliquer, relues après l'avoir remis.
pub(super) fn valeurs(id: &str) -> Vec<Valeur> {
    let fichier = |c: &str| (c.to_string(), std::fs::read_to_string(c).ok());
    match id {
        "max_map_count" => vec![
            (
                "vm.max_map_count".into(),
                std::fs::read_to_string("/proc/sys/vm/max_map_count")
                    .ok()
                    .map(|t| t.trim().to_string()),
            ),
            fichier(SYSCTL_JEUX),
        ],
        // Chargé maintenant (ou compris dans le noyau), et le fichier qui le charge au démarrage.
        "ntsync" => vec![
            (
                "ntsync".into(),
                Path::new("/sys/module/ntsync").exists().then(|| "charge".to_string()),
            ),
            fichier(NTSYNC_CONF),
        ],
        _ => Vec::new(),
    }
}

/// Un fichier que Vanguard pose dans /etc, noté sous son nom d'aujourd'hui ou sous l'ancien (note écrite avant le
/// changement de nom, `passage`) : c'est le fichier noté qui se retire ou se remet.
fn fichier_de_vanguard(nom: &str) -> bool {
    [SYSCTL_JEUX, NTSYNC_CONF]
        .iter()
        .any(|f| crate::passage::les_deux(f).iter().any(|n| n == nom))
}

/// Les commandes qui remettent les valeurs notées : les fichiers de Vanguard d'abord (retirés, ou rendus à leur
/// contenu d'avant), puis la valeur du noyau, puis le module s'il n'était pas chargé (refusé tant qu'un jeu
/// l'utilise : la note reste alors pour réessayer).
pub(super) fn remettre_commandes(_id: &str, avant: &[Valeur]) -> Vec<String> {
    let mut fichiers = Vec::new();
    let mut reste = Vec::new();
    for (nom, v) in avant {
        match (nom.as_str(), v) {
            (n, None) if fichier_de_vanguard(n) => fichiers.push(format!("sudo rm -f {nom}")),
            (n, Some(contenu)) if fichier_de_vanguard(n) => {
                fichiers.push(format!(
                    "printf '%s' {} | sudo tee {nom} >/dev/null",
                    sh_chaine(contenu)
                ));
            }
            ("vm.max_map_count", Some(n)) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => {
                reste.push(format!("sudo sysctl -w vm.max_map_count={n} >/dev/null"));
            }
            ("ntsync", None) => reste.push("sudo modprobe -r ntsync".into()),
            _ => {}
        }
    }
    fichiers.extend(reste);
    fichiers
}

fn reglages() -> Vec<Element> {
    let mut l = Vec::new();
    // vm.max_map_count : certains jeux récents (Hogwarts Legacy, Starfield, CS2…) plantent sous la valeur de SteamOS.
    let actuel: u64 = std::fs::read_to_string("/proc/sys/vm/max_map_count")
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(0);
    l.push(
        element(
            trf!(
                "vm.max_map_count (actuel : {actuel})",
                "vm.max_map_count (current: {actuel})"
            ),
            tr!(
                "Certains jeux récents plantent si cette limite de mémoire est basse ; SteamOS utilise 2147483642.",
                "Some recent games crash if this memory limit is low; SteamOS uses 2147483642."
            ),
            Some(actuel >= 1_048_576),
            vec![
                format!("echo 'vm.max_map_count = 2147483642' | sudo tee {SYSCTL_JEUX} >/dev/null"),
                format!("sudo sysctl -p {SYSCTL_JEUX} >/dev/null"),
            ],
        )
        .annulable("max_map_count", valeurs("max_map_count")),
    );
    // ntsync : synchronisation de Wine/Proton faite par le noyau (Linux 6.14 et plus), plus rapide.
    let module_present = module_existe("ntsync").unwrap_or_else(|| reussit("modinfo", &["ntsync"]));
    if module_present || Path::new("/dev/ntsync").exists() {
        l.push(element(
            tr!("Module ntsync (Wine plus rapide)", "ntsync module (faster Wine)"),
            tr!(
                "Le noyau gère la synchronisation de Wine et Proton récents : moins de saccades dans certains jeux.",
                "The kernel handles synchronization for recent Wine and Proton: less stutter in some games."
            ),
            Some(Path::new("/dev/ntsync").exists()),
            vec![
                format!("echo ntsync | sudo tee {NTSYNC_CONF} >/dev/null"),
                "sudo modprobe ntsync".into(),
            ],
        )
        .annulable("ntsync", valeurs("ntsync")));
    }
    l
}

pub(super) fn menu() {
    let Some(gestion) = Paquets::detecter() else {
        let inconnu = tr!(
            "Gestionnaire de paquets non reconnu (pacman, apt, dnf ou zypper attendu).",
            "Package manager not recognized (pacman, apt, dnf or zypper expected)."
        );
        afficher_aligne("  ✖ ", inconnu, 4, "");
        return;
    };
    match super::choisir_liste(
        (
            tr!("Paquets de base pour jouer", "Base packages for gaming"),
            tr!("Steam, Vulkan, GameMode, Wine…", "Steam, Vulkan, GameMode, Wine…"),
        ),
        (
            tr!("Réglages du système pour jouer", "System settings for gaming"),
            "vm.max_map_count, ntsync",
        ),
        None,
    )
    .as_deref()
    {
        Some("1") => {
            trp!(
                "  {GRIS}Lecture des paquets installés…{RESET}",
                "  {GRIS}Reading installed packages…{RESET}"
            );
            // Dépôt ajouté, mise à jour complète, architecture i386 : un point de restauration d'abord.
            proposer(
                tr!("Paquets de base pour jouer", "Base packages for gaming"),
                &composants(gestion),
                true,
            );
        }
        Some("2") => proposer(
            tr!("Réglages du système pour jouer", "System settings for gaming"),
            &reglages(),
            true,
        ),
        Some("3") => super::remettre(remettre_commandes, |id, _| valeurs(id)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_du_noyau_lu_dans_ses_listes() {
        let dep = "kernel/drivers/misc/ntsync.ko.zst:\nkernel/fs/fuse/fuse.ko.zst: kernel/lib/x.ko.zst\n";
        assert!(module_dans(dep, "ntsync"));
        assert!(module_dans("kernel/drivers/misc/nt_sync.ko\n", "nt-sync"));
        assert!(!module_dans(dep, "ntsy"));
        assert!(!module_dans(dep, "x.ko"));
        assert!(!module_dans("", "ntsync"));
    }

    /// Sur cet ordinateur, la liste des modules lue donne la même réponse que modinfo, quand il est là.
    #[test]
    fn comme_modinfo() {
        if present("modinfo")
            && let Some(lu) = module_existe("ntsync")
        {
            assert_eq!(lu, reussit("modinfo", &["ntsync"]));
        }
    }

    /// Chaque ligne tient dans la liste à cocher, et chaque commande est du shell valide.
    #[test]
    fn listes_de_cette_machine() {
        let mut l = reglages();
        if let Some(g) = Paquets::detecter() {
            l.extend(composants(g));
        }
        super::super::tests::tient_dans_la_liste(&l);
        for c in l.iter().flat_map(|el| &el.commandes) {
            assert!(
                Command::new("bash").args(["-n", "-c", c]).status().unwrap().success(),
                "{c}"
            );
        }
        // La mise à jour partielle d'Arch (« pacman -Sy » sans « u ») n'est jamais proposée.
        assert!(
            !l.iter()
                .flat_map(|el| &el.commandes)
                .any(|c| c.contains("pacman -Sy") && !c.contains("-Syu"))
        );
    }

    // Vanguard n'écrit que dans ses propres fichiers : un 80-gamer.conf ou un ntsync.conf posé par la personne ou sa
    // distribution n'est jamais écrasé.
    #[test]
    fn fichiers_existants_gardes() {
        for c in reglages().iter().flat_map(|el| &el.commandes) {
            assert!(
                !c.contains("80-gamer.conf") && !c.contains("modules-load.d/ntsync.conf"),
                "{c}"
            );
        }
        assert!(SYSCTL_JEUX.contains("vanguard") && NTSYNC_CONF.contains("vanguard"));
    }

    // Fichier absent avant : retiré ; valeur du noyau remise telle quelle ; module qui n'était pas chargé : retiré.
    #[test]
    fn fichier_absent_retire() {
        let avant = [
            ("vm.max_map_count".to_string(), Some("1048576".to_string())),
            (SYSCTL_JEUX.to_string(), None),
        ];
        assert_eq!(
            remettre_commandes("max_map_count", &avant),
            [
                format!("sudo rm -f {SYSCTL_JEUX}"),
                "sudo sysctl -w vm.max_map_count=1048576 >/dev/null".to_string(),
            ]
        );
        let avant = [("ntsync".to_string(), None), (NTSYNC_CONF.to_string(), None)];
        assert_eq!(
            remettre_commandes("ntsync", &avant),
            [
                format!("sudo rm -f {NTSYNC_CONF}"),
                "sudo modprobe -r ntsync".to_string()
            ]
        );
        // Une valeur qui n'est pas un nombre n'entre jamais dans la commande.
        let piege = [("vm.max_map_count".to_string(), Some("1; rm -rf ~".to_string()))];
        assert_eq!(remettre_commandes("max_map_count", &piege), Vec::<String>::new());
    }

    // Fichier de Vanguard déjà là avant (posé à la main, ou par une autre version) : rendu octet pour octet, apostrophes
    // et sauts de ligne compris. La commande est jouée pour de vrai, sur une copie dans un dossier jetable.
    #[test]
    fn fichier_existant_rendu_tel_quel() {
        let d = std::env::temp_dir().join(format!("vanguard-jeux-linux-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let copie = d.join("80-vanguard-jeux.conf");
        let contenu = "# réglé à la main, l'été\nvm.max_map_count = 262144\n";
        let avant = [(SYSCTL_JEUX.to_string(), Some(contenu.to_string()))];
        let commandes = remettre_commandes("max_map_count", &avant);
        assert_eq!(commandes.len(), 1);
        let jouee = commandes[0]
            .replace("sudo ", "")
            .replace(SYSCTL_JEUX, &copie.display().to_string());
        assert!(Command::new("bash").args(["-c", &jouee]).status().unwrap().success());
        assert_eq!(std::fs::read_to_string(&copie).unwrap(), contenu);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn depot_multilib() {
        assert!(multilib_actif(
            "[core]\nInclude = x\n\n[multilib]\nInclude = /etc/pacman.d/mirrorlist\n"
        ));
        assert!(!multilib_actif(
            "[core]\n#[multilib]\n#Include = /etc/pacman.d/mirrorlist\n"
        ));
    }
}
