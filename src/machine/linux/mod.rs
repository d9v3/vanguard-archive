//! Audit de sécurité Linux (Arch/Omarchy), sans privilèges root.

use std::fmt::Write;
use std::path::Path;
use std::process::Command;

use super::{Audit, Constat, alerte, cles_ssh, impossible, ok, score, sortie};
use crate::risk::{Niveau, info_port};
use crate::{tr, trf, trw};

mod docker;
mod durcissement;
mod maj;
mod persistance;
mod privileges;

use docker::*;
use durcissement::*;
pub use maj::mises_a_jour_completes;
use maj::*;
use persistance::*;
use privileges::*;

/// Ajouts de sentinel à la configuration de sshd (lu en premier : sshd garde la première valeur trouvée).
const SSHD_SENTINEL: &str = "/etc/ssh/sshd_config.d/00-sentinel.conf";
pub const NOM: &str = "Linux";

/// Omarchy installé : ses outils de mise à jour et d'installation passent avant pacman (instantané, migrations,
/// vérifications). Sur un Arch pur, on garde pacman.
pub fn omarchy() -> bool {
    Path::new("/usr/bin/omarchy").exists()
}

/// Commande pour installer un outil manquant sur cette distribution (texte d'aide).
pub fn commande_installation(paquet: &str) -> String {
    Paquets::detecter().map_or_else(
        || {
            trf!(
                "installe « {paquet} » avec ta distribution",
                "install “{paquet}” with your distribution"
            )
        },
        |g| g.installer(paquet),
    )
}

/// Ubuntu ou une dérivée (Mint, Pop!_OS, Zorin…) : quelques paquets n'y ont pas le nom de Debian.
pub fn famille_ubuntu() -> bool {
    std::fs::read_to_string("/etc/os-release").is_ok_and(|t| {
        t.lines()
            .filter(|l| l.starts_with("ID=") || l.starts_with("ID_LIKE="))
            .any(|l| l.split(['=', '"', ' ']).any(|id| id == "ubuntu"))
    })
}

/// Système « atomique » : racine en lecture seule, mises à jour par image complète. dnf ou zypper n'y installent
/// rien ; chacun a son outil, appliqué au prochain redémarrage.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Atomique {
    /// Fedora Silverblue/Kinoite, Bazzite, Bluefin, Aurora.
    RpmOstree,
    /// openSUSE Aeon, Kalpa, MicroOS.
    Transactionnel,
}

pub fn atomique() -> Option<Atomique> {
    if Path::new("/run/ostree-booted").exists() && Path::new("/usr/bin/rpm-ostree").exists() {
        return Some(Atomique::RpmOstree);
    }
    let racine = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    (Path::new("/usr/sbin/transactional-update").exists() && racine_lecture_seule(&racine))
        .then_some(Atomique::Transactionnel)
}

/// La racine est-elle montée en lecture seule ? (ligne « /dev/… / btrfs ro,… » de /proc/mounts)
fn racine_lecture_seule(mounts: &str) -> bool {
    mounts
        .lines()
        .rev()
        .find_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            (c.get(1) == Some(&"/")).then(|| c.get(3).copied().unwrap_or(""))
        })
        .is_some_and(|options| options.split(',').any(|o| o == "ro"))
}

/// Famille de la distribution d'après /etc/os-release : ID, puis ID_LIKE pour les dérivées (Mint et Pop!_OS
/// → ubuntu, Manjaro et CachyOS → arch, Nobara et Rocky → fedora…).
fn famille(os_release: &str) -> Option<Paquets> {
    let valeur = |cle: &str| {
        os_release
            .lines()
            .find_map(|l| l.strip_prefix(cle)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_lowercase())
            .unwrap_or_default()
    };
    format!("{} {}", valeur("ID"), valeur("ID_LIKE"))
        .split_whitespace()
        .find_map(|id| match id {
            "arch" | "archarm" => Some(Paquets::Pacman),
            "debian" | "ubuntu" => Some(Paquets::Apt),
            "fedora" | "rhel" | "centos" => Some(Paquets::Dnf),
            "suse" | "sles" => Some(Paquets::Zypper),
            id if id.starts_with("opensuse") => Some(Paquets::Zypper),
            _ => None,
        })
}

/// Gestionnaire de paquets de la distribution : Arch, Debian/Ubuntu/Mint, Fedora, openSUSE.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Paquets {
    Pacman,
    Apt,
    Dnf,
    Zypper,
}

impl Paquets {
    /// La distribution d'abord (os-release), confirmée par la présence de son outil ; sinon le premier outil
    /// trouvé, pour une distribution que l'on ne connaît pas.
    pub fn detecter() -> Option<Self> {
        let present = |c: &str| {
            ["/usr/bin", "/bin", "/usr/sbin"]
                .iter()
                .any(|d| Path::new(d).join(c).exists())
        };
        let outil = |p: Paquets| match p {
            Paquets::Pacman => present("pacman"),
            Paquets::Apt => present("apt-get"),
            // Les Fedora atomiques n'ont pas toujours dnf : rpm-ostree le remplace.
            Paquets::Dnf => present("dnf") || present("rpm-ostree"),
            Paquets::Zypper => present("zypper"),
        };
        let os_release = std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
            .unwrap_or_default();
        if let Some(p) = famille(&os_release).filter(|&p| outil(p)) {
            return Some(p);
        }
        [
            ("pacman", Paquets::Pacman),
            ("apt-get", Paquets::Apt),
            ("dnf", Paquets::Dnf),
            ("zypper", Paquets::Zypper),
        ]
        .into_iter()
        .find_map(|(c, p)| present(c).then_some(p))
    }

    /// Commande d'installation non interactive. Sous Omarchy, son propre outil (il vérifie ensuite que chaque paquet
    /// est bien là) ; sur un Arch pur, pacman. Sur un système atomique, l'ajout se fait à l'image suivante.
    pub fn installer(self, paquets: &str) -> String {
        match (self, atomique()) {
            (Paquets::Dnf, Some(Atomique::RpmOstree)) => {
                return format!(
                    "sudo rpm-ostree install --idempotent {paquets} && echo \"{}\"",
                    tr!("Redémarre pour l'utiliser.", "Reboot to use it.")
                );
            }
            (Paquets::Zypper, Some(Atomique::Transactionnel)) => {
                return format!(
                    "sudo transactional-update --non-interactive pkg install {paquets} && echo \"{}\"",
                    tr!("Redémarre pour l'utiliser.", "Reboot to use it.")
                );
            }
            _ => {}
        }
        match self {
            Paquets::Pacman if omarchy() => format!("omarchy pkg add {paquets}"),
            Paquets::Pacman => format!("sudo pacman -S --needed --noconfirm {paquets}"),
            Paquets::Apt => format!("sudo apt-get install -y {paquets}"),
            Paquets::Dnf => format!("sudo dnf install -y {paquets}"),
            Paquets::Zypper => format!("sudo zypper --non-interactive install {paquets}"),
        }
    }

    /// Le fichier appartient-il à un paquet ? (sinon : ajouté à la main)
    pub fn possede(self, fichier: &Path) -> bool {
        self.proprietaire(fichier).is_some()
    }

    /// Nom du paquet qui a installé ce fichier, `None` s'il a été ajouté à la main.
    pub fn proprietaire(self, fichier: &Path) -> Option<String> {
        let nom = |f: &Path| {
            let arg = f.to_string_lossy();
            match self {
                Paquets::Pacman => sortie("pacman", &["-Qoq", &arg]).map(|s| s.trim().to_string()),
                Paquets::Apt => sortie("dpkg", &["-S", &arg]).and_then(|s| paquet_dpkg(&s)),
                Paquets::Dnf | Paquets::Zypper => sortie("rpm", &["-qf", "--qf", "%{NAME}\\n", &arg])
                    .and_then(|s| s.lines().next().map(str::to_string)),
            }
            .filter(|n| !n.is_empty())
        };
        // /bin, /sbin et /lib sont fusionnés dans /usr sur Debian, Ubuntu et Mint, mais dpkg garde souvent
        // l'ancien chemin : /usr/bin/fusermount3 y est enregistré comme /bin/fusermount3 (vu sur Mint 22).
        nom(fichier).or_else(|| chemin_hors_usr(fichier).and_then(|ancien| nom(&ancien)))
    }

    /// Ces fichiers du paquet ont-ils changé depuis son installation ? Contenu comparé à l'empreinte enregistrée
    /// par le gestionnaire de paquets. `None` pour un fichier qu'on ne peut pas vérifier (illisible, sans empreinte).
    pub fn modifies(self, paquet: &str, fichiers: &[std::path::PathBuf]) -> Vec<Option<bool>> {
        match self {
            Paquets::Pacman => {
                // Empreintes SHA-256 dans le mtree du paquet : ne calcule que les fichiers demandés
                // (pacman -Qkk relirait tout le paquet, des centaines de Mo pour Electron).
                let mtree = sortie("pacman", &["-Q", paquet])
                    .map(|s| s.trim().replace(' ', "-"))
                    .and_then(|dossier| sortie("zcat", &[&format!("/var/lib/pacman/local/{dossier}/mtree")]));
                fichiers
                    .iter()
                    .map(|f| {
                        let attendue = empreinte_mtree(mtree.as_deref()?, f)?;
                        let calculee = sortie("sha256sum", &[&f.to_string_lossy()])?;
                        Some(calculee.split_whitespace().next()? != attendue)
                    })
                    .collect()
            }
            Paquets::Apt | Paquets::Dnf | Paquets::Zypper => {
                // dpkg --verify et rpm -V répondent 1 quand ils trouvent une différence : c'est une réponse, pas une erreur.
                let mut cmd = if self == Paquets::Apt {
                    Command::new("dpkg")
                } else {
                    Command::new("rpm")
                };
                cmd.args(if self == Paquets::Apt {
                    ["--verify", paquet]
                } else {
                    ["-V", paquet]
                })
                .env("LC_ALL", "C");
                let verif = crate::commande::lancer(&mut cmd, 60)
                    .filter(|r| matches!(r.code, Some(0 | 1)))
                    .map(|r| r.sortie);
                fichiers
                    .iter()
                    .map(|f| {
                        let verif = verif.as_deref()?;
                        let ancien = chemin_hors_usr(f);
                        Some(contenu_modifie(verif, f) || ancien.is_some_and(|a| contenu_modifie(verif, &a)))
                    })
                    .collect()
            }
        }
    }

    /// Commande pour remettre les fichiers d'origine d'un paquet.
    pub fn reinstaller(self, paquet: &str) -> String {
        match self {
            Paquets::Pacman => format!("sudo pacman -S --noconfirm {paquet}"),
            Paquets::Apt => format!("sudo apt-get install --reinstall -y {paquet}"),
            Paquets::Dnf => format!("sudo dnf reinstall -y {paquet}"),
            Paquets::Zypper => format!("sudo zypper --non-interactive install -f {paquet}"),
        }
    }

    /// Commande de mise à jour complète : l'outil propre à la distribution quand elle en a un (Omarchy,
    /// Universal Blue), l'image suivante sur un système atomique, sinon le gestionnaire de paquets.
    pub(crate) fn mise_a_jour(self) -> &'static str {
        match (self, atomique()) {
            // Bazzite, Bluefin, Aurora : met aussi à jour les Flatpak et les conteneurs.
            (Paquets::Dnf, Some(Atomique::RpmOstree)) if Path::new("/usr/bin/ujust").exists() => return "ujust update",
            (Paquets::Dnf, Some(Atomique::RpmOstree)) => return "sudo rpm-ostree upgrade",
            (Paquets::Zypper, Some(Atomique::Transactionnel)) => {
                return "sudo transactional-update --non-interactive dup";
            }
            _ => {}
        }
        match self {
            Paquets::Pacman if omarchy() => "omarchy update",
            Paquets::Pacman => "sudo pacman -Syu --noconfirm",
            Paquets::Apt => "sudo apt-get update && sudo apt-get full-upgrade -y",
            Paquets::Dnf => "sudo dnf upgrade -y",
            Paquets::Zypper => "sudo zypper --non-interactive update",
        }
    }
}

/// systemd est-il le gestionnaire de services ? Sans lui (conteneur, Alpine, Void…), on ne peut pas
/// savoir quels services tournent : on le dit au lieu de conclure.
fn systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

pub(crate) fn service_actif(nom: &str) -> bool {
    sortie("systemctl", &["is-active", nom]).is_some_and(|s| s.trim() == "active")
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

/// Politique d'entrée par défaut de ufw (ACCEPT, DROP ou REJECT), lue dans /etc/default/ufw.
pub(crate) fn politique_ufw(texte: &str) -> Option<String> {
    texte.lines().find_map(|l| {
        let v = l.trim().strip_prefix("DEFAULT_INPUT_POLICY=")?;
        Some(v.trim_matches('"').to_ascii_uppercase())
    })
}

/// ufw est-il le pare-feu actif ? (les corrections « ufw deny » n'ont de sens qu'avec lui)
pub(crate) fn ufw_actif() -> bool {
    std::fs::read_to_string("/etc/ufw/ufw.conf").is_ok_and(|c| c.lines().any(|l| l.trim() == "ENABLED=yes"))
        && service_actif("ufw")
}

fn pare_feu() -> Constat {
    let installer_ufw = format!(
        "command -v ufw >/dev/null || {}",
        Paquets::detecter().map_or(
            tr!(
                "echo 'Installe ufw avec ta distribution'",
                "echo 'Install ufw with your distribution'"
            )
            .to_string(),
            |g| g.installer("ufw")
        )
    );
    if !systemd() {
        return impossible("Pare-feu", tr!("systemd absent", "systemd missing"));
    }
    if ufw_actif() {
        // Actif ne suffit pas : encore faut-il qu'il bloque les connexions entrantes par défaut.
        let politique = std::fs::read_to_string("/etc/default/ufw")
            .ok()
            .and_then(|t| politique_ufw(&t));
        match politique.as_deref() {
            Some("ACCEPT") => alerte(
                "Pare-feu",
                Niveau::Eleve,
                tr!(
                    "ufw est actif mais accepte toutes les connexions entrantes par défaut : il ne protège rien.",
                    "ufw is running but accepts all incoming connections by default: it protects nothing."
                ),
            )
            .corriger(
                tr!(
                    "Bloquer par défaut les connexions entrantes",
                    "Block incoming connections by default"
                ),
                &["sudo ufw default deny incoming"],
            ),
            Some(p) => ok(
                "Pare-feu",
                trf!(
                    "ufw est actif, entrées refusées par défaut ({p}).",
                    "ufw is running, incoming refused by default ({p})."
                ),
            ),
            None => ok("Pare-feu", tr!("ufw est actif.", "ufw is running.")),
        }
    } else if service_actif("firewalld") {
        // La zone « trusted » laisse tout passer.
        match sortie("firewall-cmd", &["--get-default-zone"]).map(|z| z.trim().to_string()) {
            Some(z) if z == "trusted" => alerte(
                "Pare-feu",
                Niveau::Eleve,
                tr!(
                    "firewalld est actif mais en zone « trusted » : tout est accepté.",
                    "firewalld is running but in the “trusted” zone: everything is accepted."
                ),
            )
            .corriger(
                tr!(
                    "Passer la zone par défaut en « public »",
                    "Set the default zone to “public”"
                ),
                &["sudo firewall-cmd --set-default-zone=public"],
            ),
            Some(z) => ok(
                "Pare-feu",
                trf!(
                    "firewalld est actif (zone « {z} »).",
                    "firewalld is running (zone “{z}”)."
                ),
            ),
            None => ok("Pare-feu", tr!("firewalld est actif.", "firewalld is running.")),
        }
    } else if let Some(s) = ["nftables", "iptables", "ip6tables"]
        .into_iter()
        .find(|s| service_actif(s))
    {
        ok(
            "Pare-feu",
            trf!(
                "{s} est actif (règles non lisibles sans droits root).",
                "{s} is running (rules not readable without root rights)."
            ),
        )
    } else {
        alerte(
            "Pare-feu",
            Niveau::Eleve,
            tr!(
                "Aucun pare-feu actif : tout service ouvert est joignable depuis le réseau.",
                "No firewall running: every open service can be reached from the network."
            ),
        )
        .corriger(
            tr!(
                "Activer ufw : bloquer les connexions entrantes, autoriser les sortantes",
                "Turn ufw on: block incoming connections, allow outgoing ones"
            ),
            &[
                &installer_ufw,
                "sudo ufw default deny incoming",
                "sudo ufw default allow outgoing",
                "sudo ufw --force enable",
                "sudo systemctl enable --now ufw",
            ],
        )
    }
}

/// Services qui écoutent sur le réseau (pas seulement en local), en TCP et en UDP.
/// Adresses joignables depuis un autre appareil : celles des vraies interfaces (Wi-Fi, Ethernet, VPN),
/// au format de `ss` (IPv6 entre crochets). Les ponts virtuels (Docker, libvirt…) ne sont joignables
/// que depuis cette machine.
fn adresses_exposees() -> std::collections::HashSet<String> {
    let virtuelle = |nom: &str| {
        ["lo", "docker", "br-", "virbr", "veth", "podman", "lxc", "vnet"]
            .iter()
            .any(|p| nom.starts_with(p))
    };
    if_addrs::get_if_addrs()
        .into_iter()
        .flatten()
        .filter(|i| !virtuelle(&i.name) && !i.addr.ip().is_loopback())
        .map(|i| match i.addr.ip() {
            std::net::IpAddr::V4(ip) => ip.to_string(),
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        })
        .collect()
}

/// Service systemd d'une ligne de `ss -e` (« cgroup:/system.slice/passim.service » → « passim »).
pub(crate) fn service_du_cgroup(ligne: &str) -> Option<String> {
    let groupe = ligne.split_whitespace().find_map(|m| m.strip_prefix("cgroup:"))?;
    let unite = groupe.rsplit('/').next()?;
    let nom = unite.strip_suffix(".service")?;
    // Une session (« session-2.scope ») ou une app de l'utilisateur ne dit rien de plus que « programme inconnu ».
    (!nom.is_empty()).then(|| nom.to_string())
}

/// `ufw` : le pare-feu actif est ufw. Avec firewalld ou nftables, « ufw deny » ne bloquerait rien
/// (ou s'ajouterait à un ufw arrêté) tout en s'affichant « fait » : on ne le propose pas.
fn ports_ecoute(pare_feu_actif: bool, ufw: bool) -> Vec<Constat> {
    let adresses = adresses_exposees();
    let mut constats = Vec::new();
    let mut vus = Vec::new();
    let mut deja_conseille = std::collections::HashSet::new();
    let bloques = super::ports_bloques();
    // « e » : le groupe de contrôle (« cgroup:/system.slice/passim.service ») nomme le service même quand le programme,
    // lancé par root ou un compte système, reste invisible sans droits admin.
    for (proto, options) in [("tcp", "-Htlnpe"), ("udp", "-Hulnpe")] {
        let Some(ss) = sortie("ss", &[options]) else {
            return vec![alerte(
                "Ports en écoute",
                Niveau::Info,
                tr!("Commande ss indisponible.", "ss command unavailable."),
            )];
        };
        for ligne in ss.lines() {
            let c: Vec<&str> = ligne.split_whitespace().collect();
            let Some(local) = c.get(3) else { continue };
            let Some((adresse, port)) = local.rsplit_once(':') else {
                continue;
            };
            let Ok(port) = port.parse::<u16>() else { continue };
            // Zone d'une IPv6 de lien local (« [fe80::1%wlan0] ») : retirée, crochet fermant gardé.
            let sans_zone = match adresse.split_once('%') {
                Some((ip, _)) if adresse.starts_with('[') => format!("{ip}]"),
                Some((ip, _)) => ip.to_string(),
                None => adresse.to_string(),
            };
            let adresse = sans_zone.as_str();
            let expose = matches!(adresse, "0.0.0.0" | "*" | "[::]") || adresses.contains(adresse);
            let i = info_port(port);
            // UDP : client DHCP (68) et ports éphémères anonymes (sockets clientes), ce ne sont pas des services.
            let bruit = proto == "udp" && (port == 68 || (port >= 32768 && i.service == crate::risk::inconnu()));
            if !expose || bruit || vus.contains(&(proto, port)) {
                continue;
            }
            vus.push((proto, port));
            let service = service_du_cgroup(ligne);
            let programme = c
                .get(5)
                .and_then(|u| u.split('"').nth(1))
                .or(service.as_deref())
                .unwrap_or(tr!("programme inconnu (root ?)", "unknown program (root?)"));
            let niveau = super::niveau_expose(pare_feu_actif, i.niveau);
            let constat = alerte(
                "Ports en écoute",
                niveau,
                trf!(
                    "{port}/{proto} ({}) ouvert sur le réseau par « {programme} ». {}",
                    "{port}/{proto} ({}) open to the network by “{programme}”. {}",
                    i.service,
                    i.conseil
                ),
            );
            let deny = format!("sudo ufw deny {port}/{proto}");
            let cle = format!("{port}/{proto}");
            if ufw && bloques.contains(&cle) {
                constats.push(alerte(
                    "Ports en écoute",
                    Niveau::Info,
                    trf!(
                        "{cle} ({}) ouvert par « {programme} », bloqué en entrée par la règle ufw que sentinel a ajoutée (vérifier : sudo ufw status).", "{cle} ({}) opened by “{programme}”, blocked inbound by the ufw rule sentinel added (check: sudo ufw status).",
                        i.service
                    ),
                ));
                continue;
            }
            constats.push(match programme {
                "ollama" => constat.corriger(
                    tr!("Faire écouter Ollama uniquement en local (127.0.0.1)", "Make Ollama listen locally only (127.0.0.1)"),
                    &[
                        "sudo mkdir -p /etc/systemd/system/ollama.service.d",
                        "printf '[Service]\\nEnvironment=OLLAMA_HOST=127.0.0.1\\n' | sudo tee /etc/systemd/system/ollama.service.d/sentinel.conf >/dev/null",
                        "sudo systemctl daemon-reload",
                        "sudo systemctl restart ollama",
                    ],
                ),
                // Un seul conseil par programme, même s'il ouvre un port TCP et un port UDP.
                "steam" if !deja_conseille.insert("steam") => constat,
                "steam" => match remote_play_steam() {
                    // Réglage déjà coupé : le port vient d'un Steam pas redémarré, ou de sa découverte locale.
                    Some(false) => constat.manuel(
                        tr!("Remote Play est déjà désactivé dans Steam, mais Steam garde le port qu'il a ouvert au démarrage : \
                         quitte complètement Steam et relance-le. S'il reste ouvert, c'est la découverte des autres PC Steam \
                         du réseau ; ton pare-feu le bloque de toute façon", "Remote Play is already off in Steam, but Steam keeps the port it opened at startup: \
                         quit Steam completely and start it again. If it stays open, it is the discovery of the other Steam PCs \
                         on the network; your firewall blocks it anyway"),
                        &[],
                    ),
                    _ => constat.manuel(
                        tr!("Si tu n'utilises pas Remote Play : Steam > Paramètres > Remote Play > décocher « Activer Remote Play »", "If you do not use Remote Play: Steam > Settings > Remote Play > uncheck “Enable Remote Play”"),
                        &[],
                    ),
                },
                _ if niveau >= Niveau::Moyen && ufw => {
                    constat
                        .corriger(trf!("Bloquer le port {port}/{proto} dans le pare-feu", "Block port {port}/{proto} in the firewall"), &[&deny])
                        .bloquant(cle)
                }
                _ => constat,
            });
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            "Ports en écoute",
            tr!(
                "Aucun service TCP ou UDP exposé au réseau (tout écoute en local).",
                "No TCP or UDP service exposed to the network (everything listens locally)."
            ),
        ));
    }
    constats
}

/// Remote Play est-il activé dans Steam ? Lu dans le réglage « EnableStreaming » de chaque compte Steam.
/// `None` si le réglage est introuvable (Steam absent ou jamais configuré).
fn remote_play_steam() -> Option<bool> {
    let maison = Path::new(&home()).to_path_buf();
    let valeurs: Vec<bool> = [".steam/steam/userdata", ".local/share/Steam/userdata"]
        .iter()
        .filter_map(|d| std::fs::read_dir(maison.join(d)).ok())
        .flatten()
        .flatten()
        .filter_map(|compte| std::fs::read_to_string(compte.path().join("config/localconfig.vdf")).ok())
        .filter_map(|t| enable_streaming(&t))
        .collect();
    (!valeurs.is_empty()).then(|| valeurs.iter().any(|v| *v))
}

/// Valeur de « EnableStreaming » dans un fichier de réglages Steam (format VDF : "clé"<tab>"valeur").
fn enable_streaming(vdf: &str) -> Option<bool> {
    vdf.lines().find_map(|l| {
        let mut champs = l.split('"').filter(|c| !c.trim().is_empty());
        (champs.next()? == "EnableStreaming").then(|| champs.next() == Some("1"))
    })
}

fn ssh_serveur() -> Constat {
    if !systemd() {
        return impossible("SSH", tr!("systemd absent", "systemd missing"));
    }
    // « sshd » sur Arch et Fedora, « ssh » sur Debian, Ubuntu et Mint. Ubuntu (22.10+) le lance à la demande
    // par ssh.socket : le service paraît arrêté alors que le port 22 accepte les connexions.
    if !["sshd", "ssh", "sshd.socket", "ssh.socket"]
        .iter()
        .any(|s| service_actif(s))
    {
        return ok("SSH", tr!("Serveur SSH désactivé.", "SSH server off."));
    }
    let mut conf = String::new();
    // sshd garde la première valeur trouvée ; sur Arch, les fichiers .d sont inclus avant le reste.
    if let Ok(dir) = std::fs::read_dir("/etc/ssh/sshd_config.d") {
        let mut fichiers: Vec<_> = dir.flatten().map(|f| f.path()).collect();
        fichiers.sort();
        for f in fichiers {
            conf += &std::fs::read_to_string(f).unwrap_or_default();
        }
    }
    conf += &std::fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();
    let valeur = |cle: &str| {
        conf.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| {
                let (k, v) = l.split_once(char::is_whitespace)?;
                k.eq_ignore_ascii_case(cle).then(|| v.trim().to_ascii_lowercase())
            })
    };
    if valeur("PermitRootLogin").as_deref() == Some("yes") {
        return alerte(
            "SSH",
            Niveau::Eleve,
            tr!("Connexion root autorisée en SSH.", "Root login allowed over SSH."),
        )
        .corriger(
            tr!("Interdire la connexion SSH en root", "Forbid root login over SSH"),
            &[
                &format!("echo 'PermitRootLogin no' | sudo tee -a {SSHD_SENTINEL} >/dev/null"),
                "sudo sshd -t && sudo systemctl reload sshd",
            ],
        );
    }
    if valeur("PasswordAuthentication").as_deref() != Some("no") {
        let a_des_cles = std::fs::metadata(format!("{}/.ssh/authorized_keys", home())).is_ok_and(|m| m.len() > 0);
        let c = alerte(
            "SSH",
            Niveau::Moyen,
            tr!(
                "Connexion SSH par mot de passe permise (vulnérable au brute force).",
                "SSH password login allowed (vulnerable to brute force)."
            ),
        );
        return if a_des_cles {
            c.corriger(
                tr!("N'accepter que les clés SSH (tu as déjà des clés autorisées)", "Accept SSH keys only (you already have authorized keys)"),
                &[
                    &format!("printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\n' | sudo tee -a {SSHD_SENTINEL} >/dev/null"),
                    "sudo sshd -t && sudo systemctl reload sshd",
                ],
            )
        } else {
            // Sans clé autorisée, couper les mots de passe t'enfermerait dehors.
            c.manuel(
                tr!("Ajoute d'abord ta clé depuis l'autre ordinateur (ssh-copy-id), puis relance la correction. Ou désactive SSH si inutile :", "First add your key from the other computer (ssh-copy-id), then run the fix again. Or turn SSH off if unused:"),
                &["sudo systemctl disable --now sshd"],
            )
        };
    }
    ok(
        "SSH",
        tr!(
            "Serveur SSH actif, clés uniquement, root interdit.",
            "SSH server running, keys only, root forbidden."
        ),
    )
}

/// Lance une commande avec un délai maximal (sources réseau lentes). `None` si elle dépasse le délai ou si
/// son code de retour n'est pas dans `codes_ok` : une commande en échec ne doit jamais passer pour « rien à signaler »
/// (vu en test : Docker inaccessible donnait « aucun port exposé »). Certains outils répondent « rien à faire »
/// par un code non nul (yay -Qua : 1) : on les liste explicitement.
fn sortie_delai(cmd: &str, args: &[&str], secondes: u64, codes_ok: &[i32]) -> Option<String> {
    let r = crate::commande::lancer(Command::new(cmd).args(args), secondes)?;
    r.code.is_some_and(|c| codes_ok.contains(&c)).then_some(r.sortie)
}

/// Le système de fichiers racine repose-t-il sur un volume chiffré (LUKS, éventuellement sous LVM) ?
/// `None` si on ne peut pas remonter la chaîne des périphériques.
fn racine_chiffree() -> Option<bool> {
    let source = sortie("findmnt", &["-no", "SOURCE", "/"])?;
    // Btrfs affiche le sous-volume : « /dev/mapper/root[/@] ».
    let peripherique = source.trim().split('[').next()?.to_string();
    if !peripherique.starts_with("/dev/") {
        return None;
    }
    // -s : la chaîne inverse, du volume monté jusqu'au disque (lvm → crypt → part → disk).
    let chaine = sortie("lsblk", &["-nso", "TYPE", &peripherique])?;
    Some(chaine.lines().any(|l| l.trim() == "crypt"))
}

fn chiffrement_disque() -> Constat {
    // On vérifie le volume du système lui-même : un swap chiffré seul ne protège pas les données.
    match racine_chiffree() {
        Some(true) => ok("Chiffrement", tr!("Système chiffré (LUKS).", "System encrypted (LUKS).")),
        None => impossible("Chiffrement", tr!("volume racine introuvable, conteneur ?", "root volume not found, container?")),
        Some(false) => alerte(
            "Chiffrement",
            Niveau::Moyen,
            tr!("Le système n'est pas chiffré : en cas de vol, les données sont lisibles.", "The system is not encrypted: if stolen, the data can be read."),
        )
        .manuel(
            tr!("Le chiffrement complet se choisit à l'installation (Omarchy le propose) : à prévoir à la prochaine réinstallation", "Full encryption is chosen at install time (Omarchy offers it): plan it for the next reinstall"),
            &[],
        ),
    }
}

fn demarrage_securise() -> Constat {
    let actif = std::fs::read_dir("/sys/firmware/efi/efivars")
        .ok()
        .and_then(|d| {
            d.flatten()
                .find(|f| f.file_name().to_string_lossy().starts_with("SecureBoot-"))
        })
        .and_then(|f| std::fs::read(f.path()).ok())
        .is_some_and(|o| o.last() == Some(&1));
    if actif {
        ok("Secure Boot", tr!("Démarrage sécurisé actif.", "Secure Boot on."))
    } else {
        alerte("Secure Boot", Niveau::Info, tr!("Secure Boot désactivé (protège contre les bootkits).", "Secure Boot off (it protects against bootkits)."))
            .manuel(tr!("Se configure avec sbctl puis dans le BIOS ; voir le wiki Arch « Unified Extensible Firmware Interface/Secure Boot »", "Set up with sbctl, then in the BIOS; see the Arch wiki “Unified Extensible Firmware Interface/Secure Boot”"), &[])
    }
}

fn comptes() -> Constat {
    let Ok(passwd) = std::fs::read_to_string("/etc/passwd") else {
        return impossible("Comptes", tr!("/etc/passwd illisible", "/etc/passwd unreadable"));
    };
    let uid0: Vec<&str> = passwd
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split(':').collect();
            (c.get(2) == Some(&"0") && c[0] != "root").then_some(c[0])
        })
        .collect();
    if uid0.is_empty() {
        ok("Comptes", tr!("Seul root a l'UID 0.", "Only root has UID 0."))
    } else {
        alerte(
            "Comptes",
            Niveau::Critique,
            trf!(
                "Comptes avec droits root cachés (UID 0) : {}",
                "Hidden accounts with root rights (UID 0): {}",
                uid0.join(", ")
            ),
        )
        .manuel(
            tr!(
                "Signe possible d'intrusion : ne pas supprimer à l'aveugle, vérifier d'abord leur origine",
                "Possible sign of intrusion: do not delete blindly, check where they come from first"
            ),
            &["grep ':0:' /etc/passwd"],
        )
    }
}

fn wifi(passerelle: Option<String>) -> Option<Constat> {
    // SSID en dernier et sans échappement : un nom de réseau contenant « : » reste intact.
    let s = sortie(
        "nmcli",
        &["-t", "-e", "no", "-f", "ACTIVE,SECURITY,SSID", "dev", "wifi"],
    )?;
    let actif = s.lines().find(|l| l.starts_with("yes:"))?;
    let mut c = actif.splitn(3, ':').skip(1);
    let (secu, ssid) = (c.next().unwrap_or("").to_string(), c.next()?.to_string());
    let admin = format!(
        "xdg-open https://{}",
        passerelle.unwrap_or_else(|| "192.168.1.1".into())
    );
    let routeur = tr!(
        "Ouvrir l'admin du routeur > Wi-Fi > Sécurité : choisir « WPA2/WPA3 » ou « WPA3 »",
        "Open the router admin > Wi-Fi > Security: choose “WPA2/WPA3” or “WPA3”"
    );
    Some(if secu.is_empty() || secu == "--" {
        alerte(
            "Wi-Fi",
            Niveau::Eleve,
            trf!(
                "« {ssid} » est un réseau ouvert : le trafic non chiffré est visible.",
                "“{ssid}” is an open network: unencrypted traffic is visible."
            ),
        )
        .manuel(routeur, &[&admin])
    } else if secu.contains("WEP") || (secu.contains("WPA1") && !secu.contains("WPA2")) {
        alerte(
            "Wi-Fi",
            Niveau::Eleve,
            trf!(
                "« {ssid} » utilise {secu}, cassable en minutes.",
                "“{ssid}” uses {secu}, crackable in minutes."
            ),
        )
        .manuel(routeur, &[&admin])
    } else if secu.contains("WPA3") {
        ok("Wi-Fi", trf!("« {ssid} » en {secu}.", "“{ssid}” uses {secu}."))
    } else {
        alerte(
            "Wi-Fi",
            Niveau::Info,
            trf!(
                "« {ssid} » en {secu}. WPA3 serait mieux si le routeur le permet.",
                "“{ssid}” uses {secu}. WPA3 would be better if the router allows it."
            ),
        )
        .manuel(routeur, &[&admin])
    })
}

/// Verrouillage automatique de l'écran après inactivité, selon l'environnement de bureau.
fn verrouillage_ecran() -> Option<Constat> {
    // Pas de session graphique (serveur) : rien à verrouiller.
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_none() {
        return None;
    }
    let bureau = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let maison = Path::new(&home()).to_path_buf();
    // Délai de verrouillage en secondes : Some(0) = jamais, None = inconnu.
    let delai: Option<u64> = if Path::new("/usr/share/omarchy").exists() {
        // Omarchy : idle.lock dans shell.json (celui de l'utilisateur, sinon la valeur par défaut).
        [
            maison.join(".config/omarchy/shell.json"),
            "/usr/share/omarchy/config/omarchy/shell.json".into(),
        ]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .filter_map(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .find_map(|v| v["idle"]["lock"].as_u64())
    } else if bureau.contains("gnome") || bureau.contains("cinnamon") || bureau.contains("x-cinnamon") {
        let racine = if bureau.contains("cinnamon") {
            "org.cinnamon.desktop"
        } else {
            "org.gnome.desktop"
        };
        let actif =
            sortie("gsettings", &["get", &format!("{racine}.screensaver"), "lock-enabled"]).map(|v| v.trim() == "true");
        let inactivite = sortie("gsettings", &["get", &format!("{racine}.session"), "idle-delay"])
            .and_then(|v| v.split_whitespace().last()?.parse::<u64>().ok());
        match (actif, inactivite) {
            (Some(false), _) => Some(0),
            (Some(true), Some(i)) => Some(i),
            _ => None,
        }
    } else if bureau.contains("kde") {
        // KDE : verrouillage actif par défaut après 5 minutes.
        let lire = |cle: &str| {
            ["kreadconfig6", "kreadconfig5"]
                .iter()
                .find_map(|k| sortie(k, &["--file", "kscreenlockerrc", "--group", "Daemon", "--key", cle]))
                .map(|v| v.trim().to_string())
        };
        if lire("Autolock").as_deref() == Some("false") {
            Some(0)
        } else {
            Some(lire("Timeout").and_then(|m| m.parse::<u64>().ok()).unwrap_or(5) * 60)
        }
    } else if bureau.contains("hyprland") {
        // Hyprland sans Omarchy : hypridle doit avoir un délai qui verrouille.
        std::fs::read_to_string(maison.join(".config/hypr/hypridle.conf"))
            .ok()
            .map(|t| u64::from(t.contains("lock") && sortie("pgrep", &["-x", "hypridle"]).is_some()))
    } else {
        None
    };
    Some(match delai {
        None => impossible(
            "Verrouillage",
            tr!(
                "environnement de bureau non reconnu",
                "desktop environment not recognized"
            ),
        ),
        Some(0) => alerte(
            "Verrouillage",
            Niveau::Moyen,
            tr!(
                "L'écran ne se verrouille jamais tout seul : un ordinateur laissé ouvert est accessible à tous.",
                "The screen never locks by itself: a computer left open is accessible to anyone."
            ),
        )
        .manuel(
            tr!(
                "Activer le verrouillage automatique (5 minutes, c'est bien) dans les réglages d'écran du bureau",
                "Turn on automatic locking (5 minutes is good) in the desktop's display settings"
            ),
            &[],
        ),
        Some(s) if s > 15 * 60 => alerte(
            "Verrouillage",
            Niveau::Info,
            trf!(
                "L'écran se verrouille après {} minutes : 5 à 10 minutes serait plus sûr.",
                "The screen locks after {} minutes: 5 to 10 minutes would be safer.",
                s / 60
            ),
        ),
        Some(s) if s >= 60 => ok(
            "Verrouillage",
            trf!(
                "L'écran se verrouille après {} minute(s) d'inactivité.",
                "The screen locks after {} minute(s) of inactivity.",
                s / 60
            ),
        ),
        Some(_) => ok(
            "Verrouillage",
            tr!(
                "L'écran se verrouille après inactivité.",
                "The screen locks after inactivity."
            ),
        ),
    })
}

/// Minuteries systemd (système et utilisateur) : (nom, dernier passage en µs depuis 1970, service lancé, utilisateur ?).
fn minuteries() -> Vec<(String, u64, String, bool)> {
    let mut toutes = Vec::new();
    for utilisateur in [false, true] {
        let mut args = vec!["list-timers", "--all", "--output=json"];
        if utilisateur {
            args.insert(0, "--user");
        }
        let Some(json) = sortie("systemctl", &args) else {
            continue;
        };
        let Ok(serde_json::Value::Array(liste)) = serde_json::from_str::<serde_json::Value>(&json) else {
            continue;
        };
        for t in liste {
            let nom = t["unit"].as_str().unwrap_or_default().to_string();
            let service = t["activates"].as_str().unwrap_or_default().to_string();
            toutes.push((nom, t["last"].as_u64().unwrap_or(0), service, utilisateur));
        }
    }
    toutes
}

/// Une minuterie de sauvegarde ? `Some(true)` = vraie sauvegarde, `Some(false)` = instantanés sur le même disque.
fn type_sauvegarde(nom: &str) -> Option<bool> {
    let n = nom.to_ascii_lowercase();
    if [
        "restic",
        "borg",
        "backup",
        "sauvegarde",
        "kopia",
        "duplicity",
        "rsnapshot",
        "timeshift",
        "deja-dup",
        "btrbk",
    ]
    .iter()
    .any(|m| n.contains(m))
    {
        Some(true)
    } else if n.contains("snapper") && n.contains("timeline") {
        Some(false)
    } else {
        None
    }
}

/// La meilleure défense contre une panne de disque, un vol ou un rançongiciel.
fn sauvegardes() -> Constat {
    if !systemd() {
        return impossible("Sauvegardes", tr!("systemd absent", "systemd missing"));
    }
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    let jours = |dernier: u64| (maintenant.saturating_sub(dernier)) / 86_400_000_000;
    let toutes = minuteries();
    let vraies: Vec<_> = toutes.iter().filter(|t| type_sauvegarde(&t.0) == Some(true)).collect();
    let instantanes = toutes.iter().any(|t| type_sauvegarde(&t.0) == Some(false));
    let Some(meilleure) = vraies.iter().filter(|t| t.1 > 0).max_by_key(|t| t.1) else {
        return if let Some(t) = vraies.first() {
            alerte(
                "Sauvegardes",
                Niveau::Moyen,
                trf!(
                    "La sauvegarde « {} » n'a encore jamais tourné.",
                    "The “{}” backup has never run yet.",
                    t.0
                ),
            )
        } else if instantanes {
            alerte(
                "Sauvegardes",
                Niveau::Info,
                tr!("Seulement des instantanés snapper, sur le même disque : ils ne protègent ni d'une panne de disque ni d'un vol.", "Only snapper snapshots, on the same disk: they protect neither against a disk failure nor against theft."),
            )
            .manuel(tr!("Ajouter une vraie sauvegarde vers un autre disque ou en ligne (restic, Borg, Timeshift…)", "Add a real backup to another disk or online (restic, Borg, Timeshift…)"), &[])
        } else {
            alerte("Sauvegardes", Niveau::Moyen, tr!("Aucune sauvegarde automatique détectée.", "No automatic backup detected.")).manuel(
                tr!("Mettre en place une sauvegarde vers un autre disque ou en ligne (restic, Borg, Timeshift, Déjà Dup…)", "Set up a backup to another disk or online (restic, Borg, Timeshift, Déjà Dup…)"),
                &[],
            )
        };
    };
    let (nom, dernier, service, utilisateur) = meilleure;
    let mut args = vec!["show", service.as_str(), "-p", "Result", "--value"];
    if *utilisateur {
        args.insert(0, "--user");
    }
    let resultat = sortie("systemctl", &args).map(|r| r.trim().to_string());
    let age = jours(*dernier);
    let quand = if age == 0 {
        tr!("aujourd'hui", "today").to_string()
    } else {
        trf!("il y a {age} jour(s)", "{age} day(s) ago")
    };
    if resultat.as_deref().is_some_and(|r| r != "success") {
        alerte(
            "Sauvegardes",
            Niveau::Moyen,
            trf!(
                "La dernière sauvegarde « {nom} » ({quand}) a échoué ({}).",
                "The last “{nom}” backup ({quand}) failed ({}).",
                resultat.unwrap_or_default()
            ),
        )
        .manuel(
            tr!("Voir l'erreur", "See the error"),
            &[&format!(
                "journalctl {}-u {service} -n 30",
                if *utilisateur { "--user " } else { "" }
            )],
        )
    } else if age > 7 {
        alerte(
            "Sauvegardes",
            Niveau::Moyen,
            trf!(
                "Dernière sauvegarde « {nom} » {quand} : trop ancienne.",
                "Last “{nom}” backup {quand}: too old."
            ),
        )
    } else {
        ok(
            "Sauvegardes",
            trf!(
                "Sauvegarde automatique « {nom} », dernière {quand}.",
                "Automatic “{nom}” backup, last one {quand}."
            ),
        )
    }
}

/// Failles du processeur (Spectre, Meltdown…) encore ouvertes, d'après ce que le noyau en dit.
fn failles_vulnerables(etats: &[(String, String)]) -> Vec<String> {
    etats
        .iter()
        .filter(|(_, e)| e.trim_start().starts_with("Vulnerable"))
        .map(|(n, _)| n.clone())
        .collect()
}

fn processeur() -> Constat {
    let Ok(dossier) = std::fs::read_dir("/sys/devices/system/cpu/vulnerabilities") else {
        return impossible(
            "Processeur",
            tr!(
                "état des failles du processeur illisible",
                "processor flaw state unreadable"
            ),
        );
    };
    let etats: Vec<(String, String)> = dossier
        .flatten()
        .filter_map(|f| {
            Some((
                f.file_name().to_string_lossy().into_owned(),
                std::fs::read_to_string(f.path()).ok()?,
            ))
        })
        .collect();
    let failles = failles_vulnerables(&etats);
    if failles.is_empty() {
        return ok(
            "Processeur",
            trf!(
                "Protégé contre les {} failles connues du processeur (Spectre, Meltdown…).",
                "Protected against the {} known processor flaws (Spectre, Meltdown…).",
                etats.len()
            ),
        );
    }
    // Le microcode du fabricant corrige la plupart de ces failles ; le paquet change selon la distribution.
    let amd = std::fs::read_to_string("/proc/cpuinfo").is_ok_and(|c| c.contains("AuthenticAMD"));
    let paquet = match (Paquets::detecter(), amd) {
        (Some(Paquets::Pacman), true) => Some("amd-ucode"),
        (Some(Paquets::Pacman), false) => Some("intel-ucode"),
        (Some(Paquets::Apt), true) => Some("amd64-microcode"),
        (Some(Paquets::Apt), false) => Some("intel-microcode"),
        (Some(Paquets::Dnf), _) => Some("microcode_ctl linux-firmware"),
        (Some(Paquets::Zypper), true) => Some("ucode-amd"),
        (Some(Paquets::Zypper), false) => Some("ucode-intel"),
        (None, _) => None,
    };
    let constat = alerte(
        "Processeur",
        Niveau::Moyen,
        trf!(
            "Processeur vulnérable à : {}. Un programme malveillant pourrait lire la mémoire d'autres programmes.",
            "Processor vulnerable to: {}. A malicious program could read the memory of other programs.",
            failles.join(", ")
        ),
    );
    match (paquet, Paquets::detecter()) {
        (Some(p), Some(g)) => constat.corriger(
            tr!(
                "Installer le microcode du fabricant (effectif après mise à jour du système et redémarrage)",
                "Install the manufacturer's microcode (effective after a system update and a restart)"
            ),
            &[&g.installer(p)],
        ),
        _ => constat.manuel(
            tr!(
                "Installer le microcode du fabricant et mettre le noyau à jour, puis redémarrer",
                "Install the manufacturer's microcode and update the kernel, then restart"
            ),
            &[],
        ),
    }
}

fn services_en_echec() -> Constat {
    if !systemd() {
        return impossible("Services", tr!("systemd absent", "systemd missing"));
    }
    let Some(liste) = sortie("systemctl", &["--failed", "--no-legend", "--plain"]) else {
        return impossible("Services", tr!("systemctl n'a pas répondu", "systemctl did not answer"));
    };
    let n = liste.lines().filter(|l| !l.trim().is_empty()).count();
    if n == 0 {
        ok(
            "Services",
            tr!("Aucun service système en échec.", "No failed system service."),
        )
    } else {
        alerte(
            "Services",
            Niveau::Info,
            trf!("{n} service(s) en échec.", "{n} failed service(s)."),
        )
        .manuel(
            tr!("Voir lesquels et leurs erreurs", "See which ones and their errors"),
            &["systemctl --failed"],
        )
    }
}

pub fn auditer() -> Audit {
    use super::verif;
    let feu = pare_feu();
    let feu_actif = feu.probleme.is_none();
    let mut constats = vec![feu];
    constats.extend(super::en_parallele(vec![
        verif!(ports_ecoute(feu_actif, feu_actif && ufw_actif())),
        verif!(docker()),
        verif!([ssh_serveur()]),
        verif!([mises_a_jour()]),
        verif!([failles_connues()]),
        verif!(autres_mises_a_jour()),
        verif!([redemarrage()]),
        verif!([chiffrement_disque()]),
        verif!(verrouillage_ecran()),
        verif!([durcissement_noyau()]),
        verif!([module_securite()]),
        verif!([sauvegardes()]),
        verif!(fichiers_suspects()),
        verif!(persistance()),
        verif!([demarrage_securise()]),
        verif!(cles_ssh()),
        verif!(fichiers_secrets()),
        verif!([processeur()]),
        verif!(groupes_privilegies()),
        verif!(sudo_sans_mot_de_passe()),
        verif!(paquets_aur()),
        verif!([comptes()]),
        verif!(wifi(crate::scan::passerelle().map(|g| g.to_string()))),
        verif!([services_en_echec()]),
        verif!(super::dns::dns()),
        verif!(super::certificats::certificats()),
        verif!(super::extensions::extensions()),
        verif!(super::navigateur::navigateurs()),
        verif!(super::sante::sante()),
        verif!(super::journaux::journaux()),
        verif!([crate::integrite::constat()]),
    ]));

    Audit {
        systeme: NOM,
        score: score(&constats),
        constats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_d_une_ligne_ss() {
        let l =
            "LISTEN 0 10 0.0.0.0:27500 0.0.0.0:* uid:958 ino:109369 sk:5003 cgroup:/system.slice/passim.service <->";
        assert_eq!(service_du_cgroup(l).as_deref(), Some("passim"));
        let session = "LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:((\"x\",pid=1,fd=3)) uid:1000 cgroup:/user.slice/user-1000.slice/session-2.scope";
        assert_eq!(service_du_cgroup(session), None);
        assert_eq!(service_du_cgroup("LISTEN 0 1 0.0.0.0:1 0.0.0.0:*"), None);
    }

    #[test]
    fn familles_de_distributions() {
        let f = |t: &str| famille(t);
        assert!(f("ID=arch\n") == Some(Paquets::Pacman));
        assert!(f("NAME=\"Manjaro Linux\"\nID=manjaro\nID_LIKE=arch\n") == Some(Paquets::Pacman));
        assert!(f("ID=cachyos\nID_LIKE=\"arch\"\n") == Some(Paquets::Pacman));
        assert!(f("ID=debian\nVERSION_ID=\"12\"\n") == Some(Paquets::Apt));
        assert!(f("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n") == Some(Paquets::Apt));
        assert!(f("ID=pop\nID_LIKE=\"ubuntu debian\"\n") == Some(Paquets::Apt));
        assert!(f("ID=fedora\nVARIANT_ID=kinoite\n") == Some(Paquets::Dnf));
        assert!(f("ID=bazzite\nID_LIKE=\"fedora\"\n") == Some(Paquets::Dnf));
        assert!(f("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n") == Some(Paquets::Dnf));
        assert!(f("ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"\n") == Some(Paquets::Zypper));
        assert!(f("ID=alpine\n").is_none());
        // VERSION_ID ne doit pas passer pour ID.
        assert!(f("VERSION_ID=arch\n").is_none());
    }

    #[test]
    fn racine_en_lecture_seule() {
        assert!(racine_lecture_seule(
            "/dev/vda3 / btrfs ro,relatime,ssd,subvol=/@/.snapshots/5/snapshot 0 0\n/dev/vda3 /var btrfs rw 0 0\n"
        ));
        assert!(!racine_lecture_seule(
            "/dev/nvme0n1p2 / btrfs rw,noatime 0 0\nproc /proc proc ro 0 0\n"
        ));
        // Dernier montage sur / : c'est lui qui compte.
        assert!(!racine_lecture_seule("none / rootfs ro 0 0\n/dev/sda1 / ext4 rw 0 0\n"));
    }

    #[test]
    fn failles_du_processeur() {
        let etats = vec![
            ("meltdown".to_string(), "Not affected\n".to_string()),
            ("spectre_v2".to_string(), "Mitigation: Enhanced IBRS\n".to_string()),
            (
                "mds".to_string(),
                "Vulnerable: Clear CPU buffers attempted, no microcode\n".to_string(),
            ),
        ];
        assert_eq!(failles_vulnerables(&etats), vec!["mds"]);
    }

    #[test]
    fn reglage_remote_play() {
        assert_eq!(enable_streaming("\t\t\"EnableStreaming\"\t\t\"0\"\n"), Some(false));
        assert_eq!(
            enable_streaming("\"x\" \"y\"\n\t\"EnableStreaming\"\t\"1\""),
            Some(true)
        );
        assert_eq!(enable_streaming("\"Autre\"\t\"1\""), None);
    }

    #[test]
    fn minuteries_de_sauvegarde() {
        assert_eq!(type_sauvegarde("backup-home.timer"), Some(true));
        assert_eq!(type_sauvegarde("restic-nuit.timer"), Some(true));
        assert_eq!(type_sauvegarde("snapper-timeline.timer"), Some(false));
        assert_eq!(type_sauvegarde("snapper-cleanup.timer"), None);
        assert_eq!(type_sauvegarde("fstrim.timer"), None);
    }

    #[test]
    fn politique_du_pare_feu() {
        assert_eq!(
            politique_ufw("# commentaire\nDEFAULT_INPUT_POLICY=\"DROP\"\n").as_deref(),
            Some("DROP")
        );
        assert_eq!(
            politique_ufw("DEFAULT_INPUT_POLICY=\"accept\"").as_deref(),
            Some("ACCEPT")
        );
        assert_eq!(politique_ufw("rien"), None);
    }

    #[test]
    fn delai_respecte() {
        let debut = std::time::Instant::now();
        assert!(sortie_delai("sleep", &["5"], 1, &[0]).is_none());
        assert!(debut.elapsed().as_secs() < 3);
        assert_eq!(
            sortie_delai("echo", &["bonjour"], 5, &[0]).as_deref(),
            Some("bonjour\n")
        );
        // Une commande en échec n'est jamais une réponse, sauf code explicitement accepté.
        assert!(sortie_delai("sh", &["-c", "echo rien; exit 1"], 5, &[0]).is_none());
        assert_eq!(sortie_delai("sh", &["-c", "exit 1"], 5, &[0, 1]).as_deref(), Some(""));
    }
}
