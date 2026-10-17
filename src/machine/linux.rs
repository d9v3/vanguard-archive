//! Audit de sécurité Linux (Arch/Omarchy), sans privilèges root.

use std::path::Path;
use std::process::Command;

use super::{Audit, Constat, alerte, cles_ssh, impossible, ok, score, sortie};
use crate::risk::{Niveau, info_port};

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
        let (cmd, arg) = match self {
            Paquets::Pacman => ("pacman", "-Qo"),
            Paquets::Apt => ("dpkg", "-S"),
            Paquets::Dnf | Paquets::Zypper => ("rpm", "-qf"),
        };
        let connu = |f: &Path| {
            Command::new(cmd)
                .arg(arg)
                .arg(f)
                .output()
                .is_ok_and(|o| o.status.success())
        };
        // /bin, /sbin et /lib sont fusionnés dans /usr sur Debian, Ubuntu et Mint, mais dpkg garde souvent
        // l'ancien chemin : /usr/bin/fusermount3 y est enregistré comme /bin/fusermount3 (vu sur Mint 22).
        connu(fichier) || chemin_hors_usr(fichier).is_some_and(|ancien| connu(&ancien))
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

/// systemd est-il le gestionnaire de services ? Sans lui (conteneur, Alpine, Void…), on ne peut pas
/// savoir quels services tournent : on le dit au lieu de conclure.
fn systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

fn service_actif(nom: &str) -> bool {
    sortie("systemctl", &["is-active", nom]).is_some_and(|s| s.trim() == "active")
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

/// Politique d'entrée par défaut de ufw (ACCEPT, DROP ou REJECT), lue dans /etc/default/ufw.
fn politique_ufw(texte: &str) -> Option<String> {
    texte.lines().find_map(|l| {
        let v = l.trim().strip_prefix("DEFAULT_INPUT_POLICY=")?;
        Some(v.trim_matches('"').to_ascii_uppercase())
    })
}

/// ufw est-il le pare-feu actif ? (les corrections « ufw deny » n'ont de sens qu'avec lui)
fn ufw_actif() -> bool {
    std::fs::read_to_string("/etc/ufw/ufw.conf").is_ok_and(|c| c.lines().any(|l| l.trim() == "ENABLED=yes"))
        && service_actif("ufw")
}

fn pare_feu() -> Constat {
    let installer_ufw = format!(
        "command -v ufw >/dev/null || {}",
        Paquets::detecter().map_or("echo 'Installe ufw avec ta distribution'".to_string(), |g| g
            .installer("ufw"))
    );
    if !systemd() {
        return impossible("Pare-feu", "systemd absent");
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
                "ufw est actif mais accepte toutes les connexions entrantes par défaut : il ne protège rien.",
            )
            .corriger(
                "Bloquer par défaut les connexions entrantes",
                &["sudo ufw default deny incoming"],
            ),
            Some(p) => ok("Pare-feu", format!("ufw est actif, entrées refusées par défaut ({p}).")),
            None => ok("Pare-feu", "ufw est actif."),
        }
    } else if service_actif("firewalld") {
        // La zone « trusted » laisse tout passer.
        match sortie("firewall-cmd", &["--get-default-zone"]).map(|z| z.trim().to_string()) {
            Some(z) if z == "trusted" => alerte(
                "Pare-feu",
                Niveau::Eleve,
                "firewalld est actif mais en zone « trusted » : tout est accepté.",
            )
            .corriger(
                "Passer la zone par défaut en « public »",
                &["sudo firewall-cmd --set-default-zone=public"],
            ),
            Some(z) => ok("Pare-feu", format!("firewalld est actif (zone « {z} »).")),
            None => ok("Pare-feu", "firewalld est actif."),
        }
    } else if let Some(s) = ["nftables", "iptables", "ip6tables"]
        .into_iter()
        .find(|s| service_actif(s))
    {
        ok(
            "Pare-feu",
            format!("{s} est actif (règles non lisibles sans droits root)."),
        )
    } else {
        alerte(
            "Pare-feu",
            Niveau::Eleve,
            "Aucun pare-feu actif : tout service ouvert est joignable depuis le réseau.",
        )
        .corriger(
            "Activer ufw : bloquer les connexions entrantes, autoriser les sortantes",
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
            return vec![alerte("Ports en écoute", Niveau::Info, "Commande ss indisponible.")];
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
            let bruit = proto == "udp" && (port == 68 || (port >= 32768 && i.service == "Inconnu"));
            if !expose || bruit || vus.contains(&(proto, port)) {
                continue;
            }
            vus.push((proto, port));
            let programme = c
                .get(5)
                .and_then(|u| u.split('"').nth(1))
                .unwrap_or("programme inconnu (root ?)");
            // Avec un pare-feu actif, un service exposé n'est en général pas joignable : on baisse d'un cran.
            let niveau = match (pare_feu_actif, i.niveau) {
                (true, Niveau::Critique) => Niveau::Eleve,
                (true, Niveau::Eleve) => Niveau::Moyen,
                (true, _) => Niveau::Info,
                (false, Niveau::Info) => Niveau::Moyen,
                (false, n) => n,
            };
            let constat = alerte(
                "Ports en écoute",
                niveau,
                format!(
                    "{port}/{proto} ({}) ouvert sur le réseau par « {programme} ». {}",
                    i.service, i.conseil
                ),
            );
            let deny = format!("sudo ufw deny {port}/{proto}");
            let cle = format!("{port}/{proto}");
            if ufw && bloques.contains(&cle) {
                constats.push(alerte(
                    "Ports en écoute",
                    Niveau::Info,
                    format!(
                        "{cle} ({}) ouvert par « {programme} », bloqué en entrée par la règle ufw que netscan a ajoutée (vérifier : sudo ufw status).",
                        i.service
                    ),
                ));
                continue;
            }
            constats.push(match programme {
                "ollama" => constat.corriger(
                    "Faire écouter Ollama uniquement en local (127.0.0.1)",
                    &[
                        "sudo mkdir -p /etc/systemd/system/ollama.service.d",
                        "printf '[Service]\\nEnvironment=OLLAMA_HOST=127.0.0.1\\n' | sudo tee /etc/systemd/system/ollama.service.d/netscan.conf >/dev/null",
                        "sudo systemctl daemon-reload",
                        "sudo systemctl restart ollama",
                    ],
                ),
                // Un seul conseil par programme, même s'il ouvre un port TCP et un port UDP.
                "steam" if !deja_conseille.insert("steam") => constat,
                "steam" => match remote_play_steam() {
                    // Réglage déjà coupé : le port vient d'un Steam pas redémarré, ou de sa découverte locale.
                    Some(false) => constat.manuel(
                        "Remote Play est déjà désactivé dans Steam, mais Steam garde le port qu'il a ouvert au démarrage : \
                         quitte complètement Steam et relance-le. S'il reste ouvert, c'est la découverte des autres PC Steam \
                         du réseau ; ton pare-feu le bloque de toute façon",
                        &[],
                    ),
                    _ => constat.manuel(
                        "Si tu n'utilises pas Remote Play : Steam > Paramètres > Remote Play > décocher « Activer Remote Play »",
                        &[],
                    ),
                },
                _ if niveau >= Niveau::Moyen && ufw => {
                    constat
                        .corriger(format!("Bloquer le port {port}/{proto} dans le pare-feu"), &[&deny])
                        .bloquant(cle)
                }
                _ => constat,
            });
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            "Ports en écoute",
            "Aucun service TCP ou UDP exposé au réseau (tout écoute en local).",
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
        return vec![impossible("Docker", "accès au démon Docker refusé ou démon arrêté")];
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
                format!(
                    "Conteneur « {nom} » : port(s) {} publié(s) hors de la boucle locale. Docker passe devant le pare-feu : joignable(s) depuis le réseau.",
                    exposes.join(", ")
                ),
            )
            .manuel(
                "Publier seulement en local, puis recréer le conteneur : -p 127.0.0.1:PORT:PORT, ou dans docker-compose « \"127.0.0.1:PORT:PORT\" »",
                &[],
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            "Docker",
            format!("Aucun port de conteneur exposé au réseau ({actifs} conteneur(s) actif(s))."),
        ));
    }
    constats
}

fn ssh_serveur() -> Constat {
    if !systemd() {
        return impossible("SSH", "systemd absent");
    }
    // « sshd » sur Arch et Fedora, « ssh » sur Debian, Ubuntu et Mint. Ubuntu (22.10+) le lance à la demande
    // par ssh.socket : le service paraît arrêté alors que le port 22 accepte les connexions.
    if !["sshd", "ssh", "sshd.socket", "ssh.socket"]
        .iter()
        .any(|s| service_actif(s))
    {
        return ok("SSH", "Serveur SSH désactivé.");
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
    const FICHIER: &str = "/etc/ssh/sshd_config.d/00-netscan.conf";
    if valeur("PermitRootLogin").as_deref() == Some("yes") {
        return alerte("SSH", Niveau::Eleve, "Connexion root autorisée en SSH.").corriger(
            "Interdire la connexion SSH en root",
            &[
                &format!("echo 'PermitRootLogin no' | sudo tee -a {FICHIER} >/dev/null"),
                "sudo sshd -t && sudo systemctl reload sshd",
            ],
        );
    }
    if valeur("PasswordAuthentication").as_deref() != Some("no") {
        let a_des_cles = std::fs::metadata(format!("{}/.ssh/authorized_keys", home())).is_ok_and(|m| m.len() > 0);
        let c = alerte(
            "SSH",
            Niveau::Moyen,
            "Connexion SSH par mot de passe permise (vulnérable au brute force).",
        );
        return if a_des_cles {
            c.corriger(
                "N'accepter que les clés SSH (tu as déjà des clés autorisées)",
                &[
                    &format!("printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\n' | sudo tee -a {FICHIER} >/dev/null"),
                    "sudo sshd -t && sudo systemctl reload sshd",
                ],
            )
        } else {
            // Sans clé autorisée, couper les mots de passe t'enfermerait dehors.
            c.manuel(
                "Ajoute d'abord ta clé depuis l'autre ordinateur (ssh-copy-id), puis relance la correction. Ou désactive SSH si inutile :",
                &["sudo systemctl disable --now sshd"],
            )
        };
    }
    ok("SSH", "Serveur SSH actif, clés uniquement, root interdit.")
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
                None => impossible("Flatpak", "hors ligne ?"),
                Some(l) if lignes(&l) == 0 => ok("Flatpak", "Applications Flatpak à jour."),
                Some(l) => alerte(
                    "Flatpak",
                    Niveau::Moyen,
                    format!("{} application(s) Flatpak à mettre à jour.", lignes(&l)),
                )
                .corriger("Mettre à jour les applications Flatpak", &["flatpak update -y"]),
            });
        }
        if let Some(t) = snap {
            // « All snaps up to date » part sur la sortie d'erreur : sortie vide = à jour. Une ligne d'en-tête sinon.
            constats.push(match t.join().ok().flatten() {
                None => impossible("Snap", "snapd injoignable"),
                Some(l) if lignes(&l) <= 1 => ok("Snap", "Paquets Snap à jour."),
                Some(l) => alerte(
                    "Snap",
                    Niveau::Moyen,
                    format!("{} paquet(s) Snap à mettre à jour.", lignes(&l) - 1),
                )
                .corriger("Mettre à jour les paquets Snap", &["sudo snap refresh"]),
            });
        }
        if let Some((outil, t)) = aur {
            constats.push(match t.join().ok().flatten() {
                None => impossible("AUR", "hors ligne ?"),
                Some(l) if lignes(&l) == 0 => ok("AUR", "Paquets AUR à jour."),
                Some(l) => alerte(
                    "AUR",
                    Niveau::Moyen,
                    format!("{} paquet(s) AUR à mettre à jour.", lignes(&l)),
                )
                .manuel(
                    "Les paquets AUR se compilent : mets-les à jour toi-même et relis ce qui change",
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
                None => impossible("Firmware", "métadonnées fwupd absentes : fwupdmgr refresh"),
                Some(v) => {
                    let appareils: Vec<String> = v["Devices"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|d| d["Releases"].as_array().is_some_and(|r| !r.is_empty()))
                        .filter_map(|d| d["Name"].as_str().map(str::to_string))
                        .collect();
                    if appareils.is_empty() {
                        ok("Firmware", "Firmwares à jour (BIOS, SSD, périphériques).")
                    } else {
                        alerte(
                            "Firmware",
                            Niveau::Moyen,
                            format!("Mise à jour de firmware disponible : {}.", appareils.join(", ")),
                        )
                        .manuel(
                            "Installer les firmwares (un redémarrage peut être demandé)",
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
        return impossible("Mises à jour", "gestionnaire de paquets non reconnu");
    };
    let Some(liste) = liste_mises_a_jour(gestion) else {
        let raison = if gestion == Paquets::Apt {
            "liste des paquets jamais téléchargée"
        } else {
            "outil absent ou hors ligne"
        };
        return impossible("Mises à jour", raison).corriger(
            "Télécharger la liste des paquets et mettre à jour",
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
                format!("Aucune mise à jour connue, mais la liste date de {j} jours."),
            )
            .corriger("Rafraîchir la liste et mettre à jour", &[gestion.mise_a_jour()]),
            None => ok("Mises à jour", "Système à jour."),
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
        format!("{n} paquet(s) à mettre à jour, dont {sensibles} sensible(s) : noyau, openssl, navigateur…"),
    )
    .corriger("Mettre le système à jour", &[gestion.mise_a_jour()])
}

fn redemarrage() -> Constat {
    let noyau = sortie("uname", &["-r"]).unwrap_or_default().trim().to_string();
    let installes: Vec<std::path::PathBuf> = ["/usr/lib/modules", "/lib/modules"]
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .map(|e| e.path())
        // Un vrai noyau a son image (vmlinuz) ou ses modules ; on écarte les restes vides.
        .filter(|p| p.join("modules.dep").exists() || p.join("vmlinuz").exists())
        .collect();
    // Aucun noyau ici (conteneur, noyau fourni par l'hôte) : rien à comparer.
    if installes.is_empty() {
        return impossible("Noyau", "aucun noyau installé ici, conteneur ?");
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
            format!("Le noyau en cours ({noyau}) est le plus récent installé."),
        )
    } else {
        let nouveau = plus_recent
            .filter(|n| *n != noyau)
            .map(|n| format!(" ({n})"))
            .unwrap_or_default();
        alerte(
            "Noyau",
            Niveau::Moyen,
            format!("Noyau plus récent installé{nouveau} mais pas encore chargé : les correctifs ne sont pas actifs."),
        )
        .manuel("Redémarrer quand c'est pratique", &["systemctl reboot"])
    }
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
        Some(true) => ok("Chiffrement", "Système chiffré (LUKS)."),
        None => impossible("Chiffrement", "volume racine introuvable, conteneur ?"),
        Some(false) => alerte(
            "Chiffrement",
            Niveau::Moyen,
            "Le système n'est pas chiffré : en cas de vol, les données sont lisibles.",
        )
        .manuel(
            "Le chiffrement complet se choisit à l'installation (Omarchy le propose) : à prévoir à la prochaine réinstallation",
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
        ok("Secure Boot", "Démarrage sécurisé actif.")
    } else {
        alerte("Secure Boot", Niveau::Info, "Secure Boot désactivé (protège contre les bootkits).")
            .manuel("Se configure avec sbctl puis dans le BIOS ; voir le wiki Arch « Unified Extensible Firmware Interface/Secure Boot »", &[])
    }
}

fn comptes() -> Constat {
    let Ok(passwd) = std::fs::read_to_string("/etc/passwd") else {
        return impossible("Comptes", "/etc/passwd illisible");
    };
    let uid0: Vec<&str> = passwd
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split(':').collect();
            (c.get(2) == Some(&"0") && c[0] != "root").then_some(c[0])
        })
        .collect();
    if uid0.is_empty() {
        ok("Comptes", "Seul root a l'UID 0.")
    } else {
        alerte(
            "Comptes",
            Niveau::Critique,
            format!("Comptes avec droits root cachés (UID 0) : {}", uid0.join(", ")),
        )
        .manuel(
            "Signe possible d'intrusion : ne pas supprimer à l'aveugle, vérifier d'abord leur origine",
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
    let routeur = "Ouvrir l'admin du routeur > Wi-Fi > Sécurité : choisir « WPA2/WPA3 » ou « WPA3 »";
    Some(if secu.is_empty() || secu == "--" {
        alerte(
            "Wi-Fi",
            Niveau::Eleve,
            format!("« {ssid} » est un réseau ouvert : le trafic non chiffré est visible."),
        )
        .manuel(routeur, &[&admin])
    } else if secu.contains("WEP") || (secu.contains("WPA1") && !secu.contains("WPA2")) {
        alerte(
            "Wi-Fi",
            Niveau::Eleve,
            format!("« {ssid} » utilise {secu}, cassable en minutes."),
        )
        .manuel(routeur, &[&admin])
    } else if secu.contains("WPA3") {
        ok("Wi-Fi", format!("« {ssid} » en {secu}."))
    } else {
        alerte(
            "Wi-Fi",
            Niveau::Info,
            format!("« {ssid} » en {secu}. WPA3 serait mieux si le routeur le permet."),
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
            .map(|t| {
                if t.contains("lock") && sortie("pgrep", &["-x", "hypridle"]).is_some() {
                    1
                } else {
                    0
                }
            })
    } else {
        None
    };
    Some(match delai {
        None => impossible("Verrouillage", "environnement de bureau non reconnu"),
        Some(0) => alerte(
            "Verrouillage",
            Niveau::Moyen,
            "L'écran ne se verrouille jamais tout seul : un ordinateur laissé ouvert est accessible à tous.",
        )
        .manuel(
            "Activer le verrouillage automatique (5 minutes, c'est bien) dans les réglages d'écran du bureau",
            &[],
        ),
        Some(s) if s > 15 * 60 => alerte(
            "Verrouillage",
            Niveau::Info,
            format!(
                "L'écran se verrouille après {} minutes : 5 à 10 minutes serait plus sûr.",
                s / 60
            ),
        ),
        Some(s) if s >= 60 => ok(
            "Verrouillage",
            format!("L'écran se verrouille après {} minute(s) d'inactivité.", s / 60),
        ),
        Some(_) => ok("Verrouillage", "L'écran se verrouille après inactivité."),
    })
}

/// Réglages de durcissement du noyau (lisibles sans droits) : (réglage, valeur sûre minimale, rôle).
const DURCISSEMENT: &[(&str, i64, &str)] = &[
    ("kernel/randomize_va_space", 2, "adresses mémoire aléatoires (ASLR)"),
    ("kernel/kptr_restrict", 1, "adresses du noyau cachées"),
    ("kernel/dmesg_restrict", 1, "journal du noyau réservé à root"),
    (
        "kernel/yama/ptrace_scope",
        1,
        "un programme ne peut pas espionner les autres",
    ),
    ("fs/protected_symlinks", 1, "protection des liens symboliques dans /tmp"),
    ("fs/protected_hardlinks", 1, "protection des liens physiques"),
    ("net/ipv4/tcp_syncookies", 1, "résistance aux inondations SYN"),
];

/// Réglages trop faibles parmi les valeurs lues : (chemin, valeur lue, valeur sûre, rôle).
fn reglages_faibles(lire: impl Fn(&str) -> Option<i64>) -> Vec<(&'static str, i64, i64, &'static str)> {
    DURCISSEMENT
        .iter()
        .filter_map(|&(cle, min, role)| {
            let v = lire(cle)?;
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
            "Réglages de sécurité du noyau corrects (ASLR, ptrace, dmesg, liens…).",
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
    const FICHIER: &str = "/etc/sysctl.d/99-netscan.conf";
    let lignes = fusion_sysctl(
        &std::fs::read_to_string(FICHIER).unwrap_or_default(),
        &faibles
            .iter()
            .map(|(c, _, m, _)| (c.replace('/', "."), *m))
            .collect::<Vec<_>>(),
    )
    .replace('\n', "\\n");
    alerte(
        "Noyau durci",
        niveau,
        format!("Réglages faibles : {}.", liste.join(", ")),
    )
    .corriger(
        "Appliquer les valeurs sûres (fichier /etc/sysctl.d/99-netscan.conf, gardé au redémarrage)",
        &[
            &format!("printf '{lignes}' | sudo tee {FICHIER} >/dev/null"),
            "sudo sysctl --system >/dev/null",
        ],
    )
}

/// Contenu de 99-netscan.conf : les réglages déjà présents, mis à jour ou complétés par les nouveaux.
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
    reglages.iter().map(|(k, v)| format!("{k} = {v}\n")).collect()
}

/// Module de sécurité obligatoire (AppArmor, SELinux) : actif par défaut sur Ubuntu, Debian et Fedora.
fn module_securite() -> Constat {
    let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    if lsm.contains("selinux") {
        return match std::fs::read_to_string("/sys/fs/selinux/enforce").map(|v| v.trim().to_string()) {
            Ok(v) if v == "1" => ok("AppArmor/SELinux", "SELinux actif (mode strict)."),
            Ok(_) => alerte(
                "AppArmor/SELinux",
                Niveau::Moyen,
                "SELinux est en mode permissif : il signale mais ne bloque rien.",
            )
            .corriger("Repasser SELinux en mode strict", &["sudo setenforce 1"]),
            Err(_) => impossible("AppArmor/SELinux", "état de SELinux illisible"),
        };
    }
    if lsm.contains("apparmor") {
        return ok("AppArmor/SELinux", "AppArmor actif.");
    }
    // Arch ne l'active pas par défaut : simple information. Ailleurs, c'est qu'on l'a coupé.
    let attendu = matches!(Paquets::detecter(), Some(Paquets::Apt | Paquets::Dnf | Paquets::Zypper));
    if lsm.is_empty() {
        impossible("AppArmor/SELinux", "liste des modules de sécurité illisible")
    } else if attendu {
        alerte(
            "AppArmor/SELinux",
            Niveau::Moyen,
            "Ni AppArmor ni SELinux n'est actif, alors que ta distribution l'active normalement.",
        )
        .manuel(
            "Vérifier pourquoi il a été désactivé (paramètres de démarrage du noyau, paquet retiré)",
            &[],
        )
    } else {
        alerte(
            "AppArmor/SELinux",
            Niveau::Info,
            "Ni AppArmor ni SELinux (normal sur Arch, où il faut l'activer soi-même).",
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
        return impossible("Sauvegardes", "systemd absent");
    }
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64);
    let jours = |dernier: u64| (maintenant.saturating_sub(dernier)) / 86_400_000_000;
    let toutes = minuteries();
    let vraies: Vec<_> = toutes.iter().filter(|t| type_sauvegarde(&t.0) == Some(true)).collect();
    let instantanes = toutes.iter().any(|t| type_sauvegarde(&t.0) == Some(false));
    let Some(meilleure) = vraies.iter().filter(|t| t.1 > 0).max_by_key(|t| t.1) else {
        return if let Some(t) = vraies.first() {
            alerte(
                "Sauvegardes",
                Niveau::Moyen,
                format!("La sauvegarde « {} » n'a encore jamais tourné.", t.0),
            )
        } else if instantanes {
            alerte(
                "Sauvegardes",
                Niveau::Info,
                "Seulement des instantanés snapper, sur le même disque : ils ne protègent ni d'une panne de disque ni d'un vol.",
            )
            .manuel("Ajouter une vraie sauvegarde vers un autre disque ou en ligne (restic, Borg, Timeshift…)", &[])
        } else {
            alerte("Sauvegardes", Niveau::Moyen, "Aucune sauvegarde automatique détectée.").manuel(
                "Mettre en place une sauvegarde vers un autre disque ou en ligne (restic, Borg, Timeshift, Déjà Dup…)",
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
        "aujourd'hui".to_string()
    } else {
        format!("il y a {age} jour(s)")
    };
    if resultat.as_deref().is_some_and(|r| r != "success") {
        alerte(
            "Sauvegardes",
            Niveau::Moyen,
            format!(
                "La dernière sauvegarde « {nom} » ({quand}) a échoué ({}).",
                resultat.unwrap_or_default()
            ),
        )
        .manuel(
            "Voir l'erreur",
            &[&format!(
                "journalctl {}-u {service} -n 30",
                if *utilisateur { "--user " } else { "" }
            )],
        )
    } else if age > 7 {
        alerte(
            "Sauvegardes",
            Niveau::Moyen,
            format!("Dernière sauvegarde « {nom} » {quand} : trop ancienne."),
        )
    } else {
        ok(
            "Sauvegardes",
            format!("Sauvegarde automatique « {nom} », dernière {quand}."),
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

/// Programmes setuid (lancés avec les droits de leur propriétaire, souvent root) là où il ne devrait pas y en avoir,
/// ou qui n'appartiennent à aucun paquet ; et PATH piégeable.
fn fichiers_suspects() -> Vec<Constat> {
    use std::os::unix::fs::PermissionsExt;
    let mut constats = Vec::new();
    let setuid = |p: &Path| {
        p.symlink_metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o4000 != 0)
    };
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
    // Aucun setuid ne devrait vivre dans un dossier temporaire ou personnel.
    let mut anormaux = Vec::new();
    for (d, prof) in [("/tmp", 3), ("/var/tmp", 3), ("/dev/shm", 3), (&home() as &str, 2)] {
        parcourir(Path::new(d), prof, &mut anormaux, &setuid);
    }
    // Dans les dossiers système : chaque setuid doit venir d'un paquet.
    let mut systeme = Vec::new();
    for d in ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt"] {
        parcourir(Path::new(d), if d == "/opt" { 3 } else { 0 }, &mut systeme, &setuid);
    }
    if let Some(gestion) = Paquets::detecter() {
        anormaux.extend(systeme.into_iter().filter(|p| !gestion.possede(p)));
    }
    if anormaux.is_empty() {
        constats.push(ok("Fichiers suspects", "Aucun programme setuid inhabituel."));
    } else {
        let liste: Vec<String> = anormaux.iter().take(10).map(|p| p.display().to_string()).collect();
        constats.push(
            alerte(
                "Fichiers suspects",
                Niveau::Eleve,
                format!("Programme(s) setuid hors paquet ou dans un dossier temporaire : {}.", liste.join(", ")),
            )
            .manuel(
                "Un setuid inconnu peut donner les droits root : vérifier d'où il vient avant toute chose (ne pas le lancer)",
                &[&format!("ls -l {}", liste.join(" "))],
            ),
        );
    }
    let path = std::env::var("PATH").unwrap_or_default();
    let dangereux = path_dangereux(&path, |d| std::fs::metadata(d).ok().map(|m| m.permissions().mode()));
    if !dangereux.is_empty() {
        constats.push(
            alerte(
                "Fichiers suspects",
                Niveau::Eleve,
                format!(
                    "PATH piégeable : {} (n'importe qui peut y déposer un faux « ls » ou « sudo »).",
                    dangereux.join(", ")
                ),
            )
            .manuel(
                "Retirer ces dossiers du PATH (~/.bashrc, ~/.profile) ou corriger leurs droits",
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
        return impossible("Processeur", "état des failles du processeur illisible");
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
            format!(
                "Protégé contre les {} failles connues du processeur (Spectre, Meltdown…).",
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
        format!(
            "Processeur vulnérable à : {}. Un programme malveillant pourrait lire la mémoire d'autres programmes.",
            failles.join(", ")
        ),
    );
    match (paquet, Paquets::detecter()) {
        (Some(p), Some(g)) => constat.corriger(
            "Installer le microcode du fabricant (effectif après mise à jour du système et redémarrage)",
            &[&g.installer(p)],
        ),
        _ => constat.manuel(
            "Installer le microcode du fabricant et mettre le noyau à jour, puis redémarrer",
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
                format!(
                    "Lisible(s) par d'autres comptes : {} (mots de passe ou jetons d'accès).",
                    exposes.join(", ")
                ),
            )
            .corriger("Réserver ces fichiers à toi seul", &cmds),
        );
    }
    // Le dossier personnel lui-même : ouvert en lecture, il laisse voir tous tes fichiers aux autres comptes.
    if std::fs::metadata(&maison).is_ok_and(|m| m.permissions().mode() & 0o007 != 0) {
        constats.push(
            alerte(
                "Fichiers secrets",
                Niveau::Info,
                "Ton dossier personnel est lisible par les autres comptes de la machine.",
            )
            .corriger("Fermer ton dossier personnel aux autres comptes", &["chmod 750 ~"]),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            "Fichiers secrets",
            "Fichiers de mots de passe et de jetons protégés.",
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
        ok("Groupes", "Aucun groupe qui donne les droits root sans mot de passe.")
    } else {
        alerte(
            "Groupes",
            Niveau::Moyen,
            format!(
                "Tu es dans le groupe {} : tout programme lancé par toi peut devenir root sans mot de passe (via un conteneur).",
                risques.join(", ")
            ),
        )
        .manuel(
            "Si tu n'utilises pas Docker au quotidien, sors du groupe (Docker demandera alors sudo) ; sinon, garde-le en connaissance de cause",
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
            "sudo sans mot de passe pour TOUTES les commandes : n'importe quel programme lancé par toi peut devenir root.",
        )
        .manuel(
            "Retirer « NOPASSWD: » de cette règle dans /etc/sudoers.d (toujours avec sudo visudo, jamais à la main)",
            &["sudo visudo"],
        )
    } else if limitees > 0 {
        ok(
            "Sudo",
            format!("{limitees} règle(s) sudo sans mot de passe, limitée(s) à des commandes précises."),
        )
    } else {
        ok("Sudo", "sudo demande toujours le mot de passe.")
    })
}

/// Paquets AUR introuvables dans la réponse de l'AUR (retirés ou construits à la main) et paquets orphelins.
fn etat_aur(installes: &[&str], reponse: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    let resultats: Vec<&serde_json::Value> = reponse["results"].as_array().into_iter().flatten().collect();
    let absents = installes
        .iter()
        .filter(|n| !resultats.iter().any(|r| r["Name"].as_str() == Some(**n)))
        .map(|n| n.to_string())
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
            return Some(impossible("Paquets AUR", "AUR injoignable, hors ligne ?"));
        };
        resultats.extend(json["results"].as_array().cloned().unwrap_or_default());
    }
    let (absents, orphelins) = etat_aur(&installes, &serde_json::json!({ "results": resultats }));
    Some(if !absents.is_empty() {
        alerte(
            "Paquets AUR",
            Niveau::Moyen,
            format!(
                "Absent(s) de l'AUR : {} (retiré, ou construit à la main) : plus aucune mise à jour automatique.",
                absents.join(", ")
            ),
        )
        .manuel(
            "Vérifier si un paquet de remplacement existe, sinon le désinstaller s'il n'est plus utile",
            &["pacman -Qm"],
        )
    } else if !orphelins.is_empty() {
        alerte(
            "Paquets AUR",
            Niveau::Info,
            format!(
                "Paquet(s) AUR sans mainteneur : {} (les mises à jour risquent de s'arrêter).",
                orphelins.join(", ")
            ),
        )
    } else {
        ok(
            "Paquets AUR",
            format!(
                "Les {} paquets AUR installés sont tous suivis dans l'AUR.",
                installes.len()
            ),
        )
    })
}

fn services_en_echec() -> Constat {
    if !systemd() {
        return impossible("Services", "systemd absent");
    }
    let Some(liste) = sortie("systemctl", &["--failed", "--no-legend", "--plain"]) else {
        return impossible("Services", "systemctl n'a pas répondu");
    };
    let n = liste.lines().filter(|l| !l.trim().is_empty()).count();
    if n == 0 {
        ok("Services", "Aucun service système en échec.")
    } else {
        alerte("Services", Niveau::Info, format!("{n} service(s) en échec."))
            .manuel("Voir lesquels et leurs erreurs", &["systemctl --failed"])
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
    constats.extend(autres_mises_a_jour());
    constats.push(redemarrage());
    constats.push(chiffrement_disque());
    constats.extend(verrouillage_ecran());
    constats.push(durcissement_noyau());
    constats.push(module_securite());
    constats.push(sauvegardes());
    constats.extend(fichiers_suspects());
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
    fn ports_docker() {
        let c = "0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 127.0.0.1:3389->3389/tcp, 0.0.0.0:53->53/udp, 9000/tcp";
        assert_eq!(ports_docker_exposes(c), vec!["8080/tcp", "53/udp"]);
        assert!(ports_docker_exposes("127.0.0.1:8006->8006/tcp, [::1]:8006->8006/tcp").is_empty());
        // Publié sur l'IP du réseau local : exposé aussi.
        assert_eq!(ports_docker_exposes("10.0.0.179:8080->80/tcp"), vec!["8080/tcp"]);
        assert_eq!(ports_docker_exposes(":::9000->9000/tcp"), vec!["9000/tcp"]);
        assert!(ports_docker_exposes("").is_empty());
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
        assert!(!secret_expose(0o100600));
        assert!(!secret_expose(0o40700));
        assert!(secret_expose(0o100644));
        assert!(secret_expose(0o100640));
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
        assert!(reglages_faibles(|_| None).is_empty());
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
        assert!(path_dangereux("/usr/local/bin:/usr/bin", droits).is_empty());
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
        let existant = "# netscan\nkernel.kptr_restrict = 1\nkernel.dmesg_restrict=0\nmauvais = $(rm -rf ~)\n";
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
}
