//! Audit de sécurité Linux (Arch/Omarchy), sans privilèges root.

use std::path::Path;
use std::process::Command;

use super::{Audit, Constat, alerte, cles_ssh, ok, score, sortie};
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
        Command::new(cmd)
            .arg(arg)
            .arg(fichier)
            .output()
            .is_ok_and(|o| o.status.success())
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

/// systemd est-il le gestionnaire de services ? Sans lui (conteneur, Alpine, Void…), on ne peut pas
/// savoir quels services tournent : on le dit au lieu de conclure.
fn systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

fn impossible(categorie: &'static str, raison: &str) -> Constat {
    alerte(categorie, Niveau::Info, format!("Impossible de vérifier ({raison})."))
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

fn pare_feu() -> Constat {
    let installer_ufw = format!(
        "command -v ufw >/dev/null || {}",
        Paquets::detecter().map_or("echo 'Installe ufw avec ta distribution'".to_string(), |g| g
            .installer("ufw"))
    );
    if !systemd() {
        return impossible("Pare-feu", "systemd absent");
    }
    let ufw = std::fs::read_to_string("/etc/ufw/ufw.conf").is_ok_and(|c| c.lines().any(|l| l.trim() == "ENABLED=yes"))
        && service_actif("ufw");
    if ufw {
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

fn ports_ecoute(pare_feu_actif: bool) -> Vec<Constat> {
    let adresses = adresses_exposees();
    let mut constats = Vec::new();
    let mut vus = Vec::new();
    let mut deja_conseille = std::collections::HashSet::new();
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
            let adresse = adresse.split('%').next().unwrap_or(adresse);
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
                "steam" => constat.manuel(
                    "Si tu n'utilises pas Remote Play : Steam > Paramètres > Remote Play > décocher « Activer Remote Play »",
                    &[],
                ),
                _ if niveau >= Niveau::Moyen && pare_feu_actif => {
                    constat.corriger(format!("Bloquer le port {port}/{proto} dans le pare-feu"), &[&deny])
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
    let lignes = |o: &std::process::Output| {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    match gestion {
        // checkupdates : 0 = mises à jour listées, 2 = rien à faire, autre = erreur (hors ligne…).
        Paquets::Pacman => {
            let o = Command::new("checkupdates").output().ok()?;
            match o.status.code() {
                Some(0) => Some(lignes(&o)),
                Some(2) => Some(vec![]),
                _ => None,
            }
        }
        // Sorties en anglais (LC_ALL=C) : sinon les mots cherchés changent selon la langue du système.
        // Lit le cache d'apt sans le rafraîchir (il faudrait sudo) : il date du dernier « apt update ».
        // Sans cache, « rien à mettre à jour » ne voudrait rien dire.
        Paquets::Apt => {
            age_cache_apt()?;
            let o = Command::new("apt")
                .args(["list", "--upgradable"])
                .env("LC_ALL", "C")
                .output()
                .ok()?;
            o.status
                .success()
                .then(|| lignes(&o).into_iter().filter(|l| l.contains("[upgradable")).collect())
        }
        // dnf check-update : 100 = mises à jour disponibles, 0 = rien, autre = erreur.
        Paquets::Dnf => {
            let o = Command::new("dnf")
                .args(["-q", "check-update"])
                .env("LC_ALL", "C")
                .output()
                .ok()?;
            match o.status.code() {
                Some(100) => Some(
                    lignes(&o)
                        .into_iter()
                        .filter(|l| !l.trim().is_empty() && !l.starts_with(' '))
                        .collect(),
                ),
                Some(0) => Some(vec![]),
                _ => None,
            }
        }
        Paquets::Zypper => {
            let o = Command::new("zypper")
                .args(["-q", "list-updates"])
                .env("LC_ALL", "C")
                .output()
                .ok()?;
            o.status
                .success()
                .then(|| lignes(&o).into_iter().filter(|l| l.starts_with("v ")).collect())
        }
    }
}

/// Lance une commande avec un délai maximal (sources réseau lentes). `None` si elle dépasse le délai ou si
/// son code de retour n'est pas dans `codes_ok` : une commande en échec ne doit jamais passer pour « rien à signaler »
/// (vu en test : Docker inaccessible donnait « aucun port exposé »). Certains outils répondent « rien à faire »
/// par un code non nul (yay -Qua : 1) : on les liste explicitement.
fn sortie_delai(cmd: &str, args: &[&str], secondes: u64, codes_ok: &[i32]) -> Option<String> {
    use std::io::Read;
    let mut enfant = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let mut flux = enfant.stdout.take()?;
    let lecteur = std::thread::spawn(move || {
        let mut texte = String::new();
        let _ = flux.read_to_string(&mut texte);
        texte
    });
    let limite = std::time::Instant::now() + std::time::Duration::from_secs(secondes);
    let statut = loop {
        match enfant.try_wait() {
            Ok(Some(statut)) => break statut,
            Ok(None) if std::time::Instant::now() < limite => std::thread::sleep(std::time::Duration::from_millis(100)),
            _ => {
                let _ = enfant.kill();
                let _ = enfant.wait();
                return None;
            }
        }
    };
    let texte = lecteur.join().ok()?;
    statut.code().is_some_and(|c| codes_ok.contains(&c)).then_some(texte)
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
        return alerte(
            "Mises à jour",
            Niveau::Info,
            "Impossible de vérifier (gestionnaire de paquets non reconnu).",
        );
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
    let a_jour =
        en_cours && plus_recent.as_deref() == Some(noyau.as_str()) && !Path::new("/var/run/reboot-required").exists();
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
    constats.extend(ports_ecoute(feu_actif));
    constats.extend(docker());
    constats.push(ssh_serveur());
    constats.push(mises_a_jour());
    constats.extend(autres_mises_a_jour());
    constats.push(redemarrage());
    constats.push(chiffrement_disque());
    constats.push(demarrage_securise());
    constats.extend(cles_ssh());
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
