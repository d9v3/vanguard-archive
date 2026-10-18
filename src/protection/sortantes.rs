//! Qui parle à Internet ? Les connexions établies de cet ordinateur vers Internet, regroupées par programme, avec le
//! nom du serveur (DNS inverse). Repère un logiciel espion ou un mouchard : programme lancé depuis un dossier
//! temporaire ou les Téléchargements, programme effacé après son lancement, port connu des logiciels d'accès à
//! distance ou inhabituel, serveur sans nom. Les connexions des programmes d'autres comptes (système, services) sont
//! invisibles sans droits d'administrateur : comptées à part, jamais comme saines. Lecture seule : rien n'est coupé
//! ni bloqué.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::risk::Niveau;
use crate::ui::*;

/// Une connexion établie vers un serveur.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Connexion {
    pid: Option<u32>,
    /// Nom du programme ; `None` : programme d'un autre compte, invisible sans droits d'administrateur.
    programme: Option<String>,
    /// Chemin de l'exécutable, s'il a pu être lu.
    chemin: Option<String>,
    distante: IpAddr,
    port: u16,
    udp: bool,
}

impl Connexion {
    fn vers(distante: IpAddr, port: u16) -> Connexion {
        Connexion {
            pid: None,
            programme: None,
            chemin: None,
            distante,
            port,
            udp: false,
        }
    }
}

/// Grands hébergeurs, dont le nom inverse dit mal à qui l'on parle (« lhr25s34-in-f14.1e100.net » : Google). Une
/// ligne par entreprise : son nom | ses domaines.
const PROPRIETAIRES: &str = "\
Google | 1e100.net googleusercontent.com
YouTube | googlevideo.com
Akamai | akamaitechnologies.com akamai.net akamaiedge.net
Amazon AWS | amazonaws.com
Amazon CloudFront | cloudfront.net
Meta | fbcdn.net facebook.com
WhatsApp | whatsapp.net
Microsoft | msedge.net microsoft.com windows.net
Microsoft Azure | azure.com
Apple | apple.com aaplimg.com icloud.com
Cloudflare | cloudflare.com cloudflare.net
Fastly | fastly.net
Valve (Steam) | valve.net steamcontent.com steamserver.net
Netflix | nflxvideo.net
Spotify | spotify.com
GitHub | github.com";

// ───────────────────────────── Lecture des connexions ─────────────────────────────

/// « 140.82.112.4:443 », « [2606:4700::1111]:443 », « 192.168.1.2%wlan0:68 » → (adresse, port).
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn adresse_et_port(t: &str) -> Option<(IpAddr, u16)> {
    let (hote, port) = t.rsplit_once(':')?;
    let hote = hote.trim_start_matches('[').trim_end_matches(']');
    let hote = hote.split('%').next()?;
    Some((hote.parse().ok()?, port.parse().ok()?))
}

/// Le programme d'une ligne de ss : users:(("firefox",pid=4242,fd=56)). Son nom peut contenir des espaces
/// (« Web Content »).
#[cfg(any(target_os = "linux", test))]
fn lire_processus(ligne: &str) -> (Option<String>, Option<u32>) {
    let Some(debut) = ligne.find("users:((\"") else {
        return (None, None);
    };
    let reste = &ligne[debut + 9..];
    let nom = reste.split_once('"').map(|(n, _)| n.to_string());
    let pid = reste
        .split_once("pid=")
        .and_then(|(_, r)| r.split([',', ')']).next()?.parse().ok());
    (nom, pid)
}

/// Sortie de `ss -tunpH state established` : « tcp 0 0 local distante users:((…)) ». Sans droits root, les
/// connexions des autres comptes paraissent sans « users: ».
#[cfg(any(target_os = "linux", test))]
fn lire_ss(sortie: &str) -> Vec<Connexion> {
    sortie
        .lines()
        .filter_map(|l| {
            let avant = l.split("users:").next().unwrap_or(l);
            let champs: Vec<&str> = avant.split_whitespace().collect();
            let udp = champs.first()? == &"udp";
            let adresses: Vec<(IpAddr, u16)> = champs.iter().filter_map(|c| adresse_et_port(c)).collect();
            let &(distante, port) = adresses.get(1)?;
            let (programme, pid) = lire_processus(l);
            Some(Connexion {
                pid,
                programme,
                udp,
                ..Connexion::vers(distante, port)
            })
        })
        .collect()
}

/// Sortie du script PowerShell : « distante|port|pid|nom|chemin ». Le chemin d'un programme d'un autre compte
/// reste vide sans droits d'administrateur ; son nom, lui, se lit.
#[cfg(any(windows, test))]
fn lire_windows(sortie: &str) -> Vec<Connexion> {
    sortie
        .lines()
        .filter_map(|l| {
            let mut p = l.split('|');
            let distante: IpAddr = p.next()?.trim().parse().ok()?;
            let port = p.next()?.trim().parse().ok()?;
            let pid = p.next()?.trim().parse().ok();
            let programme = p.next().map(str::trim).filter(|n| !n.is_empty()).map(String::from);
            let chemin = p.next().map(str::trim).filter(|c| !c.is_empty()).map(String::from);
            Some(Connexion {
                pid,
                programme,
                chemin,
                ..Connexion::vers(distante, port)
            })
        })
        .collect()
}

/// Sortie de `lsof -nP -iTCP -sTCP:ESTABLISHED -F pcn` : un champ par ligne, « p » (processus), « c » (nom),
/// « n » (« locale->distante »).
#[cfg(any(target_os = "macos", test))]
fn lire_lsof(sortie: &str) -> Vec<Connexion> {
    let (mut pid, mut programme) = (None, None);
    let mut liste = Vec::new();
    for l in sortie.lines() {
        let mut lettres = l.chars();
        let champ = lettres.next();
        let valeur = lettres.as_str();
        match champ {
            Some('p') => {
                pid = valeur.parse().ok();
                programme = None;
            }
            Some('c') => programme = Some(valeur.to_string()),
            Some('n') => {
                if let Some((distante, port)) = valeur.split_once("->").and_then(|(_, d)| adresse_et_port(d)) {
                    liste.push(Connexion {
                        pid,
                        programme: programme.clone(),
                        ..Connexion::vers(distante, port)
                    });
                }
            }
            _ => {}
        }
    }
    liste
}

/// Connexions établies d'après `netstat -anp tcp` (macOS : « 142.250.1.1.443 », le port après le dernier point),
/// moins celles que lsof a rattachées à un programme : ce qui reste appartient à d'autres comptes.
#[cfg(any(target_os = "macos", test))]
fn invisibles(netstat: &str, visibles: &[Connexion]) -> Vec<Connexion> {
    let mut restantes: Vec<(IpAddr, u16)> = visibles.iter().map(|c| (c.distante, c.port)).collect();
    netstat
        .lines()
        .filter(|l| l.contains("ESTABLISHED"))
        .filter_map(|l| {
            let distante = l.split_whitespace().nth(4)?;
            let (ip, port) = distante.rsplit_once('.')?;
            Some((ip.split('%').next()?.parse::<IpAddr>().ok()?, port.parse::<u16>().ok()?))
        })
        .filter(|cle| match restantes.iter().position(|v| v == cle) {
            Some(i) => {
                restantes.swap_remove(i);
                false
            }
            None => true,
        })
        .map(|(distante, port)| Connexion::vers(distante, port))
        .collect()
}

#[cfg(target_os = "linux")]
fn connexions() -> Option<Vec<Connexion>> {
    let r = crate::commande::lancer(
        std::process::Command::new("ss").args(["-tunpH", "state", "established"]),
        15,
    )?;
    if r.code != Some(0) {
        return None;
    }
    let mut liste = lire_ss(&r.sortie);
    for c in &mut liste {
        if let Some(pid) = c.pid {
            c.chemin = std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .map(|p| p.display().to_string());
        }
    }
    Some(liste)
}

#[cfg(windows)]
fn connexions() -> Option<Vec<Connexion>> {
    // Le chemin d'un processus protégé lève une erreur au lieu d'être vide : rattrapée, sinon tout le script tombe.
    let sortie = crate::machine::windows::ps(
        "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object { \
         $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; \
         $c = try { $p.Path } catch { '' }; \
         \"$($_.RemoteAddress)|$($_.RemotePort)|$($_.OwningProcess)|$($p.ProcessName)|$c\" }",
    )?;
    Some(lire_windows(&sortie))
}

#[cfg(target_os = "macos")]
fn connexions() -> Option<Vec<Connexion>> {
    use std::process::Command;
    // lsof répond 1 quand il ne trouve rien : une liste vide, pas une panne.
    let lsof = crate::commande::lancer(
        Command::new("lsof").args(["-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn"]),
        20,
    )?;
    let mut liste = lire_lsof(&lsof.sortie);
    let pids: BTreeSet<u32> = liste.iter().filter_map(|c| c.pid).collect();
    let chemins: HashMap<u32, String> = pids
        .into_iter()
        .filter_map(|pid| {
            let r = crate::commande::lancer(Command::new("ps").args(["-o", "comm=", "-p", &pid.to_string()]), 5)?;
            let chemin = r.sortie.trim().to_string();
            chemin.starts_with('/').then_some((pid, chemin))
        })
        .collect();
    for c in &mut liste {
        c.chemin = c.pid.and_then(|p| chemins.get(&p).cloned());
    }
    if let Some(n) = crate::commande::lancer(Command::new("netstat").args(["-anp", "tcp"]), 15) {
        let autres = invisibles(&n.sortie, &liste);
        liste.extend(autres);
    }
    Some(liste)
}

// ───────────────────────────── Jugement ─────────────────────────────

/// Un serveur sur Internet, pas un appareil de la maison (réseau privé, adresses partagées des fournisseurs, VPN).
fn sur_internet(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return sur_internet(IpAddr::V4(v4));
            }
            let s = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s & 0xfe00) == 0xfc00
                || (s & 0xffc0) == 0xfe80)
        }
    }
}

/// Le service derrière un port bien connu.
fn service(port: u16, udp: bool) -> Option<&'static str> {
    Some(match port {
        443 if udp => tr!("web (QUIC)", "web (QUIC)"),
        443 => "HTTPS",
        80 => "HTTP",
        853 => tr!("DNS chiffré", "encrypted DNS"),
        53 => "DNS",
        123 => tr!("heure (NTP)", "time (NTP)"),
        993 | 143 => tr!("courriel (IMAP)", "email (IMAP)"),
        465 | 587 | 25 => tr!("courriel (SMTP)", "email (SMTP)"),
        995 | 110 => tr!("courriel (POP3)", "email (POP3)"),
        22 => "SSH",
        9418 => "git",
        5222 | 5223 => tr!("messagerie, notifications", "messaging, notifications"),
        5228..=5230 => tr!("notifications Google", "Google notifications"),
        3478..=3481 | 19302..=19309 => tr!("appels (STUN)", "calls (STUN)"),
        1935 => tr!("vidéo en direct", "live video"),
        27015..=27050 => "Steam",
        3074 => "Xbox Live",
        1119 => "Battle.net",
        25565 => "Minecraft",
        8080 | 8443 | 8000 | 8008 | 8888 => tr!("web (port secondaire)", "web (secondary port)"),
        1883 | 8883 => tr!("objets connectés (MQTT)", "connected devices (MQTT)"),
        5938 => "TeamViewer",
        3389 => tr!("Bureau à distance", "Remote Desktop"),
        5900..=5903 => "VNC",
        9001 | 9030 | 9050 | 9150 => "Tor",
        6881..=6889 | 51413 => "BitTorrent",
        _ => return None,
    })
}

/// Ports des logiciels d'accès à distance malveillants et des réseaux de zombies (Metasploit, IRC, NetBus,
/// njRAT, Quasar, DarkComet…).
fn port_suspect(port: u16) -> bool {
    matches!(
        port,
        4444 | 1337 | 31337 | 6666..=6669 | 12345 | 54321 | 1177 | 5552 | 4782 | 1604
    )
}

/// Un dossier d'où un vrai programme ne se lance pas d'habitude.
fn dossier_risque(chemin: &str, montages: &str) -> Option<&'static str> {
    let c = chemin.to_lowercase().replace('\\', "/");
    // macOS : une app téléchargée lancée sur place tourne depuis un dossier temporaire « AppTranslocation ».
    if c.contains("/apptranslocation/") || appimage(chemin, montages) {
        return None;
    }
    // Dossiers temporaires : à la racine sous Linux et macOS, sous le dossier du compte ou de Windows ailleurs.
    let racines = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/private/tmp/",
        "/private/var/folders/",
    ];
    if racines.iter().any(|t| c.starts_with(t))
        || ["/appdata/local/temp/", "/windows/temp/"].iter().any(|t| c.contains(t))
    {
        return Some(tr!("un dossier temporaire", "a temporary folder"));
    }
    if c.contains("/downloads/") || c.contains("/téléchargements/") {
        return Some(tr!("les Téléchargements", "Downloads"));
    }
    if c.contains("/users/public/") {
        return Some(tr!(
            "le dossier Public, partagé par tous les comptes",
            "the Public folder, shared by all accounts"
        ));
    }
    None
}

/// Linux : une AppImage tourne depuis son image, montée dans « /tmp/.mount_<nom><code> » le temps qu'elle tourne. Un
/// simple dossier de ce nom ne suffit pas : il faut qu'il soit monté (`montages` : le contenu de /proc/self/mounts).
fn appimage(chemin: &str, montages: &str) -> bool {
    let Some(reste) = chemin.strip_prefix("/tmp/.mount_") else {
        return false;
    };
    let point = format!("/tmp/.mount_{}", reste.split('/').next().unwrap_or_default());
    montages
        .lines()
        .any(|l| l.split_whitespace().nth(1) == Some(point.as_str()))
}

/// Un nouveau fichier qu'un programme lancé par la personne n'a pas pu poser : fichier et dossier à root, dossier que
/// ni le groupe ni les autres n'écrivent (/usr, /opt, /snap, /var/lib/flatpak d'ordinaire). Ailleurs (profil, /tmp),
/// un programme malveillant qui s'est effacé n'aurait qu'à reposer n'importe quel fichier à sa place.
#[cfg_attr(not(unix), allow(dead_code))]
fn hors_de_portee(proprietaire_fichier: u32, proprietaire_dossier: u32, mode_dossier: u32) -> bool {
    proprietaire_fichier == 0 && proprietaire_dossier == 0 && mode_dossier & 0o022 == 0
}

#[cfg(unix)]
fn pose_par_le_systeme(chemin: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(fichier), Some(Ok(dossier))) = (std::fs::metadata(chemin), chemin.parent().map(std::fs::metadata)) else {
        return false;
    };
    hors_de_portee(fichier.uid(), dossier.uid(), dossier.mode())
}

#[cfg(not(unix))]
fn pose_par_le_systeme(_: &std::path::Path) -> bool {
    false
}

/// Le nom à montrer pour un serveur : son domaine (« github.com »), ou l'entreprise derrière un grand hébergeur.
fn qui(nom: &str) -> String {
    let domaine = crate::protection::lien::domaine_enregistrable(nom);
    PROPRIETAIRES
        .lines()
        .find_map(|l| {
            let (qui, domaines) = l.split_once(" | ")?;
            domaines
                .split_whitespace()
                .any(|d| d == domaine)
                .then(|| qui.to_string())
        })
        .unwrap_or(domaine)
}

/// Ce qui mérite l'attention dans les connexions d'un programme : (gravité, texte).
fn signes(chemin: Option<&str>, connexions: &[(&Connexion, Option<&String>)], montages: &str) -> Vec<(Niveau, String)> {
    let mut signes = Vec::new();
    if let Some(c) = chemin {
        // Un nouveau fichier à la même place, posé par le système : le programme a été mis à jour pendant qu'il
        // tournait (Firefox après une mise à jour du système), l'ancienne version reste en mémoire.
        match c.strip_suffix(" (deleted)") {
            Some(ancien) if pose_par_le_systeme(std::path::Path::new(ancien)) => signes.push((
                Niveau::Info,
                tr!(
                    "Mis à jour pendant qu'il tournait : l'ancienne version tourne encore, redémarre-le.",
                    "Updated while running: the old version is still running, restart it."
                )
                .to_string(),
            )),
            Some(_) => signes.push((
                Niveau::Eleve,
                tr!(
                    "Programme effacé après son lancement : une ruse pour ne pas laisser de trace.",
                    "Program deleted after it started: a trick to leave no trace."
                )
                .to_string(),
            )),
            None => {}
        }
        if let Some(ou) = dossier_risque(c, montages) {
            signes.push((
                Niveau::Eleve,
                trf!(
                    "Lancé depuis {ou} : un vrai programme s'installe d'abord.",
                    "Started from {ou}: a real program gets installed first."
                ),
            ));
        }
    }
    let suspects: BTreeSet<u16> = connexions
        .iter()
        .map(|(c, _)| c.port)
        .filter(|p| port_suspect(*p))
        .collect();
    if !suspects.is_empty() {
        let ports = suspects.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
        signes.push((
            Niveau::Eleve,
            trf!(
                "Port {ports} : celui de logiciels d'accès à distance malveillants.",
                "Port {ports}: the one of malicious remote access tools."
            ),
        ));
    }
    // Un port inconnu en TCP mérite un regard ; en UDP, jeux et appels en prennent au hasard.
    let inconnus: BTreeSet<u16> = connexions
        .iter()
        .filter(|(c, _)| !c.udp && service(c.port, false).is_none() && !port_suspect(c.port))
        .map(|(c, _)| c.port)
        .collect();
    if !inconnus.is_empty() {
        let ports = resume(&inconnus.iter().map(u16::to_string).collect::<Vec<_>>(), 5, ", ");
        signes.push((
            Niveau::Moyen,
            trf!(
                "Port inhabituel ({ports}) : normal pour un jeu ou un logiciel de partage, étrange pour le reste.",
                "Unusual port ({ports}): normal for a game or a sharing program, odd for anything else."
            ),
        ));
    }
    let sans_nom = connexions.iter().filter(|(_, nom)| nom.is_none()).count();
    if sans_nom > 0 {
        signes.push((
            Niveau::Info,
            trf!(
                "{sans_nom} serveur(s) sans nom : courant pour les réseaux de diffusion, à rapprocher du reste.",
                "{sans_nom} server(s) without a name: common for delivery networks, to weigh with the rest."
            ),
        ));
    }
    signes
}

/// Noms inverses des adresses, demandés en parallèle au DNS du système ; ceux qui tardent plus de 4 secondes sont
/// laissés sans nom (un DNS lent ne doit pas tout figer). Le propriétaire de chaque adresse écrit son nom inverse :
/// lu prêt à montrer.
fn noms(adresses: &BTreeSet<IpAddr>) -> HashMap<IpAddr, String> {
    let (envoi, reception) = std::sync::mpsc::channel();
    for &ip in adresses {
        let envoi = envoi.clone();
        std::thread::spawn(move || {
            if let Some(nom) = dns_lookup::lookup_addr(&ip)
                .ok()
                .and_then(|n| crate::reseau::scan::nom_inverse(ip, &n))
            {
                let _ = envoi.send((ip, nom));
            }
        });
    }
    drop(envoi);
    let limite = Instant::now() + Duration::from_secs(4);
    let mut noms = HashMap::new();
    while let Some(reste) = limite.checked_duration_since(Instant::now()) {
        match reception.recv_timeout(reste) {
            Ok((ip, nom)) => {
                noms.insert(ip, nom);
            }
            Err(_) => break,
        }
    }
    noms
}

// ───────────────────────────── Affichage ─────────────────────────────

/// Les connexions d'un même programme.
struct Groupe<'a> {
    programme: Option<String>,
    chemin: Option<String>,
    liste: Vec<(&'a Connexion, Option<&'a String>)>,
}

/// Un programme tel qu'il s'affiche : le pire de ses signes d'abord.
struct Programme {
    pire: Option<Niveau>,
    nom: String,
    chemin: Option<String>,
    signes: Vec<(Niveau, String)>,
    serveurs: String,
    connexions: usize,
}

/// La marque d'un programme : sans signe, ✔ seulement si son chemin a pu être examiné ; sinon « ? » (non vérifié).
fn marque(niveau: Option<Niveau>, chemin_lu: bool) -> String {
    match niveau {
        Some(n @ (Niveau::Eleve | Niveau::Critique)) => format!("{}✖{RESET}", couleur(n)),
        Some(Niveau::Moyen) => format!("{}⚠{RESET}", couleur(Niveau::Moyen)),
        _ if !chemin_lu => format!("{GRIS}?{RESET}"),
        _ => format!("{VERT}✔{RESET}"),
    }
}

/// Les serveurs d'un groupe de connexions, nommés et sans doublons : « github.com, Google, 203.0.113.5:4444 ».
fn serveurs(connexions: &[(&Connexion, Option<&String>)]) -> String {
    let mut vus = BTreeSet::new();
    let mut liste = Vec::new();
    for (c, nom) in connexions {
        let montre = match nom {
            Some(n) => qui(n),
            None => format!("{}:{}", c.distante, c.port),
        };
        if vus.insert(montre.clone()) {
            liste.push(montre);
        }
    }
    resume(&liste, 6, ", ")
}

/// Menu Antivirus et protection › Qui parle à Internet ?, ou `gardien sortantes`.
pub fn afficher() {
    titre(tr!("Qui parle à Internet ?", "Who talks to the Internet?"));
    for ligne in envelopper(
        tr!(
            "Les connexions en cours de cet ordinateur vers Internet, programme par programme. Rien n'est coupé ni bloqué.",
            "This computer's current connections to the Internet, program by program. Nothing is cut or blocked."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    println!();
    let Some(toutes) = connexions() else {
        trp!(
            "  ✖ Impossible de lire les connexions de cet ordinateur.",
            "  ✖ Could not read this computer's connections."
        );
        return;
    };
    let connexions: Vec<Connexion> = toutes.into_iter().filter(|c| sur_internet(c.distante)).collect();
    if connexions.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Aucune connexion vers Internet en ce moment.",
            "  {VERT}✔{RESET} No connection to the Internet right now."
        );
        return;
    }
    let adresses: BTreeSet<IpAddr> = connexions.iter().map(|c| c.distante).collect();
    trp!(
        "  {GRIS}Noms des {} serveur(s)…{RESET}",
        "  {GRIS}Names of the {} server(s)…{RESET}",
        adresses.len()
    );
    let noms = noms(&adresses);
    let montages = if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/self/mounts").unwrap_or_default()
    } else {
        String::new()
    };

    // Regroupées par programme ; celles des autres comptes à part.
    let mut groupes: Vec<Groupe> = Vec::new();
    let mut cachees: Vec<(&Connexion, Option<&String>)> = Vec::new();
    for c in &connexions {
        let nom = noms.get(&c.distante);
        if c.programme.is_none() {
            cachees.push((c, nom));
            continue;
        }
        match groupes
            .iter_mut()
            .find(|g| g.programme == c.programme && g.chemin == c.chemin)
        {
            Some(g) => g.liste.push((c, nom)),
            None => groupes.push(Groupe {
                programme: c.programme.clone(),
                chemin: c.chemin.clone(),
                liste: vec![(c, nom)],
            }),
        }
    }
    let mut affiches: Vec<Programme> = groupes
        .iter()
        .map(|g| {
            let signes = signes(g.chemin.as_deref(), &g.liste, &montages);
            Programme {
                pire: signes.iter().map(|(n, _)| *n).filter(|n| *n > Niveau::Info).max(),
                nom: g.programme.clone().unwrap_or_default(),
                chemin: g.chemin.clone(),
                signes,
                serveurs: serveurs(&g.liste),
                connexions: g.liste.len(),
            }
        })
        .collect();
    affiches.sort_by(|a, b| b.pire.cmp(&a.pire).then(b.connexions.cmp(&a.connexions)));

    println!();
    let mut a_regarder = Vec::new();
    let mut chemins_invisibles = 0;
    for p in &affiches {
        let n = p.connexions;
        println!(
            "  {} {ACCENT}{}{RESET} {GRIS}· {}{RESET}",
            marque(p.pire, p.chemin.is_some()),
            p.nom,
            trf!("{n} connexion(s)", "{n} connection(s)")
        );
        if let Some(c) = &p.chemin {
            afficher_aligne("      ", c, 6, GRIS);
        } else {
            chemins_invisibles += 1;
            afficher_aligne(
                "      ",
                tr!(
                    "chemin invisible sans droits d'administrateur (non vérifié)",
                    "path invisible without administrator rights (not checked)"
                ),
                6,
                GRIS,
            );
        }
        afficher_aligne("      → ", &p.serveurs, 8, "");
        for (niveau, texte) in &p.signes {
            let symbole = match niveau {
                Niveau::Info => format!("{GRIS}ℹ{RESET}"),
                Niveau::Moyen => format!("{}⚠{RESET}", couleur(*niveau)),
                n => format!("{}✖{RESET}", couleur(*n)),
            };
            afficher_aligne(&format!("      {symbole} "), texte, 8, "");
        }
        if p.pire.is_some() {
            a_regarder.push(p.nom.clone());
        }
    }
    if !cachees.is_empty() {
        println!(
            "  {GRIS}?{RESET} {}",
            trf!(
                "{} connexion(s) de programmes d'autres comptes (système, services)",
                "{} connection(s) from other accounts' programs (system, services)",
                cachees.len()
            )
        );
        afficher_aligne(
            "      ",
            tr!(
                "invisibles sans droits d'administrateur : non vérifiées, jamais comptées comme saines",
                "invisible without administrator rights: not checked, never counted as safe"
            ),
            6,
            GRIS,
        );
        afficher_aligne("      → ", &serveurs(&cachees), 8, "");
    }

    println!();
    trp!(
        "  {} programme(s), {} connexion(s) vers Internet.",
        "  {} program(s), {} connection(s) to the Internet.",
        affiches.len(),
        connexions.len()
    );
    if !a_regarder.is_empty() {
        let liste = resume(&a_regarder, 4, ", ");
        for ligne in envelopper(
            &trf!(
                "À regarder de près : {liste}. Si tu ne connais pas un programme signalé, analyse-le (antivirus, YARA, même menu), puis désinstalle-le. Gardien ne coupe rien.",
                "Worth a close look: {liste}. If you do not know a flagged program, scan it (antivirus, YARA, same menu), then uninstall it. Gardien cuts nothing."
            ),
            LARGEUR - 2,
        ) {
            println!("  {ligne}");
        }
    }
    if !cachees.is_empty() || chemins_invisibles > 0 {
        let comment = if cfg!(windows) {
            tr!(
                "lance Gardien en administrateur (clic droit, « Exécuter en tant qu'administrateur »)",
                "run Gardien as administrator (right-click, “Run as administrator”)"
            )
        } else {
            tr!("sudo gardien sortantes", "sudo gardien outbound")
        };
        trp!(
            "  {GRIS}Pour tout voir : {comment}.{RESET}",
            "  {GRIS}To see everything: {comment}.{RESET}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(t: &str) -> IpAddr {
        t.parse().unwrap()
    }

    #[test]
    fn adresses() {
        assert_eq!(adresse_et_port("140.82.112.4:443"), Some((ip("140.82.112.4"), 443)));
        assert_eq!(
            adresse_et_port("[2606:4700::1111]:443"),
            Some((ip("2606:4700::1111"), 443))
        );
        assert_eq!(adresse_et_port("192.168.1.20%wlan0:68"), Some((ip("192.168.1.20"), 68)));
        assert_eq!(adresse_et_port("[fe80::1%wlan0]:22"), Some((ip("fe80::1"), 22)));
        assert_eq!(adresse_et_port("users:((x"), None);
    }

    #[test]
    fn ss_linux() {
        let sortie = "udp 0 0 192.168.1.20%wlan0:68 192.168.1.1:67\n\
                      tcp 0 0 192.168.1.20:43180 140.82.112.4:443 users:((\"firefox\",pid=4242,fd=18))\n\
                      tcp 0 0 192.168.1.20:43190 203.0.113.9:4444 users:((\"Web Content\",pid=4300,fd=7),(\"x\",pid=1,fd=2))\n\
                      tcp 0 0 [2a01:db8::2]:50000 [2606:4700::1111]:443\n";
        let liste = lire_ss(sortie);
        assert_eq!(liste.len(), 4);
        assert!(liste[0].udp && liste[0].programme.is_none());
        assert_eq!(liste[1].programme.as_deref(), Some("firefox"));
        assert_eq!(liste[1].pid, Some(4242));
        assert_eq!(liste[1].distante, ip("140.82.112.4"));
        assert_eq!(liste[2].programme.as_deref(), Some("Web Content"));
        assert_eq!(liste[2].port, 4444);
        // Sans « users: » : un programme d'un autre compte.
        assert_eq!(liste[3].programme, None);
        assert_eq!(liste[3].distante, ip("2606:4700::1111"));
    }

    #[test]
    fn windows_et_macos() {
        let w = lire_windows(
            "140.82.112.4|443|4242|firefox|C:\\Program Files\\Mozilla Firefox\\firefox.exe\n\
             203.0.113.9|4444|5000|svchost|\n\
             pas une ligne\n",
        );
        assert_eq!(w.len(), 2);
        assert_eq!(
            w[0].chemin.as_deref(),
            Some("C:\\Program Files\\Mozilla Firefox\\firefox.exe")
        );
        assert_eq!(w[1].programme.as_deref(), Some("svchost"));
        assert_eq!(w[1].chemin, None);
        let lsof = "p501\ncGoogle Chrome\nf23\nn192.168.1.20:50000->142.250.1.1:443\np777\ncssh\nf3\nn[2a01:db8::2]:50001->[2001:db8::7]:22\n";
        let m = lire_lsof(lsof);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].programme.as_deref(), Some("Google Chrome"));
        assert_eq!(m[0].pid, Some(501));
        assert_eq!(m[1].port, 22);
        let netstat = "Active Internet connections (including servers)\n\
                       tcp4 0 0 192.168.1.20.50000 142.250.1.1.443 ESTABLISHED\n\
                       tcp4 0 0 192.168.1.20.50010 17.253.1.1.443 ESTABLISHED\n\
                       tcp4 0 0 *.22 *.* LISTEN\n";
        let autres = invisibles(netstat, &m);
        assert_eq!(autres.len(), 1);
        assert_eq!(autres[0].distante, ip("17.253.1.1"));
        assert_eq!(autres[0].programme, None);
    }

    #[test]
    fn internet_ou_maison() {
        assert!(sur_internet(ip("140.82.112.4")));
        assert!(sur_internet(ip("2606:4700::1111")));
        assert!(sur_internet(ip("::ffff:140.82.112.4")));
        for local in [
            "192.168.1.1",
            "10.0.0.5",
            "127.0.0.1",
            "169.254.1.1",
            "100.100.1.1",
            "fe80::1",
            "fd00::1",
            "::1",
        ] {
            assert!(!sur_internet(ip(local)), "{local}");
        }
    }

    #[test]
    fn jugement() {
        assert_eq!(dossier_risque("/tmp/.x/miner", ""), Some("un dossier temporaire"));
        assert_eq!(
            dossier_risque("/home/alice/Téléchargements/outil", ""),
            Some("les Téléchargements")
        );
        assert_eq!(
            dossier_risque("C:\\Users\\alice\\AppData\\Local\\Temp\\a.exe", ""),
            Some("un dossier temporaire")
        );
        assert_eq!(
            dossier_risque("C:\\Users\\Public\\svc.exe", ""),
            Some("le dossier Public, partagé par tous les comptes")
        );
        assert_eq!(
            dossier_risque(
                "/private/var/folders/x/AppTranslocation/y/App.app/Contents/MacOS/App",
                ""
            ),
            None
        );
        assert_eq!(dossier_risque("/usr/lib/firefox/firefox", ""), None);
        assert_eq!(service(443, false), Some("HTTPS"));
        assert!(service(4444, false).is_none() && port_suspect(4444));
        let firefox = Connexion {
            pid: Some(4242),
            programme: Some("firefox".into()),
            chemin: Some("/usr/lib/firefox/firefox".into()),
            distante: ip("140.82.112.4"),
            port: 443,
            udp: false,
        };
        let nom = "lb-140-82-112-4-iad.github.com".to_string();
        assert_eq!(
            signes(firefox.chemin.as_deref(), &[(&firefox, Some(&nom))], ""),
            Vec::new()
        );
        let piege = Connexion {
            chemin: Some("/tmp/.cache/x (deleted)".into()),
            port: 4444,
            ..firefox.clone()
        };
        let s = signes(piege.chemin.as_deref(), &[(&piege, None)], "");
        let niveaux: Vec<Niveau> = s.iter().map(|(n, _)| *n).collect();
        assert_eq!(niveaux, [Niveau::Eleve, Niveau::Eleve, Niveau::Eleve, Niveau::Info]);
        // Un jeu en UDP sur un port quelconque : rien à dire.
        let jeu = Connexion {
            port: 61234,
            udp: true,
            ..firefox.clone()
        };
        assert_eq!(signes(jeu.chemin.as_deref(), &[(&jeu, Some(&nom))], ""), Vec::new());
        let tcp = Connexion { port: 61234, ..firefox };
        assert_eq!(
            signes(tcp.chemin.as_deref(), &[(&tcp, Some(&nom))], "")[0].0,
            Niveau::Moyen
        );
    }

    // Linux : un programme mis à jour pendant qu'il tourne (Firefox après une mise à jour du système) a son ancien
    // fichier « (deleted) », mais un nouveau à la même place, installé par le système : une information. /usr/bin/env
    // appartient à root, dans un dossier que personne d'autre n'écrit.
    #[cfg(unix)]
    #[test]
    fn programme_du_systeme_mis_a_jour() {
        let c = Connexion::vers(ip("140.82.112.4"), 443);
        let nom = "github.com".to_string();
        let s = signes(Some("/usr/bin/env (deleted)"), &[(&c, Some(&nom))], "");
        assert_eq!(s.iter().map(|(n, _)| *n).collect::<Vec<_>>(), [Niveau::Info]);
    }

    // Un fichier reposé là où la personne peut écrire (profil, dossier temporaire) ne prouve rien : un programme
    // malveillant qui s'est effacé n'aurait qu'à en reposer un. Le second signe vient du dossier temporaire du test.
    #[test]
    fn fichier_repose_par_la_personne() {
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let repose = dossier.join("firefox");
        std::fs::write(&repose, b"n'importe quoi").unwrap();
        let efface = format!("{} (deleted)", repose.display());
        let c = Connexion::vers(ip("140.82.112.4"), 443);
        let s = signes(Some(&efface), &[(&c, None)], "");
        assert_eq!(
            s.iter().map(|(n, _)| *n).take(2).collect::<Vec<_>>(),
            [Niveau::Eleve, Niveau::Eleve]
        );
        std::fs::remove_dir_all(&dossier).unwrap();
        // Plus rien à sa place : effacé pour de bon.
        let s = signes(Some(&efface), &[(&c, None)], "");
        assert_eq!(s[0].0, Niveau::Eleve);
    }

    // Fichier et dossier à root, dossier fermé au groupe et aux autres : hors de portée. /tmp appartient à root mais
    // tout le monde y écrit ; un fichier à la personne, ou un dossier qu'elle possède, non plus.
    #[test]
    fn portee_de_la_personne() {
        assert!(hors_de_portee(0, 0, 0o040_755));
        assert!(!hors_de_portee(0, 0, 0o041_777));
        assert!(!hors_de_portee(0, 0, 0o040_775));
        assert!(!hors_de_portee(1000, 0, 0o040_755));
        assert!(!hors_de_portee(0, 1000, 0o040_755));
    }

    // Une AppImage tourne depuis son image montée dans /tmp/.mount_* : pas un programme lancé d'un dossier temporaire.
    // Un simple dossier de ce nom, lui, n'est pas une image montée.
    #[test]
    fn appimage_montee() {
        let montages = "/dev/nvme0n1p2 / btrfs rw 0 0\n\
                        ArtCraft.AppImage /tmp/.mount_ArtCraXk2Pq fuse.ArtCraft.AppImage ro,nosuid,nodev 0 0\n";
        let appimage = "/tmp/.mount_ArtCraXk2Pq/usr/bin/artcraft";
        assert_eq!(dossier_risque(appimage, montages), None);
        assert_eq!(
            dossier_risque("/tmp/.mount_faux/miner", montages),
            Some("un dossier temporaire")
        );
        assert_eq!(dossier_risque(appimage, ""), Some("un dossier temporaire"));
    }

    #[test]
    fn noms_montres() {
        assert_eq!(qui("lhr25s34-in-f14.1e100.net"), "Google");
        assert_eq!(qui("lb-140-82-112-4-iad.github.com"), "GitHub");
        assert_eq!(qui("serveur.exemple.co.uk"), "exemple.co.uk");
    }

    #[test]
    fn chemin_invisible_jamais_coche() {
        assert!(marque(None, true).contains('✔'));
        assert!(marque(None, false).contains('?') && !marque(None, false).contains('✔'));
        assert!(marque(Some(Niveau::Eleve), false).contains('✖'));
    }
}
