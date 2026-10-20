//! Qui parle à Internet ? Les connexions établies de cet ordinateur vers Internet, regroupées par programme, avec le
//! nom du serveur (DNS inverse). Repère un logiciel espion ou un mouchard : programme lancé depuis un dossier
//! temporaire ou les Téléchargements, programme effacé après son lancement, port connu des logiciels d'accès à
//! distance ou inhabituel, serveur sans nom. Les connexions des programmes d'autres comptes (système, services) sont
//! invisibles sans droits d'administrateur : comptées à part, jamais comme saines. Lecture seule : rien n'est coupé
//! ni bloqué.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
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
/// (« Web Content »). N'importe quel programme choisit son nom : lu prêt à montrer, comme dans chaque lecture de ce
/// fichier (le chemin, lui, reste tel quel pour juger d'où le programme a été lancé).
#[cfg(any(target_os = "linux", test))]
fn lire_processus(ligne: &str) -> (Option<String>, Option<u32>) {
    let Some(debut) = ligne.find("users:((\"") else {
        return (None, None);
    };
    let reste = &ligne[debut + 9..];
    let nom = reste.split_once('"').map(|(n, _)| affichable(n));
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
            let programme = p.next().map(str::trim).filter(|n| !n.is_empty()).map(affichable);
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
            Some('c') => programme = Some(affichable(valeur)),
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

/// Le dossier temporaire du compte, tel que le système le donne (TEMP sous Windows, TMPDIR ailleurs) : déplacé
/// (« C:\Temp » réglé par un administrateur, un autre disque), il ne se reconnaît pas à son chemin habituel, et un
/// programme lancé de là passerait inaperçu. `chemin` : en minuscules, barres obliques. Un dossier temporaire à la
/// racine d'un disque (« C:\ », « / ») ne compte pas : tout serait dedans.
fn dans_le_temporaire_du_compte(chemin: &str) -> bool {
    let temp = std::env::temp_dir().to_string_lossy().to_lowercase().replace('\\', "/");
    let temp = format!("{}/", temp.trim_end_matches('/'));
    temp.trim_matches('/').contains('/') && chemin.starts_with(&temp)
}

/// Un dossier d'où un vrai programme ne se lance pas d'habitude.
fn dossier_risque(chemin: &str, montages: &str) -> Option<&'static str> {
    let c = chemin.to_lowercase().replace('\\', "/");
    // macOS : une app téléchargée lancée sur place tourne depuis un dossier temporaire « AppTranslocation ».
    if c.contains("/apptranslocation/") || appimage(chemin, montages) {
        return None;
    }
    // Dossiers temporaires : à la racine sous Linux et macOS, sous le dossier du compte ou de Windows ailleurs. Sous
    // macOS, celui du compte ($TMPDIR) se lit sous deux noms : /var/folders est un lien vers /private/var/folders.
    let racines = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/private/tmp/",
        "/private/var/folders/",
        "/var/folders/",
    ];
    if racines.iter().any(|t| c.starts_with(t))
        || ["/appdata/local/temp/", "/windows/temp/"].iter().any(|t| c.contains(t))
        || dans_le_temporaire_du_compte(&c)
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
pub(crate) fn appimage(chemin: &str, montages: &str) -> bool {
    let Some(reste) = chemin.strip_prefix("/tmp/.mount_") else {
        return false;
    };
    let point = format!("/tmp/.mount_{}", reste.split('/').next().unwrap_or_default());
    montages
        .lines()
        .any(|l| l.split_whitespace().nth(1) == Some(point.as_str()))
}

/// L'image d'où tourne une AppImage, d'après son environnement (/proc/<pid>/environ : « APPIMAGE=…\0 »).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn image_appimage(environ: &[u8]) -> Option<String> {
    environ
        .split(|&o| o == 0)
        .find_map(|v| v.strip_prefix(b"APPIMAGE="))
        .map(|chemin| String::from_utf8_lossy(chemin).into_owned())
        .filter(|chemin| chemin.starts_with('/'))
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

/// Les serveurs de commande de botnets connus, des deux listes d'abuse.ch (CC0) : Feodo Tracker donne des adresses,
/// ThreatFox des adresses avec leur port et le nom du logiciel malveillant.
#[derive(Debug, Default)]
struct Botnets {
    feodo: BTreeSet<IpAddr>,
    threatfox: HashMap<(IpAddr, u16), String>,
}

impl Botnets {
    /// Le serveur d'une connexion tel qu'il sera montré, s'il est sur une des listes. Une adresse IPv4 vue par une
    /// prise IPv6 (« ::ffff:192.0.2.1 ») est comparée sous sa forme IPv4, celle des listes.
    fn serveur(&self, c: &Connexion) -> Option<String> {
        let ip = c.distante.to_canonical();
        let adresse = SocketAddr::new(ip, c.port);
        match self.threatfox.get(&(ip, c.port)) {
            Some(famille) if famille.is_empty() => Some(format!("{adresse} (ThreatFox)")),
            Some(famille) => Some(format!("{adresse} ({famille}, ThreatFox)")),
            None => self.feodo.contains(&ip).then(|| format!("{ip} (Feodo Tracker)")),
        }
    }
}

/// La liste de Feodo Tracker : une adresse IP par ligne, lignes « # » de commentaire. `None` pour tout autre texte :
/// la page d'un portail Wi-Fi (hôtel, gare) arrive à la place de la liste sans erreur, et ne doit pas passer pour une
/// liste vide, donc vérifiée. Fonction pure, testée sur un texte inventé (le conteneur ne peut pas joindre abuse.ch).
fn analyser_feodo(texte: &str) -> Option<BTreeSet<IpAddr>> {
    let lignes: Vec<&str> = texte.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    // abuse.ch ouvre toujours ses listes par un en-tête en commentaire.
    if !lignes.first()?.starts_with('#') {
        return None;
    }
    lignes
        .into_iter()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.parse().ok())
        .collect()
}

/// En dessous, ThreatFox lui-même doute (50 : signalement pas encore confirmé) : une fausse alerte élevée ferait
/// couper Internet pour rien.
const THREATFOX_CONFIANCE: u8 = 75;

/// La liste de ThreatFox, export CSV « ip:port » des derniers mois : (adresse, port) → nom du logiciel malveillant,
/// prêt à montrer. Seuls les serveurs de commande (« botnet_cc ») assez sûrs ; les serveurs de téléchargement
/// (« payload_delivery ») n'ont pas leur place parmi les serveurs de commande. `None` pour tout autre texte (portail
/// Wi-Fi, ligne illisible), comme pour Feodo Tracker.
fn analyser_threatfox(texte: &str) -> Option<HashMap<(IpAddr, u16), String>> {
    let lignes: Vec<&str> = texte.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if !lignes.first()?.starts_with('#') {
        return None;
    }
    let mut serveurs = HashMap::new();
    for ligne in lignes.into_iter().filter(|l| !l.starts_with('#')) {
        // « "2026-10-20 13:46:40", "1975828", "192.0.2.25:6662", "ip:port", "botnet_cc", … » : les champs libres
        // (références, étiquettes, auteur) viennent après ceux qu'on lit.
        let champs: Vec<&str> = ligne.strip_prefix('"')?.strip_suffix('"')?.split("\", \"").collect();
        let [_, _, valeur, "ip:port", menace, _, _, famille, _, confiance, ..] = champs.as_slice() else {
            return None;
        };
        garder_threatfox(
            &mut serveurs,
            valeur.parse().ok()?,
            menace,
            famille,
            confiance.parse().ok()?,
        );
    }
    Some(serveurs)
}

/// Un serveur de ThreatFox gardé s'il est un serveur de commande assez sûr.
fn garder_threatfox(
    serveurs: &mut HashMap<(IpAddr, u16), String>,
    adresse: SocketAddr,
    menace: &str,
    famille: &str,
    confiance: u64,
) {
    if menace == "botnet_cc" && confiance >= u64::from(THREATFOX_CONFIANCE) {
        // N'importe qui signale à ThreatFox : le nom est montré tel quel seulement s'il est inoffensif, et court.
        let famille: String = affichable(famille).chars().take(40).collect();
        serveurs.insert((adresse.ip().to_canonical(), adresse.port()), famille);
    }
}

/// La réponse de l'API de ThreatFox (avec une clé) : les signalements des 7 derniers jours, tous genres confondus, en
/// JSON. Mêmes règles que l'export ; `None` pour une réponse qui n'en est pas une (portail Wi-Fi, refus).
fn analyser_threatfox_api(texte: &str) -> Option<HashMap<(IpAddr, u16), String>> {
    let reponse: serde_json::Value = serde_json::from_str(texte).ok()?;
    let mut serveurs = HashMap::new();
    match reponse["query_status"].as_str()? {
        "no_result" => return Some(serveurs),
        "ok" => {}
        _ => return None,
    }
    for ioc in reponse["data"].as_array()? {
        if ioc["ioc_type"] != "ip:port" {
            continue;
        }
        garder_threatfox(
            &mut serveurs,
            ioc["ioc"].as_str()?.parse().ok()?,
            ioc["threat_type"].as_str()?,
            ioc["malware_printable"].as_str().unwrap_or_default(),
            ioc["confidence_level"].as_u64()?,
        );
    }
    Some(serveurs)
}

/// Avec une clé, ThreatFox permet de redemander ses listes toutes les 5 minutes : un serveur de commande change
/// d'adresse en quelques jours. Les listes publiques, sans compte, restent à 12 heures (`lien::URLHAUS_FRAICHE`).
const THREATFOX_CLE_FRAICHE: Duration = Duration::from_mins(5);

/// Une liste d'abuse.ch, téléchargée et gardée (`fraiche` sans être redemandée, une semaine au plus). La télécharger ne
/// dit à personne ce qu'on a trouvé : on prend la liste entière. `options` : ce que curl reçoit en plus (la clé de
/// ThreatFox). `Err` : la raison, à montrer.
fn liste_botnets<T>(
    nom: &str,
    (sous_dossier, adresse, fichier): (&str, &str, &str),
    (options, fraiche): (&[std::ffi::OsString], Duration),
    analyser: fn(&str) -> Option<T>,
) -> Result<T, String> {
    use crate::protection::lien;
    let (texte, age) = lien::liste_abuse_ch(sous_dossier, (adresse, options), fichier, fraiche).ok_or_else(|| {
        if options.is_empty() {
            trf!(
                "liste de {nom} pas vérifiée (pas d'Internet, ou curl absent)",
                "{nom} list not checked (no Internet, or curl missing)"
            )
        } else {
            trf!(
                "liste de {nom} pas vérifiée (pas d'Internet, curl absent, ou clé refusée : donne-la de nouveau)",
                "{nom} list not checked (no Internet, curl missing, or key refused: give it again)"
            )
        }
    })?;
    if age > lien::URLHAUS_TROP_VIEILLE {
        return Err(trf!(
            "liste de {nom} trop vieille pour servir : rafraîchissement impossible",
            "{nom} list too old to use: could not refresh it"
        ));
    }
    analyser(&texte).ok_or_else(|| {
        trf!(
            "liste de {nom} illisible (page d'un portail Wi-Fi ?) : pas vérifiée",
            "{nom} list unreadable (a Wi-Fi portal page?): not checked"
        )
    })
}

/// Les serveurs de botnets des listes d'abuse.ch, téléchargées en même temps, et ce qui n'a pas pu être vérifié. Une
/// liste indisponible (hors ligne, téléchargement raté, trop vieille) est dite : on ne conclut jamais que rien ne parle
/// à un botnet, et les autres servent quand même. Avec une clé, l'API de ThreatFox s'ajoute à son export public : elle
/// ne remonte que 7 jours, l'export des mois.
fn botnets() -> (Botnets, Vec<String>) {
    let entete = fichier_cle();
    let avec_cle = entete.is_file();
    let (feodo, threatfox, api) = std::thread::scope(|s| {
        let feodo = s.spawn(|| {
            liste_botnets(
                "Feodo Tracker",
                (
                    "feodo",
                    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
                    "botnets.txt",
                ),
                (&[], crate::protection::lien::URLHAUS_FRAICHE),
                analyser_feodo,
            )
        });
        let api = s.spawn(|| {
            // La clé est lue par curl dans son fichier : jamais dans la liste des processus.
            let mut cle = std::ffi::OsString::from("@");
            cle.push(&entete);
            let options = ["-H".into(), cle, "-d".into(), r#"{"query":"get_iocs","days":7}"#.into()];
            avec_cle.then(|| {
                liste_botnets(
                    tr!("ThreatFox (ta clé)", "ThreatFox (your key)"),
                    ("threatfox", "https://threatfox-api.abuse.ch/api/v1/", FICHIER_API),
                    (&options, THREATFOX_CLE_FRAICHE),
                    analyser_threatfox_api,
                )
            })
        });
        let threatfox = liste_botnets(
            "ThreatFox",
            (
                "threatfox",
                "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
                "ip-port.csv",
            ),
            (&[], crate::protection::lien::URLHAUS_FRAICHE),
            analyser_threatfox,
        );
        let pas_verifiee = |nom| trf!("liste de {nom} pas vérifiée", "{nom} list not checked");
        (
            feodo.join().unwrap_or_else(|_| Err(pas_verifiee("Feodo Tracker"))),
            threatfox,
            api.join().unwrap_or_else(|_| Some(Err(pas_verifiee("ThreatFox")))),
        )
    });
    let mut botnets = Botnets::default();
    let mut absentes = Vec::new();
    match feodo {
        Ok(liste) => botnets.feodo = liste,
        Err(raison) => absentes.push(raison),
    }
    for liste in [Some(threatfox), api].into_iter().flatten() {
        match liste {
            Ok(liste) => botnets.threatfox.extend(liste),
            Err(raison) => absentes.push(raison),
        }
    }
    (botnets, absentes)
}

// ───────────────────────────── La clé de ThreatFox ─────────────────────────────

/// La réponse de l'API, gardée à côté de la clé : effacée quand la clé change, pour que la nouvelle serve aussitôt.
const FICHIER_API: &str = "api.json";

/// La clé de ThreatFox, sur cet ordinateur seulement (le dossier de Vanguard du compte, jamais la clé USB), sous la
/// forme de l'en-tête que curl lit lui-même (« -H @fichier »).
fn fichier_cle() -> PathBuf {
    crate::reseau::dossier_local().join("threatfox").join("cle-entete")
}

/// Une clé d'abuse.ch telle qu'elle se copie : lettres et chiffres seulement. Un retour à la ligne glissé dedans
/// ajouterait un en-tête de plus à la demande.
fn cle_valide(cle: &str) -> bool {
    (20..=128).contains(&cle.len()) && cle.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Garde la clé, lisible par ce compte seul. Le fichier est recréé : un ancien, plus ouvert, ne garde pas ses droits.
fn enregistrer_cle(cle: &str) -> std::io::Result<()> {
    use std::io::Write;
    let fichier = fichier_cle();
    if let Some(dossier) = fichier.parent() {
        std::fs::create_dir_all(dossier)?;
    }
    oublier_cle();
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(&fichier)?
        .write_all(format!("Auth-Key: {cle}\n").as_bytes())
}

/// Retire la clé et ce qu'elle a téléchargé.
fn oublier_cle() {
    let fichier = fichier_cle();
    let _ = std::fs::remove_file(&fichier);
    if let Some(dossier) = fichier.parent() {
        let _ = std::fs::remove_file(dossier.join(FICHIER_API));
    }
}

/// Donner une clé : où la trouver, puis la clé collée.
fn donner_cle() {
    println!();
    for ligne in envelopper(
        tr!(
            "Une clé gratuite d'abuse.ch ajoute les serveurs signalés à ThreatFox ces 7 derniers jours, par son accès officiel. Crée un compte sur https://auth.abuse.ch/, puis copie ta clé (« Auth-Key »). Elle reste sur cet ordinateur, jamais sur la clé USB.",
            "A free abuse.ch key adds the servers reported to ThreatFox over the last 7 days, through its official access. Create an account at https://auth.abuse.ch/, then copy your key (“Auth-Key”). It stays on this computer, never on the USB key."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    let cle = demander(tr!("  Clé (Entrée pour annuler) : ", "  Key (Enter to cancel): "));
    if cle.is_empty() {
        return;
    }
    if !cle_valide(&cle) {
        trp!(
            "  ✖ Clé illisible : seulement des lettres et des chiffres, sans espace.",
            "  ✖ Unreadable key: letters and digits only, no space."
        );
        return;
    }
    match enregistrer_cle(&cle) {
        Ok(()) => trp!(
            "  {VERT}✔{RESET} Clé gardée : elle sert dès la prochaine ouverture de cet écran.",
            "  {VERT}✔{RESET} Key saved: it is used from the next time this screen opens."
        ),
        Err(e) => trp!("  ✖ Clé pas gardée : {e}.", "  ✖ Key not saved: {e}."),
    }
}

/// Depuis le menu : l'écran, puis Entrée pour revenir, ou C pour donner ou retirer la clé de ThreatFox. Le retour au
/// menu se demande ici, pas après : une seule pause.
pub fn menu() {
    afficher();
    loop {
        let reponse = if fichier_cle().is_file() {
            demander(&trf!(
                "\n{GRIS}Entrée pour revenir au menu, C pour retirer ta clé ThreatFox…{RESET} ",
                "\n{GRIS}Enter to go back to the menu, C to remove your ThreatFox key…{RESET} "
            ))
        } else {
            demander(&trf!(
                "\n{GRIS}Entrée pour revenir au menu, C pour donner une clé ThreatFox (facultative)…{RESET} ",
                "\n{GRIS}Enter to go back to the menu, C to give a ThreatFox key (optional)…{RESET} "
            ))
        };
        if !reponse.eq_ignore_ascii_case("c") {
            return;
        }
        if fichier_cle().is_file() {
            oublier_cle();
            trp!(
                "  {VERT}✔{RESET} Clé ThreatFox retirée de cet ordinateur.",
                "  {VERT}✔{RESET} ThreatFox key removed from this computer."
            );
        } else {
            donner_cle();
        }
    }
}

/// Ce qui mérite l'attention dans les connexions d'un programme : (gravité, texte). `image` : celle d'une AppImage
/// (variable APPIMAGE), jugée à la place de son point de montage dans /tmp. `botnets` : les serveurs de commande de
/// botnets connus (sans une liste qui n'a pas pu être vérifiée ; l'absence est alors dite ailleurs, jamais ici).
fn signes(
    chemin: Option<&str>,
    connexions: &[(&Connexion, Option<&String>)],
    montages: &str,
    image: Option<&str>,
    botnets: &Botnets,
) -> Vec<(Niveau, String)> {
    let mut signes = Vec::new();
    // Un serveur de commande de botnet connu passe avant tout le reste : c'est le signe le plus grave.
    let vers_botnet: Vec<String> = connexions
        .iter()
        .filter_map(|(c, _)| botnets.serveur(c))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !vers_botnet.is_empty() {
        let adresses = resume(&vers_botnet, 4, ", ");
        signes.push((
            Niveau::Eleve,
            trf!(
                "Parle à un serveur de commande de botnet connu (listes d'abuse.ch) : {adresses}.",
                "Talks to a known botnet command server (abuse.ch lists): {adresses}."
            ),
        ));
    }
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
        let juge = image.filter(|_| appimage(c, montages)).unwrap_or(c);
        if let Some(ou) = dossier_risque(juge, montages) {
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

/// Menu Antivirus et protection › Qui parle à Internet ?, ou `vanguard sortantes`.
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
    // Les listes des serveurs de botnets, une fois pour toutes les connexions. Une liste indisponible : on le dira
    // plus bas, et aucune connexion ne sera dédouanée pour autant.
    let (botnets, listes_absentes) = botnets();

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
            // Une AppImage : son image, lue dans l'environnement de son processus (le sien, donc lisible).
            let image = g
                .chemin
                .as_deref()
                .filter(|c| cfg!(target_os = "linux") && appimage(c, &montages))
                .and_then(|_| g.liste.iter().find_map(|(c, _)| c.pid))
                .and_then(|pid| std::fs::read(format!("/proc/{pid}/environ")).ok())
                .and_then(|e| image_appimage(&e));
            let signes = signes(g.chemin.as_deref(), &g.liste, &montages, image.as_deref(), &botnets);
            Programme {
                pire: signes.iter().map(|(n, _)| *n).filter(|n| *n > Niveau::Info).max(),
                nom: g.programme.clone().unwrap_or_default(),
                // Jugé tel quel (plus haut) ; montré, le chemin est rendu inoffensif.
                chemin: g.chemin.as_deref().map(affichable),
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
    // Ce qui n'a pas pu être vérifié est dit, jamais compté comme sain.
    for raison in &listes_absentes {
        afficher_aligne(&format!("  {GRIS}ℹ{RESET} "), raison, 4, GRIS);
    }
    if !a_regarder.is_empty() {
        let liste = resume(&a_regarder, 4, ", ");
        for ligne in envelopper(
            &trf!(
                "À regarder de près : {liste}. Si tu ne connais pas un programme signalé, analyse-le (antivirus, YARA, même menu), puis désinstalle-le. Vanguard ne coupe rien.",
                "Worth a close look: {liste}. If you do not know a flagged program, scan it (antivirus, YARA, same menu), then uninstall it. Vanguard cuts nothing."
            ),
            LARGEUR - 2,
        ) {
            println!("  {ligne}");
        }
    }
    if !cachees.is_empty() || chemins_invisibles > 0 {
        let comment = if cfg!(windows) {
            tr!(
                "lance Vanguard en administrateur (clic droit, « Exécuter en tant qu'administrateur »)",
                "run Vanguard as administrator (right-click, “Run as administrator”)"
            )
        } else {
            tr!("sudo vanguard sortantes", "sudo vanguard outbound")
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

    /// N'importe quel programme choisit son nom (et celui de son fichier) : piégé, le nom arrive inoffensif dans
    /// chaque lecture ; le chemin, lui, reste tel quel pour juger d'où le programme a été lancé.
    #[test]
    fn noms_de_programmes_pieges() {
        let ss = lire_ss(
            "tcp 0 0 192.168.1.20:43180 140.82.112.4:443 users:((\"x\x1b]52;c;eA==\x07\x1b[2K\rfaux\u{202e}\",pid=4242,fd=18))\n",
        );
        assert_eq!(ss[0].programme.as_deref(), Some("x�]52;c;eA==��[2K�faux�"));
        assert_eq!(ss[0].pid, Some(4242));
        let lsof = lire_lsof("p501\ncChrome\x1b[8m\u{2066}\nf23\nn192.168.1.20:50000->142.250.1.1:443\n");
        assert_eq!(lsof[0].programme.as_deref(), Some("Chrome�[8m�"));
        let w = lire_windows("140.82.112.4|443|4242|fire\x1b]0;x\x07fox|C:\\Temp\\a\x1b.exe\n");
        assert_eq!(w[0].programme.as_deref(), Some("fire�]0;x�fox"));
        assert_eq!(w[0].chemin.as_deref(), Some("C:\\Temp\\a\x1b.exe"));
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
        // macOS : le dossier temporaire du compte, sous ses deux noms.
        for t in ["/var/folders/ab/cdef/T/miner", "/private/var/folders/ab/cdef/T/miner"] {
            assert_eq!(dossier_risque(t, ""), Some("un dossier temporaire"), "{t}");
        }
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
        // Le dossier temporaire du compte, où qu'il soit (TEMP déplacé sous Windows, TMPDIR ailleurs).
        let temp = std::env::temp_dir().join("x").join("outil.exe");
        assert_eq!(
            dossier_risque(&temp.to_string_lossy(), ""),
            Some("un dossier temporaire"),
            "{}",
            temp.display()
        );
        assert!(!dans_le_temporaire_du_compte("c:/"));
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
            signes(
                firefox.chemin.as_deref(),
                &[(&firefox, Some(&nom))],
                "",
                None,
                &Botnets::default()
            ),
            Vec::new()
        );
        let piege = Connexion {
            chemin: Some("/tmp/.cache/x (deleted)".into()),
            port: 4444,
            ..firefox.clone()
        };
        let s = signes(
            piege.chemin.as_deref(),
            &[(&piege, None)],
            "",
            None,
            &Botnets::default(),
        );
        let niveaux: Vec<Niveau> = s.iter().map(|(n, _)| *n).collect();
        assert_eq!(niveaux, [Niveau::Eleve, Niveau::Eleve, Niveau::Eleve, Niveau::Info]);
        // Un jeu en UDP sur un port quelconque : rien à dire.
        let jeu = Connexion {
            port: 61234,
            udp: true,
            ..firefox.clone()
        };
        assert_eq!(
            signes(
                jeu.chemin.as_deref(),
                &[(&jeu, Some(&nom))],
                "",
                None,
                &Botnets::default()
            ),
            Vec::new()
        );
        let tcp = Connexion { port: 61234, ..firefox };
        assert_eq!(
            signes(
                tcp.chemin.as_deref(),
                &[(&tcp, Some(&nom))],
                "",
                None,
                &Botnets::default()
            )[0]
            .0,
            Niveau::Moyen
        );
    }

    #[test]
    fn liste_de_botnets_decodee() {
        // Texte inventé (le conteneur ne peut pas joindre abuse.ch) : commentaires et lignes vides ignorés, IPv4 et
        // IPv6 gardées ; une liste sans adresse reste une liste.
        let texte = "# Feodo Tracker\n\n192.0.2.66\n198.51.100.7\n2001:db8::1\n";
        let liste = analyser_feodo(texte).unwrap();
        assert_eq!(liste.len(), 3);
        assert!(liste.contains(&ip("192.0.2.66")));
        assert!(liste.contains(&ip("2001:db8::1")));
        assert!(
            analyser_feodo("# Feodo Tracker\n# vide aujourd'hui\n")
                .unwrap()
                .is_empty()
        );
        // Autre chose qu'une liste (portail Wi-Fi, fichier vide, ligne illisible) : pas vérifiée, jamais vide.
        assert!(analyser_feodo("").is_none());
        assert!(analyser_feodo("<html><body>Bienvenue au Salon</body></html>").is_none());
        assert!(analyser_feodo("# Feodo Tracker\n192.0.2.66\npas-une-ip\n").is_none());
    }

    #[test]
    fn connexion_vers_un_botnet_signalee() {
        let botnets = Botnets {
            feodo: BTreeSet::from([ip("203.0.113.9")]),
            ..Botnets::default()
        };
        let c = Connexion {
            pid: Some(10),
            programme: Some("inconnu".into()),
            chemin: Some("/usr/bin/inconnu".into()),
            distante: ip("203.0.113.9"),
            port: 443,
            udp: false,
        };
        let s = signes(c.chemin.as_deref(), &[(&c, None)], "", None, &botnets);
        assert_eq!(s[0].0, Niveau::Eleve);
        assert!(s[0].1.contains("botnet") && s[0].1.contains("203.0.113.9"));
        // Même serveur, mais liste vide (indisponible) : aucune connexion n'est dédouanée ni accusée ici.
        let vide = signes(c.chemin.as_deref(), &[(&c, None)], "", None, &Botnets::default());
        assert!(!vide.iter().any(|(_, t)| t.contains("botnet")));
    }

    #[test]
    fn liste_threatfox_decodee() {
        // Texte inventé, à la forme de l'export (fins de ligne Windows) : seuls les serveurs de commande assez sûrs
        // comptent, avec leur port et le nom du logiciel malveillant.
        let texte = concat!(
            "################################################################\r\n",
            "# ThreatFox IOCs: recent ip-port - CSV format                  #\r\n",
            "#\r\n",
            "# \"first_seen_utc\",\"ioc_id\",\"ioc_value\",\"ioc_type\",\"threat_type\",\"fk_malware\",\"malware_alias\",\"malware_printable\",\"last_seen_utc\",\"confidence_level\"\r\n",
            "\"2026-10-20 13:46:40\", \"1\", \"192.0.2.25:6662\", \"ip:port\", \"botnet_cc\", \"win.cobalt_strike\", \"BEACON\", \"Cobalt Strike\", \"\", \"75\", \"False\", \"None\", \"a, b\", \"0\", \"alice\"\r\n",
            "\"2026-10-20 13:30:04\", \"2\", \"[2001:db8::7]:2000\", \"ip:port\", \"botnet_cc\", \"win.nanocore\", \"\", \"Nanocore\u{1b}[2K RAT\", \"\", \"100\", \"False\", \"None\", \"\", \"0\", \"bob\"\r\n",
            "\"2026-10-20 12:00:00\", \"3\", \"198.51.100.3:80\", \"ip:port\", \"botnet_cc\", \"win.x\", \"\", \"Douteux\", \"\", \"50\", \"False\", \"None\", \"\", \"0\", \"bob\"\r\n",
            "\"2026-10-20 11:00:00\", \"4\", \"198.51.100.4:80\", \"ip:port\", \"payload_delivery\", \"win.y\", \"\", \"Téléchargeur\", \"\", \"100\", \"False\", \"None\", \"\", \"0\", \"bob\"\r\n",
        );
        let liste = analyser_threatfox(texte).unwrap();
        assert_eq!(liste.len(), 2);
        assert_eq!(liste[&(ip("192.0.2.25"), 6662)], "Cobalt Strike");
        // Un nom signalé par n'importe qui ne pilote pas le terminal.
        assert_eq!(liste[&(ip("2001:db8::7"), 2000)], "Nanocore\u{fffd}[2K RAT");
        // Une liste sans serveur reste une liste ; autre chose (portail Wi-Fi, ligne tronquée ou illisible) : pas
        // vérifiée, jamais vide.
        assert!(analyser_threatfox("# ThreatFox\r\n#\r\n").unwrap().is_empty());
        assert!(analyser_threatfox("").is_none());
        assert!(analyser_threatfox("<html><body>Bienvenue au Salon</body></html>").is_none());
        assert!(analyser_threatfox("# ThreatFox\n\"2026-10-20\", \"1\", \"192.0.2.25:6662\"\n").is_none());
        assert!(
            analyser_threatfox(concat!(
                "# ThreatFox\n",
                "\"2026-10-20\", \"1\", \"pas-une-ip:80\", \"ip:port\", \"botnet_cc\", \"\", \"\", \"X\", \"\", \"75\"\n",
            ))
            .is_none()
        );
    }

    #[test]
    fn reponse_de_l_api_threatfox_decodee() {
        // Réponse inventée, à la forme de celle de l'API : les autres genres (domaines, liens) sont sautés.
        let texte = r#"{"query_status": "ok", "data": [
            {"ioc": "192.0.2.25:6662", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware_printable": "Cobalt Strike", "confidence_level": 75},
            {"ioc": "exemple.invalid", "ioc_type": "domain", "threat_type": "botnet_cc",
             "malware_printable": "X", "confidence_level": 100},
            {"ioc": "198.51.100.3:80", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware_printable": "Douteux", "confidence_level": 50},
            {"ioc": "[2001:db8::7]:2000", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware_printable": null, "confidence_level": 100}
        ]}"#;
        let liste = analyser_threatfox_api(texte).unwrap();
        assert_eq!(liste.len(), 2);
        assert_eq!(liste[&(ip("192.0.2.25"), 6662)], "Cobalt Strike");
        assert_eq!(liste[&(ip("2001:db8::7"), 2000)], "");
        assert!(
            analyser_threatfox_api(r#"{"query_status": "no_result", "data": "Your search did not yield any results"}"#)
                .unwrap()
                .is_empty()
        );
        // Clé refusée, portail Wi-Fi, adresse illisible : pas vérifiée, jamais vide.
        assert!(analyser_threatfox_api(r#"{"query_status": "unknown_auth_key"}"#).is_none());
        assert!(analyser_threatfox_api("<html><body>Bienvenue au Salon</body></html>").is_none());
        assert!(
            analyser_threatfox_api(
                r#"{"query_status": "ok", "data": [{"ioc": "x:1", "ioc_type": "ip:port", "threat_type": "botnet_cc", "confidence_level": 100}]}"#
            )
            .is_none()
        );
    }

    #[test]
    fn cle_threatfox_gardee_puis_retiree() {
        // Une clé collée avec un retour à la ligne ou un espace ajouterait un en-tête à la demande : refusée.
        assert!(cle_valide("a1B2c3D4e5F6g7H8i9J0k1L2"));
        assert!(!cle_valide("a1B2c3D4e5F6g7H8i9J0\r\nX-Autre: 1"));
        assert!(!cle_valide("a1B2c3D4 e5F6g7H8i9J0k1L2"));
        assert!(!cle_valide("court"));
        // Le dossier de Vanguard est jetable en test.
        enregistrer_cle("a1B2c3D4e5F6g7H8i9J0k1L2").unwrap();
        let fichier = fichier_cle();
        assert_eq!(
            std::fs::read_to_string(&fichier).unwrap(),
            "Auth-Key: a1B2c3D4e5F6g7H8i9J0k1L2\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&fichier).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let reponse = fichier.with_file_name(FICHIER_API);
        std::fs::write(&reponse, "{}").unwrap();
        oublier_cle();
        assert!(!fichier.exists() && !reponse.exists());
    }

    #[test]
    fn serveur_threatfox_reconnu_a_son_port() {
        let botnets = Botnets {
            threatfox: HashMap::from([((ip("192.0.2.25"), 6662), "Cobalt Strike".to_string())]),
            ..Botnets::default()
        };
        let vers = |distante: &str, port| Connexion {
            programme: Some("inconnu".into()),
            chemin: Some("/usr/bin/inconnu".into()),
            ..Connexion::vers(ip(distante), port)
        };
        let c = vers("192.0.2.25", 6662);
        let s = signes(c.chemin.as_deref(), &[(&c, None)], "", None, &botnets);
        assert_eq!(s[0].0, Niveau::Eleve);
        assert!(
            s[0].1.contains("192.0.2.25:6662 (Cobalt Strike, ThreatFox)"),
            "{}",
            s[0].1
        );
        // Même serveur vu par une prise IPv6 : la forme « ::ffff: » ne le cache pas.
        assert!(botnets.serveur(&vers("::ffff:192.0.2.25", 6662)).is_some());
        // Même adresse, autre port : un hébergeur partagé n'accuse pas tous ses clients.
        assert!(botnets.serveur(&vers("192.0.2.25", 443)).is_none());
    }

    // Linux : un programme mis à jour pendant qu'il tourne (Firefox après une mise à jour du système) a son ancien
    // fichier « (deleted) », mais un nouveau à la même place, installé par le système : une information. /usr/bin/env
    // appartient à root, dans un dossier que personne d'autre n'écrit.
    #[cfg(unix)]
    #[test]
    fn programme_du_systeme_mis_a_jour() {
        // Dans un espace de noms sans root (tests hors ligne : unshare -r), les fichiers de root paraissent à
        // « personne » : rien à essayer là.
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata("/usr/bin/env").map_or(true, |m| m.uid() != 0) {
            return;
        }
        let c = Connexion::vers(ip("140.82.112.4"), 443);
        let nom = "github.com".to_string();
        let s = signes(
            Some("/usr/bin/env (deleted)"),
            &[(&c, Some(&nom))],
            "",
            None,
            &Botnets::default(),
        );
        assert_eq!(s.iter().map(|(n, _)| *n).collect::<Vec<_>>(), [Niveau::Info]);
    }

    // Un fichier reposé là où la personne peut écrire (profil, dossier temporaire) ne prouve rien : un programme
    // malveillant qui s'est effacé n'aurait qu'à en reposer un. Le second signe vient du dossier temporaire du test.
    #[test]
    fn fichier_repose_par_la_personne() {
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let repose = dossier.join("firefox");
        std::fs::write(&repose, b"n'importe quoi").unwrap();
        // En root (ou root d'un espace de noms : tests hors ligne), ce que le test pose appartient à root : il ne peut
        // pas imiter « la personne ».
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if std::fs::metadata(&repose).is_ok_and(|m| m.uid() == 0) {
                let _ = std::fs::remove_dir_all(&dossier);
                return;
            }
        }
        let efface = format!("{} (deleted)", repose.display());
        let c = Connexion::vers(ip("140.82.112.4"), 443);
        let s = signes(Some(&efface), &[(&c, None)], "", None, &Botnets::default());
        assert_eq!(
            s.iter().map(|(n, _)| *n).take(2).collect::<Vec<_>>(),
            [Niveau::Eleve, Niveau::Eleve]
        );
        std::fs::remove_dir_all(&dossier).unwrap();
        // Plus rien à sa place : effacé pour de bon.
        let s = signes(Some(&efface), &[(&c, None)], "", None, &Botnets::default());
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
    /// Une AppImage montée se juge d'après son image (variable APPIMAGE de son environnement) : lancée depuis les
    /// Téléchargements, elle le dit ; rangée dans ~/Applications, rien à dire.
    #[test]
    fn appimage_jugee_d_apres_son_image() {
        let montages = "ArtCraft.AppImage /tmp/.mount_ArtCraXk2Pq fuse.ArtCraft.AppImage ro,nosuid,nodev 0 0\n";
        let monte = "/tmp/.mount_ArtCraXk2Pq/usr/bin/artcraft";
        let c = Connexion::vers(ip("140.82.112.4"), 443);
        let nom = "github.com".to_string();
        let telechargee = "/home/alice/Downloads/ArtCraft.AppImage";
        let niveaux = |image| {
            signes(Some(monte), &[(&c, Some(&nom))], montages, image, &Botnets::default())
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
        };
        assert_eq!(niveaux(Some(telechargee)), [Niveau::Eleve]);
        assert_eq!(niveaux(Some("/home/alice/Applications/ArtCraft.AppImage")), []);
        assert_eq!(niveaux(None), []);
        let environ = b"HOME=/home/alice\0APPIMAGE=/home/alice/Downloads/ArtCraft.AppImage\0APPDIR=/tmp/.mount_x\0";
        assert_eq!(image_appimage(environ).as_deref(), Some(telechargee));
        assert_eq!(image_appimage(b"HOME=/home/alice\0"), None);
    }

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

/// Propriétés des lectures des connexions, sur des sorties tirées au hasard : rien ne plante ; une connexion bien
/// écrite redonne son adresse, son port, son programme ; netstat ne compte jamais deux fois ce que lsof a vu.
#[cfg(test)]
mod proprietes {
    use super::*;
    use proptest::prelude::*;
    use std::net::SocketAddr;

    fn sortie() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                any::<String>(),
                "[ -~\\t\u{1b}\u{202e}:%()\\[\\]\"|,=]{0,80}",
                "(tcp|udp) [0-9]+ [0-9]+ [0-9.:\\[\\]a-f%]{0,30} [0-9.:\\[\\]a-f%]{0,30}( users:\\(\\(\"[ -~]{0,10}\",pid=[0-9]{0,6},fd=[0-9]\\)\\))?",
                "[pcnf][ -~]{0,40}",
            ],
            0..12,
        )
        .prop_map(|l| l.join("\n"))
    }

    fn programme() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9 ._-]{1,15}".prop_filter("nom non vide", |n| !n.trim().is_empty())
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lectures_sans_plantage(t in sortie()) {
            let connexions = [lire_ss(&t), lire_windows(&t), lire_lsof(&t)].concat();
            let _ = invisibles(&t, &connexions);
            for c in &connexions {
                prop_assert!(c.programme.as_deref().is_none_or(|p| !crate::ui::contient_un_piege(p)));
            }
        }

        #[test]
        fn adresse_redonnee(a in any::<SocketAddr>()) {
            // « 1.2.3.4:443 », « [2606:4700::1]:443 » : ce que ss et lsof écrivent.
            let lue = adresse_et_port(&a.to_string());
            prop_assert_eq!(lue, Some((a.ip(), a.port())));
        }

        #[test]
        fn ss_redonne_ses_valeurs(locale in any::<SocketAddr>(), distante in any::<SocketAddr>(), nom in programme(), pid in 1u32..4_000_000) {
            let ligne = format!("tcp 0 0 {locale} {distante} users:((\"{nom}\",pid={pid},fd=7))\n");
            let l = lire_ss(&ligne);
            prop_assert_eq!(l.len(), 1);
            prop_assert_eq!((l[0].distante, l[0].port, l[0].pid), (distante.ip(), distante.port(), Some(pid)));
            prop_assert_eq!(l[0].programme.as_deref(), Some(nom.as_str()));
            prop_assert!(!l[0].udp);
        }

        #[test]
        fn windows_redonne_ses_valeurs(distante in any::<std::net::IpAddr>(), port in any::<u16>(), nom in programme(), pid in any::<u32>()) {
            let l = lire_windows(&format!("{distante}|{port}|{pid}|{nom}|C:\\Program Files\\x.exe\n"));
            prop_assert_eq!(l.len(), 1);
            prop_assert_eq!((l[0].distante, l[0].port, l[0].pid), (distante, port, Some(pid)));
            prop_assert_eq!(l[0].programme.as_deref(), Some(nom.trim()));
        }

        #[test]
        fn netstat_ne_compte_pas_deux_fois_ce_que_lsof_a_vu(
            vues in prop::collection::vec((any::<std::net::Ipv4Addr>(), any::<u16>()), 0..6),
            autres in prop::collection::vec((any::<std::net::Ipv4Addr>(), any::<u16>()), 0..6),
        ) {
            let lsof = vues.iter().map(|(ip, port)| format!("p1\ncx\nn10.0.0.2:50000->{ip}:{port}\n")).collect::<Vec<_>>().concat();
            let visibles = lire_lsof(&lsof);
            prop_assert_eq!(visibles.len(), vues.len());
            let netstat = vues
                .iter()
                .chain(&autres)
                .map(|(ip, port)| format!("tcp4 0 0 10.0.0.2.50000 {ip}.{port} ESTABLISHED\n"))
                .collect::<Vec<_>>()
                .concat();
            let restantes = invisibles(&netstat, &visibles);
            prop_assert_eq!(restantes.len(), autres.len());
        }
    }
}
