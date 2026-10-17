//! Découverte des machines et scan TCP « connect » (aucun privilège root requis).

use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::risk::PORTS_HTTP;
use crate::{tr, trf};

/// Résultat d'une tentative de connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Etat {
    Ouvert,
    Ferme,
    Filtre,
}

pub async fn sonder(ip: Ipv4Addr, port: u16, delai: Duration) -> (Etat, Option<TcpStream>) {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    match timeout(delai, TcpStream::connect(addr)).await {
        Ok(Ok(flux)) => (Etat::Ouvert, Some(flux)),
        // Un RST prouve que la machine existe, même si le port est fermé.
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => (Etat::Ferme, None),
        _ => (Etat::Filtre, None),
    }
}

/// Nombre de connexions simultanées réellement possible : chaque connexion consomme un descripteur
/// de fichier, et certains systèmes n'en autorisent que 256 par défaut. On relève la limite si le système le permet.
pub fn limite_connexions(demande: usize) -> usize {
    #[cfg(unix)]
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) == 0 {
            let voulu = (demande as libc::rlim_t + 128).min(lim.rlim_max);
            if lim.rlim_cur < voulu {
                lim.rlim_cur = voulu;
                libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lim);
                libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim);
            }
            // On garde une marge pour stdin/stdout, les fichiers lus et les sockets DNS.
            return demande
                .min(usize::try_from(lim.rlim_cur).unwrap_or(usize::MAX).saturating_sub(64))
                .max(16);
        }
    }
    demande
}

/// Plage d'adresses IPv4 à partir de « 10.0.0.5 », « 10.0.0.0/24 » ou « 10.0.0.1-50 ».
pub fn parse_cible(cible: &str) -> Result<Vec<Ipv4Addr>, String> {
    if let Some((ip, pref)) = cible.split_once('/') {
        let ip: Ipv4Addr = ip.parse().map_err(|_| trf!("IP invalide : {ip}", "invalid IP: {ip}"))?;
        let pref: u32 = pref
            .parse()
            .map_err(|_| trf!("préfixe invalide : {pref}", "invalid prefix: {pref}"))?;
        if !(16..=32).contains(&pref) {
            return Err(tr!("préfixe accepté : /16 à /32", "accepted prefix: /16 to /32").into());
        }
        let masque = if pref == 32 { u32::MAX } else { !(u32::MAX >> pref) };
        let reseau = u32::from(ip) & masque;
        let diffusion = reseau | !masque;
        if pref >= 31 {
            return Ok((reseau..=diffusion).map(Ipv4Addr::from).collect());
        }
        return Ok((reseau + 1..diffusion).map(Ipv4Addr::from).collect());
    }
    if let Some((debut, fin)) = cible.split_once('-') {
        let debut: Ipv4Addr = debut
            .parse()
            .map_err(|_| trf!("IP invalide : {debut}", "invalid IP: {debut}"))?;
        let fin: u8 = fin
            .parse()
            .map_err(|_| trf!("fin de plage invalide : {fin}", "invalid end of range: {fin}"))?;
        let o = debut.octets();
        if fin < o[3] {
            return Err(trf!(
                "plage invalide : {cible} (la fin doit être ≥ {})",
                "invalid range: {cible} (the end must be ≥ {})",
                o[3]
            ));
        }
        return Ok((o[3]..=fin).map(|d| Ipv4Addr::new(o[0], o[1], o[2], d)).collect());
    }
    cible
        .parse()
        .map(|ip| vec![ip])
        .map_err(|_| trf!("cible invalide : {cible}", "invalid target: {cible}"))
}

/// Réseau local de l'interface principale (ex. 10.0.0.0/24) et IP de cette machine.
/// On préfère l'interface qui contient la passerelle (évite Docker, Hyper-V, VirtualBox…).
pub fn reseau_local() -> Option<(String, Ipv4Addr)> {
    let gw = passerelle().map(u32::from);
    let candidats: Vec<_> = if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) if !v4.ip.is_loopback() && !v4.ip.is_link_local() => Some(v4),
            _ => None,
        })
        .collect();
    let masque = |v4: &if_addrs::Ifv4Addr| u32::from(v4.netmask);
    let choisi = candidats
        .iter()
        .find(|v4| gw.is_some_and(|g| g & masque(v4) == u32::from(v4.ip) & masque(v4)))
        .or(candidats.first())?;
    // Réseau plus grand qu'un /16 (10.0.0.0/8…) : on scanne le /16 qui contient cette machine. Le calculer
    // avec le masque d'origine donnait 10.0.0.0/16 même pour l'IP 10.5.3.2, donc le mauvais morceau.
    let pref = masque(choisi).count_ones().max(16);
    let reseau = Ipv4Addr::from(u32::from(choisi.ip) & !(u32::MAX >> pref));
    Some((format!("{reseau}/{pref}"), choisi.ip))
}

#[cfg(not(target_os = "linux"))]
fn commande(cmd: &str, args: &[&str]) -> String {
    crate::commande::lancer(std::process::Command::new(cmd).args(args), 10)
        .map(|r| r.sortie)
        .unwrap_or_default()
}

/// Passerelle par défaut (la box / le routeur).
pub fn passerelle() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        passerelle_linux(&table)
    }
    #[cfg(windows)]
    {
        // Ligne « 0.0.0.0  0.0.0.0  <passerelle>  <interface>  <métrique> » ; la plus petite métrique gagne.
        commande("route", &["print", "-4", "0.0.0.0"])
            .lines()
            .filter_map(|l| {
                let c: Vec<&str> = l.split_whitespace().collect();
                (c.len() >= 5 && c[0] == "0.0.0.0" && c[1] == "0.0.0.0")
                    .then(|| Some((c[4].parse::<u32>().ok()?, c[2].parse::<Ipv4Addr>().ok()?)))
                    .flatten()
            })
            .min()
            .map(|(_, ip)| ip)
    }
    // macOS : « gateway: 10.0.0.1 » dans `route -n get default`.
    #[cfg(target_os = "macos")]
    {
        commande("route", &["-n", "get", "default"])
            .lines()
            .find_map(|l| l.trim().strip_prefix("gateway:"))
            .and_then(|g| g.trim().parse().ok())
    }
}

/// Route par défaut dans /proc/net/route (Iface Destination Gateway Flags RefCnt Use Metric…).
/// Seules les routes « via une passerelle » comptent (un VPN « default dev tun0 » a la passerelle 0.0.0.0),
/// et avec Ethernet + Wi-Fi, la plus petite métrique gagne, comme pour le système.
#[cfg(any(target_os = "linux", test))]
fn passerelle_linux(table: &str) -> Option<Ipv4Addr> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            let hex = |i: usize| u32::from_str_radix(c.get(i)?, 16).ok();
            let (dest, gw, drapeaux) = (hex(1)?, hex(2)?, hex(3)?);
            let metrique: u32 = c.get(6)?.parse().ok()?;
            let utile = dest == 0 && gw != 0 && drapeaux & (RTF_UP | RTF_GATEWAY) == RTF_UP | RTF_GATEWAY;
            utile.then_some((metrique, Ipv4Addr::from(gw.swap_bytes())))
        })
        .min()
        .map(|(_, ip)| ip)
}

/// Normalise une MAC en « aa:bb:cc:dd:ee:ff » (« a:b:… » sans zéros, Windows « aa-bb-… »).
fn normaliser_mac(brut: &str) -> Option<String> {
    let parties: Vec<String> = brut
        .split([':', '-'])
        .map(|p| format!("{:0>2}", p.to_ascii_lowercase()))
        .collect();
    let mac = parties.join(":");
    let valide = parties.len() == 6
        && parties
            .iter()
            .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok());
    // On écarte diffusion et multicast, qui ne sont pas des appareils.
    let multicast = u8::from_str_radix(&parties[0], 16).is_ok_and(|o| o & 1 == 1);
    (valide && !multicast && mac != "00:00:00:00:00:00").then_some(mac)
}

/// Table ARP du système : IP → adresse MAC (entrées complètes seulement).
pub fn table_arp() -> HashMap<Ipv4Addr, String> {
    #[cfg(target_os = "linux")]
    let entrees: Vec<(String, String)> = std::fs::read_to_string("/proc/net/arp")
        .unwrap_or_default()
        .lines()
        .skip(1)
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            (c.get(2) == Some(&"0x2"))
                .then(|| Some((c.first()?.to_string(), c.get(3)?.to_string())))
                .flatten()
        })
        .collect();
    // macOS : « ? (10.0.0.1) at f8:79:a:d:3:a2 on en0 ifscope [ethernet] » ; « (incomplete) » sans réponse.
    #[cfg(target_os = "macos")]
    let entrees: Vec<(String, String)> = commande("arp", &["-an"])
        .lines()
        .filter_map(|l| {
            let ip = l.split_once('(')?.1.split_once(')')?.0;
            let mac = l.split_once(" at ")?.1.split_whitespace().next()?;
            Some((ip.to_string(), mac.to_string()))
        })
        .collect();
    // Windows : « 10.0.0.1   f8-79-0a-0d-03-a2   dynamique »
    #[cfg(windows)]
    let entrees: Vec<(String, String)> = commande("arp", &["-a"])
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            Some((c.first()?.to_string(), c.get(1)?.to_string()))
        })
        .collect();

    entrees
        .into_iter()
        .filter_map(|(ip, mac)| Some((ip.parse().ok()?, normaliser_mac(&mac)?)))
        .collect()
}

/// Trouve les machines actives : une réponse TCP (ouvert ou RST) ou une entrée ARP suffit.
pub async fn decouvrir(ips: &[Ipv4Addr], delai: Duration, parallele: usize) -> Vec<Ipv4Addr> {
    let essais = ips
        .iter()
        .flat_map(|&ip| crate::risk::PORTS_DECOUVERTE.iter().map(move |&p| (ip, p)));
    let mut vivantes: Vec<Ipv4Addr> = stream::iter(essais)
        .map(|(ip, p)| async move { (ip, sonder(ip, p, delai).await.0) })
        .buffer_unordered(parallele)
        .filter_map(|(ip, e)| async move { (e != Etat::Filtre).then_some(ip) })
        .collect()
        .await;

    // Nos tentatives ont rempli la table ARP : les machines qui bloquent tout y apparaissent quand même.
    let arp = table_arp();
    let deja: std::collections::HashSet<Ipv4Addr> = vivantes.iter().copied().collect();
    let seulement_arp: Vec<Ipv4Addr> = ips
        .iter()
        .filter(|ip| arp.contains_key(ip) && !deja.contains(ip))
        .copied()
        .collect();
    #[cfg(target_os = "linux")]
    let seulement_arp = confirmer_voisins(ips, &deja, seulement_arp).await;
    vivantes.extend(seulement_arp);
    vivantes.sort();
    vivantes.dedup();
    vivantes
}

/// État de chaque voisin dans `ip -4 neigh show` (« 10.0.0.1 dev wlan0 lladdr … REACHABLE » : l'état est le
/// dernier mot). `None` si la commande manque.
#[cfg(target_os = "linux")]
fn etats_voisins() -> Option<HashMap<Ipv4Addr, String>> {
    let r = crate::commande::lancer(std::process::Command::new("ip").args(["-4", "neigh", "show"]), 5)?;
    (r.code == Some(0)).then(|| lire_etats_voisins(&r.sortie))
}

#[cfg(any(target_os = "linux", test))]
fn lire_etats_voisins(texte: &str) -> HashMap<Ipv4Addr, String> {
    texte
        .lines()
        .filter_map(|l| {
            let mut mots = l.split_whitespace();
            let ip = mots.next()?.parse().ok()?;
            Some((ip, mots.last()?.to_string()))
        })
        .collect()
}

/// État ARP en cours de vérification par le noyau : la réponse n'est pas encore connue.
#[cfg(any(target_os = "linux", test))]
fn etat_en_cours(etat: Option<&str>) -> bool {
    matches!(etat, Some("DELAY" | "PROBE" | "INCOMPLETE"))
}

/// Un voisin compte comme présent, sauf si le noyau a constaté qu'il ne répond plus (ou l'a oublié).
#[cfg(any(target_os = "linux", test))]
fn voisin_present(etat: Option<&str>) -> bool {
    !matches!(etat, None | Some("FAILED" | "INCOMPLETE"))
}

/// Linux garde les entrées ARP périmées (STALE) des appareils partis : sur un petit réseau, rien ne les efface.
/// Elles sont encore « complètes » quand on les lit juste après nos sondes, et l'appareil passait pour présent.
/// À l'inverse, un téléphone en veille répond à l'ARP en une ou deux secondes : lu trop tôt (INCOMPLETE), il
/// passait pour absent. Nos sondes ont lancé la vérification (5 s d'attente puis 3 essais d'1 s pour une entrée
/// périmée, 3 essais d'1 s pour une nouvelle) : on attend son verdict, au plus 10 s, pour les adresses qui n'ont
/// pas répondu en TCP. `repli` = l'ancienne liste, gardée si la commande ip manque.
#[cfg(target_os = "linux")]
async fn confirmer_voisins(
    ips: &[Ipv4Addr],
    deja: &std::collections::HashSet<Ipv4Addr>,
    repli: Vec<Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    let fin = std::time::Instant::now() + Duration::from_secs(10);
    let mut candidats: Option<Vec<Ipv4Addr>> = None;
    loop {
        let Some(etats) = tokio::task::spawn_blocking(etats_voisins).await.ok().flatten() else {
            return repli;
        };
        let etat = |ip: &Ipv4Addr| etats.get(ip).map(String::as_str);
        // Au premier passage : toute adresse sans réponse TCP que le noyau connaît ou cherche encore.
        let liste = candidats.get_or_insert_with(|| {
            ips.iter()
                .filter(|ip| !deja.contains(ip) && (voisin_present(etat(ip)) || etat_en_cours(etat(ip))))
                .copied()
                .collect()
        });
        if !liste.iter().any(|ip| etat_en_cours(etat(ip))) || std::time::Instant::now() >= fin {
            return liste.iter().filter(|ip| voisin_present(etat(ip))).copied().collect();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Lit ce que le service annonce (SSH, FTP, SMTP…) ou l'en-tête Server en HTTP.
/// Ce qu'un service répond, ou rien s'il se tait pendant 1,2 s.
async fn lire(flux: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_millis(1200), flux.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// Résumé d'une réponse HTTP : l'en-tête Server, sinon la ligne d'état.
fn resume_http(texte: &str) -> String {
    let serveur = texte
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("server:"))
        .map(|l| l[7..].trim().to_string());
    format!(
        "HTTP · {}",
        serveur.unwrap_or_else(|| texte.lines().next().unwrap_or("").trim().to_string())
    )
}

/// Ce que le service annonce (SSH, FTP, SMTP…). Sur un port web, ou si le service se tait,
/// on lui envoie une requête HTTP : un serveur web caché sur un port inhabituel est ainsi reconnu.
async fn banniere(mut flux: TcpStream, port: u16) -> Option<String> {
    let texte = if PORTS_HTTP.contains(&port) {
        None
    } else {
        lire(&mut flux).await
    };
    let ligne = match texte {
        Some(t) if t.starts_with("HTTP/") => resume_http(&t),
        Some(t) => t.lines().next().unwrap_or("").trim().to_string(),
        None => {
            flux.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await.ok()?;
            let t = lire(&mut flux).await?;
            if !t.starts_with("HTTP/") {
                return None;
            }
            resume_http(&t)
        }
    };
    // Les caractères de contrôle sont retirés : une bannière ne doit pas pouvoir piloter le terminal.
    let propre: String = ligne.chars().filter(|c| !c.is_control()).take(80).collect();
    (!propre.is_empty()).then_some(propre)
}

/// Scanne tous les ports demandés sur toutes les machines. Retourne IP → [(port, bannière)].
pub async fn scanner_ports(
    hotes: &[Ipv4Addr],
    ports: &[u16],
    delai: Duration,
    parallele: usize,
) -> BTreeMap<Ipv4Addr, Vec<(u16, Option<String>)>> {
    let essais = hotes.iter().flat_map(|&ip| ports.iter().map(move |&p| (ip, p)));
    let trouves: Vec<(Ipv4Addr, u16, Option<String>)> = stream::iter(essais)
        .map(|(ip, p)| async move {
            match sonder(ip, p, delai).await {
                (Etat::Ouvert, Some(flux)) => Some((ip, p, banniere(flux, p).await)),
                _ => None,
            }
        })
        .buffer_unordered(parallele)
        .filter_map(|r| async move { r })
        .collect()
        .await;

    let mut resultat: BTreeMap<_, Vec<_>> = hotes.iter().map(|&ip| (ip, Vec::new())).collect();
    for (ip, p, b) in trouves {
        resultat.entry(ip).or_default().push((p, b));
    }
    for ports in resultat.values_mut() {
        ports.sort_by_key(|(p, _)| *p);
    }
    resultat
}

/// Requête envoyée sur chaque port UDP : un service UDP ne répond qu'à un message de son protocole. Sans réponse, on
/// ne sait pas (port fermé ou filtré) : seul un port qui répond est déclaré ouvert.
fn requete_udp(port: u16) -> Option<Vec<u8>> {
    Some(match port {
        // DNS : serveurs de la racine (NS de « . »).
        53 => vec![0x53, 0x45, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1],
        // NTP : client, version 3.
        123 => {
            let mut r = vec![0u8; 48];
            r[0] = 0x1b;
            r
        }
        // NetBIOS : liste des noms de l'appareil (NBSTAT sur « * »).
        137 => {
            let mut r = vec![0x53, 0x45, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, b'C', b'K'];
            r.extend([b'A'; 30]);
            r.extend([0, 0, 0x21, 0, 1]);
            r
        }
        // SNMP v1 : description du système (sysDescr.0) avec la communauté par défaut « public ».
        161 => vec![
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x19, 0x02, 0x01, 0x01,
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
            0x01, 0x00, 0x05, 0x00,
        ],
        // SSDP (UPnP) : recherche des appareils.
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n"
            .to_vec(),
        // mDNS (Bonjour) : liste des services annoncés, en question directe (réponse renvoyée à notre port).
        5353 => {
            let mut r = vec![0x53, 0x45, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            for etiquette in ["_services", "_dns-sd", "_udp", "local"] {
                r.push(u8::try_from(etiquette.len()).unwrap_or(0));
                r.extend(etiquette.as_bytes());
            }
            r.extend([0, 0, 0x0c, 0, 1]);
            r
        }
        _ => return None,
    })
}

/// Ce que la réponse apprend : nom NetBIOS, description SNMP, serveur UPnP.
fn resume_udp(port: u16, reponse: &[u8]) -> Option<String> {
    match port {
        // En-tête (12) + nom (34) + type, classe, durée, longueur (10) = 56 : nombre de noms, puis le premier nom.
        137 => {
            let nom = reponse.get(57..72)?;
            let nom = String::from_utf8_lossy(nom).trim().to_string();
            (!nom.is_empty()).then(|| trf!("nom : {nom}", "name: {nom}"))
        }
        // La valeur suit l'OID de sysDescr.0 : 0x04 (texte), longueur, texte.
        161 => {
            let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
            let debut = reponse.windows(oid.len()).position(|w| w == oid)? + oid.len();
            let (&type_, reste) = reponse.get(debut..)?.split_first()?;
            if type_ != 0x04 {
                return None;
            }
            let (longueur, texte) = match reste.split_first()? {
                (&0x81, r) => (usize::from(*r.first()?), r.get(1..)?),
                (&n, r) if n < 0x80 => (usize::from(n), r),
                _ => return None,
            };
            let texte = String::from_utf8_lossy(texte.get(..longueur.min(texte.len()))?);
            let texte: String = texte
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(70)
                .collect();
            (!texte.is_empty()).then_some(texte)
        }
        1900 => String::from_utf8_lossy(reponse).lines().find_map(|l| {
            let (cle, valeur) = l.split_once(':')?;
            (cle.trim().eq_ignore_ascii_case("server")).then(|| valeur.trim().chars().take(70).collect())
        }),
        _ => None,
    }
}

async fn sonder_udp(ip: Ipv4Addr, port: u16, delai: Duration) -> Option<Option<String>> {
    let requete = requete_udp(port)?;
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    // Socket « connectée » : un port fermé renvoie une erreur (ICMP) au lieu de faire attendre tout le délai.
    socket.connect(SocketAddr::new(IpAddr::V4(ip), port)).await.ok()?;
    let mut tampon = [0u8; 1500];
    // Trois envois : un paquet UDP perdu, ou une imprimante lente à répondre (vu en réel : NetBIOS d'une HP), ne doit
    // pas faire passer un port ouvert pour fermé, puis pour « nouveau » au scan suivant.
    for _ in 0..3 {
        socket.send(&requete).await.ok()?;
        match timeout(delai, socket.recv(&mut tampon)).await {
            Ok(Ok(n)) if n > 0 => return Some(resume_udp(port, &tampon[..n])),
            Ok(_) => return None,
            Err(_) => {}
        }
    }
    None
}

/// Ports UDP qui répondent, par machine (même forme que `scanner_ports`).
pub async fn scanner_udp(
    hotes: &[Ipv4Addr],
    ports: &[u16],
    delai: Duration,
) -> BTreeMap<Ipv4Addr, Vec<(u16, Option<String>)>> {
    let essais = hotes.iter().flat_map(|&ip| ports.iter().map(move |&p| (ip, p)));
    let trouves: Vec<(Ipv4Addr, u16, Option<String>)> = stream::iter(essais)
        .map(|(ip, p)| async move { sonder_udp(ip, p, delai).await.map(|b| (ip, p, b)) })
        .buffer_unordered(128)
        .filter_map(|r| async move { r })
        .collect()
        .await;
    let mut resultat: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for (ip, p, b) in trouves {
        resultat.entry(ip).or_default().push((p, b));
    }
    for ports in resultat.values_mut() {
        ports.sort_by_key(|(p, _)| *p);
    }
    resultat
}

/// Nom DNS inverse (box, mDNS via nss…), sans bloquer le runtime.
pub async fn nom_hote(ip: Ipv4Addr) -> Option<String> {
    // Délai maximal : un DNS qui ne répond pas ne doit pas bloquer tout le scan.
    let recherche = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)));
    let nom = timeout(Duration::from_secs(2), recherche).await.ok()?.ok()?.ok()?;
    (nom != ip.to_string()).then_some(nom)
}

/// Base des fabricants (préfixe MAC → nom), extraite des registres IEEE et intégrée au programme
/// (outils/maj-fabricants.sh, relancé par deployer.sh quand elle a plus d'un mois).
pub fn base_fabricants() -> HashMap<String, String> {
    include_str!("../assets/oui.tsv")
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(p, n)| (p.to_string(), n.to_string()))
        .collect()
}

pub fn fabricant(mac: &str, base: &HashMap<String, String>) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_uppercase();
    let premier = u8::from_str_radix(hex.get(..2)?, 16).ok()?;
    // Bit « administré localement » : MAC aléatoire, typique des téléphones et tablettes récents.
    if premier & 0x02 != 0 {
        return Some(tr!("MAC aléatoire (téléphone/tablette ?)", "random MAC (phone/tablet?)").into());
    }
    // Le bloc le plus précis d'abord : MA-S (9 chiffres), MA-M (7), puis MA-L (6). Un grand bloc revendu en petits
    // morceaux porte sinon le nom du registre (« IEEE Registration Authority ») au lieu de celui du fabricant.
    [9, 7, 6].iter().find_map(|&n| base.get(hex.get(..n)?).cloned())
}

/// Nom du Wi-Fi auquel on est connecté, pour reconnaître le réseau dans la base (« Salon », « Chez Max »…).
pub fn nom_wifi() -> Option<String> {
    #[cfg(target_os = "linux")]
    let nom = commande_sortie("nmcli", &["-t", "-e", "no", "-f", "ACTIVE,SSID", "dev", "wifi"])
        .lines()
        .find_map(|l| l.strip_prefix("yes:").map(str::to_string));
    #[cfg(windows)]
    let nom = commande_sortie("netsh", &["wlan", "show", "interfaces"])
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("SSID") && !l.starts_with("BSSID"))
        .and_then(|l| Some(l.split_once(':')?.1.trim().to_string()));
    // macOS : « SSID : Salon » dans le résumé de l'interface Wi-Fi (en0 en général). Depuis macOS 14, le nom peut
    // être masqué (« <redacted> ») faute d'autorisation de localisation : le réseau est alors reconnu par sa box.
    #[cfg(target_os = "macos")]
    let nom = ["en0", "en1"].iter().find_map(|i| {
        commande_sortie("ipconfig", &["getsummary", i])
            .lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix("SSID : "))
            .map(str::to_string)
            .filter(|n| !n.starts_with('<'))
    });
    nom.filter(|n| !n.is_empty())
}

fn commande_sortie(cmd: &str, args: &[&str]) -> String {
    crate::commande::lancer(std::process::Command::new(cmd).args(args), 10)
        .map(|r| r.sortie)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cible_cidr_exclut_reseau_et_diffusion() {
        let ips = parse_cible("10.0.0.77/24").unwrap();
        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ips[253], Ipv4Addr::new(10, 0, 0, 254));
    }

    #[test]
    fn cible_plage_et_ip_seule() {
        assert_eq!(parse_cible("192.168.1.10-12").unwrap().len(), 3);
        assert_eq!(parse_cible("192.168.1.5").unwrap(), vec![Ipv4Addr::new(192, 168, 1, 5)]);
        assert!(parse_cible("192.168.1.50-10").is_err());
        assert!(parse_cible("10.0.0.0/8").is_err());
        assert!(parse_cible("pas une ip").is_err());
    }

    #[test]
    fn mac_normalisee_quel_que_soit_le_systeme() {
        assert_eq!(normaliser_mac("f8:79:a:d:3:a2").as_deref(), Some("f8:79:0a:0d:03:a2")); // zéros omis
        assert_eq!(
            normaliser_mac("F8-79-0A-0D-03-A2").as_deref(),
            Some("f8:79:0a:0d:03:a2")
        ); // Windows
        assert_eq!(normaliser_mac("ff-ff-ff-ff-ff-ff"), None); // diffusion
        assert_eq!(normaliser_mac("01-00-5e-00-00-fb"), None); // multicast
        assert_eq!(normaliser_mac("incomplete"), None);
    }

    #[test]
    fn reponses_udp() {
        // NetBIOS : le premier nom de la liste.
        let mut nb = vec![0u8; 57];
        nb.extend(b"IMPRIMANTE-HP  ");
        nb.extend([0x00, 0x04, 0x00]);
        assert!(resume_udp(137, &nb).unwrap().ends_with("IMPRIMANTE-HP"));
        // SNMP : sysDescr après son OID.
        let mut snmp = vec![0x30, 0x2a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x04, 0x0b];
        snmp.extend(b"HP LaserJet");
        assert_eq!(resume_udp(161, &snmp).as_deref(), Some("HP LaserJet"));
        // SSDP : l'en-tête SERVER.
        let ssdp =
            b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nSERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/2.1\r\n\r\n";
        assert_eq!(
            resume_udp(1900, ssdp).as_deref(),
            Some("Linux/3.14 UPnP/1.0 MiniUPnPd/2.1")
        );
        // Requêtes bien formées : SNMP annonce la longueur exacte du message.
        let r = requete_udp(161).unwrap();
        assert_eq!(usize::from(r[1]) + 2, r.len());
        assert_eq!(requete_udp(137).unwrap().len(), 50);
        assert!(requete_udp(80).is_none());
    }

    #[test]
    fn fabricant_et_mac_aleatoire() {
        let base = base_fabricants();
        assert!(base.len() > 30_000);
        assert_eq!(
            fabricant("c4:34:6b:12:34:56", &base).as_deref(),
            Some("Hewlett Packard")
        );
        assert!(fabricant("ee:12:34:56:78:9a", &base).unwrap().contains("aléatoire"));
        // Bloc MA-M (28 bits) : son fabricant, pas le registre qui détient le grand bloc.
        assert_eq!(
            fabricant("00:55:da:0a:bc:de", &base).as_deref(),
            Some("Shinko Technos co.,ltd.")
        );
    }

    #[test]
    fn passerelle_par_defaut_linux() {
        let entete = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
        // VPN « default dev tun0 » (passerelle 0), Wi-Fi (métrique 600) et Ethernet (métrique 100).
        let table = format!(
            "{entete}tun0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n\
             wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
             eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
             eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
        );
        assert_eq!(passerelle_linux(&table), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(passerelle_linux(entete), None);
    }

    #[test]
    fn voisins_perimes_ecartes() {
        let etats = lire_etats_voisins(
            "10.0.0.1 dev wlan0 lladdr f8:79:0a:0d:03:a2 router REACHABLE\n\
             10.0.0.48 dev wlan0 lladdr f4:6c:68:11:22:33 STALE\n\
             10.0.0.75 dev wlan0 lladdr 08:6a:c5:44:55:66 DELAY\n\
             10.0.0.99 dev wlan0  FAILED\n",
        );
        let etat = |d: u8| etats.get(&Ipv4Addr::new(10, 0, 0, d)).map(String::as_str);
        assert_eq!(etat(1), Some("REACHABLE"));
        assert!(etat_en_cours(etat(75)) && !etat_en_cours(etat(48)));
        // Confirmé pendant le scan puis vieilli (STALE) : présent. Sans réponse (FAILED) ou oublié : absent.
        assert!(voisin_present(etat(1)) && voisin_present(etat(48)));
        assert!(!voisin_present(etat(99)) && !voisin_present(etat(200)));
    }
}
