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

/// Plage d'adresses IPv4 à partir de « 10.0.0.5 », « 10.0.0.0/24 » ou « 10.0.0.1-50 ».
pub fn parse_cible(cible: &str) -> Result<Vec<Ipv4Addr>, String> {
    if let Some((ip, pref)) = cible.split_once('/') {
        let ip: Ipv4Addr = ip.parse().map_err(|_| format!("IP invalide : {ip}"))?;
        let pref: u32 = pref.parse().map_err(|_| format!("préfixe invalide : {pref}"))?;
        if !(16..=32).contains(&pref) {
            return Err("préfixe accepté : /16 à /32".into());
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
        let debut: Ipv4Addr = debut.parse().map_err(|_| format!("IP invalide : {debut}"))?;
        let fin: u8 = fin.parse().map_err(|_| format!("fin de plage invalide : {fin}"))?;
        let o = debut.octets();
        return Ok((o[3]..=fin).map(|d| Ipv4Addr::new(o[0], o[1], o[2], d)).collect());
    }
    cible
        .parse()
        .map(|ip| vec![ip])
        .map_err(|_| format!("cible invalide : {cible}"))
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
    let pref = masque(choisi).count_ones().max(16);
    let reseau = Ipv4Addr::from(u32::from(choisi.ip) & masque(choisi));
    Some((format!("{reseau}/{pref}"), choisi.ip))
}

#[cfg(not(target_os = "linux"))]
fn commande(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Passerelle par défaut (la box / le routeur).
pub fn passerelle() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        table.lines().skip(1).find_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            (c.get(1) == Some(&"00000000"))
                .then(|| u32::from_str_radix(c[2], 16).ok())
                .flatten()
                .map(|g| Ipv4Addr::from(g.swap_bytes()))
        })
    }
    #[cfg(target_os = "macos")]
    {
        commande("route", &["-n", "get", "default"])
            .lines()
            .find_map(|l| l.trim().strip_prefix("gateway:")?.trim().parse().ok())
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
}

/// Normalise une MAC en « aa:bb:cc:dd:ee:ff » (macOS écrit « a:b:… », Windows « aa-bb-… »).
fn normaliser_mac(brut: &str) -> Option<String> {
    let parties: Vec<String> = brut.split([':', '-']).map(|p| format!("{:0>2}", p.to_ascii_lowercase())).collect();
    let mac = parties.join(":");
    let valide = parties.len() == 6 && parties.iter().all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok());
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
            (c.get(2) == Some(&"0x2")).then(|| Some((c.first()?.to_string(), c.get(3)?.to_string()))).flatten()
        })
        .collect();
    // macOS : « ? (10.0.0.1) at f8:79:a:d:3:a2 on en0 … »
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
    vivantes.extend(ips.iter().filter(|ip| arp.contains_key(ip)));
    vivantes.sort();
    vivantes.dedup();
    vivantes
}

/// Lit ce que le service annonce (SSH, FTP, SMTP…) ou l'en-tête Server en HTTP.
async fn banniere(mut flux: TcpStream, port: u16) -> Option<String> {
    if PORTS_HTTP.contains(&port) {
        flux.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await.ok()?;
    }
    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_millis(1200), flux.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    let texte = String::from_utf8_lossy(&buf[..n]);
    let ligne = if PORTS_HTTP.contains(&port) {
        texte
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("server:"))
            .map(|l| l[7..].trim().to_string())
    } else {
        texte.lines().next().map(|l| l.trim().to_string())
    }?;
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
    let essais = hotes
        .iter()
        .flat_map(|&ip| ports.iter().map(move |&p| (ip, p)));
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

/// Nom DNS inverse (box, mDNS via nss…), sans bloquer le runtime.
pub async fn nom_hote(ip: Ipv4Addr) -> Option<String> {
    let nom = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)))
        .await
        .ok()?
        .ok()?;
    (nom != ip.to_string()).then_some(nom)
}

/// Base des fabricants (préfixe MAC → nom), extraite de la liste IEEE et intégrée au programme.
pub fn base_fabricants() -> HashMap<String, String> {
    include_str!("../assets/oui.tsv")
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(p, n)| (p.to_string(), n.to_string()))
        .collect()
}

pub fn fabricant(mac: &str, base: &HashMap<String, String>) -> Option<String> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_uppercase();
    let premier = u8::from_str_radix(hex.get(..2)?, 16).ok()?;
    // Bit « administré localement » : MAC aléatoire, typique des téléphones et tablettes récents.
    if premier & 0x02 != 0 {
        return Some("MAC aléatoire (téléphone/tablette ?)".into());
    }
    base.get(hex.get(..6)?).cloned()
}
