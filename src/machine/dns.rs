//! DNS : quel serveur traduit les noms de sites pour cette machine, et répond-il honnêtement ?
//! Un DNS changé en douce (malware, box piratée, réseau piégé) envoie tes visites où il veut, même vers un faux
//! site de banque à la bonne adresse : c'est l'une des premières choses que modifie un malware.

use std::net::IpAddr;
use std::time::Duration;

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "DNS";

/// D'où vient un serveur DNS.
#[derive(Debug, PartialEq)]
enum Origine {
    /// Résolveur sur cette machine (systemd-resolved, NextDNS, dnscrypt-proxy…).
    Local,
    /// Box, routeur ou serveur du réseau local.
    Reseau,
    /// Service public connu.
    Connu(&'static str),
    /// Serveur d'Internet qui n'est dans aucune liste : souvent celui du fournisseur Internet.
    Inconnu,
}

/// Services DNS publics reconnus à leur adresse.
fn fournisseur(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => match v4.octets() {
            [1, 1, 1, _] | [1, 0, 0, _] => Some("Cloudflare"),
            [8, 8, 8, 8] | [8, 8, 4, 4] => Some("Google"),
            [9, 9, 9, _] | [149, 112, 112, _] => Some("Quad9"),
            [208, 67, 222 | 220, _] => Some("OpenDNS"),
            [45, 90, 28 | 30, _] => Some("NextDNS"),
            [94, 140, 14 | 15, _] => Some("AdGuard DNS"),
            [194, 242, 2, _] => Some("Mullvad DNS"),
            [185, 228, 168 | 169, _] => Some("CleanBrowsing"),
            [76, 76, 2 | 10, _] => Some("Control D"),
            [100, 100, 100, 100] => Some("Tailscale"),
            _ => None,
        },
        IpAddr::V6(v6) => match v6.segments() {
            [0x2606, 0x4700, ..] => Some("Cloudflare"),
            [0x2001, 0x4860, ..] => Some("Google"),
            [0x2620, 0xfe, ..] => Some("Quad9"),
            [0x2620, 0x119, ..] => Some("OpenDNS"),
            [0x2a07, 0xa8c0 | 0xa8c1, ..] => Some("NextDNS"),
            [0x2a10, 0x50c0, ..] => Some("AdGuard DNS"),
            [0x2a07, 0xe340, ..] => Some("Mullvad DNS"),
            _ => None,
        },
    }
}

fn origine(ip: IpAddr) -> Origine {
    if ip.is_loopback() {
        return Origine::Local;
    }
    if let Some(nom) = fournisseur(ip) {
        return Origine::Connu(nom);
    }
    let local = match ip {
        // 100.64.0.0/10 : adresses partagées (CGNAT, VPN maillés) : pas Internet.
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private() || v4.is_link_local() || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local(),
    };
    if local { Origine::Reseau } else { Origine::Inconnu }
}

/// Adresse d'une ligne de configuration : « 1.1.1.1#cloudflare-dns.com » (DNS chiffré de resolved) ou
/// « fe80::1%3 » (zone IPv6) gardent seulement l'adresse.
fn adresse(texte: &str) -> Option<IpAddr> {
    texte
        .split(['#', '%'])
        .next()?
        .trim()
        .trim_matches(['[', ']'])
        .parse()
        .ok()
}

/// Serveurs listés par `resolvectl dns` (« Global: 127.0.0.1 », « Link 3 (wlan0): 10.0.0.1 »).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lire_resolvectl(sortie: &str) -> Vec<IpAddr> {
    sortie
        .lines()
        .filter_map(|l| l.split_once(':').map(|(_, reste)| reste))
        .flat_map(str::split_whitespace)
        .filter_map(adresse)
        .collect()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lire_resolv_conf(texte: &str) -> Vec<IpAddr> {
    texte
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(adresse)
        .collect()
}

/// Ce qu'on sait des serveurs DNS de la machine.
struct Serveurs {
    /// (adresse, réglée à la main) ; Linux ne dit pas d'où vient un serveur : toujours `false`.
    liste: Vec<(IpAddr, bool)>,
    /// Requêtes chiffrées (DNS over TLS, résolveur local chiffrant), quand on peut le savoir.
    chiffre: Option<bool>,
    /// Programme qui résout les noms en local (« NextDNS »…).
    resolveur_local: Option<&'static str>,
    /// Commande qui remet les DNS d'une interface en automatique (Windows), par adresse.
    remise: Vec<(IpAddr, String)>,
}

/// Résolveurs locaux connus : (service systemd, nom affiché, chiffre ses requêtes).
#[cfg(target_os = "linux")]
const RESOLVEURS: &[(&str, &str, bool)] = &[
    ("nextdns", "NextDNS", true),
    ("dnscrypt-proxy", "dnscrypt-proxy", true),
    ("stubby", "Stubby", true),
    ("cloudflared", "cloudflared", true),
    ("AdGuardHome", "AdGuard Home", false),
    ("unbound", "Unbound", false),
    ("dnsmasq", "dnsmasq", false),
    ("pihole-FTL", "Pi-hole", false),
];

#[cfg(target_os = "linux")]
fn serveurs() -> Option<Serveurs> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let mut liste = lire_resolv_conf(&conf);
    let mut chiffre = None;
    // 127.0.0.53 : systemd-resolved, qui transmet aux vrais serveurs (ceux de resolvectl).
    if liste.iter().any(|ip| *ip == IpAddr::from([127, 0, 0, 53]))
        && let Some(dns) = super::sortie("resolvectl", &["dns"])
    {
        let vrais = lire_resolvectl(&dns);
        if !vrais.is_empty() {
            liste = vrais;
        }
        chiffre = super::sortie("resolvectl", &["status"]).map(|s| s.contains("+DNSOverTLS"));
    }
    let mut resolveur_local = None;
    if liste.iter().any(IpAddr::is_loopback) {
        let noms: Vec<&str> = RESOLVEURS.iter().map(|r| r.0).collect();
        let mut args = vec!["is-active"];
        args.extend(&noms);
        // is-active répond une ligne par service, dans l'ordre ; son code de retour n'est 0 que si tous tournent.
        let etats = crate::commande::lancer(std::process::Command::new("systemctl").args(&args), 10)
            .map(|r| r.sortie)
            .unwrap_or_default();
        if let Some((_, nom, chiffrant)) = RESOLVEURS
            .iter()
            .zip(etats.lines())
            .find(|(_, etat)| etat.trim() == "active")
            .map(|(r, _)| *r)
        {
            resolveur_local = Some(nom);
            if chiffrant {
                chiffre = Some(true);
            }
        }
    }
    Some(Serveurs {
        liste: liste.into_iter().map(|ip| (ip, false)).collect(),
        chiffre,
        resolveur_local,
        remise: Vec::new(),
    })
}

/// Serveurs de `scutil --dns` (« nameserver[0] : 10.0.0.1 »), section principale seulement : celle « for scoped
/// queries » répète les mêmes serveurs par interface.
#[cfg(any(target_os = "macos", test))]
fn lire_scutil(sortie: &str) -> Vec<IpAddr> {
    let mut liste = Vec::new();
    for l in sortie.lines().take_while(|l| !l.contains("for scoped queries")) {
        if let Some((cle, valeur)) = l.split_once(':')
            && cle.trim().starts_with("nameserver[")
            && let Some(ip) = adresse(valeur.trim())
            && !liste.contains(&ip)
        {
            liste.push(ip);
        }
    }
    liste
}

/// Résolveurs locaux connus : (processus, nom affiché, chiffre ses requêtes).
#[cfg(target_os = "macos")]
const RESOLVEURS: &[(&str, &str, bool)] = &[
    ("nextdns", "NextDNS", true),
    ("dnscrypt-proxy", "dnscrypt-proxy", true),
    ("cloudflared", "cloudflared", true),
    ("AdGuardHome", "AdGuard Home", false),
    ("unbound", "Unbound", false),
    ("dnsmasq", "dnsmasq", false),
];

/// macOS : serveurs en service d'après `scutil --dns` ; un serveur est « réglé à la main » s'il figure dans les
/// réglages d'un service réseau (`networksetup -getdnsservers`), sinon il vient de la box (DHCP).
#[cfg(target_os = "macos")]
fn serveurs() -> Option<Serveurs> {
    let liste = lire_scutil(&super::sortie("scutil", &["--dns"])?);
    let services: Vec<String> = super::sortie("networksetup", &["-listallnetworkservices"])
        .unwrap_or_default()
        .lines()
        .skip(1)
        // Un service désactivé commence par « * ».
        .filter(|l| !l.starts_with('*') && !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    let mut manuels: Vec<(IpAddr, String)> = Vec::new();
    for service in &services {
        for ip in super::sortie("networksetup", &["-getdnsservers", service])
            .unwrap_or_default()
            .lines()
            .filter_map(|l| adresse(l.trim()))
        {
            let echappe = service.replace('\'', r"'\''");
            manuels.push((ip, format!("sudo networksetup -setdnsservers '{echappe}' empty")));
        }
    }
    let mut resolveur_local = None;
    let mut chiffre = None;
    if liste.iter().any(IpAddr::is_loopback)
        && let Some((_, nom, chiffrant)) = RESOLVEURS
            .iter()
            .find(|(p, _, _)| super::sortie("pgrep", &["-x", p]).is_some())
    {
        resolveur_local = Some(*nom);
        if *chiffrant {
            chiffre = Some(true);
        }
    }
    Some(Serveurs {
        liste: liste
            .iter()
            .map(|ip| (*ip, manuels.iter().any(|(m, _)| m == ip)))
            .collect(),
        chiffre,
        resolveur_local,
        remise: manuels,
    })
}

/// Lignes « DNS|index|adresse|manuel » : les serveurs de chaque carte réseau active. « manuel » : l'adresse
/// est écrite dans le registre de la carte (NameServer), donc réglée à la main ou par un programme, pas par le DHCP.
#[cfg(windows)]
fn serveurs() -> Option<Serveurs> {
    let sortie = super::windows::ps(
        "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { $i = $_.InterfaceIndex; \
         $fixe = (Get-ItemProperty \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($_.InterfaceGuid)\" -ErrorAction SilentlyContinue).NameServer; \
         (Get-DnsClientServerAddress -InterfaceIndex $i -ErrorAction SilentlyContinue).ServerAddresses | ForEach-Object { \
         \"DNS|$i|$_|$([bool]($fixe -and $fixe.Contains($_)))\" } }",
    )?;
    let mut liste = Vec::new();
    let mut remise = Vec::new();
    for l in sortie.lines() {
        let c: Vec<&str> = l.trim().split('|').collect();
        if let ["DNS", index, ip, manuel] = c[..]
            && let Some(ip) = adresse(ip)
        {
            let manuel = manuel.eq_ignore_ascii_case("true");
            if !liste.contains(&(ip, manuel)) {
                liste.push((ip, manuel));
            }
            if manuel {
                remise.push((
                    ip,
                    format!("Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses"),
                ));
            }
        }
    }
    Some(Serveurs {
        liste,
        chiffre: None,
        resolveur_local: None,
        remise,
    })
}

/// Ce que l'outil « DNS le plus rapide » doit savoir des serveurs DNS de cette machine.
pub(crate) struct Actuel {
    /// (adresse, réglée à la main).
    pub serveurs: Vec<(IpAddr, bool)>,
    /// Requêtes chiffrées, quand on peut le savoir.
    pub chiffre: Option<bool>,
    /// Programme qui résout les noms sur cet ordinateur (« NextDNS »…).
    pub resolveur_local: Option<&'static str>,
}

pub(crate) fn actuel() -> Option<Actuel> {
    serveurs().map(|s| Actuel {
        serveurs: s.liste,
        chiffre: s.chiffre,
        resolveur_local: s.resolveur_local,
    })
}

/// Le service public d'un serveur DNS, reconnu à son adresse (« Cloudflare », « NextDNS »…).
pub(crate) fn service_public(ip: IpAddr) -> Option<&'static str> {
    fournisseur(ip)
}

fn decrire(ip: IpAddr, s: &Serveurs) -> String {
    match origine(ip) {
        Origine::Local => match s.resolveur_local {
            Some(nom) => trf!("{nom} (sur cette machine)", "{nom} (on this machine)"),
            None => trf!("résolveur local ({ip})", "local resolver ({ip})"),
        },
        Origine::Reseau => trf!("ta box ou ton réseau ({ip})", "your router or network ({ip})"),
        Origine::Connu(nom) => format!("{nom} ({ip})"),
        Origine::Inconnu => ip.to_string(),
    }
}

/// Constat sur les serveurs DNS utilisés.
fn constat_serveurs(s: &Serveurs) -> Constat {
    if s.liste.is_empty() {
        return alerte(
            CAT,
            Niveau::Info,
            tr!("Aucun serveur DNS configuré.", "No DNS server configured."),
        );
    }
    let mut noms: Vec<String> = Vec::new();
    for (ip, _) in &s.liste {
        let d = decrire(*ip, s);
        if !noms.contains(&d) {
            noms.push(d);
        }
    }
    let noms = noms.join(", ");
    let inconnus_manuels: Vec<IpAddr> = s
        .liste
        .iter()
        .filter(|(ip, manuel)| *manuel && origine(*ip) == Origine::Inconnu)
        .map(|(ip, _)| *ip)
        .collect();
    if !inconnus_manuels.is_empty() {
        let liste = inconnus_manuels
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let constat = alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "DNS réglé à la main vers un serveur inconnu : {liste}. Si tu ne l'as pas choisi, un programme a pu le changer pour détourner tes visites.",
                "DNS manually set to an unknown server: {liste}. If you did not choose it, a program may have changed it to hijack your browsing."
            ),
        );
        let commandes: Vec<&str> = s
            .remise
            .iter()
            .filter(|(ip, _)| inconnus_manuels.contains(ip))
            .map(|(_, c)| c.as_str())
            .collect();
        if commandes.is_empty() {
            return constat;
        }
        let mut commandes = commandes;
        commandes.dedup();
        return constat.corriger(
            tr!(
                "Remettre le DNS en automatique (celui que donne la box)",
                "Set DNS back to automatic (the one the router provides)"
            ),
            &commandes,
        );
    }
    let chiffrement = match s.chiffre {
        Some(true) => tr!(", requêtes chiffrées", ", encrypted queries"),
        Some(false) => tr!(
            ", requêtes non chiffrées (ton fournisseur Internet voit les sites visités)",
            ", unencrypted queries (your Internet provider sees the sites you visit)"
        ),
        None => "",
    };
    if s.liste.iter().any(|(ip, _)| origine(*ip) == Origine::Inconnu) {
        return alerte(
            CAT,
            Niveau::Info,
            trf!(
                "DNS : {noms}{chiffrement}. Serveur hors des services connus : normal si c'est celui de ton fournisseur Internet.",
                "DNS: {noms}{chiffrement}. Server outside the known services: normal if it is your Internet provider's."
            ),
        );
    }
    ok(CAT, trf!("DNS : {noms}{chiffrement}.", "DNS: {noms}{chiffrement}."))
}

/// Un nom qui ne peut pas exister (16 chiffres hexadécimaux au hasard) : un DNS honnête répond « inconnu ».
fn nom_inexistant() -> String {
    let graine = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| {
            d.as_secs().wrapping_mul(1_000_000_007) ^ u64::from(d.subsec_nanos())
        })
        ^ u64::from(std::process::id());
    format!("vanguard-{graine:016x}.com")
}

/// Le DNS invente-t-il des réponses ? Il en donne une pour un site qui n'existe pas : fournisseur qui redirige les
/// erreurs vers ses pages de publicité, portail de Wi-Fi public, ou détournement. `None` : nom refusé, comme il
/// se doit, ou pas de réponse en 3 s (une vraie réponse « inconnu » vient presque toujours en moins d'une seconde ;
/// 5 s, avant, retenaient tout le bilan quand le réseau est cassé, un Wi-Fi connecté sans Internet par exemple).
fn reponse_inventee() -> Option<IpAddr> {
    use std::net::ToSocketAddrs;
    let nom = nom_inexistant();
    let (envoi, reception) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let reponse = (nom.as_str(), 80)
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .map(|a| a.ip());
        let _ = envoi.send(reponse);
    });
    reception.recv_timeout(Duration::from_secs(3)).ok().flatten()
}

pub fn dns() -> Vec<Constat> {
    // Le nom inventé se demande pendant la lecture des serveurs (un PowerShell sous Windows) : l'un n'attend plus
    // l'autre.
    let inventee = std::thread::spawn(reponse_inventee);
    let mut constats = Vec::new();
    match serveurs() {
        Some(s) => constats.push(constat_serveurs(&s)),
        None => constats.push(super::impossible(
            CAT,
            tr!("configuration DNS illisible", "DNS configuration unreadable"),
        )),
    }
    // Réponse pour un nom inexistant, sauf si le résolveur bloque en renvoyant 0.0.0.0 (listes de blocage).
    if let Some(ip) = inventee.join().ok().flatten()
        && !ip.is_unspecified()
    {
        constats.push(alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Le DNS répond même pour un site qui n'existe pas (→ {ip}) : ton fournisseur redirige les erreurs vers ses pages, un portail Wi-Fi intercepte, ou quelqu'un détourne tes requêtes.",
                "The DNS answers even for a site that does not exist (→ {ip}): your provider redirects errors to its pages, a Wi-Fi portal intercepts, or someone is hijacking your queries."
            ),
        ));
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn origine_des_serveurs() {
        assert_eq!(origine(ip("127.0.0.1")), Origine::Local);
        assert_eq!(origine(ip("::1")), Origine::Local);
        assert_eq!(origine(ip("10.0.0.1")), Origine::Reseau);
        assert_eq!(origine(ip("192.168.1.1")), Origine::Reseau);
        assert_eq!(origine(ip("fe80::1")), Origine::Reseau);
        assert_eq!(origine(ip("fd00::53")), Origine::Reseau);
        assert_eq!(origine(ip("100.64.0.1")), Origine::Reseau);
        assert_eq!(origine(ip("100.100.100.100")), Origine::Connu("Tailscale"));
        assert_eq!(origine(ip("1.1.1.1")), Origine::Connu("Cloudflare"));
        assert_eq!(origine(ip("45.90.30.12")), Origine::Connu("NextDNS"));
        assert_eq!(origine(ip("2620:fe::fe")), Origine::Connu("Quad9"));
        assert_eq!(origine(ip("2a07:a8c1::ab")), Origine::Connu("NextDNS"));
        assert_eq!(origine(ip("203.0.113.53")), Origine::Inconnu);
    }

    #[test]
    fn lecture_de_scutil() {
        let sortie = "DNS configuration\n\nresolver #1\n  search domain[0] : home\n  nameserver[0] : 10.0.0.1\n  \
                      nameserver[1] : 2001:db8::1\n  if_index : 14 (en0)\n\nresolver #2\n  domain   : local\n\n\
                      DNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 9.9.9.9\n";
        assert_eq!(lire_scutil(sortie), [ip("10.0.0.1"), ip("2001:db8::1")]);
    }

    #[test]
    fn lecture_des_configurations() {
        let conf = "# généré\nnameserver 127.0.0.53\noptions edns0 trust-ad\nnameserver fe80::1%wlan0\n";
        assert_eq!(lire_resolv_conf(conf), [ip("127.0.0.53"), ip("fe80::1")]);
        let resolvectl =
            "Global: 127.0.0.1\nLink 2 (enp12s0):\nLink 3 (wlp13s0): 10.0.0.1 1.1.1.1#cloudflare-dns.com fe80::1%3\n";
        assert_eq!(
            lire_resolvectl(resolvectl),
            [ip("127.0.0.1"), ip("10.0.0.1"), ip("1.1.1.1"), ip("fe80::1")]
        );
    }

    #[test]
    fn dns_manuel_inconnu_signale() {
        let s = |liste: Vec<(IpAddr, bool)>| Serveurs {
            liste,
            chiffre: None,
            resolveur_local: None,
            remise: vec![(
                ip("45.13.105.2"),
                "Set-DnsClientServerAddress -InterfaceIndex 7 -ResetServerAddresses".into(),
            )],
        };
        let c = constat_serveurs(&s(vec![(ip("45.13.105.2"), true)]));
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.correctif.is_some());
        // Le même serveur donné par le réseau (DHCP) : sans doute celui du fournisseur, simple information.
        assert_eq!(
            constat_serveurs(&s(vec![(ip("45.13.105.2"), false)])).probleme,
            Some(Niveau::Info)
        );
        // Un service connu réglé à la main : un choix, pas un problème.
        assert_eq!(constat_serveurs(&s(vec![(ip("1.1.1.1"), true)])).probleme, None);
        assert!(nom_inexistant().starts_with("vanguard-"));
    }
}
