//! Type de NAT pour le jeu : ouvert, modéré ou strict, comme l'affichent les consoles. Le NAT de la box traduit
//! l'adresse de chaque appareil en son adresse publique. Deux serveurs publics (STUN, RFC 5389) disent quelle adresse
//! et quel port ils voient, depuis le même port de cet ordinateur : le même port pour les deux, la box garde une
//! traduction stable (modéré, ouvert avec l'UPnP) ; un port différent par serveur, elle en change à chaque
//! destination (strict, symétrique), et les autres joueurs ne peuvent pas la joindre directement. Lecture seule.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use crate::risk::Niveau;
use crate::ui::*;

/// Valeur fixe des messages STUN (« magic cookie »), qui masque aussi les adresses rendues.
const MAGIC: u32 = 0x2112_A442;
const MAGIC_HAUT: u16 = 0x2112;

/// Serveurs STUN publics de deux opérateurs (nom, port, opérateur) : chacun voit l'adresse de la maison, comme
/// n'importe quel site.
const SERVEURS: [(&str, u16, &str); 3] = [
    ("stun.cloudflare.com", 3478, "Cloudflare"),
    ("stun.l.google.com", 19302, "Google"),
    ("stun1.l.google.com", 19302, "Google"),
];

/// Identifiant d'une requête : 12 octets au hasard, pour reconnaître sa réponse.
fn identifiant() -> [u8; 12] {
    let mut id = [0u8; 12];
    let instant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    for (i, morceau) in id.chunks_mut(8).enumerate() {
        let mut h = RandomState::new().build_hasher();
        h.write_usize(i);
        h.write_u128(instant);
        morceau.copy_from_slice(&h.finish().to_le_bytes()[..morceau.len()]);
    }
    id
}

/// Requête « Binding » sans attribut : type, longueur nulle, cookie, identifiant.
fn requete(id: &[u8; 12]) -> [u8; 20] {
    let mut r = [0u8; 20];
    r[..2].copy_from_slice(&0x0001u16.to_be_bytes());
    r[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    r[8..].copy_from_slice(id);
    r
}

/// Adresse d'un attribut STUN (réservé, famille, port, adresse), démasquée par le cookie (et l'identifiant, en IPv6)
/// pour XOR-MAPPED-ADDRESS.
fn adresse(valeur: &[u8], masque: Option<&[u8; 12]>) -> Option<SocketAddr> {
    let famille = *valeur.get(1)?;
    let mut port = u16::from_be_bytes([*valeur.get(2)?, *valeur.get(3)?]);
    let mut cle = [0u8; 16];
    if let Some(id) = masque {
        port ^= MAGIC_HAUT;
        cle[..4].copy_from_slice(&MAGIC.to_be_bytes());
        cle[4..].copy_from_slice(id);
    }
    let ip = match famille {
        1 => {
            let mut o: [u8; 4] = valeur.get(4..8)?.try_into().ok()?;
            o.iter_mut().zip(&cle).for_each(|(a, k)| *a ^= k);
            IpAddr::V4(Ipv4Addr::from(o))
        }
        2 => {
            let mut o: [u8; 16] = valeur.get(4..20)?.try_into().ok()?;
            o.iter_mut().zip(&cle).for_each(|(a, k)| *a ^= k);
            IpAddr::V6(Ipv6Addr::from(o))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// L'adresse vue par le serveur, dans sa réponse « Binding Success » à notre requête : XOR-MAPPED-ADDRESS, sinon
/// MAPPED-ADDRESS (anciens serveurs).
fn lire_reponse(r: &[u8], id: &[u8; 12]) -> Option<SocketAddr> {
    if r.len() < 20 || r[..2] != [0x01, 0x01] || r[4..8] != MAGIC.to_be_bytes() || r[8..20] != id[..] {
        return None;
    }
    let longueur = usize::from(u16::from_be_bytes([r[2], r[3]]));
    let attributs = r.get(20..20 + longueur)?;
    let mut simple = None;
    let mut i = 0;
    while let Some(entete) = attributs.get(i..i + 4) {
        let type_ = u16::from_be_bytes([entete[0], entete[1]]);
        let n = usize::from(u16::from_be_bytes([entete[2], entete[3]]));
        let valeur = attributs.get(i + 4..i + 4 + n)?;
        match type_ {
            0x0020 => return adresse(valeur, Some(id)),
            0x0001 => simple = adresse(valeur, None),
            _ => {}
        }
        // Chaque attribut est complété à un multiple de 4 octets.
        i += 4 + n.div_ceil(4) * 4;
    }
    simple
}

/// Adresse et port vus par un serveur, depuis `socket` : trois essais, une réponse UDP pouvant se perdre.
fn interroger(socket: &UdpSocket, serveur: SocketAddr) -> Option<SocketAddr> {
    let id = identifiant();
    let message = requete(&id);
    let mut tampon = [0u8; 576];
    for _ in 0..3 {
        socket.send_to(&message, serveur).ok()?;
        let fin = Instant::now() + Duration::from_millis(800);
        loop {
            let reste = fin.saturating_duration_since(Instant::now());
            if reste.is_zero() {
                break;
            }
            socket.set_read_timeout(Some(reste)).ok()?;
            match socket.recv_from(&mut tampon) {
                Ok((n, de)) if de == serveur => {
                    if let Some(vue) = lire_reponse(&tampon[..n], &id) {
                        return Some(vue);
                    }
                }
                Ok(_) => {}
                // Délai écoulé, ou réponse ICMP d'un essai précédent (Windows) : essai suivant.
                Err(_) => break,
            }
        }
    }
    None
}

/// Les serveurs, à leur adresse de la famille voulue (IPv4 ou IPv6).
fn serveurs(v6: bool) -> Vec<(&'static str, SocketAddr)> {
    SERVEURS
        .iter()
        .filter_map(|&(nom, port, operateur)| {
            let a = (nom, port).to_socket_addrs().ok()?.find(|a| a.is_ipv6() == v6)?;
            Some((operateur, a))
        })
        .collect()
}

/// L'adresse de cet ordinateur vers Internet (celle de sa carte réseau), sans rien envoyer.
fn adresse_locale(vers: SocketAddr) -> Option<IpAddr> {
    let s = UdpSocket::bind(if vers.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    s.connect(vers).ok()?;
    Some(s.local_addr().ok()?.ip())
}

/// Ce que les serveurs ont vu.
struct Mesure {
    /// Adresse de cet ordinateur sur son réseau.
    locale: IpAddr,
    port_local: u16,
    /// (serveur, adresse et port vus) : deux serveurs à des adresses différentes, au plus.
    vues: Vec<(&'static str, SocketAddr)>,
}

fn mesurer(v6: bool) -> Option<Mesure> {
    let liste = serveurs(v6);
    let socket = UdpSocket::bind(if v6 { "[::]:0" } else { "0.0.0.0:0" }).ok()?;
    let port_local = socket.local_addr().ok()?.port();
    let locale = adresse_locale(liste.first()?.1)?;
    let mut vues: Vec<(&'static str, SocketAddr)> = Vec::new();
    let mut interroges: Vec<IpAddr> = Vec::new();
    for (operateur, serveur) in liste {
        // Deux réponses d'adresses différentes suffisent ; deux serveurs à la même adresse n'en font qu'un.
        if vues.len() == 2 || interroges.contains(&serveur.ip()) {
            continue;
        }
        if let Some(vue) = interroger(&socket, serveur) {
            vues.push((operateur, vue));
            interroges.push(serveur.ip());
        }
    }
    Some(Mesure {
        locale,
        port_local,
        vues,
    })
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum TypeNat {
    Ouvert,
    Modere,
    Strict,
    /// Un seul serveur a répondu : la traduction de la box n'a pas pu se comparer.
    Incertain,
}

impl TypeNat {
    fn libelle(self) -> &'static str {
        match self {
            TypeNat::Ouvert => tr!("OUVERT", "OPEN"),
            TypeNat::Modere => tr!("MODÉRÉ", "MODERATE"),
            TypeNat::Strict => tr!("STRICT", "STRICT"),
            TypeNat::Incertain => tr!("INCERTAIN", "UNCERTAIN"),
        }
    }

    fn niveau(self) -> Option<Niveau> {
        match self {
            TypeNat::Ouvert => None,
            TypeNat::Modere | TypeNat::Incertain => Some(Niveau::Info),
            TypeNat::Strict => Some(Niveau::Moyen),
        }
    }
}

/// Le type de NAT, et pourquoi. `upnp` : l'UPnP de la box est-il actif (None : on ne sait pas).
fn juger(m: &Mesure, upnp: Option<bool>) -> Option<(TypeNat, &'static str)> {
    let (_, premiere) = m.vues.first()?;
    if premiere.ip() == m.locale {
        return Some((
            TypeNat::Ouvert,
            tr!(
                "Pas de NAT : cet ordinateur a lui-même l'adresse publique (seul son pare-feu filtre).",
                "No NAT: this computer has the public address itself (only its firewall filters)."
            ),
        ));
    }
    let Some((_, seconde)) = m.vues.get(1) else {
        return Some((
            TypeNat::Incertain,
            tr!(
                "Un seul serveur a répondu : la traduction de la box n'a pas pu être comparée.",
                "Only one server answered: the router's translation could not be compared."
            ),
        ));
    };
    if premiere != seconde {
        return Some((
            TypeNat::Strict,
            tr!(
                "La box change de port à chaque destination (NAT symétrique) : les autres joueurs ne peuvent pas te joindre directement.",
                "The router changes the port for each destination (symmetric NAT): other players cannot reach you directly."
            ),
        ));
    }
    Some(match upnp {
        Some(true) => (
            TypeNat::Ouvert,
            tr!(
                "Même port vu de partout, et l'UPnP de la box laisse les jeux ouvrir eux-mêmes leurs ports.",
                "Same port seen from everywhere, and the router's UPnP lets games open their ports themselves."
            ),
        ),
        Some(false) => (
            TypeNat::Modere,
            tr!(
                "Même port vu de partout, mais sans UPnP ni redirection, les autres joueurs ne peuvent pas ouvrir la connexion : certaines parties ne se rejoignent pas.",
                "Same port seen from everywhere, but without UPnP or port forwarding, other players cannot open the connection: some sessions cannot be joined."
            ),
        ),
        None => (
            TypeNat::Modere,
            tr!(
                "Même port vu de partout. Ouvert si l'UPnP de la box est actif, ce qui n'a pas pu se lire ici.",
                "Same port seen from everywhere. Open if the router's UPnP is on, which could not be read here."
            ),
        ),
    })
}

/// Double NAT ou adresse partagée par le fournisseur, d'après l'adresse que la box dit avoir sur Internet.
fn adresse_partagee(box_internet: Option<Ipv4Addr>, publique: IpAddr) -> Option<&'static str> {
    let b = box_internet?;
    let [a, d, ..] = b.octets();
    if a == 100 && (64..128).contains(&d) {
        return Some(tr!(
            "Ton fournisseur partage ton adresse Internet avec d'autres abonnés (CGNAT) : aucune redirection de ports ne peut marcher. Demande-lui une adresse IPv4 publique, ou sers-toi de l'IPv6.",
            "Your provider shares your Internet address with other customers (CGNAT): no port forwarding can work. Ask them for a public IPv4 address, or use IPv6."
        ));
    }
    if b.is_private() {
        return Some(tr!(
            "Double NAT : ta box est elle-même derrière un autre routeur. Mets la box du fournisseur en mode « bridge », ou dirige sa DMZ vers ton routeur.",
            "Double NAT: your router is itself behind another router. Put the provider's box in “bridge” mode, or point its DMZ at your router."
        ));
    }
    (IpAddr::V4(b) != publique).then_some(tr!(
        "L'adresse que la box dit avoir n'est pas celle que voit Internet : le fournisseur partage sans doute les adresses (CGNAT).",
        "The address the router says it has is not the one the Internet sees: the provider probably shares addresses (CGNAT)."
    ))
}

/// Adresse IPv6 publique (2000::/3) de cet ordinateur.
fn ipv6_publiques() -> Vec<Ipv6Addr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V6(v6) if v6.ip.segments()[0] & 0xe000 == 0x2000 => Some(v6.ip),
            _ => None,
        })
        .collect()
}

/// L'IPv6 : absente, directe (pas de NAT : ce que les consoles préfèrent), ou injoignable.
fn constat_ipv6() -> (String, Option<Niveau>) {
    let locales = ipv6_publiques();
    if locales.is_empty() {
        return (
            tr!(
                "IPv6 : absente sur ce réseau. Les jeux passent par l'IPv4, et donc par le NAT ci-dessus.",
                "IPv6: absent on this network. Games go through IPv4, hence through the NAT above."
            )
            .to_string(),
            Some(Niveau::Info),
        );
    }
    match mesurer(true).and_then(|m| m.vues.first().map(|(_, v)| *v)) {
        Some(vue) if matches!(vue.ip(), IpAddr::V6(v) if locales.contains(&v)) => (
            tr!(
                "IPv6 : directe, sans NAT. Les jeux et les consoles qui s'en servent sont joignables, si le pare-feu de la box les laisse passer.",
                "IPv6: direct, without NAT. Games and consoles that use it are reachable, if the router's firewall lets them through."
            )
            .to_string(),
            None,
        ),
        Some(_) => (
            tr!(
                "IPv6 : présente, mais traduite elle aussi (rare) : comme pour l'IPv4.",
                "IPv6: present, but translated as well (rare): same as IPv4."
            )
            .to_string(),
            Some(Niveau::Info),
        ),
        None => (
            tr!(
                "IPv6 : une adresse, mais Internet ne répond pas par là (bloquée par la box ou le fournisseur).",
                "IPv6: an address, but the Internet does not answer that way (blocked by the router or the provider)."
            )
            .to_string(),
            Some(Niveau::Info),
        ),
    }
}

fn conseils(t: TypeNat) -> &'static str {
    match t {
        TypeNat::Ouvert => tr!("Rien à faire pour le jeu en ligne.", "Nothing to do for online gaming."),
        TypeNat::Modere | TypeNat::Incertain => tr!(
            "Pour passer en ouvert : active l'UPnP dans la box, ou redirige les ports du jeu vers cet appareil, après lui avoir donné une adresse fixe (réservation DHCP). L'UPnP laisse tout appareil ouvrir des ports, un appareil infecté aussi : surveille-les (Scanner le réseau). La DMZ expose l'appareil entier à Internet : seulement pour une console.",
            "To get open: turn UPnP on in the router, or forward the game's ports to this device after giving it a fixed address (DHCP reservation). UPnP lets any device open ports, an infected one too: keep an eye on them (Scan the network). The DMZ exposes the whole device to the Internet: only for a console."
        ),
        TypeNat::Strict => tr!(
            "Une redirection de ports vers cet appareil (adresse fixe d'abord) ou l'UPnP de la box contournent souvent le NAT symétrique. Sinon, regarde dans la box une option « NAT » ou « jeu » (« endpoint-independent »), ou passe par l'IPv6.",
            "Port forwarding to this device (fixed address first) or the router's UPnP often get around symmetric NAT. Otherwise, look in the router for a “NAT” or “gaming” option (“endpoint-independent”), or use IPv6."
        ),
    }
}

/// Menu Réseau et Internet › Type de NAT, ou `gardien nat`.
pub fn tester() {
    titre(tr!("Type de NAT pour le jeu", "NAT type for gaming"));
    for ligne in envelopper(
        tr!(
            "Ouvert, modéré ou strict : c'est ce qui décide si tu peux rejoindre les parties des autres, et eux les tiennes. Deux serveurs publics (Cloudflare, Google) disent quelle adresse et quel port ils voient ; ils voient ton adresse, comme n'importe quel site. Rien n'est changé.",
            "Open, moderate or strict: it decides whether you can join other people's sessions, and they yours. Two public servers (Cloudflare, Google) tell which address and port they see; they see your address, like any website. Nothing is changed."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    trp!(
        "\n  {GRIS}Interrogation des serveurs…{RESET}",
        "\n  {GRIS}Asking the servers…{RESET}"
    );
    let Some(mesure) = mesurer(false).filter(|m| !m.vues.is_empty()) else {
        afficher_aligne(
            "  ✖ ",
            tr!(
                "Aucun serveur n'a répondu : pas d'Internet, ou l'UDP sortant est bloqué (pare-feu, réseau d'entreprise ou d'hôtel). Le jeu en ligne sera alors difficile.",
                "No server answered: no Internet, or outgoing UDP is blocked (firewall, company or hotel network). Online gaming will then be hard."
            ),
            4,
            "",
        );
        return;
    };
    let (upnp, box_internet) = crate::upnp::etat_et_adresse();
    let upnp_actif = match upnp {
        crate::upnp::Etat::Actif(_) => Some(true),
        crate::upnp::Etat::Absent => Some(false),
        crate::upnp::Etat::OutilAbsent => None,
    };
    let (_, publique) = mesure.vues[0];
    println!();
    afficher_aligne(
        &format!(
            "  {GRIS}{}{RESET}",
            ajuster(tr!("Adresse publique", "Public address"), 18)
        ),
        &publique.ip().to_string(),
        20,
        "",
    );
    let ports: Vec<String> = mesure
        .vues
        .iter()
        .map(|(nom, vue)| trf!("{nom} voit le port {}", "{nom} sees port {}", vue.port()))
        .collect();
    afficher_aligne(
        &format!("  {GRIS}{}{RESET}", ajuster(tr!("Ports vus", "Ports seen"), 18)),
        &trf!(
            "{} (port de cet ordinateur : {})",
            "{} (this computer's port: {})",
            ports.join(", "),
            mesure.port_local
        ),
        20,
        "",
    );
    let etat_upnp = match upnp_actif {
        Some(true) => tr!("actif", "on"),
        Some(false) => tr!("coupé ou absent", "off or absent"),
        None => tr!("inconnu (outil miniupnpc absent)", "unknown (miniupnpc tool missing)"),
    };
    afficher_aligne(
        &format!("  {GRIS}{}{RESET}", ajuster(tr!("UPnP de la box", "Router UPnP"), 18)),
        etat_upnp,
        20,
        "",
    );
    let Some((type_nat, pourquoi)) = juger(&mesure, upnp_actif) else {
        return;
    };
    let teinte = type_nat.niveau().map_or(VERT, couleur);
    println!(
        "\n  {GRAS}NAT{RESET} : {teinte}{}{RESET}  {GRIS}{}{RESET}",
        type_nat.libelle(),
        tr!(
            "(PlayStation : type 2 si modéré, 3 si strict)",
            "(PlayStation: type 2 if moderate, 3 if strict)"
        )
    );
    afficher_aligne("  ", pourquoi, 2, "");
    if let Some(partage) = adresse_partagee(box_internet, publique.ip()) {
        afficher_aligne(&format!("  {}⚠{RESET} ", couleur(Niveau::Moyen)), partage, 4, "");
    }
    let (ipv6, niveau) = constat_ipv6();
    println!();
    let marque = niveau.map_or_else(|| format!("{VERT}✔{RESET}"), |n| format!("{}ℹ{RESET}", couleur(n)));
    afficher_aligne(&format!("  {marque} "), &ipv6, 4, "");
    println!();
    afficher_aligne("  💡 ", conseils(type_nat), 5, "");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Réponse « Binding Success » avec une XOR-MAPPED-ADDRESS (et un attribut inconnu avant, de longueur impaire).
    fn reponse(id: &[u8; 12], vue: SocketAddr) -> Vec<u8> {
        let mut attribut = vec![0x80, 0x22, 0, 3, b'a', b'b', b'c', 0];
        let (famille, octets): (u8, Vec<u8>) = match vue.ip() {
            IpAddr::V4(v4) => (1, v4.octets().to_vec()),
            IpAddr::V6(v6) => (2, v6.octets().to_vec()),
        };
        let mut cle = MAGIC.to_be_bytes().to_vec();
        cle.extend(id);
        let masquee: Vec<u8> = octets.iter().zip(&cle).map(|(a, k)| a ^ k).collect();
        let longueur = u16::try_from(4 + masquee.len()).unwrap();
        attribut.extend([0x00, 0x20]);
        attribut.extend(longueur.to_be_bytes());
        attribut.extend([0, famille]);
        attribut.extend((vue.port() ^ MAGIC_HAUT).to_be_bytes());
        attribut.extend(masquee);
        let mut r = vec![0x01, 0x01];
        r.extend(u16::try_from(attribut.len()).unwrap().to_be_bytes());
        r.extend(MAGIC.to_be_bytes());
        r.extend(id);
        r.extend(attribut);
        r
    }

    #[test]
    fn requete_et_reponses_stun() {
        let id = identifiant();
        assert_ne!(id, identifiant(), "deux identifiants identiques");
        let r = requete(&id);
        assert_eq!((r[0], r[1], r[2], r[3]), (0, 1, 0, 0));
        for vue in ["203.0.113.7:54321", "[2001:db8::7]:40000"] {
            let vue: SocketAddr = vue.parse().unwrap();
            assert_eq!(lire_reponse(&reponse(&id, vue), &id), Some(vue));
        }
        // Réponse à une autre requête, message tronqué : ignorés.
        let autre = identifiant();
        let vue: SocketAddr = "203.0.113.7:1".parse().unwrap();
        assert_eq!(lire_reponse(&reponse(&autre, vue), &id), None);
        assert_eq!(lire_reponse(&reponse(&id, vue)[..24], &id), None);
        // MAPPED-ADDRESS d'un ancien serveur, en clair.
        let mut ancien = vec![0x01, 0x01, 0, 12];
        ancien.extend(MAGIC.to_be_bytes());
        ancien.extend(id);
        ancien.extend([0x00, 0x01, 0, 8, 0, 1, 0x1f, 0x90, 198, 51, 100, 9]);
        assert_eq!(lire_reponse(&ancien, &id), "198.51.100.9:8080".parse().ok());
    }

    fn mesure(locale: &str, vues: &[&str]) -> Mesure {
        Mesure {
            locale: locale.parse().unwrap(),
            port_local: 50000,
            vues: vues
                .iter()
                .zip(["cloudflare", "google"])
                .map(|(v, n)| (n, v.parse().unwrap()))
                .collect(),
        }
    }

    #[test]
    fn verdicts() {
        let cone = mesure("10.0.0.20", &["203.0.113.7:50000", "203.0.113.7:50000"]);
        assert_eq!(juger(&cone, Some(true)).unwrap().0, TypeNat::Ouvert);
        assert_eq!(juger(&cone, Some(false)).unwrap().0, TypeNat::Modere);
        assert_eq!(juger(&cone, None).unwrap().0, TypeNat::Modere);
        let symetrique = mesure("10.0.0.20", &["203.0.113.7:61000", "203.0.113.7:61004"]);
        assert_eq!(juger(&symetrique, Some(true)).unwrap().0, TypeNat::Strict);
        let direct = mesure("203.0.113.7", &["203.0.113.7:50000", "203.0.113.7:50000"]);
        assert_eq!(juger(&direct, Some(false)).unwrap().0, TypeNat::Ouvert);
        let seul = mesure("10.0.0.20", &["203.0.113.7:50000"]);
        assert_eq!(juger(&seul, None).unwrap().0, TypeNat::Incertain);
        assert!(juger(&mesure("10.0.0.20", &[]), None).is_none());
    }

    #[test]
    fn adresses_partagees() {
        let publique: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(adresse_partagee(Some(Ipv4Addr::new(100, 72, 1, 2)), publique).is_some_and(|t| t.contains("CGNAT")));
        assert!(adresse_partagee(Some(Ipv4Addr::new(192, 168, 1, 2)), publique).is_some());
        assert!(adresse_partagee(Some(Ipv4Addr::new(198, 51, 100, 3)), publique).is_some());
        assert_eq!(adresse_partagee(Some(Ipv4Addr::new(203, 0, 113, 7)), publique), None);
        assert_eq!(adresse_partagee(None, publique), None);
    }
}
