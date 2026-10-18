//! DNS le plus rapide : chaque visite de site commence par une question au DNS (« quelle adresse pour ce nom ? »).
//! Gardien mesure ici le temps de réponse du DNS actuel et de quatre DNS publics (Cloudflare, Quad9, Google,
//! AdGuard DNS), en douze questions chacun, et retient la médiane. Un DNS qui protège (résolveur sur cet ordinateur
//! comme NextDNS, requêtes chiffrées, DNS filtrant, Pi-hole du réseau) est gardé, même plus lent : le remplacer
//! affaiblirait la protection. Sinon, le plus rapide est proposé ; appliqué après accord, il s'annule exactement
//! (Optimiser › Tout remettre comme avant).

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::machine::dns::{Actuel, service_public};
use crate::selection::{Ligne, choisir};
use crate::ui::*;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Bloque {
    Rien,
    Malveillants,
    Publicites,
}

/// Un DNS public proposé : son nom, ses adresses (la première est mesurée), ce qu'il bloque.
struct Public {
    nom: &'static str,
    v4: [&'static str; 2],
    v6: [&'static str; 2],
    bloque: Bloque,
}

const PUBLICS: [Public; 4] = [
    Public {
        nom: "Cloudflare",
        v4: ["1.1.1.1", "1.0.0.1"],
        v6: ["2606:4700:4700::1111", "2606:4700:4700::1001"],
        bloque: Bloque::Rien,
    },
    Public {
        nom: "Quad9",
        v4: ["9.9.9.9", "149.112.112.112"],
        v6: ["2620:fe::fe", "2620:fe::9"],
        bloque: Bloque::Malveillants,
    },
    Public {
        nom: "Google",
        v4: ["8.8.8.8", "8.8.4.4"],
        v6: ["2001:4860:4860::8888", "2001:4860:4860::8844"],
        bloque: Bloque::Rien,
    },
    Public {
        nom: "AdGuard DNS",
        v4: ["94.140.14.14", "94.140.15.15"],
        v6: ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
        bloque: Bloque::Publicites,
    },
];

/// Des sites très visités, que tout DNS a souvent déjà en mémoire, comme lors d'une vraie navigation.
const NOMS: [&str; 6] = [
    "www.google.com",
    "www.wikipedia.org",
    "www.youtube.com",
    "www.amazon.com",
    "www.microsoft.com",
    "www.apple.com",
];
const TOURS: usize = 2;
/// Délai d'une réponse : au-delà, la question compte comme perdue.
const DELAI: Duration = Duration::from_millis(1500);

/// Question DNS : un nom, type A (IPv4), récursion demandée.
fn question(id: u16, nom: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + nom.len() + 6);
    q.extend(id.to_be_bytes());
    q.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for etiquette in nom.split('.') {
        q.push(u8::try_from(etiquette.len()).unwrap_or(0));
        q.extend(etiquette.as_bytes());
    }
    q.extend([0, 0, 1, 0, 1]);
    q
}

/// Une réponse à notre question : même identifiant, drapeau « réponse », et le serveur a su répondre (« ce nom
/// n'existe pas » compris), pas un refus ni une panne.
fn repond(r: &[u8], id: u16) -> bool {
    r.len() >= 12 && r[..2] == id.to_be_bytes() && r[2] & 0x80 != 0 && matches!(r[3] & 0x0f, 0 | 3)
}

fn mediane(mut temps: Vec<Duration>) -> Option<Duration> {
    temps.sort_unstable();
    temps.get(temps.len() / 2).copied()
}

/// Un nombre au hasard, pour les identifiants des questions.
fn hasard() -> u16 {
    let h = RandomState::new().build_hasher().finish();
    u16::try_from(h & 0xffff).unwrap_or(0)
}

/// Temps de réponse médian d'un serveur ; `None` s'il ne répond pas.
fn mesurer(serveur: IpAddr) -> Option<Duration> {
    let socket = UdpSocket::bind(if serveur.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    socket.connect(SocketAddr::new(serveur, 53)).ok()?;
    let graine = hasard();
    let mut temps = Vec::new();
    let mut perdues = 0;
    let mut tampon = [0u8; 1500];
    for (i, nom) in NOMS.iter().cycle().take(NOMS.len() * TOURS).enumerate() {
        let id = graine.wrapping_add(u16::try_from(i).unwrap_or(0));
        let debut = Instant::now();
        let mut repondu = false;
        if socket.send(&question(id, nom)).is_ok() {
            let fin = debut + DELAI;
            loop {
                let reste = fin.saturating_duration_since(Instant::now());
                if reste.is_zero() || socket.set_read_timeout(Some(reste)).is_err() {
                    break;
                }
                match socket.recv(&mut tampon) {
                    Ok(n) if repond(&tampon[..n], id) => {
                        repondu = true;
                        break;
                    }
                    // Réponse tardive à une question d'avant : on attend la nôtre.
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        if repondu {
            temps.push(debut.elapsed());
        } else {
            perdues += 1;
        }
        // Muet trois fois de suite d'entrée : inutile d'attendre davantage.
        if temps.is_empty() && perdues >= 3 {
            break;
        }
    }
    mediane(temps)
}

/// Adresse d'un réseau local (box, routeur, serveur de la maison), pas d'Internet.
fn locale(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private() || v4.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// Les adresses de la famille « Cloudflare pour les familles », qui filtrent (1.1.1.2, 1.1.1.3…).
fn cloudflare_famille(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => matches!(v4.octets(), [1, 1, 1, 2 | 3] | [1, 0, 0, 2 | 3]),
        IpAddr::V6(v6) => matches!(v6.segments()[7], 0x1112 | 0x1113 | 0x1002 | 0x1003),
    }
}

/// Un service qui protège : il bloque des sites (malveillants, publicités, contrôle parental), chiffre, ou passe par
/// un VPN. Seuls Cloudflare (hors familles) et Google ne filtrent rien.
fn filtrant(ip: IpAddr) -> Option<&'static str> {
    match service_public(ip)? {
        "Cloudflare" => cloudflare_famille(ip).then_some("Cloudflare"),
        "Google" => None,
        autre => Some(autre),
    }
}

/// Pourquoi le DNS actuel est gardé, même plus lent : il protège.
fn protection(a: &Actuel, passerelle: Option<IpAddr>) -> Option<String> {
    if let Some(nom) = a.resolveur_local {
        return Some(trf!(
            "{nom} tourne sur cet ordinateur : il chiffre ou filtre tes requêtes.",
            "{nom} runs on this computer: it encrypts or filters your queries."
        ));
    }
    if a.serveurs.iter().any(|(ip, _)| ip.is_loopback()) {
        return Some(
            tr!(
                "un résolveur tourne sur cet ordinateur : il chiffre ou filtre sans doute tes requêtes.",
                "a resolver runs on this computer: it probably encrypts or filters your queries."
            )
            .to_string(),
        );
    }
    if a.chiffre == Some(true) {
        return Some(tr!("tes requêtes DNS sont chiffrées.", "your DNS queries are encrypted.").to_string());
    }
    if let Some(nom) = a.serveurs.iter().find_map(|(ip, _)| filtrant(*ip)) {
        return Some(trf!(
            "{nom} protège (sites dangereux ou publicitaires bloqués, ou VPN).",
            "{nom} protects (dangerous or advertising sites blocked, or VPN)."
        ));
    }
    // Un serveur du réseau en IPv4 qui n'est pas la box : Pi-hole, AdGuard Home, ou le DNS d'un VPN. En IPv6, la box
    // se présente souvent par une adresse locale : celle-là n'est pas un filtre.
    if let Some((ip, _)) = a
        .serveurs
        .iter()
        .find(|(ip, _)| ip.is_ipv4() && locale(*ip) && Some(*ip) != passerelle)
    {
        return Some(trf!(
            "{ip} est un serveur DNS de ton réseau qui n'est pas la box (Pi-hole, AdGuard Home, VPN ?) : il filtre sans doute.",
            "{ip} is a DNS server on your network that is not the router (Pi-hole, AdGuard Home, VPN?): it probably filters."
        ));
    }
    None
}

/// Le nom d'un serveur DNS actuel, pour l'écran.
fn nom_actuel(ip: IpAddr, a: &Actuel, passerelle: Option<IpAddr>) -> String {
    if ip.is_loopback() {
        return a
            .resolveur_local
            .map_or_else(|| tr!("résolveur local", "local resolver").to_string(), str::to_string);
    }
    if let Some(nom) = service_public(ip) {
        return nom.to_string();
    }
    if Some(ip) == passerelle || (ip.is_ipv6() && locale(ip)) {
        return tr!("ta box", "your router").to_string();
    }
    if locale(ip) {
        return tr!("ton réseau", "your network").to_string();
    }
    tr!("ton fournisseur ?", "your provider?").to_string()
}

fn millisecondes(d: Option<Duration>) -> String {
    match d {
        None => tr!("ne répond pas", "no answer").to_string(),
        // Un résolveur sur cet ordinateur répond de sa mémoire en moins d'une milliseconde.
        Some(d) if d < Duration::from_millis(1) => "< 1 ms".to_string(),
        Some(d) => format!("{} ms", d.as_millis()),
    }
}

/// Faut-il proposer le plus rapide ? Seulement s'il gagne vraiment : un cinquième du temps, et 5 ms au moins.
fn vaut_la_peine(actuel: Option<Duration>, meilleur: Option<Duration>) -> bool {
    match (actuel, meilleur) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(a), Some(m)) => m * 5 <= a * 4 && a.saturating_sub(m) >= Duration::from_millis(5),
    }
}

/// Précision d'un DNS public dans le menu (33 caractères au plus).
fn precision(p: &Public, temps: Option<Duration>, plus_rapide: bool) -> String {
    let ms = millisecondes(temps);
    match (temps.is_some(), p.bloque, plus_rapide) {
        (true, Bloque::Malveillants, _) => trf!("{ms}, sites dangereux bloqués", "{ms}, dangerous sites blocked"),
        (true, Bloque::Publicites, _) => trf!("{ms}, pubs et pisteurs bloqués", "{ms}, ads and trackers blocked"),
        (true, Bloque::Rien, true) => trf!("{ms}, le plus rapide", "{ms}, the fastest"),
        // Muet, ou sans rien à dire de plus que son temps.
        (false, ..) | (true, Bloque::Rien, false) => ms,
    }
}

/// Menu Optimiser › DNS le plus rapide, ou `gardien dns-rapide`.
pub fn mesurer_et_proposer() {
    titre(tr!("DNS le plus rapide", "Fastest DNS"));
    for ligne in envelopper(
        tr!(
            "Chaque visite de site commence par une question au DNS. Gardien mesure ici le DNS actuel et quatre DNS publics, en douze questions chacun. Un DNS qui te protège est gardé, même plus lent.",
            "Every site visit starts with a question to the DNS. Gardien measures the current DNS and four public ones here, twelve questions each. A DNS that protects you is kept, even if slower."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    let Some(actuel) = crate::machine::dns::actuel() else {
        trp!(
            "\n  ✖ Configuration DNS illisible sur cet ordinateur.",
            "\n  ✖ DNS configuration unreadable on this computer."
        );
        return;
    };
    let passerelle = crate::scan::passerelle().map(IpAddr::V4);
    let garde = protection(&actuel, passerelle);
    let mut a_mesurer: Vec<IpAddr> = Vec::new();
    for (ip, _) in &actuel.serveurs {
        if a_mesurer.len() < 2 && !a_mesurer.contains(ip) {
            a_mesurer.push(*ip);
        }
    }
    trp!("\n  {GRIS}Mesure en cours…{RESET}", "\n  {GRIS}Measuring…{RESET}");
    let (temps_actuels, temps_publics): (Vec<Option<Duration>>, Vec<Option<Duration>>) = std::thread::scope(|s| {
        let actuels: Vec<_> = a_mesurer.iter().map(|ip| s.spawn(move || mesurer(*ip))).collect();
        let publics: Vec<_> = PUBLICS
            .iter()
            .map(|p| s.spawn(move || p.v4[0].parse().ok().and_then(mesurer)))
            .collect();
        (
            actuels.into_iter().map(|f| f.join().ok().flatten()).collect(),
            publics.into_iter().map(|f| f.join().ok().flatten()).collect(),
        )
    });
    let actuel_ms = temps_actuels.iter().flatten().min().copied();
    let meilleur = temps_publics
        .iter()
        .enumerate()
        .filter_map(|(i, t)| Some((i, (*t)?)))
        .min_by_key(|(_, t)| *t);

    let mut lignes = vec![Ligne::Texte(String::new())];
    for (ip, t) in a_mesurer.iter().zip(&temps_actuels) {
        lignes.push(Ligne::Texte(format!(
            "  {GRIS}{}{RESET} {} {GRIS}{}{RESET}",
            ajuster(tr!("Actuel", "Current"), 8),
            ajuster(&format!("{} ({ip})", nom_actuel(*ip, &actuel, passerelle)), 44),
            millisecondes(*t)
        )));
    }
    if a_mesurer.is_empty() {
        lignes.push(Ligne::Texte(format!(
            "  {GRIS}{}{RESET}",
            tr!("Aucun serveur DNS configuré.", "No DNS server configured.")
        )));
    }
    if let Some(raison) = &garde {
        for (i, ligne) in envelopper(&trf!("Gardé : {raison}", "Kept: {raison}"), LARGEUR - 4)
            .into_iter()
            .enumerate()
        {
            lignes.push(Ligne::Texte(format!(
                "  {}{ligne}",
                if i == 0 {
                    format!("{VERT}✔{RESET} ")
                } else {
                    "  ".into()
                }
            )));
        }
    }
    lignes.push(Ligne::Texte(String::new()));
    let proposer = garde.is_none() && vaut_la_peine(actuel_ms, meilleur.map(|(_, t)| t));
    // Gardé : les DNS publics sont montrés pour information, sans rien proposer.
    for (i, (p, t)) in PUBLICS.iter().zip(&temps_publics).enumerate() {
        let texte = format!("{} ({})", p.nom, p.v4[0]);
        let plus_rapide = meilleur.is_some_and(|(m, _)| m == i);
        let precision = precision(p, *t, plus_rapide);
        lignes.push(if garde.is_none() && t.is_some() {
            Ligne::choix(&(i + 1).to_string(), &texte, &precision)
        } else {
            Ligne::Texte(format!("     {}  {GRIS}{precision}{RESET}", ajuster(&texte, 34)))
        });
    }
    lignes.push(Ligne::Texte(String::new()));
    let change = crate::optimiser::dns_change();
    if let Some((date, _)) = &change {
        lignes.push(Ligne::choix(
            "r",
            tr!("Remettre le DNS d'avant Gardien", "Restore the DNS from before Gardien"),
            &trf!("changé le {date}", "changed on {date}"),
        ));
    }
    let conclusion = match (&garde, meilleur) {
        (Some(_), _) => None,
        (None, None) => Some(tr!(
            "Les DNS publics ne répondent pas d'ici (UDP 53 bloqué par le réseau ?) : rien à comparer.",
            "Public DNS servers do not answer from here (UDP 53 blocked by the network?): nothing to compare."
        )),
        (None, Some(_)) if proposer => Some(tr!(
            "Un DNS public répond nettement plus vite : choisis-le, ou garde l'actuel.",
            "A public DNS answers clearly faster: choose it, or keep the current one."
        )),
        (None, Some(_)) => Some(tr!(
            "Ton DNS actuel est déjà rapide : changer ne ferait presque rien gagner.",
            "Your current DNS is already fast: switching would gain almost nothing."
        )),
    };
    if let Some(c) = conclusion {
        for l in envelopper(c, LARGEUR - 2) {
            lignes.push(Ligne::Texte(format!("  {l}")));
        }
    }
    let selection = garde.is_none() && meilleur.is_some();
    if !selection && change.is_none() {
        for l in &lignes {
            if let Ligne::Texte(t) = l {
                println!("{t}");
            }
        }
        return;
    }
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix(
        "↵",
        tr!("Garder le DNS actuel", "Keep the current DNS"),
        "",
    ));
    lignes.push(Ligne::Texte(String::new()));
    let depart = match meilleur {
        Some((i, _)) if proposer => (i + 1).to_string(),
        _ => "↵".to_string(),
    };
    let choix = choisir(
        &lignes,
        tr!("Choix (Entrée pour garder) : ", "Choice (Enter to keep): "),
        &depart,
        tr!("garder", "keep"),
    )
    .unwrap_or_default();
    if choix.eq_ignore_ascii_case("r") && change.is_some() {
        crate::optimiser::remettre_dns();
        return;
    }
    let Some(p) = choix
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|i| PUBLICS.get(i).filter(|_| temps_publics[i].is_some() && garde.is_none()))
    else {
        trp!("  DNS gardé.", "  DNS kept.");
        return;
    };
    if p.bloque == Bloque::Publicites {
        afficher_aligne(
            "  ⚠ ",
            tr!(
                "AdGuard DNS bloque publicités et pisteurs : quelques sites ou liens d'achat peuvent ne plus s'ouvrir.",
                "AdGuard DNS blocks ads and trackers: a few sites or shopping links may stop opening."
            ),
            4,
            "",
        );
    }
    if let Err(e) = crate::optimiser::appliquer_dns(&p.v4, &p.v6) {
        afficher_aligne("  ✖ ", &e, 4, "");
        afficher_aligne(
            "    ",
            &trf!(
                "À régler à la main : {} et {} (IPv6 : {} et {}).",
                "To set by hand: {} and {} (IPv6: {} and {}).",
                p.v4[0],
                p.v4[1],
                p.v6[0],
                p.v6[1]
            ),
            4,
            GRIS,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn questions_et_reponses() {
        let q = question(0x1234, "www.example.org");
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(q.len(), 12 + 17 + 4);
        assert!(q.ends_with(&[3, b'o', b'r', b'g', 0, 0, 1, 0, 1]));
        let mut r = q.clone();
        r[2] |= 0x80;
        assert!(repond(&r, 0x1234));
        assert!(!repond(&q, 0x1234), "une question n'est pas une réponse");
        assert!(!repond(&r, 0x1235), "autre identifiant");
        r[3] = (r[3] & 0xf0) | 3;
        assert!(repond(&r, 0x1234), "« ce nom n'existe pas » est une réponse");
        r[3] = (r[3] & 0xf0) | 5;
        assert!(!repond(&r, 0x1234), "un refus n'en est pas une");
        assert!(!repond(&r[..8], 0x1234));
    }

    #[test]
    fn mediane_et_seuil() {
        let ms = Duration::from_millis;
        assert_eq!(mediane(vec![ms(30), ms(10), ms(20)]), Some(ms(20)));
        assert_eq!(mediane(Vec::new()), None);
        assert!(vaut_la_peine(Some(ms(40)), Some(ms(20))));
        assert!(!vaut_la_peine(Some(ms(12)), Some(ms(10))), "moins d'un cinquième");
        assert!(!vaut_la_peine(Some(ms(6)), Some(ms(3))), "moins de 5 ms");
        assert!(vaut_la_peine(None, Some(ms(20))), "l'actuel ne répond plus");
        assert!(!vaut_la_peine(Some(ms(20)), None));
    }

    fn actuel(serveurs: &[&str], local: Option<&'static str>, chiffre: Option<bool>) -> Actuel {
        Actuel {
            serveurs: serveurs.iter().map(|s| (s.parse().unwrap(), false)).collect(),
            chiffre,
            resolveur_local: local,
        }
    }

    #[test]
    fn dns_qui_protegent_gardes() {
        let box_ = Some("10.0.0.1".parse().unwrap());
        // La box (et sa propre adresse IPv6 locale), un fournisseur, Google, Cloudflare : remplaçables.
        for s in [
            &["10.0.0.1", "fe80::1"][..],
            &["203.0.113.53"],
            &["8.8.8.8"],
            &["1.1.1.1"],
        ] {
            assert_eq!(protection(&actuel(s, None, None), box_), None, "{s:?}");
        }
        // NextDNS sur cet ordinateur, un résolveur local inconnu, du chiffré, un DNS filtrant, un Pi-hole : gardés.
        assert!(protection(&actuel(&["127.0.0.1"], Some("NextDNS"), Some(true)), box_).is_some());
        assert!(protection(&actuel(&["127.0.0.1"], None, None), box_).is_some());
        assert!(protection(&actuel(&["10.0.0.1"], None, Some(true)), box_).is_some());
        for s in ["9.9.9.9", "45.90.28.1", "94.140.14.14", "1.1.1.3", "100.100.100.100"] {
            assert!(protection(&actuel(&[s], None, None), box_).is_some(), "{s}");
        }
        assert!(protection(&actuel(&["10.0.0.53"], None, None), box_).is_some());
        assert_eq!(
            nom_actuel("10.0.0.1".parse().unwrap(), &actuel(&[], None, None), box_),
            tr!("ta box", "your router")
        );
    }

    #[test]
    fn precisions_du_menu_courtes() {
        for p in &PUBLICS {
            for t in [None, Some(Duration::from_millis(1499))] {
                for plus_rapide in [false, true] {
                    let texte = precision(p, t, plus_rapide);
                    assert!(largeur_affichee(&texte) <= 33, "{texte}");
                }
            }
        }
        // Les adresses proposées sont toutes valides.
        for p in &PUBLICS {
            for a in p.v4.iter().chain(&p.v6) {
                assert!(a.parse::<IpAddr>().is_ok(), "{a}");
            }
        }
    }
}
