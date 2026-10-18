//! Adresse Internet sur liste noire : si l'adresse publique de la maison est listée pour pourriel, attaques ou
//! réseau de zombies (botnet), un appareil de la maison est sans doute infecté. Quatre listes publiques interrogées
//! par le DNS (Spamhaus, SpamCop, DroneBL, PSBL), après accord : elles voient l'adresse.
//!
//! Chaque liste est d'abord sondée avec son adresse d'essai (127.0.0.2, toujours listée) : si l'essai ne répond pas
//! ou si la liste refuse le DNS utilisé (Spamhaus refuse les résolveurs publics), c'est dit, jamais compté comme
//! « pas listée ».

use std::net::{Ipv4Addr, ToSocketAddrs};

use crate::risk::Niveau;
use crate::ui::*;

struct Liste {
    nom: &'static str,
    zone: &'static str,
}

const LISTES: [Liste; 4] = [
    Liste {
        nom: "Spamhaus",
        zone: "zen.spamhaus.org",
    },
    Liste {
        nom: "SpamCop",
        zone: "bl.spamcop.net",
    },
    Liste {
        nom: "DroneBL",
        zone: "dnsbl.dronebl.org",
    },
    Liste {
        nom: "PSBL",
        zone: "psbl.surriel.com",
    },
];

#[derive(Debug, PartialEq)]
enum Verdict {
    /// Listée, avec les codes de réponse (127.0.0.x : la raison).
    Listee(Vec<Ipv4Addr>),
    Absente,
    Impossible(String),
}

/// Spamhaus répond 127.255.255.x pour refuser : résolveur public (254), nom mal écrit (252), trop de requêtes (255).
fn refus(codes: &[Ipv4Addr]) -> bool {
    codes.iter().any(|c| c.octets()[..3] == [127, 255, 255])
}

/// Adresses IPv4 d'un nom, par le DNS du système. Vide si le nom n'existe pas (adresse absente de la liste).
fn resoudre(nom: &str) -> Vec<Ipv4Addr> {
    (nom, 0)
        .to_socket_addrs()
        .map(|adresses| {
            adresses
                .filter_map(|a| match a.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(_) => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Nom à demander pour une adresse : ses quatre nombres à l'envers, puis la zone de la liste.
fn requete(ip: Ipv4Addr, zone: &str) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.{zone}")
}

fn chercher_avec(ip: Ipv4Addr, zone: &str, resoudre: impl Fn(&str) -> Vec<Ipv4Addr>) -> Verdict {
    let essai = resoudre(&requete(Ipv4Addr::new(127, 0, 0, 2), zone));
    if essai.is_empty() {
        // Certains DNS (filtres, protection contre le « DNS rebinding ») retirent les réponses en 127.x de certaines
        // listes : la vraie réponse serait retirée de même, et « absente » serait un mensonge.
        return Verdict::Impossible(
            tr!(
                "ton DNS ne transmet pas les réponses de cette liste",
                "your DNS does not pass this list's answers on"
            )
            .into(),
        );
    }
    if refus(&essai) {
        return Verdict::Impossible(
            tr!(
                "la liste refuse ton DNS (résolveur public)",
                "the list refuses your DNS (public resolver)"
            )
            .into(),
        );
    }
    let codes = resoudre(&requete(ip, zone));
    if refus(&codes) {
        Verdict::Impossible(tr!("la liste a refusé la requête", "the list refused the query").into())
    } else if codes.is_empty() {
        Verdict::Absente
    } else {
        Verdict::Listee(codes)
    }
}

/// Ce que dit une inscription, et sa gravité. La PBL de Spamhaus (127.0.0.10 et 11) liste toutes les adresses
/// résidentielles, qui n'envoient pas de courriel elles-mêmes : normal, pas un signe d'infection.
fn sens(zone: &str, codes: &[Ipv4Addr]) -> (String, Option<Niveau>) {
    let derniers: Vec<u8> = codes.iter().map(|c| c.octets()[3]).collect();
    if zone.starts_with("zen.") {
        if derniers.iter().any(|&c| (4..=7).contains(&c)) {
            return (
                tr!(
                    "XBL : un appareil de la maison est infecté (réseau de zombies, logiciel qui envoie du pourriel)",
                    "XBL: a device in the house is infected (botnet, malware sending spam)"
                )
                .into(),
                Some(Niveau::Eleve),
            );
        }
        if derniers.iter().any(|&c| c == 2 || c == 3 || c == 9) {
            return (
                tr!(
                    "SBL : adresse connue pour envoyer du pourriel",
                    "SBL: address known for sending spam"
                )
                .into(),
                Some(Niveau::Eleve),
            );
        }
        return (
            tr!(
                "PBL : adresse résidentielle, normal (rien n'est envoyé directement depuis chez toi)",
                "PBL: residential address, normal (nothing is sent directly from your home)"
            )
            .into(),
            None,
        );
    }
    if zone.starts_with("dnsbl.dronebl") {
        return (
            tr!(
                "un appareil de la maison attaque d'autres ordinateurs ou sert de relais (zombie, proxy ouvert)",
                "a device in the house attacks other computers or serves as a relay (zombie, open proxy)"
            )
            .into(),
            Some(Niveau::Eleve),
        );
    }
    (
        tr!(
            "du pourriel est parti de cette adresse récemment",
            "spam was sent from this address recently"
        )
        .into(),
        Some(Niveau::Moyen),
    )
}

/// Adresse publique IPv4 de la maison, vue par Cloudflare (qui la voit de toute façon) : « ip=203.0.113.7 ».
fn adresse_publique() -> Option<Ipv4Addr> {
    let r = crate::commande::lancer(
        std::process::Command::new("curl").args(["-4", "-s", "--max-time", "8", "https://1.1.1.1/cdn-cgi/trace"]),
        12,
    )?;
    lire_trace(&r.sortie)
}

fn lire_trace(trace: &str) -> Option<Ipv4Addr> {
    trace.lines().find_map(|l| l.strip_prefix("ip=")?.trim().parse().ok())
}

/// Menu Réseau et Internet › Liste noire : après accord, cherche l'adresse publique dans les quatre listes.
pub fn verifier() {
    titre(tr!(
        "Adresse Internet sur liste noire ?",
        "Internet address on blocklists?"
    ));
    for ligne in envelopper(
        tr!(
            "Si l'adresse Internet de ta maison est sur une liste noire pour pourriel ou attaques, un de tes appareils est sans doute infecté. Gardien demande ton adresse à Cloudflare, puis la cherche dans quatre listes publiques (Spamhaus, SpamCop, DroneBL, PSBL) : elles verront ton adresse.",
            "If your home's Internet address is on a blocklist for spam or attacks, one of your devices is probably infected. Gardien asks Cloudflare for your address, then looks it up in four public lists (Spamhaus, SpamCop, DroneBL, PSBL): they will see your address."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    if !demander(tr!("\n  Continuer ? [o/N] : ", "\n  Continue? [y/N]: ")).oui() {
        trp!("  Rien n'a été envoyé.", "  Nothing was sent.");
        return;
    }
    let Some(ip) = adresse_publique() else {
        trp!(
            "  ✖ Adresse publique introuvable (pas d'Internet, ou curl absent).",
            "  ✖ Public address not found (no Internet, or curl missing)."
        );
        return;
    };
    trp!("\n  Adresse publique : {ip}\n", "\n  Public address: {ip}\n");
    let reponses: Vec<Verdict> = std::thread::scope(|s| {
        let fils: Vec<_> = LISTES
            .iter()
            .map(|l| s.spawn(move || chercher_avec(ip, l.zone, resoudre)))
            .collect();
        fils.into_iter()
            .map(|f| {
                f.join()
                    .unwrap_or(Verdict::Impossible(tr!("erreur interne", "internal error").into()))
            })
            .collect()
    });
    let mut pire: Option<Niveau> = None;
    let mut verifiees = 0;
    for (liste, reponse) in LISTES.iter().zip(&reponses) {
        let (marque, texte) = match reponse {
            Verdict::Absente => {
                verifiees += 1;
                (format!("{VERT}✔{RESET}"), tr!("pas listée", "not listed").to_string())
            }
            Verdict::Listee(codes) => {
                verifiees += 1;
                let (texte, niveau) = sens(liste.zone, codes);
                pire = pire.max(niveau);
                let marque = niveau.map_or_else(|| format!("{GRIS}ℹ{RESET}"), |n| format!("{}✖{RESET}", couleur(n)));
                (marque, texte)
            }
            Verdict::Impossible(raison) => (
                format!("{GRIS}?{RESET}"),
                trf!("impossible à vérifier : {raison}", "could not check: {raison}"),
            ),
        };
        afficher_aligne(&format!("  {marque} {} ", ajuster(liste.nom, 10)), &texte, 15, "");
    }
    println!();
    let conclusion = match (pire, verifiees) {
        (Some(_), _) => tr!(
            "Analyse chaque ordinateur de la maison (antivirus de Gardien), mets à jour les téléphones, les objets connectés et la box, change le mot de passe de la box et coupe UPnP si tu n'en as pas besoin. Si ton fournisseur partage ton adresse avec d'autres abonnés, la liste peut viser un voisin : la question vaut alors la peine d'être posée au fournisseur.",
            "Scan every computer in the house (Gardien's antivirus), update phones, connected devices and the router, change the router's password and turn UPnP off if you do not need it. If your provider shares your address with other customers, the listing may target a neighbor: worth asking the provider."
        ),
        (None, 0) => tr!(
            "Aucune liste n'a pu être interrogée : rien n'est conclu.",
            "No list could be queried: nothing is concluded."
        ),
        (None, _) => tr!(
            "Ton adresse n'est sur aucune liste noire interrogée : rien n'indique un appareil infecté.",
            "Your address is on none of the blocklists queried: nothing points to an infected device."
        ),
    };
    for ligne in envelopper(conclusion, LARGEUR - 2) {
        println!("  {ligne}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(t: &str) -> Ipv4Addr {
        t.parse().unwrap()
    }

    #[test]
    fn requete_a_l_envers() {
        assert_eq!(
            requete(ip("203.0.113.7"), "zen.spamhaus.org"),
            "7.113.0.203.zen.spamhaus.org"
        );
    }

    #[test]
    fn essai_puis_adresse() {
        // La liste répond à l'essai ; l'adresse n'y est pas.
        let liste = |nom: &str| {
            if nom.starts_with("2.0.0.127.") {
                vec![ip("127.0.0.2")]
            } else {
                vec![]
            }
        };
        assert_eq!(
            chercher_avec(ip("203.0.113.7"), "bl.spamcop.net", liste),
            Verdict::Absente
        );
        // L'adresse y est.
        let liste = |_: &str| vec![ip("127.0.0.2")];
        assert_eq!(
            chercher_avec(ip("203.0.113.7"), "bl.spamcop.net", liste),
            Verdict::Listee(vec![ip("127.0.0.2")])
        );
        // Résolveur public refusé par Spamhaus : impossible, jamais « absente ».
        let public = |_: &str| vec![ip("127.255.255.254")];
        assert!(matches!(
            chercher_avec(ip("203.0.113.7"), "zen.spamhaus.org", public),
            Verdict::Impossible(_)
        ));
        // Liste muette : impossible aussi.
        assert!(matches!(
            chercher_avec(ip("203.0.113.7"), "psbl.surriel.com", |_: &str| vec![]),
            Verdict::Impossible(_)
        ));
    }

    #[test]
    fn sens_des_codes() {
        // PBL seule : adresse résidentielle, pas une alerte.
        assert_eq!(sens("zen.spamhaus.org", &[ip("127.0.0.11")]).1, None);
        assert_eq!(
            sens("zen.spamhaus.org", &[ip("127.0.0.10"), ip("127.0.0.4")]).1,
            Some(Niveau::Eleve)
        );
        assert_eq!(sens("zen.spamhaus.org", &[ip("127.0.0.2")]).1, Some(Niveau::Eleve));
        assert_eq!(sens("dnsbl.dronebl.org", &[ip("127.0.0.17")]).1, Some(Niveau::Eleve));
        assert_eq!(sens("bl.spamcop.net", &[ip("127.0.0.2")]).1, Some(Niveau::Moyen));
    }

    #[test]
    fn trace_de_cloudflare() {
        let trace = "fl=123\nh=1.1.1.1\nip=203.0.113.7\nts=1792300000\nvisit_scheme=https\n";
        assert_eq!(lire_trace(trace), Some(ip("203.0.113.7")));
        assert_eq!(lire_trace("ip=2001:db8::1\n"), None);
    }
}
