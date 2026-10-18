//! Ports ouverts vers Internet par UPnP : les redirections que des appareils du réseau (console, caméra,
//! objet connecté…) ont demandées à la box, sans que personne ne les voie. Lecture seule, par les outils
//! standard : `upnpc -l` (miniupnpc) sous Linux, l'interface UPnP de Windows sous Windows.

use serde::Serialize;

use crate::risk::{Niveau, info_port};
use crate::ui::*;

/// Une redirection de la box : port public → appareil du réseau.
#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct Redirection {
    pub protocole: String,
    pub port_public: u16,
    pub appareil: String,
    pub port_appareil: u16,
    pub description: String,
}

/// Ce qu'on sait de l'UPnP de la box.
#[derive(Serialize, Debug, PartialEq)]
pub enum Etat {
    /// Aucune box UPnP trouvée : UPnP coupé (le mieux) ou absent.
    Absent,
    /// UPnP actif, avec ses redirections (peut-être aucune).
    Actif(Vec<Redirection>),
    /// L'outil de lecture manque (Linux sans miniupnpc).
    OutilAbsent,
}

/// Lignes de `upnpc -l` : « 0 UDP  3074->10.0.0.20:3074  'Xbox' '' 0 ». N'importe quel appareil du réseau peut
/// demander une redirection, avec l'adresse et la description de son choix : lues prêtes à montrer (`affichable`).
#[cfg_attr(windows, allow(dead_code))]
fn lire_upnpc(sortie: &str) -> Etat {
    if sortie.contains("No IGD UPnP Device") || sortie.contains("No valid UPNP Internet Gateway Device") {
        return Etat::Absent;
    }
    let mut liste = Vec::new();
    for l in sortie.lines() {
        let c: Vec<&str> = l.split_whitespace().collect();
        let [_, proto, redirection, ..] = c[..] else { continue };
        if proto != "TCP" && proto != "UDP" {
            continue;
        }
        let Some((public, interne)) = redirection.split_once("->") else {
            continue;
        };
        let Some((ip, port)) = interne.rsplit_once(':') else {
            continue;
        };
        let (Ok(public), Ok(port)) = (public.parse(), port.parse()) else {
            continue;
        };
        let description = affichable(l.split('\'').nth(1).unwrap_or(""));
        liste.push(Redirection {
            protocole: proto.to_string(),
            port_public: public,
            appareil: affichable(ip),
            port_appareil: port,
            description,
        });
    }
    Etat::Actif(liste)
}

#[cfg(unix)]
pub fn etat() -> Etat {
    etat_et_adresse().0
}

/// L'état de l'UPnP, et l'adresse que la box dit avoir sur Internet (« ExternalIPAddress = 203.0.113.7 » dans
/// `upnpc -l`) : une adresse privée ou partagée (100.64.0.0/10) y trahit un double NAT ou le partage d'adresses du
/// fournisseur (CGNAT).
#[cfg(unix)]
pub fn etat_et_adresse() -> (Etat, Option<std::net::Ipv4Addr>) {
    let Some(r) = crate::commande::lancer(std::process::Command::new("upnpc").arg("-l"), 20) else {
        return (Etat::OutilAbsent, None);
    };
    let texte = format!("{}\n{}", r.sortie, r.erreurs);
    (lire_upnpc(&texte), adresse_externe(&texte))
}

/// L'interface UPnP de Windows ne donne pas l'adresse de la box sur Internet.
#[cfg(windows)]
pub fn etat_et_adresse() -> (Etat, Option<std::net::Ipv4Addr>) {
    (etat(), None)
}

#[cfg_attr(windows, allow(dead_code))]
fn adresse_externe(texte: &str) -> Option<std::net::Ipv4Addr> {
    texte.lines().find_map(|l| {
        l.trim()
            .strip_prefix("ExternalIPAddress")?
            .trim_start()
            .strip_prefix('=')?
            .trim()
            .parse()
            .ok()
    })
}

/// Interface UPnP de Windows (HNetCfg.NATUPnP) : vide quand la box n'a pas d'UPnP ou l'a coupé.
#[cfg(windows)]
pub fn etat() -> Etat {
    let Some(sortie) = crate::machine::windows::ps(
        "$c = (New-Object -ComObject HNetCfg.NATUPnP).StaticPortMappingCollection; \
         if ($null -eq $c) { 'UPNP_ABSENT' } else { 'UPNP_ACTIF'; $c | ForEach-Object { \
         \"UPNP|$($_.Protocol)|$($_.ExternalPort)|$($_.InternalClient)|$($_.InternalPort)|$($_.Description)\" } }",
    ) else {
        return Etat::OutilAbsent;
    };
    lire_upnp_windows(&sortie)
}

/// Sortie de l'interface UPnP de Windows : « UPNP_ABSENT », ou « UPNP_ACTIF » puis une ligne
/// « UPNP|protocole|port public|appareil|port|description » par redirection, lue comme celles de upnpc.
#[cfg_attr(not(windows), allow(dead_code))]
fn lire_upnp_windows(sortie: &str) -> Etat {
    if sortie.contains("UPNP_ABSENT") {
        return Etat::Absent;
    }
    Etat::Actif(
        sortie
            .lines()
            .filter_map(|l| l.trim().strip_prefix("UPNP|"))
            .filter_map(|l| {
                let c: Vec<&str> = l.splitn(5, '|').collect();
                let [proto, public, ip, port, description] = c[..] else {
                    return None;
                };
                Some(Redirection {
                    protocole: affichable(proto),
                    port_public: public.parse().ok()?,
                    appareil: affichable(ip),
                    port_appareil: port.parse().ok()?,
                    description: affichable(description),
                })
            })
            .collect(),
    )
}

#[cfg(target_os = "linux")]
fn outil_upnp() -> String {
    crate::machine::linux::commande_installation("miniupnpc")
}

#[cfg(target_os = "macos")]
fn outil_upnp() -> String {
    crate::machine::macos::commande_installation("miniupnpc")
}

/// Sous Windows, l'interface UPnP fait partie du système : seul PowerShell bloqué l'empêche de répondre.
#[cfg(windows)]
fn outil_upnp() -> String {
    tr!(
        "PowerShell est bloqué sur ce poste.",
        "PowerShell is blocked on this computer."
    )
    .to_string()
}

/// Niveau d'une redirection : celui du service exposé (bureau à distance, partage, SSH… = élevé).
pub fn niveau(r: &Redirection) -> Niveau {
    info_port(r.port_appareil).niveau
}

/// Section du scan réseau.
pub fn afficher(e: &Etat) {
    section(tr!(
        "PORTS OUVERTS VERS INTERNET (UPnP)",
        "PORTS OPEN TO THE INTERNET (UPnP)"
    ));
    match e {
        Etat::Absent => afficher_aligne(
            &format!("  {VERT}✔{RESET} "),
            tr!(
                "UPnP coupé ou absent sur la box : aucun appareil ne peut ouvrir de port vers Internet tout seul.",
                "UPnP off or absent on the router: no device can open a port to the Internet by itself."
            ),
            4,
            "",
        ),
        Etat::OutilAbsent => afficher_aligne(
            "  ",
            &trf!(
                "Pour voir les ports que tes appareils ont ouverts sur la box : {}",
                "To see the ports your devices opened on the router: {}",
                outil_upnp()
            ),
            2,
            DISCRET,
        ),
        Etat::Actif(liste) if liste.is_empty() => afficher_aligne(
            "  ",
            tr!(
                "UPnP actif sur la box, aucun port ouvert pour l'instant. À couper dans la box si aucun appareil n'en a besoin.",
                "UPnP on at the router, no port open for now. Turn it off in the router if no device needs it."
            ),
            2,
            GRIS,
        ),
        Etat::Actif(liste) => {
            for r in liste {
                let n = niveau(r);
                let description = if r.description.is_empty() {
                    String::new()
                } else {
                    format!("  {DISCRET}« {} »{RESET}", r.description)
                };
                println!(
                    "  {}●{RESET} {:>5}/{} → {}:{}  {}{}{RESET}{description}",
                    couleur(n),
                    r.port_public,
                    r.protocole.to_lowercase(),
                    r.appareil,
                    r.port_appareil,
                    couleur(n),
                    n.libelle()
                );
            }
            afficher_aligne(
                "  ",
                tr!(
                    "Chaque ligne rend un appareil joignable depuis Internet. Si tu n'en as pas besoin, coupe UPnP dans la box.",
                    "Each line makes a device reachable from the Internet. If you do not need it, turn UPnP off in the router."
                ),
                2,
                DISCRET,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lecture_de_upnpc() {
        assert_eq!(lire_upnpc("No IGD UPnP Device found on the network !\n"), Etat::Absent);
        let sortie = "Found valid IGD : http://10.0.0.1:5000/ctl\n i protocol exPort->inAddr:inPort description remoteHost leaseTime\n 0 UDP  3074->10.0.0.20:3074  'Xbox SRA' '' 0\n 1 TCP  8080->10.0.0.30:80  'Camera' '' 3600\nGetGenericPortMappingEntry() returned 713 (SpecifiedArrayIndexInvalid)\n";
        let Etat::Actif(l) = lire_upnpc(sortie) else {
            panic!("UPnP actif attendu")
        };
        assert_eq!(l.len(), 2);
        assert_eq!(
            (l[1].port_public, l[1].appareil.as_str(), l[1].port_appareil),
            (8080, "10.0.0.30", 80)
        );
        assert_eq!(l[0].description, "Xbox SRA");
        assert_eq!(niveau(&l[1]), info_port(80).niveau);
    }

    /// N'importe quel appareil du réseau peut demander une redirection à la box, avec la description de son choix :
    /// piégée, elle arrive inoffensive, « � » à la place de chaque caractère piégé.
    #[test]
    fn description_piegee() {
        let sortie = " 0 TCP  8080->10.0.0.30:80  'Cam\x1b]52;c;eA==\x07\x1b[2K\rFaux\u{202e}' '' 0\n";
        let Etat::Actif(l) = lire_upnpc(sortie) else {
            panic!("UPnP actif attendu")
        };
        assert_eq!(l[0].description, "Cam�]52;c;eA==��[2K�Faux�");
        assert_eq!((l[0].protocole.as_str(), l[0].appareil.as_str()), ("TCP", "10.0.0.30"));
        // L'interface UPnP de Windows : la même lecture.
        assert_eq!(lire_upnp_windows("UPNP_ABSENT\n"), Etat::Absent);
        let windows = "UPNP_ACTIF\nUPNP|TCP|8080|10.0.0.30|80|Cam\x1b]52;c;eA==\x07\x1b[2K\rFaux\u{202e}\nUPNP|UDP|3074|10.0.0.20|3074|Xbox SRA\n";
        let Etat::Actif(l) = lire_upnp_windows(windows) else {
            panic!("UPnP actif attendu")
        };
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].description, "Cam�]52;c;eA==��[2K�Faux�");
        assert_eq!(
            l[1],
            Redirection {
                protocole: "UDP".into(),
                port_public: 3074,
                appareil: "10.0.0.20".into(),
                port_appareil: 3074,
                description: "Xbox SRA".into(),
            }
        );
    }

    #[test]
    fn adresse_de_la_box_sur_internet() {
        let sortie = "Found valid IGD : http://10.0.0.1:5000/ctl\nLocal LAN ip address : 10.0.0.20\n\
                      Connection Type : IP_Routed\nExternalIPAddress = 100.64.12.34\n";
        assert_eq!(adresse_externe(sortie), Some(std::net::Ipv4Addr::new(100, 64, 12, 34)));
        assert_eq!(adresse_externe("No IGD UPnP Device found on the network !\n"), None);
    }
}
