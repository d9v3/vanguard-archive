//! Parcours « Pas d'Internet » et « Le Wi-Fi coupe » : où la connexion s'arrête (cet ordinateur, la box, Internet,
//! les noms de sites), lu par des essais qui ne changent rien : une adresse sur le réseau, la box qui répond, trois
//! serveurs d'Internet joignables (Cloudflare, Quad9, Google), deux noms de sites traduits en adresses.

use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use super::{Etat, conseil, proposer_outil, proposer_reparation, question, verifications};
use crate::ui::*;

pub(super) fn titre_internet() -> &'static str {
    tr!("Internet ne marche plus", "Internet no longer works")
}

pub(super) fn titre_navigation() -> &'static str {
    tr!(
        "Navigation détournée (proxy, fichier hosts)",
        "Hijacked browsing (proxy, hosts file)"
    )
}

/// L'adresse de cet ordinateur sur le réseau local.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum Adresse {
    /// Relié à aucun réseau.
    #[default]
    Aucune,
    /// Seulement une adresse en 169.254.x.x : la box n'en a pas donné.
    Autoattribuee,
    Locale(Ipv4Addr),
}

/// Ce que les essais ont trouvé.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct EtatReseau {
    pub adresse: Adresse,
    pub passerelle: Option<Ipv4Addr>,
    pub passerelle_repond: bool,
    pub internet: bool,
    pub noms: bool,
}

/// Où la connexion s'arrête.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Panne {
    PasConnecte,
    PasDAdresse,
    BoxMuette,
    InternetCoupe,
    Noms,
    Aucune,
}

pub(super) fn panne(e: &EtatReseau) -> Panne {
    match e.adresse {
        Adresse::Aucune => return Panne::PasConnecte,
        Adresse::Autoattribuee => return Panne::PasDAdresse,
        Adresse::Locale(_) => {}
    }
    // Une box qui ne répond à aucun essai mais laisse passer Internet filtre simplement : ce n'est pas une panne.
    if !e.internet {
        return if e.passerelle.is_some() && e.passerelle_repond {
            Panne::InternetCoupe
        } else {
            Panne::BoxMuette
        };
    }
    if !e.noms {
        return Panne::Noms;
    }
    Panne::Aucune
}

pub(super) fn joignable(adresse: SocketAddr, delai: Duration) -> bool {
    match TcpStream::connect_timeout(&adresse, delai) {
        Ok(_) => true,
        // Refusé : l'appareil a répondu (aucun service sur ce port, mais il est là).
        Err(e) => e.kind() == std::io::ErrorKind::ConnectionRefused,
    }
}

/// Plusieurs essais en même temps : vrai dès que l'un réussit.
fn un_seul_suffit(adresses: &[SocketAddr], delai: Duration) -> bool {
    let (envoi, reception) = std::sync::mpsc::channel();
    for &a in adresses {
        let envoi = envoi.clone();
        std::thread::spawn(move || {
            let _ = envoi.send(joignable(a, delai));
        });
    }
    drop(envoi);
    reception.iter().any(|ok| ok)
}

/// Deux noms de sites traduits en adresses par le DNS du système, en six secondes au plus.
fn noms_resolus() -> bool {
    let (envoi, reception) = std::sync::mpsc::channel();
    for nom in ["www.wikipedia.org", "www.google.com"] {
        let envoi = envoi.clone();
        std::thread::spawn(move || {
            let _ = envoi.send((nom, 443).to_socket_addrs().is_ok_and(|mut a| a.next().is_some()));
        });
    }
    drop(envoi);
    let fin = Instant::now() + Duration::from_secs(6);
    while let Ok(ok) = reception.recv_timeout(fin.saturating_duration_since(Instant::now())) {
        if ok {
            return true;
        }
    }
    false
}

fn lire_etat() -> EtatReseau {
    let autoattribuee = || {
        if_addrs::get_if_addrs()
            .unwrap_or_default()
            .iter()
            .filter(|i| !i.is_loopback())
            .any(|i| matches!(&i.addr, if_addrs::IfAddr::V4(v4) if v4.ip.is_link_local()))
    };
    let adresse = match crate::scan::reseau_local() {
        Some((_, ip)) => Adresse::Locale(ip),
        None if autoattribuee() => Adresse::Autoattribuee,
        None => Adresse::Aucune,
    };
    let relie = matches!(adresse, Adresse::Locale(_));
    let passerelle = crate::scan::passerelle();
    let passerelle_repond = passerelle.is_some_and(|box_| {
        let ports: Vec<SocketAddr> = [80, 443, 53].iter().map(|&p| SocketAddr::from((box_, p))).collect();
        un_seul_suffit(&ports, Duration::from_millis(1500)) || crate::scan::table_arp().contains_key(&box_)
    });
    let serveurs: Vec<SocketAddr> = [[1, 1, 1, 1], [9, 9, 9, 9], [8, 8, 8, 8]]
        .iter()
        .map(|&ip| SocketAddr::from((Ipv4Addr::from(ip), 443)))
        .collect();
    EtatReseau {
        adresse,
        passerelle,
        passerelle_repond,
        internet: relie && un_seul_suffit(&serveurs, Duration::from_secs(3)),
        noms: relie && noms_resolus(),
    }
}

fn afficher_etat(e: &EtatReseau) {
    match e.adresse {
        Adresse::Locale(ip) => Etat::Bon.dire(&trf!(
            "Cet ordinateur a une adresse sur le réseau ({ip}).",
            "This computer has an address on the network ({ip})."
        )),
        Adresse::Autoattribuee => Etat::Mauvais.dire(tr!(
            "Adresse en 169.254.x.x : la box n'a pas donné d'adresse à cet ordinateur.",
            "Address in 169.254.x.x: the router gave no address to this computer."
        )),
        Adresse::Aucune => Etat::Mauvais.dire(tr!(
            "Cet ordinateur n'est relié à aucun réseau (câble débranché, Wi-Fi coupé, mode avion).",
            "This computer is connected to no network (cable unplugged, Wi-Fi off, airplane mode)."
        )),
    }
    if !matches!(e.adresse, Adresse::Locale(_)) {
        return;
    }
    match (e.passerelle, e.passerelle_repond) {
        (Some(b), true) => Etat::Bon.dire(&trf!("La box ({b}) répond.", "The router ({b}) answers.")),
        (Some(b), false) => (if e.internet { Etat::Info } else { Etat::Mauvais }).dire(&trf!(
            "La box ({b}) ne répond pas aux essais.",
            "The router ({b}) does not answer the tests."
        )),
        (None, _) => Etat::Mauvais.dire(tr!(
            "Aucune box (passerelle) n'est connue de cet ordinateur.",
            "No router (gateway) is known to this computer."
        )),
    }
    Etat::selon(e.internet).dire(if e.internet {
        tr!(
            "Internet répond (Cloudflare, Quad9 ou Google).",
            "The Internet answers (Cloudflare, Quad9 or Google)."
        )
    } else {
        tr!(
            "Internet ne répond pas (ni Cloudflare, ni Quad9, ni Google).",
            "The Internet does not answer (neither Cloudflare, Quad9 nor Google)."
        )
    });
    if e.internet {
        Etat::selon(e.noms).dire(if e.noms {
            tr!(
                "Les noms de sites se traduisent en adresses (DNS).",
                "Site names are translated into addresses (DNS)."
            )
        } else {
            tr!(
                "Les noms de sites ne se traduisent plus en adresses (DNS).",
                "Site names are no longer translated into addresses (DNS)."
            )
        });
    }
}

/// Le début des vérifications : les essais, puis ce qu'ils ont trouvé.
fn essais() -> EtatReseau {
    verifications();
    trp!(
        "  {DISCRET}Essais en cours (quelques secondes)…{RESET}",
        "  {DISCRET}Testing (a few seconds)…{RESET}"
    );
    let e = lire_etat();
    afficher_etat(&e);
    e
}

/// La navigation est-elle détournée (proxy imposé, fichier hosts) ? Lu par la réparation du même nom.
fn navigation_detournee() -> bool {
    crate::reparer::par_titre(titre_navigation()).is_some_and(|r| r.inutile.is_none())
}

/// Propose « Internet ne marche plus » ; sans elle sur ce système, le conseil qui la remplace.
fn reparer_le_reseau() {
    if !proposer_reparation(titre_internet()) {
        conseil(tr!(
            "Redémarre l'ordinateur : il refait toute la connexion au réseau.",
            "Restart the computer: it redoes the whole network connection."
        ));
    }
}

fn redemarrer_la_box() {
    conseil(tr!(
        "Redémarre la box : débranche-la 30 secondes, rebranche-la, attends que ses voyants soient stables (deux à trois minutes). Si un voyant reste rouge ou orange, le fournisseur d'accès a sans doute une panne : regarde son site ou son application sur ton téléphone, en données mobiles.",
        "Restart the router: unplug it for 30 seconds, plug it back in, wait until its lights are steady (two to three minutes). If a light stays red or orange, the Internet provider probably has an outage: check its website or app on your phone, using mobile data."
    ));
}

/// « Pas d'Internet ».
pub(super) fn internet() {
    let Some(qui) = question(
        tr!(
            "Le problème touche-t-il aussi les autres appareils de la maison (téléphone en Wi-Fi, télé…) ?",
            "Does the problem also affect the other devices at home (phone on Wi-Fi, TV…)?"
        ),
        &[
            tr!("Oui, tous les appareils", "Yes, all devices"),
            tr!("Non, seulement cet ordinateur", "No, only this computer"),
            tr!("Je ne sais pas", "I don't know"),
        ],
    ) else {
        return;
    };
    let Some(depuis) = question(
        tr!("Depuis quand ?", "Since when?"),
        &[
            tr!("Tout d'un coup", "All of a sudden"),
            tr!(
                "Depuis une mise à jour ou un nouveau programme",
                "Since an update or a new program"
            ),
            tr!("Ça va et ça vient", "It comes and goes"),
        ],
    ) else {
        return;
    };
    let e = essais();
    let detournee = e.internet && navigation_detournee();
    if e.internet {
        Etat::selon(!detournee).dire(if detournee {
            tr!(
                "Un proxy ou le fichier hosts détourne la navigation.",
                "A proxy or the hosts file hijacks browsing."
            )
        } else {
            tr!(
                "Navigation non détournée (ni proxy imposé, ni fichier hosts modifié).",
                "Browsing not hijacked (no forced proxy, no modified hosts file)."
            )
        });
    }
    section(tr!("CE QUE ÇA VEUT DIRE", "WHAT IT MEANS"));
    let tous = qui == 0;
    match panne(&e) {
        Panne::PasConnecte => {
            Etat::Info.dire(tr!(
                "Cet ordinateur n'est pas sur le réseau : rebranche le câble, ou rallume le Wi-Fi (touche ou bouton « avion ») et choisis ton réseau.",
                "This computer is not on the network: plug the cable back in, or turn Wi-Fi back on (airplane key or button) and choose your network."
            ));
            reparer_le_reseau();
        }
        Panne::PasDAdresse => {
            Etat::Info.dire(tr!(
                "La box ne donne plus d'adresse : souvent, elle est plantée.",
                "The router no longer gives addresses: often, it has crashed."
            ));
            redemarrer_la_box();
            reparer_le_reseau();
        }
        Panne::BoxMuette if tous => {
            Etat::Info.dire(tr!(
                "Rien ne passe par la box, pour aucun appareil : c'est la box.",
                "Nothing goes through the router, for any device: it is the router."
            ));
            redemarrer_la_box();
        }
        Panne::BoxMuette => {
            Etat::Info.dire(tr!(
                "Cet ordinateur ne joint pas la box.",
                "This computer cannot reach the router."
            ));
            reparer_le_reseau();
        }
        Panne::InternetCoupe if tous => {
            Etat::Info.dire(tr!(
                "La box répond, mais Internet ne passe pas : panne chez le fournisseur d'accès, ou box à redémarrer.",
                "The router answers, but the Internet does not get through: outage at the Internet provider, or router to restart."
            ));
            redemarrer_la_box();
        }
        Panne::InternetCoupe => {
            Etat::Info.dire(tr!(
                "La box répond, mais cet ordinateur ne sort pas sur Internet : un VPN, un pare-feu ou un proxy l'en empêche peut-être.",
                "The router answers, but this computer does not get out to the Internet: a VPN, a firewall or a proxy may prevent it."
            ));
            reparer_le_reseau();
        }
        Panne::Noms => {
            Etat::Info.dire(tr!(
                "Internet répond, mais les noms de sites ne se traduisent plus : le DNS est en panne ou mal réglé.",
                "The Internet answers, but site names are no longer translated: DNS is down or misconfigured."
            ));
            conseil(tr!(
                "Un DNS public (Cloudflare 1.1.1.1, Quad9 9.9.9.9) se règle dans la box, ou sur cet ordinateur.",
                "A public DNS (Cloudflare 1.1.1.1, Quad9 9.9.9.9) can be set in the router, or on this computer."
            ));
            reparer_le_reseau();
        }
        Panne::Aucune if detournee => {
            Etat::Info.dire(tr!(
                "Internet marche, mais la navigation est détournée : des sites ne s'ouvrent pas, ou pas les vrais.",
                "The Internet works, but browsing is hijacked: some sites do not open, or not the real ones."
            ));
            proposer_reparation(titre_navigation());
        }
        Panne::Aucune => {
            Etat::Bon.dire(tr!(
                "Internet marche depuis cet ordinateur, en ce moment.",
                "The Internet works from this computer, right now."
            ));
            conseil(tr!(
                "Si un site ne s'ouvre pas, essaie un autre navigateur : s'il s'ouvre, une extension ou le cache du premier est en cause. Si c'était passager, le test de connexion (Réseau et Internet) mesure les pertes et les coupures.",
                "If a site does not open, try another browser: if it opens, an extension or the cache of the first one is to blame. If it was temporary, the connection test (Network and Internet) measures losses and drops."
            ));
        }
    }
    if depuis == 1 {
        conseil(tr!(
            "Depuis un nouveau programme : un VPN, un antivirus ou un « optimiseur » coupe parfois Internet. Le désactiver un moment dit si c'est lui.",
            "Since a new program: a VPN, an antivirus or an “optimizer” sometimes cuts the Internet. Turning it off for a moment tells whether it is the culprit."
        ));
    }
    if depuis == 2 {
        conseil(tr!(
            "Coupures par moments : en Wi-Fi, le parcours « Le Wi-Fi coupe » regarde le signal ; le test de connexion mesure les pertes.",
            "Drops at times: on Wi-Fi, the “Wi-Fi keeps dropping” path looks at the signal; the connection test measures losses."
        ));
    }
}

/// Internet lent, depuis le parcours « L'ordinateur est lent » : la connexion marche-t-elle, puis où mesurer.
pub(super) fn internet_lent() {
    let e = essais();
    let s = signal();
    if let Some(s) = &s {
        afficher_signal(s);
    }
    section(tr!("CE QUE ÇA VEUT DIRE", "WHAT IT MEANS"));
    if panne(&e) == Panne::Aucune {
        conseil(tr!(
            "La connexion marche. Pour savoir si elle est lente, et pourquoi : le test de connexion (Réseau et Internet › Test de connexion) mesure le débit, le ping et le bufferbloat (la lenteur quand quelqu'un télécharge).",
            "The connection works. To know whether it is slow, and why: the connection test (Network and Internet › Connection test) measures speed, ping and bufferbloat (the slowness when someone downloads)."
        ));
        if s.is_some_and(|s| s.qualite < 60) {
            conseil(tr!(
                "Le signal Wi-Fi est moyen ou faible : il ralentit tout. Le parcours « Le Wi-Fi coupe » dit quoi faire.",
                "The Wi-Fi signal is average or weak: it slows everything down. The “Wi-Fi keeps dropping” path says what to do."
            ));
        }
    } else {
        conseil(tr!(
            "Ce n'est pas de la lenteur : la connexion a un vrai problème. Le parcours « Pas d'Internet » le trouve.",
            "This is not slowness: the connection has a real problem. The “No Internet” path finds it."
        ));
    }
}

/// Le Wi-Fi de la connexion en cours.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Signal {
    /// Qualité du signal, de 0 à 100.
    pub qualite: u8,
    pub canal: Option<u32>,
    /// Économie d'énergie de la carte Wi-Fi ; `None` : inconnue.
    pub economie: Option<bool>,
}

/// La bande d'un canal : 2,4 GHz jusqu'au canal 14, 5 GHz (ou 6 GHz) au-delà.
fn bande(canal: u32) -> &'static str {
    if canal <= 14 { "2,4 GHz" } else { "5 GHz" }
}

/// `nmcli -t -f IN-USE,SIGNAL,CHAN dev wifi list --rescan no` : la ligne du réseau en cours commence par « * ».
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn signal_nmcli(texte: &str) -> Option<Signal> {
    let ligne = texte.lines().find(|l| l.starts_with("*:"))?;
    let mut c = ligne.split(':').skip(1);
    let qualite = c.next()?.trim().parse().ok()?;
    Some(Signal {
        qualite,
        canal: c.next().and_then(|v| v.trim().parse().ok()),
        economie: None,
    })
}

/// `netsh wlan show interfaces`, en anglais ou en français : « Signal : 72% », « Channel : 36 » ou « Canal : 36 ».
/// Sans ligne « Signal », la carte n'est pas connectée.
#[cfg_attr(not(windows), allow(dead_code))]
fn signal_netsh(texte: &str) -> Option<Signal> {
    let valeur = |cles: &[&str]| {
        texte.lines().find_map(|l| {
            let (cle, valeur) = l.split_once(':')?;
            cles.contains(&cle.trim())
                .then(|| valeur.chars().filter(char::is_ascii_digit).collect::<String>())
        })
    };
    Some(Signal {
        qualite: valeur(&["Signal"])?.parse().ok()?,
        canal: valeur(&["Channel", "Canal"]).and_then(|c| c.parse().ok()),
        economie: None,
    })
}

/// `system_profiler SPAirPortDataType` (macOS) : « Signal / Noise: -58 dBm / -94 dBm » et « Channel: 36 (5GHz,
/// 80MHz) » du réseau en cours (le premier bloc). Qualité : 2 × (dBm + 100), bornée à 0-100, l'usage courant.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn signal_airport(texte: &str) -> Option<Signal> {
    let en_cours = texte.split("Current Network Information:").nth(1)?;
    let dbm: i32 = en_cours
        .lines()
        .find_map(|l| l.trim().strip_prefix("Signal / Noise:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let qualite = u8::try_from((2 * (dbm + 100)).clamp(0, 100)).ok()?;
    Some(Signal {
        qualite,
        canal: en_cours
            .lines()
            .find_map(|l| l.trim().strip_prefix("Channel:"))
            .and_then(|v| v.split_whitespace().next()?.parse().ok()),
        economie: None,
    })
}

fn signal() -> Option<Signal> {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let sortie = |cmd: &str, args: &[&str]| {
            crate::commande::lancer(Command::new(cmd).args(args).env("LC_ALL", "C"), 15)
                .filter(|r| r.code == Some(0))
                .map(|r| r.sortie)
                .unwrap_or_default()
        };
        let mut s = signal_nmcli(&sortie(
            "nmcli",
            &"-t -f IN-USE,SIGNAL,CHAN dev wifi list --rescan no"
                .split(' ')
                .collect::<Vec<_>>(),
        ))?;
        // « Interface wlan0 » dans `iw dev`, puis « Power save: on ».
        let interfaces = sortie("iw", &["dev"]);
        s.economie = interfaces
            .lines()
            .find_map(|l| l.trim().strip_prefix("Interface "))
            .map(str::trim)
            .and_then(|i| {
                let etat = sortie("iw", &["dev", i, "get", "power_save"]);
                let v = etat.split(':').nth(1)?.trim().to_string();
                Some(v == "on")
            });
        Some(s)
    }
    #[cfg(windows)]
    {
        crate::commande::lancer(
            std::process::Command::new("netsh").args(["wlan", "show", "interfaces"]),
            15,
        )
        .and_then(|r| signal_netsh(&r.sortie))
    }
    #[cfg(target_os = "macos")]
    {
        crate::commande::lancer(
            std::process::Command::new("system_profiler").arg("SPAirPortDataType"),
            30,
        )
        .and_then(|r| signal_airport(&r.sortie))
    }
}

fn afficher_signal(s: &Signal) {
    let (etat, texte) = match s.qualite {
        60.. => (
            Etat::Bon,
            trf!("Signal Wi-Fi bon ({} %).", "Good Wi-Fi signal ({}%).", s.qualite),
        ),
        40..60 => (
            Etat::Info,
            trf!("Signal Wi-Fi moyen ({} %).", "Average Wi-Fi signal ({}%).", s.qualite),
        ),
        _ => (
            Etat::Mauvais,
            trf!("Signal Wi-Fi faible ({} %).", "Weak Wi-Fi signal ({}%).", s.qualite),
        ),
    };
    etat.dire(&texte);
    if let Some(c) = s.canal {
        Etat::Info.dire(&if c <= 14 {
            trf!(
                "Bande {}, canal {c} : elle porte loin et traverse les murs, mais elle est plus lente et plus encombrée.",
                "{} band, channel {c}: it reaches far and goes through walls, but it is slower and more crowded.",
                bande(c)
            )
        } else {
            trf!(
                "Bande {}, canal {c} : rapide, mais elle porte moins loin et traverse mal les murs.",
                "{} band, channel {c}: fast, but it reaches less far and goes poorly through walls.",
                bande(c)
            )
        });
    }
    if s.economie == Some(true) {
        Etat::Info.dire(tr!(
            "Économie d'énergie du Wi-Fi activée : elle peut couper la connexion après un moment sans activité ou après la veille.",
            "Wi-Fi power saving is on: it can cut the connection after a while without activity or after sleep."
        ));
    }
}

/// Couper l'économie d'énergie de la carte Wi-Fi, sur ce système.
fn economie_d_energie() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Gestionnaire de périphériques › Cartes réseau › ta carte Wi-Fi › Gestion de l'alimentation : décoche « Autoriser l'ordinateur à éteindre ce périphérique pour économiser l'énergie ».",
            "Device Manager › Network adapters › your Wi-Fi card › Power Management: uncheck “Allow the computer to turn off this device to save power”."
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "Réglages Système › Wi-Fi › Détails du réseau : « Oublier ce réseau », puis s'y reconnecter ; et garder macOS à jour, qui corrige souvent ces coupures.",
            "System Settings › Wi-Fi › network Details: “Forget This Network”, then reconnect; and keep macOS up to date, which often fixes these drops."
        )
    } else {
        tr!(
            "Avec NetworkManager : un fichier /etc/NetworkManager/conf.d/wifi-economie.conf contenant les deux lignes « [connection] » et « wifi.powersave = 2 », puis redémarrer NetworkManager. Supprimer ce fichier remet comme avant.",
            "With NetworkManager: a file /etc/NetworkManager/conf.d/wifi-powersave.conf with the two lines “[connection]” and “wifi.powersave = 2”, then restart NetworkManager. Deleting this file puts things back."
        )
    }
}

/// « Le Wi-Fi coupe ».
pub(super) fn wifi() {
    let Some(quand) = question(
        tr!("Quand le Wi-Fi coupe-t-il ?", "When does Wi-Fi drop?"),
        &[
            tr!("Au hasard, même près de la box", "Randomly, even near the router"),
            tr!("Quand je m'éloigne de la box", "When I move away from the router"),
            tr!("Après la mise en veille", "After sleep"),
            tr!("Il ne se connecte plus du tout", "It no longer connects at all"),
        ],
    ) else {
        return;
    };
    let Some(autres) = question(
        tr!(
            "Les autres appareils en Wi-Fi coupent-ils aussi ?",
            "Do the other devices on Wi-Fi drop too?"
        ),
        &[
            tr!("Oui", "Yes"),
            tr!("Non, seulement cet ordinateur", "No, only this computer"),
            tr!("Je ne sais pas", "I don't know"),
        ],
    ) else {
        return;
    };
    verifications();
    trp!(
        "  {DISCRET}Lecture du Wi-Fi et essais (quelques secondes)…{RESET}",
        "  {DISCRET}Reading Wi-Fi and testing (a few seconds)…{RESET}"
    );
    let s = signal();
    match &s {
        Some(s) => afficher_signal(s),
        None => Etat::Mauvais.dire(tr!(
            "Cet ordinateur n'est connecté à aucun Wi-Fi en ce moment.",
            "This computer is not connected to any Wi-Fi right now."
        )),
    }
    let e = lire_etat();
    afficher_etat(&e);
    section(tr!("CE QUE ÇA VEUT DIRE", "WHAT IT MEANS"));
    let faible = s.as_ref().is_some_and(|s| s.qualite < 40);
    if autres == 0 {
        conseil(tr!(
            "Tous les appareils coupent : la box est en cause (surchauffe, canal encombré par les voisins, logiciel de la box). Redémarre-la ; si ça revient, change son canal Wi-Fi (le moins encombré, d'après l'outil des canaux Wi-Fi de Réseau et Internet) et cherche une mise à jour de la box.",
            "All devices drop: the router is to blame (overheating, channel crowded by the neighbors, router software). Restart it; if it comes back, change its Wi-Fi channel (the least crowded, according to the Wi-Fi channels tool in Network and Internet) and look for a router update."
        ));
    }
    if faible || quand == 1 {
        conseil(tr!(
            "Signal trop faible là où tu es : rapproche-toi, mets la box en hauteur, loin du micro-ondes et des murs épais. Un répéteur ou un Wi-Fi maillé (mesh) l'étend. Près de la box, la bande 5 GHz est plus rapide ; loin, la 2,4 GHz porte mieux.",
            "Signal too weak where you are: move closer, put the router up high, away from the microwave and thick walls. A repeater or a mesh Wi-Fi extends it. Near the router, the 5 GHz band is faster; far away, 2.4 GHz reaches better."
        ));
    }
    if quand == 2 || s.as_ref().is_some_and(|s| s.economie == Some(true)) {
        conseil(economie_d_energie());
    }
    if quand == 3 {
        conseil(tr!(
            "Il ne se connecte plus : oublie le réseau dans les réglages du Wi-Fi, puis reconnecte-toi avec le mot de passe (il a peut-être changé sur la box).",
            "It no longer connects: forget the network in the Wi-Fi settings, then reconnect with the password (it may have changed on the router)."
        ));
    }
    if quand == 0 && autres == 1 {
        conseil(tr!(
            "Au hasard, et seulement cet ordinateur : la carte Wi-Fi ou son pilote. Mets à jour les pilotes, et coupe l'économie d'énergie du Wi-Fi.",
            "Randomly, and only this computer: the Wi-Fi card or its driver. Update the drivers, and turn off Wi-Fi power saving."
        ));
        if quand != 2 {
            conseil(economie_d_energie());
        }
        proposer_outil(
            tr!(
                "\n  Chercher les mises à jour (pilotes compris) ? [o/N] : ",
                "\n  Look for updates (drivers included)? [y/N]: "
            ),
            crate::maj::executer,
        );
    }
    if autres != 0 {
        reparer_le_reseau();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ICI: Adresse = Adresse::Locale(Ipv4Addr::new(192, 168, 1, 20));

    fn etat(adresse: Adresse, box_: bool, internet: bool, noms: bool) -> EtatReseau {
        EtatReseau {
            adresse,
            passerelle: Some(Ipv4Addr::new(192, 168, 1, 1)),
            passerelle_repond: box_,
            internet,
            noms,
        }
    }

    #[test]
    fn ou_la_connexion_s_arrete() {
        assert_eq!(panne(&etat(Adresse::Aucune, false, false, false)), Panne::PasConnecte);
        assert_eq!(
            panne(&etat(Adresse::Autoattribuee, false, false, false)),
            Panne::PasDAdresse
        );
        assert_eq!(panne(&etat(ICI, false, false, false)), Panne::BoxMuette);
        assert_eq!(panne(&etat(ICI, true, false, false)), Panne::InternetCoupe);
        assert_eq!(panne(&etat(ICI, true, true, false)), Panne::Noms);
        assert_eq!(panne(&etat(ICI, true, true, true)), Panne::Aucune);
        // Une box qui ne répond pas aux essais mais laisse passer Internet : rien à signaler.
        assert_eq!(panne(&etat(ICI, false, true, true)), Panne::Aucune);
    }

    #[test]
    fn signal_lu_partout() {
        let nmcli = "  :45:6\n*:72:36\n  :30:1\n";
        assert_eq!(
            signal_nmcli(nmcli),
            Some(Signal {
                qualite: 72,
                canal: Some(36),
                economie: None
            })
        );
        assert_eq!(signal_nmcli("  :45:6\n"), None);
        let netsh_fr = "    Nom                    : Wi-Fi\n    État                   : connecté\n    SSID                   : Salon\n    Canal                  : 6\n    Signal                 : 58 %\n";
        assert_eq!(
            signal_netsh(netsh_fr).map(|s| (s.qualite, s.canal)),
            Some((58, Some(6)))
        );
        let netsh_en = "    State                  : connected\n    Channel                : 149\n    Signal                 : 91%\n";
        assert_eq!(
            signal_netsh(netsh_en).map(|s| (s.qualite, s.canal)),
            Some((91, Some(149)))
        );
        assert_eq!(signal_netsh("    State : disconnected\n"), None);
        let airport = "Wi-Fi:\n  Interfaces:\n    en0:\n      Current Network Information:\n        Salon:\n          Channel: 36 (5GHz, 80MHz)\n          Signal / Noise: -58 dBm / -94 dBm\n      Other Local Wi-Fi Networks:\n          Signal / Noise: -80 dBm / -94 dBm\n";
        assert_eq!(
            signal_airport(airport).map(|s| (s.qualite, s.canal)),
            Some((84, Some(36)))
        );
        assert_eq!(bande(6), "2,4 GHz");
        assert_eq!(bande(149), "5 GHz");
    }
}
