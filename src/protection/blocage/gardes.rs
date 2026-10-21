//! Les garde-fous du blocage, en fonctions pures (testées sous Linux et sous Wine) : ce qui ne s'arrête, ne se met
//! en quarantaine ni ne se bloque jamais, même quand une liste ou une règle le désigne. Ce qu'ils refusent reste une
//! alerte, avec sa raison.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::machine::regles::Os;
use crate::tr;

/// Le noyau ou Idle (0), init, systemd ou launchd (1), System de Windows (4).
const PID_CRITIQUES: [u32; 3] = [0, 1, 4];

/// Les processus dont l'arrêt fait tomber le système ou la session (écran bleu, déconnexion), ou coupe une connexion
/// à distance : jamais arrêtés, même quand un programme ailleurs prend leur nom (une alerte le dit).
const NOMS_CRITIQUES: &[&str] = &[
    // Windows.
    "system",
    "idle",
    "registry",
    "secure system",
    "memory compression",
    "smss",
    "csrss",
    "wininit",
    "winlogon",
    "services",
    "lsass",
    "lsaiso",
    "svchost",
    "dwm",
    "fontdrvhost",
    "msmpeng",
    // Linux et macOS.
    "systemd",
    "init",
    "kthreadd",
    "launchd",
    "kernel_task",
    "loginwindow",
    "windowserver",
    // Les sessions à distance en cours, de part et d'autre.
    "sshd",
    "sshd-session",
    "xrdp",
    "xrdp-sesman",
];

/// Le nom d'un processus comparé aux noms critiques : sans dossier, sans « .exe », en minuscules.
fn nom_simple(nom: &str) -> String {
    let fichier = nom.rsplit(['/', '\\']).next().unwrap_or(nom).trim().to_lowercase();
    fichier.strip_suffix(".exe").unwrap_or(&fichier).to_string()
}

/// Un programme du système : il ne s'arrête ni ne se met en quarantaine (une alerte seulement). Un chemin qui remonte
/// (« .. ») ne se juge pas : il est tenu pour du système.
pub(crate) fn dossier_systeme(chemin: &str, os: Os) -> bool {
    match os {
        Os::Windows => {
            let c = chemin.to_lowercase().replace('/', "\\");
            let c = c.strip_prefix(r"\\?\").unwrap_or(&c);
            if c.contains(r"\..\") {
                return true;
            }
            // « C:\Windows\… » quelle que soit la lettre du disque, et l'antivirus de Microsoft.
            let sans_lecteur = c
                .get(1..)
                .filter(|_| c.chars().next().is_some_and(|l| l.is_ascii_alphabetic()));
            sans_lecteur.is_some_and(|reste| {
                [
                    r":\windows\",
                    r":\program files\windows defender\",
                    r":\programdata\microsoft\windows defender\",
                ]
                .iter()
                .any(|d| reste.starts_with(d))
            })
        }
        Os::Linux | Os::MacOs | Os::Tous => {
            if chemin.contains("/../") || chemin.ends_with("/..") {
                return true;
            }
            let communs = [
                "/usr/bin/",
                "/usr/sbin/",
                "/usr/lib/",
                "/usr/lib64/",
                "/usr/libexec/",
                "/usr/share/",
                "/bin/",
                "/sbin/",
                "/lib/",
                "/lib64/",
            ];
            let mac = ["/System/", "/Library/Apple/", "/private/var/db/"];
            communs.iter().any(|d| chemin.starts_with(d))
                || (os == Os::MacOs && mac.iter().any(|d| chemin.starts_with(d)))
        }
    }
}

/// Pourquoi ce processus ne doit jamais être arrêté, ou `None`. `intouchables` : Vanguard, ce qu'il a lancé et ce qui
/// le fait tourner (son terminal, sa session), d'après `chasse::en_marche`. Sans chemin lisible, rien ne s'arrête à
/// l'aveugle : un programme du système ne se reconnaîtrait pas.
pub(crate) fn processus_intouchable(
    pid: u32,
    nom: &str,
    chemin: Option<&str>,
    intouchables: &HashSet<u32>,
    os: Os,
) -> Option<&'static str> {
    if PID_CRITIQUES.contains(&pid) || NOMS_CRITIQUES.contains(&nom_simple(nom).as_str()) {
        return Some(tr!(
            "processus critique du système : une alerte seulement",
            "critical system process: an alert only"
        ));
    }
    if intouchables.contains(&pid) || pid == std::process::id() {
        return Some(tr!(
            "Vanguard lui-même, ce qu'il a lancé ou ce qui le fait tourner (terminal, session)",
            "Vanguard itself, what it started or what runs it (terminal, session)"
        ));
    }
    let Some(chemin) = chemin else {
        return Some(tr!(
            "chemin du programme illisible sans droits d'administrateur : rien n'est arrêté à l'aveugle",
            "program path unreadable without administrator rights: nothing is stopped blindly"
        ));
    };
    if dossier_systeme(chemin, os) {
        return Some(tr!(
            "programme du système : une alerte seulement",
            "system program: an alert only"
        ));
    }
    None
}

/// Pourquoi ce fichier ne doit jamais être mis en quarantaine, ou `None` : un fichier du système, ou Vanguard.
pub(crate) fn fichier_intouchable(chemin: &str, os: Os, mon_programme: Option<&str>) -> Option<&'static str> {
    let meme = |m: &str| {
        if os == Os::Windows {
            m.eq_ignore_ascii_case(chemin)
        } else {
            m == chemin
        }
    };
    if mon_programme.is_some_and(meme) {
        return Some(tr!("Vanguard lui-même", "Vanguard itself"));
    }
    dossier_systeme(chemin, os).then_some(tr!(
        "fichier du système : une alerte seulement",
        "system file: an alert only"
    ))
}

/// Les résolveurs DNS publics les plus courants : les bloquer couperait Internet à toute la maison, même si une liste
/// les citait par erreur.
const DNS_PUBLICS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "45.90.28.0",
    "45.90.30.0",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "2620:fe::fe",
    "2620:fe::9",
];

/// Pourquoi cette adresse ne doit pas être bloquée en sortie, ou `None`. `sessions` : les adresses des connexions à
/// distance en cours (SSH, Bureau à distance) ; `None` : illisibles, et rien n'est bloqué sans les connaître.
pub(crate) fn adresse_intouchable(ip: IpAddr, sessions: Option<&[IpAddr]>) -> Option<&'static str> {
    let ip = ip.to_canonical();
    if !crate::protection::sortantes::sur_internet(ip) {
        return Some(tr!(
            "adresse du réseau local ou de cet ordinateur : jamais bloquée",
            "address of the local network or of this computer: never blocked"
        ));
    }
    if DNS_PUBLICS.iter().any(|d| d.parse::<IpAddr>().is_ok_and(|d| d == ip)) {
        return Some(tr!(
            "serveur DNS public : le bloquer couperait Internet",
            "public DNS server: blocking it would cut the Internet"
        ));
    }
    match sessions {
        None => Some(tr!(
            "connexions à distance en cours illisibles : rien n'est bloqué sans savoir si l'une passe par là",
            "remote connections in progress unreadable: nothing is blocked without knowing whether one goes there"
        )),
        Some(s) if s.iter().any(|a| a.to_canonical() == ip) => Some(tr!(
            "une connexion à distance en cours (SSH, Bureau à distance) passe par cette adresse : jamais coupée",
            "a remote connection in progress (SSH, Remote Desktop) goes through this address: never cut"
        )),
        Some(_) => None,
    }
}

/// Les ports de SSH et du Bureau à distance : jamais fermés en entrée, ce serait couper l'accès à distance.
const PORTS_DE_SESSION: [u16; 2] = [22, 3389];

pub(crate) fn port_intouchable(port: u16) -> Option<&'static str> {
    PORTS_DE_SESSION.contains(&port).then_some(tr!(
        "port de SSH ou du Bureau à distance : jamais fermé",
        "SSH or Remote Desktop port: never closed"
    ))
}

/// Une connexion établie est-elle une session à distance (SSH, Bureau à distance), d'un côté ou de l'autre ?
pub(crate) fn est_session(port_local: u16, port_distant: u16) -> bool {
    PORTS_DE_SESSION.contains(&port_local) || PORTS_DE_SESSION.contains(&port_distant)
}

/// L'adresse du client de la session SSH où tourne Vanguard (« SSH_CONNECTION=client port serveur port »), même sur
/// un autre port que 22.
pub(crate) fn client_ssh(valeur: &str) -> Option<IpAddr> {
    valeur
        .split_whitespace()
        .next()?
        .parse::<IpAddr>()
        .ok()
        .map(|a| a.to_canonical())
}

/// Les sessions à distance d'un fichier de /proc/net (tcp, tcp6) : « sl locale distante état … », état 01 = établie.
/// → l'adresse distante de chacune.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn sessions_proc(texte: &str) -> Vec<IpAddr> {
    let point = |t: &str| -> Option<(IpAddr, u16)> {
        let (adresse, port) = t.split_once(':')?;
        Some((
            crate::protection::sortantes::adresse_proc(adresse)?,
            u16::from_str_radix(port, 16).ok()?,
        ))
    };
    texte
        .lines()
        .skip(1)
        .filter_map(|l| {
            let champs: Vec<&str> = l.split_whitespace().collect();
            if champs.get(3)? != &"01" {
                return None;
            }
            let (_, local) = point(champs.get(1)?)?;
            let (distante, distant) = point(champs.get(2)?)?;
            est_session(local, distant).then(|| distante.to_canonical())
        })
        .collect()
}

/// Les sessions à distance d'une table TCP de Windows (GetExtendedTcpTable, « propriétaire, toutes ») : voir
/// `sortantes::lire_table_tcp` pour la forme. → l'adresse distante de chacune.
#[cfg(any(windows, test))]
pub(crate) fn sessions_table(octets: &[u8], ipv6: bool) -> Vec<IpAddr> {
    let mot = |o: &[u8], i: usize| o.get(i..i + 4).map(|m| u32::from_ne_bytes([m[0], m[1], m[2], m[3]]));
    let port = |o: &[u8], i: usize| o.get(i..i + 2).map(|m| u16::from_be_bytes([m[0], m[1]]));
    let (taille, port_local, adresse, port_distant, etat) =
        if ipv6 { (56, 20, 24, 44, 48) } else { (24, 8, 12, 16, 0) };
    let Some(nombre) = mot(octets, 0) else {
        return Vec::new();
    };
    octets
        .get(4..)
        .unwrap_or_default()
        .chunks_exact(taille)
        .take(usize::try_from(nombre).unwrap_or(usize::MAX))
        .filter(|l| mot(l, etat) == Some(5))
        .filter_map(|l| {
            let distante = if ipv6 {
                IpAddr::from(<[u8; 16]>::try_from(l.get(adresse..adresse + 16)?).ok()?)
            } else {
                IpAddr::from(<[u8; 4]>::try_from(l.get(adresse..adresse + 4)?).ok()?)
            };
            est_session(port(l, port_local)?, port(l, port_distant)?).then(|| distante.to_canonical())
        })
        .collect()
}

/// Les sessions à distance de `netstat -anp tcp` sous macOS : « tcp4 0 0 192.168.1.5.22 192.168.1.20.51234
/// ESTABLISHED », le port après le dernier point.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn sessions_netstat(texte: &str) -> Vec<IpAddr> {
    let point = |t: &str| -> Option<(IpAddr, u16)> {
        let (ip, port) = t.rsplit_once('.')?;
        Some((ip.split('%').next()?.parse().ok()?, port.parse().ok()?))
    };
    texte
        .lines()
        .filter(|l| l.contains("ESTABLISHED"))
        .filter_map(|l| {
            let mots: Vec<&str> = l.split_whitespace().collect();
            let (_, local) = point(mots.get(3)?)?;
            let (distante, distant) = point(mots.get(4)?)?;
            est_session(local, distant).then(|| distante.to_canonical())
        })
        .collect()
}

/// Les adresses des sessions à distance en cours sur cet ordinateur, entrantes comme sortantes, et celle du client SSH
/// de Vanguard. `None` : la table des connexions ne se lit pas.
pub(crate) fn sessions_a_distance() -> Option<Vec<IpAddr>> {
    let mut sessions = lire_sessions()?;
    sessions.extend(std::env::var("SSH_CONNECTION").ok().as_deref().and_then(client_ssh));
    sessions.sort_unstable();
    sessions.dedup();
    Some(sessions)
}

#[cfg(target_os = "linux")]
fn lire_sessions() -> Option<Vec<IpAddr>> {
    let mut lisible = false;
    let mut sessions = Vec::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(t) = std::fs::read_to_string(f) {
            lisible = true;
            sessions.extend(sessions_proc(&t));
        }
    }
    lisible.then_some(sessions)
}

#[cfg(windows)]
fn lire_sessions() -> Option<Vec<IpAddr>> {
    let v4 = crate::protection::sortantes::table_tcp(2).map(|t| sessions_table(&t, false));
    let v6 = crate::protection::sortantes::table_tcp(23).map(|t| sessions_table(&t, true));
    if v4.is_none() && v6.is_none() {
        return None;
    }
    Some(v4.into_iter().chain(v6).flatten().collect())
}

#[cfg(target_os = "macos")]
fn lire_sessions() -> Option<Vec<IpAddr>> {
    let n = crate::commande::lancer(std::process::Command::new("netstat").args(["-anp", "tcp"]), 15)?;
    (n.code == Some(0)).then(|| sessions_netstat(&n.sortie))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(t: &str) -> IpAddr {
        t.parse().unwrap()
    }

    /// Garde-fou : jamais un processus critique (PID 0, 1, 4, ou nom critique), jamais Vanguard ni ce qui le fait
    /// tourner, jamais un programme du système, jamais un programme dont le chemin ne se lit pas.
    #[test]
    fn processus_jamais_arretes() {
        let rien = HashSet::new();
        let j = |pid, nom, chemin, os| processus_intouchable(pid, nom, chemin, &rien, os);
        for pid in [0, 1, 4] {
            assert!(j(pid, "x", Some("/home/alice/x"), Os::Linux).is_some(), "{pid}");
        }
        for nom in [
            "csrss.exe",
            "LSASS.EXE",
            "smss",
            "wininit.exe",
            "services.exe",
            "winlogon.exe",
            "svchost.exe",
            "systemd",
            "launchd",
            "kernel_task",
            "sshd",
        ] {
            // Même lancé hors de son dossier (un imposteur) : une alerte seulement, jamais d'arrêt.
            assert!(
                j(4242, nom, Some(r"C:\Users\alice\AppData\Local\Temp\x.exe"), Os::Windows).is_some(),
                "{nom}"
            );
        }
        assert!(j(4242, "outil", Some(r"C:\Windows\System32\outil.exe"), Os::Windows).is_some());
        assert!(j(4242, "outil", Some(r"\\?\D:\WINDOWS\SysWOW64\outil.exe"), Os::Windows).is_some());
        assert!(j(4242, "python3", Some("/usr/bin/python3.12"), Os::Linux).is_some());
        assert!(j(4242, "outil", Some("/System/Library/x"), Os::MacOs).is_some());
        assert!(j(4242, "outil", None, Os::Linux).is_some());
        // Vanguard, ce qu'il a lancé, son terminal : intouchables.
        let vanguard: HashSet<u32> = [4300, 4301, 4299].into();
        assert!(processus_intouchable(4300, "vanguard", Some("/home/alice/vanguard"), &vanguard, Os::Linux).is_some());
        assert!(processus_intouchable(std::process::id(), "x", Some("/home/alice/x"), &rien, Os::Linux).is_some());
        // Un programme ordinaire d'un dossier du compte : rien ne l'empêche.
        assert_eq!(
            j(
                4242,
                "mimikatz.exe",
                Some(r"C:\Users\alice\Downloads\mimikatz.exe"),
                Os::Windows
            ),
            None
        );
        assert_eq!(j(4242, "xmrig", Some("/home/alice/.cache/xmrig"), Os::Linux), None);
        assert_eq!(j(4242, "xmrig", Some("/usr/local/bin/xmrig"), Os::Linux), None);
    }

    #[test]
    fn dossiers_du_systeme() {
        assert!(dossier_systeme("/usr/lib/firefox/firefox", Os::Linux));
        assert!(dossier_systeme("/sbin/init", Os::Linux));
        assert!(dossier_systeme("/home/alice/../../usr/bin/x", Os::Linux));
        assert!(!dossier_systeme(
            "/home/alice/Téléchargements/facture.pdf.sh",
            Os::Linux
        ));
        assert!(!dossier_systeme("/opt/outil/outil", Os::Linux));
        // /System n'est du système que sous macOS ; /Library/Apple aussi.
        assert!(!dossier_systeme("/System/x", Os::Linux));
        assert!(dossier_systeme("/Library/Apple/System/x", Os::MacOs));
        assert!(!dossier_systeme("/Users/alice/Library/x", Os::MacOs));
        assert!(dossier_systeme(r"c:\windows\explorer.exe", Os::Windows));
        assert!(dossier_systeme("C:/Windows/System32/cmd.exe", Os::Windows));
        assert!(dossier_systeme(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
            Os::Windows
        ));
        assert!(dossier_systeme(r"C:\Users\alice\..\..\Windows\x.exe", Os::Windows));
        assert!(!dossier_systeme(
            r"C:\Users\alice\AppData\Roaming\Windows\x.exe",
            Os::Windows
        ));
        assert!(!dossier_systeme(r"C:\ProgramData\Updater\x.exe", Os::Windows));
        assert!(!dossier_systeme("windows", Os::Windows));
    }

    #[test]
    fn fichiers_jamais_en_quarantaine() {
        assert!(fichier_intouchable("/usr/bin/curl", Os::Linux, None).is_some());
        assert!(fichier_intouchable("/home/alice/vanguard", Os::Linux, Some("/home/alice/vanguard")).is_some());
        assert!(
            fichier_intouchable(r"E:\VANGUARD.EXE", Os::Windows, Some(r"e:\vanguard.exe")).is_some(),
            "casse de Windows"
        );
        assert_eq!(
            fichier_intouchable("/home/alice/Téléchargements/x", Os::Linux, Some("/home/alice/vanguard")),
            None
        );
    }

    /// Garde-fou : jamais couper une connexion à distance en cours, ni bloquer le réseau local ou un DNS public.
    #[test]
    fn adresses_jamais_bloquees() {
        let sessions = [ip("198.51.100.20")];
        assert!(adresse_intouchable(ip("198.51.100.20"), Some(&sessions)).is_some());
        assert!(adresse_intouchable(ip("::ffff:198.51.100.20"), Some(&sessions)).is_some());
        assert!(
            adresse_intouchable(ip("203.0.113.7"), None).is_some(),
            "sessions illisibles"
        );
        assert!(adresse_intouchable(ip("192.168.1.1"), Some(&[])).is_some());
        assert!(adresse_intouchable(ip("127.0.0.1"), Some(&[])).is_some());
        assert!(adresse_intouchable(ip("8.8.8.8"), Some(&[])).is_some());
        assert!(adresse_intouchable(ip("2606:4700:4700::1111"), Some(&[])).is_some());
        assert_eq!(adresse_intouchable(ip("185.220.101.4"), Some(&sessions)), None);
        assert!(port_intouchable(22).is_some() && port_intouchable(3389).is_some());
        assert_eq!(port_intouchable(11434), None);
    }

    #[test]
    fn sessions_a_distance_lues() {
        // Linux : une session SSH entrante (port local 22), une sortante (port distant 22), et une connexion web.
        let proc = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0501A8C0:0016 1401A8C0:C822 01 00000000:00000000 00:00000000 00000000  1000        0 11 1
   1: 0501A8C0:D431 07AB33CB:0016 01 00000000:00000000 00:00000000 00000000  1000        0 12 1
   2: 0501A8C0:D432 04AB33CB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 13 1
   3: 0501A8C0:0016 1501A8C0:C823 0A 00000000:00000000 00:00000000 00000000  1000        0 14 1
";
        assert_eq!(sessions_proc(proc), [ip("192.168.1.20"), ip("203.51.171.7")]);
        // Windows : une session du Bureau à distance (port local 3389) en IPv4.
        let mut table = 2u32.to_ne_bytes().to_vec();
        for (etat, local, distante, distant) in [
            (5u32, 3389u16, [198, 51, 100, 9], 50_000u16),
            (5, 50_001, [203, 0, 113, 7], 443),
        ] {
            table.extend(etat.to_ne_bytes());
            table.extend([192, 168, 1, 5]);
            table.extend(u32::from(local).to_be_bytes()[2..].iter().chain(&[0, 0]));
            table.extend(distante);
            table.extend(u32::from(distant).to_be_bytes()[2..].iter().chain(&[0, 0]));
            table.extend(1234u32.to_ne_bytes());
        }
        assert_eq!(sessions_table(&table, false), [ip("198.51.100.9")]);
        // macOS : netstat.
        let netstat = "tcp4       0      0  192.168.1.5.22         192.168.1.20.51234     ESTABLISHED
tcp4       0      0  192.168.1.5.51000      203.0.113.7.443        ESTABLISHED
tcp6       0      0  fe80::1%en0.51001      2001:db8::7.3389       ESTABLISHED
";
        assert_eq!(sessions_netstat(netstat), [ip("192.168.1.20"), ip("2001:db8::7")]);
        assert_eq!(
            client_ssh("198.51.100.20 51234 192.168.1.5 22"),
            Some(ip("198.51.100.20"))
        );
        assert_eq!(client_ssh(""), None);
    }
}
