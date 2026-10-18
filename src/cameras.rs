//! Caméras cachées : sur le réseau d'une location, ou chez quelqu'un, les appareils qui ressemblent à des caméras.
//! Quatre indices : le fabricant (adresse MAC), un flux vidéo (RTSP) ou un port d'enregistreur ouvert, la réponse à
//! la recherche ONVIF (WS-Discovery, la norme des caméras de surveillance), et ce qu'annonce la page web de
//! l'appareil. D'un flux trouvé, Gardien demande seulement la description, pour savoir s'il exige un mot de passe :
//! aucune image n'est lue. Rien n'est coupé ni changé. Une caméra en 4G, ou qui n'enregistre que sur sa carte
//! mémoire, n'apparaît sur aucun réseau : l'œil reste le meilleur outil.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::risk::Niveau;
use crate::scan;
use crate::ui::*;

/// Fabricants de caméras tels que les nomme le registre des adresses MAC (en minuscules), et le nom à montrer.
/// Les marques qui font aussi des box, des prises ou des téléphones (TP-Link, Xiaomi, Tuya) n'y sont pas : leur
/// seul fabricant ne dit rien.
const FABRICANTS: &[(&str, &str)] = &[
    ("hikvision", "Hikvision"),
    ("ezviz", "Ezviz"),
    ("zhejiang dahua", "Dahua"),
    ("wyze labs", "Wyze"),
    ("reolink", "Reolink"),
    ("arlo technology", "Arlo"),
    ("ring llc", "Ring"),
    ("amcrest", "Amcrest"),
    ("axis communications", "Axis"),
    ("hanwha vision", "Hanwha"),
    ("samsung techwin", "Samsung Techwin"),
    ("uniview", "Uniview"),
    ("vivotek", "Vivotek"),
    ("lorex technology", "Lorex"),
    ("swann communications", "Swann"),
    ("blink by amazon", "Blink"),
    ("canary connect", "Canary"),
    ("zmodo", "Zmodo"),
    ("shanghai xiaoyi", "YI"),
    ("nest labs", "Nest"),
];

/// Ports d'un flux vidéo (RTSP).
const RTSP: [u16; 3] = [554, 8554, 10554];
/// Ports propres aux enregistreurs et caméras bon marché : Dahua (37777), XMEye (34567).
const PORTS_CAMERA: [u16; 2] = [34567, 37777];
/// Ports que les caméras ouvrent souvent, d'autres appareils aussi : ONVIF (2020, 8899), flux RTMP (1935).
const PORTS_POSSIBLES: [u16; 3] = [1935, 2020, 8899];
/// Pages web, dont l'en-tête trahit souvent une caméra ou un enregistreur.
const PORTS_WEB: [u16; 5] = [80, 81, 443, 8000, 8080];

/// Mots d'une page web de caméra ou d'enregistreur (en-tête « Server »), en minuscules.
const MOTS_WEB: &[&str] = &[
    "hikvision",
    "dahua",
    "dvr",
    "nvr",
    "ipcam",
    "ip camera",
    "webcam",
    "netcam",
    "camera",
    "uc-httpd",
    "dnvrs-webs",
    "app-webs",
    "reolink",
    "amcrest",
    "foscam",
];

/// Ce que dit un flux vidéo à qui demande sa description sans mot de passe.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Flux {
    /// Mot de passe demandé : bien.
    Protege,
    /// Description donnée sans mot de passe : n'importe qui sur le réseau peut regarder.
    Ouvert,
    /// Pas de réponse claire (chemin propre au fabricant) : protection non vérifiée.
    Inconnu,
}

/// Les indices trouvés sur un appareil.
#[derive(Default, Debug)]
struct Indices {
    fabricant: Option<&'static str>,
    /// Nom et modèle annoncés par ONVIF (« IPC · DS-2CD2032 »), vides s'ils ne sont pas donnés.
    onvif: Option<String>,
    rtsp: Vec<(u16, Flux)>,
    ports: Vec<u16>,
    web: Option<String>,
}

#[derive(Debug, PartialEq, PartialOrd)]
enum Force {
    AVerifier,
    Probable,
}

impl Indices {
    fn force(&self) -> Option<Force> {
        if self.fabricant.is_some()
            || self.onvif.is_some()
            || !self.rtsp.is_empty()
            || self.web.is_some()
            || self.ports.iter().any(|p| PORTS_CAMERA.contains(p))
        {
            Some(Force::Probable)
        } else if !self.ports.is_empty() {
            Some(Force::AVerifier)
        } else {
            None
        }
    }
}

/// Fabricant de caméras, d'après le nom du registre.
fn fabricant_camera(nom: &str) -> Option<&'static str> {
    let nom = nom.to_lowercase();
    FABRICANTS
        .iter()
        .find(|(m, _)| nom.contains(m))
        .map(|(_, affiche)| *affiche)
}

/// L'en-tête d'une page web qui parle de caméra ou d'enregistreur.
fn web_camera(banniere: &str) -> bool {
    let b = banniere.to_lowercase();
    MOTS_WEB.iter().any(|m| b.contains(m))
}

/// La réponse d'un flux vidéo à DESCRIBE : « RTSP/1.0 401 Unauthorized », « RTSP/1.0 200 OK »…
fn lire_flux(reponse: &str) -> Flux {
    let code = reponse
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("RTSP/"))
        .and_then(|l| l.split_whitespace().nth(1));
    match code {
        Some("401" | "403") => Flux::Protege,
        Some("200") => Flux::Ouvert,
        _ => Flux::Inconnu,
    }
}

/// Demande la description du flux (sans mot de passe) et lit la première ligne de la réponse.
async fn flux(ip: Ipv4Addr, port: u16) -> Flux {
    let demande = format!(
        "DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\nUser-Agent: Gardien\r\n\r\n"
    );
    let essai = async {
        let mut c = TcpStream::connect(SocketAddr::new(IpAddr::V4(ip), port)).await.ok()?;
        c.write_all(demande.as_bytes()).await.ok()?;
        let mut tampon = [0u8; 256];
        let n = c.read(&mut tampon).await.ok()?;
        Some(lire_flux(&String::from_utf8_lossy(&tampon[..n])))
    };
    timeout(Duration::from_secs(3), essai)
        .await
        .ok()
        .flatten()
        .unwrap_or(Flux::Inconnu)
}

/// Un texte entre `debut` et `fin` (le premier trouvé).
fn entre<'a>(texte: &'a str, debut: &str, fin: &str) -> Option<&'a str> {
    let reste = &texte[texte.find(debut)? + debut.len()..];
    Some(&reste[..reste.find(fin)?])
}

/// Décode les « %20 » d'un nom ONVIF.
fn sans_pourcent(t: &str) -> String {
    let mut octets = Vec::new();
    let mut i = 0;
    let b = t.as_bytes();
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = t.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            octets.push(v);
            i += 3;
        } else {
            octets.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&octets).into_owned()
}

/// Une réponse à la recherche ONVIF : une caméra (« NetworkVideoTransmitter », ou un type « video »), avec le nom et
/// le modèle de ses « Scopes » (« onvif://www.onvif.org/name/IPC »…), vides s'ils ne sont pas donnés.
fn lire_onvif(xml: &str) -> Option<String> {
    if !xml.contains("NetworkVideoTransmitter") && !xml.to_lowercase().contains("/type/video") {
        return None;
    }
    let mut nom = None;
    let mut modele = None;
    for s in entre(xml, "Scopes>", "</").unwrap_or("").split_whitespace() {
        if let Some(n) = s.strip_prefix("onvif://www.onvif.org/name/") {
            nom = Some(sans_pourcent(n));
        } else if let Some(m) = s.strip_prefix("onvif://www.onvif.org/hardware/") {
            modele = Some(sans_pourcent(m));
        }
    }
    let texte: Vec<String> = [nom, modele].into_iter().flatten().collect();
    // Les caractères de contrôle sont retirés : une réponse du réseau ne doit pas pouvoir piloter le terminal.
    Some(texte.join(" · ").chars().filter(|c| !c.is_control()).take(60).collect())
}

/// Identifiant de message au format d'un UUID, tiré du hasard du système.
fn uuid() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    let a = h.finish();
    let b = std::collections::hash_map::RandomState::new().build_hasher().finish();
    let x = format!("{a:016x}{b:016x}");
    format!(
        "{}-{}-4{}-a{}-{}",
        &x[..8],
        &x[8..12],
        &x[13..16],
        &x[17..20],
        &x[20..32]
    )
}

/// Recherche ONVIF (WS-Discovery) : une question envoyée à tout le réseau local (239.255.255.250, port 3702), à
/// laquelle seules les caméras répondent. Deux envois, une réponse UDP pouvant se perdre.
fn chercher_onvif() -> BTreeMap<Ipv4Addr, String> {
    let mut trouvees = BTreeMap::new();
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return trouvees;
    };
    // Une seule traversée de routeur : la question reste sur le réseau local.
    let _ = socket.set_multicast_ttl_v4(1);
    let question = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" \
         xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
         xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" \
         xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">\
         <e:Header><w:MessageID>uuid:{}</w:MessageID>\
         <w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>\
         <w:Action e:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>\
         </e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>\
         </e:Envelope>",
        uuid()
    );
    let groupe = SocketAddr::from(([239, 255, 255, 250], 3702));
    let mut tampon = vec![0u8; 16 * 1024];
    for _ in 0..2 {
        if socket.send_to(question.as_bytes(), groupe).is_err() {
            break;
        }
        let fin = Instant::now() + Duration::from_millis(1500);
        loop {
            let reste = fin.saturating_duration_since(Instant::now());
            if reste.is_zero() || socket.set_read_timeout(Some(reste)).is_err() {
                break;
            }
            match socket.recv_from(&mut tampon) {
                Ok((n, SocketAddr::V4(de))) => {
                    if let Some(c) = lire_onvif(&String::from_utf8_lossy(&tampon[..n])) {
                        trouvees.insert(*de.ip(), c);
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }
    trouvees
}

/// Les indices de chaque appareil du réseau local.
async fn chercher(cible: &str, moi: Ipv4Addr) -> Result<(usize, BTreeMap<Ipv4Addr, Indices>), String> {
    let ips = scan::parse_cible(cible)?;
    let parallele = scan::limite_connexions(512);
    let onvif = tokio::task::spawn_blocking(chercher_onvif);
    let vivantes = scan::decouvrir(&ips, Duration::from_millis(400), parallele).await;
    let mut ports: Vec<u16> = RTSP.to_vec();
    ports.extend(PORTS_CAMERA);
    ports.extend(PORTS_POSSIBLES);
    ports.extend(PORTS_WEB);
    let ouverts = scan::scanner_ports(&vivantes, &ports, Duration::from_millis(700), parallele).await;
    let arp = scan::table_arp();
    let onvif = onvif.await.unwrap_or_default();
    let passerelle = scan::passerelle();
    let mut indices: BTreeMap<Ipv4Addr, Indices> = BTreeMap::new();
    for (&ip, liste) in &ouverts {
        if ip == moi || Some(ip) == passerelle {
            continue;
        }
        let mut i = Indices {
            fabricant: arp
                .get(&ip)
                .and_then(|mac| scan::fabricant(mac))
                .and_then(|f| fabricant_camera(&f)),
            onvif: onvif.get(&ip).cloned(),
            ..Indices::default()
        };
        for (port, banniere) in liste {
            if RTSP.contains(port) {
                i.rtsp.push((*port, flux(ip, *port).await));
            } else if PORTS_CAMERA.contains(port) || PORTS_POSSIBLES.contains(port) {
                i.ports.push(*port);
            }
            if let Some(b) = banniere.as_deref().filter(|b| web_camera(b)) {
                i.web = Some(b.to_string());
            }
        }
        if i.force().is_some() {
            indices.insert(ip, i);
        }
    }
    // Une caméra qui a répondu à ONVIF sans qu'aucun de ses ports ne réponde (pare-feu) compte aussi.
    for (ip, c) in onvif {
        if ip != moi && Some(ip) != passerelle {
            indices.entry(ip).or_default().onvif.get_or_insert(c);
        }
    }
    Ok((vivantes.len(), indices))
}

fn lignes_indices(i: &Indices) -> Vec<(String, Option<Niveau>)> {
    let mut l = Vec::new();
    if let Some(f) = i.fabricant {
        l.push((trf!("fabricant de caméras ({f})", "camera maker ({f})"), None));
    }
    if let Some(o) = &i.onvif {
        let detail = if o.is_empty() { String::new() } else { format!(" : {o}") };
        l.push((
            trf!(
                "se présente comme caméra (ONVIF){detail}",
                "presents itself as a camera (ONVIF){detail}"
            ),
            None,
        ));
    }
    for (port, f) in &i.rtsp {
        l.push(match f {
            Flux::Protege => (
                trf!(
                    "flux vidéo (RTSP, port {port}) : mot de passe demandé",
                    "video stream (RTSP, port {port}): password required"
                ),
                None,
            ),
            Flux::Ouvert => (
                trf!(
                    "flux vidéo (RTSP, port {port}) SANS mot de passe : n'importe qui sur ce réseau peut regarder",
                    "video stream (RTSP, port {port}) WITHOUT a password: anyone on this network can watch"
                ),
                Some(Niveau::Eleve),
            ),
            Flux::Inconnu => (
                trf!(
                    "flux vidéo (RTSP, port {port}) : protection non vérifiée",
                    "video stream (RTSP, port {port}): protection not checked"
                ),
                Some(Niveau::Info),
            ),
        });
    }
    for port in &i.ports {
        l.push(match port {
            37777 => (
                tr!("port d'enregistreur Dahua (37777)", "Dahua recorder port (37777)").to_string(),
                None,
            ),
            34567 => (
                tr!(
                    "port des caméras et enregistreurs XMEye (34567)",
                    "XMEye cameras and recorders port (34567)"
                )
                .to_string(),
                None,
            ),
            p => (
                trf!(
                    "port {p} ouvert, que les caméras utilisent souvent",
                    "port {p} open, often used by cameras"
                ),
                Some(Niveau::Info),
            ),
        });
    }
    if let Some(w) = &i.web {
        l.push((trf!("page web : {w}", "web page: {w}"), None));
    }
    l
}

/// Menu Réseau et Internet › Caméras cachées, ou `gardien cameras`.
pub async fn chercher_cameras() {
    titre(tr!("Caméras cachées ?", "Hidden cameras?"));
    for ligne in envelopper(
        tr!(
            "Dans une location ou chez quelqu'un, Gardien cherche sur le réseau les appareils qui ressemblent à des caméras : fabricant, flux vidéo, recherche ONVIF, page web. Rien n'est coupé ni changé, et aucune image n'est lue.",
            "In a rental or at someone's place, Gardien looks on the network for devices that look like cameras: maker, video stream, ONVIF discovery, web page. Nothing is turned off or changed, and no image is read."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    let Some((cible, moi)) = scan::reseau_local() else {
        trp!(
            "\n  ✖ Pas de réseau local détecté : connecte-toi d'abord au Wi-Fi du lieu.",
            "\n  ✖ No local network detected: connect to the place's Wi-Fi first."
        );
        return;
    };
    trp!(
        "\n  {GRIS}Recherche sur {cible}…{RESET}",
        "\n  {GRIS}Searching {cible}…{RESET}"
    );
    let (appareils, indices) = match chercher(&cible, moi).await {
        Ok(r) => r,
        Err(e) => {
            println!("  ✖ {e}");
            return;
        }
    };
    trp!(
        "  {GRIS}{appareils} appareil(s) sur ce réseau.{RESET}\n",
        "  {GRIS}{appareils} device(s) on this network.{RESET}\n"
    );
    let mut liste: Vec<(&Ipv4Addr, &Indices)> = indices.iter().collect();
    liste.sort_by(|a, b| {
        b.1.force()
            .partial_cmp(&a.1.force())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if liste.is_empty() {
        afficher_aligne(
            &format!("  {VERT}✔{RESET} "),
            tr!(
                "Aucun appareil de ce réseau ne ressemble à une caméra.",
                "No device on this network looks like a camera."
            ),
            4,
            "",
        );
    }
    for (ip, i) in &liste {
        let (etiquette, teinte) = match i.force() {
            Some(Force::Probable) => (tr!("CAMÉRA PROBABLE", "LIKELY CAMERA"), couleur(Niveau::Moyen)),
            _ => (tr!("À VÉRIFIER", "TO CHECK"), couleur(Niveau::Info)),
        };
        println!("  {teinte}●{RESET} {:<16} {teinte}{etiquette}{RESET}", ip.to_string());
        for (texte, niveau) in lignes_indices(i) {
            let style = niveau.map_or("", couleur);
            afficher_aligne("      ", &texte, 6, style);
        }
    }
    println!();
    let conseil = if liste.is_empty() {
        tr!(
            "Une caméra en 4G, ou qui n'enregistre que sur sa carte mémoire, n'apparaît sur aucun réseau : regarde aussi les détecteurs de fumée, chargeurs, réveils et cadres tournés vers le lit ou la douche, avec la lampe du téléphone (l'objectif renvoie un petit reflet).",
            "A camera on 4G, or recording only to its memory card, shows up on no network: also look at smoke detectors, chargers, clocks and frames facing the bed or shower, with the phone's flashlight (the lens gives a small reflection)."
        )
    } else {
        tr!(
            "Une caméra peut être légitime (entrée, extérieur), mais la plupart des plateformes de location interdisent celles des chambres et des salles de bain, et exigent d'annoncer les autres. Ne la débranche pas et ne t'y connecte pas : prends une photo de l'appareil, puis préviens l'hôte et la plateforme.",
            "A camera can be legitimate (entrance, outdoors), but most rental platforms forbid them in bedrooms and bathrooms, and require the others to be disclosed. Do not unplug it or connect to it: take a photo of the device, then tell the host and the platform."
        )
    };
    afficher_aligne("  💡 ", conseil, 5, "");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fabricants_et_pages_web() {
        assert_eq!(
            fabricant_camera("Hangzhou Hikvision Digital Technology Co.,Ltd."),
            Some("Hikvision")
        );
        assert_eq!(fabricant_camera("Zhejiang Dahua Technology Co., Ltd."), Some("Dahua"));
        assert_eq!(fabricant_camera("Shanghai Dahua Scale Factory"), None);
        assert_eq!(fabricant_camera("Tp-Link Technologies Co.,Ltd."), None);
        assert!(web_camera("HTTP · uc-httpd 1.0.0"));
        assert!(web_camera("HTTP · DNVRS-Webs"));
        assert!(!web_camera("HTTP · nginx"));
    }

    #[test]
    fn reponses_rtsp() {
        assert_eq!(
            lire_flux("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"IP Camera\"\r\n"),
            Flux::Protege
        );
        assert_eq!(
            lire_flux("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\n"),
            Flux::Ouvert
        );
        assert_eq!(lire_flux("RTSP/1.0 404 Not Found\r\n"), Flux::Inconnu);
        assert_eq!(lire_flux("HTTP/1.1 400 Bad Request\r\n"), Flux::Inconnu);
        assert_eq!(lire_flux(""), Flux::Inconnu);
    }

    /// La vraie demande, contre un faux flux sur cet ordinateur (127.0.0.1) : rien ne sort sur le réseau.
    #[tokio::test]
    async fn demande_de_description_rtsp() {
        for (reponse, attendu) in [
            ("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\r\n", Flux::Protege),
            (
                "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\n\r\n",
                Flux::Ouvert,
            ),
        ] {
            let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = ecoute.local_addr().unwrap().port();
            let serveur = std::thread::spawn(move || {
                use std::io::{Read, Write};
                let (mut c, _) = ecoute.accept().unwrap();
                let mut demande = [0u8; 512];
                let n = c.read(&mut demande).unwrap();
                c.write_all(reponse.as_bytes()).unwrap();
                String::from_utf8_lossy(&demande[..n]).into_owned()
            });
            assert_eq!(flux(Ipv4Addr::LOCALHOST, port).await, attendu);
            let demande = serveur.join().unwrap();
            assert!(
                demande.starts_with(&format!("DESCRIBE rtsp://127.0.0.1:{port}/ RTSP/1.0\r\n")),
                "{demande}"
            );
        }
        // Rien n'écoute : protection non vérifiée, sans attendre longtemps.
        let libre = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = libre.local_addr().unwrap().port();
        drop(libre);
        assert_eq!(flux(Ipv4Addr::LOCALHOST, port).await, Flux::Inconnu);
    }

    #[test]
    fn reponse_onvif() {
        let xml = "<SOAP-ENV:Envelope><SOAP-ENV:Body><d:ProbeMatches><d:ProbeMatch>\
                   <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>\
                   <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/name/Salle%20de%20jeux \
                   onvif://www.onvif.org/hardware/DS-2CD2032 onvif://www.onvif.org/location/</d:Scopes>\
                   <d:XAddrs>http://10.0.0.42/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches>\
                   </SOAP-ENV:Body></SOAP-ENV:Envelope>";
        assert_eq!(lire_onvif(xml).as_deref(), Some("Salle de jeux · DS-2CD2032"));
        // Une imprimante qui répond quand même : pas une caméra.
        assert_eq!(
            lire_onvif("<d:Types>wsdp:Device wprt:PrintDeviceType</d:Types><d:Scopes></d:Scopes>"),
            None
        );
        // Une caméra sans nom ni modèle : vide, mais trouvée.
        assert_eq!(
            lire_onvif("<d:Types>dn:NetworkVideoTransmitter</d:Types>").as_deref(),
            Some("")
        );
        assert_eq!(sans_pourcent("a%20b%2"), "a b%2");
        let u = uuid();
        assert_eq!((u.len(), u.matches('-').count()), (36, 4));
    }

    #[test]
    fn force_des_indices() {
        assert_eq!(Indices::default().force(), None);
        let faible = Indices {
            ports: vec![2020],
            ..Indices::default()
        };
        assert_eq!(faible.force(), Some(Force::AVerifier));
        let enregistreur = Indices {
            ports: vec![34567],
            ..Indices::default()
        };
        assert_eq!(enregistreur.force(), Some(Force::Probable));
        let ouverte = Indices {
            rtsp: vec![(554, Flux::Ouvert)],
            ..Indices::default()
        };
        assert_eq!(ouverte.force(), Some(Force::Probable));
        let lignes = lignes_indices(&ouverte);
        assert_eq!(lignes.len(), 1);
        assert_eq!(lignes[0].1, Some(Niveau::Eleve));
    }
}
