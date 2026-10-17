//! Scan du réseau : machines, ports ouverts, risques, et comparaison avec les scans précédents.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use futures::future::join_all;
use serde::{Deserialize, Serialize};

use crate::risk::{Niveau, PORTS_COURANTS, identifier, info_port, note};
use crate::scan;
use crate::ui::*;

pub struct Options {
    pub cible: Option<String>,
    pub ports: String,
    pub timeout: u64,
    pub parallele: usize,
    pub json: bool,
    /// Aucun affichage (surveillance en arrière-plan).
    pub silencieux: bool,
}

impl Options {
    pub fn defaut(cible: Option<String>, ports: &str) -> Self {
        Options {
            cible,
            ports: ports.into(),
            timeout: 500,
            parallele: 512,
            json: false,
            silencieux: false,
        }
    }
}

#[derive(Serialize)]
pub struct PortOuvert {
    pub port: u16,
    pub service: &'static str,
    pub niveau: Niveau,
    pub banniere: Option<String>,
    pub conseil: &'static str,
    pub nouveau: bool,
    /// Programme qui écoute (seulement pour cette machine).
    pub programme: Option<String>,
}

#[derive(Serialize)]
pub struct Hote {
    pub ip: Ipv4Addr,
    pub nom: Option<String>,
    pub mac: Option<String>,
    pub fabricant: Option<String>,
    /// Nom donné par l'utilisateur (« imprimante HP »).
    pub surnom: Option<String>,
    /// Date du premier passage, AAAA-MM-JJ.
    pub premier_vu: Option<String>,
    pub role: Option<&'static str>,
    pub nouvelle: bool,
    pub ports: Vec<PortOuvert>,
    pub alertes: Vec<(Niveau, String)>,
    pub score: u32,
}

impl Hote {
    pub fn titre(&self) -> String {
        [self.surnom.as_deref(), self.nom.as_deref(), self.fabricant.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// Appareil déjà vu sur ce réseau mais absent du scan.
#[derive(Serialize)]
pub struct Absent {
    pub ip: Ipv4Addr,
    pub titre: String,
    pub dernier_vu: Option<String>,
}

#[derive(Serialize)]
pub struct Rapport {
    pub reseau: String,
    /// Nom du réseau (Wi-Fi) quand il est connu.
    pub nom_reseau: Option<String>,
    pub absents: Vec<Absent>,
    pub duree_s: f64,
    pub score_global: u32,
    pub note: &'static str,
    pub hotes: Vec<Hote>,
}

/// Base des appareils, un carnet par réseau : chez toi et chez chaque ami, sans mélange.
/// Un réseau est reconnu à l'adresse MAC de sa box (stable, contrairement à l'IP).
#[derive(Serialize, Deserialize, Default)]
struct Base {
    #[serde(default)]
    reseaux: BTreeMap<String, ReseauConnu>,
    /// Ancien format (avant les carnets par réseau) : repris dans le réseau courant au prochain scan.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    appareils: BTreeMap<String, AppareilConnu>,
}

#[derive(Serialize, Deserialize, Default)]
struct ReseauConnu {
    nom: Option<String>,
    appareils: BTreeMap<String, AppareilConnu>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AppareilConnu {
    ip: Ipv4Addr,
    nom: Option<String>,
    fabricant: Option<String>,
    /// Tous les ports déjà vus ouverts (union : un Chromecast en veille ne doit pas déclencher d'alerte au réveil).
    ports: BTreeSet<u16>,
    #[serde(default)]
    surnom: Option<String>,
    #[serde(default)]
    premier_vu: Option<String>,
    #[serde(default)]
    dernier_vu: Option<String>,
}

impl AppareilConnu {
    fn titre(&self) -> String {
        [self.surnom.as_deref(), self.nom.as_deref(), self.fabricant.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ")
    }

    /// Fusion de deux fiches du même appareil (base de la clé + copie locale).
    fn fusionner(&mut self, autre: AppareilConnu) {
        self.ports.extend(autre.ports);
        self.surnom = self.surnom.take().or(autre.surnom);
        self.premier_vu = [self.premier_vu.take(), autre.premier_vu].into_iter().flatten().min();
        if autre.dernier_vu > self.dernier_vu {
            self.dernier_vu = autre.dernier_vu;
            self.ip = autre.ip;
        }
    }
}

impl Base {
    fn lire(p: &std::path::Path) -> Base {
        let Ok(texte) = std::fs::read_to_string(p) else {
            return Base::default();
        };
        // Le Bloc-notes et PowerShell 5.1 ajoutent une marque d'ordre des octets (BOM) en tête.
        match serde_json::from_str(texte.trim_start_matches('\u{feff}')) {
            Ok(base) => base,
            Err(e) => {
                // Jamais écraser une base qu'on ne sait pas lire : on la met de côté, intacte.
                let copie = p.with_extension(format!(
                    "illisible-{}.json",
                    chrono::Local::now().format("%Y%m%d-%H%M%S")
                ));
                let _ = std::fs::copy(p, &copie);
                eprintln!(
                    "Attention : base des appareils illisible ({e}). Copie gardée : {}",
                    copie.display()
                );
                Base::default()
            }
        }
    }

    /// La base de la clé, enrichie des scans faits sans elle (copie locale).
    /// Le verrou rendu doit être gardé jusqu'à `enregistrer` : la surveillance horaire et un scan manuel
    /// ne doivent pas lire et réécrire la base en même temps (l'une effacerait les ajouts de l'autre).
    fn charger() -> (Base, [PathBuf; 2], Option<Verrou>) {
        let verrou = Verrou::prendre(&dossier_local());
        let cle = dossier_donnees().join("appareils.json");
        let local = dossier_local().join("appareils.json");
        let mut base = Base::lire(&cle);
        if local != cle {
            base.absorber(Base::lire(&local));
        }
        (base, [cle, local], verrou)
    }

    fn absorber(&mut self, autre: Base) {
        for (cle, a) in autre.appareils {
            match self.appareils.get_mut(&cle) {
                Some(connu) => connu.fusionner(a),
                None => drop(self.appareils.insert(cle, a)),
            }
        }
        for (id, r) in autre.reseaux {
            let mien = self.reseaux.entry(id).or_default();
            mien.nom = mien.nom.take().or(r.nom);
            for (cle, a) in r.appareils {
                match mien.appareils.get_mut(&cle) {
                    Some(connu) => connu.fusionner(a),
                    None => drop(mien.appareils.insert(cle, a)),
                }
            }
        }
    }

    /// On écrit la base sur la clé ET en local : la copie locale sert quand la clé est absente.
    fn enregistrer(&self, chemins: &[PathBuf; 2]) {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        for p in chemins {
            if let Err(e) = ecrire_atomique(p, &json) {
                eprintln!(
                    "Attention : base des appareils non enregistrée dans {} ({e}).",
                    p.display()
                );
            }
        }
    }
}

/// Écrit d'abord un fichier temporaire, le force sur le disque, puis le renomme à la place de l'ancien :
/// une coupure, un Ctrl-C ou une clé arrachée laissent soit l'ancienne base, soit la nouvelle, jamais une
/// base tronquée.
fn ecrire_atomique(chemin: &std::path::Path, contenu: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(d) = chemin.parent() {
        std::fs::create_dir_all(d)?;
    }
    let temporaire = chemin.with_extension(format!("tmp-{}", std::process::id()));
    let resultat = (|| {
        let mut f = std::fs::File::create(&temporaire)?;
        f.write_all(contenu.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&temporaire, chemin)
    })();
    if resultat.is_err() {
        let _ = std::fs::remove_file(&temporaire);
    }
    resultat
}

/// Verrou entre processus netscan (fichier créé de façon exclusive, retiré à la fin).
struct Verrou(PathBuf);

impl Verrou {
    /// Attend au plus 10 s. Un verrou de plus de 2 minutes vient d'un netscan interrompu : on le reprend.
    fn prendre(dossier: &std::path::Path) -> Option<Verrou> {
        let _ = std::fs::create_dir_all(dossier);
        let chemin = dossier.join("appareils.verrou");
        let fin = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&chemin) {
                Ok(_) => return Some(Verrou(chemin)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let ancien = std::fs::metadata(&chemin)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > std::time::Duration::from_secs(120));
                    if ancien {
                        let _ = std::fs::remove_file(&chemin);
                    } else if std::time::Instant::now() > fin {
                        eprintln!(
                            "Attention : base des appareils occupée par un autre netscan, enregistrement sans verrou."
                        );
                        return None;
                    } else {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

impl Drop for Verrou {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn aujourd_hui() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

/// « 2026-10-16 » → « 16/10/2026 »
pub fn date_fr(iso: &str) -> String {
    let mut p = iso.split('-');
    match (p.next(), p.next(), p.next()) {
        (Some(a), Some(m), Some(j)) => format!("{j}/{m}/{a}"),
        _ => iso.to_string(),
    }
}

/// Donne (ou retire, avec `None`) un surnom à un appareil, désigné par son IP ou son adresse MAC.
pub fn nommer(qui: &str, surnom: Option<&str>) -> Result<String, String> {
    let (mut base, chemins, _verrou) = Base::charger();
    let qui_min = qui.to_ascii_lowercase();
    let mut trouves = 0;
    let mut decrit = String::new();
    // Par IP, seulement dans le réseau où l'on se trouve (la même IP existe chez chacun) ; par MAC, partout.
    // Même identifiant que le scan : MAC de la box, sinon « plage <réseau local> ». Sans ce repli, un réseau
    // dont la box n'a pas de MAC connue ne pouvait jamais nommer un appareil par son IP.
    let ici = scan::passerelle()
        .and_then(|gw| scan::table_arp().get(&gw).cloned())
        .or_else(|| scan::reseau_local().map(|(r, _)| format!("plage {r}")));
    for (id, r) in base.reseaux.iter_mut() {
        for (cle, a) in r.appareils.iter_mut() {
            let par_mac = cle.eq_ignore_ascii_case(&qui_min);
            let par_ip = a.ip.to_string() == qui && ici.as_deref() == Some(id.as_str());
            if par_mac || par_ip {
                a.surnom = surnom.map(str::to_string);
                trouves += 1;
                decrit = format!("{} ({cle})", a.ip);
            }
        }
    }
    if trouves == 0 {
        return Err(format!(
            "aucun appareil « {qui} » dans la base : lance d'abord un scan du réseau (netscan reseau)"
        ));
    }
    base.enregistrer(&chemins);
    Ok(decrit)
}

/// Fichier témoin à la racine de la clé USB netscan.
pub const TEMOIN_CLE: &str = "netscan.cle";

/// Clé USB netscan branchée, si elle est trouvée (dossier racine contenant `netscan.cle`).
pub fn cle_usb() -> Option<PathBuf> {
    // D'abord : sommes-nous lancés depuis la clé ? (exe dans <clé>/Linux/, <clé>/Windows/…)
    let exe = std::env::current_exe().ok().and_then(|e| e.canonicalize().ok());
    let depuis_exe = exe
        .iter()
        .flat_map(|e| e.ancestors().skip(1).take(2).map(PathBuf::from))
        .collect::<Vec<_>>();
    #[cfg(target_os = "linux")]
    let montages: Vec<PathBuf> = std::env::var("USER")
        .ok()
        .and_then(|u| std::fs::read_dir(format!("/run/media/{u}")).ok())
        .into_iter()
        .flatten()
        .flatten()
        .map(|d| d.path())
        .collect();
    #[cfg(target_os = "macos")]
    let montages: Vec<PathBuf> = std::fs::read_dir("/Volumes")
        .into_iter()
        .flatten()
        .flatten()
        .map(|d| d.path())
        .collect();
    #[cfg(windows)]
    let montages: Vec<PathBuf> = ('D'..='Z').map(|l| PathBuf::from(format!("{l}:\\"))).collect();
    depuis_exe
        .into_iter()
        .chain(montages)
        .find(|d| d.join(TEMOIN_CLE).is_file())
}

/// Données (historique des appareils, rapports) : sur la clé USB quand elle est branchée,
/// pour qu'elles voyagent avec le programme ; sinon dans le dossier local de l'ordinateur.
pub fn dossier_donnees() -> PathBuf {
    cle_usb().map(|c| c.join("donnees")).unwrap_or_else(dossier_local)
}

/// Données propres à cet ordinateur (quarantaine antivirus : on ne transporte pas de malware sur une clé).
pub fn dossier_local() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"));
    #[cfg(target_os = "linux")]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));
    base.unwrap_or_default().join("netscan")
}

fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    match spec {
        "courants" => return Ok(PORTS_COURANTS.to_vec()),
        "tous" => return Ok((1..=u16::MAX).collect()),
        _ => {}
    }
    let mut ports = Vec::new();
    for morceau in spec.split(',') {
        let err = || format!("port invalide : {morceau}");
        // Port 0 impossible, et une plage à l'envers (« 100-10 ») ne doit pas devenir silencieusement vide.
        let port = |t: &str| t.trim().parse::<u16>().ok().filter(|&p| p > 0).ok_or_else(err);
        match morceau.trim().split_once('-') {
            Some((a, b)) => {
                let (a, b) = (port(a)?, port(b)?);
                if a > b {
                    return Err(format!("plage de ports à l'envers : {morceau}"));
                }
                ports.extend(a..=b);
            }
            None => ports.push(port(morceau)?),
        }
    }
    ports.sort();
    ports.dedup();
    Ok(ports)
}

/// Alertes d'une machine : celles de chaque port, plus celles qui dépendent d'une combinaison.
fn alertes(role: Option<&str>, ports: &[PortOuvert]) -> Vec<(Niveau, String)> {
    let ouverts: Vec<u16> = ports.iter().map(|p| p.port).collect();
    let a = |p| ouverts.contains(&p);
    let mut alertes: Vec<(Niveau, String)> = ports
        .iter()
        .filter(|p| p.niveau >= Niveau::Moyen)
        .map(|p| (p.niveau, format!("{} ({}) : {}", p.service, p.port, p.conseil)))
        .collect();
    if role == Some("passerelle") && a(80) && !a(443) {
        alertes.push((
            Niveau::Moyen,
            "Admin du routeur uniquement en HTTP : le mot de passe passe en clair.".into(),
        ));
    }
    if a(139) && a(445) {
        alertes.push((
            Niveau::Moyen,
            "NetBIOS + SMB : vérifier que SMBv1 est désactivé.".into(),
        ));
    }
    for p in ports {
        if let Some(b) = &p.banniere {
            if b.starts_with("SSH-1.") {
                alertes.push((
                    Niveau::Critique,
                    format!("Port {} : SSH version 1, cassé depuis 2001.", p.port),
                ));
            }
            if b.contains("vsFTPd 2.3.4") {
                alertes.push((
                    Niveau::Critique,
                    "vsFTPd 2.3.4 : version piégée (backdoor connue).".into(),
                ));
            }
        }
    }
    if ouverts.len() > 15 {
        alertes.push((
            Niveau::Moyen,
            format!("{} ports ouverts : surface d'attaque importante.", ouverts.len()),
        ));
    }
    alertes.sort_by_key(|a| std::cmp::Reverse(a.0));
    alertes
}

fn afficher(r: &Rapport) {
    let nom = r.nom_reseau.as_deref().map(|n| format!(" « {n} »")).unwrap_or_default();
    titre(&format!("Réseau{nom} {}", r.reseau));
    for h in &r.hotes {
        let role = h.role.map(|r| format!(" [{r}]")).unwrap_or_default();
        let mac = h
            .mac
            .as_deref()
            .map(|m| format!("  {GRIS}{m}{RESET}"))
            .unwrap_or_default();
        let neuve = if h.nouvelle {
            format!("  {}NOUVEL APPAREIL{RESET}", couleur(Niveau::Moyen))
        } else {
            String::new()
        };
        let depuis = match (&h.premier_vu, h.nouvelle) {
            (Some(d), false) => format!("  {GRIS}connu depuis le {}{RESET}", date_fr(d)),
            _ => String::new(),
        };
        println!("\n{GRAS}● {}{RESET} {}{role}{mac}{neuve}{depuis}", h.ip, h.titre());
        if h.ports.is_empty() {
            println!("    {GRIS}aucun port ouvert parmi ceux testés{RESET}");
        }
        for p in &h.ports {
            let b = p
                .banniere
                .as_deref()
                .map(|b| format!("  {GRIS}« {b} »{RESET}"))
                .unwrap_or_default();
            let prog = p
                .programme
                .as_deref()
                .map(|n| format!("  {GRAS}programme : {n}{RESET}"))
                .unwrap_or_default();
            let nouv = if p.nouveau && !h.nouvelle {
                format!(" {}(nouveau){RESET}", couleur(Niveau::Moyen))
            } else {
                String::new()
            };
            println!(
                "    {:>5}/tcp  {:<17} {}{:<8}{RESET}{nouv}{prog}{b}",
                p.port,
                p.service,
                couleur(p.niveau),
                p.niveau.libelle()
            );
        }
        for (n, msg) in &h.alertes {
            println!("    {}→{RESET} {msg}", couleur(*n));
        }
        println!("    {GRIS}score : {}/100{RESET}", h.score);
    }

    if !r.absents.is_empty() {
        println!("\n{GRIS}Déjà vus sur ce réseau, absents aujourd'hui :{RESET}");
        for a in &r.absents {
            let quand = a
                .dernier_vu
                .as_deref()
                .map(|d| format!(" — vu le {}", date_fr(d)))
                .unwrap_or_default();
            println!("  {GRIS}○ {} {}{quand}{RESET}", a.ip, a.titre);
        }
    }

    let compte = |n: Niveau| r.hotes.iter().flat_map(|h| &h.ports).filter(|p| p.niveau == n).count();
    titre("Bilan réseau");
    println!(
        "  {} appareils ({} nouveaux), {} ports ouverts — {}{} critiques{RESET}, {}{} élevés{RESET}, {}{} moyens{RESET}",
        r.hotes.len(),
        r.hotes.iter().filter(|h| h.nouvelle).count(),
        r.hotes.iter().map(|h| h.ports.len()).sum::<usize>(),
        couleur(Niveau::Critique),
        compte(Niveau::Critique),
        couleur(Niveau::Eleve),
        compte(Niveau::Eleve),
        couleur(Niveau::Moyen),
        compte(Niveau::Moyen),
    );
    afficher_note("Note du réseau (appareil le plus exposé)", r.score_global);
    println!("  {GRIS}Durée : {:.1} s{RESET}", r.duree_s);
}

/// Lance le scan réseau et retourne le rapport.
pub async fn executer(o: Options) -> Result<Rapport, String> {
    let bavard = !o.json && !o.silencieux;
    let debut = Instant::now();
    let local = scan::reseau_local();
    let moi = local.as_ref().map(|l| l.1);
    let cible = match o.cible {
        Some(c) => c,
        None => {
            local
                .ok_or("impossible de détecter le réseau local ; précise une cible (ex. 192.168.1.0/24)")?
                .0
        }
    };
    let ips = scan::parse_cible(&cible)?;
    let ports = parse_ports(&o.ports)?;
    let delai = Duration::from_millis(o.timeout);
    let gw = scan::passerelle();
    let parallele = scan::limite_connexions(o.parallele);

    if bavard {
        eprintln!(
            "{GRAS}Scan réseau{RESET} — {cible} ({} adresses, {} ports chacune)",
            ips.len(),
            ports.len()
        );
        eprintln!("{GRIS}Découverte des appareils…{RESET}");
    }
    let mut vivantes = if ips.len() == 1 {
        ips.clone()
    } else {
        scan::decouvrir(&ips, Duration::from_millis(o.timeout.min(400)), parallele).await
    };
    // Cette machine ne répond pas toujours à ses propres sondes sur l'IP du LAN.
    if let Some(m) = moi.filter(|m| ips.contains(m) && !vivantes.contains(m)) {
        vivantes.push(m);
        vivantes.sort();
    }

    if bavard {
        eprintln!("{GRIS}{} appareil(s) trouvé(s). Scan des ports…{RESET}", vivantes.len());
        if ips.iter().all(|ip| ip.is_loopback()) {
            eprintln!(
                "{GRIS}Note : 127.0.0.1 montre aussi les services réservés à cette machine. Pour ce qui est vraiment exposé au réseau : netscan machine.{RESET}"
            );
        }
    }
    let resultats = scan::scanner_ports(&vivantes, &ports, delai, parallele).await;
    let noms = join_all(vivantes.iter().map(|&ip| scan::nom_hote(ip))).await;
    let arp = scan::table_arp();
    let fabricants = scan::base_fabricants();

    let (mut base, chemins, _verrou) = Base::charger();
    // Le carnet de ce réseau : reconnu à la MAC de la box, sinon à la plage d'adresses.
    let id_reseau = gw
        .and_then(|g| arp.get(&g).cloned())
        .unwrap_or_else(|| format!("plage {cible}"));
    let nom_reseau = scan::nom_wifi();
    if !base.appareils.is_empty() {
        let anciens = std::mem::take(&mut base.appareils);
        let carnet = base.reseaux.entry(id_reseau.clone()).or_default();
        for (cle, a) in anciens {
            carnet.appareils.entry(cle).or_insert(a);
        }
    }
    let histo = base.reseaux.entry(id_reseau.clone()).or_default();
    let premier_scan = histo.appareils.is_empty();
    // Seul un scan du réseau entier sur les ports courants se compare aux précédents.
    let scan_comparable = ips.len() > 1 && o.ports == "courants";
    // Un port hors de la liste courante n'a jamais pu être vu par les scans précédents : pas de faux « nouveau ».
    let comparable = |port: u16| PORTS_COURANTS.contains(&port);
    // Une machine est reconnue par sa MAC (l'IP DHCP peut changer), sinon par son IP.
    let cle = |ip: Ipv4Addr, mac: &Option<String>| mac.clone().unwrap_or_else(|| ip.to_string());
    // Pour cette machine (ou 127.0.0.1), on sait quel programme tient chaque port.
    let programmes = crate::machine::programmes_en_ecoute();

    let mut hotes: Vec<Hote> = resultats
        .into_iter()
        .zip(noms)
        .map(|((ip, ouverts), nom)| {
            let mac = arp.get(&ip).cloned();
            let connu = histo.appareils.get(&cle(ip, &mac));
            let ports: Vec<PortOuvert> = ouverts
                .into_iter()
                .map(|(port, banniere)| {
                    // Port non répertorié : on se fie à ce que le service annonce (SSH sur 2222, web sur 9999…).
                    let type_port = match info_port(port).service {
                        "Inconnu" => banniere.as_deref().and_then(identifier).unwrap_or(port),
                        _ => port,
                    };
                    let i = info_port(type_port);
                    let nouveau = scan_comparable
                        && !premier_scan
                        && comparable(port)
                        && !connu.is_some_and(|c| c.ports.contains(&port));
                    let programme = (Some(ip) == moi || ip.is_loopback())
                        .then(|| programmes.get(&port).cloned())
                        .flatten();
                    PortOuvert {
                        port,
                        service: i.service,
                        niveau: i.niveau,
                        banniere,
                        conseil: i.conseil,
                        nouveau,
                        programme,
                    }
                })
                .collect();
            let role = if Some(ip) == gw {
                Some("passerelle")
            } else if Some(ip) == moi {
                Some("cette machine")
            } else {
                None
            };
            let alertes = alertes(role, &ports);
            let score = 100u32.saturating_sub(alertes.iter().map(|(n, _)| n.penalite()).sum());
            Hote {
                ip,
                nom,
                fabricant: mac.as_deref().and_then(|m| scan::fabricant(m, &fabricants)),
                surnom: connu.and_then(|c| c.surnom.clone()),
                premier_vu: connu.and_then(|c| c.premier_vu.clone()),
                mac,
                role,
                nouvelle: scan_comparable && !premier_scan && connu.is_none(),
                ports,
                alertes,
                score,
            }
        })
        .collect();
    hotes.sort_by_key(|h| h.ip);

    let mut absents = Vec::new();
    // On ne mémorise que les scans du réseau complet avec les ports par défaut, pour comparer ce qui est comparable.
    if scan_comparable {
        let presents: BTreeSet<String> = hotes.iter().map(|h| cle(h.ip, &h.mac)).collect();
        absents = histo
            .appareils
            .iter()
            .filter(|(k, _)| !presents.contains(*k))
            .map(|(_, a)| Absent {
                ip: a.ip,
                titre: a.titre(),
                dernier_vu: a.dernier_vu.clone(),
            })
            .collect();
        let jour = aujourd_hui();
        for h in &hotes {
            let a = histo
                .appareils
                .entry(cle(h.ip, &h.mac))
                .or_insert_with(|| AppareilConnu {
                    ip: h.ip,
                    nom: None,
                    fabricant: None,
                    ports: BTreeSet::new(),
                    surnom: None,
                    premier_vu: Some(jour.clone()),
                    dernier_vu: None,
                });
            a.ip = h.ip;
            a.nom = h.nom.clone().or(a.nom.take());
            a.fabricant = h.fabricant.clone();
            a.ports.extend(h.ports.iter().map(|p| p.port));
            a.premier_vu.get_or_insert_with(|| jour.clone());
            a.dernier_vu = Some(jour.clone());
        }
        if nom_reseau.is_some() {
            histo.nom = nom_reseau.clone();
        }
        base.enregistrer(&chemins);
    }

    let score_global = hotes.iter().map(|h| h.score).min().unwrap_or(100);
    let rapport = Rapport {
        reseau: cible,
        nom_reseau: nom_reseau.or_else(|| base.reseaux.get(&id_reseau).and_then(|r| r.nom.clone())),
        absents,
        duree_s: debut.elapsed().as_secs_f64(),
        score_global,
        note: note(score_global),
        hotes,
    };

    if o.json {
        println!("{}", serde_json::to_string_pretty(&rapport).unwrap_or_default());
    } else if bavard {
        afficher(&rapport);
    }
    Ok(rapport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listes_de_ports() {
        assert_eq!(parse_ports("22, 80,8000-8002").unwrap(), vec![22, 80, 8000, 8001, 8002]);
        assert_eq!(parse_ports("tous").unwrap().len(), 65535);
        assert_eq!(parse_ports("courants").unwrap(), PORTS_COURANTS);
        assert!(parse_ports("80,abc").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("100-10").is_err());
    }

    #[test]
    fn ancienne_base_toujours_lisible() {
        // Format de la v0.1 à la v0.3 : un seul carnet, sans surnom ni dates.
        let ancien = r#"{"appareils":{"c4:34:6b:12:34:56":{"ip":"10.0.0.138","nom":null,"fabricant":"Hewlett Packard","ports":[135,445]}}}"#;
        let base: Base = serde_json::from_str(ancien).unwrap();
        let a = &base.appareils["c4:34:6b:12:34:56"];
        assert_eq!(a.ports.len(), 2);
        assert!(a.surnom.is_none() && a.premier_vu.is_none());
        // Une fois migré, l'ancien champ n'est plus écrit.
        let migre = Base {
            reseaux: BTreeMap::from([(
                "box".into(),
                ReseauConnu {
                    nom: None,
                    appareils: base.appareils,
                },
            )]),
            appareils: BTreeMap::new(),
        };
        assert!(
            !serde_json::to_value(&migre)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("appareils")
        );
    }

    #[test]
    fn base_avec_bom_ou_abimee() {
        let dossier = std::env::temp_dir().join(format!("netscan-base-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let p = dossier.join("appareils.json");
        std::fs::write(
            &p,
            "\u{feff}{\"reseaux\":{\"box\":{\"nom\":\"Salon\",\"appareils\":{}}}}",
        )
        .unwrap();
        assert_eq!(Base::lire(&p).reseaux["box"].nom.as_deref(), Some("Salon"));
        std::fs::write(&p, "{ abîmé").unwrap();
        assert!(Base::lire(&p).reseaux.is_empty());
        // La base abîmée est gardée de côté, pas perdue.
        let copies = std::fs::read_dir(&dossier)
            .unwrap()
            .filter(|f| f.as_ref().unwrap().file_name().to_string_lossy().contains("illisible"))
            .count();
        assert_eq!(copies, 1);
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    #[test]
    fn ecriture_atomique_et_verrou() {
        let dossier = std::env::temp_dir().join(format!("netscan-atomique-{}", std::process::id()));
        let fichier = dossier.join("appareils.json");
        ecrire_atomique(&fichier, "{\"reseaux\":{}}").unwrap();
        ecrire_atomique(&fichier, "{\"reseaux\":{\"box\":{\"nom\":null,\"appareils\":{}}}}").unwrap();
        assert!(Base::lire(&fichier).reseaux.contains_key("box"));
        // Aucun fichier temporaire ne traîne.
        assert_eq!(std::fs::read_dir(&dossier).unwrap().count(), 1);
        // Le verrou est exclusif tant qu'il est gardé, et libéré à la fin.
        let v = Verrou::prendre(&dossier).unwrap();
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&v.0)
                .is_err()
        );
        let chemin = v.0.clone();
        drop(v);
        assert!(!chemin.exists());
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    #[test]
    fn fusion_cle_et_copie_locale() {
        let fiche = |ports: &[u16], premier: &str, dernier: &str, surnom: Option<&str>, ip: [u8; 4]| AppareilConnu {
            ip: Ipv4Addr::from(ip),
            nom: None,
            fabricant: None,
            ports: ports.iter().copied().collect(),
            surnom: surnom.map(str::to_string),
            premier_vu: Some(premier.into()),
            dernier_vu: Some(dernier.into()),
        };
        let mut cle = fiche(
            &[80],
            "2026-10-16",
            "2026-10-16",
            Some("imprimante HP"),
            [10, 0, 0, 138],
        );
        cle.fusionner(fiche(&[445], "2026-09-01", "2026-10-20", None, [10, 0, 0, 140]));
        assert_eq!(cle.ports.len(), 2);
        assert_eq!(cle.premier_vu.as_deref(), Some("2026-09-01"));
        assert_eq!(cle.dernier_vu.as_deref(), Some("2026-10-20"));
        assert_eq!(cle.ip, Ipv4Addr::new(10, 0, 0, 140)); // l'IP la plus récente
        assert_eq!(cle.surnom.as_deref(), Some("imprimante HP"));
        assert_eq!(date_fr("2026-10-16"), "16/10/2026");
    }

    #[test]
    fn alertes_croisees() {
        let port = |p: u16| {
            let i = info_port(p);
            PortOuvert {
                port: p,
                service: i.service,
                niveau: i.niveau,
                banniere: None,
                conseil: i.conseil,
                nouveau: false,
                programme: None,
            }
        };
        let routeur = alertes(Some("passerelle"), &[port(80)]);
        assert!(routeur.iter().any(|(_, m)| m.contains("routeur")));
        let windows = alertes(None, &[port(139), port(445)]);
        assert!(windows.iter().any(|(_, m)| m.contains("SMBv1")));
        // La plus grave en premier.
        assert!(windows.windows(2).all(|w| w[0].0 >= w[1].0));
    }
}
