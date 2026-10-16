//! Scan du réseau : machines, ports ouverts, risques, et comparaison avec les scans précédents.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use futures::future::join_all;
use serde::{Deserialize, Serialize};

use crate::risk::{Niveau, PORTS_COURANTS, info_port, note};
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
        Options { cible, ports: ports.into(), timeout: 500, parallele: 512, json: false, silencieux: false }
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
}

#[derive(Serialize)]
pub struct Hote {
    pub ip: Ipv4Addr,
    pub nom: Option<String>,
    pub mac: Option<String>,
    pub fabricant: Option<String>,
    pub role: Option<&'static str>,
    pub nouvelle: bool,
    pub ports: Vec<PortOuvert>,
    pub alertes: Vec<(Niveau, String)>,
    pub score: u32,
}

impl Hote {
    pub fn titre(&self) -> String {
        [self.nom.as_deref(), self.fabricant.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

#[derive(Serialize)]
pub struct Rapport {
    pub reseau: String,
    pub duree_s: f64,
    pub score_global: u32,
    pub note: &'static str,
    pub hotes: Vec<Hote>,
}

/// Tous les appareils déjà vus sur le réseau, pour repérer les nouveaux venus.
#[derive(Serialize, Deserialize, Default)]
struct Historique {
    appareils: BTreeMap<String, AppareilConnu>,
}

#[derive(Serialize, Deserialize)]
struct AppareilConnu {
    ip: Ipv4Addr,
    nom: Option<String>,
    fabricant: Option<String>,
    /// Tous les ports déjà vus ouverts (union : un Chromecast en veille ne doit pas déclencher d'alerte au réveil).
    ports: BTreeSet<u16>,
}

/// Fichier témoin à la racine de la clé USB netscan.
pub const TEMOIN_CLE: &str = "netscan.cle";

/// Clé USB netscan branchée, si elle est trouvée (dossier racine contenant `netscan.cle`).
pub fn cle_usb() -> Option<PathBuf> {
    // D'abord : sommes-nous lancés depuis la clé ? (exe dans <clé>/Linux/, <clé>/Windows/…)
    let exe = std::env::current_exe().ok().and_then(|e| e.canonicalize().ok());
    let depuis_exe = exe.iter().flat_map(|e| e.ancestors().skip(1).take(2).map(PathBuf::from)).collect::<Vec<_>>();
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
    let montages: Vec<PathBuf> = std::fs::read_dir("/Volumes").into_iter().flatten().flatten().map(|d| d.path()).collect();
    #[cfg(windows)]
    let montages: Vec<PathBuf> = ('D'..='Z').map(|l| PathBuf::from(format!("{l}:\\"))).collect();
    depuis_exe.into_iter().chain(montages).find(|d| d.join(TEMOIN_CLE).is_file())
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
        match morceau.trim().split_once('-') {
            Some((a, b)) => {
                let (a, b): (u16, u16) = (a.parse().map_err(|_| err())?, b.parse().map_err(|_| err())?);
                ports.extend(a..=b);
            }
            None => ports.push(morceau.trim().parse().map_err(|_| err())?),
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
        alertes.push((Niveau::Moyen, "Admin du routeur uniquement en HTTP : le mot de passe passe en clair.".into()));
    }
    if a(139) && a(445) {
        alertes.push((Niveau::Moyen, "NetBIOS + SMB : vérifier que SMBv1 est désactivé.".into()));
    }
    for p in ports {
        if let Some(b) = &p.banniere {
            if b.starts_with("SSH-1.") {
                alertes.push((Niveau::Critique, format!("Port {} : SSH version 1, cassé depuis 2001.", p.port)));
            }
            if b.contains("vsFTPd 2.3.4") {
                alertes.push((Niveau::Critique, "vsFTPd 2.3.4 : version piégée (backdoor connue).".into()));
            }
        }
    }
    if ouverts.len() > 15 {
        alertes.push((Niveau::Moyen, format!("{} ports ouverts : surface d'attaque importante.", ouverts.len())));
    }
    alertes.sort_by(|a, b| b.0.cmp(&a.0));
    alertes
}

fn afficher(r: &Rapport) {
    titre(&format!("Réseau {}", r.reseau));
    for h in &r.hotes {
        let role = h.role.map(|r| format!(" [{r}]")).unwrap_or_default();
        let mac = h.mac.as_deref().map(|m| format!("  {GRIS}{m}{RESET}")).unwrap_or_default();
        let neuve = if h.nouvelle { format!("  {}NOUVEL APPAREIL{RESET}", couleur(Niveau::Moyen)) } else { String::new() };
        println!("\n{GRAS}● {}{RESET} {}{role}{mac}{neuve}", h.ip, h.titre());
        if h.ports.is_empty() {
            println!("    {GRIS}aucun port ouvert parmi ceux testés{RESET}");
        }
        for p in &h.ports {
            let b = p.banniere.as_deref().map(|b| format!("  {GRIS}« {b} »{RESET}")).unwrap_or_default();
            let nouv = if p.nouveau && !h.nouvelle { format!(" {}(nouveau){RESET}", couleur(Niveau::Moyen)) } else { String::new() };
            println!(
                "    {:>5}/tcp  {:<17} {}{:<8}{RESET}{nouv}{b}",
                p.port, p.service, couleur(p.niveau), p.niveau.libelle()
            );
        }
        for (n, msg) in &h.alertes {
            println!("    {}→{RESET} {msg}", couleur(*n));
        }
        println!("    {GRIS}score : {}/100{RESET}", h.score);
    }

    let compte = |n: Niveau| r.hotes.iter().flat_map(|h| &h.ports).filter(|p| p.niveau == n).count();
    titre("Bilan réseau");
    println!(
        "  {} appareils ({} nouveaux), {} ports ouverts — {}{} critiques{RESET}, {}{} élevés{RESET}, {}{} moyens{RESET}",
        r.hotes.len(),
        r.hotes.iter().filter(|h| h.nouvelle).count(),
        r.hotes.iter().map(|h| h.ports.len()).sum::<usize>(),
        couleur(Niveau::Critique), compte(Niveau::Critique),
        couleur(Niveau::Eleve), compte(Niveau::Eleve),
        couleur(Niveau::Moyen), compte(Niveau::Moyen),
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
        None => local.ok_or("impossible de détecter le réseau local ; précise une cible (ex. 192.168.1.0/24)")?.0,
    };
    let ips = scan::parse_cible(&cible)?;
    let ports = parse_ports(&o.ports)?;
    let delai = Duration::from_millis(o.timeout);
    let gw = scan::passerelle();

    if bavard {
        eprintln!("{GRAS}Scan réseau{RESET} — {cible} ({} adresses, {} ports chacune)", ips.len(), ports.len());
        eprintln!("{GRIS}Découverte des appareils…{RESET}");
    }
    let mut vivantes = if ips.len() == 1 {
        ips.clone()
    } else {
        scan::decouvrir(&ips, Duration::from_millis(o.timeout.min(400)), o.parallele).await
    };
    // Cette machine ne répond pas toujours à ses propres sondes sur l'IP du LAN.
    if let Some(m) = moi.filter(|m| ips.contains(m) && !vivantes.contains(m)) {
        vivantes.push(m);
        vivantes.sort();
    }

    if bavard {
        eprintln!("{GRIS}{} appareil(s) trouvé(s). Scan des ports…{RESET}", vivantes.len());
    }
    let resultats = scan::scanner_ports(&vivantes, &ports, delai, o.parallele).await;
    let noms = join_all(vivantes.iter().map(|&ip| scan::nom_hote(ip))).await;
    let arp = scan::table_arp();
    let base = scan::base_fabricants();

    let lire = |p: &PathBuf| -> Historique {
        std::fs::read_to_string(p).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    };
    let chemin = dossier_donnees().join("appareils.json");
    let mut histo = lire(&chemin);
    // Scans faits sans la clé : on les fusionne dans la base de la clé dès qu'elle est là.
    let local = dossier_local().join("appareils.json");
    if local != chemin {
        for (cle, a) in lire(&local).appareils {
            match histo.appareils.get_mut(&cle) {
                Some(connu) => connu.ports.extend(a.ports),
                None => {
                    histo.appareils.insert(cle, a);
                }
            }
        }
    }
    let premier_scan = histo.appareils.is_empty();
    // Une machine est reconnue par sa MAC (l'IP DHCP peut changer), sinon par son IP.
    let cle = |ip: Ipv4Addr, mac: &Option<String>| mac.clone().unwrap_or_else(|| ip.to_string());

    let mut hotes: Vec<Hote> = resultats
        .into_iter()
        .zip(noms)
        .map(|((ip, ouverts), nom)| {
            let mac = arp.get(&ip).cloned();
            let connu = histo.appareils.get(&cle(ip, &mac));
            let ports: Vec<PortOuvert> = ouverts
                .into_iter()
                .map(|(port, banniere)| {
                    let i = info_port(port);
                    let nouveau = !premier_scan && !connu.is_some_and(|c| c.ports.contains(&port));
                    PortOuvert { port, service: i.service, niveau: i.niveau, banniere, conseil: i.conseil, nouveau }
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
                fabricant: mac.as_deref().and_then(|m| scan::fabricant(m, &base)),
                mac,
                role,
                nouvelle: !premier_scan && connu.is_none(),
                ports,
                alertes,
                score,
            }
        })
        .collect();
    hotes.sort_by_key(|h| h.ip);

    // On ne mémorise que les scans du réseau complet avec les ports par défaut, pour comparer ce qui est comparable.
    if ips.len() > 1 && o.ports == "courants" {
        for h in &hotes {
            let a = histo.appareils.entry(cle(h.ip, &h.mac)).or_insert_with(|| AppareilConnu {
                ip: h.ip,
                nom: None,
                fabricant: None,
                ports: BTreeSet::new(),
            });
            a.ip = h.ip;
            a.nom = h.nom.clone().or(a.nom.take());
            a.fabricant = h.fabricant.clone();
            a.ports.extend(h.ports.iter().map(|p| p.port));
        }
        let json = serde_json::to_string_pretty(&histo).unwrap_or_default();
        // On écrit la base sur la clé ET en local : la copie locale sert quand la clé est absente.
        for p in [&chemin, &local] {
            if let Some(d) = p.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            let _ = std::fs::write(p, &json);
        }
    }

    let score_global = hotes.iter().map(|h| h.score).min().unwrap_or(100);
    let rapport = Rapport {
        reseau: cible,
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
