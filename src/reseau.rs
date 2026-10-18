//! Scan du réseau : machines, ports ouverts, risques, et comparaison avec les scans précédents.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use futures::future::join_all;
use serde::{Deserialize, Serialize};

use crate::risk::{Niveau, PORTS_COURANTS, PORTS_UDP, identifier, info_port, info_udp, note};
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
    /// Port UDP (sinon TCP).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub udp: bool,
}

impl PortOuvert {
    /// « 445/tcp », « 161/udp ».
    pub fn libelle(&self) -> String {
        format!("{}/{}", self.port, if self.udp { "udp" } else { "tcp" })
    }
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
    /// Redirections UPnP de la box (scan du réseau local seulement).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upnp: Option<crate::upnp::Etat>,
}

/// Délai par port de la revérification d'un appareil en veille (ms) : trois fois celui d'un scan.
const DELAI_PATIENT: u64 = 1500;

/// Appareils trouvés sans aucun port ouvert, alors que la base leur en a déjà vu : (adresse, ports déjà vus parmi ceux
/// de ce scan).
fn silencieux_a_revoir(
    resultats: &BTreeMap<Ipv4Addr, Vec<(u16, Option<String>)>>,
    connus: &BTreeMap<String, AppareilConnu>,
    cle: impl Fn(Ipv4Addr) -> String,
    ports: &[u16],
) -> Vec<(Ipv4Addr, Vec<u16>)> {
    resultats
        .iter()
        .filter(|(_, ouverts)| ouverts.is_empty())
        .filter_map(|(&ip, _)| {
            let deja_vus: Vec<u16> = connus
                .get(&cle(ip))?
                .ports
                .iter()
                .copied()
                .filter(|p| ports.contains(p))
                .collect();
            (!deja_vus.is_empty()).then_some((ip, deja_vus))
        })
        .collect()
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
    /// Ce réseau a déjà été scanné en UDP (depuis la 0.42) : avant, aucun port UDP n'est « nouveau ».
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    udp: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct AppareilConnu {
    ip: Ipv4Addr,
    nom: Option<String>,
    fabricant: Option<String>,
    /// Tous les ports déjà vus ouverts (union : un Chromecast en veille ne doit pas déclencher d'alerte au réveil).
    ports: BTreeSet<u16>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    ports_udp: BTreeSet<u16>,
    #[serde(default)]
    surnom: Option<String>,
    /// Quand le surnom a été donné ou retiré (« AAAA-MM-JJ HH:MM:SS ») : à la fusion clé + copie locale,
    /// le plus récent gagne, même s'il a été donné sans la clé.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    surnom_le: Option<String>,
    #[serde(default)]
    premier_vu: Option<String>,
    #[serde(default)]
    dernier_vu: Option<String>,
}

impl AppareilConnu {
    fn titre(&self) -> String {
        let fabricant = self.fabricant.as_deref().map(scan::fabricant_traduit);
        [self.surnom.as_deref(), self.nom.as_deref(), fabricant]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ")
    }

    /// Fusion de deux fiches du même appareil (base de la clé + copie locale).
    fn fusionner(&mut self, autre: AppareilConnu) {
        self.ports.extend(autre.ports);
        self.ports_udp.extend(autre.ports_udp);
        // None < Some : une fiche datée l'emporte sur une fiche d'avant la v0.9.6.
        if autre.surnom_le > self.surnom_le {
            self.surnom = autre.surnom;
            self.surnom_le = autre.surnom_le;
        } else if self.surnom_le.is_none() {
            self.surnom = self.surnom.take().or(autre.surnom);
        }
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
                tre!(
                    "Attention : base des appareils illisible ({e}). Copie gardée : {}",
                    "Warning: device database unreadable ({e}). Copy kept: {}",
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
        // Clé protégée en écriture (autre ordinateur) : sa base sert quand même, les ajouts restent ici.
        if let Some(protegee) = cle_protegee() {
            base.absorber(Base::lire(&protegee.join("donnees").join("appareils.json")));
        }
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
            mien.udp |= r.udp;
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
                tre!(
                    "Attention : base des appareils non enregistrée dans {} ({e}).",
                    "Warning: device database not saved to {} ({e}).",
                    p.display()
                );
            }
        }
    }
}

/// Écrit d'abord un fichier temporaire, le force sur le disque, puis le renomme à la place de l'ancien :
/// une coupure, un Ctrl-C ou une clé arrachée laissent soit l'ancienne base, soit la nouvelle, jamais une
/// base tronquée.
pub(crate) fn ecrire_atomique(chemin: &std::path::Path, contenu: &str) -> std::io::Result<()> {
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

/// Verrou entre processus Gardien (fichier créé de façon exclusive, retiré à la fin).
struct Verrou(PathBuf);

impl Verrou {
    /// Attend au plus 10 s. Un verrou de plus de 2 minutes vient d'un Gardien interrompu : on le reprend.
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
                        tre!(
                            "Attention : base des appareils occupée par un autre Gardien, enregistrement sans verrou.",
                            "Warning: device database locked by another Gardien, saving without a lock."
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

/// « 0 appareil », « 1 appareil », « 2 appareils » (en français, 0 et 1 sont au singulier).
fn accord(n: usize, singulier: &str, pluriel: &str) -> String {
    format!("{n} {}", if n > 1 { pluriel } else { singulier })
}

/// « 2026-10-16 » → « 16/10/2026 » (en anglais, la date ISO reste telle quelle : pas d'ambiguïté jour/mois).
pub fn date_fr(iso: &str) -> String {
    if crate::langue::anglais() {
        return iso.to_string();
    }
    let mut p = iso.split('-');
    match (p.next(), p.next(), p.next()) {
        (Some(a), Some(m), Some(j)) => format!("{j}/{m}/{a}"),
        _ => iso.to_string(),
    }
}

/// Ce que contient une base : réseaux, appareils, surnoms donnés.
pub struct Contenu {
    pub reseaux: usize,
    pub appareils: usize,
    pub surnoms: usize,
}

impl Base {
    fn contenu(&self) -> Contenu {
        let fiches = || {
            self.reseaux
                .values()
                .flat_map(|r| r.appareils.values())
                .chain(self.appareils.values())
        };
        Contenu {
            reseaux: self.reseaux.len(),
            appareils: fiches().count(),
            surnoms: fiches().filter(|a| a.surnom.is_some()).count(),
        }
    }
}

/// La base des appareils (clé et copie locale fusionnées), pour une sauvegarde.
pub fn base_pour_sauvegarde() -> (serde_json::Value, Contenu) {
    let (base, _, _verrou) = Base::charger();
    (serde_json::to_value(&base).unwrap_or_default(), base.contenu())
}

/// Ajoute une base sauvegardée à la base actuelle : fusion fiche par fiche (ports réunis, surnom le plus
/// récent, première et dernière dates), rien n'est effacé. Rend ce que contenait la sauvegarde.
pub fn restaurer_base(sauvegarde: serde_json::Value) -> Result<Contenu, String> {
    let autre: Base = serde_json::from_value(sauvegarde)
        .map_err(|e| trf!("base des appareils illisible ({e})", "device database unreadable ({e})"))?;
    let contenu = autre.contenu();
    let (mut base, chemins, _verrou) = Base::charger();
    base.absorber(autre);
    base.enregistrer(&chemins);
    Ok(contenu)
}

/// Donne (ou retire, avec `None`) un surnom à un appareil, désigné par son IP ou son adresse MAC.
pub fn nommer(qui: &str, surnom: Option<&str>) -> Result<String, String> {
    let (mut base, chemins, _verrou) = Base::charger();
    let qui_min = qui.to_ascii_lowercase();
    let mut trouves = 0;
    let mut decrit = String::new();
    let maintenant = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    // Par IP, seulement dans le réseau où l'on se trouve (la même IP existe chez chacun) ; par MAC, partout.
    // Même identifiant que le scan : MAC de la box, sinon « plage <réseau local> ». Sans ce repli, un réseau
    // dont la box n'a pas de MAC connue ne pouvait jamais nommer un appareil par son IP.
    let ici = scan::passerelle()
        .and_then(|gw| scan::table_arp().get(&gw).cloned())
        .or_else(|| scan::reseau_local().map(|(r, _)| trf!("plage {r}", "range {r}")));
    // La MAC qui répond à cette IP en ce moment : un appareil à deux adresses (box d'une VM, VPN) n'a qu'une fiche,
    // rangée sous sa MAC avec la dernière adresse vue ; nommé par l'autre adresse, il était introuvable (vu en VM).
    let mac_actuelle = qui
        .parse::<std::net::Ipv4Addr>()
        .ok()
        .and_then(|ip| scan::table_arp().get(&ip).cloned());
    for (id, r) in &mut base.reseaux {
        for (cle, a) in &mut r.appareils {
            let par_mac = cle.eq_ignore_ascii_case(&qui_min);
            let dans_ce_reseau = ici.as_deref() == Some(id.as_str());
            let par_ip = dans_ce_reseau
                && (a.ip.to_string() == qui || mac_actuelle.as_deref().is_some_and(|m| cle.eq_ignore_ascii_case(m)));
            if par_mac || par_ip {
                a.surnom = surnom.map(str::to_string);
                a.surnom_le = Some(maintenant.clone());
                trouves += 1;
                decrit = format!("{} ({cle})", a.ip);
            }
        }
    }
    if trouves == 0 {
        return Err(trf!(
            "aucun appareil « {qui} » dans la base : lance d'abord un scan du réseau (gardien reseau)",
            "no device “{qui}” in the database: first run a network scan (gardien network)"
        ));
    }
    base.enregistrer(&chemins);
    Ok(decrit)
}

/// Fichier témoin à la racine de la clé USB de Gardien.
pub const TEMOIN_CLE: &str = "gardien.cle";
/// Témoins des clés préparées sous les anciens noms (sentinel jusqu'à 0.50, netscan jusqu'à 0.10.0), renommés au
/// prochain déploiement.
pub const ANCIENS_TEMOINS_CLE: [&str; 2] = ["sentinel.cle", "netscan.cle"];

/// Volumes montés pour l'utilisateur, un sous-dossier par clé : /run/media/<utilisateur> (Arch, Fedora, openSUSE…)
/// et /media/<utilisateur> (Debian, Ubuntu, Mint), où udisks range les clés selon la distribution.
#[cfg(target_os = "linux")]
pub fn cles_montees() -> Vec<PathBuf> {
    std::env::var("USER")
        .ok()
        .into_iter()
        .flat_map(|u| [format!("/run/media/{u}"), format!("/media/{u}")])
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .map(|d| d.path())
        .collect()
}

/// Clé USB de Gardien branchée, si elle est trouvée (dossier racine contenant son témoin, ou celui d'un ancien nom).
pub fn cle_usb() -> Option<PathBuf> {
    // D'abord : sommes-nous lancés depuis la clé ? (exe dans <clé>/Linux/, <clé>/Windows/…)
    // Sous Linux et macOS, le programme peut tourner depuis une copie temporaire (protection de la clé) : on part
    // du programme d'origine.
    #[cfg(unix)]
    let exe = crate::protection::exe_d_origine();
    #[cfg(windows)]
    let exe = std::env::current_exe().ok().and_then(|e| e.canonicalize().ok());
    let depuis_exe = exe
        .iter()
        .flat_map(|e| e.ancestors().skip(1).take(2).map(PathBuf::from))
        .collect::<Vec<_>>();
    #[cfg(target_os = "linux")]
    let montages = cles_montees();
    #[cfg(target_os = "macos")]
    let montages: Vec<PathBuf> = std::fs::read_dir("/Volumes")
        .into_iter()
        .flatten()
        .flatten()
        .map(|d| d.path())
        .collect();
    #[cfg(windows)]
    let montages: Vec<PathBuf> = ('D'..='Z').map(|l| PathBuf::from(format!("{l}:\\"))).collect();
    depuis_exe.into_iter().chain(montages).find(|d| {
        std::iter::once(TEMOIN_CLE)
            .chain(ANCIENS_TEMOINS_CLE)
            .any(|t| d.join(t).is_file())
    })
}

/// La partition GARDIEN est en lecture seule sur les autres ordinateurs (attribut GPT respecté par Windows) :
/// on essaie d'y écrire plutôt que de deviner.
fn modifiable(dossier: &std::path::Path) -> bool {
    let essai = dossier.join(format!(".gardien-ecriture-{}", std::process::id()));
    let ok = std::fs::write(&essai, b"").is_ok();
    let _ = std::fs::remove_file(&essai);
    ok
}

/// Clé branchée mais protégée en écriture : on lit sa base, sans rien y écrire.
pub fn cle_protegee() -> Option<PathBuf> {
    cle_usb().filter(|c| !modifiable(c))
}

/// Données (historique des appareils, rapports) : sur la clé USB quand elle est branchée et modifiable,
/// pour qu'elles voyagent avec le programme ; sinon dans le dossier local de l'ordinateur.
pub fn dossier_donnees() -> PathBuf {
    cle_usb()
        .filter(|c| modifiable(c))
        .map_or_else(dossier_local, |c| c.join("donnees"))
}

/// Données propres à cet ordinateur (quarantaine antivirus : on ne transporte pas de malware sur une clé).
pub fn dossier_local() -> PathBuf {
    // Tests automatiques : un dossier jetable. Ils tournent sur l'ordinateur de développement : ses vraies données ne
    // doivent être ni lues, ni écrites, ni renommées (le renommage des anciens noms, plus bas, l'avait fait).
    if cfg!(test) {
        return std::env::temp_dir().join(format!("gardien-tests-{}", std::process::id()));
    }
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"));
    #[cfg(target_os = "linux")]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));
    let base = base.unwrap_or_default();
    let dossier = base.join("gardien");
    // Anciens noms (sentinel jusqu'à 0.50, netscan jusqu'à 0.10.0) : le dossier est renommé une fois, base,
    // historique et quarantaine compris.
    if !dossier.exists()
        && let Some(ancien) = ["sentinel", "netscan"]
            .iter()
            .map(|n| base.join(n))
            .find(|a| a.is_dir())
    {
        let _ = std::fs::rename(&ancien, &dossier);
    }
    dossier
}

fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    match spec {
        "courants" | "common" => return Ok(PORTS_COURANTS.to_vec()),
        "tous" | "all" => return Ok((1..=u16::MAX).collect()),
        _ => {}
    }
    let mut ports = Vec::new();
    for morceau in spec.split(',') {
        let err = || trf!("port invalide : {morceau}", "invalid port: {morceau}");
        // Port 0 impossible, et une plage à l'envers (« 100-10 ») ne doit pas devenir silencieusement vide.
        let port = |t: &str| t.trim().parse::<u16>().ok().filter(|&p| p > 0).ok_or_else(err);
        match morceau.trim().split_once('-') {
            Some((a, b)) => {
                let (a, b) = (port(a)?, port(b)?);
                if a > b {
                    return Err(trf!(
                        "plage de ports à l'envers : {morceau}",
                        "reversed port range: {morceau}"
                    ));
                }
                ports.extend(a..=b);
            }
            None => ports.push(port(morceau)?),
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// Alertes d'une machine : celles de chaque port, plus celles qui dépendent d'une combinaison.
fn alertes(role: Option<&str>, ports: &[PortOuvert]) -> Vec<(Niveau, String)> {
    let ouverts: Vec<u16> = ports.iter().filter(|p| !p.udp).map(|p| p.port).collect();
    let a = |p| ouverts.contains(&p);
    let mut alertes: Vec<(Niveau, String)> = ports
        .iter()
        .filter(|p| p.niveau >= Niveau::Moyen)
        .map(|p| {
            (
                p.niveau,
                trf!("{} ({}) : {}", "{} ({}): {}", p.service, p.libelle(), p.conseil),
            )
        })
        .collect();
    if role == Some("passerelle") && a(80) && !a(443) {
        alertes.push((
            Niveau::Moyen,
            tr!(
                "Admin du routeur uniquement en HTTP : le mot de passe passe en clair.",
                "Router admin only over HTTP: the password travels in clear text."
            )
            .into(),
        ));
    }
    if a(139) && a(445) {
        alertes.push((
            Niveau::Moyen,
            tr!(
                "NetBIOS + SMB : vérifier que SMBv1 est désactivé.",
                "NetBIOS + SMB: make sure SMBv1 is disabled."
            )
            .into(),
        ));
    }
    for p in ports {
        if let Some(b) = &p.banniere {
            if b.starts_with("SSH-1.") {
                alertes.push((
                    Niveau::Critique,
                    trf!(
                        "Port {} : SSH version 1, cassé depuis 2001.",
                        "Port {}: SSH version 1, broken since 2001.",
                        p.port
                    ),
                ));
            }
            if b.contains("vsFTPd 2.3.4") {
                alertes.push((
                    Niveau::Critique,
                    tr!(
                        "vsFTPd 2.3.4 : version piégée (backdoor connue).",
                        "vsFTPd 2.3.4: trojaned version (known backdoor)."
                    )
                    .into(),
                ));
            }
        }
    }
    if ouverts.len() > 15 {
        alertes.push((
            Niveau::Moyen,
            trf!(
                "{} ports ouverts : surface d'attaque importante.",
                "{} open ports: large attack surface.",
                ouverts.len()
            ),
        ));
    }
    alertes.sort_by_key(|a| std::cmp::Reverse(a.0));
    alertes
}

/// Port dynamique (49152 et plus) tenu par un processus système de Windows.
fn rpc_dynamique_windows(port: u16, programme: Option<&str>) -> bool {
    port >= 49152
        && programme.is_some_and(|p| ["lsass", "wininit", "services", "svchost", "spoolsv", "System"].contains(&p))
}

/// Signe d'usurpation ARP : un autre appareil répond avec l'adresse MAC de la box. Celui qui se fait passer pour
/// la box voit passer tout le trafic du réseau (attaque « de l'homme du milieu »). Rend (IP de la box, MAC, IP qui
/// la partage). Un répéteur Wi-Fi qui relaie pour la box peut donner le même signe : c'est un « possible ».
pub fn usurpation_arp(r: &Rapport) -> Option<(Ipv4Addr, String, Ipv4Addr)> {
    let boite = r.hotes.iter().find(|h| h.role == Some("passerelle"))?;
    let mac = boite.mac.as_deref()?;
    let autre = r
        .hotes
        .iter()
        .find(|h| h.ip != boite.ip && h.mac.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(mac)))?;
    Some((boite.ip, mac.to_string(), autre.ip))
}

/// Phrase d'alerte pour une usurpation ARP possible.
pub fn message_usurpation(boite: Ipv4Addr, mac: &str, autre: Ipv4Addr) -> String {
    trf!(
        "{autre} répond avec l'adresse MAC de la box ({boite}, {mac}) : quelqu'un se fait peut-être passer pour elle pour intercepter ton trafic (usurpation ARP). Sauf répéteur Wi-Fi connu, débranche cet appareil et redémarre la box.",
        "{autre} answers with the router's MAC address ({boite}, {mac}): someone may be impersonating it to intercept your traffic (ARP spoofing). Unless it is a known Wi-Fi repeater, unplug that device and restart the router."
    )
}

/// Niveau le plus grave des ports d'un appareil (`None` : aucun port ouvert).
fn pire_niveau(h: &Hote) -> Option<Niveau> {
    h.ports.iter().map(|p| p.niveau).max()
}

/// Pastille de couleur d'un appareil : verte sans port ouvert, sinon de la couleur de son port le plus grave.
fn pastille(h: &Hote) -> String {
    match pire_niveau(h) {
        None => format!("{VERT}●{RESET}"),
        Some(n) => format!("{}●{RESET}", couleur(n)),
    }
}

fn nom_affiche(h: &Hote) -> String {
    let t = h.titre();
    if t.is_empty() {
        tr!("appareil inconnu", "unknown device").to_string()
    } else {
        t
    }
}

fn afficher(r: &Rapport) {
    let nom = r
        .nom_reseau
        .as_deref()
        .map(|n| trf!(" « {n} »", " “{n}”"))
        .unwrap_or_default();
    println!();
    cadre(
        &format!(
            "{ACCENT}{}{RESET}{GRAS}{nom}{RESET}",
            tr!("RÉSEAU LOCAL", "LOCAL NETWORK")
        ),
        &format!("{GRIS}{} · {:.1} s{RESET}", r.reseau, r.duree_s),
    );
    let compte = |n: Niveau| r.hotes.iter().flat_map(|h| &h.ports).filter(|p| p.niveau == n).count();
    let nouveaux = r.hotes.iter().filter(|h| h.nouvelle).count();
    trp!(
        "  {GRAS}Note du réseau{RESET}  {}  {}  {GRIS}(appareil le plus exposé){RESET}",
        "  {GRAS}Network grade{RESET}   {}  {}  {GRIS}(most exposed device){RESET}",
        etiquette_note(r.score_global),
        barre(r.score_global)
    );
    let mut resume = vec![
        accord(r.hotes.len(), tr!("appareil", "device"), tr!("appareils", "devices")),
        accord(
            r.hotes.iter().map(|h| h.ports.len()).sum::<usize>(),
            tr!("port ouvert", "open port"),
            tr!("ports ouverts", "open ports"),
        ),
    ];
    if nouveaux > 0 {
        resume.push(format!(
            "{}{}{RESET}",
            couleur(Niveau::Moyen),
            accord(nouveaux, tr!("nouveau", "new"), tr!("nouveaux", "new"))
        ));
    }
    for (n, un, plusieurs) in [
        (
            Niveau::Critique,
            tr!("critique", "critical"),
            tr!("critiques", "critical"),
        ),
        (Niveau::Eleve, tr!("élevé", "high"), tr!("élevés", "high")),
        (Niveau::Moyen, tr!("moyen", "medium"), tr!("moyens", "medium")),
    ] {
        if compte(n) > 0 {
            resume.push(format!("{}{}{RESET}", couleur(n), accord(compte(n), un, plusieurs)));
        }
    }
    println!("  {}", resume.join(&format!(" {GRIS}·{RESET} ")));
    if let Some((boite, mac, autre)) = usurpation_arp(r) {
        println!();
        for (i, l) in envelopper(&message_usurpation(boite, &mac, autre), LARGEUR - 6)
            .iter()
            .enumerate()
        {
            let marque = if i == 0 {
                format!("{}✖{RESET}", couleur(Niveau::Critique))
            } else {
                " ".to_string()
            };
            println!("  {marque} {l}");
        }
    }

    section(&trf!("APPAREILS ({})", "DEVICES ({})", r.hotes.len()));
    for h in &r.hotes {
        let etiquette = if h.nouvelle {
            format!("{}{}{RESET}", couleur(Niveau::Moyen), ajuster(tr!("NOUVEAU", "NEW"), 8))
        } else if let Some(role) = h.role {
            let court = match role {
                "passerelle" => tr!("box", "router"),
                "cette machine" => tr!("toi", "you"),
                autre => autre,
            };
            format!("{ACCENT}{}{RESET}", ajuster(&format!("[{court}]"), 8))
        } else {
            " ".repeat(8)
        };
        let ports = match h.ports.len() {
            0 => format!("{DISCRET}{}{RESET}", ajuster("—", 8)),
            1 => ajuster(tr!("1 port", "1 port"), 8),
            n => ajuster(&trf!("{n} ports", "{n} ports"), 8),
        };
        println!(
            "  {} {GRAS}{:<15}{RESET} {} {etiquette}{ports}{}",
            pastille(h),
            h.ip.to_string(),
            ajuster(&nom_affiche(h), 33),
            etiquette_note(h.score)
        );
    }

    // Détail des appareils qui demandent une action, le plus exposé d'abord.
    let mut a_regarder: Vec<&Hote> = r
        .hotes
        .iter()
        .filter(|h| pire_niveau(h).is_some_and(|n| n >= Niveau::Moyen) || h.nouvelle)
        .collect();
    a_regarder.sort_by_key(|h| h.score);
    if !a_regarder.is_empty() {
        section(tr!("À REGARDER", "WORTH A LOOK"));
        for h in a_regarder {
            let mac = h.mac.as_deref().map(|m| format!(" · {m}")).unwrap_or_default();
            let depuis = match (&h.premier_vu, h.nouvelle) {
                (Some(d), false) => trf!(" · connu depuis le {}", " · known since {}", date_fr(d)),
                (_, true) => tr!(" · vu pour la première fois", " · seen for the first time").to_string(),
                _ => String::new(),
            };
            println!(
                "\n  {} {GRAS}{}{RESET}  {}  {}",
                pastille(h),
                h.ip,
                nom_affiche(h),
                etiquette_note(h.score)
            );
            let infos = format!("{mac}{depuis}");
            if let Some(infos) = infos.strip_prefix(" · ") {
                println!("    {DISCRET}{infos}{RESET}");
            }
            for p in &h.ports {
                let nouveau = if p.nouveau && !h.nouvelle {
                    format!(" {}{}{RESET}", couleur(Niveau::Moyen), tr!("nouveau", "new"))
                } else {
                    String::new()
                };
                let programme = p
                    .programme
                    .as_deref()
                    .map(|n| format!("  {DISCRET}{n}{RESET}"))
                    .unwrap_or_default();
                println!(
                    "    {:>9}  {}{}{:<8}{RESET}{nouveau}{programme}",
                    p.libelle(),
                    ajuster(p.service, 16),
                    couleur(p.niveau),
                    p.niveau.libelle()
                );
            }
            for (n, msg) in &h.alertes {
                for (i, ligne) in envelopper(msg, LARGEUR - 8).iter().enumerate() {
                    let fleche = if i == 0 {
                        format!("{}→{RESET}", couleur(*n))
                    } else {
                        " ".to_string()
                    };
                    println!("    {fleche} {ligne}");
                }
            }
        }
    }

    // Ports sans danger particulier (diffusion, découverte) : une ligne par appareil suffit.
    let autres: Vec<&Hote> = r
        .hotes
        .iter()
        .filter(|h| pire_niveau(h) == Some(Niveau::Info) && !h.nouvelle)
        .collect();
    if !autres.is_empty() {
        section(tr!("AUTRES PORTS OUVERTS", "OTHER OPEN PORTS"));
        for h in autres {
            let ports: Vec<String> = h
                .ports
                .iter()
                .map(|p| format!("{}{} {}", p.port, if p.udp { "/udp" } else { "" }, p.service))
                .collect();
            afficher_aligne(
                &format!(
                    "  {} {:<15} {}  ",
                    pastille(h),
                    h.ip.to_string(),
                    ajuster(&nom_affiche(h), 26)
                ),
                &ports.join(", "),
                48,
                DISCRET,
            );
        }
    }

    if let Some(e) = &r.upnp {
        crate::upnp::afficher(e);
    }

    if !r.absents.is_empty() {
        section(&trf!("ABSENTS AUJOURD'HUI ({})", "ABSENT TODAY ({})", r.absents.len()));
        for a in &r.absents {
            let quand = a
                .dernier_vu
                .as_deref()
                .map(|d| trf!("vu le {}", "seen on {}", date_fr(d)))
                .unwrap_or_default();
            println!(
                "  {DISCRET}○ {:<15} {}  {quand}{RESET}",
                a.ip.to_string(),
                ajuster(&a.titre, 30)
            );
        }
    }
    // Chemins du menu depuis la 0.43 (groupe 5 « Réseau et Internet »), et la même chose en ligne de commande.
    println!();
    afficher_aligne(
        "  ",
        tr!(
            "Astuce : menu 5 › 3 pour nommer un appareil (gardien nommer <ip> <surnom>), 5 › 2 pour scanner tous ses ports (gardien reseau <ip> -p tous).",
            "Tip: menu 5 › 3 to name a device (gardien name <ip> <nickname>), 5 › 2 to scan all its ports (gardien network <ip> -p all)."
        ),
        2,
        DISCRET,
    );
}

/// Lance le scan réseau et retourne le rapport.
pub async fn executer(o: Options) -> Result<Rapport, String> {
    let bavard = !o.json && !o.silencieux;
    let debut = Instant::now();
    let reseau_local = o.cible.is_none();
    let local = scan::reseau_local();
    let moi = local.as_ref().map(|l| l.1);
    let cible = match o.cible {
        Some(c) => c,
        None => {
            local
                .ok_or(tr!(
                    "impossible de détecter le réseau local ; précise une cible (ex. 192.168.1.0/24)",
                    "cannot detect the local network; give a target (e.g. 192.168.1.0/24)"
                ))?
                .0
        }
    };
    let ips = scan::parse_cible(&cible)?;
    let ports = parse_ports(&o.ports)?;
    let delai = Duration::from_millis(o.timeout);
    let gw = scan::passerelle();
    let parallele = scan::limite_connexions(o.parallele);

    if bavard {
        tre!(
            "{GRAS}Scan réseau{RESET} — {cible} ({} adresse(s), {} ports chacune)",
            "{GRAS}Network scan{RESET} — {cible} ({} address(es), {} ports each)",
            ips.len(),
            ports.len()
        );
        tre!(
            "{GRIS}Découverte des appareils…{RESET}",
            "{GRIS}Discovering devices…{RESET}"
        );
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
        tre!(
            "{GRIS}{} appareil(s) trouvé(s). Scan des ports…{RESET}",
            "{GRIS}{} device(s) found. Scanning ports…{RESET}",
            vivantes.len()
        );
        if ips.iter().all(std::net::Ipv4Addr::is_loopback) {
            tre!(
                "{GRIS}Note : 127.0.0.1 montre aussi les services réservés à cette machine. Pour ce qui est vraiment exposé au réseau : gardien machine.{RESET}",
                "{GRIS}Note: 127.0.0.1 also shows services reserved to this machine. For what is really exposed to the network: gardien machine.{RESET}"
            );
        }
    }
    let mut resultats = scan::scanner_ports(&vivantes, &ports, delai, parallele).await;
    // Listes nommées, en français ou en anglais (comme parse_ports).
    let courants = matches!(o.ports.as_str(), "courants" | "common");
    let tous = matches!(o.ports.as_str(), "tous" | "all");
    // UDP : quelques services qui se taisent en TCP (SNMP, NetBIOS, UPnP…), avec les listes de ports par défaut.
    let avec_udp = courants || tous;
    let mut resultats_udp = if avec_udp {
        scan::scanner_udp(&vivantes, PORTS_UDP, Duration::from_millis(o.timeout.clamp(800, 1500))).await
    } else {
        BTreeMap::new()
    };
    let noms = join_all(vivantes.iter().map(|&ip| scan::nom_hote(ip))).await;
    let arp = scan::table_arp();

    let (mut base, chemins, _verrou) = Base::charger();
    // Le carnet de ce réseau : reconnu à la MAC de la box, sinon à la plage d'adresses.
    let id_reseau = gw
        .and_then(|g| arp.get(&g).cloned())
        .unwrap_or_else(|| trf!("plage {cible}", "range {cible}"));
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
    let udp_deja_vu = histo.udp;
    // Seul un scan du réseau entier sur les ports courants se compare aux précédents.
    let scan_comparable = ips.len() > 1 && courants;
    // Un port hors de la liste courante n'a jamais pu être vu par les scans précédents : pas de faux « nouveau ».
    let comparable = |port: u16| PORTS_COURANTS.contains(&port);
    // Une machine est reconnue par sa MAC (l'IP DHCP peut changer), sinon par son IP.
    let cle = |ip: Ipv4Addr, mac: &Option<String>| mac.clone().unwrap_or_else(|| ip.to_string());
    // Pour cette machine (ou 127.0.0.1), on sait quel programme tient chaque port.
    let programmes = crate::machine::programmes_en_ecoute();
    // Ce que Gardien a appris des scans d'avant : un appareil connu qui paraît soudain tout fermé est souvent en
    // veille, lent à répondre. Ses ports déjà vus sont revérifiés avec plus de patience : quelques essais ajoutés,
    // aucun retiré.
    if scan_comparable {
        let a_revoir = silencieux_a_revoir(
            &resultats,
            &histo.appareils,
            |ip| cle(ip, &arp.get(&ip).cloned()),
            &ports,
        );
        if bavard && !a_revoir.is_empty() {
            tre!(
                "{GRIS}{} appareil(s) connu(s) silencieux : leurs ports déjà vus sont revérifiés plus patiemment (veille ?).{RESET}",
                "{GRIS}{} known device(s) silent: their ports seen before are checked again more patiently (asleep?).{RESET}",
                a_revoir.len()
            );
        }
        for (ip, connus) in a_revoir {
            let trouves = scan::scanner_ports(&[ip], &connus, Duration::from_millis(DELAI_PATIENT), parallele).await;
            if let Some(ouverts) = trouves.get(&ip).filter(|o| !o.is_empty()) {
                resultats.insert(ip, ouverts.clone());
            }
        }
    }

    let mut hotes: Vec<Hote> =
        resultats
            .into_iter()
            .zip(noms)
            .map(|((ip, ouverts), nom)| {
                let mac = arp.get(&ip).cloned();
                let connu = histo.appareils.get(&cle(ip, &mac));
                let ports: Vec<PortOuvert> = ouverts
                .into_iter()
                .map(|(port, banniere)| {
                    // Port non répertorié : on se fie à ce que le service annonce (SSH sur 2222, web sur 9999…).
                    let type_port = if info_port(port).service == crate::risk::inconnu() {
                        banniere.as_deref().and_then(identifier).unwrap_or(port)
                    } else {
                        port
                    };
                    let i = info_port(type_port);
                    let nouveau = scan_comparable
                        && !premier_scan
                        && comparable(port)
                        && !connu.is_some_and(|c| c.ports.contains(&port));
                    let programme = (Some(ip) == moi || ip.is_loopback())
                        .then(|| programmes.get(&port).cloned())
                        .flatten();
                    // Ports dynamiques RPC ouverts par Windows lui-même (vu en test dans la VM : 49664 et suivants,
                    // tenus par lsass, wininit, services, svchost, spoolsv) : normaux, pas « inconnus moyens ».
                    if i.service == crate::risk::inconnu() && rpc_dynamique_windows(port, programme.as_deref()) {
                        return PortOuvert {
                            port,
                            service: tr!("RPC de Windows", "Windows RPC"),
                            niveau: Niveau::Info,
                            banniere,
                            conseil: tr!(
                                "Port dynamique ouvert par Windows pour ses services : normal, filtré par le pare-feu.",
                                "Dynamic port opened by Windows for its services: normal, filtered by the firewall."
                            ),
                            nouveau,
                            programme,
                            udp: false,
                        };
                    }
                    PortOuvert {
                        port,
                        service: i.service,
                        niveau: i.niveau,
                        banniere,
                        conseil: i.conseil,
                        nouveau,
                        programme,
                        udp: false,
                    }
                })
                .chain(resultats_udp.remove(&ip).unwrap_or_default().into_iter().map(|(port, banniere)| {
                    let i = info_udp(port);
                    PortOuvert {
                        port,
                        service: i.service,
                        niveau: i.niveau,
                        banniere,
                        conseil: i.conseil,
                        nouveau: scan_comparable
                            && !premier_scan
                            && udp_deja_vu
                            && !connu.is_some_and(|c| c.ports_udp.contains(&port)),
                        programme: None,
                        udp: true,
                    }
                }))
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
                    fabricant: mac.as_deref().and_then(scan::fabricant),
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
                    ports_udp: BTreeSet::new(),
                    surnom: None,
                    surnom_le: None,
                    premier_vu: Some(jour.clone()),
                    dernier_vu: None,
                });
            a.ip = h.ip;
            a.nom = h.nom.clone().or(a.nom.take());
            a.fabricant.clone_from(&h.fabricant);
            a.ports.extend(h.ports.iter().filter(|p| !p.udp).map(|p| p.port));
            a.ports_udp.extend(h.ports.iter().filter(|p| p.udp).map(|p| p.port));
            a.premier_vu.get_or_insert_with(|| jour.clone());
            a.dernier_vu = Some(jour.clone());
        }
        if nom_reseau.is_some() {
            histo.nom.clone_from(&nom_reseau);
        }
        histo.udp |= avec_udp;
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
        upnp: reseau_local.then(crate::upnp::etat),
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

    fn hote(ip: &str, mac: &str, role: Option<&'static str>) -> Hote {
        Hote {
            ip: ip.parse().unwrap(),
            nom: None,
            mac: Some(mac.into()),
            fabricant: None,
            surnom: None,
            premier_vu: None,
            role,
            nouvelle: false,
            ports: Vec::new(),
            alertes: Vec::new(),
            score: 100,
        }
    }

    fn rapport(hotes: Vec<Hote>) -> Rapport {
        Rapport {
            reseau: "10.0.0.0/24".into(),
            nom_reseau: Some("Maison".into()),
            absents: Vec::new(),
            duree_s: 1.0,
            score_global: 100,
            note: "A",
            hotes,
            upnp: None,
        }
    }

    #[test]
    fn ports_rpc_de_windows() {
        assert!(rpc_dynamique_windows(49664, Some("lsass")));
        assert!(!rpc_dynamique_windows(49664, Some("steam")));
        assert!(!rpc_dynamique_windows(8080, Some("svchost")));
        assert!(!rpc_dynamique_windows(49664, None));
    }

    #[test]
    fn usurpation_de_la_box() {
        let sain = rapport(vec![
            hote("10.0.0.1", "f8:79:0a:0d:03:a2", Some("passerelle")),
            hote("10.0.0.50", "aa:bb:cc:dd:ee:ff", None),
        ]);
        assert!(usurpation_arp(&sain).is_none());
        let usurpe = rapport(vec![
            hote("10.0.0.1", "aa:bb:cc:dd:ee:ff", Some("passerelle")),
            hote("10.0.0.50", "AA:BB:CC:DD:EE:FF", None),
        ]);
        let (boite, _, autre) = usurpation_arp(&usurpe).unwrap();
        assert_eq!(
            (boite.to_string(), autre.to_string()),
            ("10.0.0.1".into(), "10.0.0.50".into())
        );
    }

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
    fn absent_dans_la_langue_du_jour() {
        // Noté par un scan en anglais, montré dans un écran en français.
        let note = r#"{"ip":"10.0.0.4","nom":null,"fabricant":"random MAC (phone/tablet?)","ports":[]}"#;
        let a: AppareilConnu = serde_json::from_str(note).unwrap();
        assert_eq!(a.titre(), "MAC aléatoire (téléphone/tablette ?)");
        assert_eq!(scan::fabricant_traduit("Intel Corporate"), "Intel Corporate");
    }

    #[test]
    fn appareils_en_veille_revus() {
        let ip = |d: u8| Ipv4Addr::new(10, 0, 0, d);
        let connu = |ports: &[u16]| AppareilConnu {
            ip: ip(1),
            nom: None,
            fabricant: None,
            ports: ports.iter().copied().collect(),
            ports_udp: BTreeSet::new(),
            surnom: None,
            surnom_le: None,
            premier_vu: None,
            dernier_vu: None,
        };
        let resultats = BTreeMap::from([
            (ip(2), vec![]),           // connu, ports déjà vus, muet : à revoir
            (ip(3), vec![(80, None)]), // répond : rien à revoir
            (ip(4), vec![]),           // jamais vu de port ouvert : rien à revoir
            (ip(5), vec![]),           // inconnu de la base
        ]);
        let connus = BTreeMap::from([
            ("aa".to_string(), connu(&[22, 8009, 60000])),
            ("bb".to_string(), connu(&[80])),
            ("cc".to_string(), connu(&[])),
        ]);
        let cle = |i: Ipv4Addr| match i.octets()[3] {
            2 => "aa".to_string(),
            3 => "bb".to_string(),
            4 => "cc".to_string(),
            _ => i.to_string(),
        };
        // 60000 n'est pas dans les ports de ce scan : pas revérifié.
        assert_eq!(
            silencieux_a_revoir(&resultats, &connus, cle, &[22, 80, 8009]),
            [(ip(2), vec![22, 8009])]
        );
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
                    udp: false,
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
        let dossier = std::env::temp_dir().join(format!("gardien-base-{}", std::process::id()));
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
        let dossier = std::env::temp_dir().join(format!("gardien-atomique-{}", std::process::id()));
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
            ports_udp: BTreeSet::new(),
            surnom: surnom.map(str::to_string),
            surnom_le: None,
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

        // Surnom changé sans la clé (copie locale plus récente) : il remplace celui de la clé.
        let date = |mut f: AppareilConnu, le: &str| {
            f.surnom_le = Some(le.into());
            f
        };
        let mut cle = date(
            fiche(&[], "2026-10-16", "2026-10-16", Some("ancien"), [10, 0, 0, 5]),
            "2026-10-16 10:00:00",
        );
        cle.fusionner(date(
            fiche(&[], "2026-10-16", "2026-10-16", Some("nouveau"), [10, 0, 0, 5]),
            "2026-10-17 09:00:00",
        ));
        assert_eq!(cle.surnom.as_deref(), Some("nouveau"));
        // Surnom retiré plus récemment : le retrait gagne aussi.
        cle.fusionner(date(
            fiche(&[], "2026-10-16", "2026-10-16", None, [10, 0, 0, 5]),
            "2026-10-17 12:00:00",
        ));
        assert_eq!(cle.surnom, None);
        // Une fiche plus ancienne ou sans date ne l'écrase pas.
        cle.fusionner(fiche(&[], "2026-10-16", "2026-10-16", Some("vieux"), [10, 0, 0, 5]));
        assert_eq!(cle.surnom, None);
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
                udp: false,
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
