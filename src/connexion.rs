//! Test de connexion pour le jeu : latence (ping), gigue, pertes vers la box et vers Internet, débit, et
//! bufferbloat (le lag qui arrive dès que quelqu'un télécharge ou envoie un fichier sur le réseau).
//! La latence se mesure par le temps d'établissement d'une connexion TCP : sans droits admin, sur tout système.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::risk::Niveau;
use crate::ui::*;

/// Serveur de référence sur Internet (Cloudflare, présent dans presque toutes les villes).
const INTERNET: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
const TELECHARGEMENT: &str = "https://speed.cloudflare.com/__down?bytes=25000000";
const ENVOI: &str = "https://speed.cloudflare.com/__up";
/// Volume maximal d'un test de débit, dans chaque sens.
const PLAFOND: u64 = 500_000_000;

/// Une série de mesures : temps en millisecondes, `None` pour un paquet perdu (pas de réponse en 1 s).
struct Serie(Vec<Option<f64>>);

impl Serie {
    fn recus(&self) -> Vec<f64> {
        self.0.iter().flatten().copied().collect()
    }

    fn mediane(&self) -> Option<f64> {
        let mut t = self.recus();
        if t.is_empty() {
            return None;
        }
        t.sort_by(f64::total_cmp);
        Some(t[t.len() / 2])
    }

    /// Gigue : écart moyen entre deux mesures successives.
    fn gigue(&self) -> f64 {
        let t = self.recus();
        if t.len() < 2 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let n = (t.len() - 1) as f64;
        t.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / n
    }

    fn pertes(&self) -> f64 {
        if self.0.is_empty() {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let p = self.0.iter().filter(|m| m.is_none()).count() as f64 * 100.0 / self.0.len() as f64;
        p
    }
}

/// Temps d'établissement d'une connexion TCP. Un refus (« port fermé ») répond aussi vite qu'une acceptation :
/// il compte comme une réponse.
async fn sonder(cible: SocketAddr) -> Option<f64> {
    let debut = Instant::now();
    match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(cible)).await {
        Ok(Ok(_)) => Some(debut.elapsed().as_secs_f64() * 1000.0),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(debut.elapsed().as_secs_f64() * 1000.0),
        _ => None,
    }
}

async fn serie(cible: SocketAddr, nombre: usize, arret: Option<&AtomicBool>) -> Serie {
    let mut mesures = Vec::new();
    for _ in 0..nombre {
        if arret.is_some_and(|a| a.load(Ordering::Relaxed)) {
            break;
        }
        let debut = Instant::now();
        mesures.push(sonder(cible).await);
        tokio::time::sleep(Duration::from_millis(200).saturating_sub(debut.elapsed())).await;
    }
    Serie(mesures)
}

/// Port de la box qui répond (même par un refus) : web, HTTPS ou DNS.
async fn port_de_la_box(ip: Ipv4Addr) -> Option<SocketAddr> {
    for port in [80, 443, 53] {
        let cible = SocketAddr::new(IpAddr::V4(ip), port);
        if sonder(cible).await.is_some() {
            return Some(cible);
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq)]
enum Sens {
    Reception,
    Envoi,
}

/// Charge la connexion dans un sens pendant `duree` (4 transferts curl à la fois, 500 Mo au plus) et rend le débit
/// en Mbit/s. `None` : aucun transfert n'a abouti (pas de curl, pas d'Internet).
fn charger(sens: Sens, duree: Duration, arret: &Arc<AtomicBool>) -> Option<f64> {
    let nul = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let fichier = std::env::temp_dir().join(format!("sentinel-envoi-{}.bin", std::process::id()));
    if sens == Sens::Envoi && std::fs::write(&fichier, vec![0u8; 25_000_000]).is_err() {
        return None;
    }
    let octets = Arc::new(AtomicU64::new(0));
    let debut = Instant::now();
    let travailleurs: Vec<_> = (0..4)
        .map(|_| {
            let (octets, arret, fichier) = (Arc::clone(&octets), Arc::clone(arret), fichier.clone());
            std::thread::spawn(move || {
                while !arret.load(Ordering::Relaxed) && debut.elapsed() < duree && octets.load(Ordering::Relaxed) < PLAFOND {
                    let reste = duree.saturating_sub(debut.elapsed()).as_secs().max(1).to_string();
                    let mut curl = std::process::Command::new("curl");
                    curl.args(["-s", "-o", nul, "--max-time", &reste, "-A", "sentinel"]);
                    match sens {
                        Sens::Reception => curl.args(["-w", "%{size_download}", TELECHARGEMENT]),
                        Sens::Envoi => curl.args([
                            "-w",
                            "%{size_upload}",
                            "--data-binary",
                            &format!("@{}", fichier.display()),
                            ENVOI,
                        ]),
                    };
                    let Some(r) = crate::commande::lancer(&mut curl, 30) else { break };
                    let n: u64 = r.sortie.trim().parse().unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    octets.fetch_add(n, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for t in travailleurs {
        let _ = t.join();
    }
    arret.store(true, Ordering::Relaxed);
    let _ = std::fs::remove_file(&fichier);
    let total = octets.load(Ordering::Relaxed);
    #[allow(clippy::cast_precision_loss)]
    let mbits = total as f64 * 8.0 / debut.elapsed().as_secs_f64() / 1_000_000.0;
    (total > 0).then_some(mbits)
}

/// Latence pendant que la connexion est chargée dans un sens, et débit obtenu.
async fn sous_charge(sens: Sens) -> (Serie, Option<f64>) {
    let arret = Arc::new(AtomicBool::new(false));
    let charge = {
        let arret = Arc::clone(&arret);
        tokio::task::spawn_blocking(move || charger(sens, Duration::from_secs(8), &arret))
    };
    // Une seconde pour que les transferts prennent leur vitesse, puis des mesures jusqu'à la fin.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mesures = serie(INTERNET, 35, Some(&arret)).await;
    arret.store(true, Ordering::Relaxed);
    (mesures, charge.await.ok().flatten())
}

/// Note du bufferbloat d'après la hausse de latence sous charge (barème de Waveform).
fn note_bufferbloat(hausse: f64) -> (&'static str, Niveau) {
    match hausse {
        h if h <= 5.0 => ("A+", Niveau::Info),
        h if h <= 30.0 => ("A", Niveau::Info),
        h if h <= 60.0 => ("B", Niveau::Moyen),
        h if h <= 200.0 => ("C", Niveau::Eleve),
        h if h <= 400.0 => ("D", Niveau::Critique),
        _ => ("F", Niveau::Critique),
    }
}

fn ligne(nom: &str, s: &Serie) {
    match s.mediane() {
        Some(m) => trp!(
            "  {nom:<27} {m:>5.0} ms   gigue {:>4.1} ms   pertes {:>3.0} %",
            "  {nom:<27} {m:>5.0} ms   jitter {:>4.1} ms   loss {:>3.0}%",
            s.gigue(),
            s.pertes()
        ),
        None => trp!("  {nom:<27} pas de réponse", "  {nom:<27} no response"),
    }
}

/// Conseils pour le jeu, du plus important au moins important.
fn conseils(box_: Option<&Serie>, internet: &Serie, hausse: Option<f64>) -> Vec<String> {
    let mut c = Vec::new();
    if internet.pertes() > 1.0 {
        c.push(tr!(
            "Des paquets se perdent : en jeu, ça donne des saccades et des « téléportations ». Redémarre la box ; si ça reste, appelle ton fournisseur.",
            "Packets are being lost: in game, that means stutter and “teleporting”. Restart the router; if it persists, call your provider."
        ).to_string());
    }
    if let Some(b) = box_
        && (b.gigue() > 5.0 || b.mediane().is_some_and(|m| m > 5.0) || b.pertes() > 0.0)
    {
        c.push(tr!(
            "La liaison avec la box est instable (souvent le Wi-Fi) : un câble Ethernet règle presque toujours ça.",
            "The link to the router is unstable (often Wi-Fi): an Ethernet cable almost always fixes it."
        ).to_string());
    }
    if let Some(h) = hausse
        && h > 30.0
    {
        c.push(trf!(
            "Le ping grimpe de {h:.0} ms dès que la connexion est occupée : active la QoS « SQM » / « Smart Queue » de ta box ou routeur, ou limite les téléchargements pendant les parties.",
            "Ping rises by {h:.0} ms as soon as the connection is busy: turn on “SQM” / “Smart Queue” QoS on your router, or limit downloads while playing."
        ));
    }
    if internet.gigue() > 10.0 {
        c.push(tr!(
            "Le ping varie beaucoup (gigue) : ferme les téléchargements et le streaming en arrière-plan.",
            "Ping varies a lot (jitter): close background downloads and streaming."
        ).to_string());
    }
    c
}

pub async fn tester() {
    titre(tr!("Test de connexion pour le jeu", "Connection test for gaming"));
    trp!(
        "  {GRIS}Environ 25 secondes. Le test de débit télécharge et envoie quelques centaines de Mo au plus.{RESET}\n",
        "  {GRIS}About 25 seconds. The speed test downloads and uploads a few hundred MB at most.{RESET}\n"
    );
    let boite = match crate::scan::passerelle() {
        Some(ip) => port_de_la_box(ip).await,
        None => None,
    };
    let serie_box = match boite {
        Some(cible) => Some(serie(cible, 20, None).await),
        None => None,
    };
    let internet = serie(INTERNET, 20, None).await;
    trp!("  {GRAS}Au repos{RESET}", "  {GRAS}At rest{RESET}");
    if let (Some(cible), Some(s)) = (boite, &serie_box) {
        ligne(&trf!("Box ({})", "Router ({})", cible.ip()), s);
    }
    ligne("Internet (Cloudflare)", &internet);
    let Some(repos) = internet.mediane() else {
        trp!(
            "\n  ✖ Internet ne répond pas : test arrêté.",
            "\n  ✖ Internet does not answer: test stopped."
        );
        return;
    };
    trp!("\n  {GRAS}Sous charge{RESET}", "\n  {GRAS}Under load{RESET}");
    let (en_reception, debit_bas) = sous_charge(Sens::Reception).await;
    let (en_envoi, debit_haut) = sous_charge(Sens::Envoi).await;
    ligne(tr!("Pendant un téléchargement", "During a download"), &en_reception);
    ligne(tr!("Pendant un envoi", "During an upload"), &en_envoi);
    let debit = |d: Option<f64>| d.map_or_else(|| "?".to_string(), |d| format!("{d:.0}"));
    trp!(
        "  {:<27} ↓ {} Mbit/s   ↑ {} Mbit/s",
        "  {:<27} ↓ {} Mbit/s   ↑ {} Mbit/s",
        tr!("Débit", "Speed"),
        debit(debit_bas),
        debit(debit_haut)
    );
    let hausse = [en_reception.mediane(), en_envoi.mediane()]
        .into_iter()
        .flatten()
        .map(|m| (m - repos).max(0.0))
        .reduce(f64::max);
    if let Some(h) = hausse {
        let (note, niveau) = note_bufferbloat(h);
        trp!(
            "  {:<27} {}{note}{RESET} (+{h:.0} ms quand la connexion est occupée)",
            "  {:<27} {}{note}{RESET} (+{h:.0} ms when the connection is busy)",
            "Bufferbloat",
            couleur(niveau)
        );
    }
    println!();
    let conseils = conseils(serie_box.as_ref(), &internet, hausse);
    if conseils.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Connexion excellente pour le jeu.",
            "  {VERT}✔{RESET} Excellent connection for gaming."
        );
    }
    for c in conseils {
        println!("  💡 {c}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statistiques() {
        let s = Serie(vec![Some(10.0), Some(12.0), None, Some(11.0), Some(30.0)]);
        assert_eq!(s.mediane(), Some(12.0));
        assert!((s.pertes() - 20.0).abs() < 1e-9);
        // Écarts successifs : 2, 1, 19 → 22 / 3.
        assert!((s.gigue() - 22.0 / 3.0).abs() < 1e-9);
        assert_eq!(Serie(vec![None]).mediane(), None);
        assert_eq!(note_bufferbloat(3.0).0, "A+");
        assert_eq!(note_bufferbloat(45.0).0, "B");
        assert_eq!(note_bufferbloat(900.0).0, "F");
    }

    #[test]
    fn conseils_pour_le_jeu() {
        let stable = Serie(vec![Some(1.0); 10]);
        let internet = Serie(vec![Some(12.0); 10]);
        assert_eq!(conseils(Some(&stable), &internet, Some(3.0)), Vec::<String>::new());
        let wifi = Serie(vec![Some(2.0), Some(15.0), Some(3.0), Some(40.0)]);
        let perdu = Serie(vec![Some(12.0), None, Some(12.0)]);
        assert_eq!(conseils(Some(&wifi), &perdu, Some(120.0)).len(), 3);
    }
}
