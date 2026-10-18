//! Lancement des commandes système avec un délai maximal : un outil qui ne répond plus (systemctl, gsettings,
//! PowerShell, gestionnaire de paquets hors ligne…) ne doit jamais figer Gardien.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct Resultat {
    /// Code de retour (`None` si le programme a été tué par un signal).
    pub code: Option<i32>,
    pub sortie: String,
    /// Sortie d'erreur : notée dans le journal quand PowerShell ou udisksctl échouent, et lue par les tests
    /// (certains outils répondent par là).
    pub erreurs: String,
}

/// Délai d'attente des sorties après la fin du programme : un sous-processus resté en arrière-plan peut garder
/// le canal ouvert, et la lecture ne finirait jamais.
const DELAI_LECTURE: Duration = Duration::from_secs(2);

fn lire_en_fond(mut flux: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (envoi, reception) = mpsc::channel();
    std::thread::spawn(move || {
        let mut octets = Vec::new();
        let _ = flux.read_to_end(&mut octets);
        let _ = envoi.send(String::from_utf8_lossy(&octets).into_owned());
    });
    reception
}

/// Lance la commande et attend au plus `secondes`. `None` si elle ne démarre pas, dépasse le délai
/// (elle est alors tuée) ou si ses sorties ne se terminent pas.
pub fn lancer(commande: &mut Command, secondes: u64) -> Option<Resultat> {
    let mut enfant = commande
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let sortie = lire_en_fond(enfant.stdout.take()?);
    let erreurs = lire_en_fond(enfant.stderr.take()?);
    let limite = Instant::now() + Duration::from_secs(secondes);
    let statut = loop {
        match enfant.try_wait() {
            Ok(Some(statut)) => break statut,
            Ok(None) if Instant::now() < limite => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                arreter(&mut enfant);
                return None;
            }
        }
    };
    Some(Resultat {
        code: statut.code(),
        sortie: sortie.recv_timeout(DELAI_LECTURE).ok()?,
        erreurs: erreurs.recv_timeout(DELAI_LECTURE).unwrap_or_default(),
    })
}

/// Arrête le programme et tout ce qu'il a lancé : sinon un sous-processus (winget sous PowerShell, un outil sous un
/// script) continuerait en arrière-plan, avec ses verrous.
fn arreter(enfant: &mut Child) {
    // Windows : taskkill suit lui-même l'arbre des processus.
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .args(["/T", "/F", "/PID", &enfant.id().to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    // Unix : les descendants sont d'abord tous repérés (pgrep -P, de proche en proche), puis tués. Tué en premier, le
    // programme laisserait ses enfants rattachés à init, introuvables.
    #[cfg(unix)]
    {
        let mut pids = vec![enfant.id()];
        let mut i = 0;
        while let Some(&pid) = pids.get(i)
            && pids.len() < 1000
        {
            i += 1;
            if let Ok(o) = Command::new("pgrep").args(["-P", &pid.to_string()]).output() {
                pids.extend(
                    String::from_utf8_lossy(&o.stdout)
                        .split_whitespace()
                        .filter_map(|p| p.parse::<u32>().ok()),
                );
            }
        }
        for pid in pids.into_iter().skip(1).filter_map(|p| libc::pid_t::try_from(p).ok()) {
            // SAFETY : simple envoi d'un signal à un numéro de processus.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
    let _ = enfant.kill();
    let _ = enfant.wait();
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn delai_et_sorties() {
        let debut = Instant::now();
        assert!(lancer(Command::new("sleep").arg("5"), 1).is_none());
        assert!(debut.elapsed() < Duration::from_secs(3));
        let r = lancer(Command::new("sh").args(["-c", "echo ok; echo oups >&2; exit 3"]), 5).unwrap();
        assert_eq!(
            (r.code, r.sortie.as_str(), r.erreurs.as_str()),
            (Some(3), "ok\n", "oups\n")
        );
    }

    #[test]
    fn sous_processus_qui_garde_la_sortie() {
        // Le programme se termine mais laisse un processus en arrière-plan sur la sortie : pas de blocage.
        let debut = Instant::now();
        let _ = lancer(Command::new("sh").args(["-c", "sleep 20 & echo fini"]), 5);
        assert!(debut.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn le_delai_arrete_aussi_ce_que_le_programme_a_lance() {
        let fichier = std::env::temp_dir().join(format!("gardien-test-arbre-{}", std::process::id()));
        let script = format!("sleep 30 & echo $! > '{}'; wait", fichier.display());
        assert!(lancer(Command::new("sh").args(["-c", &script]), 1).is_none());
        let pid = std::fs::read_to_string(&fichier).unwrap().trim().to_string();
        let _ = std::fs::remove_file(&fichier);
        // Arrêté = absent de la liste des processus, ou zombie qui attend d'être ramassé.
        let vivant = || {
            let ps = Command::new("ps").args(["-o", "stat=", "-p", &pid]).output().unwrap();
            let etat = String::from_utf8_lossy(&ps.stdout).trim().to_string();
            !etat.is_empty() && !etat.starts_with('Z')
        };
        let debut = Instant::now();
        while vivant() && debut.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!vivant(), "le sous-processus {pid} tourne encore");
    }
}
