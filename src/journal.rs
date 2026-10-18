//! Journal des erreurs, pour améliorer sentinel après coup : plantages, scripts PowerShell en échec, vérifications
//! impossibles, scans ratés. Il est écrit sur la petite partition SENTINELLOG de la clé, la seule modifiable sur les
//! autres ordinateurs (la partition SENTINEL y est en lecture seule), et rapatrié par outils/deployer.sh au
//! branchement sur l'ordinateur de développement, qui en fait des tickets GitHub (outils/journal-vers-github.py).
//! Sans clé branchée, il est écrit dans le dossier de sentinel de cet ordinateur (rapatrié de même sur l'ordinateur
//! de développement). Écrit en français : il est destiné au développement, pas à l'utilisateur.
//!
//! Rien de personnel : dossier personnel, nom d'utilisateur et nom de la machine sont remplacés avant l'écriture.

use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Fichier témoin à la racine de la partition SENTINELLOG.
pub const TEMOIN: &str = "sentinel-journal.cle";
pub const FICHIER: &str = "journal-erreurs.txt";
/// Au-delà, plus rien n'est ajouté : une erreur répétée en boucle ne remplit pas la partition.
const TAILLE_MAX: u64 = 4 * 1024 * 1024;
/// Longueur maximale d'un détail (sortie d'erreur de PowerShell…).
const DETAIL_MAX: usize = 3000;

/// Où écrire : la partition SENTINELLOG de la clé si elle est branchée, sinon le dossier de sentinel.
fn dossier() -> Option<&'static PathBuf> {
    static DOSSIER: OnceLock<Option<PathBuf>> = OnceLock::new();
    DOSSIER
        .get_or_init(|| {
            // Pendant les tests automatiques, et sous Wine (tests de la version Windows, sans PowerShell) : pas de
            // journal, sinon de fausses erreurs partiraient en tickets.
            #[cfg(windows)]
            let essai = cfg!(test) || sous_wine();
            #[cfg(unix)]
            let essai = cfg!(test);
            if essai {
                return None;
            }
            partition_de_la_cle().or_else(|| Some(crate::reseau::dossier_local()))
        })
        .as_ref()
}

/// Partition SENTINELLOG de la clé, si elle est branchée.
fn partition_de_la_cle() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        lecteur_windows()
    }
    #[cfg(unix)]
    {
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
        montages.into_iter().find(|d| d.join(TEMOIN).is_file())
    }
}

/// Lecteurs D: à Z: interrogés en même temps, 2 s au plus : un lecteur réseau déconnecté peut mettre de longues
/// secondes à répondre, et le journal ne doit jamais faire attendre le programme.
#[cfg(windows)]
fn lecteur_windows() -> Option<PathBuf> {
    use std::time::{Duration, Instant};
    let (envoi, reception) = std::sync::mpsc::channel();
    for lettre in 'D'..='Z' {
        let envoi = envoi.clone();
        std::thread::spawn(move || {
            let lecteur = PathBuf::from(format!("{lettre}:\\"));
            let _ = envoi.send(lecteur.join(TEMOIN).is_file().then_some(lecteur));
        });
    }
    drop(envoi);
    let limite = Instant::now() + Duration::from_secs(2);
    // Fin : le lecteur trouvé, toutes les réponses reçues (canal fermé), ou le délai passé.
    while let Ok(reponse) = reception.recv_timeout(limite.saturating_duration_since(Instant::now())) {
        if reponse.is_some() {
            return reponse;
        }
    }
    None
}

/// Wine installe ses propres programmes dans system32 ; wineboot.exe n'existe pas sur un vrai Windows.
#[cfg(windows)]
fn sous_wine() -> bool {
    let systeme = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from("C:\\windows"), PathBuf::from);
    systeme.join("system32").join("wineboot.exe").is_file()
}

/// Système et version, pour situer l'erreur (« Windows 10.0.26200.9711 », « Arch Linux 6.17.2 », « macOS 15.1 »).
fn systeme() -> &'static str {
    static SYSTEME: OnceLock<String> = OnceLock::new();
    SYSTEME.get_or_init(|| {
        #[cfg(target_os = "linux")]
        {
            let nom = std::fs::read_to_string("/etc/os-release")
                .ok()
                .and_then(|t| {
                    t.lines()
                        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                        .map(|v| v.trim_matches('"').to_string())
                })
                .unwrap_or_else(|| "Linux".into());
            let noyau = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
            format!("{nom} {}", noyau.trim())
        }
        // « macOS 15.1 (Apple Silicon) »
        #[cfg(target_os = "macos")]
        {
            let version = crate::commande::lancer(std::process::Command::new("sw_vers").arg("-productVersion"), 5)
                .map(|r| r.sortie.trim().to_string())
                .unwrap_or_default();
            format!("macOS {version} ({})", crate::machine::macos::architecture())
        }
        #[cfg(windows)]
        {
            // « Microsoft Windows [Version 10.0.26200.9711] »
            crate::commande::lancer(std::process::Command::new("cmd").args(["/c", "ver"]), 5)
                .and_then(|r| {
                    r.sortie
                        .split_once("Version ")
                        .map(|(_, v)| format!("Windows {}", v.trim().trim_end_matches(']')))
                })
                .unwrap_or_else(|| "Windows".into())
        }
    })
}

/// Noms de la personne et de la machine, avec leur remplacement, du plus long au plus court : un nom contenu dans
/// un autre (« alex » dans « alex-pc ») ne le coupe pas en deux.
fn noms_personnels() -> &'static [(String, &'static str)] {
    static NOMS: OnceLock<Vec<(String, &'static str)>> = OnceLock::new();
    NOMS.get_or_init(|| {
        let mut noms: Vec<(String, &str)> = ["USER", "USERNAME", "LOGNAME"]
            .iter()
            .filter_map(|v| std::env::var(v).ok())
            .map(|n| (n, "<utilisateur>"))
            .collect();
        #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
        let mut machines: Vec<String> = ["COMPUTERNAME", "HOSTNAME"]
            .iter()
            .filter_map(|v| std::env::var(v).ok())
            .chain(std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
            .collect();
        // macOS n'exporte pas le nom de la machine et n'a pas /proc : on le demande (nom affiché « MacBook Pro de… »,
        // nom réseau, nom d'hôte « ….local »).
        #[cfg(target_os = "macos")]
        {
            let lire = |cmd: &str, args: &[&str]| {
                crate::commande::lancer(std::process::Command::new(cmd).args(args), 5).map(|r| r.sortie)
            };
            machines.extend(lire("scutil", &["--get", "ComputerName"]));
            machines.extend(lire("scutil", &["--get", "LocalHostName"]));
            machines.extend(lire("hostname", &[]));
        }
        noms.extend(machines.into_iter().map(|n| (n.trim().to_string(), "<machine>")));
        // Un nom très court (« pc », « a ») remplacerait des morceaux de mots.
        noms.retain(|(n, _)| n.chars().count() >= 3);
        noms.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
        noms
    })
}

/// Retire ce qui identifie la personne ou la machine.
fn anonymiser(texte: &str) -> String {
    let mut t = texte.to_string();
    for var in ["HOME", "USERPROFILE"] {
        if let Ok(maison) = std::env::var(var)
            && maison.len() > 3
        {
            t = t.replace(&maison, "~");
        }
    }
    for (nom, remplacement) in noms_personnels() {
        t = t.replace(nom.as_str(), remplacement);
    }
    t
}

/// Ajoute une erreur au journal de la clé. Sans clé branchée, ou si l'écriture échoue : rien, en silence (le
/// journal ne doit jamais gêner le programme).
pub fn erreur(contexte: &str, detail: &str) {
    let Some(dossier) = dossier() else {
        return;
    };
    let chemin = dossier.join(FICHIER);
    if std::fs::metadata(&chemin).is_ok_and(|m| m.len() > TAILLE_MAX) {
        return;
    }
    let commande = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    let mut detail = anonymiser(detail.trim());
    if detail.len() > DETAIL_MAX {
        let coupe = (0..=DETAIL_MAX)
            .rev()
            .find(|&i| detail.is_char_boundary(i))
            .unwrap_or(0);
        detail.truncate(coupe);
        detail.push_str(" […]");
    }
    let entree = format!(
        "== {} · sentinel {} · {} · {} · {}\n[{contexte}]\n{}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
        env!("CARGO_PKG_VERSION"),
        systeme(),
        if crate::langue::anglais() { "en" } else { "fr" },
        if commande.is_empty() {
            "menu".into()
        } else {
            anonymiser(&commande)
        },
        detail.lines().map(|l| format!("  {l}")).collect::<Vec<_>>().join("\n")
    );
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&chemin)
        .and_then(|mut f| f.write_all(entree.as_bytes()));
}

/// Les plantages (panic) sont aussi notés, avant le message habituel.
pub fn installer() {
    let defaut = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        erreur("plantage", &info.to_string());
        defaut(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rien_de_personnel() {
        let maison = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap();
        let t = anonymiser(&format!("échec dans {maison}/Documents/x.ps1"));
        assert!(!t.contains(&maison), "{t}");
        assert!(t.contains('~'), "{t}");
    }

    #[test]
    fn nom_de_la_machine_retire() {
        for (nom, _) in noms_personnels() {
            let t = anonymiser(&format!("hôte {nom} injoignable"));
            assert!(!t.contains(nom.as_str()), "{t}");
        }
        // Linux le lit dans /proc, macOS le demande à scutil : il doit avoir été trouvé.
        #[cfg(unix)]
        assert!(noms_personnels().iter().any(|(_, r)| *r == "<machine>"));
    }
}
