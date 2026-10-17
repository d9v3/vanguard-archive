//! Journal des erreurs, pour améliorer sentinel après coup : plantages, scripts PowerShell en échec, vérifications
//! impossibles, scans ratés. Il est écrit sur la petite partition SENTINELLOG de la clé, la seule modifiable sur les
//! autres ordinateurs (la partition SENTINEL y est en lecture seule), et rapatrié par outils/deployer.sh au
//! branchement sur l'ordinateur de développement. Écrit en français : il est destiné au développement, pas à
//! l'utilisateur.
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

/// Partition SENTINELLOG de la clé, si elle est branchée.
fn dossier() -> Option<&'static PathBuf> {
    static DOSSIER: OnceLock<Option<PathBuf>> = OnceLock::new();
    DOSSIER
        .get_or_init(|| {
            #[cfg(target_os = "linux")]
            let montages: Vec<PathBuf> = std::env::var("USER")
                .ok()
                .and_then(|u| std::fs::read_dir(format!("/run/media/{u}")).ok())
                .into_iter()
                .flatten()
                .flatten()
                .map(|d| d.path())
                .collect();
            #[cfg(windows)]
            let montages: Vec<PathBuf> = ('D'..='Z').map(|l| PathBuf::from(format!("{l}:\\"))).collect();
            montages.into_iter().find(|d| d.join(TEMOIN).is_file())
        })
        .as_ref()
}

/// Système et version, pour situer l'erreur (« Windows 10.0.26200.9711 », « Arch Linux 6.17.2 »).
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
    let mut noms: Vec<(String, &str)> = ["USER", "USERNAME", "LOGNAME"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .map(|n| (n, "<utilisateur>"))
        .collect();
    noms.extend(
        ["COMPUTERNAME", "HOSTNAME"]
            .iter()
            .filter_map(|v| std::env::var(v).ok())
            .chain(std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
            .map(|n| (n.trim().to_string(), "<machine>")),
    );
    for (nom, remplacement) in noms {
        // Un nom très court (« pc », « a ») remplacerait des morceaux de mots.
        if nom.chars().count() >= 3 {
            t = t.replace(&nom, remplacement);
        }
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
}
