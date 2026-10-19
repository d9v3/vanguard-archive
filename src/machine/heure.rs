//! L'heure réglée automatiquement : une horloge qui dérive de quelques minutes fait échouer les sites sécurisés
//! (certificats « pas encore valides » ou « expirés »), Windows Update et les codes de double authentification.
//! Vanguard regarde si le système règle l'heure tout seul (NTP) ; il ne mesure pas l'écart lui-même, ce qui
//! demanderait d'interroger un serveur. Sous macOS, le réglage ne se lit pas sans droits administrateur : rien n'est dit.

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::tr;

const CAT: &str = "Heure";

/// L'état lu : synchronisation activée, et faite (`None` : on ne sait pas).
#[derive(Debug, PartialEq, Eq)]
struct Etat {
    automatique: bool,
    synchronisee: Option<bool>,
}

fn juger(e: &Etat) -> Constat {
    if !e.automatique {
        let c = alerte(
            CAT,
            Niveau::Moyen,
            tr!(
                "L'heure n'est pas réglée automatiquement : une horloge qui dérive fait échouer les sites sécurisés, les mises à jour et les codes de double authentification.",
                "The time is not set automatically: a drifting clock makes secure sites, updates and two-factor codes fail."
            ),
        );
        return if cfg!(windows) {
            c.corriger(
                tr!("Régler l'heure automatiquement (service de temps de Windows)", "Set the time automatically (Windows time service)"),
                &[
                    r"Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name Type -Value NTP",
                    "Set-Service w32time -StartupType Automatic",
                    "Start-Service w32time",
                    "w32tm /resync /force",
                ],
            )
        } else {
            c.corriger(
                tr!(
                    "Régler l'heure automatiquement (NTP)",
                    "Set the time automatically (NTP)"
                ),
                &["sudo timedatectl set-ntp true"],
            )
        };
    }
    match e.synchronisee {
        Some(false) => alerte(
            CAT,
            Niveau::Info,
            tr!(
                "Réglage automatique de l'heure activé, mais pas encore synchronisé (pas d'Internet, ou démarrage récent).",
                "Automatic time setting is on, but not synchronized yet (no Internet, or recent startup)."
            ),
        ),
        _ => ok(
            CAT,
            tr!("L'heure est réglée automatiquement.", "The time is set automatically."),
        ),
    }
}

/// « NTP=yes\nNTPSynchronized=no » (timedatectl show).
#[cfg(any(target_os = "linux", test))]
fn lire_timedatectl(texte: &str) -> Option<Etat> {
    let valeur = |cle: &str| {
        texte
            .lines()
            .find_map(|l| l.trim().strip_prefix(cle)?.strip_prefix('='))
            .map(|v| v.trim() == "yes")
    };
    // Sans service de temps du tout (conteneur), timedatectl ne peut rien régler : rien à dire.
    if valeur("CanNTP") == Some(false) {
        return None;
    }
    Some(Etat {
        automatique: valeur("NTP")?,
        synchronisee: valeur("NTPSynchronized"),
    })
}

#[cfg(target_os = "linux")]
fn lire() -> Option<Etat> {
    if !std::path::Path::new("/run/systemd/system").is_dir() {
        return None;
    }
    let r = crate::commande::lancer_en_anglais(
        std::process::Command::new("timedatectl").args(["show", "-p", "NTP", "-p", "NTPSynchronized", "-p", "CanNTP"]),
        10,
    )?;
    (r.code == Some(0)).then(|| lire_timedatectl(&r.sortie)).flatten()
}

/// Windows : le service de temps (Start = 4 : désactivé) et son type de synchronisation (« NoSync » : aucune).
#[cfg(windows)]
fn lire() -> Option<Etat> {
    let cle = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Services\W32Time")
        .ok()?;
    let demarrage: u32 = cle.get_value("Start").unwrap_or(3);
    let genre: String = cle
        .open_subkey("Parameters")
        .and_then(|p| p.get_value("Type"))
        .unwrap_or_default();
    Some(Etat {
        automatique: demarrage != 4 && !genre.eq_ignore_ascii_case("NoSync"),
        synchronisee: None,
    })
}

#[cfg(target_os = "macos")]
fn lire() -> Option<Etat> {
    None
}

pub fn constat() -> Option<Constat> {
    lire().map(|e| juger(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heure_automatique() {
        let e = lire_timedatectl("CanNTP=yes\nNTP=yes\nNTPSynchronized=yes\n").unwrap();
        assert!(juger(&e).probleme.is_none());
        let e = lire_timedatectl("CanNTP=yes\nNTP=yes\nNTPSynchronized=no\n").unwrap();
        assert_eq!(juger(&e).probleme, Some(Niveau::Info));
        let e = lire_timedatectl("CanNTP=yes\nNTP=no\nNTPSynchronized=no\n").unwrap();
        let c = juger(&e);
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.correctif.as_ref().unwrap().automatique);
        assert_eq!(lire_timedatectl("CanNTP=no\nNTP=no\n"), None);
        assert_eq!(lire_timedatectl(""), None);
    }
}
