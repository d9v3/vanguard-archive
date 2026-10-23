//! Le mode Wi-Fi public sous macOS : le pare-feu applicatif bloque toutes les entrées sauf l'essentiel (DHCP,
//! Bonjour, IPsec) et passe en mode furtif ; le partage de fichiers devient injoignable avec. Le DNS protecteur est
//! posé sur le service Wi-Fi, NON chiffré : macOS ne chiffre le DNS du système que par un profil de configuration,
//! hors de ce mode (c'est dit). Un pare-feu trouvé coupé est allumé et jamais recoupé. Commandes pures, essayées
//! partout ; lectures sous macOS seulement.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use super::etat::{Element, OPTIONS_MAC};

pub(crate) const PARE_FEU: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// « on », « off », ou `None` si la réponse de socketfilterfw ne se comprend pas. `--getglobalstate` répond
/// « Firewall is enabled. (State = 1) » (2 : tout bloquer) ; `--getblockall` et `--getstealthmode` ont changé de
/// phrase selon les versions (« Block all DISABLED! », « … set to enabled », « Stealth mode enabled », « … is on »).
pub(crate) fn lire_option(sortie: &str) -> Option<&'static str> {
    let s = sortie.to_ascii_lowercase();
    if s.contains("disabled") || s.contains("state = 0") || s.contains("is off") {
        Some("off")
    } else if s.contains("enabled") || s.contains("state = 1") || s.contains("state = 2") || s.contains("is on") {
        Some("on")
    } else {
        None
    }
}

/// La commande qui pose une option du pare-feu (liste fermée, on ou off).
pub(crate) fn regler(option: &str, valeur: &str) -> Option<String> {
    (OPTIONS_MAC.contains(&option) && ["on", "off"].contains(&valeur))
        .then(|| format!("sudo {PARE_FEU} --set{option} {valeur}"))
}

/// La commande qui remet un élément propre à macOS (le DNS passe par `optimiser`) ; le pare-feu trouvé coupé reste
/// allumé.
pub(crate) fn remettre(e: &Element) -> Option<String> {
    if !e.valide() || e.jamais_remis() {
        return None;
    }
    match e {
        Element::MacPareFeu { option, avant } => regler(option, avant),
        _ => None,
    }
}

/// `networksetup -listallhardwareports` : la carte et le port (nom du service) du Wi-Fi.
pub(crate) fn port_wifi(sortie: &str) -> Option<(String, String)> {
    let mut port: Option<&str> = None;
    for l in sortie.lines().map(str::trim) {
        if let Some(p) = l.strip_prefix("Hardware Port:") {
            port = Some(p.trim());
        } else if let Some(d) = l.strip_prefix("Device:")
            && let Some(p) = port.filter(|p| *p == "Wi-Fi" || *p == "AirPort")
        {
            let d = d.trim();
            if super::etat::interface_valide(d) {
                return Some((d.to_string(), p.to_string()));
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
pub(crate) mod lecture {
    use std::process::Command;

    use super::super::etat::Element;

    pub(crate) fn option(option: &str) -> Option<&'static str> {
        let r = crate::commande::lancer(Command::new(super::PARE_FEU).arg(format!("--get{option}")), 10)?;
        super::lire_option(&r.sortie)
    }

    /// La carte Wi-Fi et son service, son nom de réseau et sa protection (system_profiler, quelques secondes).
    pub(crate) fn wifi() -> Option<(String, String, String, String)> {
        let r = crate::commande::lancer(Command::new("networksetup").arg("-listallhardwareports"), 10)?;
        let (carte, service) = super::port_wifi(&r.sortie)?;
        let profil = crate::commande::lancer(Command::new("system_profiler").arg("SPAirPortDataType"), 40)?;
        let actif = crate::machine::wifi::lire_system_profiler(&profil.sortie)
            .into_iter()
            .find(|v| v.actif)?;
        Some((carte, service, actif.ssid, actif.securite))
    }

    pub(crate) fn a_l_avant(e: &Element) -> Option<bool> {
        match e {
            Element::MacPareFeu { option: o, avant } => option(o).map(|v| v == avant),
            Element::Dns { avant } => crate::optimiser::dns_relu(avant).map(|v| v == *avant),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reponses_de_socketfilterfw() {
        assert_eq!(lire_option("Firewall is enabled. (State = 1)"), Some("on"));
        assert_eq!(lire_option("Firewall is disabled. (State = 0)"), Some("off"));
        assert_eq!(lire_option("Firewall has block all state set to enabled."), Some("on"));
        assert_eq!(lire_option("Block all DISABLED! "), Some("off"));
        assert_eq!(lire_option("Firewall stealth mode is on"), Some("on"));
        assert_eq!(lire_option("Stealth mode disabled"), Some("off"));
        assert_eq!(lire_option(""), None);
    }

    #[test]
    fn commandes_du_pare_feu() {
        assert_eq!(
            regler("blockall", "on").as_deref(),
            Some("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on")
        );
        assert!(regler("allowsigned", "off").is_none() && regler("blockall", "1").is_none());
        let coupe = Element::MacPareFeu {
            option: "globalstate".into(),
            avant: "off".into(),
        };
        assert!(remettre(&coupe).is_none(), "jamais recoupé");
        let furtif = Element::MacPareFeu {
            option: "stealthmode".into(),
            avant: "off".into(),
        };
        assert!(remettre(&furtif).unwrap().ends_with("--setstealthmode off"));
    }

    #[test]
    fn port_du_wifi() {
        let s = "Hardware Port: Ethernet\nDevice: en0\nEthernet Address: 00:11:22:aa:bb:01\n\nHardware Port: Wi-Fi\nDevice: en1\nEthernet Address: 00:11:22:aa:bb:02\n";
        assert_eq!(port_wifi(s), Some(("en1".into(), "Wi-Fi".into())));
        assert_eq!(port_wifi("Hardware Port: Ethernet\nDevice: en0\n"), None);
    }
}
