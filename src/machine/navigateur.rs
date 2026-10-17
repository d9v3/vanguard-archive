//! Réglages de sécurité des navigateurs : protection contre les sites frauduleux (Safe Browsing), cookies tiers,
//! DNS chiffré. Un navigateur n'écrit un réglage que s'il a été changé : sans valeur écrite, on retient sa valeur
//! par défaut.

use serde_json::Value;

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Navigateur";

#[derive(Debug, PartialEq)]
struct Reglages {
    /// Protection contre les sites frauduleux et les téléchargements dangereux.
    anti_hameconnage: bool,
    /// Tous les cookies tiers acceptés (suivi d'un site à l'autre).
    cookies_ouverts: bool,
    /// DNS chiffré du navigateur : `None` quand le navigateur décide seul (valeur par défaut).
    dns_chiffre: Option<bool>,
}

/// Valeur d'une préférence Firefox (`user_pref("nom", valeur);`) ; la dernière écrite gagne.
fn pref(texte: &str, nom: &str) -> Option<String> {
    let debut = format!("user_pref(\"{nom}\",");
    texte
        .lines()
        .filter_map(|l| l.trim().strip_prefix(debut.as_str()))
        .filter_map(|r| r.trim().strip_suffix(");"))
        .map(|v| v.trim().trim_matches('"').to_string())
        .next_back()
}

fn lire_firefox(prefs: &str) -> Reglages {
    let coupe = |nom: &str| pref(prefs, nom).as_deref() == Some("false");
    Reglages {
        anti_hameconnage: !coupe("browser.safebrowsing.malware.enabled")
            && !coupe("browser.safebrowsing.phishing.enabled"),
        // network.cookie.cookieBehavior : 0 = tout accepter ; sans valeur, protection totale des cookies.
        cookies_ouverts: pref(prefs, "network.cookie.cookieBehavior").as_deref() == Some("0"),
        // network.trr.mode : 2 ou 3 = DNS chiffré, 5 = coupé.
        dns_chiffre: match pref(prefs, "network.trr.mode").as_deref() {
            Some("2" | "3") => Some(true),
            Some("5") => Some(false),
            _ => None,
        },
    }
}

fn lire_chromium(preferences: &str, etat_local: &str) -> Reglages {
    let p: Value = serde_json::from_str(preferences).unwrap_or_default();
    let l: Value = serde_json::from_str(etat_local).unwrap_or_default();
    Reglages {
        anti_hameconnage: p["safebrowsing"]["enabled"] != false,
        // cookie_controls_mode 0 = cookies tiers autorisés partout (le défaut les bloque en navigation privée).
        cookies_ouverts: p["profile"]["cookie_controls_mode"] == 0 && p["profile"]["block_third_party_cookies"] != true,
        dns_chiffre: match l["dns_over_https"]["mode"].as_str() {
            Some("secure") => Some(true),
            Some("off") => Some(false),
            _ => None,
        },
    }
}

fn juger(navigateur: &str, r: &Reglages) -> Constat {
    let dns = match r.dns_chiffre {
        Some(true) => tr!("DNS chiffré activé", "encrypted DNS on"),
        Some(false) => tr!("DNS chiffré coupé", "encrypted DNS off"),
        None => tr!("DNS chiffré par défaut", "default encrypted DNS"),
    };
    if !r.anti_hameconnage {
        return alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "{navigateur} : protection contre les sites frauduleux désactivée ({dns}).",
                "{navigateur}: protection against fraudulent sites turned off ({dns})."
            ),
        )
        .manuel(
            tr!(
                "La réactiver : Paramètres > Vie privée et sécurité > Sécurité",
                "Turn it back on: Settings > Privacy and security > Security"
            ),
            &[],
        );
    }
    if r.cookies_ouverts {
        return alerte(
            CAT,
            Niveau::Info,
            trf!(
                "{navigateur} : protection contre les sites frauduleux active, mais tous les cookies tiers sont acceptés : les publicitaires te suivent de site en site ({dns}).",
                "{navigateur}: protection against fraudulent sites on, but all third-party cookies are accepted: advertisers follow you from site to site ({dns})."
            ),
        );
    }
    ok(
        CAT,
        trf!(
            "{navigateur} : protection contre les sites frauduleux active, cookies tiers limités, {dns}.",
            "{navigateur}: protection against fraudulent sites on, third-party cookies limited, {dns}."
        ),
    )
}

pub fn navigateurs() -> Vec<Constat> {
    let mut constats = Vec::new();
    let mut vus = Vec::new();
    for (nom, racine, firefox) in super::extensions::racines() {
        let profils = super::extensions::profils(&racine, firefox);
        let plusieurs = profils.len() > 1;
        for (dossier, chemin) in profils {
            let reel = chemin.canonicalize().unwrap_or_else(|_| chemin.clone());
            if vus.contains(&reel) {
                continue;
            }
            vus.push(reel);
            let lire = |f: &str| std::fs::read_to_string(chemin.join(f)).unwrap_or_default();
            let reglages = if firefox {
                lire_firefox(&(lire("prefs.js") + &lire("user.js")))
            } else {
                let etat_local = std::fs::read_to_string(racine.join("Local State")).unwrap_or_default();
                lire_chromium(&lire("Preferences"), &etat_local)
            };
            let navigateur = if plusieurs {
                let court = dossier
                    .split_once('.')
                    .filter(|_| firefox)
                    .map_or(dossier.as_str(), |(_, n)| n);
                format!("{nom} ({court})")
            } else {
                nom.to_string()
            };
            constats.push(juger(&navigateur, &reglages));
        }
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reglages_firefox() {
        let defaut = lire_firefox("user_pref(\"browser.contentblocking.category\", \"strict\");\n");
        assert_eq!(
            defaut,
            Reglages {
                anti_hameconnage: true,
                cookies_ouverts: false,
                dns_chiffre: None
            }
        );
        let r = lire_firefox(
            "user_pref(\"browser.safebrowsing.phishing.enabled\", false);\nuser_pref(\"network.cookie.cookieBehavior\", 0);\nuser_pref(\"network.trr.mode\", 3);\n",
        );
        assert_eq!(
            r,
            Reglages {
                anti_hameconnage: false,
                cookies_ouverts: true,
                dns_chiffre: Some(true)
            }
        );
        assert_eq!(juger("Firefox", &r).probleme, Some(Niveau::Moyen));
        assert_eq!(juger("Firefox", &defaut).probleme, None);
    }

    #[test]
    fn reglages_chromium() {
        let r = lire_chromium(r#"{"safebrowsing":{"enabled":true,"enhanced":true}}"#, "{}");
        assert_eq!(
            r,
            Reglages {
                anti_hameconnage: true,
                cookies_ouverts: false,
                dns_chiffre: None
            }
        );
        let r = lire_chromium(
            r#"{"safebrowsing":{"enabled":false},"profile":{"cookie_controls_mode":0}}"#,
            r#"{"dns_over_https":{"mode":"secure"}}"#,
        );
        assert_eq!(
            r,
            Reglages {
                anti_hameconnage: false,
                cookies_ouverts: true,
                dns_chiffre: Some(true)
            }
        );
    }
}
