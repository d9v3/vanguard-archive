//! Réglages de sécurité des navigateurs : protection contre les sites frauduleux (Safe Browsing), cookies tiers,
//! DNS chiffré. Un navigateur n'écrit un réglage que s'il a été changé : sans valeur écrite, on retient sa valeur
//! par défaut. Une stratégie imposée (fichier de /etc sous Linux, registre sous Windows, policies.json de Firefox)
//! passe avant les Paramètres : un logiciel indésirable s'en sert pour couper la protection sans qu'on puisse la
//! rallumer. Celles de macOS (profils gérés) ne sont pas lues.

use serde_json::Value;

use super::{Constat, alerte, impossible, ok};
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

/// `None` : Preferences n'est pas un objet JSON (abîmé, en cours d'écriture) ; rien n'est conclu, jamais « active ».
fn lire_chromium(preferences: &str, etat_local: &str) -> Option<Reglages> {
    let p: Value = serde_json::from_str(preferences).ok().filter(Value::is_object)?;
    let l: Value = serde_json::from_str(etat_local).unwrap_or_default();
    Some(Reglages {
        anti_hameconnage: p["safebrowsing"]["enabled"] != false,
        // cookie_controls_mode 0 = cookies tiers autorisés partout (le défaut les bloque en navigation privée).
        cookies_ouverts: p["profile"]["cookie_controls_mode"] == 0 && p["profile"]["block_third_party_cookies"] != true,
        dns_chiffre: match l["dns_over_https"]["mode"].as_str() {
            Some("secure") => Some(true),
            Some("off") => Some(false),
            _ => None,
        },
    })
}

/// La règle d'une stratégie qui coupe la protection contre les sites frauduleux, telle qu'elle sera montrée. Firefox :
/// ses préférences imposées (`Preferences`, valeur nue ou `{"Value": …}`) ; les Chromium : Safe Browsing à 0 ou
/// coupé, et SmartScreen pour Edge (le registre donne 0, les fichiers false).
fn coupee_par(strategie: &Value, firefox: bool) -> Option<String> {
    let faux = |v: &Value| *v == false || *v == 0;
    if firefox {
        let prefs = &strategie["Preferences"];
        return [
            "browser.safebrowsing.malware.enabled",
            "browser.safebrowsing.phishing.enabled",
        ]
        .into_iter()
        .find(|n| faux(&prefs[*n]) || faux(&prefs[*n]["Value"]))
        .map(|n| format!("Preferences : {n} = false"));
    }
    [
        "SafeBrowsingProtectionLevel",
        "SafeBrowsingEnabled",
        "SmartScreenEnabled",
    ]
    .into_iter()
    .find(|n| faux(&strategie[*n]))
    .map(|n| format!("{n} = 0"))
}

/// Les stratégies imposées au navigateur `nom` (celui de `extensions::racines`) : (où elles sont, leur contenu). Un
/// fichier qui n'est pas du JSON est sauté : le navigateur l'ignore aussi.
#[cfg(target_os = "linux")]
fn strategies(nom: &str) -> Vec<(String, Value)> {
    let lire = |chemin: &std::path::Path| {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(chemin).ok()?).ok()?;
        Some((chemin.display().to_string(), v))
    };
    if nom == "Firefox" {
        return [
            "/etc/firefox/policies/policies.json",
            "/usr/lib/firefox/distribution/policies.json",
        ]
        .into_iter()
        .filter_map(|c| lire(std::path::Path::new(c)))
        .map(|(ou, v)| (ou, v["policies"].clone()))
        .collect();
    }
    let dossiers: &[&str] = match nom {
        "Chrome" => &["/etc/opt/chrome/policies/managed"],
        "Chromium" => &[
            "/etc/chromium/policies/managed",
            "/etc/chromium-browser/policies/managed",
        ],
        "Brave" => &["/etc/brave/policies/managed"],
        "Edge" => &["/etc/opt/edge/policies/managed"],
        _ => &[],
    };
    let mut fichiers: Vec<_> = dossiers
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|c| c.extension().is_some_and(|e| e == "json"))
        .collect();
    fichiers.sort();
    fichiers.iter().filter_map(|c| lire(c)).collect()
}

#[cfg(windows)]
fn strategies(nom: &str) -> Vec<(String, Value)> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let cle = match nom {
        "Chrome" => r"SOFTWARE\Policies\Google\Chrome",
        "Chromium" => r"SOFTWARE\Policies\Chromium",
        "Brave" => r"SOFTWARE\Policies\BraveSoftware\Brave",
        "Edge" => r"SOFTWARE\Policies\Microsoft\Edge",
        _ => return Vec::new(),
    };
    [(HKEY_LOCAL_MACHINE, "HKLM"), (HKEY_CURRENT_USER, "HKCU")]
        .into_iter()
        .filter_map(|(racine, court)| {
            let k = RegKey::predef(racine).open_subkey(cle).ok()?;
            let valeurs: serde_json::Map<String, Value> = [
                "SafeBrowsingProtectionLevel",
                "SafeBrowsingEnabled",
                "SmartScreenEnabled",
            ]
            .into_iter()
            .filter_map(|v| k.get_value::<u32, _>(v).ok().map(|d| (v.to_string(), d.into())))
            .collect();
            Some((format!("{court}\\{cle}"), Value::Object(valeurs)))
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn strategies(_nom: &str) -> Vec<(String, Value)> {
    Vec::new()
}

/// Une stratégie qui coupe la protection : les Paramètres ne peuvent pas la rallumer.
fn juger_strategie(navigateur: &str, ou: &str, regle: &str) -> Constat {
    alerte(
        CAT,
        Niveau::Moyen,
        trf!(
            "{navigateur} : protection contre les sites frauduleux coupée par une stratégie imposée ({regle}), que les Paramètres ne peuvent pas rallumer. Si personne ne gère cet ordinateur (école, travail), un logiciel indésirable l'a sans doute posée.",
            "{navigateur}: protection against fraudulent sites turned off by an enforced policy ({regle}), which Settings cannot turn back on. If nobody manages this computer (school, work), unwanted software probably set it."
        ),
    )
    .manuel(
        trf!(
            "Retirer la stratégie (droits d'administrateur) : {ou} ; puis un examen antivirus",
            "Remove the policy (administrator rights): {ou}; then an antivirus scan"
        ),
        &[],
    )
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
    let mut strategies_lues = Vec::new();
    for (nom, racine, firefox) in super::extensions::racines() {
        let profils = super::extensions::profils(&racine, firefox);
        // Une stratégie vaut pour tous les profils du navigateur : dite une fois, s'il y en a un.
        if !profils.is_empty() && !strategies_lues.contains(&nom) {
            strategies_lues.push(nom);
            if let Some((ou, regle)) = strategies(nom)
                .iter()
                .find_map(|(ou, s)| coupee_par(s, firefox).map(|r| (ou.clone(), r)))
            {
                constats.push(juger_strategie(nom, &ou, &regle));
            }
        }
        let plusieurs = profils.len() > 1;
        for (dossier, chemin) in profils {
            let reel = chemin.canonicalize().unwrap_or_else(|_| chemin.clone());
            if vus.contains(&reel) {
                continue;
            }
            vus.push(reel);
            let lire = |f: &str| std::fs::read_to_string(chemin.join(f)).unwrap_or_default();
            let reglages = if firefox {
                Some(lire_firefox(&(lire("prefs.js") + &lire("user.js"))))
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
            constats.push(match reglages {
                Some(r) => juger(&navigateur, &r),
                None => impossible(
                    CAT,
                    &trf!(
                        "réglages de {navigateur} illisibles (Preferences)",
                        "{navigateur} settings unreadable (Preferences)"
                    ),
                ),
            });
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
        let r = lire_chromium(r#"{"safebrowsing":{"enabled":true,"enhanced":true}}"#, "{}").unwrap();
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
        )
        .unwrap();
        assert_eq!(
            r,
            Reglages {
                anti_hameconnage: false,
                cookies_ouverts: true,
                dns_chiffre: Some(true)
            }
        );
    }

    #[test]
    fn preferences_illisibles_jamais_actives() {
        // Abîmé, vide ou en cours d'écriture : rien n'est conclu (avant, la protection passait pour active).
        for texte in ["", "{\"safebrowsing\":", "[]", "null"] {
            assert_eq!(lire_chromium(texte, "{}"), None, "{texte}");
        }
    }

    #[test]
    fn strategies_qui_coupent() {
        let json = |t: &str| serde_json::from_str::<Value>(t).unwrap();
        // Chromium : fichiers de /etc (booléen ou nombre) et registre (DWORD) ; Edge par SmartScreen.
        for t in [
            r#"{"SafeBrowsingProtectionLevel":0}"#,
            r#"{"SafeBrowsingEnabled":false}"#,
            r#"{"SafeBrowsingEnabled":0}"#,
            r#"{"SmartScreenEnabled":0}"#,
        ] {
            assert!(coupee_par(&json(t), false).is_some(), "{t}");
        }
        // Protection standard ou renforcée, autre stratégie, rien : pas coupée.
        for t in [
            r#"{"SafeBrowsingProtectionLevel":1}"#,
            r#"{"SafeBrowsingProtectionLevel":2,"SmartScreenEnabled":1}"#,
            r#"{"HomepageLocation":"https://exemple.org"}"#,
            "{}",
            "null",
        ] {
            assert_eq!(coupee_par(&json(t), false), None, "{t}");
        }
        // Firefox : préférence imposée, nue ou verrouillée ; les autres préférences ne comptent pas.
        assert!(
            coupee_par(
                &json(r#"{"Preferences":{"browser.safebrowsing.phishing.enabled":false}}"#),
                true
            )
            .is_some()
        );
        assert!(
            coupee_par(
                &json(r#"{"Preferences":{"browser.safebrowsing.malware.enabled":{"Value":false,"Status":"locked"}}}"#),
                true
            )
            .is_some()
        );
        assert_eq!(
            coupee_par(
                &json(r#"{"Preferences":{"browser.safebrowsing.phishing.enabled":{"Value":true}}}"#),
                true
            ),
            None
        );
        assert_eq!(coupee_par(&json(r#"{"SafeBrowsingEnabled":false}"#), true), None);
        let c = juger_strategie(
            "Chrome",
            "/etc/opt/chrome/policies/managed/x.json",
            "SafeBrowsingEnabled = 0",
        );
        assert!(c.probleme == Some(Niveau::Moyen) && c.message.contains("SafeBrowsingEnabled"));
    }
}
