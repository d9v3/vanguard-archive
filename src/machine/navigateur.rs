//! Réglages de sécurité des navigateurs : protection contre les sites frauduleux (Safe Browsing), cookies tiers,
//! DNS chiffré. Un navigateur n'écrit un réglage que s'il a été changé : sans valeur écrite, on retient sa valeur
//! par défaut. Une stratégie imposée (fichier de /etc sous Linux, registre sous Windows, policies.json de Firefox)
//! passe avant les Paramètres : un logiciel indésirable s'en sert pour couper la protection sans qu'on puisse la
//! rallumer. Celles de macOS (profils gérés) ne sont pas lues.

use std::collections::BTreeMap;

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

/// Les stratégies d'un navigateur, fusionnées comme il les applique : pour chaque clé, sa valeur et l'endroit d'où
/// elle vient. Imposées (« managed », Policies) ou recommandées (« recommended », …\Recommended : la valeur par défaut
/// tant que la personne n'a pas choisi). Firefox : son policies.json, et où il est. `illisibles` : fichiers présents
/// que même le JSON de Chrome (commentaires, virgules en trop) ne lit pas ; rien n'est conclu pour eux.
#[derive(Default)]
struct Strategies {
    imposees: BTreeMap<String, (Value, String)>,
    recommandees: BTreeMap<String, (Value, String)>,
    firefox: Option<(Value, String)>,
    illisibles: Vec<String>,
}

/// Le JSON des stratégies tel que Chrome le lit : commentaires `//` et `/* */`, virgule avant `}` ou `]` permis, par
/// le lecteur commun (`socle::jsonc`).
#[cfg(any(target_os = "linux", test))]
fn json_souple(texte: &str) -> Option<Value> {
    crate::socle::jsonc::lire_json(texte.as_bytes())
}

/// Une valeur de stratégie lue comme un nombre : booléen, nombre, ou chiffres d'une chaîne (registre REG_SZ).
fn nombre(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_bool().map(i64::from))
        .or_else(|| v.as_str()?.trim().parse().ok())
}

/// La règle Safe Browsing qui coupe la protection, et son origine. SafeBrowsingProtectionLevel, présent, passe avant
/// SafeBrowsingEnabled, comme dans Chrome.
fn safe_browsing_coupe(s: &BTreeMap<String, (Value, String)>) -> Option<(String, String)> {
    if let Some((v, ou)) = s.get("SafeBrowsingProtectionLevel") {
        return (nombre(v) == Some(0)).then(|| ("SafeBrowsingProtectionLevel = 0".to_string(), ou.clone()));
    }
    let (v, ou) = s.get("SafeBrowsingEnabled")?;
    (nombre(v) == Some(0)).then(|| ("SafeBrowsingEnabled = false".to_string(), ou.clone()))
}

const PREFS_SAFE_BROWSING: [&str; 2] = [
    "browser.safebrowsing.malware.enabled",
    "browser.safebrowsing.phishing.enabled",
];

/// Firefox : (préférence imposée qui coupe, préférence seulement par défaut qui coupe). Imposée : valeur nue (ancienne
/// forme, verrouillée) ou `"Status": "locked"` ; sinon (« default », « user », sans Status), la personne garde la main.
fn firefox_coupe(politiques: &Value) -> (Option<&'static str>, Option<&'static str>) {
    let prefs = &politiques["Preferences"];
    let imposee = PREFS_SAFE_BROWSING
        .into_iter()
        .find(|n| prefs[*n] == false || (prefs[*n]["Value"] == false && prefs[*n]["Status"] == "locked"));
    let par_defaut = PREFS_SAFE_BROWSING
        .into_iter()
        .find(|n| prefs[*n]["Value"] == false && prefs[*n]["Status"] != "locked");
    (imposee, par_defaut)
}

/// Les stratégies du navigateur `nom` (celui de `extensions::racines`). Pas lues : celles de macOS (profils gérés),
/// de Firefox sous Windows (registre Mozilla), des navigateurs en Flatpak (extensions de politiques).
#[cfg(target_os = "linux")]
fn strategies(nom: &str) -> Strategies {
    use std::path::Path;
    let mut s = Strategies::default();
    if nom == "Firefox" {
        // Le premier qui existe masque l'autre, comme dans Firefox.
        if let Some(c) = [
            "/etc/firefox/policies/policies.json",
            "/usr/lib/firefox/distribution/policies.json",
        ]
        .into_iter()
        .find(|c| Path::new(c).exists())
        {
            match std::fs::read_to_string(c).ok().as_deref().and_then(json_souple) {
                Some(v) => s.firefox = Some((v["policies"].clone(), c.to_string())),
                None => s.illisibles.push(c.to_string()),
            }
        }
        return s;
    }
    let bases: &[&str] = match nom {
        "Chrome" => &["/etc/opt/chrome/policies"],
        "Chromium" => &["/etc/chromium/policies", "/etc/chromium-browser/policies"],
        "Brave" => &["/etc/brave/policies"],
        "Edge" => &["/etc/opt/edge/policies"],
        _ => &[],
    };
    for base in bases {
        for (sous, cible) in [("managed", &mut s.imposees), ("recommended", &mut s.recommandees)] {
            // Tous les fichiers du dossier, quel que soit leur nom, dans l'ordre : le dernier gagne.
            let mut fichiers: Vec<_> = std::fs::read_dir(Path::new(base).join(sous))
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|c| c.is_file())
                .collect();
            fichiers.sort();
            for c in fichiers {
                let ou = c.display().to_string();
                match std::fs::read_to_string(&c).ok().as_deref().and_then(json_souple) {
                    Some(Value::Object(o)) => cible.extend(o.into_iter().map(|(k, v)| (k, (v, ou.clone())))),
                    _ => s.illisibles.push(ou),
                }
            }
        }
    }
    s
}

#[cfg(windows)]
fn strategies(nom: &str) -> Strategies {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let mut s = Strategies::default();
    let cle = match nom {
        "Chrome" => r"SOFTWARE\Policies\Google\Chrome",
        "Chromium" => r"SOFTWARE\Policies\Chromium",
        "Brave" => r"SOFTWARE\Policies\BraveSoftware\Brave",
        "Edge" => r"SOFTWARE\Policies\Microsoft\Edge",
        _ => return s,
    };
    // HKLM lu en dernier : il passe avant HKCU.
    for (racine, court) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
        for (sous, cible) in [("", &mut s.imposees), (r"\Recommended", &mut s.recommandees)] {
            let chemin = format!("{cle}{sous}");
            let Ok(k) = RegKey::predef(racine).open_subkey(&chemin) else {
                continue;
            };
            for v in ["SafeBrowsingProtectionLevel", "SafeBrowsingEnabled"] {
                // DWORD, ou chiffres en REG_SZ : Chrome applique les deux.
                let valeur = k
                    .get_value::<u32, _>(v)
                    .ok()
                    .map(Value::from)
                    .or_else(|| k.get_value::<String, _>(v).ok().map(Value::from));
                if let Some(valeur) = valeur {
                    cible.insert(v.to_string(), (valeur, format!(r"{court}\{chemin}\{v}")));
                }
            }
        }
    }
    s
}

#[cfg(target_os = "macos")]
fn strategies(_nom: &str) -> Strategies {
    Strategies::default()
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
    // Par navigateur, lu une fois : la stratégie recommandée qui coupe (Firefox : la préférence en cause).
    let mut recommandees: Vec<(&str, Option<&str>)> = Vec::new();
    for (nom, racine, firefox) in super::extensions::racines() {
        let profils = super::extensions::profils(&racine, firefox);
        if !profils.is_empty() && !recommandees.iter().any(|(n, _)| *n == nom) {
            let s = strategies(nom);
            let (imposee, recommandee) = if firefox {
                let (imposee, defaut) = s.firefox.as_ref().map_or((None, None), |(v, _)| firefox_coupe(v));
                let ou = s.firefox.as_ref().map(|(_, ou)| ou.clone()).unwrap_or_default();
                (imposee.map(|p| (format!("Preferences : {p} = false"), ou)), defaut)
            } else {
                let recommandee = safe_browsing_coupe(&s.recommandees).map(|_| "safebrowsing.enabled");
                (safe_browsing_coupe(&s.imposees), recommandee)
            };
            if let Some((regle, ou)) = imposee {
                constats.push(juger_strategie(nom, &ou, &regle));
            }
            if !s.illisibles.is_empty() {
                constats.push(impossible(
                    CAT,
                    &trf!(
                        "stratégies de {nom} illisibles : {}",
                        "{nom} policies unreadable: {}",
                        s.illisibles.join(", ")
                    ),
                ));
            }
            recommandees.push((nom, recommandee));
        }
        let recommandee = recommandees.iter().find(|(n, _)| *n == nom).and_then(|(_, r)| *r);
        let plusieurs = profils.len() > 1;
        for (dossier, chemin) in profils {
            let reel = chemin.canonicalize().unwrap_or_else(|_| chemin.clone());
            if vus.contains(&reel) {
                continue;
            }
            vus.push(reel);
            // Absent : un profil neuf, valeurs par défaut. Illisible : rien n'est conclu.
            let lire = |f: &str| match std::fs::read_to_string(chemin.join(f)) {
                Ok(t) => Ok(t),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
                Err(e) => Err(format!("{f} : {e}")),
            };
            let reglages = if firefox {
                lire("prefs.js").and_then(|p| Ok(p + &lire("user.js")?)).map(|prefs| {
                    let mut r = lire_firefox(&prefs);
                    // Une stratégie par défaut qui coupe vaut tant que la personne n'a rien écrit elle-même.
                    if recommandee.is_some_and(|n| pref(&prefs, n).is_none()) {
                        r.anti_hameconnage = false;
                    }
                    r
                })
            } else {
                let etat_local = std::fs::read_to_string(racine.join("Local State")).unwrap_or_default();
                lire("Preferences").and_then(|p| {
                    let mut r = lire_chromium(&p, &etat_local).ok_or_else(|| "Preferences".to_string())?;
                    let choisi =
                        serde_json::from_str::<Value>(&p).unwrap_or_default()["safebrowsing"]["enabled"].is_boolean();
                    if recommandee.is_some() && !choisi {
                        r.anti_hameconnage = false;
                    }
                    Ok(r)
                })
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
                Ok(r) => juger(&navigateur, &r),
                Err(raison) => impossible(
                    CAT,
                    &trf!(
                        "réglages de {navigateur} illisibles ({raison})",
                        "{navigateur} settings unreadable ({raison})"
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
        let fusion = |t: &str| -> BTreeMap<String, (Value, String)> {
            serde_json::from_str::<serde_json::Map<String, Value>>(t)
                .unwrap()
                .into_iter()
                .map(|(k, v)| (k, (v, "ici".to_string())))
                .collect()
        };
        // Coupée : niveau 0, ou Enabled faux sans niveau ; booléen, nombre ou chiffres en REG_SZ.
        for t in [
            r#"{"SafeBrowsingProtectionLevel":0}"#,
            r#"{"SafeBrowsingProtectionLevel":"0"}"#,
            r#"{"SafeBrowsingEnabled":false}"#,
            r#"{"SafeBrowsingEnabled":0}"#,
            r#"{"SafeBrowsingEnabled":"0"}"#,
        ] {
            assert!(safe_browsing_coupe(&fusion(t)).is_some(), "{t}");
        }
        // Le niveau passe avant Enabled ; SmartScreenEnabled (sans effet hors d'un Windows géré) ne compte pas.
        for t in [
            r#"{"SafeBrowsingProtectionLevel":1,"SafeBrowsingEnabled":false}"#,
            r#"{"SafeBrowsingProtectionLevel":2}"#,
            r#"{"SmartScreenEnabled":false}"#,
            r#"{"HomepageLocation":"https://exemple.org"}"#,
            "{}",
        ] {
            assert_eq!(safe_browsing_coupe(&fusion(t)), None, "{t}");
        }
        let json = |t: &str| serde_json::from_str::<Value>(t).unwrap();
        // Firefox : verrouillée (ou valeur nue) = imposée ; sinon seulement par défaut.
        let p = "browser.safebrowsing.phishing.enabled";
        assert_eq!(
            firefox_coupe(&json(&format!(r#"{{"Preferences":{{"{p}":false}}}}"#))),
            (Some(p), None)
        );
        assert_eq!(
            firefox_coupe(&json(&format!(
                r#"{{"Preferences":{{"{p}":{{"Value":false,"Status":"locked"}}}}}}"#
            ))),
            (Some(p), None)
        );
        for statut in ["", r#","Status":"default""#, r#","Status":"user""#] {
            assert_eq!(
                firefox_coupe(&json(&format!(
                    r#"{{"Preferences":{{"{p}":{{"Value":false{statut}}}}}}}"#
                ))),
                (None, Some(p)),
                "{statut}"
            );
        }
        assert_eq!(
            firefox_coupe(&json(&format!(r#"{{"Preferences":{{"{p}":{{"Value":true}}}}}}"#))),
            (None, None)
        );
        let c = juger_strategie(
            "Chrome",
            "/etc/opt/chrome/policies/managed/x",
            "SafeBrowsingEnabled = false",
        );
        assert!(c.probleme == Some(Niveau::Moyen) && c.message.contains("SafeBrowsingEnabled"));
    }

    #[test]
    fn json_comme_chrome() {
        // Commentaires et virgules en trop : Chrome applique le fichier, il doit se lire.
        let v =
            json_souple("{\n  // coupé\n  \"SafeBrowsingEnabled\": false, /* là */\n  \"A\": [1, 2,],\n}\n").unwrap();
        assert_eq!(v["SafeBrowsingEnabled"], false);
        assert_eq!(v["A"], serde_json::json!([1, 2]));
        // Dans une chaîne, « // » et « ,} » restent du texte.
        let v = json_souple(r#"{"U": "https://exemple.org/a,}", "B": 1,}"#).unwrap();
        assert_eq!(v["U"], "https://exemple.org/a,}");
        assert!(json_souple("{\"A\": ").is_none() && json_souple("pas du json").is_none());
    }
}
