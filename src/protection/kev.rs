//! Le catalogue des failles exploitées de la CISA (Known Exploited Vulnerabilities) : les CVE dont une attaque réelle
//! est connue. Une faille connue d'un logiciel installé qui y figure passe avant les autres. Téléchargé en entier (la
//! liste des logiciels de l'ordinateur ne sort jamais), gardé un jour ; hors ligne, la copie d'avant sert jusqu'à un
//! mois. Le catalogue suit les faits : une faille exploitée d'hier peut ne pas y être encore (PHP2Shell, 21 oct. 2026).

use std::collections::HashSet;
use std::time::Duration;

use crate::{tr, trf};

const ADRESSE: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const FRAICHE: Duration = Duration::from_hours(24);
const TROP_VIEILLE: Duration = Duration::from_hours(30 * 24);

/// Les CVE exploitées, en majuscules. `Err` : pourquoi le catalogue ne sert pas ; rien n'est alors dit « pas exploité ».
pub(crate) fn exploitees() -> Result<HashSet<String>, String> {
    use crate::protection::abuse_ch::{self, Echec};
    let demande = crate::http::Demande {
        taille_max: 64 << 20,
        ..crate::http::Demande::get(ADRESSE, Duration::from_secs(60))
    };
    let (octets, age) = abuse_ch::liste(demande, ("kev", "kev.json"), FRAICHE)
        .resultat(false)
        .map_err(|e| match e {
            Echec::Reponse(code) => trf!("la CISA a répondu {code}", "CISA answered {code}"),
            Echec::SansReponse => tr!("pas d'Internet ?", "no Internet?").to_string(),
            autre => autre.raison(),
        })?;
    if age > TROP_VIEILLE {
        return Err(tr!(
            "copie de plus d'un mois, rafraîchissement impossible",
            "copy more than a month old, could not refresh it"
        )
        .to_string());
    }
    analyser(&octets).ok_or_else(|| {
        tr!(
            "catalogue illisible (page d'un portail Wi-Fi ?)",
            "catalog unreadable (a Wi-Fi portal page?)"
        )
        .to_string()
    })
}

/// `{"vulnerabilities": [{"cveID": "CVE-…"}, …]}`. `None` pour tout autre texte : jamais un catalogue vide, donc
/// « rien d'exploité », à sa place.
fn analyser(octets: &[u8]) -> Option<HashSet<String>> {
    let v: serde_json::Value = serde_json::from_slice(octets).ok()?;
    let liste = v["vulnerabilities"].as_array()?;
    let cves: HashSet<String> = liste
        .iter()
        .filter_map(|e| e["cveID"].as_str())
        .map(|c| c.trim().to_uppercase())
        .collect();
    (!cves.is_empty()).then_some(cves)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_lu() {
        let json = br#"{"title":"CISA Catalog","vulnerabilities":[{"cveID":"CVE-2021-44228","product":"Log4j"},{"cveID":"cve-2024-3400"}]}"#;
        let c = analyser(json).unwrap();
        assert!(c.contains("CVE-2021-44228") && c.contains("CVE-2024-3400") && c.len() == 2);
        // Portail Wi-Fi, catalogue vide ou d'une autre forme : pas lu, jamais « rien d'exploité ».
        for t in [
            &b"<html>Salon</html>"[..],
            br#"{"vulnerabilities":[]}"#,
            br#"{"title":"x"}"#,
        ] {
            assert!(analyser(t).is_none());
        }
    }
}
