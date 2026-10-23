//! Le JSON avec commentaires (JSONC) : réglages de VS Code et de ses dérivés, des agents d'IA, stratégies de Chrome
//! sous Linux. Deux lecteurs existaient ; celui des stratégies de Chrome gardait la virgule de « 1, // c » devant
//! une « } », refusait alors un fichier que Chrome lit, et ne retirait pas l'indicateur d'ordre des octets (BOM).

use serde_json::Value;

/// Le JSONC des réglages de VS Code (que Cursor et Windsurf reprennent) ramené au JSON : commentaires « // » et
/// « /* */ », et virgules finales, retirés hors des chaînes. Un commentaire devient une espace, ses fins de ligne
/// restent : deux mots qu'il séparait le restent.
pub(crate) fn json_sans_jsonc(texte: &str) -> String {
    let mut json = String::with_capacity(texte.len());
    let mut car = texte.chars().peekable();
    // Une virgule pas encore suivie d'autre chose que des blancs ou des commentaires : finale si « } » ou « ] » vient.
    let mut virgule: Option<usize> = None;
    while let Some(c) = car.next() {
        match c {
            '"' => {
                virgule = None;
                json.push(c);
                while let Some(c) = car.next() {
                    json.push(c);
                    match c {
                        '\\' => json.extend(car.next()),
                        '"' => break,
                        _ => {}
                    }
                }
            }
            '/' if car.peek() == Some(&'/') => {
                for c in car.by_ref() {
                    if c == '\n' {
                        json.push(c);
                        break;
                    }
                }
            }
            '/' if car.peek() == Some(&'*') => {
                car.next();
                let mut etoile = false;
                for c in car.by_ref() {
                    if c == '\n' {
                        json.push(c);
                    }
                    if etoile && c == '/' {
                        break;
                    }
                    etoile = c == '*';
                }
                json.push(' ');
            }
            '}' | ']' => {
                if let Some(i) = virgule.take() {
                    json.replace_range(i..=i, " ");
                }
                json.push(c);
            }
            ',' => {
                virgule = Some(json.len());
                json.push(c);
            }
            _ => {
                if !c.is_whitespace() {
                    virgule = None;
                }
                json.push(c);
            }
        }
    }
    json
}

/// Un fichier de réglages lu en JSON, ou à défaut en JSONC ; `None` s'il n'est ni l'un ni l'autre.
pub(crate) fn lire_json(octets: &[u8]) -> Option<Value> {
    if let Ok(json) = serde_json::from_slice(octets) {
        return Some(json);
    }
    let texte = std::str::from_utf8(octets).ok()?;
    serde_json::from_str(&json_sans_jsonc(texte.trim_start_matches('\u{feff}'))).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commentaires_virgules_et_bom() {
        let v =
            lire_json(b"{\n  // coupe\n  \"SafeBrowsingEnabled\": false, /* la */\n  \"A\": [1, 2,],\n}\n").unwrap();
        assert_eq!(v["SafeBrowsingEnabled"], false);
        assert_eq!(v["A"], serde_json::json!([1, 2]));
        // Ce que l'ancien lecteur des stratégies de Chrome refusait : la virgule, puis un commentaire, puis « } ».
        assert_eq!(lire_json(b"{\"B\": 1, // c\n}").unwrap()["B"], 1);
        assert_eq!(lire_json("\u{feff}{\"B\": 1, /* c */ }".as_bytes()).unwrap()["B"], 1);
        // Une virgule ou un « // » dans une chaîne restent.
        let v = lire_json(br#"{"U": "https://exemple.org/a,}", "B": 1,}"#).unwrap();
        assert_eq!(v["U"], "https://exemple.org/a,}");
        assert!(lire_json(b"{\"A\": ").is_none() && lire_json(b"pas du json").is_none());
    }
}
