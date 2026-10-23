//! Les casks de Homebrew (licence BSD-2-Clause) : `cask.json`, le fichier entier (19 Mo, 2 Mo en gzip), pris par
//! HTTPS sans vérifier sa signature (décision de l'auteur). Jamais l'adresse d'un cask en particulier, qui dirait le
//! logiciel cherché. Lu en structures typées : seuls le nom, la version et `auto_updates` de chaque cask, le reste
//! (artefacts, variations par macOS) ignoré sans être gardé.

use std::collections::HashMap;

use serde::Deserialize;

use super::Souple;

/// Au-dessous, ce n'est pas le fichier complet (7 803 casks le 23 oct. 2026).
const CASKS_MIN: usize = 1000;

#[derive(Deserialize)]
struct CaskBrut {
    token: Souple<String>,
    #[serde(default)]
    version: Option<Souple<String>>,
    #[serde(default)]
    auto_updates: Option<Souple<bool>>,
}

/// La version d'un cask, telle que Homebrew l'écrit avant la virgule (« 156.0.4314.42,uuid » → « 156.0.4314.42 »),
/// et s'il se met à jour tout seul.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cask {
    pub version: String,
    pub auto_updates: bool,
}

/// Les casks par nom. Un cask à `version: "latest"` (sans numéro) est écarté : il ne dit rien. `None` : pas le
/// fichier attendu (moins de 1 000 casks, JSON illisible).
pub(crate) fn casks(octets: &[u8]) -> Option<HashMap<String, Cask>> {
    casks_au_moins(octets, CASKS_MIN)
}

fn casks_au_moins(octets: &[u8], minimum: usize) -> Option<HashMap<String, Cask>> {
    let bruts: Vec<CaskBrut> = serde_json::from_slice(octets).ok()?;
    if bruts.len() < minimum {
        return None;
    }
    Some(
        bruts
            .into_iter()
            .filter_map(|c| {
                let version = c.version.and_then(Souple::bon)?;
                let version = version.split(',').next()?.trim();
                if version.is_empty() || version == "latest" {
                    return None;
                }
                Some((
                    c.token.bon()?,
                    Cask {
                        version: version.to_string(),
                        auto_updates: c.auto_updates.and_then(Souple::bon).unwrap_or(false),
                    },
                ))
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Copie réduite du fichier réel (BSD-2-Clause, voir assets/essais/LICENCES-ESSAIS.txt).
    const EXTRAIT: &[u8] = include_bytes!("../../../../assets/essais/cask-extrait.json");

    #[test]
    fn copie_reduite_lue() {
        // Le vrai fichier a des milliers de casks : la copie réduite n'est pas prise pour lui.
        assert_eq!(casks(EXTRAIT), None);
        let lus = casks_au_moins(EXTRAIT, 1).unwrap();
        for nom in [
            "google-chrome",
            "firefox",
            "microsoft-word",
            "adobe-acrobat-reader",
            "brave-browser",
            "temurin",
        ] {
            let cask = lus
                .get(nom)
                .unwrap_or_else(|| panic!("{nom} absent : {:?}", lus.keys()));
            assert!(!cask.version.contains(','), "{nom} {}", cask.version);
            assert!(
                cask.version.starts_with(|c: char| c.is_ascii_digit()),
                "{nom} {}",
                cask.version
            );
        }
        assert!(lus["google-chrome"].auto_updates);
        // « latest » : écarté.
        assert!(lus.len() < EXTRAIT.windows(8).filter(|f| f == b"\"token\":").count());
    }

    #[test]
    fn formes_inattendues() {
        let json = br#"[
            {"token": "a", "version": "1.2,abc", "auto_updates": null},
            {"token": "b", "version": "latest"},
            {"token": "c", "version": 3},
            {"token": 4, "version": "1.0"},
            {"token": "d"}
        ]"#;
        let lus = casks_au_moins(json, 1).unwrap();
        assert_eq!(lus.len(), 1);
        assert_eq!(
            lus["a"],
            Cask {
                version: "1.2".into(),
                auto_updates: false
            }
        );
        assert_eq!(casks_au_moins(b"{}", 1), None);
        assert_eq!(casks_au_moins(b"<html>", 1), None);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 500, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..300)) {
            let _ = casks_au_moins(&octets, 0);
        }
    }
}
