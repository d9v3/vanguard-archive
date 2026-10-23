//! endoflife.date (licence MIT) : pour chaque produit, ses branches, la dernière version de chacune et la fin de son
//! support. Le fichier entier (`api/v1/products/full`, 3 Mo, 320 Kio en gzip) ; seuls les produits d'une liste fermée
//! sont gardés. Son `latest` peut retarder sur l'éditeur : il ne sert que là où l'éditeur n'a pas de source fixe
//! (Java).

use chrono::NaiveDate;
use serde::Deserialize;

use super::Souple;

/// Les produits gardés : Java des quatre distributions comparées, puis la longue traîne (plus tard). Azul Zulu n'y est pas : sa version n'est pas une version de Java.
pub(crate) const PRODUITS: [&str; 7] = [
    "oracle-jdk",
    "eclipse-temurin",
    "amazon-corretto",
    "microsoft-build-of-openjdk",
    "python",
    "nodejs",
    "notepad-plus-plus",
];

/// Au-dessous, ce n'est pas le fichier complet (485 produits le 23 oct. 2026).
const TOTAL_MIN: u32 = 100;

#[derive(Deserialize)]
struct Tout {
    total: u32,
    result: Vec<ProduitBrut>,
}

#[derive(Deserialize)]
struct ProduitBrut {
    name: String,
    #[serde(default)]
    releases: Option<Souple<Vec<BrancheBrute>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrancheBrute {
    #[serde(default)]
    name: Option<Souple<String>>,
    #[serde(default)]
    is_eol: Option<Souple<bool>>,
    #[serde(default)]
    is_maintained: Option<Souple<bool>>,
    #[serde(default)]
    eol_from: Option<Souple<String>>,
    #[serde(default)]
    latest: Option<Souple<Derniere>>,
}

#[derive(Deserialize)]
struct Derniere {
    #[serde(default)]
    name: Option<Souple<String>>,
    #[serde(default)]
    date: Option<Souple<String>>,
}

// Lues en flux par `Souple` : tous leurs champs sont facultatifs, une branche sans nom est écartée plus bas.
super::forme_objet!(BrancheBrute, Derniere);

/// Un produit gardé et ses branches.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProduitEol {
    pub nom: String,
    pub branches: Vec<BrancheEol>,
}

/// Une branche (« 21 », « 8 », « 3.13 ») : finie ou non, depuis quand, sa dernière version telle qu'écrite (chaque
/// distribution a sa forme : `version::java_eol`) et sa date.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BrancheEol {
    pub nom: String,
    pub finie: Option<bool>,
    pub fin: Option<NaiveDate>,
    pub derniere: Option<String>,
    pub date: Option<NaiveDate>,
}

/// Les produits gardés. `None` : pas le fichier attendu (`total` sous 100, JSON illisible).
pub(crate) fn lire(octets: &[u8]) -> Option<Vec<ProduitEol>> {
    let tout: Tout = serde_json::from_slice(octets).ok()?;
    if tout.total < TOTAL_MIN {
        return None;
    }
    let date = |d: Option<Souple<String>>| {
        d.and_then(Souple::bon)
            .and_then(|t| NaiveDate::parse_from_str(t.get(..10)?, "%Y-%m-%d").ok())
    };
    Some(
        tout.result
            .into_iter()
            .filter(|p| PRODUITS.contains(&p.name.as_str()))
            .map(|p| ProduitEol {
                branches: p
                    .releases
                    .and_then(Souple::bon)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|b| {
                        // Sans nom lisible, la dernière version ne dit rien, sa date non plus.
                        let (derniere, depuis) = match b.latest.and_then(Souple::bon) {
                            Some(d) => match d.name.and_then(Souple::bon) {
                                Some(nom) => (Some(nom), date(d.date)),
                                None => (None, None),
                            },
                            None => (None, None),
                        };
                        Some(BrancheEol {
                            nom: b.name.and_then(Souple::bon)?,
                            // endoflife.date met isEol à la fin du support de base (Oracle 8, 11, 17), alors
                            // que la branche reçoit encore des correctifs : isMaintained fait foi.
                            finie: match b.is_maintained.and_then(Souple::bon) {
                                Some(true) => Some(false),
                                _ => b.is_eol.and_then(Souple::bon),
                            },
                            fin: date(b.eol_from),
                            derniere,
                            date: depuis,
                        })
                    })
                    .collect(),
                nom: p.name,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::perimes::version::{FormeJava, Version, java_eol};

    /// Copie réduite du fichier réel (MIT, voir assets/essais/LICENCES-ESSAIS.txt).
    const EXTRAIT: &[u8] = include_bytes!("../../../../assets/essais/eol-extrait.json");

    #[test]
    fn copie_reduite_lue() {
        let produits = lire(EXTRAIT).unwrap();
        let noms: Vec<&str> = produits.iter().map(|p| p.nom.as_str()).collect();
        // Firefox et Azul Zulu sont dans la copie, mais pas dans la liste fermée.
        assert!(!noms.contains(&"firefox") && !noms.contains(&"azul-zulu"), "{noms:?}");
        for attendu in [
            "oracle-jdk",
            "eclipse-temurin",
            "amazon-corretto",
            "microsoft-build-of-openjdk",
        ] {
            assert!(noms.contains(&attendu), "{attendu} : {noms:?}");
        }
        // Chaque dernière version de Java se lit dans la forme de sa distribution.
        for (nom, forme) in [
            ("oracle-jdk", FormeJava::Oracle),
            ("eclipse-temurin", FormeJava::Temurin),
            ("amazon-corretto", FormeJava::Corretto),
            ("microsoft-build-of-openjdk", FormeJava::Microsoft),
        ] {
            let p = produits.iter().find(|p| p.nom == nom).unwrap();
            assert!(!p.branches.is_empty(), "{nom}");
            for b in &p.branches {
                let derniere = b.derniere.as_deref().unwrap_or_else(|| panic!("{nom} {}", b.nom));
                let lue = java_eol(derniere, forme).unwrap_or_else(|| panic!("{nom} {derniere}"));
                // La branche est le premier champ (« 21 », « 8 »).
                assert_eq!(Some(lue.majeur()), b.nom.parse().ok(), "{nom} {derniere}");
                assert!(b.finie.is_some() && b.date.is_some(), "{nom} {}", b.nom);
            }
        }
        let temurin = produits.iter().find(|p| p.nom == "eclipse-temurin").unwrap();
        let b21 = temurin.branches.iter().find(|b| b.nom == "21").unwrap();
        assert_eq!(b21.finie, Some(false));
        assert!(b21.fin.is_some());
        assert_eq!(
            java_eol(b21.derniere.as_deref().unwrap(), FormeJava::Temurin),
            Version::lire("21.0.13")
        );
    }

    #[test]
    fn autre_chose_refuse() {
        assert_eq!(lire(b"{\"total\": 12, \"result\": []}"), None);
        assert_eq!(lire(b"<html>Portail</html>"), None);
        // Un champ d'un autre type n'empêche pas de lire le reste.
        let souple = br#"{"total": 485, "result": [
            {"name": "eclipse-temurin", "releases": [
                {"name": "21", "isEol": "oui", "eolFrom": 3, "latest": {"name": "21.0.13+9", "date": null}},
                {"name": 8, "isEol": false}
            ]},
            {"name": "python", "releases": "aucune"}
        ]}"#;
        let produits = lire(souple).unwrap();
        assert_eq!(produits[0].branches.len(), 1);
        let b = &produits[0].branches[0];
        assert_eq!((b.finie, b.fin, b.date), (None, None, None));
        assert_eq!(b.derniere.as_deref(), Some("21.0.13+9"));
        assert_eq!(produits[1].branches, []);
    }

    /// Oracle JDK 17 après la fin de son support de base : isEol vrai, mais toujours corrigée (isMaintained).
    #[test]
    fn branche_encore_corrigee_pas_finie() {
        let json = br#"{"total": 485, "result": [
            {"name": "oracle-jdk", "releases": [
                {"name": "17", "isEol": true, "isMaintained": true, "eolFrom": "2026-09-30",
                 "latest": {"name": "17.0.21", "date": "2026-10-21"}},
                {"name": "22", "isEol": true, "isMaintained": false, "eolFrom": "2024-09-17"},
                {"name": "23", "isEol": true, "isMaintained": "?"},
                {"name": "25", "isEol": false}
            ]}
        ]}"#;
        let produits = lire(json).unwrap();
        let finie: Vec<Option<bool>> = produits[0].branches.iter().map(|b| b.finie).collect();
        assert_eq!(finie, [Some(false), Some(true), Some(true), Some(false)]);
        // La copie réduite du vrai fichier : Oracle 8 est dans ce cas.
        let vraie = lire(EXTRAIT).unwrap();
        let oracle = vraie.iter().find(|p| p.nom == "oracle-jdk").unwrap();
        assert_eq!(
            oracle.branches.iter().find(|b| b.nom == "8").unwrap().finie,
            Some(false)
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 500, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..300)) {
            let _ = lire(&octets);
        }
    }
}
