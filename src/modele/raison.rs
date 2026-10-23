//! Pourquoi un constat n'a pas pu être vérifié, en type et non en texte : un code stable (« muette ») que les
//! scripts et l'historique comparent, et un texte dans les deux langues pour l'écran.
//!
//! `traces::Raison` (droits, délai, place, bornes de la collecte) reste à part pour l'instant : elle porte des cas
//! propres aux traces et leur texte bilingue (`Bi`). Les réunir se fera avec le canal d'erreur commun (étape E5).

/// La raison d'un « non vérifié ».
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Raison {
    /// Réservé à root ou à l'administrateur.
    #[cfg_attr(not(test), allow(dead_code))] // posée au fil de la migration des règles (E5)
    Droits,
    /// L'outil qui lit n'est pas sur cet ordinateur (son nom).
    Absente(String),
    /// La lecture a échoué : le pourquoi, tel que le système le dit.
    #[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
    // posée au fil de la migration des règles (E5)
    Illisible(String),
    /// La règle n'a rien rendu : ni sain, ni problème, ni raison. Jamais compté sain.
    Muette,
    /// La règle a planté (rattrapée) : son identifiant suit le constat.
    Panique,
    /// Écrit par une version plus ancienne de Vanguard (ou à la main) : ce qu'elle ne savait pas écrire manque.
    VersionAncienne,
    /// Un « impossible » d'avant ce modèle, dont la raison n'est que dans le message.
    NonPrecisee,
}

impl Raison {
    /// Le code stable, sans langue : il ne change jamais pour un même cas.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Raison::Droits => "droits",
            Raison::Absente(_) => "absente",
            Raison::Illisible(_) => "illisible",
            Raison::Muette => "muette",
            Raison::Panique => "panique",
            Raison::VersionAncienne => "version-ancienne",
            Raison::NonPrecisee => "non-precisee",
        }
    }

    /// Le texte en français et en anglais : montré par le canal d'erreur commun (étape E5) ; ici, vérifié par T11.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn textes(&self) -> (String, String) {
        match self {
            Raison::Droits if cfg!(windows) => ("réservé à l'administrateur".into(), "administrator only".into()),
            Raison::Droits => ("réservé à root".into(), "root only".into()),
            Raison::Absente(c) => (format!("« {c} » absent"), format!("“{c}” missing")),
            Raison::Illisible(e) => (format!("illisible : {e}"), format!("unreadable: {e}")),
            Raison::Muette => (
                "la vérification n'a rien rendu".into(),
                "the check returned nothing".into(),
            ),
            Raison::Panique => ("erreur interne".into(), "internal error".into()),
            Raison::VersionAncienne => (
                "écrit par une version plus ancienne".into(),
                "written by an older version".into(),
            ),
            Raison::NonPrecisee => ("raison dans le message".into(), "reason in the message".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T11 : un code par cas, jamais deux fois le même, et un texte dans les deux langues.
    #[test]
    fn codes_uniques_et_textes_bilingues() {
        let toutes = [
            Raison::Droits,
            Raison::Absente("nmcli".into()),
            Raison::Illisible("accès refusé".into()),
            Raison::Muette,
            Raison::Panique,
            Raison::VersionAncienne,
            Raison::NonPrecisee,
        ];
        let mut codes = std::collections::HashSet::new();
        for r in &toutes {
            assert!(codes.insert(r.code()), "code en double : {}", r.code());
            assert!(r.code().chars().all(|c| c.is_ascii_lowercase() || c == '-'));
            let (fr, en) = r.textes();
            assert!(!fr.is_empty() && !en.is_empty(), "{r:?}");
        }
    }

    /// Le plafond des fonctions qui rendent leur erreur en texte (`-> Result<_, String>`) : le canal d'erreur
    /// commun (étape E5) les fera baisser ; une nouvelle ne doit pas s'y ajouter. Baisser ce nombre, jamais le monter.
    /// Une seule exception, à la fusion du 23 oct. : les 6 du lot « preuve et réponse », écrit en même temps que ce
    /// cliquet (196 → 202) ; E5 les reprend en premier.
    const ERREURS_EN_TEXTE_AU_PLUS: usize = 202;

    /// T13 : le cliquet des erreurs en texte, compté hors des modules de tests.
    #[test]
    fn cliquet_des_erreurs_en_texte() {
        fn compter(d: &std::path::Path) -> usize {
            let mut n = 0;
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    n += compter(&p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let texte = std::fs::read_to_string(&p).unwrap();
                    let code = texte.find("#[cfg(test)]\nmod ").map_or(texte.as_str(), |t| &texte[..t]);
                    n += code
                        .lines()
                        .filter(|l| l.find("-> Result<").is_some_and(|i| l[i..].contains(", String>")))
                        .count();
                }
            }
            n
        }
        let n = compter(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
        assert!(n > 50, "{n} seulement : le compte ne lit plus les sources");
        assert!(
            n <= ERREURS_EN_TEXTE_AU_PLUS,
            "{n} fonctions rendent leur erreur en texte, plafond {ERREURS_EN_TEXTE_AU_PLUS} : ne pas en ajouter"
        );
    }
}
