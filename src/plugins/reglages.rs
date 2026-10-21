//! L'interrupteur « Restrictions » des extensions. Actives par défaut (approbation par empreinte, analyse, bornes,
//! environnement minimal, jamais en administrateur, jamais dans le bilan ni la surveillance). Coupées, pour tout ou
//! pour un élément (`confiance = "totale"` dans un plugin.toml, ou l'élément marqué « à moi » au menu), l'extension
//! tourne comme un programme de la personne : sans accord, sans contrôle d'empreinte ni analyse, avec de très larges
//! bornes, tout l'environnement, en administrateur si Vanguard l'est, et dans le bilan ou la surveillance si son
//! manifeste le demande. Ses constats restent marqués et hors de la note.
//!
//! Une seule chose reste, même coupées : le dossier des extensions doit être à la personne et fermé aux autres comptes
//! (`dossier`), sinon un programme d'un autre compte pourrait y poser du code qui tournerait comme elle sans rien
//! demander. Ce contrôle échoue : rien ne tourne, et Vanguard dit pourquoi.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{tr, trf};

const FICHIER: &str = "reglages.json";

/// Bornes très larges des extensions sans restrictions : elles ne servent qu'à ne jamais figer Vanguard pour de bon.
pub const DELAI_LIBRE: u64 = 6 * 3600;
pub const SORTIE_LIBRE: usize = 64 << 20;

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Reglages {
    /// Les restrictions coupées pour toutes les extensions.
    #[serde(default)]
    pub sans_restrictions: bool,
    /// La confirmation de la coupure a déjà été donnée une fois : on ne la redemande plus.
    #[serde(default)]
    pub coupure_confirmee: bool,
    /// Les éléments marqués « à moi » : restrictions coupées pour eux seuls.
    #[serde(default)]
    pub plugins_a_moi: Vec<String>,
    #[serde(default)]
    pub labo_a_moi: Vec<String>,
}

/// Les réglages ; un fichier illisible laisse les restrictions actives.
pub fn charger(racine: &Path) -> Reglages {
    super::lire_sur(&racine.join(FICHIER), 64 << 10)
        .ok()
        .and_then(|o| serde_json::from_slice(&o).ok())
        .unwrap_or_default()
}

pub fn enregistrer(racine: &Path, r: &Reglages) -> Result<(), String> {
    let texte = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
    crate::reseau::ecrire_atomique(&racine.join(FICHIER), texte)
        .map_err(|e| trf!("Réglage impossible à écrire : {e}", "Could not write the setting: {e}"))
}

impl Reglages {
    pub fn plugin_libre(&self, m: &super::Manifeste) -> bool {
        self.sans_restrictions || m.confiance_totale || self.plugins_a_moi.contains(&m.nom)
    }

    pub fn labo_libre(&self, fichier: &str) -> bool {
        self.sans_restrictions || self.labo_a_moi.iter().any(|f| f == fichier)
    }
}

/// Ce que dit l'interrupteur, et la phrase qui explique ce qui reste.
pub fn ce_qui_reste() -> &'static str {
    tr!(
        "Même sans restrictions, le dossier des extensions doit être à toi et fermé aux autres comptes : sinon un programme d'un autre compte pourrait y poser du code qui tournerait comme toi, sans rien demander.",
        "Even without restrictions, the extensions folder must be yours and closed to other accounts: otherwise a program of another account could drop code there that would run as you, without asking anything."
    )
}

/// Bascule l'interrupteur général. Couper demande l'accord une seule fois (puis plus jamais) ; remettre est immédiat.
/// Rend le nouvel état (vrai : sans restrictions).
pub fn basculer(racine: &Path, accord: impl FnOnce(&str) -> bool) -> Result<bool, String> {
    let mut r = charger(racine);
    if r.sans_restrictions {
        r.sans_restrictions = false;
    } else {
        if !r.coupure_confirmee {
            if !accord(tr!(
                "  Les extensions tourneront sans contrôle, avec tous tes droits. Activer ? [o/N] : ",
                "  Extensions will run without any check, with all your rights. Turn on? [y/N]: "
            )) {
                return Ok(false);
            }
            r.coupure_confirmee = true;
        }
        r.sans_restrictions = true;
    }
    enregistrer(racine, &r)?;
    Ok(r.sans_restrictions)
}

/// Bascule un élément « à moi » (plugin ou script du labo), même accord unique que l'interrupteur général. Rend le
/// nouvel état de l'élément.
pub fn basculer_element(
    racine: &Path,
    labo: bool,
    nom: &str,
    accord: impl FnOnce(&str) -> bool,
) -> Result<bool, String> {
    let mut r = charger(racine);
    let liste = if labo { &mut r.labo_a_moi } else { &mut r.plugins_a_moi };
    if let Some(i) = liste.iter().position(|n| n == nom) {
        liste.remove(i);
        enregistrer(racine, &r)?;
        return Ok(false);
    }
    if !r.coupure_confirmee {
        if !accord(tr!(
            "  Cet élément tournera sans contrôle, avec tous tes droits. Activer ? [o/N] : ",
            "  This item will run without any check, with all your rights. Turn on? [y/N]: "
        )) {
            return Ok(false);
        }
        r.coupure_confirmee = true;
    }
    let liste = if labo { &mut r.labo_a_moi } else { &mut r.plugins_a_moi };
    liste.push(nom.to_string());
    enregistrer(racine, &r)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn couper_demande_une_fois_remettre_jamais() {
        let d = std::env::temp_dir().join(format!("vanguard-reglages-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        super::super::creer_prive(&d).unwrap();
        // Refusé : rien ne change.
        assert!(!basculer(&d, |_| false).unwrap());
        assert_eq!(charger(&d), Reglages::default());
        assert!(basculer(&d, |_| true).unwrap());
        // Remettre : sans question ; recouper : plus de question non plus.
        assert!(!basculer(&d, |_| panic!("aucune question")).unwrap());
        assert!(basculer(&d, |_| panic!("aucune question")).unwrap());
        assert!(charger(&d).labo_libre("essai.sh"));
        basculer(&d, |_| true).unwrap();
        assert!(basculer_element(&d, true, "essai.sh", |_| panic!("déjà confirmé")).unwrap());
        assert!(charger(&d).labo_libre("essai.sh") && !charger(&d).labo_libre("autre.sh"));
        assert!(!basculer_element(&d, true, "essai.sh", |_| true).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }
}
