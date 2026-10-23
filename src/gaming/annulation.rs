//! Annulation exacte des réglages pour jouer, sur le modèle de reglages.json d'Optimiser : les valeurs d'avant de
//! chaque réglage sont notées au moment où il est appliqué (jeux.json, dans les données de cet ordinateur), la plus
//! ancienne note reste, puis elles sont remises telles quelles depuis le menu Gaming. Une note ne part que quand ses
//! valeurs sont relues en place.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ui::*;

/// Une valeur notée : son nom (valeur du registre, fichier, réglage du noyau) et ce qu'elle valait (`None` : absente).
pub(crate) type Valeur = (String, Option<String>);

/// Ce qu'il faut noter pour pouvoir annuler un réglage : son nom stable et ses valeurs actuelles.
pub(crate) struct Annulable {
    pub(crate) id: &'static str,
    pub(crate) avant: Vec<Valeur>,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub(crate) struct Notes {
    pub(crate) reglages: BTreeMap<String, Avant>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Avant {
    pub(crate) titre: String,
    pub(crate) date: String,
    pub(crate) valeurs: Vec<Valeur>,
}

impl Notes {
    /// Note les valeurs d'avant d'un réglage, sauf s'il l'est déjà : la plus ancienne note ramène à l'état
    /// d'origine, même après plusieurs passages.
    pub(crate) fn noter(&mut self, a: &Annulable, titre: &str) {
        self.reglages.entry(a.id.to_string()).or_insert_with(|| Avant {
            titre: titre.to_string(),
            date: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
            valeurs: a.avant.clone(),
        });
    }
}

fn fichier() -> PathBuf {
    crate::socle::dossier_local().join("jeux.json")
}

pub(crate) fn charger() -> Notes {
    charger_de(&fichier())
}

pub(crate) fn sauver(n: &Notes) -> bool {
    sauver_dans(n, &fichier())
}

fn charger_de(chemin: &Path) -> Notes {
    let Ok(texte) = std::fs::read_to_string(chemin) else {
        return Notes::default();
    };
    match serde_json::from_str(texte.trim_start_matches('\u{feff}')) {
        Ok(n) => n,
        Err(e) => {
            // Jamais écraser des valeurs d'avant qu'on ne sait pas relire : le fichier est mis de côté, intact.
            let copie = chemin.with_extension(format!(
                "illisible-{}.json",
                chrono::Local::now().format("%Y%m%d-%H%M%S")
            ));
            let _ = std::fs::copy(chemin, &copie);
            tre!(
                "Attention : valeurs d'avant des réglages pour jouer illisibles ({e}). Copie gardée : {}",
                "Warning: previous gaming setting values unreadable ({e}). Copy kept: {}",
                copie.display()
            );
            Notes::default()
        }
    }
}

/// D'un bloc (fichier temporaire, puis renommé) : une coupure laisse l'ancien ou le nouveau, jamais un fichier
/// tronqué qui ferait perdre les valeurs d'avant. Sans note, plus rien à annuler : le fichier est retiré.
fn sauver_dans(n: &Notes, chemin: &Path) -> bool {
    let ecrit = if n.reglages.is_empty() {
        match std::fs::remove_file(chemin) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    } else {
        serde_json::to_string_pretty(n)
            .map_err(std::io::Error::other)
            .and_then(|texte| crate::socle::ecrire_atomique(chemin, &texte))
    };
    if let Err(e) = &ecrit {
        tre!(
            "Attention : valeurs d'avant des réglages pour jouer non enregistrées ({e}).",
            "Warning: previous gaming setting values not saved ({e})."
        );
    }
    ecrit.is_ok()
}

/// Les notes dont les valeurs sont relues en place : celles-là sont annulées et partent. Rend les identifiants
/// remis.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn retirer_remis(n: &mut Notes, relire: impl Fn(&str, &[Valeur]) -> Vec<Valeur>) -> Vec<String> {
    let remis: Vec<String> = n
        .reglages
        .iter()
        .filter(|(id, a)| relire(id, &a.valeurs) == a.valeurs)
        .map(|(id, _)| id.clone())
        .collect();
    for id in &remis {
        n.reglages.remove(id);
    }
    remis
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-jeux-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn annulable(id: &'static str, v: Option<&str>) -> Annulable {
        Annulable {
            id,
            avant: vec![("valeur".into(), v.map(String::from))],
        }
    }

    // La plus ancienne note reste : un second passage ne remplace pas la valeur d'origine par la valeur réglée.
    #[test]
    fn plus_ancienne_note_gardee() {
        let mut n = Notes::default();
        n.noter(&annulable("hags", Some("1")), "HAGS");
        n.noter(&annulable("hags", Some("2")), "HAGS");
        assert_eq!(n.reglages["hags"].valeurs, [("valeur".into(), Some("1".into()))]);
    }

    #[test]
    fn notes_relues_telles_quelles_puis_retirees() {
        let d = dossier("notes");
        let chemin = d.join("jeux.json");
        let mut n = Notes::default();
        n.noter(&annulable("souris", Some("1")), "Souris");
        n.noter(&annulable("fenetres", None), "Fenêtres");
        assert!(sauver_dans(&n, &chemin));
        assert_eq!(charger_de(&chemin), n);
        // Plus rien de noté : le fichier part.
        assert!(sauver_dans(&Notes::default(), &chemin));
        assert!(!chemin.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn note_illisible_mise_de_cote() {
        let d = dossier("illisible");
        let chemin = d.join("jeux.json");
        std::fs::write(&chemin, "{ pas du json").unwrap();
        assert_eq!(charger_de(&chemin), Notes::default());
        let copies = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .filter(|f| f.file_name().to_string_lossy().contains("illisible-"))
            .count();
        assert_eq!(copies, 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    // Seules les notes dont les valeurs sont revenues partent ; une valeur restée autre garde sa note pour réessayer.
    #[test]
    fn note_gardee_tant_que_rien_n_est_revenu() {
        let mut n = Notes::default();
        n.noter(&annulable("revenu", Some("1")), "A");
        n.noter(&annulable("bloque", None), "B");
        let remis = retirer_remis(&mut n, |id, v| {
            if id == "revenu" {
                v.to_vec()
            } else {
                vec![("valeur".into(), Some("ntsync".into()))]
            }
        });
        assert_eq!(remis, ["revenu"]);
        assert!(n.reglages.contains_key("bloque") && !n.reglages.contains_key("revenu"));
    }
}
