//! Ce que Gardien a changé : chaque correction lancée après accord (commandes, date, réussie ou non) est notée sur cet
//! ordinateur seulement (changements.jsonl, jamais sur la clé ni ailleurs), et se relit au menu Cette machine ou par
//! `gardien changements`. Les réglages d'Optimiser gardent en plus leur valeur d'avant, pour s'annuler exactement.

use serde::{Deserialize, Serialize};

use crate::ui::*;

/// Au-delà, les plus anciens partent : le fichier ne grossit pas sans fin.
const GARDES: usize = 500;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Changement {
    /// « AAAA-MM-JJ HH:MM ».
    date: String,
    commandes: Vec<String>,
    reussi: bool,
}

fn fichier() -> std::path::PathBuf {
    crate::reseau::dossier_local().join("changements.jsonl")
}

/// Note des corrections lancées (une liste de commandes chacune) et leur résultat.
pub fn noter(correctifs: &[Vec<String>], resultats: &[bool]) {
    noter_dans(&fichier(), correctifs, resultats);
}

fn noter_dans(chemin: &std::path::Path, correctifs: &[Vec<String>], resultats: &[bool]) {
    let date = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    let mut tous = lire_de(chemin);
    for (commandes, &reussi) in correctifs.iter().zip(resultats) {
        tous.push(Changement {
            date: date.clone(),
            commandes: commandes.clone(),
            reussi,
        });
    }
    let debut = tous.len().saturating_sub(GARDES);
    let texte: String = tous[debut..]
        .iter()
        .filter_map(|c| serde_json::to_string(c).ok())
        .map(|l| l + "\n")
        .collect();
    if let Some(parent) = chemin.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = crate::reseau::ecrire_atomique(chemin, texte);
}

/// Les changements notés, du plus ancien au plus récent ; une ligne abîmée est sautée.
fn lire() -> Vec<Changement> {
    lire_de(&fichier())
}

fn lire_de(chemin: &std::path::Path) -> Vec<Changement> {
    lire_texte(&std::fs::read_to_string(chemin).unwrap_or_default())
}

fn lire_texte(texte: &str) -> Vec<Changement> {
    texte.lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// Pour le rapport HTML : (corrections notées, réussies, date de la dernière). Les commandes n'y vont pas : le rapport
/// voyage sur la clé et sert aux captures d'écran, et une commande peut citer un nom de fichier ou de compte.
pub fn resume() -> Option<(usize, usize, String)> {
    resume_de(&fichier())
}

fn resume_de(chemin: &std::path::Path) -> Option<(usize, usize, String)> {
    let tous = lire_de(chemin);
    let derniere = tous.last()?.date.clone();
    Some((tous.len(), tous.iter().filter(|c| c.reussi).count(), derniere))
}

/// `gardien changements` et le menu Cette machine.
pub fn afficher() {
    titre(tr!("Ce que Gardien a changé", "What Gardien changed"));
    let tous = lire();
    if tous.is_empty() {
        trp!(
            "  Rien encore : aucune correction n'a été lancée sur cet ordinateur.",
            "  Nothing yet: no fix has been run on this computer."
        );
        return;
    }
    for c in tous.iter().rev().take(30) {
        let marque = if c.reussi {
            format!("{VERT}✔{RESET}")
        } else {
            format!("{}✖{RESET}", couleur(crate::risk::Niveau::Eleve))
        };
        let premiere = c.commandes.first().map(String::as_str).unwrap_or_default();
        let suite = if c.commandes.len() > 1 {
            trf!(" (+{} commande(s))", " (+{} command(s))", c.commandes.len() - 1)
        } else {
            String::new()
        };
        afficher_aligne(
            &format!("  {marque} {GRIS}{}{RESET}  ", c.date),
            &format!("{}{suite}", commande_affichable(premiere)),
            21,
            "",
        );
    }
    if tous.len() > 30 {
        trp!(
            "  {GRIS}… et {} plus ancien(s), dans {}{RESET}",
            "  {GRIS}… and {} older, in {}{RESET}",
            tous.len() - 30,
            chemin_affichable(&fichier())
        );
    }
    println!();
    afficher_aligne(
        "  ",
        tr!(
            "Les réglages d'Optimiser s'annulent exactement par « Tout remettre comme avant » ; une correction se défait à la main, avec la commande inverse.",
            "Optimize settings undo exactly through “Put everything back”; a fix is undone by hand, with the opposite command."
        ),
        2,
        GRIS,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_ecrites_relues_et_limitees() {
        // Un fichier à ce test : d'autres tests lancent des corrections, notées dans le fichier habituel.
        let f = std::env::temp_dir().join(format!("gardien-changements-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&f);
        noter_dans(
            &f,
            &[vec!["chmod 700 ~/.ssh".into()], vec!["false".into(), "true".into()]],
            &[true, false],
        );
        let tous = lire_de(&f);
        assert_eq!(tous.len(), 2);
        assert!(tous[0].reussi && !tous[1].reussi);
        assert_eq!(tous[1].commandes.len(), 2);
        // Une ligne abîmée ne fait pas tout perdre.
        let t = format!("{{pas du json\n{}\n", serde_json::to_string(&tous[0]).unwrap());
        assert_eq!(lire_texte(&t).len(), 1);
        // Au-delà de la limite, les plus anciens partent.
        let beaucoup: Vec<Vec<String>> = (0..GARDES + 5).map(|i| vec![format!("echo {i}")]).collect();
        noter_dans(&f, &beaucoup, &vec![true; beaucoup.len()]);
        let tous = lire_de(&f);
        assert_eq!(tous.len(), GARDES);
        assert_eq!(tous.last().unwrap().commandes[0], format!("echo {}", GARDES + 4));
        assert_eq!(resume_de(&f).map(|(n, r, _)| (n, r)), Some((GARDES, GARDES)));
        let _ = std::fs::remove_file(&f);
        assert_eq!(resume_de(&f), None);
    }
}
