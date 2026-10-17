//! Historique des bilans complets : ce qui a changé depuis le dernier (notes, problèmes nouveaux ou réglés) et la
//! courbe des notes dans le rapport HTML. Gardé sur cet ordinateur (une note de machine ne voyage pas avec la clé).

use std::fmt::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::machine::Audit;
use crate::reseau::Rapport;
use crate::risk::Niveau;
use crate::ui::*;

/// Nombre de bilans gardés.
const GARDES: usize = 200;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Bilan {
    /// « AAAA-MM-JJ HH:MM ».
    pub date: String,
    /// Note de la machine, quand l'audit était fiable.
    pub machine: Option<u32>,
    pub reseau: Option<u32>,
    /// Réseau noté (adresse du réseau) : deux réseaux différents ne se comparent pas.
    #[serde(default)]
    pub nom_reseau: Option<String>,
    /// Problèmes moyens ou plus graves, « catégorie : message ».
    #[serde(default)]
    pub problemes: Vec<String>,
}

fn fichier() -> PathBuf {
    crate::reseau::dossier_local().join("historique.json")
}

pub fn charger() -> Vec<Bilan> {
    std::fs::read_to_string(fichier())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn bilan(audit: Option<&Audit>, reseau: Option<&Rapport>) -> Bilan {
    Bilan {
        date: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        machine: audit.filter(|a| a.fiable()).map(|a| a.score),
        reseau: reseau.map(|r| r.score_global),
        nom_reseau: reseau.map(|r| r.reseau.clone()),
        problemes: audit
            .map(|a| {
                a.constats
                    .iter()
                    .filter(|c| c.probleme.is_some_and(|n| n >= Niveau::Moyen))
                    .map(|c| format!("{} : {}", c.categorie, c.message))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Ajoute ce bilan à l'historique ; rend le précédent, s'il y en a un.
pub fn enregistrer(audit: Option<&Audit>, reseau: Option<&Rapport>) -> (Option<Bilan>, Bilan) {
    let mut tous = charger();
    let precedent = tous.last().cloned();
    let nouveau = bilan(audit, reseau);
    tous.push(nouveau.clone());
    let surplus = tous.len().saturating_sub(GARDES);
    tous.drain(..surplus);
    if let Ok(texte) = serde_json::to_string(&tous) {
        let _ = std::fs::create_dir_all(crate::reseau::dossier_local());
        let _ = std::fs::write(fichier(), texte);
    }
    (precedent, nouveau)
}

/// Un problème sans ses nombres (« 3 mises à jour » et « 4 mises à jour » sont le même problème).
fn cle(probleme: &str) -> String {
    probleme.chars().map(|c| if c.is_ascii_digit() { '#' } else { c }).collect()
}

/// (nouveaux, réglés) entre deux bilans.
fn differences<'a>(avant: &'a Bilan, apres: &'a Bilan) -> (Vec<&'a str>, Vec<&'a str>) {
    let cles_avant: Vec<String> = avant.problemes.iter().map(|p| cle(p)).collect();
    let cles_apres: Vec<String> = apres.problemes.iter().map(|p| cle(p)).collect();
    let nouveaux = apres
        .problemes
        .iter()
        .filter(|p| !cles_avant.contains(&cle(p)))
        .map(String::as_str)
        .collect();
    let regles = avant
        .problemes
        .iter()
        .filter(|p| !cles_apres.contains(&cle(p)))
        .map(String::as_str)
        .collect();
    (nouveaux, regles)
}

fn evolution(nom: &str, avant: Option<u32>, apres: Option<u32>) {
    let (Some(a), Some(b)) = (avant, apres) else { return };
    let ecart = i64::from(b) - i64::from(a);
    let signe = match ecart {
        e if e > 0 => format!("{VERT}+{e}{RESET}"),
        e if e < 0 => format!("{}{e}{RESET}", couleur(Niveau::Eleve)),
        _ => tr!("sans changement", "unchanged").to_string(),
    };
    println!("  {nom:<14} {a} → {b} ({signe})");
}

pub fn afficher_changements(avant: &Bilan, apres: &Bilan) {
    titre(&trf!(
        "Depuis le dernier bilan ({})",
        "Since the last check ({})",
        avant.date
    ));
    evolution(tr!("Cette machine", "This machine"), avant.machine, apres.machine);
    if avant.nom_reseau == apres.nom_reseau {
        evolution(tr!("Réseau", "Network"), avant.reseau, apres.reseau);
    }
    let (nouveaux, regles) = differences(avant, apres);
    let traduire = |p: &str| match p.split_once(" : ") {
        Some((cat, msg)) => format!("{} : {msg}", crate::langue::categorie(cat)),
        None => p.to_string(),
    };
    for p in regles.iter().take(8) {
        trp!("  {VERT}✔ réglé{RESET}   {}", "  {VERT}✔ fixed{RESET}   {}", traduire(p));
    }
    for p in nouveaux.iter().take(8) {
        trp!(
            "  {}✖ nouveau{RESET} {}",
            "  {}✖ new{RESET}     {}",
            couleur(Niveau::Moyen),
            traduire(p)
        );
    }
    if nouveaux.is_empty() && regles.is_empty() {
        trp!(
            "  {GRIS}Aucun problème nouveau ni réglé.{RESET}",
            "  {GRIS}No new or fixed problem.{RESET}"
        );
    }
}

/// Courbe des notes (SVG intégré, couleurs du thème clair ou sombre) ; `None` s'il y a moins de deux bilans.
/// Le réseau n'est tracé que pour le réseau du dernier bilan.
pub fn courbe(historique: &[Bilan]) -> Option<String> {
    let derniers = &historique[historique.len().saturating_sub(30)..];
    if derniers.len() < 2 {
        return None;
    }
    let reseau_actuel = derniers.last()?.nom_reseau.clone();
    let (largeur, hauteur, marge) = (640.0, 200.0, 28.0);
    #[allow(clippy::cast_precision_loss)]
    let pas = (largeur - 2.0 * marge) / (derniers.len() - 1) as f64;
    // Échelle à partir de la dizaine sous la note la plus basse (au plus 40) : le haut de l'échelle reste lisible.
    let plus_basse = derniers.iter().flat_map(|b| [b.machine, b.reseau]).flatten().min().unwrap_or(40);
    let bas = plus_basse.min(40) / 10 * 10;
    let y = |note: u32| {
        hauteur - marge - f64::from(note.saturating_sub(bas)) / f64::from(100 - bas) * (hauteur - 2.0 * marge)
    };
    let mut svg = format!(
        "<svg viewBox=\"0 0 {largeur} {hauteur}\" role=img aria-label=\"{}\" style=\"width:100%;height:auto\">",
        tr!("Évolution des notes", "Grade history")
    );
    // Seuils des lettres : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40.
    for (seuil, lettre) in [(90, "A"), (75, "B"), (60, "C"), (40, "D")].into_iter().filter(|(s, _)| *s >= bas) {
        let y0 = y(seuil);
        let _ = write!(
            svg,
            "<line x1={marge} x2={} y1={y0:.1} y2={y0:.1} style=\"stroke:var(--bord)\"/><text x=4 y={:.1} style=\"fill:var(--doux);font-size:11px\">{lettre}</text>",
            largeur - marge,
            y0 + 4.0
        );
    }
    let mut serie = |valeurs: Vec<Option<u32>>, couleur: &str, nom: &str| {
        let points: Vec<String> = valeurs
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                #[allow(clippy::cast_precision_loss)]
                let x = marge + i as f64 * pas;
                v.map(|n| format!("{x:.1},{:.1}", y(n)))
            })
            .collect();
        if points.is_empty() {
            return;
        }
        let _ = write!(
            svg,
            "<polyline points=\"{}\" style=\"fill:none;stroke:var({couleur});stroke-width:2.5\"><title>{nom}</title></polyline>",
            points.join(" ")
        );
        for p in &points {
            let (x, yy) = p.split_once(',').unwrap_or(("0", "0"));
            let _ = write!(svg, "<circle cx={x} cy={yy} r=3 style=\"fill:var({couleur})\"/>");
        }
    };
    serie(derniers.iter().map(|b| b.machine).collect(), "--info", tr!("Cette machine", "This machine"));
    serie(
        derniers
            .iter()
            .map(|b| if b.nom_reseau == reseau_actuel { b.reseau } else { None })
            .collect(),
        "--ok",
        tr!("Réseau", "Network"),
    );
    let jour = |b: &Bilan| esc_court(&b.date);
    let _ = write!(
        svg,
        "<text x={marge} y={} style=\"fill:var(--doux);font-size:11px\">{}</text><text x={} y={} text-anchor=end style=\"fill:var(--doux);font-size:11px\">{}</text></svg>",
        hauteur - 6.0,
        jour(&derniers[0]),
        largeur - marge,
        hauteur - 6.0,
        jour(derniers.last()?)
    );
    Some(svg)
}

/// Date du bilan sans l'heure, prête pour le HTML (les dates écrites par Sentinel ne contiennent rien à échapper).
fn esc_court(date: &str) -> String {
    date.split(' ').next().unwrap_or(date).replace(['<', '>', '&'], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(machine: u32, problemes: &[&str]) -> Bilan {
        Bilan {
            date: "2026-10-17 12:00".into(),
            machine: Some(machine),
            reseau: Some(80),
            nom_reseau: Some("10.0.0.0/24".into()),
            problemes: problemes.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn problemes_nouveaux_et_regles() {
        let avant = b(80, &["Mises à jour : 3 mises à jour en attente.", "Pare-feu : inactif."]);
        let apres = b(90, &["Mises à jour : 5 mises à jour en attente.", "DNS : réponses inventées."]);
        let (nouveaux, regles) = differences(&avant, &apres);
        assert_eq!(nouveaux, ["DNS : réponses inventées."]);
        assert_eq!(regles, ["Pare-feu : inactif."]);
    }

    #[test]
    fn courbe_des_notes() {
        assert!(courbe(&[b(80, &[])]).is_none());
        let svg = courbe(&[b(70, &[]), b(85, &[]), b(95, &[])]).unwrap();
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        assert_eq!(svg.matches("<polyline").count(), 2);
    }
}
