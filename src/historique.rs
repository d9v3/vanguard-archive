//! Historique des bilans complets : ce qui a changé depuis le dernier (notes, problèmes nouveaux ou réglés) et la
//! courbe des notes dans le rapport HTML. Gardé sur cet ordinateur : ce détail ne voyage pas avec la clé, seul un
//! résumé y va (« Mes ordinateurs », `ordinateurs`).
//!
//! Chaque bilan porte son empreinte BLAKE3 et celle du précédent : une chaîne. Un historique réécrit après coup (un
//! problème effacé, une note gonflée, un bilan retiré du milieu) ne colle plus, et le bilan le dit. La chaîne commence
//! au premier bilan qui a une empreinte (les anciens n'en ont pas) ; le premier bilan gardé peut pointer vers un bilan
//! que la rotation a retiré, ce n'est pas une falsification. Barrière, pas coffre : qui réécrit tout le fichier peut
//! aussi retirer toutes les empreintes.

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
    /// Empreinte BLAKE3 de ce bilan (`empreinte_de`), et celle du bilan précédent : la chaîne.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empreinte: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedent: Option<String>,
}

/// L'empreinte d'un bilan : ses champs dans un ordre fixe, y compris l'empreinte du précédent.
fn empreinte_de(b: &Bilan) -> String {
    let canon = serde_json::to_string(&(&b.date, b.machine, b.reseau, &b.nom_reseau, &b.problemes, &b.precedent))
        .unwrap_or_default();
    blake3::hash(canon.as_bytes()).to_hex().to_string()
}

/// L'état de la chaîne des bilans.
#[derive(Debug, PartialEq, Eq)]
pub enum Chaine {
    /// `chaines` bilans se suivent sans trou (0 : aucun bilan n'a encore d'empreinte).
    Intacte { chaines: usize },
    /// Le bilan `indice` ne colle pas : son contenu ne correspond plus à son empreinte, ou il ne suit plus le précédent.
    Rompue { indice: usize, date: String, contenu: bool },
}

pub fn verifier_chaine(tous: &[Bilan]) -> Chaine {
    let mut chaines = 0;
    let mut precedent: Option<&Bilan> = None;
    for (indice, b) in tous.iter().enumerate() {
        let rompue = |contenu| Chaine::Rompue {
            indice,
            date: b.date.clone(),
            contenu,
        };
        match &b.empreinte {
            Some(e) => {
                if *e != empreinte_de(b) {
                    return rompue(true);
                }
                // Un maillon suit le précédent quand celui-ci est chaîné ; le premier bilan gardé peut pointer vers un
                // bilan retiré par la rotation.
                if let Some(pe) = precedent.and_then(|p| p.empreinte.as_deref())
                    && b.precedent.as_deref() != Some(pe)
                {
                    return rompue(false);
                }
                chaines += 1;
            }
            // Un bilan sans empreinte après des bilans chaînés : ajouté à la main.
            None if precedent.is_some_and(|p| p.empreinte.is_some()) => return rompue(true),
            None => {}
        }
        precedent = Some(b);
    }
    Chaine::Intacte { chaines }
}

/// Au bilan : rien tant que la chaîne tient.
pub fn constat() -> Option<crate::machine::Constat> {
    match verifier_chaine(&charger()) {
        Chaine::Intacte { .. } => None,
        Chaine::Rompue { date, contenu, .. } => Some(
            crate::machine::alerte(
                "Historique",
                Niveau::Eleve,
                if contenu {
                    trf!(
                        "L'historique des bilans a été modifié après coup : le bilan du {date} ne correspond plus à son empreinte. Quelqu'un, ou un programme, a réécrit historique.json dans le dossier de Vanguard.",
                        "The check history was modified afterwards: the check of {date} no longer matches its checksum. Someone, or a program, rewrote historique.json in Vanguard's folder."
                    )
                } else {
                    trf!(
                        "L'historique des bilans a été modifié après coup : le bilan du {date} ne suit plus le précédent (un bilan a été retiré ou inséré au milieu).",
                        "The check history was modified afterwards: the check of {date} no longer follows the previous one (a check was removed or inserted in the middle)."
                    )
                },
            )
            .manuel(
                tr!(
                    "Regarde ce qui a accès au dossier de Vanguard (menu Protection › Intégrité, Qui parle à Internet ?) ; la chaîne repart au prochain bilan",
                    "Look at what has access to Vanguard's folder (Protection menu › Integrity, Who talks to the Internet?); the chain restarts at the next check"
                ),
                &[],
            ),
        ),
    }
}

/// Une ligne pour le rapport : la chaîne et sa longueur, ou la rupture.
pub fn etat_chaine() -> Option<String> {
    match verifier_chaine(&charger()) {
        Chaine::Intacte { chaines: 0 } => None,
        Chaine::Intacte { chaines } => Some(trf!(
            "Historique intact : {chaines} bilans chaînés par leur empreinte.",
            "History intact: {chaines} checks chained by their checksum."
        )),
        Chaine::Rompue { date, .. } => Some(trf!(
            "⚠ Historique modifié après coup : le bilan du {date} ne colle plus à la chaîne.",
            "⚠ History modified afterwards: the check of {date} no longer fits the chain."
        )),
    }
}

fn fichier() -> PathBuf {
    crate::reseau::dossier_local().join("historique.json")
}

pub fn charger() -> Vec<Bilan> {
    lire().unwrap_or_default()
}

/// L'historique tel qu'il est écrit ; `Err` s'il existe mais ne se lit pas.
fn lire() -> Result<Vec<Bilan>, String> {
    lire_de(&fichier())
}

/// Celui d'un fichier donné : les tests ont chacun le leur, sans quoi l'un réécrirait celui qu'un autre lit (le menu,
/// le rapport ; sous Windows, un fichier ouvert ne se remplace pas).
fn lire_de(chemin: &std::path::Path) -> Result<Vec<Bilan>, String> {
    match std::fs::read_to_string(chemin) {
        Ok(t) => serde_json::from_str(t.trim_start_matches('\u{feff}')).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
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
        empreinte: None,
        precedent: None,
    }
}

/// Ajoute ce bilan à l'historique ; rend le précédent, s'il y en a un.
pub fn enregistrer(audit: Option<&Audit>, reseau: Option<&Rapport>) -> (Option<Bilan>, Bilan) {
    enregistrer_dans(&fichier(), bilan(audit, reseau))
}

fn enregistrer_dans(chemin: &std::path::Path, mut nouveau: Bilan) -> (Option<Bilan>, Bilan) {
    let mut tous = match lire_de(chemin) {
        Ok(tous) => tous,
        Err(e) => {
            // Jamais écraser un historique qu'on ne sait pas relire : il est mis de côté, intact, avant le nouveau.
            let copie = chemin.with_extension(format!(
                "illisible-{}.json",
                chrono::Local::now().format("%Y%m%d-%H%M%S")
            ));
            let _ = std::fs::copy(chemin, &copie);
            tre!(
                "Attention : historique des bilans illisible ({e}). Copie gardée : {}",
                "Warning: check history unreadable ({e}). Copy kept: {}",
                copie.display()
            );
            Vec::new()
        }
    };
    let precedent = tous.last().cloned();
    nouveau.precedent = precedent.as_ref().and_then(|p| p.empreinte.clone());
    nouveau.empreinte = Some(empreinte_de(&nouveau));
    tous.push(nouveau.clone());
    let surplus = tous.len().saturating_sub(GARDES);
    tous.drain(..surplus);
    // D'un bloc : une coupure pendant l'écriture laisse l'ancien historique ou le nouveau, jamais un fichier tronqué.
    if let Ok(texte) = serde_json::to_string(&tous)
        && let Err(e) = crate::reseau::ecrire_atomique(chemin, &texte)
    {
        tre!(
            "Attention : bilan non enregistré dans l'historique ({e}).",
            "Warning: check not saved to the history ({e})."
        );
    }
    (precedent, nouveau)
}

/// Un problème sans ses nombres (« 3 mises à jour » et « 4 mises à jour » sont le même problème).
fn cle(probleme: &str) -> String {
    probleme
        .chars()
        .map(|c| if c.is_ascii_digit() { '#' } else { c })
        .collect()
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
        trp!(
            "  {VERT}✔ réglé{RESET}   {}",
            "  {VERT}✔ fixed{RESET}   {}",
            traduire(p)
        );
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
    let plus_basse = derniers
        .iter()
        .flat_map(|b| [b.machine, b.reseau])
        .flatten()
        .min()
        .unwrap_or(40);
    let bas = plus_basse.min(40) / 10 * 10;
    let y = |note: u32| {
        hauteur - marge - f64::from(note.saturating_sub(bas)) / f64::from(100 - bas) * (hauteur - 2.0 * marge)
    };
    let mut svg = format!(
        "<svg viewBox=\"0 0 {largeur} {hauteur}\" role=img aria-label=\"{}\" style=\"width:100%;height:auto\">",
        tr!("Évolution des notes", "Grade history")
    );
    // Seuils des lettres : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40.
    for (seuil, lettre) in [(90, "A"), (75, "B"), (60, "C"), (40, "D")]
        .into_iter()
        .filter(|(s, _)| *s >= bas)
    {
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
    serie(
        derniers.iter().map(|b| b.machine).collect(),
        "--info",
        tr!("Cette machine", "This machine"),
    );
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

/// Date du bilan sans l'heure, prête pour le HTML (les dates écrites par Vanguard ne contiennent rien à échapper).
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
            empreinte: None,
            precedent: None,
        }
    }

    #[test]
    fn problemes_nouveaux_et_regles() {
        let avant = b(
            80,
            &["Mises à jour : 3 mises à jour en attente.", "Pare-feu : inactif."],
        );
        let apres = b(
            90,
            &["Mises à jour : 5 mises à jour en attente.", "DNS : réponses inventées."],
        );
        let (nouveaux, regles) = differences(&avant, &apres);
        assert_eq!(nouveaux, ["DNS : réponses inventées."]);
        assert_eq!(regles, ["Pare-feu : inactif."]);
    }

    /// Un historique tronqué n'est pas remplacé en silence par le seul nouveau bilan : il est mis de côté.
    #[test]
    fn historique_illisible_mis_de_cote() {
        let dossier = std::env::temp_dir().join(format!("vanguard-historique-illisible-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join("historique.json");
        std::fs::write(&chemin, "[{\"date\":\"2026-10-17 12:00\",\"machine\":8").unwrap();
        assert!(lire_de(&chemin).is_err());
        let (precedent, _) = enregistrer_dans(&chemin, bilan(None, None));
        assert!(precedent.is_none());
        let copies = std::fs::read_dir(&dossier)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("historique.illisible-"))
            .count();
        assert!(copies >= 1, "l'historique illisible n'a pas été gardé");
        assert_eq!(lire_de(&chemin).map(|t| t.len()), Ok(1));
        let _ = std::fs::remove_dir_all(&dossier);
    }

    #[test]
    fn courbe_des_notes() {
        assert!(courbe(&[b(80, &[])]).is_none());
        let svg = courbe(&[b(70, &[]), b(85, &[]), b(95, &[])]).unwrap();
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        assert_eq!(svg.matches("<polyline").count(), 2);
    }
    #[test]
    fn chaine_des_bilans() {
        let dossier = std::env::temp_dir().join(format!("vanguard-chaine-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join("historique.json");
        // Deux anciens bilans, sans empreinte, déjà là.
        let ancien = |date: &str| Bilan {
            date: date.into(),
            machine: Some(80),
            problemes: vec!["Pare-feu : coupé".into()],
            ..Bilan::default()
        };
        std::fs::write(
            &chemin,
            serde_json::to_string(&[ancien("2026-01-01 10:00"), ancien("2026-02-01 10:00")]).unwrap(),
        )
        .unwrap();
        for (i, date) in ["2026-03-01 10:00", "2026-04-01 10:00", "2026-05-01 10:00"]
            .iter()
            .enumerate()
        {
            let mut b = ancien(date);
            b.machine = Some(80 + u32::try_from(i).unwrap());
            enregistrer_dans(&chemin, b);
        }
        let tous = lire_de(&chemin).unwrap();
        assert_eq!(tous.len(), 5);
        assert!(tous[1].empreinte.is_none() && tous[2].empreinte.is_some() && tous[2].precedent.is_none());
        assert_eq!(tous[3].precedent, tous[2].empreinte);
        assert_eq!(verifier_chaine(&tous), Chaine::Intacte { chaines: 3 });
        // Un problème effacé après coup.
        let mut falsifie = tous.clone();
        falsifie[3].problemes.clear();
        assert_eq!(
            verifier_chaine(&falsifie),
            Chaine::Rompue {
                indice: 3,
                date: "2026-04-01 10:00".into(),
                contenu: true
            }
        );
        // Un bilan retiré du milieu.
        let mut troue = tous.clone();
        troue.remove(3);
        assert_eq!(
            verifier_chaine(&troue),
            Chaine::Rompue {
                indice: 3,
                date: "2026-05-01 10:00".into(),
                contenu: false
            }
        );
        // Un bilan sans empreinte glissé après la chaîne.
        let mut glisse = tous.clone();
        glisse.push(ancien("2026-06-01 10:00"));
        assert!(matches!(
            verifier_chaine(&glisse),
            Chaine::Rompue {
                indice: 5,
                contenu: true,
                ..
            }
        ));
        // La rotation retire les premiers bilans : le premier gardé pointe vers un bilan absent, ce n'est pas une
        // falsification.
        let roule: Vec<Bilan> = tous[3..].to_vec();
        assert_eq!(verifier_chaine(&roule), Chaine::Intacte { chaines: 2 });
        assert_eq!(verifier_chaine(&tous[..2]), Chaine::Intacte { chaines: 0 });
        let _ = std::fs::remove_dir_all(&dossier);
    }
}
