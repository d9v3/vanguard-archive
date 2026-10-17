//! Gaming : composants dont les jeux ont besoin et réglages utiles en jeu, pour chaque système. Tout est lu
//! d'abord, montré avec son état (fait / à faire), puis appliqué seulement après accord.

use crate::machine;
use crate::ui::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

struct Element {
    titre: String,
    pourquoi: String,
    /// `None` : état inconnu ; `Some(true)` : déjà fait.
    fait: Option<bool>,
    commandes: Vec<String>,
    /// Lien à ouvrir au lieu de commandes (pilotes NVIDIA et AMD : pas dans winget).
    lien: Option<&'static str>,
    /// Déconseillé sur cette machine : affiché, mais pas inclus dans « tout ».
    deconseille: Option<&'static str>,
}

fn element(
    titre: impl Into<String>,
    pourquoi: impl Into<String>,
    fait: Option<bool>,
    commandes: Vec<String>,
) -> Element {
    Element {
        titre: titre.into(),
        pourquoi: pourquoi.into(),
        fait,
        commandes,
        lien: None,
        deconseille: None,
    }
}

fn etat_lisible(el: &Element) -> String {
    if let Some(d) = el.deconseille {
        return trf!(
            "{GRIS}déconseillé ici ({d}){RESET}",
            "{GRIS}not recommended here ({d}){RESET}"
        );
    }
    match (el.fait, el.lien.is_some()) {
        (_, true) => trf!("{GRIS}page du fabricant{RESET}", "{GRIS}manufacturer's page{RESET}"),
        (Some(true), _) => trf!("{VERT}✔ fait{RESET}", "{VERT}✔ done{RESET}"),
        (Some(false), _) => tr!("à faire", "to do").into(),
        (None, _) => format!("{GRIS}?{RESET}"),
    }
}

/// Choix « 1 3 4 », « 1,3 » ou « tout » (ce qui reste à faire, sans les déconseillés ni les liens).
fn lire_choix(texte: &str, liste: &[Element]) -> Vec<usize> {
    if crate::langue::tout(texte) {
        return liste
            .iter()
            .enumerate()
            .filter(|(_, el)| el.fait != Some(true) && el.deconseille.is_none() && el.lien.is_none())
            .map(|(i, _)| i)
            .collect();
    }
    let mut choix: Vec<usize> = texte
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(|n| n.parse::<usize>().ok()?.checked_sub(1))
        .filter(|&i| i < liste.len())
        .collect();
    choix.sort_unstable();
    choix.dedup();
    choix
}

fn proposer(nom: &str, liste: &[Element]) {
    titre(nom);
    for (i, el) in liste.iter().enumerate() {
        println!("  {}. {}  — {}", i + 1, el.titre, etat_lisible(el));
    }
    let texte = demander(tr!(
        "\nNuméros (ex. « 1 3 »), « tout » pour ce qui reste à faire, Entrée pour revenir : ",
        "\nNumbers (e.g. “1 3”), “all” for what is left to do, Enter to go back: "
    ));
    let choix = lire_choix(&texte, liste);
    if choix.is_empty() {
        return;
    }
    let mut commandes = Vec::new();
    for &i in &choix {
        let el = &liste[i];
        println!("\n  {GRAS}{}{RESET}", el.titre);
        println!("  {}", el.pourquoi);
        if let Some(lien) = el.lien {
            trp!(
                "  Ouverture de la page officielle : {lien}",
                "  Opening the official page: {lien}"
            );
            machine::ouvrir(lien);
        }
        for c in &el.commandes {
            println!("    {GRIS}{c}{RESET}");
        }
        commandes.extend(el.commandes.iter().cloned());
    }
    if commandes.is_empty() {
        return;
    }
    if !demander(tr!("\n  Lancer ? [o/N] : ", "\n  Run? [y/N]: ")).oui() {
        trp!("  Annulé.", "  Cancelled.");
        return;
    }
    if machine::appliquer(&commandes) {
        trp!(
            "  {VERT}✔ Terminé.{RESET} Certains changements demandent de redémarrer ou de rouvrir la session.",
            "  {VERT}✔ Done.{RESET} Some changes need a restart or a new sign-in."
        );
    } else {
        trp!(
            "  ✖ Une étape a échoué : lis le message ci-dessus.",
            "  ✖ A step failed: read the message above."
        );
    }
}

pub fn menu() {
    #[cfg(windows)]
    windows::menu();
    #[cfg(target_os = "linux")]
    linux::menu();
}
