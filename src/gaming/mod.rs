//! Gaming : composants dont les jeux ont besoin et réglages utiles en jeu, pour chaque système. Tout est lu
//! d'abord, montré avec son état (fait / à faire), puis appliqué seulement après accord.

use crate::machine;
use crate::selection::{Case, cocher};
#[cfg(not(target_os = "macos"))]
use crate::selection::{Ligne, choisir};
use crate::ui::*;

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub(crate) struct Element {
    pub(crate) titre: String,
    pub(crate) pourquoi: String,
    /// `None` : état inconnu ; `Some(true)` : déjà fait.
    pub(crate) fait: Option<bool>,
    pub(crate) commandes: Vec<String>,
    /// Lien à ouvrir au lieu de commandes (pilotes NVIDIA et AMD : pas dans winget).
    pub(crate) lien: Option<&'static str>,
    /// Déconseillé sur cette machine : affiché, mais pas inclus dans « tout ».
    pub(crate) deconseille: Option<&'static str>,
}

pub(crate) fn element(
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

/// L'état en gris à droite de la liste, court : la raison d'un déconseillé va dans l'explication.
fn etat_lisible(el: &Element) -> &'static str {
    match (el.deconseille, el.lien, el.fait) {
        (Some(_), _, _) => tr!("déconseillé ici", "not recommended here"),
        (None, Some(_), _) => tr!("page du fabricant", "manufacturer's page"),
        (None, None, Some(true)) => tr!("fait", "done"),
        (None, None, Some(false)) => tr!("à faire", "to do"),
        (None, None, None) => tr!("état inconnu", "unknown state"),
    }
}

/// Ce que R coche : ce qui reste à faire, sans le déconseillé ni les pages de fabricants (à ouvrir soi-même).
fn a_faire(el: &Element) -> bool {
    el.fait != Some(true) && el.deconseille.is_none() && el.lien.is_none()
}

fn case(el: &Element) -> Case {
    Case {
        texte: el.titre.clone(),
        precision: etat_lisible(el).into(),
        detail: match el.deconseille {
            Some(d) => format!("{} ⚠ {d}", el.pourquoi),
            None => el.pourquoi.clone(),
        },
        cochee: false,
        recommandee: a_faire(el),
        fixe: el.fait == Some(true),
    }
}

/// Point de restauration avant des réglages du système : sous Windows, en tête de la fenêtre administrateur (il
/// demande lui-même s'il faut continuer sans) ; ailleurs, d'abord, et s'il échoue on demande. Faux : on arrête.
fn avec_restauration(commandes: &mut Vec<String>) -> bool {
    let Some((outil, point)) = crate::reparer::point_restauration(tr!("réglages pour jouer", "gaming settings"))
    else {
        return true;
    };
    trp!(
        "  {GRIS}Point de restauration d'abord ({outil}).{RESET}",
        "  {GRIS}Restore point first ({outil}).{RESET}"
    );
    if cfg!(windows) {
        commandes.insert(0, point);
        return true;
    }
    machine::appliquer(&[point])
        || demander(tr!(
            "  ✖ Point de restauration impossible. Continuer quand même ? [o/N] : ",
            "  ✖ Restore point not possible. Continue anyway? [y/N]: "
        ))
        .oui()
}

/// Liste à cocher (R : tout ce qui reste à faire), puis chaque choix montré, confirmé et lancé. `restauration` : ce
/// qui change le système, avec un point de restauration d'abord.
pub(crate) fn proposer(nom: &str, liste: &[Element], restauration: bool) {
    let entete = vec![
        String::new(),
        ligne_titre(nom),
        trf!(
            "  {GRIS}Coche ce que tu veux faire ; [✔] = déjà fait.{RESET}",
            "  {GRIS}Check what you want to do; [✔] = already done.{RESET}"
        ),
        String::new(),
    ];
    let cases: Vec<Case> = liste.iter().map(case).collect();
    let Some(voulu) = cocher(&entete, &cases) else {
        return;
    };
    let mut commandes = Vec::new();
    for (el, _) in liste.iter().zip(&voulu).filter(|(el, v)| **v && el.fait != Some(true)) {
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
    if restauration && !avec_restauration(&mut commandes) {
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

/// Le menu de Linux et de Windows : deux listes (composants, réglages), et ce qu'il faut savoir dessous. Rend la
/// touche choisie, « 1 » ou « 2 » ; `None` pour revenir. (macOS n'a qu'une liste, ouverte directement.)
#[cfg(not(target_os = "macos"))]
pub(crate) fn choisir_liste(composants: (&str, &str), reglages: (&str, &str), note: Option<String>) -> Option<String> {
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre("Gaming")),
        Ligne::Texte(String::new()),
        Ligne::choix("1", composants.0, composants.1),
        Ligne::choix("2", reglages.0, reglages.1),
    ];
    if let Some(n) = note {
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::Texte(n));
    }
    lignes.extend([
        Ligne::Texte(String::new()),
        Ligne::choix("↵", tr!("Revenir", "Back"), ""),
        Ligne::Texte(String::new()),
    ]);
    let choix = choisir(
        &lignes,
        tr!("Choix (Entrée pour revenir) : ", "Choice (Enter to go back): "),
        "1",
        tr!("revenir", "back"),
    )?;
    Some(choix.trim().to_string()).filter(|c| c == "1" || c == "2")
}

pub fn menu() {
    #[cfg(windows)]
    windows::menu();
    #[cfg(target_os = "linux")]
    linux::menu();
    #[cfg(target_os = "macos")]
    macos::menu();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chaque ligne tient dans la liste à cocher : titre sans coupure, état court, explication sur trois lignes.
    pub(super) fn tient_dans_la_liste(l: &[Element]) {
        for el in l {
            assert!(largeur_affichee(&el.titre) <= 40, "{} : titre trop long", el.titre);
            let c = case(el);
            assert!(largeur_affichee(&c.precision) <= 33, "{}", el.titre);
            assert!(
                envelopper(&c.detail, LARGEUR - 4).len() <= 3,
                "{} : explication trop longue",
                el.titre
            );
            assert!(
                !el.commandes.is_empty() || el.lien.is_some() || el.deconseille.is_some(),
                "{}",
                el.titre
            );
        }
    }

    #[test]
    fn ce_que_r_coche() {
        let a_faire_ici = element("A", "a", Some(false), vec!["x".into()]);
        let fait = element("B", "b", Some(true), vec!["x".into()]);
        let mut deconseille = element("C", "c", Some(false), vec!["x".into()]);
        deconseille.deconseille = Some("portable");
        let mut lien = element("D", "d", None, vec![]);
        lien.lien = Some("https://exemple.invalid");
        let cases: Vec<Case> = [&a_faire_ici, &fait, &deconseille, &lien].map(case).into();
        assert_eq!(
            cases.iter().map(|c| c.recommandee).collect::<Vec<_>>(),
            [true, false, false, false]
        );
        assert!(cases[1].fixe && !cases[0].fixe);
        // La raison d'un déconseillé va dans l'explication, pas dans la colonne d'état.
        assert!(cases[2].detail.contains("⚠ portable") && !cases[2].precision.contains("portable"));
    }
}
