//! Gaming : composants dont les jeux ont besoin et réglages utiles en jeu, pour chaque système. Tout est lu
//! d'abord, montré avec son état (fait / à faire), puis appliqué seulement après accord. Les réglages du système
//! notent leurs valeurs d'avant et se remettent exactement (`annulation`).

use crate::machine;
use crate::selection::{Case, cocher};
#[cfg(not(target_os = "macos"))]
use crate::selection::{Ligne, choisir};
use crate::ui::*;

mod annulation;
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
    /// Réglage du système : ses valeurs d'avant, notées avant de l'appliquer pour pouvoir le remettre.
    pub(crate) annulable: Option<annulation::Annulable>,
}

impl Element {
    // macOS : pas de réglage du système à remettre (le compteur de Metal dit comment l'enlever).
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub(crate) fn annulable(mut self, id: &'static str, avant: Vec<annulation::Valeur>) -> Element {
        self.annulable = Some(annulation::Annulable { id, avant });
        self
    }
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
        annulable: None,
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

/// Ce qu'un choix montre avant d'être lancé : son titre, puis son explication coupée pour tenir dans `LARGEUR`
/// (longue de trois lignes, elle était coupée par le terminal au milieu des mots).
fn presentation(el: &Element) -> Vec<String> {
    let mut lignes = vec![String::new(), format!("  {GRAS}{}{RESET}", el.titre)];
    lignes.extend(envelopper(&el.pourquoi, LARGEUR - 2).iter().map(|l| format!("  {l}")));
    lignes
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
    let mut a_noter = Vec::new();
    for (el, _) in liste.iter().zip(&voulu).filter(|(el, v)| **v && el.fait != Some(true)) {
        a_noter.extend(el.annulable.as_ref().map(|a| (a, el.titre.as_str())));
        for l in presentation(el) {
            println!("{l}");
        }
        if let Some(lien) = el.lien {
            trp!(
                "  Ouverture de la page officielle : {lien}",
                "  Opening the official page: {lien}"
            );
            machine::ouvrir(lien);
        }
        for c in &el.commandes {
            println!("    {GRIS}{}{RESET}", crate::ui::commande_affichable(c));
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
    // Sans valeurs d'avant notées, un réglage ne pourrait plus se remettre exactement : rien n'est changé.
    if !a_noter.is_empty() {
        let mut notes = annulation::charger();
        for (a, titre) in &a_noter {
            notes.noter(a, titre);
        }
        if !annulation::sauver(&notes) {
            trp!("  Rien n'a été changé.", "  Nothing was changed.");
            return;
        }
    }
    if machine::appliquer(&commandes) {
        let fait = trf!(
            "{VERT}✔ Terminé.{RESET} Certains changements demandent de redémarrer ou de rouvrir la session.",
            "{VERT}✔ Done.{RESET} Some changes need a restart or a new sign-in."
        );
        afficher_aligne("  ", &fait, 4, "");
    } else {
        trp!(
            "  ✖ Une étape a échoué : lis le message ci-dessus.",
            "  ✖ A step failed: read the message above."
        );
    }
}

/// Le menu de Linux et de Windows : deux listes (composants, réglages), « 3 » pour remettre les réglages appliqués
/// par Vanguard, et ce qu'il faut savoir dessous. Rend la touche choisie ; `None` pour revenir. (macOS n'a qu'une
/// liste, ouverte directement.)
#[cfg(not(target_os = "macos"))]
pub(crate) fn choisir_liste(composants: (&str, &str), reglages: (&str, &str), note: Option<String>) -> Option<String> {
    let notes = annulation::charger().reglages.len();
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre("Gaming")),
        Ligne::Texte(String::new()),
        Ligne::choix("1", composants.0, composants.1),
        Ligne::choix("2", reglages.0, reglages.1),
    ];
    if notes > 0 {
        lignes.push(Ligne::choix(
            "3",
            tr!("Remettre les réglages comme avant", "Put the settings back as before"),
            &trf!("{notes} réglage(s) de Vanguard", "{notes} setting(s) by Vanguard"),
        ));
    }
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
    Some(choix.trim().to_string()).filter(|c| c == "1" || c == "2" || (c == "3" && notes > 0))
}

/// Remet comme avant les réglages pour jouer appliqués par Vanguard : ceux cochés reprennent leurs valeurs notées
/// (`commandes`), puis ne perdent leur note que si `relire` les retrouve en place.
#[cfg(not(target_os = "macos"))]
pub(crate) fn remettre(
    commandes: impl Fn(&str, &[annulation::Valeur]) -> Vec<String>,
    relire: impl Fn(&str, &[annulation::Valeur]) -> Vec<annulation::Valeur>,
) {
    let mut notes = annulation::charger();
    let entete = vec![
        String::new(),
        ligne_titre(tr!(
            "Remettre les réglages comme avant",
            "Put the settings back as before"
        )),
        trf!(
            "  {GRIS}Les valeurs notées avant que Vanguard les change.{RESET}",
            "  {GRIS}The values noted before Vanguard changed them.{RESET}"
        ),
        String::new(),
    ];
    let liste: Vec<(&String, &annulation::Avant)> = notes.reglages.iter().collect();
    let cases: Vec<Case> = liste
        .iter()
        .map(|(_, a)| Case {
            texte: a.titre.clone(),
            precision: trf!("réglé le {}", "set on {}", a.date),
            detail: String::new(),
            cochee: false,
            recommandee: true,
            fixe: false,
        })
        .collect();
    let Some(voulu) = cocher(&entete, &cases) else {
        return;
    };
    // Un correctif par réglage : un réglage qui ne revient pas (module encore utilisé) n'empêche pas les autres.
    let mut a_lancer: Vec<Vec<String>> = Vec::new();
    let mut choisis = Vec::new();
    for ((id, a), _) in liste.iter().zip(&voulu).filter(|(_, v)| **v) {
        println!("\n  {GRAS}{}{RESET}", a.titre);
        let c = commandes(id, &a.valeurs);
        for l in &c {
            println!("    {GRIS}{}{RESET}", crate::ui::commande_affichable(l));
        }
        a_lancer.push(c);
        choisis.push((*id).clone());
    }
    if a_lancer.iter().all(Vec::is_empty) || !demander(tr!("\n  Remettre ? [o/N] : ", "\n  Put back? [y/N]: ")).oui() {
        trp!("  Rien n'a été changé.", "  Nothing was changed.");
        return;
    }
    let mut point = Vec::new();
    if !avec_restauration(&mut point) {
        trp!("  Annulé.", "  Cancelled.");
        return;
    }
    if !point.is_empty() {
        a_lancer.insert(0, point);
    }
    machine::appliquer_chacune(&a_lancer);
    // Seuls les réglages choisis sont relus : les autres gardent leur note telle quelle.
    let mut a_relire = annulation::Notes::default();
    for id in &choisis {
        if let Some(a) = notes.reglages.remove(id) {
            a_relire.reglages.insert(id.clone(), a);
        }
    }
    let titres: std::collections::BTreeMap<String, String> = a_relire
        .reglages
        .iter()
        .map(|(id, a)| (id.clone(), a.titre.clone()))
        .collect();
    let remis = annulation::retirer_remis(&mut a_relire, relire);
    for (id, a) in &a_relire.reglages {
        afficher_aligne(
            "  ✖ ",
            &trf!(
                "{} : pas tout à fait revenu (programme encore ouvert, ou redémarrage nécessaire). La note reste pour réessayer.",
                "{}: not fully back (program still open, or restart needed). The note stays so you can try again.",
                a.titre
            ),
            4,
            "",
        );
        notes.reglages.insert(id.clone(), a.clone());
    }
    for id in &remis {
        println!("  {VERT}✔{RESET} {}", titres[id]);
    }
    annulation::sauver(&notes);
}

/// Le nombre de réglages pour jouer changés par Vanguard, à remettre comme avant (choix 3 du menu). macOS n'a pas
/// cette liste : rien à y remettre d'ici.
pub(crate) fn reglages_notes() -> usize {
    if cfg!(target_os = "macos") {
        0
    } else {
        annulation::charger().reglages.len()
    }
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
pub(crate) mod tests {
    use super::*;

    /// Les textes des `trp!` d'un fichier source (code seul, sans ses tests), dans les deux langues, qui dépassent
    /// `LARGEUR` colonnes : couleurs retirées, « {…} » compté pour une colonne. Affichés tels quels, le terminal les
    /// couperait au milieu d'un mot. Partagé par les tests des écrans à cocher (gaming, logiciels, nettoyer,
    /// optimiser).
    pub(crate) fn textes_trop_larges(source: &str) -> Vec<String> {
        const COULEURS: [&str; 7] = ["RESET", "GRAS", "GRIS", "VERT", "ACCENT", "TOUCHE", "DISCRET"];
        let fin = source
            .find("mod tests {")
            .and_then(|i| source[..i].rfind("#[cfg(test)]"));
        let code = &source[..fin.unwrap_or(source.len())];
        let mut trop_larges = Vec::new();
        // Le nom de la macro en deux morceaux : écrit d'un bloc, il passerait pour un texte à traduire auprès des
        // outils qui relèvent les textes (outils-dp40/textes.py).
        for appel in code.split(concat!("trp", "!(")).skip(1) {
            let mut car = appel.chars().peekable();
            // Les deux premiers littéraux de l'appel : le texte français, puis l'anglais.
            for _ in 0..2 {
                if !car.by_ref().any(|c| c == '"') {
                    break;
                }
                let mut texte = String::new();
                while let Some(c) = car.next() {
                    match (c, car.peek().copied()) {
                        ('"', _) => break,
                        ('\\', Some('n')) => {
                            car.next();
                            texte.push('\n');
                        }
                        // Ligne continuée (« \ » en fin de ligne) : les espaces qui suivent ne s'affichent pas.
                        ('\\', Some('\n')) => while car.next_if(|c| c.is_whitespace()).is_some() {},
                        ('\\', Some(echappe)) => {
                            car.next();
                            texte.push(echappe);
                        }
                        ('{', Some('{')) => {
                            car.next();
                            texte.push('{');
                        }
                        ('{', _) => {
                            let nom: String = car.by_ref().take_while(|&c| c != '}').collect();
                            if !COULEURS.contains(&nom.as_str()) {
                                texte.push('X');
                            }
                        }
                        (c, _) => texte.push(c),
                    }
                }
                trop_larges.extend(
                    texte
                        .lines()
                        .filter(|l| largeur_affichee(l) > LARGEUR)
                        .map(str::to_string),
                );
            }
        }
        trop_larges
    }

    /// Les messages de Gaming tiennent dans `LARGEUR` colonnes, dans les deux langues.
    #[test]
    fn messages_dans_la_largeur() {
        let larges: Vec<String> = [
            include_str!("mod.rs"),
            include_str!("linux.rs"),
            include_str!("macos.rs"),
            include_str!("windows.rs"),
        ]
        .into_iter()
        .flat_map(textes_trop_larges)
        .collect();
        assert_eq!(larges, Vec::<String>::new());
    }

    /// Avant d'être lancé, un choix montre son explication, longue (trois lignes sous la liste à cocher) : elle est
    /// coupée pour tenir dans `LARGEUR`.
    #[test]
    fn explication_dans_la_largeur() {
        let el = element(
            "Planification GPU matérielle (HAGS)",
            "La carte graphique gère sa propre mémoire : un peu moins de latence, et obligatoire pour la génération \
             d'images DLSS 3/4. Cartes GTX 1000 / RX 5000 et plus récentes. Prend effet au redémarrage.",
            Some(false),
            vec!["x".into()],
        );
        let lignes = presentation(&el);
        assert!(lignes.iter().all(|l| largeur_affichee(l) <= LARGEUR), "{lignes:#?}");
        assert_eq!(lignes.len(), 5, "{lignes:#?}");
    }

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
