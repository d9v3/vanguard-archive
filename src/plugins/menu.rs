//! Les menus des extensions : « Extensions » (menu principal, `vanguard extensions`) ouvre deux listes, les plugins
//! (`vanguard plugin` sans argument) et les scripts du laboratoire (`vanguard labo` sans argument). Choisir un numéro
//! lance l'élément ; les lettres du bas ajoutent, approuvent ou retirent. Rien ne s'y lance en administrateur.

use std::path::Path;

use crate::langue::Reponse;
use crate::selection::{Ligne, choisir};
use crate::ui::*;
use crate::{tr, trf};

use super::{Etat, Plugin, labo};

fn invite() -> String {
    format!("  {ACCENT}›{RESET} {}", tr!("Choix : ", "Choice: "))
}

fn attendre() {
    demander(&trf!(
        "\n{GRIS}Entrée pour revenir…{RESET}",
        "\n{GRIS}Enter to go back…{RESET}"
    ));
}

fn tete(chemin: &str, resume: &str) -> Vec<Ligne> {
    let mut l: Vec<Ligne> = lignes_cadre(&format!("{ACCENT}VANGUARD{RESET} {GRIS}›{RESET} {chemin}"), resume)
        .into_iter()
        .map(Ligne::Texte)
        .collect();
    l.push(Ligne::Texte(String::new()));
    l
}

/// Un texte de plusieurs lignes dans le menu, coupé pour tenir dans 76 colonnes.
fn paragraphe(lignes: &mut Vec<Ligne>, texte: &str) {
    for l in envelopper(texte, LARGEUR - 4) {
        lignes.push(Ligne::Texte(format!("  {l}")));
    }
}

/// La ligne de l'interrupteur : son état, et ce que fait le choisir.
fn ligne_interrupteur(touche: &str, sans: bool, quoi: &str) -> Ligne {
    if sans {
        Ligne::choix(
            touche,
            &trf!(
                "{quoi} : {}COUPÉES{RESET}",
                "{quoi}: {}OFF{RESET}",
                couleur(crate::risk::Niveau::Eleve)
            ),
            tr!("choisir pour remettre", "choose to turn back on"),
        )
    } else {
        Ligne::choix(
            touche,
            &trf!("{quoi} : {VERT}ACTIVES{RESET}", "{quoi}: {VERT}ON{RESET}"),
            tr!("choisir pour couper", "choose to turn off"),
        )
    }
}

/// Les lignes du menu « Extensions » : deux listes, l'interrupteur des restrictions et le retour.
pub(super) fn lignes_extensions(plugins: usize, scripts: usize, sans: bool) -> Vec<Ligne> {
    let mut l = tete(
        "Extensions",
        tr!("plugins et scripts, hors Vanguard", "plugins and scripts, not Vanguard"),
    );
    l.push(Ligne::choix(
        "1",
        "Plugins",
        &trf!("{plugins} outil(s) avec manifeste", "{plugins} tool(s) with a manifest"),
    ));
    l.push(Ligne::choix(
        "2",
        tr!("Scripts (labo)", "Scripts (lab)"),
        &trf!("{scripts} essai(s), expérimental", "{scripts} test(s), experimental"),
    ));
    l.push(ligne_interrupteur("3", sans, tr!("Restrictions", "Restrictions")));
    for ligne in envelopper(super::reglages::ce_qui_reste(), LARGEUR - 6) {
        l.push(Ligne::Texte(format!("     {GRIS}{ligne}{RESET}")));
    }
    l.push(Ligne::Texte(String::new()));
    l.push(Ligne::choix("0", tr!("Revenir", "Back"), ""));
    l.push(Ligne::Texte(String::new()));
    l
}

/// Ce que l'interrupteur vient de devenir, en une ligne.
pub(super) fn dire_restrictions(sans: bool) {
    if sans {
        crate::trp!(
            "  {}⚠{RESET} Restrictions coupées : les extensions tournent sans accord, sans empreinte ni analyse, avec tous tes droits.",
            "  {}⚠{RESET} Restrictions off: extensions run without consent, fingerprint or scan, with all your rights.",
            couleur(crate::risk::Niveau::Eleve)
        );
    } else {
        crate::trp!(
            "  {VERT}✔{RESET} Restrictions actives : approbation par empreinte, analyse, bornes, jamais en administrateur.",
            "  {VERT}✔{RESET} Restrictions on: approval by fingerprint, scan, limits, never as administrator."
        );
    }
}

fn etat_court(e: &Etat) -> String {
    match e {
        Etat::Pret => tr!("approuvé", "approved").to_string(),
        Etat::NonApprouve => tr!("non approuvé", "not approved").to_string(),
        Etat::Change => tr!("modifié depuis l'approbation", "changed since approval").to_string(),
        Etat::AutreSysteme => tr!("pas pour ce système", "not for this system").to_string(),
        Etat::Invalide(_) => tr!("invalide (vanguard plugin liste)", "invalid (vanguard plugin list)").to_string(),
    }
}

/// Les lignes de la liste des plugins : chacun numéroté (titre, description courte, état), puis les actions.
pub(super) fn lignes_plugins(plugins: &[Plugin], reglages: &super::reglages::Reglages) -> Vec<Ligne> {
    let mut l = tete(
        &trf!("Extensions {GRIS}›{RESET} Plugins", "Extensions {GRIS}›{RESET} Plugins"),
        tr!("outils durables, avec manifeste", "lasting tools, with a manifest"),
    );
    if plugins.is_empty() {
        paragraphe(
            &mut l,
            tr!(
                "Aucun plugin : « a » copie ici un dossier qui contient ton programme et son plugin.toml (exemple : outils/plugins/exemple dans les sources de Vanguard).",
                "No plugin: “a” copies here a folder holding your program and its plugin.toml (example: outils/plugins/exemple in Vanguard's sources)."
            ),
        );
    }
    for (i, p) in plugins.iter().enumerate() {
        let texte = p.manifeste.as_ref().map_or_else(
            || p.nom.clone(),
            |m| {
                format!(
                    "{} {GRIS}· {}{RESET}",
                    affichable(m.titre()),
                    affichable(m.description())
                )
            },
        );
        let libre = p.manifeste.as_ref().is_some_and(|m| reglages.plugin_libre(m));
        let etat = if libre && !matches!(p.etat, Etat::Invalide(_) | Etat::AutreSysteme) {
            tr!("sans restrictions", "without restrictions").to_string()
        } else {
            etat_court(&p.etat)
        };
        lignes_choix(&mut l, &(i + 1).to_string(), &texte, &etat);
    }
    l.push(Ligne::Texte(String::new()));
    l.push(Ligne::choix("a", tr!("Ajouter un plugin", "Add a plugin"), ""));
    if !plugins.is_empty() {
        l.push(Ligne::choix("p", tr!("Approuver un plugin", "Approve a plugin"), ""));
        l.push(Ligne::choix("r", tr!("Retirer un plugin", "Remove a plugin"), ""));
        l.push(Ligne::choix(
            "t",
            tr!("Restrictions d'un plugin", "Restrictions of a plugin"),
            tr!("couper ou remettre", "turn off or back on"),
        ));
    }
    l.push(Ligne::choix("0", tr!("Revenir", "Back"), ""));
    l.push(Ligne::Texte(String::new()));
    l
}

/// Une ligne numérotée : le texte coupé (sans couleur au milieu d'une coupure) pour que touche, texte et état tiennent
/// dans 76 colonnes.
fn lignes_choix(l: &mut Vec<Ligne>, touche: &str, texte: &str, etat: &str) {
    let texte = if largeur_affichee(texte) > 38 {
        // Coupé sans ses couleurs : une coupure au milieu d'un code de couleur laisserait la suite en gris.
        let nu: String = texte.replace(GRIS, "").replace(RESET, "");
        couper(&nu, 38)
    } else {
        texte.to_string()
    };
    l.push(Ligne::choix(touche, &texte, &couper(etat, 33)));
}

/// Les lignes de la liste du labo : chaque script numéroté (nom, état), puis les actions.
pub(super) fn lignes_labo(
    scripts: &[labo::Script],
    dossier: &Path,
    reglages: &super::reglages::Reglages,
) -> Vec<Ligne> {
    let mut l = tete(
        &trf!(
            "Extensions {GRIS}›{RESET} Scripts (labo)",
            "Extensions {GRIS}›{RESET} Scripts (lab)"
        ),
        tr!("EXPÉRIMENTAL, hors Vanguard", "EXPERIMENTAL, not Vanguard"),
    );
    if scripts.is_empty() {
        paragraphe(
            &mut l,
            tr!(
                "Aucun script : pose un .sh, .bash, .ps1, .py ou un programme dans le dossier du labo, puis reviens ici :",
                "No script: put a .sh, .bash, .ps1, .py or a program in the lab folder, then come back here:"
            ),
        );
        paragraphe(&mut l, &chemin_affichable(dossier));
    }
    for (i, s) in scripts.iter().enumerate() {
        let etat = if reglages.labo_libre(&s.fichier) && !matches!(s.etat, labo::Etat::Refuse(_)) {
            tr!("à moi, sans restrictions", "mine, without restrictions").to_string()
        } else {
            labo::libelle(&s.etat)
        };
        lignes_choix(&mut l, &(i + 1).to_string(), &affichable(&s.fichier), &etat);
    }
    l.push(Ligne::Texte(String::new()));
    l.push(Ligne::choix(
        "o",
        tr!("Ouvrir le dossier du labo", "Open the lab folder"),
        "",
    ));
    if !scripts.is_empty() {
        l.push(Ligne::choix("p", tr!("Approuver un script", "Approve a script"), ""));
        l.push(Ligne::choix("r", tr!("Retirer un script", "Remove a script"), ""));
        l.push(Ligne::choix(
            "t",
            tr!("Marquer un script comme à moi", "Mark a script as mine"),
            tr!("restrictions coupées ou remises", "restrictions off or back on"),
        ));
    }
    l.push(Ligne::choix("0", tr!("Revenir", "Back"), ""));
    l.push(Ligne::Texte(String::new()));
    l
}

/// Le choix du menu : `None` pour revenir (Échap, 0, Entrée seule, q).
fn choix(lignes: &[Ligne], dernier: &str) -> Option<String> {
    let c = choisir(lignes, &invite(), dernier, tr!("revenir", "back"))?;
    let c = c.trim().to_lowercase();
    (!matches!(c.as_str(), "" | "0" | "q" | "↵")).then_some(c)
}

/// L'élément désigné par son numéro ou son nom, demandé pour approuver ou retirer.
fn designer<'a>(noms: &'a [String], question: &str) -> Option<&'a str> {
    let r = demander(question);
    let r = r.trim();
    r.parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|i| noms.get(i))
        .or_else(|| noms.iter().find(|n| n.as_str() == r))
        .map(String::as_str)
}

/// Menu « Extensions » (menu principal, `vanguard extensions`). En administrateur, il s'ouvre : chaque lancement dit
/// lui-même s'il est refusé.
pub fn extensions() {
    let racine = match super::dossier() {
        Ok(r) => r,
        Err(e) => {
            super::echec(&e);
            return;
        }
    };
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let sans = super::reglages::charger(&racine).sans_restrictions;
        let lignes = lignes_extensions(super::inventaire(&racine).len(), labo::scripts(&racine).len(), sans);
        let Some(c) = choix(&lignes, &dernier) else { return };
        match c.as_str() {
            "1" => plugins(&racine),
            "2" => labo(&racine),
            "3" => {
                println!();
                match super::reglages::basculer(&racine, |q| demander(q).oui()) {
                    Ok(etat) if etat != sans => dire_restrictions(etat),
                    Ok(_) => crate::trp!("  Rien n'a changé.", "  Nothing changed."),
                    Err(e) => {
                        super::echec(&e);
                    }
                }
                attendre();
            }
            _ => continue,
        }
        dernier = c;
    }
}

/// La liste des plugins (Extensions › Plugins, `vanguard plugin` sans argument).
pub fn plugins(racine: &Path) {
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let liste = super::inventaire(racine);
        let reglages = super::reglages::charger(racine);
        let Some(c) = choix(&lignes_plugins(&liste, &reglages), &dernier) else {
            return;
        };
        let accord = |q: &str| demander(q).oui();
        let noms: Vec<String> = liste.iter().map(|p| p.nom.clone()).collect();
        let resultat = match c.as_str() {
            "a" => {
                let chemin = demander(tr!(
                    "  Dossier du plugin à ajouter (chemin) : ",
                    "  Folder of the plugin to add (path): "
                ));
                let chemin = chemin.trim().trim_matches(['"', '\'']);
                if chemin.is_empty() {
                    continue;
                }
                super::ajouter(racine, Path::new(chemin), accord).map(|nom| {
                    crate::trp!(
                        "  {VERT}✔{RESET} Plugin « {nom} » ajouté et approuvé.",
                        "  {VERT}✔{RESET} Plugin “{nom}” added and approved."
                    );
                })
            }
            "p" | "r" | "t" => {
                let Some(nom) = designer(
                    &noms,
                    tr!("  Numéro ou nom du plugin : ", "  Number or name of the plugin: "),
                ) else {
                    continue;
                };
                match c.as_str() {
                    "p" => super::approuver(racine, nom, accord),
                    "r" => super::retirer(racine, nom, accord).map(|_| ()),
                    _ => basculer_element(racine, false, nom, &liste),
                }
            }
            n => {
                let Some(p) = n
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|i| liste.get(i))
                else {
                    continue;
                };
                dernier = n.to_string();
                println!();
                lancer_plugin(racine, p);
                Ok(())
            }
        };
        if let Err(e) = resultat {
            super::echec(&e);
        }
        attendre();
    }
}

/// L'interrupteur d'un élément : « à moi » (restrictions coupées pour lui seul) ou remis. Un plugin dont le manifeste
/// dit `confiance = "totale"` le reste : c'est son manifeste qu'il faut changer.
fn basculer_element(racine: &Path, labo: bool, nom: &str, plugins: &[Plugin]) -> Result<(), String> {
    let par_manifeste = plugins
        .iter()
        .any(|p| p.nom == nom && p.manifeste.as_ref().is_some_and(|m| m.confiance_totale));
    let etat = super::reglages::basculer_element(racine, labo, nom, |q| demander(q).oui())?;
    if etat {
        dire_restrictions(true);
    } else if par_manifeste {
        crate::trp!(
            "  Son plugin.toml dit confiance = \"totale\" : il reste sans restrictions tant que son manifeste le dit.",
            "  Its plugin.toml says confiance = \"totale\": it stays without restrictions as long as its manifest says so."
        );
    } else {
        crate::trp!(
            "  {VERT}✔{RESET} Restrictions remises pour « {} ».",
            "  {VERT}✔{RESET} Restrictions back on for “{}”.",
            nom
        );
    }
    Ok(())
}

/// Lance un plugin choisi dans la liste : approuvé, il tourne ; sinon il est d'abord montré et approuvé sur accord.
fn lancer_plugin(racine: &Path, p: &Plugin) {
    let libre = p
        .manifeste
        .as_ref()
        .is_some_and(|m| super::reglages::charger(racine).plugin_libre(m));
    match &p.etat {
        Etat::Pret | Etat::NonApprouve | Etat::Change if libre => {
            super::executer(racine, &p.nom, &[], false, super::Facon::default());
        }
        Etat::Pret => {
            super::executer(racine, &p.nom, &[], false, super::Facon::default());
        }
        Etat::NonApprouve | Etat::Change => match super::approuver(racine, &p.nom, |q| demander(q).oui()) {
            Ok(()) => {
                super::executer(racine, &p.nom, &[], false, super::Facon::default());
            }
            Err(e) => {
                super::echec(&e);
            }
        },
        Etat::AutreSysteme => {
            super::echec(&trf!(
                "« {} » ne vise pas ce système.",
                "“{}” does not target this system.",
                p.nom
            ));
        }
        Etat::Invalide(e) => {
            super::echec(&trf!("« {} » : {}", "“{}”: {}", p.nom, affichable(e)));
        }
    }
}

/// La liste des scripts du labo (Extensions › Scripts, `vanguard labo` sans argument).
pub fn labo(racine: &Path) {
    let dossier = match labo::dossier_labo(racine) {
        Ok(d) => d,
        Err(e) => {
            super::echec(&e);
            return;
        }
    };
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let liste = labo::scripts(racine);
        let reglages = super::reglages::charger(racine);
        let Some(c) = choix(&lignes_labo(&liste, &dossier, &reglages), &dernier) else {
            return;
        };
        let accord = |q: &str| demander(q).oui();
        let noms: Vec<String> = liste.iter().map(|s| s.fichier.clone()).collect();
        let resultat = match c.as_str() {
            "o" => {
                println!();
                labo::montrer_dossier(&dossier);
                Ok(())
            }
            "p" | "r" | "t" => {
                let Some(f) = designer(
                    &noms,
                    tr!("  Numéro ou nom du script : ", "  Number or name of the script: "),
                ) else {
                    continue;
                };
                match c.as_str() {
                    "p" => labo::approuver(racine, f, accord),
                    "r" => labo::retirer(racine, f, accord).map(|_| ()),
                    _ => basculer_element(racine, true, f, &[]),
                }
            }
            n => {
                let Some(s) = n
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|i| liste.get(i))
                else {
                    continue;
                };
                dernier = n.to_string();
                labo::executer(racine, &s.fichier, &[], super::Facon::default());
                Ok(())
            }
        };
        if let Err(e) = resultat {
            super::echec(&e);
        }
        attendre();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ce qu'une ligne prend à l'écran : 5 colonnes de marge et de touche, le texte (38 au plus, aligné), l'état.
    fn largeur(l: &Ligne) -> usize {
        match l {
            Ligne::Texte(t) => largeur_affichee(t),
            Ligne::Choix { texte, precision, .. } => {
                8 + largeur_affichee(texte).max(30) + 2 + largeur_affichee(precision)
            }
            Ligne::Cachee { .. } => 0,
        }
    }

    fn textes(lignes: &[Ligne]) -> String {
        lignes
            .iter()
            .map(|l| match l {
                Ligne::Texte(t) => t.clone(),
                Ligne::Choix {
                    touche,
                    texte,
                    precision,
                    ..
                } => format!("{touche} {texte} {precision}"),
                Ligne::Cachee { .. } => String::new(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn les_menus_tiennent_en_76_colonnes_et_disent_quand_ils_sont_vides() {
        let reglages = super::super::reglages::Reglages::default();
        for l in lignes_extensions(3, 12, false)
            .iter()
            .chain(&lignes_extensions(0, 0, true))
        {
            assert!(largeur(l) <= LARGEUR, "{}", textes(std::slice::from_ref(l)));
        }
        assert!(textes(&lignes_extensions(0, 0, false)).contains("ACTIVES"));
        assert!(textes(&lignes_extensions(0, 0, true)).contains("COUPÉES"));
        let vide = lignes_plugins(&[], &reglages);
        assert!(textes(&vide).contains("Aucun plugin"));
        let dossier = Path::new("/home/alice/.local/share/vanguard/plugins/labo");
        let vide = lignes_labo(&[], dossier, &reglages);
        assert!(textes(&vide).contains("Aucun script") && textes(&vide).contains("plugins/labo"));
        // Des noms très longs : coupés, jamais plus larges que l'écran.
        let scripts = vec![
            labo::Script {
                fichier: "un-script-au-nom-vraiment-tres-tres-long-pour-voir.sh".into(),
                etat: labo::Etat::Change,
            },
            labo::Script {
                fichier: "essai.py".into(),
                etat: labo::Etat::Refuse("un lien : jamais suivi, et une raison bien trop longue".into()),
            },
        ];
        for l in &lignes_labo(&scripts, dossier, &reglages) {
            assert!(largeur(l) <= LARGEUR, "{}", textes(std::slice::from_ref(l)));
        }
        let plugins = vec![Plugin {
            nom: "salon".into(),
            manifeste: None,
            etat: Etat::Invalide("x".into()),
        }];
        for l in &lignes_plugins(&plugins, &reglages) {
            assert!(largeur(l) <= LARGEUR, "{}", textes(std::slice::from_ref(l)));
        }
    }
}
