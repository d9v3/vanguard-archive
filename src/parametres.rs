//! Paramètres : tous les réglages de Vanguard au même endroit (Cette machine › Paramètres, ou « s » au menu
//! principal ; `vanguard parametres`, alias `settings`). Ceux du lancement (langue, emojis, travail sans Internet) sont gardés dans
//! parametres.json, sur cet ordinateur, et lus au lancement, avant tout affichage ; une variable d'environnement
//! (VANGUARD_LANG, VANGUARD_EMOJI, VANGUARD_HORS_LIGNE) l'emporte toujours sur le fichier. Les autres gardent leur
//! place et leur code, que ce menu appelle : la surveillance horaire et l'entretien du mois (leurs minuteries), les
//! alertes apprises (appris.json), le blocage (blocage.json). Chaque changement est montré avec sa valeur d'avant,
//! et s'annule en la remettant.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::selection::{Ligne, choisir};
use crate::ui::*;

/// Ce que garde parametres.json : seulement les réglages du lancement.
#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, Debug)]
struct Fichier {
    /// « fr » ou « en » ; absente : la langue du système.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    langue: Option<String>,
    /// Absente : d'après la console (l'ancienne console de Windows les dessine mal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    emojis: Option<bool>,
    /// Travailler sans Internet, comme VANGUARD_HORS_LIGNE.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    hors_ligne: bool,
}

/// Au-delà, ce n'est pas le fichier de Vanguard : il n'est pas lu (le processus élevé de Windows le lit aussi).
const TAILLE_MAX: u64 = 64 << 10;

fn fichier() -> PathBuf {
    crate::reseau::dossier_local().join("parametres.json")
}

/// Le fichier ; absent : les défauts ; `Err` (la raison) s'il est là mais ne se lit pas.
fn charger_de(chemin: &Path) -> Result<Fichier, String> {
    match std::fs::metadata(chemin) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Fichier::default()),
        Err(e) => return Err(e.to_string()),
        Ok(m) if m.len() > TAILLE_MAX => {
            return Err(trf!("plus de {} Kio", "over {} KiB", TAILLE_MAX >> 10));
        }
        Ok(_) => {}
    }
    let texte = std::fs::read_to_string(chemin).map_err(|e| e.to_string())?;
    serde_json::from_str(texte.trim_start_matches('\u{feff}')).map_err(|e| e.to_string())
}

fn enregistrer_dans(f: &Fichier, chemin: &Path) -> std::io::Result<()> {
    let texte = serde_json::to_string_pretty(f).map_err(std::io::Error::other)?;
    crate::reseau::ecrire_atomique(chemin, texte)
}

/// Les réglages du lancement, lus une fois : un fichier abîmé vaut les défauts (le menu le dit).
fn au_demarrage() -> &'static Fichier {
    static LUS: OnceLock<Fichier> = OnceLock::new();
    LUS.get_or_init(|| charger_de(&fichier()).unwrap_or_default())
}

/// À appeler au début du programme, avant tout affichage : les réglages du lancement sont lus là.
pub fn au_lancement() {
    let _ = au_demarrage();
}

/// La langue voulue : VANGUARD_LANG, sinon le fichier ; `None` : celle du système.
pub(crate) fn langue() -> Option<String> {
    priorite(crate::passage::variable("VANGUARD_LANG"), au_demarrage().langue.clone())
}

/// Les emojis voulus, tels que `ui` les lit (« 1 », « 0 ») : VANGUARD_EMOJI, sinon le fichier ; `None` : d'après
/// la console.
pub(crate) fn emojis() -> Option<String> {
    priorite(
        crate::passage::variable("VANGUARD_EMOJI"),
        au_demarrage().emojis.map(|e| if e { "1" } else { "0" }.to_string()),
    )
}

/// Travailler sans Internet : VANGUARD_HORS_LIGNE posée (sauf à « 0 », « non »…), sinon le fichier.
pub(crate) fn hors_ligne() -> bool {
    let variable = std::env::var_os("VANGUARD_HORS_LIGNE").map(|v| v.to_string_lossy().into_owned());
    hors_ligne_voulu(variable.as_deref(), au_demarrage().hors_ligne)
}

/// La variable d'environnement l'emporte sur le fichier.
fn priorite(variable: Option<String>, fichier: Option<String>) -> Option<String> {
    variable.or(fichier)
}

fn hors_ligne_voulu(variable: Option<&str>, fichier: bool) -> bool {
    match variable.map(|v| v.trim().to_lowercase()) {
        Some(v) => !matches!(v.as_str(), "0" | "non" | "no" | "off" | "false"),
        None => fichier,
    }
}

/// Les réglages de ce menu. Chacun garde sa place et son code ; ce menu ne fait que les montrer et les changer. Les
/// restrictions des extensions (plugins/reglages.json, de leur module) viendront ici de la même façon, par leur
/// propre fonction : une ligne de plus dans `TOUS`, rien de copié.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reglage {
    Langue,
    Emojis,
    HorsLigne,
    Surveillance,
    Entretien,
    Appris,
    Blocage,
}

impl Reglage {
    const TOUS: [Reglage; 7] = [
        Reglage::Langue,
        Reglage::Emojis,
        Reglage::HorsLigne,
        Reglage::Surveillance,
        Reglage::Entretien,
        Reglage::Appris,
        Reglage::Blocage,
    ];

    /// Le mot de la ligne de commande.
    fn mot(self) -> &'static str {
        match self {
            Reglage::Langue => tr!("langue", "language"),
            Reglage::Emojis => "emojis",
            Reglage::HorsLigne => tr!("sans-internet", "offline"),
            Reglage::Surveillance => tr!("surveillance", "monitoring"),
            Reglage::Entretien => tr!("entretien", "maintenance"),
            Reglage::Appris => tr!("appris", "learned"),
            Reglage::Blocage => tr!("blocage", "blocking"),
        }
    }

    fn depuis_mot(mot: &str) -> Option<Reglage> {
        match mot.trim().to_lowercase().as_str() {
            "langue" | "language" | "lang" => Some(Reglage::Langue),
            "emojis" | "emoji" => Some(Reglage::Emojis),
            "sans-internet" | "hors-ligne" | "horsligne" | "offline" | "internet" => Some(Reglage::HorsLigne),
            "surveillance" | "monitoring" | "monitor" => Some(Reglage::Surveillance),
            "entretien" | "maintenance" => Some(Reglage::Entretien),
            "appris" | "learned" | "apprentissage" | "learning" => Some(Reglage::Appris),
            "blocage" | "blocking" => Some(Reglage::Blocage),
            _ => None,
        }
    }

    fn titre(self) -> &'static str {
        match self {
            Reglage::Langue => tr!("Langue", "Language"),
            Reglage::Emojis => tr!("Emojis", "Emojis"),
            Reglage::HorsLigne => tr!("Travailler sans Internet", "Work without the Internet"),
            Reglage::Surveillance => tr!("Surveillance horaire du réseau", "Hourly network monitoring"),
            Reglage::Entretien => tr!("Entretien du mois", "Monthly check-up"),
            Reglage::Appris => tr!("Alertes apprises", "Learned alerts"),
            Reglage::Blocage => tr!("Blocage des menaces", "Threat blocking"),
        }
    }

    /// La variable d'environnement qui l'emporte sur le fichier, pour un réglage du lancement.
    fn variable(self) -> Option<&'static str> {
        match self {
            Reglage::Langue => Some("VANGUARD_LANG"),
            Reglage::Emojis => Some("VANGUARD_EMOJI"),
            Reglage::HorsLigne => Some("VANGUARD_HORS_LIGNE"),
            _ => None,
        }
    }

    /// Les valeurs qu'il accepte, telles qu'on les tape dans la langue de l'interface (l'autre marche aussi) ; vide :
    /// il ouvre son propre écran.
    fn valeurs(self) -> &'static [&'static str] {
        let anglais = crate::langue::anglais();
        match self {
            Reglage::Langue => &["auto", "fr", "en"],
            Reglage::Emojis if anglais => &["auto", "yes", "no"],
            Reglage::Emojis => &["auto", "oui", "non"],
            Reglage::HorsLigne | Reglage::Surveillance | Reglage::Entretien if anglais => &["yes", "no"],
            Reglage::HorsLigne | Reglage::Surveillance | Reglage::Entretien => &["oui", "non"],
            Reglage::Appris | Reglage::Blocage => &[],
        }
    }
}

/// Une valeur tapée pour la langue : `Ok(None)` = auto, `Ok(Some("fr"))`… ; `Err` : inconnue.
fn langue_de(mot: &str) -> Result<Option<String>, ()> {
    match mot.trim().to_lowercase().as_str() {
        "auto" | "systeme" | "système" | "system" => Ok(None),
        "fr" | "francais" | "français" | "french" => Ok(Some("fr".into())),
        "en" | "anglais" | "english" => Ok(Some("en".into())),
        _ => Err(()),
    }
}

/// Oui ou non, dans les deux langues ; `None` : inconnu.
fn oui_non(mot: &str) -> Option<bool> {
    match mot.trim().to_lowercase().as_str() {
        "oui" | "o" | "yes" | "y" | "on" | "1" | "true" | "active" | "activee" | "activée" | "activé" => Some(true),
        "non" | "n" | "no" | "off" | "0" | "false" | "desactive" | "désactivé" | "désactivée" | "desactivee" => {
            Some(false)
        }
        _ => None,
    }
}

/// Auto (`Ok(None)`), oui ou non ; `Err` : inconnu.
fn auto_oui_non(mot: &str) -> Result<Option<bool>, ()> {
    if mot.trim().eq_ignore_ascii_case("auto") {
        Ok(None)
    } else {
        oui_non(mot).map(Some).ok_or(())
    }
}

fn mot_oui_non(oui: bool) -> &'static str {
    if oui { tr!("oui", "yes") } else { tr!("non", "no") }
}

/// Un réglage du lancement changé dans le fichier : `Err` si la valeur est inconnue. Rend (avant, après), tels
/// qu'on les tape.
fn changer_dans(f: &mut Fichier, r: Reglage, valeur: &str) -> Result<(String, String), ()> {
    let auto = |v: Option<String>| v.unwrap_or_else(|| "auto".into());
    let oui_non_auto = |v: Option<bool>| v.map_or_else(|| "auto".to_string(), |o| mot_oui_non(o).to_string());
    match r {
        Reglage::Langue => {
            let nouvelle = langue_de(valeur)?;
            let avant = auto(f.langue.clone());
            f.langue = nouvelle;
            Ok((avant, auto(f.langue.clone())))
        }
        Reglage::Emojis => {
            let nouveau = auto_oui_non(valeur)?;
            let avant = oui_non_auto(f.emojis);
            f.emojis = nouveau;
            Ok((avant, oui_non_auto(f.emojis)))
        }
        Reglage::HorsLigne => {
            let nouveau = oui_non(valeur).ok_or(())?;
            let avant = mot_oui_non(f.hors_ligne).to_string();
            f.hors_ligne = nouveau;
            Ok((avant, mot_oui_non(f.hors_ligne).to_string()))
        }
        _ => Err(()),
    }
}

/// La valeur d'un réglage, telle qu'elle se montre.
fn valeur(r: Reglage) -> String {
    let fichier = charger_de(&fichier()).unwrap_or_default();
    let mut texte = match r {
        Reglage::Langue => match &fichier.langue {
            Some(l) => l.clone(),
            None => trf!(
                "auto ({})",
                "auto ({})",
                if crate::langue::anglais() { "en" } else { "fr" }
            ),
        },
        Reglage::Emojis => fichier
            .emojis
            .map_or_else(|| tr!("auto", "auto").to_string(), |e| mot_oui_non(e).to_string()),
        Reglage::HorsLigne => mot_oui_non(fichier.hors_ligne).to_string(),
        Reglage::Surveillance => mot_oui_non(crate::reseau::surveillance::active()).to_string(),
        Reglage::Entretien => mot_oui_non(crate::entretien::active()).to_string(),
        Reglage::Appris => match crate::apprentissage::nombre() {
            Some(n) => trf!("{n} alerte(s) normale(s)", "{n} normal alert(s)"),
            None => tr!("liste illisible", "list unreadable").to_string(),
        },
        Reglage::Blocage => crate::protection::blocage::etat_court().to_string(),
    };
    if let Some(v) = r.variable().filter(|v| std::env::var_os(v).is_some()) {
        texte += &trf!(" ({v} l'emporte)", " ({v} wins)");
    }
    texte
}

/// `vanguard parametres` : l'état ; avec un réglage et une valeur, le change ; « appris » et « blocage » ouvrent leur
/// outil (« blocage » prend aussi ses propres mots : `vanguard parametres blocage connexions auto`).
pub fn commande(mots: &[String]) {
    let Some((premier, reste)) = mots.split_first() else {
        afficher();
        return;
    };
    let Some(r) = Reglage::depuis_mot(premier) else {
        trp!(
            "  ✖ Réglage inconnu : « {} ». Réglages : {}.",
            "  ✖ Unknown setting: “{}”. Settings: {}.",
            affichable(premier),
            Reglage::TOUS.map(Reglage::mot).join(", ")
        );
        return;
    };
    match (r, reste) {
        (Reglage::Appris, _) => crate::apprentissage::menu(),
        (Reglage::Blocage, _) => crate::protection::blocage::commande(reste),
        (_, [valeur]) => {
            changer(r, valeur);
        }
        _ => trp!(
            "  {} : {}. Valeurs : {}.",
            "  {}: {}. Values: {}.",
            r.mot(),
            valeur(r),
            r.valeurs().join(", ")
        ),
    }
}

/// Change un réglage : la valeur d'avant et la nouvelle sont montrées, avec de quoi revenir. `false` : rien changé.
fn changer(r: Reglage, saisie: &str) -> bool {
    let inconnue = || {
        trp!(
            "  ✖ Valeur inconnue pour {} : « {} ». Valeurs : {}.",
            "  ✖ Unknown value for {}: “{}”. Values: {}.",
            r.mot(),
            affichable(saisie),
            r.valeurs().join(", ")
        );
        false
    };
    let (avant, apres) = match r {
        Reglage::Langue | Reglage::Emojis | Reglage::HorsLigne => {
            let chemin = fichier();
            let lu = charger_de(&chemin);
            let mut f = lu.clone().unwrap_or_default();
            let Ok((avant, apres)) = changer_dans(&mut f, r, saisie) else {
                return inconnue();
            };
            if lu.is_err() {
                // Jamais écraser en silence un fichier qu'on ne sait plus lire : il est gardé à côté.
                let copie = chemin.with_extension(format!(
                    "illisible-{}.json",
                    chrono::Local::now().format("%Y%m%d-%H%M%S")
                ));
                let _ = std::fs::copy(&chemin, &copie);
            }
            if let Err(e) = enregistrer_dans(&f, &chemin) {
                trp!("  ✖ Non enregistré ({e}).", "  ✖ Not saved ({e}).");
                return false;
            }
            (avant, apres)
        }
        Reglage::Surveillance | Reglage::Entretien => {
            let Some(voulu) = oui_non(saisie) else {
                return inconnue();
            };
            let actif = if r == Reglage::Surveillance {
                crate::reseau::surveillance::active()
            } else {
                crate::entretien::active()
            };
            if actif != voulu {
                if r == Reglage::Surveillance {
                    crate::reseau::surveillance::activer(voulu);
                } else {
                    crate::entretien::activer(voulu);
                }
            }
            (mot_oui_non(actif).to_string(), mot_oui_non(voulu).to_string())
        }
        Reglage::Appris | Reglage::Blocage => return false,
    };
    trp!(
        "  {VERT}✔{RESET} {} : {avant} → {apres}",
        "  {VERT}✔{RESET} {}: {avant} → {apres}",
        r.titre()
    );
    if r.variable().is_some() {
        trp!(
            "  {GRIS}Effectif au prochain lancement de Vanguard.{RESET}",
            "  {GRIS}Effective the next time Vanguard starts.{RESET}"
        );
    }
    if let Some(v) = r.variable().filter(|v| std::env::var_os(v).is_some()) {
        trp!(
            "  {GRIS}{v} est posée : elle l'emporte sur ce réglage tant qu'elle l'est.{RESET}",
            "  {GRIS}{v} is set: it wins over this setting as long as it is.{RESET}"
        );
    }
    if avant != apres {
        trp!(
            "  {GRIS}Pour revenir en arrière : vanguard parametres {} {avant}{RESET}",
            "  {GRIS}To go back: vanguard settings {} {avant}{RESET}",
            r.mot()
        );
    }
    true
}

/// L'état de tous les réglages.
fn afficher() {
    titre(tr!("Paramètres", "Settings"));
    if let Err(e) = charger_de(&fichier()) {
        trp!(
            "  {}⚠{RESET} parametres.json illisible ({e}) : les valeurs par défaut servent.",
            "  {}⚠{RESET} parametres.json unreadable ({e}): the defaults are used.",
            couleur(crate::risk::Niveau::Moyen)
        );
    }
    for r in Reglage::TOUS {
        afficher_aligne(&format!("  {GRAS}{:<16}{RESET} ", r.mot()), &valeur(r), 19, "");
    }
    println!();
    afficher_aligne(
        "  ",
        tr!(
            "Changer : vanguard parametres <réglage> <valeur> (sans valeur : celles qu'il accepte). Pour annuler, remettre la valeur d'avant. Une variable d'environnement (VANGUARD_LANG, VANGUARD_EMOJI, VANGUARD_HORS_LIGNE) l'emporte sur ces réglages.",
            "Change: vanguard settings <setting> <value> (no value: the ones it accepts). To undo, put the previous value back. An environment variable (VANGUARD_LANG, VANGUARD_EMOJI, VANGUARD_HORS_LIGNE) wins over these settings."
        ),
        2,
        GRIS,
    );
}

/// Ce que fait un réglage, en une phrase, sous son choix de valeur.
fn explication(r: Reglage) -> &'static str {
    match r {
        Reglage::Langue => tr!(
            "La langue de l'interface ; auto : celle du système.",
            "The interface language; auto: the system's."
        ),
        Reglage::Emojis => tr!(
            "L'ampoule et la clé à molette devant les conseils ; auto : sauf dans l'ancienne console de Windows, qui les dessine mal.",
            "The light bulb and the wrench in front of tips; auto: except in the old Windows console, which draws them badly."
        ),
        Reglage::HorsLigne => tr!(
            "Ce que Vanguard demande à Internet de lui-même est sauté : adresse vue d'Internet, DNS de l'audit, nouvelle version, empreintes de MalwareBazaar.",
            "What Vanguard asks the Internet by itself is skipped: address seen from the Internet, the audit's DNS, new version, MalwareBazaar fingerprints."
        ),
        Reglage::Surveillance => tr!(
            "Un scan du réseau toutes les heures, notification si un appareil inconnu arrive.",
            "A network scan every hour, notification if an unknown device shows up."
        ),
        Reglage::Entretien => tr!(
            "Une notification par mois : note, mises à jour, place, problèmes nouveaux.",
            "One notification a month: grade, updates, space, new problems."
        ),
        Reglage::Appris | Reglage::Blocage => "",
    }
}

/// Le menu Paramètres : chaque réglage et sa valeur ; choisi, ses valeurs (ou son outil).
pub fn menu() {
    let mut dernier = String::from("1");
    loop {
        let mut lignes = vec![
            Ligne::Texte(String::new()),
            Ligne::Texte(ligne_titre(tr!("Paramètres", "Settings"))),
            Ligne::Texte(String::new()),
        ];
        for (i, r) in Reglage::TOUS.iter().enumerate() {
            lignes.push(Ligne::choix(&(i + 1).to_string(), r.titre(), &couper(&valeur(*r), 33)));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        let Some(choix) = choisir(
            &lignes,
            tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim().to_string();
        let Some(&r) = choix
            .parse::<usize>()
            .ok()
            .and_then(|i| Reglage::TOUS.get(i.checked_sub(1)?))
        else {
            return;
        };
        dernier = choix;
        match r {
            Reglage::Appris => crate::apprentissage::menu(),
            Reglage::Blocage => crate::protection::blocage::menu(),
            _ => choisir_valeur(r),
        }
    }
}

/// Le choix d'une valeur, la valeur actuelle marquée.
fn choisir_valeur(r: Reglage) {
    let actuelle = valeur(r);
    let mut lignes = vec![Ligne::Texte(String::new()), Ligne::Texte(ligne_titre(r.titre()))];
    lignes.extend(
        envelopper(explication(r), LARGEUR - 4)
            .into_iter()
            .map(|l| Ligne::Texte(format!("  {GRIS}{l}{RESET}"))),
    );
    lignes.push(Ligne::Texte(String::new()));
    for (i, v) in r.valeurs().iter().enumerate() {
        let en_cours = actuelle == *v || actuelle.starts_with(&format!("{v} ("));
        let precision = if en_cours {
            tr!("← en ce moment", "← now")
        } else {
            ""
        };
        lignes.push(Ligne::choix(&(i + 1).to_string(), v, precision));
    }
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    let Some(choix) = choisir(
        &lignes,
        tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
        "1",
        tr!("revenir", "back"),
    ) else {
        return;
    };
    if let Some(v) = choix
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|i| r.valeurs().get(i.checked_sub(1)?))
    {
        changer(r, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-parametres-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("parametres.json")
    }

    #[test]
    fn fichier_ecrit_relu_ou_refuse() {
        let f = jetable("fichier");
        // Absent : les défauts, rien d'écrit.
        assert_eq!(charger_de(&f).unwrap(), Fichier::default());
        let voulu = Fichier {
            langue: Some("en".into()),
            emojis: Some(false),
            hors_ligne: true,
        };
        enregistrer_dans(&voulu, &f).unwrap();
        assert_eq!(charger_de(&f).unwrap(), voulu);
        // Les défauts ne s'écrivent pas : un fichier vide d'un réglage le laisse à « auto ».
        enregistrer_dans(&Fichier::default(), &f).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap().trim(), "{}");
        // Abîmé ou démesuré : refusé.
        std::fs::write(&f, "{pas du json").unwrap();
        assert!(charger_de(&f).is_err());
        std::fs::write(&f, " ".repeat(usize::try_from(TAILLE_MAX).unwrap() + 1)).unwrap();
        assert!(charger_de(&f).is_err());
        let _ = std::fs::remove_dir_all(f.parent().unwrap());
    }

    /// La variable d'environnement l'emporte toujours sur le fichier.
    #[test]
    fn la_variable_l_emporte() {
        assert_eq!(priorite(Some("en".into()), Some("fr".into())).as_deref(), Some("en"));
        assert_eq!(priorite(None, Some("fr".into())).as_deref(), Some("fr"));
        assert_eq!(priorite(None, None), None);
        assert!(hors_ligne_voulu(Some("1"), false));
        assert!(hors_ligne_voulu(Some(""), false), "posée, même vide : comme avant");
        assert!(
            !hors_ligne_voulu(Some("0"), true),
            "la variable dit non : elle l'emporte"
        );
        assert!(!hors_ligne_voulu(Some("non"), true));
        assert!(hors_ligne_voulu(None, true));
        assert!(!hors_ligne_voulu(None, false));
    }

    /// Une valeur inconnue est refusée, et rien ne change ; une connue rend la valeur d'avant, pour revenir.
    #[test]
    fn valeurs_connues_ou_refusees() {
        let mut f = Fichier::default();
        assert_eq!(
            changer_dans(&mut f, Reglage::Langue, "en"),
            Ok(("auto".to_string(), "en".to_string()))
        );
        assert_eq!(f.langue.as_deref(), Some("en"));
        assert_eq!(changer_dans(&mut f, Reglage::Langue, "klingon"), Err(()));
        assert_eq!(f.langue.as_deref(), Some("en"));
        assert_eq!(
            changer_dans(&mut f, Reglage::Langue, "auto"),
            Ok(("en".to_string(), "auto".to_string()))
        );
        assert_eq!(f.langue, None);
        assert!(changer_dans(&mut f, Reglage::Emojis, "non").is_ok());
        assert_eq!(f.emojis, Some(false));
        assert_eq!(changer_dans(&mut f, Reglage::Emojis, "parfois"), Err(()));
        assert!(changer_dans(&mut f, Reglage::HorsLigne, "oui").is_ok());
        assert!(f.hors_ligne);
        assert_eq!(changer_dans(&mut f, Reglage::HorsLigne, "auto"), Err(()));
        // Les réglages qui ont leur propre place ne passent pas par le fichier.
        assert_eq!(changer_dans(&mut f, Reglage::Surveillance, "oui"), Err(()));
        assert_eq!(oui_non("Activée"), Some(true));
        assert_eq!(oui_non("off"), Some(false));
        assert_eq!(oui_non("peut-être"), None);
    }

    #[test]
    fn mots_des_reglages() {
        for r in Reglage::TOUS {
            assert_eq!(Reglage::depuis_mot(r.mot()), Some(r));
            // Chaque valeur proposée au menu est acceptée par la ligne de commande.
            for v in r.valeurs() {
                let mut f = Fichier::default();
                let ok = match r {
                    Reglage::Surveillance | Reglage::Entretien => oui_non(v).is_some(),
                    _ => changer_dans(&mut f, r, v).is_ok(),
                };
                assert!(ok, "{r:?} {v}");
            }
        }
        assert_eq!(Reglage::depuis_mot("settings"), None);
        assert_eq!(Reglage::depuis_mot("Language"), Some(Reglage::Langue));
        assert_eq!(Reglage::depuis_mot("offline"), Some(Reglage::HorsLigne));
    }
}
