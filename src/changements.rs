//! Ce que Vanguard a changé : chaque correction lancée après accord (commandes, date, réussie ou non) est notée sur cet
//! ordinateur seulement (changements.jsonl, jamais sur la clé ni ailleurs), et se relit au menu Cette machine ou par
//! `vanguard changements`. Les réglages d'Optimiser gardent en plus leur valeur d'avant, pour s'annuler exactement ;
//! un blocage (protection/blocage) garde de quoi se défaire exactement, et `vanguard blocage annuler` le défait.

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
    /// Un blocage de menace : ce qui a été bloqué, et ce qui l'annule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocage: Option<Blocage>,
}

/// Un blocage noté : de quoi le montrer, le reconnaître et l'annuler exactement.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Blocage {
    /// Unique sur cet ordinateur : c'est par lui qu'on l'annule.
    pub id: String,
    /// La menace (« connexion:203.0.113.7 ») : tant que le blocage est en place, elle n'est pas reproposée.
    pub cle: String,
    /// Ce qui a été fait, et pourquoi, prêt à montrer.
    pub quoi: String,
    /// Fait tout seul par la protection active (sinon, après un clic).
    #[serde(default)]
    pub automatique: bool,
    /// Ce qui le défait ; `None` : rien à défaire (un processus arrêté sans fichier ne se relance pas d'ici).
    pub annulation: Option<Annulation>,
    /// Date de l'annulation ; `None` : toujours en place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annule: Option<String>,
}

/// Ce qui défait un blocage, exactement.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "genre", rename_all = "kebab-case")]
pub(crate) enum Annulation {
    /// Les commandes inverses (règle de pare-feu retirée, valeur d'avant remise), par `machine::appliquer`. `port` :
    /// le port fermé en entrée (« 11434/tcp ») que Vanguard a retenu, à oublier avec la règle.
    Commandes {
        commandes: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<String>,
    },
    /// Le fichier mis en quarantaine, à remettre à sa place (son nom dans la quarantaine).
    Quarantaine { nom: String },
    /// Le fichier de réglages réécrit : sa copie d'avant, remise seulement s'il n'a pas changé depuis (empreinte
    /// SHA-256 de ce que Vanguard y a écrit).
    Copie {
        fichier: String,
        copie: String,
        empreinte: String,
    },
    /// Le programme retiré du démarrage : le réglage d'Optimiser (« demarrage:… ») à remettre.
    Demarrage { id: String },
}

/// Le relevé des corrections faites ici, dans le dossier de données : le seul endroit où leurs commandes sont notées.
pub(crate) const RELEVE: &str = "changements.jsonl";

fn fichier() -> std::path::PathBuf {
    crate::socle::dossier_local().join(RELEVE)
}

/// Note des corrections lancées (une liste de commandes chacune) et leur résultat.
pub fn noter(correctifs: &[Vec<String>], resultats: &[bool]) {
    noter_dans(&fichier(), correctifs, resultats);
}

fn noter_dans(chemin: &std::path::Path, correctifs: &[Vec<String>], resultats: &[bool]) {
    let date = maintenant();
    let mut tous = lire_de(chemin);
    for (commandes, &reussi) in correctifs.iter().zip(resultats) {
        tous.push(Changement {
            date: date.clone(),
            commandes: commandes.clone(),
            reussi,
            blocage: None,
        });
    }
    ecrire(chemin, tous);
}

fn maintenant() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M").to_string()
}

/// Un blocage en place, qui sait se défaire : jamais élagué, sans quoi une règle de pare-feu resterait sans que
/// Vanguard sache plus la retirer.
fn en_place(c: &Changement) -> bool {
    c.blocage
        .as_ref()
        .is_some_and(|b| b.annule.is_none() && b.annulation.is_some())
}

/// Garde les `GARDES` derniers changements, plus tous les blocages en place, puis réécrit le fichier d'un coup.
fn ecrire(chemin: &std::path::Path, tous: Vec<Changement>) {
    let mut en_trop = tous.len().saturating_sub(GARDES);
    let gardes: Vec<Changement> = tous
        .into_iter()
        .filter(|c| {
            if en_trop > 0 && !en_place(c) {
                en_trop -= 1;
                return false;
            }
            true
        })
        .collect();
    let texte: String = gardes
        .iter()
        .filter_map(|c| serde_json::to_string(c).ok())
        .map(|l| l + "\n")
        .collect();
    if let Some(parent) = chemin.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = crate::socle::ecrire_atomique(chemin, texte);
}

/// Note un blocage : ses commandes (telles que lancées), sa réussite, et de quoi l'annuler.
pub(crate) fn noter_blocage(commandes: Vec<String>, reussi: bool, blocage: Blocage) {
    noter_blocage_dans(&fichier(), commandes, reussi, blocage);
}

fn noter_blocage_dans(chemin: &std::path::Path, commandes: Vec<String>, reussi: bool, blocage: Blocage) {
    let mut tous = lire_de(chemin);
    tous.push(Changement {
        date: maintenant(),
        commandes,
        reussi,
        // Un échec n'a rien à défaire : il n'est pas proposé à l'annulation.
        blocage: Some(Blocage {
            annulation: blocage.annulation.filter(|_| reussi),
            ..blocage
        }),
    });
    ecrire(chemin, tous);
}

/// Les blocages en place (réussis, pas encore annulés), du plus ancien au plus récent, avec leur date.
pub(crate) fn blocages_en_place() -> Vec<(String, Blocage)> {
    blocages_en_place_de(&fichier())
}

fn blocages_en_place_de(chemin: &std::path::Path) -> Vec<(String, Blocage)> {
    lire_de(chemin)
        .into_iter()
        .filter(|c| c.reussi && en_place(c))
        .filter_map(|c| Some((c.date, c.blocage?)))
        .collect()
}

/// Note que ce blocage est défait : il n'est plus proposé à l'annulation, et la menace peut revenir.
pub(crate) fn marquer_annule(id: &str) {
    marquer_annule_dans(&fichier(), id);
}

fn marquer_annule_dans(chemin: &std::path::Path, id: &str) {
    let mut tous = lire_de(chemin);
    let date = maintenant();
    for c in &mut tous {
        if let Some(b) = c.blocage.as_mut().filter(|b| b.id == id) {
            b.annule = Some(date.clone());
        }
    }
    ecrire(chemin, tous);
}

/// Un identifiant neuf pour un blocage : l'heure en nanosecondes et le numéro du processus, sans hasard à tirer.
pub(crate) fn nouvel_id() -> String {
    static SUITE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let n = SUITE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{nanos:x}-{:x}-{n}", std::process::id())
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

/// Les corrections réussies qui ne sont pas des blocages, du plus ancien au plus récent : (date, première commande).
/// Une correction n'a pas de valeur d'avant notée : elle se défait à la main, avec la commande inverse.
pub(crate) fn a_defaire_a_la_main() -> Vec<(String, String)> {
    lire()
        .into_iter()
        .filter(|c| c.reussi && c.blocage.is_none())
        .map(|c| (c.date, c.commandes.into_iter().next().unwrap_or_default()))
        .collect()
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

/// `vanguard changements` et le menu Cette machine.
pub fn afficher() {
    titre(tr!("Ce que Vanguard a changé", "What Vanguard changed"));
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
        if let Some(b) = &c.blocage {
            let etat = match (&b.annule, &b.annulation, b.automatique) {
                (Some(le), _, _) => trf!(" (annulé le {le})", " (undone on {le})"),
                (None, Some(_), true) => tr!(" (automatique, annulable)", " (automatic, undoable)").to_string(),
                (None, Some(_), false) => tr!(" (annulable)", " (undoable)").to_string(),
                (None, None, _) => String::new(),
            };
            afficher_aligne(
                &format!("  {marque} {GRIS}{}{RESET}  ", c.date),
                &format!("{}{etat}", affichable(&b.quoi)),
                21,
                "",
            );
            continue;
        }
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
            "Les réglages d'Optimiser s'annulent exactement par « Tout remettre comme avant », un blocage par « vanguard blocage annuler » ; une correction se défait à la main, avec la commande inverse.",
            "Optimize settings are undone exactly with “Put everything back”, a block with “vanguard blocking undo”; a fix is undone by hand, with the opposite command."
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
        let f = std::env::temp_dir().join(format!("vanguard-changements-{}.jsonl", std::process::id()));
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

    fn blocage(id: &str, annulation: Option<Annulation>) -> Blocage {
        Blocage {
            id: id.into(),
            cle: format!("connexion:{id}"),
            quoi: "Règle sortante vers 203.0.113.7".into(),
            automatique: true,
            annulation,
            annule: None,
        }
    }

    /// Garde-fou : chaque blocage est noté avec de quoi l'annuler, n'est jamais élagué tant qu'il est en place, et
    /// sort de la liste des blocages en place une fois annulé. Un échec n'a rien à annuler.
    #[test]
    fn blocages_notes_annulables_jamais_elagues() {
        let f = std::env::temp_dir().join(format!("vanguard-blocages-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&f);
        let retirer = Annulation::Commandes {
            commandes: vec!["sudo ufw delete deny out to 203.0.113.7".into()],
            port: None,
        };
        noter_blocage_dans(
            &f,
            vec!["sudo ufw prepend deny out to 203.0.113.7".into()],
            true,
            blocage("a", Some(retirer.clone())),
        );
        noter_blocage_dans(&f, vec!["false".into()], false, blocage("b", Some(retirer.clone())));
        let en_place = blocages_en_place_de(&f);
        assert_eq!(en_place.len(), 1, "{en_place:?}");
        assert_eq!(en_place[0].1.annulation, Some(retirer));
        assert!(lire_de(&f)[1].blocage.as_ref().unwrap().annulation.is_none());
        // Bien plus de corrections que la limite : le blocage en place reste, le reste est élagué.
        let beaucoup: Vec<Vec<String>> = (0..GARDES + 20).map(|i| vec![format!("echo {i}")]).collect();
        noter_dans(&f, &beaucoup, &vec![true; beaucoup.len()]);
        let tous = lire_de(&f);
        assert_eq!(tous.len(), GARDES);
        assert_eq!(tous[0].blocage.as_ref().map(|b| b.id.as_str()), Some("a"));
        assert_eq!(blocages_en_place_de(&f).len(), 1);
        // Annulé : plus en place, et il peut maintenant être élagué comme le reste.
        marquer_annule_dans(&f, "a");
        assert_eq!(blocages_en_place_de(&f), Vec::new());
        assert!(
            lire_de(&f)
                .iter()
                .any(|c| c.blocage.as_ref().is_some_and(|b| b.annule.is_some()))
        );
        noter_dans(&f, &[vec!["echo fin".into()]], &[true]);
        let tous = lire_de(&f);
        assert_eq!(tous.len(), GARDES);
        assert!(tous.iter().all(|c| c.blocage.is_none()));
        // Une ligne d'une version d'avant (sans blocage) se relit toujours.
        assert_eq!(
            lire_texte("{\"date\":\"2026-10-01 10:00\",\"commandes\":[\"x\"],\"reussi\":true}\n").len(),
            1
        );
        let _ = std::fs::remove_file(&f);
        assert_ne!(nouvel_id(), nouvel_id());
    }
}
