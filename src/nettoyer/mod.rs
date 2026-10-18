//! Nettoyer le système : libérer de la place sans rien perdre d'important. Chaque élément montre la place qu'il
//! libère, mesurée avant ; ce qui se refait seul (caches, fichiers temporaires, paquets téléchargés, vieux journaux)
//! est coché d'office, la corbeille jamais. On voit les commandes, on accepte, puis la place libre relue dit ce qui a
//! vraiment été gagné. Aucun document, aucune photo, aucun réglage n'est touché.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as systeme;
#[cfg(target_os = "macos")]
use macos as systeme;
#[cfg(windows)]
use windows as systeme;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::selection::{Case, cocher};
use crate::ui::*;

/// En dessous, il n'y a rien à gagner : l'élément s'affiche « déjà propre ».
const PRESQUE_RIEN: u64 = 1 << 20;

/// Une chose à nettoyer.
pub struct Element {
    pub titre: &'static str,
    /// Ce qui est effacé, et pourquoi ça ne fait rien perdre.
    pub effet: String,
    /// Le revers, s'il y en a un.
    pub prudence: Option<&'static str>,
    /// Place à libérer, mesurée avant ; `None` : connue seulement une fois fait (paquets à retirer, Windows Update…).
    pub taille: Option<u64>,
    pub commandes: Vec<String>,
    /// Coché d'office : tout se refait seul, rien n'est perdu.
    pub recommande: bool,
    /// Windows : demande les droits d'administrateur (une seule fenêtre pour tous) ; sans, la commande est lancée dans
    /// le compte de la personne (sa corbeille, son dossier temporaire : ceux du compte qui ouvrirait la fenêtre
    /// administrateur seraient d'autres).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub admin: bool,
}

impl Element {
    fn propre(&self) -> bool {
        self.taille.is_some_and(|t| t < PRESQUE_RIEN)
    }
}

/// « 1.2 Go », « 340 Mo ».
pub fn taille_lisible(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)] // une taille affichée à un chiffre après la virgule
    let f = octets as f64;
    if octets >= 1 << 30 {
        trf!("{:.1} Go", "{:.1} GB", f / f64::from(1u32 << 30))
    } else if octets >= PRESQUE_RIEN {
        trf!("{:.0} Mo", "{:.0} MB", f / f64::from(1u32 << 20))
    } else {
        tr!("moins de 1 Mo", "less than 1 MB").into()
    }
}

/// Le dossier personnel.
#[cfg_attr(windows, allow(dead_code))]
pub fn maison() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}

/// Ce que mesurer dans un dossier.
#[derive(Clone, Copy)]
pub enum Age {
    Tout,
    /// Fichiers non lus depuis ce nombre de jours (date de dernière lecture).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    NonLuDepuis(u64),
    /// Fichiers non modifiés depuis ce nombre de jours.
    #[cfg_attr(windows, allow(dead_code))]
    NonModifieDepuis(u64),
}

/// Taille d'un dossier en octets, sous-dossiers compris, sans ceux de `exclus` ; `None` s'il ne peut pas être lu du
/// tout (droits) : « vide » et « illisible » ne se confondent pas. Arrêt après deux secondes (un cache de millions
/// de fichiers) : le total est alors un minimum.
pub fn taille_dossier(dossier: &Path, age: Age, exclus: &[PathBuf]) -> Option<u64> {
    let echeance = Instant::now() + Duration::from_secs(2);
    let jours = |j: u64| SystemTime::now() - Duration::from_secs(j * 86_400);
    let limite = match age {
        Age::Tout => None,
        Age::NonLuDepuis(j) => Some((jours(j), true)),
        Age::NonModifieDepuis(j) => Some((jours(j), false)),
    };
    let mut total = 0;
    let mut a_voir = vec![std::fs::read_dir(dossier).ok()?];
    while let Some(entrees) = a_voir.pop() {
        if Instant::now() > echeance {
            break;
        }
        for e in entrees.flatten() {
            let chemin = e.path();
            // Un lien symbolique n'est pas suivi : sa cible n'est pas dans le dossier.
            let Ok(m) = std::fs::symlink_metadata(&chemin) else {
                continue;
            };
            if m.is_dir() {
                if !exclus.contains(&chemin)
                    && let Ok(sous) = std::fs::read_dir(&chemin)
                {
                    a_voir.push(sous);
                }
            } else if limite.is_none_or(|(l, lecture)| {
                let date = if lecture { m.accessed() } else { m.modified() };
                date.or_else(|_| m.modified()).is_ok_and(|d| d < l)
            }) {
                total += m.len();
            }
        }
    }
    Some(total)
}

/// Place libre et taille du volume qui contient `chemin`, en octets.
#[cfg(unix)]
pub fn volume(chemin: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(chemin.as_os_str().as_bytes()).ok()?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY : `c` est une chaîne C valide pendant tout l'appel ; statvfs remplit `s` en entier quand elle réussit
    // (retour 0), et `s` n'est lue qu'après.
    let s = unsafe {
        if libc::statvfs(c.as_ptr(), s.as_mut_ptr()) != 0 {
            return None;
        }
        s.assume_init()
    };
    #[allow(clippy::useless_conversion)] // les types de statvfs changent d'un système à l'autre
    let bloc = u64::from(s.f_frsize);
    #[allow(clippy::useless_conversion)]
    Some((u64::from(s.f_bavail) * bloc, u64::from(s.f_blocks) * bloc))
}

/// Place libre et taille du volume du système (pour l'afficher), puis la place libre de tous les volumes que le
/// nettoyage touche (pour mesurer le gain).
fn place() -> Option<(u64, u64, u64)> {
    systeme::place()
}

fn ligne_place(libre: u64, total: u64) -> String {
    let occupe = total.saturating_sub(libre).saturating_mul(100) / total.max(1);
    trf!(
        "  {GRIS}Disque du système : {} libres sur {} (occupé à {occupe} %).{RESET}",
        "  {GRIS}System disk: {} free of {} ({occupe}% used).{RESET}",
        taille_lisible(libre),
        taille_lisible(total)
    )
}

fn precision(e: &Element) -> String {
    match e.taille {
        _ if e.propre() => tr!("déjà propre", "already clean").into(),
        Some(t) => taille_lisible(t),
        None => tr!("mesuré après", "measured after").into(),
    }
}

fn detail(e: &Element) -> String {
    match e.prudence {
        Some(p) => format!("{} ⚠ {p}", e.effet),
        None => e.effet.clone(),
    }
}

fn mesurer() -> Vec<Element> {
    trp!(
        "  {GRIS}Mesure de la place à libérer…{RESET}",
        "  {GRIS}Measuring the space to free…{RESET}"
    );
    systeme::elements()
}

/// « sentinel nettoyer » : liste à cocher, puis nettoyage après accord et bilan de la place gagnée.
pub fn menu() {
    let elements = mesurer();
    let avant = place();
    let mut entete = vec![
        String::new(),
        ligne_titre(tr!("Nettoyer le système", "Clean up the system")),
    ];
    if let Some((libre, total, _)) = avant {
        entete.push(ligne_place(libre, total));
    }
    entete.push(trf!(
        "  {GRIS}Coché d'office : ce qui se refait seul. Rien de personnel n'est touché.{RESET}",
        "  {GRIS}Checked by default: what rebuilds itself. Nothing personal is touched.{RESET}"
    ));
    entete.push(String::new());
    let cases: Vec<Case> = elements
        .iter()
        .map(|e| Case {
            texte: e.titre.to_string(),
            precision: precision(e),
            detail: detail(e),
            cochee: e.recommande && !e.propre(),
            recommandee: e.recommande,
            fixe: e.propre(),
        })
        .collect();
    let Some(voulu) = cocher(&entete, &cases) else {
        return;
    };
    let choisis: Vec<&Element> = elements
        .iter()
        .zip(&voulu)
        .filter(|(e, v)| **v && !e.propre())
        .map(|(e, _)| e)
        .collect();
    if choisis.is_empty() {
        trp!("  {GRIS}Rien à nettoyer.{RESET}", "  {GRIS}Nothing to clean.{RESET}");
        return;
    }
    trp!("\n  {GRAS}À nettoyer{RESET}", "\n  {GRAS}To clean{RESET}");
    for e in &choisis {
        println!("    {VERT}−{RESET} {}  {GRIS}{}{RESET}", e.titre, precision(e));
        for c in &e.commandes {
            println!("        {GRIS}{c}{RESET}");
        }
        if let Some(p) = e.prudence {
            println!("        ⚠ {p}");
        }
    }
    let connu: u64 = choisis.iter().filter_map(|e| e.taille).sum();
    if connu >= PRESQUE_RIEN {
        trp!(
            "\n  Au moins {} à libérer.",
            "\n  At least {} to free.",
            taille_lisible(connu)
        );
    }
    if !demander(tr!("\n  Nettoyer ? [o/N] : ", "\n  Clean up? [y/N]: ")).oui() {
        trp!("  Annulé.", "  Cancelled.");
        return;
    }
    let resultats = systeme::executer(&choisis);
    println!();
    for (e, ok) in choisis.iter().zip(&resultats) {
        if *ok {
            println!("  {VERT}✔{RESET} {}", e.titre);
        } else {
            trp!(
                "  ✖ {} : pas fait en entier, voir le message ci-dessus",
                "  ✖ {}: not fully done, see the message above",
                e.titre
            );
        }
    }
    // Ce qui a vraiment été gagné : la place libre relue, pas la somme des estimations.
    if let (Some((_, _, avant_cumul)), Some((libre, total, apres_cumul))) = (avant, place()) {
        let gagne = apres_cumul.saturating_sub(avant_cumul);
        trp!(
            "\n  {VERT}Place libérée : {}.{RESET}",
            "\n  {VERT}Space freed: {}.{RESET}",
            taille_lisible(gagne)
        );
        println!("{}", ligne_place(libre, total));
    }
}

/// « sentinel nettoyer --liste » : ce qui pourrait être nettoyé et la place à gagner, sans rien effacer.
pub fn liste() {
    let elements = mesurer();
    titre(tr!("Nettoyer le système", "Clean up the system"));
    if let Some((libre, total, _)) = place() {
        println!("{}", ligne_place(libre, total));
    }
    println!();
    for e in &elements {
        let marque = if e.propre() {
            format!("{VERT}✔{RESET}")
        } else if e.recommande {
            "+".to_string()
        } else {
            "·".to_string()
        };
        println!("    {marque} {}{GRIS}{}{RESET}", ajuster(e.titre, 40), precision(e));
    }
    let somme = |reco: bool| -> u64 {
        elements
            .iter()
            .filter(|e| !e.propre() && (e.recommande || !reco))
            .filter_map(|e| e.taille)
            .sum()
    };
    trp!(
        "\n  « + » : coché d'office, au moins {} à libérer ({} avec le reste). Rien n'a été effacé.",
        "\n  “+”: checked by default, at least {} to free ({} with the rest). Nothing was deleted.",
        taille_lisible(somme(true)),
        taille_lisible(somme(false))
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailles_lisibles() {
        assert!(taille_lisible(0).contains('1'));
        assert_eq!(taille_lisible(340 << 20), trf!("340 Mo", "340 MB"));
        assert_eq!(taille_lisible((3 << 30) / 2), trf!("1.5 Go", "1.5 GB"));
    }

    #[test]
    fn taille_d_un_dossier_avec_exclusions() {
        let racine = std::env::temp_dir().join(format!("sentinel-nettoyer-{}", std::process::id()));
        let garde = racine.join("garde");
        std::fs::create_dir_all(&garde).unwrap();
        std::fs::create_dir_all(racine.join("sous")).unwrap();
        std::fs::write(racine.join("a"), vec![0u8; 1000]).unwrap();
        std::fs::write(racine.join("sous/b"), vec![0u8; 500]).unwrap();
        std::fs::write(garde.join("c"), vec![0u8; 7000]).unwrap();
        assert_eq!(taille_dossier(&racine, Age::Tout, &[]), Some(8500));
        assert_eq!(
            taille_dossier(&racine, Age::Tout, std::slice::from_ref(&garde)),
            Some(1500)
        );
        // Rien d'assez vieux : des fichiers écrits à l'instant.
        assert_eq!(taille_dossier(&racine, Age::NonModifieDepuis(7), &[]), Some(0));
        assert_eq!(taille_dossier(&racine.join("absent"), Age::Tout, &[]), None);
        std::fs::remove_dir_all(&racine).unwrap();
    }

    #[test]
    fn chaque_element_tient_dans_la_liste() {
        for e in systeme::elements() {
            assert!(largeur_affichee(e.titre) <= 38, "{} : titre trop long", e.titre);
            assert!(!e.effet.is_empty() && !e.commandes.is_empty(), "{}", e.titre);
            assert!(largeur_affichee(&precision(&e)) <= 33);
            assert!(
                envelopper(&detail(&e), LARGEUR - 4).len() <= 3,
                "{} : explication trop longue",
                e.titre
            );
        }
    }
}
