//! Les commandes de tldr-pages (tldr.sh, licence CC BY 4.0) : des milliers d'exemples pour Linux, Windows, macOS et
//! d'autres systèmes, écrits et tenus à jour par une communauté. Vanguard télécharge leurs archives (anglais et
//! français) au plus une fois par semaine, en arrière-plan quand le guide s'ouvre, et les lit sans rien exécuter : ces
//! commandes se copient, elles ne se lancent jamais d'ici, Vanguard ne les ayant pas vérifiées
//! (`Obstacle::NonVerifiee`). Tout texte de l'archive passe par `ui::affichable` : une page piégée ne pilote pas le
//! terminal.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use super::{Commande, Obstacle, Programme, Systeme};
use crate::ui::affichable;

/// Les archives de tldr-pages : le projet les refait chaque jour, sous une page de version au numéro inchangé.
const ADRESSE: &str = "https://github.com/tldr-pages/tldr/releases/latest/download/";

/// L'anglais a toutes les pages ; le français, une partie, qui passe devant quand l'interface est en français.
const LANGUES: [&str; 2] = ["en", "fr"];

/// Âge au-delà duquel une archive se télécharge à nouveau.
const UNE_SEMAINE: Duration = Duration::from_hours(7 * 24);

/// Limites contre une archive démesurée ou piégée : taille téléchargée, taille d'une page, taille et nombre de pages.
const TAILLE_ARCHIVE: u64 = 40 << 20;
const TAILLE_PAGE: usize = 256 << 10;
const TAILLE_TOTALE: usize = 64 << 20;
const PAGES_MAX: usize = 50_000;

/// Une page de tldr-pages : son système, sous lequel elle s'affiche, et la plateforme dont elle vient (« linux »).
pub(super) struct PageTldr {
    pub systeme: Systeme,
    pub plateforme: &'static str,
    pub programme: Programme,
}

fn dossier() -> PathBuf {
    crate::reseau::dossier_local().join("tldr")
}

fn archive(langue: &str) -> PathBuf {
    dossier().join(format!("tldr-pages.{langue}.zip"))
}

/// La date de l'archive la plus récente ; `None` : aucune encore.
fn date_des_archives() -> Option<SystemTime> {
    LANGUES
        .iter()
        .filter_map(|l| std::fs::metadata(archive(l)).and_then(|m| m.modified()).ok())
        .max()
}

/// Une langue dont l'archive manque, ou a plus d'une semaine : à retélécharger. Une langue dont l'archive est fraîche
/// n'est pas reprise parce qu'une autre a échoué (le français, partiel, peut manquer sans que l'anglais le soit).
fn a_renouveler(langue: &str) -> bool {
    std::fs::metadata(archive(langue))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|date| date.elapsed().ok())
        .is_none_or(|age| age > UNE_SEMAINE)
}

/// Le téléchargement d'arrière-plan tourne déjà.
static EN_COURS: AtomicBool = AtomicBool::new(false);

/// Renouvelle les archives qui en ont besoin, en arrière-plan : le guide s'ouvre sans les attendre, et les lit à son
/// prochain affichage. Seulement dans un vrai terminal (pas pour un script ni pour les tests) ; sans Internet, curl
/// échoue vite et rien ne change.
pub(super) fn renouveler_en_fond() {
    use std::io::IsTerminal;
    let a_faire: Vec<&str> = LANGUES.into_iter().filter(|l| a_renouveler(l)).collect();
    if !std::io::stdin().is_terminal() || a_faire.is_empty() || EN_COURS.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(move || {
        // Les restes d'un téléchargement interrompu (Vanguard quitté avant la fin) partent d'abord.
        if let Ok(fichiers) = std::fs::read_dir(dossier()) {
            for f in fichiers.flatten() {
                if f.file_name().to_string_lossy().contains(".zip.") {
                    let _ = std::fs::remove_file(f.path());
                }
            }
        }
        for langue in a_faire {
            telecharger(langue);
        }
        EN_COURS.store(false, Ordering::SeqCst);
    });
}

/// Le téléchargement est-il en cours ?
pub(super) fn en_cours() -> bool {
    EN_COURS.load(Ordering::SeqCst)
}

/// Télécharge une archive à côté de l'ancienne, puis la met à sa place si elle se lit : une page d'erreur ou un
/// fichier tronqué ne remplace jamais la bonne.
fn telecharger(langue: &str) -> bool {
    if std::fs::create_dir_all(dossier()).is_err() {
        return false;
    }
    let fin = archive(langue);
    let provisoire = fin.with_extension(format!("zip.{}", std::process::id()));
    let recu = crate::commande::lancer(
        std::process::Command::new("curl")
            .args([
                "-fsSL",
                "--max-time",
                "120",
                "--max-filesize",
                &TAILLE_ARCHIVE.to_string(),
                "-o",
            ])
            .arg(&provisoire)
            .arg(format!("{ADRESSE}tldr-pages.{langue}.zip")),
        130,
    )
    .is_some_and(|r| r.code == Some(0));
    let lisible = recu && std::fs::read(&provisoire).is_ok_and(|octets| !lire_zip(&octets).is_empty());
    if lisible && std::fs::rename(&provisoire, &fin).is_ok() {
        return true;
    }
    let _ = std::fs::remove_file(&provisoire);
    false
}

/// Les fichiers d'une archive zip : (nom, contenu). Seulement ce que tldr-pages y met : des fichiers stockés tels quels
/// ou compressés (deflate), sans zip64. Une entrée illisible ou hors limites est sautée ; une archive illisible donne
/// une liste vide.
pub(super) fn lire_zip(octets: &[u8]) -> Vec<(String, Vec<u8>)> {
    // La fin du répertoire central, cherchée depuis la fin (un commentaire peut la suivre).
    let Some(fin) = (0..octets.len().saturating_sub(21))
        .rev()
        .take(65_557)
        .find(|&i| u32_a(octets, i) == Some(0x0605_4b50))
    else {
        return Vec::new();
    };
    let (Some(nombre), Some(debut)) = (u16_a(octets, fin + 10), u32_a(octets, fin + 16)) else {
        return Vec::new();
    };
    let mut fichiers = Vec::new();
    let mut total = 0;
    let mut i = debut as usize;
    for _ in 0..usize::from(nombre).min(PAGES_MAX) {
        if u32_a(octets, i) != Some(0x0201_4b50) {
            break;
        }
        let Some((methode, compresse, taille, longueur_nom, autres, local)) = entree_centrale(octets, i) else {
            break;
        };
        let nom = octets
            .get(i + 46..i + 46 + longueur_nom)
            .map(|n| String::from_utf8_lossy(n).into_owned());
        i += 46 + longueur_nom + autres;
        let Some(nom) = nom else { break };
        if taille > TAILLE_PAGE || total + taille > TAILLE_TOTALE {
            continue;
        }
        let donnees = donnees_locales(octets, local, compresse);
        let contenu = match (methode, donnees) {
            (0, Some(d)) if d.len() == taille => Some(d.to_vec()),
            (8, Some(d)) => miniz_oxide::inflate::decompress_to_vec_with_limit(d, TAILLE_PAGE).ok(),
            _ => None,
        };
        if let Some(contenu) = contenu {
            total += contenu.len();
            fichiers.push((nom, contenu));
        }
    }
    fichiers
}

fn u16_a(octets: &[u8], i: usize) -> Option<u16> {
    octets.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_a(octets: &[u8], i: usize) -> Option<u32> {
    octets
        .get(i..i + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Une entrée du répertoire central : (méthode, taille compressée, taille, longueur du nom, longueur des champs qui
/// suivent le nom, position de l'en-tête local).
fn entree_centrale(octets: &[u8], i: usize) -> Option<(u16, usize, usize, usize, usize, usize)> {
    Some((
        u16_a(octets, i + 10)?,
        u32_a(octets, i + 20)? as usize,
        u32_a(octets, i + 24)? as usize,
        usize::from(u16_a(octets, i + 28)?),
        usize::from(u16_a(octets, i + 30)?) + usize::from(u16_a(octets, i + 32)?),
        u32_a(octets, i + 42)? as usize,
    ))
}

/// Les données d'un fichier, après son en-tête local.
fn donnees_locales(octets: &[u8], local: usize, compresse: usize) -> Option<&[u8]> {
    (u32_a(octets, local)? == 0x0403_4b50).then_some(())?;
    let depart = local + 30 + usize::from(u16_a(octets, local + 26)?) + usize::from(u16_a(octets, local + 28)?);
    octets.get(depart..depart.checked_add(compresse)?)
}

/// « {{chemin/du/fichier}} » devient « <chemin/du/fichier> », comme les mots à remplacer du guide ; un choix d'option
/// (« {{[-r|--recursive]}} ») garde sa forme longue.
fn remplacer_les_espaces_reserves(commande: &str) -> String {
    let mut sortie = String::with_capacity(commande.len());
    let mut reste = commande;
    while let Some(debut) = reste.find("{{") {
        sortie.push_str(&reste[..debut]);
        let Some(fin) = reste[debut..].find("}}") else {
            sortie.push_str(&reste[debut..]);
            return sortie;
        };
        let dedans = &reste[debut + 2..debut + fin];
        match dedans.strip_prefix('[').and_then(|d| d.strip_suffix(']')) {
            Some(choix) if choix.contains('|') => sortie.push_str(choix.rsplit('|').next().unwrap_or(choix)),
            _ => {
                sortie.push('<');
                sortie.push_str(dedans);
                sortie.push('>');
            }
        }
        reste = &reste[debut + fin + 2..];
    }
    sortie.push_str(reste);
    sortie
}

/// Une page de tldr-pages, lue : son titre, sa description, ses exemples (explication, commande).
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PageLue {
    titre: String,
    description: String,
    exemples: Vec<(String, String)>,
}

/// Une page au format de tldr-pages : son titre (« # tar »), sa description (lignes « > »), puis ses exemples (« - ce
/// que ça fait : » suivi de « `la commande` »). Les liens et renvois de la description sont laissés.
pub(super) fn lire_page(texte: &str) -> Option<PageLue> {
    let mut titre = None;
    let mut description = Vec::new();
    let mut exemples = Vec::new();
    let mut en_attente: Option<String> = None;
    for ligne in texte.lines().map(str::trim) {
        if let Some(t) = ligne.strip_prefix("# ") {
            titre.get_or_insert_with(|| t.trim().to_string());
        } else if let Some(d) = ligne.strip_prefix('>') {
            let d = d.trim();
            let renvoi = [
                "More information",
                "Plus d'informations",
                "Plus d’informations",
                "See also",
                "Voir aussi",
            ]
            .iter()
            .any(|r| d.starts_with(r))
                || d.contains("<http");
            if !renvoi && !d.is_empty() {
                description.push(d.to_string());
            }
        } else if let Some(e) = ligne.strip_prefix("- ") {
            en_attente = Some(e.trim().trim_end_matches(':').trim().to_string());
        } else if let Some(c) = ligne.strip_prefix('`').and_then(|c| c.strip_suffix('`'))
            && let Some(explication) = en_attente.take()
        {
            exemples.push((explication, remplacer_les_espaces_reserves(c)));
        }
    }
    let titre = titre?;
    (!exemples.is_empty()).then(|| PageLue {
        titre,
        description: description.join(" "),
        exemples,
    })
}

/// Le système du guide d'une plateforme de tldr-pages, et son nom à l'écran.
fn systeme_de(plateforme: &str) -> (Systeme, &'static str) {
    match plateforme {
        "common" => (Systeme::Tous, crate::tr!("tous", "all")),
        "linux" => (Systeme::Linux, "linux"),
        "osx" => (Systeme::MacOs, "macOS"),
        "windows" => (Systeme::Windows, "windows"),
        "android" => (Systeme::Tldr, "android"),
        "freebsd" => (Systeme::Tldr, "freebsd"),
        "openbsd" => (Systeme::Tldr, "openbsd"),
        "netbsd" => (Systeme::Tldr, "netbsd"),
        "sunos" => (Systeme::Tldr, "sunos"),
        "dos" => (Systeme::Tldr, "dos"),
        _ => (Systeme::Tldr, "autre"),
    }
}

/// Un texte de l'archive gardé pour toute la session : les pages se chargent une fois (et à nouveau seulement après
/// un téléchargement), et le guide les manie comme ses propres programmes, aux textes « 'static ».
fn garder(texte: &str) -> &'static str {
    affichable(texte).leak()
}

/// Les pages des archives téléchargées, dans la langue de l'interface (l'anglais quand une page n'est pas traduite),
/// rangées par plateforme puis par nom.
fn charger() -> &'static [PageTldr] {
    // Par (rang de la plateforme, « plateforme/nom ») : la plateforme, et la page.
    let mut pages: BTreeMap<(u8, String), (String, PageLue)> = BTreeMap::new();
    let ordre = |plateforme: &str| match plateforme {
        "linux" => 0,
        "common" => 1,
        "windows" => 2,
        "osx" => 3,
        _ => 4,
    };
    let langues: &[&str] = if crate::langue::anglais() { &["en"] } else { &LANGUES };
    for langue in langues {
        let Ok(octets) = std::fs::read(archive(langue)) else {
            continue;
        };
        for (nom, contenu) in lire_zip(&octets) {
            let Some((plateforme, fichier)) = nom.split_once('/') else {
                continue;
            };
            let Some(base) = fichier.strip_suffix(".md") else {
                continue;
            };
            if let Some(page) = lire_page(&String::from_utf8_lossy(&contenu)) {
                // Le français, lu après l'anglais, prend sa place.
                pages.insert(
                    (ordre(plateforme), format!("{plateforme}/{base}")),
                    (plateforme.to_string(), page),
                );
            }
        }
    }
    let pages: Vec<PageTldr> = pages
        .into_values()
        .map(
            |(
                plateforme,
                PageLue {
                    titre,
                    description,
                    exemples,
                },
            )| {
                let (systeme, plateforme) = systeme_de(&plateforme);
                let description = garder(&description);
                let commandes: Vec<Commande> = exemples
                    .iter()
                    .map(|(explication, commande)| {
                        let explication = garder(explication);
                        Commande {
                            ligne: garder(commande),
                            ligne_en: "",
                            texte: (explication, explication),
                            modifie: false,
                            obstacle: Obstacle::NonVerifiee,
                        }
                    })
                    .collect();
                let executable = titre.split_whitespace().next().unwrap_or_default();
                PageTldr {
                    systeme,
                    plateforme,
                    programme: Programme {
                        nom: garder(&titre),
                        role: (description, description),
                        executable: garder(executable),
                        commandes: commandes.leak(),
                    },
                }
            },
        )
        .collect();
    pages.leak()
}

/// Les pages chargées, et la date des archives d'où elles viennent.
static CHARGEES: Mutex<Option<(Option<SystemTime>, &'static [PageTldr])>> = Mutex::new(None);

/// Les pages de tldr-pages, chargées à la première demande, et à nouveau quand une archive plus récente arrive.
/// Vide tant que rien n'est téléchargé.
pub(super) fn pages() -> &'static [PageTldr] {
    let date = date_des_archives();
    let mut chargees = CHARGEES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((quand, pages)) = *chargees
        && quand == date
    {
        return pages;
    }
    let pages = if date.is_some() { charger() } else { &[] };
    *chargees = Some((date, pages));
    pages
}

/// La plateforme d'un programme de tldr-pages (« linux »), ou `None` pour un programme du guide.
pub(super) fn plateforme(p: &Programme) -> Option<&'static str> {
    pages()
        .iter()
        .find(|page| std::ptr::eq(std::ptr::from_ref(&page.programme), p))
        .map(|page| page.plateforme)
}

/// La date des archives en clair (« 19/10/2026 »), pour dire à quel point les commandes sont fraîches.
pub(super) fn date_en_clair() -> Option<String> {
    let date: chrono::DateTime<chrono::Local> = date_des_archives()?.into();
    Some(date.format(crate::tr!("%d/%m/%Y", "%Y-%m-%d")).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une archive zip faite à la main : chaque fichier stocké tel quel, ou compressé (deflate).
    fn zip(fichiers: &[(&str, &str, bool)]) -> Vec<u8> {
        let mut octets = Vec::new();
        let mut central = Vec::new();
        for (nom, contenu, compresse) in fichiers {
            let donnees = if *compresse {
                miniz_oxide::deflate::compress_to_vec(contenu.as_bytes(), 6)
            } else {
                contenu.as_bytes().to_vec()
            };
            let methode: u16 = if *compresse { 8 } else { 0 };
            let local = u32::try_from(octets.len()).unwrap();
            let entete = |sig: u32, central: bool| {
                let mut e = sig.to_le_bytes().to_vec();
                if central {
                    e.extend([20, 0]);
                }
                e.extend([20, 0, 0, 0]);
                e.extend(methode.to_le_bytes());
                e.extend([0, 0, 0, 0, 0, 0, 0, 0]);
                e.extend(u32::try_from(donnees.len()).unwrap().to_le_bytes());
                e.extend(u32::try_from(contenu.len()).unwrap().to_le_bytes());
                e.extend(u16::try_from(nom.len()).unwrap().to_le_bytes());
                e.extend([0, 0]);
                if central {
                    e.extend([0; 10]);
                    e.extend(local.to_le_bytes());
                }
                e.extend(nom.as_bytes());
                e
            };
            octets.extend(entete(0x0403_4b50, false));
            octets.extend(&donnees);
            central.extend(entete(0x0201_4b50, true));
        }
        let debut = u32::try_from(octets.len()).unwrap();
        let taille = u32::try_from(central.len()).unwrap();
        octets.extend(&central);
        let n = u16::try_from(fichiers.len()).unwrap();
        octets.extend(0x0605_4b50u32.to_le_bytes());
        octets.extend([0, 0, 0, 0]);
        octets.extend(n.to_le_bytes());
        octets.extend(n.to_le_bytes());
        octets.extend(taille.to_le_bytes());
        octets.extend(debut.to_le_bytes());
        octets.extend([0, 0]);
        octets
    }

    #[test]
    fn une_archive_se_lit_stockee_ou_compressee() {
        let a = zip(&[("linux/a.md", "# a\n", false), ("common/b.md", &"x".repeat(5000), true)]);
        let fichiers = lire_zip(&a);
        assert_eq!(fichiers.len(), 2);
        assert_eq!(fichiers[0], ("linux/a.md".to_string(), b"# a\n".to_vec()));
        assert_eq!(fichiers[1].1.len(), 5000);
        // Rien de lisible : une page d'erreur, une archive tronquée, du vide.
        assert_eq!(lire_zip(b"<html>Not Found</html>"), []);
        assert_eq!(lire_zip(&a[..a.len() / 2]), []);
        assert_eq!(lire_zip(&[]), []);
        // Une page trop grosse est sautée, les autres restent.
        let grosse = zip(&[
            ("common/c.md", &"y".repeat(TAILLE_PAGE + 1), true),
            ("linux/a.md", "# a\n", false),
        ]);
        assert_eq!(lire_zip(&grosse).len(), 1);
    }

    #[test]
    fn une_page_donne_titre_description_et_exemples() {
        let page = "# tar\n\n> Utilitaire d'archivage.\n> Souvent combiné avec gzip.\n> Plus d'informations : <https://www.gnu.org/software/tar>.\n\n- Crée une archive :\n\n`tar cf {{chemin/vers/cible.tar}} {{fichier1 fichier2}}`\n\n- Extrait en détaillant :\n\n`tar {{[-x|--extract]}} {{[-v|--verbose]}} -f {{archive.tar}}`\n";
        let PageLue {
            titre,
            description,
            exemples,
        } = lire_page(page).unwrap();
        assert_eq!(titre, "tar");
        assert_eq!(description, "Utilitaire d'archivage. Souvent combiné avec gzip.");
        assert_eq!(
            exemples,
            [
                (
                    "Crée une archive".to_string(),
                    "tar cf <chemin/vers/cible.tar> <fichier1 fichier2>".to_string()
                ),
                (
                    "Extrait en détaillant".to_string(),
                    "tar --extract --verbose -f <archive.tar>".to_string()
                ),
            ]
        );
        assert_eq!(lire_page("pas une page"), None);
        assert_eq!(lire_page("# vide\n> Rien à montrer.\n"), None);
        assert_eq!(remplacer_les_espaces_reserves("a {{b"), "a {{b");
    }

    #[test]
    fn plateformes_rangees_dans_le_guide() {
        assert_eq!(systeme_de("linux").0, Systeme::Linux);
        assert_eq!(systeme_de("osx").0, Systeme::MacOs);
        assert_eq!(systeme_de("windows").0, Systeme::Windows);
        assert_eq!(systeme_de("common").0, Systeme::Tous);
        assert_eq!(systeme_de("android").0, Systeme::Tldr);
    }

    /// Sans archive (le dossier des tests est jetable), le guide n'a aucune page de tldr-pages.
    #[test]
    fn sans_archive_aucune_page() {
        assert_eq!(pages().len(), 0);
        assert!(date_en_clair().is_none());
    }
}

/// Archives au hasard : jamais de plantage, jamais plus que les limites.
#[cfg(test)]
mod tests_au_hasard {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn une_archive_piegee_ne_fait_rien_planter(octets in prop::collection::vec(any::<u8>(), 0..2048), page in "\\PC{0,400}") {
            for (_, contenu) in lire_zip(&octets) {
                prop_assert!(contenu.len() <= TAILLE_PAGE);
            }
            let _ = lire_page(&page);
            let _ = remplacer_les_espaces_reserves(&page);
        }
    }
}
