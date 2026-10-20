//! Analyse YARA : 308 règles de ReversingLabs (rançongiciels, voleurs de mots de passe, chevaux de Troie, portes
//! dérobées…), intégrées au programme (assets/yara, outils/maj-yara.sh ; allégées par build.rs, de 2,7 Mo à 1,2 Mo,
//! sans en changer le sens) et appliquées par YARA-X, le moteur YARA écrit en Rust par VirusTotal (licence
//! BSD-3-Clause), compilé dans Vanguard : rien à installer, depuis la clé et sans Internet comme ailleurs. En
//! complément de l'antivirus : une règle décrit une famille entière, variantes comprises. Lecture seule : rien n'est
//! déplacé ni supprimé.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use crate::protection::antivirus::{Examen, Portee};
use crate::ui::*;

const REGLES: &str = include_str!(concat!(env!("OUT_DIR"), "/reversinglabs.yara"));

/// Les fichiers plus gros ne sont pas lus (images disque, vidéos), mais dits : aucun des programmes que visent les
/// règles n'en approche, et les lire prendrait de longues minutes.
const TAILLE_MAX: u64 = 256 << 20;

/// Le temps laissé à chaque fichier, et le nombre de fichiers analysés ensemble.
const DELAI_PAR_FICHIER: Duration = Duration::from_secs(30);
const FILS: usize = 4;

/// Les règles, compilées une fois par lancement (une seconde et demie) ; les analyses suivantes les reprennent.
/// `Err` : elles ne se compilent pas, ce qu'un test empêche d'arriver jusqu'à une version livrée.
fn regles() -> Result<&'static yara_x::Rules, &'static str> {
    static COMPILEES: OnceLock<Result<yara_x::Rules, String>> = OnceLock::new();
    COMPILEES
        .get_or_init(|| {
            let mut compilateur = yara_x::Compiler::new();
            compilateur.add_source(REGLES).map_err(|e| e.to_string())?;
            Ok(compilateur.build())
        })
        .as_ref()
        .map_err(String::as_str)
}

/// Les endroits à risque : téléchargements, bureau, programmes lancés au démarrage (et le dossier temporaire sous
/// Windows, où atterrissent les programmes téléchargés).
pub(crate) fn endroits_a_risque() -> Vec<PathBuf> {
    let maison = PathBuf::from(
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .unwrap_or_default(),
    );
    #[cfg(windows)]
    let mut liste: Vec<PathBuf> = ["Downloads", "Desktop"].iter().map(|d| maison.join(d)).collect();
    #[cfg(windows)]
    liste.extend(
        [
            std::env::var_os("APPDATA")
                .map(|a| PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup")),
            std::env::var_os("TEMP").map(PathBuf::from),
        ]
        .into_iter()
        .flatten(),
    );
    #[cfg(unix)]
    let liste: Vec<PathBuf> = crate::protection::antivirus::ENDROITS_A_RISQUE
        .iter()
        .map(|d| maison.join(d))
        .collect();
    liste.into_iter().filter(|p| p.is_dir()).collect()
}

/// Une correspondance : la règle (« Win32_Ransomware_WannaCry ») et le fichier.
#[derive(Debug, PartialEq)]
struct Trouve {
    regle: String,
    /// Prêt à montrer.
    fichier: String,
    /// Tel quel, pour l'isoler.
    chemin: PathBuf,
}

impl Trouve {
    /// Le chemin, seulement montré, est rendu inoffensif : son nom est celui qu'a choisi l'auteur du fichier.
    fn nouveau(regle: &str, chemin: &Path) -> Trouve {
        Trouve {
            regle: regle.to_string(),
            fichier: affichable(&chemin.display().to_string()),
            chemin: chemin.to_path_buf(),
        }
    }
}

/// Les fichiers d'une cible, sans suivre les liens (pas de boucle, rien hors des dossiers choisis) ; les dossiers
/// illisibles s'ajoutent à `illisibles`, et les fichiers de plus de `TAILLE_MAX`, qui ne sont pas lus : ce qui n'a pas
/// été vérifié est dit.
fn fichiers(cible: &Path, illisibles: &mut Vec<PathBuf>) -> Vec<PathBuf> {
    let mut trouves = Vec::new();
    let mut a_voir = vec![cible.to_path_buf()];
    while let Some(chemin) = a_voir.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&chemin) else {
            illisibles.push(chemin);
            continue;
        };
        if meta.is_file() {
            if meta.len() <= TAILLE_MAX {
                trouves.push(chemin);
            } else {
                illisibles.push(chemin);
            }
        } else if meta.is_dir() {
            match std::fs::read_dir(&chemin) {
                Ok(entrees) => a_voir.extend(entrees.flatten().map(|e| e.path())),
                Err(_) => illisibles.push(chemin),
            }
        }
    }
    trouves
}

/// Les règles appliquées à des fichiers, par `FILS` fils, chacun avec son propre analyseur : (correspondances,
/// fichiers illisibles ou trop longs à lire).
fn analyser_fichiers(regles: &yara_x::Rules, liste: &[PathBuf]) -> (Vec<Trouve>, Vec<PathBuf>) {
    let morceaux: Vec<&[PathBuf]> = liste.chunks(liste.len().div_ceil(FILS).max(1)).collect();
    std::thread::scope(|s| {
        let fils: Vec<_> = morceaux
            .into_iter()
            .map(|morceau| {
                s.spawn(move || {
                    let mut analyseur = yara_x::Scanner::new(regles);
                    analyseur.set_timeout(DELAI_PAR_FICHIER);
                    let (mut trouves, mut echecs) = (Vec::new(), Vec::new());
                    for f in morceau {
                        match analyseur.scan_file(f) {
                            Ok(r) => trouves.extend(r.matching_rules().map(|m| Trouve::nouveau(m.identifier(), f))),
                            Err(_) => echecs.push(f.clone()),
                        }
                    }
                    (trouves, echecs)
                })
            })
            .collect();
        fils.into_iter()
            .filter_map(|f| f.join().ok())
            .fold((Vec::new(), Vec::new()), |(mut t, mut e), (t2, e2)| {
                t.extend(t2);
                e.extend(e2);
                (t, e)
            })
    })
}

/// Ce qui n'a pas pu être lu dans une cible, en une phrase : le nombre, et le premier pour exemple.
fn illisible(cible: &Path, echecs: &[PathBuf]) -> Option<String> {
    let premier = echecs.first()?;
    Some(trf!(
        "{} : {} élément(s) illisible(s), trop gros ou trop long(s) à lire, dont {}",
        "{}: {} item(s) unreadable, too large or too slow to read, including {}",
        chemin_affichable(cible),
        echecs.len(),
        chemin_affichable(premier)
    ))
}

/// La famille d'une règle de ReversingLabs, lue dans son nom (« ByteCode_MSIL_Ransomware_Apis »).
fn famille(regle: &str) -> &'static str {
    for morceau in regle.split('_') {
        let nom = match morceau {
            "Ransomware" => tr!("rançongiciel", "ransomware"),
            "Infostealer" => tr!("voleur de mots de passe", "password stealer"),
            "Trojan" => tr!("cheval de Troie", "trojan"),
            "Backdoor" => tr!("porte dérobée", "backdoor"),
            "Downloader" => tr!("téléchargeur de logiciels malveillants", "malware downloader"),
            "Exploit" => tr!("exploit d'une faille", "exploit"),
            "Rootkit" => tr!("rootkit", "rootkit"),
            "Virus" => tr!("virus", "virus"),
            _ => continue,
        };
        return nom;
    }
    tr!("logiciel malveillant", "malware")
}

/// Applique les 308 règles aux cibles : (correspondances, ce qui n'a pas pu être lu). `None` : règles qui ne se
/// compilent pas, ce qui est dit. Tout ce qui n'a pas pu être lu est rendu : jamais compté comme sain.
fn appliquer(cibles: &[PathBuf]) -> Option<(Vec<Trouve>, Vec<String>)> {
    let regles = match regles() {
        Ok(r) => r,
        Err(e) => {
            println!(
                "  ✖ {}",
                trf!(
                    "Règles YARA impossibles à compiler : {e}",
                    "YARA rules could not be compiled: {e}"
                )
            );
            return None;
        }
    };
    let mut trouves = Vec::new();
    let mut erreurs = Vec::new();
    for cible in cibles {
        trp!("  Analyse de {}…", "  Scanning {}…", chemin_affichable(cible));
        let mut echecs = Vec::new();
        let liste = fichiers(cible, &mut echecs);
        let (t, e) = analyser_fichiers(regles, &liste);
        trouves.extend(t);
        echecs.extend(e);
        erreurs.extend(illisible(cible, &echecs));
    }
    Some((trouves, erreurs))
}

pub fn analyser(portee: &Portee) {
    titre(tr!("Analyse YARA", "YARA scan"));
    let cibles = match portee {
        Portee::Dossier(d) => vec![d.clone()],
        Portee::Complete => vec![PathBuf::from(
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .unwrap_or_default(),
        )],
        Portee::Rapide => endroits_a_risque(),
    };
    if cibles.is_empty() {
        trp!("  Rien à analyser ici.", "  Nothing to scan here.");
        return;
    }
    let Some((trouves, erreurs)) = appliquer(&cibles) else {
        return;
    };
    println!();
    for e in &erreurs {
        for (i, ligne) in envelopper(
            &trf!(
                "Analyse incomplète, rien n'est conclu pour ce qui n'a pas été lu. {e}",
                "Incomplete scan, nothing is concluded for what was not read. {e}"
            ),
            LARGEUR - 4,
        )
        .iter()
        .enumerate()
        {
            println!("  {} {ligne}", if i == 0 { "⚠" } else { " " });
        }
    }
    if trouves.is_empty() {
        if erreurs.is_empty() {
            trp!(
                "  {VERT}✔{RESET} Aucun fichier ne correspond aux 308 règles.",
                "  {VERT}✔{RESET} No file matches the 308 rules."
            );
        }
        return;
    }
    for t in &trouves {
        println!("  {}✖{RESET} {}", couleur(crate::risk::Niveau::Eleve), t.fichier);
        println!("      {GRIS}{} ({}){RESET}", famille(&t.regle), t.regle);
    }
    println!();
    for ligne in envelopper(
        tr!(
            "Ne les ouvre pas. Fais-les aussi analyser par l'antivirus (même menu). Une règle peut se tromper sur un fichier légitime : la quarantaine se défait, et en cas de doute, envoie-le à VirusTotal.",
            "Do not open them. Have the antivirus scan them too (same menu). A rule can be wrong about a legitimate file: the quarantine can be undone, and when in doubt, upload it to VirusTotal."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    let mut a_isoler: Vec<(PathBuf, String)> = Vec::new();
    for t in &trouves {
        if t.chemin.is_file() && !a_isoler.iter().any(|(c, _)| *c == t.chemin) {
            a_isoler.push((t.chemin.clone(), format!("YARA {}", t.regle)));
        }
    }
    crate::protection::quarantaine::proposer(&a_isoler);
}

/// Un seul fichier, pour « Vérifier un fichier téléchargé » : le résultat, que l'appelant affiche.
pub(crate) fn examiner(fichier: &Path) -> Examen {
    match appliquer(&[fichier.to_path_buf()]) {
        None => Examen::Impossible(tr!("règles YARA inutilisables", "YARA rules unusable").into()),
        Some((trouves, _)) if !trouves.is_empty() => Examen::Trouve(
            trouves
                .iter()
                .map(|t| format!("{} ({})", famille(&t.regle), t.regle))
                .collect(),
        ),
        Some((_, erreurs)) if !erreurs.is_empty() => Examen::Impossible(erreurs.join(" ; ")),
        Some(_) => Examen::Sain,
    }
}

/// Menu Antivirus et protection › Analyse YARA : les endroits à risque, ou le dossier tapé.
pub fn menu() {
    let reponse = demander(tr!(
        "  Dossier à analyser (Entrée : téléchargements, bureau, démarrage) : ",
        "  Folder to scan (Enter: downloads, desktop, startup): "
    ));
    let reponse = reponse.trim().trim_matches(['"', '\'']);
    if reponse.is_empty() {
        analyser(&Portee::Rapide);
    } else {
        analyser(&Portee::Dossier(PathBuf::from(reponse)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regles_integrees() {
        assert!(REGLES.starts_with("// Règles YARA de ReversingLabs"));
        let regles = REGLES
            .lines()
            .filter(|l| l.trim_start().starts_with("rule ") || l.trim_start().starts_with("private rule "))
            .count();
        assert_eq!(regles, 308, "le message « 308 règles » doit suivre outils/maj-yara.sh");
    }

    const ORIGINE: &str = include_str!("../../assets/yara/reversinglabs.yara");

    /// Les noms des règles, dans l'ordre : chaque déclaration commence une ligne (« rule » paraît aussi dans les
    /// descriptions d'origine, « Yara rule that detects… »).
    fn noms(texte: &str) -> Vec<&str> {
        texte
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("rule "))
            .filter_map(|r| r.split([' ', ':']).next())
            .collect()
    }

    /// Chaque chaîne hexadécimale (« = { … } »), sans espaces, chaque saut fixe « [n] » redéveloppé en n « ?? » : la
    /// forme à laquelle l'origine et les règles allégées doivent se ramener.
    fn hexadecimales(texte: &str) -> Vec<String> {
        let mut liste = Vec::new();
        let mut reste = texte;
        while let Some(p) = reste.find('=') {
            reste = &reste[p + 1..];
            let Some(dedans) = reste.trim_start().strip_prefix('{') else {
                continue;
            };
            let fin = dedans.find('}').unwrap();
            let compact: String = dedans[..fin].chars().filter(|c| !c.is_whitespace()).collect();
            let mut forme = String::new();
            let mut morceaux = compact.split('[');
            forme.push_str(morceaux.next().unwrap_or_default());
            for m in morceaux {
                let (saut, apres) = m.split_once(']').unwrap();
                if let Ok(n) = saut.parse::<usize>() {
                    forme.push_str(&"??".repeat(n));
                } else {
                    forme.push('[');
                    forme.push_str(saut);
                    forme.push(']');
                }
                forme.push_str(apres);
            }
            liste.push(forme);
            reste = &dedans[fin..];
        }
        liste
    }

    /// Ce qui suit chaque « condition: », sans espaces, jusqu'à l'accolade qui ferme la règle (avant la règle suivante
    /// et ses imports).
    fn conditions(texte: &str) -> Vec<String> {
        texte
            .split("condition:")
            .skip(1)
            .map(|c| {
                let suite = c.find("\nrule ").unwrap_or(c.len());
                let fin = c[..suite].rfind('}').unwrap_or(suite);
                c[..fin].chars().filter(|x| !x.is_whitespace()).collect()
            })
            .collect()
    }

    #[test]
    fn regles_allegees_sans_changer_de_sens() {
        // Au moins deux fois plus légères : c'est la raison d'être de l'allègement.
        assert!(
            REGLES.len() * 2 < ORIGINE.len(),
            "{} contre {}",
            REGLES.len(),
            ORIGINE.len()
        );
        assert!(!REGLES.contains("meta:"));
        // L'en-tête (source et licence MIT) reste.
        assert!(REGLES.lines().nth(1).is_some_and(|l| l.contains("Licence MIT")));
        assert_eq!(noms(REGLES), noms(ORIGINE));
        let (allegees, origine) = (hexadecimales(REGLES), hexadecimales(ORIGINE));
        assert_eq!(allegees.len(), origine.len());
        for (a, o) in allegees.iter().zip(&origine) {
            assert_eq!(a, o);
        }
        assert_eq!(conditions(REGLES), conditions(ORIGINE));
        // Un module importé une seule fois.
        assert_eq!(REGLES.matches("import \"pe\"").count(), 1);
    }

    #[test]
    fn familles_des_regles() {
        assert_eq!(famille("Win32_Ransomware_WannaCry"), "rançongiciel");
        assert_eq!(famille("ByteCode_MSIL_Infostealer_RedLine"), "voleur de mots de passe");
        assert_eq!(famille("Linux_Inconnu_X"), "logiciel malveillant");
        // Le nom du fichier est celui que son auteur a choisi : piégé, il arrive inoffensif.
        let piege = Trouve::nouveau(
            "X",
            Path::new("/home/alice/fa\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}cture.exe"),
        );
        assert!(!piege.fichier.contains('\x1b') && !piege.fichier.contains('\u{202e}'));
    }

    /// Les 308 règles se compilent avec YARA-X : une règle refusée ne passe pas jusqu'à une version livrée.
    #[test]
    fn les_308_regles_se_compilent() {
        assert!(regles().is_ok(), "{:?}", regles().err());
    }

    /// Un dossier d'essai : un faux programme qui remplit une règle d'essai de même forme que celles de ReversingLabs
    /// (en-tête « MZ » et textes), un fichier ordinaire, un lien et un fichier creux trop gros, sautés.
    #[test]
    fn analyse_d_un_dossier() {
        let mut compilateur = yara_x::Compiler::new();
        compilateur
            .add_source(
                r#"rule Win32_Trojan_Essai { strings: $a = "vanguard-essai-yara" $b = { 4D 5A 90 } condition: uint16(0) == 0x5A4D and all of them }"#,
            )
            .unwrap();
        let essai = compilateur.build();
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::create_dir_all(dossier.join("sous")).unwrap();
        std::fs::write(dossier.join("sous/facture.exe"), b"MZ\x90\x00 vanguard-essai-yara").unwrap();
        std::fs::write(dossier.join("note.txt"), b"PK vanguard-essai-yara").unwrap();
        std::fs::File::create(dossier.join("image.iso"))
            .unwrap()
            .set_len(TAILLE_MAX + 1)
            .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dossier.join("sous/facture.exe"), dossier.join("lien.exe")).unwrap();
        let mut illisibles = Vec::new();
        let liste = fichiers(&dossier, &mut illisibles);
        assert_eq!(liste.len(), 2, "{liste:?}");
        let (trouves, echecs) = analyser_fichiers(&essai, &liste);
        // Le trop gros n'est pas lu, mais il est dit.
        assert!(
            illisibles.len() == 1 && illisibles[0].ends_with("image.iso"),
            "{illisibles:?}"
        );
        assert!(echecs.is_empty());
        assert_eq!(trouves.len(), 1);
        assert_eq!(trouves[0].regle, "Win32_Trojan_Essai");
        assert!(trouves[0].chemin.ends_with("sous/facture.exe"));
        assert_eq!(famille(&trouves[0].regle), "cheval de Troie");
        // Les vraies règles, sur le même dossier : rien.
        assert!(analyser_fichiers(regles().unwrap(), &liste).0.is_empty());
        // Une cible qui n'existe pas : dite, pas comptée comme saine.
        let mut absents = Vec::new();
        assert!(fichiers(&dossier.join("absent"), &mut absents).is_empty());
        assert!(illisible(&dossier, &absents).is_some());
        let _ = std::fs::remove_dir_all(&dossier);
    }
}
