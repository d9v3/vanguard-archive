//! Analyse YARA : 308 règles de ReversingLabs (rançongiciels, voleurs de mots de passe, chevaux de Troie, portes
//! dérobées…), intégrées au programme (assets/yara, outils/maj-yara.sh ; allégées par build.rs, de 2,7 Mo à 1,2 Mo,
//! sans en changer le sens) et appliquées par le moteur « yara » du système. En complément de l'antivirus : une règle décrit une famille entière, variantes comprises. Lecture seule :
//! rien n'est déplacé ni supprimé. Le moteur s'installe après accord (paquet de la distribution, Homebrew, winget).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::protection::antivirus::{Examen, Portee};
use crate::ui::*;

const REGLES: &str = include_str!(concat!(env!("OUT_DIR"), "/reversinglabs.yara"));

/// Le moteur : dans le PATH, ou, sous Windows, là où winget pose ses commandes (juste après l'installation, le PATH
/// de ce programme ne le connaît pas encore).
fn moteur() -> Option<PathBuf> {
    let nom = if cfg!(windows) { "yara.exe" } else { "yara" };
    let dans_le_path =
        std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(nom)).find(|f| f.is_file()));
    #[cfg(windows)]
    let dans_le_path = dans_le_path.or_else(|| {
        std::env::var_os("LOCALAPPDATA")
            .map(|d| PathBuf::from(d).join(r"Microsoft\WinGet\Links\yara.exe"))
            .filter(|f| f.is_file())
    });
    dans_le_path
}

/// Version du moteur (« 4.5.4 ») : les options -N (ne pas suivre les liens) et -z (sauter les gros fichiers) datent
/// de la 4.2 ; Ubuntu 22.04 en est encore à la 4.1.
fn version(moteur: &Path) -> (u32, u32) {
    let sortie = crate::commande::lancer(Command::new(moteur).arg("--version"), 10)
        .map(|r| r.sortie)
        .unwrap_or_default();
    lire_version(&sortie)
}

fn lire_version(texte: &str) -> (u32, u32) {
    let mut nombres = texte.trim().split('.').map(|n| n.trim().parse().unwrap_or(0));
    (nombres.next().unwrap_or(0), nombres.next().unwrap_or(0))
}

/// Propose d'installer le moteur ; `true` s'il est là ensuite.
fn installer() -> bool {
    trp!(
        "  Le moteur YARA (libre, de VirusTotal) n'est pas installé.",
        "  The YARA engine (open source, by VirusTotal) is not installed."
    );
    #[cfg(target_os = "linux")]
    let commande = crate::machine::linux::Paquets::detecter().map(|g| g.installer("yara"));
    #[cfg(target_os = "macos")]
    let commande = crate::machine::macos::homebrew().map(|brew| format!("{brew} install yara"));
    #[cfg(windows)]
    let commande = Some(
        "winget install --id VirusTotal.YARA -e --source winget --accept-source-agreements --accept-package-agreements"
            .to_string(),
    );
    let Some(commande) = commande else {
        trp!(
            "  Installe le paquet « yara » avec l'outil de ton système, puis relance l'analyse.",
            "  Install the “yara” package with your system's tool, then run the scan again."
        );
        return false;
    };
    println!("  {GRIS}{commande}{RESET}");
    if !demander(tr!("  L'installer maintenant ? [o/N] : ", "  Install it now? [y/N]: ")).oui() {
        return false;
    }
    // Installation au premier plan : sudo ou winget peuvent poser une question.
    #[cfg(unix)]
    let fait = Command::new("bash").arg("-c").arg(&commande).status();
    #[cfg(windows)]
    let fait = Command::new("winget")
        .args(commande.split_whitespace().skip(1))
        .status();
    if !fait.is_ok_and(|s| s.success()) || moteur().is_none() {
        trp!("  ✖ Installation impossible.", "  ✖ Installation failed.");
        return false;
    }
    true
}

/// Les endroits à risque : téléchargements, bureau, programmes lancés au démarrage (et le dossier temporaire sous
/// Windows, où atterrissent les programmes téléchargés).
fn endroits_a_risque() -> Vec<PathBuf> {
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
    fichier: String,
}

/// Sortie de yara : une ligne « Règle chemin » par correspondance (le chemin peut contenir des espaces).
fn lire_sortie(sortie: &str) -> Vec<Trouve> {
    sortie
        .lines()
        .filter_map(|l| {
            let (regle, fichier) = l.split_once(' ')?;
            (!regle.is_empty() && !fichier.is_empty()).then(|| Trouve {
                regle: regle.to_string(),
                fichier: fichier.to_string(),
            })
        })
        .collect()
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

/// Applique les 308 règles aux cibles : (correspondances, erreurs du moteur). `None` : moteur absent (installation
/// refusée) ou règles impossibles à écrire, ce qui est déjà dit.
fn appliquer(cibles: &[PathBuf]) -> Option<(Vec<Trouve>, Vec<String>)> {
    let moteur = moteur().or_else(|| installer().then(moteur).flatten())?;
    // Les règles sont écrites dans un dossier jetable réservé à l'utilisateur, puis effacées.
    let Ok(dossier) = crate::protection::isoler::dossier_jetable() else {
        trp!(
            "  ✖ Dossier temporaire impossible à créer.",
            "  ✖ Could not create a temporary folder."
        );
        return None;
    };
    let regles = dossier.join("reversinglabs.yara");
    if std::fs::write(&regles, REGLES).is_err() {
        let _ = std::fs::remove_dir_all(&dossier);
        trp!("  ✖ Règles impossibles à écrire.", "  ✖ Could not write the rules.");
        return None;
    }
    let recent = version(&moteur) >= (4, 2);
    let mut trouves = Vec::new();
    // Toute sortie en erreur du moteur est dite : ce qu'il n'a pas pu lire n'est jamais compté comme sain.
    let mut erreurs: Vec<String> = Vec::new();
    for cible in cibles {
        trp!("  Analyse de {}…", "  Scanning {}…", cible.display());
        let mut commande = Command::new(&moteur);
        commande.args(["-r", "-w", "-p", "4", "-a", "30"]);
        if recent {
            // Liens non suivis (pas de boucle), fichiers de plus de 256 Mo sautés (images disque, vidéos).
            commande.args(["-N", "-z", "268435456"]);
        }
        commande.arg(&regles).arg(cible);
        match crate::commande::lancer(&mut commande, 3600) {
            Some(r) => {
                trouves.extend(lire_sortie(&r.sortie));
                if r.code != Some(0) {
                    let raison = r
                        .erreurs
                        .lines()
                        .map(str::trim)
                        .find(|l| !l.is_empty())
                        .map_or_else(|| trf!("code {:?}", "code {:?}", r.code), str::to_string);
                    erreurs.push(format!("{} : {raison}", cible.display()));
                }
            }
            None => erreurs.push(trf!(
                "{} : le moteur n'a pas pu aller au bout (lancement impossible, ou plus d'une heure)",
                "{}: the engine could not finish (could not start, or over an hour)",
                cible.display()
            )),
        }
    }
    let _ = std::fs::remove_dir_all(&dossier);
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
            "Ne les ouvre pas. Fais-les aussi analyser par l'antivirus (même menu) ; si tu ne sais pas d'où vient un fichier, supprime-le. Une règle peut se tromper sur un fichier légitime : en cas de doute, envoie-le à VirusTotal.",
            "Do not open them. Have the antivirus scan them too (same menu); if you do not know where a file comes from, delete it. A rule can be wrong about a legitimate file: when in doubt, upload it to VirusTotal."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
}

/// Un seul fichier, pour « Vérifier un fichier téléchargé » : le résultat, que l'appelant affiche.
pub(crate) fn examiner(fichier: &Path) -> Examen {
    match appliquer(&[fichier.to_path_buf()]) {
        None => Examen::Impossible(tr!("moteur YARA absent", "YARA engine missing").into()),
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
    fn sortie_de_yara() {
        let sortie = "Win32_Ransomware_WannaCry /home/alice/Téléchargements/facture urgente.exe\n\
                      ByteCode_MSIL_Infostealer_RedLine C:\\Users\\alice\\Downloads\\outil.exe\n";
        let trouves = lire_sortie(sortie);
        assert_eq!(trouves.len(), 2);
        assert_eq!(trouves[0].fichier, "/home/alice/Téléchargements/facture urgente.exe");
        assert_eq!(famille(&trouves[0].regle), "rançongiciel");
        assert_eq!(famille(&trouves[1].regle), "voleur de mots de passe");
        assert_eq!(famille("Linux_Inconnu_X"), "logiciel malveillant");
    }

    #[test]
    fn versions_du_moteur() {
        assert_eq!(lire_version("4.5.4\n"), (4, 5));
        assert!(lire_version("4.1.3") < (4, 2));
        assert_eq!(lire_version("rien"), (0, 0));
    }
}
