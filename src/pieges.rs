//! Fichiers-pièges contre les rançongiciels : deux fichiers leurres (un texte et un PDF) dans Documents, Images et
//! Bureau. Personne n'a de raison d'y toucher ; un rançongiciel, lui, chiffre tout ce qu'il trouve, souvent dans
//! l'ordre alphabétique : leur nom commence par « ! » pour passer parmi les premiers, et finit par un code tiré au
//! hasard pour ne jamais être le même d'un ordinateur à l'autre. Chaque bilan, et la surveillance toutes les heures,
//! compare leur empreinte à celle de leur pose : modifié, ou renommé avec une extension en plus (« .locked »), c'est
//! l'alerte. Gardien n'arrête aucun programme lui-même : il prévient et dit quoi faire.
//!
//! Posés et retirés seulement après accord ; la liste exacte est gardée dans pieges.json, le retrait n'enlève qu'elle.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::machine::{Constat, Correctif};
use crate::risk::Niveau;
use crate::ui::*;

const CAT: &str = "Rançongiciels";

/// Un fichier-piège posé : son chemin et l'empreinte BLAKE3 de son contenu au moment de la pose.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Piege {
    chemin: PathBuf,
    empreinte: String,
}

/// Ce qu'est devenu un fichier-piège.
#[derive(Debug, PartialEq)]
enum Etat {
    Intact,
    Modifie,
    /// Renommé avec une extension en plus, comme le font la plupart des rançongiciels.
    Renomme(PathBuf),
    Supprime,
    /// Présent mais pas lisible (verrouillé par un antivirus, fichier OneDrive en ligne seulement, droits) : rien n'est
    /// conclu.
    Illisible,
}

fn fichier() -> PathBuf {
    crate::reseau::dossier_local().join("pieges.json")
}

/// Les fichiers-pièges posés ; `Err` si la liste existe mais ne se lit plus.
fn charger() -> Result<Vec<Piege>, ()> {
    match std::fs::read_to_string(fichier()) {
        Ok(texte) => serde_json::from_str(&texte).map_err(|_| ()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(()),
    }
}

fn etat(piege: &Piege) -> Etat {
    match std::fs::read(&piege.chemin) {
        Ok(octets) if blake3::hash(&octets).to_hex().as_str() == piege.empreinte => Etat::Intact,
        Ok(_) => Etat::Modifie,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            renomme(&piege.chemin).map_or(Etat::Supprime, Etat::Renomme)
        }
        Err(_) => Etat::Illisible,
    }
}

/// Le fichier-piège renommé avec une extension en plus : « !Gardien … 3f9a.txt.locked ».
fn renomme(chemin: &Path) -> Option<PathBuf> {
    let nom = chemin.file_name()?.to_str()?;
    std::fs::read_dir(chemin.parent()?)
        .ok()?
        .flatten()
        .map(|f| f.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.len() > nom.len() && n.starts_with(nom) && n[nom.len()..].starts_with('.'))
        })
}

/// Dossiers personnels où frappent d'abord les rançongiciels : Documents, Images, Bureau (ceux qui existent).
fn dossiers() -> Vec<PathBuf> {
    let mut liste = dossiers_du_systeme();
    liste.retain(|d| d.is_dir());
    liste.sort();
    liste.dedup();
    liste
}

#[cfg(target_os = "linux")]
fn dossiers_du_systeme() -> Vec<PathBuf> {
    let maison = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    // Noms des dossiers dans la langue du bureau : ~/.config/user-dirs.dirs (« XDG_DOCUMENTS_DIR="$HOME/Documents" »).
    let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
    let declares = std::fs::read_to_string(config.join("user-dirs.dirs")).unwrap_or_default();
    let mut liste: Vec<PathBuf> = ["XDG_DOCUMENTS_DIR", "XDG_PICTURES_DIR", "XDG_DESKTOP_DIR"]
        .iter()
        .filter_map(|cle| dossier_declare(&declares, cle, &maison))
        .collect();
    if liste.is_empty() {
        liste = ["Documents", "Images", "Pictures", "Bureau", "Desktop"]
            .iter()
            .map(|d| maison.join(d))
            .collect();
    }
    liste
}

/// Un dossier de user-dirs.dirs. « $HOME » seul (dossier non configuré) n'est pas un dossier personnel.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn dossier_declare(declares: &str, cle: &str, maison: &Path) -> Option<PathBuf> {
    let valeur = declares
        .lines()
        .find_map(|l| l.trim().strip_prefix(cle)?.strip_prefix('='))?
        .trim()
        .trim_matches('"');
    let chemin = match valeur.strip_prefix("$HOME") {
        Some(reste) => maison.join(reste.trim_start_matches('/')),
        None => PathBuf::from(valeur),
    };
    (chemin != maison && chemin.is_absolute()).then_some(chemin)
}

/// Windows : les dossiers déclarés pour le compte (déplacés dans OneDrive le cas échéant), sinon ceux du profil.
/// « User Shell Folders » fait foi (chemins à développer, « %USERPROFILE%\Documents ») ; « Shell Folders » n'en est
/// qu'une copie de compatibilité, parfois périmée : en secours seulement.
#[cfg(windows)]
fn dossiers_du_systeme() -> Vec<PathBuf> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;
    let profil = PathBuf::from(std::env::var_os("USERPROFILE").unwrap_or_default());
    let cle = |nom: &str| {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(format!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\{nom}"))
            .ok()
    };
    let (declares, copie) = (cle("User Shell Folders"), cle("Shell Folders"));
    [
        ("Personal", "Documents"),
        ("My Pictures", "Pictures"),
        ("Desktop", "Desktop"),
    ]
    .iter()
    .map(|(valeur, defaut)| {
        declares
            .as_ref()
            .and_then(|d| d.get_value::<String, _>(valeur).ok())
            .map(|c| developper(&c))
            .or_else(|| copie.as_ref().and_then(|d| d.get_value::<String, _>(valeur).ok()))
            .map_or_else(|| profil.join(defaut), PathBuf::from)
    })
    .collect()
}

/// « %USERPROFILE%\Documents » → le vrai chemin, d'après les variables d'environnement ; une variable inconnue reste
/// telle quelle.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn developper(chemin: &str) -> String {
    let mut sortie = String::new();
    let mut reste = chemin;
    while let Some(debut) = reste.find('%') {
        sortie.push_str(&reste[..debut]);
        let apres = &reste[debut + 1..];
        let Some(fin) = apres.find('%') else {
            sortie.push_str(&reste[debut..]);
            reste = "";
            break;
        };
        let nom = &apres[..fin];
        match std::env::var(nom) {
            Ok(valeur) if !nom.is_empty() => sortie.push_str(&valeur),
            _ => {
                sortie.push('%');
                sortie.push_str(nom);
                sortie.push('%');
            }
        }
        reste = &apres[fin + 1..];
    }
    sortie.push_str(reste);
    sortie
}

#[cfg(target_os = "macos")]
fn dossiers_du_systeme() -> Vec<PathBuf> {
    let maison = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    ["Documents", "Pictures", "Desktop"]
        .iter()
        .map(|d| maison.join(d))
        .collect()
}

/// Code tiré au hasard (4 chiffres hexadécimaux), pour que le nom change d'un ordinateur et d'une pose à l'autre.
fn code(graine: usize) -> String {
    let instant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let melange = format!("{instant}-{}-{graine}", std::process::id());
    blake3::hash(melange.as_bytes()).to_hex()[..4].to_string()
}

fn nom(code: &str, extension: &str) -> String {
    trf!(
        "!Gardien - fichier-piège {code}.{extension}",
        "!Gardien - decoy file {code}.{extension}"
    )
}

/// Le texte d'un fichier-piège : ce qu'il est, dans les deux langues (la personne qui l'ouvre comprend), puis assez
/// de lignes pour qu'il ne passe pas pour un fichier vide, que certains rançongiciels sautent.
fn texte() -> String {
    let mut t = String::from(
        "Fichier-piège de Gardien : ne le modifie pas, ne le déplace pas, ne le supprime pas.\n\
         Il sert à repérer un rançongiciel : s'il change, Gardien t'alerte.\n\
         Pour le retirer : Gardien, menu Antivirus et protection › Fichiers-pièges, ou « gardien pieges --retirer ».\n\n\
         Gardien decoy file: do not modify, move or delete it.\n\
         It is there to catch ransomware: if it changes, Gardien warns you.\n\
         To remove it: Gardien, Antivirus and protection menu › Decoy files, or “gardien pieges --retirer”.\n\n",
    );
    for i in 1..=250 {
        let _ = writeln!(t, "{i:03}  rien d'important ici / nothing important here");
    }
    t
}

/// Un PDF d'une page qui dit ce qu'il est, lisible par tout lecteur de PDF (les rançongiciels visent les PDF).
fn pdf() -> Vec<u8> {
    let page = "BT /F1 14 Tf 50 780 Td (Fichier-piege de Gardien : ne pas modifier, deplacer ni supprimer.) Tj \
                0 -24 Td (Gardien decoy file: do not modify, move or delete it.) Tj ET";
    let objets = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R \
         /Resources << /Font << /F1 5 0 R >> >> >>"
            .to_string(),
        format!("<< /Length {} >>\nstream\n{page}\nendstream", page.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    // Commentaire de remplissage (permis après l'en-tête) : un PDF de quelques centaines d'octets serait sauté.
    let mut sortie = format!("%PDF-1.4\n%{}\n", "Gardien ".repeat(2000));
    let mut positions = Vec::new();
    for (i, objet) in objets.iter().enumerate() {
        positions.push(sortie.len());
        let _ = write!(sortie, "{} 0 obj\n{objet}\nendobj\n", i + 1);
    }
    let table = sortie.len();
    let _ = write!(sortie, "xref\n0 {}\n0000000000 65535 f \n", objets.len() + 1);
    for p in positions {
        let _ = writeln!(sortie, "{p:010} 00000 n ");
    }
    let _ = write!(
        sortie,
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{table}\n%%EOF\n",
        objets.len() + 1
    );
    sortie.into_bytes()
}

/// Pose un texte et un PDF dans chaque dossier. Création exclusive : jamais un fichier existant écrasé.
fn poser_dans(dossiers: &[PathBuf]) -> Vec<Piege> {
    let mut poses = Vec::new();
    for (i, dossier) in dossiers.iter().enumerate() {
        let code = code(i);
        for (extension, contenu) in [("txt", texte().into_bytes()), ("pdf", pdf())] {
            let chemin = dossier.join(nom(&code, extension));
            let ecrit = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&chemin)
                .and_then(|mut f| std::io::Write::write_all(&mut f, &contenu));
            if ecrit.is_ok() {
                poses.push(Piege {
                    chemin,
                    empreinte: blake3::hash(&contenu).to_hex().to_string(),
                });
            }
        }
    }
    poses
}

fn enregistrer(pieges: &[Piege]) -> std::io::Result<()> {
    std::fs::create_dir_all(crate::reseau::dossier_local())?;
    crate::reseau::ecrire_atomique(&fichier(), &serde_json::to_string_pretty(pieges).unwrap_or_default())
}

/// Retire exactement les fichiers posés et intacts, puis la liste. Un piège modifié ou renommé reste : c'est la preuve
/// d'un rançongiciel ; un piège illisible reste aussi (on ne sait pas ce qu'il est devenu). Rend (fichiers qui n'ont
/// pas pu être retirés, fichiers gardés comme preuve).
fn retirer_tous(pieges: &[Piege]) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let (mut restes, mut preuves) = (Vec::new(), Vec::new());
    for p in pieges {
        match etat(p) {
            Etat::Intact => {
                if std::fs::remove_file(&p.chemin).is_err() {
                    restes.push(p.chemin.clone());
                }
            }
            Etat::Modifie => preuves.push(p.chemin.clone()),
            Etat::Renomme(nouveau) => preuves.push(nouveau),
            Etat::Illisible => restes.push(p.chemin.clone()),
            Etat::Supprime => {}
        }
    }
    if restes.is_empty() {
        let _ = std::fs::remove_file(fichier());
    }
    (restes, preuves)
}

/// Un constat de la catégorie, avec une marche à suivre à faire soi-même.
fn constat_de(probleme: Option<Niveau>, message: String, conseil: Option<&str>) -> Constat {
    Constat {
        categorie: CAT,
        probleme,
        message,
        correctif: conseil.map(|c| Correctif {
            action: c.to_string(),
            commandes: Vec::new(),
            automatique: false,
            bloque: None,
        }),
        verifie: true,
    }
}

/// Constat du bilan : rien tant qu'aucun fichier-piège n'est posé.
pub fn constat() -> Option<Constat> {
    let Ok(pieges) = charger() else {
        return Some(Constat {
            verifie: false,
            ..constat_de(
                Some(Niveau::Info),
                trf!(
                    "Impossible de vérifier ({}).",
                    "Could not check ({}).",
                    tr!("liste des fichiers-pièges illisible", "decoy file list unreadable")
                ),
                None,
            )
        });
    };
    if pieges.is_empty() {
        return None;
    }
    let etats: Vec<(&Piege, Etat)> = pieges.iter().map(|p| (p, etat(p))).collect();
    let touches: Vec<String> = etats
        .iter()
        .filter_map(|(p, e)| match e {
            Etat::Modifie => Some(trf!("{} (modifié)", "{} (modified)", p.chemin.display())),
            Etat::Renomme(n) => Some(trf!(
                "{} (renommé en {})",
                "{} (renamed to {})",
                p.chemin.display(),
                n.display()
            )),
            _ => None,
        })
        .collect();
    let supprimes: Vec<String> = etats
        .iter()
        .filter(|(_, e)| *e == Etat::Supprime)
        .map(|(p, _)| p.chemin.display().to_string())
        .collect();
    let illisibles: Vec<String> = etats
        .iter()
        .filter(|(_, e)| *e == Etat::Illisible)
        .map(|(p, _)| p.chemin.display().to_string())
        .collect();
    Some(if !touches.is_empty() {
        constat_de(
            Some(Niveau::Critique),
            trf!(
                "Fichier-piège touché : {}. Un rançongiciel chiffre peut-être tes fichiers en ce moment.",
                "Decoy file touched: {}. Ransomware may be encrypting your files right now.",
                touches.join(", ")
            ),
            Some(tr!(
                "Débranche tout de suite Internet (câble, Wi-Fi) et tes disques de sauvegarde, puis éteins l'ordinateur pour arrêter le chiffrement. Ensuite, analyse-le avec l'antivirus de Gardien depuis la clé, avant de le rebrancher. Si c'est toi qui as ouvert et modifié ce fichier, repose les fichiers-pièges",
                "Unplug the Internet (cable, Wi-Fi) and your backup drives right now, then shut the computer down to stop the encryption. Then scan it with Gardien's antivirus from the key before plugging it back in. If you opened and changed that file yourself, set the decoy files again"
            )),
        )
    } else if !supprimes.is_empty() {
        constat_de(
            Some(Niveau::Moyen),
            trf!(
                "Fichier-piège supprimé : {}. Si ce n'est pas toi, un programme touche à tes documents.",
                "Decoy file deleted: {}. If it was not you, a program is touching your documents.",
                supprimes.join(", ")
            ),
            Some(tr!(
                "Si c'est toi, repose les fichiers-pièges (menu Antivirus et protection) ; sinon, lance une analyse antivirus",
                "If it was you, set the decoy files again (Antivirus and protection menu); otherwise, run an antivirus scan"
            )),
        )
    } else if !illisibles.is_empty() {
        // Verrouillé ou en ligne seulement : ce qu'il contient n'est pas connu, donc jamais compté comme intact.
        Constat {
            verifie: false,
            ..constat_de(
                Some(Niveau::Info),
                trf!(
                    "Impossible de vérifier ({}).",
                    "Could not check ({}).",
                    trf!(
                        "fichier-piège illisible, verrouillé ou en ligne seulement : {}",
                        "decoy file unreadable, locked or online-only: {}",
                        illisibles.join(", ")
                    )
                ),
                None,
            )
        }
    } else {
        constat_de(
            None,
            trf!(
                "{} fichiers-pièges intacts : aucun rançongiciel n'y a touché.",
                "{} decoy files intact: no ransomware touched them.",
                pieges.len()
            ),
            None,
        )
    })
}

/// Un paragraphe coupé pour tenir dans la largeur de l'écran, en retrait de deux espaces.
fn dire(texte: &str) {
    for ligne in envelopper(texte, LARGEUR - 2) {
        println!("  {ligne}");
    }
}

/// Menu Antivirus et protection › Fichiers-pièges : poser, voir où ils en sont, ou les retirer.
pub fn menu() {
    titre(tr!(
        "Fichiers-pièges contre les rançongiciels",
        "Decoy files against ransomware"
    ));
    let Ok(pieges) = charger() else {
        trp!(
            "  ✖ La liste des fichiers-pièges ne se lit plus : {}",
            "  ✖ The decoy file list can no longer be read: {}",
            fichier().display()
        );
        return;
    };
    if pieges.is_empty() {
        poser();
    } else {
        for p in &pieges {
            let (marque, texte) = match etat(p) {
                Etat::Intact => (format!("{VERT}✔{RESET}"), tr!("intact", "intact").to_string()),
                Etat::Modifie => (
                    format!("{}✖{RESET}", couleur(Niveau::Critique)),
                    tr!("MODIFIÉ", "MODIFIED").to_string(),
                ),
                Etat::Renomme(n) => (
                    format!("{}✖{RESET}", couleur(Niveau::Critique)),
                    trf!("RENOMMÉ en {}", "RENAMED to {}", n.display()),
                ),
                Etat::Supprime => (
                    format!("{}⚠{RESET}", couleur(Niveau::Moyen)),
                    tr!("supprimé", "deleted").to_string(),
                ),
                Etat::Illisible => (format!("{GRIS}?{RESET}"), tr!("illisible", "unreadable").to_string()),
            };
            println!("  {marque} {}  {GRIS}{texte}{RESET}", p.chemin.display());
        }
        if let Some(c) = constat()
            && c.probleme.is_some()
        {
            println!();
            dire(&c.message);
            if let Some(k) = &c.correctif {
                dire(&k.action);
            }
        }
        retirer(&pieges, false);
    }
}

/// Montre où iront les fichiers-pièges, puis les pose après accord.
fn poser() {
    let cibles = dossiers();
    if cibles.is_empty() {
        trp!(
            "  Aucun dossier Documents, Images ou Bureau trouvé.",
            "  No Documents, Pictures or Desktop folder found."
        );
        return;
    }
    dire(tr!(
        "Gardien peut poser un texte et un PDF leurres dans tes dossiers. Personne n'a de raison d'y toucher ; un rançongiciel, lui, les chiffre avec le reste : chaque bilan, et la surveillance toutes les heures, le voient et t'alertent. Leur nom commence par « !Gardien » ; ils s'enlèvent d'ici, en une fois.",
        "Gardien can place a decoy text file and PDF in your folders. Nobody has a reason to touch them; ransomware encrypts them along with everything else: each check, and hourly monitoring, see it and warn you. Their name starts with “!Gardien”; they are removed from here, in one go."
    ));
    println!();
    for d in &cibles {
        println!("    {GRIS}{}{RESET}", d.display());
    }
    if !demander(tr!(
        "\n  Poser les fichiers-pièges dans ces dossiers ? [o/N] : ",
        "\n  Place the decoy files in these folders? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'a été posé.", "  Nothing was placed.");
        return;
    }
    let poses = poser_dans(&cibles);
    match enregistrer(&poses) {
        Ok(()) => {
            println!(
                "  {VERT}✔{RESET} {}",
                trf!("{} fichiers-pièges posés.", "{} decoy files placed.", poses.len())
            );
            if !crate::surveillance::active() {
                dire(tr!(
                    "Active la surveillance (menu Réseau et Internet) pour qu'ils soient vérifiés toutes les heures, et pas seulement à chaque bilan.",
                    "Turn monitoring on (Network and Internet menu) so they are checked every hour, not only at each check."
                ));
            }
        }
        Err(e) => {
            // Sans la liste, on ne saurait ni les vérifier ni les retirer exactement : on les retire tout de suite.
            retirer_tous(&poses);
            dire(&trf!(
                "✖ Liste des fichiers-pièges impossible à écrire ({e}) : rien n'est posé.",
                "✖ Could not write the decoy file list ({e}): nothing is placed."
            ));
        }
    }
}

/// Propose de retirer les fichiers-pièges ; `force` : sans question (ligne de commande « --retirer »).
fn retirer(pieges: &[Piege], force: bool) {
    if !force
        && !demander(tr!(
            "\n  Retirer les fichiers-pièges ? [o/N] : ",
            "\n  Remove the decoy files? [y/N]: "
        ))
        .oui()
    {
        return;
    }
    let (restes, preuves) = retirer_tous(pieges);
    if restes.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Fichiers-pièges retirés.",
            "  {VERT}✔{RESET} Decoy files removed."
        );
    } else {
        for r in &restes {
            trp!("  ✖ Impossible de retirer {}", "  ✖ Could not remove {}", r.display());
        }
    }
    for p in &preuves {
        trp!(
            "  ⚠ Gardé, c'est la preuve d'un passage : {}",
            "  ⚠ Kept, it is the evidence of an attack: {}",
            p.display()
        );
    }
}

/// « gardien pieges » : comme le menu ; « --retirer » : retire sans question.
pub fn commande(retirer_seulement: bool) {
    if !retirer_seulement {
        menu();
        return;
    }
    match charger() {
        Ok(p) if p.is_empty() => trp!("  Aucun fichier-piège posé.", "  No decoy file placed."),
        Ok(p) => retirer(&p, true),
        Err(()) => trp!(
            "  ✖ La liste des fichiers-pièges ne se lit plus : {}",
            "  ✖ The decoy file list can no longer be read: {}",
            fichier().display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier_jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gardien-pieges-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn pose_verification_retrait() {
        let d = dossier_jetable("pose");
        let pieges = poser_dans(std::slice::from_ref(&d));
        assert_eq!(pieges.len(), 2);
        for p in &pieges {
            let nom = p.chemin.file_name().unwrap().to_str().unwrap();
            assert!(nom.starts_with("!Gardien - "), "{nom}");
            assert_eq!(etat(p), Etat::Intact);
        }
        // Un rançongiciel chiffre le texte, et renomme le PDF avec son extension.
        std::fs::write(&pieges[0].chemin, b"\x8f\x02chiffre").unwrap();
        assert_eq!(etat(&pieges[0]), Etat::Modifie);
        let verrouille = PathBuf::from(format!("{}.locked", pieges[1].chemin.display()));
        std::fs::rename(&pieges[1].chemin, &verrouille).unwrap();
        assert_eq!(etat(&pieges[1]), Etat::Renomme(verrouille.clone()));
        std::fs::remove_file(&verrouille).unwrap();
        assert_eq!(etat(&pieges[1]), Etat::Supprime);
        // Retrait exact : les pièges intacts partent ; le modifié reste, c'est la preuve ; un fichier de la personne
        // n'est pas touché.
        std::fs::write(d.join("mes notes.txt"), "à garder").unwrap();
        let (restes, preuves) = retirer_tous(&pieges);
        assert_eq!(restes, Vec::<PathBuf>::new());
        assert_eq!(preuves, [pieges[0].chemin.clone()]);
        assert!(pieges[0].chemin.exists());
        assert!(d.join("mes notes.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    // Un fichier sans droit de lecture : « illisible », jamais « supprimé » (root lit tout : rien à essayer alors).
    #[cfg(unix)]
    #[test]
    fn piege_illisible() {
        use std::os::unix::fs::PermissionsExt;
        let d = dossier_jetable("illisible");
        let pieges = poser_dans(std::slice::from_ref(&d));
        std::fs::set_permissions(&pieges[0].chemin, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&pieges[0].chemin).is_err() {
            assert_eq!(etat(&pieges[0]), Etat::Illisible);
        }
        std::fs::set_permissions(&pieges[0].chemin, std::fs::Permissions::from_mode(0o600)).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn variables_developpees() {
        let path = std::env::var("PATH").unwrap_or_default();
        assert_eq!(developper("%PATH%\\x"), format!("{path}\\x"));
        assert_eq!(developper("%GARDIEN_INCONNUE%\\y"), "%GARDIEN_INCONNUE%\\y");
        assert_eq!(developper("50% de 10"), "50% de 10");
        assert_eq!(developper("sans"), "sans");
    }

    #[test]
    fn jamais_un_fichier_ecrase() {
        let d = dossier_jetable("existant");
        let premier = poser_dans(std::slice::from_ref(&d));
        // Même nom imposé : la création exclusive refuse, le fichier d'avant est intact.
        std::fs::write(&premier[0].chemin, "contenu de la personne").unwrap();
        let ecrit = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&premier[0].chemin);
        assert!(ecrit.is_err());
        assert_eq!(
            std::fs::read_to_string(&premier[0].chemin).unwrap(),
            "contenu de la personne"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn pdf_valide() {
        let pdf = pdf();
        let texte = String::from_utf8(pdf.clone()).unwrap();
        assert!(texte.starts_with("%PDF-1.4\n"));
        assert!(pdf.len() > 15_000);
        // La table des objets est là où « startxref » le dit, et chaque entrée pointe sur son objet.
        let table: usize = texte
            .rsplit("startxref\n")
            .next()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(texte[table..].starts_with("xref\n0 6\n"));
        for (i, entree) in texte[table..].lines().skip(3).take(5).enumerate() {
            let position: usize = entree[..10].parse().unwrap();
            assert_eq!(entree.len(), 19, "entrée de 20 octets avec son saut de ligne");
            assert!(texte[position..].starts_with(&format!("{} 0 obj\n", i + 1)));
        }
    }

    // user-dirs.dirs n'existe que sous Linux ; « /home/alice » n'est pas un chemin absolu pour Windows.
    #[cfg(unix)]
    #[test]
    fn dossiers_de_user_dirs() {
        let maison = Path::new("/home/alice");
        let declares = "# commentaire\nXDG_DOCUMENTS_DIR=\"$HOME/Documents\"\nXDG_DESKTOP_DIR=\"$HOME\"\nXDG_PICTURES_DIR=\"/data/Images\"\n";
        assert_eq!(
            dossier_declare(declares, "XDG_DOCUMENTS_DIR", maison),
            Some(PathBuf::from("/home/alice/Documents"))
        );
        assert_eq!(
            dossier_declare(declares, "XDG_PICTURES_DIR", maison),
            Some(PathBuf::from("/data/Images"))
        );
        // « $HOME » seul : dossier non configuré.
        assert_eq!(dossier_declare(declares, "XDG_DESKTOP_DIR", maison), None);
        assert_eq!(dossier_declare(declares, "XDG_MUSIC_DIR", maison), None);
    }

    #[test]
    fn codes_differents() {
        assert_ne!(code(1), code(2));
        assert_eq!(code(1).len(), 4);
    }
}
