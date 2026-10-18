//! Protection de la clé USB sous Linux et macOS. Sous Windows, la partition GARDIEN est en lecture seule grâce à
//! son attribut GPT ; Linux et macOS ignorent cet attribut. Sur tout ordinateur autre que celui du propriétaire,
//! Gardien remonte donc lui-même la partition en lecture seule (udisks ou diskutil, sans mot de passe) avant de
//! commencer.
//!
//! Le propriétaire est reconnu par l'empreinte SHA-1 de son /etc/machine-id (IOPlatformUUID sous macOS), que
//! outils/deployer.sh écrit dans le fichier témoin `gardien.cle`. Témoin vide (clé jamais déployée) : pas de
//! protection.
//!
//! Lancé depuis la clé, le programme s'y lit encore : la partition ne pourrait pas être démontée. Il se recopie
//! donc d'abord dans un dossier temporaire et s'y relance. C'est une barrière contre les écritures par erreur ou
//! par un programme quelconque, pas un coffre-fort : un programme malveillant lancé avec le compte de la personne
//! peut remonter la clé en écriture de la même façon.

use std::path::{Path, PathBuf};

use crate::ui::*;

/// Variable posée par la copie temporaire : chemin du programme d'origine, sur la clé.
const ORIGINE: &str = "GARDIEN_ORIGINE";
/// Dossier du programme sur la clé.
#[cfg(target_os = "linux")]
const DOSSIER_PROGRAMME: &str = "Linux";
#[cfg(target_os = "macos")]
const DOSSIER_PROGRAMME: &str = "macOS";

/// Le programme tel que lancé par la personne (sur la clé), même quand c'est sa copie temporaire qui tourne.
pub fn exe_d_origine() -> Option<PathBuf> {
    std::env::var_os(ORIGINE)
        .map(PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .and_then(|e| e.canonicalize().ok())
}

/// Empreinte de cet ordinateur, comparée à celle écrite sur la clé.
pub fn empreinte_machine() -> Option<String> {
    #[cfg(target_os = "linux")]
    let id = std::fs::read_to_string("/etc/machine-id").ok()?;
    // « "IOPlatformUUID" = "564D…" »
    #[cfg(target_os = "macos")]
    let id = crate::commande::lancer(
        std::process::Command::new("ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]),
        10,
    )?
    .sortie
    .lines()
    .find(|l| l.contains("\"IOPlatformUUID\""))?
    .rsplit('"')
    .nth(1)?
    .to_string();
    let id = id.trim();
    (!id.is_empty()).then(|| sha1_smol::Sha1::from(id).digest().to_string())
}

/// Périphérique et état (lecture seule ou non) du point de montage `dossier`, d'après /proc/self/mountinfo.
#[cfg(target_os = "linux")]
fn montage(dossier: &Path) -> Option<(String, bool)> {
    let infos = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    // Les espaces des chemins y sont écrits \040.
    let cible = dossier.to_string_lossy().replace(' ', "\\040");
    infos.lines().rev().find_map(|l| {
        let champs: Vec<&str> = l.split(' ').collect();
        let (point, options) = (*champs.get(4)?, *champs.get(5)?);
        if point != cible {
            return None;
        }
        let apres = l.split(" - ").nth(1)?;
        let source = apres.split(' ').nth(1)?.to_string();
        Some((source, options.split(',').any(|o| o == "ro")))
    })
}

/// Périphérique et état du point de montage `dossier`, d'après `mount` :
/// « /dev/disk4s1 on /Volumes/GARDIEN (exfat, local, nodev, nosuid, read-only, noowners) ».
#[cfg(target_os = "macos")]
fn montage(dossier: &Path) -> Option<(String, bool)> {
    let r = crate::commande::lancer(&mut std::process::Command::new("mount"), 10)?;
    let marque = format!(" on {} (", dossier.display());
    r.sortie.lines().find_map(|l| {
        let (source, reste) = l.split_once(&marque)?;
        Some((
            source.to_string(),
            reste.split(", ").any(|o| o.trim_end_matches(')') == "read-only"),
        ))
    })
}

/// Lance l'outil de montage (udisksctl, diskutil) ; en cas d'échec, son message d'erreur.
fn outil(cmd: &str, args: &[&str]) -> Result<(), String> {
    match crate::commande::lancer(std::process::Command::new(cmd).args(args), 30) {
        Some(r) if r.code == Some(0) => Ok(()),
        Some(r) => Err(format!("{} {}", r.erreurs.trim(), r.sortie.trim()).trim().to_string()),
        None => Err(format!("{cmd} absent ou sans réponse")),
    }
}

#[cfg(target_os = "linux")]
fn demonter(peripherique: &str) -> Result<(), String> {
    outil("udisksctl", &["unmount", "-b", peripherique])
}

#[cfg(target_os = "linux")]
fn monter(peripherique: &str, lecture_seule: bool) -> Result<(), String> {
    if lecture_seule {
        outil("udisksctl", &["mount", "-b", peripherique, "-o", "ro"])
    } else {
        outil("udisksctl", &["mount", "-b", peripherique])
    }
}

#[cfg(target_os = "macos")]
fn demonter(peripherique: &str) -> Result<(), String> {
    outil("diskutil", &["unmount", peripherique])
}

#[cfg(target_os = "macos")]
fn monter(peripherique: &str, lecture_seule: bool) -> Result<(), String> {
    if lecture_seule {
        outil("diskutil", &["mount", "readOnly", peripherique])
    } else {
        outil("diskutil", &["mount", peripherique])
    }
}

/// Empreinte de l'ordinateur du propriétaire, écrite dans le témoin de la clé. Une clé préparée sous un ancien nom
/// la garde dans l'ancien témoin : sans lui, elle passerait pour une clé sans protection, modifiable partout.
fn empreinte_attendue(cle: &Path) -> String {
    std::iter::once(crate::reseau::TEMOIN_CLE)
        .chain(crate::reseau::ANCIENS_TEMOINS_CLE)
        .find_map(|temoin| std::fs::read_to_string(cle.join(temoin)).ok())
        .unwrap_or_default()
}

/// Au démarrage : sur un ordinateur qui n'est pas celui du propriétaire, remonte la clé en lecture seule.
pub fn proteger_cle() {
    // Copie temporaire relancée : elle supprime son fichier (Linux le garde lisible jusqu'à la fin du programme).
    if std::env::var_os(ORIGINE).is_some()
        && let Ok(copie) = std::env::current_exe()
        && est_une_copie(&copie)
    {
        let _ = std::fs::remove_file(&copie);
        if let Some(dossier) = copie.parent() {
            let _ = std::fs::remove_dir(dossier);
        }
    }
    let Some(cle) = crate::reseau::cle_usb() else {
        return;
    };
    let attendue = empreinte_attendue(&cle);
    let attendue = attendue.trim();
    if attendue.is_empty() || Some(attendue) == empreinte_machine().as_deref() {
        return;
    }
    let Some((peripherique, lecture_seule)) = montage(&cle) else {
        return;
    };
    if lecture_seule {
        return;
    }
    // Lancé depuis la clé : relance depuis une copie, sinon la partition est occupée par le programme lui-même.
    if std::env::var_os(ORIGINE).is_none()
        && let Ok(exe) = std::env::current_exe()
        && exe.starts_with(&cle)
    {
        relancer_depuis_une_copie(&exe);
        return;
    }
    // Le dossier courant est peut-être sur la clé (terminal ouvert dans Linux/) : on en sort.
    if let Some(maison) = std::env::var_os("HOME") {
        let _ = std::env::set_current_dir(maison);
    }
    // Un programme du bureau (indexation, miniatures) peut lire la clé un court instant : on réessaie un peu.
    let mut demontage = demonter(&peripherique);
    for _ in 0..4 {
        if demontage.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        demontage = demonter(&peripherique);
    }
    if let Err(e) = demontage {
        trp!(
            "  ⚠ Clé GARDIEN non protégée : elle est utilisée (terminal ou fenêtre ouverts dans la clé ?).\n    {GRIS}Ferme-les, puis relance Gardien depuis un autre dossier : {}/{DOSSIER_PROGRAMME}/gardien{RESET}",
            "  ⚠ GARDIEN key not protected: it is in use (terminal or window open inside the key?).\n    {GRIS}Close them, then run Gardien from another folder: {}/{DOSSIER_PROGRAMME}/gardien{RESET}",
            cle.display()
        );
        crate::journal::erreur("protection de la clé", &format!("démontage impossible : {e}"));
        return;
    }
    if let Err(e) = monter(&peripherique, true) {
        // Remontée impossible : on la remonte comme avant plutôt que de la laisser invisible.
        let _ = monter(&peripherique, false);
        crate::journal::erreur(
            "protection de la clé",
            &format!("remontage en lecture seule refusé : {e}"),
        );
    } else {
        trp!(
            "  {GRIS}Clé GARDIEN remontée en lecture seule : cet ordinateur ne peut rien y écrire jusqu'au débranchement.{RESET}",
            "  {GRIS}GARDIEN key remounted read-only: this computer cannot write to it until it is unplugged.{RESET}"
        );
    }
}

/// Où faire la copie temporaire, dans l'ordre essayé. Linux : d'abord /run/user/<uid>, réservé à la personne (/tmp
/// est partagé par tous les comptes de l'ordinateur) ; macOS : son dossier temporaire, déjà personnel.
fn dossiers_temporaires() -> Vec<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_dir())
        .into_iter()
        .chain([std::env::temp_dir()])
        .collect()
}

/// `exe` est-il une copie faite par `relancer_depuis_une_copie` (<dossier temporaire>/gardien-<…>/gardien) ?
/// La variable GARDIEN_ORIGINE ne suffit pas : tout programme lancé depuis la copie en hérite, et un Gardien
/// relancé de là effacerait sinon son propre programme.
fn est_une_copie(exe: &Path) -> bool {
    let Some(dossier) = exe.parent() else {
        return false;
    };
    let base = dossier.parent().and_then(|b| b.canonicalize().ok());
    exe.file_name() == Some(std::ffi::OsStr::new("gardien"))
        && dossier
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("gardien-"))
        && base.is_some_and(|b| {
            dossiers_temporaires()
                .iter()
                .any(|t| t.canonicalize().is_ok_and(|t| t == b))
        })
}

/// Copie le programme hors de la clé et le relance avec les mêmes arguments. Ne revient qu'en cas d'échec.
fn relancer_depuis_une_copie(exe: &Path) {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    // Nom imprévisible, dossier réservé à la personne et refusé s'il existe déjà : sinon un autre compte de
    // l'ordinateur pourrait le préparer d'avance et remplacer le programme entre la copie et son lancement.
    let nom = format!(
        "gardien-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let mut erreurs = Vec::new();
    for base in dossiers_temporaires() {
        let dossier = base.join(&nom);
        let copie = dossier.join("gardien");
        let copiee = std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dossier)
            .and_then(|()| std::fs::copy(exe, &copie))
            .and_then(|_| std::fs::set_permissions(&copie, std::fs::Permissions::from_mode(0o700)));
        // exec ne revient qu'en cas d'échec (dossier monté sans droit d'exécution…) : on essaie le suivant.
        let erreur = match copiee {
            Ok(()) => std::process::Command::new(&copie)
                .args(std::env::args_os().skip(1))
                .env(ORIGINE, exe)
                .exec(),
            Err(e) => e,
        };
        erreurs.push(format!("{} : {erreur}", base.display()));
        let _ = std::fs::remove_file(&copie);
        let _ = std::fs::remove_dir(&dossier);
    }
    // Aucune copie n'a pu être lancée : le programme continue depuis la clé, sans protection.
    crate::journal::erreur(
        "protection de la clé",
        &format!("relance depuis une copie impossible : {}", erreurs.join(" ; ")),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montage_de_la_racine() {
        // macOS : la racine est le volume système scellé, en lecture seule ; les données sont à part.
        #[cfg(target_os = "macos")]
        assert!(montage(Path::new("/")).expect("/ est monté").1);
        #[cfg(target_os = "macos")]
        let donnees = Path::new("/System/Volumes/Data");
        #[cfg(target_os = "linux")]
        let donnees = Path::new("/");
        let (_, lecture_seule) = montage(donnees).expect("volume de données monté");
        assert!(!lecture_seule);
        assert!(montage(Path::new("/pas/un/montage")).is_none());
    }

    #[test]
    fn empreinte_lue_dans_l_ancien_temoin() {
        let cle = std::env::temp_dir().join(format!("gardien-temoin-{}", std::process::id()));
        std::fs::create_dir_all(&cle).unwrap();
        assert_eq!(empreinte_attendue(&cle), "");
        std::fs::write(cle.join("sentinel.cle"), "abc").unwrap();
        assert_eq!(empreinte_attendue(&cle), "abc");
        // Le témoin du nom actuel l'emporte, même vide (clé volontairement sans protection).
        std::fs::write(cle.join("gardien.cle"), "").unwrap();
        assert_eq!(empreinte_attendue(&cle), "");
        let _ = std::fs::remove_dir_all(&cle);
    }

    #[test]
    fn seule_la_copie_temporaire_s_efface() {
        let base = dossiers_temporaires().remove(0);
        let dossier = base.join(format!("gardien-test-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let copie = dossier.join("gardien");
        std::fs::write(&copie, "").unwrap();
        assert!(est_une_copie(&copie));
        // Le programme installé, ou un « Gardien » posé ailleurs : jamais effacés.
        assert!(!est_une_copie(Path::new("/usr/bin/gardien")));
        assert!(!est_une_copie(&base.join("gardien")));
        let _ = std::fs::remove_file(&copie);
        let _ = std::fs::remove_dir(&dossier);
    }
}
