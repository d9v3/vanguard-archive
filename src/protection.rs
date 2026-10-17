//! Protection de la clé USB sous Linux. Sous Windows, la partition SENTINEL est en lecture seule grâce à son
//! attribut GPT ; Linux ignore cet attribut. Sur tout ordinateur autre que celui du propriétaire, sentinel remonte
//! donc lui-même la partition en lecture seule (udisks, sans mot de passe) avant de commencer.
//!
//! Le propriétaire est reconnu par l'empreinte SHA-1 de son /etc/machine-id, que outils/deployer.sh écrit dans le
//! fichier témoin `sentinel.cle`. Témoin vide (clé jamais déployée) : pas de protection.
//!
//! Lancé depuis la clé, le programme s'y lit encore : la partition ne pourrait pas être démontée. Il se recopie
//! donc d'abord dans un dossier temporaire et s'y relance. C'est une barrière contre les écritures par erreur ou
//! par un programme quelconque, pas un coffre-fort : un programme malveillant lancé avec le compte de la personne
//! peut remonter la clé en écriture de la même façon.

use std::path::{Path, PathBuf};

use crate::ui::*;

/// Variable posée par la copie temporaire : chemin du programme d'origine, sur la clé.
const ORIGINE: &str = "SENTINEL_ORIGINE";

/// Le programme tel que lancé par la personne (sur la clé), même quand c'est sa copie temporaire qui tourne.
pub fn exe_d_origine() -> Option<PathBuf> {
    std::env::var_os(ORIGINE)
        .map(PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .and_then(|e| e.canonicalize().ok())
}

/// Empreinte de cet ordinateur, comparée à celle écrite sur la clé.
pub fn empreinte_machine() -> Option<String> {
    let id = std::fs::read_to_string("/etc/machine-id").ok()?;
    let id = id.trim();
    (!id.is_empty()).then(|| sha1_smol::Sha1::from(id).digest().to_string())
}

/// Périphérique et état (lecture seule ou non) du point de montage `dossier`, d'après /proc/self/mountinfo.
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

/// Lance udisksctl ; en cas d'échec, son message d'erreur.
fn udisksctl(args: &[&str]) -> Result<(), String> {
    match crate::commande::lancer(std::process::Command::new("udisksctl").args(args), 30) {
        Some(r) if r.code == Some(0) => Ok(()),
        Some(r) => Err(r.erreurs.trim().to_string()),
        None => Err("udisksctl absent ou sans réponse".into()),
    }
}

/// Au démarrage : sur un ordinateur qui n'est pas celui du propriétaire, remonte la clé en lecture seule.
pub fn proteger_cle() {
    // Copie temporaire relancée : elle supprime son fichier (Linux le garde lisible jusqu'à la fin du programme).
    if std::env::var_os(ORIGINE).is_some()
        && let Ok(copie) = std::env::current_exe()
    {
        let _ = std::fs::remove_file(&copie);
        if let Some(dossier) = copie.parent() {
            let _ = std::fs::remove_dir(dossier);
        }
    }
    let Some(cle) = crate::reseau::cle_usb() else {
        return;
    };
    let attendue = std::fs::read_to_string(cle.join(crate::reseau::TEMOIN_CLE)).unwrap_or_default();
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
    let mut demontage = udisksctl(&["unmount", "-b", &peripherique]);
    for _ in 0..4 {
        if demontage.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        demontage = udisksctl(&["unmount", "-b", &peripherique]);
    }
    if let Err(e) = demontage {
        trp!(
            "  ⚠ Clé SENTINEL non protégée : elle est utilisée (terminal ou fenêtre ouverts dans la clé ?).\n    {GRIS}Ferme-les, puis relance sentinel depuis un autre dossier : {}/Linux/sentinel{RESET}",
            "  ⚠ SENTINEL key not protected: it is in use (terminal or window open inside the key?).\n    {GRIS}Close them, then run sentinel from another folder: {}/Linux/sentinel{RESET}",
            cle.display()
        );
        crate::journal::erreur("protection de la clé", &format!("démontage impossible : {e}"));
        return;
    }
    if let Err(e) = udisksctl(&["mount", "-b", &peripherique, "-o", "ro"]) {
        // Remontée impossible : on la remonte comme avant plutôt que de la laisser invisible.
        let _ = udisksctl(&["mount", "-b", &peripherique]);
        crate::journal::erreur(
            "protection de la clé",
            &format!("remontage en lecture seule refusé : {e}"),
        );
    } else {
        trp!(
            "  {GRIS}Clé SENTINEL remontée en lecture seule : cet ordinateur ne peut rien y écrire jusqu'au débranchement.{RESET}",
            "  {GRIS}SENTINEL key remounted read-only: this computer cannot write to it until it is unplugged.{RESET}"
        );
    }
}

/// Copie le programme hors de la clé et le relance avec les mêmes arguments. Ne revient qu'en cas d'échec.
fn relancer_depuis_une_copie(exe: &Path) {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    let dossier = std::env::temp_dir().join(format!("sentinel-{}", std::process::id()));
    let copie = dossier.join("sentinel");
    let copiee = std::fs::create_dir_all(&dossier)
        .and_then(|()| std::fs::copy(exe, &copie))
        .and_then(|_| std::fs::set_permissions(&copie, std::fs::Permissions::from_mode(0o755)));
    if copiee.is_err() {
        return;
    }
    // exec ne revient qu'en cas d'échec : le programme continue alors depuis la clé, sans protection.
    let erreur = std::process::Command::new(&copie)
        .args(std::env::args_os().skip(1))
        .env(ORIGINE, exe)
        .exec();
    crate::journal::erreur(
        "protection de la clé",
        &format!("relance depuis la copie impossible : {erreur}"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montage_de_la_racine() {
        let (_, lecture_seule) = montage(Path::new("/")).expect("/ est monté");
        assert!(!lecture_seule);
        assert!(montage(Path::new("/pas/un/montage")).is_none());
    }
}
