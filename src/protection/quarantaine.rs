//! Quarantaine réversible : un fichier jugé dangereux (antivirus, YARA) est déplacé dans le dossier de Vanguard sur cet
//! ordinateur (jamais sur la clé : on ne transporte pas de logiciel malveillant), rendu inutilisable (aucune
//! permission sous Linux et macOS ; sous Windows, une extension qui empêche de le lancer d'un double-clic, et lecture
//! seule), et noté : d'où il vient, ses permissions, la détection, la date. Une détection peut se tromper : « Remettre »
//! le replace exactement où il était, avec ses permissions d'avant, sans jamais écraser un fichier qui aurait pris sa
//! place. Les fichiers isolés avant la 0.61 (journal.txt seulement) se remettent aussi.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ui::*;

/// Ajouté au nom sous Windows : un fichier en « .exe.vanguard-quarantaine » ne se lance plus d'un double-clic.
const SUFFIXE_WINDOWS: &str = ".vanguard-quarantaine";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Entree {
    /// Nom du fichier dans le dossier de la quarantaine.
    nom: String,
    /// Chemin d'origine, tel quel (pour le remettre) ; montré, il passe par `affichable`.
    origine: String,
    detection: String,
    /// « AAAA-MM-JJ HH:MM:SS ».
    date: String,
    /// Permissions d'origine (Linux, macOS), pour les remettre ; absentes pour un fichier isolé avant la 0.61.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<u32>,
}

#[derive(Serialize, Deserialize, Default)]
struct Registre {
    fichiers: Vec<Entree>,
}

pub fn dossier() -> PathBuf {
    crate::reseau::dossier_local().join("quarantaine")
}

fn registre_dans(dossier: &Path) -> PathBuf {
    dossier.join("quarantaine.json")
}

fn charger(dossier: &Path) -> Registre {
    std::fs::read_to_string(registre_dans(dossier))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn enregistrer(dossier: &Path, r: &Registre) -> std::io::Result<()> {
    let texte = serde_json::to_string_pretty(r).map_err(std::io::Error::other)?;
    crate::reseau::ecrire_atomique(&registre_dans(dossier), texte)
}

/// Isole `chemin` dans la quarantaine de cet ordinateur et le note ; rend son chemin en quarantaine.
pub fn isoler(chemin: &Path, detection: &str) -> std::io::Result<PathBuf> {
    isoler_dans(chemin, detection, &dossier())
}

fn isoler_dans(chemin: &Path, detection: &str, dossier: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dossier)?;
    let meta = std::fs::symlink_metadata(chemin)?;
    if !meta.is_file() {
        return Err(std::io::Error::other(tr!(
            "ce n'est pas un fichier",
            "this is not a file"
        )));
    }
    #[cfg(unix)]
    let mode = Some(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777);
    #[cfg(windows)]
    let mode = None;
    let nom_origine = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let horodatage = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let suffixe = if cfg!(windows) { SUFFIXE_WINDOWS } else { "" };
    let nom = format!("{horodatage}.{nom_origine}{suffixe}");
    let dest = dossier.join(&nom);
    // rename échoue d'un disque à l'autre (clé USB → disque) : copie, puis suppression de l'original.
    std::fs::rename(chemin, &dest).or_else(|_| {
        std::fs::copy(chemin, &dest)?;
        // Original impossible à supprimer : pas de seconde copie, encore utilisable, en quarantaine.
        std::fs::remove_file(chemin).inspect_err(|_| {
            let _ = std::fs::remove_file(&dest);
        })
    })?;
    #[cfg(unix)]
    std::fs::set_permissions(&dest, std::os::unix::fs::PermissionsExt::from_mode(0o000))?;
    #[cfg(windows)]
    {
        let mut p = std::fs::metadata(&dest)?.permissions();
        p.set_readonly(true);
        std::fs::set_permissions(&dest, p)?;
    }
    let mut r = charger(dossier);
    r.fichiers.push(Entree {
        nom,
        origine: chemin.to_string_lossy().into_owned(),
        detection: detection.to_string(),
        date: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        mode,
    });
    noter_journal(dossier, r.fichiers.last().expect("ajoutée"));
    enregistrer(dossier, &r)?;
    Ok(dest)
}

/// Le journal lisible par une personne (cat, éditeur), comme avant la 0.61 : noms rendus inoffensifs.
fn noter_journal(dossier: &Path, e: &Entree) {
    use std::io::Write;
    let ligne = format!(
        "{}\t{}\t{}\t{}\n",
        e.date,
        affichable(&e.detection),
        affichable(&e.origine),
        affichable(&e.nom)
    );
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dossier.join("journal.txt"))
        .and_then(|mut j| j.write_all(ligne.as_bytes()));
}

/// Tout ce qui est en quarantaine : le registre, puis les fichiers isolés avant la 0.61 (journal.txt seulement),
/// quand leur ligne est fidèle (un nom réécrit pour l'affichage ne se remettrait pas au bon endroit) et le fichier
/// toujours là.
fn liste_dans(dossier: &Path) -> Vec<Entree> {
    let mut fichiers: Vec<Entree> = charger(dossier)
        .fichiers
        .into_iter()
        .filter(|e| dossier.join(&e.nom).exists())
        .collect();
    let journal = std::fs::read_to_string(dossier.join("journal.txt")).unwrap_or_default();
    for l in journal.lines() {
        let c: Vec<&str> = l.split('\t').collect();
        let [date, detection, origine, nom] = c[..] else {
            continue;
        };
        let deja = fichiers.iter().any(|e| e.nom == nom);
        if deja || origine.contains('\u{fffd}') || nom.contains('\u{fffd}') || !dossier.join(nom).exists() {
            continue;
        }
        fichiers.push(Entree {
            nom: nom.to_string(),
            origine: origine.to_string(),
            detection: detection.to_string(),
            date: date.to_string(),
            mode: None,
        });
    }
    fichiers
}

/// Remet un fichier à sa place d'origine, avec ses permissions d'avant. Refuse d'écraser ce qui l'aurait remplacé.
fn remettre_dans(e: &Entree, dossier: &Path) -> Result<(), String> {
    let source = dossier.join(&e.nom);
    let origine = PathBuf::from(&e.origine);
    if origine.exists() {
        return Err(tr!(
            "un autre fichier est à sa place : rien n'est écrasé",
            "another file is in its place: nothing is overwritten"
        )
        .into());
    }
    if let Some(parent) = origine.parent() {
        std::fs::create_dir_all(parent).map_err(|x| x.to_string())?;
    }
    // Il faut pouvoir le lire pour le copier d'un disque à l'autre.
    #[cfg(unix)]
    let _ = std::fs::set_permissions(&source, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    #[cfg(windows)]
    if let Ok(m) = std::fs::metadata(&source) {
        let mut p = m.permissions();
        #[allow(clippy::permissions_set_readonly_false)] // le fichier redevient celui d'avant
        p.set_readonly(false);
        let _ = std::fs::set_permissions(&source, p);
    }
    std::fs::rename(&source, &origine)
        .or_else(|_| std::fs::copy(&source, &origine).and_then(|_| std::fs::remove_file(&source)))
        .map_err(|x| x.to_string())?;
    #[cfg(unix)]
    {
        // Sans mode noté (isolé avant la 0.61) : lecture et écriture pour soi, rien d'exécutable.
        let mode = e.mode.unwrap_or(0o600);
        let _ = std::fs::set_permissions(&origine, std::os::unix::fs::PermissionsExt::from_mode(mode));
    }
    retirer_du_registre(dossier, &e.nom);
    Ok(())
}

/// Remet à sa place le fichier isolé sous ce nom (l'annulation d'un blocage) ; même garde que le menu : rien n'est
/// écrasé.
pub(crate) fn remettre(nom: &str) -> Result<(), String> {
    let dossier = dossier();
    let e = liste_dans(&dossier)
        .into_iter()
        .find(|e| e.nom == nom)
        .ok_or_else(|| tr!("plus dans la quarantaine", "no longer in the quarantine").to_string())?;
    remettre_dans(&e, &dossier)
}

/// Le nombre de fichiers en quarantaine sur cet ordinateur.
pub(crate) fn nombre() -> usize {
    nombre_dans(&dossier())
}

/// Le nombre de fichiers isolés dans le dossier de quarantaine `dossier`.
pub(crate) fn nombre_dans(dossier: &Path) -> usize {
    liste_dans(dossier).len()
}

/// Supprime pour de bon un fichier de la quarantaine.
fn supprimer_dans(e: &Entree, dossier: &Path) -> Result<(), String> {
    let chemin = dossier.join(&e.nom);
    #[cfg(windows)]
    if let Ok(m) = std::fs::metadata(&chemin) {
        let mut p = m.permissions();
        #[allow(clippy::permissions_set_readonly_false)] // il va être supprimé
        p.set_readonly(false);
        let _ = std::fs::set_permissions(&chemin, p);
    }
    std::fs::remove_file(&chemin).map_err(|x| x.to_string())?;
    retirer_du_registre(dossier, &e.nom);
    Ok(())
}

fn retirer_du_registre(dossier: &Path, nom: &str) {
    let mut r = charger(dossier);
    let avant = r.fichiers.len();
    r.fichiers.retain(|x| x.nom != nom);
    if r.fichiers.len() != avant {
        let _ = enregistrer(dossier, &r);
    }
}

/// Après une analyse : propose d'isoler les fichiers trouvés, (chemin, détection). Rien sans accord.
pub fn proposer(trouves: &[(PathBuf, String)]) {
    if trouves.is_empty() {
        return;
    }
    let rep = demander(tr!(
        "\n  Les mettre en quarantaine (réversible : menu Antivirus et protection › Quarantaine) ? [o/N] : ",
        "\n  Quarantine them (reversible: menu Antivirus and protection › Quarantine)? [y/N]: "
    ));
    if !rep.oui() {
        trp!(
            "  Rien n'a été fait : les fichiers restent à leur place.",
            "  Nothing was done: the files stay where they are."
        );
        return;
    }
    for (chemin, detection) in trouves {
        let montre = chemin_affichable(chemin);
        match isoler(chemin, detection) {
            Ok(_) => println!("  {VERT}✔{RESET} {montre}"),
            Err(e) => trp!(
                "  ✖ {montre} : {e} (fichier du système ? relancer avec les droits administrateur)",
                "  ✖ {montre}: {e} (system file? run again with administrator rights)"
            ),
        }
    }
}

/// Menu Antivirus et protection › Quarantaine (`vanguard quarantaine`) : ce qui est isolé, à remettre ou à supprimer.
pub fn menu() {
    titre(tr!("Quarantaine", "Quarantine"));
    let dossier = dossier();
    loop {
        let fichiers = liste_dans(&dossier);
        if fichiers.is_empty() {
            trp!("  La quarantaine est vide.", "  The quarantine is empty.");
            return;
        }
        for (i, e) in fichiers.iter().enumerate() {
            println!("  {TOUCHE}{:>2}{RESET}  {}", i + 1, affichable(&e.origine));
            println!(
                "      {GRIS}{} · {}{RESET}",
                affichable(&e.detection),
                e.date.get(..16).unwrap_or(&e.date)
            );
        }
        let choix = demander(tr!(
            "\n  Numéro du fichier (Entrée pour revenir) : ",
            "\n  File number (Enter to go back): "
        ));
        let Some(e) = choix
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| fichiers.get(i))
        else {
            return;
        };
        let montre = affichable(&e.origine);
        let action = demander(&trf!(
            "  « {montre} » : [r]emettre à sa place (faux positif) / [s]upprimer pour de bon / Entrée : rien : ",
            "  “{montre}”: [r]estore to its place (false positive) / [d]elete for good / Enter: nothing: "
        ))
        .to_lowercase();
        let resultat = match action.trim() {
            "r" => remettre_dans(e, &dossier),
            "s" | "d" => supprimer_dans(e, &dossier),
            _ => continue,
        };
        match resultat {
            Ok(()) => trp!("  {VERT}✔{RESET} Fait.", "  {VERT}✔{RESET} Done."),
            Err(x) => trp!("  ✖ {x}", "  ✖ {x}"),
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-quarantaine-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn isole_puis_remet_a_l_identique() {
        let maison = jetable("maison");
        let q = maison.join("quarantaine");
        let fichier = maison.join("Téléchargements").join("facture.pdf.exe");
        std::fs::create_dir_all(fichier.parent().unwrap()).unwrap();
        std::fs::write(&fichier, b"MZ contenu").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&fichier, std::os::unix::fs::PermissionsExt::from_mode(0o751)).unwrap();
        let dest = isoler_dans(&fichier, "Win32.Trojan.Exemple", &q).unwrap();
        assert!(!fichier.exists() && dest.exists());
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&dest).unwrap().permissions()) & 0o777,
            0
        );
        let liste = liste_dans(&q);
        assert_eq!(liste.len(), 1);
        assert_eq!(liste[0].origine, fichier.to_string_lossy());
        // Un autre fichier a pris sa place : rien n'est écrasé.
        std::fs::write(&fichier, b"nouveau").unwrap();
        assert!(remettre_dans(&liste[0], &q).is_err());
        assert_eq!(std::fs::read(&fichier).unwrap(), b"nouveau");
        std::fs::remove_file(&fichier).unwrap();
        // Remis : même contenu, mêmes permissions, sorti du registre.
        remettre_dans(&liste[0], &q).unwrap();
        assert_eq!(std::fs::read(&fichier).unwrap(), b"MZ contenu");
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&fichier).unwrap().permissions()) & 0o777,
            0o751
        );
        assert_eq!(liste_dans(&q), Vec::<Entree>::new());
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Le journal de la quarantaine se lit avec cat : un nom piégé n'y pilote pas le terminal, et ses tabulations ou
    /// sauts de ligne ne cassent pas les quatre colonnes.
    #[test]
    fn journal_de_quarantaine_sans_piege() {
        let d = jetable("journal");
        noter_journal(
            &d,
            &Entree {
                nom: "x.q".into(),
                origine: "/home/alice/a\tb\x1b[2K\nc".into(),
                detection: "Eicar\x07".into(),
                date: "2026-10-18 23:00:00".into(),
                mode: None,
            },
        );
        let journal = std::fs::read_to_string(d.join("journal.txt")).unwrap();
        assert_eq!(journal.lines().count(), 1, "{journal:?}");
        let champs: Vec<&str> = journal.trim_end().split('\t').collect();
        assert_eq!(champs.len(), 4, "{journal:?}");
        assert_eq!(champs[1], "Eicar\u{fffd}");
        assert_eq!(champs[2], "/home/alice/a\u{fffd}b\u{fffd}[2K\u{fffd}c");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn anciennes_lignes_du_journal_et_suppression() {
        let q = jetable("ancien");
        // Isolé avant la 0.61 : journal.txt seulement.
        std::fs::write(q.join("123.outil.sh"), b"#!/bin/sh").unwrap();
        std::fs::write(
            q.join("journal.txt"),
            "2026-10-01 10:00:00\tEicar\t/home/alice/outil.sh\t123.outil.sh\n\
             2026-10-01 10:00:01\tEicar\t/home/alice/pi\u{fffd}ge.sh\t124.pi\u{fffd}ge.sh\n\
             2026-10-01 10:00:02\tEicar\t/home/alice/parti.sh\t125.parti.sh\n",
        )
        .unwrap();
        let liste = liste_dans(&q);
        // Le nom réécrit pour l'affichage et le fichier disparu ne sont pas proposés.
        assert_eq!(liste.len(), 1);
        assert_eq!(liste[0].origine, "/home/alice/outil.sh");
        assert_eq!(liste[0].mode, None);
        supprimer_dans(&liste[0], &q).unwrap();
        assert_eq!(liste_dans(&q), Vec::<Entree>::new());
        let _ = std::fs::remove_dir_all(&q);
    }
}
