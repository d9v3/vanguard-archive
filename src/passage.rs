//! Passage de l'ancien nom à Vanguard. Le programme s'appelait autrement jusqu'à la 0.78 : ce qu'une version d'avant a
//! posé sur un ordinateur porte encore cet ancien nom (dossier des données, minuteries, tâches planifiées, raccourcis,
//! règles du pare-feu, dossiers sur les disques, fichiers posés par une correction). Ce module est le seul endroit du
//! code qui le connaît : au premier lancement, il reprend ce qui peut l'être, et il aide les autres modules à
//! reconnaître le reste, pour pouvoir encore l'annuler ou le retirer. Rien ne se perd, même sur un ordinateur oublié.
//! À retirer à la 1.0.

use std::path::{Path, PathBuf};

/// L'ancien nom d'un nom de Vanguard, dans la même casse : « vanguard-surveillance » → son équivalent d'avant.
pub(crate) fn ancien(nom: &str) -> String {
    nom.replace("VANGUARD", "GARDIEN")
        .replace("Vanguard", "Gardien")
        .replace("vanguard", "gardien")
}

/// Le nom et son ancien équivalent, pour reconnaître l'un ou l'autre.
pub(crate) fn les_deux(nom: &str) -> [String; 2] {
    [nom.to_string(), ancien(nom)]
}

/// Le nom et son ancien équivalent en liste PowerShell (« 'a','b' »), pour un paramètre qui accepte plusieurs noms.
#[cfg(any(windows, test))]
pub(crate) fn liste_ps(nom: &str) -> String {
    les_deux(nom)
        .iter()
        .map(|n| format!("'{}'", crate::commande::ps_texte(n)))
        .collect::<Vec<_>>()
        .join(",")
}

/// Une variable d'environnement de Vanguard, ou à défaut son ancien nom : une clé HIBP ou une langue posée avant le
/// changement de nom continue de servir.
pub(crate) fn variable(nom: &str) -> Option<String> {
    std::env::var(nom).ok().or_else(|| std::env::var(ancien(nom)).ok())
}

/// Un fichier JSON de Vanguard (sauvegarde des données, manifeste de la clé) écrit sous l'ancien nom : son format et
/// ses champs reprennent le nouveau. Rien ne change pour un autre fichier.
pub(crate) fn reprendre_format(valeur: &mut serde_json::Value, format: &str) {
    let Some(objet) = valeur.as_object_mut() else {
        return;
    };
    if objet.get("format").and_then(|f| f.as_str()) != Some(ancien(format).as_str()) {
        return;
    }
    let a_renommer: Vec<String> = objet
        .keys()
        .filter(|k| k.contains(&ancien("vanguard")))
        .cloned()
        .collect();
    for cle in a_renommer {
        if let Some(v) = objet.remove(&cle) {
            objet.insert(cle.replace(&ancien("vanguard"), "vanguard"), v);
        }
    }
    objet.insert("format".into(), format.into());
}

/// Au lancement : si le dossier des données d'une version d'avant existe encore, tout ce qu'elle a posé passe à
/// Vanguard, une seule fois (le dossier déplacé, la question ne se repose plus). Jamais depuis un test : les vraies
/// données de l'ordinateur de développement ne doivent pas bouger.
pub(crate) fn au_lancement() {
    if cfg!(test) {
        return;
    }
    let nouveau = crate::reseau::dossier_local();
    let vieux = nouveau.with_file_name(ancien("vanguard"));
    if !vieux.is_dir() {
        return;
    }
    eprintln!(
        "{}",
        crate::tr!(
            "  Ce programme s'appelle maintenant Vanguard : reprise des données et des réglages de la version d'avant.",
            "  This program is now called Vanguard: taking over the data and settings of the previous version."
        )
    );
    if let Err(e) = deplacer_donnees(&vieux, &nouveau) {
        eprintln!(
            "{}",
            crate::trf!(
                "  ✖ Données non déplacées ({e}) : nouvel essai au prochain lancement.",
                "  ✖ Data not moved ({e}): another try at the next start."
            )
        );
        return;
    }
    let surveillance = retirer_minuterie(&ancien("vanguard-surveillance"));
    let entretien = retirer_minuterie(&ancien("vanguard-entretien"));
    #[cfg(target_os = "linux")]
    let sauvegarde = reprendre_sauvegarde();
    #[cfg(not(target_os = "linux"))]
    let sauvegarde = false;
    let raccourci = retirer_raccourci();
    // Le programme copié par la version d'avant pour ses minuteries (lancée depuis la clé) : remplacé ci-dessous.
    let _ = std::fs::remove_file(nouveau.join("bin").join(format!(
        "{}{}",
        ancien("vanguard"),
        std::env::consts::EXE_SUFFIX
    )));
    let exe = crate::reseau::surveillance::executable();
    let mut repris = Vec::new();
    if surveillance && crate::reseau::surveillance::reprendre(&exe) {
        repris.push(crate::tr!("surveillance horaire", "hourly monitoring"));
    }
    if entretien && crate::entretien::reprendre(&exe) {
        repris.push(crate::tr!("entretien du mois", "monthly check-up"));
    }
    if sauvegarde {
        repris.push(crate::tr!("sauvegarde automatique", "automatic backup"));
    }
    if let Some(ou) = raccourci
        && crate::raccourci::reprendre(&exe, &ou)
    {
        repris.push(crate::tr!("raccourci", "shortcut"));
    }
    if !repris.is_empty() {
        eprintln!(
            "{}",
            crate::trf!(
                "  ✔ Repris sous le nom Vanguard : {}.",
                "  ✔ Taken over under the Vanguard name: {}.",
                repris.join(", ")
            )
        );
    }
}

/// Le dossier des données change de nom. Si Vanguard en a déjà un (lancé avant la reprise), ce qui n'y est pas encore
/// y passe, et le reste de l'ancien dossier y est gardé à part, jamais effacé.
fn deplacer_donnees(vieux: &Path, nouveau: &Path) -> std::io::Result<()> {
    if !nouveau.exists() {
        return std::fs::rename(vieux, nouveau);
    }
    for entree in std::fs::read_dir(vieux)?.flatten() {
        let cible = nouveau.join(entree.file_name());
        if !cible.exists() {
            std::fs::rename(entree.path(), cible)?;
        }
    }
    let reste = nouveau.join("reprise-version-d-avant");
    if std::fs::read_dir(vieux)?.next().is_none() {
        std::fs::remove_dir(vieux)
    } else if reste.exists() {
        std::fs::rename(
            vieux,
            reste.join(chrono::Local::now().format("%Y%m%d-%H%M%S").to_string()),
        )
    } else {
        std::fs::rename(vieux, reste)
    }
}

/// Retire la minuterie, l'agent ou la tâche planifiée d'avant, de ce nom ; dit s'il était actif (il est alors recréé
/// sous le nouveau nom, avec le programme d'aujourd'hui).
fn retirer_minuterie(nom: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        let dossier = dossier_systemd();
        if !dossier.join(format!("{nom}.timer")).exists() {
            return false;
        }
        let actif =
            crate::reseau::surveillance::reussit("systemctl", &["--user", "is-enabled", &format!("{nom}.timer")]);
        crate::reseau::surveillance::reussit("systemctl", &["--user", "disable", "--now", &format!("{nom}.timer")]);
        let _ = std::fs::remove_file(dossier.join(format!("{nom}.service")));
        let _ = std::fs::remove_file(dossier.join(format!("{nom}.timer")));
        crate::reseau::surveillance::reussit("systemctl", &["--user", "daemon-reload"]);
        actif
    }
    #[cfg(target_os = "macos")]
    {
        let agent = format!("com.{}", nom.replacen('-', ".", 1));
        let plist = PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join(format!("Library/LaunchAgents/{agent}.plist"));
        if !plist.exists() {
            return false;
        }
        let domaine = crate::reseau::surveillance::domaine_launchd();
        let actif = crate::reseau::surveillance::reussit("launchctl", &["print", &format!("{domaine}/{agent}")]);
        let _ = crate::reseau::surveillance::reussit("launchctl", &["bootout", &domaine, &plist.display().to_string()]);
        let _ = std::fs::remove_file(&plist);
        actif
    }
    #[cfg(windows)]
    {
        // « gardien-surveillance » → la tâche « … - surveillance du reseau » (le nom lisible de la tâche).
        let tache = tache_windows(nom);
        // Absente pour le planificateur : rien à retirer, sans PowerShell.
        if crate::machine::windows::planificateur::etat(&[&tache])
            == Some(crate::machine::windows::planificateur::EtatTache::Absente)
        {
            return false;
        }
        let e = crate::commande::ps_texte(&tache);
        crate::machine::windows::ps(&format!(
            "$t = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName -eq '{e}' }}; \
             if ($t) {{ if ($t.State -ne 'Disabled') {{ 'actif' }}; Unregister-ScheduledTask -TaskName '{e}' -Confirm:$false }}"
        ))
        .is_some_and(|s| s.trim() == "actif")
    }
}

/// Le nom lisible de la tâche planifiée Windows d'avant, d'après le nom court de la minuterie.
#[cfg(any(windows, test))]
fn tache_windows(nom: &str) -> String {
    let (programme, quoi) = nom.split_once('-').unwrap_or((nom, ""));
    let lisible = match quoi {
        "surveillance" => "surveillance du reseau",
        "entretien" => "entretien du mois",
        autre => autre,
    };
    format!("{programme} - {lisible}")
}

#[cfg(target_os = "linux")]
fn dossier_systemd() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config/systemd/user")
}

/// Sauvegarde automatique de Linux (minuterie rsync) : ses deux unités prennent le nouveau nom, avec le même contenu
/// (le même disque, le même dossier dessus : pas de nouvelle copie complète à côté de l'ancienne), et la note qui sert
/// à l'annuler suit. Dit si elle a été reprise.
#[cfg(target_os = "linux")]
fn reprendre_sauvegarde() -> bool {
    let dossier = dossier_systemd();
    let [timer, service] = ["vanguard-sauvegarde.timer", "vanguard-sauvegarde.service"];
    let (vieux_timer, vieux_service) = (dossier.join(ancien(timer)), dossier.join(ancien(service)));
    let (Ok(t), Ok(s)) = (
        std::fs::read_to_string(&vieux_timer),
        std::fs::read_to_string(&vieux_service),
    ) else {
        return false;
    };
    let actif = crate::reseau::surveillance::reussit("systemctl", &["--user", "is-enabled", &ancien(timer)]);
    let (t, s) = (unite_sauvegarde(&t), unite_sauvegarde(&s));
    if std::fs::write(dossier.join(timer), &t).is_err() || std::fs::write(dossier.join(service), &s).is_err() {
        return false;
    }
    crate::reseau::surveillance::reussit("systemctl", &["--user", "disable", "--now", &ancien(timer)]);
    let _ = std::fs::remove_file(&vieux_timer);
    let _ = std::fs::remove_file(&vieux_service);
    crate::reseau::surveillance::reussit("systemctl", &["--user", "daemon-reload"]);
    if actif {
        crate::reseau::surveillance::reussit("systemctl", &["--user", "enable", "--now", timer]);
    }
    crate::sauvegarde::reprendre_note(&t, &s);
    true
}

/// Une unité de la sauvegarde d'avant, au nouveau nom : le nom du programme dans la description (le premier : la
/// suite est le chemin du disque) et le témoin des copies en cours exclu de la sauvegarde. Le dossier sur le disque
/// reste le même, la description continue de le dire tel qu'il est.
#[cfg(any(target_os = "linux", test))]
fn unite_sauvegarde(texte: &str) -> String {
    texte
        .lines()
        .map(|l| {
            if l.starts_with("Description=") {
                l.replacen(&ancien("Vanguard"), "Vanguard", 1)
            } else if l.starts_with("ExecStart=") {
                let temoin = ".vanguard-copie-en-cours";
                l.replace(&format!("--exclude={}", ancien(temoin)), &format!("--exclude={temoin}"))
            } else {
                l.to_string()
            }
        })
        .map(|l| l + "\n")
        .collect()
}

/// Le raccourci d'avant, s'il a été posé par la version d'avant : retiré ; rend l'endroit où poser le nouveau.
fn retirer_raccourci() -> Option<PathBuf> {
    let nouveau = crate::raccourci::chemin()?;
    let nom = nouveau.file_name()?.to_string_lossy().to_string();
    let vieux = nouveau.with_file_name(ancien(&nom));
    let a_lui =
        cfg!(windows) || std::fs::read_to_string(&vieux).is_ok_and(|t| t.contains(&ancien(crate::raccourci::MARQUE)));
    if !vieux.exists() || !a_lui {
        return None;
    }
    std::fs::remove_file(&vieux).ok()?;
    #[cfg(target_os = "linux")]
    if let Some(donnees) = nouveau.parent().and_then(Path::parent) {
        let _ = std::fs::remove_file(donnees.join(format!("icons/hicolor/128x128/apps/{}.png", ancien("vanguard"))));
    }
    (!nouveau.exists()).then_some(nouveau)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancien_nom_dans_chaque_casse() {
        assert_eq!(ancien("Vanguard : bloquer *"), "Gardien : bloquer *");
        assert_eq!(ancien("VANGUARD_HIBP_CLE"), "GARDIEN_HIBP_CLE");
        assert_eq!(ancien(".vanguard-copie-en-cours"), ".gardien-copie-en-cours");
        assert_eq!(les_deux("Vanguard-copie-"), ["Vanguard-copie-", "Gardien-copie-"]);
        assert_eq!(
            liste_ps("Vanguard : bloquer *"),
            "'Vanguard : bloquer *','Gardien : bloquer *'"
        );
    }

    #[test]
    fn format_d_avant_repris() {
        let mut v: serde_json::Value =
            serde_json::from_str(r#"{"format":"gardien-sauvegarde","version_gardien":"0.77.0","base":{}}"#).unwrap();
        reprendre_format(&mut v, "vanguard-sauvegarde");
        assert_eq!(v["format"], "vanguard-sauvegarde");
        assert_eq!(v["version_vanguard"], "0.77.0");
        assert!(v.get("version_gardien").is_none());
        // Un autre fichier n'est pas touché.
        let mut autre: serde_json::Value = serde_json::from_str(r#"{"format":"autre","gardien":1}"#).unwrap();
        reprendre_format(&mut autre, "vanguard-sauvegarde");
        assert_eq!(autre["gardien"], 1);
    }

    #[test]
    fn taches_windows_d_avant() {
        assert_eq!(
            tache_windows("gardien-surveillance"),
            "gardien - surveillance du reseau"
        );
        assert_eq!(tache_windows("gardien-entretien"), "gardien - entretien du mois");
    }

    #[test]
    fn unites_de_sauvegarde_reprises() {
        let service = "[Unit]\nDescription=Sauvegarde Gardien vers /run/media/alice/Externe/Sauvegarde-Gardien/pc\n\
                       ConditionPathIsMountPoint=/run/media/alice/Externe\n\n[Service]\nType=oneshot\n\
                       ExecStart=\"/usr/bin/rsync\" -a --exclude=.cache --exclude=.gardien-copie-en-cours \"/home/alice/Documents\" \"/run/media/alice/Externe/Sauvegarde-Gardien/pc/\"\n";
        let repris = unite_sauvegarde(service);
        assert!(repris.contains("Description=Sauvegarde Vanguard vers /run/media/alice/Externe/Sauvegarde-Gardien/pc"));
        // Le dossier sur le disque ne bouge pas, seul le témoin exclu suit.
        assert!(repris.contains("--exclude=.vanguard-copie-en-cours \"/home/alice/Documents\" \"/run/media/alice/Externe/Sauvegarde-Gardien/pc/\""));
    }

    #[test]
    fn donnees_d_avant_deplacees_sans_rien_perdre() {
        let base = std::env::temp_dir().join(format!("vanguard-passage-{}", std::process::id()));
        let (vieux, nouveau) = (base.join("ancien"), base.join("nouveau"));
        std::fs::create_dir_all(vieux.join("quarantaine")).unwrap();
        std::fs::write(vieux.join("historique.json"), "avant").unwrap();
        std::fs::write(vieux.join("appareils.json"), "avant").unwrap();
        // Vanguard a déjà tourné une fois : son historique reste, celui d'avant est gardé à part.
        std::fs::create_dir_all(&nouveau).unwrap();
        std::fs::write(nouveau.join("historique.json"), "nouveau").unwrap();
        deplacer_donnees(&vieux, &nouveau).unwrap();
        assert!(!vieux.exists());
        assert_eq!(
            std::fs::read_to_string(nouveau.join("historique.json")).unwrap(),
            "nouveau"
        );
        assert_eq!(
            std::fs::read_to_string(nouveau.join("appareils.json")).unwrap(),
            "avant"
        );
        assert!(nouveau.join("quarantaine").is_dir());
        assert_eq!(
            std::fs::read_to_string(nouveau.join("reprise-version-d-avant/historique.json")).unwrap(),
            "avant"
        );
        // Sans dossier de Vanguard : simple changement de nom.
        let (vieux2, nouveau2) = (base.join("ancien2"), base.join("nouveau2"));
        std::fs::create_dir_all(&vieux2).unwrap();
        std::fs::write(vieux2.join("a"), "1").unwrap();
        deplacer_donnees(&vieux2, &nouveau2).unwrap();
        assert_eq!(std::fs::read_to_string(nouveau2.join("a")).unwrap(), "1");
        let _ = std::fs::remove_dir_all(base);
    }
}
