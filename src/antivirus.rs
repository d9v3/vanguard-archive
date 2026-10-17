//! Recherche de malwares avec un moteur reconnu (ClamAV sous Linux, Microsoft Defender sous Windows)
//! et revue des programmes lancés au démarrage, là où un malware cherche à se maintenir.

use std::path::PathBuf;
use std::process::Command;

use crate::risk::Niveau;
use crate::ui::*;

#[cfg(unix)]
fn home() -> PathBuf {
    PathBuf::from(
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .unwrap_or_default(),
    )
}

pub fn analyser(complet: bool) {
    titre(if complet {
        "Analyse antivirus complète"
    } else {
        "Analyse antivirus rapide"
    });
    #[cfg(windows)]
    defender(complet);
    #[cfg(unix)]
    clamav(complet);
    demarrage();
}

// ───────────────────────────── Windows : Microsoft Defender ─────────────────────────────

#[cfg(windows)]
fn defender(complet: bool) {
    use crate::machine::windows::{powershell_admin, ps};
    let mpcmd =
        PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_default()).join(r"Windows Defender\MpCmdRun.exe");
    println!(
        "  {GRIS}Moteur : Microsoft Defender. Cela peut prendre de quelques minutes à une heure (analyse complète)…{RESET}"
    );
    let statut = Command::new(&mpcmd)
        .args(["-Scan", "-ScanType", if complet { "2" } else { "1" }])
        .status();
    match statut.map(|s| s.code()) {
        Ok(Some(0)) => println!("  {VERT}✔ Aucun malware trouvé.{RESET}"),
        Ok(Some(2)) => {
            let menaces = ps("Get-MpThreat | ForEach-Object { \"$($_.ThreatName)|$($_.Resources -join ', ')\" }")
                .unwrap_or_default();
            for l in menaces.lines() {
                let (nom, fichiers) = l.split_once('|').unwrap_or((l, ""));
                println!("  {}✖ {nom}{RESET}  {fichiers}", couleur(Niveau::Critique));
            }
            println!("  Defender a normalement déjà mis ces fichiers en quarantaine.");
            if demander("  Supprimer définitivement les menaces détectées ? [o/N] : ").eq_ignore_ascii_case("o")
                && powershell_admin(&["Remove-MpThreat".to_string()])
            {
                println!("  {VERT}✔ Menaces supprimées.{RESET}");
            }
        }
        _ => println!("  Defender n'a pas pu lancer l'analyse (antivirus tiers actif ?)."),
    }
}

// ───────────────────────────── Linux : ClamAV ─────────────────────────────

#[cfg(unix)]
fn shell(c: &str) -> bool {
    println!("  {GRIS}$ {c}{RESET}");
    Command::new("bash")
        .arg("-c")
        .arg(c)
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(unix)]
fn base_presente() -> bool {
    std::fs::read_dir("/var/lib/clamav").is_ok_and(|d| {
        d.flatten().any(|f| {
            std::path::Path::new(&f.file_name())
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("cvd") || e.eq_ignore_ascii_case("cld"))
        })
    })
}

/// Installe ClamAV et télécharge les signatures si besoin. Retourne `false` si l'utilisateur refuse.
#[cfg(unix)]
fn preparer() -> bool {
    let present = Command::new("bash")
        .args(["-c", "command -v clamscan"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !present {
        println!("  ClamAV (antivirus open source) n'est pas installé.");
        if !demander("  L'installer maintenant ? [o/N] : ").eq_ignore_ascii_case("o") {
            return false;
        }
        // Fedora sépare le moteur et l'outil de mise à jour des signatures.
        #[cfg(target_os = "linux")]
        let installation = match crate::machine::linux::Paquets::detecter() {
            Some(g @ crate::machine::linux::Paquets::Dnf) => g.installer("clamav clamav-update"),
            Some(g) => g.installer("clamav"),
            None => {
                println!("  Gestionnaire de paquets non reconnu : installe ClamAV avec l'outil de ta distribution.");
                return false;
            }
        };
        if !shell(&installation) {
            println!("  Installation impossible.");
            return false;
        }
    }
    if !base_presente() {
        println!("  Téléchargement des signatures de virus (~300 Mo, une seule fois)…");
        #[cfg(target_os = "linux")]
        // Sur Debian/Ubuntu/Mint, le service tourne déjà et verrouille la base : on l'arrête le temps du premier téléchargement.
        let ok = shell("sudo systemctl stop clamav-freshclam.service 2>/dev/null; sudo freshclam")
            && shell("sudo systemctl enable --now clamav-freshclam.service");
        if !ok {
            return false;
        }
    }
    true
}

#[cfg(unix)]
fn clamav(complet: bool) {
    if !preparer() {
        println!("  Analyse annulée.");
        return;
    }
    let h = home();
    let cibles: Vec<PathBuf> = if complet {
        vec![h.clone()]
    } else {
        [
            "Downloads",
            "Téléchargements",
            "Desktop",
            "Bureau",
            "Documents",
            ".local/bin",
            ".config/autostart",
        ]
        .iter()
        .map(|d| h.join(d))
        .chain([PathBuf::from("/tmp")])
        .filter(|p| p.exists())
        .collect()
    };
    let cibles = sans_doublons(cibles);
    // Jeux, caches et préfixes Wine sont énormes et produisent des faux positifs (cracks, outils anti-triche).
    let exclusions = [
        "Games",
        ".steam",
        ".local/share/Steam",
        ".cache",
        "Windows",
        ".cargo/registry",
        ".rustup",
        "target",
        "node_modules",
        // Dossiers privés des services systemd (root seul) : illisibles, ils feraient compter des erreurs.
        "systemd-private-[^/]*",
        ".local/share/netscan/quarantaine",
        ".snapshots",
        ".Trash",
    ];
    let mut cmd = Command::new("clamscan");
    // Le bilan final (fichiers analysés, infectés, erreurs) sert à juger si l'analyse a vraiment eu lieu.
    cmd.args(["-r", "-i", "--max-filesize=200M", "--max-scansize=400M"]);
    for e in exclusions {
        cmd.arg(format!("--exclude-dir={}", regex_echappe(e)));
    }
    cmd.args(&cibles);
    println!(
        "  {GRIS}Moteur : ClamAV. Analyse de : {}{RESET}",
        cibles
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  {GRIS}Cela peut prendre de quelques secondes à plusieurs minutes…{RESET}");

    let Ok(sortie) = cmd.output() else {
        println!("  Impossible de lancer clamscan.");
        return;
    };
    let Some(bilan) = lire_resultat(sortie.status.code(), &String::from_utf8_lossy(&sortie.stdout)) else {
        let erreur = String::from_utf8_lossy(&sortie.stderr);
        println!(
            "  {}✖ L'analyse a échoué : le résultat n'est pas fiable.{RESET}",
            couleur(Niveau::Eleve)
        );
        for l in erreur.lines().filter(|l| l.contains("ERROR")).take(5) {
            println!("    {GRIS}{l}{RESET}");
        }
        return;
    };

    let illisibles = if bilan.illisibles > 0 {
        format!(
            " ; {} élément(s) illisible(s) sans droits root, ignoré(s)",
            bilan.illisibles
        )
    } else {
        String::new()
    };
    println!("  {GRIS}{} fichier(s) analysé(s){illisibles}.{RESET}", bilan.analyses);
    // Ceinture et bretelles : un même fichier n'est proposé qu'une fois (sinon la 2e mise en quarantaine échoue).
    let mut infectes = bilan.infectes;
    let mut vus = std::collections::HashSet::new();
    infectes.retain(|(f, _)| vus.insert(f.clone()));
    if infectes.is_empty() {
        println!("  {VERT}✔ Aucun malware trouvé.{RESET}");
        return;
    }
    for (f, m) in &infectes {
        println!("  {}✖ {m}{RESET}  {f}", couleur(Niveau::Critique));
    }
    println!("\n  {} fichier(s) suspect(s).", infectes.len());
    let rep = demander("  [q]uarantaine (recommandé, réversible) / [s]upprimer / [r]ien : ").to_lowercase();
    let dossier = crate::reseau::dossier_local().join("quarantaine");
    let _ = std::fs::create_dir_all(&dossier);
    for (f, detection) in &infectes {
        let chemin = std::path::Path::new(f);
        let resultat = match rep.as_str() {
            "q" => isoler(chemin, &dossier).map(|dest| noter_quarantaine(&dossier, f, &dest, detection)),
            "s" => std::fs::remove_file(chemin),
            _ => continue,
        };
        match resultat {
            Ok(()) => println!("  {VERT}✔{RESET} {f}"),
            Err(e) => println!("  ✖ {f} : {e} (fichier système ? relancer avec sudo)"),
        }
    }
    if rep == "q" {
        println!(
            "  {GRIS}Quarantaine : {} (emplacement d'origine de chaque fichier noté dans journal.txt){RESET}",
            dossier.display()
        );
    }
}

/// Dossiers à analyser sans recouvrement : un ~/Desktop qui pointe vers ~/Bureau, ou un dossier contenu dans un
/// autre, faisait analyser deux fois les mêmes fichiers ; un fichier infecté était alors signalé deux fois et sa
/// seconde mise en quarantaine échouait (« fichier système ? »). Vu en test.
#[cfg(unix)]
fn sans_doublons(cibles: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut reels: Vec<PathBuf> = cibles.into_iter().map(|p| p.canonicalize().unwrap_or(p)).collect();
    // Trié, un dossier parent passe avant ce qu'il contient.
    reels.sort();
    reels.dedup();
    let mut garde: Vec<PathBuf> = Vec::new();
    for p in reels {
        if !garde.iter().any(|g| p.starts_with(g)) {
            garde.push(p);
        }
    }
    garde
}

/// Bilan d'une analyse ClamAV qui a vraiment eu lieu.
#[cfg(unix)]
#[derive(Debug, PartialEq)]
struct Bilan {
    infectes: Vec<(String, String)>,
    analyses: u64,
    /// Fichiers illisibles sans droits root (ignorés) : ClamAV renvoie alors le code 2 même si tout s'est bien passé.
    illisibles: u64,
}

/// Résultat de clamscan, `None` si l'analyse n'a pas eu lieu (base absente, plantage…).
/// On se fie au bilan final plutôt qu'au code de retour : sur un Linux normal, quelques dossiers de /tmp
/// appartiennent à root, et ClamAV répond « erreur » (code 2) après avoir analysé tout le reste (vu en réel).
#[cfg(unix)]
fn lire_resultat(code: Option<i32>, sortie: &str) -> Option<Bilan> {
    let infectes: Vec<(String, String)> = sortie
        .lines()
        .filter_map(|l| {
            let (fichier, menace) = l.strip_suffix(" FOUND")?.rsplit_once(": ")?;
            Some((fichier.to_string(), menace.to_string()))
        })
        .collect();
    let champ = |nom: &str| {
        sortie
            .lines()
            .find_map(|l| l.strip_prefix(nom)?.trim().parse::<u64>().ok())
    };
    let analyses = champ("Scanned files:")?;
    let annonces = champ("Infected files:")?;
    let illisibles = champ("Total errors:").unwrap_or(0);
    // Le nombre de fichiers infectés annoncé doit correspondre aux lignes lues, sinon on ne sait pas quoi isoler.
    if !matches!(code, Some(0..=2)) || annonces != infectes.len() as u64 {
        return None;
    }
    Some(Bilan {
        infectes,
        analyses,
        illisibles,
    })
}

/// Note d'où vient chaque fichier mis en quarantaine : sans cela, un faux positif ne pouvait pas être remis à
/// sa place (son nom en quarantaine ne garde pas le dossier d'origine). Vu en test.
#[cfg(unix)]
fn noter_quarantaine(dossier: &std::path::Path, origine: &str, dest: &std::path::Path, detection: &str) {
    use std::io::Write;
    let ligne = format!(
        "{}\t{detection}\t{origine}\t{}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        dest.file_name().unwrap_or_default().to_string_lossy()
    );
    let ecrit = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dossier.join("journal.txt"))
        .and_then(|mut j| j.write_all(ligne.as_bytes()));
    if let Err(e) = ecrit {
        println!("  Attention : journal de la quarantaine non écrit ({e}). Origine : {origine}");
    }
}

/// Déplace un fichier en quarantaine et lui retire toute permission : il ne peut plus être lancé ni ouvert.
#[cfg(unix)]
fn isoler(chemin: &std::path::Path, dossier: &std::path::Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dossier)?;
    let nom = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let horodatage = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dest = dossier.join(format!("{horodatage}.{nom}"));
    // rename échoue d'un disque à l'autre (clé USB → disque) : on copie puis on supprime.
    std::fs::rename(chemin, &dest).or_else(|_| {
        std::fs::copy(chemin, &dest)?;
        // Original impossible à supprimer : on ne laisse pas une seconde copie, encore exécutable, en quarantaine.
        std::fs::remove_file(chemin).inspect_err(|_| {
            let _ = std::fs::remove_file(&dest);
        })
    })?;
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o000))?;
    Ok(dest)
}

/// --exclude-dir attend une expression régulière : on échappe les points.
#[cfg(unix)]
fn regex_echappe(dossier: &str) -> String {
    // Le chemin du dossier n'a pas de « / » final : on accepte la fin de chaîne.
    format!("/{}(/|$)", dossier.replace('.', "\\."))
}

// ───────────────────────────── Démarrage automatique ─────────────────────────────

fn demarrage() {
    titre("Programmes lancés au démarrage (à vérifier)");
    let mut entrees: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let h = home();
        for d in [".config/autostart", ".config/systemd/user"] {
            for f in std::fs::read_dir(h.join(d)).into_iter().flatten().flatten() {
                if f.path().is_file() {
                    entrees.push(f.path().display().to_string());
                }
            }
        }
        if let Ok(o) = Command::new("crontab").arg("-l").output() {
            for l in String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            {
                entrees.push(format!("crontab : {l}"));
            }
        }
        for f in std::fs::read_dir("/etc/systemd/system").into_iter().flatten().flatten() {
            let p = f.path();
            // Services ajoutés à la main (pas par un paquet) : endroit classique pour une persistance root.
            if p.extension().is_some_and(|e| e == "service") && p.is_file() && !p.is_symlink() {
                let possede = crate::machine::linux::Paquets::detecter().is_none_or(|g| g.possede(&p));
                if !possede {
                    entrees.push(format!("{} (service système hors paquet)", p.display()));
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use crate::machine::windows::ps;
        let script = "Get-CimInstance Win32_StartupCommand | ForEach-Object { \"$($_.Name) — $($_.Command)\" }; \
                      Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | \
                      ForEach-Object { \"tâche planifiée : $($_.TaskName) — $($_.Actions.Execute)\" }";
        entrees.extend(ps(script).unwrap_or_default().lines().map(str::to_string));
    }

    if entrees.is_empty() {
        println!("  {VERT}✔{RESET} Rien de particulier.");
    }
    for e in entrees {
        println!("  • {e}");
    }
    println!("  {GRIS}Si tu ne reconnais pas une entrée, renseigne-toi avant de la supprimer.{RESET}");
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn resultat_clamscan() {
        let bilan = |infectes: u64, erreurs: u64| {
            format!(
                "\n----------- SCAN SUMMARY -----------\nScanned files: 12683\nInfected files: {infectes}\nTotal errors: {erreurs}\n"
            )
        };
        // Cas réel : 0 infecté, 7 dossiers de /tmp illisibles, code 2 → analyse valable.
        let r = lire_resultat(Some(2), &bilan(0, 7)).unwrap();
        assert_eq!((r.infectes.len(), r.analyses, r.illisibles), (0, 12683, 7));
        let deux = format!(
            "/home/x/Téléchargements/eicar.com: Eicar-Test-Signature FOUND\n/tmp/a b.exe: Win.Trojan.Agent-123 FOUND\n{}",
            bilan(2, 0)
        );
        let r = lire_resultat(Some(1), &deux).unwrap();
        assert_eq!(
            r.infectes[1],
            ("/tmp/a b.exe".to_string(), "Win.Trojan.Agent-123".to_string())
        );
        // Pas de bilan (base absente, plantage) : jamais « aucun malware ».
        assert!(lire_resultat(Some(2), "ERROR: Can't open database").is_none());
        assert!(lire_resultat(None, &bilan(0, 0)).is_none());
        // Infectés annoncés mais lignes illisibles : pas fiable.
        assert!(lire_resultat(Some(1), &bilan(1, 0)).is_none());
    }

    #[test]
    fn quarantaine_retire_le_fichier_et_ses_droits() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("netscan-test-{}", std::process::id()));
        let suspect = base.join("suspect.sh");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(&suspect, "#!/bin/sh\necho pirate\n").unwrap();
        let dest = isoler(&suspect, &base.join("quarantaine")).unwrap();
        assert!(!suspect.exists());
        assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0);
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn dossiers_analyses_une_seule_fois() {
        let base = std::env::temp_dir().join(format!("netscan-cibles-{}", std::process::id()));
        let bureau = base.join("Bureau");
        std::fs::create_dir_all(bureau.join("sous")).unwrap();
        std::os::unix::fs::symlink(&bureau, base.join("Desktop")).unwrap();
        let reel = bureau.canonicalize().unwrap();
        // Desktop → Bureau, et un sous-dossier de Bureau : il ne reste que Bureau.
        assert_eq!(
            sans_doublons(vec![base.join("Desktop"), bureau.clone(), bureau.join("sous")]),
            vec![reel]
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn exclusions_en_expression_reguliere() {
        assert_eq!(regex_echappe(".steam"), "/\\.steam(/|$)");
    }
}
