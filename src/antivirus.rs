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
        tr!("Analyse antivirus complète", "Full antivirus scan")
    } else {
        tr!("Analyse antivirus rapide", "Quick antivirus scan")
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
    trp!(
        "  {GRIS}Moteur : Microsoft Defender. Cela peut prendre de quelques minutes à une heure (analyse complète)…{RESET}",
        "  {GRIS}Engine: Microsoft Defender. This can take from a few minutes to an hour (full scan)…{RESET}"
    );
    let statut = Command::new(&mpcmd)
        .args(["-Scan", "-ScanType", if complet { "2" } else { "1" }])
        .status();
    match statut.map(|s| s.code()) {
        Ok(Some(0)) => trp!(
            "  {VERT}✔ Aucun malware trouvé.{RESET}",
            "  {VERT}✔ No malware found.{RESET}"
        ),
        Ok(Some(2)) => {
            let menaces = ps("Get-MpThreat | ForEach-Object { \"$($_.ThreatName)|$($_.Resources -join ', ')\" }")
                .unwrap_or_default();
            for l in menaces.lines() {
                let (nom, fichiers) = l.split_once('|').unwrap_or((l, ""));
                println!("  {}✖ {nom}{RESET}  {fichiers}", couleur(Niveau::Critique));
            }
            trp!(
                "  Defender a normalement déjà mis ces fichiers en quarantaine.",
                "  Defender has normally already quarantined these files."
            );
            if demander(tr!(
                "  Supprimer définitivement les menaces détectées ? [o/N] : ",
                "  Permanently delete the detected threats? [y/N]: "
            ))
            .oui()
                && powershell_admin(&["Remove-MpThreat".to_string()])
            {
                trp!(
                    "  {VERT}✔ Menaces supprimées.{RESET}",
                    "  {VERT}✔ Threats deleted.{RESET}"
                );
            }
        }
        _ => trp!(
            "  Defender n'a pas pu lancer l'analyse (antivirus tiers actif ?).",
            "  Defender could not start the scan (third-party antivirus active?)."
        ),
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
        trp!(
            "  ClamAV (antivirus open source) n'est pas installé.",
            "  ClamAV (open source antivirus) is not installed."
        );
        if !demander(tr!("  L'installer maintenant ? [o/N] : ", "  Install it now? [y/N]: ")).oui() {
            return false;
        }
        // Fedora sépare le moteur et l'outil de mise à jour des signatures.
        #[cfg(target_os = "linux")]
        let installation = match crate::machine::linux::Paquets::detecter() {
            Some(g @ crate::machine::linux::Paquets::Dnf) => g.installer("clamav clamav-update"),
            Some(g) => g.installer("clamav"),
            None => {
                trp!(
                    "  Gestionnaire de paquets non reconnu : installe ClamAV avec l'outil de ta distribution.",
                    "  Package manager not recognized: install ClamAV with your distribution's tool."
                );
                return false;
            }
        };
        if !shell(&installation) {
            trp!("  Installation impossible.", "  Installation failed.");
            return false;
        }
    }
    if !base_presente() {
        trp!(
            "  Téléchargement des signatures de virus (~300 Mo, une seule fois)…",
            "  Downloading the virus signatures (~300 MB, only once)…"
        );
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
        trp!("  Analyse annulée.", "  Scan cancelled.");
        return;
    }
    let h = home();
    // Analyse rapide : là où arrivent les menaces (téléchargements, bureau, démarrage automatique, programmes de
    // l'utilisateur). Documents passe par l'analyse complète : des milliers de fichiers, rarement une porte d'entrée.
    let cibles: Vec<PathBuf> = if complet {
        vec![h.clone()]
    } else {
        [
            "Downloads",
            "Téléchargements",
            "Desktop",
            "Bureau",
            ".local/bin",
            ".config/autostart",
        ]
        .iter()
        .map(|d| h.join(d))
        .filter(|p| p.exists())
        .collect()
    };
    let cibles = sans_doublons(cibles);
    // /tmp : seulement les fichiers récents (7 jours), où atterrit un téléchargement en cours ou un script lancé ;
    // le reste peut peser des gigaoctets (caches de compilation, préfixes Wine) sans rien apprendre.
    let liste_tmp = if complet {
        None
    } else {
        let fichiers = fichiers_recents(std::path::Path::new("/tmp"), 7, 5000);
        let chemin = std::env::temp_dir().join(format!("sentinel-clamav-{}.txt", std::process::id()));
        let texte: String = fichiers.iter().map(|f| format!("{}\n", f.display())).collect();
        (!fichiers.is_empty() && std::fs::write(&chemin, texte).is_ok()).then_some((chemin, fichiers.len()))
    };
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
        ".local/share/sentinel/quarantaine",
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
    if let Some((chemin, _)) = &liste_tmp {
        cmd.arg(format!("--file-list={}", chemin.display()));
    }
    let mut decrites: Vec<String> = cibles.iter().map(|p| p.display().to_string()).collect();
    if let Some((_, n)) = &liste_tmp {
        decrites.push(trf!(
            "/tmp ({n} fichier(s) de moins de 7 jours)",
            "/tmp ({n} file(s) under 7 days old)"
        ));
    }
    trp!(
        "  {GRIS}Moteur : ClamAV. Analyse de : {}{RESET}",
        "  {GRIS}Engine: ClamAV. Scanning: {}{RESET}",
        decrites.join(", ")
    );
    trp!(
        "  {GRIS}Cela peut prendre de quelques secondes à plusieurs minutes…{RESET}",
        "  {GRIS}This can take from a few seconds to several minutes…{RESET}"
    );

    let sortie = cmd.output();
    if let Some((chemin, _)) = &liste_tmp {
        let _ = std::fs::remove_file(chemin);
    }
    let Ok(sortie) = sortie else {
        trp!("  Impossible de lancer clamscan.", "  Could not start clamscan.");
        return;
    };
    let Some(bilan) = lire_resultat(sortie.status.code(), &String::from_utf8_lossy(&sortie.stdout)) else {
        let erreur = String::from_utf8_lossy(&sortie.stderr);
        trp!(
            "  {}✖ L'analyse a échoué : le résultat n'est pas fiable.{RESET}",
            "  {}✖ The scan failed: the result is not reliable.{RESET}",
            couleur(Niveau::Eleve)
        );
        for l in erreur.lines().filter(|l| l.contains("ERROR")).take(5) {
            println!("    {GRIS}{l}{RESET}");
        }
        return;
    };

    let illisibles = if bilan.illisibles > 0 {
        trf!(
            " ; {} élément(s) illisible(s) sans droits root, ignoré(s)",
            "; {} item(s) unreadable without root rights, skipped",
            bilan.illisibles
        )
    } else {
        String::new()
    };
    trp!(
        "  {GRIS}{} fichier(s) analysé(s){illisibles}.{RESET}",
        "  {GRIS}{} file(s) scanned{illisibles}.{RESET}",
        bilan.analyses
    );
    // Ceinture et bretelles : un même fichier n'est proposé qu'une fois (sinon la 2e mise en quarantaine échoue).
    let mut infectes = bilan.infectes;
    let mut vus = std::collections::HashSet::new();
    infectes.retain(|(f, _)| vus.insert(f.clone()));
    if infectes.is_empty() {
        trp!(
            "  {VERT}✔ Aucun malware trouvé.{RESET}",
            "  {VERT}✔ No malware found.{RESET}"
        );
        return;
    }
    for (f, m) in &infectes {
        println!("  {}✖ {m}{RESET}  {f}", couleur(Niveau::Critique));
    }
    trp!(
        "\n  {} fichier(s) suspect(s).",
        "\n  {} suspicious file(s).",
        infectes.len()
    );
    let rep = demander(tr!(
        "  [q]uarantaine (recommandé, réversible) / [s]upprimer / [r]ien : ",
        "  [q]uarantine (recommended, reversible) / [d]elete / [n]othing: "
    ))
    .to_lowercase();
    let dossier = crate::reseau::dossier_local().join("quarantaine");
    let _ = std::fs::create_dir_all(&dossier);
    for (f, detection) in &infectes {
        let chemin = std::path::Path::new(f);
        let resultat = match rep.as_str() {
            "q" => isoler(chemin, &dossier).map(|dest| noter_quarantaine(&dossier, f, &dest, detection)),
            "s" | "d" => std::fs::remove_file(chemin),
            _ => continue,
        };
        match resultat {
            Ok(()) => println!("  {VERT}✔{RESET} {f}"),
            Err(e) => trp!(
                "  ✖ {f} : {e} (fichier système ? relancer avec sudo)",
                "  ✖ {f}: {e} (system file? run again with sudo)"
            ),
        }
    }
    if rep == "q" {
        trp!(
            "  {GRIS}Quarantaine : {} (emplacement d'origine de chaque fichier noté dans journal.txt){RESET}",
            "  {GRIS}Quarantine: {} (original location of each file noted in journal.txt){RESET}",
            dossier.display()
        );
    }
}

/// Dossiers à analyser sans recouvrement : un ~/Desktop qui pointe vers ~/Bureau, ou un dossier contenu dans un
/// autre, faisait analyser deux fois les mêmes fichiers ; un fichier infecté était alors signalé deux fois et sa
/// seconde mise en quarantaine échouait (« fichier système ? »). Vu en test.
#[cfg(unix)]
/// Fichiers modifiés depuis moins de `jours` jours sous `dossier`, au plus `max` (les dossiers illisibles sont
/// sautés sans bruit).
fn fichiers_recents(dossier: &std::path::Path, jours: u64, max: usize) -> Vec<PathBuf> {
    let limite = std::time::SystemTime::now() - std::time::Duration::from_secs(jours * 86_400);
    let mut trouves = Vec::new();
    let mut a_voir = vec![dossier.to_path_buf()];
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            if trouves.len() >= max {
                return trouves;
            }
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                a_voir.push(e.path());
            } else if m.is_file() && m.modified().is_ok_and(|t| t >= limite) {
                trouves.push(e.path());
            }
        }
    }
    trouves
}

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
        trp!(
            "  Attention : journal de la quarantaine non écrit ({e}). Origine : {origine}",
            "  Warning: quarantine log not written ({e}). Origin: {origine}"
        );
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
    titre(tr!(
        "Programmes lancés au démarrage (à vérifier)",
        "Programs started at boot (to check)"
    ));
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
                entrees.push(trf!("crontab : {l}", "crontab: {l}"));
            }
        }
        for f in std::fs::read_dir("/etc/systemd/system").into_iter().flatten().flatten() {
            let p = f.path();
            // Services ajoutés à la main (pas par un paquet) : endroit classique pour une persistance root.
            if p.extension().is_some_and(|e| e == "service") && p.is_file() && !p.is_symlink() {
                let possede = crate::machine::linux::Paquets::detecter().is_none_or(|g| g.possede(&p));
                if !possede {
                    entrees.push(trf!(
                        "{} (service système hors paquet)",
                        "{} (system service not from a package)",
                        p.display()
                    ));
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use crate::machine::windows::ps;
        let script = tr!(
            "Get-CimInstance Win32_StartupCommand | ForEach-Object { \"$($_.Name) — $($_.Command)\" }; \
                      Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | \
                      ForEach-Object { \"tâche planifiée : $($_.TaskName) — $($_.Actions.Execute)\" }",
            "Get-CimInstance Win32_StartupCommand | ForEach-Object { \"$($_.Name) — $($_.Command)\" }; \
                      Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | \
                      ForEach-Object { \"scheduled task: $($_.TaskName) — $($_.Actions.Execute)\" }"
        );
        entrees.extend(ps(script).unwrap_or_default().lines().map(str::to_string));
    }

    if entrees.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Rien de particulier.",
            "  {VERT}✔{RESET} Nothing special."
        );
    }
    for e in entrees {
        println!("  • {e}");
    }
    trp!(
        "  {GRIS}Si tu ne reconnais pas une entrée, renseigne-toi avant de la supprimer.{RESET}",
        "  {GRIS}If you do not recognize an entry, look it up before deleting it.{RESET}"
    );
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
        let base = std::env::temp_dir().join(format!("sentinel-test-{}", std::process::id()));
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
        let base = std::env::temp_dir().join(format!("sentinel-cibles-{}", std::process::id()));
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
