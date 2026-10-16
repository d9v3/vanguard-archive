//! Recherche de malwares avec un moteur reconnu (ClamAV sous Linux/macOS, Microsoft Defender sous Windows)
//! et revue des programmes lancés au démarrage, là où un malware cherche à se maintenir.

use std::path::PathBuf;
use std::process::Command;

use crate::risk::Niveau;
use crate::ui::*;

#[cfg(unix)]
fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).unwrap_or_default())
}

pub fn analyser(complet: bool) {
    titre(if complet { "Analyse antivirus complète" } else { "Analyse antivirus rapide" });
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
    let mpcmd = PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_default()).join(r"Windows Defender\MpCmdRun.exe");
    println!("  {GRIS}Moteur : Microsoft Defender. Cela peut prendre de quelques minutes à une heure (analyse complète)…{RESET}");
    let statut = Command::new(&mpcmd).args(["-Scan", "-ScanType", if complet { "2" } else { "1" }]).status();
    match statut.map(|s| s.code()) {
        Ok(Some(0)) => println!("  {VERT}✔ Aucun malware trouvé.{RESET}"),
        Ok(Some(2)) => {
            let menaces = ps("Get-MpThreat | ForEach-Object { \"$($_.ThreatName)|$($_.Resources -join ', ')\" }").unwrap_or_default();
            for l in menaces.lines() {
                let (nom, fichiers) = l.split_once('|').unwrap_or((l, ""));
                println!("  {}✖ {nom}{RESET}  {fichiers}", couleur(Niveau::Critique));
            }
            println!("  Defender a normalement déjà mis ces fichiers en quarantaine.");
            if demander("  Supprimer définitivement les menaces détectées ? [o/N] : ").eq_ignore_ascii_case("o")
                && powershell_admin("Remove-MpThreat")
            {
                println!("  {VERT}✔ Menaces supprimées.{RESET}");
            }
        }
        _ => println!("  Defender n'a pas pu lancer l'analyse (antivirus tiers actif ?)."),
    }
}

// ───────────────────────────── Linux / macOS : ClamAV ─────────────────────────────

#[cfg(unix)]
fn shell(c: &str) -> bool {
    println!("  {GRIS}$ {c}{RESET}");
    Command::new("bash").arg("-c").arg(c).status().is_ok_and(|s| s.success())
}

#[cfg(unix)]
fn base_presente() -> bool {
    ["/var/lib/clamav", "/opt/homebrew/var/lib/clamav", "/usr/local/var/lib/clamav"].iter().any(|d| {
        std::fs::read_dir(d).is_ok_and(|d| {
            d.flatten().any(|f| {
                let n = f.file_name().to_string_lossy().into_owned();
                n.ends_with(".cvd") || n.ends_with(".cld")
            })
        })
    })
}

/// Installe ClamAV et télécharge les signatures si besoin. Retourne `false` si l'utilisateur refuse.
#[cfg(unix)]
fn preparer() -> bool {
    let present = Command::new("bash").args(["-c", "command -v clamscan"]).output().is_ok_and(|o| o.status.success());
    if !present {
        println!("  ClamAV (antivirus open source) n'est pas installé.");
        if !demander("  L'installer maintenant ? [o/N] : ").eq_ignore_ascii_case("o") {
            return false;
        }
        #[cfg(target_os = "linux")]
        let installation = "sudo pacman -S --needed --noconfirm clamav";
        #[cfg(target_os = "macos")]
        let installation = "brew install clamav";
        if !shell(installation) {
            println!("  Installation impossible (sous macOS, Homebrew est nécessaire : https://brew.sh).");
            return false;
        }
    }
    if !base_presente() {
        println!("  Téléchargement des signatures de virus (~300 Mo, une seule fois)…");
        #[cfg(target_os = "linux")]
        let ok = shell("sudo freshclam") && shell("sudo systemctl enable --now clamav-freshclam.service");
        #[cfg(target_os = "macos")]
        let ok = shell(
            "C=$(brew --prefix)/etc/clamav; [ -f $C/freshclam.conf ] || sed 's/^Example/#Example/' $C/freshclam.conf.sample > $C/freshclam.conf; freshclam",
        );
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
        ["Downloads", "Téléchargements", "Desktop", "Bureau", "Documents", ".local/bin", ".config/autostart", "Library/LaunchAgents"]
            .iter()
            .map(|d| h.join(d))
            .chain([PathBuf::from("/tmp")])
            .filter(|p| p.exists())
            .collect()
    };
    // Jeux, caches et préfixes Wine sont énormes et produisent des faux positifs (cracks, outils anti-triche).
    let exclusions = [
        "Games", ".steam", ".local/share/Steam", ".cache", "Windows", ".cargo/registry", ".rustup", "target",
        "node_modules", ".local/share/netscan/quarantaine", ".snapshots", "Library/Caches", ".Trash",
    ];
    let mut cmd = Command::new("clamscan");
    cmd.args(["-r", "-i", "--no-summary", "--max-filesize=200M", "--max-scansize=400M"]);
    for e in exclusions {
        cmd.arg(format!("--exclude-dir={}", regex_echappe(e)));
    }
    cmd.args(&cibles);
    println!("  {GRIS}Moteur : ClamAV. Analyse de : {}{RESET}", cibles.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "));
    println!("  {GRIS}Cela peut prendre de quelques secondes à plusieurs minutes…{RESET}");

    let Ok(sortie) = cmd.output() else {
        println!("  Impossible de lancer clamscan.");
        return;
    };
    // clamscan : 0 = sain, 1 = menaces trouvées, autre = erreur (base absente, disque illisible…).
    if !matches!(sortie.status.code(), Some(0 | 1)) {
        let erreur = String::from_utf8_lossy(&sortie.stderr);
        println!("  {}✖ L'analyse a échoué : le résultat n'est pas fiable.{RESET}", couleur(Niveau::Eleve));
        for l in erreur.lines().filter(|l| l.contains("ERROR")).take(5) {
            println!("    {GRIS}{l}{RESET}");
        }
        return;
    }
    let infectes: Vec<(String, String)> = String::from_utf8_lossy(&sortie.stdout)
        .lines()
        .filter_map(|l| {
            let (fichier, menace) = l.strip_suffix(" FOUND")?.rsplit_once(": ")?;
            Some((fichier.to_string(), menace.to_string()))
        })
        .collect();

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
    for (f, _) in &infectes {
        let chemin = std::path::Path::new(f);
        let resultat = match rep.as_str() {
            "q" => {
                let nom = chemin.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let dest = dossier.join(format!("{}.{nom}", std::process::id()));
                std::fs::rename(chemin, &dest)
                    .or_else(|_| std::fs::copy(chemin, &dest).and_then(|_| std::fs::remove_file(chemin)))
                    .and_then(|_| {
                        use std::os::unix::fs::PermissionsExt;
                        // Plus aucune permission : le fichier ne peut plus être lancé ni ouvert par erreur.
                        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o000))
                    })
            }
            "s" => std::fs::remove_file(chemin),
            _ => continue,
        };
        match resultat {
            Ok(()) => println!("  {VERT}✔{RESET} {f}"),
            Err(e) => println!("  ✖ {f} : {e} (fichier système ? relancer avec sudo)"),
        }
    }
    if rep == "q" {
        println!("  {GRIS}Quarantaine : {}{RESET}", dossier.display());
    }
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
            for l in String::from_utf8_lossy(&o.stdout).lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
                entrees.push(format!("crontab : {l}"));
            }
        }
        for f in std::fs::read_dir("/etc/systemd/system").into_iter().flatten().flatten() {
            let p = f.path();
            // Services ajoutés à la main (pas par un paquet) : endroit classique pour une persistance root.
            if p.extension().is_some_and(|e| e == "service") && p.is_file() && !p.is_symlink() {
                let possede = Command::new("pacman").arg("-Qo").arg(&p).output().is_ok_and(|o| o.status.success());
                if !possede {
                    entrees.push(format!("{} (service système hors paquet)", p.display()));
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let h = home();
        for d in [h.join("Library/LaunchAgents"), "/Library/LaunchAgents".into(), "/Library/LaunchDaemons".into()] {
            for f in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let nom = f.file_name().to_string_lossy().into_owned();
                if !nom.starts_with("com.apple.") {
                    entrees.push(f.path().display().to_string());
                }
            }
        }
        if let Ok(o) = Command::new("osascript").args(["-e", "tell application \"System Events\" to get the name of every login item"]).output() {
            for n in String::from_utf8_lossy(&o.stdout).trim().split(", ").filter(|n| !n.is_empty()) {
                entrees.push(format!("élément d'ouverture : {n}"));
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
