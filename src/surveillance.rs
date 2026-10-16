//! Surveillance automatique : scan du réseau toutes les heures, notification si un appareil inconnu apparaît.
//! Planificateur natif de chaque système : timer systemd (Linux), LaunchAgent (macOS), Planificateur de tâches (Windows).

use std::process::Command;

use crate::reseau::{self, Options};
use crate::risk::Niveau;
use crate::ui::*;

const NOM: &str = "netscan-surveillance";

fn reussit(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).args(args).output().is_ok_and(|o| o.status.success())
}

/// Programme à planifier. Lancé depuis la clé USB, on en installe d'abord une copie locale :
/// sinon la surveillance s'arrêterait dès que la clé est débranchée.
fn executable() -> String {
    let Ok(exe) = std::env::current_exe() else { return "netscan".into() };
    if reseau::cle_usb().is_some_and(|cle| exe.starts_with(&cle)) {
        let dest = reseau::dossier_local().join("bin").join(exe.file_name().unwrap_or_default());
        let copie = std::fs::create_dir_all(dest.parent().unwrap_or(&dest)).and_then(|_| std::fs::copy(&exe, &dest));
        if copie.is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
            }
            println!("  {GRIS}Copie locale pour la surveillance : {}{RESET}", dest.display());
            return dest.display().to_string();
        }
    }
    exe.display().to_string()
}

fn notifier(titre: &str, corps: &str) {
    #[cfg(target_os = "linux")]
    let _ = Command::new("notify-send").args(["-a", "netscan", "-i", "netscan", "-u", "critical", titre, corps]).status();
    #[cfg(target_os = "macos")]
    {
        let e = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!("display notification \"{}\" with title \"{}\" sound name \"Basso\"", e(corps), e(titre));
        let _ = Command::new("osascript").args(["-e", &script]).status();
    }
    #[cfg(windows)]
    {
        let e = |s: &str| s.replace('\'', "''");
        // Identifiant d'application de PowerShell : sans lui, Windows 10/11 n'affiche pas la notification.
        let script = format!(
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; \
             $t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
             $x = $t.GetElementsByTagName('text'); $x.Item(0).AppendChild($t.CreateTextNode('{}')) | Out-Null; $x.Item(1).AppendChild($t.CreateTextNode('{}')) | Out-Null; \
             [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\\WindowsPowerShell\\v1.0\\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($t))",
            e(titre),
            e(corps)
        );
        let _ = crate::machine::windows::ps(&script);
    }
}

/// Appelé par le planificateur : scan silencieux, puis notification s'il y a du nouveau.
pub async fn surveiller() {
    let Ok(r) = reseau::executer(Options { silencieux: true, ..Options::defaut(None, "courants") }).await else {
        return;
    };
    for h in r.hotes.iter().filter(|h| h.nouvelle) {
        let qui = if h.titre().is_empty() { "appareil inconnu".into() } else { h.titre() };
        notifier("Nouvel appareil sur ton réseau", &format!("{} — {qui} {}", h.ip, h.mac.as_deref().unwrap_or("")));
    }
    for h in r.hotes.iter().filter(|h| !h.nouvelle) {
        for p in h.ports.iter().filter(|p| p.nouveau && p.niveau >= Niveau::Eleve) {
            notifier(&format!("Port {} nouvellement ouvert", p.port), &format!("{} ({}) : {} — {}", h.ip, h.titre(), p.service, p.conseil));
        }
    }
}

pub fn active() -> bool {
    #[cfg(target_os = "linux")]
    return reussit("systemctl", &["--user", "is-enabled", &format!("{NOM}.timer")]);
    #[cfg(target_os = "macos")]
    return plist().exists();
    #[cfg(windows)]
    return reussit("schtasks", &["/Query", "/TN", NOM]);
}

#[cfg(target_os = "macos")]
fn plist() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(format!("Library/LaunchAgents/com.{NOM}.plist"))
}

pub fn activer(oui: bool) {
    let reussi = if oui { installer(&executable()) } else { desinstaller() };
    match (oui, reussi) {
        (true, true) => println!("  {VERT}✔{RESET} Surveillance activée : scan toutes les heures, notification si un appareil inconnu arrive."),
        (true, false) => println!("  ✖ Impossible d'activer la surveillance."),
        (false, _) => println!("  Surveillance désactivée."),
    }
}

#[cfg(target_os = "linux")]
fn installer(exe: &str) -> bool {
    let dossier = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config/systemd/user");
    let _ = std::fs::create_dir_all(&dossier);
    let service = format!("[Unit]\nDescription=netscan : surveillance du réseau local\n\n[Service]\nType=oneshot\nExecStart={exe} surveiller\nNice=10\n");
    let timer = "[Unit]\nDescription=netscan : scan du réseau toutes les heures\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n";
    let _ = std::fs::write(dossier.join(format!("{NOM}.service")), service);
    let _ = std::fs::write(dossier.join(format!("{NOM}.timer")), timer);
    reussit("systemctl", &["--user", "daemon-reload"]) && reussit("systemctl", &["--user", "enable", "--now", &format!("{NOM}.timer")])
}

#[cfg(target_os = "linux")]
fn desinstaller() -> bool {
    let dossier = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config/systemd/user");
    reussit("systemctl", &["--user", "disable", "--now", &format!("{NOM}.timer")]);
    let _ = std::fs::remove_file(dossier.join(format!("{NOM}.service")));
    let _ = std::fs::remove_file(dossier.join(format!("{NOM}.timer")));
    reussit("systemctl", &["--user", "daemon-reload"])
}

#[cfg(target_os = "macos")]
fn installer(exe: &str) -> bool {
    let contenu = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.{NOM}</string>
  <key>ProgramArguments</key><array><string>{exe}</string><string>surveiller</string></array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
</dict></plist>
"#
    );
    let p = plist();
    let _ = std::fs::create_dir_all(p.parent().unwrap_or(&p));
    std::fs::write(&p, contenu).is_ok() && reussit("launchctl", &["load", "-w", &p.display().to_string()])
}

#[cfg(target_os = "macos")]
fn desinstaller() -> bool {
    let p = plist();
    reussit("launchctl", &["unload", "-w", &p.display().to_string()]);
    std::fs::remove_file(p).is_ok()
}

#[cfg(windows)]
fn installer(exe: &str) -> bool {
    // conhost --headless : pas de fenêtre de console qui clignote toutes les heures.
    let tache = format!("conhost.exe --headless \"{exe}\" surveiller");
    reussit("schtasks", &["/Create", "/F", "/SC", "HOURLY", "/TN", NOM, "/TR", &tache])
}

#[cfg(windows)]
fn desinstaller() -> bool {
    reussit("schtasks", &["/Delete", "/F", "/TN", NOM])
}
