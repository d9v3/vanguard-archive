//! Surveillance automatique : scan du réseau toutes les heures, notification si un appareil inconnu apparaît.
//! Planificateur natif de chaque système : timer systemd (Linux), Planificateur de tâches (Windows).

use std::process::Command;

use crate::reseau::{self, Options};
use crate::risk::Niveau;
use crate::ui::*;

#[cfg(target_os = "linux")]
const NOM: &str = "sentinel-surveillance";
/// Nom d'avant le renommage en sentinel (0.10.0) : minuterie Linux, et tâche Windows de la v0.4 et avant.
const ANCIEN_NOM: &str = "netscan-surveillance";

fn reussit(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).args(args).output().is_ok_and(|o| o.status.success())
}

/// Programme à planifier. Lancé depuis la clé USB, on en installe d'abord une copie locale :
/// sinon la surveillance s'arrêterait dès que la clé est débranchée.
fn executable() -> String {
    let Ok(exe) = std::env::current_exe() else {
        return "sentinel".into();
    };
    if reseau::cle_usb().is_some_and(|cle| exe.starts_with(&cle)) {
        let dest = reseau::dossier_local()
            .join("bin")
            .join(exe.file_name().unwrap_or_default());
        let copie = std::fs::create_dir_all(dest.parent().unwrap_or(&dest)).and_then(|()| std::fs::copy(&exe, &dest));
        if copie.is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
            }
            trp!(
                "  {GRIS}Copie locale pour la surveillance : {}{RESET}",
                "  {GRIS}Local copy for monitoring: {}{RESET}",
                dest.display()
            );
            return dest.display().to_string();
        }
    }
    exe.display().to_string()
}

fn notifier(titre: &str, corps: &str) {
    #[cfg(target_os = "linux")]
    let _ = Command::new("notify-send")
        .args(["-a", "sentinel", "-i", "sentinel", "-u", "critical", titre, corps])
        .status();
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
    let Ok(r) = reseau::executer(Options {
        silencieux: true,
        ..Options::defaut(None, "courants")
    })
    .await
    else {
        return;
    };
    for h in r.hotes.iter().filter(|h| h.nouvelle) {
        let qui = if h.titre().is_empty() {
            tr!("appareil inconnu", "unknown device").into()
        } else {
            h.titre()
        };
        notifier(
            tr!("Nouvel appareil sur ton réseau", "New device on your network"),
            &format!("{} — {qui} {}", h.ip, h.mac.as_deref().unwrap_or("")),
        );
    }
    for h in r.hotes.iter().filter(|h| !h.nouvelle) {
        for p in h.ports.iter().filter(|p| p.nouveau && p.niveau >= Niveau::Eleve) {
            notifier(
                &trf!("Port {} nouvellement ouvert", "Port {} newly opened", p.port),
                &format!("{} ({}) : {} — {}", h.ip, h.titre(), p.service, p.conseil),
            );
        }
    }
}

pub fn active() -> bool {
    // Surveillance installée sous l'ancien nom : remplacée par la nouvelle (le programme a changé de nom aussi).
    if ancienne_installee() {
        retirer_ancienne();
        return installer(&executable());
    }
    #[cfg(target_os = "linux")]
    return reussit("systemctl", &["--user", "is-enabled", &format!("{NOM}.timer")]);
    #[cfg(windows)]
    return crate::machine::windows::ps(&format!("Get-ScheduledTask -TaskName '{TACHE_WINDOWS}' | Out-Null")).is_some();
}

pub fn activer(oui: bool) {
    let reussi = if oui { installer(&executable()) } else { desinstaller() };
    match (oui, reussi) {
        (true, true) => trp!(
            "  {VERT}✔{RESET} Surveillance activée : scan toutes les heures, notification si un appareil inconnu arrive.",
            "  {VERT}✔{RESET} Monitoring on: scan every hour, notification if an unknown device shows up."
        ),
        (true, false) => trp!(
            "  ✖ Impossible d'activer la surveillance.",
            "  ✖ Could not turn monitoring on."
        ),
        (false, _) => trp!("  Surveillance désactivée.", "  Monitoring off."),
    }
}

#[cfg(target_os = "linux")]
fn installer(exe: &str) -> bool {
    let dossier = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config/systemd/user");
    let _ = std::fs::create_dir_all(&dossier);
    let service = trf!(
        "[Unit]\nDescription=sentinel : surveillance du réseau local\n\n[Service]\nType=oneshot\nExecStart={exe} surveiller\nNice=10\n",
        "[Unit]\nDescription=sentinel: local network monitoring\n\n[Service]\nType=oneshot\nExecStart={exe} surveiller\nNice=10\n"
    );
    let timer = tr!(
        "[Unit]\nDescription=sentinel : scan du réseau toutes les heures\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
        "[Unit]\nDescription=sentinel: network scan every hour\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
    );
    let _ = std::fs::write(dossier.join(format!("{NOM}.service")), service);
    let _ = std::fs::write(dossier.join(format!("{NOM}.timer")), timer);
    reussit("systemctl", &["--user", "daemon-reload"])
        && reussit("systemctl", &["--user", "enable", "--now", &format!("{NOM}.timer")])
}

#[cfg(target_os = "linux")]
fn desinstaller() -> bool {
    retirer_ancienne();
    retirer_minuterie(NOM)
}

#[cfg(target_os = "linux")]
fn retirer_minuterie(nom: &str) -> bool {
    let dossier = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config/systemd/user");
    reussit("systemctl", &["--user", "disable", "--now", &format!("{nom}.timer")]);
    let _ = std::fs::remove_file(dossier.join(format!("{nom}.service")));
    let _ = std::fs::remove_file(dossier.join(format!("{nom}.timer")));
    reussit("systemctl", &["--user", "daemon-reload"])
}

#[cfg(target_os = "linux")]
fn ancienne_installee() -> bool {
    reussit("systemctl", &["--user", "is-enabled", &format!("{ANCIEN_NOM}.timer")])
}

#[cfg(target_os = "linux")]
fn retirer_ancienne() {
    retirer_minuterie(ANCIEN_NOM);
}

/// Nom lisible de la tâche dans le Planificateur de tâches Windows.
#[cfg(windows)]
const TACHE_WINDOWS: &str = "sentinel - surveillance du reseau";
/// Tâche des versions 0.5 à 0.10, sous l'ancien nom netscan.
#[cfg(windows)]
const ANCIENNE_TACHE_WINDOWS: &str = "netscan - surveillance du reseau";

#[cfg(windows)]
fn ancienne_installee() -> bool {
    crate::machine::windows::ps(&format!("Get-ScheduledTask -TaskName '{ANCIENNE_TACHE_WINDOWS}' | Out-Null")).is_some()
}

#[cfg(windows)]
fn retirer_ancienne() {
    let _ = reussit("schtasks", &["/Delete", "/F", "/TN", ANCIEN_NOM]);
    let _ = crate::machine::windows::ps(&format!(
        "Unregister-ScheduledTask -TaskName '{ANCIENNE_TACHE_WINDOWS}' -Confirm:$false"
    ));
}

#[cfg(windows)]
fn installer(exe: &str) -> bool {
    use crate::machine::windows::ps;
    // Anciennes tâches (v0.4 et avant, puis sous le nom netscan) : retirées au profit de la tâche décrite ci-dessous.
    retirer_ancienne();
    let exe = exe.replace('\'', "''");
    // Tâche visible et décrite : on voit dans le Planificateur ce qu'elle fait et comment l'arrêter.
    let script = trf!(
        "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
         $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
         Register-ScheduledTask -TaskName '{TACHE_WINDOWS}' -Action $a -Trigger $t -Force \
           -Description 'Scan du réseau local toutes les heures par sentinel, notification si un appareil inconnu apparaît. Pour arrêter : sentinel surveillance off' | Out-Null",
        "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
         $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
         Register-ScheduledTask -TaskName '{TACHE_WINDOWS}' -Action $a -Trigger $t -Force \
           -Description 'Hourly local network scan by sentinel, with a notification when an unknown device appears. To stop it: sentinel surveillance off' | Out-Null"
    );
    ps(&script).is_some()
}

#[cfg(windows)]
fn desinstaller() -> bool {
    retirer_ancienne();
    crate::machine::windows::ps(&format!(
        "Unregister-ScheduledTask -TaskName '{TACHE_WINDOWS}' -Confirm:$false"
    ))
    .is_some()
}
