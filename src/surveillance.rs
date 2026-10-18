//! Surveillance automatique : scan du réseau toutes les heures, notification si un appareil inconnu apparaît.
//! Planificateur natif de chaque système : timer systemd (Linux), Planificateur de tâches (Windows), agent launchd
//! (macOS).

use std::process::Command;

use crate::reseau::{self, Options};
use crate::risk::Niveau;
use crate::ui::*;

#[cfg(target_os = "linux")]
const NOM: &str = "gardien-surveillance";
/// Noms d'avant : sentinel (0.11 à 0.50) et netscan (jusqu'à 0.10.0). Minuteries Linux ; sous Windows, la tâche
/// de la v0.4 et avant s'appelait « netscan-surveillance ».
#[cfg_attr(target_os = "macos", allow(dead_code))]
const ANCIENS_NOMS: [&str; 2] = ["sentinel-surveillance", "netscan-surveillance"];

pub(crate) fn reussit(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).args(args).output().is_ok_and(|o| o.status.success())
}

/// Programme à planifier. Lancé depuis la clé USB, on en installe d'abord une copie locale :
/// sinon la surveillance (et l'entretien du mois) s'arrêterait dès que la clé est débranchée.
pub(crate) fn executable() -> String {
    // Sous Linux et macOS, le programme peut tourner depuis une copie temporaire (protection de la clé), effacée
    // à la fin.
    #[cfg(unix)]
    let exe = crate::protection::exe_d_origine();
    #[cfg(windows)]
    let exe = std::env::current_exe().ok();
    let Some(exe) = exe else {
        return "gardien".into();
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

pub(crate) fn notifier(titre: &str, corps: &str) {
    #[cfg(target_os = "linux")]
    let _ = Command::new("notify-send")
        .args(["-a", "Gardien", "-i", "gardien", "-u", "critical", titre, corps])
        .status();
    // macOS : notification du Centre de notifications, par AppleScript (texte entre guillemets échappés).
    #[cfg(target_os = "macos")]
    {
        let e = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let _ = Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "display notification \"{}\" with title \"{}\" sound name \"Basso\"",
                e(corps),
                e(titre)
            ))
            .status();
    }
    #[cfg(windows)]
    {
        let e = crate::commande::ps_texte;
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
/// Catégories surveillées sur cette machine : ce qui trahit une attaque ou une panne. Les mises à jour
/// disponibles, qui changent tous les jours, n'en font pas partie.
const CATEGORIES_SURVEILLEES: &[&str] = &[
    "Pare-feu",
    "Antivirus",
    "Ports en écoute",
    "Persistance",
    "Certificats",
    "DNS",
    "Santé",
    "Comptes",
    "Sudo",
    "Groupes",
    "Fichiers suspects",
    "Clés SSH",
    "Extensions",
];

/// État de la machine au dernier passage de la surveillance.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct EtatMachine {
    score: Option<u32>,
    /// Problèmes moyens ou plus graves des catégories surveillées, « catégorie : message ».
    alertes: Vec<String>,
}

fn fichier_etat() -> std::path::PathBuf {
    reseau::dossier_local().join("surveillance-machine.json")
}

fn etat_machine(a: &crate::machine::Audit) -> EtatMachine {
    EtatMachine {
        score: a.fiable().then_some(a.score),
        alertes: a
            .constats
            .iter()
            .filter(|c| c.probleme.is_some_and(|n| n >= Niveau::Moyen) && CATEGORIES_SURVEILLEES.contains(&c.categorie))
            .map(|c| format!("{} : {}", c.categorie, c.message))
            .collect(),
    }
}

/// Un problème comparé sans ses nombres (« 3 % libres » et « 2 % libres » sont le même problème), sauf les ports :
/// un autre numéro de port est un autre problème.
pub(crate) fn cle_alerte(alerte: &str) -> String {
    if alerte.starts_with("Ports en écoute") {
        return alerte.to_string();
    }
    alerte
        .chars()
        .map(|c| if c.is_ascii_digit() { '#' } else { c })
        .collect()
}

/// Notifications à envoyer entre deux passages : (titre, texte).
fn nouveautes_machine(avant: &EtatMachine, apres: &EtatMachine) -> Vec<(String, String)> {
    let connues: Vec<String> = avant.alertes.iter().map(|a| cle_alerte(a)).collect();
    let nouvelles: Vec<&String> = apres
        .alertes
        .iter()
        .filter(|a| !connues.contains(&cle_alerte(a)))
        .collect();
    let mut notes = Vec::new();
    for a in nouvelles.iter().take(3) {
        let (cat, msg) = a.split_once(" : ").unwrap_or(("", a.as_str()));
        notes.push((
            trf!("Gardien : {}", "Gardien: {}", crate::langue::categorie(cat)),
            msg.to_string(),
        ));
    }
    if nouvelles.len() > 3 {
        notes.push((
            tr!("Gardien : autres problèmes", "Gardien: other problems").to_string(),
            trf!(
                "{} autre(s) problème(s) nouveau(x) : lance « gardien machine ».",
                "{} other new problem(s): run “gardien machine”.",
                nouvelles.len() - 3
            ),
        ));
    }
    if let (Some(a), Some(b)) = (avant.score, apres.score)
        && b + 10 <= a
    {
        notes.push((
            tr!("Gardien : note en baisse", "Gardien: grade dropping").to_string(),
            trf!(
                "La note de cette machine passe de {a} à {b} : lance « gardien machine » pour voir pourquoi.",
                "This machine's grade drops from {a} to {b}: run “gardien machine” to see why."
            ),
        ));
    }
    notes
}

/// Audit silencieux de cette machine, comparé au passage précédent. Le premier passage mémorise seulement.
fn veiller_machine() {
    let apres = etat_machine(&crate::machine::auditer(false));
    let avant: Option<EtatMachine> = std::fs::read_to_string(fichier_etat())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    if let Some(avant) = &avant {
        for (titre, texte) in nouveautes_machine(avant, &apres) {
            notifier(&titre, &texte);
            crate::alertes::envoyer(
                &titre,
                tr!(
                    "Nouveau sur cet ordinateur : lance « gardien machine » pour le détail.",
                    "New on this computer: run “gardien machine” for the details."
                ),
            );
        }
    }
    if let Ok(texte) = serde_json::to_string(&apres) {
        let _ = std::fs::create_dir_all(reseau::dossier_local());
        let _ = std::fs::write(fichier_etat(), texte);
    }
}

/// Box vue au dernier passage : même Wi-Fi et même adresse, mais une autre adresse MAC = alerte.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct Passerelle {
    reseau: String,
    nom: Option<String>,
    ip: std::net::Ipv4Addr,
    mac: String,
}

fn fichier_passerelle() -> std::path::PathBuf {
    reseau::dossier_local().join("surveillance-passerelle.json")
}

fn passerelle_de(r: &reseau::Rapport) -> Option<Passerelle> {
    let h = r.hotes.iter().find(|h| h.role == Some("passerelle"))?;
    Some(Passerelle {
        reseau: r.reseau.clone(),
        nom: r.nom_reseau.clone(),
        ip: h.ip,
        mac: h.mac.clone()?.to_lowercase(),
    })
}

/// La box a-t-elle changé d'adresse MAC sur le même réseau (même Wi-Fi, même adresse) ? Rend (ancienne, nouvelle).
fn mac_changee(avant: &Passerelle, apres: &Passerelle) -> Option<(String, String)> {
    (avant.reseau == apres.reseau && avant.nom == apres.nom && avant.ip == apres.ip && avant.mac != apres.mac)
        .then(|| (avant.mac.clone(), apres.mac.clone()))
}

/// Contrôles contre l'usurpation de la box : MAC partagée avec un autre appareil, MAC changée depuis le passage
/// précédent. Le changement est retenu seulement s'il n'y a pas d'alerte de partage (on garde l'ancienne référence).
fn veiller_passerelle(r: &reseau::Rapport) {
    if let Some((boite, mac, autre)) = reseau::usurpation_arp(r) {
        notifier(
            tr!("Gardien : box usurpée ?", "Gardien: router impersonated?"),
            &reseau::message_usurpation(boite, &mac, autre),
        );
        crate::alertes::envoyer(
            tr!("Gardien : box usurpée ?", "Gardien: router impersonated?"),
            &sur_le_reseau(tr!(
                "une autre machine répond à sa place",
                "another machine answers in its place"
            )),
        );
        return;
    }
    let Some(apres) = passerelle_de(r) else { return };
    let avant: Option<Passerelle> = std::fs::read_to_string(fichier_passerelle())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    if let Some((ancienne, nouvelle)) = avant.as_ref().and_then(|a| mac_changee(a, &apres)) {
        notifier(
            tr!(
                "Gardien : la box a changé d'adresse MAC",
                "Gardien: the router's MAC address changed"
            ),
            &trf!(
                "La box {} répondait avec {ancienne}, elle répond maintenant avec {nouvelle}. Normal si tu viens de changer de box ; sinon, quelqu'un se fait peut-être passer pour elle (usurpation ARP).",
                "The router {} answered with {ancienne}, it now answers with {nouvelle}. Normal if you just replaced it; otherwise someone may be impersonating it (ARP spoofing).",
                apres.ip
            ),
        );
        crate::alertes::envoyer(
            tr!(
                "Gardien : la box a changé d'adresse MAC",
                "Gardien: the router's MAC address changed"
            ),
            &sur_le_reseau(tr!("lance Gardien pour le détail", "open Gardien for the details")),
        );
    }
    if let Ok(texte) = serde_json::to_string(&apres) {
        let _ = std::fs::create_dir_all(reseau::dossier_local());
        let _ = std::fs::write(fichier_passerelle(), texte);
    }
}

/// Texte d'une alerte pour le téléphone : ni les adresses, ni le nom du réseau. Le message passe par ntfy.sh, qui lit
/// tout, et le nom d'un Wi-Fi nomme souvent la maison ou ses gens (« Chez Max ») : « …, sur le réseau de cet
/// ordinateur ».
fn sur_le_reseau(quoi: &str) -> String {
    trf!(
        "{quoi}, sur le réseau de cet ordinateur.",
        "{quoi}, on this computer's network."
    )
}

/// Ce qu'une alerte du téléphone dit d'un appareil : son fabricant (« Apple »), jamais son nom ni son surnom, souvent
/// ceux de quelqu'un (« iPhone de Zoé »). Sans fabricant connu : `sinon`.
fn appareil_pour_le_telephone(h: &reseau::Hote, sinon: &str) -> String {
    h.fabricant
        .as_deref()
        .map(crate::scan::fabricant_traduit)
        .filter(|f| !f.trim().is_empty())
        .map_or_else(|| sinon.to_string(), str::to_string)
}

pub async fn surveiller() {
    veiller_machine();
    if let Some(fichiers) = crate::integrite::changements_a_signaler() {
        notifier(
            tr!(
                "Gardien : fichiers critiques modifiés",
                "Gardien: critical files changed"
            ),
            &fichiers,
        );
        crate::alertes::envoyer(
            tr!(
                "Gardien : fichiers critiques modifiés",
                "Gardien: critical files changed"
            ),
            tr!(
                "Lance « gardien integrite » sur cet ordinateur pour voir lesquels.",
                "Run “gardien integrite” on this computer to see which ones."
            ),
        );
    }
    let Ok(r) = reseau::executer(Options {
        silencieux: true,
        ..Options::defaut(None, "courants")
    })
    .await
    else {
        return;
    };
    veiller_passerelle(&r);
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
        crate::alertes::envoyer(
            tr!("Nouvel appareil sur ton réseau", "New device on your network"),
            &sur_le_reseau(&appareil_pour_le_telephone(
                h,
                tr!("appareil inconnu", "unknown device"),
            )),
        );
    }
    for h in r.hotes.iter().filter(|h| !h.nouvelle) {
        for p in h.ports.iter().filter(|p| p.nouveau && p.niveau >= Niveau::Eleve) {
            notifier(
                &trf!("Port {} nouvellement ouvert", "Port {} newly opened", p.port),
                &format!("{} ({}) : {} — {}", h.ip, h.titre(), p.service, p.conseil),
            );
            let qui = appareil_pour_le_telephone(h, tr!("un appareil", "a device"));
            crate::alertes::envoyer(
                &trf!("Port {} nouvellement ouvert", "Port {} newly opened", p.port),
                &sur_le_reseau(&format!("{qui} : {}", p.service)),
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
    return tache_existe(&[TACHE_WINDOWS]);
    #[cfg(target_os = "macos")]
    return reussit("launchctl", &["print", &format!("{}/{AGENT_MACOS}", domaine_launchd())]);
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
    // Chemin entre guillemets (un dossier personnel peut contenir une espace), « % » doublé (spécificateurs de
    // systemd).
    let exe = format!("\"{}\"", exe.replace('%', "%%").replace('"', "\\\""));
    let service = trf!(
        "[Unit]\nDescription=Gardien : surveillance du réseau local\n\n[Service]\nType=oneshot\nExecStart={exe} surveiller\nNice=10\n",
        "[Unit]\nDescription=Gardien: local network monitoring\n\n[Service]\nType=oneshot\nExecStart={exe} surveiller\nNice=10\n"
    );
    let timer = tr!(
        "[Unit]\nDescription=Gardien : scan du réseau toutes les heures\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
        "[Unit]\nDescription=Gardien: network scan every hour\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
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
    ANCIENS_NOMS
        .iter()
        .any(|n| reussit("systemctl", &["--user", "is-enabled", &format!("{n}.timer")]))
}

#[cfg(target_os = "linux")]
fn retirer_ancienne() {
    for n in ANCIENS_NOMS {
        retirer_minuterie(n);
    }
}

/// Agent launchd de la surveillance sous macOS (~/Library/LaunchAgents/<nom>.plist).
#[cfg(target_os = "macos")]
const AGENT_MACOS: &str = "com.gardien.surveillance";
/// Agent d'avant le renommage en Gardien (0.44 à 0.50).
#[cfg(target_os = "macos")]
const ANCIEN_AGENT_MACOS: &str = "com.sentinel.surveillance";

#[cfg(target_os = "macos")]
fn plist_agent_nomme(nom: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join(format!("Library/LaunchAgents/{nom}.plist"))
}

#[cfg(target_os = "macos")]
fn plist_agent() -> std::path::PathBuf {
    plist_agent_nomme(AGENT_MACOS)
}

/// Domaine launchd de la session graphique de l'utilisateur (« gui/501 »).
#[cfg(target_os = "macos")]
pub(crate) fn domaine_launchd() -> String {
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    format!("gui/{uid}")
}

/// Agent launchd : relancé toutes les heures (StartInterval), et 5 minutes après l'ouverture de session.
#[cfg(any(target_os = "macos", test))]
fn plist_surveillance(exe: &str, nom: &str) -> String {
    let exe = exe.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         \t<key>Label</key>\n\t<string>{nom}</string>\n\
         \t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>{exe}</string>\n\t\t<string>surveiller</string>\n\t</array>\n\
         \t<key>StartInterval</key>\n\t<integer>3600</integer>\n\
         \t<key>LowPriorityIO</key>\n\t<true/>\n\
         \t<key>Nice</key>\n\t<integer>10</integer>\n\
         </dict>\n</plist>\n"
    )
}

#[cfg(target_os = "macos")]
fn installer(exe: &str) -> bool {
    let plist = plist_agent();
    let _ = std::fs::create_dir_all(plist.parent().unwrap_or(&plist));
    if std::fs::write(&plist, plist_surveillance(exe, AGENT_MACOS)).is_err() {
        return false;
    }
    let chemin = plist.display().to_string();
    // Déjà chargé (réactivation) : on le retire d'abord, sinon bootstrap refuse.
    let _ = reussit("launchctl", &["bootout", &domaine_launchd(), &chemin]);
    reussit("launchctl", &["bootstrap", &domaine_launchd(), &chemin])
}

#[cfg(target_os = "macos")]
fn retirer_agent(plist: &std::path::Path) {
    let _ = reussit(
        "launchctl",
        &["bootout", &domaine_launchd(), &plist.display().to_string()],
    );
    let _ = std::fs::remove_file(plist);
}

#[cfg(target_os = "macos")]
fn desinstaller() -> bool {
    retirer_ancienne();
    retirer_agent(&plist_agent());
    true
}

#[cfg(target_os = "macos")]
fn ancienne_installee() -> bool {
    plist_agent_nomme(ANCIEN_AGENT_MACOS).is_file()
}

#[cfg(target_os = "macos")]
fn retirer_ancienne() {
    retirer_agent(&plist_agent_nomme(ANCIEN_AGENT_MACOS));
}

/// Nom lisible de la tâche dans le Planificateur de tâches Windows.
#[cfg(windows)]
const TACHE_WINDOWS: &str = "gardien - surveillance du reseau";
/// Tâches des versions 0.5 à 0.50, sous les anciens noms sentinel et netscan.
#[cfg(windows)]
const ANCIENNES_TACHES_WINDOWS: [&str; 2] = ["sentinel - surveillance du reseau", "netscan - surveillance du reseau"];

/// Une de ces tâches existe-t-elle ? Sans erreur quand aucune n'existe : un échec de PowerShell irait au journal.
#[cfg(windows)]
pub(crate) fn tache_existe(noms: &[&str]) -> bool {
    let liste = noms.iter().map(|n| format!("'{n}'")).collect::<Vec<_>>().join(",");
    crate::machine::windows::ps(&format!(
        "if (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName -in @({liste}) }}) {{ 'oui' }}"
    ))
    .is_some_and(|s| s.trim() == "oui")
}

#[cfg(windows)]
fn ancienne_installee() -> bool {
    tache_existe(&ANCIENNES_TACHES_WINDOWS)
}

#[cfg(windows)]
fn retirer_ancienne() {
    for nom in ANCIENS_NOMS {
        let _ = reussit("schtasks", &["/Delete", "/F", "/TN", nom]);
    }
    for tache in ANCIENNES_TACHES_WINDOWS {
        let _ = crate::machine::windows::ps(&format!("Unregister-ScheduledTask -TaskName '{tache}' -Confirm:$false"));
    }
}

#[cfg(windows)]
fn installer(exe: &str) -> bool {
    use crate::machine::windows::ps;
    // Anciennes tâches (v0.4 et avant, puis sous les noms netscan et sentinel) : retirées au profit de la tâche
    // décrite ci-dessous.
    retirer_ancienne();
    let exe = crate::commande::ps_texte(exe);
    // Tâche visible et décrite : on voit dans le Planificateur ce qu'elle fait et comment l'arrêter.
    let script = trf!(
        "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
         $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
         Register-ScheduledTask -TaskName '{TACHE_WINDOWS}' -Action $a -Trigger $t -Force \
           -Description 'Scan du réseau local toutes les heures par Gardien, notification si un appareil inconnu apparaît. Pour arrêter : gardien surveillance off' | Out-Null",
        "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
         $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
         Register-ScheduledTask -TaskName '{TACHE_WINDOWS}' -Action $a -Trigger $t -Force \
           -Description 'Hourly local network scan by Gardien, with a notification when an unknown device appears. To stop it: gardien surveillance off' | Out-Null"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_launchd() {
        let p = plist_surveillance(
            "/Users/a b/Library/Application Support/gardien/bin/gardien",
            "com.gardien.surveillance",
        );
        assert!(p.contains("<string>/Users/a b/Library/Application Support/gardien/bin/gardien</string>"));
        assert!(p.contains("<key>StartInterval</key>\n\t<integer>3600</integer>"));
        assert!(p.contains("<string>surveiller</string>"));
    }

    fn etat(score: u32, alertes: &[&str]) -> EtatMachine {
        EtatMachine {
            score: Some(score),
            alertes: alertes.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn box_qui_change_de_mac() {
        let p = |nom: &str, mac: &str| Passerelle {
            reseau: "10.0.0.0/24".into(),
            nom: Some(nom.into()),
            ip: "10.0.0.1".parse().unwrap(),
            mac: mac.into(),
        };
        assert!(mac_changee(&p("Maison", "aa:aa:aa:aa:aa:aa"), &p("Maison", "aa:aa:aa:aa:aa:aa")).is_none());
        assert!(mac_changee(&p("Maison", "aa:aa:aa:aa:aa:aa"), &p("Maison", "bb:bb:bb:bb:bb:bb")).is_some());
        // Autre Wi-Fi (chez un ami) avec la même adresse de box : pas une alerte.
        assert!(mac_changee(&p("Maison", "aa:aa:aa:aa:aa:aa"), &p("Ami", "bb:bb:bb:bb:bb:bb")).is_none());
    }

    #[test]
    fn nouveautes_de_la_machine() {
        let avant = etat(
            90,
            &[
                "Santé : Disque presque plein : / n'a plus que 30 Go libres (4 %).",
                "Ports en écoute : 8080/tcp ouvert.",
            ],
        );
        // Même disque avec d'autres nombres, même port : rien de nouveau.
        let pareil = etat(
            88,
            &[
                "Santé : Disque presque plein : / n'a plus que 25 Go libres (3 %).",
                "Ports en écoute : 8080/tcp ouvert.",
            ],
        );
        assert_eq!(nouveautes_machine(&avant, &pareil), Vec::<(String, String)>::new());
        // Un nouveau port et une note qui chute de 15 points : deux notifications.
        let pire = etat(
            75,
            &[
                "Ports en écoute : 8080/tcp ouvert.",
                "Ports en écoute : 4444/tcp ouvert.",
            ],
        );
        let n = nouveautes_machine(&avant, &pire);
        assert_eq!(n.len(), 2);
        assert!(n[0].1.contains("4444"));
        assert!(n[1].1.contains("90") && n[1].1.contains("75"));
    }

    #[test]
    fn le_telephone_ne_recoit_ni_nom_d_appareil_ni_nom_de_reseau() {
        let mut h = reseau::Hote {
            ip: std::net::Ipv4Addr::new(192, 168, 1, 37),
            nom: Some("iPhone-de-Zoe.local".into()),
            mac: Some("3c:22:fb:12:34:56".into()),
            fabricant: Some("Apple".into()),
            surnom: Some("Téléphone de Zoé".into()),
            premier_vu: None,
            role: None,
            nouvelle: true,
            ports: Vec::new(),
            alertes: Vec::new(),
            score: 100,
        };
        let texte = sur_le_reseau(&appareil_pour_le_telephone(&h, "appareil inconnu"));
        assert!(texte.starts_with("Apple, "), "{texte}");
        assert!(!texte.contains("Zo") && !texte.contains("iPhone") && !texte.contains("192.168"));
        // Sans fabricant connu : la formule générale, toujours sans le nom.
        h.fabricant = None;
        assert_eq!(appareil_pour_le_telephone(&h, "appareil inconnu"), "appareil inconnu");
        // Le réseau n'est jamais nommé.
        assert!(sur_le_reseau("x").contains("cet ordinateur") || sur_le_reseau("x").contains("this computer"));
    }
}
