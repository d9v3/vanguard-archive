//! Surveillance automatique : scan du réseau toutes les heures, notification si un appareil inconnu apparaît ; les
//! programmes arrivés dans Téléchargements, à vérifier avant de les ouvrir ; un programme qui parle à un serveur de
//! commande de botnet connu (rien n'est bloqué).
//! Planificateur natif de chaque système : timer systemd (Linux), Planificateur de tâches (Windows), agent launchd
//! (macOS).

#[cfg(unix)]
use std::process::Command;

use crate::machine::Constat;
use crate::reseau::tableau::{self, Genre};
use crate::reseau::{self, Options, upnp};
use crate::risk::Niveau;
use crate::ui::*;

#[cfg(target_os = "linux")]
const NOM: &str = "vanguard-surveillance";

/// La commande réussit-elle ? Avec un délai : le menu demande l'état de la surveillance à chaque affichage, et un
/// bus de session muet (systemctl --user) le figerait.
#[cfg(unix)]
pub(crate) fn reussit(cmd: &str, args: &[&str]) -> bool {
    crate::commande::lancer(Command::new(cmd).args(args), 30).is_some_and(|r| r.code == Some(0))
}

/// Programme à planifier. Lancé depuis la clé USB, on en installe d'abord une copie locale :
/// sinon la surveillance (et l'entretien du mois) s'arrêterait dès que la clé est débranchée.
pub(crate) fn executable() -> String {
    // Sous Linux et macOS, le programme peut tourner depuis une copie temporaire (protection de la clé), effacée
    // à la fin.
    #[cfg(unix)]
    let exe = crate::protection::cle::exe_d_origine();
    #[cfg(windows)]
    let exe = std::env::current_exe().ok();
    let Some(exe) = exe else {
        return "vanguard".into();
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
    // Délai : sans service de notifications qui réponde, notify-send attendrait sans fin, et la surveillance avec.
    #[cfg(target_os = "linux")]
    let _ = crate::commande::lancer(
        Command::new("notify-send").args(["-a", "Vanguard", "-i", "vanguard", "-u", "critical", titre, corps]),
        10,
    );
    // macOS : notification du Centre de notifications, par AppleScript (texte entre guillemets échappés).
    #[cfg(target_os = "macos")]
    {
        let e = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let _ = crate::commande::lancer(
            Command::new("osascript").arg("-e").arg(format!(
                "display notification \"{}\" with title \"{}\" sound name \"Basso\"",
                e(corps),
                e(titre)
            )),
            10,
        );
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

/// Une alerte de la surveillance : gardée au journal du tableau de bord, puis notifiée. Une notification disparaît
/// en quelques secondes ; celle de la nuit se relit ainsi le matin (« vanguard tableau »).
fn alerter(genre: Genre, titre: &str, texte: &str) {
    tableau::noter_alerte(genre, titre, texte);
    notifier(titre, texte);
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
    "Bluetooth",
    "Fin de support",
    "Durcissement",
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
            trf!("Vanguard : {}", "Vanguard: {}", crate::langue::categorie(cat)),
            msg.to_string(),
        ));
    }
    if nouvelles.len() > 3 {
        notes.push((
            tr!("Vanguard : autres problèmes", "Vanguard: other problems").to_string(),
            trf!(
                "{} autre(s) problème(s) nouveau(x) : lance « vanguard machine ».",
                "{} other new problem(s): run “vanguard audit”.",
                nouvelles.len() - 3
            ),
        ));
    }
    if let (Some(a), Some(b)) = (avant.score, apres.score)
        && b + 10 <= a
    {
        notes.push((
            tr!("Vanguard : note en baisse", "Vanguard: grade dropping").to_string(),
            trf!(
                "La note de cette machine passe de {a} à {b} : lance « vanguard machine » pour voir pourquoi.",
                "This machine's grade drops from {a} to {b}: run “vanguard audit” to see why."
            ),
        ));
    }
    notes
}

/// Audit silencieux de cette machine, comparé au passage précédent. Le premier passage mémorise seulement. Rend le
/// bilan : l'audit du réseau reprend ses constats réseau sans relancer ces règles.
fn veiller_machine() -> crate::machine::Audit {
    let audit = crate::machine::auditer(false);
    let apres = etat_machine(&audit);
    let avant: Option<EtatMachine> = std::fs::read_to_string(fichier_etat())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    if let Some(avant) = &avant {
        for (titre, texte) in nouveautes_machine(avant, &apres) {
            alerter(Genre::Machine, &titre, &texte);
        }
    }
    if let Ok(texte) = serde_json::to_string(&apres) {
        let _ = std::fs::create_dir_all(reseau::dossier_local());
        let _ = std::fs::write(fichier_etat(), texte);
    }
    audit
}

/// L'audit du réseau au dernier passage, réduit à ce qui déclenche une alerte quand il change : les redirections de
/// la box (`None` : non lues, rien à comparer) et les constats des règles suivies.
#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq)]
struct EtatAudit {
    redirections: Option<Vec<String>>,
    /// « règle|catégorie : message », les nombres neutralisés sauf pour le DNS du bail, dont l'adresse compte.
    constats: Vec<String>,
}

fn fichier_audit() -> std::path::PathBuf {
    reseau::dossier_local().join("surveillance-audit.json")
}

/// La clé d'une redirection, stable d'une passe à l'autre.
fn cle_redirection(r: &upnp::Redirection) -> String {
    format!(
        "{} {} → {}:{}",
        r.protocole.to_uppercase(),
        r.port_public,
        r.appareil,
        r.port_appareil
    )
}

/// Le genre de l'alerte d'une règle de l'audit que la surveillance suit ; `None` : règle non suivie. Les
/// redirections (COM-EXP-001) sont comparées à part, par redirection.
fn genre_de(regle: &str) -> Option<Genre> {
    match regle {
        "COM-EXP-003" => Some(Genre::Machine),
        "COM-DNS-002" | "COM-DNS-004" => Some(Genre::Passerelle),
        r if r.starts_with("COM-WIF-") => Some(Genre::WiFi),
        _ => None,
    }
}

/// Un constat de l'audit que la surveillance suit : vérifié, d'une règle suivie, moyen ou plus grave — sauf le DNS
/// distribué par la box, suivi dès l'information, puisque c'est son changement qui compte.
fn surveille(c: &Constat) -> bool {
    c.verifie
        && genre_de(c.regle).is_some()
        && (c.regle == "COM-DNS-002" || c.probleme.is_some_and(|n| n >= Niveau::Moyen))
}

fn cle_constat(c: &Constat) -> String {
    let texte = format!("{} : {}", c.categorie, c.message);
    let texte = if c.regle == "COM-DNS-002" {
        texte
    } else {
        cle_alerte(&texte)
    };
    format!("{}|{texte}", c.regle)
}

fn etat_audit(r: &reseau::Rapport, a: &crate::audit::AuditReseau) -> EtatAudit {
    EtatAudit {
        redirections: crate::audit::redirections_du_scan(r).map(|l| l.iter().map(cle_redirection).collect()),
        constats: a
            .domaines
            .iter()
            .flat_map(|d| &d.constats)
            .filter(|c| surveille(c))
            .map(cle_constat)
            .collect(),
    }
}

/// Le titre de la notification d'un constat nouveau, selon sa règle.
fn titre_alerte(regle: &str) -> String {
    match regle {
        "COM-DNS-002" => tr!(
            "Vanguard : le DNS distribué par la box a changé",
            "Vanguard: the DNS handed out by the router changed"
        ),
        "COM-DNS-004" => tr!("Vanguard : réponses DNS détournées", "Vanguard: DNS answers hijacked"),
        "COM-EXP-003" => tr!(
            "Vanguard : cet ordinateur exposé en IPv6",
            "Vanguard: this computer exposed over IPv6"
        ),
        _ => tr!("Vanguard : Wi-Fi moins protégé", "Vanguard: Wi-Fi less protected"),
    }
    .to_string()
}

/// Les alertes entre deux passages de l'audit : (titre, texte, genre), une par redirection nouvelle de la box et par
/// constat nouveau d'une règle suivie ; rien quand les redirections n'ont pas pu être lues à l'un des deux passages.
fn nouveautes_audit(
    avant: &EtatAudit,
    apres: &EtatAudit,
    redirections: &[upnp::Redirection],
    constats: &[&Constat],
) -> Vec<(String, String, Genre)> {
    let mut alertes = Vec::new();
    if let (Some(av), Some(ap)) = (&avant.redirections, &apres.redirections) {
        for r in redirections.iter().filter(|r| {
            let cle = cle_redirection(r);
            ap.contains(&cle) && !av.contains(&cle)
        }) {
            let description = if r.description.is_empty() {
                String::new()
            } else {
                format!(" « {} »", r.description)
            };
            alertes.push((
                tr!(
                    "Vanguard : la box ouvre un port vers Internet",
                    "Vanguard: the router opens a port to the Internet"
                )
                .to_string(),
                trf!(
                    "Nouvelle redirection : port {}/{} d'Internet vers {}:{} ({}){description}. Un appareil l'a demandée à la box (UPnP) : si ce n'est pas voulu, retire-la et coupe UPnP dans la box.",
                    "New forwarding: Internet port {}/{} to {}:{} ({}){description}. A device asked the router for it (UPnP): if it is not wanted, remove it and turn UPnP off in the router.",
                    r.port_public,
                    r.protocole.to_lowercase(),
                    r.appareil,
                    r.port_appareil,
                    crate::risk::info_port(r.port_appareil).service
                ),
                Genre::Passerelle,
            ));
        }
    }
    for c in constats.iter().filter(|c| surveille(c)) {
        let cle = cle_constat(c);
        if apres.constats.contains(&cle) && !avant.constats.contains(&cle) {
            let Some(genre) = genre_de(c.regle) else { continue };
            alertes.push((titre_alerte(c.regle), c.message.clone(), genre));
        }
    }
    alertes
}

/// Les domaines rapides de l'audit du réseau après le scan, comparés au passage précédent : une alerte par
/// changement (redirection nouvelle de la box, DNS du bail changé, Wi-Fi moins protégé, exposition IPv6 nouvelle,
/// divergence DNS), jamais à chaque passe. Le premier passage mémorise seulement.
async fn veiller_audit(r: &reseau::Rapport, machine: Vec<Constat>) {
    let a = crate::audit::auditer(r, Some(machine), false, true).await;
    let apres = etat_audit(r, &a);
    let avant: Option<EtatAudit> = std::fs::read_to_string(fichier_audit())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    if let Some(avant) = &avant {
        let redirections = crate::audit::redirections_du_scan(r).unwrap_or_default();
        let constats: Vec<&Constat> = a.domaines.iter().flat_map(|d| &d.constats).collect();
        for (titre, texte, genre) in nouveautes_audit(avant, &apres, &redirections, &constats) {
            alerter(genre, &titre, &texte);
        }
    }
    if let Ok(texte) = serde_json::to_string(&apres) {
        let _ = std::fs::create_dir_all(reseau::dossier_local());
        let _ = std::fs::write(fichier_audit(), texte);
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
        alerter(
            Genre::Passerelle,
            tr!("Vanguard : box usurpée ?", "Vanguard: router impersonated?"),
            &reseau::message_usurpation(boite, &mac, autre),
        );
        return;
    }
    let Some(apres) = passerelle_de(r) else { return };
    let avant: Option<Passerelle> = std::fs::read_to_string(fichier_passerelle())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    if let Some((ancienne, nouvelle)) = avant.as_ref().and_then(|a| mac_changee(a, &apres)) {
        alerter(
            Genre::Passerelle,
            tr!(
                "Vanguard : la box a changé d'adresse MAC",
                "Vanguard: the router's MAC address changed"
            ),
            &trf!(
                "La box {} répondait avec {ancienne}, elle répond maintenant avec {nouvelle}. Normal si tu viens de changer de box ; sinon, quelqu'un se fait peut-être passer pour elle (usurpation ARP).",
                "The router {} answered with {ancienne}, it now answers with {nouvelle}. Normal if you just replaced it; otherwise someone may be impersonating it (ARP spoofing).",
                apres.ip
            ),
        );
    }
    if let Ok(texte) = serde_json::to_string(&apres) {
        let _ = std::fs::create_dir_all(reseau::dossier_local());
        let _ = std::fs::write(fichier_passerelle(), texte);
    }
}

pub async fn surveiller() {
    // Les exemples du guide se renouvellent pendant la passe (au plus une fois par semaine), sans la retarder.
    let exemples = std::thread::spawn(crate::guide::renouveler_exemples);
    passe().await;
    let _ = exemples.join();
}

async fn passe() {
    tableau::noter_passe();
    let machine = veiller_machine();
    if let Some(fichiers) = crate::protection::integrite::changements_a_signaler() {
        alerter(
            Genre::Fichiers,
            tr!(
                "Vanguard : fichiers critiques modifiés",
                "Vanguard: critical files changed"
            ),
            &fichiers,
        );
    }
    for (titre, texte) in crate::protection::telechargement::nouveaux_a_signaler() {
        alerter(Genre::Telechargement, &titre, &texte);
    }
    for (titre, texte) in crate::protection::sortantes::botnets_a_signaler() {
        alerter(Genre::Botnet, &titre, &texte);
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
    veiller_audit(
        &r,
        machine
            .constats
            .into_iter()
            .filter(|c| crate::audit::regle_du_reseau(c.regle))
            .collect(),
    )
    .await;
    // Empoisonneur de noms (Responder…) : la sonde est déjà faite pendant le scan du réseau local, elle ne coûte
    // rien de plus ici. Sans réseau local (VPN seul), le scan n'aurait pas tourné : rien à signaler.
    if let Some(reseau::empoisonnement::Rapport::Teste(empoisonneurs)) = &r.empoisonnement {
        for e in empoisonneurs {
            let titre = r
                .hotes
                .iter()
                .find(|h| h.ip == e.ip)
                .map(reseau::Hote::titre)
                .filter(|t| !t.is_empty());
            alerter(
                Genre::Empoisonneur,
                tr!(
                    "Vanguard : empoisonneur de noms sur le réseau",
                    "Vanguard: name poisoner on the network"
                ),
                &trf!(
                    "{} répond à des noms qui n'existent pas : un outil comme Responder vole les mots de passe Windows. Débranche-le.",
                    "{} answers names that do not exist: a tool like Responder steals Windows passwords. Unplug it.",
                    titre.map_or_else(|| e.ip.to_string(), |t| format!("{} ({t})", e.ip))
                ),
            );
        }
    }
    for h in r.hotes.iter().filter(|h| h.nouvelle) {
        let qui = if h.titre().is_empty() {
            tr!("appareil inconnu", "unknown device").into()
        } else {
            h.titre()
        };
        alerter(
            Genre::Appareil,
            tr!("Nouvel appareil sur ton réseau", "New device on your network"),
            &format!("{} — {qui} {}", h.ip, h.mac.as_deref().unwrap_or("")),
        );
    }
    for h in r.hotes.iter().filter(|h| !h.nouvelle) {
        for p in h.ports.iter().filter(|p| p.nouveau && p.niveau >= Niveau::Eleve) {
            alerter(
                Genre::Port,
                &trf!("Port {} nouvellement ouvert", "Port {} newly opened", p.port),
                &format!("{} ({}) : {} — {}", h.ip, h.titre(), p.service, p.conseil),
            );
        }
    }
}

/// Le choix de la personne, noté quand la surveillance est activée (ou vue active) : si la minuterie ou la tâche
/// disparaît ensuite sans qu'elle l'ait coupée, le bilan le dit.
fn fichier_voulue() -> std::path::PathBuf {
    reseau::dossier_local().join("surveillance-voulue")
}

fn noter_voulue(oui: bool) {
    let fichier = fichier_voulue();
    if oui {
        if let Some(parent) = fichier.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(fichier, b"");
    } else {
        let _ = std::fs::remove_file(fichier);
    }
}

pub fn active() -> bool {
    let active = installee();
    if active {
        noter_voulue(true);
    }
    active
}

/// La minuterie, la tâche planifiée (non désactivée) ou l'agent existent-ils ?
fn installee() -> bool {
    #[cfg(target_os = "linux")]
    return reussit("systemctl", &["--user", "is-enabled", &format!("{NOM}.timer")]);
    #[cfg(windows)]
    return tache_active(TACHE_WINDOWS);
    #[cfg(target_os = "macos")]
    return reussit("launchctl", &["print", &format!("{}/{AGENT_MACOS}", domaine_launchd())]);
}

/// Au bilan : la surveillance voulue a disparu (minuterie ou tâche retirée, ou désactivée). Constat et proposition,
/// rien de plus : Vanguard ne s'accroche pas.
pub fn constat() -> Option<crate::machine::Constat> {
    let voulue = fichier_voulue().is_file();
    juger_disparition(voulue, voulue && installee())
}

fn juger_disparition(voulue: bool, installee: bool) -> Option<crate::machine::Constat> {
    (voulue && !installee).then(|| {
        crate::machine::alerte(
            "Surveillance",
            Niveau::Eleve,
            tr!(
                "La surveillance horaire que tu avais activée n'existe plus : sa minuterie ou sa tâche planifiée a été retirée ou désactivée. Une mise à jour du système peut l'avoir fait ; un logiciel malveillant aussi, qui coupe d'abord ce qui le surveille.",
                "The hourly monitoring you had turned on no longer exists: its timer or scheduled task was removed or disabled. A system update may have done it; so may malware, which first cuts what watches it."
            ),
        )
        .manuel(
            tr!(
                "La remettre : menu « Réseau et Internet » › Surveillance, ou « vanguard surveillance on » ; si c'est toi qui l'as coupée, « vanguard surveillance off » pour que Vanguard l'oublie",
                "Turn it back on: menu “Network and Internet” › Monitoring, or “vanguard monitor on”; if you turned it off yourself, “vanguard monitor off” so Vanguard forgets it"
            ),
            &[],
        )
    })
}

/// Reprise d'une surveillance active sous l'ancien nom (`passage`) : la minuterie recréée, le choix noté.
pub(crate) fn reprendre(exe: &str) -> bool {
    let ok = installer(exe);
    if ok {
        noter_voulue(true);
    }
    ok
}

pub fn activer(oui: bool) {
    let reussi = if oui { installer(&executable()) } else { desinstaller() };
    if !oui || reussi {
        noter_voulue(oui);
    }
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
        "[Unit]\nDescription=Vanguard : surveillance du réseau local\n\n[Service]\nType=oneshot\nExecStart={exe} surveiller\nNice=10\n",
        "[Unit]\nDescription=Vanguard: local network monitoring\n\n[Service]\nType=oneshot\nExecStart={exe} surveiller\nNice=10\n"
    );
    let timer = tr!(
        "[Unit]\nDescription=Vanguard : scan du réseau toutes les heures\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
        "[Unit]\nDescription=Vanguard: network scan every hour\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
    );
    let _ = std::fs::write(dossier.join(format!("{NOM}.service")), service);
    let _ = std::fs::write(dossier.join(format!("{NOM}.timer")), timer);
    reussit("systemctl", &["--user", "daemon-reload"])
        && reussit("systemctl", &["--user", "enable", "--now", &format!("{NOM}.timer")])
}

#[cfg(target_os = "linux")]
fn desinstaller() -> bool {
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

/// Agent launchd de la surveillance sous macOS (~/Library/LaunchAgents/<nom>.plist).
#[cfg(target_os = "macos")]
const AGENT_MACOS: &str = "com.vanguard.surveillance";

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
    // SAFETY : getuid n'a ni argument ni échec possible.
    let uid = unsafe { libc::getuid() };
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
    retirer_agent(&plist_agent());
    true
}

/// Nom lisible de la tâche dans le Planificateur de tâches Windows.
#[cfg(windows)]
const TACHE_WINDOWS: &str = "vanguard - surveillance du reseau";

/// La tâche existe et n'est pas désactivée : une tâche désactivée ne surveille plus rien.
#[cfg(windows)]
fn tache_active(nom: &str) -> bool {
    crate::machine::windows::ps(&format!(
        "if (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName -eq '{}' -and $_.State -ne 'Disabled' }}) {{ 'oui' }}",
        crate::commande::ps_texte(nom)
    ))
    .is_some_and(|s| s.trim() == "oui")
}

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
fn installer(exe: &str) -> bool {
    use crate::machine::windows::ps;
    let exe = crate::commande::ps_texte(exe);
    // Tâche visible et décrite : on voit dans le Planificateur ce qu'elle fait et comment l'arrêter.
    let script = trf!(
        "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
         $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
         Register-ScheduledTask -TaskName '{TACHE_WINDOWS}' -Action $a -Trigger $t -Force \
           -Description 'Scan du réseau local toutes les heures par Vanguard, notification si un appareil inconnu apparaît. Pour arrêter : vanguard surveillance off' | Out-Null",
        "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
         $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
         Register-ScheduledTask -TaskName '{TACHE_WINDOWS}' -Action $a -Trigger $t -Force \
           -Description 'Hourly local network scan by Vanguard, with a notification when an unknown device appears. To stop it: vanguard monitor off' | Out-Null"
    );
    ps(&script).is_some()
}

#[cfg(windows)]
fn desinstaller() -> bool {
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
            "/Users/a b/Library/Application Support/vanguard/bin/vanguard",
            "com.vanguard.surveillance",
        );
        assert!(p.contains("<string>/Users/a b/Library/Application Support/vanguard/bin/vanguard</string>"));
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
    /// L'audit du réseau entre deux passes : une alerte par redirection nouvelle de la box et par constat nouveau
    /// d'une règle suivie ; un nombre qui change ne compte pas, sauf l'adresse du DNS distribué par la box ; des
    /// redirections non lues ne se comparent pas.
    #[test]
    fn nouveautes_de_l_audit() {
        let redirection = |public: u16, appareil: &str, port: u16| upnp::Redirection {
            protocole: "TCP".into(),
            port_public: public,
            appareil: appareil.into(),
            port_appareil: port,
            description: "Camera".into(),
        };
        let constat = |regle: &'static str, niveau: Niveau, message: &str| {
            let mut c = crate::machine::alerte("Wi-Fi", niveau, message);
            c.regle = regle;
            c
        };
        let redirections = [redirection(3074, "10.0.0.20", 3074), redirection(8080, "10.0.0.30", 80)];
        let tkip = constat(
            "COM-WIF-001",
            Niveau::Moyen,
            "Le Wi-Fi « Salon » accepte encore TKIP (3 bornes).",
        );
        let dns = constat(
            "COM-DNS-002",
            Niveau::Info,
            "La box distribue le DNS 203.0.113.9 à tous tes appareils.",
        );
        let ipv6 = constat(
            "COM-EXP-003",
            Niveau::Eleve,
            "Cet ordinateur a une adresse IPv6 publique sans pare-feu.",
        );
        // Non suivis : une règle hors liste, une information d'une règle suivie, un constat non vérifié.
        let hors = constat("COM-APP-002", Niveau::Critique, "Telnet ouvert.");
        let info = constat("COM-WIF-002", Niveau::Info, "WPS par bouton seulement.");
        let mut non_verifie = constat("COM-WIF-001", Niveau::Moyen, "x");
        non_verifie.verifie = false;
        let constats = [&tkip, &dns, &ipv6, &hors, &info, &non_verifie];
        let avant = EtatAudit {
            redirections: Some(vec![cle_redirection(&redirections[0])]),
            constats: vec![
                cle_constat(&constat(
                    "COM-WIF-001",
                    Niveau::Moyen,
                    "Le Wi-Fi « Salon » accepte encore TKIP (2 bornes).",
                )),
                cle_constat(&constat(
                    "COM-DNS-002",
                    Niveau::Info,
                    "La box distribue le DNS 10.0.0.1 à tous tes appareils.",
                )),
            ],
        };
        let apres = EtatAudit {
            redirections: Some(redirections.iter().map(cle_redirection).collect()),
            constats: constats
                .iter()
                .filter(|c| surveille(c))
                .map(|c| cle_constat(c))
                .collect(),
        };
        assert_eq!(apres.constats.len(), 3);
        let alertes = nouveautes_audit(&avant, &apres, &redirections, &constats);
        let genres: Vec<Genre> = alertes.iter().map(|a| a.2).collect();
        assert_eq!(genres, [Genre::Passerelle, Genre::Passerelle, Genre::Machine]);
        assert!(
            alertes[0].1.contains("8080/tcp")
                && alertes[0].1.contains("10.0.0.30:80")
                && alertes[0].1.contains("Camera")
        );
        assert!(alertes[1].0.contains("DNS") && alertes[1].1.contains("203.0.113.9"));
        assert!(alertes[2].0.contains("IPv6"));
        // Rien de nouveau : aucune alerte ; redirections non lues à l'un des deux passages : pas comparées.
        assert_eq!(nouveautes_audit(&apres, &apres, &redirections, &constats).len(), 0);
        let non_lues = EtatAudit {
            redirections: None,
            ..EtatAudit::default()
        };
        let seulement = nouveautes_audit(&non_lues, &apres, &redirections, &constats);
        assert!(
            seulement
                .iter()
                .all(|a| a.2 != Genre::Passerelle || a.0.contains("DNS"))
        );
        // L'état se relit tel qu'il a été écrit.
        let relu: EtatAudit = serde_json::from_str(&serde_json::to_string(&apres).unwrap()).unwrap();
        assert_eq!(relu, apres);
    }

    #[test]
    fn surveillance_voulue_mais_disparue() {
        assert!(juger_disparition(false, false).is_none());
        assert!(juger_disparition(true, true).is_none());
        let c = juger_disparition(true, false).expect("constat");
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(!c.correctif.as_ref().unwrap().automatique);
    }
}
