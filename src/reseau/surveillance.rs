//! Surveillance automatique : scan du réseau toutes les heures, notification si un appareil inconnu apparaît ; les
//! programmes arrivés dans Téléchargements, à vérifier avant de les ouvrir ; un programme qui parle à un serveur de
//! commande de botnet connu (bloqué seulement si la protection active a été activée : protection/blocage). La
//! protection en temps réel coupée (`protection::temps_reel`), chaque passe s'arrête au début, sans rien regarder ni
//! notifier ; c'est aussi la passe qui constate l'échéance de la coupure et remet la protection.
//! Planificateur natif de chaque système : timer systemd (Linux), Planificateur de tâches (Windows), agent launchd
//! (macOS).

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;

use crate::machine::Constat;
use crate::reseau::tableau::{self, Genre};
use crate::reseau::{self, Options, upnp};
use crate::risk::Niveau;
use crate::ui::*;

/// Les noms de ce que la surveillance pose sur chaque système : les unités systemd (Linux), l'agent launchd (macOS),
/// la tâche du Planificateur (Windows). Connus partout : la désinstallation les cherche par leur nom exact.
pub(crate) const NOM: &str = "vanguard-surveillance";
pub(crate) const AGENT_MACOS: &str = "com.vanguard.surveillance";
/// Nom lisible de la tâche dans le Planificateur de tâches Windows.
pub(crate) const TACHE_WINDOWS: &str = "vanguard - surveillance du reseau";

/// La commande réussit-elle ? Avec un délai : le menu demande l'état de la surveillance à chaque affichage, et un
/// bus de session muet (systemctl --user) le figerait.
#[cfg(unix)]
pub(crate) fn reussit(cmd: &str, args: &[&str]) -> bool {
    crate::commande::lancer(Command::new(cmd).args(args), 30).is_some_and(|r| r.code == Some(0))
}

/// La minuterie de l'utilisateur (« nom.timer ») est-elle activée ? Lu dans les liens que pose
/// `systemctl --user enable`, sans le lancer : un bus de session muet ne fige plus le menu. La commande ne
/// sert qu'en secours, quand aucun dossier d'unités de l'utilisateur n'existe.
#[cfg(target_os = "linux")]
pub(crate) fn minuterie_activee(timer: &str) -> bool {
    crate::machine::linux::natif::unite_activee(timer, true)
        .unwrap_or_else(|| reussit("systemctl", &["--user", "is-enabled", timer]))
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
        // « -- » : un titre ou un corps qui commence par « - » (venu d'une extension) n'est jamais lu comme une option.
        Command::new("notify-send").args(["-a", "Vanguard", "-i", "vanguard", "-u", "critical", "--", titre, corps]),
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
pub(crate) fn alerter(genre: Genre, titre: &str, texte: &str) {
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
    // Coupée : rien ne se regarde ni ne se notifie, et la dernière passe notée reste la dernière vraie. Échue : la
    // protection est remise, et la passe se fait.
    if crate::protection::temps_reel::a_la_passe() {
        return;
    }
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
    // Les extensions sans restrictions qui l'ont demandé (dans_la_surveillance) : leurs problèmes graves seulement.
    for (titre, texte) in crate::plugins::a_signaler() {
        notifier(&titre, &texte);
    }
    // La protection active, si elle a été activée : le certain bloqué tout seul, chaque blocage notifié.
    crate::protection::blocage::en_surveillance();
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
    return minuterie_activee(&format!("{NOM}.timer"));
    #[cfg(windows)]
    return tache_active(TACHE_WINDOWS);
    #[cfg(target_os = "macos")]
    return reussit("launchctl", &["print", &format!("{}/{AGENT_MACOS}", domaine_launchd())]);
}

/// Au bilan : la surveillance voulue a disparu (minuterie ou tâche retirée, ou désactivée), ou elle est là mais le
/// programme qu'elle lance n'existe plus, ou elle a été posée par une version d'avant. Constat et proposition, rien de
/// plus : Vanguard ne s'accroche pas, et une tâche acceptée n'est jamais changée en silence.
pub fn constat() -> Option<crate::machine::Constat> {
    if !fichier_voulue().is_file() {
        return None;
    }
    if !installee() {
        return juger_disparition(true, false);
    }
    juger_tache(
        Planifie::Surveillance,
        &lire_planifie(Planifie::Surveillance),
        Path::is_file,
    )
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

/// Ce que Vanguard planifie : la surveillance horaire ou l'entretien du mois.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Planifie {
    Surveillance,
    Entretien,
}

impl Planifie {
    /// (unités systemd, agent launchd, tâche du Planificateur).
    pub(crate) fn noms(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Planifie::Surveillance => (NOM, AGENT_MACOS, TACHE_WINDOWS),
            Planifie::Entretien => (
                crate::entretien::NOM,
                crate::entretien::AGENT_MACOS,
                crate::entretien::TACHE_WINDOWS,
            ),
        }
    }
}

/// Ce que le planificateur du système dit d'une tâche de Vanguard : absente, le programme qu'elle lance (et si elle
/// a les réglages d'aujourd'hui), ou illisible.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lecture {
    Absente,
    Lue { programme: PathBuf, a_jour: bool },
    Illisible(String),
}

/// Lit la tâche planifiée `quoi` de cet ordinateur : le programme qu'elle lance. Linux : la ligne ExecStart= du
/// service (le minuteur a déjà OnBootSec et Persistent : toujours à jour) ; macOS : le plist de l'agent, et son
/// RunAtLoad ; Windows : le planificateur lui-même, PowerShell en secours, et ses deux réglages de rattrapage.
pub(crate) fn lire_planifie(quoi: Planifie) -> Lecture {
    let (nom, agent, tache) = quoi.noms();
    #[cfg(target_os = "linux")]
    {
        let _ = (agent, tache);
        let chemin = dossier_unites_maison().join(format!("{nom}.service"));
        match std::fs::read_to_string(&chemin) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Lecture::Absente,
            Err(e) => Lecture::Illisible(e.to_string()),
            Ok(t) => programme_d_une_unite(&t).map_or_else(
                || Lecture::Illisible(tr!("ligne ExecStart= illisible", "unreadable ExecStart= line").to_string()),
                |programme| Lecture::Lue {
                    programme,
                    a_jour: true,
                },
            ),
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (nom, tache);
        match std::fs::read(plist_agent_nomme(agent)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Lecture::Absente,
            Err(e) => Lecture::Illisible(e.to_string()),
            Ok(o) => lire_plist(&o).map_or_else(
                || Lecture::Illisible(tr!("plist illisible", "unreadable plist").to_string()),
                |(programme, au_lancement)| Lecture::Lue {
                    programme,
                    a_jour: au_lancement,
                },
            ),
        }
    }
    #[cfg(windows)]
    {
        let _ = (nom, agent);
        match definitions_windows(&[tache]) {
            None => Lecture::Illisible(tr!("planificateur non lu", "task scheduler not read").to_string()),
            Some(lues) => {
                lues.into_iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(tache))
                    .map_or(Lecture::Absente, |(_, d)| Lecture::Lue {
                        programme: PathBuf::from(d.programme.trim().trim_matches('"')),
                        a_jour: d.des_que_possible && d.a_l_ouverture,
                    })
            }
        }
    }
}

/// Le constat d'une tâche planifiée lue : rien si elle est absente (la disparition se juge à part) ou si tout va bien ;
/// une alerte si le programme qu'elle lance n'existe plus (`existe`) : la tâche est là, mais elle ne tourne plus ; une
/// information si la surveillance a été posée par une version d'avant ; « non vérifié » si rien n'a pu être lu.
pub(crate) fn juger_tache(quoi: Planifie, l: &Lecture, existe: impl Fn(&Path) -> bool) -> Option<Constat> {
    let (programme, a_jour) = match l {
        Lecture::Absente => return None,
        Lecture::Illisible(e) => {
            return Some(crate::machine::impossible(
                "Surveillance",
                &trf!(
                    "programme lancé par la tâche non lu : {e}",
                    "program started by the task not read: {e}"
                ),
            ));
        }
        Lecture::Lue { programme, a_jour } => (programme, *a_jour),
    };
    // Un nom sans chemin (« vanguard », quand le programme n'a pas pu se situer) se cherche dans le PATH au lancement :
    // d'ici, rien ne le confirme, et rien ne le dément.
    if !programme.is_absolute() {
        return Some(crate::machine::impossible(
            "Surveillance",
            &trf!(
                "programme lancé par la tâche sans chemin : {}",
                "program started by the task without a path: {}",
                programme.display()
            ),
        ));
    }
    let chemin = chemin_affichable(programme);
    if !existe(programme) {
        return Some(match quoi {
            Planifie::Surveillance => crate::machine::alerte(
                "Surveillance",
                Niveau::Eleve,
                trf!(
                    "La surveillance horaire est planifiée, mais le programme qu'elle lance n'existe plus ({chemin}) : elle ne tourne plus. Un dossier effacé, un antivirus, ou un logiciel malveillant qui coupe d'abord ce qui le surveille, peuvent l'avoir retiré.",
                    "The hourly monitoring is scheduled, but the program it starts no longer exists ({chemin}): it no longer runs. A deleted folder, an antivirus, or malware that first cuts what watches it may have removed it."
                ),
            )
            .manuel(
                tr!(
                    "La remettre : « vanguard surveillance on » (Vanguard est recopié sur cet ordinateur et la tâche refaite) ; si tu n'en veux plus, « vanguard surveillance off »",
                    "Turn it back on: “vanguard monitor on” (Vanguard is copied onto this computer again and the task redone); if you no longer want it, “vanguard monitor off”"
                ),
                &[],
            ),
            Planifie::Entretien => crate::machine::alerte(
                "Surveillance",
                Niveau::Moyen,
                trf!(
                    "L'entretien du mois est planifié, mais le programme qu'il lance n'existe plus ({chemin}) : il ne tourne plus.",
                    "The monthly check-up is scheduled, but the program it starts no longer exists ({chemin}): it no longer runs."
                ),
            )
            .manuel(
                tr!(
                    "Le remettre : « vanguard entretien on » ; si tu n'en veux plus, « vanguard entretien off »",
                    "Turn it back on: “vanguard maintenance on”; if you no longer want it, “vanguard maintenance off”"
                ),
                &[],
            ),
        });
    }
    // L'entretien a déjà son rattrapage (-StartWhenAvailable) ; et pas de RunAtLoad pour lui : il notifierait à
    // chaque ouverture de session.
    if a_jour || quoi == Planifie::Entretien {
        return None;
    }
    let message = if cfg!(target_os = "macos") {
        tr!(
            "La surveillance horaire a été planifiée par une version d'avant : elle ne passe pas à l'ouverture de session, la première passe attend une heure.",
            "The hourly monitoring was scheduled by an earlier version: it does not run at sign-in; the first run waits an hour."
        )
    } else {
        tr!(
            "La surveillance horaire a été planifiée par une version d'avant : elle ne rattrape pas une heure manquée (ordinateur éteint ou en veille) et ne passe pas à l'ouverture de session.",
            "The hourly monitoring was scheduled by an earlier version: it does not catch up a missed hour (computer off or asleep) and does not run at sign-in."
        )
    };
    Some(
        crate::machine::alerte("Surveillance", Niveau::Info, message).manuel(
            tr!(
                "La mettre à jour, si tu veux : « vanguard surveillance on » refait la tâche avec ces réglages ; rien d'autre ne change",
                "Update it if you want: “vanguard monitor on” redoes the task with these settings; nothing else changes"
            ),
            &[],
        ),
    )
}

/// Reprise d'une surveillance active sous l'ancien nom (`passage`) : la minuterie recréée avec ses réglages d'alors
/// (acceptés tels quels), le choix noté.
pub(crate) fn reprendre(exe: &str) -> bool {
    let ok = installer(exe, Reglages::DAvant);
    if ok {
        noter_voulue(true);
    }
    ok
}

/// Les réglages d'une tâche de surveillance : ceux d'aujourd'hui (une heure manquée rattrapée, une passe à
/// l'ouverture de session), ou ceux d'une version d'avant, pour une tâche déjà acceptée qu'on reprend sans la changer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Reglages {
    Aujourdhui,
    DAvant,
}

pub fn activer(oui: bool) {
    // Une tâche d'une version d'avant que la personne réactive : elle est refaite avec les réglages d'aujourd'hui, et
    // c'est dit.
    let d_avant = oui
        && matches!(
            lire_planifie(Planifie::Surveillance),
            Lecture::Lue { a_jour: false, .. }
        );
    let reussi = if oui {
        installer(&executable(), Reglages::Aujourdhui)
    } else {
        desinstaller()
    };
    if !oui || reussi {
        noter_voulue(oui);
    }
    match (oui, reussi) {
        (true, true) => {
            trp!(
                "  {VERT}✔{RESET} Surveillance activée : scan toutes les heures, notification si un appareil inconnu arrive.",
                "  {VERT}✔{RESET} Monitoring on: scan every hour, notification if an unknown device shows up."
            );
            if d_avant {
                trp!(
                    "  La tâche d'une version d'avant est remplacée par celle d'aujourd'hui.",
                    "  The task from an earlier version is replaced with today's."
                );
            }
            // Coupée, chaque passe s'arrête au début (`passe`) : « toutes les heures » ne vaut qu'à la reprise.
            crate::protection::temps_reel::dire_si_coupee(crate::protection::temps_reel::Ou::Surveillance);
        }
        (true, false) => trp!(
            "  ✖ Impossible d'activer la surveillance.",
            "  ✖ Could not turn monitoring on."
        ),
        (false, _) => trp!("  Surveillance désactivée.", "  Monitoring off."),
    }
}

/// Retire la surveillance sans rien demander (la désinstallation l'a déjà montrée et fait accepter), et l'oublie.
/// Rend la raison d'un échec, jamais un succès supposé.
pub(crate) fn retirer() -> Result<(), String> {
    let ok = desinstaller();
    noter_voulue(false);
    if ok {
        return Ok(());
    }
    Err(if cfg!(windows) {
        tr!(
            "PowerShell n'a pas pu retirer la tâche : « vanguard surveillance off » pour réessayer",
            "PowerShell could not remove the task: “vanguard monitor off” to try again"
        )
        .to_string()
    } else {
        tr!(
            "fichiers retirés, mais systemctl --user n'a pas répondu : la minuterie peut rester chargée jusqu'à la prochaine ouverture de session, où elle disparaît",
            "files removed, but systemctl --user did not answer: the timer may stay loaded until the next sign-in, where it goes away"
        )
        .to_string()
    })
}

/// Le dossier des unités systemd de l'utilisateur où Vanguard pose la surveillance et l'entretien.
#[cfg(target_os = "linux")]
pub(crate) fn dossier_unites_maison() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config/systemd/user")
}

/// Les deux unités systemd : le service, puis le minuteur (cinq minutes après le démarrage, puis toutes les heures ;
/// une heure manquée, ordinateur éteint, est rattrapée).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn unites_systemd(exe: &str) -> (String, &'static str) {
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
    (service, timer)
}

/// Le programme que lance une unité systemd : le premier mot de sa ligne ExecStart=.
pub(crate) fn programme_d_une_unite(texte: &str) -> Option<PathBuf> {
    premier_mot_cite(texte.lines().find_map(|l| l.strip_prefix("ExecStart="))?)
}

/// Le premier mot d'une ligne de commande d'unité systemd ou de fichier .desktop. Entre guillemets, « \" » et « \\ »
/// redeviennent « " » et « \ » ; partout, « %% » redevient « % » : l'inverse de ce qu'écrivent les unités de Vanguard,
/// `sauvegarde::citer_systemd` et le raccourci.
pub(crate) fn premier_mot_cite(valeur: &str) -> Option<PathBuf> {
    let v = valeur.trim_start();
    let brut = if let Some(reste) = v.strip_prefix('"') {
        let mut mot = String::new();
        let mut car = reste.chars();
        loop {
            match car.next()? {
                '"' => break,
                '\\' => match car.next()? {
                    c @ ('"' | '\\') => mot.push(c),
                    c => {
                        mot.push('\\');
                        mot.push(c);
                    }
                },
                c => mot.push(c),
            }
        }
        mot
    } else {
        v.split_whitespace().next()?.to_string()
    };
    let mot = brut.replace("%%", "%");
    (!mot.is_empty()).then(|| PathBuf::from(mot))
}

#[cfg(target_os = "linux")]
fn installer(exe: &str, r: Reglages) -> bool {
    // Le minuteur a toujours eu OnBootSec et Persistent : rien ne distingue une tâche d'avant sous Linux.
    let _ = r;
    let dossier = dossier_unites_maison();
    let _ = std::fs::create_dir_all(&dossier);
    let (service, timer) = unites_systemd(exe);
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
    let dossier = dossier_unites_maison();
    reussit("systemctl", &["--user", "disable", "--now", &format!("{nom}.timer")]);
    let _ = std::fs::remove_file(dossier.join(format!("{nom}.service")));
    let _ = std::fs::remove_file(dossier.join(format!("{nom}.timer")));
    reussit("systemctl", &["--user", "daemon-reload"])
}

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

/// Agent launchd : relancé toutes les heures (StartInterval), et dès l'ouverture de session (RunAtLoad).
#[cfg(any(target_os = "macos", test))]
fn plist_surveillance(exe: &str, nom: &str, r: Reglages) -> String {
    let exe = exe.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let au_lancement = if r == Reglages::Aujourdhui {
        "\t<key>RunAtLoad</key>\n\t<true/>\n"
    } else {
        ""
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         \t<key>Label</key>\n\t<string>{nom}</string>\n\
         \t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>{exe}</string>\n\t\t<string>surveiller</string>\n\t</array>\n\
         \t<key>StartInterval</key>\n\t<integer>3600</integer>\n\
         {au_lancement}\
         \t<key>LowPriorityIO</key>\n\t<true/>\n\
         \t<key>Nice</key>\n\t<integer>10</integer>\n\
         </dict>\n</plist>\n"
    )
}

/// Le programme que lance un agent launchd (le premier de ProgramArguments), et s'il passe à l'ouverture de session.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn lire_plist(octets: &[u8]) -> Option<(PathBuf, bool)> {
    let v = crate::plist::lire(octets)?;
    let programme = v.cle("ProgramArguments")?.tableau()?.first()?.texte()?;
    let au_lancement = v.cle("RunAtLoad") == Some(&crate::plist::Valeur::Booleen(true));
    Some((PathBuf::from(programme), au_lancement))
}

#[cfg(target_os = "macos")]
fn installer(exe: &str, r: Reglages) -> bool {
    let plist = plist_agent();
    let _ = std::fs::create_dir_all(plist.parent().unwrap_or(&plist));
    if std::fs::write(&plist, plist_surveillance(exe, AGENT_MACOS, r)).is_err() {
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

/// La tâche existe et n'est pas désactivée : une tâche désactivée ne surveille plus rien.
#[cfg(windows)]
fn tache_active(nom: &str) -> bool {
    // Le planificateur d'abord, PowerShell en secours.
    if let Some(e) = crate::machine::windows::planificateur::etat(&[nom]) {
        return e == crate::machine::windows::planificateur::EtatTache::Active;
    }
    crate::machine::windows::ps(&format!(
        "if (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName -eq '{}' -and $_.State -ne 'Disabled' }}) {{ 'oui' }}",
        crate::commande::ps_texte(nom)
    ))
    .is_some_and(|s| s.trim() == "oui")
}

/// Une de ces tâches existe-t-elle ? Sans erreur quand aucune n'existe : un échec de PowerShell irait au journal.
#[cfg(windows)]
pub(crate) fn tache_existe(noms: &[&str]) -> bool {
    if let Some(e) = crate::machine::windows::planificateur::etat(noms) {
        return e != crate::machine::windows::planificateur::EtatTache::Absente;
    }
    let liste = noms.iter().map(|n| format!("'{n}'")).collect::<Vec<_>>().join(",");
    crate::machine::windows::ps(&format!(
        "if (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName -in @({liste}) }}) {{ 'oui' }}"
    ))
    .is_some_and(|s| s.trim() == "oui")
}

/// Ce que le Planificateur de Windows dit d'une tâche : le programme de sa première action, ses deux réglages de
/// rattrapage (« dès que possible » après une heure manquée, un déclencheur à l'ouverture de session) et si elle est
/// active.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Definition {
    pub programme: String,
    pub des_que_possible: bool,
    pub a_l_ouverture: bool,
    pub active: bool,
}

/// Les tâches nommées `noms` : le planificateur d'abord, PowerShell en secours ; `None` si aucun des deux ne répond.
#[cfg(windows)]
pub(crate) fn definitions_windows(noms: &[&str]) -> Option<Vec<(String, Definition)>> {
    if let Some(lues) = crate::machine::windows::planificateur::definitions(noms) {
        return Some(lues);
    }
    let liste = noms
        .iter()
        .map(|n| format!("'{}'", crate::commande::ps_texte(n)))
        .collect::<Vec<_>>()
        .join(",");
    let sortie = crate::machine::windows::ps(&script_definitions(&liste))?;
    Some(lire_definitions_ps(&sortie))
}

/// Le script de secours : une ligne « nom|programme|StartWhenAvailable|déclencheurs à l'ouverture|état » par tâche.
#[cfg(any(windows, test))]
fn script_definitions(liste: &str) -> String {
    format!(
        "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName -in @({liste}) }} | ForEach-Object {{ \
         $o = @($_.Triggers | Where-Object {{ $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' }}).Count; \
         \"$($_.TaskName)|$($_.Actions[0].Execute)|$($_.Settings.StartWhenAvailable)|$o|$($_.State)\" }}"
    )
}

/// Les lignes du script de secours ; une ligne abîmée est sautée, jamais devinée.
#[cfg(any(windows, test))]
pub(crate) fn lire_definitions_ps(sortie: &str) -> Vec<(String, Definition)> {
    sortie
        .lines()
        .filter_map(|l| {
            let champs: Vec<&str> = l.trim().split('|').collect();
            let [nom, programme, des_que_possible, ouverture, etat] = champs[..] else {
                return None;
            };
            let des_que_possible = match des_que_possible {
                "True" => true,
                "False" => false,
                _ => return None,
            };
            let ouverture = ouverture.parse::<u32>().ok()?;
            (!nom.is_empty() && !etat.is_empty()).then(|| {
                (
                    nom.to_string(),
                    Definition {
                        programme: programme.to_string(),
                        des_que_possible,
                        a_l_ouverture: ouverture > 0,
                        active: etat != "Disabled",
                    },
                )
            })
        })
        .collect()
}

/// Le script qui pose la tâche. Aujourd'hui : rattrapée dès que possible après une heure manquée (ordinateur éteint
/// ou en veille), et une passe cinq minutes après l'ouverture de session. Le déclencheur d'ouverture nomme le compte :
/// sans lui, Windows demanderait l'administrateur ; s'il refuse quand même, la tâche est posée sans ce déclencheur, et
/// le script le dit (« sans-ouverture »). Les réglages d'avant restent pour une tâche reprise telle qu'acceptée.
#[cfg(any(windows, test))]
fn script_tache(exe: &str, nom: &str, r: Reglages) -> String {
    let exe = crate::commande::ps_texte(exe);
    let nom = crate::commande::ps_texte(nom);
    match r {
        Reglages::DAvant => trf!(
            "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
             $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
             Register-ScheduledTask -TaskName '{nom}' -Action $a -Trigger $t -Force \
               -Description 'Scan du réseau local toutes les heures par Vanguard, notification si un appareil inconnu apparaît. Pour arrêter : vanguard surveillance off' | Out-Null",
            "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
             $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
             Register-ScheduledTask -TaskName '{nom}' -Action $a -Trigger $t -Force \
               -Description 'Hourly local network scan by Vanguard, with a notification when an unknown device appears. To stop it: vanguard monitor off' | Out-Null"
        ),
        Reglages::Aujourdhui => {
            let description = tr!(
                "Scan du réseau local toutes les heures par Vanguard, notification si un appareil inconnu apparaît, rattrapé au réveil et 5 minutes après l''ouverture de session. Pour arrêter : vanguard surveillance off",
                "Hourly local network scan by Vanguard, with a notification when an unknown device appears, caught up after sleep and 5 minutes after sign-in. To stop it: vanguard monitor off"
            );
            format!(
                "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
                 $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
                 $o = New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name); $o.Delay = 'PT5M'; \
                 $s = New-ScheduledTaskSettingsSet -StartWhenAvailable; \
                 try {{ Register-ScheduledTask -TaskName '{nom}' -Action $a -Trigger @($t, $o) -Settings $s -Force -Description '{description}' -ErrorAction Stop | Out-Null }} \
                 catch {{ Register-ScheduledTask -TaskName '{nom}' -Action $a -Trigger $t -Settings $s -Force -Description '{description}' | Out-Null; 'sans-ouverture' }}"
            )
        }
    }
}

#[cfg(windows)]
fn installer(exe: &str, r: Reglages) -> bool {
    let Some(sortie) = crate::machine::windows::ps(&script_tache(exe, TACHE_WINDOWS, r)) else {
        return false;
    };
    if sortie.lines().any(|l| l.trim() == "sans-ouverture") {
        trp!(
            "  Windows a refusé le passage à l'ouverture de session : la surveillance rattrape seulement les heures manquées.",
            "  Windows refused the sign-in run: monitoring only catches up missed hours."
        );
    }
    true
}

#[cfg(windows)]
fn desinstaller() -> bool {
    // Arrêtée d'abord : une passe en cours n'écrit plus dans le dossier de données qu'une désinstallation efface.
    crate::machine::windows::ps(&format!(
        "Stop-ScheduledTask -TaskName '{TACHE_WINDOWS}' -ErrorAction SilentlyContinue; \
         Unregister-ScheduledTask -TaskName '{TACHE_WINDOWS}' -Confirm:$false"
    ))
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sur cet ordinateur, chaque minuterie de l'utilisateur activée ou non selon systemctl l'est aussi
    /// d'après ses liens. Les états à part (static, indirect, generated…) ne se comparent pas : nos
    /// minuteries ont toujours une section [Install].
    #[cfg(target_os = "linux")]
    #[test]
    fn minuteries_comme_systemctl() {
        let Some(r) = crate::commande::lancer_en_anglais(
            Command::new("systemctl").args(["--user", "list-unit-files", "--type=timer", "--no-legend"]),
            10,
        )
        .filter(|r| r.code == Some(0)) else {
            return;
        };
        for ligne in r.sortie.lines() {
            let mut mots = ligne.split_whitespace();
            let (Some(nom), Some(etat)) = (mots.next(), mots.next()) else {
                continue;
            };
            if matches!(etat, "enabled" | "disabled" | "masked") {
                assert_eq!(minuterie_activee(nom), etat == "enabled", "{ligne}");
            }
        }
    }

    #[test]
    fn agent_launchd() {
        let exe = "/Users/a b/Library/Application Support/vanguard & co/bin/<vanguard>";
        let p = plist_surveillance(exe, "com.vanguard.surveillance", Reglages::Aujourdhui);
        assert!(p.contains(
            "<string>/Users/a b/Library/Application Support/vanguard &amp; co/bin/&lt;vanguard&gt;</string>"
        ));
        assert!(p.contains("<key>StartInterval</key>\n\t<integer>3600</integer>"));
        assert!(p.contains("<string>surveiller</string>"));
        assert!(p.contains("<key>RunAtLoad</key>\n\t<true/>"));
        // Relu tel qu'écrit : le programme d'origine, et le passage à l'ouverture de session.
        assert_eq!(lire_plist(p.as_bytes()), Some((PathBuf::from(exe), true)));
        // Une tâche reprise d'une version d'avant garde ses réglages : sans RunAtLoad, et relue comme telle.
        let avant = plist_surveillance(exe, "com.vanguard.surveillance", Reglages::DAvant);
        assert!(!avant.contains("RunAtLoad"));
        assert_eq!(lire_plist(avant.as_bytes()), Some((PathBuf::from(exe), false)));
    }

    #[test]
    fn script_de_la_tache() {
        let s = script_tache(
            "C:\\Program Files\\L'outil\\vanguard.exe",
            TACHE_WINDOWS,
            Reglages::Aujourdhui,
        );
        for attendu in [
            "-StartWhenAvailable",
            "-AtLogOn -User",
            "PT5M",
            "-Trigger @($t, $o)",
            "-Settings $s",
            "catch {",
            "'sans-ouverture'",
            "-Argument 'surveiller'",
            "-Execute 'C:\\Program Files\\L''outil\\vanguard.exe'",
        ] {
            assert!(s.contains(attendu), "{attendu} absent : {s}");
        }
        // Chaque chaîne entre apostrophes se ferme : leur nombre est pair (les doublées comptent deux).
        assert_eq!(s.matches('\'').count() % 2, 0, "{s}");
        // L'apostrophe typographique ferme aussi une chaîne PowerShell : doublée de même.
        let t = script_tache(
            "C:\\Users\\Zoé\\L’outil\\vanguard.exe",
            TACHE_WINDOWS,
            Reglages::Aujourdhui,
        );
        assert!(t.contains("-Execute 'C:\\Users\\Zoé\\L’’outil\\vanguard.exe'"), "{t}");
        // Une tâche reprise d'une version d'avant : ses réglages d'alors, rien de neuf.
        let avant = script_tache("C:\\vanguard.exe", TACHE_WINDOWS, Reglages::DAvant);
        for absent in ["-StartWhenAvailable", "-AtLogOn", "PT5M", "catch", "-Settings"] {
            assert!(!avant.contains(absent), "{absent} présent : {avant}");
        }
        assert!(avant.contains("-Argument 'surveiller'") && avant.contains(TACHE_WINDOWS));
    }

    #[test]
    fn unites_et_programme_lu() {
        let exe = "/home/a b/100%/van\"guard";
        let (service, timer) = unites_systemd(exe);
        assert!(
            service.contains("ExecStart=\"/home/a b/100%%/van\\\"guard\" surveiller\n"),
            "{service}"
        );
        assert!(timer.contains("OnBootSec=5min") && timer.contains("Persistent=true"));
        // Aller-retour : le programme relu dans l'unité est celui qu'elle lance.
        assert_eq!(programme_d_une_unite(&service), Some(PathBuf::from(exe)));
        assert_eq!(programme_d_une_unite("[Service]\nType=oneshot\n"), None);
        assert_eq!(
            programme_d_une_unite("ExecStart=/usr/bin/vanguard surveiller\n"),
            Some(PathBuf::from("/usr/bin/vanguard"))
        );
        // L'unité de la sauvegarde : rsync, écrit par citer_systemd.
        let (_, sauvegarde) = crate::sauvegarde::unites(
            Path::new("/usr/bin/rsync"),
            Some(Path::new("/usr/bin/findmnt")),
            Some("1234-ABCD"),
            Path::new("/run/media/alice/Externe"),
            Path::new("/run/media/alice/Externe/Sauvegarde-Vanguard/pc"),
            &[PathBuf::from("/home/alice/Documents")],
            false,
        )
        .unwrap();
        assert_eq!(
            programme_d_une_unite(&sauvegarde),
            Some(PathBuf::from("/usr/bin/rsync"))
        );
    }

    #[test]
    fn programme_planifie_disparu_ou_d_avant() {
        let lue = |a_jour| Lecture::Lue {
            programme: PathBuf::from(if cfg!(windows) {
                r"C:\vanguard\vanguard.exe"
            } else {
                "/opt/vanguard/vanguard"
            }),
            a_jour,
        };
        // Le programme parti : la tâche est là, mais ne tourne plus.
        let c = juger_tache(Planifie::Surveillance, &lue(true), |_| false).expect("constat");
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.verifie && !c.correctif.as_ref().unwrap().automatique);
        assert!(
            c.correctif.as_ref().unwrap().action.contains("surveillance on")
                || c.correctif.as_ref().unwrap().action.contains("monitor on")
        );
        // Présent, posé par une version d'avant : une information, et la remise à jour proposée.
        let c = juger_tache(Planifie::Surveillance, &lue(false), |_| true).expect("constat");
        assert_eq!(c.probleme, Some(Niveau::Info));
        let action = &c.correctif.as_ref().unwrap().action;
        assert!(
            action.contains("surveillance on") || action.contains("monitor on"),
            "{action}"
        );
        // Illisible : non vérifié, jamais compté comme sain.
        let c = juger_tache(Planifie::Surveillance, &Lecture::Illisible("refus".into()), |_| true).expect("constat");
        assert!(!c.verifie);
        // Un nom sans chemin : non vérifié non plus.
        let relatif = Lecture::Lue {
            programme: PathBuf::from("vanguard"),
            a_jour: true,
        };
        assert!(!juger_tache(Planifie::Surveillance, &relatif, |_| true).unwrap().verifie);
        // Tout va bien, ou rien de planifié : rien à dire.
        assert!(juger_tache(Planifie::Surveillance, &lue(true), |_| true).is_none());
        assert!(juger_tache(Planifie::Surveillance, &Lecture::Absente, |_| false).is_none());
        // L'entretien : moyen, et jamais « d'une version d'avant » (il a déjà son rattrapage).
        let c = juger_tache(Planifie::Entretien, &lue(true), |_| false).expect("constat");
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("entretien") || c.message.contains("check-up"));
        assert!(juger_tache(Planifie::Entretien, &lue(false), |_| true).is_none());
    }

    #[test]
    fn definitions_lues_par_powershell() {
        let sortie = "vanguard - surveillance du reseau|C:\\Users\\alice\\vanguard.exe|True|1|Ready\n\
                      vanguard - entretien du mois|C:\\vanguard.exe|False|0|Disabled\n\
                      abîmée|sans|champs\n\
                      x|y|Peut-être|1|Ready\n";
        let lues = lire_definitions_ps(sortie);
        assert_eq!(lues.len(), 2, "{lues:?}");
        assert_eq!(
            lues[0],
            (
                "vanguard - surveillance du reseau".to_string(),
                Definition {
                    programme: "C:\\Users\\alice\\vanguard.exe".into(),
                    des_que_possible: true,
                    a_l_ouverture: true,
                    active: true,
                }
            )
        );
        assert!(!lues[1].1.des_que_possible && !lues[1].1.a_l_ouverture && !lues[1].1.active);
        // Le script de secours nomme les tâches et rend ces cinq champs.
        let script = script_definitions("'a','b'");
        assert!(script.contains("-in @('a','b')") && script.contains("MSFT_TaskLogonTrigger"));
        assert!(
            script.contains("$($_.TaskName)|$($_.Actions[0].Execute)|$($_.Settings.StartWhenAvailable)|$o|$($_.State)")
        );
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
            bail: 0,
            hote_distant: String::new(),
            active: true,
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
