//! Audit de sécurité macOS (12 Monterey et plus récents), sans droits administrateur. Les corrections passent par
//! `sudo` dans le Terminal, après accord, comme sous Linux.
//!
//! Écrit sans Mac sous la main : les lectures sont vérifiées par les tests automatiques sur les Mac de GitHub
//! (.github/workflows/macos.yml), et une vérification qui échoue le dit (« Impossible de vérifier ») plutôt que de conclure.

use std::path::PathBuf;

use super::{Audit, Constat, alerte, cles_ssh, impossible, ok, score, sortie};
use crate::risk::{Niveau, info_port};
use crate::{tr, trf};

mod maj;
mod persistance;

pub use maj::mises_a_jour_completes;
use persistance::persistance;

pub const NOM: &str = "macOS";

/// Famille de processeur, comme Apple la nomme.
pub fn architecture() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "Apple Silicon"
    } else {
        "Intel"
    }
}

const PARE_FEU: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// Commande d'installation d'un outil (Homebrew, le gestionnaire de paquets des Mac).
pub fn commande_installation(paquet: &str) -> String {
    if homebrew().is_some() {
        format!("brew install {paquet}")
    } else {
        trf!(
            "installer Homebrew (https://brew.sh), puis : brew install {paquet}",
            "install Homebrew (https://brew.sh), then: brew install {paquet}"
        )
    }
}

/// Programme brew, s'il est installé (Apple Silicon : /opt/homebrew, Intel : /usr/local).
pub fn homebrew() -> Option<&'static str> {
    ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())
}

/// Commandes qui installent une application avec Homebrew (« cask »). Sans Homebrew, on l'installe d'abord
/// (script officiel, il demande le mot de passe et explique ce qu'il fait).
pub fn installer_cask(cask: &str) -> Vec<String> {
    if let Some(brew) = homebrew() {
        return vec![format!("{brew} install --cask {cask}")];
    }
    let brew = if cfg!(target_arch = "aarch64") {
        "/opt/homebrew/bin/brew"
    } else {
        "/usr/local/bin/brew"
    };
    vec![
        "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"".into(),
        format!("{brew} install --cask {cask}"),
    ]
}

/// Application présente dans /Applications ou ~/Applications (installée par Homebrew ou à la main).
pub fn app_installee(nom: &str) -> bool {
    [PathBuf::from("/Applications"), maison().join("Applications")]
        .iter()
        .any(|d| d.join(format!("{nom}.app")).is_dir())
}

fn maison() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}

/// Lit une préférence système (`defaults read <domaine> <clé>`) ; `None` si elle n'existe pas.
fn preference(domaine: &str, cle: &str) -> Option<String> {
    sortie("defaults", &["read", domaine, cle]).map(|s| s.trim().to_string())
}

/// « Firewall is enabled. (State = 1) » ; « State = 2 » : tout bloquer sauf l'essentiel.
fn lire_pare_feu(sortie: &str) -> Option<bool> {
    if sortie.contains("disabled") || sortie.contains("State = 0") {
        Some(false)
    } else if sortie.contains("enabled") || sortie.contains("State = 1") || sortie.contains("State = 2") {
        Some(true)
    } else {
        None
    }
}

fn pare_feu() -> Constat {
    match sortie(PARE_FEU, &["--getglobalstate"]).as_deref().and_then(lire_pare_feu) {
        Some(true) => ok("Pare-feu", tr!("Le pare-feu de macOS est actif.", "The macOS firewall is on.")),
        Some(false) => alerte(
            "Pare-feu",
            Niveau::Eleve,
            tr!(
                "Le pare-feu de macOS est désactivé : les programmes de ce Mac peuvent recevoir des connexions de tout le réseau.",
                "The macOS firewall is off: the programs on this Mac can receive connections from the whole network."
            ),
        )
        .corriger(
            tr!("Activer le pare-feu de macOS", "Turn on the macOS firewall"),
            &[format!("sudo {PARE_FEU} --setglobalstate on")],
        ),
        None => impossible("Pare-feu", tr!("socketfilterfw illisible", "socketfilterfw unreadable")),
    }
}

/// Mode furtif : le Mac ne répond pas aux sondes (ping…) du réseau. Utile sur les Wi-Fi publics.
fn mode_furtif() -> Option<Constat> {
    let texte = sortie(PARE_FEU, &["--getstealthmode"])?;
    if texte.contains("enabled") || texte.contains("is on") {
        return Some(ok("Pare-feu", tr!("Mode furtif actif.", "Stealth mode on.")));
    }
    Some(
        alerte(
            "Pare-feu",
            Niveau::Info,
            tr!(
                "Mode furtif désactivé : ce Mac répond aux sondes du réseau, ce qui le rend visible sur un Wi-Fi public.",
                "Stealth mode off: this Mac answers network probes, which makes it visible on public Wi-Fi."
            ),
        )
        .corriger(
            tr!("Activer le mode furtif", "Turn on stealth mode"),
            &[format!("sudo {PARE_FEU} --setstealthmode on")],
        ),
    )
}

/// Ports en écoute de `netstat -an -p tcp|udp` : « tcp4  0  0  *.22  *.*  LISTEN » → (adresse, port).
/// L'adresse et le port sont séparés par le dernier point (« 127.0.0.1.631 », « ::1.631 », « *.5900 »).
fn lire_netstat(sortie: &str, tcp: bool) -> Vec<(String, u16)> {
    sortie
        .lines()
        .filter(|l| {
            if tcp {
                l.contains("LISTEN")
            } else {
                l.starts_with("udp")
            }
        })
        .filter_map(|l| {
            let local = l.split_whitespace().nth(3)?;
            let (adresse, port) = local.rsplit_once('.')?;
            Some((adresse.to_string(), port.parse().ok()?))
        })
        .collect()
}

/// Service de partage de macOS derrière un port, et où le couper.
fn partage(port: u16) -> Option<&'static str> {
    Some(match port {
        22 => tr!("Partage à distance (Remote Login, SSH)", "Remote Login (SSH)"),
        445 | 139 | 548 => tr!("Partage de fichiers", "File Sharing"),
        5900 => tr!("Partage d'écran", "Screen Sharing"),
        3283 => tr!("Gestion à distance", "Remote Management"),
        5000 | 7000 => tr!("Récepteur AirPlay", "AirPlay Receiver"),
        3689 => tr!("Partage de médias", "Media Sharing"),
        631 => tr!("Partage d'imprimantes", "Printer Sharing"),
        _ => return None,
    })
}

fn ports_ecoute(pare_feu_actif: bool) -> Vec<Constat> {
    let programmes = super::programmes_en_ecoute();
    let mut constats = Vec::new();
    let mut vus = Vec::new();
    for (proto, tcp) in [("tcp", true), ("udp", false)] {
        let Some(netstat) = sortie("netstat", &["-an", "-p", proto]) else {
            return vec![impossible(
                "Ports en écoute",
                tr!("netstat indisponible", "netstat unavailable"),
            )];
        };
        for (adresse, port) in lire_netstat(&netstat, tcp) {
            let local = adresse.starts_with("127.") || adresse == "::1" || adresse.starts_with("fe80:");
            let i = info_port(port);
            // UDP : Bonjour (5353) et le service de noms NetBIOS (137, 138, netbiosd) font partie de macOS ; ports
            // éphémères anonymes = sockets clientes.
            let bruit = !tcp
                && (matches!(port, 5353 | 137 | 138 | 68) || (port >= 49152 && i.service == crate::risk::inconnu()));
            if local || bruit || vus.contains(&(proto, port)) {
                continue;
            }
            vus.push((proto, port));
            let programme = programmes
                .get(&port)
                .map_or(tr!("programme du système", "system program"), String::as_str);
            let niveau = super::niveau_expose(pare_feu_actif, i.niveau);
            let constat = alerte(
                "Ports en écoute",
                niveau,
                trf!(
                    "{port}/{proto} ({}) ouvert sur le réseau par « {programme} ». {}",
                    "{port}/{proto} ({}) open to the network by “{programme}”. {}",
                    i.service,
                    i.conseil
                ),
            );
            constats.push(match partage(port) {
                Some(service) => constat.manuel(
                    trf!(
                        "Si tu ne t'en sers pas : Réglages Système > Général > Partage > désactiver « {service} »",
                        "If you do not use it: System Settings > General > Sharing > turn off “{service}”"
                    ),
                    &[],
                ),
                None => constat,
            });
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            "Ports en écoute",
            tr!(
                "Aucun service TCP ou UDP exposé au réseau (tout écoute en local).",
                "No TCP or UDP service exposed to the network (everything listens locally)."
            ),
        ));
    }
    constats
}

fn chiffrement_disque() -> Constat {
    let Some(etat) = sortie("fdesetup", &["status"]) else {
        return impossible("Chiffrement", tr!("fdesetup illisible", "fdesetup unreadable"));
    };
    if etat.contains("FileVault is On") || etat.contains("Encryption in progress") {
        ok(
            "Chiffrement",
            tr!("Disque chiffré (FileVault).", "Disk encrypted (FileVault)."),
        )
    } else {
        alerte(
            "Chiffrement",
            Niveau::Eleve,
            tr!(
                "FileVault est désactivé : un Mac perdu ou volé livre tous ses fichiers à qui le démarre sur un autre système.",
                "FileVault is off: a lost or stolen Mac hands over all its files to anyone who boots it on another system."
            ),
        )
        .manuel(
            tr!(
                "Réglages Système > Confidentialité et sécurité > FileVault > Activer (garder la clé de secours en lieu sûr)",
                "System Settings > Privacy & Security > FileVault > Turn On (keep the recovery key somewhere safe)"
            ),
            &[],
        )
    }
}

/// Gatekeeper (seuls les programmes signés et vérifiés par Apple s'ouvrent sans avertissement) et SIP (les
/// fichiers du système sont protégés, même contre l'administrateur).
fn protection_systeme() -> Vec<Constat> {
    let mut constats = Vec::new();
    match sortie("spctl", &["--status"]) {
        Some(s) if s.contains("enabled") => constats.push(ok(
            "Protection système",
            tr!("Gatekeeper actif.", "Gatekeeper on."),
        )),
        Some(_) => constats.push(
            alerte(
                "Protection système",
                Niveau::Eleve,
                tr!(
                    "Gatekeeper est désactivé : n'importe quel programme téléchargé s'ouvre sans la moindre vérification.",
                    "Gatekeeper is off: any downloaded program opens without any check."
                ),
            )
            .corriger(
                tr!("Réactiver Gatekeeper", "Turn Gatekeeper back on"),
                &["sudo spctl --global-enable 2>/dev/null || sudo spctl --master-enable"],
            ),
        ),
        None => constats.push(impossible("Protection système", tr!("spctl illisible", "spctl unreadable"))),
    }
    match sortie("csrutil", &["status"]) {
        Some(s) if s.contains("status: enabled") => constats.push(ok(
            "Protection système",
            tr!(
                "Protection de l'intégrité du système (SIP) active.",
                "System Integrity Protection (SIP) on."
            ),
        )),
        Some(_) => constats.push(
            alerte(
                "Protection système",
                Niveau::Eleve,
                tr!(
                    "La protection de l'intégrité du système (SIP) est désactivée ou réduite : un programme administrateur peut modifier macOS lui-même.",
                    "System Integrity Protection (SIP) is off or reduced: an administrator program can modify macOS itself."
                ),
            )
            .manuel(
                tr!(
                    "Redémarrer en mode de secours (bouton d'alimentation maintenu sur Apple Silicon, Cmd-R sur Intel), Utilitaires > Terminal : csrutil enable, puis redémarrer",
                    "Restart in Recovery (hold the power button on Apple Silicon, Cmd-R on Intel), Utilities > Terminal: csrutil enable, then restart"
                ),
                &[],
            ),
        ),
        None => constats.push(impossible("Protection système", tr!("csrutil illisible", "csrutil unreadable"))),
    }
    constats
}

/// Mot de passe à la sortie de veille.
#[derive(Debug, PartialEq)]
enum Verrouillage {
    Coupe,
    /// Délai avant que le mot de passe soit demandé, en secondes.
    Delai(u64),
}

/// « screenLock delay is immediate » / « screenLock delay is 300 seconds » / « screenLock is off » (sur la sortie
/// d'erreur).
fn lire_verrouillage(texte: &str) -> Option<Verrouillage> {
    if texte.contains("screenLock is off") {
        return Some(Verrouillage::Coupe);
    }
    let delai = texte.split_once("screenLock delay is ")?.1;
    if delai.starts_with("immediate") {
        return Some(Verrouillage::Delai(0));
    }
    delai.split_whitespace().next()?.parse().ok().map(Verrouillage::Delai)
}

fn verrouillage_ecran() -> Option<Constat> {
    let r = crate::commande::lancer(
        std::process::Command::new("sysadminctl").args(["-screenLock", "status"]),
        15,
    )?;
    let etat = lire_verrouillage(&format!("{}\n{}", r.sortie, r.erreurs))?;
    let reglage = tr!(
        "Réglages Système > Écran de verrouillage > « Exiger le mot de passe après le début de l'économiseur ou la suspension de l'écran » : immédiatement",
        "System Settings > Lock Screen > “Require password after screen saver begins or display is turned off”: immediately"
    );
    Some(match etat {
        Verrouillage::Coupe => alerte(
            "Verrouillage",
            Niveau::Moyen,
            tr!(
                "Aucun mot de passe n'est demandé à la sortie de veille : quiconque passe devant le Mac y a accès.",
                "No password is asked when waking up: anyone walking by the Mac gets in."
            ),
        )
        .manuel(reglage, &[]),
        Verrouillage::Delai(s) if s > 300 => alerte(
            "Verrouillage",
            Niveau::Info,
            trf!(
                "Le mot de passe n'est demandé que {} min après la mise en veille de l'écran.",
                "The password is only asked {} min after the display sleeps.",
                s / 60
            ),
        )
        .manuel(reglage, &[]),
        Verrouillage::Delai(_) => ok(
            "Verrouillage",
            tr!(
                "Mot de passe demandé à la sortie de veille.",
                "Password asked when waking up."
            ),
        ),
    })
}

/// Session ouverte automatiquement au démarrage, et compte invité.
fn ouverture_de_session() -> Vec<Constat> {
    let mut constats = Vec::new();
    if let Some(compte) = preference("/Library/Preferences/com.apple.loginwindow", "autoLoginUser") {
        constats.push(
            alerte(
                "Comptes",
                Niveau::Moyen,
                trf!(
                    "La session de « {compte} » s'ouvre toute seule au démarrage : un Mac volé s'allume directement sur tes fichiers (et FileVault ne peut pas protéger le disque).",
                    "“{compte}”'s session opens by itself at startup: a stolen Mac boots straight into your files (and FileVault cannot protect the disk)."
                ),
            )
            .corriger(
                tr!(
                    "Désactiver l'ouverture de session automatique",
                    "Turn off automatic login"
                ),
                &[
                    "sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser",
                    "sudo rm -f /etc/kcpassword",
                ],
            ),
        );
    }
    if preference("/Library/Preferences/com.apple.loginwindow", "GuestEnabled").as_deref() == Some("1") {
        constats.push(
            alerte(
                "Comptes",
                Niveau::Info,
                tr!(
                    "Le compte invité est activé : n'importe qui peut ouvrir une session sans mot de passe.",
                    "The guest account is on: anyone can log in without a password."
                ),
            )
            .corriger(
                tr!("Désactiver le compte invité", "Turn off the guest account"),
                &["sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"],
            ),
        );
    }
    constats
}

/// Comptes administrateurs (« GroupMembership: root alice »).
fn comptes() -> Constat {
    let Some(texte) = sortie("dscl", &[".", "-read", "/Groups/admin", "GroupMembership"]) else {
        return impossible("Comptes", tr!("dscl illisible", "dscl unreadable"));
    };
    // root et les comptes internes de macOS (« _mbsetupuser ») ne sont pas des personnes.
    let admins: Vec<&str> = texte
        .split_whitespace()
        .skip(1)
        .filter(|n| *n != "root" && !n.starts_with('_'))
        .collect();
    if admins.len() > 2 {
        alerte(
            "Comptes",
            Niveau::Info,
            trf!(
                "{} comptes administrateurs : {}. Chacun peut tout modifier ; vérifie qu'ils sont tous connus.",
                "{} administrator accounts: {}. Each can change everything; check they are all known.",
                admins.len(),
                admins.join(", ")
            ),
        )
    } else {
        ok(
            "Comptes",
            trf!("Administrateurs : {}.", "Administrators: {}.", admins.join(", ")),
        )
    }
}

/// Gestion à distance (MDM) : une organisation qui gère ce Mac peut y installer des programmes et des profils.
/// Normal sur un Mac de travail ; sur un Mac personnel, c'est à comprendre.
fn gestion_a_distance() -> Option<Constat> {
    let texte = sortie("profiles", &["status", "-type", "enrollment"])?;
    let inscrit = texte
        .lines()
        .any(|l| l.contains("MDM enrollment:") && l.contains("Yes"));
    Some(if inscrit {
        alerte(
            "Gestion à distance",
            Niveau::Moyen,
            tr!(
                "Ce Mac est géré à distance (MDM) : l'organisation peut y installer des programmes, des certificats et des réglages. Normal sur un Mac de travail, à vérifier sur un Mac personnel.",
                "This Mac is remotely managed (MDM): the organization can install programs, certificates and settings on it. Normal on a work Mac, worth checking on a personal Mac."
            ),
        )
        .manuel(
            tr!(
                "Voir qui le gère : Réglages Système > Général > Gestion des appareils",
                "See who manages it: System Settings > General > Device Management"
            ),
            &[],
        )
    } else {
        ok(
            "Gestion à distance",
            tr!(
                "Ce Mac n'est géré par aucune organisation (MDM).",
                "This Mac is not managed by any organization (MDM)."
            ),
        )
    })
}

/// Réglages des mises à jour automatiques. Une clé absente = réglage par défaut (activé).
fn mises_a_jour_automatiques() -> Constat {
    const DOMAINE: &str = "/Library/Preferences/com.apple.SoftwareUpdate";
    let coupe = |cle: &str| preference(DOMAINE, cle).as_deref() == Some("0");
    let mut coupes = Vec::new();
    let mut commandes = Vec::new();
    for (cle, nom) in [
        ("AutomaticCheckEnabled", tr!("recherche", "check")),
        (
            "CriticalUpdateInstall",
            tr!("réponses de sécurité", "security responses"),
        ),
        (
            "ConfigDataInstall",
            tr!("données de sécurité (XProtect)", "security data (XProtect)"),
        ),
    ] {
        if coupe(cle) {
            coupes.push(nom);
            commandes.push(format!("sudo defaults write {DOMAINE} {cle} -bool true"));
        }
    }
    if coupes.is_empty() {
        return ok(
            "Mises à jour",
            tr!(
                "Mises à jour de sécurité automatiques actives.",
                "Automatic security updates on."
            ),
        );
    }
    alerte(
        "Mises à jour",
        Niveau::Moyen,
        trf!(
            "Mises à jour automatiques coupées : {}. Les failles corrigées par Apple restent ouvertes sur ce Mac.",
            "Automatic updates turned off: {}. The flaws Apple fixes stay open on this Mac.",
            coupes.join(", ")
        ),
    )
    .corriger(
        tr!(
            "Réactiver les mises à jour de sécurité automatiques",
            "Turn automatic security updates back on"
        ),
        &commandes,
    )
}

/// Date de la dernière sauvegarde dans un chemin Time Machine (« …/2024-05-01-123456 »).
fn date_sauvegarde(chemin: &str) -> Option<chrono::NaiveDate> {
    let nom = chemin.trim().rsplit('/').next()?;
    chrono::NaiveDate::parse_from_str(nom.get(..10)?, "%Y-%m-%d").ok()
}

fn sauvegardes() -> Constat {
    let Some(destinations) = sortie("tmutil", &["destinationinfo"]) else {
        return impossible("Sauvegardes", tr!("tmutil illisible", "tmutil unreadable"));
    };
    if destinations.contains("No destinations configured") || !destinations.contains("Name") {
        return alerte(
            "Sauvegardes",
            Niveau::Moyen,
            tr!(
                "Aucune sauvegarde Time Machine configurée : un disque qui lâche, un vol ou un rançongiciel emportent tout.",
                "No Time Machine backup set up: a failing disk, a theft or ransomware takes everything."
            ),
        )
        .manuel(
            tr!(
                "Brancher un disque externe, puis Réglages Système > Général > Time Machine > Ajouter un disque de sauvegarde",
                "Plug in an external disk, then System Settings > General > Time Machine > Add Backup Disk"
            ),
            &[],
        );
    }
    // La date demande l'accès complet au disque ; sans lui, on sait seulement que Time Machine est réglé.
    match sortie("tmutil", &["latestbackup"]).as_deref().and_then(date_sauvegarde) {
        Some(date) => {
            let jours = (chrono::Local::now().date_naive() - date).num_days();
            if jours > 14 {
                alerte(
                    "Sauvegardes",
                    Niveau::Moyen,
                    trf!(
                        "Dernière sauvegarde Time Machine il y a {jours} jours : rebranche le disque de sauvegarde.",
                        "Last Time Machine backup {jours} days ago: plug the backup disk back in."
                    ),
                )
            } else {
                ok(
                    "Sauvegardes",
                    trf!(
                        "Time Machine : dernière sauvegarde il y a {jours} jour(s).",
                        "Time Machine: last backup {jours} day(s) ago."
                    ),
                )
            }
        }
        None => ok(
            "Sauvegardes",
            tr!("Time Machine est configuré.", "Time Machine is set up."),
        ),
    }
}

pub fn auditer() -> Audit {
    use super::verif;
    let feu = pare_feu();
    let feu_actif = feu.probleme.is_none();
    let mut constats = vec![feu];
    constats.extend(super::en_parallele(vec![
        verif!(mode_furtif()),
        verif!(ports_ecoute(feu_actif)),
        verif!([chiffrement_disque()]),
        verif!(protection_systeme()),
        verif!(verrouillage_ecran()),
        verif!(ouverture_de_session()),
        verif!([comptes()]),
        verif!(gestion_a_distance()),
        verif!([mises_a_jour_automatiques()]),
        verif!(maj::mises_a_jour()),
        verif!(maj::homebrew_a_jour()),
        verif!([sauvegardes()]),
        verif!(persistance()),
        verif!(cles_ssh()),
        verif!(super::dns::dns()),
        verif!(super::certificats::certificats()),
        verif!(super::extensions::extensions()),
        verif!(super::navigateur::navigateurs()),
        verif!(super::sante::sante()),
        verif!(super::journaux::journaux()),
        verif!([crate::integrite::constat()]),
    ]));
    Audit {
        systeme: NOM,
        score: score(&constats),
        constats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lecture_du_pare_feu() {
        assert_eq!(lire_pare_feu("Firewall is enabled. (State = 1)"), Some(true));
        assert_eq!(
            lire_pare_feu("Firewall is blocking all non-essential incoming connections. (State = 2)"),
            Some(true)
        );
        assert_eq!(lire_pare_feu("Firewall is disabled. (State = 0)"), Some(false));
        assert_eq!(lire_pare_feu(""), None);
    }

    #[test]
    fn lecture_de_netstat() {
        let tcp = "Active Internet connections (including servers)\n\
                   Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n\
                   tcp4       0      0  *.22                   *.*                    LISTEN\n\
                   tcp4       0      0  127.0.0.1.631          *.*                    LISTEN\n\
                   tcp6       0      0  *.5900                 *.*                    LISTEN\n\
                   tcp4       0      0  10.0.0.20.51234        17.57.146.20.443       ESTABLISHED\n";
        assert_eq!(
            lire_netstat(tcp, true),
            [("*".into(), 22), ("127.0.0.1".into(), 631), ("*".into(), 5900)]
        );
        let udp = "udp4       0      0  *.5353                 *.*\nudp6       0      0  ::1.123  *.*\n";
        assert_eq!(lire_netstat(udp, false), [("*".into(), 5353), ("::1".into(), 123)]);
    }

    #[test]
    fn lecture_du_verrouillage() {
        assert_eq!(
            lire_verrouillage("screenLock delay is immediate"),
            Some(Verrouillage::Delai(0))
        );
        assert_eq!(
            lire_verrouillage("2024-05-01 sysadminctl[1:2] screenLock delay is 300 seconds"),
            Some(Verrouillage::Delai(300))
        );
        assert_eq!(lire_verrouillage("screenLock is off"), Some(Verrouillage::Coupe));
        assert_eq!(lire_verrouillage("autre chose"), None);
    }

    #[test]
    fn date_time_machine() {
        assert_eq!(
            date_sauvegarde("/Volumes/Sauvegarde/Backups.backupdb/Mac/2024-05-01-123456\n"),
            chrono::NaiveDate::from_ymd_opt(2024, 5, 1)
        );
        assert_eq!(
            date_sauvegarde("2024-05-01-123456.backup"),
            chrono::NaiveDate::from_ymd_opt(2024, 5, 1)
        );
        assert_eq!(date_sauvegarde("Failed to mount backup destination"), None);
    }
}
