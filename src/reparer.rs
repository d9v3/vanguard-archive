//! Réparations courantes, pour chaque système : réseau, fichiers système, disque, place, mises à jour, heure.
//! Chaque réparation est montrée (pourquoi, durée, commandes) puis confirmée avant d'être lancée.

use crate::machine;
use crate::ui::*;

pub struct Reparation {
    pub titre: &'static str,
    pub pourquoi: String,
    pub duree: &'static str,
    pub commandes: Vec<String>,
    /// Réparation refusée dans ce contexte (ex. : elle couperait la connexion à distance en cours).
    pub bloquee: Option<&'static str>,
}

fn rep(titre: &'static str, pourquoi: impl Into<String>, duree: &'static str, commandes: &[&str]) -> Reparation {
    Reparation {
        titre,
        pourquoi: pourquoi.into(),
        duree,
        commandes: commandes.iter().map(std::string::ToString::to_string).collect(),
        bloquee: None,
    }
}

/// Connecté à cette machine à distance (SSH) : une réparation du réseau couperait la session.
#[cfg(unix)]
fn session_ssh() -> bool {
    std::env::var_os("SSH_CONNECTION").is_some()
}

#[cfg(target_os = "linux")]
fn present(cmd: &str) -> bool {
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .any(|d| std::path::Path::new(d).join(cmd).exists())
}

#[cfg(target_os = "linux")]
fn actif(service: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .status()
        .is_ok_and(|s| s.success())
}

/// Place libre sur le volume système, pour l'afficher dans « disque plein ».
#[cfg(unix)]
fn occupation_racine() -> String {
    std::process::Command::new("df")
        .args(["-h", "/"])
        .output()
        .ok()
        .and_then(|o| {
            let t = String::from_utf8_lossy(&o.stdout).into_owned();
            let c: Vec<String> = t.lines().nth(1)?.split_whitespace().map(str::to_string).collect();
            Some(format!("disque système plein à {} ({} libres)", c.get(4)?, c.get(3)?))
        })
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
pub fn liste() -> Vec<Reparation> {
    use crate::machine::linux::Paquets;
    let gestion = Paquets::detecter();
    // Sans systemd (conteneur, Alpine, Void…), les réparations qui passent par systemctl ou journalctl ne marchent pas.
    let systemd = std::path::Path::new("/run/systemd/system").is_dir();
    let mut l = Vec::new();

    // Réseau
    let mut reseau = if actif("NetworkManager") {
        vec!["sudo systemctl restart NetworkManager"]
    } else if actif("systemd-networkd") {
        vec!["sudo systemctl restart systemd-networkd"]
    } else {
        vec![]
    };
    if actif("systemd-resolved") {
        reseau.push("sudo resolvectl flush-caches");
    }
    if !reseau.is_empty() {
        let mut r = rep(
            "Internet ne marche plus",
            "Relance la gestion du réseau et vide le cache DNS (sites introuvables, Wi-Fi bloqué).",
            "quelques secondes",
            &reseau,
        );
        if session_ssh() {
            r.bloquee = Some("tu es connecté par SSH : relancer le réseau couperait ta connexion");
        }
        l.push(r);
    }

    // Paquets cassés
    match gestion {
        Some(Paquets::Pacman) => l.push(rep(
            "Mises à jour en erreur (pacman)",
            "Débloque pacman après un arrêt brutal, renouvelle les clés de signature (erreurs « invalid or corrupted package »), puis met à jour.",
            "quelques minutes",
            &[
                "pgrep -x pacman >/dev/null && echo 'pacman tourne déjà : attends la fin' && exit 1; sudo rm -f /var/lib/pacman/db.lck",
                "sudo pacman -Sy --needed --noconfirm archlinux-keyring",
                "sudo pacman -Syu",
            ],
        )),
        Some(Paquets::Apt) => l.push(rep(
            "Mises à jour en erreur (apt)",
            "Termine les installations interrompues et répare les dépendances cassées.",
            "quelques minutes",
            &["sudo dpkg --configure -a", "sudo apt-get -f install -y", "sudo apt-get update"],
        )),
        Some(Paquets::Dnf) => l.push(rep(
            "Mises à jour en erreur (dnf)",
            "Vérifie la base des paquets et réaligne les paquets sur les versions de la distribution.",
            "quelques minutes",
            &["sudo dnf check", "sudo dnf distro-sync -y"],
        )),
        Some(Paquets::Zypper) => l.push(rep(
            "Mises à jour en erreur (zypper)",
            "Vérifie et répare les dépendances des paquets installés.",
            "quelques minutes",
            &["sudo zypper verify"],
        )),
        None => {}
    }

    // Santé des disques
    let installer_smart = gestion.map(|g| g.installer("smartmontools")).unwrap_or_default();
    let mut disque = vec![];
    if !present("smartctl") && !installer_smart.is_empty() {
        disque.push(installer_smart.as_str());
    }
    disque.push(
        // zram (mémoire compressée) et loop ne sont pas des disques physiques : pas de SMART.
        "for d in $(lsblk -dno NAME,TYPE | awk '$2==\"disk\" && $1 !~ /^(zram|loop)/{print $1}'); do echo \"== /dev/$d\"; sudo smartctl -H /dev/$d | tail -n +4; done",
    );
    let btrfs = std::process::Command::new("findmnt")
        .args(["-no", "FSTYPE", "/"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "btrfs");
    if btrfs {
        disque.push("sudo btrfs scrub start -B /");
    }
    l.push(rep(
        "Disque : santé et erreurs",
        if btrfs {
            "Lit l'état SMART de chaque disque (usure, secteurs défectueux) et vérifie toutes les données du système (btrfs scrub)."
        } else {
            "Lit l'état SMART de chaque disque (usure, secteurs défectueux). Pour réparer un ext4, démarre sur la clé (SystemRescue)."
        },
        if btrfs { "de quelques minutes à une heure" } else { "quelques secondes" },
        &disque,
    ));

    // Place
    let mut menage: Vec<&str> = match gestion {
        Some(Paquets::Pacman) if present("paccache") => vec!["sudo paccache -rk2", "sudo paccache -ruk0"],
        Some(Paquets::Pacman) => vec!["sudo pacman -Sc --noconfirm"],
        Some(Paquets::Apt) => vec!["sudo apt-get autoremove -y", "sudo apt-get clean"],
        Some(Paquets::Dnf) => vec!["sudo dnf autoremove -y", "sudo dnf clean all"],
        Some(Paquets::Zypper) => vec!["sudo zypper clean --all"],
        None => vec![],
    };
    if systemd {
        menage.push("sudo journalctl --vacuum-time=2weeks");
    }
    menage.push("rm -rf ~/.cache/thumbnails");
    if present("flatpak") {
        menage.push("flatpak uninstall --unused -y");
    }
    menage.push("df -h /");
    l.push(rep(
        "Disque plein",
        format!(
            "Vide les anciens paquets téléchargés, les vieux journaux et les miniatures ; {}.",
            occupation_racine()
        ),
        "une minute",
        &menage,
    ));

    if !systemd {
        return l;
    }
    // Services
    l.push(rep(
        "Services en échec",
        "Montre les services qui ont planté, avec leurs dernières erreurs, puis remet leur compteur à zéro.",
        "quelques secondes",
        &[
            "systemctl --failed --no-pager",
            "for s in $(systemctl --failed --no-legend --plain | awk '{print $1}'); do echo \"== $s\"; journalctl -u $s -n 5 --no-pager; done",
            "sudo systemctl reset-failed",
        ],
    ));

    // Heure
    l.push(rep(
        "Heure fausse",
        "Réactive la synchronisation de l'heure (une heure fausse casse le HTTPS et les mises à jour).",
        "quelques secondes",
        &[
            "sudo timedatectl set-ntp true",
            "timedatectl status | grep -E 'synchronized|NTP'",
        ],
    ));
    l
}

#[cfg(windows)]
pub fn liste() -> Vec<Reparation> {
    let a_distance = machine::windows::session_a_distance();
    let mut reseau = rep(
        "Internet ne marche plus",
        "Remet à zéro Winsock et la pile TCP/IP, vide le cache DNS, redemande une adresse. Un redémarrage termine la réparation.",
        "une minute, puis redémarrer",
        &[
            "netsh winsock reset",
            "netsh int ip reset",
            "ipconfig /flushdns",
            "ipconfig /release",
            "ipconfig /renew",
        ],
    );
    if a_distance {
        reseau.bloquee = Some("tu es connecté par le Bureau à distance : cette réparation couperait ta connexion");
    }
    vec![
        rep(
            "Fichiers système abîmés",
            "Répare l'image de Windows (DISM) puis vérifie et remplace les fichiers système corrompus (SFC). À faire après un plantage ou un écran bleu.",
            "15 à 45 minutes",
            &["DISM /Online /Cleanup-Image /RestoreHealth", "sfc /scannow"],
        ),
        rep(
            "Disque : erreurs",
            "Analyse le disque C: sans le bloquer. Si des erreurs sont trouvées, la réparation se fait au redémarrage : chkdsk C: /f (C: ne peut pas être mis hors ligne pendant que Windows tourne).",
            "quelques minutes",
            &["Repair-Volume -DriveLetter C -Scan"],
        ),
        reseau,
        rep(
            "Windows Update bloqué",
            "Arrête les services de mise à jour, met de côté leurs caches (SoftwareDistribution, catroot2) et les relance.",
            "une minute",
            &[
                "Stop-Service -Force wuauserv, bits, cryptsvc",
                "Rename-Item \"$env:SystemRoot\\SoftwareDistribution\" \"SoftwareDistribution.$(Get-Date -Format yyyyMMddHHmm)\"",
                "Rename-Item \"$env:SystemRoot\\System32\\catroot2\" \"catroot2.$(Get-Date -Format yyyyMMddHHmm)\"",
                "Start-Service wuauserv, bits, cryptsvc",
            ],
        ),
        rep(
            "Disque plein",
            "Vide les fichiers temporaires et nettoie les anciennes versions des composants de Windows.",
            "quelques minutes",
            &[
                "Get-ChildItem $env:TEMP -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue",
                "Dism /Online /Cleanup-Image /StartComponentCleanup",
                "Get-PSDrive C | Format-Table Used, Free",
            ],
        ),
        rep(
            "Heure fausse",
            "Resynchronise l'horloge (une heure fausse casse le HTTPS et Windows Update).",
            "quelques secondes",
            &["Start-Service w32time", "w32tm /resync /force"],
        ),
    ]
}

#[cfg(target_os = "macos")]
pub fn liste() -> Vec<Reparation> {
    let mut reseau = rep(
        "Internet ne marche plus",
        "Vide le cache DNS et redemande une adresse au routeur (Wi-Fi en0).",
        "quelques secondes",
        &[
            "sudo dscacheutil -flushcache",
            "sudo killall -HUP mDNSResponder",
            "sudo ipconfig set en0 DHCP",
        ],
    );
    if session_ssh() {
        reseau.bloquee = Some("tu es connecté par SSH : cette réparation couperait ta connexion");
    }
    vec![
        rep(
            "Disque : vérification",
            "Vérifie le volume système (comme S.O.S. dans Utilitaire de disque). Pour réparer, démarrer en mode récupération.",
            "quelques minutes",
            &["diskutil verifyVolume /"],
        ),
        reseau,
        rep(
            "Recherche Spotlight cassée",
            "Reconstruit l'index Spotlight (recherche qui ne trouve plus rien).",
            "l'index se refait en arrière-plan",
            &["sudo mdutil -E /"],
        ),
        rep(
            "Disque plein",
            format!(
                "Montre ce qui prend de la place dans ton dossier ; {}.",
                occupation_racine()
            ),
            "une minute",
            &["du -hd1 ~ 2>/dev/null | sort -hr | head -15"],
        ),
        rep(
            "Heure fausse",
            "Resynchronise l'horloge sur les serveurs d'Apple.",
            "quelques secondes",
            &["sudo sntp -sS time.apple.com"],
        ),
    ]
}

/// Menu des réparations : choisir, lire, confirmer.
pub fn menu() {
    let reparations = liste();
    titre("Réparer");
    for (i, r) in reparations.iter().enumerate() {
        let note = if r.bloquee.is_some() {
            format!("  {GRIS}(indisponible ici){RESET}")
        } else {
            String::new()
        };
        println!("  {}. {}{note}", i + 1, r.titre);
    }
    let choix = demander("\nNuméro de la réparation (Entrée pour revenir) : ");
    let Some(r) = choix
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|n| reparations.get(n))
    else {
        return;
    };
    println!("\n  {GRAS}{}{RESET}", r.titre);
    println!("  {}", r.pourquoi);
    println!("  {GRIS}Durée : {}{RESET}", r.duree);
    if let Some(raison) = r.bloquee {
        println!("\n  ✖ Pas maintenant : {raison}. Fais-la depuis l'écran de l'ordinateur.");
        return;
    }
    println!("  Commandes :");
    for c in &r.commandes {
        println!("    {GRIS}{c}{RESET}");
    }
    if !demander("\n  Lancer cette réparation ? [o/N] : ").eq_ignore_ascii_case("o") {
        println!("  Annulé.");
        return;
    }
    if machine::appliquer(&r.commandes) {
        println!("  {VERT}✔ Réparation terminée.{RESET}");
    } else {
        println!("  ✖ Une étape a échoué : lis le message ci-dessus.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaque_reparation_est_complete() {
        let l = liste();
        assert!(l.len() >= 4);
        for r in &l {
            assert!(!r.titre.is_empty() && !r.pourquoi.is_empty() && !r.duree.is_empty());
            assert!(!r.commandes.is_empty(), "{} n'a pas de commande", r.titre);
        }
    }
}
