//! Réparations courantes, pour chaque système : réseau, navigation détournée, pare-feu, antivirus, fichiers
//! système, disque, place, mises à jour, heure.
//! Chaque réparation est montrée (pourquoi, durée, commandes) puis confirmée avant d'être lancée ; celles qui
//! modifient le système proposent d'abord un point de restauration.

#[cfg(windows)]
use std::fmt::Write;
use std::net::IpAddr;

use crate::machine;
#[cfg(windows)]
use crate::trw;
use crate::ui::*;

pub struct Reparation {
    pub titre: &'static str,
    pub pourquoi: String,
    pub duree: &'static str,
    pub commandes: Vec<String>,
    /// Réparation refusée dans ce contexte (ex. : elle couperait la connexion à distance en cours).
    pub bloquee: Option<&'static str>,
    /// Rien à réparer : la vérification faite en ouvrant le menu n'a rien trouvé.
    pub inutile: Option<String>,
    /// Modifie le système : on propose un point de restauration avant (snapper, timeshift, Windows).
    pub restauration: bool,
}

fn rep(titre: &'static str, pourquoi: impl Into<String>, duree: &'static str, commandes: &[&str]) -> Reparation {
    Reparation {
        titre,
        pourquoi: pourquoi.into(),
        duree,
        commandes: commandes.iter().map(std::string::ToString::to_string).collect(),
        bloquee: None,
        inutile: None,
        restauration: false,
    }
}

impl Reparation {
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    fn avec_restauration(mut self) -> Self {
        self.restauration = true;
        self
    }
}

/// Une adresse vers laquelle le fichier hosts ne devrait jamais envoyer un nom : ni bouclage ni « 0.0.0.0 »
/// (listes de blocage), ni réseau local (NAS, imprimante nommés à la main). Il reste les adresses d'Internet.
fn publique(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, ..] = v.octets();
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_private()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_multicast()
                || v.is_documentation()
                // 100.64.0.0/10 : réseau partagé des opérateurs (CGNAT), Tailscale.
                || (a == 100 && b & 0xc0 == 64))
        }
        IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(v4) => publique(IpAddr::V4(v4)),
            // fc00::/7 = réseau local ; fe00:: et au-delà = lien local, réservées, multicast (« fe00::0 ip6-localnet »).
            None => {
                !(v.is_loopback()
                    || v.is_unspecified()
                    || v.segments()[0] & 0xfe00 == 0xfc00
                    || v.segments()[0] >= 0xfe00)
            }
        },
    }
}

/// Lignes du fichier hosts qui envoient un nom vers une adresse d'Internet (adresse telle qu'écrite, noms).
/// Un malware s'en sert pour détourner une banque, un antivirus ou les mises à jour vers son serveur.
fn redirections(hosts: &str) -> Vec<(String, String)> {
    hosts
        .lines()
        .filter_map(|l| {
            let mut mots = l.split('#').next()?.split_whitespace();
            let ip = mots.next()?;
            let noms = mots.collect::<Vec<_>>().join(" ");
            (!noms.is_empty() && ip.parse().is_ok_and(publique)).then(|| (ip.to_string(), noms))
        })
        .collect()
}

/// Les adresses détournées, en expression régulière (« 1\.2\.3\.4|5\.6\.7\.8 »), pour sed et PowerShell.
fn motif_adresses(lignes: &[(String, String)]) -> String {
    let mut ips: Vec<String> = lignes.iter().map(|(ip, _)| ip.replace('.', r"\.")).collect();
    ips.sort();
    ips.dedup();
    ips.join("|")
}

/// Résumé lisible : « 1.2.3.4 → banque.fr, 5.6.7.8 → update.microsoft.com (et 3 autre(s)) ».
fn resume_redirections(lignes: &[(String, String)]) -> String {
    let textes: Vec<String> = lignes.iter().map(|(ip, noms)| format!("{ip} → {noms}")).collect();
    resume(&textes, 3, ", ")
}

/// Texte entre apostrophes pour bash ('…') ou PowerShell ('…').
#[cfg(unix)]
fn entre_apostrophes(t: &str) -> String {
    format!("'{}'", t.replace('\'', r"'\''"))
}
#[cfg(windows)]
fn entre_apostrophes(t: &str) -> String {
    format!("'{}'", t.replace('\'', "''"))
}

/// Outil et commande du point de restauration, s'il y en a un de configuré.
#[cfg(target_os = "linux")]
pub(crate) fn point_restauration(titre: &str) -> Option<(&'static str, String)> {
    let description = entre_apostrophes(&trf!("sentinel : avant « {titre} »", "sentinel: before “{titre}”"));
    if present("snapper") && std::path::Path::new("/etc/snapper/configs/root").is_file() {
        Some((
            "snapper",
            format!("sudo snapper --config root create --cleanup-algorithm number --description {description}"),
        ))
    } else if present("timeshift") && std::path::Path::new("/etc/timeshift/timeshift.json").is_file() {
        Some((
            "timeshift",
            format!("sudo timeshift --create --scripted --comments {description}"),
        ))
    } else {
        None
    }
}

/// Windows : la commande va dans la même fenêtre administrateur que la réparation (une seule demande).
/// Protection du système coupée sur C: : on le dit et on demande s'il faut continuer sans.
/// Windows ne crée qu'un point par 24 h : il l'écrit alors en avertissement, le plus récent sert.
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // même signature que sur Linux, où l'outil peut manquer
pub(crate) fn point_restauration(titre: &str) -> Option<(&'static str, String)> {
    let description = entre_apostrophes(&trf!("sentinel : avant « {titre} »", "sentinel: before “{titre}”"));
    Some((
        "Windows",
        trf!(
            "try {{ Checkpoint-Computer -Description {description} -RestorePointType MODIFY_SETTINGS }} \
             catch {{ Write-Host 'Point de restauration impossible (protection du système désactivée sur C: ?).' -ForegroundColor Red; \
             if ((Read-Host 'Continuer sans point de restauration ? [o/N]') -notin 'o', 'y') {{ exit 1 }} }}",
            "try {{ Checkpoint-Computer -Description {description} -RestorePointType MODIFY_SETTINGS }} \
             catch {{ Write-Host 'Restore point not possible (system protection turned off on C:?).' -ForegroundColor Red; \
             if ((Read-Host 'Continue without a restore point? [y/N]') -notin 'y', 'o') {{ exit 1 }} }}"
        ),
    ))
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
    // Sans bus système (conteneur, espace de noms), systemctl écrit son erreur au milieu du menu : on la tait.
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Place libre sur le volume système, pour l'afficher dans « disque plein ».
/// Taille d'un dossier, en octets ; `age` : seulement les fichiers non lus depuis ce nombre de jours. Arrêt à
/// l'échéance (un cache de plusieurs millions de fichiers) : le total est alors un minimum.
#[cfg(target_os = "linux")]
fn taille_dossier(dossier: &std::path::Path, age: Option<u64>, echeance: std::time::Instant) -> u64 {
    let limite = age.map(|j| std::time::SystemTime::now() - std::time::Duration::from_secs(j * 86_400));
    let mut total = 0;
    let mut a_voir = vec![dossier.to_path_buf()];
    while let Some(d) = a_voir.pop() {
        if std::time::Instant::now() > echeance {
            break;
        }
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                a_voir.push(e.path());
            } else if limite.is_none_or(|l| m.accessed().or_else(|_| m.modified()).is_ok_and(|a| a < l)) {
                total += m.len();
            }
        }
    }
    total
}

/// La date de dernière lecture est-elle tenue à jour là où se trouve `dossier` ? Monté en `noatime`, elle ne bouge
/// plus : « non lu depuis 90 jours » ne voudrait rien dire, et des fichiers lus chaque jour seraient effacés.
#[cfg(target_os = "linux")]
fn lectures_datees(dossier: &std::path::Path) -> bool {
    crate::commande::lancer(
        std::process::Command::new("findmnt")
            .args(["-no", "OPTIONS", "--target"])
            .arg(dossier),
        5,
    )
    .is_none_or(|r| !r.sortie.trim().split(',').any(|o| o == "noatime"))
}

#[cfg(target_os = "linux")]
fn en_go(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let go = octets as f64 / f64::from(1u32 << 30);
    trf!("{go:.1} Go", "{go:.1} GB")
}

/// Nettoyage plus poussé que « Disque plein » : corbeille, paquets devenus inutiles, caches de compilation AUR,
/// fichiers de cache non lus depuis 90 jours, rapports de plantage de plus d'une semaine.
#[cfg(target_os = "linux")]
fn nettoyage(gestion: Option<machine::linux::Paquets>) -> Reparation {
    use crate::machine::linux::Paquets;
    let maison = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let echeance = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let corbeille = maison.join(".local/share/Trash");
    let mut commandes: Vec<&str> = Vec::new();
    let mut details = Vec::new();
    let mut total = 0;
    let t = taille_dossier(&corbeille, None, echeance);
    if t > 0 {
        commandes.push("rm -rf ~/.local/share/Trash/files ~/.local/share/Trash/info ~/.local/share/Trash/expunged");
        details.push(trf!("corbeille {}", "trash {}", en_go(t)));
        total += t;
    }
    match gestion {
        Some(Paquets::Pacman) => commandes.push(tr!(
            "orphelins=$(pacman -Qdtq); if [ -n \"$orphelins\" ]; then sudo pacman -Rns $orphelins; else echo 'Aucun paquet orphelin.'; fi",
            "orphelins=$(pacman -Qdtq); if [ -n \"$orphelins\" ]; then sudo pacman -Rns $orphelins; else echo 'No orphan package.'; fi"
        )),
        Some(Paquets::Apt) => commandes.push("sudo apt-get autoremove --purge"),
        // Image en lecture seule (rpm-ostree) : rien à retirer à la main.
        Some(Paquets::Dnf) if crate::machine::linux::atomique().is_some() => {}
        Some(Paquets::Dnf) => commandes.push("sudo dnf autoremove"),
        Some(Paquets::Zypper) => commandes.push("zypper packages --unneeded"),
        None => {}
    }
    for (assistant, sous_dossier) in [("yay", ".cache/yay"), ("paru", ".cache/paru/clone")] {
        let t = taille_dossier(&maison.join(sous_dossier), None, echeance);
        if t >= 50 << 20 {
            commandes.push(if assistant == "yay" {
                "rm -rf ~/.cache/yay/*"
            } else {
                "rm -rf ~/.cache/paru/clone/*"
            });
            details.push(trf!("compilations {assistant} {}", "{assistant} builds {}", en_go(t)));
            total += t;
        }
    }
    let cache = maison.join(".cache");
    let t = if lectures_datees(&cache) {
        taille_dossier(&cache, Some(90), echeance)
    } else {
        0
    };
    if t >= 50 << 20 {
        commandes.push("find ~/.cache -mindepth 1 -type f -atime +90 -delete 2>/dev/null; find ~/.cache -mindepth 1 -type d -empty -delete 2>/dev/null");
        details.push(trf!("vieux fichiers de cache {}", "old cache files {}", en_go(t)));
        total += t;
    }
    let plantages = std::path::Path::new("/var/lib/systemd/coredump");
    if plantages.is_dir() {
        commandes.push("sudo find /var/lib/systemd/coredump -type f -mtime +7 -delete");
    }
    commandes.push("df -h /");
    let mut r = rep(
        tr!("Nettoyage approfondi", "Deep cleanup"),
        trf!(
            "Vide la corbeille, retire les paquets devenus inutiles (la liste s'affiche avant), les compilations AUR gardées, les fichiers de cache non lus depuis 90 jours et les rapports de plantage de plus d'une semaine. À gagner : {}.",
            "Empties the trash, removes packages no longer needed (the list is shown first), kept AUR builds, cache files unread for 90 days and crash reports older than a week. To gain: {}.",
            if details.is_empty() {
                tr!("peu de place", "little space").to_string()
            } else {
                details.join(", ")
            }
        ),
        tr!("une minute", "one minute"),
        &commandes,
    );
    if total < 100 << 20 && details.is_empty() {
        r.inutile = Some(tr!("presque rien à libérer", "almost nothing to free").into());
    }
    r
}

#[cfg(unix)]
fn occupation_racine() -> String {
    std::process::Command::new("df")
        .args(["-h", "/"])
        .output()
        .ok()
        .and_then(|o| {
            let t = String::from_utf8_lossy(&o.stdout).into_owned();
            let c: Vec<String> = t.lines().nth(1)?.split_whitespace().map(str::to_string).collect();
            Some(trf!(
                "disque système plein à {} ({} libres)",
                "system disk {} full ({} free)",
                c.get(4)?,
                c.get(3)?
            ))
        })
        .unwrap_or_default()
}

/// Proxy imposé et redirections du fichier hosts : les deux façons classiques de détourner la navigation.
#[cfg(target_os = "linux")]
fn navigation() -> Reparation {
    let detournees = redirections(&std::fs::read_to_string("/etc/hosts").unwrap_or_default());
    let variables: Vec<String> = ["http_proxy", "https_proxy", "all_proxy", "ftp_proxy"]
        .iter()
        .filter_map(|v| {
            let valeur = std::env::var(v).or_else(|_| std::env::var(v.to_uppercase())).ok()?;
            (!valeur.is_empty()).then(|| format!("{v}={valeur}"))
        })
        .collect();
    let gnome = present("gsettings")
        .then(|| {
            crate::commande::lancer(
                std::process::Command::new("gsettings").args(["get", "org.gnome.system.proxy", "mode"]),
                5,
            )
        })
        .flatten()
        .map(|r| r.sortie.trim().trim_matches('\'').to_string())
        .filter(|m| m == "manual" || m == "auto");

    let mut constats = Vec::new();
    let mut commandes = Vec::new();
    if !detournees.is_empty() {
        constats.push(trf!(
            "fichier hosts : {}",
            "hosts file: {}",
            resume_redirections(&detournees)
        ));
        commandes.push("sudo cp -p /etc/hosts /etc/hosts.sentinel-$(date +%Y%m%d-%H%M%S)".to_string());
        commandes.push(format!(
            "sudo sed -i -E 's/^([[:space:]]*({})[[:space:]])/# sentinel : \\1/' /etc/hosts",
            motif_adresses(&detournees)
        ));
    }
    if let Some(mode) = &gnome {
        constats.push(trf!(
            "proxy du bureau en mode « {mode} »",
            "desktop proxy in “{mode}” mode"
        ));
        commandes.push("gsettings set org.gnome.system.proxy mode 'none'".to_string());
    }
    if !variables.is_empty() {
        // Définies dans un fichier de démarrage : on montre où, c'est à retirer à la main (peut être voulu).
        constats.push(trf!(
            "variables {} (à retirer à la main du fichier montré)",
            "{} variables (to remove by hand from the file shown)",
            variables.join(", ")
        ));
        commandes.push(
            "grep -nsE '^[^#]*(https?|all|ftp)_proxy=' /etc/environment /etc/profile /etc/profile.d/* ~/.profile ~/.bashrc ~/.bash_profile ~/.zshrc ~/.config/environment.d/*; true"
                .to_string(),
        );
    }
    let mut r = rep(
        tr!(
            "Navigation détournée (proxy, fichier hosts)",
            "Hijacked browsing (proxy, hosts file)"
        ),
        trf!(
            "Met en commentaire les lignes du fichier hosts qui envoient un site vers une adresse d'Internet (une copie est gardée) et coupe le proxy imposé. Les listes de blocage (0.0.0.0) et les appareils du réseau local ne sont pas touchés. Trouvé : {}.",
            "Comments out the hosts file lines that send a site to an Internet address (a copy is kept) and turns off the forced proxy. Block lists (0.0.0.0) and local network devices are left alone. Found: {}.",
            constats.join(" ; ")
        ),
        tr!("quelques secondes", "a few seconds"),
        &[],
    );
    r.restauration = !detournees.is_empty();
    if commandes.is_empty() {
        r.inutile = Some(
            tr!(
                "ni redirection dans le fichier hosts, ni proxy imposé",
                "no redirection in the hosts file, no forced proxy"
            )
            .into(),
        );
    }
    r.commandes = commandes;
    r
}

/// Signatures ClamAV : téléchargement immédiat, puis mise à jour automatique.
#[cfg(target_os = "linux")]
fn antivirus(systemd: bool) -> Reparation {
    let mut r = rep(
        tr!("Antivirus pas à jour", "Antivirus out of date"),
        "",
        tr!("une minute", "one minute"),
        &[],
    );
    if !present("clamscan") {
        r.inutile = Some(
            tr!(
                "ClamAV n'est pas installé : l'analyse antivirus (choix 6 ou 7) propose de l'installer",
                "ClamAV is not installed: the antivirus scan (choice 6 or 7) offers to install it"
            )
            .into(),
        );
        return r;
    }
    let derniere = ["daily.cld", "daily.cvd"]
        .iter()
        .filter_map(|f| {
            std::fs::metadata(std::path::Path::new("/var/lib/clamav").join(f))
                .ok()?
                .modified()
                .ok()
        })
        .max()
        .and_then(|m| m.elapsed().ok())
        .map_or(tr!("jamais", "never").to_string(), |d| match d.as_secs() / 86_400 {
            0 => tr!("aujourd'hui", "today").to_string(),
            1 => tr!("hier", "yesterday").to_string(),
            n => trf!("il y a {n} jours", "{n} days ago"),
        });
    r.pourquoi = trf!(
        "Télécharge les dernières signatures de virus de ClamAV et active leur mise à jour automatique. Dernière mise à jour : {derniere}.",
        "Downloads the latest ClamAV virus signatures and turns on their automatic update. Last update: {derniere}."
    );
    if systemd {
        // Le service, s'il tourne, verrouille la base : on l'arrête le temps du téléchargement.
        r.commandes = vec![
            "sudo systemctl stop clamav-freshclam.service 2>/dev/null; sudo freshclam".into(),
            "if systemctl cat clamav-freshclam.service >/dev/null 2>&1; then sudo systemctl enable --now clamav-freshclam.service; fi".into(),
        ];
    } else {
        r.commandes = vec!["sudo freshclam".into()];
    }
    r
}

/// Pare-feu coupé ou qui laisse tout entrer : on garde celui qui est en place (firewalld), sinon ufw.
#[cfg(target_os = "linux")]
fn pare_feu(gestion: Option<machine::linux::Paquets>) -> Reparation {
    use crate::machine::linux::{politique_ufw, service_actif, ufw_actif};
    let mut r = rep(
        tr!("Pare-feu coupé ou ouvert", "Firewall off or open"),
        "",
        tr!("quelques secondes", "a few seconds"),
        &[],
    );
    if service_actif("firewalld") {
        let zone = crate::commande::lancer(std::process::Command::new("firewall-cmd").arg("--get-default-zone"), 10)
            .map(|z| z.sortie.trim().to_string());
        if zone.as_deref() == Some("trusted") {
            r.pourquoi = tr!("firewalld est actif mais en zone « trusted » : il laisse tout entrer. Passe la zone par défaut en « public ».", "firewalld is running but in the “trusted” zone: it lets everything in. Sets the default zone to “public”.").into();
            r.commandes = vec!["sudo firewall-cmd --set-default-zone=public".into()];
        } else {
            r.inutile = Some(tr!("firewalld est actif", "firewalld is running").into());
        }
        return r;
    }
    let politique = std::fs::read_to_string("/etc/default/ufw")
        .ok()
        .and_then(|t| politique_ufw(&t));
    if ufw_actif() && politique.as_deref() != Some("ACCEPT") {
        r.inutile = Some(
            tr!(
                "ufw est actif et refuse les connexions entrantes",
                "ufw is running and refuses incoming connections"
            )
            .into(),
        );
        return r;
    }
    if !present("ufw") {
        if let Some(autre) = ["nftables", "iptables"].into_iter().find(|s| service_actif(s)) {
            r.inutile = Some(trf!(
                "{autre} est actif : ses règles se gèrent à la main",
                "{autre} is running: its rules are managed by hand"
            ));
            return r;
        }
        let Some(g) = gestion else {
            r.inutile = Some(
                tr!(
                    "aucun pare-feu, et gestionnaire de paquets non reconnu : installe ufw avec ta distribution",
                    "no firewall, and package manager not recognized: install ufw with your distribution"
                )
                .into(),
            );
            return r;
        };
        r.commandes.push(g.installer("ufw"));
    }
    r.pourquoi = tr!("Active ufw et refuse par défaut les connexions entrantes (les sorties restent permises). Un service qui doit rester joignable depuis le réseau (partage, KDE Connect…) sera à autoriser : sudo ufw allow <port>.", "Turns ufw on and refuses incoming connections by default (outgoing stays allowed). A service that must stay reachable from the network (sharing, KDE Connect…) will need to be allowed: sudo ufw allow <port>.").into();
    r.commandes.extend(
        [
            "sudo ufw default deny incoming",
            "sudo ufw default allow outgoing",
            "sudo systemctl enable --now ufw",
            "sudo ufw --force enable",
            "sudo ufw status verbose",
        ]
        .map(String::from),
    );
    if session_ssh() {
        r.bloquee = Some(tr!(
            "tu es connecté par SSH : refuser les connexions entrantes couperait ta connexion",
            "you are connected over SSH: refusing incoming connections would cut your connection"
        ));
    }
    r
}

#[cfg(target_os = "linux")]
pub fn liste() -> Vec<Reparation> {
    use crate::machine::linux::{Atomique, Paquets, atomique};
    let gestion = Paquets::detecter();
    let atomique = atomique();
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
            tr!("Internet ne marche plus", "Internet no longer works"),
            tr!(
                "Relance la gestion du réseau et vide le cache DNS (sites introuvables, Wi-Fi bloqué).",
                "Restarts network management and clears the DNS cache (sites not found, Wi-Fi stuck)."
            ),
            tr!("quelques secondes", "a few seconds"),
            &reseau,
        );
        if session_ssh() {
            r.bloquee = Some(tr!(
                "tu es connecté par SSH : relancer le réseau couperait ta connexion",
                "you are connected over SSH: restarting the network would cut your connection"
            ));
        }
        l.push(r);
    }
    l.push(navigation());
    l.push(antivirus(systemd));

    // Paquets cassés
    match gestion {
        // Système atomique : on ne répare pas l'image en place, on annule une opération restée bloquée puis on
        // repart d'une image propre (l'ancienne reste au menu de démarrage).
        Some(Paquets::Dnf) if atomique == Some(Atomique::RpmOstree) => l.push(rep(
            tr!("Mises à jour en erreur (rpm-ostree)", "Updates failing (rpm-ostree)"),
            tr!("Annule une opération restée bloquée, vide le cache, puis prépare l'image suivante. L'image actuelle reste au menu de démarrage en cas de problème.", "Cancels a stuck operation, clears the cache, then prepares the next image. The current image stays in the boot menu in case of trouble."),
            tr!("quelques minutes", "a few minutes"),
            &["sudo rpm-ostree cancel", "sudo rpm-ostree cleanup -m", "sudo rpm-ostree upgrade"],
        )),
        Some(Paquets::Zypper) if atomique == Some(Atomique::Transactionnel) => l.push(rep(
            tr!("Mises à jour en erreur (transactional-update)", "Updates failing (transactional-update)"),
            tr!("Prépare un nouvel instantané à jour, dépendances réparées. L'actuel reste au menu de démarrage en cas de problème.", "Prepares a new up-to-date snapshot with dependencies repaired. The current one stays in the boot menu in case of trouble."),
            tr!("quelques minutes", "a few minutes"),
            &["sudo transactional-update --non-interactive dup"],
        )),
        Some(Paquets::Pacman) => l.push(rep(
            tr!("Mises à jour en erreur (pacman)", "Updates failing (pacman)"),
            tr!("Débloque pacman après un arrêt brutal, renouvelle les clés de signature (erreurs « invalid or corrupted package »), puis met à jour.", "Unlocks pacman after a crash, renews the signing keys (“invalid or corrupted package” errors), then updates."),
            tr!("quelques minutes", "a few minutes"),
            &[
                // pamac (Manjaro) et PackageKit (Discover) travaillent sur la même base sans lancer pacman : effacer
                // leur verrou en pleine opération l'abîmerait.
                tr!("pgrep -x 'pacman|pamac-daemon|packagekitd' >/dev/null && echo 'un gestionnaire de paquets tourne déjà (pacman, pamac ou PackageKit) : attends la fin' && exit 1; sudo rm -f /var/lib/pacman/db.lck", "pgrep -x 'pacman|pamac-daemon|packagekitd' >/dev/null && echo 'a package manager is already running (pacman, pamac or PackageKit): wait for it to finish' && exit 1; sudo rm -f /var/lib/pacman/db.lck"),
                // Les dérivées signent aussi leurs paquets avec leurs propres clés.
                "sudo pacman -Sy --needed --noconfirm archlinux-keyring $(pacman -Qq manjaro-keyring endeavouros-keyring cachyos-keyring omarchy-keyring 2>/dev/null)",
                // Sous Omarchy, sa mise à jour (instantané, migrations) plutôt qu'un pacman -Syu brut.
                if machine::linux::omarchy() { "omarchy update" } else { "sudo pacman -Syu" },
            ],
        ).avec_restauration()),
        Some(Paquets::Apt) => l.push(rep(
            tr!("Mises à jour en erreur (apt)", "Updates failing (apt)"),
            tr!("Termine les installations interrompues et répare les dépendances cassées.", "Finishes interrupted installs and repairs broken dependencies."),
            tr!("quelques minutes", "a few minutes"),
            // Une étape en échec n'arrête pas les suivantes : ce sont elles qui réparent. La liste des paquets est
            // relue avant la réparation, qui sinon chercherait des versions disparues des dépôts.
            &["sudo dpkg --configure -a || true", "sudo apt-get update || true", "sudo apt-get -f install -y"],
        ).avec_restauration()),
        Some(Paquets::Dnf) => l.push(rep(
            tr!("Mises à jour en erreur (dnf)", "Updates failing (dnf)"),
            tr!("Vérifie la base des paquets et réaligne les paquets sur les versions de la distribution.", "Checks the package database and realigns packages with the distribution's versions."),
            tr!("quelques minutes", "a few minutes"),
            // « dnf check » sort en erreur quand il trouve un problème : c'est distro-sync qui le répare ensuite.
            &["sudo dnf check || true", "sudo dnf distro-sync -y"],
        ).avec_restauration()),
        Some(Paquets::Zypper) => l.push(rep(
            tr!("Mises à jour en erreur (zypper)", "Updates failing (zypper)"),
            tr!("Vérifie et répare les dépendances des paquets installés.", "Checks and repairs the dependencies of installed packages."),
            tr!("quelques minutes", "a few minutes"),
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
        tr!("Disque : santé et erreurs", "Disk: health and errors"),
        if btrfs {
            tr!("Lit l'état SMART de chaque disque (usure, secteurs défectueux) et vérifie toutes les données du système (btrfs scrub).", "Reads the SMART state of each disk (wear, bad sectors) and checks all the system data (btrfs scrub).")
        } else {
            tr!("Lit l'état SMART de chaque disque (usure, secteurs défectueux). Pour réparer un ext4, démarre sur la clé (SystemRescue).", "Reads the SMART state of each disk (wear, bad sectors). To repair ext4, boot from the USB key (SystemRescue).")
        },
        if btrfs { tr!("de quelques minutes à une heure", "from a few minutes to an hour") } else { tr!("quelques secondes", "a few seconds") },
        &disque,
    ));

    // Place
    // autoremove sans -y : la liste des paquets retirés s'affiche et se confirme (retirer un métapaquet peut
    // emporter tout un bureau).
    let mut menage: Vec<&str> = match gestion {
        Some(Paquets::Pacman) if present("paccache") => vec!["sudo paccache -rk2", "sudo paccache -ruk0"],
        Some(Paquets::Pacman) => vec!["sudo pacman -Sc --noconfirm"],
        Some(Paquets::Apt) => vec!["sudo apt-get autoremove", "sudo apt-get clean"],
        Some(Paquets::Dnf) if atomique == Some(Atomique::RpmOstree) => vec!["sudo rpm-ostree cleanup -bm"],
        Some(Paquets::Dnf) => vec!["sudo dnf autoremove", "sudo dnf clean all"],
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
        tr!("Disque plein", "Disk full"),
        trf!(
            "Vide les anciens paquets téléchargés, les vieux journaux et les miniatures ; {}.",
            "Removes old downloaded packages, old logs and thumbnails; {}.",
            occupation_racine()
        ),
        tr!("une minute", "one minute"),
        &menage,
    ));
    l.push(nettoyage(gestion));

    if !systemd {
        return l;
    }
    // Services
    l.push(rep(
        tr!("Services en échec", "Failed services"),
        tr!("Montre les services qui ont planté, avec leurs dernières erreurs, puis remet leur compteur à zéro.", "Shows the services that crashed, with their latest errors, then resets their counter."),
        tr!("quelques secondes", "a few seconds"),
        &[
            "systemctl --failed --no-pager",
            "for s in $(systemctl --failed --no-legend --plain | awk '{print $1}'); do echo \"== $s\"; journalctl -u $s -n 5 --no-pager; done",
            "sudo systemctl reset-failed",
        ],
    ));

    l.push(pare_feu(gestion));

    // Heure
    l.push(rep(
        tr!("Heure fausse", "Wrong time"),
        tr!(
            "Réactive la synchronisation de l'heure (une heure fausse casse le HTTPS et les mises à jour).",
            "Turns time synchronization back on (a wrong time breaks HTTPS and updates)."
        ),
        tr!("quelques secondes", "a few seconds"),
        &[
            "sudo timedatectl set-ntp true",
            "timedatectl status | grep -E 'synchronized|NTP'",
        ],
    ));
    l
}

// ───────────────────────────── macOS ─────────────────────────────

/// Instantané local de Time Machine (APFS) : macOS le garde 24 heures, de quoi revenir en arrière si la
/// réparation tourne mal (Récupération > Restaurer depuis Time Machine).
#[cfg(target_os = "macos")]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux, où l'outil peut manquer
pub(crate) fn point_restauration(_titre: &str) -> Option<(&'static str, String)> {
    Some(("Time Machine", "tmutil localsnapshot".to_string()))
}

/// Services réseau actifs de macOS (« Wi-Fi », « Ethernet »…), pour networksetup.
#[cfg(target_os = "macos")]
fn services_reseau() -> Vec<String> {
    crate::commande::lancer(
        std::process::Command::new("networksetup").arg("-listallnetworkservices"),
        10,
    )
    .map(|r| r.sortie)
    .unwrap_or_default()
    .lines()
    .skip(1)
    .filter(|l| !l.starts_with('*') && !l.trim().is_empty())
    .map(str::to_string)
    .collect()
}

/// Proxy imposé (`scutil --proxy` : « HTTPEnable : 1 ») et redirections du fichier hosts.
#[cfg(target_os = "macos")]
fn navigation_macos() -> Reparation {
    let detournees = redirections(&std::fs::read_to_string("/etc/hosts").unwrap_or_default());
    let proxy = crate::commande::lancer(std::process::Command::new("scutil").arg("--proxy"), 5)
        .map(|r| r.sortie)
        .unwrap_or_default();
    let actifs: Vec<&str> = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable"]
        .into_iter()
        .filter(|cle| {
            proxy
                .lines()
                .any(|l| l.trim().starts_with(cle) && l.trim().ends_with(": 1"))
        })
        .collect();
    let mut constats = Vec::new();
    let mut commandes = Vec::new();
    if !detournees.is_empty() {
        constats.push(trf!(
            "fichier hosts : {}",
            "hosts file: {}",
            resume_redirections(&detournees)
        ));
        commandes.push("sudo cp -p /etc/hosts /etc/hosts.sentinel-$(date +%Y%m%d-%H%M%S)".to_string());
        // sed de macOS : -i demande un suffixe (vide) ; puis vider le cache DNS pour que ça compte tout de suite.
        commandes.push(format!(
            "sudo sed -i '' -E 's/^([[:space:]]*({})[[:space:]])/# sentinel : \\1/' /etc/hosts",
            motif_adresses(&detournees)
        ));
        commandes.push("sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder".to_string());
    }
    if !actifs.is_empty() {
        constats.push(trf!("proxy actif ({})", "proxy on ({})", actifs.join(", ")));
        for service in services_reseau() {
            let s = entre_apostrophes(&service);
            commandes.push(format!(
                "sudo networksetup -setwebproxystate {s} off; sudo networksetup -setsecurewebproxystate {s} off; \
                 sudo networksetup -setsocksfirewallproxystate {s} off; sudo networksetup -setautoproxystate {s} off"
            ));
        }
    }
    let mut r = rep(
        tr!(
            "Navigation détournée (proxy, fichier hosts)",
            "Hijacked browsing (proxy, hosts file)"
        ),
        trf!(
            "Met en commentaire les lignes du fichier hosts qui envoient un site vers une adresse d'Internet (une copie est gardée) et coupe les proxys réglés dans le réseau. Les listes de blocage (0.0.0.0) et les appareils du réseau local ne sont pas touchés. Trouvé : {}.",
            "Comments out the hosts file lines that send a site to an Internet address (a copy is kept) and turns off the proxies set in the network settings. Block lists (0.0.0.0) and local network devices are left alone. Found: {}.",
            constats.join(" ; ")
        ),
        tr!("quelques secondes", "a few seconds"),
        &[],
    );
    r.restauration = !detournees.is_empty();
    if commandes.is_empty() {
        r.inutile = Some(
            tr!(
                "ni redirection dans le fichier hosts, ni proxy imposé",
                "no redirection in the hosts file, no forced proxy"
            )
            .into(),
        );
    }
    r.commandes = commandes;
    r
}

#[cfg(target_os = "macos")]
pub fn liste() -> Vec<Reparation> {
    const PARE_FEU: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
    let mut l = Vec::new();

    // Réseau : cache DNS, nouvelle adresse (DHCP) et Wi-Fi coupé puis rallumé, sur chaque interface active.
    let mut r = rep(
        tr!("Internet ne marche plus", "Internet no longer works"),
        tr!(
            "Vide le cache DNS, redemande une adresse à la box et relance le Wi-Fi (sites introuvables, Wi-Fi bloqué).",
            "Clears the DNS cache, asks the router for a new address and restarts Wi-Fi (sites not found, Wi-Fi stuck)."
        ),
        tr!("quelques secondes", "a few seconds"),
        &[
            "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder",
            // Seulement les interfaces déjà en DHCP (getpacket) : une adresse réglée à la main ne doit pas y passer.
            // « ; true » : la boucle prend le code de la dernière interface, souvent sans DHCP, et arrêterait la suite.
            "for i in $(ifconfig -lu); do ipconfig getpacket $i >/dev/null 2>&1 && sudo ipconfig set $i DHCP; done; true",
            "W=$(networksetup -listallhardwareports | awk '/Wi-Fi/{getline; print $2}'); \
             [ -n \"$W\" ] && networksetup -setairportpower $W off && sleep 3 && networksetup -setairportpower $W on; true",
        ],
    );
    if session_ssh() {
        r.bloquee = Some(tr!(
            "tu es connecté par SSH : relancer le réseau couperait ta connexion",
            "you are connected over SSH: restarting the network would cut your connection"
        ));
    }
    l.push(r);
    l.push(navigation_macos());

    // Pare-feu
    let actif = crate::commande::lancer(std::process::Command::new(PARE_FEU).arg("--getglobalstate"), 5)
        .is_some_and(|r| r.sortie.contains("enabled"));
    let mut feu = rep(
        tr!("Pare-feu coupé", "Firewall off"),
        tr!(
            "Active le pare-feu de macOS et son mode furtif (le Mac ne répond plus aux sondes du réseau).",
            "Turns on the macOS firewall and its stealth mode (the Mac no longer answers network probes)."
        ),
        tr!("quelques secondes", "a few seconds"),
        &[
            &format!("sudo {PARE_FEU} --setglobalstate on"),
            &format!("sudo {PARE_FEU} --setstealthmode on"),
        ],
    );
    if actif {
        feu.inutile = Some(tr!("le pare-feu est déjà actif", "the firewall is already on").into());
    }
    l.push(feu);

    // Antivirus : signatures ClamAV de Homebrew.
    let freshclam = machine::macos::homebrew()
        .map(|b| std::path::Path::new(b).with_file_name("freshclam"))
        .filter(|f| f.is_file());
    let mut av = rep(
        tr!("Antivirus pas à jour", "Antivirus out of date"),
        tr!(
            "Télécharge les dernières signatures de virus de ClamAV.",
            "Downloads the latest ClamAV virus signatures."
        ),
        tr!("une minute", "one minute"),
        &[],
    );
    match freshclam {
        Some(f) => av.commandes = vec![crate::antivirus::commande_freshclam(&f.display().to_string())],
        None => {
            av.inutile = Some(
                tr!(
                    "ClamAV n'est pas installé : l'analyse antivirus propose de l'installer",
                    "ClamAV is not installed: the antivirus scan offers to install it"
                )
                .into(),
            );
        }
    }
    l.push(av);

    // Homebrew en erreur
    if let Some(brew) = machine::macos::homebrew() {
        l.push(rep(
            tr!("Homebrew en erreur", "Homebrew failing"),
            tr!(
                "Remet Homebrew dans un état propre (dépôts réalignés), puis montre ce qu'il reste à corriger.",
                "Puts Homebrew back in a clean state (repositories realigned), then shows what is left to fix."
            ),
            tr!("quelques minutes", "a few minutes"),
            &[
                &format!("{brew} update-reset"),
                &format!("{brew} update"),
                &format!("{brew} doctor; true"),
            ],
        ));
    }

    // Disque
    l.push(rep(
        tr!("Disque : santé et erreurs", "Disk: health and errors"),
        tr!(
            "Lit l'état SMART du disque interne et vérifie le volume du système (sans le démonter). Pour réparer, Utilitaire de disque > S.O.S. en mode de secours.",
            "Reads the SMART state of the internal disk and checks the system volume (without unmounting it). To repair, Disk Utility > First Aid in Recovery."
        ),
        tr!("quelques minutes", "a few minutes"),
        &[
            "diskutil info disk0 | grep -i smart",
            "diskutil verifyVolume /",
        ],
    ));
    let mut menage = vec![
        // Fichiers de cache pas modifiés depuis une semaine, puis les dossiers restés vides : la date d'un dossier ne dit
        // pas si l'app y a écrit récemment plus bas, et l'effacer en entier emporterait ses fichiers du jour.
        "find ~/Library/Caches -type f -mtime +7 -delete 2>/dev/null; find ~/Library/Caches -mindepth 2 -type d -empty -delete 2>/dev/null; true".to_string(),
        // Instantanés locaux de Time Machine : macOS les garde tant qu'il y a de la place, mais ils comptent.
        "sudo tmutil thinlocalsnapshots / 999999999999 4".to_string(),
    ];
    if let Some(brew) = machine::macos::homebrew() {
        menage.push(format!("{brew} cleanup --prune=all"));
    }
    menage.push("df -h /".to_string());
    let mut plein = rep(
        tr!("Disque plein", "Disk full"),
        trf!(
            "Vide les caches anciens, les instantanés locaux de Time Machine et les téléchargements de Homebrew ; {}. La corbeille n'est pas touchée : vide-la toi-même.",
            "Removes old caches, local Time Machine snapshots and Homebrew downloads; {}. The Trash is left alone: empty it yourself.",
            occupation_racine()
        ),
        tr!("une minute", "one minute"),
        &[],
    );
    plein.commandes = menage;
    l.push(plein);

    // Heure
    l.push(rep(
        tr!("Heure fausse", "Wrong time"),
        tr!(
            "Réactive la mise à l'heure automatique et resynchronise tout de suite (une heure fausse casse le HTTPS et les mises à jour).",
            "Turns automatic time back on and syncs right away (a wrong time breaks HTTPS and updates)."
        ),
        tr!("quelques secondes", "a few seconds"),
        &["sudo systemsetup -setusingnetworktime on", "sudo sntp -sS time.apple.com"],
    ));
    l
}

/// Ce que la réparation Windows doit savoir avant d'ouvrir le menu, lu en un seul appel PowerShell (chacun
/// coûte une seconde) : proxy de l'utilisateur, proxy WinHTTP (services, mises à jour), profils du pare-feu.
#[cfg(windows)]
#[derive(Default, serde::Deserialize)]
#[serde(default)]
struct EtatWindows {
    proxy: String,
    pac: String,
    winhttp: String,
    parefeu_coupe: String,
    profils: u32,
}

#[cfg(windows)]
fn etat_windows() -> Option<EtatWindows> {
    // WinHttpSettings : l'octet 8 vaut 1 pour « accès direct » ; sinon la longueur du proxy est à l'octet 12
    // et son nom suit à l'octet 16.
    let json = machine::windows::ps(
        r"$i = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
          $w = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -ErrorAction SilentlyContinue).WinHttpSettings
          $wp = ''
          if ($w -and $w.Length -ge 16 -and $w[8] -ne 1) { $n = [BitConverter]::ToInt32($w, 12); $wp = if ($n -gt 0 -and $w.Length -ge 16 + $n) { [Text.Encoding]::ASCII.GetString($w, 16, $n) } else { 'configuré' } }
          $profils = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
          [pscustomobject]@{
            proxy = if ($i.ProxyEnable -eq 1) { [string]$i.ProxyServer } else { '' }
            pac = [string]$i.AutoConfigURL
            winhttp = $wp
            parefeu_coupe = (@($profils | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name }) -join ', ')
            profils = $profils.Count
          } | ConvertTo-Json -Compress",
    )?;
    serde_json::from_str(&json).ok()
}

#[cfg(windows)]
fn navigation(etat: Option<&EtatWindows>) -> Reparation {
    const REGLAGES: &str = r"'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'";
    let racine = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let hosts = std::path::Path::new(&racine).join(r"System32\drivers\etc\hosts");
    let detournees = redirections(&String::from_utf8_lossy(&std::fs::read(hosts).unwrap_or_default()));
    let mut constats = Vec::new();
    let mut commandes = Vec::new();
    if !detournees.is_empty() {
        constats.push(trf!(
            "fichier hosts : {}",
            "hosts file: {}",
            resume_redirections(&detournees)
        ));
        commandes.push(
            r#"$h = "$env:SystemRoot\System32\drivers\etc\hosts"; Copy-Item $h "$h.sentinel-$(Get-Date -Format yyyyMMdd-HHmmss)""#
                .to_string(),
        );
        // Réécrit en « Default » (ANSI), comme il a été lu : « ASCII » changerait en « ? » les lettres accentuées
        // des commentaires.
        commandes.push(format!(
            r#"$h = "$env:SystemRoot\System32\drivers\etc\hosts"; (Get-Content $h) | ForEach-Object {{ if ($_ -match '^\s*({})\s') {{ '# sentinel : ' + $_ }} else {{ $_ }} }} | Set-Content $h -Encoding Default"#,
            motif_adresses(&detournees)
        ));
    }
    // La fenêtre administrateur écrit dans le HKCU du compte qui l'ouvre : le même que le tien quand tu es
    // administrateur (cas courant), pas si tu tapes le mot de passe d'un autre compte.
    if let Some(e) = etat {
        if !e.proxy.is_empty() {
            constats.push(format!("proxy {}", e.proxy));
            commandes.push(format!("Set-ItemProperty {REGLAGES} -Name ProxyEnable -Value 0"));
        }
        if !e.pac.is_empty() {
            constats.push(trf!("script de proxy {}", "proxy script {}", e.pac));
            commandes.push(format!("Remove-ItemProperty {REGLAGES} -Name AutoConfigURL"));
        }
        if !e.winhttp.is_empty() {
            constats.push(trf!("proxy WinHTTP {}", "WinHTTP proxy {}", e.winhttp));
            commandes.push("netsh winhttp reset proxy".into());
        }
    }
    let mut r = rep(
        tr!(
            "Navigation détournée (proxy, fichier hosts)",
            "Hijacked browsing (proxy, hosts file)"
        ),
        trf!(
            "Met en commentaire les lignes du fichier hosts qui envoient un site vers une adresse d'Internet (une copie est gardée) et coupe le proxy imposé. Les listes de blocage (0.0.0.0) et les appareils du réseau local ne sont pas touchés. En entreprise, le proxy peut être voulu. Trouvé : {}.",
            "Comments out the hosts file lines that send a site to an Internet address (a copy is kept) and turns off the forced proxy. Block lists (0.0.0.0) and local network devices are left alone. In a company, the proxy may be intended. Found: {}.",
            constats.join(" ; ")
        ),
        tr!("quelques secondes", "a few seconds"),
        &[],
    );
    if commandes.is_empty() {
        r.inutile = Some(if etat.is_some() {
            tr!(
                "ni redirection dans le fichier hosts, ni proxy imposé",
                "no redirection in the hosts file, no forced proxy"
            )
            .into()
        } else {
            tr!(
                "aucune redirection dans le fichier hosts (réglages du proxy non lus)",
                "no redirection in the hosts file (proxy settings not read)"
            )
            .into()
        });
    } else {
        commandes.push("ipconfig /flushdns".into());
        r.restauration = true;
    }
    r.commandes = commandes;
    r
}

#[cfg(windows)]
fn pare_feu(etat: Option<&EtatWindows>) -> Reparation {
    let mut r = rep(
        tr!("Pare-feu coupé", "Firewall off"),
        tr!(
            "Réactive le pare-feu Windows sur les trois profils (domaine, privé, public).",
            "Turns the Windows firewall back on for the three profiles (domain, private, public)."
        ),
        tr!("quelques secondes", "a few seconds"),
        &[
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            "Get-NetFirewallProfile | Format-Table Name, Enabled",
        ],
    );
    match etat {
        Some(e) if e.profils > 0 && e.parefeu_coupe.is_empty() => {
            r.inutile = Some(
                tr!(
                    "le pare-feu Windows est actif sur tous les profils",
                    "the Windows firewall is on for every profile"
                )
                .into(),
            );
        }
        Some(e) if e.profils > 0 => {
            let _ = trw!(
                r.pourquoi,
                " Coupé pour : {}. Si un pare-feu tiers le remplace, ne rien faire.",
                " Off for: {}. If a third-party firewall replaces it, do nothing.",
                e.parefeu_coupe
            );
        }
        _ => r.pourquoi += tr!(" (état actuel non lu)", " (current state not read)"),
    }
    r
}

#[cfg(windows)]
pub fn liste() -> Vec<Reparation> {
    let etat = etat_windows();
    let etat = etat.as_ref();
    let a_distance = machine::windows::session_a_distance();
    let mut reseau = rep(
        tr!("Internet ne marche plus", "Internet no longer works"),
        tr!("Remet à zéro Winsock et la pile TCP/IP, vide le cache DNS, redemande une adresse. Un redémarrage termine la réparation. Une adresse IP fixe réglée à la main sera à remettre.", "Resets Winsock and the TCP/IP stack, clears the DNS cache, asks for a new address. A restart finishes the repair. A static IP address set by hand will have to be entered again."),
        tr!("une minute, puis redémarrer", "one minute, then restart"),
        &[
            "netsh winsock reset",
            "netsh int ip reset",
            "ipconfig /flushdns",
            "ipconfig /release",
            "ipconfig /renew",
        ],
    ).avec_restauration();
    if a_distance {
        reseau.bloquee = Some(tr!(
            "tu es connecté par le Bureau à distance : cette réparation couperait ta connexion",
            "you are connected over Remote Desktop: this repair would cut your connection"
        ));
    }
    vec![
        rep(
            tr!("Fichiers système abîmés", "Damaged system files"),
            tr!("Répare l'image de Windows (DISM) puis vérifie et remplace les fichiers système corrompus (SFC). À faire après un plantage ou un écran bleu.", "Repairs the Windows image (DISM), then checks and replaces corrupted system files (SFC). Do it after a crash or a blue screen."),
            tr!("15 à 45 minutes", "15 to 45 minutes"),
            &["DISM /Online /Cleanup-Image /RestoreHealth", "sfc /scannow"],
        ).avec_restauration(),
        rep(
            tr!("Disque : erreurs", "Disk: errors"),
            tr!("Analyse le disque C: sans le bloquer. Si des erreurs sont trouvées, la réparation se fait au redémarrage : chkdsk C: /f (C: ne peut pas être mis hors ligne pendant que Windows tourne).", "Scans disk C: without locking it. If errors are found, the repair happens at restart: chkdsk C: /f (C: cannot be taken offline while Windows is running)."),
            tr!("quelques minutes", "a few minutes"),
            &["Repair-Volume -DriveLetter C -Scan"],
        ),
        reseau,
        navigation(etat),
        pare_feu(etat),
        rep(
            tr!("Antivirus pas à jour", "Antivirus out of date"),
            tr!("Télécharge les dernières signatures de Microsoft Defender et affiche leur date.", "Downloads the latest Microsoft Defender signatures and shows their date."),
            tr!("une minute", "one minute"),
            &[
                "Update-MpSignature",
                "Get-MpComputerStatus | Format-List AntivirusSignatureLastUpdated, AntivirusSignatureVersion",
            ],
        ),
        rep(
            tr!("Windows Update bloqué", "Windows Update stuck"),
            tr!("Arrête les services de mise à jour, met de côté leurs caches (SoftwareDistribution, catroot2) et les relance.", "Stops the update services, sets their caches aside (SoftwareDistribution, catroot2) and restarts them."),
            tr!("une minute", "one minute"),
            &[
                "Stop-Service -Force wuauserv, bits, cryptsvc",
                "Rename-Item \"$env:SystemRoot\\SoftwareDistribution\" \"SoftwareDistribution.$(Get-Date -Format yyyyMMddHHmm)\"",
                "Rename-Item \"$env:SystemRoot\\System32\\catroot2\" \"catroot2.$(Get-Date -Format yyyyMMddHHmm)\"",
                "Start-Service wuauserv, bits, cryptsvc",
            ],
        ).avec_restauration(),
        rep(
            tr!("Disque plein", "Disk full"),
            tr!("Vide les fichiers temporaires et nettoie les anciennes versions des composants de Windows.", "Clears the temporary files and cleans up old versions of Windows components."),
            tr!("quelques minutes", "a few minutes"),
            &[
                "Get-ChildItem $env:TEMP -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue",
                "Dism /Online /Cleanup-Image /StartComponentCleanup",
                "Get-PSDrive C | Format-Table Used, Free",
            ],
        ),
        rep(
            tr!("Nettoyage approfondi", "Deep cleanup"),
            tr!("Vide la corbeille, le dossier temporaire de Windows, le cache de Windows Update et de l'optimisation de distribution, et les anciens rapports de plantage.", "Empties the recycle bin, the Windows temporary folder, the Windows Update and Delivery Optimization caches, and old crash reports."),
            tr!("quelques minutes", "a few minutes"),
            &[
                "Clear-RecycleBin -Force -ErrorAction SilentlyContinue",
                "Get-ChildItem \"$env:SystemRoot\\Temp\" -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue",
                "Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue",
                "Stop-Service wuauserv -Force; Get-ChildItem \"$env:SystemRoot\\SoftwareDistribution\\Download\" -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue; Start-Service wuauserv",
                "Remove-Item \"$env:SystemRoot\\Minidump\\*\", \"$env:LOCALAPPDATA\\CrashDumps\\*\" -Force -ErrorAction SilentlyContinue",
                "Get-PSDrive C | Format-Table Used, Free",
            ],
        ),
        rep(
            tr!("Heure fausse", "Wrong time"),
            tr!("Resynchronise l'horloge (une heure fausse casse le HTTPS et Windows Update).", "Resynchronizes the clock (a wrong time breaks HTTPS and Windows Update)."),
            tr!("quelques secondes", "a few seconds"),
            // Service désactivé (par un outil d'« optimisation ») : remis comme à l'origine, sinon il ne démarre pas.
            &[
                "if ((Get-Service w32time).StartType -eq 'Disabled') { Set-Service w32time -StartupType Manual }",
                "Start-Service w32time",
                "w32tm /resync /force",
            ],
        ),
    ]
}

/// Menu des réparations : choisir, lire, confirmer.
pub fn menu() {
    let reparations = liste();
    titre(tr!("Réparer", "Repair"));
    for (i, r) in reparations.iter().enumerate() {
        let note = if r.bloquee.is_some() {
            trf!(
                "  {GRIS}(indisponible ici){RESET}",
                "  {GRIS}(not available here){RESET}"
            )
        } else if r.inutile.is_some() {
            trf!("  {GRIS}(rien à faire){RESET}", "  {GRIS}(nothing to do){RESET}")
        } else {
            String::new()
        };
        println!("  {}. {}{note}", i + 1, r.titre);
    }
    let choix = demander(tr!(
        "\nNuméro de la réparation (Entrée pour revenir) : ",
        "\nRepair number (Enter to go back): "
    ));
    let Some(r) = choix
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|n| reparations.get(n))
    else {
        return;
    };
    println!("\n  {GRAS}{}{RESET}", r.titre);
    if let Some(raison) = &r.inutile {
        trp!(
            "  {VERT}✔ Rien à faire : {raison}.{RESET}",
            "  {VERT}✔ Nothing to do: {raison}.{RESET}"
        );
        return;
    }
    println!("  {}", r.pourquoi);
    trp!("  {GRIS}Durée : {}{RESET}", "  {GRIS}Duration: {}{RESET}", r.duree);
    if let Some(raison) = r.bloquee {
        trp!(
            "\n  ✖ Pas maintenant : {raison}. Fais-la depuis l'écran de l'ordinateur.",
            "\n  ✖ Not now: {raison}. Do it from the computer's own screen."
        );
        return;
    }
    trp!("  Commandes :", "  Commands:");
    for c in &r.commandes {
        println!("    {GRIS}{c}{RESET}");
    }
    if !demander(tr!(
        "\n  Lancer cette réparation ? [o/N] : ",
        "\n  Run this repair? [y/N]: "
    ))
    .oui()
    {
        trp!("  Annulé.", "  Cancelled.");
        return;
    }
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut commandes = r.commandes.clone();
    // Point de restauration automatique avant une réparation qui modifie le système : on peut revenir en arrière.
    if r.restauration
        && let Some((outil, point)) = point_restauration(r.titre)
    {
        trp!(
            "  {GRIS}Point de restauration d'abord ({outil}).{RESET}",
            "  {GRIS}Restore point first ({outil}).{RESET}"
        );
        // Windows : dans la même fenêtre administrateur (une seule demande) ; elle demande quoi faire si ça échoue.
        #[cfg(windows)]
        commandes.insert(0, point);
        #[cfg(not(windows))]
        if !machine::appliquer(&[point])
            && !demander(tr!(
                "  ✖ Point de restauration impossible. Continuer quand même ? [o/N] : ",
                "  ✖ Restore point not possible. Continue anyway? [y/N]: "
            ))
            .oui()
        {
            trp!("  Annulé.", "  Cancelled.");
            return;
        }
    }
    if machine::appliquer(&commandes) {
        trp!(
            "  {VERT}✔ Réparation terminée.{RESET}",
            "  {VERT}✔ Repair finished.{RESET}"
        );
    } else {
        trp!(
            "  ✖ Une étape a échoué : lis le message ci-dessus.",
            "  ✖ A step failed: read the message above."
        );
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
            assert!(!r.titre.is_empty() && !r.duree.is_empty());
            if r.inutile.is_none() {
                assert!(!r.pourquoi.is_empty(), "{} n'explique rien", r.titre);
                assert!(!r.commandes.is_empty(), "{} n'a pas de commande", r.titre);
            }
        }
    }

    /// Une apostrophe ou une parenthèse oubliée ne se verrait qu'au lancement de la réparation, chez quelqu'un.
    #[cfg(unix)]
    #[test]
    fn les_commandes_sont_du_shell_valide() {
        for r in liste() {
            for c in &r.commandes {
                let valide = std::process::Command::new("bash")
                    .args(["-n", "-c", c])
                    .status()
                    .is_ok_and(|s| s.success());
                assert!(valide, "« {} » : {c}", r.titre);
            }
        }
    }

    #[test]
    fn redirections_du_fichier_hosts() {
        let hosts = "127.0.0.1 localhost\n::1 localhost ip6-localhost\nfe00::0 ip6-localnet\nff02::1 ip6-allnodes\n\
                     127.0.1.1 machine.local machine\n0.0.0.0 pub.exemple.com\n:: pistage.exemple.com\n\
                     192.168.1.20 nas # mon NAS\n100.101.2.3 tailscale-pc\n# 8.8.8.8 commentaire.exemple\n\
                     \t185.12.0.9\tbanque.fr   www.banque.fr\n2a00:1450::1 update.microsoft.com\n::ffff:93.184.216.34 mappee.com\n1.2.3.4\n";
        let r = redirections(hosts);
        assert_eq!(
            r,
            vec![
                ("185.12.0.9".to_string(), "banque.fr www.banque.fr".to_string()),
                ("2a00:1450::1".to_string(), "update.microsoft.com".to_string()),
                ("::ffff:93.184.216.34".to_string(), "mappee.com".to_string()),
            ]
        );
        assert_eq!(
            motif_adresses(&r),
            r"185\.12\.0\.9|2a00:1450::1|::ffff:93\.184\.216\.34"
        );
        assert!(resume_redirections(&r).starts_with("185.12.0.9 → banque.fr www.banque.fr, "));
    }
}
