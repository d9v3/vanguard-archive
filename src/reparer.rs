//! Réparations courantes, pour chaque système : réseau, navigation détournée, pare-feu, antivirus, fichiers
//! système, disque, place, mises à jour, heure.
//! Chaque réparation est montrée (pourquoi, durée, commandes) puis confirmée avant d'être lancée ; celles qui
//! modifient le système proposent d'abord un point de restauration.

use std::fmt::Write;
use std::net::IpAddr;

use crate::machine;
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

/// Résumé lisible : « 1.2.3.4 → banque.fr, 5.6.7.8 → update.microsoft.com (et 3 autres) ».
fn resume_redirections(lignes: &[(String, String)]) -> String {
    let mut t = lignes
        .iter()
        .take(3)
        .map(|(ip, noms)| format!("{ip} → {noms}"))
        .collect::<Vec<_>>()
        .join(", ");
    if lignes.len() > 3 {
        let _ = write!(t, " (et {} autres)", lignes.len() - 3);
    }
    t
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
fn point_restauration(titre: &str) -> Option<(&'static str, String)> {
    let description = entre_apostrophes(&format!("netscan : avant « {titre} »"));
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
fn point_restauration(titre: &str) -> Option<(&'static str, String)> {
    let description = entre_apostrophes(&format!("netscan : avant « {titre} »"));
    Some((
        "Windows",
        format!(
            "try {{ Checkpoint-Computer -Description {description} -RestorePointType MODIFY_SETTINGS }} \
             catch {{ Write-Host 'Point de restauration impossible (protection du système désactivée sur C: ?).' -ForegroundColor Red; \
             if ((Read-Host 'Continuer sans point de restauration ? [o/N]') -ne 'o') {{ exit 1 }} }}"
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
        constats.push(format!("fichier hosts : {}", resume_redirections(&detournees)));
        commandes.push("sudo cp -p /etc/hosts /etc/hosts.netscan-$(date +%Y%m%d-%H%M%S)".to_string());
        commandes.push(format!(
            "sudo sed -i -E 's/^([[:space:]]*({})[[:space:]])/# netscan : \\1/' /etc/hosts",
            motif_adresses(&detournees)
        ));
    }
    if let Some(mode) = &gnome {
        constats.push(format!("proxy du bureau en mode « {mode} »"));
        commandes.push("gsettings set org.gnome.system.proxy mode 'none'".to_string());
    }
    if !variables.is_empty() {
        // Définies dans un fichier de démarrage : on montre où, c'est à retirer à la main (peut être voulu).
        constats.push(format!(
            "variables {} (à retirer à la main du fichier montré)",
            variables.join(", ")
        ));
        commandes.push(
            "grep -nsE '^[^#]*(https?|all|ftp)_proxy=' /etc/environment /etc/profile /etc/profile.d/* ~/.profile ~/.bashrc ~/.bash_profile ~/.zshrc ~/.config/environment.d/*; true"
                .to_string(),
        );
    }
    let mut r = rep(
        "Navigation détournée (proxy, fichier hosts)",
        format!(
            "Met en commentaire les lignes du fichier hosts qui envoient un site vers une adresse d'Internet (une copie est gardée) et coupe le proxy imposé. Les listes de blocage (0.0.0.0) et les appareils du réseau local ne sont pas touchés. Trouvé : {}.",
            constats.join(" ; ")
        ),
        "quelques secondes",
        &[],
    );
    r.restauration = !detournees.is_empty();
    if commandes.is_empty() {
        r.inutile = Some("ni redirection dans le fichier hosts, ni proxy imposé".into());
    }
    r.commandes = commandes;
    r
}

/// Signatures ClamAV : téléchargement immédiat, puis mise à jour automatique.
#[cfg(target_os = "linux")]
fn antivirus(systemd: bool) -> Reparation {
    let mut r = rep("Antivirus pas à jour", "", "une minute", &[]);
    if !present("clamscan") {
        r.inutile =
            Some("ClamAV n'est pas installé : l'analyse antivirus (choix 6 ou 7) propose de l'installer".into());
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
        .map_or("jamais".to_string(), |d| match d.as_secs() / 86_400 {
            0 => "aujourd'hui".to_string(),
            1 => "hier".to_string(),
            n => format!("il y a {n} jours"),
        });
    r.pourquoi = format!(
        "Télécharge les dernières signatures de virus de ClamAV et active leur mise à jour automatique. Dernière mise à jour : {derniere}."
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
    let mut r = rep("Pare-feu coupé ou ouvert", "", "quelques secondes", &[]);
    if service_actif("firewalld") {
        let zone = crate::commande::lancer(std::process::Command::new("firewall-cmd").arg("--get-default-zone"), 10)
            .map(|z| z.sortie.trim().to_string());
        if zone.as_deref() == Some("trusted") {
            r.pourquoi = "firewalld est actif mais en zone « trusted » : il laisse tout entrer. Passe la zone par défaut en « public ».".into();
            r.commandes = vec!["sudo firewall-cmd --set-default-zone=public".into()];
        } else {
            r.inutile = Some("firewalld est actif".into());
        }
        return r;
    }
    let politique = std::fs::read_to_string("/etc/default/ufw")
        .ok()
        .and_then(|t| politique_ufw(&t));
    if ufw_actif() && politique.as_deref() != Some("ACCEPT") {
        r.inutile = Some("ufw est actif et refuse les connexions entrantes".into());
        return r;
    }
    if !present("ufw") {
        if let Some(autre) = ["nftables", "iptables"].into_iter().find(|s| service_actif(s)) {
            r.inutile = Some(format!("{autre} est actif : ses règles se gèrent à la main"));
            return r;
        }
        let Some(g) = gestion else {
            r.inutile = Some(
                "aucun pare-feu, et gestionnaire de paquets non reconnu : installe ufw avec ta distribution".into(),
            );
            return r;
        };
        r.commandes.push(g.installer("ufw"));
    }
    r.pourquoi = "Active ufw et refuse par défaut les connexions entrantes (les sorties restent permises). Un service qui doit rester joignable depuis le réseau (partage, KDE Connect…) sera à autoriser : sudo ufw allow <port>.".into();
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
        r.bloquee = Some("tu es connecté par SSH : refuser les connexions entrantes couperait ta connexion");
    }
    r
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
    l.push(navigation());
    l.push(antivirus(systemd));

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
        ).avec_restauration()),
        Some(Paquets::Apt) => l.push(rep(
            "Mises à jour en erreur (apt)",
            "Termine les installations interrompues et répare les dépendances cassées.",
            "quelques minutes",
            &["sudo dpkg --configure -a", "sudo apt-get -f install -y", "sudo apt-get update"],
        ).avec_restauration()),
        Some(Paquets::Dnf) => l.push(rep(
            "Mises à jour en erreur (dnf)",
            "Vérifie la base des paquets et réaligne les paquets sur les versions de la distribution.",
            "quelques minutes",
            &["sudo dnf check", "sudo dnf distro-sync -y"],
        ).avec_restauration()),
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

    l.push(pare_feu(gestion));

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
        constats.push(format!("fichier hosts : {}", resume_redirections(&detournees)));
        commandes.push(
            r#"$h = "$env:SystemRoot\System32\drivers\etc\hosts"; Copy-Item $h "$h.netscan-$(Get-Date -Format yyyyMMdd-HHmmss)""#
                .to_string(),
        );
        commandes.push(format!(
            r#"$h = "$env:SystemRoot\System32\drivers\etc\hosts"; (Get-Content $h) | ForEach-Object {{ if ($_ -match '^\s*({})\s') {{ '# netscan : ' + $_ }} else {{ $_ }} }} | Set-Content $h -Encoding ASCII"#,
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
            constats.push(format!("script de proxy {}", e.pac));
            commandes.push(format!("Remove-ItemProperty {REGLAGES} -Name AutoConfigURL"));
        }
        if !e.winhttp.is_empty() {
            constats.push(format!("proxy WinHTTP {}", e.winhttp));
            commandes.push("netsh winhttp reset proxy".into());
        }
    }
    let mut r = rep(
        "Navigation détournée (proxy, fichier hosts)",
        format!(
            "Met en commentaire les lignes du fichier hosts qui envoient un site vers une adresse d'Internet (une copie est gardée) et coupe le proxy imposé. Les listes de blocage (0.0.0.0) et les appareils du réseau local ne sont pas touchés. En entreprise, le proxy peut être voulu. Trouvé : {}.",
            constats.join(" ; ")
        ),
        "quelques secondes",
        &[],
    );
    if commandes.is_empty() {
        r.inutile = Some(if etat.is_some() {
            "ni redirection dans le fichier hosts, ni proxy imposé".into()
        } else {
            "aucune redirection dans le fichier hosts (réglages du proxy non lus)".into()
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
        "Pare-feu coupé",
        "Réactive le pare-feu Windows sur les trois profils (domaine, privé, public).",
        "quelques secondes",
        &[
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            "Get-NetFirewallProfile | Format-Table Name, Enabled",
        ],
    );
    match etat {
        Some(e) if e.profils > 0 && e.parefeu_coupe.is_empty() => {
            r.inutile = Some("le pare-feu Windows est actif sur tous les profils".into());
        }
        Some(e) if e.profils > 0 => {
            let _ = write!(
                r.pourquoi,
                " Coupé pour : {}. Si un pare-feu tiers le remplace, ne rien faire.",
                e.parefeu_coupe
            );
        }
        _ => r.pourquoi += " (état actuel non lu)",
    }
    r
}

#[cfg(windows)]
pub fn liste() -> Vec<Reparation> {
    let etat = etat_windows();
    let etat = etat.as_ref();
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
    ).avec_restauration();
    if a_distance {
        reseau.bloquee = Some("tu es connecté par le Bureau à distance : cette réparation couperait ta connexion");
    }
    vec![
        rep(
            "Fichiers système abîmés",
            "Répare l'image de Windows (DISM) puis vérifie et remplace les fichiers système corrompus (SFC). À faire après un plantage ou un écran bleu.",
            "15 à 45 minutes",
            &["DISM /Online /Cleanup-Image /RestoreHealth", "sfc /scannow"],
        ).avec_restauration(),
        rep(
            "Disque : erreurs",
            "Analyse le disque C: sans le bloquer. Si des erreurs sont trouvées, la réparation se fait au redémarrage : chkdsk C: /f (C: ne peut pas être mis hors ligne pendant que Windows tourne).",
            "quelques minutes",
            &["Repair-Volume -DriveLetter C -Scan"],
        ),
        reseau,
        navigation(etat),
        pare_feu(etat),
        rep(
            "Antivirus pas à jour",
            "Télécharge les dernières signatures de Microsoft Defender et affiche leur date.",
            "une minute",
            &[
                "Update-MpSignature",
                "Get-MpComputerStatus | Format-List AntivirusSignatureLastUpdated, AntivirusSignatureVersion",
            ],
        ),
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
        ).avec_restauration(),
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

/// Menu des réparations : choisir, lire, confirmer.
pub fn menu() {
    let reparations = liste();
    titre("Réparer");
    for (i, r) in reparations.iter().enumerate() {
        let note = if r.bloquee.is_some() {
            format!("  {GRIS}(indisponible ici){RESET}")
        } else if r.inutile.is_some() {
            format!("  {GRIS}(rien à faire){RESET}")
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
    if let Some(raison) = &r.inutile {
        println!("  {VERT}✔ Rien à faire : {raison}.{RESET}");
        return;
    }
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
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut commandes = r.commandes.clone();
    if r.restauration
        && let Some((outil, point)) = point_restauration(r.titre)
        && !demander(&format!(
            "  Créer d'abord un point de restauration ({outil}) ? [O/n] : "
        ))
        .eq_ignore_ascii_case("n")
    {
        // Windows : dans la même fenêtre administrateur (une seule demande) ; elle demande quoi faire si ça échoue.
        #[cfg(windows)]
        commandes.insert(0, point);
        #[cfg(not(windows))]
        if !machine::appliquer(&[point])
            && !demander("  ✖ Point de restauration impossible. Continuer quand même ? [o/N] : ")
                .eq_ignore_ascii_case("o")
        {
            println!("  Annulé.");
            return;
        }
    }
    if machine::appliquer(&commandes) {
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
            assert!(!r.titre.is_empty() && !r.duree.is_empty());
            if r.inutile.is_none() {
                assert!(!r.pourquoi.is_empty(), "{} n'explique rien", r.titre);
                assert!(!r.commandes.is_empty(), "{} n'a pas de commande", r.titre);
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
