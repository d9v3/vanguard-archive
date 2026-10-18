//! Programmes au démarrage : ceux qui se lancent à l'ouverture de session, retirés ou remis après accord. Chacun est
//! un réglage hors catalogue (« demarrage:<identité> ») : la valeur d'avant est notée, il s'annule exactement, un par
//! un dans cette liste ou tous par « Tout remettre comme avant ». Le programme reste installé et se lance à la main.
//! Ce qui protège ou fait marcher l'ordinateur (Gardien, antivirus, pare-feu, pilotes, accessibilité, composants du
//! bureau) est montré sans être proposé.

use std::borrow::Cow;

use super::{Categorie, Historique, Reglage, charger, confirmer_et_executer, systeme};
use crate::selection::{Case, cocher};
use crate::ui::*;

/// Préfixe des réglages de démarrage dans l'historique des réglages (reglages.json).
pub(super) const PREFIXE: &str = "demarrage:";

/// Un programme lancé à l'ouverture de session, tel que le système de cette machine le décrit.
pub struct Programme {
    /// Nom affiché (« Discord »).
    pub nom: String,
    /// Ce qui est lancé (commande, fichier), pour le reconnaître.
    pub commande: String,
    /// Se lance en ce moment à l'ouverture de session.
    pub actif: bool,
    /// Programme de toute la machine : la fenêtre administrateur s'ouvrira (Windows).
    pub machine: bool,
    /// Composant de la session du bureau (GNOME, KDE…) : à garder.
    pub bureau: bool,
    /// Ce qui le retire, et le remet.
    pub changement: systeme::Changement,
}

/// Le réglage qui retire ce programme du démarrage.
fn reglage(nom: &str, changement: systeme::Changement) -> Option<Reglage> {
    Some(Reglage {
        id: Cow::Owned(format!("{PREFIXE}{}", changement.identite_demarrage()?)),
        // Hors des menus de catégorie : la catégorie ne sert pas.
        categorie: Categorie::Confort,
        titre: Cow::Owned(trf!("{nom} (au démarrage)", "{nom} (at startup)")),
        effet: tr!(
            "Ne se lance plus à l'ouverture de session ; il reste installé et se lance à la main.",
            "No longer starts at login; it stays installed and starts by hand."
        ),
        prudence: None,
        recommande: false,
        changements: vec![changement],
    })
}

/// Les programmes que Gardien a retirés du démarrage, rebâtis d'après leurs notes : pour les remettre (« Tout remettre
/// comme avant », ou cette liste), même s'ils ne se lancent plus et n'apparaissent donc plus ailleurs.
pub(super) fn notes(h: &Historique) -> Vec<Reglage> {
    h.reglages
        .keys()
        .filter_map(|cle| {
            let identite = cle.strip_prefix(PREFIXE)?;
            let c = systeme::Changement::demarrage_depuis(identite)?;
            reglage(&systeme::Changement::nom_demarrage(identite), c)
        })
        .collect()
}

/// Pourquoi un programme reste au démarrage, s'il le doit : il protège ou fait marcher l'ordinateur. Comparé en
/// minuscules au nom et à la commande ; un motif court est un mot entier (« avg » ne doit pas trouver « savgame »).
pub(super) fn a_garder(nom: &str, commande: &str, bureau: bool) -> Option<&'static str> {
    const GARDIEN: &[&str] = &["gardien", "sentinel", "netscan"];
    const SECURITE: &[&str] = &[
        "securityhealth",
        "windows security",
        "defender",
        "msmpeng",
        "smartscreen",
        "mcafee",
        "norton",
        "symantec",
        "avast",
        "avg",
        "avira",
        "bitdefender",
        "eset",
        "kaspersky",
        "avp",
        "malwarebytes",
        "mbam",
        "sophos",
        "trendmicro",
        "trend micro",
        "f-secure",
        "webroot",
        "clamav",
        "clamtk",
        "firewall",
        "firewalld",
        "gufw",
        "ufw",
        "opensnitch",
        "little snitch",
        "lulu",
        // Notifications d'AppArmor (Ubuntu), contrôle des clés USB.
        "apparmor",
        "usbguard",
        // Protections d'entreprise et autres antivirus.
        "crowdstrike",
        "csfalcon",
        "sentinelone",
        "cylance",
        "carbon black",
        "cbdefense",
        "comodo",
        "zonealarm",
        "panda",
        "emsisoft",
        "antivirus",
        "gdata",
        "avktray",
        "hitmanpro",
        "zemana",
        "acronis",
        "forticlient",
        "globalprotect",
        "zscaler",
        "netskope",
        // Mac : Intego, ClamXAV, les outils d'Objective-See (BlockBlock, KnockKnock, LuLu…).
        "intego",
        "virusbarrier",
        "clamxav",
        "objective-see",
        "blockblock",
        // Un VPN qui démarre avec la session protège la connexion (souvent avec un coupe-circuit).
        "wireguard",
        "openvpn",
        "protonvpn",
        "mullvad",
        "nordvpn",
        "expressvpn",
        "surfshark",
    ];
    const PILOTES: &[&str] = &[
        "realtek",
        "rtkaud",
        "rtkngui",
        "ravcpl",
        "ravbg",
        "synaptics",
        "syntp",
        "etdctrl",
        "elantech",
        "igfx",
        "hkcmd",
        "nvidia",
        "nvbackend",
        "radeon",
        "amdrsserv",
        "wacom",
    ];
    const ACCESSIBILITE: &[&str] = &[
        "narrator",
        "magnify",
        "osk",
        "sapisvr",
        "nvda",
        "jaws",
        "zoomtext",
        "orca",
        "onboard",
        "at-spi",
        "accessibility",
        "voiceover",
        "atbroker",
        "utilman",
    ];
    const BUREAU: &[&str] = &[
        "pipewire",
        "wireplumber",
        "pulseaudio",
        "xdg-desktop-portal",
        "gnome-keyring",
        "polkit",
        "dbus",
        "gsd",
        "settingsdaemon",
        "plasmashell",
        "kded",
        "ksmserver",
    ];
    let texte = format!("{nom} {commande}").to_lowercase();
    let mots: Vec<&str> = texte
        .split(|c: char| !c.is_alphanumeric())
        .filter(|m| !m.is_empty())
        .collect();
    // Un motif d'au moins six lettres, ou avec une espace ou un tiret, se cherche dans le texte ; plus court, c'est un
    // mot entier.
    let trouve = |motifs: &[&str]| {
        motifs.iter().any(|m| {
            if m.len() >= 6 || m.contains([' ', '-']) {
                texte.contains(m)
            } else {
                mots.contains(m)
            }
        })
    };
    // La sécurité d'abord : « sentinelone » contient « sentinel », l'ancien nom de Gardien.
    if trouve(SECURITE) {
        Some(tr!("à garder : sécurité", "keep: security"))
    } else if trouve(GARDIEN) {
        Some(tr!("à garder : Gardien", "keep: Gardien"))
    } else if trouve(PILOTES) {
        Some(tr!("à garder : pilote", "keep: driver"))
    } else if trouve(ACCESSIBILITE) {
        Some(tr!("à garder : accessibilité", "keep: accessibility"))
    } else if bureau || trouve(BUREAU) {
        Some(tr!("à garder : le bureau", "keep: desktop"))
    } else {
        None
    }
}

/// Ce que Gardien ne retire pas d'ici, et où le faire.
fn ailleurs() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Les tâches planifiées et les services ne sont pas dans cette liste : Gestionnaire des tâches, ou Antivirus et protection › Analyse rapide (revue du démarrage).",
            "Scheduled tasks and services are not in this list: Task Manager, or Antivirus and protection › Quick scan (startup review)."
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "Éléments de connexion et agents de toute la machine : Réglages Système › Général › Ouverture (« − » pour retirer). Ils demandent un geste dans les Réglages ou l'administrateur.",
            "Login items and machine-wide agents: System Settings › General › Login Items (“−” to remove). They need a step in Settings or an administrator."
        )
    } else {
        tr!(
            "Ce que lance la configuration du bureau (exec-once de Hyprland, par exemple), les services du système, et les entrées qui sont des liens (dotfiles, home-manager) : dans leurs fichiers.",
            "What the desktop configuration starts (Hyprland's exec-once, for example), system services, and entries that are links (dotfiles, home-manager): in their files."
        )
    }
}

// ── Windows : comme le Gestionnaire des tâches ──────────────────────────────────────────────────────────────────

/// Où Windows note les programmes de démarrage désactivés, sous HKCU (le compte) ou HKLM (la machine), puis Run,
/// Run32 ou StartupFolder.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) const APPROUVES: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

/// Les listes de StartupApproved que Gardien touche (une note ne doit pas en viser une autre).
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn liste_approuvee(l: &str) -> Option<&'static str> {
    ["Run", "Run32", "StartupFolder"].into_iter().find(|x| *x == l)
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn hex(octets: &[u8]) -> String {
    use std::fmt::Write;
    octets.iter().fold(String::with_capacity(octets.len() * 2), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    })
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn octets(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Désactivé pour Windows : premier octet impair (03, 07). Pair (02, 06) ou valeur absente : activé.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn desactive_windows(hex: &str) -> bool {
    octets(hex).and_then(|o| o.first().copied()).is_some_and(|b| b & 1 == 1)
}

/// Ce qu'écrit le Gestionnaire des tâches pour désactiver un programme : 03 00 00 00, puis l'heure du changement
/// (FILETIME : centaines de nanosecondes depuis 1601), en hexadécimal.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn valeur_desactivee(quand: std::time::SystemTime) -> String {
    const DE_1601_A_1970: u64 = 116_444_736_000_000_000;
    let depuis_1970 = quand.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let temps = u64::try_from(depuis_1970.as_nanos() / 100).unwrap_or(0) + DE_1601_A_1970;
    let mut o = vec![3, 0, 0, 0];
    o.extend_from_slice(&temps.to_le_bytes());
    hex(&o)
}

/// Le script PowerShell de la fenêtre administrateur qui écrit (ou retire, `None`) la valeur d'un programme de toute
/// la machine dans StartupApproved. Par le registre de .NET : le -Name de Remove-ItemProperty accepte des jokers, un
/// nom comme « App[1] » y viserait d'autres valeurs ; CreateSubKey garde ce que la clé contient déjà.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn script_machine(liste: &str, nom: &str, valeur: Option<&str>) -> Option<String> {
    let cle = crate::commande::ps_texte(&format!(r"{APPROUVES}\{}", liste_approuvee(liste)?));
    let n = crate::commande::ps_texte(nom);
    Some(match valeur.filter(|v| !v.is_empty()) {
        None => format!(
            "$k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('{cle}', $true); \
             if ($k) {{ $k.DeleteValue('{n}', $false); $k.Close() }}"
        ),
        Some(h) => {
            let o: Vec<String> = octets(h)?.iter().map(|b| format!("0x{b:02x}")).collect();
            format!(
                "$k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('{cle}'); \
                 $k.SetValue('{n}', [byte[]]({}), [Microsoft.Win32.RegistryValueKind]::Binary); $k.Close()",
                o.join(",")
            )
        }
    })
}

// ── macOS : agents de launchd du compte ─────────────────────────────────────────────────────────────────────────

/// Un nom d'agent de launchd (« com.exemple.agent ») : il entre tel quel dans une commande.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn label_valide(t: &str) -> bool {
    !t.is_empty() && t.len() <= 255 && t.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// Les agents désactivés, d'après `launchctl print-disabled gui/<uid>` : « "com.x" => disabled » (ou « => true »
/// pour les anciens macOS).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn desactives_launchd(texte: &str) -> std::collections::HashSet<String> {
    texte
        .lines()
        .filter_map(|l| {
            let (label, etat) = l.trim().split_once("=>")?;
            let label = label.trim().trim_matches('"');
            matches!(etat.trim(), "disabled" | "true").then(|| label.to_string())
        })
        .collect()
}

/// Un programme de la liste : ce qui l'affiche et le réglage qui le retire.
struct Ligne {
    nom: String,
    commande: String,
    actif: bool,
    machine: bool,
    garder: Option<&'static str>,
    par_gardien: bool,
    reglage: Reglage,
}

/// Ce qui se montre : les programmes qui se lancent, et ceux que Gardien a retirés (pour pouvoir les remettre). Un
/// programme retiré ailleurs (Gestionnaire des tâches, Réglages) reste comme il est, sans être montré.
fn lignes(programmes: Vec<Programme>, h: &Historique) -> Vec<Ligne> {
    let mut l: Vec<Ligne> = Vec::new();
    for p in programmes {
        let Some(r) = reglage(&p.nom, p.changement) else {
            continue;
        };
        let par_gardien = h.reglages.contains_key(r.id.as_ref());
        if !p.actif && !par_gardien {
            continue;
        }
        l.push(Ligne {
            garder: a_garder(&p.nom, &p.commande, p.bureau),
            nom: p.nom,
            commande: p.commande,
            actif: p.actif,
            machine: p.machine,
            par_gardien,
            reglage: r,
        });
    }
    // Retirés par Gardien mais introuvables ici (un service désactivé ne se liste plus) : rebâtis d'après la note.
    for r in notes(h) {
        if l.iter().any(|x| x.reglage.id == r.id) {
            continue;
        }
        let identite = r.id.strip_prefix(PREFIXE).unwrap_or_default();
        l.push(Ligne {
            nom: systeme::Changement::nom_demarrage(identite),
            commande: identite.to_string(),
            actif: false,
            machine: false,
            garder: None,
            par_gardien: true,
            reglage: r,
        });
    }
    l.sort_by_key(|x| x.nom.to_lowercase());
    l
}

/// La liste à cocher : coché = se lance à l'ouverture de session. Décocher retire, recocher remet exactement comme
/// avant ce que Gardien avait retiré.
pub fn menu() {
    let h = charger();
    let l = lignes(systeme::au_demarrage(), &h);
    if l.is_empty() {
        titre(tr!("Programmes au démarrage", "Startup programs"));
        trp!(
            "  {VERT}✔{RESET} Aucun programme du compte ne se lance à l'ouverture de session.",
            "  {VERT}✔{RESET} No program of this account starts at login."
        );
        afficher_aligne("  ", ailleurs(), 2, "");
        return;
    }
    let cases: Vec<Case> = l
        .iter()
        .map(|x| {
            let precision = match (x.garder, x.actif) {
                (Some(raison), _) => raison,
                (None, true) => tr!("se lance", "starts"),
                (None, false) => tr!("retiré par Gardien", "removed by Gardien"),
            };
            let mut detail = x.commande.chars().take(200).collect::<String>();
            if x.machine {
                detail.push_str(tr!(
                    " · toute la machine : la fenêtre administrateur s'ouvrira",
                    " · whole machine: the administrator window will open"
                ));
            }
            Case {
                texte: x.nom.clone(),
                precision: precision.to_string(),
                detail,
                cochee: x.actif,
                recommandee: false,
                // À garder : montré, jamais proposé.
                fixe: x.garder.is_some() && x.actif,
            }
        })
        .collect();
    let entete = vec![
        String::new(),
        ligne_titre(tr!("Programmes au démarrage", "Startup programs")),
        trf!(
            "  {GRIS}Coché = se lance à l'ouverture de session. Décoche pour le retirer :{RESET}",
            "  {GRIS}Checked = starts at login. Uncheck to remove it: it stays{RESET}"
        ),
        trf!(
            "  {GRIS}il reste installé. Recocher le remet exactement comme avant.{RESET}",
            "  {GRIS}installed. Checking it again puts it back exactly as before.{RESET}"
        ),
        String::new(),
    ];
    let Some(voulu) = cocher(&entete, &cases) else {
        return;
    };
    let a_retirer: Vec<&Reglage> = l
        .iter()
        .zip(&voulu)
        .filter(|(x, v)| x.actif && !**v && x.garder.is_none())
        .map(|(x, _)| &x.reglage)
        .collect();
    let a_remettre: Vec<&Reglage> = l
        .iter()
        .zip(&voulu)
        .filter(|(x, v)| !x.actif && **v && x.par_gardien)
        .map(|(x, _)| &x.reglage)
        .collect();
    if a_retirer.is_empty() && a_remettre.is_empty() {
        trp!("  {GRIS}Rien à changer.{RESET}", "  {GRIS}Nothing to change.{RESET}");
    } else {
        confirmer_et_executer(&a_retirer, &a_remettre);
    }
    println!();
    afficher_aligne("  ", ailleurs(), 2, "");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programmes_a_garder() {
        assert!(
            a_garder(
                "SecurityHealth",
                r"C:\Windows\system32\SecurityHealthSystray.exe",
                false
            )
            .is_some()
        );
        assert!(a_garder("AVG UI", "avgui.exe", false).is_some());
        // « avg » est un mot entier : un jeu qui le contient au milieu d'un mot n'est pas un antivirus.
        assert_eq!(a_garder("Savgame Sync", "savgame.exe", false), None);
        assert!(a_garder("RtkAudUService", r"C:\Windows\System32\RtkAudUService64.exe", false).is_some());
        assert!(a_garder("Clavier visuel", "osk.exe", false).is_some());
        assert!(a_garder("gardien-surveillance", "gardien surveiller", false).is_some());
        assert!(a_garder("PipeWire", "/usr/bin/pipewire", false).is_some());
        assert!(a_garder("Panneau", "panneau", true).is_some());
        assert_eq!(
            a_garder("Discord", r"C:\Users\alice\AppData\Local\Discord\Update.exe", false),
            None
        );
        assert_eq!(a_garder("Steam", "/usr/bin/steam -silent", false), None);
        // Outils de sécurité ajoutés : notifications d'AppArmor, protections d'entreprise, VPN, outils du Mac.
        assert!(a_garder("AppArmor Notify", "aa-notify -p -s 1 -w 60 -f /var/log/kern.log", false).is_some());
        assert!(
            a_garder("SentinelOne", r"C:\Program Files\SentinelOne\SentinelUI.exe", false)
                .is_some_and(|r| r.contains("sécurité") || r.contains("security"))
        );
        assert!(
            a_garder(
                "blockblock",
                "/Applications/BlockBlock Helper.app/Contents/MacOS/BlockBlock",
                false
            )
            .is_some()
        );
        assert!(a_garder("NordVPN", r"C:\Program Files\NordVPN\NordVPN.exe", false).is_some());
        assert!(a_garder("mullvad-vpn", "/opt/Mullvad VPN/mullvad-gui", false).is_some());
        assert!(
            a_garder(
                "AVKTray",
                r"C:\Program Files (x86)\G DATA\AntiVirus\AVK\AVKTray.exe",
                false
            )
            .is_some()
        );
        // Et pas les programmes ordinaires.
        for (nom, commande) in [
            ("Spotify", "spotify --minimized"),
            ("Slack", "slack -u"),
            ("Pandoc", "pandoc"),
            ("Telegram", "telegram-desktop"),
            ("Big Data Studio", "bigdata --tray"),
        ] {
            assert_eq!(a_garder(nom, commande, false), None, "{nom}");
        }
    }

    #[test]
    fn valeurs_de_startup_approved() {
        assert_eq!(octets(&hex(&[3, 0, 0x10, 0xff])), Some(vec![3, 0, 0x10, 0xff]));
        assert_eq!(octets("0"), None);
        assert_eq!(octets("zz"), None);
        assert!(desactive_windows("030000000011223344556677"));
        assert!(desactive_windows("07000000"));
        assert!(!desactive_windows("020000000000000000000000"));
        assert!(!desactive_windows(""));
        // 1970 : la première date des FILETIME de 1601 décalée, en petit-boutiste après 03 00 00 00.
        let v = valeur_desactivee(std::time::UNIX_EPOCH);
        assert_eq!(v, format!("03000000{}", hex(&116_444_736_000_000_000u64.to_le_bytes())));
        assert_eq!(v.len(), 24);
        assert!(desactive_windows(&valeur_desactivee(std::time::SystemTime::now())));
        assert_eq!(liste_approuvee("Run32"), Some("Run32"));
        assert_eq!(liste_approuvee(r"Run\..\Autre"), None);
    }

    #[test]
    fn script_de_la_fenetre_administrateur() {
        let s = script_machine("Run", "L’appli", Some("0300")).unwrap();
        assert!(s.contains("SetValue('L’’appli', [byte[]](0x03,0x00)"), "{s}");
        assert!(s.contains(r"CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run')"));
        let s = script_machine("StartupFolder", "Appli.lnk", None).unwrap();
        assert!(s.contains("DeleteValue('Appli.lnk', $false)"), "{s}");
        assert_eq!(script_machine("Autre", "x", None), None);
        assert_eq!(script_machine("Run", "x", Some("0")), None);
    }

    /// Le script, analysé par un vrai PowerShell : un nom piégé reste du texte, et le script garde ses instructions
    /// (une injection en ajouterait). Sauté sans pwsh (sous Wine, PowerShell n'existe pas).
    #[test]
    fn script_piege_reste_du_texte() {
        let piege = "Appli’; Write-Output INJECTE; ’ ‘x‚ ‛ 'y [1]";
        for (valeur, instructions) in [(None, 2), (Some("0300000000000000"), 3)] {
            let script = script_machine("Run", piege, valeur).unwrap();
            let analyse = format!(
                "$t = $null; $e = $null; $a = [System.Management.Automation.Language.Parser]::ParseInput({}, [ref]$t, [ref]$e); Write-Output (\"$($e.Count) $($a.EndBlock.Statements.Count)\")",
                crate::commande::ps_chaine(&script)
            );
            let programme = if cfg!(windows) { "powershell" } else { "pwsh" };
            let Some(r) = crate::commande::lancer(
                std::process::Command::new(programme).args(["-NoProfile", "-NonInteractive", "-Command", &analyse]),
                60,
            ) else {
                eprintln!("{programme} absent : essai sauté");
                return;
            };
            if r.sortie.trim().is_empty() {
                return;
            }
            assert_eq!(r.sortie.trim(), format!("0 {instructions}"), "{script}\n{}", r.erreurs);
        }
    }

    /// Montrés : ceux qui se lancent, et ceux que Gardien a retirés, même introuvables (un service désactivé ne se
    /// liste plus) ; pas ceux retirés ailleurs.
    #[cfg(target_os = "linux")]
    #[test]
    fn programmes_montres() {
        use super::super::Avant;
        use super::systeme::{Changement, Entree};
        let service = |nom: &str, actif: bool| Programme {
            nom: nom.to_string(),
            commande: format!("/usr/bin/{nom}"),
            actif,
            machine: false,
            bureau: false,
            changement: Changement::Demarrage {
                entree: Entree::Service(format!("{nom}.service")),
                cible: Some("disabled".to_string()),
            },
        };
        let mut h = Historique::default();
        h.reglages.insert(
            format!("{PREFIXE}systemd|retire.service"),
            Avant {
                date: String::new(),
                valeurs: vec![Some("enabled".to_string())],
            },
        );
        let l = lignes(
            vec![
                service("syncthing", true),
                service("ailleurs", false),
                service("gardien-essai", true),
            ],
            &h,
        );
        let vus: Vec<(&str, bool, bool, bool)> = l
            .iter()
            .map(|x| (x.nom.as_str(), x.actif, x.par_gardien, x.garder.is_some()))
            .collect();
        assert_eq!(
            vus,
            [
                ("gardien-essai", true, false, true),
                ("retire", false, true, false),
                ("syncthing", true, false, false)
            ]
        );
        // « Tout remettre comme avant » le retrouve aussi.
        let n = notes(&h);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].id, "demarrage:systemd|retire.service");
    }

    #[test]
    fn agents_desactives_de_launchd() {
        let texte = "disabled services = {\n\t\"com.exemple.agent\" => disabled\n\t\"com.exemple.autre\" => enabled\n\t\"org.ancien.mac\" => true\n\t\"org.ancien.actif\" => false\n}\n";
        let d = desactives_launchd(texte);
        assert!(d.contains("com.exemple.agent") && d.contains("org.ancien.mac"));
        assert!(!d.contains("com.exemple.autre") && !d.contains("org.ancien.actif"));
        assert!(label_valide("com.exemple.agent-2_b"));
        assert!(!label_valide("com.exemple;rm"));
        assert!(!label_valide(""));
    }
}
