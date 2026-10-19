//! Recherche de malwares avec un moteur reconnu (ClamAV sous Linux, Microsoft Defender sous Windows)
//! et revue des programmes lancés au démarrage, là où un malware cherche à se maintenir.

use std::path::PathBuf;
use std::process::Command;

use crate::risk::Niveau;
use crate::ui::*;

#[cfg(unix)]
fn home() -> PathBuf {
    PathBuf::from(
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .unwrap_or_default(),
    )
}

/// Ce qu'un moteur a conclu sur un fichier.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Examen {
    Sain,
    /// Détections : nom de la menace ou de la famille.
    Trouve(Vec<String>),
    /// Pas pu analyser, avec la raison : jamais compté comme sain.
    Impossible(String),
}

/// Ce que couvre une analyse.
pub enum Portee {
    /// Là où arrivent les menaces : téléchargements, bureau, démarrage automatique, /tmp récent.
    Rapide,
    /// Tout le dossier personnel.
    Complete,
    /// Une clé USB, un disque externe ou un dossier choisi.
    Dossier(PathBuf),
}

pub fn analyser(portee: Portee) {
    titre(match portee {
        Portee::Rapide => tr!("Analyse antivirus rapide", "Quick antivirus scan"),
        Portee::Complete => tr!("Analyse antivirus complète", "Full antivirus scan"),
        Portee::Dossier(_) => tr!(
            "Analyse antivirus d'une clé ou d'un dossier",
            "Antivirus scan of a drive or folder"
        ),
    });
    let portee = match portee {
        Portee::Dossier(d) => {
            let Ok(reel) = d.canonicalize() else {
                trp!("  ✖ Introuvable : {}", "  ✖ Not found: {}", chemin_affichable(&d));
                return;
            };
            Portee::Dossier(reel)
        }
        autre => autre,
    };
    #[cfg(windows)]
    defender(&portee);
    #[cfg(unix)]
    clamav(&portee);
    match &portee {
        // Une clé n'a pas de programmes de démarrage : on regarde plutôt les pièges des vers de clé USB.
        Portee::Dossier(d) => revue_cle(d),
        _ => demarrage(),
    }
}

/// Menu : propose les clés et disques externes branchés, ou un chemin tapé à la main.
pub fn choisir() {
    let volumes = volumes_amovibles();
    titre(tr!("Antivirus : clé USB ou dossier", "Antivirus: USB drive or folder"));
    if volumes.is_empty() {
        trp!(
            "  {GRIS}Aucune clé ni disque externe monté.{RESET}",
            "  {GRIS}No USB drive or external disk mounted.{RESET}"
        );
    }
    for (i, (chemin, description)) in volumes.iter().enumerate() {
        println!(
            "  {TOUCHE}{}{RESET}  {}  {DISCRET}{description}{RESET}",
            i + 1,
            chemin_affichable(chemin)
        );
    }
    let reponse = demander(tr!(
        "\n  Numéro, ou chemin d'un dossier (Entrée pour revenir) : ",
        "\n  Number, or path of a folder (Enter to go back): "
    ));
    let reponse = reponse.trim();
    if reponse.is_empty() {
        return;
    }
    let cible = match reponse.parse::<usize>() {
        Ok(n) if (1..=volumes.len()).contains(&n) => volumes[n - 1].0.clone(),
        _ => PathBuf::from(reponse.trim_matches(['"', '\''])),
    };
    analyser(Portee::Dossier(cible));
}

/// Clés et disques externes montés : (point de montage, description).
#[cfg(target_os = "linux")]
fn volumes_amovibles() -> Vec<(PathBuf, String)> {
    Command::new("lsblk")
        .args(["-Pno", "RM,HOTPLUG,LABEL,SIZE,MOUNTPOINT"])
        .output()
        .map(|o| lire_lsblk(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

/// Clés et disques externes montés sous macOS : tout ce qui est dans /Volumes, sauf le disque du système (un
/// lien vers « / »). Description : nom et taille (df), prête à montrer (l'étiquette vient de qui a préparé la clé).
#[cfg(target_os = "macos")]
fn volumes_amovibles() -> Vec<(PathBuf, String)> {
    let racine = std::fs::canonicalize("/").unwrap_or_default();
    std::fs::read_dir("/Volumes")
        .into_iter()
        .flatten()
        .flatten()
        .map(|d| d.path())
        .filter(|p| std::fs::canonicalize(p).is_ok_and(|r| r != racine))
        .map(|p| {
            let taille = Command::new("df")
                .args(["-h", "-P"])
                .arg(&p)
                .output()
                .ok()
                .and_then(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .nth(1)
                        .and_then(|l| l.split_whitespace().nth(1).map(str::to_string))
                })
                .unwrap_or_default();
            let nom = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (p, affichable(&format!("{nom} · {taille}")))
        })
        .collect()
}

/// Lignes de `lsblk -P` : RM="1" HOTPLUG="1" LABEL="CLE" SIZE="28,9G" MOUNTPOINT="/run/media/alice/CLE". La
/// description est prête à montrer (l'étiquette vient de qui a préparé la clé) ; le point de montage reste tel quel,
/// pour l'analyse.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lire_lsblk(texte: &str) -> Vec<(PathBuf, String)> {
    texte
        .lines()
        .filter_map(|l| {
            let champ = |nom: &str| {
                let debut = l.find(&format!("{nom}=\""))? + nom.len() + 2;
                let fin = l[debut..].find('"')? + debut;
                // lsblk échappe les espaces et caractères spéciaux en \xHH.
                Some(l[debut..fin].replace("\\x20", " "))
            };
            let amovible = champ("RM").as_deref() == Some("1") || champ("HOTPLUG").as_deref() == Some("1");
            let point = champ("MOUNTPOINT").filter(|m| m.starts_with('/'))?;
            amovible.then(|| {
                let nom = champ("LABEL").filter(|n| !n.is_empty());
                let taille = champ("SIZE").unwrap_or_default();
                (
                    PathBuf::from(point),
                    affichable(&nom.map_or(taille.clone(), |n| format!("{n} · {taille}"))),
                )
            })
        })
        .collect()
}

#[cfg(windows)]
fn volumes_amovibles() -> Vec<(PathBuf, String)> {
    crate::machine::windows::ps(
        "Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter } | ForEach-Object { \
         \"$($_.DriveLetter)|$($_.FileSystemLabel)|$([math]::Round($_.Size / 1GB, 1))\" }",
    )
    .unwrap_or_default()
    .lines()
    .filter_map(|l| {
        let mut c = l.trim().splitn(3, '|');
        let lettre = c.next().filter(|x| !x.is_empty())?;
        let nom = c.next().unwrap_or("");
        let taille = c.next().unwrap_or("");
        Some((
            PathBuf::from(format!("{lettre}:\\")),
            affichable(&format!("{nom} · {taille} Go")),
        ))
    })
    .collect()
}

/// Pièges classiques des vers de clé USB, à la racine : raccourci qui imite un dossier (le vrai est caché),
/// lanceur automatique, scripts. `entrees` = (nom, est un dossier).
fn signes_de_ver(entrees: &[(String, bool)]) -> Vec<(Niveau, String)> {
    // La clé de Gardien (ou préparée sous un ancien nom) a son autorun.inf et son lanceur : rien de suspect.
    if entrees.iter().any(|(n, _)| {
        std::iter::once(crate::reseau::TEMOIN_CLE)
            .chain(crate::reseau::ANCIENS_TEMOINS_CLE)
            .any(|t| n.eq_ignore_ascii_case(t))
    }) {
        return Vec::new();
    }
    let mut signes = Vec::new();
    let dossiers: Vec<String> = entrees
        .iter()
        .filter(|(_, d)| *d)
        .map(|(n, _)| n.to_lowercase())
        .collect();
    for (nom, dossier) in entrees.iter().filter(|(_, d)| !*d) {
        let bas = nom.to_lowercase();
        let (souche, extension) = bas.rsplit_once('.').unwrap_or((&bas, ""));
        if bas == "autorun.inf" {
            signes.push((Niveau::Moyen, trf!(
                "autorun.inf : Windows ne le lance plus tout seul, mais des vers s'en servent encore. À supprimer si tu ne l'as pas mis.",
                "autorun.inf: Windows no longer runs it by itself, but worms still use it. Delete it if you did not put it there."
            )));
        } else if extension == "lnk" && (dossiers.iter().any(|d| d == souche) || entrees.len() <= 3) && !dossier {
            signes.push((Niveau::Eleve, trf!(
                "« {nom} » : un raccourci qui se fait passer pour un dossier, technique classique d'un ver de clé USB (le vrai dossier est caché, le raccourci lance le ver). N'ouvre pas ce raccourci.",
                "“{nom}”: a shortcut posing as a folder, a classic USB worm trick (the real folder is hidden, the shortcut runs the worm). Do not open this shortcut."
            )));
        } else if ["vbs", "vbe", "js", "jse", "wsf", "wsh", "scr", "pif", "hta"].contains(&extension) {
            signes.push((Niveau::Eleve, trf!(
                "« {nom} » : script ou programme rarement légitime sur une clé. Ne le lance pas sans savoir d'où il vient.",
                "“{nom}”: a script or program rarely legitimate on a drive. Do not run it without knowing where it comes from."
            )));
        }
    }
    signes
}

fn revue_cle(racine: &std::path::Path) {
    if !racine.is_dir() {
        return;
    }
    titre(tr!("Pièges de clé USB", "USB drive traps"));
    // Les noms, choisis par qui a rempli la clé, sont seulement montrés : lus prêts à montrer.
    let entrees: Vec<(String, bool)> = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| (affichable(&e.file_name().to_string_lossy()), e.path().is_dir()))
        .collect();
    let signes = signes_de_ver(&entrees);
    if signes.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Aucun raccourci piégé, lanceur automatique ni script suspect à la racine.",
            "  {VERT}✔{RESET} No trapped shortcut, autorun or suspicious script at the root."
        );
    }
    for (n, s) in signes {
        println!("  {}●{RESET} {s}", couleur(n));
    }
}

// ───────────────────────────── Windows : Microsoft Defender ─────────────────────────────

#[cfg(windows)]
fn defender(portee: &Portee) {
    use crate::machine::windows::{powershell_admin, ps};
    let mpcmd =
        PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_default()).join(r"Windows Defender\MpCmdRun.exe");
    trp!(
        "  {GRIS}Moteur : Microsoft Defender. Cela peut prendre de quelques minutes à une heure (analyse complète)…{RESET}",
        "  {GRIS}Engine: Microsoft Defender. This can take from a few minutes to an hour (full scan)…{RESET}"
    );
    let mut commande = Command::new(&mpcmd);
    match portee {
        Portee::Rapide => commande.args(["-Scan", "-ScanType", "1"]),
        Portee::Complete => commande.args(["-Scan", "-ScanType", "2"]),
        // Analyse personnalisée d'un dossier ou d'une clé.
        Portee::Dossier(d) => commande.args(["-Scan", "-ScanType", "3", "-File"]).arg(d),
    };
    let statut = commande.status();
    match statut.map(|s| s.code()) {
        Ok(Some(0)) => trp!(
            "  {VERT}✔ Aucun malware trouvé.{RESET}",
            "  {VERT}✔ No malware found.{RESET}"
        ),
        Ok(Some(2)) => {
            let menaces = ps("Get-MpThreat | ForEach-Object { \"$($_.ThreatName)|$($_.Resources -join ', ')\" }")
                .unwrap_or_default();
            for l in menaces.lines() {
                let (nom, fichiers) = l.split_once('|').unwrap_or((l, ""));
                let (nom, fichiers) = (affichable(nom), affichable(fichiers));
                println!("  {}✖ {nom}{RESET}  {fichiers}", couleur(Niveau::Critique));
            }
            trp!(
                "  Defender a normalement déjà mis ces fichiers en quarantaine.",
                "  Defender has normally already quarantined these files."
            );
            if demander(tr!(
                "  Supprimer définitivement les menaces détectées ? [o/N] : ",
                "  Permanently delete the detected threats? [y/N]: "
            ))
            .oui()
                && powershell_admin(&["Remove-MpThreat".to_string()])
            {
                trp!(
                    "  {VERT}✔ Menaces supprimées.{RESET}",
                    "  {VERT}✔ Threats deleted.{RESET}"
                );
            }
        }
        _ => trp!(
            "  Defender n'a pas pu lancer l'analyse (antivirus tiers actif ?).",
            "  Defender could not start the scan (third-party antivirus active?)."
        ),
    }
}

/// Un seul fichier, pour « Vérifier un fichier téléchargé » : le résultat de Defender, qui met lui-même en
/// quarantaine ce qu'il reconnaît.
#[cfg(windows)]
pub(crate) fn examiner(fichier: &std::path::Path) -> Examen {
    let mpcmd =
        PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_default()).join(r"Windows Defender\MpCmdRun.exe");
    let Some(r) = crate::commande::lancer(
        Command::new(&mpcmd)
            .args(["-Scan", "-ScanType", "3", "-File"])
            .arg(fichier),
        900,
    ) else {
        return Examen::Impossible(tr!("Defender n'a pas pu aller au bout", "Defender could not finish").into());
    };
    match r.code {
        Some(0) => Examen::Sain,
        Some(2) => Examen::Trouve(menaces_mpcmdrun(&r.sortie)),
        _ => Examen::Impossible(
            tr!(
                "Defender n'a pas pu analyser (antivirus tiers actif ?)",
                "Defender could not scan (third-party antivirus active?)"
            )
            .into(),
        ),
    }
}

/// Noms des menaces dans la sortie de MpCmdRun : « Threat                  : Virus:DOS/EICAR_Test_File », prêts à
/// montrer.
#[cfg(any(windows, test))]
fn menaces_mpcmdrun(sortie: &str) -> Vec<String> {
    let noms: Vec<String> = sortie
        .lines()
        .filter_map(|l| {
            let (cle, valeur) = l.split_once(':')?;
            (cle.trim() == "Threat").then(|| affichable(valeur.trim()))
        })
        .filter(|v| !v.is_empty())
        .collect();
    if noms.is_empty() {
        vec![tr!("menace reconnue par Defender", "threat recognized by Defender").to_string()]
    } else {
        noms
    }
}

/// Un seul fichier, pour « Vérifier un fichier téléchargé » : le résultat de ClamAV, sans rien déplacer.
#[cfg(unix)]
pub(crate) fn examiner(fichier: &std::path::Path) -> Examen {
    if !preparer() {
        return Examen::Impossible(
            tr!(
                "ClamAV absent (installation refusée ou impossible)",
                "ClamAV missing (installation declined or failed)"
            )
            .into(),
        );
    }
    // Au-delà de 200 Mo, ClamAV saute le fichier sans le lire (--max-filesize) : rien ne serait conclu.
    if std::fs::metadata(fichier).is_ok_and(|m| m.len() > 200 * 1024 * 1024) {
        return Examen::Impossible(
            tr!(
                "fichier de plus de 200 Mo, que ClamAV ne lit pas",
                "file over 200 MB, which ClamAV does not read"
            )
            .into(),
        );
    }
    let Some(r) = crate::commande::lancer(
        Command::new(outil_clamav("clamscan"))
            .args(["-i", "--max-filesize=200M", "--max-scansize=400M"])
            .arg(fichier),
        900,
    ) else {
        return Examen::Impossible(tr!("ClamAV n'a pas pu aller au bout", "ClamAV could not finish").into());
    };
    match lire_resultat(r.code, &r.sortie) {
        Some(b) if b.analyses == 0 => {
            Examen::Impossible(tr!("fichier illisible pour ClamAV", "file unreadable for ClamAV").into())
        }
        Some(b) if b.infectes.is_empty() => Examen::Sain,
        Some(b) => Examen::Trouve(b.infectes.into_iter().map(|(_, menace)| menace).collect()),
        None => Examen::Impossible(tr!("l'analyse de ClamAV a échoué", "the ClamAV scan failed").into()),
    }
}

// ───────────────────────────── Linux : ClamAV ─────────────────────────────

#[cfg(unix)]
fn shell(c: &str) -> bool {
    println!("  {GRIS}$ {}{RESET}", crate::ui::commande_affichable(c));
    Command::new("bash")
        .arg("-c")
        .arg(c)
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(unix)]
fn base_presente() -> bool {
    // Homebrew : /opt/homebrew (Apple Silicon) ou /usr/local (Intel).
    [
        "/var/lib/clamav",
        "/opt/homebrew/var/lib/clamav",
        "/usr/local/var/lib/clamav",
    ]
    .iter()
    .any(|dossier| {
        std::fs::read_dir(dossier).is_ok_and(|d| {
            d.flatten().any(|f| {
                std::path::Path::new(&f.file_name())
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("cvd") || e.eq_ignore_ascii_case("cld"))
            })
        })
    })
}

/// freshclam sous macOS : ClamAV de Homebrew y écrit « ERROR: NULL X509 store » à chaque téléchargement, alors que
/// les signatures arrivent et sont vérifiées (cause inconnue même des auteurs : Cisco-Talos/clamav#1421). Le
/// message, alarmant et sans conséquence, est retiré ; le code de retour de freshclam est gardé.
#[cfg(target_os = "macos")]
pub(crate) fn commande_freshclam(freshclam: &str) -> String {
    format!(
        "set -o pipefail; '{}' 2>&1 | {{ grep -v 'NULL X509 store' || true; }}",
        freshclam.replace('\'', r"'\''")
    )
}

/// Chemin d'un outil de ClamAV. Sous macOS, Homebrew n'est pas toujours dans le PATH du Terminal.
#[cfg(unix)]
fn outil_clamav(nom: &str) -> String {
    #[cfg(target_os = "macos")]
    if let Some(brew) = crate::machine::macos::homebrew() {
        let chemin = std::path::Path::new(brew).with_file_name(nom);
        if chemin.is_file() {
            return chemin.display().to_string();
        }
    }
    nom.to_string()
}

/// Installe ClamAV et télécharge les signatures si besoin. Retourne `false` si l'utilisateur refuse.
#[cfg(unix)]
fn preparer() -> bool {
    let present = Command::new("bash")
        .arg("-c")
        .arg(format!("command -v '{}'", outil_clamav("clamscan")))
        .output()
        .is_ok_and(|o| o.status.success());
    if !present {
        trp!(
            "  ClamAV (antivirus open source) n'est pas installé.",
            "  ClamAV (open source antivirus) is not installed."
        );
        if !demander(tr!("  L'installer maintenant ? [o/N] : ", "  Install it now? [y/N]: ")).oui() {
            return false;
        }
        // Fedora sépare le moteur et l'outil de mise à jour des signatures.
        #[cfg(target_os = "linux")]
        let installation = match crate::machine::linux::Paquets::detecter() {
            Some(g @ crate::machine::linux::Paquets::Dnf) => g.installer("clamav clamav-update"),
            Some(g) => g.installer("clamav"),
            None => {
                trp!(
                    "  Gestionnaire de paquets non reconnu : installe ClamAV avec l'outil de ta distribution.",
                    "  Package manager not recognized: install ClamAV with your distribution's tool."
                );
                return false;
            }
        };
        #[cfg(target_os = "macos")]
        let Some(brew) = crate::machine::macos::homebrew() else {
            trp!(
                "  Homebrew est nécessaire pour installer ClamAV : https://brew.sh",
                "  Homebrew is needed to install ClamAV: https://brew.sh"
            );
            return false;
        };
        #[cfg(target_os = "macos")]
        let installation = format!("{brew} install clamav");
        if !shell(&installation) {
            trp!("  Installation impossible.", "  Installation failed.");
            return false;
        }
    }
    if !base_presente() {
        trp!(
            "  Téléchargement des signatures de virus (~300 Mo, une seule fois)…",
            "  Downloading the virus signatures (~300 MB, only once)…"
        );
        #[cfg(target_os = "linux")]
        // Sur Debian/Ubuntu/Mint, le service tourne déjà et verrouille la base : on l'arrête le temps du premier téléchargement.
        let ok = shell("sudo systemctl stop clamav-freshclam.service 2>/dev/null; sudo freshclam")
            && shell("sudo systemctl enable --now clamav-freshclam.service");
        // Homebrew livre seulement un modèle de configuration (« Example » à retirer) ; pas besoin de sudo.
        #[cfg(target_os = "macos")]
        let ok = {
            let freshclam = outil_clamav("freshclam");
            let prefixe = std::path::Path::new(&freshclam)
                .parent()
                .and_then(std::path::Path::parent)
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            shell(&format!(
                "C='{prefixe}/etc/clamav/freshclam.conf'; [ -f \"$C\" ] || sed '/^Example/d' \"$C.sample\" > \"$C\"; {}",
                commande_freshclam(&freshclam)
            ))
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Les endroits à risque du dossier personnel sous Linux et macOS : là où arrivent les menaces (téléchargements,
/// bureau, démarrage automatique, programmes de l'utilisateur). L'analyse rapide de l'antivirus et celle de YARA.
#[cfg(unix)]
pub(crate) const ENDROITS_A_RISQUE: [&str; 7] = [
    "Downloads",
    "Téléchargements",
    "Desktop",
    "Bureau",
    ".local/bin",
    ".config/autostart",
    "Library/LaunchAgents",
];

#[cfg(unix)]
fn clamav(portee: &Portee) {
    if !preparer() {
        trp!("  Analyse annulée.", "  Scan cancelled.");
        return;
    }
    let h = home();
    // Analyse rapide : là où arrivent les menaces (téléchargements, bureau, démarrage automatique, programmes de
    // l'utilisateur). Documents passe par l'analyse complète : des milliers de fichiers, rarement une porte d'entrée.
    let cibles: Vec<PathBuf> = match portee {
        Portee::Dossier(d) => vec![d.clone()],
        Portee::Complete => vec![h.clone()],
        Portee::Rapide => ENDROITS_A_RISQUE
            .iter()
            .map(|d| h.join(d))
            .filter(|p| p.exists())
            .collect(),
    };
    let cibles = sans_doublons(cibles);
    // /tmp : seulement les fichiers récents (7 jours), où atterrit un téléchargement en cours ou un script lancé ;
    // le reste peut peser des gigaoctets (caches de compilation, préfixes Wine) sans rien apprendre.
    let liste_tmp = if matches!(portee, Portee::Rapide) {
        let fichiers = fichiers_recents(std::path::Path::new("/tmp"), 7, 5000);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let chemin = std::env::temp_dir().join(format!("gardien-clamav-{}-{nanos}.txt", std::process::id()));
        let texte = fichiers
            .iter()
            .map(|f| f.display().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        // Création exclusive : jamais un fichier ou un lien posé d'avance par un autre compte dans /tmp.
        let ecrit = !fichiers.is_empty()
            && std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&chemin)
                .and_then(|mut f| std::io::Write::write_all(&mut f, texte.as_bytes()))
                .is_ok();
        ecrit.then_some((chemin, fichiers.len()))
    } else {
        None
    };
    // Jeux, caches et préfixes Wine sont énormes et produisent des faux positifs (cracks, outils anti-triche).
    // Un dossier choisi est analysé en entier : seules les quarantaines restent à l'écart.
    let tout = [
        "Games",
        ".steam",
        ".local/share/Steam",
        ".cache",
        "Windows",
        ".cargo/registry",
        ".rustup",
        "target",
        "node_modules",
        // Dossiers privés des services systemd (root seul) : illisibles, ils feraient compter des erreurs.
        "systemd-private-[^/]*",
        // Quarantaine de Gardien, et sous ses anciens noms si le dossier n'a pas pu être renommé.
        ".local/share/gardien/quarantaine",
        ".local/share/sentinel/quarantaine",
        ".local/share/netscan/quarantaine",
        ".snapshots",
        ".Trash",
        // macOS : caches et conteneurs d'apps (énormes), quarantaine de Gardien.
        "Library/Caches",
        "Library/Containers",
        "Library/Application Support/gardien/quarantaine",
        "Library/Application Support/sentinel/quarantaine",
    ];
    let exclusions: &[&str] = if matches!(portee, Portee::Dossier(_)) {
        &[
            ".local/share/gardien/quarantaine",
            ".local/share/sentinel/quarantaine",
            ".local/share/netscan/quarantaine",
            "Library/Application Support/gardien/quarantaine",
            "Library/Application Support/sentinel/quarantaine",
        ]
    } else {
        &tout
    };
    let mut cmd = Command::new(outil_clamav("clamscan"));
    // Le bilan final (fichiers analysés, infectés, erreurs) sert à juger si l'analyse a vraiment eu lieu.
    cmd.args(["-r", "-i", "--max-filesize=200M", "--max-scansize=400M"]);
    for e in exclusions {
        cmd.arg(format!("--exclude-dir={}", regex_echappe(e)));
    }
    cmd.args(&cibles);
    if let Some((chemin, _)) = &liste_tmp {
        cmd.arg(format!("--file-list={}", chemin.display()));
    }
    let mut decrites: Vec<String> = cibles.iter().map(|p| chemin_affichable(p)).collect();
    if let Some((_, n)) = &liste_tmp {
        decrites.push(trf!(
            "/tmp ({n} fichier(s) de moins de 7 jours)",
            "/tmp ({n} file(s) under 7 days old)"
        ));
    }
    trp!(
        "  {GRIS}Moteur : ClamAV. Analyse de : {}{RESET}",
        "  {GRIS}Engine: ClamAV. Scanning: {}{RESET}",
        decrites.join(", ")
    );
    trp!(
        "  {GRIS}Cela peut prendre de quelques secondes à plusieurs minutes…{RESET}",
        "  {GRIS}This can take from a few seconds to several minutes…{RESET}"
    );

    let sortie = cmd.output();
    if let Some((chemin, _)) = &liste_tmp {
        let _ = std::fs::remove_file(chemin);
    }
    let Ok(sortie) = sortie else {
        trp!("  Impossible de lancer clamscan.", "  Could not start clamscan.");
        return;
    };
    let Some(bilan) = lire_resultat(sortie.status.code(), &String::from_utf8_lossy(&sortie.stdout)) else {
        let erreur = String::from_utf8_lossy(&sortie.stderr);
        trp!(
            "  {}✖ L'analyse a échoué : le résultat n'est pas fiable.{RESET}",
            "  {}✖ The scan failed: the result is not reliable.{RESET}",
            couleur(Niveau::Eleve)
        );
        // Les erreurs de ClamAV citent souvent un fichier, au nom choisi par n'importe qui.
        for l in erreur.lines().filter(|l| l.contains("ERROR")).take(5) {
            println!("    {GRIS}{}{RESET}", affichable(l));
        }
        return;
    };

    let illisibles = if bilan.illisibles > 0 {
        trf!(
            " ; {} élément(s) illisible(s) sans droits root, ignoré(s)",
            "; {} item(s) unreadable without root rights, skipped",
            bilan.illisibles
        )
    } else {
        String::new()
    };
    trp!(
        "  {GRIS}{} fichier(s) analysé(s){illisibles}.{RESET}",
        "  {GRIS}{} file(s) scanned{illisibles}.{RESET}",
        bilan.analyses
    );
    // Ceinture et bretelles : un même fichier n'est proposé qu'une fois (sinon la 2e mise en quarantaine échoue).
    let mut infectes = bilan.infectes;
    let mut vus = std::collections::HashSet::new();
    infectes.retain(|(f, _)| vus.insert(f.clone()));
    if infectes.is_empty() {
        trp!(
            "  {VERT}✔ Aucun malware trouvé.{RESET}",
            "  {VERT}✔ No malware found.{RESET}"
        );
        return;
    }
    // Le chemin reste tel quel pour la quarantaine ; montré, il est rendu inoffensif.
    for (f, m) in &infectes {
        println!("  {}✖ {m}{RESET}  {}", couleur(Niveau::Critique), affichable(f));
    }
    trp!(
        "\n  {} fichier(s) suspect(s).",
        "\n  {} suspicious file(s).",
        infectes.len()
    );
    let rep = demander(tr!(
        "  [q]uarantaine (recommandé, réversible) / [s]upprimer / [r]ien : ",
        "  [q]uarantine (recommended, reversible) / [d]elete / [n]othing: "
    ))
    .to_lowercase();
    for (f, detection) in &infectes {
        let chemin = std::path::Path::new(f);
        let resultat = match rep.as_str() {
            "q" => crate::protection::quarantaine::isoler(chemin, detection).map(|_| ()),
            "s" | "d" => std::fs::remove_file(chemin),
            _ => continue,
        };
        let f = affichable(f);
        match resultat {
            Ok(()) => println!("  {VERT}✔{RESET} {f}"),
            Err(e) => trp!(
                "  ✖ {f} : {e} (fichier système ? relancer avec sudo)",
                "  ✖ {f}: {e} (system file? run again with sudo)"
            ),
        }
    }
    if !matches!(rep.as_str(), "q" | "s" | "d") {
        trp!(
            "  Rien n'a été fait : les fichiers restent à leur place.",
            "  Nothing was done: the files stay where they are."
        );
    }
    if rep == "q" {
        trp!(
            "  {GRIS}Quarantaine : {} ; un fichier se remet à sa place par le menu Antivirus et protection › Quarantaine.{RESET}",
            "  {GRIS}Quarantine: {}; a file goes back to its place through the menu Antivirus and protection › Quarantine.{RESET}",
            crate::protection::quarantaine::dossier().display()
        );
    }
}

/// Fichiers modifiés depuis moins de `jours` jours sous `dossier`, au plus `max` (les dossiers illisibles sont
/// sautés sans bruit).
#[cfg(unix)]
fn fichiers_recents(dossier: &std::path::Path, jours: u64, max: usize) -> Vec<PathBuf> {
    let limite = std::time::SystemTime::now() - std::time::Duration::from_secs(jours * 86_400);
    let mut trouves = Vec::new();
    let mut a_voir = vec![dossier.to_path_buf()];
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            if trouves.len() >= max {
                return trouves;
            }
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                a_voir.push(e.path());
            } else if m.is_file() && m.modified().is_ok_and(|t| t >= limite) {
                trouves.push(e.path());
            }
        }
    }
    trouves
}

/// Dossiers à analyser sans recouvrement : un ~/Desktop qui pointe vers ~/Bureau, ou un dossier contenu dans un
/// autre, faisait analyser deux fois les mêmes fichiers ; un fichier infecté était alors signalé deux fois et sa
/// seconde mise en quarantaine échouait (« fichier système ? »). Vu en test.
#[cfg(unix)]
fn sans_doublons(cibles: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut reels: Vec<PathBuf> = cibles.into_iter().map(|p| p.canonicalize().unwrap_or(p)).collect();
    // Trié, un dossier parent passe avant ce qu'il contient.
    reels.sort();
    reels.dedup();
    let mut garde: Vec<PathBuf> = Vec::new();
    for p in reels {
        if !garde.iter().any(|g| p.starts_with(g)) {
            garde.push(p);
        }
    }
    garde
}

/// Bilan d'une analyse ClamAV qui a vraiment eu lieu.
#[cfg(unix)]
#[derive(Debug, PartialEq)]
struct Bilan {
    infectes: Vec<(String, String)>,
    analyses: u64,
    /// Fichiers illisibles sans droits root (ignorés) : ClamAV renvoie alors le code 2 même si tout s'est bien passé.
    illisibles: u64,
}

/// Résultat de clamscan, `None` si l'analyse n'a pas eu lieu (base absente, plantage…).
/// On se fie au bilan final plutôt qu'au code de retour : sur un Linux normal, quelques dossiers de /tmp
/// appartiennent à root, et ClamAV répond « erreur » (code 2) après avoir analysé tout le reste (vu en réel).
#[cfg(unix)]
fn lire_resultat(code: Option<i32>, sortie: &str) -> Option<Bilan> {
    // Le chemin reste tel quel : c'est lui qu'on isole ou qu'on efface. Le nom de la menace est seulement montré.
    let infectes: Vec<(String, String)> = sortie
        .lines()
        .filter_map(|l| {
            let (fichier, menace) = l.strip_suffix(" FOUND")?.rsplit_once(": ")?;
            Some((fichier.to_string(), affichable(menace)))
        })
        .collect();
    let champ = |nom: &str| {
        sortie
            .lines()
            .find_map(|l| l.strip_prefix(nom)?.trim().parse::<u64>().ok())
    };
    let analyses = champ("Scanned files:")?;
    let annonces = champ("Infected files:")?;
    let illisibles = champ("Total errors:").unwrap_or(0);
    // Le nombre de fichiers infectés annoncé doit correspondre aux lignes lues, sinon on ne sait pas quoi isoler.
    if !matches!(code, Some(0..=2)) || annonces != infectes.len() as u64 {
        return None;
    }
    Some(Bilan {
        infectes,
        analyses,
        illisibles,
    })
}

/// --exclude-dir attend une expression régulière : on échappe les points.
#[cfg(unix)]
fn regex_echappe(dossier: &str) -> String {
    // Le chemin du dossier n'a pas de « / » final : on accepte la fin de chaîne.
    format!("/{}(/|$)", dossier.replace('.', "\\."))
}

// ───────────────────────────── Démarrage automatique ─────────────────────────────

fn demarrage() {
    titre(tr!(
        "Programmes lancés au démarrage (à vérifier)",
        "Programs started at boot (to check)"
    ));
    // Chaque entrée est écrite par qui l'a posée (le programme qui veut se faire relancer) : montrée rendue inoffensive.
    let mut entrees: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let h = home();
        for d in [".config/autostart", ".config/systemd/user"] {
            for f in std::fs::read_dir(h.join(d)).into_iter().flatten().flatten() {
                if f.path().is_file() {
                    entrees.push(chemin_affichable(&f.path()));
                }
            }
        }
        if let Ok(o) = Command::new("crontab").arg("-l").output() {
            for l in String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            {
                let l = affichable(l);
                entrees.push(trf!("crontab : {l}", "crontab: {l}"));
            }
        }
        for f in std::fs::read_dir("/etc/systemd/system").into_iter().flatten().flatten() {
            let p = f.path();
            // Services ajoutés à la main (pas par un paquet) : endroit classique pour une persistance root.
            if p.extension().is_some_and(|e| e == "service") && p.is_file() && !p.is_symlink() {
                let possede = crate::machine::linux::Paquets::detecter().is_none_or(|g| g.possede(&p));
                if !possede {
                    entrees.push(trf!(
                        "{} (service système hors paquet)",
                        "{} (system service not from a package)",
                        chemin_affichable(&p)
                    ));
                }
            }
        }
    }

    // macOS : agents et démons de launchd ajoutés par des programmes (ceux d'Apple sont dans /System).
    #[cfg(target_os = "macos")]
    {
        let h = home();
        for d in [
            h.join("Library/LaunchAgents"),
            "/Library/LaunchAgents".into(),
            "/Library/LaunchDaemons".into(),
        ] {
            for f in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                if f.path().extension().is_some_and(|e| e == "plist") {
                    entrees.push(chemin_affichable(&f.path()));
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use crate::machine::windows::ps;
        let script = tr!(
            "Get-CimInstance Win32_StartupCommand | ForEach-Object { \"$($_.Name) — $($_.Command)\" }; \
                      Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | \
                      ForEach-Object { \"tâche planifiée : $($_.TaskName) — $($_.Actions.Execute)\" }",
            "Get-CimInstance Win32_StartupCommand | ForEach-Object { \"$($_.Name) — $($_.Command)\" }; \
                      Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | \
                      ForEach-Object { \"scheduled task: $($_.TaskName) — $($_.Actions.Execute)\" }"
        );
        entrees.extend(ps(script).unwrap_or_default().lines().map(affichable));
    }

    if entrees.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Rien de particulier.",
            "  {VERT}✔{RESET} Nothing special."
        );
    }
    for e in entrees {
        println!("  • {e}");
    }
    trp!(
        "  {GRIS}Si tu ne reconnais pas une entrée, renseigne-toi avant de la supprimer.{RESET}",
        "  {GRIS}If you do not recognize an entry, look it up before deleting it.{RESET}"
    );
    afficher_aligne(
        "  ",
        tr!(
            "Pour qu'un programme ne se lance plus à l'ouverture de session, sans le désinstaller et de façon annulable : gardien demarrage (ou Cette machine › Pourquoi c'est lent ?).",
            "To stop a program from starting at login, without uninstalling it and in an undoable way: gardien startup (or This machine › Why is it slow?)."
        ),
        2,
        GRIS,
    );
}

#[cfg(test)]
mod tests_cle {
    use super::*;

    #[test]
    fn volumes_de_lsblk() {
        let texte = "RM=\"0\" HOTPLUG=\"0\" LABEL=\"\" SIZE=\"931,5G\" MOUNTPOINT=\"/\"\n\
                     RM=\"1\" HOTPLUG=\"1\" LABEL=\"\" SIZE=\"28,9G\" MOUNTPOINT=\"\"\n\
                     RM=\"1\" HOTPLUG=\"1\" LABEL=\"MA\\x20CLE\" SIZE=\"28,8G\" MOUNTPOINT=\"/run/media/alice/MA\\x20CLE\"\n\
                     RM=\"0\" HOTPLUG=\"1\" LABEL=\"\" SIZE=\"1T\" MOUNTPOINT=\"/run/media/alice/disque\"\n";
        let v = lire_lsblk(texte);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].0, PathBuf::from("/run/media/alice/MA CLE"));
        assert_eq!(v[0].1, "MA CLE · 28,8G");
        assert_eq!(v[1].1, "1T");
        // L'étiquette d'une clé USB est choisie par qui l'a préparée : piégée, elle arrive inoffensive.
        let piege = "RM=\"1\" HOTPLUG=\"1\" LABEL=\"CLE\x1b]52;c;eA==\x07\u{202e}\" SIZE=\"8G\" MOUNTPOINT=\"/run/media/alice/CLE\"\n";
        assert_eq!(lire_lsblk(piege)[0].1, "CLE�]52;c;eA==�� · 8G");
    }

    #[test]
    fn pieges_de_cle() {
        let e = |l: &[(&str, bool)]| l.iter().map(|(n, d)| ((*n).to_string(), *d)).collect::<Vec<_>>();
        // Ver de raccourcis : dossier caché + raccourci du même nom, autorun, script.
        let s = signes_de_ver(&e(&[
            ("Photos", true),
            ("Photos.lnk", false),
            ("autorun.inf", false),
            ("x.vbs", false),
            ("notes.txt", false),
        ]));
        assert_eq!(s.len(), 3);
        assert_eq!(s.iter().filter(|(n, _)| *n == Niveau::Eleve).count(), 2);
        // Clé normale.
        assert_eq!(
            signes_de_ver(&e(&[
                ("Photos", true),
                ("cv.pdf", false),
                ("jeu.lnk", false),
                ("a", false),
                ("b", false)
            ])),
            vec![]
        );
        // Clé Gardien : son autorun et son lanceur sont attendus.
        assert_eq!(
            signes_de_ver(&e(&[("gardien.cle", false), ("autorun.inf", false)])),
            vec![]
        );
    }

    #[test]
    fn menaces_de_defender() {
        let sortie = "Scan starting...\nScan finished.\nScanning C:\\Users\\alice\\Downloads\\x.exe found 1 threats.\n\n\
                      ----------------------------- Threat information ------------------------------\n\
                      Threat                  : Virus:DOS/EICAR_Test_File\n\
                      Resources               : 1 total\n";
        assert_eq!(menaces_mpcmdrun(sortie), ["Virus:DOS/EICAR_Test_File"]);
        // Sortie inattendue : la menace est quand même dite.
        assert_eq!(menaces_mpcmdrun("").len(), 1);
        assert_eq!(
            menaces_mpcmdrun("Threat                  : Trojan\x1b[2K\rFaux\u{202e}\n"),
            ["Trojan�[2K�Faux�"]
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn resultat_clamscan() {
        let bilan = |infectes: u64, erreurs: u64| {
            format!(
                "\n----------- SCAN SUMMARY -----------\nScanned files: 12683\nInfected files: {infectes}\nTotal errors: {erreurs}\n"
            )
        };
        // Cas réel : 0 infecté, 7 dossiers de /tmp illisibles, code 2 → analyse valable.
        let r = lire_resultat(Some(2), &bilan(0, 7)).unwrap();
        assert_eq!((r.infectes.len(), r.analyses, r.illisibles), (0, 12683, 7));
        let deux = format!(
            "/home/x/Téléchargements/eicar.com: Eicar-Test-Signature FOUND\n/tmp/a b.exe: Win.Trojan.Agent-123 FOUND\n{}",
            bilan(2, 0)
        );
        let r = lire_resultat(Some(1), &deux).unwrap();
        assert_eq!(
            r.infectes[1],
            ("/tmp/a b.exe".to_string(), "Win.Trojan.Agent-123".to_string())
        );
        // Pas de bilan (base absente, plantage) : jamais « aucun malware ».
        assert!(lire_resultat(Some(2), "ERROR: Can't open database").is_none());
        assert!(lire_resultat(None, &bilan(0, 0)).is_none());
        // Infectés annoncés mais lignes illisibles : pas fiable.
        assert!(lire_resultat(Some(1), &bilan(1, 0)).is_none());
    }

    #[test]
    fn dossiers_analyses_une_seule_fois() {
        let base = std::env::temp_dir().join(format!("gardien-cibles-{}", std::process::id()));
        let bureau = base.join("Bureau");
        std::fs::create_dir_all(bureau.join("sous")).unwrap();
        std::os::unix::fs::symlink(&bureau, base.join("Desktop")).unwrap();
        let reel = bureau.canonicalize().unwrap();
        // Desktop → Bureau, et un sous-dossier de Bureau : il ne reste que Bureau.
        assert_eq!(
            sans_doublons(vec![base.join("Desktop"), bureau.clone(), bureau.join("sous")]),
            vec![reel]
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn exclusions_en_expression_reguliere() {
        assert_eq!(regex_echappe(".steam"), "/\\.steam(/|$)");
    }
}

/// Propriétés de la lecture de lsblk : rien ne plante, quelle que soit la sortie ; une clé amovible bien décrite
/// redonne son point de montage et son étiquette, rendue prête à montrer.
#[cfg(test)]
mod proprietes {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lsblk_sans_plantage(t in prop::collection::vec(prop_oneof![any::<String>(), "([A-Z]+=\"[ -~\u{1b}é]{0,12}\" ?){0,6}"], 0..8)) {
            for (point, nom) in lire_lsblk(&t.join("\n")) {
                prop_assert!(point.is_absolute());
                prop_assert!(!crate::ui::contient_un_piege(&nom));
            }
        }

        #[test]
        fn lsblk_redonne_ses_valeurs(etiquette in "[A-Za-z0-9_-]{1,11}", taille in "[0-9]{1,3}(,[0-9])?[GM]", amovible in prop_oneof![Just("RM=\"1\" HOTPLUG=\"0\""), Just("RM=\"0\" HOTPLUG=\"1\"")]) {
            let ligne = format!("{amovible} LABEL=\"{etiquette}\" SIZE=\"{taille}\" MOUNTPOINT=\"/run/media/alice/{etiquette}\"\n");
            let l = lire_lsblk(&ligne);
            prop_assert_eq!(l.len(), 1);
            prop_assert_eq!(&l[0].0, &PathBuf::from(format!("/run/media/alice/{etiquette}")));
            prop_assert_eq!(&l[0].1, &format!("{etiquette} · {taille}"));
            // Ni amovible ni branchée à chaud : pas une clé.
            prop_assert!(lire_lsblk(&ligne.replace("=\"1\"", "=\"0\"")).is_empty());
        }
    }
}
