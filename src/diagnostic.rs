//! Diagnostic de l'ordinateur, le premier réflexe d'un dépannage : matériel, système, et surtout les problèmes
//! récents (erreurs du journal et programmes plantés sous Linux ; écrans bleus, arrêts brutaux et programmes plantés
//! sous Windows). Lecture seule. Une copie texte est enregistrée pour l'envoyer ou la garder.

use std::fmt::Write;

use crate::risk::Niveau;
use crate::ui::*;

/// Une ligne du diagnostic : libellé, valeur, et un niveau quand la ligne signale un problème.
struct Ligne {
    libelle: String,
    valeur: String,
    niveau: Option<Niveau>,
}

fn ligne(libelle: &str, valeur: impl Into<String>) -> Ligne {
    Ligne {
        libelle: libelle.to_string(),
        valeur: valeur.into(),
        niveau: None,
    }
}

fn alerte(libelle: &str, valeur: impl Into<String>, niveau: Niveau) -> Ligne {
    Ligne {
        libelle: libelle.to_string(),
        valeur: valeur.into(),
        niveau: Some(niveau),
    }
}

type Section = (String, Vec<Ligne>);

fn duree(secondes: u64) -> String {
    let (j, h, m) = (secondes / 86_400, secondes % 86_400 / 3600, secondes % 3600 / 60);
    match j {
        0 => format!("{h} h {m:02}"),
        _ => trf!("{j} j {h} h", "{j} d {h} h"),
    }
}

fn go(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let g = octets as f64 / f64::from(1u32 << 30);
    if g >= 1000.0 {
        trf!("{} To", "{} TB", crate::langue::decimal(g / 1024.0, 1))
    } else {
        trf!("{} Go", "{} GB", crate::langue::decimal(g, 1))
    }
}

/// Sources qui reviennent le plus dans une liste : « NetworkManager (12), kernel (5) ».
fn plus_frequentes(sources: &[String], max: usize) -> String {
    let mut comptes: Vec<(String, usize)> = Vec::new();
    for s in sources {
        match comptes.iter_mut().find(|(n, _)| n == s) {
            Some((_, c)) => *c += 1,
            None => comptes.push((s.clone(), 1)),
        }
    }
    comptes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    comptes
        .iter()
        .take(max)
        .map(|(n, c)| format!("{n} ({c})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// La ligne des programmes plantés en 7 jours, la même sur les trois systèmes.
fn programmes_plantes(plantages: &[String]) -> Ligne {
    if plantages.is_empty() {
        ligne(
            tr!("Programmes plantés", "Crashed programs"),
            tr!("aucun en 7 jours", "none in 7 days"),
        )
    } else {
        alerte(
            tr!("Programmes plantés", "Crashed programs"),
            trf!(
                "{} en 7 jours : {}",
                "{} in 7 days: {}",
                plantages.len(),
                plus_frequentes(plantages, 5)
            ),
            Niveau::Moyen,
        )
    }
}

/// Les trois sections du diagnostic, dans leur ordre.
fn trois_sections(systeme: Vec<Ligne>, materiel: Vec<Ligne>, problemes: Vec<Ligne>) -> Vec<Section> {
    vec![
        (tr!("SYSTÈME", "SYSTEM").into(), systeme),
        (tr!("MATÉRIEL", "HARDWARE").into(), materiel),
        (tr!("PROBLÈMES RÉCENTS", "RECENT PROBLEMS").into(), problemes),
    ]
}

#[cfg(target_os = "linux")]
mod systeme {
    use super::{Ligne, Niveau, Section, alerte, duree, go, ligne, plus_frequentes};
    use crate::ui::affichable;
    use crate::{tr, trf};

    fn lire(chemin: &str) -> Option<String> {
        std::fs::read_to_string(chemin)
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    }

    fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
        let r = crate::commande::lancer(std::process::Command::new(cmd).args(args), 20)?;
        (r.code == Some(0)).then_some(r.sortie)
    }

    fn valeur_meminfo(texte: &str, cle: &str) -> Option<u64> {
        texte
            .lines()
            .find(|l| l.starts_with(cle))?
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()
            .map(|ko| ko * 1024)
    }

    /// Version du pilote dans /proc/driver/nvidia/version (« … Kernel Module for x86_64  610.57.04  Release … »).
    pub(super) fn version_nvidia(texte: &str) -> Option<String> {
        texte
            .split_whitespace()
            .find(|m| m.contains('.') && m.chars().all(|c| c.is_ascii_digit() || c == '.'))
            .map(str::to_string)
    }

    /// Valeur d'une colonne d'une ligne de `lsblk -P` (`NAME="sda" SIZE="31004295168" …`). Le modèle vient du disque
    /// lui-même (une clé USB dit ce qu'elle veut) : chaque valeur est lue prête à montrer, comme tout ce que ce
    /// diagnostic lit du système.
    pub(super) fn champ_lsblk(ligne: &str, cle: &str) -> Option<String> {
        let debut = format!("{cle}=\"");
        let reste = &ligne[ligne.find(&debut)? + debut.len()..];
        Some(affichable(reste[..reste.find('"')?].trim()))
    }

    /// Le journal du système se lit-il ? Sans être root ni dans les groupes adm, systemd-journal ou wheel,
    /// journalctl ne montre que les messages de la session, sans le dire (-q) : « aucune erreur » serait faux.
    fn journal_systeme_lisible() -> bool {
        ["/var/log/journal", "/run/log/journal"].iter().any(|d| {
            std::fs::read_dir(d)
                .into_iter()
                .flatten()
                .flatten()
                .any(|e| std::fs::File::open(e.path().join("system.journal")).is_ok())
        })
    }

    /// Source d'une ligne du journal (« Oct 17 15:29:32 portable NetworkManager[1334]: … » → « NetworkManager »). Une
    /// ligne en retrait continue l'entrée d'avant (la pile d'un programme planté) : elle n'en est pas une autre. Tout
    /// programme choisit le nom sous lequel il écrit au journal : lu prêt à montrer.
    pub(super) fn source_journal(l: &str) -> Option<String> {
        if l.starts_with(char::is_whitespace) {
            return None;
        }
        let apres_hote = l.splitn(5, ' ').nth(4)?;
        let source = apres_hote.split(':').next()?;
        Some(affichable(source.split('[').next()?.trim())).filter(|s| !s.is_empty())
    }

    /// Cartes graphiques de `lspci -mm` (« 01:00.0 "VGA compatible controller" "NVIDIA Corporation" "GB205 …" … ») :
    /// fabricant et modèle. Classes VGA, 3D et Display, comme la fiche : bien des cartes AMD de portable sont des
    /// « Display controller ».
    pub(super) fn cartes_lspci(texte: &str) -> Vec<String> {
        texte
            .lines()
            .filter_map(|l| {
                let champs: Vec<&str> = l.split('"').collect();
                let classe = champs.get(1).copied().unwrap_or_default();
                ["VGA", "3D", "Display"].iter().any(|c| classe.contains(c)).then(|| {
                    let nom = format!("{} {}", champs.get(3).unwrap_or(&""), champs.get(5).unwrap_or(&""));
                    affichable(nom.trim())
                })
            })
            .collect()
    }

    /// Programmes plantés d'après `coredumpctl list` : le nom du programme, à la fin du chemin de la colonne EXE. Ce
    /// chemin peut contenir des espaces (« …/common/Hollow Knight/hollow_knight ») : il va du premier mot qui
    /// commence par « / » jusqu'à la colonne SIZE, la dernière quand l'en-tête l'annonce (systemd 248 et plus).
    pub(super) fn programmes_coredumpctl(texte: &str) -> Vec<String> {
        let taille_en_fin = texte
            .lines()
            .find(|l| l.split_whitespace().next() == Some("TIME"))
            .is_some_and(|entete| entete.split_whitespace().any(|c| c == "SIZE"));
        texte
            .lines()
            .filter_map(|l| {
                let exe = l[l.find(" /")? + 1..].trim_end();
                let exe = match exe.rsplit_once(char::is_whitespace) {
                    Some((chemin, _)) if taille_en_fin => chemin.trim_end(),
                    _ => exe,
                };
                Some(affichable(exe.rsplit('/').next().unwrap_or(exe)))
            })
            .collect()
    }

    pub fn sections() -> Vec<Section> {
        let mut systeme = Vec::new();
        let os = lire("/etc/os-release")
            .and_then(|t| {
                t.lines()
                    .find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| affichable(v.trim_matches('"'))))
            })
            .unwrap_or_else(|| "Linux".into());
        // Une valeur d'une ligne lue dans /proc ou /sys, prête à montrer.
        let valeur = |chemin: &str| lire(chemin).map(|v| affichable(&v));
        systeme.push(ligne(
            tr!("Système", "System"),
            trf!(
                "{os} · noyau {}",
                "{os} · kernel {}",
                valeur("/proc/sys/kernel/osrelease").unwrap_or_default()
            ),
        ));
        systeme.push(ligne(
            tr!("Nom", "Name"),
            valeur("/proc/sys/kernel/hostname").unwrap_or_default(),
        ));
        let modele = [
            valeur("/sys/class/dmi/id/sys_vendor"),
            valeur("/sys/class/dmi/id/board_name"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
        if !modele.is_empty() {
            let bios = valeur("/sys/class/dmi/id/bios_version")
                .map(|b| format!(" · BIOS {b}"))
                .unwrap_or_default();
            systeme.push(ligne(tr!("Modèle", "Model"), format!("{modele}{bios}")));
        }
        if let Some(s) = lire("/proc/uptime").and_then(|t| t.split('.').next().and_then(|s| s.parse::<u64>().ok())) {
            systeme.push(ligne(tr!("Allumé depuis", "Up for"), duree(s)));
        }

        let mut materiel = Vec::new();
        let cpuinfo = lire("/proc/cpuinfo").unwrap_or_default();
        if let Some(cpu) = cpuinfo
            .lines()
            .find_map(|l| l.strip_prefix("model name"))
            .and_then(|l| l.split_once(':'))
        {
            let fils = std::thread::available_parallelism().map_or(0, std::num::NonZero::get);
            materiel.push(ligne(
                tr!("Processeur", "Processor"),
                trf!("{} ({fils} fils)", "{} ({fils} threads)", affichable(cpu.1.trim())),
            ));
        }
        let meminfo = lire("/proc/meminfo").unwrap_or_default();
        if let (Some(total), Some(dispo)) = (
            valeur_meminfo(&meminfo, "MemTotal:"),
            valeur_meminfo(&meminfo, "MemAvailable:"),
        ) {
            materiel.push(ligne(
                tr!("Mémoire", "Memory"),
                trf!("{} ({} libres)", "{} ({} free)", go(total), go(dispo)),
            ));
        }
        for nom in cartes_lspci(&sortie("lspci", &["-mm"]).unwrap_or_default()) {
            let pilote = lire("/proc/driver/nvidia/version")
                .filter(|_| nom.contains("NVIDIA"))
                .and_then(|v| version_nvidia(&v))
                .map(|v| trf!(" · pilote NVIDIA {v}", " · NVIDIA driver {v}"))
                .unwrap_or_default();
            materiel.push(ligne(tr!("Carte graphique", "Graphics card"), format!("{nom}{pilote}")));
        }
        for l in sortie("lsblk", &["-dnbP", "-o", "NAME,SIZE,ROTA,TYPE,TRAN,MODEL"])
            .unwrap_or_default()
            .lines()
        {
            let champ = |cle: &str| champ_lsblk(l, cle).unwrap_or_default();
            let nom = champ("NAME");
            if champ("TYPE") != "disk" || nom.starts_with("zram") || nom.starts_with("loop") {
                continue;
            }
            // Une clé USB se déclare souvent « rotative » : le transport dit la vérité.
            let sorte = match (champ("TRAN").as_str(), champ("ROTA").as_str()) {
                ("usb", _) => tr!("clé ou disque USB", "USB stick or drive"),
                (_, "1") => tr!("disque dur", "hard drive"),
                _ => "SSD",
            };
            materiel.push(ligne(
                tr!("Disque", "Disk"),
                format!(
                    "{nom} · {} · {sorte} · {}",
                    go(champ("SIZE").parse().unwrap_or(0)),
                    champ("MODEL")
                ),
            ));
        }

        let mut problemes: Vec<Ligne> = Vec::new();
        let journal = journal_systeme_lisible()
            .then(|| sortie("journalctl", &["-b", "-p", "err", "-q", "--no-pager", "-o", "short"]))
            .flatten();
        match journal {
            Some(j) => {
                let sources: Vec<String> = j.lines().filter_map(source_journal).collect();
                if sources.is_empty() {
                    problemes.push(ligne(
                        tr!("Erreurs du journal", "Journal errors"),
                        tr!("aucune depuis le démarrage", "none since boot"),
                    ));
                } else {
                    let niveau = if sources.len() > 200 {
                        Niveau::Moyen
                    } else {
                        Niveau::Info
                    };
                    problemes.push(alerte(
                        tr!("Erreurs du journal", "Journal errors"),
                        trf!(
                            "{} depuis le démarrage : {}",
                            "{} since boot: {}",
                            sources.len(),
                            plus_frequentes(&sources, 5)
                        ),
                        niveau,
                    ));
                }
            }
            None => problemes.push(ligne(
                tr!("Erreurs du journal", "Journal errors"),
                tr!("journal illisible sans droits", "journal unreadable without rights"),
            )),
        }
        let plantages = programmes_coredumpctl(
            &sortie("coredumpctl", &["list", "--no-pager", "-q", "--since=-7d"]).unwrap_or_default(),
        );
        problemes.push(super::programmes_plantes(&plantages));
        let en_echec: Vec<String> = sortie("systemctl", &["--failed", "--no-legend", "--plain"])
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_whitespace().next().map(affichable))
            .collect();
        problemes.push(if en_echec.is_empty() {
            ligne(tr!("Services en échec", "Failed services"), tr!("aucun", "none"))
        } else {
            alerte(
                tr!("Services en échec", "Failed services"),
                en_echec.join(", "),
                Niveau::Moyen,
            )
        });
        super::trois_sections(systeme, materiel, problemes)
    }
}

#[cfg(target_os = "macos")]
mod systeme {
    use super::{Niveau, Section, alerte, duree, go, ligne};
    use crate::ui::affichable;
    use crate::{tr, trf};

    fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
        let r = crate::commande::lancer(std::process::Command::new(cmd).args(args), 30)?;
        (r.code == Some(0)).then(|| r.sortie.trim().to_string())
    }

    /// Valeur d'une ligne « Clé: valeur » (system_profiler, diskutil info), espaces de tête ignorés, prête à montrer
    /// (un disque branché dit son nom lui-même), comme tout ce que ce diagnostic lit du système.
    pub(super) fn valeur(texte: &str, cle: &str) -> Option<String> {
        texte
            .lines()
            .find_map(|l| l.trim().strip_prefix(cle)?.trim().strip_prefix(':'))
            .map(|v| affichable(v.trim()))
            .filter(|v| !v.is_empty())
    }

    /// Secondes depuis le démarrage, d'après `sysctl -n kern.boottime` : « { sec = 1715000000, usec = 0 } … ».
    pub(super) fn depuis_demarrage(boottime: &str, maintenant: u64) -> Option<u64> {
        let sec: u64 = boottime
            .split_once("sec = ")?
            .1
            .split(',')
            .next()?
            .trim()
            .parse()
            .ok()?;
        maintenant.checked_sub(sec)
    }

    /// Rapports de plantage récents (moins de `jours`) : nom du programme avant la date (« Safari-2024-05-01-… »).
    fn rapports(dossiers: &[std::path::PathBuf], extensions: &[&str], jours: u64) -> Vec<String> {
        let limite = std::time::Duration::from_secs(jours * 86_400);
        dossiers
            .iter()
            .filter_map(|d| std::fs::read_dir(d).ok())
            .flatten()
            .flatten()
            .filter(|f| f.path().extension().is_some_and(|e| extensions.iter().any(|x| e == *x)))
            .filter(|f| {
                f.metadata()
                    .and_then(|m| m.modified())
                    .is_ok_and(|m| m.elapsed().is_ok_and(|e| e < limite))
            })
            .map(|f| {
                let nom = f.file_name().to_string_lossy().into_owned();
                // Le nom s'arrête au premier « -2 » d'une date (« Google Chrome Helper-2024-… »).
                affichable(nom.split_once("-20").map_or(nom.as_str(), |(n, _)| n))
            })
            .collect()
    }

    pub fn sections() -> Vec<Section> {
        let mut systeme = Vec::new();
        // Une valeur d'une ligne, prête à montrer.
        let valeur_seule = |cmd: &str, args: &[&str]| sortie(cmd, args).map(|v| affichable(&v));
        let version = [
            valeur_seule("sw_vers", &["-productName"]),
            valeur_seule("sw_vers", &["-productVersion"]),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
        let build = valeur_seule("sw_vers", &["-buildVersion"]).unwrap_or_default();
        systeme.push(ligne(
            tr!("Système", "System"),
            format!("{version} ({build}) · {}", crate::machine::macos::architecture()),
        ));
        systeme.push(ligne(
            tr!("Nom", "Name"),
            valeur_seule("scutil", &["--get", "ComputerName"]).unwrap_or_default(),
        ));
        let materiel_txt = sortie("system_profiler", &["SPHardwareDataType"]).unwrap_or_default();
        let modele = [
            valeur(&materiel_txt, "Model Name"),
            valeur(&materiel_txt, "Model Identifier"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
        if !modele.is_empty() {
            systeme.push(ligne(tr!("Modèle", "Model"), modele));
        }
        let maintenant = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if let Some(s) = sortie("sysctl", &["-n", "kern.boottime"])
            .as_deref()
            .and_then(|b| depuis_demarrage(b, maintenant))
        {
            systeme.push(ligne(tr!("Allumé depuis", "Up for"), duree(s)));
        }

        let mut materiel = Vec::new();
        if let Some(cpu) = valeur_seule("sysctl", &["-n", "machdep.cpu.brand_string"]) {
            let fils = std::thread::available_parallelism().map_or(0, std::num::NonZero::get);
            materiel.push(ligne(
                tr!("Processeur", "Processor"),
                trf!("{cpu} ({fils} cœurs)", "{cpu} ({fils} cores)"),
            ));
        }
        if let Some(total) = sortie("sysctl", &["-n", "hw.memsize"]).and_then(|t| t.parse::<u64>().ok()) {
            materiel.push(ligne(tr!("Mémoire", "Memory"), go(total)));
        }
        let ecrans = sortie("system_profiler", &["SPDisplaysDataType"]).unwrap_or_default();
        if let Some(puce) = valeur(&ecrans, "Chipset Model") {
            materiel.push(ligne(tr!("Carte graphique", "Graphics card"), puce));
        }
        for disque in sortie("diskutil", &["list", "internal", "physical"])
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.strip_prefix("/dev/")?.split_whitespace().next().map(str::to_string))
        {
            let info = sortie("diskutil", &["info", &disque]).unwrap_or_default();
            let taille = valeur(&info, "Disk Size")
                .map(|t| t.split(" (").next().unwrap_or(&t).to_string())
                .unwrap_or_default();
            let sorte = if valeur(&info, "Solid State").as_deref() == Some("Yes") {
                "SSD"
            } else {
                tr!("disque dur", "hard drive")
            };
            materiel.push(ligne(
                tr!("Disque", "Disk"),
                format!(
                    "{disque} · {taille} · {sorte} · {}",
                    valeur(&info, "Device / Media Name").unwrap_or_default()
                ),
            ));
        }

        let maison = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        let dossiers = [
            maison.join("Library/Logs/DiagnosticReports"),
            std::path::PathBuf::from("/Library/Logs/DiagnosticReports"),
        ];
        let mut problemes = Vec::new();
        let paniques = rapports(&dossiers, &["panic"], 30);
        problemes.push(if paniques.is_empty() {
            ligne(
                tr!("Redémarrages brutaux", "Kernel panics"),
                tr!("aucun en 30 jours", "none in 30 days"),
            )
        } else {
            alerte(
                tr!("Redémarrages brutaux", "Kernel panics"),
                trf!(
                    "{} en 30 jours (panique du noyau : matériel, pilote ou extension)",
                    "{} in 30 days (kernel panic: hardware, driver or extension)",
                    paniques.len()
                ),
                Niveau::Moyen,
            )
        });
        let plantages = rapports(&dossiers, &["ips", "crash"], 7);
        problemes.push(super::programmes_plantes(&plantages));
        super::trois_sections(systeme, materiel, problemes)
    }
}

#[cfg(windows)]
mod systeme {
    use serde::Deserialize;

    use super::{Niveau, Section, alerte, duree, go, ligne};
    use crate::ui::affichable;
    use crate::{tr, trf};

    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Etat {
        systeme: String,
        version: String,
        nom: String,
        modele: String,
        bios: String,
        allume_s: u64,
        processeur: String,
        fils: u32,
        memoire: u64,
        memoire_libre: u64,
        cartes: Vec<Carte>,
        disques: Vec<Disque>,
        ecrans_bleus: u32,
        dernier_ecran_bleu: String,
        arrets_brutaux: u32,
        plantages: Vec<String>,
    }

    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Carte {
        nom: String,
        pilote: String,
    }

    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Disque {
        nom: String,
        taille: u64,
        sorte: String,
    }

    /// Une seule lecture PowerShell, en JSON : matériel, système, puis les événements des 30 derniers jours
    /// (1001 = écran bleu, 41 = arrêt brutal) et les programmes plantés des 7 derniers jours (événement 1000).
    fn lire() -> Option<Etat> {
        let json = crate::machine::windows::ps(
            r#"$os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
               $cpu = @(Get-CimInstance Win32_Processor)[0]; $mois = (Get-Date).AddDays(-30); $semaine = (Get-Date).AddDays(-7)
               $bleus = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; StartTime = $mois } -ErrorAction SilentlyContinue)
               [pscustomobject]@{
                 systeme = $os.Caption; version = "$($os.Version)"; nom = $env:COMPUTERNAME
                 modele = "$($cs.Manufacturer) $($cs.Model)"; bios = "$((Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion)"
                 allume_s = [uint64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
                 processeur = "$($cpu.Name)".Trim(); fils = [uint32]$cpu.NumberOfLogicalProcessors
                 memoire = [uint64]$cs.TotalPhysicalMemory; memoire_libre = [uint64]$os.FreePhysicalMemory * 1024
                 cartes = @(Get-CimInstance Win32_VideoController | ForEach-Object { @{ nom = "$($_.Name)"; pilote = "$($_.DriverVersion)" } })
                 disques = @(try { Get-PhysicalDisk | ForEach-Object { @{ nom = "$($_.FriendlyName)"; taille = [uint64]$_.Size; sorte = "$($_.MediaType)" } } } catch { })
                 ecrans_bleus = $bleus.Count
                 dernier_ecran_bleu = if ($bleus.Count) { $bleus[0].TimeCreated.ToString('yyyy-MM-dd') } else { '' }
                 arrets_brutaux = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41; StartTime = $mois } -ErrorAction SilentlyContinue).Count
                 plantages = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000; StartTime = $semaine } -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Properties[0].Value)" })
               } | ConvertTo-Json -Compress -Depth 3"#,
        )?;
        let mut e: Etat = serde_json::from_str(&json).ok()?;
        // Chaque texte prêt à montrer : un programme planté porte le nom de son choix, un disque branché aussi.
        for t in [
            &mut e.systeme,
            &mut e.version,
            &mut e.nom,
            &mut e.modele,
            &mut e.bios,
            &mut e.processeur,
            &mut e.dernier_ecran_bleu,
        ] {
            *t = affichable(t);
        }
        for c in &mut e.cartes {
            (c.nom, c.pilote) = (affichable(&c.nom), affichable(&c.pilote));
        }
        for d in &mut e.disques {
            d.nom = affichable(&d.nom);
        }
        for p in &mut e.plantages {
            *p = affichable(p);
        }
        Some(e)
    }

    pub fn sections() -> Vec<Section> {
        let Some(e) = lire() else {
            return vec![(
                tr!("DIAGNOSTIC", "DIAGNOSTIC").into(),
                vec![ligne(
                    tr!("Lecture", "Reading"),
                    tr!("PowerShell ne répond pas", "PowerShell is not responding"),
                )],
            )];
        };
        let systeme = vec![
            ligne(tr!("Système", "System"), format!("{} · {}", e.systeme, e.version)),
            ligne(tr!("Nom", "Name"), e.nom),
            ligne(tr!("Modèle", "Model"), format!("{} · BIOS {}", e.modele.trim(), e.bios)),
            ligne(tr!("Allumé depuis", "Up for"), duree(e.allume_s)),
        ];
        let mut materiel = vec![
            ligne(
                tr!("Processeur", "Processor"),
                trf!("{} ({} fils)", "{} ({} threads)", e.processeur, e.fils),
            ),
            ligne(
                tr!("Mémoire", "Memory"),
                trf!("{} ({} libres)", "{} ({} free)", go(e.memoire), go(e.memoire_libre)),
            ),
        ];
        materiel.extend(e.cartes.iter().map(|c| {
            ligne(
                tr!("Carte graphique", "Graphics card"),
                trf!("{} · pilote {}", "{} · driver {}", c.nom, c.pilote),
            )
        }));
        materiel.extend(e.disques.iter().map(|d| {
            let sorte = match d.sorte.as_str() {
                "HDD" => tr!("disque dur", "hard drive"),
                "SSD" => "SSD",
                _ => tr!("type inconnu", "unknown type"),
            };
            ligne(tr!("Disque", "Disk"), format!("{} · {} · {sorte}", d.nom, go(d.taille)))
        }));
        let mut problemes = vec![if e.ecrans_bleus == 0 {
            ligne(
                tr!("Écrans bleus", "Blue screens"),
                tr!("aucun en 30 jours", "none in 30 days"),
            )
        } else {
            alerte(
                tr!("Écrans bleus", "Blue screens"),
                trf!(
                    "{} en 30 jours, le dernier le {}",
                    "{} in 30 days, the last one on {}",
                    e.ecrans_bleus,
                    e.dernier_ecran_bleu
                ),
                Niveau::Eleve,
            )
        }];
        problemes.push(if e.arrets_brutaux == 0 {
            ligne(
                tr!("Arrêts brutaux", "Unexpected shutdowns"),
                tr!("aucun en 30 jours", "none in 30 days"),
            )
        } else {
            alerte(
                tr!("Arrêts brutaux", "Unexpected shutdowns"),
                trf!(
                    "{} en 30 jours (coupure, gel ou bouton maintenu)",
                    "{} in 30 days (power cut, freeze or held button)",
                    e.arrets_brutaux
                ),
                Niveau::Moyen,
            )
        });
        problemes.push(super::programmes_plantes(&e.plantages));
        super::trois_sections(systeme, materiel, problemes)
    }
}

/// Texte simple du diagnostic (sans couleur), pour le fichier enregistré.
fn en_texte(sections: &[Section]) -> String {
    let mut t = String::new();
    let date = chrono::Local::now().format("%Y-%m-%d %H:%M");
    let _ = writeln!(
        t,
        "{} — Gardien {} — {date}\n",
        tr!("Diagnostic de l'ordinateur", "Computer diagnostic"),
        env!("CARGO_PKG_VERSION")
    );
    for (nom, lignes) in sections {
        let _ = writeln!(t, "{nom}");
        for l in lignes {
            let marque = l.niveau.map_or("  ", |_| "! ");
            let _ = writeln!(t, "{marque}{:<22} {}", l.libelle, l.valeur);
        }
        t.push('\n');
    }
    t
}

/// Une ligne du diagnostic à l'écran : marque, libellé sur 22 colonnes, puis la valeur coupée pour tenir dans
/// `LARGEUR`, la suite alignée sous elle. Sans cela, une longue valeur (carte graphique et son pilote, modèle, sources
/// des erreurs) était coupée par le terminal au milieu d'un mot et reprise au bord gauche.
fn a_l_ecran(l: &Ligne) -> Vec<String> {
    // « ● », le libellé et leurs espaces : la valeur commence à la 28e colonne.
    const RETRAIT: usize = 27;
    let (marque, couleur_valeur) = match l.niveau {
        Some(n) => (format!("{}●{RESET}", couleur(n)), couleur(n)),
        None => (format!("{VERT}●{RESET}"), ""),
    };
    let debut = format!("  {marque} {GRAS}{}{RESET} ", ajuster(&l.libelle, 22));
    let mut morceaux = envelopper(&l.valeur, LARGEUR - RETRAIT);
    if morceaux.is_empty() {
        morceaux.push(String::new());
    }
    morceaux
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let avant = if i == 0 { debut.clone() } else { " ".repeat(RETRAIT) };
            format!("{avant}{couleur_valeur}{m}{RESET}")
        })
        .collect()
}

/// « gardien diagnostic » : affiche le diagnostic et l'enregistre en texte.
pub fn diagnostic() {
    println!();
    cadre(
        &format!(
            "{ACCENT}{}{RESET}",
            tr!("DIAGNOSTIC DE L'ORDINATEUR", "COMPUTER DIAGNOSTIC")
        ),
        &format!("{GRIS}{}{RESET}", tr!("lecture seule", "read only")),
    );
    trp!(
        "  {DISCRET}Lecture du matériel et des journaux…{RESET}",
        "  {DISCRET}Reading hardware and logs…{RESET}"
    );
    let sections = systeme::sections();
    for (nom, lignes) in &sections {
        section(nom);
        for t in lignes.iter().flat_map(a_l_ecran) {
            println!("{t}");
        }
    }
    let fichier = crate::reseau::dossier_donnees().join(format!(
        "diagnostic-{}.txt",
        chrono::Local::now().format("%Y-%m-%d-%H%M")
    ));
    let enregistre = std::fs::create_dir_all(fichier.parent().unwrap_or(&fichier)).is_ok()
        && std::fs::write(&fichier, en_texte(&sections)).is_ok();
    if enregistre {
        trp!(
            "\n  {DISCRET}Copie texte : {}{RESET}",
            "\n  {DISCRET}Text copy: {}{RESET}",
            fichier.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mise_en_forme() {
        assert_eq!(duree(3 * 3600 + 5 * 60), "3 h 05");
        assert_eq!(duree(2 * 86_400 + 4 * 3600), "2 j 4 h");
        let sources: Vec<String> = ["dnsmasq", "kernel", "dnsmasq", "firefox"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(plus_frequentes(&sources, 2), "dnsmasq (2), firefox (1)");
        let t = en_texte(&[(
            "SYSTÈME".into(),
            vec![ligne("Nom", "portable"), alerte("Erreurs", "3", Niveau::Moyen)],
        )]);
        assert!(t.contains("  Nom") && t.contains("! Erreurs") && !t.contains('\x1b'));
    }

    /// Une longue valeur (modèle de la carte mère, carte graphique et son pilote, sources des erreurs) tient dans
    /// `LARGEUR` colonnes, la suite alignée sous elle ; une valeur vide garde sa ligne.
    #[test]
    fn lignes_du_diagnostic_dans_la_largeur() {
        let longue = alerte(
            "Erreurs du journal",
            "311 depuis le démarrage : kernel (200), NetworkManager (50), bluetoothd (30), \
             pipewire (20), wireplumber (11)",
            Niveau::Moyen,
        );
        let modele = ligne(
            "Modèle",
            "Exemple Informatique Co., Ltd. · CARTE-MERE X670-E WIFI (EX-0001) · BIOS 1.00",
        );
        for l in [&longue, &modele] {
            let lignes = a_l_ecran(l);
            for t in &lignes {
                assert!(largeur_affichee(t) <= LARGEUR, "{} colonnes : {t}", largeur_affichee(t));
            }
            let mots = |t: &str| t.split_whitespace().map(str::to_string).collect::<Vec<_>>();
            let affiches: Vec<String> = lignes.iter().flat_map(|t| mots(&sans_couleurs(t))).collect();
            assert!(affiches.ends_with(&mots(&l.valeur)), "{lignes:?}");
            assert!(
                lignes.iter().skip(1).all(|t| t.starts_with(&" ".repeat(27))),
                "{lignes:?}"
            );
        }
        assert_eq!(a_l_ecran(&ligne("Nom", "")).len(), 1);
    }

    fn sans_couleurs(t: &str) -> String {
        let mut propre = String::new();
        let mut code = false;
        for c in t.chars() {
            match (code, c) {
                (false, '\x1b') => code = true,
                (true, 'm') => code = false,
                (false, c) => propre.push(c),
                (true, _) => {}
            }
        }
        propre
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lectures_macos() {
        let profil =
            "Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Air\n      Model Identifier: Mac14,2\n";
        assert_eq!(systeme::valeur(profil, "Model Name").as_deref(), Some("MacBook Air"));
        assert_eq!(systeme::valeur(profil, "Model Identifier").as_deref(), Some("Mac14,2"));
        assert_eq!(
            systeme::depuis_demarrage(
                "{ sec = 1715000000, usec = 123 } Mon May  6 12:53:20 2024",
                1_715_003_600
            ),
            Some(3600)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_des_lignes_du_journal() {
        assert_eq!(
            systeme::source_journal("Oct 07 15:29:32 portable NetworkManager[1334]: dhcp4: request timed out")
                .as_deref(),
            Some("NetworkManager")
        );
        assert_eq!(
            systeme::source_journal("Oct 17 14:42:05 portable kernel: kvm_amd: kvm").as_deref(),
            Some("kernel")
        );
        let v = "NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  610.57.04  Release Build  (root@builder)";
        assert_eq!(systeme::version_nvidia(v).as_deref(), Some("610.57.04"));
        let disque = r#"NAME="sda" SIZE="31004295168" ROTA="1" TYPE="disk" TRAN="usb" MODEL="USB Flash Disk""#;
        assert_eq!(systeme::champ_lsblk(disque, "TRAN").as_deref(), Some("usb"));
        assert_eq!(systeme::champ_lsblk(disque, "MODEL").as_deref(), Some("USB Flash Disk"));
        assert_eq!(go(2_000_398_934_016), "1,8 To");
    }

    /// Ce que le diagnostic montre du journal et du système : n'importe quel programme choisit le nom sous lequel il
    /// écrit au journal, le nom de son fichier, celui de son service ; un appareil, son modèle. Piégés (couleur, OSC 52,
    /// effacement de ligne, bidi), ils arrivent inoffensifs, « � » à la place de chaque caractère piégé.
    #[cfg(target_os = "linux")]
    #[test]
    fn journal_et_systeme_pieges() {
        assert_eq!(
            systeme::source_journal("Oct 17 15:29:32 portable \x1b]52;c;eA==\x07\r\u{202e}x[1334]: boum").as_deref(),
            Some("�]52;c;eA==���x")
        );
        let coredumpctl = "TIME                            PID  UID  GID SIG     COREFILE EXE\n\
                           Sun 2026-09-27 11:30:12 UTC  513823 1000 1000 SIGSEGV missing  /tmp/x\x1b]52;c;eA==\x07\u{202e}\n";
        assert_eq!(systeme::programmes_coredumpctl(coredumpctl), ["x�]52;c;eA==��"]);
        let lspci = "01:00.0 \"VGA compatible controller\" \"Faux\x1b[2K\" \"Carte\u{2066}\" -r01\n";
        assert_eq!(systeme::cartes_lspci(lspci), ["Faux�[2K Carte�"]);
        let lsblk = "NAME=\"sdb\" SIZE=\"1\" ROTA=\"0\" TYPE=\"disk\" TRAN=\"usb\" MODEL=\"Cle\x1b]0;x\x07\u{200b}\"";
        assert_eq!(systeme::champ_lsblk(lsblk, "MODEL").as_deref(), Some("Cle�]0;x��"));
        assert_eq!(systeme::champ_lsblk(lsblk, "TYPE").as_deref(), Some("disk"));
    }

    /// Une entrée de plusieurs lignes (la pile d'un programme planté, écrite par systemd-coredump au niveau « crit »)
    /// se continue en retrait : ce ne sont pas d'autres erreurs, et leur début n'est pas une source.
    #[cfg(target_os = "linux")]
    #[test]
    fn suite_d_une_entree_du_journal() {
        let retrait = " ".repeat(51);
        for suite in [
            format!("{retrait}Stack trace of thread 1949948:"),
            format!("{retrait}#0  0x000071e6e46dc78a save_context (libessai.so.1 + 0x1c78a)"),
            retrait.clone(),
        ] {
            assert_eq!(systeme::source_journal(&suite), None, "« {suite} »");
        }
    }

    /// `coredumpctl list` : le chemin d'un jeu contient souvent des espaces (« …/Hollow Knight/hollow_knight ») ;
    /// systemd 248 et plus ajoutent la colonne SIZE après lui, les versions d'avant non.
    #[cfg(target_os = "linux")]
    #[test]
    fn programmes_plantes_au_chemin_avec_espaces() {
        let entete = "TIME                            PID  UID  GID SIG     COREFILE EXE";
        let lignes = [
            "Sun 2026-09-27 11:30:12 UTC  513823 1000 1000 SIGSEGV missing  /usr/bin/firefox",
            "Sun 2026-09-27 17:18:43 UTC 1528339 1000 1000 SIGSEGV missing  /srv/jeux/Hollow Knight/hollow_knight",
            "Mon 2026-09-28 09:02:11 UTC    4242 1000 1000 SIGABRT present  /opt/Jeu Essai/jeu",
            "Mon 2026-09-28 09:05:00 UTC    4243 1000 1000 SIGSEGV none     n/a",
        ];
        // Comme coredumpctl : la colonne EXE à la largeur du plus long chemin, puis SIZE.
        let taille = ["-", "-", "1.2M", "-"];
        let mut liste = format!("{entete:<120} SIZE\n");
        for (l, t) in lignes.iter().zip(taille) {
            let _ = writeln!(liste, "{l:<120} {t:>4}");
        }
        assert_eq!(
            systeme::programmes_coredumpctl(&liste),
            ["firefox", "hollow_knight", "jeu"]
        );
        let sans_taille = "TIME                            PID   UID   GID SIG COREFILE  EXE\n\
                           Sat 2021-05-01 10:00:00 UTC    1234  1000  1000  11 present   /opt/Mon Jeu/jeu\n";
        assert_eq!(systeme::programmes_coredumpctl(sans_taille), ["jeu"]);
    }

    /// La ligne « Système » de Linux existe dans les deux langues : « noyau » s'affichait aussi en anglais. Les tests
    /// tournent en français : le texte anglais est cherché dans le code de ce fichier.
    #[test]
    fn noyau_dans_les_deux_langues() {
        let source = include_str!("diagnostic.rs");
        let code = &source[..source.find("#[cfg(test)]\nmod tests").unwrap_or(source.len())];
        assert!(
            code.contains("\"{os} · kernel {}\""),
            "ligne « Système » sans texte anglais"
        );
    }

    /// Les cartes graphiques de lspci : « VGA », « 3D » (la carte NVIDIA d'un portable), et aussi « Display
    /// controller », la classe de bien des cartes AMD de portable, comme dans la fiche de l'ordinateur.
    #[cfg(target_os = "linux")]
    #[test]
    fn cartes_graphiques_de_lspci() {
        let lspci = [
            r#"00:02.0 "VGA compatible controller" "Intel Corporation" "Alder Lake-P GT2" -r0c "Lenovo" "Device 3b2f""#,
            r#"01:00.0 "3D controller" "NVIDIA Corporation" "AD107M [GeForce RTX 4060]" -ra1 "Lenovo" "Device 3b2f""#,
            r#"03:00.0 "Display controller" "Advanced Micro Devices, Inc. [AMD/ATI]" "Navi 24 [Radeon RX 6500M]" -rc3"#,
            r#"04:00.0 "Network controller" "Intel Corporation" "Wi-Fi 6E AX211 160MHz" -r01 "Intel Corporation" "0094""#,
        ]
        .join("\n");
        assert_eq!(
            systeme::cartes_lspci(&lspci),
            [
                "Intel Corporation Alder Lake-P GT2",
                "NVIDIA Corporation AD107M [GeForce RTX 4060]",
                "Advanced Micro Devices, Inc. [AMD/ATI] Navi 24 [Radeon RX 6500M]"
            ]
        );
    }
}
