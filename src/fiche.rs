//! Fiche de l'ordinateur : ce qu'on demande au téléphone ou pour acheter une pièce. Modèle, carte mère, processeur,
//! mémoire (barrettes quand le système les dit), carte graphique et son pilote, disques, système. Lecture seule.
//! Les numéros de série s'affichent à l'écran seulement : ni dans le JSON (`gardien fiche --json`), ni dans un
//! fichier, ni dans le journal des erreurs. Ils identifient un appareil, et une fiche se partage facilement.

use serde::Serialize;

use crate::ui::*;

/// Ce que le système dit de l'ordinateur. Un champ vide : le système ne le dit pas (ou pas sans droits).
#[derive(Serialize, Default, Debug)]
pub struct Fiche {
    pub systeme: String,
    pub modele: String,
    pub carte_mere: String,
    pub bios: String,
    pub processeur: String,
    pub coeurs: Option<u32>,
    pub fils: Option<u32>,
    /// Mémoire totale, en octets.
    pub memoire: Option<u64>,
    pub barrettes: Vec<Barrette>,
    /// Les barrettes n'ont pas pu être lues : on le dit, sans rien inventer.
    pub barrettes_illisibles: bool,
    pub graphique: Vec<Graphique>,
    pub disques: Vec<Disque>,
    /// (ce qui porte le numéro, le numéro) : montrés à l'écran, jamais écrits.
    #[serde(skip)]
    pub series: Vec<(String, String)>,
}

#[derive(Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Barrette {
    /// En octets.
    pub taille: u64,
    /// « DDR5 », « LPDDR4X »…
    pub sorte: String,
    /// En MT/s (millions de transferts par seconde, ce que les fabricants appellent « MHz »).
    pub vitesse: Option<u32>,
    pub fabricant: String,
    pub reference: String,
    pub emplacement: String,
}

#[derive(Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Graphique {
    pub nom: String,
    pub pilote: String,
}

#[derive(Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Disque {
    /// Nom du disque pour le système : « nvme0n1 », « disk0 », « 0 ».
    pub nom: String,
    pub modele: String,
    /// En octets.
    pub taille: u64,
    /// « SSD NVMe », « SSD », « disque dur », « USB ».
    pub sorte: String,
}

/// Textes d'usine des cartes mères vendues nues, séparés par « | » : ils ne disent rien.
const TEXTES_D_USINE: &str = "\
to be filled by o.e.m.|default string|system product name|system manufacturer|system serial number|\
system version|not specified|not applicable|unknown|none|o.e.m.|oem|0|00000000|0123456789|123456789|\
base board serial number|chassis serial number|invalid|n/a";

/// Valeur réellement renseignée par le fabricant, pas un texte d'usine.
fn renseigne(valeur: &str) -> bool {
    let v = valeur.trim().to_ascii_lowercase();
    !v.is_empty() && !TEXTES_D_USINE.split('|').any(|x| x == v) && !v.starts_with("type1productconfigid")
}

fn propre(valeur: &str) -> String {
    let v = valeur.trim();
    if renseigne(v) { v.to_string() } else { String::new() }
}

impl Fiche {
    /// Un numéro de série renseigné, rangé à part : il ne s'affiche qu'à l'écran.
    fn serie(&mut self, quoi: &str, numero: &str) {
        if renseigne(numero) {
            self.series.push((quoi.to_string(), numero.trim().to_string()));
        }
    }

    /// La fiche prête à montrer (écran et JSON) : chaque texte vient du système ou du matériel lui-même (un disque
    /// branché dit son modèle, une barrette sa référence), rendu `affichable`. Appelé au bout de chaque lecture.
    fn prete_a_montrer(mut self) -> Self {
        let textes = [
            &mut self.systeme,
            &mut self.modele,
            &mut self.carte_mere,
            &mut self.bios,
            &mut self.processeur,
        ];
        for t in textes {
            *t = affichable(t);
        }
        for b in &mut self.barrettes {
            for t in [&mut b.sorte, &mut b.fabricant, &mut b.reference, &mut b.emplacement] {
                *t = affichable(t);
            }
        }
        for g in &mut self.graphique {
            (g.nom, g.pilote) = (affichable(&g.nom), affichable(&g.pilote));
        }
        for d in &mut self.disques {
            for t in [&mut d.nom, &mut d.modele, &mut d.sorte] {
                *t = affichable(t);
            }
        }
        for (quoi, numero) in &mut self.series {
            (*quoi, *numero) = (affichable(quoi), affichable(numero));
        }
        self
    }
}

/// « fabricant modèle », sans répéter le fabricant quand le modèle le contient déjà (« LENOVO » + « LENOVO 21AH »).
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn avec_fabricant(fabricant: &str, modele: &str) -> String {
    let (f, m) = (propre(fabricant), propre(modele));
    match (f.is_empty(), m.is_empty()) {
        (_, true) => f,
        (true, false) => m,
        (false, false) if m.to_lowercase().starts_with(&f.to_lowercase()) => m,
        (false, false) => format!("{f} {m}"),
    }
}

/// « version (date) » du BIOS ou d'un pilote : la version seule sans date, rien sans version.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn version_datee(version: &str, date: &str) -> String {
    match (propre(version), date.trim()) {
        (v, d) if v.is_empty() || d.is_empty() => v,
        (v, d) => format!("{v} ({d})"),
    }
}

/// « 09/04/2026 » (mois/jour/année, comme les BIOS l'écrivent) → « 2026-09-04 ».
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn date_bios(date: &str) -> String {
    let parties: Vec<&str> = date.trim().split('/').collect();
    match parties[..] {
        [m, j, a] if a.len() == 4 && m.len() <= 2 && j.len() <= 2 => format!("{a}-{m:0>2}-{j:0>2}"),
        _ => date.trim().to_string(),
    }
}

/// Nom d'une carte graphique d'après lspci : le nom court du fabricant (« NVIDIA Corporation » → « NVIDIA »), puis le
/// nom commercial, entre crochets (« GB205 [GeForce RTX 5070] »), sinon le nom de la puce.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nom_graphique(fabricant: &str, puce: &str) -> String {
    let n = fabricant.to_lowercase();
    // « ati » se cherche comme un mot : « Intel Corporation » le contient aussi.
    let mots: Vec<&str> = n.split(|c: char| !c.is_alphanumeric()).collect();
    let court = if n.contains("nvidia") {
        "NVIDIA"
    } else if n.contains("intel") {
        "Intel"
    } else if n.contains("advanced micro devices") || mots.contains(&"amd") || mots.contains(&"ati") {
        "AMD"
    } else {
        fabricant.trim()
    };
    let commercial = match puce.rsplit_once('[').and_then(|(_, reste)| reste.split_once(']')) {
        Some((nom, _)) => nom,
        None => puce,
    };
    let nom = format!("{court} {}", commercial.trim());
    nom.trim().to_string()
}

/// Les cartes graphiques de `lspci -vmmk` (fiches séparées par une ligne vide) : (nom, module du pilote).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn graphiques_lspci(texte: &str) -> Vec<(String, String)> {
    texte
        .split("\n\n")
        .filter_map(|fiche| {
            let champ = |cle: &str| {
                fiche
                    .lines()
                    .find_map(|l| l.strip_prefix(cle)?.strip_prefix(':'))
                    .map_or_else(String::new, |v| v.trim().to_string())
            };
            let classe = champ("Class");
            (classe.contains("VGA") || classe.contains("3D") || classe.contains("Display"))
                .then(|| (nom_graphique(&champ("Vendor"), &champ("Device")), champ("Driver")))
        })
        .collect()
}

/// Les barrettes de mémoire, d'après les propriétés que udev tire de la table DMI (`udevadm info -q property -p
/// /sys/class/dmi/id`), lisibles sans droits : « MEMORY_DEVICE_1_SIZE=17179869184 »… Un emplacement vide n'en est
/// pas une. Rend aussi les numéros de série (emplacement, numéro).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn barrettes_udev(texte: &str) -> (Vec<Barrette>, Vec<(String, String)>) {
    use std::collections::BTreeMap;
    let mut champs: BTreeMap<u32, BTreeMap<&str, &str>> = BTreeMap::new();
    let lus = texte.lines().filter_map(|l| {
        let (cle, valeur) = l.trim().split_once('=')?;
        let (numero, nom) = cle.strip_prefix("MEMORY_DEVICE_")?.split_once('_')?;
        Some((numero.parse::<u32>().ok()?, nom, valeur.trim()))
    });
    for (numero, nom, valeur) in lus {
        champs.entry(numero).or_default().insert(nom, valeur);
    }
    let mut f = Fiche::default();
    for c in champs.values() {
        let lire = |nom: &str| c.get(nom).copied().unwrap_or_default();
        let taille: u64 = lire("SIZE").parse().unwrap_or(0);
        if lire("PRESENT") == "0" || taille == 0 {
            continue;
        }
        let emplacement = propre(lire("LOCATOR"));
        let quoi = trf!("Barrette {emplacement}", "Memory module {emplacement}");
        f.serie(&quoi, lire("SERIAL_NUMBER"));
        f.barrettes.push(Barrette {
            taille,
            sorte: propre(lire("TYPE")),
            vitesse: [lire("CONFIGURED_SPEED_MTS"), lire("SPEED_MTS")]
                .iter()
                .find_map(|v| v.parse::<u32>().ok().filter(|&v| v > 0)),
            fabricant: propre(lire("MANUFACTURER")),
            reference: propre(lire("PART_NUMBER")),
            emplacement,
        });
    }
    (f.barrettes, f.series)
}

/// Le type de mémoire d'après son code SMBIOS (Win32_PhysicalMemory.SMBIOSMemoryType).
#[cfg_attr(not(windows), allow(dead_code))]
fn sorte_smbios(code: u64) -> &'static str {
    #[rustfmt::skip] // cinq codes par ligne, que rustfmt étalerait sur dix
    const SORTES: [(u64, &str); 10] = [
        (20, "DDR"), (21, "DDR2"), (24, "DDR3"), (26, "DDR4"), (27, "LPDDR"),
        (28, "LPDDR2"), (29, "LPDDR3"), (30, "LPDDR4"), (34, "DDR5"), (35, "LPDDR5"),
    ];
    SORTES.iter().find(|(c, _)| *c == code).map_or("", |&(_, sorte)| sorte)
}

/// « SSD NVMe », « disque dur »… d'après le transport et la rotation (lsblk), ou le type et le bus (Windows).
fn sorte_disque(transport: &str, rotatif: bool) -> String {
    match transport.to_ascii_lowercase().as_str() {
        "nvme" => "SSD NVMe".into(),
        "usb" => "USB".into(),
        _ if rotatif => tr!("disque dur", "hard drive").into(),
        _ => "SSD".into(),
    }
}

#[cfg(target_os = "linux")]
fn lire() -> Fiche {
    let fichier = |chemin: &str| std::fs::read_to_string(chemin).unwrap_or_default().trim().to_string();
    let dmi = |f: &str| fichier(&format!("/sys/class/dmi/id/{f}"));
    let sortie = |cmd: &str, args: &[&str]| {
        crate::commande::lancer(std::process::Command::new(cmd).args(args), 20)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
            .unwrap_or_default()
    };
    let os = fichier("/etc/os-release")
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string()))
        .unwrap_or_else(|| "Linux".into());
    let mut f = Fiche {
        systeme: trf!(
            "{os} · noyau {}",
            "{os} · kernel {}",
            fichier("/proc/sys/kernel/osrelease")
        ),
        modele: avec_fabricant(&dmi("sys_vendor"), &dmi("product_name")),
        carte_mere: avec_fabricant(&dmi("board_vendor"), &dmi("board_name")),
        bios: version_datee(&dmi("bios_version"), &date_bios(&dmi("bios_date"))),
        ..Fiche::default()
    };
    // Numéros de l'ordinateur et de la carte mère : lisibles par root seulement, le plus souvent.
    f.serie(tr!("Ordinateur", "Computer"), &dmi("product_serial"));
    f.serie(tr!("Carte mère", "Motherboard"), &dmi("board_serial"));

    let cpuinfo = fichier("/proc/cpuinfo");
    let valeur = |cle: &str| {
        cpuinfo
            .lines()
            .find_map(|l| l.strip_prefix(cle)?.trim_start().strip_prefix(':'))
            .map(|v| v.trim().to_string())
    };
    f.processeur = valeur("model name")
        .or_else(|| {
            // En anglais : lscpu traduit ses libellés (« Nom de modèle : » en français).
            crate::commande::lancer_en_anglais(&mut std::process::Command::new("lscpu"), 20)
                .filter(|r| r.code == Some(0))
                .map(|r| r.sortie)
                .unwrap_or_default()
                .lines()
                .find_map(|l| l.strip_prefix("Model name:").map(|v| v.trim().to_string()))
        })
        .unwrap_or_default();
    let processeurs: std::collections::BTreeSet<&str> = cpuinfo
        .lines()
        .filter_map(|l| l.strip_prefix("physical id")?.split(':').nth(1).map(str::trim))
        .collect();
    f.coeurs = valeur("cpu cores")
        .and_then(|c| c.parse::<u32>().ok())
        .map(|c| c * u32::try_from(processeurs.len().max(1)).unwrap_or(1));
    f.fils = u32::try_from(cpuinfo.lines().filter(|l| l.starts_with("processor")).count())
        .ok()
        .filter(|&n| n > 0);

    f.memoire = fichier("/proc/meminfo")
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        .map(|ko| ko * 1024);
    let udev = sortie("udevadm", &["info", "--query=property", "--path=/sys/class/dmi/id"]);
    let (barrettes, series) = barrettes_udev(&udev);
    f.barrettes_illisibles = barrettes.is_empty();
    f.barrettes = barrettes;
    f.series.extend(series);

    let noyau = fichier("/proc/sys/kernel/osrelease");
    for (nom, module) in graphiques_lspci(&sortie("lspci", &["-vmmk"])) {
        let pilote = match module.as_str() {
            "nvidia" => fichier("/proc/driver/nvidia/version")
                .split_whitespace()
                .find(|m| m.contains('.') && m.chars().all(|c| c.is_ascii_digit() || c == '.'))
                .map_or_else(|| "nvidia".to_string(), |v| format!("nvidia {v}")),
            "" => tr!("aucun pilote chargé", "no driver loaded").to_string(),
            autre => trf!("{autre} (noyau {noyau})", "{autre} (kernel {noyau})"),
        };
        f.graphique.push(Graphique { nom, pilote });
    }

    for l in sortie("lsblk", &["-dnbP", "-o", "NAME,SIZE,ROTA,TYPE,TRAN,MODEL,SERIAL"]).lines() {
        let champ = |cle: &str| {
            l.split_once(&format!("{cle}=\""))
                .and_then(|(_, reste)| reste.split_once('"'))
                .map_or_else(String::new, |(valeur, _)| valeur.trim().to_string())
        };
        let nom = champ("NAME");
        if champ("TYPE") != "disk" || ["zram", "loop", "ram", "sr"].iter().any(|p| nom.starts_with(p)) {
            continue;
        }
        f.serie(&trf!("Disque {nom}", "Disk {nom}"), &champ("SERIAL"));
        f.disques.push(Disque {
            modele: propre(&champ("MODEL")),
            taille: champ("SIZE").parse().unwrap_or(0),
            sorte: sorte_disque(&champ("TRAN"), champ("ROTA") == "1"),
            nom,
        });
    }
    f.prete_a_montrer()
}

/// Ce que lit le script PowerShell (Windows) : un objet JSON, aux champs du même nom que dans le script.
type LectureWindows = serde_json::Map<String, serde_json::Value>;

#[cfg_attr(target_os = "linux", allow(dead_code))]
fn champ<'a>(objet: &'a serde_json::Value, cle: &str) -> &'a str {
    objet[cle].as_str().unwrap_or_default()
}

/// La fiche d'après la lecture PowerShell (séparée pour être testée partout).
#[cfg_attr(not(windows), allow(dead_code))]
fn fiche_windows(l: LectureWindows) -> Fiche {
    // Lu comme ses barrettes, cartes et disques : un champ absent se lit vide, ou zéro.
    let l = serde_json::Value::Object(l);
    let nombre = |objet: &serde_json::Value, cle: &str| objet[cle].as_u64().filter(|&n| n > 0);
    let build = format!("({})", champ(&l, "build").trim());
    let mut f = Fiche {
        systeme: [champ(&l, "systeme").trim(), champ(&l, "version").trim(), &build]
            .into_iter()
            .filter(|p| !p.is_empty() && *p != "()")
            .collect::<Vec<_>>()
            .join(" "),
        modele: avec_fabricant(champ(&l, "fabricant"), champ(&l, "modele")),
        carte_mere: avec_fabricant(champ(&l, "carte_fabricant"), champ(&l, "carte")),
        bios: version_datee(champ(&l, "bios"), champ(&l, "bios_date")),
        processeur: champ(&l, "processeur").trim().to_string(),
        coeurs: nombre(&l, "coeurs").and_then(|c| u32::try_from(c).ok()),
        fils: nombre(&l, "fils").and_then(|c| u32::try_from(c).ok()),
        memoire: nombre(&l, "memoire"),
        barrettes_illisibles: l["barrettes"].as_array().is_none_or(Vec::is_empty),
        ..Fiche::default()
    };
    f.serie(tr!("Ordinateur", "Computer"), champ(&l, "serie"));
    f.serie(tr!("Carte mère", "Motherboard"), champ(&l, "serie_carte"));
    for b in l["barrettes"].as_array().into_iter().flatten() {
        let emplacement = champ(b, "emplacement");
        let quoi = trf!("Barrette {}", "Memory module {}", emplacement.trim());
        f.serie(&quoi, champ(b, "serie"));
        f.barrettes.push(Barrette {
            taille: nombre(b, "taille").unwrap_or(0),
            sorte: sorte_smbios(nombre(b, "sorte").unwrap_or(0)).to_string(),
            vitesse: nombre(b, "vitesse").and_then(|v| u32::try_from(v).ok()),
            fabricant: propre(champ(b, "fabricant")),
            reference: propre(champ(b, "reference")),
            emplacement: propre(emplacement),
        });
    }
    for g in l["graphique"].as_array().into_iter().flatten() {
        let pilote = match champ(g, "date").trim() {
            "" => champ(g, "pilote").trim().to_string(),
            date => format!("{} ({date})", champ(g, "pilote").trim()),
        };
        let nom = champ(g, "nom").trim().to_string();
        f.graphique.push(Graphique { nom, pilote });
    }
    for d in l["disques"].as_array().into_iter().flatten() {
        let nom = champ(d, "nom").to_string();
        f.serie(&trf!("Disque {}", "Disk {}", nom), champ(d, "serie"));
        let sorte = match (champ(d, "bus").to_ascii_lowercase().as_str(), champ(d, "sorte")) {
            (bus @ ("nvme" | "usb"), _) => sorte_disque(bus, false),
            (_, "HDD") => sorte_disque("", true),
            (_, "SSD") => sorte_disque("", false),
            _ => tr!("type inconnu", "unknown type").into(),
        };
        f.disques.push(Disque {
            modele: champ(d, "modele").trim().to_string(),
            taille: nombre(d, "taille").unwrap_or(0),
            sorte,
            nom,
        });
    }
    f.prete_a_montrer()
}

#[cfg(windows)]
fn lire() -> Fiche {
    crate::machine::windows::ps(
        r#"$os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
           $bb = Get-CimInstance Win32_BaseBoard; $bios = Get-CimInstance Win32_BIOS; $cpu = @(Get-CimInstance Win32_Processor)
           $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
           [pscustomobject]@{
             systeme = "$($os.Caption)"; version = "$($cv.DisplayVersion)"; build = "$($os.BuildNumber).$($cv.UBR)"
             fabricant = "$($cs.Manufacturer)"; modele = "$($cs.Model)"; carte_fabricant = "$($bb.Manufacturer)"; carte = "$($bb.Product)"
             bios = "$($bios.SMBIOSBIOSVersion)"; bios_date = $(if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { '' })
             processeur = "$($cpu[0].Name)".Trim()
             coeurs = [uint32](($cpu | Measure-Object NumberOfCores -Sum).Sum); fils = [uint32](($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum)
             memoire = [uint64]$cs.TotalPhysicalMemory
             barrettes = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { @{ taille = [uint64]$_.Capacity; sorte = [uint32]$_.SMBIOSMemoryType
               vitesse = [uint32]$(if ($_.ConfiguredClockSpeed) { $_.ConfiguredClockSpeed } else { $_.Speed }); fabricant = "$($_.Manufacturer)"
               reference = "$($_.PartNumber)"; emplacement = "$($_.DeviceLocator)"; serie = "$($_.SerialNumber)" } })
             graphique = @(Get-CimInstance Win32_VideoController | ForEach-Object { @{ nom = "$($_.Name)"; pilote = "$($_.DriverVersion)"
               date = $(if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' }) } })
             disques = @(try { Get-PhysicalDisk | ForEach-Object { @{ nom = "$($_.DeviceId)"; modele = "$($_.FriendlyName)"; taille = [uint64]$_.Size
               sorte = "$($_.MediaType)"; bus = "$($_.BusType)"; serie = "$($_.SerialNumber)" } } } catch { })
             serie = "$($bios.SerialNumber)"; serie_carte = "$($bb.SerialNumber)"
           } | ConvertTo-Json -Compress -Depth 3"#,
    )
    .and_then(|json| serde_json::from_str(&json).ok())
    .map_or_else(Fiche::default, fiche_windows)
}

/// La fiche d'après `system_profiler -json SPHardwareDataType SPMemoryDataType SPDisplaysDataType` (séparée pour être
/// testée partout).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn fiche_macos(json: &serde_json::Value) -> Fiche {
    let texte = |objet: &serde_json::Value, cle: &str| champ(objet, cle).trim().to_string();
    let materiel = &json["SPHardwareDataType"][0];
    let mut f = Fiche {
        modele: [texte(materiel, "machine_name"), texte(materiel, "machine_model")]
            .into_iter()
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join(" · "),
        processeur: [texte(materiel, "chip_type"), texte(materiel, "cpu_type")]
            .into_iter()
            .find(|t| !t.is_empty())
            .unwrap_or_default(),
        bios: texte(materiel, "boot_rom_version"),
        // « proc 10:4:6 » (Apple Silicon : total, performance, efficacité) ou un nombre (Intel).
        coeurs: texte(materiel, "number_processors")
            .trim_start_matches("proc ")
            .split(':')
            .next()
            .and_then(|n| n.trim().parse().ok())
            .or_else(|| materiel["number_processors"].as_u64().and_then(|n| n.try_into().ok())),
        memoire: taille_lue(&texte(materiel, "physical_memory")),
        ..Fiche::default()
    };
    let numero = texte(materiel, "serial_number");
    if !numero.is_empty() {
        f.series.push((tr!("Ordinateur", "Computer").to_string(), numero));
    }
    let memoire = &json["SPMemoryDataType"][0];
    if let Some(items) = memoire["_items"].as_array() {
        // Mac Intel : une fiche par barrette.
        for b in items {
            let Some(taille) = taille_lue(&texte(b, "dimm_size")) else {
                continue;
            };
            let quoi = trf!("Barrette {}", "Memory module {}", texte(b, "_name"));
            f.serie(&quoi, &texte(b, "dimm_serial_number"));
            f.barrettes.push(Barrette {
                taille,
                sorte: texte(b, "dimm_type"),
                vitesse: texte(b, "dimm_speed")
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok()),
                fabricant: propre(&texte(b, "dimm_manufacturer")),
                reference: propre(&texte(b, "dimm_part_number")),
                emplacement: texte(b, "_name"),
            });
        }
    } else if let Some(taille) = taille_lue(&texte(memoire, "SPMemoryDataType")) {
        // Apple Silicon : la mémoire fait partie de la puce, une seule « barrette ».
        f.barrettes.push(Barrette {
            taille,
            sorte: texte(memoire, "dimm_type"),
            fabricant: texte(memoire, "dimm_manufacturer"),
            emplacement: tr!("dans la puce", "on the chip").into(),
            ..Barrette::default()
        });
    }
    f.barrettes_illisibles = f.barrettes.is_empty();
    for g in json["SPDisplaysDataType"].as_array().into_iter().flatten() {
        let nom = [texte(g, "sppci_model"), texte(g, "_name")]
            .into_iter()
            .find(|t| !t.is_empty())
            .unwrap_or_default();
        let nom = match texte(g, "sppci_cores") {
            coeurs if coeurs.is_empty() => nom,
            coeurs => trf!("{nom} ({coeurs} cœurs)", "{nom} ({coeurs} cores)"),
        };
        let pilote = tr!("intégré à macOS", "built into macOS").into();
        f.graphique.push(Graphique { nom, pilote });
    }
    f
}

/// « 16 GB », « 8 Go », « 512 MB » → octets.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn taille_lue(texte: &str) -> Option<u64> {
    let mut mots = texte.split_whitespace();
    let nombre: f64 = mots.next()?.replace(',', ".").parse().ok()?;
    let facteur: u64 = match mots.next()?.to_ascii_uppercase().as_str() {
        "TB" | "TO" => 1 << 40,
        "GB" | "GO" => 1 << 30,
        "MB" | "MO" => 1 << 20,
        _ => return None,
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    #[allow(clippy::cast_precision_loss)]
    Some((nombre * facteur as f64) as u64)
}

#[cfg(target_os = "macos")]
fn lire() -> Fiche {
    let sortie = |cmd: &str, args: &[&str]| {
        crate::commande::lancer(std::process::Command::new(cmd).args(args), 60)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie.trim().to_string())
            .unwrap_or_default()
    };
    let sections = ["-json", "SPHardwareDataType", "SPMemoryDataType", "SPDisplaysDataType"];
    let profil = sortie("system_profiler", &sections);
    let mut f = fiche_macos(&serde_json::from_str(&profil).unwrap_or_default());
    f.systeme = format!(
        "{} {} ({})",
        sortie("sw_vers", &["-productName"]),
        sortie("sw_vers", &["-productVersion"]),
        sortie("sw_vers", &["-buildVersion"])
    );
    let valeur = |texte: &str, cle: &str| {
        texte
            .lines()
            .find_map(|l| l.trim().strip_prefix(cle)?.trim().strip_prefix(':'))
            .map(|v| v.trim().to_string())
            .unwrap_or_default()
    };
    for disque in sortie("diskutil", &["list", "internal", "physical"])
        .lines()
        .filter_map(|l| l.strip_prefix("/dev/")?.split_whitespace().next().map(str::to_string))
    {
        let info = sortie("diskutil", &["info", &disque]);
        let taille = valeur(&info, "Disk Size")
            .split('(')
            .nth(1)
            .and_then(|o| o.split_whitespace().next()?.parse().ok())
            .unwrap_or(0);
        f.disques.push(Disque {
            modele: valeur(&info, "Device / Media Name"),
            taille,
            sorte: sorte_disque("", valeur(&info, "Solid State") != "Yes"),
            nom: disque,
        });
    }
    f.prete_a_montrer()
}

fn taille(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let g = octets as f64 / f64::from(1u32 << 30);
    if g >= 1000.0 {
        trf!("{} To", "{} TB", crate::langue::decimal(g / 1024.0, 1))
    } else if g >= 10.0 {
        trf!("{g:.0} Go", "{g:.0} GB")
    } else {
        trf!("{} Go", "{} GB", crate::langue::decimal(g, 1))
    }
}

/// Ajoute « séparateur partie » au texte, sauf si la partie est vide.
fn ajouter(texte: &mut String, separateur: &str, partie: &str) {
    if !partie.is_empty() {
        texte.push_str(separateur);
        texte.push_str(partie);
    }
}

fn barrette_en_texte(b: &Barrette) -> String {
    let vitesse = b.vitesse.map_or_else(String::new, |v| format!("{v} MT/s"));
    let mut texte = taille(b.taille);
    ajouter(&mut texte, " ", &b.sorte);
    ajouter(&mut texte, " ", &vitesse);
    for detail in [&b.fabricant, &b.reference, &b.emplacement] {
        ajouter(&mut texte, " · ", detail);
    }
    texte
}

/// Une ligne « libellé  valeur », la valeur coupée et alignée dans 76 colonnes.
fn ligne(libelle: &str, valeur: &str) {
    if !valeur.is_empty() {
        afficher_aligne(&format!("  {GRAS}{}{RESET} ", ajuster(libelle, 17)), valeur, 20, "");
    }
}

fn afficher(f: &Fiche) {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("FICHE DE L'ORDINATEUR", "COMPUTER SPECS")),
        &format!("{GRIS}{}{RESET}", tr!("lecture seule", "read only")),
    );
    section(tr!("ORDINATEUR", "COMPUTER"));
    ligne(tr!("Modèle", "Model"), &f.modele);
    ligne(tr!("Carte mère", "Motherboard"), &f.carte_mere);
    ligne("BIOS", &f.bios);
    ligne(tr!("Système", "System"), &f.systeme);

    section(tr!("PROCESSEUR ET MÉMOIRE", "PROCESSOR AND MEMORY"));
    let coeurs = match (f.coeurs, f.fils) {
        (Some(c), Some(t)) if c != t => trf!(" ({c} cœurs, {t} fils)", " ({c} cores, {t} threads)"),
        (Some(c), _) => trf!(" ({c} cœurs)", " ({c} cores)"),
        (None, Some(t)) => trf!(" ({t} fils)", " ({t} threads)"),
        (None, None) => String::new(),
    };
    ligne(tr!("Processeur", "Processor"), &format!("{}{coeurs}", f.processeur));
    // Installée (les barrettes) et utilisable (le système en garde une part, pour la carte graphique intégrée…).
    let installee: u64 = f.barrettes.iter().map(|b| b.taille).sum();
    let memoire = match (installee, f.memoire) {
        (i, Some(u)) if i > u => trf!("{} ({} utilisables)", "{} ({} usable)", taille(i), taille(u)),
        (_, Some(u)) => taille(u),
        (i, None) if i > 0 => taille(i),
        _ => String::new(),
    };
    ligne(tr!("Mémoire", "Memory"), &memoire);
    for b in &f.barrettes {
        ligne(tr!("  barrette", "  module"), &barrette_en_texte(b));
    }
    if f.barrettes_illisibles {
        let illisible = tr!("détail illisible ici", "details not readable here");
        ligne(tr!("  barrettes", "  modules"), &format!("{GRIS}{illisible}{RESET}"));
    }

    section(tr!("GRAPHISME", "GRAPHICS"));
    if f.graphique.is_empty() {
        ligne(tr!("Carte graphique", "Graphics card"), tr!("non trouvée", "not found"));
    }
    for g in &f.graphique {
        ligne(tr!("Carte graphique", "Graphics card"), &g.nom);
        ligne(tr!("  pilote", "  driver"), &g.pilote);
    }

    section(tr!("DISQUES", "DISKS"));
    for d in &f.disques {
        let mut texte = format!("{} · {} · {}", d.nom, taille(d.taille), d.sorte);
        ajouter(&mut texte, " · ", &d.modele);
        ligne(tr!("Disque", "Disk"), &texte);
    }

    if !f.series.is_empty() {
        section(tr!(
            "NUMÉROS DE SÉRIE (à l'écran seulement)",
            "SERIAL NUMBERS (on screen only)"
        ));
        for (quoi, numero) in &f.series {
            ligne(quoi, numero);
        }
        let nulle_part = tr!(
            "Ils ne sont écrits nulle part : ni rapport, ni fichier, ni journal. Recopie-les toi-même si un service après-vente les demande.",
            "They are written nowhere: no report, no file, no log. Copy them yourself if an after-sales service asks for them."
        );
        afficher_aligne("  ", nulle_part, 2, DISCRET);
    }
}

/// « gardien fiche » : la fiche à l'écran ; `--json` pour les scripts, sans les numéros de série.
pub fn fiche(json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(&lire()).unwrap_or_default());
    } else {
        trp!(
            "  {DISCRET}Lecture du matériel…{RESET}",
            "  {DISCRET}Reading the hardware…{RESET}"
        );
        afficher(&lire());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn textes_d_usine_ecartes() {
        assert!(!renseigne("To be filled by O.E.M."));
        assert!(!renseigne(" Default string "));
        assert!(!renseigne("Unknown"));
        assert!(renseigne("ThinkPad T14"));
        assert_eq!(avec_fabricant("LENOVO", "LENOVO 21AH"), "LENOVO 21AH");
        assert_eq!(avec_fabricant("Dell Inc.", "XPS 13"), "Dell Inc. XPS 13");
        assert_eq!(avec_fabricant("System manufacturer", "System Product Name"), "");
        assert_eq!(date_bios("09/04/2026"), "2026-09-04");
        assert_eq!(date_bios("2026-09-04"), "2026-09-04");
    }

    #[test]
    fn cartes_graphiques_de_lspci() {
        let texte = "Slot:\t00:02.0\nClass:\tVGA compatible controller\nVendor:\tIntel Corporation\nDevice:\tAlder Lake-P GT2 [Iris Xe Graphics]\nDriver:\ti915\nModule:\ti915\n\n\
                     Slot:\t01:00.0\nClass:\t3D controller\nVendor:\tNVIDIA Corporation\nDevice:\tGA107M [GeForce RTX 3050 Mobile]\nModule:\tnouveau\n\n\
                     Slot:\t02:00.0\nClass:\tNetwork controller\nVendor:\tIntel Corporation\nDevice:\tWi-Fi 6E\nDriver:\tiwlwifi\n";
        assert_eq!(
            graphiques_lspci(texte),
            [
                ("Intel Iris Xe Graphics".to_string(), "i915".to_string()),
                ("NVIDIA GeForce RTX 3050 Mobile".to_string(), String::new()),
            ]
        );
        assert_eq!(
            nom_graphique("Advanced Micro Devices, Inc. [AMD/ATI]", "Navi 31 [Radeon RX 7900 XT]"),
            "AMD Radeon RX 7900 XT"
        );
    }

    #[test]
    fn barrettes_lues_par_udev() {
        // Valeurs inventées : un emplacement vide, deux barrettes.
        let texte = "MEMORY_ARRAY_LOCATION=System Board Or Motherboard\n\
                     MEMORY_DEVICE_0_PRESENT=0\nMEMORY_DEVICE_0_LOCATOR=DIMMA1\n\
                     MEMORY_DEVICE_1_SIZE=17179869184\nMEMORY_DEVICE_1_TYPE=DDR5\nMEMORY_DEVICE_1_SPEED_MTS=6400\n\
                     MEMORY_DEVICE_1_CONFIGURED_SPEED_MTS=6000\nMEMORY_DEVICE_1_MANUFACTURER=Unknown\n\
                     MEMORY_DEVICE_1_PART_NUMBER=ESSAI-6400 \nMEMORY_DEVICE_1_LOCATOR=DIMMA2\nMEMORY_DEVICE_1_SERIAL_NUMBER=ABCD1234\n\
                     MEMORY_DEVICE_2_SIZE=17179869184\nMEMORY_DEVICE_2_TYPE=DDR5\nMEMORY_DEVICE_2_LOCATOR=DIMMB2\n\
                     MEMORY_DEVICE_2_SERIAL_NUMBER=Unknown\n";
        let (barrettes, series) = barrettes_udev(texte);
        assert_eq!(barrettes.len(), 2);
        assert_eq!(
            barrettes[0],
            Barrette {
                taille: 17_179_869_184,
                sorte: "DDR5".into(),
                vitesse: Some(6000),
                fabricant: String::new(),
                reference: "ESSAI-6400".into(),
                emplacement: "DIMMA2".into(),
            }
        );
        assert_eq!(barrettes[1].vitesse, None);
        // Le numéro de série, à part : jamais dans la fiche écrite.
        assert_eq!(series, [("Barrette DIMMA2".to_string(), "ABCD1234".to_string())]);
        assert_eq!(
            barrette_en_texte(&barrettes[0]),
            "16 Go DDR5 6000 MT/s · ESSAI-6400 · DIMMA2"
        );
    }

    #[test]
    fn fiche_windows_sans_series_dans_le_json() {
        let lecture: LectureWindows = serde_json::from_str(
            r#"{"systeme":"Microsoft Windows 11 Famille","version":"24H2","build":"26100.2033","fabricant":"LENOVO",
                "modele":"21AH","carte_fabricant":"LENOVO","carte":"21AH00XXUS","bios":"N3MET16W","bios_date":"2023-05-11",
                "processeur":"AMD Ryzen 7 PRO 6850U","coeurs":8,"fils":16,"memoire":34359738368,
                "barrettes":[{"taille":17179869184,"sorte":34,"vitesse":4800,"fabricant":"Samsung","reference":"ESSAI","emplacement":"DIMM 0","serie":"00000000"}],
                "graphique":[{"nom":"AMD Radeon(TM) Graphics","pilote":"31.0.21001.45002","date":"2024-03-01"}],
                "disques":[{"nom":"0","modele":"Disque d'essai 1 To","taille":1024209543168,"sorte":"SSD","bus":"NVMe","serie":"E823_8FA6_BF53_0001."}],
                "serie":"PF0ESSAI","serie_carte":"To be filled by O.E.M."}"#,
        )
        .unwrap();
        let f = fiche_windows(lecture);
        assert_eq!(f.systeme, "Microsoft Windows 11 Famille 24H2 (26100.2033)");
        assert_eq!(f.modele, "LENOVO 21AH");
        assert_eq!(f.bios, "N3MET16W (2023-05-11)");
        assert_eq!(f.barrettes[0].sorte, "DDR5");
        assert_eq!(f.disques[0].sorte, "SSD NVMe");
        assert_eq!(f.graphique[0].pilote, "31.0.21001.45002 (2024-03-01)");
        // Numéros d'usine écartés ; les vrais à part.
        assert_eq!(f.series.len(), 2, "{:?}", f.series);
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("PF0ESSAI") && !json.contains("E823_8FA6"), "{json}");
    }

    #[test]
    fn fiche_macos_apple_silicon_et_intel() {
        let silicon: serde_json::Value = serde_json::from_str(
            r#"{"SPHardwareDataType":[{"machine_name":"MacBook Air","machine_model":"Mac14,2","chip_type":"Apple M2",
                "number_processors":"proc 8:4:4","physical_memory":"16 GB","serial_number":"C02ESSAI"}],
                "SPMemoryDataType":[{"SPMemoryDataType":"16 GB","dimm_manufacturer":"Hynix","dimm_type":"LPDDR5"}],
                "SPDisplaysDataType":[{"_name":"Apple M2","sppci_model":"Apple M2","sppci_cores":"10"}]}"#,
        )
        .unwrap();
        let f = fiche_macos(&silicon);
        assert_eq!(f.modele, "MacBook Air · Mac14,2");
        assert_eq!((f.processeur.as_str(), f.coeurs), ("Apple M2", Some(8)));
        assert_eq!(f.memoire, Some(16 << 30));
        assert_eq!(f.barrettes[0].sorte, "LPDDR5");
        assert_eq!(f.graphique[0].nom, "Apple M2 (10 cœurs)");
        assert!(!serde_json::to_string(&f).unwrap().contains("C02ESSAI"));
        let intel: serde_json::Value = serde_json::from_str(
            r#"{"SPHardwareDataType":[{"machine_name":"iMac","cpu_type":"Quad-Core Intel Core i5","number_processors":4,"physical_memory":"8 GB"}],
                "SPMemoryDataType":[{"_items":[{"_name":"BANK 0/DIMM0","dimm_size":"4 GB","dimm_speed":"2400 MHz","dimm_type":"DDR4"},
                                               {"_name":"BANK 1/DIMM0","dimm_size":"empty","dimm_type":"empty"}]}]}"#,
        )
        .unwrap();
        let f = fiche_macos(&intel);
        assert_eq!(f.coeurs, Some(4));
        assert_eq!(f.barrettes.len(), 1);
        assert_eq!(f.barrettes[0].vitesse, Some(2400));
        assert_eq!(taille_lue("512 MB"), Some(512 << 20));
        assert_eq!(taille_lue("vide"), None);
    }

    #[test]
    fn fiche_windows_cas_limites() {
        // Valeurs inventées : textes d'usine, champs vides ou absents, zéros, chaque sorte de disque.
        let lecture: LectureWindows = serde_json::from_str(
            r#"{"systeme":" Microsoft Windows 10 Pro ","version":"","build":"","fabricant":"System manufacturer",
                "modele":"Essai 3000","carte_fabricant":"ASUSTeK","carte":"ASUSTeK PRIME B450","bios":"Default string",
                "bios_date":"2020-01-01","processeur":" Processeur d'essai ","coeurs":0,"fils":12,"memoire":0,
                "barrettes":[{"taille":8589934592,"sorte":26,"vitesse":0,"fabricant":"Unknown","reference":" REF-1 ",
                              "emplacement":" DIMM 1 ","serie":"ABCD"},
                             {"taille":8589934592,"sorte":99,"vitesse":3200,"emplacement":"","serie":"Unknown"}],
                "graphique":[{"nom":" Carte d'essai ","pilote":" 1.2.3 ","date":""},
                             {"nom":"Autre","pilote":"","date":"2024-01-01"}],
                "disques":[{"nom":"1","modele":" Clé d'essai ","taille":32000000000,"sorte":"Unspecified","bus":"USB",
                            "serie":"0"},
                           {"nom":"2","modele":"Disque d'essai","taille":2000000000000,"sorte":"HDD","bus":"SATA",
                            "serie":"WD-ESSAI"},
                           {"nom":"3","modele":"","taille":0,"sorte":"Unspecified","bus":"SATA"},
                           {"nom":"4","modele":"SSD d'essai","taille":500000000000,"sorte":"SSD","bus":"SAS"}]}"#,
        )
        .unwrap();
        let f = fiche_windows(lecture);
        assert_eq!(
            serde_json::to_value(&f).unwrap(),
            serde_json::json!({
                "systeme": "Microsoft Windows 10 Pro", "modele": "Essai 3000", "carte_mere": "ASUSTeK PRIME B450",
                "bios": "", "processeur": "Processeur d'essai", "coeurs": null, "fils": 12, "memoire": null,
                "barrettes": [
                    {"taille": 8_589_934_592_u64, "sorte": "DDR4", "vitesse": null, "fabricant": "",
                     "reference": "REF-1", "emplacement": "DIMM 1"},
                    {"taille": 8_589_934_592_u64, "sorte": "", "vitesse": 3200, "fabricant": "", "reference": "",
                     "emplacement": ""}
                ],
                "barrettes_illisibles": false,
                "graphique": [{"nom": "Carte d'essai", "pilote": "1.2.3"}, {"nom": "Autre", "pilote": " (2024-01-01)"}],
                "disques": [
                    {"nom": "1", "modele": "Clé d'essai", "taille": 32_000_000_000_u64, "sorte": "USB"},
                    {"nom": "2", "modele": "Disque d'essai", "taille": 2_000_000_000_000_u64, "sorte": "disque dur"},
                    {"nom": "3", "modele": "", "taille": 0, "sorte": "type inconnu"},
                    {"nom": "4", "modele": "SSD d'essai", "taille": 500_000_000_000_u64, "sorte": "SSD"}
                ]
            })
        );
        assert_eq!(
            f.series,
            [
                ("Barrette DIMM 1".to_string(), "ABCD".to_string()),
                ("Disque 2".to_string(), "WD-ESSAI".to_string())
            ]
        );
    }

    /// Un disque branché dit son modèle, une barrette sa référence, le micrologiciel son fabricant : piégés, ils
    /// arrivent inoffensifs à l'écran comme dans le JSON.
    #[test]
    fn fiche_aux_textes_pieges() {
        let lecture: LectureWindows = serde_json::from_str(
            r#"{"modele":"Essai\u001b]52;c;eA==\u0007","processeur":"CPU\u001b[2K\r",
                "barrettes":[{"taille":1,"reference":"REF\u001b[8m","emplacement":"DIMM\u001b]0;t\u0007","serie":"X\u001b[1A"}],
                "graphique":[{"nom":"Carte\u001b[2K","pilote":"1.2\u0007"}],
                "disques":[{"nom":"1","modele":"Cle\u001b]52;c;eA==\u0007","taille":1,"bus":"USB","serie":"S\u001b[2K"}]}"#,
        )
        .unwrap();
        let f = fiche_windows(lecture);
        let json = serde_json::to_string(&f).unwrap();
        assert!(
            !json.contains("\\u001b") && !json.contains("\\u0007") && !json.contains("\\r"),
            "{json}"
        );
        assert_eq!(f.modele, "Essai�]52;c;eA==�");
        assert_eq!(f.disques[0].modele, "Cle�]52;c;eA==�");
        assert!(
            f.series
                .iter()
                .all(|(q, n)| !crate::ui::contient_un_piege(q) && !crate::ui::contient_un_piege(n))
        );
    }

    #[test]
    fn fiche_macos_cas_limites() {
        // Rien de lisible : une fiche vide, qui le dit pour les barrettes.
        let vide = fiche_macos(&serde_json::json!({"SPHardwareDataType": {"machine_name": "pas un tableau"}}));
        assert_eq!(
            serde_json::to_value(&vide).unwrap(),
            serde_json::json!({
                "systeme": "", "modele": "", "carte_mere": "", "bios": "", "processeur": "", "coeurs": null,
                "fils": null, "memoire": null, "barrettes": [], "barrettes_illisibles": true, "graphique": [],
                "disques": []
            })
        );
        assert_eq!(vide.series, Vec::<(String, String)>::new());
        let mac: serde_json::Value = serde_json::from_str(
            r#"{"SPHardwareDataType":[{"machine_model":"Macmini9,1","chip_type":" ","cpu_type":"Intel",
                "number_processors":"6","boot_rom_version":"1.0","serial_number":"Unknown","physical_memory":"1,5 TB"}],
                "SPMemoryDataType":[{"_items":[{"_name":"DIMM0","dimm_size":"8 Go","dimm_speed":"vite",
                    "dimm_manufacturer":"0x80CE","dimm_part_number":"Unknown","dimm_serial_number":"ESSAI42"}]}],
                "SPDisplaysDataType":[{"_name":"Carte d'essai"},{"sppci_model":"","_name":""}]}"#,
        )
        .unwrap();
        let f = fiche_macos(&mac);
        assert_eq!(
            serde_json::to_value(&f).unwrap(),
            serde_json::json!({
                "systeme": "", "modele": "Macmini9,1", "carte_mere": "", "bios": "1.0", "processeur": "Intel",
                "coeurs": 6, "fils": null, "memoire": 1_649_267_441_664_u64,
                "barrettes": [{"taille": 8_589_934_592_u64, "sorte": "", "vitesse": null, "fabricant": "0x80CE",
                               "reference": "", "emplacement": "DIMM0"}],
                "barrettes_illisibles": false,
                "graphique": [{"nom": "Carte d'essai", "pilote": "intégré à macOS"},
                              {"nom": "", "pilote": "intégré à macOS"}],
                "disques": []
            })
        );
        // Sur Mac, le numéro de l'ordinateur est montré tel qu'il est lu ; celui d'une barrette, s'il est renseigné.
        assert_eq!(
            f.series,
            [
                ("Ordinateur".to_string(), "Unknown".to_string()),
                ("Barrette DIMM0".to_string(), "ESSAI42".to_string())
            ]
        );
    }

    #[test]
    fn barrettes_udev_cas_limites() {
        let texte = "MEMORY_DEVICE_X_SIZE=4096\n  MEMORY_DEVICE_3_SIZE=8589934592  \nMEMORY_DEVICE_3_SPEED_MTS=0\n\
                     MEMORY_DEVICE_3_CONFIGURED_SPEED_MTS=abc\nMEMORY_DEVICE_3_TYPE=Unknown\n\
                     MEMORY_DEVICE_3_SERIAL_NUMBER= 00000000 \nMEMORY_DEVICE_4_SIZE=0\n\
                     MEMORY_DEVICE_4_SERIAL_NUMBER=PERDU\nMEMORY_DEVICE_5_SIZE=4294967296\nMEMORY_DEVICE_5_PRESENT=1\n\
                     MEMORY_DEVICE_5_SPEED_MTS=3200\nMEMORY_DEVICE_5_LOCATOR=ChannelA-DIMM0\n\
                     MEMORY_DEVICE_5_SERIAL_NUMBER=SERIE5\nautre ligne\n";
        let (barrettes, series) = barrettes_udev(texte);
        assert_eq!(
            barrettes,
            [
                Barrette {
                    taille: 8_589_934_592,
                    ..Barrette::default()
                },
                Barrette {
                    taille: 4_294_967_296,
                    vitesse: Some(3200),
                    emplacement: "ChannelA-DIMM0".into(),
                    ..Barrette::default()
                }
            ]
        );
        assert_eq!(series, [("Barrette ChannelA-DIMM0".to_string(), "SERIE5".to_string())]);
    }
}
