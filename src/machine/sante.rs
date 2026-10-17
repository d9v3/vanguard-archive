//! Santé de l'ordinateur : espace disque, état des disques (SMART), usure de la batterie, températures.
//! Un disque qui lâche ou plein, c'est des données perdues ; seuls ces deux cas comptent dans la note.
//! Batterie et chaleur sont de simples informations.

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Santé";

const GIO: u64 = 1 << 30;

fn taille(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let go = octets as f64 / GIO as f64;
    if go >= 1000.0 {
        trf!("{:.1} To", "{:.1} TB", go / 1024.0)
    } else if go >= 10.0 {
        trf!("{go:.0} Go", "{go:.0} GB")
    } else {
        trf!("{go:.1} Go", "{go:.1} GB")
    }
}

/// Un volume monté : point de montage, octets libres (pour l'utilisateur), octets au total.
struct Volume {
    point: String,
    libre: u64,
    total: u64,
}

/// `None` si la place suffit. Petits volumes (partition de démarrage) : seul le pourcentage compte.
fn juger_volume(v: &Volume) -> Option<Constat> {
    if v.total == 0 {
        return None;
    }
    let pourcent = v.libre * 100 / v.total;
    let petit = v.total < 8 * GIO;
    let niveau = if pourcent < 5 || (!petit && v.libre < GIO) {
        Niveau::Eleve
    } else if pourcent < 10 && (petit || v.libre < 20 * GIO) {
        Niveau::Moyen
    } else {
        return None;
    };
    let commande = if cfg!(windows) {
        format!(
            "Get-ChildItem '{}' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {{ [pscustomobject]@{{ Go = [math]::Round(((Get-ChildItem $_.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum) / 1GB, 1); Dossier = $_.FullName }} }} | Sort-Object Go -Descending | Select-Object -First 15 | Format-Table -AutoSize",
            v.point
        )
    } else {
        format!(
            "du -xh --max-depth=2 '{}' 2>/dev/null | sort -h | tail -15",
            v.point.replace('\'', r"'\''")
        )
    };
    Some(
        alerte(
            CAT,
            niveau,
            trf!(
                "Disque presque plein : {} n'a plus que {} libres sur {} ({pourcent} %). Un disque plein bloque les mises à jour et peut abîmer des fichiers.",
                "Disk almost full: {} has only {} free out of {} ({pourcent}%). A full disk blocks updates and can damage files.",
                v.point,
                taille(v.libre),
                taille(v.total)
            ),
        )
        .manuel(
            tr!(
                "Voir les plus gros dossiers, puis « Réparer → Disque plein »",
                "See the biggest folders, then “Repair → Disk full”"
            ),
            &[&commande],
        ),
    )
}

fn constats_volumes(volumes: &[Volume]) -> Vec<Constat> {
    let mut constats: Vec<Constat> = volumes.iter().filter_map(juger_volume).collect();
    if constats.is_empty() && !volumes.is_empty() {
        let resume = volumes
            .iter()
            .map(|v| trf!("{} : {} libres", "{}: {} free", v.point, taille(v.libre)))
            .collect::<Vec<_>>()
            .join(", ");
        constats.push(ok(
            CAT,
            trf!("Espace disque suffisant ({resume}).", "Enough disk space ({resume})."),
        ));
    }
    constats
}

/// État d'un disque d'après SMART.
#[derive(Default)]
struct Disque {
    modele: String,
    /// Le disque annonce lui-même une panne proche (avertissement critique NVMe, SMART « failing »).
    defaillant: bool,
    /// Usure annoncée (NVMe), en pourcentage de sa durée de vie prévue.
    usure: Option<u64>,
    /// Secteurs défectueux (SATA) ou erreurs de support (NVMe).
    erreurs: u64,
}

fn constats_disques(disques: &[Disque]) -> Vec<Constat> {
    let mut constats = Vec::new();
    let mut sains = Vec::new();
    for d in disques {
        if d.defaillant {
            constats.push(
                alerte(
                    CAT,
                    Niveau::Eleve,
                    trf!(
                        "Le disque {} annonce une panne proche (SMART). Sauvegarde tes fichiers maintenant et prévois de le remplacer.",
                        "The {} disk announces an upcoming failure (SMART). Back up your files now and plan to replace it.",
                        d.modele
                    ),
                )
                .manuel(tr!("Sauvegarder puis remplacer le disque", "Back up, then replace the disk"), &[]),
            );
        } else if d.usure.is_some_and(|u| u >= 90) || d.erreurs > 0 {
            let detail = match (d.usure.filter(|u| *u >= 90), d.erreurs) {
                (Some(u), 0) => trf!("usé à {u} %", "{u}% worn"),
                (Some(u), e) => trf!("usé à {u} %, {e} erreur(s)", "{u}% worn, {e} error(s)"),
                (None, e) => trf!("{e} erreur(s) de lecture enregistrée(s)", "{e} read error(s) recorded"),
            };
            constats.push(alerte(
                CAT,
                Niveau::Moyen,
                trf!(
                    "Le disque {} vieillit ({detail}) : garde une sauvegarde à jour.",
                    "The {} disk is aging ({detail}): keep a backup up to date.",
                    d.modele
                ),
            ));
        } else {
            sains.push(match d.usure {
                Some(u) => trf!("{} (usé à {u} %)", "{} ({u}% worn)", d.modele),
                None => d.modele.clone(),
            });
        }
    }
    if !sains.is_empty() {
        constats.push(ok(
            CAT,
            trf!(
                "Disques en bonne santé : {}.",
                "Disks in good health: {}.",
                sains.join(", ")
            ),
        ));
    }
    constats
}

fn constat_batterie(sante: u64) -> Constat {
    if sante < 80 {
        alerte(
            CAT,
            Niveau::Info,
            trf!(
                "Batterie usée : elle ne garde plus que {sante} % de sa capacité d'origine (autonomie réduite d'autant).",
                "Worn battery: it holds only {sante}% of its original capacity (battery life reduced accordingly)."
            ),
        )
    } else {
        ok(
            CAT,
            trf!(
                "Batterie en bon état ({sante} % de sa capacité d'origine).",
                "Battery in good condition ({sante}% of its original capacity)."
            ),
        )
    }
}

/// Températures relevées : (composant, degrés, seuil au-delà duquel c'est trop chaud au repos).
fn constat_temperatures(mesures: &[(&'static str, f64, f64)]) -> Option<Constat> {
    if mesures.is_empty() {
        return None;
    }
    let texte = |(nom, t, _): &(&str, f64, f64)| format!("{nom} {t:.0} °C");
    let chauds: Vec<String> = mesures.iter().filter(|(_, t, seuil)| t >= seuil).map(texte).collect();
    Some(if chauds.is_empty() {
        let liste = mesures.iter().map(texte).collect::<Vec<_>>().join(", ");
        ok(
            CAT,
            trf!("Températures normales : {liste}.", "Normal temperatures: {liste}."),
        )
    } else {
        alerte(
            CAT,
            Niveau::Info,
            trf!(
                "Ça chauffe : {}. Au repos, c'est souvent de la poussière dans les ventilateurs ou une pâte thermique sèche.",
                "Running hot: {}. At rest, it is often dust in the fans or dried thermal paste.",
                chauds.join(", ")
            ),
        )
    })
}

fn degres_nvidia() -> Option<f64> {
    let r = crate::commande::lancer(
        std::process::Command::new("nvidia-smi").args(["--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"]),
        10,
    )?;
    if r.code != Some(0) {
        return None;
    }
    r.sortie
        .lines()
        .filter_map(|l| l.trim().parse::<f64>().ok())
        .reduce(f64::max)
}

#[cfg(target_os = "linux")]
mod systeme {
    use std::path::Path;

    use serde_json::Value;

    use super::{Disque, Volume};

    const SYSTEMES_DE_FICHIERS: &[&str] = &[
        "ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3", "zfs", "bcachefs", "jfs",
    ];

    /// Volumes montés (un par périphérique : les sous-volumes btrfs partagent la même place), hors supports amovibles.
    pub fn volumes() -> Vec<Volume> {
        let montages = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        let mut vus = Vec::new();
        let mut volumes = Vec::new();
        for l in montages.lines() {
            let c: Vec<&str> = l.split_whitespace().collect();
            let [peripherique, point, genre, ..] = c[..] else {
                continue;
            };
            // /proc/mounts écrit les espaces en « \040 ».
            let point = point.replace("\\040", " ");
            if !SYSTEMES_DE_FICHIERS.contains(&genre)
                || vus.contains(&peripherique)
                || ["/run/media/", "/media/", "/mnt/", "/var/lib/docker", "/snap/"]
                    .iter()
                    .any(|p| point.starts_with(p))
            {
                continue;
            }
            vus.push(peripherique);
            let Ok(chemin) = std::ffi::CString::new(point.as_bytes()) else {
                continue;
            };
            // SAFETY : statvfs remplit la structure fournie à partir d'un chemin C valide.
            let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statvfs(chemin.as_ptr(), &raw mut s) } != 0 {
                continue;
            }
            #[allow(clippy::useless_conversion)]
            let (bloc, libres, total) = (u64::from(s.f_frsize), u64::from(s.f_bavail), u64::from(s.f_blocks));
            volumes.push(Volume {
                point,
                libre: libres * bloc,
                total: total * bloc,
            });
        }
        volumes
    }

    fn busctl(args: &[&str]) -> Option<Value> {
        let mut tous = vec!["--json=short"];
        tous.extend(args);
        let r = crate::commande::lancer(std::process::Command::new("busctl").args(&tous), 10)?;
        if r.code != Some(0) {
            return None;
        }
        serde_json::from_str::<Value>(&r.sortie).ok().map(|v| v["data"].clone())
    }

    const UDISKS: &str = "org.freedesktop.UDisks2";

    /// Disques internes lus par udisks2, sans droits root : NVMe (attributs SMART complets) et SATA (verdict SMART).
    pub fn disques() -> Vec<Disque> {
        let Some(r) = crate::commande::lancer(
            std::process::Command::new("busctl").args(["--list", "tree", UDISKS]),
            10,
        ) else {
            return Vec::new();
        };
        let mut disques = Vec::new();
        for chemin in r
            .sortie
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("/org/freedesktop/UDisks2/drives/"))
        {
            let propriete = |interface: &str, nom: &str| busctl(&["get-property", UDISKS, chemin, interface, nom]);
            let modele = propriete("org.freedesktop.UDisks2.Drive", "Model")
                .and_then(|v| v.as_str().map(str::to_string))
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| chemin.rsplit('/').next().unwrap_or("?").replace('_', " "));
            let nvme = "org.freedesktop.UDisks2.NVMe.Controller";
            if let Some(avertissements) = propriete(nvme, "SmartCriticalWarning") {
                let attributs = busctl(&["call", UDISKS, chemin, nvme, "SmartGetAttributes", "a{sv}", "0"])
                    .and_then(|d| d.get(0).cloned())
                    .unwrap_or_default();
                let nombre = |cle: &str| attributs[cle]["data"].as_u64();
                let reserve_epuisee =
                    matches!((nombre("avail_spare"), nombre("spare_thresh")), (Some(r), Some(s)) if r < s);
                disques.push(Disque {
                    modele,
                    defaillant: avertissements.as_array().is_some_and(|a| !a.is_empty()) || reserve_epuisee,
                    usure: nombre("percent_used"),
                    erreurs: nombre("media_errors").unwrap_or(0),
                });
                continue;
            }
            let ata = "org.freedesktop.UDisks2.Drive.Ata";
            if propriete(ata, "SmartEnabled").and_then(|v| v.as_bool()) == Some(true) {
                disques.push(Disque {
                    modele,
                    defaillant: propriete(ata, "SmartFailing").and_then(|v| v.as_bool()) == Some(true),
                    usure: None,
                    erreurs: propriete(ata, "SmartNumBadSectors")
                        .and_then(|v| v.as_i64())
                        .and_then(|n| u64::try_from(n).ok())
                        .unwrap_or(0),
                });
            }
        }
        disques
    }

    fn lire(chemin: &Path) -> Option<String> {
        std::fs::read_to_string(chemin).ok().map(|t| t.trim().to_string())
    }

    /// Santé de la batterie de l'ordinateur (pas celle d'une souris ou d'une manette), en pourcentage.
    pub fn batterie() -> Option<u64> {
        for e in std::fs::read_dir("/sys/class/power_supply")
            .into_iter()
            .flatten()
            .flatten()
        {
            let d = e.path();
            if lire(&d.join("type")).as_deref() != Some("Battery")
                || lire(&d.join("scope")).as_deref() == Some("Device")
            {
                continue;
            }
            let nombre = |f: &str| lire(&d.join(f)).and_then(|t| t.parse::<u64>().ok());
            let (plein, origine) = match (nombre("energy_full"), nombre("energy_full_design")) {
                (Some(p), Some(o)) => (p, o),
                _ => (nombre("charge_full")?, nombre("charge_full_design")?),
            };
            if let Some(sante) = (plein * 100).checked_div(origine) {
                return Some(sante.min(100));
            }
        }
        None
    }

    /// Températures des capteurs du noyau : processeur, carte graphique AMD, SSD NVMe (le plus chaud de chaque).
    pub fn temperatures() -> Vec<(&'static str, f64, f64)> {
        let mut processeur: Option<f64> = None;
        let mut graphique: Option<f64> = None;
        let mut ssd: Option<f64> = None;
        for e in std::fs::read_dir("/sys/class/hwmon").into_iter().flatten().flatten() {
            let d = e.path();
            let nom = lire(&d.join("name")).unwrap_or_default();
            let mut valeurs = Vec::new();
            for n in 1..=16 {
                let Some(t) = lire(&d.join(format!("temp{n}_input"))).and_then(|t| t.parse::<f64>().ok()) else {
                    continue;
                };
                valeurs.push((lire(&d.join(format!("temp{n}_label"))).unwrap_or_default(), t / 1000.0));
            }
            let choisir = |etiquettes: &[&str]| {
                valeurs
                    .iter()
                    .filter(|(l, _)| etiquettes.is_empty() || etiquettes.iter().any(|e| l.starts_with(e)))
                    .map(|(_, t)| *t)
                    .reduce(f64::max)
                    .or_else(|| valeurs.iter().map(|(_, t)| *t).reduce(f64::max))
            };
            let plus_chaud = |actuel: Option<f64>, nouveau: Option<f64>| match (actuel, nouveau) {
                (Some(a), Some(n)) => Some(a.max(n)),
                (a, n) => a.or(n),
            };
            match nom.as_str() {
                "k10temp" | "zenpower" | "coretemp" | "cpu_thermal" => {
                    processeur = plus_chaud(processeur, choisir(&["Tctl", "Tdie", "Package"]));
                }
                "amdgpu" | "nouveau" => graphique = plus_chaud(graphique, choisir(&["edge"])),
                "nvme" => ssd = plus_chaud(ssd, choisir(&["Composite"])),
                _ => {}
            }
        }
        let mut mesures = Vec::new();
        if let Some(t) = processeur {
            mesures.push((crate::tr!("processeur", "processor"), t, 90.0));
        }
        if let Some(t) = super::degres_nvidia().or(graphique) {
            mesures.push((crate::tr!("carte graphique", "graphics card"), t, 88.0));
        }
        if let Some(t) = ssd {
            mesures.push(("SSD", t, 75.0));
        }
        mesures
    }
}

#[cfg(windows)]
mod systeme {
    use super::{Disque, Volume};

    /// Une seule lecture PowerShell, en sections : volumes fixes, disques physiques, batterie.
    pub fn lectures() -> Option<String> {
        crate::machine::windows::ps(
            "try { Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' } | ForEach-Object { \
             \"VOL|$($_.DriveLetter):|$($_.SizeRemaining)|$($_.Size)\" }; 'VOL_FIN' } catch {}; \
             try { Get-PhysicalDisk | ForEach-Object { \"DSK|$($_.HealthStatus)|$($_.FriendlyName)\" }; 'DSK_FIN' } catch {}; \
             try { $p = @(Get-CimInstance -Namespace root\\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop)[0].FullChargedCapacity; \
             $o = @(Get-CimInstance -Namespace root\\wmi -ClassName BatteryStaticData -ErrorAction Stop)[0].DesignedCapacity; \
             if ($p -and $o) { \"BAT|$p|$o\" }; 'BAT_FIN' } catch {}; \
             try { Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction Stop | ForEach-Object { \
             \"TZ|$($_.HighPrecisionTemperature)\" }; 'TZ_FIN' } catch {}",
        )
    }

    pub fn volumes(lectures: Option<&str>) -> Vec<Volume> {
        crate::machine::windows::section(lectures, "VOL")
            .unwrap_or_default()
            .iter()
            .filter_map(|l| {
                let c: Vec<&str> = l.trim().split('|').collect();
                let [point, libre, total] = c[..] else { return None };
                Some(Volume {
                    point: point.to_string(),
                    libre: libre.parse().ok()?,
                    total: total.parse().ok()?,
                })
            })
            .collect()
    }

    /// État donné par Windows (Healthy, Warning, Unhealthy) : le pilote lit SMART lui-même.
    pub fn disques(lectures: Option<&str>) -> Vec<Disque> {
        crate::machine::windows::section(lectures, "DSK")
            .unwrap_or_default()
            .iter()
            .filter_map(|l| {
                let (etat, nom) = l.trim().split_once('|')?;
                Some(Disque {
                    modele: nom.to_string(),
                    defaillant: etat.eq_ignore_ascii_case("Unhealthy"),
                    usure: None,
                    erreurs: u64::from(etat.eq_ignore_ascii_case("Warning")),
                })
            })
            .collect()
    }

    pub fn batterie(lectures: Option<&str>) -> Option<u64> {
        let l = crate::machine::windows::section(lectures, "BAT")?;
        let (plein, origine) = l.first()?.trim().split_once('|')?;
        let (plein, origine): (u64, u64) = (plein.parse().ok()?, origine.parse().ok()?);
        (plein * 100).checked_div(origine).map(|s| s.min(100))
    }

    /// Zones thermiques de la carte mère (en dixièmes de kelvin, sans droits admin ; souvent le processeur sur un
    /// portable), la plus chaude, et la carte graphique NVIDIA. Une VM n'a pas de zone thermique.
    pub fn temperatures(lectures: Option<&str>) -> Vec<(&'static str, f64, f64)> {
        let mut mesures = Vec::new();
        let zone = crate::machine::windows::section(lectures, "TZ")
            .unwrap_or_default()
            .iter()
            .filter_map(|l| l.trim().parse::<f64>().ok())
            .map(|dixiemes_kelvin| dixiemes_kelvin / 10.0 - 273.15)
            // Zones factices de certaines cartes mères (0 K ou valeur figée absurde).
            .filter(|t| (5.0..130.0).contains(t))
            .reduce(f64::max);
        if let Some(t) = zone {
            mesures.push((crate::tr!("zone thermique", "thermal zone"), t, 90.0));
        }
        if let Some(t) = super::degres_nvidia() {
            mesures.push((crate::tr!("carte graphique", "graphics card"), t, 88.0));
        }
        mesures
    }
}

pub fn sante() -> Vec<Constat> {
    #[cfg(target_os = "linux")]
    let (volumes, disques, batterie) = (systeme::volumes(), systeme::disques(), systeme::batterie());
    #[cfg(windows)]
    let lectures = systeme::lectures();
    #[cfg(windows)]
    let (volumes, disques, batterie) = (
        systeme::volumes(lectures.as_deref()),
        systeme::disques(lectures.as_deref()),
        systeme::batterie(lectures.as_deref()),
    );
    let mut constats = constats_volumes(&volumes);
    constats.extend(constats_disques(&disques));
    constats.extend(batterie.map(constat_batterie));
    #[cfg(target_os = "linux")]
    let temperatures = systeme::temperatures();
    #[cfg(windows)]
    let temperatures = systeme::temperatures(lectures.as_deref());
    constats.extend(constat_temperatures(&temperatures));
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn place_sur_les_disques() {
        let v = |libre: u64, total: u64| Volume {
            point: "/".into(),
            libre: libre * GIO,
            total: total * GIO,
        };
        assert!(juger_volume(&v(500, 1800)).is_none());
        // 30 Go libres sur 1 To : 3 %, sous le seuil de 5 %.
        assert_eq!(juger_volume(&v(30, 1000)).unwrap().probleme, Some(Niveau::Eleve));
        assert_eq!(juger_volume(&v(15, 200)).unwrap().probleme, Some(Niveau::Moyen));
        // 60 Go libres sur 1 To (6 %) : assez de place, pas d'alerte.
        assert!(juger_volume(&v(60, 1000)).is_none());
        // Petite partition de démarrage (1 Go) : 8 % libres = moyen, sous 5 % = élevé (un noyau ne s'installe plus).
        let demarrage = |libre| Volume {
            point: "/boot".into(),
            libre,
            total: GIO,
        };
        assert_eq!(
            juger_volume(&demarrage(GIO / 12)).unwrap().probleme,
            Some(Niveau::Moyen)
        );
        assert_eq!(
            juger_volume(&demarrage(GIO / 25)).unwrap().probleme,
            Some(Niveau::Eleve)
        );
        assert_eq!(constats_volumes(&[v(500, 1800)])[0].probleme, None);
    }

    #[test]
    fn etat_des_disques() {
        let d = |defaillant, usure, erreurs| Disque {
            modele: "SSD".into(),
            defaillant,
            usure,
            erreurs,
        };
        assert_eq!(constats_disques(&[d(false, Some(6), 0)])[0].probleme, None);
        assert_eq!(
            constats_disques(&[d(true, Some(6), 0)])[0].probleme,
            Some(Niveau::Eleve)
        );
        assert_eq!(
            constats_disques(&[d(false, Some(95), 0)])[0].probleme,
            Some(Niveau::Moyen)
        );
        assert_eq!(constats_disques(&[d(false, None, 3)])[0].probleme, Some(Niveau::Moyen));
        assert_eq!(constat_batterie(72).probleme, Some(Niveau::Info));
        assert_eq!(
            constat_temperatures(&[("processeur", 43.0, 90.0)]).unwrap().probleme,
            None
        );
        assert_eq!(
            constat_temperatures(&[("processeur", 96.0, 90.0)]).unwrap().probleme,
            Some(Niveau::Info)
        );
        assert!(constat_temperatures(&[]).is_none());
    }
}
