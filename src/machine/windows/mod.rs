//! Audit de sécurité Windows 10/11 via PowerShell (sans droits administrateur pour l'audit).

use std::fmt::Write;
use std::process::Command;

use super::{Audit, Constat, alerte, impossible, ok, score};
use crate::risk::{Niveau, info_port};
use crate::trw;
use crate::ui::{resume, tr, trf, trp};

mod comptes;
mod maj;
mod persistance;

use comptes::comptes;
use maj::signatures;
pub use maj::{mises_a_jour_completes, pilote_fabricant};
use persistance::persistance;

pub const NOM: &str = "Windows";

const FIN: &str = "__GARDIEN_FIN__";

/// winget sort ces codes quand le paquet est déjà là (« aucune mise à jour applicable », « déjà installé ») :
/// ce n'est pas un échec.
const DEJA_INSTALLE: &str = "-1978335189, -1978335135";

/// Installation silencieuse par winget, sans erreur si le paquet est déjà là. La source est imposée : un
/// identifiant ne peut pas être pris pour une application du Microsoft Store au nom voisin.
pub fn winget_installer(id: &str) -> String {
    format!(
        "winget install --id {id} --exact --source winget --silent --accept-package-agreements --accept-source-agreements --disable-interactivity; \
         if ($LASTEXITCODE -in {DEJA_INSTALLE}) {{ $global:LASTEXITCODE = 0 }}"
    )
}

/// Windows PowerShell 5.1, avec ses propres modules. Lancé depuis PowerShell 7 (Windows Terminal), il hériterait
/// de son PSModulePath et chargerait des modules de la version 7, incompatibles : le lecteur Cert: manquait ainsi
/// dans le test de la VM. Sans la variable, la 5.1 reprend ses chemins par défaut.
fn powershell() -> Command {
    let mut c = Command::new("powershell");
    c.env_remove("PSModulePath");
    c
}

/// Exécute un script PowerShell et retourne sa sortie (UTF-8), ou `None` en cas d'échec.
/// Le script doit aller jusqu'au marqueur de fin : une sortie vide sans marqueur (PowerShell bloqué,
/// absent, ou remplacé par un bouchon comme sous Wine) n'est jamais prise pour une réponse.
pub fn ps(script: &str) -> Option<String> {
    // 60 s : un cmdlet bloqué (service Defender suspendu…) ne doit pas figer l'audit.
    ps_delai(script, 60)
}

/// Comme `ps`, avec un délai choisi : la recherche Windows Update ou winget peuvent prendre une minute ou deux.
fn ps_delai(script: &str, secondes: u64) -> Option<String> {
    let complet =
        format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; {script}; '{FIN}'");
    // Début du script, pour retrouver lequel a échoué dans le journal.
    let debut: String = script.trim().chars().take(240).collect();
    let Some(r) = crate::commande::lancer(
        powershell().args(["-NoProfile", "-NonInteractive", "-Command", &complet]),
        secondes,
    ) else {
        crate::journal::erreur(
            "PowerShell",
            &format!("délai de {secondes} s dépassé, ou lancement impossible\n{debut}"),
        );
        return None;
    };
    match r.sortie.rsplit_once(FIN) {
        Some((avant, _)) if r.code == Some(0) => Some(avant.trim().to_string()),
        _ => {
            let etat = match r.code {
                Some(0) => "sortie incomplète (marqueur de fin absent)".to_string(),
                Some(c) => format!("code de retour {c}"),
                None => "arrêté par le système".to_string(),
            };
            crate::journal::erreur(
                "PowerShell",
                &format!("{etat}\n{debut}\n--- erreurs ---\n{}", r.erreurs.trim()),
            );
            None
        }
    }
}

/// Constat quand une vérification n'a pas pu se faire : on le dit, on ne conclut jamais « OK ».
pub(super) fn illisible(categorie: &'static str) -> Constat {
    impossible(
        categorie,
        tr!("PowerShell indisponible ou bloqué", "PowerShell unavailable or blocked"),
    )
}

/// Le script exécuté dans la fenêtre administrateur : chaque commande est annoncée, puis « OK » ou l'erreur.
/// Une fenêtre muette ne se distingue pas d'une fenêtre figée. Chaque étape a son try/catch : une erreur PowerShell
/// compte, comme un programme externe en échec, pour une étape ratée, et la fenêtre passe à la suivante. Après chaque
/// correctif, une ligne « ok » ou « echec » s'ajoute au fichier `resultats`, que Gardien lit à la fermeture.
fn script_admin(correctifs: &[Vec<String>], resultats: &str) -> String {
    let texte = |s: &str| s.replace('\'', "''");
    let mut script = String::from(tr!(
        "$Host.UI.RawUI.WindowTitle = 'Gardien : correction en cours'\n\
         [Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
         $ErrorActionPreference = 'Stop'\n\
         Write-Host 'Gardien applique une correction.' -ForegroundColor Cyan\n\
         Write-Host 'Une étape longue (mise à jour, analyse, réparation de Windows) peut durer plusieurs minutes : son heure de début est affichée.'\n\
         $echecs = 0\n",
        "$Host.UI.RawUI.WindowTitle = 'Gardien: applying a fix'\n\
         [Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
         $ErrorActionPreference = 'Stop'\n\
         Write-Host 'Gardien is applying a fix.' -ForegroundColor Cyan\n\
         Write-Host 'A long step (update, scan, Windows repair) can take several minutes: its start time is shown.'\n\
         $echecs = 0\n"
    ));
    for commandes in correctifs {
        script += "$avant = $echecs\n";
        for c in commandes {
            // Un programme externe (DISM, sfc, netsh…) en échec ne lève pas d'erreur PowerShell : seul son code de
            // retour le dit. On le lit après chaque commande (3010 = réussi, redémarrage demandé) et on continue :
            // dans « Internet ne marche plus », un netsh en échec ne doit pas empêcher de renouveler l'adresse.
            let _ = trw!(
                script,
                "Write-Host ''; Write-Host ('> ' + (Get-Date -Format 'HH:mm') + '  {}') -ForegroundColor Yellow\n$global:LASTEXITCODE = 0\ntry {{\n  {c}\n  \
                 if ($LASTEXITCODE -eq 3010) {{ Write-Host '  OK (redémarrage nécessaire)' -ForegroundColor Green }}\n  \
                 elseif ($LASTEXITCODE) {{ $echecs++; Write-Host \"  Échec (code $LASTEXITCODE) : voir le message ci-dessus\" -ForegroundColor Red }}\n  \
                 else {{ Write-Host '  OK' -ForegroundColor Green }}\n\
                 }} catch {{ $echecs++; Write-Host ('  Échec : ' + $_.Exception.Message) -ForegroundColor Red }}\n",
                "Write-Host ''; Write-Host ('> ' + (Get-Date -Format 'HH:mm') + '  {}') -ForegroundColor Yellow\n$global:LASTEXITCODE = 0\ntry {{\n  {c}\n  \
                 if ($LASTEXITCODE -eq 3010) {{ Write-Host '  OK (restart needed)' -ForegroundColor Green }}\n  \
                 elseif ($LASTEXITCODE) {{ $echecs++; Write-Host \"  Failed (code $LASTEXITCODE): see the message above\" -ForegroundColor Red }}\n  \
                 else {{ Write-Host '  OK' -ForegroundColor Green }}\n\
                 }} catch {{ $echecs++; Write-Host ('  Failed: ' + $_.Exception.Message) -ForegroundColor Red }}\n",
                texte(c)
            );
        }
        let _ = writeln!(
            script,
            "try {{ Add-Content -LiteralPath '{}' -Value $(if ($echecs -gt $avant) {{ 'echec' }} else {{ 'ok' }}) }} catch {{ }}",
            texte(resultats)
        );
    }
    script += tr!(
        "if ($echecs) { Write-Host ''; Write-Host \"Terminé, avec $echecs étape(s) en échec.\" -ForegroundColor Red; Read-Host 'Appuie sur Entrée pour fermer'; exit 1 }\n\
               Write-Host ''; Write-Host 'Terminé.' -ForegroundColor Green; Read-Host 'Appuie sur Entrée pour fermer'; exit 0",
        "if ($echecs) { Write-Host ''; Write-Host \"Finished, with $echecs failed step(s).\" -ForegroundColor Red; Read-Host 'Press Enter to close'; exit 1 }\n\
               Write-Host ''; Write-Host 'Finished.' -ForegroundColor Green; Read-Host 'Press Enter to close'; exit 0"
    );
    script
}

/// Lance des commandes dans une fenêtre PowerShell administrateur (une demande UAC). Retourne `true` si tout a réussi.
pub fn powershell_admin(commandes: &[String]) -> bool {
    powershell_admin_chacune(&[commandes.to_vec()]) == [true]
}

/// Lance des correctifs (chacun sa liste de commandes) dans une seule fenêtre PowerShell administrateur et dit
/// lesquels ont réussi. Le script est écrit en clair dans un fichier .ps1 dont le chemin est affiché : on peut le
/// lire avant d'accepter la demande d'administrateur, et il reste comme trace de ce qui a été modifié.
pub fn powershell_admin_chacune(correctifs: &[Vec<String>]) -> Vec<bool> {
    let echec = vec![false; correctifs.len()];
    let dossier = crate::reseau::dossier_local().join("corrections");
    let nom = format!("correction-{}", chrono::Local::now().format("%Y%m%d-%H%M%S"));
    let chemin = dossier.join(format!("{nom}.ps1"));
    // La fenêtre administrateur est un autre processus : elle répond par ce fichier, une ligne par correctif.
    let resultats = dossier.join(format!("{nom}.resultats"));
    let entete = trf!(
        "# Correction proposée par Gardien {} le {}.\r\n# Ce script n'est lancé qu'après ton accord (demande d'administrateur).\r\n\r\n",
        "# Fix proposed by Gardien {} on {}.\r\n# This script only runs after your consent (administrator prompt).\r\n\r\n",
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M"))
    );
    // BOM : sans lui, Windows PowerShell 5.1 lit le fichier en ANSI et casse les accents.
    let script = script_admin(correctifs, &resultats.display().to_string());
    let contenu = format!("\u{feff}{entete}{}\r\n", script.replace('\n', "\r\n"));
    if std::fs::create_dir_all(&dossier)
        .and_then(|()| std::fs::write(&chemin, contenu))
        .is_err()
    {
        trp!(
            "    Impossible d'écrire le script de correction dans {}",
            "    Could not write the fix script to {}",
            dossier.display()
        );
        return echec;
    }
    let _ = std::fs::remove_file(&resultats);
    trp!(
        "    Script de correction (lisible) : {}",
        "    Fix script (readable): {}",
        chemin.display()
    );
    let fichier = chemin.display().to_string().replace('\'', "''");
    // Demande d'administrateur refusée : Start-Process échoue et $p reste vide. Sans ce test, l'appel de méthode
    // sur $null était sauté et « exit $p.ExitCode » devenait « exit 0 » : la correction s'affichait « fait ».
    // Attente sans limite : la fenêtre est visible et attend Entrée, un délai compterait aussi le temps de lecture.
    let lanceur = trf!(
        "$p = Start-Process powershell -Verb RunAs -PassThru -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"{fichier}\"'; \
         if (-not $p) {{ Write-Host 'Demande d''administrateur refusée : rien n''a été modifié.'; exit 3 }}; \
         $p.WaitForExit(); \
         if ($null -eq $p.ExitCode) {{ exit 4 }}; exit $p.ExitCode",
        "$p = Start-Process powershell -Verb RunAs -PassThru -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"{fichier}\"'; \
         if (-not $p) {{ Write-Host 'Administrator prompt refused: nothing was changed.'; exit 3 }}; \
         $p.WaitForExit(); \
         if ($null -eq $p.ExitCode) {{ exit 4 }}; exit $p.ExitCode"
    );
    let reussi = powershell()
        .args(["-NoProfile", "-Command", &lanceur])
        .status()
        .is_ok_and(|s| s.success());
    let lus = std::fs::read_to_string(&resultats).unwrap_or_default();
    let _ = std::fs::remove_file(&resultats);
    if reussi {
        return vec![true; correctifs.len()];
    }
    // Demande refusée, point de restauration refusé, fenêtre fermée en route : un correctif sans sa ligne « ok »
    // n'a pas été fait, ou pas en entier.
    let mut etats: Vec<bool> = lus.lines().map(|l| l.trim() == "ok").collect();
    etats.resize(correctifs.len(), false);
    etats
}

fn pare_feu() -> Constat {
    let Some(etat) = ps("Get-NetFirewallProfile | ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }") else {
        return illisible("Pare-feu");
    };
    let profils: Vec<(&str, &str)> = etat.lines().filter_map(|l| l.trim().split_once('=')).collect();
    let off: Vec<&str> = profils
        .iter()
        .filter(|(_, v)| !v.eq_ignore_ascii_case("true"))
        .map(|(n, _)| *n)
        .collect();
    match (profils.is_empty(), off.join(", ")) {
        (true, _) => alerte(
            "Pare-feu",
            Niveau::Info,
            tr!(
                "Aucun profil de pare-feu lu (pare-feu tiers ?).",
                "No firewall profile read (third-party firewall?)."
            ),
        ),
        (false, off) if off.is_empty() => ok(
            "Pare-feu",
            tr!(
                "Pare-feu Windows actif sur tous les profils.",
                "Windows firewall on for every profile."
            ),
        ),
        (false, off) => alerte(
            "Pare-feu",
            Niveau::Eleve,
            trf!("Pare-feu désactivé pour : {off}.", "Firewall off for: {off}."),
        )
        .corriger(
            tr!(
                "Réactiver le pare-feu Windows sur tous les profils",
                "Turn the Windows firewall back on for every profile"
            ),
            &["Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"],
        ),
    }
}

fn antivirus() -> Vec<Constat> {
    if ps("1").is_none() {
        return vec![illisible("Antivirus")];
    }
    let Some(json) = ps(
        "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,IsTamperProtected | ConvertTo-Json",
    ) else {
        let tiers =
            ps("(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).displayName -join ', '")
                .unwrap_or_default();
        return vec![if tiers.is_empty() {
            alerte(
                "Antivirus",
                Niveau::Critique,
                tr!("Aucun antivirus détecté.", "No antivirus detected."),
            )
            .manuel(
                tr!(
                    "Ouvrir Sécurité Windows et réactiver Microsoft Defender",
                    "Open Windows Security and turn Microsoft Defender back on"
                ),
                &["Start-Process windowsdefender:"],
            )
        } else {
            ok(
                "Antivirus",
                trf!("Antivirus tiers : {tiers}.", "Third-party antivirus: {tiers}."),
            )
        }];
    };
    let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
    if !v["RealTimeProtectionEnabled"].is_boolean() {
        return vec![illisible("Antivirus")];
    }
    let mut c = Vec::new();
    if v["RealTimeProtectionEnabled"] == false || v["AntivirusEnabled"] == false {
        c.push(
            alerte(
                "Antivirus",
                Niveau::Critique,
                tr!(
                    "Protection en temps réel de Defender désactivée.",
                    "Defender real-time protection is off."
                ),
            )
            .corriger(
                tr!(
                    "Réactiver la protection en temps réel",
                    "Turn real-time protection back on"
                ),
                &["Set-MpPreference -DisableRealtimeMonitoring $false"],
            ),
        );
    } else {
        c.push(ok(
            "Antivirus",
            tr!(
                "Microsoft Defender actif, protection en temps réel.",
                "Microsoft Defender on, real-time protection."
            ),
        ));
    }
    c.push(signatures(v["AntivirusSignatureAge"].as_u64().unwrap_or(0)));
    if v["IsTamperProtected"] == false {
        c.push(alerte("Antivirus", Niveau::Moyen, tr!("Protection contre les falsifications désactivée : un malware peut couper Defender.", "Tamper protection is off: malware can turn Defender off."))
            .manuel(tr!("Sécurité Windows > Protection contre les virus > Gérer les paramètres > Protection contre les falsifications", "Windows Security > Virus protection > Manage settings > Tamper protection"), &["Start-Process windowsdefender://threatsettings"]));
    }
    c
}

fn smb1() -> Option<Constat> {
    let actif = ps("(Get-SmbServerConfiguration).EnableSMB1Protocol")?.to_ascii_lowercase();
    if actif != "true" && actif != "false" {
        return Some(illisible("SMBv1"));
    }
    Some(if actif == "true" {
        alerte(
            "SMBv1",
            Niveau::Critique,
            tr!(
                "SMBv1 activé (exploité par WannaCry / NotPetya).",
                "SMBv1 on (exploited by WannaCry / NotPetya)."
            ),
        )
        .corriger(
            tr!("Désactiver SMBv1", "Turn SMBv1 off"),
            &["Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"],
        )
    } else {
        ok("SMBv1", tr!("SMBv1 désactivé.", "SMBv1 off."))
    })
}

fn bureau_distance() -> Constat {
    let cle = r"HKLM:\System\CurrentControlSet\Control\Terminal Server";
    let actif = match ps(&format!("(Get-ItemProperty '{cle}').fDenyTSConnections")).as_deref() {
        Some("0") => true,
        Some("1") => false,
        _ => return illisible("Bureau à distance"),
    };
    if !actif {
        return ok(
            "Bureau à distance",
            tr!("Bureau à distance (RDP) désactivé.", "Remote Desktop (RDP) off."),
        );
    }
    let nla = ps(&format!(
        r"(Get-ItemProperty '{cle}\WinStations\RDP-Tcp').UserAuthentication"
    ))
    .is_some_and(|v| v == "1");
    let couper = format!("Set-ItemProperty '{cle}' -Name fDenyTSConnections -Value 1");
    // Session ouverte PAR le Bureau à distance (SESSIONNAME = RDP-Tcp#…) : le couper couperait l'utilisateur
    // lui-même. Jamais en correction automatique dans ce cas.
    if session_a_distance() {
        alerte("Bureau à distance", Niveau::Moyen, tr!("RDP activé ; tu es connecté par lui en ce moment.", "RDP on; you are connected through it right now.")).manuel(
            tr!("Ne pas le couper d'ici (tu perdrais la connexion). S'il n'est pas utile, le désactiver depuis l'écran de l'ordinateur : Paramètres > Système > Bureau à distance", "Do not turn it off from here (you would lose the connection). If it is not needed, turn it off from the computer's own screen: Settings > System > Remote Desktop"),
            &[],
        )
    } else if nla {
        alerte(
            "Bureau à distance",
            Niveau::Moyen,
            tr!(
                "RDP activé (avec NLA). Très attaqué s'il est exposé.",
                "RDP on (with NLA). Heavily attacked if exposed."
            ),
        )
        .corriger(
            tr!(
                "Désactiver le Bureau à distance si tu ne l'utilises pas",
                "Turn Remote Desktop off if you do not use it"
            ),
            &[&couper],
        )
    } else {
        alerte(
            "Bureau à distance",
            Niveau::Eleve,
            tr!(
                "RDP activé SANS authentification au niveau réseau (NLA).",
                "RDP on WITHOUT Network Level Authentication (NLA)."
            ),
        )
        .corriger(
            tr!("Exiger NLA pour le Bureau à distance", "Require NLA for Remote Desktop"),
            &[&format!(
                r"Set-ItemProperty '{cle}\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
            )],
        )
    }
}

#[link(name = "user32")]
unsafe extern "system" {
    fn GetSystemMetrics(index: i32) -> i32;
}

/// Cette session Windows est-elle affichée à travers le Bureau à distance, en ce moment ?
/// On interroge Windows directement : la variable SESSIONNAME est figée à l'ouverture de session et
/// reste « Console » quand le Bureau à distance reprend une session ouverte sur l'écran (vu en test réel).
pub fn session_a_distance() -> bool {
    const SM_REMOTESESSION: i32 = 0x1000;
    // SAFETY : GetSystemMetrics n'a ni pointeur ni effet de bord.
    let distante = unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0;
    distante || std::env::var("SESSIONNAME").is_ok_and(|s| s.to_ascii_uppercase().starts_with("RDP-"))
}

fn uac() -> Constat {
    let cle = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    let valeur = ps(&format!("(Get-ItemProperty '{cle}').EnableLUA"));
    if !matches!(valeur.as_deref(), Some("0" | "1")) {
        return illisible("UAC");
    }
    if valeur.as_deref() == Some("0") {
        alerte(
            "UAC",
            Niveau::Eleve,
            tr!(
                "Contrôle de compte d'utilisateur (UAC) désactivé : tout programme a les droits admin.",
                "User Account Control (UAC) is off: every program has admin rights."
            ),
        )
        .corriger(
            tr!(
                "Réactiver l'UAC (effectif après redémarrage)",
                "Turn UAC back on (effective after a restart)"
            ),
            &[&format!("Set-ItemProperty '{cle}' -Name EnableLUA -Value 1")],
        )
    } else {
        ok(
            "UAC",
            tr!("Contrôle de compte d'utilisateur actif.", "User Account Control on."),
        )
    }
}

fn mises_a_jour() -> Constat {
    let jours = ps("((Get-Date) - (Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn).Days")
        .and_then(|j| j.parse::<i64>().ok());
    match jours {
        Some(j) if j > 45 => alerte(
            "Mises à jour",
            Niveau::Eleve,
            trf!(
                "Dernière mise à jour Windows il y a {j} jours.",
                "Last Windows update {j} days ago."
            ),
        )
        .manuel(
            tr!(
                "Ouvrir Windows Update et installer les mises à jour",
                "Open Windows Update and install the updates"
            ),
            &["Start-Process ms-settings:windowsupdate"],
        ),
        Some(j) => ok(
            "Mises à jour",
            trf!(
                "Dernière mise à jour Windows il y a {j} jours.",
                "Last Windows update {j} days ago."
            ),
        ),
        None => impossible(
            "Mises à jour",
            tr!(
                "historique Windows Update illisible",
                "Windows Update history unreadable"
            ),
        ),
    }
}

fn chiffrement() -> Constat {
    // Lisible sans droits admin, contrairement à Get-BitLockerVolume. 1, 3 et 5 = protégé.
    let etat = ps(
        "(New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')",
    );
    match etat.as_deref() {
        Some("1" | "3" | "5") => ok(
            "Chiffrement",
            tr!("Disque C: chiffré (BitLocker).", "Disk C: encrypted (BitLocker)."),
        ),
        Some(_) => alerte(
            "Chiffrement",
            Niveau::Moyen,
            tr!(
                "Disque C: non chiffré : en cas de vol, les données sont lisibles.",
                "Disk C: not encrypted: if stolen, the data can be read."
            ),
        )
        .manuel(
            tr!(
                "Paramètres > Confidentialité et sécurité > Chiffrement de l'appareil (ou BitLocker sur Pro)",
                "Settings > Privacy & security > Device encryption (or BitLocker on Pro)"
            ),
            &["Start-Process ms-settings:deviceencryption"],
        ),
        None => impossible(
            "Chiffrement",
            tr!("état BitLocker illisible", "BitLocker state unreadable"),
        ),
    }
}

fn ports_ecoute(pare_feu_actif: bool, ip_lan: Option<&str>) -> Vec<Constat> {
    let Some(liste) = ps(
        "Get-NetTCPConnection -State Listen | ForEach-Object { \"$($_.LocalAddress)|$($_.LocalPort)|$((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName)\" }",
    ) else {
        return vec![illisible("Ports en écoute")];
    };
    // Ports déjà bloqués en entrée par une règle de Gardien (ou de sentinel, de netscan, ses anciens noms) active : le
    // port écoute toujours, mais n'est plus joignable.
    // Sans cette lecture, l'alerte et la même correction (une règle de plus à chaque fois) revenaient à chaque audit.
    let bloques: Vec<u16> = if pare_feu_actif {
        ps(
            "@(Get-NetFirewallRule -DisplayName 'Gardien : bloquer *','sentinel : bloquer *','netscan : bloquer *' -ErrorAction SilentlyContinue | \
            Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' -and $_.Direction -eq 'Inbound' } | \
            Get-NetFirewallPortFilter | ForEach-Object { $_.LocalPort }) -join ','",
        )
        .unwrap_or_default()
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect()
    } else {
        Vec::new()
    };
    // Ports RPC dynamiques ouverts par Windows lui-même : normaux et filtrés par le pare-feu.
    let systeme = ["svchost", "lsass", "wininit", "services", "spoolsv", "System", "Idle"];
    let mut vus = Vec::new();
    let mut constats = Vec::new();
    for l in liste.lines() {
        let mut c = l.splitn(3, '|');
        let (Some(adresse), Some(Ok(port)), programme) =
            (c.next(), c.next().map(str::parse::<u16>), c.next().unwrap_or("?"))
        else {
            continue;
        };
        let expose = matches!(adresse, "0.0.0.0" | "::") || ip_lan == Some(adresse);
        if !expose || vus.contains(&port) || (port >= 49152 && systeme.contains(&programme)) {
            continue;
        }
        vus.push(port);
        let i = info_port(port);
        if bloques.contains(&port) {
            constats.push(alerte(
                "Ports en écoute",
                Niveau::Info,
                trf!(
                    "{port}/tcp ({}) ouvert par « {programme} », bloqué en entrée par la règle « Gardien : bloquer {port} » du pare-feu Windows.", "{port}/tcp ({}) opened by “{programme}”, blocked inbound by the “Gardien : bloquer {port}” Windows firewall rule.",
                    i.service
                ),
            ));
            continue;
        }
        let niveau = super::niveau_expose(pare_feu_actif, i.niveau);
        let constat = alerte(
            "Ports en écoute",
            niveau,
            trf!(
                "{port}/tcp ({}) ouvert par « {programme} ». {}",
                "{port}/tcp ({}) opened by “{programme}”. {}",
                i.service,
                i.conseil
            ),
        );
        // RDP : pas de blocage aveugle, il coupe l'accès aux machines pilotées à distance (VM…).
        // Le constat « Bureau à distance » propose déjà NLA ou la désactivation propre.
        constats.push(if niveau >= Niveau::Moyen && port != 3389 {
            constat.corriger(
                trf!("Bloquer le port {port} en entrée dans le pare-feu Windows", "Block inbound port {port} in the Windows firewall"),
                // Sans effet si la règle existe déjà (pare-feu coupé pendant l'audit : les règles n'y étaient pas comptées).
                &[&format!("if (-not (Get-NetFirewallRule -DisplayName 'Gardien : bloquer {port}' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -DisplayName 'Gardien : bloquer {port}' -Direction Inbound -Protocol TCP -LocalPort {port} -Action Block | Out-Null }}")],
            )
            .bloquant(format!("{port}/tcp"))
        } else {
            constat
        });
    }
    if constats.is_empty() {
        constats.push(ok(
            "Ports en écoute",
            tr!(
                "Aucun service TCP sensible exposé au réseau.",
                "No sensitive TCP service exposed to the network."
            ),
        ));
    }
    constats
}

/// Wi-Fi : protection du réseau connecté, et un éventuel jumeau maléfique parmi les réseaux visibles.
fn wifi() -> Vec<Constat> {
    let Some(texte) =
        crate::commande::lancer(Command::new("netsh").args(["wlan", "show", "interfaces"]), 15).map(|r| r.sortie)
    else {
        return Vec::new();
    };
    let champ = |cle: &str| {
        texte
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(cle) && !l.starts_with("BSSID"))
            .and_then(|l| Some(l.split_once(':')?.1.trim().to_string()))
    };
    let (Some(ssid), Some(auth)) = (champ("SSID"), champ("Authenti")) else {
        return Vec::new();
    };
    let mut constats = vec![super::wifi::securite(&ssid, &auth, &[])];
    // Windows 11 24H2 réserve la liste à l'autorisation de localisation : sans elle, netsh ne liste rien, et il n'y a
    // simplement pas de jumeau à chercher.
    if let Some(r) = crate::commande::lancer(Command::new("netsh").args(["wlan", "show", "networks"]), 15) {
        let mut visibles = super::wifi::lire_netsh(&r.sortie);
        visibles.push(super::wifi::Visible {
            ssid,
            securite: auth,
            actif: true,
        });
        constats.extend(super::wifi::jumeau(&visibles));
    }
    constats
}

/// Lignes d'une section de `lectures_rapides`, sans leur préfixe ; `None` si la section n'a pas pu être lue.
pub(super) fn section<'a>(sortie: Option<&'a str>, nom: &str) -> Option<Vec<&'a str>> {
    let sortie = sortie?;
    let fin = format!("{nom}_FIN");
    sortie.lines().any(|l| l.trim() == fin).then(|| {
        sortie
            .lines()
            .filter_map(|l| l.trim().strip_prefix(nom)?.strip_prefix('|'))
            .collect()
    })
}

/// Ports UDP ouverts sur le réseau. Windows en ouvre beaucoup lui-même (découverte, heure, VPN) : on ne garde
/// que les services à risque et ceux des programmes installés, hors ports éphémères (réponses de clients).
fn ports_udp(pare_feu_actif: bool, ip_lan: Option<&str>) -> Vec<Constat> {
    let Some(liste) = ps(
        // Première ligne : le réglage LLMNR (0 = coupé, effectif au prochain redémarrage seulement).
        "'LLMNR|' + (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast; \
         Get-NetUDPEndpoint | ForEach-Object { \"$($_.LocalAddress)|$($_.LocalPort)|$((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName)\" }",
    ) else {
        return vec![illisible("Ports en écoute")];
    };
    lire_ports_udp(&liste, pare_feu_actif, ip_lan)
}

fn lire_ports_udp(liste: &str, pare_feu_actif: bool, ip_lan: Option<&str>) -> Vec<Constat> {
    let systeme = [
        "svchost", "lsass", "wininit", "services", "spoolsv", "System", "Idle", "",
    ];
    let mut vus = Vec::new();
    let mut constats = Vec::new();
    let llmnr_coupe = liste.lines().any(|l| l.trim() == "LLMNR|0");
    for l in liste.lines().filter(|l| !l.starts_with("LLMNR|")) {
        let mut c = l.trim().splitn(3, '|');
        let (Some(adresse), Some(Ok(port)), programme) =
            (c.next(), c.next().map(str::parse::<u16>), c.next().unwrap_or("").trim())
        else {
            continue;
        };
        let expose = matches!(adresse, "0.0.0.0" | "::") || ip_lan == Some(adresse);
        if !expose || port >= 49152 || vus.contains(&port) {
            continue;
        }
        let i = info_port(port);
        let du_systeme = systeme.contains(&programme);
        // 3389/udp : la moitié UDP du Bureau à distance, déjà jugé par son propre constat.
        if (du_systeme && i.niveau == Niveau::Info) || port == 3389 {
            continue;
        }
        vus.push(port);
        let programme = if programme.is_empty() {
            tr!("programme inconnu", "unknown program")
        } else {
            programme
        };
        let constat = alerte(
            "Ports en écoute",
            super::niveau_expose(pare_feu_actif, i.niveau),
            trf!(
                "{port}/udp ({}) ouvert par « {programme} ». {}",
                "{port}/udp ({}) opened by “{programme}”. {}",
                i.service,
                i.conseil
            ),
        );
        // Services de découverte de Windows : une correction qui les coupe proprement (138 suit 137, une seule fois).
        constats.push(match port {
            5355 if llmnr_coupe => alerte(
                "Ports en écoute",
                Niveau::Info,
                tr!(
                    "5355/udp (LLMNR) encore ouvert, mais LLMNR est coupé : ce sera effectif au prochain redémarrage.",
                    "5355/udp (LLMNR) still open, but LLMNR is turned off: it takes effect at the next restart."
                ),
            ),
            5355 => constat.corriger(
                tr!(
                    "Couper LLMNR (résolution de noms usurpable ; le DNS suffit)",
                    "Turn off LLMNR (spoofable name resolution; DNS is enough)"
                ),
                // Clé créée seulement si elle manque : « New-Item -Force » sur une clé existante l'écraserait, avec
                // les autres stratégies DNS qu'elle contient.
                &[
                    "if (-not (Test-Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient')) { New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null }",
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0 -Type DWord",
                ],
            ),
            137 | 138 if !vus.contains(&if port == 137 { 138 } else { 137 }) => constat.corriger(
                tr!(
                    "Couper NetBIOS sur TCP/IP (vieux partage ; le partage moderne passe par le port 445)",
                    "Turn off NetBIOS over TCP/IP (old sharing; modern sharing uses port 445)"
                ),
                &["Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null"],
            ),
            1900 => constat.corriger(
                tr!(
                    "Couper la découverte UPnP (SSDP) ; à garder si tu diffuses vers une TV ou une console",
                    "Turn off UPnP discovery (SSDP); keep it if you cast to a TV or console"
                ),
                &["Stop-Service SSDPSRV -Force", "Set-Service SSDPSRV -StartupType Disabled"],
            ),
            _ => constat,
        });
    }
    constats
}

pub fn auditer() -> Audit {
    use super::verif;
    let feu = pare_feu();
    let feu_actif = feu.probleme.is_none();
    let ip_lan = crate::scan::reseau_local().map(|l| l.1.to_string());
    let lan = ip_lan.as_deref();
    let mut constats = vec![feu];
    constats.extend(super::en_parallele(vec![
        verif!(antivirus()),
        verif!(ports_ecoute(feu_actif, lan)),
        verif!(ports_udp(feu_actif, lan)),
        verif!(smb1()),
        verif!([bureau_distance()]),
        verif!([uac()]),
        verif!([mises_a_jour()]),
        verif!([chiffrement()]),
        verif!(comptes()),
        verif!(persistance()),
        verif!(wifi()),
        verif!(super::dns::dns()),
        verif!(super::certificats::certificats()),
        verif!(super::extensions::extensions()),
        verif!(super::navigateur::navigateurs()),
        verif!(super::sante::sante()),
        verif!(super::journaux::journaux()),
        verif!([crate::integrite::constat()]),
        verif!(crate::pieges::constat()),
    ]));
    Audit {
        systeme: NOM,
        score: score(&constats),
        constats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_udp_retenus() {
        let liste = "0.0.0.0|3389|svchost\n0.0.0.0|5353|svchost\n0.0.0.0|123|svchost\n0.0.0.0|161|snmp\n127.0.0.1|1900|svchost\n0.0.0.0|27036|steam\n0.0.0.0|60000|chrome\n0.0.0.0|161|snmp";
        let c = lire_ports_udp(liste, true, None);
        assert_eq!(c.len(), 2);
        assert!(c[0].message.starts_with("161/udp"));
        assert!(c[1].message.starts_with("27036/udp"));
        // Découverte de Windows : une correction chacune, une seule pour 137 et 138.
        let c = lire_ports_udp(
            "0.0.0.0|5355|svchost\n0.0.0.0|137|System\n0.0.0.0|138|System\n0.0.0.0|1900|svchost",
            false,
            None,
        );
        let corrigibles: Vec<bool> = c.iter().map(|c| c.correctif.is_some()).collect();
        assert_eq!(corrigibles, [true, true, false, true]);
        // LLMNR : la clé des stratégies DNS n'est créée que si elle manque, jamais écrasée.
        let llmnr = &c[0].correctif.as_ref().unwrap().commandes[0];
        assert!(llmnr.starts_with("if (-not (Test-Path ") && llmnr.contains("New-Item"));
        let c = lire_ports_udp("LLMNR|0\n0.0.0.0|5355|svchost", false, None);
        assert!(c.len() == 1 && c[0].correctif.is_none() && c[0].probleme == Some(Niveau::Info));
    }

    #[test]
    fn jamais_couper_le_bureau_a_distance_qu_on_utilise() {
        // SAFETY (test) : variable propre au processus de test.
        unsafe { std::env::set_var("SESSIONNAME", "RDP-Tcp#3") };
        assert!(session_a_distance());
    }

    #[test]
    fn la_fenetre_admin_annonce_chaque_etape() {
        let s = script_admin(
            &[
                vec!["Update-MpSignature".to_string()],
                vec!["Disable-LocalUser -Name 'Invité'".to_string()],
            ],
            r"C:\Users\Zoé O'Brien\correction.resultats",
        );
        assert!(s.contains("+ '  Update-MpSignature')"));
        assert!(s.contains("+ '  Disable-LocalUser -Name ''Invité'''"));
        assert!(s.contains("Read-Host"));
        // Un programme externe en échec est signalé, pas affiché « OK ».
        assert_eq!(s.matches("$global:LASTEXITCODE = 0").count(), 2);
        assert!(s.contains("$echecs++") && s.contains("exit 1 }"));
        // Chaque étape a son try/catch : une erreur PowerShell n'arrête pas les suivantes.
        assert_eq!(s.matches("} catch { $echecs++").count(), 2);
        // Une ligne de résultat par correctif, pour savoir lesquels ont réussi.
        assert_eq!(s.matches("$avant = $echecs").count(), 2);
        assert_eq!(
            s.matches(r"Add-Content -LiteralPath 'C:\Users\Zoé O''Brien\correction.resultats'")
                .count(),
            2
        );
    }
}
