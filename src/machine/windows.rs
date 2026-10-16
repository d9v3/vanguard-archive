//! Audit de sécurité Windows 10/11 via PowerShell (sans droits administrateur pour l'audit).

use std::process::Command;

use super::{Audit, Constat, alerte, ok, score};
use crate::risk::{Niveau, info_port};

pub const NOM: &str = "Windows";

/// Exécute un script PowerShell et retourne sa sortie (UTF-8), ou `None` en cas d'échec.
pub fn ps(script: &str) -> Option<String> {
    let complet = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; {script}");
    let o = Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &complet]).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Encode en base64 (pour -EncodedCommand, qui évite tout problème de guillemets).
fn base64(octets: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for bloc in octets.chunks(3) {
        let n = bloc.iter().enumerate().fold(0u32, |acc, (i, &b)| acc | (b as u32) << (16 - 8 * i));
        for i in 0..4 {
            s.push(if i <= bloc.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    s
}

/// Lance un script dans une fenêtre PowerShell administrateur (une demande UAC). Retourne `true` si tout a réussi.
pub fn powershell_admin(script: &str) -> bool {
    let enveloppe = format!(
        "try {{\n{script}\nexit 0 }} catch {{ Write-Host $_ -ForegroundColor Red; Read-Host 'Erreur. Entrée pour fermer'; exit 1 }}"
    );
    let utf16: Vec<u8> = enveloppe.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let lanceur = format!(
        "$p = Start-Process powershell -Verb RunAs -Wait -PassThru -ArgumentList '-NoProfile','-EncodedCommand','{}'; exit $p.ExitCode",
        base64(&utf16)
    );
    Command::new("powershell")
        .args(["-NoProfile", "-Command", &lanceur])
        .status()
        .is_ok_and(|s| s.success())
}

fn pare_feu() -> Constat {
    match ps("(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Name -join ', '") {
        Some(off) if off.is_empty() => ok("Pare-feu", "Pare-feu Windows actif sur tous les profils."),
        Some(off) => alerte("Pare-feu", Niveau::Eleve, format!("Pare-feu désactivé pour : {off}.")).corriger(
            "Réactiver le pare-feu Windows sur tous les profils",
            &["Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"],
        ),
        None => alerte("Pare-feu", Niveau::Info, "État du pare-feu illisible (pare-feu tiers ?)."),
    }
}

fn antivirus() -> Vec<Constat> {
    let Some(json) = ps("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,IsTamperProtected | ConvertTo-Json")
    else {
        let tiers = ps("(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).displayName -join ', '").unwrap_or_default();
        return vec![if tiers.is_empty() {
            alerte("Antivirus", Niveau::Critique, "Aucun antivirus détecté.")
                .manuel("Ouvrir Sécurité Windows et réactiver Microsoft Defender", &["Start-Process windowsdefender:"])
        } else {
            ok("Antivirus", format!("Antivirus tiers : {tiers}."))
        }];
    };
    let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
    let mut c = Vec::new();
    if v["RealTimeProtectionEnabled"] == false || v["AntivirusEnabled"] == false {
        c.push(alerte("Antivirus", Niveau::Critique, "Protection en temps réel de Defender désactivée.").corriger(
            "Réactiver la protection en temps réel",
            &["Set-MpPreference -DisableRealtimeMonitoring $false"],
        ));
    } else {
        c.push(ok("Antivirus", "Microsoft Defender actif, protection en temps réel."));
    }
    let age = v["AntivirusSignatureAge"].as_u64().unwrap_or(0);
    if age > 3 {
        c.push(
            alerte("Signatures", Niveau::Moyen, format!("Signatures antivirus vieilles de {age} jours."))
                .corriger("Mettre à jour les signatures", &["Update-MpSignature"]),
        );
    }
    if v["IsTamperProtected"] == false {
        c.push(alerte("Antivirus", Niveau::Moyen, "Protection contre les falsifications désactivée : un malware peut couper Defender.")
            .manuel("Sécurité Windows > Protection contre les virus > Gérer les paramètres > Protection contre les falsifications", &["Start-Process windowsdefender://threatsettings"]));
    }
    c
}

fn smb1() -> Option<Constat> {
    let actif = ps("(Get-SmbServerConfiguration).EnableSMB1Protocol")?;
    Some(if actif.eq_ignore_ascii_case("true") {
        alerte("SMBv1", Niveau::Critique, "SMBv1 activé (exploité par WannaCry / NotPetya).").corriger(
            "Désactiver SMBv1",
            &["Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"],
        )
    } else {
        ok("SMBv1", "SMBv1 désactivé.")
    })
}

fn bureau_distance() -> Constat {
    let cle = r"HKLM:\System\CurrentControlSet\Control\Terminal Server";
    let actif = ps(&format!("(Get-ItemProperty '{cle}').fDenyTSConnections")).is_some_and(|v| v == "0");
    if !actif {
        return ok("Bureau à distance", "Bureau à distance (RDP) désactivé.");
    }
    let nla = ps(&format!(r"(Get-ItemProperty '{cle}\WinStations\RDP-Tcp').UserAuthentication")).is_some_and(|v| v == "1");
    let couper = format!("Set-ItemProperty '{cle}' -Name fDenyTSConnections -Value 1");
    if nla {
        alerte("Bureau à distance", Niveau::Moyen, "RDP activé (avec NLA). Très attaqué s'il est exposé.")
            .corriger("Désactiver le Bureau à distance si tu ne l'utilises pas", &[&couper])
    } else {
        alerte("Bureau à distance", Niveau::Eleve, "RDP activé SANS authentification au niveau réseau (NLA).").corriger(
            "Exiger NLA pour le Bureau à distance",
            &[&format!(r"Set-ItemProperty '{cle}\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1")],
        )
    }
}

fn uac() -> Constat {
    let cle = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    if ps(&format!("(Get-ItemProperty '{cle}').EnableLUA")).is_some_and(|v| v == "0") {
        alerte("UAC", Niveau::Eleve, "Contrôle de compte d'utilisateur (UAC) désactivé : tout programme a les droits admin.")
            .corriger("Réactiver l'UAC (effectif après redémarrage)", &[&format!("Set-ItemProperty '{cle}' -Name EnableLUA -Value 1")])
    } else {
        ok("UAC", "Contrôle de compte d'utilisateur actif.")
    }
}

fn mises_a_jour() -> Constat {
    let jours = ps("((Get-Date) - (Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn).Days")
        .and_then(|j| j.parse::<i64>().ok());
    match jours {
        Some(j) if j > 45 => alerte("Mises à jour", Niveau::Eleve, format!("Dernière mise à jour Windows il y a {j} jours."))
            .manuel("Ouvrir Windows Update et installer les mises à jour", &["Start-Process ms-settings:windowsupdate"]),
        Some(j) => ok("Mises à jour", format!("Dernière mise à jour Windows il y a {j} jours.")),
        None => alerte("Mises à jour", Niveau::Info, "Impossible de lire l'historique Windows Update."),
    }
}

fn chiffrement() -> Constat {
    // Lisible sans droits admin, contrairement à Get-BitLockerVolume. 1, 3 et 5 = protégé.
    let etat = ps("(New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')");
    match etat.as_deref() {
        Some("1" | "3" | "5") => ok("Chiffrement", "Disque C: chiffré (BitLocker)."),
        Some(_) => alerte("Chiffrement", Niveau::Moyen, "Disque C: non chiffré : en cas de vol, les données sont lisibles.")
            .manuel("Paramètres > Confidentialité et sécurité > Chiffrement de l'appareil (ou BitLocker sur Pro)", &["Start-Process ms-settings:deviceencryption"]),
        None => alerte("Chiffrement", Niveau::Info, "État BitLocker illisible."),
    }
}

fn invite() -> Constat {
    match ps("(Get-LocalUser | Where-Object { $_.Enabled -and $_.SID -like '*-501' }).Name") {
        Some(nom) if !nom.is_empty() => alerte("Comptes", Niveau::Eleve, format!("Compte invité « {nom} » activé.")).corriger(
            "Désactiver le compte invité",
            &[&format!("Disable-LocalUser -Name '{nom}'")],
        ),
        _ => ok("Comptes", "Compte invité désactivé."),
    }
}

fn ports_ecoute(pare_feu_actif: bool, ip_lan: Option<String>) -> Vec<Constat> {
    let Some(liste) = ps(
        "Get-NetTCPConnection -State Listen | ForEach-Object { \"$($_.LocalAddress)|$($_.LocalPort)|$((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName)\" }",
    ) else {
        return vec![];
    };
    // Ports RPC dynamiques ouverts par Windows lui-même : normaux et filtrés par le pare-feu.
    let systeme = ["svchost", "lsass", "wininit", "services", "spoolsv", "System", "Idle"];
    let mut vus = Vec::new();
    let mut constats = Vec::new();
    for l in liste.lines() {
        let mut c = l.splitn(3, '|');
        let (Some(adresse), Some(Ok(port)), programme) = (c.next(), c.next().map(str::parse::<u16>), c.next().unwrap_or("?")) else {
            continue;
        };
        let expose = matches!(adresse, "0.0.0.0" | "::") || ip_lan.as_deref() == Some(adresse);
        if !expose || vus.contains(&port) || (port >= 49152 && systeme.contains(&programme)) {
            continue;
        }
        vus.push(port);
        let i = info_port(port);
        let niveau = match (pare_feu_actif, i.niveau) {
            (true, Niveau::Critique) => Niveau::Eleve,
            (true, Niveau::Eleve) => Niveau::Moyen,
            (true, _) => Niveau::Info,
            (false, Niveau::Info) => Niveau::Moyen,
            (false, n) => n,
        };
        let constat = alerte("Ports en écoute", niveau, format!("{port}/tcp ({}) ouvert par « {programme} ». {}", i.service, i.conseil));
        constats.push(if niveau >= Niveau::Moyen {
            constat.corriger(
                format!("Bloquer le port {port} en entrée dans le pare-feu Windows"),
                &[&format!("New-NetFirewallRule -DisplayName 'netscan : bloquer {port}' -Direction Inbound -Protocol TCP -LocalPort {port} -Action Block")],
            )
        } else {
            constat
        });
    }
    if constats.is_empty() {
        constats.push(ok("Ports en écoute", "Aucun service TCP sensible exposé au réseau."));
    }
    constats
}

fn wifi() -> Option<Constat> {
    let sortie = Command::new("netsh").args(["wlan", "show", "interfaces"]).output().ok()?;
    let texte = String::from_utf8_lossy(&sortie.stdout);
    let champ = |cle: &str| {
        texte.lines().map(str::trim).find(|l| l.starts_with(cle) && !l.starts_with("BSSID")).and_then(|l| Some(l.split_once(':')?.1.trim().to_string()))
    };
    let ssid = champ("SSID")?;
    let auth = champ("Authenti")?;
    let routeur = "Ouvrir l'admin du routeur > Wi-Fi > Sécurité : choisir « WPA2/WPA3 » ou « WPA3 »";
    Some(if auth.contains("WPA3") {
        ok("Wi-Fi", format!("« {ssid} » en {auth}."))
    } else if auth.contains("WPA2") {
        alerte("Wi-Fi", Niveau::Info, format!("« {ssid} » en {auth}. WPA3 serait mieux si le routeur le permet.")).manuel(routeur, &[])
    } else {
        alerte("Wi-Fi", Niveau::Eleve, format!("« {ssid} » en {auth} : réseau ouvert ou chiffrement faible.")).manuel(routeur, &[])
    })
}

pub fn auditer() -> Audit {
    let feu = pare_feu();
    let feu_actif = feu.probleme.is_none();
    let ip_lan = crate::scan::reseau_local().map(|l| l.1.to_string());
    let mut constats = vec![feu];
    constats.extend(antivirus());
    constats.extend(ports_ecoute(feu_actif, ip_lan));
    constats.extend(smb1());
    constats.push(bureau_distance());
    constats.push(uac());
    constats.push(mises_a_jour());
    constats.push(chiffrement());
    constats.push(invite());
    constats.extend(wifi());
    Audit { systeme: NOM, score: score(&constats), constats }
}
