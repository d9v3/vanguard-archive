//! Audit de sécurité Windows 10/11 via PowerShell (sans droits administrateur pour l'audit).

use std::process::Command;

use super::{Audit, Constat, alerte, ok, score};
use crate::risk::{Niveau, info_port};

pub const NOM: &str = "Windows";

const FIN: &str = "__NETSCAN_FIN__";

/// Exécute un script PowerShell et retourne sa sortie (UTF-8), ou `None` en cas d'échec.
/// Le script doit aller jusqu'au marqueur de fin : une sortie vide sans marqueur (PowerShell bloqué,
/// absent, ou remplacé par un bouchon comme sous Wine) n'est jamais prise pour une réponse.
pub fn ps(script: &str) -> Option<String> {
    let complet = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; {script}; '{FIN}'");
    let o = Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &complet]).output().ok()?;
    let texte = String::from_utf8_lossy(&o.stdout);
    let (avant, _) = texte.rsplit_once(FIN)?;
    o.status.success().then(|| avant.trim().to_string())
}

/// Constat quand une vérification n'a pas pu se faire : on le dit, on ne conclut jamais « OK ».
fn illisible(categorie: &'static str) -> Constat {
    alerte(categorie, Niveau::Info, "Impossible de vérifier (PowerShell indisponible ou bloqué).")
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
/// Délai maximal d'une correction : au-delà, on rend la main au lieu d'attendre indéfiniment.
const DELAI_CORRECTION_MS: u32 = 10 * 60 * 1000;

/// Le script exécuté dans la fenêtre administrateur : chaque commande est annoncée, puis « OK » ou l'erreur.
/// Une fenêtre muette ne se distingue pas d'une fenêtre figée.
fn script_admin(commandes: &[String]) -> String {
    let texte = |s: &str| s.replace('\'', "''");
    let mut script = String::from(
        "$Host.UI.RawUI.WindowTitle = 'netscan : correction en cours'\n\
         [Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
         $ErrorActionPreference = 'Stop'\n\
         Write-Host 'netscan applique une correction (cette fenêtre se fermera seule).' -ForegroundColor Cyan\n\
         try {\n",
    );
    for c in commandes {
        let long = ["Update-MpSignature", "Remove-MpThreat", "Start-MpScan"].iter().any(|l| c.contains(l));
        let note = if long { " (peut prendre quelques minutes)" } else { "" };
        script += &format!("  Write-Host ''; Write-Host '> {}{note}' -ForegroundColor Yellow\n  {c}\n  Write-Host '  OK' -ForegroundColor Green\n", texte(c));
    }
    script += "  Write-Host ''; Write-Host 'Terminé.' -ForegroundColor Green; Start-Sleep -Seconds 2; exit 0\n\
               } catch {\n\
                 Write-Host ''; Write-Host ('Erreur : ' + $_.Exception.Message) -ForegroundColor Red\n\
                 Read-Host 'Appuie sur Entrée pour fermer'; exit 1\n\
               }";
    script
}

/// Lance des commandes dans une fenêtre PowerShell administrateur (une demande UAC). Retourne `true` si tout a réussi.
pub fn powershell_admin(commandes: &[String]) -> bool {
    let utf16: Vec<u8> = script_admin(commandes).encode_utf16().flat_map(u16::to_le_bytes).collect();
    let lanceur = format!(
        "$p = Start-Process powershell -Verb RunAs -PassThru -ArgumentList '-NoProfile','-EncodedCommand','{}'; \
         if (-not $p.WaitForExit({DELAI_CORRECTION_MS})) {{ Write-Host 'Correction trop longue : abandon de l''attente.'; exit 2 }}; exit $p.ExitCode",
        base64(&utf16)
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
    let off: Vec<&str> = profils.iter().filter(|(_, v)| !v.eq_ignore_ascii_case("true")).map(|(n, _)| *n).collect();
    match (profils.is_empty(), off.join(", ")) {
        (true, _) => alerte("Pare-feu", Niveau::Info, "Aucun profil de pare-feu lu (pare-feu tiers ?)."),
        (false, off) if off.is_empty() => ok("Pare-feu", "Pare-feu Windows actif sur tous les profils."),
        (false, off) => alerte("Pare-feu", Niveau::Eleve, format!("Pare-feu désactivé pour : {off}.")).corriger(
            "Réactiver le pare-feu Windows sur tous les profils",
            &["Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"],
        ),
    }
}

fn antivirus() -> Vec<Constat> {
    if ps("1").is_none() {
        return vec![illisible("Antivirus")];
    }
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
    if !v["RealTimeProtectionEnabled"].is_boolean() {
        return vec![illisible("Antivirus")];
    }
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
    let actif = ps("(Get-SmbServerConfiguration).EnableSMB1Protocol")?.to_ascii_lowercase();
    if actif != "true" && actif != "false" {
        return Some(illisible("SMBv1"));
    }
    Some(if actif == "true" {
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
    let actif = match ps(&format!("(Get-ItemProperty '{cle}').fDenyTSConnections")).as_deref() {
        Some("0") => true,
        Some("1") => false,
        _ => return illisible("Bureau à distance"),
    };
    if !actif {
        return ok("Bureau à distance", "Bureau à distance (RDP) désactivé.");
    }
    let nla = ps(&format!(r"(Get-ItemProperty '{cle}\WinStations\RDP-Tcp').UserAuthentication")).is_some_and(|v| v == "1");
    let couper = format!("Set-ItemProperty '{cle}' -Name fDenyTSConnections -Value 1");
    // Session ouverte PAR le Bureau à distance (SESSIONNAME = RDP-Tcp#…) : le couper couperait l'utilisateur
    // lui-même. Jamais en correction automatique dans ce cas.
    if session_a_distance() {
        alerte("Bureau à distance", Niveau::Moyen, "RDP activé ; tu es connecté par lui en ce moment.").manuel(
            "Ne pas le couper d'ici (tu perdrais la connexion). S'il n'est pas utile, le désactiver depuis l'écran de l'ordinateur : Paramètres > Système > Bureau à distance",
            &[],
        )
    } else if nla {
        alerte("Bureau à distance", Niveau::Moyen, "RDP activé (avec NLA). Très attaqué s'il est exposé.")
            .corriger("Désactiver le Bureau à distance si tu ne l'utilises pas", &[&couper])
    } else {
        alerte("Bureau à distance", Niveau::Eleve, "RDP activé SANS authentification au niveau réseau (NLA).").corriger(
            "Exiger NLA pour le Bureau à distance",
            &[&format!(r"Set-ItemProperty '{cle}\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1")],
        )
    }
}

/// Cette session Windows est-elle ouverte à travers le Bureau à distance ?
fn session_a_distance() -> bool {
    std::env::var("SESSIONNAME").is_ok_and(|s| s.to_ascii_uppercase().starts_with("RDP-"))
}

fn uac() -> Constat {
    let cle = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    let valeur = ps(&format!("(Get-ItemProperty '{cle}').EnableLUA"));
    if !matches!(valeur.as_deref(), Some("0" | "1")) {
        return illisible("UAC");
    }
    if valeur.as_deref() == Some("0") {
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
        None => alerte("Mises à jour", Niveau::Info, "Impossible de vérifier (historique Windows Update illisible)."),
    }
}

fn chiffrement() -> Constat {
    // Lisible sans droits admin, contrairement à Get-BitLockerVolume. 1, 3 et 5 = protégé.
    let etat = ps("(New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')");
    match etat.as_deref() {
        Some("1" | "3" | "5") => ok("Chiffrement", "Disque C: chiffré (BitLocker)."),
        Some(_) => alerte("Chiffrement", Niveau::Moyen, "Disque C: non chiffré : en cas de vol, les données sont lisibles.")
            .manuel("Paramètres > Confidentialité et sécurité > Chiffrement de l'appareil (ou BitLocker sur Pro)", &["Start-Process ms-settings:deviceencryption"]),
        None => alerte("Chiffrement", Niveau::Info, "Impossible de vérifier (état BitLocker illisible)."),
    }
}

fn invite() -> Constat {
    match ps("(Get-LocalUser | Where-Object { $_.Enabled -and $_.SID -like '*-501' }).Name") {
        None => illisible("Comptes"),
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
        return vec![illisible("Ports en écoute")];
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
        // RDP : pas de blocage aveugle, il coupe l'accès aux machines pilotées à distance (VM…).
        // Le constat « Bureau à distance » propose déjà NLA ou la désactivation propre.
        constats.push(if niveau >= Niveau::Moyen && port != 3389 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jamais_couper_le_bureau_a_distance_qu_on_utilise() {
        // SAFETY (test) : variable propre au processus de test.
        unsafe { std::env::set_var("SESSIONNAME", "RDP-Tcp#3") };
        assert!(session_a_distance());
        unsafe { std::env::set_var("SESSIONNAME", "Console") };
        assert!(!session_a_distance());
    }

    #[test]
    fn base64_standard() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
    }

    #[test]
    fn la_fenetre_admin_annonce_chaque_etape() {
        let s = script_admin(&["Update-MpSignature".to_string(), "Disable-LocalUser -Name 'Invité'".to_string()]);
        assert!(s.contains("> Update-MpSignature (peut prendre quelques minutes)"));
        assert!(s.contains("> Disable-LocalUser -Name ''Invité''"));
        assert!(s.contains("Read-Host"));
    }
}
