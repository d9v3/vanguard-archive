//! Audit de sécurité Windows 10/11 via PowerShell (sans droits administrateur pour l'audit).

use std::fmt::Write;
use std::process::Command;

use super::{Audit, Constat, alerte, impossible, ok, score};
use crate::risk::{Niveau, info_port};

pub const NOM: &str = "Windows";

const FIN: &str = "__NETSCAN_FIN__";

/// Exécute un script PowerShell et retourne sa sortie (UTF-8), ou `None` en cas d'échec.
/// Le script doit aller jusqu'au marqueur de fin : une sortie vide sans marqueur (PowerShell bloqué,
/// absent, ou remplacé par un bouchon comme sous Wine) n'est jamais prise pour une réponse.
pub fn ps(script: &str) -> Option<String> {
    let complet =
        format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; {script}; '{FIN}'");
    // 60 s : un cmdlet bloqué (service Defender suspendu…) ne doit pas figer l'audit.
    let r = crate::commande::lancer(
        Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &complet]),
        60,
    )?;
    let (avant, _) = r.sortie.rsplit_once(FIN)?;
    (r.code == Some(0)).then(|| avant.trim().to_string())
}

/// Constat quand une vérification n'a pas pu se faire : on le dit, on ne conclut jamais « OK ».
fn illisible(categorie: &'static str) -> Constat {
    impossible(categorie, "PowerShell indisponible ou bloqué")
}

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
         $echecs = 0\n\
         try {\n",
    );
    for c in commandes {
        let long = [
            "Update-MpSignature",
            "Remove-MpThreat",
            "Start-MpScan",
            "DISM",
            "sfc",
            "Checkpoint-Computer",
        ]
        .iter()
        .any(|l| c.contains(l));
        let note = if long { " (peut prendre quelques minutes)" } else { "" };
        // Un programme externe (DISM, sfc, netsh…) en échec ne lève pas d'erreur PowerShell : seul son code de
        // retour le dit. On le lit après chaque commande (3010 = réussi, redémarrage demandé) et on continue :
        // dans « Internet ne marche plus », un netsh en échec ne doit pas empêcher de renouveler l'adresse.
        let _ = write!(
            script,
            "  Write-Host ''; Write-Host '> {}{note}' -ForegroundColor Yellow\n  $global:LASTEXITCODE = 0\n  {c}\n  \
             if ($LASTEXITCODE -eq 3010) {{ Write-Host '  OK (redémarrage nécessaire)' -ForegroundColor Green }}\n  \
             elseif ($LASTEXITCODE) {{ $echecs++; Write-Host \"  Échec (code $LASTEXITCODE) : voir le message ci-dessus\" -ForegroundColor Red }}\n  \
             else {{ Write-Host '  OK' -ForegroundColor Green }}\n",
            texte(c)
        );
    }
    script += "  if ($echecs) { Write-Host ''; Write-Host \"Terminé, avec $echecs étape(s) en échec.\" -ForegroundColor Red; Read-Host 'Appuie sur Entrée pour fermer'; exit 1 }\n\
               Write-Host ''; Write-Host 'Terminé.' -ForegroundColor Green; Start-Sleep -Seconds 2; exit 0\n\
               } catch {\n\
                 Write-Host ''; Write-Host ('Erreur : ' + $_.Exception.Message) -ForegroundColor Red\n\
                 Read-Host 'Appuie sur Entrée pour fermer'; exit 1\n\
               }";
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
    let entete = format!(
        "# Correction proposée par netscan {} le {}.\r\n# Ce script n'est lancé qu'après ton accord (demande d'administrateur).\r\n\r\n",
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format("%d/%m/%Y à %H:%M")
    );
    // BOM : sans lui, Windows PowerShell 5.1 lit le fichier en ANSI et casse les accents.
    let contenu = format!("\u{feff}{entete}{}\r\n", script_admin(commandes).replace('\n', "\r\n"));
    if std::fs::create_dir_all(&dossier)
        .and_then(|()| std::fs::write(&chemin, contenu))
        .is_err()
    {
        println!(
            "    Impossible d'écrire le script de correction dans {}",
            dossier.display()
        );
        return false;
    }
    println!("    Script de correction (lisible) : {}", chemin.display());
    let fichier = chemin.display().to_string().replace('\'', "''");
    // Demande d'administrateur refusée : Start-Process échoue et $p reste vide. Sans ce test, l'appel de méthode
    // sur $null était sauté et « exit $p.ExitCode » devenait « exit 0 » : la correction s'affichait « fait ».
    let lanceur = format!(
        "$p = Start-Process powershell -Verb RunAs -PassThru -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"{fichier}\"'; \
         if (-not $p) {{ Write-Host 'Demande d''administrateur refusée : rien n''a été modifié.'; exit 3 }}; \
         if (-not $p.WaitForExit({DELAI_CORRECTION_MS})) {{ Write-Host 'Correction trop longue : abandon de l''attente.'; exit 2 }}; \
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
            "Aucun profil de pare-feu lu (pare-feu tiers ?).",
        ),
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
    let Some(json) = ps(
        "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,IsTamperProtected | ConvertTo-Json",
    ) else {
        let tiers =
            ps("(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).displayName -join ', '")
                .unwrap_or_default();
        return vec![if tiers.is_empty() {
            alerte("Antivirus", Niveau::Critique, "Aucun antivirus détecté.").manuel(
                "Ouvrir Sécurité Windows et réactiver Microsoft Defender",
                &["Start-Process windowsdefender:"],
            )
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
        c.push(
            alerte(
                "Antivirus",
                Niveau::Critique,
                "Protection en temps réel de Defender désactivée.",
            )
            .corriger(
                "Réactiver la protection en temps réel",
                &["Set-MpPreference -DisableRealtimeMonitoring $false"],
            ),
        );
    } else {
        c.push(ok("Antivirus", "Microsoft Defender actif, protection en temps réel."));
    }
    let age = v["AntivirusSignatureAge"].as_u64().unwrap_or(0);
    if age > 3 {
        c.push(
            alerte(
                "Signatures",
                Niveau::Moyen,
                format!("Signatures antivirus vieilles de {age} jours."),
            )
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
        alerte(
            "SMBv1",
            Niveau::Critique,
            "SMBv1 activé (exploité par WannaCry / NotPetya).",
        )
        .corriger(
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
    let nla = ps(&format!(
        r"(Get-ItemProperty '{cle}\WinStations\RDP-Tcp').UserAuthentication"
    ))
    .is_some_and(|v| v == "1");
    let couper = format!("Set-ItemProperty '{cle}' -Name fDenyTSConnections -Value 1");
    // Session ouverte PAR le Bureau à distance (SESSIONNAME = RDP-Tcp#…) : le couper couperait l'utilisateur
    // lui-même. Jamais en correction automatique dans ce cas.
    if session_a_distance() {
        alerte("Bureau à distance", Niveau::Moyen, "RDP activé ; tu es connecté par lui en ce moment.").manuel(
            "Ne pas le couper d'ici (tu perdrais la connexion). S'il n'est pas utile, le désactiver depuis l'écran de l'ordinateur : Paramètres > Système > Bureau à distance",
            &[],
        )
    } else if nla {
        alerte(
            "Bureau à distance",
            Niveau::Moyen,
            "RDP activé (avec NLA). Très attaqué s'il est exposé.",
        )
        .corriger("Désactiver le Bureau à distance si tu ne l'utilises pas", &[&couper])
    } else {
        alerte(
            "Bureau à distance",
            Niveau::Eleve,
            "RDP activé SANS authentification au niveau réseau (NLA).",
        )
        .corriger(
            "Exiger NLA pour le Bureau à distance",
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
            "Contrôle de compte d'utilisateur (UAC) désactivé : tout programme a les droits admin.",
        )
        .corriger(
            "Réactiver l'UAC (effectif après redémarrage)",
            &[&format!("Set-ItemProperty '{cle}' -Name EnableLUA -Value 1")],
        )
    } else {
        ok("UAC", "Contrôle de compte d'utilisateur actif.")
    }
}

fn mises_a_jour() -> Constat {
    let jours = ps("((Get-Date) - (Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn).Days")
        .and_then(|j| j.parse::<i64>().ok());
    match jours {
        Some(j) if j > 45 => alerte(
            "Mises à jour",
            Niveau::Eleve,
            format!("Dernière mise à jour Windows il y a {j} jours."),
        )
        .manuel(
            "Ouvrir Windows Update et installer les mises à jour",
            &["Start-Process ms-settings:windowsupdate"],
        ),
        Some(j) => ok(
            "Mises à jour",
            format!("Dernière mise à jour Windows il y a {j} jours."),
        ),
        None => impossible("Mises à jour", "historique Windows Update illisible"),
    }
}

fn chiffrement() -> Constat {
    // Lisible sans droits admin, contrairement à Get-BitLockerVolume. 1, 3 et 5 = protégé.
    let etat = ps(
        "(New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')",
    );
    match etat.as_deref() {
        Some("1" | "3" | "5") => ok("Chiffrement", "Disque C: chiffré (BitLocker)."),
        Some(_) => alerte(
            "Chiffrement",
            Niveau::Moyen,
            "Disque C: non chiffré : en cas de vol, les données sont lisibles.",
        )
        .manuel(
            "Paramètres > Confidentialité et sécurité > Chiffrement de l'appareil (ou BitLocker sur Pro)",
            &["Start-Process ms-settings:deviceencryption"],
        ),
        None => impossible("Chiffrement", "état BitLocker illisible"),
    }
}

fn invite() -> Constat {
    match ps("(Get-LocalUser | Where-Object { $_.Enabled -and $_.SID -like '*-501' }).Name") {
        None => illisible("Comptes"),
        Some(nom) if !nom.is_empty() => alerte("Comptes", Niveau::Eleve, format!("Compte invité « {nom} » activé."))
            .corriger(
                "Désactiver le compte invité",
                &[&format!("Disable-LocalUser -Name '{nom}'")],
            ),
        _ => ok("Comptes", "Compte invité désactivé."),
    }
}

fn ports_ecoute(pare_feu_actif: bool, ip_lan: Option<&str>) -> Vec<Constat> {
    let Some(liste) = ps(
        "Get-NetTCPConnection -State Listen | ForEach-Object { \"$($_.LocalAddress)|$($_.LocalPort)|$((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName)\" }",
    ) else {
        return vec![illisible("Ports en écoute")];
    };
    // Ports déjà bloqués en entrée par une règle netscan active : le port écoute toujours, mais n'est plus joignable.
    // Sans cette lecture, l'alerte et la même correction (une règle de plus à chaque fois) revenaient à chaque audit.
    let bloques: Vec<u16> = if pare_feu_actif {
        ps(
            "@(Get-NetFirewallRule -DisplayName 'netscan : bloquer *' -ErrorAction SilentlyContinue | \
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
                format!(
                    "{port}/tcp ({}) ouvert par « {programme} », bloqué en entrée par la règle « netscan : bloquer {port} » du pare-feu Windows.",
                    i.service
                ),
            ));
            continue;
        }
        let niveau = super::niveau_expose(pare_feu_actif, i.niveau);
        let constat = alerte(
            "Ports en écoute",
            niveau,
            format!("{port}/tcp ({}) ouvert par « {programme} ». {}", i.service, i.conseil),
        );
        // RDP : pas de blocage aveugle, il coupe l'accès aux machines pilotées à distance (VM…).
        // Le constat « Bureau à distance » propose déjà NLA ou la désactivation propre.
        constats.push(if niveau >= Niveau::Moyen && port != 3389 {
            constat.corriger(
                format!("Bloquer le port {port} en entrée dans le pare-feu Windows"),
                &[&format!("New-NetFirewallRule -DisplayName 'netscan : bloquer {port}' -Direction Inbound -Protocol TCP -LocalPort {port} -Action Block")],
            )
            .bloquant(format!("{port}/tcp"))
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
    let routeur = "Ouvrir l'admin du routeur > Wi-Fi > Sécurité : choisir « WPA2/WPA3 » ou « WPA3 »";
    Some(if auth.contains("WPA3") {
        ok("Wi-Fi", format!("« {ssid} » en {auth}."))
    } else if auth.contains("WPA2") {
        alerte(
            "Wi-Fi",
            Niveau::Info,
            format!("« {ssid} » en {auth}. WPA3 serait mieux si le routeur le permet."),
        )
        .manuel(routeur, &[])
    } else {
        alerte(
            "Wi-Fi",
            Niveau::Eleve,
            format!("« {ssid} » en {auth} : réseau ouvert ou chiffrement faible."),
        )
        .manuel(routeur, &[])
    })
}

pub fn auditer() -> Audit {
    let feu = pare_feu();
    let feu_actif = feu.probleme.is_none();
    let ip_lan = crate::scan::reseau_local().map(|l| l.1.to_string());
    let mut constats = vec![feu];
    constats.extend(antivirus());
    constats.extend(ports_ecoute(feu_actif, ip_lan.as_deref()));
    constats.extend(smb1());
    constats.push(bureau_distance());
    constats.push(uac());
    constats.push(mises_a_jour());
    constats.push(chiffrement());
    constats.push(invite());
    constats.extend(wifi());
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
    fn jamais_couper_le_bureau_a_distance_qu_on_utilise() {
        // SAFETY (test) : variable propre au processus de test.
        unsafe { std::env::set_var("SESSIONNAME", "RDP-Tcp#3") };
        assert!(session_a_distance());
    }

    #[test]
    fn la_fenetre_admin_annonce_chaque_etape() {
        let s = script_admin(&[
            "Update-MpSignature".to_string(),
            "Disable-LocalUser -Name 'Invité'".to_string(),
        ]);
        assert!(s.contains("> Update-MpSignature (peut prendre quelques minutes)"));
        assert!(s.contains("> Disable-LocalUser -Name ''Invité''"));
        assert!(s.contains("Read-Host"));
        // Un programme externe en échec est signalé, pas affiché « OK ».
        assert_eq!(s.matches("$global:LASTEXITCODE = 0").count(), 2);
        assert!(s.contains("$echecs++") && s.contains("exit 1 }"));
    }
}
