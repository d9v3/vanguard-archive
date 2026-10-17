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
fn illisible(categorie: &'static str) -> Constat {
    impossible(categorie, "PowerShell indisponible ou bloqué")
}

/// Le script exécuté dans la fenêtre administrateur : chaque commande est annoncée, puis « OK » ou l'erreur.
/// Une fenêtre muette ne se distingue pas d'une fenêtre figée. Chaque étape a son try/catch : une erreur PowerShell
/// compte, comme un programme externe en échec, pour une étape ratée, et la fenêtre passe à la suivante.
fn script_admin(commandes: &[String]) -> String {
    let texte = |s: &str| s.replace('\'', "''");
    let mut script = String::from(
        "$Host.UI.RawUI.WindowTitle = 'netscan : correction en cours'\n\
         [Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
         $ErrorActionPreference = 'Stop'\n\
         Write-Host 'netscan applique une correction.' -ForegroundColor Cyan\n\
         $echecs = 0\n",
    );
    for c in commandes {
        let long = [
            "Update-MpSignature",
            "Remove-MpThreat",
            "Start-MpScan",
            "DISM",
            "sfc",
            "Checkpoint-Computer",
            "CreateUpdate",
            "winget",
        ]
        .iter()
        .any(|l| c.contains(l));
        let note = if long { " (peut prendre quelques minutes)" } else { "" };
        // Un programme externe (DISM, sfc, netsh…) en échec ne lève pas d'erreur PowerShell : seul son code de
        // retour le dit. On le lit après chaque commande (3010 = réussi, redémarrage demandé) et on continue :
        // dans « Internet ne marche plus », un netsh en échec ne doit pas empêcher de renouveler l'adresse.
        let _ = write!(
            script,
            "Write-Host ''; Write-Host '> {}{note}' -ForegroundColor Yellow\n$global:LASTEXITCODE = 0\ntry {{\n  {c}\n  \
             if ($LASTEXITCODE -eq 3010) {{ Write-Host '  OK (redémarrage nécessaire)' -ForegroundColor Green }}\n  \
             elseif ($LASTEXITCODE) {{ $echecs++; Write-Host \"  Échec (code $LASTEXITCODE) : voir le message ci-dessus\" -ForegroundColor Red }}\n  \
             else {{ Write-Host '  OK' -ForegroundColor Green }}\n\
             }} catch {{ $echecs++; Write-Host ('  Échec : ' + $_.Exception.Message) -ForegroundColor Red }}\n",
            texte(c)
        );
    }
    script += "if ($echecs) { Write-Host ''; Write-Host \"Terminé, avec $echecs étape(s) en échec.\" -ForegroundColor Red; Read-Host 'Appuie sur Entrée pour fermer'; exit 1 }\n\
               Write-Host ''; Write-Host 'Terminé.' -ForegroundColor Green; Read-Host 'Appuie sur Entrée pour fermer'; exit 0";
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
    // Attente sans limite : la fenêtre est visible et attend Entrée, un délai compterait aussi le temps de lecture.
    let lanceur = format!(
        "$p = Start-Process powershell -Verb RunAs -PassThru -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"{fichier}\"'; \
         if (-not $p) {{ Write-Host 'Demande d''administrateur refusée : rien n''a été modifié.'; exit 3 }}; \
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
    c.push(signatures(v["AntivirusSignatureAge"].as_u64().unwrap_or(0)));
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

/// « a ; b ; c (et 2 autres) » : les premiers noms d'une liste, pour un message d'une ligne.
fn resume(noms: &[impl AsRef<str>], separateur: &str) -> String {
    const MAX: usize = 3;
    let mut t = noms
        .iter()
        .take(MAX)
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(separateur);
    if noms.len() > MAX {
        let _ = write!(t, " (et {} autre(s))", noms.len() - MAX);
    }
    t
}

/// Commandes de la fenêtre administrateur qui téléchargent et installent les mises à jour d'un type
/// (« Software » ou « Driver ») par l'API de Windows Update, comme le bouton « Tout installer ».
fn installer_windows_update(genre: &str) -> Vec<String> {
    vec![
        format!(
            "$maj = New-Object -ComObject Microsoft.Update.Session; $liste = New-Object -ComObject Microsoft.Update.UpdateColl; \
             foreach ($u in $maj.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0 and Type='{genre}'\").Updates) \
             {{ if (-not $u.EulaAccepted) {{ $u.AcceptEula() }}; [void]$liste.Add($u); Write-Host \"  - $($u.Title)\" }}"
        ),
        // Une mise à jour non téléchargée (vu dans la VM : Windows Update bloqué sur « En attente de
        // téléchargement ») ne doit pas passer pour installée : chacune est vérifiée et nommée.
        "if ($liste.Count) { $t = $maj.CreateUpdateDownloader(); $t.Updates = $liste; \
         try { [void]$t.Download() } catch { Write-Host \"  Téléchargement interrompu : $($_.Exception.Message)\" -ForegroundColor Red } }; \
         $pret = New-Object -ComObject Microsoft.Update.UpdateColl; $ko = 0; \
         foreach ($u in $liste) { if ($u.IsDownloaded) { [void]$pret.Add($u) } \
         else { $ko++; Write-Host \"  Pas téléchargée : $($u.Title)\" -ForegroundColor Red } }"
            .into(),
        "$r = $null; if ($pret.Count) { $i = $maj.CreateUpdateInstaller(); $i.Updates = $pret; $r = $i.Install() }; \
         if ($r) { for ($n = 0; $n -lt $pret.Count; $n++) { $code = $r.GetUpdateResult($n).ResultCode; \
         if ($code -eq 2) { Write-Host \"  Installée : $($pret.Item($n).Title)\" -ForegroundColor Green } \
         else { $ko++; Write-Host \"  Pas installée (code $code) : $($pret.Item($n).Title)\" -ForegroundColor Red } } }; \
         if ($r -and $r.RebootRequired) { Write-Host '  Redémarrage nécessaire pour finir.' -ForegroundColor Yellow }; \
         if ($ko) { throw \"$ko mise(s) à jour à refaire plus tard (ou Paramètres > Windows Update)\" }"
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
            impossible("Windows Update", "recherche impossible, hors ligne ?"),
            impossible("Pilotes", "recherche Windows Update impossible"),
        ];
    };
    let (pilotes, logiciels): (Vec<_>, Vec<_>) = lire_windows_update(&sortie).into_iter().partition(|m| m.pilote);
    vec![
        constat_windows_update(
            "Windows Update",
            "Windows à jour (correctifs, .NET, Defender).",
            "mise(s) à jour en attente",
            "Télécharger et installer les mises à jour de Windows",
            "Software",
            &logiciels,
        ),
        constat_windows_update(
            "Pilotes",
            "Aucun pilote à mettre à jour dans Windows Update.",
            "pilote(s) à mettre à jour",
            "Installer les pilotes proposés par Windows Update",
            "Driver",
            &pilotes,
        ),
    ]
}

/// « À jour », ou la liste des mises à jour d'un type (« Software », « Driver ») avec leur installation.
fn constat_windows_update(
    categorie: &'static str,
    a_jour: &str,
    quoi: &str,
    action: &str,
    genre: &str,
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
        format!("{} {quoi} : {}.", liste.len(), resume(&titres, " ; ")),
    )
    .corriger(action, &installer_windows_update(genre))
}

fn redemarrage_en_attente() -> Constat {
    let attente = ps(
        "[bool]((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired -or \
         (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'))",
    );
    match attente.as_deref() {
        Some(a) if a.eq_ignore_ascii_case("true") => alerte(
            "Redémarrage",
            Niveau::Moyen,
            "Des mises à jour attendent un redémarrage pour être actives.",
        )
        .manuel("Redémarrer quand c'est pratique", &["Restart-Computer"]),
        Some(a) if a.eq_ignore_ascii_case("false") => ok("Redémarrage", "Aucun redémarrage en attente."),
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
            "Installer « Programme d'installation d'application » depuis le Microsoft Store",
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
                &format!("winget en erreur (code {})", code.map_or("?".into(), |c| c.to_string())),
            );
        }
    };
    if programmes.is_empty() {
        return ok("Programmes", "Programmes à jour (winget).");
    }
    let noms: Vec<&str> = programmes.iter().map(|(n, _)| n.as_str()).collect();
    alerte(
        "Programmes",
        Niveau::Moyen,
        format!("{} programme(s) à mettre à jour : {}.", noms.len(), resume(&noms, ", ")),
    )
    .corriger(
        "Mettre à jour ces programmes avec winget",
        &commandes_winget(&programmes),
    )
}

/// Périphériques en erreur dans le Gestionnaire de périphériques (pilote absent, qui ne démarre pas…).
fn peripheriques() -> Constat {
    // 22 = désactivé à la main : un choix, pas une panne. Sans nom, l'identifiant matériel (PCI\VEN_1AF4&DEV_1045…)
    // le remplace : c'est lui qu'on cherche sur Internet pour trouver le pilote.
    let Some(sortie) = ps(
        "Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0 AND ConfigManagerErrorCode <> 22' | \
         ForEach-Object { \"$($_.ConfigManagerErrorCode)|$(if ($_.Name) { $_.Name } else { $_.PNPDeviceID })\" }",
    ) else {
        return illisible("Périphériques");
    };
    let en_panne: Vec<String> = sortie
        .lines()
        .filter_map(|l| l.trim().split_once('|'))
        .map(|(code, nom)| {
            let nom = if nom.trim().is_empty() {
                "Périphérique inconnu"
            } else {
                nom.trim()
            };
            match code {
                "28" | "1" => format!("{nom} (pas de pilote)"),
                _ => format!("{nom} (erreur {code})"),
            }
        })
        .collect();
    if en_panne.is_empty() {
        return ok("Périphériques", "Tous les périphériques ont un pilote qui fonctionne.");
    }
    alerte(
        "Périphériques",
        Niveau::Moyen,
        format!(
            "{} périphérique(s) sans pilote ou en erreur : {}.",
            en_panne.len(),
            resume(&en_panne, ", ")
        ),
    )
    .manuel(
        "Chercher le pilote dans Windows Update > Options avancées > Mises à jour facultatives, sinon sur le site du fabricant",
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
fn cartes_graphiques() -> Vec<Constat> {
    let Some(sortie) = ps("Get-CimInstance Win32_VideoController | ForEach-Object { \
         \"$($_.Name)|$($_.DriverVersion)|$(if ($_.DriverDate) { ((Get-Date) - $_.DriverDate).Days })\" }")
    else {
        return vec![illisible("Carte graphique")];
    };
    sortie
        .lines()
        .filter_map(|l| {
            let mut c = l.trim().splitn(3, '|');
            let (nom, version, jours) = (c.next()?.trim(), c.next()?.trim(), c.next()?.trim().parse::<u32>().ok());
            let (outil, lien) = pilote_fabricant(nom)?;
            let manuel = format!("Mettre le pilote à jour avec {outil}");
            let ouvrir = format!("Start-Process {lien}");
            Some(match jours {
                Some(j) if j > 180 => alerte(
                    "Carte graphique",
                    Niveau::Moyen,
                    format!("{nom} : pilote {version} vieux de {j} jours."),
                )
                .manuel(manuel, &[&ouvrir]),
                Some(j) => ok("Carte graphique", format!("{nom} : pilote {version} de {j} jours.")),
                None => ok("Carte graphique", format!("{nom} : pilote {version}.")),
            })
        })
        .collect()
}

/// Signatures de Defender : la même règle pour l'audit et pour `netscan maj`.
fn signatures(age: u64) -> Constat {
    if age > 3 {
        alerte(
            "Signatures",
            Niveau::Moyen,
            format!("Signatures antivirus vieilles de {age} jours."),
        )
        .corriger("Mettre à jour les signatures", &["Update-MpSignature"])
    } else {
        ok("Signatures", "Signatures de Defender à jour.")
    }
}

/// `None` avec un antivirus tiers : Defender n'a alors pas de signatures à tenir à jour.
fn signatures_defender() -> Option<Constat> {
    let age = ps("(Get-MpComputerStatus).AntivirusSignatureAge")?.parse().ok()?;
    Some(signatures(age))
}

/// Tout ce qui doit être à jour : Windows, ses pilotes, les programmes, Defender. Tout tourne en parallèle :
/// Windows Update et winget prennent chacun jusqu'à deux minutes, chaque PowerShell met une seconde à démarrer.
pub fn mises_a_jour_completes() -> Vec<Constat> {
    std::thread::scope(|portee| {
        let wu = portee.spawn(windows_update);
        let redemarrage = portee.spawn(redemarrage_en_attente);
        let signatures = portee.spawn(signatures_defender);
        let winget = portee.spawn(programmes);
        let peripheriques = portee.spawn(peripheriques);
        let cartes = portee.spawn(cartes_graphiques);
        let mut constats = wu.join().unwrap_or_default();
        constats.push(redemarrage.join().unwrap_or_else(|_| illisible("Redémarrage")));
        constats.extend(signatures.join().ok().flatten());
        constats.push(winget.join().unwrap_or_else(|_| illisible("Programmes")));
        constats.push(peripheriques.join().unwrap_or_else(|_| illisible("Périphériques")));
        constats.extend(cartes.join().unwrap_or_default());
        constats
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
        assert_eq!(resume(&resume_noms, ", "), "a, b, c (et 2 autre(s))");
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
        assert!(s.contains("> Update-MpSignature (peut prendre quelques minutes)"));
        assert!(s.contains("> Disable-LocalUser -Name ''Invité''"));
        assert!(s.contains("Read-Host"));
        // Un programme externe en échec est signalé, pas affiché « OK ».
        assert_eq!(s.matches("$global:LASTEXITCODE = 0").count(), 2);
        assert!(s.contains("$echecs++") && s.contains("exit 1 }"));
        // Chaque étape a son try/catch : une erreur PowerShell n'arrête pas les suivantes.
        assert_eq!(s.matches("} catch {").count(), 2);
    }
}
