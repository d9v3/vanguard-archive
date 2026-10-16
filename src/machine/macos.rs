//! Audit de sécurité macOS (sans sudo pour l'audit ; les correctifs le demandent dans le terminal).

use std::process::Command;

use super::{Audit, Constat, alerte, cles_ssh, ok, score, sortie};
use crate::risk::{Niveau, info_port};

pub const NOM: &str = "macOS";

const FIREWALL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// Sortie standard + erreur (certains outils Apple écrivent sur stderr).
fn tout(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
        .unwrap_or_default()
}

fn pare_feu() -> Vec<Constat> {
    let etat = tout(FIREWALL, &["--getglobalstate"]);
    if !etat.contains("enabled") {
        return vec![alerte("Pare-feu", Niveau::Eleve, "Pare-feu macOS désactivé.").corriger(
            "Activer le pare-feu et le mode furtif",
            &[&format!("sudo {FIREWALL} --setglobalstate on"), &format!("sudo {FIREWALL} --setstealthmode on")],
        )];
    }
    let mut c = vec![ok("Pare-feu", "Pare-feu macOS actif.")];
    if !tout(FIREWALL, &["--getstealthmode"]).contains("enabled") {
        c.push(
            alerte("Pare-feu", Niveau::Info, "Mode furtif désactivé : le Mac répond aux sondes réseau.")
                .corriger("Activer le mode furtif", &[&format!("sudo {FIREWALL} --setstealthmode on")]),
        );
    }
    c
}

fn filevault() -> Constat {
    if tout("fdesetup", &["status"]).contains("FileVault is On") {
        ok("Chiffrement", "FileVault actif.")
    } else {
        // Manuel : l'activation affiche une clé de secours qu'il faut absolument noter.
        alerte("Chiffrement", Niveau::Moyen, "FileVault désactivé : en cas de vol, les données sont lisibles.")
            .manuel("Réglages Système > Confidentialité et sécurité > FileVault > Activer (note la clé de secours !)", &[])
    }
}

fn gatekeeper() -> Constat {
    if tout("spctl", &["--status"]).contains("assessments enabled") {
        ok("Gatekeeper", "Gatekeeper actif (apps vérifiées).")
    } else {
        alerte("Gatekeeper", Niveau::Eleve, "Gatekeeper désactivé : n'importe quelle app peut se lancer.")
            .corriger("Réactiver Gatekeeper", &["sudo spctl --master-enable"])
    }
}

fn sip() -> Constat {
    if tout("csrutil", &["status"]).contains("enabled") {
        ok("SIP", "Protection de l'intégrité du système active.")
    } else {
        alerte("SIP", Niveau::Eleve, "SIP désactivé : les fichiers système ne sont plus protégés.")
            .manuel("Redémarrer en mode Récupération, ouvrir le Terminal et lancer : csrutil enable", &[])
    }
}

fn mises_a_jour() -> Constat {
    let liste = tout("softwareupdate", &["-l"]);
    let n = liste.lines().filter(|l| l.trim_start().starts_with("* Label:")).count();
    if n == 0 {
        ok("Mises à jour", "macOS à jour.")
    } else {
        alerte("Mises à jour", Niveau::Eleve, format!("{n} mise(s) à jour macOS en attente."))
            .corriger("Installer les mises à jour (un redémarrage peut suivre)", &["sudo softwareupdate -ia"])
    }
}

fn connexion_auto() -> Constat {
    match sortie("defaults", &["read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]) {
        Some(u) => alerte("Session", Niveau::Eleve, format!("Ouverture de session automatique pour « {} ».", u.trim())).corriger(
            "Désactiver l'ouverture de session automatique",
            &["sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser"],
        ),
        None => ok("Session", "Mot de passe demandé à l'ouverture de session."),
    }
}

fn ports_ecoute(pare_feu_actif: bool) -> Vec<Constat> {
    // netstat voit tous les ports (même ceux de root), lsof donne le nom quand c'est un de nos processus.
    let mut noms = std::collections::HashMap::new();
    for l in tout("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"]).lines().skip(1) {
        let c: Vec<&str> = l.split_whitespace().collect();
        if let (Some(nom), Some(adr)) = (c.first(), c.get(8))
            && let Some(p) = adr.rsplit(':').next().and_then(|p| p.parse::<u16>().ok())
        {
            noms.insert(p, nom.to_string());
        }
    }
    let mut vus = Vec::new();
    let mut constats = Vec::new();
    for l in tout("netstat", &["-anp", "tcp"]).lines().filter(|l| l.contains("LISTEN")) {
        let Some(local) = l.split_whitespace().nth(3) else { continue };
        let Some((adresse, port)) = local.rsplit_once('.') else { continue };
        let Ok(port) = port.parse::<u16>() else { continue };
        if adresse != "*" || vus.contains(&port) {
            continue;
        }
        vus.push(port);
        let programme = noms.get(&port).cloned().unwrap_or_else(|| "service système".into());
        let i = info_port(port);
        let niveau = match (pare_feu_actif, i.niveau) {
            (true, Niveau::Critique) => Niveau::Eleve,
            (true, Niveau::Eleve) => Niveau::Moyen,
            (true, _) => Niveau::Info,
            (false, Niveau::Info) => Niveau::Moyen,
            (false, n) => n,
        };
        let constat = alerte("Ports en écoute", niveau, format!("{port}/tcp ({}) ouvert par « {programme} ». {}", i.service, i.conseil));
        constats.push(match port {
            22 => constat.corriger("Désactiver la session à distance (SSH)", &["sudo systemsetup -f -setremotelogin off"]),
            5900 => constat.manuel("Réglages Système > Général > Partage > désactiver « Partage d'écran »", &[]),
            445 => constat.manuel("Réglages Système > Général > Partage > désactiver « Partage de fichiers » si inutile", &[]),
            5000 | 7000 => constat.manuel("Réglages Système > Général > AirDrop et Handoff > « Récepteur AirPlay » si inutile", &[]),
            _ => constat,
        });
    }
    if constats.is_empty() {
        constats.push(ok("Ports en écoute", "Aucun service TCP exposé au réseau."));
    }
    constats
}

fn wifi() -> Option<Constat> {
    let texte = tout("system_profiler", &["SPAirPortDataType"]);
    let actuel = texte.split_once("Current Network Information:")?.1;
    let secu = actuel.lines().find_map(|l| l.trim().strip_prefix("Security:"))?.trim().to_string();
    let routeur = "Ouvrir l'admin du routeur > Wi-Fi > Sécurité : choisir « WPA2/WPA3 » ou « WPA3 »";
    Some(if secu.contains("WPA3") {
        ok("Wi-Fi", format!("Réseau actuel en {secu}."))
    } else if secu.contains("WPA2") {
        alerte("Wi-Fi", Niveau::Info, format!("Réseau actuel en {secu}. WPA3 serait mieux.")).manuel(routeur, &[])
    } else {
        alerte("Wi-Fi", Niveau::Eleve, format!("Réseau actuel en « {secu} » : ouvert ou chiffrement faible.")).manuel(routeur, &[])
    })
}

pub fn auditer() -> Audit {
    let mut constats = pare_feu();
    let feu_actif = constats[0].probleme.is_none();
    constats.extend(ports_ecoute(feu_actif));
    constats.push(mises_a_jour());
    constats.push(filevault());
    constats.push(gatekeeper());
    constats.push(sip());
    constats.push(connexion_auto());
    constats.extend(cles_ssh());
    constats.extend(wifi());
    Audit { systeme: NOM, score: score(&constats), constats }
}
