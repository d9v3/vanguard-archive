//! Ce que Linux et macOS vérifient de la même façon : fichiers secrets lisibles par d'autres comptes, sudo sans mot de
//! passe. Chaque système garde ses mots à lui (« la machine », « le Mac ») et ce qu'il vérifie en plus
//! (machine/linux/privileges.rs, machine/macos/privileges.rs).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::{Constat, alerte, ok, sortie};
use crate::risk::Niveau;
use crate::{tr, trf};

/// Fichiers qui contiennent des mots de passe ou des jetons d'accès, chemin relatif au dossier personnel.
const SECRETS: &[&str] = &[
    ".git-credentials",
    ".netrc",
    ".pgpass",
    ".my.cnf",
    ".npmrc",
    ".pypirc",
    ".aws/credentials",
    ".docker/config.json",
    ".kube/config",
    ".config/gh/hosts.yml",
    ".config/rclone/rclone.conf",
    ".gnupg",
];

/// Un secret est mal protégé si le groupe ou les autres comptes peuvent le lire (ou y entrer, pour un dossier).
pub(super) fn secret_expose(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// Les fichiers secrets de `maison`, et le dossier personnel lui-même. `dossier_ouvert` : le texte de l'alerte quand
/// les autres comptes peuvent lire le dossier personnel (il nomme la machine ou le Mac).
pub(super) fn fichiers_secrets(maison: &Path, dossier_ouvert: &str) -> Vec<Constat> {
    let mut exposes = Vec::new();
    let mut commandes = Vec::new();
    for nom in SECRETS {
        let chemin = maison.join(nom);
        // Droits du fichier lui-même, pas du lien : un lien symbolique (stow, chezmoi…) a toujours 777,
        // ce qui donnait une fausse alerte, jamais corrigée par le chmod.
        let Ok(meta) = std::fs::metadata(&chemin) else {
            continue;
        };
        if secret_expose(meta.permissions().mode()) {
            exposes.push(format!("~/{nom}"));
            commandes.push(format!("chmod {} ~/{nom}", if meta.is_dir() { "700" } else { "600" }));
        }
    }
    let mut constats = Vec::new();
    if !exposes.is_empty() {
        let cmds: Vec<&str> = commandes.iter().map(String::as_str).collect();
        constats.push(
            alerte(
                "Fichiers secrets",
                Niveau::Eleve,
                trf!(
                    "Lisible(s) par d'autres comptes : {} (mots de passe ou jetons d'accès).",
                    "Readable by other accounts: {} (passwords or access tokens).",
                    exposes.join(", ")
                ),
            )
            .corriger(
                tr!("Réserver ces fichiers à toi seul", "Restrict these files to you only"),
                &cmds,
            ),
        );
    }
    // Le dossier personnel lui-même (macOS le ferme d'origine, droits 750) : ouvert en lecture, il laisse voir tous tes
    // fichiers aux autres comptes.
    if std::fs::metadata(maison).is_ok_and(|m| m.permissions().mode() & 0o007 != 0) {
        constats.push(alerte("Fichiers secrets", Niveau::Info, dossier_ouvert).corriger(
            tr!(
                "Fermer ton dossier personnel aux autres comptes",
                "Close your home folder to the other accounts"
            ),
            &["chmod 750 ~"],
        ));
    }
    if constats.is_empty() {
        constats.push(ok(
            "Fichiers secrets",
            tr!(
                "Fichiers de mots de passe et de jetons protégés.",
                "Password and token files are protected."
            ),
        ));
    }
    constats
}

/// Règles « sudo sans mot de passe » : (règles qui donnent tout, règles limitées à des commandes précises).
pub(super) fn regles_nopasswd(liste: &str) -> (Vec<String>, usize) {
    let mut totales = Vec::new();
    let mut limitees = 0;
    for l in liste.lines().map(str::trim).filter(|l| l.contains("NOPASSWD:")) {
        let commandes = l.split_once("NOPASSWD:").map_or("", |(_, c)| c).trim();
        if commandes == "ALL" || commandes.starts_with("ALL,") {
            totales.push(l.to_string());
        } else {
            limitees += 1;
        }
    }
    (totales, limitees)
}

/// sudo sans mot de passe. `tout_permis` : le texte de l'alerte quand une règle donne toutes les commandes (il dit ce
/// que risque ce système).
/// Réglages par défaut de sudo qui valent pour ce compte (« Matching Defaults entries », première section de
/// `sudo -l`) : (sudo ne demande jamais le mot de passe, délai de mémorisation en minutes s'il est donné).
pub(super) fn defauts_sudo(liste: &str) -> (bool, Option<f64>) {
    let mut sans_mot_de_passe = false;
    let mut delai = None;
    let mut lignes = liste
        .lines()
        .skip_while(|l| !l.starts_with("Matching Defaults entries"));
    lignes.next();
    for ligne in lignes.take_while(|l| !l.trim().is_empty()) {
        // Une longue liste peut être coupée en fin de ligne après une virgule : elle est retirée.
        for reglage in ligne.split(", ").map(|r| r.trim().trim_end_matches(',')) {
            if reglage == "!authenticate" {
                sans_mot_de_passe = true;
            } else if reglage == "authenticate" {
                sans_mot_de_passe = false;
            } else if let Some(v) = reglage.strip_prefix("timestamp_timeout=") {
                delai = v.trim_matches('"').parse::<f64>().ok().or(delai);
            }
        }
    }
    (sans_mot_de_passe, delai)
}

pub(super) fn sudo_sans_mot_de_passe(tout_permis: &str) -> Vec<Constat> {
    // -n : jamais de demande de mot de passe. Sans règle NOPASSWD (ni sudo récent), la liste est refusée : rien à dire.
    let Some(liste) = sortie("sudo", &["-n", "-l"]) else {
        return Vec::new();
    };
    let (totales, limitees) = regles_nopasswd(&liste);
    let (jamais_demande, delai) = defauts_sudo(&liste);
    let mut constats = Vec::new();
    if jamais_demande {
        constats.push(
            alerte(
                "Sudo",
                Niveau::Eleve,
                tr!(
                    "sudo ne demande jamais le mot de passe (« Defaults !authenticate ») : n'importe quel programme lancé par toi peut devenir root.",
                    "sudo never asks for the password (“Defaults !authenticate”): any program you run can become root."
                ),
            )
            .manuel(
                tr!(
                    "Retirer « !authenticate » des Defaults dans /etc/sudoers ou /etc/sudoers.d (toujours avec sudo visudo)",
                    "Remove “!authenticate” from the Defaults in /etc/sudoers or /etc/sudoers.d (always with sudo visudo)"
                ),
                &["sudo visudo"],
            ),
        );
    } else if let Some(minutes) = delai.filter(|&m| m < 0.0 || m > 60.0) {
        let message = if minutes < 0.0 {
            tr!(
                "sudo ne redemande jamais le mot de passe une fois tapé (« timestamp_timeout » négatif) : tout programme lancé ensuite dans ce terminal peut devenir root sans rien demander.",
                "sudo never asks for the password again once typed (negative “timestamp_timeout”): any program started later in that terminal can become root without asking."
            )
            .to_string()
        } else {
            trf!(
                "sudo garde le mot de passe {} minutes (« timestamp_timeout ») : un programme lancé pendant ce temps devient root sans rien demander.",
                "sudo keeps the password for {} minutes (“timestamp_timeout”): a program started during that time becomes root without asking.",
                minutes.round()
            )
        };
        constats.push(
            alerte("Sudo", if minutes < 0.0 { Niveau::Moyen } else { Niveau::Info }, message).manuel(
                tr!(
                    "Remettre le délai de sudo à 5 minutes, ou retirer « timestamp_timeout » (toujours avec sudo visudo)",
                    "Set sudo's delay back to 5 minutes, or remove “timestamp_timeout” (always with sudo visudo)"
                ),
                &["sudo visudo"],
            ),
        );
    }
    if !totales.is_empty() {
        constats.push(alerte("Sudo", Niveau::Eleve, tout_permis).manuel(
            tr!(
                "Retirer « NOPASSWD: » de cette règle dans /etc/sudoers.d (toujours avec sudo visudo, jamais à la main)",
                "Remove “NOPASSWD:” from this rule in /etc/sudoers.d (always with sudo visudo, never by hand)"
            ),
            &["sudo visudo"],
        ));
    } else if jamais_demande {
        // Déjà dit plus haut : pas de « demande toujours le mot de passe ».
    } else if limitees > 0 {
        constats.push(ok(
            "Sudo",
            trf!(
                "{limitees} règle(s) sudo sans mot de passe, limitée(s) à des commandes précises.",
                "{limitees} passwordless sudo rule(s), limited to specific commands."
            ),
        ));
    } else {
        constats.push(ok(
            "Sudo",
            tr!(
                "sudo demande toujours le mot de passe.",
                "sudo always asks for the password."
            ),
        ));
    }
    constats
}
