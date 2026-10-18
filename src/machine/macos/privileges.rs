//! Privilèges sous macOS : fichiers de mots de passe et de jetons lisibles par d'autres comptes, sudo sans mot de
//! passe, compte root activé. Mêmes vérifications que sous Linux (machine/linux/privileges.rs), avec ce que macOS
//! a en propre.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use super::{Constat, alerte, maison, ok, sortie};
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
fn secret_expose(mode: u32) -> bool {
    mode & 0o077 != 0
}

pub(super) fn fichiers_secrets() -> Vec<Constat> {
    let maison = maison();
    let mut exposes = Vec::new();
    let mut commandes = Vec::new();
    for nom in SECRETS {
        // Droits du fichier lui-même, pas du lien (un lien symbolique a toujours 777).
        let Ok(meta) = std::fs::metadata(maison.join(nom)) else {
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
    // macOS ferme le dossier personnel aux autres comptes (droits 750) : ouvert, il laisse voir tous tes fichiers.
    if std::fs::metadata(&maison).is_ok_and(|m| m.permissions().mode() & 0o007 != 0) {
        constats.push(
            alerte(
                "Fichiers secrets",
                Niveau::Info,
                tr!(
                    "Ton dossier personnel est lisible par les autres comptes du Mac.",
                    "Your home folder is readable by the Mac's other accounts."
                ),
            )
            .corriger(
                tr!(
                    "Fermer ton dossier personnel aux autres comptes",
                    "Close your home folder to the other accounts"
                ),
                &["chmod 750 ~"],
            ),
        );
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

/// Règles « sudo sans mot de passe » qui donnent tout, et nombre de celles limitées à des commandes précises.
fn regles_nopasswd(liste: &str) -> (usize, usize) {
    let mut totales = 0;
    let mut limitees = 0;
    for l in liste.lines().map(str::trim).filter(|l| l.contains("NOPASSWD:")) {
        let commandes = l.split_once("NOPASSWD:").map_or("", |(_, c)| c).trim();
        if commandes == "ALL" || commandes.starts_with("ALL,") {
            totales += 1;
        } else {
            limitees += 1;
        }
    }
    (totales, limitees)
}

pub(super) fn sudo_sans_mot_de_passe() -> Option<Constat> {
    // -n : jamais de demande de mot de passe. Sans règle NOPASSWD (ni sudo récent), la liste est refusée : rien à dire.
    let liste = sortie("sudo", &["-n", "-l"])?;
    let (totales, limitees) = regles_nopasswd(&liste);
    Some(if totales > 0 {
        alerte(
            "Sudo",
            Niveau::Eleve,
            tr!(
                "sudo sans mot de passe pour TOUTES les commandes : n'importe quel programme lancé par toi peut prendre la main sur le Mac.",
                "sudo without a password for ALL commands: any program you run can take over the Mac."
            ),
        )
        .manuel(
            tr!(
                "Retirer « NOPASSWD: » de cette règle dans /etc/sudoers.d (toujours avec sudo visudo, jamais à la main)",
                "Remove “NOPASSWD:” from this rule in /etc/sudoers.d (always with sudo visudo, never by hand)"
            ),
            &["sudo visudo"],
        )
    } else if limitees > 0 {
        ok(
            "Sudo",
            trf!(
                "{limitees} règle(s) sudo sans mot de passe, limitée(s) à des commandes précises.",
                "{limitees} passwordless sudo rule(s), limited to specific commands."
            ),
        )
    } else {
        ok(
            "Sudo",
            tr!(
                "sudo demande toujours le mot de passe.",
                "sudo always asks for the password."
            ),
        )
    })
}

/// Le compte root a-t-il un mot de passe (activé) ? macOS le laisse désactivé d'origine. `None` : illisible.
fn lire_root(sortie: &str, erreurs: &str) -> Option<bool> {
    if erreurs.contains("No such key") || sortie.contains("DisabledUser") {
        Some(false)
    } else if sortie.contains("ShadowHash") || sortie.contains("Kerberosv5") {
        Some(true)
    } else {
        None
    }
}

pub(super) fn compte_root() -> Option<Constat> {
    let r = crate::commande::lancer(
        Command::new("dscl").args([".", "-read", "/Users/root", "AuthenticationAuthority"]),
        10,
    )?;
    Some(if lire_root(&r.sortie, &r.erreurs)? {
        alerte(
            "Comptes",
            Niveau::Moyen,
            tr!(
                "Le compte root est activé : un seul mot de passe ouvre tout le Mac, sans aucune limite.",
                "The root account is on: a single password opens the whole Mac, with no limit."
            ),
        )
        .manuel(
            tr!(
                "Désactiver root (le mot de passe d'un administrateur est demandé)",
                "Turn root off (an administrator's password is asked)"
            ),
            &["dsenableroot -d"],
        )
    } else {
        ok("Comptes", tr!("Compte root désactivé.", "Root account off."))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn droits_et_regles() {
        assert!(!secret_expose(0o100_600) && !secret_expose(0o40700));
        assert!(secret_expose(0o100_644));
        assert_eq!(regles_nopasswd("    (ALL) NOPASSWD: ALL\n"), (1, 0));
        assert_eq!(
            regles_nopasswd("    (root) NOPASSWD: /usr/bin/pmset\n    (ALL) ALL\n"),
            (0, 1)
        );
    }

    #[test]
    fn compte_root_lu() {
        assert_eq!(lire_root("", "No such key: AuthenticationAuthority"), Some(false));
        assert_eq!(
            lire_root("AuthenticationAuthority: ;DisabledUser;;ShadowHash;", ""),
            Some(false)
        );
        assert_eq!(
            lire_root(
                "AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>",
                ""
            ),
            Some(true)
        );
        assert_eq!(lire_root("", ""), None);
    }
}
