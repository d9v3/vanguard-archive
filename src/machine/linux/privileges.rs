//! Privilèges : fichiers secrets lisibles, groupes équivalents à root, sudo sans mot de passe.

use super::*;

/// Fichiers qui contiennent des mots de passe ou des jetons d'accès, chemin relatif au dossier personnel.
pub(super) const SECRETS: &[&str] = &[
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

/// Un secret est mal protégé si le groupe ou les autres utilisateurs peuvent le lire (ou y entrer, pour un dossier).
pub(super) fn secret_expose(mode: u32) -> bool {
    mode & 0o077 != 0
}

pub(super) fn fichiers_secrets() -> Vec<Constat> {
    use std::os::unix::fs::PermissionsExt;
    let maison = Path::new(&home()).to_path_buf();
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
    // Le dossier personnel lui-même : ouvert en lecture, il laisse voir tous tes fichiers aux autres comptes.
    if std::fs::metadata(&maison).is_ok_and(|m| m.permissions().mode() & 0o007 != 0) {
        constats.push(
            alerte(
                "Fichiers secrets",
                Niveau::Info,
                tr!(
                    "Ton dossier personnel est lisible par les autres comptes de la machine.",
                    "Your home folder is readable by the other accounts of the machine."
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

/// Groupes qui donnent en pratique les droits root sans mot de passe.
pub(super) fn groupes_privilegies() -> Option<Constat> {
    let groupes = sortie("id", &["-nG"])?;
    let risques: Vec<&str> = groupes
        .split_whitespace()
        .filter(|g| matches!(*g, "docker" | "lxd" | "incus-admin"))
        .collect();
    Some(if risques.is_empty() {
        ok(
            "Groupes",
            tr!(
                "Aucun groupe qui donne les droits root sans mot de passe.",
                "No group gives root rights without a password."
            ),
        )
    } else {
        alerte(
            "Groupes",
            Niveau::Moyen,
            trf!(
                "Tu es dans le groupe {} : tout programme lancé par toi peut devenir root sans mot de passe (via un conteneur).", "You are in the {} group: any program you run can become root without a password (through a container).",
                risques.join(", ")
            ),
        )
        .manuel(
            tr!("Si tu n'utilises pas Docker au quotidien, sors du groupe (Docker demandera alors sudo) ; sinon, garde-le en connaissance de cause", "If you do not use Docker every day, leave the group (Docker will then ask for sudo); otherwise, keep it knowingly"),
            &[&format!("sudo gpasswd -d $USER {}", risques.first().copied().unwrap_or("docker"))],
        )
    })
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

pub(super) fn sudo_sans_mot_de_passe() -> Option<Constat> {
    // -n : jamais de demande de mot de passe. Sans règle NOPASSWD (ni sudo récent), la liste est refusée : rien à dire.
    let liste = sortie("sudo", &["-n", "-l"])?;
    let (totales, limitees) = regles_nopasswd(&liste);
    Some(if !totales.is_empty() {
        alerte(
            "Sudo",
            Niveau::Eleve,
            tr!("sudo sans mot de passe pour TOUTES les commandes : n'importe quel programme lancé par toi peut devenir root.", "sudo without a password for ALL commands: any program you run can become root."),
        )
        .manuel(
            tr!("Retirer « NOPASSWD: » de cette règle dans /etc/sudoers.d (toujours avec sudo visudo, jamais à la main)", "Remove “NOPASSWD:” from this rule in /etc/sudoers.d (always with sudo visudo, never by hand)"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn droits_des_secrets() {
        assert!(!secret_expose(0o100_600));
        assert!(!secret_expose(0o40700));
        assert!(secret_expose(0o100_644));
        assert!(secret_expose(0o100_640));
    }

    #[test]
    fn regles_sudo() {
        let omarchy = "User alice may run the following commands on portable:\n    (ALL) ALL\n    (root) NOPASSWD: /usr/bin/omarchy-dns Cloudflare, /usr/bin/omarchy-dns DHCP\n";
        assert_eq!(regles_nopasswd(omarchy), (vec![], 1));
        let tout = "    (ALL : ALL) NOPASSWD: ALL\n";
        assert_eq!(regles_nopasswd(tout).0.len(), 1);
    }
}
