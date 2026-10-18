//! Privilèges : fichiers secrets lisibles, groupes équivalents à root, sudo sans mot de passe. Fichiers secrets et sudo
//! se vérifient comme sous macOS (machine/unix.rs).

use super::*;
#[cfg(test)]
use crate::machine::unix::{regles_nopasswd, secret_expose};

pub(super) fn fichiers_secrets() -> Vec<Constat> {
    super::super::unix::fichiers_secrets(
        Path::new(&home()),
        tr!(
            "Ton dossier personnel est lisible par les autres comptes de la machine.",
            "Your home folder is readable by the other accounts of the machine."
        ),
    )
}

/// Groupes qui donnent en pratique les droits root sans mot de passe.
pub(super) fn groupes_privilegies() -> Option<Constat> {
    let groupes = sortie("id", &["-nG"])?;
    let risques = groupes_a_risque(&groupes);
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
                "Tu es dans le groupe {} : tout programme lancé par toi peut devenir root sans mot de passe (par un conteneur, une machine virtuelle ou le disque lui-même).", "You are in the {} group: any program you run can become root without a password (through a container, a virtual machine or the disk itself).",
                risques.join(", ")
            ),
        )
        .manuel(
            tr!("Si tu n'en as pas besoin chaque jour, sors du groupe (l'outil demandera alors sudo) ; sinon, garde-le en connaissance de cause", "If you do not need it every day, leave the group (the tool will then ask for sudo); otherwise, keep it knowingly"),
            &[&format!("sudo gpasswd -d $USER {}", risques.first().copied().unwrap_or("docker"))],
        )
    })
}

/// Groupes de `id -nG` qui valent root : docker, lxd et incus-admin par un conteneur qui monte /, libvirt par une
/// machine virtuelle qui reçoit le disque de l'ordinateur, disk par la lecture et l'écriture directes du disque (donc
/// de /etc/shadow).
fn groupes_a_risque(groupes: &str) -> Vec<&str> {
    groupes
        .split_whitespace()
        .filter(|g| matches!(*g, "docker" | "lxd" | "incus-admin" | "libvirt" | "disk"))
        .collect()
}

pub(super) fn sudo_sans_mot_de_passe() -> Option<Constat> {
    super::super::unix::sudo_sans_mot_de_passe(tr!(
        "sudo sans mot de passe pour TOUTES les commandes : n'importe quel programme lancé par toi peut devenir root.",
        "sudo without a password for ALL commands: any program you run can become root."
    ))
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
    fn groupes_qui_valent_root() {
        assert_eq!(
            groupes_a_risque("alice wheel libvirt kvm docker"),
            ["libvirt", "docker"]
        );
        assert_eq!(groupes_a_risque("alice wheel video audio kvm"), Vec::<&str>::new());
    }

    #[test]
    fn regles_sudo() {
        let omarchy = "User alice may run the following commands on portable:\n    (ALL) ALL\n    (root) NOPASSWD: /usr/bin/omarchy-dns Cloudflare, /usr/bin/omarchy-dns DHCP\n";
        assert_eq!(regles_nopasswd(omarchy), (vec![], 1));
        let tout = "    (ALL : ALL) NOPASSWD: ALL\n";
        assert_eq!(regles_nopasswd(tout).0.len(), 1);
    }
}
