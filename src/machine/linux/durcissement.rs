//! Durcissement : réglages de sécurité du noyau (sysctl) et module de sécurité (AppArmor, SELinux).

use super::*;

/// Réglages du noyau posés par sentinel, gardés au redémarrage.
pub(super) const SYSCTL_SENTINEL: &str = "/etc/sysctl.d/99-sentinel.conf";
/// Même fichier sous l'ancien nom (netscan, jusqu'à 0.10.0) : repris puis remplacé à la prochaine correction.
pub(super) const SYSCTL_ANCIEN: &str = "/etc/sysctl.d/99-netscan.conf";

/// Réglages de durcissement du noyau (lisibles sans droits) : (réglage, valeur sûre minimale, rôle en français
/// et en anglais ; une constante ne peut pas choisir la langue, `reglages_faibles` le fait).
pub(super) const DURCISSEMENT: &[(&str, i64, (&str, &str))] = &[
    (
        "kernel/randomize_va_space",
        2,
        ("adresses mémoire aléatoires (ASLR)", "random memory addresses (ASLR)"),
    ),
    (
        "kernel/kptr_restrict",
        1,
        ("adresses du noyau cachées", "hidden kernel addresses"),
    ),
    (
        "kernel/dmesg_restrict",
        1,
        ("journal du noyau réservé à root", "kernel log reserved to root"),
    ),
    (
        "kernel/yama/ptrace_scope",
        1,
        (
            "un programme ne peut pas espionner les autres",
            "a program cannot spy on the others",
        ),
    ),
    (
        "fs/protected_symlinks",
        1,
        (
            "protection des liens symboliques dans /tmp",
            "symbolic link protection in /tmp",
        ),
    ),
    (
        "fs/protected_hardlinks",
        1,
        ("protection des liens physiques", "hard link protection"),
    ),
    (
        "net/ipv4/tcp_syncookies",
        1,
        ("résistance aux inondations SYN", "SYN flood resistance"),
    ),
];

/// Réglages trop faibles parmi les valeurs lues : (chemin, valeur lue, valeur sûre, rôle).
pub(super) fn reglages_faibles(lire: impl Fn(&str) -> Option<i64>) -> Vec<(&'static str, i64, i64, &'static str)> {
    DURCISSEMENT
        .iter()
        .filter_map(|&(cle, min, (fr, en))| {
            let v = lire(cle)?;
            let role = if crate::langue::anglais() { en } else { fr };
            (v < min).then_some((cle, v, min, role))
        })
        .collect()
}

pub(super) fn durcissement_noyau() -> Constat {
    let faibles = reglages_faibles(|cle| {
        std::fs::read_to_string(format!("/proc/sys/{cle}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    });
    if faibles.is_empty() {
        return ok(
            "Noyau durci",
            tr!(
                "Réglages de sécurité du noyau corrects (ASLR, ptrace, dmesg, liens…).",
                "Kernel security settings are correct (ASLR, ptrace, dmesg, links…)."
            ),
        );
    }
    let niveau = if faibles.iter().any(|f| f.0 == "kernel/randomize_va_space") {
        Niveau::Moyen
    } else {
        Niveau::Info
    };
    let liste: Vec<String> = faibles
        .iter()
        .map(|(c, v, _, r)| format!("{} = {v} ({r})", c.replace('/', ".")))
        .collect();
    // Le fichier est réécrit en entier : on garde les réglages qu'une correction précédente y avait mis,
    // sinon ils sauteraient au prochain redémarrage.
    let lignes = fusion_sysctl(
        &std::fs::read_to_string(SYSCTL_SENTINEL)
            .or_else(|_| std::fs::read_to_string(SYSCTL_ANCIEN))
            .unwrap_or_default(),
        &faibles
            .iter()
            .map(|(c, _, m, _)| (c.replace('/', "."), *m))
            .collect::<Vec<_>>(),
    )
    .replace('\n', "\\n");
    alerte(
        "Noyau durci",
        niveau,
        trf!("Réglages faibles : {}.", "Weak settings: {}.", liste.join(", ")),
    )
    .corriger(
        tr!(
            "Appliquer les valeurs sûres (fichier /etc/sysctl.d/99-sentinel.conf, gardé au redémarrage)",
            "Apply the safe values (file /etc/sysctl.d/99-sentinel.conf, kept after restart)"
        ),
        &[
            &format!("printf '{lignes}' | sudo tee {SYSCTL_SENTINEL} >/dev/null"),
            &format!("sudo rm -f {SYSCTL_ANCIEN}"),
            "sudo sysctl --system >/dev/null",
        ],
    )
}

/// Contenu de 99-sentinel.conf : les réglages déjà présents, mis à jour ou complétés par les nouveaux.
pub(super) fn fusion_sysctl(existant: &str, nouveaux: &[(String, i64)]) -> String {
    let mut reglages: Vec<(String, String)> = existant
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            let (k, v) = (k.trim(), v.trim());
            // Le contenu repasse par printf dans le shell : seuls des caractères sans effet y sont gardés.
            let sur = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || " ._-/".contains(c));
            (sur(k) && sur(v)).then(|| (k.to_string(), v.to_string()))
        })
        .collect();
    for (cle, valeur) in nouveaux {
        match reglages.iter_mut().find(|(k, _)| k == cle) {
            Some(r) => r.1 = valeur.to_string(),
            None => reglages.push((cle.clone(), valeur.to_string())),
        }
    }
    reglages.iter().fold(String::new(), |mut texte, (k, v)| {
        let _ = writeln!(texte, "{k} = {v}");
        texte
    })
}

/// Module de sécurité obligatoire (AppArmor, SELinux) : actif par défaut sur Ubuntu, Debian et Fedora.
pub(super) fn module_securite() -> Constat {
    let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    if lsm.contains("selinux") {
        return match std::fs::read_to_string("/sys/fs/selinux/enforce").map(|v| v.trim().to_string()) {
            Ok(v) if v == "1" => ok(
                "AppArmor/SELinux",
                tr!("SELinux actif (mode strict).", "SELinux on (enforcing mode)."),
            ),
            Ok(_) => alerte(
                "AppArmor/SELinux",
                Niveau::Moyen,
                tr!(
                    "SELinux est en mode permissif : il signale mais ne bloque rien.",
                    "SELinux is in permissive mode: it reports but blocks nothing."
                ),
            )
            .corriger(
                tr!("Repasser SELinux en mode strict", "Put SELinux back in enforcing mode"),
                &["sudo setenforce 1"],
            ),
            Err(_) => impossible(
                "AppArmor/SELinux",
                tr!("état de SELinux illisible", "SELinux state unreadable"),
            ),
        };
    }
    if lsm.contains("apparmor") {
        return ok("AppArmor/SELinux", tr!("AppArmor actif.", "AppArmor on."));
    }
    // Arch ne l'active pas par défaut : simple information. Ailleurs, c'est qu'on l'a coupé.
    let attendu = matches!(Paquets::detecter(), Some(Paquets::Apt | Paquets::Dnf | Paquets::Zypper));
    if lsm.is_empty() {
        impossible(
            "AppArmor/SELinux",
            tr!(
                "liste des modules de sécurité illisible",
                "security module list unreadable"
            ),
        )
    } else if attendu {
        alerte(
            "AppArmor/SELinux",
            Niveau::Moyen,
            tr!(
                "Ni AppArmor ni SELinux n'est actif, alors que ta distribution l'active normalement.",
                "Neither AppArmor nor SELinux is on, although your distribution normally turns it on."
            ),
        )
        .manuel(
            tr!(
                "Vérifier pourquoi il a été désactivé (paramètres de démarrage du noyau, paquet retiré)",
                "Check why it was turned off (kernel boot parameters, package removed)"
            ),
            &[],
        )
    } else {
        alerte(
            "AppArmor/SELinux",
            Niveau::Info,
            tr!(
                "Ni AppArmor ni SELinux (normal sur Arch, où il faut l'activer soi-même).",
                "Neither AppArmor nor SELinux (normal on Arch, where you turn it on yourself)."
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reglages_du_noyau() {
        let lu = |c: &str| Some(if c == "kernel/kptr_restrict" { 0 } else { 2 });
        let faibles = reglages_faibles(lu);
        assert_eq!(faibles.len(), 1);
        assert_eq!(faibles[0].0, "kernel/kptr_restrict");
        // Réglage absent (noyau sans Yama…) : ni faible ni fort, on ne conclut pas.
        assert_eq!(reglages_faibles(|_| None), [] as [(&str, i64, i64, &str); 0]);
    }

    #[test]
    fn sysctl_garde_les_reglages_precedents() {
        let existant = "# sentinel\nkernel.kptr_restrict = 1\nkernel.dmesg_restrict=0\nmauvais = $(rm -rf ~)\n";
        let nouveaux = [
            ("kernel.dmesg_restrict".to_string(), 1),
            ("fs.protected_symlinks".to_string(), 1),
        ];
        assert_eq!(
            fusion_sysctl(existant, &nouveaux),
            "kernel.kptr_restrict = 1\nkernel.dmesg_restrict = 1\nfs.protected_symlinks = 1\n"
        );
        assert_eq!(fusion_sysctl("", &nouveaux[..1]), "kernel.dmesg_restrict = 1\n");
    }
}
