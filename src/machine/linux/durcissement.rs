//! Durcissement : réglages de sécurité du noyau (sysctl) et module de sécurité (AppArmor, SELinux).

use super::*;

/// Réglages du noyau posés par Gardien, gardés au redémarrage.
pub(super) const SYSCTL_GARDIEN: &str = "/etc/sysctl.d/99-gardien.conf";

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
    (
        "fs/protected_fifos",
        1,
        ("protection des tubes nommés dans /tmp", "named pipe protection in /tmp"),
    ),
    (
        "fs/protected_regular",
        1,
        (
            "protection des fichiers ordinaires dans /tmp",
            "regular file protection in /tmp",
        ),
    ),
    (
        "kernel/perf_event_paranoid",
        2,
        (
            "les compteurs du processeur ne servent pas à espionner les autres programmes",
            "processor counters cannot be used to spy on other programs",
        ),
    ),
];

/// Réglages dont une valeur précise est risquée, sans que « plus haut » veuille dire « plus sûr » : (réglage, valeur
/// risquée, valeur sûre écrite à sa place, rôle).
pub(super) const INTERDITS: &[(&str, i64, i64, (&str, &str))] = &[
    (
        "fs/suid_dumpable",
        1,
        0,
        (
            "un programme root qui plante ne laisse pas sa mémoire lisible par tous",
            "a crashing root program does not leave its memory readable by all",
        ),
    ),
    (
        "kernel/sysrq",
        1,
        176,
        (
            "les touches magiques du noyau ne tuent ni ne vident la mémoire",
            "the kernel's magic keys neither kill programs nor dump memory",
        ),
    ),
];

/// Réglages trop faibles parmi les valeurs lues : (chemin, valeur lue, valeur sûre, rôle).
pub(super) fn reglages_faibles(lire: impl Fn(&str) -> Option<i64>) -> Vec<(&'static str, i64, i64, &'static str)> {
    let langue = |(fr, en): (&'static str, &'static str)| if crate::langue::anglais() { en } else { fr };
    let trop_bas = DURCISSEMENT.iter().filter_map(|&(cle, min, role)| {
        let v = lire(cle)?;
        (v < min).then(|| (cle, v, min, langue(role)))
    });
    let interdits = INTERDITS.iter().filter_map(|&(cle, risquee, sure, role)| {
        let v = lire(cle)?;
        (v == risquee).then(|| (cle, v, sure, langue(role)))
    });
    trop_bas.chain(interdits).collect()
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
        &std::fs::read_to_string(SYSCTL_GARDIEN).unwrap_or_default(),
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
            "Appliquer les valeurs sûres (fichier /etc/sysctl.d/99-gardien.conf, gardé au redémarrage)",
            "Apply the safe values (file /etc/sysctl.d/99-gardien.conf, kept after restart)"
        ),
        &[
            &format!("printf '{lignes}' | sudo tee {SYSCTL_GARDIEN} >/dev/null"),
            "sudo sysctl --system >/dev/null",
        ],
    )
}

/// Contenu de 99-gardien.conf : les réglages déjà présents, mis à jour ou complétés par les nouveaux.
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
        // Les protections de /tmp à 0 (noyau sans systemd pour les régler) : signalées.
        let tmp = reglages_faibles(|c| {
            Some(
                if c.starts_with("fs/protected_") && c != "fs/protected_symlinks" && c != "fs/protected_hardlinks" {
                    0
                } else {
                    2
                },
            )
        });
        let noms: Vec<&str> = tmp.iter().map(|f| f.0).collect();
        assert_eq!(noms, ["fs/protected_fifos", "fs/protected_regular"]);
        // Compteurs du processeur : 2 (noyau d'origine) et 3 (Debian) suffisent, 1 ou moins non.
        let compteurs = |v: i64| reglages_faibles(|c| Some(if c == "kernel/perf_event_paranoid" { v } else { 2 }));
        assert!(compteurs(2).is_empty() && compteurs(3).is_empty());
        assert_eq!(compteurs(1)[0].0, "kernel/perf_event_paranoid");
        assert_eq!(compteurs(-1)[0].2, 2);
        // Valeurs interdites : seulement la valeur risquée, remplacée par la valeur sûre.
        let lu = |suid: i64, sysrq: i64| {
            move |c: &str| {
                Some(match c {
                    "fs/suid_dumpable" => suid,
                    "kernel/sysrq" => sysrq,
                    _ => 2,
                })
            }
        };
        assert!(reglages_faibles(lu(0, 16)).is_empty() && reglages_faibles(lu(2, 176)).is_empty());
        let faibles = reglages_faibles(lu(1, 1));
        let noms: Vec<(&str, i64)> = faibles.iter().map(|f| (f.0, f.2)).collect();
        assert_eq!(noms, [("fs/suid_dumpable", 0), ("kernel/sysrq", 176)]);
        // Réglage absent (noyau sans Yama…) : ni faible ni fort, on ne conclut pas.
        assert_eq!(reglages_faibles(|_| None), [] as [(&str, i64, i64, &str); 0]);
    }

    #[test]
    fn sysctl_garde_les_reglages_precedents() {
        let existant = "# gardien\nkernel.kptr_restrict = 1\nkernel.dmesg_restrict=0\nmauvais = $(rm -rf ~)\n";
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
