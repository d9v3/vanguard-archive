//! Durcissement : réglages de sécurité du noyau (sysctl) et module de sécurité (AppArmor, SELinux).

use super::*;

/// Réglages du noyau posés par Vanguard, gardés au redémarrage.
pub(super) const SYSCTL_VANGUARD: &str = "/etc/sysctl.d/99-vanguard.conf";

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
        ("journal du noyau réservé à root", "kernel log reserved for root"),
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
///
/// Réseau IPv4 : une interface prend la valeur de `default` tant que personne ne l'a réglée elle-même, y compris
/// quand `default` change après sa création (carte réseau montée avant que les réglages ne soient lus au
/// démarrage). Hors routage, une redirection est acceptée si `all` ou l'interface le permet : il faut les deux à 0.
/// Le filtre des adresses d'origine prend le plus fort de `all` et de l'interface : `default` à 2 (souple, ce que
/// systemd pose) suffit, et `all` à 2 relâcherait une interface réglée exprès en strict (1).
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
    (
        "net/ipv4/conf/all/accept_redirects",
        1,
        0,
        (
            "le réseau ne peut pas détourner le trafic par des redirections ICMP",
            "the network cannot divert traffic with ICMP redirects",
        ),
    ),
    (
        "net/ipv4/conf/default/accept_redirects",
        1,
        0,
        (
            "pareil pour chaque interface réseau",
            "the same for each network interface",
        ),
    ),
    (
        "net/ipv6/conf/default/accept_redirects",
        1,
        0,
        (
            "pareil en IPv6 pour les interfaces à venir",
            "the same in IPv6 for interfaces to come",
        ),
    ),
    (
        "net/ipv4/conf/default/rp_filter",
        0,
        2,
        (
            "les paquets à l'adresse d'origine impossible sont écartés",
            "packets with an impossible source address are dropped",
        ),
    ),
];

/// IPv6 : chaque interface décide seule des redirections (ni `all` ni `default` ne comptent pour elle une fois créée),
/// et `default` ne change pas les interfaces déjà là. D'où un motif pour toutes (`*`) : systemd l'applique au
/// démarrage puis à chaque interface qui arrive ; procps l'applique depuis la 4.0, et la 3.3 (Ubuntu 22.04, Debian 11)
/// le saute sans erreur avec --system. Tout de suite, une boucle sur /proc le fait partout.
pub(super) const REDIRECTIONS_IPV6: &str = "net/ipv6/conf/*/accept_redirects";

/// Une interface IPv6 qui accepte les redirections, parmi (nom, valeur) ; `all`, `default` et la boucle locale à part.
pub(super) fn redirections_ipv6(interfaces: &[(String, i64)]) -> bool {
    interfaces
        .iter()
        .any(|(nom, v)| *v == 1 && !matches!(nom.as_str(), "all" | "default" | "lo"))
}

fn interfaces_ipv6() -> Vec<(String, i64)> {
    std::fs::read_dir("/proc/sys/net/ipv6/conf")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let v = std::fs::read_to_string(e.path().join("accept_redirects")).ok()?;
            Some((e.file_name().to_string_lossy().into_owned(), v.trim().parse().ok()?))
        })
        .collect()
}

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
    let mut faibles = reglages_faibles(|cle| {
        std::fs::read_to_string(format!("/proc/sys/{cle}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    });
    let ipv6 = redirections_ipv6(&interfaces_ipv6());
    if ipv6 {
        let role = if crate::langue::anglais() {
            "network interfaces in IPv6 do not follow ICMP redirects"
        } else {
            "les interfaces réseau en IPv6 ne suivent pas les redirections ICMP"
        };
        faibles.push((REDIRECTIONS_IPV6, 1, 0, role));
    }
    if faibles.is_empty() {
        return ok(
            "Noyau durci",
            tr!(
                "Réglages de sécurité du noyau corrects (ASLR, ptrace, dmesg, liens, réseau…).",
                "Kernel security settings are correct (ASLR, ptrace, dmesg, links, network…)."
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
        &std::fs::read_to_string(SYSCTL_VANGUARD).unwrap_or_default(),
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
            "Appliquer les valeurs sûres (fichier /etc/sysctl.d/99-vanguard.conf, gardé au redémarrage)",
            "Apply the safe values (file /etc/sysctl.d/99-vanguard.conf, kept after restart)"
        ),
        &[
            format!("printf '{lignes}' | sudo tee {SYSCTL_VANGUARD} >/dev/null"),
            "sudo sysctl --system >/dev/null".to_string(),
        ]
        .into_iter()
        .chain(ipv6.then(|| {
            "sudo sh -c 'for f in /proc/sys/net/ipv6/conf/*/accept_redirects; do echo 0 > \"$f\"; done'".to_string()
        }))
        .collect::<Vec<_>>(),
    )
}

/// Contenu de 99-vanguard.conf : les réglages déjà présents, mis à jour ou complétés par les nouveaux.
pub(super) fn fusion_sysctl(existant: &str, nouveaux: &[(String, i64)]) -> String {
    let mut reglages: Vec<(String, String)> = existant
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            let (k, v) = (k.trim(), v.trim());
            // Le contenu repasse par printf dans le shell : seuls des caractères sans effet y sont gardés.
            let sur = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || " ._-/".contains(c));
            // « * » : le motif des interfaces (REDIRECTIONS_IPV6), sans effet entre apostrophes pour le shell.
            let cle_sure = !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || "._-/*".contains(c));
            (cle_sure && sur(v)).then(|| (k.to_string(), v.to_string()))
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
        // Réseau : valeurs d'origine du noyau (redirections acceptées, filtre coupé) contre celles d'un système durci ;
        // le filtre strict (1) n'est jamais relâché.
        let reseau = |redirections: i64, filtre: i64| {
            reglages_faibles(move |c| {
                Some(match c {
                    "net/ipv4/conf/all/accept_redirects" | "net/ipv4/conf/default/accept_redirects" => redirections,
                    "net/ipv4/conf/default/rp_filter" => filtre,
                    _ => 2,
                })
            })
        };
        assert!(reseau(0, 2).is_empty() && reseau(0, 1).is_empty());
        let noms: Vec<(&str, i64)> = reseau(1, 0).iter().map(|f| (f.0, f.2)).collect();
        assert_eq!(
            noms,
            [
                ("net/ipv4/conf/all/accept_redirects", 0),
                ("net/ipv4/conf/default/accept_redirects", 0),
                ("net/ipv4/conf/default/rp_filter", 2)
            ]
        );
        // Réglage absent (noyau sans Yama…) : ni faible ni fort, on ne conclut pas.
        assert_eq!(reglages_faibles(|_| None), [] as [(&str, i64, i64, &str); 0]);
    }

    #[test]
    fn sysctl_garde_les_reglages_precedents() {
        let existant = "# vanguard\nkernel.kptr_restrict = 1\nkernel.dmesg_restrict=0\nmauvais = $(rm -rf ~)\n";
        let nouveaux = [
            ("kernel.dmesg_restrict".to_string(), 1),
            ("fs.protected_symlinks".to_string(), 1),
        ];
        assert_eq!(
            fusion_sysctl(existant, &nouveaux),
            "kernel.kptr_restrict = 1\nkernel.dmesg_restrict = 1\nfs.protected_symlinks = 1\n"
        );
        assert_eq!(fusion_sysctl("", &nouveaux[..1]), "kernel.dmesg_restrict = 1\n");
        // Le motif des interfaces IPv6 se garde d'une correction à l'autre.
        assert_eq!(
            fusion_sysctl("net.ipv6.conf.*.accept_redirects = 0\n", &nouveaux[..1]),
            "net.ipv6.conf.*.accept_redirects = 0\nkernel.dmesg_restrict = 1\n"
        );
    }

    #[test]
    fn redirections_en_ipv6() {
        let i = |nom: &str, v: i64| (nom.to_string(), v);
        assert!(!redirections_ipv6(&[
            i("all", 1),
            i("default", 1),
            i("lo", 1),
            i("eth0", 0)
        ]));
        assert!(redirections_ipv6(&[i("all", 0), i("wlan0", 1)]));
        assert!(!redirections_ipv6(&[]));
    }
}
