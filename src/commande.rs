//! Lancement des commandes système avec un délai maximal : un outil qui ne répond plus (systemctl, gsettings,
//! PowerShell, gestionnaire de paquets hors ligne…) ne doit jamais figer Vanguard.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct Resultat {
    /// Code de retour (`None` si le programme a été tué par un signal).
    pub code: Option<i32>,
    pub sortie: String,
    /// Sortie d'erreur : notée dans le journal quand PowerShell ou udisksctl échouent, et lue par les tests
    /// (certains outils répondent par là).
    pub erreurs: String,
}

/// Délai d'attente des sorties après la fin du programme : un sous-processus resté en arrière-plan peut garder
/// le canal ouvert, et la lecture ne finirait jamais.
const DELAI_LECTURE: Duration = Duration::from_secs(2);

fn lire_en_fond(mut flux: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (envoi, reception) = mpsc::channel();
    std::thread::spawn(move || {
        let mut octets = Vec::new();
        let _ = flux.read_to_end(&mut octets);
        let _ = envoi.send(String::from_utf8_lossy(&octets).into_owned());
    });
    reception
}

/// Lance la commande et attend au plus `secondes`. `None` si elle ne démarre pas, dépasse le délai
/// (elle est alors tuée) ou si ses sorties ne se terminent pas.
pub fn lancer(commande: &mut Command, secondes: u64) -> Option<Resultat> {
    let mut enfant = commande
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let sortie = lire_en_fond(enfant.stdout.take()?);
    let erreurs = lire_en_fond(enfant.stderr.take()?);
    let limite = Instant::now() + Duration::from_secs(secondes);
    // Attente qui double de 1 à 50 ms : la plupart des commandes finissent en quelques millisecondes, et une pause
    // fixe de 50 ms coûtait 50 ms à chacune (5 s pour la centaine de petites commandes des fichiers suspects).
    let mut pause = Duration::from_millis(1);
    let statut = loop {
        match enfant.try_wait() {
            Ok(Some(statut)) => break statut,
            Ok(None) if Instant::now() < limite => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(50));
            }
            _ => {
                arreter(&mut enfant);
                return None;
            }
        }
    };
    Some(Resultat {
        code: statut.code(),
        sortie: sortie.recv_timeout(DELAI_LECTURE).ok()?,
        erreurs: erreurs.recv_timeout(DELAI_LECTURE).unwrap_or_default(),
    })
}

/// Comme `lancer`, l'outil répondant en anglais, avec les nombres et les dates du « C » : pour une sortie que Vanguard
/// analyse et que l'outil traduit (nmcli écrit « oui » pour « yes », lscpu « Nom de modèle » pour « Model name »).
/// En UTF-8, un nom de réseau accentué reste intact ; sans C.UTF-8, le système se replie sur le « C ». LANGUAGE est
/// retirée : selon la bibliothèque C, elle l'emporterait sur C.UTF-8. Une sortie montrée telle quelle à la personne
/// garde sa langue : `lancer`.
#[cfg(target_os = "linux")]
pub fn lancer_en_anglais(commande: &mut Command, secondes: u64) -> Option<Resultat> {
    lancer(commande.env("LC_ALL", "C.UTF-8").env_remove("LANGUAGE"), secondes)
}

/// Arrête le programme et tout ce qu'il a lancé : sinon un sous-processus (winget sous PowerShell, un outil sous un
/// script) continuerait en arrière-plan, avec ses verrous.
pub fn arreter(enfant: &mut Child) {
    // Windows : taskkill suit lui-même l'arbre des processus.
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .args(["/T", "/F", "/PID", &enfant.id().to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    // Unix : les descendants sont d'abord tous repérés (pgrep -P, de proche en proche), puis tués. Tué en premier, le
    // programme laisserait ses enfants rattachés à init, introuvables.
    #[cfg(unix)]
    {
        let mut pids = vec![enfant.id()];
        let mut i = 0;
        while let Some(&pid) = pids.get(i)
            && pids.len() < 1000
        {
            i += 1;
            if let Ok(o) = Command::new("pgrep").args(["-P", &pid.to_string()]).output() {
                pids.extend(
                    String::from_utf8_lossy(&o.stdout)
                        .split_whitespace()
                        .filter_map(|p| p.parse::<u32>().ok()),
                );
            }
        }
        for pid in pids.into_iter().skip(1).filter_map(|p| libc::pid_t::try_from(p).ok()) {
            // SAFETY : simple envoi d'un signal à un numéro de processus.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
    let _ = enfant.kill();
    let _ = enfant.wait();
}

/// Apostrophes qui ouvrent et ferment une chaîne '…' de PowerShell : la droite, et aussi les typographiques ‘ ’ ‚ ‛
/// (U+2018 à U+201B), courantes dans un nom de fichier, de compte ou d'appareil.
const APOSTROPHES_PS: [char; 5] = ['\'', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'];

/// Le texte à placer entre apostrophes dans un script PowerShell : chaque apostrophe, droite ou typographique,
/// doublée. Ne doubler que « ' » laissait « ’ » fermer la chaîne : la suite d'un nom de fichier téléchargé ou d'un
/// appareil du réseau s'exécutait comme une commande.
pub fn ps_texte(t: &str) -> String {
    let mut s = String::with_capacity(t.len() + 2);
    for c in t.chars() {
        s.push(c);
        if APOSTROPHES_PS.contains(&c) {
            s.push(c);
        }
    }
    s
}

/// Le texte entre apostrophes, pour bash : « '…' » ; une apostrophe du texte ferme, s'échappe et rouvre. La seule
/// façon de mettre un texte venu d'ailleurs (nom d'appareil, de fichier, de certificat…) dans une commande shell : le
/// test `textes_dans_sudo_et_rm_mis_entre_apostrophes` le garde.
pub fn sh_chaine(t: &str) -> String {
    format!("'{}'", t.replace('\'', "'\\''"))
}

/// Le texte entre apostrophes, pour PowerShell : « '…' ».
#[cfg(any(windows, test))]
pub fn ps_chaine(t: &str) -> String {
    format!("'{}'", ps_texte(t))
}

/// Lignes « NOM|… » d'une section de la sortie d'un script, sans leur préfixe ; `None` sans le marqueur « NOM_FIN » :
/// la section n'a pas pu être lue jusqu'au bout.
#[cfg(any(windows, test))]
pub fn section<'a>(sortie: Option<&'a str>, nom: &str) -> Option<Vec<&'a str>> {
    let sortie = sortie?;
    let fin = format!("{nom}_FIN");
    sortie.lines().any(|l| l.trim() == fin).then(|| {
        sortie
            .lines()
            .filter_map(|l| l.trim().strip_prefix(nom)?.strip_prefix('|'))
            .collect()
    })
}

/// Programme et arguments d'une ligne de commande Windows (« "C:\Program Files\x.exe" -a », « x.exe -a »,
/// « C:\Program Files\x.exe -a » sans guillemets).
#[cfg(any(windows, test))]
pub fn decouper_commande(ligne: &str) -> (String, String) {
    let ligne = ligne.trim();
    if let Some(reste) = ligne.strip_prefix('"')
        && let Some((exe, args)) = reste.split_once('"')
    {
        return (exe.to_string(), args.trim().to_string());
    }
    let bas = ligne.to_lowercase();
    if let Some(i) = bas.find(".exe") {
        let (exe, args) = ligne.split_at(i + 4);
        return (exe.to_string(), args.trim().to_string());
    }
    match ligne.split_once(' ') {
        Some((exe, args)) => (exe.to_string(), args.trim().to_string()),
        None => (ligne.to_string(), String::new()),
    }
}

#[cfg(test)]
mod tests_powershell {
    use super::*;

    /// Un nom piégé : chaque sorte d'apostrophe tente de fermer la chaîne pour lancer une commande.
    const PIEGE: &str = "a'; Write-Output INJECTE; 'b ‘; Write-Output INJECTE; ‘ ’; Write-Output INJECTE; ’ \
                         ‚; Write-Output INJECTE; ‚ ‛; Write-Output INJECTE; ‛ L’outil";

    #[test]
    fn apostrophes_doublees() {
        assert_eq!(ps_texte("L'outil"), "L''outil");
        assert_eq!(ps_texte("L’outil ‘x‚ ‛"), "L’’outil ‘‘x‚‚ ‛‛");
        assert_eq!(ps_chaine("C:\\Users\\Zoé"), "'C:\\Users\\Zoé'");
        // Les guillemets doubles et le « $ » ne comptent pas entre apostrophes.
        assert_eq!(ps_texte("\"$x\" “y”"), "\"$x\" “y”");
    }

    /// La chaîne piégée, passée à un vrai PowerShell, reste du texte. Windows : powershell ; ailleurs, pwsh s'il est
    /// installé (sinon l'essai est sauté : sous Wine, PowerShell n'existe pas).
    #[test]
    fn chaine_piegee_reste_du_texte() {
        let programme = if cfg!(windows) { "powershell" } else { "pwsh" };
        let script = format!(
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $x = {}; Write-Output ('<' + $x + '>')",
            ps_chaine(PIEGE)
        );
        let Some(r) = lancer(
            Command::new(programme).args(["-NoProfile", "-NonInteractive", "-Command", &script]),
            60,
        ) else {
            eprintln!("{programme} absent : essai sauté");
            return;
        };
        // Une injection réussie écrirait « INJECTE » sur une ligne à part.
        assert!(!r.sortie.lines().any(|l| l.trim() == "INJECTE"), "{}", r.sortie);
        // Un PowerShell factice (Wine) ne répond rien : rien à comparer.
        if !r.sortie.trim().is_empty() {
            assert_eq!(r.sortie.trim(), format!("<{PIEGE}>"), "{}", r.erreurs);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Les sorties analysées que leur outil traduit (relevées outil par outil, en français et en anglais) passent
    /// toutes par `lancer_en_anglais` : nmcli écrit « oui » pour « yes » dans la colonne ACTIVE, lscpu « Nom de
    /// modèle : » pour « Model name: », dpkg -S traduit ses lignes « diversion by … ». Lu dans les fichiers : l'appel
    /// de l'outil et `lancer_en_anglais` dans la même instruction.
    #[cfg(target_os = "linux")]
    #[test]
    fn sorties_traduites_lues_en_anglais() {
        let dans_la_langue_du_systeme: Vec<String> = [
            (
                "machine/linux/mod.rs",
                include_str!("machine/linux/mod.rs"),
                "Command::new(\"nmcli\")",
            ),
            (
                "machine/linux/mod.rs",
                include_str!("machine/linux/mod.rs"),
                "Command::new(\"dpkg\").args([\"-S\"",
            ),
            (
                "reseau/canaux.rs",
                include_str!("reseau/canaux.rs"),
                "Command::new(\"nmcli\")",
            ),
            (
                "reseau/scan.rs",
                include_str!("reseau/scan.rs"),
                "Command::new(\"nmcli\")",
            ),
            ("fiche.rs", include_str!("fiche.rs"), "Command::new(\"lscpu\")"),
        ]
        .into_iter()
        .filter(|(_, source, appel)| {
            source.find(appel).is_none_or(|i| {
                let instruction = &source[source[..i].rfind(';').map_or(0, |d| d + 1)..i];
                !instruction.contains("lancer_en_anglais(")
            })
        })
        .map(|(fichier, _, appel)| format!("{fichier} : {appel}"))
        .collect();
        assert!(dans_la_langue_du_systeme.is_empty(), "{dans_la_langue_du_systeme:#?}");
    }

    /// La langue de la personne (ici donnée à la commande : LC_ALL et LANGUAGE en français) arrive à l'outil par
    /// `lancer`, jamais par `lancer_en_anglais`.
    #[cfg(target_os = "linux")]
    #[test]
    fn lancer_en_anglais_remplace_la_langue_de_la_personne() {
        let langue = |r: Option<Resultat>| r.map(|r| r.sortie.trim().to_string()).unwrap_or_default();
        let en_francais = || {
            let mut c = Command::new("sh");
            c.args(["-c", "echo \"$LC_ALL|${LANGUAGE-aucune}\""])
                .env("LC_ALL", "fr_CA.UTF-8")
                .env("LANGUAGE", "fr_CA:fr");
            c
        };
        assert_eq!(langue(lancer(&mut en_francais(), 5)), "fr_CA.UTF-8|fr_CA:fr");
        assert_eq!(langue(lancer_en_anglais(&mut en_francais(), 5)), "C.UTF-8|aucune");
    }

    #[test]
    fn delai_et_sorties() {
        let debut = Instant::now();
        assert!(lancer(Command::new("sleep").arg("5"), 1).is_none());
        assert!(debut.elapsed() < Duration::from_secs(3));
        let r = lancer(Command::new("sh").args(["-c", "echo ok; echo oups >&2; exit 3"]), 5).unwrap();
        assert_eq!(
            (r.code, r.sortie.as_str(), r.erreurs.as_str()),
            (Some(3), "ok\n", "oups\n")
        );
    }

    #[test]
    fn sous_processus_qui_garde_la_sortie() {
        // Le programme se termine mais laisse un processus en arrière-plan sur la sortie : pas de blocage.
        let debut = Instant::now();
        let _ = lancer(Command::new("sh").args(["-c", "sleep 20 & echo fini"]), 5);
        assert!(debut.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn le_delai_arrete_aussi_ce_que_le_programme_a_lance() {
        let fichier = std::env::temp_dir().join(format!("vanguard-test-arbre-{}", std::process::id()));
        let script = format!("sleep 30 & echo $! > '{}'; wait", fichier.display());
        assert!(lancer(Command::new("sh").args(["-c", &script]), 1).is_none());
        let pid = std::fs::read_to_string(&fichier).unwrap().trim().to_string();
        let _ = std::fs::remove_file(&fichier);
        // Arrêté = absent de la liste des processus, ou zombie qui attend d'être ramassé.
        let vivant = || {
            let ps = Command::new("ps").args(["-o", "stat=", "-p", &pid]).output().unwrap();
            let etat = String::from_utf8_lossy(&ps.stdout).trim().to_string();
            !etat.is_empty() && !etat.starts_with('Z')
        };
        let debut = Instant::now();
        while vivant() && debut.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!vivant(), "le sous-processus {pid} tourne encore");
    }
}

/// Le garde de `sh_chaine` : tout texte qui entre dans une commande `sudo` ou `rm` est une constante, un texte passé par
/// `sh_chaine`, ou une exception relue (`RELUES`). Lu dans les fichiers du code, comme un relecteur le ferait.
#[cfg(all(test, unix))]
mod tests_sh_chaine {
    use std::path::Path;

    /// Les arguments relus un par un : (fichier, expression, pourquoi elle ne peut rien injecter).
    const RELUES: &[(&str, &str, &str)] = &[
        (
            "gaming/linux.rs",
            "nom",
            "fichier_de_vanguard : liste blanche de chemins écrits par Vanguard",
        ),
        ("gaming/linux.rs", "n", "chiffres seulement, vérifié juste avant"),
        (
            "machine/linux/durcissement.rs",
            "lignes",
            "réglages sysctl du code et fichier de Vanguard, à root",
        ),
        (
            "machine/linux/maj.rs",
            "k",
            "versions de noyau lues dans dkms status et /lib/modules, à root",
        ),
        (
            "machine/linux/mod.rs",
            "paquets",
            "noms de paquets choisis par le code ou lus dans la base des paquets",
        ),
        (
            "machine/linux/mod.rs",
            "paquet",
            "nom de paquet choisi par le code ou lu dans la base des paquets",
        ),
        (
            "machine/linux/mod.rs",
            "cle",
            "« port/protocole », fait de nombres par le code",
        ),
        (
            "machine/linux/privileges.rs",
            "risques.first().copied().unwrap_or(\"docker\")",
            "noms de groupes du code",
        ),
        (
            "machine/macos/maj.rs",
            "noms.iter() .map(|n| crate::commande::sh_chaine(n)) .collect::<Vec<_>>() .join(\" \")",
            "chaque étiquette passe par sh_chaine",
        ),
        ("machine/macos/mod.rs", "cle", "clés de defaults du code"),
        ("optimiser/linux.rs", "nom", "noms d'unités du code"),
        ("optimiser/linux.rs", "etat_unite(e)", "enable, disable ou mask"),
        (
            "optimiser/linux.rs",
            "apres",
            "commande constante du code (&'static str)",
        ),
        ("optimiser/linux.rs", "cle", "clés de fichiers de configuration du code"),
        (
            "optimiser/linux.rs",
            "v.replace('\\\\', r\"\\\\\") .replace('|', r\"\\|\") .replace('&', r\"\\&\") .replace('\\'', r\"'\\''\")",
            "remplacement de sed, déjà entre apostrophes : protégé pour sed puis pour le shell",
        ),
        ("optimiser/linux.rs", "connexion", "UUID vérifié par uuid_valide"),
        ("optimiser/linux.rs", "oui_non(ignore4)", "yes ou no"),
        ("optimiser/linux.rs", "oui_non(ignore6)", "yes ou no"),
        (
            "optimiser/macos.rs",
            "serveurs",
            "adresses IP relues par IpAddr, ou « empty »",
        ),
        (
            "protection/distance.rs",
            "if application { \"rf\" } else { \"f\" }",
            "deux constantes",
        ),
        (
            "reparer.rs",
            "description",
            "entre_apostrophes, qui passe par sh_chaine sous Unix",
        ),
        (
            "reparer.rs",
            "s",
            "entre_apostrophes, qui passe par sh_chaine sous Unix",
        ),
        (
            "reparer.rs",
            "motif_adresses(&detournees)",
            "adresses IP validées, points protégés pour sed",
        ),
        (
            "sauvegarde.rs",
            "id",
            "chiffres hexadécimaux et tirets, vérifié juste avant",
        ),
    ];

    fn sources(dossier: &Path, base: &Path, sortie: &mut Vec<(String, String)>) {
        for e in std::fs::read_dir(dossier).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                sources(&p, base, sortie);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let nom = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                sortie.push((nom, std::fs::read_to_string(&p).unwrap()));
            }
        }
    }

    /// Un littéral de chaîne qui commence à `i` (« "…" », « r"…" », « r#"…"# ») : son texte tel qu'écrit, et la
    /// position qui le suit.
    fn litteral(src: &str, i: usize) -> Option<(&str, usize)> {
        let reste = &src[i..];
        if let Some(apres) = reste.strip_prefix('r') {
            let dieses = apres.len() - apres.trim_start_matches('#').len();
            if !apres[dieses..].starts_with('"') {
                return None;
            }
            let fermeture = format!("\"{}", "#".repeat(dieses));
            let debut = i + 2 + dieses;
            let fin = debut + src[debut..].find(&fermeture)?;
            return Some((&src[debut..fin], fin + fermeture.len()));
        }
        if !reste.starts_with('"') {
            return None;
        }
        let octets = src.as_bytes();
        let mut j = i + 1;
        while octets[j] != b'"' {
            j += if octets[j] == b'\\' { 2 } else { 1 };
        }
        Some((&src[i + 1..j], j + 1))
    }

    /// Les arguments qui suivent le texte d'un format!, jusqu'à sa parenthèse fermante.
    fn arguments(src: &str, mut i: usize) -> Vec<String> {
        let octets = src.as_bytes();
        let (mut profondeur, mut debut, mut args) = (0, i, Vec::new());
        loop {
            let c = octets[i];
            let precede_d_un_mot = i > 0 && (octets[i - 1].is_ascii_alphanumeric() || octets[i - 1] == b'_');
            if (c == b'"' || (c == b'r' && !precede_d_un_mot && matches!(octets[i + 1], b'"' | b'#')))
                && let Some((_, fin)) = litteral(src, i)
            {
                i = fin;
                continue;
            }
            if c == b'\'' {
                // Un caractère (',' ou ')' n'ouvrent ni ne ferment rien) ; sinon une durée de vie.
                let longueur = if octets[i + 1] == b'\\' {
                    2
                } else {
                    src[i + 1..].chars().next().map_or(1, char::len_utf8)
                };
                if octets.get(i + 1 + longueur) == Some(&b'\'') {
                    i += longueur + 2;
                    continue;
                }
            }
            match c {
                b'(' | b'[' | b'{' => profondeur += 1,
                b')' | b']' | b'}' if profondeur == 0 => break,
                b')' | b']' | b'}' => profondeur -= 1,
                b',' if profondeur == 0 => {
                    args.push(src[debut..i].split_whitespace().collect::<Vec<_>>().join(" "));
                    debut = i + 1;
                }
                _ => {}
            }
            i += 1;
        }
        args.push(src[debut..i].split_whitespace().collect::<Vec<_>>().join(" "));
        args.into_iter().filter(|a| !a.is_empty()).collect()
    }

    /// Le texte lance-t-il sudo ou rm (en début de commande, après un séparateur ou un espace) ?
    fn lance_sudo_ou_rm(texte: &str) -> bool {
        ["sudo", "rm"].iter().any(|mot| {
            texte.match_indices(mot).any(|(k, _)| {
                let suivi = texte[k + mot.len()..].starts_with(char::is_whitespace);
                let avant = texte[..k].trim_end();
                let precede = k == 0
                    || texte[..k].ends_with(char::is_whitespace)
                    || avant.is_empty()
                    || avant.ends_with([';', '&', '|', '(']);
                suivi && precede
            })
        })
    }

    fn par_sh_chaine(expr: &str) -> bool {
        ["sh_chaine(", "commande::sh_chaine(", "crate::commande::sh_chaine("]
            .iter()
            .any(|f| expr.starts_with(f))
    }

    /// Une constante, un texte passé par sh_chaine, ou une variable qui en reçoit un (« let nom = sh_chaine(…) »).
    fn sur(expr: &str, avant: &str) -> bool {
        let expr = expr.trim_start_matches('&').trim();
        let constante = expr.starts_with(['"', 'r']) && litteral(expr, 0).is_some()
            || expr.chars().all(|c| c.is_ascii_digit())
            || expr.starts_with(|c: char| c.is_ascii_uppercase())
                && expr
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        let variable = expr.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && avant.rfind(&format!("let {expr} = ")).is_some_and(|k| {
                let valeur = &avant[k + expr.len() + 7..];
                par_sh_chaine(valeur.trim_start())
            });
        constante || par_sh_chaine(expr) || variable
    }

    /// Les arguments d'un format! qui lance sudo ou rm et qui ne sont pas sûrs : (expression, ligne).
    fn douteux(src: &str) -> Vec<(String, usize)> {
        let mut trouves = Vec::new();
        for (k, _) in src.match_indices("format!(") {
            let i = k + "format!(".len();
            let i = i + src[i..].len() - src[i..].trim_start().len();
            let Some((texte, fin)) = litteral(src, i) else { continue };
            if !lance_sudo_ou_rm(texte) {
                continue;
            }
            let args = arguments(src, fin);
            let (nommes, positionnels): (Vec<&String>, Vec<&String>) = args.iter().partition(|a| {
                a.split_once('=').is_some_and(|(nom, reste)| {
                    !reste.starts_with('=') && nom.trim().chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                })
            });
            let mut rang = 0;
            let mut reste = texte;
            while let Some(d) = reste.find('{') {
                if reste[d + 1..].starts_with('{') {
                    reste = &reste[d + 2..];
                    continue;
                }
                let Some(f) = reste[d..].find('}') else { break };
                let nom = reste[d + 1..d + f].split(':').next().unwrap_or("").trim();
                reste = &reste[d + f + 1..];
                let expr = if nom.is_empty() {
                    rang += 1;
                    positionnels.get(rang - 1).map(|s| (*s).clone())
                } else if let Ok(n) = nom.parse::<usize>() {
                    positionnels.get(n).map(|s| (*s).clone())
                } else {
                    let nomme = nommes.iter().find_map(|a| {
                        a.split_once('=')
                            .filter(|(n, _)| n.trim() == nom)
                            .map(|(_, v)| v.trim().to_string())
                    });
                    Some(nomme.unwrap_or_else(|| nom.to_string()))
                };
                let expr = expr.unwrap_or_default();
                if !sur(&expr, &src[..k]) {
                    trouves.push((expr, src[..k].lines().count()));
                }
            }
        }
        trouves
    }

    #[test]
    fn textes_dans_sudo_et_rm_mis_entre_apostrophes() {
        let base = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut fichiers = Vec::new();
        sources(base, base, &mut fichiers);
        let mut nouveaux = Vec::new();
        let mut servies = vec![false; RELUES.len()];
        for (nom, src) in &fichiers {
            // Les tests des modules lancent leurs propres commandes, sur des dossiers jetables.
            let code = src.find("#[cfg(test)]\nmod ").map_or(src.as_str(), |t| &src[..t]);
            for (expr, ligne) in douteux(code) {
                match RELUES.iter().position(|(f, e, _)| f == nom && *e == expr) {
                    Some(i) => servies[i] = true,
                    None => nouveaux.push(format!("{nom}:{ligne} : {expr}")),
                }
            }
        }
        assert!(
            nouveaux.is_empty(),
            "texte non protégé dans une commande sudo ou rm : passe-le par commande::sh_chaine (ou, s'il est sûr \
             par construction, ajoute-le à RELUES avec la raison) :\n{}",
            nouveaux.join("\n")
        );
        let perimees: Vec<_> = RELUES
            .iter()
            .zip(&servies)
            .filter(|(_, s)| !**s)
            .map(|(r, _)| r)
            .collect();
        assert!(perimees.is_empty(), "exceptions qui ne servent plus : {perimees:#?}");
    }

    /// Le garde lui-même : il voit un nom glissé tel quel, et laisse passer sh_chaine et les constantes.
    #[test]
    fn le_garde_voit_un_nom_glisse_tel_quel() {
        let piege = "fn f(nom: &str) { let c = format!(\"sudo rm -f {nom}\"); }";
        assert_eq!(douteux(piege), [("nom".to_string(), 1)]);
        let positionnel = "let c = format!(\"echo ok; sudo cupsenable {}\", i.nom);";
        assert_eq!(douteux(positionnel), [("i.nom".to_string(), 1)]);
        let protege = "let cite = sh_chaine(nom);\nlet c = format!(\"sudo rm -f {cite} {} {DOSSIER}\", crate::commande::sh_chaine(&x));";
        assert_eq!(douteux(protege), []);
        let sans_sudo = "let c = format!(\"ls {nom}\");";
        assert_eq!(douteux(sans_sudo), []);
        assert!(!lance_sudo_ou_rm("format ce disque") && lance_sudo_ou_rm("a && rm -rf x"));
    }
}
