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

/// Quelle part d'une sortie trop longue garder.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Garder {
    /// Le début : la commande est arrêtée à la borne (journalctl --reverse, le plus récent d'abord).
    #[cfg_attr(target_os = "macos", allow(dead_code))] // journalctl n'existe que sous Linux
    Debut,
    /// La fin : tout est lu, seuls les derniers octets restent (log show de macOS, le plus ancien d'abord).
    Fin,
}

/// Ce que `lancer_vers` a écrit.
#[cfg(unix)]
pub struct Ecrit {
    /// Code de retour (`None` : arrêtée par la borne, le délai ou un signal).
    pub code: Option<i32>,
    pub octets: u64,
    /// La sortie dépassait la borne : une partie manque.
    pub tronque: bool,
    /// Le délai est passé : la commande a été arrêtée, ce qui était déjà écrit reste.
    pub delai: bool,
    pub erreurs: String,
}

/// Les morceaux à garder pour n'avoir que les `borne` derniers octets : les plus anciens tombent, et ce qui reste
/// commence au début d'une ligne (une ligne coupée par le milieu se lirait de travers). Rend aussi s'il en est tombé.
#[cfg(any(unix, test))]
pub fn garder_la_fin(morceaux: std::collections::VecDeque<Vec<u8>>, borne: u64) -> (Vec<u8>, bool) {
    let total: usize = morceaux.iter().map(Vec::len).sum();
    let borne = usize::try_from(borne).unwrap_or(usize::MAX);
    let mut tout: Vec<u8> = morceaux.into_iter().flatten().collect();
    if total <= borne {
        return (tout, false);
    }
    let mut debut = total - borne;
    if debut > 0 && tout[debut - 1] != b'\n' {
        debut = tout[debut..]
            .iter()
            .position(|&o| o == b'\n')
            .map_or(total, |p| debut + p + 1);
    }
    tout.drain(..debut);
    (tout, true)
}

/// Comme `lancer`, la sortie écrite dans `fichier` au fil de l'eau, `borne` octets au plus : un journal de plusieurs
/// centaines de Mo ne passe pas tout entier par la mémoire. `Garder::Debut` arrête la commande à la borne ;
/// `Garder::Fin` lit tout et ne garde que la fin (en mémoire, la borne au plus). Le délai passé, la commande est
/// arrêtée et ce qui est déjà lu reste. `None` : la commande ne démarre pas, ou le fichier ne s'écrit pas.
#[cfg(unix)]
pub fn lancer_vers(
    commande: &mut Command,
    secondes: u64,
    fichier: &std::fs::File,
    borne: u64,
    garder: Garder,
) -> Option<Ecrit> {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut enfant = commande
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let mut flux = enfant.stdout.take()?;
    let erreurs = lire_en_fond(enfant.stderr.take()?);
    let mut vers = fichier.try_clone().ok()?;
    let plein = std::sync::Arc::new(AtomicBool::new(false));
    let plein_lu = plein.clone();
    let (envoi, fini) = mpsc::channel();
    std::thread::spawn(move || {
        let mut tampon = vec![0u8; 64 << 10];
        let (mut ecrits, mut tronque, mut ok) = (0u64, false, true);
        let mut fin = std::collections::VecDeque::new();
        let mut en_memoire = 0u64;
        loop {
            let n = match flux.read(&mut tampon) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            match garder {
                Garder::Debut => {
                    let reste = usize::try_from(borne.saturating_sub(ecrits)).unwrap_or(usize::MAX);
                    let n_gardes = n.min(reste);
                    ok &= vers.write_all(&tampon[..n_gardes]).is_ok();
                    ecrits += n_gardes as u64;
                    if n_gardes < n || !ok {
                        tronque = n_gardes < n;
                        plein_lu.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                Garder::Fin => {
                    fin.push_back(tampon[..n].to_vec());
                    en_memoire += n as u64;
                    // Les morceaux entièrement hors de la borne tombent tout de suite : la mémoire reste bornée.
                    while fin
                        .front()
                        .is_some_and(|m: &Vec<u8>| en_memoire - m.len() as u64 >= borne)
                    {
                        en_memoire -= fin.pop_front().map_or(0, |m| m.len() as u64);
                        tronque = true;
                    }
                }
            }
        }
        if garder == Garder::Fin {
            let (derniers, coupe) = garder_la_fin(fin, borne);
            tronque |= coupe;
            ok &= vers.write_all(&derniers).is_ok();
            ecrits = derniers.len() as u64;
        }
        let _ = envoi.send((ecrits, tronque, ok));
    });
    let limite = Instant::now() + Duration::from_secs(secondes);
    let mut pause = Duration::from_millis(1);
    let mut delai = false;
    let code = loop {
        match enfant.try_wait() {
            Ok(Some(statut)) => break statut.code(),
            Ok(None) if plein.load(Ordering::Relaxed) => {
                arreter(&mut enfant);
                break None;
            }
            Ok(None) if Instant::now() < limite => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(50));
            }
            _ => {
                delai = true;
                arreter(&mut enfant);
                break None;
            }
        }
    };
    // Après la fin, la lecture finit vite ; `Garder::Fin` écrit encore ce qu'il a gardé (la borne au plus).
    let (octets, tronque, ok) = fini.recv_timeout(DELAI_LECTURE + Duration::from_secs(30)).ok()?;
    if !ok {
        return None;
    }
    Some(Ecrit {
        code,
        octets,
        tronque,
        delai,
        erreurs: erreurs.recv_timeout(DELAI_LECTURE).unwrap_or_default(),
    })
}

/// Les descendants de `racine` (enfants, petits-enfants…) dans une liste de (processus, parent), sans `racine`
/// elle-même. Une boucle dans la liste (un numéro réutilisé, le processus 0 parent de lui-même) ne fait pas tourner
/// sans fin ; 1 000 au plus.
fn descendants(liste: &[(u32, u32)], racine: u32) -> Vec<u32> {
    let mut vus = vec![racine];
    let mut i = 0;
    while let Some(&pid) = vus.get(i)
        && vus.len() < 1000
    {
        i += 1;
        for &(enfant, parent) in liste {
            if parent == pid && !vus.contains(&enfant) {
                vus.push(enfant);
            }
        }
    }
    vus.split_off(1)
}

/// Les (processus, parent) de Linux, lus dans /proc/<pid>/stat : « 4242 (nom) S 4200 … ». Le nom peut contenir des
/// espaces et des parenthèses : le parent se lit après la dernière.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn parent_linux(stat: &str) -> Option<(u32, u32)> {
    let (debut, reste) = stat.rsplit_once(") ")?;
    let pid = debut.split_once(" (")?.0.trim().parse().ok()?;
    let parent = reste.split_whitespace().nth(1)?.parse().ok()?;
    Some((pid, parent))
}

/// Tous les (processus, parent) de l'ordinateur, sans lancer de commande sous Linux et Windows ; pgrep sur macOS.
fn processus_et_parents(racine: u32) -> Vec<(u32, u32)> {
    #[cfg(target_os = "linux")]
    {
        let _ = racine;
        std::fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|d| parent_linux(&std::fs::read_to_string(d.path().join("stat")).ok()?))
            .collect()
    }
    #[cfg(windows)]
    {
        let _ = racine;
        crate::machine::windows::processus::liste()
            .into_iter()
            .map(|p| (p.pid, p.parent))
            .collect()
    }
    // macOS : pas de /proc ; pgrep -P, de proche en proche.
    #[cfg(target_os = "macos")]
    {
        let mut liste = Vec::new();
        let mut a_voir = vec![racine];
        while let Some(pid) = a_voir.pop()
            && liste.len() < 1000
        {
            if let Ok(o) = Command::new("pgrep").args(["-P", &pid.to_string()]).output() {
                for enfant in String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .filter_map(|p| p.parse::<u32>().ok())
                {
                    liste.push((enfant, pid));
                    a_voir.push(enfant);
                }
            }
        }
        liste
    }
}

/// Arrête le programme et tout ce qu'il a lancé : sinon un sous-processus (winget sous PowerShell, un outil sous un
/// script) continuerait en arrière-plan, avec ses verrous. Les descendants sont d'abord tous repérés, puis tués : tué
/// en premier, le programme laisserait ses enfants rattachés à un autre parent, introuvables. Sous Unix, le programme
/// est suspendu avant : sinon, entre la mort de ses enfants et la sienne, il continue (un script lance la commande
/// suivante dès que la précédente meurt), et sa sortie passe la borne ou le délai : « echo apres » écrit après l'arrêt
/// de « sleep », vu quand l'ordinateur est chargé.
pub fn arreter(enfant: &mut Child) {
    let racine = enfant.id();
    #[cfg(unix)]
    if let Ok(pid) = libc::pid_t::try_from(racine) {
        // SAFETY : simple envoi d'un signal à un numéro de processus ; SIGKILL arrête aussi un processus suspendu.
        unsafe { libc::kill(pid, libc::SIGSTOP) };
    }
    for pid in descendants(&processus_et_parents(racine), racine) {
        #[cfg(windows)]
        crate::machine::windows::processus::terminer(pid);
        #[cfg(unix)]
        if let Ok(pid) = libc::pid_t::try_from(pid) {
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
    // Minuscules ASCII seulement : la position trouvée vaut dans la ligne d'origine (« İ » change de longueur en
    // minuscules Unicode). « .exe » doit finir un mot : « node.exec\run.exe » n'est pas coupé à « node.exe ».
    let bas = ligne.to_ascii_lowercase();
    let fin = bas
        .match_indices(".exe")
        .map(|(i, _)| i + 4)
        .find(|&f| bas[f..].chars().next().is_none_or(|c| c.is_whitespace() || c == '"'));
    if let Some(f) = fin {
        let (exe, args) = ligne.split_at(f);
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

    /// La commande d'un programme : « .exe » qui finit un mot, cherché sans changer la longueur de la ligne.
    #[test]
    fn exe_trouve_a_la_bonne_place() {
        let d = |l: &str| decouper_commande(l);
        assert_eq!(
            d(r"C:\Users\alice\İnstall\app.exe -a"),
            (r"C:\Users\alice\İnstall\app.exe".into(), "-a".into())
        );
        assert_eq!(
            d(r"C:\Tools\node.exec\run.exe /q"),
            (r"C:\Tools\node.exec\run.exe".into(), "/q".into())
        );
        assert_eq!(
            d(r"C:\Program Files\App\APP.EXE"),
            (r"C:\Program Files\App\APP.EXE".into(), String::new())
        );
        assert_eq!(d(r#""C:\A B\x.exe" /s"#), (r"C:\A B\x.exe".into(), "/s".into()));
    }

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

    #[test]
    fn arbre_des_processus() {
        // 10 lance 11 et 12 ; 11 lance 13 ; 20 n'est pas de la famille ; 0 est son propre parent (Windows).
        let liste = [(11, 10), (12, 10), (13, 11), (20, 1), (0, 0), (10, 1)];
        let mut d = descendants(&liste, 10);
        d.sort_unstable();
        assert_eq!(d, [11, 12, 13]);
        assert_eq!(descendants(&liste, 0), Vec::<u32>::new());
        // Une boucle (numéro réutilisé) ne tourne pas sans fin.
        assert_eq!(descendants(&[(2, 1), (1, 2)], 1), [2]);
        assert_eq!(parent_linux("4242 (Web Content) S 4200 4242 0"), Some((4242, 4200)));
        // Un nom piégé avec « ) » et des espaces : le parent se lit après la dernière parenthèse.
        assert_eq!(parent_linux("77 (a) S 1 (b) R 55 77"), Some((77, 55)));
        assert_eq!(parent_linux("pas une ligne"), None);
    }

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

    /// Chemins pris dans une variable et passés tels quels à Get-ChildItem ou Remove-Item, relus : sûrs ici.
    const PS_RELUES: &[(&str, &str, &str)] = &[
        (
            "guide/windows.rs",
            "$env:TEMP",
            "texte du guide, tapé par la personne, jamais lancé par Vanguard",
        ),
        (
            "machine/sante.rs",
            "$_.FullName",
            "le chemin d'un dossier que Get-ChildItem vient de lister",
        ),
    ];

    /// Les variables passées comme chemin à Get-ChildItem ou Remove-Item sans -LiteralPath, avec leur ligne.
    fn ps_douteux(code: &str) -> Vec<(String, usize)> {
        let mut trouves = Vec::new();
        for applet in ["Get-ChildItem ", "Remove-Item "] {
            for (i, _) in code.match_indices(applet) {
                let apres = code[i + applet.len()..].trim_start();
                // Dans le source Rust, le guillemet d'un chemin s'écrit « \" ».
                let apres = apres
                    .strip_prefix("\\\"")
                    .or_else(|| apres.strip_prefix(['"', '\'']))
                    .unwrap_or(apres);
                if let Some(nom) = apres.strip_prefix('$') {
                    let fin = nom
                        .find(|c: char| !(c.is_alphanumeric() || "_:.".contains(c)))
                        .unwrap_or(nom.len());
                    let ligne = code[..i].matches('\n').count() + 1;
                    trouves.push((format!("${}", &nom[..fin]), ligne));
                }
            }
        }
        trouves
    }

    /// Une variable vide passée comme chemin fait lire le dossier courant à Get-ChildItem (« Get-ChildItem '' »), et
    /// Remove-Item -Recurse le viderait ; « $env:SystemRoot\x » vide devient la racine du disque. Vu le 19 octobre : un
    /// dossier Démarrage absent faisait prendre le dossier courant pour des démarrages suspects.
    #[test]
    fn chemins_powershell_jamais_une_variable_nue() {
        let base = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut fichiers = Vec::new();
        sources(base, base, &mut fichiers);
        let mut nouveaux = Vec::new();
        let mut servies = vec![false; PS_RELUES.len()];
        for (nom, src) in &fichiers {
            let code = src.find("#[cfg(test)]\nmod ").map_or(src.as_str(), |t| &src[..t]);
            for (variable, ligne) in ps_douteux(code) {
                match PS_RELUES.iter().position(|(f, v, _)| f == nom && *v == variable) {
                    Some(i) => servies[i] = true,
                    None => nouveaux.push(format!("{nom}:{ligne} : {variable}")),
                }
            }
        }
        assert!(
            nouveaux.is_empty(),
            "chemin PowerShell pris dans une variable, sans -LiteralPath : écris le chemin (ps_chaine) après l'avoir \
             vérifié, ou ajoute-le à PS_RELUES avec la raison :\n{}",
            nouveaux.join("\n")
        );
        let perimees: Vec<_> = PS_RELUES
            .iter()
            .zip(&servies)
            .filter(|(_, s)| !**s)
            .map(|(r, _)| r)
            .collect();
        assert!(perimees.is_empty(), "exceptions qui ne servent plus : {perimees:#?}");
    }

    #[test]
    fn le_garde_powershell_voit_une_variable_nue() {
        assert_eq!(
            ps_douteux("\"Get-ChildItem $env:TEMP -Force\""),
            [("$env:TEMP".to_string(), 1)]
        );
        assert_eq!(
            ps_douteux("x\n\"Remove-Item \\\"$env:SystemRoot\\\\Minidump\\\\*\\\" -Force\""),
            [("$env:SystemRoot".to_string(), 2)]
        );
        assert_eq!(ps_douteux("\"Get-ChildItem -LiteralPath $d -File\""), []);
        assert_eq!(ps_douteux("\"Get-ChildItem 'C:\\\\Windows' -File\""), []);
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

#[cfg(test)]
mod tests_lancer_vers {
    use super::*;

    #[test]
    fn la_fin_gardee_commence_a_une_ligne() {
        let morceaux = |m: &[&str]| m.iter().map(|t| t.as_bytes().to_vec()).collect();
        // Tout tient : rien ne tombe.
        assert_eq!(
            garder_la_fin(morceaux(&["a\nb", "\nc\n"]), 10),
            (b"a\nb\nc\n".to_vec(), false)
        );
        // Dix octets au plus : « un\n » tombe, et « eux\n » aussi, coupée en plein milieu.
        let (gardes, coupe) = garder_la_fin(morceaux(&["un\ndeux\n", "trois\n"]), 10);
        assert!(coupe);
        assert_eq!(gardes, b"trois\n".to_vec());
        // La coupure tombe juste après un saut de ligne : la ligne suivante reste entière.
        assert_eq!(garder_la_fin(morceaux(&["un\n", "deux\n"]), 5).0, b"deux\n".to_vec());
        // Une seule ligne trop longue : rien ne reste plutôt qu'une ligne coupée.
        assert_eq!(garder_la_fin(morceaux(&["abcdefghij"]), 4), (Vec::new(), true));
    }

    #[cfg(unix)]
    /// Nommé par processus : verifier.sh lance deux suites Linux en même temps (avec et sans Internet) sur le même
    /// dossier jetable, et le `sh` de l'une écrivait « apres » dans le fichier que l'autre relisait.
    fn fichier_jetable(nom: &str) -> (std::path::PathBuf, std::fs::File) {
        let dossier = crate::reseau::dossier_local();
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join(format!("{}-{nom}", std::process::id()));
        (chemin.clone(), std::fs::File::create(&chemin).unwrap())
    }

    /// Une sortie de 200 000 octets bornée à 1 000 : le début seul, la commande arrêtée ; ou la fin seule, en
    /// commençant par une ligne entière.
    #[cfg(unix)]
    #[test]
    fn sortie_bornee_dans_un_fichier() {
        let (chemin, f) = fichier_jetable("debut.txt");
        let mut c = Command::new("sh");
        c.args(["-c", "i=0; while [ $i -lt 20000 ]; do echo ligne$i; i=$((i+1)); done"]);
        let e = lancer_vers(&mut c, 30, &f, 1000, Garder::Debut).unwrap();
        assert!(e.tronque && !e.delai && e.octets == 1000);
        let texte = std::fs::read_to_string(&chemin).unwrap();
        assert!(texte.starts_with("ligne0\nligne1\n") && texte.len() == 1000);

        let (chemin, f) = fichier_jetable("fin.txt");
        let mut c = Command::new("sh");
        c.args(["-c", "i=0; while [ $i -lt 20000 ]; do echo ligne$i; i=$((i+1)); done"]);
        let e = lancer_vers(&mut c, 30, &f, 1000, Garder::Fin).unwrap();
        assert!(e.tronque && e.code == Some(0));
        let texte = std::fs::read_to_string(&chemin).unwrap();
        assert!(texte.ends_with("ligne19999\n") && texte.starts_with("ligne") && texte.len() <= 1000);

        // Sous la borne : tout, sans troncature ; le délai passé, la commande est arrêtée et le début reste.
        let (chemin, f) = fichier_jetable("court.txt");
        let e = lancer_vers(Command::new("echo").arg("bonjour"), 10, &f, 1000, Garder::Debut).unwrap();
        assert!(!e.tronque && e.code == Some(0));
        assert_eq!(std::fs::read_to_string(&chemin).unwrap(), "bonjour\n");
        let (chemin, f) = fichier_jetable("lent.txt");
        let mut c = Command::new("sh");
        c.args(["-c", "echo avant; sleep 30; echo apres"]);
        let e = lancer_vers(&mut c, 1, &f, 1000, Garder::Debut).unwrap();
        assert!(e.delai && e.code.is_none());
        assert_eq!(std::fs::read_to_string(&chemin).unwrap(), "avant\n");
    }
}
