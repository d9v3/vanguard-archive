//! Lancement des commandes système avec un délai maximal : un outil qui ne répond plus (systemctl, gsettings,
//! PowerShell, gestionnaire de paquets hors ligne…) ne doit jamais figer Gardien.

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
    let statut = loop {
        match enfant.try_wait() {
            Ok(Some(statut)) => break statut,
            Ok(None) if Instant::now() < limite => std::thread::sleep(Duration::from_millis(50)),
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

/// Comme `lancer`, l'outil répondant en anglais, avec les nombres et les dates du « C » : pour une sortie que Gardien
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
fn arreter(enfant: &mut Child) {
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

/// Le texte entre apostrophes, pour PowerShell : « '…' ».
#[cfg(any(windows, test))]
pub fn ps_chaine(t: &str) -> String {
    format!("'{}'", ps_texte(t))
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
        let fichier = std::env::temp_dir().join(format!("gardien-test-arbre-{}", std::process::id()));
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
