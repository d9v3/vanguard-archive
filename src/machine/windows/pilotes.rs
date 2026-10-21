//! Les pilotes du noyau : ce qui tourne au plus profond de Windows, avec tous les droits. Deux signes, en lecture
//! seule. Un pilote rangé dans un dossier du compte, temporaire ou de données, où rien d'installé normalement n'en
//! pose. Un pilote connu pour être vulnérable ou malveillant (liste LOLDrivers, Apache-2.0) : signé, il se charge
//! sans alerte, puis sert à un attaquant qui a les droits d'administrateur pour désarmer l'antivirus (« Bring Your Own
//! Vulnerable Driver »). La liste se télécharge une fois par semaine ; sans elle, c'est dit, jamais compté comme sain.
//! Les pilotes se lisent dans le registre des services (type pilote du noyau ou du système de fichiers, pas
//! désactivés), sans PowerShell ni droits d'administrateur. Rien ne se corrige tout seul : retirer un pilote peut
//! empêcher Windows de démarrer.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use super::*;
use crate::machine::regles::{Os, regle};
use crate::ui::{affichable, couper};

const CAT: &str = "Persistance";
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
const LOLDRIVERS: &str = "https://www.loldrivers.io/api/drivers.csv";
/// La liste fait environ 1,2 Mo en octobre 2026 : au-delà de 32 Mo, ce n'est pas elle.
const LISTE_MAX: u64 = 32 << 20;
const SEMAINE: Duration = Duration::from_hours(7 * 24);

regle!(
    "WIN-PRS-012",
    Os::Windows,
    229,
    (
        "pilotes du noyau (emplacement, pilotes vulnérables connus)",
        "kernel drivers (location, known vulnerable drivers)"
    ),
    &["MITRE ATT&CK T1543.003", "MITRE ATT&CK T1068", "LOLDrivers"],
    pilotes
);

/// Un pilote déclaré : son nom de service et son fichier.
struct Pilote {
    nom: String,
    fichier: PathBuf,
}

/// Le fichier d'un pilote à partir de son ImagePath (« \SystemRoot\… », « System32\… », « \??\C:\… », un chemin
/// complet) ; sans ImagePath, Windows prend System32\drivers\<nom>.sys.
fn fichier_du_pilote(nom: &str, image: Option<&str>, racine: &str) -> PathBuf {
    let Some(image) = image.map(|i| i.trim().trim_matches('"')).filter(|i| !i.is_empty()) else {
        return Path::new(racine)
            .join("System32")
            .join("drivers")
            .join(format!("{nom}.sys"));
    };
    // Préfixes comparés en ASCII : to_lowercase change la longueur de certains caractères (K Kelvin, İ), et un
    // découpage fait d'après la chaîne en minuscules tombait au mauvais endroit, ou au milieu d'un caractère.
    if image
        .get(..12)
        .is_some_and(|p| p.eq_ignore_ascii_case("\\systemroot\\"))
    {
        return Path::new(racine).join(&image[12..]);
    }
    if let Some(reste) = image.strip_prefix("\\??\\") {
        return PathBuf::from(reste);
    }
    if image
        .get(..9)
        .is_some_and(|p| p.eq_ignore_ascii_case("system32\\") || p.eq_ignore_ascii_case("syswow64\\"))
    {
        return Path::new(racine).join(image);
    }
    PathBuf::from(image)
}

/// Les dossiers de ProgramData que seul le système peut modifier.
const PROTEGES: [&str; 2] = [
    "\\programdata\\microsoft\\windows defender\\",
    "\\programdata\\microsoft\\windows defender advanced threat protection\\",
];

/// Pourquoi l'emplacement d'un pilote est suspect, ou `None` : le dossier de Windows (dont DriverStore) et les dossiers
/// de programmes sont normaux.
fn emplacement_suspect(fichier: &Path) -> Option<&'static str> {
    let f = fichier.to_string_lossy().to_lowercase().replace('/', "\\");
    // Defender range son pilote d'analyse (MpKslDrv) dans ses mises à jour de définitions, sous ProgramData : un dossier
    // que seul le système peut modifier, contrairement au reste de ProgramData.
    if PROTEGES.iter().any(|p| f.contains(p)) {
        return None;
    }
    if f.contains("\\temp\\") || f.contains("\\users\\public\\") || f.contains("\\$recycle.bin\\") {
        return Some(tr!("dossier temporaire ou public", "temporary or public folder"));
    }
    if f.contains("\\appdata\\")
        || f.contains("\\users\\")
        || f.contains("\\programdata\\")
        || f.contains("\\downloads\\")
    {
        return Some(tr!("dossier du compte ou de données", "account or data folder"));
    }
    None
}

/// Les empreintes SHA-256 de la liste LOLDrivers (CSV) : toute suite de 64 chiffres hexadécimaux. Elle contient aussi
/// des empreintes Authenticode, qui ne correspondent à aucun fichier entier : les garder ne peut rien fausser.
fn empreintes_de_la_liste(texte: &str) -> HashSet<[u8; 32]> {
    texte
        .split(|c: char| !c.is_ascii_hexdigit())
        .filter(|m| m.len() == 64)
        .filter_map(|m| {
            let mut e = [0u8; 32];
            for (i, o) in e.iter_mut().enumerate() {
                *o = u8::from_str_radix(m.get(2 * i..2 * i + 2)?, 16).ok()?;
            }
            Some(e)
        })
        .collect()
}

/// `liste` : les empreintes connues, `None` si la liste manque. `empreinte` : celle d'un fichier, `None` s'il est
/// illisible ou absent (pilote déclaré mais pas installé, cas courant : il n'est pas compté).
fn juger_pilotes(pilotes: &[(Pilote, Option<[u8; 32]>)], liste: Option<&HashSet<[u8; 32]>>) -> Vec<Constat> {
    let mut constats = Vec::new();
    let suspects: Vec<String> = pilotes
        .iter()
        .filter(|(_, e)| e.is_some())
        .filter_map(|(p, _)| {
            emplacement_suspect(&p.fichier).map(|r| format!("{} : {} ({r})", p.nom, p.fichier.display()))
        })
        .collect();
    let lus = pilotes.iter().filter(|(_, e)| e.is_some()).count();
    if suspects.is_empty() {
        constats.push(ok(
            CAT,
            trf!(
                "Pilotes du noyau : {lus} fichier(s), aucun dans un dossier du compte ou temporaire",
                "Kernel drivers: {lus} file(s), none in an account or temporary folder"
            ),
        ));
    } else {
        let liste = couper(&affichable(&suspects.join(" ; ")), 240);
        constats.push(alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "Un pilote du noyau est rangé là où rien d'installé normalement n'en pose : {liste}. Un pilote a tous les droits sur l'ordinateur ; c'est la cachette d'un rootkit.",
                "A kernel driver is stored where nothing normally installed puts one: {liste}. A driver has full rights over the computer; it is a rootkit's hiding place."
            ),
        ));
    }
    let Some(liste) = liste else {
        constats.push(impossible(
            CAT,
            tr!(
                "pilotes vulnérables connus : liste LOLDrivers indisponible (sans Internet ?)",
                "known vulnerable drivers: LOLDrivers list unavailable (no Internet?)"
            ),
        ));
        return constats;
    };
    let vulnerables: Vec<String> = pilotes
        .iter()
        .filter(|(_, e)| e.is_some_and(|e| liste.contains(&e)))
        .map(|(p, _)| format!("{} ({})", p.nom, p.fichier.display()))
        .collect();
    if vulnerables.is_empty() {
        let n = liste.len();
        constats.push(ok(
            CAT,
            trf!(
                "Pilotes vulnérables connus : aucun parmi {lus} (liste LOLDrivers, {n} empreintes)",
                "Known vulnerable drivers: none among {lus} (LOLDrivers list, {n} fingerprints)",
            ),
        ));
    } else {
        let noms = couper(&affichable(&vulnerables.join(", ")), 240);
        constats.push(alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "Pilote connu pour être vulnérable ou malveillant (LOLDrivers) : {noms}. Signé, il se charge sans alerte ; un attaquant qui a les droits d'administrateur s'en sert pour désarmer l'antivirus. Mets à jour ou désinstalle le logiciel qui l'a posé, et active l'intégrité de la mémoire (elle bloque ces pilotes).",
                "Driver known to be vulnerable or malicious (LOLDrivers): {noms}. Being signed, it loads without warning; an attacker with administrator rights uses it to disarm the antivirus. Update or uninstall the software that put it there, and turn on memory integrity (it blocks these drivers)."
            ),
        ));
    }
    constats
}

/// Les pilotes déclarés dans le registre des services : type 1 (noyau) ou 2 (système de fichiers), pas désactivés.
fn lire_pilotes() -> Option<Vec<Pilote>> {
    let services = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(SERVICES).ok()?;
    let racine = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    Some(
        services
            .enum_keys()
            .flatten()
            .filter_map(|nom| {
                let k = services.open_subkey(&nom).ok()?;
                let genre = k.get_value::<u32, _>("Type").ok()?;
                if !matches!(genre, 1 | 2) || k.get_value::<u32, _>("Start").ok() == Some(4) {
                    return None;
                }
                let image = k.get_value::<String, _>("ImagePath").ok();
                let fichier = fichier_du_pilote(&nom, image.as_deref(), &racine);
                Some(Pilote { nom, fichier })
            })
            .collect(),
    )
}

/// La liste LOLDrivers, rafraîchie une fois par semaine ; la copie d'avant sert hors ligne.
fn liste_loldrivers() -> Option<HashSet<[u8; 32]>> {
    let dossier = crate::reseau::dossier_local().join("loldrivers");
    let _ = std::fs::create_dir_all(&dossier);
    let chemin = dossier.join("drivers.csv");
    crate::protection::empreintes::rafraichir(LOLDRIVERS, &chemin, SEMAINE, LISTE_MAX, 120);
    let liste = empreintes_de_la_liste(&std::fs::read_to_string(&chemin).ok()?);
    (!liste.is_empty()).then_some(liste)
}

fn pilotes() -> Vec<Constat> {
    let Some(pilotes) = lire_pilotes() else {
        return vec![registre_illisible(CAT)];
    };
    let avec: Vec<(Pilote, Option<[u8; 32]>)> = pilotes
        .into_iter()
        .map(|p| {
            let e = crate::protection::empreintes::sha256(&p.fichier);
            (p, e)
        })
        .collect();
    juger_pilotes(&avec, liste_loldrivers().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(nom: &str, fichier: &str) -> Pilote {
        Pilote {
            nom: nom.into(),
            fichier: fichier.into(),
        }
    }

    /// Le vrai registre des services (celui de Wine pendant les tests) déclare des pilotes, et leurs fichiers se lisent.
    #[test]
    fn lecture_du_vrai_registre() {
        let pilotes = lire_pilotes().unwrap();
        assert!(!pilotes.is_empty());
        let lus = pilotes
            .iter()
            .filter(|p| crate::protection::empreintes::sha256(&p.fichier).is_some())
            .count();
        println!("{} pilotes déclarés, {lus} fichiers lus", pilotes.len());
    }

    #[test]
    fn le_fichier_d_un_pilote() {
        let r = r"C:\Windows";
        let f = |n, i| fichier_du_pilote(n, i, r).to_string_lossy().replace('/', "\\");
        assert_eq!(f("disque", None), r"C:\Windows\System32\drivers\disque.sys");
        assert_eq!(
            f("a", Some(r"\SystemRoot\System32\drivers\a.sys")),
            r"C:\Windows\System32\drivers\a.sys"
        );
        assert_eq!(
            f("a", Some(r"\SYSTEMROOT\System32\drivers\A.sys")),
            r"C:\Windows\System32\drivers\A.sys"
        );
        assert_eq!(
            f("b", Some(r"System32\DriverStore\b.sys")),
            r"C:\Windows\System32\DriverStore\b.sys"
        );
        assert_eq!(
            f("c", Some(r"\??\C:\Program Files\Outil\c.sys")),
            r"C:\Program Files\Outil\c.sys"
        );
        assert_eq!(
            f("d", Some(r#""C:\Users\alice\AppData\Local\d.sys""#)),
            r"C:\Users\alice\AppData\Local\d.sys"
        );
    }

    #[test]
    fn l_emplacement_d_un_pilote() {
        assert!(emplacement_suspect(Path::new(r"C:\Windows\System32\drivers\a.sys")).is_none());
        assert!(emplacement_suspect(Path::new(r"C:\Program Files\Outil\c.sys")).is_none());
        assert!(emplacement_suspect(Path::new(r"C:\Users\alice\AppData\Local\d.sys")).is_some());
        assert!(emplacement_suspect(Path::new(r"C:\Windows\Temp\e.sys")).is_some());
        assert!(emplacement_suspect(Path::new(r"C:\ProgramData\x\f.sys")).is_some());
        let defender = r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{0A1B}\MpKslDrv.sys";
        assert!(emplacement_suspect(Path::new(defender)).is_none());
        // Un faux dossier « Windows Defender » ailleurs ne passe pas.
        assert!(emplacement_suspect(Path::new(r"C:\Users\alice\Windows Defender\x.sys")).is_some());
    }

    #[test]
    fn la_liste_et_le_jugement() {
        let vulnerable = "ab".repeat(32);
        let csv = format!(
            "\"Id\",\"KnownVulnerableSamples_SHA256\"\n\"1\",\"{vulnerable}, {}\"\n",
            "0".repeat(63)
        );
        let liste = empreintes_de_la_liste(&csv);
        assert_eq!(liste.len(), 1);
        let e = [0xab; 32];
        let sains = [(p("disque", r"C:\Windows\System32\drivers\disque.sys"), Some([1; 32]))];
        let c = juger_pilotes(&sains, Some(&liste));
        assert!(c.iter().all(|c| c.probleme.is_none() && c.verifie));
        let vieux = [
            (p("disque", r"C:\Windows\System32\drivers\disque.sys"), Some([1; 32])),
            (p("vieuxoutil", r"C:\Program Files\Vieux\outil.sys"), Some(e)),
            (p("absent", r"C:\Windows\System32\drivers\absent.sys"), None),
        ];
        let c = juger_pilotes(&vieux, Some(&liste));
        assert!(c[1].probleme == Some(Niveau::Eleve) && c[1].message.contains("vieuxoutil"));
        let cache = [(p("cache", r"C:\Users\alice\AppData\Local\Temp\x.sys"), Some([2; 32]))];
        assert_eq!(juger_pilotes(&cache, Some(&liste))[0].probleme, Some(Niveau::Eleve));
        // Sans la liste : dit non vérifié, jamais sain.
        let c = juger_pilotes(&sains, None);
        assert!(!c[1].verifie);
    }
}
