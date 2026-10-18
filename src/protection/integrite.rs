//! Intégrité des fichiers critiques (comptes, sudo, SSH, PAM, cron, services, démarrage automatique, hosts) :
//! une référence d'empreintes BLAKE3, puis la liste de ce qui a été modifié, ajouté ou supprimé depuis.
//! Les fichiers illisibles sans droits root sont suivis par leur taille et leur date de modification.
//! « --temps-reel » surveille ces fichiers en direct ; « --accepter » prend l'état actuel comme référence
//! (après une mise à jour du système, qui modifie légitimement certains d'entre eux).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::machine::Constat;
use crate::risk::Niveau;
use crate::ui::*;

/// Fichiers et dossiers suivis (un dossier : les fichiers qu'il contient directement).
fn cibles() -> Vec<PathBuf> {
    let maison = PathBuf::from(
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .unwrap_or_default(),
    );
    #[cfg(target_os = "linux")]
    let systeme: &[&str] = &[
        "/etc/passwd",
        "/etc/group",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/hosts",
        "/etc/ld.so.preload",
        "/etc/environment",
        "/etc/profile",
        "/etc/fstab",
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/etc/pam.d",
        "/etc/systemd/system",
        "/etc/xdg/autostart",
    ];
    #[cfg(target_os = "linux")]
    let utilisateur: &[&str] = &[
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".ssh/authorized_keys",
        ".config/autostart",
        ".config/systemd/user",
    ];
    // macOS : /etc est un lien vers /private/etc ; les démons et agents de launchd sont le démarrage automatique.
    #[cfg(target_os = "macos")]
    let systeme: &[&str] = &[
        "/etc/hosts",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/pam.d",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/etc/zshrc",
        "/etc/zprofile",
        "/etc/profile",
        "/etc/paths",
        "/etc/paths.d",
        "/etc/periodic/daily",
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
    ];
    #[cfg(target_os = "macos")]
    let utilisateur: &[&str] = &[
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".bash_profile",
        ".profile",
        ".ssh/authorized_keys",
        "Library/LaunchAgents",
    ];
    // Profils PowerShell (relancés à chaque ouverture de PowerShell) et scripts des stratégies de groupe : des
    // endroits où un programme malveillant aime se faire relancer.
    #[cfg(windows)]
    let systeme: &[&str] = &[
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        r"C:\ProgramData\ssh\administrators_authorized_keys",
        r"C:\ProgramData\ssh\sshd_config",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
        r"C:\Program Files\PowerShell\7\profile.ps1",
        r"C:\Windows\System32\GroupPolicy\Machine\Scripts\scripts.ini",
        r"C:\Windows\System32\GroupPolicy\User\Scripts\scripts.ini",
    ];
    #[cfg(windows)]
    let utilisateur: &[&str] = &[
        r".ssh\authorized_keys",
        r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        r"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
        r"Documents\WindowsPowerShell\profile.ps1",
        r"Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
        r"Documents\PowerShell\profile.ps1",
    ];
    systeme
        .iter()
        .map(PathBuf::from)
        .chain(utilisateur.iter().map(|u| maison.join(u)))
        .collect()
}

/// Fichiers réels derrière les cibles (dossiers développés d'un niveau), dans l'ordre.
fn fichiers(cibles: &[PathBuf]) -> Vec<PathBuf> {
    let mut liste = Vec::new();
    for c in cibles {
        if c.is_dir() {
            let mut contenu: Vec<PathBuf> = std::fs::read_dir(c)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            contenu.sort();
            liste.extend(contenu);
        } else if c.is_file() {
            liste.push(c.clone());
        }
    }
    liste
}

/// Empreinte d'un fichier : « b3:<BLAKE3> » s'il est lisible, sinon « meta:<taille>:<date> ».
fn empreinte(f: &Path) -> Option<String> {
    if let Ok(octets) = std::fs::read(f) {
        return Some(format!("b3:{}", blake3::hash(&octets).to_hex()));
    }
    let m = std::fs::metadata(f).ok()?;
    let date = m.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(format!("meta:{}:{date}", m.len()))
}

type Etat = BTreeMap<String, String>;

fn etat_actuel() -> Etat {
    fichiers(&cibles())
        .into_iter()
        .filter_map(|f| Some((f.display().to_string(), empreinte(&f)?)))
        .collect()
}

fn fichier_reference() -> PathBuf {
    crate::reseau::dossier_local().join("integrite.json")
}

fn reference() -> Option<Etat> {
    serde_json::from_str(&std::fs::read_to_string(fichier_reference()).ok()?).ok()
}

fn enregistrer(etat: &Etat) -> bool {
    let _ = std::fs::create_dir_all(crate::reseau::dossier_local());
    serde_json::to_string_pretty(etat).is_ok_and(|t| std::fs::write(fichier_reference(), t).is_ok())
}

/// Différences avec la référence : (modifiés, ajoutés, supprimés).
#[derive(Debug, Default, PartialEq)]
struct Ecarts {
    modifies: Vec<String>,
    ajoutes: Vec<String>,
    supprimes: Vec<String>,
}

impl Ecarts {
    fn vide(&self) -> bool {
        self.modifies.is_empty() && self.ajoutes.is_empty() && self.supprimes.is_empty()
    }

    fn total(&self) -> usize {
        self.modifies.len() + self.ajoutes.len() + self.supprimes.len()
    }
}

fn comparer(reference: &Etat, actuel: &Etat) -> Ecarts {
    let mut e = Ecarts::default();
    for (f, h) in actuel {
        match reference.get(f) {
            None => e.ajoutes.push(f.clone()),
            Some(r) if r != h => e.modifies.push(f.clone()),
            Some(_) => {}
        }
    }
    e.supprimes = reference.keys().filter(|f| !actuel.contains_key(*f)).cloned().collect();
    e
}

/// Constat pour le bilan de la machine.
pub fn constat() -> Constat {
    let Some(reference) = reference() else {
        return Constat {
            categorie: CAT,
            probleme: Some(Niveau::Info),
            message: tr!(
                "Pas encore de référence pour les fichiers critiques : « gardien integrite » la crée.",
                "No reference yet for critical files: “gardien integrite” creates it."
            )
            .into(),
            correctif: None,
            verifie: true,
        };
    };
    juger(reference.len(), &comparer(&reference, &etat_actuel()))
}

/// Catégorie du constat.
const CAT: &str = "Intégrité";

/// Le constat d'après les écarts avec une référence de `total` fichiers. Les chemins restent tels quels pour comparer ;
/// montrés, ils sont rendus inoffensifs : un fichier ajouté dans un dossier suivi porte le nom que son auteur a choisi.
fn juger(total: usize, e: &Ecarts) -> Constat {
    if e.vide() {
        return Constat {
            categorie: CAT,
            probleme: None,
            message: trf!(
                "{} fichiers critiques identiques à la référence.",
                "{} critical files identical to the reference.",
                total
            ),
            correctif: None,
            verifie: true,
        };
    }
    let exemples: Vec<String> = e
        .modifies
        .iter()
        .chain(&e.ajoutes)
        .chain(&e.supprimes)
        .map(|f| affichable(f))
        .collect();
    Constat {
        categorie: CAT,
        probleme: Some(Niveau::Moyen),
        message: trf!(
            "{} fichier(s) critique(s) changé(s) depuis la référence : {}. Normal après une mise à jour ; sinon, à examiner (« gardien integrite »).",
            "{} critical file(s) changed since the reference: {}. Normal after an update; otherwise, worth a look (“gardien integrite”).",
            e.total(),
            resume(&exemples, 3, ", ")
        ),
        correctif: None,
        verifie: true,
    }
}

/// Changements pas encore signalés par la surveillance horaire (pour ne prévenir qu'une fois par changement).
pub fn changements_a_signaler() -> Option<String> {
    let reference = reference()?;
    let e = comparer(&reference, &etat_actuel());
    let deja = crate::reseau::dossier_local().join("integrite-signale.json");
    let signales: Vec<String> = std::fs::read_to_string(&deja)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let tous: Vec<String> = e
        .modifies
        .iter()
        .chain(&e.ajoutes)
        .chain(&e.supprimes)
        .cloned()
        .collect();
    let nouveaux: Vec<String> = tous
        .iter()
        .filter(|f| !signales.contains(f))
        .map(|f| affichable(f))
        .collect();
    if let Ok(t) = serde_json::to_string(&tous) {
        let _ = std::fs::write(&deja, t);
    }
    (!nouveaux.is_empty()).then(|| resume(&nouveaux, 3, ", "))
}

fn afficher(e: &Ecarts) {
    for (liste, marque, libelle) in [
        (&e.modifies, couleur(Niveau::Eleve), tr!("modifié", "modified")),
        (&e.ajoutes, couleur(Niveau::Moyen), tr!("ajouté", "added")),
        (&e.supprimes, couleur(Niveau::Moyen), tr!("supprimé", "removed")),
    ] {
        for f in liste {
            println!("  {marque}{}{RESET} {}", ajuster(libelle, 10), affichable(f));
        }
    }
}

/// « gardien integrite » : crée la référence au premier passage, puis compare.
pub fn verifier(accepter: bool) {
    titre(tr!("Intégrité des fichiers critiques", "Critical file integrity"));
    let actuel = etat_actuel();
    match reference() {
        Some(r) if !accepter => {
            let e = comparer(&r, &actuel);
            if e.vide() {
                trp!(
                    "  {VERT}✔{RESET} {} fichiers identiques à la référence.",
                    "  {VERT}✔{RESET} {} files identical to the reference.",
                    actuel.len()
                );
            } else {
                afficher(&e);
                trp!(
                    "\n  {DISCRET}Après une mise à jour du système, c'est normal : « gardien integrite --accepter » prend cet état comme nouvelle référence.{RESET}",
                    "\n  {DISCRET}After a system update, this is normal: “gardien integrite --accepter” takes this state as the new reference.{RESET}"
                );
            }
        }
        _ => {
            if enregistrer(&actuel) {
                trp!(
                    "  {VERT}✔{RESET} Référence enregistrée : {} fichiers critiques.",
                    "  {VERT}✔{RESET} Reference saved: {} critical files.",
                    actuel.len()
                );
                let illisibles = actuel.values().filter(|h| h.starts_with("meta:")).count();
                if illisibles > 0 {
                    trp!(
                        "  {DISCRET}{illisibles} fichier(s) illisible(s) sans droits root, suivi(s) par leur taille et leur date.{RESET}",
                        "  {DISCRET}{illisibles} file(s) unreadable without root rights, tracked by size and date.{RESET}"
                    );
                }
            } else {
                trp!(
                    "  ✖ Référence impossible à enregistrer.",
                    "  ✖ Could not save the reference."
                );
            }
        }
    }
}

/// « gardien integrite --temps-reel » : surveille les fichiers critiques en direct jusqu'à Ctrl-C.
pub fn temps_reel() {
    use notify::{RecursiveMode, Watcher};
    titre(tr!("Intégrité en temps réel", "Real-time integrity"));
    let Some(reference) = reference() else {
        trp!(
            "  Pas encore de référence : lance d'abord « gardien integrite ».",
            "  No reference yet: run “gardien integrite” first."
        );
        return;
    };
    let (envoi, reception) = std::sync::mpsc::channel();
    let Ok(mut veilleur) = notify::recommended_watcher(envoi) else {
        trp!(
            "  ✖ Surveillance en direct impossible ici.",
            "  ✖ Live watching not possible here."
        );
        return;
    };
    // On surveille les dossiers qui contiennent les cibles : un fichier remplacé (nouvelle copie) reste suivi.
    let mut dossiers: Vec<PathBuf> = cibles()
        .iter()
        .map(|c| {
            if c.is_dir() {
                c.clone()
            } else {
                c.parent().map(Path::to_path_buf).unwrap_or_default()
            }
        })
        .filter(|d| d.is_dir())
        .collect();
    dossiers.sort();
    dossiers.dedup();
    let suivis = dossiers
        .iter()
        .filter(|d| veilleur.watch(d, RecursiveMode::NonRecursive).is_ok())
        .count();
    trp!(
        "  {VERT}●{RESET} {} dossiers surveillés, {} fichiers de référence. Ctrl-C pour arrêter.\n",
        "  {VERT}●{RESET} {} folders watched, {} reference files. Ctrl-C to stop.\n",
        suivis,
        reference.len()
    );
    let cibles = cibles();
    let concerne = |p: &Path| cibles.iter().any(|c| p == c || p.parent() == Some(c.as_path()));
    // Dernier état signalé par fichier : lire un fichier pour calculer son empreinte produit lui-même un
    // événement ; sans ce garde-fou, la surveillance se relançait sans fin (vu en test : 1 500 alertes en 4 s).
    let mut signale: std::collections::HashMap<String, Option<String>> = std::collections::HashMap::new();
    for evenement in reception.into_iter().flatten() {
        // Seules les vraies modifications comptent : création, écriture, renommage, suppression.
        if matches!(evenement.kind, notify::EventKind::Access(_) | notify::EventKind::Other) {
            continue;
        }
        for p in evenement.paths.iter().filter(|p| concerne(p)) {
            let cle = p.display().to_string();
            let maintenant = empreinte(p);
            if signale.get(&cle) == Some(&maintenant) {
                continue;
            }
            let deja_vu = signale.insert(cle.clone(), maintenant.clone()).flatten().is_some();
            let etat = match (reference.get(&cle), &maintenant) {
                (Some(r), Some(h)) if r == h => continue,
                (Some(_), Some(_)) => tr!("modifié", "modified"),
                (None, Some(_)) if deja_vu => tr!("modifié", "modified"),
                (None, Some(_)) => tr!("ajouté", "added"),
                (Some(_), None) => tr!("supprimé", "removed"),
                (None, None) => continue,
            };
            let heure = chrono::Local::now().format("%H:%M:%S");
            let montre = affichable(&cle);
            println!(
                "  {}{heure}  {}{RESET} {montre}",
                couleur(Niveau::Eleve),
                ajuster(etat, 10)
            );
            crate::reseau::surveillance::notifier(
                &trf!("Gardien : fichier critique {etat}", "Gardien: critical file {etat}"),
                &montre,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecarts_avec_la_reference() {
        let reference: Etat = [
            ("/etc/hosts", "b3:aa"),
            ("/etc/passwd", "b3:bb"),
            ("/etc/shadow", "meta:10:1"),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        let mut actuel = reference.clone();
        assert!(comparer(&reference, &actuel).vide());
        actuel.insert("/etc/passwd".into(), "b3:cc".into());
        actuel.insert("/etc/sudoers.d/x".into(), "b3:dd".into());
        actuel.remove("/etc/shadow");
        let e = comparer(&reference, &actuel);
        assert_eq!(e.modifies, ["/etc/passwd"]);
        assert_eq!(e.ajoutes, ["/etc/sudoers.d/x"]);
        assert_eq!(e.supprimes, ["/etc/shadow"]);
        assert_eq!(e.total(), 3);
        // Un fichier posé dans un dossier suivi (/etc/cron.d…) au nom piégé : comparé tel quel, montré inoffensif.
        actuel.insert(
            "/etc/cron.d/x\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}".into(),
            "b3:ee".into(),
        );
        let e = comparer(&reference, &actuel);
        assert_eq!(e.ajoutes.len(), 2);
        let c = juger(reference.len(), &e);
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(!crate::ui::contient_un_piege(&c.message), "{}", c.message);
        assert_eq!(juger(3, &Ecarts::default()).probleme, None);
    }

    #[test]
    fn empreinte_lisible() {
        let f = std::env::temp_dir().join(format!("gardien-integrite-{}", std::process::id()));
        std::fs::write(&f, b"abc").unwrap();
        let h = empreinte(&f).unwrap();
        // BLAKE3 de « abc ».
        assert_eq!(h, "b3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
        let _ = std::fs::remove_file(&f);
    }
}
