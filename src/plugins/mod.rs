//! Plugins : des programmes ajoutés à Vanguard sans changer son code (un essai, un outil expérimental), chacun dans
//! son sous-dossier de `<dossier local>/plugins/`, décrit par un `plugin.toml` (voir `manifeste`).
//!
//! Un plugin n'est pas du code de Vanguard : il ne tourne qu'à la demande (`vanguard plugin <nom>`, menu Cette
//! machine › Plugins), jamais dans le bilan, `complet`, la surveillance ni l'entretien, jamais en administrateur, et
//! ses constats ne touchent jamais la note. Il doit avoir été approuvé : `vanguard plugin ajouter` montre ce qu'il
//! lancera et note l'empreinte SHA-256 du manifeste et de chaque programme ; une empreinte qui change ensuite le fait
//! refuser jusqu'à une nouvelle approbation. Au lancement, le programme est copié en même temps qu'il est haché, et
//! c'est la copie vérifiée qui tourne : le remplacer entre la vérification et le lancement ne sert à rien. La
//! conception (menaces et garde-fous) est résumée dans CONTRIBUTING.md, section Plugins.

mod archive;
pub mod labo;
pub mod manifeste;
mod menu;
pub mod reglages;
pub mod sortie;

pub use menu::extensions;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use manifeste::{Manifeste, Systeme};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::langue::Reponse;
use crate::ui::*;
use crate::{tr, trf, trp};

const MANIFESTE: &str = "plugin.toml";
const APPROUVES: &str = "approuves.json";
/// Les constats gardés par `--rapport`, un fichier par plugin, repris par le rapport HTML.
pub(crate) const CONSTATS: &str = ".constats";
/// Ce qu'un plugin peut écrire (chaque sortie) avant d'être arrêté, et la taille d'un programme.
const SORTIE_MAX: usize = 1 << 20;
const PROGRAMME_MAX: u64 = 200 << 20;
/// Un plugin ajouté : fichiers, octets et profondeur au plus.
const COPIE_FICHIERS_MAX: usize = 500;
const COPIE_OCTETS_MAX: u64 = 300 << 20;
const PROFONDEUR_MAX: usize = 8;
/// Les arguments passés en ligne de commande : nombre et longueur.
const ARGUMENTS_MAX: usize = 32;
const ARGUMENT_MAX: usize = 1000;

/// Le dossier des plugins : `<dossier local>/plugins`, créé à soi seul (0700) s'il manque, et refusé s'il est
/// partagé, sur la clé VANGUARD ou hors du profil (Windows). Jamais le dossier du programme ni la clé : un plugin ne
/// voyage pas, et un dossier que d'autres comptes peuvent écrire leur ferait lancer ce qu'ils veulent sous ce compte.
pub fn dossier() -> Result<PathBuf, String> {
    let local = crate::reseau::dossier_local();
    let d = local.join("plugins");
    creer_prive(&d).map_err(|e| {
        trf!(
            "Dossier des plugins impossible à créer ({}) : {e}",
            "Could not create the plugins folder ({}): {e}",
            chemin_affichable(&d)
        )
    })?;
    if let Some(cle) = crate::reseau::cle_usb()
        && (d.starts_with(&cle) || std::fs::canonicalize(&d).is_ok_and(|c| c.starts_with(&cle)))
    {
        return Err(trf!(
            "Le dossier des plugins ({}) est sur la clé VANGUARD : refusé, un plugin ne voyage pas sur la clé.",
            "The plugins folder ({}) is on the VANGUARD key: refused, a plugin does not travel on the key.",
            chemin_affichable(&d)
        ));
    }
    dossier_sur(&d)?;
    Ok(d)
}

/// Crée un dossier (et ses parents) réservé à son compte. Déjà là, il n'est pas touché : `dossier_sur` le juge.
fn creer_prive(d: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(d)
}

/// Le compte de ce processus (Unix).
#[cfg(unix)]
fn moi() -> u32 {
    // SAFETY : getuid ne prend aucun argument, ne touche aucune mémoire et ne peut pas échouer.
    unsafe { libc::getuid() }
}

/// Un dossier où lire et lancer un plugin. Unix : à soi, ni lien ni ouvert en écriture au groupe ou aux autres ; chaque
/// parent à soi ou à root, et s'il est ouvert en écriture, collant (/tmp) : sinon un autre compte pourrait renommer le
/// dossier et en mettre un autre à sa place.
#[cfg(unix)]
fn dossier_sur(d: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let refus = |pourquoi: &str| {
        trf!(
            "Dossier refusé ({}) : {pourquoi}.",
            "Folder refused ({}): {pourquoi}.",
            chemin_affichable(d)
        )
    };
    let m = std::fs::symlink_metadata(d).map_err(|e| refus(&e.to_string()))?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(refus(tr!("un lien ou pas un dossier", "a link or not a folder")));
    }
    if m.uid() != moi() {
        return Err(refus(tr!(
            "il appartient à un autre compte",
            "it belongs to another account"
        )));
    }
    if m.mode() & 0o022 != 0 {
        return Err(refus(tr!(
            "d'autres comptes peuvent y écrire (chmod go-w)",
            "other accounts can write to it (chmod go-w)"
        )));
    }
    for parent in d.ancestors().skip(1).filter(|p| !p.as_os_str().is_empty()) {
        let Ok(m) = std::fs::metadata(parent) else {
            return Err(refus(&trf!("{} illisible", "{} unreadable", chemin_affichable(parent))));
        };
        let ouvert = m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0;
        if (m.uid() != moi() && m.uid() != 0) || ouvert {
            return Err(refus(&trf!(
                "{} est à un autre compte ou ouvert en écriture",
                "{} belongs to another account or is open for writing",
                chemin_affichable(parent)
            )));
        }
    }
    Ok(())
}

/// Windows : le dossier doit être dans le profil de la personne (les droits par défaut l'y réservent à son compte), et
/// ni lui ni son parent ne doivent être un point d'analyse (lien, jonction) qui mènerait ailleurs.
#[cfg(windows)]
fn dossier_sur(d: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    const POINT_D_ANALYSE: u32 = 0x400;
    let refus = |pourquoi: &str| {
        trf!(
            "Dossier refusé ({}) : {pourquoi}.",
            "Folder refused ({}): {pourquoi}.",
            chemin_affichable(d)
        )
    };
    for p in [Some(d), d.parent()].into_iter().flatten() {
        let m = std::fs::symlink_metadata(p).map_err(|e| refus(&e.to_string()))?;
        if m.file_attributes() & POINT_D_ANALYSE != 0 || (p == d && !m.is_dir()) {
            return Err(refus(tr!(
                "un lien, une jonction ou pas un dossier",
                "a link, a junction or not a folder"
            )));
        }
    }
    let profil = std::env::var_os("USERPROFILE").and_then(|p| std::fs::canonicalize(p).ok());
    let ici = std::fs::canonicalize(d).ok();
    match (profil, ici) {
        (Some(profil), Some(ici)) if ici.starts_with(&profil) => Ok(()),
        _ => Err(refus(tr!(
            "il n'est pas dans le profil de ce compte",
            "it is not in this account's profile"
        ))),
    }
}

/// Lancé en administrateur ? Unix : root, ou un programme setuid (compte effectif ≠ compte réel) ; Windows : jeton
/// élevé. Un plugin ne tourne jamais ainsi : il aurait tous les droits sur l'ordinateur.
fn eleve() -> bool {
    #[cfg(unix)]
    {
        // SAFETY : geteuid ne prend aucun argument, ne touche aucune mémoire et ne peut pas échouer.
        let effectif = unsafe { libc::geteuid() };
        effectif == 0 || effectif != moi()
    }
    #[cfg(windows)]
    {
        crate::machine::windows::processus::eleve()
    }
}

fn refus_eleve() -> String {
    tr!(
        "Vanguard tourne en administrateur : les plugins sont refusés. Un plugin n'est pas du code de Vanguard ; lancé ainsi, il aurait tous les droits sur l'ordinateur. Relance Vanguard sans droits d'administrateur (sans sudo, ou pas « en tant qu'administrateur ») pour ajouter, approuver ou lancer un plugin.",
        "Vanguard is running as administrator: plugins are refused. A plugin is not Vanguard's code; run like this, it would have every right on the computer. Start Vanguard again without administrator rights (no sudo, or not “as administrator”) to add, approve or run a plugin."
    )
    .to_string()
}

/// Ce que la personne a approuvé : pour chaque plugin, l'empreinte de son manifeste et de chacun de ses programmes.
#[derive(Serialize, Deserialize, Default, Debug)]
struct Approbations {
    #[serde(default)]
    plugins: BTreeMap<String, Approbation>,
    /// Les scripts du laboratoire : nom du fichier → son empreinte.
    #[serde(default)]
    labo: BTreeMap<String, labo::Approbation>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
struct Approbation {
    manifeste: String,
    /// Chemin relatif du programme → son SHA-256.
    programmes: BTreeMap<String, String>,
    le: String,
}

/// Les approbations ; un fichier illisible n'approuve rien (tout est alors refusé, jamais tout permis).
fn approbations(racine: &Path) -> Approbations {
    lire_sur(&racine.join(APPROUVES), 1 << 20)
        .ok()
        .and_then(|o| serde_json::from_slice(&o).ok())
        .unwrap_or_default()
}

fn enregistrer(racine: &Path, a: &Approbations) -> Result<(), String> {
    let texte = serde_json::to_string_pretty(a).map_err(|e| e.to_string())?;
    crate::reseau::ecrire_atomique(&racine.join(APPROUVES), texte).map_err(|e| {
        trf!(
            "Approbation impossible à écrire : {e}",
            "Could not write the approval: {e}"
        )
    })
}

/// Ouvre un fichier du plugin sans suivre de lien (Unix : O_NOFOLLOW ; Windows : le point d'analyse lui-même, puis
/// refusé), sans bloquer sur un tube nommé (O_NONBLOCK), et le refuse s'il n'est pas un fichier ordinaire, ou (Unix)
/// s'il est à un autre compte ou modifiable par d'autres. Les vérifications portent sur le fichier ouvert, pas sur son
/// nom : celui-ci peut changer entre deux appels.
fn ouvrir_sur(chemin: &Path) -> Result<std::fs::File, String> {
    let refus = |pourquoi: &str| {
        trf!(
            "{} refusé : {pourquoi}",
            "{} refused: {pourquoi}",
            chemin_affichable(chemin)
        )
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(&mut options, 0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    let f = options.open(chemin).map_err(|e| refus(&e.to_string()))?;
    let m = f.metadata().map_err(|e| refus(&e.to_string()))?;
    if !m.is_file() {
        return Err(refus(tr!("pas un fichier ordinaire", "not a regular file")));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != moi() || m.mode() & 0o022 != 0 {
            return Err(refus(tr!(
                "à un autre compte, ou modifiable par d'autres",
                "owned by another account, or writable by others"
            )));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err(refus(tr!("un lien", "a link")));
        }
    }
    Ok(f)
}

/// Le fichier entier, `max` octets au plus.
fn lire_sur(chemin: &Path, max: usize) -> Result<Vec<u8>, String> {
    let f = ouvrir_sur(chemin)?;
    let mut octets = Vec::new();
    f.take(max as u64 + 1)
        .read_to_end(&mut octets)
        .map_err(|e| e.to_string())?;
    if octets.len() > max {
        return Err(trf!("{} : trop gros", "{}: too large", chemin_affichable(chemin)));
    }
    Ok(octets)
}

fn hex(octets: &[u8]) -> String {
    use std::fmt::Write as _;
    octets.iter().fold(String::new(), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    })
}

/// Copie `source` vers `copie` (créé, jamais écrasé) en la hachant au passage ; `None` pour `copie` : seulement haché.
/// Rend l'empreinte de ce qui a été lu, donc de ce qui a été écrit.
fn hacher_et_copier(source: &Path, copie: Option<&Path>) -> Result<String, String> {
    let mut f = ouvrir_sur(source)?;
    let mut vers = match copie {
        None => None,
        Some(c) => {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o700);
            Some(o.open(c).map_err(|e| e.to_string())?)
        }
    };
    let mut h = sha2::Sha256::new();
    let mut tampon = vec![0u8; 64 << 10];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut tampon).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > PROGRAMME_MAX {
            return Err(trf!("{} : trop gros", "{}: too large", chemin_affichable(source)));
        }
        h.update(&tampon[..n]);
        if let Some(v) = vers.as_mut() {
            v.write_all(&tampon[..n]).map_err(|e| e.to_string())?;
        }
    }
    if let Some(v) = vers {
        v.sync_all().map_err(|e| e.to_string())?;
    }
    Ok(hex(&h.finalize()))
}

/// Le manifeste d'un dossier de plugin, lu une seule fois : l'empreinte est celle des octets mêmes qui sont analysés.
fn lire_manifeste(d: &Path) -> Result<(Manifeste, String), String> {
    let octets = lire_sur(&d.join(MANIFESTE), manifeste::OCTETS_MAX)?;
    let empreinte = hex(&sha2::Sha256::digest(&octets));
    let texte = String::from_utf8(octets)
        .map_err(|_| tr!("plugin.toml n'est pas en UTF-8", "plugin.toml is not UTF-8").to_string())?;
    let m = manifeste::lire(&texte).map_err(|e| format!("plugin.toml, {e}"))?;
    Ok((m, empreinte))
}

/// Le chemin d'un programme du manifeste dans son dossier (`chemin_valide` l'a déjà gardé dedans).
fn chemin_du_programme(d: &Path, programme: &str) -> PathBuf {
    programme.split(['/', '\\']).fold(d.to_path_buf(), |c, p| c.join(p))
}

/// Les empreintes des programmes déclarés. Celui de ce système doit exister ; celui d'un autre système peut manquer
/// (un programme Rust compilé ici n'a pas son .exe) : absent de l'approbation, il sera refusé s'il apparaît.
fn empreintes(d: &Path, m: &Manifeste) -> Result<BTreeMap<String, String>, String> {
    let ici = m.commande(Systeme::ici()).map(|c| c.programme.as_str());
    let mut e = BTreeMap::new();
    for p in m.programmes() {
        let chemin = chemin_du_programme(d, p);
        if Some(p) != ici && std::fs::symlink_metadata(&chemin).is_err() {
            continue;
        }
        e.insert(p.to_string(), hacher_et_copier(&chemin, None)?);
    }
    Ok(e)
}

/// L'état d'un plugin du dossier.
#[derive(Debug, PartialEq, Eq)]
pub enum Etat {
    Pret,
    NonApprouve,
    /// Une empreinte a changé depuis l'approbation.
    Change,
    /// Il ne vise pas ce système.
    AutreSysteme,
    Invalide(String),
}

pub struct Plugin {
    pub nom: String,
    pub manifeste: Option<Manifeste>,
    pub etat: Etat,
}

/// Les plugins du dossier, dans l'ordre des noms (100 au plus). Les dossiers cachés (copies en cours, constats
/// gardés) n'en sont pas.
pub fn inventaire(racine: &Path) -> Vec<Plugin> {
    let approuves = approbations(racine);
    let mut noms: Vec<String> = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        // Le laboratoire a son dossier à lui, sans manifeste : ce n'est pas un plugin.
        .filter(|n| !n.starts_with('.') && n != labo::DOSSIER)
        .take(100)
        .collect();
    noms.sort();
    noms.into_iter()
        .map(|nom| {
            let d = racine.join(&nom);
            let lu = if manifeste::nom_valide(&nom) {
                dossier_sur(&d).and_then(|()| lire_manifeste(&d))
            } else {
                Err(tr!("nom de dossier refusé", "folder name refused").to_string())
            };
            match lu {
                Err(e) => Plugin {
                    nom,
                    manifeste: None,
                    etat: Etat::Invalide(e),
                },
                Ok((m, empreinte)) => {
                    let etat = if m.nom == nom {
                        match approuves.plugins.get(&nom) {
                            None => Etat::NonApprouve,
                            Some(a) if a.manifeste != empreinte => Etat::Change,
                            Some(a) => match empreintes(&d, &m) {
                                Ok(e) if e != a.programmes => Etat::Change,
                                Ok(_) if m.commande(Systeme::ici()).is_none() => Etat::AutreSysteme,
                                Ok(_) => Etat::Pret,
                                Err(e) => Etat::Invalide(e),
                            },
                        }
                    } else {
                        Etat::Invalide(trf!("le manifeste dit « {} »", "the manifest says “{}”", m.nom))
                    };
                    Plugin {
                        nom,
                        manifeste: Some(m),
                        etat,
                    }
                }
            }
        })
        .collect()
}

/// Les variables d'un plugin : le PATH du système (jamais celui de la personne, qu'un programme peut allonger), LANG,
/// HOME ; sous Windows, en plus, ce sans quoi PowerShell et la plupart des programmes ne démarrent pas. Aucune variable
/// de Vanguard (VANGUARD_*), ni rien d'autre de son environnement.
fn environnement(c: &mut Command) {
    c.env_clear();
    // La langue de l'interface de Vanguard (VANGUARD_LANG compris) : celle du système si elle est la même, pour
    // garder sa région (fr_CA), sinon la sienne.
    let langue = std::env::var("LANG")
        .ok()
        .filter(|l| l.starts_with(tr!("fr", "en")))
        .unwrap_or_else(|| tr!("fr_FR.UTF-8", "en_US.UTF-8").to_string());
    c.env("LANG", langue);
    c.env("PATH", path_systeme());
    #[cfg(unix)]
    {
        if let Some(h) = std::env::var_os("HOME") {
            c.env("HOME", h);
        }
    }
    #[cfg(windows)]
    {
        let racine = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        c.env("SystemRoot", &racine).env("windir", &racine);
        for v in [
            "SystemDrive",
            "USERPROFILE",
            "TEMP",
            "TMP",
            "APPDATA",
            "LOCALAPPDATA",
            "COMPUTERNAME",
            "USERNAME",
        ] {
            if let Some(x) = std::env::var_os(v) {
                c.env(v, x);
            }
        }
        if let Some(h) = std::env::var_os("USERPROFILE") {
            c.env("HOME", h);
        }
    }
}

/// Le PATH du système : jamais celui de la personne, qu'un programme peut allonger.
fn path_systeme() -> String {
    #[cfg(unix)]
    {
        PATH_SYSTEME.to_string()
    }
    #[cfg(windows)]
    {
        let racine = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        format!(r"{racine}\System32;{racine};{racine}\System32\Wbem;{racine}\System32\WindowsPowerShell\v1.0")
    }
}

/// Un programme du PATH du système (sous Windows, son « .exe »).
fn dans_le_path_systeme(nom: &str) -> Option<PathBuf> {
    let nom = if cfg!(windows) {
        format!("{nom}.exe")
    } else {
        nom.to_string()
    };
    let separateur = if cfg!(windows) { ';' } else { ':' };
    path_systeme()
        .split(separateur)
        .map(|d| Path::new(d).join(&nom))
        .find(|p| p.is_file())
}

#[cfg(target_os = "macos")]
const PATH_SYSTEME: &str = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin";
#[cfg(all(unix, not(target_os = "macos")))]
const PATH_SYSTEME: &str = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin";

/// Ce qui lance `programme` : un script shell par /bin/sh (une copie depuis une clé exFAT perd le droit d'exécution),
/// un script PowerShell par le PowerShell de System32 (Windows) ou pwsh (ailleurs), le reste directement. Rend le
/// programme à lancer et ses premiers arguments.
fn interprete(programme: &Path) -> Result<(PathBuf, Vec<String>), String> {
    let extension = programme
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    let chemin = programme.to_string_lossy().into_owned();
    match extension.as_deref() {
        #[cfg(unix)]
        Some("sh") => Ok(("/bin/sh".into(), vec![chemin])),
        // La stratégie d'exécution (Restricted par défaut sur un poste Windows) refuserait tout script : Bypass ne vaut
        // que pour ce processus, et ce script-là vient d'être vérifié par son empreinte.
        #[cfg(windows)]
        Some("ps1") => Ok((
            crate::machine::windows::powershell().get_program().into(),
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]
                .map(String::from)
                .into_iter()
                .chain([chemin])
                .collect(),
        )),
        #[cfg(unix)]
        Some("bash") => Ok(("/bin/bash".into(), vec![chemin])),
        #[cfg(unix)]
        Some("ps1") => dans_le_path_systeme("pwsh")
            .map(|p| {
                (
                    p,
                    vec!["-NoProfile".into(), "-NonInteractive".into(), "-File".into(), chemin],
                )
            })
            .ok_or_else(|| {
                tr!(
                    "pwsh est introuvable : un script PowerShell ne peut pas tourner ici",
                    "pwsh not found: a PowerShell script cannot run here"
                )
                .to_string()
            }),
        // Le python3 du système seulement : un python posé plus tôt dans le PATH de la personne ne sera pas pris.
        Some("py") => dans_le_path_systeme("python3")
            .map(|p| (p, vec![chemin]))
            .ok_or_else(|| tr!("python3 introuvable : non lancé", "python3 not found: not run").to_string()),
        _ => Ok((programme.to_path_buf(), Vec::new())),
    }
}

/// La commande telle qu'elle sera lancée, prête à montrer.
fn decrire(programme: &str, arguments: &[String]) -> String {
    let premier = interprete(Path::new(programme)).map_or_else(
        |_| programme.to_string(),
        |(p, a)| {
            let p = if a.is_empty() {
                programme.to_string()
            } else {
                p.file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
            };
            std::iter::once(p)
                .chain(a.into_iter().map(|x| {
                    if x.ends_with(programme) {
                        programme.to_string()
                    } else {
                        x
                    }
                }))
                .collect::<Vec<_>>()
                .join(" ")
        },
    );
    std::iter::once(premier)
        .chain(arguments.iter().map(|a| {
            if a.is_empty() || a.contains(char::is_whitespace) {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        }))
        .map(|t| commande_affichable(&t))
        .collect::<Vec<_>>()
        .join(" ")
}

/// L'analyse d'un plugin ou d'un script avant l'accord : les règles YARA et les empreintes de MalwareBazaar de
/// Vanguard, sur la copie qui sera approuvée. Une correspondance : `Err`, avec la règle (refusé). Une analyse
/// impossible : dite, et l'accord reste à demander. Rend la ligne à montrer.
fn analyser_avant_accord(chemin: &Path) -> Result<String, String> {
    use crate::protection::antivirus::Examen;
    let bazaar = crate::protection::empreintes::connues().is_some();
    match crate::protection::yara::examiner(chemin) {
        Examen::Trouve(regles) => Err(trf!(
            "Refusé : l'analyse de Vanguard reconnaît un logiciel malveillant ({}). Rien n'a été approuvé.",
            "Refused: Vanguard's scan recognizes malware ({}). Nothing was approved.",
            regles.iter().map(|r| affichable(r)).collect::<Vec<_>>().join(", ")
        )),
        Examen::Impossible(pourquoi) => Ok(trf!(
            "⚠ analyse impossible ({}) : rien ne dit qu'il est sain",
            "⚠ scan not possible ({}): nothing says it is safe",
            affichable(&pourquoi)
        )),
        Examen::Sain if bazaar => Ok(tr!(
            "aucune règle YARA ni empreinte MalwareBazaar ne correspond",
            "no YARA rule nor MalwareBazaar fingerprint matches"
        )
        .to_string()),
        Examen::Sain => Ok(tr!(
            "aucune règle YARA ne correspond (⚠ empreintes MalwareBazaar absentes : non comparées)",
            "no YARA rule matches (⚠ MalwareBazaar fingerprints missing: not compared)"
        )
        .to_string()),
    }
}

/// Les fichiers d'un dossier et leur taille, chemins relatifs, dans l'ordre (sans suivre de lien).
fn fichiers_et_tailles(d: &Path) -> Vec<(String, u64)> {
    let mut liste = Vec::new();
    let mut a_voir = vec![d.to_path_buf()];
    while let Some(x) = a_voir.pop() {
        for e in std::fs::read_dir(&x).into_iter().flatten().flatten() {
            let Ok(m) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            if m.is_dir() {
                a_voir.push(e.path());
            } else {
                let relatif = e.path().strip_prefix(d).map_or_else(|_| e.path(), Path::to_path_buf);
                liste.push((relatif.to_string_lossy().into_owned(), m.len()));
            }
        }
    }
    liste.sort();
    liste
}

/// Une taille lisible : « 812 o », « 4,2 Kio », « 1,3 Mio ».
fn taille(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)] // une taille à montrer, au dixième
    let f = octets as f64;
    if octets < 1024 {
        trf!("{octets} o", "{octets} B")
    } else if octets < 1 << 20 {
        trf!("{} Kio", "{} KiB", crate::langue::decimal(f / 1024.0, 1))
    } else {
        trf!("{} Mio", "{} MiB", crate::langue::decimal(f / f64::from(1u32 << 20), 1))
    }
}

/// Le rappel montré avant chaque accord.
fn rappel(texte: &str) {
    for (i, l) in envelopper(texte, LARGEUR - 4).iter().enumerate() {
        let marque = if i == 0 {
            format!("{}⚠{RESET}", couleur(crate::risk::Niveau::Moyen))
        } else {
            " ".to_string()
        };
        println!("  {marque} {l}");
    }
}

/// Ce que l'approbation montre : nom, auteur et source (non vérifiés), ce qu'il lancera, ses fichiers et leur taille,
/// les empreintes notées et le résultat de l'analyse. `copie` : le dossier tel qu'il sera approuvé.
fn presenter(
    copie: &Path,
    destination: &Path,
    m: &Manifeste,
    manifeste: &str,
    programmes: &BTreeMap<String, String>,
    analyse: &str,
) {
    println!();
    trp!(
        "  {GRAS}Plugin « {} »{RESET} ({})",
        "  {GRAS}Plugin “{}”{RESET} ({})",
        affichable(m.titre()),
        m.nom
    );
    afficher_aligne("  ", &affichable(m.description()), 2, GRIS);
    let non_verifie = tr!("non vérifié par Vanguard", "not checked by Vanguard");
    for (libelle, valeur) in [
        (tr!("  Auteur     : ", "  Author     : "), &m.auteur),
        (tr!("  Source     : ", "  Source     : "), &m.source),
    ] {
        let texte = valeur.as_deref().map_or_else(
            || trf!("non dit ({non_verifie})", "not given ({non_verifie})"),
            |v| format!("{} ({non_verifie})", affichable(v)),
        );
        afficher_aligne(libelle, &texte, 15, "");
    }
    let systemes: Vec<&str> = m.systemes.iter().map(|s| s.nom()).collect();
    trp!("  Systèmes   : {}", "  Systems    : {}", systemes.join(", "));
    match m.commande(Systeme::ici()) {
        Some(c) => afficher_aligne(
            &trf!("  Lancera    : ", "  Will run   : "),
            &decrire(&c.programme, &c.arguments),
            15,
            "",
        ),
        None => trp!(
            "  Lancera    : rien ici (ne vise pas ce système)",
            "  Will run   : nothing here (does not target this system)"
        ),
    }
    trp!(
        "  Au plus    : {} s, sans droits d'administrateur",
        "  At most    : {} s, without administrator rights",
        m.delai
    );
    afficher_aligne(
        &trf!("  Dossier    : ", "  Folder     : "),
        &chemin_affichable(destination),
        15,
        "",
    );
    let fichiers = fichiers_et_tailles(copie);
    trp!(
        "  Fichiers ({}, {}) :",
        "  Files ({}, {}):",
        fichiers.len(),
        taille(fichiers.iter().map(|f| f.1).sum())
    );
    for (f, o) in fichiers.iter().take(30) {
        println!("    {}  {GRIS}{}{RESET}", couper(&affichable(f), 56), taille(*o));
    }
    if fichiers.len() > 30 {
        trp!("    … et {} autre(s)", "    … and {} more", fichiers.len() - 30);
    }
    trp!("  Empreintes SHA-256 :", "  SHA-256 fingerprints:");
    println!("    {MANIFESTE}");
    println!("      {GRIS}{manifeste}{RESET}");
    for (p, e) in programmes {
        println!("    {}", affichable(p));
        println!("      {GRIS}{e}{RESET}");
    }
    afficher_aligne(&trf!("  Analyse    : ", "  Scan       : "), analyse, 15, "");
    println!();
    rappel(tr!(
        "Un plugin n'est pas du code de Vanguard : ce programme pourra lire et modifier tes fichiers, comme toi, et parler au réseau. N'approuve que ce que tu as écrit ou relu. S'il change, Vanguard le refusera jusqu'à une nouvelle approbation.",
        "A plugin is not Vanguard's code: this program will be able to read and change your files, like you, and talk to the network. Only approve what you wrote or reviewed. If it changes, Vanguard will refuse it until approved again."
    ));
}

/// Une copie en cours (ajout ou lancement), retirée quoi qu'il arrive.
struct Temporaire(PathBuf);

impl Temporaire {
    /// Un dossier caché du dossier des plugins, réservé à son compte, qui ne doit pas déjà exister : rien de posé
    /// d'avance n'est repris.
    fn creer(racine: &Path, quoi: &str) -> Result<Temporaire, String> {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = racine.join(format!(".{quoi}-{}-{n}", std::process::id()));
        #[cfg_attr(windows, allow(unused_mut))]
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&d).map_err(|e| e.to_string())?;
        Ok(Temporaire(d))
    }
}

impl Drop for Temporaire {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Les copies laissées par un Vanguard arrêté net (plus d'une heure) : retirées.
fn menage(racine: &Path) {
    let vieux = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    for e in std::fs::read_dir(racine).into_iter().flatten().flatten() {
        let nom = e.file_name().to_string_lossy().into_owned();
        if (nom.starts_with(".lancement-") || nom.starts_with(".ajout-"))
            && e.metadata().and_then(|m| m.modified()).is_ok_and(|t| t < vieux)
        {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Copie le dossier `de` dans `vers` (qui existe) : seulement des fichiers et des dossiers ordinaires, jamais un lien
/// (il ferait lire ou lancer autre chose que ce qui a été copié), dans les bornes.
fn copier_arbre(de: &Path, vers: &Path, compte: &mut (usize, u64), profondeur: usize) -> Result<(), String> {
    if profondeur > PROFONDEUR_MAX {
        return Err(tr!("dossiers trop imbriqués", "folders nested too deep").to_string());
    }
    let entrees = std::fs::read_dir(de).map_err(|e| format!("{} : {e}", chemin_affichable(de)))?;
    for entree in entrees {
        let entree = entree.map_err(|e| e.to_string())?;
        // Ce que la compilation ou git laissent à la racine d'un plugin (target/ d'un plugin en Rust, des centaines de
        // Mo) n'en fait pas partie : son programme est dans bin/ (voir extensions/LISEZMOI.md).
        if profondeur == 0 && matches!(entree.file_name().to_str(), Some("target" | ".git")) {
            continue;
        }
        let source = entree.path();
        let cible = vers.join(entree.file_name());
        let meta = std::fs::symlink_metadata(&source).map_err(|e| e.to_string())?;
        compte.0 += 1;
        if compte.0 > COPIE_FICHIERS_MAX {
            return Err(trf!(
                "plus de {COPIE_FICHIERS_MAX} fichiers",
                "more than {COPIE_FICHIERS_MAX} files"
            ));
        }
        if meta.file_type().is_symlink() {
            return Err(trf!(
                "{} est un lien : refusé",
                "{} is a link: refused",
                chemin_affichable(&source)
            ));
        } else if meta.is_dir() {
            creer_prive(&cible).map_err(|e| e.to_string())?;
            copier_arbre(&source, &cible, compte, profondeur + 1)?;
        } else if meta.is_file() {
            compte.1 += meta.len();
            if compte.1 > COPIE_OCTETS_MAX {
                return Err(trf!("plus de {} Mo", "more than {} MB", COPIE_OCTETS_MAX >> 20));
            }
            let mut lecture = std::fs::File::open(&source).map_err(|e| e.to_string())?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let droits = if meta.permissions().mode() & 0o111 != 0 {
                    0o700
                } else {
                    0o600
                };
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, droits);
            }
            let mut ecriture = options.open(&cible).map_err(|e| e.to_string())?;
            std::io::copy(&mut lecture, &mut ecriture).map_err(|e| e.to_string())?;
        } else {
            return Err(trf!(
                "{} n'est pas un fichier ordinaire : refusé",
                "{} is not a regular file: refused",
                chemin_affichable(&source)
            ));
        }
    }
    Ok(())
}

/// `vanguard plugin ajouter <dossier ou archive.zip>` : copie le plugin dans le dossier des plugins, l'analyse, montre
/// ce qu'il lancera, et l'approuve sur accord. Ce qui est montré, analysé et haché est la copie, pas l'original : c'est
/// elle qui tournera. Une archive est d'abord dépliée à l'écart (`archive`). Rend le nom.
fn ajouter(racine: &Path, source: &Path, accord: impl FnOnce(&str) -> bool) -> Result<String, String> {
    menage(racine);
    let est_zip = source.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip"));
    if !est_zip {
        let source_reelle =
            std::fs::canonicalize(source).map_err(|e| trf!("{} : {e}", "{}: {e}", chemin_affichable(source)))?;
        if std::fs::canonicalize(racine).is_ok_and(|r| source_reelle.starts_with(r)) {
            return Err(tr!(
                "Ce dossier est déjà dans celui des plugins : « vanguard plugin approuver <nom> ».",
                "This folder is already in the plugins folder: “vanguard plugin approve <name>”."
            )
            .to_string());
        }
        return ajouter_dossier(racine, source, accord);
    }
    let depliage = Temporaire::creer(racine, "ajout")?;
    archive::deplier(source, &depliage.0).map_err(|e| trf!("Plugin non ajouté : {e}.", "Plugin not added: {e}."))?;
    // Le manifeste à la racine de l'archive, ou dans son seul dossier (une archive faite d'un dossier entier).
    let mut d = depliage.0.clone();
    if !d.join(MANIFESTE).exists() {
        let dossiers: Vec<PathBuf> = std::fs::read_dir(&d)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        if let [seul] = &dossiers[..] {
            d.clone_from(seul);
        }
    }
    ajouter_dossier(racine, &d, accord)
}

fn ajouter_dossier(racine: &Path, source: &Path, accord: impl FnOnce(&str) -> bool) -> Result<String, String> {
    let (m, _) = lire_manifeste(source)?;
    let essai = Temporaire::creer(racine, "ajout")?;
    let copie = essai.0.join(&m.nom);
    creer_prive(&copie).map_err(|e| e.to_string())?;
    copier_arbre(source, &copie, &mut (0, 0), 0)
        .map_err(|e| trf!("Plugin non ajouté : {e}.", "Plugin not added: {e}."))?;
    let (m, empreinte) = lire_manifeste(&copie)?;
    let programmes = empreintes(&copie, &m)?;
    let destination = racine.join(&m.nom);
    let libre = reglages::charger(racine).sans_restrictions;
    if !libre {
        let analyse = analyser_avant_accord(&copie)?;
        presenter(&copie, &destination, &m, &empreinte, &programmes, &analyse);
    }
    let question = if destination.exists() {
        trf!(
            "\n  Un plugin « {} » est déjà là : le remplacer par celui-ci et l'approuver ? [o/N] : ",
            "\n  A plugin “{}” is already there: replace it with this one and approve it? [y/N]: ",
            m.nom
        )
    } else {
        trf!(
            "\n  Ajouter ce plugin et l'approuver ? [o/N] : ",
            "\n  Add this plugin and approve it? [y/N]: "
        )
    };
    if !libre && !accord(&question) {
        return Err(tr!("Rien n'a été ajouté.", "Nothing was added.").to_string());
    }
    if destination.exists() {
        let ancien = Temporaire::creer(racine, "ajout")?;
        std::fs::rename(&destination, ancien.0.join("ancien")).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&copie, &destination).map_err(|e| e.to_string())?;
    noter(racine, &m.nom, empreinte, programmes)?;
    Ok(m.nom)
}

fn noter(racine: &Path, nom: &str, manifeste: String, programmes: BTreeMap<String, String>) -> Result<(), String> {
    let mut a = approbations(racine);
    a.plugins.insert(
        nom.to_string(),
        Approbation {
            manifeste,
            programmes,
            le: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        },
    );
    enregistrer(racine, &a)
}

/// `vanguard plugin approuver <nom>` : le plugin tel qu'il est maintenant dans son dossier, remontré, puis approuvé.
fn approuver(racine: &Path, nom: &str, accord: impl FnOnce(&str) -> bool) -> Result<(), String> {
    let d = dossier_du_plugin(racine, nom)?;
    let (m, empreinte) = lire_manifeste(&d)?;
    if m.nom != nom {
        return Err(trf!(
            "Le manifeste de « {nom} » dit « {} » : refusé.",
            "The manifest of “{nom}” says “{}”: refused.",
            m.nom
        ));
    }
    let programmes = empreintes(&d, &m)?;
    let avant = approbations(racine).plugins.get(nom).cloned();
    let analyse = analyser_avant_accord(&d)?;
    presenter(&d, &d, &m, &empreinte, &programmes, &analyse);
    if let Some(a) = &avant {
        let mut changes: Vec<String> = Vec::new();
        if a.manifeste != empreinte {
            changes.push(MANIFESTE.to_string());
        }
        for (p, e) in &programmes {
            if a.programmes.get(p) != Some(e) {
                changes.push(affichable(p));
            }
        }
        if changes.is_empty() {
            trp!(
                "\n  Rien n'a changé depuis l'approbation du {}.",
                "\n  Nothing changed since the approval of {}.",
                a.le
            );
            return Ok(());
        }
        trp!(
            "\n  Changé depuis l'approbation du {} : {}",
            "\n  Changed since the approval of {}: {}",
            a.le,
            changes.join(", ")
        );
    }
    if !accord(&trf!(
        "\n  Approuver ce plugin tel quel ? [o/N] : ",
        "\n  Approve this plugin as it is? [y/N]: "
    )) {
        return Err(tr!("Rien n'a été approuvé.", "Nothing was approved.").to_string());
    }
    noter(racine, nom, empreinte, programmes)
}

/// Le dossier d'un plugin, jugé : un nom valide, un dossier sûr.
fn dossier_du_plugin(racine: &Path, nom: &str) -> Result<PathBuf, String> {
    if !manifeste::nom_valide(nom) {
        return Err(trf!(
            "« {} » n'est pas un nom de plugin.",
            "“{}” is not a plugin name.",
            affichable(nom)
        ));
    }
    let d = racine.join(nom);
    if std::fs::symlink_metadata(&d).is_err() {
        return Err(trf!(
            "Aucun plugin « {nom} » : « vanguard plugin liste ».",
            "No plugin “{nom}”: “vanguard plugin list”."
        ));
    }
    dossier_sur(&d)?;
    Ok(d)
}

/// `vanguard plugin retirer <nom>` : son dossier, son approbation et ses constats gardés, sur accord.
fn retirer(racine: &Path, nom: &str, accord: impl FnOnce(&str) -> bool) -> Result<bool, String> {
    if !manifeste::nom_valide(nom) {
        return Err(trf!(
            "« {} » n'est pas un nom de plugin.",
            "“{}” is not a plugin name.",
            affichable(nom)
        ));
    }
    let d = racine.join(nom);
    let mut a = approbations(racine);
    if std::fs::symlink_metadata(&d).is_err() && !a.plugins.contains_key(nom) {
        return Err(trf!("Aucun plugin « {nom} ».", "No plugin “{nom}”."));
    }
    if !accord(&trf!(
        "  Retirer le plugin « {nom} » (son dossier et son approbation) ? [o/N] : ",
        "  Remove the plugin “{nom}” (its folder and its approval)? [y/N]: "
    )) {
        return Ok(false);
    }
    // Un lien posé à la place du dossier est retiré lui-même, sans suivre ce qu'il désigne.
    match std::fs::symlink_metadata(&d) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(&d).map_err(|e| e.to_string())?,
        Ok(_) => std::fs::remove_file(&d).map_err(|e| e.to_string())?,
        Err(_) => {}
    }
    let _ = std::fs::remove_file(racine.join(CONSTATS).join(format!("{nom}.json")));
    if a.plugins.remove(nom).is_some() {
        enregistrer(racine, &a)?;
    }
    Ok(true)
}

/// Un plugin qui a tourné.
pub struct Issue {
    pub manifeste: Manifeste,
    pub borne: crate::commande::Borne,
}

/// Comment lancer : `isole` (Linux, bubblewrap) sans réseau ni écriture hors d'un dossier jetable.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Facon {
    pub isole: bool,
}

/// La commande d'un programme d'extension : son interpréteur, ses arguments, son dossier comme dossier courant ;
/// l'environnement minimal sauf sans restrictions (`libre`) ; dans bubblewrap avec `isole` (alors `jetable` reçoit
/// la seule écriture permise).
fn commande_de(
    programme: &Path,
    arguments: &[String],
    dossier: &Path,
    libre: bool,
    isole: Option<&Path>,
) -> Result<Command, String> {
    let (p, premiers) = interprete(programme)?;
    let tout: Vec<String> = premiers.into_iter().chain(arguments.iter().cloned()).collect();
    let mut c = match isole {
        None => {
            let mut c = Command::new(p);
            c.args(&tout);
            c
        }
        #[cfg(target_os = "linux")]
        Some(jetable) => {
            let ligne: Vec<String> = std::iter::once(p.to_string_lossy().into_owned()).chain(tout).collect();
            let a = crate::protection::isoler::arguments_extension(jetable, dossier, &ligne).ok_or_else(|| {
                tr!(
                    "Isolement impossible : bubblewrap (bwrap) n'est pas installé.",
                    "Isolation not possible: bubblewrap (bwrap) is not installed."
                )
                .to_string()
            })?;
            let mut c = Command::new(dans_le_path_systeme("bwrap").unwrap_or_else(|| "bwrap".into()));
            c.args(a);
            c
        }
        #[cfg(not(target_os = "linux"))]
        Some(_) => {
            return Err(tr!(
                "Isolement non disponible sur ce système (Linux et bubblewrap seulement).",
                "Isolation not available on this system (Linux and bubblewrap only)."
            )
            .to_string());
        }
    };
    c.current_dir(dossier);
    if !libre {
        environnement(&mut c);
    }
    Ok(c)
}

/// Sans restrictions et en administrateur : permis, mais dit.
fn avertir_eleve_libre() {
    if eleve() {
        trp!(
            "  {}⚠{RESET} Sans restrictions et en administrateur : cette extension a tous les droits sur l'ordinateur.",
            "  {}⚠{RESET} Without restrictions and as administrator: this extension has every right on the computer.",
            couleur(crate::risk::Niveau::Eleve)
        );
    }
}

/// Lance le plugin `nom`, avec `arguments` après ses arguments fixes. Restrictions actives, chaque garde-fou dans
/// l'ordre : pas en administrateur, dossier sûr, manifeste lu une fois et comparé à son empreinte, programme copié
/// en étant haché puis comparé, copie lancée (environnement minimal, son dossier comme dossier courant, délai et sortie
/// bornés). Sans restrictions (`reglages`) : le dossier sûr seulement, puis le programme lui-même.
pub fn lancer(racine: &Path, nom: &str, arguments: &[String], facon: Facon) -> Result<Issue, String> {
    if arguments.len() > ARGUMENTS_MAX || arguments.iter().any(|a| a.len() > ARGUMENT_MAX || a.contains('\0')) {
        return Err(trf!(
            "Trop d'arguments, ou trop longs ({ARGUMENTS_MAX} de {ARGUMENT_MAX} caractères au plus).",
            "Too many arguments, or too long ({ARGUMENTS_MAX} of {ARGUMENT_MAX} characters at most)."
        ));
    }
    let d = dossier_du_plugin(racine, nom)?;
    let refuse_change = || {
        trf!(
            "Le plugin « {nom} » a changé depuis son approbation : refusé. Relis-le, puis « vanguard plugin approuver {nom} ».",
            "The plugin “{nom}” changed since it was approved: refused. Review it, then “vanguard plugin approve {nom}”."
        )
    };
    let (m, empreinte) = lire_manifeste(&d)?;
    if m.nom != nom {
        return Err(refuse_change());
    }
    let Some(c) = m.commande(Systeme::ici()).cloned() else {
        return Err(trf!(
            "Le plugin « {nom} » ne vise pas ce système ({}).",
            "The plugin “{nom}” does not target this system ({}).",
            Systeme::ici().nom()
        ));
    };
    let libre = reglages::charger(racine).plugin_libre(&m);
    let tous: Vec<String> = c.arguments.iter().chain(arguments).cloned().collect();
    menage(racine);
    let essai = Temporaire::creer(racine, "lancement")?;
    let source = chemin_du_programme(&d, &c.programme);
    let (programme, delai, sortie) = if libre {
        avertir_eleve_libre();
        (source, reglages::DELAI_LIBRE.max(m.delai), reglages::SORTIE_LIBRE)
    } else {
        if eleve() {
            return Err(refus_eleve());
        }
        let Some(approuve) = approbations(racine).plugins.remove(nom) else {
            return Err(trf!(
                "Le plugin « {nom} » n'est pas approuvé : « vanguard plugin approuver {nom} » montre ce qu'il lancera.",
                "The plugin “{nom}” is not approved: “vanguard plugin approve {nom}” shows what it will run."
            ));
        };
        if empreinte != approuve.manifeste {
            return Err(refuse_change());
        }
        let attendue = approuve.programmes.get(&c.programme).ok_or_else(refuse_change)?;
        let copie = essai.0.join(source.file_name().unwrap_or_default());
        if hacher_et_copier(&source, Some(&copie))? != *attendue {
            return Err(refuse_change());
        }
        (copie, m.delai, SORTIE_MAX)
    };
    let mut commande = commande_de(&programme, &tous, &d, libre, facon.isole.then_some(essai.0.as_path()))?;
    let borne = crate::commande::lancer_borne(&mut commande, delai, sortie).ok_or_else(|| {
        trf!(
            "Le plugin « {nom} » n'a pas pu démarrer.",
            "The plugin “{nom}” could not start."
        )
    })?;
    drop(essai);
    Ok(Issue { manifeste: m, borne })
}

/// `vanguard plugin …` : rend le code de sortie (celui du plugin lancé, sinon 0 ou 1).
pub fn commande(quoi: &[String]) -> i32 {
    let Some(mot) = quoi.first().map(String::as_str) else {
        return match dossier() {
            Ok(r) => {
                menu::plugins(&r);
                0
            }
            Err(e) => echec(&e),
        };
    };
    if matches!(mot, "liste" | "list") {
        return match dossier() {
            Ok(r) => {
                liste(&r);
                0
            }
            Err(e) => echec(&e),
        };
    }
    // Retirer reste permis en administrateur : ça n'exécute rien.
    let racine = match dossier() {
        Ok(r) => r,
        Err(e) => return echec(&e),
    };
    if matches!(mot, "ajouter" | "add" | "approuver" | "approve")
        && eleve()
        && !reglages::charger(&racine).sans_restrictions
    {
        return echec(&refus_eleve());
    }
    let accord = |q: &str| demander(q).oui();
    let deuxieme = quoi.get(1).map(String::as_str);
    let resultat = match (mot, deuxieme) {
        ("ajouter" | "add", Some(source)) => ajouter(&racine, Path::new(source), accord).map(|nom| {
            trp!(
                "  {VERT}✔{RESET} Plugin « {nom} » ajouté et approuvé : « vanguard plugin {nom} » le lance.",
                "  {VERT}✔{RESET} Plugin “{nom}” added and approved: “vanguard plugin {nom}” runs it."
            );
        }),
        ("approuver" | "approve", Some(nom)) => approuver(&racine, nom, accord).map(|()| {
            trp!("  {VERT}✔{RESET} Approuvé.", "  {VERT}✔{RESET} Approved.");
        }),
        ("retirer" | "remove", Some(nom)) => retirer(&racine, nom, accord).map(|fait| {
            if fait {
                trp!("  {VERT}✔{RESET} Retiré.", "  {VERT}✔{RESET} Removed.");
            }
        }),
        ("ajouter" | "add" | "approuver" | "approve" | "retirer" | "remove", None) => Err(trf!(
            "Il manque le dossier ou le nom : « vanguard plugin {mot} <…> ».",
            "The folder or the name is missing: “vanguard plugin {mot} <…>”."
        )),
        (nom, _) => {
            let (rapport, facon, arguments) = options_de_lancement(&quoi[1..]);
            return executer(&racine, nom, &arguments, rapport, facon);
        }
    };
    match resultat {
        Ok(()) => 0,
        Err(e) => echec(&e),
    }
}

/// `--rapport` (n'importe où avant `--`) est pour Vanguard ; tout le reste, et tout ce qui suit `--`, pour le plugin.
fn options_de_lancement(args: &[String]) -> (bool, Facon, Vec<String>) {
    let mut rapport = false;
    let mut facon = Facon::default();
    let mut pour_le_plugin = Vec::new();
    let mut apres = false;
    for a in args {
        match a.as_str() {
            "--" if !apres => apres = true,
            "--rapport" | "--report" if !apres => rapport = true,
            "--isole" | "--isolated" if !apres => facon.isole = true,
            _ => pour_le_plugin.push(a.clone()),
        }
    }
    (rapport, facon, pour_le_plugin)
}

fn echec(e: &str) -> i32 {
    afficher_aligne(&format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)), e, 4, "");
    1
}

/// Lance un plugin et montre ce qu'il a dit ; avec `rapport`, ses constats sont gardés pour le rapport HTML.
fn executer(racine: &Path, nom: &str, arguments: &[String], rapport: bool, facon: Facon) -> i32 {
    if let Ok(d) = dossier_du_plugin(racine, nom)
        && let Ok((m, _)) = lire_manifeste(&d)
    {
        titre(&trf!(
            "Plugin « {} » — hors code de Vanguard",
            "Plugin “{}” — not Vanguard's code",
            affichable(m.titre())
        ));
        trp!(
            "  {GRIS}En cours (au plus {} s)…{RESET}",
            "  {GRIS}Running (at most {} s)…{RESET}",
            m.delai
        );
    }
    match lancer(racine, nom, arguments, facon) {
        Err(e) => echec(&e),
        Ok(issue) => {
            let lu = sortie::analyser(&issue.borne.sortie);
            sortie::afficher(
                &format!("plugin {nom}"),
                issue.manifeste.titre(),
                issue.manifeste.delai,
                &issue.borne,
                &lu,
            );
            if rapport {
                match sortie::garder(racine, &issue.manifeste, &lu.constats) {
                    Ok(()) => trp!(
                        "\n  {GRIS}Constats gardés pour le rapport HTML (section Plugins) : menu 3, ou « vanguard complet --html ».{RESET}",
                        "\n  {GRIS}Findings kept for the HTML report (Plugins section): menu 3, or “vanguard full --html”.{RESET}"
                    ),
                    Err(e) => {
                        echec(&e);
                    }
                }
            }
            issue.borne.code.unwrap_or(1)
        }
    }
}

/// `vanguard plugin liste` : chaque plugin du dossier et son état.
fn liste(racine: &Path) {
    titre(tr!("Plugins", "Plugins"));
    afficher_aligne(
        &trf!("  {GRIS}Dossier : ", "  {GRIS}Folder: "),
        &chemin_affichable(racine),
        4,
        GRIS,
    );
    let plugins = inventaire(racine);
    if plugins.is_empty() {
        aide_ajout();
        return;
    }
    let approuves = approbations(racine);
    for p in &plugins {
        let (marque, etat) = match &p.etat {
            Etat::Pret => (
                format!("{VERT}✔{RESET}"),
                trf!(
                    "approuvé le {}",
                    "approved on {}",
                    approuves.plugins.get(&p.nom).map_or("?", |a| a.le.as_str())
                ),
            ),
            Etat::NonApprouve => (
                format!("{}•{RESET}", couleur(crate::risk::Niveau::Moyen)),
                trf!(
                    "pas approuvé : vanguard plugin approuver {}",
                    "not approved: vanguard plugin approve {}",
                    p.nom
                ),
            ),
            Etat::Change => (
                format!("{}✖{RESET}", couleur(crate::risk::Niveau::Eleve)),
                trf!(
                    "a changé depuis son approbation : refusé (vanguard plugin approuver {})",
                    "changed since its approval: refused (vanguard plugin approve {})",
                    p.nom
                ),
            ),
            Etat::AutreSysteme => (
                format!("{GRIS}–{RESET}"),
                tr!(
                    "approuvé, ne vise pas ce système",
                    "approved, does not target this system"
                )
                .to_string(),
            ),
            Etat::Invalide(e) => (
                format!("{}✖{RESET}", couleur(crate::risk::Niveau::Eleve)),
                affichable(e),
            ),
        };
        let titre = p
            .manifeste
            .as_ref()
            .map(|m| format!(" — {}", affichable(m.titre())))
            .unwrap_or_default();
        afficher_aligne(&format!("  {marque} "), &format!("{}{titre}", p.nom), 4, GRAS);
        afficher_aligne("    ", &etat, 4, GRIS);
    }
}

fn aide_ajout() {
    trp!(
        "  Aucun plugin. Un plugin est un programme à toi (script, programme) dans un dossier avec un plugin.toml ; « vanguard plugin ajouter <dossier> » le copie ici et l'approuve. Un exemple : outils/plugins/exemple dans les sources de Vanguard.",
        "  No plugin. A plugin is a program of yours (script, program) in a folder with a plugin.toml; “vanguard plugin add <folder>” copies it here and approves it. An example: outils/plugins/exemple in Vanguard's sources."
    );
}

/// Les plugins sans restrictions dont le manifeste demande `dans_le_bilan` ou `dans_la_surveillance` (selon
/// `surveillance`), lancés l'un après l'autre. Jamais un plugin aux restrictions actives : c'est la personne qui a
/// levé les garde-fous pour lui. Rien si le dossier n'est pas sûr.
fn opt_in(surveillance: bool) -> Vec<(Manifeste, Vec<sortie::ConstatPlugin>)> {
    let Ok(racine) = dossier() else {
        return Vec::new();
    };
    let reglages = reglages::charger(&racine);
    inventaire(&racine)
        .into_iter()
        .filter_map(|p| p.manifeste)
        .filter(|m| reglages.plugin_libre(m) && m.commande(Systeme::ici()).is_some())
        .filter(|m| {
            if surveillance {
                m.dans_la_surveillance
            } else {
                m.dans_le_bilan
            }
        })
        .filter_map(|m| {
            let issue = lancer(&racine, &m.nom, &[], Facon::default()).ok()?;
            let lu = sortie::analyser(&issue.borne.sortie);
            if !surveillance {
                let _ = sortie::garder(&racine, &issue.manifeste, &lu.constats);
            }
            Some((issue.manifeste, lu.constats))
        })
        .collect()
}

/// Avec le bilan complet : les plugins qui l'ont demandé, et leurs constats, à part et hors de la note.
pub fn avec_le_bilan() {
    for (m, constats) in opt_in(false) {
        sortie::afficher_constats(&format!("extension {}", m.nom), m.titre(), &constats);
    }
}

/// Avec la surveillance : une notification par plugin qui l'a demandé et signale un problème élevé ou critique.
pub fn a_signaler() -> Vec<(String, String)> {
    opt_in(true)
        .into_iter()
        .filter_map(|(m, constats)| {
            let graves: Vec<String> = constats
                .iter()
                .filter(|c| {
                    matches!(
                        c.probleme(),
                        Some(crate::risk::Niveau::Eleve | crate::risk::Niveau::Critique)
                    )
                })
                .map(|c| format!("{} : {}", c.categorie, c.message))
                .collect();
            (!graves.is_empty()).then(|| {
                (
                    trf!(
                        "Vanguard : extension « {} »",
                        "Vanguard: extension “{}”",
                        affichable(m.titre())
                    ),
                    graves.join("\n"),
                )
            })
        })
        .collect()
}

/// `vanguard extensions --sans-restrictions on|off`.
pub fn regler_restrictions(sans: bool) -> i32 {
    let racine = match dossier() {
        Ok(r) => r,
        Err(e) => {
            trp!("  Le réglage reste inactif : {}", "  The setting stays off: {}", e);
            return 1;
        }
    };
    if reglages::charger(&racine).sans_restrictions == sans {
        menu::dire_restrictions(sans);
        return 0;
    }
    match reglages::basculer(&racine, |q| demander(q).oui()) {
        Ok(etat) => {
            menu::dire_restrictions(etat);
            i32::from(etat != sans)
        }
        Err(e) => echec(&e),
    }
}

#[cfg(test)]
mod tests;
