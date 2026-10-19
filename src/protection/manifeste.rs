//! Manifeste de la clé VANGUARD : l'empreinte BLAKE3 de chaque fichier de la partition VANGUARD, écrite au déploiement
//! (outils/deployer.sh lance `vanguard manifeste --ecrire`) et gardée sur l'ordinateur du propriétaire, pas sur la clé
//! (qui change la clé changerait aussi un manifeste qui y vivrait ; sa présence dit aussi « on est chez le
//! propriétaire »). Au bilan chez lui, la clé revenue de chez quelqu'un est comparée : fichiers ajoutés (un
//! autorun.inf planté), modifiés (un programme remplacé), disparus. La lecture seule arrête Windows, pas un Linux
//! démarré en direct sur l'ordinateur de l'ami. Ce qui change normalement n'y entre pas : donnees/, les images ISO/
//! et le menu ventoy/, réécrits par outils/images-cle.sh et à chaque branchement. Une image de secours remplacée passe
//! donc inaperçue ici : images-cle.sh vérifie leur signature à la mise à jour, et pourra plus tard noter leur empreinte.
//!
//! Et « Vérifier Vanguard lui-même » : version, date de compilation (celle du dernier commit, jamais l'horloge : un
//! même code donne le même programme), empreinte SHA-256 du programme par l'outil du système, comme pour un fichier
//! téléchargé, à comparer à la page de la version ; sur la clé du propriétaire, au manifeste. Une barrière, pas un
//! coffre : qui remplace le programme peut mentir sur tout cela ; c'est pourquoi la référence reste chez le
//! propriétaire et l'empreinte est publiée ailleurs.

use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::machine::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::ui::*;

const CAT: &str = "Clé USB";
const FORMAT: &str = "vanguard-manifeste";
/// Dossiers de la clé qui changent sans que personne n'y touche, et ceux que les systèmes y posent eux-mêmes.
const EXCLUS: &[&str] = &[
    "donnees",
    "ISO",
    "ventoy",
    "System Volume Information",
    "$RECYCLE.BIN",
    ".Trashes",
    ".Spotlight-V100",
    ".fseventsd",
    ".TemporaryItems",
];
/// Au-delà, le fichier n'est pas lu : sa taille seulement (une image disque se lit en une minute).
const GROS: u64 = 64 << 20;
/// Une copie de Vanguard plus vieille que ça mérite une mise à jour.
const PERIME_JOURS: i64 = 180;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Entree {
    /// Chemin dans la clé, séparé par « / » quel que soit le système.
    chemin: String,
    taille: u64,
    /// Absente pour un gros fichier, comparé par sa taille.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blake3: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Manifeste {
    format: String,
    version_vanguard: String,
    /// « AAAA-MM-JJ HH:MM » de l'écriture.
    date: String,
    fichiers: Vec<Entree>,
}

/// Ce qui a changé sur la clé depuis le manifeste.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ecart {
    pub verifies: usize,
    pub nouveaux: Vec<String>,
    pub modifies: Vec<String>,
    pub disparus: Vec<String>,
}

impl Ecart {
    pub fn vide(&self) -> bool {
        self.nouveaux.is_empty() && self.modifies.is_empty() && self.disparus.is_empty()
    }
}

/// L'unique référence des 0.59 : une seule clé connue, et une deuxième clé VANGUARD paraissait tout entière changée.
const ANCIENNE_REFERENCE: &str = "manifeste-cle.json";
/// Une référence par clé depuis la 0.60, nommée par l'identifiant du volume.
const REFERENCES: &str = "manifestes-cle";

/// L'identifiant du système de fichiers de la clé (UUID que le formatage lui donne, « 1A2B-3C4D » en exFAT), d'après
/// le périphérique monté et /dev/disk/by-uuid. Sous Windows et macOS, aucun : le déploiement, qui écrit les
/// références, se fait sous Linux ; l'ancienne référence unique y sert encore.
#[cfg(target_os = "linux")]
pub(crate) fn identifiant_volume(racine: &Path) -> Option<String> {
    let (source, _) = crate::protection::cle::montage(racine)?;
    let peripherique = std::fs::canonicalize(&source).ok()?;
    let id = std::fs::read_dir("/dev/disk/by-uuid")
        .ok()?
        .flatten()
        .find(|e| std::fs::canonicalize(e.path()).ok().as_ref() == Some(&peripherique))?
        .file_name();
    nom_de_reference(&id.to_string_lossy())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn identifiant_volume(_racine: &Path) -> Option<String> {
    None
}

/// L'identifiant gardé tel quel s'il ne contient que des lettres, des chiffres et des tirets : il devient un nom de
/// fichier, et une étiquette choisie par n'importe qui ne doit pas sortir du dossier des références.
#[cfg(any(target_os = "linux", test))]
fn nom_de_reference(id: &str) -> Option<String> {
    let id = id.trim();
    (!id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        .then(|| id.to_string())
}

/// Les références de clé déjà écrites dans `base` (le dossier de Vanguard).
fn references_par_cle(base: &Path) -> usize {
    std::fs::read_dir(base.join(REFERENCES))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .count()
}

/// La référence de la clé `id` : la sienne ; sinon l'ancienne référence unique, tant qu'aucune clé n'a la sienne
/// (avant le premier déploiement en 0.60). `None` : cette clé n'a pas de référence ici.
fn reference_lue(base: &Path, id: Option<&str>) -> Option<PathBuf> {
    if let Some(id) = id {
        let propre = base.join(REFERENCES).join(format!("{id}.json"));
        if propre.is_file() {
            return Some(propre);
        }
    }
    let ancienne = base.join(ANCIENNE_REFERENCE);
    (ancienne.is_file() && (id.is_none() || references_par_cle(base) == 0)).then_some(ancienne)
}

/// Où écrire la référence de la clé `id`.
fn reference_ecrite(base: &Path, id: Option<&str>) -> PathBuf {
    match id {
        Some(id) => base.join(REFERENCES).join(format!("{id}.json")),
        None => base.join(ANCIENNE_REFERENCE),
    }
}

/// La référence de la clé branchée à `racine`, sur l'ordinateur du propriétaire.
fn reference(racine: &Path) -> Option<PathBuf> {
    reference_lue(&crate::reseau::dossier_local(), identifiant_volume(racine).as_deref())
}

/// Un chemin de la clé qui ne compte pas : dossier exclu, corbeille d'un gestionnaire de fichiers (« .Trash-1000 »,
/// créée dès qu'on supprime quelque chose sur la clé), fichiers que macOS pose sur une clé (« ._x », .DS_Store).
fn exclu(relatif: &str) -> bool {
    let premier = relatif.split('/').next().unwrap_or_default();
    let nom = relatif.rsplit('/').next().unwrap_or_default();
    EXCLUS.contains(&premier) || premier.starts_with(".Trash-") || nom.starts_with("._") || nom == ".DS_Store"
}

/// Les fichiers de la clé (chemin relatif, taille), sans les liens ni les dossiers exclus, triés.
fn parcourir(racine: &Path) -> Vec<(String, u64)> {
    fn descendre(dossier: &Path, prefixe: &str, liste: &mut Vec<(String, u64)>) {
        for e in std::fs::read_dir(dossier).into_iter().flatten().flatten() {
            let nom = e.file_name().to_string_lossy().into_owned();
            let relatif = if prefixe.is_empty() {
                nom
            } else {
                format!("{prefixe}/{nom}")
            };
            if exclu(&relatif) {
                continue;
            }
            let Ok(meta) = e.metadata() else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                descendre(&e.path(), &relatif, liste);
            } else if meta.is_file() {
                liste.push((relatif, meta.len()));
            }
        }
    }
    let mut liste = Vec::new();
    descendre(racine, "", &mut liste);
    liste.sort();
    liste
}

/// L'empreinte BLAKE3 d'un fichier, lu par morceaux.
fn empreinte(chemin: &Path) -> Option<String> {
    let mut fichier = std::fs::File::open(chemin).ok()?;
    let mut hacheur = blake3::Hasher::new();
    std::io::copy(&mut fichier, &mut hacheur).ok()?;
    Some(hacheur.finalize().to_hex().to_string())
}

fn relever(racine: &Path, gros: u64) -> Vec<Entree> {
    parcourir(racine)
        .into_iter()
        .map(|(chemin, taille)| Entree {
            blake3: (taille < gros).then(|| empreinte(&racine.join(&chemin))).flatten(),
            chemin,
            taille,
        })
        .collect()
}

fn ecrire_dans(racine: &Path, reference: &Path, gros: u64) -> Result<usize, String> {
    let fichiers = relever(racine, gros);
    let manifeste = Manifeste {
        format: FORMAT.to_string(),
        version_vanguard: env!("CARGO_PKG_VERSION").to_string(),
        date: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        fichiers,
    };
    if let Some(parent) = reference.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let texte = serde_json::to_string_pretty(&manifeste).map_err(|e| e.to_string())?;
    std::fs::write(reference, texte).map_err(|e| e.to_string())?;
    Ok(manifeste.fichiers.len())
}

/// Écrit le manifeste de la clé `racine` dans sa référence sur cet ordinateur ; rend le nombre de fichiers et la
/// référence. L'ancienne référence unique part dès qu'une clé a la sienne : elle décrivait la clé déployée jusque-là,
/// et gardée, elle servirait de référence à une autre.
pub fn ecrire(racine: &Path) -> Result<(usize, PathBuf), String> {
    let base = crate::reseau::dossier_local();
    let id = identifiant_volume(racine);
    let chemin = reference_ecrite(&base, id.as_deref());
    let n = ecrire_dans(racine, &chemin, GROS)?;
    if id.is_some() {
        let _ = std::fs::remove_file(base.join(ANCIENNE_REFERENCE));
    }
    Ok((n, chemin))
}

fn lire(reference: &Path) -> Result<Manifeste, String> {
    let texte = std::fs::read_to_string(reference).map_err(|e| e.to_string())?;
    let mut valeur: serde_json::Value =
        serde_json::from_str(texte.trim_start_matches('\u{feff}')).map_err(|e| e.to_string())?;
    // Manifeste écrit avant le changement de nom (`passage`).
    crate::passage::reprendre_format(&mut valeur, FORMAT);
    let m: Manifeste = serde_json::from_value(valeur).map_err(|e| e.to_string())?;
    if m.format != FORMAT {
        return Err(tr!("ce n'est pas un manifeste Vanguard", "this is not a Vanguard manifest").to_string());
    }
    Ok(m)
}

fn comparer_avec(racine: &Path, manifeste: &Manifeste, gros: u64) -> Ecart {
    let mut ecart = Ecart::default();
    let presents = parcourir(racine);
    for (chemin, taille) in &presents {
        match manifeste.fichiers.iter().find(|e| e.chemin == *chemin) {
            None => ecart.nouveaux.push(chemin.clone()),
            Some(attendu) => {
                let pareil = attendu.taille == *taille
                    && match &attendu.blake3 {
                        Some(h) if *taille < gros => empreinte(&racine.join(chemin)).as_deref() == Some(h.as_str()),
                        _ => true,
                    };
                if pareil {
                    ecart.verifies += 1;
                } else {
                    ecart.modifies.push(chemin.clone());
                }
            }
        }
    }
    for attendu in &manifeste.fichiers {
        if !presents.iter().any(|(c, _)| *c == attendu.chemin) {
            ecart.disparus.push(attendu.chemin.clone());
        }
    }
    ecart
}

/// Compare la clé `racine` à sa référence sur cet ordinateur.
pub fn comparer(racine: &Path) -> Result<Ecart, String> {
    let reference = reference(racine)
        .ok_or_else(|| tr!("aucune référence pour cette clé", "no reference for this key").to_string())?;
    Ok(comparer_avec(racine, &lire(&reference)?, GROS))
}

/// Les changements, en une liste courte : « autorun.inf (nouveau), Windows/vanguard.exe (modifié)… ».
fn resume_ecart(ecart: &Ecart) -> String {
    let (n, m, d) = (
        tr!("nouveau", "new"),
        tr!("modifié", "modified"),
        tr!("disparu", "missing"),
    );
    let tous: Vec<String> = ecart
        .nouveaux
        .iter()
        .map(|c| format!("{} ({n})", affichable(c)))
        .chain(ecart.modifies.iter().map(|c| format!("{} ({m})", affichable(c))))
        .chain(ecart.disparus.iter().map(|c| format!("{} ({d})", affichable(c))))
        .collect();
    resume(&tous, 5, ", ")
}

/// Au bilan, chez le propriétaire (la référence existe) avec la clé branchée.
pub fn constat() -> Option<Constat> {
    let cle = crate::reseau::cle_usb()?;
    let base = crate::reseau::dossier_local();
    if reference(&cle).is_none() {
        // Chez le propriétaire (d'autres clés y ont leur référence), une clé VANGUARD sans la sienne : une deuxième
        // clé, ou une clé reformatée. Rien n'a pu être comparé, et c'est dit.
        return (references_par_cle(&base) > 0 || base.join(ANCIENNE_REFERENCE).is_file()).then(|| Constat {
            verifie: false,
            ..alerte(
                CAT,
                Niveau::Info,
                tr!(
                    "Cette clé VANGUARD n'a pas de manifeste sur cet ordinateur (une autre clé que celles déployées ici, ou une clé reformatée) : son contenu n'a pas pu être comparé.",
                    "This VANGUARD key has no manifest on this computer (a key other than those deployed here, or a reformatted key): its content could not be compared."
                ),
            )
            .manuel(
                tr!(
                    "outils/deployer.sh écrit son manifeste en la mettant à jour",
                    "outils/deployer.sh writes its manifest when it updates the key"
                ),
                &[],
            )
        });
    }
    Some(match comparer(&cle) {
        Err(e) => impossible(CAT, &trf!("manifeste de la clé illisible : {e}", "key manifest unreadable: {e}")),
        Ok(ecart) if ecart.vide() => ok(
            CAT,
            trf!(
                "La clé VANGUARD n'a pas changé depuis son écriture ({} fichiers vérifiés ; données, images ISO et menu Ventoy mis à part).",
                "The VANGUARD key has not changed since it was written ({} files checked; data, ISO images and Ventoy menu aside).",
                ecart.verifies
            ),
        ),
        Ok(ecart) => alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "La clé VANGUARD a changé depuis son écriture : {}. Un fichier ajouté ou remplacé sur une clé qui a voyagé peut être un piège (autorun, programme remplacé).",
                "The VANGUARD key has changed since it was written: {}. A file added or replaced on a key that traveled may be a trap (autorun, replaced program).",
                resume_ecart(&ecart)
            ),
        )
        .manuel(
            tr!(
                "Ne lance plus Vanguard depuis cette clé avant de l'avoir réécrite : chez toi, outils/deployer.sh la remet à neuf",
                "Do not run Vanguard from this key until it is rewritten: at home, outils/deployer.sh restores it"
            ),
            &[],
        ),
    })
}

// ───────────────────────────── Vérifier Vanguard lui-même ─────────────────────────────

/// Date du dernier commit compilé (build.rs), `None` hors d'un dépôt git.
pub fn date_compilation() -> Option<NaiveDate> {
    NaiveDate::parse_from_str(env!("VANGUARD_COMPILE"), "%Y-%m-%d").ok()
}

fn age_jours(aujourd_hui: NaiveDate) -> Option<i64> {
    date_compilation().map(|d| (aujourd_hui - d).num_days())
}

/// La ligne d'avertissement du menu quand cette copie a plus de six mois, sinon rien.
pub fn avertissement_perime() -> Option<String> {
    avertissement(age_jours(chrono::Local::now().date_naive())?)
}

fn avertissement(jours: i64) -> Option<String> {
    (jours >= PERIME_JOURS).then(|| {
        let mois = jours / 30;
        trf!(
            "Cette copie de Vanguard a {mois} mois : remets la clé à jour chez toi.",
            "This copy of Vanguard is {mois} months old: update the key at home."
        )
    })
}

/// Le programme tel que lancé (sur la clé, même quand c'est sa copie temporaire qui tourne).
fn programme() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        crate::protection::cle::exe_d_origine()
    }
    #[cfg(windows)]
    {
        std::env::current_exe().ok()
    }
}

/// « vanguard verifier-moi » : version, date, empreinte SHA-256, et le manifeste sur la clé du propriétaire.
pub fn verifier_moi() {
    titre(tr!("Vérifier Vanguard lui-même", "Check Vanguard itself"));
    println!(
        "  {GRIS}{}{RESET}  {}",
        tr!("Version   ", "Version   "),
        env!("CARGO_PKG_VERSION")
    );
    let aujourd_hui = chrono::Local::now().date_naive();
    match (date_compilation(), age_jours(aujourd_hui)) {
        (Some(d), Some(jours)) => {
            let depuis = match jours {
                0 => tr!("aujourd'hui", "today").to_string(),
                1 => tr!("hier", "yesterday").to_string(),
                _ => trf!("il y a {jours} jours", "{jours} days ago"),
            };
            println!("  {GRIS}{}{RESET}  {d} ({depuis})", tr!("Compilé le", "Built on  "));
            if let Some(a) = avertissement(jours) {
                println!("  ⚠ {a}");
            }
        }
        _ => trp!(
            "  {GRIS}Compilé le{RESET}  inconnu (compilé hors d'un dépôt git)",
            "  {GRIS}Built on  {RESET}  unknown (built outside a git repository)"
        ),
    }
    let Some(exe) = programme() else {
        trp!(
            "  ✖ Impossible de savoir quel fichier est en train de tourner.",
            "  ✖ Could not tell which file is running."
        );
        return;
    };
    println!(
        "  {GRIS}{}{RESET}  {}",
        tr!("Programme ", "Program   "),
        chemin_affichable(&exe)
    );
    match crate::protection::telechargement::calculer(&exe, crate::protection::telechargement::Algo::Sha256) {
        Ok(h) => println!("  {GRIS}SHA-256   {RESET}  {h}"),
        Err(e) => trp!("  ✖ Empreinte impossible ({e}).", "  ✖ Checksum impossible ({e})."),
    }
    if let Some(cle) = crate::reseau::cle_usb()
        && let Ok(relatif) = exe.strip_prefix(&cle)
    {
        let relatif = relatif.to_string_lossy().replace('\\', "/");
        match reference(&cle).ok_or(()).and_then(|r| lire(&r).map_err(|_| ())) {
            Err(()) => trp!(
                "  {GRIS}Lancé depuis la clé, hors de l'ordinateur du propriétaire : pas de manifeste à comparer.{RESET}",
                "  {GRIS}Started from the key, away from the owner's computer: no manifest to compare.{RESET}"
            ),
            Ok(m) => match m.fichiers.iter().find(|e| e.chemin == relatif) {
                Some(e) if e.blake3.is_some() && e.blake3 == empreinte(&exe) => trp!(
                    "  {VERT}✔{RESET} Identique au manifeste de la clé écrit le {}.",
                    "  {VERT}✔{RESET} Identical to the key manifest written on {}.",
                    m.date
                ),
                Some(_) => trp!(
                    "  ✖ DIFFÈRE du manifeste écrit le {} : ce n'est pas le programme posé sur la clé. Réécris la clé (outils/deployer.sh) avant de t'en servir.",
                    "  ✖ DIFFERS from the manifest written on {}: this is not the program put on the key. Rewrite the key (outils/deployer.sh) before using it.",
                    m.date
                ),
                None => trp!(
                    "  ⚠ Absent du manifeste de la clé : ce fichier n'y était pas quand elle a été écrite.",
                    "  ⚠ Missing from the key manifest: this file was not there when it was written."
                ),
            },
        }
    }
    println!();
    for ligne in envelopper(
        tr!(
            "Compare l'empreinte SHA-256 à celle de la page de la version de Vanguard, ou à celle que t'a donnée la personne qui t'a remis le programme. Si elles diffèrent, ne l'utilise pas.",
            "Compare the SHA-256 checksum with the one on Vanguard's release page, or the one given by the person who handed you the program. If they differ, do not use it."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
}

/// « vanguard manifeste [--ecrire DOSSIER] » : écrit la référence (déploiement), ou compare la clé branchée.
pub fn commande(ecrire_dossier: Option<&Path>) {
    if let Some(racine) = ecrire_dossier {
        match ecrire(racine) {
            Ok((n, reference)) => trp!(
                "Manifeste de la clé écrit : {n} fichiers, référence {}",
                "Key manifest written: {n} files, reference {}",
                chemin_affichable(&reference)
            ),
            Err(e) => {
                trp!("✖ Manifeste non écrit : {e}", "✖ Manifest not written: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    titre(tr!("Manifeste de la clé", "Key manifest"));
    let Some(cle) = crate::reseau::cle_usb() else {
        trp!("  Clé VANGUARD non branchée.", "  VANGUARD key not plugged in.");
        return;
    };
    match comparer(&cle) {
        Err(e) => trp!(
            "  ✖ Pas de référence lisible sur cet ordinateur ({e}) : le manifeste s'écrit au déploiement, chez le propriétaire.",
            "  ✖ No readable reference on this computer ({e}): the manifest is written at deployment, on the owner's computer."
        ),
        Ok(ecart) if ecart.vide() => trp!(
            "  {VERT}✔{RESET} La clé n'a pas changé depuis son écriture ({} fichiers vérifiés).",
            "  {VERT}✔{RESET} The key has not changed since it was written ({} files checked).",
            ecart.verifies
        ),
        Ok(ecart) => {
            for (liste, mot) in [
                (&ecart.nouveaux, tr!("nouveau", "new")),
                (&ecart.modifies, tr!("modifié", "modified")),
                (&ecart.disparus, tr!("disparu", "missing")),
            ] {
                for c in liste {
                    println!("  {}✖{RESET} {} ({mot})", couleur(Niveau::Eleve), affichable(c));
                }
            }
            trp!(
                "  {} fichiers inchangés. Réécris la clé chez toi (outils/deployer.sh) avant de t'en servir.",
                "  {} files unchanged. Rewrite the key at home (outils/deployer.sh) before using it.",
                ecart.verifies
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier_jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-manifeste-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn exclusions() {
        assert!(exclu("donnees/appareils.json"));
        assert!(exclu("ISO/omarchy.iso"));
        assert!(exclu("ventoy/ventoy.json"));
        assert!(exclu("Linux/._vanguard"));
        assert!(exclu(".DS_Store"));
        assert!(exclu(".Trash-1000/files/vieux.txt"));
        assert!(exclu(".TemporaryItems/x"));
        assert!(!exclu("Linux/vanguard"));
        assert!(!exclu("autorun.inf"));
        assert!(!exclu("source/outils/images-cle.sh"));
    }

    #[test]
    fn ecriture_puis_comparaison() {
        let racine = dossier_jetable("cle");
        let reference = dossier_jetable("ref").join("manifeste-cle.json");
        std::fs::create_dir_all(racine.join("Linux")).unwrap();
        std::fs::create_dir_all(racine.join("donnees")).unwrap();
        std::fs::create_dir_all(racine.join("ISO")).unwrap();
        std::fs::write(racine.join("Linux/vanguard"), b"programme").unwrap();
        std::fs::write(racine.join("LISEZMOI.txt"), b"lis-moi").unwrap();
        std::fs::write(racine.join("gros.img"), b"0123456789abcdef").unwrap();
        std::fs::write(racine.join("donnees/appareils.json"), b"{}").unwrap();
        std::fs::write(racine.join("ISO/x.iso"), b"iso").unwrap();
        // Au-delà de 10 octets, la taille seulement.
        assert_eq!(ecrire_dans(&racine, &reference, 10).unwrap(), 3);
        let m = lire(&reference).unwrap();
        assert_eq!(m.format, FORMAT);
        let gros = m.fichiers.iter().find(|e| e.chemin == "gros.img").unwrap();
        assert!(gros.blake3.is_none() && gros.taille == 16);
        assert!(
            m.fichiers
                .iter()
                .find(|e| e.chemin == "Linux/vanguard")
                .unwrap()
                .blake3
                .is_some()
        );
        let ecart = comparer_avec(&racine, &m, 10);
        assert!(ecart.vide(), "{ecart:?}");
        assert_eq!(ecart.verifies, 3);

        // La clé revient : un autorun planté, le programme remplacé (même taille), le guide disparu, les données et
        // une image changées (normal), le gros fichier changé à taille égale (pas vu : dit dans la doc).
        std::fs::write(racine.join("autorun.inf"), b"[autorun]").unwrap();
        std::fs::write(racine.join("Linux/vanguard"), b"PROGRAMME").unwrap();
        std::fs::remove_file(racine.join("LISEZMOI.txt")).unwrap();
        std::fs::write(racine.join("donnees/appareils.json"), b"{\"x\":1}").unwrap();
        std::fs::write(racine.join("ISO/y.iso"), b"iso2").unwrap();
        std::fs::write(racine.join("gros.img"), b"fedcba9876543210").unwrap();
        let ecart = comparer_avec(&racine, &m, 10);
        assert_eq!(ecart.nouveaux, ["autorun.inf"]);
        assert_eq!(ecart.modifies, ["Linux/vanguard"]);
        assert_eq!(ecart.disparus, ["LISEZMOI.txt"]);
        assert_eq!(ecart.verifies, 1);
        assert!(
            resume_ecart(&ecart).starts_with("autorun.inf (nouveau), Linux/vanguard (modifié), LISEZMOI.txt (disparu)")
        );
        // Le gros fichier qui change de taille, lui, se voit.
        std::fs::write(racine.join("gros.img"), b"court").unwrap();
        assert!(
            comparer_avec(&racine, &m, 10)
                .modifies
                .contains(&"gros.img".to_string())
        );

        // Une référence qui n'est pas un manifeste est refusée.
        std::fs::write(
            &reference,
            b"{\"format\":\"autre\",\"version_vanguard\":\"\",\"date\":\"\",\"fichiers\":[]}",
        )
        .unwrap();
        assert!(lire(&reference).is_err());
        let _ = std::fs::remove_dir_all(&racine);
        let _ = std::fs::remove_dir_all(reference.parent().unwrap());
    }

    #[test]
    fn une_reference_par_cle() {
        let base = dossier_jetable("refs");
        // Rien d'écrit : aucune référence, pour aucune clé.
        assert_eq!(reference_lue(&base, Some("1A2B-3C4D")), None);
        assert_eq!(reference_lue(&base, None), None);
        // L'ancienne référence unique (0.59) sert encore, tant qu'aucune clé n'a la sienne.
        std::fs::write(base.join(ANCIENNE_REFERENCE), b"{}").unwrap();
        assert_eq!(
            reference_lue(&base, Some("1A2B-3C4D")),
            Some(base.join(ANCIENNE_REFERENCE))
        );
        // La clé A a la sienne : la clé B n'emprunte plus l'ancienne, qui décrivait peut-être A.
        let a = reference_ecrite(&base, Some("1A2B-3C4D"));
        assert_eq!(a, base.join(REFERENCES).join("1A2B-3C4D.json"));
        std::fs::create_dir_all(a.parent().unwrap()).unwrap();
        std::fs::write(&a, b"{}").unwrap();
        assert_eq!(reference_lue(&base, Some("1A2B-3C4D")), Some(a));
        assert_eq!(reference_lue(&base, Some("5E6F-7A8B")), None);
        // Sans identifiant (Windows, macOS) : l'ancienne.
        assert_eq!(reference_lue(&base, None), Some(base.join(ANCIENNE_REFERENCE)));
        assert_eq!(reference_ecrite(&base, None), base.join(ANCIENNE_REFERENCE));
        // L'identifiant devient un nom de fichier : rien qui sorte du dossier.
        assert_eq!(nom_de_reference(" 1A2B-3C4D\n").as_deref(), Some("1A2B-3C4D"));
        assert_eq!(
            nom_de_reference("0f1e2d3c-aaaa-bbbb-cccc-0123456789ab").as_deref(),
            Some("0f1e2d3c-aaaa-bbbb-cccc-0123456789ab")
        );
        assert_eq!(nom_de_reference("../../x"), None);
        assert_eq!(nom_de_reference(""), None);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn date_de_compilation_et_copie_perimee() {
        // Compilé depuis le dépôt : la date du dernier commit est là.
        let d = date_compilation().expect("VANGUARD_COMPILE posée par build.rs");
        assert!(d.format("%Y").to_string().starts_with("20"));
        assert_eq!(avertissement(10), None);
        assert_eq!(avertissement(179), None);
        assert_eq!(
            avertissement(210).as_deref(),
            Some("Cette copie de Vanguard a 7 mois : remets la clé à jour chez toi.")
        );
    }
}
