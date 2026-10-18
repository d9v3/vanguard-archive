//! Copier mes fichiers : Documents, Images, Bureau, Vidéos et Musique vers un disque externe, avant une réparation
//! risquée, une réinstallation ou un ordinateur qu'on rend. La copie va dans un dossier daté ; la place nécessaire est
//! comparée à la place libre avant de commencer ; chaque fichier est relu après la copie et son empreinte BLAKE3
//! comparée à celle de l'original. Rien n'est jamais effacé ni écrasé : un fichier différent déjà sur le disque garde
//! sa place, la copie prend un autre nom (« photo (2).jpg »). Une copie interrompue (disque débranché, Ctrl-C)
//! reprend là où elle s'est arrêtée : ce qui est déjà copié, à l'identique, n'est pas recopié. Jamais vers la clé
//! GARDIEN ni vers le disque du système.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::nettoyer::taille_lisible;
use crate::selection::{Case, Ligne, choisir, cocher};
use crate::ui::*;

/// Témoin d'une copie pas finie, dans son dossier daté : sa présence propose la reprise.
const TEMOIN: &str = ".gardien-copie-en-cours";
/// Fichier en cours d'écriture : renommé seulement une fois complet, il n'est jamais pris pour une vraie copie.
const PARTIEL: &str = ".gardien-partiel";
const COMPTE_RENDU: &str = "gardien-copie.txt";
/// Début du nom des dossiers datés, en français puis en anglais (une copie se reprend dans les deux langues).
const PREFIXES: [&str; 2] = ["Gardien-copie-", "Gardien-copy-"];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sorte {
    Documents,
    Images,
    Bureau,
    Videos,
    Musique,
}

/// Où trouver chaque dossier : user-dirs.dirs, puis noms usuels (Linux) ; registre, puis profil (Windows) ; macOS.
#[rustfmt::skip] // une ligne par dossier, que rustfmt étalerait sur huit
const DOSSIERS: [(Sorte, &str, &[&str], [&str; 3]); 5] = [
    (Sorte::Documents, "XDG_DOCUMENTS_DIR", &["Documents"], ["Personal", "Documents", "Documents"]),
    (Sorte::Images, "XDG_PICTURES_DIR", &["Images", "Pictures"], ["My Pictures", "Pictures", "Pictures"]),
    (Sorte::Bureau, "XDG_DESKTOP_DIR", &["Bureau", "Desktop"], ["Desktop", "Desktop", "Desktop"]),
    (Sorte::Videos, "XDG_VIDEOS_DIR", &["Vidéos", "Videos"], ["My Video", "Videos", "Movies"]),
    (Sorte::Musique, "XDG_MUSIC_DIR", &["Musique", "Music"], ["My Music", "Music", "Music"]),
];

impl Sorte {
    fn nom(self) -> &'static str {
        match self {
            Sorte::Documents => tr!("Documents", "Documents"),
            Sorte::Images => tr!("Images", "Pictures"),
            Sorte::Bureau => tr!("Bureau", "Desktop"),
            Sorte::Videos => tr!("Vidéos", "Videos"),
            Sorte::Musique => tr!("Musique", "Music"),
        }
    }
}

/// Les dossiers personnels qui existent, chacun avec son chemin dans la langue du système.
fn sources() -> Vec<(Sorte, PathBuf)> {
    let mut liste: Vec<(Sorte, PathBuf)> = Vec::new();
    for (sorte, ..) in DOSSIERS {
        // Deux sortes au même endroit (Bureau non configuré = dossier personnel) : une seule fois.
        if let Some(chemin) = chemin_de(sorte).filter(|c| c.is_dir() && liste.iter().all(|(_, vu)| vu != c)) {
            liste.push((sorte, chemin));
        }
    }
    liste
}

#[cfg(target_os = "linux")]
fn chemin_de(sorte: Sorte) -> Option<PathBuf> {
    let &(_, cle, noms, _) = DOSSIERS.iter().find(|d| d.0 == sorte)?;
    let maison = crate::nettoyer::maison();
    let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
    let declares = std::fs::read_to_string(config.join("user-dirs.dirs")).unwrap_or_default();
    crate::protection::pieges::dossier_declare(&declares, cle, &maison)
        .or_else(|| noms.iter().map(|n| maison.join(n)).find(|d| d.is_dir()))
}

/// Windows : les dossiers déclarés pour le compte (déplacés dans OneDrive le cas échéant), sinon ceux du profil.
#[cfg(windows)]
fn chemin_de(sorte: Sorte) -> Option<PathBuf> {
    let &(.., [valeur, profil, _]) = DOSSIERS.iter().find(|d| d.0 == sorte)?;
    winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
        .ok()
        .and_then(|k| k.get_value::<String, _>(valeur).ok())
        .map(|c| PathBuf::from(crate::protection::pieges::developper(&c)))
        .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join(profil)))
}

#[cfg(target_os = "macos")]
fn chemin_de(sorte: Sorte) -> Option<PathBuf> {
    let &(.., [_, _, nom]) = DOSSIERS.iter().find(|d| d.0 == sorte)?;
    Some(crate::nettoyer::maison().join(nom))
}

pub struct Disque {
    pub racine: PathBuf,
    pub nom: String,
    pub libre: u64,
    pub total: u64,
}

/// La clé GARDIEN (ou sa partition des journaux), reconnue à ses témoins.
pub(crate) fn est_la_cle(racine: &Path) -> bool {
    std::iter::once(crate::reseau::TEMOIN_CLE)
        .chain(crate::reseau::ANCIENS_TEMOINS_CLE)
        .chain([crate::journal::TEMOIN, "sentinel-journal.cle"])
        .any(|t| racine.join(t).is_file())
}

/// Le volume de `p` porte-t-il le système ou le dossier personnel ? `None` : le volume ne peut pas être lu.
#[cfg(target_os = "linux")]
fn sur_le_systeme(p: &Path) -> Option<bool> {
    let montages = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    sur_le_systeme_selon(&montages, &p.canonicalize().ok()?, &crate::nettoyer::maison())
}

/// D'après /proc/self/mountinfo : le système de fichiers (« majeur:mineur ») du montage le plus profond qui contient
/// chaque chemin. `st_dev` ne suffit pas : chaque sous-volume d'un btrfs a le sien, et /var/log ou un sous-volume
/// monté dans /mnt passait pour un autre disque.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sur_le_systeme_selon(montages: &str, p: &Path, maison: &Path) -> Option<bool> {
    let volume = |chemin: &Path| {
        montages
            .lines()
            .filter_map(|l| {
                let mut c = l.split_whitespace().skip(2);
                let dev = c.next()?;
                let point = PathBuf::from(sans_echappements(c.nth(1)?));
                chemin.starts_with(&point).then_some((point, dev))
            })
            // Le plus long ; à longueur égale, le dernier monté, qui recouvre les autres.
            .max_by_key(|(point, _)| point.as_os_str().len())
            .map(|(_, dev)| dev)
    };
    let v = volume(p)?;
    Some([volume(Path::new("/")), volume(maison)].contains(&Some(v)))
}

/// Un chemin de /proc/mounts ou mountinfo : l'espace, la tabulation, le saut de ligne et la barre oblique inverse y
/// sont écrits en octal (« \040 » pour l'espace).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sans_echappements(t: &str) -> String {
    let mut sortie = Vec::with_capacity(t.len());
    let octets = t.as_bytes();
    let mut i = 0;
    while i < octets.len() {
        let code = octets
            .get(i + 1..i + 4)
            .and_then(|o| u8::from_str_radix(std::str::from_utf8(o).ok()?, 8).ok());
        match (octets[i], code) {
            (b'\\', Some(c)) => {
                sortie.push(c);
                i += 4;
            }
            (o, _) => {
                sortie.push(o);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&sortie).into_owned()
}

/// macOS : chaque volume a son `st_dev` (les volumes d'un même conteneur APFS aussi, mais le compte est sur celui des
/// données, comparé lui aussi).
#[cfg(target_os = "macos")]
fn sur_le_systeme(p: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    let volume = |p: &Path| std::fs::metadata(p).ok().map(|m| m.dev());
    let v = volume(p)?;
    Some([volume(Path::new("/")), volume(&crate::nettoyer::maison())].contains(&Some(v)))
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux et macOS, où le volume peut être illisible
fn sur_le_systeme(p: &Path) -> Option<bool> {
    let lecteur: String = p
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .chars()
        .take(2)
        .collect();
    let systeme = std::env::var("SystemDrive").map_or("C:".into(), |s| s.to_uppercase());
    Some(lecteur.to_uppercase() == systeme)
}

/// Linux : les systèmes de fichiers montés pour l'utilisateur (/run/media, /media, /mnt), modifiables, hors du disque
/// du système et du dossier personnel, et pas la clé.
#[cfg(target_os = "linux")]
fn disques() -> Vec<Disque> {
    const SYSTEMES: &[&str] = &[
        "vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "hfsplus", "udf",
    ];
    let mut liste = Vec::new();
    for l in std::fs::read_to_string("/proc/mounts").unwrap_or_default().lines() {
        let c: Vec<&str> = l.split_whitespace().collect();
        let [_, point, genre, options, ..] = c[..] else {
            continue;
        };
        let point = PathBuf::from(sans_echappements(point));
        let monte_pour_l_utilisateur = ["/run/media/", "/media/", "/mnt/"]
            .iter()
            .any(|d| point.starts_with(d) && point.as_os_str().len() > d.len());
        if monte_pour_l_utilisateur
            && SYSTEMES.contains(&genre)
            && !options.split(',').any(|o| o == "ro")
            && !est_la_cle(&point)
            && sur_le_systeme(&point) == Some(false)
            && let Some((libre, total)) = crate::nettoyer::volume(&point)
        {
            // Le nom d'un disque vient de son étiquette, choisie par qui l'a formaté : lu prêt à montrer.
            let nom = affichable(&point.file_name().unwrap_or_default().to_string_lossy());
            liste.push(Disque {
                racine: point,
                nom,
                libre,
                total,
            });
        }
    }
    liste
}

#[cfg(target_os = "macos")]
fn disques() -> Vec<Disque> {
    use std::os::unix::fs::MetadataExt;
    let systeme = std::fs::metadata("/").ok().map(|m| m.dev());
    std::fs::read_dir("/Volumes")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let (racine, nom) = (e.path(), e.file_name().to_string_lossy().into_owned());
            let dev = std::fs::metadata(&racine).ok()?.dev();
            if Some(dev) == systeme || nom.starts_with("com.apple.") || est_la_cle(&racine) {
                return None;
            }
            let (libre, total) = crate::nettoyer::volume(&racine)?;
            Some(Disque {
                racine,
                nom: affichable(&nom),
                libre,
                total,
            })
        })
        .collect()
}

/// Windows : les lecteurs prêts, amovibles ou fixes, sauf celui du système et la clé.
#[cfg(windows)]
fn disques() -> Vec<Disque> {
    let lecteurs = crate::machine::windows::ps(
        "[IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and ($_.DriveType -eq 'Removable' -or $_.DriveType -eq 'Fixed') } | \
         ForEach-Object { \"$($_.Name)|$($_.VolumeLabel)|$($_.AvailableFreeSpace)|$($_.TotalSize)\" }",
    );
    let systeme = std::env::var("SystemDrive").map_or("C:".into(), |s| s.to_uppercase());
    let mut liste = lire_lecteurs(&lecteurs.unwrap_or_default(), &systeme);
    liste.retain(|d| !est_la_cle(&d.racine));
    liste
}

/// « E:\|Sauvegarde|1000|2000 » par ligne, sans le lecteur du système (« C: »).
#[cfg_attr(not(windows), allow(dead_code))]
fn lire_lecteurs(texte: &str, systeme: &str) -> Vec<Disque> {
    texte
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.trim().split('|').collect();
            let [racine, etiquette, libre, total] = c[..] else {
                return None;
            };
            let lettre = racine.trim_end_matches('\\');
            if lettre.to_uppercase() == systeme.trim_end_matches('\\') {
                return None;
            }
            Some(Disque {
                racine: PathBuf::from(racine),
                nom: affichable(&match etiquette {
                    "" => lettre.to_string(),
                    _ => format!("{etiquette} ({lettre})"),
                }),
                libre: libre.parse().ok()?,
                total: total.parse().ok()?,
            })
        })
        .collect()
}

/// Nombre de fichiers et octets d'un dossier, sous-dossiers compris, sans suivre les liens.
fn mesurer(dossier: &Path) -> (u64, u64) {
    let (mut fichiers, mut octets) = (0, 0);
    let mut a_voir = vec![dossier.to_path_buf()];
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let Ok(m) = e.path().symlink_metadata() else { continue };
            if m.is_dir() {
                a_voir.push(e.path());
            } else if m.is_file() {
                fichiers += 1;
                octets += m.len();
            }
        }
    }
    (fichiers, octets)
}

/// Ce qui s'est passé pendant la copie.
#[derive(Default, Debug)]
pub struct Bilan {
    pub copies: u64,
    /// Déjà sur le disque, à l'identique (reprise) : pas recopiés.
    pub deja: u64,
    pub octets: u64,
    /// Copiés sous un autre nom : (original, copie). Un fichier différent occupait déjà la place, ou le nom n'est pas
    /// permis sur ce disque (« : » sur un disque formaté pour Windows).
    pub renommes: Vec<(PathBuf, PathBuf)>,
    pub echecs: Vec<(PathBuf, String)>,
    /// Liens symboliques : ce sont des raccourcis, pas des fichiers ; non copiés.
    pub liens: u64,
}

/// Affichage de l'avancement, au plus deux fois par seconde (seulement dans un vrai terminal).
struct Avancement {
    total_fichiers: u64,
    total_octets: u64,
    fichiers: u64,
    octets: u64,
    debut: Instant,
    dernier: Instant,
    terminal: bool,
}

impl Avancement {
    /// `fin` : le dernier affichage, toujours montré, qui termine la ligne.
    fn montrer(&mut self, fin: bool) {
        if !self.terminal || (!fin && self.dernier.elapsed() < Duration::from_millis(500)) {
            return;
        }
        self.dernier = Instant::now();
        #[allow(clippy::cast_precision_loss)]
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let debit = taille_lisible((self.octets as f64 / self.debut.elapsed().as_secs_f64().max(0.1)) as u64);
        let texte = trf!(
            "{} / {} fichiers · {} / {} · {debit}/s",
            "{} / {} files · {} / {} · {debit}/s",
            self.fichiers,
            self.total_fichiers,
            taille_lisible(self.octets),
            taille_lisible(self.total_octets)
        );
        print!("\r  {texte}\x1b[K{}", if fin { "\n" } else { "" });
        let _ = std::io::stdout().flush();
    }
}

/// Un nom permis partout (FAT, exFAT, NTFS) : les caractères interdits par Windows remplacés par « _ », sans point
/// ni espace à la fin.
fn nom_permis(nom: &str) -> String {
    let propre = nom.replace(|c: char| c.is_control() || "<>:\"/\\|?*".contains(c), "_");
    let propre = propre.trim_end_matches(['.', ' ']);
    if propre.is_empty() { "_".into() } else { propre.into() }
}

/// « photo.jpg » → « photo (2).jpg », « photo (3).jpg »… : le premier nom libre du dossier.
fn nom_libre(dossier: &Path, nom: &str) -> PathBuf {
    let (base, extension) = match nom.rsplit_once('.') {
        Some((base, extension)) if !base.is_empty() => (base, format!(".{extension}")),
        _ => (nom, String::new()),
    };
    (2..=9999)
        .map(|n| dossier.join(format!("{base} ({n}){extension}")))
        .find(|p| std::fs::symlink_metadata(p).is_err())
        .unwrap_or_else(|| dossier.join(nom))
}

fn empreinte(chemin: &Path) -> std::io::Result<blake3::Hash> {
    Ok(blake3::Hasher::new().update_reader(File::open(chemin)?)?.finalize())
}

/// Copie `source` vers `cible` (qui n'existe pas) en passant par un fichier partiel, puis vérifie.
fn copier_vers(source: &Path, cible: &Path) -> std::io::Result<()> {
    let nom = cible.file_name().unwrap_or_default().to_string_lossy();
    let partiel = cible.with_file_name(format!(".{nom}{PARTIEL}"));
    // Un partiel laissé par une copie interrompue est à nous : on le remplace.
    let _ = std::fs::remove_file(&partiel);
    let mut entree = File::open(source)?;
    let mut sortie = OpenOptions::new().write(true).create_new(true).open(&partiel)?;
    // Le partiel se ferme à la fin de l'écriture, réussie ou non : il peut alors être renommé ou retiré.
    let ecrit = (move || -> std::io::Result<blake3::Hash> {
        let (mut h, mut tampon) = (blake3::Hasher::new(), vec![0u8; 1 << 20]);
        loop {
            let n = entree.read(&mut tampon)?;
            if n == 0 {
                break;
            }
            h.update(&tampon[..n]);
            sortie.write_all(&tampon[..n])?;
        }
        // Sur le disque, pas seulement en mémoire : un disque débranché juste après ne doit rien perdre.
        sortie.sync_all()?;
        if let Ok(date) = std::fs::metadata(source).and_then(|m| m.modified()) {
            let _ = sortie.set_modified(date);
        }
        // Personne n'a pris la place entre-temps : sinon, renommer l'écraserait.
        if std::fs::symlink_metadata(cible).is_ok() {
            return Err(std::io::Error::new(ErrorKind::AlreadyExists, "occupé"));
        }
        Ok(h.finalize())
    })();
    let original = ecrit.inspect_err(|_| {
        let _ = std::fs::remove_file(&partiel);
    })?;
    std::fs::rename(&partiel, cible)?;
    // Relue sur le disque : une copie différente de l'original n'est pas gardée.
    if empreinte(cible)? != original {
        let _ = std::fs::remove_file(cible);
        return Err(std::io::Error::other(tr!(
            "la copie relue diffère de l'original",
            "the copy read back differs from the original"
        )));
    }
    Ok(())
}

/// Un fichier : déjà là à l'identique (rien à faire), ou copié, sous son nom ou un autre.
fn copier_fichier(source: &Path, dossier: &Path, bilan: &mut Bilan) {
    let nom = source.file_name().unwrap_or_default().to_string_lossy();
    let mut cible = dossier.join(&*nom);
    if let Ok(m) = std::fs::symlink_metadata(&cible) {
        let taille = std::fs::metadata(source).map_or(u64::MAX, |s| s.len());
        if m.is_file()
            && m.len() == taille
            && matches!((empreinte(&cible), empreinte(source)), (Ok(a), Ok(b)) if a == b)
        {
            bilan.deja += 1;
            bilan.octets += taille;
            return;
        }
        cible = nom_libre(dossier, &nom);
    }
    let mut essai = copier_vers(source, &cible);
    // Nom refusé par ce disque (« : », « ? » sur un disque formaté pour Windows) : un nom permis partout.
    let permis = nom_permis(&nom);
    if let Err(e) = &essai
        && matches!(e.kind(), ErrorKind::InvalidInput | ErrorKind::InvalidFilename)
        && permis != nom
    {
        cible = dossier.join(&permis);
        if std::fs::symlink_metadata(&cible).is_ok() {
            cible = nom_libre(dossier, &permis);
        }
        essai = copier_vers(source, &cible);
    }
    match essai {
        Ok(()) => {
            bilan.copies += 1;
            bilan.octets += std::fs::metadata(&cible).map_or(0, |m| m.len());
            if cible.file_name() != source.file_name() {
                bilan.renommes.push((source.to_path_buf(), cible));
            }
        }
        Err(e) => bilan.echecs.push((source.to_path_buf(), e.to_string())),
    }
}

fn copier_arbre(source: &Path, cible: &Path, bilan: &mut Bilan, avancement: &mut Avancement) {
    let mut a_voir = vec![(source.to_path_buf(), cible.to_path_buf())];
    while let Some((de, vers)) = a_voir.pop() {
        let entrees = std::fs::create_dir_all(&vers).and_then(|()| std::fs::read_dir(&de));
        let Ok(entrees) = entrees.inspect_err(|e| bilan.echecs.push((de, e.to_string()))) else {
            continue;
        };
        for e in entrees.flatten() {
            let chemin = e.path();
            let Ok(m) = chemin.symlink_metadata() else { continue };
            if m.is_symlink() {
                bilan.liens += 1;
            } else if m.is_dir() {
                a_voir.push((chemin, vers.join(nom_permis(&e.file_name().to_string_lossy()))));
            } else if m.is_file() {
                copier_fichier(&chemin, &vers, bilan);
                avancement.fichiers += 1;
                avancement.octets += m.len();
                avancement.montrer(false);
            }
        }
    }
}

/// Le dossier daté où copier : celui d'une copie interrompue à reprendre (le plus récent), sinon un nouveau.
fn dossier_de_copie(racine: &Path, reprendre: impl Fn(&str) -> bool) -> PathBuf {
    let interrompue = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let nom = p.file_name().unwrap_or_default().to_string_lossy();
            PREFIXES.iter().any(|pre| nom.starts_with(pre)) && p.join(TEMOIN).is_file()
        })
        .max()
        .filter(|d| reprendre(&d.file_name().unwrap_or_default().to_string_lossy()));
    if let Some(d) = interrompue {
        return d;
    }
    let date = chrono::Local::now().format("%Y-%m-%d");
    let base = trf!("Gardien-copie-{}", "Gardien-copy-{}", date);
    std::iter::once(racine.join(&base))
        .chain((2..=999).map(|n| racine.join(format!("{base}-{n}"))))
        .find(|d| std::fs::symlink_metadata(d).is_err())
        .unwrap_or_else(|| racine.join(base))
}

fn copier(choisis: &[(Sorte, PathBuf)], dossier: &Path, total: (u64, u64)) -> Bilan {
    let mut bilan = Bilan::default();
    let mut avancement = Avancement {
        total_fichiers: total.0,
        total_octets: total.1,
        fichiers: 0,
        octets: 0,
        debut: Instant::now(),
        dernier: Instant::now(),
        terminal: std::io::stdout().is_terminal(),
    };
    if let Err(e) = std::fs::create_dir_all(dossier)
        .and_then(|()| std::fs::write(dossier.join(TEMOIN), chrono::Local::now().to_rfc3339()))
    {
        bilan.echecs.push((dossier.to_path_buf(), e.to_string()));
        return bilan;
    }
    for (sorte, source) in choisis {
        let nom = source.file_name().map_or(sorte.nom().into(), |n| n.to_string_lossy());
        copier_arbre(source, &dossier.join(nom_permis(&nom)), &mut bilan, &mut avancement);
    }
    avancement.montrer(true);
    let _ = std::fs::write(dossier.join(COMPTE_RENDU), compte_rendu(choisis, &bilan));
    // Tout est copié : la copie n'est plus « en cours ». Avec des échecs, le témoin reste, pour réessayer.
    if bilan.echecs.is_empty() {
        let _ = std::fs::remove_file(dossier.join(TEMOIN));
    }
    bilan
}

fn compte_rendu(choisis: &[(Sorte, PathBuf)], b: &Bilan) -> String {
    use std::fmt::Write as _;
    let mut t = format!(
        "{} — Gardien {} — {}\n\n",
        tr!("Copie de fichiers", "File copy"),
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format("%Y-%m-%d %H:%M")
    );
    for (s, chemin) in choisis {
        let _ = writeln!(t, "{} : {}", s.nom(), chemin.display());
    }
    let resume = trf!(
        "{} fichier(s) copié(s), {} déjà présent(s) à l'identique, {} lien(s) non copié(s), {} échec(s).",
        "{} file(s) copied, {} already there unchanged, {} link(s) not copied, {} failure(s).",
        b.copies,
        b.deja,
        b.liens,
        b.echecs.len()
    );
    let _ = writeln!(t, "\n{resume}");
    let autre_nom = tr!("Autre nom", "Other name");
    for (de, vers) in &b.renommes {
        let _ = writeln!(t, "{autre_nom} : {} → {}", de.display(), vers.display());
    }
    for (chemin, erreur) in &b.echecs {
        let _ = writeln!(t, "{} : {} ({erreur})", tr!("Échec", "Failed"), chemin.display());
    }
    t
}

/// Le chemin désigné en ligne de commande, s'il est un dossier d'un autre disque que celui du système (et pas la
/// clé, ni l'un des dossiers copiés : la copie s'y copierait elle-même).
fn destination_permise(chemin: &Path, sources: &[(Sorte, PathBuf)]) -> Result<PathBuf, String> {
    let chemin = chemin
        .canonicalize()
        .map_err(|e| trf!("{} : {e}", "{}: {e}", chemin_affichable(chemin)))?;
    if !chemin.is_dir() {
        let dossier = chemin_affichable(&chemin);
        return Err(trf!("{} n'est pas un dossier.", "{} is not a folder.", dossier));
    }
    let refus = if chemin.ancestors().any(est_la_cle) {
        tr!(
            "La clé GARDIEN n'est pas un disque de copie.",
            "The GARDIEN key is not a copy disk."
        )
    } else if sources
        .iter()
        .any(|(_, s)| s.canonicalize().is_ok_and(|s| chemin.starts_with(s)))
    {
        tr!(
            "Ce dossier est dans un des dossiers à copier.",
            "This folder is inside one of the folders to copy."
        )
    } else if sur_le_systeme(&chemin) == Some(true) {
        tr!(
            "Ce dossier est sur le disque du système : une copie n'y protège de rien.",
            "This folder is on the system disk: a copy there protects from nothing."
        )
    } else {
        return Ok(chemin);
    };
    Err(refus.into())
}

fn choisir_disque() -> Option<PathBuf> {
    let liste = disques();
    if liste.is_empty() {
        let aucun = tr!(
            "Aucun disque externe branché (la clé GARDIEN et le disque du système ne comptent pas). Branche un disque ou une clé assez grande, attends qu'il apparaisse, puis recommence.",
            "No external disk plugged in (the GARDIEN key and the system disk do not count). Plug in a large enough disk or USB stick, wait for it to appear, then start again."
        );
        afficher_aligne("  ✖ ", aucun, 4, "");
        return None;
    }
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_section(tr!("OÙ COPIER", "WHERE TO COPY"))),
    ];
    for (i, d) in liste.iter().enumerate() {
        let (libre, total) = (taille_lisible(d.libre), taille_lisible(d.total));
        let place = trf!("{} libres sur {}", "{} free out of {}", libre, total);
        lignes.push(Ligne::choix(&(i + 1).to_string(), &d.nom, &place));
    }
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    lignes.push(Ligne::Texte(String::new()));
    let invite = tr!(
        "  Numéro du disque (Entrée pour revenir) : ",
        "  Disk number (Enter to go back): "
    );
    let choix = choisir(&lignes, invite, "1", tr!("revenir", "back"))?;
    let i = choix.trim().parse::<usize>().ok()?.checked_sub(1)?;
    liste.into_iter().nth(i).map(|d| d.racine)
}

/// « gardien copier-fichiers [destination] » ; sans destination, le disque se choisit parmi ceux qui sont branchés.
pub fn commande(destination: Option<&Path>) {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("COPIER MES FICHIERS", "COPY MY FILES")),
        &format!("{GRIS}{}{RESET}", tr!("rien n'est effacé", "nothing is deleted")),
    );
    let sources = sources();
    if sources.is_empty() {
        trp!(
            "  Aucun dossier personnel trouvé (Documents, Images…).",
            "  No personal folder found (Documents, Pictures…)."
        );
        return;
    }
    let racine = match destination.map(|d| destination_permise(d, &sources)) {
        None => choisir_disque(),
        Some(permise) => permise.inspect_err(|e| println!("  ✖ {e}")).ok(),
    };
    let Some(racine) = racine else { return };
    trp!(
        "  {DISCRET}Mesure des dossiers…{RESET}",
        "  {DISCRET}Measuring the folders…{RESET}"
    );
    let mesures: Vec<(u64, u64)> = sources.iter().map(|(_, c)| mesurer(c)).collect();
    let cases: Vec<Case> = sources
        .iter()
        .zip(&mesures)
        .map(|((s, chemin), &(n, octets))| Case {
            texte: s.nom().to_string(),
            precision: trf!("{} · {n} fichier(s)", "{} · {n} file(s)", taille_lisible(octets)),
            detail: chemin_affichable(chemin),
            cochee: n > 0,
            recommandee: n > 0,
            fixe: false,
        })
        .collect();
    let entete = [
        String::new(),
        ligne_titre(tr!("Quels dossiers copier ?", "Which folders to copy?")),
        trf!(
            "  {GRIS}Vers : {}{RESET}",
            "  {GRIS}To: {}{RESET}",
            chemin_affichable(&racine)
        ),
        String::new(),
    ];
    let Some(coches) = cocher(&entete, &cases) else { return };
    let (choisis, tailles): (Vec<_>, Vec<(u64, u64)>) = sources
        .into_iter()
        .zip(mesures)
        .zip(coches)
        .filter_map(|(choisi, coche)| coche.then_some(choisi))
        .unzip();
    let total = tailles.iter().fold((0, 0), |(n, o), (f, b)| (n + f, o + b));
    if choisis.is_empty() {
        trp!("  Rien à copier.", "  Nothing to copy.");
        return;
    }
    let dossier = dossier_de_copie(&racine, |nom| {
        // Un dossier du disque de destination, qui peut être celui de n'importe qui.
        let nom = affichable(nom);
        demander(&trf!(
            "\n  Une copie commencée n'est pas finie ({nom}). La reprendre ? [O/n] : ",
            "\n  A started copy is not finished ({nom}). Resume it? [Y/n]: "
        ))
        .chars()
        .next()
        .is_none_or(|c| matches!(c, 'o' | 'O' | 'y' | 'Y'))
    });
    // En reprise, ce qui est déjà copié ne reprend pas de place.
    let deja = if dossier.is_dir() { mesurer(&dossier).1 } else { 0 };
    #[cfg(unix)]
    let libre = crate::nettoyer::volume(&racine).map(|(libre, _)| libre);
    #[cfg(windows)]
    let libre = disques()
        .into_iter()
        .find(|d| racine.starts_with(&d.racine))
        .map(|d| d.libre);
    let besoin = total.1.saturating_sub(deja);
    if let Some(libre) = libre
        && besoin > libre
    {
        trp!(
            "\n  ✖ Pas assez de place : il faut {}, le disque n'a que {} de libre. Décoche des dossiers, ou prends un disque plus grand.",
            "\n  ✖ Not enough space: {} needed, the disk only has {} free. Uncheck some folders, or use a larger disk.",
            taille_lisible(besoin),
            taille_lisible(libre)
        );
        return;
    }
    trp!(
        "\n  {} fichier(s), {} → {}",
        "\n  {} file(s), {} → {}",
        total.0,
        taille_lisible(total.1),
        chemin_affichable(&dossier)
    );
    if !demander(tr!("  Copier ? [o/N] : ", "  Copy? [y/N]: ")).oui() {
        trp!("  Annulé.", "  Cancelled.");
        return;
    }
    let debut = Instant::now();
    afficher_bilan(&copier(&choisis, &dossier, total), &dossier, debut.elapsed());
}

fn afficher_bilan(b: &Bilan, dossier: &Path, duree: Duration) {
    println!();
    if b.echecs.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Copie terminée et vérifiée : {} fichier(s) copié(s), {} déjà là à l'identique, {} en {} s.",
            "  {VERT}✔{RESET} Copy finished and checked: {} file(s) copied, {} already there unchanged, {} in {} s.",
            b.copies,
            b.deja,
            taille_lisible(b.octets),
            duree.as_secs()
        );
    } else {
        trp!(
            "  ⚠ Copie terminée avec {} échec(s) : {} fichier(s) copié(s), {} déjà là. Relance la copie pour réessayer les fichiers ratés.",
            "  ⚠ Copy finished with {} failure(s): {} file(s) copied, {} already there. Run the copy again to retry the failed files.",
            b.echecs.len(),
            b.copies,
            b.deja
        );
        for (chemin, erreur) in b.echecs.iter().take(5) {
            afficher_aligne("    ✖ ", &format!("{} ({erreur})", chemin_affichable(chemin)), 6, GRIS);
        }
    }
    if !b.renommes.is_empty() {
        trp!(
            "  {} fichier(s) copié(s) sous un autre nom (place déjà prise, ou nom refusé par ce disque) : voir {COMPTE_RENDU}.",
            "  {} file(s) copied under another name (place already taken, or name refused by this disk): see {COMPTE_RENDU}.",
            b.renommes.len()
        );
    }
    if b.liens > 0 {
        trp!(
            "  {GRIS}{} raccourci(s) (liens) non copié(s) : ce ne sont pas des fichiers.{RESET}",
            "  {GRIS}{} shortcut(s) (links) not copied: they are not files.{RESET}",
            b.liens
        );
    }
    trp!(
        "  {GRIS}Dans : {}{RESET}",
        "  {GRIS}In: {}{RESET}",
        chemin_affichable(dossier)
    );
}

pub fn menu() {
    commande(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les sous-volumes d'un même btrfs (/, /home, /var/log) ont chacun leur `st_dev` : ils comptaient pour d'autres
    /// disques, et une copie vers /var/log ou un sous-volume monté dans /mnt était acceptée. Le montage qui contient
    /// le chemin, lui, dit le vrai système de fichiers.
    #[cfg(target_os = "linux")]
    #[test]
    fn sous_volumes_du_systeme() {
        let montages = "23 1 0:30 /@ / rw,relatime shared:1 - btrfs /dev/mapper/root rw\n\
                        24 23 0:30 /@home /home rw,relatime shared:2 - btrfs /dev/mapper/root rw\n\
                        25 23 0:30 /@log /var/log rw,relatime shared:3 - btrfs /dev/mapper/root rw\n\
                        26 23 0:30 /@sauve /mnt/sauve rw,relatime shared:4 - btrfs /dev/mapper/root rw\n\
                        90 23 8:17 / /run/media/alice/Mon\\040disque rw,nosuid - exfat /dev/sdb1 rw\n";
        let maison = Path::new("/home/alice");
        let systeme = |p: &str| sur_le_systeme_selon(montages, Path::new(p), maison);
        assert_eq!(systeme("/var/log/copie"), Some(true));
        assert_eq!(systeme("/mnt/sauve"), Some(true));
        assert_eq!(systeme("/home/alice/Documents"), Some(true));
        assert_eq!(systeme("/run/media/alice/Mon disque/x"), Some(false));
        // Un nom qui commence pareil n'est pas sous ce montage.
        assert_eq!(systeme("/run/media/alice/Mon disque2"), Some(true));
    }

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gardien-copie-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn avancement() -> Avancement {
        Avancement {
            total_fichiers: 0,
            total_octets: 0,
            fichiers: 0,
            octets: 0,
            debut: Instant::now(),
            dernier: Instant::now(),
            terminal: false,
        }
    }

    #[test]
    fn copie_verifiee_puis_reprise_sans_rien_ecraser() {
        let base = jetable("arbre");
        let source = base.join("Documents");
        std::fs::create_dir_all(source.join("factures/2026")).unwrap();
        std::fs::write(source.join("lettre.txt"), "Bonjour alice").unwrap();
        std::fs::write(source.join("factures/2026/janvier.pdf"), vec![7u8; 3 << 20]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/hostname", source.join("raccourci")).unwrap();
        let cible = base.join("disque/Gardien-copie-2026-10-18/Documents");
        let mut b = Bilan::default();
        copier_arbre(&source, &cible, &mut b, &mut avancement());
        assert_eq!((b.copies, b.deja, b.echecs.len()), (2, 0, 0), "{b:?}");
        assert_eq!(
            std::fs::read(cible.join("factures/2026/janvier.pdf")).unwrap(),
            vec![7u8; 3 << 20]
        );
        #[cfg(unix)]
        assert_eq!(b.liens, 1);
        // Aucun fichier partiel ne reste.
        assert!(!cible.join(format!(".lettre.txt{PARTIEL}")).exists());
        // Reprise : ce qui est déjà là à l'identique n'est pas recopié.
        let mut reprise = Bilan::default();
        copier_arbre(&source, &cible, &mut reprise, &mut avancement());
        assert_eq!((reprise.copies, reprise.deja), (0, 2), "{reprise:?}");
        // L'original a changé : la copie d'avant reste, la nouvelle prend un autre nom.
        std::fs::write(source.join("lettre.txt"), "Bonjour bob").unwrap();
        let mut change = Bilan::default();
        copier_arbre(&source, &cible, &mut change, &mut avancement());
        assert_eq!(
            std::fs::read_to_string(cible.join("lettre.txt")).unwrap(),
            "Bonjour alice"
        );
        assert_eq!(
            std::fs::read_to_string(cible.join("lettre (2).txt")).unwrap(),
            "Bonjour bob"
        );
        assert_eq!(change.renommes.len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn partiel_d_une_copie_interrompue_remplace() {
        let base = jetable("partiel");
        std::fs::write(base.join("photo.jpg"), b"image entiere").unwrap();
        let cible = base.join("copie");
        std::fs::create_dir_all(&cible).unwrap();
        std::fs::write(cible.join(format!(".photo.jpg{PARTIEL}")), b"ima").unwrap();
        let mut b = Bilan::default();
        copier_fichier(&base.join("photo.jpg"), &cible, &mut b);
        assert_eq!(b.copies, 1);
        assert_eq!(std::fs::read(cible.join("photo.jpg")).unwrap(), b"image entiere");
        assert!(!cible.join(format!(".photo.jpg{PARTIEL}")).exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn noms_et_dossiers_dates() {
        assert_eq!(nom_permis("réunion : bilan?.txt"), "réunion _ bilan_.txt");
        assert_eq!(nom_permis("fin. "), "fin");
        assert_eq!(nom_permis("::"), "__");
        let base = jetable("dates");
        std::fs::write(base.join("photo.jpg"), b"x").unwrap();
        std::fs::write(base.join("photo (2).jpg"), b"x").unwrap();
        assert_eq!(nom_libre(&base, "photo.jpg"), base.join("photo (3).jpg"));
        assert_eq!(nom_libre(&base, "LISEZMOI"), base.join("LISEZMOI (2)"));
        // Une copie interrompue se propose ; refusée, un nouveau dossier daté.
        let interrompue = base.join("Gardien-copie-2026-10-01");
        std::fs::create_dir_all(&interrompue).unwrap();
        std::fs::write(interrompue.join(TEMOIN), "").unwrap();
        assert_eq!(dossier_de_copie(&base, |_| true), interrompue);
        let nouveau = dossier_de_copie(&base, |_| false);
        assert!(
            nouveau
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("Gardien-copie-")
        );
        assert_ne!(nouveau, interrompue);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn copie_complete_avec_compte_rendu() {
        let base = jetable("complete");
        let source = base.join("Images");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("vacances.png"), b"png").unwrap();
        let dossier = base.join("disque/Gardien-copie-2026-10-18");
        let b = copier(&[(Sorte::Images, source.clone())], &dossier, (1, 3));
        assert_eq!(b.copies, 1);
        assert!(dossier.join("Images/vacances.png").is_file());
        // Finie sans échec : plus de témoin, un compte rendu.
        assert!(!dossier.join(TEMOIN).exists());
        assert!(
            std::fs::read_to_string(dossier.join(COMPTE_RENDU))
                .unwrap()
                .contains("1 fichier(s) copié(s)")
        );
        assert_eq!(mesurer(&source), (1, 3));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn destination_refusee_dans_les_dossiers_copies() {
        let base = jetable("refus");
        let documents = base.join("Documents");
        std::fs::create_dir_all(documents.join("sauvegardes")).unwrap();
        let sources = [(Sorte::Documents, documents.clone())];
        assert!(destination_permise(&documents.join("sauvegardes"), &sources).is_err());
        assert!(destination_permise(&base.join("absent"), &sources).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn lecteurs_de_windows() {
        let d = lire_lecteurs(
            "C:\\|Windows|1000|2000\nE:\\|Sauvegarde|500|1000\nF:\\||10|20\nG:\\|x|abc|20\n",
            "C:",
        );
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].nom, "Sauvegarde (E:)");
        assert_eq!(d[1].nom, "F:");
        assert_eq!(d[0].libre, 500);
        // L'étiquette d'un disque branché, choisie par qui l'a formaté : piégée, elle arrive inoffensive.
        let d = lire_lecteurs("E:\\|Sauve\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}|500|1000\n", "C:");
        assert_eq!(d[0].nom, "Sauve�]52;c;eA==��[2K�� (E:)");
    }

    #[test]
    fn noms_reprises_et_refus_cas_limites() {
        let base = jetable("limites");
        assert_eq!(nom_libre(&base, ".bashrc"), base.join(".bashrc (2)"));
        assert_eq!(nom_libre(&base, "archive.tar.gz"), base.join("archive.tar (2).gz"));
        assert_eq!(nom_libre(&base, "fin."), base.join("fin (2)."));
        assert_eq!(nom_permis("a\tb\u{7f}c"), "a_b_c");
        assert_eq!(nom_permis(". ."), "_");
        // La plus récente des copies interrompues, quelle que soit la langue ; un dossier sans témoin n'en est pas une.
        for nom in [
            "Gardien-copie-2026-10-01",
            "Gardien-copy-2026-10-02",
            "Gardien-copy-2026-10-03",
        ] {
            std::fs::create_dir_all(base.join(nom)).unwrap();
        }
        std::fs::write(base.join("Gardien-copie-2026-10-01").join(TEMOIN), "").unwrap();
        std::fs::write(base.join("Gardien-copy-2026-10-02").join(TEMOIN), "").unwrap();
        let proposee = std::cell::RefCell::new(String::new());
        let reprise = dossier_de_copie(&base, |nom| {
            *proposee.borrow_mut() = nom.to_string();
            true
        });
        assert_eq!(reprise, base.join("Gardien-copy-2026-10-02"));
        assert_eq!(*proposee.borrow(), "Gardien-copy-2026-10-02");
        // Le lecteur du système est écarté, en minuscules comme avec sa barre.
        let d = lire_lecteurs("c:\\|Windows|1|2\nD:\\|Données|3|4\n", "C:\\");
        assert_eq!((d.len(), d[0].nom.as_str(), d[0].total), (1, "Données (D:)", 4));
        // Refus : un fichier, la clé GARDIEN et ses sous-dossiers.
        let cle = base.join("cle");
        std::fs::create_dir_all(cle.join("sous")).unwrap();
        std::fs::write(cle.join(crate::reseau::TEMOIN_CLE), "").unwrap();
        std::fs::write(base.join("note.txt"), "x").unwrap();
        let refus = destination_permise(&base.join("note.txt"), &[]).unwrap_err();
        assert!(refus.ends_with("note.txt n'est pas un dossier."), "{refus}");
        assert_eq!(
            destination_permise(&cle.join("sous"), &[]).unwrap_err(),
            "La clé GARDIEN n'est pas un disque de copie."
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
