//! Les empreintes SHA-256 de logiciels malveillants connus (MalwareBazaar, abuse.ch, CC0), pour l'analyse YARA : un
//! fichier dont l'empreinte y est, c'est ce logiciel malveillant précis, sans doute possible (une règle YARA, elle,
//! reconnaît une famille et peut se tromper). Gardées dans le dossier de Vanguard, triées pour une recherche en
//! quelques microsecondes : la liste complète (une archive zip d'environ 43 Mo, une fois par semaine) et les récentes
//! (48 heures, une fois par jour). Sans Internet, la copie d'avant sert ; sans copie du tout, c'est dit, jamais sain.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::ui::*;

const COMPLETE: &str = "https://bazaar.abuse.ch/export/txt/sha256/full/";
const RECENTES: &str = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
/// La liste complète se retélécharge après une semaine, les récentes après un jour.
const SEMAINE: Duration = Duration::from_hours(7 * 24);
const JOUR: Duration = Duration::from_hours(24);
/// Au-delà, ce n'est pas l'archive attendue (elle fait environ 43 Mo, 90 décompressée).
const ARCHIVE_MAX: u64 = 256 << 20;
const TEXTE_MAX: usize = 1 << 30;

/// Les empreintes connues, triées : (combien, de quand) se dit avec.
pub(crate) struct Empreintes {
    triees: Vec<[u8; 32]>,
}

impl Empreintes {
    #[cfg(test)]
    pub(crate) fn depuis(mut triees: Vec<[u8; 32]>) -> Empreintes {
        triees.sort_unstable();
        Empreintes { triees }
    }

    pub(crate) fn contient(&self, empreinte: &[u8; 32]) -> bool {
        self.triees.binary_search(empreinte).is_ok()
    }

    pub(crate) fn nombre(&self) -> usize {
        self.triees.len()
    }
}

/// Les empreintes d'un texte d'abuse.ch : une par ligne, 64 chiffres hexadécimaux, lignes « # » de commentaire.
fn lire_texte(texte: &str) -> Vec<[u8; 32]> {
    texte
        .lines()
        .map(str::trim)
        .filter(|l| l.len() == 64 && !l.starts_with('#'))
        .filter_map(|l| {
            let mut e = [0u8; 32];
            for (i, o) in e.iter_mut().enumerate() {
                *o = u8::from_str_radix(l.get(2 * i..2 * i + 2)?, 16).ok()?;
            }
            Some(e)
        })
        .collect()
}

fn mot16(o: &[u8], i: usize) -> Option<usize> {
    o.get(i..i + 2).map(|m| usize::from(u16::from_le_bytes([m[0], m[1]])))
}

fn mot32(o: &[u8], i: usize) -> Option<usize> {
    o.get(i..i + 4)
        .and_then(|m| usize::try_from(u32::from_le_bytes([m[0], m[1], m[2], m[3]])).ok())
}

/// Le premier fichier d'une archive zip, décompressé : lu par son répertoire central (fin de l'archive), qui donne les
/// vraies tailles même quand l'en-tête local les laisse à zéro. Compression « deflate » (8) ou aucune (0) ; au-delà de
/// `max` octets décompressés, rien. `None` : ce n'est pas une archive lisible.
fn premier_fichier_zip(archive: &[u8], max: usize) -> Option<Vec<u8>> {
    // La fin du répertoire central : 22 octets, au plus 64 Kio de commentaire après.
    let debut = archive.len().saturating_sub(22 + 0xffff);
    let fin = (debut..archive.len().saturating_sub(21))
        .rev()
        .find(|&i| archive.get(i..i + 4) == Some(b"PK\x05\x06"))?;
    let central = mot32(archive, fin + 16)?;
    if archive.get(central..central + 4)? != b"PK\x01\x02" {
        return None;
    }
    let methode = mot16(archive, central + 10)?;
    let compresse = mot32(archive, central + 20)?;
    let decompresse = mot32(archive, central + 24)?;
    let local = mot32(archive, central + 42)?;
    if archive.get(local..local + 4)? != b"PK\x03\x04" || decompresse > max {
        return None;
    }
    let donnees = local + 30 + mot16(archive, local + 26)? + mot16(archive, local + 28)?;
    let brut = archive.get(donnees..donnees.checked_add(compresse)?)?;
    match methode {
        0 => Some(brut.to_vec()),
        8 => miniz_oxide::inflate::decompress_to_vec_with_limit(brut, max).ok(),
        _ => None,
    }
}

fn dossier() -> PathBuf {
    crate::reseau::dossier_local().join("malwarebazaar")
}

pub(crate) fn age(chemin: &Path) -> Option<Duration> {
    std::fs::metadata(chemin)
        .and_then(|m| m.modified())
        .ok()
        .map(|t| t.elapsed().unwrap_or_default())
}

/// Télécharge `adresse` dans `chemin` quand la copie a plus de `apres` (écrite à côté puis renommée : une coupure ne
/// laisse jamais un fichier à moitié). Rien hors ligne, ni pendant les tests.
pub(crate) fn rafraichir(adresse: &str, chemin: &Path, apres: Duration, max: u64, secondes: u64) {
    if cfg!(test) || std::env::var_os("VANGUARD_HORS_LIGNE").is_some() || age(chemin).is_some_and(|a| a < apres) {
        return;
    }
    let reponse = crate::http::envoyer(crate::http::Demande {
        adresse,
        entetes: Vec::new(),
        corps: None,
        delai: Duration::from_secs(secondes),
        taille_max: max,
    });
    if let Some(r) = reponse.filter(|r| r.code == 200 && !r.corps.is_empty()) {
        let provisoire = chemin.with_extension("nouveau");
        if std::fs::write(&provisoire, &r.corps).is_ok() {
            let _ = std::fs::rename(&provisoire, chemin);
        }
    }
}

/// Les empreintes connues, chargées une fois par lancement (et rafraîchies d'abord quand il le faut). `None` : aucune
/// liste, ni téléchargée ni gardée.
pub(crate) fn connues() -> Option<&'static Empreintes> {
    static CHARGEES: OnceLock<Option<Empreintes>> = OnceLock::new();
    CHARGEES.get_or_init(|| charger(true)).as_ref()
}

/// Les empreintes déjà gardées sur cet ordinateur, sans rien télécharger : pour le bilan, qui ne doit pas attendre
/// 43 Mo quand personne n'a demandé la protection active. `None` : aucune liste gardée.
pub(crate) fn gardees() -> Option<&'static Empreintes> {
    static GARDEES: OnceLock<Option<Empreintes>> = OnceLock::new();
    GARDEES.get_or_init(|| charger(false)).as_ref()
}

fn charger(telecharger: bool) -> Option<Empreintes> {
    let d = dossier();
    let (complete, recentes) = (d.join("complete.zip"), d.join("recentes.txt"));
    if telecharger {
        let _ = std::fs::create_dir_all(&d);
        if age(&complete).is_none_or(|a| a > SEMAINE) {
            trp!(
                "  {GRIS}Empreintes de MalwareBazaar : liste complète (environ 43 Mo, une fois par semaine)…{RESET}",
                "  {GRIS}MalwareBazaar fingerprints: full list (about 43 MB, once a week)…{RESET}"
            );
        }
        rafraichir(COMPLETE, &complete, SEMAINE, ARCHIVE_MAX, 600);
        rafraichir(RECENTES, &recentes, JOUR, 16 << 20, 60);
    }
    let mut triees = std::fs::read(&complete)
        .ok()
        .and_then(|a| premier_fichier_zip(&a, TEXTE_MAX))
        .map(|t| lire_texte(&String::from_utf8_lossy(&t)))
        .unwrap_or_default();
    triees.extend(lire_texte(&std::fs::read_to_string(&recentes).unwrap_or_default()));
    triees.sort_unstable();
    triees.dedup();
    (!triees.is_empty()).then_some(Empreintes { triees })
}

/// Une empreinte en hexadécimal minuscule, telle que MalwareBazaar l'écrit.
pub(crate) fn hex(e: &[u8; 32]) -> String {
    e.iter().fold(String::with_capacity(64), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    })
}

/// L'empreinte SHA-256 d'un fichier, lue par morceaux. `None` : illisible.
pub(crate) fn sha256(chemin: &Path) -> Option<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open(chemin).ok()?;
    let mut h = Sha256::new();
    let mut tampon = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut tampon).ok()?;
        if n == 0 {
            break;
        }
        h.update(&tampon[..n]);
    }
    Some(h.finalize().into())
}

/// Les fichiers dont l'empreinte est connue, parmi `fichiers` : leur chemin et leur empreinte en hexadécimal.
pub(crate) fn connus(empreintes: &Empreintes, fichiers: &[PathBuf]) -> Vec<(PathBuf, String)> {
    fichiers
        .iter()
        .filter_map(|f| {
            let e = sha256(f)?;
            empreintes.contient(&e).then(|| (f.clone(), hex(&e)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empreintes_lues_triees_cherchees() {
        let texte = "# MalwareBazaar\n# sha256_hash\n\
            9edfda3b77b3973f37708add497130d44cd88374c85812926f7974687006e3e5\n\
            pas une empreinte\n\
            23B2BEE6D808E7D3CAF0E3E6F51E10D470F4CF298766C87F2062A4121DFB0D19\n\
            zz2bee6d808e7d3caf0e3e6f51e10d470f4cf298766c87f2062a4121dfb0d19\n";
        let mut triees = lire_texte(texte);
        assert_eq!(triees.len(), 2);
        triees.sort_unstable();
        let e = Empreintes { triees };
        assert_eq!(e.nombre(), 2);
        assert!(e.contient(&lire_texte("23b2bee6d808e7d3caf0e3e6f51e10d470f4cf298766c87f2062a4121dfb0d19")[0]));
        assert!(!e.contient(&[0; 32]));
    }

    /// Une archive zip faite ici, comme celle d'abuse.ch (un fichier, « deflate », tailles dans le répertoire central
    /// seulement) ; puis la même sans compression, et des archives abîmées.
    #[test]
    fn archive_zip_lue() {
        fn archive(contenu: &[u8], methode: u16) -> Vec<u8> {
            let donnees = if methode == 8 {
                miniz_oxide::deflate::compress_to_vec(contenu, 6)
            } else {
                contenu.to_vec()
            };
            let nom = b"full_sha256.txt";
            let mut z = b"PK\x03\x04".to_vec();
            z.extend_from_slice(&[20, 0, 8, 0]); // version, drapeaux (bit 3 : tailles plus loin)
            z.extend_from_slice(&methode.to_le_bytes());
            z.extend_from_slice(&[0; 16]); // heure, date, CRC et tailles laissés à zéro
            z.extend_from_slice(&u16::try_from(nom.len()).unwrap().to_le_bytes());
            z.extend_from_slice(&[0, 0]);
            z.extend_from_slice(nom);
            z.extend_from_slice(&donnees);
            let central = z.len();
            z.extend_from_slice(b"PK\x01\x02");
            z.extend_from_slice(&[20, 0, 20, 0, 8, 0]);
            z.extend_from_slice(&methode.to_le_bytes());
            z.extend_from_slice(&[0; 8]);
            z.extend_from_slice(&u32::try_from(donnees.len()).unwrap().to_le_bytes());
            z.extend_from_slice(&u32::try_from(contenu.len()).unwrap().to_le_bytes());
            z.extend_from_slice(&u16::try_from(nom.len()).unwrap().to_le_bytes());
            z.extend_from_slice(&[0; 12]);
            z.extend_from_slice(&0u32.to_le_bytes()); // l'en-tête local, au début
            z.extend_from_slice(nom);
            let taille_central = z.len() - central;
            z.extend_from_slice(b"PK\x05\x06");
            z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
            z.extend_from_slice(&u32::try_from(taille_central).unwrap().to_le_bytes());
            z.extend_from_slice(&u32::try_from(central).unwrap().to_le_bytes());
            z.extend_from_slice(&[0, 0]);
            z
        }
        let texte = "# sha256_hash\n9edfda3b77b3973f37708add497130d44cd88374c85812926f7974687006e3e5\n".repeat(50);
        assert_eq!(
            premier_fichier_zip(&archive(texte.as_bytes(), 8), 1 << 20).unwrap(),
            texte.as_bytes()
        );
        assert_eq!(
            premier_fichier_zip(&archive(texte.as_bytes(), 0), 1 << 20).unwrap(),
            texte.as_bytes()
        );
        // Trop gros une fois décompressé, abîmé, ou pas une archive : rien, sans paniquer.
        assert!(premier_fichier_zip(&archive(texte.as_bytes(), 8), 100).is_none());
        let mut abimee = archive(texte.as_bytes(), 8);
        abimee.truncate(abimee.len() - 30);
        assert!(premier_fichier_zip(&abimee, 1 << 20).is_none());
        assert!(premier_fichier_zip(b"pas une archive", 1 << 20).is_none());
    }

    #[test]
    fn fichier_connu_retrouve() {
        let d = crate::reseau::dossier_local().join("empreintes");
        std::fs::create_dir_all(&d).unwrap();
        let (mauvais, bon) = (d.join("facture.exe"), d.join("photo.jpg"));
        std::fs::write(&mauvais, b"contenu d'essai qui joue le logiciel malveillant").unwrap();
        std::fs::write(&bon, b"autre chose").unwrap();
        let empreintes = Empreintes {
            triees: vec![sha256(&mauvais).unwrap()],
        };
        let trouves = connus(&empreintes, &[mauvais.clone(), bon, d.join("absent")]);
        assert_eq!(trouves.len(), 1);
        assert_eq!(trouves[0].0, mauvais);
        assert_eq!(trouves[0].1.len(), 64);
    }
}
