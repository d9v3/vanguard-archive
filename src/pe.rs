//! La version d'un exécutable Windows (PE), lue dans sa ressource de version (RT_VERSION, VS_FIXEDFILEINFO), avec
//! son architecture (champ Machine de l'en-tête COFF). Écrit pour Vanguard, en Rust, sans fonction de Windows : la
//! même lecture sous Linux, où elle se teste, que sous Windows. Un .exe peut être fabriqué pour gêner l'analyse :
//! seuls les morceaux utiles sont lus, par `Seek`, jamais le fichier entier ; chaque position est contrôlée contre la
//! taille du fichier, l'arbre des ressources a sa profondeur exacte (3) et au plus 1 024 entrées par répertoire, et
//! tout ce qui sort de la forme attendue donne `None`, jamais une panique.
//!
//! Lecteur pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Au-delà, l'en-tête PE ne commence pas là où un éditeur de liens le met.
const E_LFANEW_MAX: u32 = 4096;
/// Le maximum de sections que Windows accepte.
const SECTIONS_MAX: u16 = 96;
/// Entrées d'un répertoire de ressources : un exécutable réel en a quelques dizaines.
const ENTREES_MAX: usize = 1024;
/// La ressource de version : quelques Kio.
const VERSION_MAX: u32 = 64 << 10;
/// Octets lus en tout dans un fichier.
const LUS_MAX: usize = 256 << 10;
/// Le type RT_VERSION.
const RT_VERSION: u32 = 16;
/// La signature de VS_FIXEDFILEINFO.
const SIGNATURE: u32 = 0xFEEF_04BD;

/// L'architecture d'un exécutable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Machine {
    X86,
    X64,
    Arm64,
    Autre(u16),
}

impl Machine {
    fn depuis(champ: u16) -> Machine {
        match champ {
            0x014c => Machine::X86,
            0x8664 => Machine::X64,
            0xAA64 => Machine::Arm64,
            autre => Machine::Autre(autre),
        }
    }
}

/// Ce que dit un exécutable : version du fichier et du produit (quatre nombres de 16 bits chacune), architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InfoPe {
    pub fichier: [u16; 4],
    pub produit: [u16; 4],
    pub machine: Machine,
}

/// Pourquoi la version d'un exécutable n'a pas été lue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Echec {
    /// Le fichier ne s'ouvre pas (absent, interdit…).
    Ouverture(std::io::ErrorKind),
    /// Pas un fichier ordinaire (dossier, tube nommé).
    PasUnFichier,
    /// Pas un exécutable PE, pas de ressource de version, ou une forme refusée.
    Format,
}

/// La version de l'exécutable `chemin`. Un fichier ordinaire seulement (un tube nommé bloquerait la lecture).
pub(crate) fn version(chemin: &Path) -> Result<InfoPe, Echec> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let mut fichier = options.open(chemin).map_err(|e| Echec::Ouverture(e.kind()))?;
    let meta = fichier.metadata().map_err(|e| Echec::Ouverture(e.kind()))?;
    if !meta.is_file() {
        return Err(Echec::PasUnFichier);
    }
    lire(&mut fichier, meta.len()).ok_or(Echec::Format)
}

/// Une section : où ses données sont en mémoire (RVA) et dans le fichier.
#[derive(Clone, Copy)]
struct Section {
    adresse: u32,
    taille_virtuelle: u32,
    taille_brute: u32,
    position: u32,
}

/// Le lecteur borné : position contrôlée contre la taille du fichier, total des octets lus compté.
struct Lecteur<'a, R> {
    source: &'a mut R,
    taille: u64,
    lus: usize,
}

impl<R: Read + Seek> Lecteur<'_, R> {
    fn octets(&mut self, position: u64, n: usize) -> Option<Vec<u8>> {
        let fin = position.checked_add(n as u64)?;
        self.lus = self.lus.checked_add(n)?;
        if fin > self.taille || self.lus > LUS_MAX {
            return None;
        }
        self.source.seek(SeekFrom::Start(position)).ok()?;
        let mut tampon = vec![0u8; n];
        self.source.read_exact(&mut tampon).ok()?;
        Some(tampon)
    }

    fn u16(&mut self, position: u64) -> Option<u16> {
        let o = self.octets(position, 2)?;
        Some(u16::from_le_bytes([o[0], o[1]]))
    }

    fn u32(&mut self, position: u64) -> Option<u32> {
        let o = self.octets(position, 4)?;
        Some(u32::from_le_bytes([o[0], o[1], o[2], o[3]]))
    }
}

/// La position dans le fichier d'une adresse virtuelle (RVA) et des `n` octets qui la suivent, s'ils sont tous dans
/// les données brutes d'une même section.
fn position(sections: &[Section], rva: u32, n: u32) -> Option<u64> {
    let s = sections.iter().find(|s| {
        let etendue = s.taille_virtuelle.max(s.taille_brute);
        rva >= s.adresse && u64::from(rva) < u64::from(s.adresse) + u64::from(etendue)
    })?;
    let decalage = rva - s.adresse;
    if u64::from(decalage) + u64::from(n) > u64::from(s.taille_brute) {
        return None;
    }
    Some(u64::from(s.position) + u64::from(decalage))
}

/// La version et l'architecture d'un exécutable de `taille` octets. `None` : pas un PE, pas de ressource de version,
/// ou une forme refusée.
pub(crate) fn lire<R: Read + Seek>(source: &mut R, taille: u64) -> Option<InfoPe> {
    let mut l = Lecteur { source, taille, lus: 0 };
    // En-tête DOS, puis l'en-tête PE qu'il désigne.
    if l.octets(0, 2)? != b"MZ" {
        return None;
    }
    let e_lfanew = l.u32(0x3C)?;
    if e_lfanew >= E_LFANEW_MAX {
        return None;
    }
    let pe = u64::from(e_lfanew);
    if l.octets(pe, 4)? != b"PE\0\0" {
        return None;
    }
    // En-tête COFF.
    let machine = Machine::depuis(l.u16(pe + 4)?);
    let nombre_sections = l.u16(pe + 6)?;
    let taille_facultatif = l.u16(pe + 20)?;
    if nombre_sections == 0 || nombre_sections > SECTIONS_MAX {
        return None;
    }
    // En-tête facultatif : PE32 ou PE32+, et la table des répertoires de données qui le termine.
    let facultatif = pe + 24;
    let (nombre_repertoires, repertoires) = match l.u16(facultatif)? {
        0x10B => (l.u32(facultatif + 92)?, 96u16),
        0x20B => (l.u32(facultatif + 108)?, 112u16),
        _ => return None,
    };
    // Le répertoire n° 2 (ressources) doit exister, et tenir dans l'en-tête facultatif annoncé.
    if nombre_repertoires <= 2 || u32::from(repertoires) + 3 * 8 > u32::from(taille_facultatif) {
        return None;
    }
    let rva_ressources = l.u32(facultatif + u64::from(repertoires) + 16)?;
    if rva_ressources == 0 {
        return None;
    }
    // Table des sections.
    let table = facultatif + u64::from(taille_facultatif);
    let mut sections = Vec::with_capacity(usize::from(nombre_sections));
    for i in 0..u64::from(nombre_sections) {
        let s = l.octets(table + i * 40, 40)?;
        let mot = |a: usize| u32::from_le_bytes([s[a], s[a + 1], s[a + 2], s[a + 3]]);
        sections.push(Section {
            taille_virtuelle: mot(8),
            adresse: mot(12),
            taille_brute: mot(16),
            position: mot(20),
        });
    }
    // Les données brutes de chaque section doivent être dans le fichier.
    if sections
        .iter()
        .any(|s| u64::from(s.position) + u64::from(s.taille_brute) > taille)
    {
        return None;
    }
    let donnees = ressource_de_version(&mut l, &sections, rva_ressources)?;
    let (fichier, produit) = info_fixe(&donnees)?;
    Some(InfoPe {
        fichier,
        produit,
        machine,
    })
}

/// Une entrée d'un répertoire de ressources : son nom ou numéro, et le décalage de ce qu'elle désigne (bit de poids
/// fort : un sous-répertoire), depuis le début des ressources.
struct Entree {
    nom: u32,
    decalage: u32,
}

/// Les entrées du répertoire au `decalage` des ressources : d'abord celles à nom, puis celles à numéro.
fn entrees<R: Read + Seek>(
    l: &mut Lecteur<'_, R>,
    sections: &[Section],
    rva_ressources: u32,
    decalage: u32,
) -> Option<Vec<Entree>> {
    let rva = rva_ressources.checked_add(decalage)?;
    let debut = position(sections, rva, 16)?;
    let nommees = usize::from(l.u16(debut + 12)?);
    let numerotees = usize::from(l.u16(debut + 14)?);
    let n = nommees + numerotees;
    if n == 0 || n > ENTREES_MAX {
        return None;
    }
    let taille = u32::try_from(n * 8).ok()?;
    let position_entrees = position(sections, rva.checked_add(16)?, taille)?;
    let brut = l.octets(position_entrees, n * 8)?;
    let (morceaux, _) = brut.as_chunks::<8>();
    Some(
        morceaux
            .iter()
            .map(|e| Entree {
                nom: u32::from_le_bytes([e[0], e[1], e[2], e[3]]),
                decalage: u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
            })
            .collect(),
    )
}

const SOUS_REPERTOIRE: u32 = 0x8000_0000;

/// Les octets de la ressource de version : niveau 1, le type 16 ; niveau 2, son premier nom ; niveau 3, sa première
/// langue, qui désigne les données. Chaque sous-répertoire est plus loin que son parent : un arbre qui reviendrait en
/// arrière (une boucle) est refusé.
fn ressource_de_version<R: Read + Seek>(
    l: &mut Lecteur<'_, R>,
    sections: &[Section],
    rva_ressources: u32,
) -> Option<Vec<u8>> {
    let niveau1 = entrees(l, sections, rva_ressources, 0)?;
    let version = niveau1.iter().find(|e| e.nom == RT_VERSION)?;
    if version.decalage & SOUS_REPERTOIRE == 0 {
        return None;
    }
    let decalage2 = version.decalage & !SOUS_REPERTOIRE;
    if decalage2 == 0 {
        return None;
    }
    let niveau2 = entrees(l, sections, rva_ressources, decalage2)?;
    let nom = niveau2.first()?;
    if nom.decalage & SOUS_REPERTOIRE == 0 {
        return None;
    }
    let decalage3 = nom.decalage & !SOUS_REPERTOIRE;
    if decalage3 <= decalage2 {
        return None;
    }
    let niveau3 = entrees(l, sections, rva_ressources, decalage3)?;
    let langue = niveau3.first()?;
    // Au troisième niveau, des données, jamais un répertoire : la profondeur est exactement 3.
    if langue.decalage & SOUS_REPERTOIRE != 0 || langue.decalage <= decalage3 {
        return None;
    }
    // IMAGE_RESOURCE_DATA_ENTRY : adresse (RVA) et taille des données.
    let entree = position(sections, rva_ressources.checked_add(langue.decalage)?, 16)?;
    let rva_donnees = l.u32(entree)?;
    let taille = l.u32(entree + 4)?;
    if taille == 0 || taille > VERSION_MAX {
        return None;
    }
    let debut = position(sections, rva_donnees, taille)?;
    l.octets(debut, usize::try_from(taille).ok()?)
}

/// VS_VERSIONINFO : longueur, longueur de la valeur, type, la clé « VS_VERSION_INFO » en UTF-16, un alignement sur
/// 4 octets, puis VS_FIXEDFILEINFO (52 octets, signature 0xFEEF04BD). Rend les versions du fichier et du produit.
fn info_fixe(donnees: &[u8]) -> Option<([u16; 4], [u16; 4])> {
    let mot16 = |a: usize| Some(u16::from_le_bytes([*donnees.get(a)?, *donnees.get(a + 1)?]));
    let mot32 = |a: usize| {
        Some(u32::from_le_bytes([
            *donnees.get(a)?,
            *donnees.get(a + 1)?,
            *donnees.get(a + 2)?,
            *donnees.get(a + 3)?,
        ]))
    };
    let longueur = usize::from(mot16(0)?);
    let longueur_valeur = usize::from(mot16(2)?);
    if longueur > donnees.len() || longueur_valeur < 52 {
        return None;
    }
    let cle: Vec<u16> = "VS_VERSION_INFO\0".encode_utf16().collect();
    for (i, c) in cle.iter().enumerate() {
        if mot16(6 + 2 * i)? != *c {
            return None;
        }
    }
    let fixe = (6 + 2 * cle.len()).next_multiple_of(4);
    if fixe + 52 > longueur || mot32(fixe)? != SIGNATURE {
        return None;
    }
    let quatre = |ms: u32, ls: u32| {
        #[allow(clippy::cast_possible_truncation)]
        [(ms >> 16) as u16, ms as u16, (ls >> 16) as u16, ls as u16]
    };
    Some((
        quatre(mot32(fixe + 8)?, mot32(fixe + 12)?),
        quatre(mot32(fixe + 16)?, mot32(fixe + 20)?),
    ))
}

#[cfg(test)]
pub(crate) mod essais {
    //! Un PE minimal fabriqué en Rust, pour les tests d'ici et de l'inventaire : aucun .exe tiers dans le dépôt.

    /// Les réglages d'un PE fabriqué : de quoi le rendre valide, ou abîmé d'une façon précise.
    #[derive(Clone)]
    pub(crate) struct Fabrique {
        pub machine: u16,
        pub pe32_plus: bool,
        pub fichier: [u16; 4],
        pub produit: [u16; 4],
        pub signature: u32,
        /// Décalage du répertoire de niveau 2 (depuis le début des ressources).
        pub niveau2: u32,
        pub niveau3: u32,
        /// Le troisième niveau pointe un sous-répertoire au lieu des données.
        pub trop_profond: bool,
        pub entrees_niveau1: u16,
        pub taille_version: Option<u32>,
        /// Ajouté à l'adresse des données de version (hors section).
        pub decalage_donnees: u32,
        pub e_lfanew: u32,
        pub taille_brute: Option<u32>,
    }

    impl Default for Fabrique {
        fn default() -> Self {
            Fabrique {
                machine: 0x8664,
                pe32_plus: true,
                fichier: [1, 2, 3, 4],
                produit: [5, 6, 7, 8],
                signature: super::SIGNATURE,
                niveau2: 0x18,
                niveau3: 0x30,
                trop_profond: false,
                entrees_niveau1: 1,
                taille_version: None,
                decalage_donnees: 0,
                e_lfanew: 0x40,
                taille_brute: None,
            }
        }
    }

    fn mot16(v: &mut [u8], a: usize, x: u16) {
        v[a..a + 2].copy_from_slice(&x.to_le_bytes());
    }

    fn mot32(v: &mut [u8], a: usize, x: u32) {
        v[a..a + 4].copy_from_slice(&x.to_le_bytes());
    }

    /// La ressource VS_VERSIONINFO, seule (sans StringFileInfo).
    fn version_info(f: &Fabrique) -> Vec<u8> {
        let mut v = vec![0u8; 92];
        mot16(&mut v, 0, 92);
        mot16(&mut v, 2, 52);
        for (i, c) in "VS_VERSION_INFO\0".encode_utf16().enumerate() {
            mot16(&mut v, 6 + 2 * i, c);
        }
        mot32(&mut v, 40, f.signature);
        mot32(&mut v, 44, 0x0001_0000);
        let ms = |q: [u16; 4]| (u32::from(q[0]) << 16) | u32::from(q[1]);
        let ls = |q: [u16; 4]| (u32::from(q[2]) << 16) | u32::from(q[3]);
        mot32(&mut v, 48, ms(f.fichier));
        mot32(&mut v, 52, ls(f.fichier));
        mot32(&mut v, 56, ms(f.produit));
        mot32(&mut v, 60, ls(f.produit));
        v
    }

    /// Un PE : en-tête DOS, en-têtes PE, une section « .rsrc » (RVA 0x1000, à 0x200 du fichier) qui contient l'arbre
    /// des ressources (types, noms, langues), l'entrée de données, puis VS_VERSIONINFO.
    pub(crate) fn pe(f: &Fabrique) -> Vec<u8> {
        const RVA: u32 = 0x1000;
        const BRUT: usize = 0x200;
        let mut v = vec![0u8; 0x400];
        v[..2].copy_from_slice(b"MZ");
        mot32(&mut v, 0x3C, f.e_lfanew);
        let pe = 0x40usize;
        v[pe..pe + 4].copy_from_slice(b"PE\0\0");
        mot16(&mut v, pe + 4, f.machine);
        mot16(&mut v, pe + 6, 1);
        let (magic, taille_facultatif, nombre, repertoires) = if f.pe32_plus {
            (0x20Bu16, 240u16, 108usize, 112usize)
        } else {
            (0x10B, 224, 92, 96)
        };
        mot16(&mut v, pe + 20, taille_facultatif);
        let facultatif = pe + 24;
        mot16(&mut v, facultatif, magic);
        mot32(&mut v, facultatif + nombre, 16);
        mot32(&mut v, facultatif + repertoires + 16, RVA);
        mot32(&mut v, facultatif + repertoires + 20, 0x200);
        let section = facultatif + usize::from(taille_facultatif);
        v[section..section + 5].copy_from_slice(b".rsrc");
        mot32(&mut v, section + 8, 0x200);
        mot32(&mut v, section + 12, RVA);
        mot32(&mut v, section + 16, f.taille_brute.unwrap_or(0x200));
        mot32(&mut v, section + 20, u32::try_from(BRUT).unwrap());
        // Niveau 1 (0x00) : n entrées à numéro, la dernière RT_VERSION.
        let r = BRUT;
        mot16(&mut v, r + 14, f.entrees_niveau1);
        for i in 0..usize::from(f.entrees_niveau1.min(1)) {
            mot32(&mut v, r + 16 + 8 * i, 16);
            mot32(&mut v, r + 20 + 8 * i, 0x8000_0000 | f.niveau2);
        }
        // Niveau 2 : un nom (1).
        let n2 = r + f.niveau2 as usize;
        mot16(&mut v, n2 + 14, 1);
        mot32(&mut v, n2 + 16, 1);
        mot32(&mut v, n2 + 20, 0x8000_0000 | f.niveau3);
        // Niveau 3 : une langue (0x409), qui désigne l'entrée de données à 0x48.
        let n3 = r + f.niveau3 as usize;
        mot16(&mut v, n3 + 14, 1);
        mot32(&mut v, n3 + 16, 0x409);
        mot32(&mut v, n3 + 20, if f.trop_profond { 0x8000_0048 } else { 0x48 });
        let donnees = version_info(f);
        let entree = r + 0x48;
        mot32(&mut v, entree, RVA + 0x60 + f.decalage_donnees);
        mot32(
            &mut v,
            entree + 4,
            f.taille_version.unwrap_or(u32::try_from(donnees.len()).unwrap()),
        );
        v[r + 0x60..r + 0x60 + donnees.len()].copy_from_slice(&donnees);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::essais::{Fabrique, pe};
    use super::*;
    use std::io::Cursor;

    fn lu(octets: &[u8]) -> Option<InfoPe> {
        lire(&mut Cursor::new(octets), octets.len() as u64)
    }

    #[test]
    fn version_et_architecture() {
        for (machine, attendue) in [
            (0x8664, Machine::X64),
            (0x014c, Machine::X86),
            (0xAA64, Machine::Arm64),
            (0x01c4, Machine::Autre(0x01c4)),
        ] {
            for pe32_plus in [true, false] {
                let f = Fabrique {
                    machine,
                    pe32_plus,
                    fichier: [156, 0, 8078, 48],
                    produit: [156, 0, 8078, 47],
                    ..Fabrique::default()
                };
                assert_eq!(
                    lu(&pe(&f)),
                    Some(InfoPe {
                        fichier: [156, 0, 8078, 48],
                        produit: [156, 0, 8078, 47],
                        machine: attendue
                    }),
                    "{machine:x} {pe32_plus}"
                );
            }
        }
    }

    #[test]
    fn formes_hostiles_refusees() {
        let refuse = |f: Fabrique, quoi: &str| assert_eq!(lu(&pe(&f)), None, "{quoi}");
        refuse(
            Fabrique {
                e_lfanew: 0x2000,
                ..Fabrique::default()
            },
            "e_lfanew hors fichier",
        );
        refuse(
            Fabrique {
                e_lfanew: 0x41,
                ..Fabrique::default()
            },
            "e_lfanew qui ne désigne pas « PE »",
        );
        refuse(
            Fabrique {
                signature: 0xFEEF_04BC,
                ..Fabrique::default()
            },
            "signature fausse",
        );
        refuse(
            Fabrique {
                entrees_niveau1: 0,
                ..Fabrique::default()
            },
            "répertoire sans entrée",
        );
        refuse(
            Fabrique {
                entrees_niveau1: 2000,
                ..Fabrique::default()
            },
            "trop d'entrées",
        );
        refuse(
            Fabrique {
                niveau3: 0x18,
                niveau2: 0x30,
                ..Fabrique::default()
            },
            "arbre qui revient en arrière",
        );
        refuse(
            Fabrique {
                trop_profond: true,
                ..Fabrique::default()
            },
            "quatrième niveau",
        );
        refuse(
            Fabrique {
                taille_version: Some(0),
                ..Fabrique::default()
            },
            "taille 0",
        );
        refuse(
            Fabrique {
                taille_version: Some(1 << 20),
                ..Fabrique::default()
            },
            "taille démesurée",
        );
        refuse(
            Fabrique {
                decalage_donnees: 0x1000,
                ..Fabrique::default()
            },
            "données hors section",
        );
        refuse(
            Fabrique {
                taille_brute: Some(0x10_0000),
                ..Fabrique::default()
            },
            "section qui déborde du fichier",
        );
        // Coupé : à chaque endroit, jamais lu.
        let bon = pe(&Fabrique::default());
        for n in [0, 2, 0x3C, 0x44, 0x100, 0x200, 0x260, 0x2b0, bon.len() - 1] {
            assert_eq!(lu(&bon[..n]), None, "coupé à {n}");
        }
        assert_eq!(lu(b"#!/bin/sh\n"), None);
    }

    #[test]
    fn fichier_ordinaire_seulement() {
        let dossier = std::env::temp_dir().join(format!("vanguard-pe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let exe = dossier.join("chrome.exe");
        std::fs::write(&exe, pe(&Fabrique::default())).unwrap();
        assert_eq!(version(&exe).map(|i| i.fichier), Ok([1, 2, 3, 4]));
        // Un dossier : refusé à l'ouverture sous Windows, refusé comme pas un fichier ailleurs.
        if cfg!(windows) {
            assert!(version(&dossier).is_err());
        } else {
            assert_eq!(version(&dossier), Err(Echec::PasUnFichier));
        }
        assert!(matches!(version(&dossier.join("absent.exe")), Err(Echec::Ouverture(_))));
        std::fs::write(&exe, b"MZ").unwrap();
        assert_eq!(version(&exe), Err(Echec::Format));
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// Sous Windows (Wine) : notre propre programme, compilé à côté des tests, porte la version de Cargo.toml
    /// (winresource la grave à la compilation). Absent : le test le dit et sort.
    #[cfg(windows)]
    #[test]
    fn version_de_vanguard_exe() {
        let Some(exe) = std::env::current_exe()
            .ok()
            .and_then(|t| Some(t.parent()?.parent()?.join("vanguard.exe")))
            .filter(|e| e.is_file())
        else {
            eprintln!("vanguard.exe pas encore compilé à côté des tests : version non vérifiée");
            return;
        };
        let info = version(&exe).unwrap_or_else(|e| panic!("{}: {e:?}", exe.display()));
        let attendue: Vec<u16> = env!("CARGO_PKG_VERSION")
            .split('.')
            .map(|n| n.parse().unwrap())
            .collect();
        assert_eq!(&info.fichier[..3], &attendue[..], "{}", exe.display());
        assert_eq!(info.machine, Machine::X64);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..1200)) {
            let _ = lu(&octets);
            let mut mz = octets.clone();
            if mz.len() >= 0x40 {
                mz[..2].copy_from_slice(b"MZ");
                mz[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
            }
            let _ = lu(&mz);
        }

        /// Un PE valide abîmé à quelques endroits : lu ou refusé, sans planter.
        #[test]
        fn pe_abime(changements in proptest::collection::vec((0usize..0x400, proptest::num::u8::ANY), 1..6), pe32 in proptest::bool::ANY) {
            let mut octets = pe(&Fabrique { pe32_plus: pe32, ..Fabrique::default() });
            for (i, x) in changements {
                octets[i] = x;
            }
            let _ = lu(&octets);
        }
    }
}
