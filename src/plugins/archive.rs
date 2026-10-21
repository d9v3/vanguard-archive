//! Une archive .zip de plugin (celui d'un autre, téléchargé), dépliée en Rust avec miniz_oxide (déjà là pour les
//! empreintes de MalwareBazaar), sans programme externe. Une archive vient de n'importe qui : rien n'est écrit hors du
//! dossier de dépliage (chemin absolu, lecteur, « .. », lien : refusés), et elle est bornée en taille et en nombre.

use std::path::Path;

use crate::{tr, trf};

/// Ce qu'une archive peut faire une fois dépliée, au plus.
pub const OCTETS_MAX: usize = 50 << 20;
const FICHIERS_MAX: usize = 500;

fn mot16(o: &[u8], i: usize) -> Option<usize> {
    Some(usize::from(u16::from_le_bytes(o.get(i..i + 2)?.try_into().ok()?)))
}

fn mot32(o: &[u8], i: usize) -> Option<usize> {
    usize::try_from(u32::from_le_bytes(o.get(i..i + 4)?.try_into().ok()?)).ok()
}

/// Une entrée lue : son chemin relatif (séparateurs « / ») et son contenu ; `None` pour un dossier.
pub struct Entree {
    pub chemin: String,
    pub contenu: Option<Vec<u8>>,
}

/// Les entrées de l'archive, lues par son répertoire central. `Err` dit pourquoi elle est refusée.
pub fn lire(archive: &[u8]) -> Result<Vec<Entree>, String> {
    let illisible = || tr!("archive .zip illisible", "unreadable .zip archive").to_string();
    let debut = archive.len().saturating_sub(22 + 0xffff);
    let fin = (debut..archive.len().saturating_sub(21))
        .rev()
        .find(|&i| archive.get(i..i + 4) == Some(b"PK\x05\x06"))
        .ok_or_else(illisible)?;
    let nombre = mot16(archive, fin + 10).ok_or_else(illisible)?;
    if nombre > FICHIERS_MAX {
        return Err(trf!(
            "archive de plus de {FICHIERS_MAX} fichiers",
            "archive of more than {FICHIERS_MAX} files"
        ));
    }
    let mut central = mot32(archive, fin + 16).ok_or_else(illisible)?;
    let mut entrees = Vec::new();
    let mut total = 0usize;
    for _ in 0..nombre {
        if archive.get(central..central + 4) != Some(b"PK\x01\x02") {
            return Err(illisible());
        }
        let drapeaux = mot16(archive, central + 8).ok_or_else(illisible)?;
        let methode = mot16(archive, central + 10).ok_or_else(illisible)?;
        let compresse = mot32(archive, central + 20).ok_or_else(illisible)?;
        let decompresse = mot32(archive, central + 24).ok_or_else(illisible)?;
        let n_nom = mot16(archive, central + 28).ok_or_else(illisible)?;
        let n_extra = mot16(archive, central + 30).ok_or_else(illisible)?;
        let n_comm = mot16(archive, central + 32).ok_or_else(illisible)?;
        let externes = mot32(archive, central + 38).ok_or_else(illisible)?;
        let local = mot32(archive, central + 42).ok_or_else(illisible)?;
        let nom = archive.get(central + 46..central + 46 + n_nom).ok_or_else(illisible)?;
        let nom = String::from_utf8(nom.to_vec()).map_err(|_| illisible())?;
        central += 46 + n_nom + n_extra + n_comm;
        let refus = |pourquoi: &str| {
            trf!(
                "« {} » dans l'archive : {pourquoi}",
                "“{}” in the archive: {pourquoi}",
                crate::ui::affichable(&nom)
            )
        };
        let dossier = nom.ends_with('/');
        let chemin = nom.trim_end_matches('/').to_string();
        if !super::manifeste::chemin_valide(&chemin) {
            return Err(refus(tr!(
                "chemin hors du dossier (absolu, lecteur ou « .. »)",
                "path outside the folder (absolute, drive or “..”)"
            )));
        }
        // Les droits Unix sont dans les 16 bits hauts des attributs externes : 0o120000, un lien symbolique.
        if (externes >> 16) & 0o170_000 == 0o120_000 {
            return Err(refus(tr!("un lien : refusé", "a link: refused")));
        }
        if drapeaux & 1 != 0 {
            return Err(refus(tr!("chiffré : refusé", "encrypted: refused")));
        }
        if dossier {
            entrees.push(Entree { chemin, contenu: None });
            continue;
        }
        total = total.saturating_add(decompresse);
        if total > OCTETS_MAX {
            return Err(trf!(
                "archive de plus de {} Mo une fois dépliée",
                "archive over {} MB once unpacked",
                OCTETS_MAX >> 20
            ));
        }
        if archive.get(local..local + 4) != Some(b"PK\x03\x04") {
            return Err(illisible());
        }
        let donnees = local
            + 30
            + mot16(archive, local + 26).ok_or_else(illisible)?
            + mot16(archive, local + 28).ok_or_else(illisible)?;
        let brut = archive
            .get(donnees..donnees.checked_add(compresse).ok_or_else(illisible)?)
            .ok_or_else(illisible)?;
        let contenu = match methode {
            0 => brut.to_vec(),
            8 => miniz_oxide::inflate::decompress_to_vec_with_limit(brut, decompresse).map_err(|_| illisible())?,
            _ => return Err(refus(tr!("compression inconnue", "unknown compression"))),
        };
        if contenu.len() != decompresse {
            return Err(illisible());
        }
        entrees.push(Entree {
            chemin,
            contenu: Some(contenu),
        });
    }
    Ok(entrees)
}

/// Déplie l'archive dans `vers` (qui existe, vide, réservé à son compte) : seulement des fichiers et des dossiers
/// ordinaires, jamais écrasés.
pub fn deplier(archive: &Path, vers: &Path) -> Result<(), String> {
    // Ouverte sans suivre de lien ni bloquer sur un tube, puis lue par une borne : remplacée entre deux appels par un
    // lien vers /dev/zero, elle ne remplirait ni la mémoire ni le disque.
    let refus = || {
        trf!(
            "archive refusée : pas un fichier ordinaire, ou plus de {} Mo",
            "archive refused: not a regular file, or over {} MB",
            OCTETS_MAX >> 20
        )
    };
    let f = super::ouvrir_sans_lien(archive, false).map_err(|_| refus())?;
    let mut octets = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(f, OCTETS_MAX as u64 + 1), &mut octets)
        .map_err(|e| e.to_string())?;
    if octets.len() > OCTETS_MAX {
        return Err(refus());
    }
    for e in lire(&octets)? {
        let cible = e.chemin.split('/').fold(vers.to_path_buf(), |c, p| c.join(p));
        let parent = if e.contenu.is_none() {
            Some(cible.as_path())
        } else {
            cible.parent()
        };
        if let Some(p) = parent {
            super::creer_prive(p).map_err(|e| e.to_string())?;
        }
        if let Some(contenu) = e.contenu {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            let mut f = o.open(&cible).map_err(|e| e.to_string())?;
            std::io::Write::write_all(&mut f, &contenu).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Une archive .zip sans compression, écrite à la main : (chemin, contenu, droits Unix).
    pub(crate) fn zip(entrees: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut a = Vec::new();
        let mut central = Vec::new();
        for (nom, contenu, droits) in entrees {
            let local = u32::try_from(a.len()).unwrap();
            let taille = u32::try_from(contenu.len()).unwrap();
            let n = u16::try_from(nom.len()).unwrap();
            a.extend(b"PK\x03\x04");
            a.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            a.extend(taille.to_le_bytes());
            a.extend(taille.to_le_bytes());
            a.extend(n.to_le_bytes());
            a.extend([0, 0]);
            a.extend(nom.as_bytes());
            a.extend(*contenu);
            central.extend(b"PK\x01\x02");
            central.extend([20, 3, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend(taille.to_le_bytes());
            central.extend(taille.to_le_bytes());
            central.extend(n.to_le_bytes());
            central.extend([0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend((droits << 16).to_le_bytes());
            central.extend(local.to_le_bytes());
            central.extend(nom.as_bytes());
        }
        let debut = u32::try_from(a.len()).unwrap();
        let n = u16::try_from(entrees.len()).unwrap();
        let taille = u32::try_from(central.len()).unwrap();
        a.extend(central);
        a.extend(b"PK\x05\x06");
        a.extend([0, 0, 0, 0]);
        a.extend(n.to_le_bytes());
        a.extend(n.to_le_bytes());
        a.extend(taille.to_le_bytes());
        a.extend(debut.to_le_bytes());
        a.extend([0, 0]);
        a
    }

    #[test]
    fn une_archive_ne_sort_jamais_de_son_dossier() {
        let bonne = zip(&[("salon/", b"", 0o40_755), ("salon/essai.sh", b"echo un\n", 0o100_644)]);
        let e = lire(&bonne).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[1].contenu.as_deref(), Some(&b"echo un\n"[..]));
        for (nom, droits, attendu) in [
            ("../x", 0o100_644, "hors du dossier"),
            ("/etc/x", 0o100_644, "hors du dossier"),
            ("a\\..\\..\\x", 0o100_644, "hors du dossier"),
            ("C:/x", 0o100_644, "hors du dossier"),
            ("lien", 0o120_777, "lien"),
        ] {
            let e = lire(&zip(&[(nom, b"x", droits)])).err().unwrap();
            assert!(e.contains(attendu), "{nom} : {e}");
        }
        assert!(lire(b"pas une archive").is_err());
    }
}
