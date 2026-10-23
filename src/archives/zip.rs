//! Les fichiers d'une archive zip : seulement des fichiers stockés tels quels ou compressés (deflate), sans zip64 ni
//! chiffrement, comme tldr-pages en publie. Le répertoire central est cherché depuis la fin, puis chaque entrée lue à
//! la position que donne son en-tête local.

use super::Bornes;

/// Les fichiers (nom, contenu). Une entrée illisible, hors des bornes ou dont le contenu n'a pas la taille annoncée
/// est sautée ; une archive illisible donne une liste vide. Au plus `entrees` entrées parcourues, `fichier` octets
/// par fichier, `total` en tout.
pub(crate) fn lire(octets: &[u8], bornes: &Bornes) -> Vec<(String, Vec<u8>)> {
    // La fin du répertoire central, cherchée depuis la fin (un commentaire peut la suivre).
    let Some(fin) = (0..octets.len().saturating_sub(21))
        .rev()
        .take(65_557)
        .find(|&i| u32_a(octets, i) == Some(0x0605_4b50))
    else {
        return Vec::new();
    };
    let (Some(nombre), Some(debut)) = (u16_a(octets, fin + 10), u32_a(octets, fin + 16)) else {
        return Vec::new();
    };
    let mut fichiers = Vec::new();
    let mut total = 0;
    let mut i = debut as usize;
    for _ in 0..usize::from(nombre).min(bornes.entrees) {
        if u32_a(octets, i) != Some(0x0201_4b50) {
            break;
        }
        let Some((methode, compresse, taille, longueur_nom, autres, local)) = entree_centrale(octets, i) else {
            break;
        };
        let nom = octets
            .get(i + 46..i + 46 + longueur_nom)
            .map(|n| String::from_utf8_lossy(n).into_owned());
        i += 46 + longueur_nom + autres;
        let Some(nom) = nom else { break };
        if taille > bornes.fichier || total + taille > bornes.total {
            continue;
        }
        let donnees = donnees_locales(octets, local, compresse);
        // La taille rendue doit être celle annoncée, qui a passé les bornes : une entrée qui ment (annoncée minuscule,
        // décompressée bien plus grande) ferait sinon dépasser la borne du total.
        let contenu = match (methode, donnees) {
            (0, Some(d)) if d.len() == taille => Some(d.to_vec()),
            (8, Some(d)) => miniz_oxide::inflate::decompress_to_vec_with_limit(d, taille)
                .ok()
                .filter(|c| c.len() == taille),
            _ => None,
        };
        if let Some(contenu) = contenu {
            total += contenu.len();
            fichiers.push((nom, contenu));
        }
    }
    fichiers
}

fn u16_a(octets: &[u8], i: usize) -> Option<u16> {
    octets.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_a(octets: &[u8], i: usize) -> Option<u32> {
    octets
        .get(i..i + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Une entrée du répertoire central : (méthode, taille compressée, taille, longueur du nom, longueur des champs qui
/// suivent le nom, position de l'en-tête local).
fn entree_centrale(octets: &[u8], i: usize) -> Option<(u16, usize, usize, usize, usize, usize)> {
    Some((
        u16_a(octets, i + 10)?,
        u32_a(octets, i + 20)? as usize,
        u32_a(octets, i + 24)? as usize,
        usize::from(u16_a(octets, i + 28)?),
        usize::from(u16_a(octets, i + 30)?) + usize::from(u16_a(octets, i + 32)?),
        u32_a(octets, i + 42)? as usize,
    ))
}

/// Les données d'un fichier, après son en-tête local.
fn donnees_locales(octets: &[u8], local: usize, compresse: usize) -> Option<&[u8]> {
    (u32_a(octets, local)? == 0x0403_4b50).then_some(())?;
    let depart = local + 30 + usize::from(u16_a(octets, local + 26)?) + usize::from(u16_a(octets, local + 28)?);
    octets.get(depart..depart.checked_add(compresse)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une archive zip faite à la main : (nom, données telles qu'écrites, méthode, taille annoncée) par entrée.
    fn archive(entrees: &[(&str, Vec<u8>, u16, u32)]) -> Vec<u8> {
        let (mut zip, mut central) = (Vec::new(), Vec::new());
        for (nom, donnees, methode, taille) in entrees {
            let local = u32::try_from(zip.len()).unwrap();
            let compresse = u32::try_from(donnees.len()).unwrap();
            let longueur = u16::try_from(nom.len()).unwrap();
            zip.extend(0x0403_4b50u32.to_le_bytes());
            zip.extend([20, 0, 0, 0]);
            zip.extend(methode.to_le_bytes());
            zip.extend([0u8; 8]);
            zip.extend(compresse.to_le_bytes());
            zip.extend(taille.to_le_bytes());
            zip.extend(longueur.to_le_bytes());
            zip.extend([0, 0]);
            zip.extend(nom.as_bytes());
            zip.extend(donnees);
            central.extend(0x0201_4b50u32.to_le_bytes());
            central.extend([20, 0, 20, 0, 0, 0]);
            central.extend(methode.to_le_bytes());
            central.extend([0u8; 8]);
            central.extend(compresse.to_le_bytes());
            central.extend(taille.to_le_bytes());
            central.extend(longueur.to_le_bytes());
            central.extend([0u8; 12]);
            central.extend(local.to_le_bytes());
            central.extend(nom.as_bytes());
        }
        let debut = u32::try_from(zip.len()).unwrap();
        let n = u16::try_from(entrees.len()).unwrap();
        let taille_centrale = u32::try_from(central.len()).unwrap();
        zip.extend(central);
        zip.extend(0x0605_4b50u32.to_le_bytes());
        zip.extend([0, 0, 0, 0]);
        zip.extend(n.to_le_bytes());
        zip.extend(n.to_le_bytes());
        zip.extend(taille_centrale.to_le_bytes());
        zip.extend(debut.to_le_bytes());
        zip.extend([0, 0]);
        zip
    }

    #[test]
    fn stockees_et_compressees() {
        let texte = b"# exemple\n\n> Une page inventee.\n".repeat(20);
        let deflate = miniz_oxide::deflate::compress_to_vec(&texte, 6);
        let taille = u32::try_from(texte.len()).unwrap();
        let zip = archive(&[
            ("pages/common/a.md", b"stockee".to_vec(), 0, 7),
            ("pages/common/b.md", deflate, 8, taille),
            ("pages/common/c.md", b"xx".to_vec(), 0, 3),
        ]);
        let bornes = Bornes {
            entrees: 10,
            fichier: 1 << 16,
            total: 1 << 16,
        };
        let lus = lire(&zip, &bornes);
        assert_eq!(lus.len(), 2, "la taille fausse de c.md l'écarte");
        assert_eq!(lus[0], ("pages/common/a.md".to_string(), b"stockee".to_vec()));
        assert_eq!(lus[1].1, texte);
    }

    /// Une entrée compressée qui ment sur sa taille (annoncée minuscule, décompressée bien plus grande) : écartée, et
    /// les bornes tiennent sur ce qui est rendu, pas sur ce qui est annoncé.
    #[test]
    fn taille_annoncee_fausse() {
        let gros = vec![b'a'; 60_000];
        let deflate = miniz_oxide::deflate::compress_to_vec(&gros, 6);
        let entrees: Vec<(String, Vec<u8>, u16, u32)> = (0..20)
            .map(|i| (format!("pages/common/{i}.md"), deflate.clone(), 8, 1))
            .collect();
        let entrees: Vec<(&str, Vec<u8>, u16, u32)> = entrees
            .iter()
            .map(|(n, d, m, t)| (n.as_str(), d.clone(), *m, *t))
            .collect();
        let bornes = Bornes {
            entrees: 100,
            fichier: 1 << 16,
            total: 1 << 17,
        };
        let lus = lire(&archive(&entrees), &bornes);
        assert!(lus.iter().map(|(_, c)| c.len()).sum::<usize>() <= bornes.total);
        assert!(lus.is_empty(), "{} entrées rendues", lus.len());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..600)) {
            let bornes = Bornes { entrees: 100, fichier: 1 << 12, total: 1 << 14 };
            let _ = lire(&octets, &bornes);
            // Une fin de répertoire central en queue : le parcours des entrées est essayé, pas seulement la recherche.
            let mut avec_fin = octets.clone();
            avec_fin.extend(0x0605_4b50u32.to_le_bytes());
            avec_fin.extend([0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let _ = lire(&avec_fin, &bornes);
        }
    }
}
