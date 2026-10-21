//! La configuration de chargement du programme Windows (IMAGE_LOAD_CONFIG_DIRECTORY64), pour un seul champ :
//! DependentLoadFlags = LOAD_LIBRARY_SEARCH_SYSTEM32. Sans lui, le chargeur cherche les DLL importées qui ne sont pas
//! des « DLL connues » (iphlpapi, userenv, wevtapi…) d'abord à côté du programme, avant même sa première ligne : une
//! DLL posée dans Téléchargements ou sur la clé USB tournerait dans Vanguard, et en administrateur quand Vanguard se
//! relance pour une correction (eleve.rs). Aucun contrôle fait par le programme ne peut fermer ça : il arrive trop
//! tard. Avec ce champ (Windows 10 1607 et plus), les imports ne viennent que de System32.
//!
//! GNU ld n'a pas d'option pour ce champ, mais il remplit le répertoire « Load Config » du PE dès qu'un symbole
//! `_load_config_used` existe, avec la taille lue dans son premier mot ; le CRT de MinGW n'en fournit pas. Un test lit
//! le programme compilé pour vérifier que le champ y est bien.

/// IMAGE_LOAD_CONFIG_DIRECTORY64 jusqu'à GuardFlags (148 octets, la forme de Windows 8.1) : tout à zéro (ni cookie,
/// ni SafeSEH, ni CFG), sauf la taille et DependentLoadFlags.
#[repr(C)]
pub(crate) struct ConfigurationDeChargement {
    taille: u32,
    horodatage: u32,
    versions: [u16; 2],
    drapeaux_globaux: [u32; 2],
    delai_sections_critiques: u32,
    /// DeCommitFreeBlockThreshold … ProcessAffinityMask.
    seuils: [u64; 6],
    drapeaux_du_tas: u32,
    version_csd: u16,
    drapeaux_des_dependances: u16,
    /// EditList, SecurityCookie, SEHandlerTable, SEHandlerCount et les quatre champs de CFG.
    pointeurs: [u64; 8],
    drapeaux_de_garde: u32,
}

/// LOAD_LIBRARY_SEARCH_SYSTEM32.
pub(crate) const SYSTEM32_SEULEMENT: u16 = 0x800;
/// Taille annoncée : jusqu'à GuardFlags compris (sans le bourrage final de la structure Rust).
pub(crate) const TAILLE: u32 = 148;

// Le nom est imposé par l'éditeur de liens ; `#[used]` le garde même si rien ne le lit.
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
#[used]
pub(crate) static _load_config_used: ConfigurationDeChargement = ConfigurationDeChargement {
    taille: TAILLE,
    horodatage: 0,
    versions: [0; 2],
    drapeaux_globaux: [0; 2],
    delai_sections_critiques: 0,
    seuils: [0; 6],
    drapeaux_du_tas: 0,
    version_csd: 0,
    drapeaux_des_dependances: SYSTEM32_SEULEMENT,
    pointeurs: [0; 8],
    drapeaux_de_garde: 0,
};

#[cfg(test)]
/// La taille annoncée et DependentLoadFlags du répertoire « Load Config » d'un PE 64 bits ; `None` s'il n'en a pas.
pub(crate) fn lire(pe: &[u8]) -> Option<(u32, u16)> {
    let u16_a = |i: usize| pe.get(i..i + 2).map(|o| u16::from_le_bytes([o[0], o[1]]));
    let u32_a = |i: usize| pe.get(i..i + 4).map(|o| u32::from_le_bytes([o[0], o[1], o[2], o[3]]));
    let entete = usize::try_from(u32_a(0x3C)?).ok()?;
    if pe.get(entete..entete + 4)? != b"PE\0\0" {
        return None;
    }
    let sections = usize::from(u16_a(entete + 6)?);
    let facultatif = entete + 24;
    if u16_a(facultatif)? != 0x20B {
        return None;
    }
    // Répertoire n° 10 (Load Config), après les 112 premiers octets de l'en-tête facultatif PE32+.
    let rva = u32_a(facultatif + 112 + 10 * 8)?;
    if rva == 0 {
        return None;
    }
    let premiere = facultatif + usize::from(u16_a(entete + 20)?);
    (0..sections).find_map(|n| {
        let s = premiere + n * 40;
        let (taille, debut, brut) = (u32_a(s + 8)?, u32_a(s + 12)?, u32_a(s + 20)?);
        let dedans = rva.checked_sub(debut).filter(|d| *d < taille)?;
        let position = usize::try_from(brut.checked_add(dedans)?).ok()?;
        Some((u32_a(position)?, u16_a(position + 78)?))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_structure_a_la_forme_de_windows() {
        assert_eq!(
            std::mem::offset_of!(ConfigurationDeChargement, drapeaux_des_dependances),
            78
        );
        assert_eq!(std::mem::offset_of!(ConfigurationDeChargement, drapeaux_de_garde), 144);
        assert!(std::mem::size_of::<ConfigurationDeChargement>() >= TAILLE as usize);
    }

    /// Le programme compilé (ici, celui des tests, fait du même code) porte bien le champ : sans lui, une DLL posée à
    /// côté de Vanguard serait chargée avant sa première ligne.
    #[test]
    fn le_programme_ne_charge_ses_dll_que_depuis_system32() {
        let pe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(lire(&pe), Some((TAILLE, SYSTEM32_SEULEMENT)));
        assert_eq!(lire(b"MZ"), None);
    }
}
