//! Les partages de Windows lus sans PowerShell : NetShareEnum (les partages et leur descripteur de sécurité),
//! NetUserEnum (le compte Invité) et le gestionnaire de services (le service Serveur). Le texte rendu a la forme de
//! celui du script de secours (sections ACC, INV, SRV), lu par le même code. Le descripteur de sécurité est copié
//! puis relu en code sûr.

use std::ffi::c_void;

/// SHARE_INFO_502 de lmshare.h.
#[repr(C)]
struct Partage502 {
    nom: *const u16,
    sorte: u32,
    remarque: *const u16,
    permissions: u32,
    max: u32,
    en_cours: u32,
    chemin: *const u16,
    mot_de_passe: *const u16,
    reserve: u32,
    securite: *const c_void,
}

/// SHARE_INFO_1 de lmshare.h : sans chemin ni droits, lisible sans être administrateur.
#[repr(C)]
struct Partage1 {
    nom: *const u16,
    sorte: u32,
    remarque: *const u16,
}

/// USER_INFO_20 de lmaccess.h : `rid` est le dernier nombre du SID du compte (501 : Invité).
#[repr(C)]
struct Compte20 {
    nom: *const u16,
    nom_complet: *const u16,
    commentaire: *const u16,
    drapeaux: u32,
    rid: u32,
}

#[link(name = "netapi32")]
unsafe extern "system" {
    fn NetShareEnum(
        serveur: *const u16,
        niveau: u32,
        tampon: *mut *mut c_void,
        maximum: u32,
        lus: *mut u32,
        total: *mut u32,
        reprise: *mut u32,
    ) -> u32;
    fn NetUserEnum(
        serveur: *const u16,
        niveau: u32,
        filtre: u32,
        tampon: *mut *mut c_void,
        maximum: u32,
        lus: *mut u32,
        total: *mut u32,
        reprise: *mut u32,
    ) -> u32;
    fn NetApiBufferFree(tampon: *mut c_void) -> u32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn IsValidSecurityDescriptor(descripteur: *const c_void) -> i32;
    fn GetSecurityDescriptorLength(descripteur: *const c_void) -> u32;
    fn LookupAccountSidW(
        systeme: *const u16,
        sid: *const c_void,
        nom: *mut u16,
        taille_nom: *mut u32,
        domaine: *mut u16,
        taille_domaine: *mut u32,
        usage: *mut u32,
    ) -> i32;
}

const TOUT: u32 = u32::MAX;
const SPECIAL: u32 = 0x8000_0000;

/// Un texte UTF-16 terminé par un zéro, rendu par Windows ; lu sur 32 767 caractères au plus (la plus grande longueur
/// d'un nom ou d'un chemin de Windows).
///
/// # Safety
/// `p` est nul, ou désigne un texte terminé par un zéro qui vit pendant l'appel.
unsafe fn texte(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY : la borne est testée avant chaque lecture ; le texte se termine par un zéro (contrat de l'appelant).
    unsafe {
        while n < 32_767 && *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

/// Les lignes « ACC|… » des partages non spéciaux, puis « ACC_FIN » ; `None` si Windows refuse même la liste simple.
/// Sans droits d'administrateur, les droits d'un partage ne se lisent pas : sa ligne le dit (« ? »), comme le script.
fn acces() -> Option<Vec<String>> {
    let mut tampon: *mut c_void = std::ptr::null_mut();
    let (mut lus, mut total) = (0u32, 0u32);
    let mut lignes = Vec::new();
    // SAFETY : NetShareEnum (serveur nul : cet ordinateur) écrit dans `tampon` `lus` structures du niveau demandé,
    // que les types repr(C) reproduisent ; elles sont lues tant que le tampon vit, puis rendu une seule fois. Code non
    // nul : rien n'a été alloué.
    unsafe {
        if NetShareEnum(
            std::ptr::null(),
            502,
            &raw mut tampon,
            TOUT,
            &raw mut lus,
            &raw mut total,
            std::ptr::null_mut(),
        ) == 0
            && !tampon.is_null()
        {
            let liste = std::slice::from_raw_parts(tampon.cast::<Partage502>(), usize::try_from(lus).ok()?);
            for p in liste.iter().filter(|p| p.sorte & SPECIAL == 0) {
                let (nom, chemin) = (texte(p.nom), texte(p.chemin));
                match droits(p.securite) {
                    Some(regles) => lignes.extend(regles.into_iter().map(|r| format!("ACC|{nom}|{chemin}|{r}"))),
                    None => lignes.push(format!("ACC|{nom}|{chemin}|?|?|?|?")),
                }
            }
            NetApiBufferFree(tampon);
        } else if NetShareEnum(
            std::ptr::null(),
            1,
            &raw mut tampon,
            TOUT,
            &raw mut lus,
            &raw mut total,
            std::ptr::null_mut(),
        ) == 0
            && !tampon.is_null()
        {
            let liste = std::slice::from_raw_parts(tampon.cast::<Partage1>(), usize::try_from(lus).ok()?);
            for p in liste.iter().filter(|p| p.sorte & SPECIAL == 0) {
                lignes.push(format!("ACC|{}||?|?|?|?", texte(p.nom)));
            }
            NetApiBufferFree(tampon);
        } else {
            return None;
        }
    }
    lignes.push("ACC_FIN".into());
    Some(lignes)
}

/// Les règles d'un partage, « compte|SID|Allow ou Deny|droit » ; `None` si son descripteur ne se lit pas. Sans
/// descripteur, ou sans liste de droits, Windows ouvre le partage à tout le monde.
fn droits(descripteur: *const c_void) -> Option<Vec<String>> {
    if descripteur.is_null() {
        return Some(vec!["Everyone|S-1-1-0|Allow|Full".into()]);
    }
    // SAFETY : le descripteur vient de NetShareEnum et vit avec son tampon ; il est vérifié avant que sa longueur soit
    // demandée, et copié sur cette longueur seulement.
    let octets = unsafe {
        if IsValidSecurityDescriptor(descripteur) == 0 {
            return None;
        }
        let n = usize::try_from(GetSecurityDescriptorLength(descripteur)).ok()?;
        if n == 0 || n > 64 * 1024 {
            return None;
        }
        std::slice::from_raw_parts(descripteur.cast::<u8>(), n).to_vec()
    };
    let Some(regles) = regles_du_descripteur(&octets) else {
        return Some(vec!["Everyone|S-1-1-0|Allow|Full".into()]);
    };
    Some(
        regles
            .into_iter()
            .map(|r| format!("{}|{}|{}|{}", nom_du_compte(&r.sid), r.sid_texte, r.genre, r.droit))
            .collect(),
    )
}

/// Une règle lue dans la liste des droits d'un partage.
#[derive(Debug, PartialEq)]
struct Regle {
    sid: Vec<u8>,
    sid_texte: String,
    genre: &'static str,
    droit: &'static str,
}

/// Les règles d'un descripteur de sécurité autonome (SECURITY_DESCRIPTOR_RELATIVE) ; `None` sans liste de droits
/// (tout le monde a tout). Seules les règles « autoriser » et « refuser » simples comptent, comme pour
/// Get-SmbShareAccess. Chaque décalage est vérifié dans `octets` avant d'être lu.
fn regles_du_descripteur(octets: &[u8]) -> Option<Vec<Regle>> {
    const AUTONOME: u16 = 0x8000;
    const LISTE_PRESENTE: u16 = 0x4;
    let u16_a = |d: usize| Some(u16::from_le_bytes(octets.get(d..d + 2)?.try_into().ok()?));
    let u32_a = |d: usize| Some(u32::from_le_bytes(octets.get(d..d + 4)?.try_into().ok()?));
    let controle = u16_a(2)?;
    let liste = usize::try_from(u32_a(16)?).ok()?;
    if controle & AUTONOME == 0 || controle & LISTE_PRESENTE == 0 || liste == 0 {
        return None;
    }
    let taille = usize::from(u16_a(liste + 2)?);
    let nombre = u16_a(liste + 4)?;
    let fin = liste.checked_add(taille).filter(|&f| f <= octets.len())?;
    let mut regles = Vec::new();
    let mut d = liste + 8;
    for _ in 0..nombre {
        let (sorte, taille_regle) = (*octets.get(d)?, usize::from(u16_a(d + 2)?));
        if taille_regle < 8 || d + taille_regle > fin {
            break;
        }
        let genre = match sorte {
            0 => "Allow",
            1 => "Deny",
            _ => {
                d += taille_regle;
                continue;
            }
        };
        let masque = u32_a(d + 4)?;
        let sid = octets[d + 8..d + taille_regle].to_vec();
        if let Some(sid_texte) = sid_en_texte(&sid) {
            regles.push(Regle {
                sid_texte,
                sid,
                genre,
                droit: droit(masque),
            });
        }
        d += taille_regle;
    }
    Some(regles)
}

/// Le droit d'un masque, dans les mots de Get-SmbShareAccess : Full (contrôle total), Change (modifier), Read (lire),
/// sinon Custom.
fn droit(masque: u32) -> &'static str {
    const TOUS: u32 = 0x1000_0000;
    const LECTURE_GENERIQUE: u32 = 0x8000_0000;
    const CONTROLE_TOTAL: u32 = 0x001F_01FF;
    const MODIFIER: u32 = 0x0013_01BF;
    const LIRE: u32 = 0x0012_00A9;
    if masque & TOUS != 0 || masque & CONTROLE_TOTAL == CONTROLE_TOTAL {
        "Full"
    } else if masque & MODIFIER == MODIFIER {
        "Change"
    } else if masque & LIRE == LIRE || masque & LECTURE_GENERIQUE != 0 {
        "Read"
    } else {
        "Custom"
    }
}

/// « S-1-5-21-… » d'un SID binaire : révision, nombre de sous-autorités, autorité sur six octets (gros-boutiste), puis
/// les sous-autorités (petit-boutistes).
fn sid_en_texte(sid: &[u8]) -> Option<String> {
    use std::fmt::Write as _;
    let (revision, n) = (*sid.first()?, usize::from(*sid.get(1)?));
    if revision != 1 || n > 15 || sid.len() < 8 + 4 * n {
        return None;
    }
    let autorite = sid[2..8].iter().fold(0u64, |a, &o| (a << 8) | u64::from(o));
    let mut t = format!("S-1-{autorite}");
    for i in 0..n {
        let s = u32::from_le_bytes(sid[8 + 4 * i..12 + 4 * i].try_into().ok()?);
        let _ = write!(t, "-{s}");
    }
    Some(t)
}

/// Le nom d'un compte (« Everyone », « BUILTIN\Administrators ») ; son SID en texte s'il ne se traduit pas.
fn nom_du_compte(sid: &[u8]) -> String {
    let repli = || sid_en_texte(sid).unwrap_or_default();
    // Un SID est fait de mots de 32 bits : copié dans un tampon aligné pour Windows.
    let mut aligne = vec![0u32; sid.len().div_ceil(4)];
    for (i, o) in sid.iter().enumerate() {
        aligne[i / 4] |= u32::from(*o) << (8 * (i % 4));
    }
    let (mut nom, mut domaine) = (vec![0u16; 256], vec![0u16; 256]);
    let (mut taille_nom, mut taille_domaine, mut usage) = (256u32, 256u32, 0u32);
    // SAFETY : le SID copié vit pendant l'appel ; Windows écrit au plus 256 caractères dans chaque tampon, qui les a.
    let lu = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            aligne.as_ptr().cast(),
            nom.as_mut_ptr(),
            &raw mut taille_nom,
            domaine.as_mut_ptr(),
            &raw mut taille_domaine,
            &raw mut usage,
        )
    } != 0;
    if !lu {
        return repli();
    }
    let lire = |t: &[u16]| String::from_utf16_lossy(&t[..t.iter().position(|&c| c == 0).unwrap_or(t.len())]);
    match (lire(&domaine), lire(&nom)) {
        (_, n) if n.is_empty() => repli(),
        (d, n) if d.is_empty() => n,
        (d, n) => format!("{d}\\{n}"),
    }
}

/// « INV|True » si le compte Invité (RID 501) est activé, « INV|False » sinon, « INV| » s'il n'existe pas ; `None`
/// si la liste des comptes ne se lit pas.
fn invite() -> Option<String> {
    const COMPTES_NORMAUX: u32 = 0x2;
    const DESACTIVE: u32 = 0x2;
    let mut tampon: *mut c_void = std::ptr::null_mut();
    let (mut lus, mut total, mut reprise) = (0u32, 0u32, 0u32);
    // SAFETY : comme pour NetShareEnum : `lus` structures USER_INFO_20, lues tant que le tampon vit, rendu une fois.
    unsafe {
        if NetUserEnum(
            std::ptr::null(),
            20,
            COMPTES_NORMAUX,
            &raw mut tampon,
            TOUT,
            &raw mut lus,
            &raw mut total,
            &raw mut reprise,
        ) != 0
            || tampon.is_null()
        {
            return None;
        }
        let liste = std::slice::from_raw_parts(tampon.cast::<Compte20>(), usize::try_from(lus).unwrap_or(0));
        let etat = liste
            .iter()
            .find(|c| c.rid == 501)
            .map_or("", |c| if c.drapeaux & DESACTIVE == 0 { "True" } else { "False" });
        NetApiBufferFree(tampon);
        Some(format!("INV|{etat}"))
    }
}

/// Le relevé des partages, dans la forme du script de secours ; `None` si Windows refuse la liste des partages.
pub(crate) fn releve() -> Option<String> {
    let mut lignes = acces()?;
    if let Some(i) = invite() {
        lignes.extend([i, "INV_FIN".into()]);
    }
    if let Some(super::gestionnaire::Service::Etat(e)) = super::gestionnaire::etat("LanmanServer") {
        lignes.extend([format!("SRV|{e}"), "SRV_FIN".into()]);
    }
    Some(lignes.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SID binaire de « Tout le monde » (S-1-1-0) et d'un compte inventé.
    const TOUT_LE_MONDE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];

    fn regle(sorte: u8, masque: u32, sid: &[u8]) -> Vec<u8> {
        let taille = u16::try_from(8 + sid.len()).unwrap();
        let mut r = vec![sorte, 0];
        r.extend_from_slice(&taille.to_le_bytes());
        r.extend_from_slice(&masque.to_le_bytes());
        r.extend_from_slice(sid);
        r
    }

    fn descripteur(regles: &[Vec<u8>], controle: u16) -> Vec<u8> {
        let corps: Vec<u8> = regles.concat();
        let mut d = vec![1, 0];
        d.extend_from_slice(&controle.to_le_bytes());
        d.extend_from_slice(&[0; 12]);
        d.extend_from_slice(&20u32.to_le_bytes());
        d.extend_from_slice(&[2, 0]);
        d.extend_from_slice(&u16::try_from(8 + corps.len()).unwrap().to_le_bytes());
        d.extend_from_slice(&u16::try_from(regles.len()).unwrap().to_le_bytes());
        d.extend_from_slice(&[0, 0]);
        d.extend_from_slice(&corps);
        d
    }

    #[test]
    fn sids_en_texte() {
        assert_eq!(sid_en_texte(&TOUT_LE_MONDE).as_deref(), Some("S-1-1-0"));
        let mut invite = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for s in [21u32, 111, 222, 333, 501] {
            invite.extend_from_slice(&s.to_le_bytes());
        }
        assert_eq!(sid_en_texte(&invite).as_deref(), Some("S-1-5-21-111-222-333-501"));
        assert_eq!(sid_en_texte(&invite[..20]), None);
        assert_eq!(sid_en_texte(&[2, 0, 0, 0, 0, 0, 0, 1]), None);
    }

    #[test]
    fn droits_des_masques() {
        assert_eq!(droit(0x001F_01FF), "Full");
        assert_eq!(droit(0x1000_0000), "Full");
        assert_eq!(droit(0x0013_01BF), "Change");
        assert_eq!(droit(0x0012_00A9), "Read");
        assert_eq!(droit(0x0000_0001), "Custom");
    }

    #[test]
    fn regles_relues_dans_le_descripteur() {
        let d = descripteur(
            &[
                regle(0, 0x0012_00A9, &TOUT_LE_MONDE),
                regle(5, 0x001F_01FF, &TOUT_LE_MONDE),
                regle(1, 0x001F_01FF, &TOUT_LE_MONDE),
            ],
            0x8004,
        );
        let r = regles_du_descripteur(&d).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(
            (r[0].sid_texte.as_str(), r[0].genre, r[0].droit),
            ("S-1-1-0", "Allow", "Read")
        );
        assert_eq!((r[1].genre, r[1].droit), ("Deny", "Full"));
        // Sans liste de droits : tout le monde a tout.
        assert_eq!(regles_du_descripteur(&descripteur(&[], 0x8000)), None);
        // Une règle qui déborde de la liste arrête la lecture ; un descripteur tronqué ne se lit pas.
        let mut tronque = d.clone();
        tronque[22] = 30;
        assert!(regles_du_descripteur(&tronque).is_some_and(|r| r.len() <= 1));
        assert_eq!(regles_du_descripteur(&d[..10]), None);
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : le relevé se lit sans planter.
    #[test]
    fn partages_lus_par_windows() {
        if let Some(t) = releve() {
            assert!(t.lines().any(|l| l == "ACC_FIN"), "{t}");
        }
        assert_ne!(nom_du_compte(&TOUT_LE_MONDE), "");
    }
}
