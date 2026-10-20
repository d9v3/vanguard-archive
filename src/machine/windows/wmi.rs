//! WMI sans PowerShell : une requête WQL lue directement par COM. Chaque lancement de PowerShell coûte près d'une
//! demi-seconde (plusieurs secondes sur un ordinateur lent) ; la même lecture par COM, quelques millisecondes.
//! Chaque requête tourne dans son propre fil : son appartement COM ne gêne pas celui de l'appelant, et un fournisseur
//! WMI bloqué (Defender suspendu…) ne fige pas l'audit, comme le délai de `ps()`.

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;

use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize,
    EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, SAFEARRAY,
};
use windows::Win32::System::Ole::{SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound};
use windows::Win32::System::Variant::{
    VARENUM, VARIANT, VT_ARRAY, VT_BOOL, VT_BSTR, VT_I1, VT_I2, VT_I4, VT_I8, VT_INT, VT_UI1, VT_UI2, VT_UI4, VT_UI8,
    VT_UINT, VariantClear,
};
use windows::Win32::System::Wmi::{
    IWbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_GENERIC_FLAG_TYPE, WBEM_INFINITE,
    WbemLocator,
};
use windows::core::{BSTR, HSTRING, IUnknown, Interface};

/// Constantes de rpcdce.h (authentification Windows, sans autorisation), ici pour ne pas tirer tout Win32_System_Rpc.
const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;

/// Le délai de `ps()` est de 60 s ; ici la moitié, puisque PowerShell prend le relais si WMI ne répond pas.
const DELAI: Duration = Duration::from_secs(30);

/// Plus d'éléments qu'aucune liste lue par Vanguard n'en a : une liste plus longue est tronquée, pas parcourue.
const ELEMENTS_MAX: i32 = 4096;

/// Une valeur lue par WMI. Les entiers de 64 bits arrivent en texte (c'est ainsi que WMI les donne) : `entier()`
/// les relit.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Valeur {
    Nul,
    Booleen(bool),
    Entier(i64),
    Texte(String),
    Liste(Vec<Valeur>),
}

impl Valeur {
    pub(crate) fn entier(&self) -> Option<i64> {
        match self {
            Valeur::Entier(n) => Some(*n),
            Valeur::Texte(t) => t.trim().parse().ok(),
            _ => None,
        }
    }

    pub(crate) fn liste(&self) -> &[Valeur] {
        match self {
            Valeur::Liste(l) => l,
            _ => &[],
        }
    }
}

/// Une instance : ses champs demandés, `Valeur::Nul` pour un champ que la classe n'a pas (version de Windows plus
/// ancienne).
pub(crate) type Ligne = HashMap<String, Valeur>;

/// Les `champs` de chaque instance de `classe` dans l'espace de noms `espace` (`root\cimv2`…), filtrées par
/// `condition` (WQL, après WHERE ; vide : toutes). `None` : WMI absent ou en panne, espace ou classe inconnus (Wine,
/// édition de Windows sans ce composant), délai dépassé ; l'appelant passe alors par PowerShell ou dit « non
/// vérifié ». Une liste vide est une vraie réponse, aucune instance : la classe a été trouvée.
pub(crate) fn requete(espace: &str, classe: &str, condition: &str, champs: &[&str]) -> Option<Vec<Ligne>> {
    let (envoi, reception) = mpsc::channel();
    // Tous les champs (`*`), lus ensuite un par un : un champ que cette version de Windows n'a pas devient
    // `Valeur::Nul`, au lieu de faire échouer toute la requête.
    let wql = if condition.is_empty() {
        format!("SELECT * FROM {classe}")
    } else {
        format!("SELECT * FROM {classe} WHERE {condition}")
    };
    let (espace, classe) = (espace.to_string(), classe.to_string());
    let champs: Vec<String> = champs.iter().map(|c| (*c).to_string()).collect();
    let debut: String = wql.chars().take(240).collect();
    std::thread::Builder::new()
        .name("wmi".into())
        .spawn(move || {
            let _ = envoi.send(dans_ce_fil(&espace, &classe, &wql, &champs));
        })
        .ok()?;
    match reception.recv_timeout(DELAI) {
        Ok(Ok(lignes)) => Some(lignes),
        // Classe ou espace absents sont le cas courant sous Wine et sur les éditions familiales : PowerShell ou
        // « non vérifié » suivent, rien à noter au journal.
        Ok(Err(_)) => None,
        Err(_) => {
            crate::journal::erreur("WMI", &format!("délai de {} s dépassé\n{debut}", DELAI.as_secs()));
            None
        }
    }
}

/// Rend l'appartement COM du fil à sa fin, quel que soit le chemin de sortie.
struct Appartement;

impl Drop for Appartement {
    fn drop(&mut self) {
        // SAFETY : créé seulement après un CoInitializeEx réussi dans ce même fil.
        unsafe { CoUninitialize() };
    }
}

/// Droits d'appel sur un mandataire vers le service WMI : se faire passer pour l'utilisateur (impersonate), comme
/// Get-CimInstance. L'échec est sans suite : un objet sans mandataire (le WMI de Wine, dans le processus) n'en a pas
/// besoin, et un vrai refus se voit à la requête.
fn droits_d_appel<T: Interface>(objet: &T) {
    let Ok(objet) = objet.cast::<IUnknown>() else {
        return;
    };
    // SAFETY : objet est une interface COM vivante ; les autres paramètres sont des constantes ou nuls.
    let _ = unsafe {
        CoSetProxyBlanket(
            &objet,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    };
}

fn dans_ce_fil(espace: &str, classe: &str, wql: &str, champs: &[String]) -> windows::core::Result<Vec<Ligne>> {
    // SAFETY : fil créé pour cette seule requête ; l'appartement est rendu par `Appartement` à la sortie.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok()?;
    let _appartement = Appartement;
    // SAFETY : COM est initialisé dans ce fil ; WbemLocator est la classe du localisateur WMI de Windows.
    let localisateur: IWbemLocator = unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }?;
    let vide = BSTR::new();
    // SAFETY : chaînes BSTR valides pendant l'appel ; utilisateur et mot de passe vides = le compte qui lance.
    let services = unsafe { localisateur.ConnectServer(&BSTR::from(espace), &vide, &vide, &vide, 0, &vide, None) }?;
    droits_d_appel(&services);
    // SAFETY : services est vivant ; requête et langage sont des BSTR valides pendant l'appel.
    let instances = unsafe {
        services.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from(wql),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )
    }?;
    droits_d_appel(&instances);
    let noms: Vec<HSTRING> = champs.iter().map(|c| HSTRING::from(c.as_str())).collect();
    let mut lignes = Vec::new();
    loop {
        let mut objets = [None];
        let mut rendus = 0u32;
        // SAFETY : un emplacement pour un objet, `rendus` dit combien ont été écrits.
        unsafe { instances.Next(WBEM_INFINITE, &mut objets, &raw mut rendus) }.ok()?;
        let Some(objet) = objets[0].take().filter(|_| rendus == 1) else {
            break;
        };
        let mut ligne = Ligne::new();
        for (champ, nom) in champs.iter().zip(&noms) {
            let mut v = VARIANT::default();
            // SAFETY : objet est vivant, `nom` une chaîne terminée par un zéro, `v` un VARIANT vide qui reçoit la copie.
            let valeur = match unsafe { objet.Get(nom, 0, &raw mut v, None, None) } {
                // SAFETY : `v` vient d'être rempli par Get.
                Ok(()) => unsafe { lire(&v) },
                Err(_) => Valeur::Nul,
            };
            // SAFETY : `v` est à nous (copie rendue par Get, ou vide) ; VariantClear libère ce qu'il porte.
            let _ = unsafe { VariantClear(&raw mut v) };
            ligne.insert(champ.clone(), valeur);
        }
        lignes.push(ligne);
    }
    if lignes.is_empty() {
        // Le WMI de Wine répond à une classe inconnue par une liste vide, sans erreur : sans cette preuve que la
        // classe existe, « aucune instance » pourrait passer pour sain. L'emplacement de retour est exigé par Wine.
        let mut definition = None;
        // SAFETY : services est vivant ; le chemin est un BSTR valide pendant l'appel ; `definition` reçoit l'objet.
        unsafe {
            services.GetObject(
                &BSTR::from(classe),
                WBEM_GENERIC_FLAG_TYPE(0),
                None,
                Some(&raw mut definition),
                None,
            )
        }?;
    }
    Ok(lignes)
}

/// Le membre de l'union que désigne `vt`, et lui seul.
///
/// # Safety
/// `v` est un VARIANT initialisé dont `vt` décrit le contenu (rempli par COM).
unsafe fn lire(v: &VARIANT) -> Valeur {
    // SAFETY : le VARIANT est initialisé (contrat de la fonction) ; on lit son en-tête puis le membre de `vt`.
    unsafe {
        let interne = &v.Anonymous.Anonymous;
        let vt = interne.vt;
        let u = &interne.Anonymous;
        if vt.0 & VT_ARRAY.0 != 0 {
            return lire_liste(u.parray, VARENUM(vt.0 & !VT_ARRAY.0));
        }
        match vt {
            VT_BOOL => Valeur::Booleen(u.boolVal.as_bool()),
            VT_BSTR => Valeur::Texte(u.bstrVal.to_string()),
            VT_I1 => Valeur::Entier(i64::from(u.cVal)),
            VT_UI1 => Valeur::Entier(i64::from(u.bVal)),
            VT_I2 => Valeur::Entier(i64::from(u.iVal)),
            VT_UI2 => Valeur::Entier(i64::from(u.uiVal)),
            VT_I4 => Valeur::Entier(i64::from(u.lVal)),
            VT_UI4 => Valeur::Entier(i64::from(u.ulVal)),
            VT_INT => Valeur::Entier(i64::from(u.intVal)),
            VT_UINT => Valeur::Entier(i64::from(u.uintVal)),
            VT_I8 => Valeur::Entier(u.llVal),
            VT_UI8 => i64::try_from(u.ullVal).map_or(Valeur::Nul, Valeur::Entier),
            // Vide, nul, ou un type que Vanguard ne lit pas (date, objet) : sans valeur, jamais deviné.
            _ => Valeur::Nul,
        }
    }
}

/// Un élément d'une liste à une dimension, copié par SafeArrayGetElement. La taille d'un élément est vérifiée
/// AVANT la copie : SafeArrayGetElement en écrit `cbElements` octets dans la destination.
///
/// # Safety
/// `liste` pointe sur un SAFEARRAY vivant à une dimension, `T` est le type de ses éléments.
unsafe fn element<T: Default>(liste: *const SAFEARRAY, i: i32) -> Option<T> {
    // SAFETY : `liste` est non nul et vivant (contrat de la fonction).
    if usize::try_from(unsafe { (*liste).cbElements }).ok()? != size_of::<T>() {
        return None;
    }
    let mut x = T::default();
    // SAFETY : un seul indice pour une dimension ; la destination a exactement la taille d'un élément.
    unsafe { SafeArrayGetElement(liste, &raw const i, (&raw mut x).cast()) }.ok()?;
    Some(x)
}

/// # Safety
/// `liste` est nul ou pointe sur un SAFEARRAY vivant dont les éléments sont du type `vt`.
unsafe fn lire_liste(liste: *const SAFEARRAY, vt: VARENUM) -> Valeur {
    // SAFETY : pointeur vérifié non nul avant chaque lecture ; dimensions et bornes demandées à Windows.
    unsafe {
        if liste.is_null() || SafeArrayGetDim(liste) != 1 {
            return Valeur::Nul;
        }
        let (Ok(bas), Ok(haut)) = (SafeArrayGetLBound(liste, 1), SafeArrayGetUBound(liste, 1)) else {
            return Valeur::Nul;
        };
        let haut = haut.min(bas.saturating_add(ELEMENTS_MAX - 1));
        let mut valeurs = Vec::new();
        for i in bas..=haut {
            let v = match vt {
                VT_BSTR => element::<BSTR>(liste, i).map(|b| Valeur::Texte(b.to_string())),
                VT_BOOL => element::<VARIANT_BOOL>(liste, i).map(|b| Valeur::Booleen(b.as_bool())),
                VT_I1 => element::<i8>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_UI1 => element::<u8>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_I2 => element::<i16>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_UI2 => element::<u16>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_I4 | VT_INT => element::<i32>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_UI4 | VT_UINT => element::<u32>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_I8 => element::<i64>(liste, i).map(Valeur::Entier),
                _ => None,
            };
            valeurs.push(v.unwrap_or(Valeur::Nul));
        }
        Valeur::Liste(valeurs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valeurs_relues() {
        assert_eq!(Valeur::Texte(" 18446744 ".into()).entier(), Some(18_446_744));
        assert_eq!(Valeur::Entier(3).entier(), Some(3));
        assert_eq!(Valeur::Nul.entier(), None);
        assert_eq!(Valeur::Nul.liste(), []);
        assert_eq!(Valeur::Liste(vec![Valeur::Entier(2)]).liste(), &[Valeur::Entier(2)]);
    }

    /// Le WMI de Wine connaît Win32_OperatingSystem : la requête aboutit sans PowerShell, comme sous Windows.
    #[test]
    fn requete_reelle() {
        let lignes = requete(
            r"root\cimv2",
            "Win32_OperatingSystem",
            "",
            &["Caption", "ChampQuiNExistePas"],
        )
        .expect("WMI répond");
        assert_eq!(lignes.len(), 1);
        assert!(matches!(&lignes[0]["Caption"], Valeur::Texte(t) if !t.is_empty()));
        assert_eq!(lignes[0]["ChampQuiNExistePas"], Valeur::Nul);
    }

    /// Une classe inconnue n'est pas une liste vide : c'est « illisible », pour que l'appelant ne conclue pas.
    #[test]
    fn classe_inconnue() {
        assert!(requete(r"root\cimv2", "Classe_Qui_N_Existe_Pas", "", &["Name"]).is_none());
        assert!(requete(r"root\EspaceQuiNExistePas", "Win32_OperatingSystem", "", &["Name"]).is_none());
        // Une classe connue sans instance qui réponde : une vraie liste vide.
        assert_eq!(
            requete(
                r"root\cimv2",
                "Win32_OperatingSystem",
                "Caption = 'Pas un nom de Windows'",
                &["Caption"]
            ),
            Some(Vec::new())
        );
    }
}
