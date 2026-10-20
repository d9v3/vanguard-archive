//! L'état d'un service Windows, lu auprès du gestionnaire de services (advapi32) sans PowerShell : ce que
//! `(Get-Service <nom>).Status` donnait, avec les mêmes mots.

use std::ffi::c_void;

#[repr(C)]
#[derive(Default)]
struct EtatDuService {
    sorte: u32,
    etat: u32,
    acceptes: u32,
    code: u32,
    code_du_service: u32,
    etape: u32,
    attente: u32,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenSCManagerW(machine: *const u16, base: *const u16, acces: u32) -> *mut c_void;
    fn OpenServiceW(gestionnaire: *mut c_void, nom: *const u16, acces: u32) -> *mut c_void;
    fn QueryServiceStatus(service: *mut c_void, etat: *mut EtatDuService) -> i32;
    fn CloseServiceHandle(objet: *mut c_void) -> i32;
}

/// Ce qu'un service répond.
#[derive(Debug, PartialEq)]
pub(crate) enum Service {
    /// Son état, dans les mots de Get-Service (« Running », « Stopped »…).
    Etat(&'static str),
    /// Le service n'existe pas sur cette machine.
    Absent,
}

/// L'état du service ; `None` si le gestionnaire de services ne répond pas (l'appelant ne conclut pas).
pub(crate) fn etat(nom: &str) -> Option<Service> {
    const CONNEXION: u32 = 0x1;
    const LIRE_L_ETAT: u32 = 0x4;
    const INTROUVABLE: i32 = 1060;
    let large: Vec<u16> = nom.encode_utf16().chain([0]).collect();
    // SAFETY : le nom est terminé par un zéro et vit pendant l'appel ; chaque poignée obtenue (nulle : refus, vérifié)
    // est fermée une seule fois ; la structure a la forme de SERVICE_STATUS (sept u32).
    unsafe {
        let gestionnaire = OpenSCManagerW(std::ptr::null(), std::ptr::null(), CONNEXION);
        if gestionnaire.is_null() {
            return None;
        }
        let service = OpenServiceW(gestionnaire, large.as_ptr(), LIRE_L_ETAT);
        let reponse = if service.is_null() {
            (std::io::Error::last_os_error().raw_os_error() == Some(INTROUVABLE)).then_some(Service::Absent)
        } else {
            let mut e = EtatDuService::default();
            let lu = QueryServiceStatus(service, &raw mut e) != 0;
            CloseServiceHandle(service);
            lu.then(|| Service::Etat(mot(e.etat)))
        };
        CloseServiceHandle(gestionnaire);
        reponse
    }
}

/// Le mot de Get-Service pour un état de SERVICE_STATUS.
fn mot(etat: u32) -> &'static str {
    match etat {
        1 => "Stopped",
        2 => "StartPending",
        3 => "StopPending",
        4 => "Running",
        5 => "ContinuePending",
        6 => "PausePending",
        7 => "Paused",
        _ => "Unknown",
    }
}

/// Comme `"$((Get-Service <nom>).Status)"` : le mot de l'état, vide si le service n'existe pas.
pub(crate) fn statut(nom: &str) -> Option<&'static str> {
    Some(match etat(nom)? {
        Service::Etat(m) => m,
        Service::Absent => "",
    })
}

/// Un service Win32 inscrit dans le registre, avec ce que Win32_Service en montrait.
pub(crate) struct Inscrit {
    pub nom: String,
    /// Dans les mots de Win32_Service (« Running », « Stopped », « Start Pending »…) ; vide s'il ne se lit pas.
    pub etat: &'static str,
    /// « Boot », « System », « Auto », « Manual », « Disabled ».
    pub demarrage: &'static str,
    /// Le compte du service (ObjectName : « LocalSystem », « NT AUTHORITY\LocalService »…).
    pub compte: String,
    /// La ligne lancée (ImagePath), telle qu'inscrite.
    pub programme: String,
}

/// Les services Win32 (ni pilotes ni systèmes de fichiers) inscrits sous `HKLM\SYSTEM\CurrentControlSet\Services`,
/// avec leur état ; `None` si la clé ne s'ouvre pas.
pub(crate) fn inscrits() -> Option<Vec<Inscrit>> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    const SERVICE_WIN32: u32 = 0x30;
    let services = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Services")
        .ok()?;
    Some(
        services
            .enum_keys()
            .flatten()
            .filter_map(|nom| {
                let cle = services.open_subkey(&nom).ok()?;
                if cle.get_value::<u32, _>("Type").ok()? & SERVICE_WIN32 == 0 {
                    return None;
                }
                let texte = |v: &str| cle.get_value::<String, _>(v).unwrap_or_default();
                let demarrage = match cle.get_value::<u32, _>("Start").unwrap_or(u32::MAX) {
                    0 => "Boot",
                    1 => "System",
                    2 => "Auto",
                    3 => "Manual",
                    4 => "Disabled",
                    _ => "Unknown",
                };
                let etat = match etat(&nom) {
                    Some(Service::Etat(m)) => mot_wmi(m),
                    _ => "",
                };
                Some(Inscrit {
                    etat,
                    demarrage,
                    compte: texte("ObjectName"),
                    programme: texte("ImagePath"),
                    nom,
                })
            })
            .collect(),
    )
}

/// Le mot de Win32_Service pour celui de Get-Service (« StartPending » → « Start Pending »).
fn mot_wmi(mot: &'static str) -> &'static str {
    match mot {
        "StartPending" => "Start Pending",
        "StopPending" => "Stop Pending",
        "ContinuePending" => "Continue Pending",
        "PausePending" => "Pause Pending",
        autre => autre,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mots_de_get_service() {
        assert_eq!(mot(4), "Running");
        assert_eq!(mot(1), "Stopped");
        assert_eq!(mot(0), "Unknown");
    }

    /// Le vrai gestionnaire de services (Wine ici, la VM ensuite) : un service inventé est absent, et la réponse pour
    /// un vrai service est un mot de Get-Service.
    #[test]
    fn services_lus_par_windows() {
        if let Some(e) = etat("VanguardServiceInexistant") {
            assert_eq!(e, Service::Absent);
        }
        let _ = statut("Spooler");
        assert!(inscrits().expect("clé des services").iter().all(|s| !s.nom.is_empty()));
        assert_eq!(mot_wmi("StartPending"), "Start Pending");
    }
}
