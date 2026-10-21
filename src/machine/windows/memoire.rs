//! La mémoire des processus de Windows, lue et jamais écrite (VirtualQueryEx, ReadProcessMemory), pour le scan YARA
//! de la mémoire (`protection::memoire`). Un processus protégé (LSASS, antivirus, tout PPL) n'est jamais ouvert en
//! lecture : son niveau se lit d'abord avec les seuls droits « limités », et tout niveau autre que « aucun » l'exclut,
//! comme un niveau qui ne se lit pas. Jamais d'écriture, d'injection, de suspension, de MiniDump ni de
//! SeDebugPrivilege : lire la mémoire d'autrui ressemble déjà assez à un vol d'identifiants pour ne rien y ajouter.
//! Le dossier System32 est lu ici aussi : un processus au nom critique n'est écarté que si son programme y est.

use std::ffi::c_void;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessInformation, OpenProcess, PROCESS_PROTECTION_LEVEL_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ, PROTECTION_LEVEL_NONE, ProcessProtectionLevelInfo,
};

use crate::protection::memoire::{Region, region_windows};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualQueryEx(
        processus: *mut c_void,
        adresse: *const c_void,
        information: *mut Information,
        taille: usize,
    ) -> usize;
    fn ReadProcessMemory(
        processus: *mut c_void,
        adresse: *const c_void,
        tampon: *mut c_void,
        taille: usize,
        lus: *mut usize,
    ) -> i32;
    fn GetSystemDirectoryW(tampon: *mut u16, taille: u32) -> u32;
}

/// MEMORY_BASIC_INFORMATION (winnt.h), telle que VirtualQueryEx la remplit sur x86_64.
#[repr(C)]
struct Information {
    base: *mut c_void,
    base_allocation: *mut c_void,
    protection_allocation: u32,
    partition: u16,
    taille: usize,
    etat: u32,
    protection: u32,
    sorte: u32,
}

/// Le niveau de protection d'un processus, lu avec les seuls droits « limités » : `Some(true)` protégé (PPL, LSA,
/// antimalware…), `Some(false)` aucun. `None` : le processus ne s'ouvre pas (autre compte, sans élévation) ou Windows
/// ne dit pas son niveau (avant 8.1) ; dans les deux cas, il n'est pas lu.
pub(crate) fn protege(pid: u32) -> Option<bool> {
    // SAFETY : la poignée vient d'OpenProcess (Err : refus) et est refermée une seule fois ; la structure reçue a la
    // taille annoncée à Windows, qui n'écrit rien au-delà.
    unsafe {
        let poignee = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut niveau = PROCESS_PROTECTION_LEVEL_INFORMATION::default();
        let lu = GetProcessInformation(
            poignee,
            ProcessProtectionLevelInfo,
            (&raw mut niveau).cast(),
            u32::try_from(size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>()).unwrap_or(0),
        )
        .is_ok();
        let _ = CloseHandle(poignee);
        lu.then(|| niveau.ProtectionLevel != PROTECTION_LEVEL_NONE)
    }
}

/// Le dossier System32 de ce Windows (« C:\WINDOWS\system32 »), tel que Windows le donne : pas la variable
/// SystemRoot, que choisit le programme qui lance Vanguard, ni un chemin écrit en dur. `None` s'il ne se lit pas.
pub(crate) fn system32() -> Option<String> {
    let mut tampon = [0u16; 1024];
    let taille = u32::try_from(tampon.len()).ok()?;
    // SAFETY : le tampon fait `taille` caractères ; GetSystemDirectoryW n'écrit pas au-delà et rend le nombre écrit
    // (sans le zéro final), la taille qu'il lui faudrait s'il est trop petit, ou 0 en cas d'échec.
    let ecrits = unsafe { GetSystemDirectoryW(tampon.as_mut_ptr(), taille) };
    let ecrits = usize::try_from(ecrits).ok()?;
    (ecrits > 0 && ecrits < tampon.len()).then(|| String::from_utf16_lossy(&tampon[..ecrits]))
}

/// Un processus ouvert pour lire sa mémoire, et rien d'autre (PROCESS_VM_READ) ; refermé avec lui.
pub(crate) struct Lecteur(HANDLE);

impl Lecteur {
    /// `None` : Windows refuse (autre compte sans élévation, processus protégé).
    pub(crate) fn ouvrir(pid: u32) -> Option<Lecteur> {
        // SAFETY : OpenProcess rend une poignée valide ou Err ; elle est refermée par `Drop`, une seule fois.
        unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid)
                .ok()
                .map(Lecteur)
        }
    }

    /// Les régions retenues (`region_windows`), parcourues depuis l'adresse 0 jusqu'à ce que VirtualQueryEx n'ait plus
    /// rien à dire.
    pub(crate) fn regions(&self) -> Vec<Region> {
        let mut liste = Vec::new();
        let mut adresse: usize = 0;
        loop {
            // SAFETY : `information` est une MEMORY_BASIC_INFORMATION de la taille annoncée, que VirtualQueryEx
            // remplit entièrement quand il rend autre chose que 0 ; la poignée est valide tant que `self` vit.
            let (rendu, information) = unsafe {
                let mut information: Information = std::mem::zeroed();
                let rendu = VirtualQueryEx(
                    self.0.0,
                    std::ptr::with_exposed_provenance(adresse),
                    &raw mut information,
                    size_of::<Information>(),
                );
                (rendu, information)
            };
            if rendu == 0 {
                break;
            }
            let base = information.base as usize;
            if region_windows(information.etat, information.protection, information.sorte) {
                liste.push(Region {
                    debut: base as u64,
                    taille: information.taille as u64,
                });
            }
            match base.checked_add(information.taille) {
                Some(suivante) if suivante > adresse => adresse = suivante,
                _ => break,
            }
        }
        liste
    }

    /// Lit le début d'une région dans `zone` (de sa taille, prise dans un tampon qui ne grandit jamais) et rend le
    /// nombre d'octets lus : 0 si rien n'a pu l'être (région disparue ou changée entre-temps). Une lecture partielle
    /// est gardée telle quelle : ce qui est lu est analysé.
    pub(crate) fn lire(&self, region: &Region, zone: &mut [u8]) -> usize {
        let Ok(debut) = usize::try_from(region.debut) else {
            return 0;
        };
        let mut lus = 0usize;
        // SAFETY : `zone` est une tranche à nous de `zone.len()` octets, la taille passée à ReadProcessMemory, qui
        // n'écrit pas au-delà et rend le nombre écrit ; la poignée est valide tant que `self` vit.
        unsafe {
            ReadProcessMemory(
                self.0.0,
                std::ptr::with_exposed_provenance(debut),
                zone.as_mut_ptr().cast(),
                zone.len(),
                &raw mut lus,
            );
        }
        lus.min(zone.len())
    }
}

impl Drop for Lecteur {
    fn drop(&mut self) {
        // SAFETY : la poignée vient d'OpenProcess et n'est refermée qu'ici.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
