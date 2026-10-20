//! Les tâches planifiées lues par le planificateur de Windows lui-même (ITaskService, COM), au lieu de
//! Get-ScheduledTask : quelques millisecondes là où PowerShell prend une à plusieurs secondes.

use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::TaskScheduler::{
    IExecAction, ITaskFolder, ITaskService, TASK_ACTION_EXEC, TASK_ACTION_TYPE, TASK_ENUM_HIDDEN, TASK_STATE_DISABLED,
    TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface};

use super::wmi;

/// Plus de dossiers qu'un vrai planificateur n'en a : au-delà, la lecture est refusée plutôt que laissée à moitié.
const DOSSIERS_MAX: usize = 10_000;

/// Les tâches qui ne sont pas désactivées, hors \Microsoft\ (celles de Windows), cachées comprises : une ligne
/// « dossier|nom|programme|arguments » par action qui lance un programme, comme la section TCH du script
/// PowerShell (le dossier finit par « \ », comme TaskPath). `None` si le planificateur ne répond pas ou refuse une
/// lecture : PowerShell prend le relais, jamais une liste partielle qui passerait pour saine. Même chose sans le
/// dossier \Microsoft, que tout Windows a : un planificateur qui ne le montre pas ne montre rien (celui de Wine rend
/// des listes vides sans erreur, GetTasks n'y étant qu'une ébauche).
pub(super) fn taches() -> Option<Vec<String>> {
    wmi::com("Tâches planifiées", "ITaskService", lire)
}

fn hors_windows(dossier: &str) -> bool {
    let bas = dossier.to_ascii_lowercase();
    bas != r"\microsoft" && !bas.starts_with(r"\microsoft\")
}

fn lire() -> windows::core::Result<Vec<String>> {
    // SAFETY : COM est initialisé dans ce fil (par `wmi::com`) ; TaskScheduler est la classe du planificateur.
    let service: ITaskService = unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }?;
    let vide = VARIANT::default();
    // SAFETY : VARIANT vides = cet ordinateur, le compte qui lance.
    unsafe { service.Connect(&vide, &vide, &vide, &vide) }?;
    // SAFETY : service connecté ; chemin BSTR valide pendant l'appel.
    let racine = unsafe { service.GetFolder(&BSTR::from(r"\")) }?;
    let mut lignes = Vec::new();
    let mut a_lire: Vec<ITaskFolder> = vec![racine];
    let mut lus = 0;
    let mut dossier_de_windows = false;
    while let Some(dossier) = a_lire.pop() {
        lus += 1;
        if lus > DOSSIERS_MAX {
            return Err(windows::core::Error::empty());
        }
        // SAFETY : dossier est une interface vivante rendue par le planificateur.
        let chemin = unsafe { dossier.Path() }?.to_string();
        if !hors_windows(&chemin) {
            dossier_de_windows = true;
            continue;
        }
        let prefixe = if chemin.ends_with('\\') {
            chemin
        } else {
            format!("{chemin}\\")
        };
        // SAFETY : dossier vivant ; les collections sont indexées de 1 à Count, bornes lues avant chaque accès.
        unsafe {
            let taches = dossier.GetTasks(TASK_ENUM_HIDDEN.0)?;
            for i in 1..=taches.Count()? {
                let tache = taches.get_Item(&wmi::variant_entier(i))?;
                if tache.State()? == TASK_STATE_DISABLED {
                    continue;
                }
                let nom = tache.Name()?;
                let actions = tache.Definition()?.Actions()?;
                let mut nombre = 0;
                actions.Count(&raw mut nombre)?;
                for j in 1..=nombre {
                    let action = actions.get_Item(j)?;
                    let mut genre = TASK_ACTION_TYPE::default();
                    action.Type(&raw mut genre)?;
                    if genre != TASK_ACTION_EXEC {
                        continue;
                    }
                    let lancement: IExecAction = action.cast()?;
                    let (mut programme, mut arguments) = (BSTR::new(), BSTR::new());
                    lancement.Path(&raw mut programme)?;
                    lancement.Arguments(&raw mut arguments)?;
                    // Comme le `Where-Object { $_.Execute }` du script : une action sans programme ne lance rien.
                    if !programme.is_empty() {
                        lignes.push(format!("{prefixe}|{nom}|{programme}|{arguments}"));
                    }
                }
            }
            let sous = dossier.GetFolders(0)?;
            for i in 1..=sous.Count()? {
                a_lire.push(sous.get_Item(&wmi::variant_entier(i))?);
            }
        }
    }
    if !dossier_de_windows {
        return Err(windows::core::Error::empty());
    }
    Ok(lignes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dossiers_de_windows_ecartes() {
        assert!(hors_windows(r"\"));
        assert!(hors_windows(r"\Mozilla"));
        assert!(hors_windows(r"\MicrosoftEdgeUpdate"));
        assert!(!hors_windows(r"\Microsoft"));
        assert!(!hors_windows(r"\microsoft\Windows\Defrag"));
    }

    /// Sous Wine, sans dossier \Microsoft (GetTasks n'y est qu'une ébauche) : aucune réponse plutôt qu'une liste
    /// vide. Ailleurs (vrai Windows de la CI), des lignes à quatre champs.
    #[test]
    fn lecture_reelle() {
        let wine = std::path::Path::new(r"C:\windows\system32\wineboot.exe").is_file();
        let lu = taches();
        assert!(!wine || lu.is_none(), "{lu:?}");
        if let Some(lignes) = lu {
            assert!(lignes.iter().all(|l| l.splitn(4, '|').count() == 4));
        }
    }
}
