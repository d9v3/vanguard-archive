//! Programmes installés, lus dans le registre (winreg) sans PowerShell : les noms du panneau « Applications
//! installées » (clés Uninstall), ceux des applications du Store et la présence de winget. Mêmes listes que
//! `Get-ItemProperty …\Uninstall\*`, `Get-AppxPackage` et `Get-Command winget`, en quelques millisecondes.

use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const UNINSTALL_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
/// Les paquets du Store installés pour ce compte (ce que Get-AppxPackage liste sans -AllUsers).
const PAQUETS: &str =
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

/// Les noms affichés (DisplayName) des programmes installés pour la machine (64 et 32 bits) et pour ce compte.
/// `None` si la clé Uninstall de la machine ne s'ouvre pas : l'appelant demande alors à PowerShell.
pub(crate) fn noms() -> Option<Vec<String>> {
    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let principale = machine.open_subkey(UNINSTALL).ok()?;
    let mut noms = noms_de(&principale);
    for cle in [
        machine.open_subkey(UNINSTALL_32),
        RegKey::predef(HKEY_CURRENT_USER).open_subkey(UNINSTALL),
    ]
    .into_iter()
    .flatten()
    {
        noms.extend(noms_de(&cle));
    }
    Some(noms)
}

fn noms_de(cle: &RegKey) -> Vec<String> {
    cle.enum_keys()
        .flatten()
        .filter_map(|sous| cle.open_subkey(sous).ok()?.get_value::<String, _>("DisplayName").ok())
        .filter(|n| !n.is_empty())
        .collect()
}

/// Les noms des paquets du Store de ce compte (« Microsoft.WindowsTerminal »), tirés de leur nom complet.
pub(crate) fn paquets_store() -> Vec<String> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(PAQUETS)
        .map(|cle| {
            cle.enum_keys()
                .flatten()
                .filter_map(|complet| nom_du_paquet(&complet))
                .collect()
        })
        .unwrap_or_default()
}

/// « Microsoft.WindowsTerminal_1.21.3231.0_x64__8wekyb3d8bbwe » → « Microsoft.WindowsTerminal » : le nom d'un paquet
/// ne contient jamais « _ » (lettres, chiffres, points et tirets), qui sépare les parties du nom complet.
pub(crate) fn nom_du_paquet(complet: &str) -> Option<String> {
    let (nom, reste) = complet.split_once('_')?;
    (!nom.is_empty() && !reste.is_empty()).then(|| nom.to_string())
}

/// winget trouvable par son nom, comme `Get-Command winget` : un fichier « winget » + une extension de PATHEXT dans
/// un dossier du PATH. Celui du Store est un alias d'exécution (point d'analyse) : son entrée se lit sans le suivre.
pub(crate) fn winget_present() -> bool {
    let extensions = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).any(|d| {
        extensions
            .split(';')
            .filter(|e| !e.is_empty())
            .any(|e| std::fs::symlink_metadata(d.join(format!("winget{}", e.to_lowercase()))).is_ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_des_paquets() {
        assert_eq!(
            nom_du_paquet("Microsoft.WindowsTerminal_1.21.3231.0_x64__8wekyb3d8bbwe").as_deref(),
            Some("Microsoft.WindowsTerminal")
        );
        assert_eq!(nom_du_paquet("sans-separateur"), None);
        assert_eq!(nom_du_paquet("_1.0_x64__abc"), None);
        assert_eq!(nom_du_paquet("Nom_"), None);
    }

    /// Le vrai registre (Wine ici, la VM ensuite), en lecture seule : la clé Uninstall de la machine s'ouvre et chaque
    /// nom lu est un vrai nom.
    #[test]
    fn programmes_lus_dans_le_registre() {
        let noms = noms().expect("clé Uninstall de la machine");
        assert!(noms.iter().all(|n| !n.is_empty()), "{noms:?}");
        assert!(paquets_store().iter().all(|p| !p.contains('_')));
    }
}
