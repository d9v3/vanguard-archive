//! Durcissement de Windows : ce qui livre les mots de passe ou ouvre une porte, au-delà du pare-feu et de l'antivirus.
//! WDigest qui garde les mots de passe en clair dans la mémoire (ce qu'un voleur de mots de passe lit), la protection
//! de l'autorité de sécurité locale (LSA) qui protège ces secrets, PowerShell 2.0 qui échappe à l'antivirus et aux
//! journaux, et l'Assistance à distance, la porte des faux techniciens. Le registre se lit sans droits
//! administrateur ; PowerShell 2.0, par WMI.

use super::*;

const DURCI: &str = "Durcissement";
const WDIGEST: &str = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";

fn lire_dword(cle: &str, valeur: &str) -> Option<u32> {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(cle)
        .ok()?
        .get_value(valeur)
        .ok()
}

/// WDigest : `UseLogonCredential` à 1 garde chaque mot de passe en clair dans la mémoire de LSASS.
pub(super) fn juger_wdigest(valeur: Option<u32>) -> Constat {
    if valeur == Some(1) {
        alerte(
            DURCI,
            Niveau::Eleve,
            tr!(
                "WDigest garde les mots de passe en clair dans la mémoire : un voleur de mots de passe (Mimikatz et ses copies) les lit tels quels.",
                "WDigest keeps passwords in clear text in memory: a password stealer (Mimikatz and its copies) reads them as they are."
            ),
        )
        .corriger(
            tr!(
                "Couper WDigest (valeur par défaut depuis Windows 8.1 ; effet à la prochaine ouverture de session)",
                "Turn WDigest off (the default since Windows 8.1; takes effect at the next sign-in)"
            ),
            &[&format!(
                "Set-ItemProperty -LiteralPath 'HKLM:\\{WDIGEST}' -Name UseLogonCredential -Value 0 -Type DWord"
            )],
        )
    } else {
        ok(
            DURCI,
            tr!(
                "WDigest ne garde pas les mots de passe en clair dans la mémoire.",
                "WDigest does not keep passwords in clear text in memory."
            ),
        )
    }
}

/// Protection LSA : `RunAsPPL` à 1 ou 2 (2 : sans verrou UEFI). Absente : une information, à activer soi-même (un
/// pilote ancien peut la refuser, Windows le dit alors).
pub(super) fn juger_lsa(valeur: Option<u32>) -> Constat {
    if matches!(valeur, Some(1 | 2)) {
        ok(
            DURCI,
            tr!(
                "Protection de l'autorité de sécurité locale (LSA) active : les secrets de connexion sont protégés.",
                "Local Security Authority (LSA) protection on: sign-in secrets are protected."
            ),
        )
    } else {
        alerte(
            DURCI,
            Niveau::Info,
            tr!(
                "Protection de l'autorité de sécurité locale (LSA) inactive : un programme avec les droits administrateur peut lire les secrets de connexion.",
                "Local Security Authority (LSA) protection off: a program with administrator rights can read sign-in secrets."
            ),
        )
        .manuel(
            tr!(
                "Sécurité Windows › Sécurité de l'appareil › Isolation du noyau › Protection de l'autorité de sécurité locale, puis redémarrer",
                "Windows Security › Device security › Core isolation › Local Security Authority protection, then restart"
            ),
            &["Start-Process windowsdefender://coreisolation"],
        )
    }
}

/// PowerShell 2.0 : `InstallState` du composant (1 : installé). Il ne passe ni par AMSI (l'antivirus) ni par les
/// journaux de scripts : les attaques le rappellent exprès.
pub(super) fn juger_powershell2(installe: Option<bool>) -> Option<Constat> {
    Some(if installe? {
        alerte(
            DURCI,
            Niveau::Moyen,
            tr!(
                "PowerShell 2.0 est encore installé : cette vieille version échappe à l'antivirus et aux journaux, les attaques s'en servent exprès.",
                "PowerShell 2.0 is still installed: this old version escapes the antivirus and the logs, attacks use it on purpose."
            ),
        )
        .corriger(
            tr!(
                "Retirer PowerShell 2.0 (les versions actuelles restent ; remis par « Activer ou désactiver des fonctionnalités Windows »)",
                "Remove PowerShell 2.0 (the current versions stay; put back through “Turn Windows features on or off”)"
            ),
            &["Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null"],
        )
    } else {
        ok(
            DURCI,
            tr!("PowerShell 2.0 n'est pas installé.", "PowerShell 2.0 is not installed."),
        )
    })
}

/// Assistance à distance (`fAllowToGetHelp`) : une information, à couper soi-même (couper ici pourrait interrompre
/// une assistance en cours, et Gardien ne coupe jamais une connexion à distance).
pub(super) fn juger_assistance(valeur: Option<u32>) -> Option<Constat> {
    (valeur == Some(1)).then(|| {
        alerte(
            "Accès à distance",
            Niveau::Info,
            tr!(
                "L'Assistance à distance de Windows accepte les invitations : c'est l'outil que les faux techniciens demandent d'ouvrir.",
                "Windows Remote Assistance accepts invitations: it is the tool fake technicians ask you to open."
            ),
        )
        .manuel(
            tr!(
                "Si personne ne t'aide ainsi : Panneau de configuration › Système › Paramètres d'utilisation à distance, décocher « Autoriser les connexions d'assistance à distance »",
                "If nobody helps you this way: Control Panel › System › Remote settings, untick “Allow Remote Assistance connections”"
            ),
            &["Start-Process SystemPropertiesRemote.exe"],
        )
    })
}

pub(super) fn durcissement() -> Vec<Constat> {
    let mut c = vec![
        juger_wdigest(lire_dword(WDIGEST, "UseLogonCredential")),
        juger_lsa(lire_dword(r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")),
    ];
    let ps2 = ps(
        "try { 'PS2|' + (Get-CimInstance Win32_OptionalFeature -Filter \"Name='MicrosoftWindowsPowerShellV2Root'\").InstallState; 'PS2_FIN' } catch {}",
    );
    let installe = section(ps2.as_deref(), "PS2")
        .and_then(|l| l.first().map(|v| v.trim().to_string()))
        .and_then(|v| match v.as_str() {
            "1" => Some(true),
            "2" | "3" => Some(false),
            _ => None,
        });
    c.extend(juger_powershell2(installe));
    c.extend(juger_assistance(lire_dword(
        r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
        "fAllowToGetHelp",
    )));
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durcissement_juge() {
        let w = juger_wdigest(Some(1));
        assert_eq!(w.probleme, Some(Niveau::Eleve));
        assert!(w.correctif.as_ref().unwrap().commandes[0].contains("UseLogonCredential -Value 0"));
        assert!(juger_wdigest(None).probleme.is_none() && juger_wdigest(Some(0)).probleme.is_none());
        assert!(juger_lsa(Some(2)).probleme.is_none());
        assert_eq!(juger_lsa(None).probleme, Some(Niveau::Info));
        assert_eq!(juger_powershell2(Some(true)).unwrap().probleme, Some(Niveau::Moyen));
        assert!(juger_powershell2(Some(false)).unwrap().probleme.is_none());
        assert!(juger_powershell2(None).is_none());
        let a = juger_assistance(Some(1)).unwrap();
        assert!(!a.correctif.as_ref().unwrap().automatique);
        assert!(juger_assistance(Some(0)).is_none() && juger_assistance(None).is_none());
    }
}
