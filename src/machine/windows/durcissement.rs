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

fn lire_texte(cle: &str, valeur: &str) -> Option<String> {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(cle)
        .ok()?
        .get_value(valeur)
        .ok()
}

const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

/// Ouverture de session automatique : avec `DefaultPassword`, le mot de passe est écrit en clair dans le registre,
/// lisible par tout programme qui tourne sur l'ordinateur. Sans lui (réglage par netplwiz, gardé chiffré), une
/// information : quiconque allume l'ordinateur entre dans la session.
pub(super) fn juger_ouverture_auto(auto: Option<&str>, mot_de_passe: bool) -> Option<Constat> {
    if auto.map(str::trim) != Some("1") {
        return None;
    }
    Some(if mot_de_passe {
        alerte(
            "Comptes",
            Niveau::Eleve,
            tr!(
                "Ouverture de session automatique avec le mot de passe écrit en clair dans le registre : tout programme qui tourne ici peut le lire.",
                "Automatic sign-in with the password written in clear text in the registry: any program running here can read it."
            ),
        )
        .manuel(
            tr!(
                "Touche Windows + R, « netplwiz », cocher « Les utilisateurs doivent entrer un nom et un mot de passe » ; puis retirer DefaultPassword (commande ci-dessous, en administrateur)",
                "Windows key + R, “netplwiz”, tick “Users must enter a user name and password”; then remove DefaultPassword (command below, as administrator)"
            ),
            &[r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword"],
        )
    } else {
        alerte(
            "Comptes",
            Niveau::Info,
            tr!(
                "Ouverture de session automatique : quiconque allume l'ordinateur entre dans la session, sans mot de passe.",
                "Automatic sign-in: anyone who turns the computer on gets into the session, without a password."
            ),
        )
        .manuel(
            tr!(
                "Si l'ordinateur sort de la maison : touche Windows + R, « netplwiz », cocher « Les utilisateurs doivent entrer un nom et un mot de passe »",
                "If the computer leaves the house: Windows key + R, “netplwiz”, tick “Users must enter a user name and password”"
            ),
            &[],
        )
    })
}

/// SmartScreen coupé (réglage de l'Explorateur à « Off », ou stratégie EnableSmartScreen à 0) : un programme téléchargé
/// inconnu se lance sans avertissement.
pub(super) fn juger_smartscreen(explorateur: Option<&str>, strategie: Option<u32>) -> Option<Constat> {
    let coupe = explorateur.is_some_and(|v| v.eq_ignore_ascii_case("off")) || strategie == Some(0);
    coupe.then(|| {
        alerte(
            DURCI,
            Niveau::Moyen,
            tr!(
                "SmartScreen est coupé : un programme téléchargé inconnu se lance sans le moindre avertissement.",
                "SmartScreen is off: an unknown downloaded program starts without any warning."
            ),
        )
        .manuel(
            tr!(
                "Sécurité Windows › Contrôle des applications et du navigateur › Protection fondée sur la réputation : tout activer",
                "Windows Security › App & browser control › Reputation-based protection: turn everything on"
            ),
            &["Start-Process windowsdefender://appbrowser"],
        )
    })
}

/// `LocalAccountTokenFilterPolicy` à 1 : un compte local administrateur garde tous ses droits quand il se connecte à
/// distance, ce que les attaques par « pass-the-hash » utilisent pour passer d'un ordinateur à l'autre.
pub(super) fn juger_jeton_distant(valeur: Option<u32>) -> Option<Constat> {
    (valeur == Some(1)).then(|| {
        alerte(
            DURCI,
            Niveau::Moyen,
            tr!(
                "Le contrôle de compte est désactivé pour les connexions à distance des comptes locaux : un mot de passe d'administrateur volé ouvre cet ordinateur depuis le réseau.",
                "Account control is off for remote connections of local accounts: a stolen administrator password opens this computer from the network."
            ),
        )
        .corriger(
            tr!(
                "Remettre le contrôle de compte pour les connexions à distance (un outil d'administration à distance peut en avoir besoin : il le dira)",
                "Put account control back for remote connections (a remote administration tool may need it off: it will say so)"
            ),
            &[r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy"],
        )
    })
}

/// Intégrité de la mémoire (HVCI) : bloque les pilotes modifiés ou vulnérables. Une information : quelques vieux
/// pilotes (et anti-triches) la refusent, Windows le dit alors.
pub(super) fn juger_integrite_memoire(active: Option<u32>) -> Constat {
    if active == Some(1) {
        ok(
            DURCI,
            tr!(
                "Intégrité de la mémoire active : les pilotes modifiés ou vulnérables sont bloqués.",
                "Memory integrity on: modified or vulnerable drivers are blocked."
            ),
        )
    } else {
        alerte(
            DURCI,
            Niveau::Info,
            tr!(
                "Intégrité de la mémoire inactive : un pilote vulnérable peut servir à désarmer l'antivirus.",
                "Memory integrity off: a vulnerable driver can be used to disarm the antivirus."
            ),
        )
        .manuel(
            tr!(
                "Sécurité Windows › Sécurité de l'appareil › Isolation du noyau › Intégrité de la mémoire, puis redémarrer",
                "Windows Security › Device security › Core isolation › Memory integrity, then restart"
            ),
            &["Start-Process windowsdefender://coreisolation"],
        )
    }
}

/// Mises à jour en pause : la date de fin (« 2026-11-02T… ») dans le futur.
pub(super) fn juger_pause(fin: Option<&str>, aujourd_hui: &str) -> Option<Constat> {
    let date = fin?.get(..10)?;
    (date > aujourd_hui).then(|| {
        alerte(
            "Mises à jour",
            Niveau::Info,
            trf!(
                "Les mises à jour de Windows sont en pause jusqu'au {date} : les corrections de sécurité attendent aussi.",
                "Windows updates are paused until {date}: security fixes wait too."
            ),
        )
        .manuel(
            tr!(
                "Paramètres › Windows Update › Reprendre les mises à jour",
                "Settings › Windows Update › Resume updates"
            ),
            &["Start-Process ms-settings:windowsupdate"],
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
    c.extend(juger_ouverture_auto(
        lire_texte(WINLOGON, "AutoAdminLogon").as_deref(),
        lire_texte(WINLOGON, "DefaultPassword").is_some_and(|m| !m.is_empty()),
    ));
    c.extend(juger_smartscreen(
        lire_texte(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "SmartScreenEnabled",
        )
        .as_deref(),
        lire_dword(r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen"),
    ));
    c.extend(juger_jeton_distant(lire_dword(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "LocalAccountTokenFilterPolicy",
    )));
    c.push(juger_integrite_memoire(lire_dword(
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        "Enabled",
    )));
    let aujourd_hui = chrono::Local::now().format("%Y-%m-%d").to_string();
    c.extend(juger_pause(
        lire_texte(
            r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
            "PauseUpdatesExpiryTime",
        )
        .as_deref(),
        &aujourd_hui,
    ));
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
        assert_eq!(
            juger_ouverture_auto(Some("1"), true).unwrap().probleme,
            Some(Niveau::Eleve)
        );
        assert_eq!(
            juger_ouverture_auto(Some("1"), false).unwrap().probleme,
            Some(Niveau::Info)
        );
        assert!(juger_ouverture_auto(Some("0"), true).is_none() && juger_ouverture_auto(None, false).is_none());
        assert!(juger_smartscreen(Some("Off"), None).is_some() && juger_smartscreen(None, Some(0)).is_some());
        assert!(juger_smartscreen(Some("Warn"), None).is_none() && juger_smartscreen(None, Some(1)).is_none());
        assert!(
            juger_jeton_distant(Some(1))
                .unwrap()
                .correctif
                .as_ref()
                .unwrap()
                .automatique
        );
        assert!(juger_jeton_distant(Some(0)).is_none());
        assert!(juger_integrite_memoire(Some(1)).probleme.is_none());
        assert_eq!(juger_integrite_memoire(None).probleme, Some(Niveau::Info));
        let p = juger_pause(Some("2026-11-02T09:00:00Z"), "2026-10-19").unwrap();
        assert!(p.message.contains("2026-11-02"));
        assert!(
            juger_pause(Some("2026-10-01T09:00:00Z"), "2026-10-19").is_none()
                && juger_pause(None, "2026-10-19").is_none()
        );
    }
}
