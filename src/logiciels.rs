//! Logiciels essentiels : préparer un ordinateur neuf (ou celui d'un ami) en quelques choix. Chaque logiciel est
//! montré installé ou à faire, puis installé seulement après accord. Linux : paquets de la distribution, ou Flatpak
//! quand elle n'en a pas ; Windows : winget.

use crate::gaming::{Element, element, proposer};
use crate::ui::*;

/// Un logiciel : nom, à quoi il sert, et comment l'installer sur chaque système.
struct Logiciel {
    nom: &'static str,
    role: (&'static str, &'static str),
    /// Paquets pour pacman, apt, dnf, zypper (vide : pas dans la distribution, voir `flatpak`).
    #[cfg_attr(windows, allow(dead_code))]
    paquets: [&'static [&'static str]; 4],
    /// Identifiant Flathub, quand la distribution n'a pas le logiciel.
    #[cfg_attr(windows, allow(dead_code))]
    flatpak: Option<&'static str>,
    /// Identifiant winget, et un bout du nom affiché dans « Applications installées » pour le reconnaître.
    #[cfg_attr(not(windows), allow(dead_code))]
    winget: Option<(&'static str, &'static str)>,
}

const LOGICIELS: &[Logiciel] = &[
    Logiciel {
        nom: "Firefox",
        role: (
            "Navigateur web, respectueux de la vie privée.",
            "Web browser, privacy-friendly.",
        ),
        paquets: [&["firefox"], &["firefox-esr"], &["firefox"], &["MozillaFirefox"]],
        flatpak: Some("org.mozilla.firefox"),
        winget: Some(("Mozilla.Firefox", "Mozilla Firefox")),
    },
    Logiciel {
        nom: "Google Chrome",
        role: ("Navigateur web de Google.", "Google's web browser."),
        paquets: [&[], &[], &[], &[]],
        flatpak: Some("com.google.Chrome"),
        winget: Some(("Google.Chrome", "Google Chrome")),
    },
    Logiciel {
        nom: "VLC",
        role: (
            "Lit toutes les vidéos et musiques.",
            "Plays every video and music file.",
        ),
        paquets: [&["vlc"], &["vlc"], &["vlc"], &["vlc"]],
        flatpak: Some("org.videolan.VLC"),
        winget: Some(("VideoLAN.VLC", "VLC media player")),
    },
    Logiciel {
        nom: "7-Zip",
        role: (
            "Ouvre et crée les archives (zip, 7z, rar…).",
            "Opens and creates archives (zip, 7z, rar…).",
        ),
        paquets: [&["7zip"], &["7zip"], &["p7zip", "p7zip-plugins"], &["7zip"]],
        flatpak: None,
        winget: Some(("7zip.7zip", "7-Zip")),
    },
    Logiciel {
        nom: "LibreOffice",
        role: (
            "Traitement de texte, tableur, présentations.",
            "Word processor, spreadsheet, presentations.",
        ),
        paquets: [
            &["libreoffice-fresh"],
            &["libreoffice"],
            &["libreoffice"],
            &["libreoffice"],
        ],
        flatpak: Some("org.libreoffice.LibreOffice"),
        winget: Some(("TheDocumentFoundation.LibreOffice", "LibreOffice")),
    },
    Logiciel {
        nom: "Bitwarden",
        role: (
            "Gestionnaire de mots de passe : un mot de passe différent par site.",
            "Password manager: a different password for each site.",
        ),
        paquets: [&["bitwarden"], &[], &[], &[]],
        flatpak: Some("com.bitwarden.desktop"),
        winget: Some(("Bitwarden.Bitwarden", "Bitwarden")),
    },
    Logiciel {
        nom: "Thunderbird",
        role: ("Courriel et agenda.", "Email and calendar."),
        paquets: [
            &["thunderbird"],
            &["thunderbird"],
            &["thunderbird"],
            &["MozillaThunderbird"],
        ],
        flatpak: Some("org.mozilla.Thunderbird"),
        winget: Some(("Mozilla.Thunderbird", "Mozilla Thunderbird")),
    },
    Logiciel {
        nom: "Discord",
        role: (
            "Discussion écrite et vocale (jeux, amis).",
            "Text and voice chat (games, friends).",
        ),
        paquets: [&["discord"], &[], &[], &[]],
        flatpak: Some("com.discordapp.Discord"),
        winget: Some(("Discord.Discord", "Discord")),
    },
    Logiciel {
        nom: "OBS Studio",
        role: (
            "Enregistrer l'écran et diffuser en direct.",
            "Record the screen and stream live.",
        ),
        paquets: [&["obs-studio"], &["obs-studio"], &["obs-studio"], &["obs-studio"]],
        flatpak: Some("com.obsproject.Studio"),
        winget: Some(("OBSProject.OBSStudio", "OBS Studio")),
    },
    Logiciel {
        nom: "GIMP",
        role: ("Retouche d'images.", "Image editing."),
        paquets: [&["gimp"], &["gimp"], &["gimp"], &["gimp"]],
        flatpak: Some("org.gimp.GIMP"),
        winget: None,
    },
    Logiciel {
        nom: "Notepad++",
        role: ("Éditeur de texte léger.", "Lightweight text editor."),
        paquets: [&[], &[], &[], &[]],
        flatpak: None,
        winget: Some(("Notepad++.Notepad++", "Notepad++")),
    },
    Logiciel {
        nom: "PowerToys",
        role: (
            "Outils pratiques de Microsoft (raccourcis, fenêtres, couleurs…).",
            "Handy Microsoft tools (shortcuts, windows, colors…).",
        ),
        paquets: [&[], &[], &[], &[]],
        flatpak: None,
        winget: Some(("Microsoft.PowerToys", "PowerToys")),
    },
];

fn role(l: &Logiciel) -> &'static str {
    if crate::langue::anglais() { l.role.1 } else { l.role.0 }
}

#[cfg(target_os = "linux")]
fn liste() -> Option<Vec<Element>> {
    use crate::gaming::linux::{flatpak_installe, installer_flatpak, installes, present};
    use crate::machine::linux::Paquets;
    let gestion = Paquets::detecter()?;
    let rang = match gestion {
        Paquets::Pacman => 0,
        Paquets::Apt => 1,
        Paquets::Dnf => 2,
        Paquets::Zypper => 3,
    };
    let flatpak = present("flatpak");
    let mut l = Vec::new();
    // Debian n'a que firefox-esr ; Ubuntu et ses dérivées ont firefox.
    let ubuntu = gestion == Paquets::Apt && crate::machine::linux::famille_ubuntu();
    for lo in LOGICIELS {
        let paquets: &[&str] = if ubuntu && lo.paquets[rang] == ["firefox-esr"] {
            &["firefox"]
        } else {
            lo.paquets[rang]
        };
        if !paquets.is_empty() {
            let fait = installes(gestion, paquets) || lo.flatpak.is_some_and(|id| flatpak && flatpak_installe(id));
            l.push(element(
                lo.nom,
                role(lo),
                Some(fait),
                vec![gestion.installer(&paquets.join(" "))],
            ));
        } else if let Some(id) = lo.flatpak.filter(|_| flatpak) {
            l.push(element(
                format!("{} (Flatpak)", lo.nom),
                role(lo),
                Some(flatpak_installe(id)),
                installer_flatpak(id),
            ));
        }
    }
    Some(l)
}

#[cfg(windows)]
fn liste() -> Option<Vec<Element>> {
    // Noms des programmes installés, lus une fois (panneau « Applications installées »).
    let noms = crate::machine::windows::ps(
        r"Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ }",
    )?;
    Some(
        LOGICIELS
            .iter()
            .filter_map(|lo| {
                let (id, motif) = lo.winget?;
                Some(element(
                    lo.nom,
                    role(lo),
                    Some(noms.lines().any(|n| n.contains(motif))),
                    vec![format!(
                        "winget install --id {id} --exact --silent --accept-package-agreements --accept-source-agreements"
                    )],
                ))
            })
            .collect(),
    )
}

/// « sentinel logiciels » : choisir et installer les logiciels essentiels.
pub fn menu() {
    trp!(
        "  {GRIS}Lecture des logiciels installés…{RESET}",
        "  {GRIS}Reading installed software…{RESET}"
    );
    match liste() {
        Some(l) if !l.is_empty() => proposer(tr!("Logiciels essentiels", "Essential software"), &l),
        _ => trp!(
            "  ✖ Impossible de lire les logiciels installés (gestionnaire de paquets non reconnu ou PowerShell bloqué).",
            "  ✖ Could not read installed software (package manager not recognized or PowerShell blocked)."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaque_logiciel_s_installe_quelque_part() {
        for l in LOGICIELS {
            let linux = l.paquets.iter().any(|p| !p.is_empty()) || l.flatpak.is_some();
            assert!(linux || l.winget.is_some(), "{} ne s'installe nulle part", l.nom);
            assert!(!l.role.0.is_empty() && !l.role.1.is_empty());
        }
    }
}
