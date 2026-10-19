//! Raccourci sur cet ordinateur : lancer Vanguard d'un clic, sans passer par la clé. Le programme est d'abord copié
//! dans le dossier de Vanguard de cet ordinateur (lancé depuis la clé, il disparaîtrait avec elle), puis un raccourci
//! le lance : une entrée du menu des applications sous Linux (avec son icône), un raccourci sur le Bureau sous
//! Windows, un fichier « Vanguard.command » sur le Bureau sous macOS. Montré puis accepté ; retiré aussi simplement.
//! Un raccourci qui n'a pas été posé par Vanguard n'est jamais remplacé ni retiré.

use std::path::PathBuf;

use crate::ui::*;

/// Ce qui marque un raccourci posé par Vanguard (Linux : une clé du fichier .desktop ; macOS : un commentaire).
const MARQUE: &str = "X-Vanguard-Raccourci=1";
#[cfg(target_os = "linux")]
const ICONE: &[u8] = include_bytes!("../assets/icones/vanguard-128.png");

/// Où va le raccourci sur ce système.
#[cfg_attr(target_os = "macos", allow(clippy::unnecessary_wraps))] // même signature que sous Linux et Windows
fn chemin() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let donnees = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
        Some(donnees.join("applications/Vanguard.desktop"))
    }
    #[cfg(windows)]
    {
        let bureau = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
            .ok()
            .and_then(|k| k.get_value::<String, _>("Desktop").ok())
            .map(|c| PathBuf::from(crate::protection::pieges::developper(&c)))
            .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("Desktop")))?;
        Some(bureau.join("Vanguard.lnk"))
    }
    #[cfg(target_os = "macos")]
    {
        Some(crate::nettoyer::maison().join("Desktop/Vanguard.command"))
    }
}

/// L'entrée du menu des applications, Linux : Vanguard s'ouvre dans un terminal.
#[cfg(any(target_os = "linux", test))]
fn bureau_linux(exe: &str) -> String {
    // Exec : entre guillemets, « % » doublé (codes de champ de la spécification).
    let exe = format!(
        "\"{}\"",
        exe.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%")
    );
    format!(
        "[Desktop Entry]\nType=Application\nName=Vanguard\nComment={}\nExec={exe}\nTerminal=true\nIcon=vanguard\nCategories=System;Security;\n{MARQUE}\n",
        tr!(
            "Sécurise et optimise ta machine et ton réseau",
            "Secures and optimizes your machine and network"
        )
    )
}

/// Le fichier du Bureau, macOS : un script que le Finder ouvre dans le Terminal.
#[cfg(any(target_os = "macos", test))]
fn commande_macos(exe: &str) -> String {
    format!("#!/bin/sh\n# {MARQUE}\nexec {}\n", crate::commande::sh_chaine(exe))
}

/// Le raccourci existe-t-il, et est-il de Vanguard ?
fn etat() -> Option<(PathBuf, bool)> {
    let p = chemin()?;
    if !p.exists() {
        return Some((p, false));
    }
    // Windows : un raccourci .lnk ne se lit pas comme du texte ; celui-là s'appelle Vanguard.lnk, posé par Vanguard.
    let a_nous = cfg!(windows) || std::fs::read_to_string(&p).is_ok_and(|t| t.contains(MARQUE));
    Some((p, a_nous))
}

fn poser(exe: &str, ou: &std::path::Path) -> Result<(), String> {
    if let Some(parent) = ou.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::write(ou, bureau_linux(exe)).map_err(|e| e.to_string())?;
        if let Some(donnees) = ou.parent().and_then(std::path::Path::parent) {
            let icone = donnees.join("icons/hicolor/128x128/apps/vanguard.png");
            let _ = std::fs::create_dir_all(icone.parent().unwrap_or(&icone));
            if !icone.exists() {
                let _ = std::fs::write(&icone, ICONE);
            }
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(ou, commande_macos(exe)).map_err(|e| e.to_string())?;
        std::fs::set_permissions(ou, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())
    }
    #[cfg(windows)]
    {
        let e = crate::commande::ps_texte;
        let script = format!(
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath = '{}'; $s.IconLocation = '{},0'; \
             $s.Description = 'Vanguard'; $s.Save()",
            e(&ou.display().to_string()),
            e(exe),
            e(exe)
        );
        crate::machine::windows::ps(&script).map(|_| ()).ok_or_else(|| {
            tr!(
                "PowerShell n'a pas pu créer le raccourci",
                "PowerShell could not create the shortcut"
            )
            .into()
        })
    }
}

/// `vanguard raccourci [on|off]` et le menu Données : sans argument, l'état et la proposition.
pub fn commande(voulu: Option<bool>) {
    titre(tr!("Raccourci sur cet ordinateur", "Shortcut on this computer"));
    let Some((ou, a_nous)) = etat() else {
        trp!(
            "  ✖ Impossible de trouver le Bureau ou le menu des applications ici.",
            "  ✖ Could not find the Desktop or the applications menu here."
        );
        return;
    };
    let montre = chemin_affichable(&ou);
    let present = ou.exists();
    if present && !a_nous {
        trp!(
            "  {VERT}✔{RESET} Un raccourci vers Vanguard existe déjà ({montre}) : il n'a pas été posé par Vanguard, il reste tel quel.",
            "  {VERT}✔{RESET} A shortcut to Vanguard already exists ({montre}): it was not placed by Vanguard, it stays as it is."
        );
        return;
    }
    let voulu = voulu.unwrap_or_else(|| {
        let question = if present {
            trf!("  Raccourci présent ({montre}). Le retirer ? [o/N] : ", "  Shortcut present ({montre}). Remove it? [y/N]: ")
        } else {
            trf!(
                "  Vanguard sera copié sur cet ordinateur, puis lancé d'un clic par {montre}. Le poser ? [o/N] : ",
                "  Vanguard will be copied onto this computer, then started with one click from {montre}. Place it? [y/N]: "
            )
        };
        demander(&question).oui() != present
    });
    if voulu {
        if present {
            trp!(
                "  {VERT}✔{RESET} Le raccourci est déjà là.",
                "  {VERT}✔{RESET} The shortcut is already there."
            );
            return;
        }
        let exe = crate::reseau::surveillance::executable();
        match poser(&exe, &ou) {
            Ok(()) => trp!(
                "  {VERT}✔{RESET} Raccourci posé : {montre}",
                "  {VERT}✔{RESET} Shortcut placed: {montre}"
            ),
            Err(e) => trp!("  ✖ Raccourci non posé : {e}", "  ✖ Shortcut not placed: {e}"),
        }
    } else if present {
        match std::fs::remove_file(&ou) {
            Ok(()) => trp!(
                "  {VERT}✔{RESET} Raccourci retiré.",
                "  {VERT}✔{RESET} Shortcut removed."
            ),
            Err(e) => trp!("  ✖ Raccourci non retiré : {e}", "  ✖ Shortcut not removed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fichiers_du_raccourci() {
        let d = bureau_linux("/home/alice/.local/share/vanguard/bin/gar\"dien 100%");
        assert!(
            d.contains("Exec=\"/home/alice/.local/share/vanguard/bin/gar\\\"dien 100%%\"\n"),
            "{d}"
        );
        assert!(d.contains("Terminal=true") && d.contains(MARQUE));
        let m = commande_macos("/Users/alice/Library/Application Support/vanguard/bin/vanguard");
        assert!(m.starts_with("#!/bin/sh\n") && m.contains(MARQUE));
        assert!(m.contains("exec '/Users/alice/Library/Application Support/vanguard/bin/vanguard'"));
    }
}
