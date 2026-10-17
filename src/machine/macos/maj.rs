//! Mises à jour sous macOS : le système (softwareupdate), les programmes Homebrew et ceux de l'App Store (mas).

use super::super::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

/// Mises à jour proposées par `softwareupdate -l` : « * Label: macOS Sonoma 14.5-23F79 ». La réponse « No new
/// software available. » arrive sur la sortie d'erreur.
fn lire_softwareupdate(texte: &str) -> Option<Vec<String>> {
    if texte.contains("No new software available") {
        return Some(Vec::new());
    }
    let liste: Vec<String> = texte
        .lines()
        .filter_map(|l| l.trim().strip_prefix("* Label:"))
        .map(|l| l.trim().to_string())
        .collect();
    (!liste.is_empty() || texte.contains("Software Update found")).then_some(liste)
}

pub fn mises_a_jour() -> Constat {
    // La recherche interroge les serveurs d'Apple : jusqu'à une ou deux minutes.
    let Some(r) = crate::commande::lancer(std::process::Command::new("softwareupdate").arg("-l"), 180) else {
        return impossible(
            "Mises à jour",
            tr!("softwareupdate sans réponse", "softwareupdate did not answer"),
        );
    };
    let Some(liste) = lire_softwareupdate(&format!("{}\n{}", r.sortie, r.erreurs)) else {
        return impossible(
            "Mises à jour",
            tr!("hors ligne ou réponse illisible", "offline or unreadable answer"),
        );
    };
    if liste.is_empty() {
        return ok("Mises à jour", tr!("macOS est à jour.", "macOS is up to date."));
    }
    alerte(
        "Mises à jour",
        Niveau::Eleve,
        trf!(
            "{} mise(s) à jour d'Apple en attente : {}. Elles corrigent souvent des failles déjà exploitées.",
            "{} Apple update(s) waiting: {}. They often fix flaws already being exploited.",
            liste.len(),
            liste.join(", ")
        ),
    )
    .corriger(
        tr!(
            "Installer les mises à jour d'Apple (un redémarrage peut être demandé)",
            "Install the Apple updates (a restart may be needed)"
        ),
        &["sudo softwareupdate --install --all"],
    )
}

/// Programmes Homebrew et App Store en retard. `None` sans Homebrew ni mas.
pub fn homebrew_a_jour() -> Vec<Constat> {
    let mut constats = Vec::new();
    if let Some(brew) = super::homebrew() {
        let r = crate::commande::lancer(std::process::Command::new(brew).args(["outdated", "--quiet"]), 120);
        match r {
            Some(r) if r.code == Some(0) => {
                let paquets: Vec<&str> = r.sortie.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
                constats.push(if paquets.is_empty() {
                    ok(
                        "Homebrew",
                        tr!("Programmes Homebrew à jour.", "Homebrew programs up to date."),
                    )
                } else {
                    alerte(
                        "Homebrew",
                        Niveau::Moyen,
                        trf!(
                            "{} programme(s) Homebrew à mettre à jour : {}.",
                            "{} Homebrew program(s) to update: {}.",
                            paquets.len(),
                            paquets.join(", ")
                        ),
                    )
                    .corriger(
                        tr!("Mettre à jour les programmes Homebrew", "Update the Homebrew programs"),
                        &[format!("{brew} update && {brew} upgrade")],
                    )
                });
            }
            _ => constats.push(impossible(
                "Homebrew",
                tr!("brew outdated a échoué", "brew outdated failed"),
            )),
        }
    }
    // mas : l'App Store en ligne de commande, s'il est installé (brew install mas).
    if let Some(r) = crate::commande::lancer(std::process::Command::new("mas").arg("outdated"), 60)
        && r.code == Some(0)
    {
        let apps: Vec<String> = r
            .sortie
            .lines()
            .filter_map(|l| {
                // « 497799835 Xcode (15.3 -> 15.4) » : le nom est entre l'identifiant et la parenthèse.
                let (_, reste) = l.trim().split_once(' ')?;
                Some(reste.rsplit_once(" (").map_or(reste, |(n, _)| n).trim().to_string())
            })
            .collect();
        if !apps.is_empty() {
            constats.push(
                alerte(
                    "Programmes",
                    Niveau::Moyen,
                    trf!(
                        "{} app(s) de l'App Store à mettre à jour : {}.",
                        "{} App Store app(s) to update: {}.",
                        apps.len(),
                        apps.join(", ")
                    ),
                )
                .corriger(
                    tr!("Mettre à jour les apps de l'App Store", "Update the App Store apps"),
                    &["mas upgrade"],
                ),
            );
        }
    }
    constats
}

/// `sentinel maj` : système, Homebrew, App Store. `seulement` limite aux catégories qu'on vient d'installer.
pub fn mises_a_jour_completes(seulement: Option<&[&str]>) -> Vec<Constat> {
    let voulu = |categories: &[&str]| seulement.is_none_or(|s| categories.iter().any(|c| s.contains(c)));
    std::thread::scope(|portee| {
        let systeme = voulu(&["Mises à jour"]).then(|| portee.spawn(mises_a_jour));
        let programmes = voulu(&["Homebrew", "Programmes"]).then(|| portee.spawn(homebrew_a_jour));
        let mut constats: Vec<Constat> = systeme
            .map(|t| {
                t.join().unwrap_or_else(|_| {
                    impossible("Mises à jour", tr!("vérification interrompue", "check interrupted"))
                })
            })
            .into_iter()
            .collect();
        constats.extend(programmes.map(|t| t.join().unwrap_or_default()).unwrap_or_default());
        constats
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lecture_de_softwareupdate() {
        let attente = "Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n\
                       * Label: macOS Sonoma 14.5-23F79\n\tTitle: macOS Sonoma 14.5, Version: 14.5, Size: 1234567KiB, Recommended: YES, Action: restart,\n\
                       * Label: Safari17.5MontereyAuto-17.5\n";
        assert_eq!(
            lire_softwareupdate(attente).unwrap(),
            ["macOS Sonoma 14.5-23F79", "Safari17.5MontereyAuto-17.5"]
        );
        assert_eq!(
            lire_softwareupdate("Software Update Tool\n\nFinding available software\nNo new software available.\n"),
            Some(Vec::new())
        );
        assert_eq!(
            lire_softwareupdate("Software Update Tool\n\nFinding available software\n"),
            None
        );
    }
}
