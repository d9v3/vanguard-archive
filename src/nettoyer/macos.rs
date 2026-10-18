//! Nettoyer sous macOS : caches des applications inutilisées, téléchargements de Homebrew, compilations de Xcode,
//! instantanés locaux de Time Machine. La corbeille n'est pas touchée : macOS la protège (accès complet au disque),
//! elle se vide depuis le Finder.

use super::{Age, Element, caches_inutilises, lectures_datees, maison, taille_dossier, volume};
use crate::machine::macos::homebrew;
use crate::ui::*;

pub fn elements() -> Vec<Element> {
    let maison = maison();
    let caches = maison.join("Library/Caches");
    // Les téléchargements de Homebrew sont comptés à part.
    let mut l: Vec<Element> = caches_inutilises(&caches, "~/Library/Caches", &["Homebrew"], lectures_datees(&caches))
        .into_iter()
        .collect();
    if let Some(brew) = homebrew() {
        l.push(Element {
            titre: tr!("Téléchargements de Homebrew", "Homebrew downloads"),
            effet: tr!(
                "Les fichiers d'installation gardés par Homebrew et ses anciennes versions.",
                "Install files kept by Homebrew and its old versions."
            )
            .into(),
            prudence: None,
            taille: taille_dossier(&caches.join("Homebrew"), Age::Tout, &[]),
            commandes: vec![format!("{brew} cleanup --prune=all")],
            recommande: true,
            admin: false,
        });
    }
    let xcode = maison.join("Library/Developer/Xcode/DerivedData");
    if let Some(taille) = taille_dossier(&xcode, Age::Tout, &[]) {
        l.push(Element {
            titre: tr!("Compilations de Xcode", "Xcode builds"),
            effet: tr!(
                "Les fichiers intermédiaires des projets Xcode (DerivedData) ; Xcode les refait.",
                "Intermediate files of Xcode projects (DerivedData); Xcode makes them again."
            )
            .into(),
            prudence: Some(tr!(
                "La prochaine compilation de chaque projet sera plus longue.",
                "The next build of each project will take longer."
            )),
            taille: Some(taille),
            commandes: vec!["rm -rf ~/Library/Developer/Xcode/DerivedData/*".into()],
            recommande: true,
            admin: false,
        });
    }
    l.push(Element {
        titre: tr!("Instantanés locaux Time Machine", "Local Time Machine snapshots"),
        effet: tr!(
            "Copies de l'état du disque que macOS garde en attendant la sauvegarde ; elles occupent de la place.",
            "Copies of the disk state macOS keeps while waiting for the backup; they take up space."
        )
        .into(),
        prudence: Some(tr!(
            "Time Machine ne pourra plus revenir à ces moments-là.",
            "Time Machine will no longer be able to go back to those moments."
        )),
        taille: None,
        commandes: vec!["sudo tmutil thinlocalsnapshots / 999999999999 4".into()],
        recommande: false,
        admin: true,
    });
    l
}

/// Le volume des données (celui du dossier personnel) : sur APFS, le volume du système, scellé, partage la même place.
pub fn place() -> Option<(u64, u64, u64)> {
    let (libre, total) = volume(&maison())?;
    Some((libre, total, libre))
}

pub fn executer(choisis: &[&Element]) -> Vec<bool> {
    let groupes: Vec<Vec<String>> = choisis.iter().map(|e| e.commandes.clone()).collect();
    crate::machine::appliquer_chacune(&groupes)
}
