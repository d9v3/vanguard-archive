//! Nettoyer sous Windows : fichiers temporaires (les tiens et ceux de Windows), cache de Windows Update et de
//! l'optimisation de distribution, anciennes versions des composants (DISM), rapports de plantage, corbeille. Ce qui
//! est à toi se nettoie dans ton compte ; ce qui est à Windows passe par une seule fenêtre administrateur.

use std::path::PathBuf;

use super::{Age, Element, taille_dossier};
use crate::ui::*;

fn variable(nom: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(nom).unwrap_or_default())
}

fn dossier_windows() -> PathBuf {
    let racine = variable("SystemRoot");
    if racine.as_os_str().is_empty() {
        PathBuf::from(r"C:\Windows")
    } else {
        racine
    }
}

/// La corbeille du disque système : un dossier par compte dans `$Recycle.Bin`, seul le sien est lisible.
fn taille_corbeille() -> Option<u64> {
    let lecteur = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let racine = PathBuf::from(format!(r"{lecteur}\$Recycle.Bin"));
    std::fs::read_dir(racine)
        .ok()?
        .flatten()
        .filter_map(|e| taille_dossier(&e.path(), Age::Tout, &[]))
        .reduce(|a, b| a + b)
}

pub fn elements() -> Vec<Element> {
    let windows = dossier_windows();
    vec![
        Element {
            titre: tr!("Tes fichiers temporaires", "Your temporary files"),
            effet: tr!(
                "Ce que les programmes laissent dans ton dossier temporaire ; un fichier encore ouvert reste.",
                "What programs leave in your temporary folder; a file still open stays."
            )
            .into(),
            prudence: None,
            taille: taille_dossier(&variable("TEMP"), Age::Tout, &[]),
            commandes: vec!["Get-ChildItem $env:TEMP -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue".into()],
            recommande: true,
            admin: false,
        },
        Element {
            titre: tr!("Fichiers temporaires de Windows", "Windows temporary files"),
            effet: tr!(
                "Le dossier temporaire de Windows lui-même (installations, mises à jour).",
                "Windows' own temporary folder (installs, updates)."
            )
            .into(),
            prudence: None,
            taille: taille_dossier(&windows.join("Temp"), Age::Tout, &[]),
            commandes: vec![
                "Get-ChildItem \"$env:SystemRoot\\Temp\" -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue"
                    .into(),
            ],
            recommande: true,
            admin: true,
        },
        Element {
            titre: tr!("Cache de Windows Update", "Windows Update cache"),
            effet: tr!(
                "Les mises à jour déjà téléchargées et installées.",
                "Updates already downloaded and installed."
            )
            .into(),
            prudence: Some(tr!(
                "Une mise à jour en cours de téléchargement recommencera.",
                "An update being downloaded will start over."
            )),
            taille: taille_dossier(&windows.join(r"SoftwareDistribution\Download"), Age::Tout, &[]),
            commandes: vec![
                "Stop-Service wuauserv -Force; Get-ChildItem \"$env:SystemRoot\\SoftwareDistribution\\Download\" -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue; Start-Service wuauserv"
                    .into(),
            ],
            recommande: true,
            admin: true,
        },
        Element {
            titre: tr!("Optimisation de distribution", "Delivery Optimization"),
            effet: tr!(
                "Le cache des mises à jour partagées avec les autres PC (réseau local ou Internet).",
                "The cache of updates shared with other PCs (local network or Internet)."
            )
            .into(),
            prudence: None,
            taille: None,
            commandes: vec!["Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue".into()],
            recommande: true,
            admin: true,
        },
        Element {
            titre: tr!("Anciens composants de Windows", "Old Windows components"),
            effet: tr!(
                "Les versions remplacées des composants de Windows (DISM), gardées après chaque mise à jour ; quelques minutes.",
                "Replaced versions of Windows components (DISM), kept after each update; a few minutes."
            )
            .into(),
            prudence: None,
            taille: None,
            commandes: vec!["Dism /Online /Cleanup-Image /StartComponentCleanup".into()],
            recommande: true,
            admin: true,
        },
        Element {
            titre: tr!("Tes rapports de plantage", "Your crash reports"),
            effet: tr!(
                "Copies de la mémoire des programmes qui ont planté.",
                "Memory copies of programs that crashed."
            )
            .into(),
            prudence: None,
            taille: Some(taille_dossier(&variable("LOCALAPPDATA").join("CrashDumps"), Age::Tout, &[]).unwrap_or(0)),
            commandes: vec!["Remove-Item \"$env:LOCALAPPDATA\\CrashDumps\\*\" -Recurse -Force -ErrorAction SilentlyContinue".into()],
            recommande: true,
            admin: false,
        },
        Element {
            titre: tr!("Rapports d'erreurs de Windows", "Windows error reports"),
            effet: tr!(
                "Rapports d'erreurs déjà traités et copies de la mémoire après un écran bleu.",
                "Error reports already processed and memory copies after a blue screen."
            )
            .into(),
            prudence: None,
            taille: None,
            commandes: vec![
                "Remove-Item \"$env:SystemRoot\\Minidump\\*\", \"$env:ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\*\" -Recurse -Force -ErrorAction SilentlyContinue"
                    .into(),
            ],
            recommande: true,
            admin: true,
        },
        Element {
            titre: tr!("Corbeille", "Recycle Bin"),
            effet: tr!("Les fichiers mis à la corbeille.", "Files moved to the Recycle Bin.").into(),
            prudence: Some(tr!(
                "Ce qui est dans la corbeille ne pourra plus être récupéré.",
                "What is in the Recycle Bin can no longer be recovered."
            )),
            taille: taille_corbeille(),
            commandes: vec!["Clear-RecycleBin -Force -ErrorAction SilentlyContinue".into()],
            recommande: false,
            admin: false,
        },
    ]
}

/// Place libre du disque du système, lue par .NET (le seul disque que le nettoyage touche).
pub fn place() -> Option<(u64, u64, u64)> {
    let s = crate::machine::windows::ps(
        "$d = [IO.DriveInfo]::new($env:SystemDrive); \"$($d.AvailableFreeSpace) $($d.TotalSize)\"",
    )?;
    let mut n = s.split_whitespace().filter_map(|x| x.parse::<u64>().ok());
    let (libre, total) = (n.next()?, n.next()?);
    Some((libre, total, libre))
}

/// Ce qui est à Windows dans une seule fenêtre administrateur ; ce qui est à la personne dans son propre compte (la
/// fenêtre administrateur peut être celle d'un autre compte, avec une autre corbeille et un autre dossier temporaire).
pub fn executer(choisis: &[&Element]) -> Vec<bool> {
    let systeme: Vec<Vec<String>> = choisis
        .iter()
        .filter(|e| e.admin)
        .map(|e| e.commandes.clone())
        .collect();
    let mut resultats = if systeme.is_empty() {
        Vec::new()
    } else {
        crate::machine::appliquer_chacune(&systeme)
    }
    .into_iter();
    choisis
        .iter()
        .map(|e| {
            if e.admin {
                resultats.next().unwrap_or(false)
            } else {
                e.commandes.iter().all(|c| {
                    println!("    {GRIS}PS> {c}{RESET}");
                    crate::machine::windows::ps(c).is_some()
                })
            }
        })
        .collect()
}
