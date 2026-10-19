//! Nettoyer sous Linux : paquets téléchargés et devenus inutiles, anciennes versions des Snap, applications Flatpak
//! inutilisées, compilations AUR, caches des applications inutilisées, miniatures, vieux journaux, rapports de
//! plantage, corbeille.
//! La place à gagner est mesurée avant (simulations de paccache, tailles des dossiers) quand on peut le faire sans
//! droits d'administrateur.

use std::path::Path;
use std::process::Command;

use super::{Age, Element, caches_inutilises, lectures_datees, maison, taille_dossier, volume};
use crate::machine::linux::{Atomique, Paquets, atomique};
use crate::ui::*;

fn present(cmd: &str) -> bool {
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .any(|d| Path::new(d).join(cmd).exists())
}

/// Sortie d'un outil lancé en anglais (ses messages se lisent alors à coup sûr).
fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
    crate::commande::lancer(Command::new(cmd).args(args).env("LC_ALL", "C"), 30)
        .filter(|r| r.code == Some(0))
        .map(|r| r.sortie)
}

/// « 80.47 MiB », « 1.2 GiB », « 512 B » → octets.
fn octets(nombre: &str, unite: &str) -> Option<u64> {
    let n: f64 = nombre.parse().ok()?;
    let facteur = match unite.trim_end_matches(['.', ')']) {
        "B" => 1.0,
        "KiB" | "K" => 1024.0,
        "MiB" | "M" => 1024.0 * 1024.0,
        "GiB" | "G" => 1024.0 * 1024.0 * 1024.0,
        "TiB" | "T" => 1024.0_f64.powi(4),
        _ => return None,
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // une taille positive, arrondie à l'octet
    Some((n * facteur) as u64)
}

/// Simulation de paccache : « ==> finished dry run: 2 candidates (disk space saved: 80.47 MiB) », ou rien à faire.
fn lire_paccache(sortie: &str) -> u64 {
    sortie
        .lines()
        .filter_map(|l| {
            let reste = l.split("disk space saved: ").nth(1)?;
            let mut mots = reste.split_whitespace();
            octets(mots.next()?, mots.next()?)
        })
        .sum()
}

/// « Installed Size  : 1.23 MiB » dans `pacman -Qi`, pour chaque paquet.
fn lire_tailles_pacman(sortie: &str) -> u64 {
    sortie
        .lines()
        .filter(|l| l.starts_with("Installed Size"))
        .filter_map(|l| {
            let mut mots = l.split(':').nth(1)?.split_whitespace();
            octets(mots.next()?, mots.next()?)
        })
        .sum()
}

/// `snap list --all` : les révisions désactivées (anciennes versions gardées), en (nom, révision).
fn revisions_desactivees(sortie: &str) -> Vec<(String, String)> {
    sortie
        .lines()
        .skip(1)
        .filter(|l| {
            l.split_whitespace()
                .last()
                .is_some_and(|n| n.split(',').any(|x| x == "disabled"))
        })
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            Some(((*c.first()?).to_string(), (*c.get(2)?).to_string()))
        })
        .collect()
}

fn paquets_telecharges(gestion: Paquets) -> Element {
    let (taille, commandes): (Option<u64>, Vec<&str>) = match gestion {
        // paccache garde les deux dernières versions de chaque paquet (de quoi revenir en arrière) ; sa simulation dit
        // exactement ce qu'il libère, sans droits.
        Paquets::Pacman if present("paccache") => (
            Some(
                lire_paccache(&sortie("paccache", &["-dk2"]).unwrap_or_default())
                    + lire_paccache(&sortie("paccache", &["-duk0"]).unwrap_or_default()),
            ),
            vec!["sudo paccache -rk2", "sudo paccache -ruk0"],
        ),
        Paquets::Pacman => (None, vec!["sudo pacman -Sc --noconfirm"]),
        Paquets::Apt => (
            taille_dossier(Path::new("/var/cache/apt/archives"), Age::Tout, &[]),
            vec!["sudo apt-get clean"],
        ),
        Paquets::Dnf if atomique() == Some(Atomique::RpmOstree) => (None, vec!["sudo rpm-ostree cleanup -bm"]),
        Paquets::Dnf => (
            ["/var/cache/libdnf5", "/var/cache/dnf"]
                .iter()
                .filter_map(|d| taille_dossier(Path::new(d), Age::Tout, &[]))
                .reduce(|a, b| a + b),
            vec!["sudo dnf clean all"],
        ),
        Paquets::Zypper => (
            taille_dossier(Path::new("/var/cache/zypp"), Age::Tout, &[]),
            vec!["sudo zypper clean --all"],
        ),
    };
    Element {
        titre: tr!("Paquets téléchargés", "Downloaded packages"),
        effet: tr!(
            "Les paquets gardés après chaque mise à jour. Sous Arch, les deux dernières versions restent, pour pouvoir revenir en arrière.",
            "Packages kept after each update. On Arch, the last two versions stay, so you can roll back."
        )
        .into(),
        prudence: None,
        taille,
        commandes: commandes.into_iter().map(String::from).collect(),
        recommande: true,
        admin: true,
    }
}

fn paquets_inutiles(gestion: Paquets) -> Option<Element> {
    let (taille, commande) = match gestion {
        Paquets::Pacman => {
            let orphelins = sortie("pacman", &["-Qdtq"]).unwrap_or_default();
            let noms: Vec<&str> = orphelins.split_whitespace().collect();
            let taille = if noms.is_empty() {
                Some(0)
            } else {
                let mut args = vec!["-Qi"];
                args.extend(&noms);
                sortie("pacman", &args).map(|s| lire_tailles_pacman(&s))
            };
            (
                taille,
                tr!(
                    "orphelins=$(pacman -Qdtq); if [ -n \"$orphelins\" ]; then sudo pacman -Rns $orphelins; else echo 'Aucun paquet orphelin.'; fi",
                    "orphelins=$(pacman -Qdtq); if [ -n \"$orphelins\" ]; then sudo pacman -Rns $orphelins; else echo 'No orphan packages.'; fi"
                ),
            )
        }
        // Sans -y : la liste s'affiche et se confirme (retirer un métapaquet peut emporter tout un bureau).
        Paquets::Apt => (None, "sudo apt-get autoremove --purge"),
        // Image en lecture seule (rpm-ostree) : rien à retirer à la main.
        Paquets::Dnf if atomique().is_some() => return None,
        Paquets::Dnf => (None, "sudo dnf autoremove"),
        Paquets::Zypper => return None,
    };
    Some(Element {
        titre: tr!("Paquets devenus inutiles", "Packages no longer needed"),
        effet: tr!(
            "Paquets installés pour un autre que plus rien n'utilise.",
            "Packages installed for another one that nothing uses any more."
        )
        .into(),
        prudence: Some(tr!(
            "La liste s'affiche et se confirme avant : vérifie qu'elle ne contient rien que tu utilises.",
            "The list is shown and confirmed first: check it holds nothing you use."
        )),
        taille,
        commandes: vec![commande.to_string()],
        recommande: false,
        admin: true,
    })
}

fn snap() -> Option<Element> {
    if !present("snap") {
        return None;
    }
    let anciennes = revisions_desactivees(&sortie("snap", &["list", "--all"])?);
    let taille = anciennes
        .iter()
        .filter_map(|(nom, rev)| std::fs::metadata(format!("/var/lib/snapd/snaps/{nom}_{rev}.snap")).ok())
        .map(|m| m.len())
        .sum();
    Some(Element {
        titre: tr!("Anciennes versions des Snap", "Old Snap versions"),
        effet: tr!(
            "Snap garde les versions précédentes de chaque application ; la version en service reste.",
            "Snap keeps the previous versions of each app; the version in use stays."
        )
        .into(),
        prudence: None,
        taille: Some(taille),
        commandes: vec![
            "snap list --all | awk '/disabled/{print $1, $3}' | while read -r nom rev; do sudo snap remove \"$nom\" --revision=\"$rev\"; done"
                .into(),
        ],
        recommande: true,
        admin: true,
    })
}

fn flatpak() -> Option<Element> {
    present("flatpak").then(|| Element {
        titre: tr!("Flatpak inutilisés", "Unused Flatpak runtimes"),
        effet: tr!(
            "Bibliothèques Flatpak qu'aucune application installée n'utilise plus.",
            "Flatpak libraries that no installed app uses any more."
        )
        .into(),
        prudence: None,
        taille: None,
        commandes: vec!["flatpak uninstall --unused -y".into()],
        recommande: true,
        admin: false,
    })
}

/// Compilations gardées par les assistants AUR (yay, paru) : seulement reconstruire un paquet en a besoin.
fn compilations_aur(maison: &Path) -> Vec<Element> {
    [
        ("yay", ".cache/yay", "rm -rf ~/.cache/yay/*"),
        ("paru", ".cache/paru/clone", "rm -rf ~/.cache/paru/clone/*"),
    ]
    .into_iter()
    .filter_map(|(assistant, dossier, commande)| {
        let taille = taille_dossier(&maison.join(dossier), Age::Tout, &[])?;
        Some(Element {
            titre: if assistant == "yay" {
                tr!("Compilations AUR (yay)", "AUR builds (yay)")
            } else {
                tr!("Compilations AUR (paru)", "AUR builds (paru)")
            },
            effet: trf!(
                "Sources et compilations des paquets AUR, gardées par {assistant} ; il les retélécharge au besoin.",
                "Sources and builds of AUR packages, kept by {assistant}; it downloads them again when needed."
            ),
            prudence: None,
            taille: Some(taille),
            commandes: vec![commande.into()],
            recommande: true,
            admin: false,
        })
    })
    .collect()
}

/// Les caches d'applications de ~/.cache qui dorment ; ceux comptés à part (miniatures, AUR) n'y sont pas.
fn vieux_cache(maison: &Path) -> Option<Element> {
    let cache = maison.join(".cache");
    caches_inutilises(
        &cache,
        "~/.cache",
        &["thumbnails", "yay", "paru"],
        lectures_datees(&cache),
    )
}

fn miniatures(maison: &Path) -> Element {
    Element {
        titre: tr!("Miniatures des images", "Image thumbnails"),
        effet: tr!(
            "Aperçus des photos et vidéos ; le gestionnaire de fichiers les refait en les affichant.",
            "Previews of photos and videos; the file manager makes them again when showing them."
        )
        .into(),
        prudence: None,
        taille: Some(taille_dossier(&maison.join(".cache/thumbnails"), Age::Tout, &[]).unwrap_or(0)),
        commandes: vec!["rm -rf ~/.cache/thumbnails".into()],
        recommande: true,
        admin: false,
    }
}

fn journaux() -> Option<Element> {
    if !Path::new("/run/systemd/system").exists() {
        return None;
    }
    // « Archived and active journals take up 292.7M in the file system. » : la taille actuelle, pas ce qui partira.
    let actuelle = sortie("journalctl", &["--disk-usage"]).and_then(|s| {
        let reste = s.split("take up ").nth(1)?;
        let mot = reste.split_whitespace().next()?;
        let (nombre, unite) = mot.split_at(mot.find(|c: char| c.is_ascii_alphabetic())?);
        octets(nombre, unite)
    });
    Some(Element {
        titre: tr!("Vieux journaux du système", "Old system logs"),
        effet: match actuelle {
            Some(t) => trf!(
                "Les journaux font {} ; les deux dernières semaines restent.",
                "The logs take {}; the last two weeks stay.",
                super::taille_lisible(t)
            ),
            None => tr!(
                "Les deux dernières semaines de journaux restent.",
                "The last two weeks of logs stay."
            )
            .into(),
        },
        prudence: None,
        taille: None,
        commandes: vec!["sudo journalctl --vacuum-time=2weeks".into()],
        recommande: true,
        admin: true,
    })
}

fn plantages() -> Option<Element> {
    let dossier = Path::new("/var/lib/systemd/coredump");
    let taille = taille_dossier(dossier, Age::NonModifieDepuis(7), &[])?;
    Some(Element {
        titre: tr!("Rapports de plantage", "Crash reports"),
        effet: tr!(
            "Copies de la mémoire des programmes qui ont planté il y a plus d'une semaine.",
            "Memory copies of programs that crashed more than a week ago."
        )
        .into(),
        prudence: None,
        taille: Some(taille),
        commandes: vec!["sudo find /var/lib/systemd/coredump -type f -mtime +7 -delete".into()],
        recommande: true,
        admin: true,
    })
}

fn corbeille(maison: &Path) -> Element {
    Element {
        titre: tr!("Corbeille", "Trash"),
        effet: tr!("Les fichiers mis à la corbeille.", "Files moved to the trash.").into(),
        prudence: Some(tr!(
            "Ce qui est dans la corbeille ne pourra plus être récupéré.",
            "What is in the trash can no longer be recovered."
        )),
        taille: Some(taille_dossier(&maison.join(".local/share/Trash"), Age::Tout, &[]).unwrap_or(0)),
        commandes: vec![
            "rm -rf ~/.local/share/Trash/files ~/.local/share/Trash/info ~/.local/share/Trash/expunged".into(),
        ],
        recommande: false,
        admin: false,
    }
}

pub fn elements() -> Vec<Element> {
    let maison = maison();
    let gestion = Paquets::detecter();
    let mut l: Vec<Element> = Vec::new();
    l.extend(gestion.map(paquets_telecharges));
    l.extend(gestion.and_then(paquets_inutiles));
    l.extend(snap());
    l.extend(flatpak());
    l.extend(compilations_aur(&maison));
    l.extend(vieux_cache(&maison));
    l.push(miniatures(&maison));
    l.extend(journaux());
    l.extend(plantages());
    l.push(corbeille(&maison));
    l
}

/// Le volume racine, et celui du dossier personnel s'il est ailleurs. Deux sous-volumes btrfs (« @ » et « @home »)
/// partagent la même place : à la même taille, c'est le même disque, compté une fois.
pub fn place() -> Option<(u64, u64, u64)> {
    let (libre, total) = volume(Path::new("/"))?;
    let cumul = match volume(&maison()) {
        Some((l, t)) if t != total => libre + l,
        _ => libre,
    };
    Some((libre, total, cumul))
}

/// Les commandes de chaque élément, l'une après l'autre (sudo demande le mot de passe dans le terminal).
pub fn executer(choisis: &[&Element]) -> Vec<bool> {
    let groupes: Vec<Vec<String>> = choisis.iter().map(|e| e.commandes.clone()).collect();
    crate::machine::appliquer_chacune(&groupes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorties_lues() {
        assert_eq!(
            lire_paccache("==> finished dry run: 2 candidates (disk space saved: 80.47 MiB)\n"),
            84_378_910
        );
        assert_eq!(lire_paccache("==> no candidate packages found for pruning\n"), 0);
        let qi = "Name            : a\nInstalled Size  : 1.50 MiB\nName            : b\nInstalled Size  : 512.00 KiB\n";
        assert_eq!(lire_tailles_pacman(qi), (3 << 19) + (512 << 10));
        let snaps = "Name    Version   Rev    Tracking       Publisher   Notes\n\
                     core20  20240416  2264   latest/stable  canonical✓  base,disabled\n\
                     core20  20240705  2318   latest/stable  canonical✓  base\n\
                     firefox 128.0     4451   latest/stable  mozilla✓    disabled\n";
        assert_eq!(
            revisions_desactivees(snaps),
            [
                ("core20".to_string(), "2264".to_string()),
                ("firefox".to_string(), "4451".to_string())
            ]
        );
    }

    #[test]
    fn commandes_shell_valides() {
        for e in elements() {
            for c in &e.commandes {
                let valide = Command::new("bash")
                    .args(["-n", "-c", c])
                    .status()
                    .is_ok_and(|s| s.success());
                assert!(valide, "« {} » : {c}", e.titre);
            }
        }
    }
}
