//! Ce que Linux et macOS partagent pour les traces : tâches cron, fichiers du shell et clés SSH autorisées, la fin
//! d'un fichier journal, un journal écrit par sa commande dans une borne.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{Bi, Feuille, Partie, Raison, bi, creer_fichier, entete};
use crate::commande::{Garder, lancer_vers};

/// Le dossier personnel.
pub(super) fn maison() -> PathBuf {
    crate::nettoyer::maison()
}

/// Ce qui se lance à l'ouverture d'un shell, et les clés SSH qui ouvrent ce compte sans mot de passe : deux façons
/// courantes de garder la main sur un compte.
pub(super) fn shell_et_ssh(f: &mut Feuille) {
    let m = maison();
    for nom in [
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".zlogin",
        ".xprofile",
        ".xinitrc",
        ".config/fish/config.fish",
    ] {
        f.fichier_shell(&m.join(nom));
    }
    for chemin in ["/etc/profile", "/etc/bash.bashrc", "/etc/zshrc", "/etc/zprofile"] {
        f.fichier_shell(Path::new(chemin));
    }
    f.dossier(Path::new("/etc/profile.d"), 0, false);
    f.fichier(&m.join(".ssh/authorized_keys"), true);
    f.fichier(&m.join(".ssh/authorized_keys2"), false);
    f.fichier(Path::new("/root/.ssh/authorized_keys"), false);
}

/// Les tâches cron : celles du compte (crontab -l), celles du système, et le dossier des tâches de chaque compte,
/// lisible par root seulement.
pub(super) fn cron(f: &mut Feuille) {
    f.commande(Command::new("crontab").arg("-l"), 10, false);
    f.fichier(Path::new("/etc/crontab"), true);
    f.fichier(Path::new("/etc/anacrontab"), false);
    for d in [
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/periodic/daily",
    ] {
        f.dossier(Path::new(d), 50, false);
    }
    for d in [
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
        "/var/at/tabs",
        "/usr/lib/cron/tabs",
    ] {
        if Path::new(d).is_dir() {
            if super::privilegie() {
                f.dossier(Path::new(d), 100, false);
            } else {
                f.section(d);
                f.ajouter(&Raison::Droits.note());
                f.manques.push(super::Manque {
                    quoi: bi!("Tâches cron de chaque compte ({d})", "Each account's cron jobs ({d})"),
                    raison: Raison::Droits,
                });
            }
        }
    }
}

/// Recopie la fin d'un fichier journal (`borne` octets au plus, à partir d'une ligne entière) dans `nom` ; rend la
/// taille écrite.
pub(super) fn copier_la_fin(source: &Path, dossier: &Path, nom: &str, borne: u64) -> std::io::Result<u64> {
    let mut f = std::fs::File::open(source)?;
    let taille = f.metadata()?.len();
    let depart = taille.saturating_sub(borne);
    f.seek(SeekFrom::Start(depart))?;
    let mut octets = Vec::new();
    f.take(borne).read_to_end(&mut octets)?;
    if depart > 0
        && let Some(i) = octets.iter().position(|&o| o == b'\n')
    {
        octets.drain(..=i);
    }
    let mut sortie = creer_fichier(&dossier.join(nom))?;
    sortie.write_all(entete(&Bi::meme(source.to_string_lossy())).as_bytes())?;
    sortie.write_all(super::texte_sur(&String::from_utf8_lossy(&octets)).as_bytes())?;
    Ok(octets.len() as u64)
}

/// Lance une commande qui écrit un journal dans `nom` (après l'en-tête), `borne` octets au plus. `Err` : le fichier
/// ne s'écrit pas ; `Ok(None)` : la commande ne démarre pas.
pub(super) fn journal_vers(
    dossier: &Path,
    nom: &str,
    titre: &Bi,
    commande: &mut Command,
    secondes: u64,
    garder: Garder,
) -> std::io::Result<Option<crate::commande::Ecrit>> {
    let mut f = creer_fichier(&dossier.join(nom))?;
    f.write_all(entete(titre).as_bytes())?;
    let _ = writeln!(f, "# $ {}", super::affichage_commande(commande));
    Ok(lancer_vers(commande, secondes, &f, super::BORNE_JOURNAL, garder))
}

/// La taille lisible d'un journal écrit.
pub(super) fn mo(octets: u64) -> Bi {
    #[allow(clippy::cast_precision_loss)]
    let mo = octets as f64 / f64::from(1u32 << 20);
    if mo < 1.0 {
        Bi::new("moins de 1 Mo", "less than 1 MB")
    } else {
        bi!("{mo:.0} Mo", "{mo:.0} MB")
    }
}

/// Les fichiers journaux classiques, quand le journal du système ne répond pas (pas de systemd, journal vide) : la
/// fin de chacun.
pub(super) fn journaux_classiques(p: &mut Partie, dossier: &Path, fichiers: &[&str]) -> u64 {
    let mut total = 0;
    for source in fichiers {
        let source = Path::new(source);
        if !source.is_file() {
            continue;
        }
        let nom = format!(
            "05-{}.txt",
            source.to_string_lossy().trim_start_matches('/').replace('/', "-")
        );
        match copier_la_fin(source, dossier, &nom, 10 << 20) {
            Ok(n) => {
                total += n;
                p.fichiers.push(super::Produit {
                    nom,
                    contenu: bi!(
                        "la fin de {} (10 Mo au plus)",
                        "the end of {} (10 MB at most)",
                        source.display()
                    ),
                });
            }
            Err(e) => p.manque(
                Bi::meme(source.to_string_lossy()),
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    Raison::Droits
                } else {
                    Raison::Erreur(e.to_string())
                },
            ),
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fin_d_un_journal_a_partir_d_une_ligne() {
        let dossier = crate::reseau::dossier_local().join("fin-journal");
        std::fs::create_dir_all(&dossier).unwrap();
        let source = dossier.join("auth.log");
        std::fs::write(&source, "un\ndeux\ntrois\n").unwrap();
        assert_eq!(copier_la_fin(&source, &dossier, "fin.txt", 8).unwrap(), 6);
        let texte = std::fs::read_to_string(dossier.join("fin.txt")).unwrap();
        assert!(
            texte.starts_with("# Vanguard ") && texte.ends_with("\ntrois\n"),
            "{texte}"
        );
        assert!(!texte.contains("deux"));
        // Tout tient : rien n'est coupé.
        assert_eq!(copier_la_fin(&source, &dossier, "tout.txt", 100).unwrap(), 14);
        // Jamais un fichier existant écrasé.
        assert!(copier_la_fin(&source, &dossier, "tout.txt", 100).is_err());
        assert_eq!(mo(3 << 20).fr, "3 Mo");
        assert_eq!(mo(10).en, "less than 1 MB");
    }
}
