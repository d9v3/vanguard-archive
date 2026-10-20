//! Les traces sous Linux : /proc pour les processus (sans rien lancer), ss et ip pour le réseau, systemd, cron et
//! les fichiers de démarrage, les comptes et leurs connexions, le journal de systemd.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::unix::{cron, journal_vers, journaux_classiques, maison, mo, shell_et_ssh};
use super::{Bi, Empreinte, Feuille, Partie, Processus, Raison, bi};
use crate::commande::Garder;
use crate::machine::linux::dissimulation::{SansFichier, juger_exe, proc_masque};

/// Les comptes d'après /etc/passwd : numéro → nom.
pub(crate) fn comptes_de(passwd: &str) -> HashMap<u32, String> {
    passwd
        .lines()
        .filter_map(|l| {
            let mut c = l.split(':');
            let nom = c.next()?;
            let uid = c.nth(1)?.parse().ok()?;
            Some((uid, nom.to_string()))
        })
        .collect()
}

/// Le parent, le compte (numéro réel) et le nom d'un processus, d'après /proc/<pid>/status.
pub(crate) fn lire_status(status: &str) -> (Option<u32>, Option<u32>, String) {
    let valeur = |cle: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(cle))
            .map(|v| v.trim().to_string())
    };
    let ppid = valeur("PPid:").and_then(|v| v.parse().ok());
    let uid = valeur("Uid:").and_then(|v| v.split_whitespace().next()?.parse().ok());
    (ppid, uid, valeur("Name:").unwrap_or_default())
}

/// L'heure de démarrage d'un processus (secondes depuis 1970) d'après /proc/<pid>/stat : son 22e champ compte les
/// tops d'horloge depuis le démarrage de l'ordinateur (`btime` de /proc/stat). Le nom, entre parenthèses, est choisi
/// par le programme et peut contenir espaces et parenthèses : les champs se comptent après la dernière.
pub(crate) fn debut_du_processus(stat: &str, btime: u64, tops: u64) -> Option<u64> {
    let (_, apres) = stat.rsplit_once(')')?;
    // Après le nom : l'état est le 3e champ, le démarrage le 22e.
    let depart: u64 = apres.split_whitespace().nth(19)?.parse().ok()?;
    Some(btime + depart / tops.max(1))
}

/// Le démarrage de l'ordinateur, d'après /proc/stat.
fn btime() -> Option<u64> {
    std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()
}

/// Ce qui cloche dans le programme d'un processus, dans les deux langues.
fn etat(s: SansFichier) -> &'static str {
    match s {
        SansFichier::Memoire => "en mémoire seulement/in memory only (memfd)",
        SansFichier::EffaceTemporaire => "effacé d'un dossier temporaire/deleted from a temporary folder",
        SansFichier::Efface => "effacé/deleted",
        SansFichier::Temporaire => "dossier temporaire/temporary folder",
        SansFichier::AJour => "remplacé par une mise à jour/replaced by an update",
    }
}

/// Une heure locale lisible, d'après des secondes depuis 1970.
fn heure_locale(secondes: u64) -> String {
    i64::try_from(secondes)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

/// Les processus, lus dans /proc sans rien lancer. Le programme de chacun se lit par /proc/<pid>/exe, même effacé du
/// disque ou chargé en mémoire seulement : c'est ce qu'il faut à un spécialiste, et son empreinte se cherche sur
/// VirusTotal. Ceux des autres comptes ne se lisent qu'en root.
pub(super) fn processus(dossier: &Path) -> Partie {
    let mut manques = Vec::new();
    let Ok(entrees) = std::fs::read_dir("/proc") else {
        let mut p = Partie::new(Bi::new("Processus", "Processes"));
        p.manque(Bi::meme("/proc"), Raison::Erreur("illisible / unreadable".into()));
        return p;
    };
    let pids: Vec<u32> = entrees
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    let comptes = comptes_de(&std::fs::read_to_string("/etc/passwd").unwrap_or_default());
    let demarrage = btime().unwrap_or(0);
    // SAFETY : sysconf lit une constante du système, sans toucher à la mémoire du programme.
    let tops = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap_or(100);
    let montages = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let mut empreintes: HashMap<(u64, u64), Empreinte> = HashMap::new();
    let mut illisibles = 0;
    let fin = std::time::Instant::now() + super::DELAI_EMPREINTES;
    let mut liste = Vec::new();
    for pid in pids {
        let racine = PathBuf::from(format!("/proc/{pid}"));
        // Parti entre la liste et la lecture : rien à garder.
        let Ok(status) = std::fs::read_to_string(racine.join("status")) else {
            continue;
        };
        let (ppid, uid, nom) = lire_status(&status);
        let ligne = std::fs::read(racine.join("cmdline"))
            .map(|o| {
                String::from_utf8_lossy(&o)
                    .split('\0')
                    .filter(|a| !a.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let debut = std::fs::read_to_string(racine.join("stat"))
            .ok()
            .and_then(|s| debut_du_processus(&s, demarrage, tops))
            .map(heure_locale)
            .unwrap_or_default();
        let (programme, etat, empreinte) = match std::fs::read_link(racine.join("exe")) {
            Ok(lien) => {
                let lien = lien.to_string_lossy().into_owned();
                let chemin = lien.strip_suffix(" (deleted)").unwrap_or(&lien);
                let remplace = Path::new(&format!("/proc/{pid}/root{chemin}")).exists();
                let etat = juger_exe(&lien, remplace, &montages).map_or("", etat);
                // Le programme lu par /proc/<pid>/exe : le fichier qui tourne, même effacé ; une fois par fichier.
                let empreinte = match std::fs::metadata(racine.join("exe")) {
                    Ok(m) => {
                        use std::os::unix::fs::MetadataExt;
                        empreintes
                            .entry((m.dev(), m.ino()))
                            .or_insert_with(|| {
                                if std::time::Instant::now() > fin {
                                    Empreinte::Delai
                                } else {
                                    super::empreinte(&racine.join("exe"), super::TAILLE_PROGRAMME)
                                }
                            })
                            .clone()
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Empreinte::Droits,
                    Err(_) => Empreinte::Illisible,
                };
                (lien, etat, empreinte)
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                illisibles += 1;
                (String::new(), "", Empreinte::Droits)
            }
            // Fil du noyau : pas de programme.
            Err(_) => (format!("[{nom}]"), "", Empreinte::Aucune),
        };
        liste.push(Processus {
            pid,
            ppid,
            compte: uid
                .map(|u| comptes.get(&u).cloned().unwrap_or_else(|| u.to_string()))
                .unwrap_or_default(),
            debut,
            programme,
            etat,
            ligne: if ligne.is_empty() { format!("[{nom}]") } else { ligne },
            empreinte,
        });
    }
    if illisibles > 0 {
        manques.push(super::Manque {
            quoi: bi!(
                "Programme et empreinte de {illisibles} processus d'autres comptes",
                "Program and fingerprint of {illisibles} processes of other accounts"
            ),
            raison: Raison::Droits,
        });
    }
    if proc_masque(&montages) && !super::privilegie() {
        manques.push(super::Manque {
            quoi: Bi::new(
                "Processus des autres comptes (/proc monté avec hidepid)",
                "Processes of other accounts (/proc mounted with hidepid)",
            ),
            raison: Raison::Droits,
        });
    }
    super::partie_processus(dossier, liste, manques)
}

/// Connexions et ports à l'écoute avec leur programme, voisins (ARP), adresses, routes, DNS et fichier hosts.
pub(super) fn reseau(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Réseau", "Network"));
    let mut f = Feuille::new(&p.titre);
    let ss = f.commande(Command::new("ss").args(["-tunap"]), 15, true);
    f.commande(Command::new("ip").args(["neigh", "show"]), 10, true);
    f.commande(Command::new("ip").args(["address", "show"]), 10, true);
    f.commande(Command::new("ip").args(["route", "show", "table", "all"]), 10, false);
    for chemin in ["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"] {
        f.fichier(Path::new(chemin), true);
    }
    f.commande(Command::new("resolvectl").arg("status"), 10, false);
    let connexions = ss.as_ref().map(|s| {
        s.lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with("Netid"))
            .count()
    });
    if ss.is_some() && !super::privilegie() {
        f.manques.push(super::Manque {
            quoi: Bi::new(
                "Programme des connexions des autres comptes",
                "Program of the other accounts' connections",
            ),
            raison: Raison::Droits,
        });
    }
    p.manques.append(&mut f.manques);
    if p.ecrire(
        dossier,
        "02-reseau.txt",
        &f.texte,
        Bi::new(
            "connexions et ports à l'écoute avec leur programme (ss -tunap), voisins du réseau local (table ARP), adresses, routes, DNS configuré et fichier hosts",
            "connections and listening ports with their program (ss -tunap), local network neighbours (ARP table), addresses, routes, configured DNS and hosts file",
        ),
    ) {
        p.compte = Some(match connexions {
            Some(n) => bi!("{n} connexions et ports à l'écoute", "{n} connections and listening ports"),
            None => bi!("{} source(s) lue(s)", "{} source(s) read", f.lues),
        });
    }
    p
}

/// Ce qui se lance tout seul : unités et minuteries de systemd, tâches cron, démarrage de session, bibliothèque
/// préchargée, fichiers du shell, clés SSH autorisées, modules du noyau.
pub(super) fn demarrage(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Ce qui se lance tout seul", "What starts by itself"));
    let mut f = Feuille::new(&p.titre);
    let m = maison();
    f.commande(
        Command::new("systemctl").args(["list-unit-files", "--no-pager", "--full"]),
        20,
        true,
    );
    f.commande(
        Command::new("systemctl").args(["list-units", "--all", "--no-pager", "--full", "--plain"]),
        20,
        false,
    );
    f.commande(
        Command::new("systemctl").args(["list-timers", "--all", "--no-pager"]),
        20,
        false,
    );
    f.commande(
        Command::new("systemctl").args(["--user", "list-unit-files", "--no-pager", "--full"]),
        20,
        false,
    );
    // Les unités posées à la main (hors paquets) : là où une persistance s'installe.
    f.dossier(Path::new("/etc/systemd/system"), 100, false);
    f.dossier(&m.join(".config/systemd/user"), 100, false);
    cron(&mut f);
    f.dossier(&m.join(".config/autostart"), 100, false);
    f.dossier(Path::new("/etc/xdg/autostart"), 100, false);
    for chemin in ["/etc/ld.so.preload", "/etc/rc.local", "/proc/modules"] {
        f.fichier(Path::new(chemin), false);
    }
    shell_et_ssh(&mut f);
    p.manques.append(&mut f.manques);
    if p.ecrire(
        dossier,
        "03-demarrage.txt",
        &f.texte,
        Bi::new(
            "ce qui se lance tout seul, tel quel : unités et minuteries de systemd, tâches cron, démarrage de session (autostart), bibliothèque préchargée (ld.so.preload), fichiers du shell, clés SSH autorisées, modules du noyau chargés",
            "what starts by itself, as is: systemd units and timers, cron jobs, session autostart, preloaded library (ld.so.preload), shell files, authorized SSH keys, loaded kernel modules",
        ),
    ) {
        p.compte = Some(bi!("{} source(s) lue(s)", "{} source(s) read", f.lues));
    }
    p
}

/// Comptes et groupes, sessions ouvertes, dernières connexions réussies et ratées.
pub(super) fn comptes(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Comptes", "Accounts"));
    let mut f = Feuille::new(&p.titre);
    f.fichier(Path::new("/etc/passwd"), true);
    f.fichier(Path::new("/etc/group"), true);
    f.commande(&mut Command::new("who"), 10, false);
    f.commande(
        Command::new("loginctl").args(["list-sessions", "--no-pager"]),
        10,
        false,
    );
    f.commande(Command::new("last").args(["-F", "-w", "-n", "1000"]), 20, false);
    f.commande(Command::new("wtmpdb").arg("last"), 20, false);
    f.commande(&mut Command::new("lastlog"), 20, false);
    f.commande(&mut Command::new("lastlog2"), 20, false);
    if super::privilegie() {
        f.commande(Command::new("lastb").args(["-F", "-w", "-n", "1000"]), 20, false);
    } else {
        f.section("$ lastb");
        f.ajouter(&Raison::Droits.note());
        f.manques.push(super::Manque {
            quoi: Bi::new("Connexions ratées (lastb)", "Failed logins (lastb)"),
            raison: Raison::Droits,
        });
    }
    let n = std::fs::read_to_string("/etc/passwd").map_or(0, |t| t.lines().filter(|l| l.contains(':')).count());
    p.manques.append(&mut f.manques);
    if p.ecrire(
        dossier,
        "04-comptes.txt",
        &f.texte,
        Bi::new(
            "comptes et groupes (passwd, group), sessions ouvertes, dernières connexions (last, lastlog) et connexions ratées (lastb, en root)",
            "accounts and groups (passwd, group), open sessions, last logins (last, lastlog) and failed logins (lastb, as root)",
        ),
    ) {
        p.compte = Some(bi!("{n} comptes", "{n} accounts"));
    }
    p
}

/// Le journal de systemd des 7 derniers jours, du plus récent au plus ancien, 50 Mo au plus ; sans systemd ou sans
/// journal, la fin des fichiers de /var/log.
pub(super) fn journaux(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Journaux", "Logs"));
    let titre = Bi::new("Journal du système, 7 jours", "System log, 7 days");
    let nom = "05-journal.txt";
    let mut commande = Command::new("journalctl");
    commande
        .args(["--since=-7d", "--reverse", "--no-pager", "-o", "short-iso"])
        .env("LC_ALL", "C.UTF-8");
    let ecrit = journal_vers(dossier, nom, &titre, &mut commande, 120, Garder::Debut);
    let vide = match ecrit {
        Err(e) => {
            p.manque(titre.clone(), Raison::Erreur(e.to_string()));
            true
        }
        Ok(None) => {
            p.manque(titre.clone(), Raison::Absente("journalctl".into()));
            true
        }
        Ok(Some(e)) => {
            p.fichiers.push(super::Produit {
                nom: nom.into(),
                contenu: Bi::new(
                    "le journal de systemd (journalctl) des 7 derniers jours, du plus récent au plus ancien, 50 Mo au plus",
                    "the systemd journal (journalctl) of the last 7 days, newest first, 50 MB at most",
                ),
            });
            if e.tronque {
                p.manque(
                    Bi::new("Journal du système, les plus anciens", "System log, the oldest entries"),
                    Raison::Borne(super::BORNE_JOURNAL),
                );
            }
            if e.delai {
                p.manque(titre.clone(), Raison::Delai(120));
            }
            if e.erreurs.contains("not seeing messages from other users")
                || e.erreurs.contains("insufficient permissions")
            {
                p.manque(
                    Bi::new(
                        "Journal : messages du système et des autres comptes",
                        "Log: messages of the system and other accounts",
                    ),
                    Raison::Droits,
                );
            }
            if let Some(code) = e.code.filter(|c| *c != 0) {
                let premiere = e.erreurs.lines().next().unwrap_or_default().to_string();
                p.manque(titre.clone(), Raison::Erreur(format!("code {code} : {premiere}")));
            }
            let rien = e.erreurs.contains("No journal files") || e.octets < 200;
            if !rien {
                let m = mo(e.octets);
                p.compte = Some(Bi::new(format!("{} (7 jours)", m.fr), format!("{} (7 days)", m.en)));
            }
            rien
        }
    };
    if vide {
        let avant = p.fichiers.len();
        let total = journaux_classiques(
            &mut p,
            dossier,
            &[
                "/var/log/syslog",
                "/var/log/messages",
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/kern.log",
            ],
        );
        if p.fichiers.len() > avant {
            let m = mo(total);
            p.compte = Some(Bi::new(format!("/var/log, {}", m.fr), format!("/var/log, {}", m.en)));
        } else {
            p.manque(Bi::new("Journal du système", "System log"), Raison::Introuvable);
        }
    }
    p
}

/// Les dossiers temporaires du système, où un programme dépose ce qu'il lance.
pub(super) fn endroits_temporaires() -> Vec<PathBuf> {
    ["/tmp", "/var/tmp", "/dev/shm"].iter().map(PathBuf::from).collect()
}

/// Les points de montage de cet ordinateur, que le parcours des fichiers récents ne traverse pas.
pub(super) fn points_de_montage() -> Vec<PathBuf> {
    montages_selon(&std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default())
}

/// Le point de montage est le cinquième champ de chaque ligne de mountinfo, ses espaces écrits en octal.
fn montages_selon(mountinfo: &str) -> Vec<PathBuf> {
    mountinfo
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(|c| PathBuf::from(crate::copier::sans_echappements(c)))
        .collect()
}

/// La place que peuvent prendre les journaux.
pub(super) fn place_des_journaux() -> u64 {
    super::BORNE_JOURNAL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn points_de_montage_lus() {
        let mountinfo = "22 1 0:21 / /tmp rw,nosuid shared:5 - tmpfs tmpfs rw\n\
            98 22 0:52 / /tmp/com.freerdp.client.cliprdr.108479 rw - fuse /dev/fuse rw\n\
            99 22 0:53 / /tmp/mon\\040dossier ro - fuse.essai essai ro\n";
        assert_eq!(
            montages_selon(mountinfo),
            [
                PathBuf::from("/tmp"),
                PathBuf::from("/tmp/com.freerdp.client.cliprdr.108479"),
                PathBuf::from("/tmp/mon dossier")
            ]
        );
        assert!(points_de_montage().contains(&PathBuf::from("/")));
    }

    #[test]
    fn comptes_et_status() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/zsh\n# rien\n";
        let c = comptes_de(passwd);
        assert_eq!(c.get(&0).map(String::as_str), Some("root"));
        assert_eq!(c.get(&1000).map(String::as_str), Some("alice"));
        assert_eq!(c.len(), 2);
        let status = "Name:\tmineur\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\nPid:\t4242\nPPid:\t1\n\
                      Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(lire_status(status), (Some(1), Some(1000), "mineur".to_string()));
    }

    #[test]
    fn heure_de_demarrage() {
        // Un nom piégé, avec espaces et parenthèses : les champs se comptent après la dernière.
        let mut champs = vec!["S"; 19];
        champs.push("250000");
        champs.extend(["0"; 20]);
        let stat = format!("4242 (a) b (c) {}", champs.join(" "));
        assert_eq!(debut_du_processus(&stat, 1_000_000, 100), Some(1_002_500));
        assert_eq!(debut_du_processus("4242 (court) S 1", 1_000_000, 100), None);
        // Le vrai /proc de ce processus : un démarrage après celui de l'ordinateur, et pas dans le futur.
        let vrai = std::fs::read_to_string("/proc/self/stat").unwrap();
        let debut = debut_du_processus(&vrai, btime().unwrap(), 100).unwrap();
        assert!(debut >= btime().unwrap());
    }

    /// Les processus de ce compte, lus pour de vrai : celui des tests en fait partie, avec son programme et son
    /// empreinte.
    #[test]
    fn processus_de_cette_machine() {
        let dossier = crate::reseau::dossier_local().join("processus");
        std::fs::create_dir_all(&dossier).unwrap();
        let p = processus(&dossier);
        assert!(p.compte.is_some(), "{p:?}");
        let texte = std::fs::read_to_string(dossier.join("01-processus.txt")).unwrap();
        let moi = std::process::id().to_string();
        let ligne = texte
            .lines()
            .find(|l| l.split('\t').next() == Some(moi.as_str()))
            .expect("le processus des tests manque");
        let champs: Vec<&str> = ligne.split('\t').collect();
        // Le programme des tests (debug, avec le client HTTPS) dépasse parfois la borne des empreintes : c'est dit.
        let gros = std::env::current_exe()
            .and_then(std::fs::metadata)
            .is_ok_and(|m| m.len() > super::super::TAILLE_EMPREINTE);
        if gros {
            assert_eq!(champs[4], "(trop gros/too big)", "{ligne}");
        } else {
            assert_eq!(champs[4].len(), 64, "{ligne}");
        }
        assert!(champs[5].starts_with('/'), "{ligne}");
    }
}
