//! Les traces sous macOS : ps pour les processus, lsof et netstat pour le réseau, launchd (agents et démons), cron,
//! fichiers du shell, comptes (dscl, last), journal unifié (log show) et journal des installations.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::unix::{cron, journal_vers, journaux_classiques, maison, mo, shell_et_ssh};
use super::{Bi, Empreinte, Feuille, Manque, Partie, Processus, Raison, bi, lire_args, lire_ps};
use crate::commande::Garder;

pub(super) fn processus(dossier: &Path) -> Partie {
    let ps = |format: &str| {
        crate::commande::lancer(Command::new("ps").args(["-axww", "-o", format]).env("LC_ALL", "C"), 20)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
    };
    let Some(liste) = ps("pid=,ppid=,user=,lstart=,comm=") else {
        let mut p = Partie::new(Bi::new("Processus", "Processes"));
        p.manque(Bi::meme("ps"), Raison::Absente("ps".into()));
        return p;
    };
    let args = ps("pid=,args=").map(|s| lire_args(&s)).unwrap_or_default();
    let mut empreintes: HashMap<String, Empreinte> = HashMap::new();
    let fin = std::time::Instant::now() + super::DELAI_EMPREINTES;
    let liste: Vec<Processus> = lire_ps(&liste)
        .into_iter()
        .map(|(pid, ppid, compte, debut, programme)| {
            let empreinte = if programme.starts_with('/') {
                empreintes
                    .entry(programme.clone())
                    .or_insert_with(|| {
                        if std::time::Instant::now() > fin {
                            Empreinte::Delai
                        } else {
                            super::empreinte(Path::new(&programme), super::TAILLE_PROGRAMME)
                        }
                    })
                    .clone()
            } else {
                Empreinte::Aucune
            };
            Processus {
                pid,
                ppid,
                compte,
                debut,
                ligne: args.get(&pid).cloned().unwrap_or_default(),
                programme,
                etat: "",
                empreinte,
            }
        })
        .collect();
    super::partie_processus(dossier, liste, Vec::new())
}

pub(super) fn reseau(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Réseau", "Network"));
    let mut f = Feuille::new(&p.titre);
    let lsof = f.commande(Command::new("lsof").args(["-nP", "-i"]), 30, true);
    f.commande(Command::new("netstat").args(["-an"]), 20, false);
    f.commande(Command::new("arp").args(["-an"]), 15, true);
    f.commande(Command::new("netstat").args(["-rn"]), 15, false);
    f.commande(Command::new("scutil").arg("--dns"), 15, true);
    f.commande(Command::new("scutil").arg("--proxy"), 15, false);
    f.fichier(Path::new("/etc/hosts"), true);
    f.fichier(Path::new("/etc/resolv.conf"), false);
    if lsof.is_some() && !super::privilegie() {
        f.manques.push(Manque {
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
            "connexions et ports à l'écoute avec leur programme (lsof -nP -i), toutes les connexions (netstat -an), voisins du réseau local (arp -an), routes, DNS (scutil --dns), proxy et fichier hosts",
            "connections and listening ports with their program (lsof -nP -i), all connections (netstat -an), local network neighbours (arp -an), routes, DNS (scutil --dns), proxy and hosts file",
        ),
    ) {
        p.compte = Some(match lsof {
            Some(s) => bi!(
                "{} connexions et ports à l'écoute",
                "{} connections and listening ports",
                s.lines().count().saturating_sub(1)
            ),
            None => bi!("{} source(s) lue(s)", "{} source(s) read", f.lues),
        });
    }
    p
}

/// Les agents et démons de launchd d'un dossier : la liste, puis chaque .plist lisible par plutil (souvent binaire).
fn plists(f: &mut Feuille, dossier: &Path) {
    f.dossier(dossier, 0, false);
    let mut fichiers: Vec<PathBuf> = std::fs::read_dir(dossier)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|c| c.extension().is_some_and(|e| e == "plist"))
        .collect();
    fichiers.sort();
    for c in fichiers.iter().take(200) {
        f.commande(Command::new("plutil").arg("-p").arg(c), 10, false);
    }
}

pub(super) fn demarrage(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Ce qui se lance tout seul", "What starts by itself"));
    let mut f = Feuille::new(&p.titre);
    let m = maison();
    f.commande(Command::new("launchctl").arg("list"), 20, true);
    plists(&mut f, &m.join("Library/LaunchAgents"));
    plists(&mut f, Path::new("/Library/LaunchAgents"));
    plists(&mut f, Path::new("/Library/LaunchDaemons"));
    f.dossier(Path::new("/Library/StartupItems"), 0, false);
    // Les éléments d'ouverture et de fond (applications, agents) : leur base ne se lit qu'en root.
    if super::privilegie() {
        f.commande(Command::new("sfltool").arg("dumpbtm"), 30, false);
    } else {
        f.section("$ sfltool dumpbtm");
        f.ajouter(&Raison::Droits.note());
        f.manques.push(Manque {
            quoi: Bi::new(
                "Éléments d'ouverture et de fond (sfltool dumpbtm)",
                "Login and background items (sfltool dumpbtm)",
            ),
            raison: Raison::Droits,
        });
    }
    f.commande(Command::new("profiles").arg("list"), 20, false);
    f.commande(Command::new("kmutil").args(["showloaded", "--list-only"]), 30, false);
    cron(&mut f);
    shell_et_ssh(&mut f);
    p.manques.append(&mut f.manques);
    if p.ecrire(
        dossier,
        "03-demarrage.txt",
        &f.texte,
        Bi::new(
            "ce qui se lance tout seul, tel quel : launchctl list, agents et démons de launchd (chaque .plist par plutil -p), éléments d'ouverture (sfltool, en root), profils de configuration, extensions du noyau chargées, tâches cron, fichiers du shell, clés SSH autorisées",
            "what starts by itself, as is: launchctl list, launchd agents and daemons (each .plist through plutil -p), login items (sfltool, as root), configuration profiles, loaded kernel extensions, cron jobs, shell files, authorized SSH keys",
        ),
    ) {
        p.compte = Some(bi!("{} source(s) lue(s)", "{} source(s) read", f.lues));
    }
    p
}

pub(super) fn comptes(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Comptes", "Accounts"));
    let mut f = Feuille::new(&p.titre);
    let liste = f.commande(
        Command::new("dscl").args([".", "-list", "/Users", "UniqueID"]),
        15,
        true,
    );
    f.commande(
        Command::new("dscl").args([".", "-read", "/Groups/admin", "GroupMembership"]),
        15,
        true,
    );
    f.commande(&mut Command::new("who"), 10, false);
    f.commande(Command::new("last").args(["-100"]), 20, true);
    p.manques.append(&mut f.manques);
    if p.ecrire(
        dossier,
        "04-comptes.txt",
        &f.texte,
        Bi::new(
            "comptes (dscl), administrateurs (groupe admin), sessions ouvertes (who), dernières connexions (last)",
            "accounts (dscl), administrators (admin group), open sessions (who), last logins (last)",
        ),
    ) {
        p.compte = Some(match liste {
            Some(l) => bi!("{} comptes", "{} accounts", l.lines().count()),
            None => bi!("{} source(s) lue(s)", "{} source(s) read", f.lues),
        });
    }
    p
}

/// Le journal unifié du dernier jour (log show est lent : deux minutes au plus, et seule la fin, la plus récente, est
/// gardée dans la borne), puis la fin du journal des installations.
pub(super) fn journaux(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Journaux", "Logs"));
    let titre = Bi::new("Journal unifié, 1 jour", "Unified log, 1 day");
    let nom = "05-log-show.txt";
    let mut commande = Command::new("log");
    commande.args(["show", "--last", "1d", "--style", "syslog"]);
    match journal_vers(dossier, nom, &titre, &mut commande, 120, Garder::Fin) {
        Err(e) => p.manque(titre.clone(), Raison::Erreur(e.to_string())),
        Ok(None) => p.manque(titre.clone(), Raison::Absente("log".into())),
        Ok(Some(e)) => {
            p.fichiers.push(super::Produit {
                nom: nom.into(),
                contenu: Bi::new(
                    "le journal unifié de macOS (log show) du dernier jour, la fin la plus récente, 50 Mo au plus",
                    "macOS's unified log (log show) of the last day, the most recent end, 50 MB at most",
                ),
            });
            if e.tronque {
                p.manque(
                    Bi::new("Journal unifié, le plus ancien", "Unified log, the oldest part"),
                    Raison::Borne(super::BORNE_JOURNAL),
                );
            }
            if e.delai {
                p.manque(
                    Bi::new("Journal unifié, la suite", "Unified log, the rest"),
                    Raison::Delai(120),
                );
            }
            if let Some(code) = e.code.filter(|c| *c != 0) {
                let premiere = e.erreurs.lines().next().unwrap_or_default().to_string();
                p.manque(titre.clone(), Raison::Erreur(format!("code {code} : {premiere}")));
            }
            let m = mo(e.octets);
            p.compte = Some(Bi::new(format!("{} (1 jour)", m.fr), format!("{} (1 day)", m.en)));
        }
    }
    journaux_classiques(&mut p, dossier, &["/var/log/install.log"]);
    p
}

/// Les dossiers temporaires et le dossier partagé, où un programme dépose ce qu'il lance.
pub(super) fn endroits_temporaires() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::env::var_os("TMPDIR").map(PathBuf::from).into_iter().collect();
    v.extend(
        ["/private/tmp", "/private/var/tmp", "/Users/Shared"]
            .iter()
            .map(PathBuf::from),
    );
    v
}

/// Pas de liste des montages ici : le parcours s'arrête aux dossiers d'un autre appareil que leur racine.
pub(super) fn points_de_montage() -> Vec<PathBuf> {
    Vec::new()
}

/// La place que peuvent prendre les journaux : le journal unifié borné et la fin du journal des installations.
pub(super) fn place_des_journaux() -> u64 {
    super::BORNE_JOURNAL + (10 << 20)
}
