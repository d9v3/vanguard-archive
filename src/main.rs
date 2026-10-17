//! netscan — vérifie la sécurité de ta machine et de ton réseau, propose et applique des correctifs.
//!
//! N'utilise le scan réseau que sur un réseau qui t'appartient ou que tu as le droit d'auditer.
//! Lancé sans argument, affiche un menu.

mod antivirus;
mod commande;
mod corriger;
mod donnees;
#[cfg(windows)]
mod gaming;
mod langue;
mod machine;
mod maj;
mod rapport;
mod reparer;
mod reseau;
mod risk;
mod scan;
mod surveillance;
mod ui;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

use machine::Audit;
use reseau::{Options, Rapport};
use ui::*;

#[derive(Parser)]
#[command(
    version,
    about = "Bilan de sécurité : cette machine + réseau local, avec correctifs. Sans argument : menu."
)]
struct Args {
    #[command(subcommand)]
    commande: Option<Commande>,
}

#[derive(Subcommand)]
enum Commande {
    /// Bilan complet : cette machine puis le réseau.
    #[command(visible_alias = "full")]
    Complet {
        /// Ouvrir aussi le rapport HTML dans le navigateur.
        #[arg(long)]
        html: bool,
    },
    /// Audit de cette machine (pare-feu, ports, SSH, mises à jour, chiffrement…).
    #[command(visible_alias = "audit")]
    Machine {
        #[arg(long)]
        json: bool,
    },
    /// Audit de la machine puis application guidée des correctifs.
    #[command(visible_alias = "fix")]
    Corriger,
    /// Scan du réseau : appareils, ports ouverts, risques, nouveautés depuis les scans précédents.
    #[command(visible_alias = "network")]
    Reseau {
        /// IP, réseau CIDR (10.0.0.0/24) ou plage (10.0.0.1-50). Par défaut : ton réseau local.
        cible: Option<String>,
        /// « courants » (défaut), « tous » (1-65535) ou liste « 22,80,8000-8100 ».
        #[arg(short, long, default_value = "courants")]
        ports: String,
        /// Délai de connexion par port, en millisecondes.
        #[arg(short, long, default_value_t = 500)]
        timeout: u64,
        /// Nombre de connexions simultanées.
        #[arg(short = 'j', long, default_value_t = 512)]
        parallele: usize,
        #[arg(long)]
        json: bool,
    },
    /// Recherche de malwares : ClamAV (Linux) ou Microsoft Defender (Windows).
    Antivirus {
        /// Tout le dossier personnel au lieu des endroits à risque.
        #[arg(long)]
        complet: bool,
    },
    /// Active ou désactive la surveillance horaire du réseau (notification si appareil inconnu).
    #[command(visible_alias = "monitor")]
    Surveillance {
        #[arg(value_parser = ["on", "off"])]
        etat: String,
    },
    /// Mises à jour : système, programmes, pilotes et firmware vérifiés d'un coup, puis installés après accord.
    #[command(visible_alias = "update", alias = "mises-a-jour")]
    Maj,
    /// Réparations courantes : réseau, navigation détournée, pare-feu, antivirus, fichiers système, disque, place, mises à jour, heure.
    #[command(visible_alias = "repair")]
    Reparer,
    /// Gaming (Windows) : composants pour les jeux (Visual C++, DirectX, .NET…) et réglages de Windows.
    #[cfg(windows)]
    Gaming,
    /// Sauvegarde la base des appareils et l'état de la surveillance dans un fichier JSON.
    #[command(visible_alias = "backup")]
    Sauvegarder {
        /// Fichier à écrire (par défaut : netscan-sauvegarde-AAAA-MM-JJ.json dans le dossier personnel ou Documents).
        fichier: Option<std::path::PathBuf>,
    },
    /// Ajoute une sauvegarde (ou un appareils.json) à la base actuelle, sans rien effacer.
    #[command(visible_alias = "restore")]
    Restaurer { fichier: std::path::PathBuf },
    /// Donne un surnom à un appareil de la base (« imprimante HP »), désigné par son IP ou sa MAC.
    #[command(visible_alias = "name")]
    Nommer {
        /// IP (sur le réseau actuel) ou adresse MAC de l'appareil.
        appareil: String,
        /// Le surnom ; vide pour le retirer.
        surnom: Vec<String>,
    },
    /// Scan silencieux + notifications (utilisé par la surveillance).
    #[command(hide = true)]
    Surveiller,
}

/// Résultats de la session, pour le rapport HTML et les corrections.
#[derive(Default)]
struct Session {
    audit: Option<Audit>,
    reseau: Option<Rapport>,
}

impl Session {
    async fn scanner_reseau(&mut self, cible: Option<String>, ports: &str) {
        match reseau::executer(Options::defaut(cible, ports)).await {
            Ok(r) => self.reseau = Some(r),
            Err(e) => eprintln!("{}", trf!("Scan réseau impossible : {e}", "Network scan failed: {e}")),
        }
    }

    async fn complet(&mut self) {
        self.audit = Some(machine::executer(false));
        self.scanner_reseau(None, "courants").await;
        titre(tr!("Bilan global", "Overall result"));
        let m = self.audit.as_ref().filter(|a| a.fiable()).map(|a| a.score);
        let r = self.reseau.as_ref().map(|r| r.score_global);
        match m {
            Some(m) => afficher_note(tr!("Cette machine", "This machine"), m),
            None => trp!(
                "  Cette machine : pas de note (vérifications impossibles)",
                "  This machine: no grade (checks could not be done)"
            ),
        }
        if let Some(r) = r {
            afficher_note(tr!("Réseau", "Network"), r);
        }
        if let Some(g) = [m, r].into_iter().flatten().min() {
            afficher_note(tr!("Global", "Overall"), g);
        }
        let a_corriger = self.audit.as_ref().is_some_and(|a| {
            a.constats
                .iter()
                .any(|c| c.correctif.as_ref().is_some_and(|k| k.automatique))
        });
        if a_corriger {
            trp!(
                "\n  🔧 Des corrections sont possibles : choix « 2 » du menu ou « netscan corriger ».",
                "\n  🔧 Fixes are available: menu choice “2” or “netscan fix”."
            );
        }
        let _ = rapport::generer(self.audit.as_ref(), self.reseau.as_ref());
    }

    fn corriger(&mut self) {
        if self.audit.is_none() {
            self.audit = Some(machine::executer(false));
        }
        if let Some(nouveau) = corriger::corriger(self.audit.as_ref().unwrap(), self.reseau.as_ref()) {
            self.audit = Some(nouveau);
        }
    }
}

fn nommer(appareil: &str, surnom: &str) {
    let surnom = Some(surnom.trim()).filter(|s| !s.is_empty());
    match reseau::nommer(appareil, surnom) {
        Ok(qui) => match surnom {
            Some(s) => trp!(
                "  {VERT}✔{RESET} {qui} s'appelle maintenant « {s} ».",
                "  {VERT}✔{RESET} {qui} is now called “{s}”."
            ),
            None => trp!(
                "  {VERT}✔{RESET} Surnom retiré pour {qui}.",
                "  {VERT}✔{RESET} Nickname removed for {qui}."
            ),
        },
        Err(e) => println!("  ✖ {e}"),
    }
}

async fn menu() {
    let mut s = Session::default();
    loop {
        print!("\x1b[2J\x1b[H");
        trp!(
            "{GRAS}netscan{RESET} — sécurité de ta machine et de ton réseau\n",
            "{GRAS}netscan{RESET} — security of your machine and your network\n"
        );
        trp!(
            "  1. Bilan complet (machine + réseau)       {GRIS}← commencer ici{RESET}",
            "  1. Full check (machine + network)         {GRIS}← start here{RESET}"
        );
        trp!("  2. Corriger les problèmes trouvés", "  2. Fix the problems found");
        trp!("  3. Audit de cette machine", "  3. Audit this machine");
        trp!("  4. Scan du réseau local", "  4. Scan the local network");
        trp!(
            "  5. Scan approfondi d'un appareil (tous les ports)",
            "  5. Deep scan of one device (all ports)"
        );
        trp!("  6. Antivirus : analyse rapide", "  6. Antivirus: quick scan");
        trp!(
            "  7. Antivirus : analyse complète du dossier personnel",
            "  7. Antivirus: full scan of the home folder"
        );
        trp!(
            "  8. Ouvrir le rapport détaillé (navigateur)",
            "  8. Open the detailed report (browser)"
        );
        let etat = if surveillance::active() {
            format!("{VERT}{}{RESET}", tr!("activée", "on"))
        } else {
            format!("{GRIS}{}{RESET}", tr!("désactivée", "off"))
        };
        trp!(
            "  9. Surveillance du réseau toutes les heures : {etat}",
            "  9. Hourly network monitoring: {etat}"
        );
        trp!(
            "  u. Mises à jour : tout vérifier et installer (système, programmes, pilotes)",
            "  u. Updates: check and install everything (system, programs, drivers)"
        );
        trp!(
            "  r. Réparer (réseau, pare-feu, antivirus, disque, système…)",
            "  r. Repair (network, firewall, antivirus, disk, system…)"
        );
        #[cfg(windows)]
        trp!(
            "  g. Gaming : composants (Visual C++, DirectX, .NET…) et réglages Windows",
            "  g. Gaming: components (Visual C++, DirectX, .NET…) and Windows settings"
        );
        trp!(
            "  n. Nommer un appareil (« imprimante HP »)",
            "  n. Name a device (“HP printer”)"
        );
        trp!(
            "  d. Données : sauvegarder ou restaurer (surnoms, historique des réseaux)",
            "  d. Data: back up or restore (nicknames, network history)"
        );
        trp!("  q. Quitter\n", "  q. Quit\n");
        let choix = demander(tr!("Choix : ", "Choice: "));
        println!();
        match choix.as_str() {
            "1" => s.complet().await,
            "2" => s.corriger(),
            "3" => s.audit = Some(machine::executer(false)),
            "4" => s.scanner_reseau(None, "courants").await,
            "5" => {
                let ip = demander(tr!(
                    "Adresse IP de l'appareil (ex. 10.0.0.1) : ",
                    "IP address of the device (e.g. 10.0.0.1): "
                ));
                s.scanner_reseau(Some(ip), "tous").await;
            }
            "6" => antivirus::analyser(false),
            "7" => antivirus::analyser(true),
            "8" => {
                if s.audit.is_none() && s.reseau.is_none() {
                    s.complet().await;
                }
                rapport::ouvrir(s.audit.as_ref(), s.reseau.as_ref());
            }
            "9" => surveillance::activer(!surveillance::active()),
            "u" | "U" => maj::executer(),
            "r" | "R" => reparer::menu(),
            #[cfg(windows)]
            "g" | "G" => gaming::menu(),
            "n" | "N" => {
                let qui = demander(tr!(
                    "IP ou adresse MAC de l'appareil : ",
                    "IP or MAC address of the device: "
                ));
                let surnom = demander(tr!(
                    "Surnom (vide pour le retirer) : ",
                    "Nickname (empty to remove it): "
                ));
                nommer(&qui, &surnom);
            }
            "d" | "D" => donnees::menu(),
            "q" | "Q" => break,
            _ => continue,
        }
        demander(&trf!(
            "\n{GRIS}Entrée pour revenir au menu…{RESET}",
            "\n{GRIS}Enter to go back to the menu…{RESET}"
        ));
    }
}

/// La ligne de commande, avec son aide en anglais si l'interface est en anglais (l'aide écrite plus haut, en
/// commentaires, est la version française).
fn ligne_de_commande() -> clap::Command {
    let c = Args::command();
    if !langue::anglais() {
        return c;
    }
    let mut c = c.about("Security check: this machine + local network, with fixes. No argument: menu.");
    let aides: &[(&str, &str)] = &[
        ("complet", "Full check: this machine, then the network"),
        (
            "machine",
            "Audit this machine (firewall, ports, SSH, updates, encryption…)",
        ),
        ("corriger", "Audit the machine, then apply the fixes step by step"),
        (
            "reseau",
            "Network scan: devices, open ports, risks, changes since previous scans",
        ),
        (
            "antivirus",
            "Malware scan: ClamAV (Linux) or Microsoft Defender (Windows)",
        ),
        (
            "surveillance",
            "Turn hourly network monitoring on or off (notification for unknown devices)",
        ),
        (
            "maj",
            "Updates: system, programs, drivers and firmware checked at once, then installed with your consent",
        ),
        (
            "reparer",
            "Common repairs: network, hijacked browsing, firewall, antivirus, system files, disk, space, updates, time",
        ),
        (
            "sauvegarder",
            "Back up the device database and the monitoring state to a JSON file",
        ),
        (
            "restaurer",
            "Add a backup (or an appareils.json) to the current database, without erasing anything",
        ),
        (
            "nommer",
            "Give a nickname to a device of the database (“HP printer”), by its IP or MAC",
        ),
        #[cfg(windows)]
        (
            "gaming",
            "Gaming (Windows): components for games (Visual C++, DirectX, .NET…) and Windows settings",
        ),
    ];
    for &(nom, aide) in aides {
        c = c.mut_subcommand(nom, |s| s.about(aide));
    }
    c.mut_subcommand("complet", |s| {
        s.mut_arg("html", |a| a.help("Also open the HTML report in the browser"))
    })
    .mut_subcommand("reseau", |s| {
        s.mut_arg("cible", |a| {
            a.help("IP, CIDR network (10.0.0.0/24) or range (10.0.0.1-50). Default: your local network")
        })
        .mut_arg("ports", |a| {
            a.help("“courants”/“common” (default), “tous”/“all” (1-65535) or a list “22,80,8000-8100”")
        })
        .mut_arg("timeout", |a| a.help("Connection timeout per port, in milliseconds"))
        .mut_arg("parallele", |a| a.help("Number of simultaneous connections"))
    })
    .mut_subcommand("antivirus", |s| {
        s.mut_arg("complet", |a| {
            a.help("The whole home folder instead of the risky places")
        })
    })
    .mut_subcommand("sauvegarder", |s| {
        s.mut_arg("fichier", |a| {
            a.help("File to write (default: netscan-sauvegarde-YYYY-MM-DD.json in the home or Documents folder)")
        })
    })
    .mut_subcommand("nommer", |s| {
        s.mut_arg("appareil", |a| {
            a.help("IP (on the current network) or MAC address of the device")
        })
        .mut_arg("surnom", |a| a.help("The nickname; empty to remove it"))
    })
}

#[tokio::main]
async fn main() {
    // Couleurs ANSI dans l'ancienne console Windows (Windows Terminal les gère déjà).
    #[cfg(windows)]
    let _ = enable_ansi_support::enable_ansi_support();
    let args = Args::from_arg_matches(&ligne_de_commande().get_matches()).unwrap_or_else(|e| e.exit());
    match args.commande {
        None => menu().await,
        Some(Commande::Complet { html }) => {
            let mut s = Session::default();
            s.complet().await;
            if html {
                rapport::ouvrir(s.audit.as_ref(), s.reseau.as_ref());
            }
        }
        Some(Commande::Machine { json }) => {
            machine::executer(json);
        }
        Some(Commande::Corriger) => Session::default().corriger(),
        Some(Commande::Reseau {
            cible,
            ports,
            timeout,
            parallele,
            json,
        }) => {
            let o = Options {
                cible,
                ports,
                timeout,
                parallele,
                json,
                silencieux: false,
            };
            if let Err(e) = reseau::executer(o).await {
                eprintln!("{}", trf!("Erreur : {e}", "Error: {e}"));
                std::process::exit(1);
            }
        }
        Some(Commande::Antivirus { complet }) => antivirus::analyser(complet),
        Some(Commande::Surveillance { etat }) => surveillance::activer(etat == "on"),
        Some(Commande::Surveiller) => surveillance::surveiller().await,
        Some(Commande::Maj) => maj::executer(),
        Some(Commande::Reparer) => reparer::menu(),
        #[cfg(windows)]
        Some(Commande::Gaming) => gaming::menu(),
        Some(Commande::Sauvegarder { fichier }) => donnees::sauvegarder(fichier),
        Some(Commande::Restaurer { fichier }) => donnees::restaurer(&fichier),
        Some(Commande::Nommer { appareil, surnom }) => nommer(&appareil, &surnom.join(" ")),
    }
}
