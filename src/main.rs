//! sentinel — vérifie la sécurité de ta machine et de ton réseau, propose et applique des correctifs.
//!
//! N'utilise le scan réseau que sur un réseau qui t'appartient ou que tu as le droit d'auditer.
//! Lancé sans argument, affiche un menu.

mod antivirus;
mod commande;
mod connexion;
mod corriger;
mod donnees;
mod fuites;
#[cfg(windows)]
mod gaming;
mod historique;
mod integrite;
mod isoler;
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
mod upnp;

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
        /// Afficher le rapport en texte simple (Markdown) dans le terminal : sans navigateur ni affichage graphique.
        #[arg(long, visible_alias = "text")]
        texte: bool,
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
    /// Test de connexion pour le jeu : ping, gigue, pertes, débit et bufferbloat.
    #[command(visible_alias = "connection")]
    Connexion,
    /// Intégrité des fichiers critiques : référence d'empreintes BLAKE3, puis ce qui a changé depuis.
    #[command(visible_alias = "integrity")]
    Integrite {
        /// Prendre l'état actuel comme nouvelle référence (après une mise à jour du système).
        #[arg(long, visible_alias = "accept")]
        accepter: bool,
        /// Surveiller les fichiers critiques en direct jusqu'à Ctrl-C.
        #[arg(long, visible_alias = "live")]
        temps_reel: bool,
    },
    /// Lance un programme inconnu dans un bac à sable : pas de réseau, dossier personnel invisible.
    #[command(visible_alias = "sandbox")]
    Isoler {
        /// Programme ou script à lancer.
        fichier: std::path::PathBuf,
    },
    /// Fuites d'adresse courriel : l'adresse est envoyée au service de recherche, après ton accord.
    #[command(visible_alias = "email")]
    Courriel,
    /// Vérifie si des mots de passe ont fuité (Have I Been Pwned) ; seuls 5 caractères de leur empreinte partent.
    #[command(name = "motdepasse", visible_alias = "password")]
    MotDePasse,
    /// Sauvegarde la base des appareils et l'état de la surveillance dans un fichier JSON.
    #[command(visible_alias = "backup")]
    Sauvegarder {
        /// Fichier à écrire (par défaut : sentinel-sauvegarde-AAAA-MM-JJ.json dans le dossier personnel ou Documents).
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
        let (precedent, nouveau) = historique::enregistrer(self.audit.as_ref(), self.reseau.as_ref());
        if let Some(p) = precedent {
            historique::afficher_changements(&p, &nouveau);
        }
        let a_corriger = self.audit.as_ref().is_some_and(|a| {
            a.constats
                .iter()
                .any(|c| c.correctif.as_ref().is_some_and(|k| k.automatique))
        });
        if a_corriger {
            trp!(
                "\n  🔧 Des corrections sont possibles : choix « 2 » du menu ou « sentinel corriger ».",
                "\n  🔧 Fixes are available: menu choice “2” or “sentinel fix”."
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

/// Une ligne du menu : la touche en blanc vif, le texte, et une précision en gris à droite.
fn option(touche: &str, texte: &str, precision: &str) {
    if precision.is_empty() {
        println!("   {TOUCHE}{touche:>2}{RESET}  {texte}");
    } else {
        println!(
            "   {TOUCHE}{touche:>2}{RESET}  {}{DISCRET}{precision}{RESET}",
            ajuster(texte, 36)
        );
    }
}

/// État affiché en tête du menu : dernier bilan, dernier test de connexion, clé, surveillance.
fn etat_du_menu(surveillance_active: bool) {
    let historique = historique::charger();
    match historique.last() {
        Some(b) => {
            let note = |s: Option<u32>| s.map_or_else(|| "—".to_string(), etiquette_note);
            trp!(
                "  {GRIS}Dernier bilan{RESET}  {}   machine {}   réseau {}",
                "  {GRIS}Last check{RESET}     {}   machine {}   network {}",
                b.date,
                note(b.machine),
                note(b.reseau)
            );
        }
        None => trp!(
            "  {GRIS}Aucun bilan encore : commence par 1.{RESET}",
            "  {GRIS}No check yet: start with 1.{RESET}"
        ),
    }
    if let Some(c) = connexion::historique().last() {
        let debit = |d: Option<f64>| d.map_or_else(|| "?".to_string(), |d| format!("{d:.0}"));
        let bufferbloat = c
            .hausse_ms
            .map(|h| {
                let (n, niveau) = connexion::note_bufferbloat(h);
                format!("{}{n}{RESET}", couleur(niveau))
            })
            .unwrap_or_default();
        trp!(
            "  {GRIS}Connexion{RESET}      {:.0} ms · ↓ {} ↑ {} Mbit/s · bufferbloat {bufferbloat}",
            "  {GRIS}Connection{RESET}     {:.0} ms · ↓ {} ↑ {} Mbit/s · bufferbloat {bufferbloat}",
            c.internet_ms,
            debit(c.descendant),
            debit(c.montant)
        );
    }
    let cle = if reseau::cle_usb().is_some() {
        format!(
            "{VERT}{}{RESET}",
            tr!("clé SENTINEL branchée", "SENTINEL key plugged in")
        )
    } else {
        format!("{GRIS}{}{RESET}", tr!("clé non branchée", "key not plugged in"))
    };
    let surveillance = if surveillance_active {
        format!("{VERT}{}{RESET}", tr!("surveillance active", "monitoring on"))
    } else {
        format!("{GRIS}{}{RESET}", tr!("surveillance coupée", "monitoring off"))
    };
    println!("  {cle} {GRIS}·{RESET} {surveillance}");
}

async fn menu() {
    let mut s = Session::default();
    loop {
        print!("\x1b[2J\x1b[H");
        cadre(
            &format!("{ACCENT}SENTINEL{RESET} {GRIS}{}{RESET}", env!("CARGO_PKG_VERSION")),
            tr!(
                "sécurité de ta machine et de ton réseau",
                "security of your machine and your network"
            ),
        );
        let surveillance_active = surveillance::active();
        etat_du_menu(surveillance_active);

        section(tr!("BILAN DE SÉCURITÉ", "SECURITY CHECK"));
        option(
            "1",
            tr!("Bilan complet : machine + réseau", "Full check: machine + network"),
            tr!("← commencer ici", "← start here"),
        );
        option("2", tr!("Corriger les problèmes trouvés", "Fix the problems found"), "");
        option("3", tr!("Audit de cette machine", "Audit this machine"), "");
        option(
            "8",
            tr!("Rapport détaillé dans le navigateur", "Detailed report in the browser"),
            "",
        );

        section(tr!("RÉSEAU LOCAL", "LOCAL NETWORK"));
        option(
            "4",
            tr!("Scanner le réseau", "Scan the network"),
            tr!("appareils, ports, nouveautés", "devices, ports, changes"),
        );
        option(
            "5",
            tr!("Scan approfondi d'un appareil", "Deep scan of one device"),
            tr!("tous les ports", "all ports"),
        );
        option(
            "n",
            tr!("Nommer un appareil", "Name a device"),
            tr!("« imprimante HP »", "“HP printer”"),
        );
        option(
            "9",
            tr!("Surveillance toutes les heures", "Hourly monitoring"),
            if surveillance_active {
                tr!("activée", "on")
            } else {
                tr!("désactivée", "off")
            },
        );

        section(tr!("CONNEXION", "CONNECTION"));
        option(
            "c",
            tr!("Test pour le jeu", "Gaming test"),
            tr!("ping, gigue, débit, bufferbloat", "ping, jitter, speed, bufferbloat"),
        );

        section(tr!("PROTECTION", "PROTECTION"));
        option("6", tr!("Antivirus : analyse rapide", "Antivirus: quick scan"), "");
        option(
            "7",
            tr!("Antivirus : analyse complète", "Antivirus: full scan"),
            tr!("dossier personnel", "home folder"),
        );
        option(
            "p",
            tr!("Mots de passe : ont-ils fuité ?", "Passwords: have they leaked?"),
            tr!("rien n'est envoyé en clair", "nothing sent in clear"),
        );
        option(
            "e",
            tr!("Adresse courriel : a-t-elle fuité ?", "Email address: has it leaked?"),
            tr!("avec ton accord", "with your consent"),
        );
        option(
            "b",
            tr!(
                "Bac à sable : lancer un programme inconnu",
                "Sandbox: run an unknown program"
            ),
            tr!("sans réseau, isolé", "no network, isolated"),
        );
        option(
            "i",
            tr!("Intégrité des fichiers critiques", "Critical file integrity"),
            tr!("comptes, sudo, SSH, démarrage…", "accounts, sudo, SSH, startup…"),
        );

        section(tr!("ENTRETIEN", "MAINTENANCE"));
        option(
            "u",
            tr!("Mises à jour", "Updates"),
            tr!("système, programmes, pilotes", "system, programs, drivers"),
        );
        option(
            "r",
            tr!("Réparer et nettoyer", "Repair and clean up"),
            tr!("réseau, disque, système…", "network, disk, system…"),
        );
        #[cfg(windows)]
        option(
            "g",
            tr!("Gaming", "Gaming"),
            tr!("composants et réglages de Windows", "components and Windows settings"),
        );
        option(
            "d",
            tr!("Données", "Data"),
            tr!("sauvegarder ou restaurer", "back up or restore"),
        );

        println!();
        option("q", tr!("Quitter", "Quit"), "");
        println!();
        let choix = demander(&format!("  {ACCENT}›{RESET} {}", tr!("Choix : ", "Choice: ")));
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
            "c" | "C" => connexion::tester().await,
            "p" | "P" => fuites::verifier(),
            "e" | "E" => fuites::verifier_courriel(),
            "b" | "B" => {
                let chemin = demander(tr!("  Programme à isoler (chemin) : ", "  Program to isolate (path): "));
                let chemin = chemin.trim().trim_matches(['"', '\'']);
                if !chemin.is_empty() {
                    isoler::isoler(std::path::Path::new(chemin));
                }
            }
            "i" | "I" => integrite::verifier(false),
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
            "connexion",
            "Connection test for gaming: ping, jitter, packet loss, speed and bufferbloat",
        ),
        (
            "isoler",
            "Run an unknown program in a sandbox: no network, home folder hidden",
        ),
        (
            "courriel",
            "Email address leaks: the address is sent to the search service, after your consent",
        ),
        (
            "integrite",
            "Critical file integrity: BLAKE3 fingerprint reference, then what changed since",
        ),
        (
            "motdepasse",
            "Check whether passwords have leaked (Have I Been Pwned); only 5 characters of their fingerprint are sent",
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
            .mut_arg("texte", |a| {
                a.help(
                    "Show the report as plain text (Markdown) in the terminal: no browser or graphical display needed",
                )
            })
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
    .mut_subcommand("isoler", |s| {
        s.mut_arg("fichier", |a| a.help("Program or script to run"))
    })
    .mut_subcommand("integrite", |s| {
        s.mut_arg("accepter", |a| {
            a.help("Take the current state as the new reference (after a system update)")
        })
        .mut_arg("temps_reel", |a| a.help("Watch the critical files live until Ctrl-C"))
    })
    .mut_subcommand("sauvegarder", |s| {
        s.mut_arg("fichier", |a| {
            a.help("File to write (default: sentinel-sauvegarde-YYYY-MM-DD.json in the home or Documents folder)")
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
        Some(Commande::Complet { html, texte }) => {
            let mut s = Session::default();
            s.complet().await;
            if html {
                rapport::ouvrir(s.audit.as_ref(), s.reseau.as_ref());
            }
            if texte {
                println!("\n{}", rapport::markdown(s.audit.as_ref(), s.reseau.as_ref()));
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
        Some(Commande::Connexion) => connexion::tester().await,
        Some(Commande::MotDePasse) => fuites::verifier(),
        Some(Commande::Courriel) => fuites::verifier_courriel(),
        Some(Commande::Isoler { fichier }) => isoler::isoler(&fichier),
        Some(Commande::Integrite { accepter, temps_reel }) => {
            if temps_reel {
                integrite::temps_reel();
            } else {
                integrite::verifier(accepter);
            }
        }
        Some(Commande::Sauvegarder { fichier }) => donnees::sauvegarder(fichier),
        Some(Commande::Restaurer { fichier }) => donnees::restaurer(&fichier),
        Some(Commande::Nommer { appareil, surnom }) => nommer(&appareil, &surnom.join(" ")),
    }
}
