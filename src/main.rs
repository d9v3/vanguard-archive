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
mod machine;
mod maj;
mod rapport;
mod reparer;
mod reseau;
mod risk;
mod scan;
mod surveillance;
mod ui;

use clap::{Parser, Subcommand};

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
    Complet {
        /// Ouvrir aussi le rapport HTML dans le navigateur.
        #[arg(long)]
        html: bool,
    },
    /// Audit de cette machine (pare-feu, ports, SSH, mises à jour, chiffrement…).
    Machine {
        #[arg(long)]
        json: bool,
    },
    /// Audit de la machine puis application guidée des correctifs.
    Corriger,
    /// Scan du réseau : appareils, ports ouverts, risques, nouveautés depuis les scans précédents.
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
    Surveillance {
        #[arg(value_parser = ["on", "off"])]
        etat: String,
    },
    /// Mises à jour : système, programmes, pilotes et firmware vérifiés d'un coup, puis installés après accord.
    #[command(alias = "mises-a-jour")]
    Maj,
    /// Réparations courantes : réseau, navigation détournée, pare-feu, antivirus, fichiers système, disque, place, mises à jour, heure.
    Reparer,
    /// Gaming (Windows) : composants pour les jeux (Visual C++, DirectX, .NET…) et réglages de Windows.
    #[cfg(windows)]
    Gaming,
    /// Sauvegarde la base des appareils et l'état de la surveillance dans un fichier JSON.
    Sauvegarder {
        /// Fichier à écrire (par défaut : netscan-sauvegarde-AAAA-MM-JJ.json dans le dossier personnel ou Documents).
        fichier: Option<std::path::PathBuf>,
    },
    /// Ajoute une sauvegarde (ou un appareils.json) à la base actuelle, sans rien effacer.
    Restaurer { fichier: std::path::PathBuf },
    /// Donne un surnom à un appareil de la base (« imprimante HP »), désigné par son IP ou sa MAC.
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
            Err(e) => eprintln!("Scan réseau impossible : {e}"),
        }
    }

    async fn complet(&mut self) {
        self.audit = Some(machine::executer(false));
        self.scanner_reseau(None, "courants").await;
        titre("Bilan global");
        let m = self.audit.as_ref().filter(|a| a.fiable()).map(|a| a.score);
        let r = self.reseau.as_ref().map(|r| r.score_global);
        match m {
            Some(m) => afficher_note("Cette machine", m),
            None => println!("  Cette machine : pas de note (vérifications impossibles)"),
        }
        if let Some(r) = r {
            afficher_note("Réseau", r);
        }
        if let Some(g) = [m, r].into_iter().flatten().min() {
            afficher_note("Global", g);
        }
        let a_corriger = self.audit.as_ref().is_some_and(|a| {
            a.constats
                .iter()
                .any(|c| c.correctif.as_ref().is_some_and(|k| k.automatique))
        });
        if a_corriger {
            println!("\n  🔧 Des corrections sont possibles : choix « 2 » du menu ou « netscan corriger ».");
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
            Some(s) => println!("  {VERT}✔{RESET} {qui} s'appelle maintenant « {s} »."),
            None => println!("  {VERT}✔{RESET} Surnom retiré pour {qui}."),
        },
        Err(e) => println!("  ✖ {e}"),
    }
}

async fn menu() {
    let mut s = Session::default();
    loop {
        print!("\x1b[2J\x1b[H");
        println!("{GRAS}netscan{RESET} — sécurité de ta machine et de ton réseau\n");
        println!("  1. Bilan complet (machine + réseau)       {GRIS}← commencer ici{RESET}");
        println!("  2. Corriger les problèmes trouvés");
        println!("  3. Audit de cette machine");
        println!("  4. Scan du réseau local");
        println!("  5. Scan approfondi d'un appareil (tous les ports)");
        println!("  6. Antivirus : analyse rapide");
        println!("  7. Antivirus : analyse complète du dossier personnel");
        println!("  8. Ouvrir le rapport détaillé (navigateur)");
        let etat = if surveillance::active() {
            format!("{VERT}activée{RESET}")
        } else {
            format!("{GRIS}désactivée{RESET}")
        };
        println!("  9. Surveillance du réseau toutes les heures : {etat}");
        println!("  u. Mises à jour : tout vérifier et installer (système, programmes, pilotes)");
        println!("  r. Réparer (réseau, pare-feu, antivirus, disque, système…)");
        #[cfg(windows)]
        println!("  g. Gaming : composants (Visual C++, DirectX, .NET…) et réglages Windows");
        println!("  n. Nommer un appareil (« imprimante HP »)");
        println!("  d. Données : sauvegarder ou restaurer (surnoms, historique des réseaux)");
        println!("  q. Quitter\n");
        let choix = demander("Choix : ");
        println!();
        match choix.as_str() {
            "1" => s.complet().await,
            "2" => s.corriger(),
            "3" => s.audit = Some(machine::executer(false)),
            "4" => s.scanner_reseau(None, "courants").await,
            "5" => {
                let ip = demander("Adresse IP de l'appareil (ex. 10.0.0.1) : ");
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
                let qui = demander("IP ou adresse MAC de l'appareil : ");
                let surnom = demander("Surnom (vide pour le retirer) : ");
                nommer(&qui, &surnom);
            }
            "d" | "D" => donnees::menu(),
            "q" | "Q" => break,
            _ => continue,
        }
        demander(&format!("\n{GRIS}Entrée pour revenir au menu…{RESET}"));
    }
}

#[tokio::main]
async fn main() {
    // Couleurs ANSI dans l'ancienne console Windows (Windows Terminal les gère déjà).
    #[cfg(windows)]
    let _ = enable_ansi_support::enable_ansi_support();
    match Args::parse().commande {
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
                eprintln!("Erreur : {e}");
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
