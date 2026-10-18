//! Gardien — sécurise et optimise ta machine et ton réseau : bilan, correctifs, réglages.
//!
//! N'utilise le scan réseau que sur un réseau qui t'appartient ou que tu as le droit d'auditer.
//! Lancé sans argument, affiche un menu.

mod antivirus;
mod apprentissage;
mod commande;
mod connexion;
mod corriger;
mod diagnostic;
mod donnees;
mod fuites;
mod gaming;
mod historique;
mod integrite;
mod isoler;
mod journal;
mod langue;
mod listes_noires;
mod logiciels;
mod machine;
mod maj;
mod nettoyer;
mod optimiser;
mod pieges;
#[cfg(unix)]
mod protection;
mod rapport;
mod reparer;
mod reseau;
mod risk;
mod scan;
mod selection;
mod surveillance;
mod ui;
mod upnp;
mod yara;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

use machine::Audit;
use reseau::{Options, Rapport};
use selection::{Ligne, choisir};
use ui::*;

#[derive(Parser)]
#[command(
    version,
    about = "Sécurise et optimise ta machine et ton réseau local : bilan, correctifs, réglages. Sans argument : menu."
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
    /// Recherche de malwares : ClamAV (Linux, macOS) ou Microsoft Defender (Windows).
    Antivirus {
        /// Tout le dossier personnel au lieu des endroits à risque.
        #[arg(long)]
        complet: bool,
        /// Une clé USB, un disque externe ou un dossier à analyser en entier.
        dossier: Option<std::path::PathBuf>,
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
    /// Gaming : composants pour les jeux (Windows : Visual C++, DirectX… ; Linux : Steam, Vulkan, GameMode, Wine… ;
    /// macOS : Rosetta, Steam, Epic…) et réglages du système.
    Gaming,
    /// Diagnostic de l'ordinateur : matériel, système et problèmes récents (plantages, erreurs). Lecture seule.
    #[command(visible_alias = "diag")]
    Diagnostic,
    /// Logiciels : les meilleurs, libres pour la plupart (navigateurs, mots de passe, bureautique, vidéo, création,
    /// outils système…), par catégorie : choisir puis installer depuis la source officielle du système.
    #[command(visible_alias = "apps")]
    Logiciels {
        /// Montrer chaque logiciel proposé et son état, sans rien installer.
        #[arg(long, visible_alias = "list")]
        liste: bool,
        /// Installer le pack de départ (navigateur, mots de passe, vidéo, bureautique, archives), après accord.
        #[arg(long, visible_alias = "recommended")]
        recommandes: bool,
    },
    /// Nettoyer le système : caches, fichiers temporaires, paquets téléchargés, vieux journaux, corbeille… La place
    /// libérée par chaque élément est montrée avant ; on coche, puis on accepte.
    #[command(visible_alias = "clean")]
    Nettoyer {
        /// Montrer ce qui pourrait être nettoyé et la place à gagner, sans rien effacer.
        #[arg(long, visible_alias = "list")]
        liste: bool,
    },
    /// Ce que Gardien a appris sur cet ordinateur : les alertes déclarées normales, et les oublier.
    #[command(visible_alias = "learned")]
    Appris,
    /// Test de connexion pour le jeu : ping, gigue, pertes, débit et bufferbloat.
    #[command(visible_alias = "connection")]
    Connexion,
    /// L'adresse Internet de la maison est-elle sur une liste noire (Spamhaus, SpamCop, DroneBL, PSBL) ? Si oui, un
    /// appareil est sans doute infecté. Après accord : les listes voient l'adresse.
    #[command(name = "listes-noires", visible_alias = "blocklists")]
    ListesNoires,
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
    /// Fichiers-pièges contre les rançongiciels : les poser (après accord), voir s'ils sont intacts, ou les retirer.
    #[command(visible_alias = "decoys")]
    Pieges {
        /// Retirer les fichiers-pièges posés.
        #[arg(long, visible_alias = "remove")]
        retirer: bool,
    },
    /// Analyse YARA : 308 règles de familles de logiciels malveillants (ReversingLabs), en complément de l'antivirus.
    /// Sans dossier : téléchargements, bureau, démarrage. Lecture seule.
    Yara {
        /// Tout le dossier personnel au lieu des endroits à risque.
        #[arg(long, visible_alias = "full")]
        complet: bool,
        /// Une clé USB, un disque externe ou un dossier à analyser en entier.
        dossier: Option<std::path::PathBuf>,
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
        /// Fichier à écrire (par défaut : gardien-sauvegarde-AAAA-MM-JJ.json dans le dossier personnel ou Documents).
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
            Err(e) => {
                journal::erreur("scan réseau", &e);
                eprintln!("{}", trf!("Scan réseau impossible : {e}", "Network scan failed: {e}"));
            }
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
                "\n  🔧 Des corrections sont possibles : choix « 2 » du menu ou « gardien corriger ».",
                "\n  🔧 Fixes are available: menu choice “2” or “gardien fix”."
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

/// État affiché en tête du menu : dernier bilan, dernier test de connexion, clé, surveillance.
fn etat_du_menu(surveillance_active: bool) -> Vec<String> {
    let mut lignes = Vec::new();
    let historique = historique::charger();
    lignes.push(match historique.last() {
        Some(b) => {
            let note = |s: Option<u32>| s.map_or_else(|| "—".to_string(), etiquette_note);
            trf!(
                "  {GRIS}Dernier bilan{RESET}  {}   machine {}   réseau {}",
                "  {GRIS}Last check{RESET}     {}   machine {}   network {}",
                b.date,
                note(b.machine),
                note(b.reseau)
            )
        }
        None => trf!(
            "  {GRIS}Aucun bilan encore : commence par 1.{RESET}",
            "  {GRIS}No check yet: start with 1.{RESET}"
        ),
    });
    if let Some(c) = connexion::historique().last() {
        let debit = |d: Option<f64>| d.map_or_else(|| "?".to_string(), |d| format!("{d:.0}"));
        let bufferbloat = c
            .hausse_ms
            .map(|h| {
                let (n, niveau) = connexion::note_bufferbloat(h);
                format!("{}{n}{RESET}", couleur(niveau))
            })
            .unwrap_or_default();
        lignes.push(trf!(
            "  {GRIS}Connexion{RESET}      {:.0} ms · ↓ {} ↑ {} Mbit/s · bufferbloat {bufferbloat}",
            "  {GRIS}Connection{RESET}     {:.0} ms · ↓ {} ↑ {} Mbit/s · bufferbloat {bufferbloat}",
            c.internet_ms,
            debit(c.descendant),
            debit(c.montant)
        ));
    }
    let cle = if reseau::cle_protegee().is_some() {
        format!(
            "{VERT}{}{RESET}",
            tr!(
                "clé GARDIEN branchée (protégée en écriture)",
                "GARDIEN key plugged in (write-protected)"
            )
        )
    } else if reseau::cle_usb().is_some() {
        format!("{VERT}{}{RESET}", tr!("clé GARDIEN branchée", "GARDIEN key plugged in"))
    } else {
        format!("{GRIS}{}{RESET}", tr!("clé non branchée", "key not plugged in"))
    };
    let surveillance = if surveillance_active {
        format!("{VERT}{}{RESET}", tr!("surveillance active", "monitoring on"))
    } else {
        format!("{GRIS}{}{RESET}", tr!("surveillance coupée", "monitoring off"))
    };
    lignes.push(format!("  {cle} {GRIS}·{RESET} {surveillance}"));
    lignes
}

/// Lignes vides et sous-titre « ── NOM ──── » d'un menu.
fn section_du_menu(t: &str) -> [Ligne; 2] {
    [Ligne::Texte(String::new()), Ligne::Texte(ligne_section(t))]
}

async fn menu() {
    let mut s = Session::default();
    // La ligne en surbrillance au retour dans le menu : la dernière choisie.
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let mut lignes: Vec<Ligne> = lignes_cadre(
            &format!("{ACCENT}GARDIEN{RESET} {GRIS}{}{RESET}", env!("CARGO_PKG_VERSION")),
            tr!(
                "sécurise et optimise ta machine et ton réseau",
                "secures and optimizes your machine and network"
            ),
        )
        .into_iter()
        .map(Ligne::Texte)
        .collect();
        lignes.extend(etat_du_menu(surveillance::active()).into_iter().map(Ligne::Texte));

        lignes.extend(section_du_menu(tr!("BILAN DE SÉCURITÉ", "SECURITY CHECK")));
        lignes.push(Ligne::choix(
            "1",
            tr!("Bilan complet : machine + réseau", "Full check: machine + network"),
            tr!("← commencer ici", "← start here"),
        ));
        lignes.push(Ligne::choix(
            "2",
            tr!("Corriger les problèmes trouvés", "Fix the problems found"),
            "",
        ));
        lignes.push(Ligne::choix(
            "3",
            tr!("Rapport détaillé dans le navigateur", "Detailed report in the browser"),
            "",
        ));

        lignes.extend(section_du_menu(tr!("OUTILS", "TOOLS")));
        for (touche, groupe) in GROUPES.iter().enumerate() {
            lignes.push(Ligne::choix(
                &(touche + 4).to_string(),
                &format!("{} {ACCENT}›{RESET}", groupe.titre()),
                groupe.resume(),
            ));
        }

        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("q", tr!("Quitter", "Quit"), ""));
        lignes.push(Ligne::Texte(String::new()));
        let Some(choix) = choisir(
            &lignes,
            &format!("  {ACCENT}›{RESET} {}", tr!("Choix : ", "Choice: ")),
            &dernier,
            tr!("quitter", "quit"),
        ) else {
            break;
        };
        let choix = choix.trim().to_lowercase();
        println!();
        let groupe = choix
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(4))
            .and_then(|i| GROUPES.get(i));
        if let Some(g) = groupe {
            dernier = choix;
            sous_menu(&mut s, *g).await;
            continue;
        }
        let action = match choix.as_str() {
            "1" => Action::Complet,
            "2" => Action::Corriger,
            "3" => Action::Rapport,
            "q" => break,
            // Raccourcis des versions précédentes (une lettre par outil), toujours acceptés.
            autre => match Action::TOUTES.iter().find(|a| a.raccourci() == Some(autre)) {
                Some(&a) => a,
                None => continue,
            },
        };
        dernier = choix;
        executer(&mut s, action).await;
        demander(&trf!(
            "\n{GRIS}Entrée pour revenir au menu…{RESET}",
            "\n{GRIS}Enter to go back to the menu…{RESET}"
        ));
    }
}

/// Ce que le menu sait faire. Chaque outil vit dans un groupe ; son ancienne lettre reste un raccourci.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Complet,
    Corriger,
    Rapport,
    Audit,
    Integrite,
    Appris,
    Diagnostic,
    Maj,
    Reparer,
    Scanner,
    Appareil,
    Nommer,
    Surveillance,
    Connexion,
    ListesNoires,
    AntivirusRapide,
    AntivirusComplet,
    AntivirusDossier,
    Yara,
    Pieges,
    Bac,
    MotsDePasse,
    Courriel,
    Logiciels,
    Gaming,
    Nettoyer,
    OptimiserRecommandes,
    OptimiserConfidentialite,
    #[cfg(not(target_os = "macos"))]
    OptimiserPerformance,
    OptimiserConfort,
    OptimiserAnnuler,
    Sauvegarder,
}

impl Action {
    const TOUTES: &[Action] = &[
        Action::Complet,
        Action::Corriger,
        Action::Rapport,
        Action::Audit,
        Action::Integrite,
        Action::Appris,
        Action::Diagnostic,
        Action::Maj,
        Action::Reparer,
        Action::Scanner,
        Action::Appareil,
        Action::Nommer,
        Action::Surveillance,
        Action::Connexion,
        Action::ListesNoires,
        Action::AntivirusRapide,
        Action::AntivirusComplet,
        Action::AntivirusDossier,
        Action::Yara,
        Action::Pieges,
        Action::Bac,
        Action::MotsDePasse,
        Action::Courriel,
        Action::Logiciels,
        Action::Gaming,
        Action::Nettoyer,
        Action::OptimiserRecommandes,
        Action::OptimiserConfidentialite,
        #[cfg(not(target_os = "macos"))]
        Action::OptimiserPerformance,
        Action::OptimiserConfort,
        Action::OptimiserAnnuler,
        Action::Sauvegarder,
    ];

    /// Lettre de l'outil dans les menus d'avant la 0.43 (les chiffres, eux, ont changé de sens).
    fn raccourci(self) -> Option<&'static str> {
        Some(match self {
            Action::Integrite => "i",
            Action::Diagnostic => "o",
            Action::Maj => "u",
            Action::Reparer => "r",
            Action::Nommer => "n",
            Action::Connexion => "c",
            Action::AntivirusDossier => "a",
            Action::Bac => "b",
            Action::MotsDePasse => "p",
            Action::Courriel => "e",
            Action::Logiciels => "l",
            Action::Gaming => "g",
            Action::Nettoyer => "v",
            Action::Sauvegarder => "d",
            _ => return None,
        })
    }

    /// L'outil a-t-il quelque chose à proposer sur ce système ? (une catégorie de réglages vide n'est pas montrée)
    fn disponible(self) -> bool {
        match self {
            Action::OptimiserConfidentialite => optimiser::a_des_reglages(optimiser::Categorie::Confidentialite),
            #[cfg(not(target_os = "macos"))]
            Action::OptimiserPerformance => optimiser::a_des_reglages(optimiser::Categorie::Performance),
            Action::OptimiserConfort => optimiser::a_des_reglages(optimiser::Categorie::Confort),
            _ => true,
        }
    }

    /// Texte de la ligne de menu et sa précision en gris.
    fn libelle(self) -> (&'static str, &'static str) {
        match self {
            Action::Complet => (
                tr!("Bilan complet : machine + réseau", "Full check: machine + network"),
                "",
            ),
            Action::Corriger => (tr!("Corriger les problèmes trouvés", "Fix the problems found"), ""),
            Action::Rapport => (
                tr!("Rapport détaillé dans le navigateur", "Detailed report in the browser"),
                "",
            ),
            Action::Audit => (
                tr!("Audit de sécurité", "Security audit"),
                tr!("pare-feu, comptes, chiffrement…", "firewall, accounts, encryption…"),
            ),
            Action::Integrite => (
                tr!("Intégrité des fichiers critiques", "Critical file integrity"),
                tr!("comptes, sudo, SSH, démarrage…", "accounts, sudo, SSH, startup…"),
            ),
            Action::Appris => (
                tr!("Ce que Gardien a appris", "What Gardien has learned"),
                tr!("tes choix, tes habitudes", "your choices, your habits"),
            ),
            Action::Diagnostic => (
                tr!("Diagnostic", "Diagnostic"),
                tr!("matériel, plantages, erreurs", "hardware, crashes, errors"),
            ),
            Action::Maj => (
                tr!("Mises à jour", "Updates"),
                tr!("système, programmes, pilotes", "system, programs, drivers"),
            ),
            Action::Reparer => (
                tr!("Réparer et nettoyer", "Repair and clean up"),
                tr!("réseau, disque, système…", "network, disk, system…"),
            ),
            Action::Scanner => (
                tr!("Scanner le réseau", "Scan the network"),
                tr!("appareils, ports, nouveautés", "devices, ports, changes"),
            ),
            Action::Appareil => (
                tr!("Scan approfondi d'un appareil", "Deep scan of one device"),
                tr!("tous les ports", "all ports"),
            ),
            Action::Nommer => (
                tr!("Nommer un appareil", "Name a device"),
                tr!("« imprimante HP »", "“HP printer”"),
            ),
            Action::Surveillance => (
                tr!("Surveillance toutes les heures", "Hourly monitoring"),
                if surveillance::active() {
                    tr!("activée", "on")
                } else {
                    tr!("désactivée", "off")
                },
            ),
            Action::Connexion => (
                tr!("Test de connexion pour le jeu", "Connection test for gaming"),
                tr!("ping, gigue, débit, bufferbloat", "ping, jitter, speed, bufferbloat"),
            ),
            Action::ListesNoires => (
                tr!("Adresse sur liste noire ?", "Address on blocklists?"),
                tr!("si oui, un appareil est infecté", "if so, a device is infected"),
            ),
            Action::AntivirusRapide => (
                tr!("Analyse rapide", "Quick scan"),
                tr!("téléchargements, bureau…", "downloads, desktop…"),
            ),
            Action::AntivirusComplet => (
                tr!("Analyse complète", "Full scan"),
                tr!("dossier personnel", "home folder"),
            ),
            Action::AntivirusDossier => (
                tr!("Clé USB ou dossier", "USB drive or folder"),
                tr!("et pièges de clé", "and drive traps"),
            ),
            Action::Yara => (
                tr!("Analyse YARA", "YARA scan"),
                tr!("règles de logiciels malveillants", "malware detection rules"),
            ),
            Action::Pieges => (
                tr!("Fichiers-pièges", "Decoy files"),
                tr!("alerte si un rançongiciel chiffre", "early ransomware warning"),
            ),
            Action::Bac => (
                tr!(
                    "Bac à sable : lancer un programme inconnu",
                    "Sandbox: run an unknown program"
                ),
                tr!("sans réseau, isolé", "no network, isolated"),
            ),
            Action::MotsDePasse => (
                tr!("Mots de passe : ont-ils fuité ?", "Passwords: have they leaked?"),
                tr!("rien n'est envoyé en clair", "nothing sent in clear"),
            ),
            Action::Courriel => (
                tr!("Adresse courriel : a-t-elle fuité ?", "Email address: has it leaked?"),
                tr!("avec ton accord", "with your consent"),
            ),
            Action::Logiciels => (
                tr!("Logiciels", "Software"),
                tr!("les meilleurs, par catégorie", "the best ones, by category"),
            ),
            Action::Gaming => (
                tr!("Gaming", "Gaming"),
                if cfg!(windows) {
                    tr!("composants et réglages de Windows", "components and Windows settings")
                } else if cfg!(target_os = "macos") {
                    tr!("Rosetta, Steam, Epic, GOG…", "Rosetta, Steam, Epic, GOG…")
                } else {
                    tr!("Steam, Vulkan, GameMode, Wine…", "Steam, Vulkan, GameMode, Wine…")
                },
            ),
            Action::Nettoyer => (
                tr!("Nettoyer le système", "Clean up the system"),
                tr!("caches, temporaires, corbeille…", "caches, temp files, trash…"),
            ),
            Action::OptimiserRecommandes => (
                tr!("Réglages recommandés", "Recommended settings"),
                tr!("en une fois, tout s'annule", "in one go, all undoable"),
            ),
            Action::OptimiserConfidentialite => (
                tr!("Confidentialité", "Privacy"),
                if cfg!(windows) {
                    tr!("télémétrie, publicités, suivi", "telemetry, ads, tracking")
                } else if cfg!(target_os = "macos") {
                    tr!("publicités, analyses", "ads, analytics")
                } else {
                    tr!("rapports et statistiques", "reports and statistics")
                },
            ),
            #[cfg(not(target_os = "macos"))]
            Action::OptimiserPerformance => (
                tr!("Performance et fiabilité", "Performance and reliability"),
                if cfg!(windows) {
                    tr!("démarrage rapide, widgets…", "fast startup, widgets…")
                } else {
                    tr!("SSD, taille du journal", "SSD, journal size")
                },
            ),
            Action::OptimiserConfort => (
                tr!("Confort et fichiers", "Comfort and files"),
                if cfg!(windows) {
                    tr!("extensions, clés USB, clic droit", "extensions, USB drives, menus")
                } else if cfg!(target_os = "macos") {
                    tr!("extensions, .DS_Store, Finder", "extensions, .DS_Store, Finder")
                } else {
                    tr!("annonces d'Ubuntu", "Ubuntu announcements")
                },
            ),
            Action::OptimiserAnnuler => (
                tr!("Tout remettre comme avant", "Put everything back"),
                tr!("annule ce que Gardien a changé", "undo what Gardien changed"),
            ),
            Action::Sauvegarder => (
                tr!("Sauvegarder ou restaurer", "Back up or restore"),
                tr!("base des appareils, réglages", "device database, settings"),
            ),
        }
    }
}

/// Un groupe d'outils du menu principal, ouvert en sous-menu.
#[derive(Clone, Copy)]
enum Groupe {
    Machine,
    Reseau,
    Protection,
    Installer,
    Optimiser,
    Donnees,
}

const GROUPES: [Groupe; 6] = [
    Groupe::Machine,
    Groupe::Reseau,
    Groupe::Protection,
    Groupe::Installer,
    Groupe::Optimiser,
    Groupe::Donnees,
];

impl Groupe {
    fn titre(self) -> &'static str {
        match self {
            Groupe::Machine => tr!("Cette machine", "This machine"),
            Groupe::Reseau => tr!("Réseau et Internet", "Network and Internet"),
            Groupe::Protection => tr!("Antivirus et protection", "Antivirus and protection"),
            Groupe::Installer => tr!("Installer et jouer", "Install and play"),
            Groupe::Optimiser => tr!("Optimiser", "Optimize"),
            Groupe::Donnees => tr!("Données", "Data"),
        }
    }

    fn resume(self) -> &'static str {
        match self {
            Groupe::Machine => tr!("audit, mises à jour, réparer…", "audit, updates, repair…"),
            Groupe::Reseau => tr!("appareils, surveillance, débit", "devices, monitoring, speed test"),
            Groupe::Protection => tr!("analyses, clé USB, fuites…", "scans, USB drive, leaks…"),
            Groupe::Installer => tr!("logiciels libres, gaming", "open source software, gaming"),
            Groupe::Optimiser => tr!("nettoyer, confidentialité…", "clean up, privacy…"),
            Groupe::Donnees => tr!("sauvegarder ou restaurer", "back up or restore"),
        }
    }

    fn actions(self) -> &'static [Action] {
        match self {
            Groupe::Machine => &[
                Action::Audit,
                Action::Maj,
                Action::Reparer,
                Action::Diagnostic,
                Action::Integrite,
                Action::Appris,
            ],
            Groupe::Reseau => &[
                Action::Scanner,
                Action::Appareil,
                Action::Nommer,
                Action::Surveillance,
                Action::Connexion,
                Action::ListesNoires,
            ],
            Groupe::Protection => &[
                Action::AntivirusRapide,
                Action::AntivirusComplet,
                Action::AntivirusDossier,
                Action::Yara,
                Action::Pieges,
                Action::Bac,
                Action::MotsDePasse,
                Action::Courriel,
            ],
            Groupe::Installer => &[Action::Logiciels, Action::Gaming],
            Groupe::Optimiser => &[
                Action::Nettoyer,
                Action::OptimiserRecommandes,
                Action::OptimiserConfidentialite,
                #[cfg(not(target_os = "macos"))]
                Action::OptimiserPerformance,
                Action::OptimiserConfort,
                Action::OptimiserAnnuler,
            ],
            Groupe::Donnees => &[Action::Sauvegarder],
        }
    }
}

/// Sous-menu d'un groupe : ses outils numérotés, Entrée pour revenir au menu principal. Un groupe d'un seul outil
/// (Données) l'ouvre directement. Un outil sans rien à proposer sur ce système n'est pas montré.
async fn sous_menu(s: &mut Session, groupe: Groupe) {
    let actions: Vec<Action> = groupe.actions().iter().copied().filter(|a| a.disponible()).collect();
    if let [seule] = actions[..] {
        executer(s, seule).await;
        demander(&trf!(
            "\n{GRIS}Entrée pour revenir au menu…{RESET}",
            "\n{GRIS}Enter to go back to the menu…{RESET}"
        ));
        return;
    }
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let mut lignes: Vec<Ligne> = lignes_cadre(
            &format!("{ACCENT}GARDIEN{RESET} {GRIS}›{RESET} {}", groupe.titre()),
            groupe.resume(),
        )
        .into_iter()
        .map(Ligne::Texte)
        .collect();
        lignes.push(Ligne::Texte(String::new()));
        for (i, a) in actions.iter().enumerate() {
            let (texte, precision) = a.libelle();
            lignes.push(Ligne::choix(&(i + 1).to_string(), texte, precision));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix(
            "↵",
            tr!("Revenir au menu principal", "Back to the main menu"),
            "",
        ));
        lignes.push(Ligne::Texte(String::new()));
        let Some(choix) = choisir(
            &lignes,
            &format!("  {ACCENT}›{RESET} {}", tr!("Choix : ", "Choice: ")),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim();
        if choix.is_empty() || choix == "↵" || choix.eq_ignore_ascii_case("q") {
            return;
        }
        let Some(&action) = choix
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| actions.get(i))
        else {
            continue;
        };
        dernier = choix.to_string();
        println!();
        executer(s, action).await;
        demander(&trf!(
            "\n{GRIS}Entrée pour revenir…{RESET}",
            "\n{GRIS}Enter to go back…{RESET}"
        ));
    }
}

async fn executer(s: &mut Session, action: Action) {
    match action {
        Action::Complet => s.complet().await,
        Action::Corriger => s.corriger(),
        Action::Rapport => {
            if s.audit.is_none() && s.reseau.is_none() {
                s.complet().await;
            }
            rapport::ouvrir(s.audit.as_ref(), s.reseau.as_ref());
        }
        Action::Audit => s.audit = Some(machine::executer(false)),
        Action::Integrite => integrite::verifier(false),
        Action::Appris => apprentissage::menu(),
        Action::Diagnostic => diagnostic::diagnostic(),
        Action::Maj => maj::executer(),
        Action::Reparer => reparer::menu(),
        Action::Scanner => s.scanner_reseau(None, "courants").await,
        Action::Appareil => {
            let ip = demander(tr!(
                "Adresse IP de l'appareil (ex. 10.0.0.1) : ",
                "IP address of the device (e.g. 10.0.0.1): "
            ));
            s.scanner_reseau(Some(ip), "tous").await;
        }
        Action::Nommer => {
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
        Action::Surveillance => surveillance::activer(!surveillance::active()),
        Action::Connexion => connexion::tester().await,
        Action::ListesNoires => listes_noires::verifier(),
        Action::AntivirusRapide => antivirus::analyser(antivirus::Portee::Rapide),
        Action::AntivirusComplet => antivirus::analyser(antivirus::Portee::Complete),
        Action::AntivirusDossier => antivirus::choisir(),
        Action::Yara => yara::menu(),
        Action::Pieges => pieges::menu(),
        Action::Bac => {
            let chemin = demander(tr!("  Programme à isoler (chemin) : ", "  Program to isolate (path): "));
            let chemin = chemin.trim().trim_matches(['"', '\'']);
            if !chemin.is_empty() {
                isoler::isoler(std::path::Path::new(chemin));
            }
        }
        Action::MotsDePasse => fuites::verifier(),
        Action::Courriel => fuites::verifier_courriel(),
        Action::Logiciels => logiciels::menu(),
        Action::Gaming => gaming::menu(),
        Action::Nettoyer => nettoyer::menu(),
        Action::OptimiserRecommandes => optimiser::recommandes(),
        Action::OptimiserConfidentialite => optimiser::menu(optimiser::Categorie::Confidentialite),
        #[cfg(not(target_os = "macos"))]
        Action::OptimiserPerformance => optimiser::menu(optimiser::Categorie::Performance),
        Action::OptimiserConfort => optimiser::menu(optimiser::Categorie::Confort),
        Action::OptimiserAnnuler => optimiser::tout_annuler(),
        Action::Sauvegarder => donnees::menu(),
    }
}

/// La ligne de commande, avec son aide en anglais si l'interface est en anglais (l'aide écrite plus haut, en
/// commentaires, est la version française).
fn ligne_de_commande() -> clap::Command {
    let c = Args::command();
    if !langue::anglais() {
        return c;
    }
    let mut c = c
        .about("Secures and optimizes your machine and your local network: check, fixes, settings. No argument: menu.");
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
            "Malware scan: ClamAV (Linux, macOS) or Microsoft Defender (Windows)",
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
            "logiciels",
            "Software: the best programs, mostly open source (browsers, passwords, office, video, design, system tools…), by category: choose, then install from the system's official source",
        ),
        (
            "diagnostic",
            "Computer diagnostic: hardware, system and recent problems (crashes, errors). Read only",
        ),
        (
            "nettoyer",
            "Clean up the system: caches, temporary files, downloaded packages, old logs, trash… The space each item frees is shown first; check, then accept",
        ),
        (
            "connexion",
            "Connection test for gaming: ping, jitter, packet loss, speed and bufferbloat",
        ),
        (
            "appris",
            "What Gardien has learned on this computer: the alerts declared normal, and forgetting them",
        ),
        (
            "listes-noires",
            "Is your home's Internet address on a blocklist (Spamhaus, SpamCop, DroneBL, PSBL)? If so, a device is probably infected. After your consent: the lists see the address",
        ),
        (
            "yara",
            "YARA scan: 308 rules for malware families (ReversingLabs), alongside the antivirus. Without a folder: downloads, desktop, startup. Read-only",
        ),
        (
            "pieges",
            "Decoy files against ransomware: place them (after your consent), see whether they are intact, or remove them",
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
        (
            "gaming",
            "Gaming: components for games (Windows: Visual C++, DirectX…; Linux: Steam, Vulkan, GameMode, Wine…; macOS: Rosetta, Steam, Epic…) and system settings",
        ),
    ];
    for &(nom, aide) in aides {
        c = c.mut_subcommand(nom, |s| s.about(aide));
    }
    c.mut_subcommand("nettoyer", |s| {
        s.mut_arg("liste", |a| {
            a.help("Show what could be cleaned up and the space to gain, deleting nothing")
        })
    })
    .mut_subcommand("logiciels", |s| {
        s.mut_arg("liste", |a| {
            a.help("Show each program offered and its state, without installing anything")
        })
        .mut_arg("recommandes", |a| {
            a.help("Install the starter pack (browser, passwords, video, office, archives), after your consent")
        })
    })
    .mut_subcommand("complet", |s| {
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
        .mut_arg("dossier", |a| {
            a.help("A USB drive, external disk or folder to scan entirely")
        })
    })
    .mut_subcommand("isoler", |s| {
        s.mut_arg("fichier", |a| a.help("Program or script to run"))
    })
    .mut_subcommand("pieges", |s| {
        s.mut_arg("retirer", |a| a.help("Remove the decoy files placed"))
    })
    .mut_subcommand("yara", |s| {
        s.mut_arg("complet", |a| {
            a.help("The whole home folder instead of the risky places")
        })
        .mut_arg("dossier", |a| {
            a.help("A USB drive, external disk or folder to scan entirely")
        })
    })
    .mut_subcommand("integrite", |s| {
        s.mut_arg("accepter", |a| {
            a.help("Take the current state as the new reference (after a system update)")
        })
        .mut_arg("temps_reel", |a| a.help("Watch the critical files live until Ctrl-C"))
    })
    .mut_subcommand("sauvegarder", |s| {
        s.mut_arg("fichier", |a| {
            a.help("File to write (default: gardien-sauvegarde-YYYY-MM-DD.json in the home or Documents folder)")
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
    journal::installer();
    #[cfg(unix)]
    protection::proteger_cle();
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
                journal::erreur("scan réseau", &e);
                eprintln!("{}", trf!("Erreur : {e}", "Error: {e}"));
                std::process::exit(1);
            }
        }
        Some(Commande::Antivirus { complet, dossier }) => antivirus::analyser(match (dossier, complet) {
            (Some(d), _) => antivirus::Portee::Dossier(d),
            (None, true) => antivirus::Portee::Complete,
            (None, false) => antivirus::Portee::Rapide,
        }),
        Some(Commande::Surveillance { etat }) => surveillance::activer(etat == "on"),
        Some(Commande::Surveiller) => surveillance::surveiller().await,
        Some(Commande::Maj) => maj::executer(),
        Some(Commande::Reparer) => reparer::menu(),
        Some(Commande::Gaming) => gaming::menu(),
        Some(Commande::Nettoyer { liste }) => {
            if liste {
                nettoyer::liste();
            } else {
                nettoyer::menu();
            }
        }
        Some(Commande::Connexion) => connexion::tester().await,
        Some(Commande::Diagnostic) => diagnostic::diagnostic(),
        Some(Commande::Logiciels { liste, recommandes }) => {
            if liste {
                logiciels::liste();
            } else if recommandes {
                logiciels::recommandes();
            } else {
                logiciels::menu();
            }
        }
        Some(Commande::MotDePasse) => fuites::verifier(),
        Some(Commande::Courriel) => fuites::verifier_courriel(),
        Some(Commande::Isoler { fichier }) => isoler::isoler(&fichier),
        Some(Commande::Pieges { retirer }) => pieges::commande(retirer),
        Some(Commande::Yara { complet, dossier }) => yara::analyser(&match (dossier, complet) {
            (Some(d), _) => antivirus::Portee::Dossier(d),
            (None, true) => antivirus::Portee::Complete,
            (None, false) => antivirus::Portee::Rapide,
        }),
        Some(Commande::ListesNoires) => listes_noires::verifier(),
        Some(Commande::Appris) => apprentissage::menu(),
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

#[cfg(test)]
mod tests_menu {
    use super::*;

    #[test]
    fn chaque_outil_a_sa_place() {
        // 1, 2, 3 au menu principal ; tout le reste dans un seul groupe.
        let principal = [Action::Complet, Action::Corriger, Action::Rapport];
        for a in Action::TOUTES {
            let groupes = GROUPES.iter().filter(|g| g.actions().contains(a)).count();
            assert_eq!(groupes + usize::from(principal.contains(a)), 1);
        }
        // Raccourcis uniques, et jamais un chiffre (les chiffres ouvrent les groupes).
        let mut lettres: Vec<&str> = Action::TOUTES.iter().filter_map(|a| a.raccourci()).collect();
        assert!(
            lettres
                .iter()
                .all(|l| !l.starts_with(|c: char| c.is_ascii_digit()) && *l != "q")
        );
        let n = lettres.len();
        lettres.sort_unstable();
        lettres.dedup();
        assert_eq!(lettres.len(), n);
    }
}
