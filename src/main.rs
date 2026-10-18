//! Gardien — sécurise et optimise ta machine et ton réseau : bilan, correctifs, réglages.
//!
//! N'utilise le scan réseau que sur un réseau qui t'appartient ou que tu as le droit d'auditer.
//! Lancé sans argument, affiche un menu.

mod alertes;
mod antivirus;
mod apprentissage;
mod cameras;
mod canaux;
mod commande;
mod connexion;
mod copier;
mod corriger;
mod depanner;
mod diagnostic;
mod dns_rapide;
mod donnees;
mod entretien;
mod fiche;
mod fuites;
mod gaming;
mod guide;
mod historique;
mod integrite;
mod isoler;
mod journal;
mod langue;
mod lenteur;
mod lien;
mod listes_noires;
mod logiciels;
mod machine;
mod maj;
mod nat;
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
mod sortantes;
mod surveillance;
mod telechargement;
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
    /// Entretien du mois : une fois par mois, en silence, la note, les mises à jour en attente, la place à libérer et
    /// les problèmes nouveaux, en une notification ; rien n'est changé. Sans argument : ce qu'il dirait maintenant.
    #[command(visible_alias = "maintenance")]
    Entretien {
        #[arg(value_parser = ["on", "off"])]
        etat: Option<String>,
    },
    /// Alertes sur le téléphone, par ntfy (surveillance, entretien du mois) : les activer après accord, les couper,
    /// ou envoyer une alerte d'essai. Sans argument : le menu.
    #[command(visible_alias = "alerts")]
    Alertes {
        #[arg(value_parser = ["on", "off", "essai", "test"])]
        etat: Option<String>,
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
    /// Wi-Fi encombré : les réseaux voisins par canal, et le canal le plus libre à régler sur la box. Lecture seule.
    #[command(visible_alias = "channels")]
    Canaux,
    /// Type de NAT pour le jeu (ouvert, modéré ou strict), d'après deux serveurs publics (STUN). Lecture seule.
    Nat,
    /// Caméras cachées : sur le réseau d'une location ou de quelqu'un, les appareils qui ressemblent à des caméras.
    /// Lecture seule.
    Cameras,
    /// DNS le plus rapide : mesure le DNS actuel et des DNS publics, puis propose le plus rapide, annulable. Un DNS
    /// qui protège (NextDNS, chiffré, filtrant) est gardé.
    #[command(name = "dns-rapide", visible_alias = "fast-dns")]
    DnsRapide,
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
    /// Qui parle à Internet ? Les connexions en cours de chaque programme, avec le nom du serveur. Lecture seule.
    #[command(visible_alias = "outbound")]
    Sortantes,
    /// Ce lien est-il dangereux ? Examiné sans jamais l'ouvrir ; après accord, son âge et des listes publiques.
    #[command(visible_alias = "link")]
    Lien {
        /// Le lien reçu (entre guillemets s'il contient « & » ou « ? »).
        adresse: String,
    },
    /// Vérifier un fichier téléchargé : empreinte comparée à celle du site, nom et contenu, YARA et antivirus.
    #[command(name = "verifier-fichier", visible_alias = "check-file")]
    VerifierFichier {
        /// Le fichier téléchargé.
        fichier: std::path::PathBuf,
        /// L'empreinte publiée par le site (SHA-256 de préférence). Sinon : un SHA256SUMS ou .sha256 à côté.
        empreinte: Option<String>,
    },
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
    /// Guide des commandes : celles de Linux, de Windows, de macOS et de tous les systèmes, rangées par programme.
    Guide {
        /// Un système (linux, windows, macos, tous), un programme (systemctl, winget…) ou des mots à chercher.
        quoi: Vec<String>,
    },
    /// Pourquoi c'est lent ? Ce qui occupe le processeur, la mémoire et le disque, le démarrage, les programmes lancés
    /// à l'ouverture de session. Lecture seule.
    #[command(visible_alias = "slow")]
    Lenteur,
    /// Fiche de l'ordinateur : modèle, carte mère, processeur, mémoire, carte graphique, disques, système. Les numéros
    /// de série s'affichent à l'écran seulement.
    #[command(visible_alias = "specs")]
    Fiche {
        /// La fiche en JSON, pour un script (sans les numéros de série).
        #[arg(long)]
        json: bool,
    },
    /// Copier mes fichiers (Documents, Images, Bureau, Vidéos, Musique) vers un disque externe : copie vérifiée, rien
    /// n'est effacé ni écrasé, une copie interrompue reprend.
    #[command(name = "copier-fichiers", visible_alias = "copy-files")]
    CopierFichiers {
        /// Un dossier d'un disque externe (par défaut : choisi parmi les disques branchés).
        destination: Option<std::path::PathBuf>,
    },
    /// Dépanner pas à pas : pas d'Internet, Wi-Fi qui coupe, ordinateur lent, pas de son, imprimante, disque plein.
    #[command(visible_alias = "troubleshoot")]
    Depanner {
        /// Le sujet : internet, wifi, lent, son, imprimante, disque (ou des mots qui le décrivent).
        sujet: Vec<String>,
    },
    /// Scan silencieux + notifications (utilisé par la surveillance).
    #[command(hide = true)]
    Surveiller,
    /// Entretien silencieux + notification (utilisé par le planificateur, une fois par mois).
    #[command(hide = true)]
    Entretenir,
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

/// Les lignes du menu principal, sous l'état (dernier bilan, clé, surveillance).
fn lignes_du_menu(etat: Vec<String>) -> Vec<Ligne> {
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
    lignes.extend(etat.into_iter().map(Ligne::Texte));

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

    // « q » suit les groupes, et l'aide le suit, sans ligne vide : avec le 8e groupe (dépanner), le menu tient
    // encore dans un terminal de 24 lignes (macOS, beaucoup de Linux), où les flèches marchent.
    lignes.push(Ligne::choix("q", tr!("Quitter", "Quit"), ""));

    // Ce que la recherche trouve en plus, sans l'afficher : chaque outil des sous-menus (« 5.2 » : groupe 5, 2e outil,
    // aussi tapable tel quel), chaque parcours de dépannage et chaque page du guide. Les pages du guide en dernier :
    // la recherche garde cet ordre, et un outil ou un parcours répond mieux à « son » qu'une commande à taper.
    let mut pages_du_guide = Vec::new();
    for (i, groupe) in GROUPES.iter().enumerate() {
        let cle = (i + 4).to_string();
        if matches!(groupe, Groupe::Guide) {
            pages_du_guide = guide::lignes_de_recherche(&cle);
            continue;
        }
        if matches!(groupe, Groupe::Depanner) {
            lignes.extend(depanner::lignes_de_recherche(&cle));
            continue;
        }
        let chemin = format!("{} ›", groupe.titre());
        for (j, a) in groupe.actions().iter().filter(|a| a.disponible()).enumerate() {
            let (texte, precision) = a.libelle();
            lignes.push(Ligne::cachee(&format!("{cle}.{}", j + 1), &chemin, texte, precision).avec_mots(a.mots_cles()));
        }
    }
    lignes.extend(pages_du_guide);
    lignes
}

/// Une catégorie de réglages a-t-elle de quoi proposer ici ? Lire les réglages lance des commandes du système : une
/// fois par session suffit, alors que le menu principal le demande à chaque affichage (pour sa recherche).
fn reglages_disponibles(c: optimiser::Categorie) -> bool {
    use optimiser::Categorie::{Confidentialite, Confort, Performance};
    static CATEGORIES: std::sync::OnceLock<[bool; 3]> = std::sync::OnceLock::new();
    let [confidentialite, performance, confort] =
        *CATEGORIES.get_or_init(|| [Confidentialite, Performance, Confort].map(optimiser::a_des_reglages));
    match c {
        Confidentialite => confidentialite,
        Performance => performance,
        Confort => confort,
    }
}

/// Un outil désigné par son chemin, tapé ou trouvé par la recherche : « 5.2 », le 2e outil du groupe 5.
fn outil_au_chemin(chemin: &str) -> Option<Action> {
    let (groupe, outil) = chemin.split_once('.')?;
    let groupe = GROUPES.get(groupe.parse::<usize>().ok()?.checked_sub(4)?)?;
    // Le guide et le dépannage ont leurs propres chemins : système puis programme, parcours (`guide::chemin`,
    // `depanner::chemin`).
    if matches!(groupe, Groupe::Guide | Groupe::Depanner) {
        return None;
    }
    let outil = outil.parse::<usize>().ok()?.checked_sub(1)?;
    groupe.actions().iter().copied().filter(|a| a.disponible()).nth(outil)
}

async fn menu() {
    let mut s = Session::default();
    // La ligne en surbrillance au retour dans le menu : la dernière choisie.
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let lignes = lignes_du_menu(etat_du_menu(surveillance::active()));
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
        // Un outil ou une page du guide, trouvés par la recherche (ou leur chemin tapé : « 5.2 », « 10.2.4 »).
        if let Some((groupe, reste)) = choix.split_once('.') {
            let cle_de = |voulu: fn(&Groupe) -> bool| GROUPES.iter().position(voulu).map(|i| (i + 4).to_string());
            if cle_de(|g| matches!(g, Groupe::Guide)).as_deref() == Some(groupe) {
                if let Some((systeme, programme)) = guide::chemin(reste) {
                    dernier = groupe.to_string();
                    guide::ouvrir(systeme, programme);
                }
            } else if cle_de(|g| matches!(g, Groupe::Depanner)).as_deref() == Some(groupe) {
                if let Some(n) = depanner::chemin(reste) {
                    dernier = groupe.to_string();
                    depanner::ouvrir(n);
                }
            } else if let Some(action) = outil_au_chemin(&choix) {
                dernier = groupe.to_string();
                executer(&mut s, action).await;
                if action.attendre_apres() {
                    demander(&trf!(
                        "\n{GRIS}Entrée pour revenir au menu…{RESET}",
                        "\n{GRIS}Enter to go back to the menu…{RESET}"
                    ));
                }
            }
            continue;
        }
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
    Lenteur,
    Fiche,
    Entretien,
    Diagnostic,
    Maj,
    Reparer,
    Scanner,
    Appareil,
    Nommer,
    Surveillance,
    Connexion,
    ListesNoires,
    WifiCanaux,
    Nat,
    Cameras,
    Alertes,
    AntivirusRapide,
    AntivirusComplet,
    AntivirusDossier,
    Yara,
    Pieges,
    Bac,
    MotsDePasse,
    Courriel,
    QuiParle,
    Lien,
    VerifierFichier,
    Logiciels,
    Gaming,
    Nettoyer,
    OptimiserRecommandes,
    OptimiserConfidentialite,
    #[cfg(not(target_os = "macos"))]
    OptimiserPerformance,
    OptimiserConfort,
    DnsRapide,
    OptimiserAnnuler,
    Sauvegarder,
    CopierFichiers,
    Guide,
    Depanner,
}

impl Action {
    const TOUTES: &[Action] = &[
        Action::Complet,
        Action::Corriger,
        Action::Rapport,
        Action::Audit,
        Action::Integrite,
        Action::Appris,
        Action::Lenteur,
        Action::Fiche,
        Action::Entretien,
        Action::Diagnostic,
        Action::Maj,
        Action::Reparer,
        Action::Scanner,
        Action::Appareil,
        Action::Nommer,
        Action::Surveillance,
        Action::Connexion,
        Action::ListesNoires,
        Action::WifiCanaux,
        Action::Nat,
        Action::Cameras,
        Action::Alertes,
        Action::AntivirusRapide,
        Action::AntivirusComplet,
        Action::AntivirusDossier,
        Action::Yara,
        Action::Pieges,
        Action::Bac,
        Action::MotsDePasse,
        Action::Courriel,
        Action::QuiParle,
        Action::Lien,
        Action::VerifierFichier,
        Action::Logiciels,
        Action::Gaming,
        Action::Nettoyer,
        Action::OptimiserRecommandes,
        Action::OptimiserConfidentialite,
        #[cfg(not(target_os = "macos"))]
        Action::OptimiserPerformance,
        Action::OptimiserConfort,
        Action::DnsRapide,
        Action::OptimiserAnnuler,
        Action::Sauvegarder,
        Action::CopierFichiers,
        Action::Guide,
        Action::Depanner,
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
            Action::OptimiserConfidentialite => reglages_disponibles(optimiser::Categorie::Confidentialite),
            #[cfg(not(target_os = "macos"))]
            Action::OptimiserPerformance => reglages_disponibles(optimiser::Categorie::Performance),
            Action::OptimiserConfort => reglages_disponibles(optimiser::Categorie::Confort),
            _ => true,
        }
    }

    /// Après l'outil, attendre Entrée avant de revenir au menu ? Pas pour ceux qui ont leurs propres écrans et se
    /// quittent par Échap (le guide, le dépannage) : on y reviendrait deux fois.
    fn attendre_apres(self) -> bool {
        !matches!(self, Action::Guide | Action::Depanner)
    }

    /// Des mots que la recherche du menu principal trouve, en plus du texte affiché : ce que l'outil sait faire, en
    /// français et en anglais (jamais affichés).
    fn mots_cles(self) -> &'static str {
        match self {
            Action::Complet | Action::Corriger | Action::Rapport => "bilan check",
            Action::Audit => "sécurité security pare-feu firewall ports ssh chiffrement encryption comptes accounts",
            Action::Integrite => "blake3 empreintes fingerprints fichiers files",
            Action::Appris => "apprentissage learning appris learned choix choices normal oublier forget",
            Action::Entretien => "maintenance mensuel monthly mois month rappel reminder notification",
            Action::Lenteur => "lent slow lenteur rame processeur cpu mémoire memory ram démarrage startup",
            Action::Fiche => {
                "fiche specs matériel hardware modèle model processeur carte graphique gpu mémoire ram série"
            }
            Action::CopierFichiers => "copier copy sauvegarde backup photos disque externe external drive fichiers",
            Action::Depanner => "dépanner troubleshoot panne problème internet son imprimante",
            Action::Diagnostic => "plantages crashes erreurs errors écran bleu bsod journal logs matériel hardware",
            Action::Maj => "update upgrade pilotes drivers firmware bios windows update",
            Action::Reparer => {
                "internet wifi dns proxy hosts pare-feu firewall antivirus disque disk smart heure time sfc dism winsock"
            }
            Action::Scanner | Action::Appareil => "appareils devices ports réseau network lan nmap",
            Action::Nommer => "surnom nickname",
            Action::Surveillance => "monitor surveiller notification",
            Action::Connexion => "ping latence latency débit speed jitter gigue bufferbloat jeu",
            Action::ListesNoires => "spamhaus botnet liste noire blocklist blacklist dnsbl",
            Action::WifiCanaux => {
                "wifi canal canaux channel encombré crowded interférences interference voisins neighbors signal box router"
            }
            Action::Nat => {
                "nat stun upnp console xbox playstation jeu game multijoueur multiplayer redirection port forwarding \
                 ouvert open modéré moderate strict"
            }
            Action::Cameras => "caméra camera espion spy cachée hidden location rental airbnb rtsp onvif",
            Action::Alertes => "ntfy téléphone phone mobile portable notification push",
            Action::AntivirusRapide | Action::AntivirusComplet => "virus malware clamav defender",
            Action::AntivirusDossier => "virus usb clé autorun",
            Action::Yara => "yara règles rules malware",
            Action::Pieges => "rançongiciel ransomware leurre decoy piège trap",
            Action::Bac => "sandbox isoler firejail bubblewrap",
            Action::MotsDePasse => "password hibp pwned fuite leak",
            Action::Courriel => "email mail fuite leak",
            Action::QuiParle => {
                "connexions connections sortantes outbound espion spyware mouchard télémétrie telemetry serveurs servers"
            }
            Action::Lien => "url lien link phishing hameçonnage arnaque scam texto sms courriel email domaine domain",
            Action::VerifierFichier => {
                "sha256 empreinte checksum hash télécharger download iso installateur installer fichier file"
            }
            Action::Logiciels => "apps programmes programs installer install firefox vlc libreoffice",
            Action::Gaming => "jeux games steam directx vulkan",
            Action::Nettoyer => "place space disque plein disk full cache corbeille trash",
            Action::OptimiserRecommandes => "réglages settings",
            Action::OptimiserConfidentialite => "télémétrie telemetry vie privée privacy publicité ads",
            #[cfg(not(target_os = "macos"))]
            Action::OptimiserPerformance => "ssd démarrage startup journal",
            Action::OptimiserConfort => "extensions fichiers cachés hidden files",
            Action::DnsRapide => "dns rapide fast résolveur resolver cloudflare quad9 google adguard vitesse speed",
            Action::OptimiserAnnuler => "annuler undo restaurer",
            Action::Sauvegarder => "backup restore sauvegarde base",
            Action::Guide => "commandes commands terminal aide help",
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
            Action::Entretien => (
                tr!("Entretien du mois", "Monthly check-up"),
                if entretien::active() {
                    tr!("activé : une notification", "on: one notification")
                } else {
                    tr!("désactivé", "off")
                },
            ),
            Action::Lenteur => (
                tr!("Pourquoi c'est lent ?", "Why is it slow?"),
                tr!("processeur, mémoire, démarrage", "processor, memory, startup"),
            ),
            Action::Fiche => (
                tr!("Fiche de l'ordinateur", "Computer specs"),
                tr!("modèle, processeur, mémoire…", "model, processor, memory…"),
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
            Action::WifiCanaux => (
                tr!("Wi-Fi encombré ?", "Crowded Wi-Fi?"),
                tr!("canaux voisins, le plus libre", "nearby channels, the freest"),
            ),
            Action::Nat => (
                tr!("Type de NAT pour le jeu", "NAT type for gaming"),
                tr!("ouvert, modéré ou strict", "open, moderate or strict"),
            ),
            Action::Cameras => (
                tr!("Caméras cachées ?", "Hidden cameras?"),
                tr!("location, chez quelqu'un", "rental, someone else's place"),
            ),
            Action::Alertes => (
                tr!("Alertes sur le téléphone", "Alerts on your phone"),
                if alertes::actives() {
                    tr!("activées (ntfy)", "on (ntfy)")
                } else {
                    tr!("désactivées", "off")
                },
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
            // Textes de 34 caractères au plus dans ce groupe : au-delà, la colonne des précisions recule et les plus
            // longues (YARA, fichiers-pièges) sortent des 76 colonnes.
            Action::Bac => (
                tr!("Bac à sable : programme inconnu", "Sandbox: run an unknown program"),
                tr!("sans réseau, isolé", "no network, isolated"),
            ),
            Action::MotsDePasse => (
                tr!("Mots de passe : ont-ils fuité ?", "Passwords: have they leaked?"),
                tr!("rien n'est envoyé en clair", "nothing sent in clear"),
            ),
            Action::Courriel => (
                tr!("Courriel : a-t-il fuité ?", "Email address: has it leaked?"),
                tr!("avec ton accord", "with your consent"),
            ),
            Action::QuiParle => (
                tr!("Qui parle à Internet ?", "Who talks to the Internet?"),
                tr!("connexions de chaque programme", "each program's connections"),
            ),
            Action::Lien => (
                tr!("Ce lien est-il dangereux ?", "Is this link dangerous?"),
                tr!("examiné sans l'ouvrir", "checked without opening it"),
            ),
            Action::VerifierFichier => (
                tr!("Vérifier un fichier téléchargé", "Check a downloaded file"),
                tr!("empreinte, YARA, antivirus", "checksum, YARA, antivirus"),
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
            Action::DnsRapide => (
                tr!("DNS le plus rapide", "Fastest DNS"),
                tr!("mesuré ici, annulable", "measured here, undoable"),
            ),
            Action::OptimiserAnnuler => (
                tr!("Tout remettre comme avant", "Put everything back"),
                tr!("annule ce que Gardien a changé", "undo what Gardien changed"),
            ),
            Action::Sauvegarder => (
                tr!("Sauvegarder ou restaurer", "Back up or restore"),
                tr!("base des appareils, réglages", "device database, settings"),
            ),
            Action::CopierFichiers => (
                tr!("Copier mes fichiers", "Copy my files"),
                tr!("vers un disque externe, vérifié", "to an external disk, checked"),
            ),
            Action::Guide => (
                tr!("Guide des commandes", "Command guide"),
                tr!("Linux, Windows, macOS, tous", "Linux, Windows, macOS, all"),
            ),
            Action::Depanner => (
                tr!("Dépanner pas à pas", "Troubleshoot step by step"),
                tr!("Internet, son, imprimante…", "Internet, sound, printer…"),
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
    Guide,
    Depanner,
}

const GROUPES: [Groupe; 8] = [
    Groupe::Machine,
    Groupe::Reseau,
    Groupe::Protection,
    Groupe::Installer,
    Groupe::Optimiser,
    Groupe::Donnees,
    Groupe::Guide,
    Groupe::Depanner,
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
            Groupe::Guide => tr!("Guide des commandes", "Command guide"),
            Groupe::Depanner => tr!("Dépanner pas à pas", "Troubleshoot step by step"),
        }
    }

    fn resume(self) -> &'static str {
        match self {
            Groupe::Machine => tr!("audit, mises à jour, réparer…", "audit, updates, repair…"),
            Groupe::Reseau => tr!("appareils, surveillance, débit", "devices, monitoring, speed test"),
            Groupe::Protection => tr!("analyses, clé USB, fuites…", "scans, USB drive, leaks…"),
            Groupe::Installer => tr!("logiciels libres, gaming", "open source software, gaming"),
            Groupe::Optimiser => tr!("nettoyer, confidentialité…", "clean up, privacy…"),
            Groupe::Donnees => tr!("sauvegarder, copier mes fichiers", "back up, copy my files"),
            Groupe::Guide => tr!("Linux, Windows, macOS, tous", "Linux, Windows, macOS, all"),
            Groupe::Depanner => tr!("Internet, son, imprimante…", "Internet, sound, printer…"),
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
                Action::Lenteur,
                Action::Fiche,
                Action::Entretien,
            ],
            Groupe::Reseau => &[
                Action::Scanner,
                Action::Appareil,
                Action::Nommer,
                Action::Surveillance,
                Action::Connexion,
                Action::ListesNoires,
                Action::WifiCanaux,
                Action::Nat,
                Action::Cameras,
                Action::Alertes,
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
                Action::QuiParle,
                Action::Lien,
                Action::VerifierFichier,
            ],
            Groupe::Installer => &[Action::Logiciels, Action::Gaming],
            Groupe::Optimiser => &[
                Action::Nettoyer,
                Action::OptimiserRecommandes,
                Action::OptimiserConfidentialite,
                #[cfg(not(target_os = "macos"))]
                Action::OptimiserPerformance,
                Action::OptimiserConfort,
                Action::DnsRapide,
                Action::OptimiserAnnuler,
            ],
            Groupe::Donnees => &[Action::Sauvegarder, Action::CopierFichiers],
            Groupe::Guide => &[Action::Guide],
            Groupe::Depanner => &[Action::Depanner],
        }
    }
}

/// Sous-menu d'un groupe : ses outils numérotés, Entrée pour revenir au menu principal. Un groupe d'un seul outil
/// (Données) l'ouvre directement. Un outil sans rien à proposer sur ce système n'est pas montré.
async fn sous_menu(s: &mut Session, groupe: Groupe) {
    let actions: Vec<Action> = groupe.actions().iter().copied().filter(|a| a.disponible()).collect();
    if let [seule] = actions[..] {
        executer(s, seule).await;
        if seule.attendre_apres() {
            demander(&trf!(
                "\n{GRIS}Entrée pour revenir au menu…{RESET}",
                "\n{GRIS}Enter to go back to the menu…{RESET}"
            ));
        }
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
        Action::Lenteur => lenteur::menu(),
        Action::Fiche => fiche::fiche(false),
        Action::Entretien => entretien::activer(!entretien::active()),
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
        Action::WifiCanaux => canaux::analyser(),
        Action::Nat => nat::tester(),
        Action::Cameras => cameras::chercher_cameras().await,
        Action::Alertes => alertes::menu(),
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
        Action::QuiParle => sortantes::afficher(),
        Action::Lien => lien::verifier(None),
        Action::VerifierFichier => telechargement::verifier(None, None),
        Action::Logiciels => logiciels::menu(),
        Action::Gaming => gaming::menu(),
        Action::Nettoyer => nettoyer::menu(),
        Action::OptimiserRecommandes => optimiser::recommandes(),
        Action::OptimiserConfidentialite => optimiser::menu(optimiser::Categorie::Confidentialite),
        #[cfg(not(target_os = "macos"))]
        Action::OptimiserPerformance => optimiser::menu(optimiser::Categorie::Performance),
        Action::OptimiserConfort => optimiser::menu(optimiser::Categorie::Confort),
        Action::DnsRapide => dns_rapide::mesurer_et_proposer(),
        Action::OptimiserAnnuler => optimiser::tout_annuler(),
        Action::Sauvegarder => donnees::menu(),
        Action::CopierFichiers => copier::menu(),
        Action::Guide => guide::menu(),
        Action::Depanner => depanner::menu(),
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
            "entretien",
            "Monthly check-up: once a month, silently, the grade, waiting updates, space to free and new problems, in one notification; nothing is changed. Without argument: what it would say now",
        ),
        (
            "alertes",
            "Alerts on your phone through ntfy (monitoring, monthly check-up): turn them on after your consent, off, or send a test alert. Without argument: the menu",
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
            "canaux",
            "Crowded Wi-Fi: nearby networks by channel, and the freest channel to set on the router. Read-only",
        ),
        (
            "nat",
            "NAT type for gaming (open, moderate or strict), from two public servers (STUN). Read-only",
        ),
        (
            "cameras",
            "Hidden cameras: on a rental's or someone's network, the devices that look like cameras. Read-only",
        ),
        (
            "dns-rapide",
            "Fastest DNS: measures the current DNS and public ones, then offers the fastest, undoable. A DNS that protects (NextDNS, encrypted, filtering) is kept",
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
            "sortantes",
            "Who talks to the Internet? Each program's current connections, with the server's name. Read-only",
        ),
        (
            "lien",
            "Is this link dangerous? Checked without ever opening it; after your consent, its age and public lists",
        ),
        (
            "verifier-fichier",
            "Check a downloaded file: checksum compared with the site's, name and content, YARA and antivirus",
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
        (
            "guide",
            "Command guide: the useful commands of Linux, Windows, macOS and all systems, sorted by program",
        ),
        (
            "lenteur",
            "Why is it slow? What keeps the processor, memory and disk busy, startup, the programs started at login. Read only",
        ),
        (
            "fiche",
            "Computer specs: model, motherboard, processor, memory, graphics card, disks, system. Serial numbers are shown on screen only",
        ),
        (
            "copier-fichiers",
            "Copy my files (Documents, Pictures, Desktop, Videos, Music) to an external disk: checked copy, nothing deleted or overwritten, an interrupted copy resumes",
        ),
        (
            "depanner",
            "Troubleshoot step by step: no Internet, Wi-Fi dropping, slow computer, no sound, printer, disk full",
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
    .mut_subcommand("lien", |s| {
        s.mut_arg("adresse", |a| {
            a.help("The link you received (in quotes if it contains “&” or “?”)")
        })
    })
    .mut_subcommand("verifier-fichier", |s| {
        s.mut_arg("fichier", |a| a.help("The downloaded file"))
            .mut_arg("empreinte", |a| {
                a.help("The checksum published by the site (preferably SHA-256). Otherwise: a SHA256SUMS or .sha256 next to it")
            })
    })
    .mut_subcommand("guide", |s| {
        s.mut_arg("quoi", |a| {
            a.help("A system (linux, windows, macos, all), a program (systemctl, winget…) or words to look for")
        })
    })
    .mut_subcommand("fiche", |s| {
        s.mut_arg("json", |a| {
            a.help("The specs as JSON, for a script (without the serial numbers)")
        })
    })
    .mut_subcommand("copier-fichiers", |s| {
        s.mut_arg("destination", |a| {
            a.help("A folder on an external disk (default: chosen among the plugged-in disks)")
        })
    })
    .mut_subcommand("depanner", |s| {
        s.mut_arg("sujet", |a| {
            a.help("The subject: internet, wifi, slow, sound, printer, disk (or words describing it)")
        })
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
        Some(Commande::Entretien { etat }) => match etat {
            Some(e) => entretien::activer(e == "on"),
            None => entretien::maintenant(),
        },
        Some(Commande::Entretenir) => entretien::entretenir(),
        Some(Commande::Alertes { etat }) => alertes::commande(etat.as_deref()),
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
        Some(Commande::Sortantes) => sortantes::afficher(),
        Some(Commande::Lien { adresse }) => lien::verifier(Some(&adresse)),
        Some(Commande::VerifierFichier { fichier, empreinte }) => {
            telechargement::verifier(Some(&fichier), empreinte.as_deref());
        }
        Some(Commande::Isoler { fichier }) => isoler::isoler(&fichier),
        Some(Commande::Pieges { retirer }) => pieges::commande(retirer),
        Some(Commande::Yara { complet, dossier }) => yara::analyser(&match (dossier, complet) {
            (Some(d), _) => antivirus::Portee::Dossier(d),
            (None, true) => antivirus::Portee::Complete,
            (None, false) => antivirus::Portee::Rapide,
        }),
        Some(Commande::ListesNoires) => listes_noires::verifier(),
        Some(Commande::Canaux) => canaux::analyser(),
        Some(Commande::Nat) => nat::tester(),
        Some(Commande::Cameras) => cameras::chercher_cameras().await,
        Some(Commande::DnsRapide) => dns_rapide::mesurer_et_proposer(),
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
        Some(Commande::Guide { quoi }) => guide::executer(&quoi.join(" ")),
        Some(Commande::Lenteur) => lenteur::commande(),
        Some(Commande::Fiche { json }) => fiche::fiche(json),
        Some(Commande::CopierFichiers { destination }) => copier::commande(destination.as_deref()),
        Some(Commande::Depanner { sujet }) => depanner::executer(&sujet.join(" ")),
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

    #[test]
    fn le_menu_principal_tient_dans_24_lignes() {
        // Trois lignes d'état (dernier bilan, connexion, clé) : le menu le plus haut. Avec l'aide et la saisie, il doit
        // tenir dans un terminal de 24 lignes, sinon les flèches ne marchent plus.
        let lignes = lignes_du_menu(vec![String::new(); 3]);
        let affichees = lignes.iter().filter(|l| !matches!(l, Ligne::Cachee { .. })).count();
        assert!(affichees + 2 <= 24, "{affichees} lignes affichées");
        // La recherche voit plus que l'écran : outils des sous-menus et pages du guide.
        assert!(lignes.len() > affichees + 50);
    }

    #[test]
    fn chaque_outil_trouve_par_la_recherche_s_ouvre() {
        for (i, g) in GROUPES.iter().enumerate() {
            if matches!(g, Groupe::Guide | Groupe::Depanner) {
                continue;
            }
            for (j, a) in g.actions().iter().filter(|a| a.disponible()).enumerate() {
                assert!(outil_au_chemin(&format!("{}.{}", i + 4, j + 1)) == Some(*a));
            }
        }
        assert!(outil_au_chemin("4.99").is_none() && outil_au_chemin("x.1").is_none());
        assert!(outil_au_chemin("10.1").is_none(), "le guide a ses propres chemins");
        assert!(outil_au_chemin("11.1").is_none(), "le dépannage a ses propres chemins");
        // Les places annoncées : 4.7, 4.8 et 9.2.
        assert!(outil_au_chemin("4.7") == Some(Action::Lenteur));
        assert!(outil_au_chemin("4.8") == Some(Action::Fiche));
        assert!(outil_au_chemin("9.2") == Some(Action::CopierFichiers));
        assert!(depanner::chemin("1").is_some());
    }
}
