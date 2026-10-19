//! Vanguard — sécurise et optimise ta machine et ton réseau : bilan, correctifs, réglages.
//!
//! N'utilise le scan réseau que sur un réseau qui t'appartient ou que tu as le droit d'auditer.
//! Lancé sans argument, affiche un menu.

mod a_laisser;
mod apprentissage;
mod changements;
mod chiffrement;
mod commande;
mod copier;
mod corriger;
mod depanner;
mod diagnostic;
mod dns_rapide;
mod donnees;
mod entretien;
mod fiche;
mod gaming;
mod guide;
mod historique;
mod journal;
mod langue;
mod lenteur;
mod logiciels;
mod machine;
mod maj;
mod nettoyer;
mod optimiser;
mod ordinateurs;
mod passage;
mod prediction;
mod protection;
mod raccourci;
mod rapport;
mod reparer;
mod reseau;
mod risk;
mod sauvegarde;
mod selection;
mod ui;
mod verifier_cle;

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
        #[arg(long, visible_alias = "full")]
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
    /// Ce que Vanguard a appris sur cet ordinateur : les alertes déclarées normales, et les oublier.
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
    /// Blocages de Windows Defender : règles ASR, protection réseau, logiciels indésirables, accès contrôlé aux
    /// dossiers. Chacun s'active après accord et s'annule exactement (Windows seulement).
    #[command(visible_alias = "harden")]
    Durcir,
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
    /// Quelqu'un contrôle mon ordinateur ? Les logiciels de prise de contrôle à distance (AnyDesk, TeamViewer,
    /// RustDesk…) installés, lancés au démarrage, en cours ou téléchargés : l'outil des faux techniciens. Retrait
    /// après accord ; un programme en cours demande un second accord.
    #[command(visible_alias = "remote-access")]
    Distance,
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
    /// Caméra et micro : qui s'en sert ? Sous Windows, chaque programme et la dernière fois ; sous Linux, ce qui les
    /// tient en ce moment. Lecture seule.
    #[command(name = "camera-micro", visible_alias = "camera-mic")]
    CameraMicro,
    /// Quarantaine : les fichiers isolés par l'antivirus ou YARA, à remettre à leur place (faux positif) ou à
    /// supprimer pour de bon.
    #[command(visible_alias = "quarantine")]
    Quarantaine,
    /// Sauvegarde la base des appareils et l'état de la surveillance dans un fichier JSON.
    #[command(visible_alias = "backup")]
    Sauvegarder {
        /// Fichier à écrire (par défaut : vanguard-sauvegarde-AAAA-MM-JJ.json dans le dossier personnel ou Documents).
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
    /// Guide des commandes : celles d'Omarchy, d'Arch, de Fedora, de Debian, des autres Linux, de Windows, de macOS et
    /// de tous les systèmes, rangées par programme, avec des marches à suivre ; et les exemples de tldr-pages,
    /// téléchargés chaque semaine.
    Guide {
        /// Un système (omarchy, arch, fedora, debian, windows, macos, tous ; linux : les programmes communs ; tldr), un
        /// programme (systemctl, winget, tar…) ou des mots à chercher.
        quoi: Vec<String>,
    },
    /// Pourquoi c'est lent ? Ce qui occupe le processeur, la mémoire et le disque, le démarrage, les programmes lancés
    /// à l'ouverture de session. Lecture seule.
    #[command(visible_alias = "slow")]
    Lenteur,
    /// Programmes au démarrage : ceux qui se lancent à l'ouverture de session, à retirer ou à remettre après accord.
    /// Chaque retrait s'annule exactement (Optimiser › Tout remettre comme avant).
    #[command(visible_alias = "startup")]
    Demarrage,
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
    /// Vérifier une copie faite par « Copier mes fichiers » (test de restauration) : des fichiers répartis sur toute
    /// la copie, relus sur le disque et comparés à leur original. Rien n'est écrit ni effacé.
    #[command(name = "verifier-copie", visible_alias = "check-copy")]
    VerifierCopie {
        /// Le disque ou le dossier de la copie (par défaut : choisi parmi les disques branchés).
        dossier: Option<std::path::PathBuf>,
    },
    /// Vérifier ma clé : capacité réelle (fausses clés), vitesses et blocs en erreur d'une clé USB ou d'un disque
    /// externe. Écrit dans l'espace libre après accord, relit, puis efface ; tes fichiers ne sont pas touchés.
    #[command(name = "verifier-cle", visible_alias = "check-drive")]
    VerifierCle {
        /// Un dossier de la clé ou du disque (par défaut : choisi parmi les disques branchés).
        dossier: Option<std::path::PathBuf>,
    },
    /// Rapport à laisser : une page simple pour la personne qu'on vient de dépanner (note, ce qu'il lui reste à faire,
    /// ce qui va bien), posée sur son Bureau après accord et ouverte dans le navigateur.
    #[command(name = "a-laisser", visible_alias = "handout")]
    ALaisser,
    /// Ce que Vanguard a changé : chaque correction lancée sur cet ordinateur, sa date et son résultat.
    #[command(visible_alias = "changes")]
    Changements,
    /// Sauvegarde automatique : mise en place avec l'outil du système (Déjà Dup ou rsync chaque jour, Time Machine,
    /// Historique des fichiers) vers un disque externe, après accord, annulable exactement.
    #[command(name = "sauvegarde-auto", visible_alias = "auto-backup")]
    SauvegardeAuto {
        /// Retirer la sauvegarde automatique mise en place par Vanguard (les fichiers sauvegardés restent).
        #[arg(long, visible_alias = "undo")]
        annuler: bool,
    },
    /// Raccourci sur cet ordinateur : Vanguard copié ici et lancé d'un clic (menu des applications sous Linux, Bureau
    /// sous Windows et macOS). Sans argument : l'état, puis la proposition.
    #[command(visible_alias = "shortcut")]
    Raccourci {
        #[arg(value_parser = ["on", "off"])]
        etat: Option<String>,
    },
    /// Mes ordinateurs : ceux où la clé VANGUARD a fait un bilan, leur note et leurs problèmes restants (sur la
    /// partition VANGUARDLOG de la clé).
    #[command(visible_alias = "computers")]
    Ordinateurs,
    /// Les règles du bilan déclarées pour ce système : identifiant stable, sujet, références de durcissement.
    #[command(visible_alias = "rules")]
    Regles,
    /// Dépanner pas à pas : pas d'Internet, Wi-Fi qui coupe, ordinateur lent, pas de son, imprimante, disque plein ;
    /// après une infection, nouvel ordinateur, ordinateur qui part (vente, don).
    #[command(visible_alias = "troubleshoot")]
    Depanner {
        /// Le sujet : internet, wifi, lent, son, imprimante, disque, infection, nouveau, depart (ou des mots qui le
        /// décrivent).
        sujet: Vec<String>,
    },
    /// Vérifier Vanguard lui-même : version, date de compilation, empreinte SHA-256 du programme (à comparer à la
    /// page de la version) et, sur la clé du propriétaire, le manifeste de la clé.
    #[command(name = "verifier-moi", visible_alias = "self-check")]
    VerifierMoi,
    /// Manifeste de la clé VANGUARD : écrit au déploiement (outils/deployer.sh), comparé à la clé branchée.
    #[command(hide = true)]
    Manifeste {
        /// Écrire le manifeste de ce dossier (la racine de la clé) dans la référence de cet ordinateur.
        #[arg(long)]
        ecrire: Option<std::path::PathBuf>,
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
        // Sur la clé VANGUARD branchée (partition VANGUARDLOG) : la visite de cet ordinateur, pour « Mes ordinateurs ».
        ordinateurs::noter(self.audit.as_ref(), self.reseau.as_ref());
        if let Some(p) = precedent {
            historique::afficher_changements(&p, &nouveau);
        }
        let a_corriger = self.audit.as_ref().is_some_and(|a| {
            a.constats
                .iter()
                .any(|c| c.correctif.as_ref().is_some_and(|k| k.automatique))
        });
        if a_corriger {
            let cle = cle_a_molette();
            trp!(
                "\n  {cle} Des corrections sont possibles : choix « 2 » du menu ou « vanguard corriger ».",
                "\n  {cle} Fixes are available: menu choice “2” or “vanguard fix”."
            );
        }
        let _ = rapport::generer(self.audit.as_ref(), self.reseau.as_ref());
    }

    fn corriger(&mut self) {
        let audit = self.audit.get_or_insert_with(|| machine::executer(false));
        if let Some(nouveau) = corriger::corriger(audit, self.reseau.as_ref()) {
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

/// Lancé en root (sudo) : Vanguard n'en a pas besoin, et une sortie piégée aurait tous les droits. Dit, jamais imposé :
/// sans session graphique ni agent polkit, pkexec ne peut rien demander, et « sudo vanguard » est alors la seule façon
/// de corriger. Sous Windows, une console administrateur est l'habitude de certains : rien d'alarmant.
#[cfg(unix)]
fn avertir_si_root() {
    // SAFETY : geteuid ne prend aucun argument et ne touche aucune mémoire ; il rend l'identifiant effectif du processus.
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    for (i, ligne) in envelopper(
        tr!(
            "Vanguard tourne en root (sudo) : il n'en a pas besoin, chaque correction demande le mot de passe au moment voulu, et une sortie piégée aurait ici tous les droits. Relance-le sans sudo, sauf si aucune fenêtre ne peut demander le mot de passe sur cet ordinateur (pas de session graphique) : alors continue.",
            "Vanguard is running as root (sudo): it does not need it, each fix asks for the password when needed, and a booby-trapped output would have every right here. Start it again without sudo, unless no window can ask for the password on this computer (no graphical session): then carry on."
        ),
        LARGEUR - 4,
    )
    .into_iter()
    .enumerate()
    {
        if i == 0 {
            eprintln!("  {}⚠{RESET} {ligne}", couleur(risk::Niveau::Moyen));
        } else {
            eprintln!("    {ligne}");
        }
    }
}

#[cfg(windows)]
fn avertir_si_root() {}

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
    if let Some(c) = reseau::connexion::historique().last() {
        let debit = |d: Option<f64>| d.map_or_else(|| "?".to_string(), |d| format!("{d:.0}"));
        let bufferbloat = c
            .hausse_ms
            .map(|h| {
                let (n, niveau) = reseau::connexion::note_bufferbloat(h);
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
                "clé VANGUARD branchée (protégée en écriture)",
                "VANGUARD key plugged in (write-protected)"
            )
        )
    } else if reseau::cle_usb().is_some() {
        format!(
            "{VERT}{}{RESET}",
            tr!("clé VANGUARD branchée", "VANGUARD key plugged in")
        )
    } else {
        format!("{GRIS}{}{RESET}", tr!("clé non branchée", "key not plugged in"))
    };
    let surveillance = if surveillance_active {
        format!("{VERT}{}{RESET}", tr!("surveillance active", "monitoring on"))
    } else {
        format!("{GRIS}{}{RESET}", tr!("surveillance coupée", "monitoring off"))
    };
    lignes.push(format!("  {cle} {GRIS}·{RESET} {surveillance}"));
    if let Some(a) = protection::manifeste::avertissement_perime() {
        lignes.push(format!("  {}⚠{RESET} {a}", couleur(risk::Niveau::Moyen)));
    }
    lignes
}

/// Lignes vides et sous-titre « ── NOM ──── » d'un menu.
fn section_du_menu(t: &str) -> [Ligne; 2] {
    [Ligne::Texte(String::new()), Ligne::Texte(ligne_section(t))]
}

/// Les lignes du menu principal, sous l'état (dernier bilan, clé, surveillance).
fn lignes_du_menu(etat: Vec<String>) -> Vec<Ligne> {
    let mut lignes: Vec<Ligne> = lignes_cadre(
        &format!("{ACCENT}VANGUARD{RESET} {GRIS}{}{RESET}", env!("CARGO_PKG_VERSION")),
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
    let principal = [Action::Complet, Action::Corriger, Action::Rapport];
    for (touche, action) in principal.into_iter().enumerate() {
        let a_droite = if touche == 0 {
            tr!("← commencer ici", "← start here")
        } else {
            ""
        };
        lignes.push(Ligne::choix(&(touche + 1).to_string(), action.libelle().0, a_droite));
    }

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
        for (j, a) in groupe.actions().into_iter().filter(|a| a.disponible()).enumerate() {
            let (texte, precision) = a.libelle();
            lignes
                .push(Ligne::cachee(&format!("{cle}.{}", j + 1), &chemin, texte, precision).avec_mots(a.outil().mots));
        }
    }
    lignes.extend(pages_du_guide);
    lignes
}

/// Une catégorie de réglages a-t-elle de quoi proposer ici ? Lire les réglages lance des commandes du système : une
/// fois par session suffit, alors que le menu principal le demande à chaque affichage (pour sa recherche).
fn reglages_disponibles(c: optimiser::Categorie) -> bool {
    use optimiser::Categorie::{Confidentialite, Confort, Performance, Protection};
    static CATEGORIES: std::sync::OnceLock<[bool; 3]> = std::sync::OnceLock::new();
    let [confidentialite, performance, confort] =
        *CATEGORIES.get_or_init(|| [Confidentialite, Performance, Confort].map(optimiser::a_des_reglages));
    match c {
        Confidentialite => confidentialite,
        Performance => performance,
        Confort => confort,
        Protection => cfg!(windows),
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
    groupe.actions().into_iter().filter(|a| a.disponible()).nth(outil)
}

async fn menu() {
    let mut s = Session::default();
    // La ligne en surbrillance au retour dans le menu : la dernière choisie.
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let lignes = lignes_du_menu(etat_du_menu(reseau::surveillance::active()));
        let Some(choix) = choix_du_menu(&lignes, &dernier, tr!("quitter", "quit")) else {
            break;
        };
        let choix = choix.trim().to_lowercase();
        println!();
        // Un outil, une page ou une commande du guide, trouvés par la recherche (ou leur chemin tapé : « 5.2 »,
        // « 10.3.1 », « 10.3.1.2 »).
        if let Some((groupe, reste)) = choix.split_once('.') {
            let cle_de = |voulu: Groupe| GROUPES.iter().position(|g| *g == voulu).map(|i| (i + 4).to_string());
            if cle_de(Groupe::Guide).as_deref() == Some(groupe) {
                if let Some((systeme, programme, commande)) = guide::chemin(reste) {
                    dernier = groupe.to_string();
                    guide::ouvrir(systeme, programme, commande);
                }
            } else if cle_de(Groupe::Depanner).as_deref() == Some(groupe) {
                if let Some(n) = depanner::chemin(reste) {
                    dernier = groupe.to_string();
                    depanner::ouvrir(n);
                }
            } else if let Some(action) = outil_au_chemin(&choix) {
                dernier = groupe.to_string();
                executer(&mut s, action).await;
                revenir_au_menu(action);
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
            autre => match OUTILS.iter().find(|o| !o.lettre.is_empty() && o.lettre == autre) {
                Some(o) => o.action,
                None => continue,
            },
        };
        dernier = choix;
        executer(&mut s, action).await;
        revenir_au_menu(action);
    }
}

/// Le choix fait dans un menu, avec l'invite commune (`None` : Échap, qui fait `echap`).
fn choix_du_menu(lignes: &[Ligne], dernier: &str, echap: &str) -> Option<String> {
    let invite = format!("  {ACCENT}›{RESET} {}", tr!("Choix : ", "Choice: "));
    choisir(lignes, &invite, dernier, echap)
}

/// Après un outil lancé du menu : Entrée pour y revenir, sauf pour ceux qui ont leurs propres écrans.
fn revenir_au_menu(action: Action) {
    if action.attendre_apres() {
        demander(&trf!(
            "\n{GRIS}Entrée pour revenir au menu…{RESET}",
            "\n{GRIS}Enter to go back to the menu…{RESET}"
        ));
    }
}

/// Ce que le menu sait faire, dans l'ordre des sous-menus : la ligne d'un outil dans `OUTILS` est à son numéro.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Complet,
    Corriger,
    Rapport,
    Audit,
    Maj,
    Reparer,
    Diagnostic,
    Integrite,
    Appris,
    Lenteur,
    Fiche,
    ALaisser,
    Changements,
    Entretien,
    Scanner,
    Appareil,
    Nommer,
    Surveillance,
    Connexion,
    ListesNoires,
    WifiCanaux,
    Nat,
    Cameras,
    AntivirusRapide,
    AntivirusComplet,
    AntivirusDossier,
    Yara,
    Pieges,
    Protection,
    Bac,
    MotsDePasse,
    Courriel,
    QuiParle,
    CameraMicro,
    Distance,
    Lien,
    VerifierFichier,
    Quarantaine,
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
    SauvegardeAuto,
    VerifierCopie,
    VerifierCle,
    Raccourci,
    Ordinateurs,
    ProtegerDonnees,
    Guide,
    Depanner,
}

/// Un outil du menu : son groupe (aucun pour 1, 2 et 3, au menu principal), sa lettre des menus d'avant la 0.43
/// (vide : aucune ; les chiffres, eux, ont changé de sens), son titre et sa précision en français puis en anglais, et
/// les mots que la recherche trouve en plus, jamais affichés.
struct Outil {
    action: Action,
    groupe: Option<Groupe>,
    lettre: &'static str,
    titre: [&'static str; 2],
    precision: [&'static str; 2],
    mots: &'static str,
}

/// Une ligne par outil, dans l'ordre de `Action` et des sous-menus (4.1, 4.2…). La précision des outils à interrupteur
/// (surveillance, entretien) suit leur état : `Action::libelle`.
#[rustfmt::skip] // une ligne de données par outil, que rustfmt étalerait sur huit
const OUTILS: &[Outil] = &[
    Outil { action: Action::Complet, groupe: None, lettre: "",
        titre: ["Bilan complet : machine + réseau", "Full check: machine + network"], precision: ["", ""],
        mots: "" },
    Outil { action: Action::Corriger, groupe: None, lettre: "",
        titre: ["Corriger les problèmes trouvés", "Fix the problems found"], precision: ["", ""],
        mots: "" },
    Outil { action: Action::Rapport, groupe: None, lettre: "",
        titre: ["Rapport détaillé dans le navigateur", "Detailed report in the browser"], precision: ["", ""],
        mots: "" },
    Outil { action: Action::Audit, groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Audit de sécurité", "Security audit"],
        precision: ["pare-feu, comptes, chiffrement…", "firewall, accounts, encryption…"],
        mots: "sécurité security pare-feu firewall ports ssh chiffrement encryption comptes accounts" },
    Outil { action: Action::Maj, groupe: Some(Groupe::Machine), lettre: "u",
        titre: ["Mises à jour", "Updates"], precision: ["système, programmes, pilotes", "system, programs, drivers"],
        mots: "update upgrade pilotes drivers firmware bios windows update" },
    Outil { action: Action::Reparer, groupe: Some(Groupe::Machine), lettre: "r",
        titre: ["Réparer et nettoyer", "Repair and clean up"],
        precision: ["réseau, disque, système…", "network, disk, system…"],
        mots: "internet wifi dns proxy hosts pare-feu firewall antivirus disque disk smart heure time sfc dism \
               winsock" },
    Outil { action: Action::Diagnostic, groupe: Some(Groupe::Machine), lettre: "o",
        titre: ["Diagnostic", "Diagnostic"], precision: ["matériel, plantages, erreurs", "hardware, crashes, errors"],
        mots: "plantages crashes erreurs errors écran bleu bsod journal logs matériel hardware" },
    Outil { action: Action::Integrite, groupe: Some(Groupe::Machine), lettre: "i",
        titre: ["Intégrité des fichiers critiques", "Critical file integrity"],
        precision: ["comptes, sudo, SSH, démarrage…", "accounts, sudo, SSH, startup…"],
        mots: "blake3 empreintes fingerprints fichiers files" },
    Outil { action: Action::Appris, groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Ce que Vanguard a appris", "What Vanguard has learned"],
        precision: ["tes choix, tes habitudes", "your choices, your habits"],
        mots: "apprentissage learning appris learned choix choices normal oublier forget" },
    Outil { action: Action::Lenteur, groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Pourquoi c'est lent ?", "Why is it slow?"],
        precision: ["processeur, mémoire, démarrage", "processor, memory, startup"],
        mots: "lent slow lenteur rame processeur cpu mémoire memory ram démarrage startup" },
    Outil { action: Action::Fiche, groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Fiche de l'ordinateur", "Computer specs"],
        precision: ["modèle, processeur, mémoire…", "model, processor, memory…"],
        mots: "fiche specs matériel hardware modèle model processeur carte graphique gpu mémoire ram série" },
    Outil { action: Action::ALaisser, groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Rapport à laisser", "Report to leave behind"],
        precision: ["une page simple, à imprimer", "a simple page, to print"],
        mots: "rapport report imprimer print dépannage help famille family laisser leave page résumé summary" },
    Outil { action: Action::Changements, groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Ce que Vanguard a changé", "What Vanguard changed"],
        precision: ["chaque correction, datée", "each fix, dated"],
        mots: "changements changes historique history corrections fixes journal log annuler undo" },
    Outil { action: Action::Entretien, groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Entretien du mois", "Monthly check-up"], precision: ["", ""],
        mots: "maintenance mensuel monthly mois month rappel reminder notification" },
    Outil { action: Action::Scanner, groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Scanner le réseau", "Scan the network"],
        precision: ["appareils, ports, nouveautés", "devices, ports, changes"],
        mots: "appareils devices ports réseau network lan nmap" },
    Outil { action: Action::Appareil, groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Scan approfondi d'un appareil", "Deep scan of one device"], precision: ["tous les ports", "all ports"],
        mots: "appareils devices ports réseau network lan nmap" },
    Outil { action: Action::Nommer, groupe: Some(Groupe::Reseau), lettre: "n",
        titre: ["Nommer un appareil", "Name a device"], precision: ["« imprimante HP »", "“HP printer”"],
        mots: "surnom nickname" },
    Outil { action: Action::Surveillance, groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Surveillance toutes les heures", "Hourly monitoring"], precision: ["", ""],
        mots: "monitor surveiller notification" },
    Outil { action: Action::Connexion, groupe: Some(Groupe::Reseau), lettre: "c",
        titre: ["Test de connexion pour le jeu", "Connection test for gaming"],
        precision: ["ping, gigue, débit, bufferbloat", "ping, jitter, speed, bufferbloat"],
        mots: "ping latence latency débit speed jitter gigue bufferbloat jeu" },
    Outil { action: Action::ListesNoires, groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Adresse sur liste noire ?", "Address on blocklists?"],
        precision: ["si oui, un appareil est infecté", "if so, a device is infected"],
        mots: "spamhaus botnet liste noire blocklist blacklist dnsbl" },
    Outil { action: Action::WifiCanaux, groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Wi-Fi encombré ?", "Crowded Wi-Fi?"],
        precision: ["canaux voisins, le plus libre", "nearby channels, the freest"],
        mots: "wifi canal canaux channel encombré crowded interférences interference voisins neighbors signal box \
               router" },
    Outil { action: Action::Nat, groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Type de NAT pour le jeu", "NAT type for gaming"],
        precision: ["ouvert, modéré ou strict", "open, moderate or strict"],
        mots: "nat stun upnp console xbox playstation jeu game multijoueur multiplayer redirection port forwarding \
               ouvert open modéré moderate strict" },
    Outil { action: Action::Cameras, groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Caméras cachées ?", "Hidden cameras?"],
        precision: ["location, chez quelqu'un", "rental, someone else's place"],
        mots: "caméra camera espion spy cachée hidden location rental airbnb rtsp onvif" },
    Outil { action: Action::AntivirusRapide, groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Analyse rapide", "Quick scan"], precision: ["téléchargements, bureau…", "downloads, desktop…"],
        mots: "virus malware clamav defender" },
    Outil { action: Action::AntivirusComplet, groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Analyse complète", "Full scan"], precision: ["dossier personnel", "home folder"],
        mots: "virus malware clamav defender" },
    Outil { action: Action::AntivirusDossier, groupe: Some(Groupe::Protection), lettre: "a",
        titre: ["Clé USB ou dossier", "USB drive or folder"], precision: ["et pièges de clé", "and drive traps"],
        mots: "virus usb clé autorun" },
    Outil { action: Action::Yara, groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Analyse YARA", "YARA scan"],
        precision: ["règles de logiciels malveillants", "malware detection rules"],
        mots: "yara règles rules malware" },
    Outil { action: Action::Pieges, groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Fichiers-pièges", "Decoy files"],
        precision: ["alerte si un rançongiciel chiffre", "early ransomware warning"],
        mots: "rançongiciel ransomware leurre decoy piège trap" },
    Outil { action: Action::Protection, groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Blocages de Windows Defender", "Windows Defender blocking"],
        precision: ["ASR, réseau, dossiers contrôlés", "ASR, network, folders"],
        mots: "defender asr bloquer block exploit dossiers contrôlés controlled folder pua" },
    // Titres de 34 caractères au plus dans ce groupe : au-delà, la colonne des précisions recule et les plus
    // longues (YARA, fichiers-pièges) sortent des 76 colonnes.
    Outil { action: Action::Bac, groupe: Some(Groupe::Protection), lettre: "b",
        titre: ["Bac à sable : programme inconnu", "Sandbox: run an unknown program"],
        precision: ["sans réseau, isolé", "no network, isolated"],
        mots: "sandbox isoler firejail bubblewrap" },
    Outil { action: Action::MotsDePasse, groupe: Some(Groupe::Protection), lettre: "p",
        titre: ["Mots de passe : ont-ils fuité ?", "Passwords: have they leaked?"],
        precision: ["rien n'est envoyé en clair", "nothing sent in clear"],
        mots: "password hibp pwned fuite leak" },
    Outil { action: Action::Courriel, groupe: Some(Groupe::Protection), lettre: "e",
        titre: ["Courriel : a-t-il fuité ?", "Email address: has it leaked?"],
        precision: ["avec ton accord", "with your consent"],
        mots: "email mail fuite leak" },
    Outil { action: Action::QuiParle, groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Qui parle à Internet ?", "Who talks to the Internet?"],
        precision: ["connexions de chaque programme", "each program's connections"],
        mots: "connexions connections sortantes outbound espion spyware mouchard télémétrie telemetry serveurs \
               servers" },
    Outil { action: Action::CameraMicro, groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Caméra et micro : qui s'en sert ?", "Camera and mic: who uses them?"],
        precision: ["programmes et dernière fois", "programs and last time"],
        mots: "caméra camera webcam micro microphone espion spy écoute voyant light enregistre record" },
    Outil { action: Action::Distance, groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Quelqu'un contrôle mon ordi ?", "Is someone controlling my PC?"],
        precision: ["faux technicien, accès à distance", "tech-support scam, remote access"],
        mots: "arnaque scam faux technicien fake tech support anydesk teamviewer rustdesk accès distance remote \
               access contrôle control prise de contrôle" },
    Outil { action: Action::Lien, groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Ce lien est-il dangereux ?", "Is this link dangerous?"],
        precision: ["examiné sans l'ouvrir", "checked without opening it"],
        mots: "url lien link phishing hameçonnage arnaque scam texto sms courriel email domaine domain" },
    Outil { action: Action::VerifierFichier, groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Vérifier un fichier téléchargé", "Check a downloaded file"],
        precision: ["empreinte, YARA, antivirus", "checksum, YARA, antivirus"],
        mots: "sha256 empreinte checksum hash télécharger download iso installateur installer fichier file" },
    Outil { action: Action::Quarantaine, groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Quarantaine : remettre un fichier", "Quarantine: restore a file"],
        precision: ["isolés, remis à l'identique", "isolated, put back exactly"],
        mots: "quarantaine quarantine isolé isolated faux positif false positive remettre restore restaurer" },
    Outil { action: Action::Logiciels, groupe: Some(Groupe::Installer), lettre: "l",
        titre: ["Logiciels", "Software"], precision: ["les meilleurs, par catégorie", "the best ones, by category"],
        mots: "apps programmes programs installer install firefox vlc libreoffice" },
    Outil { action: Action::Gaming, groupe: Some(Groupe::Installer), lettre: "g",
        titre: ["Gaming", "Gaming"],
        precision: if cfg!(windows) { ["composants et réglages de Windows", "components and Windows settings"] }
            else if cfg!(target_os = "macos") { ["Rosetta, Steam, Epic, GOG…", "Rosetta, Steam, Epic, GOG…"] }
            else { ["Steam, Vulkan, GameMode, Wine…", "Steam, Vulkan, GameMode, Wine…"] },
        mots: "jeux games steam directx vulkan" },
    Outil { action: Action::Nettoyer, groupe: Some(Groupe::Optimiser), lettre: "v",
        titre: ["Nettoyer le système", "Clean up the system"],
        precision: ["caches, temporaires, corbeille…", "caches, temp files, trash…"],
        mots: "place space disque plein disk full cache corbeille trash" },
    Outil { action: Action::OptimiserRecommandes, groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Réglages recommandés", "Recommended settings"],
        precision: ["en une fois, tout s'annule", "in one go, all undoable"],
        mots: "réglages settings" },
    Outil { action: Action::OptimiserConfidentialite, groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Confidentialité", "Privacy"],
        precision: if cfg!(windows) { ["télémétrie, publicités, suivi", "telemetry, ads, tracking"] }
            else if cfg!(target_os = "macos") { ["publicités, analyses", "ads, analytics"] }
            else { ["rapports et statistiques", "reports and statistics"] },
        mots: "télémétrie telemetry vie privée privacy publicité ads" },
    #[cfg(not(target_os = "macos"))]
    Outil { action: Action::OptimiserPerformance, groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Performance et fiabilité", "Performance and reliability"],
        precision: if cfg!(windows) { ["démarrage rapide, widgets…", "fast startup, widgets…"] }
            else { ["SSD, taille du journal", "SSD, journal size"] },
        mots: "ssd démarrage startup journal" },
    Outil { action: Action::OptimiserConfort, groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Confort et fichiers", "Comfort and files"],
        precision: if cfg!(windows) { ["extensions, clés USB, clic droit", "extensions, USB drives, menus"] }
            else if cfg!(target_os = "macos") { ["extensions, .DS_Store, Finder", "extensions, .DS_Store, Finder"] }
            else { ["annonces d'Ubuntu", "Ubuntu announcements"] },
        mots: "extensions fichiers cachés hidden files" },
    Outil { action: Action::DnsRapide, groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["DNS le plus rapide", "Fastest DNS"], precision: ["mesuré ici, annulable", "measured here, undoable"],
        mots: "dns rapide fast résolveur resolver cloudflare quad9 google adguard vitesse speed" },
    Outil { action: Action::OptimiserAnnuler, groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Tout remettre comme avant", "Put everything back"],
        precision: ["annule ce que Vanguard a changé", "undo what Vanguard changed"],
        mots: "annuler undo restaurer" },
    Outil { action: Action::Sauvegarder, groupe: Some(Groupe::Donnees), lettre: "d",
        titre: ["Sauvegarder ou restaurer", "Back up or restore"],
        precision: ["base des appareils, réglages", "device database, settings"],
        mots: "backup restore sauvegarde base" },
    Outil { action: Action::CopierFichiers, groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Copier mes fichiers", "Copy my files"],
        precision: ["vers un disque externe, vérifié", "to an external disk, checked"],
        mots: "copier copy sauvegarde backup photos disque externe external drive fichiers" },
    Outil { action: Action::SauvegardeAuto, groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Sauvegarde automatique", "Automatic backup"],
        precision: ["chaque jour, sur un autre disque", "every day, to an external disk"],
        mots: "sauvegarde backup automatique automatic time machine historique des fichiers file history deja dup \
               rsync disque externe external drive" },
    Outil { action: Action::VerifierCopie, groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Vérifier une copie", "Check a copy"],
        precision: ["relue, comparée aux originaux", "read back, compared"],
        mots: "restauration restore test vérifier verify copie copy sauvegarde backup relire" },
    Outil { action: Action::VerifierCle, groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Vérifier ma clé", "Check my drive"],
        precision: ["vraie capacité, vitesse, erreurs", "real capacity, speed, errors"],
        mots: "clé key usb fausse fake capacité capacity vitesse speed débit secteurs sectors erreurs errors f3 h2testw \
               disque externe external drive" },
    Outil { action: Action::Raccourci, groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Raccourci sur cet ordinateur", "Shortcut on this computer"],
        precision: ["lancer Vanguard d'un clic", "start Vanguard with one click"],
        mots: "raccourci shortcut bureau desktop installer install menu lancer launch icône icon" },
    Outil { action: Action::Ordinateurs, groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Mes ordinateurs", "My computers"],
        precision: ["suivis par la clé VANGUARD", "tracked by the VANGUARD key"],
        mots: "ordinateurs computers tableau dashboard suivi parc famille family clé key" },
    Outil { action: Action::ProtegerDonnees, groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Protéger les données de la clé", "Protect the key's data"],
        precision: ["carnet chiffré par une phrase", "record encrypted by a passphrase"],
        mots: "chiffrer encrypt chiffrement encryption phrase passphrase mot de passe password protéger protect \
               perdue lost" },
    Outil { action: Action::Guide, groupe: Some(Groupe::Guide), lettre: "",
        titre: ["Guide des commandes", "Command guide"],
        precision: ["Linux, Windows, macOS, tous", "Linux, Windows, macOS, all"],
        mots: "commandes commands terminal aide help" },
    Outil { action: Action::Depanner, groupe: Some(Groupe::Depanner), lettre: "",
        titre: ["Dépanner pas à pas", "Troubleshoot step by step"],
        precision: ["Internet, son, imprimante…", "Internet, sound, printer…"],
        mots: "dépanner troubleshoot panne problème internet son imprimante" },
];

// Une action ajoutée sans sa ligne décalerait toutes les suivantes : la compilation s'arrête.
const _: () = assert!(OUTILS.len() == Action::Depanner as usize + 1);

impl Action {
    fn outil(self) -> &'static Outil {
        &OUTILS[self as usize]
    }

    /// Texte de la ligne de menu et sa précision en gris.
    fn libelle(self) -> (&'static str, &'static str) {
        let precision = match self {
            Action::Entretien if entretien::active() => tr!("activé : une notification", "on: one notification"),
            Action::Entretien => tr!("désactivé", "off"),
            Action::Surveillance if reseau::surveillance::active() => tr!("activée", "on"),
            Action::Surveillance => tr!("désactivée", "off"),
            _ => texte(self.outil().precision),
        };
        (texte(self.outil().titre), precision)
    }

    /// L'outil a-t-il quelque chose à proposer sur ce système ? (une catégorie de réglages vide n'est pas montrée)
    fn disponible(self) -> bool {
        match self {
            Action::OptimiserConfidentialite => reglages_disponibles(optimiser::Categorie::Confidentialite),
            #[cfg(not(target_os = "macos"))]
            Action::OptimiserPerformance => reglages_disponibles(optimiser::Categorie::Performance),
            Action::OptimiserConfort => reglages_disponibles(optimiser::Categorie::Confort),
            // Lire l'état de Defender lance PowerShell : vérifié seulement à l'ouverture (`optimiser::protection`).
            Action::Protection => cfg!(windows),
            _ => true,
        }
    }

    /// Après l'outil, attendre Entrée avant de revenir au menu ? Pas pour ceux qui ont leurs propres écrans et se
    /// quittent par Échap (le guide, le dépannage) : on y reviendrait deux fois.
    fn attendre_apres(self) -> bool {
        !matches!(self, Action::Guide | Action::Depanner)
    }
}

/// Un texte de la table dans la langue de l'interface.
fn texte([fr, en]: [&'static str; 2]) -> &'static str {
    if langue::anglais() { en } else { fr }
}

/// Un groupe d'outils du menu principal, ouvert en sous-menu.
#[derive(Clone, Copy, PartialEq, Eq)]
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
            Groupe::Guide => tr!("Linux, Windows, macOS, pas à pas", "Linux, Windows, macOS, how-tos"),
            Groupe::Depanner => tr!("Internet, son, imprimante…", "Internet, sound, printer…"),
        }
    }

    /// Ses outils, dans l'ordre du sous-menu.
    fn actions(self) -> Vec<Action> {
        OUTILS
            .iter()
            .filter(|o| o.groupe == Some(self))
            .map(|o| o.action)
            .collect()
    }
}

/// Sous-menu d'un groupe : ses outils numérotés, Entrée pour revenir au menu principal. Un groupe d'un seul outil
/// (Données) l'ouvre directement. Un outil sans rien à proposer sur ce système n'est pas montré.
async fn sous_menu(s: &mut Session, groupe: Groupe) {
    let actions: Vec<Action> = groupe.actions().into_iter().filter(|a| a.disponible()).collect();
    if let [seule] = actions[..] {
        executer(s, seule).await;
        revenir_au_menu(seule);
        return;
    }
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let mut lignes: Vec<Ligne> = lignes_cadre(
            &format!("{ACCENT}VANGUARD{RESET} {GRIS}›{RESET} {}", groupe.titre()),
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
        let Some(choix) = choix_du_menu(&lignes, &dernier, tr!("revenir", "back")) else {
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
        Action::Integrite => protection::integrite::verifier(false),
        Action::Appris => apprentissage::menu(),
        Action::Changements => changements::afficher(),
        Action::Lenteur => lenteur::menu(),
        Action::Fiche => fiche::fiche(false),
        Action::ALaisser => {
            let audit = s.audit.get_or_insert_with(|| machine::executer(false));
            a_laisser::laisser(audit);
        }
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
        Action::Surveillance => reseau::surveillance::activer(!reseau::surveillance::active()),
        Action::Connexion => reseau::connexion::tester().await,
        Action::ListesNoires => reseau::listes_noires::verifier(),
        Action::WifiCanaux => reseau::canaux::analyser(),
        Action::Nat => reseau::nat::tester(),
        Action::Cameras => reseau::cameras::chercher_cameras().await,
        Action::AntivirusRapide => protection::antivirus::analyser(protection::antivirus::Portee::Rapide),
        Action::AntivirusComplet => protection::antivirus::analyser(protection::antivirus::Portee::Complete),
        Action::AntivirusDossier => protection::antivirus::choisir(),
        Action::Yara => protection::yara::menu(),
        Action::Pieges => protection::pieges::menu(),
        Action::Bac => {
            let chemin = demander(tr!("  Programme à isoler (chemin) : ", "  Program to isolate (path): "));
            let chemin = chemin.trim().trim_matches(['"', '\'']);
            if !chemin.is_empty() {
                protection::isoler::isoler(std::path::Path::new(chemin));
            }
        }
        Action::MotsDePasse => protection::fuites::verifier(),
        Action::Courriel => protection::fuites::verifier_courriel(),
        Action::QuiParle => protection::sortantes::afficher(),
        Action::CameraMicro => protection::camera::afficher_tout(),
        Action::Distance => protection::distance::menu(),
        Action::Lien => protection::lien::verifier(None),
        Action::VerifierFichier => protection::telechargement::verifier(None, None),
        Action::Quarantaine => protection::quarantaine::menu(),
        Action::Logiciels => logiciels::menu(),
        Action::Gaming => gaming::menu(),
        Action::Nettoyer => nettoyer::menu(),
        Action::OptimiserRecommandes => optimiser::recommandes(),
        Action::OptimiserConfidentialite => optimiser::menu(optimiser::Categorie::Confidentialite),
        #[cfg(not(target_os = "macos"))]
        Action::OptimiserPerformance => optimiser::menu(optimiser::Categorie::Performance),
        Action::OptimiserConfort => optimiser::menu(optimiser::Categorie::Confort),
        Action::Protection => optimiser::protection(),
        Action::DnsRapide => dns_rapide::mesurer_et_proposer(),
        Action::OptimiserAnnuler => optimiser::tout_annuler(),
        Action::Sauvegarder => donnees::menu(),
        Action::CopierFichiers => copier::menu(),
        Action::SauvegardeAuto => sauvegarde::menu(),
        Action::VerifierCopie => copier::verifier_copie(None),
        Action::VerifierCle => verifier_cle::menu(),
        Action::Raccourci => raccourci::commande(None),
        Action::Ordinateurs => ordinateurs::menu(),
        Action::ProtegerDonnees => chiffrement::menu(),
        Action::Guide => guide::menu(),
        Action::Depanner => depanner::menu(),
    }
}

/// Aide anglaise des commandes : la française est dans les commentaires de `Commande`.
#[rustfmt::skip] // une ligne par aide, que rustfmt étalerait sur quatre
const AIDES_EN: &[(&str, &str)] = &[
    ("complet", "Full check: this machine, then the network"),
    ("machine", "Audit this machine (firewall, ports, SSH, updates, encryption…)"),
    ("corriger", "Audit the machine, then apply the fixes step by step"),
    ("reseau", "Network scan: devices, open ports, risks, changes since previous scans"),
    ("antivirus", "Malware scan: ClamAV (Linux, macOS) or Microsoft Defender (Windows)"),
    ("surveillance", "Turn hourly network monitoring on or off (notification for unknown devices)"),
    ("entretien", "Monthly check-up: once a month, silently, the grade, waiting updates, space to free and new \
                   problems, in one notification; nothing is changed. Without argument: what it would say now"),
    ("maj", "Updates: system, programs, drivers and firmware checked at once, then installed with your consent"),
    ("reparer", "Common repairs: network, hijacked browsing, firewall, antivirus, system files, disk, space, updates, \
                 time"),
    ("logiciels", "Software: the best programs, mostly open source (browsers, passwords, office, video, design, system \
                   tools…), by category: choose, then install from the system's official source"),
    ("diagnostic", "Computer diagnostic: hardware, system and recent problems (crashes, errors). Read only"),
    ("nettoyer", "Clean up the system: caches, temporary files, downloaded packages, old logs, trash… The space each \
                  item frees is shown first; check, then accept"),
    ("connexion", "Connection test for gaming: ping, jitter, packet loss, speed and bufferbloat"),
    ("appris", "What Vanguard has learned on this computer: the alerts declared normal, and forgetting them"),
    ("listes-noires", "Is your home's Internet address on a blocklist (Spamhaus, SpamCop, DroneBL, PSBL)? If so, a \
                       device is probably infected. After your consent: the lists see the address"),
    ("yara", "YARA scan: 308 rules for malware families (ReversingLabs), alongside the antivirus. Without a folder: \
              downloads, desktop, startup. Read-only"),
    ("canaux", "Crowded Wi-Fi: nearby networks by channel, and the freest channel to set on the router. Read-only"),
    ("nat", "NAT type for gaming (open, moderate or strict), from two public servers (STUN). Read-only"),
    ("cameras", "Hidden cameras: on a rental's or someone's network, the devices that look like cameras. Read-only"),
    ("dns-rapide", "Fastest DNS: measures the current DNS and public ones, then offers the fastest, undoable. A DNS \
                    that protects (NextDNS, encrypted, filtering) is kept"),
    ("pieges", "Decoy files against ransomware: place them (after your consent), see whether they are intact, or \
                remove them"),
    ("durcir", "Windows Defender blocking: ASR rules, network protection, unwanted software, controlled folder access. \
                Each one is turned on after your consent and undoes exactly (Windows only)"),
    ("isoler", "Run an unknown program in a sandbox: no network, home folder hidden"),
    ("courriel", "Email address leaks: the address is sent to the search service, after your consent"),
    ("integrite", "Critical file integrity: BLAKE3 fingerprint reference, then what changed since"),
    ("motdepasse", "Check whether passwords have leaked (Have I Been Pwned); only 5 characters of their fingerprint \
                    are sent"),
    ("sortantes", "Who talks to the Internet? Each program's current connections, with the server's name. Read-only"),
    ("verifier-moi", "Check Vanguard itself: version, build date, SHA-256 fingerprint of the program (to compare with the release page) and, on the owner's key, the key manifest"),
    ("distance", "Is someone controlling my computer? Remote control software (AnyDesk, TeamViewer, RustDesk…) installed, started at boot, running or downloaded: the fake technicians' tool. Removed after your consent; a running program asks for a second consent"),
    ("lien", "Is this link dangerous? Checked without ever opening it; after your consent, its age and public lists"),
    ("verifier-fichier", "Check a downloaded file: checksum compared with the site's, name and content, YARA and \
                          antivirus"),
    ("camera-micro", "Camera and microphone: who uses them? On Windows, each program and the last time; on Linux, \
                      what holds them right now. Read-only"),
    ("quarantaine", "Quarantine: the files isolated by the antivirus or YARA, to put back in their place (false \
                     positive) or to delete for good"),
    ("sauvegarder", "Back up the device database and the monitoring state to a JSON file"),
    ("restaurer", "Add a backup (or an appareils.json) to the current database, without erasing anything"),
    ("nommer", "Give a nickname to a device of the database (“HP printer”), by its IP or MAC"),
    ("gaming", "Gaming: components for games (Windows: Visual C++, DirectX…; Linux: Steam, Vulkan, GameMode, Wine…; \
                macOS: Rosetta, Steam, Epic…) and system settings"),
    ("guide", "Command guide: the useful commands of Omarchy, Arch, Fedora, Debian, other Linux, Windows, macOS and \
               all systems, sorted by program, with step-by-step guides; plus the tldr-pages examples, downloaded \
               every week"),
    ("lenteur", "Why is it slow? What keeps the processor, memory and disk busy, startup, the programs started at \
                 login. Read only"),
    ("demarrage", "Startup programs: those that start at login, to remove or put back after your consent. Each removal \
                   is undone exactly (Optimize › Put everything back)"),
    ("fiche", "Computer specs: model, motherboard, processor, memory, graphics card, disks, system. Serial numbers are \
               shown on screen only"),
    ("copier-fichiers", "Copy my files (Documents, Pictures, Desktop, Videos, Music) to an external disk: checked \
                         copy, nothing deleted or overwritten, an interrupted copy resumes"),
    ("verifier-copie", "Check a copy made by “Copy my files” (restore test): files spread over the whole copy, read \
                        back from the disk and compared with their original. Nothing is written or deleted"),
    ("verifier-cle", "Check my drive: real capacity (fake drives), speeds and bad blocks of a USB stick or an \
                      external disk. Writes into the free space after your consent, reads back, then erases; your \
                      files are not touched"),
    ("changements", "What Vanguard changed: each fix run on this computer, its date and its result"),
    ("a-laisser", "Report to leave behind: a simple page for the person you just helped (grade, what is left to do, \
                   what is fine), put on their Desktop after consent and opened in the browser"),
    ("sauvegarde-auto", "Automatic backup: set up with the system's tool (Déjà Dup or rsync every day, Time Machine, \
                         File History) to an external disk, after your consent, exactly undoable"),
    ("raccourci", "Shortcut on this computer: Vanguard copied here and started with one click (applications menu on \
                   Linux, Desktop on Windows and macOS). Without argument: the state, then the offer"),
    ("regles", "The check rules declared for this system: stable identifier, subject, hardening references"),
    ("ordinateurs", "My computers: those where the VANGUARD key ran a check, their grade and remaining problems (on the \
     key's VANGUARDLOG partition)"),
    ("depanner", "Troubleshoot step by step: no Internet, Wi-Fi dropping, slow computer, no sound, printer, disk full; \
                  after an infection, new computer, computer leaving (sale, gift)"),
];

/// Aide anglaise des options : (commande, option, aide).
#[rustfmt::skip]
const OPTIONS_EN: &[(&str, &str, &str)] = &[
    ("nettoyer", "liste", "Show what could be cleaned up and the space to gain, deleting nothing"),
    ("logiciels", "liste", "Show each program offered and its state, without installing anything"),
    ("logiciels", "recommandes", "Install the starter pack (browser, passwords, video, office, archives), after your \
                                  consent"),
    ("complet", "html", "Also open the HTML report in the browser"),
    ("complet", "texte", "Show the report as plain text (Markdown) in the terminal: no browser or graphical display \
                          needed"),
    ("reseau", "cible", "IP, CIDR network (10.0.0.0/24) or range (10.0.0.1-50). Default: your local network"),
    ("reseau", "ports", "“courants”/“common” (default), “tous”/“all” (1-65535) or a list “22,80,8000-8100”"),
    ("reseau", "timeout", "Connection timeout per port, in milliseconds"),
    ("reseau", "parallele", "Number of simultaneous connections"),
    ("antivirus", "complet", "The whole home folder instead of the risky places"),
    ("antivirus", "dossier", "A USB drive, external disk or folder to scan entirely"),
    ("isoler", "fichier", "Program or script to run"),
    ("pieges", "retirer", "Remove the decoy files placed"),
    ("yara", "complet", "The whole home folder instead of the risky places"),
    ("yara", "dossier", "A USB drive, external disk or folder to scan entirely"),
    ("integrite", "accepter", "Take the current state as the new reference (after a system update)"),
    ("integrite", "temps_reel", "Watch the critical files live until Ctrl-C"),
    ("sauvegarder", "fichier", "File to write (default: vanguard-sauvegarde-YYYY-MM-DD.json in the home or Documents \
                                folder)"),
    ("nommer", "appareil", "IP (on the current network) or MAC address of the device"),
    ("nommer", "surnom", "The nickname; empty to remove it"),
    ("lien", "adresse", "The link you received (in quotes if it contains “&” or “?”)"),
    ("verifier-fichier", "fichier", "The downloaded file"),
    ("verifier-fichier", "empreinte", "The checksum published by the site (preferably SHA-256). Otherwise: a \
                                       SHA256SUMS or .sha256 next to it"),
    ("guide", "quoi", "A system (omarchy, arch, fedora, debian, windows, macos, all; linux: the common programs; tldr), \
                       a program (systemctl, winget, tar…) or words to look for"),
    ("fiche", "json", "The specs as JSON, for a script (without the serial numbers)"),
    ("copier-fichiers", "destination", "A folder on an external disk (default: chosen among the plugged-in disks)"),
    ("verifier-copie", "dossier", "The disk or the folder of the copy (default: chosen among the plugged-in disks)"),
    ("verifier-cle", "dossier", "A folder of the drive or disk (default: chosen among the plugged-in disks)"),
    ("sauvegarde-auto", "annuler", "Remove the automatic backup set up by Vanguard (the backed-up files stay)"),
    ("depanner", "sujet", "The subject: internet, wifi, slow, sound, printer, disk, infection, new, leaving (or words \
                             describing it)"),
];

/// La ligne de commande, avec son aide en anglais si l'interface est en anglais (l'aide écrite plus haut, en
/// commentaires, est la version française).
fn ligne_de_commande() -> clap::Command {
    let c = Args::command();
    if !langue::anglais() {
        return c;
    }
    let mut c = c
        .about("Secures and optimizes your machine and your local network: check, fixes, settings. No argument: menu.");
    for &(nom, aide) in AIDES_EN {
        c = c.mut_subcommand(nom, |s| s.about(aide));
    }
    for &(commande, option, aide) in OPTIONS_EN {
        c = c.mut_subcommand(commande, |s| s.mut_arg(option, |a| a.help(aide)));
    }
    c
}

/// La portée d'une analyse demandée en ligne de commande : le dossier donné, sinon tout le dossier personnel
/// (--complet), sinon les endroits à risque.
fn portee(dossier: Option<std::path::PathBuf>, complet: bool) -> protection::antivirus::Portee {
    match (dossier, complet) {
        (Some(d), _) => protection::antivirus::Portee::Dossier(d),
        (None, true) => protection::antivirus::Portee::Complete,
        (None, false) => protection::antivirus::Portee::Rapide,
    }
}

#[tokio::main]
async fn main() {
    // Couleurs ANSI dans l'ancienne console Windows (Windows Terminal les gère déjà).
    #[cfg(windows)]
    let _ = enable_ansi_support::enable_ansi_support();
    journal::installer();
    #[cfg(unix)]
    protection::cle::proteger_cle();
    protection::environnement::afficher();
    avertir_si_root();
    passage::au_lancement();
    // Après le passage, qui a pu déplacer l'ancien dossier avec ses droits d'avant.
    #[cfg(unix)]
    reseau::proteger_dossier_local();
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
        Some(Commande::Antivirus { complet, dossier }) => protection::antivirus::analyser(portee(dossier, complet)),
        Some(Commande::Surveillance { etat }) => reseau::surveillance::activer(etat == "on"),
        Some(Commande::Surveiller) => reseau::surveillance::surveiller().await,
        Some(Commande::Entretien { etat }) => match etat {
            Some(e) => entretien::activer(e == "on"),
            None => entretien::maintenant(),
        },
        Some(Commande::Entretenir) => entretien::entretenir(),
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
        Some(Commande::Connexion) => reseau::connexion::tester().await,
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
        Some(Commande::MotDePasse) => protection::fuites::verifier(),
        Some(Commande::Courriel) => protection::fuites::verifier_courriel(),
        Some(Commande::Sortantes) => protection::sortantes::afficher(),
        Some(Commande::Distance) => protection::distance::menu(),
        Some(Commande::VerifierMoi) => protection::manifeste::verifier_moi(),
        Some(Commande::Manifeste { ecrire }) => protection::manifeste::commande(ecrire.as_deref()),
        Some(Commande::Lien { adresse }) => protection::lien::verifier(Some(&adresse)),
        Some(Commande::VerifierFichier { fichier, empreinte }) => {
            protection::telechargement::verifier(Some(&fichier), empreinte.as_deref());
        }
        Some(Commande::CameraMicro) => protection::camera::afficher_tout(),
        Some(Commande::Quarantaine) => protection::quarantaine::menu(),
        Some(Commande::Isoler { fichier }) => protection::isoler::isoler(&fichier),
        Some(Commande::Pieges { retirer }) => protection::pieges::commande(retirer),
        Some(Commande::Durcir) => optimiser::protection(),
        Some(Commande::Yara { complet, dossier }) => protection::yara::analyser(&portee(dossier, complet)),
        Some(Commande::ListesNoires) => reseau::listes_noires::verifier(),
        Some(Commande::Canaux) => reseau::canaux::analyser(),
        Some(Commande::Nat) => reseau::nat::tester(),
        Some(Commande::Cameras) => reseau::cameras::chercher_cameras().await,
        Some(Commande::DnsRapide) => dns_rapide::mesurer_et_proposer(),
        Some(Commande::Appris) => apprentissage::menu(),
        Some(Commande::Integrite { accepter, temps_reel }) => {
            if temps_reel {
                protection::integrite::temps_reel();
            } else {
                protection::integrite::verifier(accepter);
            }
        }
        Some(Commande::Sauvegarder { fichier }) => donnees::sauvegarder(fichier),
        Some(Commande::Restaurer { fichier }) => donnees::restaurer(&fichier),
        Some(Commande::Nommer { appareil, surnom }) => nommer(&appareil, &surnom.join(" ")),
        Some(Commande::Guide { quoi }) => guide::executer(&quoi.join(" ")),
        Some(Commande::Lenteur) => lenteur::commande(),
        Some(Commande::Demarrage) => optimiser::programmes_au_demarrage(),
        Some(Commande::Fiche { json }) => fiche::fiche(json),
        Some(Commande::CopierFichiers { destination }) => copier::commande(destination.as_deref()),
        Some(Commande::VerifierCopie { dossier }) => copier::verifier_copie(dossier.as_deref()),
        Some(Commande::VerifierCle { dossier }) => verifier_cle::commande(dossier.as_deref()),
        Some(Commande::Changements) => changements::afficher(),
        Some(Commande::ALaisser) => a_laisser::laisser(&machine::executer(false)),
        Some(Commande::SauvegardeAuto { annuler }) => {
            if annuler {
                sauvegarde::annuler();
            } else {
                sauvegarde::menu();
            }
        }
        Some(Commande::Raccourci { etat }) => raccourci::commande(etat.map(|e| e == "on")),
        Some(Commande::Ordinateurs) => ordinateurs::menu(),
        Some(Commande::Regles) => machine::regles::afficher(),
        Some(Commande::Depanner { sujet }) => depanner::executer(&sujet.join(" ")),
    }
}

#[cfg(test)]
mod tests_menu {
    use super::*;

    #[test]
    fn chaque_commande_a_son_aide_en_anglais() {
        // Une commande oubliée gardait son aide française dans l'interface anglaise (« distance »).
        let traduites: Vec<&str> = AIDES_EN.iter().map(|(nom, _)| *nom).collect();
        let manquantes: Vec<String> = Args::command()
            .get_subcommands()
            // Les commandes cachées (surveillance, planificateur) n'apparaissent pas dans l'aide.
            .filter(|s| !s.is_hide_set())
            .map(|s| s.get_name().to_string())
            .filter(|nom| nom != "help" && !traduites.contains(&nom.as_str()))
            .collect();
        assert_eq!(manquantes, Vec::<String>::new());
    }

    #[test]
    fn chaque_option_a_son_aide_en_anglais() {
        let traduites: Vec<(&str, &str)> = OPTIONS_EN.iter().map(|(c, o, _)| (*c, *o)).collect();
        let mut manquantes = Vec::new();
        for s in Args::command().get_subcommands().filter(|s| !s.is_hide_set()) {
            for a in s.get_arguments().filter(|a| !a.is_hide_set() && a.get_help().is_some()) {
                let (c, o) = (s.get_name(), a.get_id().as_str());
                if !traduites.contains(&(c, o)) {
                    manquantes.push(format!("{c} {o}"));
                }
            }
        }
        assert_eq!(manquantes, Vec::<String>::new());
    }

    #[test]
    fn chaque_outil_a_sa_place() {
        // 1, 2, 3 au menu principal ; tout le reste dans un seul groupe.
        let principal = [Action::Complet, Action::Corriger, Action::Rapport];
        for (i, o) in OUTILS.iter().enumerate() {
            // La ligne d'un outil est à son numéro : `Action::outil` la trouve sans chercher.
            assert_eq!(o.action as usize, i);
            let groupes = GROUPES.iter().filter(|g| g.actions().contains(&o.action)).count();
            assert_eq!(groupes + usize::from(principal.contains(&o.action)), 1);
        }
        // Raccourcis uniques, et jamais un chiffre (les chiffres ouvrent les groupes).
        let mut lettres: Vec<&str> = OUTILS.iter().map(|o| o.lettre).filter(|l| !l.is_empty()).collect();
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
            for (j, a) in g.actions().into_iter().filter(|a| a.disponible()).enumerate() {
                assert!(outil_au_chemin(&format!("{}.{}", i + 4, j + 1)) == Some(a));
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
