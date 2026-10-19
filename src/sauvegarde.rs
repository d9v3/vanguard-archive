//! Sauvegarde automatique guidée : la meilleure défense contre un disque qui lâche, un vol ou un rançongiciel, mise en
//! place avec l'outil du système, vers un disque externe, après accord, et annulable exactement. Linux : Déjà Dup s'il
//! est là (ses réglages gsettings, valeurs d'avant notées), sinon une minuterie systemd de l'utilisateur qui lance rsync
//! chaque jour vers le disque (et se tait quand il n'est pas branché) ; macOS : Time Machine (`tmutil`) ; Windows :
//! l'Historique des fichiers, que Gardien vérifie au bilan et guide pas à pas (il se règle dans le Panneau de
//! configuration, rien ne se fait à sa place). Ce que Gardien a posé est noté (sauvegarde.json) pour ne retirer que ça.
//! Jamais vers la clé GARDIEN ni le disque du système : la liste des disques de Copier mes fichiers les exclut.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::machine::Constat;
#[cfg(not(windows))]
use crate::nettoyer::taille_lisible;
use crate::selection::{Ligne, choisir};
use crate::ui::*;

/// Le dossier posé sur le disque externe, un sous-dossier par ordinateur.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const DOSSIER: &str = "Sauvegarde-Gardien";
/// Les unités systemd posées par Gardien (le nom contient « sauvegarde » : le bilan les reconnaît comme une vraie
/// sauvegarde).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const TIMER: &str = "gardien-sauvegarde.timer";
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const SERVICE: &str = "gardien-sauvegarde.service";
/// L'heure du passage quotidien ; l'ordinateur éteint à cette heure-là, le passage se fait au prochain démarrage.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const HEURE: &str = "12:00:00";

/// Ce que Gardien a mis en place, pour l'annuler exactement.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum MiseEnPlace {
    /// Linux : minuterie et service de systemd --user, avec l'empreinte de chaque fichier posé (un fichier modifié
    /// depuis n'est pas retiré).
    Systemd {
        date: String,
        destination: String,
        empreinte_timer: String,
        empreinte_service: String,
    },
    /// Linux : réglages de Déjà Dup, avec la valeur d'avant de chaque clé.
    DejaDup {
        date: String,
        destination: String,
        avant: Vec<(String, String)>,
    },
    /// macOS : destination ajoutée à Time Machine (son identifiant), et si Time Machine était déjà actif.
    TimeMachine {
        date: String,
        destination: String,
        identifiant: Option<String>,
        deja_actif: bool,
    },
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
struct Notes {
    #[serde(default)]
    mise_en_place: Option<MiseEnPlace>,
}

fn fichier_notes() -> PathBuf {
    crate::reseau::dossier_local().join("sauvegarde.json")
}

fn charger_de(chemin: &Path) -> Notes {
    std::fs::read_to_string(chemin)
        .ok()
        .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok())
        .unwrap_or_default()
}

fn ecrire_dans(chemin: &Path, notes: &Notes) -> std::io::Result<()> {
    if let Some(parent) = chemin.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(chemin, serde_json::to_string_pretty(notes).unwrap_or_default())
}

#[cfg_attr(windows, allow(dead_code))]
fn aujourd_hui() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn empreinte(texte: &str) -> String {
    blake3::hash(texte.as_bytes()).to_hex().to_string()
}

/// Le nom de cet ordinateur, pour son dossier sur le disque ; « ordinateur » à défaut.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nom_machine() -> String {
    let brut = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_default();
    let propre: String = brut
        .trim()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .take(40)
        .collect();
    if propre.is_empty() { "ordinateur".into() } else { propre }
}

// ───────────────────────────── Linux : systemd + rsync ─────────────────────────────

/// Un argument cité pour ExecStart= de systemd : entre guillemets, « \ » et « " » protégés, « % » doublé (systemd y
/// lit ses propres codes).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn citer_systemd(t: &str) -> String {
    format!(
        "\"{}\"",
        t.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%")
    )
}

/// Un chemin prêt pour une ligne d'unité systemd, `None` s'il contient un caractère de contrôle. Le chemin vient en
/// partie du nom du disque, que choisit qui l'a formaté : un saut de ligne y ajouterait à l'unité une ligne de son
/// choix (ExecStartPre=…), lancée chaque jour sous ce compte.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn chemin_systemd(p: &Path) -> Option<String> {
    let t = p.display().to_string();
    (!t.chars().any(char::is_control)).then(|| t.replace('%', "%%"))
}

/// Les deux fichiers d'unité : (timer, service). `racine` : le disque, dont le montage conditionne le passage ;
/// `destination` : le dossier de cet ordinateur dessus ; `sources` : les dossiers personnels copiés tels quels.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn unites(rsync: &Path, racine: &Path, destination: &Path, sources: &[PathBuf]) -> Option<(String, String)> {
    let tous = [rsync, racine, destination]
        .into_iter()
        .chain(sources.iter().map(PathBuf::as_path));
    for p in tous {
        chemin_systemd(p)?;
    }
    let timer = format!(
        "[Unit]\nDescription=Sauvegarde Gardien, chaque jour\n\n[Timer]\nOnCalendar=*-*-* {HEURE}\nPersistent=true\nRandomizedDelaySec=10min\n\n[Install]\nWantedBy=timers.target\n"
    );
    let mut commande = vec![
        citer_systemd(&rsync.display().to_string()),
        "-a".into(),
        "--no-specials".into(),
        "--no-devices".into(),
        "--exclude=.cache".into(),
        "--exclude=node_modules".into(),
        "--exclude=.gardien-copie-en-cours".into(),
    ];
    commande.extend(sources.iter().map(|s| citer_systemd(&s.display().to_string())));
    commande.push(citer_systemd(&format!("{}/", destination.display())));
    let service = format!(
        "[Unit]\nDescription=Sauvegarde Gardien vers {}\n# Disque débranché : rien ne se passe, sans erreur.\nConditionPathIsMountPoint={}\n\n[Service]\nType=oneshot\nNice=10\nIOSchedulingClass=idle\nExecStart={}\n",
        chemin_systemd(destination)?,
        chemin_systemd(racine)?,
        commande.join(" ")
    );
    Some((timer, service))
}

#[cfg(target_os = "linux")]
fn dossier_unites() -> PathBuf {
    let maison = crate::nettoyer::maison();
    std::env::var_os("XDG_CONFIG_HOME")
        .map_or_else(|| maison.join(".config"), PathBuf::from)
        .join("systemd/user")
}

#[cfg(target_os = "linux")]
fn dans_le_path(commande: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|d| d.join(commande))
        .find(|f| f.is_file())
}

/// Les clés de Déjà Dup que Gardien règle : (schéma, clé, valeur voulue) ; la destination se construit à part.
#[cfg(target_os = "linux")]
fn cles_deja_dup(destination: &Path) -> Vec<(&'static str, &'static str, String)> {
    vec![
        ("org.gnome.DejaDup", "backend", "'local'".into()),
        (
            "org.gnome.DejaDup.Local",
            "folder",
            format!("'{}'", destination.display().to_string().replace('\'', "\\'")),
        ),
        ("org.gnome.DejaDup", "periodic", "true".into()),
        ("org.gnome.DejaDup", "periodic-period", "1".into()),
    ]
}

#[cfg(target_os = "linux")]
fn deja_dup_present() -> bool {
    dans_le_path("deja-dup").is_some()
        && crate::machine::sortie("gsettings", &["list-keys", "org.gnome.DejaDup"])
            .is_some_and(|t| t.contains("periodic"))
}

// ───────────────────────────── macOS : Time Machine ─────────────────────────────

/// Les identifiants des destinations de `tmutil destinationinfo` (« ID : 1234-… »).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn identifiants_time_machine(texte: &str) -> Vec<String> {
    texte
        .lines()
        .filter_map(|l| {
            let (cle, valeur) = l.split_once(':')?;
            (cle.trim() == "ID").then(|| valeur.trim().to_string())
        })
        .collect()
}

/// L'identifiant apparu après l'ajout : celui d'après qui n'était pas là avant.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn nouvel_identifiant(avant: &[String], apres: &[String]) -> Option<String> {
    apres.iter().find(|id| !avant.contains(id)).cloned()
}

// ───────────────────────────── Windows : Historique des fichiers ─────────────────────────────

/// Le nom du lecteur cible dans Config1.xml de l'Historique des fichiers (« <TargetName>… »).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn cible_historique(xml: &str) -> Option<String> {
    let debut = xml.find("<TargetName>")? + "<TargetName>".len();
    let fin = xml[debut..].find("</TargetName>")?;
    let nom = xml[debut..debut + fin].trim();
    (!nom.is_empty()).then(|| affichable(nom))
}

/// Âge en jours d'une date FILETIME (centaines de nanosecondes depuis 1601) par rapport à maintenant (secondes
/// Unix).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn age_filetime_jours(filetime: u64, maintenant_unix: u64) -> u64 {
    const ECART_1601_1970: u64 = 11_644_473_600;
    let secondes = (filetime / 10_000_000).saturating_sub(ECART_1601_1970);
    maintenant_unix.saturating_sub(secondes) / 86_400
}

/// Le constat « Sauvegardes » de Windows : l'Historique des fichiers configuré, et jusqu'à quand il a protégé.
#[cfg(windows)]
fn historique_des_fichiers() -> Constat {
    use crate::machine::{alerte, ok};
    use crate::risk::Niveau;
    let local = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default());
    let config = local.join("Microsoft\\Windows\\FileHistory\\Configuration\\Config1.xml");
    let cible = std::fs::read(&config)
        .ok()
        .map(|o| String::from_utf8_lossy(&o).into_owned())
        .and_then(|xml| cible_historique(&xml));
    let protege: Option<u64> = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\FileHistory")
        .ok()
        .and_then(|k| k.get_value::<u64, _>("ProtectedUpToTime").ok());
    let Some(cible) = cible else {
        return alerte(
            "Sauvegardes",
            Niveau::Moyen,
            tr!(
                "Aucune sauvegarde automatique : l'Historique des fichiers n'est pas configuré (la sauvegarde OneDrive de Windows n'est pas vérifiée ici).",
                "No automatic backup: File History is not set up (the Windows OneDrive backup is not checked here)."
            ),
        )
        .manuel(
            tr!(
                "Brancher un disque externe, puis Panneau de configuration > Historique des fichiers > Activer ; le pas à pas est dans le menu Données > Sauvegarde automatique",
                "Plug in an external disk, then Control Panel > File History > Turn on; the step by step is in the Data > Automatic backup menu"
            ),
            &["control.exe /name Microsoft.FileHistory"],
        );
    };
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    match protege.map(|p| age_filetime_jours(p, maintenant)) {
        Some(jours) if jours > 7 => alerte(
            "Sauvegardes",
            Niveau::Moyen,
            trf!(
                "Historique des fichiers vers « {cible} » : dernière sauvegarde il y a {jours} jours. Rebranche le disque.",
                "File History to “{cible}”: last backup {jours} days ago. Plug the disk back in."
            ),
        ),
        Some(jours) => ok(
            "Sauvegardes",
            trf!(
                "Historique des fichiers vers « {cible} », dernière sauvegarde il y a {jours} jour(s).",
                "File History to “{cible}”, last backup {jours} day(s) ago."
            ),
        ),
        None => ok(
            "Sauvegardes",
            trf!(
                "Historique des fichiers configuré vers « {cible} » (pas encore de passage noté).",
                "File History set up to “{cible}” (no run recorded yet)."
            ),
        ),
    }
}

/// Au bilan : Windows seulement (Linux et macOS ont déjà leur vérification des sauvegardes).
pub fn constats() -> Vec<Constat> {
    #[cfg(windows)]
    {
        vec![historique_des_fichiers()]
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

// ───────────────────────────── Le menu ─────────────────────────────

fn bon(texte: &str) {
    afficher_aligne(&format!("  {VERT}✔{RESET} "), texte, 4, "");
}

fn mauvais(texte: &str) {
    afficher_aligne(
        &format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)),
        texte,
        4,
        "",
    );
}

fn info(texte: &str) {
    afficher_aligne(
        &format!("  {}ℹ{RESET} ", couleur(crate::risk::Niveau::Info)),
        texte,
        4,
        "",
    );
}

/// Ce que Gardien a mis en place, en une phrase.
fn decrire(m: &MiseEnPlace) -> String {
    match m {
        MiseEnPlace::Systemd { date, destination, .. } => trf!(
            "Mise en place par Gardien le {date} : rsync chaque jour vers {destination} (minuterie {TIMER}).",
            "Set up by Gardien on {date}: rsync every day to {destination} (timer {TIMER})."
        ),
        MiseEnPlace::DejaDup { date, destination, .. } => trf!(
            "Mise en place par Gardien le {date} : Déjà Dup, chaque jour, vers {destination}.",
            "Set up by Gardien on {date}: Déjà Dup, every day, to {destination}."
        ),
        MiseEnPlace::TimeMachine { date, destination, .. } => trf!(
            "Mise en place par Gardien le {date} : Time Machine vers {destination}.",
            "Set up by Gardien on {date}: Time Machine to {destination}."
        ),
    }
}

/// Le disque externe où sauvegarder, parmi ceux qui sont branchés.
#[cfg(not(windows))]
fn choisir_disque() -> Option<crate::copier::Disque> {
    let liste = crate::copier::disques();
    if liste.is_empty() {
        mauvais(tr!(
            "Aucun disque externe branché (la clé GARDIEN et le disque du système ne comptent pas). Branche un disque assez grand pour tes fichiers, attends qu'il apparaisse, puis recommence.",
            "No external disk plugged in (the GARDIEN key and the system disk do not count). Plug in a disk large enough for your files, wait for it to appear, then start again."
        ));
        return None;
    }
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_section(tr!("VERS QUEL DISQUE", "TO WHICH DISK"))),
    ];
    for (i, d) in liste.iter().enumerate() {
        let place = trf!(
            "{} libres sur {}",
            "{} free out of {}",
            taille_lisible(d.libre),
            taille_lisible(d.total)
        );
        lignes.push(Ligne::choix(&(i + 1).to_string(), &d.nom, &place));
    }
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    lignes.push(Ligne::Texte(String::new()));
    let choix = choisir(
        &lignes,
        tr!(
            "  Numéro du disque (Entrée pour revenir) : ",
            "  Disk number (Enter to go back): "
        ),
        "1",
        tr!("revenir", "back"),
    )?;
    let i = choix.trim().parse::<usize>().ok()?.checked_sub(1)?;
    liste.into_iter().nth(i)
}

/// Linux : met en place la minuterie rsync ou Déjà Dup vers le disque choisi.
#[cfg(target_os = "linux")]
fn mettre_en_place() -> Option<MiseEnPlace> {
    let sources: Vec<PathBuf> = crate::copier::sources().into_iter().map(|(_, c)| c).collect();
    if sources.is_empty() {
        mauvais(tr!(
            "Aucun dossier personnel trouvé (Documents, Images…) : rien à sauvegarder.",
            "No personal folder found (Documents, Pictures…): nothing to back up."
        ));
        return None;
    }
    let disque = choisir_disque()?;
    let destination = disque.racine.join(DOSSIER).join(nom_machine());
    let deja_dup = deja_dup_present();
    let rsync = dans_le_path("rsync");
    let outil = match (deja_dup, &rsync) {
        (false, None) => {
            mauvais(tr!(
                "Ni Déjà Dup ni rsync sur cet ordinateur : installe rsync (paquet « rsync ») ou Déjà Dup, puis recommence.",
                "Neither Déjà Dup nor rsync on this computer: install rsync (“rsync” package) or Déjà Dup, then start again."
            ));
            return None;
        }
        (true, None) => 1,
        (false, Some(_)) => 2,
        (true, Some(_)) => {
            let lignes = vec![
                Ligne::Texte(String::new()),
                Ligne::Texte(ligne_section(tr!("AVEC QUEL OUTIL", "WITH WHICH TOOL"))),
                Ligne::choix(
                    "1",
                    tr!("Déjà Dup (outil du bureau)", "Déjà Dup (desktop tool)"),
                    tr!("chiffré, restauration graphique", "encrypted, graphical restore"),
                ),
                Ligne::choix(
                    "2",
                    tr!("rsync par systemd", "rsync via systemd"),
                    tr!("copie fidèle, lisible partout", "faithful copy, readable anywhere"),
                ),
                Ligne::choix("↵", tr!("Revenir", "Back"), ""),
                Ligne::Texte(String::new()),
            ];
            let choix = choisir(
                &lignes,
                tr!("  Choix (Entrée pour revenir) : ", "  Choice (Enter to go back): "),
                "1",
                tr!("revenir", "back"),
            )?;
            match choix.trim() {
                "1" => 1,
                "2" => 2,
                _ => return None,
            }
        }
    };
    section(tr!("CE QUE GARDIEN VA FAIRE", "WHAT GARDIEN WILL DO"));
    afficher_aligne(
        "  ",
        &trf!(
            "Créer le dossier {} sur « {} » ({} libres).",
            "Create the folder {} on “{}” ({} free).",
            chemin_affichable(&destination),
            disque.nom,
            taille_lisible(disque.libre)
        ),
        2,
        "",
    );
    if outil == 1 {
        let cles = cles_deja_dup(&destination);
        afficher_aligne(
            "  ",
            tr!(
                "Régler Déjà Dup : destination locale = ce dossier, sauvegarde automatique chaque jour. Le reste (dossiers inclus, mot de passe de chiffrement) se choisit dans Déjà Dup au premier passage ; les valeurs d'avant sont notées pour annuler.",
                "Set Déjà Dup: local destination = this folder, automatic backup every day. The rest (folders included, encryption password) is chosen in Déjà Dup on the first run; the previous values are noted to undo."
            ),
            2,
            "",
        );
        for (schema, cle, valeur) in &cles {
            println!("    {GRIS}$ gsettings set {schema} {cle} {valeur}{RESET}");
        }
        if !demander(tr!("\n  Appliquer ? [o/N] : ", "\n  Apply? [y/N]: ")).oui() {
            return None;
        }
        if let Err(e) = std::fs::create_dir_all(&destination) {
            mauvais(&trf!(
                "Dossier impossible à créer : {e}",
                "Could not create the folder: {e}"
            ));
            return None;
        }
        let mut avant = Vec::new();
        for (schema, cle, valeur) in &cles {
            let ancienne = crate::machine::sortie("gsettings", &["get", schema, cle]).unwrap_or_default();
            avant.push((format!("{schema} {cle}"), ancienne.trim().to_string()));
            if crate::machine::sortie("gsettings", &["set", schema, cle, valeur]).is_none() {
                mauvais(&trf!(
                    "gsettings set {schema} {cle} a échoué ; rien d'autre n'est changé.",
                    "gsettings set {schema} {cle} failed; nothing else is changed."
                ));
                return None;
            }
        }
        bon(tr!(
            "Déjà Dup réglé. Ouvre-le une première fois (il demande les dossiers à inclure et un mot de passe de chiffrement) : « deja-dup ».",
            "Déjà Dup set. Open it once (it asks which folders to include and an encryption password): “deja-dup”."
        ));
        return Some(MiseEnPlace::DejaDup {
            date: aujourd_hui(),
            destination: destination.display().to_string(),
            avant,
        });
    }
    let rsync = rsync?;
    let Some((timer, service)) = unites(&rsync, &disque.racine, &destination, &sources) else {
        mauvais(tr!(
            "Le nom de ce disque ou d'un dossier contient un caractère de contrôle : rien n'est posé. Renomme le disque, puis recommence.",
            "The name of this disk or of a folder contains a control character: nothing is set up. Rename the disk, then start again."
        ));
        return None;
    };
    let dossier = dossier_unites();
    afficher_aligne(
        "  ",
        &trf!(
            "Poser deux fichiers dans {} puis activer la minuterie : chaque jour à {}, rsync copie {} dans ce dossier (disque débranché : rien ne se passe ; ordinateur éteint : au prochain démarrage). Rien n'est effacé sur le disque : ce qui a disparu ici reste dans la sauvegarde.",
            "Put two files in {} then enable the timer: every day at {}, rsync copies {} into this folder (disk unplugged: nothing happens; computer off: at the next start). Nothing is deleted on the disk: what disappeared here stays in the backup.",
            chemin_affichable(&dossier),
            &HEURE[..5],
            sources
                .iter()
                .map(|s| chemin_affichable(s))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        2,
        "",
    );
    println!("\n  {GRIS}{SERVICE}{RESET}");
    for l in service.lines() {
        println!("    {GRIS}{l}{RESET}");
    }
    println!("  {GRIS}{TIMER}{RESET}");
    for l in timer.lines() {
        println!("    {GRIS}{l}{RESET}");
    }
    println!("    {GRIS}$ systemctl --user daemon-reload && systemctl --user enable --now {TIMER}{RESET}");
    if !demander(tr!("\n  Appliquer ? [o/N] : ", "\n  Apply? [y/N]: ")).oui() {
        return None;
    }
    let poser = || -> std::io::Result<()> {
        std::fs::create_dir_all(&destination)?;
        std::fs::create_dir_all(&dossier)?;
        std::fs::write(dossier.join(SERVICE), &service)?;
        std::fs::write(dossier.join(TIMER), &timer)
    };
    if let Err(e) = poser() {
        mauvais(&trf!(
            "Impossible de poser les fichiers : {e}",
            "Could not put the files: {e}"
        ));
        return None;
    }
    if crate::machine::appliquer(&[
        "systemctl --user daemon-reload".to_string(),
        format!("systemctl --user enable --now {TIMER}"),
    ]) {
        bon(&trf!(
            "Sauvegarde automatique active : chaque jour à {}, vers {}.",
            "Automatic backup on: every day at {}, to {}.",
            &HEURE[..5],
            chemin_affichable(&destination)
        ));
        if demander(tr!(
            "  Lancer la première sauvegarde maintenant, en arrière-plan ? [o/N] : ",
            "  Run the first backup now, in the background? [y/N]: "
        ))
        .oui()
        {
            if crate::machine::sortie("systemctl", &["--user", "start", "--no-block", SERVICE]).is_some() {
                info(&trf!(
                    "Première sauvegarde lancée. La suivre : journalctl --user -u {SERVICE} -f ; le bilan (catégorie Sauvegardes) dira la date du dernier passage.",
                    "First backup started. Follow it: journalctl --user -u {SERVICE} -f; the check (Backups category) will show the date of the last run."
                ));
            } else {
                mauvais(tr!("Le lancement a échoué.", "The start failed."));
            }
        }
    } else {
        mauvais(tr!(
            "La minuterie n'a pas pu être activée ; les fichiers sont posés, « Annuler » les retire.",
            "The timer could not be enabled; the files are in place, “Undo” removes them."
        ));
    }
    Some(MiseEnPlace::Systemd {
        date: aujourd_hui(),
        destination: destination.display().to_string(),
        empreinte_timer: empreinte(&timer),
        empreinte_service: empreinte(&service),
    })
}

/// macOS : ajoute le disque choisi aux destinations de Time Machine et l'active.
#[cfg(target_os = "macos")]
fn mettre_en_place() -> Option<MiseEnPlace> {
    let disque = choisir_disque()?;
    let avant = crate::machine::sortie("tmutil", &["destinationinfo"]).unwrap_or_default();
    let deja_actif = avant.contains("Name");
    let chemin = disque.racine.display().to_string();
    let commandes = vec![
        format!("sudo tmutil setdestination -a '{}'", chemin.replace('\'', "'\\''")),
        "sudo tmutil enable".to_string(),
    ];
    section(tr!("CE QUE GARDIEN VA FAIRE", "WHAT GARDIEN WILL DO"));
    afficher_aligne(
        "  ",
        &trf!(
            "Ajouter « {} » ({} libres) aux disques de Time Machine et l'activer : sauvegardes toutes les heures, tout le Mac, restauration dans le Finder ou à la réinstallation. Le mot de passe d'administrateur sera demandé.",
            "Add “{}” ({} free) to Time Machine's disks and turn it on: hourly backups, the whole Mac, restore from the Finder or at reinstall. The administrator password will be asked.",
            disque.nom,
            taille_lisible(disque.libre)
        ),
        2,
        "",
    );
    for c in &commandes {
        println!("    {GRIS}$ {c}{RESET}");
    }
    if !demander(tr!("\n  Appliquer ? [o/N] : ", "\n  Apply? [y/N]: ")).oui() {
        return None;
    }
    if !crate::machine::appliquer(&commandes) {
        mauvais(tr!(
            "tmutil a refusé ; rien n'est noté.",
            "tmutil refused; nothing is noted."
        ));
        return None;
    }
    let apres = crate::machine::sortie("tmutil", &["destinationinfo"]).unwrap_or_default();
    let identifiant = nouvel_identifiant(&identifiants_time_machine(&avant), &identifiants_time_machine(&apres));
    bon(&trf!(
        "Time Machine sauvegarde vers « {} ». Laisse le disque branché : la première sauvegarde prend du temps.",
        "Time Machine backs up to “{}”. Leave the disk plugged in: the first backup takes time.",
        disque.nom
    ));
    Some(MiseEnPlace::TimeMachine {
        date: aujourd_hui(),
        destination: chemin,
        identifiant,
        deja_actif,
    })
}

/// Windows : l'Historique des fichiers se règle dans le Panneau de configuration ; Gardien guide et l'ouvre.
#[cfg(windows)]
fn mettre_en_place() -> Option<MiseEnPlace> {
    section(tr!("PAS À PAS", "STEP BY STEP"));
    for (i, etape) in [
        tr!(
            "Branche un disque externe (ou une grosse clé) qui restera branché le plus souvent possible.",
            "Plug in an external disk (or a big USB stick) that will stay plugged in as often as possible."
        ),
        tr!(
            "Dans la fenêtre qui s'ouvre (Panneau de configuration > Historique des fichiers), choisis « Sélectionner un lecteur », puis ce disque.",
            "In the window that opens (Control Panel > File History), choose “Select drive”, then that disk."
        ),
        tr!(
            "Clique « Activer ». Dans « Paramètres avancés », garde « Toutes les heures » et « Conserver les versions : toujours ».",
            "Click “Turn on”. In “Advanced settings”, keep “Every hour” and “Keep saved versions: forever”."
        ),
        tr!(
            "Le bilan de Gardien (catégorie Sauvegardes) dira ensuite la date de la dernière sauvegarde.",
            "Gardien's check (Backups category) will then show the date of the last backup."
        ),
    ]
    .iter()
    .enumerate()
    {
        afficher_aligne(&format!("  {TOUCHE}{}{RESET} ", i + 1), etape, 4, "");
    }
    info(tr!(
        "Windows 11 n'a plus ce réglage dans Paramètres, seulement dans le Panneau de configuration. L'autre voie est la sauvegarde OneDrive (Paramètres > Comptes > Sauvegarde Windows), en ligne, limitée par l'espace OneDrive.",
        "Windows 11 no longer has this setting in Settings, only in the Control Panel. The other way is the OneDrive backup (Settings > Accounts > Windows backup), online, limited by the OneDrive space."
    ));
    if demander(tr!(
        "\n  Ouvrir l'Historique des fichiers ? [o/N] : ",
        "\n  Open File History? [y/N]: "
    ))
    .oui()
    {
        crate::machine::ouvrir("control.exe /name Microsoft.FileHistory");
    }
    None
}

/// Retire exactement ce que Gardien a mis en place.
fn annuler_mise_en_place(m: &MiseEnPlace) -> bool {
    match m {
        MiseEnPlace::Systemd {
            empreinte_timer,
            empreinte_service,
            ..
        } => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (empreinte_timer, empreinte_service);
                false
            }
            #[cfg(target_os = "linux")]
            {
                let dossier = dossier_unites();
                let mut ok = crate::machine::appliquer(&[format!("systemctl --user disable --now {TIMER}")]);
                for (nom, attendu) in [(TIMER, empreinte_timer), (SERVICE, empreinte_service)] {
                    let chemin = dossier.join(nom);
                    match std::fs::read_to_string(&chemin) {
                        Ok(t) if &empreinte(&t) == attendu => {
                            if std::fs::remove_file(&chemin).is_err() {
                                ok = false;
                            }
                        }
                        Ok(_) => {
                            info(&trf!(
                                "{} a été modifié depuis : laissé en place.",
                                "{} was modified since: left in place.",
                                chemin_affichable(&chemin)
                            ));
                        }
                        Err(_) => {}
                    }
                }
                let _ = crate::machine::sortie("systemctl", &["--user", "daemon-reload"]);
                ok
            }
        }
        MiseEnPlace::DejaDup { avant, .. } => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = avant;
                false
            }
            #[cfg(target_os = "linux")]
            {
                let mut ok = true;
                for (schema_cle, valeur) in avant {
                    let Some((schema, cle)) = schema_cle.split_once(' ') else {
                        continue;
                    };
                    println!("    {GRIS}$ gsettings set {schema} {cle} {valeur}{RESET}");
                    if crate::machine::sortie("gsettings", &["set", schema, cle, valeur]).is_none() {
                        ok = false;
                    }
                }
                ok
            }
        }
        MiseEnPlace::TimeMachine {
            identifiant,
            deja_actif,
            ..
        } => {
            let mut commandes = Vec::new();
            if let Some(id) = identifiant {
                commandes.push(format!("sudo tmutil removedestination {id}"));
            }
            if !deja_actif {
                commandes.push("sudo tmutil disable".to_string());
            }
            commandes.is_empty() || crate::machine::appliquer(&commandes)
        }
    }
}

/// « gardien sauvegarde-auto --annuler » : retire ce que Gardien a mis en place, après accord.
pub fn annuler() {
    let chemin = fichier_notes();
    let notes = charger_de(&chemin);
    let Some(m) = &notes.mise_en_place else {
        info(tr!(
            "Gardien n'a rien mis en place à annuler.",
            "Gardien set nothing up to undo."
        ));
        return;
    };
    info(&decrire(m));
    if !demander(tr!(
        "  Retirer cette sauvegarde automatique (les fichiers déjà sauvegardés restent sur le disque) ? [o/N] : ",
        "  Remove this automatic backup (the files already backed up stay on the disk)? [y/N]: "
    ))
    .oui()
    {
        return;
    }
    if annuler_mise_en_place(m) {
        let _ = ecrire_dans(&chemin, &Notes::default());
        bon(tr!(
            "Retiré. Les fichiers sauvegardés restent sur le disque externe.",
            "Removed. The backed-up files stay on the external disk."
        ));
    } else {
        mauvais(tr!(
            "Une étape a échoué : la note est gardée pour réessayer.",
            "A step failed: the note is kept to try again."
        ));
    }
}

/// Menu Données › Sauvegarde automatique.
pub fn menu() {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("SAUVEGARDE AUTOMATIQUE", "AUTOMATIC BACKUP")),
        &format!(
            "{GRIS}{}{RESET}",
            tr!("outil du système, disque externe", "system tool, external disk")
        ),
    );
    afficher_aligne(
        "  ",
        tr!(
            "Un disque qui lâche, un vol ou un rançongiciel emportent tout ce qui n'existe qu'ici. Gardien met en place la sauvegarde avec l'outil du système, vers un disque externe, et peut la retirer exactement.",
            "A failing disk, a theft or ransomware take everything that exists only here. Gardien sets up the backup with the system's tool, to an external disk, and can remove it exactly."
        ),
        2,
        GRIS,
    );
    let chemin = fichier_notes();
    let notes = charger_de(&chemin);
    println!();
    match &notes.mise_en_place {
        Some(m) => info(&decrire(m)),
        None => info(tr!(
            "Gardien n'a rien mis en place ici. Le bilan (catégorie Sauvegardes) dit si une sauvegarde existe déjà par ailleurs.",
            "Gardien set nothing up here. The check (Backups category) says whether a backup already exists otherwise."
        )),
    }
    let mut lignes = vec![Ligne::Texte(String::new())];
    if notes.mise_en_place.is_none() {
        lignes.push(Ligne::choix(
            "1",
            tr!("Mettre en place", "Set up"),
            tr!(
                "montré, puis appliqué après accord",
                "shown, then applied after consent"
            ),
        ));
    } else {
        lignes.push(Ligne::choix(
            "2",
            tr!("Annuler ce que Gardien a mis en place", "Undo what Gardien set up"),
            tr!("les fichiers sauvegardés restent", "the backed-up files stay"),
        ));
    }
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    lignes.push(Ligne::Texte(String::new()));
    let Some(choix) = choisir(
        &lignes,
        tr!("  Choix (Entrée pour revenir) : ", "  Choice (Enter to go back): "),
        if notes.mise_en_place.is_none() { "1" } else { "2" },
        tr!("revenir", "back"),
    ) else {
        return;
    };
    match choix.trim() {
        "1" if notes.mise_en_place.is_none() => {
            if let Some(m) = mettre_en_place()
                && let Err(e) = ecrire_dans(&chemin, &Notes { mise_en_place: Some(m) })
            {
                mauvais(&trf!(
                    "La note de ce qui a été mis en place n'a pas pu être écrite ({e}) : l'annulation devra se faire à la main.",
                    "The note of what was set up could not be written ({e}): undoing will have to be done by hand."
                ));
            }
        }
        "2" if notes.mise_en_place.is_some() => annuler(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unites_systemd_bien_formees() {
        let (timer, service) = unites(
            Path::new("/usr/bin/rsync"),
            Path::new("/run/media/alice/Externe"),
            Path::new("/run/media/alice/Externe/Sauvegarde-Gardien/pc-alice"),
            &[
                PathBuf::from("/home/alice/Documents"),
                PathBuf::from("/home/alice/Mes \"images\""),
            ],
        )
        .unwrap();
        // Un nom de disque piégé (saut de ligne) : rien n'est écrit. Un « % » est doublé pour systemd.
        assert!(
            unites(
                Path::new("/usr/bin/rsync"),
                Path::new("/run/media/alice/X\nExecStartPre=/bin/touch /tmp/pirate"),
                Path::new("/run/media/alice/X\nExecStartPre=/bin/touch /tmp/pirate/Sauvegarde-Gardien/pc"),
                &[PathBuf::from("/home/alice/Documents")],
            )
            .is_none()
        );
        let (_, cent) = unites(
            Path::new("/usr/bin/rsync"),
            Path::new("/run/media/alice/100%"),
            Path::new("/run/media/alice/100%/Sauvegarde-Gardien/pc"),
            &[PathBuf::from("/home/alice/Documents")],
        )
        .unwrap();
        assert!(cent.contains("ConditionPathIsMountPoint=/run/media/alice/100%%\n"));
        assert!(cent.contains("\"/run/media/alice/100%%/Sauvegarde-Gardien/pc/\""));
        assert!(timer.contains("OnCalendar=*-*-* 12:00:00") && timer.contains("Persistent=true"));
        assert!(timer.contains("WantedBy=timers.target"));
        assert!(service.contains("ConditionPathIsMountPoint=/run/media/alice/Externe"));
        assert!(service.contains("Type=oneshot"));
        let exec = service.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        assert!(exec.starts_with("ExecStart=\"/usr/bin/rsync\" -a --no-specials"));
        assert!(exec.contains("\"/home/alice/Documents\" \"/home/alice/Mes \\\"images\\\"\" "));
        assert!(exec.ends_with("\"/run/media/alice/Externe/Sauvegarde-Gardien/pc-alice/\""));
        assert!(!exec.contains("--delete"));
        assert_eq!(citer_systemd(r"a\b"), "\"a\\\\b\"");
    }

    #[test]
    fn notes_ecrites_et_relues() {
        let f = std::env::temp_dir().join(format!("gardien-sauvegarde-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&f);
        assert_eq!(charger_de(&f), Notes::default());
        let m = MiseEnPlace::Systemd {
            date: "2026-10-18".into(),
            destination: "/run/media/alice/Externe/Sauvegarde-Gardien/pc".into(),
            empreinte_timer: empreinte("a"),
            empreinte_service: empreinte("b"),
        };
        ecrire_dans(
            &f,
            &Notes {
                mise_en_place: Some(m.clone()),
            },
        )
        .unwrap();
        assert_eq!(charger_de(&f).mise_en_place, Some(m.clone()));
        assert!(decrire(&m).contains("rsync") && decrire(&m).contains("2026-10-18"));
        let t = MiseEnPlace::TimeMachine {
            date: "2026-10-18".into(),
            destination: "/Volumes/Externe".into(),
            identifiant: Some("ABC".into()),
            deja_actif: false,
        };
        ecrire_dans(
            &f,
            &Notes {
                mise_en_place: Some(t.clone()),
            },
        )
        .unwrap();
        assert_eq!(charger_de(&f).mise_en_place, Some(t));
        // Un fichier abîmé : rien, jamais une erreur.
        std::fs::write(&f, "{abîmé").unwrap();
        assert_eq!(charger_de(&f), Notes::default());
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn destinations_de_time_machine() {
        let avant = "> Name          : Externe\n  Kind          : Local\n  Mount Point   : /Volumes/Externe\n  ID            : 1111-AAAA\n";
        let apres = format!(
            "{avant}====================================================\n> Name          : Neuf\n  Kind          : Local\n  ID            : 2222-BBBB\n"
        );
        assert_eq!(identifiants_time_machine(avant), ["1111-AAAA"]);
        assert_eq!(
            nouvel_identifiant(&identifiants_time_machine(avant), &identifiants_time_machine(&apres)),
            Some("2222-BBBB".into())
        );
        assert_eq!(nouvel_identifiant(&["a".into()], &["a".into()]), None);
        assert_eq!(identifiants_time_machine("tmutil: No destinations configured").len(), 0);
    }

    #[test]
    fn historique_des_fichiers_de_windows() {
        let xml = "<?xml version=\"1.0\"?><DataProtectionUserConfig><Target><TargetName>Externe (E:)</TargetName><TargetUrl>E:\\</TargetUrl></Target></DataProtectionUserConfig>";
        assert_eq!(cible_historique(xml), Some("Externe (E:)".into()));
        assert_eq!(cible_historique("<x/>"), None);
        assert_eq!(cible_historique("<TargetName></TargetName>"), None);
        // 2026-10-18 00:00 UTC en FILETIME, vu trois jours plus tard.
        let unix_2026_10_18: u64 = 1_792_281_600;
        let filetime = (unix_2026_10_18 + 11_644_473_600) * 10_000_000;
        assert_eq!(age_filetime_jours(filetime, unix_2026_10_18 + 3 * 86_400), 3);
        assert_eq!(age_filetime_jours(filetime, unix_2026_10_18), 0);
        assert_eq!(age_filetime_jours(0, unix_2026_10_18), unix_2026_10_18 / 86_400);
    }

    #[test]
    fn nom_de_machine_propre() {
        let n = nom_machine();
        assert!(!n.is_empty() && n.chars().all(|c| c.is_alphanumeric() || c == '-'));
        assert!(constats().len() <= 1);
    }
}
