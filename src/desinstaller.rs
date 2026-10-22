//! Retirer Vanguard de cet ordinateur : tout ce qu'il y a posé (surveillance horaire, entretien du mois, sauvegarde
//! automatique, fichiers-pièges, raccourci et icône, copie du programme, restes d'une version d'avant, dossier de
//! données), retrouvé, montré avec ce qui sera fait, puis coché.
//!
//! Rien n'est tenu dans un registre de ce qui a été posé : tout est recalculé à partir de ce qui est trouvé, par des
//! noms exacts, une marque ou une empreinte. Un registre se perd, et un programme du compte peut le réécrire : il ne
//! doit jamais pouvoir faire effacer autre chose. Ce que Vanguard n'a pas posé, et la clé USB, ne sont jamais touchés.
//! Le dossier de données n'est jamais coché d'office et demande un second accord : il garde le carnet des appareils,
//! l'historique, l'apprentissage, la quarantaine (des fichiers peut-être à remettre) et de quoi défaire les
//! changements faits sur le système, que la désinstallation propose de défaire d'abord par leurs propres outils.
//! Sans droits d'administrateur.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::passage::{self, Reste};
use crate::reseau::surveillance::{self, Planifie};
use crate::sauvegarde::MiseEnPlace;
use crate::selection::{Case, Ligne, choisir, cocher};
use crate::ui::*;

/// Où chercher : les chemins de cet ordinateur, ou ceux d'un dossier jetable (tests).
pub(crate) struct Lieux {
    /// Le dossier de données de Vanguard (`reseau::dossier_local`).
    pub donnees: PathBuf,
    /// Les dossiers des unités systemd de l'utilisateur (Linux ; vide ailleurs) : celui de la surveillance et de
    /// l'entretien, puis celui de la sauvegarde s'il diffère (XDG_CONFIG_HOME).
    pub unites: Vec<PathBuf>,
    /// Le dossier des agents launchd (macOS).
    pub agents: Option<PathBuf>,
    /// Les tâches du Planificateur aux noms de Vanguard (Windows) ; `None` : le planificateur n'a pas pu être lu.
    pub taches: Option<Vec<TacheLue>>,
    /// Où va le raccourci sur ce système (`raccourci::chemin`).
    pub raccourci: Option<PathBuf>,
    /// Le programme en marche.
    pub programme: Option<PathBuf>,
    /// La clé VANGUARD branchée : jamais touchée.
    pub cle: Option<PathBuf>,
}

/// Une tâche du Planificateur de Windows, lue.
pub(crate) struct TacheLue {
    pub nom: String,
    pub programme: String,
    pub active: bool,
}

impl Lieux {
    pub(crate) fn de_cet_ordinateur() -> Result<Lieux, String> {
        let donnees = crate::reseau::dossier_local();
        // Sans HOME ni XDG_DATA_HOME (LOCALAPPDATA sous Windows), le dossier serait relatif : le dossier courant, qui
        // n'est pas celui de Vanguard. Rien n'est cherché, encore moins effacé.
        if !donnees.is_absolute() {
            return Err(tr!(
                "✖ Dossier de Vanguard inconnu (ni HOME ni XDG_DATA_HOME, ou LOCALAPPDATA) : rien n'est cherché.",
                "✖ Vanguard's folder is unknown (no HOME nor XDG_DATA_HOME, or LOCALAPPDATA): nothing is looked for."
            )
            .to_string());
        }
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut unites: Vec<PathBuf> = Vec::new();
        #[cfg(target_os = "linux")]
        {
            for d in [
                surveillance::dossier_unites_maison(),
                crate::sauvegarde::dossier_unites(),
            ] {
                if d.is_absolute() && !unites.contains(&d) {
                    unites.push(d);
                }
            }
        }
        #[cfg(target_os = "macos")]
        let agents = Some(crate::nettoyer::maison().join("Library/LaunchAgents")).filter(|d| d.is_absolute());
        #[cfg(not(target_os = "macos"))]
        let agents = None;
        #[cfg(windows)]
        let taches = {
            let mut noms = vec![
                surveillance::TACHE_WINDOWS.to_string(),
                crate::entretien::TACHE_WINDOWS.to_string(),
            ];
            noms.extend(passage::taches_d_avant());
            let noms: Vec<&str> = noms.iter().map(String::as_str).collect();
            surveillance::definitions_windows(&noms).map(|lues| {
                lues.into_iter()
                    .map(|(nom, d)| TacheLue {
                        nom,
                        programme: d.programme,
                        active: d.active,
                    })
                    .collect()
            })
        };
        #[cfg(not(windows))]
        let taches = Some(Vec::new());
        #[cfg(unix)]
        let programme = crate::protection::cle::exe_d_origine();
        #[cfg(windows)]
        let programme = std::env::current_exe().ok().and_then(|e| e.canonicalize().ok());
        Ok(Lieux {
            donnees,
            unites,
            agents,
            taches,
            raccourci: crate::raccourci::chemin(),
            programme,
            cle: crate::reseau::cle_usb(),
        })
    }

    /// Les lieux d'un ordinateur jetable, sous `racine` : la même disposition que sous Linux.
    #[cfg(test)]
    pub(crate) fn jetable(racine: &Path) -> Lieux {
        Lieux {
            donnees: racine.join("donnees/vanguard"),
            unites: vec![racine.join(".config/systemd/user"), racine.join("config/systemd/user")],
            agents: Some(racine.join("Library/LaunchAgents")),
            taches: Some(Vec::new()),
            raccourci: Some(racine.join("donnees/applications/Vanguard.desktop")),
            programme: None,
            cle: Some(racine.join("cle")),
        }
    }
}

/// Ce qu'est un élément trouvé ; l'ordre est celui de la liste et du retrait. Les données partent en dernier :
/// plusieurs retraits y écrivent avant (changements.jsonl, pieges.json, sauvegarde.json).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Genre {
    Surveillance,
    Entretien,
    Sauvegarde,
    Avant,
    Pieges,
    Raccourci,
    Icone,
    Programme,
    DonneesAvant,
    Donnees,
}

/// Comment le retirer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Retrait {
    Surveillance,
    Entretien,
    /// La note de ce qui a été mis en place (`None` : unités trouvées par leur nom, sans note), et les unités trouvées.
    Sauvegarde(Option<MiseEnPlace>, Vec<PathBuf>),
    Pieges,
    /// Le raccourci (même absent) : `raccourci::retirer` retire aussi l'icône de Vanguard.
    Raccourci(PathBuf),
    /// Des copies du programme dans bin/.
    Fichiers(Vec<PathBuf>),
    /// Délégué à `passage` (ancien nom).
    Avant(Reste),
    Dossier(PathBuf),
}

/// Un élément de la liste : ce qu'on montre, ce qui est coché d'office, ce qui sera fait.
#[derive(Debug, Clone)]
pub(crate) struct Element {
    pub genre: Genre,
    pub texte: String,
    pub precision: String,
    pub detail: String,
    pub coche: bool,
    pub retrait: Retrait,
    /// Le programme que lance cette tâche ou ce raccourci : la copie de bin/ reste s'il est gardé.
    pub lance: Option<PathBuf>,
}

#[derive(Default)]
pub(crate) struct Recensement {
    pub elements: Vec<Element>,
    /// Ce qui reste à faire soi-même, avec la commande (Time Machine, programme en marche sous Windows…).
    pub a_faire: Vec<String>,
    /// Ce qui n'est pas à Vanguard ou pas à retirer d'ici (le programme sur la clé…) : gardé, dit.
    pub pas_a_lui: Vec<String>,
    /// Ce qui n'a pas pu être cherché : dit, jamais compté comme absent.
    pub non_verifie: Vec<String>,
}

/// Le même fichier ? Leurs formes canoniques d'abord (un lien, `\\?\` de Windows), à défaut les chemins tels quels.
fn meme(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// Ce chemin est-il sur la clé ? Sa forme canonique, ou le chemin tel quel s'il n'existe plus.
fn sur_la_cle(p: &Path, cle: &Path) -> bool {
    let c = cle.canonicalize().unwrap_or_else(|_| cle.to_path_buf());
    p.canonicalize().is_ok_and(|q| q.starts_with(&c)) || p.starts_with(cle) || p.starts_with(&c)
}

/// La place prise par un dossier, sans suivre aucun lien.
fn taille(d: &Path) -> u64 {
    fn dans(d: &Path, profondeur: usize) -> u64 {
        if profondeur > 64 {
            return 0;
        }
        let Ok(entrees) = std::fs::read_dir(d) else {
            return 0;
        };
        entrees
            .flatten()
            .map(|e| match std::fs::symlink_metadata(e.path()) {
                Ok(m) if m.is_dir() => dans(&e.path(), profondeur + 1),
                Ok(m) if m.is_file() => m.len(),
                _ => 0,
            })
            .sum()
    }
    dans(d, 0)
}

/// Le programme d'un raccourci : la ligne Exec= d'un .desktop, la ligne exec d'un .command (citée pour sh) ; aucun
/// pour un .lnk, qui ne se lit pas comme du texte.
fn programme_du_raccourci(p: &Path) -> Option<PathBuf> {
    let texte = std::fs::read_to_string(p).ok()?;
    if let Some(v) = texte.lines().find_map(|l| l.strip_prefix("Exec=")) {
        return surveillance::premier_mot_cite(v);
    }
    let v = texte.lines().find_map(|l| l.strip_prefix("exec "))?;
    let mut mot = String::new();
    let mut car = v.trim_start().chars();
    while let Some(c) = car.next() {
        match c {
            '\'' => mot.extend(car.by_ref().take_while(|&c| c != '\'')),
            '\\' => mot.extend(car.next()),
            c if c.is_whitespace() => break,
            c => mot.push(c),
        }
    }
    (!mot.is_empty()).then(|| PathBuf::from(mot))
}

/// Le programme que lance un agent launchd.
#[cfg(any(target_os = "macos", test))]
fn programme_d_un_agent(p: &Path) -> Option<PathBuf> {
    surveillance::lire_plist(&std::fs::read(p).ok()?).map(|(programme, _)| programme)
}

#[cfg(not(any(target_os = "macos", test)))]
fn programme_d_un_agent(_: &Path) -> Option<PathBuf> {
    None
}

/// La surveillance ou l'entretien, s'ils sont planifiés quelque part dans les lieux : unités systemd, agent launchd,
/// tâche du Planificateur, chacun à son nom exact.
fn planifie(l: &Lieux, quoi: Planifie) -> Option<Element> {
    let (nom, agent, tache) = quoi.noms();
    let mut trouve: Vec<String> = Vec::new();
    let mut lance: Option<PathBuf> = None;
    for d in &l.unites {
        let service = d.join(format!("{nom}.service"));
        let timer = d.join(format!("{nom}.timer"));
        if service.exists() || timer.exists() {
            trouve.push(chemin_affichable(if timer.exists() { &timer } else { &service }));
            if lance.is_none() {
                lance = std::fs::read_to_string(&service)
                    .ok()
                    .and_then(|t| surveillance::programme_d_une_unite(&t));
            }
        }
    }
    if let Some(a) = &l.agents {
        let plist = a.join(format!("{agent}.plist"));
        if plist.is_file() {
            trouve.push(chemin_affichable(&plist));
            lance = lance.or_else(|| programme_d_un_agent(&plist));
        }
    }
    if let Some(t) = l.taches.iter().flatten().find(|t| t.nom.eq_ignore_ascii_case(tache)) {
        let etat = if t.active {
            ""
        } else {
            tr!(" (désactivée)", " (disabled)")
        };
        trouve.push(format!("« {} »{etat}", t.nom));
        lance = lance.or_else(|| Some(PathBuf::from(t.programme.trim().trim_matches('"'))));
    }
    if trouve.is_empty() {
        return None;
    }
    let lance_montre = lance
        .as_deref()
        .map_or_else(|| tr!("non lu", "not read").to_string(), chemin_affichable);
    let (genre, retrait, texte, detail) = match quoi {
        Planifie::Surveillance => (
            Genre::Surveillance,
            Retrait::Surveillance,
            tr!("Surveillance horaire", "Hourly monitoring"),
            trf!(
                "Arrêtée, puis retirée du planificateur : {}. Elle lance : {lance_montre}",
                "Stopped, then removed from the scheduler: {}. It starts: {lance_montre}",
                trouve.join(", ")
            ),
        ),
        Planifie::Entretien => (
            Genre::Entretien,
            Retrait::Entretien,
            tr!("Entretien du mois", "Monthly check-up"),
            trf!(
                "Arrêté, puis retiré du planificateur : {}. Il lance : {lance_montre}",
                "Stopped, then removed from the scheduler: {}. It starts: {lance_montre}",
                trouve.join(", ")
            ),
        ),
    };
    Some(Element {
        genre,
        texte: texte.to_string(),
        precision: tr!("désactivée puis retirée", "turned off, then removed").to_string(),
        detail,
        coche: true,
        retrait,
        lance,
    })
}

/// La sauvegarde automatique : d'après sa note, ou ses unités trouvées par leur nom exact si la note manque.
fn sauvegarde(l: &Lieux, r: &mut Recensement) {
    use crate::sauvegarde::{SERVICE, TIMER};
    let unites: Vec<PathBuf> = l
        .unites
        .iter()
        .flat_map(|d| [d.join(TIMER), d.join(SERVICE)])
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .collect();
    let rsync = unites
        .iter()
        .filter(|p| p.ends_with(SERVICE))
        .find_map(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| surveillance::programme_d_une_unite(&t));
    let precision = tr!("retirée, tes copies restent", "removed, your copies stay").to_string();
    let montre: Vec<String> = unites.iter().map(|p| chemin_affichable(p)).collect();
    let rsync_texte = tr!("Sauvegarde automatique (rsync)", "Automatic backup (rsync)").to_string();
    let element = match crate::sauvegarde::mise_en_place_de(&l.donnees) {
        Some(m @ MiseEnPlace::Systemd { .. }) => {
            let MiseEnPlace::Systemd { destination, .. } = &m else {
                return;
            };
            Element {
                genre: Genre::Sauvegarde,
                texte: rsync_texte,
                precision,
                detail: trf!(
                    "Minuterie arrêtée, ses unités retirées ({}) ; une unité modifiée depuis sa pose reste, et c'est dit. Les copies restent sur {destination}.",
                    "Timer stopped, its units removed ({}); a unit changed since it was placed stays, and this is said. The copies stay on {destination}.",
                    montre.join(", ")
                ),
                coche: true,
                lance: rsync,
                retrait: Retrait::Sauvegarde(Some(m), unites),
            }
        }
        Some(m @ MiseEnPlace::DejaDup { .. }) => {
            let MiseEnPlace::DejaDup { destination, .. } = &m else {
                return;
            };
            Element {
                genre: Genre::Sauvegarde,
                texte: tr!("Sauvegarde automatique (Déjà Dup)", "Automatic backup (Déjà Dup)").to_string(),
                precision,
                detail: trf!(
                    "Les réglages de Déjà Dup reprennent leur valeur d'avant (gsettings). Les copies restent sur {destination}.",
                    "Déjà Dup's settings get their earlier value back (gsettings). The copies stay on {destination}."
                ),
                coche: true,
                lance: None,
                retrait: Retrait::Sauvegarde(Some(m), Vec::new()),
            }
        }
        // Time Machine se défait avec sudo : jamais lancé d'ici, dit avec sa commande.
        Some(MiseEnPlace::TimeMachine { .. }) => {
            r.a_faire.push(tr!(
                "Time Machine : la destination ajoutée par Vanguard reste ; « vanguard sauvegarde-auto --annuler » la retire (mot de passe administrateur).",
                "Time Machine: the destination added by Vanguard stays; “vanguard auto-backup --undo” removes it (administrator password)."
            ).to_string());
            return;
        }
        None if !unites.is_empty() => Element {
            genre: Genre::Sauvegarde,
            texte: rsync_texte,
            precision,
            detail: trf!(
                "Sans note de sa mise en place : minuterie arrêtée, unités retirées par leur nom ({}).",
                "Without a note of its setup: timer stopped, units removed by their name ({}).",
                montre.join(", ")
            ),
            coche: true,
            lance: rsync,
            retrait: Retrait::Sauvegarde(None, unites),
        },
        None => return,
    };
    r.elements.push(element);
}

/// Tout ce que Vanguard a posé dans les lieux `l`, sans rien changer : ne lit que des fichiers sous les chemins de
/// `l` et les tâches de `l.taches`. Dans l'ordre du retrait ; tout coché d'office, sauf les dossiers de données.
pub(crate) fn recenser(l: &Lieux) -> Recensement {
    let mut r = Recensement::default();
    if l.taches.is_none() {
        r.non_verifie.push(tr!(
            "Tâches planifiées non lues : la surveillance et l'entretien n'ont pas pu être cherchés (non vérifié). « vanguard surveillance off » et « vanguard entretien off » les retirent.",
            "Scheduled tasks not read: monitoring and the monthly check-up could not be looked for (not checked). “vanguard monitor off” and “vanguard maintenance off” remove them."
        ).to_string());
    }
    for quoi in [Planifie::Surveillance, Planifie::Entretien] {
        r.elements.extend(planifie(l, quoi));
    }
    sauvegarde(l, &mut r);

    // Les restes d'une version d'avant : la copie du programme d'avant va avec bin/, l'ancien dossier de données avec
    // les données ; le reste à part.
    let mut copies_d_avant = Vec::new();
    let mut donnees_d_avant = None;
    for (reste, montre) in passage::restes(l) {
        match reste {
            Reste::Programme(p) => copies_d_avant.push(p),
            Reste::Donnees(d) => donnees_d_avant = Some(d),
            reste => r.elements.push(Element {
                genre: Genre::Avant,
                texte: trf!("Version d'avant : {}", "Earlier version: {}", reste.quoi()),
                precision: tr!("reste d'une version d'avant", "left by an earlier version").to_string(),
                detail: trf!("Retire {}.", "Removes {}.", chemin_affichable(&montre)),
                coche: true,
                lance: None,
                retrait: Retrait::Avant(reste),
            }),
        }
    }

    match crate::protection::pieges::nombre_dans(&l.donnees) {
        Ok(0) => {}
        Ok(n) => r.elements.push(Element {
            genre: Genre::Pieges,
            texte: tr!(
                "Fichiers-pièges (Documents, Images, Bureau)",
                "Decoy files (Documents, Pictures, Desktop)"
            )
            .to_string(),
            precision: trf!("{n} retirés, sauf les modifiés", "{n} removed, except changed ones"),
            detail: tr!(
                "Les fichiers « !Vanguard » posés dans tes dossiers partent ; un fichier modifié ou renommé reste : c'est la preuve d'un passage.",
                "The “!Vanguard” files placed in your folders go; a changed or renamed one stays: it is the evidence of an attack."
            )
            .to_string(),
            coche: true,
            lance: None,
            retrait: Retrait::Pieges,
        }),
        Err(()) => r.non_verifie.push(trf!(
            "La liste des fichiers-pièges ne se lit plus ({}) : ils ne peuvent pas être retirés exactement. Les fichiers « !Vanguard » de Documents, Images et Bureau se suppriment à la main.",
            "The decoy file list can no longer be read ({}): they cannot be removed exactly. The “!Vanguard” files in Documents, Pictures and Desktop can be deleted by hand.",
            chemin_affichable(&l.donnees.join("pieges.json"))
        )),
    }

    if let Some(p) = &l.raccourci {
        let present = std::fs::symlink_metadata(p).is_ok();
        let a_lui = present && crate::raccourci::de_vanguard(p);
        let icone = crate::raccourci::icone(p).filter(|i| {
            std::fs::symlink_metadata(i).is_ok_and(|m| m.is_file())
                && std::fs::read(i).is_ok_and(|o| crate::raccourci::icone_de_vanguard(&o))
        });
        let menu = p.extension().is_some_and(|e| e == "desktop");
        if a_lui {
            let lance = programme_du_raccourci(p);
            let avec = icone
                .as_deref()
                .map(|i| trf!(" et son icône {}", " and its icon {}", chemin_affichable(i)))
                .unwrap_or_default();
            r.elements.push(Element {
                genre: Genre::Raccourci,
                texte: if menu {
                    tr!("Raccourci : menu des applications", "Shortcut: applications menu")
                } else {
                    tr!("Raccourci sur le Bureau", "Shortcut on the Desktop")
                }
                .to_string(),
                precision: if icone.is_some() {
                    tr!("retiré, avec son icône", "removed, with its icon")
                } else {
                    tr!("retiré", "removed")
                }
                .to_string(),
                detail: trf!(
                    "Efface {}{avec}. Il lance : {}",
                    "Erases {}{avec}. It starts: {}",
                    chemin_affichable(p),
                    lance
                        .as_deref()
                        .map_or_else(|| tr!("non lu", "not read").to_string(), chemin_affichable)
                ),
                coche: true,
                lance,
                retrait: Retrait::Raccourci(p.clone()),
            });
        } else if present {
            // Le même nom, sans la marque : posé par quelqu'un d'autre, qui peut aussi se servir de l'icône.
            r.pas_a_lui.push(trf!(
                "Un raccourci au nom de Vanguard ({}) n'a pas été posé par Vanguard : il reste, avec son icône.",
                "A shortcut named Vanguard ({}) was not placed by Vanguard: it stays, with its icon.",
                chemin_affichable(p)
            ));
        } else if let Some(i) = &icone {
            r.elements.push(Element {
                genre: Genre::Icone,
                texte: tr!("Icône du menu des applications", "Applications menu icon").to_string(),
                precision: tr!("retirée (celle de Vanguard)", "removed (Vanguard's own)").to_string(),
                detail: trf!(
                    "Efface {}, restée sans son raccourci : reconnue à son empreinte.",
                    "Erases {}, left without its shortcut: recognised by its fingerprint.",
                    chemin_affichable(i)
                ),
                coche: true,
                lance: None,
                retrait: Retrait::Raccourci(p.clone()),
            });
        }
    }

    // La copie du programme : bin/vanguard, les restes d'une mise à jour, la copie d'avant ; rien d'autre de bin/.
    let bin = l.donnees.join("bin");
    let nom = crate::mise_a_jour::NOM;
    let mut fichiers: Vec<PathBuf> = [nom.to_string(), format!("{nom}.ancien"), format!("{nom}.nouveau")]
        .iter()
        .map(|n| bin.join(n))
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .collect();
    fichiers.extend(copies_d_avant);
    // Windows n'efface pas un programme en marche : la copie qui tourne n'est pas essayée, et c'est dit.
    let en_marche = l.programme.as_deref();
    let tourne = |f: &Path| cfg!(windows) && en_marche.is_some_and(|p| meme(p, f));
    let garde = fichiers.iter().find(|f| tourne(f)).cloned();
    fichiers.retain(|f| !tourne(f));
    if let Some(g) = &garde {
        r.a_faire.push(trf!(
            "Ce programme est la copie de bin/ ({}) : Windows n'efface pas un programme en marche. Ferme Vanguard, puis supprime le dossier {} ; ou lance « vanguard desinstaller » depuis la clé, qui l'effacera.",
            "This program is the bin/ copy ({}): Windows does not erase a running program. Close Vanguard, then delete the folder {}; or run “vanguard uninstall” from the key, which will erase it.",
            chemin_affichable(g),
            chemin_affichable(&bin)
        ));
    }
    if !fichiers.is_empty() {
        let liste: Vec<String> = fichiers.iter().map(|f| chemin_affichable(f)).collect();
        r.elements.push(Element {
            genre: Genre::Programme,
            texte: tr!("Copie du programme (bin/)", "Program copy (bin/)").to_string(),
            precision: if garde.is_some() {
                tr!("en marche : à supprimer après", "running: delete it afterwards")
            } else {
                tr!("effacée", "erased")
            }
            .to_string(),
            detail: trf!(
                "Efface {} ; le dossier bin/ part s'il est vide ensuite, rien d'autre de bin/ n'est touché.",
                "Erases {}; the bin/ folder goes if it is empty afterwards, nothing else in bin/ is touched.",
                liste.join(", ")
            ),
            coche: true,
            lance: None,
            retrait: Retrait::Fichiers(fichiers),
        });
    }

    if let Some(p) = en_marche {
        let dans_les_donnees = p.starts_with(&l.donnees) || l.donnees.canonicalize().is_ok_and(|d| p.starts_with(d));
        if l.cle.as_deref().is_some_and(|c| sur_la_cle(p, c)) {
            r.pas_a_lui.push(trf!(
                "Le programme de la clé ({}) reste sur la clé : Vanguard n'efface jamais la clé.",
                "The key's program ({}) stays on the key: Vanguard never erases the key.",
                chemin_affichable(p)
            ));
        } else if !dans_les_donnees {
            r.pas_a_lui.push(trf!(
                "Le programme lancé ({}) n'a pas été posé par Vanguard : il reste. Supprime-le toi-même si tu n'en veux plus.",
                "The running program ({}) was not placed by Vanguard: it stays. Delete it yourself if you no longer want it.",
                chemin_affichable(p)
            ));
        }
    }

    if let Some(d) = donnees_d_avant {
        r.elements.push(Element {
            genre: Genre::DonneesAvant,
            texte: trf!(
                "Ancien dossier de données ({})",
                "Old data folder ({})",
                crate::nettoyer::taille_lisible(taille(&d))
            ),
            precision: tr!("gardé, sauf si tu le coches", "kept unless you check it").to_string(),
            detail: trf!(
                "L'ancien dossier de données ({}), qui n'a pas pu être repris : effacé seulement après une seconde question.",
                "The old data folder ({}), which could not be taken over: erased only after a second question.",
                chemin_affichable(&d)
            ),
            coche: false,
            lance: None,
            retrait: Retrait::Dossier(d),
        });
    }
    if std::fs::symlink_metadata(&l.donnees).is_ok() {
        r.elements.push(Element {
            genre: Genre::Donnees,
            texte: trf!(
                "Dossier de données ({})",
                "Data folder ({})",
                crate::nettoyer::taille_lisible(taille(&l.donnees))
            ),
            precision: tr!("gardé, sauf si tu le coches", "kept unless you check it").to_string(),
            detail: trf!(
                "Carnet des appareils, historique, apprentissage, quarantaine : {}. Effacé seulement après une seconde question.",
                "Device record, history, learning, quarantine: {}. Erased only after a second question.",
                chemin_affichable(&l.donnees)
            ),
            coche: false,
            lance: None,
            retrait: Retrait::Dossier(l.donnees.clone()),
        });
    }

    // La clé n'est jamais touchée, quoi qu'on ait trouvé : un chemin qui y mène est écarté, et c'est dit.
    if let Some(cle) = l.cle.as_deref() {
        r.elements.retain(|e| {
            let sur = chemins(e).iter().any(|p| sur_la_cle(p, cle));
            if sur {
                r.pas_a_lui.push(trf!(
                    "{} : sur la clé, jamais touché.",
                    "{}: on the key, never touched.",
                    e.texte
                ));
            }
            !sur
        });
    }
    r
}

/// Les fichiers et dossiers qu'un élément touche.
fn chemins(e: &Element) -> Vec<PathBuf> {
    match &e.retrait {
        Retrait::Surveillance | Retrait::Entretien | Retrait::Pieges => Vec::new(),
        Retrait::Sauvegarde(_, f) | Retrait::Fichiers(f) => f.clone(),
        Retrait::Raccourci(p) | Retrait::Dossier(p) => vec![p.clone()],
        Retrait::Avant(r) => r.chemins(),
    }
}

/// Les cases à cocher. Sans terminal, rien n'est coché au départ : `cocher` y valide sur une ligne vide les cases déjà
/// cochées, et une entrée redirigée vide accepterait tout. Les numéros sont alors à taper.
fn cases(e: &[Element], terminal: bool) -> Vec<Case> {
    e.iter()
        .map(|x| Case {
            texte: x.texte.clone(),
            precision: x.precision.clone(),
            detail: x.detail.clone(),
            cochee: terminal && x.coche,
            recommandee: x.coche,
            fixe: false,
        })
        .collect()
}

/// La copie du programme reste si un élément gardé la lance (une surveillance gardée lancerait un programme effacé) :
/// elle est décochée, et c'est dit.
fn garder_les_dependances(e: &[Element], etats: &mut [bool]) -> Vec<String> {
    let mut messages = Vec::new();
    for (i, garde_e) in e.iter().enumerate() {
        if etats[i] {
            continue;
        }
        let Some(lance) = &garde_e.lance else { continue };
        for (j, copie) in e.iter().enumerate() {
            if let Retrait::Fichiers(fichiers) = &copie.retrait
                && etats[j]
                && fichiers.iter().any(|f| f == lance || meme(f, lance))
            {
                etats[j] = false;
                messages.push(trf!(
                    "Copie du programme gardée : {}, que tu gardes, la lance.",
                    "Program copy kept: {}, which you keep, starts it.",
                    garde_e.texte
                ));
            }
        }
    }
    messages
}

/// Efface le dossier `d` en entier, sans jamais suivre un lien ni une jonction (le lien lui-même part, pas ce qu'il
/// désigne). Sous Windows, la lecture seule est retirée d'abord (la quarantaine pose ses fichiers ainsi). `garder` :
/// le programme en marche (Windows ne l'efface pas). Refusé pour un chemin relatif ou sur la clé. Rend ce qui n'a pas
/// pu partir, avec la raison.
pub(crate) fn effacer_dossier(d: &Path, garder: Option<&Path>, cle: Option<&Path>) -> Vec<(PathBuf, String)> {
    if !d.is_absolute() {
        return vec![(
            d.to_path_buf(),
            tr!("chemin relatif : refusé", "relative path: refused").to_string(),
        )];
    }
    if cle.is_some_and(|c| sur_la_cle(d, c)) {
        return vec![(
            d.to_path_buf(),
            tr!("sur la clé : jamais effacé", "on the key: never erased").to_string(),
        )];
    }
    let garder = garder.and_then(|g| g.canonicalize().ok());
    let mut restes = Vec::new();
    effacer(d, garder.as_deref(), &mut restes, 0);
    restes
}

/// Efface `p` (un fichier, un lien ou un dossier) ; dit si quelque chose y est resté.
fn effacer(p: &Path, garder: Option<&Path>, restes: &mut Vec<(PathBuf, String)>, profondeur: usize) -> bool {
    let meta = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(e) => {
            restes.push((p.to_path_buf(), e.to_string()));
            return false;
        }
    };
    if meta.is_symlink() {
        // Sous Windows, un lien vers un dossier (ou une jonction) se retire comme un dossier : sa cible reste.
        if std::fs::remove_file(p).is_ok() || std::fs::remove_dir(p).is_ok() {
            return true;
        }
        restes.push((p.to_path_buf(), tr!("lien non retiré", "link not removed").to_string()));
        return false;
    }
    if meta.is_dir() {
        if profondeur > 256 {
            restes.push((p.to_path_buf(), tr!("trop profond", "too deep").to_string()));
            return false;
        }
        let mut vide = true;
        match std::fs::read_dir(p) {
            Ok(entrees) => {
                for e in entrees.flatten() {
                    vide &= effacer(&e.path(), garder, restes, profondeur + 1);
                }
            }
            Err(e) => {
                restes.push((p.to_path_buf(), e.to_string()));
                return false;
            }
        }
        // Ce qui est resté dedans est déjà dit : le dossier qui le contient ne s'ajoute pas à la liste.
        if !vide {
            return false;
        }
        return match std::fs::remove_dir(p) {
            Ok(()) => true,
            Err(e) => {
                restes.push((p.to_path_buf(), e.to_string()));
                false
            }
        };
    }
    if garder.is_some_and(|g| p.canonicalize().is_ok_and(|c| c == g)) {
        restes.push((
            p.to_path_buf(),
            tr!("programme en marche : gardé", "running program: kept").to_string(),
        ));
        return false;
    }
    #[cfg(windows)]
    {
        let mut droits = meta.permissions();
        if droits.readonly() {
            #[allow(clippy::permissions_set_readonly_false)] // il va être supprimé
            droits.set_readonly(false);
            let _ = std::fs::set_permissions(p, droits);
        }
    }
    match std::fs::remove_file(p) {
        Ok(()) => true,
        Err(e) => {
            restes.push((p.to_path_buf(), e.to_string()));
            false
        }
    }
}

/// Les changements faits sur le système que des outils de Vanguard savent défaire, et les corrections qui se défont à
/// la main.
struct Annulables {
    optimiser: usize,
    blocages: usize,
    jeux: usize,
    quarantaine: usize,
    a_la_main: Vec<(String, String)>,
}

impl Annulables {
    fn menu_vide(&self) -> bool {
        self.optimiser + self.blocages + self.jeux + self.quarantaine == 0
    }

    fn vide(&self) -> bool {
        self.menu_vide() && self.a_la_main.is_empty()
    }

    /// Ce qui se défait exactement grâce au dossier de données.
    fn a_defaire(&self) -> usize {
        self.optimiser + self.blocages + self.jeux
    }
}

fn annulables() -> Annulables {
    Annulables {
        optimiser: crate::optimiser::reglages_notes(),
        blocages: crate::changements::blocages_en_place().len(),
        jeux: crate::gaming::reglages_notes(),
        quarantaine: crate::protection::quarantaine::nombre(),
        a_la_main: crate::changements::a_defaire_a_la_main(),
    }
}

/// Les changements faits sur le système : retirer Vanguard ne les défait pas. Leurs propres outils les défont d'abord,
/// si on veut ; ce qui reste est redit à la fin. `liste` : les montrer seulement.
fn defaire_d_abord(liste: bool) {
    let a = annulables();
    if a.vide() {
        return;
    }
    section(tr!("Changements faits sur le système", "Changes made to the system"));
    afficher_aligne(
        "  ",
        tr!(
            "Retirer Vanguard ne les défait pas : défais d'abord ceux que tu ne veux plus, avec leurs outils. Ce que tu gardes est redit à la fin.",
            "Removing Vanguard does not undo them: first undo those you no longer want, with their tools. What you keep is said again at the end."
        ),
        2,
        "",
    );
    if liste {
        for (texte, precision) in entrees_annulables(&a) {
            println!("  • {texte} : {precision}");
        }
    } else if !a.menu_vide() {
        loop {
            let a = annulables();
            if a.menu_vide() {
                break;
            }
            let mut lignes = vec![Ligne::Texte(String::new())];
            for (i, (texte, precision)) in entrees_annulables(&a).into_iter().enumerate() {
                lignes.push(Ligne::choix(&(i + 1).to_string(), &texte, &precision));
            }
            lignes.push(Ligne::Texte(String::new()));
            lignes.push(Ligne::choix("↵", tr!("Continuer", "Continue"), ""));
            let Some(choix) = choisir(
                &lignes,
                tr!(
                    "\n  Numéro (Entrée pour continuer) : ",
                    "\n  Number (Enter to continue): "
                ),
                "↵",
                tr!("continuer", "continue"),
            ) else {
                break;
            };
            let outils = outils_annulables(&a);
            let Some(outil) = choix
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|n| outils.get(n.checked_sub(1)?))
            else {
                break;
            };
            outil();
        }
    }
    let a = annulables();
    if !a.a_la_main.is_empty() {
        println!();
        afficher_aligne(
            "  ",
            &trf!(
                "« vanguard changements » montre les {} correction(s) faites ici : celles qui ne viennent ni d'Optimiser ni d'un blocage ne se défont pas toutes seules, chacune avec la commande inverse. Les dernières :",
                "“vanguard changes” shows the {} fix(es) made here: those that come neither from Optimize nor from a block do not undo themselves, each with the opposite command. The latest:",
                a.a_la_main.len()
            ),
            2,
            "",
        );
        for (date, commande) in a.a_la_main.iter().rev().take(5) {
            afficher_aligne(
                &format!("    {GRIS}{date}{RESET}  "),
                &commande_affichable(commande),
                22,
                GRIS,
            );
        }
    }
}

/// Les lignes du petit menu : (texte, précision), seulement celles qui ont de quoi défaire.
fn entrees_annulables(a: &Annulables) -> Vec<(String, String)> {
    let mut e = Vec::new();
    if a.optimiser > 0 {
        e.push((
            tr!("Réglages d'Optimiser", "Optimize settings").to_string(),
            trf!("{} réglage(s), annulables", "{} setting(s), undoable", a.optimiser),
        ));
    }
    if a.blocages > 0 {
        e.push((
            tr!("Blocages en place", "Blocks in place").to_string(),
            trf!("{}, annulables un à un", "{}, undoable one by one", a.blocages),
        ));
    }
    if a.jeux > 0 {
        e.push((
            tr!("Réglages pour jouer", "Gaming settings").to_string(),
            trf!("{} réglage(s), annulables", "{} setting(s), undoable", a.jeux),
        ));
    }
    if a.quarantaine > 0 {
        e.push((
            tr!("Quarantaine", "Quarantine").to_string(),
            trf!("{} fichier(s) à remettre ?", "{} file(s) to put back?", a.quarantaine),
        ));
    }
    e
}

/// Les outils qui défont, dans l'ordre de `entrees_annulables`.
fn outils_annulables(a: &Annulables) -> Vec<fn()> {
    let mut o: Vec<fn()> = Vec::new();
    if a.optimiser > 0 {
        o.push(crate::optimiser::tout_annuler);
    }
    if a.blocages > 0 {
        o.push(crate::protection::blocage::annuler);
    }
    if a.jeux > 0 {
        // Son choix 3 : « Remettre les réglages comme avant ».
        o.push(crate::gaming::menu);
    }
    if a.quarantaine > 0 {
        o.push(crate::protection::quarantaine::menu);
    }
    o
}

/// Ce qui a été fait, gardé, ce qui a échoué et ce qui reste à faire soi-même.
#[derive(Default)]
struct Bilan {
    retire: Vec<String>,
    garde: Vec<String>,
    echoue: Vec<(String, String)>,
    a_faire: Vec<String>,
}

/// Le texte du bilan. Un échec n'est jamais compté comme retiré, ni la fin dite « faite » s'il y en a un.
fn rediger_bilan(b: &Bilan) -> Vec<String> {
    let mut l = Vec::new();
    let mut partie = |titre: &str, lignes: Vec<String>| {
        if !lignes.is_empty() {
            l.push(String::new());
            l.push(ligne_section(titre));
            l.extend(lignes);
        }
    };
    partie(
        tr!("Retiré", "Removed"),
        b.retire.iter().map(|x| format!("  {VERT}✔{RESET} {x}")).collect(),
    );
    partie(
        tr!("Gardé", "Kept"),
        b.garde.iter().map(|x| format!("  • {x}")).collect(),
    );
    partie(
        tr!("Échoué", "Failed"),
        b.echoue
            .iter()
            .map(|(x, raison)| format!("  ✖ {x} : {raison}"))
            .collect(),
    );
    partie(
        tr!("Reste à faire toi-même", "Left for you to do"),
        b.a_faire.iter().map(|x| format!("  → {x}")).collect(),
    );
    l.push(String::new());
    if b.echoue.is_empty() {
        l.push(trf!(
            "  {VERT}✔{RESET} Fait : rien d'autre de Vanguard ne reste ici, sauf ce qui est gardé ou à faire ci-dessus.",
            "  {VERT}✔{RESET} Done: nothing else of Vanguard stays here, except what is kept or left to do above."
        ));
    } else {
        l.push(trf!(
            "  ✖ {} élément(s) non retiré(s) : ils sont dits ci-dessus, avec quoi faire.",
            "  ✖ {} item(s) not removed: they are listed above, with what to do.",
            b.echoue.len()
        ));
    }
    l
}

/// Retire un élément, sans rien demander (montré et accepté avant) ; rend ce qui est fait, ou la raison d'un échec.
fn retirer(e: &Element, garder: Option<&Path>, cle: Option<&Path>) -> Result<String, String> {
    match &e.retrait {
        Retrait::Surveillance => surveillance::retirer().map(|()| e.texte.clone()),
        Retrait::Entretien => crate::entretien::retirer().map(|()| e.texte.clone()),
        Retrait::Sauvegarde(Some(m), _) => {
            if crate::sauvegarde::annuler_sans_question(m) {
                Ok(trf!(
                    "{} (tes copies restent sur le disque)",
                    "{} (your copies stay on the disk)",
                    e.texte
                ))
            } else {
                Err(tr!(
                    "une étape a échoué, sa note est gardée : « vanguard sauvegarde-auto --annuler » pour réessayer",
                    "a step failed, its note is kept: “vanguard auto-backup --undo” to try again"
                )
                .to_string())
            }
        }
        Retrait::Sauvegarde(None, fichiers) => crate::sauvegarde::retirer_sans_note(fichiers).map(|()| e.texte.clone()),
        Retrait::Pieges => match crate::protection::pieges::retirer_sans_question() {
            Err(()) => Err(tr!("leur liste ne se lit plus", "their list can no longer be read").to_string()),
            Ok((restes, _)) if !restes.is_empty() => Err(trf!(
                "{} non retiré(s), dont {}",
                "{} not removed, including {}",
                restes.len(),
                chemin_affichable(&restes[0])
            )),
            Ok((_, preuves)) if !preuves.is_empty() => Ok(trf!(
                "{} ; gardés, preuve d'un passage : {}",
                "{}; kept, evidence of an attack: {}",
                e.texte,
                preuves
                    .iter()
                    .map(|p| chemin_affichable(p))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            Ok(_) => Ok(e.texte.clone()),
        },
        Retrait::Raccourci(p) => {
            let faits = crate::raccourci::retirer(p);
            let echecs: Vec<String> = faits
                .iter()
                .filter_map(|(f, x)| match x {
                    crate::raccourci::Fait::Echec(raison) => Some(format!("{} ({raison})", chemin_affichable(f))),
                    _ => None,
                })
                .collect();
            if !echecs.is_empty() {
                return Err(echecs.join(", "));
            }
            Ok(match faits.iter().find(|(_, x)| *x == crate::raccourci::Fait::Garde) {
                Some((i, _)) => trf!(
                    "{} ; icône gardée ({}) : ce n'est pas celle de Vanguard",
                    "{}; icon kept ({}): it is not Vanguard's",
                    e.texte,
                    chemin_affichable(i)
                ),
                None => e.texte.clone(),
            })
        }
        Retrait::Fichiers(fichiers) => {
            let mut echecs = Vec::new();
            for f in fichiers {
                if let Err(x) = std::fs::remove_file(f)
                    && x.kind() != std::io::ErrorKind::NotFound
                {
                    // Sous Windows, un programme en marche (une passe de la surveillance) ne s'efface pas.
                    let raison = if cfg!(windows) {
                        trf!(
                            "{x} ; la surveillance tourne peut-être encore, réessaie dans une minute",
                            "{x}; monitoring may still be running, try again in a minute"
                        )
                    } else {
                        x.to_string()
                    };
                    echecs.push(format!("{} ({raison})", chemin_affichable(f)));
                }
            }
            // bin/ part s'il est vide ; ce que Vanguard n'y a pas mis le garde.
            if let Some(bin) = fichiers.first().and_then(|f| f.parent()) {
                let _ = std::fs::remove_dir(bin);
            }
            if echecs.is_empty() {
                Ok(e.texte.clone())
            } else {
                Err(echecs.join(", "))
            }
        }
        Retrait::Avant(r) => passage::retirer_reste(r).map(|()| e.texte.clone()),
        Retrait::Dossier(d) => {
            let restes = effacer_dossier(d, garder, cle);
            match restes.first() {
                None => Ok(e.texte.clone()),
                Some((p, raison)) => Err(trf!(
                    "{} élément(s) non effacé(s), dont {} ({raison})",
                    "{} item(s) not erased, including {} ({raison})",
                    restes.len(),
                    chemin_affichable(p)
                )),
            }
        }
    }
}

/// Le second accord pour un dossier de données coché : ce qu'il garde, la quarantaine à remettre d'abord, une
/// sauvegarde du carnet, puis la question. Rend la réponse.
fn accord_donnees(e: &Element, a: &Annulables) -> bool {
    let Retrait::Dossier(d) = &e.retrait else {
        return false;
    };
    let montre = chemin_affichable(d);
    let place = crate::nettoyer::taille_lisible(taille(d));
    println!();
    if e.genre == Genre::DonneesAvant {
        afficher_aligne(
            "  ",
            &trf!(
                "Les données d'une version d'avant ({montre}, {place}) gardent son carnet des appareils et son historique.",
                "The data of an earlier version ({montre}, {place}) keeps its device record and its history."
            ),
            2,
            "",
        );
        return demander(tr!(
            "  Effacer aussi ce dossier pour de bon ? [o/N] : ",
            "  Erase this folder too, for good? [y/N]: "
        ))
        .oui();
    }
    afficher_aligne(
        "  ",
        &trf!(
            "Le dossier de données ({montre}, {place}) garde le carnet des appareils, l'historique des bilans et ce que Vanguard a appris.",
            "The data folder ({montre}, {place}) keeps the device record, the check-up history and what Vanguard has learned."
        ),
        2,
        "",
    );
    let compter = |filtre: &dyn Fn(&std::fs::DirEntry) -> bool, dossier: &Path| {
        std::fs::read_dir(dossier).map_or(0, |l| l.flatten().filter(|x| filtre(x)).count())
    };
    let extensions = compter(&|x| x.path().is_dir(), &d.join("plugins"));
    let traces = compter(&|x| x.file_name().to_string_lossy().starts_with("traces-"), d);
    if extensions + traces > 0 {
        afficher_aligne(
            "  ",
            &trf!(
                "Tes extensions ({extensions}) et les traces collectées ({traces}) y sont aussi.",
                "Your extensions ({extensions}) and the collected traces ({traces}) are there too."
            ),
            2,
            "",
        );
    }
    if a.quarantaine > 0 {
        afficher_aligne(
            "  ",
            &trf!(
                "Il garde aussi {} fichier(s) en quarantaine. Une détection peut se tromper : remets d'abord ceux qui sont à toi, ou garde le dossier.",
                "It also holds {} quarantined file(s). A detection can be wrong: first put back those that are yours, or keep the folder.",
                a.quarantaine
            ),
            2,
            "",
        );
        if demander(tr!(
            "  Ouvrir la quarantaine maintenant ? [o/N] : ",
            "  Open the quarantine now? [y/N]: "
        ))
        .oui()
        {
            crate::protection::quarantaine::menu();
        }
    }
    if a.a_defaire() > 0 {
        afficher_aligne(
            "  ",
            &trf!(
                "Il garde aussi de quoi défaire {} changement(s) : effacé, Vanguard ne pourra plus les défaire.",
                "It also keeps what undoes {} change(s): erased, Vanguard can no longer undo them.",
                a.a_defaire()
            ),
            2,
            "",
        );
    }
    if demander(tr!(
        "\n  Faire d'abord une sauvegarde du carnet des appareils (vanguard sauvegarder) ? [O/n] : ",
        "\n  First back up the device record (vanguard backup)? [Y/n]: "
    ))
    .chars()
    .next()
    .is_none_or(|c| matches!(c, 'o' | 'O' | 'y' | 'Y'))
    {
        crate::donnees::sauvegarder(None);
    }
    demander(tr!(
        "\n  Effacer le dossier de données pour de bon ? [o/N] : ",
        "\n  Erase the data folder for good? [y/N]: "
    ))
    .oui()
}

/// Ce qui reste des changements faits sur le système, pour la fin : avec la commande qui les défait, ou dit perdu si
/// le dossier de données (qui savait les défaire) est effacé.
fn changements_restants(a: &Annulables, donnees_effacees: bool) -> Vec<String> {
    let mut l = Vec::new();
    if donnees_effacees {
        if a.a_defaire() > 0 {
            l.push(trf!(
                "{} changement(s) faits par Vanguard restent sur le système, sans plus de quoi les défaire d'ici.",
                "{} change(s) made by Vanguard stay on the system, with nothing left here to undo them.",
                a.a_defaire()
            ));
        }
        return l;
    }
    if a.optimiser > 0 {
        l.push(trf!(
            "{} réglage(s) d'Optimiser restent : menu Optimiser › Tout remettre comme avant.",
            "{} Optimize setting(s) stay: menu Optimize › Put everything back.",
            a.optimiser
        ));
    }
    if a.blocages > 0 {
        l.push(trf!(
            "{} blocage(s) restent en place : « vanguard blocage annuler » les défait.",
            "{} block(s) stay in place: “vanguard blocking undo” undoes them.",
            a.blocages
        ));
    }
    if a.jeux > 0 {
        l.push(trf!(
            "{} réglage(s) pour jouer restent : menu Gaming › Remettre les réglages comme avant.",
            "{} gaming setting(s) stay: menu Gaming › Put the settings back as before.",
            a.jeux
        ));
    }
    if !a.a_la_main.is_empty() {
        l.push(trf!(
            "{} correction(s) notée(s) : « vanguard changements » les montre ; chacune se défait avec la commande inverse.",
            "{} fix(es) noted: “vanguard changes” shows them; each is undone with the opposite command.",
            a.a_la_main.len()
        ));
    }
    l
}

/// `vanguard desinstaller [--liste]` et le menu Données › Retirer Vanguard de cet ordinateur.
pub fn commande(liste: bool) {
    titre(tr!(
        "Retirer Vanguard de cet ordinateur",
        "Remove Vanguard from this computer"
    ));
    afficher_aligne(
        "  ",
        tr!(
            "Vanguard cherche ce qu'il a posé sur cet ordinateur : il le retrouve, rien n'est noté d'avance. Rien n'est retiré sans ton accord ; la clé USB et ce que Vanguard n'a pas posé ne sont jamais touchés.",
            "Vanguard looks for what it placed on this computer: it finds it, nothing is recorded in advance. Nothing is removed without your consent; the USB key and what Vanguard did not place are never touched."
        ),
        2,
        "",
    );
    let lieux = match Lieux::de_cet_ordinateur() {
        Ok(l) => l,
        Err(e) => {
            afficher_aligne("  ", &e, 4, "");
            return;
        }
    };
    let rec = recenser(&lieux);
    println!();
    for m in rec.pas_a_lui.iter().chain(&rec.non_verifie) {
        afficher_aligne("  • ", m, 4, "");
    }
    if crate::protection::blocage::protection_active() {
        afficher_aligne(
            "  • ",
            tr!(
                "La protection active tourne dans la surveillance horaire et s'arrête avec elle ; son réglage reste dans le dossier de données.",
                "Active protection runs inside the hourly monitoring and stops with it; its setting stays in the data folder."
            ),
            4,
            "",
        );
    }
    if rec.elements.is_empty() {
        afficher_aligne(
            "  ",
            tr!(
                "Vanguard n'a rien posé sur cet ordinateur, ou tout a déjà été retiré.",
                "Vanguard placed nothing on this computer, or everything was already removed."
            ),
            2,
            "",
        );
        for x in &rec.a_faire {
            afficher_aligne("  → ", x, 4, "");
        }
        return;
    }
    if liste {
        section(tr!("Ce que Vanguard a posé ici", "What Vanguard placed here"));
        for (i, e) in rec.elements.iter().enumerate() {
            let coche = if e.coche {
                ""
            } else {
                tr!(" (pas coché d'office)", " (not checked by default)")
            };
            afficher_aligne(
                &format!("  {TOUCHE}{:>2}{RESET} ", i + 1),
                &format!("{}{coche}", e.texte),
                5,
                "",
            );
            afficher_aligne("     → ", &e.precision, 7, GRIS);
            afficher_aligne("       ", &e.detail, 7, GRIS);
        }
        defaire_d_abord(true);
        for x in &rec.a_faire {
            afficher_aligne("  → ", x, 4, "");
        }
        println!();
        afficher_aligne(
            "  ",
            tr!(
                "Rien n'a été retiré : « vanguard desinstaller » sans --liste propose de le faire.",
                "Nothing was removed: “vanguard uninstall” without --list offers to do it."
            ),
            2,
            "",
        );
        return;
    }
    defaire_d_abord(false);
    // Défaire un changement a pu toucher au dossier de données (une note, la quarantaine) : la liste est refaite.
    let rec = recenser(&lieux);
    if rec.elements.is_empty() {
        trp!("  Rien n'a été retiré.", "  Nothing was removed.");
        return;
    }
    let terminal = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mut entete = vec![
        String::new(),
        ligne_titre(tr!("Ce que Vanguard a posé ici", "What Vanguard placed here")),
    ];
    entete.extend(
        envelopper(
            tr!(
                "Coche ce qui doit partir. Le dossier de données n'est pas coché : il garde tes données.",
                "Check what should go. The data folder is not checked: it keeps your data."
            ),
            LARGEUR - 2,
        )
        .into_iter()
        .map(|l| format!("  {GRIS}{l}{RESET}")),
    );
    entete.push(String::new());
    let Some(mut etats) = cocher(&entete, &cases(&rec.elements, terminal)) else {
        trp!("  Rien n'a été retiré.", "  Nothing was removed.");
        return;
    };
    for m in garder_les_dependances(&rec.elements, &mut etats) {
        afficher_aligne("  ", &m, 2, "");
    }
    if !etats.contains(&true) {
        trp!("  Rien n'a été retiré.", "  Nothing was removed.");
        return;
    }
    println!();
    trp!("  Sera retiré :", "  Will be removed:");
    for (e, _) in rec.elements.iter().zip(&etats).filter(|(_, c)| **c) {
        let action = if matches!(e.genre, Genre::Donnees | Genre::DonneesAvant) {
            tr!("effacé après une seconde question", "erased after a second question")
        } else {
            &e.precision
        };
        afficher_aligne("  • ", &format!("{} → {action}", e.texte), 4, "");
    }
    let a = annulables();
    for (i, e) in rec.elements.iter().enumerate() {
        if etats[i] && matches!(e.genre, Genre::Donnees | Genre::DonneesAvant) && !accord_donnees(e, &a) {
            etats[i] = false;
            trp!("  Dossier de données gardé.", "  Data folder kept.");
        }
    }
    if !etats.contains(&true) {
        trp!("  Rien n'a été retiré.", "  Nothing was removed.");
        return;
    }
    if !demander(tr!(
        "\n  Retirer ce qui est coché ? [o/N] : ",
        "\n  Remove what is checked? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'a été retiré.", "  Nothing was removed.");
        return;
    }
    let garder = if cfg!(windows) {
        lieux.programme.as_deref()
    } else {
        None
    };
    let mut bilan = Bilan::default();
    let mut donnees_touchees = false;
    println!();
    for (e, &coche) in rec.elements.iter().zip(&etats) {
        if !coche {
            bilan.garde.push(e.texte.clone());
            continue;
        }
        donnees_touchees |= e.genre == Genre::Donnees;
        match retirer(e, garder, lieux.cle.as_deref()) {
            Ok(fait) => {
                afficher_aligne(&format!("  {VERT}✔{RESET} "), &e.texte, 4, "");
                bilan.retire.push(fait);
            }
            Err(raison) => {
                afficher_aligne("  ✖ ", &format!("{} : {raison}", e.texte), 4, "");
                bilan.echoue.push((e.texte.clone(), raison));
            }
        }
    }
    bilan.garde.extend(rec.pas_a_lui.iter().cloned());
    bilan.a_faire.extend(rec.a_faire.iter().cloned());
    bilan.a_faire.extend(changements_restants(&a, donnees_touchees));
    for l in rediger_bilan(&bilan) {
        imprimer(&l);
    }
    if donnees_touchees {
        // Revenir au menu réécrirait des fichiers (état, journal) dans le dossier qu'on vient d'effacer.
        println!();
        trp!(
            "  Vanguard se ferme : rouvert, il recréerait son dossier de données.",
            "  Vanguard closes: reopened, it would create its data folder again."
        );
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn racine(nom: &str) -> PathBuf {
        let d = crate::reseau::dossier_local().join(format!("desinstaller-{nom}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ecrire(p: &Path, texte: impl AsRef<[u8]>) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, texte).unwrap();
    }

    /// Un ordinateur jetable où Vanguard, et une version d'avant, ont tout posé, avec à côté ce qui n'est pas à eux.
    fn ordinateur(nom: &str) -> (PathBuf, Lieux) {
        let r = racine(nom);
        let l = Lieux::jetable(&r);
        let unites = &l.unites[0];
        let bin = l.donnees.join("bin");
        let exe = bin.join(crate::mise_a_jour::NOM);
        let (service, timer) = surveillance::unites_systemd(&exe.display().to_string());
        ecrire(&unites.join("vanguard-surveillance.service"), service);
        ecrire(&unites.join("vanguard-surveillance.timer"), timer);
        ecrire(&unites.join("vanguard-entretien.timer"), "[Timer]\n");
        ecrire(&l.unites[1].join(crate::sauvegarde::TIMER), "[Timer]\n");
        ecrire(
            &l.unites[1].join(crate::sauvegarde::SERVICE),
            "ExecStart=\"/usr/bin/rsync\" -a\n",
        );
        // Une version d'avant : sa minuterie et sa copie du programme.
        ecrire(
            &unites.join(format!("{}.timer", passage::ancien("vanguard-surveillance"))),
            "[Timer]\n",
        );
        ecrire(
            &bin.join(format!(
                "{}{}",
                passage::ancien("vanguard"),
                std::env::consts::EXE_SUFFIX
            )),
            "avant",
        );
        // Un agent launchd, le raccourci marqué et son icône.
        let agent = l
            .agents
            .as_ref()
            .unwrap()
            .join(format!("{}.plist", surveillance::AGENT_MACOS));
        ecrire(&agent, "<?xml version=\"1.0\"?><plist><dict></dict></plist>");
        let raccourci = l.raccourci.clone().unwrap();
        ecrire(
            &raccourci,
            format!(
                "[Desktop Entry]\nExec=\"{}\"\n{}\n",
                exe.display(),
                crate::raccourci::MARQUE
            ),
        );
        ecrire(
            &crate::raccourci::icone(&raccourci).unwrap(),
            include_bytes!("../assets/icones/vanguard-128.png"),
        );
        ecrire(&exe, "programme");
        ecrire(&bin.join(format!("{}.ancien", crate::mise_a_jour::NOM)), "programme");
        // Des données, une quarantaine, et l'ancien dossier de données.
        ecrire(&l.donnees.join("appareils.json"), "{}");
        ecrire(&l.donnees.join("quarantaine/x"), "x");
        ecrire(
            &l.donnees
                .with_file_name(passage::ancien("vanguard"))
                .join("historique.json"),
            "[]",
        );
        // Ce qui n'est pas à Vanguard : une autre minuterie, un autre .desktop, un fichier de bin/, une clé.
        ecrire(&unites.join("autre.timer"), "[Timer]\n");
        ecrire(
            &raccourci.with_file_name("Autre.desktop"),
            "[Desktop Entry]\nExec=autre\n",
        );
        ecrire(&bin.join("mon-outil"), "à moi");
        ecrire(&r.join("cle/vanguard"), "programme de la clé");
        (r, l)
    }

    fn genres(rec: &Recensement) -> Vec<Genre> {
        rec.elements.iter().map(|e| e.genre).collect()
    }

    #[test]
    fn recensement_d_un_ordinateur_jetable() {
        let (r, mut l) = ordinateur("recensement");
        let rec = recenser(&l);
        assert_eq!(
            genres(&rec),
            [
                Genre::Surveillance,
                Genre::Entretien,
                Genre::Sauvegarde,
                Genre::Avant,
                Genre::Raccourci,
                Genre::Programme,
                Genre::DonneesAvant,
                Genre::Donnees
            ]
        );
        let tout = format!("{:?}", rec.elements);
        for etranger in ["autre.timer", "Autre.desktop", "mon-outil", "cle/vanguard"] {
            assert!(!tout.contains(etranger), "{etranger} listé : {tout}");
        }
        // La surveillance lance la copie de bin/ ; le raccourci aussi ; l'icône part avec le raccourci.
        let exe = l.donnees.join("bin").join(crate::mise_a_jour::NOM);
        assert_eq!(rec.elements[0].lance.as_deref(), Some(exe.as_path()));
        assert_eq!(rec.elements[4].lance.as_deref(), Some(exe.as_path()));
        assert!(rec.elements[4].precision.contains("icône") || rec.elements[4].precision.contains("icon"));
        let Retrait::Fichiers(copies) = &rec.elements[5].retrait else {
            panic!("{:?}", rec.elements[5]);
        };
        assert_eq!(copies.len(), 3, "{copies:?}");
        assert!(matches!(
            &rec.elements[3].retrait,
            Retrait::Avant(Reste::Minuterie { .. })
        ));
        // Le programme en marche ailleurs : gardé, dit ; sur la clé : jamais touché, dit.
        l.programme = Some(r.join("ailleurs/vanguard"));
        assert!(recenser(&l).pas_a_lui.iter().any(|m| m.contains("ailleurs")));
        l.programme = Some(r.join("cle/vanguard"));
        let sur_la_cle = recenser(&l);
        assert!(
            sur_la_cle.pas_a_lui.iter().any(|m| m.contains("cle")),
            "{:?}",
            sur_la_cle.pas_a_lui
        );
        // Des données posées sur la clé (un dossier de données qui y mène) : écartées.
        l.donnees = r.join("cle/donnees/vanguard");
        std::fs::create_dir_all(&l.donnees).unwrap();
        assert!(!genres(&recenser(&l)).contains(&Genre::Donnees));
        // Des tâches de Windows lues : celle d'aujourd'hui, celle d'avant ; une autre est ignorée.
        let mut w = Lieux::jetable(&racine("taches"));
        w.taches = Some(
            [
                surveillance::TACHE_WINDOWS.to_string(),
                passage::taches_d_avant()[1].clone(),
                "Mise à jour de MonAppli".to_string(),
            ]
            .into_iter()
            .map(|nom| TacheLue {
                nom,
                programme: r"C:\Users\alice\AppData\Local\vanguard\bin\vanguard.exe".into(),
                active: true,
            })
            .collect(),
        );
        let rec = recenser(&w);
        assert_eq!(genres(&rec), [Genre::Surveillance, Genre::Avant]);
        assert!(!format!("{:?}", rec.elements).contains("MonAppli"));
        // Le planificateur non lu : dit, jamais compté comme absent.
        w.taches = None;
        assert_ne!(recenser(&w).non_verifie, Vec::<String>::new());
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn donnees_jamais_cochees_par_defaut() {
        let (r, l) = ordinateur("coches");
        let rec = recenser(&l);
        for e in &rec.elements {
            assert_eq!(
                e.coche,
                !matches!(e.genre, Genre::Donnees | Genre::DonneesAvant),
                "{e:?}"
            );
        }
        assert!(cases(&rec.elements, false).iter().all(|c| !c.cochee));
        let avec = cases(&rec.elements, true);
        assert_eq!(
            avec.iter().map(|c| c.cochee).collect::<Vec<_>>(),
            rec.elements.iter().map(|e| e.coche).collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn copie_gardee_si_une_tache_gardee_la_lance() {
        let (r, l) = ordinateur("dependances");
        let rec = recenser(&l);
        let mut etats: Vec<bool> = rec.elements.iter().map(|e| e.coche).collect();
        // Tout ce qui est coché part : rien à garder.
        assert_eq!(garder_les_dependances(&rec.elements, &mut etats), Vec::<String>::new());
        // La surveillance gardée : la copie qu'elle lance reste, et c'est dit.
        etats[0] = false;
        let messages = garder_les_dependances(&rec.elements, &mut etats);
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(messages[0].contains(&rec.elements[0].texte));
        assert!(!etats[5]);
        let _ = std::fs::remove_dir_all(r);
    }

    #[cfg(unix)]
    #[test]
    fn effacer_sans_suivre_les_liens() {
        let r = racine("liens");
        let d = r.join("donnees");
        let dehors = r.join("dehors");
        ecrire(&dehors.join("garde.txt"), "à moi");
        ecrire(&d.join("a/b.txt"), "b");
        std::os::unix::fs::symlink(dehors.join("garde.txt"), d.join("lien-fichier")).unwrap();
        std::os::unix::fs::symlink(&dehors, d.join("a/lien-dossier")).unwrap();
        let en_marche = d.join("bin/vanguard");
        ecrire(&en_marche, "x");
        let restes = effacer_dossier(&d, Some(&en_marche), None);
        // Les cibles des liens restent intactes ; le programme gardé reste, et c'est dit.
        assert_eq!(std::fs::read_to_string(dehors.join("garde.txt")).unwrap(), "à moi");
        assert!(en_marche.is_file());
        assert_eq!(restes.len(), 1, "{restes:?}");
        assert_eq!(restes[0].0, en_marche);
        assert!(!d.join("a").exists() && !d.join("lien-fichier").exists());
        // Sans rien à garder : tout part.
        assert_eq!(effacer_dossier(&d, None, None), Vec::new());
        assert!(!d.exists());
        // Sur la clé, ou un chemin relatif : refusé, rien n'est touché.
        let cle = r.join("cle");
        ecrire(&cle.join("donnees/x"), "x");
        assert_eq!(effacer_dossier(&cle.join("donnees"), None, Some(&cle)).len(), 1);
        assert!(cle.join("donnees/x").is_file());
        assert_eq!(effacer_dossier(Path::new("relatif"), None, None).len(), 1);
        let _ = std::fs::remove_dir_all(r);
    }

    #[cfg(windows)]
    #[test]
    fn effacer_un_fichier_en_lecture_seule() {
        let r = racine("lecture-seule");
        let f = r.join("quarantaine/x.exe.vanguard-quarantaine");
        ecrire(&f, "x");
        let mut droits = std::fs::metadata(&f).unwrap().permissions();
        droits.set_readonly(true);
        std::fs::set_permissions(&f, droits).unwrap();
        assert_eq!(effacer_dossier(&r, None, None), Vec::new());
        assert!(!r.exists());
    }

    #[test]
    fn un_echec_n_est_jamais_compte_comme_fait() {
        let b = Bilan {
            retire: vec!["Raccourci".into()],
            garde: vec!["Dossier de données".into()],
            echoue: vec![("Surveillance horaire".into(), "systemctl".into())],
            a_faire: vec!["vanguard blocage annuler".into()],
        };
        let texte = rediger_bilan(&b).join("\n");
        let retire = texte.split(tr!("Gardé", "Kept")).next().unwrap();
        assert!(!retire.contains("Surveillance horaire"), "{texte}");
        assert!(texte.contains("✖ Surveillance horaire"), "{texte}");
        assert!(!texte.contains("Fait :") && !texte.contains("Done:"), "{texte}");
        assert!(texte.contains("1 "), "{texte}");
        let tout_bon = Bilan {
            echoue: Vec::new(),
            ..b
        };
        let texte = rediger_bilan(&tout_bon).join("\n");
        assert!(texte.contains("Fait :") || texte.contains("Done:"), "{texte}");
    }

    #[test]
    fn messages_dans_la_largeur() {
        let larges = crate::gaming::tests::textes_trop_larges(include_str!("desinstaller.rs"));
        assert_eq!(larges, Vec::<String>::new());
        let (r, l) = ordinateur("largeur");
        for e in recenser(&l).elements {
            assert!(largeur_affichee(&e.precision) <= 33, "{}", e.precision);
            assert!(largeur_affichee(&e.texte) <= 44, "{}", e.texte);
        }
        for (texte, precision) in entrees_annulables(&Annulables {
            optimiser: 120,
            blocages: 120,
            jeux: 120,
            quarantaine: 120,
            a_la_main: Vec::new(),
        }) {
            assert!(largeur_affichee(&precision) <= 33 && largeur_affichee(&texte) <= 44);
        }
        let _ = std::fs::remove_dir_all(r);
    }
}
