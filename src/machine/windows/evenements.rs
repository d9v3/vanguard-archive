//! Journaux d'événements de Windows, les 7 derniers jours : rafales d'échecs de connexion (quelqu'un essaie des mots
//! de passe), journal de sécurité effacé, comptes créés, services installés. Une seule lecture PowerShell, bornée en
//! nombre d'événements et en temps. L'effacement des autres journaux (événement 104 du journal Système) est déjà dit
//! par la règle commune des journaux (journaux.rs) : pas deux fois.

use std::collections::HashMap;

use chrono::{NaiveDateTime, TimeDelta};

use super::persistance::lancement_suspect;
use super::portes::INTERPRETES;
use super::*;
use crate::commande::decouper_commande;
use crate::machine::regles::{Os, regle};
use crate::ui::{affichable, couper};

const JOURS: u32 = 7;
/// À partir de tant d'échecs de connexion en une heure, ce n'est plus une faute de frappe.
const RAFALE: usize = 20;
/// Les échecs lus au plus : assez pour voir une rafale, sans faire durer le bilan quand un robot en envoie des
/// milliers par jour.
const MAX_ECHECS: usize = 2000;

/// Une lecture d'un journal : sa section (ECH, SEC, SRV), le journal, les événements voulus, combien au plus.
struct Lecture {
    section: &'static str,
    journal: &'static str,
    evenements: &'static str,
    max: usize,
}

/// ECH (4625, échecs de connexion), SEC (1102 journal de sécurité effacé ; 4720 compte créé) : journal Security, lisible
/// seulement en administrateur. SRV (7045 service installé) : journal System.
const LECTURES: [Lecture; 3] = [
    Lecture {
        section: "ECH",
        journal: "Security",
        evenements: "EventID=4625",
        max: MAX_ECHECS,
    },
    Lecture {
        section: "SEC",
        journal: "Security",
        evenements: "EventID=1102 or EventID=4720",
        max: 100,
    },
    Lecture {
        section: "SRV",
        journal: "System",
        evenements: "EventID=7045",
        max: 200,
    },
];

/// Un événement lu dans son XML (celui que montre l'Observateur d'événements) : son numéro, sa date (UTC, ISO 8601) et
/// ses valeurs dans l'ordre (EventData/Data, ou les champs sous UserData pour le 1102) : les « Properties » que
/// Get-WinEvent donnait. `None` : XML illisible.
fn lire_xml(xml: &str) -> Option<(u32, String, Vec<String>)> {
    lire_xml_nomme(xml).map(|(id, date, valeurs, _)| (id, date, valeurs))
}

/// Comme `lire_xml`, avec le nom de chaque valeur (l'attribut Name d'un Data, ou le nom du champ sous UserData) :
/// des événements dont les champs changent de place d'un numéro à l'autre (Diagnostics-Performance).
fn lire_xml_nomme(xml: &str) -> Option<(u32, String, Vec<String>, Vec<String>)> {
    use quick_xml::events::Event;
    let mut lecteur = quick_xml::Reader::from_str(xml);
    let mut chemin: Vec<Vec<u8>> = Vec::new();
    let (mut id, mut date, mut valeurs, mut noms) = (String::new(), String::new(), Vec::new(), Vec::new());
    // La valeur en cours de lecture, et la profondeur de son élément.
    let mut valeur: Option<(usize, String)> = None;
    loop {
        let evenement = lecteur.read_event().ok()?;
        let (ouvert, vide) = match &evenement {
            Event::Start(e) => (Some(e), false),
            Event::Empty(e) => (Some(e), true),
            _ => (None, false),
        };
        if let Some(e) = ouvert {
            let nom = e.local_name().as_ref().as_bytes().to_vec();
            if nom == b"TimeCreated"
                && let Some(a) = e.try_get_attribute("SystemTime").ok().flatten()
            {
                date = a
                    .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    .ok()?
                    .into_owned();
            }
            let dans = |n: &[u8]| chemin.last().is_some_and(|p| p == n);
            // Une valeur : un Data sous EventData, ou un champ sous l'élément unique de UserData.
            let est_valeur =
                (dans(b"EventData") && nom == b"Data") || chemin.len() >= 2 && chemin[chemin.len() - 2] == b"UserData";
            if est_valeur && valeur.is_none() {
                let attribut = e.try_get_attribute("Name").ok().flatten();
                noms.push(match attribut {
                    Some(a) => a
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .ok()?
                        .into_owned(),
                    None => String::from_utf8_lossy(&nom).into_owned(),
                });
                if vide {
                    valeurs.push(String::new());
                } else {
                    valeur = Some((chemin.len(), String::new()));
                }
            }
            if !vide {
                chemin.push(nom);
            }
            continue;
        }
        match evenement {
            Event::Text(t) => {
                let texte = t.xml10_content();
                if let Some((_, v)) = &mut valeur {
                    v.push_str(&texte);
                } else if chemin.last().is_some_and(|n| n == b"EventID") {
                    id.push_str(&texte);
                }
            }
            Event::GeneralRef(r) => {
                let c = match r.as_ref() {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    _ => r.resolve_char_ref().ok().flatten(),
                };
                if let (Some((_, v)), Some(c)) = (&mut valeur, c) {
                    v.push(c);
                }
            }
            Event::End(_) => {
                chemin.pop();
                if valeur
                    .as_ref()
                    .is_some_and(|(profondeur, _)| *profondeur == chemin.len())
                {
                    valeurs.extend(valeur.take().map(|(_, v)| v));
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Some((id.trim().parse().ok()?, date, valeurs, noms))
}

/// Une valeur sur une ligne, sans le séparateur des champs.
fn champ(v: Option<&String>) -> String {
    let v = v.map_or("", String::as_str);
    v.split(['\r', '\n', '|'])
        .filter(|m| !m.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

/// La ligne d'une section pour un événement, telle que les jugements la lisent. `date` : déjà à l'heure locale.
fn ligne(section: &str, id: u32, date: &str, p: &[String]) -> Option<String> {
    Some(match (section, id) {
        // Type de connexion, adresse d'origine, compte visé.
        ("ECH", 4625) => format!("{date}|{}|{}|{}", champ(p.get(10)), champ(p.get(19)), champ(p.get(5))),
        ("SEC", 1102) => format!("1102|{date}|{}", champ(p.get(1))),
        // Auteur, nouveau compte.
        ("SEC", 4720) => format!("4720|{date}|{}|{}", champ(p.get(4)), champ(p.first())),
        // Nom et programme du service.
        ("SRV", 7045) => format!("{date}|{}|{}", champ(p.first()), champ(p.get(1))),
        _ => return None,
    })
}

/// « 2026-10-20T13:46:40.1234567Z » → « 2026-10-20 09:46 » à l'heure de l'ordinateur, comme l'Observateur
/// d'événements la montre.
pub(crate) fn date_locale(systeme: &str) -> Option<String> {
    let utc = chrono::DateTime::parse_from_rfc3339(systeme).ok()?;
    Some(utc.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
}

#[link(name = "wevtapi")]
unsafe extern "system" {
    fn EvtQuery(session: *mut c_void, chemin: *const u16, requete: *const u16, drapeaux: u32) -> *mut c_void;
    fn EvtNext(
        resultats: *mut c_void,
        taille: u32,
        evenements: *mut *mut c_void,
        delai: u32,
        drapeaux: u32,
        rendus: *mut u32,
    ) -> i32;
    fn EvtRender(
        contexte: *mut c_void,
        fragment: *mut c_void,
        drapeaux: u32,
        taille: u32,
        tampon: *mut c_void,
        utilise: *mut u32,
        proprietes: *mut u32,
    ) -> i32;
    fn EvtClose(objet: *mut c_void) -> i32;
}

use std::ffi::c_void;

/// Le XML d'un événement ; `None` s'il ne se rend pas.
fn rendre(evenement: *mut c_void) -> Option<String> {
    const XML: u32 = 1;
    let mut utilise = 0u32;
    let mut proprietes = 0u32;
    // SAFETY : un premier appel sans tampon donne la taille en octets (refus attendu) ; le second écrit au plus
    // `taille` octets dans `tampon`, qui les a, alignés pour des caractères UTF-16.
    unsafe {
        EvtRender(
            std::ptr::null_mut(),
            evenement,
            XML,
            0,
            std::ptr::null_mut(),
            &raw mut utilise,
            &raw mut proprietes,
        );
        let mut tampon = vec![0u16; usize::try_from(utilise.div_ceil(2)).ok()?];
        let taille = u32::try_from(tampon.len() * 2).ok()?;
        if EvtRender(
            std::ptr::null_mut(),
            evenement,
            XML,
            taille,
            tampon.as_mut_ptr().cast(),
            &raw mut utilise,
            &raw mut proprietes,
        ) == 0
        {
            return None;
        }
        let fin = tampon.iter().position(|&c| c == 0).unwrap_or(tampon.len());
        Some(String::from_utf16_lossy(&tampon[..fin]))
    }
}

/// Les lignes d'une lecture, les plus récentes d'abord, ou `None` si le journal refuse (droits, journal absent, délai
/// dépassé). Aucun événement : une liste vide, pas une erreur.
fn lire(lecture: &Lecture, fin: std::time::Instant) -> Option<Vec<String>> {
    let requete = format!(
        "*[System[({}) and TimeCreated[timediff(@SystemTime) <= {}]]]",
        lecture.evenements,
        u64::from(JOURS) * 86_400_000
    );
    parcourir(lecture.journal, &requete, lecture.max, fin, |id, date, valeurs| {
        ligne(lecture.section, id, &date_locale(date).unwrap_or_default(), valeurs)
    })
}

/// Les événements d'un journal qui répondent à une requête XPath, les plus récents d'abord : chacun rendu en XML, lu,
/// puis changé en ligne par `faire` (rien : passé), `max` lignes au plus. `None` si le journal refuse (droits,
/// journal absent) ou que le délai `fin` est dépassé ; aucun événement : une liste vide, pas une erreur.
pub(crate) fn parcourir(
    journal: &str,
    requete: &str,
    max: usize,
    fin: std::time::Instant,
    mut faire: impl FnMut(u32, &str, &[String]) -> Option<String>,
) -> Option<Vec<String>> {
    parcourir_xml(journal, requete, max, fin, |xml| {
        let (id, date, valeurs) = lire_xml(xml)?;
        faire(id, &date, &valeurs)
    })
}

/// Comme `parcourir`, les valeurs données avec leur nom : `faire` reçoit (numéro, date, [(nom, valeur)]).
pub(crate) fn parcourir_nommes(
    journal: &str,
    requete: &str,
    max: usize,
    fin: std::time::Instant,
    mut faire: impl FnMut(u32, &str, &[(String, String)]) -> Option<String>,
) -> Option<Vec<String>> {
    parcourir_xml(journal, requete, max, fin, |xml| {
        let (id, date, valeurs, noms) = lire_xml_nomme(xml)?;
        let paires: Vec<(String, String)> = noms.into_iter().zip(valeurs).collect();
        faire(id, &date, &paires)
    })
}

fn parcourir_xml(
    journal: &str,
    requete: &str,
    max: usize,
    fin: std::time::Instant,
    mut faire: impl FnMut(&str) -> Option<String>,
) -> Option<Vec<String>> {
    const CHEMIN_DU_JOURNAL: u32 = 0x1;
    const PLUS_RECENTS_D_ABORD: u32 = 0x200;
    const PLUS_RIEN: i32 = 259;
    let large = |t: &str| t.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (journal, requete) = (large(journal), large(requete));
    let mut lignes = Vec::new();
    // SAFETY : les chaînes sont terminées par un zéro et vivent pendant l'appel ; la requête (nulle : refus, vérifié) et
    // chaque événement rendu par EvtNext sont fermés une seule fois, ici. EvtNext écrit au plus `lot.len()` poignées.
    unsafe {
        let resultats = EvtQuery(
            std::ptr::null_mut(),
            journal.as_ptr(),
            requete.as_ptr(),
            CHEMIN_DU_JOURNAL | PLUS_RECENTS_D_ABORD,
        );
        if resultats.is_null() {
            return None;
        }
        let mut lot = [std::ptr::null_mut::<c_void>(); 64];
        let mut complet = true;
        while lignes.len() < max {
            let reste = fin.saturating_duration_since(std::time::Instant::now());
            if reste.is_zero() {
                complet = false;
                break;
            }
            let mut rendus = 0u32;
            let delai = u32::try_from(reste.as_millis()).unwrap_or(u32::MAX);
            if EvtNext(resultats, 64, lot.as_mut_ptr(), delai, 0, &raw mut rendus) == 0 {
                complet = std::io::Error::last_os_error().raw_os_error() == Some(PLUS_RIEN);
                break;
            }
            for &evenement in lot.iter().take(usize::try_from(rendus).unwrap_or(0)) {
                if lignes.len() < max
                    && let Some(l) = rendre(evenement).as_deref().and_then(&mut faire)
                {
                    lignes.push(l);
                }
                EvtClose(evenement);
            }
        }
        EvtClose(resultats);
        complet.then_some(lignes)
    }
}

/// Les journaux lus par les fonctions de Windows (wevtapi), sans PowerShell, dans la forme que `juger_evenements` lit :
/// une section par lecture (« NOM|… », puis « NOM_FIN ») ; une section sans fin quand le journal a refusé. Bornée à
/// 30 s en tout : au-delà, le service des journaux est bloqué.
fn lire_journaux() -> String {
    use std::fmt::Write as _;
    let fin = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut texte = format!(
        "ADM|{}\nADM_FIN\n",
        if super::processus::eleve() { "True" } else { "False" }
    );
    for lecture in &LECTURES {
        if let Some(lignes) = lire(lecture, fin) {
            for l in lignes {
                let _ = writeln!(texte, "{}|{l}", lecture.section);
            }
            let _ = writeln!(texte, "{}_FIN", lecture.section);
        }
    }
    texte
}

/// Un échec de connexion (4625).
struct Echec {
    quand: NaiveDateTime,
    /// Par le réseau : partage ou connexion réseau (3), mot de passe en clair (8), Bureau à distance (10).
    reseau: bool,
    adresse: String,
    compte: String,
}

fn date(texte: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(texte.trim(), "%Y-%m-%d %H:%M").ok()
}

fn lire_echecs(lignes: &[&str]) -> Vec<Echec> {
    lignes
        .iter()
        .filter_map(|l| {
            let c: Vec<&str> = l.splitn(4, '|').collect();
            let [quand, type_, adresse, compte] = c[..] else {
                return None;
            };
            Some(Echec {
                quand: date(quand)?,
                reseau: matches!(type_.trim(), "3" | "8" | "10"),
                adresse: adresse.trim().to_string(),
                compte: compte.trim().to_string(),
            })
        })
        .collect()
}

/// Le plus grand nombre d'événements tombés dans une même heure (fenêtre glissante).
fn plus_forte_rafale(mut heures: Vec<NaiveDateTime>) -> usize {
    heures.sort_unstable();
    let (mut debut, mut plus) = (0, 0);
    for fin in 0..heures.len() {
        while heures[fin] - heures[debut] >= TimeDelta::hours(1) {
            debut += 1;
        }
        plus = plus.max(fin - debut + 1);
    }
    plus
}

/// Les `n` valeurs les plus fréquentes, montrées inoffensives, avec leur nombre : « 203.0.113.5 (40) ». Les valeurs
/// vides, « - » et la machine elle-même ne disent rien de l'origine.
fn plus_frequents<'a>(valeurs: impl Iterator<Item = &'a str>, n: usize) -> Vec<String> {
    let mut nombres: HashMap<&str, usize> = HashMap::new();
    for v in valeurs {
        if !matches!(v, "" | "-" | "127.0.0.1" | "::1") {
            *nombres.entry(v).or_default() += 1;
        }
    }
    let mut tries: Vec<(&str, usize)> = nombres.into_iter().collect();
    tries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    tries
        .into_iter()
        .take(n)
        .map(|(v, k)| format!("{} ({k})", affichable(v)))
        .collect()
}

/// Tous les échecs par le réseau viennent-ils d'une seule adresse du réseau local, pour un seul compte ? C'est le
/// portrait d'un appareil de la maison qui répète un mot de passe périmé, pas celui d'une attaque (plusieurs origines,
/// plusieurs comptes, souvent depuis Internet). L'adresse et le compte, sinon rien.
fn appareil_qui_insiste(echecs: &[Echec]) -> Option<(String, String)> {
    let mut reseau = echecs.iter().filter(|e| e.reseau);
    let premier = reseau.next()?;
    let locale = match premier.adresse.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(a) => a.is_private() || a.is_link_local(),
        std::net::IpAddr::V6(a) => (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80,
    };
    let meme = |e: &&Echec| e.adresse == premier.adresse && e.compte.eq_ignore_ascii_case(&premier.compte);
    (locale && !premier.compte.is_empty() && reseau.all(|e| meme(&e)))
        .then(|| (premier.adresse.clone(), premier.compte.clone()))
}

fn juger_echecs(echecs: &[Echec]) -> Constat {
    let total = echecs.len();
    if total == 0 {
        return ok(
            "Comptes",
            trf!(
                "Aucun échec de connexion ces {JOURS} derniers jours.",
                "No failed sign-in over the last {JOURS} days."
            ),
        );
    }
    let rafale_reseau = plus_forte_rafale(echecs.iter().filter(|e| e.reseau).map(|e| e.quand).collect());
    let rafale = plus_forte_rafale(echecs.iter().map(|e| e.quand).collect());
    if rafale < RAFALE {
        return ok(
            "Comptes",
            trf!(
                "{total} échec(s) de connexion ces {JOURS} derniers jours, sans rafale.",
                "{total} failed sign-in(s) over the last {JOURS} days, no burst."
            ),
        );
    }
    let total = if total >= MAX_ECHECS {
        trf!("au moins {total}", "at least {total}")
    } else {
        total.to_string()
    };
    let comptes = plus_frequents(echecs.iter().map(|e| e.compte.as_str()), 3).join(", ");
    if rafale_reseau >= RAFALE
        && let Some((adresse, compte)) = appareil_qui_insiste(echecs)
    {
        return alerte(
            "Comptes",
            Niveau::Moyen,
            trf!(
                "{rafale_reseau} échecs de connexion en une heure, tous depuis {} sur le réseau local et pour le seul compte {} ({total} en {JOURS} jours) : sans doute un appareil de la maison (NAS, imprimante, autre ordinateur) qui garde un vieux mot de passe pour un partage. Si tu ne le reconnais pas, c'est peut-être quelqu'un sur ton réseau.",
                "{rafale_reseau} failed sign-ins within an hour, all from {} on the local network and for the single account {} ({total} in {JOURS} days): most likely a device at home (NAS, printer, another computer) keeping an old password for a share. If you do not recognize it, it may be someone on your network.",
                affichable(&adresse),
                affichable(&compte)
            ),
        )
        .manuel(
            tr!(
                "Sur cet appareil, remets le mot de passe actuel du partage, ou retire le partage enregistré",
                "On that device, enter the share's current password again, or remove the saved share"
            ),
            &[],
        );
    }
    if rafale_reseau >= RAFALE {
        let origines = plus_frequents(echecs.iter().filter(|e| e.reseau).map(|e| e.adresse.as_str()), 3);
        let origines = if origines.is_empty() {
            tr!("non notées par Windows", "not recorded by Windows").to_string()
        } else {
            origines.join(", ")
        };
        return alerte(
            "Comptes",
            Niveau::Eleve,
            trf!(
                "{rafale_reseau} échecs de connexion en une heure depuis le réseau (Bureau à distance, partages), {total} en {JOURS} jours : quelqu'un essaie des mots de passe. Origines : {origines} ; comptes visés : {comptes}.",
                "{rafale_reseau} failed sign-ins within an hour from the network (Remote Desktop, shares), {total} in {JOURS} days: someone is trying passwords. Sources: {origines}; accounts targeted: {comptes}."
            ),
        )
        .manuel(
            tr!(
                "Si ce n'est pas toi : des mots de passe longs, le blocage après des essais ratés, et le Bureau à distance coupé s'il ne sert pas",
                "If it is not you: long passwords, lockout after failed attempts, and Remote Desktop turned off if it is not used"
            ),
            &["Start-Process ms-settings:remotedesktop"],
        );
    }
    alerte(
        "Comptes",
        Niveau::Moyen,
        trf!(
            "{rafale} échecs de connexion en une heure sur cet ordinateur, {total} en {JOURS} jours : quelqu'un a essayé des mots de passe au clavier, ou un programme garde un mot de passe périmé. Comptes visés : {comptes}.",
            "{rafale} failed sign-ins within an hour on this computer, {total} in {JOURS} days: someone tried passwords at the keyboard, or a program keeps an outdated password. Accounts targeted: {comptes}."
        ),
    )
}

/// Lignes « 1102|date|compte » et « 4720|date|auteur|nouveau compte », les plus récentes d'abord.
fn juger_securite(lignes: &[&str]) -> Vec<Constat> {
    let mut constats = Vec::new();
    let effacements: Vec<(&str, &str)> = lignes
        .iter()
        .filter_map(|l| l.strip_prefix("1102|")?.split_once('|'))
        .collect();
    if let Some((quand, compte)) = effacements.first() {
        let (quand, compte) = (affichable(quand), affichable(compte));
        let autres = effacements.len() - 1;
        let autres = if autres > 0 {
            trf!(" et {autres} autre(s) fois", " and {autres} more time(s)")
        } else {
            String::new()
        };
        constats.push(alerte(
            "Journaux",
            Niveau::Eleve,
            trf!(
                "Le journal de sécurité a été effacé le {quand} (compte {compte}){autres} : si ce n'est pas toi, quelqu'un a pu effacer les traces d'une intrusion.",
                "The security log was cleared on {quand} (account {compte}){autres}: if it was not you, someone may have erased the traces of an intrusion."
            ),
        ));
    }
    let crees: Vec<String> = lignes
        .iter()
        .filter_map(|l| {
            let c: Vec<&str> = l.strip_prefix("4720|")?.splitn(3, '|').collect();
            let [quand, auteur, nom] = c[..] else {
                return None;
            };
            let (quand, auteur, nom) = (affichable(quand), affichable(auteur), affichable(nom));
            Some(trf!(
                "« {nom} » le {quand} (par {auteur})",
                "“{nom}” on {quand} (by {auteur})"
            ))
        })
        .collect();
    if !crees.is_empty() {
        constats.push(alerte(
            "Comptes",
            Niveau::Info,
            trf!(
                "Compte(s) créé(s) ces {JOURS} derniers jours : {}. Si l'un t'est inconnu, quelqu'un s'est fait une entrée.",
                "Account(s) created over the last {JOURS} days: {}. If one is unknown to you, someone made themselves a way in.",
                resume(&crees, 5, ", ")
            ),
        ));
    }
    constats
}

/// Pourquoi ce service installé ressemble à une attaque, avec la gravité, ou `None`. Un service qui lance un
/// interpréteur de commandes (cmd, PowerShell…) est la façon de faire des outils d'attaque qui s'installent à distance ;
/// un pilote ou un service rangé dans un dossier temporaire ou du profil est moins sûr : quelques outils de diagnostic
/// du matériel posent ainsi leur pilote le temps d'une lecture.
fn service_suspect(chemin: &str) -> Option<(Niveau, &'static str)> {
    let (exe, args) = decouper_commande(chemin);
    let bas = chemin.to_lowercase().replace('/', "\\");
    let exe_bas = exe.trim().trim_matches('"').to_lowercase().replace('/', "\\");
    let programme = exe_bas.rsplit('\\').next().unwrap_or(&exe_bas).trim_end_matches(".exe");
    if bas.contains("%comspec%") || INTERPRETES.contains(&programme) {
        return Some((
            Niveau::Eleve,
            lancement_suspect(&exe, &args).unwrap_or(tr!(
                "le service lance un interpréteur de commandes, comme les outils d'attaque qui s'installent à distance",
                "the service runs a command interpreter, like attack tools that install themselves remotely"
            )),
        ));
    }
    let dossier_douteux = ["\\users\\", "\\appdata\\", "%temp%", "%tmp%", "\\windows\\temp\\"]
        .iter()
        .any(|d| bas.contains(d));
    dossier_douteux.then_some((
        Niveau::Moyen,
        tr!(
            "rangé dans un dossier temporaire ou du profil, où rien ne s'installe normalement",
            "stored in a temporary or profile folder, where nothing is normally installed"
        ),
    ))
}

/// Lignes « date|nom|chemin » des services installés, les plus récents d'abord ; un nom repris n'est compté qu'une fois.
fn juger_services(lignes: &[&str]) -> Vec<Constat> {
    let mut vus = std::collections::HashSet::new();
    let mut constats = Vec::new();
    let mut ordinaires = Vec::new();
    for l in lignes {
        let c: Vec<&str> = l.splitn(3, '|').collect();
        let [quand, nom, chemin] = c[..] else {
            continue;
        };
        if !vus.insert(nom.to_lowercase()) {
            continue;
        }
        let (quand, montre, chemin_montre) = (affichable(quand), affichable(nom), couper(&affichable(chemin), 160));
        match service_suspect(chemin) {
            Some((niveau, raison)) => constats.push(
                alerte(
                    "Persistance",
                    niveau,
                    trf!(
                        "Service installé le {quand}, « {montre} » : {raison} ({chemin_montre}).",
                        "Service installed on {quand}, “{montre}”: {raison} ({chemin_montre})."
                    ),
                )
                .manuel(
                    tr!(
                        "Si tu ne l'as pas installé toi-même : le regarder dans Services, puis lancer une analyse antivirus complète",
                        "If you did not install it yourself: look at it in Services, then run a full antivirus scan"
                    ),
                    &["Start-Process services.msc"],
                ),
            ),
            None => ordinaires.push(montre),
        }
    }
    if !ordinaires.is_empty() {
        constats.push(alerte(
            "Persistance",
            Niveau::Info,
            trf!(
                "Service(s) installé(s) ces {JOURS} derniers jours : {}. Rien d'anormal dans leur chemin ; si l'un t'est inconnu, regarde-le dans Services.",
                "Service(s) installed over the last {JOURS} days: {}. Nothing odd in their path; if one is unknown to you, look at it in Services.",
                resume(&ordinaires, 5, ", ")
            ),
        ));
    }
    constats
}

/// Pourquoi le journal Security a refusé. `admin` : Vanguard tourne-t-il en administrateur ? Sans, c'est la raison, et
/// le remède.
fn refus_de_securite(admin: Option<bool>) -> &'static str {
    if admin == Some(false) {
        tr!(
            "journal de sécurité lisible seulement en administrateur : relancer Vanguard en administrateur",
            "security log readable only as administrator: run Vanguard again as administrator"
        )
    } else {
        tr!("journal de sécurité illisible", "security log unreadable")
    }
}

fn juger_evenements(sortie: Option<&str>) -> Vec<Constat> {
    let Some(sortie) = sortie else {
        return vec![illisible("Journaux")];
    };
    let s = |nom: &str| section(Some(sortie), nom);
    let mut constats = Vec::new();
    if let (Some(echecs), Some(securite)) = (s("ECH"), s("SEC")) {
        constats.push(juger_echecs(&lire_echecs(&echecs)));
        constats.extend(juger_securite(&securite));
    } else {
        let admin = s("ADM").and_then(|l| l.first().map(|v| v.trim().eq_ignore_ascii_case("true")));
        constats.push(impossible("Journaux", refus_de_securite(admin)));
    }
    match s("SRV") {
        Some(services) => constats.extend(juger_services(&services)),
        None => constats.push(impossible(
            "Journaux",
            tr!("journal Système illisible", "System log unreadable"),
        )),
    }
    constats
}

regle!(
    "WIN-JRN-003",
    Os::Windows,
    253,
    (
        "journaux d'événements des 7 derniers jours (connexions, comptes, services)",
        "event logs of the last 7 days (sign-ins, accounts, services)"
    ),
    &[
        "MITRE ATT&CK T1110",
        "MITRE ATT&CK T1070.001",
        "MITRE ATT&CK T1136.001",
        "MITRE ATT&CK T1543.003",
    ],
    // 30 s : la lecture est bornée ; au-delà, PowerShell ou le service des journaux est bloqué.
    || juger_evenements(Some(&lire_journaux()))
);

// ───────────────────────────── Mot de passe deviné ─────────────────────────────

/// Les adresses dont on lit les connexions réussies, au plus : les plus insistantes. Chacune est une lecture du journal.
const ADRESSES_LUES: usize = 5;

/// Une adresse telle que le journal l'écrit. « ::ffff:192.0.2.5 » (IPv4 dans IPv6) est 192.0.2.5 ; la zone d'une
/// adresse de lien local (« fe80::1%12 ») ne change pas l'appareil ; « - » (session au clavier) n'en est pas une.
fn adresse(texte: &str) -> Option<std::net::IpAddr> {
    let texte = texte.trim();
    let sans_zone = texte.split_once('%').map_or(texte, |(a, _)| a);
    sans_zone.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// Les adresses d'où sont venus au moins `chasse::SEUIL_ECHECS` échecs, les plus insistantes d'abord, écrites comme le
/// journal les écrit : elles entrent telles quelles dans la requête des réussites. Seulement des chiffres, des lettres
/// hexadécimales, « . », « : » et « % » : rien d'autre ne peut sortir de la chaîne XPath.
fn adresses_insistantes(echecs: &[Echec]) -> Vec<String> {
    let mut nombres: HashMap<&str, usize> = HashMap::new();
    for e in echecs {
        let sure = e
            .adresse
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '%'));
        if sure && adresse(&e.adresse).is_some_and(|ip| !ip.is_loopback()) {
            *nombres.entry(e.adresse.as_str()).or_default() += 1;
        }
    }
    let mut tries: Vec<(&str, usize)> = nombres
        .into_iter()
        .filter(|(_, n)| *n >= crate::machine::chasse::SEUIL_ECHECS)
        .collect();
    tries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    tries
        .into_iter()
        .take(ADRESSES_LUES)
        .map(|(a, _)| a.to_string())
        .collect()
}

/// La ligne d'une connexion réussie (4624) par le réseau (type 3) ou le Bureau à distance (type 10), de la même forme
/// que celle d'un échec (« date|type|adresse|compte ») : `lire_echecs` la lit. Les autres types (session ouverte au
/// clavier, services) ne viennent pas d'une adresse : rien.
fn ligne_reussite(id: u32, date: &str, champs: &[(String, String)]) -> Option<String> {
    let valeur = |nom: &str| champs.iter().find(|(n, _)| n == nom).map(|(_, v)| v);
    let type_ = valeur("LogonType")?.trim();
    // Une session anonyme (S-1-5-7, la session nulle d'un partage) ou un compte d'ordinateur (« PC$ ») n'est pas un
    // mot de passe deviné : sans cette exclusion, une télé qui rate l'accès invité puis ouvre une session nulle
    // donnait une alerte critique.
    let anonyme = valeur("TargetUserSid").is_some_and(|s| s.trim() == "S-1-5-7")
        || valeur("TargetUserName").is_some_and(|n| {
            let n = n.trim();
            n.ends_with('$') || n.eq_ignore_ascii_case("ANONYMOUS LOGON")
        });
    (id == 4624 && matches!(type_, "3" | "10") && !anonyme).then(|| {
        format!(
            "{}|{type_}|{}|{}",
            date_locale(date).unwrap_or_default(),
            champ(valeur("IpAddress")),
            champ(valeur("TargetUserName"))
        )
    })
}

/// Échecs et réussites dans l'ordre où ils ont eu lieu. À la même minute, l'échec passe avant : le journal ne date
/// qu'à la minute ici, et une rafale finit souvent par la réussite.
fn dans_l_ordre(echecs: &[Echec], reussites: &[Echec]) -> Vec<crate::machine::chasse::Tentative> {
    let mut toutes: Vec<(NaiveDateTime, bool, &Echec)> = echecs
        .iter()
        .map(|e| (e.quand, false, e))
        .chain(reussites.iter().map(|r| (r.quand, true, r)))
        .collect();
    toutes.sort_by_key(|(quand, reussie, _)| (*quand, *reussie));
    toutes
        .into_iter()
        .filter_map(|(_, reussie, e)| {
            Some(crate::machine::chasse::Tentative {
                adresse: adresse(&e.adresse)?,
                compte: e.compte.clone(),
                reussie,
            })
        })
        .collect()
}

/// Les échecs de connexion (4625) des 7 derniers jours, et les connexions réussies par le réseau ou le Bureau à
/// distance (4624) depuis les adresses qui en ont raté au moins dix, dans l'ordre : pour la recherche d'un mot de passe
/// deviné (`machine::chasse`). Les réussites ne se lisent que pour ces adresses-là : le journal en garde des milliers
/// d'autres. `Err` : pourquoi le journal Security refuse (sans droits d'administrateur, souvent).
pub(crate) fn tentatives_lues() -> Result<Vec<crate::machine::chasse::Tentative>, &'static str> {
    let fin = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let refus = || refus_de_securite(Some(super::processus::eleve()));
    let Some(lignes) = lire(&LECTURES[0], fin) else {
        return Err(refus());
    };
    let echecs = lire_echecs(&lignes.iter().map(String::as_str).collect::<Vec<_>>());
    let mut reussites = Vec::new();
    for adresse in adresses_insistantes(&echecs) {
        let requete = format!(
            "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= {}]] and EventData[Data[@Name='IpAddress']='{adresse}']]",
            u64::from(JOURS) * 86_400_000
        );
        let Some(lues) = parcourir_nommes("Security", &requete, 50, fin, ligne_reussite) else {
            return Err(refus());
        };
        reussites.extend(lues);
    }
    let reussites = lire_echecs(&reussites.iter().map(String::as_str).collect::<Vec<_>>());
    Ok(dans_l_ordre(&echecs, &reussites))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une rafale de `n` échecs, une minute d'écart, à partir de 10 h.
    fn rafale(n: usize, type_: &str, adresse: &str) -> Vec<String> {
        (0..n)
            .map(|i| format!("2026-10-18 10:{:02}|{type_}|{adresse}|alice", i % 60))
            .collect()
    }

    #[test]
    fn rafales_d_echecs() {
        let lignes = |v: &[String]| lire_echecs(&v.iter().map(String::as_str).collect::<Vec<_>>());
        assert!(juger_echecs(&[]).probleme.is_none());
        // Quelques fautes de frappe, et des échecs étalés sur la semaine : pas de rafale.
        let etales: Vec<String> = (0..30)
            .map(|i| format!("2026-10-{:02} {:02}:00|2|-|alice", 12 + i % 7, i % 24))
            .collect();
        let c = juger_echecs(&lignes(&etales));
        assert!(c.probleme.is_none(), "{}", c.message);
        // Depuis le réseau (Bureau à distance) : élevé, avec les origines les plus fréquentes.
        let mut reseau = rafale(25, "10", "203.0.113.7");
        reseau.extend(rafale(5, "3", "192.0.2.44"));
        let c = juger_echecs(&lignes(&reseau));
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("203.0.113.7 (25), 192.0.2.44 (5)"), "{}", c.message);
        assert!(c.message.contains("alice (30)"), "{}", c.message);
        // Un NAS de la maison qui répète un vieux mot de passe (une adresse locale, un compte) : moyen, expliqué.
        let c = juger_echecs(&lignes(&rafale(40, "3", "192.168.1.20")));
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(
            c.message.contains("192.168.1.20") && c.message.contains("NAS"),
            "{}",
            c.message
        );
        // Deux adresses locales, ou une adresse d'Internet : toujours élevé.
        let mut deux = rafale(25, "3", "192.168.1.20");
        deux.extend(rafale(5, "3", "192.168.1.21"));
        assert_eq!(juger_echecs(&lignes(&deux)).probleme, Some(Niveau::Eleve));
        assert_eq!(
            juger_echecs(&lignes(&rafale(25, "3", "203.0.113.9"))).probleme,
            Some(Niveau::Eleve)
        );
        // Au clavier : moyen.
        let c = juger_echecs(&lignes(&rafale(22, "2", "-")));
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        // Une ligne mal formée est ignorée, sans tout faire tomber.
        assert_eq!(
            lire_echecs(&["n'importe quoi", "2026-10-18 10:00|3|192.0.2.1|alice"]).len(),
            1
        );
    }

    #[test]
    fn rafale_glissante() {
        let h = |t: &str| date(t).unwrap();
        // 10:50 → 11:40 : six dans la même heure, même à cheval sur deux heures pleines.
        let heures = ["10:50", "11:00", "11:10", "11:20", "11:30", "11:40", "13:00"]
            .iter()
            .map(|t| h(&format!("2026-10-18 {t}")))
            .collect();
        assert_eq!(plus_forte_rafale(heures), 6);
        assert_eq!(plus_forte_rafale(Vec::new()), 0);
    }

    #[test]
    fn journal_efface_et_comptes_crees() {
        let c = juger_securite(&[
            "1102|2026-10-18 03:12|alice",
            "1102|2026-10-15 22:40|alice",
            "4720|2026-10-17 09:00|alice|bob",
        ]);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(c[0].message.contains("2026-10-18 03:12"));
        assert_eq!(c[1].probleme, Some(Niveau::Info));
        assert!(c[1].message.contains("bob"));
        assert!(juger_securite(&[]).is_empty());
        // Un nom de compte piégé arrive inoffensif.
        let c = juger_securite(&["4720|2026-10-17 09:00|alice|x\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}"]);
        assert!(!crate::ui::contient_un_piege(&c[0].message));
    }

    #[test]
    fn services_installes() {
        assert_eq!(
            service_suspect(r"%COMSPEC% /b /c start /b /min powershell -nop -w hidden -enc SQBFAFgA").map(|s| s.0),
            Some(Niveau::Eleve)
        );
        assert_eq!(
            service_suspect(r"cmd.exe /c echo abcd > \\.\pipe\abcd").map(|s| s.0),
            Some(Niveau::Eleve)
        );
        assert_eq!(
            service_suspect(r"\??\C:\Users\alice\AppData\Local\Temp\cpuz_x64.sys").map(|s| s.0),
            Some(Niveau::Moyen)
        );
        assert!(service_suspect(r#""C:\Program Files\Mozilla Maintenance Service\maintenanceservice.exe""#).is_none());
        assert!(service_suspect(r"\SystemRoot\System32\drivers\wd\WdNisDrv.sys").is_none());
        let c = juger_services(&[
            r"2026-10-18 10:00|abcdef|%COMSPEC% /c powershell -enc SQBFAFgA",
            r"2026-10-17 10:00|Mozilla Maintenance Service|C:\Program Files\Mozilla Maintenance Service\maintenanceservice.exe",
            r"2026-10-16 10:00|Mozilla Maintenance Service|C:\Program Files\Mozilla Maintenance Service\maintenanceservice.exe",
        ]);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(!c[0].correctif.as_ref().unwrap().automatique);
        assert_eq!(c[1].probleme, Some(Niveau::Info));
        assert_eq!(c[1].message.matches("Mozilla").count(), 1, "{}", c[1].message);
    }

    #[test]
    fn evenements_lus_dans_leur_xml() {
        // XML inventé, à la forme de celui de Windows : 4625 (EventData), 1102 (UserData), entités et valeur vide.
        let echec = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID>\
             <TimeCreated SystemTime='2026-10-18T14:05:09.1234567Z'/></System><EventData>\
             <Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data>\
             <Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data>\
             <Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>alice&amp;bob</Data>\
             <Data Name='TargetDomainName'/><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data>\
             <Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp</Data>\
             <Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>SALON</Data>\
             <Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data>\
             <Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>192.0.2.10</Data>\
             <Data Name='IpPort'>0</Data></EventData></Event>";
        let (id, date, valeurs) = lire_xml(echec).unwrap();
        assert_eq!((id, date.as_str()), (4625, "2026-10-18T14:05:09.1234567Z"));
        assert_eq!(valeurs.len(), 21);
        assert_eq!(
            ligne("ECH", id, "2026-10-18 10:05", &valeurs).as_deref(),
            Some("2026-10-18 10:05|3|192.0.2.10|alice&bob")
        );
        let efface = "<Event><System><EventID>1102</EventID><TimeCreated SystemTime='2026-10-18T14:05:09Z'/></System>\
             <UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>\
             <SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>bob</SubjectUserName>\
             <SubjectDomainName>SALON</SubjectDomainName><SubjectLogonId>0x1</SubjectLogonId></LogFileCleared></UserData></Event>";
        let (id, _, valeurs) = lire_xml(efface).unwrap();
        assert_eq!(ligne("SEC", id, "d", &valeurs).as_deref(), Some("1102|d|bob"));
        // Un nom piégé ne casse pas la ligne : le séparateur et les retours deviennent des espaces.
        let p = vec!["a|b\r\nc".to_string(), "C:\\x.exe".to_string()];
        assert_eq!(ligne("SRV", 7045, "d", &p).as_deref(), Some("d|a b c|C:\\x.exe"));
        assert_eq!(ligne("SRV", 4625, "d", &p), None);
        assert!(lire_xml("<Event><System><EventID>x</EventID></System></Event>").is_none());
        assert!(lire_xml("pas du xml <").is_none());
        let demarrage = "<Event><System><EventID>100</EventID></System><EventData>\
            <Data Name='BootTsVersion'>2</Data><Data Name='BootTime'>41234</Data><Data Name='BootPostBootTime'>9000</Data>\
            <Data Name='Vide'/></EventData></Event>";
        let (id, _, valeurs, noms) = lire_xml_nomme(demarrage).unwrap();
        assert_eq!(id, 100);
        assert_eq!(noms, ["BootTsVersion", "BootTime", "BootPostBootTime", "Vide"]);
        assert_eq!(valeurs, ["2", "41234", "9000", ""]);
        assert_eq!(date_locale("pas une date"), None);
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : rien ne plante, et chaque section lue est complète.
    #[test]
    fn journaux_lus_par_windows() {
        let texte = lire_journaux();
        assert!(texte.starts_with("ADM|"), "{texte}");
        let _ = juger_evenements(Some(&texte));
        // Lu, ou refusé avec sa raison (Wine, sans droits d'administrateur).
        if let Err(raison) = tentatives_lues() {
            assert_ne!(raison, "");
        }
    }

    /// Dix échecs (4625) depuis une adresse, puis une connexion réussie (4624, Bureau à distance) depuis la même : un
    /// mot de passe deviné. Une session ouverte au clavier ne vient d'aucune adresse ; la machine elle-même, une
    /// adresse qui n'en est pas une ou qui sortirait de la requête XPath ne sont pas lues.
    #[test]
    fn adresses_du_journal() {
        let ip = |t: &str| t.parse::<std::net::IpAddr>().ok();
        assert_eq!(adresse("192.0.2.5"), ip("192.0.2.5"));
        assert_eq!(adresse(" ::ffff:192.0.2.5 "), ip("192.0.2.5"));
        assert_eq!(adresse("fe80::1%12"), ip("fe80::1"));
        assert_eq!(adresse("-"), None);
        assert_eq!(adresse(""), None);
    }

    #[test]
    fn mot_de_passe_devine_sous_windows() {
        use crate::machine::chasse::{Intrusion, SEUIL_ECHECS, intrusions};
        let mut lignes = rafale(SEUIL_ECHECS, "10", "203.0.113.7");
        lignes.extend(rafale(25, "3", "127.0.0.1"));
        lignes.extend(rafale(30, "3", "203.0.113.7' or '1'='1"));
        lignes.extend(rafale(SEUIL_ECHECS - 1, "3", "::ffff:192.0.2.9"));
        let echecs = lire_echecs(&lignes.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(adresses_insistantes(&echecs), ["203.0.113.7"]);
        let champs = |type_: &str| {
            [
                ("TargetUserName", "alice"),
                ("LogonType", type_),
                ("IpAddress", "203.0.113.7"),
            ]
            .map(|(n, v)| (n.to_string(), v.to_string()))
        };
        assert_eq!(ligne_reussite(4624, "pas une date", &champs("2")), None);
        assert_eq!(ligne_reussite(4625, "pas une date", &champs("10")), None);
        // Le dernier échec est à 10:09 ; la réussite à 10:09, puis une autre à 10:30.
        let reussites = [
            "2026-10-18 10:09|10|203.0.113.7|alice",
            "2026-10-18 10:30|10|203.0.113.7|alice",
        ];
        assert!(
            ligne_reussite(4624, "2026-10-18T14:05:09Z", &champs("10"))
                .is_some_and(|l| l.ends_with("|10|203.0.113.7|alice"))
        );
        let t = dans_l_ordre(&echecs, &lire_echecs(&reussites));
        assert_eq!(
            intrusions(&t),
            [Intrusion {
                adresse: "203.0.113.7".parse().unwrap(),
                compte: "alice".into(),
                echecs: SEUIL_ECHECS
            }]
        );
        // Une réussite avant la rafale ne dit rien.
        let t = dans_l_ordre(&echecs, &lire_echecs(&["2026-10-18 09:59|10|203.0.113.7|alice"]));
        assert_eq!(intrusions(&t), Vec::<Intrusion>::new());
    }

    #[test]
    fn lecture_complete_ou_non() {
        let complet = "ADM|True\nADM_FIN\nECH|2026-10-18 10:00|3|192.0.2.10|alice\nECH_FIN\nSEC_FIN\nSRV_FIN";
        let c = juger_evenements(Some(complet));
        assert!(
            c.len() == 1 && c[0].verifie && c[0].probleme.is_none(),
            "{}",
            c[0].message
        );
        // Sans droits : le journal Security refusé, dit et jamais compté comme sain ; le journal Système lu quand même.
        let sans_droits = "ADM|False\nADM_FIN\nSRV|2026-10-18 10:00|abcdef|cmd.exe /c whoami\nSRV_FIN";
        let c = juger_evenements(Some(sans_droits));
        assert_eq!(c.len(), 2);
        assert!(!c[0].verifie && c[0].message.contains(tr!("administrateur", "administrator")));
        assert_eq!(c[1].probleme, Some(Niveau::Eleve));
        assert!(!juger_evenements(None)[0].verifie);
        assert!(juger_evenements(Some("ADM|True\nADM_FIN")).iter().all(|c| !c.verifie));
    }
}
