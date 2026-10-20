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

/// Sections : ADM (droits administrateur), ECH (4625, échecs de connexion : date, type de connexion, adresse
/// d'origine, compte visé), SEC (1102 journal de sécurité effacé : date, compte ; 4720 compte créé : date, auteur,
/// nouveau compte), SRV (7045 service installé : date, nom, chemin). Les deux premières lectures demandent les droits
/// administrateur (journal Security) ; « aucun événement » n'est pas une erreur, un refus en est une (section sans
/// fin). Dates en culture invariante : le séparateur des heures change avec la langue.
const SCRIPT: &str = "function N($v) { (\"$v\" -replace '[\\r\\n|]+', ' ').Trim() }; \
     function D($e) { $e.TimeCreated.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) }; \
     function Lire($filtre, $max, $nom, $ligne) { try { try { Get-WinEvent -FilterHashtable $filtre -MaxEvents $max -ErrorAction Stop | ForEach-Object { \"$nom|\" + (& $ligne $_) } } \
       catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }; \"$($nom)_FIN\" } catch {} }; \
     $depuis = (Get-Date).AddDays(-7); \
     try { 'ADM|' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); 'ADM_FIN' } catch {}; \
     Lire @{ LogName = 'Security'; Id = 4625; StartTime = $depuis } 2000 'ECH' { param($e) $p = $e.Properties; (D $e) + '|' + (N $p[10].Value) + '|' + (N $p[19].Value) + '|' + (N $p[5].Value) }; \
     Lire @{ LogName = 'Security'; Id = 1102, 4720; StartTime = $depuis } 100 'SEC' { param($e) $p = $e.Properties; \
       if ($e.Id -eq 1102) { '1102|' + (D $e) + '|' + (N $p[1].Value) } else { '4720|' + (D $e) + '|' + (N $p[4].Value) + '|' + (N $p[0].Value) } }; \
     Lire @{ LogName = 'System'; Id = 7045; StartTime = $depuis } 200 'SRV' { param($e) $p = $e.Properties; (D $e) + '|' + (N $p[0].Value) + '|' + (N $p[1].Value) }";

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
        constats.push(impossible(
            "Journaux",
            if admin == Some(false) {
                tr!(
                    "journal de sécurité lisible seulement en administrateur : relancer Vanguard en administrateur",
                    "security log readable only as administrator: run Vanguard again as administrator"
                )
            } else {
                tr!("journal de sécurité illisible", "security log unreadable")
            },
        ));
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
    || juger_evenements(ps_delai(SCRIPT, 30).as_deref())
);

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
