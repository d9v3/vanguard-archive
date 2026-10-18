//! Entretien du mois : une fois par mois, en silence, Gardien regarde cet ordinateur et le dit en une notification :
//! la note de la machine, les mises à jour en attente, la place que le nettoyage libérerait et les problèmes apparus
//! depuis le mois d'avant. Rien n'est changé : c'est un rappel, les outils restent à lancer soi-même. Planifié comme
//! la surveillance : minuterie systemd (Linux), Planificateur de tâches (Windows), agent launchd (macOS).

use std::sync::atomic::{AtomicU8, Ordering};

use crate::risk::Niveau;
#[cfg(target_os = "macos")]
use crate::surveillance::domaine_launchd;
#[cfg(unix)]
use crate::surveillance::reussit;
use crate::surveillance::{cle_alerte, executable};
use crate::ui::*;

#[cfg(target_os = "linux")]
const NOM: &str = "gardien-entretien";
#[cfg(target_os = "macos")]
const AGENT_MACOS: &str = "com.gardien.entretien";
#[cfg(windows)]
const TACHE_WINDOWS: &str = "gardien - entretien du mois";

/// Catégories de l'audit qui disent « des mises à jour attendent ».
#[rustfmt::skip] // une ligne, que rustfmt étalerait sur huit
const CATEGORIES_MAJ: &[&str] =
    &["Mises à jour", "Programmes", "Pilotes", "Firmware", "Flatpak", "Snap", "AUR", "Paquets AUR"];

/// Ce que l'entretien retient d'un mois à l'autre.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Etat {
    date: String,
    score: Option<u32>,
    /// Problèmes moyens ou plus graves, « catégorie : message ».
    alertes: Vec<String>,
}

fn fichier_etat() -> std::path::PathBuf {
    crate::reseau::dossier_local().join("entretien.json")
}

struct Examen {
    score: Option<u32>,
    maj: Vec<&'static str>,
    /// Catégories de mises à jour qui n'ont pas pu être vérifiées : jamais « rien n'attend ».
    maj_inconnues: Vec<&'static str>,
    /// Place que le nettoyage recommandé libérerait, en octets.
    place: u64,
    alertes: Vec<String>,
}

fn examiner() -> Examen {
    let audit = crate::machine::auditer(false);
    let probleme = |c: &&crate::machine::Constat| c.probleme.is_some_and(|n| n >= Niveau::Moyen);
    let des_maj = |c: &&crate::machine::Constat| CATEGORIES_MAJ.contains(&c.categorie);
    let alerte = |c: &&crate::machine::Constat| format!("{} : {}", c.categorie, c.message);
    let (maj, autres): (Vec<_>, Vec<_>) = audit.constats.iter().partition(des_maj);
    Examen {
        score: audit.fiable().then_some(audit.score),
        maj: maj.iter().filter(|c| probleme(c)).map(|c| c.categorie).collect(),
        maj_inconnues: maj.iter().filter(|c| !c.verifie).map(|c| c.categorie).collect(),
        place: crate::nettoyer::place_a_liberer(),
        alertes: autres.iter().filter(|c| probleme(c)).map(alerte).collect(),
    }
}

/// Les problèmes de ce mois que le mois d'avant n'avait pas (comparés sans leurs nombres, comme la surveillance).
fn nouvelles(avant: &[String], apres: &[String]) -> Vec<String> {
    let connues: Vec<String> = avant.iter().map(|a| cle_alerte(a)).collect();
    let nouvelle = |a: &&String| !connues.contains(&cle_alerte(a));
    apres.iter().filter(nouvelle).cloned().collect()
}

/// Texte de l'entretien : (titre, lignes). `nouvelles` vaut `None` au premier passage (rien à comparer).
fn rediger(e: &Examen, nouvelles: Option<&[String]>) -> (&'static str, Vec<String>) {
    let mut lignes = vec![match e.score {
        Some(s) => trf!(
            "Note de cette machine : {} ({s}/100).",
            "This machine's grade: {} ({s}/100).",
            crate::risk::note(s)
        ),
        None => String::from(tr!(
            "Note de cette machine : aucune (des vérifications n'ont pas pu se faire).",
            "This machine's grade: none (some checks could not be done)."
        )),
    }];
    lignes.push(match (e.maj.as_slice(), e.maj_inconnues.as_slice()) {
        ([], []) => tr!("Mises à jour : rien n'attend.", "Updates: nothing waiting.").to_string(),
        ([], inconnues) => trf!(
            "Mises à jour : impossible à vérifier ({}).",
            "Updates: could not be checked ({}).",
            categories(inconnues)
        ),
        (m, _) => trf!("Mises à jour en attente : {}.", "Updates waiting: {}.", categories(m)),
    });
    let place = (e.place >= 1 << 30).then(|| crate::nettoyer::taille_lisible(e.place));
    if let Some(p) = &place {
        lignes.push(trf!("Le nettoyage libérerait {}.", "Cleaning up would free {}.", p));
    }
    lignes.push(match nouvelles {
        None => String::from(tr!(
            "Premier entretien : la suite comparera avec aujourd'hui.",
            "First check-up: the next ones will compare with today."
        )),
        Some([]) => String::from(tr!(
            "Aucun problème nouveau depuis le mois dernier.",
            "No new problem since last month."
        )),
        Some(n) => trf!(
            "{} problème(s) nouveau(x) depuis le mois dernier : {}.",
            "{} new problem(s) since last month: {}.",
            n.len(),
            categories(n)
        ),
    });
    if !e.maj.is_empty() || place.is_some() || nouvelles.is_some_and(|n| !n.is_empty()) {
        lignes.push(String::from(tr!(
            "Ouvre Gardien pour t'en occuper : rien n'a été changé.",
            "Open Gardien to deal with it: nothing was changed."
        )));
    }
    (tr!("Gardien : entretien du mois", "Gardien: monthly check-up"), lignes)
}

/// « a, b, c » : les catégories (noms internes, ou alertes « catégorie : message ») traduites, sans doublon, 3 au plus.
fn categories(noms: &[impl AsRef<str>]) -> String {
    let mut uniques: Vec<&str> = Vec::new();
    for nom in noms.iter().map(AsRef::as_ref) {
        let c = crate::langue::categorie(nom.split_once(" : ").map_or(nom, |(c, _)| c));
        if !uniques.contains(&c) {
            uniques.push(c);
        }
    }
    resume(&uniques, 3, ", ")
}

fn lire_etat() -> Option<Etat> {
    serde_json::from_str(&std::fs::read_to_string(fichier_etat()).ok()?).ok()
}

/// Appelé par le planificateur : examen silencieux, notification, puis l'état est gardé pour le mois suivant.
pub fn entretenir() {
    let examen = examiner();
    let avant = lire_etat();
    let nouvelles = avant.as_ref().map(|a| nouvelles(&a.alertes, &examen.alertes));
    let (titre, lignes) = rediger(&examen, nouvelles.as_deref());
    crate::surveillance::notifier(titre, &lignes.join("\n"));
    let etat = Etat {
        date: chrono::Local::now().format("%Y-%m-%d").to_string(),
        score: examen.score,
        alertes: examen.alertes,
    };
    if let Ok(t) = serde_json::to_string(&etat) {
        let _ = std::fs::create_dir_all(crate::reseau::dossier_local());
        let _ = std::fs::write(fichier_etat(), t);
    }
}

/// « gardien entretien » sans argument : ce que dirait l'entretien maintenant, dans le terminal. Rien n'est gardé :
/// le mois prochain comparera toujours avec le dernier vrai passage.
pub fn maintenant() {
    titre(tr!("Entretien du mois", "Monthly check-up"));
    trp!(
        "  {GRIS}Examen de cet ordinateur (une minute au plus)…{RESET}",
        "  {GRIS}Looking at this computer (a minute at most)…{RESET}"
    );
    let examen = examiner();
    let avant = lire_etat();
    let nouvelles = avant.as_ref().map(|a| nouvelles(&a.alertes, &examen.alertes));
    let (_, lignes) = rediger(&examen, nouvelles.as_deref());
    println!();
    for ligne in &lignes {
        for (i, morceau) in envelopper(ligne, LARGEUR - 4).iter().enumerate() {
            println!("  {} {morceau}", if i == 0 { "•" } else { " " });
        }
    }
    if let (Some(a), Some(n @ [_, ..])) = (&avant, nouvelles.as_deref()) {
        trp!(
            "\n  {GRIS}Nouveau depuis l'entretien du {} :{RESET}",
            "\n  {GRIS}New since the check-up of {}:{RESET}",
            a.date
        );
        for alerte in n {
            afficher_aligne("    – ", alerte, 6, "");
        }
    }
    println!();
    if active() {
        trp!(
            "  {VERT}✔{RESET} Entretien activé : une notification par mois.",
            "  {VERT}✔{RESET} Check-up on: one notification a month."
        );
    } else {
        trp!(
            "  Entretien coupé : « gardien entretien on » pour une notification par mois.",
            "  Check-up off: “gardien entretien on” for one notification a month."
        );
    }
}

/// État de l'interrupteur, lu une fois par session (le menu le demande à chaque affichage ; sous Windows, chaque
/// lecture lancerait PowerShell) : 0 pas encore lu, 1 coupé, 2 activé.
static ETAT: AtomicU8 = AtomicU8::new(0);

pub fn active() -> bool {
    if ETAT.load(Ordering::Relaxed) == 0 {
        #[cfg(target_os = "linux")]
        let installe = reussit("systemctl", &["--user", "is-enabled", &format!("{NOM}.timer")]);
        #[cfg(target_os = "macos")]
        let installe = reussit("launchctl", &["print", &format!("{}/{AGENT_MACOS}", domaine_launchd())]);
        #[cfg(windows)]
        let installe = crate::surveillance::tache_existe(&[TACHE_WINDOWS]);
        ETAT.store(1 + u8::from(installe), Ordering::Relaxed);
    }
    ETAT.load(Ordering::Relaxed) == 2
}

pub fn activer(oui: bool) {
    let reussi = if oui { installer(&executable()) } else { desinstaller() };
    ETAT.store(0, Ordering::Relaxed);
    match (oui, reussi) {
        (true, true) => trp!(
            "  {VERT}✔{RESET} Entretien du mois activé : une notification par mois (note, mises à jour, place, problèmes nouveaux), rien n'est changé.\n  {GRIS}Ce qu'il dirait aujourd'hui : « gardien entretien ».{RESET}",
            "  {VERT}✔{RESET} Monthly check-up on: one notification a month (grade, updates, space, new problems), nothing is changed.\n  {GRIS}What it would say today: “gardien entretien”.{RESET}"
        ),
        (true, false) => trp!(
            "  ✖ Impossible d'activer l'entretien du mois.",
            "  ✖ Could not turn the monthly check-up on."
        ),
        (false, _) => trp!("  Entretien du mois coupé.", "  Monthly check-up off."),
    }
}

/// Unités systemd : le 1er du mois à midi (rattrapé au démarrage suivant si l'ordinateur était éteint).
#[cfg(any(target_os = "linux", test))]
fn unites_systemd(exe: &str) -> (String, &'static str) {
    // Chemin entre guillemets (un dossier personnel peut contenir une espace), « % » doublé (spécificateurs systemd).
    let exe = format!("\"{}\"", exe.replace('%', "%%").replace('"', "\\\""));
    (
        trf!(
            "[Unit]\nDescription=Gardien : entretien du mois\n\n[Service]\nType=oneshot\nExecStart={exe} entretenir\nNice=10\n",
            "[Unit]\nDescription=Gardien: monthly check-up\n\n[Service]\nType=oneshot\nExecStart={exe} entretenir\nNice=10\n"
        ),
        tr!(
            "[Unit]\nDescription=Gardien : entretien une fois par mois\n\n[Timer]\nOnCalendar=*-*-01 12:00\nRandomizedDelaySec=15min\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
            "[Unit]\nDescription=Gardien: check-up once a month\n\n[Timer]\nOnCalendar=*-*-01 12:00\nRandomizedDelaySec=15min\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
        ),
    )
}

#[cfg(target_os = "linux")]
fn dossier_systemd() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config/systemd/user")
}

#[cfg(target_os = "linux")]
fn installer(exe: &str) -> bool {
    let dossier = dossier_systemd();
    let _ = std::fs::create_dir_all(&dossier);
    let (service, minuterie) = unites_systemd(exe);
    std::fs::write(dossier.join(format!("{NOM}.service")), service).is_ok()
        && std::fs::write(dossier.join(format!("{NOM}.timer")), minuterie).is_ok()
        && reussit("systemctl", &["--user", "daemon-reload"])
        && reussit("systemctl", &["--user", "enable", "--now", &format!("{NOM}.timer")])
}

#[cfg(target_os = "linux")]
fn desinstaller() -> bool {
    reussit("systemctl", &["--user", "disable", "--now", &format!("{NOM}.timer")]);
    let _ = std::fs::remove_file(dossier_systemd().join(format!("{NOM}.service")));
    let _ = std::fs::remove_file(dossier_systemd().join(format!("{NOM}.timer")));
    reussit("systemctl", &["--user", "daemon-reload"])
}

/// Agent launchd : le 1er du mois à midi (au réveil suivant si le Mac dormait).
#[cfg(any(target_os = "macos", test))]
fn plist_entretien(exe: &str, nom: &str) -> String {
    let exe = exe.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         \t<key>Label</key>\n\t<string>{nom}</string>\n\
         \t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>{exe}</string>\n\t\t<string>entretenir</string>\n\t</array>\n\
         \t<key>StartCalendarInterval</key>\n\t<dict>\n\t\t<key>Day</key>\n\t\t<integer>1</integer>\n\
         \t\t<key>Hour</key>\n\t\t<integer>12</integer>\n\t\t<key>Minute</key>\n\t\t<integer>0</integer>\n\t</dict>\n\
         \t<key>LowPriorityIO</key>\n\t<true/>\n\
         \t<key>Nice</key>\n\t<integer>10</integer>\n\
         </dict>\n</plist>\n"
    )
}

#[cfg(target_os = "macos")]
fn plist_agent() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join(format!("Library/LaunchAgents/{AGENT_MACOS}.plist"))
}

#[cfg(target_os = "macos")]
fn installer(exe: &str) -> bool {
    let plist = plist_agent();
    let _ = std::fs::create_dir_all(plist.parent().unwrap_or(&plist));
    if std::fs::write(&plist, plist_entretien(exe, AGENT_MACOS)).is_err() {
        return false;
    }
    let chemin = plist.display().to_string();
    // Déjà chargé (réactivation) : on le retire d'abord, sinon bootstrap refuse.
    let _ = reussit("launchctl", &["bootout", &domaine_launchd(), &chemin]);
    reussit("launchctl", &["bootstrap", &domaine_launchd(), &chemin])
}

#[cfg(target_os = "macos")]
fn desinstaller() -> bool {
    let plist = plist_agent();
    let chemin = plist.display().to_string();
    let _ = reussit("launchctl", &["bootout", &domaine_launchd(), &chemin]);
    let _ = std::fs::remove_file(&plist);
    true
}

/// Tâche du Planificateur : toutes les quatre semaines, le samedi à midi, et dès que possible si l'ordinateur était
/// éteint (New-ScheduledTaskTrigger ne sait pas faire « chaque mois »).
#[cfg(any(windows, test))]
fn script_tache(exe: &str, nom: &str) -> String {
    let exe = crate::commande::ps_texte(exe);
    trf!(
        "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'entretenir'; \
         $t = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Saturday -At '12:00'; \
         $s = New-ScheduledTaskSettingsSet -StartWhenAvailable; \
         Register-ScheduledTask -TaskName '{nom}' -Action $a -Trigger $t -Settings $s -Force \
           -Description 'Entretien de Gardien toutes les quatre semaines : une notification (note, mises à jour, place, problèmes nouveaux), rien n''est changé. Pour arrêter : gardien entretien off' | Out-Null",
        "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'entretenir'; \
         $t = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Saturday -At '12:00'; \
         $s = New-ScheduledTaskSettingsSet -StartWhenAvailable; \
         Register-ScheduledTask -TaskName '{nom}' -Action $a -Trigger $t -Settings $s -Force \
           -Description 'Gardien check-up every four weeks: one notification (grade, updates, space, new problems), nothing is changed. To stop it: gardien entretien off' | Out-Null"
    )
}

#[cfg(windows)]
fn installer(exe: &str) -> bool {
    crate::machine::windows::ps(&script_tache(exe, TACHE_WINDOWS)).is_some()
}

#[cfg(windows)]
fn desinstaller() -> bool {
    crate::machine::windows::ps(&format!(
        "Unregister-ScheduledTask -TaskName '{TACHE_WINDOWS}' -Confirm:$false"
    ))
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn examen(score: Option<u32>, maj: &[&'static str], place: u64) -> Examen {
        Examen {
            score,
            maj: maj.to_vec(),
            maj_inconnues: Vec::new(),
            place,
            alertes: Vec::new(),
        }
    }

    #[test]
    fn problemes_nouveaux_du_mois() {
        let avant = vec![
            "Santé : Disque presque plein : / n'a plus que 30 Go libres (4 %).".to_string(),
            "Pare-feu : Pare-feu inactif.".to_string(),
        ];
        let apres = vec![
            "Santé : Disque presque plein : / n'a plus que 22 Go libres (3 %).".to_string(),
            "Clés SSH : Clé sans phrase de passe.".to_string(),
        ];
        // Le disque, avec d'autres nombres, n'est pas nouveau ; le pare-feu réglé n'apparaît pas.
        assert_eq!(
            nouvelles(&avant, &apres),
            vec!["Clés SSH : Clé sans phrase de passe.".to_string()]
        );
    }

    #[test]
    fn texte_de_l_entretien() {
        let (titre, lignes) = rediger(&examen(Some(82), &["Mises à jour", "Flatpak"], 3 << 30), Some(&[]));
        assert!(titre.contains("Gardien"));
        assert_eq!(lignes.len(), 5, "{lignes:?}");
        assert!(lignes[0].contains("82/100") && lignes[0].contains('B'));
        assert!(lignes[2].contains("3.0") || lignes[2].contains("3,0"));
        assert!(
            lignes.last().unwrap().contains("rien n'a été changé")
                || lignes.last().unwrap().contains("nothing was changed")
        );
        // Tout va bien : ni place à signaler (moins d'un Go), ni rappel à agir.
        let (_, calme) = rediger(&examen(Some(95), &[], 200 << 20), Some(&[]));
        assert_eq!(calme.len(), 3, "{calme:?}");
        // Mises à jour pas vérifiées : jamais « rien n'attend ».
        let inconnu = Examen {
            maj_inconnues: vec!["Mises à jour"],
            ..examen(Some(95), &[], 0)
        };
        let (_, l) = rediger(&inconnu, Some(&[]));
        assert!(
            l[1].contains("impossible à vérifier") || l[1].contains("could not be checked"),
            "{l:?}"
        );
        assert!(!l[1].contains("rien n'attend") && !l[1].contains("nothing waiting"));
        // Premier passage : rien à comparer.
        let (_, premier) = rediger(&examen(None, &[], 0), None);
        assert!(premier[0].contains("aucune") || premier[0].contains("none"));
        assert!(premier.iter().any(|l| l.contains("Premier") || l.contains("First")));
        // Problèmes nouveaux : leurs catégories, sans doublon.
        let n = vec![
            "Pare-feu : a".to_string(),
            "Pare-feu : b".to_string(),
            "Santé : c".to_string(),
        ];
        let (_, l) = rediger(&examen(Some(70), &[], 0), Some(&n));
        assert!(
            l.iter()
                .any(|t| t.starts_with('3') && t.matches("Pare-feu").count() + t.matches("Firewall").count() == 1)
        );
    }

    #[test]
    fn planificateurs() {
        let (service, minuterie) = unites_systemd("/home/alice/.local/share/gardien/bin/gardien");
        assert!(service.contains("ExecStart=\"/home/alice/.local/share/gardien/bin/gardien\" entretenir"));
        assert!(minuterie.contains("OnCalendar=*-*-01 12:00") && minuterie.contains("Persistent=true"));
        let p = plist_entretien("/Users/alice/Gardien & co/gardien", "com.gardien.entretien");
        assert!(p.contains("<string>/Users/alice/Gardien &amp; co/gardien</string>"));
        assert!(p.contains("<key>Day</key>\n\t\t<integer>1</integer>"));
        assert!(p.contains("<string>entretenir</string>"));
        let s = script_tache("C:\\Program Files\\L'outil\\gardien.exe", "gardien - entretien du mois");
        assert!(s.contains("-Execute 'C:\\Program Files\\L''outil\\gardien.exe'"));
        // L'apostrophe typographique ferme aussi une chaîne PowerShell : doublée de même.
        let s2 = script_tache("C:\\Users\\Zoé\\L’outil\\gardien.exe", "gardien - entretien du mois");
        assert!(s2.contains("-Execute 'C:\\Users\\Zoé\\L’’outil\\gardien.exe'"));
        assert!(s.contains("-WeeksInterval 4") && s.contains("-StartWhenAvailable"));
        assert!(s.contains("'entretenir'"));
    }
}
