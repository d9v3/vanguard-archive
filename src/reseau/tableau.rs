//! Tableau de bord de la surveillance : une page locale, un seul fichier sans aucune ressource externe, qui montre
//! l'état de la surveillance horaire, ses alertes jour par jour, les appareils apparus sur le réseau et les connexions
//! vers des serveurs de botnets. Rien n'est envoyé : la page est écrite dans le dossier de Vanguard de cet ordinateur.
//!
//! Le journal des alertes est tenu ici : la surveillance y ajoute chaque alerte au moment de la notifier. Une
//! notification disparaît en quelques secondes ; sans ce journal, une alerte de la nuit était perdue.

use std::fmt::Write;
use std::path::{Path, PathBuf};

use chrono::NaiveDateTime;

use crate::rapport::{CSS, base64, esc};
use crate::reseau::{self, FicheAppareil, date_fr};
use crate::{tr, trf, trp, trw};

/// Format des dates du journal : trié comme du texte, il l'est aussi dans le temps.
const FORMAT_DATE: &str = "%Y-%m-%d %H:%M:%S";
/// Le journal garde au plus les 500 dernières alertes des 90 derniers jours : quelques centaines de Ko au pire,
/// même si un appareil bavard déclenche une alerte à chaque passe.
const ALERTES_GARDEES: usize = 500;
const JOURS_GARDES: i64 = 90;
/// Un appareil apparu depuis moins de 30 jours est « nouveau » sur le tableau.
const JOURS_NOUVEAUX: i64 = 30;
/// Jours montrés dans le résumé en barres : deux semaines se lisent d'un coup d'œil.
const JOURS_RESUMES: i64 = 14;
/// Longueurs gardées d'une alerte : un nom d'appareil choisi par n'importe qui ne doit pas gonfler le journal.
const TITRE_MAX: usize = 200;
const TEXTE_MAX: usize = 1000;

/// Ce qui a déclenché une alerte : il donne sa couleur et son étiquette sur le tableau.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Genre {
    Machine,
    Fichiers,
    Telechargement,
    Botnet,
    Passerelle,
    Empoisonneur,
    Appareil,
    Port,
    /// Le Wi-Fi moins protégé qu'au passage d'avant (ouvert, TKIP, WPS apparu) : l'audit du réseau.
    WiFi,
    /// Une menace bloquée par la protection active, ou qu'elle n'a pas pu bloquer (protection/blocage).
    Blocage,
    Autre,
}

impl Genre {
    const TOUS: [Genre; 11] = [
        Genre::Machine,
        Genre::Fichiers,
        Genre::Telechargement,
        Genre::Botnet,
        Genre::Passerelle,
        Genre::Empoisonneur,
        Genre::Appareil,
        Genre::Port,
        Genre::WiFi,
        Genre::Blocage,
        Genre::Autre,
    ];

    /// Le nom gardé dans le journal : stable, jamais traduit.
    fn nom(self) -> &'static str {
        match self {
            Genre::Machine => "machine",
            Genre::Fichiers => "fichiers",
            Genre::Telechargement => "telechargement",
            Genre::Botnet => "botnet",
            Genre::Passerelle => "passerelle",
            Genre::Empoisonneur => "empoisonneur",
            Genre::Appareil => "appareil",
            Genre::Port => "port",
            Genre::WiFi => "wifi",
            Genre::Blocage => "blocage",
            Genre::Autre => "autre",
        }
    }

    /// Un nom inconnu (journal d'une version plus récente) reste montré, sans couleur particulière.
    fn de(nom: &str) -> Genre {
        Genre::TOUS.into_iter().find(|g| g.nom() == nom).unwrap_or(Genre::Autre)
    }

    fn libelle(self) -> &'static str {
        match self {
            Genre::Machine => tr!("MACHINE", "MACHINE"),
            Genre::Fichiers => tr!("FICHIERS", "FILES"),
            Genre::Telechargement => tr!("TÉLÉCHARGEMENT", "DOWNLOAD"),
            Genre::Botnet => tr!("BOTNET", "BOTNET"),
            Genre::Passerelle => tr!("BOX", "ROUTER"),
            Genre::Empoisonneur => tr!("EMPOISONNEUR", "POISONER"),
            Genre::Appareil => tr!("APPAREIL", "DEVICE"),
            Genre::Port => tr!("PORT", "PORT"),
            Genre::WiFi => tr!("WI-FI", "WI-FI"),
            Genre::Blocage => tr!("BLOCAGE", "BLOCKING"),
            Genre::Autre => tr!("AUTRE", "OTHER"),
        }
    }

    /// La classe de couleur du rapport HTML : rouge pour ce qui trahit une attaque en cours.
    fn classe(self) -> &'static str {
        match self {
            Genre::Botnet | Genre::Passerelle | Genre::Empoisonneur | Genre::Blocage => "critique",
            Genre::Appareil | Genre::Port | Genre::Fichiers | Genre::WiFi => "eleve",
            Genre::Machine | Genre::Telechargement => "moyen",
            Genre::Autre => "info",
        }
    }
}

/// Une alerte notifiée par la surveillance, une ligne JSON du journal.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Alerte {
    /// « AAAA-MM-JJ HH:MM:SS », heure de cet ordinateur.
    pub date: String,
    pub genre: String,
    pub titre: String,
    pub texte: String,
}

fn fichier_journal() -> PathBuf {
    reseau::dossier_local().join("surveillance-alertes.jsonl")
}

fn fichier_passe() -> PathBuf {
    reseau::dossier_local().join("surveillance-passe.txt")
}

fn fichier_page() -> PathBuf {
    reseau::dossier_local().join("tableau.html")
}

/// Les `max` premiers caractères (jamais au milieu d'un caractère), suivis de « … » s'il y en avait plus.
fn tronquer(texte: &str, max: usize) -> String {
    match texte.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &texte[..i]),
        None => texte.to_string(),
    }
}

/// Ajoute une alerte au journal, au moment où la surveillance la notifie. Un échec d'écriture ne doit pas empêcher
/// la notification : il va au journal des erreurs, en silence.
pub(crate) fn noter_alerte(genre: Genre, titre: &str, texte: &str) {
    let maintenant = chrono::Local::now().naive_local();
    let alerte = Alerte {
        date: maintenant.format(FORMAT_DATE).to_string(),
        genre: genre.nom().to_string(),
        titre: tronquer(titre, TITRE_MAX),
        texte: tronquer(texte, TEXTE_MAX),
    };
    if let Err(e) = ajouter(&fichier_journal(), alerte, maintenant) {
        crate::journal::erreur("journal des alertes", &e.to_string());
    }
}

/// Le journal relu, l'alerte ajoutée, le tout borné puis réécrit d'un coup (`ecrire_atomique`) : une coupure en
/// pleine écriture laisse l'ancien journal ou le nouveau, jamais un journal tronqué. Sous verrou : la minuterie et
/// un `vanguard surveiller` lancé à la main en même temps réécrivaient chacun le journal lu avant l'autre, et la
/// seconde écriture effaçait l'alerte de la première.
fn ajouter(fichier: &Path, alerte: Alerte, maintenant: NaiveDateTime) -> std::io::Result<()> {
    let _verrou = fichier
        .parent()
        .and_then(|d| reseau::Verrou::prendre_nomme(d, "alertes.verrou"));
    let mut alertes = lire_journal(fichier);
    alertes.push(alerte);
    let texte: String = borner(alertes, maintenant)
        .iter()
        .filter_map(|a| serde_json::to_string(a).ok())
        .map(|ligne| ligne + "\n")
        .collect();
    reseau::ecrire_atomique(fichier, texte)
}

/// Les alertes de moins de 90 jours, les 500 plus récentes au plus.
fn borner(mut alertes: Vec<Alerte>, maintenant: NaiveDateTime) -> Vec<Alerte> {
    let limite = (maintenant - chrono::Duration::days(JOURS_GARDES))
        .format(FORMAT_DATE)
        .to_string();
    alertes.retain(|a| a.date >= limite);
    let trop = alertes.len().saturating_sub(ALERTES_GARDEES);
    alertes.drain(..trop);
    alertes
}

/// Le journal tel qu'il est sur le disque. Une ligne illisible ou mal datée (fichier abîmé, retouché à la main) est
/// laissée de côté : le reste du journal sert quand même. Les textes sont rendus inoffensifs pour le terminal comme
/// pour la page, qui les échappe en plus.
fn lire_journal(fichier: &Path) -> Vec<Alerte> {
    let Ok(texte) = std::fs::read_to_string(fichier) else {
        return Vec::new();
    };
    texte
        .trim_start_matches('\u{feff}')
        .lines()
        .filter_map(|ligne| serde_json::from_str::<Alerte>(ligne).ok())
        .filter(|a| NaiveDateTime::parse_from_str(&a.date, FORMAT_DATE).is_ok())
        .map(|a| Alerte {
            titre: crate::ui::affichable(&a.titre),
            texte: crate::ui::affichable(&a.texte),
            ..a
        })
        .collect()
}

/// Noté au début de chaque passe de la surveillance : le tableau dit quand elle a tourné pour la dernière fois.
pub(crate) fn noter_passe() {
    let maintenant = chrono::Local::now().format(FORMAT_DATE).to_string();
    let _ = reseau::ecrire_atomique(&fichier_passe(), maintenant);
}

/// La dernière passe : notée par `noter_passe`, sinon (passes d'avant le tableau) la date de l'état de la machine,
/// que chaque passe réécrit.
fn derniere_passe() -> Option<String> {
    let notee = std::fs::read_to_string(fichier_passe())
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| NaiveDateTime::parse_from_str(t, FORMAT_DATE).is_ok());
    notee.or_else(|| {
        let date = std::fs::metadata(reseau::dossier_local().join("surveillance-machine.json"))
            .and_then(|m| m.modified())
            .ok()?;
        Some(
            chrono::DateTime::<chrono::Local>::from(date)
                .format(FORMAT_DATE)
                .to_string(),
        )
    })
}

/// Tout ce que la page montre, réuni d'abord : la page elle-même se teste sur des données inventées.
pub(crate) struct Donnees {
    pub maintenant: NaiveDateTime,
    pub active: bool,
    pub derniere_passe: Option<String>,
    pub alertes: Vec<Alerte>,
    pub appareils: Vec<FicheAppareil>,
    /// Les connexions vers un serveur de commande vues à la dernière passe qui a pu lire les connexions.
    pub botnets_en_cours: Vec<String>,
    /// Quand elles ont été vues (la date du fichier) : la passe suivante ne le réécrit pas si la lecture des
    /// connexions échoue, et une liste d'il y a trois jours n'est plus « encore vue ».
    pub botnets_vus: Option<NaiveDateTime>,
    /// La protection en temps réel coupée, avec son échéance (« jusqu'à 17:30 ») : la minuterie est là, mais aucune
    /// passe ne se fait.
    pub temps_reel_coupe: Option<String>,
}

/// Au-delà, les connexions vues ne sont plus dites en cours : la surveillance repasse chaque heure.
const BOTNETS_RECENTS_HEURES: i64 = 2;

fn collecter() -> Donnees {
    let fichier_botnets = crate::protection::sortantes::fichier_botnets();
    let botnets_en_cours = std::fs::read_to_string(&fichier_botnets)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(crate::ui::affichable)
        .collect();
    let botnets_vus = std::fs::metadata(&fichier_botnets)
        .and_then(|m| m.modified())
        .ok()
        .map(|t| chrono::DateTime::<chrono::Local>::from(t).naive_local());
    Donnees {
        maintenant: chrono::Local::now().naive_local(),
        active: reseau::surveillance::active(),
        derniere_passe: derniere_passe(),
        alertes: lire_journal(&fichier_journal()),
        appareils: reseau::appareils_connus(),
        botnets_en_cours,
        botnets_vus,
        temps_reel_coupe: crate::protection::temps_reel::coupure().map(|c| crate::protection::temps_reel::echeance(&c)),
    }
}

/// « 2026-10-20 14:05:33 » → « 20/10/2026 à 14:05 » (en anglais : « 2026-10-20 14:05 »).
fn quand(date: &str) -> String {
    match NaiveDateTime::parse_from_str(date, FORMAT_DATE) {
        Ok(d) => d.format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M")).to_string(),
        Err(_) => date.to_string(),
    }
}

/// Le jour d'une date du journal, « AAAA-MM-JJ » (les dates lues ont été vérifiées : le découpage est sûr).
fn jour(date: &str) -> &str {
    date.get(..10).unwrap_or(date)
}

/// Les appareils apparus depuis 30 jours, les plus récents en tête. Ceux du premier scan d'un réseau n'en sont pas :
/// ils étaient déjà là quand Vanguard l'a découvert.
fn nouveaux(appareils: &[FicheAppareil], maintenant: NaiveDateTime) -> Vec<&FicheAppareil> {
    let limite = (maintenant - chrono::Duration::days(JOURS_NOUVEAUX))
        .format("%Y-%m-%d")
        .to_string();
    let mut debut: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for a in appareils {
        if let Some(p) = a.premier_vu.as_deref() {
            let d = debut.entry(a.reseau.as_str()).or_insert(p);
            *d = (*d).min(p);
        }
    }
    let mut liste: Vec<&FicheAppareil> = appareils
        .iter()
        .filter(|a| {
            a.premier_vu
                .as_deref()
                .is_some_and(|p| p >= limite.as_str() && debut.get(a.reseau.as_str()).is_some_and(|d| p > *d))
        })
        .collect();
    liste.sort_by(|a, b| b.premier_vu.cmp(&a.premier_vu).then(a.ip.cmp(&b.ip)));
    liste
}

/// Le nom montré d'un appareil : son surnom en gras d'abord, puis son nom et son fabricant.
fn nom_appareil(a: &FicheAppareil) -> String {
    let description = if a.description.is_empty() && a.surnom.is_none() {
        format!("<span class=meta>{}</span>", tr!("appareil inconnu", "unknown device"))
    } else {
        esc(&a.description)
    };
    match a.surnom.as_deref() {
        Some(s) if a.description.is_empty() => format!("<strong>{}</strong>", esc(s)),
        Some(s) => format!("<strong>{}</strong> · {description}", esc(s)),
        None => description,
    }
}

fn nom_reseau(a: &FicheAppareil) -> String {
    match (a.nom_reseau.as_deref(), a.reseau.as_str()) {
        (Some(n), _) => esc(n),
        (None, "") => tr!("réseau inconnu", "unknown network").to_string(),
        (None, id) => esc(id),
    }
}

/// Une table d'appareils : première apparition, dernière fois vu, nom, adresse, identifiant, réseau.
fn table_appareils(appareils: &[&FicheAppareil]) -> String {
    let mut h = String::from(tr!(
        "<table><tr class=entete><td>Apparu le</td><td>Vu le</td><td>Appareil</td><td>Adresse</td><td>MAC</td><td>Réseau</td></tr>",
        "<table><tr class=entete><td>First seen</td><td>Last seen</td><td>Device</td><td>Address</td><td>MAC</td><td>Network</td></tr>"
    ));
    let date = |d: Option<&String>| d.map_or_else(|| "?".to_string(), |d| esc(&date_fr(d)));
    for a in appareils {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
            date(a.premier_vu.as_ref()),
            date(a.dernier_vu.as_ref()),
            nom_appareil(a),
            a.ip,
            esc(&a.id),
            nom_reseau(a)
        );
    }
    h += "</table>";
    h
}

/// Styles propres au tableau, ajoutés à ceux du rapport : tuiles de chiffres et barres par jour.
const CSS_TABLEAU: &str = "
.tuiles{display:flex;gap:12px;flex-wrap:wrap;margin-top:12px}
.tuile{background:var(--carte);border:1px solid var(--bord);border-radius:12px;padding:12px 16px;flex:1;min-width:150px}
.tuile .n{font-size:28px;font-weight:800}.tuile .etiq{color:var(--doux);font-size:13px}
.barre{display:flex;gap:10px;align-items:center;font-size:13px;padding:2px 0}.barre .j{min-width:96px;color:var(--doux)}
.barre .b{height:10px;background:var(--eleve);border-radius:3px;min-width:2px}.barre .zero{background:var(--bord)}
.entete td{color:var(--doux);font-size:13px;border-top:0}.jour{font-weight:700;margin:0 0 4px}
details summary{cursor:pointer;font-weight:600}
";

/// Le comment l'activer, dit partout où la surveillance manque.
fn comment_activer() -> &'static str {
    tr!(
        "Pour l'activer : menu « Réseau et Internet » › « Surveillance toutes les heures », ou <code>vanguard surveillance on</code>. Elle scanne alors le réseau toutes les heures, sans rien changer, et notifie un nouvel appareil, un port dangereux nouvellement ouvert, une box usurpée, un port que la box ouvre vers Internet, un DNS ou un Wi-Fi qui changent, ou un programme qui parle à un serveur de botnet ; chaque alerte est gardée ici.",
        "To turn it on: menu “Network and Internet” › “Hourly monitoring”, or <code>vanguard monitor on</code>. It then scans the network every hour, changing nothing, and notifies a new device, a dangerous newly opened port, an impersonated router, a port the router opens to the Internet, a DNS or Wi-Fi that changes, or a program talking to a botnet server; each alert is kept here."
    )
}

/// La carte de l'état de la surveillance, en tête de page.
fn etat(d: &Donnees) -> String {
    let passe = d
        .derniere_passe
        .as_deref()
        .map(|p| trf!("dernière passe le {}", "last run on {}", esc(&quand(p))));
    let mut h = String::from("<div class=carte>");
    match (d.active, passe, d.temps_reel_coupe.as_deref()) {
        (true, passe, Some(quand)) => {
            let _ = trw!(
                h,
                "<span class=\"badge moyen\">EN PAUSE</span> Surveillance toutes les heures en pause : la protection en temps réel de Vanguard est coupée ({}), aucune passe ne se fait et rien n'est notifié{}.<div class=fix>Pour la remettre : <code>vanguard parametres temps-reel oui</code>.</div>",
                "<span class=\"badge moyen\">PAUSED</span> Hourly monitoring paused: Vanguard's real-time protection is off ({}), no run happens and nothing is notified{}.<div class=fix>To turn it back on: <code>vanguard settings real-time yes</code>.</div>",
                esc(quand),
                passe.map(|p| format!(" ({p})")).unwrap_or_default()
            );
        }
        (true, Some(p), None) => {
            let _ = trw!(
                h,
                "<span class=\"badge ok\">ACTIVE</span> Surveillance toutes les heures : {p}.",
                "<span class=\"badge ok\">ON</span> Hourly monitoring: {p}."
            );
        }
        (true, None, None) => {
            h += tr!(
                "<span class=\"badge ok\">ACTIVE</span> Surveillance toutes les heures : pas encore de passe, la première vient dans l'heure (5 minutes après le démarrage de l'ordinateur).",
                "<span class=\"badge ok\">ON</span> Hourly monitoring: no run yet, the first one comes within the hour (5 minutes after the computer starts)."
            );
        }
        (false, passe, _) => {
            let _ = trw!(
                h,
                "<span class=\"badge moyen\">COUPÉE</span> La surveillance horaire n'est pas active{} : rien de nouveau n'est noté.<div class=fix>{}</div>",
                "<span class=\"badge moyen\">OFF</span> Hourly monitoring is not on{}: nothing new is recorded.<div class=fix>{}</div>",
                passe.map(|p| format!(" ({p})")).unwrap_or_default(),
                comment_activer()
            );
        }
    }
    h += "</div>";
    h
}

/// Rien à montrer du tout : ni surveillance, ni passe, ni alerte, ni appareil. La page l'explique au lieu d'être vide.
fn page_vide(d: &Donnees) -> bool {
    !d.active && d.derniere_passe.is_none() && d.alertes.is_empty() && d.appareils.is_empty()
}

fn tuiles(d: &Donnees, nouveaux: usize, suspectes: usize) -> String {
    let depuis = |jours: i64| {
        let limite = (d.maintenant - chrono::Duration::days(jours))
            .format(FORMAT_DATE)
            .to_string();
        d.alertes.iter().filter(|a| a.date >= limite).count()
    };
    let tuile = |n: usize, etiquette: &str| {
        format!("<div class=tuile><div class=n>{n}</div><div class=etiq>{etiquette}</div></div>")
    };
    [
        tuile(depuis(1), tr!("alertes en 24 heures", "alerts in 24 hours")),
        tuile(depuis(7), tr!("alertes en 7 jours", "alerts in 7 days")),
        tuile(
            nouveaux,
            tr!("nouveaux appareils en 30 jours", "new devices in 30 days"),
        ),
        tuile(
            suspectes,
            tr!("connexions suspectes en 90 jours", "suspicious connections in 90 days"),
        ),
    ]
    .into_iter()
    .fold(String::from("<div class=tuiles>"), |h, t| h + &t)
        + "</div>"
}

/// Les alertes jour par jour : les 14 derniers jours en barres, puis chaque jour qui en a, le plus récent en tête.
fn alertes_par_jour(d: &Donnees) -> String {
    let mut h = String::from(tr!("<h2>Alertes par jour</h2>", "<h2>Alerts by day</h2>"));
    if d.alertes.is_empty() {
        h += tr!(
            "<div class=carte>Aucune alerte notée ces 90 derniers jours.</div>",
            "<div class=carte>No alert recorded in the last 90 days.</div>"
        );
        return h;
    }
    let mut par_jour: std::collections::BTreeMap<&str, Vec<&Alerte>> = std::collections::BTreeMap::new();
    for a in &d.alertes {
        par_jour.entry(jour(&a.date)).or_default().push(a);
    }
    let plus = par_jour.values().map(Vec::len).max().unwrap_or(1).max(1);
    h += "<div class=carte>";
    for i in (0..JOURS_RESUMES).rev() {
        let j = (d.maintenant - chrono::Duration::days(i))
            .format("%Y-%m-%d")
            .to_string();
        let n = par_jour.get(j.as_str()).map_or(0, Vec::len);
        let largeur = if n == 0 { 0 } else { (n * 100).div_ceil(plus) };
        let _ = write!(
            h,
            "<div class=barre><span class=j>{}</span><span class=\"b{}\" style=\"width:{largeur}%\"></span><span>{n}</span></div>",
            date_fr(&j),
            if n == 0 { " zero" } else { "" }
        );
    }
    h += "</div>";
    for (j, alertes) in par_jour.iter().rev() {
        let _ = write!(
            h,
            "<div class=carte><p class=jour>{} — {}</p>",
            esc(&date_fr(j)),
            trf!("{} alerte(s)", "{} alert(s)", alertes.len())
        );
        // Dans la journée aussi, la plus récente en haut.
        for a in alertes.iter().rev() {
            let genre = Genre::de(&a.genre);
            let heure = a.date.get(11..16).unwrap_or("");
            let _ = write!(
                h,
                "<div class=ligne><span class=meta>{}</span><span class=\"badge {}\">{}</span><div><span class=cat>{}</span> {}</div></div>",
                esc(heure),
                genre.classe(),
                genre.libelle(),
                esc(&a.titre),
                esc(&a.texte)
            );
        }
        h += "</div>";
    }
    h
}

fn appareils(d: &Donnees, nouveaux: &[&FicheAppareil]) -> String {
    let mut h = String::from(tr!(
        "<h2>Nouveaux appareils (30 derniers jours)</h2><div class=carte>",
        "<h2>New devices (last 30 days)</h2><div class=carte>"
    ));
    if d.appareils.is_empty() {
        h += tr!(
            "Aucun appareil connu : lance un scan du réseau (menu « Réseau et Internet » › « Scanner le réseau », ou <code>vanguard reseau</code>) pour que Vanguard apprenne ceux de la maison.",
            "No known device: run a network scan (menu “Network and Internet” › “Scan the network”, or <code>vanguard network</code>) so Vanguard learns your home's devices."
        );
    } else if nouveaux.is_empty() {
        h += tr!(
            "Aucun appareil apparu ces 30 derniers jours.",
            "No device appeared in the last 30 days."
        );
    } else {
        h += &table_appareils(nouveaux);
    }
    if !d.appareils.is_empty() {
        h += tr!(
            "<div class=meta>Ceux du premier scan d'un réseau n'y sont pas : ils étaient déjà là. Un surnom (menu « Nommer un appareil » ou <code>vanguard nommer &lt;ip&gt; &lt;surnom&gt;</code>) s'affiche en gras.</div>",
            "<div class=meta>Those of a network's first scan are not listed: they were already there. A nickname (menu “Name a device” or <code>vanguard name &lt;ip&gt; &lt;nickname&gt;</code>) is shown in bold.</div>"
        );
    }
    h += "</div>";
    if !d.appareils.is_empty() {
        let mut tous: Vec<&FicheAppareil> = d.appareils.iter().collect();
        tous.sort_by(|a, b| a.reseau.cmp(&b.reseau).then(a.ip.cmp(&b.ip)));
        let _ = trw!(
            h,
            "<div class=carte><details><summary>Tous les appareils connus ({})</summary>{}</details></div>",
            "<div class=carte><details><summary>All known devices ({})</summary>{}</details></div>",
            tous.len(),
            table_appareils(&tous)
        );
    }
    h
}

fn connexions_suspectes(d: &Donnees, vues: &[&Alerte]) -> String {
    let mut h = String::from(tr!(
        "<h2>Connexions suspectes</h2><div class=carte>",
        "<h2>Suspicious connections</h2><div class=carte>"
    ));
    if d.botnets_en_cours.is_empty() && vues.is_empty() {
        h += tr!(
            "Aucun programme de cet ordinateur n'a été vu parler à un serveur de commande de botnet connu (listes Feodo Tracker et ThreatFox d'abuse.ch).",
            "No program on this computer was seen talking to a known botnet command server (abuse.ch's Feodo Tracker and ThreatFox lists)."
        );
    }
    if !d.botnets_en_cours.is_empty() {
        // Vues il y a moins de deux heures : la dernière passe les a revues. Plus vieilles (surveillance coupée,
        // connexions illisibles depuis) : la date, sans « encore ».
        let recentes = d
            .botnets_vus
            .is_some_and(|v| (d.maintenant - v) <= chrono::Duration::hours(BOTNETS_RECENTS_HEURES));
        let vues = d
            .botnets_vus
            .map(|v| quand(&v.format(FORMAT_DATE).to_string()))
            .unwrap_or_default();
        let _ = if recentes {
            trw!(
                h,
                "<p class=jour>Encore vues à la dernière passe (le {})</p><ul>",
                "<p class=jour>Still seen at the last run ({})</p><ul>",
                esc(&vues)
            )
        } else {
            trw!(
                h,
                "<p class=jour>Vues le {} ; rien de plus récent : la surveillance n'a pas pu revérifier depuis</p><ul>",
                "<p class=jour>Seen on {}; nothing more recent: monitoring could not check again since</p><ul>",
                esc(&vues)
            )
        };
        for c in &d.botnets_en_cours {
            let _ = write!(h, "<li><span class=\"badge critique\">BOTNET</span> {}</li>", esc(c));
        }
        h += tr!(
            "</ul><div class=fix>Ouvre « Après une infection » dans Vanguard (<code>vanguard depanner infection</code>) : coupe Internet d'abord.</div>",
            "</ul><div class=fix>Open “After an infection” in Vanguard (<code>vanguard troubleshoot infection</code>): cut the Internet first.</div>"
        );
    }
    if !vues.is_empty() {
        h += tr!("<p class=jour>Signalées</p>", "<p class=jour>Reported</p>");
        for a in vues.iter().rev() {
            let _ = write!(
                h,
                "<div class=ligne><span class=meta>{}</span><div>{}</div></div>",
                esc(&quand(&a.date)),
                esc(&a.texte)
            );
        }
    }
    h += "</div>";
    h
}

/// Ce que le navigateur a le droit de charger dans la page : rien, sauf sa feuille de style écrite dedans et son
/// icône en data:. Deuxième barrière derrière l'échappement (`esc`) : une section qui l'oublierait un jour ne
/// pourrait toujours pas faire tourner un script ni appeler Internet.
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:";

/// La page entière, à partir des données réunies.
pub(crate) fn html(d: &Donnees) -> String {
    let mut h = String::new();
    let date = d.maintenant.format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M"));
    let logo = base64(include_bytes!("../../assets/icones/vanguard-32.png"));
    let _ = trw!(
        h,
        "<!doctype html><html lang=fr><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">\
         <title>Tableau de bord Vanguard</title><link rel=icon href=\"data:image/png;base64,{logo}\"><style>{CSS}{CSS_TABLEAU}</style></head><body><main>\
         <h1>Surveillance du réseau</h1><p class=sous>Généré par Vanguard le {date}. Rien n'est envoyé : cette page est écrite sur cet ordinateur.</p>",
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">\
         <title>Vanguard dashboard</title><link rel=icon href=\"data:image/png;base64,{logo}\"><style>{CSS}{CSS_TABLEAU}</style></head><body><main>\
         <h1>Network monitoring</h1><p class=sous>Generated by Vanguard on {date}. Nothing is sent: this page is written on this computer.</p>"
    );
    if page_vide(d) {
        let _ = trw!(
            h,
            "<div class=carte><span class=\"badge moyen\">COUPÉE</span> Rien à montrer pour l'instant : la surveillance horaire n'a jamais tourné sur cet ordinateur, et aucun appareil n'est encore connu.<div class=fix>{}</div><div class=fix>Pour voir tout de suite les appareils de la maison : menu « Réseau et Internet » › « Scanner le réseau », ou <code>vanguard reseau</code>.</div></div>",
            "<div class=carte><span class=\"badge moyen\">OFF</span> Nothing to show yet: hourly monitoring has never run on this computer, and no device is known yet.<div class=fix>{}</div><div class=fix>To see your home's devices right away: menu “Network and Internet” › “Scan the network”, or <code>vanguard network</code>.</div></div>",
            comment_activer()
        );
        h += "</main></body></html>";
        return h;
    }
    h += &etat(d);
    let nouveaux = nouveaux(&d.appareils, d.maintenant);
    let vues: Vec<&Alerte> = d
        .alertes
        .iter()
        .filter(|a| Genre::de(&a.genre) == Genre::Botnet)
        .collect();
    h += &tuiles(d, nouveaux.len(), vues.len());
    h += &alertes_par_jour(d);
    h += &appareils(d, &nouveaux);
    h += &connexions_suspectes(d, &vues);
    let _ = trw!(
        h,
        "<p class=meta>Les alertes sont gardées {JOURS_GARDES} jours ({ALERTES_GARDEES} au plus) dans le dossier de Vanguard de cet ordinateur. Pour remettre la page à jour : <code>vanguard tableau</code>.</p>",
        "<p class=meta>Alerts are kept {JOURS_GARDES} days ({ALERTES_GARDEES} at most) in this computer's Vanguard folder. To refresh the page: <code>vanguard dashboard</code>.</p>"
    );
    h += "</main></body></html>";
    h
}

/// Écrit la page dans le dossier de Vanguard de cet ordinateur (jamais sur la clé : elle dit ce qui a été vu ici).
pub fn generer() -> std::io::Result<PathBuf> {
    let chemin = fichier_page();
    reseau::ecrire_atomique(&chemin, html(&collecter()))?;
    Ok(chemin)
}

/// La commande et le menu : la page écrite, puis ouverte dans le navigateur sauf avec `sans_ouvrir` (sans affichage
/// graphique, par SSH, ou pour l'essayer).
pub fn ouvrir(sans_ouvrir: bool) {
    match generer() {
        Ok(p) => {
            trp!("  Tableau de bord : {}", "  Dashboard: {}", p.display());
            if !sans_ouvrir {
                crate::machine::ouvrir(&p.display().to_string());
            }
        }
        Err(e) => trp!(
            "  Impossible d'écrire le tableau de bord : {e}",
            "  Could not write the dashboard: {e}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(texte: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(texte, FORMAT_DATE).unwrap()
    }

    fn une_alerte(date: &str, genre: Genre, titre: &str, texte: &str) -> Alerte {
        Alerte {
            date: date.into(),
            genre: genre.nom().into(),
            titre: titre.into(),
            texte: texte.into(),
        }
    }

    fn appareil(id: &str, ip: &str, premier: &str, surnom: Option<&str>, description: &str) -> FicheAppareil {
        FicheAppareil {
            reseau: "3c:22:fb:00:00:01".into(),
            nom_reseau: Some("Salon".into()),
            id: id.into(),
            ip: ip.parse().unwrap(),
            surnom: surnom.map(str::to_string),
            description: description.into(),
            premier_vu: Some(premier.into()),
            dernier_vu: Some("2026-10-20".into()),
        }
    }

    fn donnees() -> Donnees {
        Donnees {
            maintenant: date("2026-10-20 14:50:00"),
            active: true,
            derniere_passe: Some("2026-10-20 14:00:00".into()),
            alertes: vec![
                une_alerte(
                    "2026-10-19 03:00:00",
                    Genre::Appareil,
                    "Nouvel appareil sur ton réseau",
                    "10.0.0.66 — <script>alert(1)</script> 3c:22:fb:00:00:66",
                ),
                une_alerte(
                    "2026-10-20 14:00:00",
                    Genre::Botnet,
                    "Vanguard : programme relié à un botnet",
                    "outil → 192.0.2.7:443 (Emotet, ThreatFox) : un serveur de commande connu.",
                ),
            ],
            appareils: vec![
                appareil(
                    "3c:22:fb:00:00:10",
                    "10.0.0.10",
                    "2026-09-01",
                    Some("imprimante HP"),
                    "HP",
                ),
                appareil(
                    "3c:22:fb:00:00:66",
                    "10.0.0.66",
                    "2026-10-19",
                    None,
                    "<img src=x onerror=alert(2)>",
                ),
                appareil(
                    "3c:22:fb:00:00:20",
                    "10.0.0.20",
                    "2026-10-18",
                    Some("<b>tablette</b>"),
                    "",
                ),
            ],
            botnets_en_cours: vec!["<svg onload=alert(3)> → 192.0.2.7:443".into()],
            botnets_vus: Some(date("2026-10-20 14:00:00")),
            temps_reel_coupe: None,
        }
    }

    #[test]
    fn page_sur_des_donnees_inventees() {
        let page = html(&donnees());
        assert!(page.contains("ACTIVE") && page.contains("20/10/2026 à 14:00"));
        // Deux jours d'alertes, le plus récent en tête.
        assert!(page.find("20/10/2026 — 1 alerte").unwrap() < page.find("19/10/2026 — 1 alerte").unwrap());
        // Le premier scan du réseau (1er septembre) n'est pas une nouveauté ; les deux suivants le sont.
        let nouveaux = &page[page.find("<h2>Nouveaux").unwrap()..page.find("Tous les appareils connus").unwrap()];
        assert!(nouveaux.contains("10.0.0.66") && nouveaux.contains("10.0.0.20"));
        assert!(!nouveaux.contains("10.0.0.10"));
        // Le surnom donné par « nommer » est montré.
        assert!(page.contains("<strong>imprimante HP</strong> · HP"));
        assert!(page.contains("Emotet") && page.contains("Encore vues à la dernière passe (le 20/10/2026 à 14:00)"));
        // Aucune ressource externe : la page se suffit (logo compris), et sa politique de sécurité (CSP) interdit
        // tout script et tout appel vers l'extérieur, même si une section oubliait d'échapper un nom.
        for externe in ["http://", "https://", "<script", "<img", "<link rel=stylesheet"] {
            assert!(!page.contains(externe), "{externe}");
        }
        let entete = &page[..page.find("<title>").unwrap()];
        assert!(entete.contains(&format!(
            "<meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">"
        )));
        assert!(CSP.starts_with("default-src 'none'") && !CSP.contains("script-src"));
    }

    /// Des connexions vues il y a trois jours ne sont plus « encore vues » : la surveillance a été coupée, ou la
    /// lecture des connexions échoue depuis ; la page dit la date, sans laisser croire qu'elles durent.
    #[test]
    fn connexions_vues_datees() {
        let vieilles = Donnees {
            botnets_vus: Some(date("2026-10-17 09:00:00")),
            ..donnees()
        };
        let page = html(&vieilles);
        assert!(!page.contains("Encore vues"));
        assert!(page.contains("Vues le 17/10/2026 à 09:00") && page.contains("Emotet"));
        let sans_date = Donnees {
            botnets_vus: None,
            ..donnees()
        };
        assert!(!html(&sans_date).contains("Encore vues"));
    }

    #[test]
    fn un_nom_piege_ne_devient_pas_du_code() {
        // Un appareil choisit son nom ; un programme, son nom de fichier : ils restent du texte dans la page.
        let page = html(&donnees());
        for piege in ["<script>alert", "<img src=x", "<svg onload", "<b>tablette</b>"] {
            assert!(!page.contains(piege), "{piege}");
        }
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(page.contains("<strong>&lt;b&gt;tablette&lt;/b&gt;</strong>"));
    }

    #[test]
    fn page_vide_expliquee() {
        let vide = Donnees {
            maintenant: date("2026-10-20 14:50:00"),
            active: false,
            derniere_passe: None,
            alertes: vec![],
            appareils: vec![],
            botnets_en_cours: vec![],
            botnets_vus: None,
            temps_reel_coupe: None,
        };
        let page = html(&vide);
        assert!(page.contains("Rien à montrer pour l'instant") && page.contains("vanguard surveillance on"));
        assert!(page.contains("vanguard reseau") && page.ends_with("</main></body></html>"));
        // Coupée mais avec un historique : l'historique reste, et la façon de la réactiver est dite.
        let coupee = Donnees {
            active: false,
            ..donnees()
        };
        let page = html(&coupee);
        assert!(page.contains("COUPÉE") && page.contains("vanguard surveillance on"));
        assert!(page.contains("Nouvel appareil sur ton réseau"));
        // Active mais la protection en temps réel coupée : en pause, pas « ACTIVE », et la façon de la remettre.
        let en_pause = Donnees {
            temps_reel_coupe: Some("jusqu'à reprise".into()),
            ..donnees()
        };
        let page = html(&en_pause);
        assert!(page.contains("EN PAUSE") && !page.contains("badge ok"), "{page}");
        assert!(page.contains("jusqu'à reprise") && page.contains("vanguard parametres temps-reel oui"));
        assert!(
            page.contains("20/10/2026 à 14:00"),
            "la dernière vraie passe reste dite"
        );
        // Active, sans alerte ni appareil : chaque section le dit au lieu d'être vide.
        let calme = Donnees {
            alertes: vec![],
            appareils: vec![],
            botnets_en_cours: vec![],
            ..donnees()
        };
        let page = html(&calme);
        assert!(page.contains("Aucune alerte notée") && page.contains("Aucun appareil connu"));
        assert!(page.contains("Aucun programme de cet ordinateur"));
    }

    #[test]
    fn journal_borne_en_nombre_et_en_age() {
        let dossier = reseau::dossier_local().join("tableau-journal");
        let _ = std::fs::remove_dir_all(&dossier);
        let fichier = dossier.join("surveillance-alertes.jsonl");
        let maintenant = date("2026-10-20 14:50:00");
        // Une alerte notée en juillet, puis 510 en octobre : celle de juillet a plus de 90 jours, et des 510 il
        // reste les 500 plus récentes.
        let juillet = date("2026-07-01 10:00:00");
        ajouter(
            &fichier,
            une_alerte("2026-07-01 10:00:00", Genre::Port, "vieux", "x"),
            juillet,
        )
        .unwrap();
        assert_eq!(lire_journal(&fichier).len(), 1);
        for i in 0..510 {
            let d = (maintenant - chrono::Duration::minutes(510 - i))
                .format(FORMAT_DATE)
                .to_string();
            ajouter(
                &fichier,
                une_alerte(&d, Genre::Appareil, "neuf", &i.to_string()),
                maintenant,
            )
            .unwrap();
        }
        let gardees = lire_journal(&fichier);
        assert_eq!(gardees.len(), ALERTES_GARDEES);
        assert!(gardees.iter().all(|a| a.titre == "neuf"));
        assert_eq!(gardees.first().unwrap().texte, "10");
        assert_eq!(gardees.last().unwrap().texte, "509");
        // Une ligne abîmée ou mal datée est laissée de côté, le reste se lit ; le prochain ajout la retire.
        let mut texte = std::fs::read_to_string(&fichier).unwrap();
        texte += "{pas du json\n{\"date\":\"<script>\",\"genre\":\"port\",\"titre\":\"t\",\"texte\":\"x\"}\n";
        std::fs::write(&fichier, texte).unwrap();
        assert_eq!(lire_journal(&fichier).len(), ALERTES_GARDEES);
        // Aucun fichier temporaire laissé à côté (écriture atomique), ni le verrou pris pendant l'ajout.
        let fichiers = std::fs::read_dir(&dossier).unwrap().count();
        assert_eq!(fichiers, 1);
    }

    #[test]
    fn alerte_tronquee_et_genres_stables() {
        assert_eq!(tronquer("abc", 5), "abc");
        assert_eq!(tronquer("éléphant", 3), "élé…");
        for g in Genre::TOUS {
            assert_eq!(Genre::de(g.nom()), g);
        }
        // Un genre inconnu (journal d'une version plus récente) reste montré.
        assert_eq!(Genre::de("nouveau-genre"), Genre::Autre);
    }
}
