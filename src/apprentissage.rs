//! Ce que Gardien apprend sur cet ordinateur, gardé ici seulement (appris.json) : les alertes que tu as déclarées
//! normales chez toi. Une alerte acceptée reste visible, au niveau info, avec la date de ton choix ; elle n'est plus
//! proposée à la correction ni notifiée par la surveillance. Elle revient au bout de 90 jours, ou tout de suite si
//! elle devient plus grave qu'au moment de ton choix. « Ce que Gardien a appris » (menu Cette machine) montre tout et
//! permet d'oublier.

use std::collections::BTreeMap;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::machine::Constat;
use crate::risk::Niveau;
use crate::ui::*;

/// Durée d'un choix : au-delà, Gardien repose la question (la situation a pu changer).
const DUREE_JOURS: i64 = 90;

#[derive(Serialize, Deserialize, Default)]
struct Appris {
    #[serde(default)]
    acceptees: BTreeMap<String, Acceptee>,
}

/// Une alerte déclarée normale : telle qu'elle était, et quand.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Acceptee {
    categorie: String,
    message: String,
    niveau: Niveau,
    /// AAAA-MM-JJ.
    le: String,
}

fn fichier() -> std::path::PathBuf {
    crate::reseau::dossier_local().join("appris.json")
}

/// Les choix retenus ; `Err` si la liste existe mais ne se lit plus. Alors aucun choix n'est appliqué (les alertes se
/// montrent comme d'habitude, jamais l'inverse) et rien ne l'écrase : les choix d'avant ne se perdent pas en silence.
fn charger() -> Result<Appris, ()> {
    match std::fs::read_to_string(fichier()) {
        Ok(texte) => serde_json::from_str(&texte).map_err(|_| ()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Appris::default()),
        Err(_) => Err(()),
    }
}

fn enregistrer(appris: &Appris) -> std::io::Result<()> {
    std::fs::create_dir_all(crate::reseau::dossier_local())?;
    crate::reseau::ecrire_atomique(&fichier(), &serde_json::to_string_pretty(appris).unwrap_or_default())
}

/// Une alerte reconnue d'un bilan à l'autre sans ses quantités (« 12 % libres » et « 9 % libres » sont la même). Une
/// adresse, une heure ou une version (des nombres liés par « . » ou « : ») reste telle quelle : accepter un DNS
/// réglé vers 10.0.0.5 ne doit jamais faire taire un DNS détourné vers une autre adresse ; un port non plus. Le
/// message est dans la langue de l'interface : changer de langue fait revenir les alertes acceptées, du bon côté.
fn signature(categorie: &str, message: &str) -> String {
    if categorie == "Ports en écoute" {
        return format!("{categorie} : {message}");
    }
    let lettres: Vec<char> = message.chars().collect();
    let mut sortie = String::new();
    let mut i = 0;
    while i < lettres.len() {
        if !lettres[i].is_ascii_digit() {
            sortie.push(lettres[i]);
            i += 1;
            continue;
        }
        // Un bloc de chiffres, avec ce qui les lie (« 10.0.0.5 », « 12:30 », « 4.5.4 »).
        let debut = i;
        while i < lettres.len()
            && (lettres[i].is_ascii_digit()
                || (matches!(lettres[i], '.' | ':') && lettres.get(i + 1).is_some_and(char::is_ascii_digit)))
        {
            i += 1;
        }
        let bloc: String = lettres[debut..i].iter().collect();
        if bloc.contains(['.', ':']) {
            sortie.push_str(&bloc);
        } else {
            sortie.push('#');
        }
    }
    format!("{categorie} : {sortie}")
}

fn aujourd_hui() -> NaiveDate {
    chrono::Local::now().date_naive()
}

fn date(texte: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(texte, "%Y-%m-%d").ok()
}

fn affichee(d: NaiveDate) -> String {
    d.format(tr!("%d/%m/%Y", "%Y-%m-%d")).to_string()
}

/// Le choix vaut-il encore pour cette alerte, ce jour-là ?
fn en_vigueur(choix: &Acceptee, niveau: Niveau, jour: NaiveDate) -> bool {
    niveau <= choix.niveau && date(&choix.le).is_some_and(|le| (jour - le).num_days() < DUREE_JOURS)
}

/// Retient qu'une alerte est normale ici.
pub fn accepter(c: &Constat) {
    let Some(niveau) = c.probleme else {
        return;
    };
    let Ok(mut appris) = charger() else {
        trp!(
            "    ✖ La liste de tes choix ne se lit plus ({}) : rien n'est retenu, pour ne pas l'écraser.",
            "    ✖ Your choice list can no longer be read ({}): nothing is saved, so as not to overwrite it.",
            fichier().display()
        );
        return;
    };
    appris.acceptees.insert(
        signature(c.categorie, &c.message),
        Acceptee {
            categorie: c.categorie.to_string(),
            message: c.message.clone(),
            niveau,
            le: aujourd_hui().format("%Y-%m-%d").to_string(),
        },
    );
    match enregistrer(&appris) {
        Ok(()) => trp!(
            "    {GRIS}retenu pour {DUREE_JOURS} jours, sauf si elle s'aggrave{RESET}",
            "    {GRIS}noted for {DUREE_JOURS} days, unless it gets worse{RESET}"
        ),
        Err(e) => trp!("    ✖ Choix non retenu ({e}).", "    ✖ Choice not saved ({e})."),
    }
}

/// Applique tes choix au bilan : une alerte acceptée passe au niveau info, avec la date du choix, sans correction
/// proposée. Rend le nombre d'alertes concernées.
pub fn appliquer(constats: &mut [Constat]) -> usize {
    charger().map_or(0, |appris| appliquer_le(&appris, constats, aujourd_hui()))
}

fn appliquer_le(appris: &Appris, constats: &mut [Constat], jour: NaiveDate) -> usize {
    let mut n = 0;
    for c in constats.iter_mut() {
        let Some(niveau) = c.probleme else {
            continue;
        };
        let Some(choix) = appris.acceptees.get(&signature(c.categorie, &c.message)) else {
            continue;
        };
        if !en_vigueur(choix, niveau, jour) {
            continue;
        }
        let le = date(&choix.le).map(affichee).unwrap_or_default();
        c.probleme = Some(Niveau::Info);
        c.correctif = None;
        c.message += &trf!(
            " (normal chez toi, selon ton choix du {le})",
            " (normal for you, as you chose on {le})"
        );
        n += 1;
    }
    n
}

/// Ce qui est habituel ici, appris des mesures passées : la connexion (médiane des derniers tests).
fn habitudes() {
    section(tr!("TES HABITUDES", "YOUR HABITS"));
    let Some(h) = crate::reseau::connexion::habitudes_ici() else {
        for ligne in envelopper(
            tr!(
                "Pas encore assez de tests de connexion (il en faut 3) pour connaître la normale.",
                "Not enough connection tests yet (3 are needed) to know what is normal."
            ),
            LARGEUR - 2,
        ) {
            println!("  {GRIS}{ligne}{RESET}");
        }
        return;
    };
    let debit = |d: Option<f64>| d.map_or_else(|| "?".to_string(), |d| format!("{d:.0}"));
    trp!(
        "  Connexion : ping {:.0} ms, ↓ {} Mbit/s, ↑ {} Mbit/s",
        "  Connection: ping {:.0} ms, ↓ {} Mbit/s, ↑ {} Mbit/s",
        h.ping_ms,
        debit(h.descendant),
        debit(h.montant)
    );
    trp!(
        "  {GRIS}médiane de tes {} derniers tests ; chaque nouveau test s'y compare{RESET}",
        "  {GRIS}median of your last {} tests; each new test is compared to it{RESET}",
        h.tests
    );
}

/// Menu Cette machine › Ce que Gardien a appris : tes habitudes, tes choix, et les oublier.
pub fn menu() {
    titre(tr!("Ce que Gardien a appris", "What Gardien has learned"));
    habitudes();
    section(tr!("TES CHOIX", "YOUR CHOICES"));
    let Ok(mut appris) = charger() else {
        trp!(
            "  ✖ La liste de tes choix ne se lit plus : {}",
            "  ✖ Your choice list can no longer be read: {}",
            fichier().display()
        );
        return;
    };
    let jour = aujourd_hui();
    if appris.acceptees.is_empty() {
        for ligne in envelopper(
            tr!(
                "Rien pour l'instant. Quand une alerte est normale chez toi, réponds « i » au moment de la corriger : Gardien s'en souviendra pendant 90 jours, et te la montrera seulement pour info.",
                "Nothing yet. When an alert is normal for you, answer “i” when it is offered as a fix: Gardien will remember it for 90 days, and only show it for information."
            ),
            LARGEUR - 2,
        ) {
            println!("  {ligne}");
        }
        return;
    }
    trp!(
        "  Alertes que tu as déclarées normales :\n",
        "  Alerts you declared normal:\n"
    );
    let liste: Vec<(String, Acceptee)> = appris.acceptees.clone().into_iter().collect();
    for (i, (_, a)) in liste.iter().enumerate() {
        let fin = date(&a.le).map(|le| le + chrono::Duration::days(DUREE_JOURS));
        let etat = match fin {
            Some(f) if f > jour => trf!("jusqu'au {}", "until {}", affichee(f)),
            _ => tr!("expiré : la question reviendra", "expired: the question will come back").to_string(),
        };
        afficher_aligne(
            &format!("  {TOUCHE}{:>2}{RESET} ", i + 1),
            &format!("{} : {}", crate::langue::categorie(&a.categorie), a.message),
            5,
            "",
        );
        println!("     {GRIS}{etat}{RESET}");
    }
    let reponse = demander(tr!(
        "\n  Oublier : numéro(s), « t » pour tout, Entrée pour garder : ",
        "\n  Forget: number(s), “a” for all, Enter to keep: "
    ));
    let mut a_oublier: Vec<usize> = if crate::langue::tout(&reponse) {
        (0..liste.len()).collect()
    } else {
        reponse
            .split([' ', ','])
            .filter_map(|n| n.trim().parse::<usize>().ok())
            .filter(|n| (1..=liste.len()).contains(n))
            .map(|n| n - 1)
            .collect()
    };
    // « 1 1 » ou « 1,1 » : un seul choix.
    a_oublier.sort_unstable();
    a_oublier.dedup();
    if a_oublier.is_empty() {
        return;
    }
    for i in &a_oublier {
        appris.acceptees.remove(&liste[*i].0);
    }
    match enregistrer(&appris) {
        Ok(()) => trp!(
            "  {VERT}✔{RESET} {} choix oublié(s) : ces alertes reviendront normalement.",
            "  {VERT}✔{RESET} {} choice(s) forgotten: these alerts will come back as usual.",
            a_oublier.len()
        ),
        Err(e) => trp!("  ✖ Impossible d'enregistrer ({e}).", "  ✖ Could not save ({e})."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constat(categorie: &'static str, niveau: Niveau, message: &str) -> Constat {
        Constat {
            categorie,
            probleme: Some(niveau),
            message: message.into(),
            correctif: Some(crate::machine::Correctif {
                action: "corriger".into(),
                commandes: vec!["sudo x".into()],
                automatique: true,
                bloque: None,
            }),
            verifie: true,
        }
    }

    fn appris(categorie: &str, message: &str, niveau: Niveau, le: &str) -> Appris {
        let mut a = Appris::default();
        a.acceptees.insert(
            signature(categorie, message),
            Acceptee {
                categorie: categorie.into(),
                message: message.into(),
                niveau,
                le: le.into(),
            },
        );
        a
    }

    fn jour(t: &str) -> NaiveDate {
        date(t).unwrap()
    }

    #[test]
    fn choix_applique_puis_expire() {
        let a = appris("Groupes", "Tu es dans le groupe docker.", Niveau::Moyen, "2026-10-18");
        let mut c = [constat("Groupes", Niveau::Moyen, "Tu es dans le groupe docker.")];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-11-01")), 1);
        assert_eq!(c[0].probleme, Some(Niveau::Info));
        assert!(c[0].correctif.is_none());
        // 90 jours plus tard, la question revient.
        let mut c = [constat("Groupes", Niveau::Moyen, "Tu es dans le groupe docker.")];
        assert_eq!(appliquer_le(&a, &mut c, jour("2027-01-16")), 0);
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
    }

    #[test]
    fn adresses_gardees_dans_la_signature() {
        // Une quantité change, la même alerte ; une autre adresse, une autre alerte.
        assert_eq!(
            signature("Santé", "Disque : 12 % libres sur 512 Go."),
            signature("Santé", "Disque : 9 % libres sur 1000 Go.")
        );
        assert_ne!(
            signature("DNS", "DNS réglé à la main vers un serveur inconnu : 10.0.0.5."),
            signature("DNS", "DNS réglé à la main vers un serveur inconnu : 185.1.2.3.")
        );
        assert_eq!(
            signature("DNS", "Vers 10.0.0.5, 3 fois."),
            "DNS : Vers 10.0.0.5, # fois."
        );
    }

    #[test]
    fn aggravation_et_nombres() {
        let a = appris("Santé", "Disque : 12 % libres.", Niveau::Moyen, "2026-10-18");
        // Mêmes mots, autres nombres : la même alerte.
        let mut c = [constat("Santé", Niveau::Moyen, "Disque : 9 % libres.")];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-10-20")), 1);
        // Plus grave qu'au moment du choix : elle revient.
        let mut c = [constat("Santé", Niveau::Eleve, "Disque : 2 % libres.")];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-10-20")), 0);
        // Un port, c'est un numéro précis : un autre port est une autre alerte.
        let a = appris("Ports en écoute", "8080/tcp ouvert.", Niveau::Moyen, "2026-10-18");
        let mut c = [constat("Ports en écoute", Niveau::Moyen, "8081/tcp ouvert.")];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-10-20")), 0);
    }
}
