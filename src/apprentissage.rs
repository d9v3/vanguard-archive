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

/// Liste illisible : aucun choix appliqué (les alertes se montrent comme d'habitude), jamais l'inverse.
fn charger() -> Appris {
    std::fs::read_to_string(fichier())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn enregistrer(appris: &Appris) -> std::io::Result<()> {
    std::fs::create_dir_all(crate::reseau::dossier_local())?;
    crate::reseau::ecrire_atomique(&fichier(), &serde_json::to_string_pretty(appris).unwrap_or_default())
}

/// Une alerte reconnue d'un bilan à l'autre sans ses nombres (« 3 % libres » et « 2 % libres » sont la même), sauf
/// pour les ports : un autre numéro de port est une autre alerte.
fn signature(categorie: &str, message: &str) -> String {
    let message: String = if categorie == "Ports en écoute" {
        message.to_string()
    } else {
        // Un nombre entier devient un seul « # » : « 12 % » et « 9 % » se ressemblent.
        let mut sans_nombres = String::new();
        for c in message.chars() {
            if !c.is_ascii_digit() {
                sans_nombres.push(c);
            } else if !sans_nombres.ends_with('#') {
                sans_nombres.push('#');
            }
        }
        sans_nombres
    };
    format!("{categorie} : {message}")
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
    let mut appris = charger();
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
            "    {GRIS}retenu : je ne te la proposerai plus avant {DUREE_JOURS} jours, sauf si elle s'aggrave{RESET}",
            "    {GRIS}noted: I will not offer it again for {DUREE_JOURS} days, unless it gets worse{RESET}"
        ),
        Err(e) => trp!("    ✖ Choix non retenu ({e}).", "    ✖ Choice not saved ({e})."),
    }
}

/// Applique tes choix au bilan : une alerte acceptée passe au niveau info, avec la date du choix, sans correction
/// proposée. Rend le nombre d'alertes concernées.
pub fn appliquer(constats: &mut [Constat]) -> usize {
    appliquer_le(&charger(), constats, aujourd_hui())
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

/// Menu Cette machine › Ce que Gardien a appris : tes choix, et les oublier.
pub fn menu() {
    titre(tr!("Ce que Gardien a appris", "What Gardien has learned"));
    let mut appris = charger();
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
    let a_oublier: Vec<usize> = if crate::langue::tout(&reponse) {
        (0..liste.len()).collect()
    } else {
        reponse
            .split([' ', ','])
            .filter_map(|n| n.trim().parse::<usize>().ok())
            .filter(|n| (1..=liste.len()).contains(n))
            .map(|n| n - 1)
            .collect()
    };
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
