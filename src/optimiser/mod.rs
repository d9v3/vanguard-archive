//! Optimiser : réglages de confidentialité, de performance et de confort, écrits pour Gardien. Chaque réglage montre
//! son état réel, explique ce qu'il change et s'applique après accord, avec un point de restauration si le système est
//! touché. Il s'annule exactement : la valeur d'avant est notée au moment du changement, puis remise telle quelle ;
//! sans note (réglage fait ailleurs), c'est la valeur d'un système neuf qui revient. Aucun réglage n'affaiblit la
//! sécurité, et ceux qui ne conviennent pas à cette machine (version du système, bureau, matériel) ne sont pas proposés.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as systeme;
#[cfg(target_os = "macos")]
use macos as systeme;
#[cfg(windows)]
use windows as systeme;

use std::collections::BTreeMap;

use crate::selection::{Case, cocher};
use crate::ui::*;

/// Valeur d'un réglage, telle qu'on la lit et qu'on la remet. `None` : absente (valeur du registre, fichier,
/// préférence jamais définie).
pub type Valeur = Option<String>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Categorie {
    Confidentialite,
    // Rien dans cette catégorie pour macOS, pour l'instant.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Performance,
    Confort,
}

impl Categorie {
    pub fn titre(self) -> &'static str {
        match self {
            Categorie::Confidentialite => tr!("Confidentialité", "Privacy"),
            Categorie::Performance => tr!("Performance et fiabilité", "Performance and reliability"),
            Categorie::Confort => tr!("Confort et fichiers", "Comfort and files"),
        }
    }
}

/// Un réglage proposé par Gardien.
pub struct Reglage {
    /// Nom stable, noté dans l'historique pour pouvoir annuler.
    pub id: &'static str,
    pub categorie: Categorie,
    pub titre: &'static str,
    /// Ce que ça change, et pourquoi.
    pub effet: &'static str,
    /// Le revers, s'il y en a un.
    pub prudence: Option<&'static str>,
    /// Fait partie des réglages recommandés (sans revers pour la plupart des gens).
    pub recommande: bool,
    pub changements: Vec<systeme::Changement>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Etat {
    Fait,
    AFaire,
    EnPartie,
}

fn etat(r: &Reglage) -> Etat {
    let bons = r.changements.iter().filter(|c| c.lire() == c.cible()).count();
    match bons {
        0 => Etat::AFaire,
        n if n == r.changements.len() => Etat::Fait,
        _ => Etat::EnPartie,
    }
}

/// Valeurs d'avant de chaque réglage appliqué par Gardien, dans l'ordre de ses changements.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Historique {
    reglages: BTreeMap<String, Avant>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Avant {
    date: String,
    valeurs: Vec<Valeur>,
}

fn fichier_historique() -> std::path::PathBuf {
    crate::reseau::dossier_local().join("reglages.json")
}

fn charger() -> Historique {
    let chemin = fichier_historique();
    let Ok(texte) = std::fs::read_to_string(&chemin) else {
        return Historique::default();
    };
    match serde_json::from_str(texte.trim_start_matches('\u{feff}')) {
        Ok(h) => h,
        Err(e) => {
            // Jamais écraser des valeurs d'avant qu'on ne sait pas relire : le fichier est mis de côté, intact.
            let copie = chemin.with_extension(format!(
                "illisible-{}.json",
                chrono::Local::now().format("%Y%m%d-%H%M%S")
            ));
            let _ = std::fs::copy(&chemin, &copie);
            tre!(
                "Attention : valeurs d'avant des réglages illisibles ({e}). Copie gardée : {}",
                "Warning: previous setting values unreadable ({e}). Copy kept: {}",
                copie.display()
            );
            Historique::default()
        }
    }
}

/// Écrit l'historique d'un bloc (fichier temporaire, puis renommé) : une coupure ou un Ctrl-C laissent l'ancien ou
/// le nouveau, jamais un fichier tronqué qui, relu vide, ferait perdre toutes les valeurs d'avant.
fn sauver(h: &Historique) -> bool {
    let ecrit = serde_json::to_string_pretty(h)
        .map_err(std::io::Error::other)
        .and_then(|texte| crate::reseau::ecrire_atomique(&fichier_historique(), &texte));
    if let Err(e) = &ecrit {
        tre!(
            "Attention : valeurs d'avant des réglages non enregistrées ({e}).",
            "Warning: previous setting values not saved ({e})."
        );
    }
    ecrit.is_ok()
}

/// Valeurs à remettre pour annuler `r` : celles notées avant le changement, sinon celles d'un système neuf.
fn valeurs_d_avant(r: &Reglage, h: &Historique) -> Vec<Valeur> {
    let notees = h.reglages.get(r.id);
    r.changements
        .iter()
        .enumerate()
        .map(|(i, c)| {
            notees
                .and_then(|a| a.valeurs.get(i).cloned())
                .unwrap_or_else(|| c.defaut())
        })
        .collect()
}

/// Les valeurs à remettre pour annuler `r` sont-elles relues en place ?
fn remis_en_place(r: &Reglage, h: &Historique) -> bool {
    r.changements
        .iter()
        .zip(valeurs_d_avant(r, h))
        .all(|(c, v)| c.lire() == v)
}

/// Applique et annule, d'un seul passage (un point de restauration, une demande administrateur), puis met
/// l'historique à jour. Retourne la réussite de chaque réglage appliqué, puis de chaque réglage annulé.
fn executer(a_faire: &[&Reglage], a_annuler: &[&Reglage], h: &mut Historique) -> (Vec<bool>, Vec<bool>) {
    let date = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    // Valeurs d'avant notées avant de toucher à quoi que ce soit : la plus ancienne reste, pour revenir à l'état
    // d'origine même après plusieurs passages.
    for r in a_faire {
        h.reglages.entry(r.id.to_string()).or_insert_with(|| Avant {
            date: date.clone(),
            valeurs: r.changements.iter().map(systeme::Changement::lire).collect(),
        });
    }
    // Sans valeurs d'avant notées, un réglage ne pourrait plus s'annuler exactement : rien n'est changé.
    if !a_faire.is_empty() && !sauver(h) {
        return (vec![false; a_faire.len()], vec![false; a_annuler.len()]);
    }
    let mut groupes: Vec<Vec<(&systeme::Changement, Valeur)>> = a_faire
        .iter()
        .map(|r| r.changements.iter().map(|c| (c, c.cible())).collect())
        .collect();
    for r in a_annuler {
        groupes.push(r.changements.iter().zip(valeurs_d_avant(r, h)).collect());
    }
    let resultats = systeme::ecrire(&groupes);
    let (faits, annules) = resultats.split_at(a_faire.len().min(resultats.len()));
    // Échec sans aucun changement : la note n'a pas lieu d'être (en partie fait, elle reste pour pouvoir annuler).
    for (r, ok) in a_faire.iter().zip(faits) {
        if !*ok && etat(r) == Etat::AFaire {
            h.reglages.remove(r.id);
        }
    }
    // Annulé = les valeurs d'avant relues en place, pas seulement des commandes sans erreur : une valeur qu'aucune
    // commande ne sait remettre laisse la note, pour pouvoir réessayer.
    let remis: Vec<bool> = a_annuler
        .iter()
        .zip(annules)
        .map(|(r, ok)| *ok && remis_en_place(r, h))
        .collect();
    for (r, _) in a_annuler.iter().zip(&remis).filter(|(_, remis)| **remis) {
        h.reglages.remove(r.id);
    }
    sauver(h);
    (faits.to_vec(), remis)
}

fn libelle(e: Etat, par_gardien: bool) -> &'static str {
    match (e, par_gardien) {
        (Etat::Fait, true) => tr!("fait par Gardien", "done by Gardien"),
        (Etat::Fait, false) => tr!("déjà fait", "already done"),
        (Etat::EnPartie, _) => tr!("en partie", "partly"),
        (Etat::AFaire, _) => tr!("à faire", "to do"),
    }
}

/// Montre ce qui va changer, demande l'accord, applique, puis relit l'état de chaque réglage.
fn confirmer_et_executer(a_faire: &[&Reglage], a_annuler: &[&Reglage]) {
    let mut h = charger();
    if !a_faire.is_empty() {
        trp!("\n  {GRAS}À appliquer{RESET}", "\n  {GRAS}To apply{RESET}");
        for r in a_faire {
            println!("    {VERT}+{RESET} {}", r.titre);
            for c in &r.changements {
                println!("        {GRIS}{}{RESET}", c.decrire(c.cible().as_deref()));
            }
            if let Some(p) = r.prudence {
                println!("        ⚠ {p}");
            }
        }
    }
    if !a_annuler.is_empty() {
        trp!("\n  {GRAS}À annuler{RESET}", "\n  {GRAS}To undo{RESET}");
        for r in a_annuler {
            let note = if h.reglages.contains_key(r.id) {
                tr!("valeurs d'avant remises", "previous values restored")
            } else {
                tr!("valeurs d'un système neuf", "values of a fresh system")
            };
            println!("    − {} {GRIS}({note}){RESET}", r.titre);
            for (c, v) in r.changements.iter().zip(valeurs_d_avant(r, &h)) {
                println!("        {GRIS}{}{RESET}", c.decrire(v.as_deref()));
            }
        }
    }
    if !demander(tr!(
        "\n  Faire ces changements ? [o/N] : ",
        "\n  Make these changes? [y/N]: "
    ))
    .oui()
    {
        trp!("  Annulé.", "  Cancelled.");
        return;
    }
    let (faits, annules) = executer(a_faire, a_annuler, &mut h);
    println!();
    for (r, ok) in a_faire.iter().zip(&faits).chain(a_annuler.iter().zip(&annules)) {
        // L'état relu après coup : c'est lui qui dit si le changement a pris.
        let e = etat(r);
        let voulu_fait = a_faire.iter().any(|f| f.id == r.id);
        if *ok && (e == Etat::Fait) == voulu_fait {
            println!("  {VERT}✔{RESET} {}", r.titre);
        } else {
            trp!(
                "  ✖ {} : pas changé, voir le message ci-dessus",
                "  ✖ {}: not changed, see the message above",
                r.titre
            );
        }
    }
    let touches: Vec<&Reglage> = a_faire.iter().chain(a_annuler).copied().collect();
    systeme::apres(&touches);
}

/// Cette catégorie a-t-elle au moins un réglage pour cette machine ?
pub fn a_des_reglages(categorie: Categorie) -> bool {
    systeme::catalogue().iter().any(|r| r.categorie == categorie)
}

/// Une catégorie : liste à cocher. Coché = réglage en place ; cocher applique, décocher annule.
pub fn menu(categorie: Categorie) {
    let reglages: Vec<Reglage> = systeme::catalogue()
        .into_iter()
        .filter(|r| r.categorie == categorie)
        .collect();
    if reglages.is_empty() {
        titre(categorie.titre());
        trp!(
            "  {GRIS}Rien dans cette catégorie pour ce système.{RESET}",
            "  {GRIS}Nothing in this category for this system.{RESET}"
        );
        return;
    }
    let h = charger();
    let etats: Vec<Etat> = reglages.iter().map(etat).collect();
    let cases: Vec<Case> = reglages
        .iter()
        .zip(&etats)
        .map(|(r, e)| Case {
            texte: r.titre.to_string(),
            precision: libelle(*e, h.reglages.contains_key(r.id)).to_string(),
            detail: match r.prudence {
                Some(p) => format!("{} ⚠ {p}", r.effet),
                None => r.effet.to_string(),
            },
            cochee: *e == Etat::Fait,
            recommandee: r.recommande,
            fixe: false,
        })
        .collect();
    let entete = vec![
        String::new(),
        ligne_titre(categorie.titre()),
        trf!(
            "  {GRIS}Coché = réglage en place. Ce que tu coches s'applique, ce que tu décoches s'annule.{RESET}",
            "  {GRIS}Checked = setting in place. What you check is applied, what you uncheck is undone.{RESET}"
        ),
        String::new(),
    ];
    let Some(voulu) = cocher(&entete, &cases) else {
        return;
    };
    let a_faire: Vec<&Reglage> = reglages
        .iter()
        .zip(&etats)
        .zip(&voulu)
        .filter(|((_, e), v)| **v && **e != Etat::Fait)
        .map(|((r, _), _)| r)
        .collect();
    let a_annuler: Vec<&Reglage> = reglages
        .iter()
        .zip(&etats)
        .zip(&voulu)
        .filter(|((_, e), v)| !**v && **e == Etat::Fait)
        .map(|((r, _), _)| r)
        .collect();
    if a_faire.is_empty() && a_annuler.is_empty() {
        trp!("  {GRIS}Rien à changer.{RESET}", "  {GRIS}Nothing to change.{RESET}");
        return;
    }
    confirmer_et_executer(&a_faire, &a_annuler);
}

/// Tous les réglages recommandés qui ne sont pas encore en place, en une fois.
pub fn recommandes() {
    titre(tr!("Réglages recommandés", "Recommended settings"));
    let reglages = systeme::catalogue();
    let a_faire: Vec<&Reglage> = reglages
        .iter()
        .filter(|r| r.recommande && etat(r) != Etat::Fait)
        .collect();
    if a_faire.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Les réglages recommandés sont déjà en place.",
            "  {VERT}✔{RESET} The recommended settings are already in place."
        );
        return;
    }
    trp!(
        "  Sans revers pour la plupart des gens, et chacun s'annule depuis sa catégorie.",
        "  No downside for most people, and each one can be undone from its category."
    );
    confirmer_et_executer(&a_faire, &[]);
}

/// Annule tout ce que Gardien a changé : les valeurs notées avant chaque changement reviennent.
pub fn tout_annuler() {
    titre(tr!("Tout remettre comme avant", "Put everything back"));
    let h = charger();
    let reglages = systeme::catalogue();
    let a_annuler: Vec<&Reglage> = reglages.iter().filter(|r| h.reglages.contains_key(r.id)).collect();
    if a_annuler.is_empty() {
        trp!(
            "  {GRIS}Gardien n'a changé aucun réglage sur cette machine.{RESET}",
            "  {GRIS}Gardien has not changed any setting on this machine.{RESET}"
        );
        return;
    }
    confirmer_et_executer(&[], &a_annuler);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_complet_et_sans_doublon() {
        let c = systeme::catalogue();
        let mut ids: Vec<&str> = c.iter().map(|r| r.id).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "deux réglages ont le même id");
        for r in &c {
            assert!(!r.titre.is_empty() && !r.effet.is_empty(), "{}", r.id);
            assert!(!r.changements.is_empty(), "{} ne change rien", r.id);
            // Le titre tient dans la liste à cocher sans être coupé.
            assert!(largeur_affichee(r.titre) <= 42, "{} : titre trop long", r.id);
        }
    }

    #[test]
    fn historique_relu_tel_quel() {
        let mut h = Historique::default();
        h.reglages.insert(
            "x".into(),
            Avant {
                date: "2026-10-17 21:00".into(),
                valeurs: vec![Some("dword:1".into()), None],
            },
        );
        let relu: Historique = serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        assert_eq!(relu.reglages["x"].valeurs, [Some("dword:1".to_string()), None]);
    }

    /// Un historique tronqué (coupure pendant l'écriture) n'est pas pris pour vide puis écrasé : il est mis de côté.
    #[test]
    fn historique_illisible_mis_de_cote() {
        let chemin = fichier_historique();
        let dossier = chemin.parent().unwrap();
        std::fs::create_dir_all(dossier).unwrap();
        std::fs::write(&chemin, "{\"reglages\":{\"x\":{\"date\":\"2026-10").unwrap();
        assert!(charger().reglages.is_empty());
        let copies = std::fs::read_dir(dossier)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("reglages.illisible-"))
            .count();
        assert!(copies >= 1, "le fichier illisible n'a pas été gardé");
        let mut h = Historique::default();
        h.reglages.insert(
            "x".into(),
            Avant {
                date: "2026-10-18 01:00".into(),
                valeurs: vec![Some("1".into())],
            },
        );
        assert!(sauver(&h));
        assert_eq!(charger().reglages["x"].valeurs, [Some("1".to_string())]);
    }

    /// L'annulation se juge sur les valeurs relues : une ligne qui était absente doit l'être de nouveau.
    #[cfg(target_os = "linux")]
    #[test]
    fn annulation_jugee_sur_les_valeurs_relues() {
        let f = std::env::temp_dir().join(format!("gardien-test-annuler-{}", std::process::id()));
        std::fs::write(&f, "ENABLED=0\n").unwrap();
        let chemin: &'static str = Box::leak(f.display().to_string().into_boxed_str());
        let r = Reglage {
            id: "essai",
            categorie: Categorie::Confort,
            titre: "Essai",
            effet: "Essai",
            prudence: None,
            recommande: false,
            changements: vec![systeme::Changement::Option {
                fichier: chemin,
                cle: "ENABLED",
                cible: "0",
                defaut: "1",
            }],
        };
        let mut h = Historique::default();
        h.reglages.insert(
            "essai".into(),
            Avant {
                date: String::new(),
                valeurs: vec![None],
            },
        );
        assert!(!remis_en_place(&r, &h), "la ligne posée par Gardien est encore là");
        std::fs::write(&f, "# ligne retirée\n").unwrap();
        assert!(remis_en_place(&r, &h));
        // Sans note, c'est la valeur d'un système neuf qui doit revenir.
        assert!(!remis_en_place(&r, &Historique::default()));
        std::fs::write(&f, "ENABLED=1\n").unwrap();
        assert!(remis_en_place(&r, &Historique::default()));
        let _ = std::fs::remove_file(&f);
    }
}
