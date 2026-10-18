//! Optimiser : réglages de confidentialité, de performance et de confort, écrits pour Gardien. Chaque réglage montre
//! son état réel, explique ce qu'il change et s'applique après accord, avec un point de restauration si le système est
//! touché. Il s'annule exactement : la valeur d'avant est notée au moment du changement, puis remise telle quelle ;
//! sans note (réglage fait ailleurs), c'est la valeur d'un système neuf qui revient. Aucun réglage n'affaiblit la
//! sécurité, et ceux qui ne conviennent pas à cette machine (version du système, bureau, matériel) ne sont pas proposés.

#[cfg(windows)]
mod defender;
mod demarrage;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub use demarrage::menu as programmes_au_demarrage;

#[cfg(target_os = "linux")]
use linux as systeme;
#[cfg(target_os = "macos")]
use macos as systeme;
#[cfg(windows)]
use windows as systeme;

use std::borrow::Cow;
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
    /// Protections de Defender qui bloquent les attaques (Windows seulement).
    #[cfg_attr(not(windows), allow(dead_code))]
    Protection,
}

impl Categorie {
    pub fn titre(self) -> &'static str {
        match self {
            Categorie::Confidentialite => tr!("Confidentialité", "Privacy"),
            Categorie::Performance => tr!("Performance et fiabilité", "Performance and reliability"),
            Categorie::Confort => tr!("Confort et fichiers", "Comfort and files"),
            Categorie::Protection => tr!("Protection contre les attaques", "Protection against attacks"),
        }
    }
}

/// Un réglage proposé par Gardien.
pub struct Reglage {
    /// Nom stable, noté dans l'historique pour pouvoir annuler. Construit à la demande pour un programme au
    /// démarrage (« demarrage:… »), fixe pour le catalogue.
    pub id: Cow<'static, str>,
    pub categorie: Categorie,
    pub titre: Cow<'static, str>,
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
    let notees = h.reglages.get(r.id.as_ref());
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
            h.reglages.remove(r.id.as_ref());
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
        h.reglages.remove(r.id.as_ref());
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

/// Ce qui va changer, montré avant de demander : chaque réglage, ses changements, et son revers coupé pour tenir
/// dans `LARGEUR` (d'une traite, le terminal le coupait au milieu des mots).
fn a_changer(a_faire: &[&Reglage], a_annuler: &[&Reglage], h: &Historique) -> Vec<String> {
    let mut lignes = Vec::new();
    if !a_faire.is_empty() {
        lignes.push(trf!("\n  {GRAS}À appliquer{RESET}", "\n  {GRAS}To apply{RESET}"));
        for r in a_faire {
            lignes.push(format!("    {VERT}+{RESET} {}", r.titre));
            for c in &r.changements {
                lignes.push(format!("        {GRIS}{}{RESET}", c.decrire(c.cible().as_deref())));
            }
            if let Some(p) = r.prudence {
                let mut morceaux = envelopper(p, LARGEUR - 10).into_iter();
                lignes.extend(morceaux.next().map(|m| format!("        ⚠ {m}")));
                lignes.extend(morceaux.map(|m| format!("          {m}")));
            }
        }
    }
    if !a_annuler.is_empty() {
        lignes.push(trf!("\n  {GRAS}À annuler{RESET}", "\n  {GRAS}To undo{RESET}"));
        for r in a_annuler {
            let note = if h.reglages.contains_key(r.id.as_ref()) {
                tr!("valeurs d'avant remises", "previous values restored")
            } else {
                tr!("valeurs d'un système neuf", "values of a fresh system")
            };
            lignes.push(format!("    − {} {GRIS}({note}){RESET}", r.titre));
            for (c, v) in r.changements.iter().zip(valeurs_d_avant(r, h)) {
                lignes.push(format!("        {GRIS}{}{RESET}", c.decrire(v.as_deref())));
            }
        }
    }
    lignes
}

/// Montre ce qui va changer, demande l'accord, applique, puis relit l'état de chaque réglage.
fn confirmer_et_executer(a_faire: &[&Reglage], a_annuler: &[&Reglage]) {
    let mut h = charger();
    for l in a_changer(a_faire, a_annuler, &h) {
        println!("{l}");
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

/// L'en-tête de la liste à cocher d'une catégorie, sur deux lignes : plus large que `LARGEUR`, il passait sur deux
/// rangées du terminal et décalait la liste, qui compte une rangée par ligne.
fn entete(categorie: Categorie) -> Vec<String> {
    vec![
        String::new(),
        ligne_titre(categorie.titre()),
        trf!(
            "  {GRIS}Coché = réglage en place. Ce que tu coches s'applique,{RESET}\n  {GRIS}ce que tu décoches s'annule.{RESET}",
            "  {GRIS}Checked = setting in place. What you check is applied,{RESET}\n  {GRIS}what you uncheck is undone.{RESET}"
        ),
        String::new(),
    ]
}

/// L'accès contrôlé aux dossiers de Defender bloque-t-il les écritures (mode 1) ? Pour expliquer un refus.
#[cfg(windows)]
pub fn dossiers_controles_actifs() -> bool {
    let e = defender::etat();
    e.actif && e.valeur(defender::Pref::DossiersControles).as_deref() == Some("mp:1")
}

/// Les protections de Defender : seulement s'il est l'antivirus actif, puisque sinon ses blocages ne s'appliquent
/// pas (un autre antivirus le met en mode passif).
pub fn protection() {
    #[cfg(windows)]
    if !windows::defender_actif() {
        titre(Categorie::Protection.titre());
        afficher_aligne(
            "  ",
            tr!(
                "Microsoft Defender n'est pas l'antivirus actif ici (coupé, ou remplacé par un autre antivirus) : ses blocages ne s'appliqueraient pas. Rien à proposer.",
                "Microsoft Defender is not the active antivirus here (off, or replaced by another antivirus): its blocking would not apply. Nothing to offer."
            ),
            2,
            "",
        );
        return;
    }
    menu(Categorie::Protection);
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
            precision: libelle(*e, h.reglages.contains_key(r.id.as_ref())).to_string(),
            detail: match r.prudence {
                Some(p) => format!("{} ⚠ {p}", r.effet),
                None => r.effet.to_string(),
            },
            cochee: *e == Etat::Fait,
            recommandee: r.recommande,
            fixe: false,
        })
        .collect();
    let Some(voulu) = cocher(&entete(categorie), &cases) else {
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
    let sans_revers = tr!(
        "Sans revers pour la plupart des gens, et chacun s'annule depuis sa catégorie.",
        "No downside for most people, and each one can be undone from its category."
    );
    afficher_aligne("  ", sans_revers, 2, "");
    confirmer_et_executer(&a_faire, &[]);
}

/// Ce que dit un réglage de DNS : les serveurs imposés, ou ceux de la box. `avec_box` : ceux de la box servent encore
/// après les serveurs listés.
fn texte_dns(serveurs: &[&str], avec_box: bool) -> String {
    match (serveurs.is_empty(), avec_box) {
        (true, _) => tr!("DNS automatique : celui de la box", "automatic DNS: the router's").to_string(),
        (false, false) => trf!("DNS : {}", "DNS: {}", serveurs.join(", ")),
        (false, true) => trf!(
            "DNS : {}, puis celui de la box",
            "DNS: {}, then the router's",
            serveurs.join(", ")
        ),
    }
}

/// Le réglage du DNS le plus rapide (outil Réseau et Internet › DNS) : construit à la demande, hors des catégories,
/// noté et annulé comme les autres.
const DNS: &str = "dns_rapide";

fn reglage_dns(c: systeme::Changement) -> Reglage {
    Reglage {
        id: Cow::Borrowed(DNS),
        // Hors des menus de catégorie (il n'est pas au catalogue) : la catégorie ne sert pas.
        categorie: Categorie::Confort,
        titre: tr!("DNS le plus rapide", "Fastest DNS").into(),
        effet: tr!(
            "Les noms de sites sont traduits par le DNS le plus rapide mesuré ici.",
            "Site names are translated by the fastest DNS measured here."
        ),
        prudence: None,
        recommande: false,
        changements: vec![c],
    }
}

/// Les réglages hors catalogue que Gardien a appliqués et pas encore annulés : ceux dont une note garde la valeur
/// d'avant (le DNS, les programmes retirés du démarrage).
fn hors_catalogue(h: &Historique) -> Vec<Reglage> {
    let mut l: Vec<Reglage> = h
        .reglages
        .get(DNS)
        .and_then(|a| a.valeurs.first().cloned().flatten())
        .and_then(|v| systeme::Changement::dns_note(&v))
        .map(reglage_dns)
        .into_iter()
        .collect();
    l.extend(demarrage::notes(h));
    l
}

/// Le DNS changé par Gardien, s'il l'a fait : (date du changement, réseau concerné : connexion, carte ou service).
pub fn dns_change() -> Option<(String, String)> {
    let h = charger();
    let a = h.reglages.get(DNS)?;
    let (reseau, _) = a.valeurs.first()?.as_deref()?.split_once('\n')?;
    Some((a.date.clone(), reseau.to_string()))
}

/// Règle le DNS de la connexion principale sur ces serveurs, après accord, comme un réglage : la valeur d'avant est
/// notée, et « Tout remettre comme avant » la remet. Erreur : pourquoi ce n'est pas possible ici.
pub fn appliquer_dns(serveurs4: &[&str], serveurs6: &[&str]) -> Result<(), String> {
    let c = systeme::dns_principal(serveurs4, serveurs6)?;
    // Une seule valeur d'avant se garde : celle d'un autre réseau doit d'abord revenir.
    if let Some((_, reseau)) = dns_change()
        && Some(reseau.as_str()) != c.identite_dns()
    {
        return Err(tr!(
            "Gardien a déjà changé le DNS d'une autre connexion : remets-le d'abord (Optimiser › Tout remettre comme avant).",
            "Gardien already changed the DNS of another connection: put it back first (Optimize › Put everything back)."
        )
        .to_string());
    }
    let r = reglage_dns(c);
    if etat(&r) == Etat::Fait {
        trp!(
            "  {VERT}✔{RESET} Ce DNS est déjà en place.",
            "  {VERT}✔{RESET} This DNS is already in place."
        );
        return Ok(());
    }
    confirmer_et_executer(&[&r], &[]);
    Ok(())
}

/// Remet le DNS d'avant le changement de Gardien, après accord.
pub fn remettre_dns() {
    let h = charger();
    let reglages = hors_catalogue(&h);
    if let Some(r) = reglages.first() {
        confirmer_et_executer(&[], &[r]);
    }
}

/// Annule tout ce que Gardien a changé : les valeurs notées avant chaque changement reviennent.
pub fn tout_annuler() {
    titre(tr!("Tout remettre comme avant", "Put everything back"));
    let h = charger();
    let mut reglages = systeme::catalogue();
    reglages.extend(hors_catalogue(&h));
    let a_annuler: Vec<&Reglage> = reglages
        .iter()
        .filter(|r| h.reglages.contains_key(r.id.as_ref()))
        .collect();
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
        let mut ids: Vec<&str> = c.iter().map(|r| r.id.as_ref()).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "deux réglages ont le même id");
        for r in &c {
            assert!(!r.titre.is_empty() && !r.effet.is_empty(), "{}", r.id);
            assert!(!r.changements.is_empty(), "{} ne change rien", r.id);
            // Le titre tient dans la liste à cocher sans être coupé.
            assert!(largeur_affichee(&r.titre) <= 42, "{} : titre trop long", r.id);
        }
    }

    /// Les messages d'Optimiser et des programmes au démarrage tiennent dans `LARGEUR` colonnes, dans les deux
    /// langues.
    #[test]
    fn messages_dans_la_largeur() {
        let larges: Vec<String> = [include_str!("mod.rs"), include_str!("demarrage.rs")]
            .into_iter()
            .flat_map(crate::gaming::tests::textes_trop_larges)
            .collect();
        assert_eq!(larges, Vec::<String>::new());
    }

    /// L'en-tête de chaque catégorie tient dans `LARGEUR` : plus large, il passait sur deux rangées du terminal et
    /// décalait la liste à cocher, qui compte une rangée par ligne.
    #[test]
    fn entete_dans_la_largeur() {
        for c in [
            Categorie::Confidentialite,
            Categorie::Performance,
            Categorie::Confort,
            Categorie::Protection,
        ] {
            for l in entete(c).iter().flat_map(|t| t.split('\n')) {
                assert!(largeur_affichee(l) <= LARGEUR, "{} colonnes : {l}", largeur_affichee(l));
            }
        }
    }

    /// Les lignes d'un revers, dans ce qui va changer.
    fn revers_trop_larges(lignes: &[String]) -> Vec<String> {
        let changement = format!("        {GRIS}");
        lignes
            .iter()
            .flat_map(|t| t.split('\n'))
            .filter(|l| !l.starts_with(&changement) && largeur_affichee(l) > LARGEUR)
            .map(str::to_string)
            .collect()
    }

    /// Avant de demander, ce qui va changer montre le revers de chaque réglage, coupé pour tenir dans `LARGEUR` ;
    /// les changements eux-mêmes (clé du registre, commande) restent entiers.
    #[test]
    fn changements_dans_la_largeur() {
        let catalogue = systeme::catalogue();
        let tous: Vec<&Reglage> = catalogue.iter().collect();
        assert_eq!(
            revers_trop_larges(&a_changer(&tous, &[], &Historique::default())),
            Vec::<String>::new()
        );
        #[cfg(target_os = "linux")]
        {
            let r = Reglage {
                id: "essai".into(),
                categorie: Categorie::Confort,
                titre: "Essai".into(),
                effet: "Essai",
                prudence: Some(
                    "Courrier, Calendrier et les autres applications du Store n'enverront plus de notifications une fois fermées.",
                ),
                recommande: false,
                changements: vec![systeme::Changement::Option {
                    fichier: "/etc/essai.conf",
                    cle: "ESSAI",
                    cible: "0",
                    defaut: "1",
                }],
            };
            assert_eq!(
                revers_trop_larges(&a_changer(&[&r], &[], &Historique::default())),
                Vec::<String>::new()
            );
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
            id: "essai".into(),
            categorie: Categorie::Confort,
            titre: "Essai".into(),
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
