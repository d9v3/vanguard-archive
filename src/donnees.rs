//! Sauvegarde et restauration des données de netscan dans un seul fichier : base des appareils (surnoms,
//! historique de chaque réseau) et état de la surveillance. Sert à passer d'un ordinateur à l'autre sans la clé,
//! ou à garder une copie avant d'effacer la clé.
//! La quarantaine de l'antivirus n'y va jamais : on ne transporte pas de malware.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::reseau::{self, Contenu};
use crate::surveillance;
use crate::ui::*;

const FORMAT: &str = "netscan-sauvegarde";

#[derive(Serialize, Deserialize)]
struct Sauvegarde {
    format: String,
    #[serde(default)]
    version_netscan: String,
    #[serde(default)]
    date: String,
    #[serde(default)]
    surveillance: Option<bool>,
    base: serde_json::Value,
}

/// Dossier proposé : Documents sous Windows, le dossier personnel sous Linux.
fn dossier_par_defaut() -> PathBuf {
    #[cfg(windows)]
    {
        let profil = PathBuf::from(std::env::var_os("USERPROFILE").unwrap_or_default());
        let documents = profil.join("Documents");
        if documents.is_dir() { documents } else { profil }
    }
    #[cfg(not(windows))]
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}

fn chemin_par_defaut() -> PathBuf {
    dossier_par_defaut().join(format!(
        "netscan-sauvegarde-{}.json",
        chrono::Local::now().format("%Y-%m-%d")
    ))
}

/// Chemin tapé ou collé : sans guillemets (« Copier en tant que chemin » de Windows en ajoute), « ~/ » développé.
fn chemin_saisi(texte: &str) -> Option<PathBuf> {
    let t = texte.trim().trim_matches('"').trim_matches('\'');
    if t.is_empty() {
        return None;
    }
    Some(match t.strip_prefix("~/") {
        Some(reste) => PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(reste),
        None => PathBuf::from(t),
    })
}

/// Lit une sauvegarde netscan, ou directement un appareils.json (la base copiée à la main depuis la clé).
/// Rend la base et l'état de la surveillance s'il est connu.
fn lire_sauvegarde(texte: &str) -> Result<(serde_json::Value, Option<bool>), String> {
    let valeur: serde_json::Value = serde_json::from_str(texte.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("ce n'est pas un fichier JSON lisible ({e})"))?;
    if valeur.get("format").and_then(|f| f.as_str()) == Some(FORMAT) {
        let s: Sauvegarde = serde_json::from_value(valeur).map_err(|e| format!("sauvegarde abîmée ({e})"))?;
        return Ok((s.base, s.surveillance));
    }
    if valeur.get("reseaux").is_some_and(serde_json::Value::is_object) {
        return Ok((valeur, None));
    }
    Err("ce fichier n'est ni une sauvegarde netscan ni une base appareils.json".into())
}

fn decrire(c: &Contenu) -> String {
    format!(
        "{} réseau(x), {} appareil(s), dont {} avec un surnom",
        c.reseaux, c.appareils, c.surnoms
    )
}

pub fn sauvegarder(fichier: Option<PathBuf>) {
    let fichier = fichier.unwrap_or_else(chemin_par_defaut);
    let (base, contenu) = reseau::base_pour_sauvegarde();
    let sauvegarde = Sauvegarde {
        format: FORMAT.into(),
        version_netscan: env!("CARGO_PKG_VERSION").into(),
        date: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        surveillance: Some(surveillance::active()),
        base,
    };
    let json = serde_json::to_string_pretty(&sauvegarde).unwrap_or_default();
    match reseau::ecrire_atomique(&fichier, &json) {
        Ok(()) => println!(
            "  {VERT}✔{RESET} Sauvegarde écrite : {}\n  {}.",
            fichier.display(),
            decrire(&contenu)
        ),
        Err(e) => println!("  ✖ Impossible d'écrire {} ({e}).", fichier.display()),
    }
}

pub fn restaurer(fichier: &Path) {
    let texte = match std::fs::read_to_string(fichier) {
        Ok(t) => t,
        Err(e) => {
            println!("  ✖ Impossible de lire {} ({e}).", fichier.display());
            return;
        }
    };
    let (base, surveillance_avant) = match lire_sauvegarde(&texte) {
        Ok(r) => r,
        Err(e) => {
            println!("  ✖ Rien de restauré : {e}.");
            return;
        }
    };
    match reseau::restaurer_base(base) {
        Ok(c) => println!(
            "  {VERT}✔{RESET} Ajouté à la base actuelle : {}.\n  {GRIS}Rien n'a été effacé : les fiches communes ont été fusionnées (le surnom le plus récent gagne).{RESET}",
            decrire(&c)
        ),
        Err(e) => {
            println!("  ✖ Rien de restauré : {e}.");
            return;
        }
    }
    if surveillance_avant == Some(true)
        && !surveillance::active()
        && demander("  La surveillance horaire était activée : la réactiver ici ? [o/N] : ").eq_ignore_ascii_case("o")
    {
        surveillance::activer(true);
    }
}

pub fn menu() {
    titre("Données de netscan");
    println!("  Base des appareils (surnoms, historique de chaque réseau) et état de la surveillance.");
    println!("  {GRIS}La quarantaine de l'antivirus n'est jamais sauvegardée.{RESET}\n");
    println!("  1. Sauvegarder dans un fichier");
    println!("  2. Restaurer depuis un fichier (ajouté à la base actuelle, rien n'est effacé)");
    match demander("\nChoix (Entrée pour revenir) : ").as_str() {
        "1" => {
            let defaut = chemin_par_defaut();
            let saisi = demander(&format!("  Fichier (Entrée pour {}) : ", defaut.display()));
            let fichier = chemin_saisi(&saisi).unwrap_or(defaut);
            if fichier.exists()
                && !demander(&format!(
                    "  {} existe déjà : le remplacer ? [o/N] : ",
                    fichier.display()
                ))
                .eq_ignore_ascii_case("o")
            {
                println!("  Annulé.");
                return;
            }
            sauvegarder(Some(fichier));
        }
        "2" => match chemin_saisi(&demander(
            "  Fichier à restaurer (tu peux le glisser dans la fenêtre) : ",
        )) {
            Some(f) => restaurer(&f),
            None => println!("  Annulé."),
        },
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_acceptes() {
        let s = format!(
            "\u{feff}{{\"format\":\"{FORMAT}\",\"version_netscan\":\"0.9.13\",\"date\":\"2026-10-17\",\"surveillance\":true,\"base\":{{\"reseaux\":{{}}}}}}"
        );
        let (base, surv) = lire_sauvegarde(&s).unwrap();
        assert_eq!((base["reseaux"].is_object(), surv), (true, Some(true)));
        // Une base appareils.json copiée telle quelle.
        let (base, surv) = lire_sauvegarde("{\"reseaux\":{\"box\":{\"nom\":null,\"appareils\":{}}}}").unwrap();
        assert_eq!((base["reseaux"]["box"].is_object(), surv), (true, None));
        assert!(lire_sauvegarde("{\"autre\":1}").is_err());
        assert!(lire_sauvegarde("pas du json").is_err());
        assert!(lire_sauvegarde(&format!("{{\"format\":\"{FORMAT}\"}}")).is_err());
    }

    #[test]
    fn chemins_saisis() {
        assert_eq!(chemin_saisi("  "), None);
        assert_eq!(
            chemin_saisi("\"C:\\Users\\moi\\sauvegarde.json\""),
            Some(PathBuf::from("C:\\Users\\moi\\sauvegarde.json"))
        );
        assert_eq!(chemin_saisi("'/tmp/a b.json' "), Some(PathBuf::from("/tmp/a b.json")));
    }
}
