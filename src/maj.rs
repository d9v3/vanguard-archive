//! Mises à jour : système, programmes, pilotes et firmware vérifiés d'un coup, puis installés après accord.
//! Sous Windows, « tout installer » passe par une seule fenêtre administrateur (une seule demande UAC).

use crate::machine::{self, Constat, Correctif};
use crate::ui::*;

fn corrections(constats: &[Constat], automatique: bool) -> Vec<(&Constat, &Correctif)> {
    constats
        .iter()
        .filter_map(|c| Some((c, c.correctif.as_ref().filter(|k| k.automatique == automatique)?)))
        .collect()
}

fn verifier() -> Vec<Constat> {
    println!("  {GRIS}Recherche en cours (jusqu'à deux minutes : les serveurs de mises à jour sont interrogés)…{RESET}");
    machine::mises_a_jour_completes()
}

pub fn executer() {
    titre("Mises à jour");
    let constats = verifier();
    machine::afficher_constats(&constats);
    let auto = corrections(&constats, true);
    let manuels = corrections(&constats, false);
    let impossibles = constats.iter().filter(|c| !c.verifie).count();

    if auto.is_empty() && manuels.is_empty() {
        if impossibles == 0 {
            println!("\n  {VERT}✔ Tout est à jour.{RESET}");
        } else {
            println!("\n  ⚠ {impossibles} vérification(s) impossible(s) : je ne peux pas dire que tout est à jour.");
        }
        return;
    }

    let mut applique = false;
    if !auto.is_empty() {
        println!("\n  {GRAS}À installer{RESET} :");
        for (_, k) in &auto {
            println!("  🔧 {}", k.action);
        }
        let rep = demander("\n  Tout installer maintenant ? [o]ui / [c]hoisir une par une / [N]on : ").to_lowercase();
        if rep == "o" || rep == "oui" {
            // Une seule exécution : sous Windows, une seule fenêtre administrateur pour tout.
            let commandes: Vec<String> = auto.iter().flat_map(|(_, k)| k.commandes.clone()).collect();
            applique = true;
            if machine::appliquer(&commandes) {
                println!("  {VERT}✔ Installation terminée.{RESET}");
            } else {
                println!("  ✖ Une étape a échoué : lis le message ci-dessus.");
            }
        } else if rep == "c" {
            for (c, k) in &auto {
                println!("\n  {GRAS}{}{RESET} — {}", c.categorie, c.message);
                if !demander(&format!("  {} ? [o/N] : ", k.action)).eq_ignore_ascii_case("o") {
                    println!("    {GRIS}ignoré{RESET}");
                    continue;
                }
                applique = true;
                if machine::appliquer(&k.commandes) {
                    println!("    {VERT}✔ fait{RESET}");
                } else {
                    println!("    ✖ non appliqué : voir le message ci-dessus");
                }
            }
        } else {
            println!("  Rien n'a été installé.");
        }
    }

    if !manuels.is_empty() {
        titre("À faire toi-même");
        for (c, k) in &manuels {
            println!("  💡 {GRAS}{}{RESET} : {}", c.categorie, k.action);
            for cmd in &k.commandes {
                println!("     {GRIS}{cmd}{RESET}");
            }
        }
    }

    if applique {
        titre("Nouvelle vérification");
        let apres = verifier();
        let restants: Vec<&Constat> = apres.iter().filter(|c| c.correctif.is_some()).collect();
        if restants.is_empty() && apres.iter().all(|c| c.verifie) {
            println!("  {VERT}✔ Tout est à jour.{RESET}");
        } else {
            machine::afficher_constats(&apres);
        }
    }
}
