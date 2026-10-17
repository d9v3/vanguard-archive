//! Mises à jour : système, programmes, pilotes et firmware vérifiés d'un coup, puis installés après accord
//! (mêmes étapes que « netscan corriger » ; « [t]out » passe par une seule fenêtre administrateur sous Windows).

use crate::machine::{self, Constat};
use crate::ui::*;

fn verifier() -> Vec<Constat> {
    println!(
        "  {GRIS}Recherche en cours (jusqu'à deux minutes : les serveurs de mises à jour sont interrogés)…{RESET}"
    );
    let constats = machine::mises_a_jour_completes();
    machine::afficher_constats(&constats);
    constats
}

/// « Tout est à jour » seulement si rien n'est à faire et que tout a pu être vérifié.
fn tout_a_jour(constats: &[Constat]) -> bool {
    if constats.iter().any(|c| c.correctif.is_some()) {
        return false;
    }
    let impossibles = constats.iter().filter(|c| !c.verifie).count();
    if impossibles == 0 {
        println!("\n  {VERT}✔ Tout est à jour.{RESET}");
    } else {
        println!("\n  ⚠ {impossibles} vérification(s) impossible(s) : je ne peux pas dire que tout est à jour.");
    }
    true
}

pub fn executer() {
    titre("Mises à jour");
    let constats = verifier();
    if tout_a_jour(&constats) {
        return;
    }
    titre("Installation");
    if crate::corriger::proposer(&constats) {
        titre("Nouvelle vérification");
        tout_a_jour(&verifier());
    }
}
