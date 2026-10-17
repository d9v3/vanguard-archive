//! Mises à jour : système, programmes, pilotes et firmware vérifiés d'un coup, puis installés après accord
//! (mêmes étapes que « sentinel corriger » ; « [t]out » passe par une seule fenêtre administrateur sous Windows).

use crate::machine::{self, Constat};
use crate::ui::*;

/// `seulement` : après une installation, les catégories installées, pour ne pas refaire toutes les recherches.
fn verifier(seulement: Option<&[&str]>) -> Vec<Constat> {
    trp!(
        "  {GRIS}Recherche en cours (jusqu'à deux minutes : les serveurs de mises à jour sont interrogés)…{RESET}",
        "  {GRIS}Searching (up to two minutes: the update servers are queried)…{RESET}"
    );
    let constats = machine::mises_a_jour_completes(seulement);
    machine::afficher_constats(&constats);
    constats
}

pub fn executer() {
    titre(tr!("Mises à jour", "Updates"));
    let constats = verifier(None);
    if constats.iter().all(|c| c.correctif.is_none()) {
        let impossibles = constats.iter().filter(|c| !c.verifie).count();
        if impossibles == 0 {
            trp!(
                "\n  {VERT}✔ Tout est à jour.{RESET}",
                "\n  {VERT}✔ Everything is up to date.{RESET}"
            );
        } else {
            trp!(
                "\n  ⚠ {impossibles} vérification(s) impossible(s) : je ne peux pas dire que tout est à jour.",
                "\n  ⚠ {impossibles} check(s) could not be done: I cannot say everything is up to date."
            );
        }
        return;
    }
    titre("Installation");
    let installees = crate::corriger::proposer(&constats, tr!("mises à jour", "updates"));
    if installees.is_empty() {
        return;
    }
    titre(tr!(
        "Nouvelle vérification de ce qui a été installé",
        "Checking again what was installed"
    ));
    let apres = verifier(Some(&installees));
    let restent = apres
        .iter()
        .filter(|c| installees.contains(&c.categorie) && c.correctif.is_some());
    if restent.count() == 0 {
        trp!(
            "\n  {VERT}✔ Installé et vérifié.{RESET}",
            "\n  {VERT}✔ Installed and checked.{RESET}"
        );
    }
}
