//! Cale : ce que les modules inclus demandent à `crate::socle`. `adresses` est le vrai module (il décide quelles
//! adresses de la liste d'Échap sont gardées) ; le cache ne sert qu'à télécharger, ce que le fuzzing ne fait jamais :
//! il reprend la cale d'`abuse_ch`, qui répond « pas de réponse ».

#![allow(dead_code)]

#[path = "../../src/socle/adresses.rs"]
pub mod adresses;

pub mod cache {
    pub(crate) use crate::protection::abuse_ch::{Echec, Liste, liste};
}

pub fn dossier_local() -> std::path::PathBuf {
    crate::reseau::dossier_local()
}
