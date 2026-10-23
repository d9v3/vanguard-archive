//! Cale : `crate::http::Demande`, que les modules inclus préparent sans jamais l'envoyer ici.

#![allow(dead_code)]

use std::time::Duration;

pub(crate) struct Demande<'a> {
    pub adresse: &'a str,
    pub delai: Duration,
    pub taille_max: u64,
    pub meme_hote: bool,
}

impl<'a> Demande<'a> {
    pub(crate) fn get(adresse: &'a str, delai: Duration) -> Self {
        Demande {
            adresse,
            delai,
            taille_max: 64 << 20,
            meme_hote: false,
        }
    }
}
