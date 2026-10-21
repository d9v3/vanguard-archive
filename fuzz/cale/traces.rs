//! Cale : ce que `traces/chronologie.rs` demande à son module parent (`super::`). Les types gardent leurs champs ;
//! l'écriture des fichiers et l'en-tête, que le fuzzing n'appelle pas, ne font rien.

#![allow(dead_code)]

use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Bi {
    pub(crate) fr: String,
    pub(crate) en: String,
}

impl Bi {
    pub(crate) fn new(fr: impl Into<String>, en: impl Into<String>) -> Bi {
        Bi {
            fr: fr.into(),
            en: en.into(),
        }
    }
}

macro_rules! bi {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        $crate::traces::Bi::new(format!($fr $(, $arg)*), format!($en $(, $arg)*))
    };
}
pub(crate) use bi;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Raison {
    Lignes(usize),
}

impl Raison {
    pub(crate) fn note(&self) -> String {
        match self {
            Raison::Lignes(n) => format!("({n})"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Manque {
    pub quoi: Bi,
    pub raison: Raison,
}

pub(crate) struct Partie {
    pub titre: Bi,
    pub compte: Option<Bi>,
    pub manques: Vec<Manque>,
    pub evenements: Vec<crate::chronologie::Evenement>,
}

impl Partie {
    pub(crate) fn new(titre: Bi) -> Partie {
        Partie {
            titre,
            compte: None,
            manques: Vec::new(),
            evenements: Vec::new(),
        }
    }

    pub(crate) fn manque(&mut self, quoi: Bi, raison: Raison) {
        self.manques.push(Manque { quoi, raison });
    }

    pub(crate) fn ecrire(&mut self, _dossier: &Path, _nom: &str, _contenu: &str, _description: Bi) -> bool {
        false
    }
}

pub(crate) fn entete(_titre: &Bi) -> String {
    String::new()
}

/// Comme `traces::champ` pour ce qui casse une ligne ; les autres caractères de contrôle restent.
pub(crate) fn champ(t: &str) -> String {
    t.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('|', "\\x7c")
}
