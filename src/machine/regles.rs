//! Le registre des règles du bilan. Chaque règle se déclare là où elle est écrite (`inventory::submit!`), avec un
//! identifiant stable et ce qu'il faut savoir d'elle ; le bilan prend toutes celles de son système et les lance en
//! parallèle avec les autres vérifications. Ajouter une règle, c'est l'écrire et la déclarer : aucune liste centrale à
//! tenir. Son identifiant suit chacun de ses constats (champ `regle`) jusqu'au rapport JSON : reformuler un message ne
//! change pas la règle.

use super::{Constat, Verification};

/// Le système d'une règle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(clippy::enum_variant_names)] // MacOs, comme partout ailleurs dans Vanguard.
pub enum Os {
    Linux,
    Windows,
    MacOs,
}

impl Os {
    /// Celui où tourne Vanguard.
    pub const fn actuel() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::MacOs
        } else {
            Os::Linux
        }
    }

    /// Le début des identifiants de ses règles.
    #[cfg(test)]
    pub const fn prefixe(self) -> &'static str {
        match self {
            Os::Linux => "LNX",
            Os::Windows => "WIN",
            Os::MacOs => "MAC",
        }
    }
}

/// Une règle du bilan.
pub struct Regle {
    /// Stable et jamais réutilisé : système, domaine, numéro (« LNX-PLT-001 »).
    pub id: &'static str,
    pub systeme: Os,
    /// Ce qu'elle vérifie, en français et en anglais.
    pub sujet: (&'static str, &'static str),
    /// Références de durcissement (CIS, ANSSI, documentation de l'éditeur), quand il y en a.
    pub references: &'static [&'static str],
    pub verifier: fn() -> Vec<Constat>,
}

inventory::collect!(Regle);

/// Les règles déclarées pour un système, rangées par identifiant.
pub fn regles(os: Os) -> Vec<&'static Regle> {
    let mut regles: Vec<&'static Regle> = inventory::iter::<Regle>
        .into_iter()
        .filter(|r| r.systeme == os)
        .collect();
    regles.sort_by_key(|r| r.id);
    regles
}

/// « vanguard regles » : les règles déclarées pour ce système, avec leur sujet et leurs références. Les autres
/// vérifications du bilan, plus anciennes, viendront au registre peu à peu.
pub fn afficher() {
    use crate::ui::*;
    let regles = regles(Os::actuel());
    titre(&crate::trf!(
        "Règles du bilan déclarées pour ce système : {}",
        "Check rules declared for this system: {}",
        regles.len()
    ));
    for r in regles {
        let sujet = if crate::langue::anglais() { r.sujet.1 } else { r.sujet.0 };
        println!("  {TOUCHE}{}{RESET}  {sujet}", r.id);
        if !r.references.is_empty() {
            println!("        {GRIS}{}{RESET}", r.references.join(" · "));
        }
    }
}

/// Les vérifications du bilan pour ce système, une par règle : chaque constat porte l'identifiant de sa règle.
pub(super) fn verifications<'a>() -> Vec<Verification<'a>> {
    regles(Os::actuel())
        .into_iter()
        .map(|r| {
            Box::new(move || {
                (r.verifier)()
                    .into_iter()
                    .map(|mut c| {
                        c.regle = r.id;
                        c
                    })
                    .collect::<Vec<Constat>>()
            }) as Verification<'a>
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chaque identifiant : unique, de la forme « LNX-PLT-001 », au préfixe de son système ; chaque règle a son sujet
    /// dans les deux langues.
    #[test]
    fn identifiants_uniques_et_bien_formes() {
        let mut vus = std::collections::HashSet::new();
        for r in inventory::iter::<Regle> {
            assert!(vus.insert(r.id), "{} déclaré deux fois", r.id);
            let morceaux: Vec<&str> = r.id.split('-').collect();
            assert!(
                morceaux.len() == 3
                    && morceaux[0] == r.systeme.prefixe()
                    && morceaux[1].len() == 3
                    && morceaux[1].chars().all(|c| c.is_ascii_uppercase())
                    && morceaux[2].len() == 3
                    && morceaux[2].chars().all(|c| c.is_ascii_digit()),
                "identifiant mal formé : {}",
                r.id
            );
            assert!(!r.sujet.0.is_empty() && !r.sujet.1.is_empty(), "{} sans sujet", r.id);
        }
    }

    /// Le bilan de ce système lance une vérification par règle déclarée pour lui.
    #[test]
    fn une_verification_par_regle() {
        assert_eq!(verifications().len(), regles(Os::actuel()).len());
        assert!(regles(Os::actuel()).windows(2).all(|r| r[0].id < r[1].id));
    }
}
