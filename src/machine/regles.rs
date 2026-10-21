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
    /// Les trois : les vérifications communes, montrées après celles du système.
    Tous,
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
            Os::Tous => "COM",
        }
    }
}

/// Une règle du bilan.
pub struct Regle {
    /// Stable et jamais réutilisé : système, domaine, numéro (« LNX-PLT-001 »).
    pub id: &'static str,
    pub systeme: Os,
    /// Sa place dans le bilan : les règles s'y montrent par rang croissant (100 et plus pour celles du système, 500
    /// et plus pour les communes), comme les listes d'avant.
    pub rang: u16,
    /// Ce qu'elle vérifie, en français et en anglais.
    pub sujet: (&'static str, &'static str),
    /// Références de durcissement (CIS, ANSSI, documentation de l'éditeur), quand il y en a.
    pub references: &'static [&'static str],
    pub verifier: fn() -> Vec<Constat>,
}

inventory::collect!(Regle);

/// Déclare une règle au registre : identifiant, système, rang, sujet (français, anglais), références, vérification.
macro_rules! regle {
    ($id:literal, $os:expr, $rang:literal, $sujet:expr, $refs:expr, $verifier:expr $(,)?) => {
        inventory::submit! {
            $crate::machine::regles::Regle {
                id: $id,
                systeme: $os,
                rang: $rang,
                sujet: $sujet,
                references: $refs,
                verifier: $verifier,
            }
        }
    };
}
pub(crate) use regle;

/// Les règles d'un système, communes comprises, dans l'ordre du bilan (rang, puis identifiant).
pub fn regles(os: Os) -> Vec<&'static Regle> {
    let mut regles: Vec<&'static Regle> = inventory::iter::<Regle>
        .into_iter()
        .filter(|r| r.systeme == os || r.systeme == Os::Tous)
        .collect();
    regles.sort_by_key(|r| (r.rang, r.id));
    regles
}

/// « vanguard regles » : les règles du bilan pour ce système (toutes ses vérifications), avec leur sujet et leurs
/// références.
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

/// Les vérifications du bilan pour ce système, une par règle, dans l'ordre des rangs.
pub(super) fn verifications<'a>() -> Vec<Verification<'a>> {
    regles(Os::actuel()).into_iter().map(verification).collect()
}

/// La vérification d'une règle : chaque constat porte son identifiant, même celui d'une règle qui plante (« erreur
/// interne » non vérifiée, qui dit laquelle et que `Audit::fiable` voit).
pub(super) fn verification<'a>(r: &'static Regle) -> Verification<'a> {
    Box::new(move || {
        crate::journal::rattraper(r.verifier)
            .unwrap_or_else(|_| {
                vec![super::impossible(
                    "Audit",
                    &crate::trf!("erreur interne, règle {}", "internal error, rule {}", r.id),
                )]
            })
            .into_iter()
            .map(|mut c| {
                c.regle = r.id;
                c
            })
            .collect::<Vec<Constat>>()
    })
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

    /// Le bilan de ce système lance une vérification par règle, dans l'ordre des rangs ; toutes sont bien
    /// enregistrées (une déclaration perdue à l'édition des liens ferait tomber le compte).
    #[test]
    fn une_verification_par_regle() {
        let regles = regles(Os::actuel());
        assert_eq!(verifications().len(), regles.len());
        assert!(regles.windows(2).all(|r| (r[0].rang, r[0].id) < (r[1].rang, r[1].id)));
        assert!(regles.len() >= 35, "{} règles seulement", regles.len());
        assert!(regles.iter().filter(|r| r.systeme == Os::Tous).count() >= 20);
    }
}
