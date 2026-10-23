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
/// Un identifiant mal formé ne compile pas.
macro_rules! regle {
    ($id:literal, $os:expr, $rang:literal, $sujet:expr, $refs:expr, $verifier:expr $(,)?) => {
        const _: () = assert!(
            $crate::modele::id::bien_forme($id),
            "identifiant de règle mal formé"
        );
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

/// Le texte d'un sujet dans la langue de l'interface.
fn sujet(s: (&'static str, &'static str)) -> &'static str {
    if crate::langue::anglais() { s.1 } else { s.0 }
}

/// « vanguard regles » : les règles du bilan pour ce système (toutes ses vérifications), puis celles de l'audit du
/// réseau et les outils, avec leur sujet et leurs références : un seul registre d'identifiants.
pub fn afficher() {
    use crate::ui::*;
    let ligne = |id: &str, s: (&'static str, &'static str), references: &[&str]| {
        println!("  {TOUCHE}{id}{RESET}  {}", sujet(s));
        if !references.is_empty() {
            println!("        {GRIS}{}{RESET}", references.join(" · "));
        }
    };
    let regles = regles(Os::actuel());
    titre(&crate::trf!(
        "Règles du bilan déclarées pour ce système : {}",
        "Check rules declared for this system: {}",
        regles.len()
    ));
    for r in regles {
        ligne(r.id, r.sujet, r.references);
    }
    let fiches = crate::audit::fiches::FICHES;
    titre(&crate::trf!(
        "Règles de l'audit du réseau : {}",
        "Network audit rules: {}",
        fiches.len()
    ));
    for f in fiches {
        ligne(f.id, f.sujet, f.references);
    }
    let outils = crate::modele::registre::OUTILS;
    titre(&crate::trf!(
        "Outils et surveillances : {}",
        "Tools and monitoring: {}",
        outils.len()
    ));
    for o in outils {
        ligne(o.id, o.sujet, &[]);
    }
}

/// Tous les identifiants de ce programme : règles du bilan de ce système, fiches de l'audit du réseau, outils et
/// surveillances (identifiant, sujet).
#[cfg(test)]
pub(crate) fn tous_les_identifiants() -> Vec<(&'static str, (&'static str, &'static str))> {
    regles(Os::actuel())
        .into_iter()
        .map(|r| (r.id, r.sujet))
        .chain(crate::audit::fiches::FICHES.iter().map(|f| (f.id, f.sujet)))
        .chain(crate::modele::registre::OUTILS.iter().map(|o| (o.id, o.sujet)))
        .collect()
}

/// Les règles qui peuvent encore ne rien rendre sans panne : chez elles, une liste vide veut dire « rien à signaler »
/// ou « rien à juger » (pas de clé branchée, aucun piège posé, rien d'anormal). Ailleurs, une règle qui ne rend
/// rien devient « non vérifié » (`modele::Raison::Muette`), jamais un silence qu'on lirait comme sain. Cliquet :
/// la liste ne fait que rétrécir, à mesure que ces règles disent elles-mêmes sain, sans objet ou non vérifié.
pub(crate) const MUETTES_TOLEREES: &[&str] = &[
    "COM-AGT-001",
    "COM-AGT-002",
    "COM-BLU-001",
    "COM-CLE-001",
    "COM-CLE-002",
    "COM-CLE-003",
    "COM-CPT-001",
    "COM-CPT-002",
    "COM-CPT-003",
    "COM-CRT-001",
    "COM-DIS-001",
    "COM-DNS-001",
    "COM-ESP-001",
    "COM-ETA-001",
    "COM-FIC-001",
    "COM-HEU-001",
    "COM-HIS-001",
    "COM-INT-002",
    "COM-JRN-001",
    "COM-MAJ-001",
    "COM-MAT-001",
    "COM-MDP-001",
    "COM-NAV-001",
    "COM-NAV-002",
    "COM-PAR-001",
    "COM-PRG-001",
    "COM-PUB-001",
    "COM-SAV-001",
    "COM-SUR-001",
    "COM-SUR-003",
    "LNX-CPT-002",
    "LNX-CTN-001",
    "LNX-JRN-001",
    "LNX-MAJ-002",
    "LNX-MAJ-004",
    "LNX-MAJ-006",
    "LNX-NOY-001",
    "LNX-NOY-002",
    "LNX-NOY-005",
    "LNX-NOY-006",
    "LNX-PRS-001",
    "LNX-PRS-002",
    "LNX-PRS-004",
    "LNX-PRV-001",
    "LNX-PRV-002",
    "LNX-PRV-003",
    "LNX-PRV-004",
    "LNX-RES-002",
    "LNX-SES-001",
    "LNX-SES-002",
    "LNX-SES-003",
    "LNX-SSH-002",
    "LNX-SSH-003",
    "LNX-SSH-004",
    "LNX-SSH-005",
    "LNX-SSH-006",
    "MAC-DIS-001",
    "MAC-MAJ-002",
    "MAC-MAJ-003",
    "MAC-MAJ-004",
    "MAC-PAR-001",
    "MAC-PRF-001",
    "MAC-PRS-001",
    "MAC-PRV-001",
    "MAC-PRV-002",
    "MAC-PRV-003",
    "MAC-PRV-004",
    "MAC-RES-002",
    "MAC-SAV-002",
    "MAC-SES-001",
    "MAC-SES-002",
    "MAC-SSH-001",
    "MAC-SYS-001",
    "MAC-SYS-002",
    "WIN-ANV-001",
    "WIN-ANV-002",
    "WIN-CPT-001",
    "WIN-CPT-002",
    "WIN-DEM-001",
    "WIN-DUR-001",
    "WIN-JRN-002",
    "WIN-JRN-003",
    "WIN-MAJ-002",
    "WIN-PRS-001",
    "WIN-PRS-002",
    "WIN-PRS-003",
    "WIN-PRS-004",
    "WIN-PRS-005",
    "WIN-PRS-006",
    "WIN-PRS-007",
    "WIN-PRS-008",
    "WIN-PRS-009",
    "WIN-PRS-010",
    "WIN-PRS-011",
    "WIN-PRS-012",
    "WIN-RES-002",
    "WIN-SRV-001",
];

/// Le plafond du cliquet : baisser ce nombre quand une règle sort de la liste, jamais le monter.
#[cfg(test)]
const MUETTES_TOLEREES_AU_PLUS: usize = 97;

/// Les vérifications du bilan pour ce système, une par règle, dans l'ordre des rangs.
pub(super) fn verifications<'a>() -> Vec<Verification<'a>> {
    regles(Os::actuel()).into_iter().map(verification).collect()
}

/// La vérification d'une règle : chaque constat porte son identifiant, même celui d'une règle qui plante (« erreur
/// interne » non vérifiée, qui dit laquelle et que `Audit::fiable` voit) ou qui ne rend rien (« non vérifié »,
/// hors des muettes tolérées).
pub(super) fn verification<'a>(r: &'static Regle) -> Verification<'a> {
    use crate::modele::Raison;
    Box::new(move || {
        let mut constats = crate::journal::rattraper(r.verifier).unwrap_or_else(|_| {
            vec![super::impossible_par(
                "Audit",
                Raison::Panique,
                crate::trf!(
                    "Impossible de vérifier (erreur interne, règle {}).",
                    "Could not check (internal error, rule {}).",
                    r.id
                ),
            )]
        });
        if constats.is_empty() && !MUETTES_TOLEREES.contains(&r.id) {
            constats.push(super::impossible_par(
                "Audit",
                Raison::Muette,
                crate::trf!(
                    "Impossible de vérifier ({}) : la vérification n'a rien rendu, règle {}.",
                    "Could not check ({}): the check returned nothing, rule {}.",
                    sujet(r.sujet),
                    r.id
                ),
            ));
        }
        constats
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

    /// Les lignes de tests/regles-connues.txt : (identifiant, marques).
    fn connus() -> Vec<(&'static str, Vec<&'static str>)> {
        include_str!("../../tests/regles-connues.txt")
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(|l| {
                let mut mots = l.split_whitespace();
                (mots.next().unwrap_or_default(), mots.collect())
            })
            .collect()
    }

    /// Un identifiant de ce système (ou commun) : ceux que ce programme compile tous.
    fn d_ici(id: &str) -> bool {
        id.starts_with(Os::actuel().prefixe()) || ["COM", "PRO", "SUR", "VEI"].iter().any(|p| id.starts_with(p))
    }

    /// T1 : règles du bilan, fiches de l'audit du réseau et outils forment un seul registre : chaque identifiant une
    /// fois, bien formé, avec son sujet dans les deux langues.
    #[test]
    fn registre_unique() {
        let tous = tous_les_identifiants();
        let mut vus = std::collections::HashSet::new();
        for (id, (fr, en)) in &tous {
            assert!(vus.insert(*id), "{id} donné deux fois (règle, fiche ou outil)");
            assert!(crate::modele::id::bien_forme(id), "{id} mal formé");
            assert!(!fr.is_empty() && !en.is_empty(), "{id} sans sujet");
        }
        assert!(tous.len() >= 90, "{} identifiants seulement", tous.len());
        for o in crate::modele::registre::OUTILS {
            assert!(!o.module.is_empty(), "{} sans module", o.id);
            let prefixe = &o.id[..3];
            assert!(
                ["PRO", "SUR", "VEI"].contains(&prefixe),
                "{} : préfixe d'outil attendu",
                o.id
            );
        }
    }

    /// T2 : chaque identifiant est noté dans tests/regles-connues.txt, un identifiant retiré n'y revient jamais, et un
    /// identifiant de ce système qui disparaît du programme doit y être marqué « retire » (sinon une autre règle
    /// pourrait le reprendre sans que l'historique ni les alertes acceptées ne le voient).
    #[test]
    fn identifiants_connus_jamais_repris() {
        let connus = connus();
        let mut vus = std::collections::HashSet::new();
        for (id, marques) in &connus {
            assert!(vus.insert(*id), "{id} noté deux fois dans regles-connues.txt");
            assert!(
                crate::modele::id::bien_forme(id),
                "{id} mal formé dans regles-connues.txt"
            );
            assert!(
                marques.iter().all(|m| ["sans-reference", "retire"].contains(m)),
                "{id} : marque inconnue {marques:?}"
            );
        }
        let ici: std::collections::HashSet<&str> = tous_les_identifiants().into_iter().map(|(id, _)| id).collect();
        for id in &ici {
            match connus.iter().find(|(c, _)| c == id) {
                None => panic!("{id} absent de tests/regles-connues.txt : l'y ajouter"),
                Some((_, m)) => assert!(!m.contains(&"retire"), "{id} est retiré : jamais le reprendre"),
            }
        }
        for (id, marques) in &connus {
            if d_ici(id) && !marques.contains(&"retire") {
                assert!(
                    ici.contains(id),
                    "{id} n'existe plus : le marquer « retire » dans regles-connues.txt"
                );
            }
        }
    }

    /// T3 : les règles sans référence sont marquées « sans-reference » ; une règle qui en gagne doit perdre sa
    /// marque (le cliquet ne fait que rétrécir).
    #[test]
    fn cliquet_sans_reference() {
        let connus = connus();
        for r in regles(Os::actuel()) {
            let marquee = connus
                .iter()
                .any(|(id, m)| *id == r.id && m.contains(&"sans-reference"));
            assert_eq!(
                r.references.is_empty(),
                marquee,
                "{} : marque « sans-reference » de regles-connues.txt à {}",
                r.id,
                if marquee {
                    "retirer"
                } else {
                    "ajouter, ou mieux, des références à citer"
                }
            );
        }
        for f in crate::audit::fiches::FICHES {
            assert!(!f.references.is_empty(), "{} sans référence", f.id);
        }
    }

    /// T5 : le cliquet des muettes tolérées : rangées, une seule fois, au plus ce qu'elles étaient, toutes connues,
    /// et celles de ce système existent encore.
    #[test]
    fn cliquet_des_muettes() {
        assert!(
            MUETTES_TOLEREES.len() <= MUETTES_TOLEREES_AU_PLUS,
            "la liste des muettes tolérées ne doit jamais grandir"
        );
        assert!(
            MUETTES_TOLEREES.windows(2).all(|p| p[0] < p[1]),
            "liste à ranger, sans doublon"
        );
        let connus = connus();
        let ici: Vec<&str> = regles(Os::actuel()).iter().map(|r| r.id).collect();
        for id in MUETTES_TOLEREES {
            assert!(connus.iter().any(|(c, _)| c == id), "{id} inconnue");
            assert!(
                !d_ici(id) || ici.contains(id),
                "{id} n'existe plus : la retirer de MUETTES_TOLEREES"
            );
        }
    }

    /// Chaque règle de ce système, mise à l'épreuve : si elle ne rendait rien, son constat dirait « non vérifié
    /// (muette) » avec son identifiant (sauf les muettes tolérées) ; si elle plantait, « non vérifié (erreur
    /// interne) ». Jamais un silence, jamais un sain.
    #[test]
    fn toute_regle_muette_ou_plantee_dit_non_verifie() {
        use crate::modele::{Etat, Raison};
        for r in regles(Os::actuel()) {
            let doublure = |verifier: fn() -> Vec<Constat>| -> &'static Regle {
                Box::leak(Box::new(Regle {
                    id: r.id,
                    systeme: r.systeme,
                    rang: r.rang,
                    sujet: r.sujet,
                    references: r.references,
                    verifier,
                }))
            };
            let muette = verification(doublure(Vec::new))();
            if MUETTES_TOLEREES.contains(&r.id) {
                assert!(muette.is_empty(), "{}", r.id);
            } else {
                assert_eq!(muette.len(), 1, "{}", r.id);
                assert_eq!(muette[0].regle, r.id);
                assert_eq!(muette[0].etat(), Etat::NonVerifie(Raison::Muette), "{}", r.id);
                assert!(muette[0].message.contains(r.id) && muette[0].message.contains(r.sujet.0));
                assert!(muette[0].coherent());
            }
            let plantee = verification(doublure(|| panic!("règle d'essai")))();
            assert_eq!(plantee.len(), 1, "{}", r.id);
            assert_eq!(plantee[0].etat(), Etat::NonVerifie(Raison::Panique), "{}", r.id);
            assert_eq!(plantee[0].regle, r.id);
        }
    }
}
