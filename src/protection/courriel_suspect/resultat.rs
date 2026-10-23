//! Le résultat de l'examen d'un courriel suspect (`modele::resultat`) : chaque signe vu, sa gravité, et ce qui n'a
//! pas pu être vérifié, sans l'écran. Versé au rapport (`examens/PRO-COU-001.json`), au journal des événements, et
//! rendu par `--json`. Le verdict n'est jamais « sûr » : sans signe et sans manque, il est « sain » au sens de
//! « rien trouvé dans ce qui a été examiné », comme l'écran le dit.

use super::Constats;
use crate::machine::{Constat, alerte, impossible, ok};
use crate::modele::resultat::{Couverture, Resultat};
use crate::protection::antivirus::Examen;
use crate::risk::Niveau;

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-COU-001";

const CAT: &str = "Courriel suspect";

/// Les sections examinées sur l'ordinateur : expéditeur, authentification, forme, liens, HTML, pièces jointes.
const SECTIONS: u32 = 6;

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Le résultat d'un examen : un constat par signe plus grave qu'une information, un par pièce qu'un moteur a
/// reconnue, sinon « rien de suspect » ; `pire_en_ligne` : ce que la vérification en ligne a ajouté.
pub(super) fn resultat(c: &Constats, pire_en_ligne: Option<Niveau>, debut: Debut) -> Resultat {
    let signes = c
        .expediteur
        .iter()
        .chain(&c.authentification)
        .chain(&c.structure)
        .chain(&c.liens.trompeurs)
        .chain(c.liens.par_site.iter().flat_map(|(_, _, _, s)| s))
        .chain(&c.html)
        .chain(c.pieces.iter().flat_map(|p| &p.signes))
        .filter(|(n, _)| *n > Niveau::Info);
    let mut constats: Vec<Constat> = signes.map(|(n, t)| alerte(CAT, *n, t.clone())).collect();
    for p in &c.pieces {
        for (moteur, e) in &p.moteurs {
            if let Examen::Trouve(detection) = e {
                constats.push(alerte(
                    CAT,
                    Niveau::Critique,
                    format!("{} : {moteur} {}", p.nom, detection.join(", ")),
                ));
            }
        }
    }
    if let Some(n) = pire_en_ligne.filter(|n| *n > Niveau::Info) {
        constats.push(alerte(
            CAT,
            n,
            crate::tr!(
                "Un domaine du courriel est récent ou dans une liste publique de sites dangereux.",
                "A domain in the email is recent or on a public list of dangerous sites."
            ),
        ));
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            crate::tr!(
                "Rien de suspect trouvé dans ce qui a été examiné (ce n'est pas une garantie).",
                "Nothing suspicious found in what was examined (that is not a guarantee)."
            ),
        ));
    }
    Resultat::nouveau(
        ID,
        debut,
        &constats,
        Couverture {
            verifies: SECTIONS,
            non_verifies: c.manques.clone(),
        },
    )
}

/// Le résultat d'un fichier qui n'a pas pu être examiné : rien de vérifié.
pub(super) fn refuse(raison: &str, debut: Debut) -> Resultat {
    Resultat::nouveau(ID, debut, &[impossible(CAT, raison)], Couverture::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signes_et_manques() {
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        let mut c = Constats::default();
        let r = resultat(&c, None, debut);
        assert_eq!(r.verdict(), "sain");
        c.manques.push("l'âge des domaines".into());
        assert_eq!(resultat(&c, None, debut).verdict(), "non-verifie");
        c.expediteur.push((Niveau::Info, "expéditeur connu".into()));
        assert_eq!(resultat(&c, None, debut).pire(), None, "une information ne compte pas");
        c.expediteur.push((
            Niveau::Eleve,
            "nom affiché « PayPal », domaine paypa1-secure.example".into(),
        ));
        let r = resultat(&c, Some(Niveau::Moyen), debut);
        assert_eq!(r.verdict(), "probleme");
        assert_eq!(r.pire(), Some(Niveau::Eleve));
        assert_eq!(r.constats.len(), 2);
        assert_eq!(refuse("pas un courriel", debut).verdict(), "non-verifie");
    }
}
