//! Le résultat de l'examen des logiciels espions (`modele::resultat`) : le jugement du relevé, sans l'écran. Il est
//! versé au rapport (`examens/PRO-ESP-001.json`), au journal des événements, et rendu par `--json`.

use super::{Releve, constats_de};
use crate::modele::resultat::{Couverture, Resultat};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-ESP-001";

/// Le résultat d'un relevé commencé à `debut` : ses constats (un par trouvaille, ou « aucun signe » avec ce qui n'a
/// pas été vérifié, ou « impossible ») et sa couverture.
pub(super) fn resultat(r: &Releve, debut: (chrono::DateTime<chrono::Utc>, std::time::Instant)) -> Resultat {
    Resultat::nouveau(
        ID,
        debut,
        &constats_de(r),
        Couverture {
            verifies: u32::try_from(r.verifies).unwrap_or(u32::MAX),
            non_verifies: r.non_verifies.clone(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::Niveau;

    #[test]
    fn resultat_d_un_releve() {
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        let mut r = Releve::default();
        assert_eq!(
            resultat(&r, debut).verdict(),
            "non-verifie",
            "rien de vérifié n'est jamais sain"
        );
        r.verifies = 2;
        r.non_verifie("mémoire DNS non vérifiée");
        assert_eq!(resultat(&r, debut).verdict(), "non-verifie");
        r.trouvailles.push(super::super::Trouvaille {
            niveau: Niveau::Eleve,
            section: super::super::Section::Programmes,
            quoi: "Spyrix : logiciel vendu pour épier".into(),
            ou: vec!["en cours : spyrix (pid 12)".into()],
            objet: "programme:Spyrix".into(),
        });
        let res = resultat(&r, debut);
        assert_eq!(res.verdict(), "probleme");
        assert_eq!(res.constats[0].objet.as_deref(), Some("programme:Spyrix"));
    }
}
