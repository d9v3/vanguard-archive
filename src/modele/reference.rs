//! Les référentiels reconnus pour les règles de la machine : chaque règle du bilan cite au moins une référence du
//! CIS (Controls v8, ou un benchmark), de Microsoft ou de l'ANSSI (champ `references` de `machine::regles::Regle`).
//! Les autres sources (MITRE ATT&CK, RFC, documentation d'un éditeur) peuvent s'y ajouter, jamais la remplacer : la
//! personne relie ainsi chaque alerte à un référentiel reconnu, et Vanguard pourra dire combien de mesures d'un
//! référentiel la machine suit.

/// Un référentiel reconnu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Referentiel {
    Cis,
    Microsoft,
    Anssi,
}

/// Le référentiel d'une référence, d'après son début (« CIS Controls v8 4.5 », « Microsoft : … », « ANSSI … »).
pub(crate) fn referentiel(reference: &str) -> Option<Referentiel> {
    if reference.starts_with("CIS ") {
        Some(Referentiel::Cis)
    } else if reference.starts_with("Microsoft") {
        Some(Referentiel::Microsoft)
    } else if reference.starts_with("ANSSI") {
        Some(Referentiel::Anssi)
    } else {
        None
    }
}

/// La première référence d'un référentiel reconnu, celle qu'on cite d'abord.
pub(crate) fn principale<'a>(references: &[&'a str]) -> Option<&'a str> {
    references.iter().copied().find(|r| referentiel(r).is_some())
}

/// Une mesure des CIS Controls v8 bien écrite (lue par les tests des règles) : « CIS Controls v8 4.5 », 18 contrôles, numéro de mesure ensuite.
#[cfg(test)]
pub(crate) fn mesure_cis_bien_ecrite(reference: &str) -> bool {
    let Some(numero) = reference.strip_prefix("CIS Controls v8 ") else {
        return true;
    };
    let Some((controle, mesure)) = numero.split_once('.') else {
        return false;
    };
    controle.parse::<u8>().is_ok_and(|c| (1..=18).contains(&c)) && mesure.parse::<u8>().is_ok_and(|m| m >= 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referentiels_reconnus() {
        assert_eq!(referentiel("CIS Controls v8 4.5"), Some(Referentiel::Cis));
        assert_eq!(
            referentiel("Microsoft : BitLocker overview"),
            Some(Referentiel::Microsoft)
        );
        assert_eq!(
            referentiel("ANSSI BP-028 (configuration d'un système GNU/Linux)"),
            Some(Referentiel::Anssi)
        );
        assert_eq!(referentiel("MITRE ATT&CK T1547"), None);
        assert_eq!(
            principale(&["MITRE ATT&CK T1547", "CIS Controls v8 13.2"]),
            Some("CIS Controls v8 13.2")
        );
        assert_eq!(principale(&["RFC 6092"]), None);
        assert!(mesure_cis_bien_ecrite("CIS Controls v8 12.6") && mesure_cis_bien_ecrite("CIS Docker Benchmark"));
        assert!(!mesure_cis_bien_ecrite("CIS Controls v8 19.1") && !mesure_cis_bien_ecrite("CIS Controls v8 4"));
    }
}
