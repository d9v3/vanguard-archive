//! Domaine DNS et TLS (règles COM-DNS-002 à 005 et COM-TLS-001 à 003 du cadrage) : DNS distribué par la box comparé
//! au DNS utilisé, DNS chiffré et DDR, réponses divergentes sur des noms stables, DNSSEC, HTTPS intercepté en acte,
//! exceptions de certificat de Firefox, racines ajoutées aux navigateurs. Pas encore écrit : le lot dns-tls remplit
//! ce fichier (avec dns_client.rs et bail.rs) ; d'ici là, chaque audit dit « non vérifié », jamais un faux sain. Les
//! règles COM-DNS-001 et COM-CRT-001 du bilan de la machine restent, reprises par le domaine Postes.

use crate::machine::Constat;

/// Ce que le domaine reçoit de l'audit : tout le `Contexte` (scan, passerelle, constats réseau de la machine, passe
/// rapide sans les questions aux résolveurs publics). Le lot peut le remplacer par ses propres champs : seul
/// `audit/mod.rs` construit cette entrée.
pub struct Entree<'a> {
    pub contexte: &'a super::Contexte<'a>,
}

pub const FICHES: &[super::Fiche] = &[];

pub fn constats(entree: &Entree) -> Vec<Constat> {
    let _ = entree.contexte.scan;
    vec![super::pas_encore_ecrit(super::Domaine::DnsTls)]
}
