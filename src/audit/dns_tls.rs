//! Domaine DNS et TLS (règles COM-DNS-002 à 005 et COM-TLS-001 à 003 du cadrage) : DNS distribué par la box comparé
//! au DNS utilisé, DNS chiffré et DDR, réponses divergentes sur des noms stables, DNSSEC, HTTPS intercepté en acte,
//! exceptions de certificat de Firefox, racines ajoutées aux navigateurs. Pas encore écrit ici : le lot dns-tls
//! remplit ce fichier (avec dns_client.rs et bail.rs) ; cette ébauche en reprend les deux fonctions telles qu'il les
//! déclare (`entree` lit et mesure, `constats` juge), pour que `audit/mod.rs` l'appelle sans retouche. D'ici là,
//! chaque audit dit « non vérifié », jamais un faux sain. Les règles COM-DNS-001 et COM-CRT-001 du bilan de la
//! machine restent, reprises par le domaine Postes.

use std::net::Ipv4Addr;

use crate::machine::Constat;

/// Tout ce que le domaine a lu et mesuré ; `constats` juge sans rien relire.
pub struct Entree {
    /// La box, si l'audit la connaît déjà (sinon la route par défaut).
    pub passerelle: Option<Ipv4Addr>,
}

/// Lit et mesure tout ce que le domaine juge. Hors ligne, rien ne part sur le réseau.
pub fn entree(passerelle: Option<Ipv4Addr>) -> Entree {
    Entree { passerelle }
}

pub fn constats(e: &Entree) -> Vec<Constat> {
    // L'entrée n'est pas encore jugée : le lot dns-tls le fera.
    let _ = e.passerelle;
    vec![super::pas_encore_ecrit(super::Domaine::DnsTls)]
}
