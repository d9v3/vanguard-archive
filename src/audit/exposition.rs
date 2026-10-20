//! Domaine Exposition (règles COM-EXP-001 à 004 du cadrage) : les redirections de ports de la box lues nativement
//! (UPnP IGD) et jointes aux appareils, l'adresse publique IPv4 avec CGNAT et double NAT, l'IPv6 publique de cet
//! ordinateur et son pare-feu, les services de la box côté réseau local. Pas encore écrit : le lot exposition
//! remplit ce fichier (et ses fichiers d'aide igd.rs, http_local.rs, ipv6.rs) ; d'ici là, chaque audit dit
//! « non vérifié », jamais un faux sain.

use crate::machine::Constat;

/// Ce que le domaine reçoit de l'audit : tout le `Contexte` (scan, constats réseau de la machine, passerelle, adresse
/// locale, carnet du réseau, passe rapide sans STUN). Le lot peut le remplacer par ses propres champs : seul
/// `audit/mod.rs` construit cette entrée.
pub struct Entree<'a> {
    pub contexte: &'a super::Contexte<'a>,
}

pub const FICHES: &[super::Fiche] = &[];

pub fn constats(entree: &Entree) -> Vec<Constat> {
    let _ = entree.contexte.scan;
    vec![super::pas_encore_ecrit(super::Domaine::Exposition)]
}
