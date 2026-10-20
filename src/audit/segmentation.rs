//! Domaine Segmentation et intégrité du réseau local (règles COM-SEG-001, 002, 004, 005 et COM-ARP-001 à 004 du
//! cadrage) : objets connectés et ordinateurs sur le même réseau, isolation du réseau invité, serveur DHCP qui n'est
//! pas la box, deux routeurs IPv6, box usurpée ou dont la MAC a changé, fabricant de la MAC de la box. Pas encore
//! écrit : le lot segmentation remplit ce fichier (après exposition et dns-tls, dont il lit ipv6.rs et bail.rs) ;
//! d'ici là, chaque audit dit « non vérifié », jamais un faux sain.

use crate::machine::Constat;

/// Ce que le domaine reçoit de l'audit : tout le `Contexte` (scan, passerelle, adresse locale, carnet du réseau, nom
/// du Wi-Fi, réseau invité déclaré ou reconnu). Le lot peut le remplacer par ses propres champs : seul `audit/mod.rs`
/// construit cette entrée.
pub struct Entree<'a> {
    pub contexte: &'a super::Contexte<'a>,
}

pub const FICHES: &[super::Fiche] = &[];

pub fn constats(entree: &Entree) -> Vec<Constat> {
    let _ = entree.contexte.scan;
    vec![super::pas_encore_ecrit(super::Domaine::Segmentation)]
}
