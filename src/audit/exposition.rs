//! Domaine Exposition (règles COM-EXP-001 à 004 du cadrage) : les redirections de ports de la box lues nativement
//! (UPnP IGD) et jointes aux appareils, l'adresse publique IPv4 avec CGNAT et double NAT, l'IPv6 publique de cet
//! ordinateur et son pare-feu, les services de la box côté réseau local. Pas encore écrit ici : le lot exposition
//! remplit ce fichier (avec igd.rs, http_local.rs et ipv6.rs) ; cette ébauche en reprend l'entrée telle qu'il la
//! déclare, pour que `audit/mod.rs` l'appelle sans retouche. D'ici là, chaque audit dit « non vérifié », jamais un
//! faux sain.

use std::net::{IpAddr, Ipv4Addr};

use crate::machine::Constat;
use crate::reseau::Rapport;

/// L'adresse vue d'Internet, mesurée par STUN (`nat::mesurer`) ; `None` dans un champ : pas de réponse par là.
#[derive(Debug, Clone, Copy, Default)]
pub struct Internet {
    pub v4: Option<IpAddr>,
    pub v6: Option<IpAddr>,
}

/// Ce que les règles lisent. Le squelette de l'audit le remplit depuis son contexte ; le scan du réseau, depuis son
/// seul rapport (`du_scan`).
pub struct Entree<'a> {
    /// Le scan : ses appareils avec leurs ports, les absents du carnet, et la réponse UPnP de la box.
    pub rapport: &'a Rapport,
    pub passerelle: Option<Ipv4Addr>,
    /// L'adresse de cet ordinateur sur le réseau local.
    pub locale: Option<Ipv4Addr>,
    /// L'adresse vue d'Internet ; `None` : pas mesurée (passe rapide, hors ligne).
    pub internet: Option<Internet>,
    /// Le pare-feu de cet ordinateur est actif, d'après le constat `*-PFE-001` du bilan ; `None` : non lu.
    pub pare_feu_local: Option<bool>,
}

impl<'a> Entree<'a> {
    /// D'après le scan seul : la passerelle et l'adresse locale du système ; sans STUN ni pare-feu.
    pub fn du_scan(rapport: &'a Rapport) -> Entree<'a> {
        Entree {
            rapport,
            passerelle: crate::reseau::scan::passerelle(),
            locale: crate::reseau::scan::reseau_local().map(|(_, ip)| ip),
            internet: None,
            pare_feu_local: None,
        }
    }
}

pub fn constats(e: &Entree) -> Vec<Constat> {
    // L'entrée n'est pas encore jugée : le lot exposition le fera.
    let _ = (
        e.rapport,
        e.passerelle,
        e.locale,
        e.internet.map(|i| (i.v4, i.v6)),
        e.pare_feu_local,
    );
    vec![super::pas_encore_ecrit(super::Domaine::Exposition)]
}
