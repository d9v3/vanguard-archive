//! Domaine Wi-Fi (règles COM-WIF-001 à 005 du cadrage) : chiffrement faible du réseau connecté (TKIP), WPS allumé
//! sur la box, plusieurs émetteurs pour le même nom de réseau, réseaux ouverts qui se reconnectent seuls, appareils
//! inconnus. Pas encore écrit : le lot wifi remplit ce fichier (l'acquisition par système, en Rust pur) ; d'ici là,
//! chaque audit dit « non vérifié », jamais un faux sain. Les règles `*-WIF-001` du bilan de la machine restent.

use crate::machine::Constat;

/// Ce que le domaine reçoit de l'audit : tout le `Contexte` (scan avec ses nouveaux appareils, nom du Wi-Fi, passerelle
/// dont la MAC donne le fabricant de la box, passe rapide). Le lot peut le remplacer par ses propres champs : seul
/// `audit/mod.rs` construit cette entrée.
pub struct Entree<'a> {
    pub contexte: &'a super::Contexte<'a>,
}

pub fn constats(entree: &Entree) -> Vec<Constat> {
    let _ = entree.contexte.scan;
    vec![super::pas_encore_ecrit(super::Domaine::WiFi)]
}
