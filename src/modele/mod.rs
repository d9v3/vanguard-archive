//! Le modèle commun de Vanguard : de quoi parle un constat (une clé `règle + objet`, sans texte traduit), dans quel
//! état il est (sain, sans objet, non vérifié, problème) et pourquoi il n'a pas pu être vérifié, quels identifiants
//! existent (règles du bilan, fiches de l'audit du réseau, outils) et quels fichiers d'état Vanguard garde.
//!
//! Pourquoi un module à part : l'historique, l'apprentissage et la surveillance reconnaissaient un problème à son
//! texte traduit, si bien qu'un changement de langue faisait revenir les alertes acceptées et voir des « nouveaux »
//! problèmes. Ce module n'importe rien de l'interface : ce qu'il décide ne dépend jamais de la langue.

pub(crate) mod etat;
pub(crate) mod id;
pub(crate) mod inventaire;
pub(crate) mod raison;
pub(crate) mod registre;

pub(crate) use etat::{Absence, Etat, Precision};
pub(crate) use id::{Cle, Objet};
pub(crate) use raison::Raison;
