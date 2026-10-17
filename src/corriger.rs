//! Application interactive des correctifs : chaque action est montrée puis confirmée.

use crate::machine::{self, Audit, Constat, Correctif};
use crate::reseau::Rapport;
use crate::risk::Niveau;
use crate::ui::*;

/// Propose chaque correction automatique, puis liste celles à faire soi-même. « [t]out » applique la correction
/// en cours et toutes les suivantes en une seule exécution : une seule fenêtre administrateur sous Windows.
/// Retourne les catégories des corrections appliquées.
pub fn proposer(constats: &[Constat]) -> Vec<&'static str> {
    let auto: Vec<_> = constats
        .iter()
        .filter_map(|c| Some((c, c.correctif.as_ref().filter(|k| k.automatique)?)))
        .collect();
    let mut appliquees = Vec::new();
    if auto.is_empty() {
        println!("  {VERT}✔{RESET} Rien à corriger automatiquement.");
    } else {
        println!(
            "  {} correction(s) possible(s). Chacune te sera montrée avant d'être appliquée.",
            auto.len()
        );
        for (i, (c, k)) in auto.iter().enumerate() {
            let n = c.probleme.unwrap_or(Niveau::Info);
            println!(
                "\n  {}[{}]{RESET} {GRAS}{}{RESET} — {}",
                couleur(n),
                n.libelle(),
                c.categorie,
                c.message
            );
            println!("  🔧 {}", k.action);
            for cmd in &k.commandes {
                println!("    {GRIS}{cmd}{RESET}");
            }
            let rep = demander("  Appliquer ? [o]ui / [n]on / [t]out appliquer : ").to_lowercase();
            let lot: Vec<(&Constat, &Correctif)> = match rep.as_str() {
                "t" => auto[i..].to_vec(),
                "o" | "oui" => vec![(c, k)],
                _ => {
                    println!("    {GRIS}ignoré{RESET}");
                    continue;
                }
            };
            if lot.len() > 1 {
                println!("    {GRIS}Les {} corrections restantes, en une fois.{RESET}", lot.len());
            }
            let commandes: Vec<String> = lot.iter().flat_map(|(_, k)| k.commandes.clone()).collect();
            if machine::appliquer(&commandes) {
                for (c, k) in &lot {
                    machine::retenir_blocage(k);
                    appliquees.push(c.categorie);
                }
                println!("    {VERT}✔ fait{RESET}");
            } else {
                // Sans cette ligne, un échec (UAC refusée, commande en erreur) passait sans un mot de netscan.
                println!("    ✖ non appliqué : voir le message ci-dessus");
            }
            if rep == "t" {
                break;
            }
        }
    }

    let manuels: Vec<_> = constats
        .iter()
        .filter_map(|c| Some((c, c.correctif.as_ref().filter(|k| !k.automatique)?)))
        .collect();
    if !manuels.is_empty() {
        titre("À faire toi-même");
        for (c, k) in &manuels {
            println!("  💡 {GRAS}{}{RESET} : {}", c.categorie, k.action);
            for cmd in &k.commandes {
                println!("     {GRIS}{cmd}{RESET}");
            }
        }
    }
    appliquees
}

/// Propose les corrections de la machine, puis la marche à suivre pour le reste. Retourne le nouvel audit.
pub fn corriger(audit: &Audit, reseau: Option<&Rapport>) -> Option<Audit> {
    titre("Corrections");
    let applique = !proposer(&audit.constats).is_empty();

    if let Some(r) = reseau {
        let exposes: Vec<_> = r
            .hotes
            .iter()
            .filter(|h| h.role != Some("cette machine") && !h.alertes.is_empty())
            .collect();
        if !exposes.is_empty() {
            titre("Autres appareils du réseau (à corriger sur l'appareil lui-même)");
            for h in exposes {
                println!("  {GRAS}{}{RESET} {}", h.ip, h.titre());
                for (n, msg) in &h.alertes {
                    println!("    {}→{RESET} {msg}", couleur(*n));
                }
                let ouvert = |l: &[u16]| h.ports.iter().any(|p| l.contains(&p.port));
                if ouvert(&[80, 8080]) {
                    println!("    {GRIS}interface d'admin : http://{}{RESET}", h.ip);
                } else if ouvert(&[443, 8443]) {
                    println!("    {GRIS}interface d'admin : https://{}{RESET}", h.ip);
                }
                if h.ports.iter().any(|p| [135, 139, 445].contains(&p.port)) {
                    println!(
                        "    {GRIS}PC Windows : Paramètres > Réseau > Propriétés > profil « Public », et dans PowerShell admin :{RESET}"
                    );
                    println!("    {GRIS}  Set-SmbServerConfiguration -EnableSMB1Protocol $false{RESET}");
                }
            }
        }
    }

    if applique {
        println!("\n{GRIS}Nouvelle vérification…{RESET}");
        let nouveau = machine::auditer(false);
        afficher_note("Avant", audit.score);
        afficher_note("Après", nouveau.score);
        return Some(nouveau);
    }
    None
}
