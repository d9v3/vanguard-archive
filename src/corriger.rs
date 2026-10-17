//! Application interactive des correctifs : chaque action est montrée puis confirmée.

use crate::machine::{self, Audit};
use crate::reseau::Rapport;
use crate::risk::Niveau;
use crate::ui::*;

/// Propose les corrections de la machine, puis la marche à suivre pour le reste. Retourne le nouvel audit.
pub fn corriger(audit: &Audit, reseau: Option<&Rapport>) -> Option<Audit> {
    let auto: Vec<_> = audit
        .constats
        .iter()
        .filter_map(|c| Some((c, c.correctif.as_ref().filter(|k| k.automatique)?)))
        .collect();
    let manuels: Vec<_> = audit
        .constats
        .iter()
        .filter_map(|c| Some((c, c.correctif.as_ref().filter(|k| !k.automatique)?)))
        .collect();

    titre("Corrections");
    let mut applique = false;
    if auto.is_empty() {
        println!("  {VERT}✔{RESET} Rien à corriger automatiquement sur cette machine.");
    } else {
        println!(
            "  {} correction(s) possible(s). Chacune te sera montrée avant d'être appliquée.",
            auto.len()
        );
        let mut tout = false;
        for (c, k) in auto {
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
            let rep = if tout {
                "o".into()
            } else {
                demander("  Appliquer ? [o]ui / [n]on / [t]out appliquer : ").to_lowercase()
            };
            if rep == "t" {
                tout = true;
            }
            if tout || rep == "o" || rep == "oui" {
                if machine::appliquer(&k.commandes) {
                    machine::retenir_blocage(k);
                    println!("    {VERT}✔ fait{RESET}");
                    applique = true;
                }
            } else {
                println!("    {GRIS}ignoré{RESET}");
            }
        }
    }

    if !manuels.is_empty() {
        titre("À faire toi-même");
        for (c, k) in &manuels {
            println!("  💡 {GRAS}{}{RESET} : {}", c.categorie, k.action);
            for cmd in &k.commandes {
                println!("     {GRIS}{cmd}{RESET}");
            }
        }
    }

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
