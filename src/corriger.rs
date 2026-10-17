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
        trp!(
            "  {VERT}✔{RESET} Rien à corriger automatiquement.",
            "  {VERT}✔{RESET} Nothing to fix automatically."
        );
    } else {
        trp!(
            "  {} correction(s) possible(s). Chacune te sera montrée avant d'être appliquée.",
            "  {} fix(es) available. Each one will be shown to you before it is applied.",
            auto.len()
        );
        for (i, (c, k)) in auto.iter().enumerate() {
            let n = c.probleme.unwrap_or(Niveau::Info);
            println!(
                "\n  {}[{}]{RESET} {GRAS}{}{RESET} — {}",
                couleur(n),
                n.libelle(),
                crate::langue::categorie(c.categorie),
                c.message
            );
            println!("  🔧 {}", k.action);
            for cmd in &k.commandes {
                println!("    {GRIS}{cmd}{RESET}");
            }
            let rep = demander(tr!(
                "  Appliquer ? [o]ui / [n]on / [t]out appliquer : ",
                "  Apply? [y]es / [n]o / [a]ll: "
            ))
            .to_lowercase();
            let tout = crate::langue::tout(&rep);
            let lot: Vec<(&Constat, &Correctif)> = if tout {
                auto[i..].to_vec()
            } else if crate::langue::oui(&rep) {
                vec![(c, k)]
            } else {
                trp!("    {GRIS}ignoré{RESET}", "    {GRIS}skipped{RESET}");
                continue;
            };
            if lot.len() > 1 {
                trp!(
                    "    {GRIS}Les {} corrections restantes, en une fois.{RESET}",
                    "    {GRIS}The {} remaining fixes, in one go.{RESET}",
                    lot.len()
                );
            }
            let commandes: Vec<String> = lot.iter().flat_map(|(_, k)| k.commandes.clone()).collect();
            if machine::appliquer(&commandes) {
                for (c, k) in &lot {
                    machine::retenir_blocage(k);
                    appliquees.push(c.categorie);
                }
                trp!("    {VERT}✔ fait{RESET}", "    {VERT}✔ done{RESET}");
            } else {
                // Sans cette ligne, un échec (UAC refusée, commande en erreur) passait sans un mot de netscan.
                trp!(
                    "    ✖ non appliqué : voir le message ci-dessus",
                    "    ✖ not applied: see the message above"
                );
            }
            if tout {
                break;
            }
        }
    }

    let manuels: Vec<_> = constats
        .iter()
        .filter_map(|c| Some((c, c.correctif.as_ref().filter(|k| !k.automatique)?)))
        .collect();
    if !manuels.is_empty() {
        titre(tr!("À faire toi-même", "To do yourself"));
        for (c, k) in &manuels {
            let cat = crate::langue::categorie(c.categorie);
            trp!("  💡 {GRAS}{cat}{RESET} : {}", "  💡 {GRAS}{cat}{RESET}: {}", k.action);
            for cmd in &k.commandes {
                println!("     {GRIS}{cmd}{RESET}");
            }
        }
    }
    appliquees
}

/// Propose les corrections de la machine, puis la marche à suivre pour le reste. Retourne le nouvel audit.
pub fn corriger(audit: &Audit, reseau: Option<&Rapport>) -> Option<Audit> {
    titre(tr!("Corrections", "Fixes"));
    let applique = !proposer(&audit.constats).is_empty();

    if let Some(r) = reseau {
        let exposes: Vec<_> = r
            .hotes
            .iter()
            .filter(|h| h.role != Some("cette machine") && !h.alertes.is_empty())
            .collect();
        if !exposes.is_empty() {
            titre(tr!(
                "Autres appareils du réseau (à corriger sur l'appareil lui-même)",
                "Other devices on the network (to fix on the device itself)"
            ));
            for h in exposes {
                println!("  {GRAS}{}{RESET} {}", h.ip, h.titre());
                for (n, msg) in &h.alertes {
                    println!("    {}→{RESET} {msg}", couleur(*n));
                }
                let ouvert = |l: &[u16]| h.ports.iter().any(|p| l.contains(&p.port));
                if ouvert(&[80, 8080]) {
                    trp!(
                        "    {GRIS}interface d'admin : http://{}{RESET}",
                        "    {GRIS}admin interface: http://{}{RESET}",
                        h.ip
                    );
                } else if ouvert(&[443, 8443]) {
                    trp!(
                        "    {GRIS}interface d'admin : https://{}{RESET}",
                        "    {GRIS}admin interface: https://{}{RESET}",
                        h.ip
                    );
                }
                if h.ports.iter().any(|p| [135, 139, 445].contains(&p.port)) {
                    trp!(
                        "    {GRIS}PC Windows : Paramètres > Réseau > Propriétés > profil « Public », et dans PowerShell admin :{RESET}",
                        "    {GRIS}Windows PC: Settings > Network > Properties > “Public” profile, and in an admin PowerShell:{RESET}"
                    );
                    println!("    {GRIS}  Set-SmbServerConfiguration -EnableSMB1Protocol $false{RESET}");
                }
            }
        }
    }

    if applique {
        trp!(
            "\n{GRIS}Nouvelle vérification…{RESET}",
            "\n{GRIS}Checking again…{RESET}"
        );
        let nouveau = machine::auditer(false);
        afficher_note(tr!("Avant", "Before"), audit.score);
        afficher_note(tr!("Après", "After"), nouveau.score);
        return Some(nouveau);
    }
    None
}
