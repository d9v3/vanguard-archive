//! Nouveaux administrateurs : un compte ajouté au groupe des administrateurs (wheel, sudo ou admin sous Linux, admin
//! sous macOS, Administrateurs sous Windows) a tous les droits. Un intrus qui s'installe se les donne souvent ainsi.
//! Gardien note la première fois qu'il voit chaque administrateur (administrateurs.json, sur cet ordinateur) et
//! signale ceux de la dernière semaine ; ceux du premier passage sont connus d'avant. La surveillance horaire suit la
//! catégorie « Comptes » : un nouvel administrateur y fait une notification.

use std::collections::BTreeMap;

use chrono::NaiveDate;

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::ui::{affichable, resume};
use crate::{tr, trf};

const CAT: &str = "Comptes";
const RECENT_JOURS: i64 = 7;

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq, Eq)]
struct Vus {
    /// Nom → date de la première fois (« AAAA-MM-JJ »), vide pour ceux du premier passage.
    vus: BTreeMap<String, String>,
}

fn fichier() -> std::path::PathBuf {
    crate::reseau::dossier_local().join("administrateurs.json")
}

/// Les membres des groupes d'administration dans /etc/group (« wheel:x:998:alice,bob »).
#[cfg(any(target_os = "linux", test))]
fn lire_groupes(texte: &str) -> Vec<String> {
    let mut noms: Vec<String> = texte
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split(':').collect();
            (c.len() >= 4 && matches!(c[0], "wheel" | "sudo" | "admin")).then(|| c[3])
        })
        .flat_map(|membres| {
            membres
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(String::from)
        })
        .collect();
    noms.sort();
    noms.dedup();
    noms
}

/// « GroupMembership: root alice » (dscl . -read /Groups/admin GroupMembership).
#[cfg(any(target_os = "macos", test))]
fn lire_dscl(texte: &str) -> Vec<String> {
    texte
        .split_once("GroupMembership:")
        .map(|(_, r)| {
            r.split_whitespace()
                .filter(|n| *n != "root")
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Les administrateurs de cet ordinateur ; `None` : la liste ne se lit pas.
fn lire() -> Option<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/group").ok().map(|t| lire_groupes(&t))
    }
    #[cfg(target_os = "macos")]
    {
        let r = crate::commande::lancer(
            std::process::Command::new("dscl").args([".", "-read", "/Groups/admin", "GroupMembership"]),
            10,
        )?;
        Some(lire_dscl(&r.sortie))
    }
    #[cfg(windows)]
    {
        // Le groupe par son identifiant (S-1-5-32-544) : son nom change avec la langue de Windows.
        let sortie = super::windows::ps(
            "try { Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { 'ADM|' + $_.Name }; 'ADM_FIN' } catch {}",
        );
        crate::commande::section(sortie.as_deref(), "ADM").map(|l| {
            l.iter()
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .collect()
        })
    }
}

fn juger(admins: &[String], avant: Option<&Vus>, aujourd_hui: NaiveDate) -> (Constat, Vus) {
    let mut vus = avant.map(|v| v.vus.clone()).unwrap_or_default();
    for a in admins {
        let date = if avant.is_some() {
            aujourd_hui.format("%Y-%m-%d").to_string()
        } else {
            String::new()
        };
        vus.entry(a.clone()).or_insert(date);
    }
    let recents: Vec<String> = admins
        .iter()
        .filter(|a| {
            vus.get(*a)
                .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
                .is_some_and(|d| (aujourd_hui - d).num_days() < RECENT_JOURS)
        })
        .map(|a| affichable(a))
        .collect();
    let constat = if recents.is_empty() {
        let noms: Vec<String> = admins.iter().map(|a| affichable(a)).collect();
        ok(
            CAT,
            trf!(
                "Administrateurs de cet ordinateur : {} ; aucun nouveau cette semaine.",
                "Administrators of this computer: {}; none new this week.",
                if noms.is_empty() {
                    tr!("aucun en dehors de root", "none besides root").to_string()
                } else {
                    resume(&noms, 5, ", ")
                }
            ),
        )
    } else {
        alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "Nouveau compte administrateur cette semaine : {}. Si ce n'est pas toi qui l'as ajouté, quelqu'un s'est donné tous les droits sur cet ordinateur.",
                "New administrator account this week: {}. If you did not add it, someone gave themselves every right on this computer.",
                recents.join(", ")
            ),
        )
        .manuel(retrait(), &[])
    };
    (constat, Vus { vus })
}

fn retrait() -> &'static str {
    if cfg!(windows) {
        tr!(
            "S'il n'est pas à toi : le retirer des administrateurs (Gestion de l'ordinateur › Utilisateurs et groupes locaux › Groupes › Administrateurs), puis changer tes mots de passe et lancer l'antivirus",
            "If it is not yours: remove it from administrators (Computer Management › Local Users and Groups › Groups › Administrators), then change your passwords and run the antivirus"
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "S'il n'est pas à toi : Réglages Système › Utilisateurs et groupes, lui retirer « Administrateur », puis changer tes mots de passe",
            "If it is not yours: System Settings › Users & Groups, remove “Administrator”, then change your passwords"
        )
    } else {
        tr!(
            "S'il n'est pas à toi : le retirer du groupe (« sudo gpasswd -d <compte> wheel », ou sudo), puis changer tes mots de passe et lancer l'antivirus",
            "If it is not yours: remove it from the group (“sudo gpasswd -d <account> wheel”, or sudo), then change your passwords and run the antivirus"
        )
    }
}

pub fn constat() -> Option<Constat> {
    let admins = lire()?;
    let avant: Option<Vus> = std::fs::read_to_string(fichier())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    let (c, apres) = juger(&admins, avant.as_ref(), chrono::Local::now().date_naive());
    if avant.as_ref() != Some(&apres)
        && let Ok(texte) = serde_json::to_string_pretty(&apres)
    {
        let _ = std::fs::create_dir_all(crate::reseau::dossier_local());
        let _ = crate::reseau::ecrire_atomique(&fichier(), texte);
    }
    Some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jour(j: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, j).unwrap()
    }

    #[test]
    fn lectures() {
        let group = "root:x:0:root\nwheel:x:998:alice,bob\nsudo:x:27:alice\nvideo:x:985:alice,carol\n";
        assert_eq!(lire_groupes(group), ["alice", "bob"]);
        assert_eq!(lire_dscl("GroupMembership: root alice bob\n"), ["alice", "bob"]);
        assert_eq!(lire_dscl("No such key: GroupMembership"), Vec::<String>::new());
    }

    #[test]
    fn nouvel_administrateur_signale_une_semaine() {
        let alice = vec!["alice".to_string()];
        let (c, vus) = juger(&alice, None, jour(10));
        assert!(c.probleme.is_none() && c.message.contains("alice"));
        let deux = vec!["alice".to_string(), "intrus".to_string()];
        let (c, vus) = juger(&deux, Some(&vus), jour(12));
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("intrus") && !c.message.contains("alice"));
        assert_eq!(juger(&deux, Some(&vus), jour(18)).0.probleme, Some(Niveau::Eleve));
        assert!(juger(&deux, Some(&vus), jour(19)).0.probleme.is_none());
    }
}
