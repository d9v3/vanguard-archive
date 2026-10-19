//! Comptes oubliés : un compte de l'ordinateur encore actif mais que personne n'utilise plus (l'ancien employé, le
//! compte créé pour un dépannage, celui d'un enfant parti). C'est une porte de plus, souvent avec un vieux mot de
//! passe. Gardien cherche la dernière trace d'utilisation : la dernière connexion notée par le système (Windows,
//! lastlog2 ou lastlog sous Linux), et la date du dossier personnel (Linux, macOS : une connexion graphique n'est pas
//! toujours notée). Rien depuis six mois : une information, avec la façon de le désactiver. Le compte qui lance
//! Gardien n'est jamais compté.

use super::{Constat, alerte};
use crate::risk::Niveau;
use crate::ui::affichable;
use crate::{tr, trf};

const CAT: &str = "Comptes";
/// Sans trace depuis plus longtemps, un compte est oublié.
const OUBLIE_JOURS: i64 = 180;

/// Un compte actif : son nom, et la dernière trace d'utilisation (`None` : aucune, jamais connecté).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Compte {
    nom: String,
    derniere: Option<chrono::NaiveDate>,
}

fn juger(comptes: &[Compte], aujourd_hui: chrono::NaiveDate) -> Vec<Constat> {
    comptes
        .iter()
        .filter_map(|c| {
            let nom = affichable(&c.nom);
            let message = match c.derniere {
                None => trf!(
                    "Le compte « {nom} » est actif mais n'a jamais servi : un compte oublié est une porte de plus, souvent avec un mot de passe faible.",
                    "The “{nom}” account is active but has never been used: a forgotten account is one more door, often with a weak password."
                ),
                Some(d) if (aujourd_hui - d).num_days() > OUBLIE_JOURS => trf!(
                    "Le compte « {nom} » est actif mais n'a pas servi depuis le {d} : un compte oublié est une porte de plus, souvent avec un vieux mot de passe.",
                    "The “{nom}” account is active but has not been used since {d}: a forgotten account is one more door, often with an old password."
                ),
                Some(_) => return None,
            };
            Some(alerte(CAT, Niveau::Info, message).manuel(desactiver(), &[]))
        })
        .collect()
}

/// Comment désactiver un compte sans rien effacer, sur ce système.
fn desactiver() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Si personne ne s'en sert, le désactiver (ses fichiers restent) : Gestion de l'ordinateur › Utilisateurs locaux, ou « Disable-LocalUser -Name <nom> » en administrateur",
            "If nobody uses it, disable it (its files stay): Computer Management › Local Users, or “Disable-LocalUser -Name <name>” as administrator"
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "Si personne ne s'en sert, le supprimer en gardant son dossier : Réglages Système › Utilisateurs et groupes",
            "If nobody uses it, delete it while keeping its folder: System Settings › Users & Groups"
        )
    } else {
        tr!(
            "Si personne ne s'en sert, le verrouiller (ses fichiers restent) : « sudo usermod --lock --expiredate 1 <nom> »",
            "If nobody uses it, lock it (its files stay): “sudo usermod --lock --expiredate 1 <name>”"
        )
    }
}

/// La date d'un fichier, en jour local.
#[cfg(unix)]
fn date_de(chemin: &std::path::Path) -> Option<chrono::NaiveDate> {
    let m = std::fs::metadata(chemin).ok()?.modified().ok()?;
    Some(chrono::DateTime::<chrono::Local>::from(m).date_naive())
}

/// Le compte qui lance Gardien (sous sudo : celui qui l'a lancé).
#[cfg(unix)]
fn moi() -> String {
    std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
}

/// « dp  tty1   Sat Oct 17 22:51:53 -0400 2026 » ou « **Never logged in** » (lastlog2, lastlog) : la date.
#[cfg(any(target_os = "linux", test))]
fn lire_lastlog(ligne: &str) -> Option<chrono::NaiveDate> {
    let mots: Vec<&str> = ligne.split_whitespace().collect();
    let i = mots
        .iter()
        .position(|m| m.len() == 3 && ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].contains(m))?;
    let texte = mots.get(i..i + 6)?.join(" ");
    chrono::DateTime::parse_from_str(&texte, "%a %b %e %H:%M:%S %z %Y")
        .ok()
        .map(|d| d.date_naive())
}

#[cfg(target_os = "linux")]
pub fn constats() -> Vec<Constat> {
    let moi = moi();
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let comptes: Vec<Compte> = passwd
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split(':').collect();
            let (nom, uid, maison, shell) = (*c.first()?, c.get(2)?.parse::<u32>().ok()?, *c.get(5)?, *c.get(6)?);
            let humain = (1000..60000).contains(&uid) && !shell.ends_with("nologin") && !shell.ends_with("false");
            (humain && nom != moi).then(|| (nom.to_string(), maison.to_string()))
        })
        .map(|(nom, maison)| {
            let connexion = ["lastlog2", "lastlog"].iter().find_map(|outil| {
                let r = crate::commande::lancer_en_anglais(std::process::Command::new(outil).args(["-u", &nom]), 5)?;
                r.sortie.lines().skip(1).find_map(lire_lastlog)
            });
            let dossier = date_de(std::path::Path::new(&maison));
            Compte {
                nom,
                derniere: connexion.max(dossier),
            }
        })
        .collect();
    juger(&comptes, chrono::Local::now().date_naive())
}

/// macOS : les comptes à partir de 501 (dscl), jugés à la date de leur dossier personnel.
#[cfg(target_os = "macos")]
pub fn constats() -> Vec<Constat> {
    let moi = moi();
    let Some(r) = crate::commande::lancer(
        std::process::Command::new("dscl").args([".", "-list", "/Users", "UniqueID"]),
        10,
    ) else {
        return Vec::new();
    };
    let comptes: Vec<Compte> = r
        .sortie
        .lines()
        .filter_map(|l| {
            let (nom, uid) = l.trim().rsplit_once(char::is_whitespace)?;
            let nom = nom.trim();
            let uid: u32 = uid.trim().parse().ok()?;
            (uid >= 501 && !nom.starts_with('_') && nom != moi).then(|| Compte {
                nom: nom.to_string(),
                derniere: date_de(&std::path::Path::new("/Users").join(nom)),
            })
        })
        .collect();
    juger(&comptes, chrono::Local::now().date_naive())
}

/// Windows : les comptes locaux actifs et leur dernière connexion, sauf les comptes intégrés (Administrateur, Invité,
/// DefaultAccount, WDAGUtilityAccount : déjà jugés à part ou sans session) et le compte en cours.
#[cfg(windows)]
pub fn constats() -> Vec<Constat> {
    let sortie = super::windows::ps(
        "$moi = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; \
         Get-LocalUser | Where-Object { $_.Enabled -and $_.SID.Value -ne $moi -and $_.SID.Value -notmatch '-(500|501|503|504)$' } | \
         ForEach-Object { \"CPT|$(if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') })|$($_.Name)\" }; 'CPT_FIN'",
    );
    let Some(lignes) = crate::commande::section(sortie.as_deref(), "CPT") else {
        return Vec::new();
    };
    let comptes: Vec<Compte> = lignes
        .iter()
        .filter_map(|l| {
            let (date, nom) = l.split_once('|')?;
            Some(Compte {
                nom: nom.trim().to_string(),
                derniere: chrono::NaiveDate::parse_from_str(date.trim(), "%Y-%m-%d").ok(),
            })
        })
        .collect();
    juger(&comptes, chrono::Local::now().date_naive())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jour(a: i32, m: u32, j: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(a, m, j).unwrap()
    }

    #[test]
    fn comptes_oublies_seulement() {
        let comptes = [
            Compte {
                nom: "alice".into(),
                derniere: Some(jour(2026, 10, 1)),
            },
            Compte {
                nom: "ancien".into(),
                derniere: Some(jour(2025, 12, 1)),
            },
            Compte {
                nom: "depannage".into(),
                derniere: None,
            },
        ];
        let c = juger(&comptes, jour(2026, 10, 19));
        assert_eq!(c.len(), 2);
        assert!(c[0].message.contains("ancien") && c[0].message.contains("2025-12-01"));
        assert!(c[1].message.contains("jamais"));
        assert!(
            c.iter()
                .all(|x| x.probleme == Some(Niveau::Info) && !x.correctif.as_ref().unwrap().automatique)
        );
    }

    #[test]
    fn dates_de_lastlog() {
        assert_eq!(
            lire_lastlog(
                "dp               tty1                                                Sat Oct 17 22:51:53 -0400 2026"
            ),
            Some(jour(2026, 10, 17))
        );
        assert_eq!(
            lire_lastlog("bob      pts/0    10.0.0.5   Mon Mar  2 09:05:01 +0100 2026"),
            Some(jour(2026, 3, 2))
        );
        assert_eq!(lire_lastlog("ancien                    **Never logged in**"), None);
    }
}
