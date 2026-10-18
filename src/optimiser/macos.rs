//! Réglages de macOS : préférences `defaults` (booléens) du compte, ou de la machine pour celles qui demandent les
//! droits administrateur. Le Finder est relancé à la fin quand un de ses réglages a changé.

use std::process::Command;

use super::{Categorie, Reglage, Valeur};
use crate::ui::*;

pub enum Changement {
    /// Préférence booléenne : domaine (ou fichier .plist), clé, valeur voulue, valeur d'un Mac neuf (`None` : absente),
    /// et s'il faut les droits administrateur pour l'écrire.
    Preference {
        domaine: &'static str,
        cle: &'static str,
        cible: bool,
        defaut: Option<bool>,
        admin: bool,
    },
    /// Serveurs DNS d'un service réseau (« Wi-Fi »), outil « DNS le plus rapide ». Valeur : « service\n1.1.1.1,… »,
    /// vide pour ceux de la box. `cible` : `None` quand le réglage n'est rebâti que pour être annulé.
    Dns { service: String, cible: Option<String> },
}

fn bool_texte(b: bool) -> String {
    if b { "1" } else { "0" }.to_string()
}

fn shell(t: &str) -> String {
    format!("'{}'", t.replace('\'', r"'\''"))
}

/// `networksetup -getdnsservers` : une adresse par ligne, ou une phrase quand il n'y en a pas (ceux de la box).
fn lire_networksetup(sortie: &str) -> String {
    sortie
        .lines()
        .map(str::trim)
        .filter(|l| l.parse::<std::net::IpAddr>().is_ok())
        .collect::<Vec<_>>()
        .join(",")
}

impl Changement {
    pub fn lire(&self) -> Valeur {
        match self {
            Changement::Preference { domaine, cle, .. } => {
                let r = crate::commande::lancer(Command::new("defaults").args(["read", domaine, cle]), 10)?;
                (r.code == Some(0)).then(|| r.sortie.trim().to_string())
            }
            Changement::Dns { service, .. } => {
                let r = crate::commande::lancer(Command::new("networksetup").args(["-getdnsservers", service]), 10)?;
                // Un service inconnu répond « … is not a recognized network service » : illisible, pas « aucun ».
                (r.code == Some(0) && !r.sortie.contains("not a recognized"))
                    .then(|| format!("{service}\n{}", lire_networksetup(&r.sortie)))
            }
        }
    }

    // Même forme que `lire`, pour les comparer.
    #[allow(clippy::unnecessary_wraps)]
    pub fn cible(&self) -> Valeur {
        Some(match self {
            Changement::Preference { cible, .. } => bool_texte(*cible),
            // Rebâti pour être annulé : une cible qu'aucune lecture ne donne.
            Changement::Dns { service, cible } => format!("{service}\n{}", cible.as_deref().unwrap_or("?")),
        })
    }

    pub fn defaut(&self) -> Valeur {
        match self {
            Changement::Preference { defaut, .. } => defaut.map(bool_texte),
            // Les DNS donnés par la box.
            Changement::Dns { service, .. } => Some(format!("{service}\n")),
        }
    }

    pub fn decrire(&self, v: Option<&str>) -> String {
        match self {
            Changement::Preference { domaine, cle, .. } => match v {
                Some("1") => format!("defaults write {domaine} {cle} -bool true"),
                Some(_) => format!("defaults write {domaine} {cle} -bool false"),
                None => format!("defaults delete {domaine} {cle}"),
            },
            Changement::Dns { .. } => {
                let serveurs: Vec<&str> = v
                    .and_then(|v| v.split_once('\n'))
                    .map_or("", |(_, l)| l)
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .collect();
                super::texte_dns(&serveurs, false)
            }
        }
    }

    fn commande(&self, v: Option<&str>) -> Option<String> {
        match self {
            Changement::Preference {
                domaine, cle, admin, ..
            } => {
                let sudo = if *admin { "sudo " } else { "" };
                Some(match v {
                    Some(v) => format!(
                        "{sudo}defaults write {} {cle} -bool {}",
                        shell(domaine),
                        if v == "1" { "true" } else { "false" }
                    ),
                    // Déjà absente : `defaults delete` répond par une erreur, qui n'en est pas une ici.
                    None => format!("{sudo}defaults delete {} {cle} 2>/dev/null; true", shell(domaine)),
                })
            }
            Changement::Dns { service, .. } => {
                let (id, liste) = v?.split_once('\n')?;
                if id != service {
                    return None;
                }
                // Seules des adresses IP entrent dans la commande ; « empty » rend ceux de la box.
                let serveurs: Vec<String> = liste
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse::<std::net::IpAddr>().map(|ip| ip.to_string()))
                    .collect::<Result<_, _>>()
                    .ok()?;
                let serveurs = if serveurs.is_empty() {
                    "empty".to_string()
                } else {
                    serveurs.join(" ")
                };
                Some(format!(
                    "sudo networksetup -setdnsservers {} {serveurs}",
                    shell(service)
                ))
            }
        }
    }

    /// Le service réseau d'un réglage de DNS.
    pub fn identite_dns(&self) -> Option<&str> {
        match self {
            Changement::Dns { service, .. } => Some(service),
            Changement::Preference { .. } => None,
        }
    }

    /// Le réglage de DNS rebâti d'après sa valeur d'avant notée, pour l'annuler.
    pub fn dns_note(avant: &str) -> Option<Changement> {
        let (service, _) = avant.split_once('\n')?;
        (!service.is_empty()).then(|| Changement::Dns {
            service: service.to_string(),
            cible: None,
        })
    }
}

/// Le service réseau d'une carte, dans `networksetup -listnetworkserviceorder` : « (1) Wi-Fi » puis
/// « (Hardware Port: Wi-Fi, Device: en0) ». Un service coupé commence par « (*) ».
fn service_de(liste: &str, carte: &str) -> Option<String> {
    let mut nom: Option<&str> = None;
    for l in liste.lines().map(str::trim) {
        if let Some(reste) = l.strip_prefix('(')
            && let Some((numero, service)) = reste.split_once(") ")
            && (numero == "*" || numero.parse::<u32>().is_ok())
        {
            nom = (numero != "*").then_some(service);
        } else if l.contains(&format!("Device: {carte})")) {
            return nom.map(str::to_string);
        }
    }
    None
}

/// Le DNS du service réseau de la route par défaut, à régler sur ces serveurs (IPv4 et IPv6 ensemble : macOS ne
/// se sert que de ceux qu'il peut joindre). Erreur : pourquoi il faut le faire à la main.
pub fn dns_principal(v4: &[&str], v6: &[&str]) -> Result<Changement, String> {
    let a_la_main = tr!(
        "Le service réseau principal est illisible : le DNS se règle à la main (Réglages Système > Réseau, ou dans la box).",
        "The main network service is unreadable: set the DNS by hand (System Settings > Network, or in the router)."
    );
    let route = crate::commande::lancer(Command::new("route").args(["-n", "get", "default"]), 10)
        .map(|r| r.sortie)
        .unwrap_or_default();
    let carte = route
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:"))
        .map(str::trim)
        .ok_or_else(|| tr!("Pas de connexion à Internet.", "No Internet connection.").to_string())?;
    let liste = crate::commande::lancer(Command::new("networksetup").arg("-listnetworkserviceorder"), 10)
        .map(|r| r.sortie)
        .unwrap_or_default();
    let service = service_de(&liste, carte).ok_or_else(|| a_la_main.to_string())?;
    let mut serveurs: Vec<&str> = v4.to_vec();
    serveurs.extend(v6);
    Ok(Changement::Dns {
        service,
        cible: Some(serveurs.join(",")),
    })
}

pub fn ecrire(lots: &[Vec<(&Changement, Valeur)>]) -> Vec<bool> {
    let commandes: Vec<Vec<String>> = lots
        .iter()
        .map(|lot| lot.iter().filter_map(|(c, v)| c.commande(v.as_deref())).collect())
        .collect();
    crate::machine::appliquer_chacune(&commandes)
}

/// Le Finder relit ses préférences à son démarrage : on le relance si l'une d'elles a changé.
pub fn apres(touches: &[&Reglage]) {
    if touches
        .iter()
        .any(|r| matches!(r.id, "extensions" | "fichiers_caches" | "chemin_finder"))
    {
        let _ = Command::new("killall").arg("Finder").status();
    }
}

fn pref(domaine: &'static str, cle: &'static str, cible: bool) -> Changement {
    Changement::Preference {
        domaine,
        cle,
        cible,
        defaut: None,
        admin: false,
    }
}

pub fn catalogue() -> Vec<Reglage> {
    use Categorie::{Confidentialite, Confort};
    const DIAGNOSTICS: &str = "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory";
    vec![
        Reglage {
            id: "pub_personnalisee",
            categorie: Confidentialite,
            titre: tr!(
                "Publicités personnalisées d'Apple coupées",
                "Apple personalized ads off"
            ),
            effet: tr!(
                "Apple ne se sert plus de ce qu'il sait de toi pour choisir les publicités de l'App Store, d'Apple News et de Bourse.",
                "Apple no longer uses what it knows about you to pick ads in the App Store, Apple News and Stocks."
            ),
            prudence: None,
            recommande: true,
            changements: vec![pref("com.apple.AdLib", "allowApplePersonalizedAdvertising", false)],
        },
        Reglage {
            id: "analyses",
            categorie: Confidentialite,
            titre: tr!("Analyses du Mac gardées pour toi", "Mac analytics kept to yourself"),
            effet: tr!(
                "Les rapports d'utilisation et de plantage ne partent plus chez Apple ni chez les développeurs des applications.",
                "Usage and crash reports no longer go to Apple or to app developers."
            ),
            prudence: None,
            recommande: true,
            changements: ["AutoSubmit", "ThirdPartyDataSubmit"]
                .into_iter()
                .map(|cle| Changement::Preference {
                    domaine: DIAGNOSTICS,
                    cle,
                    cible: false,
                    defaut: None,
                    admin: true,
                })
                .collect(),
        },
        Reglage {
            id: "extensions",
            categorie: Confort,
            titre: tr!("Extensions des fichiers visibles", "File extensions shown"),
            effet: tr!(
                "Le Finder affiche « facture.pdf.app » au lieu de « facture.pdf » : un programme ne peut plus se faire passer pour un document.",
                "Finder shows “invoice.pdf.app” instead of “invoice.pdf”: a program can no longer pass for a document."
            ),
            prudence: None,
            recommande: true,
            changements: vec![pref("NSGlobalDomain", "AppleShowAllExtensions", true)],
        },
        Reglage {
            id: "ds_store",
            categorie: Confort,
            titre: tr!(
                "Pas de .DS_Store sur les clés et partages",
                "No .DS_Store on drives and shares"
            ),
            effet: tr!(
                "Le Mac n'écrit plus ses fichiers cachés .DS_Store sur les clés USB et les dossiers partagés : rien de laissé chez les autres.",
                "The Mac no longer writes its hidden .DS_Store files on USB drives and shared folders: nothing left behind on other people's things."
            ),
            prudence: None,
            recommande: true,
            changements: vec![
                pref("com.apple.desktopservices", "DSDontWriteUSBStores", true),
                pref("com.apple.desktopservices", "DSDontWriteNetworkStores", true),
            ],
        },
        Reglage {
            id: "fichiers_caches",
            categorie: Confort,
            titre: tr!("Fichiers cachés visibles", "Hidden files shown"),
            effet: tr!(
                "Le Finder montre aussi les fichiers et dossiers cachés (Cmd-Maj-. les masque à nouveau).",
                "Finder also shows hidden files and folders (Cmd-Shift-. hides them again)."
            ),
            prudence: None,
            recommande: false,
            changements: vec![pref("com.apple.finder", "AppleShowAllFiles", true)],
        },
        Reglage {
            id: "chemin_finder",
            categorie: Confort,
            titre: tr!("Chemin complet dans le Finder", "Full path in Finder"),
            effet: tr!(
                "Le titre des fenêtres du Finder montre le chemin complet du dossier.",
                "Finder window titles show the folder's full path."
            ),
            prudence: None,
            recommande: false,
            changements: vec![pref("com.apple.finder", "_FXShowPosixPathInTitle", true)],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_d_un_service_reseau() {
        assert_eq!(lire_networksetup("There aren't any DNS Servers set on Wi-Fi.\n"), "");
        assert_eq!(
            lire_networksetup("1.1.1.1\n2606:4700:4700::1111\n"),
            "1.1.1.1,2606:4700:4700::1111"
        );
        let liste = "An asterisk (*) denotes that a network service is disabled.\n(1) Wi-Fi\n\
                     (Hardware Port: Wi-Fi, Device: en0)\n\n(*) Ethernet\n(Hardware Port: Ethernet, Device: en1)\n\n\
                     (2) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n";
        assert_eq!(service_de(liste, "en0").as_deref(), Some("Wi-Fi"));
        assert_eq!(service_de(liste, "en1"), None, "service coupé");
        assert_eq!(service_de(liste, "en9"), None);
        let c = Changement::Dns {
            service: "Wi-Fi".into(),
            cible: Some("1.1.1.1,1.0.0.1".into()),
        };
        let cible = c.cible().unwrap();
        assert_eq!(
            c.commande(Some(&cible)).as_deref(),
            Some("sudo networksetup -setdnsservers 'Wi-Fi' 1.1.1.1 1.0.0.1")
        );
        assert_eq!(
            c.commande(c.defaut().as_deref()).as_deref(),
            Some("sudo networksetup -setdnsservers 'Wi-Fi' empty")
        );
        // Autre chose qu'une adresse IP, ou un autre service : aucune commande.
        assert_eq!(c.commande(Some("Wi-Fi\n1.1.1.1;reboot")), None);
        assert_eq!(c.commande(Some("Ethernet\n")), None);
        assert!(Changement::dns_note("Wi-Fi\n").is_some_and(|r| r.identite_dns() == Some("Wi-Fi")));
    }
}
