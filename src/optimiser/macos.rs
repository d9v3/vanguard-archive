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
}

fn bool_texte(b: bool) -> String {
    if b { "1" } else { "0" }.to_string()
}

fn shell(t: &str) -> String {
    format!("'{}'", t.replace('\'', r"'\''"))
}

impl Changement {
    pub fn lire(&self) -> Valeur {
        let Changement::Preference { domaine, cle, .. } = self;
        let r = crate::commande::lancer(Command::new("defaults").args(["read", domaine, cle]), 10)?;
        (r.code == Some(0)).then(|| r.sortie.trim().to_string())
    }

    // Même forme que `lire`, pour les comparer.
    #[allow(clippy::unnecessary_wraps)]
    pub fn cible(&self) -> Valeur {
        let Changement::Preference { cible, .. } = self;
        Some(bool_texte(*cible))
    }

    pub fn defaut(&self) -> Valeur {
        let Changement::Preference { defaut, .. } = self;
        defaut.map(bool_texte)
    }

    pub fn decrire(&self, v: Option<&str>) -> String {
        let Changement::Preference { domaine, cle, .. } = self;
        match v {
            Some("1") => format!("defaults write {domaine} {cle} -bool true"),
            Some(_) => format!("defaults write {domaine} {cle} -bool false"),
            None => format!("defaults delete {domaine} {cle}"),
        }
    }

    fn commande(&self, v: Option<&str>) -> String {
        let Changement::Preference {
            domaine, cle, admin, ..
        } = self;
        let sudo = if *admin { "sudo " } else { "" };
        match v {
            Some(v) => format!(
                "{sudo}defaults write {} {cle} -bool {}",
                shell(domaine),
                if v == "1" { "true" } else { "false" }
            ),
            // Déjà absente : `defaults delete` répond par une erreur, qui n'en est pas une ici.
            None => format!("{sudo}defaults delete {} {cle} 2>/dev/null; true", shell(domaine)),
        }
    }
}

pub fn ecrire(lots: &[Vec<(&Changement, Valeur)>]) -> Vec<bool> {
    let commandes: Vec<Vec<String>> = lots
        .iter()
        .map(|lot| lot.iter().map(|(c, v)| c.commande(v.as_deref())).collect())
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
