//! Langue de l'interface : français ou anglais, choisie d'après le système (variable NETSCAN_LANG pour forcer).
//! Chaque texte est écrit dans les deux langues à l'endroit où il sert : `tr!("Pare-feu actif", "Firewall on")`.
//! Les noms internes (catégories des constats, clés JSON) restent en français : le code s'en sert pour décider.

use std::sync::OnceLock;

static ANGLAIS: OnceLock<bool> = OnceLock::new();

/// Code de langue d'une variable d'environnement : « fr_CA.UTF-8 » → « fr », « C » ou vide → `None`.
fn code(valeur: &str) -> Option<String> {
    let c = valeur.split(['_', '.', '@', '-']).next()?.trim().to_ascii_lowercase();
    (c.len() == 2 || c.len() == 3).then_some(c)
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux, où la langue peut être inconnue
fn langue_systeme() -> Option<String> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }
    // SAFETY : fonction sans argument de l'API Windows, toujours disponible.
    let id = unsafe { GetUserDefaultUILanguage() };
    // 10 bits bas = langue principale ; 0x0C = français (France, Canada, Belgique, Suisse…).
    Some(if id & 0x3ff == 0x0c { "fr" } else { "en" }.to_string())
}

#[cfg(not(windows))]
fn langue_systeme() -> Option<String> {
    // Même ordre de priorité que gettext : LC_ALL, puis LC_MESSAGES, puis LANG.
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .find(|v| !v.is_empty())
        .and_then(|v| code(&v))
}

/// Français si le système est en français, anglais sinon. Les tests, eux, sont toujours en français.
fn detecter() -> bool {
    if cfg!(test) {
        return false;
    }
    let forcee = std::env::var("NETSCAN_LANG").ok().and_then(|v| code(&v));
    forcee.or_else(langue_systeme).is_none_or(|c| c != "fr")
}

pub fn anglais() -> bool {
    *ANGLAIS.get_or_init(detecter)
}

/// Le texte dans la langue de l'interface (deux littéraux) : `tr!("Annulé.", "Cancelled.")`.
#[macro_export]
macro_rules! tr {
    ($fr:literal, $en:literal $(,)?) => {
        if $crate::langue::anglais() { $en } else { $fr }
    };
}

/// `format!` dans la langue de l'interface : `trf!("{n} appareil(s)", "{n} device(s)")`.
#[macro_export]
macro_rules! trf {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { format!($en $(, $arg)*) } else { format!($fr $(, $arg)*) }
    };
}

/// `println!` dans la langue de l'interface.
#[macro_export]
macro_rules! trp {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { println!($en $(, $arg)*) } else { println!($fr $(, $arg)*) }
    };
}

/// `eprintln!` dans la langue de l'interface.
#[macro_export]
macro_rules! tre {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { eprintln!($en $(, $arg)*) } else { eprintln!($fr $(, $arg)*) }
    };
}

/// `print!` dans la langue de l'interface.
#[macro_export]
macro_rules! trpr {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { print!($en $(, $arg)*) } else { print!($fr $(, $arg)*) }
    };
}

/// `write!` dans la langue de l'interface.
#[macro_export]
macro_rules! trw {
    ($dest:expr, $fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { write!($dest, $en $(, $arg)*) } else { write!($dest, $fr $(, $arg)*) }
    };
}

/// `writeln!` dans la langue de l'interface.
#[macro_export]
macro_rules! trwln {
    ($dest:expr, $fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { writeln!($dest, $en $(, $arg)*) } else { writeln!($dest, $fr $(, $arg)*) }
    };
}

/// Réponse « oui » à une question [o/N] : o, oui, y, yes, quelle que soit la langue.
pub fn oui(reponse: &str) -> bool {
    matches!(reponse.trim().to_lowercase().as_str(), "o" | "oui" | "y" | "yes")
}

/// `demander(…).oui()` : la réponse à une question [o/N] / [y/N], dans les deux langues.
pub trait Reponse {
    fn oui(&self) -> bool;
    fn non(&self) -> bool;
}

impl Reponse for String {
    fn oui(&self) -> bool {
        oui(self)
    }
    fn non(&self) -> bool {
        matches!(self.trim().to_lowercase().as_str(), "n" | "non" | "no")
    }
}

/// Réponse « tout » : t (tout) ou a (all).
pub fn tout(reponse: &str) -> bool {
    matches!(reponse.trim().to_lowercase().as_str(), "t" | "tout" | "a" | "all")
}

/// Nom affiché du rôle d'un appareil du réseau (son nom interne est français).
pub fn role(nom: &str) -> &str {
    match (anglais(), nom) {
        (true, "passerelle") => "gateway",
        (true, "cette machine") => "this machine",
        _ => nom,
    }
}

/// Nom affiché d'une catégorie de constat (son nom interne est français).
pub fn categorie(nom: &str) -> &str {
    if !anglais() {
        return nom;
    }
    match nom {
        "Pare-feu" => "Firewall",
        "Bureau à distance" => "Remote Desktop",
        "Carte graphique" => "Graphics card",
        "Chiffrement" => "Encryption",
        "Clés SSH" => "SSH keys",
        "Comptes" => "Accounts",
        "Failles connues" => "Known flaws",
        "Fichiers secrets" => "Secret files",
        "Fichiers suspects" => "Suspicious files",
        "Groupes" => "Groups",
        "Mises à jour" => "Updates",
        "Noyau" => "Kernel",
        "Noyau durci" => "Kernel hardening",
        "Paquets AUR" => "AUR packages",
        "Persistance" => "Persistence",
        "Pilotes" => "Drivers",
        "Pilotes DKMS" => "DKMS drivers",
        "Ports en écoute" => "Listening ports",
        "Processeur" => "Processor",
        "Programmes" => "Programs",
        "Périphériques" => "Devices",
        "Redémarrage" => "Restart",
        "Sauvegardes" => "Backups",
        "Verrouillage" => "Screen lock",
        _ => nom,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_de_langue() {
        assert_eq!(code("fr_CA.UTF-8").as_deref(), Some("fr"));
        assert_eq!(code("en_US").as_deref(), Some("en"));
        assert_eq!(code("fr").as_deref(), Some("fr"));
        assert_eq!(code("C"), None);
        assert_eq!(code(""), None);
        assert!(oui("Yes") && oui("o") && !oui("n") && !oui(""));
        assert!(tout("a") && tout("T") && !tout("o"));
    }
}
