//! Audit de sécurité de cette machine : types communs, affichage et exécution des correctifs.
//! Les vérifications elles-mêmes dépendent du système (linux.rs, windows.rs, macos.rs).

use std::process::Command;

use serde::Serialize;

use crate::risk::Niveau;
use crate::ui::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
use windows as os;

#[derive(Serialize, Clone)]
pub struct Correctif {
    /// Ce que fait la correction, en une phrase.
    pub action: String,
    /// Commandes exécutées dans l'ordre : bash sous Linux/macOS, PowerShell (administrateur) sous Windows.
    pub commandes: Vec<String>,
    /// `false` = à faire soi-même (redémarrage, réglage du routeur…) : on affiche seulement la marche à suivre.
    pub automatique: bool,
}

#[derive(Serialize)]
pub struct Constat {
    pub categorie: &'static str,
    /// `None` = tout va bien.
    pub probleme: Option<Niveau>,
    pub message: String,
    pub correctif: Option<Correctif>,
}

#[derive(Serialize)]
pub struct Audit {
    pub systeme: &'static str,
    pub score: u32,
    pub constats: Vec<Constat>,
}

fn ok(categorie: &'static str, message: impl Into<String>) -> Constat {
    Constat { categorie, probleme: None, message: message.into(), correctif: None }
}

fn alerte(categorie: &'static str, niveau: Niveau, message: impl Into<String>) -> Constat {
    Constat { categorie, probleme: Some(niveau), message: message.into(), correctif: None }
}

impl Constat {
    fn corriger(mut self, action: impl Into<String>, commandes: &[&str]) -> Self {
        self.correctif = Some(Correctif {
            action: action.into(),
            commandes: commandes.iter().map(|c| c.to_string()).collect(),
            automatique: true,
        });
        self
    }

    fn manuel(self, action: impl Into<String>, commandes: &[&str]) -> Self {
        let mut c = self.corriger(action, commandes);
        if let Some(k) = &mut c.correctif {
            k.automatique = false;
        }
        c
    }
}

fn score(constats: &[Constat]) -> u32 {
    100u32.saturating_sub(constats.iter().filter_map(|c| c.probleme).map(Niveau::penalite).sum())
}

/// Sortie standard d'une commande, ou `None` si elle est absente ou échoue.
#[cfg(unix)]
fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Permissions de ~/.ssh (commun à Linux et macOS).
#[cfg(unix)]
fn cles_ssh() -> Vec<Constat> {
    let dossier = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".ssh");
    let Ok(meta) = std::fs::metadata(&dossier) else {
        return vec![ok("Clés SSH", "Pas de dossier ~/.ssh.")];
    };
    let mut constats = Vec::new();
    if std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o077 != 0 {
        constats.push(
            alerte("Clés SSH", Niveau::Eleve, "~/.ssh est lisible par d'autres utilisateurs.")
                .corriger("Restreindre ~/.ssh à toi seul", &["chmod 700 ~/.ssh"]),
        );
    }
    for f in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
        let nom = f.file_name().to_string_lossy().into_owned();
        let privee = nom.starts_with("id_") && !nom.ends_with(".pub");
        if privee && f.metadata().is_ok_and(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o077 != 0) {
            constats.push(
                alerte("Clés SSH", Niveau::Critique, format!("Clé privée ~/.ssh/{nom} lisible par d'autres."))
                    .corriger(format!("Protéger la clé {nom}"), &[&format!("chmod 600 ~/.ssh/{nom}")]),
            );
        }
    }
    if constats.is_empty() {
        constats.push(ok("Clés SSH", "Permissions de ~/.ssh correctes."));
    }
    constats
}

/// Exécute les commandes d'un correctif. Sous Windows, une seule fenêtre UAC par correctif.
pub fn appliquer(commandes: &[String]) -> bool {
    #[cfg(windows)]
    {
        let script = format!("$ErrorActionPreference='Stop'\n{}", commandes.join("\n"));
        for c in commandes {
            println!("    {GRIS}PS> {c}{RESET}");
        }
        windows::powershell_admin(&script)
    }
    #[cfg(not(windows))]
    {
        for c in commandes {
            println!("    {GRIS}$ {c}{RESET}");
            if !Command::new("bash").arg("-c").arg(c).status().is_ok_and(|s| s.success()) {
                return false;
            }
        }
        true
    }
}

/// Ouvre un fichier ou une URL avec l'application par défaut du système.
pub fn ouvrir(cible: &str) {
    #[cfg(target_os = "linux")]
    let _ = Command::new("xdg-open").arg(cible).spawn();
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg(cible).spawn();
    #[cfg(windows)]
    let _ = Command::new("cmd").args(["/C", "start", "", cible]).spawn();
}

pub fn auditer(bavard: bool) -> Audit {
    if bavard {
        eprintln!("{GRAS}Audit de cette machine{RESET} ({})", os::NOM);
        eprintln!("{GRIS}Vérifications en cours (quelques secondes)…{RESET}");
    }
    os::auditer()
}

pub fn afficher(a: &Audit) {
    titre(&format!("Cette machine ({})", a.systeme));
    for c in &a.constats {
        let (icone, etiquette) = match c.probleme {
            None => (format!("{VERT}✔{RESET}"), String::new()),
            // Une simple information n'est pas un problème : pas de croix rouge.
            Some(Niveau::Info) => (format!("{}ℹ{RESET}", couleur(Niveau::Info)), String::new()),
            Some(n) => (format!("{}✖{RESET}", couleur(n)), format!(" {}[{}]{RESET}", couleur(n), n.libelle())),
        };
        println!("  {icone} {GRAS}{:<16}{RESET}{etiquette} {}", c.categorie, c.message);
        if let Some(k) = &c.correctif {
            let marque = if k.automatique { "🔧 correction possible" } else { "💡 à faire" };
            println!("  {:18}{GRIS}{marque} : {}{RESET}", "", k.action);
        }
    }
    println!();
    afficher_note("Note de la machine", a.score);
}

pub fn executer(json: bool) -> Audit {
    let a = auditer(!json);
    if json {
        println!("{}", serde_json::to_string_pretty(&a).unwrap_or_default());
    } else {
        afficher(&a);
    }
    a
}
