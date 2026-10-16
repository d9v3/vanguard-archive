//! Audit de sécurité de cette machine : types communs, affichage et exécution des correctifs.
//! Les vérifications elles-mêmes dépendent du système (linux.rs, windows.rs, macos.rs).

use std::process::Command;

use serde::Serialize;

use crate::risk::Niveau;
use crate::ui::*;

#[cfg(target_os = "linux")]
pub mod linux;
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

impl Audit {
    /// Nombre de vérifications qui n'ont pas pu se faire.
    pub fn impossibles(&self) -> usize {
        self.constats
            .iter()
            .filter(|c| c.message.starts_with("Impossible de vérifier"))
            .count()
    }

    /// Une note n'a de sens que si le pare-feu a été vérifié et qu'au plus un tiers des vérifications a échoué :
    /// sinon une machine peu vérifiée obtiendrait un « A » rassurant (vu en test sur Fedora en conteneur).
    pub fn fiable(&self) -> bool {
        let pare_feu_inconnu = self
            .constats
            .iter()
            .any(|c| c.categorie == "Pare-feu" && c.message.starts_with("Impossible de vérifier"));
        !pare_feu_inconnu && self.impossibles() * 3 < self.constats.len()
    }
}

fn ok(categorie: &'static str, message: impl Into<String>) -> Constat {
    Constat {
        categorie,
        probleme: None,
        message: message.into(),
        correctif: None,
    }
}

fn alerte(categorie: &'static str, niveau: Niveau, message: impl Into<String>) -> Constat {
    Constat {
        categorie,
        probleme: Some(niveau),
        message: message.into(),
        correctif: None,
    }
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
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
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
            alerte(
                "Clés SSH",
                Niveau::Eleve,
                "~/.ssh est lisible par d'autres utilisateurs.",
            )
            .corriger("Restreindre ~/.ssh à toi seul", &["chmod 700 ~/.ssh"]),
        );
    }
    for f in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
        let nom = f.file_name().to_string_lossy().into_owned();
        let privee = nom.starts_with("id_") && !nom.ends_with(".pub");
        if privee
            && f.metadata()
                .is_ok_and(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o077 != 0)
        {
            constats.push(
                alerte(
                    "Clés SSH",
                    Niveau::Critique,
                    format!("Clé privée ~/.ssh/{nom} lisible par d'autres."),
                )
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
        for c in commandes {
            println!("    {GRIS}PS> {c}{RESET}");
        }
        println!(
            "    {GRIS}Une fenêtre administrateur s'ouvre et montre chaque étape ; attends qu'elle se ferme.{RESET}"
        );
        windows::powershell_admin(commandes)
    }
    #[cfg(not(windows))]
    {
        for c in commandes {
            println!("    {GRIS}$ {c}{RESET}");
            if !Command::new("bash")
                .arg("-c")
                .arg(c)
                .status()
                .is_ok_and(|s| s.success())
            {
                return false;
            }
        }
        true
    }
}

/// Programme qui écoute sur chaque port TCP de cette machine (port → nom du programme).
/// Sans droits admin, les programmes de root/SYSTEM restent souvent anonymes.
pub fn programmes_en_ecoute() -> std::collections::HashMap<u16, String> {
    let mut map = std::collections::HashMap::new();
    #[cfg(target_os = "linux")]
    for l in sortie("ss", &["-Htlnp"]).unwrap_or_default().lines() {
        let c: Vec<&str> = l.split_whitespace().collect();
        let port = c
            .get(3)
            .and_then(|a| a.rsplit_once(':'))
            .and_then(|(_, p)| p.parse::<u16>().ok());
        let nom = c.get(5).and_then(|u| u.split('"').nth(1));
        if let (Some(port), Some(nom)) = (port, nom) {
            map.insert(port, nom.to_string());
        }
    }
    #[cfg(target_os = "macos")]
    for l in sortie("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"])
        .unwrap_or_default()
        .lines()
        .skip(1)
    {
        let c: Vec<&str> = l.split_whitespace().collect();
        let port = c
            .get(8)
            .and_then(|a| a.rsplit(':').next())
            .and_then(|p| p.parse::<u16>().ok());
        if let (Some(port), Some(nom)) = (port, c.first()) {
            map.insert(port, nom.to_string());
        }
    }
    #[cfg(windows)]
    for l in windows::ps("Get-NetTCPConnection -State Listen | ForEach-Object { \"$($_.LocalPort)|$((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName)\" }")
        .unwrap_or_default()
        .lines()
    {
        if let Some((p, nom)) = l.split_once('|')
            && let Ok(port) = p.trim().parse::<u16>()
            && !nom.trim().is_empty()
        {
            map.insert(port, nom.trim().to_string());
        }
    }
    map
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
            Some(n) => (
                format!("{}✖{RESET}", couleur(n)),
                format!(" {}[{}]{RESET}", couleur(n), n.libelle()),
            ),
        };
        println!("  {icone} {GRAS}{:<16}{RESET}{etiquette} {}", c.categorie, c.message);
        if let Some(k) = &c.correctif {
            let marque = if k.automatique {
                "🔧 correction possible"
            } else {
                "💡 à faire"
            };
            println!("  {:18}{GRIS}{marque} : {}{RESET}", "", k.action);
        }
    }
    println!();
    if a.fiable() {
        afficher_note("Note de la machine", a.score);
    } else {
        println!(
            "  Note de la machine : {}aucune{RESET} (pare-feu ou trop de vérifications impossibles à faire ici)",
            couleur(Niveau::Eleve)
        );
    }
    if a.impossibles() > 0 {
        println!(
            "  {}⚠ {} vérification(s) impossible(s) : résultat incomplet.{RESET}",
            couleur(Niveau::Moyen),
            a.impossibles()
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn audit(etats: &[(&'static str, Option<Niveau>, &str)]) -> Audit {
        let constats: Vec<Constat> = etats
            .iter()
            .map(|(c, n, m)| Constat {
                categorie: c,
                probleme: *n,
                message: m.to_string(),
                correctif: None,
            })
            .collect();
        Audit {
            systeme: "test",
            score: score(&constats),
            constats,
        }
    }

    #[test]
    fn pas_de_note_sans_pare_feu_verifie() {
        let inconnu = "Impossible de vérifier (systemd absent).";
        let sans_pare_feu = audit(&[
            ("Pare-feu", Some(Niveau::Info), inconnu),
            ("Mises à jour", None, "Système à jour."),
            ("Chiffrement", None, "Disque chiffré."),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        assert!(!sans_pare_feu.fiable());
        let peu_verifie = audit(&[
            ("Pare-feu", None, "ufw est actif."),
            ("SSH", Some(Niveau::Info), inconnu),
            ("Services", Some(Niveau::Info), inconnu),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        assert!(!peu_verifie.fiable());
        let complet = audit(&[
            ("Pare-feu", None, "ufw est actif."),
            ("SSH", None, "Serveur SSH désactivé."),
            ("Mises à jour", Some(Niveau::Info), inconnu),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        assert!(complet.fiable());
    }
}
