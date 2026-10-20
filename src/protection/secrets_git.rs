//! Secrets dans les projets git : gitleaks (libre, licence MIT), lancé s'il est installé, relit l'historique des dépôts
//! git du dossier personnel à la recherche de mots de passe, clés d'API et jetons écrits un jour. Un secret effacé
//! d'un fichier reste dans l'historique, lisible par quiconque a une copie du dépôt (GitHub, une sauvegarde, une
//! clé USB). Lecture seule. gitleaks masque lui-même les secrets (--redact) ; son rapport, qui nomme aussi les auteurs
//! des commits, est lu puis effacé : seuls le fichier, la ligne, le genre de secret et le commit sont montrés.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::protection::outil::{self, Externe, Linux};
use crate::ui::*;

const GITLEAKS: Externe = Externe {
    nom: "gitleaks",
    presentation: (
        "gitleaks (libre, licence MIT) cherche les secrets dans l'historique git ; il n'est pas installé.",
        "gitleaks (open source, MIT license) looks for secrets in git history; it is not installed.",
    ),
    linux: Linux::Partout,
    brew: "gitleaks",
    winget: "Gitleaks.Gitleaks",
    site: "https://github.com/gitleaks/gitleaks",
};

/// Dossiers où un dépôt n'est pas cherché : copies de dépendances, environnements et caches, souvent énormes.
const SAUTES: &[&str] = &[
    "node_modules",
    "target",
    "vendor",
    "venv",
    "__pycache__",
    "Library",
    "AppData",
];

/// Jusqu'où descendre sous le dossier personnel (~/a/b/c/d), et combien de dépôts au plus : de quoi trouver les
/// projets sans parcourir tout le disque.
const PROFONDEUR: usize = 4;
const DEPOTS_MAX: usize = 200;

/// Les dépôts git sous `racine`. Les dossiers cachés (réglages, caches) et les liens sont sautés ; un dépôt n'est pas
/// fouillé plus loin, ses sous-modules étant d'autres dépôts. La racine elle-même peut être un dépôt (fichiers de
/// configuration suivis par git) sans cacher ceux qui sont dessous.
pub(crate) fn depots(racine: &Path) -> Vec<PathBuf> {
    let mut trouves = Vec::new();
    let mut a_voir = vec![(racine.to_path_buf(), 0)];
    while let Some((dossier, profondeur)) = a_voir.pop() {
        if trouves.len() >= DEPOTS_MAX {
            break;
        }
        // « .git » est un dossier, ou un fichier pour un arbre de travail lié (git worktree).
        if dossier.join(".git").exists() {
            trouves.push(dossier.clone());
            if profondeur > 0 {
                continue;
            }
        }
        if profondeur >= PROFONDEUR {
            continue;
        }
        let Ok(entrees) = std::fs::read_dir(&dossier) else {
            continue;
        };
        for e in entrees.flatten() {
            let nom = e.file_name().to_string_lossy().into_owned();
            if nom.starts_with('.') || SAUTES.contains(&nom.as_str()) {
                continue;
            }
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                a_voir.push((e.path(), profondeur + 1));
            }
        }
    }
    trouves.sort();
    trouves
}

/// Les arguments de gitleaks pour un dépôt : la commande « git » depuis la 8.19, « detect --source » avant (Debian 12
/// et Ubuntu 24.04 ont la 8.16), reconnue dans son aide. Le rapport en JSON, les secrets masqués, le code de retour à 0
/// même quand il trouve : seul un vrai échec (pas un dépôt, git absent) laisse le rapport vide.
pub(crate) fn arguments(aide: &str, depot: &Path, rapport: &Path) -> Vec<OsString> {
    let recent = aide.lines().any(|l| l.trim_start().starts_with("git "));
    let mut a: Vec<OsString> = if recent {
        vec!["git".into()]
    } else {
        vec!["detect".into(), "--source".into(), depot.into()]
    };
    a.extend(
        [
            "--no-banner",
            "--redact",
            "--report-format",
            "json",
            "--log-level",
            "error",
            "--exit-code",
            "0",
            "--report-path",
        ]
        .map(OsString::from),
    );
    a.push(rapport.into());
    if recent {
        a.push(depot.into());
    }
    a
}

/// Un secret trouvé : son genre (règle de gitleaks), le fichier et la ligne, le commit abrégé.
#[derive(Debug, PartialEq)]
pub(crate) struct Fuite {
    pub regle: String,
    pub fichier: String,
    pub ligne: u64,
    pub commit: String,
}

/// Le rapport de gitleaks ; `None` s'il ne se lit pas. Ni le secret, ni l'auteur, ni son adresse ne sont gardés.
pub(crate) fn lire_rapport(json: &str) -> Option<Vec<Fuite>> {
    let valeur: serde_json::Value = serde_json::from_str(json).ok()?;
    Some(
        valeur
            .as_array()?
            .iter()
            .map(|f| Fuite {
                regle: affichable(f["RuleID"].as_str().unwrap_or("?")),
                fichier: affichable(f["File"].as_str().unwrap_or("?")),
                ligne: f["StartLine"].as_u64().unwrap_or(0),
                commit: f["Commit"].as_str().unwrap_or("").chars().take(7).collect(),
            })
            .collect(),
    )
}

/// Ce qu'il advient d'un dépôt.
enum Issue {
    Sain,
    Fuites(Vec<Fuite>),
    Illisible,
}

fn examiner(gitleaks: &Path, aide: &str, depot: &Path, rapport: &Path) -> Issue {
    let lance = crate::commande::lancer(Command::new(gitleaks).args(arguments(aide, depot, rapport)), 300);
    let lu = std::fs::read_to_string(rapport).ok().and_then(|t| lire_rapport(&t));
    let _ = std::fs::remove_file(rapport);
    match (lance, lu) {
        (Some(_), Some(f)) if f.is_empty() => Issue::Sain,
        (Some(_), Some(f)) => Issue::Fuites(f),
        _ => Issue::Illisible,
    }
}

/// Menu Antivirus et protection › Secrets dans les projets git, et « vanguard secrets ».
pub fn analyser() {
    use std::io::Write;
    titre(tr!("Secrets dans les projets git", "Secrets in git projects"));
    let Some(gitleaks) = outil::trouver("gitleaks").or_else(|| outil::proposer(&GITLEAKS)) else {
        return;
    };
    let maison = PathBuf::from(
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .unwrap_or_default(),
    );
    let depots = depots(&maison);
    if depots.is_empty() {
        trp!(
            "  Aucun projet git dans ton dossier personnel.",
            "  No git project in your home folder."
        );
        return;
    }
    println!(
        "  {}",
        trf!(
            "{} projet(s) git : l'historique de chacun est relu, rien n'est modifié.",
            "{} git project(s): each one's history is read, nothing is changed.",
            depots.len()
        )
    );
    let aide = crate::commande::lancer(Command::new(&gitleaks).arg("--help"), 10)
        .map(|r| r.sortie + &r.erreurs)
        .unwrap_or_default();
    // Les rapports, dans un dossier réservé au compte : ils nomment les auteurs des commits.
    let Ok(dossier) = crate::protection::isoler::dossier_jetable() else {
        trp!(
            "  ✖ Dossier temporaire impossible à créer.",
            "  ✖ Could not create a temporary folder."
        );
        return;
    };
    let mut sains = 0;
    let mut illisibles = Vec::new();
    let mut avec = Vec::new();
    // Le compteur seulement dans un terminal : lu par un script (test de la VM), il ne ferait que du bruit.
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stdout());
    for (i, depot) in depots.iter().enumerate() {
        if terminal {
            print!("\r  {}/{}", i + 1, depots.len());
            let _ = std::io::stdout().flush();
        }
        match examiner(&gitleaks, &aide, depot, &dossier.join(format!("{i}.json"))) {
            Issue::Sain => sains += 1,
            Issue::Fuites(f) => avec.push((depot, f)),
            Issue::Illisible => illisibles.push(depot),
        }
    }
    let _ = std::fs::remove_dir_all(&dossier);
    if terminal {
        print!("\r{}\r", " ".repeat(20));
    }
    for depot in &illisibles {
        println!(
            "  ⚠ {}",
            trf!(
                "{} : pas pu être relu, rien n'est conclu pour lui.",
                "{}: could not be read, nothing is concluded for it.",
                outil::chemin_affiche(depot, &maison)
            )
        );
    }
    if avec.is_empty() {
        if illisibles.is_empty() {
            println!(
                "  {VERT}✔{RESET} {}",
                trf!(
                    "Aucun secret dans l'historique de tes {sains} projet(s).",
                    "No secret in the history of your {sains} project(s)."
                )
            );
        }
        return;
    }
    let rouge = couleur(crate::risk::Niveau::Eleve);
    for (depot, fuites) in &avec {
        println!(
            "  {rouge}✖{RESET} {}",
            trf!(
                "{} : {} secret(s)",
                "{}: {} secret(s)",
                outil::chemin_affiche(depot, &maison),
                fuites.len()
            )
        );
        for f in fuites.iter().take(10) {
            println!(
                "      {GRIS}{}:{} — {} ({}){RESET}",
                f.fichier, f.ligne, f.regle, f.commit
            );
        }
        if fuites.len() > 10 {
            println!(
                "      {GRIS}{}{RESET}",
                trf!("… et {} autre(s)", "… and {} more", fuites.len() - 10)
            );
        }
    }
    println!();
    for ligne in envelopper(
        tr!(
            "Un secret écrit un jour reste dans l'historique, même effacé ensuite, et quiconque a une copie du dépôt peut le lire. D'abord le changer là où il sert (révoquer la clé, changer le mot de passe) ; puis, avant de publier, le retirer de l'historique (git filter-repo). Une règle peut se tromper : un exemple de documentation n'est pas un vrai secret. Les secrets ne sont ni affichés ni gardés par Vanguard.",
            "A secret written once stays in the history, even when deleted later, and anyone with a copy of the repository can read it. First change it where it is used (revoke the key, change the password); then, before publishing, remove it from the history (git filter-repo). A rule can be wrong: a documentation example is not a real secret. Secrets are neither shown nor kept by Vanguard."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un rapport de gitleaks 8.16 tel qu'il l'écrit (secret masqué), sur un dépôt d'essai : valeurs inventées.
    const RAPPORT: &str = r#"[
 {
  "Description": "AWS",
  "StartLine": 1,
  "EndLine": 1,
  "Match": "REDACTED",
  "Secret": "REDACTED",
  "File": "config.env",
  "Commit": "70d57ee42c8a91d4b534c5879690a43bb8f89fe4",
  "Author": "alice",
  "Email": "alice@exemple.invalid",
  "RuleID": "aws-access-token"
 }
]"#;

    #[test]
    fn rapport_lu_sans_secret_ni_auteur() {
        let f = lire_rapport(RAPPORT).unwrap();
        assert_eq!(
            f,
            [Fuite {
                regle: "aws-access-token".into(),
                fichier: "config.env".into(),
                ligne: 1,
                commit: "70d57ee".into(),
            }]
        );
        assert_eq!(lire_rapport("[]").unwrap(), []);
        assert!(lire_rapport("").is_none() && lire_rapport("{\"a\":1}").is_none());
        // Un nom de fichier piégé ne pilote pas le terminal.
        let piege = RAPPORT.replace("config.env", "\\u001b[2Jx");
        assert!(!lire_rapport(&piege).unwrap()[0].fichier.contains('\x1b'));
    }

    #[test]
    fn commande_selon_la_version() {
        let depot = Path::new("/home/alice/projet");
        let rapport = Path::new("/tmp/r.json");
        let ancienne =
            "Available Commands:\n  completion  ...\n  detect      detect secrets in code\n  protect     ...\n";
        let a = arguments(ancienne, depot, rapport);
        assert_eq!(a[..3], ["detect", "--source", "/home/alice/projet"].map(OsString::from));
        assert!(a.contains(&"--redact".into()) && a.last() == Some(&OsString::from("/tmp/r.json")));
        let recente = "Available Commands:\n  dir         scan directories or files for secrets\n  git         scan git repositories for secrets\n";
        let a = arguments(recente, depot, rapport);
        assert_eq!(a[0], "git");
        assert_eq!(a.last(), Some(&OsString::from("/home/alice/projet")));
    }

    #[test]
    fn depots_du_dossier_personnel() {
        let maison = crate::protection::isoler::dossier_jetable().unwrap();
        for d in [
            "projets/site/.git",
            "projets/site/sous-module/.git",
            "projets/node_modules/paquet/.git",
            ".cache/outil/.git",
            "a/b/c/d/e/trop-profond/.git",
            "documents/notes/.git",
        ] {
            std::fs::create_dir_all(maison.join(d)).unwrap();
        }
        // Un arbre de travail lié : « .git » est un fichier.
        std::fs::create_dir_all(maison.join("projets/lie")).unwrap();
        std::fs::write(maison.join("projets/lie/.git"), "gitdir: ailleurs").unwrap();
        let trouves: Vec<String> = depots(&maison)
            .iter()
            .map(|d| d.strip_prefix(&maison).unwrap().to_string_lossy().replace('\\', "/"))
            .collect();
        assert_eq!(trouves, ["documents/notes", "projets/lie", "projets/site"]);
        // Le dossier personnel suivi par git (fichiers de configuration) ne cache pas les projets.
        std::fs::create_dir_all(maison.join(".git")).unwrap();
        assert_eq!(depots(&maison).len(), 4);
        let _ = std::fs::remove_dir_all(&maison);
    }
}
