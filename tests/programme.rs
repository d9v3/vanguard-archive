//! Tests du programme lui-même, vu de l'extérieur : sentinel est lancé comme le ferait quelqu'un (arguments, réponses
//! envoyées par un tube), avec un dossier personnel jetable pour ne rien écrire dans le vrai (journal des erreurs,
//! base des appareils, historique). Les fonctions internes (lecture des sorties des outils, notes, fabricants…) se
//! testent dans leur propre module : un programme n'a pas de bibliothèque que ce dossier pourrait appeler.
//! Rien ici ne change le système : listes, menus quittés, refus aux questions, scan de 127.0.0.1 seulement.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct Sortie {
    code: Option<i32>,
    texte: String,
    erreurs: String,
}

/// Un dossier personnel neuf pour chaque lancement.
fn maison_jetable() -> PathBuf {
    static NUMERO: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "sentinel-essai-{}-{}",
        std::process::id(),
        NUMERO.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Wine (tests Windows faits depuis Linux) n'a pas de PowerShell : les lectures du système y échouent, et c'est dit.
fn sous_wine() -> bool {
    cfg!(windows) && Path::new(r"C:\windows\system32\wineboot.exe").is_file()
}

fn lire_en_fond(mut flux: impl Read + Send + 'static) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut octets = Vec::new();
        let _ = flux.read_to_end(&mut octets);
        String::from_utf8_lossy(&octets).into_owned()
    })
}

/// Lance sentinel en `langue` avec `entree` tapée d'avance, et l'attend au plus `secondes` (tué au-delà : un menu
/// qui ne rend pas la main est un défaut).
fn sentinel(langue: &str, args: &[&str], entree: &str, secondes: u64) -> Sortie {
    let maison = maison_jetable();
    let mut enfant = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(args)
        .env("SENTINEL_LANG", langue)
        // La vraie clé (cherchée dans /run/media/$USER, journal compris) et la vraie session (systemctl --user) restent
        // hors de portée : sinon le programme essayé écrirait sur la clé et toucherait la surveillance installée.
        .env("USER", "essai")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("XDG_RUNTIME_DIR", maison.join("run"))
        .env("HOME", &maison)
        .env("XDG_DATA_HOME", maison.join("donnees"))
        .env("XDG_CONFIG_HOME", maison.join("config"))
        .env("XDG_CACHE_HOME", maison.join("cache"))
        .env("LOCALAPPDATA", maison.join("local"))
        .env("APPDATA", maison.join("roaming"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sentinel ne démarre pas");
    // Les sorties sont lues pendant que le programme tourne : un tube plein le bloquerait.
    let texte = lire_en_fond(enfant.stdout.take().unwrap());
    let erreurs = lire_en_fond(enfant.stderr.take().unwrap());
    {
        let mut stdin = enfant.stdin.take().unwrap();
        let _ = stdin.write_all(entree.as_bytes());
    }
    let fin = Instant::now() + Duration::from_secs(secondes);
    let code = loop {
        if let Some(statut) = enfant.try_wait().unwrap() {
            break statut.code();
        }
        if Instant::now() > fin {
            let _ = enfant.kill();
            panic!("sentinel {args:?} n'a pas rendu la main en {secondes} s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let sortie = Sortie {
        code,
        texte: texte.join().unwrap_or_default(),
        erreurs: erreurs.join().unwrap_or_default(),
    };
    let _ = std::fs::remove_dir_all(&maison);
    sortie
}

/// Le texte sans les codes de couleur.
fn sans_couleurs(t: &str) -> String {
    let mut propre = String::with_capacity(t.len());
    let mut dans_code = false;
    for c in t.chars() {
        match (dans_code, c) {
            (false, '\x1b') => dans_code = true,
            (true, c) if c.is_ascii_alphabetic() => dans_code = false,
            (true, _) => {}
            (false, c) => propre.push(c),
        }
    }
    propre
}

#[test]
fn version() {
    let s = sentinel("fr", &["--version"], "", 30);
    assert_eq!(s.code, Some(0));
    assert_eq!(s.texte.trim(), format!("sentinel {}", env!("CARGO_PKG_VERSION")));
}

#[test]
fn aide_dans_les_deux_langues() {
    let fr = sentinel("fr", &["--help"], "", 30);
    assert_eq!(fr.code, Some(0));
    for commande in ["complet", "machine", "logiciels", "nettoyer", "reparer", "maj"] {
        assert!(fr.texte.contains(commande), "aide sans « {commande} »");
    }
    let en = sentinel("en", &["nettoyer", "--help"], "", 30);
    assert!(en.texte.contains("Clean up the system"), "{}", en.texte);
    assert!(en.texte.contains("--liste") && en.texte.contains("deleting nothing"));
}

#[test]
fn commande_inconnue_refusee() {
    let s = sentinel("fr", &["nimportequoi"], "", 30);
    assert_eq!(s.code, Some(2), "clap refuse une commande inconnue avec le code 2");
    assert!(s.erreurs.contains("nimportequoi"));
}

#[test]
fn menu_quitte_par_q_et_par_la_fin_de_l_entree() {
    let s = sentinel("fr", &[], "q\n", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(t.contains("BILAN DE SÉCURITÉ") && t.contains("Quitter"), "{t}");
    // Entrée fermée sans réponse (script, tâche planifiée) : le menu s'en va au lieu d'attendre.
    let ferme = sentinel("fr", &[], "", 60);
    assert_eq!(ferme.code, Some(0));
}

#[test]
fn sous_menu_optimiser() {
    // 8 : le groupe Optimiser ; Entrée : revenir ; q : quitter.
    let s = sentinel("fr", &[], "8\n\nq\n", 60);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Nettoyer le système") && t.contains("Réglages recommandés"),
        "{t}"
    );
    assert_eq!(s.code, Some(0));
}

#[test]
fn logiciels_listes_sans_rien_installer() {
    let s = sentinel("fr", &["logiciels", "--liste"], "", 120);
    let t = sans_couleurs(&s.texte);
    if sous_wine() {
        assert!(t.contains("PowerShell ne répond pas"), "{t}");
        return;
    }
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(
        t.contains("Navigateurs et courriel") && t.contains("logiciels proposés ici"),
        "{t}"
    );
    // Le menu, quitté tout de suite.
    let menu = sentinel("fr", &["logiciels"], "\n", 120);
    assert!(sans_couleurs(&menu.texte).contains("Pack de départ"));
}

#[test]
fn nettoyer_mesure_puis_refus() {
    let liste = sentinel("fr", &["nettoyer", "--liste"], "", 120);
    assert_eq!(liste.code, Some(0), "{}", liste.erreurs);
    assert!(sans_couleurs(&liste.texte).contains("Rien n'a été effacé"));
    // Entrée garde les cases cochées d'office ; « n » à la question : rien n'est fait.
    let refus = sentinel("fr", &["nettoyer"], "\nn\n", 120);
    let t = sans_couleurs(&refus.texte);
    assert!(t.contains("Annulé") || t.contains("Rien à nettoyer"), "{t}");
}

#[test]
fn audit_en_json() {
    let s = sentinel("fr", &["machine", "--json"], "", 300);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let audit: serde_json::Value = serde_json::from_str(&s.texte).expect("machine --json : JSON illisible");
    let score = audit["score"].as_u64().expect("pas de note");
    assert!(score <= 100);
    let constats = audit["constats"].as_array().expect("pas de constats");
    assert!(constats.len() >= 5, "{} constats seulement", constats.len());
    for c in constats {
        assert!(c["categorie"].is_string() && c["message"].is_string() && c["verifie"].is_boolean());
    }
}

#[test]
fn scan_de_cette_machine_en_json() {
    // Sous Wine, ce scan ne finit pas (sa pile réseau n'imite pas celle de Windows) ; le vrai Windows de la CI le fait.
    if sous_wine() {
        return;
    }
    // 127.0.0.1 seulement : aucun paquet ne part sur le réseau.
    let s = sentinel("fr", &["reseau", "127.0.0.1", "--json"], "", 300);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let scan: serde_json::Value = serde_json::from_str(&s.texte).expect("reseau --json : JSON illisible");
    let hotes = scan["hotes"].as_array().expect("pas d'appareils");
    assert!(hotes.iter().all(|h| h["ip"] == "127.0.0.1"), "{hotes:?}");
}
