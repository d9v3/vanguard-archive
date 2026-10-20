//! Tests du programme lui-même, vu de l'extérieur : Vanguard est lancé comme le ferait quelqu'un (arguments, réponses
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
        "vanguard-essai-{}-{}",
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

/// Lance Vanguard en `langue` avec `entree` tapée d'avance, et l'attend au plus `secondes` (tué au-delà : un menu
/// qui ne rend pas la main est un défaut).
fn vanguard(langue: &str, args: &[&str], entree: &str, secondes: u64) -> Sortie {
    let maison = maison_jetable();
    let sortie = vanguard_dans(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        langue,
        args,
        entree,
        secondes,
    );
    let _ = std::fs::remove_dir_all(&maison);
    sortie
}

/// Comme `vanguard`, avec un programme et un dossier personnel donnés (gardé après le lancement).
fn vanguard_dans(programme: &Path, maison: &Path, langue: &str, args: &[&str], entree: &str, secondes: u64) -> Sortie {
    let mut commande = Command::new(programme);
    commande
        .args(args)
        .env("VANGUARD_LANG", langue)
        // La vraie clé (cherchée dans /run/media/$USER, journal compris) et la vraie session (systemctl --user) restent
        // hors de portée : sinon le programme écrirait sur la clé, et la surveillance installée sous un ancien nom
        // serait reprise au nom de ce programme d'essai.
        .env("USER", "essai")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("XDG_RUNTIME_DIR", maison.join("run"))
        .env("HOME", maison)
        .env("XDG_DATA_HOME", maison.join("donnees"))
        .env("XDG_CONFIG_HOME", maison.join("config"))
        .env("XDG_CACHE_HOME", maison.join("cache"))
        .env("LOCALAPPDATA", maison.join("local"))
        .env("APPDATA", maison.join("roaming"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Un programme copié à l'instant (mise_a_jour_depuis_la_cle) peut être refusé « Text file busy » : un autre test
    // qui lance un processus au même moment a hérité, le temps de son exec, du fichier encore ouvert en écriture.
    // Quelques essais espacés suffisent ; toute autre erreur arrête le test.
    let mut essais = 0;
    let mut enfant = loop {
        match commande.spawn() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && essais < 20 => {
                essais += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            r => break r.expect("vanguard ne démarre pas"),
        }
    };
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
            panic!("vanguard {args:?} n'a pas rendu la main en {secondes} s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Sortie {
        code,
        texte: texte.join().unwrap_or_default(),
        erreurs: erreurs.join().unwrap_or_default(),
    }
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
    let s = vanguard("fr", &["--version"], "", 30);
    assert_eq!(s.code, Some(0));
    assert_eq!(s.texte.trim(), format!("vanguard {}", env!("CARGO_PKG_VERSION")));
}

#[test]
fn aide_dans_les_deux_langues() {
    let fr = vanguard("fr", &["--help"], "", 30);
    assert_eq!(fr.code, Some(0));
    for commande in ["complet", "machine", "logiciels", "nettoyer", "reparer", "maj"] {
        assert!(fr.texte.contains(commande), "aide sans « {commande} »");
    }
    let en = vanguard("en", &["nettoyer", "--help"], "", 30);
    assert!(en.texte.contains("Clean up the system"), "{}", en.texte);
    assert!(en.texte.contains("--liste") && en.texte.contains("deleting nothing"));
}

// Blocages de Windows Defender : en anglais dans l'aide ; ailleurs que sous Windows, rien à proposer et rien changé.
#[test]
fn durcir_hors_de_windows() {
    let aide = vanguard("en", &["harden", "--help"], "", 30);
    assert!(aide.texte.contains("Windows Defender blocking"), "{}", aide.texte);
    if !cfg!(windows) {
        let r = vanguard("en", &["harden"], "", 30);
        assert_eq!(r.code, Some(0));
        assert!(r.texte.contains("Nothing in this category"), "{}", r.texte);
    }
}

#[test]
fn commande_inconnue_refusee() {
    let s = vanguard("fr", &["nimportequoi"], "", 30);
    assert_eq!(s.code, Some(2), "clap refuse une commande inconnue avec le code 2");
    assert!(s.erreurs.contains("nimportequoi"));
}

#[test]
fn menu_quitte_par_q_et_par_la_fin_de_l_entree() {
    let s = vanguard("fr", &[], "q\n", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(t.contains("BILAN DE SÉCURITÉ") && t.contains("Quitter"), "{t}");
    // Entrée fermée sans réponse (script, tâche planifiée) : le menu s'en va au lieu d'attendre.
    let ferme = vanguard("fr", &[], "", 60);
    assert_eq!(ferme.code, Some(0));
}

#[test]
fn sous_menu_optimiser() {
    // 8 : le groupe Optimiser ; Entrée : revenir ; q : quitter.
    let s = vanguard("fr", &[], "8\n\nq\n", 60);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Nettoyer le système") && t.contains("Réglages recommandés"),
        "{t}"
    );
    assert_eq!(s.code, Some(0));
}

#[test]
fn logiciels_listes_sans_rien_installer() {
    let s = vanguard("fr", &["logiciels", "--liste"], "", 120);
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
    let menu = vanguard("fr", &["logiciels"], "\n", 120);
    assert!(sans_couleurs(&menu.texte).contains("Pack de départ"));
}

#[test]
fn nettoyer_mesure_puis_refus() {
    let liste = vanguard("fr", &["nettoyer", "--liste"], "", 120);
    assert_eq!(liste.code, Some(0), "{}", liste.erreurs);
    assert!(sans_couleurs(&liste.texte).contains("Rien n'a été effacé"));
    // Entrée garde les cases cochées d'office ; « n » à la question : rien n'est fait.
    let refus = vanguard("fr", &["nettoyer"], "\nn\n", 120);
    let t = sans_couleurs(&refus.texte);
    assert!(t.contains("Annulé") || t.contains("Rien à nettoyer"), "{t}");
}

#[test]
fn audit_en_json() {
    let s = vanguard("fr", &["machine", "--json"], "", 300);
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
    let s = vanguard("fr", &["reseau", "127.0.0.1", "--json"], "", 300);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let scan: serde_json::Value = serde_json::from_str(&s.texte).expect("reseau --json : JSON illisible");
    let hotes = scan["hotes"].as_array().expect("pas d'appareils");
    assert!(hotes.iter().all(|h| h["ip"] == "127.0.0.1"), "{hotes:?}");
}

#[test]
fn sauvegarde_puis_restauration() {
    // Hors du dossier personnel jetable : le fichier doit passer d'un lancement à l'autre.
    let fichier = std::env::temp_dir().join(format!("vanguard-sauvegarde-essai-{}.json", std::process::id()));
    let chemin = fichier.to_str().unwrap();
    let s = vanguard("fr", &["sauvegarder", chemin], "", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(sans_couleurs(&s.texte).contains("Sauvegarde écrite"), "{}", s.texte);
    let texte = std::fs::read_to_string(&fichier).unwrap();
    assert!(texte.contains("\"format\": \"vanguard-sauvegarde\""), "{texte}");
    let r = vanguard("fr", &["restaurer", chemin], "", 60);
    assert_eq!(r.code, Some(0), "{}", r.erreurs);
    assert!(
        sans_couleurs(&r.texte).contains("Ajouté à la base actuelle"),
        "{}",
        r.texte
    );
    // Un fichier qui n'est pas une sauvegarde : rien n'est restauré.
    std::fs::write(&fichier, "{\"autre\":1}").unwrap();
    let refus = vanguard("fr", &["restaurer", chemin], "", 60);
    assert!(
        sans_couleurs(&refus.texte).contains("Rien de restauré"),
        "{}",
        refus.texte
    );
    let _ = std::fs::remove_file(&fichier);
}

#[test]
fn lenteur_fiche_depanner_et_copie_sans_rien_changer() {
    // Fiche en JSON : lisible, et sans les numéros de série (ils ne s'affichent qu'à l'écran).
    let sortie_fiche = vanguard("fr", &["fiche", "--json"], "", 120);
    assert_eq!(sortie_fiche.code, Some(0), "{}", sortie_fiche.erreurs);
    let fiche: serde_json::Value = serde_json::from_str(&sortie_fiche.texte).expect("fiche --json : JSON illisible");
    assert!(
        fiche.get("processeur").is_some() && fiche.get("series").is_none(),
        "{fiche}"
    );
    // Pourquoi c'est lent : la mesure et ses sections, en lecture seule.
    let lenteur = vanguard("fr", &["lenteur"], "", 120);
    assert_eq!(lenteur.code, Some(0), "{}", lenteur.erreurs);
    let texte = sans_couleurs(&lenteur.texte);
    assert!(texte.contains("EN CE MOMENT") && texte.contains("DÉMARRAGE"), "{texte}");
    // Un sujet de dépannage inconnu : la liste des sujets, dans la langue de l'interface.
    let depanner = vanguard("en", &["troubleshoot", "nimportequoi"], "", 30);
    assert_eq!(depanner.code, Some(0), "{}", depanner.erreurs);
    let texte = sans_couleurs(&depanner.texte);
    assert!(texte.contains("printer") && texte.contains("Disk full"), "{texte}");
    assert!(
        texte.contains("leaving") && texte.contains("After an infection"),
        "{texte}"
    );
    // Ordinateur qui part, quitté à la première question : rien n'est effacé ni lancé.
    let depart = vanguard("en", &["troubleshoot", "leaving"], "", 30);
    assert_eq!(depart.code, Some(0), "{}", depart.erreurs);
    assert!(
        sans_couleurs(&depart.texte).contains("Computer leaving"),
        "{}",
        depart.texte
    );
    // Copier vers un dossier qui n'existe pas : rien n'est copié.
    let copie = vanguard("fr", &["copier-fichiers", "/chemin/qui/n-existe/pas"], "", 30);
    assert_eq!(copie.code, Some(0), "{}", copie.erreurs);
    let texte = sans_couleurs(&copie.texte);
    assert!(
        texte.contains("Aucun dossier personnel") || texte.contains("n-existe"),
        "{texte}"
    );
}

#[test]
fn gaming_quitte_sans_rien_installer() {
    let s = vanguard("fr", &["gaming"], "\n", 120);
    let t = sans_couleurs(&s.texte);
    if sous_wine() {
        assert!(t.contains("PowerShell ne répond pas"), "{t}");
        return;
    }
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(t.contains("Gaming") && !t.contains("Terminé"), "{t}");
}

#[test]
fn entretien_du_mois_sans_rien_installer() {
    let coupe = vanguard("fr", &["entretien", "off"], "", 60);
    assert_eq!(coupe.code, Some(0), "{}", coupe.erreurs);
    assert!(
        sans_couleurs(&coupe.texte).contains("Entretien du mois coupé"),
        "{}",
        coupe.texte
    );
    // Sans argument : ce qu'il dirait maintenant, dans le terminal ; rien n'est gardé ni planifié.
    let s = vanguard("fr", &["entretien"], "", 300);
    let t = sans_couleurs(&s.texte);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(
        t.contains("Note de cette machine") && t.contains("Entretien coupé"),
        "{t}"
    );
}

#[test]
fn sous_menu_protection() {
    // 6 : Antivirus et protection ; Entrée : revenir ; q : quitter.
    let s = vanguard("fr", &[], "6\n\nq\n", 60);
    let t = sans_couleurs(&s.texte);
    for outil in [
        "Qui parle à Internet ?",
        "Ce lien est-il dangereux ?",
        "Vérifier un fichier téléchargé",
    ] {
        assert!(t.contains(outil), "{outil} absent : {t}");
    }
    // Chaque ligne du sous-menu tient dans 76 colonnes (sans terminal, l'écran suivant suit la question « Choix » sur
    // la même ligne : celles-là ne comptent pas).
    let longues: Vec<&str> = t
        .lines()
        .filter(|l| !l.contains("Choix :") && l.chars().count() > 76)
        .collect();
    assert_eq!(longues, Vec::<&str>::new(), "lignes trop longues");
    assert_eq!(s.code, Some(0));
}

#[test]
fn lien_examine_sans_rien_envoyer() {
    // Refus de la vérification en ligne : rien ne sort de l'ordinateur, le verdict vient du lien lui-même. Des noms
    // réservés aux exemples (.example) : outils/liens.py ne cherche pas à les ouvrir.
    let s = vanguard(
        "fr",
        &["lien", "https://paypal.com.compte-secure.example/login"],
        "n\n",
        60,
    );
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Sous-domaine trompeur") && t.contains("compte-secure.example"),
        "{t}"
    );
    assert!(t.contains("Rien n'a été envoyé") && t.contains("Dangereux"), "{t}");
    let en = vanguard("en", &["link", "https://paypa1.example/"], "n\n", 60);
    let t = sans_couleurs(&en.texte);
    assert!(t.contains("Looks like PayPal") && t.contains("Nothing was sent"), "{t}");
    let aide = vanguard("en", &["lien", "--help"], "", 30);
    assert!(aide.texte.contains("The link you received"), "{}", aide.texte);
}

#[test]
fn verifier_fichier_absent_ou_dossier() {
    let s = vanguard("fr", &["verifier-fichier", "/nexiste/pas/outil.zip"], "", 30);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(sans_couleurs(&s.texte).contains("Introuvable"), "{}", s.texte);
    let dossier = std::env::temp_dir();
    let d = vanguard("fr", &["verifier-fichier", dossier.to_str().unwrap()], "", 30);
    assert!(
        sans_couleurs(&d.texte).contains("Ce n'est pas un fichier"),
        "{}",
        d.texte
    );
    let aide = vanguard("en", &["check-file", "--help"], "", 30);
    assert!(
        aide.texte.contains("The checksum published by the site"),
        "{}",
        aide.texte
    );
}

#[test]
fn sortantes_en_lecture_seule() {
    let s = vanguard("fr", &["sortantes"], "", 90);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Qui parle à Internet ?") && t.contains("Rien n'est coupé ni bloqué"),
        "{t}"
    );
    // Sous Wine, pas de PowerShell : c'est dit, rien n'est inventé.
    assert!(
        t.contains("vers Internet") || t.contains("Impossible de lire les connexions"),
        "{t}"
    );
}

/// Quelqu'un contrôle mon ordi ? : l'arnaque est expliquée, la recherche se fait, et « n » ne retire rien.
#[test]
fn distance_sans_rien_retirer() {
    let s = vanguard("fr", &["distance"], "n\nn\n", 120);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Quelqu'un contrôle mon ordi ?") && t.contains("faux technicien"),
        "{t}"
    );
    // Rien trouvé, quelque chose trouvé mais gardé, ou PowerShell absent (Wine) : jamais un retrait.
    assert!(
        t.contains("Aucun logiciel de prise de contrôle")
            || t.contains("Rien n'a été retiré")
            || t.contains("Impossible de vérifier"),
        "{t}"
    );
    assert!(!t.contains("retiré."), "{t}");
}

/// Vérifier Vanguard lui-même : version, date et empreinte, sans rien changer.
#[test]
fn verifier_moi_en_lecture_seule() {
    let s = vanguard("fr", &["verifier-moi"], "", 120);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Vérifier Vanguard lui-même") && t.contains(env!("CARGO_PKG_VERSION")),
        "{t}"
    );
    // Sous Wine, pas de PowerShell : l'empreinte est dite impossible, jamais inventée.
    assert!(t.contains("SHA-256") || t.contains("Empreinte impossible"), "{t}");
    assert!(t.contains("Compilé le"), "{t}");
}

/// Programmes au démarrage : la liste se montre, et Entrée sans rien décocher ne change rien.
#[test]
fn demarrage_sans_rien_changer() {
    let s = vanguard("fr", &["demarrage"], "\n", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(!t.contains("À appliquer") && !t.contains("À annuler"), "{t}");
    assert!(t.contains("Rien à changer") || t.contains("Aucun programme"), "{t}");
    let aide = vanguard("en", &["startup", "--help"], "", 30);
    assert!(
        sans_couleurs(&aide.texte).contains("Startup programs"),
        "{}",
        aide.texte
    );
}

/// Lancés sans Internet : outils/verifier.sh refait toute la suite dans un espace réseau vide (unshare -rn, la boucle
/// locale seule) et pose VANGUARD_HORS_LIGNE. Ailleurs, ce test ne fait rien : Internet y répondrait.
fn hors_ligne() -> bool {
    std::env::var_os("VANGUARD_HORS_LIGNE").is_some()
}

/// Sans Internet, chaque outil qui en dépend s'arrête de lui-même, vite, sans planter, et dit pourquoi : jamais une
/// attente sans fin, jamais un « tout va bien » qu'il n'a pas pu vérifier.
#[test]
fn sans_internet_chaque_outil_le_dit() {
    if !hors_ligne() || cfg!(not(target_os = "linux")) {
        return;
    }
    let cas: [(&[&str], &str, &str); 6] = [
        (&["listes-noires"], "o\n", "Adresse publique introuvable"),
        (&["nat"], "", "Aucun serveur n'a répondu"),
        (&["dns-rapide"], "", "ne répond pas"),
        (&["sortantes"], "", "Aucune connexion vers Internet"),
        (&["connexion"], "", "Internet ne répond pas : test arrêté"),
        (
            &["lien", "https://exemple.com/a"],
            "n\n",
            "listes et âge du domaine non vérifiés",
        ),
    ];
    for (args, entree, attendu) in cas {
        let debut = Instant::now();
        let s = vanguard("fr", args, entree, 90);
        let texte = sans_couleurs(&s.texte);
        assert_eq!(s.code, Some(0), "{args:?} : {}", s.erreurs);
        assert!(!s.erreurs.contains("panicked"), "{args:?} : {}", s.erreurs);
        assert!(texte.contains(attendu), "{args:?} : « {attendu} » absent de\n{texte}");
        assert!(
            debut.elapsed() < Duration::from_secs(60),
            "{args:?} : {:?}",
            debut.elapsed()
        );
    }
    // Le scan sans réseau local : une erreur claire, pas une attente.
    let s = vanguard("fr", &["reseau"], "", 60);
    assert_eq!(s.code, Some(1), "{}", s.texte);
    assert!(
        sans_couleurs(&s.erreurs).contains("impossible de détecter le réseau local"),
        "{}",
        s.erreurs
    );
}

/// Les outils de la 0.61 et de la 0.62, en lecture seule ou refusés : ils s'ouvrent, disent ce qu'ils voient et ne
/// changent rien. (Le rapport à laisser n'est pas lancé ici : il ouvre le navigateur.)
#[test]
fn outils_recents_sans_rien_changer() {
    let camera = vanguard("fr", &["camera-micro"], "", 60);
    assert_eq!(camera.code, Some(0), "{}", camera.erreurs);
    assert!(
        sans_couleurs(&camera.texte).contains("Caméra et micro : qui s'en sert ?"),
        "{}",
        camera.texte
    );
    let changements = vanguard("fr", &["changements"], "", 30);
    assert_eq!(changements.code, Some(0), "{}", changements.erreurs);
    assert!(
        sans_couleurs(&changements.texte).contains("aucune correction n'a été lancée"),
        "{}",
        changements.texte
    );
    let quarantaine = vanguard("fr", &["quarantaine"], "", 30);
    assert_eq!(quarantaine.code, Some(0), "{}", quarantaine.erreurs);
    assert!(
        sans_couleurs(&quarantaine.texte).contains("La quarantaine est vide."),
        "{}",
        quarantaine.texte
    );
    let copie = vanguard("fr", &["verifier-copie", "/chemin/qui/n-existe/pas"], "", 30);
    assert_eq!(copie.code, Some(0), "{}", copie.erreurs);
    assert!(
        sans_couleurs(&copie.texte).contains("Aucune copie de Vanguard ici"),
        "{}",
        copie.texte
    );
    // Parcours « Mon compte a été piraté », quitté à la première question.
    let compte = vanguard("en", &["troubleshoot", "account"], "", 30);
    assert_eq!(compte.code, Some(0), "{}", compte.erreurs);
    assert!(
        sans_couleurs(&compte.texte).contains("My account was hacked"),
        "{}",
        compte.texte
    );
    let aide = vanguard("en", &["--help"], "", 30);
    for commande in [
        "camera-micro",
        "quarantaine",
        "verifier-copie",
        "verifier-cle",
        "sauvegarde-auto",
        "raccourci",
        "a-laisser",
    ] {
        assert!(aide.texte.contains(commande), "aide sans « {commande} »");
    }
}

/// Raccourci sur cet ordinateur, dans un dossier personnel jetable : refusé, rien n'est posé ; posé puis retiré, il
/// apparaît puis disparaît. Linux seulement : sous Windows et macOS, il va sur le Bureau.
#[test]
fn raccourci_pose_puis_retire() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let refus = vanguard("fr", &["raccourci"], "n\n", 30);
    assert_eq!(refus.code, Some(0), "{}", refus.erreurs);
    assert!(
        !sans_couleurs(&refus.texte).contains("Raccourci posé"),
        "{}",
        refus.texte
    );
    // Une même maison pour les deux lancements : le dossier personnel jetable est refait à chaque fois, donc chacun
    // se vérifie seul.
    let pose = vanguard("fr", &["raccourci", "on"], "", 30);
    assert_eq!(pose.code, Some(0), "{}", pose.erreurs);
    assert!(sans_couleurs(&pose.texte).contains("Raccourci posé"), "{}", pose.texte);
    let retire = vanguard("fr", &["raccourci", "off"], "", 30);
    assert_eq!(retire.code, Some(0), "{}", retire.erreurs);
}

/// Les outils qui écrivent sur un disque s'ouvrent et rendent la main quand on revient sans rien choisir (Entrée) ;
/// la clé VANGUARD, et chacune de ses partitions, n'est jamais proposée.
#[test]
fn outils_de_disque_quittes_sans_rien_ecrire() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let cle = vanguard("fr", &["verifier-cle"], "\n", 30);
    assert_eq!(cle.code, Some(0), "{}", cle.erreurs);
    let t = sans_couleurs(&cle.texte);
    assert!(t.contains("VÉRIFIER MA CLÉ"), "{t}");
    for partition in ["VANGUARD ", "VANGUARDLOG", "VTOYEFI", "WIN11"] {
        assert!(!t.contains(&format!("  {partition}")), "{partition} proposée : {t}");
    }
    assert!(!t.contains("Commencer ?"), "{t}");
    let sauvegarde = vanguard("fr", &["sauvegarde-auto"], "\n\n", 60);
    assert_eq!(sauvegarde.code, Some(0), "{}", sauvegarde.erreurs);
    let t = sans_couleurs(&sauvegarde.texte);
    assert!(t.contains("SAUVEGARDE AUTOMATIQUE"), "{t}");
}

/// Lancé depuis une clé (le programme copié dans <clé>/Linux, témoin vide : jamais la protection de la clé), Vanguard
/// remplace sur accord la copie plus ancienne de cet ordinateur par lui-même ; lancé depuis cette copie, il se tourne
/// vers GitHub. Dans le dossier temporaire de cargo, pas dans /tmp : deux programmes de debug y pèsent 250 Mo.
#[cfg(target_os = "linux")]
#[test]
fn mise_a_jour_depuis_la_cle() {
    let racine = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("mise-a-jour-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&racine);
    let (cle, maison) = (racine.join("cle"), racine.join("maison"));
    std::fs::create_dir_all(cle.join("Linux")).unwrap();
    std::fs::write(cle.join("vanguard.cle"), "").unwrap();
    let sur_la_cle = cle.join("Linux").join("vanguard");
    std::fs::copy(env!("CARGO_BIN_EXE_vanguard"), &sur_la_cle).unwrap();
    let copie = maison.join("donnees").join("vanguard").join("bin").join("vanguard");
    std::fs::create_dir_all(copie.parent().unwrap()).unwrap();
    std::fs::write(&copie, "vieille copie, sans version gravée").unwrap();

    // Refusée (Entrée) : rien ne change.
    let refus = vanguard_dans(&sur_la_cle, &maison, "fr", &["se-mettre-a-jour"], "\n", 60);
    assert_eq!(refus.code, Some(0), "{}", refus.erreurs);
    let t = sans_couleurs(&refus.texte);
    assert!(t.contains("d'avant la 0.78") && t.contains("La remplacer"), "{t}");
    assert_eq!(
        std::fs::read(&copie).unwrap(),
        b"vieille copie, sans version grav\xc3\xa9e"
    );
    // Acceptée : la copie devient le programme de la clé, octet pour octet.
    let accord = vanguard_dans(&sur_la_cle, &maison, "fr", &["se-mettre-a-jour"], "o\n", 60);
    assert!(
        sans_couleurs(&accord.texte).contains("Copie de cet ordinateur mise à jour"),
        "{}",
        accord.texte
    );
    // Comparés sans assert_eq! : en cas d'échec, il imprimerait deux programmes de 113 Mo.
    let identique = std::fs::read(&copie).unwrap() == std::fs::read(&sur_la_cle).unwrap();
    assert!(identique, "la copie n'est pas le programme de la clé");
    // Ensuite : à jour depuis la clé ; depuis la copie, renvoi vers la clé (jamais une clé seulement branchée).
    let ensuite = vanguard_dans(&sur_la_cle, &maison, "fr", &["se-mettre-a-jour"], "", 60);
    assert!(
        sans_couleurs(&ensuite.texte).contains("est à jour"),
        "{}",
        ensuite.texte
    );
    let depuis_la_copie = vanguard_dans(&copie, &maison, "en", &["se-mettre-a-jour"], "", 60);
    assert!(
        sans_couleurs(&depuis_la_copie.texte).contains("the update comes from"),
        "{}",
        depuis_la_copie.texte
    );
    let _ = std::fs::remove_dir_all(&racine);
}

/// Les traces collectées dans un dossier jetable : un seul dossier daté, réservé au compte, avec LISEZMOI (en
/// français puis en anglais), MANIFESTE et les processus ; chaque empreinte du manifeste est juste et chaque fichier y
/// est. Sous Wine, sans PowerShell, une partie manque et c'est dit ; LISEZMOI et MANIFESTE, eux, sont là.
#[test]
fn traces_collectees_et_manifeste_juste() {
    use sha2::Digest;
    let maison = maison_jetable();
    let dossier = maison.join("enquete");
    let s = vanguard_dans(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "fr",
        &["traces", dossier.to_str().unwrap()],
        "",
        300,
    );
    assert_eq!(s.code, Some(0), "{}\n{}", s.texte, s.erreurs);
    assert!(!s.erreurs.contains("panicked"), "{}", s.erreurs);
    let texte = sans_couleurs(&s.texte);
    assert!(
        texte.contains("Collecter les traces") && texte.contains("Traces : "),
        "{texte}"
    );
    let traces: Vec<PathBuf> = std::fs::read_dir(&dossier)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    assert_eq!(traces.len(), 1, "{traces:?}");
    let d = &traces[0];
    let nom = d.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        nom.starts_with("traces-") && nom.len() == "traces-20261020-140322".len(),
        "{nom}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(d).unwrap().permissions().mode() & 0o777, 0o700);
    }
    let lisezmoi = std::fs::read_to_string(d.join("LISEZMOI.txt")).unwrap();
    assert!(
        lisezmoi.contains("TRACES COLLECTÉES PAR VANGUARD") && lisezmoi.contains("TRACES COLLECTED BY VANGUARD"),
        "{lisezmoi}"
    );
    assert!(lisezmoi.contains("données personnelles") && lisezmoi.contains(env!("CARGO_PKG_VERSION")));
    if !sous_wine() {
        let processus = std::fs::read_to_string(d.join("01-processus.txt")).unwrap();
        assert!(processus.lines().count() > 3, "{processus}");
    }
    // Le manifeste : chaque fichier du dossier, sauf lui-même, avec son empreinte juste (format de sha256sum).
    let manifeste = std::fs::read_to_string(d.join("MANIFESTE.txt")).unwrap();
    let mut listes: Vec<String> = Vec::new();
    for ligne in manifeste.lines() {
        let (empreinte, nom) = ligne.split_once("  ").expect("ligne du manifeste mal formée");
        let calculee =
            sha2::Sha256::digest(std::fs::read(d.join(nom)).unwrap())
                .iter()
                .fold(String::new(), |mut s, o| {
                    use std::fmt::Write;
                    let _ = write!(s, "{o:02x}");
                    s
                });
        assert_eq!(empreinte, calculee, "{nom}");
        listes.push(nom.to_string());
    }
    let mut presents: Vec<String> = std::fs::read_dir(d)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "MANIFESTE.txt")
        .collect();
    presents.sort();
    assert_eq!(listes, presents);
    assert!(listes.contains(&"LISEZMOI.txt".to_string()));
    let _ = std::fs::remove_dir_all(&maison);
}
