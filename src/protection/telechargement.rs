//! Vérifier un fichier téléchargé : son empreinte, calculée par l'outil du système, comparée à celle que publie le
//! site (collée, ou lue dans un fichier SHA256SUMS ou .sha256 posé à côté) ; son nom et sa nature (double extension,
//! programme déguisé en document) ; puis l'analyse YARA et l'antivirus. Un moteur absent ou en échec est dit, jamais
//! compté comme sain. Vanguard ne déplace ni ne supprime rien (Defender, lui, met en quarantaine ce qu'il reconnaît).

use std::path::{Path, PathBuf};

use crate::protection::antivirus::Examen;
use crate::risk::Niveau;
use crate::ui::*;

/// Sorte d'empreinte, reconnue à sa longueur en chiffres hexadécimaux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Algo {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl Algo {
    fn par_longueur(n: usize) -> Option<Algo> {
        match n {
            32 => Some(Algo::Md5),
            40 => Some(Algo::Sha1),
            64 => Some(Algo::Sha256),
            128 => Some(Algo::Sha512),
            _ => None,
        }
    }

    fn nom(self) -> &'static str {
        match self {
            Algo::Md5 => "MD5",
            Algo::Sha1 => "SHA-1",
            Algo::Sha256 => "SHA-256",
            Algo::Sha512 => "SHA-512",
        }
    }

    /// MD5 et SHA-1 se falsifient : ils montrent un fichier abîmé, pas un fichier remplacé exprès.
    fn faible(self) -> bool {
        matches!(self, Algo::Md5 | Algo::Sha1)
    }
}

/// Extensions de programmes, de scripts et d'installateurs.
pub(crate) const PROGRAMMES: &[&str] = &[
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msix", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "jar",
    "lnk", "apk", "app", "sh", "run", "bin", "elf", "appimage", "dmg", "pkg",
];

/// Extensions de documents, d'images et de médias : un programme qui en porte une se déguise.
const DOCUMENTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "txt", "csv", "jpg", "jpeg", "png",
    "gif", "bmp", "webp", "heic", "mp3", "mp4", "avi", "mkv", "mov", "wav",
];

/// Une empreinte collée : la première suite de chiffres hexadécimaux d'une longueur connue, en ignorant un préfixe
/// (« sha256: ») ou un nom de fichier (« 3a5f…  vanguard.iso »), ou une empreinte coupée en groupes.
fn lire_empreinte(saisie: &str) -> Option<(Algo, String)> {
    let trouvee = saisie
        .split(|c: char| c.is_whitespace() || matches!(c, ':' | '=' | '*' | '(' | ')' | ',' | ';'))
        .filter(|j| j.chars().all(|c| c.is_ascii_hexdigit()))
        .find_map(|j| Algo::par_longueur(j.len()).map(|a| (a, j.to_ascii_lowercase())));
    if trouvee.is_some() {
        return trouvee;
    }
    let colle: String = saisie.chars().filter(|c| !c.is_whitespace()).collect();
    if colle.chars().all(|c| c.is_ascii_hexdigit()) {
        Algo::par_longueur(colle.len()).map(|a| (a, colle.to_ascii_lowercase()))
    } else {
        None
    }
}

/// L'empreinte d'un fichier dans une liste d'empreintes : lignes « empreinte  nom », « empreinte *nom »,
/// « SHA256 (nom) = empreinte », ou une empreinte seule si `seule_permise` (fichier « <nom>.sha256 » d'un seul
/// fichier ; dans une liste commune, une empreinte sans nom peut être celle de n'importe quel fichier du dossier).
fn chercher_dans_liste(texte: &str, nom: &str, seule_permise: bool) -> Option<(Algo, String)> {
    let lignes: Vec<&str> = texte
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    // Un nom peut contenir des espaces (« mon outil.zip ») : il est aussi cherché en fin de ligne, en entier.
    let mentionne = |l: &str| {
        l.split_whitespace()
            .map(|j| j.trim_start_matches('*').trim_matches(['(', ')']))
            .any(|j| j == nom || j.ends_with(&format!("/{nom}")))
            || [" ", "*", "/"]
                .iter()
                .any(|avant| l.ends_with(&format!("{avant}{nom}")))
            || l.contains(&format!("({nom})"))
    };
    if let Some(l) = lignes.iter().find(|l| mentionne(l)) {
        return lire_empreinte(l);
    }
    match lignes[..] {
        [seule] if seule_permise && !seule.contains(char::is_whitespace) => lire_empreinte(seule),
        _ => None,
    }
}

/// L'empreinte publiée à côté du fichier, s'il y en a une : (sorte, empreinte, fichier où elle a été lue).
fn empreinte_a_cote(fichier: &Path) -> Option<(Algo, String, PathBuf)> {
    let nom = fichier.file_name()?.to_string_lossy().to_string();
    let dossier = fichier.parent()?;
    let candidats = [
        format!("{nom}.sha256"),
        format!("{nom}.sha256sum"),
        format!("{nom}.sha256.txt"),
        format!("{nom}.sha512"),
        format!("{nom}.sha1"),
        format!("{nom}.md5"),
        "SHA256SUMS".into(),
        "SHA256SUMS.txt".into(),
        "sha256sums.txt".into(),
        "sha256sum.txt".into(),
        "SHA512SUMS".into(),
        "CHECKSUMS".into(),
        "checksums.txt".into(),
    ];
    candidats.iter().find_map(|c| {
        let chemin = dossier.join(c);
        // Une liste d'empreintes tient en quelques kilo-octets : un gros fichier de ce nom n'en est pas une.
        if !std::fs::metadata(&chemin).is_ok_and(|m| m.len() <= 1_000_000) {
            return None;
        }
        let texte = std::fs::read_to_string(&chemin).ok()?;
        // « outil.zip.sha256 » ne parle que d'outil.zip ; « SHA256SUMS » parle de tout le dossier.
        chercher_dans_liste(&texte, &nom, c.starts_with(&format!("{nom}."))).map(|(a, e)| (a, e, chemin))
    })
}

/// L'empreinte du fichier, calculée par l'outil du système.
pub(crate) fn calculer(fichier: &Path, algo: Algo) -> Result<String, String> {
    #[cfg(windows)]
    let sortie = {
        let nom = match algo {
            Algo::Md5 => "MD5",
            Algo::Sha1 => "SHA1",
            Algo::Sha256 => "SHA256",
            Algo::Sha512 => "SHA512",
        };
        let chemin = crate::commande::ps_texte(&fichier.display().to_string());
        crate::machine::windows::ps(&format!("(Get-FileHash -Algorithm {nom} -LiteralPath '{chemin}').Hash"))
            .ok_or_else(|| tr!("Get-FileHash a échoué", "Get-FileHash failed").to_string())?
    };
    #[cfg(unix)]
    let sortie = {
        use std::process::Command;
        #[cfg(target_os = "macos")]
        let mut commande = match algo {
            Algo::Md5 => {
                let mut c = Command::new("md5");
                c.arg("-q");
                c
            }
            autre => {
                let mut c = Command::new("shasum");
                c.args([
                    "-a",
                    match autre {
                        Algo::Sha1 => "1",
                        Algo::Sha512 => "512",
                        _ => "256",
                    },
                ]);
                c
            }
        };
        #[cfg(not(target_os = "macos"))]
        let mut commande = Command::new(match algo {
            Algo::Md5 => "md5sum",
            Algo::Sha1 => "sha1sum",
            Algo::Sha256 => "sha256sum",
            Algo::Sha512 => "sha512sum",
        });
        commande.arg(fichier);
        // Une image disque de plusieurs gigaoctets se lit en une minute ou deux.
        let r = crate::commande::lancer(&mut commande, 900)
            .ok_or_else(|| tr!("l'outil n'a pas pu aller au bout", "the tool could not finish").to_string())?;
        if r.code != Some(0) {
            // Le message de l'outil cite le fichier, au nom choisi par son auteur.
            return Err(affichable(r.erreurs.lines().next().unwrap_or_default().trim()));
        }
        r.sortie
    };
    // sha256sum commence la ligne par « \\ » quand le nom du fichier contient « \\ » ou un saut de ligne.
    let empreinte = sortie
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_start_matches('\\')
        .to_ascii_lowercase();
    if Algo::par_longueur(empreinte.len()) == Some(algo) && empreinte.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(empreinte)
    } else {
        Err(tr!("réponse illisible de l'outil", "unreadable answer from the tool").into())
    }
}

/// Ce que disent le nom et les premiers octets : programme déguisé en document, double extension, caractère qui
/// retourne la fin du nom.
fn nature(nom: &str, debut: &[u8]) -> Vec<(Niveau, String)> {
    let mut signes = Vec::new();
    // U+202E retourne l'écriture : « facture[U+202E]fdp.exe » s'affiche « facture exe.pdf ».
    if nom.contains('\u{202e}') {
        signes.push((
            Niveau::Critique,
            tr!(
                "Nom piégé : un caractère invisible retourne la fin du nom pour cacher qu'il s'agit d'un programme.",
                "Trapped name: an invisible character reverses the end of the name to hide that it is a program."
            )
            .to_string(),
        ));
    }
    // Espaces autour des morceaux retirées : « facture.pdf .exe » reste une double extension (Windows ignore aussi
    // les espaces et les points en fin de nom).
    let morceaux: Vec<String> = nom
        .to_lowercase()
        .trim_end_matches(['.', ' '])
        .split('.')
        .map(|m| m.trim().to_string())
        .collect();
    let extension = morceaux
        .last()
        .filter(|_| morceaux.len() > 1)
        .cloned()
        .unwrap_or_default();
    let avant = morceaux
        .len()
        .checked_sub(2)
        .filter(|_| morceaux.len() > 2)
        .map(|i| morceaux[i].clone());
    if let Some(avant) = avant.filter(|a| DOCUMENTS.contains(&a.as_str()))
        && PROGRAMMES.contains(&extension.as_str())
    {
        signes.push((
            Niveau::Eleve,
            trf!(
                "Double extension « .{avant}.{extension} » : il se fait passer pour un document, c'est un programme.",
                "Double extension “.{avant}.{extension}”: it pretends to be a document, it is a program."
            ),
        ));
    }
    let programme = match debut {
        [b'M', b'Z', ..] => Some("Windows"),
        [0x7f, b'E', b'L', b'F', ..] => Some("Linux"),
        [0xcf | 0xce, 0xfa, 0xed, 0xfe, ..] | [0xca, 0xfe, 0xba, 0xbe, ..] => Some("macOS"),
        [b'#', b'!', ..] => Some("script"),
        _ => None,
    };
    if let Some(sorte) = programme {
        if DOCUMENTS.contains(&extension.as_str()) {
            signes.push((
                Niveau::Eleve,
                trf!(
                    "C'est un programme ({sorte}) déguisé en fichier .{extension}.",
                    "It is a program ({sorte}) disguised as a .{extension} file."
                ),
            ));
        } else {
            signes.push((
                Niveau::Info,
                trf!(
                    "Programme ({sorte}) : ne le lance que s'il vient du site officiel de son éditeur.",
                    "Program ({sorte}): only run it if it comes from its publisher's official site."
                ),
            ));
        }
    }
    signes
}

/// Windows : `canonicalize` rend un chemin étendu (« \\?\C:\… », « \\?\UNC\serveur\… ») que la personne ne
/// reconnaît pas à l'écran : remis sous sa forme habituelle, celle qu'elle a tapée ou glissée.
fn sans_prefixe_etendu(chemin: &str) -> String {
    if let Some(reseau) = chemin.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{reseau}");
    }
    match chemin.strip_prefix(r"\\?\") {
        Some(local) if local.as_bytes().get(1) == Some(&b':') => local.to_string(),
        _ => chemin.to_string(),
    }
}

/// « 3,4 Mo », « 812 o ».
fn taille(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)] // un ordre de grandeur, pour l'œil
    let o = octets as f64;
    match octets {
        0..1_000 => trf!("{octets} o", "{octets} B"),
        1_000..1_000_000 => trf!("{:.0} Ko", "{:.0} KB", o / 1e3),
        1_000_000..1_000_000_000 => trf!("{} Mo", "{} MB", crate::langue::decimal(o / 1e6, 1)),
        _ => trf!("{} Go", "{} GB", crate::langue::decimal(o / 1e9, 1)),
    }
}

fn ligne(niveau: Option<Niveau>, texte: &str) {
    let marque = match niveau {
        None => format!("{VERT}✔{RESET}"),
        Some(Niveau::Info) => format!("{GRIS}ℹ{RESET}"),
        Some(Niveau::Moyen) => format!("{}⚠{RESET}", couleur(Niveau::Moyen)),
        Some(n) => format!("{}✖{RESET}", couleur(n)),
    };
    afficher_aligne(&format!("  {marque} "), texte, 4, "");
}

/// Menu Antivirus et protection › Vérifier un fichier téléchargé (tout est demandé), ou
/// `vanguard verifier-fichier <fichier> [empreinte]`.
pub fn verifier(fichier: Option<&Path>, empreinte: Option<&str>) {
    titre(tr!("Vérifier un fichier téléchargé", "Check a downloaded file"));
    let interactif = fichier.is_none();
    let chemin = if let Some(f) = fichier {
        f.to_path_buf()
    } else {
        let reponse = demander(tr!(
            "  Fichier à vérifier (glisse-le ici, ou tape son chemin) : ",
            "  File to check (drag it here, or type its path): "
        ));
        let reponse = reponse.trim().trim_matches(['"', '\'']);
        if reponse.is_empty() {
            return;
        }
        PathBuf::from(reponse)
    };
    let Ok(chemin) = chemin
        .canonicalize()
        .map(|c| PathBuf::from(sans_prefixe_etendu(&c.to_string_lossy())))
    else {
        trp!("  ✖ Introuvable : {}", "  ✖ Not found: {}", chemin_affichable(&chemin));
        return;
    };
    let Ok(meta) = std::fs::metadata(&chemin) else {
        trp!("  ✖ Illisible : {}", "  ✖ Unreadable: {}", chemin_affichable(&chemin));
        return;
    };
    if !meta.is_file() {
        trp!(
            "  ✖ Ce n'est pas un fichier (un dossier s'analyse avec l'antivirus ou YARA).",
            "  ✖ This is not a file (a folder is scanned with the antivirus or YARA)."
        );
        return;
    }
    // Le nom tel quel sert à juger (un caractère qui retourne la fin du nom est justement le piège à trouver) ; montré,
    // il est rendu inoffensif, comme le dossier.
    let nom = chemin
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    println!();
    println!(
        "  {GRIS}{}{RESET} {} {GRIS}({}){RESET}",
        ajuster(tr!("Fichier", "File"), 8),
        affichable(&nom),
        taille(meta.len())
    );
    afficher_aligne(
        &format!("  {GRIS}{}{RESET} ", ajuster(tr!("Dossier", "Folder"), 8)),
        &chemin.parent().map(chemin_affichable).unwrap_or_default(),
        11,
        "",
    );

    // 1. L'empreinte : celle collée, sinon celle posée à côté, sinon on la demande (menu).
    let saisie = match empreinte {
        Some(e) => Some(e.to_string()),
        None if interactif && empreinte_a_cote(&chemin).is_none() => Some(demander(tr!(
            "  Empreinte publiée par le site (SHA-256 ; Entrée si tu ne l'as pas) : ",
            "  Checksum published by the site (SHA-256; Enter if you do not have it): "
        )))
        .filter(|e| !e.trim().is_empty()),
        None => None,
    };
    let attendue = match &saisie {
        Some(s) => {
            let lue = lire_empreinte(s).map(|(a, e)| (a, e, tr!("collée", "pasted").to_string()));
            if lue.is_none() {
                // Le texte collé vient souvent d'une page web.
                trp!(
                    "  ⚠ « {} » n'est pas une empreinte reconnue (32, 40, 64 ou 128 chiffres hexadécimaux).",
                    "  ⚠ “{}” is not a recognized checksum (32, 40, 64 or 128 hexadecimal digits).",
                    affichable(s.trim())
                );
            }
            lue
        }
        None => empreinte_a_cote(&chemin).map(|(a, e, f)| {
            let source = f
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            (a, e, trf!("lue dans {source}", "read from {source}"))
        }),
    };

    section(tr!("Empreinte", "Checksum"));
    trp!(
        "  {GRIS}Calcul de l'empreinte…{RESET}",
        "  {GRIS}Computing the checksum…{RESET}"
    );
    let mut pire: Option<Niveau> = None;
    let mut incomplet = Vec::new();
    let mut conforme = false;
    let sha256 = calculer(&chemin, Algo::Sha256);
    match &sha256 {
        Ok(sha256) => println!("  {GRIS}SHA-256{RESET}  {sha256}"),
        Err(e) => {
            ligne(
                Some(Niveau::Moyen),
                &trf!(
                    "SHA-256 impossible à calculer : {e}",
                    "SHA-256 could not be computed: {e}"
                ),
            );
            incomplet.push(tr!("l'empreinte", "the checksum"));
        }
    }
    match &attendue {
        None => ligne(
            Some(Niveau::Info),
            tr!(
                "Pas d'empreinte à comparer : cherche « SHA-256 » sur la page de téléchargement officielle, puis refais la vérification avec elle.",
                "No checksum to compare: look for “SHA-256” on the official download page, then check again with it."
            ),
        ),
        // Une image disque de plusieurs gigaoctets ne se relit pas pour rien.
        Some((algo, valeur, source)) => match if *algo == Algo::Sha256 {
            sha256.clone()
        } else {
            calculer(&chemin, *algo)
        } {
            Ok(calculee) if calculee == *valeur => {
                conforme = !algo.faible();
                ligne(
                    if algo.faible() { Some(Niveau::Info) } else { None },
                    &if algo.faible() {
                        trf!(
                            "L'empreinte {} ({source}) correspond : le fichier n'est pas abîmé. {} se falsifie, il ne prouve pas que personne ne l'a remplacé.",
                            "The {} checksum ({source}) matches: the file is not damaged. {} can be forged; it does not prove nobody replaced it.",
                            algo.nom(),
                            algo.nom()
                        )
                    } else {
                        trf!(
                            "L'empreinte {} ({source}) correspond : c'est bien le fichier publié, intact.",
                            "The {} checksum ({source}) matches: it is the published file, intact.",
                            algo.nom()
                        )
                    },
                );
            }
            Ok(calculee) => {
                pire = Some(Niveau::Critique);
                ligne(
                    Some(Niveau::Critique),
                    &trf!(
                        "L'empreinte {} ({source}) ne correspond pas : le fichier a été abîmé ou remplacé. Attendue {valeur}, obtenue {calculee}.",
                        "The {} checksum ({source}) does not match: the file was damaged or replaced. Expected {valeur}, got {calculee}.",
                        algo.nom()
                    ),
                );
            }
            Err(e) => {
                ligne(
                    Some(Niveau::Moyen),
                    &trf!(
                        "{} impossible à calculer : {e}",
                        "{} could not be computed: {e}",
                        algo.nom()
                    ),
                );
                incomplet.push(tr!("l'empreinte", "the checksum"));
            }
        },
    }

    // 2. Le nom et les premiers octets.
    section(tr!("Nom et contenu", "Name and content"));
    let mut debut = [0_u8; 4];
    let lus = std::fs::File::open(&chemin)
        .and_then(|mut f| std::io::Read::read(&mut f, &mut debut))
        .unwrap_or(0);
    let signes = nature(&nom, &debut[..lus]);
    if signes.is_empty() {
        ligne(
            None,
            tr!(
                "Rien de trompeur dans le nom ni dans le contenu.",
                "Nothing misleading in the name or the content."
            ),
        );
    }
    for (niveau, texte) in &signes {
        ligne(Some(*niveau), texte);
        if *niveau > Niveau::Info {
            pire = pire.max(Some(*niveau));
        }
    }

    // 3. Les moteurs : YARA, puis l'antivirus du système.
    section(tr!("Analyse", "Scan"));
    let antivirus = if cfg!(windows) { "Defender" } else { "ClamAV" };
    let mut detecte = false;
    for (moteur, examen) in [
        ("YARA", crate::protection::yara::examiner(&chemin)),
        (antivirus, crate::protection::antivirus::examiner(&chemin)),
    ] {
        match examen {
            Examen::Sain => ligne(None, &trf!("{moteur} : rien trouvé.", "{moteur}: nothing found.")),
            Examen::Trouve(noms) => {
                detecte = true;
                pire = Some(Niveau::Critique);
                ligne(
                    Some(Niveau::Critique),
                    &trf!("{moteur} : {}", "{moteur}: {}", resume(&noms, 3, ", ")),
                );
            }
            Examen::Impossible(raison) => {
                incomplet.push(moteur);
                ligne(
                    Some(Niveau::Moyen),
                    &trf!(
                        "{moteur} : impossible à vérifier ({raison}).",
                        "{moteur}: could not check ({raison})."
                    ),
                );
            }
        }
    }

    // Le verdict.
    println!();
    let verdict = if detecte {
        tr!(
            "Ne l'ouvre pas : il contient un logiciel malveillant connu. Supprime-le (ou laisse-le en quarantaine) et vide la corbeille.",
            "Do not open it: it contains known malware. Delete it (or leave it in quarantine) and empty the trash."
        )
        .to_string()
    } else if pire >= Some(Niveau::Eleve) {
        tr!(
            "Ne l'ouvre pas : ce fichier n'est pas ce qu'il prétend être, ou il a été modifié. Retélécharge-le depuis le site officiel.",
            "Do not open it: this file is not what it claims to be, or it was modified. Download it again from the official site."
        )
        .to_string()
    } else {
        let mut t = if conforme {
            tr!(
                "Rien de suspect : empreinte conforme et aucune détection.",
                "Nothing suspicious: matching checksum and no detection."
            )
            .to_string()
        } else {
            tr!(
                "Aucune détection, mais l'empreinte n'a pas prouvé que c'est le fichier publié.",
                "No detection, but the checksum did not prove it is the published file."
            )
            .to_string()
        };
        t += tr!(
            " Aucun outil ne garantit qu'un programme est honnête : télécharge seulement depuis le site officiel de l'éditeur.",
            " No tool guarantees a program is honest: only download from the publisher's official site."
        );
        t
    };
    let couleur_verdict = match pire {
        Some(n) if n >= Niveau::Eleve => couleur(n),
        _ if !incomplet.is_empty() => couleur(Niveau::Moyen),
        _ => VERT,
    };
    for l in envelopper(&verdict, LARGEUR - 2) {
        println!("  {couleur_verdict}{l}{RESET}");
    }
    if !incomplet.is_empty() && !detecte {
        let quoi = resume(&incomplet, 3, ", ");
        for l in envelopper(
            &trf!(
                "Vérification incomplète ({quoi}) : rien n'est conclu pour ce qui n'a pas pu être vérifié.",
                "Incomplete check ({quoi}): nothing is concluded for what could not be checked."
            ),
            LARGEUR - 2,
        ) {
            println!("  {GRIS}{l}{RESET}");
        }
    }
}

// ───────────────────────────── Surveillance des Téléchargements ─────────────────────────────

/// Le dossier des téléchargements : celui que déclare le bureau (user-dirs.dirs sous Linux, le registre sous Windows,
/// déplacé dans OneDrive le cas échéant), sinon le nom usuel.
#[cfg_attr(target_os = "macos", allow(clippy::unnecessary_wraps))] // même signature que sous Linux et Windows
pub(crate) fn dossier_telechargements() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let maison = crate::nettoyer::maison();
        let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
        let declares = std::fs::read_to_string(config.join("user-dirs.dirs")).unwrap_or_default();
        crate::protection::pieges::dossier_declare(&declares, "XDG_DOWNLOAD_DIR", &maison).or_else(|| {
            ["Téléchargements", "Downloads"]
                .iter()
                .map(|n| maison.join(n))
                .find(|d| d.is_dir())
        })
    }
    #[cfg(windows)]
    {
        // Le dossier Téléchargements n'a pas de nom lisible dans le registre, seulement son identifiant connu.
        winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
            .ok()
            .and_then(|k| k.get_value::<String, _>("{374DE290-123F-4565-9164-39C4925E467B}").ok())
            .map(|c| PathBuf::from(crate::protection::pieges::developper(&c)))
            .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("Downloads")))
    }
    #[cfg(target_os = "macos")]
    {
        Some(crate::nettoyer::maison().join("Downloads"))
    }
}

/// Un fichier en cours de téléchargement : il sera renommé à la fin, et vu alors.
fn en_cours(nom: &str) -> bool {
    let bas = nom.to_lowercase();
    [".part", ".crdownload", ".download", ".partial", ".tmp", ".opdownload"]
        .iter()
        .any(|e| bas.ends_with(e))
}

/// Instant d'arrivée d'un fichier, en secondes depuis 1970 : sa dernière modification, ou son arrivée dans le dossier
/// si elle est plus récente (un navigateur renomme « x.exe.part » en « x.exe » à la fin, ce qui ne change pas la date
/// de modification : sous Linux et macOS, le changement d'état le note ; sous Windows, la création).
fn arrivee(meta: &std::fs::Metadata) -> u64 {
    let secondes = |t: std::io::Result<std::time::SystemTime>| {
        t.ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs())
    };
    #[cfg(unix)]
    let changement = u64::try_from(std::os::unix::fs::MetadataExt::ctime(meta)).unwrap_or(0);
    #[cfg(windows)]
    let changement = secondes(meta.created());
    secondes(meta.modified()).max(changement)
}

/// Ce qu'un fichier arrivé dit de lui-même (nom et premiers octets) : un programme, ou un fichier déguisé. Rien pour un
/// document ordinaire. Rend (titre, texte) de la notification.
fn signalement(nom: &str, debut: &[u8]) -> Option<(String, String)> {
    let signes = nature(nom, debut);
    // Un installateur sans signature d'en-tête connue (.msi, .dmg, .pkg, .apk…) reste un programme, d'après son nom.
    let extension = nom
        .rsplit_once('.')
        .map(|(_, e)| e.trim().to_lowercase())
        .unwrap_or_default();
    let pire = signes
        .iter()
        .map(|(n, _)| *n)
        .max()
        .or_else(|| PROGRAMMES.contains(&extension.as_str()).then_some(Niveau::Info))?;
    let nom = affichable(nom);
    let verifier = tr!(
        "vérifie-le avant de l'ouvrir : menu Antivirus et protection › Vérifier un fichier téléchargé, ou « vanguard verifier-fichier ».",
        "check it before opening it: menu Antivirus and protection › Check a downloaded file, or “vanguard check-file”."
    );
    Some(if pire >= Niveau::Eleve {
        let raisons: Vec<&str> = signes
            .iter()
            .filter(|(n, _)| *n >= Niveau::Eleve)
            .map(|(_, t)| t.as_str())
            .collect();
        (
            tr!(
                "Vanguard : fichier déguisé téléchargé",
                "Vanguard: disguised file downloaded"
            )
            .to_string(),
            trf!(
                "« {nom} » : {} Ne l'ouvre pas ; {verifier}",
                "“{nom}”: {} Do not open it; {verifier}",
                raisons.join(" ")
            ),
        )
    } else {
        (
            tr!("Vanguard : programme téléchargé", "Vanguard: program downloaded").to_string(),
            trf!(
                "« {nom} » est un programme : {verifier}",
                "“{nom}” is a program: {verifier}"
            ),
        )
    })
}

/// Les fichiers arrivés après `depuis` parmi `fichiers` (nom, arrivée, premiers octets), à signaler : trois au plus,
/// puis une ligne pour le reste.
fn a_signaler(fichiers: &[(String, u64, Vec<u8>)], depuis: u64) -> Vec<(String, String)> {
    let trouves: Vec<(String, String)> = fichiers
        .iter()
        .filter(|(nom, arrivee, _)| *arrivee > depuis && !nom.starts_with('.') && !en_cours(nom))
        .filter_map(|(nom, _, debut)| signalement(nom, debut))
        .collect();
    let mut notes: Vec<(String, String)> = trouves.iter().take(3).cloned().collect();
    if trouves.len() > 3 {
        notes.push((
            tr!(
                "Vanguard : autres programmes téléchargés",
                "Vanguard: other programs downloaded"
            )
            .to_string(),
            trf!(
                "{} autre(s) programme(s) arrivé(s) dans Téléchargements : vérifie-les avant de les ouvrir.",
                "{} other program(s) arrived in Downloads: check them before opening them.",
                trouves.len() - 3
            ),
        ));
    }
    notes
}

fn fichier_surveillance() -> PathBuf {
    crate::reseau::dossier_local().join("surveillance-telechargements.json")
}

/// Pour la surveillance horaire : les programmes et fichiers déguisés arrivés dans Téléchargements depuis le passage
/// précédent, à notifier. Rien n'est bloqué, déplacé ni ouvert ; le premier passage note seulement l'heure.
pub fn nouveaux_a_signaler() -> Vec<(String, String)> {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Etat {
        depuis: u64,
    }
    let Some(dossier) = dossier_telechargements().filter(|d| d.is_dir()) else {
        return Vec::new();
    };
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let avant: Option<Etat> = std::fs::read_to_string(fichier_surveillance())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    let notes = avant.map_or_else(Vec::new, |avant| {
        let fichiers: Vec<(String, u64, Vec<u8>)> = std::fs::read_dir(&dossier)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let meta = std::fs::symlink_metadata(e.path())
                    .ok()
                    .filter(std::fs::Metadata::is_file)?;
                let arrivee = arrivee(&meta);
                if arrivee <= avant.depuis {
                    return Some((e.file_name().to_string_lossy().into_owned(), arrivee, Vec::new()));
                }
                let mut debut = [0u8; 4];
                let lus = std::fs::File::open(e.path())
                    .and_then(|mut f| std::io::Read::read(&mut f, &mut debut))
                    .unwrap_or(0);
                Some((
                    e.file_name().to_string_lossy().into_owned(),
                    arrivee,
                    debut[..lus].to_vec(),
                ))
            })
            .collect();
        a_signaler(&fichiers, avant.depuis)
    });
    if let Ok(texte) = serde_json::to_string(&Etat { depuis: maintenant }) {
        let _ = std::fs::create_dir_all(crate::reseau::dossier_local());
        let _ = std::fs::write(fichier_surveillance(), texte);
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    #[test]
    fn empreintes_collees() {
        assert_eq!(lire_empreinte(SHA), Some((Algo::Sha256, SHA.into())));
        assert_eq!(
            lire_empreinte(&format!("sha256:{}", SHA.to_uppercase())),
            Some((Algo::Sha256, SHA.into()))
        );
        assert_eq!(
            lire_empreinte(&format!("{SHA}  vanguard.iso")),
            Some((Algo::Sha256, SHA.into()))
        );
        assert_eq!(
            lire_empreinte(&format!("SHA256 (vanguard.iso) = {SHA}")),
            Some((Algo::Sha256, SHA.into()))
        );
        // Coupée en groupes, comme certaines pages l'affichent.
        let groupes: Vec<String> = SHA
            .as_bytes()
            .chunks(8)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        assert_eq!(lire_empreinte(&groupes.join(" ")), Some((Algo::Sha256, SHA.into())));
        assert_eq!(
            lire_empreinte("d41d8cd98f00b204e9800998ecf8427e"),
            Some((Algo::Md5, "d41d8cd98f00b204e9800998ecf8427e".into()))
        );
        assert_eq!(lire_empreinte("pas une empreinte"), None);
        assert_eq!(lire_empreinte("deadbeef"), None);
    }

    #[test]
    fn listes_d_empreintes() {
        let autre = "0".repeat(64);
        let liste = format!("{autre}  vanguard.iso.sig\n{SHA} *vanguard.iso\n");
        assert_eq!(
            chercher_dans_liste(&liste, "vanguard.iso", false),
            Some((Algo::Sha256, SHA.into()))
        );
        assert_eq!(
            chercher_dans_liste(&format!("{SHA}  ./dist/vanguard.iso\n"), "vanguard.iso", false).map(|e| e.1),
            Some(SHA.into())
        );
        assert_eq!(
            chercher_dans_liste(&format!("SHA256 (vanguard.iso) = {SHA}\n"), "vanguard.iso", false).map(|e| e.1),
            Some(SHA.into())
        );
        // Fichier .sha256 d'un seul fichier : l'empreinte seule.
        assert_eq!(
            chercher_dans_liste(&format!("{SHA}\n"), "vanguard.iso", true).map(|e| e.1),
            Some(SHA.into())
        );
        // Un nom avec des espaces.
        assert_eq!(
            chercher_dans_liste(&format!("{SHA}  mon outil.zip\n"), "mon outil.zip", false).map(|e| e.1),
            Some(SHA.into())
        );
        // L'empreinte d'un autre fichier ne compte pas.
        assert_eq!(
            chercher_dans_liste(&format!("{SHA}  autre.iso\n"), "vanguard.iso", false),
            None
        );
    }

    #[test]
    fn empreinte_posee_a_cote() {
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let fichier = dossier.join("outil.zip");
        std::fs::write(&fichier, b"test").unwrap();
        assert_eq!(empreinte_a_cote(&fichier), None);
        std::fs::write(dossier.join("SHA256SUMS"), format!("{SHA}  outil.zip\n")).unwrap();
        let (algo, valeur, source) = empreinte_a_cote(&fichier).unwrap();
        assert_eq!((algo, valeur.as_str()), (Algo::Sha256, SHA));
        assert!(source.ends_with("SHA256SUMS"));
        // L'outil du système calcule la même empreinte (« test »).
        if cfg!(unix) {
            assert_eq!(calculer(&fichier, Algo::Sha256).as_deref(), Ok(SHA));
            // Un nom avec « \\ » : sha256sum échappe sa ligne, l'empreinte reste lue.
            let bizarre = dossier.join("a\\b.zip");
            std::fs::write(&bizarre, b"test").unwrap();
            assert_eq!(calculer(&bizarre, Algo::Sha256).as_deref(), Ok(SHA));
        }
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    // Une empreinte seule, sans nom, ne vaut que dans le fichier propre à l'image (« outil.zip.sha256 ») : dans une
    // liste commune (SHA256SUMS), elle peut être celle de n'importe quel fichier du dossier, et la comparer donnait
    // « abîmé ou remplacé » à tort.
    #[test]
    fn empreinte_seule_dans_une_liste_commune() {
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let fichier = dossier.join("outil.zip");
        std::fs::write(&fichier, b"test").unwrap();
        std::fs::write(dossier.join("SHA256SUMS"), format!("{}\n", "0".repeat(64))).unwrap();
        assert_eq!(empreinte_a_cote(&fichier), None);
        std::fs::write(dossier.join("outil.zip.sha256"), format!("{SHA}\n")).unwrap();
        assert_eq!(empreinte_a_cote(&fichier).map(|e| e.1), Some(SHA.to_string()));
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    #[test]
    fn noms_et_contenus() {
        let niveaux = |nom: &str, debut: &[u8]| nature(nom, debut).iter().map(|(n, _)| *n).collect::<Vec<_>>();
        assert_eq!(niveaux("facture.pdf.exe", b"MZ\x90\x00"), [Niveau::Eleve, Niveau::Info]);
        assert_eq!(niveaux("photo.jpg", b"MZ\x90\x00"), [Niveau::Eleve]);
        assert_eq!(
            niveaux("facture\u{202e}fdp.exe", b"MZ\x90\x00"),
            [Niveau::Critique, Niveau::Info]
        );
        assert_eq!(niveaux("installateur.exe", b"MZ\x90\x00"), [Niveau::Info]);
        assert_eq!(
            niveaux("facture.pdf   .exe", b"MZ\x90\x00"),
            [Niveau::Eleve, Niveau::Info]
        );
        assert_eq!(niveaux("rapport.pdf", b"%PDF"), []);
        assert_eq!(niveaux("notes.v2.txt", b"Bonj"), []);
        assert_eq!(niveaux("script", b"#!/b"), [Niveau::Info]);
    }

    #[test]
    fn chemins_etendus_de_windows() {
        assert_eq!(
            sans_prefixe_etendu(r"\\?\C:\Users\alice\outil.zip"),
            r"C:\Users\alice\outil.zip"
        );
        assert_eq!(
            sans_prefixe_etendu(r"\\?\UNC\nas\partage\a.iso"),
            r"\\nas\partage\a.iso"
        );
        // Un volume sans lettre garde son préfixe ; un chemin ordinaire reste tel quel.
        assert_eq!(
            sans_prefixe_etendu(r"\\?\Volume{1234}\a.iso"),
            r"\\?\Volume{1234}\a.iso"
        );
        assert_eq!(sans_prefixe_etendu("/home/alice/a.iso"), "/home/alice/a.iso");
    }

    #[test]
    fn tailles() {
        assert_eq!(taille(812), "812 o");
        assert_eq!(taille(3_400_000), "3,4 Mo");
        assert_eq!(taille(4_700_000_000), "4,7 Go");
    }

    #[test]
    fn telechargements_signales_a_la_surveillance() {
        let f = |nom: &str, arrivee: u64, debut: &[u8]| (nom.to_string(), arrivee, debut.to_vec());
        let fichiers = [
            // Arrivés avant le passage précédent : déjà vus.
            f("vieux.exe", 100, b"MZ\x90\0"),
            // Un document ordinaire : rien à dire.
            f("facture.pdf", 200, b"%PDF"),
            // Un programme, un fichier déguisé, un nom piégé.
            f("setup.exe", 200, b"MZ\x90\0"),
            f("facture.pdf.exe", 200, b"MZ\x90\0"),
            f("photo\u{202e}gpj.scr", 200, b"MZ\x90\0"),
            // En cours de téléchargement, ou caché : pas encore.
            f("jeu.exe.part", 200, b"MZ\x90\0"),
            f(".cache.exe", 200, b"MZ\x90\0"),
        ];
        let notes = a_signaler(&fichiers, 150);
        assert_eq!(notes.len(), 3, "{notes:?}");
        assert!(notes[0].0.contains("programme téléchargé") && notes[0].1.contains("setup.exe"));
        assert!(notes[1].0.contains("déguisé") && notes[1].1.contains("Double extension"));
        assert!(notes[2].0.contains("déguisé") && notes[2].1.contains("photo�gpj.scr"));
        assert!(notes.iter().all(|(_, t)| !t.contains('\u{202e}')));
        // Quatre de plus : trois notifications, puis une pour le reste.
        let beaucoup: Vec<_> = (0..5).map(|i| f(&format!("outil{i}.msi"), 300, b"\xd0\xcf")).collect();
        let notes = a_signaler(&beaucoup, 150);
        assert_eq!(notes.len(), 4);
        assert!(notes[3].1.starts_with("2 autre(s)"));
        assert_eq!(a_signaler(&beaucoup, 300), Vec::<(String, String)>::new());
    }
}
