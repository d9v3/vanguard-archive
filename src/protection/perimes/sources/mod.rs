//! Les fichiers fixes qui disent la dernière version des logiciels suivis : une table fermée, la même pour tous les
//! ordinateurs d'un même système, qui ne dépend jamais de ce qui est installé. Chaque fichier est téléchargé en
//! entier, sans paramètre de version ni adresse par logiciel : la liste des logiciels de l'ordinateur ne sort jamais.
//! Le modèle est celui du catalogue de la CISA (`kev`) : gardé un jour dans le dossier de Vanguard, la copie d'avant
//! sert hors ligne. Le réglage « Versions des logiciels » (Paramètres) et le travail sans Internet coupent tout
//! téléchargement ; les copies déjà gardées servent alors seules, et c'est dit.
//!
//! Une réponse qui n'a pas la forme attendue (page d'un portail Wi-Fi, format changé) ne remplace jamais la bonne
//! copie (`abuse_ch::liste_validee`). Un fichier gzip est gardé tel que reçu, et relu par `degzip_controle` (CRC et
//! taille vérifiés) : un téléchargement coupé ne passe pas pour un fichier entier.

pub(crate) mod editeurs;
pub(crate) mod eol;
pub(crate) mod homebrew;

use std::time::Duration;

use serde::Deserialize;

use crate::{tr, trf};

/// Au-delà, la copie est redemandée.
pub(crate) const FRAICHE: Duration = Duration::from_hours(24);
/// Au-delà, une copie ne suffit plus pour dire « à jour » : le logiciel est « non vérifié ».
pub(crate) const A_JOUR_MAX: Duration = Duration::from_hours(72);
/// Au-delà, la source ne sert plus du tout : une copie aussi vieille n'est plus suivie.
pub(crate) const DEPASSEE_MAX: Duration = Duration::from_hours(30 * 24);
/// Le sous-dossier des copies, dans le dossier de Vanguard.
const SOUS_DOSSIER: &str = "versions";

/// Les systèmes dont les logiciels sont suivis (sous Linux, le gestionnaire de paquets tient les versions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Systeme {
    Windows,
    MacOs,
}

impl Systeme {
    /// Le système qui tourne ; `None` sous Linux.
    #[cfg(test)]
    pub(crate) fn courant() -> Option<Systeme> {
        if cfg!(windows) {
            Some(Systeme::Windows)
        } else if cfg!(target_os = "macos") {
            Some(Systeme::MacOs)
        } else {
            None
        }
    }
}

/// Comment un fichier se lit (et se valide : une réponse que son lecteur refuse ne remplace pas la copie d'avant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lecteur {
    Firefox,
    /// Plateforme et canal de versionhistory.
    Chrome(&'static str, &'static str),
    Edge,
    Office,
    /// L'identifiant d'application du manifeste de Microsoft AutoUpdate.
    Mau(&'static str),
    Adobe,
    Brave,
    Eol,
    Cask,
    /// L'archive des avis de sécurité de Mozilla (tar en gzip).
    Mfsa,
}

/// Une ligne de la table : un fichier fixe.
#[derive(Debug)]
pub(crate) struct Source {
    /// Aussi le nom de la copie gardée.
    pub id: &'static str,
    pub adresse: &'static str,
    pub lecteur: Lecteur,
    pub systemes: &'static [Systeme],
    /// Octets reçus au plus (compressés, quand le serveur compresse).
    pub taille_max: u64,
    /// `Some(n)` : demandé en gzip (`Accept-Encoding`), au plus `n` octets une fois décompressé.
    pub gzip: Option<usize>,
    /// Délai de la demande, en secondes.
    pub delai: u64,
}

const W: &[Systeme] = &[Systeme::Windows];
const M: &[Systeme] = &[Systeme::MacOs];
const WM: &[Systeme] = &[Systeme::Windows, Systeme::MacOs];

/// Une source de versionhistory (Chrome) : une adresse par plateforme et par canal, toutes prises.
macro_rules! chrome {
    ($p:literal, $c:literal, $s:expr) => {
        Source {
            id: concat!("chrome-", $p, "-", $c),
            adresse: concat!(
                "https://versionhistory.googleapis.com/v1/chrome/platforms/",
                $p,
                "/channels/",
                $c,
                "/versions/all/releases?filter=endtime=none"
            ),
            lecteur: Lecteur::Chrome($p, $c),
            systemes: $s,
            taille_max: 256 << 10,
            gzip: None,
            delai: 30,
        }
    };
}

/// Un manifeste de Microsoft AutoUpdate (Office pour Mac) : un par application, tous pris.
macro_rules! mau {
    ($id:literal) => {
        Source {
            id: concat!("mau-", $id),
            adresse: concat!(
                "https://res.public.onecdn.static.microsoft/mro1cdnstorage/C1297A47-86C4-4C1F-97FA-950631F94777/MacAutoupdate/0409",
                $id,
                "-chk.xml"
            ),
            lecteur: Lecteur::Mau($id),
            systemes: M,
            taille_max: 64 << 10,
            gzip: None,
            delai: 30,
        }
    };
}

/// Un petit fichier texte d'un éditeur (Adobe, Brave).
macro_rules! texte {
    ($id:literal, $adresse:literal, $lecteur:expr, $s:expr) => {
        Source {
            id: $id,
            adresse: $adresse,
            lecteur: $lecteur,
            systemes: $s,
            taille_max: 1 << 10,
            gzip: None,
            delai: 30,
        }
    };
}

/// La table : 15 fichiers sous Windows, 19 sous macOS (adresses finales, mesurées le 23 oct. 2026 : aucune
/// redirection, qu'un en-tête interdirait de suivre vers un autre hôte, voir `http::envoyer`). Le catalogue de la
/// CISA s'y ajoute, par `kev::catalogue`.
pub(crate) const SOURCES: &[Source] = &[
    Source {
        id: "mozilla",
        adresse: "https://product-details.mozilla.org/1.0/firefox_versions.json",
        lecteur: Lecteur::Firefox,
        systemes: WM,
        taille_max: 64 << 10,
        gzip: None,
        delai: 30,
    },
    chrome!("win", "stable", W),
    chrome!("win", "extended", W),
    chrome!("win64", "stable", W),
    chrome!("win64", "extended", W),
    chrome!("win_arm64", "stable", W),
    chrome!("win_arm64", "extended", W),
    chrome!("mac", "stable", M),
    chrome!("mac", "extended", M),
    chrome!("mac_arm64", "stable", M),
    chrome!("mac_arm64", "extended", M),
    Source {
        id: "edge",
        adresse: "https://edgeupdates.microsoft.com/api/products",
        lecteur: Lecteur::Edge,
        systemes: WM,
        taille_max: 1 << 20,
        gzip: None,
        delai: 30,
    },
    Source {
        id: "office",
        adresse: "https://clients.config.office.net/releases/v1.0/OfficeReleases",
        lecteur: Lecteur::Office,
        systemes: W,
        taille_max: 1 << 20,
        gzip: None,
        delai: 30,
    },
    mau!("MSWD2019"),
    mau!("XCEL2019"),
    mau!("PPT32019"),
    mau!("OPIM2019"),
    mau!("ONMC2019"),
    mau!("MSau04"),
    // Seul le chemin « mac/ » existe chez Adobe (« win/ » répond 404) ; la piste Continuous porte le même numéro.
    texte!(
        "adobe-reader",
        "https://armmf.adobe.com/arm-manifests/mac/AcrobatDC/reader/current_version.txt",
        Lecteur::Adobe,
        WM
    ),
    texte!(
        "adobe-acrobat",
        "https://armmf.adobe.com/arm-manifests/mac/AcrobatDC/acrobat/current_version.txt",
        Lecteur::Adobe,
        WM
    ),
    texte!(
        "brave-windows-x64",
        "https://versions.brave.com/latest/release-windows-x64.version",
        Lecteur::Brave,
        W
    ),
    texte!(
        "brave-windows-arm64",
        "https://versions.brave.com/latest/release-windows-arm64.version",
        Lecteur::Brave,
        W
    ),
    texte!(
        "brave-macos-arm64",
        "https://versions.brave.com/latest/release-macos-arm64.version",
        Lecteur::Brave,
        M
    ),
    texte!(
        "brave-macos-x64",
        "https://versions.brave.com/latest/release-macos-x64.version",
        Lecteur::Brave,
        M
    ),
    Source {
        id: "eol",
        adresse: "https://endoflife.date/api/v1/products/full",
        lecteur: Lecteur::Eol,
        systemes: WM,
        taille_max: 8 << 20,
        gzip: Some(16 << 20),
        delai: 30,
    },
    // L'archive entière du dépôt des avis (codeload, adresse finale de GitHub, sans redirection) : 600 Kio en gzip,
    // 5 Mio une fois décompressée le 23 oct. 2026.
    Source {
        id: "mfsa",
        adresse: "https://codeload.github.com/mozilla/foundation-security-advisories/tar.gz/main",
        lecteur: Lecteur::Mfsa,
        systemes: WM,
        taille_max: 8 << 20,
        gzip: Some(64 << 20),
        delai: 60,
    },
    // HTTPS seulement, sans vérifier la signature (cask.jws.json) : décision de l'auteur, pour ne pas prendre ring
    // en direct.
    Source {
        id: "cask",
        adresse: "https://formulae.brew.sh/api/cask.json",
        lecteur: Lecteur::Cask,
        systemes: M,
        taille_max: 40 << 20,
        gzip: Some(64 << 20),
        delai: 60,
    },
];

/// Les sources d'un système : ne dépend que de lui.
pub(crate) fn du_systeme(systeme: Systeme) -> impl Iterator<Item = &'static Source> {
    SOURCES.iter().filter(move |s| s.systemes.contains(&systeme))
}

/// Une source sert si un logiciel de la table s'en sert : les autres ne sont pas téléchargées (cask.json attend la
/// longue traîne de macOS ; le manifeste de Microsoft AutoUpdate lui-même n'est pas jugé). Ne dépend que des deux
/// tables fixes, jamais de ce qui est installé.
pub(crate) fn sert(source: &Source) -> bool {
    super::produits::FICHES.iter().any(|f| f.sources.contains(&source.id))
}

/// Pourquoi rien ne doit être téléchargé (tests, réglage coupé, travail sans Internet) ; `None` : permis.
pub(crate) fn coupure() -> Option<String> {
    if cfg!(test) {
        Some(tr!("tests : rien n'est téléchargé", "tests: nothing is downloaded").to_string())
    } else if !crate::parametres::versions_logiciels() {
        Some(
            tr!(
                "téléchargement coupé (Paramètres › Versions des logiciels)",
                "download turned off (Settings › Software versions)"
            )
            .to_string(),
        )
    } else if crate::parametres::hors_ligne() {
        Some(tr!("travail sans Internet", "working without the Internet").to_string())
    } else {
        None
    }
}

/// Une valeur JSON dont le type peut changer sans tout rendre illisible : gardée si elle a le type attendu, ignorée
/// sinon (un champ d'un autre produit qui change de forme ne fait pas tomber la lecture des autres).
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum Souple<T> {
    Bon(T),
    Autre(serde::de::IgnoredAny),
}

impl<T> Souple<T> {
    pub(crate) fn bon(self) -> Option<T> {
        match self {
            Souple::Bon(v) => Some(v),
            Souple::Autre(_) => None,
        }
    }
}

/// Une copie utilisable : son contenu (décompressé), son âge, et pourquoi elle n'a pas été rafraîchie quand elle
/// aurait dû l'être.
#[derive(Debug)]
pub(crate) struct Copie {
    pub octets: Vec<u8>,
    pub age: Duration,
    pub manque: Option<String>,
}

/// Ce que chaque source du système a donné : sa copie, ou pourquoi il n'y en a pas.
pub(crate) struct Releve {
    pub sources: Vec<(&'static Source, Result<Copie, String>)>,
}

impl Releve {
    /// La copie de la source `id` ; `Err` : pourquoi elle manque.
    pub(crate) fn copie(&self, id: &str) -> Result<&Copie, String> {
        match self.sources.iter().find(|(s, _)| s.id == id) {
            Some((_, Ok(c))) => Ok(c),
            Some((_, Err(raison))) => Err(raison.clone()),
            None => Err(tr!("source inconnue", "unknown source").to_string()),
        }
    }
}

/// Télécharger, ou seulement relire les copies gardées (avec la raison à dire quand une copie aurait dû être
/// rafraîchie).
enum Mode {
    Telecharger,
    CopieSeule(String),
}

/// Ce que chaque source de `systeme` donne : téléchargées en parallèle (une minute au pire), sauf si le réglage les
/// coupe, sans Internet, ou dans les tests ; les copies gardées servent alors seules.
pub(crate) fn rafraichir(systeme: Systeme) -> Releve {
    let mode = coupure().map_or(Mode::Telecharger, Mode::CopieSeule);
    let sources: Vec<&'static Source> = du_systeme(systeme).filter(|s| sert(s)).collect();
    let resultats = std::thread::scope(|portee| {
        let fils: Vec<_> = sources
            .iter()
            .map(|&s| {
                let mode = &mode;
                portee.spawn(move || obtenir(s, s.adresse, mode))
            })
            .collect();
        fils.into_iter()
            .map(|f| {
                f.join()
                    .unwrap_or_else(|_| Err(tr!("lecture interrompue", "reading interrupted").to_string()))
            })
            .collect::<Vec<_>>()
    });
    Releve {
        sources: sources.into_iter().zip(resultats).collect(),
    }
}

/// La copie d'une source, demandée à `adresse` (un serveur local dans les tests) quand il faut la rafraîchir.
fn obtenir(source: &Source, adresse: &str, mode: &Mode) -> Result<Copie, String> {
    let lieu = (SOUS_DOSSIER, source.id);
    let (brut, age, manque) = match mode {
        Mode::Telecharger => {
            let mut demande = crate::http::Demande {
                taille_max: source.taille_max,
                ..crate::http::Demande::get(adresse, Duration::from_secs(source.delai))
            };
            if source.gzip.is_some() {
                demande.entetes.push(("Accept-Encoding", "gzip".to_string()));
            }
            let liste =
                crate::protection::abuse_ch::liste_validee(demande, lieu, FRAICHE, &|o| contenu(source, o).is_some());
            let manque = liste.manque.map(raison);
            let (brut, age) = liste.resultat(false).map_err(raison)?;
            (brut, age, manque)
        }
        Mode::CopieSeule(pourquoi) => {
            let (brut, age) = gardee(lieu).ok_or_else(|| pourquoi.clone())?;
            let manque = (age >= FRAICHE).then(|| pourquoi.clone());
            (brut, age, manque)
        }
    };
    if age > DEPASSEE_MAX {
        return Err(trf!(
            "copie de {} jours, plus suivie",
            "{}-day-old copy, no longer followed",
            age.as_secs() / 86_400
        ));
    }
    let octets = contenu(source, &brut).ok_or_else(|| {
        tr!(
            "copie gardée illisible (format changé ?)",
            "kept copy unreadable (format changed?)"
        )
        .to_string()
    })?;
    Ok(Copie { octets, age, manque })
}

/// La copie gardée et son âge, sans rien demander.
fn gardee((sous_dossier, nom): (&str, &str)) -> Option<(Vec<u8>, Duration)> {
    let fichier = crate::reseau::dossier_local().join(sous_dossier).join(nom);
    let age = std::fs::metadata(&fichier)
        .and_then(|m| m.modified())
        .ok()?
        .elapsed()
        .unwrap_or_default();
    Some((std::fs::read(&fichier).ok()?, age))
}

/// Le contenu d'une réponse ou d'une copie, décompressé s'il le faut, et seulement s'il a la forme attendue.
fn contenu(source: &Source, brut: &[u8]) -> Option<Vec<u8>> {
    let octets = match source.gzip {
        Some(limite) if crate::archives::gzip::est_gzip(brut) => crate::archives::gzip::degzip_controle(brut, limite)?,
        _ => brut.to_vec(),
    };
    lisible(source.lecteur, &octets).then_some(octets)
}

/// Le fichier se lit-il comme son lecteur l'attend ?
fn lisible(lecteur: Lecteur, octets: &[u8]) -> bool {
    match lecteur {
        Lecteur::Firefox => editeurs::firefox(octets).is_some(),
        Lecteur::Chrome(plateforme, canal) => editeurs::chrome(octets, plateforme, canal).is_some(),
        Lecteur::Edge => editeurs::edge(octets).is_some(),
        Lecteur::Office => editeurs::office(octets).is_some(),
        Lecteur::Mau(id) => editeurs::mau(octets, id).is_some(),
        Lecteur::Adobe => editeurs::adobe(octets).is_some(),
        Lecteur::Brave => editeurs::brave(octets).is_some(),
        Lecteur::Eol => eol::lire(octets).is_some(),
        Lecteur::Cask => homebrew::casks(octets).is_some(),
        Lecteur::Mfsa => super::avis_de_l_archive(octets).is_some(),
    }
}

/// La raison d'une copie manquée, dite sans l'adresse.
fn raison(echec: crate::protection::abuse_ch::Echec) -> String {
    use crate::protection::abuse_ch::Echec;
    match echec {
        Echec::Reponse(code) => trf!("le serveur a répondu {code}", "the server answered {code}"),
        Echec::SansReponse => tr!("pas d'Internet ?", "no Internet?").to_string(),
        autre => autre.raison(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// Un serveur HTTP local qui répond `reponse` à une demande et rend les en-têtes reçus.
    fn serveur(reponse: Vec<u8>) -> (String, std::thread::JoinHandle<String>) {
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = format!("http://{}/api/products/full", ecoute.local_addr().unwrap());
        let fil = std::thread::spawn(move || {
            let (mut prise, _) = ecoute.accept().unwrap();
            prise.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut recu = vec![0u8; 65_536];
            let n = prise.read(&mut recu).unwrap_or(0);
            let _ = prise.write_all(&reponse);
            String::from_utf8_lossy(&recu[..n]).into_owned()
        });
        (adresse, fil)
    }

    fn reponse(corps: &[u8]) -> Vec<u8> {
        let mut r = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            corps.len()
        )
        .into_bytes();
        r.extend(corps);
        r
    }

    fn gzip(contenu: &[u8]) -> Vec<u8> {
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        gz.extend(miniz_oxide::deflate::compress_to_vec(contenu, 6));
        let crc = {
            // Le CRC du lecteur, recalculé ici par la définition (bit à bit) : les deux doivent s'accorder.
            let mut c = !0u32;
            for &o in contenu {
                c ^= u32::from(o);
                for _ in 0..8 {
                    c = if c & 1 == 1 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                }
            }
            !c
        };
        gz.extend(crc.to_le_bytes());
        gz.extend(u32::try_from(contenu.len()).unwrap().to_le_bytes());
        gz
    }

    /// Une source d'essai, pour la copie « essai-eol » (lecteur d'endoflife.date).
    const ESSAI: Source = Source {
        id: "essai-eol",
        adresse: "https://endoflife.date/api/v1/products/full",
        lecteur: Lecteur::Eol,
        systemes: WM,
        taille_max: 1 << 20,
        gzip: Some(1 << 20),
        delai: 5,
    };

    const EOL: &[u8] = include_bytes!("../../../../assets/essais/eol-extrait.json");

    /// La table : les mêmes fichiers pour tous les ordinateurs d'un système, en HTTPS, sans rien de variable dans
    /// l'adresse, jamais l'adresse d'un logiciel en particulier (cask par cask) ni winget.
    #[test]
    fn table_fermee_et_fixe() {
        let mut ids: Vec<&str> = SOURCES.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), SOURCES.len(), "identifiants en double");
        assert_eq!(du_systeme(Systeme::Windows).count(), 15);
        assert_eq!(du_systeme(Systeme::MacOs).count(), 19);
        // Toutes servent, sauf celles qu'aucun logiciel jugé n'utilise encore (Microsoft AutoUpdate lui-même, la
        // longue traîne de macOS par cask.json) : pas téléchargées pour rien.
        let inutiles: Vec<&str> = SOURCES.iter().filter(|s| !sert(s)).map(|s| s.id).collect();
        assert_eq!(inutiles, ["mau-MSau04", "cask"]);
        for s in SOURCES {
            assert!(s.adresse.starts_with("https://"), "{}", s.adresse);
            assert!(
                !s.adresse.contains('{') && !s.adresse.contains("api/cask/"),
                "{}",
                s.adresse
            );
            assert!(
                !s.adresse.contains("winget") && !s.adresse.contains("version="),
                "{}",
                s.adresse
            );
            assert!(!s.systemes.is_empty() && s.taille_max > 0 && (5..=60).contains(&s.delai));
            assert!(
                s.id.bytes()
                    .all(|o| o.is_ascii_alphanumeric() || o == b'-' || o == b'_'),
                "{}",
                s.id
            );
            if let Lecteur::Chrome(p, c) = s.lecteur {
                assert!(
                    s.adresse.contains(&format!("/platforms/{p}/channels/{c}/")),
                    "{}",
                    s.adresse
                );
            }
        }
        // Chaque plateforme de Chrome a ses deux canaux (sans extended, un Chrome d'entreprise serait dit dépassé).
        for p in ["win", "win64", "win_arm64", "mac", "mac_arm64"] {
            for c in ["stable", "extended"] {
                assert!(SOURCES.iter().any(|s| s.lecteur == Lecteur::Chrome(p, c)), "{p} {c}");
            }
        }
    }

    /// Téléchargée en gzip (l'en-tête est envoyé), gardée telle quelle, relue décompressée ; une page de portail ensuite
    /// ne chasse pas la bonne copie, et c'est dit.
    #[test]
    fn gzip_garde_et_portail_refuse() {
        let dossier = crate::reseau::dossier_local().join(SOUS_DOSSIER);
        let _ = std::fs::remove_file(dossier.join(ESSAI.id));
        let (adresse, fil) = serveur(reponse(&gzip(EOL)));
        let copie = obtenir(&ESSAI, &adresse, &Mode::Telecharger).unwrap();
        let recu = fil.join().unwrap().to_lowercase();
        assert!(recu.contains("accept-encoding: gzip"), "{recu}");
        assert!(recu.contains("user-agent: vanguard\r\n"), "{recu}");
        assert_eq!(copie.octets, EOL);
        assert!(copie.manque.is_none());
        assert!(crate::archives::gzip::est_gzip(
            &std::fs::read(dossier.join(ESSAI.id)).unwrap()
        ));
        // Une copie de moins d'un jour n'est pas redemandée : vieillie pour que la suite le soit.
        let vieillir = |jours: u64| {
            std::fs::File::options()
                .write(true)
                .open(dossier.join(ESSAI.id))
                .unwrap()
                .set_modified(std::time::SystemTime::now() - Duration::from_hours(24 * jours))
                .unwrap();
        };
        vieillir(2);
        // Une page de portail Wi-Fi : la copie d'avant sert, le manque est dit.
        let (adresse, fil) = serveur(reponse(b"<html>Connexion requise</html>"));
        let copie = obtenir(&ESSAI, &adresse, &Mode::Telecharger).unwrap();
        fil.join().unwrap();
        assert_eq!(copie.octets, EOL);
        assert!(
            copie
                .manque
                .is_some_and(|m| m.contains("portail") || m.contains("portal"))
        );
        // Un gzip coupé ou abîmé non plus.
        vieillir(2);
        let mut abime = gzip(EOL);
        let n = abime.len();
        abime[n - 6] ^= 0xff;
        let (adresse, fil) = serveur(reponse(&abime));
        let copie = obtenir(&ESSAI, &adresse, &Mode::Telecharger).unwrap();
        fil.join().unwrap();
        assert_eq!(copie.octets, EOL);
        assert!(copie.manque.is_some());
        // Sans téléchargement : la copie seule, et pourquoi elle n'est pas rafraîchie quand elle est vieille.
        vieillir(0);
        let copie = obtenir(&ESSAI, &adresse, &Mode::CopieSeule("coupé".into())).unwrap();
        assert_eq!((copie.octets.as_slice(), copie.manque), (EOL, None));
        vieillir(2);
        let copie = obtenir(&ESSAI, &adresse, &Mode::CopieSeule("coupé".into())).unwrap();
        assert_eq!(copie.manque.as_deref(), Some("coupé"));
        assert!(copie.age > A_JOUR_MAX / 2);
        // Plus de 30 jours : plus suivie.
        vieillir(31);
        let refus = obtenir(&ESSAI, &adresse, &Mode::CopieSeule("coupé".into())).unwrap_err();
        assert!(refus.contains("31"), "{refus}");
        std::fs::remove_file(dossier.join(ESSAI.id)).unwrap();
        // Aucune copie : la raison de la coupure.
        assert_eq!(
            obtenir(&ESSAI, &adresse, &Mode::CopieSeule("coupé".into())).unwrap_err(),
            "coupé"
        );
    }

    /// Sans copie et sans réponse : la raison, jamais une copie vide ; une réponse refusée sans copie d'avant dit la
    /// forme, pas le code.
    #[test]
    fn sans_copie_la_raison() {
        let source = Source {
            id: "essai-sans-copie",
            ..ESSAI
        };
        let _ = std::fs::remove_file(crate::reseau::dossier_local().join(SOUS_DOSSIER).join(source.id));
        let libre = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let adresse = format!("http://{libre}/full");
        assert_eq!(
            obtenir(&source, &adresse, &Mode::Telecharger).unwrap_err(),
            tr!("pas d'Internet ?", "no Internet?")
        );
        let (adresse, fil) = serveur(reponse(b"{\"total\": 3, \"result\": []}"));
        let refus = obtenir(&source, &adresse, &Mode::Telecharger).unwrap_err();
        fil.join().unwrap();
        assert!(refus.contains("portail") || refus.contains("portal"), "{refus}");
        let (adresse, fil) =
            serveur(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec());
        let refus = obtenir(&source, &adresse, &Mode::Telecharger).unwrap_err();
        fil.join().unwrap();
        assert!(refus.contains("503"), "{refus}");
    }

    /// Dans les tests, rien ne part : chaque source du système dit pourquoi elle n'a pas de copie.
    #[test]
    fn rien_ne_part_dans_les_tests() {
        // Sous Linux, aucun système suivi : le gestionnaire de paquets tient les versions.
        assert_eq!(Systeme::courant().is_none(), cfg!(target_os = "linux"));
        for systeme in [Systeme::Windows, Systeme::MacOs] {
            let releve = rafraichir(systeme);
            assert_eq!(releve.sources.len(), du_systeme(systeme).filter(|s| sert(s)).count());
            for (s, r) in &releve.sources {
                if let Err(raison) = r {
                    assert!(raison.contains("test"), "{} : {raison}", s.id);
                }
            }
            assert!(releve.copie("absente").is_err());
        }
    }
}
