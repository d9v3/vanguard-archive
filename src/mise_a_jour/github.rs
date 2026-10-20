//! Les versions publiées de Vanguard sur GitHub, pour se mettre à jour sans la clé. Les programmes signés sont
//! publiés à part du code (d9v3/vanguard-officiel), dans un dépôt qui ne contient qu'eux. Rien n'y est cru sur parole : la
//! dernière version est décrite par un manifeste (`derniere.txt` : la version, puis l'empreinte SHA-256 et la taille
//! du programme de chaque système), signé en Ed25519 sur l'ordinateur de l'auteur (`outils/signer-versions.sh`), dont
//! la clé publique est gravée ici. Un manifeste mal signé, une version qui n'est pas plus récente, un programme dont
//! la taille, l'empreinte ou la version gravée ne sont pas celles signées : refusés. Qui prendrait le compte GitHub
//! ne pourrait donc pas faire installer autre chose que ce que l'auteur a signé.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::{Mutex, Once, PoisonError};
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::{TAILLE_MAX, Version, lire_version};
use crate::ui::*;

/// Les fichiers de la dernière version publiée : le lien « latest » de GitHub suit toujours la plus récente.
const ADRESSE: &str = "https://github.com/d9v3/vanguard-officiel/releases/latest/download/";

/// La clé publique qui signe les manifestes ; la clé privée ne quitte pas l'ordinateur de l'auteur
/// (~/.config/vanguard-dev/versions-ed25519.pem, `outils/signer-versions.sh --cle` la redonne sous cette forme).
const CLE_PUBLIQUE: [u8; 32] = [
    186, 93, 90, 226, 248, 122, 48, 200, 24, 51, 85, 91, 90, 167, 134, 196, 11, 226, 137, 238, 52, 158, 117, 140, 106,
    87, 92, 183, 180, 7, 166, 124,
];

/// Ce qui précède le manifeste dans le message signé : une signature faite pour autre chose ne vaut pas ici.
const DOMAINE: &[u8] = b"vanguard-versions 1\n";

/// Au-delà, ce n'est pas un manifeste.
const MANIFESTE_MAX: u64 = 16 << 10;

/// Une réponse de GitHub gardée ce temps-là : l'annonce du menu ne le redemande pas à chaque lancement.
const FRAICHE: Duration = Duration::from_hours(12);

/// Le programme de ce système : son nom dans le manifeste, puis sur GitHub (ceux de `outils/publier-version.sh`).
const SYSTEME: Option<(&str, &str)> = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
    Some(("linux-x86_64", "vanguard-linux-x86_64"))
} else if cfg!(all(windows, target_arch = "x86_64")) {
    Some(("windows-x86_64", "vanguard-windows-x86_64.exe"))
} else if cfg!(target_os = "macos") {
    Some(("macos", "vanguard-macos"))
} else {
    None
};

/// La dernière version publiée pour ce système, d'après un manifeste dont la signature a été vérifiée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Publiee {
    pub version: Version,
    sha256: [u8; 32],
    taille: u64,
    fichier: &'static str,
}

/// Le manifeste : « version 0.79.0+1792540000 », puis une ligne par système, « linux-x86_64 <sha256> <taille> ». Le
/// moindre écart de forme le fait refuser.
fn lire_manifeste(texte: &str, systeme: &str) -> Option<(Version, [u8; 32], u64)> {
    let mut lignes = texte.lines();
    let version = lire_version(lignes.next()?.strip_prefix("version ")?)?;
    for ligne in lignes {
        let champs: Vec<&str> = ligne.split(' ').collect();
        let [nom, empreinte, taille] = champs[..] else {
            return None;
        };
        if nom == systeme {
            return Some((version, en_octets(empreinte)?, taille.parse().ok()?));
        }
    }
    None
}

/// 64 chiffres hexadécimaux en 32 octets.
fn en_octets(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut octets = [0u8; 32];
    for (i, o) in octets.iter_mut().enumerate() {
        *o = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(octets)
}

/// La signature est-elle celle de `cle` sur ce manifeste ? (vérification stricte : une signature trafiquée pour
/// passer chez certaines bibliothèques est refusée).
fn signature_valide(cle: &[u8; 32], manifeste: &[u8], signature: &[u8]) -> bool {
    let (Ok(cle), Ok(signature)) = (
        ed25519_dalek::VerifyingKey::from_bytes(cle),
        <[u8; 64]>::try_from(signature),
    ) else {
        return false;
    };
    let mut message = DOMAINE.to_vec();
    message.extend_from_slice(manifeste);
    cle.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&signature))
        .is_ok()
}

/// Le manifeste et sa signature, vérifiés : la version publiée pour `systeme`, ou pourquoi elle ne vaut rien.
fn juger(manifeste: &[u8], signature: &[u8], systeme: &str, fichier: &'static str) -> Result<Publiee, String> {
    if !signature_valide(&CLE_PUBLIQUE, manifeste, signature) {
        return Err(tr!(
            "manifeste de GitHub mal signé : rien n'est proposé",
            "badly signed GitHub manifest: nothing is offered"
        )
        .into());
    }
    let (version, sha256, taille) = std::str::from_utf8(manifeste)
        .ok()
        .and_then(|t| lire_manifeste(t, systeme))
        .ok_or_else(|| {
            tr!(
                "manifeste de GitHub illisible, ou sans version pour ce système",
                "unreadable GitHub manifest, or no version for this system"
            )
            .to_string()
        })?;
    if taille > TAILLE_MAX {
        return Err(tr!(
            "programme publié démesuré : refusé",
            "oversized published program: refused"
        )
        .into());
    }
    Ok(Publiee {
        version,
        sha256,
        taille,
        fichier,
    })
}

fn dossier() -> PathBuf {
    crate::reseau::dossier_local().join("versions")
}

/// Le dossier de Vanguard est-il sûr pour y écrire (le mémo de l'annonce, le programme provisoire à côté des cibles) ? Lancé en root avec le dossier d'un autre compte
/// (sudo qui garde HOME), ce compte pourrait y poser des liens et faire écrire root ailleurs : rien n'y est fait.
pub(super) fn dossier_sur() -> bool {
    #[cfg(unix)]
    {
        // SAFETY : geteuid n'a ni pointeur ni effet de bord.
        if unsafe { libc::geteuid() } != 0 {
            return true;
        }
        std::fs::symlink_metadata(crate::reseau::dossier_local())
            .is_ok_and(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0)
    }
    #[cfg(windows)]
    {
        true
    }
}

/// Un fichier de la dernière version, reçu en mémoire par le client HTTPS de Vanguard (`http`) : en HTTPS seulement,
/// redirections comprises ; le transfert est coupé au-delà de `max` octets ou de `secondes`. Rien ne passe par le
/// disque ni par un autre programme : ce qui est vérifié est ce qui s'installe. `None` : pas de réponse 200.
fn recevoir(nom: &str, max: u64, secondes: u64) -> Option<Vec<u8>> {
    let adresse = format!("{ADRESSE}{nom}");
    crate::http::envoyer(crate::http::Demande {
        adresse: &adresse,
        entetes: Vec::new(),
        corps: None,
        delai: Duration::from_secs(secondes),
        taille_max: max,
    })
    .filter(|r| r.code == 200)
    .map(|r| r.corps)
}

/// La dernière version publiée pour ce système, manifeste téléchargé et vérifié ; `Err` : pourquoi on ne sait pas.
pub(super) fn derniere() -> Result<Publiee, String> {
    let (systeme, fichier) = SYSTEME.ok_or_else(|| {
        tr!(
            "pas de version publiée pour ce système",
            "no published version for this system"
        )
        .to_string()
    })?;
    let pas_de_reponse = || {
        tr!(
            "pas de réponse (pas d'Internet, ou aucune version publiée pour tous)",
            "no answer (no Internet, or no version published for everyone)"
        )
        .to_string()
    };
    if std::env::var_os("VANGUARD_HORS_LIGNE").is_some() {
        return Err(pas_de_reponse());
    }
    let manifeste = recevoir("derniere.txt", MANIFESTE_MAX, 20).ok_or_else(pas_de_reponse)?;
    let signature = recevoir("derniere.txt.sig", 64, 20).ok_or_else(pas_de_reponse)?;
    juger(&manifeste, &signature, systeme, fichier)
}

/// Télécharge le programme de `p` et rend ses octets, seulement si leur taille et leur empreinte sont celles signées.
/// Ce sont ces octets-là, gardés en mémoire, qui s'installent (`installer`, qui vérifie encore la version gravée).
pub(super) fn programme_verifie(p: &Publiee) -> Result<Vec<u8>, String> {
    let Some(recus) = recevoir(p.fichier, p.taille, 900) else {
        return Err(tr!("téléchargement interrompu", "download interrupted").into());
    };
    if u64::try_from(recus.len()).ok() == Some(p.taille) && Sha256::digest(&recus)[..] == p.sha256 {
        return Ok(recus);
    }
    Err(tr!(
        "le programme téléchargé n'est pas celui que l'auteur a signé : rien n'est remplacé",
        "the downloaded program is not the one the author signed: nothing is replaced"
    )
    .into())
}

static ANNONCE: Mutex<Option<Version>> = Mutex::new(None);
static CHERCHEE: Once = Once::new();

/// La dernière version publiée, pour l'annonce du menu : cherchée en fond une fois par lancement (le menu ne
/// l'attend jamais, elle paraît à l'affichage suivant), et seulement dans un vrai terminal (ni scripts, ni tests).
/// La réponse est gardée 12 heures ; l'installation, elle, revérifie tout.
pub(super) fn annonce() -> Option<Version> {
    if cfg!(test) || !std::io::stdin().is_terminal() || SYSTEME.is_none() || !dossier_sur() {
        return None;
    }
    CHERCHEE.call_once(|| {
        std::thread::spawn(|| {
            let vue = derniere_vue();
            *ANNONCE.lock().unwrap_or_else(PoisonError::into_inner) = vue;
        });
    });
    *ANNONCE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// La version vue sur GitHub il y a moins de 12 heures, sinon redemandée.
fn derniere_vue() -> Option<Version> {
    let memoire = dossier().join("derniere-vue.txt");
    let fraiche = std::fs::metadata(&memoire)
        .and_then(|m| m.modified())
        .is_ok_and(|t| t.elapsed().unwrap_or_default() < FRAICHE);
    if fraiche
        && let Some(v) = std::fs::read_to_string(&memoire)
            .ok()
            .and_then(|t| lire_version(t.trim()))
    {
        return Some(v);
    }
    let v = derniere().ok()?.version;
    let _ = std::fs::create_dir_all(dossier());
    let _ = std::fs::write(&memoire, format!("{}.{}.{}+{}", v.0, v.1, v.2, v.3));
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn cle_d_essai() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
    }

    fn signer(cle: &ed25519_dalek::SigningKey, manifeste: &str) -> Vec<u8> {
        let mut message = DOMAINE.to_vec();
        message.extend_from_slice(manifeste.as_bytes());
        cle.sign(&message).to_bytes().to_vec()
    }

    const MANIFESTE: &str = "version 0.79.0+1792540000\n\
        linux-x86_64 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 26214400\n\
        windows-x86_64 ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100 27262976\n\
        macos 0000000000000000000000000000000000000000000000000000000000000001 30000000\n";

    #[test]
    fn manifeste_lu_ligne_par_ligne() {
        let (v, sha, taille) = lire_manifeste(MANIFESTE, "windows-x86_64").unwrap();
        assert_eq!(v, (0, 79, 0, 1_792_540_000));
        assert_eq!((sha[0], sha[31], taille), (0xff, 0x00, 27_262_976));
        assert!(lire_manifeste(MANIFESTE, "freebsd").is_none());
        // Le moindre écart de forme : refusé.
        assert!(lire_manifeste(&MANIFESTE.replace("version ", "version: "), "macos").is_none());
        assert!(lire_manifeste(&MANIFESTE.replace(" 30000000", " 3e7"), "macos").is_none());
        assert!(lire_manifeste(&MANIFESTE.replace("0001 ", "01 "), "macos").is_none());
        assert!(lire_manifeste(&MANIFESTE.replace(" 26214400", " 26214400 en-trop"), "macos").is_none());
    }

    #[test]
    fn seule_la_signature_de_l_auteur_compte() {
        let cle = cle_d_essai();
        let publique = cle.verifying_key().to_bytes();
        let signature = signer(&cle, MANIFESTE);
        assert!(signature_valide(&publique, MANIFESTE.as_bytes(), &signature));
        // Un octet changé dans le manifeste, la signature d'un autre, une signature tronquée : refusés.
        let trafique = MANIFESTE.replace("26214400", "26214401");
        assert!(!signature_valide(&publique, trafique.as_bytes(), &signature));
        let autre = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        assert!(!signature_valide(
            &publique,
            MANIFESTE.as_bytes(),
            &signer(&autre, MANIFESTE)
        ));
        assert!(!signature_valide(&publique, MANIFESTE.as_bytes(), &signature[..63]));
        // Signé sans le domaine (pour autre chose) : refusé.
        let sans_domaine = cle.sign(MANIFESTE.as_bytes()).to_bytes();
        assert!(!signature_valide(&publique, MANIFESTE.as_bytes(), &sans_domaine));
        // La clé gravée n'est pas celle d'essai : un manifeste signé par la clé d'essai ne passe pas `juger`.
        assert!(
            juger(
                MANIFESTE.as_bytes(),
                &signature,
                "linux-x86_64",
                "vanguard-linux-x86_64"
            )
            .is_err()
        );
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&CLE_PUBLIQUE).is_ok());
    }

    /// Un manifeste signé par openssl avec la vraie clé de l'auteur (outils/signer-versions.sh) passe la vérification
    /// de Vanguard : les deux parlent le même Ed25519, et la clé gravée est la bonne. Sa version (0.0.1) n'est jamais
    /// plus récente que la version en place : il ne peut rien faire installer.
    #[test]
    fn signature_d_openssl_acceptee() {
        let zeros = "0".repeat(64);
        let manifeste = format!("version 0.0.1+1\nlinux-x86_64 {zeros} 1\nwindows-x86_64 {zeros} 1\nmacos {zeros} 1\n");
        let hex = "1e18007252034d7adcedaa611ec81a32b58ab854730570bfc8f51c98802f946f\
                   78d20361922bdd46f827570670bf597d0e6b5f8a26472317d8e85cbdef20040a";
        let signature: Vec<u8> = [&hex[..64], &hex[64..]]
            .iter()
            .flat_map(|h| en_octets(h).unwrap())
            .collect();
        let p = juger(manifeste.as_bytes(), &signature, "macos", "vanguard-macos").unwrap();
        assert_eq!((p.version, p.taille, p.fichier), ((0, 0, 1, 1), 1, "vanguard-macos"));
        assert!(p.version < super::super::courante().unwrap());
        let mut abimee = signature.clone();
        abimee[10] ^= 1;
        assert!(juger(manifeste.as_bytes(), &abimee, "macos", "vanguard-macos").is_err());
    }

    #[test]
    fn empreintes_hexadecimales() {
        assert_eq!(en_octets(&"ab".repeat(32)), Some([0xab; 32]));
        assert!(en_octets(&"ab".repeat(31)).is_none());
        assert!(en_octets(&"zz".repeat(32)).is_none());
        assert!(en_octets(&format!("é{}", "a".repeat(62))).is_none());
    }
}
