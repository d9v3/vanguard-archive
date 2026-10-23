//! Les versions publiées de Vanguard sur GitHub, pour se mettre à jour sans la clé. Les programmes signés sont
//! publiés à part du code (d9v3/vanguard-update), dans un dépôt qui ne contient qu'eux. Rien n'y est cru sur parole : la
//! dernière version est décrite par un manifeste (`derniere.txt` : la version, puis l'empreinte SHA-256 et la taille
//! du programme de chaque système), signé en Ed25519 sur l'ordinateur de l'auteur (`outils/signer-versions.sh`), dont
//! la clé publique est gravée ici. Un manifeste mal signé, une version qui n'est pas plus récente, un programme dont
//! la taille, l'empreinte ou la version gravée ne sont pas celles signées : refusés. Qui prendrait le compte GitHub
//! ne pourrait donc pas faire installer autre chose que ce que l'auteur a signé.
//!
//! Une clé de secours, gardée hors ligne par l'auteur, signe aussi : la clé principale perdue ou volée, les versions
//! suivantes passent par elle sans que les ordinateurs déjà installés perdent la mise à jour. Les anciens manifestes
//! signés restent publics : quelqu'un qui tient le dépôt des versions pourrait en remettre un pour geler les mises à
//! jour. Vanguard retient donc la plus haute version signée déjà vue et refuse tout manifeste plus vieux ; et une
//! dernière version signée de plus de 45 jours n'est plus dite « à jour », mais non vérifiée.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::{Mutex, Once, PoisonError};
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::{TAILLE_MAX, Version, ecrire, lire_version};
use crate::ui::*;

/// Les fichiers de la dernière version publiée : le lien « latest » de GitHub suit toujours la plus récente.
const ADRESSE: &str = "https://github.com/d9v3/vanguard-update/releases/latest/download/";

/// La clé publique qui signe les manifestes ; la clé privée ne quitte pas l'ordinateur de l'auteur
/// (~/.config/vanguard-dev/versions-ed25519.pem, `outils/signer-versions.sh --cle` la redonne sous cette forme).
const CLE_PUBLIQUE: [u8; 32] = [
    186, 93, 90, 226, 248, 122, 48, 200, 24, 51, 85, 91, 90, 167, 134, 196, 11, 226, 137, 238, 52, 158, 117, 140, 106,
    87, 92, 183, 180, 7, 166, 124,
];

/// La clé de secours (~/.config/vanguard-dev/versions-secours-ed25519.pem, à garder hors ligne ;
/// `outils/signer-versions.sh --cle --secours`). Même domaine, même manifeste : elle signe à la place de la principale.
/// Les copies d'avant elle (0.85 et plus anciennes) ne la connaissent pas : tant qu'il en reste, la principale signe.
const CLE_SECOURS: [u8; 32] = [
    253, 121, 8, 156, 255, 154, 64, 102, 35, 79, 86, 44, 208, 155, 54, 97, 17, 83, 70, 26, 59, 253, 145, 101, 131, 85,
    241, 233, 76, 241, 32, 178,
];

/// Les clés dont la signature est acceptée.
const CLES: [[u8; 32]; 2] = [CLE_PUBLIQUE, CLE_SECOURS];

/// Au-delà, la dernière version signée (la date de son commit) n'est plus crue la dernière : l'auteur publie bien plus
/// souvent, un manifeste aussi vieux est plus probablement un ancien remis en place qu'une absence.
pub(super) const FRAICHEUR_JOURS: u64 = 45;

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
    juger_avec(&CLES, manifeste, signature, systeme, fichier)
}

/// `juger` avec ces clés-là (les tests y passent des clés d'essai).
fn juger_avec(
    cles: &[[u8; 32]],
    manifeste: &[u8],
    signature: &[u8],
    systeme: &str,
    fichier: &'static str,
) -> Result<Publiee, String> {
    if !cles.iter().any(|c| signature_valide(c, manifeste, signature)) {
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
    crate::socle::dossier_local().join("versions")
}

/// L'âge en jours de la version signée `v`, d'après la date de son commit gravée avec elle ; `None` sans date, ou
/// quand l'horloge d'ici est en retard sur ce commit (pile du BIOS à plat, machine virtuelle restaurée) : l'âge est
/// alors inconnu, jamais « 0 jour », sinon un manifeste de n'importe quel âge paraîtrait frais. Un jour de tolérance
/// couvre le petit décalage d'une horloge juste après une publication.
pub(super) fn age_jours(v: Version, maintenant: u64) -> Option<u64> {
    (v.3 > 0 && v.3 <= maintenant.saturating_add(86_400)).then(|| maintenant.saturating_sub(v.3) / 86_400)
}

/// La plus haute version signée déjà vue ici. `Err` : l'état a été changé hors de Vanguard (`sceau`) ou ne se lit
/// pas ; il ne peut alors ni protéger d'un vieux manifeste, ni être refait en silence.
fn plus_haute_vue() -> Result<Option<Version>, String> {
    version_vue(crate::sceau::lire(crate::sceau::VERSIONS))
}

/// La plus haute version déjà vue, d'après ce que les sceaux en disent.
fn version_vue(lu: crate::sceau::Lecture) -> Result<Option<Version>, String> {
    use crate::sceau::Lecture;
    match lu {
        Lecture::Absent => Ok(None),
        Lecture::Intact(o) => Ok(std::str::from_utf8(&o).ok().and_then(|t| lire_version(t.trim()))),
        // Adoptées sans sceau d'avant : un plancher baissé juste avant que `sceaux.json` soit effacé ne doit pas
        // laisser passer un vieux manifeste en silence.
        Lecture::Adopte(_) => Err(tr!(
            "les versions déjà vues ont été acceptées telles quelles, sans sceau d'avant : rien n'est cru",
            "the versions already seen were accepted as they were, without an earlier seal: nothing is trusted"
        )
        .into()),
        Lecture::Falsifie(_) => Err(tr!(
            "les versions déjà vues ont été changées hors de Vanguard : rien n'est cru",
            "the versions already seen were changed outside Vanguard: nothing is trusted"
        )
        .into()),
        Lecture::Illisible(e) => Err(e),
    }
}

/// Les versions déjà vues ont-elles été changées hors de Vanguard ? (`depuis_github` le dit et demande avant de
/// repartir du manifeste reçu.)
pub(super) fn versions_vues_douteuses() -> bool {
    plus_haute_vue().is_err()
}

/// Repartir de zéro, sur accord (`depuis_github`) : la prochaine version signée reçue devient la plus haute vue.
pub(super) fn oublier_versions_vues() -> std::io::Result<()> {
    crate::sceau::effacer(crate::sceau::VERSIONS)
}

/// Le manifeste reçu, comparé à la plus haute version signée déjà vue : refusé s'il est plus vieux (un ancien remis
/// en place pour geler les mises à jour) ; `Ok(true)` s'il est plus récent, à retenir.
fn comparer_a_la_vue(vue: Option<Version>, recue: Version) -> Result<bool, String> {
    match vue {
        Some(v) if recue < v => Err(trf!(
            "manifeste plus vieux que celui déjà vu : refusé ({} reçu, {} déjà vu)",
            "manifest older than the one already seen: refused ({} received, {} already seen)",
            ecrire(recue),
            ecrire(v)
        )),
        Some(v) => Ok(recue > v),
        None => Ok(true),
    }
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
        std::fs::symlink_metadata(crate::socle::dossier_local())
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
        meme_hote: false,
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
    if crate::parametres::hors_ligne() {
        return Err(pas_de_reponse());
    }
    let vue = plus_haute_vue()?;
    let manifeste = recevoir("derniere.txt", MANIFESTE_MAX, 20).ok_or_else(pas_de_reponse)?;
    let signature = recevoir("derniere.txt.sig", 64, 20).ok_or_else(pas_de_reponse)?;
    let publiee = juger(&manifeste, &signature, systeme, fichier)?;
    // Retenue seulement une fois la signature vérifiée : un manifeste quelconque ne fait pas monter la barre.
    if comparer_a_la_vue(vue, publiee.version)? {
        let v = publiee.version;
        let _ = crate::sceau::ecrire(crate::sceau::VERSIONS, format!("{}.{}.{}+{}", v.0, v.1, v.2, v.3));
    }
    Ok(publiee)
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

    /// La principale ou la clé de secours, oui ; une troisième, non. Avec des clés d'essai dans les deux places, puis
    /// avec la vraie clé de secours gravée (signature faite par openssl, comme `signer-versions.sh --secours`).
    #[test]
    fn principale_ou_secours_seulement() {
        let principale = cle_d_essai();
        let secours = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let autre = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let cles = [
            principale.verifying_key().to_bytes(),
            secours.verifying_key().to_bytes(),
        ];
        let essai = |cle: &ed25519_dalek::SigningKey| {
            juger_avec(
                &cles,
                MANIFESTE.as_bytes(),
                &signer(cle, MANIFESTE),
                "linux-x86_64",
                "vanguard-linux-x86_64",
            )
        };
        assert_eq!(essai(&principale).unwrap().version, (0, 79, 0, 1_792_540_000));
        assert_eq!(essai(&secours).unwrap().version, (0, 79, 0, 1_792_540_000));
        assert!(essai(&autre).is_err());

        let zeros = "0".repeat(64);
        let manifeste = format!("version 0.0.1+1\nlinux-x86_64 {zeros} 1\nwindows-x86_64 {zeros} 1\nmacos {zeros} 1\n");
        let hex = "9682e180f3fee9b88fc4e6f927fe06532eccc7c37de002d57ca9d6e6a3d64dae\
                   7e05d0a0381f1fcd259056cd9f0e1be294e258e1e75b1d23c15bb71be9001506";
        let signature: Vec<u8> = [&hex[..64], &hex[64..]]
            .iter()
            .flat_map(|h| en_octets(h).unwrap())
            .collect();
        assert!(signature_valide(&CLE_SECOURS, manifeste.as_bytes(), &signature));
        assert!(!signature_valide(&CLE_PUBLIQUE, manifeste.as_bytes(), &signature));
        let p = juger(
            manifeste.as_bytes(),
            &signature,
            "linux-x86_64",
            "vanguard-linux-x86_64",
        )
        .unwrap();
        assert_eq!(p.version, (0, 0, 1, 1));
        assert_ne!(CLE_PUBLIQUE, CLE_SECOURS);
    }

    /// Un ancien manifeste signé remis en place est refusé dès qu'un plus récent a été vu ici ; le même, ou un plus
    /// récent, passe (et seul le plus récent fait monter la barre).
    #[test]
    fn vieux_manifeste_refuse() {
        let vue = Some((0, 85, 0, 1_792_540_000));
        assert_eq!(comparer_a_la_vue(None, (0, 84, 0, 1)), Ok(true));
        assert_eq!(comparer_a_la_vue(vue, (0, 85, 0, 1_792_540_000)), Ok(false));
        assert_eq!(comparer_a_la_vue(vue, (0, 86, 0, 1_792_600_000)), Ok(true));
        let refus = comparer_a_la_vue(vue, (0, 84, 0, 1_792_000_000)).unwrap_err();
        assert!(refus.contains("0.84.0") && refus.contains("0.85.0"), "{refus}");
        // Même numéro, commit plus ancien : plus vieux aussi.
        assert!(comparer_a_la_vue(vue, (0, 85, 0, 1_792_539_999)).is_err());
    }

    /// L'état « déjà vu » est scellé : réécrit hors de Vanguard (pour abaisser la barre), il ne protège plus et le
    /// dit, au lieu de laisser passer un vieux manifeste.
    #[test]
    fn versions_vues_changees_a_cote() {
        crate::sceau::ecrire(crate::sceau::VERSIONS, "0.85.0+1792540000").unwrap();
        assert_eq!(plus_haute_vue(), Ok(Some((0, 85, 0, 1_792_540_000))));
        std::fs::write(crate::socle::dossier_local().join(crate::sceau::VERSIONS), "0.1.0+1").unwrap();
        assert!(plus_haute_vue().is_err() && versions_vues_douteuses());
        oublier_versions_vues().unwrap();
        assert_eq!(plus_haute_vue(), Ok(None));
        // Abaissée puis acceptée telle quelle, les sceaux effacés : pas un plancher, c'est dit.
        let lu = crate::sceau::Lecture::Adopte(b"0.1.0+1".to_vec());
        assert!(version_vue(lu).is_err());
    }

    #[test]
    fn age_de_la_derniere_version_signee() {
        let jour = 86_400;
        assert_eq!(
            age_jours((0, 85, 0, 1_792_540_000), 1_792_540_000 + 46 * jour),
            Some(46)
        );
        assert_eq!(age_jours((0, 85, 0, 1_792_540_000), 1_792_540_000 + jour - 1), Some(0));
        // Horloge très en retard : âge inconnu, jamais « frais ».
        assert_eq!(age_jours((0, 85, 0, 1_792_540_000), 1_000), None);
        // Une heure de décalage juste après la publication : dans la tolérance.
        assert_eq!(age_jours((0, 85, 0, 1_792_540_000), 1_792_540_000 - 3_600), Some(0));
        assert_eq!(age_jours((0, 85, 0, 0), 1_792_540_000), None);
    }

    /// Les Vanguard 0.85 déjà installés lisent le manifeste avec leur propre lecteur, recopié ici tel quel depuis
    /// l'étiquette v0.85.0 : le manifeste que signe `signer-versions.sh` aujourd'hui (même forme, clé principale) doit
    /// leur donner la même version, la même empreinte et la même taille qu'au lecteur d'aujourd'hui.
    #[test]
    fn le_lecteur_de_la_0_85_lit_le_manifeste_d_aujourd_hui() {
        fn lire_manifeste_0_85(texte: &str, systeme: &str) -> Option<(Version, [u8; 32], u64)> {
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
        // La forme exacte qu'écrit signer-versions.sh : « version X », puis les trois systèmes dans cet ordre.
        let (a, b, c) = ("ab".repeat(32), "cd".repeat(32), "ef".repeat(32));
        let manifeste = format!(
            "version 0.86.0+1792600000\nlinux-x86_64 {a} 26214400\nwindows-x86_64 {b} 27262976\nmacos {c} 30000000\n"
        );
        for systeme in ["linux-x86_64", "windows-x86_64", "macos"] {
            let ancien = lire_manifeste_0_85(&manifeste, systeme);
            assert!(ancien.is_some(), "{systeme}");
            assert_eq!(ancien, lire_manifeste(&manifeste, systeme), "{systeme}");
        }
        assert_eq!(
            lire_manifeste_0_85(MANIFESTE, "macos"),
            lire_manifeste(MANIFESTE, "macos")
        );
        // Le message signé garde le domaine de la 0.85 : sa vérification (clé principale) reste la même.
        assert_eq!(DOMAINE, b"vanguard-versions 1\n");
    }

    #[test]
    fn empreintes_hexadecimales() {
        assert_eq!(en_octets(&"ab".repeat(32)), Some([0xab; 32]));
        assert!(en_octets(&"ab".repeat(31)).is_none());
        assert!(en_octets(&"zz".repeat(32)).is_none());
        assert!(en_octets(&format!("é{}", "a".repeat(62))).is_none());
    }
}
