//! Les fichiers de Vanguard : son dossier sur cet ordinateur, l'écriture qui ne laisse jamais un fichier à moitié
//! écrit, le verrou entre deux Vanguard lancés en même temps. Ils servaient d'abord à la base des appareils, d'où
//! leur ancienne place dans `reseau` ; le bilan, la protection et les traces s'en servent autant, sans rien avoir à
//! faire du réseau.

use std::path::PathBuf;

use crate::tre;

/// Écrit d'abord un fichier temporaire, le force sur le disque, puis le renomme à la place de l'ancien :
/// une coupure, un Ctrl-C ou une clé arrachée laissent soit l'ancienne base, soit la nouvelle, jamais une
/// base tronquée.
pub(crate) fn ecrire_atomique(chemin: &std::path::Path, contenu: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::io::Write;
    // Un nom par écriture, pas seulement par processus : deux fils qui écrivent le même fichier en même temps se
    // volaient leur fichier temporaire, et le second renommage échouait (vu dans les tests sous Wine).
    static ECRITURES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if let Some(d) = chemin.parent() {
        std::fs::create_dir_all(d)?;
    }
    let n = ECRITURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporaire = chemin.with_extension(format!("tmp-{}-{n}", std::process::id()));
    let resultat = (|| {
        let mut f = std::fs::File::create(&temporaire)?;
        f.write_all(contenu.as_ref())?;
        f.sync_all()?;
        remplacer(&temporaire, chemin)
    })();
    if resultat.is_err() {
        let _ = std::fs::remove_file(&temporaire);
    }
    resultat
}

/// Renomme `de` à la place de `vers`. Sous Windows, le remplacement échoue tant qu'un autre programme tient `vers`
/// ouvert : Defender qui analyse le fichier qu'on vient d'écrire, un autre fil qui le lit. Quelques essais
/// rapprochés (une demi-seconde au plus) plutôt qu'une écriture perdue.
fn remplacer(de: &std::path::Path, vers: &std::path::Path) -> std::io::Result<()> {
    let mut essais = 0;
    loop {
        match std::fs::rename(de, vers) {
            Err(_) if cfg!(windows) && essais < 10 => {
                essais += 1;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            r => return r,
        }
    }
}

/// Verrou entre processus Vanguard (fichier créé de façon exclusive, retiré à la fin).
pub(crate) struct Verrou(PathBuf);

impl Verrou {
    /// Le verrou `nom` dans `dossier` (un par fichier à protéger : le journal des alertes a le sien, pris pendant
    /// qu'un autre tient celui de la base). Attend au plus 10 s. Un verrou de plus de 2 minutes vient d'un Vanguard
    /// interrompu : on le reprend.
    pub(crate) fn prendre_nomme(dossier: &std::path::Path, nom: &str) -> Option<Verrou> {
        let _ = std::fs::create_dir_all(dossier);
        let chemin = dossier.join(nom);
        let fin = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&chemin) {
                Ok(_) => return Some(Verrou(chemin)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let ancien = std::fs::metadata(&chemin)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > std::time::Duration::from_secs(120));
                    if ancien {
                        let _ = std::fs::remove_file(&chemin);
                    } else if std::time::Instant::now() > fin {
                        tre!(
                            "Attention : « {nom} » occupé par un autre Vanguard, écriture sans verrou.",
                            "Warning: “{nom}” locked by another Vanguard, writing without a lock."
                        );
                        return None;
                    } else {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

impl Drop for Verrou {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Données propres à cet ordinateur (quarantaine antivirus : on ne transporte pas de malware sur une clé).
pub fn dossier_local() -> PathBuf {
    // Tests automatiques : un dossier jetable. Ils tournent sur l'ordinateur de développement : ses vraies données ne
    // doivent être ni lues ni écrites.
    if cfg!(test) {
        return dossier_des_tests();
    }
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = super::personnel::dossier_personnel().map(|h| h.join("Library/Application Support"));
    #[cfg(target_os = "linux")]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| super::personnel::dossier_personnel().map(|h| h.join(".local/share")));
    base.unwrap_or_default().join("vanguard")
}

/// Le dossier local réservé à son compte (0700) : il garde les bilans (donc les failles trouvées sur cet ordinateur),
/// les appareils du réseau, la quarantaine et la référence des fichiers critiques. Créé avec les droits par défaut
/// (0755), il se lisait par les autres comptes de la machine dès que le dossier personnel leur était ouvert. Un dossier
/// déjà là n'est resserré que s'il est vraiment un dossier à soi : jamais un lien, ni le dossier d'un autre compte.
#[cfg(unix)]
pub fn proteger_dossier_local() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let dossier = dossier_local();
    let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dossier);
    // SAFETY : getuid lit le compte du processus, sans argument ni échec possible.
    let moi = unsafe { libc::getuid() };
    if let Ok(m) = std::fs::symlink_metadata(&dossier)
        && m.is_dir()
        && m.uid() == moi
        && m.mode() & 0o077 != 0
    {
        let _ = std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o700));
    }
}

/// Le dossier jetable des tests de ce processus (un par `cargo test`, nommé par son numéro de processus), retiré
/// quand le processus se termine : chaque lancement en laissait un dans le dossier temporaire. Le crochet de sortie
/// est posé une fois, au premier appel ; les tests tournent tous avant que le processus ne sorte.
fn dossier_des_tests() -> PathBuf {
    let dossier = std::env::temp_dir().join(format!("vanguard-tests-{}", std::process::id()));
    #[cfg(test)]
    {
        static CROCHET: std::sync::Once = std::sync::Once::new();
        CROCHET.call_once(|| {
            unsafe extern "C" {
                fn atexit(f: extern "C" fn()) -> i32;
            }
            extern "C" fn retirer() {
                let _ = std::fs::remove_dir_all(
                    std::env::temp_dir().join(format!("vanguard-tests-{}", std::process::id())),
                );
            }
            // SAFETY : atexit de la bibliothèque C, présent sous Linux, Windows (msvcrt) et macOS ; il reçoit une
            // fonction sans argument qui vit tout le programme, appelée une fois à la sortie normale du processus.
            unsafe { atexit(retirer) };
        });
    }
    dossier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn dossier_local_reserve_au_compte() {
        use std::os::unix::fs::PermissionsExt;
        let dossier = dossier_local();
        std::fs::create_dir_all(&dossier).unwrap();
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o755)).unwrap();
        proteger_dossier_local();
        assert_eq!(std::fs::metadata(&dossier).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn ecriture_atomique_et_verrou() {
        let dossier = std::env::temp_dir().join(format!("vanguard-atomique-{}", std::process::id()));
        let fichier = dossier.join("appareils.json");
        ecrire_atomique(&fichier, "{\"reseaux\":{}}").unwrap();
        ecrire_atomique(&fichier, "{\"reseaux\":{\"box\":{}}}").unwrap();
        assert_eq!(std::fs::read_to_string(&fichier).unwrap(), "{\"reseaux\":{\"box\":{}}}");
        // Aucun fichier temporaire ne traîne.
        assert_eq!(std::fs::read_dir(&dossier).unwrap().count(), 1);
        // Le verrou est exclusif tant qu'il est gardé, et libéré à la fin.
        let v = Verrou::prendre_nomme(&dossier, "appareils.verrou").unwrap();
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&v.0)
                .is_err()
        );
        let chemin = v.0.clone();
        drop(v);
        assert!(!chemin.exists());
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// Une écriture qui échoue (le dossier parent est un fichier) ne laisse aucun fichier provisoire derrière elle.
    #[test]
    fn ecriture_ratee_sans_reste() {
        let dossier = std::env::temp_dir().join(format!("vanguard-atomique-rate-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let bouchon = dossier.join("bouchon");
        std::fs::write(&bouchon, b"x").unwrap();
        assert!(ecrire_atomique(&bouchon.join("liste.json"), b"[]").is_err());
        assert_eq!(std::fs::read_dir(&dossier).unwrap().count(), 1);
        std::fs::remove_dir_all(&dossier).unwrap();
    }
}
