//! Mettre Vanguard à jour sur cet ordinateur. La copie que la surveillance, l'entretien et le raccourci y lancent
//! (`reseau::surveillance::executable`) ne suit pas la clé, qui, elle, se met à jour chez son propriétaire. Quand la
//! clé est plus récente que cette copie, le menu le dit, et la mise à jour se fait sur accord : le programme de la clé
//! est copié à côté, relu et comparé, puis mis en place d'un coup. Jamais vers une version plus ancienne. La version
//! d'une copie se lit dans son fichier, sans la lancer : une vieille copie ne refait pas ses étapes de démarrage
//! (protection de la clé, passage à un nouveau nom). La clé est la seule source : le dépôt est privé, et les pages de
//! version de GitHub ne se lisent pas sans compte.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::ui::*;

/// La version de ce programme, gravée dans son fichier pour qu'une autre copie la lise sans le lancer. `courante` la
/// lit là : sans lecture, l'éditeur de liens retirerait ce texte du programme publié.
static VERSION_GRAVEE: &str = concat!("VANGUARD-VERSION:", env!("CARGO_PKG_VERSION"), ";");

/// Ce qui précède la version gravée, écrit décalé d'un cran (« W » pour « V ») : en clair, ce texte paraîtrait une
/// seconde fois dans le programme, suivi de ce que l'éditeur de liens met après lui (« 0.78.0 » d'un autre texte,
/// par exemple), et la recherche pourrait y lire une fausse version. Ainsi, seule la version gravée le porte.
const ENTETE_DECALE: [u8; 17] = *b"WBOHVBSE.WFSTJPO;";

/// L'en-tête en clair, refait au lancement (`black_box` : le compilateur ne le calcule pas d'avance, ce qui l'écrirait
/// en clair dans le programme).
fn entete() -> [u8; 17] {
    std::hint::black_box(ENTETE_DECALE).map(|o| o - 1)
}

/// Le dossier du programme sur la clé, et son nom.
#[cfg(target_os = "linux")]
const DOSSIER_SUR_LA_CLE: &str = "Linux";
#[cfg(windows)]
const DOSSIER_SUR_LA_CLE: &str = "Windows";
#[cfg(target_os = "macos")]
const DOSSIER_SUR_LA_CLE: &str = "macOS";
const NOM: &str = if cfg!(windows) { "vanguard.exe" } else { "vanguard" };

/// Une version : majeure, mineure, correctif.
type Version = (u32, u32, u32);

fn lire_version(texte: &str) -> Option<Version> {
    let mut morceaux = texte.split('.').map(|m| m.parse::<u32>().ok());
    let version = (morceaux.next()??, morceaux.next()??, morceaux.next()??);
    morceaux.next().is_none().then_some(version)
}

fn ecrire(v: Version) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

/// La version de ce programme, lue dans sa version gravée (`black_box` : le compilateur ne la remplace pas par sa
/// valeur, le texte reste dans le fichier).
fn courante() -> Version {
    version_gravee(std::hint::black_box(VERSION_GRAVEE).as_bytes()).unwrap_or_default()
}

/// La version gravée dans le contenu d'un programme : `None` quand il n'en a pas (une copie d'avant la 0.78, donc
/// plus ancienne que toute copie qui en a une). Seule une occurrence suivie d'une version et d'un « ; » compte.
fn version_gravee(octets: &[u8]) -> Option<Version> {
    let entete = entete();
    let mut debut = 0;
    while let Some(i) = octets[debut..].windows(entete.len()).position(|f| f == entete) {
        let apres = debut + i + entete.len();
        let suite = &octets[apres..octets.len().min(apres + 32)];
        if let Some(fin) = suite.iter().position(|&o| o == b';')
            && let Some(v) = std::str::from_utf8(&suite[..fin]).ok().and_then(lire_version)
        {
            return Some(v);
        }
        debut = apres;
    }
    None
}

/// Où en est la copie de cet ordinateur.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Etat {
    /// Rien à dire : Vanguard ne tourne ni depuis la clé ni depuis sa copie, ou cette copie n'existe pas.
    Rien,
    /// Lancé depuis la copie de cet ordinateur, sans clé branchée : pas de quoi la mettre à jour.
    SansCle,
    /// La copie est à jour (même version que la clé).
    AJour(Version),
    /// La copie est plus récente que la clé : la clé est à remettre à jour chez son propriétaire.
    ClePlusAncienne { copie: Version, cle: Version },
    /// La clé est plus récente : la copie peut être remplacée par `source`.
    AMettreAJour {
        source: PathBuf,
        copie: Option<Version>,
        cle: Version,
    },
}

/// Ce qu'on lit d'un programme sur le disque.
#[derive(Debug, PartialEq, Eq)]
enum Lu {
    Illisible,
    /// Sans version gravée : d'avant la 0.78.
    Ancien,
    Version(Version),
}

fn lire_programme(chemin: &Path) -> Lu {
    match std::fs::read(chemin) {
        Err(_) => Lu::Illisible,
        Ok(octets) => version_gravee(&octets).map_or(Lu::Ancien, Lu::Version),
    }
}

/// Compare la copie de cet ordinateur et le programme de la clé. `copie` : sa version (`None` : d'avant la 0.78).
fn comparer(copie: Option<Version>, cle: Version, source: PathBuf) -> Etat {
    match copie {
        Some(c) if c == cle => Etat::AJour(c),
        Some(c) if c > cle => Etat::ClePlusAncienne { copie: c, cle },
        _ => Etat::AMettreAJour { source, copie, cle },
    }
}

/// L'état, d'après le programme lancé (`exe`), la clé d'où il tourne (`cle_du_programme`), la copie de cet
/// ordinateur et, quand c'est elle qui tourne, la clé branchée (`cle_branchee`, cherchée seulement alors : parcourir
/// les lecteurs peut faire attendre).
fn etat_de(
    exe: &Path,
    cle_du_programme: Option<&Path>,
    copie: &Path,
    cle_branchee: impl FnOnce() -> Option<PathBuf>,
) -> Etat {
    if !copie.is_file() {
        return Etat::Rien;
    }
    // Lancé depuis la clé : ce programme est la version de la clé.
    if cle_du_programme.is_some_and(|c| exe.starts_with(c)) {
        return match lire_programme(copie) {
            Lu::Illisible => Etat::Rien,
            Lu::Ancien => comparer(None, courante(), exe.to_path_buf()),
            Lu::Version(v) => comparer(Some(v), courante(), exe.to_path_buf()),
        };
    }
    let meme = |a: &Path, b: &Path| match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !meme(exe, copie) {
        return Etat::Rien;
    }
    // Lancé depuis la copie : la clé branchée dit s'il y a mieux.
    let Some(cle) = cle_branchee() else {
        return Etat::SansCle;
    };
    let source = cle.join(DOSSIER_SUR_LA_CLE).join(NOM);
    match lire_programme(&source) {
        Lu::Version(v) => comparer(Some(courante()), v, source),
        // Le programme de la clé d'avant la 0.78, ou illisible : jamais plus récent que celui-ci.
        Lu::Ancien | Lu::Illisible => Etat::AJour(courante()),
    }
}

/// La copie de cet ordinateur (celle de `reseau::surveillance::executable`).
fn copie_de_cet_ordinateur() -> PathBuf {
    crate::reseau::dossier_local().join("bin").join(NOM)
}

fn programme() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        crate::protection::cle::exe_d_origine()
    }
    #[cfg(windows)]
    {
        std::env::current_exe().ok().and_then(|e| e.canonicalize().ok())
    }
}

/// L'état, cherché une fois par session : le menu le demande à chaque affichage, et lire le programme de la clé prend
/// un moment. Oublié après une mise à jour.
static ETAT: Mutex<Option<Etat>> = Mutex::new(None);

fn etat() -> Etat {
    let mut garde = ETAT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    garde
        .get_or_insert_with(|| {
            // Jamais pendant les tests : la vraie copie et la vraie clé peuvent être là.
            if cfg!(test) {
                return Etat::Rien;
            }
            programme().map_or(Etat::Rien, |exe| {
                etat_de(
                    &exe,
                    crate::reseau::cle_du_programme().as_deref(),
                    &copie_de_cet_ordinateur(),
                    crate::reseau::cle_usb,
                )
            })
        })
        .clone()
}

/// La copie, avant la 0.78, n'avait pas de version lisible.
fn version_affichee(v: Option<Version>) -> String {
    v.map_or_else(|| tr!("d'avant la 0.78", "older than 0.78").to_string(), ecrire)
}

/// La ligne du menu quand la clé est plus récente que la copie de cet ordinateur, sinon rien. `touche` : l'entrée du
/// menu qui la met à jour (« 9.9 »).
pub fn avertissement(touche: &str) -> Option<String> {
    match etat() {
        Etat::AMettreAJour { cle, .. } => Some(trf!(
            "Nouvelle version sur la clé ({}) : {touche} met à jour cet ordinateur.",
            "New version on the key ({}): {touche} updates this computer.",
            ecrire(cle)
        )),
        _ => None,
    }
}

/// Copie `source` à la place de `cible` : à côté d'abord, relue et comparée, puis renommée d'un coup ; une copie
/// interrompue ou abîmée ne remplace jamais celle qui marche.
fn remplacer(source: &Path, cible: &Path) -> Result<(), String> {
    let octets = std::fs::read(source).map_err(|e| e.to_string())?;
    let provisoire = cible.with_file_name(format!("{NOM}.nouveau"));
    std::fs::write(&provisoire, &octets).map_err(|e| e.to_string())?;
    if std::fs::read(&provisoire).ok().as_deref() != Some(&octets[..]) {
        let _ = std::fs::remove_file(&provisoire);
        return Err(tr!("la copie relue ne correspond pas", "the copy read back does not match").into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&provisoire, std::fs::Permissions::from_mode(0o755));
    }
    mettre_en_place(&provisoire, cible).map_err(|e| {
        let _ = std::fs::remove_file(&provisoire);
        e.to_string()
    })
}

/// Le renommage final. Sous Windows, un programme qui tourne (la surveillance, lancée à l'heure pile) ne se remplace
/// pas, mais il se renomme : l'ancien part de côté et s'efface à la prochaine mise à jour.
fn mettre_en_place(provisoire: &Path, cible: &Path) -> std::io::Result<()> {
    let erreur = match std::fs::rename(provisoire, cible) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    if !cfg!(windows) {
        return Err(erreur);
    }
    let ancien = cible.with_file_name(format!("{NOM}.ancien"));
    let _ = std::fs::remove_file(&ancien);
    std::fs::rename(cible, &ancien)?;
    std::fs::rename(provisoire, cible).inspect_err(|_| {
        let _ = std::fs::rename(&ancien, cible);
    })
}

/// « vanguard se-mettre-a-jour » et l'entrée du menu : l'état, puis la mise à jour sur accord.
pub fn commande() {
    titre(tr!("Mettre Vanguard à jour", "Update Vanguard"));
    trp!(
        "  {GRIS}La copie de Vanguard sur cet ordinateur (surveillance, entretien, raccourci) ne suit pas la clé,\n  qui se met à jour chez toi : c'est d'elle que vient la mise à jour.{RESET}\n",
        "  {GRIS}The copy of Vanguard on this computer (monitoring, maintenance, shortcut) does not follow the key,\n  which updates at home: the update comes from it.{RESET}\n"
    );
    let cible = copie_de_cet_ordinateur();
    // Le reste d'une mise à jour faite pendant que la copie tournait (Windows).
    let _ = std::fs::remove_file(cible.with_file_name(format!("{NOM}.ancien")));
    match etat() {
        Etat::Rien => trp!(
            "  Pas de copie de Vanguard sur cet ordinateur : rien à mettre à jour. La surveillance, l'entretien et\n  le raccourci en posent une.",
            "  No copy of Vanguard on this computer: nothing to update. Monitoring, maintenance and the shortcut\n  place one."
        ),
        Etat::SansCle => trp!(
            "  La mise à jour vient de la clé VANGUARD : branche-la, puis recommence.",
            "  The update comes from the VANGUARD key: plug it in, then try again."
        ),
        Etat::AJour(v) => trp!(
            "  {VERT}✔{RESET} La copie de cet ordinateur est à jour ({}).",
            "  {VERT}✔{RESET} The copy on this computer is up to date ({}).",
            ecrire(v)
        ),
        Etat::ClePlusAncienne { copie, cle } => trp!(
            "  La copie de cet ordinateur ({}) est plus récente que la clé ({}) : remets la clé à jour chez toi.\n  Vanguard ne revient jamais à une version plus ancienne.",
            "  The copy on this computer ({}) is newer than the key ({}): update the key at home.\n  Vanguard never goes back to an older version.",
            ecrire(copie),
            ecrire(cle)
        ),
        Etat::AMettreAJour { source, copie, cle } => {
            trp!(
                "  Copie de cet ordinateur : {}\n  Clé VANGUARD           : {}\n",
                "  Copy on this computer: {}\n  VANGUARD key         : {}\n",
                version_affichee(copie),
                ecrire(cle)
            );
            if !demander(tr!(
                "  La remplacer par celle de la clé ? [o/N] : ",
                "  Replace it with the key's? [y/N]: "
            ))
            .oui()
            {
                return;
            }
            match remplacer(&source, &cible) {
                Ok(()) => {
                    *ETAT.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                    trp!(
                        "  {VERT}✔{RESET} Vanguard {} sur cet ordinateur : la surveillance, l'entretien et le raccourci le lancent désormais.",
                        "  {VERT}✔{RESET} Vanguard {} on this computer: monitoring, maintenance and the shortcut now start it.",
                        ecrire(cle)
                    );
                    if programme().is_some_and(|exe| !exe.starts_with(source.parent().unwrap_or(&source))) {
                        trp!(
                            "  {GRIS}Relance Vanguard pour utiliser la nouvelle version.{RESET}",
                            "  {GRIS}Restart Vanguard to use the new version.{RESET}"
                        );
                    }
                }
                Err(e) => trp!(
                    "  ✖ Copie non mise à jour, l'ancienne reste en place : {e}",
                    "  ✖ Copy not updated, the old one stays in place: {e}"
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_lues_et_comparees() {
        assert_eq!(lire_version("0.78.0"), Some((0, 78, 0)));
        assert_eq!(lire_version("1.2"), None);
        assert_eq!(lire_version("1.2.3.4"), None);
        assert_eq!(lire_version("1.x.3"), None);
        // Comparées comme des nombres : 0.100 vient après 0.99.
        assert!((0, 100, 0) > (0, 99, 9));
        assert_eq!(courante(), lire_version(env!("CARGO_PKG_VERSION")).unwrap());
    }

    /// Un contenu de programme avec l'en-tête de la version gravée : construit au lancement, jamais écrit tel quel
    /// dans le code, sans quoi le programme des tests porterait ces fausses versions et la recherche les prendrait.
    fn avec_entete(avant: &str, apres: &str) -> Vec<u8> {
        [avant.as_bytes(), &entete(), apres.as_bytes()].concat()
    }

    #[test]
    fn version_gravee_dans_un_programme() {
        // L'en-tête seul (la constante de recherche), suivi d'autre chose, ne compte pas ; la vraie version, oui.
        let mut octets = avec_entete("\x00\x7fELF...", "\x00abc...");
        octets.extend(avec_entete("", ""));
        octets.extend(avec_entete("", "0.81.2;..."));
        assert_eq!(version_gravee(&octets), Some((0, 81, 2)));
        // Une copie d'avant la 0.78 : pas de version.
        assert_eq!(version_gravee(b"\x7fELF un vieux programme"), None);
        // Tronquée, ou sans « ; » : rien.
        assert_eq!(version_gravee(&avec_entete("", "0.81")), None);
        assert_eq!(version_gravee(&avec_entete("", "0.81.2")), None);
        assert_eq!(version_gravee(b""), None);
    }

    /// Le programme des tests porte sa version, lisible sans le lancer, et aucune autre (le programme publié non plus :
    /// l'en-tête n'est écrit tel quel qu'une fois, dans `ENTETE`, suivi d'autre chose qu'une version).
    #[test]
    fn ce_programme_porte_sa_version() {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(lire_programme(&exe), Lu::Version(courante()));
    }

    /// Un faux programme : son contenu, avec sa version gravée (ou sans, pour une copie d'avant la 0.78).
    fn faux_programme(chemin: &Path, version: Option<&str>) {
        std::fs::create_dir_all(chemin.parent().unwrap()).unwrap();
        let contenu = version.map_or_else(
            || b"ancien programme".to_vec(),
            |v| avec_entete("prog ", &format!("{v}; fin")),
        );
        std::fs::write(chemin, contenu).unwrap();
    }

    #[test]
    fn ce_que_dit_le_menu_selon_les_copies() {
        let racine = crate::reseau::dossier_local().join("essai-mise-a-jour");
        let _ = std::fs::remove_dir_all(&racine);
        let cle = racine.join("cle");
        let sur_la_cle = cle.join(DOSSIER_SUR_LA_CLE).join(NOM);
        let copie = racine.join("ordinateur").join("bin").join(NOM);
        let v = ecrire(courante());
        let pas_de_cle = || -> Option<PathBuf> { None };

        // Pas de copie sur l'ordinateur : rien à dire.
        faux_programme(&sur_la_cle, Some(&v));
        assert_eq!(etat_de(&sur_la_cle, Some(&cle), &copie, pas_de_cle), Etat::Rien);

        // Lancé depuis la clé, copie d'avant la 0.78 : à mettre à jour depuis ce programme.
        faux_programme(&copie, None);
        assert_eq!(
            etat_de(&sur_la_cle, Some(&cle), &copie, pas_de_cle),
            Etat::AMettreAJour {
                source: sur_la_cle.clone(),
                copie: None,
                cle: courante()
            }
        );
        // Copie à la même version : à jour ; plus récente : la clé est à remettre à jour, jamais de retour en arrière.
        faux_programme(&copie, Some(&v));
        assert_eq!(
            etat_de(&sur_la_cle, Some(&cle), &copie, pas_de_cle),
            Etat::AJour(courante())
        );
        faux_programme(&copie, Some("999.0.0"));
        assert_eq!(
            etat_de(&sur_la_cle, Some(&cle), &copie, pas_de_cle),
            Etat::ClePlusAncienne {
                copie: (999, 0, 0),
                cle: courante()
            }
        );

        // Lancé depuis la copie, sans clé : pas de source.
        assert_eq!(etat_de(&copie, None, &copie, pas_de_cle), Etat::SansCle);
        // La clé branchée est plus récente : à mettre à jour depuis la clé.
        faux_programme(&sur_la_cle, Some("999.1.0"));
        assert_eq!(
            etat_de(&copie, None, &copie, || Some(cle.clone())),
            Etat::AMettreAJour {
                source: sur_la_cle.clone(),
                copie: Some(courante()),
                cle: (999, 1, 0)
            }
        );
        // Un programme de clé d'avant la 0.78 n'est jamais pris pour plus récent.
        faux_programme(&sur_la_cle, None);
        assert_eq!(
            etat_de(&copie, None, &copie, || Some(cle.clone())),
            Etat::AJour(courante())
        );
        // Un autre programme (ni la clé, ni la copie) : rien à dire.
        let ailleurs = racine.join("ailleurs").join(NOM);
        faux_programme(&ailleurs, Some(&v));
        assert_eq!(etat_de(&ailleurs, None, &copie, || Some(cle.clone())), Etat::Rien);
        let _ = std::fs::remove_dir_all(&racine);
    }

    #[test]
    fn la_copie_remplacee_d_un_coup() {
        let racine = crate::reseau::dossier_local().join("essai-remplacement");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("999.0.0"));
        faux_programme(&cible, None);
        remplacer(&source, &cible).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(!cible.with_file_name(format!("{NOM}.nouveau")).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&cible).unwrap().permissions().mode() & 0o777, 0o755);
        }
        // Une source illisible : l'ancienne copie reste telle quelle.
        faux_programme(&cible, Some("1.0.0"));
        assert!(remplacer(&racine.join("absente"), &cible).is_err());
        assert_eq!(lire_programme(&cible), Lu::Version((1, 0, 0)));
        let _ = std::fs::remove_dir_all(&racine);
    }
}
