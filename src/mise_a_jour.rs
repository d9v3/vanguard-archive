//! Mettre Vanguard à jour sur cet ordinateur. La copie que la surveillance, l'entretien et le raccourci y lancent
//! (`reseau::surveillance::executable`) ne suit pas la clé, qui, elle, se met à jour chez son propriétaire. Lancé
//! depuis une clé plus récente, Vanguard le dit au menu et remplace la copie sur accord par le programme qui tourne :
//! copié à côté, sa version revérifiée, relu et comparé, puis mis en place d'un coup. Jamais vers une version plus
//! ancienne. La source est toujours le programme lancé depuis la clé, la confiance que la surveillance lui faisait
//! déjà en le copiant ; jamais un volume seulement branché, qui n'aurait qu'à porter le fichier témoin. La version
//! d'une copie se lit dans son fichier, sans la lancer : une vieille copie ne refait pas ses étapes de démarrage
//! (protection de la clé, passage à un nouveau nom). GitHub n'est pas une source : le dépôt est privé.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::ui::*;

/// La version de ce programme et la date de son commit, gravées dans son fichier pour qu'une autre copie les lise sans
/// le lancer (« VANGUARD-VERSION:0.78.0+1760900000; »). `courante` la lit là : sans lecture, l'éditeur de liens
/// retirerait ce texte du programme publié.
static VERSION_GRAVEE: &str = concat!(
    "VANGUARD-VERSION:",
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("VANGUARD_COMMIT_SECONDES"),
    ";"
);

/// Ce qui précède la version gravée, écrit décalé d'un cran (« W » pour « V ») : en clair, ce texte paraîtrait une
/// seconde fois dans le programme, suivi de ce que l'éditeur de liens met après lui (« 0.78.0 » d'un autre texte,
/// par exemple), et la recherche pourrait y lire une fausse version. Ainsi, seule la version gravée le porte.
const ENTETE_DECALE: [u8; 17] = *b"WBOHVBSE.WFSTJPO;";

/// L'en-tête en clair, refait au lancement (`black_box` : le compilateur ne le calcule pas d'avance, ce qui l'écrirait
/// en clair dans le programme).
fn entete() -> [u8; 17] {
    std::hint::black_box(ENTETE_DECALE).map(|o| o - 1)
}

/// Au-delà, un fichier n'est pas un programme de Vanguard (un release fait environ 25 Mo avec YARA-X, un debug
/// un peu plus de 200) : il n'est pas lu, la mémoire ne se remplit pas.
const TAILLE_MAX: u64 = 512 << 20;

const NOM: &str = if cfg!(windows) { "vanguard.exe" } else { "vanguard" };

/// Une version : majeure, mineure, correctif, puis la date de son commit en secondes (0 : inconnue). Entre deux
/// publications, les compilations intermédiaires gardent le même numéro : la date les départage, et l'ordre des
/// tuples fait le reste.
type Version = (u32, u32, u32, u64);

/// « 0.78.0 » ou « 0.78.0+1760900000 ».
fn lire_version(texte: &str) -> Option<Version> {
    let (numero, date) = match texte.split_once('+') {
        Some((n, d)) => (n, d.parse::<u64>().ok()?),
        None => (texte, 0),
    };
    let mut morceaux = numero.split('.').map(|m| m.parse::<u32>().ok());
    let version = (morceaux.next()??, morceaux.next()??, morceaux.next()??, date);
    morceaux.next().is_none().then_some(version)
}

fn ecrire(v: Version) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

/// Deux versions à montrer côte à côte : le numéro seul, et la date du commit quand le numéro ne suffit pas à les
/// distinguer (deux compilations entre deux publications).
fn cote_a_cote(a: Version, b: Version) -> (String, String) {
    if (a.0, a.1, a.2) != (b.0, b.1, b.2) || a.3 == b.3 {
        return (ecrire(a), ecrire(b));
    }
    let date = |v: Version| {
        i64::try_from(v.3)
            .ok()
            .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
            .filter(|_| v.3 > 0)
            .map_or_else(
                || tr!("sans date", "undated").to_string(),
                |d| {
                    d.with_timezone(&chrono::Local)
                        .format(tr!("%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M"))
                        .to_string()
                },
            )
    };
    (
        format!("{} ({})", ecrire(a), date(a)),
        format!("{} ({})", ecrire(b), date(b)),
    )
}

/// La version de ce programme, lue dans sa version gravée (`black_box` : le compilateur ne la remplace pas par sa
/// valeur, le texte reste dans le fichier). `None` ne devrait jamais arriver (un test le garde) : rien n'est alors
/// proposé, plutôt que de comparer à une version inventée.
fn courante() -> Option<Version> {
    version_gravee(std::hint::black_box(VERSION_GRAVEE).as_bytes())
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

/// Ce qu'on lit d'un programme sur le disque.
#[derive(Debug, PartialEq, Eq)]
enum Lu {
    Absent,
    /// Là, mais pas lisible comme un programme (droits, dossier, fichier spécial, démesuré) : le pourquoi.
    Illisible(String),
    /// Sans version gravée : d'avant la 0.78.
    Ancien,
    Version(Version),
}

/// Le contenu d'un programme : seulement un fichier ordinaire, jamais plus de `max` octets lus (un fichier spécial
/// bloquerait, un fichier démesuré remplirait la mémoire).
fn lire_octets(chemin: &Path, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let meta = std::fs::metadata(chemin).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(tr!("pas un fichier ordinaire", "not a regular file").into());
    }
    let mut octets = Vec::new();
    std::fs::File::open(chemin)
        .and_then(|f| f.take(max + 1).read_to_end(&mut octets))
        .map_err(|e| e.to_string())?;
    if u64::try_from(octets.len()).unwrap_or(u64::MAX) > max {
        return Err(tr!("fichier démesuré", "oversized file").into());
    }
    Ok(octets)
}

fn lire_programme(chemin: &Path, max: u64) -> Lu {
    if std::fs::symlink_metadata(chemin).is_err() {
        return Lu::Absent;
    }
    match lire_octets(chemin, max) {
        Err(e) => Lu::Illisible(e),
        Ok(octets) => version_gravee(&octets).map_or(Lu::Ancien, Lu::Version),
    }
}

/// Où en est la copie de cet ordinateur.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Etat {
    /// Rien à dire : pas de copie sur cet ordinateur.
    Rien,
    /// Une copie est là, mais Vanguard ne tourne pas depuis la clé : la mise à jour se fait depuis la clé.
    PasDepuisLaCle,
    /// La copie est là mais ne se lit pas : sa version n'a pas pu être vérifiée (le pourquoi).
    Illisible(String),
    AJour(Version),
    /// La copie est plus récente que la clé : la clé est à remettre à jour chez son propriétaire.
    ClePlusAncienne {
        copie: Version,
        cle: Version,
    },
    /// La clé est plus récente : la copie peut être remplacée par `source`, le programme qui tourne.
    AMettreAJour {
        source: PathBuf,
        copie: Option<Version>,
        cle: Version,
    },
}

/// Compare la copie de cet ordinateur et ce programme. `copie` : sa version (`None` : d'avant la 0.78).
fn comparer(copie: Option<Version>, cle: Version, source: PathBuf) -> Etat {
    match copie {
        Some(c) if c == cle => Etat::AJour(c),
        Some(c) if c > cle => Etat::ClePlusAncienne { copie: c, cle },
        _ => Etat::AMettreAJour { source, copie, cle },
    }
}

/// L'état, d'après le programme lancé (`exe`), la clé d'où il tourne (`cle_du_programme`), la copie de cet ordinateur
/// et la version de ce programme.
fn etat_de(exe: &Path, cle_du_programme: Option<&Path>, copie: &Path, courante: Option<Version>, max: u64) -> Etat {
    let lu = lire_programme(copie, max);
    if lu == Lu::Absent {
        return Etat::Rien;
    }
    if !cle_du_programme.is_some_and(|c| exe.starts_with(c)) {
        return Etat::PasDepuisLaCle;
    }
    let Some(courante) = courante else {
        return Etat::Rien;
    };
    match lu {
        Lu::Absent => Etat::Rien,
        Lu::Illisible(e) => Etat::Illisible(e),
        Lu::Ancien => comparer(None, courante, exe.to_path_buf()),
        Lu::Version(v) => comparer(Some(v), courante, exe.to_path_buf()),
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

/// Ce qui dit qu'une copie a changé : sa taille et sa date (`None` : absente).
type Empreinte = Option<(u64, SystemTime)>;

fn empreinte(chemin: &Path) -> Empreinte {
    let meta = std::fs::metadata(chemin).ok()?;
    Some((meta.len(), meta.modified().ok()?))
}

/// L'état gardé tant que la copie ne change pas : le menu le demande à chaque affichage, et lire la copie prend un
/// moment. Une copie posée ou remplacée pendant la session (surveillance activée, mise à jour) le fait relire.
struct Memoire(Mutex<Option<(Empreinte, Etat)>>);

impl Memoire {
    const fn new() -> Self {
        Self(Mutex::new(None))
    }

    fn lire(&self, empreinte: Empreinte, calcul: impl FnOnce() -> Etat) -> Etat {
        let mut garde = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((e, etat)) = garde.as_ref()
            && *e == empreinte
        {
            return etat.clone();
        }
        let etat = calcul();
        *garde = Some((empreinte, etat.clone()));
        etat
    }
}

static ETAT: Memoire = Memoire::new();

fn etat() -> Etat {
    // Jamais pendant les tests : la vraie copie peut être là.
    if cfg!(test) {
        return Etat::Rien;
    }
    let copie = copie_de_cet_ordinateur();
    ETAT.lire(empreinte(&copie), || {
        // Le reste d'une mise à jour faite pendant que la copie tournait (Windows), s'il ne tourne plus.
        let _ = std::fs::remove_file(copie.with_file_name(format!("{NOM}.ancien")));
        programme().map_or(Etat::Rien, |exe| {
            etat_de(
                &exe,
                crate::reseau::cle_du_programme().as_deref(),
                &copie,
                courante(),
                TAILLE_MAX,
            )
        })
    })
}

/// La copie, avant la 0.78, n'avait pas de version lisible.
fn version_affichee(v: Option<Version>) -> String {
    v.map_or_else(|| tr!("d'avant la 0.78", "older than 0.78").to_string(), ecrire)
}

/// La ligne du menu quand la clé d'où tourne Vanguard est plus récente que la copie de cet ordinateur, sinon rien.
/// `touche` : l'entrée du menu qui la met à jour (« 9.9 »).
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

/// Copie `source` à la place de `cible` : à côté d'abord, sa version revérifiée (ce qui a été montré est ce qui
/// s'installe : la clé a pu changer depuis l'affichage), relue et comparée, puis renommée d'un coup ; une copie
/// interrompue ou abîmée ne remplace jamais celle qui marche, et ne reste pas sur le disque.
fn remplacer(source: &Path, cible: &Path, attendue: Version, max: u64) -> Result<(), String> {
    let octets = lire_octets(source, max)?;
    if version_gravee(&octets) != Some(attendue) {
        return Err(tr!(
            "le programme de la clé a changé depuis l'affichage, rien n'est remplacé",
            "the key's program changed since it was shown, nothing is replaced"
        )
        .into());
    }
    let provisoire = cible.with_file_name(format!("{NOM}.nouveau"));
    let ecrite = (|| -> Result<(), String> {
        std::fs::write(&provisoire, &octets).map_err(|e| e.to_string())?;
        if std::fs::read(&provisoire).ok().as_deref() != Some(&octets[..]) {
            return Err(tr!("la copie relue ne correspond pas", "the copy read back does not match").into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&provisoire, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
        }
        mettre_en_place(&provisoire, cible).map_err(|e| e.to_string())
    })();
    if ecrite.is_err() {
        let _ = std::fs::remove_file(&provisoire);
    }
    ecrite
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
    // Celui d'une mise à jour précédente tourne peut-être encore : rien ne se remplace, et c'est dit clairement.
    if std::fs::symlink_metadata(&ancien).is_ok() && std::fs::remove_file(&ancien).is_err() {
        return Err(std::io::Error::other(tr!(
            "l'ancienne copie tourne encore (surveillance) : réessaie dans une minute",
            "the old copy is still running (monitoring): try again in a minute"
        )));
    }
    std::fs::rename(cible, &ancien)?;
    std::fs::rename(provisoire, cible).inspect_err(|_| {
        let _ = std::fs::rename(&ancien, cible);
    })
}

/// « vanguard se-mettre-a-jour » et l'entrée du menu : l'état, puis la mise à jour sur accord.
pub fn commande() {
    titre(tr!("Mettre Vanguard à jour", "Update Vanguard"));
    trp!(
        "  {GRIS}La copie de Vanguard posée sur cet ordinateur (surveillance, entretien,\n  raccourci) ne suit pas la clé : elle se met à jour d'ici, sur accord.{RESET}\n",
        "  {GRIS}The copy of Vanguard placed on this computer (monitoring, maintenance,\n  shortcut) does not follow the key: it is updated from here, on your OK.{RESET}\n"
    );
    let cible = copie_de_cet_ordinateur();
    // Le reste d'une mise à jour faite pendant que la copie tournait (Windows).
    let _ = std::fs::remove_file(cible.with_file_name(format!("{NOM}.ancien")));
    match etat() {
        Etat::Rien => trp!(
            "  Pas de copie de Vanguard sur cet ordinateur : rien à mettre à jour.\n  La surveillance, l'entretien et le raccourci en posent une.",
            "  No copy of Vanguard on this computer: nothing to update.\n  Monitoring, maintenance and the shortcut place one."
        ),
        Etat::PasDepuisLaCle => trp!(
            "  La mise à jour vient de la clé VANGUARD : lance Vanguard depuis la clé,\n  puis reviens ici.",
            "  The update comes from the VANGUARD key: start Vanguard from the key,\n  then come back here."
        ),
        Etat::Illisible(e) => trp!(
            "  ✖ La copie de cet ordinateur ne se lit pas : sa version reste inconnue.\n    {GRIS}{} : {}{RESET}",
            "  ✖ The copy on this computer cannot be read: its version is unknown.\n    {GRIS}{}: {}{RESET}",
            affichable(&cible.display().to_string()),
            affichable(&e)
        ),
        Etat::AJour(v) => trp!(
            "  {VERT}✔{RESET} La copie de cet ordinateur est à jour ({}).",
            "  {VERT}✔{RESET} The copy on this computer is up to date ({}).",
            ecrire(v)
        ),
        Etat::ClePlusAncienne { copie, cle } => {
            let (copie, cle) = cote_a_cote(copie, cle);
            trp!(
                "  La copie d'ici ({copie}) est plus récente que la clé ({cle}).\n  Remets la clé à jour chez toi : Vanguard ne revient jamais en arrière.",
                "  The copy on this computer ({copie}) is newer than the key ({cle}).\n  Update the key at home: Vanguard never goes back to an older version."
            );
        }
        Etat::AMettreAJour { source, copie, cle } => proposer(&source, &cible, copie, cle),
    }
}

/// Montre les deux versions et d'où vient la nouvelle, puis remplace la copie après un « o ».
fn proposer(source: &Path, cible: &Path, copie: Option<Version>, cle: Version) {
    let (ici, sur_la_cle) = match copie {
        Some(c) => cote_a_cote(c, cle),
        None => (version_affichee(None), ecrire(cle)),
    };
    trp!(
        "  Copie de cet ordinateur : {ici}\n  Clé VANGUARD           : {sur_la_cle}\n  {GRIS}Depuis {}{RESET}\n",
        "  Copy on this computer: {ici}\n  VANGUARD key         : {sur_la_cle}\n  {GRIS}From {}{RESET}\n",
        affichable(&source.display().to_string())
    );
    if !demander(tr!(
        "  La remplacer par celle de la clé ? [o/N] : ",
        "  Replace it with the key's? [y/N]: "
    ))
    .oui()
    {
        return;
    }
    match remplacer(source, cible, cle, TAILLE_MAX) {
        Ok(()) => trp!(
            "  {VERT}✔{RESET} Copie de cet ordinateur mise à jour : Vanguard {}.\n    La surveillance, l'entretien et le raccourci lancent cette version.",
            "  {VERT}✔{RESET} Copy on this computer updated: Vanguard {}.\n    Monitoring, maintenance and the shortcut start this version.",
            ecrire(cle)
        ),
        Err(e) => trp!(
            "  ✖ Copie non mise à jour, l'ancienne reste en place :\n    {}",
            "  ✖ Copy not updated, the old one stays in place:\n    {}",
            affichable(&e)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_lues_et_comparees() {
        assert_eq!(lire_version("0.78.0"), Some((0, 78, 0, 0)));
        assert_eq!(lire_version("0.78.0+1760900000"), Some((0, 78, 0, 1_760_900_000)));
        assert_eq!(lire_version("0.78.0+x"), None);
        assert_eq!(lire_version("1.2"), None);
        assert_eq!(lire_version("1.2.3.4"), None);
        assert_eq!(lire_version("1.x.3"), None);
        // Comparées comme des nombres : 0.100 vient après 0.99 ; à numéro égal, le commit le plus récent l'emporte, et
        // le numéro passe toujours avant la date.
        assert!((0, 100, 0, 0) > (0, 99, 9, 0));
        assert!((0, 78, 0, 2) > (0, 78, 0, 1));
        assert!((0, 79, 0, 1) > (0, 78, 0, 9));
        // La version gravée est bien celle du paquet, avec la date de son commit : sans quoi rien ne serait proposé.
        let numero = |v: Option<Version>| v.map(|v| (v.0, v.1, v.2));
        assert_eq!(numero(courante()), numero(lire_version(env!("CARGO_PKG_VERSION"))));
        assert_eq!(
            courante().map(|v| v.3.to_string()).as_deref(),
            Some(env!("VANGUARD_COMMIT_SECONDES"))
        );
    }

    #[test]
    fn deux_compilations_d_un_meme_numero_se_distinguent_par_la_date() {
        let (a, b) = cote_a_cote((0, 78, 0, 0), (0, 79, 0, 5));
        assert_eq!((a.as_str(), b.as_str()), ("0.78.0", "0.79.0"));
        let (a, b) = cote_a_cote((0, 78, 0, 5), (0, 78, 0, 5));
        assert_eq!((a.as_str(), b.as_str()), ("0.78.0", "0.78.0"));
        let (a, b) = cote_a_cote((0, 78, 0, 1_760_000_000), (0, 78, 0, 1_760_900_000));
        assert!(
            a.starts_with("0.78.0 (") && b.starts_with("0.78.0 (") && a != b,
            "{a} / {b}"
        );
    }

    /// Un contenu de programme avec l'en-tête de la version gravée : construit au lancement, jamais écrit tel quel
    /// dans le code, sans quoi le programme des tests porterait ces fausses versions et la recherche les prendrait.
    fn avec_entete(avant: &str, apres: &str) -> Vec<u8> {
        [avant.as_bytes(), &entete(), apres.as_bytes()].concat()
    }

    #[test]
    fn version_gravee_dans_un_programme() {
        // L'en-tête seul, suivi d'autre chose, ne compte pas ; la vraie version, oui.
        let mut octets = avec_entete("\x00\x7fELF...", "\x00abc...");
        octets.extend(avec_entete("", ""));
        octets.extend(avec_entete("", "0.81.2+x;..."));
        octets.extend(avec_entete("", "0.81.2+1760900000;..."));
        assert_eq!(version_gravee(&octets), Some((0, 81, 2, 1_760_900_000)));
        assert_eq!(version_gravee(&avec_entete("", "0.81.2;")), Some((0, 81, 2, 0)));
        // Une copie d'avant la 0.78 : pas de version.
        assert_eq!(version_gravee(b"\x7fELF un vieux programme"), None);
        // Tronquée, ou sans « ; » : rien.
        assert_eq!(version_gravee(&avec_entete("", "0.81")), None);
        assert_eq!(version_gravee(&avec_entete("", "0.81.2")), None);
        assert_eq!(version_gravee(b""), None);
    }

    /// Le programme des tests porte sa version, lisible sans le lancer, et aucune autre (le programme publié non plus :
    /// l'en-tête n'est écrit en clair qu'une fois, dans la version gravée).
    #[test]
    fn ce_programme_porte_sa_version() {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(lire_programme(&exe, TAILLE_MAX), Lu::Version(courante().unwrap()));
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
    fn ce_que_dit_le_menu_selon_la_copie() {
        let racine = crate::reseau::dossier_local().join("essai-mise-a-jour");
        let _ = std::fs::remove_dir_all(&racine);
        let cle = racine.join("cle");
        let sur_la_cle = cle.join("Linux").join(NOM);
        let copie = racine.join("ordinateur").join("bin").join(NOM);
        let v = (0, 78, 0, 0);
        let etat =
            |exe: &Path, cle_du_programme: Option<&Path>| etat_de(exe, cle_du_programme, &copie, Some(v), TAILLE_MAX);
        faux_programme(&sur_la_cle, Some("0.78.0"));

        // Pas de copie sur l'ordinateur : rien à dire.
        assert_eq!(etat(&sur_la_cle, Some(&cle)), Etat::Rien);
        // Lancé depuis la clé, copie d'avant la 0.78 : à mettre à jour depuis le programme qui tourne.
        faux_programme(&copie, None);
        assert_eq!(
            etat(&sur_la_cle, Some(&cle)),
            Etat::AMettreAJour {
                source: sur_la_cle.clone(),
                copie: None,
                cle: v
            }
        );
        // Copie à la même version : à jour ; plus récente : la clé est à remettre à jour, jamais de retour en arrière.
        faux_programme(&copie, Some("0.78.0"));
        assert_eq!(etat(&sur_la_cle, Some(&cle)), Etat::AJour(v));
        faux_programme(&copie, Some("0.79.0"));
        assert_eq!(
            etat(&sur_la_cle, Some(&cle)),
            Etat::ClePlusAncienne {
                copie: (0, 79, 0, 0),
                cle: v
            }
        );
        // Même numéro : le commit le plus récent l'emporte (compilations entre deux publications).
        faux_programme(&copie, Some("0.78.0+5"));
        let plus_tard = (0, 78, 0, 9);
        assert!(matches!(
            etat_de(&sur_la_cle, Some(&cle), &copie, Some(plus_tard), TAILLE_MAX),
            Etat::AMettreAJour {
                copie: Some((0, 78, 0, 5)),
                ..
            }
        ));
        assert!(matches!(
            etat_de(&sur_la_cle, Some(&cle), &copie, Some((0, 78, 0, 1)), TAILLE_MAX),
            Etat::ClePlusAncienne { .. }
        ));
        // Lancé depuis la copie, ou d'ailleurs : la mise à jour se fait depuis la clé, jamais depuis un volume
        // seulement branché.
        assert_eq!(etat(&copie, None), Etat::PasDepuisLaCle);
        assert_eq!(etat(&racine.join("ailleurs").join(NOM), None), Etat::PasDepuisLaCle);
        // Sans version lisible pour ce programme : rien n'est proposé.
        assert_eq!(etat_de(&sur_la_cle, Some(&cle), &copie, None, TAILLE_MAX), Etat::Rien);
        // Une copie qui ne se lit pas (ici un dossier, ou démesurée) est dite, jamais comptée comme à jour.
        std::fs::remove_file(&copie).unwrap();
        std::fs::create_dir_all(&copie).unwrap();
        assert!(matches!(etat(&sur_la_cle, Some(&cle)), Etat::Illisible(_)));
        std::fs::remove_dir(&copie).unwrap();
        faux_programme(&copie, Some("0.70.0"));
        assert!(matches!(
            etat_de(&sur_la_cle, Some(&cle), &copie, Some(v), 4),
            Etat::Illisible(_)
        ));
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Une copie posée ou remplacée pendant la session (surveillance activée) fait relire l'état ; sinon il est gardé.
    #[test]
    fn l_etat_suit_la_copie() {
        let memoire = Memoire::new();
        let premiere = Some((10, SystemTime::UNIX_EPOCH));
        assert_eq!(
            memoire.lire(premiere, || Etat::AJour((0, 1, 0, 0))),
            Etat::AJour((0, 1, 0, 0))
        );
        assert_eq!(
            memoire.lire(premiere, || unreachable!("gardé")),
            Etat::AJour((0, 1, 0, 0))
        );
        assert_eq!(
            memoire.lire(Some((11, SystemTime::UNIX_EPOCH)), || Etat::Rien),
            Etat::Rien
        );
        assert_eq!(memoire.lire(None, || Etat::PasDepuisLaCle), Etat::PasDepuisLaCle);
    }

    #[test]
    fn la_copie_remplacee_d_un_coup() {
        let racine = crate::reseau::dossier_local().join("essai-remplacement");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0"));
        faux_programme(&cible, None);
        remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(!cible.with_file_name(format!("{NOM}.nouveau")).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&cible).unwrap().permissions().mode() & 0o777, 0o755);
        }
        // La clé a changé depuis l'affichage (une autre version) : rien n'est remplacé.
        faux_programme(&cible, Some("0.70.0"));
        faux_programme(&source, Some("0.69.0"));
        assert!(remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX).is_err());
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 70, 0, 0)));
        // Une source absente ou démesurée : l'ancienne copie reste, rien ne traîne à côté.
        assert!(remplacer(&racine.join("absente"), &cible, (0, 80, 0, 0), TAILLE_MAX).is_err());
        faux_programme(&source, Some("0.80.0"));
        assert!(remplacer(&source, &cible, (0, 80, 0, 0), 4).is_err());
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 70, 0, 0)));
        assert!(!cible.with_file_name(format!("{NOM}.nouveau")).exists());
        let _ = std::fs::remove_dir_all(&racine);
    }
}
