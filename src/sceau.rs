//! Les sceaux de l'état de Vanguard : les fichiers qu'il garde sur cet ordinateur et qui décident de ce qu'il dit (les
//! alertes déclarées normales, la référence des fichiers critiques et les changements déjà signalés, les connexions
//! à des botnets déjà signalées, la plus haute version signée déjà vue, l'état de la machine au dernier passage de
//! la surveillance, les valeurs d'avant des réglages d'Optimiser, les alertes de la surveillance déclarées normales).
//! Un programme qui tourne sous le compte pouvait réécrire l'un d'eux pour faire
//! taire sa propre alerte, sans que rien ne le dise. Chaque écriture de Vanguard note donc l'empreinte BLAKE3 du
//! fichier dans `sceaux.json` ; une lecture qui ne la retrouve pas rend le fichier « falsifié », que chaque lecteur
//! traite comme s'il ne valait rien (jamais comme un feu vert), et le bilan l'annonce (COM-ETA-001).
//!
//! Comme la chaîne de l'historique : barrière, pas coffre. Qui connaît ce mécanisme peut aussi réécrire les sceaux ;
//! seule la séparation des comptes ferait mieux. Les fichiers d'une version d'avant, qui ne scellait rien, sont
//! scellés tels quels la première fois (confiance au premier usage) ; ce départ est daté dans les sceaux. Effacer
//! `sceaux.json` refait ce premier usage : les fichiers alors acceptés tels quels restent marqués « adoptés » (lus
//! `Adopte`) jusqu'à ce que Vanguard les réécrive, et le bilan le dit (COM-ETA-001), au lieu de les croire en
//! silence. Qui efface les sceaux puis en réécrit de valables n'est toujours pas vu.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::machine::Constat;
use crate::risk::Niveau;
use crate::ui::*;

/// Les alertes déclarées normales (`apprentissage`).
pub(crate) const APPRIS: &str = "appris.json";
/// La référence des fichiers critiques (`protection::integrite`).
pub(crate) const INTEGRITE: &str = "integrite.json";
/// Les connexions à des botnets déjà notifiées par la surveillance (`protection::sortantes`).
pub(crate) const BOTNETS: &str = "surveillance-botnets.txt";
/// La plus haute version signée déjà vue sur GitHub (`mise_a_jour::github`).
pub(crate) const VERSIONS: &str = "versions/plus-haute-vue.txt";
/// L'état de la machine au passage d'avant de la surveillance (`reseau::surveillance`) : un programme qui y écrit
/// d'avance sa propre alerte, ou qui l'efface, ne la ferait jamais notifier.
pub(crate) const MACHINE: &str = "surveillance-machine.json";
/// Les changements de fichiers critiques déjà notifiés par la surveillance (`protection::integrite`) : un programme
/// qui y écrit d'avance le ~/.bashrc qu'il vient de changer tairait la notification.
pub(crate) const INTEGRITE_SIGNALE: &str = "integrite-signale.json";

/// L'état du mode Wi-Fi public (`reseau::wifi_public`) : ce qu'il a changé et les valeurs d'avant, remises en
/// administrateur à l'extinction. Un programme qui y écrirait une valeur d'avant à lui la ferait poser avec les droits
/// d'administrateur.
pub(crate) const WIFI_PUBLIC: &str = "wifi-public.json";

/// Les valeurs d'avant des réglages d'Optimiser (`optimiser`), remises en administrateur pour annuler : un programme
/// qui y écrirait une valeur à lui la ferait poser avec tous les droits.
pub(crate) const REGLAGES: &str = "reglages.json";

/// Les alertes du veilleur, de la surveillance et du blocage déclarées normales (`protection::normales`) : un
/// programme qui s'y ajouterait ferait taire sa propre alerte.
pub(crate) const NORMALES: &str = "normales.json";

/// Les fichiers protégés : ceux que l'inventaire des fichiers d'état dit scellés (`modele::inventaire`). Un fichier
/// d'état s'ajoute là, avec sa constante ici : on ne peut plus en sceller un sans l'inventorier.
fn proteges() -> impl Iterator<Item = &'static str> {
    crate::modele::inventaire::scelles()
}

/// Les fichiers protégés après le premier sceau : une version d'avant les écrivait déjà sans sceau, et des sceaux
/// existants les feraient passer pour falsifiés à la mise à jour. La première fois que des sceaux les rencontrent,
/// ils sont acceptés tels quels (« adoptés », dit au bilan comme tout premier usage), puis jugés comme les autres.
const TARDIFS: [&str; 2] = [REGLAGES, NORMALES];

const REGISTRE: &str = "sceaux.json";
const VERROU: &str = "sceaux.verrou";

/// Les sceaux : depuis quand (AAAA-MM-JJ), l'empreinte de chaque fichier tel que Vanguard l'a écrit, et ceux qui
/// ont été scellés tels quels au premier usage, sans que Vanguard les ait écrits depuis.
#[derive(Serialize, Deserialize, Default)]
struct Registre {
    depuis: String,
    fichiers: BTreeMap<String, String>,
    #[serde(default)]
    adoptes: BTreeSet<String>,
    /// La version du format de chaque fichier tel que Vanguard l'a écrit (`modele::inventaire`) : notée ici et non
    /// dans le fichier, qui garde sa forme (l'historique reste un tableau). Absente des sceaux d'avant.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    versions: BTreeMap<String, u16>,
    /// Les fichiers protégés tard (`TARDIFS`) que ces sceaux ont déjà rencontrés : passé ce premier regard, un tel
    /// fichier posé sans sceau est falsifié, comme les autres.
    #[serde(default)]
    vus: BTreeSet<String>,
}

/// Ce que Vanguard retrouve d'un de ses fichiers.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lecture {
    Absent,
    /// Tel que Vanguard l'a écrit.
    Intact(Vec<u8>),
    /// Scellé tel quel au premier usage, sans sceau d'avant (une version d'avant les sceaux, ou `sceaux.json`
    /// effacé) et pas réécrit depuis par Vanguard : rien ne prouve qu'il n'a pas été changé juste avant.
    Adopte(Vec<u8>),
    /// Changé hors de Vanguard : le contenu actuel, ou `None` s'il a été supprimé.
    Falsifie(Option<Vec<u8>>),
    /// Là, mais il ne se lit pas (droits, dossier à sa place) : le pourquoi.
    Illisible(String),
}

/// L'empreinte d'un fichier d'état : son nom en fait partie, un sceau ne vaut pas pour un autre fichier.
fn empreinte(nom: &str, octets: &[u8]) -> String {
    let mut h = blake3::Hasher::new_derive_key("vanguard sceau 1");
    h.update(nom.as_bytes());
    h.update(&[0]);
    h.update(octets);
    h.finalize().to_hex().to_string()
}

/// Le verrou des sceaux : la surveillance horaire, le veilleur et le menu écrivent chacun leurs fichiers, et un
/// lecteur qui passerait entre l'écriture d'un fichier et celle de son sceau le croirait falsifié. Tenu quelques
/// millisecondes ; au-delà de deux secondes (un processus figé), on avance sans lui plutôt que de tout bloquer.
fn verrou(dossier: &Path) -> Option<std::fs::File> {
    std::fs::create_dir_all(dossier).ok()?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dossier.join(VERROU))
        .ok()?;
    let fin = Instant::now() + Duration::from_secs(2);
    loop {
        match f.try_lock() {
            Ok(()) => return Some(f),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < fin => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
}

/// Les sceaux : `Ok(None)` s'il n'y en a pas encore (une version d'avant), `Err` s'ils ne se lisent plus.
fn registre(dossier: &Path) -> Result<Option<Registre>, ()> {
    match std::fs::read(dossier.join(REGISTRE)) {
        Ok(o) => serde_json::from_slice(&o).map(Some).map_err(|_| ()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

fn enregistrer_registre(dossier: &Path, r: &Registre) -> std::io::Result<()> {
    crate::socle::ecrire_atomique(
        &dossier.join(REGISTRE),
        serde_json::to_vec_pretty(r).map_err(std::io::Error::other)?,
    )
}

/// Le contenu d'un fichier d'état, `Ok(None)` s'il n'existe pas.
fn contenu(chemin: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(chemin) {
        Ok(o) => Ok(Some(o)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Premier passage d'une version qui scelle : les fichiers déjà là sont scellés tels quels, et ce départ est daté.
fn adopter(dossier: &Path) -> Registre {
    let mut r = Registre {
        depuis: chrono::Local::now().format("%Y-%m-%d").to_string(),
        ..Registre::default()
    };
    for nom in proteges() {
        if let Ok(Some(o)) = contenu(&dossier.join(nom)) {
            r.fichiers.insert(nom.to_string(), empreinte(nom, &o));
            r.adoptes.insert(nom.to_string());
        }
    }
    r.vus = TARDIFS.iter().map(|n| (*n).to_string()).collect();
    let _ = enregistrer_registre(dossier, &r);
    r
}

/// Des sceaux d'une version qui ne protégeait pas encore les fichiers `TARDIFS` : celui qui est déjà là, sans sceau,
/// est adopté tel quel (il vient de cette version), une fois pour toutes.
fn rattraper(dossier: &Path, mut r: Registre) -> Registre {
    let mut change = false;
    for nom in TARDIFS {
        if r.vus.contains(nom) {
            continue;
        }
        if !r.fichiers.contains_key(nom)
            && let Ok(Some(o)) = contenu(&dossier.join(nom))
        {
            r.fichiers.insert(nom.to_string(), empreinte(nom, &o));
            r.adoptes.insert(nom.to_string());
        }
        r.vus.insert(nom.to_string());
        change = true;
    }
    if change {
        let _ = enregistrer_registre(dossier, &r);
    }
    r
}

/// Le jugement d'un fichier d'après les sceaux (`None` : ils ne se lisent plus, rien ne peut être cru).
fn juger(nom: &str, lu: Result<Option<Vec<u8>>, String>, sceaux: Option<&Registre>) -> Lecture {
    let lu = match lu {
        Ok(lu) => lu,
        Err(e) => return Lecture::Illisible(e),
    };
    let attendu = sceaux.and_then(|r| r.fichiers.get(nom));
    match (lu, attendu) {
        // Même sans sceaux lisibles : un fichier absent ne fait rien croire.
        (None, None) => Lecture::Absent,
        (None, Some(_)) => Lecture::Falsifie(None),
        (Some(o), Some(e)) if *e == empreinte(nom, &o) => {
            if sceaux.is_some_and(|r| r.adoptes.contains(nom)) {
                Lecture::Adopte(o)
            } else {
                Lecture::Intact(o)
            }
        }
        // Changé, ou posé sans sceau alors que les sceaux existent (par un autre programme, ou par une copie de
        // Vanguard d'avant les sceaux).
        (Some(o), _) => Lecture::Falsifie(Some(o)),
    }
}

/// Un fichier d'état de `dossier`, jugé d'après ses sceaux.
pub(crate) fn lire_dans(dossier: &Path, nom: &str) -> Lecture {
    let _verrou = verrou(dossier);
    let sceaux = match registre(dossier) {
        Ok(Some(r)) => Some(rattraper(dossier, r)),
        Ok(None) => Some(adopter(dossier)),
        Err(()) => None,
    };
    juger(nom, contenu(&dossier.join(nom)), sceaux.as_ref())
}

/// Écrit un fichier d'état de `dossier` (d'un coup) et son sceau. Des sceaux illisibles repartent de celui-ci : les
/// autres fichiers restent falsifiés jusqu'à ce que Vanguard les réécrive.
pub(crate) fn ecrire_dans(dossier: &Path, nom: &str, octets: &[u8]) -> std::io::Result<()> {
    let _verrou = verrou(dossier);
    let mut sceaux = match registre(dossier) {
        Ok(Some(r)) => rattraper(dossier, r),
        Ok(None) => adopter(dossier),
        Err(()) => Registre {
            depuis: chrono::Local::now().format("%Y-%m-%d").to_string(),
            vus: TARDIFS.iter().map(|n| (*n).to_string()).collect(),
            ..Registre::default()
        },
    };
    crate::socle::ecrire_atomique(&dossier.join(nom), octets)?;
    sceaux.fichiers.insert(nom.to_string(), empreinte(nom, octets));
    sceaux.adoptes.remove(nom);
    sceaux
        .versions
        .insert(nom.to_string(), crate::modele::inventaire::schema(nom));
    enregistrer_registre(dossier, &sceaux)
}

/// Retire un fichier d'état et son sceau (Vanguard l'oublie lui-même).
fn effacer_dans(dossier: &Path, nom: &str) -> std::io::Result<()> {
    let _verrou = verrou(dossier);
    match std::fs::remove_file(dossier.join(nom)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    if let Ok(Some(mut r)) = registre(dossier)
        && (r.fichiers.remove(nom).is_some() | r.adoptes.remove(nom) | r.versions.remove(nom).is_some())
    {
        enregistrer_registre(dossier, &r)?;
    }
    Ok(())
}

fn dossier() -> PathBuf {
    crate::socle::dossier_local()
}

pub(crate) fn lire(nom: &str) -> Lecture {
    lire_dans(&dossier(), nom)
}

pub(crate) fn ecrire(nom: &str, octets: impl AsRef<[u8]>) -> std::io::Result<()> {
    ecrire_dans(&dossier(), nom, octets.as_ref())
}

pub(crate) fn effacer(nom: &str) -> std::io::Result<()> {
    effacer_dans(&dossier(), nom)
}

/// Ce que le bilan doit dire des fichiers d'état.
#[derive(Debug, PartialEq, Eq, Default)]
struct Releve {
    /// Changés hors de Vanguard.
    falsifies: Vec<&'static str>,
    /// Les sceaux eux-mêmes ne se lisent plus.
    illisibles: bool,
    /// Acceptés tels quels au premier usage, pas réécrits depuis.
    adoptes: Vec<&'static str>,
    /// Le jour de ce premier usage.
    depuis: String,
}

fn falsifies_dans(dossier: &Path) -> Releve {
    let mut r = Releve {
        illisibles: registre(dossier).is_err(),
        ..Releve::default()
    };
    for nom in proteges() {
        match lire_dans(dossier, nom) {
            Lecture::Falsifie(_) => r.falsifies.push(nom),
            Lecture::Adopte(_) => r.adoptes.push(nom),
            _ => {}
        }
    }
    if !r.adoptes.is_empty() {
        r.depuis = registre(dossier).ok().flatten().map(|s| s.depuis).unwrap_or_default();
    }
    r
}

/// La catégorie du constat.
const CAT: &str = "État de Vanguard";

/// Le constat d'après les fichiers falsifiés ; `copie_ancienne` : la copie de cet ordinateur (celle que lancent la
/// surveillance et l'entretien) est plus ancienne que ce programme, et elle écrit encore ces fichiers sans sceau.
fn juger_constat(falsifies: &[&str], illisibles: bool, copie_ancienne: bool) -> Option<Constat> {
    if falsifies.is_empty() {
        return None;
    }
    let liste = falsifies.join(", ");
    let mut message = if illisibles {
        trf!(
            "Les sceaux de l'état de Vanguard (sceaux.json) ne se lisent plus : {liste} ne peuvent pas être crus. Vanguard les traite comme vides (aucune alerte n'est tue) jusqu'à ce qu'il les réécrive.",
            "The seals of Vanguard's state (sceaux.json) can no longer be read: {liste} cannot be trusted. Vanguard treats them as empty (no alert is silenced) until it rewrites them."
        )
    } else {
        trf!(
            "L'état de Vanguard a été changé hors de Vanguard : {liste}. Un programme qui tourne sous ton compte a pu s'en servir pour faire taire une alerte ; Vanguard n'en tient plus compte (aucune alerte n'est tue) jusqu'à ce qu'il les réécrive.",
            "Vanguard's state was changed outside Vanguard: {liste}. A program running under your account may have used it to silence an alert; Vanguard ignores it (no alert is silenced) until it rewrites it."
        )
    };
    if copie_ancienne {
        message += tr!(
            " Cause probable : la copie de Vanguard de cet ordinateur est plus ancienne et écrit ces fichiers sans sceau ; mets-la à jour (« vanguard se-mettre-a-jour »).",
            " Likely cause: the copy of Vanguard on this computer is older and writes these files without a seal; update it (“vanguard se-mettre-a-jour”)."
        );
    }
    let niveau = if copie_ancienne { Niveau::Moyen } else { Niveau::Eleve };
    Some(
        crate::machine::alerte(CAT, niveau, message).manuel(
            tr!(
                "Regarde ce qui tourne sous ton compte (Protection › Qui parle à Internet ?) ; Ce que Vanguard a appris et « vanguard integrite --accepter » refont leurs fichiers",
                "Look at what runs under your account (Protection › Who talks to the Internet?); What Vanguard has learned and “vanguard integrity --accept” remake their files"
            ),
            &[],
        ),
    )
}

/// Les fichiers acceptés tels quels au premier usage : normal le jour où Vanguard est passé à une version qui
/// scelle, mais c'est aussi ce que donne `sceaux.json` effacé après qu'un programme a changé ces fichiers. Dit tant
/// que Vanguard ne les a pas réécrits, jamais compté comme sain.
fn juger_adoptes(adoptes: &[&str], depuis: &str) -> Option<Constat> {
    if adoptes.is_empty() {
        return None;
    }
    let liste = adoptes.join(", ");
    Some(
        crate::machine::alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "{liste} ont été acceptés tels quels le {depuis}, sans sceau d'avant. Si Vanguard n'a pas été mis à jour ce jour-là, sceaux.json a été effacé et ces fichiers ne peuvent pas être crus.",
                "{liste} were accepted as they were on {depuis}, without an earlier seal. If Vanguard was not updated that day, sceaux.json was deleted and these files cannot be trusted."
            ),
        )
        .manuel(
            tr!(
                "Ce que Vanguard a appris propose de garder tes choix ; « vanguard integrite --accepter » refait la référence ; les autres sont réécrits par la surveillance",
                "What Vanguard has learned offers to keep your choices; “vanguard integrity --accept” remakes the reference; monitoring rewrites the others"
            ),
            &[],
        ),
    )
}

/// Au bilan : rien tant que l'état de Vanguard est tel qu'il l'a écrit.
pub(crate) fn constat() -> Vec<Constat> {
    let r = falsifies_dans(&dossier());
    let mut constats: Vec<Constat> = juger_adoptes(&r.adoptes, &r.depuis).into_iter().collect();
    if !r.falsifies.is_empty() {
        constats.extend(juger_constat(
            &r.falsifies,
            r.illisibles,
            crate::mise_a_jour::copie_plus_ancienne(),
        ));
    }
    constats
}

/// Ce fichier d'état a-t-il été accepté tel quel au premier usage, sans être réécrit depuis ?
pub(crate) fn adopte(nom: &str) -> bool {
    matches!(lire(nom), Lecture::Adopte(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-sceau-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn ecrit_par_vanguard_puis_change_a_cote() {
        let d = jetable("change");
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Absent);
        ecrire_dans(&d, APPRIS, br#"{"acceptees":{}}"#).unwrap();
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Intact(br#"{"acceptees":{}}"#.to_vec()));
        // Une ligne ajoutée par un autre programme : falsifié, avec ce qu'il contient maintenant.
        std::fs::write(d.join(APPRIS), br#"{"acceptees":{"x":1}}"#).unwrap();
        assert_eq!(
            lire_dans(&d, APPRIS),
            Lecture::Falsifie(Some(br#"{"acceptees":{"x":1}}"#.to_vec()))
        );
        assert_eq!(falsifies_dans(&d).falsifies, vec![APPRIS]);
        // Réécrit par Vanguard : de nouveau intact.
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        assert_eq!(falsifies_dans(&d), Releve::default());
        // Supprimé hors de Vanguard : la référence des fichiers critiques disparue ne doit pas passer pour « pas
        // encore de référence ».
        ecrire_dans(&d, INTEGRITE, b"{}").unwrap();
        std::fs::remove_file(d.join(INTEGRITE)).unwrap();
        assert_eq!(lire_dans(&d, INTEGRITE), Lecture::Falsifie(None));
        // Oublié par Vanguard lui-même : absent, sans alerte.
        effacer_dans(&d, INTEGRITE).unwrap();
        assert_eq!(lire_dans(&d, INTEGRITE), Lecture::Absent);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn un_sceau_ne_vaut_que_pour_son_fichier() {
        let d = jetable("echange");
        ecrire_dans(&d, BOTNETS, b"1.2.3.4").unwrap();
        // Les sceaux recopiés d'un fichier à l'autre, contenu compris : falsifié quand même.
        let mut r = registre(&d).unwrap().unwrap();
        let sceau = r.fichiers[BOTNETS].clone();
        r.fichiers.insert(APPRIS.into(), sceau);
        enregistrer_registre(&d, &r).unwrap();
        std::fs::write(d.join(APPRIS), b"1.2.3.4").unwrap();
        assert!(matches!(lire_dans(&d, APPRIS), Lecture::Falsifie(Some(_))));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn les_fichiers_d_une_version_d_avant_sont_scelles_tels_quels() {
        let d = jetable("adoption");
        std::fs::create_dir_all(d.join("versions")).unwrap();
        std::fs::write(d.join(APPRIS), b"{}").unwrap();
        std::fs::write(d.join(VERSIONS), b"0.85.0+1792540000").unwrap();
        assert_eq!(lire_dans(&d, VERSIONS), Lecture::Adopte(b"0.85.0+1792540000".to_vec()));
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Adopte(b"{}".to_vec()));
        assert_ne!(registre(&d).unwrap().unwrap().depuis, "");
        // Réécrit par Vanguard : il n'est plus « adopté ».
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Intact(b"{}".to_vec()));
        // Ensuite, un fichier posé sans sceau (par un autre programme, ou par une copie d'avant les sceaux) ne l'est
        // plus : il est falsifié.
        std::fs::write(d.join(BOTNETS), b"5.6.7.8").unwrap();
        assert!(matches!(lire_dans(&d, BOTNETS), Lecture::Falsifie(Some(_))));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Des sceaux abîmés ne rendent jamais un fichier « intact » : rien n'est cru tant que Vanguard ne l'a pas
    /// réécrit, et le constat le dit.
    #[test]
    fn des_sceaux_abimes_ne_font_rien_croire() {
        let d = jetable("abimes");
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        ecrire_dans(&d, BOTNETS, b"").unwrap();
        std::fs::write(d.join(REGISTRE), b"{ pas du json").unwrap();
        assert!(matches!(lire_dans(&d, APPRIS), Lecture::Falsifie(Some(_))));
        let r = falsifies_dans(&d);
        assert_eq!((r.falsifies, r.illisibles), (vec![APPRIS, BOTNETS], true));
        let c = juger_constat(&[APPRIS, BOTNETS], true, false).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("sceaux.json"), "{}", c.message);
        // Vanguard réécrit l'un : il repart de lui, l'autre reste falsifié.
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Intact(b"{}".to_vec()));
        assert!(matches!(lire_dans(&d, BOTNETS), Lecture::Falsifie(Some(_))));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un programme du compte ajoute son alerte aux choix, puis efface les sceaux : le premier usage rejoué accepte
    /// la liste telle quelle, mais elle reste « adoptée », jamais intacte, et le bilan le dit.
    #[test]
    fn sceaux_effaces_jamais_en_silence() {
        let d = jetable("effaces");
        ecrire_dans(&d, APPRIS, br#"{"acceptees":{}}"#).unwrap();
        ecrire_dans(&d, BOTNETS, b"").unwrap();
        std::fs::write(d.join(APPRIS), br#"{"acceptees":{"x":1}}"#).unwrap();
        std::fs::remove_file(d.join(REGISTRE)).unwrap();
        assert_eq!(
            lire_dans(&d, APPRIS),
            Lecture::Adopte(br#"{"acceptees":{"x":1}}"#.to_vec())
        );
        let r = falsifies_dans(&d);
        assert_eq!((r.falsifies.len(), &r.adoptes), (0, &vec![APPRIS, BOTNETS]));
        let c = juger_adoptes(&r.adoptes, &r.depuis).unwrap();
        assert_eq!((c.categorie, c.probleme), (CAT, Some(Niveau::Moyen)));
        assert!(
            c.message.contains(APPRIS) && c.message.contains(&r.depuis),
            "{}",
            c.message
        );
        // Oublié par Vanguard : plus adopté.
        effacer_dans(&d, BOTNETS).unwrap();
        assert_eq!(falsifies_dans(&d).adoptes, vec![APPRIS]);
        assert!(juger_adoptes(&[], "").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une version d'avant écrivait reglages.json sans sceau, à côté de sceaux existants : à la mise à jour, il est
    /// adopté une fois (pas falsifié) ; ensuite, un fichier protégé tard posé sans sceau est falsifié comme un autre.
    #[test]
    fn un_fichier_protege_tard_est_adopte_une_fois() {
        let d = jetable("tardif");
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        // Les sceaux de cette version d'avant : sans « vus ».
        let mut r = registre(&d).unwrap().unwrap();
        r.vus.clear();
        enregistrer_registre(&d, &r).unwrap();
        std::fs::write(d.join(REGLAGES), br#"{"reglages":{}}"#).unwrap();
        assert_eq!(lire_dans(&d, REGLAGES), Lecture::Adopte(br#"{"reglages":{}}"#.to_vec()));
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Intact(b"{}".to_vec()));
        ecrire_dans(&d, REGLAGES, b"{}").unwrap();
        assert_eq!(lire_dans(&d, REGLAGES), Lecture::Intact(b"{}".to_vec()));
        // Passé ce premier regard : un fichier protégé tard posé sans sceau est falsifié.
        std::fs::write(d.join(NORMALES), b"{}").unwrap();
        assert!(matches!(lire_dans(&d, NORMALES), Lecture::Falsifie(Some(_))));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn constat_selon_la_cause_probable() {
        assert!(juger_constat(&[], false, true).is_none());
        let c = juger_constat(&[INTEGRITE], false, false).unwrap();
        assert_eq!((c.categorie, c.probleme), (CAT, Some(Niveau::Eleve)));
        assert!(c.message.contains(INTEGRITE) && !c.message.contains("se-mettre-a-jour"));
        // Une copie plus ancienne écrit encore sans sceau : la cause probable est dite, un cran plus bas.
        let c = juger_constat(&[BOTNETS], false, true).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("se-mettre-a-jour"), "{}", c.message);
    }

    #[test]
    fn ecritures_en_meme_temps_sans_fausse_alerte() {
        let d = jetable("ensemble");
        let fils: Vec<_> = proteges()
            .map(|nom| {
                let d = d.clone();
                std::thread::spawn(move || {
                    for i in 0..20 {
                        ecrire_dans(&d, nom, format!("{nom} {i}").as_bytes()).unwrap();
                        assert!(matches!(lire_dans(&d, nom), Lecture::Intact(_)), "{nom}");
                    }
                })
            })
            .collect();
        for f in fils {
            f.join().unwrap();
        }
        assert_eq!(falsifies_dans(&d), Releve::default());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les sceaux d'une version d'avant l'inventaire n'ont pas de versions de format : ils se relisent tels quels, et
    /// la prochaine écriture note la version de chaque fichier qu'elle scelle.
    #[test]
    fn sceaux_sans_versions_relus_puis_completes() {
        let d = jetable("versions");
        ecrire_dans(&d, APPRIS, br#"{"acceptees":{}}"#).unwrap();
        let mut brut: serde_json::Value = serde_json::from_slice(&std::fs::read(d.join(REGISTRE)).unwrap()).unwrap();
        assert_eq!(brut["versions"][APPRIS], 1);
        brut.as_object_mut().unwrap().remove("versions");
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&brut).unwrap()).unwrap();
        assert!(matches!(lire_dans(&d, APPRIS), Lecture::Intact(_)));
        ecrire_dans(&d, MACHINE, b"{}").unwrap();
        let r = registre(&d).unwrap().unwrap();
        assert_eq!(r.versions.get(MACHINE), Some(&1));
        assert_eq!(r.versions.get(APPRIS), None);
        effacer_dans(&d, MACHINE).unwrap();
        assert_eq!(registre(&d).unwrap().unwrap().versions.get(MACHINE), None);
        // Ce que protège le sceau, c'est l'inventaire qui le dit.
        assert_eq!(proteges().count(), crate::modele::inventaire::scelles().count());
        assert!(proteges().any(|n| n == WIFI_PUBLIC));
        let _ = std::fs::remove_dir_all(&d);
    }
}
