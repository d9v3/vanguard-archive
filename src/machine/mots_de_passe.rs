//! Mots de passe enregistrés dans les navigateurs : combien, et par quoi ils sont protégés. Firefox (et ses cousins)
//! les garde dans logins.json, chiffrés avec key4.db ; sans mot de passe principal, la clé est sur le disque à côté et
//! qui ouvre ta session (ou un programme malveillant) les lit tous ; Vanguard ne peut pas voir si ce mot de passe
//! principal est défini, et le dit. Chrome, Edge, Brave, Vivaldi et Chromium les gardent dans la base « Login Data »,
//! protégés seulement par la session (DPAPI sous Windows, trousseau sous macOS, porte-clés ou rien sous Linux). Vanguard
//! compte les entrées sans en lire une seule : logins.json est compté dans sa structure, la base SQLite est parcourue
//! page par page pour compter les lignes de la table « logins », sans décoder leur contenu ni dépendre de SQLite.

use std::path::Path;

use super::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::ui::*;

const CAT: &str = "Navigateur";

/// Les identifiants d'un profil : combien, et ce qui les protège.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Profil {
    navigateur: &'static str,
    nom: String,
    identifiants: usize,
    firefox: bool,
}

/// logins.json de Firefox : le nombre d'entrées de « logins » (chacune porte un site et deux champs chiffrés, qu'on
/// ne touche pas).
pub(super) fn compter_firefox(texte: &str) -> Option<usize> {
    let v: serde_json::Value = serde_json::from_str(texte).ok()?;
    Some(v.get("logins")?.as_array()?.len())
}

// ───────────────────────────── Un lecteur SQLite minimal ─────────────────────────────

/// Un fichier SQLite, lu en mémoire, juste assez pour compter les lignes d'une table : l'en-tête donne la taille des
/// pages, la page 1 porte la table des tables (sqlite_master) où se lit la page racine de « logins », puis l'arbre de
/// cette table se parcourt, feuille par feuille, en additionnant les nombres de cellules. Aucune cellule n'est décodée.
struct Sqlite<'a> {
    octets: &'a [u8],
    page: usize,
    /// Octets réservés à la fin de chaque page (presque toujours 0).
    reserve: usize,
}

/// Un entier variable de SQLite (1 à 9 octets) : (valeur, longueur).
fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    for (i, o) in b.iter().take(9).enumerate() {
        if i == 8 {
            return Some(((v << 8) | u64::from(*o), 9));
        }
        v = (v << 7) | u64::from(o & 0x7f);
        if o & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

fn u16be(b: &[u8], i: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?])))
}

fn u32be(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

/// Taille d'une colonne d'après son type de série (texte, blob, entier, nul) ; `None` pour un type inconnu.
fn taille_colonne(type_serie: u64) -> Option<usize> {
    Some(match type_serie {
        0 | 8 | 9 | 12 | 13 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 6,
        6 | 7 => 8,
        n if n >= 12 => usize::try_from((n - 12) / 2).ok()?,
        _ => return None,
    })
}

/// Un entier d'une colonne, d'après son type de série.
fn entier(type_serie: u64, b: &[u8]) -> Option<u64> {
    match type_serie {
        8 => Some(0),
        9 => Some(1),
        1..=6 => {
            let n = taille_colonne(type_serie)?;
            let mut v: u64 = 0;
            for o in b.get(..n)? {
                v = (v << 8) | u64::from(*o);
            }
            Some(v)
        }
        _ => None,
    }
}

impl<'a> Sqlite<'a> {
    fn ouvrir(octets: &'a [u8]) -> Option<Self> {
        if octets.get(..16)? != b"SQLite format 3\0" {
            return None;
        }
        let page = match u16be(octets, 16)? {
            1 => 65536,
            n if n.is_power_of_two() && n >= 512 => n,
            _ => return None,
        };
        Some(Sqlite {
            octets,
            page,
            reserve: usize::from(*octets.get(20)?),
        })
    }

    /// La page n (à partir de 1).
    fn page(&self, n: u32) -> Option<&'a [u8]> {
        let debut = usize::try_from(n).ok()?.checked_sub(1)?.checked_mul(self.page)?;
        self.octets.get(debut..debut.checked_add(self.page)?)
    }

    /// Les cellules d'une page d'arbre : (type de page, positions des cellules, enfant de droite).
    fn cellules(&self, numero: u32) -> Option<(u8, Vec<usize>, Option<u32>)> {
        let p = self.page(numero)?;
        let base = if numero == 1 { 100 } else { 0 };
        let genre = *p.get(base)?;
        let n = u16be(p, base + 3)?;
        let (droite, entete) = if genre == 0x05 || genre == 0x02 {
            (Some(u32be(p, base + 8)?), 12)
        } else {
            (None, 8)
        };
        let positions = (0..n)
            .map(|i| u16be(p, base + entete + 2 * i))
            .collect::<Option<Vec<usize>>>()?;
        Some((genre, positions, droite))
    }

    /// Nombre de lignes de l'arbre d'une table, à partir de sa page racine. Une page déjà vue est refusée : dans un
    /// vrai arbre, chaque page n'a qu'un parent ; un fichier abîmé dont une page renvoie à elle-même (ou plusieurs
    /// fois à la même) ferait sinon des milliards de chemins et figerait le bilan, malgré la limite de profondeur.
    fn compter(&self, racine: u32, profondeur: usize, vues: &mut std::collections::HashSet<u32>) -> Option<usize> {
        if profondeur > 20 || !vues.insert(racine) {
            return None;
        }
        let (genre, positions, droite) = self.cellules(racine)?;
        match genre {
            0x0d => Some(positions.len()),
            0x05 => {
                let p = self.page(racine)?;
                let mut total = 0;
                for pos in positions {
                    total += self.compter(u32be(p, pos)?, profondeur + 1, vues)?;
                }
                Some(total + self.compter(droite?, profondeur + 1, vues)?)
            }
            _ => None,
        }
    }

    /// La page racine de la table `nom`, lue dans sqlite_master (page 1 : type, name, tbl_name, rootpage, sql).
    fn racine_de(
        &self,
        nom: &str,
        page: u32,
        profondeur: usize,
        vues: &mut std::collections::HashSet<u32>,
    ) -> Option<u32> {
        if profondeur > 20 || !vues.insert(page) {
            return None;
        }
        let (genre, positions, droite) = self.cellules(page)?;
        let p = self.page(page)?;
        match genre {
            0x0d => {
                for pos in positions {
                    if let Some(r) = Self::ligne_de_master(p, pos, nom) {
                        return Some(r);
                    }
                }
                None
            }
            0x05 => positions
                .into_iter()
                .filter_map(|pos| u32be(p, pos))
                .chain(droite)
                .find_map(|enfant| self.racine_de(nom, enfant, profondeur + 1, vues)),
            _ => None,
        }
    }

    /// Une cellule de sqlite_master : la page racine si c'est la table `nom`. Les quatre premières colonnes tiennent
    /// toujours dans la partie locale de la cellule (seul le texte SQL, après elles, peut déborder).
    fn ligne_de_master(p: &[u8], pos: usize, nom: &str) -> Option<u32> {
        let (_, l1) = varint(p.get(pos..)?)?;
        let (_, l2) = varint(p.get(pos + l1..)?)?;
        let enregistrement = p.get(pos + l1 + l2..)?;
        let (taille_entete, l3) = varint(enregistrement)?;
        let taille_entete = usize::try_from(taille_entete).ok()?;
        let mut types = Vec::new();
        let mut i = l3;
        while i < taille_entete {
            let (t, l) = varint(enregistrement.get(i..taille_entete)?)?;
            types.push(t);
            i += l;
        }
        let [t_type, t_nom, t_table, t_racine, ..] = types[..] else {
            return None;
        };
        let mut i = taille_entete;
        let champ = |i: &mut usize, t: u64| -> Option<&[u8]> {
            let n = taille_colonne(t)?;
            let c = enregistrement.get(*i..i.checked_add(n)?)?;
            *i += n;
            Some(c)
        };
        let genre = champ(&mut i, t_type)?;
        let nom_lu = champ(&mut i, t_nom)?;
        champ(&mut i, t_table)?;
        let racine = champ(&mut i, t_racine)?;
        (genre == b"table" && nom_lu == nom.as_bytes())
            .then(|| entier(t_racine, racine))
            .flatten()
            .and_then(|r| u32::try_from(r).ok())
    }
}

/// Le nombre de lignes de la table `table` d'un fichier SQLite ; `None` si le fichier ne se lit pas ainsi.
pub(super) fn compter_lignes(octets: &[u8], table: &str) -> Option<usize> {
    let db = Sqlite::ouvrir(octets)?;
    // L'octet de réserve ne change pas la lecture des en-têtes ; il est lu pour refuser un fichier incohérent.
    if db.reserve >= db.page {
        return None;
    }
    let racine = db.racine_de(table, 1, 0, &mut std::collections::HashSet::new())?;
    db.compter(racine, 0, &mut std::collections::HashSet::new())
}

// ───────────────────────────── Les profils ─────────────────────────────

/// Les profils des navigateurs installés et ce qu'ils gardent ; `Err` : le fichier existe mais ne se lit pas.
fn profils() -> Vec<Result<Profil, (String, String)>> {
    let mut liste = Vec::new();
    for (navigateur, racine, firefox) in super::extensions::racines() {
        for (nom, chemin) in super::extensions::profils(&racine, firefox) {
            if firefox {
                let f = chemin.join("logins.json");
                if !f.is_file() {
                    continue;
                }
                match std::fs::read_to_string(&f).ok().and_then(|t| compter_firefox(&t)) {
                    Some(n) => liste.push(Ok(Profil {
                        navigateur,
                        nom,
                        identifiants: n,
                        firefox: true,
                    })),
                    None => liste.push(Err((navigateur.to_string(), format!("{nom}/logins.json")))),
                }
            } else {
                let mut total = 0;
                let mut lus = 0;
                for base in ["Login Data", "Login Data For Account"] {
                    let f = chemin.join(base);
                    if !f.is_file() {
                        continue;
                    }
                    match compter_base(&f) {
                        Some(n) => {
                            total += n;
                            lus += 1;
                        }
                        None => liste.push(Err((navigateur.to_string(), format!("{nom}/{base}")))),
                    }
                }
                if lus > 0 {
                    liste.push(Ok(Profil {
                        navigateur,
                        nom,
                        identifiants: total,
                        firefox: false,
                    }));
                }
            }
        }
    }
    liste
}

/// Les lignes de « logins » d'une base, lue d'un coup (quelques Mo au plus : au-delà, on renonce).
fn compter_base(chemin: &Path) -> Option<usize> {
    let taille = std::fs::metadata(chemin).ok()?.len();
    if taille > 64 << 20 {
        return None;
    }
    compter_lignes(&std::fs::read(chemin).ok()?, "logins")
}

/// Ce qui protège les identifiants d'un navigateur Chromium sur ce système.
fn protection_chromium() -> &'static str {
    if cfg!(windows) {
        tr!(
            "protégés par ta session Windows seulement (DPAPI) : qui ouvre ta session, ou un programme qui tourne dedans, les lit",
            "protected by your Windows session only (DPAPI): whoever opens your session, or a program running in it, reads them"
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "la clé est dans le trousseau : un programme qui tourne dans ta session peut la demander",
            "the key is in the keychain: a program running in your session can ask for it"
        )
    } else {
        tr!(
            "la clé est dans le porte-clés du bureau, ou en clair s'il n'y en a pas : qui ouvre ta session les lit",
            "the key is in the desktop keyring, or in clear if there is none: whoever opens your session reads them"
        )
    }
}

pub(super) fn juger(profils: &[Result<Profil, (String, String)>]) -> Vec<Constat> {
    let mut constats = Vec::new();
    for (navigateur, fichier) in profils.iter().filter_map(|p| p.as_ref().err()) {
        constats.push(impossible(
            CAT,
            &trf!(
                "{navigateur} : {fichier} illisible",
                "{navigateur}: {fichier} unreadable"
            ),
        ));
    }
    let pleins: Vec<&Profil> = profils.iter().flatten().filter(|p| p.identifiants > 0).collect();
    let total: usize = pleins.iter().map(|p| p.identifiants).sum();
    if pleins.is_empty() {
        if profils.iter().any(Result::is_ok) {
            constats.push(ok(
                CAT,
                tr!(
                    "Aucun mot de passe enregistré dans les navigateurs.",
                    "No password saved in the browsers."
                ),
            ));
        }
        return constats;
    }
    let ou: Vec<String> = pleins
        .iter()
        .map(|p| {
            if p.nom == "Default" || p.nom == "default" {
                format!("{} ({})", p.navigateur, p.identifiants)
            } else {
                format!("{} « {} » ({})", p.navigateur, p.nom, p.identifiants)
            }
        })
        .collect();
    let firefox = pleins.iter().any(|p| p.firefox);
    let chromium = pleins.iter().any(|p| !p.firefox);
    let mut protection = Vec::new();
    if firefox {
        protection.push(tr!(
            "Firefox : Vanguard ne peut pas voir si un mot de passe principal les protège ; sans lui, qui ouvre ta session les lit tous",
            "Firefox: Vanguard cannot see whether a primary password protects them; without one, whoever opens your session reads them all"
        ).to_string());
    }
    if chromium {
        protection.push(trf!(
            "Chrome et cousins : {}",
            "Chrome and similar browsers: {}",
            protection_chromium()
        ));
    }
    constats.push(
        alerte(
            CAT,
            Niveau::Info,
            trf!(
                "{total} mot(s) de passe enregistré(s) dans {} : {}. Comptés seulement, jamais lus.",
                "{total} saved password(s) in {}: {}. Counted only, never read.",
                ou.join(", "),
                protection.join(" ; ")
            ),
        )
        .manuel(
            if firefox {
                tr!(
                    "Un gestionnaire de mots de passe (Bitwarden, KeePassXC), ou au moins le mot de passe principal de Firefox (Paramètres > Vie privée et sécurité > Identifiants)",
                    "A password manager (Bitwarden, KeePassXC), or at least Firefox's primary password (Settings > Privacy & Security > Logins)"
                )
            } else {
                tr!(
                    "Un gestionnaire de mots de passe (Bitwarden, KeePassXC) avec son propre mot de passe principal, et le verrouillage de l'écran quand tu t'éloignes",
                    "A password manager (Bitwarden, KeePassXC) with its own primary password, and the screen lock when you step away"
                )
            },
            &[],
        ),
    );
    constats
}

/// Au bilan.
pub fn constats() -> Vec<Constat> {
    juger(&profils())
}

// ───────────────────────────── La commande « navigateurs » ─────────────────────────────

/// La vérification intégrée d'un navigateur présent, à conseiller à la personne : c'est elle qui
/// trouve les mots de passe faibles, réutilisés ou compromis, en sécurité, dans le navigateur.
#[derive(Debug, PartialEq, Eq)]
enum Checkup {
    Firefox,
    Chrome,
    Edge,
    Autre(&'static str),
}

/// Quelles vérifications intégrées montrer, d'après les familles qui ont des mots de passe
/// enregistrés (sans doublon, dans l'ordre où elles apparaissent). Un profil illisible n'invente
/// pas une famille ; un profil vide non plus.
fn checkups(profils: &[Result<Profil, (String, String)>]) -> Vec<Checkup> {
    let mut v: Vec<Checkup> = Vec::new();
    for p in profils.iter().flatten().filter(|p| p.identifiants > 0) {
        let c = if p.firefox {
            Checkup::Firefox
        } else {
            match p.navigateur {
                "Chrome" | "Chromium" => Checkup::Chrome,
                "Edge" => Checkup::Edge,
                autre => Checkup::Autre(autre),
            }
        };
        if !v.contains(&c) {
            v.push(c);
        }
    }
    v
}

/// « vanguard navigateurs » : l'état des mots de passe enregistrés dans les navigateurs (comptés,
/// jamais lus), où lancer la vérification intégrée de chaque navigateur pour trouver les faibles,
/// réutilisés et compromis, puis la vérification HIBP d'un mot de passe tapé. Vanguard ne lit ni ne
/// déchiffre jamais un mot de passe enregistré : les lire, c'est le geste d'un voleur de mots de
/// passe, et un antivirus classerait alors Vanguard comme malveillant.
pub(crate) fn navigateurs() {
    titre(tr!("Mots de passe des navigateurs", "Browser passwords"));
    let profils = profils();
    // 1. L'état, repris du bilan : comptés, jamais lus.
    let constats = juger(&profils);
    if constats.is_empty() {
        trp!(
            "  Aucun navigateur avec des mots de passe enregistrés n'a été trouvé.",
            "  No browser with saved passwords was found."
        );
    } else {
        for constat in &constats {
            let puce = match constat.probleme {
                None => format!("{VERT}✔{RESET}"),
                Some(niveau) => format!("{}•{RESET}", couleur(niveau)),
            };
            println!("  {puce} {}", constat.message);
        }
    }
    // 2. Ce que Vanguard ne fait pas, et pourquoi : c'est une garantie, pas une limite.
    trp!(
        "\n  {GRIS}Vanguard ne lit ni ne déchiffre jamais tes mots de passe enregistrés : les lire, c'est le\n  geste d'un voleur de mots de passe. Il les compte seulement, et te renvoie à ton navigateur.{RESET}",
        "\n  {GRIS}Vanguard never reads or decrypts your saved passwords: reading them is what a password\n  stealer does. It only counts them, and points you to your browser.{RESET}"
    );
    // 3. La vérification intégrée de chaque navigateur présent (faibles, réutilisés, compromis).
    let a_montrer = checkups(&profils);
    if !a_montrer.is_empty() {
        trp!(
            "\n  {} Pour les mots de passe faibles, réutilisés ou compromis, ouvre la vérification intégrée\n     de ton navigateur (copie l'adresse dans sa barre) :",
            "\n  {} For weak, reused or compromised passwords, open your browser's built-in check\n     (paste the address into its bar):",
            ampoule()
        );
        for c in a_montrer {
            let (quoi, adresse): (&str, &str) = match c {
                Checkup::Firefox => (tr!("Firefox et cousins", "Firefox and similar"), "about:logins"),
                Checkup::Chrome => ("Chrome / Chromium", "chrome://password-manager/checkup"),
                Checkup::Edge => ("Edge", "edge://settings/passwords"),
                Checkup::Autre(nom) => (
                    nom,
                    tr!(
                        "gestionnaire de mots de passe du navigateur",
                        "the browser's password manager"
                    ),
                ),
            };
            println!("       {quoi} : {GRIS}{adresse}{RESET}");
        }
    }
    // 4. Vérifier un mot de passe précis, tapé maintenant : jamais affiché, jamais écrit, seuls 5
    //    caractères de son empreinte partent (réutilise la vérification HIBP existante).
    trp!(
        "\n  Tu peux aussi vérifier un mot de passe précis : il ne s'affiche pas, ne quitte pas cet\n  ordinateur, et seuls 5 caractères de son empreinte partent vers Have I Been Pwned.",
        "\n  You can also check a specific password: it is not shown, it does not leave this computer,\n  and only 5 characters of its fingerprint are sent to Have I Been Pwned."
    );
    if demander(tr!(
        "  Vérifier un mot de passe maintenant ? [o/N] : ",
        "  Check a password now? [y/N]: "
    ))
    .oui()
    {
        println!();
        crate::protection::fuites::verifier();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logins_de_firefox_comptes_sans_les_lire() {
        let texte = r#"{"nextId":3,"logins":[{"id":1,"hostname":"https://exemple.test","encryptedUsername":"MDoE","encryptedPassword":"MFIE","encType":1},{"id":2,"hostname":"https://autre.test","encryptedUsername":"MDoE","encryptedPassword":"MFIE","encType":1}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}"#;
        assert_eq!(compter_firefox(texte), Some(2));
        assert_eq!(compter_firefox(r#"{"nextId":1,"logins":[],"version":3}"#), Some(0));
        assert_eq!(compter_firefox("pas du json"), None);
        assert_eq!(compter_firefox(r#"{"version":3}"#), None);
    }

    #[test]
    fn lignes_de_login_data_comptees_page_par_page() {
        let vide = include_bytes!("../../assets/essais/login-data-vide.sqlite");
        let trois = include_bytes!("../../assets/essais/login-data-3.sqlite");
        // 300 lignes sur des pages de 512 octets : l'arbre a des pages intérieures.
        let trois_cents = include_bytes!("../../assets/essais/login-data-300.sqlite");
        assert_eq!(compter_lignes(vide, "logins"), Some(0));
        assert_eq!(compter_lignes(trois, "logins"), Some(3));
        assert_eq!(compter_lignes(trois_cents, "logins"), Some(300));
        assert_eq!(compter_lignes(trois, "meta"), Some(2));
        assert_eq!(compter_lignes(trois, "inexistante"), None);
        assert_eq!(compter_lignes(b"pas une base", "logins"), None);
        assert_eq!(compter_lignes(&trois[..3000], "logins"), None);
        // Un fichier abîmé : chaque cellule de la page racine (intérieure) renvoie à cette même page. Avant, des
        // milliards de chemins ; maintenant, refusé tout de suite.
        let db = Sqlite::ouvrir(trois_cents).unwrap();
        let racine = db
            .racine_de("logins", 1, 0, &mut std::collections::HashSet::new())
            .unwrap();
        let (genre, positions, _) = db.cellules(racine).unwrap();
        assert_eq!(genre, 0x05, "la racine doit être une page intérieure pour cet essai");
        let mut piege = trois_cents.to_vec();
        let debut = (racine as usize - 1) * db.page;
        for pos in positions {
            piege[debut + pos..debut + pos + 4].copy_from_slice(&racine.to_be_bytes());
        }
        let avant = std::time::Instant::now();
        assert_eq!(compter_lignes(&piege, "logins"), None);
        assert!(avant.elapsed() < std::time::Duration::from_secs(1));
        // Les entiers variables de SQLite.
        assert_eq!(varint(&[0x05]), Some((5, 1)));
        assert_eq!(varint(&[0x81, 0x00]), Some((128, 2)));
        assert_eq!(varint(&[0xff; 9]), Some((u64::MAX, 9)));
        assert_eq!(varint(&[0x80]), None);
        assert_eq!(taille_colonne(13), Some(0));
        assert_eq!(taille_colonne(27), Some(7));
        assert_eq!(taille_colonne(10), None);
        assert_eq!(entier(1, &[7]), Some(7));
        assert_eq!(entier(2, &[1, 0]), Some(256));
    }

    #[test]
    fn jugement_selon_les_profils() {
        let profil = |navigateur, nom: &str, n, firefox| Profil {
            navigateur,
            nom: nom.into(),
            identifiants: n,
            firefox,
        };
        assert!(juger(&[]).is_empty());
        let rien = juger(&[Ok(profil("Chrome", "Default", 0, false))]);
        assert_eq!(rien.len(), 1);
        assert_eq!(rien[0].probleme, None);
        let c = juger(&[
            Ok(profil("Firefox", "abc.default-release", 12, true)),
            Ok(profil("Chrome", "Default", 3, false)),
            Ok(profil("Brave", "Default", 0, false)),
            Err(("Edge".into(), "Default/Login Data".into())),
        ]);
        assert_eq!(c.len(), 2);
        assert!(!c[0].verifie && c[0].message.contains("Edge"));
        assert_eq!(c[1].probleme, Some(Niveau::Info));
        assert!(c[1].message.starts_with("15 mot(s) de passe"), "{}", c[1].message);
        assert!(
            c[1].message
                .contains("Firefox « abc.default-release » (12), Chrome (3)"),
            "{}",
            c[1].message
        );
        assert!(c[1].message.contains("mot de passe principal") && c[1].message.contains("Chrome et cousins"));
        assert!(
            c[1].correctif
                .as_ref()
                .is_some_and(|k| !k.automatique && k.action.contains("Firefox"))
        );
    }

    #[test]
    fn checkups_selon_les_familles_presentes() {
        let lu = |navigateur, nom: &str, n, firefox| {
            Ok(Profil {
                navigateur,
                nom: nom.into(),
                identifiants: n,
                firefox,
            })
        };
        // Rien à montrer : aucun profil, ou seulement des profils vides.
        assert_eq!(checkups(&[]), Vec::<Checkup>::new());
        assert_eq!(checkups(&[lu("Firefox", "x.default", 0, true)]), Vec::<Checkup>::new());
        // Les familles sont dédoublonnées (Zen = Firefox, Chromium = Chrome) et gardent leur ordre ;
        // un profil illisible n'invente pas de famille.
        let c = checkups(&[
            lu("Firefox", "x.default-release", 3, true),
            lu("Zen", "y.default", 2, true),
            lu("Chrome", "Default", 5, false),
            lu("Chromium", "Default", 1, false),
            lu("Edge", "Default", 4, false),
            lu("Brave", "Default", 1, false),
            Err(("Vivaldi".into(), "Default/Login Data".into())),
        ]);
        assert_eq!(
            c,
            vec![
                Checkup::Firefox,
                Checkup::Chrome,
                Checkup::Edge,
                Checkup::Autre("Brave")
            ]
        );
    }
}
