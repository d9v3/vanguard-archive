//! Lecteur GVDB et GVariant, en lecture seule : le format des bases de dconf (`~/.config/dconf/user`,
//! `/etc/dconf/db/*`), des schémas compilés de GSettings (`gschemas.compiled`) et des autorisations que gardent les
//! portails de Flatpak (`~/.local/share/flatpak/db/*`).
//!
//! Pourquoi : `gsettings get` et `flatpak permissions` ne font que lire ces fichiers. Les lire ici évite un
//! programme qui peut manquer, être remplacé dans le PATH, ou attendre un service D-Bus ; la commande reste en
//! secours quand le fichier ne se lit pas.
//!
//! GVDB : un en-tête (« GVariant », version, racine), puis des tables de hachage. Chaque élément d'une table a un
//! nom (dont le début peut se trouver chez un élément parent : dconf range ainsi `/org/gnome/` puis `desktop/`), un
//! genre (`v` une valeur, `H` une table imbriquée, `L` une liste) et un pointeur vers ses données. Les noms sont
//! rebâtis en entier une fois pour toutes, plutôt que de refaire le hachage de GLib : une table de ces fichiers a
//! au plus quelques milliers d'éléments.
//!
//! GVariant : la forme sérialisée de GLib (types de taille fixe alignés, chaînes terminées par un zéro, décalages de
//! fin rangés en queue des tableaux et des n-uplets). Tout est vérifié : un fichier tronqué ou forgé rend `None`,
//! jamais une valeur inventée ni une panique. Seuls les fichiers petit-boutistes sont lus (ceux qu'écrit un PC ou un
//! ARM sous Linux) ; un autre rend `None` et la commande prend le relais.

use std::collections::HashMap;
use std::fmt::Write;
use std::rc::Rc;

/// Profondeur d'imbrication des types et des valeurs au-delà de laquelle une donnée est refusée : GLib n'en
/// produit pas d'aussi profondes, et une donnée forgée ne doit pas épuiser la pile.
const PROFONDEUR_MAX: usize = 64;

// ---------------------------------------------------------------------------------------------------------------
// Fichier et tables

/// Un fichier GVDB lu en mémoire.
pub(crate) struct Gvdb {
    octets: Rc<[u8]>,
}

/// Un élément d'une table : son genre et l'étendue de ses données dans le fichier.
#[derive(Clone, Copy)]
struct Element {
    genre: u8,
    debut: usize,
    fin: usize,
}

/// Une table de hachage du fichier, ses éléments rangés par nom complet.
pub(crate) struct Table {
    octets: Rc<[u8]>,
    elements: HashMap<String, Element>,
}

fn u32_le(octets: &[u8], position: usize) -> Option<u32> {
    let mot = octets.get(position..position.checked_add(4)?)?;
    Some(u32::from_le_bytes(mot.try_into().ok()?))
}

fn u16_le(octets: &[u8], position: usize) -> Option<u16> {
    let mot = octets.get(position..position.checked_add(2)?)?;
    Some(u16::from_le_bytes(mot.try_into().ok()?))
}

impl Gvdb {
    /// `None` : pas un fichier GVDB lisible ici (signature, version, ou ordre des octets d'une autre machine).
    pub(crate) fn depuis(octets: Vec<u8>) -> Option<Gvdb> {
        if octets.get(..8)? != b"GVariant" || u32_le(&octets, 8)? != 0 {
            return None;
        }
        Some(Gvdb { octets: octets.into() })
    }

    pub(crate) fn racine(&self) -> Option<Table> {
        let debut = u32_le(&self.octets, 16)? as usize;
        let fin = u32_le(&self.octets, 20)? as usize;
        Table::lire(Rc::clone(&self.octets), debut, fin)
    }
}

impl Table {
    fn lire(octets: Rc<[u8]>, debut: usize, fin: usize) -> Option<Table> {
        if !debut.is_multiple_of(4) || debut > fin {
            return None;
        }
        let zone = octets.get(debut..fin)?;
        // Les 5 bits du haut du premier mot donnent le décalage du filtre de Bloom, inutile à qui lit tout.
        let mots_bloom = (u32_le(zone, 0)? & ((1 << 27) - 1)) as usize;
        let seaux = u32_le(zone, 4)? as usize;
        let debut_elements = mots_bloom.checked_add(seaux)?.checked_mul(4)?.checked_add(8)?;
        let place = zone.len().checked_sub(debut_elements)?;
        let n = place / 24;
        let mut bruts = Vec::with_capacity(n);
        for i in 0..n {
            let e = debut_elements + 24 * i;
            let parent = u32_le(zone, e + 4)?;
            let debut_nom = u32_le(zone, e + 8)? as usize;
            let longueur_nom = usize::from(u16_le(zone, e + 12)?);
            let nom = octets.get(debut_nom..debut_nom.checked_add(longueur_nom)?)?;
            let element = Element {
                genre: zone[e + 14],
                debut: u32_le(zone, e + 16)? as usize,
                fin: u32_le(zone, e + 20)? as usize,
            };
            bruts.push((parent, nom, element));
        }
        let mut elements = HashMap::with_capacity(n);
        for (i, (_, _, element)) in bruts.iter().enumerate() {
            // Le nom complet, des parents vers l'élément ; une boucle de parents forgée s'arrête à n pas.
            let mut morceaux = Vec::new();
            let mut courant = i;
            loop {
                let (parent, nom, _) = bruts[courant];
                morceaux.push(nom);
                if parent == u32::MAX {
                    break;
                }
                courant = parent as usize;
                if courant >= n || morceaux.len() > n {
                    return None;
                }
            }
            let complet: Vec<u8> = morceaux.iter().rev().flat_map(|m| m.iter().copied()).collect();
            let Ok(nom) = String::from_utf8(complet) else {
                continue;
            };
            elements.insert(nom, *element);
        }
        drop(bruts);
        Some(Table { octets, elements })
    }

    fn donnees(&self, nom: &str, genre: u8) -> Option<(&[u8], Element)> {
        let e = *self.elements.get(nom).filter(|e| e.genre == genre)?;
        if e.debut > e.fin {
            return None;
        }
        Some((self.octets.get(e.debut..e.fin)?, e))
    }

    /// La valeur rangée sous `nom` (genre `v`), avec son type ; `None` si elle manque ou ne se lit pas.
    pub(crate) fn valeur(&self, nom: &str) -> Option<Variante> {
        let (octets, _) = self.donnees(nom, b'v')?;
        match decoder(&Genre::Variante, octets, 0)? {
            Variante::Boite(v) => Some(*v),
            _ => None,
        }
    }

    /// La table imbriquée rangée sous `nom` (genre `H`).
    pub(crate) fn table(&self, nom: &str) -> Option<Table> {
        let (_, e) = self.donnees(nom, b'H')?;
        Table::lire(Rc::clone(&self.octets), e.debut, e.fin)
    }

    /// Un élément de genre `v` porte ce nom (ce que regarde dconf dans la table des verrous).
    pub(crate) fn contient_valeur(&self, nom: &str) -> bool {
        self.elements.get(nom).is_some_and(|e| e.genre == b'v')
    }

    /// Les noms des valeurs de la table (genre `v`), dans un ordre quelconque.
    pub(crate) fn noms_des_valeurs(&self) -> impl Iterator<Item = &str> {
        self.elements
            .iter()
            .filter(|(_, e)| e.genre == b'v')
            .map(|(n, _)| n.as_str())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Types GVariant

/// Un type GVariant. `Simple` : une lettre de base (b y n q i u x t h d s o g).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Genre {
    Simple(u8),
    Variante,
    Tableau(Box<Genre>),
    Peut(Box<Genre>),
    Tuple(Vec<Genre>),
    Entree(Box<Genre>, Box<Genre>),
}

const SIMPLES: &[u8] = b"bynqiuxthdsog";

impl Genre {
    /// Un type complet, et rien d'autre, depuis sa chaîne (« as », « (s(yau)) »…).
    pub(crate) fn depuis(texte: &[u8]) -> Option<Genre> {
        let mut position = 0;
        let g = lire_genre(texte, &mut position, 0)?;
        (position == texte.len()).then_some(g)
    }

    pub(crate) fn chaine(&self) -> String {
        match self {
            Genre::Simple(c) => char::from(*c).to_string(),
            Genre::Variante => "v".to_string(),
            Genre::Tableau(e) => format!("a{}", e.chaine()),
            Genre::Peut(e) => format!("m{}", e.chaine()),
            Genre::Tuple(m) => format!("({})", m.iter().map(Genre::chaine).collect::<String>()),
            Genre::Entree(k, v) => format!("{{{}{}}}", k.chaine(), v.chaine()),
        }
    }

    fn alignement(&self) -> usize {
        match self {
            Genre::Simple(b'n' | b'q') => 2,
            Genre::Simple(b'i' | b'u' | b'h') => 4,
            Genre::Simple(b'x' | b't' | b'd') | Genre::Variante => 8,
            Genre::Simple(_) => 1,
            Genre::Tableau(e) | Genre::Peut(e) => e.alignement(),
            Genre::Tuple(m) => m.iter().map(Genre::alignement).max().unwrap_or(1),
            Genre::Entree(k, v) => k.alignement().max(v.alignement()),
        }
    }

    /// La taille d'une valeur de ce type quand elle est fixe ; `None` pour les chaînes, tableaux, variantes…
    fn taille_fixe(&self) -> Option<usize> {
        match self {
            Genre::Simple(b'b' | b'y') => Some(1),
            Genre::Simple(b'n' | b'q') => Some(2),
            Genre::Simple(b'i' | b'u' | b'h') => Some(4),
            Genre::Simple(b'x' | b't' | b'd') => Some(8),
            Genre::Simple(_) | Genre::Variante | Genre::Tableau(_) | Genre::Peut(_) => None,
            Genre::Tuple(m) => taille_membres(m.iter(), self.alignement()),
            Genre::Entree(k, v) => taille_membres([k.as_ref(), v.as_ref()].into_iter(), self.alignement()),
        }
    }

    fn membres(&self) -> Vec<&Genre> {
        match self {
            Genre::Tuple(m) => m.iter().collect(),
            Genre::Entree(k, v) => vec![k, v],
            _ => Vec::new(),
        }
    }
}

fn taille_membres<'a>(membres: impl Iterator<Item = &'a Genre>, alignement: usize) -> Option<usize> {
    let mut taille = 0;
    for m in membres {
        taille = aligner(taille, m.alignement())? + m.taille_fixe()?;
    }
    // Un n-uplet vide occupe tout de même un octet.
    Some(aligner(taille, alignement)?.max(1))
}

fn aligner(position: usize, alignement: usize) -> Option<usize> {
    Some(position.checked_add(alignement - 1)? / alignement * alignement)
}

fn lire_genre(texte: &[u8], position: &mut usize, profondeur: usize) -> Option<Genre> {
    if profondeur > PROFONDEUR_MAX {
        return None;
    }
    let c = *texte.get(*position)?;
    *position += 1;
    Some(match c {
        b'v' => Genre::Variante,
        b'a' => Genre::Tableau(Box::new(lire_genre(texte, position, profondeur + 1)?)),
        b'm' => Genre::Peut(Box::new(lire_genre(texte, position, profondeur + 1)?)),
        b'(' => {
            let mut membres = Vec::new();
            while *texte.get(*position)? != b')' {
                membres.push(lire_genre(texte, position, profondeur + 1)?);
            }
            *position += 1;
            Genre::Tuple(membres)
        }
        b'{' => {
            let cle = lire_genre(texte, position, profondeur + 1)?;
            // La clé d'un dictionnaire est toujours d'un type de base.
            if !matches!(cle, Genre::Simple(_)) {
                return None;
            }
            let valeur = lire_genre(texte, position, profondeur + 1)?;
            if *texte.get(*position)? != b'}' {
                return None;
            }
            *position += 1;
            Genre::Entree(Box::new(cle), Box::new(valeur))
        }
        c if SIMPLES.contains(&c) => Genre::Simple(c),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Valeurs GVariant

/// Une valeur GVariant décodée.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Variante {
    Booleen(bool),
    Octet(u8),
    Entier16(i16),
    Naturel16(u16),
    Entier32(i32),
    Naturel32(u32),
    Entier64(i64),
    Naturel64(u64),
    Poignee(i32),
    Double(f64),
    Chaine(String),
    Objet(String),
    Signature(String),
    Boite(Box<Variante>),
    /// Type de l'élément, et la valeur s'il y en a une.
    Peut(Genre, Option<Box<Variante>>),
    /// Type des éléments, et les éléments.
    Tableau(Genre, Vec<Variante>),
    Tuple(Vec<Variante>),
    Entree(Box<Variante>, Box<Variante>),
}

impl Variante {
    pub(crate) fn genre(&self) -> Genre {
        match self {
            Variante::Booleen(_) => Genre::Simple(b'b'),
            Variante::Octet(_) => Genre::Simple(b'y'),
            Variante::Entier16(_) => Genre::Simple(b'n'),
            Variante::Naturel16(_) => Genre::Simple(b'q'),
            Variante::Entier32(_) => Genre::Simple(b'i'),
            Variante::Naturel32(_) => Genre::Simple(b'u'),
            Variante::Entier64(_) => Genre::Simple(b'x'),
            Variante::Naturel64(_) => Genre::Simple(b't'),
            Variante::Poignee(_) => Genre::Simple(b'h'),
            Variante::Double(_) => Genre::Simple(b'd'),
            Variante::Chaine(_) => Genre::Simple(b's'),
            Variante::Objet(_) => Genre::Simple(b'o'),
            Variante::Signature(_) => Genre::Simple(b'g'),
            Variante::Boite(_) => Genre::Variante,
            Variante::Peut(g, _) => Genre::Peut(Box::new(g.clone())),
            Variante::Tableau(g, _) => Genre::Tableau(Box::new(g.clone())),
            Variante::Tuple(m) => Genre::Tuple(m.iter().map(Variante::genre).collect()),
            Variante::Entree(k, v) => Genre::Entree(Box::new(k.genre()), Box::new(v.genre())),
        }
    }

    pub(crate) fn chaine(&self) -> Option<&str> {
        match self {
            Variante::Chaine(s) => Some(s),
            _ => None,
        }
    }

    /// Les chaînes d'un tableau de chaînes (« as »).
    pub(crate) fn chaines(&self) -> Option<Vec<&str>> {
        match self {
            Variante::Tableau(Genre::Simple(b's'), v) => v.iter().map(Variante::chaine).collect(),
            _ => None,
        }
    }

    /// Le texte que donnerait `g_variant_print (valeur, TRUE)`, donc `gsettings get` : `true`, `uint32 300`,
    /// `'none'`, `['a', 'b']`, `@as []`. `None` pour ce que ce lecteur ne sait pas écrire à l'identique
    /// (nombres à virgule, octets, « peut-être », dictionnaires, caractères dont GLib décide l'échappement par ses
    /// tables Unicode) : l'appelant demande alors à la commande.
    pub(crate) fn texte(&self) -> Option<String> {
        let mut s = String::new();
        self.ecrire(&mut s, true)?;
        Some(s)
    }

    fn ecrire(&self, s: &mut String, annoter: bool) -> Option<()> {
        let prefixe = |s: &mut String, p: &str| {
            if annoter {
                s.push_str(p);
            }
        };
        match self {
            Variante::Booleen(b) => s.push_str(if *b { "true" } else { "false" }),
            Variante::Entier16(n) => {
                prefixe(s, "int16 ");
                s.push_str(&n.to_string());
            }
            Variante::Naturel16(n) => {
                prefixe(s, "uint16 ");
                s.push_str(&n.to_string());
            }
            // int32 n'est jamais annoté : c'est le type des nombres par défaut.
            Variante::Entier32(n) => s.push_str(&n.to_string()),
            Variante::Naturel32(n) => {
                prefixe(s, "uint32 ");
                s.push_str(&n.to_string());
            }
            Variante::Entier64(n) => {
                prefixe(s, "int64 ");
                s.push_str(&n.to_string());
            }
            Variante::Naturel64(n) => {
                prefixe(s, "uint64 ");
                s.push_str(&n.to_string());
            }
            Variante::Poignee(n) => {
                prefixe(s, "handle ");
                s.push_str(&n.to_string());
            }
            Variante::Chaine(t) => ecrire_chaine(s, t)?,
            Variante::Objet(t) => {
                prefixe(s, "objectpath ");
                s.push('\'');
                s.push_str(t);
                s.push('\'');
            }
            Variante::Signature(t) => {
                prefixe(s, "signature ");
                s.push('\'');
                s.push_str(t);
                s.push('\'');
            }
            Variante::Boite(v) => {
                s.push('<');
                v.ecrire(s, true)?;
                s.push('>');
            }
            Variante::Tableau(g, v) => {
                // Un tableau d'octets s'écrit en b'…', un dictionnaire entre accolades : non repris ici.
                if matches!(g, Genre::Simple(b'y') | Genre::Entree(..)) {
                    return None;
                }
                if v.is_empty() {
                    if annoter {
                        s.push('@');
                        s.push_str(&self.genre().chaine());
                        s.push(' ');
                    }
                    s.push_str("[]");
                } else {
                    s.push('[');
                    for (i, e) in v.iter().enumerate() {
                        if i > 0 {
                            s.push_str(", ");
                        }
                        // Seul le premier élément porte son type : il vaut pour tous.
                        e.ecrire(s, annoter && i == 0)?;
                    }
                    s.push(']');
                }
            }
            Variante::Tuple(m) => {
                s.push('(');
                for (i, e) in m.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    e.ecrire(s, annoter)?;
                }
                if m.len() == 1 {
                    s.push(',');
                }
                s.push(')');
            }
            Variante::Octet(_) | Variante::Double(_) | Variante::Peut(..) | Variante::Entree(..) => return None,
        }
        Some(())
    }
}

/// Une chaîne entre guillemets simples, doubles si elle contient une apostrophe ; la barre oblique inverse et le
/// guillemet choisi sont échappés, les caractères de contrôle aussi (\n, \t, \u0001…). GLib échappe en plus ce que
/// ses tables Unicode disent non imprimable (formats, caractères non attribués) : hors de l'ASCII, seuls les lettres,
/// chiffres et espaces sont écrits ici, le reste rend `None`.
fn ecrire_chaine(s: &mut String, t: &str) -> Option<()> {
    let guillemet = if t.contains('\'') { '"' } else { '\'' };
    s.push(guillemet);
    for c in t.chars() {
        if c == guillemet || c == '\\' {
            s.push('\\');
            s.push(c);
        } else if c.is_control() {
            s.push('\\');
            match c {
                '\u{7}' => s.push('a'),
                '\u{8}' => s.push('b'),
                '\u{c}' => s.push('f'),
                '\n' => s.push('n'),
                '\r' => s.push('r'),
                '\t' => s.push('t'),
                '\u{b}' => s.push('v'),
                _ => {
                    let _ = write!(s, "u{:04x}", u32::from(c));
                }
            }
        } else if c.is_ascii() || c.is_alphanumeric() || c.is_whitespace() {
            s.push(c);
        } else {
            return None;
        }
    }
    s.push(guillemet);
    Some(())
}

/// Taille des décalages de fin d'un conteneur de `taille` octets, comme GLib la choisit.
fn taille_decalage(taille: usize) -> usize {
    match taille {
        0 => 0,
        1..=0xff => 1,
        0x100..=0xffff => 2,
        0x1_0000..=0xffff_ffff => 4,
        _ => 8,
    }
}

fn lire_decalage(octets: &[u8]) -> Option<usize> {
    let mut mot = [0u8; 8];
    mot.get_mut(..octets.len())?.copy_from_slice(octets);
    usize::try_from(u64::from_le_bytes(mot)).ok()
}

/// Décode `octets`, sérialisés comme le type `genre`. `None` : données qui ne sont pas sous la forme normale que
/// GLib écrit (taille fausse, chaîne sans zéro final, décalage hors du conteneur…).
pub(crate) fn decoder(genre: &Genre, octets: &[u8], profondeur: usize) -> Option<Variante> {
    if profondeur > PROFONDEUR_MAX {
        return None;
    }
    if let Some(taille) = genre.taille_fixe()
        && octets.len() != taille
    {
        return None;
    }
    let tableau = |o: &[u8]| -> Option<[u8; 8]> {
        let mut m = [0u8; 8];
        m.get_mut(..o.len())?.copy_from_slice(o);
        Some(m)
    };
    Some(match genre {
        Genre::Simple(c) => match c {
            b'b' => match octets[0] {
                0 => Variante::Booleen(false),
                1 => Variante::Booleen(true),
                _ => return None,
            },
            b'y' => Variante::Octet(octets[0]),
            b'n' => Variante::Entier16(i16::from_le_bytes(octets.try_into().ok()?)),
            b'q' => Variante::Naturel16(u16::from_le_bytes(octets.try_into().ok()?)),
            b'i' => Variante::Entier32(i32::from_le_bytes(octets.try_into().ok()?)),
            b'h' => Variante::Poignee(i32::from_le_bytes(octets.try_into().ok()?)),
            b'u' => Variante::Naturel32(u32::from_le_bytes(octets.try_into().ok()?)),
            b'x' => Variante::Entier64(i64::from_le_bytes(tableau(octets)?)),
            b't' => Variante::Naturel64(u64::from_le_bytes(tableau(octets)?)),
            b'd' => Variante::Double(f64::from_le_bytes(tableau(octets)?)),
            _ => {
                let (zero, texte) = octets.split_last()?;
                if *zero != 0 || texte.contains(&0) {
                    return None;
                }
                let texte = std::str::from_utf8(texte).ok()?.to_string();
                match c {
                    b's' => Variante::Chaine(texte),
                    b'o' => Variante::Objet(texte),
                    _ => Variante::Signature(texte),
                }
            }
        },
        Genre::Variante => {
            let zero = octets.iter().rposition(|&o| o == 0)?;
            let interieur = Genre::depuis(&octets[zero + 1..])?;
            Variante::Boite(Box::new(decoder(&interieur, &octets[..zero], profondeur + 1)?))
        }
        Genre::Peut(e) => {
            let valeur = if octets.is_empty() {
                None
            } else if e.taille_fixe().is_some() {
                Some(decoder(e, octets, profondeur + 1)?)
            } else {
                let (zero, reste) = octets.split_last()?;
                if *zero != 0 {
                    return None;
                }
                Some(decoder(e, reste, profondeur + 1)?)
            };
            Variante::Peut((**e).clone(), valeur.map(Box::new))
        }
        Genre::Tableau(e) => Variante::Tableau((**e).clone(), elements(e, octets, profondeur)?),
        Genre::Tuple(_) | Genre::Entree(..) => {
            let membres = genre.membres();
            let n = membres.len();
            let tde = taille_decalage(octets.len());
            let mut fin_decalages = octets.len();
            let mut position = 0;
            let mut valeurs = Vec::with_capacity(n);
            for (i, m) in membres.into_iter().enumerate() {
                position = aligner(position, m.alignement())?;
                let fin = match m.taille_fixe() {
                    Some(t) => position.checked_add(t)?,
                    None if i + 1 == n => fin_decalages,
                    None => {
                        fin_decalages = fin_decalages.checked_sub(tde)?;
                        lire_decalage(octets.get(fin_decalages..fin_decalages + tde)?)?
                    }
                };
                if position > fin || fin > fin_decalages {
                    return None;
                }
                valeurs.push(decoder(m, &octets[position..fin], profondeur + 1)?);
                position = fin;
            }
            match genre {
                Genre::Entree(..) => {
                    let mut v = valeurs.into_iter();
                    Variante::Entree(Box::new(v.next()?), Box::new(v.next()?))
                }
                _ => Variante::Tuple(valeurs),
            }
        }
    })
}

fn elements(e: &Genre, octets: &[u8], profondeur: usize) -> Option<Vec<Variante>> {
    if let Some(taille) = e.taille_fixe() {
        if !octets.len().is_multiple_of(taille) {
            return None;
        }
        return octets.chunks(taille).map(|o| decoder(e, o, profondeur + 1)).collect();
    }
    if octets.is_empty() {
        return Some(Vec::new());
    }
    let tde = taille_decalage(octets.len());
    let debut_decalages = lire_decalage(&octets[octets.len() - tde..])?;
    let place = octets.len().checked_sub(debut_decalages)?;
    if place % tde != 0 {
        return None;
    }
    let mut valeurs = Vec::with_capacity(place / tde);
    let mut position = 0;
    for mot in octets[debut_decalages..].chunks(tde) {
        let fin = lire_decalage(mot)?;
        position = aligner(position, e.alignement())?;
        if position > fin || fin > debut_decalages {
            return None;
        }
        valeurs.push(decoder(e, &octets[position..fin], profondeur + 1)?);
        position = fin;
    }
    Some(valeurs)
}

// ---------------------------------------------------------------------------------------------------------------
// Fabrique, pour les tests : sérialisation GVariant et fichiers GVDB comme les écrivent GLib et dconf.

#[cfg(test)]
pub(crate) mod fabrique {
    use super::{Genre, Variante, aligner, taille_decalage};

    fn completer(sortie: &mut Vec<u8>, alignement: usize) {
        sortie.resize(aligner(sortie.len(), alignement).expect("taille"), 0);
    }

    fn decalages(corps: &mut Vec<u8>, fins: &[usize]) {
        let mut tde = 1;
        while taille_decalage(corps.len() + fins.len() * tde) > tde {
            tde *= 2;
        }
        for f in fins {
            corps.extend_from_slice(&(f.to_le_bytes())[..tde]);
        }
    }

    /// La forme sérialisée de `v`, celle qu'écrit GLib.
    pub(crate) fn serialiser(v: &Variante) -> Vec<u8> {
        match v {
            Variante::Booleen(b) => vec![u8::from(*b)],
            Variante::Octet(o) => vec![*o],
            Variante::Entier16(n) => n.to_le_bytes().to_vec(),
            Variante::Naturel16(n) => n.to_le_bytes().to_vec(),
            Variante::Entier32(n) | Variante::Poignee(n) => n.to_le_bytes().to_vec(),
            Variante::Naturel32(n) => n.to_le_bytes().to_vec(),
            Variante::Entier64(n) => n.to_le_bytes().to_vec(),
            Variante::Naturel64(n) => n.to_le_bytes().to_vec(),
            Variante::Double(n) => n.to_le_bytes().to_vec(),
            Variante::Chaine(s) | Variante::Objet(s) | Variante::Signature(s) => {
                let mut o = s.as_bytes().to_vec();
                o.push(0);
                o
            }
            Variante::Boite(v) => {
                let mut o = serialiser(v);
                o.push(0);
                o.extend_from_slice(v.genre().chaine().as_bytes());
                o
            }
            Variante::Peut(g, v) => match v {
                None => Vec::new(),
                Some(v) => {
                    let mut o = serialiser(v);
                    if g.taille_fixe().is_none() {
                        o.push(0);
                    }
                    o
                }
            },
            Variante::Tableau(g, v) => {
                let mut o = Vec::new();
                let mut fins = Vec::new();
                for e in v {
                    completer(&mut o, g.alignement());
                    o.extend(serialiser(e));
                    fins.push(o.len());
                }
                if g.taille_fixe().is_none() && !v.is_empty() {
                    decalages(&mut o, &fins);
                }
                o
            }
            Variante::Tuple(_) | Variante::Entree(..) => {
                let membres: Vec<&Variante> = match v {
                    Variante::Tuple(m) => m.iter().collect(),
                    Variante::Entree(k, v) => vec![k, v],
                    _ => unreachable!(),
                };
                let genre = v.genre();
                let mut o = Vec::new();
                let mut fins = Vec::new();
                for (i, m) in membres.iter().enumerate() {
                    let g = m.genre();
                    completer(&mut o, g.alignement());
                    o.extend(serialiser(m));
                    if g.taille_fixe().is_none() && i + 1 < membres.len() {
                        fins.push(o.len());
                    }
                }
                if let Some(t) = genre.taille_fixe() {
                    o.resize(t, 0);
                } else {
                    fins.reverse();
                    decalages(&mut o, &fins);
                }
                o
            }
        }
    }

    /// Le contenu d'une table à fabriquer : une valeur, une table imbriquée ou un dossier de dconf (genre `L`).
    pub(crate) enum Contenu {
        Valeur(Variante),
        Table(Vec<(String, Contenu)>),
        Dossier,
    }

    pub(crate) fn valeur(nom: &str, v: Variante) -> (String, Contenu) {
        (nom.to_string(), Contenu::Valeur(v))
    }

    fn hachage(nom: &[u8]) -> u32 {
        // Le hachage de djb, sur des `signed char` comme dans GLib.
        nom.iter().fold(5381u32, |h, &c| {
            h.wrapping_mul(33)
                .wrapping_add(i32::from(c.cast_signed()).cast_unsigned())
        })
    }

    fn mot(sortie: &mut [u8], position: usize, valeur: usize) {
        let v = u32::try_from(valeur).expect("fichier de test trop grand");
        sortie[position..position + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Range la table `entrees` à la fin de `sortie` ; rend son étendue. Avec `parents`, un nom dont le début est
    /// celui d'un dossier (« /org/gnome/ ») n'en garde que la fin et pointe vers lui, comme dconf.
    fn ecrire_table(sortie: &mut Vec<u8>, entrees: &[(String, Contenu)], parents: bool) -> (usize, usize) {
        completer(sortie, 4);
        let n = entrees.len();
        let seaux = n.max(1);
        let mut ordre: Vec<usize> = (0..n).collect();
        ordre.sort_by_key(|&i| hachage(entrees[i].0.as_bytes()) as usize % seaux);
        let index: Vec<usize> = {
            let mut index = vec![0; n];
            for (place, &i) in ordre.iter().enumerate() {
                index[i] = place;
            }
            index
        };
        let debut = sortie.len();
        sortie.resize(debut + 8 + seaux * 4 + n * 24, 0);
        mot(sortie, debut, 0);
        mot(sortie, debut + 4, seaux);
        for s in 0..seaux {
            let premier = ordre
                .iter()
                .position(|&i| hachage(entrees[i].0.as_bytes()) as usize % seaux >= s)
                .unwrap_or(n);
            mot(sortie, debut + 8 + 4 * s, premier);
        }
        let fin = sortie.len();
        for (place, &i) in ordre.iter().enumerate() {
            let (nom, contenu) = &entrees[i];
            let parent = parents
                .then(|| {
                    entrees
                        .iter()
                        .enumerate()
                        .filter(|(j, (p, c))| {
                            *j != i && matches!(c, Contenu::Dossier) && nom.starts_with(p.as_str()) && nom != p
                        })
                        .max_by_key(|(_, (p, _))| p.len())
                        .map(|(j, (p, _))| (j, p.len()))
                })
                .flatten();
            let (parent, propre) = match parent {
                Some((j, longueur)) => (index[j], &nom[longueur..]),
                None => (u32::MAX as usize, nom.as_str()),
            };
            let e = debut + 8 + seaux * 4 + 24 * place;
            mot(sortie, e, hachage(nom.as_bytes()) as usize);
            mot(sortie, e + 4, parent);
            let debut_nom = sortie.len();
            sortie.extend_from_slice(propre.as_bytes());
            mot(sortie, e + 8, debut_nom);
            sortie[e + 12..e + 14].copy_from_slice(&u16::try_from(propre.len()).expect("nom court").to_le_bytes());
            let (genre, etendue) = match contenu {
                Contenu::Valeur(v) => {
                    completer(sortie, 8);
                    let d = sortie.len();
                    sortie.extend(serialiser(&Variante::Boite(Box::new(v.clone()))));
                    (b'v', (d, sortie.len()))
                }
                Contenu::Table(t) => (b'H', ecrire_table(sortie, t, parents)),
                Contenu::Dossier => (b'L', (sortie.len(), sortie.len())),
            };
            sortie[e + 14] = genre;
            mot(sortie, e + 16, etendue.0);
            mot(sortie, e + 20, etendue.1);
        }
        (debut, fin)
    }

    /// Un fichier GVDB complet dont la racine est `entrees`.
    pub(crate) fn fichier(entrees: &[(String, Contenu)], parents: bool) -> Vec<u8> {
        let mut sortie = b"GVariant".to_vec();
        sortie.resize(24, 0);
        let (debut, fin) = ecrire_table(&mut sortie, entrees, parents);
        mot(&mut sortie, 16, debut);
        mot(&mut sortie, 20, fin);
        sortie
    }

    /// Une base de dconf : les dossiers de chaque clé, la clé, et les verrous dans la table `.locks`.
    pub(crate) fn base_dconf(valeurs: &[(&str, Variante)], verrous: &[&str]) -> Vec<u8> {
        let mut entrees: Vec<(String, Contenu)> = Vec::new();
        let mut dossiers: Vec<String> = Vec::new();
        for (cle, v) in valeurs {
            let mut fin = 0;
            while let Some(p) = cle[fin + 1..].find('/') {
                fin += p + 1;
                let dossier = cle[..=fin].to_string();
                if !dossiers.contains(&dossier) {
                    dossiers.push(dossier);
                }
            }
            entrees.push(valeur(cle, v.clone()));
        }
        if !dossiers.iter().any(|d| d == "/") {
            dossiers.push("/".to_string());
        }
        entrees.extend(dossiers.into_iter().map(|d| (d, Contenu::Dossier)));
        if !verrous.is_empty() {
            entrees.push((
                ".locks".to_string(),
                Contenu::Table(
                    verrous
                        .iter()
                        .map(|v| valeur(v, Variante::Chaine(String::new())))
                        .collect(),
                ),
            ));
        }
        fichier(&entrees, true)
    }

    /// Les octets d'un texte hexadécimal (fichiers relevés tels que leurs programmes les écrivent).
    pub(crate) fn hexa(texte: &str) -> Vec<u8> {
        let chiffres: Vec<u8> = texte.bytes().filter(u8::is_ascii_hexdigit).collect();
        chiffres
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).expect("hexadécimal"), 16).expect("hexadécimal"))
            .collect()
    }

    pub(crate) fn chaines(v: &[&str]) -> Variante {
        Variante::Tableau(
            Genre::Simple(b's'),
            v.iter().map(|s| Variante::Chaine((*s).to_string())).collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::fabrique::{Contenu, base_dconf, chaines, fichier, hexa, serialiser, valeur};
    use super::*;

    fn aller_retour(v: &Variante) {
        let octets = serialiser(v);
        assert_eq!(decoder(&v.genre(), &octets, 0).as_ref(), Some(v), "{v:?} : {octets:?}");
    }

    #[test]
    fn types_depuis_leur_chaine() {
        for t in [
            "b",
            "as",
            "(s(yau))",
            "a{sv}",
            "(va{sas})",
            "mmi",
            "()",
            "a(ii)",
            "{sv}",
        ] {
            assert_eq!(Genre::depuis(t.as_bytes()).map(|g| g.chaine()).as_deref(), Some(t));
        }
        for t in ["", "a", "(i", "{vs}", "{s}", "z", "ii", "{sii}"] {
            assert_eq!(Genre::depuis(t.as_bytes()), None, "{t}");
        }
        // Une imbrication sans fin, forgée, est refusée sans épuiser la pile.
        assert_eq!(Genre::depuis(&[b'a'; 10_000]), None);
        assert_eq!(
            Genre::depuis(format!("{}i{}", "(".repeat(5000), ")".repeat(5000)).as_bytes()),
            None
        );
    }

    #[test]
    fn tailles_et_alignements_de_glib() {
        let g = |t: &str| Genre::depuis(t.as_bytes()).expect(t);
        assert_eq!(g("(yu)").taille_fixe(), Some(8));
        assert_eq!(g("(uy)").taille_fixe(), Some(8));
        assert_eq!(g("(ii)").taille_fixe(), Some(8));
        assert_eq!(g("(bdy)").taille_fixe(), Some(24));
        assert_eq!(g("()").taille_fixe(), Some(1));
        assert_eq!(g("(ys)").taille_fixe(), None);
        assert_eq!(g("(yx)").alignement(), 8);
    }

    #[test]
    fn valeurs_aller_retour() {
        let s = |t: &str| Variante::Chaine(t.to_string());
        for v in [
            Variante::Booleen(true),
            Variante::Naturel32(300),
            Variante::Entier32(-7),
            Variante::Entier64(-1 << 40),
            Variante::Naturel16(65535),
            Variante::Double(0.5),
            s("none"),
            s(""),
            chaines(&["localhost", "127.0.0.0/8", "::1"]),
            chaines(&[]),
            Variante::Tuple(vec![Variante::Entier32(890), Variante::Entier32(550)]),
            Variante::Tuple(vec![
                s("none"),
                Variante::Tuple(vec![
                    Variante::Octet(b'e'),
                    Variante::Tableau(
                        Genre::Simple(b'u'),
                        vec![Variante::Naturel32(0), Variante::Naturel32(u32::MAX)],
                    ),
                ]),
            ]),
            Variante::Boite(Box::new(Variante::Booleen(false))),
            Variante::Peut(Genre::Simple(b's'), Some(Box::new(s("x")))),
            Variante::Peut(Genre::Simple(b'i'), None),
            Variante::Tableau(
                Genre::Entree(
                    Box::new(Genre::Simple(b's')),
                    Box::new(Genre::Tableau(Box::new(Genre::Simple(b's')))),
                ),
                vec![Variante::Entree(
                    Box::new(s("org.exemple.Camera")),
                    Box::new(chaines(&["yes"])),
                )],
            ),
            // Plus de 255 octets : les décalages passent à deux octets.
            chaines(&vec!["une chaîne assez longue pour grossir le tableau"; 20]),
        ] {
            aller_retour(&v);
        }
    }

    /// Octets écrits par GLib (gschemas.compiled de GNOME, base de dconf) : le décodage les relit tels quels.
    #[test]
    fn octets_ecrits_par_glib() {
        let v = |o: &[u8]| decoder(&Genre::Variante, o, 0);
        assert_eq!(
            v(b",\x01\x00\x00\x00(u)"),
            Some(Variante::Boite(Box::new(Variante::Tuple(vec![Variante::Naturel32(
                300
            )]))))
        );
        assert_eq!(
            v(b"localhost\x00127.0.0.0/8\x00::1\x00\n\x16\x1a\x00(as)").and_then(|b| match b {
                Variante::Boite(t) => Some(*t),
                _ => None,
            }),
            Some(Variante::Tuple(vec![chaines(&["localhost", "127.0.0.0/8", "::1"])]))
        );
        let mode = v(b"none\x00\x00\x00\x00e\x00\x00\x00\x00\x00\x00\x00\xffnone\x00\x00\xff\x01\x00\x00\x00\xffmanual\x00\x00\x00\x00\xff\x02\x00\x00\x00\xffauto\x00\x00\xff\x05\x00(s(yau))");
        let Some(Variante::Boite(t)) = mode else {
            panic!("{mode:?}")
        };
        let Variante::Tuple(m) = *t else { panic!() };
        assert_eq!(m[0], Variante::Chaine("none".into()));
        assert!(matches!(&m[1], Variante::Tuple(x) if x[0] == Variante::Octet(b'e')));
        assert_eq!(
            v(b"z\x03\x00\x00&\x02\x00\x00\x00(ii)"),
            Some(Variante::Boite(Box::new(Variante::Tuple(vec![
                Variante::Entier32(890),
                Variante::Entier32(550)
            ]))))
        );
    }

    #[test]
    fn donnees_forgees_refusees() {
        let s = |g: &str, o: &[u8]| decoder(&Genre::depuis(g.as_bytes()).unwrap(), o, 0);
        assert_eq!(s("s", b"abc"), None, "sans zéro final");
        assert_eq!(s("s", b"a\0c\0"), None, "zéro au milieu");
        assert_eq!(s("s", b"\xff\0"), None, "pas de l'UTF-8");
        assert_eq!(s("b", b"\x02"), None);
        assert_eq!(s("u", b"\x01\x00"), None, "taille fausse");
        assert_eq!(s("as", b"a\0\x09"), None, "décalage hors du conteneur");
        assert_eq!(s("(si)", b"a\0\0\0\x01\0\0\0\x09"), None);
        assert_eq!(s("v", b"\x01\0zz"), None, "type inconnu");
        // Des variantes imbriquées à l'infini : refusées à la profondeur maximale.
        let mut o = vec![1u8, 0, b'b'];
        for _ in 0..200 {
            o.extend_from_slice(b"\0v");
        }
        assert_eq!(s("v", &o), None);
    }

    #[test]
    fn texte_comme_gsettings() {
        let t = |v: Variante| v.texte();
        assert_eq!(t(Variante::Booleen(true)).as_deref(), Some("true"));
        assert_eq!(t(Variante::Naturel32(300)).as_deref(), Some("uint32 300"));
        assert_eq!(t(Variante::Entier32(1)).as_deref(), Some("1"));
        assert_eq!(t(Variante::Entier64(-2)).as_deref(), Some("int64 -2"));
        assert_eq!(t(Variante::Chaine("none".into())).as_deref(), Some("'none'"));
        assert_eq!(t(Variante::Chaine("l'été".into())).as_deref(), Some("\"l'été\""));
        assert_eq!(t(Variante::Chaine("a\\b\n".into())).as_deref(), Some("'a\\\\b\\n'"));
        assert_eq!(t(Variante::Chaine("\u{1}".into())).as_deref(), Some("'\\u0001'"));
        assert_eq!(
            t(Variante::Chaine("«".into())),
            None,
            "échappement décidé par les tables de GLib"
        );
        assert_eq!(t(chaines(&["a", "b"])).as_deref(), Some("['a', 'b']"));
        assert_eq!(t(chaines(&[])).as_deref(), Some("@as []"));
        assert_eq!(
            t(Variante::Tableau(
                Genre::Simple(b'u'),
                vec![Variante::Naturel32(1), Variante::Naturel32(2)]
            ))
            .as_deref(),
            Some("[uint32 1, 2]")
        );
        assert_eq!(
            t(Variante::Tuple(vec![Variante::Entier32(890), Variante::Entier32(550)])).as_deref(),
            Some("(890, 550)")
        );
        assert_eq!(
            t(Variante::Tuple(vec![Variante::Naturel32(1)])).as_deref(),
            Some("(uint32 1,)")
        );
        assert_eq!(
            t(Variante::Boite(Box::new(Variante::Naturel32(1)))).as_deref(),
            Some("<uint32 1>")
        );
        assert_eq!(t(Variante::Double(1.0)), None);
        assert_eq!(t(Variante::Octet(1)), None);
    }

    #[test]
    fn table_lue_avec_ses_parents() {
        let octets = base_dconf(
            &[
                ("/org/gnome/desktop/screensaver/lock-enabled", Variante::Booleen(false)),
                ("/org/gnome/desktop/session/idle-delay", Variante::Naturel32(600)),
                ("/system/proxy/mode", Variante::Chaine("manual".into())),
            ],
            &["/org/gnome/desktop/screensaver/lock-enabled"],
        );
        let base = Gvdb::depuis(octets).expect("en-tête");
        let racine = base.racine().expect("racine");
        assert_eq!(
            racine.valeur("/org/gnome/desktop/session/idle-delay"),
            Some(Variante::Naturel32(600))
        );
        assert_eq!(
            racine.valeur("/system/proxy/mode"),
            Some(Variante::Chaine("manual".into()))
        );
        assert_eq!(racine.valeur("/system/proxy/"), None, "un dossier n'est pas une valeur");
        assert_eq!(racine.valeur("/absente"), None);
        let verrous = racine.table(".locks").expect("verrous");
        assert!(verrous.contient_valeur("/org/gnome/desktop/screensaver/lock-enabled"));
        assert!(!verrous.contient_valeur("/system/proxy/mode"));
        let mut noms: Vec<&str> = racine.noms_des_valeurs().collect();
        noms.sort_unstable();
        assert_eq!(noms.len(), 3);
    }

    /// Une base écrite par `dconf compile` (dconf 51.0 d'Arch), avec un verrou : la même lecture.
    #[test]
    fn base_ecrite_par_dconf() {
        let base = Gvdb::depuis(hexa(BASE_DCONF)).expect("en-tête");
        let racine = base.racine().expect("racine");
        assert_eq!(
            racine.valeur("/org/gnome/desktop/screensaver/lock-enabled"),
            Some(Variante::Booleen(false))
        );
        assert_eq!(
            racine.valeur("/org/gnome/desktop/session/idle-delay"),
            Some(Variante::Naturel32(600))
        );
        assert_eq!(
            racine.valeur("/system/proxy/mode"),
            Some(Variante::Chaine("manual".into()))
        );
        assert!(
            racine
                .table(".locks")
                .expect("verrous")
                .contient_valeur("/org/gnome/desktop/screensaver/lock-enabled")
        );
    }

    #[test]
    fn fichiers_tronques_ou_forges() {
        assert!(
            Gvdb::depuis(b"GVariant".to_vec()).is_none()
                || Gvdb::depuis(b"GVariant".to_vec()).unwrap().racine().is_none()
        );
        assert!(
            Gvdb::depuis(b"raVGtnai\0\0\0\0\0\0\0\0\x18\0\0\0\x20\0\0\0".to_vec()).is_none(),
            "gros-boutiste"
        );
        assert!(Gvdb::depuis(b"Pas un GVDB du tout....".to_vec()).is_none());
        let bon = fichier(
            &[
                valeur("cle", Variante::Chaine("valeur".into())),
                ("t".into(), Contenu::Table(vec![valeur("x", Variante::Booleen(true))])),
            ],
            false,
        );
        // Chaque troncature et chaque octet changé : jamais de panique, au pire « illisible ».
        for longueur in 0..bon.len() {
            if let Some(b) = Gvdb::depuis(bon[..longueur].to_vec()) {
                let _ = b
                    .racine()
                    .map(|t| (t.valeur("cle"), t.table("t").map(|x| x.valeur("x"))));
            }
        }
        for i in 0..bon.len() {
            for o in [0u8, 1, 0x7f, 0xff] {
                let mut abime = bon.clone();
                abime[i] = o;
                if let Some(b) = Gvdb::depuis(abime) {
                    let _ = b
                        .racine()
                        .map(|t| (t.valeur("cle"), t.table("t").map(|x| x.valeur("x"))));
                }
            }
        }
        // Une boucle de parents forgée ne tourne pas sans fin.
        let mut boucle = base_dconf(&[("/a/b", Variante::Booleen(true))], &[]);
        let racine = Gvdb::depuis(boucle.clone()).unwrap().racine().unwrap();
        assert_eq!(racine.valeur("/a/b"), Some(Variante::Booleen(true)));
        let debut = u32_le(&boucle, 16).unwrap() as usize;
        let seaux = u32_le(&boucle, debut + 4).unwrap() as usize;
        let elements = debut + 8 + 4 * seaux;
        for e in 0..3 {
            let p = elements + 24 * e + 4;
            boucle[p..p + 4].copy_from_slice(&u32::try_from(e).unwrap().to_le_bytes());
        }
        assert!(Gvdb::depuis(boucle).unwrap().racine().is_none());
    }

    /// `dconf compile` d'un dossier : lock-enabled=false (verrouillé), idle-delay=uint32 600, mode='manual'.
    const BASE_DCONF: &str = "
    4756617269616e7400000000000000001800000070010000000000280c000000000000000000000001000000010000000200000004000000
    0400000007000000080000000a0000000c0000000c00000029b90fc60a000000700100000c004c007c010000800100008f390d7bffffffff
    800100000600480088010000ac010000e837d59208000000db01000007004c00e4010000e80100008c87dd660a000000e801000008004c00
    f0010000f4010000e6c919d503000000f40100000a0076000002000006020000aacd936000000000060200000c007600180200001b020000
    5e31bcef0b0000001b0200000400760020020000290200004b50900b080000002902000004004c003002000034020000d4b50200ffffffff
    3402000001004c003802000040020000b0b72430070000004002000006004c00480200004c020000b988fdda090000004c02000008004c00
    540200005c0200001922f931020000005c02000006004c00640200006802000073637265656e73617665722f050000002e6c6f636b730000
    000000280100000000000000aacd9360ffffffffac0100002b007600d8010000db0100002f6f72672f676e6f6d652f6465736b746f702f73
    637265656e73617665722f6c6f636b2d656e61626c65640000007373797374656d2f00000b00000073657373696f6e2f0400000069646c65
    2d64656c617900005802000000756c6f636b2d656e61626c65640000000000000000626d6f6465006d616e75616c0000736f72672f000000
    090000002f0000000700000002000000676e6f6d652f00000a0000006465736b746f702f000000000300000070726f78792f000006000000";
}
