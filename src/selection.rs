//! Menus au clavier : ↑ ↓ pour se déplacer, Entrée pour lancer, Échap pour revenir. Les touches d'avant (un chiffre
//! ou une lettre, puis Entrée) marchent toujours, et la ligne en surbrillance les suit. Taper un mot cherche : seules
//! les lignes qui le contiennent restent à l'écran, sans tenir compte des accents ni des majuscules ; au menu
//! principal, la recherche voit aussi les outils des sous-menus et les pages du guide (lignes « cachées »). Un menu
//! plus haut que la fenêtre défile : l'en-tête reste en place, la liste suit la ligne en surbrillance, et « ↑ » ou
//! « ↓ » disent combien de lignes sont cachées. Sans vrai terminal (réponses envoyées par un tube : tests, scripts), ou
//! dans une fenêtre minuscule, la réponse se lit ligne par ligne, comme avant ; un mot qui ne désigne qu'un seul choix
//! le choisit.

use std::fmt::Write as _;
use std::io::{IsTerminal, Write};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;

use crate::ui::*;

/// Une ligne d'un menu.
pub enum Ligne {
    /// Affichée telle quelle : cadre, titre, état, ligne vide.
    Texte(String),
    /// Ligne qu'on peut choisir : la touche qui la désigne, son texte, une précision en gris à droite, et des mots que
    /// la recherche trouve sans qu'ils s'affichent.
    Choix {
        touche: String,
        texte: String,
        precision: String,
        mots: String,
    },
    /// Choix que seule la recherche montre : un outil d'un sous-menu, une page du guide. `chemin` dit où il se trouve
    /// (« Réseau et Internet › »).
    Cachee {
        touche: String,
        chemin: String,
        texte: String,
        precision: String,
        mots: String,
    },
}

impl Ligne {
    pub fn choix(touche: &str, texte: &str, precision: &str) -> Self {
        Ligne::Choix {
            touche: touche.into(),
            texte: texte.into(),
            precision: precision.into(),
            mots: String::new(),
        }
    }

    pub fn cachee(touche: &str, chemin: &str, texte: &str, precision: &str) -> Self {
        Ligne::Cachee {
            touche: touche.into(),
            chemin: chemin.into(),
            texte: texte.into(),
            precision: precision.into(),
            mots: String::new(),
        }
    }

    /// Des mots de plus pour la recherche : ce qu'un outil sait faire, les commandes d'un programme du guide.
    #[must_use]
    pub fn avec_mots(mut self, en_plus: &str) -> Self {
        if let Ligne::Choix { mots, .. } | Ligne::Cachee { mots, .. } = &mut self {
            mots.push(' ');
            mots.push_str(en_plus);
        }
        self
    }
}

/// Minuscules, sans accents, sans tirets et sans codes de couleur : « Wi-Fi » se trouve en tapant « wifi », « Réseau »
/// en tapant « reseau ».
pub fn simplifier(t: &str) -> String {
    let mut sortie = String::with_capacity(t.len());
    let mut code = false;
    for c in t.chars() {
        if code {
            code = c != 'm';
            continue;
        }
        if c == '\x1b' {
            code = true;
            continue;
        }
        if c == '-' {
            continue;
        }
        for m in c.to_lowercase() {
            match m {
                'à' | 'â' | 'ä' | 'á' => sortie.push('a'),
                'é' | 'è' | 'ê' | 'ë' => sortie.push('e'),
                'î' | 'ï' | 'í' => sortie.push('i'),
                'ô' | 'ö' | 'ó' => sortie.push('o'),
                'ù' | 'û' | 'ü' | 'ú' => sortie.push('u'),
                'ç' => sortie.push('c'),
                'œ' => sortie.push_str("oe"),
                autre => sortie.push(autre),
            }
        }
    }
    sortie
}

/// Tous les mots de `recherche` paraissent-ils dans `texte`, déjà passé par `simplifier` ? Un mot de trois lettres au
/// plus doit commencer un mot (« ip » ne trouve pas « description ») ; un plus long peut être n'importe où (« update »
/// trouve « windowsupdate »), et sa fin peut changer : on tape « vider », « réparer », « disques », le texte dit
/// « Vide », « Répare », « disque ».
pub fn correspond(recherche: &str, texte: &str) -> bool {
    let voulus: Vec<String> = recherche
        .split_whitespace()
        .map(simplifier)
        .filter(|m| !m.is_empty())
        .collect();
    !voulus.is_empty()
        && voulus.iter().all(|v| {
            let n = v.chars().count();
            if n <= 3 {
                return texte
                    .split(|c: char| !c.is_alphanumeric())
                    .any(|m| m.starts_with(v.as_str()));
            }
            // La racine garde au moins quatre lettres (cinq quand on en retire deux) : « réseau » ne devient pas
            // « rese », qui trouverait « reset ».
            let racine = |retire: usize| v.chars().take(n - retire).collect::<String>();
            texte.contains(v.as_str())
                || (n >= 5 && texte.contains(&racine(1)))
                || (n >= 7 && texte.contains(&racine(2)))
        })
}

/// Ce qui est tapé est-il une recherche ? Pas une touche du menu ni le début d'une touche (« 1 » de « 10 », « 4. » de
/// « 4.2 »), et au moins deux lettres : une lettre seule reste un raccourci des anciennes versions (u, r, o…).
fn est_une_recherche(tape: &str, touches: &[&str]) -> bool {
    let t = tape.trim().to_lowercase();
    t.chars().count() >= 2 && !touches.iter().any(|k| k.to_lowercase().starts_with(&t))
}

/// Une ligne qu'on peut choisir, telle que la recherche la voit.
struct Choisissable<'a> {
    touche: &'a str,
    /// Le texte sans couleurs, précédé de son chemin pour une ligne cachée (« Réseau et Internet › Scanner le réseau »).
    texte: String,
    precision: &'a str,
    /// Tout ce que lit la recherche, simplifié une fois pour toutes.
    cherche: String,
    visible: bool,
}

fn choisissables(lignes: &[Ligne]) -> Vec<Choisissable<'_>> {
    lignes
        .iter()
        .filter_map(|l| match l {
            Ligne::Texte(_) => None,
            Ligne::Choix {
                touche,
                texte,
                precision,
                mots,
            } => Some(Choisissable {
                touche,
                texte: simplement_affiche(texte),
                precision,
                cherche: simplifier(&format!("{texte} {precision} {mots}")),
                visible: true,
            }),
            Ligne::Cachee {
                touche,
                chemin,
                texte,
                precision,
                mots,
            } => Some(Choisissable {
                touche,
                texte: simplement_affiche(&format!("{chemin} {texte}")),
                precision,
                cherche: simplifier(&format!("{chemin} {texte} {precision} {mots}")),
                visible: false,
            }),
        })
        .collect()
}

/// Le texte sans ses codes de couleur, pour pouvoir le couper.
fn simplement_affiche(t: &str) -> String {
    let mut sortie = String::with_capacity(t.len());
    let mut code = false;
    for c in t.chars() {
        match (code, c) {
            (false, '\x1b') => code = true,
            (true, 'm') => code = false,
            (false, _) => sortie.push(c),
            _ => {}
        }
    }
    sortie
}

/// Coupe un texte trop long (« … » à la fin), sans le compléter d'espaces.
fn couper(t: &str, n: usize) -> String {
    if t.chars().count() <= n {
        return t.to_string();
    }
    let mut court: String = t.chars().take(n.saturating_sub(1)).collect();
    court.push('…');
    court
}

/// Une ligne trouvée par la recherche : la touche, le texte, puis la précision s'il reste de la place. Toujours dans
/// `LARGEUR` colonnes, même avec un long chemin : l'écran est redessiné depuis le haut et ne doit pas défiler.
fn rendu_trouve(c: &Choisissable<'_>, largeur_touche: usize, en_cours: bool) -> String {
    let (marque, gras) = if en_cours {
        (format!("{ACCENT}►{RESET}"), GRAS)
    } else {
        (" ".to_string(), "")
    };
    let dispo = LARGEUR.saturating_sub(largeur_touche + 5);
    let texte = couper(&c.texte, dispo);
    let reste = dispo.saturating_sub(texte.chars().count() + 2);
    let precision = simplement_affiche(c.precision);
    let precision = if precision.is_empty() || reste < 10 {
        String::new()
    } else {
        format!("  {DISCRET}{}{RESET}", couper(&precision, reste))
    };
    format!(
        " {marque} {TOUCHE}{:>largeur_touche$}{RESET}  {gras}{texte}{RESET}{precision}",
        c.touche
    )
}

fn largeur_des_touches<'a>(trouves: impl Iterator<Item = &'a Choisissable<'a>>) -> usize {
    trouves.map(|c| c.touche.chars().count()).max().unwrap_or(2).max(2)
}

/// Sans terminal : la réponse se lit ligne par ligne. Un mot qui n'est pas une touche cherche : un seul choix trouvé
/// est choisi ; plusieurs sont montrés avec leur touche, et la question revient.
fn par_ligne(choix: &[Choisissable<'_>], touches: &[&str], invite: &str) -> String {
    loop {
        let reponse = demander(invite);
        if !est_une_recherche(&reponse, touches) {
            return reponse;
        }
        let trouves: Vec<&Choisissable> = choix.iter().filter(|c| correspond(&reponse, &c.cherche)).collect();
        match trouves.as_slice() {
            [seul] => return seul.touche.to_string(),
            [] => trp!(
                "  Rien ne correspond à « {reponse} ».",
                "  Nothing matches “{reponse}”."
            ),
            plusieurs => {
                let largeur = largeur_des_touches(plusieurs.iter().copied());
                for c in plusieurs {
                    println!("{}", rendu_trouve(c, largeur, false));
                }
                trp!(
                    "  {GRIS}Tape la touche de ton choix, ou d'autres mots.{RESET}",
                    "  {GRIS}Type the key of your choice, or other words.{RESET}"
                );
            }
        }
    }
}

/// Une ligne de choix : la touche en blanc vif, le texte, sa précision en gris à partir de la colonne `colonne`. La
/// ligne en cours est marquée « ► » (présent dans les polices de l'ancienne console Windows) et écrite en gras.
fn rendu(touche: &str, texte: &str, precision: &str, colonne: usize, en_cours: bool) -> String {
    let (marque, gras) = if en_cours {
        (format!("{ACCENT}►{RESET}"), GRAS)
    } else {
        (" ".to_string(), "")
    };
    if precision.is_empty() {
        format!(" {marque} {TOUCHE}{touche:>2}{RESET}  {gras}{texte}{RESET}")
    } else {
        format!(
            " {marque} {TOUCHE}{touche:>2}{RESET}  {gras}{}{RESET}{DISCRET}{precision}{RESET}",
            ajuster(texte, colonne)
        )
    }
}

/// Colonne des précisions : la même pour toutes les lignes du menu, après le texte le plus long.
fn colonne(lignes: &[Ligne]) -> usize {
    let plus_long = lignes
        .iter()
        .filter_map(|l| match l {
            Ligne::Choix { texte, .. } => Some(largeur_affichee(texte)),
            Ligne::Texte(_) | Ligne::Cachee { .. } => None,
        })
        .max()
        .unwrap_or(0);
    (plus_long + 2).clamp(36, 48)
}

/// La ligne à l'écran, ou rien pour une ligne cachée (seule la recherche la montre).
fn texte(l: &Ligne, colonne: usize, en_cours: bool) -> Option<String> {
    match l {
        Ligne::Texte(t) => Some(t.clone()),
        Ligne::Choix {
            touche,
            texte,
            precision,
            ..
        } => Some(rendu(touche, texte, precision, colonne, en_cours)),
        Ligne::Cachee { .. } => None,
    }
}

/// Hauteur de fenêtre en dessous de laquelle un menu se lit ligne par ligne : trop peu de place pour défiler.
const RANGEES_MINIMUM: usize = 10;

/// Ce qui tient dans `place` rangées d'un menu trop haut pour la fenêtre : l'en-tête (`entete` premières rangées :
/// cadre, titre) reste en place s'il laisse de la place à la liste, puis la partie de la liste qui contient la rangée
/// `en_cours`, entre deux annonces de ce qui est caché au-dessus et au-dessous. `haut`, la première rangée montrée de
/// la liste, est gardé d'un affichage à l'autre : la liste ne bouge que si la ligne en cours allait en sortir, et
/// garde alors une rangée de contexte (le titre d'une section). Rend au plus `place` rangées.
fn fenetre(rangees: &[String], entete: usize, en_cours: usize, place: usize, haut: &mut usize) -> Vec<String> {
    if rangees.len() <= place {
        *haut = 0;
        return rangees.to_vec();
    }
    // Au moins trois rangées de liste sous l'en-tête et les deux annonces ; sinon l'en-tête défile aussi.
    let entete = if entete + 2 + 3 <= place { entete } else { 0 };
    let liste = &rangees[entete..];
    let hauteur = place.saturating_sub(entete + 2).max(1);
    let ligne = en_cours.saturating_sub(entete).min(liste.len().saturating_sub(1));
    let marge = usize::from(hauteur >= 5);
    // Borné d'abord : l'appelant demande la fin de la liste avec `usize::MAX`.
    let dernier_haut = liste.len().saturating_sub(hauteur);
    *haut = (*haut).min(dernier_haut);
    if ligne < *haut + marge {
        *haut = ligne.saturating_sub(marge);
    } else if ligne + marge >= *haut + hauteur {
        *haut = (ligne + marge + 1).saturating_sub(hauteur);
    }
    *haut = (*haut).min(dernier_haut);
    let reste = liste.len().saturating_sub(*haut + hauteur);
    let annonce = |fleche: char, n: usize, texte: String| {
        if n == 0 {
            String::new()
        } else {
            format!("  {GRIS}{fleche} {texte}{RESET}")
        }
    };
    let mut ecran: Vec<String> = rangees[..entete].to_vec();
    ecran.push(annonce(
        '↑',
        *haut,
        trf!("{} ligne(s) plus haut", "{} more line(s) above", *haut),
    ));
    ecran.extend(liste.iter().skip(*haut).take(hauteur).cloned());
    ecran.push(annonce(
        '↓',
        reste,
        trf!("{reste} ligne(s) plus bas", "{reste} more line(s) below"),
    ));
    ecran
}

/// Le mode clavier (touches lues une à une, sans écho), rendu au terminal quoi qu'il arrive : choix fait, plantage.
struct ModeClavier;

impl ModeClavier {
    fn activer() -> Option<Self> {
        terminal::enable_raw_mode().ok().map(|()| ModeClavier)
    }
}

impl Drop for ModeClavier {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

/// Montre le menu et attend un choix : la touche de la ligne choisie, ce qui a été tapé (raccourci), ou `None` pour
/// Échap. `invite` : la question quand la réponse se lit ligne par ligne. `depart` : la touche de la ligne en
/// surbrillance au départ (la dernière choisie). `echap` : ce que fait Échap (« revenir », « quitter »).
pub fn choisir(lignes: &[Ligne], invite: &str, depart: &str, echap: &str) -> Option<String> {
    let choix = choisissables(lignes);
    let touches: Vec<&str> = choix.iter().map(|c| c.touche).collect();
    // Les flèches ne parcourent que les lignes affichées ; la recherche, elle, voit aussi les lignes cachées.
    let visibles: Vec<&str> = choix.iter().filter(|c| c.visible).map(|c| c.touche).collect();
    let colonne = colonne(lignes);
    // Le menu est redessiné depuis le haut de la fenêtre, sans retour à la ligne : assez large pour ses lignes ; s'il
    // est plus haut que la fenêtre, il défile.
    let tient = terminal::size()
        .is_ok_and(|(largeur, rangees)| usize::from(largeur) > LARGEUR && usize::from(rangees) >= RANGEES_MINIMUM);
    let clavier = std::io::stdin().is_terminal() && std::io::stdout().is_terminal() && tient && !visibles.is_empty();
    let Some(_mode) = clavier.then(ModeClavier::activer).flatten() else {
        for t in lignes.iter().filter_map(|l| texte(l, colonne, false)) {
            println!("{t}");
        }
        return Some(par_ligne(&choix, &touches, invite));
    };

    let mut en_cours = visibles
        .iter()
        .position(|t| t.eq_ignore_ascii_case(depart))
        .unwrap_or(0);
    // La ligne en surbrillance parmi celles que la recherche a trouvées.
    let mut en_cours_trouve = 0;
    // Première rangée montrée de la liste, quand le menu défile.
    let mut haut = 0;
    // Ce qui est tapé au clavier : un raccourci validé par Entrée, comme avant, ou des mots à chercher.
    let mut tape = String::new();
    let aide = trf!(
        "  {GRIS}↑ ↓ choisir · Entrée lancer · un mot : chercher · Échap {echap}{RESET}",
        "  {GRIS}↑ ↓ select · Enter run · a word: search · Esc {echap}{RESET}"
    );
    let aide_recherche = trf!(
        "  {GRIS}↑ ↓ choisir · Entrée lancer · Échap effacer la recherche{RESET}",
        "  {GRIS}↑ ↓ select · Enter run · Esc clear the search{RESET}"
    );
    // L'en-tête (cadre, titre, état) reste en place pendant la recherche, sans le sous-titre ni la ligne vide qui
    // annonçaient la première section (« BILAN DE SÉCURITÉ ») : les lignes trouvées viennent de partout.
    let mut entete: Vec<String> = lignes
        .iter()
        .take_while(|l| matches!(l, Ligne::Texte(_)))
        .filter_map(|l| texte(l, colonne, false))
        .collect();
    while entete.last().is_some_and(|t| {
        let t = simplement_affiche(t);
        t.trim().is_empty() || t.trim_start().starts_with("── ")
    }) {
        entete.pop();
    }
    entete.push(String::new());
    let hauteur_entete: usize = entete.iter().map(|t| 1 + t.matches('\n').count()).sum();
    let mut sortie = std::io::stdout();
    let _ = sortie.write_all(b"\x1b[2J");
    loop {
        let recherche = est_une_recherche(&tape, &touches);
        let trouves: Vec<&Choisissable> = if recherche {
            choix.iter().filter(|c| correspond(&tape, &c.cherche)).collect()
        } else {
            Vec::new()
        };
        en_cours_trouve = en_cours_trouve.min(trouves.len().saturating_sub(1));
        // En mode clavier, le terminal ne revient plus seul au début de la ligne : d'où les « \r\n ».
        let mut ecran = String::from("\x1b[H");
        if recherche {
            // L'en-tête reste au-dessus de la recherche s'il laisse au moins trois lignes trouvées à l'écran.
            let rangees = terminal::size().map_or(24, |(_, r)| usize::from(r));
            let montre_entete = hauteur_entete + 4 + 3 <= rangees;
            if montre_entete {
                for t in &entete {
                    ecran += &t.replace('\n', "\x1b[K\r\n");
                    ecran += "\x1b[K\r\n";
                }
            }
            ecran += &ligne_section(&trf!("RECHERCHE « {} »", "SEARCH “{}”", couper(tape.trim(), 40)));
            ecran += "\x1b[K\r\n";
            // Ce qui tient sous l'en-tête, au-dessus de l'aide et de la saisie ; au-delà, une ligne le dit.
            let au_dessus = if montre_entete { hauteur_entete } else { 0 };
            let mut place = rangees.saturating_sub(au_dessus + 4).max(1);
            if trouves.len() > place {
                place = place.saturating_sub(1).max(1);
            }
            let debut = (en_cours_trouve + 1).saturating_sub(place);
            let largeur = largeur_des_touches(trouves.iter().copied());
            for (i, c) in trouves.iter().enumerate().skip(debut).take(place) {
                ecran += &rendu_trouve(c, largeur, i == en_cours_trouve);
                ecran += "\x1b[K\r\n";
            }
            if trouves.is_empty() {
                let _ = write!(
                    ecran,
                    "  {GRIS}{}{RESET}\x1b[K\r\n",
                    tr!(
                        "Rien ne correspond : Retour arrière pour corriger, Échap pour effacer.",
                        "Nothing matches: Backspace to correct, Esc to clear."
                    )
                );
            } else if trouves.len() > place {
                let _ = write!(
                    ecran,
                    "  {GRIS}{}{RESET}\x1b[K\r\n",
                    trf!(
                        "… {} en tout : ajoute un mot pour préciser.",
                        "… {} in all: add a word to narrow it down.",
                        trouves.len()
                    )
                );
            }
            let _ = write!(ecran, "{aide_recherche}\x1b[K\r\n  {ACCENT}›{RESET} {tape}\x1b[K\x1b[J");
        } else {
            // Les rangées du menu ; l'en-tête est ce qui précède la première ligne de choix.
            let mut rangees: Vec<String> = Vec::new();
            let (mut n, mut rangee_en_cours, mut entete_menu) = (0, 0, None);
            for l in lignes {
                let ligne_de_choix = matches!(l, Ligne::Choix { .. });
                if ligne_de_choix {
                    entete_menu.get_or_insert(rangees.len());
                    if n == en_cours {
                        rangee_en_cours = rangees.len();
                    }
                }
                if let Some(t) = texte(l, colonne, ligne_de_choix && n == en_cours) {
                    rangees.extend(t.split('\n').map(String::from));
                }
                n += usize::from(ligne_de_choix);
            }
            // L'en-tête fixe s'arrête avant le titre de la première section et sa ligne vide : ils défilent avec la
            // liste, qu'ils annoncent.
            let mut entete_menu = entete_menu.unwrap_or(0);
            while entete_menu > 0 && {
                let t = simplement_affiche(&rangees[entete_menu - 1]);
                t.trim().is_empty() || t.trim_start().starts_with("── ")
            } {
                entete_menu -= 1;
            }
            // Première ou dernière ligne : la liste montre son début ou sa fin, titres compris.
            if en_cours == 0 {
                haut = 0;
            } else if en_cours + 1 == visibles.len() {
                haut = usize::MAX;
            }
            // L'aide et la saisie restent sous le menu.
            let place = terminal::size().map_or(24, |(_, r)| usize::from(r)).saturating_sub(2);
            for t in fenetre(&rangees, entete_menu, rangee_en_cours, place, &mut haut) {
                ecran += &t;
                ecran += "\x1b[K\r\n";
            }
            let _ = write!(ecran, "{aide}\x1b[K\r\n  {ACCENT}›{RESET} {tape}\x1b[K\x1b[J");
        }
        let _ = sortie.write_all(ecran.as_bytes());
        let _ = sortie.flush();

        let Ok(Event::Key(k)) = event::read() else {
            continue;
        };
        // Windows signale aussi le relâchement de la touche : un seul événement par appui.
        if k.kind == KeyEventKind::Release {
            continue;
        }
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        // Les flèches parcourent les lignes trouvées pendant une recherche, celles du menu sinon.
        let nombre = if recherche { trouves.len() } else { visibles.len() };
        let actuelle = if recherche { en_cours_trouve } else { en_cours };
        let derniere = nombre.saturating_sub(1);
        let deplacement = match k.code {
            KeyCode::Up | KeyCode::BackTab => Some(actuelle.checked_sub(1).unwrap_or(derniere)),
            KeyCode::Down | KeyCode::Tab => Some(if actuelle >= derniere { 0 } else { actuelle + 1 }),
            KeyCode::Home | KeyCode::PageUp => Some(0),
            KeyCode::End | KeyCode::PageDown => Some(derniere),
            _ => None,
        };
        // Ctrl-J ou Ctrl-M : le saut de ligne que certains terminaux envoient pour Entrée.
        let entree = k.code == KeyCode::Enter || (ctrl && matches!(k.code, KeyCode::Char('j' | 'm')));
        if let Some(i) = deplacement {
            if recherche {
                en_cours_trouve = i;
            } else {
                en_cours = i;
                tape.clear();
            }
        } else if entree {
            if recherche {
                // Rien de trouvé : Entrée ne lance rien, on corrige ou on efface.
                let Some(c) = trouves.get(en_cours_trouve) else {
                    continue;
                };
                let _ = sortie.write_all(b"\r\n");
                return Some(c.touche.to_string());
            }
            let _ = sortie.write_all(b"\r\n");
            return Some(if tape.is_empty() {
                visibles[en_cours].to_string()
            } else {
                tape
            });
        } else if ctrl && matches!(k.code, KeyCode::Char('c' | 'd')) {
            // Ctrl-C arrête Gardien ; Ctrl-D (fin de l'entrée) le quitte, comme avant.
            let _ = terminal::disable_raw_mode();
            println!();
            std::process::exit(if k.code == KeyCode::Char('c') { 130 } else { 0 });
        } else if k.code == KeyCode::Esc || (k.code == KeyCode::Backspace && tape.is_empty()) {
            // Retour arrière sans rien de tapé : revient en arrière, comme Échap.
            if tape.is_empty() {
                let _ = sortie.write_all(b"\r\n");
                return None;
            }
            // Échap pendant une recherche l'efface : le menu revient en entier.
            tape.clear();
            en_cours_trouve = 0;
        } else {
            match k.code {
                KeyCode::Backspace => {
                    tape.pop();
                }
                KeyCode::Char(c) if !ctrl => tape.push(c),
                _ => continue,
            }
            // Chaque lettre change ce qui est trouvé : la surbrillance repart du premier.
            en_cours_trouve = 0;
            // La surbrillance suit la touche tapée.
            if let Some(i) = visibles.iter().position(|t| t.eq_ignore_ascii_case(&tape)) {
                en_cours = i;
            }
        }
    }
}

/// Une ligne de choix d'une liste à cocher.
pub struct Case {
    pub texte: String,
    /// État en gris à droite (« fait », « à faire »…).
    pub precision: String,
    /// Explication montrée sous la liste quand la ligne est en surbrillance.
    pub detail: String,
    pub cochee: bool,
    /// Cochée par R (« recommandés »).
    pub recommandee: bool,
    /// Déjà faite (un logiciel installé) : montrée « [✔] », ni Espace ni R ne la changent.
    pub fixe: bool,
}

fn rendu_case(n: usize, c: &Case, cochee: bool, colonne: usize, en_cours: bool) -> String {
    let (marque, gras) = if en_cours {
        (format!("{ACCENT}►{RESET}"), GRAS)
    } else {
        (" ".to_string(), "")
    };
    let case = if c.fixe {
        format!("{VERT}[✔]{RESET}")
    } else if cochee {
        format!("{VERT}[x]{RESET}")
    } else {
        "[ ]".to_string()
    };
    format!(
        " {marque} {TOUCHE}{n:>2}{RESET} {case} {gras}{}{RESET}{DISCRET}{}{RESET}",
        ajuster(&c.texte, colonne),
        c.precision
    )
}

/// Liste à cocher, sous un titre : ↑ ↓ pour se déplacer, Espace pour cocher ou décocher, R pour cocher les
/// recommandés, Entrée pour valider, Échap pour revenir sans rien changer. Retourne l'état final des cases, ou
/// `None` pour Échap. Sans terminal, les numéros à inverser se tapent sur une ligne (« 1 4 », « r »). Une case
/// `fixe` garde son état.
pub fn cocher(titre: &[String], cases: &[Case]) -> Option<Vec<bool>> {
    let mut etats: Vec<bool> = cases.iter().map(|c| c.cochee).collect();
    if cases.is_empty() {
        return Some(etats);
    }
    let colonne = cases
        .iter()
        .map(|c| largeur_affichee(&c.texte) + 2)
        .max()
        .unwrap_or(0)
        .clamp(30, 44);
    let lignes_detail = 3;
    // Sous la liste : une ligne vide, l'explication de la ligne en cours, l'aide.
    let dessous = 1 + lignes_detail + 1;
    // Une liste plus haute que la fenêtre défile ; une fenêtre minuscule lit la réponse ligne par ligne.
    let tient = terminal::size().is_ok_and(|(largeur, rangees)| {
        usize::from(largeur) > LARGEUR && usize::from(rangees) >= RANGEES_MINIMUM + dessous - 2
    });
    let clavier = std::io::stdin().is_terminal() && std::io::stdout().is_terminal() && tient;
    let Some(_mode) = clavier.then(ModeClavier::activer).flatten() else {
        for l in titre {
            println!("{l}");
        }
        for (i, c) in cases.iter().enumerate() {
            println!("{}", rendu_case(i + 1, c, c.cochee, colonne, false));
        }
        let reponse = demander(tr!(
            "\n  Numéros à cocher ou décocher (ex. 1 4), r = recommandés, Entrée = valider, q = revenir : ",
            "\n  Numbers to check or uncheck (e.g. 1 4), r = recommended, Enter = confirm, q = back: "
        ));
        if reponse.eq_ignore_ascii_case("q") {
            return None;
        }
        for mot in reponse
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|m| !m.is_empty())
        {
            if mot.eq_ignore_ascii_case("r") {
                for (e, c) in etats.iter_mut().zip(cases) {
                    *e |= c.recommandee && !c.fixe;
                }
            } else if let Some(i) = mot
                .parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .filter(|&i| cases.get(i).is_some_and(|c| !c.fixe))
            {
                etats[i] = !etats[i];
            }
        }
        return Some(etats);
    };

    let aide = trf!(
        "  {GRIS}↑ ↓ choisir · Espace cocher · R recommandés · Entrée valider · Échap revenir{RESET}",
        "  {GRIS}↑ ↓ select · Space check · R recommended · Enter confirm · Esc back{RESET}"
    );
    let mut en_cours = 0;
    let mut haut = 0;
    let mut sortie = std::io::stdout();
    let _ = sortie.write_all(b"\x1b[2J");
    loop {
        let mut ecran = String::from("\x1b[H");
        let mut rangees: Vec<String> = titre.iter().flat_map(|l| l.split('\n').map(String::from)).collect();
        let entete = rangees.len();
        rangees.extend(
            cases
                .iter()
                .enumerate()
                .map(|(i, c)| rendu_case(i + 1, c, etats[i], colonne, i == en_cours)),
        );
        if en_cours == 0 {
            haut = 0;
        } else if en_cours + 1 == cases.len() {
            haut = usize::MAX;
        }
        let place = terminal::size()
            .map_or(24, |(_, r)| usize::from(r))
            .saturating_sub(dessous);
        for t in fenetre(&rangees, entete, entete + en_cours, place, &mut haut) {
            ecran += &t;
            ecran += "\x1b[K\r\n";
        }
        ecran += "\x1b[K\r\n";
        // L'explication de la ligne en cours, toujours sur le même nombre de lignes : l'écran ne saute pas.
        let mut detail = envelopper(&cases[en_cours].detail, LARGEUR - 4);
        detail.resize(lignes_detail, String::new());
        for l in detail.iter().take(lignes_detail) {
            let _ = write!(ecran, "  {GRIS}{l}{RESET}\x1b[K\r\n");
        }
        let _ = write!(ecran, "{aide}\x1b[K\x1b[J");
        let _ = sortie.write_all(ecran.as_bytes());
        let _ = sortie.flush();

        let Ok(Event::Key(k)) = event::read() else {
            continue;
        };
        if k.kind == KeyEventKind::Release {
            continue;
        }
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let derniere = cases.len() - 1;
        match k.code {
            KeyCode::Up | KeyCode::BackTab => en_cours = en_cours.checked_sub(1).unwrap_or(derniere),
            KeyCode::Down | KeyCode::Tab => en_cours = if en_cours == derniere { 0 } else { en_cours + 1 },
            KeyCode::Home | KeyCode::PageUp => en_cours = 0,
            KeyCode::End | KeyCode::PageDown => en_cours = derniere,
            KeyCode::Char(' ') if !cases[en_cours].fixe => etats[en_cours] = !etats[en_cours],
            KeyCode::Char('r' | 'R') if !ctrl => {
                for (e, c) in etats.iter_mut().zip(cases) {
                    *e |= c.recommandee && !c.fixe;
                }
            }
            KeyCode::Enter => {
                let _ = sortie.write_all(b"\r\n");
                return Some(etats);
            }
            KeyCode::Char('j' | 'm') if ctrl => {
                let _ = sortie.write_all(b"\r\n");
                return Some(etats);
            }
            // Rien ne se tape dans une liste à cocher : Retour arrière revient en arrière, comme Échap.
            KeyCode::Esc | KeyCode::Backspace => {
                let _ = sortie.write_all(b"\r\n");
                return None;
            }
            KeyCode::Char('c' | 'd') if ctrl => {
                let _ = terminal::disable_raw_mode();
                println!();
                std::process::exit(if k.code == KeyCode::Char('c') { 130 } else { 0 });
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_ligne_en_cours_se_voit_et_tout_reste_aligne() {
        let lignes = [
            Ligne::choix("1", "Bilan complet", "← commencer ici"),
            Ligne::choix("q", "Quitter", ""),
        ];
        let c = colonne(&lignes);
        let normale = rendu("1", "Bilan complet", "← commencer ici", c, false);
        let choisie = rendu("1", "Bilan complet", "← commencer ici", c, true);
        assert!(choisie.contains('►') && !normale.contains('►'));
        assert_eq!(largeur_affichee(&normale), largeur_affichee(&choisie));
        // Un long titre (réparations) n'est pas coupé : la colonne des précisions se pousse.
        let long = "Navigation détournée (proxy, fichier hosts)";
        let c = colonne(&[Ligne::choix("2", long, "rien à faire")]);
        assert!(rendu("2", long, "rien à faire", c, false).contains(long));
    }

    #[test]
    fn recherche_sans_accents_ni_majuscules() {
        let t = simplifier("Réseau et Internet › Scanner le Wi-Fi");
        assert_eq!(t, "reseau et internet › scanner le wifi");
        assert!(correspond("RESEAU", &t));
        // Tous les mots comptent, dans n'importe quel ordre.
        assert!(correspond("wi-fi scanner", &t));
        assert!(!correspond("wifi imprimante", &t));
        // Un mot court commence un mot : « sc » trouve « scanner », « an » ne trouve rien.
        assert!(correspond("sc", &t));
        assert!(!correspond("an", &t));
        assert!(!correspond("", &t));
        // La fin d'un mot peut changer : l'infinitif, le pluriel.
        let vide = simplifier("Vide le cache DNS. Répare les disques.");
        assert!(correspond("vider dns", &vide) && correspond("réparer", &vide) && correspond("disque", &vide));
        assert!(!correspond("réseau", &simplifier("Resets the TCP/IP settings")));
        assert_eq!(simplifier("\x1b[1;96mCœur\x1b[0m"), "coeur");
    }

    #[test]
    fn une_lettre_ou_une_touche_n_est_pas_une_recherche() {
        let touches = ["1", "10", "4.2", "q", "↵"];
        // Les raccourcis des anciennes versions (une lettre) et les touches, même à moitié tapées.
        assert!(!est_une_recherche("u", &touches));
        assert!(!est_une_recherche("10", &touches));
        assert!(!est_une_recherche("4.", &touches));
        assert!(!est_une_recherche(" 4.2 ", &touches));
        assert!(est_une_recherche("wifi", &touches));
        assert!(est_une_recherche("1a", &touches));
    }

    #[test]
    fn les_lignes_cachees_se_trouvent_et_tiennent_dans_l_ecran() {
        let lignes = [
            Ligne::Texte("titre".into()),
            Ligne::choix("1", "Bilan complet", "← commencer ici"),
            Ligne::cachee(
                "5.2",
                "Réseau et Internet ›",
                "Scan approfondi d'un appareil",
                "tous les ports",
            )
            .avec_mots("nmap"),
        ];
        let choix = choisissables(&lignes);
        assert_eq!(choix.len(), 2);
        assert!(choix[0].visible && !choix[1].visible);
        assert!(correspond("approfondi", &choix[1].cherche));
        // Les mots en plus se trouvent sans s'afficher.
        assert!(correspond("nmap", &choix[1].cherche));
        assert!(!choix[1].texte.contains("nmap"));
        // Hors recherche, une ligne cachée ne s'affiche pas.
        assert!(texte(&lignes[2], 36, false).is_none());
        // Un très long chemin est coupé : la ligne trouvée tient dans LARGEUR.
        let long = [Ligne::cachee(
            "10.1.12",
            &"chemin très long ".repeat(10),
            "texte",
            "précision",
        )];
        let c = choisissables(&long);
        assert!(largeur_affichee(&rendu_trouve(&c[0], 7, true)) <= LARGEUR);
    }

    #[test]
    fn un_menu_trop_haut_defile() {
        let rangees: Vec<String> = (0..40).map(|i| format!("r{i}")).collect();
        let mut haut = 0;
        // Il tient : tout, tel quel.
        assert_eq!(fenetre(&rangees[..10], 2, 5, 20, &mut haut), rangees[..10].to_vec());
        // 40 rangées dont 3 d'en-tête, dans 20 : l'en-tête reste, la ligne en cours se voit, 20 rangées au plus.
        for en_cours in 3..40 {
            let e = fenetre(&rangees, 3, en_cours, 20, &mut haut);
            assert!(e.len() <= 20, "{e:?}");
            assert_eq!(e[..3], rangees[..3]);
            assert!(e.contains(&rangees[en_cours]), "{en_cours} : {e:?}");
        }
        // Au bout : l'annonce du dessus dit ce qui est caché, celle du dessous est vide.
        let e = fenetre(&rangees, 3, 39, 20, &mut haut);
        assert!(e[3].contains('↑') && e[3].contains("22"), "{e:?}");
        assert!(e.last().is_some_and(String::is_empty));
        // Remonter d'une ligne, sans sortir de l'écran, ne fait pas bouger la liste.
        let avant = haut;
        let _ = fenetre(&rangees, 3, 37, 20, &mut haut);
        assert_eq!(haut, avant);
        // Revenir en haut garde une rangée de contexte au-dessus de la ligne en cours (un titre de section).
        let e = fenetre(&rangees, 3, 10, 20, &mut haut);
        assert!(e.contains(&rangees[9]) && e.contains(&rangees[10]), "{e:?}");
        // La fin demandée par usize::MAX (touche Fin, dernière ligne) : le bas de la liste, sans débordement.
        let mut tout_en_bas = usize::MAX;
        let e = fenetre(&rangees, 3, 39, 20, &mut tout_en_bas);
        assert!(e.contains(&rangees[39]) && e.last().is_some_and(String::is_empty) && tout_en_bas == 22);
        // Un en-tête trop haut pour la fenêtre défile avec le reste.
        let e = fenetre(&rangees, 30, 35, 20, &mut haut);
        assert!(e.len() <= 20 && e.contains(&rangees[35]));
        // Toutes les tailles de fenêtre : jamais plus de rangées que de place, la ligne en cours toujours là.
        for place in 5..45 {
            for en_cours in 0..40 {
                for depart in [0, 7, usize::MAX] {
                    let mut h = depart;
                    let e = fenetre(&rangees, 3, en_cours, place, &mut h);
                    assert!(
                        e.len() <= place && e.contains(&rangees[en_cours]),
                        "{place} {en_cours} : {e:?}"
                    );
                }
            }
        }
    }
}
