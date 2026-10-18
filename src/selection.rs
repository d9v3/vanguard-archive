//! Menus au clavier : ↑ ↓ pour se déplacer, Entrée pour lancer, Échap pour revenir. Les touches d'avant (un chiffre
//! ou une lettre, puis Entrée) marchent toujours, et la ligne en surbrillance les suit. Sans vrai terminal (réponses
//! envoyées par un tube : tests, scripts), ou dans une fenêtre trop petite pour le menu, la réponse se lit ligne
//! par ligne, comme avant.

use std::fmt::Write as _;
use std::io::{IsTerminal, Write};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;

use crate::ui::*;

/// Une ligne d'un menu.
pub enum Ligne {
    /// Affichée telle quelle : cadre, titre, état, ligne vide.
    Texte(String),
    /// Ligne qu'on peut choisir : la touche qui la désigne, son texte, une précision en gris à droite.
    Choix {
        touche: String,
        texte: String,
        precision: String,
    },
}

impl Ligne {
    pub fn choix(touche: &str, texte: &str, precision: &str) -> Self {
        Ligne::Choix {
            touche: touche.into(),
            texte: texte.into(),
            precision: precision.into(),
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
            Ligne::Texte(_) => None,
        })
        .max()
        .unwrap_or(0);
    (plus_long + 2).clamp(36, 48)
}

fn texte(l: &Ligne, colonne: usize, en_cours: bool) -> String {
    match l {
        Ligne::Texte(t) => t.clone(),
        Ligne::Choix {
            touche,
            texte,
            precision,
        } => rendu(touche, texte, precision, colonne, en_cours),
    }
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
    let touches: Vec<&str> = lignes
        .iter()
        .filter_map(|l| match l {
            Ligne::Choix { touche, .. } => Some(touche.as_str()),
            Ligne::Texte(_) => None,
        })
        .collect();
    let colonne = colonne(lignes);
    // Le menu est redessiné depuis le haut de la fenêtre : il doit y tenir en entier, sans retour à la ligne.
    let hauteur: usize = lignes
        .iter()
        .map(|l| 1 + texte(l, colonne, false).matches('\n').count())
        .sum();
    let tient = terminal::size()
        .is_ok_and(|(largeur, rangees)| usize::from(largeur) > LARGEUR && usize::from(rangees) >= hauteur + 2);
    let clavier = std::io::stdin().is_terminal() && std::io::stdout().is_terminal() && tient && !touches.is_empty();
    let Some(_mode) = clavier.then(ModeClavier::activer).flatten() else {
        for l in lignes {
            println!("{}", texte(l, colonne, false));
        }
        return Some(demander(invite));
    };

    let mut en_cours = touches.iter().position(|t| t.eq_ignore_ascii_case(depart)).unwrap_or(0);
    // Ce qui est tapé au clavier : un raccourci, validé par Entrée comme avant.
    let mut tape = String::new();
    let aide = trf!(
        "  {GRIS}↑ ↓ choisir · Entrée lancer · Échap {echap}{RESET}",
        "  {GRIS}↑ ↓ select · Enter run · Esc {echap}{RESET}"
    );
    let mut sortie = std::io::stdout();
    let _ = sortie.write_all(b"\x1b[2J");
    loop {
        // En mode clavier, le terminal ne revient plus seul au début de la ligne : d'où les « \r\n ».
        let mut ecran = String::from("\x1b[H");
        let mut n = 0;
        for l in lignes {
            let choix = matches!(l, Ligne::Choix { .. });
            ecran += &texte(l, colonne, choix && n == en_cours).replace('\n', "\x1b[K\r\n");
            ecran += "\x1b[K\r\n";
            n += usize::from(choix);
        }
        let _ = write!(ecran, "{aide}\x1b[K\r\n  {ACCENT}›{RESET} {tape}\x1b[K\x1b[J");
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
        let derniere = touches.len() - 1;
        let deplacement = match k.code {
            KeyCode::Up | KeyCode::BackTab => Some(en_cours.checked_sub(1).unwrap_or(derniere)),
            KeyCode::Down | KeyCode::Tab => Some(if en_cours == derniere { 0 } else { en_cours + 1 }),
            KeyCode::Home | KeyCode::PageUp => Some(0),
            KeyCode::End | KeyCode::PageDown => Some(derniere),
            _ => None,
        };
        // Ctrl-J ou Ctrl-M : le saut de ligne que certains terminaux envoient pour Entrée.
        let entree = k.code == KeyCode::Enter || (ctrl && matches!(k.code, KeyCode::Char('j' | 'm')));
        if let Some(i) = deplacement {
            en_cours = i;
            tape.clear();
        } else if entree {
            let _ = sortie.write_all(b"\r\n");
            return Some(if tape.is_empty() {
                touches[en_cours].to_string()
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
            tape.clear();
        } else {
            match k.code {
                KeyCode::Backspace => {
                    tape.pop();
                }
                KeyCode::Char(c) if !ctrl => tape.push(c),
                _ => continue,
            }
            // La surbrillance suit la touche tapée.
            if let Some(i) = touches.iter().position(|t| t.eq_ignore_ascii_case(&tape)) {
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
    let hauteur = titre.len() + cases.len() + 1 + lignes_detail + 2;
    let tient = terminal::size()
        .is_ok_and(|(largeur, rangees)| usize::from(largeur) > LARGEUR && usize::from(rangees) >= hauteur);
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
    let mut sortie = std::io::stdout();
    let _ = sortie.write_all(b"\x1b[2J");
    loop {
        let mut ecran = String::from("\x1b[H");
        for l in titre {
            ecran += l;
            ecran += "\x1b[K\r\n";
        }
        for (i, c) in cases.iter().enumerate() {
            ecran += &rendu_case(i + 1, c, etats[i], colonne, i == en_cours);
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
}
