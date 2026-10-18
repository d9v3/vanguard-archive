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
            // Ctrl-C arrête sentinel ; Ctrl-D (fin de l'entrée) le quitte, comme avant.
            let _ = terminal::disable_raw_mode();
            println!();
            std::process::exit(if k.code == KeyCode::Char('c') { 130 } else { 0 });
        } else if k.code == KeyCode::Esc {
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
