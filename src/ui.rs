//! Couleurs et petits éléments d'affichage partagés.

use crate::risk::Niveau;

pub const RESET: &str = "\x1b[0m";
pub const GRAS: &str = "\x1b[1m";
pub const GRIS: &str = "\x1b[2m";
pub const VERT: &str = "\x1b[1;32m";

pub fn couleur(niveau: Niveau) -> &'static str {
    match niveau {
        Niveau::Info => "\x1b[36m",
        Niveau::Moyen => "\x1b[33m",
        Niveau::Eleve => "\x1b[38;5;208m",
        Niveau::Critique => "\x1b[1;31m",
    }
}

pub fn couleur_note(n: &str) -> &'static str {
    match n {
        "A" | "B" => VERT,
        "C" => "\x1b[1;33m",
        _ => "\x1b[1;31m",
    }
}

pub fn titre(t: &str) {
    println!("\n{GRAS}══ {t} ══{RESET}");
}

pub fn afficher_note(quoi: &str, score: u32) {
    let n = crate::risk::note(score);
    println!("  {quoi} : {}{n}{RESET} ({score}/100)", couleur_note(n));
}

/// Pose une question dans le terminal et retourne la réponse sans espaces autour.
pub fn demander(question: &str) -> String {
    use std::io::Write;
    print!("{question}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim().to_string()
}
