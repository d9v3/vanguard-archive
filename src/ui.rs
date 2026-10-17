//! Couleurs et petits éléments d'affichage partagés.

pub use crate::langue::Reponse;
use crate::risk::Niveau;
pub use crate::{tr, tre, trf, trp};

pub const RESET: &str = "\x1b[0m";
pub const GRAS: &str = "\x1b[1m";
/// Texte secondaire : un gris clair, lisible sur un fond noir (le « gris atténué » du terminal l'était mal).
pub const GRIS: &str = "\x1b[38;5;250m";
pub const VERT: &str = "\x1b[1;92m";
/// Titres de section et touches du menu.
pub const ACCENT: &str = "\x1b[1;96m";
/// Touches du menu : blanc vif.
pub const TOUCHE: &str = "\x1b[1;97m";
/// Précisions à côté d'un texte : un cran sous le gris clair, pour qu'on les distingue du texte principal.
pub const DISCRET: &str = "\x1b[38;5;245m";

/// Largeur des titres et des cadres (tient dans un terminal de 80 colonnes).
pub const LARGEUR: usize = 76;

pub fn couleur(niveau: Niveau) -> &'static str {
    match niveau {
        Niveau::Info => "\x1b[96m",
        Niveau::Moyen => "\x1b[93m",
        Niveau::Eleve => "\x1b[38;5;214m",
        Niveau::Critique => "\x1b[1;91m",
    }
}

pub fn couleur_note(n: &str) -> &'static str {
    match n {
        "A" | "B" => VERT,
        "C" => "\x1b[1;93m",
        _ => "\x1b[1;91m",
    }
}

/// Largeur affichée d'un texte (sans les codes de couleur).
pub fn largeur_affichee(t: &str) -> usize {
    let mut n = 0;
    let mut code = false;
    for c in t.chars() {
        match (code, c) {
            (false, '\x1b') => code = true,
            (true, 'm') => code = false,
            (false, _) => n += 1,
            _ => {}
        }
    }
    n
}

/// Coupe un texte trop long (« … » à la fin) ou le complète d'espaces jusqu'à `n` caractères.
pub fn ajuster(t: &str, n: usize) -> String {
    let l = largeur_affichee(t);
    // Un texte en couleur n'est jamais coupé (on couperait un code) : seulement complété.
    if l > n && !t.contains('\x1b') {
        let mut court: String = t.chars().take(n.saturating_sub(1)).collect();
        court.push('…');
        court
    } else {
        format!("{t}{}", " ".repeat(n.saturating_sub(l)))
    }
}

/// Coupe un texte en lignes d'au plus `largeur` caractères, aux espaces.
pub fn envelopper(t: &str, largeur: usize) -> Vec<String> {
    let mut lignes = Vec::new();
    let mut ligne = String::new();
    for mot in t.split_whitespace() {
        if !ligne.is_empty() && ligne.chars().count() + 1 + mot.chars().count() > largeur {
            lignes.push(std::mem::take(&mut ligne));
        }
        if !ligne.is_empty() {
            ligne.push(' ');
        }
        ligne.push_str(mot);
    }
    if !ligne.is_empty() {
        lignes.push(ligne);
    }
    lignes
}

/// Titre de section : « ━━ Titre ━━━━━━━━… » sur toute la largeur.
pub fn titre(t: &str) {
    let reste = LARGEUR.saturating_sub(largeur_affichee(t) + 4);
    println!("\n{ACCENT}━━ {t} {}{RESET}", "━".repeat(reste));
}

/// Sous-titre discret à l'intérieur d'un écran : « ── NOM ──────… ».
pub fn section(t: &str) {
    let reste = LARGEUR.saturating_sub(largeur_affichee(t) + 6);
    println!("\n  {ACCENT}── {t}{RESET} {GRIS}{}{RESET}", "─".repeat(reste));
}

/// Cadre de tête d'écran : un titre à gauche, une précision à droite.
pub fn cadre(gauche: &str, droite: &str) {
    let interieur = LARGEUR - 2;
    let espace = interieur.saturating_sub(largeur_affichee(gauche) + largeur_affichee(droite) + 4);
    println!("{ACCENT}╭{}╮{RESET}", "─".repeat(interieur));
    println!(
        "{ACCENT}│{RESET}  {gauche}{}{droite}  {ACCENT}│{RESET}",
        " ".repeat(espace)
    );
    println!("{ACCENT}╰{}╯{RESET}", "─".repeat(interieur));
}

/// Barre de score sur 10 cases, de la couleur de sa lettre : « ▰▰▰▰▰▰▰▰▱▱ ».
pub fn barre(score: u32) -> String {
    let pleines = (score.min(100) as usize + 5) / 10;
    format!(
        "{}{}{GRIS}{}{RESET}",
        couleur_note(crate::risk::note(score)),
        "▰".repeat(pleines),
        "▱".repeat(10 - pleines)
    )
}

/// Note sous forme d'étiquette : « A 100 » en couleur.
pub fn etiquette_note(score: u32) -> String {
    let n = crate::risk::note(score);
    format!("{}{n}{RESET} {GRIS}{score}{RESET}", couleur_note(n))
}

pub fn afficher_note(quoi: &str, score: u32) {
    let n = crate::risk::note(score);
    let c = couleur_note(n);
    crate::trp!(
        "  {quoi} : {c}{n}{RESET} ({score}/100)  {}",
        "  {quoi}: {c}{n}{RESET} ({score}/100)  {}",
        barre(score)
    );
}

/// « a, b, c (et 2 autre(s)) » / “a, b, c (and 2 more)” : les `max` premiers éléments d'une liste, pour un message d'une ligne.
pub fn resume(noms: &[impl AsRef<str>], max: usize, separateur: &str) -> String {
    let mut t = noms
        .iter()
        .take(max)
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(separateur);
    if noms.len() > max {
        let reste = noms.len() - max;
        t += &crate::trf!(" (et {reste} autre(s))", " (and {reste} more)");
    }
    t
}

/// Pose une question dans le terminal et retourne la réponse sans espaces autour.
pub fn demander(question: &str) -> String {
    use std::io::Write;
    print!("{question}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    // Fin de l'entrée (Ctrl-D, terminal fermé, entrée redirigée) : on quitte. Le menu reposait sinon la question
    // sans fin, en effaçant l'écran à toute vitesse (un cœur du processeur à 100 %). Vu en test.
    if matches!(std::io::stdin().read_line(&mut s), Ok(0) | Err(_)) {
        println!();
        std::process::exit(0);
    }
    s.trim().to_string()
}
