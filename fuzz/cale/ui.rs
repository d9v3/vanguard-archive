//! Cale : `crate::ui::affichable`, qui ne fait que remplacer des caractères. Le fuzzing cherche les plantages des
//! lecteurs, pas ceux de l'affichage : la copie conforme n'est pas utile ici.

pub fn affichable(texte: &str) -> String {
    texte
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}
