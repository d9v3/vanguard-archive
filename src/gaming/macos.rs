//! Gaming sous macOS : les lanceurs de jeux, par Homebrew. Le Mode Jeu de macOS (Sonoma et plus récents) s'active
//! tout seul en plein écran : rien à régler.

use super::{element, proposer};
use crate::machine::macos::{app_installee, installer_cask};
use crate::ui::*;

pub fn menu() {
    let elements = vec![
        element(
            "Steam",
            tr!(
                "La boutique et le lanceur de jeux de Valve (de nombreux jeux tournent nativement sur Mac).",
                "Valve's game store and launcher (many games run natively on Mac)."
            ),
            Some(app_installee("Steam")),
            installer_cask("steam"),
        ),
        element(
            "Heroic Games Launcher",
            tr!(
                "Lanceur libre pour les jeux Epic Games, GOG et Amazon.",
                "Free launcher for Epic Games, GOG and Amazon games."
            ),
            Some(app_installee("Heroic")),
            installer_cask("heroic"),
        ),
    ];
    trp!(
        "  {GRIS}Le Mode Jeu de macOS s'active tout seul quand un jeu passe en plein écran.{RESET}",
        "  {GRIS}macOS Game Mode turns on by itself when a game goes full screen.{RESET}"
    );
    proposer(tr!("Gaming (macOS)", "Gaming (macOS)"), &elements);
}
