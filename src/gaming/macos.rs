//! Gaming sous macOS : Rosetta 2 (les jeux pour processeur Intel sur un Mac Apple Silicon), les lanceurs de jeux par
//! Homebrew, et le compteur d'images de Metal. Le Mode Jeu de macOS (Sonoma et plus récents) s'active tout seul en
//! plein écran : rien à régler.

use super::{Element, element, proposer};
use crate::machine::macos::{app_installee, installer_cask};
use crate::ui::*;

/// Rosetta 2 installé : son moteur d'exécution est là (il n'existe pas sur un Mac Intel, qui n'en a pas besoin).
fn rosetta_installe() -> bool {
    std::path::Path::new("/Library/Apple/usr/libexec/oah/libRosettaRuntime").exists()
}

/// Le compteur de Metal est-il affiché dans tous les jeux ? (« defaults read -g MetalForceHudEnabled » : 1)
fn compteur_metal() -> Option<bool> {
    let r = crate::commande::lancer(
        std::process::Command::new("defaults").args(["read", "-g", "MetalForceHudEnabled"]),
        10,
    )?;
    // Clé absente : le compteur est caché (réglage d'origine), la commande répond en erreur.
    Some(r.code == Some(0) && r.sortie.trim() == "1")
}

fn lanceur(nom: &str, pourquoi: &str, app: &str, cask: &str) -> Element {
    element(nom, pourquoi, Some(app_installee(app)), installer_cask(cask))
}

pub fn menu() {
    let mut elements = Vec::new();
    if cfg!(target_arch = "aarch64") {
        elements.push(element(
            "Rosetta 2",
            tr!(
                "Fait tourner sur ce Mac Apple Silicon les jeux et programmes écrits pour les Mac Intel (beaucoup de jeux Steam).",
                "Runs games and programs written for Intel Macs on this Apple Silicon Mac (many Steam games)."
            ),
            Some(rosetta_installe()),
            vec!["sudo softwareupdate --install-rosetta --agree-to-license".into()],
        ));
    }
    elements.extend([
        lanceur(
            "Steam",
            tr!(
                "La boutique et le lanceur de jeux de Valve (de nombreux jeux tournent nativement sur Mac).",
                "Valve's game store and launcher (many games run natively on Mac)."
            ),
            "Steam",
            "steam",
        ),
        lanceur(
            "Heroic Games Launcher",
            tr!(
                "Lanceur libre pour les jeux Epic Games, GOG et Amazon.",
                "Free launcher for Epic Games, GOG and Amazon games."
            ),
            "Heroic",
            "heroic",
        ),
        lanceur(
            "Epic Games Launcher",
            tr!(
                "Le lanceur officiel d'Epic Games, et ses jeux offerts chaque semaine.",
                "Epic Games' official launcher, and its free games every week."
            ),
            "Epic Games Launcher",
            "epic-games",
        ),
        lanceur(
            "GOG Galaxy",
            tr!(
                "Le lanceur de GOG : des jeux vendus sans verrou anti-copie.",
                "GOG's launcher: games sold without copy protection."
            ),
            "GOG Galaxy",
            "gog-galaxy",
        ),
        lanceur(
            "Prism Launcher",
            tr!(
                "Lanceur libre pour Minecraft : plusieurs versions et mods côte à côte.",
                "Free launcher for Minecraft: several versions and mods side by side."
            ),
            "Prism Launcher",
            "prismlauncher",
        ),
    ]);
    // Réglage : le compteur d'images de Metal (images par seconde, temps d'image), l'équivalent de MangoHud.
    elements.push(element(
        tr!("Compteur d'images (Metal)", "Frame counter (Metal)"),
        tr!(
            "Affiche dans chaque jeu les images par seconde et la mémoire graphique. Pour l'enlever : defaults delete -g MetalForceHudEnabled.",
            "Shows frames per second and graphics memory in every game. To remove it: defaults delete -g MetalForceHudEnabled."
        ),
        compteur_metal(),
        vec!["defaults write -g MetalForceHudEnabled -bool YES".into()],
    ));
    trp!(
        "  {GRIS}Le Mode Jeu de macOS s'active tout seul quand un jeu passe en plein écran.{RESET}",
        "  {GRIS}macOS Game Mode turns on by itself when a game goes full screen.{RESET}"
    );
    proposer(tr!("Gaming (macOS)", "Gaming (macOS)"), &elements);
}
