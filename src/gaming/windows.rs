//! Gaming sous Windows : composants dont les jeux ont besoin (Visual C++, .NET, DirectX, XNA, PhysX, pilote
//! graphique) et réglages de Windows utiles en jeu.
//! Tout est lu d'abord (un seul appel PowerShell), montré avec son état, puis appliqué seulement après accord.
//! Les réglages qui retirent une protection (intégrité de la mémoire, Defender, pare-feu…) ne sont jamais proposés.

use std::fmt::Write;

use serde::Deserialize;

#[cfg(test)]
use super::lire_choix;
use super::{Element, element, proposer};
use crate::machine;
use crate::trw;
use crate::ui::*;

/// Ce que Gardien lit avant d'afficher le menu : une photo de l'état, lue telle quelle depuis PowerShell.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default, Deserialize)]
#[serde(default)]
struct Etat {
    winget: bool,
    /// Noms des programmes installés (panneau « Applications installées »).
    programmes: Vec<String>,
    vc14_x64: bool,
    vc14_x86: bool,
    directx9: bool,
    netfx3: bool,
    gpu: Vec<Carte>,
    portable: bool,
    windows11: bool,
    mode_jeu: Option<u32>,
    hags: Option<u32>,
    fenetres: String,
    dvr: Option<u32>,
    capture: Option<u32>,
    souris: String,
    alimentation: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Carte {
    nom: String,
    version: String,
    date: String,
}

fn lire_etat() -> Option<Etat> {
    let json = machine::windows::ps(
        r#"$noms = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ })
          function Lire($cle, $nom) { $v = Get-ItemProperty $cle -Name $nom -ErrorAction SilentlyContinue; if ($v) { $v.$nom } else { $null } }
          $vc = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes'
          [pscustomobject]@{
            winget = [bool](Get-Command winget -ErrorAction SilentlyContinue)
            programmes = $noms
            vc14_x64 = (Lire "$vc\x64" Installed) -eq 1
            vc14_x86 = (Lire "$vc\x86" Installed) -eq 1
            directx9 = (Test-Path "$env:SystemRoot\System32\d3dx9_43.dll") -and (Test-Path "$env:SystemRoot\SysWOW64\d3dx9_43.dll")
            netfx3 = (Lire 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' Install) -eq 1
            gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'Basic|Remote|Virtual|Parsec|Meta' } | ForEach-Object { [pscustomobject]@{ nom = [string]$_.Name; version = [string]$_.DriverVersion; date = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' } } })
            portable = [bool](Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
            windows11 = [Environment]::OSVersion.Version.Build -ge 22000
            mode_jeu = Lire 'HKCU:\Software\Microsoft\GameBar' AutoGameModeEnabled
            hags = Lire 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' HwSchMode
            fenetres = [string](Lire 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences' DirectXUserGlobalSettings)
            dvr = Lire 'HKCU:\System\GameConfigStore' GameDVR_Enabled
            capture = Lire 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' AppCaptureEnabled
            souris = [string](Lire 'HKCU:\Control Panel\Mouse' MouseSpeed)
            alimentation = [string](powercfg /getactivescheme)
          } | ConvertTo-Json -Compress -Depth 4"#,
    )?;
    serde_json::from_str(&json).ok()
}

fn winget(id: &str) -> String {
    machine::windows::winget_installer(id)
}

/// Écrit une valeur DWORD en créant la clé si besoin (jamais « New-Item -Force » sur une clé existante :
/// il l'effacerait avec toutes ses valeurs).
fn dword(cle: &str, nom: &str, valeur: u32) -> String {
    format!(
        "if (-not (Test-Path '{cle}')) {{ New-Item '{cle}' -Force | Out-Null }}; \
         Set-ItemProperty '{cle}' -Name {nom} -Value {valeur} -Type DWord"
    )
}

fn a_programme(e: &Etat, motif: &str) -> bool {
    e.programmes.iter().any(|p| p.contains(motif))
}

fn composants(e: &Etat) -> Vec<Element> {
    let mut l = vec![
        element(
            tr!(
                "Visual C++ 2015-2022 (64 et 32 bits)",
                "Visual C++ 2015-2022 (64 and 32 bit)"
            ),
            tr!(
                "Bibliothèques demandées par presque tous les jeux récents (erreur « VCRUNTIME140.dll introuvable »).",
                "Libraries needed by almost every recent game (“VCRUNTIME140.dll not found” error)."
            ),
            Some(e.vc14_x64 && e.vc14_x86),
            vec![
                winget("Microsoft.VCRedist.2015+.x64"),
                winget("Microsoft.VCRedist.2015+.x86"),
            ],
        ),
        {
            let annees = ["2005", "2008", "2010", "2012", "2013"];
            let presentes = annees
                .iter()
                .filter(|a| a_programme(e, &format!("Visual C++ {a}")))
                .count();
            element(
                trf!(
                    "Visual C++ 2005 à 2013 ({presentes}/5 présents)",
                    "Visual C++ 2005 to 2013 ({presentes}/5 present)"
                ),
                tr!(
                    "Anciennes versions, pour les jeux d'avant 2015 (erreurs MSVCR100.dll, MSVCP120.dll…).",
                    "Old versions, for games from before 2015 (MSVCR100.dll, MSVCP120.dll… errors)."
                ),
                Some(presentes == annees.len()),
                annees
                    .iter()
                    .flat_map(|a| ["x64", "x86"].map(|arch| winget(&format!("Microsoft.VCRedist.{a}.{arch}"))))
                    .collect(),
            )
        },
        element(
            tr!(
                "DirectX 9 à 11 : anciennes bibliothèques (juin 2010)",
                "DirectX 9 to 11: old libraries (June 2010)"
            ),
            tr!(
                "d3dx9, d3dx10, d3dx11, XAudio2 et XInput anciens : Windows ne les fournit pas, beaucoup de jeux d'avant 2016 en ont besoin.",
                "Old d3dx9, d3dx10, d3dx11, XAudio2 and XInput: Windows does not include them, and many games from before 2016 need them."
            ),
            Some(e.directx9),
            vec![winget("Microsoft.DirectX")],
        ),
        element(
            tr!(".NET Desktop Runtime 8 et 10", ".NET Desktop Runtime 8 and 10"),
            tr!(
                "Lanceurs, mods et outils de jeu écrits en .NET (les versions encore suivies par Microsoft).",
                "Launchers, mods and game tools written in .NET (the versions still supported by Microsoft)."
            ),
            Some(a_programme(e, "Windows Desktop Runtime - 8.") && a_programme(e, "Windows Desktop Runtime - 10.")),
            vec![
                winget("Microsoft.DotNet.DesktopRuntime.8"),
                winget("Microsoft.DotNet.DesktopRuntime.10"),
            ],
        ),
        element(
            ".NET Framework 3.5",
            tr!(
                "Demandé par des jeux et lanceurs anciens ; c'est une fonctionnalité de Windows (téléchargée par Windows Update).",
                "Needed by older games and launchers; it is a Windows feature (downloaded by Windows Update)."
            ),
            Some(e.netfx3),
            vec!["DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart".into()],
        ),
        element(
            "XNA Framework 4.0",
            tr!(
                "Jeux indépendants des années 2010 (Terraria ancien, Stardew Valley ancien, Fez…).",
                "Indie games from the 2010s (old Terraria, old Stardew Valley, Fez…)."
            ),
            Some(a_programme(e, "XNA Framework Redistributable 4.0")),
            vec![winget("Microsoft.XNARedist")],
        ),
        element(
            tr!("PhysX ancien (Legacy)", "Old PhysX (Legacy)"),
            tr!(
                "Physique des jeux NVIDIA PhysX d'avant 2010 (Mirror's Edge, Mafia II…) ; utile même sans carte NVIDIA.",
                "Physics of NVIDIA PhysX games from before 2010 (Mirror's Edge, Mafia II…); useful even without an NVIDIA card."
            ),
            Some(e.programmes.iter().any(|p| p.contains("PhysX") && p.contains("Legacy"))),
            vec![winget("Nvidia.PhysXLegacy")],
        ),
    ];

    // Pilote graphique : celui du fabricant, plus récent que celui de Windows Update.
    for carte in &e.gpu {
        let nom = carte.nom.to_lowercase();
        let pilote = trf!("pilote {} du {}", "driver {} from {}", carte.version, carte.date);
        let mut el = element(
            trf!("Pilote graphique : {}", "Graphics driver: {}", carte.nom),
            trf!(
                "Installé : {pilote}. Le pilote du fabricant est plus récent et mieux optimisé que celui de Windows Update.",
                "Installed: {pilote}. The manufacturer's driver is newer and better optimized than the Windows Update one."
            ),
            None,
            vec![],
        );
        let Some((outil, lien)) = machine::windows::pilote_fabricant(&carte.nom) else {
            continue;
        };
        // Intel : son assistant s'installe par winget ; NVIDIA et AMD, seulement depuis leur page officielle.
        if nom.contains("intel") {
            let _ = trw!(
                el.pourquoi,
                " {outil} trouve le bon pilote.",
                " {outil} finds the right driver."
            );
            el.commandes = vec![winget("Intel.IntelDriverAndSupportAssistant")];
        } else {
            let _ = trw!(
                el.pourquoi,
                " {outil} installe et tient à jour le pilote (page officielle).",
                " {outil} installs the driver and keeps it up to date (official page)."
            );
            el.lien = Some(lien);
        }
        l.push(el);
    }
    l
}

fn reglages(e: &Etat) -> Vec<Element> {
    const PERF: &str = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
    let preferences = r"HKCU:\Software\Microsoft\DirectX\UserGpuPreferences";
    let mut l = vec![
        element(
            tr!("Mode Jeu activé", "Game Mode on"),
            tr!(
                "Windows donne la priorité au jeu et repousse les mises à jour et notifications pendant la partie.",
                "Windows gives priority to the game and holds back updates and notifications while you play."
            ),
            Some(e.mode_jeu != Some(0)),
            vec![dword(r"HKCU:\Software\Microsoft\GameBar", "AutoGameModeEnabled", 1)],
        ),
        element(
            tr!(
                "Planification GPU à accélération matérielle",
                "Hardware-accelerated GPU scheduling"
            ),
            tr!(
                "La carte graphique gère sa propre mémoire : un peu moins de latence, et obligatoire pour la génération d'images DLSS 3/4. Cartes GTX 1000 / RX 5000 et plus récentes. Prend effet au redémarrage.",
                "The graphics card manages its own memory: slightly lower latency, and required for DLSS 3/4 frame generation. GTX 1000 / RX 5000 cards and newer. Takes effect after a restart."
            ),
            Some(e.hags == Some(2)),
            vec![dword(
                r"HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
                "HwSchMode",
                2,
            )],
        ),
        element(
            tr!(
                "Enregistrement Xbox en arrière-plan coupé",
                "Xbox background recording off"
            ),
            tr!(
                "La capture de jeu de la Xbox Game Bar consomme un peu de carte graphique et de disque. La Game Bar (Win+G) reste disponible.",
                "Xbox Game Bar game capture uses a bit of graphics card and disk. The Game Bar (Win+G) stays available."
            ),
            Some(e.dvr == Some(0) && e.capture != Some(1)),
            vec![
                dword(r"HKCU:\System\GameConfigStore", "GameDVR_Enabled", 0),
                dword(
                    r"HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR",
                    "AppCaptureEnabled",
                    0,
                ),
            ],
        ),
        element(
            tr!("Accélération de la souris coupée", "Mouse acceleration off"),
            tr!(
                "« Améliorer la précision du pointeur » change la distance parcourue selon la vitesse du geste : la visée devient imprévisible. Prend effet à la prochaine ouverture de session.",
                "“Enhance pointer precision” changes the distance traveled depending on how fast you move: aiming becomes unpredictable. Takes effect at the next sign-in."
            ),
            (!e.souris.is_empty()).then(|| e.souris == "0"),
            vec![
                r"Set-ItemProperty 'HKCU:\Control Panel\Mouse' -Name MouseSpeed -Value '0'".into(),
                r"Set-ItemProperty 'HKCU:\Control Panel\Mouse' -Name MouseThreshold1 -Value '0'".into(),
                r"Set-ItemProperty 'HKCU:\Control Panel\Mouse' -Name MouseThreshold2 -Value '0'".into(),
            ],
        ),
    ];
    if e.windows11 {
        // La valeur regroupe plusieurs réglages (« VRROptimizeEnable=0;SwapEffectUpgradeEnable=1; ») : on ne
        // remplace que le nôtre.
        l.push(element(
            tr!("Optimisations pour les jeux en fenêtre", "Optimizations for windowed games"),
            tr!("Les jeux DirectX 10/11 en fenêtre ou fenêtre sans bordure passent au mode d'affichage moderne : moins de latence, VRR et HDR automatique possibles.", "DirectX 10/11 games in windowed or borderless mode switch to the modern presentation model: lower latency, VRR and Auto HDR possible."),
            Some(e.fenetres.contains("SwapEffectUpgradeEnable=1")),
            vec![format!(
                "$k = '{preferences}'; if (-not (Test-Path $k)) {{ New-Item $k -Force | Out-Null }}; \
                 $v = [string](Get-ItemProperty $k -ErrorAction SilentlyContinue).DirectXUserGlobalSettings; \
                 Set-ItemProperty $k -Name DirectXUserGlobalSettings -Value (($v -replace 'SwapEffectUpgradeEnable=[0-9];?', '') + 'SwapEffectUpgradeEnable=1;')"
            )],
        ));
    }
    let mut alimentation = element(
        tr!(
            "Mode d'alimentation « Performances élevées »",
            "“High performance” power plan"
        ),
        tr!(
            "Le processeur reste à pleine fréquence : moins de saccades quand le jeu varie beaucoup. Consomme plus au repos.",
            "The processor stays at full speed: fewer stutters when the game load changes a lot. Uses more power at idle."
        ),
        (!e.alimentation.is_empty()).then(|| e.alimentation.contains(PERF)),
        vec![
            "powercfg /setactive SCHEME_MIN".into(),
            "powercfg /getactivescheme".into(),
        ],
    );
    if e.portable {
        alimentation.deconseille = Some(tr!(
            "PC portable : la batterie fondrait et il chaufferait",
            "Laptop: the battery would drain and it would heat up"
        ));
    }
    l.push(alimentation);
    l
}

pub(super) fn menu() {
    trp!("  Lecture de l'état de Windows…", "  Reading the state of Windows…");
    let Some(etat) = lire_etat() else {
        trp!(
            "  ✖ Impossible de lire l'état de Windows (PowerShell ne répond pas).",
            "  ✖ Could not read the state of Windows (PowerShell is not responding)."
        );
        return;
    };
    titre("Gaming");
    trp!(
        "  1. Composants pour les jeux (Visual C++, DirectX, .NET, pilote graphique…)",
        "  1. Components for games (Visual C++, DirectX, .NET, graphics driver…)"
    );
    trp!(
        "  2. Réglages de Windows pour jouer",
        "  2. Windows settings for gaming"
    );
    if !etat.winget {
        trp!(
            "\n  {GRIS}winget manque : le choix 1 ouvre le Microsoft Store (« Programme d'installation d'application »).{RESET}",
            "\n  {GRIS}winget is missing: choice 1 opens the Microsoft Store (“App Installer”).{RESET}"
        );
    }
    match demander(tr!("\nChoix (Entrée pour revenir) : ", "\nChoice (Enter to go back): ")).as_str() {
        "1" if !etat.winget => machine::ouvrir("ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"),
        "1" => proposer(
            tr!("Composants pour les jeux", "Components for games"),
            &composants(&etat),
        ),
        "2" => proposer(
            tr!("Réglages de Windows pour jouer", "Windows settings for gaming"),
            &reglages(&etat),
        ),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn etat_vide() -> Etat {
        Etat {
            programmes: vec![
                "Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219".into(),
                "Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.40664".into(),
                "Microsoft Windows Desktop Runtime - 8.0.11 (x64)".into(),
            ],
            souris: "1".into(),
            portable: true,
            windows11: true,
            ..Etat::default()
        }
    }

    #[test]
    fn composants_et_etat() {
        let e = etat_vide();
        let l = composants(&e);
        assert!(l[1].titre.contains("2/5"));
        // .NET 8 présent mais pas 10 : à faire.
        assert_eq!(l[3].fait, Some(false));
        assert_eq!(l[1].commandes.len(), 10);
        assert!(l[0].commandes[0].contains("--id Microsoft.VCRedist.2015+.x64 --exact"));
        assert!(l.iter().all(|el| !el.commandes.is_empty()));
    }

    #[test]
    fn reglages_et_choix() {
        let e = etat_vide();
        let l = reglages(&e);
        // Mode Jeu absent du registre = activé par défaut.
        assert_eq!(l[0].fait, Some(true));
        assert_eq!(l[3].fait, Some(false));
        let alim = l.last().unwrap();
        assert!(alim.deconseille.is_some());
        // « tout » : ni ce qui est fait, ni le déconseillé.
        let tout = lire_choix("tout", &l);
        assert!(!tout.contains(&0) && !tout.contains(&(l.len() - 1)) && tout.contains(&3));
        assert_eq!(lire_choix("1, 3 3 99 x", &l), vec![0, 2]);
        assert_eq!(lire_choix("", &l), Vec::<usize>::new());
    }

    #[test]
    fn cle_jamais_ecrasee() {
        let c = dword(r"HKCU:\System\GameConfigStore", "GameDVR_Enabled", 0);
        assert!(c.starts_with(r"if (-not (Test-Path 'HKCU:\System\GameConfigStore'))"));
        assert!(c.ends_with("-Name GameDVR_Enabled -Value 0 -Type DWord"));
    }
}
