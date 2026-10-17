//! Gaming sous Windows : composants dont les jeux ont besoin (Visual C++, .NET, DirectX, XNA, PhysX, pilote
//! graphique) et réglages de Windows utiles en jeu.
//! Tout est lu d'abord (un seul appel PowerShell), montré avec son état, puis appliqué seulement après accord.
//! Les réglages qui retirent une protection (intégrité de la mémoire, Defender, pare-feu…) ne sont jamais proposés.

use serde::Deserialize;

use crate::machine;
use crate::ui::*;

/// winget sort ces codes quand le paquet est déjà là (« aucune mise à jour applicable », « déjà installé ») :
/// ce n'est pas un échec.
const DEJA_INSTALLE: &str = "-1978335189, -1978335135";

/// Ce que netscan lit avant d'afficher le menu : une photo de l'état, lue telle quelle depuis PowerShell.
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

/// Installation silencieuse par winget, sans erreur si le paquet est déjà là.
fn winget(id: &str) -> String {
    format!(
        "winget install --id {id} --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity; \
         if ($LASTEXITCODE -in {DEJA_INSTALLE}) {{ $global:LASTEXITCODE = 0 }}"
    )
}

/// Écrit une valeur DWORD en créant la clé si besoin (jamais « New-Item -Force » sur une clé existante :
/// il l'effacerait avec toutes ses valeurs).
fn dword(cle: &str, nom: &str, valeur: u32) -> String {
    format!(
        "if (-not (Test-Path '{cle}')) {{ New-Item '{cle}' -Force | Out-Null }}; \
         Set-ItemProperty '{cle}' -Name {nom} -Value {valeur} -Type DWord"
    )
}

struct Element {
    titre: String,
    pourquoi: String,
    /// `None` : état inconnu ; `Some(true)` : déjà fait.
    fait: Option<bool>,
    commandes: Vec<String>,
    /// Lien à ouvrir au lieu de commandes (pilotes NVIDIA et AMD : pas dans winget).
    lien: Option<&'static str>,
    /// Déconseillé sur cette machine : affiché, mais pas inclus dans « tout ».
    deconseille: Option<&'static str>,
}

fn element(
    titre: impl Into<String>,
    pourquoi: impl Into<String>,
    fait: Option<bool>,
    commandes: Vec<String>,
) -> Element {
    Element {
        titre: titre.into(),
        pourquoi: pourquoi.into(),
        fait,
        commandes,
        lien: None,
        deconseille: None,
    }
}

fn a_programme(e: &Etat, motif: &str) -> bool {
    e.programmes.iter().any(|p| p.contains(motif))
}

fn composants(e: &Etat) -> Vec<Element> {
    let mut l = vec![
        element(
            "Visual C++ 2015-2022 (64 et 32 bits)",
            "Bibliothèques demandées par presque tous les jeux récents (erreur « VCRUNTIME140.dll introuvable »).",
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
                format!("Visual C++ 2005 à 2013 ({presentes}/5 présents)"),
                "Anciennes versions, pour les jeux d'avant 2015 (erreurs MSVCR100.dll, MSVCP120.dll…).",
                Some(presentes == annees.len()),
                annees
                    .iter()
                    .flat_map(|a| ["x64", "x86"].map(|arch| winget(&format!("Microsoft.VCRedist.{a}.{arch}"))))
                    .collect(),
            )
        },
        element(
            "DirectX 9 à 11 : anciennes bibliothèques (juin 2010)",
            "d3dx9, d3dx10, d3dx11, XAudio2 et XInput anciens : Windows ne les fournit pas, beaucoup de jeux d'avant 2016 en ont besoin.",
            Some(e.directx9),
            vec![winget("Microsoft.DirectX")],
        ),
        element(
            ".NET Desktop Runtime 8 et 10",
            "Lanceurs, mods et outils de jeu écrits en .NET (les versions encore suivies par Microsoft).",
            Some(a_programme(e, "Windows Desktop Runtime - 8.") && a_programme(e, "Windows Desktop Runtime - 10.")),
            vec![
                winget("Microsoft.DotNet.DesktopRuntime.8"),
                winget("Microsoft.DotNet.DesktopRuntime.10"),
            ],
        ),
        element(
            ".NET Framework 3.5",
            "Demandé par des jeux et lanceurs anciens ; c'est une fonctionnalité de Windows (téléchargée par Windows Update).",
            Some(e.netfx3),
            vec!["DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart".into()],
        ),
        element(
            "XNA Framework 4.0",
            "Jeux indépendants des années 2010 (Terraria ancien, Stardew Valley ancien, Fez…).",
            Some(a_programme(e, "XNA Framework Redistributable 4.0")),
            vec![winget("Microsoft.XNARedist")],
        ),
        element(
            "PhysX ancien (Legacy)",
            "Physique des jeux NVIDIA PhysX d'avant 2010 (Mirror's Edge, Mafia II…) ; utile même sans carte NVIDIA.",
            Some(e.programmes.iter().any(|p| p.contains("PhysX") && p.contains("Legacy"))),
            vec![winget("Nvidia.PhysXLegacy")],
        ),
    ];

    // Pilote graphique : celui du fabricant, plus récent que celui de Windows Update.
    for carte in &e.gpu {
        let nom = carte.nom.to_lowercase();
        let pilote = format!("pilote {} du {}", carte.version, carte.date);
        let mut el = element(
            format!("Pilote graphique : {}", carte.nom),
            format!(
                "Installé : {pilote}. Le pilote du fabricant est plus récent et mieux optimisé que celui de Windows Update."
            ),
            None,
            vec![],
        );
        if nom.contains("nvidia") {
            el.pourquoi += " NVIDIA App installe et tient à jour le pilote (page officielle).";
            el.lien = Some("https://www.nvidia.com/fr-fr/software/nvidia-app/");
        } else if nom.contains("amd") || nom.contains("radeon") {
            el.pourquoi += " AMD Software Adrenalin installe et tient à jour le pilote (page officielle).";
            el.lien = Some("https://www.amd.com/fr/support/download/drivers.html");
        } else if nom.contains("intel") {
            el.pourquoi += " Intel Driver & Support Assistant trouve le bon pilote.";
            el.commandes = vec![winget("Intel.IntelDriverAndSupportAssistant")];
        } else {
            continue;
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
            "Mode Jeu activé",
            "Windows donne la priorité au jeu et repousse les mises à jour et notifications pendant la partie.",
            Some(e.mode_jeu != Some(0)),
            vec![dword(r"HKCU:\Software\Microsoft\GameBar", "AutoGameModeEnabled", 1)],
        ),
        element(
            "Planification GPU à accélération matérielle",
            "La carte graphique gère sa propre mémoire : un peu moins de latence, et obligatoire pour la génération d'images DLSS 3/4. Cartes GTX 1000 / RX 5000 et plus récentes. Prend effet au redémarrage.",
            Some(e.hags == Some(2)),
            vec![dword(
                r"HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
                "HwSchMode",
                2,
            )],
        ),
        element(
            "Enregistrement Xbox en arrière-plan coupé",
            "La capture de jeu de la Xbox Game Bar consomme un peu de carte graphique et de disque. La Game Bar (Win+G) reste disponible.",
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
            "Accélération de la souris coupée",
            "« Améliorer la précision du pointeur » change la distance parcourue selon la vitesse du geste : la visée devient imprévisible. Prend effet à la prochaine ouverture de session.",
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
            "Optimisations pour les jeux en fenêtre",
            "Les jeux DirectX 10/11 en fenêtre ou fenêtre sans bordure passent au mode d'affichage moderne : moins de latence, VRR et HDR automatique possibles.",
            Some(e.fenetres.contains("SwapEffectUpgradeEnable=1")),
            vec![format!(
                "$k = '{preferences}'; if (-not (Test-Path $k)) {{ New-Item $k -Force | Out-Null }}; \
                 $v = [string](Get-ItemProperty $k -ErrorAction SilentlyContinue).DirectXUserGlobalSettings; \
                 Set-ItemProperty $k -Name DirectXUserGlobalSettings -Value (($v -replace 'SwapEffectUpgradeEnable=[0-9];?', '') + 'SwapEffectUpgradeEnable=1;')"
            )],
        ));
    }
    let mut alimentation = element(
        "Mode d'alimentation « Performances élevées »",
        "Le processeur reste à pleine fréquence : moins de saccades quand le jeu varie beaucoup. Consomme plus au repos.",
        (!e.alimentation.is_empty()).then(|| e.alimentation.contains(PERF)),
        vec![
            "powercfg /setactive SCHEME_MIN".into(),
            "powercfg /getactivescheme".into(),
        ],
    );
    if e.portable {
        alimentation.deconseille = Some("PC portable : la batterie fondrait et il chaufferait");
    }
    l.push(alimentation);
    l
}

fn etat_lisible(el: &Element) -> String {
    if let Some(d) = el.deconseille {
        return format!("{GRIS}déconseillé ici ({d}){RESET}");
    }
    match (el.fait, el.lien.is_some()) {
        (_, true) => format!("{GRIS}page du fabricant{RESET}"),
        (Some(true), _) => format!("{VERT}✔ fait{RESET}"),
        (Some(false), _) => "à faire".into(),
        (None, _) => format!("{GRIS}?{RESET}"),
    }
}

/// Choix « 1 3 4 », « 1,3 » ou « tout » (ce qui reste à faire, sans les déconseillés ni les liens).
fn lire_choix(texte: &str, liste: &[Element]) -> Vec<usize> {
    if texte.eq_ignore_ascii_case("tout") || texte.eq_ignore_ascii_case("t") {
        return liste
            .iter()
            .enumerate()
            .filter(|(_, el)| el.fait != Some(true) && el.deconseille.is_none() && el.lien.is_none())
            .map(|(i, _)| i)
            .collect();
    }
    let mut choix: Vec<usize> = texte
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(|n| n.parse::<usize>().ok()?.checked_sub(1))
        .filter(|&i| i < liste.len())
        .collect();
    choix.sort_unstable();
    choix.dedup();
    choix
}

fn proposer(nom: &str, liste: &[Element]) {
    titre(nom);
    for (i, el) in liste.iter().enumerate() {
        println!("  {}. {}  — {}", i + 1, el.titre, etat_lisible(el));
    }
    let texte = demander("\nNuméros (ex. « 1 3 »), « tout » pour ce qui reste à faire, Entrée pour revenir : ");
    let choix = lire_choix(&texte, liste);
    if choix.is_empty() {
        return;
    }
    let mut commandes = Vec::new();
    for &i in &choix {
        let el = &liste[i];
        println!("\n  {GRAS}{}{RESET}", el.titre);
        println!("  {}", el.pourquoi);
        if let Some(lien) = el.lien {
            println!("  Ouverture de la page officielle : {lien}");
            machine::ouvrir(lien);
        }
        for c in &el.commandes {
            println!("    {GRIS}{c}{RESET}");
        }
        commandes.extend(el.commandes.iter().cloned());
    }
    if commandes.is_empty() {
        return;
    }
    if !demander("\n  Lancer ? [o/N] : ").eq_ignore_ascii_case("o") {
        println!("  Annulé.");
        return;
    }
    if machine::appliquer(&commandes) {
        println!("  {VERT}✔ Terminé.{RESET} Certains changements demandent de redémarrer ou de rouvrir la session.");
    } else {
        println!("  ✖ Une étape a échoué : lis le message ci-dessus.");
    }
}

pub fn menu() {
    println!("  Lecture de l'état de Windows…");
    let Some(etat) = lire_etat() else {
        println!("  ✖ Impossible de lire l'état de Windows (PowerShell ne répond pas).");
        return;
    };
    titre("Gaming");
    println!("  1. Composants pour les jeux (Visual C++, DirectX, .NET, pilote graphique…)");
    println!("  2. Réglages de Windows pour jouer");
    if !etat.winget {
        println!(
            "\n  {GRIS}winget manque : le choix 1 ouvre le Microsoft Store (« Programme d'installation d'application »).{RESET}"
        );
    }
    match demander("\nChoix (Entrée pour revenir) : ").as_str() {
        "1" if !etat.winget => machine::ouvrir("ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"),
        "1" => proposer("Composants pour les jeux", &composants(&etat)),
        "2" => proposer("Réglages de Windows pour jouer", &reglages(&etat)),
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
