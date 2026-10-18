//! Réglages de Windows. Le registre se lit directement, sans PowerShell (une fraction de seconde pour tout le
//! catalogue). Ce qui est propre au compte (HKCU) s'écrit aussi directement, dans le compte de la personne, même si
//! la fenêtre administrateur s'ouvre sous un autre compte ; le reste (HKLM, stratégies, services) passe par une seule
//! fenêtre administrateur, après un point de restauration.

use std::process::Command;

use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE};

use super::{Categorie, Reglage, Valeur};
use crate::ui::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Racine {
    /// HKCU : le compte de la personne ; Sentinel y écrit lui-même.
    Hkcu,
    /// HKCU\Software\Policies : en lecture seule pour l'utilisateur, écrit par la fenêtre administrateur.
    HkcuStrategie,
    /// HKLM : toute la machine, par la fenêtre administrateur.
    Hklm,
}

#[derive(Clone, Copy)]
pub enum Val {
    Dword(u32),
    Texte(&'static str),
}

impl Val {
    fn coder(self) -> String {
        match self {
            Val::Dword(d) => format!("dword:{d}"),
            Val::Texte(t) => format!("sz:{t}"),
        }
    }
}

pub enum Changement {
    /// Valeur du registre. `defaut` : celle d'un Windows neuf (`None` : absente).
    Registre {
        racine: Racine,
        chemin: &'static str,
        nom: &'static str,
        cible: Val,
        defaut: Option<Val>,
    },
    /// Clé du compte créée avec une valeur par défaut vide (présente = fait) ; `retirer`, la clé enlevée pour annuler.
    Cle {
        chemin: &'static str,
        retirer: &'static str,
    },
    /// Type de démarrage d'un service : 2 automatique, 3 manuel, 4 désactivé.
    Service { nom: &'static str, cible: u32, defaut: u32 },
}

fn lire_valeur(racine: Racine, chemin: &str, nom: &str) -> Valeur {
    let predef = if racine == Racine::Hklm {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    };
    let cle = RegKey::predef(predef).open_subkey_with_flags(chemin, KEY_READ).ok()?;
    if let Ok(d) = cle.get_value::<u32, _>(nom) {
        return Some(format!("dword:{d}"));
    }
    cle.get_value::<String, _>(nom).ok().map(|t| format!("sz:{t}"))
}

/// Valeur codée (« dword:0 », « sz:texte ») : le nombre ou le texte.
enum Lue {
    Dword(u32),
    Texte(String),
}

fn decoder(v: &str) -> Option<Lue> {
    if let Some(d) = v.strip_prefix("dword:") {
        return d.parse().ok().map(Lue::Dword);
    }
    v.strip_prefix("sz:").map(|t| Lue::Texte(t.to_string()))
}

fn demarrage(n: u32) -> Option<&'static str> {
    match n {
        2 => Some("Automatic"),
        3 => Some("Manual"),
        4 => Some("Disabled"),
        _ => None,
    }
}

fn chemin_lisible(racine: Racine, chemin: &str) -> String {
    format!("{}\\{chemin}", if racine == Racine::Hklm { "HKLM" } else { "HKCU" })
}

impl Changement {
    pub fn lire(&self) -> Valeur {
        match self {
            Changement::Registre {
                racine, chemin, nom, ..
            } => lire_valeur(*racine, chemin, nom),
            Changement::Cle { chemin, .. } => RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(chemin, KEY_READ)
                .ok()
                .map(|_| "cle".to_string()),
            Changement::Service { nom, .. } => lire_valeur(
                Racine::Hklm,
                &format!(r"SYSTEM\CurrentControlSet\Services\{nom}"),
                "Start",
            )
            .map(|v| v.replace("dword:", "start:")),
        }
    }

    // Même forme que `lire`, pour les comparer.
    #[allow(clippy::unnecessary_wraps)]
    pub fn cible(&self) -> Valeur {
        Some(match self {
            Changement::Registre { cible, .. } => cible.coder(),
            Changement::Cle { .. } => "cle".to_string(),
            Changement::Service { cible, .. } => format!("start:{cible}"),
        })
    }

    pub fn defaut(&self) -> Valeur {
        match self {
            Changement::Registre { defaut, .. } => defaut.map(Val::coder),
            Changement::Cle { .. } => None,
            Changement::Service { defaut, .. } => Some(format!("start:{defaut}")),
        }
    }

    /// Ce qui est écrit, en clair : « HKCU\…\HideFileExt = 0 », « … : retirée », « service DiagTrack : Disabled ».
    pub fn decrire(&self, v: Option<&str>) -> String {
        match self {
            Changement::Registre {
                racine, chemin, nom, ..
            } => {
                let ou = format!("{}\\{nom}", chemin_lisible(*racine, chemin));
                match v.and_then(decoder) {
                    Some(Lue::Dword(d)) => format!("{ou} = {d}"),
                    Some(Lue::Texte(t)) => format!("{ou} = « {t} »"),
                    None => trf!("{ou} : retirée", "{ou}: removed"),
                }
            }
            Changement::Cle { chemin, retirer } => match v {
                Some(_) => trf!("HKCU\\{chemin} : créée", "HKCU\\{chemin}: created"),
                None => trf!("HKCU\\{retirer} : retirée", "HKCU\\{retirer}: removed"),
            },
            Changement::Service { nom, .. } => {
                let mode = v
                    .and_then(|t| t.strip_prefix("start:"))
                    .and_then(|n| n.parse().ok())
                    .and_then(demarrage)
                    .unwrap_or("?");
                trf!("service {nom} : {mode}", "service {nom}: {mode}")
            }
        }
    }

    /// Demande la fenêtre administrateur (tout sauf le compte de la personne).
    fn admin(&self) -> bool {
        !matches!(
            self,
            Changement::Registre {
                racine: Racine::Hkcu,
                ..
            } | Changement::Cle { .. }
        )
    }

    /// Écrit dans le compte de la personne, sans fenêtre administrateur.
    fn ecrire_ici(&self, v: Option<&str>) -> bool {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        match self {
            Changement::Registre { chemin, nom, .. } => match v.and_then(decoder) {
                // Déjà absente : rien à faire, c'est réussi.
                None => hkcu
                    .open_subkey_with_flags(chemin, KEY_SET_VALUE | KEY_QUERY_VALUE)
                    .map_or(true, |k| k.delete_value(nom).is_ok() || k.get_raw_value(nom).is_err()),
                Some(lue) => {
                    let Ok((k, _)) = hkcu.create_subkey(chemin) else {
                        return false;
                    };
                    match lue {
                        Lue::Dword(d) => k.set_value(nom, &d).is_ok(),
                        Lue::Texte(t) => k.set_value(nom, &t).is_ok(),
                    }
                }
            },
            Changement::Cle { chemin, retirer } => match v {
                Some(_) => hkcu
                    .create_subkey(chemin)
                    .is_ok_and(|(k, _)| k.set_value("", &String::new()).is_ok()),
                None => hkcu.delete_subkey_all(retirer).is_ok() || hkcu.open_subkey(retirer).is_err(),
            },
            Changement::Service { .. } => false,
        }
    }

    /// La commande PowerShell pour la fenêtre administrateur.
    fn commande_admin(&self, v: Option<&str>) -> Option<String> {
        match self {
            Changement::Registre {
                racine, chemin, nom, ..
            } => {
                let p =
                    format!("{}:\\{chemin}", if *racine == Racine::Hklm { "HKLM" } else { "HKCU" }).replace('\'', "''");
                // Clé créée seulement si elle manque : New-Item -Force sur une clé existante l'écraserait, valeurs
                // comprises.
                let creer =
                    format!("if (-not (Test-Path -LiteralPath '{p}')) {{ New-Item -Path '{p}' -Force | Out-Null }}");
                Some(match v.and_then(decoder) {
                    None => {
                        format!("Remove-ItemProperty -LiteralPath '{p}' -Name '{nom}' -ErrorAction SilentlyContinue")
                    }
                    Some(Lue::Dword(d)) => {
                        format!("{creer}; Set-ItemProperty -LiteralPath '{p}' -Name '{nom}' -Value {d} -Type DWord")
                    }
                    Some(Lue::Texte(t)) => format!(
                        "{creer}; Set-ItemProperty -LiteralPath '{p}' -Name '{nom}' -Value '{}' -Type String",
                        t.replace('\'', "''")
                    ),
                })
            }
            Changement::Service { nom, .. } => {
                let n: u32 = v?.strip_prefix("start:")?.parse().ok()?;
                // Désactivé : arrêté tout de suite ; remis en automatique : relancé, comme avant le changement.
                let suite = match n {
                    4 => format!("; Stop-Service -Name '{nom}' -Force -ErrorAction SilentlyContinue"),
                    2 => format!("; Start-Service -Name '{nom}' -ErrorAction SilentlyContinue"),
                    _ => String::new(),
                };
                Some(format!(
                    "Set-Service -Name '{nom}' -StartupType {}{suite}",
                    demarrage(n)?
                ))
            }
            Changement::Cle { .. } => None,
        }
    }
}

/// Applique des lots de changements (un lot par réglage) et dit lesquels ont réussi. La fenêtre administrateur passe
/// d'abord, point de restauration en tête : refusée, rien n'est changé, pas même dans le compte de la personne.
pub fn ecrire(lots: &[Vec<(&Changement, Valeur)>]) -> Vec<bool> {
    let admin: Vec<(usize, Vec<String>)> = lots
        .iter()
        .enumerate()
        .filter_map(|(i, lot)| {
            let commandes: Vec<String> = lot
                .iter()
                .filter(|(c, _)| c.admin())
                .filter_map(|(c, v)| c.commande_admin(v.as_deref()))
                .collect();
            (!commandes.is_empty()).then_some((i, commandes))
        })
        .collect();
    let mut resultats = vec![true; lots.len()];
    if !admin.is_empty() {
        let point = crate::reparer::point_restauration(tr!("réglages", "settings")).map(|(_, p)| p);
        let mut groupes: Vec<Vec<String>> = point.iter().map(|p| vec![p.clone()]).collect();
        groupes.extend(admin.iter().map(|(_, c)| c.clone()));
        let mut r = crate::machine::appliquer_chacune(&groupes);
        if point.is_some() && !r.remove(0) {
            // Point de restauration refusé, ou fenêtre administrateur refusée : on ne touche à rien d'autre.
            return vec![false; lots.len()];
        }
        for ((i, _), ok) in admin.iter().zip(r) {
            resultats[*i] = ok;
        }
    }
    for (i, lot) in lots.iter().enumerate() {
        if !resultats[i] {
            continue;
        }
        for (c, v) in lot.iter().filter(|(c, _)| !c.admin()) {
            println!("    {GRIS}{}{RESET}", c.decrire(v.as_deref()));
            resultats[i] &= c.ecrire_ici(v.as_deref());
        }
    }
    resultats
}

/// Après coup : l'Explorateur relit ses réglages à son prochain démarrage ; on propose de le relancer.
pub fn apres(touches: &[&Reglage]) {
    const EXPLORATEUR: [&str; 6] = [
        "extensions",
        "fichiers_caches",
        "ce_pc",
        "barre_gauche",
        "menu_classique",
        "fin_de_tache",
    ];
    if !touches.iter().any(|r| EXPLORATEUR.contains(&r.id)) {
        return;
    }
    if !demander(tr!(
        "\n  Relancer l'Explorateur pour voir les changements tout de suite ? (les fenêtres de dossiers se ferment) [o/N] : ",
        "\n  Restart File Explorer to see the changes right away? (folder windows will close) [y/N]: "
    ))
    .oui()
    {
        trp!(
            "  {GRIS}Les changements de l'Explorateur apparaîtront à ta prochaine session.{RESET}",
            "  {GRIS}File Explorer changes will show at your next sign-in.{RESET}"
        );
        return;
    }
    let _ = Command::new("taskkill").args(["/f", "/im", "explorer.exe"]).output();
    // Windows relance le bureau tout seul ; sinon on le relance.
    std::thread::sleep(std::time::Duration::from_secs(3));
    let tourne = Command::new("tasklist")
        .args(["/fi", "imagename eq explorer.exe", "/nh"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("explorer.exe"));
    if !tourne {
        let _ = Command::new("explorer.exe").spawn();
    }
}

/// Numéro de version de Windows (22000 et plus : Windows 11).
fn build() -> u32 {
    lire_valeur(
        Racine::Hklm,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuildNumber",
    )
    .and_then(|v| v.strip_prefix("sz:")?.parse().ok())
    .unwrap_or(0)
}

fn reg(racine: Racine, chemin: &'static str, nom: &'static str, cible: Val, defaut: Option<Val>) -> Changement {
    Changement::Registre {
        racine,
        chemin,
        nom,
        cible,
        defaut,
    }
}

const ANALYSE: &str = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection";
const EXPLORATEUR_AVANCE: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
const CONTENU: &str = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";

/// Les réglages qui conviennent à cette version de Windows.
pub fn catalogue() -> Vec<Reglage> {
    use Categorie::{Confidentialite, Confort, Performance};
    use Racine::{Hkcu, HkcuStrategie, Hklm};
    use Val::{Dword, Texte};
    let b = build();
    let windows_11 = b >= 22_000;
    let r = |id, categorie, titre, effet, prudence, recommande, changements| Reglage {
        id,
        categorie,
        titre,
        effet,
        prudence,
        recommande,
        changements,
    };
    let mut l = vec![
        // ── Confidentialité
        r(
            "telemetrie",
            Confidentialite,
            tr!("Télémétrie au minimum", "Telemetry kept to a minimum"),
            tr!(
                "Windows n'envoie plus à Microsoft que les données de diagnostic obligatoires, et son service de collecte est arrêté. Les éditions Famille et Pro gardent ce minimum « requis ».",
                "Windows sends Microsoft only the required diagnostic data, and its collection service is stopped. Home and Pro editions keep that “required” minimum."
            ),
            None,
            true,
            vec![
                reg(Hklm, ANALYSE, "AllowTelemetry", Dword(0), None),
                Changement::Service {
                    nom: "DiagTrack",
                    cible: 4,
                    defaut: 2,
                },
            ],
        ),
        r(
            "publicite",
            Confidentialite,
            tr!("Identifiant de publicité coupé", "Advertising ID turned off"),
            tr!(
                "Les applications ne peuvent plus te suivre de l'une à l'autre pour te montrer de la publicité ciblée.",
                "Apps can no longer follow you from one to another to show you targeted ads."
            ),
            None,
            true,
            vec![reg(
                Hkcu,
                r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                "Enabled",
                Dword(0),
                Some(Dword(1)),
            )],
        ),
        r(
            "suggestions",
            Confidentialite,
            tr!("Pas de publicités dans Windows", "No ads inside Windows"),
            tr!(
                "Fini les applications installées sans ton accord (jeux mis en avant) et les suggestions dans le menu Démarrer, les Paramètres et l'écran de verrouillage.",
                "No more apps installed without your consent (promoted games), and no suggestions in Start, Settings and on the lock screen."
            ),
            None,
            true,
            [
                "SilentInstalledAppsEnabled",
                "SystemPaneSuggestionsEnabled",
                "SoftLandingEnabled",
                "SubscribedContent-338388Enabled",
                "SubscribedContent-338389Enabled",
                "SubscribedContent-353694Enabled",
                "SubscribedContent-353696Enabled",
            ]
            .into_iter()
            .map(|nom| reg(Hkcu, CONTENU, nom, Dword(0), Some(Dword(1))))
            .collect(),
        ),
        r(
            "activites",
            Confidentialite,
            tr!("Historique des activités coupé", "Activity history turned off"),
            tr!(
                "Windows ne garde plus la liste de ce que tu ouvres (documents, sites, applications) et ne l'envoie plus à ton compte Microsoft.",
                "Windows no longer keeps the list of what you open (documents, sites, apps) nor sends it to your Microsoft account."
            ),
            None,
            true,
            ["EnableActivityFeed", "PublishUserActivities", "UploadUserActivities"]
                .into_iter()
                .map(|nom| reg(Hklm, r"SOFTWARE\Policies\Microsoft\Windows\System", nom, Dword(0), None))
                .collect(),
        ),
        r(
            "recherche_web",
            Confidentialite,
            tr!("Recherche du menu Démarrer sans Bing", "Start menu search without Bing"),
            tr!(
                "La recherche du menu Démarrer cherche dans l'ordinateur, plus sur Internet : elle répond plus vite, et ce que tu tapes ne part plus chez Microsoft.",
                "Start menu search looks in the computer, no longer on the Internet: it answers faster, and what you type no longer goes to Microsoft."
            ),
            None,
            true,
            vec![
                reg(
                    Hkcu,
                    r"Software\Microsoft\Windows\CurrentVersion\Search",
                    "BingSearchEnabled",
                    Dword(0),
                    None,
                ),
                reg(
                    HkcuStrategie,
                    r"Software\Policies\Microsoft\Windows\Explorer",
                    "DisableSearchBoxSuggestions",
                    Dword(1),
                    None,
                ),
            ],
        ),
        r(
            "avis",
            Confidentialite,
            tr!("Plus de demandes d'avis", "No more feedback requests"),
            tr!(
                "Windows ne te demande plus ton avis par des notifications.",
                "Windows no longer asks for your feedback through notifications."
            ),
            None,
            true,
            vec![
                reg(
                    Hkcu,
                    r"Software\Microsoft\Siuf\Rules",
                    "NumberOfSIUFInPeriod",
                    Dword(0),
                    None,
                ),
                reg(Hklm, ANALYSE, "DoNotShowFeedbackNotifications", Dword(1), None),
            ],
        ),
        r(
            "saisie",
            Confidentialite,
            tr!("Ce que tu tapes reste chez toi", "What you type stays with you"),
            tr!(
                "Windows n'envoie plus d'exemples de ta frappe et de ton écriture manuscrite pour « améliorer » la reconnaissance, et ne relève plus tes contacts pour cela.",
                "Windows no longer sends samples of your typing and handwriting to “improve” recognition, nor collects your contacts for it."
            ),
            None,
            true,
            vec![
                reg(
                    Hkcu,
                    r"Software\Microsoft\Input\TIPC",
                    "Enabled",
                    Dword(0),
                    Some(Dword(1)),
                ),
                reg(
                    Hkcu,
                    r"Software\Microsoft\InputPersonalization",
                    "RestrictImplicitInkCollection",
                    Dword(1),
                    Some(Dword(0)),
                ),
                reg(
                    Hkcu,
                    r"Software\Microsoft\InputPersonalization",
                    "RestrictImplicitTextCollection",
                    Dword(1),
                    Some(Dword(0)),
                ),
                reg(
                    Hkcu,
                    r"Software\Microsoft\InputPersonalization\TrainedDataStore",
                    "HarvestContacts",
                    Dword(0),
                    Some(Dword(1)),
                ),
            ],
        ),
        r(
            "experiences",
            Confidentialite,
            tr!("Pas de conseils tirés des diagnostics", "No tips based on diagnostics"),
            tr!(
                "Microsoft n'utilise plus tes données de diagnostic pour te montrer des conseils, des publicités et des recommandations personnalisés.",
                "Microsoft no longer uses your diagnostic data to show you personalized tips, ads and recommendations."
            ),
            None,
            true,
            vec![reg(
                Hkcu,
                r"Software\Microsoft\Windows\CurrentVersion\Privacy",
                "TailoredExperiencesWithDiagnosticDataEnabled",
                Dword(0),
                Some(Dword(1)),
            )],
        ),
        r(
            "localisation",
            Confidentialite,
            tr!("Localisation coupée", "Location turned off"),
            tr!(
                "Ni Windows ni les applications ne savent plus où se trouve l'ordinateur.",
                "Neither Windows nor apps know where the computer is any more."
            ),
            Some(tr!(
                "La météo, les cartes et « Localiser mon appareil » ne marcheront plus.",
                "Weather, maps and “Find my device” will no longer work."
            )),
            false,
            vec![reg(
                Hklm,
                r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors",
                "DisableLocation",
                Dword(1),
                None,
            )],
        ),
        // ── Performance et fiabilité
        r(
            "demarrage_rapide",
            Performance,
            tr!("Démarrage rapide coupé", "Fast startup turned off"),
            tr!(
                "« Arrêter » éteint vraiment Windows : les mises à jour se terminent, les pilotes repartent à neuf, et un autre système (double démarrage) peut lire le disque sans risque.",
                "“Shut down” really turns Windows off: updates finish, drivers start fresh, and another system (dual boot) can read the disk safely."
            ),
            Some(tr!(
                "Le démarrage prend quelques secondes de plus.",
                "Startup takes a few seconds longer."
            )),
            false,
            vec![reg(
                Hklm,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
                "HiberbootEnabled",
                Dword(0),
                Some(Dword(1)),
            )],
        ),
        r(
            "chemins_longs",
            Performance,
            tr!("Chemins de fichiers longs autorisés", "Long file paths allowed"),
            tr!(
                "Les programmes récents peuvent dépasser la vieille limite de 260 caractères par chemin : utile pour les projets de développement et les dossiers très imbriqués.",
                "Recent programs can go past the old 260-character path limit: handy for development projects and deeply nested folders."
            ),
            None,
            false,
            vec![reg(
                Hklm,
                r"SYSTEM\CurrentControlSet\Control\FileSystem",
                "LongPathsEnabled",
                Dword(1),
                Some(Dword(0)),
            )],
        ),
        // ── Confort et fichiers
        r(
            "extensions",
            Confort,
            tr!("Extensions des fichiers visibles", "File extensions shown"),
            tr!(
                "L'Explorateur affiche « facture.pdf.exe » au lieu de « facture.pdf » : un programme ne peut plus se faire passer pour un document.",
                "File Explorer shows “invoice.pdf.exe” instead of “invoice.pdf”: a program can no longer pass for a document."
            ),
            None,
            true,
            vec![reg(Hkcu, EXPLORATEUR_AVANCE, "HideFileExt", Dword(0), Some(Dword(1)))],
        ),
        r(
            "exec_auto",
            Confort,
            tr!("Pas de lancement automatique des clés", "No autorun from USB drives"),
            tr!(
                "Brancher une clé USB, un disque ou un CD ne lance plus rien tout seul : les vers de clé USB ne peuvent plus démarrer ainsi.",
                "Plugging in a USB drive, disk or CD no longer starts anything by itself: USB worms can no longer start this way."
            ),
            None,
            true,
            vec![
                reg(
                    Hklm,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                    "NoDriveTypeAutoRun",
                    Dword(255),
                    None,
                ),
                reg(
                    Hkcu,
                    r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
                    "DisableAutoplay",
                    Dword(1),
                    Some(Dword(0)),
                ),
            ],
        ),
        r(
            "fichiers_caches",
            Confort,
            tr!("Fichiers cachés visibles", "Hidden files shown"),
            tr!(
                "L'Explorateur montre aussi les fichiers et dossiers cachés, comme ceux qu'un virus de clé USB dissimule.",
                "File Explorer also shows hidden files and folders, like the ones a USB virus hides."
            ),
            None,
            false,
            vec![reg(Hkcu, EXPLORATEUR_AVANCE, "Hidden", Dword(1), Some(Dword(2)))],
        ),
        r(
            "ce_pc",
            Confort,
            tr!(
                "L'Explorateur s'ouvre sur « Ce PC »",
                "File Explorer opens on “This PC”"
            ),
            tr!(
                "Il montre tout de suite les disques et les clés, au lieu de l'accueil et des fichiers récents.",
                "It shows the disks and drives right away, instead of the home page and recent files."
            ),
            None,
            false,
            vec![reg(Hkcu, EXPLORATEUR_AVANCE, "LaunchTo", Dword(1), None)],
        ),
        r(
            "verr_num",
            Confort,
            tr!("Verr. num. allumé à l'ouverture", "Num Lock on at sign-in"),
            tr!(
                "Le pavé numérique est prêt dès l'ouverture de ta session.",
                "The number pad is ready as soon as you sign in."
            ),
            None,
            false,
            vec![reg(
                Hkcu,
                r"Control Panel\Keyboard",
                "InitialKeyboardIndicators",
                Texte("2"),
                Some(Texte("0")),
            )],
        ),
        r(
            "touches_remanentes",
            Confort,
            tr!(
                "Raccourci des touches rémanentes coupé",
                "Sticky Keys shortcut turned off"
            ),
            tr!(
                "Appuyer cinq fois sur Maj (en jeu, par exemple) n'ouvre plus la fenêtre des touches rémanentes. Elles restent dans les paramètres d'accessibilité.",
                "Pressing Shift five times (in a game, for example) no longer opens the Sticky Keys window. They stay available in the accessibility settings."
            ),
            None,
            false,
            vec![reg(
                Hkcu,
                r"Control Panel\Accessibility\StickyKeys",
                "Flags",
                Texte("506"),
                Some(Texte("510")),
            )],
        ),
        r(
            "theme_sombre",
            Confort,
            tr!("Thème sombre", "Dark theme"),
            tr!(
                "Windows et les applications passent en couleurs sombres, plus reposantes le soir.",
                "Windows and apps switch to dark colors, easier on the eyes at night."
            ),
            None,
            false,
            ["AppsUseLightTheme", "SystemUsesLightTheme"]
                .into_iter()
                .map(|nom| {
                    reg(
                        Hkcu,
                        r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                        nom,
                        Dword(0),
                        Some(Dword(1)),
                    )
                })
                .collect(),
        ),
    ];
    if windows_11 {
        l.push(r(
            "recall",
            Confidentialite,
            tr!("Recall : pas de captures de l'écran", "Recall: no screen snapshots"),
            tr!(
                "Sur les PC Copilot+, Recall photographie l'écran toutes les quelques secondes, mots de passe et messages compris. Ce réglage l'en empêche ; ailleurs, il ne change rien.",
                "On Copilot+ PCs, Recall takes a picture of the screen every few seconds, passwords and messages included. This setting prevents it; elsewhere it changes nothing."
            ),
            None,
            true,
            vec![reg(
                Hklm,
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
                "DisableAIDataAnalysis",
                Dword(1),
                None,
            )],
        ));
        l.push(r(
            "widgets",
            Performance,
            tr!("Widgets retirés", "Widgets removed"),
            tr!(
                "Le panneau Widgets (actualités, météo) disparaît de la barre des tâches et ne tourne plus en arrière-plan.",
                "The Widgets panel (news, weather) leaves the taskbar and no longer runs in the background."
            ),
            None,
            false,
            vec![reg(
                Hklm,
                r"SOFTWARE\Policies\Microsoft\Dsh",
                "AllowNewsAndInterests",
                Dword(0),
                None,
            )],
        ));
        l.push(r(
            "menu_classique",
            Confort,
            tr!("Menu complet au clic droit", "Full right-click menu"),
            tr!(
                "Le clic droit montre tout de suite toutes les options, comme sous Windows 10, sans passer par « Afficher plus d'options ».",
                "Right-click shows every option right away, as on Windows 10, without going through “Show more options”."
            ),
            None,
            false,
            vec![Changement::Cle {
                chemin: r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32",
                retirer: r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}",
            }],
        ));
        l.push(r(
            "barre_gauche",
            Confort,
            tr!("Barre des tâches alignée à gauche", "Taskbar aligned left"),
            tr!(
                "Le bouton Démarrer et les icônes reviennent à gauche, comme sous Windows 10.",
                "The Start button and the icons go back to the left, as on Windows 10."
            ),
            None,
            false,
            vec![reg(Hkcu, EXPLORATEUR_AVANCE, "TaskbarAl", Dword(0), None)],
        ));
    } else {
        l.push(r(
            "arriere_plan",
            Performance,
            tr!("Applications en arrière-plan coupées", "Background apps turned off"),
            tr!(
                "Les applications du Store ne tournent plus une fois fermées : moins de mémoire et de batterie utilisées.",
                "Store apps no longer run once closed: less memory and battery used."
            ),
            Some(tr!(
                "Courrier, Calendrier et les autres applications du Store n'enverront plus de notifications une fois fermées.",
                "Mail, Calendar and other Store apps will no longer send notifications once closed."
            )),
            false,
            vec![reg(
                Hkcu,
                r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
                "GlobalUserDisabled",
                Dword(1),
                Some(Dword(0)),
            )],
        ));
    }
    // « Fin de tâche » : à partir de Windows 11 23H2.
    if b >= 22_631 {
        l.push(r(
            "fin_de_tache",
            Confort,
            tr!("« Fin de tâche » dans la barre des tâches", "“End task” in the taskbar"),
            tr!(
                "Un clic droit sur une application de la barre des tâches peut la fermer de force quand elle ne répond plus (un jeu figé, par exemple).",
                "Right-clicking an app on the taskbar can force it closed when it stops responding (a frozen game, for example)."
            ),
            None,
            false,
            vec![reg(
                Hkcu,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings",
                "TaskbarEndTask",
                Dword(1),
                None,
            )],
        ));
    }
    // Un service absent (édition allégée de Windows) n'est pas proposé.
    for reglage in &mut l {
        reglage
            .changements
            .retain(|c| !matches!(c, Changement::Service { .. }) || c.lire().is_some());
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecrire_puis_remettre_dans_le_compte() {
        // Une clé jetable du compte : écrite, relue, puis remise à son état d'avant (absente).
        let c = reg(
            Racine::Hkcu,
            r"Software\SentinelTest\Optimiser",
            "Essai",
            Val::Dword(7),
            None,
        );
        assert_eq!(c.lire(), None);
        assert!(c.ecrire_ici(c.cible().as_deref()));
        assert_eq!(c.lire().as_deref(), Some("dword:7"));
        assert!(c.ecrire_ici(None));
        assert_eq!(c.lire(), None);
        let texte = reg(
            Racine::Hkcu,
            r"Software\SentinelTest\Optimiser",
            "Texte",
            Val::Texte("506"),
            None,
        );
        assert!(texte.ecrire_ici(texte.cible().as_deref()));
        assert_eq!(texte.lire().as_deref(), Some("sz:506"));
        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(r"Software\SentinelTest");
    }

    #[test]
    fn commandes_de_la_fenetre_administrateur() {
        let c = reg(Racine::Hklm, ANALYSE, "AllowTelemetry", Val::Dword(0), None);
        let ecrire = c.commande_admin(Some("dword:0")).unwrap();
        assert!(
            ecrire.contains("Test-Path -LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection'")
        );
        assert!(ecrire.ends_with("-Name 'AllowTelemetry' -Value 0 -Type DWord"));
        assert!(c.commande_admin(None).unwrap().starts_with("Remove-ItemProperty"));
        let s = Changement::Service {
            nom: "DiagTrack",
            cible: 4,
            defaut: 2,
        };
        assert_eq!(
            s.commande_admin(Some("start:4")).as_deref(),
            Some(
                "Set-Service -Name 'DiagTrack' -StartupType Disabled; Stop-Service -Name 'DiagTrack' -Force -ErrorAction SilentlyContinue"
            )
        );
        assert_eq!(
            s.commande_admin(Some("start:2")).as_deref(),
            Some(
                "Set-Service -Name 'DiagTrack' -StartupType Automatic; Start-Service -Name 'DiagTrack' -ErrorAction SilentlyContinue"
            )
        );
    }
}
