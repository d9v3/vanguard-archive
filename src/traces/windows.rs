//! Les traces sous Windows : processus par PowerShell (Win32_Process), connexions et ports par Get-NetTCPConnection,
//! tâches planifiées, services, clés Run et abonnements WMI, comptes locaux, journaux d'événements exportés en .evtx
//! par wevtutil (le format que lisent l'Observateur d'événements et les outils des spécialistes).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{Bi, Empreinte, Feuille, Manque, Partie, Processus, Produit, Raison, bi};
use crate::commande::section;

/// Le séparateur des champs dans les sorties des scripts : une ligne de commande peut contenir « | » ou une
/// tabulation, jamais ce caractère (retiré par N).
const SEP: char = '\u{1f}';

/// Une commande de la console, lancée en UTF-8 : sans « chcp 65001 », ipconfig, schtasks ou reg écrivent dans
/// l'ancienne page de code de la console, et les accents d'un Windows français deviennent illisibles.
fn console(ligne: &str) -> Command {
    let mut c = Command::new("cmd");
    c.args(["/d", "/s", "/c", &format!("chcp 65001 >nul & {ligne}")]);
    c
}

/// Lancé en administrateur (fenêtre élevée) ? Le niveau d'intégrité « élevé » ou « système » de `whoami /groups`
/// (S-1-16-12288, S-1-16-16384), le même dans toutes les langues.
pub(super) fn administrateur() -> bool {
    static ADMIN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ADMIN.get_or_init(|| {
        crate::commande::lancer(Command::new("whoami").arg("/groups"), 10)
            .is_some_and(|r| r.sortie.contains("S-1-16-12288") || r.sortie.contains("S-1-16-16384"))
    })
}

/// Place libre pour ce compte sur le disque de `d`.
pub(super) fn place_libre(d: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(dossier: *const u16, libre: *mut u64, total: *mut u64, libre_total: *mut u64) -> i32;
    }
    let large: Vec<u16> = d.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut libre = 0u64;
    // SAFETY : `large` est une chaîne terminée par un zéro, vivante pendant l'appel ; `libre` est un entier de 64 bits
    // à nous ; les deux autres tailles, dont on n'a pas besoin, peuvent être nulles (documentation de l'API).
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            large.as_ptr(),
            &raw mut libre,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(libre)
}

/// Fonction des scripts : une valeur sur une ligne, sans le séparateur des champs.
const N: &str = "$s = [char]31; function N($v) { (\"$v\" -replace '[\\r\\n\\x1f]+', ' ').Trim() }; ";

/// Les processus : numéro, parent, compte (Get-Process -IncludeUserName en administrateur, sinon GetOwner, qui ne
/// répond que pour les processus du compte), démarrage, programme et ligne de commande.
pub(crate) const SCRIPT_PROCESSUS: &str = "$u = @{}; \
     try { Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object { $u[$_.Id] = $_.UserName } } catch {}; \
     Get-CimInstance Win32_Process | ForEach-Object { \
       $c = $u[[int]$_.ProcessId]; \
       if (-not $c) { $c = try { $r = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop; if ($r.User) { $r.Domain + '\\' + $r.User } } catch { '' } }; \
       $d = if ($_.CreationDate) { $_.CreationDate.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) } else { '' }; \
       'PRC|' + $_.ProcessId + $s + $_.ParentProcessId + $s + (N $c) + $s + $d + $s + (N $_.ExecutablePath) + $s + (N $_.CommandLine) }; \
     'PRC_FIN'";

/// Les lignes « PRC|… » du script des processus : (pid, parent, compte, démarrage, programme, ligne de commande).
pub(crate) fn lire_processus(lignes: &[&str]) -> Vec<(u32, Option<u32>, String, String, String, String)> {
    lignes
        .iter()
        .filter_map(|l| {
            let c: Vec<&str> = l.split(SEP).collect();
            let [pid, parent, compte, debut, programme, ligne] = c[..] else {
                return None;
            };
            Some((
                pid.trim().parse().ok()?,
                parent.trim().parse().ok(),
                compte.to_string(),
                debut.to_string(),
                programme.to_string(),
                ligne.to_string(),
            ))
        })
        .collect()
}

pub(super) fn processus(dossier: &Path) -> Partie {
    let mut manques = Vec::new();
    let sortie = crate::machine::windows::ps_delai(&format!("{N}{SCRIPT_PROCESSUS}"), 120);
    let Some(lignes) = section(sortie.as_deref(), "PRC") else {
        // Sans PowerShell : la liste de tasklist, sans programme ni ligne de commande.
        let mut p = Partie::new(Bi::new("Processus", "Processes"));
        let mut f = Feuille::new(&p.titre);
        let tasklist = f.commande(&mut console("tasklist /v /fo csv"), 60, true);
        p.manques.append(&mut f.manques);
        p.manque(
            Bi::new(
                "Programme, ligne de commande et empreinte des processus",
                "Program, command line and fingerprint of the processes",
            ),
            Raison::SansPowerShell,
        );
        if tasklist.is_some()
            && p.ecrire(
                dossier,
                "01-processus.txt",
                &f.texte,
                Bi::new(
                    "processus en marche, d'après tasklist (PowerShell n'a pas répondu)",
                    "running processes, from tasklist (PowerShell did not answer)",
                ),
            )
        {
            let n = tasklist.unwrap_or_default().lines().count().saturating_sub(1);
            p.compte = Some(bi!("{n} (sans empreintes)", "{n} (no fingerprints)"));
        }
        return p;
    };
    let admin = administrateur();
    let mut empreintes: HashMap<String, Empreinte> = HashMap::new();
    let fin = std::time::Instant::now() + super::DELAI_EMPREINTES;
    let mut sans_programme = 0;
    let liste: Vec<Processus> = lire_processus(&lignes)
        .into_iter()
        .map(|(pid, ppid, compte, debut, programme, ligne)| {
            let empreinte = if programme.is_empty() {
                // « System Idle Process » et « System » n'ont pas de programme ; les autres le cachent à qui n'est
                // pas administrateur.
                if pid <= 4 {
                    Empreinte::Aucune
                } else {
                    sans_programme += 1;
                    if admin { Empreinte::Illisible } else { Empreinte::Droits }
                }
            } else {
                empreintes
                    .entry(programme.to_lowercase())
                    .or_insert_with(|| {
                        if std::time::Instant::now() > fin {
                            Empreinte::Delai
                        } else {
                            super::empreinte(Path::new(&programme), super::TAILLE_PROGRAMME)
                        }
                    })
                    .clone()
            };
            Processus {
                pid,
                ppid,
                compte,
                debut,
                programme,
                etat: "",
                ligne,
                empreinte,
            }
        })
        .collect();
    if sans_programme > 0 && !admin {
        manques.push(Manque {
            quoi: bi!(
                "Programme et empreinte de {sans_programme} processus protégés ou d'autres comptes",
                "Program and fingerprint of {sans_programme} protected or other accounts' processes"
            ),
            raison: Raison::Droits,
        });
    }
    super::partie_processus(dossier, liste, manques)
}

/// Les connexions TCP et les ports UDP, avec le numéro et le nom du programme.
const SCRIPT_RESEAU: &str = "$p = @{}; Get-Process | ForEach-Object { $p[$_.Id] = $_.ProcessName }; \
     Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object { 'NET|TCP' + $s + $_.State + $s + $_.LocalAddress + ':' + $_.LocalPort + $s + $_.RemoteAddress + ':' + $_.RemotePort + $s + $_.OwningProcess + $s + (N $p[[int]$_.OwningProcess]) }; \
     Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { 'NET|UDP' + $s + '-' + $s + $_.LocalAddress + ':' + $_.LocalPort + $s + '-' + $s + $_.OwningProcess + $s + (N $p[[int]$_.OwningProcess]) }; \
     'NET_FIN'";

/// Les lignes « NET|… » mises en tableau, une connexion par ligne, champs séparés par des tabulations.
pub(crate) fn tableau_reseau(lignes: &[&str]) -> String {
    let mut t = String::from("PROTO\tÉTAT/STATE\tLOCALE/LOCAL\tDISTANTE/REMOTE\tPID\tPROGRAMME/PROGRAM\n");
    for l in lignes {
        let champs: Vec<String> = l.split(SEP).map(super::champ).collect();
        let _ = writeln!(t, "{}", champs.join("\t"));
    }
    t
}

pub(super) fn reseau(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Réseau", "Network"));
    let mut f = Feuille::new(&p.titre);
    let sortie = crate::machine::windows::ps(&format!("{N}{SCRIPT_RESEAU}"));
    let connexions = section(sortie.as_deref(), "NET");
    f.section("Get-NetTCPConnection, Get-NetUDPEndpoint");
    if let Some(lignes) = &connexions {
        f.lues += 1;
        f.ajouter(&tableau_reseau(lignes));
    } else {
        f.ajouter("(PowerShell)");
        f.commande(&mut console("netstat -ano"), 30, true);
    }
    f.commande(&mut console("arp -a"), 15, true);
    f.commande(&mut console("ipconfig /all"), 15, true);
    // Les noms demandés récemment : ils disparaissent au redémarrage ou après quelques heures.
    f.commande(&mut console("ipconfig /displaydns"), 30, false);
    f.commande(&mut console("route print"), 15, false);
    f.commande(&mut console("netsh winhttp show proxy"), 15, false);
    let racine = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    f.fichier(&racine.join(r"System32\drivers\etc\hosts"), true);
    p.manques.append(&mut f.manques);
    if p.ecrire(
        dossier,
        "02-reseau.txt",
        &f.texte,
        Bi::new(
            "connexions TCP et ports UDP avec leur programme (Get-NetTCPConnection, ou netstat -ano), voisins du réseau local (arp -a), cartes et DNS (ipconfig /all), noms demandés récemment (ipconfig /displaydns), routes, proxy et fichier hosts",
            "TCP connections and UDP ports with their program (Get-NetTCPConnection, or netstat -ano), local network neighbours (arp -a), adapters and DNS (ipconfig /all), recently resolved names (ipconfig /displaydns), routes, proxy and hosts file",
        ),
    ) {
        p.compte = Some(match connexions {
            Some(l) => bi!(
                "{} connexions et ports à l'écoute",
                "{} connections and listening ports",
                l.len()
            ),
            None => bi!("{} source(s) lue(s)", "{} source(s) read", f.lues),
        });
    }
    p
}

/// Services (programme lancé et compte), abonnements WMI permanents (filtre, commande ou script lancés, et leurs
/// liens) : deux persistances que l'on ne voit dans aucune liste ordinaire.
const SCRIPT_DEMARRAGE: &str = "try { Get-CimInstance Win32_Service | ForEach-Object { 'SRV|' + (N $_.Name) + $s + $_.State + $s + $_.StartMode + $s + (N $_.StartName) + $s + (N $_.PathName) }; 'SRV_FIN' } catch {}; \
     try { \
       Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction Stop | ForEach-Object { 'WMI|filtre' + $s + (N $_.Name) + $s + (N $_.Query) }; \
       Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction Stop | ForEach-Object { 'WMI|commande' + $s + (N $_.Name) + $s + (N ($_.ExecutablePath + ' ' + $_.CommandLineTemplate)) }; \
       Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction Stop | ForEach-Object { 'WMI|script' + $s + (N $_.Name) + $s + (N $_.ScriptText) }; \
       Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object { 'WMI|lien' + $s + (N $_.Filter) + $s + (N $_.Consumer) }; \
       'WMI_FIN' } catch {}";

/// Les clés du registre qui lancent un programme à l'ouverture de session ou au démarrage, ou s'immiscent dans
/// chaque lancement (Winlogon, AppInit_DLLs, AutoRun de l'invite de commandes, BootExecute).
const CLES_DEMARRAGE: [&str; 13] = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
    r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows",
    r"HKCU\Software\Microsoft\Command Processor",
    r"HKLM\Software\Microsoft\Command Processor",
    r"HKLM\System\CurrentControlSet\Control\Session Manager",
];

pub(super) fn demarrage(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Ce qui se lance tout seul", "What starts by itself"));
    let mut f = Feuille::new(&p.titre);
    f.commande(&mut console("schtasks /query /fo LIST /v"), 90, true);
    for cle in CLES_DEMARRAGE {
        // Session Manager : seulement BootExecute, le reste est long et sans rapport.
        let ligne = if cle.ends_with("Session Manager") {
            format!("reg query \"{cle}\" /v BootExecute")
        } else {
            format!("reg query \"{cle}\"")
        };
        f.commande(&mut console(&ligne), 15, false);
    }
    for dossier_demarrage in [
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup")),
        std::env::var_os("ProgramData")
            .map(|a| PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\StartUp")),
    ]
    .into_iter()
    .flatten()
    {
        // Des raccourcis (.lnk) : la liste seulement ; leur empreinte est dans les fichiers récents.
        f.dossier(&dossier_demarrage, 0, false);
    }
    let sortie = crate::machine::windows::ps(&format!("{N}{SCRIPT_DEMARRAGE}"));
    f.section("Win32_Service");
    if let Some(services) = section(sortie.as_deref(), "SRV") {
        f.lues += 1;
        let mut t = String::from("NOM/NAME\tÉTAT/STATE\tDÉMARRAGE/START\tCOMPTE/ACCOUNT\tPROGRAMME/PROGRAM\n");
        for s in services {
            let champs: Vec<String> = s.split(SEP).map(super::champ).collect();
            let _ = writeln!(t, "{}", champs.join("\t"));
        }
        f.ajouter(&t);
    } else {
        f.ajouter("(PowerShell)");
        f.manques.push(Manque {
            quoi: Bi::new("Services", "Services"),
            raison: Raison::SansPowerShell,
        });
    }
    f.section("root/subscription (WMI)");
    if let Some(abonnements) = section(sortie.as_deref(), "WMI") {
        f.lues += 1;
        if abonnements.is_empty() {
            f.ajouter("(aucun / none)");
        }
        for a in abonnements {
            let champs: Vec<String> = a.split(SEP).map(super::champ).collect();
            f.ajouter(&champs.join("\t"));
        }
    } else {
        // L'espace root/subscription ne se lit qu'en administrateur ; sans réponse du tout, PowerShell est en cause.
        let raison = if sortie.is_none() || administrateur() {
            Raison::SansPowerShell
        } else {
            Raison::Droits
        };
        f.ajouter(&raison.note());
        f.manques.push(Manque {
            quoi: Bi::new("Abonnements WMI permanents", "Permanent WMI subscriptions"),
            raison,
        });
    }
    p.manques.append(&mut f.manques);
    if p.ecrire(
        dossier,
        "03-demarrage.txt",
        &f.texte,
        Bi::new(
            "ce qui se lance tout seul, tel quel : tâches planifiées (schtasks), clés Run et RunOnce, Winlogon, AppInit_DLLs, AutoRun, BootExecute, dossiers Démarrage, services (programme et compte), abonnements WMI permanents",
            "what starts by itself, as is: scheduled tasks (schtasks), Run and RunOnce keys, Winlogon, AppInit_DLLs, AutoRun, BootExecute, Startup folders, services (program and account), permanent WMI subscriptions",
        ),
    ) {
        p.compte = Some(bi!("{} source(s) lue(s)", "{} source(s) read", f.lues));
    }
    p
}

/// Les comptes locaux (activé, dernière connexion, mot de passe changé, SID) et les administrateurs, par le SID du
/// groupe (son nom change avec la langue).
const SCRIPT_COMPTES: &str = "function D($t) { if ($t) { $t.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) } }; \
     try { Get-LocalUser | ForEach-Object { 'USR|' + (N $_.Name) + $s + $_.Enabled + $s + (D $_.LastLogon) + $s + (D $_.PasswordLastSet) + $s + $_.SID.Value + $s + (N $_.Description) }; 'USR_FIN' } catch {}; \
     try { Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { 'ADM|' + (N $_.Name) + $s + $_.ObjectClass + $s + $_.PrincipalSource }; 'ADM_FIN' } catch {}";

pub(super) fn comptes(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Comptes", "Accounts"));
    let mut f = Feuille::new(&p.titre);
    let sortie = crate::machine::windows::ps(&format!("{N}{SCRIPT_COMPTES}"));
    let utilisateurs = section(sortie.as_deref(), "USR");
    f.section("Get-LocalUser");
    if let Some(u) = &utilisateurs {
        f.lues += 1;
        let mut t = String::from(
            "NOM/NAME\tACTIVÉ/ENABLED\tDERNIÈRE CONNEXION/LAST LOGON\tMOT DE PASSE/PASSWORD SET\tSID\tDESCRIPTION\n",
        );
        for l in u {
            let champs: Vec<String> = l.split(SEP).map(super::champ).collect();
            let _ = writeln!(t, "{}", champs.join("\t"));
        }
        f.ajouter(&t);
    } else {
        f.ajouter("(PowerShell)");
        f.commande(&mut console("net user"), 15, true);
    }
    f.section("Get-LocalGroupMember -SID S-1-5-32-544");
    if let Some(a) = section(sortie.as_deref(), "ADM") {
        f.lues += 1;
        for l in a {
            let champs: Vec<String> = l.split(SEP).map(super::champ).collect();
            f.ajouter(&champs.join("\t"));
        }
    } else {
        f.ajouter("(PowerShell)");
        f.manques.push(Manque {
            quoi: Bi::new("Administrateurs", "Administrators"),
            raison: Raison::SansPowerShell,
        });
    }
    f.commande(&mut console("query user"), 15, false);
    p.manques.append(&mut f.manques);
    if p.ecrire(
        dossier,
        "04-comptes.txt",
        &f.texte,
        Bi::new(
            "comptes locaux (activé, dernière connexion, mot de passe changé, SID), administrateurs, sessions ouvertes ; les connexions elles-mêmes (4624, 4625) sont dans le journal de sécurité",
            "local accounts (enabled, last logon, password set, SID), administrators, open sessions; the logons themselves (4624, 4625) are in the security log",
        ),
    ) {
        p.compte = Some(match utilisateurs {
            Some(u) => bi!("{} comptes", "{} accounts", u.len()),
            None => bi!("{} source(s) lue(s)", "{} source(s) read", f.lues),
        });
    }
    p
}

/// Les journaux exportés : (journal, fichier, titre, réservé à l'administrateur).
const JOURNAUX: [(&str, &str, (&str, &str), bool); 4] = [
    ("System", "05-System.evtx", ("Journal Système", "System log"), false),
    (
        "Security",
        "05-Security.evtx",
        ("Journal de sécurité", "Security log"),
        true,
    ),
    (
        "Microsoft-Windows-PowerShell/Operational",
        "05-PowerShell.evtx",
        ("Journal de PowerShell", "PowerShell log"),
        false,
    ),
    (
        "Microsoft-Windows-Windows Defender/Operational",
        "05-Defender.evtx",
        ("Journal de Windows Defender", "Windows Defender log"),
        false,
    ),
];

/// Les événements des 7 derniers jours (604 800 000 ms), dans la syntaxe XPath de wevtutil.
const SEPT_JOURS: &str = "/q:*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]";

/// La taille d'un journal d'après « wevtutil gli » (« fileSize: 1052672 »).
pub(crate) fn taille_gli(sortie: &str) -> Option<u64> {
    sortie
        .lines()
        .find_map(|l| l.trim().strip_prefix("fileSize:"))?
        .trim()
        .parse()
        .ok()
}

/// Pourquoi wevtutil a refusé, d'après son message (en anglais ou en français).
pub(crate) fn raison_wevtutil(erreurs: &str) -> Raison {
    let e = erreurs.to_lowercase();
    if e.contains("access is denied") || e.contains("accès refusé") || e.contains("acces refuse") {
        Raison::Droits
    } else if ["not found", "not be found", "introuvable", "n'existe pas"]
        .iter()
        .any(|m| e.contains(m))
    {
        Raison::Introuvable
    } else {
        Raison::Erreur(erreurs.lines().next().unwrap_or_default().trim().to_string())
    }
}

pub(super) fn journaux(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Journaux", "Logs"));
    let admin = administrateur();
    let mut lus = Vec::new();
    let mut total = 0;
    for (journal, nom, (fr, en), reserve) in JOURNAUX {
        let titre = Bi::new(fr, en);
        if reserve && !admin {
            p.manque(titre, Raison::Droits);
            continue;
        }
        let destination = dossier.join(nom);
        let debut = std::time::Instant::now();
        let r = crate::commande::lancer(
            Command::new("wevtutil")
                .args(["epl", journal])
                .arg(&destination)
                .arg(SEPT_JOURS),
            120,
        );
        match r {
            None if debut.elapsed().as_secs() >= 120 => p.manque(titre, Raison::Delai(120)),
            None => p.manque(titre, Raison::Absente("wevtutil".into())),
            // Codes de Windows : 5, accès refusé ; 15007, journal introuvable (Defender retiré, par exemple). Le
            // message, lui, est dans la langue et la page de code de la console.
            Some(r) if r.code == Some(5) => p.manque(titre, Raison::Droits),
            Some(r) if r.code == Some(15007) => p.manque(titre, Raison::Introuvable),
            Some(r) if r.code != Some(0) => p.manque(titre, raison_wevtutil(&format!("{}{}", r.erreurs, r.sortie))),
            // Une réussite sans fichier (wevtutil de Wine, qui ne fait rien) n'est pas une réussite.
            Some(_) if !destination.is_file() => {
                p.manque(
                    titre,
                    Raison::Erreur("wevtutil : aucun fichier écrit / no file written".into()),
                );
            }
            Some(_) => {
                total += std::fs::metadata(&destination).map_or(0, |m| m.len());
                lus.push((fr, en));
                p.fichiers.push(Produit {
                    nom: nom.into(),
                    contenu: bi!(
                        "{fr} ({journal}), les événements des 7 derniers jours, au format .evtx (Observateur d'événements)",
                        "{en} ({journal}), the events of the last 7 days, as .evtx (Event Viewer)"
                    ),
                });
            }
        }
    }
    if !lus.is_empty() {
        #[allow(clippy::cast_precision_loss)]
        let mo = total as f64 / f64::from(1u32 << 20);
        let liste_fr = lus.iter().map(|(fr, _)| *fr).collect::<Vec<_>>().join(", ");
        let liste_en = lus.iter().map(|(_, en)| *en).collect::<Vec<_>>().join(", ");
        p.compte = Some(Bi::new(
            format!("{liste_fr} : {mo:.0} Mo (7 jours)"),
            format!("{liste_en}: {mo:.0} MB (7 days)"),
        ));
    }
    p
}

/// La place que peuvent prendre les journaux : leur taille entière, au plus (l'export ne garde que 7 jours).
pub(super) fn place_des_journaux() -> u64 {
    JOURNAUX
        .iter()
        .map(|(journal, ..)| {
            crate::commande::lancer(Command::new("wevtutil").args(["gli", journal]), 15)
                .and_then(|r| taille_gli(&r.sortie))
                .unwrap_or(20 << 20)
        })
        .sum()
}

/// Les dossiers où un programme dépose ce qu'il lance, en plus de TEMP (déjà dans les endroits à risque) : le profil
/// Public, ouvert à tous les comptes, et le dossier Démarrage commun.
pub(super) fn endroits_temporaires() -> Vec<PathBuf> {
    [
        std::env::var_os("PUBLIC").map(PathBuf::from),
        std::env::var_os("ProgramData")
            .map(|d| PathBuf::from(d).join(r"Microsoft\Windows\Start Menu\Programs\StartUp")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lignes_des_scripts() {
        let s = SEP;
        let lignes = [
            format!("4242{s}1000{s}PC\\alice{s}2026-10-20 14:03:22{s}C:\\Users\\alice\\AppData\\x.exe{s}x.exe -a | b"),
            format!("4{s}0{s}{s}{s}{s}"),
            "illisible".to_string(),
        ];
        let lignes: Vec<&str> = lignes.iter().map(String::as_str).collect();
        let p = lire_processus(&lignes);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].0, 4242);
        assert_eq!(p[0].1, Some(1000));
        assert_eq!(p[0].2, "PC\\alice");
        assert_eq!(p[0].5, "x.exe -a | b");
        assert_eq!(p[1].4, "");
        let t = tableau_reseau(&[&format!(
            "TCP{s}Established{s}10.0.0.2:50000{s}203.0.113.5:4444{s}4242{s}x"
        )]);
        assert!(
            t.ends_with("TCP\tEstablished\t10.0.0.2:50000\t203.0.113.5:4444\t4242\tx\n"),
            "{t}"
        );
    }

    #[test]
    fn reponses_de_wevtutil() {
        assert_eq!(
            taille_gli("creationTime: 2026-01-01\nfileSize: 1052672\nattributes: 32"),
            Some(1_052_672)
        );
        assert_eq!(taille_gli("rien"), None);
        assert_eq!(
            raison_wevtutil("Failed to export log Security. Access is denied."),
            Raison::Droits
        );
        assert_eq!(raison_wevtutil("Échec de l'exportation. Accès refusé."), Raison::Droits);
        assert_eq!(
            raison_wevtutil("Failed to export log X. The specified channel could not be found."),
            Raison::Introuvable
        );
        assert!(matches!(raison_wevtutil("Autre chose"), Raison::Erreur(_)));
    }

    /// Les scripts envoyés à PowerShell, tels qu'ils partent : écrits dans le dossier des tests pour être analysés
    /// par pwsh (VANGUARD_SCRIPTS : le dossier où les copier).
    #[test]
    fn scripts_complets() {
        let scripts = [
            ("processus", format!("{N}{SCRIPT_PROCESSUS}")),
            ("reseau", format!("{N}{SCRIPT_RESEAU}")),
            ("demarrage", format!("{N}{SCRIPT_DEMARRAGE}")),
            ("comptes", format!("{N}{SCRIPT_COMPTES}")),
        ];
        for (nom, s) in &scripts {
            for marque in ["PRC_FIN", "NET_FIN", "SRV_FIN", "WMI_FIN", "USR_FIN", "ADM_FIN"] {
                if s.contains(&marque[..3]) {
                    assert!(s.contains(marque), "{nom} : {marque}");
                }
            }
            if let Some(d) = std::env::var_os("VANGUARD_SCRIPTS") {
                let mut contenu = vec![0xef, 0xbb, 0xbf];
                contenu.extend_from_slice(s.as_bytes());
                std::fs::write(PathBuf::from(d).join(format!("traces-{nom}.ps1")), contenu).unwrap();
            }
        }
    }
}
