//! Audit de sécurité de cette machine : types communs, affichage et exécution des correctifs.
//! Les vérifications elles-mêmes dépendent du système (linux/, windows/, macos/).

use std::process::Command;

use serde::Serialize;

use crate::risk::Niveau;
use crate::ui::*;

mod administrateurs;
mod bluetooth;
mod certificats;
mod comptes_oublies;
pub(crate) mod dns;
mod extensions;
mod fin_de_support;
mod heure;
mod journaux;
#[cfg(target_os = "linux")]
pub mod linux;
mod mots_de_passe;
mod navigateur;
mod navigation_detournee;
mod partages;
mod sante;
mod sensibles;
pub(crate) mod wifi;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
use windows as os;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(unix)]
mod unix;
#[cfg(target_os = "macos")]
use macos as os;

#[derive(Serialize, Clone)]
pub struct Correctif {
    /// Ce que fait la correction, en une phrase.
    pub action: String,
    /// Commandes exécutées dans l'ordre : bash sous Linux, PowerShell (administrateur) sous Windows.
    pub commandes: Vec<String>,
    /// `false` = à faire soi-même (redémarrage, réglage du routeur…) : on affiche seulement la marche à suivre.
    pub automatique: bool,
    /// Port bloqué en entrée par cette correction (« 8080/tcp »), retenu une fois appliquée.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bloque: Option<String>,
}

#[derive(Serialize)]
pub struct Constat {
    pub categorie: &'static str,
    /// `None` = tout va bien.
    pub probleme: Option<Niveau>,
    pub message: String,
    pub correctif: Option<Correctif>,
    /// `false` = la vérification n'a pas pu se faire. C'est ce champ, et non le texte du message,
    /// qui décide de la note : reformuler un message ne doit pas désactiver ce garde-fou.
    pub verifie: bool,
}

#[derive(Serialize)]
pub struct Audit {
    pub systeme: &'static str,
    pub score: u32,
    pub constats: Vec<Constat>,
}

impl Audit {
    /// Nombre de vérifications qui n'ont pas pu se faire.
    pub fn impossibles(&self) -> usize {
        self.constats.iter().filter(|c| !c.verifie).count()
    }

    /// Une note n'a de sens que si le pare-feu a été vérifié et qu'au plus un tiers des vérifications a échoué :
    /// sinon une machine peu vérifiée obtiendrait un « A » rassurant (vu en test sur Fedora en conteneur).
    pub fn fiable(&self) -> bool {
        let pare_feu_inconnu = self.constats.iter().any(|c| c.categorie == "Pare-feu" && !c.verifie);
        !pare_feu_inconnu && self.impossibles() * 3 < self.constats.len()
    }
}

pub(crate) fn ok(categorie: &'static str, message: impl Into<String>) -> Constat {
    Constat {
        categorie,
        probleme: None,
        message: message.into(),
        correctif: None,
        verifie: true,
    }
}

pub(crate) fn alerte(categorie: &'static str, niveau: Niveau, message: impl Into<String>) -> Constat {
    Constat {
        categorie,
        probleme: Some(niveau),
        message: message.into(),
        correctif: None,
        verifie: true,
    }
}

/// Vérification qui n'a pas pu se faire : on le dit, sans jamais conclure « OK ».
pub(crate) fn impossible(categorie: &'static str, raison: &str) -> Constat {
    Constat {
        verifie: false,
        ..alerte(
            categorie,
            Niveau::Info,
            trf!("Impossible de vérifier ({raison}).", "Could not check ({raison})."),
        )
    }
}

impl Constat {
    pub(crate) fn corriger(mut self, action: impl Into<String>, commandes: &[impl ToString]) -> Self {
        self.correctif = Some(Correctif {
            action: action.into(),
            commandes: commandes.iter().map(ToString::to_string).collect(),
            automatique: true,
            bloque: None,
        });
        self
    }

    /// La correction bloque ce port (« 8080/tcp ») dans le pare-feu.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    fn bloquant(mut self, port: String) -> Self {
        if let Some(k) = &mut self.correctif {
            k.bloque = Some(port);
        }
        self
    }

    pub(crate) fn manuel(self, action: impl Into<String>, commandes: &[&str]) -> Self {
        let mut c = self.corriger(action, commandes);
        if let Some(k) = &mut c.correctif {
            k.automatique = false;
        }
        c
    }
}

/// Niveau d'un service ouvert sur le réseau. Avec un pare-feu actif, il n'est en général pas joignable : on baisse
/// d'un cran ; sans pare-feu, même un service anodin est exposé (Info → Moyen). Une ligne par cas, pour la lecture.
#[allow(clippy::match_same_arms)]
fn niveau_expose(pare_feu_actif: bool, niveau: Niveau) -> Niveau {
    match (pare_feu_actif, niveau) {
        (true, Niveau::Critique) => Niveau::Eleve,
        (true, Niveau::Eleve) => Niveau::Moyen,
        (true, _) => Niveau::Info,
        (false, Niveau::Info) => Niveau::Moyen,
        (false, n) => n,
    }
}

/// Une vérification à lancer : elle rend ses constats.
pub(crate) type Verification<'a> = Box<dyn FnOnce() -> Vec<Constat> + Send + 'a>;

/// Lance les vérifications en même temps (chacune attend surtout des commandes du système) et rend leurs constats
/// dans l'ordre de la liste. Une vérification qui plante le dit, sans emporter les autres.
fn en_parallele(verifications: Vec<Verification<'_>>) -> Vec<Constat> {
    // GARDIEN_CHRONO : chaque vérification dit son temps sur la sortie d'erreur, pour trouver ce qui ralentit le bilan.
    let chrono = std::env::var_os("GARDIEN_CHRONO").is_some();
    std::thread::scope(|s| {
        let fils: Vec<_> = verifications
            .into_iter()
            .map(|v| {
                s.spawn(move || {
                    let debut = std::time::Instant::now();
                    let constats = v();
                    (constats, debut.elapsed())
                })
            })
            .collect();
        fils.into_iter()
            .enumerate()
            .flat_map(|(i, f)| {
                let (constats, duree) = f.join().unwrap_or_else(|_| {
                    (
                        vec![impossible("Audit", tr!("erreur interne", "internal error"))],
                        std::time::Duration::ZERO,
                    )
                });
                if chrono {
                    let quoi = constats.first().map_or("(rien)", |c| c.categorie);
                    eprintln!("chrono {i:>2} {:>6} ms  {quoi}", duree.as_millis());
                }
                constats
            })
            .collect()
    })
}

/// `verif!(f())` : une vérification qui rend un constat, une liste ou une option, mise en boîte pour `en_parallele`.
macro_rules! verif {
    ($e:expr) => {
        Box::new(move || $e.into_iter().collect::<Vec<$crate::machine::Constat>>()) as $crate::machine::Verification<'_>
    };
}
pub(crate) use verif;

/// L'audit d'un système : `premier` (le pare-feu, dont d'autres vérifications dépendent), puis ses vérifications et
/// celles communes aux trois systèmes, lancées en même temps et rendues dans l'ordre de la liste.
fn audit(systeme: &'static str, premier: Constat, mut propres: Vec<Verification<'_>>) -> Audit {
    propres.extend([
        verif!(dns::dns()),
        verif!(certificats::certificats()),
        verif!(extensions::extensions()),
        verif!(navigateur::navigateurs()),
        verif!([navigation_detournee::constat()]),
        verif!(mots_de_passe::constats()),
        verif!(sensibles::constats()),
        verif!(sante::sante()),
        verif!(partages::partages()),
        verif!(bluetooth::constats()),
        verif!(administrateurs::constat()),
        verif!(journaux::journaux()),
        verif!(heure::constat()),
        verif!(fin_de_support::constats()),
        verif!(comptes_oublies::constats()),
        verif!([crate::protection::integrite::constat()]),
        verif!(crate::protection::pieges::constat()),
        verif!(crate::protection::distance::constats()),
        verif!(crate::protection::manifeste::constat()),
        verif!(crate::historique::constat()),
        verif!(crate::reseau::surveillance::constat()),
        verif!(crate::chiffrement::constat()),
        verif!(crate::sauvegarde::constats()),
    ]);
    let mut constats = vec![premier];
    constats.extend(en_parallele(propres));
    Audit {
        systeme,
        score: score(&constats),
        constats,
    }
}

fn score(constats: &[Constat]) -> u32 {
    100u32.saturating_sub(constats.iter().filter_map(|c| c.probleme).map(Niveau::penalite).sum())
}

/// Un port ouvert sur le réseau par un programme, sous Linux et macOS : (niveau qu'il vaut derrière ce pare-feu,
/// alerte).
#[cfg(unix)]
fn port_expose(
    port: u16,
    proto: &str,
    i: &crate::risk::InfoPort,
    programme: &str,
    pare_feu_actif: bool,
) -> (Niveau, Constat) {
    let niveau = niveau_expose(pare_feu_actif, i.niveau);
    let constat = alerte(
        "Ports en écoute",
        niveau,
        trf!(
            "{port}/{proto} ({}) ouvert sur le réseau par « {programme} ». {}",
            "{port}/{proto} ({}) open to the network by “{programme}”. {}",
            i.service,
            i.conseil
        ),
    );
    (niveau, constat)
}

/// Aucun service exposé au réseau, sous Linux et macOS.
#[cfg(unix)]
fn aucun_port_expose() -> Constat {
    ok(
        "Ports en écoute",
        tr!(
            "Aucun service TCP ou UDP exposé au réseau (tout écoute en local).",
            "No TCP or UDP service exposed to the network (everything listens locally)."
        ),
    )
}

/// Sortie standard d'une commande, ou `None` si elle est absente ou échoue.
#[cfg(unix)]
pub(crate) fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
    let r = crate::commande::lancer(Command::new(cmd).args(args), 30)?;
    (r.code == Some(0)).then_some(r.sortie)
}

/// Permissions de ~/.ssh.
#[cfg(unix)]
fn cles_ssh() -> Vec<Constat> {
    let dossier = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".ssh");
    let Ok(meta) = std::fs::metadata(&dossier) else {
        return vec![ok("Clés SSH", tr!("Pas de dossier ~/.ssh.", "No ~/.ssh folder."))];
    };
    let mut constats = Vec::new();
    if std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o077 != 0 {
        constats.push(
            alerte(
                "Clés SSH",
                Niveau::Eleve,
                tr!(
                    "~/.ssh est lisible par d'autres utilisateurs.",
                    "~/.ssh is readable by other users."
                ),
            )
            .corriger(
                tr!("Restreindre ~/.ssh à toi seul", "Restrict ~/.ssh to you only"),
                &["chmod 700 ~/.ssh"],
            ),
        );
    }
    for f in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
        let brut = f.file_name().to_string_lossy().into_owned();
        // Toute clé privée, quel que soit son nom (pas seulement id_*).
        let protegee = std::fs::read_to_string(f.path()).ok().and_then(|t| cle_protegee(&t));
        // Nom entre apostrophes dans les commandes : une clé « ma cle » ne casse pas la commande. Les commandes visent
        // le vrai nom ; les messages montrent un nom rendu inoffensif.
        let chemin = format!("~/.ssh/'{}'", brut.replace('\'', r"'\''"));
        let nom = affichable(&brut);
        if protegee == Some(false) {
            constats.push(
                alerte(
                    "Clés SSH",
                    Niveau::Moyen,
                    trf!("Clé privée ~/.ssh/{nom} sans phrase de passe : volée, elle ouvre tous les serveurs où elle est autorisée.", "Private key ~/.ssh/{nom} has no passphrase: if stolen, it opens every server where it is authorized."),
                )
                .corriger(
                    trf!("Ajouter une phrase de passe à {nom} (la clé publique ne change pas, rien à refaire sur les serveurs)", "Add a passphrase to {nom} (the public key does not change, nothing to redo on the servers)"),
                    &[&format!("ssh-keygen -p -f {chemin}")],
                ),
            );
        }
        // Même règle que ci-dessus : une clé « github » ou « serveur » compte autant qu'« id_ed25519 ».
        let privee = protegee.is_some()
            || (brut.starts_with("id_")
                && !std::path::Path::new(&brut)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("pub")));
        if privee
            && f.metadata()
                .is_ok_and(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o077 != 0)
        {
            constats.push(
                alerte(
                    "Clés SSH",
                    Niveau::Critique,
                    trf!(
                        "Clé privée ~/.ssh/{nom} lisible par d'autres.",
                        "Private key ~/.ssh/{nom} is readable by others."
                    ),
                )
                .corriger(
                    trf!("Protéger la clé {nom}", "Protect the key {nom}"),
                    &[&format!("chmod 600 {chemin}")],
                ),
            );
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            "Clés SSH",
            tr!("Permissions de ~/.ssh correctes.", "~/.ssh permissions are correct."),
        ));
    }
    constats
}

/// Une clé privée SSH est-elle protégée par une phrase de passe ? `None` si ce n'est pas une clé privée.
#[cfg(unix)]
fn cle_protegee(texte: &str) -> Option<bool> {
    let entete = texte.lines().next()?.trim();
    if !entete.starts_with("-----BEGIN") || !entete.contains("PRIVATE KEY") {
        return None;
    }
    match entete {
        // PKCS#8 : le type dit tout.
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" => Some(true),
        // Format OpenSSH : le nom du chiffrement est écrit dans la clé (« none » = pas de phrase de passe).
        "-----BEGIN OPENSSH PRIVATE KEY-----" => {
            let corps: String = texte.lines().filter(|l| !l.starts_with("-----")).collect();
            let octets = base64_decoder(&corps)?;
            let reste = octets.strip_prefix(b"openssh-key-v1\0")?;
            let longueur = u32::from_be_bytes(reste.get(..4)?.try_into().ok()?) as usize;
            Some(reste.get(4..4 + longueur)? != b"none")
        }
        // Ancien format PEM (RSA, EC, DSA) : un en-tête Proc-Type signale le chiffrement.
        _ => Some(texte.contains("Proc-Type: 4,ENCRYPTED")),
    }
}

/// Décode du base64, espaces et « = » ignorés ; `None` si un caractère n'est pas de l'alphabet. Un dernier bloc d'un
/// seul caractère ne donne aucun octet.
fn base64_decoder(texte: &str) -> Option<Vec<u8>> {
    let valeur = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let propre: Vec<u8> = texte
        .bytes()
        .filter(|c| !c.is_ascii_whitespace() && *c != b'=')
        .collect();
    let mut sortie = Vec::with_capacity(propre.len() * 3 / 4);
    for bloc in propre.chunks(4) {
        let n = bloc.iter().try_fold(0u32, |acc, &c| Some(acc << 6 | valeur(c)?))? << (6 * (4 - bloc.len()));
        sortie.extend_from_slice(&n.to_be_bytes()[1..bloc.len()]);
    }
    Some(sortie)
}

/// Ports que Gardien a bloqués dans le pare-feu de cet ordinateur, un par ligne (« 8080/tcp »).
/// Un port bloqué écoute toujours : sans ce registre, l'alerte et la même correction revenaient à chaque audit.
/// Sous Linux, les règles ufw ne sont pas lisibles sans root ; Windows, lui, relit ses règles directement.
fn fichier_blocages() -> std::path::PathBuf {
    crate::reseau::dossier_local().join("ports-bloques.txt")
}

fn lire_blocages(texte: &str) -> std::collections::HashSet<String> {
    texte
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(target_os = "linux")]
fn ports_bloques() -> std::collections::HashSet<String> {
    lire_blocages(&std::fs::read_to_string(fichier_blocages()).unwrap_or_default())
}

/// À appeler après une correction réussie : retient le port qu'elle a bloqué.
/// Empreinte de cet ordinateur : SHA-1 de son identifiant (/etc/machine-id sous Linux, IOPlatformUUID sous macOS,
/// MachineGuid sous Windows). La clé s'en sert pour reconnaître l'ordinateur de son propriétaire, et « Mes
/// ordinateurs » pour retrouver l'entrée d'un ordinateur ; elle ne dit pas qui est la personne.
pub fn empreinte_machine() -> Option<String> {
    #[cfg(target_os = "linux")]
    let id = std::fs::read_to_string("/etc/machine-id").ok()?;
    // « "IOPlatformUUID" = "564D…" »
    #[cfg(target_os = "macos")]
    let id = crate::commande::lancer(Command::new("ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]), 10)?
        .sortie
        .lines()
        .find(|l| l.contains("\"IOPlatformUUID\""))?
        .rsplit('"')
        .nth(1)?
        .to_string();
    #[cfg(windows)]
    let id: String = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Cryptography")
        .and_then(|k| k.get_value("MachineGuid"))
        .ok()?;
    let id = id.trim();
    (!id.is_empty()).then(|| sha1_smol::Sha1::from(id).digest().to_string())
}

pub fn retenir_blocage(k: &Correctif) {
    let Some(port) = &k.bloque else { return };
    let chemin = fichier_blocages();
    let mut deja = lire_blocages(&std::fs::read_to_string(&chemin).unwrap_or_default());
    if deja.insert(port.clone()) {
        let mut lignes: Vec<_> = deja.into_iter().collect();
        lignes.sort();
        let _ = std::fs::create_dir_all(chemin.parent().unwrap_or(&chemin));
        let _ = std::fs::write(&chemin, lignes.join("\n") + "\n");
    }
}

/// Exécute les commandes d'un correctif. Sous Windows, une seule fenêtre UAC par correctif.
pub fn appliquer(commandes: &[String]) -> bool {
    appliquer_chacune(&[commandes.to_vec()]) == [true]
}

/// Applique plusieurs correctifs indépendants (chacun sa liste de commandes) et dit lesquels ont réussi : un
/// correctif en échec n'empêche pas les suivants. Sous Linux et macOS, les commandes d'un correctif s'arrêtent à la
/// première en échec ; sous Windows, une seule fenêtre UAC pour tous.
pub fn appliquer_chacune(correctifs: &[Vec<String>]) -> Vec<bool> {
    let resultats = lancer_chacune(correctifs);
    // Gardé sur cet ordinateur : « Ce que Gardien a changé » (changements.rs).
    crate::changements::noter(correctifs, &resultats);
    resultats
}

fn lancer_chacune(correctifs: &[Vec<String>]) -> Vec<bool> {
    #[cfg(windows)]
    {
        for c in correctifs.iter().flatten() {
            println!("    {GRIS}PS> {}{RESET}", crate::ui::commande_affichable(c));
        }
        trp!(
            "    {GRIS}Une fenêtre administrateur s'ouvre et montre chaque étape ; attends qu'elle se ferme.{RESET}",
            "    {GRIS}An administrator window opens and shows each step; wait for it to close.{RESET}"
        );
        windows::powershell_admin_chacune(correctifs)
    }
    #[cfg(not(windows))]
    {
        correctifs
            .iter()
            .map(|commandes| {
                commandes.iter().all(|c| {
                    println!("    {GRIS}$ {}{RESET}", crate::ui::commande_affichable(c));
                    Command::new("bash")
                        .arg("-c")
                        .arg(c)
                        .status()
                        .is_ok_and(|s| s.success())
                })
            })
            .collect()
    }
}

/// Programme qui écoute sur chaque port TCP de cette machine (port → nom du programme, que chaque programme choisit :
/// prêt à montrer). Sans droits admin, les programmes de root/SYSTEM restent souvent anonymes.
pub fn programmes_en_ecoute() -> std::collections::HashMap<u16, String> {
    let mut map = std::collections::HashMap::new();
    #[cfg(target_os = "linux")]
    for l in sortie("ss", &["-Htlnpe"]).unwrap_or_default().lines() {
        let c: Vec<&str> = l.split_whitespace().collect();
        let port = c
            .get(3)
            .and_then(|a| a.rsplit_once(':'))
            .and_then(|(_, p)| p.parse::<u16>().ok());
        let nom = c
            .get(5)
            .and_then(|u| u.split('"').nth(1))
            .map(affichable)
            .or_else(|| linux::service_du_cgroup(l));
        if let (Some(port), Some(nom)) = (port, nom) {
            map.insert(port, nom);
        }
    }
    // « COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME » … « ControlCe 512 alice 9u IPv4 … TCP *:7000 (LISTEN) ».
    // Sans droits admin, lsof ne montre que les programmes de l'utilisateur.
    #[cfg(target_os = "macos")]
    for l in sortie("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"])
        .unwrap_or_default()
        .lines()
        .skip(1)
    {
        let c: Vec<&str> = l.split_whitespace().collect();
        let port = c
            .iter()
            .rev()
            .find_map(|m| m.rsplit_once(':'))
            .and_then(|(_, p)| p.parse::<u16>().ok());
        if let (Some(port), Some(nom)) = (port, c.first()) {
            // lsof échappe les espaces des noms : « Google\x20Chrome ».
            map.insert(port, affichable(&nom.replace("\\x20", " ")));
        }
    }
    #[cfg(windows)]
    for l in windows::ps("Get-NetTCPConnection -State Listen | ForEach-Object { \"$($_.LocalPort)|$((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName)\" }")
        .unwrap_or_default()
        .lines()
    {
        if let Some((p, nom)) = l.split_once('|')
            && let Ok(port) = p.trim().parse::<u16>()
            && !nom.trim().is_empty()
        {
            map.insert(port, affichable(nom.trim()));
        }
    }
    map
}

/// Ouvre un fichier ou une URL avec l'application par défaut du système.
pub fn ouvrir(cible: &str) {
    #[cfg(target_os = "linux")]
    let _ = Command::new("xdg-open").arg(cible).spawn();
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("cmd").raw_arg(ligne_ouvrir(cible)).spawn();
    }
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg(cible).spawn();
}

/// Ligne de cmd qui ouvre `cible`, toujours entre guillemets : « & », « | » ou « ^ » d'un lien ou d'un dossier
/// (Windows permet « & » dans un nom de compte) y restent du texte. Sans guillemets, cmd coupait la ligne au « & »
/// et lançait la suite comme une commande.
#[cfg(any(windows, test))]
fn ligne_ouvrir(cible: &str) -> String {
    format!("/C start \"\" \"{}\"", cible.replace('"', ""))
}

pub fn auditer(bavard: bool) -> Audit {
    if bavard {
        tre!(
            "{GRAS}Audit de cette machine{RESET} ({})",
            "{GRAS}Audit of this machine{RESET} ({})",
            os::NOM
        );
        tre!(
            "{GRIS}Vérifications en cours (quelques secondes)…{RESET}",
            "{GRIS}Checking (a few seconds)…{RESET}"
        );
    }
    let mut a = os::auditer();
    // Alertes que tu as déclarées normales : au niveau info, sans correction proposée (apprentissage.rs).
    if crate::apprentissage::appliquer(&mut a.constats) > 0 {
        a.score = score(&a.constats);
    }
    // Vérifications impossibles : souvent une version de Windows ou une distribution que le code ne connaît pas.
    // Seulement à la demande : la surveillance horaire répéterait les mêmes lignes.
    if bavard {
        for c in a.constats.iter().filter(|c| !c.verifie) {
            crate::journal::erreur("vérification impossible", &format!("{} : {}", c.categorie, c.message));
        }
    }
    a
}

/// Système, programmes, pilotes et firmware : tout ce qui doit être à jour (`gardien maj`). `seulement` limite
/// les longues recherches à ces catégories, pour revérifier ce qui vient d'être installé.
pub fn mises_a_jour_completes(seulement: Option<&[&str]>) -> Vec<Constat> {
    os::mises_a_jour_completes(seulement)
}

pub fn afficher(a: &Audit) {
    titre(&trf!("Cette machine ({})", "This machine ({})", a.systeme));
    afficher_constats(&a.constats);
    println!();
    if a.fiable() {
        afficher_note(tr!("Note de la machine", "Machine grade"), a.score);
    } else {
        trp!(
            "  Note de la machine : {}aucune{RESET} (pare-feu ou trop de vérifications impossibles à faire ici)",
            "  Machine grade: {}none{RESET} (firewall or too many checks could not be done here)",
            couleur(Niveau::Eleve)
        );
    }
    if a.impossibles() > 0 {
        trp!(
            "  {}⚠ {} vérification(s) impossible(s) : résultat incomplet.{RESET}",
            "  {}⚠ {} check(s) could not be done: incomplete result.{RESET}",
            couleur(Niveau::Moyen),
            a.impossibles()
        );
    }
}

pub fn afficher_constats(constats: &[Constat]) {
    for c in constats {
        let (icone, etiquette) = match c.probleme {
            None => (format!("{VERT}✔{RESET}"), String::new()),
            // Une simple information n'est pas un problème : pas de croix rouge.
            Some(Niveau::Info) => (format!("{}ℹ{RESET}", couleur(Niveau::Info)), String::new()),
            Some(n) => (
                format!("{}✖{RESET}", couleur(n)),
                format!(" {}[{}]{RESET}", couleur(n), n.libelle()),
            ),
        };
        let cat = crate::langue::categorie(c.categorie);
        // Le message commence à la 21e colonne ; sa suite s'y aligne.
        afficher_aligne(
            &format!("  {icone} {GRAS}{cat:<16}{RESET}{etiquette} "),
            &c.message,
            21,
            "",
        );
        if let Some(k) = &c.correctif {
            let marque = if k.automatique {
                trf!("{} correction possible", "{} fix available", cle_a_molette())
            } else {
                trf!("{} à faire", "{} to do", ampoule())
            };
            let texte = trf!("{marque} : {}", "{marque}: {}", k.action);
            afficher_aligne(&format!("  {:18}", ""), &texte, 23, GRIS);
        }
    }
}

pub fn executer(json: bool) -> Audit {
    let a = auditer(!json);
    if json {
        println!("{}", serde_json::to_string_pretty(&a).unwrap_or_default());
    } else {
        afficher(&a);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lien_ouvert_d_un_seul_morceau() {
        assert_eq!(
            ligne_ouvrir(r"C:\Users\A&B\AppData\Local\gardien\rapport.html"),
            r#"/C start "" "C:\Users\A&B\AppData\Local\gardien\rapport.html""#
        );
        assert_eq!(
            ligne_ouvrir("https://exemple.org/page?a=1&b=2|c"),
            r#"/C start "" "https://exemple.org/page?a=1&b=2|c""#
        );
        assert_eq!(ligne_ouvrir(r#"a"b"#), r#"/C start "" "ab""#);
    }

    fn audit(etats: &[(&'static str, Option<Niveau>, &str)]) -> Audit {
        let constats: Vec<Constat> = etats
            .iter()
            .map(|(c, n, m)| Constat {
                verifie: !m.starts_with("Impossible de vérifier"),
                categorie: c,
                probleme: *n,
                message: m.to_string(),
                correctif: None,
            })
            .collect();
        Audit {
            systeme: "test",
            score: score(&constats),
            constats,
        }
    }

    #[cfg(unix)]
    #[test]
    fn phrase_de_passe_des_cles_ssh() {
        // Clés générées pour le test, si ssh-keygen est disponible.
        let dossier = std::env::temp_dir().join(format!("gardien-cles-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let generer = |nom: &str, phrase: &str| {
            std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", phrase, "-f"])
                .arg(dossier.join(nom))
                .status()
                .is_ok_and(|s| s.success())
        };
        if generer("nue", "") && generer("protegee", "phrase de test") {
            let lire = |n: &str| std::fs::read_to_string(dossier.join(n)).unwrap();
            assert_eq!(cle_protegee(&lire("nue")), Some(false));
            assert_eq!(cle_protegee(&lire("protegee")), Some(true));
            assert_eq!(cle_protegee(&lire("nue.pub")), None);
        }
        std::fs::remove_dir_all(&dossier).unwrap();
        assert_eq!(cle_protegee("-----BEGIN ENCRYPTED PRIVATE KEY-----\nxx"), Some(true));
        assert_eq!(
            cle_protegee("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"),
            Some(true)
        );
        assert_eq!(cle_protegee("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n"), Some(false));
        assert_eq!(base64_decoder("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decoder("TQ==").unwrap(), b"M");
    }

    #[test]
    fn pas_de_note_sans_pare_feu_verifie() {
        let inconnu = "Impossible de vérifier (systemd absent).";
        let sans_pare_feu = audit(&[
            ("Pare-feu", Some(Niveau::Info), inconnu),
            ("Mises à jour", None, "Système à jour."),
            ("Chiffrement", None, "Disque chiffré."),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        assert!(!sans_pare_feu.fiable());
        let peu_verifie = audit(&[
            ("Pare-feu", None, "ufw est actif."),
            ("SSH", Some(Niveau::Info), inconnu),
            ("Services", Some(Niveau::Info), inconnu),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        assert!(!peu_verifie.fiable());
        let complet = audit(&[
            ("Pare-feu", None, "ufw est actif."),
            ("SSH", None, "Serveur SSH désactivé."),
            ("Mises à jour", Some(Niveau::Info), inconnu),
            ("Comptes", None, "Seul root a l'UID 0."),
        ]);
        assert!(complet.fiable());
    }

    #[cfg(unix)]
    #[test]
    fn un_correctif_en_echec_n_arrete_pas_les_autres() {
        let temoin = std::env::temp_dir().join(format!("gardien-test-appliquer-{}", std::process::id()));
        let toucher = format!("touch '{}'", temoin.display());
        let r = appliquer_chacune(&[vec!["true".into()], vec!["false".into(), toucher], vec!["true".into()]]);
        assert_eq!(r, [true, false, true]);
        // Dans un même correctif, rien ne part après une commande en échec.
        assert!(!temoin.exists());
    }
}
