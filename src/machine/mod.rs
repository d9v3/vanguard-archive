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

/// Le verrouillage de l'écran d'après son délai en secondes (0 = jamais), avec où l'activer quand il manque.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn verrouillage_selon_delai(secondes: u64, ou_l_activer: &str) -> Constat {
    match secondes {
        0 => alerte(
            "Verrouillage",
            Niveau::Moyen,
            tr!(
                "L'écran ne se verrouille jamais tout seul : un ordinateur laissé ouvert est accessible à tous.",
                "The screen never locks by itself: a computer left open is accessible to anyone."
            ),
        )
        .manuel(ou_l_activer, &[]),
        s if s > 15 * 60 => alerte(
            "Verrouillage",
            Niveau::Info,
            trf!(
                "L'écran se verrouille après {} minutes : 5 à 10 minutes serait plus sûr.",
                "The screen locks after {} minutes: 5 to 10 minutes would be safer.",
                s / 60
            ),
        ),
        s if s >= 60 => ok(
            "Verrouillage",
            trf!(
                "L'écran se verrouille après {} minute(s) d'inactivité.",
                "The screen locks after {} minute(s) of inactivity.",
                s / 60
            ),
        ),
        _ => ok(
            "Verrouillage",
            tr!(
                "L'écran se verrouille après inactivité.",
                "The screen locks after inactivity."
            ),
        ),
    }
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
    if let Ok(config) = std::fs::read_to_string(dossier.join("config")) {
        let mut lignes = Vec::new();
        deplier_config_ssh(
            "~/.ssh/config",
            &config,
            &|motif| fichiers_inclus_ssh(&dossier, motif),
            8,
            &mut lignes,
        );
        constats.extend(constats_config_ssh(&lignes));
    }
    if constats.is_empty() {
        constats.push(ok(
            "Clés SSH",
            tr!("Permissions de ~/.ssh correctes.", "~/.ssh permissions are correct."),
        ));
    }
    constats
}

/// La configuration de SSH avec ses fichiers inclus (« Include ») dépliés à leur place, comme SSH les lit : (fichier
/// à montrer, numéro de ligne, ligne). `lire` rend les fichiers d'un motif d'inclusion ; `profondeur` arrête une
/// inclusion en boucle.
#[cfg(unix)]
fn deplier_config_ssh(
    nom: &str,
    texte: &str,
    lire: &dyn Fn(&str) -> Vec<(String, String)>,
    profondeur: u32,
    sortie: &mut Vec<(String, usize, String)>,
) {
    for (i, ligne) in texte.lines().enumerate() {
        let propre = ligne.split('#').next().unwrap_or_default().trim();
        let (cle, motifs) = propre
            .split_once(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or((propre, ""));
        if cle.eq_ignore_ascii_case("include") && profondeur > 0 {
            for motif in motifs
                .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
                .split_whitespace()
            {
                for (inclus, contenu) in lire(motif.trim_matches('"')) {
                    deplier_config_ssh(&inclus, &contenu, lire, profondeur - 1, sortie);
                }
            }
        } else {
            sortie.push((nom.to_string(), i + 1, ligne.to_string()));
        }
    }
}

/// Les fichiers d'un motif d'inclusion de ~/.ssh/config, triés : relatif à ~/.ssh, ou commençant par « ~/ » ; les
/// jokers « * » et « ? » valent dans le dernier élément du chemin.
#[cfg(unix)]
fn fichiers_inclus_ssh(dossier_ssh: &std::path::Path, motif: &str) -> Vec<(String, String)> {
    let maison = dossier_ssh.parent().unwrap_or(dossier_ssh);
    let chemin = match motif.strip_prefix("~/") {
        Some(reste) => maison.join(reste),
        None => dossier_ssh.join(motif),
    };
    let montrer = |p: &std::path::Path| match p.strip_prefix(maison) {
        Ok(r) => format!("~/{}", r.display()),
        Err(_) => p.display().to_string(),
    };
    let nom = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut trouves: Vec<std::path::PathBuf> = if nom.contains(['*', '?']) {
        let parent = chemin.parent().unwrap_or(dossier_ssh);
        std::fs::read_dir(parent)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| joker(&nom, &e.file_name().to_string_lossy()))
            .map(|e| e.path())
            .collect()
    } else {
        vec![chemin]
    };
    trouves.sort();
    trouves
        .into_iter()
        .filter(|p| p.is_file())
        .filter_map(|p| Some((montrer(&p), std::fs::read_to_string(&p).ok()?)))
        .collect()
}

/// Un nom correspond-il à un motif à jokers (« * » : n'importe quelle suite, « ? » : un caractère) ?
#[cfg(unix)]
fn joker(motif: &str, nom: &str) -> bool {
    let (m, n): (Vec<char>, Vec<char>) = (motif.chars().collect(), nom.chars().collect());
    // Programmation dynamique : possible[j] = le début du motif correspond aux j premiers caractères du nom.
    let mut possible = vec![false; n.len() + 1];
    possible[0] = true;
    for c in m {
        let mut suivant = vec![false; n.len() + 1];
        for j in 0..=n.len() {
            suivant[j] = match c {
                '*' => possible[j] || (j > 0 && suivant[j - 1]),
                '?' => j > 0 && possible[j - 1],
                _ => j > 0 && possible[j - 1] && n[j - 1] == c,
            };
        }
        possible = suivant;
    }
    possible[n.len()]
}

/// Réglages risqués de ~/.ssh/config qui valent pour tous les serveurs (avant le premier « Host », sous « Host * »
/// ou « Match all ») : (numéro de ligne, réglage en minuscules). Un réglage sous un « Host » précis reste : un
/// serveur de test qu'on recrée souvent peut s'en passer.
#[cfg(unix)]
fn reglages_ssh_risques(config: &str) -> Vec<(usize, &'static str)> {
    let mut global = true;
    let mut trouves = Vec::new();
    for (i, ligne) in config.lines().enumerate() {
        let ligne = ligne.split('#').next().unwrap_or_default().trim();
        let (cle, valeur) = ligne
            .split_once(|c: char| c.is_whitespace() || c == '=')
            .map_or((ligne, ""), |(c, v)| {
                (c, v.trim_start_matches(|c: char| c.is_whitespace() || c == '='))
            });
        let cle = cle.to_ascii_lowercase();
        let valeur = valeur.trim().trim_matches('"').to_ascii_lowercase();
        match cle.as_str() {
            "host" => global = valeur.split_whitespace().all(|motif| motif == "*"),
            "match" => global = valeur == "all",
            "stricthostkeychecking" if global && matches!(valeur.as_str(), "no" | "off") => {
                trouves.push((i + 1, "stricthostkeychecking"));
            }
            "forwardagent" if global && valeur == "yes" => trouves.push((i + 1, "forwardagent")),
            _ => {}
        }
    }
    trouves
}

#[cfg(unix)]
fn constats_config_ssh(lignes: &[(String, usize, String)]) -> Vec<Constat> {
    let texte = lignes.iter().map(|(_, _, l)| l.as_str()).collect::<Vec<_>>().join("\n");
    reglages_ssh_risques(&texte)
        .into_iter()
        .filter_map(|(n, reglage)| {
            let (fichier, ligne, _) = lignes.get(n - 1)?;
            let fichier = affichable(fichier);
            Some((fichier, *ligne, reglage))
        })
        .map(|(fichier, ligne, reglage)| {
            let (message, conseil) = if reglage == "stricthostkeychecking" {
                (
                    trf!(
                        "{fichier}, ligne {ligne} : SSH se connecte à n'importe quel serveur sans vérifier qu'il est le bon ; un appareil au milieu peut se faire passer pour lui et lire le mot de passe.",
                        "{fichier}, line {ligne}: SSH connects to any server without checking it is the right one; a device in the middle can pose as it and read the password."
                    ),
                    tr!(
                        "Retirer cette ligne, ou la réserver aux serveurs de test sous leur propre « Host » ; « accept-new » accepte un nouveau serveur mais refuse un serveur qui change",
                        "Remove this line, or keep it for test servers under their own “Host”; “accept-new” accepts a new server but refuses one that changes"
                    ),
                )
            } else {
                (
                    trf!(
                        "{fichier}, ligne {ligne} : ton agent SSH est prêté à tous les serveurs ; un serveur piraté peut s'en servir pour se connecter ailleurs avec tes clés.",
                        "{fichier}, line {ligne}: your SSH agent is lent to every server; a hacked server can use it to log in elsewhere with your keys."
                    ),
                    tr!(
                        "Retirer cette ligne, ou la réserver aux serveurs de confiance sous leur propre « Host » ; « ssh -J » remplace le plus souvent ce prêt",
                        "Remove this line, or keep it for trusted servers under their own “Host”; “ssh -J” usually replaces this lending"
                    ),
                )
            };
            alerte("Clés SSH", Niveau::Moyen, message).manuel(conseil, &[])
        })
        .collect()
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
    // Les noms des programmes lus une fois, pas un Get-Process par port.
    for l in windows::ps("$noms = @{}; Get-Process | ForEach-Object { $noms[$_.Id] = $_.ProcessName }; Get-NetTCPConnection -State Listen | ForEach-Object { \"$($_.LocalPort)|$($noms[[int]$_.OwningProcess])\" }")
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
    fn config_ssh_avec_inclusions() {
        assert!(joker("*.conf", "travail.conf") && joker("c?nfig", "config") && joker("*", ""));
        assert!(!joker("*.conf", "travail.conf.bak") && !joker("c?nfig", "cnfig"));
        // Un Include déplié à sa place ; l'alerte nomme le fichier inclus et sa ligne. Une boucle s'arrête.
        let lire = |motif: &str| -> Vec<(String, String)> {
            match motif {
                "config.d/*" => vec![("~/.ssh/config.d/labo".into(), "# labo\nForwardAgent yes\n".into())],
                "boucle" => vec![("~/.ssh/boucle".into(), "Include boucle\n".into())],
                _ => Vec::new(),
            }
        };
        let mut lignes = Vec::new();
        deplier_config_ssh(
            "~/.ssh/config",
            "Include config.d/*\nInclude boucle\nHost x\n",
            &lire,
            8,
            &mut lignes,
        );
        // Les deux lignes du fichier inclus, « Host x », et l'Include de trop au bout de la boucle (laissé tel quel).
        assert_eq!(lignes.len(), 4);
        let c = constats_config_ssh(&lignes);
        assert!(
            c.len() == 1
                && (c[0].message.contains("~/.ssh/config.d/labo, ligne 2")
                    || c[0].message.contains("~/.ssh/config.d/labo, line 2"))
        );
        // Inclus sous un Host précis : le réglage ne vaut que pour lui.
        let mut lignes = Vec::new();
        deplier_config_ssh(
            "~/.ssh/config",
            "Host labo\n  Include config.d/*\n",
            &lire,
            8,
            &mut lignes,
        );
        assert!(constats_config_ssh(&lignes).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn config_ssh_risquee() {
        let config = "\
# commun
ForwardAgent yes
Host labo labo2
    StrictHostKeyChecking no
Host *
    StrictHostKeyChecking=off # pour aller vite
    ForwardAgent no
Host serveur
    ForwardAgent yes
Match all
  stricthostkeychecking \"no\"
Match host x
  StrictHostKeyChecking no
Host *
  StrictHostKeyChecking accept-new
";
        assert_eq!(
            reglages_ssh_risques(config),
            [
                (2, "forwardagent"),
                (6, "stricthostkeychecking"),
                (11, "stricthostkeychecking")
            ]
        );
        assert_eq!(reglages_ssh_risques("Host *\n  User moi\n"), []);
        let c = constats_config_ssh(&[("~/.ssh/config".into(), 1, "StrictHostKeyChecking no".into())]);
        assert!(c.len() == 1 && c[0].probleme == Some(Niveau::Moyen));
        assert!(c[0].message.contains("ligne 1") || c[0].message.contains("line 1"));
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
