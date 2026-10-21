//! Les agents d'IA de cet ordinateur, en lecture seule. Un agent malveillant ne se reconnaît pas à coup sûr : il
//! utilise les mêmes outils qu'un agent honnête. Ce qui se vérifie, ce sont les portes par lesquelles un agent, honnête
//! mais détourné (injection de prompt dans une page ou un fichier) ou piégé par un outil, ferait des dégâts :
//! - un serveur d'IA local (Ollama, LM Studio, ComfyUI, interfaces Gradio) ouvert au réseau sans mot de passe ;
//! - un agent réglé pour tout faire sans demander (Claude Code : mode « bypassPermissions », toute commande permise) ;
//! - un serveur MCP lancé par `npx`, `uvx`… sans version fixée (la prochaine version publiée, piégée ou non,
//!   s'exécute avec les droits de la personne), joint en HTTP sans chiffrement, ou avec une clé écrite en clair.
//!
//! Les fichiers lus : réglages de Claude Code (~/.claude), de Claude Desktop, de Cursor, de VS Code, de Windsurf et
//! de Gemini CLI, en JSON ou en JSONC (commentaires et virgules finales, que VS Code accepte) ; un fichier présent
//! mais illisible rend l'outil « non vérifié », jamais « aucun agent ». Aucune valeur secrète n'est affichée ni
//! gardée : seulement le nom du serveur et celui de la clé. Rien ne se corrige tout seul.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::ui::{affichable, couper, tr, trf};

const CAT: &str = "Agents d'IA";

/// Les serveurs d'IA locaux connus par leur port d'origine : sans mot de passe, ils doivent rester sur 127.0.0.1.
const PORTS_IA: [(u16, &str); 4] = [
    (11434, "Ollama"),
    (1234, "LM Studio"),
    (8188, "ComfyUI"),
    (7860, "Gradio (Stable Diffusion WebUI, text-generation-webui)"),
];

/// Les programmes d'IA reconnus par leur nom, quel que soit leur port.
const PROGRAMMES_IA: [&str; 5] = ["ollama", "llama-server", "koboldcpp", "comfyui", "lm studio"];

/// Un port en écoute : adresse locale, port, programme (vide s'il est inconnu).
pub(crate) struct Prise {
    pub adresse: String,
    pub port: u16,
    pub programme: String,
}

fn serveur_ia(p: &Prise) -> Option<String> {
    if let Some((_, nom)) = PORTS_IA.iter().find(|(port, _)| *port == p.port) {
        return Some((*nom).to_string());
    }
    let programme = p.programme.to_lowercase();
    PROGRAMMES_IA
        .iter()
        .any(|n| programme.contains(n))
        .then(|| p.programme.clone())
}

fn juger_exposition(prises: &[Prise]) -> Constat {
    let mut ouverts: Vec<String> = prises
        .iter()
        .filter(|p| {
            !p.adresse
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|a| a.is_loopback())
        })
        .filter_map(|p| serveur_ia(p).map(|nom| format!("{nom} ({}:{})", p.adresse, p.port)))
        .collect();
    ouverts.sort();
    ouverts.dedup();
    if ouverts.is_empty() {
        return ok(
            CAT,
            tr!(
                "Aucun serveur d'IA local ouvert au réseau",
                "No local AI server open to the network"
            ),
        );
    }
    let liste = couper(&affichable(&ouverts.join(", ")), 200);
    alerte(
        CAT,
        Niveau::Eleve,
        trf!(
            "Serveur d'IA ouvert au réseau, sans mot de passe : {liste}. N'importe quel appareil du Wi-Fi peut s'en servir (et, selon l'outil, lire ou écrire des fichiers). Fais-le écouter sur 127.0.0.1 seulement (Ollama : OLLAMA_HOST=127.0.0.1).",
            "AI server open to the network, without a password: {liste}. Any device on the Wi-Fi can use it (and, depending on the tool, read or write files). Make it listen on 127.0.0.1 only (Ollama: OLLAMA_HOST=127.0.0.1)."
        ),
    )
}

#[cfg(target_os = "linux")]
fn prises() -> Option<Vec<Prise>> {
    Some(
        super::linux::ecoute::prises_ou_ss()?
            .into_iter()
            .filter(|e| !e.udp)
            .map(|e| Prise {
                adresse: e.adresse.to_string(),
                port: e.port,
                programme: e.nom().unwrap_or_default(),
            })
            .collect(),
    )
}

#[cfg(windows)]
fn prises() -> Option<Vec<Prise>> {
    Some(
        super::windows::ecoute::ecoutes()?
            .into_iter()
            .filter(|e| e.tcp)
            .map(|e| Prise {
                adresse: e.adresse,
                port: e.port,
                programme: e.nom,
            })
            .collect(),
    )
}

#[cfg(not(any(target_os = "linux", windows)))]
fn prises() -> Option<Vec<Prise>> {
    None
}

pub(crate) fn exposition() -> Vec<Constat> {
    match prises() {
        Some(p) => vec![juger_exposition(&p)],
        None => vec![impossible(
            CAT,
            tr!(
                "serveurs d'IA ouverts au réseau : ports en écoute illisibles ici",
                "AI servers open to the network: listening ports unreadable here"
            ),
        )],
    }
}

// --------------------------------------------------------------------------------------------- réglages des agents

/// Ce qu'un fichier de réglages apprend : (outil, problème trouvé).
#[derive(Default)]
struct Trouvailles {
    tout_permis: Vec<String>,
    commandes_permises: Vec<String>,
    non_epingles: Vec<String>,
    sans_chiffrement: Vec<String>,
    cles_en_clair: Vec<String>,
    serveurs: usize,
}

/// Les options d'un lanceur suivies d'une valeur (« --python 3.12 ») : sautées avec elle, pour que la valeur ne passe
/// pas pour le paquet. Le second groupe nomme le paquet lui-même (« uvx --from paquet==1.0 commande », « npx -p paquet
/// commande ») : c'est lui qui est jugé, et non la commande qui suit.
const OPTIONS_PYTHON: [&str; 5] = ["--python", "-p", "--with", "--index-url", "--pip-args"];
const PAQUET_PYTHON: [&str; 2] = ["--from", "--spec"];
const PAQUET_JS: [&str; 2] = ["--package", "-p"];

/// Le paquet lancé par un lanceur (`npx`, `bunx`, `pnpm dlx`, `uvx`, `pipx run`), s'il n'a pas de version fixée.
/// « cmd /c npx -y paquet », la forme de Claude Desktop sous Windows, est jugée comme « npx -y paquet ».
fn paquet_non_epingle(commande: &str, args: &[&str]) -> Option<String> {
    let lanceur = Path::new(commande)
        .file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if lanceur == "cmd" {
        // cmd relit la ligne qui suit /c (ou /k) : un mot peut en porter plusieurs.
        let i = args
            .iter()
            .position(|a| a.eq_ignore_ascii_case("/c") || a.eq_ignore_ascii_case("/k"))?;
        let mots: Vec<&str> = args[i + 1..].iter().flat_map(|a| a.split_whitespace()).collect();
        let (commande, reste) = mots.split_first()?;
        return paquet_non_epingle(commande, reste);
    }
    let mut reste = args.iter().copied();
    match lanceur.as_str() {
        "npx" | "bunx" | "uvx" => {}
        "pnpm" | "yarn" => {
            reste.find(|a| *a == "dlx")?;
        }
        "pipx" => {
            reste.find(|a| *a == "run")?;
        }
        _ => return None,
    }
    let pyth = lanceur == "uvx" || lanceur == "pipx";
    let (avec_valeur, nomment): (&[&str], &[&str]) = if pyth {
        (&OPTIONS_PYTHON, &PAQUET_PYTHON)
    } else {
        (&[], &PAQUET_JS)
    };
    let mut nommes = Vec::new();
    let mut premier = None;
    while let Some(a) = reste.next() {
        let (option, valeur) = match a.split_once('=') {
            Some((o, v)) if a.starts_with('-') => (o, Some(v)),
            _ => (a, None),
        };
        if nomment.contains(&option) {
            nommes.extend(valeur.or_else(|| reste.next()));
        } else if avec_valeur.contains(&option) {
            if valeur.is_none() {
                reste.next();
            }
        } else if premier.is_none() && !a.is_empty() && !a.starts_with('-') {
            premier = Some(a);
        }
    }
    let candidats = if nommes.is_empty() {
        Vec::from_iter(premier)
    } else {
        nommes
    };
    let non_epingle = |paquet: &&str| {
        let epingle = if pyth {
            paquet.contains("==") || paquet.contains('@')
        } else {
            // « @portee/nom@1.2.3 » ou « nom@1.2.3 » : le @ de la version vient après le premier caractère.
            paquet.chars().skip(1).any(|c| c == '@')
        };
        let flottant = paquet.ends_with("@latest") || paquet.ends_with("@next");
        !epingle || flottant
    };
    candidats.into_iter().find(non_epingle).map(str::to_string)
}

/// Les mots d'un nom qui désignent un secret, comparés entiers : « TOKENIZERS » n'est pas « TOKEN », ni « MONKEY »
/// « KEY ».
const MOTS_SECRETS: [&str; 14] = [
    "KEY",
    "KEYS",
    "APIKEY",
    "TOKEN",
    "TOKENS",
    "SECRET",
    "SECRETS",
    "PASSWORD",
    "PASSWORDS",
    "PASSWD",
    "PASSPHRASE",
    "CREDENTIAL",
    "CREDENTIALS",
    "AUTHORIZATION",
];

/// Le dernier mot d'un nom qui dit où est le secret, ou comment il s'appelle, et non le secret lui-même :
/// PASSWORD_STORE_DIR, API_KEY_FILE, TOKEN_URL, AWS_ACCESS_KEY_ID.
const MOTS_HORS_SECRET: [&str; 14] = [
    "DIR",
    "DIRECTORY",
    "PATH",
    "FILE",
    "STORE",
    "URL",
    "URI",
    "HOST",
    "PORT",
    "ENDPOINT",
    "ID",
    "NAME",
    "TYPE",
    "HEADER",
];

/// Les mots d'un nom, en majuscules : coupé aux « _ », « - » et « . », et entre une minuscule et une majuscule
/// (« apiKey », « accessToken »).
fn mots(nom: &str) -> Vec<String> {
    let mut mots = Vec::new();
    let mut mot = String::new();
    let mut apres_minuscule = false;
    for c in nom.chars() {
        let separateur = matches!(c, '_' | '-' | '.');
        if (separateur || (apres_minuscule && c.is_uppercase())) && !mot.is_empty() {
            mots.push(std::mem::take(&mut mot));
        }
        if !separateur {
            mot.extend(c.to_uppercase());
        }
        apres_minuscule = c.is_lowercase();
    }
    if !mot.is_empty() {
        mots.push(mot);
    }
    mots
}

fn ressemble_a_un_secret(nom: &str) -> bool {
    let mots = mots(nom);
    mots.iter().any(|m| MOTS_SECRETS.contains(&m.as_str()))
        && mots.last().is_some_and(|m| !MOTS_HORS_SECRET.contains(&m.as_str()))
}

/// Les schémas d'authentification écrits devant le secret dans un en-tête (« Bearer jeton », « Basic base64 »).
const SCHEMAS: [&str; 3] = ["Bearer", "Basic", "Token"];

/// Une valeur écrite en clair, et non une référence à un secret gardé ailleurs : variable (« ${VAR} », « $VAR »,
/// « ${env:VAR} », « env:VAR »), invite de VS Code (« ${input:jeton} »), y compris derrière un schéma
/// d'authentification (« Bearer ${API_KEY} », « Basic ${IDENTIFIANTS} »).
fn en_clair(valeur: &Value) -> bool {
    let Some(v) = valeur.as_str().map(str::trim) else {
        return false;
    };
    let v = match v.split_once(char::is_whitespace) {
        Some((schema, reste)) if SCHEMAS.iter().any(|s| s.eq_ignore_ascii_case(schema)) => reste.trim(),
        _ => v,
    };
    !v.is_empty() && !v.starts_with('$') && !v.starts_with("env:") && !v.starts_with("{env:")
}

fn lire_serveurs(outil: &str, serveurs: &serde_json::Map<String, Value>, t: &mut Trouvailles) {
    for (nom, s) in serveurs {
        t.serveurs += 1;
        let qui = format!("{outil} › {nom}");
        if let Some(commande) = s.get("command").and_then(Value::as_str) {
            let args: Vec<&str> = s
                .get("args")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if let Some(paquet) = paquet_non_epingle(commande, &args) {
                t.non_epingles.push(format!("{qui} ({paquet})"));
            }
        }
        for champ in ["url", "serverUrl", "httpUrl"] {
            if let Some(url) = s.get(champ).and_then(Value::as_str)
                && let Some(reste) = url.trim().strip_prefix("http://")
            {
                let hote = match reste.strip_prefix('[') {
                    Some(v6) => v6.split(']').next().unwrap_or_default(),
                    None => reste.split(['/', ':']).next().unwrap_or_default(),
                };
                let local = hote == "localhost" || hote.parse::<IpAddr>().is_ok_and(|a| a.is_loopback());
                if !local {
                    t.sans_chiffrement.push(qui.clone());
                }
            }
        }
        for champ in ["env", "headers"] {
            if let Some(valeurs) = s.get(champ).and_then(Value::as_object) {
                for (cle, v) in valeurs {
                    if ressemble_a_un_secret(cle) && en_clair(v) {
                        t.cles_en_clair.push(format!("{qui} ({cle})"));
                    }
                }
            }
        }
    }
}

/// Les permissions de Claude Code : le mode par défaut et la liste des outils permis sans demander.
fn lire_permissions(outil: &str, permissions: &Value, t: &mut Trouvailles) {
    if permissions.get("defaultMode").and_then(Value::as_str) == Some("bypassPermissions") {
        t.tout_permis.push(outil.to_string());
    }
    let permis = permissions
        .get("allow")
        .or_else(|| permissions.get("allowedTools"))
        .and_then(Value::as_array);
    if permis.is_some_and(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .any(|p| matches!(p.trim(), "Bash" | "Bash(*)" | "Bash(:*)" | "Bash(**)"))
    }) {
        t.commandes_permises.push(outil.to_string());
    }
}

/// Ce que dit un fichier de réglages d'un outil, quelle que soit sa forme : serveurs MCP (« mcpServers », « servers »,
/// « mcp.servers »), permissions de Claude Code, et pour ~/.claude.json, les mêmes par projet.
fn lire_reglages(outil: &str, json: &Value, t: &mut Trouvailles) {
    for serveurs in [
        json.get("mcpServers"),
        json.get("servers"),
        json.get("mcp").and_then(|m| m.get("servers")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_object)
    {
        lire_serveurs(outil, serveurs, t);
    }
    if let Some(p) = json.get("permissions") {
        lire_permissions(outil, p, t);
    }
    if let Some(projets) = json.get("projects").and_then(Value::as_object) {
        for (chemin, projet) in projets {
            let nom = Path::new(chemin)
                .file_name()
                .map_or_else(|| chemin.clone(), |n| n.to_string_lossy().into_owned());
            let ici = format!("{outil} ({nom})");
            if let Some(serveurs) = projet.get("mcpServers").and_then(Value::as_object) {
                lire_serveurs(&ici, serveurs, t);
            }
            lire_permissions(&ici, projet, t);
        }
    }
}

/// `fichiers` : les fichiers lus ; `illisibles` : les outils dont le fichier est là mais n'a pas pu être lu, avec la
/// raison (« Cursor (JSON invalide) »).
fn juger_reglages(t: &Trouvailles, fichiers: usize, illisibles: &[String]) -> Vec<Constat> {
    let liste = |v: &[String]| couper(&affichable(&v.join(", ")), 200);
    let mut constats = Vec::new();
    if !t.tout_permis.is_empty() {
        let l = liste(&t.tout_permis);
        constats.push(alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "Agent d'IA réglé pour tout faire sans demander (bypassPermissions) : {l}. Une page ou un fichier piégé qu'il lit peut lui faire lancer n'importe quelle commande. Remets les demandes de permission (defaultMode « default » ou « acceptEdits »).",
                "AI agent set to do everything without asking (bypassPermissions): {l}. A booby-trapped page or file it reads can make it run any command. Turn permission prompts back on (defaultMode “default” or “acceptEdits”)."
            ),
        ));
    }
    if !t.commandes_permises.is_empty() {
        let l = liste(&t.commandes_permises);
        constats.push(alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Agent d'IA autorisé à lancer toute commande sans demander (Bash) : {l}. Ne permets que des commandes précises (par exemple « Bash(git status) »).",
                "AI agent allowed to run any command without asking (Bash): {l}. Only allow precise commands (for example “Bash(git status)”)."
            ),
        ));
    }
    if !t.non_epingles.is_empty() {
        let l = liste(&t.non_epingles);
        constats.push(alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Serveur MCP lancé sans version fixée : {l}. Chaque lancement prend la dernière version publiée ; si elle est piégée, elle s'exécute avec tes droits. Fixe la version (« paquet@1.2.3 »).",
                "MCP server started without a pinned version: {l}. Each start takes the latest published version; if it is booby-trapped, it runs with your rights. Pin the version (“package@1.2.3”)."
            ),
        ));
    }
    if !t.sans_chiffrement.is_empty() {
        let l = liste(&t.sans_chiffrement);
        constats.push(alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Serveur MCP joint sans chiffrement (http://) : {l}. Sur le réseau, ses réponses peuvent être lues ou changées, et un agent obéit à ce qu'il reçoit. Utilise https.",
                "MCP server reached without encryption (http://): {l}. On the network its answers can be read or changed, and an agent obeys what it receives. Use https."
            ),
        ));
    }
    if !t.cles_en_clair.is_empty() {
        let l = liste(&t.cles_en_clair);
        constats.push(alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Clé ou jeton écrit en clair dans les réglages d'un serveur MCP : {l}. Tout programme de ton compte peut le lire. Passe-le par une variable d'environnement (« ${{NOM}} ») ou le trousseau.",
                "Key or token written in clear text in an MCP server's settings: {l}. Any program of your account can read it. Pass it through an environment variable (“${{NAME}}”) or the keychain."
            ),
        ));
    }
    if constats.is_empty() {
        let n = t.serveurs;
        if fichiers > 0 {
            constats.push(ok(
                CAT,
                trf!(
                    "Agents d'IA : {fichiers} fichier(s) de réglages, {n} serveur(s) MCP, rien de risqué",
                    "AI agents: {fichiers} settings file(s), {n} MCP server(s), nothing risky"
                ),
            ));
        } else if illisibles.is_empty() {
            constats.push(ok(CAT, tr!("Aucun agent d'IA configuré", "No AI agent configured")));
        }
    }
    if !illisibles.is_empty() {
        let l = liste(illisibles);
        constats.push(impossible(
            CAT,
            &trf!(
                "réglages d'agents d'IA présents mais illisibles : {l}",
                "AI agent settings present but unreadable: {l}"
            ),
        ));
    }
    constats
}

/// Les fichiers de réglages connus : (outil, chemin).
fn fichiers_de_reglages() -> Vec<(&'static str, PathBuf)> {
    let maison =
        PathBuf::from(std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).unwrap_or_default());
    if maison.as_os_str().is_empty() {
        return Vec::new();
    }
    let config = if cfg!(windows) {
        PathBuf::from(std::env::var_os("APPDATA").unwrap_or_default())
    } else if cfg!(target_os = "macos") {
        maison.join("Library/Application Support")
    } else {
        std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from)
    };
    vec![
        ("Claude Code", maison.join(".claude/settings.json")),
        ("Claude Code", maison.join(".claude/settings.local.json")),
        ("Claude Code", maison.join(".claude.json")),
        ("Claude Desktop", config.join("Claude/claude_desktop_config.json")),
        ("Cursor", maison.join(".cursor/mcp.json")),
        ("VS Code", config.join("Code/User/mcp.json")),
        ("Windsurf", maison.join(".codeium/windsurf/mcp_config.json")),
        ("Gemini CLI", maison.join(".gemini/settings.json")),
    ]
}

/// Au-delà, ce n'est pas un fichier de réglages (~/.claude.json grossit avec l'historique des projets) : il n'est
/// pas lu, et l'outil est dit non vérifié.
const REGLAGES_MAX: u64 = 64 << 20;

/// Le JSONC des réglages de VS Code (que Cursor et Windsurf reprennent) ramené au JSON : commentaires « // » et
/// « /* */ », et virgules finales, retirés hors des chaînes. Un commentaire devient une espace, ses fins de ligne
/// restent : deux mots qu'il séparait le restent.
fn json_sans_jsonc(texte: &str) -> String {
    let mut json = String::with_capacity(texte.len());
    let mut car = texte.chars().peekable();
    // Une virgule pas encore suivie d'autre chose que des blancs ou des commentaires : finale si « } » ou « ] » vient.
    let mut virgule: Option<usize> = None;
    while let Some(c) = car.next() {
        match c {
            '"' => {
                virgule = None;
                json.push(c);
                while let Some(c) = car.next() {
                    json.push(c);
                    match c {
                        '\\' => json.extend(car.next()),
                        '"' => break,
                        _ => {}
                    }
                }
            }
            '/' if car.peek() == Some(&'/') => {
                for c in car.by_ref() {
                    if c == '\n' {
                        json.push(c);
                        break;
                    }
                }
            }
            '/' if car.peek() == Some(&'*') => {
                car.next();
                let mut etoile = false;
                for c in car.by_ref() {
                    if c == '\n' {
                        json.push(c);
                    }
                    if etoile && c == '/' {
                        break;
                    }
                    etoile = c == '*';
                }
                json.push(' ');
            }
            '}' | ']' => {
                if let Some(i) = virgule.take() {
                    json.replace_range(i..=i, " ");
                }
                json.push(c);
            }
            ',' => {
                virgule = Some(json.len());
                json.push(c);
            }
            _ => {
                if !c.is_whitespace() {
                    virgule = None;
                }
                json.push(c);
            }
        }
    }
    json
}

/// Un fichier de réglages lu en JSON, ou à défaut en JSONC ; `None` s'il n'est ni l'un ni l'autre.
fn lire_json(octets: &[u8]) -> Option<Value> {
    if let Ok(json) = serde_json::from_slice(octets) {
        return Some(json);
    }
    let texte = std::str::from_utf8(octets).ok()?;
    serde_json::from_str(&json_sans_jsonc(texte.trim_start_matches('\u{feff}'))).ok()
}

/// Les réglages d'un fichier : `Ok(None)` s'il n'existe pas (l'outil n'est pas installé), `Err` avec la raison s'il
/// est là mais ne se lit pas (droits, trop gros, ni JSON ni JSONC).
fn lire_fichier(chemin: &Path) -> Result<Option<Value>, String> {
    use std::io::ErrorKind::NotFound;
    let illisible = || tr!("illisible", "unreadable").to_string();
    let taille = match std::fs::metadata(chemin) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == NotFound => return Ok(None),
        Err(_) => return Err(illisible()),
    };
    if taille > REGLAGES_MAX {
        return Err(trf!("plus de {} Mio", "over {} MiB", REGLAGES_MAX >> 20));
    }
    let octets = match std::fs::read(chemin) {
        Ok(o) => o,
        Err(e) if e.kind() == NotFound => return Ok(None),
        Err(_) => return Err(illisible()),
    };
    lire_json(&octets)
        .map(Some)
        .ok_or_else(|| tr!("JSON invalide", "invalid JSON").to_string())
}

pub(crate) fn reglages() -> Vec<Constat> {
    let mut t = Trouvailles::default();
    let mut lus = 0;
    let mut illisibles = Vec::new();
    for (outil, chemin) in fichiers_de_reglages() {
        match lire_fichier(&chemin) {
            Ok(None) => {}
            Ok(Some(json)) => {
                lus += 1;
                lire_reglages(outil, &json, &mut t);
            }
            Err(raison) => illisibles.push(format!("{outil} ({raison})")),
        }
    }
    juger_reglages(&t, lus, &illisibles)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prise(adresse: &str, port: u16, programme: &str) -> Prise {
        Prise {
            adresse: adresse.into(),
            port,
            programme: programme.into(),
        }
    }

    #[test]
    fn serveurs_d_ia_exposes() {
        let locaux = [
            prise("127.0.0.1", 11434, "ollama"),
            prise("::1", 1234, ""),
            prise("0.0.0.0", 22, "sshd"),
        ];
        assert!(juger_exposition(&locaux).probleme.is_none());
        let ouvert = [prise("0.0.0.0", 11434, "ollama"), prise("[::]", 8188, "python3")];
        let c = juger_exposition(&ouvert);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("Ollama (0.0.0.0:11434)") && c.message.contains("ComfyUI"));
        // Reconnu par son nom, sur un autre port.
        assert!(
            juger_exposition(&[prise("192.168.1.20", 9000, "llama-server")])
                .probleme
                .is_some()
        );
    }

    #[test]
    fn paquets_epingles_ou_non() {
        assert_eq!(
            paquet_non_epingle("npx", &["-y", "@outils/serveur-mcp"]),
            Some("@outils/serveur-mcp".into())
        );
        assert_eq!(paquet_non_epingle("npx", &["-y", "@outils/serveur-mcp@1.4.2"]), None);
        assert_eq!(
            paquet_non_epingle("npx", &["serveur@latest"]),
            Some("serveur@latest".into())
        );
        assert_eq!(paquet_non_epingle("/usr/bin/npx", &["serveur@2.0.0"]), None);
        assert_eq!(paquet_non_epingle("uvx", &["mcp-serveur"]), Some("mcp-serveur".into()));
        assert_eq!(paquet_non_epingle("uvx", &["mcp-serveur==0.3.1"]), None);
        assert_eq!(paquet_non_epingle("pnpm", &["dlx", "outil"]), Some("outil".into()));
        assert_eq!(paquet_non_epingle("node", &["serveur.js"]), None);
        assert_eq!(paquet_non_epingle("npx.cmd", &["-y", "outil"]), Some("outil".into()));
    }

    /// Une option suivie de sa valeur n'est pas le paquet ; une option qui nomme le paquet le donne à juger.
    #[test]
    fn options_avant_le_paquet() {
        assert_eq!(paquet_non_epingle("uvx", &["--python", "3.12", "paquet==1.0"]), None);
        assert_eq!(
            paquet_non_epingle("uvx", &["--python", "3.12", "paquet"]),
            Some("paquet".into())
        );
        assert_eq!(
            paquet_non_epingle("uvx", &["-p", "3.12", "--with", "outil-b", "paquet==2.1"]),
            None
        );
        assert_eq!(paquet_non_epingle("uvx", &["--python=3.12", "paquet==1.0"]), None);
        assert_eq!(
            paquet_non_epingle("uvx", &["--index-url", "https://depot.exemple/simple", "paquet"]),
            Some("paquet".into())
        );
        // « --from » nomme le paquet ; ce qui suit est la commande qu'il fournit.
        assert_eq!(
            paquet_non_epingle("uvx", &["--from", "serveur-git==0.6.2", "serveur-git"]),
            None
        );
        assert_eq!(
            paquet_non_epingle("uvx", &["--from", "serveur-git", "serveur-git"]),
            Some("serveur-git".into())
        );
        assert_eq!(
            paquet_non_epingle("uvx", &["--from=serveur-git==0.6.2", "serveur-git"]),
            None
        );
        assert_eq!(
            paquet_non_epingle("pipx", &["run", "--python", "3.11", "outil==3.0"]),
            None
        );
        assert_eq!(
            paquet_non_epingle("pipx", &["run", "--spec", "outil==3.0", "outil"]),
            None
        );
        assert_eq!(paquet_non_epingle("npx", &["-p", "@exemple/cli@1.2.0", "cli"]), None);
        assert_eq!(
            paquet_non_epingle("npx", &["--package", "@exemple/cli", "cli"]),
            Some("@exemple/cli".into())
        );
        assert_eq!(
            paquet_non_epingle("npx", &["--package=@exemple/cli@1.2.0", "cli"]),
            None
        );
        assert_eq!(
            paquet_non_epingle("npx", &["-y", "-p", "a@1.0.0", "-p", "b", "cli"]),
            Some("b".into())
        );
    }

    /// « cmd /c npx -y paquet » (Claude Desktop sous Windows) se juge comme « npx -y paquet ».
    #[test]
    fn cmd_avant_le_lanceur() {
        assert_eq!(
            paquet_non_epingle("cmd", &["/c", "npx", "-y", "@exemple/fichiers"]),
            Some("@exemple/fichiers".into())
        );
        assert_eq!(
            paquet_non_epingle("cmd.exe", &["/C", "npx", "-y", "@exemple/fichiers@1.4.2"]),
            None
        );
        assert_eq!(
            paquet_non_epingle("CMD.EXE", &["/s", "/k", "uvx", "--python", "3.12", "outil"]),
            Some("outil".into())
        );
        // cmd relit la ligne : un seul mot peut porter la commande entière.
        assert_eq!(
            paquet_non_epingle("cmd", &["/c", "npx -y @exemple/fichiers"]),
            Some("@exemple/fichiers".into())
        );
        assert_eq!(paquet_non_epingle("cmd", &["/c", "node", "serveur.js"]), None);
        assert_eq!(paquet_non_epingle("cmd", &["/c"]), None);
        assert_eq!(paquet_non_epingle("cmd", &["npx", "-y", "outil"]), None);
        let json: Value = serde_json::from_str(
            r#"{ "mcpServers": { "fichiers": { "command": "cmd", "args": ["/c", "npx", "-y", "@exemple/fichiers", "C:\\Users\\alice"] } } }"#,
        )
        .unwrap();
        let mut t = Trouvailles::default();
        lire_reglages("Claude Desktop", &json, &mut t);
        assert_eq!(t.non_epingles, ["Claude Desktop › fichiers (@exemple/fichiers)"]);
    }

    #[test]
    fn reglages_risques() {
        let json: Value = serde_json::from_str(
            r#"{
              "permissions": { "defaultMode": "bypassPermissions", "allow": ["Bash", "Read"] },
              "mcpServers": {
                "fichiers": { "command": "npx", "args": ["-y", "@exemple/fichiers"], "env": { "API_KEY": "abc123", "CHEMIN": "/tmp" } },
                "distant": { "type": "http", "url": "http://serveur.exemple:8000/mcp", "headers": { "Authorization": "${JETON}" } },
                "local": { "url": "http://localhost:3000/mcp" },
                "sur": { "command": "npx", "args": ["@exemple/sur@1.0.0"], "env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" } }
              },
              "projects": { "/home/alice/projet": { "allowedTools": ["Bash(*)"], "mcpServers": {} } }
            }"#,
        )
        .unwrap();
        let mut t = Trouvailles::default();
        lire_reglages("Claude Code", &json, &mut t);
        assert_eq!(t.serveurs, 4);
        assert_eq!(t.tout_permis, ["Claude Code"]);
        assert_eq!(t.commandes_permises, ["Claude Code", "Claude Code (projet)"]);
        assert_eq!(t.non_epingles, ["Claude Code › fichiers (@exemple/fichiers)"]);
        assert_eq!(t.sans_chiffrement, ["Claude Code › distant"]);
        let mut v6 = Trouvailles::default();
        let json6: Value = serde_json::from_str(
            r#"{ "mcpServers": { "a": { "url": "http://[::1]:3000/mcp" }, "b": { "url": "http://[2001:db8::5]/mcp" } } }"#,
        )
        .unwrap();
        lire_reglages("Cursor", &json6, &mut v6);
        assert_eq!(v6.sans_chiffrement, ["Cursor › b"]);
        assert_eq!(t.cles_en_clair, ["Claude Code › fichiers (API_KEY)"]);
        let c = juger_reglages(&t, 1, &[]);
        assert_eq!(c.len(), 5);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        // Aucune valeur secrète dans les messages.
        assert!(c.iter().all(|c| !c.message.contains("abc123")));
    }

    #[test]
    fn reglages_sains_ou_absents() {
        let json: Value = serde_json::from_str(
            r#"{ "servers": { "doc": { "command": "uvx", "args": ["doc-mcp==1.2.0"] } }, "permissions": { "allow": ["Bash(git status)"] } }"#,
        )
        .unwrap();
        let mut t = Trouvailles::default();
        lire_reglages("VS Code", &json, &mut t);
        let c = juger_reglages(&t, 1, &[]);
        assert!(c.len() == 1 && c[0].probleme.is_none() && c[0].message.contains("1 serveur"));
        assert!(
            juger_reglages(&Trouvailles::default(), 0, &[])[0]
                .message
                .contains("Aucun agent")
        );
    }

    /// Un fichier présent mais illisible n'est jamais « aucun agent » : l'outil est dit non vérifié, à côté de ce
    /// qui a pu être lu.
    #[test]
    fn reglages_illisibles_non_verifies() {
        let illisible = ["VS Code (JSON invalide)".to_string()];
        let c = juger_reglages(&Trouvailles::default(), 0, &illisible);
        assert_eq!(c.len(), 1);
        assert!(!c[0].verifie && c[0].message.contains("VS Code (JSON invalide)"));
        assert!(c.iter().all(|c| !c.message.contains("Aucun agent")));
        let t = Trouvailles {
            serveurs: 2,
            ..Trouvailles::default()
        };
        let c = juger_reglages(&t, 1, &illisible);
        assert_eq!(c.len(), 2);
        assert!(c[0].verifie && c[0].message.contains("2 serveur"));
        assert!(!c[1].verifie);
    }

    /// Le JSONC de VS Code : commentaires et virgules finales retirés, jamais dans une chaîne.
    #[test]
    fn jsonc_de_vs_code() {
        let jsonc = r#"{
          // Serveurs de l'équipe
          "servers": {
            /* documentation */ "doc": { "command": "npx", "args": ["-y", "doc-mcp",], },
            "web": { "url": "http://exemple.test/a//b/*c*/", "headers": { "Authorization": "Bearer jeton-essai" } },
          },
        }"#;
        let json = lire_json(jsonc.as_bytes()).expect("JSONC lisible");
        assert_eq!(json["servers"]["doc"]["args"], serde_json::json!(["-y", "doc-mcp"]));
        // Les « // » et « /* */ » d'une chaîne y restent.
        assert_eq!(json["servers"]["web"]["url"], "http://exemple.test/a//b/*c*/");
        let mut t = Trouvailles::default();
        lire_reglages("VS Code", &json, &mut t);
        assert_eq!(t.serveurs, 2);
        assert_eq!(t.non_epingles, ["VS Code › doc (doc-mcp)"]);
        assert_eq!(t.cles_en_clair, ["VS Code › web (Authorization)"]);
        // Une virgule dans une chaîne, un guillemet échappé, un commentaire collé : rien de changé à tort.
        let json = lire_json(br#"{"a": "x, }", "b": "y\"//z", /**/"c": [1,/* , */2,]}"#).unwrap();
        assert_eq!(json, serde_json::json!({"a": "x, }", "b": "y\"//z", "c": [1, 2]}));
        // Le BOM d'un éditeur de Windows, puis du JSON ordinaire, lu tel quel.
        assert!(lire_json("\u{feff}{\"a\": 1, // b\n}".as_bytes()).is_some());
        assert_eq!(lire_json(br#"{"a": [1, 2]}"#), Some(serde_json::json!({"a": [1, 2]})));
        // Ni JSON ni JSONC : refusé.
        for mauvais in [
            &b"{\"a\": 1"[..],
            b"{\"a\": /* sans fin",
            b"\xff\xfe{}",
            b"servers = 1",
            b"",
        ] {
            assert!(lire_json(mauvais).is_none(), "{mauvais:?}");
        }
    }

    /// Absent : rien à dire ; présent mais illisible, trop gros ou invalide : la raison.
    #[test]
    fn fichiers_absents_ou_illisibles() {
        let dossier = std::env::temp_dir().join(format!("vanguard-agents-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        assert_eq!(lire_fichier(&dossier.join("absent.json")), Ok(None));
        let bon = dossier.join("mcp.json");
        std::fs::write(&bon, "{ \"servers\": {}, // VS Code\n }").unwrap();
        assert_eq!(lire_fichier(&bon), Ok(Some(serde_json::json!({"servers": {}}))));
        let casse = dossier.join("casse.json");
        std::fs::write(&casse, "{ \"servers\": ").unwrap();
        assert!(lire_fichier(&casse).is_err());
        let gros = dossier.join("gros.json");
        std::fs::File::create(&gros).unwrap().set_len(REGLAGES_MAX + 1).unwrap();
        assert!(lire_fichier(&gros).unwrap_err().contains("64"));
        // Un dossier à la place du fichier : là, mais illisible.
        let dossier_a_la_place = dossier.join("settings.json");
        std::fs::create_dir_all(&dossier_a_la_place).unwrap();
        assert!(lire_fichier(&dossier_a_la_place).is_err());
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// Une référence reste une référence derrière « Bearer » ou « Basic » ; des noms qui contiennent « TOKEN » ou
    /// « PASSWORD » sans désigner un secret ne sont pas des clés.
    #[test]
    fn cles_en_clair_ou_references() {
        let json: Value = serde_json::from_str(
            r#"{ "mcpServers": {
              "a": { "url": "https://a.exemple/mcp", "headers": { "Authorization": "Bearer ${API_KEY}" } },
              "b": { "url": "https://b.exemple/mcp", "headers": { "Authorization": "bearer ${input:jeton}", "X-Api-Key": "${input:cle}" } },
              "c": { "url": "https://c.exemple/mcp", "headers": { "Authorization": "Basic ${IDENTIFIANTS}" } },
              "d": { "command": "uvx", "args": ["d==1.0"], "env": { "TOKENIZERS_PARALLELISM": "false", "PASSWORD_STORE_DIR": "/home/alice/.password-store", "API_KEY_FILE": "/home/alice/cle" } },
              "e": { "url": "https://e.exemple/mcp", "headers": { "Authorization": "Bearer sk-essai-123" } },
              "f": { "url": "https://f.exemple/mcp", "headers": { "Authorization": "Basic YWxpY2U6c2Fsb24=" } },
              "g": { "command": "uvx", "args": ["g==1.0"], "env": { "apiKey": "essai", "CLIENT_SECRET": "essai" } }
            } }"#,
        )
        .unwrap();
        let mut t = Trouvailles::default();
        lire_reglages("Cursor", &json, &mut t);
        assert_eq!(
            t.cles_en_clair,
            [
                "Cursor › e (Authorization)",
                "Cursor › f (Authorization)",
                "Cursor › g (apiKey)",
                "Cursor › g (CLIENT_SECRET)"
            ]
        );
    }

    #[test]
    fn noms_de_secrets() {
        for secret in [
            "API_KEY",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "CLIENT_SECRET",
            "DB_PASSWORD",
            "Authorization",
            "X-Api-Key",
            "x-goog-api-key",
            "apiKey",
            "accessToken",
            "AWS_SECRET_ACCESS_KEY",
            "SECRET_KEY_BASE",
            "api.key",
            "APIKEY",
            "SMTP_PASSWD",
            "GOOGLE_CREDENTIALS",
        ] {
            assert!(ressemble_a_un_secret(secret), "{secret}");
        }
        for ordinaire in [
            "TOKENIZERS_PARALLELISM",
            "PASSWORD_STORE_DIR",
            "KEYBOARD_LAYOUT",
            "MONKEY",
            "CHEMIN",
            "AWS_ACCESS_KEY_ID",
            "API_KEY_FILE",
            "TOKEN_URL",
            "SECRETARY",
            "KEYCLOAK_URL",
            "",
        ] {
            assert!(!ressemble_a_un_secret(ordinaire), "{ordinaire}");
        }
        assert_eq!(mots("x-goog-api.KEY_id"), ["X", "GOOG", "API", "KEY", "ID"]);
        assert_eq!(mots("accessToken"), ["ACCESS", "TOKEN"]);
    }
}
