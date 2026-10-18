//! Alertes sur le téléphone, par ntfy (logiciel libre, application gratuite pour Android et iPhone) : la surveillance
//! et l'entretien du mois y envoient aussi leurs alertes. Le serveur public ntfy.sh ne demande aucun compte : qui
//! connaît le sujet lit les messages. Le sujet est donc tiré au hasard (120 bits, il sert de mot de passe) et gardé
//! sur cet ordinateur seulement ; le message reste minimal, sans adresse IP ni MAC (masquées si un texte en
//! contenait). Un envoi raté est noté au journal, sans jamais rien bloquer.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::langue::Reponse;
use crate::selection::{Ligne, choisir};
use crate::ui::*;

const SERVEUR_PUBLIC: &str = "https://ntfy.sh";

/// Ce qu'il faut pour publier : le serveur, le sujet (secret) et, pour un serveur à soi qui le demande, un jeton.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
struct Reglage {
    serveur: String,
    sujet: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jeton: Option<String>,
}

fn fichier() -> PathBuf {
    crate::reseau::dossier_local().join("alertes.json")
}

fn lire() -> Option<Reglage> {
    serde_json::from_str(&std::fs::read_to_string(fichier()).ok()?).ok()
}

/// Les alertes partent-elles vers un téléphone ?
pub fn actives() -> bool {
    lire().is_some()
}

/// Écrit un fichier lisible par ce compte seulement (le sujet et le jeton sont des secrets), en remplaçant l'ancien.
fn ecrire_prive(chemin: &Path, contenu: &[u8]) -> bool {
    if let Some(dossier) = chemin.parent() {
        let _ = std::fs::create_dir_all(dossier);
    }
    let _ = std::fs::remove_file(chemin);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let ecrit = options.open(chemin).and_then(|mut f| f.write_all(contenu));
    if ecrit.is_err() {
        let _ = std::fs::remove_file(chemin);
    }
    ecrit.is_ok()
}

fn ecrire(r: &Reglage) -> bool {
    serde_json::to_string_pretty(r).is_ok_and(|t| ecrire_prive(&fichier(), t.as_bytes()))
}

/// Octets tirés au hasard : par le système sous Unix (/dev/urandom) ; ailleurs, et en secours, par le hachage de la
/// bibliothèque standard, dont la clé vient du générateur du système.
fn hasard(n: usize) -> Vec<u8> {
    use std::hash::{BuildHasher, Hasher};
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut octets = vec![0; n];
        if std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut octets))
            .is_ok()
        {
            return octets;
        }
    }
    let etat = std::collections::hash_map::RandomState::new();
    let instant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut octets = Vec::with_capacity(n + 8);
    for i in 0u64.. {
        if octets.len() >= n {
            break;
        }
        let mut h = etat.build_hasher();
        h.write_u64(i);
        h.write_u128(instant);
        octets.extend_from_slice(&h.finish().to_le_bytes());
    }
    octets.truncate(n);
    octets
}

/// Sujet ntfy : « gardien- » et 24 lettres et chiffres tirés au hasard (5 bits chacun, 120 en tout), sans les
/// signes qu'on confond en les recopiant à la main (l et 1, o et 0).
fn nouveau_sujet() -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let code: String = hasard(24)
        .iter()
        .map(|b| char::from(ALPHABET[usize::from(b % 32)]))
        .collect();
    format!("gardien-{code}")
}

/// Une adresse IP (v4 ou v6) ou MAC ?
fn est_adresse(mot: &str) -> bool {
    if mot.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // MAC : six paires de chiffres hexadécimaux séparées par « : » ou « - ».
    let groupes: Vec<&str> = mot.split([':', '-']).collect();
    groupes.len() == 6
        && groupes
            .iter()
            .all(|g| g.len() == 2 && g.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Le texte d'une alerte sans adresse IP ni MAC : le téléphone n'en a pas besoin, et le message passe par un serveur
/// public. Chaque adresse devient « … » ; la ponctuation qui la suit reste.
fn masquer(texte: &str) -> String {
    fn vider(mot: &mut String, sortie: &mut String) {
        let adresse = mot.trim_end_matches(['.', ':', '-']);
        if est_adresse(adresse) {
            sortie.push('…');
            sortie.push_str(&mot[adresse.len()..]);
        } else {
            sortie.push_str(mot);
        }
        mot.clear();
    }
    let mut sortie = String::with_capacity(texte.len());
    let mut mot = String::new();
    for c in texte.chars() {
        if c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '-') {
            mot.push(c);
        } else {
            vider(&mut mot, &mut sortie);
            sortie.push(c);
        }
    }
    vider(&mut mot, &mut sortie);
    sortie
}

/// Corps du message pour ntfy, en JSON : le sujet voyage dans le corps, pas dans l'adresse.
fn corps(r: &Reglage, titre: &str, message: &str, essai: bool) -> String {
    serde_json::json!({
        "topic": r.sujet,
        "title": titre,
        "message": message,
        "priority": if essai { 3 } else { 4 },
        "tags": [if essai { "white_check_mark" } else { "shield" }],
    })
    .to_string()
}

/// Publie sur le serveur ntfy. Le corps (avec le sujet) et le jeton passent par des fichiers réservés à ce compte :
/// sur la ligne de commande de curl, tous les comptes de l'ordinateur les liraient. L'erreur rendue ne cite jamais
/// le sujet.
fn poster(r: &Reglage, titre: &str, message: &str, essai: bool) -> Result<(), String> {
    let dossier = crate::reseau::dossier_local();
    let id = format!(
        "{}-{}",
        std::process::id(),
        nouveau_sujet().trim_start_matches("gardien-")
    );
    let fichier_corps = dossier.join(format!("alerte-{id}.json"));
    if !ecrire_prive(&fichier_corps, corps(r, titre, message, essai).as_bytes()) {
        return Err("message impossible à préparer (dossier des données)".into());
    }
    let fichier_jeton = r
        .jeton
        .as_ref()
        .map(|jeton| (dossier.join(format!("alerte-{id}.entete")), jeton));
    if let Some((f, jeton)) = &fichier_jeton
        && !ecrire_prive(f, format!("Authorization: Bearer {jeton}\n").as_bytes())
    {
        let _ = std::fs::remove_file(&fichier_corps);
        return Err("jeton impossible à préparer (dossier des données)".into());
    }
    let mut curl = std::process::Command::new("curl");
    curl.args(["-sS", "--max-time", "15", "-A", "gardien", "-w", "\n%{http_code}"])
        .args(["-H", "Content-Type: application/json"]);
    if let Some((f, _)) = &fichier_jeton {
        curl.arg("-H").arg(format!("@{}", f.display()));
    }
    curl.arg("--data-binary")
        .arg(format!("@{}", fichier_corps.display()))
        .arg(&r.serveur);
    let resultat = crate::commande::lancer(&mut curl, 20);
    let _ = std::fs::remove_file(&fichier_corps);
    if let Some((f, _)) = &fichier_jeton {
        let _ = std::fs::remove_file(f);
    }
    let Some(resultat) = resultat else {
        return Err("curl ne répond pas (absent, ou serveur muet)".into());
    };
    match resultat.sortie.trim_end().rsplit('\n').next().map(str::trim) {
        Some("200") => Ok(()),
        Some(code) if !code.is_empty() && code != "000" => Err(format!("le serveur répond {code}")),
        _ => Err(format!("serveur injoignable : {}", resultat.erreurs.trim())),
    }
}

/// Envoie une alerte au téléphone, si les alertes sont activées. Ne bloque jamais : un envoi raté (pas d'Internet,
/// serveur absent) est noté au journal.
pub fn envoyer(titre: &str, message: &str) {
    let Some(r) = lire() else { return };
    if let Err(e) = poster(&r, &masquer(titre), &masquer(message), false) {
        crate::journal::erreur("alertes sur le téléphone", &e);
    }
}

/// Adresse d'un serveur ntfy tapée par la personne : « ntfy.exemple.fr » devient « https://ntfy.exemple.fr ».
fn adresse_serveur(tape: &str) -> Option<String> {
    let tape = tape.trim();
    if tape.is_empty() {
        return Some(SERVEUR_PUBLIC.into());
    }
    let (schema, reste) = tape.split_once("://").unwrap_or(("https", tape));
    let schema = schema.to_lowercase();
    let reste = reste.trim_end_matches('/');
    // Le nom du serveur (et son port) : ni vide, ni coupé (« https: »), sans espace.
    let hote = reste.split('/').next().unwrap_or_default();
    let valide = matches!(schema.as_str(), "https" | "http")
        && hote.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '[')
        && !hote.ends_with(':')
        && !reste.contains(char::is_whitespace);
    valide.then(|| format!("{schema}://{reste}"))
}

fn expliquer() {
    for paragraphe in [
        tr!(
            "La surveillance et l'entretien du mois peuvent aussi prévenir ton téléphone, par ntfy : une application libre et gratuite (Android : Google Play ou F-Droid ; iPhone : App Store).",
            "Monitoring and the monthly check-up can also alert your phone, through ntfy: a free and open source app (Android: Google Play or F-Droid; iPhone: App Store)."
        ),
        tr!(
            "Le serveur public ntfy.sh ne demande aucun compte, mais qui connaît le sujet lit les messages. Gardien tire donc un sujet au hasard, impossible à deviner, gardé sur cet ordinateur seulement. Les messages restent courts : jamais d'adresse IP ni MAC. Tu peux aussi donner l'adresse de ton propre serveur ntfy.",
            "The public server ntfy.sh needs no account, but whoever knows the topic reads the messages. Gardien therefore draws a random topic, impossible to guess, kept on this computer only. Messages stay short: never an IP or MAC address. You can also give the address of your own ntfy server."
        ),
    ] {
        println!();
        for ligne in envelopper(paragraphe, LARGEUR - 2) {
            println!("  {ligne}");
        }
    }
}

/// Comment s'abonner dans l'application, et où voir les messages sans elle.
fn afficher(r: &Reglage) {
    let serveur = r.serveur.trim_start_matches("https://");
    trp!(
        "\n  Serveur : {ACCENT}{}{RESET}",
        "\n  Server: {ACCENT}{}{RESET}",
        serveur
    );
    trp!("  Sujet   : {ACCENT}{}{RESET}", "  Topic:  {ACCENT}{}{RESET}", r.sujet);
    let conseil = if r.serveur == SERVEUR_PUBLIC {
        trf!(
            "Dans l'application ntfy : « + », puis ce sujet. Sans l'application : {}/{} dans un navigateur.",
            "In the ntfy app: “+”, then this topic. Without the app: {}/{} in a browser.",
            r.serveur,
            r.sujet
        )
    } else {
        trf!(
            "Dans l'application ntfy : « + », ce sujet, puis « Utiliser un autre serveur » : {}.",
            "In the ntfy app: “+”, this topic, then “Use another server”: {}.",
            r.serveur
        )
    };
    println!();
    for ligne in envelopper(&conseil, LARGEUR - 2) {
        println!("  {GRIS}{ligne}{RESET}");
    }
}

fn essai_avec(r: &Reglage) {
    trp!(
        "\n  {GRIS}Envoi d'une alerte d'essai…{RESET}",
        "\n  {GRIS}Sending a test alert…{RESET}"
    );
    match poster(
        r,
        tr!("Gardien : alerte d'essai", "Gardien: test alert"),
        tr!(
            "Les alertes de cet ordinateur arriveront ici.",
            "This computer's alerts will arrive here."
        ),
        true,
    ) {
        Ok(()) => trp!(
            "  {VERT}✔{RESET} Envoyée : elle doit s'afficher sur le téléphone abonné au sujet.",
            "  {VERT}✔{RESET} Sent: it should show up on the phone subscribed to the topic."
        ),
        Err(e) => {
            crate::journal::erreur("alertes sur le téléphone", &e);
            trp!(
                "  ✖ Pas envoyée ({}). Les alertes restent activées ; réessaie avec « gardien alertes essai ».",
                "  ✖ Not sent ({}). Alerts stay on; try again with “gardien alertes essai”.",
                e
            );
        }
    }
}

/// Activer : explication, accord, serveur, sujet tiré au hasard, puis alerte d'essai.
fn activer() {
    if let Some(r) = lire() {
        trp!("  Les alertes sont déjà activées.", "  Alerts are already on.");
        afficher(&r);
        return;
    }
    expliquer();
    if !demander(tr!(
        "\n  Activer les alertes sur le téléphone ? [o/N] : ",
        "\n  Turn on alerts on your phone? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'a été activé.", "  Nothing was turned on.");
        return;
    }
    let serveur = loop {
        let tape = demander(tr!(
            "  Serveur ntfy (Entrée : ntfy.sh, ou l'adresse du tien) : ",
            "  ntfy server (Enter: ntfy.sh, or your own server's address): "
        ));
        match adresse_serveur(&tape) {
            Some(s) => break s,
            None => trp!(
                "  ✖ Adresse incomprise : « ntfy.exemple.fr » ou « https://ntfy.exemple.fr ».",
                "  ✖ Address not understood: “ntfy.example.com” or “https://ntfy.example.com”."
            ),
        }
    };
    // Un jeton n'a de sens que sur un serveur à soi : ntfy.sh publie sans compte.
    let jeton = (serveur != SERVEUR_PUBLIC)
        .then(|| {
            rpassword::prompt_password(tr!(
                "  Jeton d'accès de ce serveur (Entrée : aucun) : ",
                "  Access token for this server (Enter: none): "
            ))
            .unwrap_or_default()
        })
        .map(|j| j.trim().to_string())
        .filter(|j| !j.is_empty());
    let r = Reglage {
        serveur,
        sujet: nouveau_sujet(),
        jeton,
    };
    if !ecrire(&r) {
        trp!(
            "  ✖ Réglage impossible à écrire dans le dossier des données de Gardien.",
            "  ✖ Could not write the setting in Gardien's data folder."
        );
        return;
    }
    trp!(
        "\n  {VERT}✔{RESET} Alertes activées. Abonne ton téléphone à ce sujet :",
        "\n  {VERT}✔{RESET} Alerts on. Subscribe your phone to this topic:"
    );
    afficher(&r);
    essai_avec(&r);
}

fn couper() {
    let _ = std::fs::remove_file(fichier());
    trp!(
        "  Alertes coupées : le sujet est oublié (un nouveau sera tiré si tu les réactives).",
        "  Alerts off: the topic is forgotten (a new one will be drawn if you turn them back on)."
    );
}

/// Menu 5 › Alertes sur le téléphone : activer, ou, déjà activées, un essai ou les couper.
pub fn menu() {
    titre(tr!("Alertes sur le téléphone", "Alerts on your phone"));
    let Some(r) = lire() else {
        activer();
        return;
    };
    trp!(
        "  {VERT}✔{RESET} Activées : la surveillance et l'entretien du mois préviennent aussi ton téléphone.",
        "  {VERT}✔{RESET} On: monitoring and the monthly check-up also alert your phone."
    );
    afficher(&r);
    let lignes = [
        Ligne::Texte(String::new()),
        Ligne::choix("1", tr!("Envoyer une alerte d'essai", "Send a test alert"), ""),
        Ligne::choix("2", tr!("Couper les alertes", "Turn alerts off"), ""),
        Ligne::choix("↵", tr!("Revenir", "Back"), ""),
        Ligne::Texte(String::new()),
    ];
    match choisir(
        &lignes,
        &format!("  {ACCENT}›{RESET} {}", tr!("Choix : ", "Choice: ")),
        "1",
        tr!("revenir", "back"),
    )
    .as_deref()
    .map(str::trim)
    {
        Some("1") => essai_avec(&r),
        Some("2") => couper(),
        _ => {}
    }
}

/// « gardien alertes [on|off|essai] » ; sans argument, le menu.
pub fn commande(etat: Option<&str>) {
    match etat {
        None => menu(),
        Some("on") => {
            titre(tr!("Alertes sur le téléphone", "Alerts on your phone"));
            activer();
        }
        Some("off") => couper(),
        Some(_) => match lire() {
            Some(r) => essai_avec(&r),
            None => trp!(
                "  Les alertes ne sont pas activées : « gardien alertes on ».",
                "  Alerts are not on: “gardien alertes on”."
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sujet_tire_au_hasard() {
        let a = nouveau_sujet();
        let b = nouveau_sujet();
        assert_ne!(a, b);
        assert_eq!(a.len(), "gardien-".len() + 24);
        assert!(a.starts_with("gardien-"));
        // Ce que ntfy accepte dans un sujet, sans signe qu'on confond en le recopiant.
        assert!(
            a["gardien-".len()..]
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        assert!(!a["gardien-".len()..].contains(['l', 'o', '0', '1']));
        assert_eq!(hasard(40).len(), 40);
    }

    #[test]
    fn ni_ip_ni_mac_sur_le_telephone() {
        assert_eq!(
            masquer("Nouvel appareil : 192.168.1.37 — Apple 3c:22:fb:12:34:56."),
            "Nouvel appareil : … — Apple …."
        );
        assert_eq!(
            masquer("Box fe80::1 et 2001:db8::7, MAC 3C-22-FB-12-34-56"),
            "Box … et …, MAC …"
        );
        // Ni les ports, ni les dates, ni les heures, ni les mots ne bougent.
        let garde = "Port 4444/tcp ouvert le 2026-10-18 à 12:30, réseau « Salon », décodé.";
        assert_eq!(masquer(garde), garde);
        assert_eq!(masquer("Réseau 10.0.0.0/24."), "Réseau …/24.");
    }

    #[test]
    fn corps_du_message() {
        let r = Reglage {
            serveur: SERVEUR_PUBLIC.into(),
            sujet: "gardien-abcdefghijkmnpqrstuvwxyz".into(),
            jeton: None,
        };
        let c: serde_json::Value = serde_json::from_str(&corps(&r, "Titre « é »", "Message", false)).unwrap();
        assert_eq!(c["topic"], "gardien-abcdefghijkmnpqrstuvwxyz");
        assert_eq!(c["title"], "Titre « é »");
        assert_eq!(c["priority"], 4);
        // Le sujet n'est jamais dans l'adresse (ni sur la ligne de commande) : il voyage dans le corps.
        assert!(!r.serveur.contains(&r.sujet));
    }

    #[test]
    fn adresse_du_serveur() {
        assert_eq!(adresse_serveur("").as_deref(), Some(SERVEUR_PUBLIC));
        assert_eq!(
            adresse_serveur("ntfy.example.com/").as_deref(),
            Some("https://ntfy.example.com")
        );
        assert_eq!(
            adresse_serveur("http://10.0.0.5:8080").as_deref(),
            Some("http://10.0.0.5:8080")
        );
        assert_eq!(adresse_serveur("ftp://x"), None);
        assert_eq!(adresse_serveur("https://"), None);
        assert_eq!(adresse_serveur("mon serveur"), None);
    }

    #[test]
    fn reglage_prive_et_relu() {
        let r = Reglage {
            serveur: "https://ntfy.example.com".into(),
            sujet: nouveau_sujet(),
            jeton: Some("tk_essai".into()),
        };
        assert!(ecrire(&r));
        assert_eq!(lire(), Some(r));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(fichier()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_file(fichier());
        assert!(!actives());
    }
}
