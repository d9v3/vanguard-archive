//! Certificats racine ajoutés : celui qui en installe un peut fabriquer un faux certificat pour n'importe quel
//! site et lire tout le trafic HTTPS (banque, courriel), sans le moindre avertissement du navigateur.
//! Les certificats livrés par le système ne sont pas examinés : seulement ceux ajoutés à côté.

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Certificats";

/// Ce qu'on sait d'un certificat d'après son nom.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Famille {
    /// Logiciel connu pour avoir installé une racine dont la clé privée est la même partout (Superfish…).
    Compromis,
    /// Outil d'interception du trafic (débogage, test d'intrusion) : quiconque a sa clé lit tout.
    Interception,
    /// Antivirus, filtre ou proxy d'entreprise qui inspecte le HTTPS.
    Inspection,
    /// Autorité de développement (mkcert).
    Developpement,
    Autre,
}

fn famille(nom: &str) -> Famille {
    let n = nom.to_lowercase();
    let contient = |motifs: &[&str]| motifs.iter().any(|m| n.contains(m));
    if contient(&["superfish", "edellroot", "dsdtestprovider", "komodia", "privdog"]) {
        Famille::Compromis
    } else if contient(&[
        "mitmproxy",
        "fiddler",
        "charles proxy",
        "portswigger",
        "burp",
        "owasp zap",
        "zap root",
        "proxyman",
        "http toolkit",
        "httptoolkit",
    ]) {
        Famille::Interception
    } else if contient(&[
        "avast",
        "avg ",
        "kaspersky",
        "eset ssl",
        "bitdefender",
        "norton",
        "mcafee",
        "webroot",
        "adguard",
        "zscaler",
        "netskope",
        "umbrella",
        "sophos",
        "fortinet",
        "fortigate",
        "blue coat",
        "forcepoint",
        "palo alto",
        "untangle",
    ]) {
        Famille::Inspection
    } else if contient(&["mkcert"]) {
        Famille::Developpement
    } else {
        Famille::Autre
    }
}

/// Un élément DER : (étiquette, contenu, reste après lui).
fn tlv(octets: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&etiquette, reste) = octets.split_first()?;
    let (&premier, reste) = reste.split_first()?;
    let (longueur, reste) = if premier < 0x80 {
        (usize::from(premier), reste)
    } else {
        let n = usize::from(premier & 0x7f);
        if n == 0 || n > 4 || reste.len() < n {
            return None;
        }
        let longueur = reste[..n].iter().fold(0usize, |acc, &o| acc << 8 | usize::from(o));
        (longueur, &reste[n..])
    };
    (reste.len() >= longueur).then(|| (etiquette, &reste[..longueur], &reste[longueur..]))
}

/// Valeur d'un attribut d'un nom X.500 (CN = 2.5.4.3, O = 2.5.4.10…), donné par le dernier octet de son OID.
fn attribut(nom: &[u8], code: u8) -> Option<String> {
    let mut ensembles = nom;
    while let Some((_, ensemble, suite)) = tlv(ensembles) {
        ensembles = suite;
        let Some((_, paire, _)) = tlv(ensemble) else { continue };
        let Some((0x06, oid, reste)) = tlv(paire) else { continue };
        if oid == [0x55, 0x04, code]
            && let Some((genre, valeur, _)) = tlv(reste)
        {
            return Some(if genre == 0x1e {
                // BMPString : UTF-16 gros-boutiste.
                let unites: Vec<u16> = valeur
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                    .collect();
                String::from_utf16_lossy(&unites)
            } else {
                String::from_utf8_lossy(valeur).into_owned()
            });
        }
    }
    None
}

/// Nom du sujet d'un certificat DER : son CN, sinon son organisation, sinon son unité.
fn sujet(der: &[u8]) -> Option<String> {
    let (_, certificat, _) = tlv(der)?;
    let (_, tbs, _) = tlv(certificat)?;
    let mut champs = tbs;
    // Version facultative [0], puis numéro de série, algorithme, émetteur, validité, sujet.
    if champs.first() == Some(&0xa0) {
        champs = tlv(champs)?.2;
    }
    for _ in 0..4 {
        champs = tlv(champs)?.2;
    }
    let (_, nom, _) = tlv(champs)?;
    attribut(nom, 3)
        .or_else(|| attribut(nom, 10))
        .or_else(|| attribut(nom, 11))
}

fn base64(texte: &str) -> Option<Vec<u8>> {
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
        if bloc.len() < 2 {
            return None;
        }
        let n = bloc.iter().try_fold(0u32, |acc, &c| Some(acc << 6 | valeur(c)?))? << (6 * (4 - bloc.len()));
        sortie.extend_from_slice(&n.to_be_bytes()[1..bloc.len()]);
    }
    Some(sortie)
}

/// Noms des certificats d'un fichier : un ou plusieurs blocs PEM, ou un certificat DER brut.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn noms_du_fichier(octets: &[u8]) -> Vec<String> {
    let texte = String::from_utf8_lossy(octets);
    if !texte.contains("-----BEGIN CERTIFICATE-----") {
        return sujet(octets).into_iter().collect();
    }
    texte
        .split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .filter_map(|bloc| bloc.split("-----END CERTIFICATE-----").next())
        .filter_map(base64)
        .filter_map(|der| sujet(&der))
        .collect()
}

/// Constat pour un certificat ajouté. `cle_privee` : sa clé privée est sur cette machine (Windows le sait).
fn juger(nom: &str, ou: &str, cle_privee: bool, retirer: &[String]) -> Constat {
    let (niveau, message, retrait) = match famille(nom) {
        Famille::Compromis => (
            Niveau::Critique,
            trf!(
                "Certificat racine « {nom} » ({ou}) : installé par un logiciel publicitaire, sa clé est publique et permet à n'importe qui de lire ton trafic HTTPS.",
                "Root certificate “{nom}” ({ou}): installed by adware, its key is public and lets anyone read your HTTPS traffic."
            ),
            true,
        ),
        Famille::Interception => (
            Niveau::Moyen,
            trf!(
                "Certificat racine « {nom} » ({ou}) : outil d'interception du trafic. À retirer si tu ne t'en sers plus.",
                "Root certificate “{nom}” ({ou}): traffic interception tool. Remove it if you no longer use it."
            ),
            true,
        ),
        _ if cle_privee => (
            Niveau::Eleve,
            trf!(
                "Certificat racine « {nom} » ({ou}) dont la clé privée est sur cette machine : un programme peut fabriquer de faux certificats pour n'importe quel site.",
                "Root certificate “{nom}” ({ou}) whose private key is on this machine: a program can forge certificates for any site."
            ),
            true,
        ),
        Famille::Inspection => (
            Niveau::Info,
            trf!(
                "Certificat racine « {nom} » ({ou}) : un antivirus ou un filtre inspecte ton trafic HTTPS. Normal si tu l'as installé.",
                "Root certificate “{nom}” ({ou}): an antivirus or filter inspects your HTTPS traffic. Normal if you installed it."
            ),
            false,
        ),
        Famille::Developpement => (
            Niveau::Info,
            trf!(
                "Certificat racine de développement « {nom} » ({ou}). Normal pour un développeur ; garde sa clé privée pour toi.",
                "Development root certificate “{nom}” ({ou}). Normal for a developer; keep its private key to yourself."
            ),
            false,
        ),
        Famille::Autre => (
            Niveau::Info,
            trf!(
                "Certificat racine ajouté : « {nom} » ({ou}). Normal si tu l'as installé (entreprise, école, VPN) ; sinon, retire-le.",
                "Added root certificate: “{nom}” ({ou}). Normal if you installed it (work, school, VPN); otherwise remove it."
            ),
            false,
        ),
    };
    let constat = alerte(CAT, niveau, message);
    if retirer.is_empty() {
        return constat;
    }
    let action = trf!("Retirer le certificat « {nom} »", "Remove the “{nom}” certificate");
    if retrait {
        constat.corriger(action, retirer)
    } else {
        let commandes: Vec<&str> = retirer.iter().map(String::as_str).collect();
        constat.manuel(action, &commandes)
    }
}

/// Dossiers où chaque distribution range les autorités ajoutées par l'administrateur.
#[cfg(target_os = "linux")]
const DOSSIERS_AJOUTS: &[&str] = &[
    "/etc/ca-certificates/trust-source/anchors",
    "/usr/local/share/ca-certificates",
    "/etc/pki/ca-trust/source/anchors",
    "/etc/pki/trust/anchors",
];

#[cfg(target_os = "linux")]
fn fichiers(dossier: &std::path::Path, profondeur: u8, sortie: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dossier).into_iter().flatten().flatten() {
        let chemin = e.path();
        if chemin.is_dir() && profondeur > 0 {
            fichiers(&chemin, profondeur - 1, sortie);
        } else if chemin.is_file() {
            sortie.push(chemin);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn certificats() -> Vec<Constat> {
    let mut trouves = Vec::new();
    for d in DOSSIERS_AJOUTS {
        fichiers(std::path::Path::new(d), 3, &mut trouves);
    }
    let mut constats = Vec::new();
    for f in trouves {
        let Ok(octets) = std::fs::read(&f) else { continue };
        let chemin = f.display().to_string();
        let entre_apostrophes = format!("'{}'", chemin.replace('\'', r"'\''"));
        let retirer = vec![
            format!("sudo rm -f {entre_apostrophes}"),
            "if command -v update-ca-trust >/dev/null; then sudo update-ca-trust; else sudo update-ca-certificates --fresh; fi"
                .to_string(),
        ];
        for nom in noms_du_fichier(&octets) {
            constats.push(juger(&nom, &chemin, false, &retirer));
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun certificat racine ajouté aux certificats du système.",
                "No root certificate added to the system certificates."
            ),
        ));
    }
    constats
}

/// Noms des certificats auxquels une confiance particulière a été donnée (`security dump-trust-settings`) :
/// « Cert 0: Charles Proxy CA (12 Jan 2023, MacBook) ». Les racines d'Apple n'y figurent pas : elles ont leur
/// propre trousseau, que l'utilisateur ne modifie pas.
#[cfg(any(target_os = "macos", test))]
fn lire_reglages_confiance(sortie: &str) -> Vec<String> {
    sortie
        .lines()
        .filter_map(|l| l.trim().strip_prefix("Cert ")?.split_once(": ").map(|(_, nom)| nom))
        // La date et la machine d'ajout, entre parenthèses à la fin, ne font pas partie du nom.
        .map(|nom| {
            nom.rsplit_once(" (")
                .filter(|_| nom.ends_with(')'))
                .map_or(nom, |(n, _)| n)
        })
        .map(|nom| nom.trim().to_string())
        .collect()
}

/// macOS : certificats rendus « de confiance » par l'administrateur (trousseau Système) ou par l'utilisateur
/// (trousseau de session). C'est ce que font les outils d'interception et les logiciels publicitaires.
#[cfg(target_os = "macos")]
pub fn certificats() -> Vec<Constat> {
    let mut constats = Vec::new();
    for (admin, ou) in [
        (true, tr!("trousseau Système", "System keychain")),
        (false, tr!("trousseau de session", "login keychain")),
    ] {
        let args: &[&str] = if admin {
            &["dump-trust-settings", "-d"]
        } else {
            &["dump-trust-settings"]
        };
        // Sans réglage, la commande répond « No Trust Settings were found » avec un code d'erreur.
        let sortie = crate::commande::lancer(std::process::Command::new("security").args(args), 20)
            .map(|r| r.sortie)
            .unwrap_or_default();
        for nom in lire_reglages_confiance(&sortie) {
            let echappe = nom.replace('\'', r"'\''");
            let retirer = if admin {
                vec![format!(
                    "sudo security delete-certificate -c '{echappe}' /Library/Keychains/System.keychain"
                )]
            } else {
                vec![format!("security delete-certificate -c '{echappe}'")]
            };
            constats.push(juger(&nom, ou, false, &retirer));
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun certificat racine ajouté aux certificats du système.",
                "No root certificate added to the system certificates."
            ),
        ));
    }
    constats
}

/// Racines des magasins de la machine et de l'utilisateur : « CERT|magasin|clé privée|empreinte|sujet ».
/// Le magasin de l'utilisateur montre aussi ceux de la machine : un certificat présent dans les deux est de la
/// machine. Windows met à jour lui-même ses racines : seules les marques d'un ajout sont examinées.
#[cfg(windows)]
pub fn certificats() -> Vec<Constat> {
    let Some(sortie) = super::windows::ps(
        // Module du lecteur Cert: chargé d'office (voir windows::powershell pour la cause de la panne vue en VM).
        "Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue; \
         foreach ($m in 'LocalMachine', 'CurrentUser') { Get-ChildItem \"Cert:\\$m\\Root\" | ForEach-Object { $c = $_; \
         $nom = try { $c.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } catch { $c.Subject }; \
         \"CERT|$m|$($c.HasPrivateKey)|$($c.Thumbprint)|$nom\" } }",
    ) else {
        return vec![super::windows::illisible(CAT)];
    };
    let mut vus = std::collections::HashSet::new();
    let mut total = 0;
    let mut constats = Vec::new();
    for l in sortie.lines() {
        let c: Vec<&str> = l.trim().splitn(5, '|').collect();
        let ["CERT", magasin, cle, empreinte, nom] = c[..] else {
            continue;
        };
        if !vus.insert(empreinte.to_string()) {
            continue;
        }
        total += 1;
        let cle_privee = cle.eq_ignore_ascii_case("true")
            // Certificats de développement de Visual Studio / .NET : valables pour localhost seulement.
            && !nom.eq_ignore_ascii_case("localhost");
        if famille(nom) == Famille::Autre && !cle_privee {
            continue;
        }
        let ou = if magasin == "LocalMachine" {
            tr!("magasin de l'ordinateur", "computer store")
        } else {
            tr!("magasin de l'utilisateur", "user store")
        };
        let retirer = vec![format!("Remove-Item -Path 'Cert:\\{magasin}\\Root\\{empreinte}'")];
        constats.push(juger(nom, ou, cle_privee, &retirer));
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            trf!(
                "{total} certificats racine, aucun ajouté par un outil d'interception ou un logiciel connu pour en abuser.",
                "{total} root certificates, none added by an interception tool or software known to abuse them."
            ),
        ));
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reglages_de_confiance_macos() {
        let sortie = "Number of trusted certs = 2\nCert 0: Charles Proxy CA (12 Jan 2023, MacBook)\n   Number of trust settings : 0\nCert 1: mitmproxy\n";
        assert_eq!(lire_reglages_confiance(sortie), ["Charles Proxy CA", "mitmproxy"]);
        assert_eq!(
            lire_reglages_confiance("SecTrustSettingsCopyCertificates: No Trust Settings were found."),
            Vec::<String>::new()
        );
    }

    /// Certificat autosigné « CN=Sentinel Test CA, O=Sentinel » (openssl req -x509, clé EC P-256).
    const PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBsjCCAVegAwIBAgIUPedwVGO78YHnV8dFaXepfufztX4wCgYIKoZIzj0EAwIw
LjEZMBcGA1UEAwwQU2VudGluZWwgVGVzdCBDQTERMA8GA1UECgwIU2VudGluZWww
HhcNMjYxMDE3MTYzMjI1WhcNMzYxMDE0MTYzMjI1WjAuMRkwFwYDVQQDDBBTZW50
aW5lbCBUZXN0IENBMREwDwYDVQQKDAhTZW50aW5lbDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABMtkHFFz9C3uTS616s7rG9y3ha3S4Gyms43WvmA46TBA65v4NpNy
eVsiT86il5TzRMPzz5F8OB3xB1Y8CFtrXXSjUzBRMB0GA1UdDgQWBBT233gr/Pp1
gk5KK8txYEsrKRNO0zAfBgNVHSMEGDAWgBT233gr/Pp1gk5KK8txYEsrKRNO0zAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQD/g1xI0eK6PL8ZXaFY
x2g9XTLdeXAcgcywj7ksqylDtAIhAMEhPiY2FdJm7R4VvROsvv37j6MzSBV6rVPP
wdpi4zlo
-----END CERTIFICATE-----
";

    #[test]
    fn familles_de_certificats() {
        assert_eq!(famille("Superfish, Inc."), Famille::Compromis);
        assert_eq!(famille("mitmproxy"), Famille::Interception);
        assert_eq!(famille("Avast Web/Mail Shield Root"), Famille::Inspection);
        assert_eq!(famille("mkcert alice@portable"), Famille::Developpement);
        assert_eq!(famille("Mon entreprise CA"), Famille::Autre);
    }

    #[test]
    fn sujet_d_un_certificat() {
        let noms = noms_du_fichier(PEM.as_bytes());
        assert_eq!(noms, ["Sentinel Test CA"]);
        // Le même certificat en DER brut (.der, .cer).
        let corps: String = PEM.lines().filter(|l| !l.starts_with("-----")).collect();
        assert_eq!(noms_du_fichier(&base64(&corps).unwrap()), ["Sentinel Test CA"]);
        // Fichier qui n'est pas un certificat : rien, sans planter.
        let rien: Vec<String> = Vec::new();
        assert_eq!(noms_du_fichier(b"pas un certificat"), rien);
        assert_eq!(
            noms_du_fichier(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"),
            rien
        );
    }

    #[test]
    fn jugement() {
        let retirer = vec!["sudo rm -f '/x'".to_string()];
        let c = juger("Superfish, Inc.", "/x", false, &retirer);
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert!(c.correctif.as_ref().is_some_and(|k| k.automatique));
        let c = juger("Mon entreprise CA", "/x", false, &retirer);
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.correctif.as_ref().is_some_and(|k| !k.automatique));
        assert_eq!(
            juger("Mon entreprise CA", "/x", true, &retirer).probleme,
            Some(Niveau::Eleve)
        );
    }
}
