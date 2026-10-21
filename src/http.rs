//! Les demandes HTTPS de Vanguard, faites par reqwest au lieu de curl : rien à installer (curl manque sur des
//! distributions minimales et sur de vieux Windows), le même comportement partout, et une clé d'API qui ne passe
//! jamais par la ligne de commande d'un autre programme, que la liste des processus montrerait.
//!
//! Chaque demande tourne sur son propre fil, avec son propre moteur tokio : elle s'appelle de la même façon depuis un
//! code ordinaire ou depuis la surveillance, déjà asynchrone (reqwest refuse qu'un moteur en bloque un autre).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Le nom donné aux services : certains refusent une demande sans nom (Have I Been Pwned l'exige).
const AGENT: &str = "vanguard";

/// Une demande : GET sans corps, POST avec.
pub(crate) struct Demande<'a> {
    pub adresse: &'a str,
    pub entetes: Vec<(&'a str, String)>,
    pub corps: Option<Vec<u8>>,
    pub delai: Duration,
    /// Au-delà, la réponse est abandonnée (`None`) : une archive ne doit pas remplir le disque.
    pub taille_max: u64,
    /// Jamais de redirection vers un autre hôte, même sans en-tête : l'adresse porte un secret (la clé d'abuse.ch dans
    /// le chemin de ses exports). Toujours le cas avec des en-têtes.
    pub meme_hote: bool,
}

impl<'a> Demande<'a> {
    pub(crate) fn get(adresse: &'a str, delai: Duration) -> Self {
        Demande {
            adresse,
            entetes: Vec::new(),
            corps: None,
            delai,
            taille_max: 64 << 20,
            meme_hote: false,
        }
    }
}

/// Une réponse reçue en entier, quel que soit son code (404 compte pour Have I Been Pwned).
pub(crate) struct Reponse {
    pub code: u16,
    pub corps: Vec<u8>,
}

impl Reponse {
    pub(crate) fn texte(&self) -> String {
        String::from_utf8_lossy(&self.corps).into_owned()
    }
}

/// Fait tourner `travail` sur un fil à part, avec un moteur tokio à lui. `None` : le moteur n'a pas démarré.
fn a_part<T: Send + 'static>(travail: impl Future<Output = T> + Send + 'static) -> Option<T> {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()
            .map(|moteur| {
                let resultat = moteur.block_on(travail);
                // Sans attendre une résolution DNS encore bloquée dans un fil du moteur : le délai reste le délai.
                moteur.shutdown_background();
                resultat
            })
    })
    .join()
    .ok()
    .flatten()
}

/// Le chiffrement de TLS : ring, installé une fois pour tout le programme (reqwest est pris sans fournisseur).
fn fournisseur() {
    static FAIT: std::sync::Once = std::sync::Once::new();
    FAIT.call_once(|| {
        // Déjà installé (par un autre appel) : rien à faire, l'erreur le dit seulement.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Une redirection ne quitte jamais HTTPS : sinon quelqu'un sur le chemin pourrait répondre à la place du service (le
/// registre d'un domaine, une liste d'abuse.ch). Dix au plus. Avec `meme_hote`, jamais vers un autre hôte : reqwest n'y
/// retire que les en-têtes d'authentification qu'il connaît, une clé d'API (« Auth-Key », « hibp-api-key ») suivrait.
fn client(delai: Duration, meme_hote: bool, certificat: bool) -> Option<reqwest::Client> {
    fournisseur();
    let redirections = reqwest::redirect::Policy::custom(move |essai| {
        let autre_hote = essai.previous().first().and_then(|u| u.host_str()) != essai.url().host_str();
        if essai.previous().len() >= 10 || essai.url().scheme() != "https" || (meme_hote && autre_hote) {
            essai.stop()
        } else {
            essai.follow()
        }
    });
    reqwest::Client::builder()
        .user_agent(AGENT)
        .redirect(redirections)
        .connect_timeout(delai.min(Duration::from_secs(15)))
        .timeout(delai)
        // Le certificat présenté par le serveur, gardé avec la réponse (audit du HTTPS intercepté).
        .tls_info(certificat)
        .build()
        .ok()
}

/// Envoie la demande et reçoit la réponse entière. `None` : pas de réponse (hors ligne, délai dépassé, certificat
/// refusé) ou réponse trop grosse.
pub(crate) fn envoyer(demande: Demande) -> Option<Reponse> {
    let Demande {
        adresse,
        entetes,
        corps,
        delai,
        taille_max,
        meme_hote,
    } = demande;
    // HTTPS seulement, dès l'adresse de départ ; en clair, seulement vers cette machine (les tests).
    if !(adresse.starts_with("https://") || adresse.starts_with("http://127.0.0.1:")) {
        return None;
    }
    let adresse = adresse.to_string();
    let entetes: Vec<(String, String)> = entetes.into_iter().map(|(n, v)| (n.to_string(), v)).collect();
    a_part(async move {
        let client = client(delai, meme_hote || !entetes.is_empty(), false)?;
        let mut requete = match corps {
            Some(corps) => client.post(&adresse).body(corps),
            None => client.get(&adresse),
        };
        for (nom, valeur) in &entetes {
            requete = requete.header(nom.as_str(), valeur.as_str());
        }
        // L'erreur de reqwest est jetée sans être lue ni gardée : son texte contient l'adresse, et avec elle la clé
        // d'abuse.ch quand elle est dans le chemin.
        let mut reponse = requete.send().await.ok()?;
        let code = reponse.status().as_u16();
        if reponse.content_length().is_some_and(|t| t > taille_max) {
            return None;
        }
        // La place d'un coup quand la taille est annoncée (bornée), au lieu de doublements successifs.
        let annoncee = reponse.content_length().unwrap_or(0).min(taille_max);
        let mut recu = Vec::with_capacity(usize::try_from(annoncee).unwrap_or(0));
        while let Some(morceau) = reponse.chunk().await.ok()? {
            recu.extend_from_slice(&morceau);
            if recu.len() as u64 > taille_max {
                return None;
            }
        }
        Some(Reponse { code, corps: recu })
    })
    .flatten()
}

/// GET dont seule une réponse 200 compte (comme « curl -f ») : son texte.
pub(crate) fn texte(adresse: &str, delai: Duration) -> Option<String> {
    envoyer(Demande::get(adresse, delai))
        .filter(|r| r.code == 200)
        .map(|r| r.texte())
}

/// Pourquoi un site n'a pas rendu son certificat.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refus {
    /// La connexion a été refusée à cause du certificat présenté (autorité inconnue du système, nom qui ne
    /// correspond pas, certificat expiré) : le texte de l'erreur, tel que le vérificateur l'a dit.
    Certificat(String),
    /// Pas de réponse : hors ligne, délai, adresse qui n'est pas en HTTPS, ou réponse sans certificat.
    Reseau,
}

/// Ce qu'un site HTTPS a présenté : le certificat de feuille (DER), tel que reçu, et le code de la réponse.
pub(crate) struct Presente {
    pub code: u16,
    pub certificat: Vec<u8>,
}

/// Dans la chaîne des causes d'une erreur de reqwest, celle qui parle du certificat, s'il y en a une.
fn cause_certificat(erreur: &reqwest::Error) -> Option<String> {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(erreur);
    while let Some(e) = cause {
        let texte = e.to_string();
        let bas = texte.to_lowercase();
        if bas.contains("certificate") || bas.contains("certificat") || bas.contains("unknownissuer") {
            return Some(texte);
        }
        cause = e.source();
    }
    None
}

/// Demande `adresse` (HTTPS seulement, sans suivre de redirection vers un autre hôte : le certificat jugé est celui
/// du site demandé) et rend le certificat que le serveur a présenté, accepté par le vérificateur du système, avec
/// le code de sa réponse ; le corps n'est pas lu. `Err(Refus::Certificat)` : le système l'a refusé.
pub(crate) fn certificat_presente(adresse: &str, delai: Duration) -> Result<Presente, Refus> {
    if !adresse.starts_with("https://") {
        return Err(Refus::Reseau);
    }
    let adresse = adresse.to_string();
    a_part(async move {
        let client = client(delai, true, true)?;
        let reponse = match client.get(&adresse).send().await {
            Ok(r) => r,
            Err(e) => return Some(Err(cause_certificat(&e).map_or(Refus::Reseau, Refus::Certificat))),
        };
        let code = reponse.status().as_u16();
        let certificat = reponse
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(|t| t.peer_certificate().map(<[u8]>::to_vec));
        let Some(certificat) = certificat else {
            return Some(Err(Refus::Reseau));
        };
        Some(Ok(Presente { code, certificat }))
    })
    .flatten()
    .unwrap_or(Err(Refus::Reseau))
}

/// Pour la mesure du débit : reçoit `adresse` en comptant les octets au fil de l'eau dans `octets`, jusqu'à la fin de
/// la réponse, `fin` ou `arret`. `false` : rien n'est arrivé.
pub(crate) fn recevoir_en_comptant(adresse: &str, fin: Instant, octets: &AtomicU64, arret: &AtomicBool) -> bool {
    let reste = fin.saturating_duration_since(Instant::now());
    if reste.is_zero() {
        return false;
    }
    std::thread::scope(|s| {
        s.spawn(|| {
            let moteur = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()?;
            let resultat = moteur.block_on(async {
                let mut reponse = client(reste, false, false)?.get(adresse).send().await.ok()?;
                let mut recus = 0u64;
                while Instant::now() < fin && !arret.load(Ordering::Relaxed) {
                    let Ok(Some(morceau)) = reponse.chunk().await else {
                        break;
                    };
                    recus += morceau.len() as u64;
                    octets.fetch_add(morceau.len() as u64, Ordering::Relaxed);
                }
                Some(recus > 0)
            });
            moteur.shutdown_background();
            resultat
        })
        .join()
        .ok()
        .flatten()
        .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// Un petit serveur HTTP local (sans Internet, comme le veut la vérification hors ligne) : il répond `reponse` à
    /// la première demande et rend ce qu'il a reçu.
    fn serveur(reponse: &'static [u8]) -> (String, std::thread::JoinHandle<String>) {
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = format!("http://{}/", ecoute.local_addr().unwrap());
        let fil = std::thread::spawn(move || {
            let (mut prise, _) = ecoute.accept().unwrap();
            prise.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut recu = vec![0u8; 65_536];
            let n = prise.read(&mut recu).unwrap_or(0);
            let _ = prise.write_all(reponse);
            String::from_utf8_lossy(&recu[..n]).into_owned()
        });
        (adresse, fil)
    }

    #[test]
    fn reponse_entiere_avec_son_code() {
        let (adresse, fil) = serveur(b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabsent");
        let mut demande = Demande::get(&adresse, Duration::from_secs(5));
        demande.entetes.push(("Auth-Key", "a1B2c3".into()));
        demande.corps = Some(b"{\"query\":\"x\"}".to_vec());
        let r = envoyer(demande).unwrap();
        assert_eq!((r.code, r.texte().as_str()), (404, "absen"));
        let recu = fil.join().unwrap();
        assert!(recu.starts_with("POST / HTTP/1.1"), "{recu}");
        assert!(recu.to_lowercase().contains("auth-key: a1b2c3"));
        assert!(recu.to_lowercase().contains("user-agent: vanguard"));
        // « curl -f » : seule une réponse 200 donne un texte.
        let (adresse, _) = serveur(b"HTTP/1.1 500 Erreur\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        assert_eq!(texte(&adresse, Duration::from_secs(5)), None);
        let (adresse, _) = serveur(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        assert_eq!(texte(&adresse, Duration::from_secs(5)).as_deref(), Some("ok"));
    }

    #[test]
    fn trop_gros_ou_injoignable() {
        let (adresse, _) = serveur(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789");
        let mut demande = Demande::get(&adresse, Duration::from_secs(5));
        demande.taille_max = 4;
        assert!(envoyer(demande).is_none());
        // Personne n'écoute : pas de réponse, sans attendre le délai entier.
        let libre = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let debut = Instant::now();
        assert!(envoyer(Demande::get(&format!("http://{libre}/"), Duration::from_secs(20))).is_none());
        assert!(debut.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn reception_comptee() {
        let (adresse, _) = serveur(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabcdef");
        let octets = AtomicU64::new(0);
        let fin = Instant::now() + Duration::from_secs(5);
        assert!(recevoir_en_comptant(&adresse, fin, &octets, &AtomicBool::new(false)));
        assert_eq!(octets.load(Ordering::Relaxed), 6);
    }

    /// Appelée depuis un moteur tokio déjà en marche (la surveillance) : pas de panique.
    #[test]
    fn depuis_un_code_asynchrone() {
        let (adresse, _) = serveur(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        let moteur = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let t = moteur.block_on(async move { texte(&adresse, Duration::from_secs(5)) });
        assert_eq!(t.as_deref(), Some("ok"));
    }
}
