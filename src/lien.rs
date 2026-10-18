//! Ce lien est-il dangereux ? Un lien reçu (courriel, texto, message) examiné sans jamais l'ouvrir. D'abord sur
//! l'ordinateur seul : lettres d'un autre alphabet qui imitent les nôtres (punycode), sous-domaine trompeur
//! (« paypal.com.exemple.xyz »), marque imitée ou mal orthographiée, raccourcisseur, adresse IP brute, « @ » qui
//! cache le vrai site, extension de domaine prisée des arnaques. Puis, après accord, car le nom de domaine sort de
//! l'ordinateur (jamais le lien entier) : l'âge du domaine (RDAP), et les listes publiques de sites dangereux
//! (URLhaus, téléchargée sans rien dire de ce qu'on cherche ; Spamhaus DBL et SURBL, par le DNS). Une liste qui ne
//! répond pas, ou qui refuse le DNS utilisé, est dite : jamais « pas listé ». Le verdict reste prudent : aucun outil
//! ne peut dire qu'un lien est sûr.

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::time::Duration;

use crate::risk::Niveau;
use crate::ui::*;

/// Un lien découpé. L'hôte est en minuscules, tel qu'écrit (punycode compris).
#[derive(Debug, PartialEq, Eq)]
struct Lien {
    /// « https », « http », « javascript »… ; vide si le lien n'en a pas (« exemple.com/page »).
    schema: String,
    /// Ce qui précède « @ » : un faux nom de site, qu'on lit à la place du vrai.
    utilisateur: Option<String>,
    hote: String,
    port: Option<u16>,
    /// Chemin, requête et ancre.
    reste: String,
}

/// Ce qu'on a vu dans le lien, et sa gravité.
#[derive(Debug, PartialEq, Eq)]
struct Signe {
    niveau: Niveau,
    texte: String,
}

fn signe(niveau: Niveau, texte: String) -> Signe {
    Signe { niveau, texte }
}

/// Une marque souvent imitée : ses mots dans un nom de domaine, et ses vrais domaines.
struct Marque {
    nom: &'static str,
    mots: &'static [&'static str],
    domaines: &'static [&'static str],
}

const MARQUES: &[Marque] = &[
    Marque {
        nom: "PayPal",
        mots: &["paypal"],
        domaines: &["paypal.com", "paypal.me", "paypal.ca", "paypal.fr"],
    },
    Marque {
        nom: "Apple",
        mots: &["apple", "icloud", "appleid", "itunes"],
        domaines: &["apple.com", "icloud.com", "me.com", "itunes.com", "apple.ca"],
    },
    Marque {
        nom: "Microsoft",
        mots: &[
            "microsoft",
            "outlook",
            "office365",
            "onedrive",
            "hotmail",
            "sharepoint",
            "microsoftonline",
        ],
        domaines: &[
            "microsoft.com",
            "live.com",
            "outlook.com",
            "office.com",
            "office365.com",
            "onedrive.com",
            "hotmail.com",
            "microsoftonline.com",
            "sharepoint.com",
            "windows.com",
            "msn.com",
            "skype.com",
            "bing.com",
            "xbox.com",
        ],
    },
    Marque {
        nom: "Google",
        mots: &["google", "gmail", "youtube"],
        domaines: &[
            "google.com",
            "google.ca",
            "google.fr",
            "gmail.com",
            "youtube.com",
            "youtu.be",
            "googleapis.com",
            "gstatic.com",
        ],
    },
    Marque {
        nom: "Meta",
        mots: &["facebook", "instagram", "whatsapp", "messenger"],
        domaines: &[
            "facebook.com",
            "fb.com",
            "instagram.com",
            "whatsapp.com",
            "messenger.com",
            "meta.com",
            "wa.me",
        ],
    },
    Marque {
        nom: "Amazon",
        mots: &["amazon"],
        domaines: &[
            "amazon.com",
            "amazon.ca",
            "amazon.fr",
            "amazon.co.uk",
            "amazon.de",
            "amzn.to",
            "amazonaws.com",
        ],
    },
    Marque {
        nom: "Netflix",
        mots: &["netflix"],
        domaines: &["netflix.com"],
    },
    Marque {
        nom: "Steam",
        mots: &["steam", "steampowered", "steamcommunity"],
        domaines: &[
            "steampowered.com",
            "steamcommunity.com",
            "steamstatic.com",
            "valvesoftware.com",
        ],
    },
    Marque {
        nom: "Epic Games",
        mots: &["epicgames", "fortnite"],
        domaines: &["epicgames.com", "fortnite.com", "unrealengine.com"],
    },
    Marque {
        nom: "Discord",
        mots: &["discord", "discordapp"],
        domaines: &[
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
            "discord.media",
        ],
    },
    Marque {
        nom: "Roblox",
        mots: &["roblox"],
        domaines: &["roblox.com"],
    },
    Marque {
        nom: "PlayStation",
        mots: &["playstation"],
        domaines: &["playstation.com", "sony.com"],
    },
    Marque {
        nom: "Nintendo",
        mots: &["nintendo"],
        domaines: &["nintendo.com", "nintendo.net"],
    },
    Marque {
        nom: "Spotify",
        mots: &["spotify"],
        domaines: &["spotify.com"],
    },
    Marque {
        nom: "Twitch",
        mots: &["twitch"],
        domaines: &["twitch.tv"],
    },
    Marque {
        nom: "eBay",
        mots: &["ebay"],
        domaines: &["ebay.com", "ebay.ca", "ebay.fr"],
    },
    Marque {
        nom: "LinkedIn",
        mots: &["linkedin"],
        domaines: &["linkedin.com", "lnkd.in"],
    },
    Marque {
        nom: "Dropbox",
        mots: &["dropbox"],
        domaines: &["dropbox.com"],
    },
    Marque {
        nom: "DocuSign",
        mots: &["docusign"],
        domaines: &["docusign.com", "docusign.net"],
    },
    Marque {
        nom: "Adobe",
        mots: &["adobe"],
        domaines: &["adobe.com"],
    },
    Marque {
        nom: "Airbnb",
        mots: &["airbnb"],
        domaines: &["airbnb.com", "airbnb.ca", "airbnb.fr"],
    },
    Marque {
        nom: "Telegram",
        mots: &["telegram"],
        domaines: &["telegram.org", "t.me"],
    },
    Marque {
        nom: "DHL",
        mots: &["dhl"],
        domaines: &["dhl.com", "dhl.ca", "dhl.fr", "dhl.de"],
    },
    Marque {
        nom: "FedEx",
        mots: &["fedex"],
        domaines: &["fedex.com"],
    },
    Marque {
        nom: "UPS",
        mots: &["ups"],
        domaines: &["ups.com"],
    },
    Marque {
        nom: "Postes Canada",
        mots: &["postescanada", "canadapost"],
        domaines: &["canadapost.ca", "postescanada.ca", "canadapost-postescanada.ca"],
    },
    Marque {
        nom: "La Poste",
        mots: &["laposte", "colissimo", "chronopost"],
        domaines: &["laposte.fr", "laposte.net", "colissimo.fr", "chronopost.fr"],
    },
    Marque {
        nom: "Desjardins",
        mots: &["desjardins"],
        domaines: &["desjardins.com"],
    },
    Marque {
        nom: "Banque Nationale",
        mots: &["bnc", "banquenationale"],
        domaines: &["bnc.ca", "nbc.ca"],
    },
    Marque {
        nom: "RBC",
        mots: &["rbc", "rbcroyalbank"],
        domaines: &["rbc.com", "rbcroyalbank.com"],
    },
    Marque {
        nom: "BMO",
        mots: &["bmo"],
        domaines: &["bmo.com"],
    },
    Marque {
        nom: "TD",
        mots: &["td", "tdbank", "tdcanadatrust"],
        domaines: &["td.com", "tdbank.com", "tdcanadatrust.com"],
    },
    Marque {
        nom: "Scotiabank",
        mots: &["scotiabank"],
        domaines: &["scotiabank.com"],
    },
    Marque {
        nom: "Tangerine",
        mots: &["tangerine"],
        domaines: &["tangerine.ca"],
    },
    Marque {
        nom: "Interac",
        mots: &["interac"],
        domaines: &["interac.ca"],
    },
    Marque {
        nom: "Hydro-Québec",
        mots: &["hydroquebec"],
        domaines: &["hydroquebec.com"],
    },
    Marque {
        nom: "Revenu Québec",
        mots: &["revenuquebec"],
        domaines: &["revenuquebec.ca"],
    },
    Marque {
        nom: "SAAQ",
        mots: &["saaq"],
        domaines: &["saaq.gouv.qc.ca"],
    },
    Marque {
        nom: "Agence du revenu du Canada",
        mots: &["cra", "craarc", "arccra"],
        domaines: &["canada.ca", "gc.ca"],
    },
    Marque {
        nom: "Vidéotron",
        mots: &["videotron"],
        domaines: &["videotron.com"],
    },
    Marque {
        nom: "Rogers",
        mots: &["rogers"],
        domaines: &["rogers.com"],
    },
    Marque {
        nom: "Telus",
        mots: &["telus"],
        domaines: &["telus.com"],
    },
    Marque {
        nom: "Ameli",
        mots: &["ameli"],
        domaines: &["ameli.fr"],
    },
    Marque {
        nom: "Impôts (France)",
        mots: &["impots", "dgfip"],
        domaines: &["impots.gouv.fr"],
    },
    Marque {
        nom: "ANTAI",
        mots: &["antai"],
        domaines: &["antai.gouv.fr"],
    },
    Marque {
        nom: "La Banque Postale",
        mots: &["labanquepostale"],
        domaines: &["labanquepostale.fr"],
    },
    Marque {
        nom: "Crédit Agricole",
        mots: &["creditagricole"],
        domaines: &["credit-agricole.fr", "credit-agricole.com"],
    },
    Marque {
        nom: "Mastercard",
        mots: &["mastercard"],
        domaines: &["mastercard.com", "mastercard.ca"],
    },
    Marque {
        nom: "American Express",
        mots: &["americanexpress", "amex"],
        domaines: &["americanexpress.com"],
    },
    Marque {
        nom: "Binance",
        mots: &["binance"],
        domaines: &["binance.com"],
    },
    Marque {
        nom: "Coinbase",
        mots: &["coinbase"],
        domaines: &["coinbase.com"],
    },
    Marque {
        nom: "MetaMask",
        mots: &["metamask"],
        domaines: &["metamask.io"],
    },
];

/// Mots qu'un faux site colle à une marque (« paypal-verification », « appleidlogin ») pour faire sérieux.
const MOTS_DE_PIEGE: &[&str] = &[
    "login",
    "signin",
    "logon",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "accounts",
    "update",
    "confirm",
    "support",
    "service",
    "services",
    "help",
    "auth",
    "wallet",
    "billing",
    "payment",
    "pay",
    "refund",
    "id",
    "online",
    "web",
    "app",
    "client",
    "clients",
    "compte",
    "connexion",
    "securite",
    "remboursement",
    "colis",
    "livraison",
    "delivery",
    "parcel",
    "tracking",
    "suivi",
    "gift",
    "free",
    "bonus",
    "promo",
];

/// Raccourcisseurs : on ne voit pas où mène le lien avant de l'ouvrir.
const RACCOURCISSEURS: &[&str] = &[
    "bit.ly",
    "bitly.com",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "v.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
    "s.id",
    "t.ly",
    "bl.ink",
    "x.co",
    "qrco.de",
    "tr.im",
    "clck.ru",
    "u.to",
    "short.gy",
    "lnk.bio",
];

/// Hébergements gratuits où chacun crée son site en une minute : le vrai propriétaire est le sous-domaine. Comptés
/// comme suffixes publics, comme le fait la liste publique des suffixes (« evil.github.io » appartient à « evil »).
const HEBERGEURS: &[&str] = &[
    "github.io",
    "gitlab.io",
    "blogspot.com",
    "wordpress.com",
    "wixsite.com",
    "weebly.com",
    "webflow.io",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "workers.dev",
    "web.app",
    "firebaseapp.com",
    "herokuapp.com",
    "glitch.me",
    "repl.co",
    "replit.app",
    "azurewebsites.net",
    "appspot.com",
    "000webhostapp.com",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "duckdns.org",
    "s3.amazonaws.com",
];

/// Suffixes publics à deux étiquettes les plus courants : le domaine de « shop.exemple.co.uk » est
/// « exemple.co.uk », pas « co.uk ». Une liste courte, pas la liste publique entière : un suffixe rare donne un
/// domaine trop court, ce qui rend l'analyse plus méfiante, jamais moins.
const SUFFIXES_DOUBLES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "com.au", "net.au", "org.au",
    "gov.au", "edu.au", "co.nz", "org.nz", "net.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "com.br", "net.br",
    "org.br", "gov.br", "com.mx", "org.mx", "gob.mx", "com.ar", "com.co", "com.pe", "co.za", "org.za", "com.cn",
    "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg", "com.my", "com.ph", "com.vn", "co.th", "co.id",
    "co.in", "net.in", "org.in", "co.kr", "or.kr", "com.tr", "com.ua", "com.pl", "com.ru", "com.sa", "com.eg",
    "com.ng", "co.ke", "co.il", "org.il", "gouv.fr", "asso.fr", "qc.ca", "on.ca", "bc.ca", "ab.ca", "gc.ca",
];

/// Extensions de domaine très prisées des arnaques (rapports de Spamhaus et d'Interisle), et .zip et .mov, qu'on
/// prend pour des noms de fichiers. Pas une preuve à elle seule : des sites honnêtes en ont.
const EXTENSIONS_A_RISQUE: &[&str] = &[
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "loan", "men", "rest", "cam",
    "icu", "bond", "sbs", "cfd", "quest", "lol", "buzz", "monster", "cyou", "fit", "support", "online", "site", "live",
    "shop", "store", "vip", "win", "date", "review",
];

/// Extensions de fichiers qui sont des programmes ou des installateurs.
const PROGRAMMES: &[&str] = &[
    "exe", "scr", "msi", "msix", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "jar",
    "apk", "dmg", "pkg", "app", "sh", "lnk", "iso", "img",
];

// ───────────────────────────── Découpage ─────────────────────────────

/// Le lien tel qu'on le colle, sans espaces ni guillemets autour, « désamorcé » remis en état : les alertes de
/// sécurité écrivent « hxxp://exemple[.]com » pour qu'on ne clique pas.
fn nettoyer(entree: &str) -> String {
    let t = entree
        .trim()
        .trim_matches(['<', '>', '"', '\'', '`', '«', '»', ' ', '\u{a0}'])
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[dot]", ".")
        .replace("[:]", ":");
    match t.get(..4) {
        Some(debut) if debut.eq_ignore_ascii_case("hxxp") => format!("http{}", &t[4..]),
        _ => t,
    }
}

fn decouper(adresse: &str) -> Option<Lien> {
    // « https: », « javascript: », « mailto: »… ; pas « exemple.com:8080 » (un port n'est pas un schéma).
    let (schema, reste) = match adresse.split_once(':') {
        Some((s, r))
            if s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && s.chars().all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
                && !r.starts_with(|c: char| c.is_ascii_digit()) =>
        {
            (s.to_ascii_lowercase(), r)
        }
        _ => (String::new(), adresse),
    };
    if !matches!(schema.as_str(), "" | "http" | "https") {
        // javascript:, data:, file:… : pas de site, c'est le lien lui-même qui agit.
        return Some(Lien {
            schema,
            utilisateur: None,
            hote: String::new(),
            port: None,
            reste: reste.to_string(),
        });
    }
    let reste = reste.strip_prefix("//").unwrap_or(reste);
    let fin = reste.find(['/', '?', '#', '\\']).unwrap_or(reste.len());
    let (autorite, suite) = reste.split_at(fin);
    let (utilisateur, hote_port) = match autorite.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h),
        None => (None, autorite),
    };
    let (hote, port) = if let Some(r) = hote_port.strip_prefix('[') {
        let (h, apres) = r.split_once(']')?;
        (h.to_string(), apres.strip_prefix(':').and_then(|p| p.parse().ok()))
    } else {
        match hote_port.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (h.to_string(), p.parse().ok()),
            _ => (hote_port.to_string(), None),
        }
    };
    let hote = hote.trim_end_matches('.').to_lowercase();
    // Un nom de site a au moins un point, ou c'est une adresse IP (parfois déguisée en un seul nombre) ; « bonjour »
    // n'est pas un lien.
    if hote.is_empty() || (!hote.contains('.') && !adresse_ip(&hote)) || hote.contains(char::is_whitespace) {
        return None;
    }
    Some(Lien {
        schema,
        utilisateur,
        hote,
        port,
        reste: suite.to_string(),
    })
}

/// Une adresse IP déguisée : un seul nombre (« 3232235777 ») ou des morceaux en hexadécimal (« 0x7f.0x0.0x0.0x1 »),
/// que les navigateurs comprennent comme une adresse.
fn ip_deguisee(hote: &str) -> bool {
    hote.parse::<IpAddr>().is_err()
        && hote.split('.').all(|e| {
            !e.is_empty()
                && (e.chars().all(|c| c.is_ascii_digit())
                    || e.strip_prefix("0x")
                        .is_some_and(|h| h.chars().all(|c| c.is_ascii_hexdigit())))
        })
}

/// L'hôte est-il une adresse IP, en clair ou déguisée ?
fn adresse_ip(hote: &str) -> bool {
    hote.parse::<IpAddr>().is_ok() || ip_deguisee(hote)
}

/// Ce qu'on vérifie en ligne : le domaine qu'on achète, ou l'adresse IP elle-même.
fn site(lien: &Lien) -> String {
    if adresse_ip(&lien.hote) {
        lien.hote.clone()
    } else {
        domaine_enregistrable(&lien.hote)
    }
}

/// Décode une étiquette punycode (« pple-43d », sans « xn-- ») : RFC 3492.
fn punycode(entree: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    let (basique, code) = entree.rsplit_once('-').unwrap_or(("", entree));
    if !basique.is_ascii() {
        return None;
    }
    let mut sortie: Vec<char> = basique.chars().collect();
    // Les noms de la RFC : n (caractère), i (rang), k (palier), t (seuil).
    let (mut caractere, mut rang, mut biais) = (128_u32, 0_u32, 72_u32);
    let mut octets = code.bytes().peekable();
    while octets.peek().is_some() {
        let ancien = rang;
        let mut poids = 1_u32;
        let mut palier = BASE;
        loop {
            let octet = octets.next()?;
            let chiffre = u32::from(match octet {
                b'a'..=b'z' => octet - b'a',
                b'A'..=b'Z' => octet - b'A',
                b'0'..=b'9' => octet - b'0' + 26,
                _ => return None,
            });
            rang = rang.checked_add(chiffre.checked_mul(poids)?)?;
            let seuil = if palier <= biais {
                TMIN
            } else if palier >= biais + TMAX {
                TMAX
            } else {
                palier - biais
            };
            if chiffre < seuil {
                break;
            }
            poids = poids.checked_mul(BASE - seuil)?;
            palier += BASE;
        }
        let nombre = u32::try_from(sortie.len()).ok()? + 1;
        biais = adapter(rang - ancien, nombre, ancien == 0);
        caractere = caractere.checked_add(rang / nombre)?;
        rang %= nombre;
        sortie.insert(usize::try_from(rang).ok()?, char::from_u32(caractere)?);
        rang += 1;
    }
    Some(sortie.into_iter().collect())
}

fn adapter(delta: u32, nombre: u32, premier: bool) -> u32 {
    let mut delta = if premier { delta / 700 } else { delta / 2 };
    delta += delta / nombre;
    let mut k = 0;
    while delta > ((36 - 1) * 26) / 2 {
        delta /= 36 - 1;
        k += 36;
    }
    k + (36 * delta) / (delta + 38)
}

/// L'hôte tel qu'un navigateur peut l'afficher : étiquettes punycode décodées.
fn affiche(hote: &str) -> String {
    hote.split('.')
        .map(|l| match l.strip_prefix("xn--").and_then(punycode) {
            Some(u) => u,
            None => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Le domaine qu'on achète (« exemple.co.uk » pour « shop.exemple.co.uk ») : le vrai propriétaire du site.
pub(crate) fn domaine_enregistrable(hote: &str) -> String {
    let hote = hote.trim_end_matches('.').to_lowercase();
    let etiquettes: Vec<&str> = hote.split('.').collect();
    let suffixe = SUFFIXES_DOUBLES
        .iter()
        .chain(HEBERGEURS)
        .filter(|s| hote.ends_with(&format!(".{s}")))
        .map(|s| s.matches('.').count() + 1)
        .max()
        .unwrap_or(1);
    let garde = (suffixe + 1).min(etiquettes.len());
    etiquettes[etiquettes.len() - garde..].join(".")
}

/// La lettre latine qu'imite un caractère d'un autre alphabet (cyrillique, grec, arménien, latin rare ou accentué,
/// pleine chasse). `None` : ni une lettre latine, ni une imitation connue.
fn latine(c: char) -> Option<char> {
    if c.is_ascii_alphanumeric() || c == '-' {
        return Some(c);
    }
    // Pleine chasse : « ａ » à « ｚ ».
    if ('\u{ff41}'..='\u{ff5a}').contains(&c) {
        return char::from_u32(u32::from(c) - 0xff41 + u32::from(b'a'));
    }
    Some(match c {
        'а' | 'α' | 'ɑ' | 'à' | 'á' | 'â' | 'ä' | 'ã' | 'å' => 'a',
        'Ь' | 'ƅ' => 'b',
        'с' | 'ϲ' | 'ç' => 'c',
        'ԁ' => 'd',
        'е' | 'é' | 'è' | 'ê' | 'ë' | 'ё' => 'e',
        'ɡ' | 'ց' => 'g',
        'һ' => 'h',
        'і' | 'ι' | 'ı' | 'ɩ' | 'î' | 'ï' | 'í' | 'ì' => 'i',
        'ј' | 'ϳ' | 'ȷ' => 'j',
        'к' | 'κ' => 'k',
        'ӏ' | 'ǀ' | 'ℓ' => 'l',
        'ո' | 'ñ' => 'n',
        'о' | 'ο' | 'ö' | 'ô' | 'ó' | 'ò' | 'õ' | 'օ' => 'o',
        'р' | 'ρ' => 'p',
        'ԛ' => 'q',
        'ѕ' => 's',
        'ս' | 'υ' | 'ü' | 'û' | 'ú' | 'ù' => 'u',
        'ν' => 'v',
        'ԝ' | 'ω' => 'w',
        'х' | 'χ' => 'x',
        'у' | 'ý' | 'ÿ' => 'y',
        _ => return None,
    })
}

/// Alphabet d'une lettre, pour repérer un nom qui en mélange deux (le signe des lettres déguisées).
fn alphabet(c: char) -> &'static str {
    match u32::from(c) {
        0x30..=0x39 | 0x61..=0x7a | 0x41..=0x5a | 0xc0..=0x24f | 0xff41..=0xff5a => "latin",
        0x370..=0x3ff => "grec",
        0x400..=0x52f => "cyrillique",
        0x530..=0x58f => "arménien",
        _ => "autre",
    }
}

// ───────────────────────────── Ressemblances ─────────────────────────────

/// Un mot ramené à ce qu'on lit d'un coup d'œil : chiffres pris pour des lettres, « rn » pour « m », « vv » pour
/// « w », tirets retirés.
fn normaliser(mot: &str) -> String {
    mot.replace("rn", "m")
        .replace("vv", "w")
        .chars()
        .filter(|c| *c != '-')
        .map(|c| match c {
            '0' => 'o',
            '1' | '|' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' => 'b',
            '9' => 'g',
            c => c,
        })
        .collect()
}

/// Deux lettres qu'on confond facilement à l'écran.
fn confondues(a: char, b: char) -> bool {
    let paire = |x: char, y: char| (a == x && b == y) || (a == y && b == x);
    paire('l', 'i') || paire('n', 'm') || paire('u', 'v') || paire('c', 'e') || paire('g', 'q') || paire('o', 'c')
}

/// Une seule retouche d'un mot à l'autre : lettre confondue, deux lettres voisines échangées, lettre doublée ou
/// perdue (« gooogle », « paypall ») ; n'importe quelle lettre en trop ou en moins pour les mots longs.
fn une_retouche(a: &[char], b: &[char], long: bool) -> bool {
    if a.len() == b.len() {
        let ecarts: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
        return match ecarts[..] {
            [i] => confondues(a[i], b[i]),
            [i, j] => j == i + 1 && a[i] == b[j] && a[j] == b[i],
            _ => false,
        };
    }
    if a.len().abs_diff(b.len()) != 1 {
        return false;
    }
    let (court, longue) = if a.len() < b.len() { (a, b) } else { (b, a) };
    let i = (0..court.len()).find(|&i| court[i] != longue[i]).unwrap_or(court.len());
    if court[i..] != longue[i + 1..] {
        return false;
    }
    long || (i > 0 && longue[i] == longue[i - 1]) || (i + 1 < longue.len() && longue[i] == longue[i + 1])
}

/// `mot` imite-t-il la marque `cle` sans l'être ? (« paypa1 », « arnazon », « micros0ft », « gooogle »). Les clés
/// courtes ne comptent qu'à l'identique après lecture rapide : « steam » ne doit pas attraper « stream ».
fn ressemble(mot: &str, cle: &str) -> bool {
    if mot == cle {
        return false;
    }
    let (m, c) = (normaliser(mot), normaliser(cle));
    if m == c {
        return true;
    }
    let (m, c): (Vec<char>, Vec<char>) = (m.chars().collect(), c.chars().collect());
    c.len() >= 6 && une_retouche(&m, &c, c.len() >= 8)
}

/// La marque dont parle une étiquette du nom (« paypal-secure », « appleidlogin », « secure-paypal »).
fn parle_de(etiquette: &str, cle: &str) -> bool {
    let morceaux: Vec<&str> = etiquette.split('-').collect();
    if morceaux.contains(&cle) {
        return true;
    }
    let colle = etiquette.replace('-', "");
    let piege = |reste: &str| {
        !reste.is_empty() && (MOTS_DE_PIEGE.contains(&reste) || reste.chars().all(|c| c.is_ascii_digit()))
    };
    colle == cle || colle.strip_prefix(cle).is_some_and(piege) || colle.strip_suffix(cle).is_some_and(piege)
}

/// Le nom est-il un vrai domaine de la marque, ou l'un de ses sous-domaines ?
fn officiel(hote: &str, marque: &Marque) -> bool {
    marque
        .domaines
        .iter()
        .any(|d| hote == *d || hote.ends_with(&format!(".{d}")))
}

// ───────────────────────────── Examen sur l'ordinateur ─────────────────────────────

/// Tout ce qui se voit dans le lien lui-même, sans rien demander à personne.
fn examiner(lien: &Lien) -> Vec<Signe> {
    let mut signes = Vec::new();
    match lien.schema.as_str() {
        "javascript" | "vbscript" | "data" => {
            signes.push(signe(
                Niveau::Critique,
                tr!(
                    "Ce lien n'ouvre pas un site : il exécute du code ou contient une page cachée.",
                    "This link does not open a site: it runs code or carries a hidden page."
                )
                .into(),
            ));
            return signes;
        }
        "" | "http" | "https" => {}
        autre => {
            signes.push(signe(
                Niveau::Eleve,
                trf!(
                    "Lien « {autre}: », pas une page web : il ouvre un fichier ou un programme.",
                    "“{autre}:” link, not a web page: it opens a file or a program."
                ),
            ));
            return signes;
        }
    }
    let hote = lien.hote.as_str();
    let domaine = domaine_enregistrable(hote);

    if let Some(faux) = &lien.utilisateur {
        signes.push(signe(
            Niveau::Eleve,
            trf!(
                "Un « @ » cache le vrai site : on lit « {faux} », mais le lien mène à {hote}.",
                "An “@” hides the real site: you read “{faux}”, but the link leads to {hote}."
            ),
        ));
    }

    // Adresse IP au lieu d'un nom, parfois déguisée en un seul nombre (« http://3232235777/ »).
    if let Ok(ip) = hote.parse::<IpAddr>() {
        let locale = match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
        signes.push(if locale {
            signe(
                Niveau::Info,
                tr!(
                    "Adresse d'un appareil de ton réseau (box, imprimante…), pas un site d'Internet.",
                    "Address of a device on your network (router, printer…), not an Internet site."
                )
                .into(),
            )
        } else {
            signe(
                Niveau::Eleve,
                tr!(
                    "Adresse IP brute au lieu d'un nom : les vrais services ont un nom, les pièges souvent pas.",
                    "Raw IP address instead of a name: real services have a name, traps often do not."
                )
                .into(),
            )
        });
    } else if ip_deguisee(hote) {
        signes.push(signe(
            Niveau::Eleve,
            tr!(
                "Adresse IP déguisée (en un seul nombre ou en hexadécimal) : une ruse pour cacher où mène le lien.",
                "Disguised IP address (one number or hexadecimal): a trick to hide where the link leads."
            )
            .into(),
        ));
    } else {
        signes.extend(examiner_nom(hote, &domaine));
    }

    if lien.schema == "http" {
        // Une page de connexion ou de paiement sans chiffrement : plus grave qu'une simple page.
        let reste = lien.reste.to_lowercase();
        let piege = MOTS_DE_PIEGE.iter().any(|m| m.len() > 4 && reste.contains(m));
        signes.push(signe(
            if piege { Niveau::Moyen } else { Niveau::Info },
            tr!(
                "Pas chiffré (http, sans « s ») : ce qu'on y tape peut être lu en route.",
                "Not encrypted (http, without “s”): what you type there can be read on the way."
            )
            .into(),
        ));
    }
    if let Some(p) = lien.port.filter(|p| ![80, 443].contains(p)) {
        signes.push(signe(
            Niveau::Info,
            trf!(
                "Port {p} : inhabituel pour un site.",
                "Port {p}: unusual for a website."
            ),
        ));
    }
    // Le dernier morceau du chemin, sans requête ni ancre : un programme à télécharger ?
    let chemin = lien.reste.split(['?', '#']).next().unwrap_or("");
    if let Some(ext) = chemin
        .rsplit('/')
        .next()
        .and_then(|f| f.rsplit_once('.'))
        .map(|(_, e)| e.to_lowercase())
        .filter(|e| PROGRAMMES.contains(&e.as_str()))
    {
        signes.push(signe(
            Niveau::Moyen,
            trf!(
                "Il télécharge un fichier .{ext} : un programme ou un installateur. Ne le lance pas s'il ne vient pas du site officiel.",
                "It downloads a .{ext} file: a program or an installer. Do not run it unless it comes from the official site."
            ),
        ));
    }
    let codes = lien.reste.matches('%').count();
    if lien.reste.len() > 200 || codes > 10 {
        signes.push(signe(
            Niveau::Info,
            tr!(
                "Lien très long ou rempli de caractères codés : souvent pour cacher sa vraie destination.",
                "Very long link or full of encoded characters: often to hide where it really goes."
            )
            .into(),
        ));
    }
    signes
}

/// Ce que dit le nom du site : lettres déguisées, marque imitée, sous-domaine trompeur, raccourcisseur, hébergement
/// gratuit, extension à risque.
fn examiner_nom(hote: &str, domaine: &str) -> Vec<Signe> {
    let mut signes = Vec::new();
    let lisible = affiche(hote);
    // Lettres d'un autre alphabet : le nom tel qu'on le lit, ramené aux lettres latines qu'il imite.
    if lisible != hote || !lisible.is_ascii() {
        let mut lu = String::new();
        let mut melange = false;
        let mut etranger = false;
        for etiquette in lisible.split('.') {
            let alphabets: std::collections::BTreeSet<&str> =
                etiquette.chars().filter(|c| *c != '-').map(alphabet).collect();
            melange |= alphabets.len() > 1;
            etranger |= alphabets.iter().any(|a| *a != "latin");
            if !lu.is_empty() {
                lu.push('.');
            }
            lu.extend(etiquette.chars().map(|c| latine(c).unwrap_or('?')));
        }
        let imitee = MARQUES.iter().find(|m| officiel(&lu, m));
        // Lettres accentuées seules (« québec.ca ») : un nom honnête, sauf s'il imite une marque.
        if imitee.is_none() && !melange && !etranger {
            return examiner_marques(hote, domaine, signes);
        }
        signes.push(match imitee {
            Some(m) => signe(
                Niveau::Critique,
                trf!(
                    "Lettres déguisées : s'affiche « {lisible} », se lit comme {} de {}, mais n'en est pas un.",
                    "Disguised letters: shows as “{lisible}”, reads like {} of {}, but is not.",
                    domaine_enregistrable(&lu),
                    m.nom
                ),
            ),
            None if melange => signe(
                Niveau::Eleve,
                trf!(
                    "Lettres de deux alphabets mélangées dans « {lisible} » : la ruse des faux sites qui imitent un vrai nom.",
                    "Letters from two alphabets mixed in “{lisible}”: the trick of fake sites imitating a real name."
                ),
            ),
            None => signe(
                Niveau::Info,
                trf!(
                    "Nom écrit dans un autre alphabet : « {lisible} ».",
                    "Name written in another alphabet: “{lisible}”."
                ),
            ),
        });
    }
    examiner_marques(hote, domaine, signes)
}

/// Marque imitée, sous-domaine trompeur, raccourcisseur, hébergement gratuit, extension à risque.
fn examiner_marques(hote: &str, domaine: &str, mut signes: Vec<Signe>) -> Vec<Signe> {
    let etiquettes: Vec<&str> = hote.split('.').collect();
    let n_domaine = domaine.split('.').count();
    let sous_domaine = &etiquettes[..etiquettes.len().saturating_sub(n_domaine)];
    let principal = domaine.split('.').next().unwrap_or(domaine);
    let mut marques_vues = Vec::new();
    for marque in MARQUES {
        if officiel(hote, marque) {
            signes.push(signe(
                Niveau::Info,
                trf!(
                    "Domaine officiel de {} : bon signe, mais un lien reçu peut quand même mener à une fausse page de connexion ailleurs.",
                    "Official {} domain: a good sign, but a link you received can still lead to a fake login page elsewhere.",
                    marque.nom
                ),
            ));
            continue;
        }
        let vrai = marque.domaines[0];
        // Sous-domaine trompeur : « paypal.com.exemple.xyz » commence par un vrai domaine.
        let sous = sous_domaine.join(".");
        if marque
            .domaines
            .iter()
            .any(|d| sous == *d || sous.ends_with(&format!(".{d}")) || sous.starts_with(&format!("{d}.")))
        {
            signes.push(signe(
                Niveau::Critique,
                trf!(
                    "Sous-domaine trompeur : commence par un nom de {}, mais le site est {domaine} (le vrai : {vrai}).",
                    "Misleading subdomain: starts with a {} name, but the site is {domaine} (the real one: {vrai}).",
                    marque.nom
                ),
            ));
            marques_vues.push(marque.nom);
            continue;
        }
        let mentionnee = etiquettes[..etiquettes.len().saturating_sub(1)]
            .iter()
            .any(|e| marque.mots.iter().any(|m| parle_de(e, m)));
        let imitee = marque.mots.iter().any(|m| ressemble(principal, m));
        if mentionnee || imitee {
            signes.push(signe(
                Niveau::Eleve,
                if imitee {
                    trf!(
                        "Ressemble à {} sans en être : « {principal} ». Le vrai site : {vrai}.",
                        "Looks like {} without being it: “{principal}”. The real site: {vrai}.",
                        marque.nom
                    )
                } else {
                    trf!(
                        "Utilise le nom de {} sans être un de ses sites (le vrai : {vrai}).",
                        "Uses the {} name without being one of its sites (the real one: {vrai}).",
                        marque.nom
                    )
                },
            ));
            marques_vues.push(marque.nom);
        }
    }

    // Un « .com » ou un « .ca » au milieu : on croit lire la fin du nom.
    if marques_vues.is_empty()
        && sous_domaine
            .iter()
            .any(|e| ["com", "net", "org", "ca", "fr", "gouv", "gov"].contains(e))
    {
        signes.push(signe(
            Niveau::Moyen,
            trf!(
                "Le nom contient une fausse fin (« .com », « .ca »…) avant le vrai domaine, qui est {domaine}.",
                "The name contains a fake ending (“.com”, “.ca”…) before the real domain, which is {domaine}."
            ),
        ));
    }
    if sous_domaine.len() >= 4 {
        signes.push(signe(
            Niveau::Moyen,
            trf!(
                "Beaucoup de sous-domaines : le vrai site est seulement {domaine}.",
                "Many subdomains: the real site is only {domaine}."
            ),
        ));
    }
    if RACCOURCISSEURS.contains(&domaine) {
        signes.push(signe(
            Niveau::Moyen,
            tr!(
                "Raccourcisseur de liens : on ne voit pas où il mène avant de l'ouvrir. Ne l'ouvre que si tu connais l'expéditeur.",
                "Link shortener: you cannot see where it leads before opening it. Only open it if you know the sender."
            )
            .into(),
        ));
    }
    if let Some(h) = HEBERGEURS.iter().find(|h| hote.ends_with(&format!(".{h}"))) {
        signes.push(signe(
            if marques_vues.is_empty() { Niveau::Info } else { Niveau::Eleve },
            trf!(
                "Site hébergé gratuitement ({h}) : n'importe qui en crée un en une minute, aucun service sérieux n'y demande ton mot de passe.",
                "Site on free hosting ({h}): anyone can create one in a minute, no serious service asks for your password there."
            ),
        ));
    }
    let extension = domaine.rsplit('.').next().unwrap_or("");
    if EXTENSIONS_A_RISQUE.contains(&extension) {
        signes.push(signe(
            Niveau::Moyen,
            trf!(
                "Extension .{extension}, très prisée des arnaques (pas une preuve à elle seule).",
                "“.{extension}” extension, very popular with scams (not proof on its own)."
            ),
        ));
    }
    signes
}

// ───────────────────────────── Vérifications en ligne ─────────────────────────────

/// Réponse d'une liste de sites dangereux.
#[derive(Debug, PartialEq)]
enum Inscription {
    /// Inscrit, avec la raison et sa gravité.
    Inscrit(String, Niveau),
    Absent,
    Impossible(String),
}

/// Cherche un domaine dans une liste par le DNS, après son entrée d'essai (toujours listée) : un DNS qui retire les
/// réponses de la liste (filtres, résolveur public refusé) rendrait « absent » mensonger.
fn chercher_dns(
    domaine: &str,
    zone: &str,
    essai: &str,
    refuse: impl Fn(&[Ipv4Addr]) -> bool,
    resoudre: impl Fn(&str) -> Option<Vec<Ipv4Addr>>,
) -> Result<Vec<Ipv4Addr>, String> {
    let muet = || tr!("ton DNS n'a pas répondu", "your DNS did not answer").to_string();
    let reponse = resoudre(&format!("{essai}.{zone}")).ok_or_else(muet)?;
    if reponse.is_empty() {
        return Err(tr!(
            "ton DNS ne transmet pas les réponses de cette liste",
            "your DNS does not pass this list's answers on"
        )
        .into());
    }
    if refuse(&reponse) {
        return Err(tr!(
            "la liste refuse ton DNS (résolveur public ou trop de demandes)",
            "the list refuses your DNS (public resolver or too many queries)"
        )
        .into());
    }
    let codes = resoudre(&format!("{domaine}.{zone}")).ok_or_else(muet)?;
    if refuse(&codes) {
        return Err(tr!("la liste a refusé la requête", "the list refused the query").into());
    }
    Ok(codes)
}

/// Spamhaus DBL : 127.0.1.x, la raison dans le dernier nombre ; 127.255.255.x et 127.0.1.255, des refus.
fn refus_dbl(codes: &[Ipv4Addr]) -> bool {
    codes
        .iter()
        .any(|c| c.octets()[..3] == [127, 255, 255] || *c == Ipv4Addr::new(127, 0, 1, 255))
}

fn sens_dbl(codes: &[Ipv4Addr]) -> Inscription {
    let pire = codes
        .iter()
        .filter_map(|c| {
            let [a, b, x, y] = c.octets();
            (a == 127 && b == 0 && x == 1).then_some(y)
        })
        .map(|y| match y {
            4 | 104 => (Niveau::Critique, tr!("hameçonnage", "phishing")),
            5 | 105 => (Niveau::Critique, tr!("logiciels malveillants", "malware")),
            6 | 106 => (Niveau::Critique, tr!("réseau de zombies (botnet)", "botnet")),
            103 => (Niveau::Eleve, tr!("redirection détournée", "abused redirector")),
            _ => (Niveau::Eleve, tr!("pourriel", "spam")),
        })
        .max_by_key(|(n, _)| *n);
    match pire {
        Some((niveau, raison)) => Inscription::Inscrit(raison.into(), niveau),
        None if codes.is_empty() => Inscription::Absent,
        None => Inscription::Impossible(tr!("réponse inconnue de la liste", "unknown answer from the list").into()),
    }
}

/// SURBL (multi) : 127.0.0.x, une case par liste dans le dernier nombre ; 127.0.0.1, un refus.
fn refus_surbl(codes: &[Ipv4Addr]) -> bool {
    codes.contains(&Ipv4Addr::LOCALHOST)
}

fn sens_surbl(codes: &[Ipv4Addr]) -> Inscription {
    let cases = codes
        .iter()
        .filter(|c| c.octets()[..3] == [127, 0, 0])
        .fold(0_u8, |acc, c| acc | c.octets()[3]);
    if cases & 8 != 0 {
        Inscription::Inscrit(tr!("hameçonnage", "phishing").into(), Niveau::Critique)
    } else if cases & 16 != 0 {
        Inscription::Inscrit(tr!("logiciels malveillants", "malware").into(), Niveau::Critique)
    } else if cases & 128 != 0 {
        Inscription::Inscrit(tr!("site piraté", "hacked site").into(), Niveau::Eleve)
    } else if cases & 64 != 0 {
        Inscription::Inscrit(tr!("pourriel, abus", "spam, abuse").into(), Niveau::Eleve)
    } else if codes.is_empty() {
        Inscription::Absent
    } else {
        Inscription::Impossible(tr!("réponse inconnue de la liste", "unknown answer from the list").into())
    }
}

/// Une liste d'URLhaus (abuse.ch), gardée 12 heures dans le dossier de Gardien. La télécharger ne dit à personne quel
/// lien on vérifie. Sans Internet, la copie d'avant sert encore.
fn liste_urlhaus(adresse: &str, nom: &str) -> Option<String> {
    let dossier = crate::reseau::dossier_local().join("urlhaus");
    let fichier = dossier.join(nom);
    let fraiche = std::fs::metadata(&fichier)
        .and_then(|m| m.modified())
        .is_ok_and(|t| t.elapsed().is_ok_and(|d| d < Duration::from_hours(12)));
    if !fraiche && std::fs::create_dir_all(&dossier).is_ok() {
        let provisoire = dossier.join(format!("{nom}.nouveau"));
        let telecharge = crate::commande::lancer(
            Command::new("curl")
                .args(["-sf", "--max-time", "40", "-o"])
                .arg(&provisoire)
                .arg(adresse),
            50,
        )
        .is_some_and(|r| r.code == Some(0));
        if telecharge {
            let _ = std::fs::rename(&provisoire, &fichier);
        } else {
            let _ = std::fs::remove_file(&provisoire);
        }
    }
    std::fs::read_to_string(&fichier).ok()
}

/// URLhaus : les noms consacrés aux logiciels malveillants (liste des hôtes), et les liens en service (liste des
/// liens), pour les hébergeurs partagés (GitHub, Discord…) où seul le lien exact compte.
fn chercher_urlhaus(lien: &Lien, adresse: &str, hotes: Option<&str>, liens: Option<&str>) -> Inscription {
    let (Some(hotes), Some(liens)) = (hotes, liens) else {
        return Inscription::Impossible(
            tr!(
                "listes impossibles à télécharger (pas d'Internet, ou curl absent)",
                "lists could not be downloaded (no Internet, or curl missing)"
            )
            .into(),
        );
    };
    let domaine = site(lien);
    let dans_hotes = hotes
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().nth(1))
        .any(|h| h.eq_ignore_ascii_case(&lien.hote) || h.eq_ignore_ascii_case(&domaine));
    let exact = adresse.trim_end_matches('/');
    let dans_liens = liens.lines().map(str::trim).any(|l| {
        l.trim_end_matches('/') == exact
            || (adresse_ip(&lien.hote) && decouper(l).is_some_and(|autre| autre.hote == lien.hote))
    });
    if dans_hotes || dans_liens {
        Inscription::Inscrit(
            tr!("distribue des logiciels malveillants", "distributes malware").into(),
            Niveau::Critique,
        )
    } else {
        Inscription::Absent
    }
}

/// Date d'enregistrement d'un domaine, dans une réponse RDAP.
fn date_d_enregistrement(json: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let date = v
        .get("events")?
        .as_array()?
        .iter()
        .find(|e| e.get("eventAction").and_then(serde_json::Value::as_str) == Some("registration"))?
        .get("eventDate")?
        .as_str()?;
    chrono::DateTime::parse_from_rfc3339(date)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}

/// Âge du domaine d'après son registre (RDAP ; rdap.org renvoie au bon registre).
fn age(domaine: &str) -> Result<(chrono::DateTime<chrono::Utc>, i64), String> {
    if !domaine
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(tr!("nom non latin : âge non vérifié", "non-Latin name: age not checked").into());
    }
    let r = crate::commande::lancer(
        Command::new("curl").args([
            "-sL",
            "--max-time",
            "12",
            "-H",
            "Accept: application/rdap+json",
            "-w",
            "\n%{http_code}",
            &format!("https://rdap.org/domain/{domaine}"),
        ]),
        18,
    )
    .ok_or_else(|| {
        tr!(
            "pas de réponse (pas d'Internet, ou curl absent)",
            "no answer (no Internet, or curl missing)"
        )
        .to_string()
    })?;
    let sortie = r.sortie.trim_end();
    let (corps, code) = sortie.rsplit_once('\n').unwrap_or(("", sortie));
    match code.trim() {
        "200" => {}
        "404" => {
            return Err(tr!(
                "inconnu du registre, ou registre sans RDAP",
                "unknown to the registry, or registry without RDAP"
            )
            .into());
        }
        autre => return Err(trf!("le registre a répondu {autre}", "the registry answered {autre}")),
    }
    let date = date_d_enregistrement(corps).ok_or_else(|| {
        tr!(
            "date d'enregistrement absente de la réponse",
            "registration date missing from the answer"
        )
        .to_string()
    })?;
    Ok((date, (chrono::Utc::now() - date).num_days()))
}

/// Ce que dit l'âge d'un domaine : un site piège a souvent quelques jours.
fn signe_d_age(date: chrono::DateTime<chrono::Utc>, jours: i64) -> Signe {
    let quand = date.format("%Y-%m-%d");
    if jours < 30 {
        signe(
            Niveau::Eleve,
            trf!(
                "Domaine tout neuf : créé le {quand}, il y a {jours} jour(s). Les sites pièges vivent rarement plus de quelques semaines.",
                "Brand-new domain: created on {quand}, {jours} day(s) ago. Trap sites rarely live more than a few weeks."
            ),
        )
    } else if jours < 180 {
        signe(
            Niveau::Moyen,
            trf!(
                "Domaine récent : créé le {quand}, il y a {} mois.",
                "Recent domain: created on {quand}, {} month(s) ago.",
                jours / 30
            ),
        )
    } else {
        signe(
            Niveau::Info,
            trf!(
                "Domaine créé le {quand}, il y a {} an(s) : bon signe, pas une garantie (un vieux site peut être piraté).",
                "Domain created on {quand}, {} year(s) ago: a good sign, not a guarantee (an old site can be hacked).",
                (jours / 365).max(1)
            ),
        )
    }
}

// ───────────────────────────── Affichage ─────────────────────────────

fn afficher_signe(s: &Signe) {
    let marque = match s.niveau {
        Niveau::Info => format!("{GRIS}ℹ{RESET}"),
        Niveau::Moyen => format!("{}⚠{RESET}", couleur(Niveau::Moyen)),
        n => format!("{}✖{RESET}", couleur(n)),
    };
    afficher_aligne(&format!("  {marque} "), &s.texte, 4, "");
}

fn afficher_reponse(liste: &str, reponse: &Inscription) {
    let (marque, texte) = match reponse {
        Inscription::Absent => (format!("{VERT}✔{RESET}"), tr!("pas listé", "not listed").to_string()),
        Inscription::Inscrit(raison, niveau) => (
            format!("{}✖{RESET}", couleur(*niveau)),
            trf!("listé : {raison}", "listed: {raison}"),
        ),
        Inscription::Impossible(raison) => (
            format!("{GRIS}?{RESET}"),
            trf!("impossible à vérifier : {raison}", "could not check: {raison}"),
        ),
    };
    afficher_aligne(&format!("  {marque} {} ", ajuster(liste, 13)), &texte, 18, "");
}

/// Les vérifications en ligne, en parallèle : (âge, URLhaus, Spamhaus DBL, SURBL). Aucune n'ouvre le site.
fn en_ligne(lien: &Lien, adresse: &str) -> Vec<(String, Inscription, Option<Signe>)> {
    // Un nom tapé en lettres non latines (« pаypal.com », avec un « а » cyrillique) : les listes et les registres ne
    // connaissent que sa forme « xn-- ». Le demander tel quel ferait répondre « absent » sans l'avoir vraiment cherché.
    if !lien.hote.is_ascii() {
        let raison = || {
            Inscription::Impossible(
                tr!(
                    "nom en lettres non latines, que les listes ne connaissent que sous sa forme « xn-- »",
                    "name in non-Latin letters, which the lists only know in its “xn--” form"
                )
                .into(),
            )
        };
        return [tr!("Âge", "Age"), "URLhaus", "Spamhaus DBL", "SURBL"]
            .into_iter()
            .map(|liste| (liste.to_string(), raison(), None))
            .collect();
    }
    let domaine = site(lien);
    // Une adresse IP n'a ni âge ni place dans les listes de noms : seule URLhaus la connaît.
    let ip = adresse_ip(&lien.hote);
    std::thread::scope(|s| {
        let urlhaus = s.spawn(|| {
            let hotes = liste_urlhaus("https://urlhaus.abuse.ch/downloads/hostfile/", "hotes.txt");
            let liens = liste_urlhaus("https://urlhaus.abuse.ch/downloads/text_online/", "liens.txt");
            chercher_urlhaus(lien, adresse, hotes.as_deref(), liens.as_deref())
        });
        let age = (!ip).then(|| s.spawn(|| age(&domaine)));
        let dbl = (!ip).then(|| {
            s.spawn(|| {
                chercher_dns(
                    &domaine,
                    "dbl.spamhaus.org",
                    "dbltest.com",
                    refus_dbl,
                    crate::listes_noires::resoudre,
                )
                .map_or_else(Inscription::Impossible, |c| sens_dbl(&c))
            })
        });
        let surbl = (!ip).then(|| {
            s.spawn(|| {
                chercher_dns(
                    &domaine,
                    "multi.surbl.org",
                    "test.surbl.org",
                    refus_surbl,
                    crate::listes_noires::resoudre,
                )
                .map_or_else(Inscription::Impossible, |c| sens_surbl(&c))
            })
        });
        let erreur = || Inscription::Impossible(tr!("erreur interne", "internal error").into());
        let mut resultats = Vec::new();
        if let Some(age) = age {
            resultats.push(match age.join() {
                Ok(Ok((date, jours))) => {
                    let s = signe_d_age(date, jours);
                    (tr!("Âge", "Age").to_string(), Inscription::Absent, Some(s))
                }
                Ok(Err(raison)) => (tr!("Âge", "Age").to_string(), Inscription::Impossible(raison), None),
                Err(_) => (tr!("Âge", "Age").to_string(), erreur(), None),
            });
        }
        resultats.push(("URLhaus".to_string(), urlhaus.join().unwrap_or_else(|_| erreur()), None));
        for (nom, fil) in [("Spamhaus DBL", dbl), ("SURBL", surbl)] {
            if let Some(fil) = fil {
                resultats.push((nom.to_string(), fil.join().unwrap_or_else(|_| erreur()), None));
            }
        }
        resultats
    })
}

/// Le verdict, prudent : jamais « sûr ».
fn verdict(pire: Option<Niveau>, incomplet: bool) -> String {
    let mut t = match pire {
        Some(Niveau::Critique | Niveau::Eleve) => tr!(
            "Dangereux : ne l'ouvre pas. Supprime le message. S'il parle d'un service que tu utilises, va sur son site en tapant toi-même son adresse.",
            "Dangerous: do not open it. Delete the message. If it mentions a service you use, go to its site by typing the address yourself."
        )
        .to_string(),
        Some(Niveau::Moyen) => tr!(
            "Douteux : ne l'ouvre que si tu connais l'expéditeur et que tu attendais ce lien. N'y tape jamais de mot de passe.",
            "Doubtful: only open it if you know the sender and were expecting this link. Never type a password there."
        )
        .to_string(),
        _ => tr!(
            "Rien de suspect trouvé. Ce n'est pas une garantie : un site piège tout neuf n'est encore sur aucune liste. Après un lien reçu, ne tape jamais de mot de passe : va sur le site en tapant son adresse toi-même.",
            "Nothing suspicious found. That is not a guarantee: a brand-new trap site is on no list yet. After a link you received, never type a password: go to the site by typing its address yourself."
        )
        .to_string(),
    };
    if incomplet {
        t += tr!(
            " Certaines vérifications en ligne n'ont pas pu se faire (voir plus haut) : rien n'est conclu pour elles.",
            " Some online checks could not be done (see above): nothing is concluded for them."
        );
    }
    t
}

/// Menu Antivirus et protection › Ce lien est-il dangereux ?, ou `gardien lien <adresse>`.
pub fn verifier(adresse: Option<&str>) {
    titre(tr!("Ce lien est-il dangereux ?", "Is this link dangerous?"));
    for ligne in envelopper(
        tr!(
            "Gardien examine le lien sans jamais l'ouvrir : le site n'est pas contacté.",
            "Gardien examines the link without ever opening it: the site is not contacted."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    let saisie = match adresse {
        Some(a) => a.to_string(),
        None => demander(tr!(
            "\n  Lien à vérifier (colle-le ici) : ",
            "\n  Link to check (paste it here): "
        )),
    };
    let propre = nettoyer(&saisie);
    let Some(lien) = decouper(&propre) else {
        trp!(
            "  ✖ Ce n'est pas un lien reconnu (il faut au moins un nom comme « exemple.com »).",
            "  ✖ This is not a recognized link (it needs at least a name like “example.com”)."
        );
        return;
    };
    println!();
    let montre: String = if propre.chars().count() > LARGEUR - 12 {
        propre.chars().take(LARGEUR - 13).chain(['…']).collect()
    } else {
        propre.clone()
    };
    println!("  {GRIS}{}{RESET} {montre}", ajuster(tr!("Lien", "Link"), 9));
    if !lien.hote.is_empty() {
        println!(
            "  {GRIS}{}{RESET} {ACCENT}{}{RESET}",
            ajuster(tr!("Vrai site", "Real site"), 9),
            site(&lien)
        );
        let lisible = affiche(&lien.hote);
        if lisible != lien.hote {
            println!("  {GRIS}{}{RESET} {lisible}", ajuster(tr!("S'affiche", "Shows as"), 9));
        }
    }
    println!();
    let mut signes = examiner(&lien);
    signes.sort_by_key(|s| std::cmp::Reverse(s.niveau));
    if signes.is_empty() {
        trp!(
            "  {GRIS}Rien de suspect dans le lien lui-même.{RESET}",
            "  {GRIS}Nothing suspicious in the link itself.{RESET}"
        );
    }
    for s in &signes {
        afficher_signe(s);
    }
    let mut pire = signes.iter().map(|s| s.niveau).filter(|n| *n > Niveau::Info).max();
    let mut incomplet = false;
    if !lien.hote.is_empty() {
        let domaine = site(&lien);
        println!();
        for ligne in envelopper(
            &trf!(
                "Vérifier aussi en ligne ? L'âge du domaine (son registre) et trois listes publiques de sites dangereux (URLhaus, Spamhaus, SURBL). Seul le nom {domaine} sortira de l'ordinateur, jamais le lien entier ; le site lui-même n'est pas contacté.",
                "Also check online? The domain's age (its registry) and three public lists of dangerous sites (URLhaus, Spamhaus, SURBL). Only the name {domaine} will leave the computer, never the whole link; the site itself is not contacted."
            ),
            LARGEUR - 2,
        ) {
            println!("  {ligne}");
        }
        if demander(tr!("  Continuer ? [o/N] : ", "  Continue? [y/N]: ")).oui() {
            println!();
            for (liste, reponse, signe) in en_ligne(&lien, &propre) {
                match &signe {
                    Some(s) => {
                        afficher_signe(s);
                        if s.niveau > Niveau::Info {
                            pire = pire.max(Some(s.niveau));
                        }
                    }
                    None => afficher_reponse(&liste, &reponse),
                }
                match reponse {
                    Inscription::Inscrit(_, n) => pire = pire.max(Some(n)),
                    Inscription::Impossible(_) => incomplet = true,
                    Inscription::Absent => {}
                }
            }
        } else {
            trp!("  Rien n'a été envoyé.", "  Nothing was sent.");
        }
    }
    println!();
    // Pas en vert quand des vérifications n'ont pas pu se faire, comme pour un fichier téléchargé.
    let couleur_verdict = match pire {
        Some(n) => couleur(n),
        None if incomplet => couleur(Niveau::Moyen),
        None => VERT,
    };
    for ligne in envelopper(&verdict(pire, incomplet), LARGEUR - 2) {
        println!("  {couleur_verdict}{ligne}{RESET}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lien(t: &str) -> Lien {
        decouper(&nettoyer(t)).unwrap()
    }

    fn niveaux(t: &str) -> Vec<Niveau> {
        examiner(&lien(t)).iter().map(|s| s.niveau).collect()
    }

    fn pire(t: &str) -> Option<Niveau> {
        niveaux(t).into_iter().max()
    }

    #[test]
    fn decoupage() {
        let l = lien("https://alice@exemple.com:8443/chemin?a=1#b");
        assert_eq!(l.schema, "https");
        assert_eq!(l.utilisateur.as_deref(), Some("alice"));
        assert_eq!(l.hote, "exemple.com");
        assert_eq!(l.port, Some(8443));
        assert_eq!(l.reste, "/chemin?a=1#b");
        // Sans schéma, désamorcé, en IPv6, avec un port collé au nom.
        assert_eq!(lien("Exemple.COM/page").hote, "exemple.com");
        assert_eq!(lien("hxxps://exemple[.]com/x").hote, "exemple.com");
        assert_eq!(lien("hxxps://exemple[.]com/x").schema, "https");
        assert_eq!(lien("http://[2001:db8::1]:8080/").hote, "2001:db8::1");
        assert_eq!(lien("exemple.com:8080").port, Some(8080));
        assert_eq!(lien("  <https://exemple.com>  ").hote, "exemple.com");
        // Pas des liens.
        assert!(decouper("bonjour").is_none());
        assert!(decouper("").is_none());
        assert_eq!(lien("javascript:alert(1)").schema, "javascript");
    }

    #[test]
    fn punycode_decode() {
        assert_eq!(punycode("pple-43d").as_deref(), Some("аpple"));
        assert_eq!(punycode("80ak6aa92e").as_deref(), Some("аррӏе"));
        assert_eq!(punycode("bcher-kva").as_deref(), Some("bücher"));
        assert_eq!(punycode("e1afmkfd").as_deref(), Some("пример"));
        assert_eq!(punycode("!!"), None);
        assert_eq!(affiche("www.xn--80ak6aa92e.com"), "www.аррӏе.com");
    }

    #[test]
    fn domaine_du_proprietaire() {
        assert_eq!(domaine_enregistrable("www.exemple.com"), "exemple.com");
        assert_eq!(domaine_enregistrable("shop.exemple.co.uk"), "exemple.co.uk");
        assert_eq!(domaine_enregistrable("faux-site.github.io"), "faux-site.github.io");
        assert_eq!(domaine_enregistrable("a.b.c.exemple.qc.ca"), "exemple.qc.ca");
        assert_eq!(domaine_enregistrable("exemple.com"), "exemple.com");
        assert_eq!(domaine_enregistrable("localhost"), "localhost");
    }

    #[test]
    fn ressemblances() {
        for (mot, cle) in [
            ("paypa1", "paypal"),
            ("arnazon", "amazon"),
            ("micros0ft", "microsoft"),
            ("gooogle", "google"),
            ("microsfot", "microsoft"),
            ("micrsoft", "microsoft"),
            ("netfl1x", "netflix"),
            ("app1e", "apple"),
        ] {
            assert!(ressemble(mot, cle), "{mot} devrait ressembler à {cle}");
        }
        for (mot, cle) in [
            ("stream", "steam"),
            ("finance", "binance"),
            ("paypal", "paypal"),
            ("pineapple", "apple"),
            ("goggles", "google"),
        ] {
            assert!(!ressemble(mot, cle), "{mot} ne devrait pas ressembler à {cle}");
        }
        assert!(parle_de("paypal-secure", "paypal"));
        assert!(parle_de("appleidlogin", "appleid"));
        assert!(parle_de("secure-login-td", "td"));
        assert!(parle_de("craarcrefund", "craarc"));
        assert!(!parle_de("pineapple", "apple"));
        assert!(!parle_de("ltd", "td"));
    }

    #[test]
    fn liens_dangereux() {
        // Sous-domaine trompeur, marque imitée, lettres déguisées, « @ », adresse IP brute ou déguisée.
        assert_eq!(
            pire("https://paypal.com.compte-secure.xyz/login"),
            Some(Niveau::Critique)
        );
        assert_eq!(pire("https://paypa1.com/"), Some(Niveau::Eleve));
        assert_eq!(pire("https://secure-paypal-verification.com/"), Some(Niveau::Eleve));
        assert_eq!(pire("https://xn--pple-43d.com/"), Some(Niveau::Critique));
        assert_eq!(pire("https://www.paypal.com@203.0.113.7/"), Some(Niveau::Eleve));
        assert_eq!(pire("http://203.0.113.7/facture.exe"), Some(Niveau::Eleve));
        assert_eq!(pire("http://3232235777/"), Some(Niveau::Eleve));
        assert_eq!(pire("javascript:alert(1)"), Some(Niveau::Critique));
        assert_eq!(
            pire("https://arc-remboursement.ca/"),
            None,
            "« arc » seul ne suffit pas"
        );
        assert_eq!(pire("https://cra-arc-refund.com/"), Some(Niveau::Eleve));
    }

    #[test]
    fn liens_douteux_ou_normaux() {
        // Raccourcisseur, extension à risque, téléchargement d'un programme : douteux.
        assert_eq!(pire("https://bit.ly/3AbCdEf"), Some(Niveau::Moyen));
        assert_eq!(pire("https://promo-chaussures.xyz/"), Some(Niveau::Moyen));
        assert_eq!(pire("https://exemple.com/outil.exe"), Some(Niveau::Moyen));
        // Vrais sites : au plus une information.
        assert!(pire("https://www.paypal.com/signin").is_none_or(|n| n == Niveau::Info));
        assert!(pire("https://accounts.google.com/").is_none_or(|n| n == Niveau::Info));
        assert!(pire("https://www.pineapple-recettes.com/").is_none());
        assert!(pire("https://www.desjardins.com/").is_none_or(|n| n == Niveau::Info));
        assert!(pire("https://xn--bcher-kva.example/").is_none_or(|n| n == Niveau::Info));
        // Un appareil du réseau : information seulement.
        assert_eq!(pire("http://192.168.1.1/"), Some(Niveau::Info));
        // Site gratuit qui parle d'une marque : très suspect.
        assert_eq!(pire("https://netflix-compte.github.io/"), Some(Niveau::Eleve));
    }

    #[test]
    fn listes_par_le_dns() {
        let ip = |t: &str| t.parse::<Ipv4Addr>().unwrap();
        // L'essai répond ; le domaine n'y est pas.
        let liste = |nom: &str| {
            Some(if nom.starts_with("dbltest.com.") {
                vec![ip("127.0.1.2")]
            } else {
                vec![]
            })
        };
        assert_eq!(
            chercher_dns("exemple.com", "dbl.spamhaus.org", "dbltest.com", refus_dbl, liste),
            Ok(vec![])
        );
        // Résolveur public : Spamhaus refuse, jamais « absent ».
        let public = |_: &str| Some(vec![ip("127.255.255.254")]);
        assert!(chercher_dns("exemple.com", "dbl.spamhaus.org", "dbltest.com", refus_dbl, public).is_err());
        // DNS qui retire les réponses (Google répond « nom inconnu ») : impossible.
        assert!(
            chercher_dns(
                "exemple.com",
                "dbl.spamhaus.org",
                "dbltest.com",
                refus_dbl,
                |_: &str| Some(vec![])
            )
            .is_err()
        );
        // SURBL refuse par 127.0.0.1.
        let refuse = |_: &str| Some(vec![Ipv4Addr::LOCALHOST]);
        assert!(chercher_dns("exemple.com", "multi.surbl.org", "test.surbl.org", refus_surbl, refuse).is_err());
        // Sens des codes.
        assert_eq!(
            sens_dbl(&[ip("127.0.1.4")]),
            Inscription::Inscrit("hameçonnage".into(), Niveau::Critique)
        );
        assert_eq!(sens_dbl(&[]), Inscription::Absent);
        assert_eq!(
            sens_surbl(&[ip("127.0.0.24")]),
            Inscription::Inscrit("hameçonnage".into(), Niveau::Critique)
        );
        assert_eq!(
            sens_surbl(&[ip("127.0.0.64")]),
            Inscription::Inscrit("pourriel, abus".into(), Niveau::Eleve)
        );
    }

    #[test]
    fn urlhaus_et_age() {
        let hotes = "# commentaire\n127.0.0.1\tpiege-exemple.com\n";
        let liens = "http://203.0.113.9:4444/i\nhttps://depot.example.org/alice/outil.zip\n";
        let l = lien("https://www.piege-exemple.com/a");
        assert!(matches!(
            chercher_urlhaus(&l, "https://www.piege-exemple.com/a", Some(hotes), Some(liens)),
            Inscription::Inscrit(_, Niveau::Critique)
        ));
        let l = lien("https://depot.example.org/alice/outil.zip");
        assert!(matches!(
            chercher_urlhaus(
                &l,
                "https://depot.example.org/alice/outil.zip",
                Some(hotes),
                Some(liens)
            ),
            Inscription::Inscrit(..)
        ));
        let l = lien("http://203.0.113.9/autre");
        assert!(matches!(
            chercher_urlhaus(&l, "http://203.0.113.9/autre", Some(hotes), Some(liens)),
            Inscription::Inscrit(..)
        ));
        let l = lien("https://depot.example.org/bob/autre.zip");
        assert_eq!(
            chercher_urlhaus(&l, "https://depot.example.org/bob/autre.zip", Some(hotes), Some(liens)),
            Inscription::Absent
        );
        assert!(matches!(
            chercher_urlhaus(&l, "https://x.example", None, Some(liens)),
            Inscription::Impossible(_)
        ));
        let json = r#"{"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},{"eventAction":"expiration","eventDate":"2030-08-13T04:00:00Z"}]}"#;
        let date = date_d_enregistrement(json).unwrap();
        assert_eq!(date.format("%Y-%m-%d").to_string(), "1995-08-14");
        assert_eq!(date_d_enregistrement("{}"), None);
        assert_eq!(signe_d_age(date, 3).niveau, Niveau::Eleve);
        assert_eq!(signe_d_age(date, 90).niveau, Niveau::Moyen);
        assert_eq!(signe_d_age(date, 9000).niveau, Niveau::Info);
    }

    #[test]
    fn nom_non_latin_jamais_dit_absent() {
        // Rien ne part sur le réseau : chaque liste dit qu'elle n'a pas pu chercher.
        let lien = decouper("https://pаypal.com/connexion").unwrap();
        let reponses = en_ligne(&lien, "https://pаypal.com/connexion");
        assert_eq!(reponses.len(), 4);
        assert!(reponses.iter().all(|(_, r, _)| matches!(r, Inscription::Impossible(_))));
    }
}
