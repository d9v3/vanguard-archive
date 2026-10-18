//! Wi-Fi : la protection du réseau où l'on est connecté, et le faux point d'accès (« jumeau maléfique ») qui copie
//! son nom. Un jumeau se montre souvent sans mot de passe, pour attirer les appareils et voir passer leur trafic :
//! même nom que le vrai réseau, protection plus faible. Un répéteur protégé comme le réseau principal n'alerte pas.

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

/// Nom d'un réseau que macOS 14 cache sans l'autorisation de localisation : sa protection se lit encore, mais il ne
/// se compare pas aux autres.
pub(super) const CACHE: &str = "<redacted>";

/// Un réseau Wi-Fi visible d'ici.
#[derive(Debug, PartialEq)]
pub(super) struct Visible {
    pub ssid: String,
    /// Protection telle que le système la nomme (« WPA2 », « WPA2-Personal », « Open », « Ouvert »…).
    pub securite: String,
    /// Le réseau où l'on est connecté.
    pub actif: bool,
}

/// Force d'une protection : 0 ouverte, 1 faible (WEP, WPA, chiffrée sans mot de passe), 2 WPA2, 3 WPA3 ou entreprise
/// (802.1X). Ce qui ne nomme aucune protection connue (« -- », « Open », « Ouvert », « None ») est ouvert, dans
/// toutes les langues.
pub(super) fn force(securite: &str) -> u8 {
    let s = securite.to_ascii_uppercase();
    if ["WPA3", "SAE", "802.1X", "ENTERPRISE", "ENTREPRISE"]
        .iter()
        .any(|m| s.contains(m))
    {
        3
    } else if s.contains("WPA2") {
        2
    } else {
        // 1 : WEP, WPA, ou chiffré sans mot de passe ; 0 : ouvert.
        u8::from(["WEP", "WPA", "OWE", "ENHANCED OPEN"].iter().any(|m| s.contains(m)))
    }
}

/// Protection du réseau où l'on est connecté. `admin` : commandes pour ouvrir l'administration de la box.
pub(super) fn securite(ssid: &str, libelle: &str, admin: &[&str]) -> Constat {
    let routeur = tr!(
        "Ouvrir l'admin du routeur > Wi-Fi > Sécurité : choisir « WPA2/WPA3 » ou « WPA3 »",
        "Open the router admin > Wi-Fi > Security: choose “WPA2/WPA3” or “WPA3”"
    );
    match force(libelle) {
        3 => ok("Wi-Fi", trf!("« {ssid} » en {libelle}.", "“{ssid}” uses {libelle}.")),
        2 => alerte(
            "Wi-Fi",
            Niveau::Info,
            trf!(
                "« {ssid} » en {libelle}. WPA3 serait mieux si le routeur le permet.",
                "“{ssid}” uses {libelle}. WPA3 would be better if the router allows it."
            ),
        )
        .manuel(routeur, admin),
        // Chiffré, mais sans mot de passe : n'importe qui peut s'y connecter, ou l'imiter.
        1 if libelle.to_ascii_uppercase().contains("OWE") || libelle.to_ascii_uppercase().contains("ENHANCED") => {
            alerte(
                "Wi-Fi",
                Niveau::Moyen,
                trf!(
                    "« {ssid} » est chiffré mais sans mot de passe ({libelle}) : n'importe qui peut s'y connecter.",
                    "“{ssid}” is encrypted but has no password ({libelle}): anyone can join it."
                ),
            )
            .manuel(routeur, admin)
        }
        1 => alerte(
            "Wi-Fi",
            Niveau::Eleve,
            trf!(
                "« {ssid} » utilise {libelle}, cassable en minutes.",
                "“{ssid}” uses {libelle}, crackable in minutes."
            ),
        )
        .manuel(routeur, admin),
        _ => alerte(
            "Wi-Fi",
            Niveau::Eleve,
            trf!(
                "« {ssid} » est un réseau ouvert : le trafic non chiffré est visible.",
                "“{ssid}” is an open network: unencrypted traffic is visible."
            ),
        )
        .manuel(routeur, admin),
    }
}

/// Un réseau qui porte le nom de celui où l'on est connecté, ouvert ou à la protection cassable, alors que le vrai
/// est en WPA2 ou mieux : la signature d'un jumeau maléfique.
pub(super) fn jumeau(visibles: &[Visible]) -> Option<Constat> {
    let actif = visibles.iter().find(|v| v.actif)?;
    if force(&actif.securite) < 2 || actif.ssid == CACHE {
        return None;
    }
    let faible = visibles
        .iter()
        .find(|v| !v.actif && v.ssid == actif.ssid && force(&v.securite) <= 1)?;
    let ssid = &actif.ssid;
    let protection = if force(&faible.securite) == 0 {
        tr!("sans mot de passe", "without a password").to_string()
    } else {
        trf!("en {}", "using {}", faible.securite)
    };
    Some(
        alerte(
            "Wi-Fi",
            Niveau::Moyen,
            trf!(
                "Un autre réseau « {ssid} », {protection}, est visible d'ici : un faux point d'accès (« jumeau maléfique ») copie souvent le nom d'un vrai réseau pour attirer les appareils et voir passer leur trafic.",
                "Another “{ssid}” network, {protection}, is visible from here: a fake access point (“evil twin”) often copies a real network's name to lure devices and see their traffic."
            ),
        )
        .manuel(
            tr!(
                "Ne t'y connecte pas, et refuse si un appareil propose de le rejoindre. Si c'est un de tes appareils (vieux répéteur, réseau invité), donne-lui un autre nom ou un mot de passe",
                "Do not connect to it, and decline if a device offers to join it. If it is one of your devices (old repeater, guest network), give it another name or a password"
            ),
            &[],
        ),
    )
}

/// `nmcli -t -e no -f ACTIVE,SECURITY,SSID dev wifi` : « yes:WPA2:Maison ». Le nom vient en dernier, il peut
/// contenir « : » ; un réseau caché (nom vide) est ignoré.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn lire_nmcli(sortie: &str) -> Vec<Visible> {
    sortie
        .lines()
        .filter_map(|l| {
            let mut champs = l.splitn(3, ':');
            let actif = champs.next()? == "yes";
            let securite = champs.next()?.to_string();
            let ssid = champs.next()?.to_string();
            (!ssid.is_empty()).then_some(Visible { ssid, securite, actif })
        })
        .collect()
}

/// `netsh wlan show networks` : un bloc par réseau (« SSID 1 : Maison », puis « Authentication : WPA2-Personal »,
/// « Authentification » en français). Le réseau connecté vient de `netsh wlan show interfaces`.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn lire_netsh(sortie: &str) -> Vec<Visible> {
    let mut reseaux: Vec<Visible> = Vec::new();
    for l in sortie.lines().map(str::trim) {
        if l.starts_with("SSID ")
            && let Some((_, nom)) = l.split_once(':')
        {
            reseaux.push(Visible {
                ssid: nom.trim().to_string(),
                securite: String::new(),
                actif: false,
            });
        } else if l.starts_with("Authenti")
            && let Some((_, protection)) = l.split_once(':')
            && let Some(r) = reseaux.last_mut()
        {
            r.securite = protection.trim().to_string();
        }
    }
    reseaux.retain(|r| !r.ssid.is_empty());
    reseaux
}

/// Un réseau de `system_profiler SPAirPortDataType` : son nom, s'il est le réseau connecté, ses lignes de détail.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct BlocMac<'a> {
    nom: String,
    actif: bool,
    details: Vec<&'a str>,
}

/// Sous « Current Network Information: » (le réseau connecté) et « Other Local Wi-Fi Networks: », un nom par réseau
/// puis ses détails (« Security: WPA2 Personal », « Channel: 36 (5GHz, 80MHz) »…), plus en retrait.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn blocs_system_profiler(sortie: &str) -> Vec<BlocMac<'_>> {
    let mut blocs: Vec<BlocMac> = Vec::new();
    let mut section: Option<(usize, bool)> = None;
    let mut retrait_nom: Option<usize> = None;
    for ligne in sortie.lines() {
        let l = ligne.trim();
        if l.is_empty() {
            continue;
        }
        let retrait = ligne.len() - ligne.trim_start().len();
        if section.is_some_and(|(r, _)| retrait <= r) {
            section = None;
        }
        if l == "Current Network Information:" || l == "Other Local Wi-Fi Networks:" {
            section = Some((retrait, l.starts_with("Current")));
            retrait_nom = None;
            continue;
        }
        let Some((_, actif)) = section else {
            continue;
        };
        if retrait == *retrait_nom.get_or_insert(retrait) {
            blocs.push(BlocMac {
                nom: l.trim_end_matches(':').to_string(),
                actif,
                details: Vec::new(),
            });
        } else if let Some(b) = blocs.last_mut() {
            b.details.push(l);
        }
    }
    blocs.retain(|b| !b.nom.is_empty());
    blocs
}

/// `system_profiler SPAirPortDataType` : la protection de chaque réseau (« Security: WPA2 Personal »).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn lire_system_profiler(sortie: &str) -> Vec<Visible> {
    blocs_system_profiler(sortie)
        .into_iter()
        .map(|b| Visible {
            securite: b
                .details
                .iter()
                .find_map(|d| d.strip_prefix("Security:"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default(),
            ssid: b.nom,
            actif: b.actif,
        })
        .collect()
}

/// Bande de fréquences d'un réseau Wi-Fi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Bande {
    G24,
    G5,
    G6,
}

impl Bande {
    /// D'après la fréquence, en MHz.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn de_frequence(mhz: u32) -> Option<Bande> {
        match mhz {
            2400..=2500 => Some(Bande::G24),
            4900..=5899 => Some(Bande::G5),
            5925..=7125 => Some(Bande::G6),
            _ => None,
        }
    }

    /// D'après le canal seul, quand le système ne dit pas la bande (Windows 10) : 1 à 14 en 2,4 GHz, au-delà en
    /// 5 GHz. Ces systèmes-là ne connaissent pas le 6 GHz, qui réutilise les petits numéros.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn de_canal(canal: u16) -> Option<Bande> {
        match canal {
            1..=14 => Some(Bande::G24),
            32..=177 => Some(Bande::G5),
            _ => None,
        }
    }

    /// D'après un texte du système : « 2.4 GHz », « 2,4 GHz », « 5 GHz », « 2GHz » (macOS)…
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    fn de_texte(t: &str) -> Option<Bande> {
        let t: String = t
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        if t.starts_with("2.4") || t.starts_with("2,4") || t.starts_with("2ghz") {
            Some(Bande::G24)
        } else if t.starts_with('5') {
            Some(Bande::G5)
        } else if t.starts_with('6') {
            Some(Bande::G6)
        } else {
            None
        }
    }

    pub(crate) fn libelle(self) -> &'static str {
        match self {
            Bande::G24 => tr!("2,4 GHz", "2.4 GHz"),
            Bande::G5 => "5 GHz",
            Bande::G6 => "6 GHz",
        }
    }
}

/// Canal d'une fréquence en MHz : 2412 → 1 (2484 → 14), 5180 → 36, 5955 → 1 (6 GHz).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn canal_de_frequence(mhz: u32) -> Option<u16> {
    let canal = match Bande::de_frequence(mhz)? {
        Bande::G24 if mhz == 2484 => 14,
        Bande::G24 => mhz.checked_sub(2407)? / 5,
        Bande::G5 => mhz.checked_sub(5000)? / 5,
        Bande::G6 => mhz.checked_sub(5950)? / 5,
    };
    u16::try_from(canal).ok()
}

/// Puissance reçue en dBm vers le pourcentage que montrent les systèmes : −100 dBm → 0 %, −50 dBm et mieux → 100 %.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn pourcentage(dbm: i32) -> u8 {
    u8::try_from(dbm.saturating_add(100).saturating_mul(2).clamp(0, 100)).unwrap_or(0)
}

/// Un réseau Wi-Fi entendu d'ici sur un canal : une borne. Un même réseau peut en avoir plusieurs (2,4 et 5 GHz,
/// répéteurs).
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Borne {
    /// Nom du réseau ; vide s'il est caché.
    pub ssid: String,
    pub bande: Bande,
    pub canal: u16,
    /// Force du signal reçu, de 0 à 100 %.
    pub signal: Option<u8>,
    /// La borne de la connexion actuelle.
    pub actif: bool,
}

/// `nmcli -t -e no -f ACTIVE,SIGNAL,FREQ,CHAN,SSID dev wifi list` : « yes:72:5180 MHz:36:Salon ». Le nom vient en
/// dernier, il peut contenir « : ».
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn bornes_nmcli(sortie: &str) -> Vec<Borne> {
    sortie
        .lines()
        .filter_map(|l| {
            let mut champs = l.splitn(5, ':');
            let actif = champs.next()? == "yes";
            let signal = champs.next()?.trim().parse().ok();
            let mhz: u32 = champs.next()?.split_whitespace().next()?.parse().ok()?;
            let canal = champs.next()?.trim().parse().ok()?;
            Some(Borne {
                ssid: champs.next().unwrap_or("").to_string(),
                bande: Bande::de_frequence(mhz)?,
                canal,
                signal,
                actif,
            })
        })
        .collect()
}

/// `iw dev <carte> scan dump` : le dernier balayage gardé par le noyau, lisible sans droits d'administrateur (utile
/// sans NetworkManager : iwd, systemd-networkd). Un bloc par borne, « BSS aa:bb:…(on wlan0) -- associated » pour
/// celle de la connexion, puis « freq: 5180 », « signal: -45.00 dBm », « SSID: Salon ».
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn bornes_iw(sortie: &str) -> Vec<Borne> {
    struct EnCours {
        actif: bool,
        mhz: Option<u32>,
        dbm: Option<i32>,
        ssid: String,
    }
    fn finir(b: EnCours) -> Option<Borne> {
        let mhz = b.mhz?;
        Some(Borne {
            ssid: b.ssid,
            bande: Bande::de_frequence(mhz)?,
            canal: canal_de_frequence(mhz)?,
            signal: b.dbm.map(pourcentage),
            actif: b.actif,
        })
    }
    let mut bornes = Vec::new();
    let mut courante: Option<EnCours> = None;
    for ligne in sortie.lines() {
        // Les éléments d'une borne sont en retrait (« \tBSS Load: ») : seul un « BSS » en début de ligne en ouvre une.
        if let Some(reste) = ligne.strip_prefix("BSS ") {
            bornes.extend(courante.take().and_then(finir));
            courante = Some(EnCours {
                actif: reste.contains("-- associated"),
                mhz: None,
                dbm: None,
                ssid: String::new(),
            });
            continue;
        }
        let Some(b) = courante.as_mut() else {
            continue;
        };
        let l = ligne.trim();
        if let Some(f) = l.strip_prefix("freq:") {
            // « 5180 » ou « 5180.0 » selon la version d'iw.
            b.mhz = f.trim().split('.').next().and_then(|n| n.parse().ok());
        } else if let Some(s) = l.strip_prefix("signal:") {
            // « -45.00 dBm » : le degré près suffit.
            b.dbm = s
                .split_whitespace()
                .next()
                .and_then(|n| n.split('.').next()?.parse().ok());
        } else if let Some(n) = l.strip_prefix("SSID:") {
            b.ssid = n.trim().to_string();
        }
    }
    bornes.extend(courante.and_then(finir));
    bornes
}

/// Une ligne « Clé : valeur » de netsh, la clé sans son numéro (« BSSID 1 » → « BSSID »). La valeur d'un BSSID
/// contient elle-même des « : ».
#[cfg_attr(not(windows), allow(dead_code))]
fn champ_netsh(ligne: &str) -> Option<(&str, &str)> {
    let (cle, valeur) = ligne.split_once(':')?;
    let cle = cle.trim();
    let cle = cle.trim_end_matches(|c: char| c.is_ascii_digit()).trim_end();
    Some((cle, valeur.trim()))
}

/// Une borne lue dans netsh, en cours de lecture : la bande peut manquer (Windows 10).
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Default)]
struct BorneNetsh {
    ssid: String,
    bande: Option<Bande>,
    canal: Option<u16>,
    signal: Option<u8>,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl BorneNetsh {
    /// Lit un champ de la borne ; faux si la ligne ne la concerne pas.
    fn lire(&mut self, cle: &str, valeur: &str) -> bool {
        match cle {
            "Signal" => self.signal = valeur.trim_end_matches('%').trim().parse().ok(),
            "Band" | "Bande" => self.bande = Bande::de_texte(valeur),
            "Channel" | "Canal" => self.canal = valeur.parse().ok(),
            _ => return false,
        }
        true
    }

    fn finir(self, actif: bool) -> Option<Borne> {
        let canal = self.canal?;
        Some(Borne {
            ssid: self.ssid,
            bande: self.bande.or_else(|| Bande::de_canal(canal))?,
            canal,
            signal: self.signal,
            actif,
        })
    }
}

/// `netsh wlan show networks mode=bssid` : sous « SSID 1 : Salon », un bloc par borne (« BSSID 1 : … ») avec
/// « Signal : 80% », « Band : 5 GHz » (Windows 11) et « Channel : 36 » ; en français « Bande » et « Canal ».
/// « Channel Utilization » (charge annoncée par la borne) n'est pas le canal.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn bornes_netsh(sortie: &str) -> Vec<Borne> {
    let mut bornes = Vec::new();
    let mut ssid = String::new();
    let mut courante: Option<BorneNetsh> = None;
    for ligne in sortie.lines() {
        let Some((cle, valeur)) = champ_netsh(ligne) else {
            continue;
        };
        match cle {
            "SSID" => {
                bornes.extend(courante.take().and_then(|b| b.finir(false)));
                ssid = valeur.to_string();
            }
            "BSSID" => {
                bornes.extend(courante.take().and_then(|b| b.finir(false)));
                courante = Some(BorneNetsh {
                    ssid: ssid.clone(),
                    ..BorneNetsh::default()
                });
            }
            _ => {
                if let Some(b) = courante.as_mut() {
                    b.lire(cle, valeur);
                }
            }
        }
    }
    bornes.extend(courante.and_then(|b| b.finir(false)));
    bornes
}

/// La borne de la connexion, dans `netsh wlan show interfaces` (« SSID : Salon », « Channel : 36 », « Signal : 80% »,
/// « Band : 5 GHz »).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn borne_active_netsh(sortie: &str) -> Option<Borne> {
    let mut b = BorneNetsh::default();
    for (cle, valeur) in sortie.lines().filter_map(champ_netsh) {
        if cle == "SSID" {
            b.ssid = valeur.to_string();
        } else {
            b.lire(cle, valeur);
        }
    }
    b.finir(true)
}

/// `system_profiler SPAirPortDataType` : « Channel: 36 (5GHz, 80MHz) » et, pour le réseau connecté (et parfois les
/// autres), « Signal / Noise: -50 dBm / -90 dBm ».
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn bornes_system_profiler(sortie: &str) -> Vec<Borne> {
    blocs_system_profiler(sortie)
        .into_iter()
        .filter_map(|b| {
            let (canal, reste) = b
                .details
                .iter()
                .find_map(|d| d.strip_prefix("Channel:"))?
                .trim()
                .split_once(' ')?;
            let canal: u16 = canal.parse().ok()?;
            let bande = Bande::de_texte(reste.trim_start_matches('('))?;
            let signal = b
                .details
                .iter()
                .find_map(|d| d.strip_prefix("Signal / Noise:"))
                .and_then(|s| s.split_whitespace().next()?.parse::<i32>().ok())
                .map(pourcentage);
            Some(Borne {
                ssid: if b.nom == CACHE { String::new() } else { b.nom },
                bande,
                canal,
                signal,
                actif: b.actif,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn visible(ssid: &str, securite: &str, actif: bool) -> Visible {
        Visible {
            ssid: ssid.into(),
            securite: securite.into(),
            actif,
        }
    }

    #[test]
    fn force_des_protections() {
        for (protection, attendue) in [
            ("--", 0),
            ("Open", 0),
            ("Ouvert", 0),
            ("None", 0),
            ("WEP", 1),
            ("WPA1", 1),
            ("OWE", 1),
            ("WPA1 WPA2", 2),
            ("WPA2-Personal", 2),
            ("WPA2 - Personnel", 2),
            ("WPA2/WPA3 Personal", 3),
            ("WPA3", 3),
            ("WPA2 802.1X", 3),
            ("WPA2-Enterprise", 3),
            ("WPA2 - Entreprise", 3),
        ] {
            assert_eq!(force(protection), attendue, "{protection}");
        }
    }

    #[test]
    fn jumeau_ouvert_repere() {
        let reseaux = [
            visible("Salon", "WPA2", true),
            visible("Salon", "WPA2 WPA3", false),
            visible("Voisin", "--", false),
        ];
        // Un répéteur protégé, un voisin ouvert : rien.
        assert!(jumeau(&reseaux).is_none());
        let reseaux = [visible("Salon", "WPA2", true), visible("Salon", "--", false)];
        let c = jumeau(&reseaux).expect("jumeau ouvert");
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("sans mot de passe"));
        // Le réseau connecté est lui-même ouvert : c'est sa propre alerte, pas celle d'un jumeau.
        assert!(jumeau(&[visible("Salon", "--", true), visible("Salon", "--", false)]).is_none());
    }

    #[test]
    fn reseaux_de_nmcli() {
        let sortie = "no:WPA2:Voisin\nyes:WPA2 WPA3:Salon\nno::\nno:--:Café:Wi-Fi\n";
        assert_eq!(
            lire_nmcli(sortie),
            [
                visible("Voisin", "WPA2", false),
                visible("Salon", "WPA2 WPA3", true),
                visible("Café:Wi-Fi", "--", false),
            ]
        );
    }

    #[test]
    fn reseaux_de_netsh_en_deux_langues() {
        let anglais = "Interface name : Wi-Fi\nThere are 2 networks currently visible.\n\nSSID 1 : Salon\n    Network type            : Infrastructure\n    Authentication          : WPA2-Personal\n    Encryption              : CCMP\n\nSSID 2 : Salon\n    Network type            : Infrastructure\n    Authentication          : Open\n    Encryption              : None\n";
        assert_eq!(
            lire_netsh(anglais),
            [
                visible("Salon", "WPA2-Personal", false),
                visible("Salon", "Open", false)
            ]
        );
        let francais = "SSID 1 : Salon\n    Type de réseau          : Infrastructure\n    Authentification        : Ouvert\n    Chiffrement             : Aucun\n";
        assert_eq!(lire_netsh(francais), [visible("Salon", "Ouvert", false)]);
    }

    #[test]
    fn reseaux_de_system_profiler() {
        let sortie = "Wi-Fi:

      Software Versions:
          CoreWLAN: 16.0 (1657)
      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4387)
          Status: Connected
          Current Network Information:
            Salon:
              PHY Mode: 802.11ax
              Channel: 36 (5GHz, 80MHz)
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -50 dBm / -90 dBm
          Other Local Wi-Fi Networks:
            Salon:
              PHY Mode: 802.11n
              Network Type: Infrastructure
              Security: None
            <redacted>:
              Security: WPA2 Personal
        awdl0:
          MAC Address: 12:34:56:78:9a:bc
";
        let reseaux = lire_system_profiler(sortie);
        assert_eq!(
            reseaux,
            [
                visible("Salon", "WPA2 Personal", true),
                visible("Salon", "None", false),
                visible(CACHE, "WPA2 Personal", false),
            ]
        );
        assert!(jumeau(&reseaux).is_some());
        // Noms cachés par macOS : rien ne se compare.
        assert!(jumeau(&[visible(CACHE, "WPA2 Personal", true), visible(CACHE, "None", false)]).is_none());
    }

    fn borne(ssid: &str, bande: Bande, canal: u16, signal: Option<u8>, actif: bool) -> Borne {
        Borne {
            ssid: ssid.into(),
            bande,
            canal,
            signal,
            actif,
        }
    }

    #[test]
    fn bandes_canaux_et_signal() {
        for (mhz, canal) in [(2412, 1), (2437, 6), (2484, 14), (5180, 36), (5745, 149), (5955, 1)] {
            assert_eq!(canal_de_frequence(mhz), Some(canal), "{mhz}");
        }
        assert_eq!(Bande::de_frequence(5955), Some(Bande::G6));
        assert_eq!(canal_de_frequence(900), None);
        assert_eq!(Bande::de_canal(11), Some(Bande::G24));
        assert_eq!(Bande::de_canal(36), Some(Bande::G5));
        assert_eq!(Bande::de_canal(0), None);
        for (texte, bande) in [
            ("2.4 GHz", Bande::G24),
            ("2,4 GHz", Bande::G24),
            ("2GHz, 20MHz)", Bande::G24),
            ("5 GHz", Bande::G5),
            ("5GHz, 80MHz)", Bande::G5),
            ("6 GHz", Bande::G6),
        ] {
            assert_eq!(Bande::de_texte(texte), Some(bande), "{texte}");
        }
        assert_eq!(pourcentage(-45), 100);
        assert_eq!(pourcentage(-75), 50);
        assert_eq!(pourcentage(-110), 0);
        assert_eq!(pourcentage(i32::MIN), 0);
    }

    #[test]
    fn bornes_de_nmcli() {
        let sortie = "no:40:2437 MHz:6:Voisin\nyes:72:5180 MHz:36:Salon\nno:15:2412 MHz:1:\nno:20:5955 MHz:1:Café:Wi-Fi\nligne abîmée\n";
        assert_eq!(
            bornes_nmcli(sortie),
            [
                borne("Voisin", Bande::G24, 6, Some(40), false),
                borne("Salon", Bande::G5, 36, Some(72), true),
                borne("", Bande::G24, 1, Some(15), false),
                borne("Café:Wi-Fi", Bande::G6, 1, Some(20), false),
            ]
        );
    }

    #[test]
    fn bornes_de_iw() {
        let sortie = "BSS 02:00:00:aa:bb:01(on wlan0) -- associated\n\tlast seen: 120 ms ago\n\tfreq: 5180.0\n\
                      \tsignal: -45.00 dBm\n\tSSID: Salon\n\tBSS Load:\n\t\t * station count: 3\n\
                      BSS 02:00:00:aa:bb:02(on wlan0)\n\tfreq: 2437\n\tsignal: -81.00 dBm\n\tSSID: Voisin\n\
                      BSS 02:00:00:aa:bb:03(on wlan0)\n\tsignal: -60.00 dBm\n";
        assert_eq!(
            bornes_iw(sortie),
            [
                borne("Salon", Bande::G5, 36, Some(100), true),
                borne("Voisin", Bande::G24, 6, Some(38), false),
            ]
        );
    }

    #[test]
    fn bornes_de_netsh_en_deux_langues() {
        let anglais = "Interface name : Wi-Fi\nThere are 2 networks currently visible.\n\nSSID 1 : Salon\n\
                       \x20   Network type            : Infrastructure\n    Authentication          : WPA2-Personal\n\
                       \x20   BSSID 1                 : 02:00:00:aa:bb:01\n         Signal             : 80%\n\
                       \x20        Radio type         : 802.11ax\n         Band               : 5 GHz\n\
                       \x20        Channel            : 36\n         Channel Utilization: 21 (8 %)\n\
                       \x20   BSSID 2                 : 02:00:00:aa:bb:02\n         Signal             : 60%\n\
                       \x20        Band               : 2.4 GHz\n         Channel            : 6\n\nSSID 2 : \n\
                       \x20   BSSID 1                 : 02:00:00:aa:bb:03\n         Signal             : 30%\n\
                       \x20        Channel            : 11\n";
        assert_eq!(
            bornes_netsh(anglais),
            [
                borne("Salon", Bande::G5, 36, Some(80), false),
                borne("Salon", Bande::G24, 6, Some(60), false),
                borne("", Bande::G24, 11, Some(30), false),
            ]
        );
        let francais = "SSID 1 : Salon\n    BSSID 1                 : 02:00:00:aa:bb:01\n         Signal             : 55%\n\
                        \x20        Bande              : 2,4 GHz\n         Canal              : 1\n\
                        \x20        Utilisation du canal : 10 (4 %)\n";
        assert_eq!(bornes_netsh(francais), [borne("Salon", Bande::G24, 1, Some(55), false)]);
        let interfaces = "    Name                   : Wi-Fi\n    State                  : connected\n\
                          \x20   SSID                   : Salon\n    BSSID                  : 02:00:00:aa:bb:01\n\
                          \x20   Band                   : 5 GHz\n    Channel                : 36\n\
                          \x20   Signal                 : 80%\n";
        assert_eq!(
            borne_active_netsh(interfaces),
            Some(borne("Salon", Bande::G5, 36, Some(80), true))
        );
        assert_eq!(borne_active_netsh("    State : disconnected\n"), None);
    }

    #[test]
    fn bornes_de_system_profiler() {
        let sortie = "Wi-Fi:
      Interfaces:
        en0:
          Current Network Information:
            Salon:
              PHY Mode: 802.11ax
              Channel: 36 (5GHz, 80MHz)
              Security: WPA2 Personal
              Signal / Noise: -50 dBm / -90 dBm
          Other Local Wi-Fi Networks:
            Voisin:
              Channel: 6 (2GHz, 20MHz)
              Security: WPA2 Personal
            <redacted>:
              Channel: 149 (5GHz, 80MHz)
              Signal / Noise: -70 dBm / -92 dBm
";
        assert_eq!(
            bornes_system_profiler(sortie),
            [
                borne("Salon", Bande::G5, 36, Some(100), true),
                borne("Voisin", Bande::G24, 6, None, false),
                borne("", Bande::G5, 149, Some(60), false),
            ]
        );
        // La lecture des protections, elle, est la même qu'avant.
        assert_eq!(lire_system_profiler(sortie).len(), 3);
    }
}
