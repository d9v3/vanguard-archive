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

/// `system_profiler SPAirPortDataType` : sous « Current Network Information: » (le réseau connecté) et « Other Local
/// Wi-Fi Networks: », un nom par réseau puis ses détails, dont « Security: WPA2 Personal ».
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn lire_system_profiler(sortie: &str) -> Vec<Visible> {
    let mut reseaux: Vec<Visible> = Vec::new();
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
            reseaux.push(Visible {
                ssid: l.trim_end_matches(':').to_string(),
                securite: String::new(),
                actif,
            });
        } else if let Some(protection) = l.strip_prefix("Security:")
            && let Some(r) = reseaux.last_mut()
        {
            r.securite = protection.trim().to_string();
        }
    }
    reseaux.retain(|r| !r.ssid.is_empty());
    reseaux
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
}
