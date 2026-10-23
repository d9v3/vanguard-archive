//! Ports en écoute de Windows lus sans PowerShell : `netstat -ano` (les sockets et le numéro de leur programme) et la
//! liste des processus de Windows (le nom de chaque programme), qui répondent en quelques millisecondes. Les
//! lectures par PowerShell (Get-NetTCPConnection, Get-NetUDPEndpoint) prenaient chacune 2 à 5 s au bilan, une
//! vingtaine de PowerShell démarrant ensemble. Les règles de blocage de Vanguard se lisent dans le registre.

use std::collections::HashMap;

/// Un port ouvert en écoute.
pub(crate) struct Ecoute {
    /// Adresse locale, sans crochets (« 0.0.0.0 », « :: », « 192.168.1.10 »).
    pub adresse: String,
    pub port: u16,
    /// Nom du programme sans « .exe », comme Get-Process (« svchost », « System ») ; vide s'il est inconnu.
    pub nom: String,
    pub tcp: bool,
}

/// Les ports en écoute (TCP et UDP) et le nom de leur programme. `None` si netstat ne répond pas : l'appelant se
/// replie alors sur PowerShell. Les noms viennent de la liste des processus de Windows (Toolhelp32).
pub(crate) fn ecoutes() -> Option<Vec<Ecoute>> {
    let sockets =
        crate::commande::lancer(crate::commande::systeme("netstat").arg("-ano"), 20).filter(|r| r.code == Some(0))?;
    let noms: HashMap<u32, String> = super::processus::liste().into_iter().map(|p| (p.pid, p.nom)).collect();
    let ecoutes = lire_netstat(&sockets.sortie)
        .into_iter()
        .map(|(adresse, port, pid, tcp)| Ecoute {
            nom: noms.get(&pid).cloned().unwrap_or_default(),
            adresse,
            port,
            tcp,
        })
        .collect::<Vec<_>>();
    // Une sortie sans aucun port n'est pas crédible (Windows écoute toujours sur 135 ou 445) : PowerShell la refera.
    (!ecoutes.is_empty()).then_some(ecoutes)
}

/// Les sockets en écoute de `netstat -ano` : (adresse, port, numéro du programme, TCP). Une ligne TCP en écoute a pour
/// adresse distante « 0.0.0.0:0 » ou « [::]:0 » (le mot « LISTENING » change avec la langue de Windows) ; une ligne
/// UDP n'a pas d'état, son adresse distante est « *:* ».
pub(crate) fn lire_netstat(sortie: &str) -> Vec<(String, u16, u32, bool)> {
    sortie
        .lines()
        .filter_map(|ligne| {
            let c: Vec<&str> = ligne.split_whitespace().collect();
            let tcp = match c.first()?.to_ascii_uppercase().as_str() {
                "TCP" if c.len() == 5 => true,
                "UDP" if c.len() == 4 => false,
                _ => return None,
            };
            let distante = c[2];
            if tcp && !matches!(distante, "0.0.0.0:0" | "[::]:0") {
                return None;
            }
            let (adresse, port) = c[1].rsplit_once(':')?;
            let adresse = adresse.trim_start_matches('[').trim_end_matches(']');
            Some((
                adresse.to_string(),
                port.parse().ok()?,
                c[c.len() - 1].parse().ok()?,
                tcp,
            ))
        })
        .collect()
}

/// Les ports TCP bloqués en entrée par une règle active de Vanguard, lus dans les règles du pare-feu du registre (celles
/// que New-NetFirewallRule écrit). `None` si la clé ne se lit pas : l'appelant demande alors à PowerShell.
pub(crate) fn ports_bloques() -> Option<Vec<u16>> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let cle = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules")
        .ok()?;
    Some(
        cle.enum_values()
            .flatten()
            .filter_map(|(_, valeur)| {
                let texte: String = winreg::types::FromRegValue::from_reg_value(&valeur).ok()?;
                port_bloque(&texte)
            })
            .collect(),
    )
}

/// Le port d'une règle du registre si c'est un blocage actif de Vanguard en entrée :
/// « v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=8080|Name=Vanguard : bloquer 8080| ».
pub(crate) fn port_bloque(regle: &str) -> Option<u16> {
    let champ = |cle: &str| regle.split('|').find_map(|c| c.strip_prefix(cle)?.strip_prefix('='));
    let nom = champ("Name")?;
    // Les règles posées sous l'ancien nom bloquent encore (`passage`).
    (crate::passage::les_deux("Vanguard : bloquer")
        .iter()
        .any(|p| nom.starts_with(p.as_str()))
        && champ("Active")?.eq_ignore_ascii_case("true")
        && champ("Action")?.eq_ignore_ascii_case("block")
        && champ("Dir")?.eq_ignore_ascii_case("in"))
    .then(|| champ("LPort")?.parse().ok())
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockets_de_netstat() {
        // Anglais et français : seul l'en-tête change, et l'état, qui ne sert pas.
        let sortie = "\r
Active Connections\r
\r
  Proto  Local Address          Foreign Address        State           PID\r
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1012\r
  TCP    [::]:445               [::]:0                 ÉCOUTE          4\r
  TCP    192.168.1.10:49712     20.42.65.92:443        ESTABLISHED     5560\r
  TCP    127.0.0.1:5354         0.0.0.0:0              LISTENING       3300\r
  UDP    0.0.0.0:123            *:*                                    1688\r
  UDP    [fe80::1%5]:1900       *:*                                    3300\r
";
        assert_eq!(
            lire_netstat(sortie),
            [
                ("0.0.0.0".to_string(), 135, 1012, true),
                ("::".to_string(), 445, 4, true),
                ("127.0.0.1".to_string(), 5354, 3300, true),
                ("0.0.0.0".to_string(), 123, 1688, false),
                ("fe80::1%5".to_string(), 1900, 3300, false),
            ]
        );
    }

    #[test]
    fn regles_de_blocage() {
        let regle = "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=8080|Name=Vanguard : bloquer 8080|";
        assert_eq!(port_bloque(regle), Some(8080));
        assert_eq!(port_bloque(&regle.replace("Active=TRUE", "Active=FALSE")), None);
        assert_eq!(port_bloque(&regle.replace("Dir=In", "Dir=Out")), None);
        assert_eq!(port_bloque(&regle.replace("Action=Block", "Action=Allow")), None);
        assert_eq!(port_bloque(&regle.replace("Name=Vanguard", "Name=Autre")), None);
        // Une règle d'avant le changement de nom bloque toujours.
        let ancienne = regle.replace("Vanguard", &crate::passage::ancien("Vanguard"));
        assert_eq!(port_bloque(&ancienne), Some(8080));
        assert_eq!(
            port_bloque("v2.32|Action=Block|Active=TRUE|Dir=In|Name=Vanguard : bloquer 8080|"),
            None
        );
    }
}

/// Sorties de netstat et règles du registre, au hasard : jamais de plantage, adresses sans crochets.
#[cfg(test)]
mod tests_au_hasard {
    use super::*;
    use proptest::prelude::*;

    fn texte() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                any::<String>(),
                "[ -~\\t\u{1b}é:|=\"\\[\\]]{0,60}",
                "  (TCP|UDP|tcp)  +[0-9.:\\[\\]a-f%]{1,30}  +[0-9.:\\[\\]*]{1,20}  +[A-ZÉ_]{0,12}  +[0-9]{0,8}",
                "\"[ -~]{0,20}\",\"[0-9]{0,8}\",\"[ -~]{0,10}\"",
            ],
            0..12,
        )
        .prop_map(|l| l.join("\r\n"))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lecteurs_sans_plantage(t in texte()) {
            for (adresse, _, _, _) in lire_netstat(&t) {
                prop_assert!(!adresse.starts_with('[') && !adresse.ends_with(']'));
            }
            for ligne in t.lines() {
                let _ = port_bloque(ligne);
            }
        }
    }
}
