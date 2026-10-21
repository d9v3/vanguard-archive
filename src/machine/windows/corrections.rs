//! Les corrections natives de Windows : une liste fermée, appliquée par les fonctions de Windows (registre…) dans
//! le processus élevé (`eleve`), au lieu d'un script PowerShell. Une correction se désigne par `vanguard:<id>` :
//! jamais du code ni une commande libre. C'est le processus élevé qui relit chaque ligne contre cette table : ce
//! que le clic d'administrateur autorise, ce sont ces gestes-là, et rien d'autre. Chaque entrée garde son
//! équivalent PowerShell, pour le chemin par script (liste mêlée à une commande PowerShell, Wine).

use crate::langue::anglais;

/// Devant chaque identifiant, pour qu'aucune commande PowerShell ne soit prise pour une correction native.
pub(crate) const PREFIXE: &str = "vanguard:";
/// Au-delà, une liste n'est pas celle d'une session de Vanguard.
pub(crate) const LIGNES_MAX: usize = 64;
/// Une ligne plus longue qu'un identifiant ne vient pas de Vanguard (le canal la refuse avant de l'analyser).
pub(crate) const LIGNE_MAX: usize = 256;

/// L'identifiant du point de restauration, passé en premier par `reparer::point_restauration`.
pub(crate) const POINT: &str = "vanguard:point-de-restauration";

/// Ce qu'une correction change.
pub(crate) enum Geste {
    /// Une valeur DWORD sous HKEY_LOCAL_MACHINE, mise à la donnée voulue (la clé est créée si elle manque).
    Dword {
        cle: &'static str,
        valeur: &'static str,
        donnee: u32,
    },
    /// Le point de restauration, avant de toucher au système.
    PointDeRestauration,
}

pub(crate) struct Correction {
    /// Sans le préfixe : `[a-z0-9-]`, 40 caractères au plus.
    pub id: &'static str,
    pub geste: Geste,
    fr: &'static str,
    en: &'static str,
    /// L'équivalent PowerShell, pour le chemin par script.
    powershell: fn() -> String,
}

impl Correction {
    /// Ce que la correction fait, en une phrase, montré par le processus élevé avant de la faire.
    pub(crate) fn texte(&self) -> &'static str {
        if anglais() { self.en } else { self.fr }
    }

    pub(crate) fn powershell(&self) -> String {
        (self.powershell)()
    }
}

const WDIGEST: &str = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
const RDP_TCP: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

/// La liste fermée. Chaque entrée renforce la sécurité ; aucune ne coupe un pare-feu, Defender, BitLocker ou l'UAC,
/// ni une connexion à distance en cours (`rdp-nla` exige une authentification, il ne ferme pas le Bureau à distance).
static TABLE: &[Correction] = &[
    Correction {
        id: "point-de-restauration",
        geste: Geste::PointDeRestauration,
        fr: "Point de restauration, pour pouvoir revenir en arrière",
        en: "Restore point, so you can go back",
        powershell: crate::reparer::point_restauration_powershell,
    },
    Correction {
        id: "wdigest-coupe",
        geste: Geste::Dword {
            cle: WDIGEST,
            valeur: "UseLogonCredential",
            donnee: 0,
        },
        fr: "Couper WDigest : plus de mot de passe en clair dans la mémoire (HKLM\\…\\WDigest, UseLogonCredential = 0)",
        en: "Turn WDigest off: no more clear-text password in memory (HKLM\\...\\WDigest, UseLogonCredential = 0)",
        powershell: || {
            format!("Set-ItemProperty -LiteralPath 'HKLM:\\{WDIGEST}' -Name UseLogonCredential -Value 0 -Type DWord")
        },
    },
    Correction {
        id: "rdp-nla",
        geste: Geste::Dword {
            cle: RDP_TCP,
            valeur: "UserAuthentication",
            donnee: 1,
        },
        fr: "Exiger l'authentification au niveau réseau (NLA) pour le Bureau à distance (HKLM\\…\\RDP-Tcp, UserAuthentication = 1)",
        en: "Require Network Level Authentication (NLA) for Remote Desktop (HKLM\\...\\RDP-Tcp, UserAuthentication = 1)",
        powershell: || {
            format!("Set-ItemProperty -LiteralPath 'HKLM:\\{RDP_TCP}' -Name UserAuthentication -Value 1 -Type DWord")
        },
    },
];

/// L'identifiant complet d'une correction de la table (« vanguard:wdigest-coupe »), à mettre dans un `Correctif`.
pub(crate) fn id(court: &str) -> String {
    debug_assert!(
        TABLE.iter().any(|c| c.id == court),
        "correction native inconnue : {court}"
    );
    format!("{PREFIXE}{court}")
}

/// La correction désignée par une ligne, si et seulement si la ligne est exactement un identifiant de la table :
/// le préfixe, puis des minuscules, chiffres et tirets, rien d'autre (ni espace, ni paramètre, ni fin de ligne).
pub(crate) fn analyser(ligne: &str) -> Option<&'static Correction> {
    if ligne.len() > LIGNE_MAX {
        return None;
    }
    let court = ligne.strip_prefix(PREFIXE)?;
    let forme = !court.is_empty()
        && court.len() <= 40
        && court
            .bytes()
            .all(|o| o.is_ascii_lowercase() || o.is_ascii_digit() || o == b'-');
    if !forme {
        return None;
    }
    TABLE.iter().find(|c| c.id == court)
}

/// Toutes les commandes de ces correctifs sont-elles des corrections natives ? Alors tout passe par le processus
/// élevé en Rust ; une seule commande PowerShell, et tout passe par le script.
pub(crate) fn toutes_natives(correctifs: &[Vec<String>]) -> bool {
    !correctifs.is_empty()
        && correctifs
            .iter()
            .all(|c| !c.is_empty() && c.iter().all(|l| analyser(l).is_some()))
}

/// La liste telle que le processus élevé la recevra, validée ligne à ligne, dans l'ordre ; `None` dès qu'une ligne
/// n'est pas une correction de la table, qu'il y en a trop, ou qu'une revient deux fois (une liste de Vanguard
/// n'applique jamais deux fois le même geste : une répétition est un signe de bricolage).
pub(crate) fn valider(lignes: &[String]) -> Option<Vec<&'static Correction>> {
    if lignes.is_empty() || lignes.len() > LIGNES_MAX {
        return None;
    }
    let mut vues = std::collections::HashSet::new();
    lignes
        .iter()
        .map(|l| analyser(l).filter(|c| vues.insert(c.id)))
        .collect()
}

/// Pour le chemin par script : chaque correction native remplacée par son équivalent PowerShell, le reste inchangé.
pub(crate) fn en_powershell(correctifs: &[Vec<String>]) -> Vec<Vec<String>> {
    correctifs
        .iter()
        .map(|c| {
            c.iter()
                .map(|l| analyser(l).map_or_else(|| l.clone(), Correction::powershell))
                .collect()
        })
        .collect()
}

/// Le texte à montrer pour une commande : la phrase d'une correction native, la commande elle-même sinon.
pub(crate) fn affichable(commande: &str) -> String {
    analyser(commande).map_or_else(|| crate::ui::commande_affichable(commande), |c| c.texte().to_string())
}

/// Résultat d'une correction appliquée par le processus élevé : réussie ou non, et la valeur d'avant quand il y en
/// a une (« 1 », « absent »), pour l'annuler exactement.
pub(crate) struct Resultat {
    pub reussi: bool,
    pub avant: Option<String>,
    pub raison: String,
}

/// Applique une correction de la table avec les droits du processus (élevé) : la valeur d'avant est lue, la nouvelle
/// écrite puis relue, et seul ce qui se relit tel qu'écrit compte comme réussi.
pub(crate) fn appliquer(c: &Correction) -> Resultat {
    match c.geste {
        Geste::Dword { cle, valeur, donnee } => ecrire_dword(cle, valeur, donnee),
        Geste::PointDeRestauration => {
            let (reussi, raison) = super::eleve::point_de_restauration();
            Resultat {
                reussi,
                avant: None,
                raison,
            }
        }
    }
}

/// La valeur d'avant, telle qu'on saura la remettre : un DWORD (« 1 »), « absent » (valeur absente) ou « clé absente ».
/// Autre type, ou lecture en échec : rien n'est changé, puisque le retour arrière effacerait une valeur qui existait.
fn valeur_d_avant(racine: &winreg::RegKey, cle: &str, valeur: &str) -> Result<String, String> {
    use std::io::ErrorKind::NotFound;
    use winreg::enums::{KEY_READ, RegType};
    let k = match racine.open_subkey_with_flags(cle, KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == NotFound => return Ok("clé absente".into()),
        Err(e) => return Err(format!("valeur d'avant illisible, rien changé : {e}")),
    };
    match k.get_raw_value(valeur) {
        Err(e) if e.kind() == NotFound => Ok("absent".into()),
        Err(e) => Err(format!("valeur d'avant illisible, rien changé : {e}")),
        Ok(brute) if brute.vtype == RegType::REG_DWORD && brute.bytes.len() == 4 => {
            let octets: [u8; 4] = brute.bytes[..4].try_into().unwrap_or_default();
            Ok(u32::from_le_bytes(octets).to_string())
        }
        Ok(brute) => Err(format!(
            "valeur d'avant de type inattendu ({:?}), rien changé",
            brute.vtype
        )),
    }
}

fn ecrire_dword(cle: &str, valeur: &str, donnee: u32) -> Resultat {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    let racine = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    let avant = match valeur_d_avant(&racine, cle, valeur) {
        Ok(avant) => avant,
        Err(raison) => {
            return Resultat {
                reussi: false,
                avant: None,
                raison,
            };
        }
    };
    // RegCreateKeyEx ouvre une clé qui existe sans toucher à ses valeurs (au contraire de New-Item -Force).
    let ecrit = racine
        .create_subkey_with_flags(cle, KEY_READ | KEY_WRITE)
        .and_then(|(k, _)| k.set_value(valeur, &donnee).map(|()| k))
        .and_then(|k| k.get_value::<u32, _>(valeur));
    match ecrit {
        Ok(relu) if relu == donnee => Resultat {
            reussi: true,
            avant: Some(avant),
            raison: String::new(),
        },
        Ok(relu) => Resultat {
            reussi: false,
            avant: Some(avant),
            raison: format!("relu {relu} au lieu de {donnee}"),
        },
        Err(e) => Resultat {
            reussi: false,
            avant: Some(avant),
            raison: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lecture seule : rien n'est écrit dans le registre de la machine de test.
    #[test]
    fn valeur_d_avant_exacte_ou_refus() {
        let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
        let nt = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        assert_eq!(
            valeur_d_avant(&hklm, r"SOFTWARE\VanguardInexistante", "X").unwrap(),
            "clé absente"
        );
        assert_eq!(valeur_d_avant(&hklm, nt, "VanguardInexistante").unwrap(), "absent");
        // Une chaîne (REG_SZ) ne se remet pas comme un DWORD : refusée, rien n'est changé.
        assert!(
            valeur_d_avant(&hklm, nt, "ProductName")
                .unwrap_err()
                .contains("type inattendu")
        );
    }

    #[test]
    fn la_table_est_bien_formee() {
        for c in TABLE {
            assert!(analyser(&id(c.id)).is_some_and(|t| std::ptr::eq(t, c)), "{}", c.id);
            assert!(!c.powershell().is_empty() && !c.texte().is_empty());
            // Aucun geste de la table n'affaiblit la sécurité : les valeurs écrites sont celles du durcissement.
            if let Geste::Dword { valeur, donnee, .. } = c.geste {
                assert!(matches!(
                    (valeur, donnee),
                    ("UseLogonCredential", 0) | ("UserAuthentication", 1)
                ));
            }
        }
        assert_eq!(analyser(POINT).map(|c| c.id), Some("point-de-restauration"));
    }

    /// Tout ce qui n'est pas exactement un identifiant de la table est refusé : du PowerShell, un identifiant
    /// décoré, un paramètre, une casse différente, un caractère de contrôle, une ligne trop longue.
    #[test]
    fn les_lignes_hostiles_sont_refusees() {
        for hostile in [
            "",
            "vanguard:",
            "Set-ItemProperty HKLM:\\x -Name y -Value 1",
            "vanguard:wdigest-coupe; Remove-Item C:\\",
            "vanguard:wdigest-coupe ",
            " vanguard:wdigest-coupe",
            "vanguard:wdigest-coupe\n",
            "vanguard:wdigest-coupe\r",
            "vanguard:wdigest-coupe\0",
            "vanguard:WDIGEST-COUPE",
            "vanguard:wdigest-coupe 1",
            "vanguard:wdigest-coupe=1",
            "vanguard:../wdigest-coupe",
            "vanguard:inconnue",
            "vanguard:uac-coupe",
            "Vanguard:wdigest-coupe",
            "vanguard:vanguard:wdigest-coupe",
            "vanguard:wdigést-coupe",
        ] {
            assert!(analyser(hostile).is_none(), "{hostile:?}");
        }
        let longue = format!("vanguard:{}", "a".repeat(41));
        assert!(analyser(&longue).is_none());
        let tres_longue = format!("vanguard:wdigest-coupe{}", " ".repeat(LIGNE_MAX));
        assert!(analyser(&tres_longue).is_none());
    }

    #[test]
    fn la_liste_est_validee_entiere_ou_pas_du_tout() {
        let bonne = vec![POINT.to_string(), id("wdigest-coupe"), id("rdp-nla")];
        let v = valider(&bonne).unwrap();
        assert_eq!(
            v.iter().map(|c| c.id).collect::<Vec<_>>(),
            ["point-de-restauration", "wdigest-coupe", "rdp-nla"]
        );
        // Une seule ligne étrangère, et rien ne passe.
        let mut melee = bonne.clone();
        melee.push("Disable-LocalUser alice".into());
        assert!(valider(&melee).is_none());
        // Une répétition non plus, ni une liste vide ou trop longue.
        assert!(valider(&[id("rdp-nla"), id("rdp-nla")]).is_none());
        assert!(valider(&[]).is_none());
        assert!(valider(&vec![id("rdp-nla"); LIGNES_MAX + 1]).is_none());
    }

    #[test]
    fn liste_mixte_vers_powershell() {
        let correctifs = vec![
            vec![POINT.to_string()],
            vec![id("rdp-nla")],
            vec!["Update-MpSignature".to_string()],
        ];
        assert!(!toutes_natives(&correctifs));
        assert!(toutes_natives(&correctifs[..2]));
        assert!(!toutes_natives(&[]));
        assert!(!toutes_natives(&[vec![]]));
        let ps = en_powershell(&correctifs);
        assert!(ps[0][0].contains("Checkpoint-Computer"), "{}", ps[0][0]);
        assert!(ps[1][0].contains("UserAuthentication -Value 1"), "{}", ps[1][0]);
        assert_eq!(ps[2][0], "Update-MpSignature");
        assert!(affichable(&id("rdp-nla")).contains("NLA"));
        assert_eq!(affichable("Update-MpSignature"), "Update-MpSignature");
    }
}
