//! Durcissement de macOS, lu sans droits d'administrateur : volume du système scellé et signé (SSV), signature du
//! code imposée au démarrage (AMFI), validation des bibliothèques, extensions du noyau et du système ajoutées par
//! d'autres qu'Apple, visibilité d'AirDrop.

use std::process::Command;

use super::{Constat, alerte, impossible, ok, preference, sortie};
use crate::risk::Niveau;
use crate::{tr, trf};

/// « Authenticated Root status: enabled » : le volume du système est scellé ; la moindre modification casse le sceau.
fn lire_racine_authentifiee(texte: &str) -> Option<bool> {
    let etat = texte.split("status:").nth(1)?.trim();
    Some(etat.starts_with("enabled"))
}

/// Options de démarrage qui coupent la vérification des signatures du code (AMFI). Réservées au développement de
/// pilotes, elles laissent n'importe quel programme s'exécuter, même modifié.
fn options_dangereuses(boot_args: &str) -> Vec<&str> {
    const COUPENT_AMFI: [&str; 4] = [
        "amfi_get_out_of_my_way",
        "cs_enforcement_disable",
        "amfi_allow_any_signature",
        "amfi_unrestrict_task_for_pid",
    ];
    boot_args
        .split_whitespace()
        .filter(|o| COUPENT_AMFI.iter().any(|d| o.starts_with(d)))
        .collect()
}

pub(super) fn systeme_signe() -> Vec<Constat> {
    let mut constats = Vec::new();
    match sortie("csrutil", &["authenticated-root", "status"])
        .as_deref()
        .and_then(lire_racine_authentifiee)
    {
        Some(true) => constats.push(ok(
            "Protection système",
            tr!(
                "Volume du système scellé et signé par Apple (SSV).",
                "System volume sealed and signed by Apple (SSV)."
            ),
        )),
        Some(false) => constats.push(
            alerte(
                "Protection système",
                Niveau::Eleve,
                tr!(
                    "Le sceau du volume du système (SSV) est désactivé : macOS lui-même peut être modifié sans que rien ne le remarque.",
                    "The system volume seal (SSV) is off: macOS itself can be modified without anything noticing."
                ),
            )
            .manuel(
                tr!(
                    "Redémarrer en mode de secours, Utilitaires > Terminal : csrutil authenticated-root enable, puis redémarrer",
                    "Restart in Recovery, Utilities > Terminal: csrutil authenticated-root enable, then restart"
                ),
                &[],
            ),
        ),
        None => constats.push(impossible(
            "Protection système",
            tr!(
                "état du sceau du système illisible (csrutil)",
                "system seal state unreadable (csrutil)"
            ),
        )),
    }
    // nvram répond en erreur quand boot-args n'existe pas : c'est le cas normal, pas une lecture ratée.
    match crate::commande::lancer(Command::new("nvram").arg("boot-args"), 10) {
        Some(r) => {
            let dangereuses = options_dangereuses(&r.sortie);
            constats.push(if dangereuses.is_empty() {
                ok(
                    "Protection système",
                    tr!(
                        "Signature du code imposée dès le démarrage (aucune option ne la coupe).",
                        "Code signing enforced from startup (no option turns it off)."
                    ),
                )
            } else {
                alerte(
                    "Protection système",
                    Niveau::Eleve,
                    trf!(
                        "Une option de démarrage coupe la vérification des signatures du code ({}) : n'importe quel programme peut s'exécuter, même modifié.",
                        "A startup option turns code signature checks off ({}): any program can run, even modified.",
                        dangereuses.join(" ")
                    ),
                )
                .manuel(
                    tr!(
                        "Retirer les options de démarrage : sudo nvram -d boot-args (sur Apple Silicon, depuis le Terminal du mode de secours), puis redémarrer",
                        "Remove the startup options: sudo nvram -d boot-args (on Apple Silicon, from the Recovery Terminal), then restart"
                    ),
                    &["sudo nvram -d boot-args"],
                )
            });
        }
        None => constats.push(impossible(
            "Protection système",
            tr!(
                "options de démarrage illisibles (nvram)",
                "startup options unreadable (nvram)"
            ),
        )),
    }
    // Clé absente : la validation est active (réglage d'origine).
    let validation = preference(
        "/Library/Preferences/com.apple.security.libraryvalidation",
        "DisableLibraryValidation",
    );
    constats.push(if validation.as_deref() == Some("1") {
        alerte(
            "Protection système",
            Niveau::Moyen,
            tr!(
                "La validation des bibliothèques est désactivée : un programme peut charger du code qui n'est signé ni par Apple ni par son éditeur.",
                "Library validation is off: a program can load code signed neither by Apple nor by its developer."
            ),
        )
        .corriger(
            tr!("Réactiver la validation des bibliothèques", "Turn library validation back on"),
            &["sudo defaults delete /Library/Preferences/com.apple.security.libraryvalidation DisableLibraryValidation"],
        )
    } else {
        ok(
            "Protection système",
            tr!(
                "Validation des bibliothèques active : seul du code signé se charge dans les programmes.",
                "Library validation on: only signed code loads into programs."
            ),
        )
    });
    constats
}

/// Un nom d'extension (« com.vmware.kext.vmx86 ») : commence par une lettre, au moins trois parties.
fn identifiant(mot: &str) -> bool {
    mot.starts_with(|c: char| c.is_ascii_alphabetic())
        && mot.split('.').count() >= 3
        && mot.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// `kmutil showloaded` : les extensions du noyau chargées, sans celles d'Apple.
fn extensions_noyau(texte: &str) -> Vec<String> {
    let mut l: Vec<String> = texte
        .lines()
        .filter_map(|ligne| ligne.split_whitespace().find(|m| identifiant(m)))
        .filter(|id| !id.starts_with("com.apple."))
        .map(str::to_string)
        .collect();
    l.sort_unstable();
    l.dedup();
    l
}

/// `systemextensionsctl list` : les extensions du système actives (VPN, antivirus, pilotes), « nom (identifiant) ».
fn extensions_systeme(texte: &str) -> Vec<String> {
    texte
        .lines()
        .filter(|l| l.contains("[activated enabled]"))
        .filter_map(|l| {
            let c: Vec<&str> = l.split('\t').map(str::trim).collect();
            let id = c.get(3)?.split_whitespace().next()?;
            let nom = c.get(4).copied().filter(|n| !n.is_empty()).unwrap_or(id);
            Some(format!("{nom} ({id})"))
        })
        .collect()
}

pub(super) fn extensions_tierces() -> Constat {
    let (Some(noyau), Some(systeme)) = (
        sortie("kmutil", &["showloaded"]),
        sortie("systemextensionsctl", &["list"]),
    ) else {
        return impossible(
            "Pilotes",
            tr!(
                "extensions du noyau et du système illisibles (kmutil, systemextensionsctl)",
                "kernel and system extensions unreadable (kmutil, systemextensionsctl)"
            ),
        );
    };
    let tierces: Vec<String> = extensions_noyau(&noyau)
        .into_iter()
        .chain(extensions_systeme(&systeme))
        .collect();
    if tierces.is_empty() {
        return ok(
            "Pilotes",
            tr!(
                "Aucune extension du noyau ni du système ajoutée par un autre qu'Apple.",
                "No kernel or system extension added by anyone but Apple."
            ),
        );
    }
    alerte(
        "Pilotes",
        Niveau::Info,
        trf!(
            "Extensions ajoutées par d'autres qu'Apple : {}. Normal pour un VPN, un antivirus ou un pilote de matériel ; une inconnue est à vérifier (elle voit tout ce que fait le Mac).",
            "Extensions added by others than Apple: {}. Normal for a VPN, an antivirus or a hardware driver; an unknown one is worth checking (it sees everything the Mac does).",
            tierces.join(", ")
        ),
    )
    .manuel(
        tr!(
            "Réglages Système > Général > Éléments de connexion et extensions : retirer celle qu'on ne connaît pas (et son application)",
            "System Settings > General > Login Items & Extensions: remove the one you do not know (and its app)"
        ),
        &[],
    )
}

/// AirDrop ouvert à tous : des inconnus à portée (train, café) peuvent proposer des fichiers, et voient le nom du Mac.
pub(super) fn airdrop() -> Option<Constat> {
    let mode = preference("com.apple.sharingd", "DiscoverableMode")?;
    Some(if mode.starts_with("Everyone") {
        alerte(
            "AirDrop",
            Niveau::Info,
            tr!(
                "AirDrop est visible par tout le monde : des inconnus à proximité peuvent t'envoyer des fichiers et voient le nom de ce Mac.",
                "AirDrop is visible to everyone: strangers nearby can send you files and see this Mac's name."
            ),
        )
        .corriger(
            tr!("AirDrop pour les contacts seulement", "AirDrop for contacts only"),
            &[
                "defaults write com.apple.sharingd DiscoverableMode -string \"Contacts Only\"",
                "killall sharingd 2>/dev/null; true",
            ],
        )
    } else {
        ok("AirDrop", trf!("AirDrop : {mode}.", "AirDrop: {mode}."))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sceau_et_options_de_demarrage() {
        assert_eq!(
            lire_racine_authentifiee("Authenticated Root status: enabled\n"),
            Some(true)
        );
        assert_eq!(
            lire_racine_authentifiee("Authenticated Root status: disabled\n"),
            Some(false)
        );
        assert_eq!(lire_racine_authentifiee("autre"), None);
        assert_eq!(
            options_dangereuses("boot-args\t-v amfi_get_out_of_my_way=1"),
            ["amfi_get_out_of_my_way=1"]
        );
        assert_eq!(options_dangereuses("boot-args\t-v keepsyms=1"), Vec::<&str>::new());
    }

    #[test]
    fn extensions_lues() {
        let kmutil = "Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>\n\
                        1  152 0                  0          0          com.apple.kpi.bsd (24.0.0) 0A1B <>\n\
                      182    0 0xfffffe0007b4c000 0x8000     0x8000     com.vmware.kext.vmx86 (17.5.2) 9C2D-11 <8 6 5 3 1>\n";
        assert_eq!(extensions_noyau(kmutil), ["com.vmware.kext.vmx86"]);
        let ctl = "2 extension(s)\n--- com.apple.system_extension.network_extension\n\
                   enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n\
                   *\t*\tABCDE12345\tcom.exemple.vpn.extension (1.0/1)\tExemple VPN\t[activated enabled]\n\
                   \t\tABCDE12345\tcom.exemple.vieux (0.9/1)\tVieux\t[terminated waiting to uninstall on reboot]\n";
        assert_eq!(extensions_systeme(ctl), ["Exemple VPN (com.exemple.vpn.extension)"]);
    }
}
