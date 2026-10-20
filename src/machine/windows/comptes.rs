//! Comptes locaux Windows : invité, Administrateur intégré, comptes sans mot de passe exigé, règle des mots de passe
//! (longueur minimale, blocage après des essais ratés).

use super::*;

/// Comptes locaux : invité, administrateur intégré, comptes sans mot de passe exigé, et la règle qui empêche
/// d'utiliser un compte sans mot de passe depuis le réseau. Lus avec les autres vérifications des comptes
/// (`comptes_locaux`), en sections.
pub(super) fn comptes() -> Vec<Constat> {
    let sortie = super::comptes_locaux();
    let Some(utilisateurs) = section(sortie.as_deref(), "USR") else {
        return vec![illisible("Comptes")];
    };
    let moi = section(sortie.as_deref(), "MOI").and_then(|l| l.first().map(|s| s.trim().to_string()));
    let lbp = section(sortie.as_deref(), "LBP").and_then(|l| l.first().and_then(|s| s.trim().parse().ok()));
    juger_comptes(&utilisateurs, moi.as_deref(), lbp)
}

fn juger_comptes(utilisateurs: &[&str], moi: Option<&str>, lbp: Option<u32>) -> Vec<Constat> {
    let mut constats = Vec::new();
    for u in utilisateurs {
        let c: Vec<&str> = u.trim().splitn(4, '|').collect();
        let [actif, exige, sid, nom] = c[..] else { continue };
        if !actif.eq_ignore_ascii_case("true") {
            continue;
        }
        let nom_ps = crate::commande::ps_texte(nom);
        if sid.ends_with("-501") {
            constats.push(
                alerte(
                    "Comptes",
                    Niveau::Eleve,
                    trf!("Compte invité « {nom} » activé.", "Guest account “{nom}” enabled."),
                )
                .corriger(
                    tr!("Désactiver le compte invité", "Disable the guest account"),
                    &[&format!("Disable-LocalUser -Name '{nom_ps}'")],
                ),
            );
            continue;
        }
        if sid.ends_with("-500") {
            let constat = alerte(
                "Comptes",
                Niveau::Moyen,
                trf!(
                    "Compte Administrateur intégré « {nom} » activé : son nom est connu de tous, c'est la cible préférée des attaques par mot de passe.",
                    "Built-in Administrator account “{nom}” enabled: its name is known to everyone, it is the favorite target of password attacks."
                ),
            );
            // On ne coupe pas le compte avec lequel on travaille.
            constats.push(if moi == Some(sid) {
                constat.manuel(
                    tr!(
                        "Créer ton propre compte administrateur, puis désactiver celui-ci",
                        "Create your own administrator account, then disable this one"
                    ),
                    &["Start-Process ms-settings:otherusers"],
                )
            } else {
                constat.corriger(
                    tr!(
                        "Désactiver le compte Administrateur intégré",
                        "Disable the built-in Administrator account"
                    ),
                    &[&format!("Disable-LocalUser -Name '{nom_ps}'")],
                )
            });
        }
        if exige.eq_ignore_ascii_case("false") {
            constats.push(
                alerte(
                    "Comptes",
                    Niveau::Moyen,
                    // Windows dit seulement qu'un mot de passe vide serait accepté (« mot de passe non exigé »), pas
                    // s'il l'est : un compte créé par New-LocalUser a ce réglage même avec un mot de passe.
                    trf!(
                        "Le compte « {nom} » accepte un mot de passe vide (Windows ne l'exige pas pour lui) : s'il n'en a pas, il s'ouvre sans rien taper.",
                        "The “{nom}” account accepts an empty password (Windows does not require one for it): if it has none, it opens without typing anything."
                    ),
                )
                // À faire soi-même : -PasswordRequired lève seulement le drapeau, sans donner de mot de passe. Un compte
                // déjà vide s'ouvrirait toujours sans rien taper, et le bilan le dirait sain. Le mot de passe d'abord
                // (Paramètres), puis le drapeau.
                .manuel(
                    trf!(
                        "Donner un mot de passe à « {nom} » (Paramètres > Comptes), puis l'exiger toujours",
                        "Give “{nom}” a password (Settings > Accounts), then always require one"
                    ),
                    &[
                        "Start-Process ms-settings:otherusers",
                        &format!("Set-LocalUser -Name '{nom_ps}' -PasswordRequired $true"),
                    ],
                ),
            );
        }
    }
    if lbp == Some(0) {
        constats.push(
            alerte(
                "Comptes",
                Niveau::Eleve,
                tr!(
                    "Les comptes sans mot de passe sont utilisables depuis le réseau (LimitBlankPasswordUse = 0).",
                    "Accounts without a password can be used from the network (LimitBlankPasswordUse = 0)."
                ),
            )
            .corriger(
                tr!(
                    "Réserver les comptes sans mot de passe à l'écran de connexion",
                    "Restrict password-less accounts to the sign-in screen"
                ),
                &["Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LimitBlankPasswordUse -Value 1"],
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            "Comptes",
            tr!(
                "Compte invité et Administrateur intégré désactivés, chaque compte exige un mot de passe.",
                "Guest and built-in Administrator accounts disabled, every account requires a password."
            ),
        ));
    }
    constats
}

/// USER_MODALS_INFO_0 de lmaccess.h : la longueur minimale des mots de passe, puis des champs qui ne servent pas ici.
#[repr(C)]
#[derive(Clone, Copy)]
struct Modales0 {
    longueur_min: u32,
    _age_max: u32,
    _age_min: u32,
    _deconnexion: u32,
    _historique: u32,
}

/// USER_MODALS_INFO_3 de lmaccess.h : durée et fenêtre du blocage, puis le nombre d'essais ratés qui bloque.
#[repr(C)]
#[derive(Clone, Copy)]
struct Modales3 {
    _duree: u32,
    _fenetre: u32,
    seuil: u32,
}

#[link(name = "netapi32")]
unsafe extern "system" {
    fn NetUserModalsGet(serveur: *const u16, niveau: u32, tampon: *mut *mut u8) -> u32;
    fn NetApiBufferFree(tampon: *mut std::ffi::c_void) -> u32;
}

/// Un niveau de NetUserModalsGet sur cet ordinateur ; `None` si Windows refuse.
fn modales<T: Copy>(niveau: u32) -> Option<T> {
    let mut tampon: *mut u8 = std::ptr::null_mut();
    // SAFETY : NetUserModalsGet (serveur nul : cet ordinateur) écrit dans `tampon` un bloc alloué par Windows au format
    // du niveau demandé, que `T` reproduit (repr(C), champs de lmaccess.h) ; il est copié tant qu'il vit, puis rendu
    // une seule fois par NetApiBufferFree. Code non nul : rien n'a été alloué.
    unsafe {
        if NetUserModalsGet(std::ptr::null(), niveau, &raw mut tampon) != 0 || tampon.is_null() {
            return None;
        }
        let valeur = std::ptr::read_unaligned(tampon.cast::<T>());
        NetApiBufferFree(tampon.cast());
        Some(valeur)
    }
}

/// La règle des mots de passe des comptes locaux, lue comme « net accounts » la lit (NetUserModalsGet : sans droits
/// d'administrateur, sans dépendre de la langue de Windows) : (longueur minimale, essais ratés avant blocage ; 0 :
/// jamais bloqué). ADSI (« WinNT://<nom de l'ordinateur> ») ne convient pas : sur un vrai Windows, ce nom désigne
/// l'objet ordinateur, qui n'a pas ces réglages (vu dans la VM de test le 20 octobre).
fn lire_politique() -> Option<(u32, u32)> {
    let longueur = modales::<Modales0>(0)?.longueur_min;
    let seuil = modales::<Modales3>(3)?.seuil;
    Some((longueur, seuil))
}

pub(super) fn politique() -> Option<Constat> {
    match lire_politique() {
        Some((longueur, seuil)) => juger_politique(longueur, seuil),
        None => Some(impossible(
            "Comptes",
            tr!(
                "règle des mots de passe illisible (NetUserModalsGet)",
                "password policy unreadable (NetUserModalsGet)"
            ),
        )),
    }
}

/// Sans blocage, un programme essaie des milliers de mots de passe sur un compte local (par le réseau, le Bureau à
/// distance) : Windows 11 bloque 10 minutes après 10 essais depuis 2022, les installations plus anciennes jamais.
/// Une longueur minimale sous 8 ne vaut qu'une information : elle ne touche que les comptes locaux, pas ceux de
/// Microsoft, et seulement au prochain changement de mot de passe. Rien d'illisible n'est compté comme sain : sans
/// valeur lue, `politique` le dit.
fn juger_politique(longueur: u32, seuil: u32) -> Option<Constat> {
    if seuil == 0 {
        return Some(
            alerte(
                "Comptes",
                Niveau::Moyen,
                tr!(
                    "Aucun blocage après des mots de passe faux : un programme peut en essayer des milliers sur les comptes locaux.",
                    "No lockout after wrong passwords: a program can try thousands of them on the local accounts."
                ),
            )
            .corriger(
                tr!(
                    "Bloquer un compte 10 minutes après 10 essais ratés (réglage de Windows 11)",
                    "Lock an account for 10 minutes after 10 failed attempts (Windows 11's setting)"
                ),
                &["net accounts /lockoutthreshold:10 /lockoutduration:10 /lockoutwindow:10"],
            ),
        );
    }
    (longueur < 8).then(|| {
        alerte(
            "Comptes",
            Niveau::Info,
            trf!(
                "Les mots de passe des comptes locaux peuvent faire moins de 8 caractères (minimum : {longueur}).",
                "Local account passwords can be shorter than 8 characters (minimum: {longueur})."
            ),
        )
        .corriger(
            tr!(
                "Exiger 8 caractères au prochain changement de mot de passe",
                "Require 8 characters at the next password change"
            ),
            &["net accounts /minpwlen:8"],
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regle_des_mots_de_passe() {
        assert!(juger_politique(8, 10).is_none() && juger_politique(14, 5).is_none());
        let sans_blocage = juger_politique(0, 0).unwrap();
        assert_eq!(sans_blocage.probleme, Some(Niveau::Moyen));
        assert!(sans_blocage.correctif.unwrap().commandes[0].contains("/lockoutthreshold:10"));
        let courts = juger_politique(0, 10).unwrap();
        assert_eq!(courts.probleme, Some(Niveau::Info));
        assert_eq!(courts.correctif.unwrap().commandes, ["net accounts /minpwlen:8"]);
    }

    /// Les deux structures ont la taille de celles de lmaccess.h : un champ de trop ou de moins décalerait le seuil.
    #[test]
    fn modales_au_format_de_windows() {
        assert_eq!(std::mem::size_of::<Modales0>(), 20);
        assert_eq!(std::mem::size_of::<Modales3>(), 12);
        // Sous Wine, l'appel répond ou refuse, sans planter ; la valeur lue n'est jamais inventée.
        let _ = lire_politique();
    }

    #[test]
    fn comptes_juges() {
        let utilisateurs = [
            "True|True|S-1-5-21-1-1-1-1001|alice",
            "False|False|S-1-5-21-1-1-1-501|Invité",
            "False|True|S-1-5-21-1-1-1-500|Administrateur",
        ];
        let c = juger_comptes(&utilisateurs, Some("S-1-5-21-1-1-1-1001"), Some(1));
        assert!(c.len() == 1 && c[0].probleme.is_none());
        let utilisateurs = [
            "True|False|S-1-5-21-1-1-1-1002|enfant",
            "True|False|S-1-5-21-1-1-1-501|Invité",
            "True|True|S-1-5-21-1-1-1-500|Administrateur",
        ];
        let c = juger_comptes(&utilisateurs, Some("S-1-5-21-1-1-1-500"), Some(0));
        let niveaux: Vec<_> = c.iter().map(|c| c.probleme).collect();
        assert_eq!(
            niveaux,
            [
                Some(Niveau::Moyen),
                Some(Niveau::Eleve),
                Some(Niveau::Moyen),
                Some(Niveau::Eleve)
            ]
        );
        // Administrateur intégré utilisé en ce moment : conseil, pas de désactivation automatique.
        assert!(c[2].correctif.as_ref().is_some_and(|k| !k.automatique));
        // Compte sans mot de passe exigé : à faire soi-même (le drapeau seul ne donne pas de mot de passe), le nom
        // protégé dans la commande montrée.
        let k = c[0].correctif.as_ref().unwrap();
        assert!(!k.automatique);
        assert_eq!(
            k.commandes,
            [
                "Start-Process ms-settings:otherusers",
                "Set-LocalUser -Name 'enfant' -PasswordRequired $true"
            ]
        );
    }
}
