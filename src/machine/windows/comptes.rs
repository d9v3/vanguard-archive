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
                    trf!(
                        "Le compte « {nom} » n'exige pas de mot de passe : il peut s'ouvrir sans rien taper.",
                        "The “{nom}” account does not require a password: it may open without typing anything."
                    ),
                )
                // Le mot de passe actuel ne change pas (personne n'est enfermé dehors) : Windows refusera seulement
                // qu'on lui en mette un vide ensuite.
                .corriger(
                    trf!(
                        "Exiger un mot de passe pour « {nom} »",
                        "Require a password for “{nom}”"
                    ),
                    &[&format!("Set-LocalUser -Name '{nom_ps}' -PasswordRequired $true")],
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

/// La règle des mots de passe des comptes locaux, lue par ADSI (sans droits d'administrateur, et sans dépendre de la
/// langue de Windows comme « net accounts ») : (longueur minimale, essais ratés avant blocage ; 0 : jamais bloqué).
pub(super) fn politique() -> Option<Constat> {
    let sortie = super::comptes_locaux();
    let ligne = section(sortie.as_deref(), "POL")?.first()?.trim().to_string();
    let (longueur, seuil) = ligne.split_once('|')?;
    juger_politique(longueur.trim().parse().ok()?, seuil.trim().parse().ok()?)
}

/// Sans blocage, un programme essaie des milliers de mots de passe sur un compte local (par le réseau, le Bureau à
/// distance) : Windows 11 bloque 10 minutes après 10 essais depuis 2022, les installations plus anciennes jamais.
/// Une longueur minimale sous 8 ne vaut qu'une information : elle ne touche que les comptes locaux, pas ceux de
/// Microsoft, et seulement au prochain changement de mot de passe. Rien d'illisible n'est compté comme sain : sans
/// valeur lue, aucun constat.
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
        assert_eq!(section(Some("POL|0|10\nPOL_FIN\n"), "POL"), Some(vec!["0|10"]));
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
        // Compte sans mot de passe exigé : corrigé par Vanguard, le nom protégé dans la commande.
        let k = c[0].correctif.as_ref().unwrap();
        assert!(k.automatique && k.commandes == ["Set-LocalUser -Name 'enfant' -PasswordRequired $true"]);
    }
}
