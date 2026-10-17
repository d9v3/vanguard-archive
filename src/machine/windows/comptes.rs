//! Comptes locaux Windows : invité, Administrateur intégré, comptes sans mot de passe exigé.

use super::*;

/// Comptes locaux : invité, administrateur intégré, comptes sans mot de passe exigé, et la règle qui empêche
/// d'utiliser un compte sans mot de passe depuis le réseau. Une seule lecture PowerShell, en sections.
pub(super) fn comptes() -> Vec<Constat> {
    let sortie = ps(
        "try { Get-LocalUser | ForEach-Object { \"USR|$($_.Enabled)|$($_.PasswordRequired)|$($_.SID.Value)|$($_.Name)\" }; 'USR_FIN' } catch {}; \
         try { 'MOI|' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; 'MOI_FIN' } catch {}; \
         try { 'LBP|' + (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').LimitBlankPasswordUse; 'LBP_FIN' } catch {}",
    );
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
        let nom_ps = nom.replace('\'', "''");
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
                    tr!("Désactiver le compte Administrateur intégré", "Disable the built-in Administrator account"),
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
                .manuel(
                    trf!("Donner un mot de passe à « {nom} »", "Give “{nom}” a password"),
                    &["Start-Process ms-settings:signinoptions"],
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

#[cfg(test)]
mod tests {
    use super::*;

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
            [Some(Niveau::Moyen), Some(Niveau::Eleve), Some(Niveau::Moyen), Some(Niveau::Eleve)]
        );
        // Administrateur intégré utilisé en ce moment : conseil, pas de désactivation automatique.
        assert!(c[2].correctif.as_ref().is_some_and(|k| !k.automatique));
    }
}
