//! La lecture de sshd_config, commune à Linux, macOS et Windows (le serveur OpenSSH de Microsoft lit le même format,
//! dans %ProgramData%\ssh) : la partie qui vaut pour toutes les connexions et la valeur d'un réglage, telles que
//! sshd les retient.

/// La partie d'un fichier de configuration de sshd qui vaut pour toutes les connexions : un bloc « Match » ne
/// s'applique qu'à certaines (un utilisateur, une adresse) et va jusqu'à la fin du fichier.
pub(crate) fn partie_globale_sshd(texte: &str) -> String {
    texte
        .lines()
        .take_while(|l| {
            !l.split_whitespace()
                .next()
                .is_some_and(|m| m.eq_ignore_ascii_case("match"))
        })
        .flat_map(|l| [l, "\n"])
        .collect()
}

/// Première valeur d'un réglage de sshd, en minuscules. Le nom et la valeur se séparent par des espaces ou par un
/// « = » (« PasswordAuthentication=no » est valable).
pub(crate) fn valeur_sshd(conf: &str, cle: &str) -> Option<String> {
    conf.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let (k, v) = l.split_once(|c: char| c.is_whitespace() || c == '=')?;
            let v = v.trim().trim_start_matches('=').trim().trim_matches('"');
            k.eq_ignore_ascii_case(cle).then(|| v.to_ascii_lowercase())
        })
}

/// sshd accepte-t-il un mot de passe ? Par « PasswordAuthentication » (oui par défaut), ou, avec PAM, par le mode
/// « clavier interactif » qui demande le même mot de passe (oui par défaut aussi).
pub(crate) fn mots_de_passe_sshd(conf: &str) -> bool {
    let valeur = |cle: &str| valeur_sshd(conf, cle);
    let clavier = valeur("KbdInteractiveAuthentication").or_else(|| valeur("ChallengeResponseAuthentication"));
    valeur("PasswordAuthentication").as_deref() != Some("no")
        || (valeur("UsePAM").as_deref() == Some("yes") && clavier.as_deref() != Some("no"))
}

/// sshd ouvre-t-il un compte sans mot de passe ? « PermitEmptyPasswords yes », quand les mots de passe sont permis.
pub(crate) fn mots_de_passe_vides_sshd(conf: &str) -> bool {
    valeur_sshd(conf, "PermitEmptyPasswords").as_deref() == Some("yes") && mots_de_passe_sshd(conf)
}
