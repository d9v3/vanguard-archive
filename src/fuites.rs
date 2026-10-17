//! Mots de passe fuités : vérifie si un mot de passe figure dans les fuites de données connues (Have I Been Pwned).
//! Le mot de passe ne quitte jamais l'ordinateur : seuls les 5 premiers caractères de son empreinte SHA-1 partent,
//! le service renvoie toutes les empreintes qui commencent pareil (des centaines), et la comparaison se fait ici.

use crate::ui::*;

const SERVICE: &str = "https://api.pwnedpasswords.com/range/";

/// Empreinte SHA-1 en hexadécimal majuscule, coupée en (5 premiers caractères envoyés, reste gardé ici).
fn empreinte(mot_de_passe: &str) -> (String, String) {
    let hex = sha1_smol::Sha1::from(mot_de_passe).digest().to_string().to_uppercase();
    let (debut, fin) = hex.split_at(5);
    (debut.to_string(), fin.to_string())
}

/// Nombre de fuites où l'empreinte apparaît, d'après la réponse du service (« SUFFIXE:NOMBRE » par ligne ;
/// les lignes de remplissage, ajoutées pour masquer la taille de la réponse, valent 0).
fn occurrences(reponse: &str, fin: &str) -> u64 {
    reponse
        .lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(suffixe, _)| suffixe.eq_ignore_ascii_case(fin))
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(0)
}

/// Interroge le service avec curl (présent sous Linux et dans Windows 10/11). `None` : pas de réponse.
fn interroger(debut: &str) -> Option<String> {
    let r = crate::commande::lancer(
        std::process::Command::new("curl").args([
            "-fsS",
            "--max-time",
            "15",
            "-H",
            "Add-Padding: true",
            "-A",
            "sentinel",
            &format!("{SERVICE}{debut}"),
        ]),
        20,
    )?;
    (r.code == Some(0) && r.sortie.contains(':')).then_some(r.sortie)
}

/// « 52 372 427 » en français, « 52,372,427 » en anglais.
fn milliers(n: u64) -> String {
    let separateur = if crate::langue::anglais() { ',' } else { ' ' };
    let chiffres = n.to_string();
    let mut sortie = String::new();
    for (i, c) in chiffres.chars().enumerate() {
        if i > 0 && (chiffres.len() - i).is_multiple_of(3) {
            sortie.push(separateur);
        }
        sortie.push(c);
    }
    sortie
}

/// Conseil sur la forme du mot de passe, sans le juger « solide » : ce test ne le sait pas.
fn conseil_forme(mot_de_passe: &str) -> Option<&'static str> {
    (mot_de_passe.chars().count() < 12).then(|| {
        tr!(
            "Il fait moins de 12 caractères : une phrase de passe de 4 ou 5 mots est plus solide et plus facile à retenir.",
            "It is shorter than 12 characters: a passphrase of 4 or 5 words is stronger and easier to remember."
        )
    })
}

pub fn verifier() {
    titre(tr!("Mots de passe fuités", "Leaked passwords"));
    trp!(
        "  Tape un mot de passe : il ne s'affiche pas et ne quitte jamais cet ordinateur. Seuls 5 caractères de son\n  empreinte sont envoyés à Have I Been Pwned, et la comparaison se fait ici. Entrée seule pour terminer.\n",
        "  Type a password: it is not shown and never leaves this computer. Only 5 characters of its fingerprint\n  are sent to Have I Been Pwned, and the comparison happens here. Enter alone to finish.\n"
    );
    while let Ok(mot_de_passe) = rpassword::prompt_password(tr!("  Mot de passe : ", "  Password: ")) {
        if mot_de_passe.is_empty() {
            break;
        }
        let (debut, fin) = empreinte(&mot_de_passe);
        let Some(reponse) = interroger(&debut) else {
            trp!(
                "  ✖ Service injoignable (pas d'Internet, ou curl absent).",
                "  ✖ Service unreachable (no Internet, or curl missing)."
            );
            break;
        };
        match occurrences(&reponse, &fin) {
            0 => {
                trp!(
                    "  {VERT}✔{RESET} Absent des fuites connues. Ça ne veut pas dire qu'il est solide : seulement qu'il n'a pas circulé.",
                    "  {VERT}✔{RESET} Not in known leaks. That does not mean it is strong: only that it has not circulated."
                );
                if let Some(c) = conseil_forme(&mot_de_passe) {
                    println!("    {GRIS}{c}{RESET}");
                }
            }
            n => trp!(
                "  {}✖ Trouvé {} fois dans des fuites{RESET} : les pirates l'essaient en premier. Change-le partout où tu l'utilises,\n    et prends un mot de passe différent pour chaque site (un gestionnaire comme Bitwarden s'en charge).",
                "  {}✖ Found {} times in leaks{RESET}: attackers try it first. Change it everywhere you use it,\n    and use a different password for each site (a manager like Bitwarden does it for you).",
                couleur(crate::risk::Niveau::Critique),
                milliers(n)
            ),
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empreinte_et_reponse() {
        // SHA-1 de « password » : 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
        let (debut, fin) = empreinte("password");
        assert_eq!(debut, "5BAA6");
        assert_eq!(fin, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        let reponse = "0018A45C4D1DEF81644B54AB7F969B88D65:10\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:52256179\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n";
        assert_eq!(occurrences(reponse, &fin), 52_256_179);
        assert_eq!(occurrences(reponse, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0);
        assert_eq!(milliers(52_256_179), "52 256 179");
        assert_eq!(milliers(999), "999");
        assert!(conseil_forme("court").is_some());
        assert!(conseil_forme("cheval agrafe batterie correct").is_none());
    }
}
