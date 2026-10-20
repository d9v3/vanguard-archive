//! Privilèges : fichiers secrets lisibles, groupes équivalents à root, sudo sans mot de passe, dossiers de commandes
//! modifiables par d'autres comptes. Fichiers secrets et sudo se vérifient comme sous macOS (machine/unix.rs).

use super::*;
#[cfg(test)]
use crate::machine::unix::{regles_nopasswd, secret_expose};

pub(super) fn fichiers_secrets() -> Vec<Constat> {
    super::super::unix::fichiers_secrets(
        Path::new(&home()),
        tr!(
            "Ton dossier personnel est lisible par les autres comptes de la machine.",
            "Your home folder is readable by the other accounts of the machine."
        ),
    )
}

/// Groupes qui donnent en pratique les droits root sans mot de passe.
pub(super) fn groupes_privilegies() -> Option<Constat> {
    let groupes = sortie("id", &["-nG"])?;
    let risques = groupes_a_risque(&groupes);
    Some(if risques.is_empty() {
        ok(
            "Groupes",
            tr!(
                "Aucun groupe qui donne les droits root sans mot de passe.",
                "No group gives root rights without a password."
            ),
        )
    } else {
        alerte(
            "Groupes",
            Niveau::Moyen,
            trf!(
                "Tu es dans le groupe {} : tout programme lancé par toi peut devenir root sans mot de passe (par un conteneur, une machine virtuelle ou le disque lui-même).", "You are in the {} group: any program you run can become root without a password (through a container, a virtual machine or the disk itself).",
                risques.join(", ")
            ),
        )
        .manuel(
            tr!("Si tu n'en as pas besoin chaque jour, sors du groupe (l'outil demandera alors sudo) ; sinon, garde-le en connaissance de cause", "If you do not need it every day, leave the group (the tool will then ask for sudo); otherwise, keep it knowingly"),
            &[&format!("sudo gpasswd -d $USER {}", risques.first().copied().unwrap_or("docker"))],
        )
    })
}

/// Groupes de `id -nG` qui valent root : docker, lxd et incus-admin par un conteneur qui monte /, libvirt par une
/// machine virtuelle qui reçoit le disque de l'ordinateur, disk par la lecture et l'écriture directes du disque (donc
/// de /etc/shadow).
fn groupes_a_risque(groupes: &str) -> Vec<&str> {
    groupes
        .split_whitespace()
        .filter(|g| matches!(*g, "docker" | "lxd" | "incus-admin" | "libvirt" | "disk"))
        .collect()
}

pub(super) fn sudo_sans_mot_de_passe() -> Vec<Constat> {
    super::super::unix::sudo_sans_mot_de_passe(tr!(
        "sudo sans mot de passe pour TOUTES les commandes : n'importe quel programme lancé par toi peut devenir root.",
        "sudo without a password for ALL commands: any program you run can become root."
    ))
}

/// Les dossiers où root cherche ses commandes : le `secure_path` de sudo des grandes distributions.
const DOSSIERS_DE_ROOT: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/snap/bin",
];

/// Un dossier de commandes tel qu'il est lu : son chemin réel, ses droits, son propriétaire, et si root y cherche ses
/// commandes.
pub(super) struct DossierDeCommandes {
    pub chemin: String,
    pub mode: u32,
    pub proprietaire: u32,
    pub de_root: bool,
}

/// Les dossiers de commandes modifiables par d'autres comptes. Quiconque peut écrire dans l'un d'eux y dépose un
/// programme du nom d'une vraie commande (« ls », « sudo ») : il tourne à la place de l'autre, avec les droits de qui
/// la tape, root compris après sudo. Un dossier ouvert à tous est fautif où qu'il soit ; un dossier de root qui
/// appartient à un autre compte que root l'est aussi. Le bit « sticky » (/tmp) n'y change rien : il empêche de
/// supprimer les fichiers des autres, pas d'en ajouter. Ailleurs, un dossier à un autre compte est voulu (Homebrew
/// sous Linux) : rien à dire.
pub(super) fn juger_dossiers_de_commandes(dossiers: &[DossierDeCommandes]) -> Option<Constat> {
    let ouverts: Vec<&DossierDeCommandes> = dossiers.iter().filter(|d| d.mode & 0o002 != 0).collect();
    let a_d_autres: Vec<&DossierDeCommandes> = dossiers
        .iter()
        .filter(|d| d.de_root && d.proprietaire != 0 && d.mode & 0o002 == 0)
        .collect();
    if ouverts.is_empty() && a_d_autres.is_empty() {
        return None;
    }
    let niveau = if ouverts.iter().chain(&a_d_autres).any(|d| d.de_root) {
        Niveau::Eleve
    } else {
        Niveau::Moyen
    };
    let noms: Vec<&str> = ouverts.iter().chain(&a_d_autres).map(|d| d.chemin.as_str()).collect();
    let constat = alerte(
        "Privilèges",
        niveau,
        trf!(
            "D'autres comptes peuvent déposer des programmes dans {} : une fausse commande y prendrait la place de la vraie, avec tes droits, ou ceux de root après sudo.",
            "Other accounts can drop programs into {}: a fake command there would take the real one's place, with your rights, or root's after sudo.",
            noms.join(", ")
        ),
    );
    Some(if a_d_autres.is_empty() {
        // Retirer l'écriture aux autres se défait exactement (chmod o+w) et ne gêne aucun programme : rien ne doit
        // pouvoir y écrire sans en être propriétaire.
        let commandes: Vec<String> = ouverts
            .iter()
            .map(|d| format!("sudo chmod o-w {}", crate::commande::sh_chaine(&d.chemin)))
            .collect();
        constat.corriger(
            tr!(
                "Retirer l'écriture aux autres comptes (chmod o-w)",
                "Remove write access for other accounts (chmod o-w)"
            ),
            &commandes,
        )
    } else {
        // Rendre un dossier à root peut casser l'outil qui l'a pris : à décider soi-même.
        constat.manuel(
            tr!(
                "Rendre ces dossiers à root (sudo chown root:root <dossier> ; sudo chmod 755 <dossier>), après avoir vérifié quel outil les a changés",
                "Give these folders back to root (sudo chown root:root <folder>; sudo chmod 755 <folder>), after checking which tool changed them"
            ),
            &[],
        )
    })
}

/// Les dossiers de root, puis ceux du PATH de la personne, sous leur chemin réel (« /bin » mène souvent à
/// « /usr/bin ») et sans doublon. Un dossier absent est sauté ; le dossier personnel aussi, qui est à la personne.
pub(super) fn dossiers_de_commandes() -> Option<Constat> {
    use std::os::unix::fs::MetadataExt;
    let maison = std::fs::canonicalize(home()).ok();
    let path = std::env::var("PATH").unwrap_or_default();
    let mut vus: Vec<DossierDeCommandes> = Vec::new();
    let candidats = DOSSIERS_DE_ROOT
        .iter()
        .map(|d| (*d, true))
        .chain(path.split(':').filter(|d| d.starts_with('/')).map(|d| (d, false)));
    for (dossier, de_root) in candidats {
        let Ok(reel) = std::fs::canonicalize(dossier) else {
            continue;
        };
        if maison.as_ref().is_some_and(|m| reel.starts_with(m)) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&reel) else { continue };
        let chemin = reel.to_string_lossy().into_owned();
        match vus.iter_mut().find(|d| d.chemin == chemin) {
            Some(deja) => deja.de_root |= de_root,
            None => vus.push(DossierDeCommandes {
                chemin,
                mode: meta.mode(),
                proprietaire: meta.uid(),
                de_root,
            }),
        }
    }
    juger_dossiers_de_commandes(&vus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn droits_des_secrets() {
        assert!(!secret_expose(0o100_600));
        assert!(!secret_expose(0o40700));
        assert!(secret_expose(0o100_644));
        assert!(secret_expose(0o100_640));
    }

    #[test]
    fn dossiers_de_commandes_ouverts_a_d_autres() {
        let d = |chemin: &str, mode: u32, proprietaire: u32, de_root: bool| DossierDeCommandes {
            chemin: chemin.to_string(),
            mode: 0o40000 | mode,
            proprietaire,
            de_root,
        };
        let sains = [d("/usr/bin", 0o755, 0, true), d("/opt/outil/bin", 0o755, 1001, false)];
        assert!(juger_dossiers_de_commandes(&sains).is_none());
        // Ouvert à tous, même avec le bit sticky : corrigé par chmod o-w, le nom protégé.
        let ouvert = juger_dossiers_de_commandes(&[d("/usr/local/bin", 0o1777, 0, true)]).unwrap();
        assert_eq!(ouvert.probleme, Some(Niveau::Eleve));
        assert_eq!(ouvert.correctif.unwrap().commandes, ["sudo chmod o-w '/usr/local/bin'"]);
        let a_moi = juger_dossiers_de_commandes(&[d("/opt/l'outil/bin", 0o777, 1000, false)]).unwrap();
        assert_eq!(a_moi.probleme, Some(Niveau::Moyen));
        assert_eq!(
            a_moi.correctif.unwrap().commandes,
            ["sudo chmod o-w '/opt/l'\\''outil/bin'"]
        );
        // Un dossier de root à un autre compte : à décider soi-même.
        let pris = juger_dossiers_de_commandes(&[d("/usr/local/bin", 0o755, 1000, true)]).unwrap();
        assert!(pris.probleme == Some(Niveau::Eleve) && !pris.correctif.unwrap().automatique);
    }

    #[test]
    fn groupes_qui_valent_root() {
        assert_eq!(
            groupes_a_risque("alice wheel libvirt kvm docker"),
            ["libvirt", "docker"]
        );
        assert_eq!(groupes_a_risque("alice wheel video audio kvm"), Vec::<&str>::new());
    }

    #[test]
    fn regles_sudo() {
        let omarchy = "User alice may run the following commands on portable:\n    (ALL) ALL\n    (root) NOPASSWD: /usr/bin/omarchy-dns Cloudflare, /usr/bin/omarchy-dns DHCP\n";
        assert_eq!(regles_nopasswd(omarchy), (vec![], 1));
        let tout = "    (ALL : ALL) NOPASSWD: ALL\n";
        assert_eq!(regles_nopasswd(tout).0.len(), 1);
    }

    #[test]
    fn reglages_par_defaut_de_sudo() {
        use crate::machine::unix::defauts_sudo;
        let liste = |defauts: &str| {
            format!(
                "Matching Defaults entries for alice on portable:\n    {defauts}\n\nRunas and Command-specific defaults for alice:\n    Defaults!/usr/bin/visudo env_keep+=\"SUDO_EDITOR EDITOR\"\n\nUser alice may run the following commands on portable:\n    (ALL) ALL\n"
            )
        };
        assert_eq!(
            defauts_sudo(&liste("secure_path=/usr/bin, passwd_tries=10")),
            (false, None)
        );
        assert_eq!(
            defauts_sudo(&liste("!authenticate, secure_path=/usr/bin")),
            (true, None)
        );
        assert_eq!(defauts_sudo(&liste("!authenticate, authenticate")), (false, None));
        assert_eq!(defauts_sudo(&liste("timestamp_timeout=-1")), (false, Some(-1.0)));
        assert_eq!(
            defauts_sudo(&liste("env_reset, timestamp_timeout=120")),
            (false, Some(120.0))
        );
        assert_eq!(defauts_sudo("    (ALL) ALL\n"), (false, None));
        // Liste coupée en fin de ligne après une virgule.
        let coupee = "Matching Defaults entries for alice on portable:\n    env_reset, timestamp_timeout=-1,\n    !authenticate\n\n";
        assert_eq!(defauts_sudo(coupee), (true, Some(-1.0)));
    }
}
