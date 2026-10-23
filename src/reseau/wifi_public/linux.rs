//! Le mode Wi-Fi public sous Linux. Ce qui peut ne vivre que jusqu'au redémarrage le fait : une table nftables à
//! part (`inet vanguard_public`, jamais celle du blocage) qui ferme les entrées de la seule carte Wi-Fi, et les
//! services d'annonce et de partage masqués par `systemctl mask --runtime` (dans /run). Ce qui se règle par réseau
//! est posé sur le profil NetworkManager du café seulement (LLMNR, mDNS, DNS chiffré) : oublié, il ne gêne pas la
//! maison. Les commandes sont pures (essayées sur toutes les plateformes) ; les lectures, elles, ne tournent qu'ici.

use super::etat::{Element, PROPRIETES_NM, UNITES, interface_valide, uuid_valide};
use crate::commande::sh_chaine;

/// La table du mode : à part de celle du blocage (`inet vanguard`), que le blocage vide et repose sans la voir.
pub(crate) const TABLE: &str = "vanguard_public";

/// Le script nft du mode, en une transaction : la table est d'abord créée vide puis retirée, ce qui rend le script
/// rejouable sans erreur si une table d'un allumage interrompu est restée. Seules les entrées de `interface`
/// changent : ce qui est établi (sessions SSH comprises) passe, DHCP (v4, v6) et la découverte des voisins IPv6
/// aussi ; le reste est jeté. Un `drop` d'une chaîne de base est définitif, quelles que soient les autres tables
/// (ufw, firewalld, le blocage) ; un `accept` ici ne passe outre aucune d'elles.
pub(crate) fn script_nft(interface: &str) -> Option<String> {
    interface_valide(interface).then(|| {
        format!(
            "add table inet {TABLE}\n\
             delete table inet {TABLE}\n\
             table inet {TABLE} {{\n\
             \tchain entree {{\n\
             \t\ttype filter hook input priority -5; policy accept;\n\
             \t\tiifname != \"{interface}\" accept\n\
             \t\tct state established,related accept\n\
             \t\tct state invalid drop\n\
             \t\tudp dport {{ 68, 546 }} accept\n\
             \t\ticmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert }} accept\n\
             \t\tdrop\n\
             \t}}\n\
             }}\n"
        )
    })
}

/// Pose la table, puis la relit en administrateur : la commande ne réussit que si la table est là.
pub(crate) fn poser_nft(interface: &str) -> Option<String> {
    Some(format!(
        "printf '%s' {} | sudo nft -f - && sudo nft list table inet {TABLE} >/dev/null",
        sh_chaine(&script_nft(interface)?)
    ))
}

/// Retire la table (rejouable) : réussit seulement si elle n'est plus là ensuite.
pub(crate) fn retirer_nft() -> String {
    format!("sudo nft delete table inet {TABLE} 2>/dev/null; ! sudo nft list table inet {TABLE} >/dev/null 2>&1")
}

/// Masque une unité de la liste fermée jusqu'au redémarrage, et l'arrête.
pub(crate) fn masquer(unite: &str) -> Option<String> {
    UNITES
        .contains(&unite)
        .then(|| format!("sudo systemctl mask --runtime --now {unite}"))
}

/// Retire le masque runtime, puis relance l'unité si elle tournait avant. Rejouable : retirer un masque absent ne
/// fait rien.
pub(crate) fn demasquer(unite: &str, relancer: bool) -> Option<String> {
    if !UNITES.contains(&unite) {
        return None;
    }
    let mut c = format!("sudo systemctl unmask --runtime {unite}");
    if relancer {
        c.push_str(" && sudo systemctl start ");
        c.push_str(unite);
    }
    Some(c)
}

/// Pose des propriétés sur un profil NetworkManager (valeurs des ensembles fermés seulement), puis les applique à la
/// carte si le profil est actif (`device reapply` ne coupe pas la connexion) ; un profil inactif les prendra à son
/// prochain branchement.
pub(crate) fn nm_modifier(uuid: &str, proprietes: &[(&str, &str)]) -> Option<String> {
    if !uuid_valide(uuid) || proprietes.is_empty() {
        return None;
    }
    let mut paires = Vec::new();
    for (p, v) in proprietes {
        let valeurs = PROPRIETES_NM.iter().find(|(nom, _)| nom == p)?.1;
        if !valeurs.contains(v) {
            return None;
        }
        paires.push(format!("{p} {v}"));
    }
    Some(format!(
        "sudo nmcli connection modify {uuid} {} && carte=$(nmcli -t -f UUID,DEVICE connection show --active | grep -m1 \
         '^{uuid}:' | cut -d: -f2) && {{ [ -z \"$carte\" ] || sudo nmcli device reapply \"$carte\"; }}",
        paires.join(" ")
    ))
}

/// La commande qui remet un élément propre à Linux (le DNS passe par `optimiser`).
pub(crate) fn remettre(e: &Element) -> Option<String> {
    if !e.valide() {
        return None;
    }
    match e {
        Element::NftTable { .. } => Some(retirer_nft()),
        Element::UniteRuntime { unite, actif_avant } => demasquer(unite, *actif_avant),
        Element::Nm { uuid, propriete, avant } => nm_modifier(uuid, &[(propriete.as_str(), avant.as_str())]),
        _ => None,
    }
}

/// Une valeur d'énumération de NetworkManager lue en mode terse (« -1 », « 0 »…) ou en clair, sous son nom.
pub(crate) fn nom_nm(propriete: &str, lu: &str) -> Option<&'static str> {
    let un = if propriete == "connection.dns-over-tls" {
        "opportunistic"
    } else {
        "resolve"
    };
    let nom = match lu.split_whitespace().next()? {
        "-1" | "default" => "default",
        "0" | "no" => "no",
        "1" | "resolve" | "opportunistic" => un,
        "2" | "yes" => "yes",
        _ => return None,
    };
    Some(nom)
}

/// Une unité masquée par le mode est-elle revenue ? Sans masque, et de nouveau active si elle tournait avant : démasquée
/// mais pas relancée (son socket encore masqué au moment du `start`), l'annonce du nom resterait coupée.
pub(crate) fn unite_revenue(masque: bool, actif_avant: bool, actif: bool) -> bool {
    !masque && (!actif_avant || actif)
}

/// `nmcli -t -g UUID connection show` (lu sans erreur) : ce profil n'existe plus (« Oublier ce réseau »). Rien ne
/// reste alors à remettre sur lui ; une lecture ratée, elle, ne le dit jamais.
pub(crate) fn profil_absent_de(liste: &str, uuid: &str) -> bool {
    uuid_valide(uuid) && !liste.lines().any(|u| u.trim() == uuid)
}

/// Le chemin d'un masque runtime : un lien vers /dev/null.
pub(crate) fn masque_runtime_dans(dossier: &std::path::Path, unite: &str) -> bool {
    std::fs::read_link(dossier.join(unite)).is_ok_and(|cible| cible == std::path::Path::new("/dev/null"))
}

/// `nmcli -t -e no -f DEVICE,TYPE,STATE,CON-UUID device` : la carte Wi-Fi connectée et l'UUID de son profil.
pub(crate) fn wifi_connectee(sortie: &str) -> Option<(String, String)> {
    sortie.lines().find_map(|l| {
        let c: Vec<&str> = l.split(':').collect();
        (c.len() == 4 && c[1] == "wifi" && c[2] == "connected" && interface_valide(c[0]) && uuid_valide(c[3]))
            .then(|| (c[0].to_string(), c[3].to_string()))
    })
}

/// L'adresse de la page que NetworkManager interroge pour savoir s'il y a un portail (section `[connectivity]`,
/// `uri=`), en http seulement : ouverte dans le navigateur, un portail la détourne vers sa page de connexion.
pub(crate) fn uri_de_connectivite(textes: &[String]) -> Option<String> {
    let mut trouvee = None;
    for t in textes {
        let mut dedans = false;
        for l in t.lines().map(str::trim) {
            if l.starts_with('[') {
                dedans = l == "[connectivity]";
            } else if dedans && let Some(v) = l.strip_prefix("uri=") {
                trouvee = Some(v.trim().to_string());
            }
        }
    }
    trouvee.filter(|u| {
        u.starts_with("http://")
            && u.len() <= 200
            && u.bytes()
                .all(|o| o.is_ascii_alphanumeric() || b":/.-_~?=&%".contains(&o))
    })
}

#[cfg(target_os = "linux")]
pub(crate) mod lecture {
    use std::process::Command;

    use super::super::etat::{Element, UNITES};
    use super::{nom_nm, uuid_valide};

    pub(crate) const RUNTIME: &str = "/run/systemd/system";

    fn nmcli(args: &[&str]) -> Option<String> {
        let r = crate::commande::lancer_en_anglais(Command::new("nmcli").args(args), 10)?;
        (r.code == Some(0)).then(|| r.sortie.trim().to_string())
    }

    /// La carte Wi-Fi connectée, l'UUID de son profil et son nom de réseau.
    pub(crate) fn wifi() -> Option<(String, String, String)> {
        let sortie = nmcli(&["-t", "-e", "no", "-f", "DEVICE,TYPE,STATE,CON-UUID", "device"])?;
        let (carte, uuid) = super::wifi_connectee(&sortie)?;
        let nom = nmcli(&[
            "-t",
            "-e",
            "no",
            "-g",
            "802-11-wireless.ssid",
            "connection",
            "show",
            &uuid,
        ])
        .unwrap_or_default();
        Some((carte, uuid, nom))
    }

    /// La protection du réseau connecté, telle que nmcli la nomme (« WPA2 », « » pour ouvert).
    pub(crate) fn securite() -> Option<String> {
        let s = nmcli(&[
            "-t",
            "-e",
            "no",
            "-f",
            "ACTIVE,SECURITY,SSID",
            "dev",
            "wifi",
            "list",
            "--rescan",
            "no",
        ])?;
        crate::machine::wifi::lire_nmcli(&s)
            .into_iter()
            .find(|v| v.actif)
            .map(|v| v.securite)
    }

    /// L'avis de NetworkManager sur la connexion, d'après son propre test (rien n'est envoyé ici) : « portal »,
    /// « limited », « full », « none », « unknown » (test coupé).
    pub(crate) fn connectivite() -> Option<String> {
        nmcli(&["-t", "-f", "CONNECTIVITY", "general"])
    }

    pub(crate) fn nm(uuid: &str, propriete: &str) -> Option<&'static str> {
        if !uuid_valide(uuid) {
            return None;
        }
        nom_nm(
            propriete,
            &nmcli(&["-t", "-e", "no", "-g", propriete, "connection", "show", uuid])?,
        )
    }

    /// Les unités de la liste fermée présentes sur ce système, si elles tournent, et si un masque runtime y est.
    pub(crate) fn unites() -> Vec<(&'static str, bool, bool)> {
        let presentes: Vec<&'static str> = UNITES
            .into_iter()
            .filter(|u| crate::machine::linux::natif::unite_existe(u))
            .collect();
        if presentes.is_empty() {
            return Vec::new();
        }
        let actives =
            crate::commande::lancer_en_anglais(Command::new("systemctl").arg("is-active").args(&presentes), 10)
                .map(|r| r.sortie)
                .unwrap_or_default();
        let actives: Vec<bool> = actives.lines().map(|l| l.trim() == "active").collect();
        presentes
            .into_iter()
            .enumerate()
            .map(|(i, u)| {
                (
                    u,
                    actives.get(i).copied().unwrap_or(false),
                    super::masque_runtime_dans(std::path::Path::new(RUNTIME), u),
                )
            })
            .collect()
    }

    /// Le démarrage en cours du système.
    pub(crate) fn demarrage() -> String {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|t| t.trim().to_string())
            .unwrap_or_default()
    }

    /// systemd-resolved répond aux noms (NetworkManager lui confie alors le DNS de chaque carte) : seul lui sait
    /// chiffrer le DNS d'un seul profil.
    pub(crate) fn resolved() -> bool {
        std::fs::read_to_string("/etc/resolv.conf").is_ok_and(|t| {
            t.lines()
                .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["nameserver", "127.0.0.53"])
        }) && crate::machine::linux::natif::services_actifs(&["systemd-resolved"]).is_some_and(|a| a == [true])
    }

    pub(crate) fn nft_present() -> bool {
        crate::machine::linux::natif::present("nft")
    }

    /// Les fichiers de NetworkManager où se règle son test de connectivité, dans l'ordre où il les lit.
    pub(crate) fn uri_de_connectivite() -> Option<String> {
        let mut textes = Vec::new();
        for d in [
            "/usr/lib/NetworkManager/conf.d",
            "/run/NetworkManager/conf.d",
            "/etc/NetworkManager/conf.d",
        ] {
            let mut fichiers: Vec<_> = std::fs::read_dir(d)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "conf"))
                .collect();
            fichiers.sort();
            textes.extend(fichiers.iter().filter_map(|p| std::fs::read_to_string(p).ok()));
        }
        textes.extend(std::fs::read_to_string("/etc/NetworkManager/NetworkManager.conf").ok());
        super::uri_de_connectivite(&textes)
    }

    /// Le profil n'existe plus dans NetworkManager (lu sans erreur) : supprimé, rien à remettre sur lui.
    pub(crate) fn profil_absent(uuid: &str) -> bool {
        uuid_valide(uuid)
            && nmcli(&["-t", "-e", "no", "-g", "UUID", "connection", "show"])
                .is_some_and(|l| super::profil_absent_de(&l, uuid))
    }

    fn active(unite: &str) -> bool {
        crate::commande::lancer_en_anglais(Command::new("systemctl").args(["is-active", "--quiet", unite]), 10)
            .is_some_and(|r| r.code == Some(0))
    }

    /// L'élément est-il revenu à sa valeur d'avant ? `None` : ne se relit pas sans droits (la table nft dans le même
    /// démarrage).
    pub(crate) fn a_l_avant(e: &Element, meme_demarrage: bool) -> Option<bool> {
        match e {
            // Sans droits, la table ne se lit pas ; un autre démarrage l'a forcément emportée.
            Element::NftTable { .. } => (!meme_demarrage).then_some(true),
            Element::UniteRuntime { unite, actif_avant } => {
                let masque = super::masque_runtime_dans(std::path::Path::new(RUNTIME), unite);
                Some(super::unite_revenue(masque, *actif_avant, !masque && active(unite)))
            }
            Element::Nm { uuid, propriete, avant } => match nm(uuid, propriete) {
                Some(v) => Some(v == avant),
                None => profil_absent(uuid).then_some(true),
            },
            Element::Dns { avant } => match crate::optimiser::dns_relu(avant) {
                Some(v) => Some(v == *avant),
                None => avant
                    .split_once('\n')
                    .is_some_and(|(u, _)| profil_absent(u))
                    .then_some(true),
            },
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const U: &str = "0b8c2f4e-1a2b-4c3d-9e8f-001122334455";

    #[test]
    fn script_nft_exact() {
        let s = script_nft("wlan0").unwrap();
        assert!(s.starts_with("add table inet vanguard_public\ndelete table inet vanguard_public\n"));
        assert!(s.contains("iifname != \"wlan0\" accept"));
        assert!(s.contains("type filter hook input priority -5; policy accept;"));
        assert!(s.trim_end().ends_with("drop\n\t}\n}"), "{s}");
        // Jamais la table du blocage.
        assert!(!s.contains("inet vanguard {") && !s.contains("inet vanguard\n"));
        for mauvaise in ["wlan0\"; flush ruleset; \"", "wlan0 ", "", "carte-bien-trop-longue"] {
            assert!(script_nft(mauvaise).is_none(), "{mauvaise}");
            assert!(poser_nft(mauvaise).is_none());
        }
        assert!(poser_nft("wlp2s0").unwrap().starts_with("printf '%s' 'add table"));
    }

    #[test]
    fn commandes_rejouables_et_fermees() {
        // Retirer deux fois : mêmes commandes, la seconde ne trouve rien et réussit quand même.
        assert_eq!(retirer_nft(), retirer_nft());
        assert!(retirer_nft().contains("! sudo nft list table inet vanguard_public"));
        assert_eq!(
            masquer("avahi-daemon.socket").as_deref(),
            Some("sudo systemctl mask --runtime --now avahi-daemon.socket")
        );
        assert!(masquer("sshd.service").is_none() && masquer("avahi-daemon.service; reboot").is_none());
        assert_eq!(
            demasquer("smb.service", true).as_deref(),
            Some("sudo systemctl unmask --runtime smb.service && sudo systemctl start smb.service")
        );
        assert_eq!(
            demasquer("wsdd.service", false).as_deref(),
            Some("sudo systemctl unmask --runtime wsdd.service")
        );
        let c = nm_modifier(U, &[("connection.mdns", "no"), ("connection.llmnr", "no")]).unwrap();
        assert!(c.starts_with(&format!(
            "sudo nmcli connection modify {U} connection.mdns no connection.llmnr no && "
        )));
        assert!(nm_modifier(U, &[("connection.mdns", "non")]).is_none());
        assert!(nm_modifier(U, &[("ipv4.method", "manual")]).is_none());
        assert!(nm_modifier("pas-un-uuid", &[("connection.mdns", "no")]).is_none());
        assert!(nm_modifier(U, &[]).is_none());
        // Remettre : la valeur notée, telle quelle.
        let e = Element::Nm {
            uuid: U.into(),
            propriete: "connection.dns-over-tls".into(),
            avant: "default".into(),
        };
        assert!(remettre(&e).unwrap().contains("connection.dns-over-tls default"));
        let mauvais = Element::Nm {
            uuid: U.into(),
            propriete: "connection.dns-over-tls".into(),
            avant: "yes; reboot".into(),
        };
        assert!(remettre(&mauvais).is_none());
        // Chaque commande est du shell valide.
        for c in [
            poser_nft("wlan0").unwrap(),
            retirer_nft(),
            masquer("wsdd2.service").unwrap(),
            demasquer("nmb.service", true).unwrap(),
            nm_modifier(U, &[("connection.dns-over-tls", "opportunistic")]).unwrap(),
        ] {
            let r = std::process::Command::new("bash")
                .args(["-n", "-c", &c])
                .status()
                .unwrap();
            assert!(r.success(), "{c}");
        }
    }

    #[test]
    fn valeurs_de_networkmanager_par_leur_nom() {
        assert_eq!(nom_nm("connection.mdns", "-1"), Some("default"));
        assert_eq!(nom_nm("connection.mdns", "1"), Some("resolve"));
        assert_eq!(nom_nm("connection.dns-over-tls", "1"), Some("opportunistic"));
        assert_eq!(nom_nm("connection.llmnr", "0 (no)"), Some("no"));
        assert_eq!(nom_nm("connection.dns-over-tls", "yes"), Some("yes"));
        assert_eq!(nom_nm("connection.mdns", "7"), None);
        assert_eq!(nom_nm("connection.mdns", ""), None);
    }

    #[test]
    fn carte_wifi_et_test_de_connectivite() {
        let sortie = format!(
            "enp3s0:ethernet:unavailable:\nwlan0:wifi:connected:{U}\np2p-dev-wlan0:wifi-p2p:disconnected:\nlo:loopback:connected (externally):{U}"
        );
        assert_eq!(wifi_connectee(&sortie), Some(("wlan0".into(), U.into())));
        assert_eq!(wifi_connectee("wlan0:wifi:disconnected:"), None);
        assert_eq!(
            wifi_connectee(&format!("wlan0:wifi:connecting (getting IP configuration):{U}")),
            None
        );
        let arch = "[connectivity]\nuri=http://ping.archlinux.org/nm-check.txt\n".to_string();
        let local = "[main]\nplugins=keyfile\n[connectivity]\nuri=http://exemple.test/x.txt\n".to_string();
        assert_eq!(
            uri_de_connectivite(std::slice::from_ref(&arch)).as_deref(),
            Some("http://ping.archlinux.org/nm-check.txt")
        );
        // Le dernier fichier lu l'emporte.
        assert_eq!(
            uri_de_connectivite(&[arch, local]).as_deref(),
            Some("http://exemple.test/x.txt")
        );
        assert!(uri_de_connectivite(&["[connectivity]\nuri=https://x.test/\n".to_string()]).is_none());
        assert!(uri_de_connectivite(&["[connectivity]\nuri=http://x.test/\"$(id)\n".to_string()]).is_none());
        assert!(uri_de_connectivite(&["[main]\nuri=http://x.test/\n".to_string()]).is_none());
    }

    /// Avahi : le service démasqué mais pas relancé (son socket encore masqué au `start`) n'est pas revenu.
    #[test]
    fn unite_demasquee_mais_arretee_pas_revenue() {
        assert!(!unite_revenue(false, true, false));
        assert!(unite_revenue(false, true, true));
        assert!(unite_revenue(false, false, false));
        assert!(!unite_revenue(true, true, true));
    }

    /// Un profil oublié dans NetworkManager : absent de la liste lue. Une liste vide est lue (aucun profil) ; une
    /// lecture ratée n'arrive jamais ici.
    #[test]
    fn profil_supprime_reconnu() {
        let autre = "11111111-2222-3333-4444-555555555555";
        assert!(profil_absent_de(&format!("{autre}\n"), U));
        assert!(profil_absent_de("", U));
        assert!(!profil_absent_de(&format!("{autre}\n{U}\n"), U));
        assert!(!profil_absent_de("", "pas-un-uuid"));
    }

    #[test]
    fn masque_runtime_lu_dans_un_dossier() {
        let d = std::env::temp_dir().join(format!("vanguard-masque-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::os::unix::fs::symlink("/dev/null", d.join("avahi-daemon.service")).unwrap();
        std::os::unix::fs::symlink("/usr/lib/systemd/system/wsdd.service", d.join("wsdd.service")).unwrap();
        assert!(masque_runtime_dans(&d, "avahi-daemon.service"));
        assert!(!masque_runtime_dans(&d, "wsdd.service"));
        assert!(!masque_runtime_dans(&d, "smb.service"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La vraie table, posée puis retirée dans un espace de noms réseau à soi (`unshare -rn`) : rien ne touche la
    /// machine. Sautée sans nft ou sans espaces de noms.
    #[test]
    fn table_posee_puis_retiree_dans_un_espace_a_soi() {
        let nft = ["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(nft) = nft else {
            return crate::essais::saute("nft absent");
        };
        let essai = std::process::Command::new("unshare").args(["-rn", "true"]).status();
        if !essai.is_ok_and(|s| s.success()) {
            return crate::essais::saute("espaces de noms indisponibles");
        }
        let d = std::env::temp_dir().join(format!("vanguard-nft-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let fichier = d.join("public.nft");
        std::fs::write(&fichier, script_nft("wlan0").unwrap()).unwrap();
        // Posée deux fois (allumage interrompu puis refait), relue, puis retirée deux fois.
        let script = format!(
            "{nft} -f {f} && {nft} -f {f} && {nft} list table inet {TABLE} && {nft} delete table inet {TABLE} && \
             {{ {nft} delete table inet {TABLE} 2>/dev/null; ! {nft} list table inet {TABLE} >/dev/null 2>&1; }}",
            f = fichier.display()
        );
        let r = std::process::Command::new("unshare")
            .args(["-rn", "sh", "-c", &script])
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&d);
        let texte = String::from_utf8_lossy(&r.stdout);
        if !r.status.success() && String::from_utf8_lossy(&r.stderr).contains("Operation not permitted") {
            return crate::essais::saute("nft refusé dans l'espace de noms");
        }
        assert!(r.status.success(), "{}{}", texte, String::from_utf8_lossy(&r.stderr));
        assert!(
            texte.contains("iifname != \"wlan0\" accept") && texte.contains("drop"),
            "{texte}"
        );
    }
}
