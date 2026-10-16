//! Audit de sécurité Linux (Arch/Omarchy), sans privilèges root.

use std::path::Path;
use std::process::Command;

use super::{Audit, Constat, alerte, cles_ssh, ok, score, sortie};
use crate::risk::{Niveau, info_port};

pub const NOM: &str = "Linux";

fn service_actif(nom: &str) -> bool {
    sortie("systemctl", &["is-active", nom]).is_some_and(|s| s.trim() == "active")
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

fn pare_feu() -> Constat {
    let ufw = std::fs::read_to_string("/etc/ufw/ufw.conf")
        .is_ok_and(|c| c.lines().any(|l| l.trim() == "ENABLED=yes"))
        && service_actif("ufw");
    if ufw {
        ok("Pare-feu", "ufw est actif.")
    } else if service_actif("nftables") || service_actif("firewalld") {
        ok("Pare-feu", "nftables/firewalld est actif.")
    } else {
        alerte("Pare-feu", Niveau::Eleve, "Aucun pare-feu actif : tout service ouvert est joignable depuis le réseau.").corriger(
            "Activer ufw : bloquer les connexions entrantes, autoriser les sortantes",
            &[
                "command -v ufw >/dev/null || sudo pacman -S --needed --noconfirm ufw",
                "sudo ufw default deny incoming",
                "sudo ufw default allow outgoing",
                "sudo ufw --force enable",
                "sudo systemctl enable --now ufw",
            ],
        )
    }
}

/// Services qui écoutent sur le réseau (pas seulement en local).
fn ports_ecoute(pare_feu_actif: bool, ip_lan: Option<String>) -> Vec<Constat> {
    let Some(ss) = sortie("ss", &["-Htlnp"]) else {
        return vec![alerte("Ports en écoute", Niveau::Info, "Commande ss indisponible.")];
    };
    let mut constats = Vec::new();
    let mut vus = Vec::new();
    for ligne in ss.lines() {
        let c: Vec<&str> = ligne.split_whitespace().collect();
        let Some(local) = c.get(3) else { continue };
        let Some((adresse, port)) = local.rsplit_once(':') else { continue };
        let Ok(port) = port.parse::<u16>() else { continue };
        let expose = matches!(adresse, "0.0.0.0" | "*" | "[::]") || ip_lan.as_deref() == Some(adresse);
        if !expose || vus.contains(&port) {
            continue;
        }
        vus.push(port);
        let programme = c.get(5).and_then(|u| u.split('"').nth(1)).unwrap_or("programme inconnu (root ?)");
        let i = info_port(port);
        // Avec un pare-feu actif, un service exposé n'est en général pas joignable : on baisse d'un cran.
        let niveau = match (pare_feu_actif, i.niveau) {
            (true, Niveau::Critique) => Niveau::Eleve,
            (true, Niveau::Eleve) => Niveau::Moyen,
            (true, _) => Niveau::Info,
            (false, Niveau::Info) => Niveau::Moyen,
            (false, n) => n,
        };
        let constat = alerte(
            "Ports en écoute",
            niveau,
            format!("{port}/tcp ({}) ouvert sur le réseau par « {programme} ». {}", i.service, i.conseil),
        );
        let deny = format!("sudo ufw deny {port}/tcp");
        constats.push(match programme {
            "ollama" => constat.corriger(
                "Faire écouter Ollama uniquement en local (127.0.0.1)",
                &[
                    "sudo mkdir -p /etc/systemd/system/ollama.service.d",
                    "printf '[Service]\\nEnvironment=OLLAMA_HOST=127.0.0.1\\n' | sudo tee /etc/systemd/system/ollama.service.d/netscan.conf >/dev/null",
                    "sudo systemctl daemon-reload",
                    "sudo systemctl restart ollama",
                ],
            ),
            "steam" => constat.manuel(
                "Si tu n'utilises pas Remote Play : Steam > Paramètres > Remote Play > décocher « Activer Remote Play »",
                &[],
            ),
            _ if niveau >= Niveau::Moyen && pare_feu_actif => {
                constat.corriger(format!("Bloquer le port {port} dans le pare-feu"), &[&deny])
            }
            _ => constat,
        });
    }
    if constats.is_empty() {
        constats.push(ok("Ports en écoute", "Aucun service TCP exposé au réseau (tout écoute en local)."));
    }
    constats
}

fn ssh_serveur() -> Constat {
    if !service_actif("sshd") {
        return ok("SSH", "Serveur SSH désactivé.");
    }
    let mut conf = String::new();
    // sshd garde la première valeur trouvée ; sur Arch, les fichiers .d sont inclus avant le reste.
    if let Ok(dir) = std::fs::read_dir("/etc/ssh/sshd_config.d") {
        let mut fichiers: Vec<_> = dir.flatten().map(|f| f.path()).collect();
        fichiers.sort();
        for f in fichiers {
            conf += &std::fs::read_to_string(f).unwrap_or_default();
        }
    }
    conf += &std::fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();
    let valeur = |cle: &str| {
        conf.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| {
                let (k, v) = l.split_once(char::is_whitespace)?;
                k.eq_ignore_ascii_case(cle).then(|| v.trim().to_ascii_lowercase())
            })
    };
    const FICHIER: &str = "/etc/ssh/sshd_config.d/00-netscan.conf";
    if valeur("PermitRootLogin").as_deref() == Some("yes") {
        return alerte("SSH", Niveau::Eleve, "Connexion root autorisée en SSH.").corriger(
            "Interdire la connexion SSH en root",
            &[
                &format!("echo 'PermitRootLogin no' | sudo tee -a {FICHIER} >/dev/null"),
                "sudo sshd -t && sudo systemctl reload sshd",
            ],
        );
    }
    if valeur("PasswordAuthentication").as_deref() != Some("no") {
        let a_des_cles = std::fs::metadata(format!("{}/.ssh/authorized_keys", home())).is_ok_and(|m| m.len() > 0);
        let c = alerte("SSH", Niveau::Moyen, "Connexion SSH par mot de passe permise (vulnérable au brute force).");
        return if a_des_cles {
            c.corriger(
                "N'accepter que les clés SSH (tu as déjà des clés autorisées)",
                &[
                    &format!("printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\n' | sudo tee -a {FICHIER} >/dev/null"),
                    "sudo sshd -t && sudo systemctl reload sshd",
                ],
            )
        } else {
            // Sans clé autorisée, couper les mots de passe t'enfermerait dehors.
            c.manuel(
                "Ajoute d'abord ta clé depuis l'autre ordinateur (ssh-copy-id), puis relance la correction. Ou désactive SSH si inutile :",
                &["sudo systemctl disable --now sshd"],
            )
        };
    }
    ok("SSH", "Serveur SSH actif, clés uniquement, root interdit.")
}

fn mises_a_jour() -> Constat {
    let Some(liste) = sortie("checkupdates", &[]) else {
        // checkupdates sort avec le code 2 quand il n'y a rien à mettre à jour.
        return if Command::new("checkupdates").output().is_ok_and(|o| o.status.code() == Some(2)) {
            ok("Mises à jour", "Système à jour.")
        } else {
            alerte("Mises à jour", Niveau::Info, "Impossible de vérifier (pacman-contrib absent ou hors ligne).")
        };
    };
    let n = liste.lines().count();
    let sensibles = liste
        .lines()
        .filter(|l| ["linux ", "openssl", "openssh", "glibc", "sudo", "firefox", "nvidia"].iter().any(|p| l.starts_with(p)))
        .count();
    let niveau = if n > 50 || sensibles > 0 { Niveau::Eleve } else { Niveau::Moyen };
    alerte("Mises à jour", niveau, format!("{n} paquets à mettre à jour (dont {sensibles} sensibles : noyau, openssl, navigateur…)."))
        .corriger("Mettre le système à jour", &["omarchy update"])
}

fn redemarrage() -> Constat {
    let noyau = sortie("uname", &["-r"]).unwrap_or_default();
    if Path::new("/usr/lib/modules").join(noyau.trim()).exists() {
        ok("Noyau", format!("Le noyau en cours ({}) est celui installé.", noyau.trim()))
    } else {
        alerte("Noyau", Niveau::Moyen, "Noyau mis à jour mais pas encore chargé : les correctifs ne sont pas actifs.")
            .manuel("Redémarrer quand c'est pratique", &["omarchy system reboot"])
    }
}

fn chiffrement_disque() -> Constat {
    if sortie("lsblk", &["-no", "TYPE"]).is_some_and(|s| s.lines().any(|l| l.trim() == "crypt")) {
        ok("Chiffrement", "Disque chiffré (LUKS).")
    } else {
        alerte("Chiffrement", Niveau::Moyen, "Aucun volume chiffré : en cas de vol, les données sont lisibles.")
            .manuel("Le chiffrement complet se choisit à l'installation (Omarchy le propose) : à prévoir à la prochaine réinstallation", &[])
    }
}

fn demarrage_securise() -> Constat {
    let actif = std::fs::read_dir("/sys/firmware/efi/efivars")
        .ok()
        .and_then(|d| d.flatten().find(|f| f.file_name().to_string_lossy().starts_with("SecureBoot-")))
        .and_then(|f| std::fs::read(f.path()).ok())
        .is_some_and(|o| o.last() == Some(&1));
    if actif {
        ok("Secure Boot", "Démarrage sécurisé actif.")
    } else {
        alerte("Secure Boot", Niveau::Info, "Secure Boot désactivé (protège contre les bootkits).")
            .manuel("Se configure avec sbctl puis dans le BIOS ; voir le wiki Arch « Unified Extensible Firmware Interface/Secure Boot »", &[])
    }
}

fn comptes() -> Constat {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let uid0: Vec<&str> = passwd
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split(':').collect();
            (c.get(2) == Some(&"0") && c[0] != "root").then_some(c[0])
        })
        .collect();
    if uid0.is_empty() {
        ok("Comptes", "Seul root a l'UID 0.")
    } else {
        alerte("Comptes", Niveau::Critique, format!("Comptes avec droits root cachés (UID 0) : {}", uid0.join(", ")))
            .manuel("Signe possible d'intrusion : ne pas supprimer à l'aveugle, vérifier d'abord leur origine", &["grep ':0:' /etc/passwd"])
    }
}

fn wifi(passerelle: Option<String>) -> Option<Constat> {
    let s = sortie("nmcli", &["-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"])?;
    let actif = s.lines().find(|l| l.starts_with("yes:"))?;
    let mut c = actif.splitn(3, ':').skip(1);
    let (ssid, secu) = (c.next()?.to_string(), c.next().unwrap_or("").to_string());
    let admin = format!("xdg-open https://{}", passerelle.unwrap_or_else(|| "192.168.1.1".into()));
    let routeur = "Ouvrir l'admin du routeur > Wi-Fi > Sécurité : choisir « WPA2/WPA3 » ou « WPA3 »";
    Some(if secu.is_empty() || secu == "--" {
        alerte("Wi-Fi", Niveau::Eleve, format!("« {ssid} » est un réseau ouvert : le trafic non chiffré est visible."))
            .manuel(routeur, &[&admin])
    } else if secu.contains("WEP") || (secu.contains("WPA1") && !secu.contains("WPA2")) {
        alerte("Wi-Fi", Niveau::Eleve, format!("« {ssid} » utilise {secu}, cassable en minutes.")).manuel(routeur, &[&admin])
    } else if secu.contains("WPA3") {
        ok("Wi-Fi", format!("« {ssid} » en {secu}."))
    } else {
        alerte("Wi-Fi", Niveau::Info, format!("« {ssid} » en {secu}. WPA3 serait mieux si le routeur le permet."))
            .manuel(routeur, &[&admin])
    })
}

fn services_en_echec() -> Constat {
    let n = sortie("systemctl", &["--failed", "--no-legend", "--plain"]).map_or(0, |s| s.lines().count());
    if n == 0 {
        ok("Services", "Aucun service système en échec.")
    } else {
        alerte("Services", Niveau::Info, format!("{n} service(s) en échec.")).manuel("Voir lesquels et leurs erreurs", &["systemctl --failed"])
    }
}

pub fn auditer() -> Audit {
    let feu = pare_feu();
    let feu_actif = feu.probleme.is_none();
    let ip_lan = crate::scan::reseau_local().map(|l| l.1.to_string());

    let mut constats = vec![feu];
    constats.extend(ports_ecoute(feu_actif, ip_lan));
    constats.push(ssh_serveur());
    constats.push(mises_a_jour());
    constats.push(redemarrage());
    constats.push(chiffrement_disque());
    constats.push(demarrage_securise());
    constats.extend(cles_ssh());
    constats.push(comptes());
    constats.extend(wifi(crate::scan::passerelle().map(|g| g.to_string())));
    constats.push(services_en_echec());

    Audit { systeme: NOM, score: score(&constats), constats }
}
