//! Réglages de Linux : services de systemd, fichiers de réglage posés par Gardien, préférences de GNOME, options des
//! distributions (Ubuntu, Debian). Chacun n'est proposé que si cette machine en a l'usage : un SSD pour l'entretien
//! des SSD, GNOME pour ses préférences, le paquet concerné pour les options des distributions.

use std::path::Path;
use std::process::Command;

use super::{Categorie, Reglage, Valeur};
use crate::ui::*;

pub enum Changement {
    /// Minuterie ou service de systemd : « enabled » ou « disabled ». `defaut` : son état sur un système neuf.
    Unite {
        nom: &'static str,
        cible: &'static str,
        defaut: &'static str,
    },
    /// Fichier posé par Gardien (présent = fait), retiré pour annuler ; `apres`, la commande qui le fait prendre.
    /// `ancien` : le même fichier posé sous un ancien nom (sentinel), lu à sa place et retiré avec lui.
    Fichier {
        chemin: &'static str,
        ancien: Option<&'static str>,
        contenu: &'static str,
        apres: &'static str,
    },
    /// Préférence de GNOME (gsettings), avec sa valeur d'origine.
    Gnome {
        schema: &'static str,
        cle: &'static str,
        cible: &'static str,
        defaut: &'static str,
    },
    /// Ligne « CLE=valeur » d'un fichier de configuration du système.
    Option {
        fichier: &'static str,
        cle: &'static str,
        cible: &'static str,
        defaut: &'static str,
    },
    /// DNS d'une connexion de NetworkManager (outil « DNS le plus rapide »). Valeur : « uuid\ndns4|ignore4|dns6|ignore6 »,
    /// les serveurs séparés par des virgules ; « ignore » (yes, no) dit si ceux de la box sont écartés. `cible` :
    /// `None` quand le réglage n'est rebâti que pour être annulé.
    Dns { connexion: String, cible: Option<String> },
}

/// Une propriété d'une connexion de NetworkManager, sans échappement (les « : » des adresses IPv6 restent).
fn nm_valeur(connexion: &str, propriete: &str) -> Option<String> {
    let r = crate::commande::lancer(
        Command::new("nmcli").args(["-t", "-e", "no", "-g", propriete, "connection", "show", connexion]),
        10,
    )?;
    (r.code == Some(0)).then(|| r.sortie.trim().to_string())
}

/// Liste de serveurs normalisée : « 1.1.1.1,1.0.0.1 », quel que soit le séparateur lu.
fn liste_dns(t: &str) -> String {
    t.split([',', ' ', ';'])
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

/// Un identifiant de connexion de NetworkManager (UUID) : il entre tel quel dans les commandes.
fn uuid_valide(t: &str) -> bool {
    t.len() == 36 && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Ce que dit une valeur de DNS : les serveurs listés, et si ceux de la box servent encore.
fn decrire_dns(v: Option<&str>) -> String {
    let reste = v.and_then(|v| v.split_once('\n')).map_or("", |(_, r)| r);
    let c: Vec<&str> = reste.split('|').collect();
    let serveurs: Vec<&str> = [0, 2]
        .iter()
        .filter_map(|&i| c.get(i))
        .flat_map(|l| l.split(','))
        .filter(|s| !s.is_empty())
        .collect();
    super::texte_dns(&serveurs, c.get(1) != Some(&"yes"))
}

/// Carte réseau de la route par défaut dans /proc/net/route (la plus petite métrique, via une passerelle).
fn carte_par_defaut(table: &str) -> Option<String> {
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            let drapeaux = u32::from_str_radix(c.get(3)?, 16).ok()?;
            // Route vers tout (destination 0), par une passerelle, active (drapeaux UP et GATEWAY).
            if c.get(1) != Some(&"00000000") || c.get(2) == Some(&"00000000") || drapeaux & 0x3 != 0x3 {
                return None;
            }
            Some((c.get(6)?.parse::<u32>().ok()?, (*c.first()?).to_string()))
        })
        .min()
        .map(|(_, carte)| carte)
}

/// Le DNS de la connexion principale (celle de la route par défaut), à régler sur ces serveurs ; ceux en IPv6
/// seulement si la connexion se sert de l'IPv6. Erreur : pourquoi il faut le faire à la main.
pub fn dns_principal(v4: &[&str], v6: &[&str]) -> Result<Changement, String> {
    let a_la_main = tr!(
        "NetworkManager ne gère pas cette connexion : le DNS se règle à la main (paramètres réseau, ou dans la box).",
        "NetworkManager does not manage this connection: set the DNS by hand (network settings, or in the router)."
    );
    let carte = std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|t| carte_par_defaut(&t))
        .ok_or_else(|| tr!("Pas de connexion à Internet.", "No Internet connection.").to_string())?;
    let connexion = sortie(
        "nmcli",
        &["-t", "-e", "no", "-f", "UUID,DEVICE", "connection", "show", "--active"],
    )
    .unwrap_or_default()
    .lines()
    .find_map(|l| {
        let (uuid, appareil) = l.split_once(':')?;
        (appareil == carte && uuid_valide(uuid)).then(|| uuid.to_string())
    })
    .ok_or_else(|| a_la_main.to_string())?;
    let actuel = Changement::Dns {
        connexion: connexion.clone(),
        cible: None,
    }
    .lire()
    .ok_or_else(|| a_la_main.to_string())?;
    let c: Vec<&str> = actuel.split_once('\n').map_or("", |(_, r)| r).split('|').collect();
    let ipv6 = !matches!(
        nm_valeur(&connexion, "ipv6.method").as_deref(),
        None | Some("disabled" | "ignore")
    );
    let (dns6, ignore6) = if ipv6 && !v6.is_empty() {
        (v6.join(","), "yes".to_string())
    } else {
        (
            c.get(2).copied().unwrap_or_default().to_string(),
            c.get(3).copied().unwrap_or("no").to_string(),
        )
    };
    Ok(Changement::Dns {
        connexion,
        cible: Some(format!("{}|yes|{dns6}|{ignore6}", v4.join(","))),
    })
}

fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
    let r = crate::commande::lancer(Command::new(cmd).args(args), 10)?;
    Some(r.sortie.trim().to_string())
}

/// Entre apostrophes, pour bash.
fn shell(t: &str) -> String {
    format!("'{}'", t.replace('\'', r"'\''"))
}

impl Changement {
    pub fn lire(&self) -> Valeur {
        match self {
            // « is-enabled » répond aussi par son code de retour : seul le texte compte ici.
            Changement::Unite { nom, .. } => sortie("systemctl", &["is-enabled", nom]).filter(|t| !t.is_empty()),
            Changement::Fichier {
                chemin,
                ancien,
                contenu,
                ..
            } => {
                let t = std::fs::read_to_string(chemin)
                    .or_else(|e| ancien.map_or(Err(e), std::fs::read_to_string))
                    .ok()?;
                Some(if t == *contenu { "present" } else { "autre" }.to_string())
            }
            Changement::Gnome { schema, cle, .. } => sortie("gsettings", &["get", schema, cle]),
            Changement::Option { fichier, cle, .. } => std::fs::read_to_string(fichier).ok()?.lines().find_map(|l| {
                l.trim()
                    .strip_prefix(cle)
                    .and_then(|r| r.strip_prefix('='))
                    .map(|v| v.trim().to_string())
            }),
            Changement::Dns { connexion, .. } => {
                let champ = |p| nm_valeur(connexion, p);
                Some(format!(
                    "{connexion}\n{}|{}|{}|{}",
                    liste_dns(&champ("ipv4.dns")?),
                    champ("ipv4.ignore-auto-dns")?,
                    liste_dns(&champ("ipv6.dns")?),
                    champ("ipv6.ignore-auto-dns")?
                ))
            }
        }
    }

    // Même forme que `lire`, pour les comparer.
    #[allow(clippy::unnecessary_wraps)]
    pub fn cible(&self) -> Valeur {
        Some(match self {
            Changement::Unite { cible, .. } | Changement::Gnome { cible, .. } | Changement::Option { cible, .. } => {
                (*cible).to_string()
            }
            Changement::Fichier { .. } => "present".to_string(),
            // Rebâti pour être annulé : une cible qu'aucune lecture ne donne.
            Changement::Dns { connexion, cible } => format!("{connexion}\n{}", cible.as_deref().unwrap_or("?")),
        })
    }

    pub fn defaut(&self) -> Valeur {
        match self {
            Changement::Unite { defaut, .. } | Changement::Gnome { defaut, .. } | Changement::Option { defaut, .. } => {
                Some((*defaut).to_string())
            }
            Changement::Fichier { .. } => None,
            // Les DNS donnés par la box, en IPv4 comme en IPv6.
            Changement::Dns { connexion, .. } => Some(format!("{connexion}\n|no||no")),
        }
    }

    /// La connexion d'un réglage de DNS.
    pub fn identite_dns(&self) -> Option<&str> {
        match self {
            Changement::Dns { connexion, .. } => Some(connexion),
            _ => None,
        }
    }

    /// Le réglage de DNS rebâti d'après sa valeur d'avant notée, pour l'annuler.
    pub fn dns_note(avant: &str) -> Option<Changement> {
        let (connexion, _) = avant.split_once('\n')?;
        uuid_valide(connexion).then(|| Changement::Dns {
            connexion: connexion.to_string(),
            cible: None,
        })
    }

    pub fn decrire(&self, v: Option<&str>) -> String {
        match self {
            Changement::Unite { nom, .. } => format!("systemctl {} {nom}", v.map_or("?", etat_unite)),
            Changement::Fichier { chemin, .. } => match v {
                Some(_) => trf!("{chemin} : posé", "{chemin}: written"),
                None => trf!("{chemin} : retiré", "{chemin}: removed"),
            },
            Changement::Gnome { schema, cle, .. } => match v {
                Some(v) => format!("gsettings set {schema} {cle} {v}"),
                None => format!("gsettings reset {schema} {cle}"),
            },
            Changement::Option { fichier, cle, .. } => match v {
                Some(v) => format!("{fichier} : {cle}={v}"),
                None => trf!("{fichier} : ligne {cle} retirée", "{fichier}: line {cle} removed"),
            },
            Changement::Dns { .. } => decrire_dns(v),
        }
    }

    /// La commande qui met la valeur `v`.
    fn commande(&self, v: Option<&str>) -> Option<String> {
        Some(match self {
            Changement::Unite { nom, .. } => match v? {
                "enabled" => format!("sudo systemctl enable --now {nom}"),
                "disabled" => format!("sudo systemctl disable --now {nom}"),
                "masked" => format!("sudo systemctl mask --now {nom}"),
                // « static », « indirect » : pas un état qu'on choisit, rien à remettre.
                _ => return None,
            },
            Changement::Fichier {
                chemin,
                ancien,
                contenu,
                apres,
            } => {
                let anciens = ancien
                    .map(|a| format!("sudo rm -f {} && ", shell(a)))
                    .unwrap_or_default();
                match v {
                    Some(_) => {
                        let dossier = Path::new(chemin).parent()?.display().to_string();
                        format!(
                            "{anciens}sudo mkdir -p {} && printf '%s' {} | sudo tee {} >/dev/null && {apres}",
                            shell(&dossier),
                            shell(contenu),
                            shell(chemin)
                        )
                    }
                    None => format!("{anciens}sudo rm -f {} && {apres}", shell(chemin)),
                }
            }
            Changement::Gnome { schema, cle, .. } => match v {
                Some(v) => format!("gsettings set {schema} {cle} {}", shell(v)),
                None => format!("gsettings reset {schema} {cle}"),
            },
            Changement::Option { fichier, cle, .. } => {
                let f = shell(fichier);
                match v {
                    // La ligne est remplacée si elle existe, ajoutée sinon. Dans le remplacement de sed, « \ », « | »
                    // et « & » sont protégés : une valeur d'avant remise doit l'être telle quelle.
                    Some(v) => format!(
                        "if grep -q '^{cle}=' {f}; then sudo sed -i 's|^{cle}=.*|{cle}={}|' {f}; else echo {} | sudo tee -a {f} >/dev/null; fi",
                        v.replace('\\', r"\\")
                            .replace('|', r"\|")
                            .replace('&', r"\&")
                            .replace('\'', r"'\''"),
                        shell(&format!("{cle}={v}")),
                    ),
                    // Absente avant le changement : la ligne est retirée.
                    None => format!("sudo sed -i '/^{cle}=/d' {f}"),
                }
            }
            Changement::Dns { connexion, .. } => {
                let (id, reste) = v?.split_once('\n')?;
                if id != connexion || !uuid_valide(connexion) {
                    return None;
                }
                let [dns4, ignore4, dns6, ignore6] = reste.split('|').collect::<Vec<_>>()[..] else {
                    return None;
                };
                let oui_non = |t: &str| if t == "yes" { "yes" } else { "no" };
                // Appliqué tout de suite à la carte active (reapply ne coupe pas la connexion) ; une connexion inactive
                // le prendra à son prochain branchement.
                format!(
                    "sudo nmcli connection modify {connexion} ipv4.dns {} ipv4.ignore-auto-dns {} ipv6.dns {} \
                     ipv6.ignore-auto-dns {} && carte=$(nmcli -t -f UUID,DEVICE connection show --active | grep -m1 \
                     '^{connexion}:' | cut -d: -f2) && {{ [ -z \"$carte\" ] || sudo nmcli device reapply \"$carte\"; }}",
                    shell(&dns4.replace(',', " ")),
                    oui_non(ignore4),
                    shell(&dns6.replace(',', " ")),
                    oui_non(ignore6)
                )
            }
        })
    }

    fn admin(&self) -> bool {
        !matches!(self, Changement::Gnome { .. })
    }
}

fn etat_unite(v: &str) -> &str {
    match v {
        "enabled" => "enable",
        "disabled" => "disable",
        "masked" => "mask",
        autre => autre,
    }
}

/// Applique des lots de changements (un lot par réglage), point de restauration d'abord si le système est touché.
pub fn ecrire(lots: &[Vec<(&Changement, Valeur)>]) -> Vec<bool> {
    if lots.iter().flatten().any(|(c, _)| c.admin())
        && let Some((outil, point)) = crate::reparer::point_restauration(tr!("réglages", "settings"))
    {
        trp!(
            "    {GRIS}Point de restauration d'abord ({outil}).{RESET}",
            "    {GRIS}Restore point first ({outil}).{RESET}"
        );
        if !crate::machine::appliquer(&[point])
            && !demander(tr!(
                "    ✖ Point de restauration impossible. Continuer quand même ? [o/N] : ",
                "    ✖ Restore point not possible. Continue anyway? [y/N]: "
            ))
            .oui()
        {
            return vec![false; lots.len()];
        }
    }
    let commandes: Vec<Vec<String>> = lots
        .iter()
        .map(|lot| lot.iter().filter_map(|(c, v)| c.commande(v.as_deref())).collect())
        .collect();
    crate::machine::appliquer_chacune(&commandes)
}

pub fn apres(_touches: &[&Reglage]) {}

fn unite_existe(nom: &str) -> bool {
    crate::commande::lancer(Command::new("systemctl").args(["cat", nom]), 10).is_some_and(|r| r.code == Some(0))
}

/// Au moins un disque sans pièce mobile (SSD, NVMe) : `lsblk` le marque ROTA 0.
fn ssd() -> bool {
    sortie("lsblk", &["-dno", "NAME,ROTA,TYPE"]).is_some_and(|t| a_un_ssd(&t))
}

/// `lsblk -dno NAME,ROTA,TYPE` : la mémoire compressée (zram) se dit aussi « disque » sans pièce mobile, mais TRIM
/// n'y a pas de sens.
fn a_un_ssd(lsblk: &str) -> bool {
    lsblk.lines().any(|l| {
        let c: Vec<&str> = l.split_whitespace().collect();
        matches!(c[..], [nom, "0", "disk"] if !nom.starts_with("zram") && !nom.starts_with("loop"))
    })
}

fn gnome() -> bool {
    std::env::var("XDG_CURRENT_DESKTOP").is_ok_and(|d| d.to_uppercase().contains("GNOME"))
        && sortie("gsettings", &["list-keys", "org.gnome.desktop.privacy"]).is_some_and(|t| !t.is_empty())
}

pub fn catalogue() -> Vec<Reglage> {
    use Categorie::{Confidentialite, Confort, Performance};
    let systemd = Path::new("/run/systemd/system").is_dir();
    let mut l = Vec::new();
    if systemd && unite_existe("fstrim.timer") && ssd() {
        l.push(Reglage {
            id: "fstrim",
            categorie: Performance,
            titre: tr!("Entretien du SSD chaque semaine", "Weekly SSD maintenance"),
            effet: tr!(
                "Une fois par semaine, le système dit au SSD quelles zones sont libres (TRIM) : les écritures restent rapides et le disque s'use moins.",
                "Once a week, the system tells the SSD which areas are free (TRIM): writes stay fast and the drive wears less."
            ),
            prudence: None,
            recommande: true,
            changements: vec![Changement::Unite {
                nom: "fstrim.timer",
                cible: "enabled",
                defaut: "disabled",
            }],
        });
    }
    if systemd {
        l.push(Reglage {
            id: "journal_taille",
            categorie: Performance,
            titre: tr!("Journal du système limité à 500 Mo", "System journal capped at 500 MB"),
            effet: tr!(
                "Les journaux du système ne prennent plus jusqu'à 4 Go : les plus anciens s'effacent au-delà de 500 Mo.",
                "System logs no longer take up to 4 GB: the oldest are removed beyond 500 MB."
            ),
            prudence: Some(tr!(
                "L'historique des journaux remonte moins loin dans le temps.",
                "The log history goes back less far in time."
            )),
            recommande: false,
            changements: vec![Changement::Fichier {
                chemin: "/etc/systemd/journald.conf.d/50-gardien-taille.conf",
                ancien: Some("/etc/systemd/journald.conf.d/50-sentinel-taille.conf"),
                contenu: "[Journal]\nSystemMaxUse=500M\n",
                apres: "sudo systemctl restart systemd-journald",
            }],
        });
    }
    if gnome() {
        l.push(Reglage {
            id: "gnome_rapports",
            categorie: Confidentialite,
            titre: tr!("GNOME : pas de rapports envoyés", "GNOME: no reports sent"),
            effet: tr!(
                "GNOME n'envoie plus de rapports de problèmes techniques.",
                "GNOME no longer sends technical problem reports."
            ),
            prudence: None,
            recommande: true,
            changements: vec![Changement::Gnome {
                schema: "org.gnome.desktop.privacy",
                cle: "report-technical-problems",
                cible: "false",
                defaut: "true",
            }],
        });
    }
    if systemd && unite_existe("apport.service") {
        l.push(Reglage {
            id: "apport",
            categorie: Confidentialite,
            titre: tr!("Ubuntu : rapports de plantage coupés", "Ubuntu: crash reports off"),
            effet: tr!(
                "Ubuntu ne propose plus d'envoyer les plantages à ses serveurs, et n'en garde plus de copie.",
                "Ubuntu no longer offers to send crashes to its servers, and keeps no copy of them."
            ),
            prudence: None,
            recommande: true,
            changements: vec![
                Changement::Option {
                    fichier: "/etc/default/apport",
                    cle: "enabled",
                    cible: "0",
                    defaut: "1",
                },
                Changement::Unite {
                    nom: "apport.service",
                    cible: "disabled",
                    defaut: "enabled",
                },
            ],
        });
    }
    if Path::new("/etc/popularity-contest.conf").is_file() {
        l.push(Reglage {
            id: "popcon",
            categorie: Confidentialite,
            titre: tr!("Statistiques de paquets coupées", "Package statistics off"),
            effet: tr!(
                "La liste des programmes installés n'est plus envoyée chaque semaine à Debian ou Ubuntu.",
                "The list of installed programs is no longer sent to Debian or Ubuntu every week."
            ),
            prudence: None,
            recommande: true,
            changements: vec![Changement::Option {
                fichier: "/etc/popularity-contest.conf",
                cle: "PARTICIPATE",
                cible: "\"no\"",
                defaut: "\"yes\"",
            }],
        });
    }
    if Path::new("/etc/default/motd-news").is_file() {
        l.push(Reglage {
            id: "motd_news",
            categorie: Confort,
            titre: tr!("Ubuntu : pas d'annonces au terminal", "Ubuntu: no terminal ads"),
            effet: tr!(
                "Les annonces d'Ubuntu affichées à l'ouverture d'une session en terminal disparaissent.",
                "The Ubuntu announcements shown when opening a terminal session go away."
            ),
            prudence: None,
            recommande: false,
            changements: vec![Changement::Option {
                fichier: "/etc/default/motd-news",
                cle: "ENABLED",
                cible: "0",
                defaut: "1",
            }],
        });
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commandes_du_shell() {
        let o = Changement::Option {
            fichier: "/etc/popularity-contest.conf",
            cle: "PARTICIPATE",
            cible: "\"no\"",
            defaut: "\"yes\"",
        };
        let c = o.commande(Some("\"no\"")).unwrap();
        assert!(c.contains("s|^PARTICIPATE=.*|PARTICIPATE=\"no\"|"), "{c}");
        let f = Changement::Fichier {
            chemin: "/etc/systemd/journald.conf.d/50-gardien-taille.conf",
            ancien: Some("/etc/systemd/journald.conf.d/50-sentinel-taille.conf"),
            contenu: "[Journal]\nSystemMaxUse=500M\n",
            apres: "sudo systemctl restart systemd-journald",
        };
        // Chaque commande est du shell valide (une apostrophe de trop ne se verrait qu'au lancement).
        for c in [
            o.commande(Some("\"no\"")),
            f.commande(Some("present")),
            f.commande(None),
        ]
        .into_iter()
        .flatten()
        {
            assert!(
                Command::new("bash").args(["-n", "-c", &c]).status().unwrap().success(),
                "{c}"
            );
        }
        let u = Changement::Unite {
            nom: "fstrim.timer",
            cible: "enabled",
            defaut: "disabled",
        };
        assert_eq!(
            u.commande(Some("enabled")).as_deref(),
            Some("sudo systemctl enable --now fstrim.timer")
        );
        assert_eq!(u.commande(Some("static")), None);
    }

    /// Les commandes d'une option, lancées pour de vrai sur un fichier jetable (sans sudo) : une valeur aux caractères
    /// spéciaux revient telle quelle, et « absente » retire la ligne.
    #[test]
    fn option_posee_remise_puis_retiree() {
        let f = std::env::temp_dir().join(format!("gardien-test-option-sed-{}", std::process::id()));
        std::fs::write(&f, "# réglage\nPARTICIPATE=\"yes\"\nAUTRE=1\n").unwrap();
        let chemin: &'static str = Box::leak(f.display().to_string().into_boxed_str());
        let o = Changement::Option {
            fichier: chemin,
            cle: "PARTICIPATE",
            cible: "\"no\"",
            defaut: "\"yes\"",
        };
        let lancer = |v: Option<&str>| {
            let c = o.commande(v).unwrap().replace("sudo ", "");
            assert!(Command::new("bash").args(["-c", &c]).status().unwrap().success(), "{c}");
        };
        let etrange = r"a&b|c\d'e";
        lancer(Some(etrange));
        assert_eq!(o.lire().as_deref(), Some(etrange));
        lancer(None);
        assert_eq!(o.lire(), None);
        lancer(Some("\"no\""));
        assert_eq!(o.lire().as_deref(), Some("\"no\""));
        let texte = std::fs::read_to_string(&f).unwrap();
        assert!(
            texte.contains("AUTRE=1\n") && texte.starts_with("# réglage\n"),
            "{texte}"
        );
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn dns_de_networkmanager() {
        let connexion = "6b9a0f0e-1c2d-4e5f-8a9b-0c1d2e3f4a5b";
        let c = Changement::Dns {
            connexion: connexion.into(),
            cible: Some("1.1.1.1,1.0.0.1|yes|2606:4700:4700::1111|yes".into()),
        };
        let cible = c.cible().unwrap();
        assert_eq!(
            cible,
            format!("{connexion}\n1.1.1.1,1.0.0.1|yes|2606:4700:4700::1111|yes")
        );
        let commande = c.commande(Some(&cible)).unwrap();
        assert!(
            commande.contains("ipv4.dns '1.1.1.1 1.0.0.1' ipv4.ignore-auto-dns yes"),
            "{commande}"
        );
        let remise = c.commande(c.defaut().as_deref()).unwrap();
        assert!(
            remise.contains("ipv4.dns '' ipv4.ignore-auto-dns no ipv6.dns '' ipv6.ignore-auto-dns no"),
            "{remise}"
        );
        for ligne in [&commande, &remise] {
            assert!(
                Command::new("bash")
                    .args(["-n", "-c", ligne])
                    .status()
                    .unwrap()
                    .success(),
                "{ligne}"
            );
        }
        // Une valeur d'une autre connexion, ou un identifiant qui n'en est pas un : aucune commande.
        assert_eq!(c.commande(Some("autre\n|no||no")), None);
        assert!(Changement::dns_note("pas un uuid\n|no||no").is_none());
        let rebati = Changement::dns_note(&format!("{connexion}\n|no||no")).unwrap();
        assert_eq!(rebati.identite_dns(), Some(connexion));
        assert_ne!(
            rebati.cible(),
            rebati.defaut(),
            "une cible inconnue ne doit jamais passer pour atteinte"
        );
        assert_eq!(
            decrire_dns(Some(&cible)),
            super::super::texte_dns(&["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"], false)
        );
        assert_eq!(decrire_dns(c.defaut().as_deref()), super::super::texte_dns(&[], true));
        assert_eq!(liste_dns("1.1.1.1 1.0.0.1,"), "1.1.1.1,1.0.0.1");
    }

    #[test]
    fn carte_de_la_route_par_defaut() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     tun0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n\
                     wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                     eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(carte_par_defaut(table).as_deref(), Some("eth0"));
        assert_eq!(carte_par_defaut("Iface\tDestination\n"), None);
    }

    #[test]
    fn la_memoire_compressee_n_est_pas_un_ssd() {
        assert!(!a_un_ssd("zram0 0 disk\nsda 1 disk\nloop0 0 loop\n"));
        assert!(a_un_ssd("zram0 0 disk\nnvme0n1 0 disk\n"));
        assert!(!a_un_ssd(""));
    }

    #[test]
    fn lit_une_option_d_un_fichier() {
        let f = std::env::temp_dir().join(format!("gardien-test-option-{}", std::process::id()));
        std::fs::write(&f, "# commentaire\nENABLED=1\n").unwrap();
        let chemin: &'static str = Box::leak(f.display().to_string().into_boxed_str());
        let o = Changement::Option {
            fichier: chemin,
            cle: "ENABLED",
            cible: "0",
            defaut: "1",
        };
        assert_eq!(o.lire().as_deref(), Some("1"));
        let _ = std::fs::remove_file(&f);
    }
}
