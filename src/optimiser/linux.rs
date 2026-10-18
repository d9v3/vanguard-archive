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
        }
    }

    // Même forme que `lire`, pour les comparer.
    #[allow(clippy::unnecessary_wraps)]
    pub fn cible(&self) -> Valeur {
        Some(
            match self {
                Changement::Unite { cible, .. }
                | Changement::Gnome { cible, .. }
                | Changement::Option { cible, .. } => cible,
                Changement::Fichier { .. } => "present",
            }
            .to_string(),
        )
    }

    pub fn defaut(&self) -> Valeur {
        match self {
            Changement::Unite { defaut, .. } | Changement::Gnome { defaut, .. } | Changement::Option { defaut, .. } => {
                Some((*defaut).to_string())
            }
            Changement::Fichier { .. } => None,
        }
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
            Changement::Option { fichier, cle, .. } => format!("{fichier} : {cle}={}", v.unwrap_or("?")),
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
                let v = v?;
                // La ligne est remplacée si elle existe, ajoutée sinon.
                format!(
                    "if grep -q '^{cle}=' {f}; then sudo sed -i 's|^{cle}=.*|{cle}={}|' {f}; else echo {} | sudo tee -a {f} >/dev/null; fi",
                    v.replace('|', r"\|").replace('\'', r"'\''"),
                    shell(&format!("{cle}={v}")),
                    f = shell(fichier)
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
    Command::new("systemctl")
        .args(["cat", nom])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Au moins un disque sans pièce mobile (SSD, NVMe) : `lsblk` le marque ROTA 0.
fn ssd() -> bool {
    sortie("lsblk", &["-dno", "ROTA,TYPE"]).is_some_and(|t| {
        t.lines().any(|l| {
            let mut c = l.split_whitespace();
            c.next() == Some("0") && c.next() == Some("disk")
        })
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
