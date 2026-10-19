//! Mises à jour Linux : paquets, Flatpak, Snap, AUR, firmware, failles connues, noyau et pilotes DKMS.

use super::*;

/// Paquets à mettre à jour, un par ligne commençant par son nom ; `None` si on ne peut pas savoir.
pub(super) fn liste_mises_a_jour(gestion: Paquets) -> Option<Vec<String>> {
    // Ces outils interrogent les dépôts : hors ligne ou serveur lent, ils ne doivent pas figer l'audit.
    let lancer =
        |cmd: &str, args: &[&str]| crate::commande::lancer(Command::new(cmd).args(args).env("LC_ALL", "C"), 120);
    let lignes = |t: &str| t.lines().map(str::to_string).collect::<Vec<_>>();
    match gestion {
        // checkupdates : 0 = mises à jour listées, 2 = rien à faire, autre = erreur (hors ligne…).
        Paquets::Pacman => {
            let r = lancer("checkupdates", &[])?;
            match r.code {
                Some(0) => Some(lignes(&r.sortie)),
                Some(2) => Some(vec![]),
                _ => None,
            }
        }
        // Sorties en anglais (LC_ALL=C) : sinon les mots cherchés changent selon la langue du système.
        // Lit le cache d'apt sans le rafraîchir (il faudrait sudo) : il date du dernier « apt update ».
        // Sans cache, « rien à mettre à jour » ne voudrait rien dire.
        Paquets::Apt => {
            age_cache_apt()?;
            let r = lancer("apt", &["list", "--upgradable"])?;
            (r.code == Some(0)).then(|| {
                lignes(&r.sortie)
                    .into_iter()
                    .filter(|l| l.contains("[upgradable"))
                    .collect()
            })
        }
        // dnf check-update : 100 = mises à jour disponibles, 0 = rien, autre = erreur.
        Paquets::Dnf => {
            let r = lancer("dnf", &["-q", "check-update"])?;
            match r.code {
                Some(100) => Some(
                    lignes(&r.sortie)
                        .into_iter()
                        .filter(|l| !l.trim().is_empty() && !l.starts_with(' '))
                        .collect(),
                ),
                Some(0) => Some(vec![]),
                _ => None,
            }
        }
        Paquets::Zypper => {
            let r = lancer("zypper", &["-q", "list-updates"])?;
            (r.code == Some(0)).then(|| lignes(&r.sortie).into_iter().filter(|l| l.starts_with("v ")).collect())
        }
    }
}

/// Logiciels installés hors du gestionnaire de paquets principal : Flatpak, Snap, AUR et firmware.
pub(super) fn autres_mises_a_jour() -> Vec<Constat> {
    let present = |c: &str| {
        ["/usr/bin", "/bin", "/usr/local/bin"]
            .iter()
            .any(|d| Path::new(d).join(c).exists())
    };
    let lignes = |t: &str| t.lines().filter(|l| !l.trim().is_empty()).count();
    let mut constats = Vec::new();
    std::thread::scope(|portee| {
        let flatpak = present("flatpak").then(|| {
            portee.spawn(|| {
                sortie_delai(
                    "flatpak",
                    &["remote-ls", "--updates", "--columns=application"],
                    40,
                    &[0],
                )
            })
        });
        let snap = present("snap").then(|| portee.spawn(|| sortie_delai("snap", &["refresh", "--list"], 30, &[0])));
        let aur = ["yay", "paru"]
            .into_iter()
            .find(|c| present(c))
            .map(|c| (c, portee.spawn(move || sortie_delai(c, &["-Qua"], 40, &[0, 1]))));
        let firmware = present("fwupdmgr").then(|| {
            portee.spawn(|| {
                sortie_delai(
                    "fwupdmgr",
                    &["get-updates", "--json", "--no-unreported-check"],
                    40,
                    &[0, 2],
                )
            })
        });

        if let Some(t) = flatpak {
            constats.push(match t.join().ok().flatten() {
                None => impossible("Flatpak", tr!("hors ligne ?", "offline?")),
                Some(l) if lignes(&l) == 0 => ok(
                    "Flatpak",
                    tr!("Applications Flatpak à jour.", "Flatpak apps up to date."),
                ),
                Some(l) => alerte(
                    "Flatpak",
                    Niveau::Moyen,
                    trf!(
                        "{} application(s) Flatpak à mettre à jour.",
                        "{} Flatpak app(s) to update.",
                        lignes(&l)
                    ),
                )
                .corriger(
                    tr!("Mettre à jour les applications Flatpak", "Update the Flatpak apps"),
                    &["flatpak update -y"],
                ),
            });
        }
        if let Some(t) = snap {
            // « All snaps up to date » part sur la sortie d'erreur : sortie vide = à jour. Une ligne d'en-tête sinon.
            constats.push(match t.join().ok().flatten() {
                None => impossible("Snap", tr!("snapd injoignable", "snapd unreachable")),
                Some(l) if lignes(&l) <= 1 => ok("Snap", tr!("Paquets Snap à jour.", "Snap packages up to date.")),
                Some(l) => alerte(
                    "Snap",
                    Niveau::Moyen,
                    trf!(
                        "{} paquet(s) Snap à mettre à jour.",
                        "{} Snap package(s) to update.",
                        lignes(&l) - 1
                    ),
                )
                .corriger(
                    tr!("Mettre à jour les paquets Snap", "Update the Snap packages"),
                    &["sudo snap refresh"],
                ),
            });
        }
        if let Some((outil, t)) = aur {
            constats.push(match t.join().ok().flatten() {
                None => impossible("AUR", tr!("hors ligne ?", "offline?")),
                Some(l) if lignes(&l) == 0 => ok("AUR", tr!("Paquets AUR à jour.", "AUR packages up to date.")),
                Some(l) => alerte(
                    "AUR",
                    Niveau::Moyen,
                    trf!(
                        "{} paquet(s) AUR à mettre à jour.",
                        "{} AUR package(s) to update.",
                        lignes(&l)
                    ),
                )
                .manuel(
                    tr!(
                        "Les paquets AUR se compilent : mets-les à jour toi-même et relis ce qui change",
                        "AUR packages are compiled: update them yourself and read what changes"
                    ),
                    &[&format!("{outil} -Sua")],
                ),
            });
        }
        if let Some(t) = firmware {
            let json = t
                .join()
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok());
            constats.push(match json {
                None => impossible(
                    "Firmware",
                    tr!(
                        "métadonnées fwupd absentes : fwupdmgr refresh",
                        "fwupd metadata missing: fwupdmgr refresh"
                    ),
                ),
                Some(v) => {
                    let appareils = firmwares_proposes(&v);
                    if appareils.is_empty() {
                        ok(
                            "Firmware",
                            tr!(
                                "Firmwares à jour (BIOS, SSD, périphériques).",
                                "Firmware up to date (BIOS, SSD, devices)."
                            ),
                        )
                    } else {
                        alerte(
                            "Firmware",
                            Niveau::Moyen,
                            trf!(
                                "Mise à jour de firmware disponible : {}.",
                                "Firmware update available: {}.",
                                appareils.join(", ")
                            ),
                        )
                        .manuel(
                            tr!(
                                "Installer les firmwares (un redémarrage peut être demandé)",
                                "Install the firmware (a restart may be requested)"
                            ),
                            &["fwupdmgr update"],
                        )
                    }
                }
            });
        }
    });
    constats
}

/// Appareils à qui fwupd propose un nouveau firmware (`fwupdmgr get-updates --json`). Le nom vient souvent de
/// l'appareil lui-même (la chaîne que le fabricant d'une clé USB ou d'une souris y a gravée) : prêt à montrer.
fn firmwares_proposes(v: &serde_json::Value) -> Vec<String> {
    v["Devices"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|d| d["Releases"].as_array().is_some_and(|r| !r.is_empty()))
        .filter_map(|d| d["Name"].as_str().map(crate::ui::affichable))
        .collect()
}

/// Âge en jours de la liste des paquets d'apt, `None` si elle n'a jamais été téléchargée.
pub(super) fn age_cache_apt() -> Option<u64> {
    let plus_recent = std::fs::read_dir("/var/lib/apt/lists")
        .ok()?
        .flatten()
        .filter(|f| {
            f.file_name().to_string_lossy().ends_with("Packages")
                || f.file_name().to_string_lossy().contains("Packages.")
        })
        .filter_map(|f| f.metadata().ok()?.modified().ok())
        .max()?;
    Some(plus_recent.elapsed().map_or(0, |d| d.as_secs() / 86_400))
}

pub(super) fn mises_a_jour() -> Constat {
    let Some(gestion) = Paquets::detecter() else {
        return impossible(
            "Mises à jour",
            tr!("gestionnaire de paquets non reconnu", "package manager not recognized"),
        );
    };
    let Some(liste) = liste_mises_a_jour(gestion) else {
        let raison = if gestion == Paquets::Apt {
            tr!("liste des paquets jamais téléchargée", "package list never downloaded")
        } else {
            tr!("outil absent ou hors ligne", "tool missing or offline")
        };
        return impossible("Mises à jour", raison).corriger(
            tr!(
                "Télécharger la liste des paquets et mettre à jour",
                "Download the package list and update"
            ),
            &[gestion.mise_a_jour()],
        );
    };
    // apt ne connaît que les mises à jour vues à son dernier « apt update » : une vieille liste en cache tout.
    let vieux = (gestion == Paquets::Apt)
        .then(age_cache_apt)
        .flatten()
        .filter(|&j| j > 7);
    if liste.is_empty() {
        return match vieux {
            Some(j) => alerte(
                "Mises à jour",
                Niveau::Moyen,
                trf!(
                    "Aucune mise à jour connue, mais la liste date de {j} jours.",
                    "No known update, but the list is {j} days old."
                ),
            )
            .corriger(
                tr!("Rafraîchir la liste et mettre à jour", "Refresh the list and update"),
                &[gestion.mise_a_jour()],
            ),
            None => ok("Mises à jour", tr!("Système à jour.", "System up to date.")),
        };
    }
    let n = liste.len();
    let sensibles = liste.iter().filter(|l| paquet_sensible(gestion, l)).count();
    let niveau = if n > 50 || sensibles > 0 {
        Niveau::Eleve
    } else {
        Niveau::Moyen
    };
    alerte(
        "Mises à jour",
        niveau,
        // Sans paquet sensible, on ne cite pas « noyau, openssl… » : la phrase laissait croire qu'ils étaient touchés.
        if sensibles == 0 {
            trf!("{n} paquet(s) à mettre à jour.", "{n} package(s) to update.")
        } else {
            trf!(
                "{n} paquet(s) à mettre à jour, dont {sensibles} sensible(s) (noyau, openssl, navigateur…).",
                "{n} package(s) to update, {sensibles} of them sensitive (kernel, openssl, browser…)."
            )
        },
    )
    .corriger(
        tr!("Mettre le système à jour", "Update the system"),
        &[gestion.mise_a_jour()],
    )
}

/// Une ligne de la liste des mises à jour touche-t-elle un paquet sensible (noyau, chiffrement, navigateur…) ?
/// zypper écrit un tableau « v | dépôt | nom | … » : le nom est dans la 3e colonne. Le noyau s'appelle « linux »
/// sur Arch et Debian, « kernel » sur Fedora et openSUSE.
pub(super) fn paquet_sensible(gestion: Paquets, ligne: &str) -> bool {
    let nom = match gestion {
        Paquets::Zypper => ligne.split('|').nth(2).unwrap_or(ligne),
        _ => ligne,
    }
    .trim()
    .to_ascii_lowercase();
    [
        "linux", "kernel", "openssl", "libssl", "openssh", "glibc", "libc6", "sudo", "firefox", "chromium", "nvidia",
    ]
    .iter()
    .any(|p| nom.starts_with(p))
}

/// Paquet installé touché par une faille publiée (CVE, avis de sécurité de la distribution).
#[derive(Debug, PartialEq)]
pub(super) struct Faille {
    paquet: String,
    gravite: Niveau,
    /// Une version corrigée est déjà dans les dépôts : la mise à jour suffit.
    corrigee: bool,
}

/// Gravité écrite par les distributions (anglais), en niveau de Vanguard. Inconnue : on ne minimise pas.
pub(super) fn gravite(texte: &str) -> Niveau {
    match texte.trim().to_ascii_lowercase().as_str() {
        "critical" => Niveau::Critique,
        "high" | "important" => Niveau::Eleve,
        "low" | "unknown" | "none" => Niveau::Info,
        _ => Niveau::Moyen,
    }
}

/// arch-audit --json : groupes de failles avec la liste des paquets installés touchés.
pub(super) fn failles_arch(json: &serde_json::Value) -> Vec<Faille> {
    json.as_array()
        .into_iter()
        .flatten()
        .flat_map(|g| {
            let gravite = gravite(g["severity"].as_str().unwrap_or("unknown"));
            let corrigee = g["fixed"].as_str().is_some_and(|v| !v.is_empty());
            g["packages"].as_array().into_iter().flatten().filter_map(move |p| {
                Some(Faille {
                    paquet: p.as_str()?.to_string(),
                    gravite,
                    corrigee,
                })
            })
        })
        .collect()
}

/// apt list --upgradable : une mise à jour venue d'un dépôt « -security » (noble-security, stable-security…)
/// corrige une faille. apt ne donne pas la gravité.
pub(super) fn failles_apt(lignes: &[String]) -> Vec<Faille> {
    lignes
        .iter()
        .filter_map(|l| {
            let (nom, reste) = l.split_once('/')?;
            let depots = reste.split_whitespace().next()?;
            depots.split(',').any(|d| d.ends_with("-security")).then(|| Faille {
                paquet: nom.to_string(),
                gravite: Niveau::Eleve,
                corrigee: true,
            })
        })
        .collect()
}

/// dnf updateinfo list --security. dnf 4 : « FEDORA-2024-1a2b Important/Sec. curl-8.6.0-7.fc40.x86_64 » ;
/// dnf 5 : « FEDORA-2024-1a2b security Important curl-8.6.0-7.fc40.x86_64 2024-04-01 00:43:20 ».
pub(super) fn failles_dnf(texte: &str) -> Vec<Faille> {
    texte
        .lines()
        .filter_map(|l| {
            let mots: Vec<&str> = l.split_whitespace().collect();
            let (gravite_txt, paquet) = match mots.as_slice() {
                [_, g, p, ..] if g.ends_with("/Sec.") => (g.trim_end_matches("/Sec."), *p),
                [_, "security", g, p, ..] => (*g, *p),
                _ => return None,
            };
            // nom-version-révision.arch → nom
            let nom = paquet.rsplitn(3, '-').nth(2)?;
            Some(Faille {
                paquet: nom.to_string(),
                gravite: gravite(gravite_txt),
                corrigee: true,
            })
        })
        .collect()
}

/// zypper list-patches --category security : tableau « dépôt | nom | catégorie | gravité | interactif | état | résumé ».
pub(super) fn failles_zypper(texte: &str) -> Vec<Faille> {
    texte
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split('|').map(str::trim).collect();
            (c.len() >= 6 && c[2] == "security" && c[5].starts_with("needed")).then(|| Faille {
                paquet: c[1].to_string(),
                gravite: gravite(c[3]),
                corrigee: true,
            })
        })
        .collect()
}

/// Failles connues des paquets installés, d'après le suivi de sécurité de la distribution.
pub(super) fn failles_connues() -> Constat {
    const CAT: &str = "Failles connues";
    let Some(gestion) = Paquets::detecter() else {
        return impossible(
            CAT,
            tr!("gestionnaire de paquets non reconnu", "package manager not recognized"),
        );
    };
    let failles = match gestion {
        Paquets::Pacman => {
            if !Path::new("/usr/bin/arch-audit").exists() {
                return impossible(CAT, tr!("arch-audit absent", "arch-audit missing")).corriger(
                    tr!(
                        "Installer arch-audit, qui lit le suivi de sécurité d'Arch (security.archlinux.org)",
                        "Install arch-audit, which reads the Arch security tracker (security.archlinux.org)"
                    ),
                    &[&gestion.installer("arch-audit")],
                );
            }
            match sortie_delai("arch-audit", &["--json"], 40, &[0])
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            {
                Some(json) => failles_arch(&json),
                None => {
                    return impossible(
                        CAT,
                        tr!(
                            "suivi de sécurité injoignable, hors ligne ?",
                            "security tracker unreachable, offline?"
                        ),
                    );
                }
            }
        }
        Paquets::Apt => match liste_mises_a_jour(gestion) {
            Some(l) => failles_apt(&l),
            None => {
                return impossible(
                    CAT,
                    tr!("liste des paquets jamais téléchargée", "package list never downloaded"),
                );
            }
        },
        Paquets::Dnf => {
            match crate::commande::lancer(
                Command::new("dnf")
                    .args(["-q", "updateinfo", "list", "--security"])
                    .env("LC_ALL", "C"),
                120,
            ) {
                Some(r) if r.code == Some(0) => failles_dnf(&r.sortie),
                _ => {
                    return impossible(
                        CAT,
                        tr!(
                            "avis de sécurité de dnf injoignables, hors ligne ?",
                            "dnf security advisories unreachable, offline?"
                        ),
                    );
                }
            }
        }
        Paquets::Zypper => {
            match crate::commande::lancer(
                Command::new("zypper")
                    .args(["-q", "list-patches", "--category", "security"])
                    .env("LC_ALL", "C"),
                120,
            ) {
                Some(r) if r.code == Some(0) => failles_zypper(&r.sortie),
                _ => {
                    return impossible(
                        CAT,
                        tr!(
                            "avis de sécurité de zypper injoignables, hors ligne ?",
                            "zypper security advisories unreachable, offline?"
                        ),
                    );
                }
            }
        }
    };
    bilan_failles(gestion, &failles)
}

pub(super) fn bilan_failles(gestion: Paquets, failles: &[Faille]) -> Constat {
    const CAT: &str = "Failles connues";
    let noms = |corrigee: bool| {
        let mut n: Vec<&str> = failles
            .iter()
            .filter(|f| f.corrigee == corrigee)
            .map(|f| f.paquet.as_str())
            .collect();
        n.sort_unstable();
        n.dedup();
        n
    };
    let (a_corriger, sans_correctif) = (noms(true), noms(false));
    let resume = |n: &[&str]| crate::ui::resume(n, 8, ", ");
    // Une faille sans correctif publié : rien à faire de ton côté, la mise à jour viendra. Le suivi d'Arch garde
    // souvent des failles corrigées en amont : on le dit, sans baisser la note.
    let attente = (!sans_correctif.is_empty()).then(|| {
        trf!(
            "{} paquet(s) touché(s) par une faille encore sans correctif publié : {}.",
            "{} package(s) affected by a flaw with no published fix yet: {}.",
            sans_correctif.len(),
            resume(&sans_correctif)
        )
    });
    if a_corriger.is_empty() {
        return match attente {
            Some(t) => alerte(
                CAT,
                Niveau::Info,
                trf!("Aucune faille corrigée en attente. {t}", "No fixed flaw pending. {t}"),
            ),
            None => ok(
                CAT,
                tr!(
                    "Aucun paquet installé n'a de faille connue.",
                    "No installed package has a known flaw."
                ),
            ),
        };
    }
    let pire = failles
        .iter()
        .filter(|f| f.corrigee)
        .map(|f| f.gravite)
        .max()
        .unwrap_or(Niveau::Moyen)
        .max(Niveau::Moyen);
    let mut message = trf!(
        "{} paquet(s) avec une faille connue, déjà corrigée dans les dépôts : {}.",
        "{} package(s) with a known flaw, already fixed in the repositories: {}.",
        a_corriger.len(),
        resume(&a_corriger)
    );
    if let Some(t) = attente {
        let _ = write!(message, " {t}");
    }
    alerte(CAT, pire, message).corriger(
        tr!("Installer les correctifs de sécurité", "Install the security fixes"),
        &[gestion.mise_a_jour()],
    )
}

/// Version du noyau qui tourne (« 7.2.5-3-omarchy »).
pub(super) fn noyau_en_cours() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .or_else(|| sortie("uname", &["-r"]))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Dossiers des noyaux installés, un par version. Un vrai noyau a son image (dans son dossier, ou /boot sous Debian)
/// ou ses modules ; on écarte les restes vides. /lib/modules est souvent le même dossier que /usr/lib/modules.
pub(super) fn noyaux_installes() -> Vec<std::path::PathBuf> {
    let mut noyaux: Vec<std::path::PathBuf> = ["/usr/lib/modules", "/lib/modules"]
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let nom = p.file_name().unwrap_or_default().to_string_lossy();
            p.join("modules.dep").exists()
                || p.join("vmlinuz").exists()
                || Path::new(&format!("/boot/vmlinuz-{nom}")).exists()
        })
        .collect();
    noyaux.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    noyaux.dedup_by(|a, b| a.file_name() == b.file_name());
    noyaux
}

pub(super) fn redemarrage() -> Constat {
    let noyau = noyau_en_cours();
    let installes = noyaux_installes();
    // Aucun noyau ici (conteneur, noyau fourni par l'hôte) : rien à comparer.
    if installes.is_empty() {
        return impossible(
            "Noyau",
            tr!(
                "aucun noyau installé ici, conteneur ?",
                "no kernel installed here, container?"
            ),
        );
    }
    let en_cours = installes
        .iter()
        .any(|p| p.file_name().is_some_and(|n| n.to_string_lossy() == noyau));
    // Fedora, openSUSE et Debian gardent plusieurs noyaux : le plus récemment installé doit être celui qui tourne.
    let plus_recent = installes
        .iter()
        .max_by_key(|p| p.metadata().and_then(|m| m.modified()).ok())
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned());
    // Arch efface le dossier de l'ancien noyau à la mise à jour : s'il existe encore, le noyau chargé est le bon.
    // La date n'y veut rien dire : avec linux + linux-lts (ou DKMS qui recompile pour chacun), le dernier
    // dossier touché n'est pas forcément celui qui devrait tourner.
    let dernier_installe =
        Paquets::detecter() == Some(Paquets::Pacman) || plus_recent.as_deref() == Some(noyau.as_str());
    let a_jour = en_cours && dernier_installe && !Path::new("/var/run/reboot-required").exists();
    if a_jour {
        ok(
            "Noyau",
            trf!(
                "Le noyau en cours ({noyau}) est le plus récent installé.",
                "The running kernel ({noyau}) is the newest installed."
            ),
        )
    } else {
        let nouveau = plus_recent
            .filter(|n| *n != noyau)
            .map(|n| format!(" ({n})"))
            .unwrap_or_default();
        alerte(
            "Noyau",
            Niveau::Moyen,
            trf!(
                "Noyau plus récent installé{nouveau} mais pas encore chargé : les correctifs ne sont pas actifs.",
                "Newer kernel installed{nouveau} but not loaded yet: its fixes are not active."
            ),
        )
        .manuel(
            tr!("Redémarrer quand c'est pratique", "Restart when convenient"),
            &["systemctl reboot"],
        )
    }
}

/// Modules de « dkms status » et, pour chacun, les noyaux de `noyaux` où il n'est pas installé.
/// Lignes « nvidia/610.57, 7.2.5-arch1, x86_64: installed » (ancien format : « nvidia, 610.57, 7.2.5, x86_64: »).
pub(super) fn dkms_manquants(status: &str, noyaux: &[String]) -> Vec<(String, Vec<String>)> {
    // Chaque module, dans l'ordre de « dkms status », avec les noyaux où il est installé.
    let mut modules: Vec<(String, Vec<String>)> = Vec::new();
    for l in status.lines() {
        let Some((gauche, etat)) = l.split_once(": ") else {
            continue;
        };
        let parties: Vec<&str> = gauche.split(", ").map(str::trim).collect();
        let (nom, noyau) = match parties.first() {
            Some(p) if p.contains('/') => (p.split('/').next().unwrap_or(p), parties.get(1)),
            Some(p) => (*p, parties.get(2)),
            None => continue,
        };
        if nom.is_empty() {
            continue;
        }
        let i = modules.iter().position(|(m, _)| m == nom).unwrap_or_else(|| {
            modules.push((nom.to_string(), Vec::new()));
            modules.len() - 1
        });
        if let Some(k) = noyau
            && etat.trim_start().starts_with("installed")
        {
            modules[i].1.push((*k).to_string());
        }
    }
    modules
        .into_iter()
        .map(|(m, installes)| (m, noyaux.iter().filter(|k| !installes.contains(k)).cloned().collect()))
        .collect()
}

/// Pilotes DKMS (NVIDIA, manette, VirtualBox…) : recompilés pour chaque noyau. S'il en manque un pour le noyau
/// qu'on va démarrer, c'est l'écran noir ou un périphérique muet au prochain démarrage.
pub(super) fn pilotes_dkms() -> Option<Constat> {
    let status = sortie("dkms", &["status"])?;
    let mut noyaux: Vec<String> = noyaux_installes()
        .iter()
        .filter_map(|p| Some(p.file_name()?.to_string_lossy().into_owned()))
        .collect();
    let en_cours = noyau_en_cours();
    if !en_cours.is_empty() && !noyaux.contains(&en_cours) {
        noyaux.push(en_cours);
    }
    let modules = dkms_manquants(&status, &noyaux);
    if modules.is_empty() {
        return None;
    }
    let mut a_refaire: Vec<String> = modules.iter().flat_map(|(_, k)| k.clone()).collect();
    a_refaire.sort();
    a_refaire.dedup();
    if a_refaire.is_empty() {
        return Some(ok(
            "Pilotes DKMS",
            trf!(
                "{} compilé(s) pour chaque noyau installé.",
                "{} built for every installed kernel.",
                modules.iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    let detail: Vec<String> = modules
        .iter()
        .filter(|(_, k)| !k.is_empty())
        .map(|(m, k)| trf!("{m} (noyau {})", "{m} (kernel {})", k.join(", ")))
        .collect();
    Some(
        alerte(
            "Pilotes DKMS",
            Niveau::Eleve,
            trf!(
                "Pilote pas compilé : {}. Écran noir ou périphérique muet possible au prochain démarrage.",
                "Driver not built: {}. Black screen or silent device possible at the next boot.",
                detail.join(", ")
            ),
        )
        .corriger(
            tr!(
                "Recompiler les pilotes DKMS (les en-têtes du noyau doivent être installés)",
                "Rebuild the DKMS drivers (the kernel headers must be installed)"
            ),
            &a_refaire
                .iter()
                .map(|k| format!("sudo dkms autoinstall -k {k}"))
                .collect::<Vec<_>>(),
        ),
    )
}

/// Tout ce qui doit être à jour : paquets, Flatpak, Snap, AUR, firmware, pilotes DKMS, noyau chargé. En parallèle :
/// la liste des paquets interroge les dépôts (jusqu'à 30 s) pendant que le reste se vérifie.
/// `seulement` : les catégories à revérifier (après une installation) ; le noyau chargé est toujours vérifié.
pub fn mises_a_jour_completes(seulement: Option<&[&str]>) -> Vec<Constat> {
    let voulu = |categories: &[&str]| seulement.is_none_or(|s| categories.iter().any(|c| s.contains(c)));
    std::thread::scope(|portee| {
        let paquets = voulu(&["Mises à jour"]).then(|| portee.spawn(mises_a_jour));
        let autres = voulu(&["Flatpak", "Snap", "AUR", "Firmware"]).then(|| portee.spawn(autres_mises_a_jour));
        let dkms = voulu(&["Pilotes DKMS"]).then(|| portee.spawn(pilotes_dkms));
        let noyau = redemarrage();
        let mut constats: Vec<Constat> = paquets
            .map(|t| {
                t.join().unwrap_or_else(|_| {
                    impossible("Mises à jour", tr!("vérification interrompue", "check interrupted"))
                })
            })
            .into_iter()
            .collect();
        constats.extend(autres.map(|t| t.join().unwrap_or_default()).unwrap_or_default());
        constats.extend(dkms.and_then(|t| t.join().ok().flatten()));
        constats.push(noyau);
        constats
    })
}

/// Paquets AUR introuvables dans la réponse de l'AUR (retirés ou construits à la main) et paquets orphelins.
pub(super) fn etat_aur(installes: &[&str], reponse: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    let resultats: Vec<&serde_json::Value> = reponse["results"].as_array().into_iter().flatten().collect();
    let absents = installes
        .iter()
        .filter(|n| !resultats.iter().any(|r| r["Name"].as_str() == Some(**n)))
        .map(std::string::ToString::to_string)
        .collect();
    let orphelins = resultats
        .iter()
        .filter(|r| r["Maintainer"].is_null())
        .filter_map(|r| r["Name"].as_str().map(str::to_string))
        .collect();
    (absents, orphelins)
}

/// Encode un nom pour une adresse web : « libc++ » doit devenir « libc%2B%2B », sinon « + » est lu comme une
/// espace et le paquet passe pour absent de l'AUR (vérifié sur aewm++).
pub(super) fn encoder_url(texte: &str) -> String {
    texte
        .bytes()
        .map(|o| match o {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (o as char).to_string(),
            _ => format!("%{o:02X}"),
        })
        .collect()
}

/// Un paquet retiré de l'AUR ne reçoit plus jamais de mise à jour, sans que rien ne prévienne.
pub(super) fn paquets_aur() -> Option<Constat> {
    if Paquets::detecter() != Some(Paquets::Pacman) {
        return None;
    }
    // Sans liste des dépôts (jamais téléchargée), pacman -Qm prend chaque paquet pour un paquet de l'AUR et toute
    // la base serait déclarée « absente de l'AUR » (vu dans un conteneur Arch neuf).
    let depots = std::fs::read_dir("/var/lib/pacman/sync")
        .into_iter()
        .flatten()
        .flatten()
        .any(|f| f.path().extension().is_some_and(|e| e == "db"));
    if !depots {
        return Some(impossible(
            "Paquets AUR",
            tr!(
                "liste des dépôts jamais téléchargée (sudo pacman -Sy)",
                "repository list never downloaded (sudo pacman -Sy)"
            ),
        ));
    }
    let liste = sortie("pacman", &["-Qmq"])?;
    let installes: Vec<&str> = liste.lines().filter(|l| !l.is_empty()).collect();
    if installes.is_empty() {
        return None;
    }
    // Même requête que yay ou paru : seuls les noms des paquets partent vers aur.archlinux.org.
    // Par lots de 100, pour ne pas dépasser la longueur maximale d'une adresse.
    let mut resultats = Vec::new();
    for lot in installes.chunks(100) {
        let requete = format!(
            "https://aur.archlinux.org/rpc/v5/info?{}",
            lot.iter()
                .map(|n| format!("arg[]={}", encoder_url(n)))
                .collect::<Vec<_>>()
                .join("&")
        );
        let Some(json) = sortie_delai("curl", &["-fsS", "--max-time", "20", &requete], 25, &[0])
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        else {
            return Some(impossible(
                "Paquets AUR",
                tr!("AUR injoignable, hors ligne ?", "AUR unreachable, offline?"),
            ));
        };
        resultats.extend(json["results"].as_array().cloned().unwrap_or_default());
    }
    let (absents, orphelins) = etat_aur(&installes, &serde_json::json!({ "results": resultats }));
    Some(if !absents.is_empty() {
        alerte(
            "Paquets AUR",
            Niveau::Moyen,
            trf!(
                "Absent(s) de l'AUR : {} (retiré, ou construit à la main) : plus aucune mise à jour automatique.",
                "Missing from the AUR: {} (removed, or built by hand): no more automatic updates.",
                absents.join(", ")
            ),
        )
        .manuel(
            tr!(
                "Vérifier si un paquet de remplacement existe, sinon le désinstaller s'il n'est plus utile",
                "Check whether a replacement package exists, otherwise uninstall it if no longer needed"
            ),
            &["pacman -Qm"],
        )
    } else if !orphelins.is_empty() {
        alerte(
            "Paquets AUR",
            Niveau::Info,
            trf!(
                "Paquet(s) AUR sans mainteneur : {} (les mises à jour risquent de s'arrêter).",
                "Orphaned AUR package(s): {} (updates may stop).",
                orphelins.join(", ")
            ),
        )
    } else {
        ok(
            "Paquets AUR",
            trf!(
                "Les {} paquets AUR installés sont tous suivis dans l'AUR.",
                "The {} installed AUR packages are all tracked in the AUR.",
                installes.len()
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnf_automatic_qui_installe() {
        let telecharge = "[commands]\nupgrade_type = security\napply_updates = no\n";
        let installe = "[commands]\napply_updates = yes\n";
        assert!(!juger_dnf_auto(false, true, telecharge));
        assert!(!juger_dnf_auto(false, true, ""));
        assert!(juger_dnf_auto(false, true, installe));
        assert!(juger_dnf_auto(true, false, ""));
        assert!(!juger_dnf_auto(false, false, installe));
        // Une autre section ne compte pas.
        assert!(!juger_dnf_auto(false, true, "[emitters]\napply_updates = yes\n"));
    }

    #[test]
    fn paquets_sensibles() {
        assert!(paquet_sensible(Paquets::Pacman, "linux 7.2.5.arch1-1 -> 7.2.6.arch1-1"));
        assert!(paquet_sensible(Paquets::Dnf, "kernel.x86_64 6.11.4-301.fc41 updates"));
        assert!(paquet_sensible(
            Paquets::Zypper,
            "v | Main Update Repository | kernel-default | 6.11.1-1.1 | 6.11.2-1.1 | x86_64"
        ));
        assert!(!paquet_sensible(
            Paquets::Zypper,
            "v | Main Update Repository | vim | 9.1.0-1.1 | 9.1.1-1.1 | x86_64"
        ));
        assert!(!paquet_sensible(
            Paquets::Apt,
            "vim/noble-updates 2:9.1 amd64 [upgradable from: 2:9.0]"
        ));
    }

    #[test]
    fn modules_dkms_par_noyau() {
        let noyaux = ["7.2.5-arch1".to_string(), "7.3.0-arch1".to_string()];
        let status = "nvidia/610.57.04, 7.2.5-arch1, x86_64: installed\n\
                      nvidia/610.57.04, 7.3.0-arch1, x86_64: built\n\
                      hid-xpadneo/v0.10.4, 7.2.5-arch1, x86_64: installed\n\
                      hid-xpadneo/v0.10.4, 7.3.0-arch1, x86_64: installed (WARNING! Diff between built and installed module!)\n\
                      vboxhost/7.1: added\n\
                      ancien, 1.0, 7.2.5-arch1, x86_64: installed\n";
        assert_eq!(
            dkms_manquants(status, &noyaux),
            [
                ("nvidia".to_string(), vec!["7.3.0-arch1".to_string()]),
                ("hid-xpadneo".to_string(), vec![]),
                ("vboxhost".to_string(), noyaux.to_vec()),
                ("ancien".to_string(), vec!["7.3.0-arch1".to_string()]),
            ]
        );
    }

    /// Un appareil branché choisit le nom que fwupd rapporte : piégé, il arrive inoffensif dans le constat.
    #[test]
    fn firmware_d_un_appareil_piege() {
        let v = serde_json::json!({"Devices": [
            {"Name": "Souris\u{1b}]52;c;eA==\u{7}\u{1b}[2K\r\u{202e}", "Releases": [{"Version": "1.2"}]},
            {"Name": "Disque", "Releases": []}
        ]});
        assert_eq!(firmwares_proposes(&v), ["Souris�]52;c;eA==��[2K��"]);
    }

    #[test]
    fn noms_encodes_pour_l_aur() {
        assert_eq!(encoder_url("aewm++"), "aewm%2B%2B");
        assert_eq!(encoder_url("python-foo_bar.1"), "python-foo_bar.1");
        assert_eq!(encoder_url("a@b"), "a%40b");
    }

    #[test]
    fn suivi_aur() {
        let reponse = serde_json::json!({"results": [
            {"Name": "nextdns-bin", "Maintainer": "quelquun"},
            {"Name": "vieux-outil", "Maintainer": null}
        ]});
        let (absents, orphelins) = etat_aur(&["nextdns-bin", "vieux-outil", "fait-maison"], &reponse);
        assert_eq!(absents, vec!["fait-maison"]);
        assert_eq!(orphelins, vec!["vieux-outil"]);
    }

    #[test]
    fn failles_des_distributions() {
        let arch = serde_json::json!([
            {"packages": ["openssl", "lib32-openssl"], "severity": "High", "fixed": "3.5.1-1", "status": "Fixed"},
            {"packages": ["pam"], "severity": "High", "fixed": null, "status": "Vulnerable"},
            {"packages": ["lua51"], "severity": "Low", "fixed": null}
        ]);
        let f = failles_arch(&arch);
        assert_eq!(f.len(), 4);
        assert!(f[0].corrigee && f[0].gravite == Niveau::Eleve && f[1].paquet == "lib32-openssl");
        assert!(!f[2].corrigee && f[3].gravite == Niveau::Info);

        let apt = [
            "libssl3t64/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]",
            "firefox/noble-updates 1:1snap1 amd64 [upgradable from: 1:1snap0]",
            "openssl/stable-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]",
        ]
        .map(String::from);
        let noms: Vec<String> = failles_apt(&apt).into_iter().map(|f| f.paquet).collect();
        assert_eq!(noms, ["libssl3t64", "openssl"]);

        let dnf4 = "FEDORA-2024-1a2b Important/Sec. curl-8.6.0-7.fc40.x86_64\nFEDORA-2024-9f9f bugfix   bash-5.2-1.fc40.x86_64\n";
        assert_eq!(
            failles_dnf(dnf4),
            [Faille {
                paquet: "curl".into(),
                gravite: Niveau::Eleve,
                corrigee: true
            }]
        );
        let dnf5 = "Name             Type     Severity  Package                         Issued\n\
                    FEDORA-2024-1a2b security Critical  python3-libs-3.12.4-1.fc40.x86_64 2024-04-01 00:43:20\n";
        let f = failles_dnf(dnf5);
        assert_eq!((f[0].paquet.as_str(), f[0].gravite), ("python3-libs", Niveau::Critique));

        let zypper = "Repository | Name                  | Category    | Severity  | Interactive | Status     | Summary\n\
                      -----------+-----------------------+-------------+-----------+-------------+------------+--------\n\
                      Update     | openSUSE-2024-123     | security    | important | ---         | needed     | openssl\n\
                      Update     | openSUSE-2024-124     | security    | low       | ---         | applied    | curl\n\
                      Update     | openSUSE-2024-125     | recommended | moderate  | ---         | needed     | vim\n";
        let f = failles_zypper(zypper);
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].paquet.as_str(), f[0].gravite),
            ("openSUSE-2024-123", Niveau::Eleve)
        );
    }

    #[test]
    fn bilan_des_failles() {
        let f = |paquet: &str, gravite, corrigee| Faille {
            paquet: paquet.into(),
            gravite,
            corrigee,
        };
        assert!(bilan_failles(Paquets::Pacman, &[]).probleme.is_none());
        // Faille sans correctif : signalée, sans baisser la note ni proposer de correction.
        let c = bilan_failles(Paquets::Pacman, &[f("pam", Niveau::Eleve, false)]);
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.correctif.is_none() && c.message.contains("pam"));
        // La pire gravité des failles corrigées donne le niveau ; jamais moins que Moyen.
        let c = bilan_failles(
            Paquets::Dnf,
            &[
                f("curl", Niveau::Info, true),
                f("curl", Niveau::Critique, true),
                f("pam", Niveau::Eleve, false),
            ],
        );
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert!(c.message.starts_with("1 paquet(s)") && c.message.contains("pam") && c.correctif.is_some());
        assert_eq!(
            bilan_failles(Paquets::Apt, &[f("vim", Niveau::Info, true)]).probleme,
            Some(Niveau::Moyen)
        );
    }
}

/// Les mises à jour de sécurité installées toutes seules : unattended-upgrades sous Debian et Ubuntu, dnf-automatic
/// sous Fedora. Ailleurs (Arch, openSUSE, systèmes atomiques), rien à dire : la mise à jour se fait autrement, ou
/// l'outil met déjà le système entier à jour. Une information, avec la commande pour l'activer.
/// dnf-automatic installe-t-il vraiment ? Le minuteur « -install » toujours ; le minuteur ordinaire seulement si
/// automatic.conf dit « apply_updates = yes » dans [commands] (sinon il télécharge, sans rien installer : le réglage
/// livré par Fedora).
pub(super) fn juger_dnf_auto(minuteur_install: bool, minuteur: bool, conf: &str) -> bool {
    minuteur_install
        || (minuteur
            && super::valeur_ini(conf, |s| s == "commands", "apply_updates")
                .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")))
}

pub(super) fn maj_automatiques() -> Option<Constat> {
    if atomique().is_some() {
        return None;
    }
    let apt = std::path::Path::new("/usr/bin/apt-get").exists();
    let dnf = std::path::Path::new("/usr/bin/dnf").exists();
    let actives = if apt {
        // L'ordre d'APT : apt.conf.d trié, puis apt.conf ; la dernière valeur l'emporte.
        let mut fichiers: Vec<std::path::PathBuf> = std::fs::read_dir("/etc/apt/apt.conf.d")
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        fichiers.sort();
        fichiers.push("/etc/apt/apt.conf".into());
        let conf = fichiers
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .collect::<Vec<_>>()
            .join("\n");
        juger_apt_auto(&conf, std::path::Path::new("/usr/bin/unattended-upgrade").exists())
    } else if dnf {
        let actif = |t: &str| sortie("systemctl", &["is-enabled", t]).is_some_and(|s| s.trim() == "enabled");
        let conf = ["/etc/dnf/automatic.conf", "/etc/dnf/dnf5-plugins/automatic.conf"]
            .iter()
            .filter_map(|c| std::fs::read_to_string(c).ok())
            .collect::<Vec<_>>()
            .join("\n");
        juger_dnf_auto(
            actif("dnf-automatic-install.timer"),
            actif("dnf-automatic.timer") || actif("dnf5-automatic.timer"),
            &conf,
        )
    } else {
        return None;
    };
    Some(if actives {
        ok(
            "Mises à jour",
            tr!(
                "Les mises à jour de sécurité s'installent toutes seules.",
                "Security updates install by themselves."
            ),
        )
    } else if apt {
        alerte(
            "Mises à jour",
            Niveau::Info,
            tr!(
                "Les mises à jour de sécurité ne s'installent pas toutes seules : une faille corrigée reste ouverte ici jusqu'à la prochaine mise à jour faite à la main.",
                "Security updates do not install by themselves: a fixed flaw stays open here until the next update done by hand."
            ),
        )
        .manuel(
            tr!(
                "Activer les mises à jour de sécurité automatiques (unattended-upgrades)",
                "Turn on automatic security updates (unattended-upgrades)"
            ),
            &["sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"],
        )
    } else {
        alerte(
            "Mises à jour",
            Niveau::Info,
            tr!(
                "Les mises à jour de sécurité ne s'installent pas toutes seules : une faille corrigée reste ouverte ici jusqu'à la prochaine mise à jour faite à la main.",
                "Security updates do not install by themselves: a fixed flaw stays open here until the next update done by hand."
            ),
        )
        .manuel(
            tr!(
                "Activer dnf-automatic en mode installation (le minuteur ordinaire ne fait que télécharger) : la commande ci-dessous jusqu'à Fedora 40 ; à partir de Fedora 41 (dnf5), « apply_updates = yes » dans la section [commands] de /etc/dnf/automatic.conf, puis sudo systemctl enable --now dnf5-automatic.timer",
                "Turn on dnf-automatic in install mode (the plain timer only downloads): the command below up to Fedora 40; from Fedora 41 (dnf5), “apply_updates = yes” in the [commands] section of /etc/dnf/automatic.conf, then sudo systemctl enable --now dnf5-automatic.timer"
            ),
            &["sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer"],
        )
    })
}

/// apt : `APT::Periodic::Unattended-Upgrade "1";` dans la configuration, et l'outil installé.
fn juger_apt_auto(conf: &str, outil: bool) -> bool {
    // La dernière valeur l'emporte : un « 0 » dans un fichier lu après annule un « 1 » d'avant.
    outil
        && conf
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//") && l.starts_with("APT::Periodic::Unattended-Upgrade"))
            .filter_map(|l| l.split('"').nth(1))
            .next_back()
            .is_some_and(|v| v.trim() != "0")
}

#[cfg(test)]
mod tests_maj_automatiques {
    use super::*;

    #[test]
    fn configuration_d_apt() {
        let actif = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n";
        assert!(juger_apt_auto(actif, true));
        assert!(!juger_apt_auto(actif, false));
        assert!(!juger_apt_auto("APT::Periodic::Unattended-Upgrade \"0\";\n", true));
        assert!(!juger_apt_auto("// APT::Periodic::Unattended-Upgrade \"1\";\n", true));
        assert!(!juger_apt_auto("", true));
        // Annulé par un fichier lu après ; réactivé encore après.
        assert!(!juger_apt_auto(
            "APT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n",
            true
        ));
        assert!(juger_apt_auto(
            "APT::Periodic::Unattended-Upgrade \"0\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
            true
        ));
    }
}
