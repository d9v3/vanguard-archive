//! « Pourquoi c'est lent ? » : un instantané en deux mesures, à deux secondes d'écart. Ce qui occupe le processeur,
//! la mémoire et le disque, programme par programme ; le démarrage (sa durée, ce qui le retarde) ; les programmes
//! lancés à l'ouverture de session et leur poids. La mesure est en lecture seule : les conseils disent quel outil de
//! Gardien règle quoi (Nettoyer, Optimiser, Mises à jour, programmes au démarrage à retirer ou remettre, après accord
//! et de façon annulable), et l'écran les ouvre.

use std::collections::HashMap;

use crate::ui::*;

/// Durée entre les deux mesures : assez pour lisser un pic, assez courte pour qu'on attende sans s'impatienter.
/// (Windows et macOS mesurent eux-mêmes sur deux secondes : PowerShell, top.)
#[cfg(target_os = "linux")]
const ECART: std::time::Duration = std::time::Duration::from_secs(2);

/// Un programme (tous ses processus réunis : Firefox en compte une dizaine).
#[derive(Debug, Clone, PartialEq)]
pub struct Programme {
    pub nom: String,
    /// Part de toute la machine (tous les cœurs), en %.
    pub processeur: f64,
    /// Mémoire vive occupée, en octets.
    pub memoire: u64,
    /// Lectures et écritures, en octets par seconde ; `None` : illisible (programme d'un autre compte).
    pub disque: Option<f64>,
}

/// Le dernier démarrage de l'ordinateur.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Demarrage {
    /// Durée totale, en secondes.
    pub total: f64,
    /// Les étapes (« micrologiciel 11,8 s · chargeur 8,1 s… »).
    pub etapes: String,
    /// Ce qui l'a le plus retardé : (nom, secondes).
    pub lents: Vec<(String, f64)>,
}

/// Un programme lancé à l'ouverture de session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuDemarrage {
    pub nom: String,
    /// Mémoire qu'il occupe en ce moment ; `None` : il ne tourne pas, ou on ne l'a pas retrouvé.
    pub poids: Option<u64>,
}

#[derive(Debug)]
pub struct Instantane {
    /// Processeur occupé, toute la machine, en %.
    pub processeur: Option<f64>,
    pub fils: usize,
    /// (totale, disponible), en octets.
    pub memoire: Option<(u64, u64)>,
    /// Mémoire d'échange (fichier ou partition) : (taille, utilisée).
    pub echange: Option<(u64, u64)>,
    /// Temps d'occupation du disque le plus chargé, en %.
    pub disque: Option<f64>,
    pub programmes: Vec<Programme>,
    /// `Err` : pourquoi la durée du démarrage n'a pas pu être lue.
    pub demarrage: Result<Demarrage, String>,
    pub au_demarrage: Vec<AuDemarrage>,
    /// Secondes depuis le démarrage.
    pub allume_depuis: Option<u64>,
    /// Disque du système : (libre, total).
    pub place: Option<(u64, u64)>,
}

impl Default for Instantane {
    fn default() -> Self {
        Instantane {
            processeur: None,
            fils: 1,
            memoire: None,
            echange: None,
            disque: None,
            programmes: Vec::new(),
            demarrage: Err(tr!("durée non mesurée", "duration not measured").into()),
            au_demarrage: Vec::new(),
            allume_depuis: None,
            place: None,
        }
    }
}

/// Les processus d'un même programme réunis, triés plus tard selon ce qu'on regarde.
fn reunir(processus: impl Iterator<Item = Programme>) -> Vec<Programme> {
    let mut par_nom: HashMap<String, Programme> = HashMap::new();
    for p in processus {
        let e = par_nom.entry(p.nom.clone()).or_insert(Programme {
            nom: p.nom.clone(),
            processeur: 0.0,
            memoire: 0,
            disque: None,
        });
        e.processeur += p.processeur;
        e.memoire += p.memoire;
        if let Some(d) = p.disque {
            e.disque = Some(e.disque.unwrap_or(0.0) + d);
        }
    }
    par_nom.into_values().collect()
}

/// « 1min 2.105s », « 835ms », « 1.186s », « 2h 3min » (durées de systemd) → secondes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn secondes_systemd(texte: &str) -> Option<f64> {
    let mut total = 0.0;
    let mut vu = false;
    for morceau in texte.split_whitespace() {
        let morceau = morceau.trim_start_matches('+');
        let (nombre, unite) = morceau
            .find(|c: char| c.is_ascii_alphabetic())
            .map(|i| morceau.split_at(i))?;
        let n: f64 = nombre.parse().ok()?;
        total += n * match unite {
            "h" => 3600.0,
            "min" => 60.0,
            "s" => 1.0,
            "ms" => 0.001,
            "us" | "µs" => 0.000_001,
            _ => return None,
        };
        vu = true;
    }
    vu.then_some(total)
}

/// `systemd-analyze` : « Startup finished in 11.846s (firmware) + 8.083s (loader) + 15.167s (kernel) + 5.575s
/// (userspace) = 40.673s » → (total, étapes).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn duree_systemd(texte: &str) -> Option<(f64, String)> {
    let ligne = texte.lines().find(|l| l.starts_with("Startup finished in "))?;
    let (etapes, total) = ligne.strip_prefix("Startup finished in ")?.rsplit_once(" = ")?;
    let total = secondes_systemd(total.trim())?;
    let noms = |e: &str| match e {
        "firmware" => tr!("micrologiciel", "firmware"),
        "loader" => tr!("chargeur", "loader"),
        "kernel" => tr!("noyau", "kernel"),
        "initrd" => "initrd",
        "userspace" => tr!("système", "userspace"),
        _ => "",
    };
    let etapes = etapes
        .split(" + ")
        .filter_map(|e| {
            let (duree, nom) = e.trim().split_once(" (")?;
            let nom = noms(nom.trim_end_matches(')'));
            let secondes = secondes_systemd(duree)?;
            (!nom.is_empty()).then(|| format!("{nom} {}", secondes_lisibles(secondes)))
        })
        .collect::<Vec<_>>()
        .join(" · ");
    Some((total, etapes))
}

/// `systemd-analyze critical-chain` : les unités du chemin critique et le temps que chacune a pris à démarrer
/// (« +1.186s »), les plus longues d'abord. `blame` mélangerait ce qui tourne après le démarrage (mise à jour de la
/// base de locate, par exemple) avec ce qui le retarde vraiment.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn chaine_critique(texte: &str) -> Vec<(String, f64)> {
    let mut lents: Vec<(String, f64)> = texte
        .lines()
        .filter_map(|l| {
            let l = l.trim_start_matches(|c: char| !c.is_alphanumeric());
            let (nom, reste) = l.split_once(' ')?;
            let duree = reste.split_once('+')?.1;
            Some((nom.to_string(), secondes_systemd(duree)?))
        })
        .filter(|(_, s)| *s >= 0.5)
        .collect();
    lents.sort_by(|a, b| b.1.total_cmp(&a.1));
    lents.truncate(5);
    lents
}

/// « 12,3 s », « 1 min 05 s ».
fn secondes_lisibles(s: f64) -> String {
    if s >= 60.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let s = s.round() as u64;
        format!("{} min {:02} s", s / 60, s % 60)
    } else if crate::langue::anglais() {
        format!("{s:.1} s")
    } else {
        format!("{s:.1} s").replace('.', ",")
    }
}

/// Une entrée de démarrage automatique (fichier .desktop d'autostart) : (nom affiché, programme) si elle est active
/// pour ce bureau. `Hidden=true` ou `X-GNOME-Autostart-enabled=false` : désactivée ; `OnlyShowIn`/`NotShowIn` :
/// selon le bureau.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn entree_autostart(texte: &str, bureau: &str) -> Option<(String, String)> {
    let mut dans_entree = false;
    let mut champs: HashMap<&str, &str> = HashMap::new();
    for l in texte.lines() {
        let l = l.trim();
        if l.starts_with('[') {
            dans_entree = l == "[Desktop Entry]";
            continue;
        }
        if dans_entree && let Some((cle, valeur)) = l.split_once('=') {
            champs.entry(cle.trim()).or_insert(valeur.trim());
        }
    }
    let vrai = |cle: &str| champs.get(cle).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if vrai("Hidden")
        || champs
            .get("X-GNOME-Autostart-enabled")
            .is_some_and(|v| v.eq_ignore_ascii_case("false"))
    {
        return None;
    }
    let bureaux: Vec<String> = bureau
        .split(':')
        .map(str::to_lowercase)
        .filter(|b| !b.is_empty())
        .collect();
    let liste = |cle: &str| -> Vec<String> {
        champs
            .get(cle)
            .map(|v| {
                v.split(';')
                    .map(|b| b.trim().to_lowercase())
                    .filter(|b| !b.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    let seulement = liste("OnlyShowIn");
    if !seulement.is_empty() && !seulement.iter().any(|b| bureaux.contains(b)) {
        return None;
    }
    if liste("NotShowIn").iter().any(|b| bureaux.contains(b)) {
        return None;
    }
    let commande = champs.get("Exec")?;
    // « env VAR=1 programme --option %u » → « programme ».
    let programme = commande
        .split_whitespace()
        .find(|m| *m != "env" && !m.contains('=') && !m.starts_with('-'))?
        .trim_matches('"');
    let programme = programme.rsplit('/').next().unwrap_or(programme).to_string();
    let nom = champs
        .get("Name")
        .map_or_else(|| programme.clone(), ToString::to_string);
    Some((nom, programme))
}

/// Les conseils d'un instantané : (niveau d'alerte, texte, outil à proposer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outil {
    Nettoyer,
    Demarrage,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Performance,
    MisesAJour,
}

pub struct Conseil {
    pub grave: bool,
    pub texte: String,
    pub outil: Option<Outil>,
}

/// Programmes qui travaillent fort pendant un moment, puis se calment seuls : les nommer évite d'accuser l'ordinateur.
const PASSAGERS: &[(&str, &str, &str)] = &[
    (
        "msmpeng",
        "l'antivirus de Windows analyse les fichiers",
        "Windows' antivirus is scanning files",
    ),
    (
        "mpdefendercoreservice",
        "l'antivirus de Windows analyse les fichiers",
        "Windows' antivirus is scanning files",
    ),
    (
        "tiworker",
        "Windows installe des mises à jour",
        "Windows is installing updates",
    ),
    (
        "trustedinstaller",
        "Windows installe des mises à jour",
        "Windows is installing updates",
    ),
    (
        "searchindexer",
        "Windows indexe les fichiers pour la recherche",
        "Windows is indexing files for search",
    ),
    (
        "mdworker",
        "macOS indexe les fichiers pour Spotlight",
        "macOS is indexing files for Spotlight",
    ),
    (
        "mds_stores",
        "macOS indexe les fichiers pour Spotlight",
        "macOS is indexing files for Spotlight",
    ),
    (
        "localsearch",
        "le bureau indexe les fichiers pour la recherche",
        "the desktop is indexing files for search",
    ),
    (
        "tracker-miner",
        "le bureau indexe les fichiers pour la recherche",
        "the desktop is indexing files for search",
    ),
    (
        "baloo_file",
        "KDE indexe les fichiers pour la recherche",
        "KDE is indexing files for search",
    ),
    (
        "packagekitd",
        "les mises à jour se téléchargent",
        "updates are downloading",
    ),
    (
        "plocate",
        "la base de recherche des fichiers se refait",
        "the file search database is being rebuilt",
    ),
    (
        "updatedb",
        "la base de recherche des fichiers se refait",
        "the file search database is being rebuilt",
    ),
];

fn passager(nom: &str) -> Option<&'static str> {
    let n = nom.to_lowercase();
    PASSAGERS
        .iter()
        .find(|(cle, ..)| n.starts_with(cle))
        .map(|(_, fr, en)| if crate::langue::anglais() { *en } else { *fr })
}

#[allow(clippy::cast_precision_loss)]
fn pourcent(partie: u64, tout: u64) -> f64 {
    if tout == 0 {
        0.0
    } else {
        partie as f64 * 100.0 / tout as f64
    }
}

/// Ce qu'on peut conclure de l'instantané, le plus grave d'abord.
pub fn conseils(i: &Instantane) -> Vec<Conseil> {
    let mut c = Vec::new();
    let plus = |cle: fn(&Programme) -> f64| {
        i.programmes
            .iter()
            .max_by(|a, b| cle(a).total_cmp(&cle(b)))
            .filter(|p| cle(p) > 0.0)
    };
    if let Some(occupe) = i.processeur
        && occupe >= 80.0
    {
        let texte = match plus(|p| p.processeur) {
            Some(p) => match passager(&p.nom) {
                Some(raison) => trf!(
                    "Processeur occupé à {occupe:.0} %, surtout par {} : {raison}. Ça passe seul, en général en moins d'une heure.",
                    "Processor {occupe:.0}% busy, mostly by {}: {raison}. It passes by itself, usually within an hour.",
                    p.nom
                ),
                None => trf!(
                    "Processeur occupé à {occupe:.0} %, surtout par {} ({:.0} %). Le fermer s'il ne sert pas en ce moment.",
                    "Processor {occupe:.0}% busy, mostly by {} ({:.0}%). Close it if it is not in use right now.",
                    p.nom,
                    p.processeur
                ),
            },
            None => trf!("Processeur occupé à {occupe:.0} %.", "Processor {occupe:.0}% busy."),
        };
        c.push(Conseil {
            grave: true,
            texte,
            outil: None,
        });
    }
    if let Some((total, dispo)) = i.memoire
        && pourcent(dispo, total) < 10.0
    {
        let gros = plus(|p| {
            #[allow(clippy::cast_precision_loss)]
            let m = p.memoire as f64;
            m
        });
        c.push(Conseil {
            grave: true,
            texte: match gros {
                Some(p) => trf!(
                    "Mémoire presque pleine ({} libres sur {}) : l'ordinateur écrit sur le disque ce qui ne tient plus, d'où la lenteur. {} en occupe {} : le fermer, ou fermer des onglets.",
                    "Memory almost full ({} free out of {}): the computer writes what no longer fits to the disk, hence the slowness. {} uses {}: close it, or close some tabs.",
                    taille(dispo),
                    taille(total),
                    p.nom,
                    taille(p.memoire)
                ),
                None => trf!(
                    "Mémoire presque pleine ({} libres sur {}).",
                    "Memory almost full ({} free out of {}).",
                    taille(dispo),
                    taille(total)
                ),
            },
            outil: Some(Outil::Demarrage),
        });
    }
    if let Some(occupe) = i.disque
        && occupe >= 80.0
    {
        let texte = match plus(|p| p.disque.unwrap_or(0.0)) {
            Some(p) => trf!(
                "Disque occupé {occupe:.0} % du temps, surtout par {} ({}/s){}.",
                "Disk busy {occupe:.0}% of the time, mostly by {} ({}/s){}.",
                p.nom,
                taille(debit(p.disque.unwrap_or(0.0))),
                passager(&p.nom).map(|r| format!(" : {r}")).unwrap_or_default()
            ),
            None => trf!(
                "Disque occupé {occupe:.0} % du temps : tout ce qui le lit ou l'écrit attend son tour.",
                "Disk busy {occupe:.0}% of the time: everything that reads or writes it waits its turn."
            ),
        };
        c.push(Conseil {
            grave: true,
            texte,
            outil: None,
        });
    }
    if let Some((libre, total)) = i.place
        && pourcent(libre, total) < 10.0
    {
        c.push(Conseil {
            grave: true,
            texte: trf!(
                "Disque du système presque plein ({} libres sur {}) : le système a besoin de place pour travailler.",
                "System disk almost full ({} free out of {}): the system needs room to work.",
                taille(libre),
                taille(total)
            ),
            outil: Some(Outil::Nettoyer),
        });
    }
    if let Ok(d) = &i.demarrage
        && d.total >= 60.0
    {
        let lents = d
            .lents
            .iter()
            .take(3)
            .map(|(n, s)| format!("{n} {}", secondes_lisibles(*s)))
            .collect::<Vec<_>>()
            .join(", ");
        c.push(Conseil {
            grave: false,
            texte: if lents.is_empty() {
                trf!("Démarrage long ({}).", "Slow startup ({}).", secondes_lisibles(d.total))
            } else {
                trf!(
                    "Démarrage long ({}) ; ce qui le retarde le plus : {lents}.",
                    "Slow startup ({}); what delays it most: {lents}.",
                    secondes_lisibles(d.total)
                )
            },
            outil: Some(Outil::Performance),
        });
    }
    let lourds: Vec<&AuDemarrage> = i.au_demarrage.iter().filter(|p| p.poids.is_some()).collect();
    if i.au_demarrage.len() >= 8 || lourds.iter().filter_map(|p| p.poids).sum::<u64>() >= 1 << 30 {
        c.push(Conseil {
            grave: false,
            texte: trf!(
                "{} programmes se lancent à l'ouverture de session : ceux dont tu n'as pas besoin tout de suite peuvent attendre que tu les ouvres.",
                "{} programs start when you log in: those you do not need right away can wait until you open them.",
                i.au_demarrage.len()
            ),
            outil: Some(Outil::Demarrage),
        });
    }
    // Windows surtout : des semaines sans redémarrer, et des mises à jour attendent, des fuites de mémoire s'accumulent.
    if i.allume_depuis.is_some_and(|s| s >= 14 * 86_400) {
        c.push(Conseil {
            grave: false,
            texte: trf!(
                "Allumé depuis {} jours sans redémarrer : redémarrer libère la mémoire et termine les mises à jour en attente.",
                "On for {} days without a restart: restarting frees memory and finishes pending updates.",
                i.allume_depuis.unwrap_or(0) / 86_400
            ),
            outil: Some(Outil::MisesAJour),
        });
    }
    c
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn debit(octets_par_seconde: f64) -> u64 {
    octets_par_seconde.max(0.0) as u64
}

fn taille(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let f = octets as f64;
    if octets >= 1 << 30 {
        trf!("{:.1} Go", "{:.1} GB", f / f64::from(1u32 << 30))
    } else if octets >= 1 << 20 {
        trf!("{:.0} Mo", "{:.0} MB", f / f64::from(1u32 << 20))
    } else {
        trf!("{:.0} ko", "{:.0} kB", f / 1024.0)
    }
}

/// Une barre de 10 cases, colorée selon la charge.
fn jauge(pct: f64) -> String {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let pleines = ((pct.clamp(0.0, 100.0) + 5.0) / 10.0) as usize;
    let couleur_jauge = if pct >= 80.0 {
        couleur(crate::risk::Niveau::Eleve)
    } else if pct >= 50.0 {
        couleur(crate::risk::Niveau::Moyen)
    } else {
        VERT
    };
    format!(
        "{couleur_jauge}{}{GRIS}{}{RESET}",
        "▰".repeat(pleines.min(10)),
        "▱".repeat(10 - pleines.min(10))
    )
}

/// Les trois plus gros selon `cle`, en une ligne : « firefox 22 %, code 9 % ». Sous `seuil`, rien à dire : un
/// programme à « 0 % » n'est pas un suspect.
fn plus_gros(
    programmes: &[Programme],
    seuil: f64,
    cle: impl Fn(&Programme) -> f64,
    texte: impl Fn(&Programme) -> String,
) -> String {
    let mut tries: Vec<&Programme> = programmes.iter().filter(|p| cle(p) >= seuil).collect();
    tries.sort_by(|a, b| cle(b).total_cmp(&cle(a)));
    tries
        .iter()
        .take(3)
        .map(|p| format!("{} {}", p.nom, texte(p)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn ligne_mesure(libelle: &str, valeur: &str) {
    afficher_aligne(&format!("  {GRAS}{}{RESET} ", ajuster(libelle, 13)), valeur, 16, "");
}

fn afficher(i: &Instantane) {
    section(tr!("EN CE MOMENT", "RIGHT NOW"));
    match i.processeur {
        Some(p) => ligne_mesure(
            tr!("Processeur", "Processor"),
            &trf!("{} {p:.0} % ({} fils)", "{} {p:.0}% ({} threads)", jauge(p), i.fils),
        ),
        None => ligne_mesure(tr!("Processeur", "Processor"), tr!("non mesuré", "not measured")),
    }
    if let Some((total, dispo)) = i.memoire {
        let utilise = pourcent(total.saturating_sub(dispo), total);
        let echange = match i.echange {
            Some((t, u)) if t > 0 && u >= 1 << 20 => {
                trf!(", échange {} utilisés", ", swap {} used", taille(u))
            }
            _ => String::new(),
        };
        ligne_mesure(
            tr!("Mémoire", "Memory"),
            &trf!(
                "{} {utilise:.0} % ({} libres sur {}){echange}",
                "{} {utilise:.0}% ({} free out of {}){echange}",
                jauge(utilise),
                taille(dispo),
                taille(total)
            ),
        );
    }
    match i.disque {
        Some(d) => ligne_mesure(
            tr!("Disque", "Disk"),
            &trf!("{} occupé {d:.0} % du temps", "{} busy {d:.0}% of the time", jauge(d)),
        ),
        None => ligne_mesure(
            tr!("Disque", "Disk"),
            tr!("activité non mesurable ici", "activity not measurable here"),
        ),
    }
    if let Some((libre, total)) = i.place {
        ligne_mesure(
            tr!("Place", "Space"),
            &trf!(
                "{} libres sur {} (disque du système)",
                "{} free out of {} (system disk)",
                taille(libre),
                taille(total)
            ),
        );
    }

    section(tr!("CE QUI PÈSE LE PLUS", "WHAT WEIGHS THE MOST"));
    let cpu = plus_gros(
        &i.programmes,
        1.0,
        |p| p.processeur,
        |p| trf!("{:.0} %", "{:.0}%", p.processeur),
    );
    #[allow(clippy::cast_precision_loss)]
    let mem = plus_gros(
        &i.programmes,
        100.0 * 1_048_576.0,
        |p| p.memoire as f64,
        |p| taille(p.memoire),
    );
    let dsk = plus_gros(
        &i.programmes,
        1_048_576.0,
        |p| p.disque.unwrap_or(0.0),
        |p| format!("{}/s", taille(debit(p.disque.unwrap_or(0.0)))),
    );
    let rien = tr!("rien de notable", "nothing notable");
    ligne_mesure(
        tr!("Processeur", "Processor"),
        if cpu.is_empty() { rien } else { cpu.as_str() },
    );
    ligne_mesure(
        tr!("Mémoire", "Memory"),
        if mem.is_empty() { rien } else { mem.as_str() },
    );
    ligne_mesure(tr!("Disque", "Disk"), if dsk.is_empty() { rien } else { dsk.as_str() });

    section(tr!("DÉMARRAGE", "STARTUP"));
    match &i.demarrage {
        Ok(d) => {
            let etapes = if d.etapes.is_empty() {
                String::new()
            } else {
                format!(" ({})", d.etapes)
            };
            ligne_mesure(
                tr!("Durée", "Duration"),
                &format!("{}{etapes}", secondes_lisibles(d.total)),
            );
            if !d.lents.is_empty() {
                let lents = d
                    .lents
                    .iter()
                    .map(|(n, s)| format!("{n} {}", secondes_lisibles(*s)))
                    .collect::<Vec<_>>()
                    .join(", ");
                ligne_mesure(tr!("Retardé par", "Delayed by"), &lents);
            }
        }
        Err(raison) => ligne_mesure(tr!("Durée", "Duration"), &format!("{GRIS}{raison}{RESET}")),
    }
    if let Some(s) = i.allume_depuis {
        let (j, h) = (s / 86_400, s % 86_400 / 3600);
        ligne_mesure(
            tr!("Allumé depuis", "On for"),
            &if j > 0 {
                trf!("{j} j {h} h", "{j} d {h} h")
            } else {
                trf!("{h} h {:02}", "{h} h {:02}", s % 3600 / 60)
            },
        );
    }
    if i.au_demarrage.is_empty() {
        ligne_mesure(
            tr!("À l'ouverture", "At login"),
            tr!("aucun programme trouvé", "no program found"),
        );
    } else {
        let mut liste: Vec<&AuDemarrage> = i.au_demarrage.iter().collect();
        liste.sort_by(|a, b| b.poids.cmp(&a.poids).then_with(|| a.nom.cmp(&b.nom)));
        let noms = liste
            .iter()
            .take(8)
            .map(|p| match p.poids {
                Some(o) => format!("{} ({})", p.nom, taille(o)),
                None => p.nom.clone(),
            })
            .collect::<Vec<_>>();
        let reste = liste.len().saturating_sub(8);
        let texte = if reste > 0 {
            format!(
                "{}{}",
                noms.join(", "),
                trf!(" et {reste} autre(s)", " and {reste} more")
            )
        } else {
            noms.join(", ")
        };
        ligne_mesure(
            tr!("À l'ouverture", "At login"),
            &trf!("{} programme(s) : {texte}", "{} program(s): {texte}", liste.len()),
        );
    }
}

fn afficher_conseils(c: &[Conseil]) {
    section(tr!("CE QUE ÇA VEUT DIRE", "WHAT IT MEANS"));
    if c.is_empty() {
        afficher_aligne(
            &format!("  {VERT}✔{RESET} "),
            tr!(
                "Rien ne force en ce moment : si c'est lent par moments, relance la mesure à ce moment-là.",
                "Nothing is straining right now: if it is slow at times, run the measure again at that moment."
            ),
            4,
            "",
        );
    }
    for k in c {
        let marque = if k.grave {
            format!("{}⚠{RESET} ", couleur(crate::risk::Niveau::Moyen))
        } else {
            "💡 ".to_string()
        };
        afficher_aligne(&format!("  {marque}"), &k.texte, 5, "");
    }
}

/// Mesure, puis montre.
fn mesurer() -> Instantane {
    trp!(
        "  {DISCRET}Mesure pendant deux secondes : continue à utiliser l'ordinateur comme d'habitude…{RESET}",
        "  {DISCRET}Measuring for two seconds: keep using the computer as usual…{RESET}"
    );
    systeme::instantane()
}

fn entete() {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("POURQUOI C'EST LENT ?", "WHY IS IT SLOW?")),
        &format!("{GRIS}{}{RESET}", tr!("lecture seule", "read only")),
    );
}

/// « gardien lenteur » : l'instantané et ses conseils.
pub fn commande() {
    entete();
    let i = mesurer();
    afficher(&i);
    afficher_conseils(&conseils(&i));
}

/// L'outil au menu : l'instantané, ses conseils, puis l'outil qui règle ce qui a été trouvé.
pub fn menu() {
    loop {
        entete();
        let i = mesurer();
        afficher(&i);
        let c = conseils(&i);
        afficher_conseils(&c);
        // Les choix s'écrivent sous la mesure, qui reste à l'écran (un menu au clavier redessinerait tout l'écran).
        section(tr!("ET MAINTENANT", "WHAT NEXT"));
        let mut outils: Vec<(String, Outil)> = Vec::new();
        let proposer = |outils: &mut Vec<(String, Outil)>, outil: Outil| {
            if outils.iter().any(|(_, o)| *o == outil) {
                return;
            }
            let (texte, precision) = match outil {
                Outil::Nettoyer => (
                    tr!("Nettoyer le système", "Clean up the system"),
                    tr!("caches, temporaires, corbeille…", "caches, temp files, trash…"),
                ),
                Outil::Demarrage => (
                    tr!("Programmes au démarrage", "Startup programs"),
                    tr!("les retirer ou les remettre", "remove or put back"),
                ),
                Outil::Performance => (
                    tr!("Réglages de performance", "Performance settings"),
                    tr!("Optimiser, tout s'annule", "Optimize, all undoable"),
                ),
                Outil::MisesAJour => (
                    tr!("Mises à jour", "Updates"),
                    tr!("système, programmes, pilotes", "system, programs, drivers"),
                ),
            };
            let touche = (outils.len() + 1).to_string();
            println!(
                "   {TOUCHE}{touche}{RESET}  {}{DISCRET}{precision}{RESET}",
                ajuster(texte, 34)
            );
            outils.push((touche, outil));
        };
        for k in &c {
            if let Some(o) = k.outil {
                proposer(&mut outils, o);
            }
        }
        // Toujours sous la main, même quand rien ne force.
        proposer(&mut outils, Outil::Demarrage);
        proposer(&mut outils, Outil::Nettoyer);
        println!("   {TOUCHE}m{RESET}  {}", tr!("Mesurer de nouveau", "Measure again"));
        println!("   {TOUCHE}↵{RESET}  {}", tr!("Revenir", "Back"));
        let choix = demander(tr!(
            "\n  Choix (Entrée pour revenir) : ",
            "\n  Choice (Enter to go back): "
        ))
        .trim()
        .to_lowercase();
        if choix == "m" {
            continue;
        }
        let Some((_, outil)) = outils.iter().find(|(t, _)| *t == choix) else {
            return;
        };
        println!();
        match outil {
            Outil::Nettoyer => crate::nettoyer::menu(),
            Outil::Demarrage => crate::optimiser::programmes_au_demarrage(),
            #[cfg(not(target_os = "macos"))]
            Outil::Performance => crate::optimiser::menu(crate::optimiser::Categorie::Performance),
            #[cfg(target_os = "macos")]
            Outil::Performance => {}
            Outil::MisesAJour => crate::maj::executer(),
        }
        return;
    }
}

// ───────────────────────────── Linux ─────────────────────────────

/// Le nom d'un processus : son programme (lien /proc/<pid>/exe, lisible pour nos propres processus), sauf quand ce
/// programme est un interpréteur ou un moteur partagé (python, electron…) : son nom court dit alors mieux qui il est.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nom_de_processus(exe: Option<&str>, comm: &str) -> String {
    const MOTEURS: &[&str] = &[
        "python", "perl", "ruby", "node", "electron", "java", "bash", "sh", "dash", "zsh", "lua",
    ];
    let court = comm.split('/').next().unwrap_or(comm).trim().to_string();
    match exe
        .and_then(|e| e.rsplit('/').next())
        .map(|e| e.trim_end_matches(" (deleted)"))
    {
        Some(e) if !e.is_empty() && !MOTEURS.iter().any(|m| e.starts_with(m)) => e.to_string(),
        _ => court,
    }
}

/// /proc/<pid>/stat : (temps processeur en tops d'horloge, mémoire résidente en pages). Le nom (2e champ) peut
/// contenir des espaces et des parenthèses : on repart de la dernière « ) ».
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stat_processus(texte: &str) -> Option<(u64, u64)> {
    let champs: Vec<&str> = texte.get(texte.rfind(')')? + 1..)?.split_whitespace().collect();
    // Après le nom : état (3e champ), …, utime (14e), stime (15e), …, rss (24e).
    let utime: u64 = champs.get(11)?.parse().ok()?;
    let stime: u64 = champs.get(12)?.parse().ok()?;
    let rss: u64 = champs.get(21)?.parse().ok()?;
    Some((utime + stime, rss))
}

/// Première ligne de /proc/stat : (occupé, total) en tops d'horloge, toute la machine.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stat_processeur(texte: &str) -> Option<(u64, u64)> {
    let valeurs: Vec<u64> = texte
        .lines()
        .next()?
        .strip_prefix("cpu ")?
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();
    // user nice system idle iowait irq softirq steal (guest est déjà compté dans user).
    let total: u64 = valeurs.iter().take(8).sum();
    let repos = valeurs.get(3)? + valeurs.get(4).copied().unwrap_or(0);
    Some((total.saturating_sub(repos), total))
}

/// /proc/diskstats : temps passé à servir des entrées-sorties (ms), par disque.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn occupation_disques(texte: &str, disques: &[String]) -> HashMap<String, u64> {
    texte
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            let nom = (*c.get(2)?).to_string();
            disques.contains(&nom).then_some((nom, c.get(12)?.parse().ok()?))
        })
        .collect()
}

#[cfg(target_os = "linux")]
mod systeme {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Instant;

    use super::{
        AuDemarrage, Demarrage, Instantane, Programme, chaine_critique, duree_systemd, entree_autostart,
        nom_de_processus, occupation_disques, reunir, stat_processeur, stat_processus,
    };
    use crate::commande::lancer;
    use crate::tr;

    struct Echantillon {
        quand: Instant,
        processeur: Option<(u64, u64)>,
        /// pid → (nom, temps processeur, mémoire en pages, octets lus et écrits)
        processus: HashMap<u32, (String, u64, u64, Option<u64>)>,
        disques: HashMap<String, u64>,
    }

    fn getconf(variable: &str, defaut: u64) -> u64 {
        lancer(Command::new("getconf").arg(variable), 5)
            .and_then(|r| r.sortie.trim().parse().ok())
            .unwrap_or(defaut)
    }

    /// Les disques entiers (pas les partitions), sans les disques virtuels.
    fn disques() -> Vec<String> {
        std::fs::read_dir("/sys/block")
            .into_iter()
            .flatten()
            .flatten()
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .filter(|n| {
                !["loop", "ram", "zram", "dm-", "sr", "fd"]
                    .iter()
                    .any(|p| n.starts_with(p))
            })
            .collect()
    }

    fn octets_es(pid: &str) -> Option<u64> {
        let io = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
        let lire = |cle: &str| io.lines().find_map(|l| l.strip_prefix(cle)?.trim().parse::<u64>().ok());
        Some(lire("read_bytes:")? + lire("write_bytes:")?)
    }

    fn echantillon(disques: &[String]) -> Echantillon {
        let mut processus = HashMap::new();
        for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
            let pid = e.file_name().to_string_lossy().into_owned();
            let Ok(n) = pid.parse::<u32>() else {
                continue;
            };
            let Some((temps, pages)) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|t| stat_processus(&t))
            else {
                continue;
            };
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
            let nom = nom_de_processus(exe.as_deref().and_then(Path::to_str), comm.trim());
            processus.insert(n, (nom, temps, pages, octets_es(&pid)));
        }
        Echantillon {
            quand: Instant::now(),
            processeur: std::fs::read_to_string("/proc/stat")
                .ok()
                .and_then(|t| stat_processeur(&t)),
            processus,
            disques: occupation_disques(&std::fs::read_to_string("/proc/diskstats").unwrap_or_default(), disques),
        }
    }

    fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
        let r = lancer(Command::new(cmd).args(args), 20)?;
        (r.code == Some(0)).then_some(r.sortie)
    }

    fn demarrage() -> Result<Demarrage, String> {
        let Some(temps) = sortie("systemd-analyze", &[]) else {
            return Err(tr!(
                "durée illisible (systemd-analyze absent, ou démarrage pas encore fini)",
                "duration not readable (no systemd-analyze, or startup not finished yet)"
            )
            .into());
        };
        let (total, etapes) =
            duree_systemd(&temps).ok_or_else(|| tr!("durée illisible", "duration not readable").to_string())?;
        Ok(Demarrage {
            total,
            etapes,
            lents: chaine_critique(&sortie("systemd-analyze", &["critical-chain", "--no-pager"]).unwrap_or_default()),
        })
    }

    /// Les programmes lancés à l'ouverture de session : entrées d'autostart actives (celles de l'utilisateur
    /// remplacent celles du système au même nom) et services ajoutés par l'utilisateur (~/.config/systemd/user).
    fn au_demarrage(memoire_par_nom: &HashMap<String, u64>) -> Vec<AuDemarrage> {
        let maison = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
        let systeme: Vec<PathBuf> = std::env::var("XDG_CONFIG_DIRS")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "/etc/xdg".into())
            .split(':')
            .map(|d| Path::new(d).join("autostart"))
            .collect();
        let bureau = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        // Nom du fichier → contenu ; l'utilisateur d'abord, il l'emporte.
        let mut entrees: Vec<(String, String)> = Vec::new();
        for dossier in std::iter::once(config.join("autostart")).chain(systeme) {
            for f in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
                let nom = f.file_name().to_string_lossy().into_owned();
                if Path::new(&nom).extension().is_none_or(|e| e != "desktop") || entrees.iter().any(|(n, _)| *n == nom)
                {
                    continue;
                }
                entrees.push((nom, std::fs::read_to_string(f.path()).unwrap_or_default()));
            }
        }
        let mut liste: Vec<AuDemarrage> = entrees
            .iter()
            .filter_map(|(_, texte)| entree_autostart(texte, &bureau))
            .map(|(nom, programme)| AuDemarrage {
                poids: memoire_par_nom.get(&programme.to_lowercase()).copied(),
                nom,
            })
            .collect();
        let services = config.join("systemd/user");
        for l in sortie(
            "systemctl",
            &[
                "--user",
                "list-unit-files",
                "--type=service",
                "--state=enabled",
                "--no-legend",
                "--no-pager",
            ],
        )
        .unwrap_or_default()
        .lines()
        {
            let Some(unite) = l.split_whitespace().next() else {
                continue;
            };
            if services.join(unite).is_file() {
                let nom = unite.trim_end_matches(".service").to_string();
                liste.push(AuDemarrage {
                    poids: memoire_par_nom.get(&nom.to_lowercase()).copied(),
                    nom,
                });
            }
        }
        liste
    }

    pub fn instantane() -> Instantane {
        let disques = disques();
        let horloge = getconf("CLK_TCK", 100).max(1);
        let page = getconf("PAGESIZE", 4096);
        let fils = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let a = echantillon(&disques);
        std::thread::sleep(super::ECART);
        let b = echantillon(&disques);
        #[allow(clippy::cast_precision_loss)]
        let ecart_s = b.quand.duration_since(a.quand).as_secs_f64().max(0.001);
        #[allow(clippy::cast_precision_loss)]
        let processeur = match (a.processeur, b.processeur) {
            (Some((oa, ta)), Some((ob, tb))) if tb > ta => {
                Some((ob.saturating_sub(oa)) as f64 * 100.0 / (tb - ta) as f64)
            }
            _ => None,
        };
        #[allow(clippy::cast_precision_loss)]
        let programmes = reunir(b.processus.iter().map(|(pid, (nom, temps, pages, es))| {
            let avant = a.processus.get(pid);
            let tops = avant.map_or(0, |(_, t, ..)| temps.saturating_sub(*t));
            let disque = match (avant.and_then(|(.., e)| *e), es) {
                (Some(x), Some(y)) => Some(y.saturating_sub(x) as f64 / ecart_s),
                _ => None,
            };
            Programme {
                nom: nom.clone(),
                // Tops d'horloge → secondes de processeur, rapportées au temps écoulé et à tous les fils.
                processeur: tops as f64 / horloge as f64 / ecart_s / fils as f64 * 100.0,
                memoire: pages * page,
                disque,
            }
        }));
        #[allow(clippy::cast_precision_loss)]
        let disque = b
            .disques
            .iter()
            .filter_map(|(nom, ms)| {
                let avant = a.disques.get(nom)?;
                Some(ms.saturating_sub(*avant) as f64 / (ecart_s * 1000.0) * 100.0)
            })
            .reduce(f64::max)
            .map(|d| d.min(100.0));
        let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let lire = |cle: &str| {
            meminfo
                .lines()
                .find_map(|l| l.strip_prefix(cle)?.split_whitespace().next()?.parse::<u64>().ok())
                .map(|ko| ko * 1024)
        };
        let memoire = lire("MemTotal:").zip(lire("MemAvailable:"));
        let echange = lire("SwapTotal:")
            .zip(lire("SwapFree:"))
            .map(|(t, l)| (t, t.saturating_sub(l)));
        let mut memoire_par_nom: HashMap<String, u64> = HashMap::new();
        for p in &programmes {
            *memoire_par_nom.entry(p.nom.to_lowercase()).or_default() += p.memoire;
        }
        Instantane {
            processeur,
            fils,
            memoire,
            echange,
            disque,
            au_demarrage: au_demarrage(&memoire_par_nom),
            programmes,
            demarrage: demarrage(),
            allume_depuis: std::fs::read_to_string("/proc/uptime")
                .ok()
                .and_then(|t| t.split('.').next()?.parse().ok()),
            place: crate::nettoyer::volume(Path::new("/")),
        }
    }
}

// ───────────────────────────── Windows ─────────────────────────────

/// Ce que lit le script PowerShell, en JSON.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct LectureWindows {
    processeur: Option<f64>,
    fils: usize,
    memoire: u64,
    disponible: u64,
    echange: u64,
    echange_utilise: u64,
    disque: Option<f64>,
    programmes: Vec<ProgrammeWindows>,
    demarrage_ms: Option<u64>,
    apres_ms: Option<u64>,
    demarrage_illisible: bool,
    lents: Vec<LentWindows>,
    au_demarrage: Vec<DemarrageWindows>,
    allume_s: Option<u64>,
    libre: u64,
    total: u64,
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ProgrammeWindows {
    nom: String,
    processeur: f64,
    memoire: u64,
    disque: Option<f64>,
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct LentWindows {
    nom: String,
    ms: u64,
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct DemarrageWindows {
    nom: String,
    programme: String,
}

/// L'instantané d'après la lecture PowerShell (séparé pour être testé partout).
#[cfg_attr(not(windows), allow(dead_code))]
#[allow(clippy::cast_precision_loss)]
fn instantane_windows(l: LectureWindows) -> Instantane {
    let programmes = reunir(l.programmes.into_iter().map(|p| Programme {
        nom: p.nom,
        processeur: p.processeur.max(0.0),
        memoire: p.memoire,
        disque: p.disque.map(|d| d.max(0.0)),
    }));
    let mut memoire_par_nom: HashMap<String, u64> = HashMap::new();
    for p in &programmes {
        *memoire_par_nom.entry(p.nom.to_lowercase()).or_default() += p.memoire;
    }
    let demarrage = match (l.demarrage_ms, l.demarrage_illisible) {
        (Some(ms), _) => {
            let mut lents: Vec<(String, f64)> = l
                .lents
                .into_iter()
                .filter(|x| !x.nom.trim().is_empty())
                .map(|x| (x.nom.trim().to_string(), x.ms as f64 / 1000.0))
                .collect();
            lents.sort_by(|a, b| b.1.total_cmp(&a.1));
            // Un même programme ralentit souvent plusieurs démarrages : une fois, avec son pire retard.
            let mut vus = std::collections::HashSet::new();
            lents.retain(|(nom, _)| vus.insert(nom.clone()));
            lents.truncate(5);
            Ok(Demarrage {
                total: ms as f64 / 1000.0,
                etapes: l
                    .apres_ms
                    .filter(|&a| a > 0)
                    .map(|a| {
                        trf!(
                            "dont {} après l'ouverture de session",
                            "including {} after login",
                            secondes_lisibles(a as f64 / 1000.0)
                        )
                    })
                    .unwrap_or_default(),
                lents,
            })
        }
        (None, true) => Err(tr!(
            "durée lisible seulement avec les droits d'administrateur",
            "duration readable only with administrator rights"
        )
        .into()),
        (None, false) => Err(tr!("pas de mesure du dernier démarrage", "no measure of the last startup").into()),
    };
    Instantane {
        processeur: l.processeur.map(|p| p.clamp(0.0, 100.0)),
        fils: l.fils.max(1),
        memoire: Some((l.memoire, l.disponible)).filter(|(t, _)| *t > 0),
        echange: Some((l.echange, l.echange_utilise)).filter(|(t, _)| *t > 0),
        disque: l.disque.map(|d| d.clamp(0.0, 100.0)),
        au_demarrage: l
            .au_demarrage
            .into_iter()
            .map(|d| AuDemarrage {
                poids: memoire_par_nom.get(&d.programme.to_lowercase()).copied(),
                nom: d.nom,
            })
            .collect(),
        programmes,
        demarrage,
        allume_depuis: l.allume_s,
        place: Some((l.libre, l.total)).filter(|(_, t)| *t > 0),
    }
}

#[cfg(windows)]
mod systeme {
    use super::{Instantane, LectureWindows, instantane_windows};

    pub fn instantane() -> Instantane {
        // Compteurs bruts lus deux fois, à deux secondes d'écart : les compteurs « mis en forme » de WMI ne sont justes
        // qu'à leur deuxième lecture, et leurs noms ne changent pas avec la langue de Windows (ceux de Get-Counter, si).
        let script = r#"
            $n = [Environment]::ProcessorCount
            function Cpu { Get-CimInstance Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction SilentlyContinue }
            function Disques { @(Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue | Where-Object Name -ne '_Total') }
            function Temps { $t = @{}; foreach ($p in Get-Process) { try { $t[$p.Id] = $p.TotalProcessorTime.Ticks } catch { } }; $t }
            function Es { $t = @{}; foreach ($p in Get-CimInstance Win32_PerfRawData_PerfProc_Process -ErrorAction SilentlyContinue) { $t[[int]$p.IDProcess] = [double]$p.IODataBytesPersec }; $t }
            $c0 = Cpu; $d0 = Disques; $t0 = Temps; $e0 = Es; $chrono = [Diagnostics.Stopwatch]::StartNew()
            Start-Sleep -Seconds 2
            $c1 = Cpu; $d1 = Disques; $t1 = Temps; $e1 = Es; $ms = [Math]::Max($chrono.Elapsed.TotalMilliseconds, 1)
            $processeur = $null
            if ($c1.Timestamp_Sys100NS -gt $c0.Timestamp_Sys100NS) {
              $processeur = 100 * (1 - ($c1.PercentProcessorTime - $c0.PercentProcessorTime) / ($c1.Timestamp_Sys100NS - $c0.Timestamp_Sys100NS)) }
            $disque = $null
            foreach ($d in $d1) { $avant = $d0 | Where-Object Name -eq $d.Name
              if ($avant -and $d.Timestamp_Sys100NS -gt $avant.Timestamp_Sys100NS) {
                $o = 100 * (1 - ($d.PercentIdleTime - $avant.PercentIdleTime) / ($d.Timestamp_Sys100NS - $avant.Timestamp_Sys100NS))
                if ($disque -eq $null -or $o -gt $disque) { $disque = $o } } }
            $programmes = foreach ($p in Get-Process) {
              $cpu = 0; if ($t0.ContainsKey($p.Id) -and $t1.ContainsKey($p.Id)) { $cpu = ($t1[$p.Id] - $t0[$p.Id]) / 10000 / $ms / $n * 100 }
              $es = $null; if ($e0.ContainsKey($p.Id) -and $e1.ContainsKey($p.Id)) { $es = ($e1[$p.Id] - $e0[$p.Id]) / ($ms / 1000) }
              @{ nom = $p.ProcessName; processeur = [double]$cpu; memoire = [uint64]$p.WorkingSet64; disque = $es } }
            $os = Get-CimInstance Win32_OperatingSystem
            $memoire = Get-CimInstance Win32_PerfRawData_PerfOS_Memory -ErrorAction SilentlyContinue
            $echange = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)
            $demarrage = $null; $apres = $null; $illisible = $false; $lents = @()
            try {
              $e = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100 } -MaxEvents 1 -ErrorAction Stop
              $x = [xml]$e.ToXml(); $v = @{}; foreach ($d in $x.Event.EventData.Data) { $v[$d.Name] = $d.'#text' }
              $demarrage = [uint64]$v['BootTime']; $apres = [uint64]$v['BootPostBootTime']
              $lents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 101, 102, 103, 106; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object {
                $x = [xml]$_.ToXml(); $v = @{}; foreach ($d in $x.Event.EventData.Data) { $v[$d.Name] = $d.'#text' }
                @{ nom = "$(if ($v['FriendlyName']) { $v['FriendlyName'] } else { $v['Name'] })"; ms = [uint64]$v['DegradationTime'] } })
            } catch [System.UnauthorizedAccessException] { $illisible = $true } catch { if ("$_" -match 'unauthorized|refusé|denied') { $illisible = $true } }
            function Approuve($ruche, $sous, $nom) {
              try { $v = (Get-ItemProperty -Path "$ruche\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$sous" -Name $nom -ErrorAction Stop).$nom
                    return -not ($v[0] -band 1) } catch { return $true } }
            $au = foreach ($s in Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue) {
              $ruche = if ("$($s.Location)" -like 'HKLM*') { 'HKLM:' } else { 'HKCU:' }
              $sous = if ("$($s.Location)" -like '*Startup*') { 'StartupFolder' } elseif ("$($s.Location)" -like '*Wow6432Node*') { 'Run32' } else { 'Run' }
              $cle = if ($sous -eq 'StartupFolder') { Split-Path -Leaf "$($s.Command)" } else { "$($s.Name)" }
              if (Approuve $ruche $sous $cle) {
                $c = "$($s.Command)".Trim()
                $prog = if ($c.StartsWith('"')) { ($c -split '"')[1] } else { ($c -split '\s+')[0] }
                @{ nom = "$($s.Caption)"; programme = [IO.Path]::GetFileNameWithoutExtension($prog) } } }
            $lecteur = [IO.DriveInfo]::new($env:SystemDrive)
            [pscustomobject]@{
              processeur = $processeur; fils = $n; memoire = [uint64]($os.TotalVisibleMemorySize * 1024); disponible = [uint64]$memoire.AvailableBytes
              echange = [uint64](($echange | Measure-Object AllocatedBaseSize -Sum).Sum * 1MB)
              echange_utilise = [uint64](($echange | Measure-Object CurrentUsage -Sum).Sum * 1MB)
              disque = $disque; programmes = @($programmes)
              demarrage_ms = $demarrage; apres_ms = $apres; demarrage_illisible = $illisible; lents = @($lents)
              au_demarrage = @($au); allume_s = [uint64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
              libre = [uint64]$lecteur.AvailableFreeSpace; total = [uint64]$lecteur.TotalSize
            } | ConvertTo-Json -Compress -Depth 3"#;
        crate::machine::windows::ps(script)
            .and_then(|json| serde_json::from_str::<LectureWindows>(&json).ok())
            .map_or_else(Instantane::default, instantane_windows)
    }
}

// ───────────────────────────── macOS ─────────────────────────────

/// « 1234M », « 12K », « 1.2G », « 512B » (colonne MEM de top, parfois suivie de « + » ou « - ») → octets.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn taille_top(texte: &str) -> Option<u64> {
    let t = texte.trim_end_matches(['+', '-']);
    let (nombre, unite) = t.split_at(t.len().checked_sub(1)?);
    let n: f64 = nombre.parse().ok()?;
    let facteur: f64 = match unite {
        "B" => 1.0,
        "K" => 1024.0,
        "M" => 1_048_576.0,
        "G" => 1_073_741_824.0,
        _ => return None,
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some((n * facteur) as u64)
}

/// `top -l 2 -s 2 -n 20 -o cpu -stats pid,command,cpu,mem` : la seconde mesure seulement (la première compte depuis le
/// lancement de top). Rend (processeur occupé en %, programmes).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn lire_top(texte: &str, fils: usize) -> (Option<f64>, Vec<Programme>) {
    let derniere = texte.rsplit("Processes:").next().unwrap_or_default();
    let processeur = derniere.lines().find_map(|l| {
        let reste = l.strip_prefix("CPU usage:")?;
        let repos = reste.split(',').find(|p| p.contains("idle"))?;
        let repos: f64 = repos.trim().split('%').next()?.trim().parse().ok()?;
        Some(100.0 - repos)
    });
    let mut programmes = Vec::new();
    let mut dans_liste = false;
    for l in derniere.lines() {
        if l.trim_start().starts_with("PID") {
            dans_liste = true;
            continue;
        }
        if !dans_liste {
            continue;
        }
        let mots: Vec<&str> = l.split_whitespace().collect();
        let [_pid, nom @ .., cpu, mem] = mots.as_slice() else {
            continue;
        };
        let (Ok(cpu), Some(memoire)) = (cpu.parse::<f64>(), taille_top(mem)) else {
            continue;
        };
        #[allow(clippy::cast_precision_loss)]
        programmes.push(Programme {
            nom: nom.join(" "),
            // top compte 100 % par cœur : rapporté à toute la machine.
            processeur: cpu / fils.max(1) as f64,
            memoire,
            disque: None,
        });
    }
    (processeur, reunir(programmes.into_iter()))
}

#[cfg(target_os = "macos")]
mod systeme {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{AuDemarrage, Instantane, lire_top};
    use crate::commande::lancer;
    use crate::tr;

    fn sortie(cmd: &str, args: &[&str]) -> String {
        lancer(Command::new(cmd).args(args), 30)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
            .unwrap_or_default()
    }

    pub fn instantane() -> Instantane {
        let fils = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let (processeur, programmes) = lire_top(
            &sortie(
                "top",
                &[
                    "-l",
                    "2",
                    "-s",
                    "2",
                    "-n",
                    "20",
                    "-o",
                    "cpu",
                    "-stats",
                    "pid,command,cpu,mem",
                ],
            ),
            fils,
        );
        let total: Option<u64> = sortie("sysctl", &["-n", "hw.memsize"]).trim().parse().ok();
        // « System-wide memory free percentage: 63% ».
        let libre_pct: Option<u64> = sortie("memory_pressure", &[])
            .lines()
            .find_map(|l| l.strip_prefix("System-wide memory free percentage:"))
            .and_then(|v| v.trim().trim_end_matches('%').parse().ok());
        // « total = 2048.00M  used = 1024.50M  free = 1023.50M  (encrypted) ».
        let echange = sortie("sysctl", &["-n", "vm.swapusage"]);
        let valeur = |cle: &str| {
            echange
                .split(cle)
                .nth(1)?
                .split_whitespace()
                .next()?
                .trim_end_matches('M')
                .parse::<f64>()
                .ok()
        };
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let echange = valeur("total = ")
            .zip(valeur("used = "))
            .map(|(t, u)| ((t * 1_048_576.0) as u64, (u * 1_048_576.0) as u64));
        let maintenant = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let allume_depuis = sortie("sysctl", &["-n", "kern.boottime"])
            .split_once("sec = ")
            .and_then(|(_, r)| r.split(',').next()?.trim().parse::<u64>().ok())
            .and_then(|s| maintenant.checked_sub(s));
        let maison = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        // Agents lancés à l'ouverture de session par des programmes installés (pas ceux d'Apple).
        let au_demarrage = [
            maison.join("Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchAgents"),
        ]
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .filter_map(|f| {
            let nom = f.file_name().to_string_lossy().into_owned();
            let nom = nom.strip_suffix(".plist")?.to_string();
            (!nom.starts_with("com.apple.")).then_some(AuDemarrage { nom, poids: None })
        })
        .collect();
        Instantane {
            processeur,
            fils,
            memoire: total.zip(libre_pct).map(|(t, p)| (t, t / 100 * p)),
            echange,
            disque: None,
            programmes,
            demarrage: Err(tr!(
                "macOS ne note pas la durée du démarrage",
                "macOS does not record the startup duration"
            )
            .into()),
            au_demarrage,
            allume_depuis,
            place: crate::nettoyer::volume(Path::new(if Path::new("/System/Volumes/Data").is_dir() {
                "/System/Volumes/Data"
            } else {
                "/"
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durees_de_systemd() {
        assert_eq!(secondes_systemd("1min 2.105s"), Some(62.105));
        assert_eq!(secondes_systemd("835ms"), Some(0.835));
        assert_eq!(secondes_systemd("+1.186s"), Some(1.186));
        assert_eq!(secondes_systemd("vite"), None);
        let (total, etapes) = duree_systemd(
            "Startup finished in 11.846s (firmware) + 8.083s (loader) + 15.167s (kernel) + 5.575s (userspace) = 40.673s \ngraphical.target reached after 3.750s in userspace.\n",
        )
        .unwrap();
        assert!((total - 40.673).abs() < 1e-9);
        assert_eq!(
            etapes,
            "micrologiciel 11,8 s · chargeur 8,1 s · noyau 15,2 s · système 5,6 s"
        );
        assert!(duree_systemd("Bootup is not yet finished.").is_none());
        let chaine = "The time when unit became active or started is printed after the \"@\" character.\n\n\
                      graphical.target @13.750s\n└─sddm.service @13.647s +102ms\n  └─docker.service @9.1s +4.512s\n    \
                      └─NetworkManager-wait-online.service @2.3s +6.810s\n      └─basic.target @2.318s\n";
        assert_eq!(
            chaine_critique(chaine),
            [
                ("NetworkManager-wait-online.service".to_string(), 6.81),
                ("docker.service".to_string(), 4.512)
            ]
        );
    }

    #[test]
    fn compteurs_du_noyau() {
        // Un nom avec espaces et parenthèses ne décale pas les champs.
        let stat = "4321 (Isolated Web Co) S 1 4321 4321 0 -1 4194560 1000 0 0 0 250 50 0 0 20 0 30 0 100 2000000000 51200 18446744073709551615";
        assert_eq!(stat_processus(stat), Some((300, 51_200)));
        assert_eq!(stat_processus("1 (a) b) S 0"), None);
        assert_eq!(
            stat_processeur("cpu  615243 4461 358423 22585874 9347 49110 11212 0 21330 0\ncpu0 1 2 3 4\n"),
            Some((1_038_449, 23_633_670))
        );
        let disques = vec!["nvme0n1".to_string(), "sda".to_string()];
        let occupation = occupation_disques(
            " 259       0 nvme0n1 15653 7015 913108 2511 10334 5220 2294634 27465 0 2667 30239 0 0 0 0 129 263\n \
             259       1 nvme0n1p1 1 2 3 4 5 6 7 8 9 10 11 0 0 0 0 0 0\n",
            &disques,
        );
        assert_eq!(occupation.get("nvme0n1"), Some(&2667));
        assert!(!occupation.contains_key("nvme0n1p1"));
        assert_eq!(
            nom_de_processus(Some("/usr/lib/firefox/firefox"), "Isolated Web Co"),
            "firefox"
        );
        assert_eq!(
            nom_de_processus(Some("/usr/bin/python3.13"), "gardien-outil"),
            "gardien-outil"
        );
        assert_eq!(nom_de_processus(None, "kworker/u32:2"), "kworker");
    }

    #[test]
    fn entrees_au_demarrage() {
        let actif =
            "[Desktop Entry]\nType=Application\nName=Discord\nExec=env FOO=1 /usr/bin/discord --start-minimized\n";
        assert_eq!(
            entree_autostart(actif, "Hyprland"),
            Some(("Discord".to_string(), "discord".to_string()))
        );
        assert_eq!(entree_autostart(&format!("{actif}Hidden=true\n"), "Hyprland"), None);
        let gnome = "[Desktop Entry]\nName=Clavier\nExec=ibus-daemon\nOnlyShowIn=GNOME;Unity;\n";
        assert_eq!(entree_autostart(gnome, "Hyprland"), None);
        assert!(entree_autostart(gnome, "ubuntu:GNOME").is_some());
        let pas_kde = "[Desktop Entry]\nName=Outil\nExec=outil\nNotShowIn=KDE;\nX-GNOME-Autostart-enabled=true\n";
        assert!(entree_autostart(pas_kde, "GNOME").is_some() && entree_autostart(pas_kde, "KDE").is_none());
        // Une action d'un autre groupe ne remplace pas l'entrée principale.
        let actions =
            "[Desktop Entry]\nName=Appli\nExec=appli\n[Desktop Action Nouvelle]\nExec=appli --nouvelle\nHidden=true\n";
        assert_eq!(
            entree_autostart(actions, ""),
            Some(("Appli".to_string(), "appli".to_string()))
        );
    }

    #[test]
    fn lecture_de_top_sous_macos() {
        let top = "Processes: 1 total\nCPU usage: 50.0% user, 10.0% sys, 40.0% idle\nPID COMMAND %CPU MEM\n1 premier 99.0 1G\n\
                   Processes: 512 total, 3 running\nLoad Avg: 1.23\nCPU usage: 12.5% user, 6.25% sys, 81.25% idle\n\
                   PhysMem: 15G used (2048M wired), 1024M unused.\n\nPID    COMMAND          %CPU MEM\n\
                   123    WindowServer     12.0 512M\n456    Google Chrome He 8.0 1024M+\n789    Google Chrome He 4.0 512M\n";
        let (processeur, programmes) = lire_top(top, 4);
        assert_eq!(processeur, Some(18.75));
        let chrome = programmes.iter().find(|p| p.nom == "Google Chrome He").unwrap();
        assert!((chrome.processeur - 3.0).abs() < 1e-9 && chrome.memoire == 1536 << 20);
        assert_eq!(taille_top("12K"), Some(12 * 1024));
        assert_eq!(taille_top("x"), None);
    }

    #[test]
    fn lecture_windows() {
        let l: LectureWindows = serde_json::from_str(
            r#"{"processeur":92.5,"fils":8,"memoire":17179869184,"disponible":1073741824,"echange":4294967296,"echange_utilise":2147483648,
                "disque":12.0,"programmes":[{"nom":"chrome","processeur":30,"memoire":1073741824,"disque":1048576},
                {"nom":"chrome","processeur":10,"memoire":536870912,"disque":null},{"nom":"MsMpEng","processeur":60,"memoire":268435456}],
                "demarrage_ms":95000,"apres_ms":40000,"lents":[{"nom":"Programme d'essai","ms":12000},{"nom":"Programme d'essai","ms":9000}],
                "au_demarrage":[{"nom":"Discord","programme":"Discord"},{"nom":"Chrome","programme":"chrome"}],
                "allume_s":1728000,"libre":10737418240,"total":256060514304}"#,
        )
        .unwrap();
        let i = instantane_windows(l);
        let chrome = i.programmes.iter().find(|p| p.nom == "chrome").unwrap();
        assert!((chrome.processeur - 40.0).abs() < 1e-9);
        assert_eq!(chrome.memoire, 1_610_612_736);
        let d = i.demarrage.as_ref().unwrap();
        assert!((d.total - 95.0).abs() < 1e-9 && d.lents.len() == 1);
        assert_eq!(i.au_demarrage[1].poids, Some(1_610_612_736));
        // L'antivirus qui travaille est nommé comme passager ; mémoire presque pleine ; 20 jours sans redémarrer.
        let c = conseils(&i);
        assert!(c[0].texte.contains("l'antivirus de Windows"), "{}", c[0].texte);
        assert!(c.iter().any(|k| k.texte.contains("Mémoire presque pleine")));
        assert!(c.iter().any(|k| k.outil == Some(Outil::MisesAJour)));
        assert!(c.iter().any(|k| k.texte.contains("Démarrage long")));
        let illisible: LectureWindows = serde_json::from_str(r#"{"demarrage_illisible":true}"#).unwrap();
        assert!(
            instantane_windows(illisible)
                .demarrage
                .unwrap_err()
                .contains("administrateur")
        );
    }

    #[test]
    fn rien_a_signaler() {
        let i = Instantane {
            processeur: Some(12.0),
            fils: 8,
            memoire: Some((16 << 30, 9 << 30)),
            disque: Some(3.0),
            place: Some((200 << 30, 500 << 30)),
            demarrage: Ok(Demarrage {
                total: 20.0,
                ..Demarrage::default()
            }),
            allume_depuis: Some(3600),
            ..Instantane::default()
        };
        assert!(conseils(&i).is_empty());
        assert_eq!(secondes_lisibles(75.4), "1 min 15 s");
        assert_eq!(secondes_lisibles(5.04), "5,0 s");
    }
}
