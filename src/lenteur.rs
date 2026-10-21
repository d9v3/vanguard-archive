//! « Pourquoi c'est lent ? » : un instantané en deux mesures, à deux secondes d'écart. Ce qui occupe le processeur,
//! la mémoire et le disque, programme par programme ; le démarrage (sa durée, ce qui le retarde) ; les programmes
//! lancés à l'ouverture de session et leur poids. La mesure est en lecture seule : les conseils disent quel outil de
//! Vanguard règle quoi (Nettoyer, Optimiser, Mises à jour, programmes au démarrage à retirer ou remettre, après accord
//! et de façon annulable), et l'écran les ouvre.

use std::collections::HashMap;

use crate::risk::Niveau;
use crate::ui::*;

/// Un programme (tous ses processus réunis : Firefox en compte une dizaine), tel que le script de Windows le donne.
#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default)]
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

/// Les processus d'un même programme réunis, triés plus tard selon ce qu'on regarde. Par ici passent les programmes
/// des trois systèmes : chacun choisit son nom, rendu prêt à montrer (`affichable`).
fn reunir(processus: impl Iterator<Item = Programme>) -> Vec<Programme> {
    let mut par_nom: HashMap<String, Programme> = HashMap::new();
    for p in processus {
        let e = par_nom.entry(affichable(&p.nom)).or_default();
        e.processeur += p.processeur;
        e.memoire += p.memoire;
        e.disque = p.disque.map(|d| e.disque.unwrap_or(0.0) + d).or(e.disque);
    }
    par_nom.into_iter().map(|(nom, p)| Programme { nom, ..p }).collect()
}

/// Les programmes au démarrage, (nom, programme lancé), avec la mémoire qu'occupe ce programme en ce moment. Le nom,
/// écrit par qui a posé l'entrée, est rendu prêt à montrer.
fn avec_poids(programmes: &[Programme], liste: impl Iterator<Item = (String, String)>) -> Vec<AuDemarrage> {
    let mut par_nom: HashMap<String, u64> = HashMap::new();
    for p in programmes {
        *par_nom.entry(p.nom.to_lowercase()).or_default() += p.memoire;
    }
    let poids = |programme: &str| par_nom.get(&affichable(programme).to_lowercase()).copied();
    liste
        .map(|(nom, p)| AuDemarrage {
            poids: poids(&p),
            nom: affichable(&nom),
        })
        .collect()
}

/// « 1min 2.105s », « 835ms », « 1.186s », « 2h 3min » (durées de systemd) → secondes.
fn secondes_systemd(texte: &str) -> Option<f64> {
    let mut total = None;
    for morceau in texte.split_whitespace() {
        let morceau = morceau.trim_start_matches('+');
        let (nombre, unite) = morceau.split_at(morceau.find(|c: char| c.is_ascii_alphabetic())?);
        let n: f64 = nombre.parse().ok()?;
        let facteur = match unite {
            "h" => 3600.0,
            "min" => 60.0,
            "s" => 1.0,
            "ms" => 0.001,
            "us" | "µs" => 0.000_001,
            _ => return None,
        };
        total = Some(total.unwrap_or(0.0) + n * facteur);
    }
    total
}

/// `systemd-analyze` : « Startup finished in 11.846s (firmware) + 8.083s (loader) + 15.167s (kernel) + 5.575s
/// (userspace) = 40.673s » → (total, étapes).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn duree_systemd(texte: &str) -> Option<(f64, String)> {
    let ligne = texte.lines().find_map(|l| l.strip_prefix("Startup finished in "))?;
    let (etapes, total) = ligne.rsplit_once(" = ")?;
    let total = secondes_systemd(total.trim())?;
    let etape = |e: &str| {
        let (duree, nom) = e.trim().split_once(" (")?;
        let nom = match nom.trim_end_matches(')') {
            "firmware" => tr!("micrologiciel", "firmware"),
            "loader" => tr!("chargeur", "loader"),
            "kernel" => tr!("noyau", "kernel"),
            "initrd" => "initrd",
            "userspace" => tr!("système", "userspace"),
            _ => return None,
        };
        Some(format!("{nom} {}", secondes_lisibles(secondes_systemd(duree)?)))
    };
    let etapes: Vec<String> = etapes.split(" + ").filter_map(etape).collect();
    Some((total, etapes.join(" · ")))
}

/// `systemd-analyze critical-chain` : les unités du chemin critique et le temps que chacune a pris à démarrer
/// (« +1.186s »), les plus longues d'abord. `blame` mélangerait ce qui tourne après le démarrage (mise à jour de la
/// base de locate, par exemple) avec ce qui le retarde vraiment. Le nom d'une unité de l'utilisateur est le sien :
/// lu prêt à montrer.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn chaine_critique(texte: &str) -> Vec<(String, f64)> {
    let unite = |l: &str| {
        let (nom, reste) = l.trim_start_matches(|c: char| !c.is_alphanumeric()).split_once(' ')?;
        Some((affichable(nom), secondes_systemd(reste.split_once('+')?.1)?))
    };
    let mut lents: Vec<(String, f64)> = texte.lines().filter_map(unite).filter(|(_, s)| *s >= 0.5).collect();
    lents.sort_by(|a, b| b.1.total_cmp(&a.1));
    lents.truncate(5);
    lents
}

/// « 12,3 s », « 1 min 05 s ».
fn secondes_lisibles(s: f64) -> String {
    if s >= 60.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let s = s.round() as u64;
        return format!("{} min {:02} s", s / 60, s % 60);
    }
    format!("{} s", crate::langue::decimal(s, 1))
}

/// Un service de l'utilisateur lancé à l'ouverture de session : voulu par default.target (ou la session graphique). Un
/// service activé pour autre chose (au branchement d'une clé, par une minuterie, un chemin surveillé) ne l'est pas.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lance_a_l_ouverture(unite: &str) -> bool {
    let mut dans_install = false;
    unite.lines().map(str::trim).any(|l| {
        if l.starts_with('[') {
            dans_install = l == "[Install]";
            return false;
        }
        dans_install
            && l.split_once('=').is_some_and(|(cle, cibles)| {
                matches!(cle.trim(), "WantedBy" | "RequiredBy")
                    && cibles
                        .split_whitespace()
                        .any(|c| matches!(c, "default.target" | "graphical-session.target"))
            })
    })
}

/// Une entrée de démarrage automatique (fichier .desktop d'autostart) : (nom affiché, programme) si elle est active
/// pour ce bureau. `Hidden=true` ou `X-GNOME-Autostart-enabled=false` : désactivée ; `OnlyShowIn`/`NotShowIn` :
/// selon le bureau.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn entree_autostart(texte: &str, bureau: &str) -> Option<(String, String)> {
    let mut dans_entree = false;
    let mut champs: HashMap<&str, &str> = HashMap::new();
    for l in texte.lines().map(str::trim) {
        if l.starts_with('[') {
            dans_entree = l == "[Desktop Entry]";
        } else if dans_entree && let Some((cle, valeur)) = l.split_once('=') {
            champs.entry(cle.trim()).or_insert(valeur.trim());
        }
    }
    let vaut = |cle: &str, v: &str| champs.get(cle).is_some_and(|x| x.eq_ignore_ascii_case(v));
    // Les bureaux d'une liste (« GNOME;Unity; »), sans les vides : un nom vide de la session ne peut rien y trouver.
    let liste = |cle: &str| -> Vec<String> {
        let v = champs.get(cle).copied().unwrap_or_default().split(';');
        v.map(|b| b.trim().to_lowercase()).filter(|b| !b.is_empty()).collect()
    };
    let bureaux: Vec<String> = bureau.split(':').map(str::to_lowercase).collect();
    let ici = |l: Vec<String>| l.iter().any(|b| bureaux.contains(b));
    let seulement = liste("OnlyShowIn");
    if vaut("Hidden", "true")
        || vaut("X-GNOME-Autostart-enabled", "false")
        || (!seulement.is_empty() && !ici(seulement))
        || ici(liste("NotShowIn"))
    {
        return None;
    }
    // « env VAR=1 programme --option %u » → « programme ».
    let programme = champs
        .get("Exec")?
        .split_whitespace()
        .find(|m| *m != "env" && !m.contains('=') && !m.starts_with('-'))?
        .trim_matches('"');
    let programme = programme.rsplit('/').next().unwrap_or(programme).to_string();
    let nom = champs.get("Name").map_or(programme.clone(), ToString::to_string);
    Some((nom, programme))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outil {
    Nettoyer,
    Demarrage,
    Performance,
    MisesAJour,
}

/// Les conseils d'un instantané : (niveau d'alerte, texte, outil à proposer).
pub struct Conseil {
    pub grave: bool,
    pub texte: String,
    pub outil: Option<Outil>,
}

/// Programmes qui travaillent fort pendant un moment, puis se calment seuls : les nommer évite d'accuser l'ordinateur.
/// Une ligne par raison : débuts de leurs noms | en français | en anglais.
const PASSAGERS: &str = "\
msmpeng mpdefendercoreservice | l'antivirus de Windows analyse les fichiers | Windows' antivirus is scanning files
tiworker trustedinstaller | Windows installe des mises à jour | Windows is installing updates
searchindexer | Windows indexe les fichiers pour la recherche | Windows is indexing files for search
mdworker mds_stores | macOS indexe les fichiers pour Spotlight | macOS is indexing files for Spotlight
localsearch tracker-miner | le bureau indexe les fichiers pour la recherche | the desktop is indexing files for search
baloo_file | KDE indexe les fichiers pour la recherche | KDE is indexing files for search
packagekitd | les mises à jour se téléchargent | updates are downloading
plocate updatedb | la base de recherche des fichiers se refait | the file search database is being rebuilt";

fn passager(nom: &str) -> Option<&'static str> {
    let n = nom.to_lowercase();
    PASSAGERS.lines().find_map(|l| {
        let mut champs = l.split(" | ");
        let (cles, fr, en) = (champs.next()?, champs.next()?, champs.next()?);
        let trouve = cles.split_whitespace().any(|c| n.starts_with(c));
        trouve.then_some(if crate::langue::anglais() { en } else { fr })
    })
}

#[allow(clippy::cast_precision_loss)]
fn pourcent(n: u64, sur: u64) -> f64 {
    if sur == 0 { 0.0 } else { n as f64 * 100.0 / sur as f64 }
}

/// Ce qu'on peut conclure de l'instantané, le plus grave d'abord.
#[allow(clippy::cast_precision_loss)]
pub fn conseils(i: &Instantane) -> Vec<Conseil> {
    let mut c = Vec::new();
    let mut pousser = |grave, texte, outil| c.push(Conseil { grave, texte, outil });
    let plus = |cle: fn(&Programme) -> f64| {
        i.programmes
            .iter()
            .max_by(|a, b| cle(a).total_cmp(&cle(b)))
            .filter(|p| cle(p) > 0.0)
    };
    if let Some(occupe) = i.processeur.filter(|&o| o >= 80.0) {
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
        pousser(true, texte, None);
    }
    if let Some((total, dispo)) = i.memoire.filter(|&(t, d)| pourcent(d, t) < 10.0) {
        let texte = match plus(|p| p.memoire as f64) {
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
        };
        pousser(true, texte, Some(Outil::Demarrage));
    }
    if let Some(occupe) = i.disque.filter(|&o| o >= 80.0) {
        let texte = match plus(|p| p.disque.unwrap_or(0.0)) {
            Some(p) => trf!(
                "Disque occupé {occupe:.0} % du temps, surtout par {} ({}/s){}.",
                "Disk busy {occupe:.0}% of the time, mostly by {} ({}/s){}.",
                p.nom,
                taille(debit(p)),
                passager(&p.nom).map(|r| format!(" : {r}")).unwrap_or_default()
            ),
            None => trf!(
                "Disque occupé {occupe:.0} % du temps : tout ce qui le lit ou l'écrit attend son tour.",
                "Disk busy {occupe:.0}% of the time: everything that reads or writes it waits its turn."
            ),
        };
        pousser(true, texte, None);
    }
    if let Some((libre, total)) = i.place.filter(|&(l, t)| pourcent(l, t) < 10.0) {
        let texte = trf!(
            "Disque du système presque plein ({} libres sur {}) : le système a besoin de place pour travailler.",
            "System disk almost full ({} free out of {}): the system needs room to work.",
            taille(libre),
            taille(total)
        );
        pousser(true, texte, Some(Outil::Nettoyer));
    }
    if let Some(d) = i.demarrage.as_ref().ok().filter(|d| d.total >= 60.0) {
        let lents = retards(&d.lents[..d.lents.len().min(3)]);
        let texte = if lents.is_empty() {
            trf!("Démarrage long ({}).", "Slow startup ({}).", secondes_lisibles(d.total))
        } else {
            trf!(
                "Démarrage long ({}) ; ce qui le retarde le plus : {lents}.",
                "Slow startup ({}); what delays it most: {lents}.",
                secondes_lisibles(d.total)
            )
        };
        pousser(false, texte, Some(Outil::Performance));
    }
    if i.au_demarrage.len() >= 8 || i.au_demarrage.iter().filter_map(|p| p.poids).sum::<u64>() >= 1 << 30 {
        let texte = trf!(
            "{} programmes se lancent à l'ouverture de session : ceux dont tu n'as pas besoin tout de suite peuvent attendre que tu les ouvres.",
            "{} programs start when you log in: those you do not need right away can wait until you open them.",
            i.au_demarrage.len()
        );
        pousser(false, texte, Some(Outil::Demarrage));
    }
    // Windows surtout : des semaines sans redémarrer, et des mises à jour attendent, des fuites de mémoire s'accumulent.
    if i.allume_depuis.is_some_and(|s| s >= 14 * 86_400) {
        let texte = trf!(
            "Allumé depuis {} jours sans redémarrer : redémarrer libère la mémoire et termine les mises à jour en attente.",
            "On for {} days without a restart: restarting frees memory and finishes pending updates.",
            i.allume_depuis.unwrap_or(0) / 86_400
        );
        pousser(false, texte, Some(Outil::MisesAJour));
    }
    c
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn debit(p: &Programme) -> u64 {
    p.disque.unwrap_or(0.0).max(0.0) as u64
}

fn taille(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let f = octets as f64;
    if octets >= 1 << 30 {
        trf!("{} Go", "{} GB", crate::langue::decimal(f / f64::from(1u32 << 30), 1))
    } else if octets >= 1 << 20 {
        trf!("{:.0} Mo", "{:.0} MB", f / f64::from(1u32 << 20))
    } else {
        trf!("{:.0} ko", "{:.0} kB", f / 1024.0)
    }
}

/// « docker.service 4,5 s, … » : ce qui a retardé le démarrage.
fn retards(lents: &[(String, f64)]) -> String {
    let texte = |(n, s): &(String, f64)| format!("{n} {}", secondes_lisibles(*s));
    lents.iter().map(texte).collect::<Vec<_>>().join(", ")
}

/// Une barre de 10 cases (le `clamp` en garde 10 au plus), colorée selon la charge.
fn jauge(pct: f64) -> String {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let pleines = ((pct.clamp(0.0, 100.0) + 5.0) / 10.0) as usize;
    let c = match pct {
        p if p >= 80.0 => couleur(Niveau::Eleve),
        p if p >= 50.0 => couleur(Niveau::Moyen),
        _ => VERT,
    };
    format!("{c}{}{GRIS}{}{RESET}", "▰".repeat(pleines), "▱".repeat(10 - pleines))
}

fn ligne_mesure(libelle: &str, valeur: &str) {
    afficher_aligne(&format!("  {GRAS}{}{RESET} ", ajuster(libelle, 13)), valeur, 16, "");
}

/// Une mesure de « ce qui pèse le plus » : libellé, seuil, valeur d'un programme, et cette valeur en texte.
type Mesure = (&'static str, f64, fn(&Programme) -> f64, fn(&Programme) -> String);

#[allow(clippy::cast_precision_loss)]
fn afficher(i: &Instantane) {
    let processeur = tr!("Processeur", "Processor");
    let memoire = tr!("Mémoire", "Memory");
    let disque = tr!("Disque", "Disk");
    section(tr!("EN CE MOMENT", "RIGHT NOW"));
    let texte = match i.processeur {
        Some(p) => trf!("{} {p:.0} % ({} fils)", "{} {p:.0}% ({} threads)", jauge(p), i.fils),
        None => tr!("non mesuré", "not measured").into(),
    };
    ligne_mesure(processeur, &texte);
    if let Some((total, dispo)) = i.memoire {
        let utilise = pourcent(total.saturating_sub(dispo), total);
        let echange = match i.echange {
            Some((t, u)) if t > 0 && u >= 1 << 20 => trf!(", échange {} utilisés", ", swap {} used", taille(u)),
            _ => String::new(),
        };
        let texte = trf!(
            "{} {utilise:.0} % ({} libres sur {}){echange}",
            "{} {utilise:.0}% ({} free out of {}){echange}",
            jauge(utilise),
            taille(dispo),
            taille(total)
        );
        ligne_mesure(memoire, &texte);
    }
    let texte = match i.disque {
        Some(d) => trf!("{} occupé {d:.0} % du temps", "{} busy {d:.0}% of the time", jauge(d)),
        None => tr!("activité non mesurable ici", "activity not measurable here").into(),
    };
    ligne_mesure(disque, &texte);
    if let Some((libre, total)) = i.place {
        let texte = trf!(
            "{} libres sur {} (disque du système)",
            "{} free out of {} (system disk)",
            taille(libre),
            taille(total)
        );
        ligne_mesure(tr!("Place", "Space"), &texte);
    }

    section(tr!("CE QUI PÈSE LE PLUS", "WHAT WEIGHS THE MOST"));
    let rien = tr!("rien de notable", "nothing notable");
    // Les trois plus gros, au-dessus d'un seuil : un programme à « 0 % » n'est pas un suspect.
    #[rustfmt::skip] // une ligne par mesure, que rustfmt étalerait sur six
    let mesures: [Mesure; 3] = [
        (processeur, 1.0, |p| p.processeur, |p| trf!("{:.0} %", "{:.0}%", p.processeur)),
        (memoire, 100.0 * 1_048_576.0, |p| p.memoire as f64, |p| taille(p.memoire)),
        (disque, 1_048_576.0, |p| p.disque.unwrap_or(0.0), |p| format!("{}/s", taille(debit(p)))),
    ];
    for (libelle, seuil, cle, texte) in mesures {
        let mut tries: Vec<&Programme> = i.programmes.iter().filter(|p| cle(p) >= seuil).collect();
        tries.sort_by(|a, b| cle(b).total_cmp(&cle(a)));
        tries.truncate(3);
        let liste: Vec<String> = tries.iter().map(|p| format!("{} {}", p.nom, texte(p))).collect();
        let liste = liste.join(", ");
        ligne_mesure(libelle, if liste.is_empty() { rien } else { &liste });
    }

    section(tr!("DÉMARRAGE", "STARTUP"));
    let duree = tr!("Durée", "Duration");
    match &i.demarrage {
        Ok(d) => {
            let mut texte = secondes_lisibles(d.total);
            if !d.etapes.is_empty() {
                texte = format!("{texte} ({})", d.etapes);
            }
            ligne_mesure(duree, &texte);
            if !d.lents.is_empty() {
                ligne_mesure(tr!("Retardé par", "Delayed by"), &retards(&d.lents));
            }
        }
        Err(raison) => ligne_mesure(duree, &format!("{GRIS}{raison}{RESET}")),
    }
    if let Some(s) = i.allume_depuis {
        let (j, h) = (s / 86_400, s % 86_400 / 3600);
        let texte = if j > 0 {
            trf!("{j} j {h} h", "{j} d {h} h")
        } else {
            trf!("{h} h {:02}", "{h} h {:02}", s % 3600 / 60)
        };
        ligne_mesure(tr!("Allumé depuis", "On for"), &texte);
    }
    let a_l_ouverture = tr!("À l'ouverture", "At login");
    if i.au_demarrage.is_empty() {
        ligne_mesure(a_l_ouverture, tr!("aucun programme trouvé", "no program found"));
        return;
    }
    let mut liste: Vec<&AuDemarrage> = i.au_demarrage.iter().collect();
    liste.sort_by(|a, b| b.poids.cmp(&a.poids).then_with(|| a.nom.cmp(&b.nom)));
    let avec_taille = |p: &&AuDemarrage| match p.poids {
        Some(o) => format!("{} ({})", p.nom, taille(o)),
        None => p.nom.clone(),
    };
    let noms: Vec<String> = liste.iter().take(8).map(avec_taille).collect();
    let mut texte = noms.join(", ");
    let reste = liste.len().saturating_sub(8);
    if reste > 0 {
        texte += &trf!(" et {reste} autre(s)", " and {reste} more");
    }
    let texte = trf!("{} programme(s) : {texte}", "{} program(s): {texte}", liste.len());
    ligne_mesure(a_l_ouverture, &texte);
}

/// L'écran : l'en-tête, la mesure de deux secondes, puis ce qu'elle veut dire. Rend les conseils.
/// « Rien ne force » se conclut seulement sur une mesure : sans processeur ni mémoire mesurés, ce n'est pas sain,
/// c'est non vérifié.
fn mesure_complete(i: &Instantane) -> bool {
    i.processeur.is_some() && i.memoire.is_some()
}

fn mesurer() -> Vec<Conseil> {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("POURQUOI C'EST LENT ?", "WHY IS IT SLOW?")),
        &format!("{GRIS}{}{RESET}", tr!("lecture seule", "read only")),
    );
    trp!(
        "  {DISCRET}Mesure pendant deux secondes : continue à utiliser l'ordinateur comme d'habitude…{RESET}",
        "  {DISCRET}Measuring for two seconds: keep using the computer as usual…{RESET}"
    );
    let i = systeme::instantane();
    afficher(&i);
    let c = conseils(&i);
    section(tr!("CE QUE ÇA VEUT DIRE", "WHAT IT MEANS"));
    if c.is_empty() && !mesure_complete(&i) {
        let rien = tr!(
            "Mesure incomplète (processeur ou mémoire non mesurés) : rien n'est conclu, non vérifié.",
            "Incomplete measurement (processor or memory not measured): nothing concluded, not verified."
        );
        afficher_aligne(&format!("  {}⚠{RESET} ", couleur(Niveau::Moyen)), rien, 4, "");
    } else if c.is_empty() {
        let rien = tr!(
            "Rien ne force en ce moment : si c'est lent par moments, relance la mesure à ce moment-là.",
            "Nothing is straining right now: if it is slow at times, run the measurement again at that moment."
        );
        afficher_aligne(&format!("  {VERT}✔{RESET} "), rien, 4, "");
    }
    let attention = format!("  {}⚠{RESET} ", couleur(Niveau::Moyen));
    for k in &c {
        let conseil = format!("  {} ", ampoule());
        afficher_aligne(if k.grave { &attention } else { &conseil }, &k.texte, 5, "");
    }
    c
}

/// « vanguard lenteur » : l'instantané et ses conseils.
pub fn commande() {
    mesurer();
}

/// L'outil au menu : l'instantané, ses conseils, puis l'outil qui règle ce qui a été trouvé.
pub fn menu() {
    loop {
        let c = mesurer();
        // Les choix s'écrivent sous la mesure, qui reste à l'écran (un menu au clavier redessinerait tout l'écran).
        section(tr!("ET MAINTENANT", "WHAT NEXT"));
        // Les outils des conseils, puis ceux toujours sous la main, même quand rien ne force.
        let proposes = c.iter().filter_map(|k| k.outil);
        let mut outils: Vec<Outil> = Vec::new();
        for o in proposes.chain([Outil::Demarrage, Outil::Nettoyer]) {
            if !outils.contains(&o) {
                outils.push(o);
            }
        }
        for (n, outil) in (1..).zip(&outils) {
            #[rustfmt::skip] // deux lignes par outil, que rustfmt étalerait sur quatre
            let (texte, precision) = match outil {
                Outil::Nettoyer => (tr!("Nettoyer le système", "Clean up the system"),
                    tr!("caches, temporaires, corbeille…", "caches, temp files, trash…")),
                Outil::Demarrage => (tr!("Programmes au démarrage", "Startup programs"),
                    tr!("les retirer ou les remettre", "remove or put back")),
                Outil::Performance => (tr!("Réglages de performance", "Performance settings"),
                    tr!("Optimiser, tout s'annule", "Optimize, all undoable")),
                Outil::MisesAJour => (tr!("Mises à jour", "Updates"),
                    tr!("système, programmes, pilotes", "system, programs, drivers")),
            };
            let texte = ajuster(texte, 34);
            println!("   {TOUCHE}{n}{RESET}  {texte}{DISCRET}{precision}{RESET}");
        }
        println!("   {TOUCHE}m{RESET}  {}", tr!("Mesurer de nouveau", "Measure again"));
        println!("   {TOUCHE}↵{RESET}  {}", tr!("Revenir", "Back"));
        let choix = demander(tr!(
            "\n  Choix (Entrée pour revenir) : ",
            "\n  Choice (Enter to go back): "
        ));
        let choix = choix.to_lowercase();
        if choix == "m" {
            continue;
        }
        if let Some(n) = (1..=outils.len()).find(|n| n.to_string() == choix) {
            println!();
            match outils[n - 1] {
                Outil::Nettoyer => crate::nettoyer::menu(),
                Outil::Demarrage => crate::optimiser::programmes_au_demarrage(),
                #[cfg(not(target_os = "macos"))]
                Outil::Performance => crate::optimiser::menu(crate::optimiser::Categorie::Performance),
                #[cfg(target_os = "macos")]
                Outil::Performance => {}
                Outil::MisesAJour => crate::maj::executer(),
            }
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
    let fichier = exe.and_then(|e| e.rsplit('/').next());
    match fichier.map(|e| e.trim_end_matches(" (deleted)")) {
        Some(e) if !e.is_empty() && !MOTEURS.iter().any(|m| e.starts_with(m)) => e.to_string(),
        _ => comm.split('/').next().unwrap_or(comm).trim().to_string(),
    }
}

/// /proc/<pid>/stat : (temps processeur en tops d'horloge, mémoire résidente en pages). Le nom (2e champ) peut
/// contenir des espaces et des parenthèses : on repart de la dernière « ) ».
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stat_processus(texte: &str) -> Option<(u64, u64)> {
    let champs: Vec<&str> = texte.get(texte.rfind(')')? + 1..)?.split_whitespace().collect();
    // Après le nom : état (3e champ), …, utime (14e), stime (15e), …, rss (24e).
    let nombre = |i: usize| champs.get(i)?.parse::<u64>().ok();
    let (utime, stime, rss) = (nombre(11)?, nombre(12)?, nombre(21)?);
    Some((utime + stime, rss))
}

/// Première ligne de /proc/stat : (occupé, total) en tops d'horloge, toute la machine.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stat_processeur(texte: &str) -> Option<(u64, u64)> {
    let ligne = texte.strip_prefix("cpu ")?.lines().next()?;
    let valeurs: Vec<u64> = ligne.split_whitespace().filter_map(|v| v.parse().ok()).collect();
    // user nice system idle iowait irq softirq steal (guest est déjà compté dans user).
    let total: u64 = valeurs.iter().take(8).sum();
    let repos = valeurs.get(3)? + valeurs.get(4).copied().unwrap_or(0);
    Some((total.saturating_sub(repos), total))
}

/// /proc/diskstats : temps passé à servir des entrées-sorties (ms), par disque.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn occupation_disques(texte: &str, disques: &[String]) -> HashMap<String, u64> {
    let disque = |l: &str| {
        let c: Vec<&str> = l.split_whitespace().collect();
        let nom = (*c.get(2)?).to_string();
        disques.contains(&nom).then_some((nom, c.get(12)?.parse().ok()?))
    };
    texte.lines().filter_map(disque).collect()
}

#[cfg(target_os = "linux")]
mod systeme {
    use std::fs::{read_dir, read_link, read_to_string};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::commande::lancer;

    /// Durée entre les deux mesures : assez pour lisser un pic, assez courte pour qu'on attende sans s'impatienter.
    /// (Windows et macOS mesurent eux-mêmes sur deux secondes : PowerShell, top.)
    const ECART: Duration = Duration::from_secs(2);

    struct Echantillon {
        quand: Instant,
        processeur: Option<(u64, u64)>,
        /// pid → (nom, temps processeur, mémoire en pages, octets lus et écrits)
        processus: HashMap<u32, (String, u64, u64, Option<u64>)>,
        disques: HashMap<String, u64>,
    }

    fn getconf(variable: &str, defaut: u64) -> u64 {
        let r = lancer(Command::new("getconf").arg(variable), 5);
        r.and_then(|r| r.sortie.trim().parse().ok()).unwrap_or(defaut)
    }

    /// La sortie d'une commande qui a réussi (« systemd-analyze critical-chain --no-pager »).
    fn sortie(commande: &str) -> Option<String> {
        let mut mots = commande.split(' ');
        let r = lancer(Command::new(mots.next()?).args(mots), 20)?;
        (r.code == Some(0)).then_some(r.sortie)
    }

    /// Les disques entiers (pas les partitions), sans les disques virtuels.
    fn disques() -> Vec<String> {
        const VIRTUELS: [&str; 6] = ["loop", "ram", "zram", "dm-", "sr", "fd"];
        read_dir("/sys/block")
            .into_iter()
            .flatten()
            .flatten()
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .filter(|n| !VIRTUELS.iter().any(|p| n.starts_with(p)))
            .collect()
    }

    fn echantillon(disques: &[String]) -> Echantillon {
        let processus = read_dir("/proc")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let pid = e.file_name().to_string_lossy().into_owned();
                let n = pid.parse::<u32>().ok()?;
                let (temps, pages) = stat_processus(&read_to_string(format!("/proc/{pid}/stat")).ok()?)?;
                let comm = read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                let exe = read_link(format!("/proc/{pid}/exe")).ok();
                let nom = nom_de_processus(exe.as_deref().and_then(Path::to_str), comm.trim());
                // Octets lus et écrits : illisibles pour les programmes d'un autre compte.
                let io = read_to_string(format!("/proc/{pid}/io")).unwrap_or_default();
                let lire = |cle: &str| io.lines().find_map(|l| l.strip_prefix(cle)?.trim().parse::<u64>().ok());
                let es = lire("read_bytes:").zip(lire("write_bytes:")).map(|(l, e)| l + e);
                Some((n, (nom, temps, pages, es)))
            })
            .collect();
        Echantillon {
            quand: Instant::now(),
            processeur: read_to_string("/proc/stat").ok().and_then(|t| stat_processeur(&t)),
            processus,
            disques: occupation_disques(&read_to_string("/proc/diskstats").unwrap_or_default(), disques),
        }
    }

    fn demarrage() -> Result<Demarrage, String> {
        let absent = tr!(
            "durée illisible (systemd-analyze absent, ou démarrage pas encore fini)",
            "duration not readable (no systemd-analyze, or startup not finished yet)"
        );
        let temps = sortie("systemd-analyze").ok_or(absent)?;
        let (total, etapes) =
            duree_systemd(&temps).ok_or_else(|| tr!("durée illisible", "duration not readable").to_string())?;
        let lents = chaine_critique(&sortie("systemd-analyze critical-chain --no-pager").unwrap_or_default());
        Ok(Demarrage { total, etapes, lents })
    }

    /// Les programmes lancés à l'ouverture de session, (nom, programme) : entrées d'autostart actives (celles de
    /// l'utilisateur remplacent celles du système au même nom) et services ajoutés par l'utilisateur
    /// (~/.config/systemd/user).
    fn au_demarrage() -> Vec<(String, String)> {
        let maison = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
        let systeme = std::env::var("XDG_CONFIG_DIRS").unwrap_or_default();
        let systeme = if systeme.is_empty() { "/etc/xdg" } else { &systeme };
        let bureau = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        let mut liste = Vec::new();
        // L'utilisateur d'abord : son entrée l'emporte sur celle du système au même nom, même désactivée.
        let mut vus: Vec<String> = Vec::new();
        for f in std::iter::once(config.join("autostart"))
            .chain(systeme.split(':').map(|d| Path::new(d).join("autostart")))
            .flat_map(|d| read_dir(d).into_iter().flatten().flatten())
        {
            let nom = f.file_name().to_string_lossy().into_owned();
            if Path::new(&nom).extension().is_some_and(|e| e == "desktop") && !vus.contains(&nom) {
                liste.extend(entree_autostart(&read_to_string(f.path()).unwrap_or_default(), &bureau));
                vus.push(nom);
            }
        }
        let services = config.join("systemd/user");
        let actives = sortie("systemctl --user list-unit-files --type=service --state=enabled --no-legend --no-pager")
            .unwrap_or_default();
        for unite in actives.lines().filter_map(|l| l.split_whitespace().next()) {
            let fichier = services.join(unite);
            if fichier.is_file() && lance_a_l_ouverture(&read_to_string(&fichier).unwrap_or_default()) {
                let nom = unite.trim_end_matches(".service").to_string();
                liste.push((nom.clone(), nom));
            }
        }
        liste
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn instantane() -> Instantane {
        let disques = disques();
        let horloge = getconf("CLK_TCK", 100).max(1);
        let page = getconf("PAGESIZE", 4096);
        let fils = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let a = echantillon(&disques);
        std::thread::sleep(ECART);
        let b = echantillon(&disques);
        let ecart_s = b.quand.duration_since(a.quand).as_secs_f64().max(0.001);
        let releves = a.processeur.zip(b.processeur).filter(|((_, ta), (_, tb))| tb > ta);
        let processeur = releves.map(|((oa, ta), (ob, tb))| ob.saturating_sub(oa) as f64 * 100.0 / (tb - ta) as f64);
        let programmes = reunir(b.processus.iter().map(|(pid, (nom, temps, pages, es))| {
            let avant = a.processus.get(pid);
            let tops = avant.map_or(0, |(_, t, ..)| temps.saturating_sub(*t));
            Programme {
                nom: nom.clone(),
                // Tops d'horloge → secondes de processeur, rapportées au temps écoulé et à tous les fils.
                processeur: tops as f64 / horloge as f64 / ecart_s / fils as f64 * 100.0,
                memoire: pages * page,
                disque: avant
                    .and_then(|(.., e)| *e)
                    .zip(*es)
                    .map(|(x, y)| y.saturating_sub(x) as f64 / ecart_s),
            }
        }));
        let disque = b
            .disques
            .iter()
            .filter_map(|(nom, ms)| Some(ms.saturating_sub(*a.disques.get(nom)?) as f64 / (ecart_s * 1000.0) * 100.0))
            .reduce(f64::max)
            .map(|d| d.min(100.0));
        let meminfo = read_to_string("/proc/meminfo").unwrap_or_default();
        let lire = |cle: &str| {
            meminfo
                .lines()
                .find_map(|l| l.strip_prefix(cle)?.split_whitespace().next()?.parse::<u64>().ok())
                .map(|ko| ko * 1024)
        };
        Instantane {
            processeur,
            fils,
            memoire: lire("MemTotal:").zip(lire("MemAvailable:")),
            echange: lire("SwapTotal:")
                .zip(lire("SwapFree:"))
                .map(|(t, l)| (t, t.saturating_sub(l))),
            disque,
            au_demarrage: avec_poids(&programmes, au_demarrage().into_iter()),
            programmes,
            demarrage: demarrage(),
            allume_depuis: read_to_string("/proc/uptime")
                .ok()
                .and_then(|t| t.split('.').next()?.parse().ok()),
            place: crate::nettoyer::volume(Path::new("/")),
        }
    }
}

// ───────────────────────────── Windows ─────────────────────────────

/// Ce que lit le script PowerShell, en JSON.
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
    programmes: Vec<Programme>,
    demarrage_ms: Option<u64>,
    apres_ms: Option<u64>,
    demarrage_illisible: bool,
    lents: Vec<LentWindows>,
    au_demarrage: Vec<DemarrageWindows>,
    allume_s: Option<u64>,
    libre: u64,
    total: u64,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct LentWindows {
    nom: String,
    ms: u64,
}

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
        processeur: p.processeur.max(0.0),
        disque: p.disque.map(|d| d.max(0.0)),
        ..p
    }));
    let demarrage = match (l.demarrage_ms, l.demarrage_illisible) {
        (Some(ms), _) => {
            let mut lents: Vec<(String, f64)> = l
                .lents
                .into_iter()
                .filter(|x| !x.nom.trim().is_empty())
                .map(|x| (affichable(x.nom.trim()), x.ms as f64 / 1000.0))
                .collect();
            lents.sort_by(|a, b| b.1.total_cmp(&a.1));
            // Un même programme ralentit souvent plusieurs démarrages : une fois, avec son pire retard.
            let mut vus = std::collections::HashSet::new();
            lents.retain(|(nom, _)| vus.insert(nom.clone()));
            lents.truncate(5);
            let total = ms as f64 / 1000.0;
            let apres = l
                .apres_ms
                .filter(|&a| a > 0)
                .map(|a| secondes_lisibles(a as f64 / 1000.0));
            let etapes = apres
                .map(|a| trf!("dont {} après l'ouverture de session", "including {} after login", a))
                .unwrap_or_default();
            Ok(Demarrage { total, etapes, lents })
        }
        (None, true) => Err(tr!(
            "durée lisible seulement avec les droits d'administrateur",
            "duration readable only with administrator rights"
        )
        .into()),
        (None, false) => Err(tr!(
            "pas de mesure du dernier démarrage",
            "no measurement of the last startup"
        )
        .into()),
    };
    Instantane {
        processeur: l.processeur.map(|p| p.clamp(0.0, 100.0)),
        fils: l.fils.max(1),
        memoire: Some((l.memoire, l.disponible)).filter(|(t, _)| *t > 0),
        echange: Some((l.echange, l.echange_utilise)).filter(|(t, _)| *t > 0),
        disque: l.disque.map(|d| d.clamp(0.0, 100.0)),
        au_demarrage: avec_poids(&programmes, l.au_demarrage.into_iter().map(|d| (d.nom, d.programme))),
        programmes,
        demarrage,
        allume_depuis: l.allume_s,
        place: Some((l.libre, l.total)).filter(|(_, t)| *t > 0),
    }
}

#[cfg(windows)]
mod systeme {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    use super::{DemarrageWindows, Instantane, LectureWindows, LentWindows, Programme, instantane_windows};
    use crate::machine::windows::wmi::{self, Ligne};

    const CIMV2: &str = r"root\cimv2";
    const PERFORMANCES: &str = "Microsoft-Windows-Diagnostics-Performance/Operational";

    /// Une lecture des compteurs bruts : le processeur (temps de repos), chaque disque (temps de repos), chaque
    /// processus (temps de processeur, octets lus et écrits, mémoire). Les mêmes classes que le script PowerShell.
    struct Releve {
        processeur: Option<Ligne>,
        disques: Vec<Ligne>,
        processus: Vec<Ligne>,
        quand: Instant,
    }

    fn releve() -> Option<Releve> {
        let processeur = wmi::requete(
            CIMV2,
            "Win32_PerfRawData_PerfOS_Processor",
            "Name='_Total'",
            &["PercentProcessorTime", "Timestamp_Sys100NS"],
        )
        .and_then(|l| l.into_iter().next());
        let disques = wmi::requete(
            CIMV2,
            "Win32_PerfRawData_PerfDisk_PhysicalDisk",
            "Name <> '_Total'",
            &["Name", "PercentIdleTime", "Timestamp_Sys100NS"],
        )
        .unwrap_or_default();
        // Sans les compteurs des processus (compteurs de performance coupés), PowerShell prend tout le relais.
        let processus = wmi::requete(
            CIMV2,
            "Win32_PerfRawData_PerfProc_Process",
            "Name <> '_Total'",
            &[
                "IDProcess",
                "Name",
                "PercentProcessorTime",
                "IODataBytesPersec",
                "WorkingSet",
            ],
        )?;
        Some(Releve {
            processeur,
            disques,
            processus,
            quand: Instant::now(),
        })
    }

    #[allow(clippy::cast_precision_loss)]
    fn nombre(l: &Ligne, champ: &str) -> Option<f64> {
        l[champ].entier().map(|n| n as f64)
    }

    /// Part occupée entre deux lectures d'un compteur de repos : 100 × (1 − repos / temps écoulé).
    fn occupe(avant: &Ligne, apres: &Ligne, repos: &str) -> Option<f64> {
        let ecoule = nombre(apres, "Timestamp_Sys100NS")? - nombre(avant, "Timestamp_Sys100NS")?;
        let libre = nombre(apres, repos)? - nombre(avant, repos)?;
        (ecoule > 0.0).then(|| 100.0 * (1.0 - libre / ecoule))
    }

    /// Le nom d'un processus comme Get-Process le donne : les compteurs numérotent les homonymes (« chrome#3 »).
    pub(super) fn nom_du_processus(instance: &str) -> &str {
        match instance.rsplit_once('#') {
            Some((nom, n)) if !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) => nom,
            _ => instance,
        }
    }

    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    fn programmes(avant: &Releve, apres: &Releve, ms: f64, fils: usize) -> Vec<Programme> {
        let par_pid = |r: &Releve| -> HashMap<i64, Ligne> {
            r.processus
                .iter()
                .filter_map(|l| Some((l["IDProcess"].entier()?, l.clone())))
                .collect()
        };
        let debut = par_pid(avant);
        apres
            .processus
            .iter()
            .filter_map(|l| {
                let pid = l["IDProcess"].entier()?;
                let d = debut.get(&pid);
                // Temps de processeur en centaines de nanosecondes, comme TotalProcessorTime.Ticks.
                let cpu = d
                    .and_then(|d| Some(nombre(l, "PercentProcessorTime")? - nombre(d, "PercentProcessorTime")?))
                    .map_or(0.0, |t| t / 10_000.0 / ms / fils as f64 * 100.0);
                let disque = d.and_then(|d| {
                    Some((nombre(l, "IODataBytesPersec")? - nombre(d, "IODataBytesPersec")?) / (ms / 1000.0))
                });
                Some(Programme {
                    nom: nom_du_processus(l["Name"].texte().unwrap_or_default()).to_string(),
                    processeur: cpu,
                    memoire: l["WorkingSet"].entier().map_or(0, |m| m.max(0) as u64),
                    disque,
                })
            })
            .collect()
    }

    /// Durée du dernier démarrage (événement 100) et ce qui l'a ralenti depuis trente jours (101, 102, 103, 106),
    /// comme le script : (durée, après l'ouverture de session, illisible, lents). Le journal ne s'ouvre qu'aux
    /// administrateurs : refusé sans élévation, c'est « illisible ».
    fn demarrage() -> (Option<u64>, Option<u64>, bool, Vec<LentWindows>) {
        use crate::machine::windows::evenements::parcourir_nommes;
        let fin = Instant::now() + Duration::from_secs(30);
        let champ = |v: &[(String, String)], nom: &str| v.iter().find(|(n, _)| n == nom).map(|(_, x)| x.clone());
        let Some(dernier) = parcourir_nommes(PERFORMANCES, "*[System[(EventID=100)]]", 1, fin, |_, _, v| {
            Some(format!(
                "{}|{}",
                champ(v, "BootTime")?,
                champ(v, "BootPostBootTime").unwrap_or_default()
            ))
        }) else {
            return (None, None, !crate::machine::windows::processus::eleve(), Vec::new());
        };
        let Some((total, apres)) = dernier.first().and_then(|l| l.split_once('|')) else {
            return (None, None, false, Vec::new());
        };
        let lents = parcourir_nommes(
            PERFORMANCES,
            "*[System[(EventID=101 or EventID=102 or EventID=103 or EventID=106) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]",
            50,
            fin,
            |_, _, v| {
                let nom = champ(v, "FriendlyName").filter(|n| !n.is_empty()).or_else(|| champ(v, "Name"))?;
                Some(format!("{}|{nom}", champ(v, "DegradationTime")?))
            },
        )
        .unwrap_or_default()
        .iter()
        .filter_map(|l| {
            let (ms, nom) = l.split_once('|')?;
            Some(LentWindows { nom: nom.to_string(), ms: ms.parse().ok()? })
        })
        .collect();
        (total.parse().ok(), apres.parse().ok(), false, lents)
    }

    /// Ce que StartupApproved dit d'une entrée : coupée dans le Gestionnaire des tâches si le premier octet est
    /// impair ; sans valeur, lancée.
    fn approuve(hklm: bool, sous: &str, nom: &str) -> bool {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        let ruche = winreg::RegKey::predef(if hklm { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER });
        ruche
            .open_subkey(format!(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{sous}"
            ))
            .and_then(|k| k.get_raw_value(nom))
            .ok()
            .and_then(|v| v.bytes.first().copied())
            .is_none_or(|octet| octet & 1 == 0)
    }

    /// Les programmes lancés à l'ouverture de session (Win32_StartupCommand), sans ceux qu'on a coupés.
    fn au_demarrage() -> Vec<DemarrageWindows> {
        let lignes = wmi::requete(
            CIMV2,
            "Win32_StartupCommand",
            "",
            &["Caption", "Command", "Location", "Name"],
        )
        .unwrap_or_default();
        lignes
            .iter()
            .filter_map(|s| {
                let texte = |c: &str| s[c].texte().unwrap_or_default().to_string();
                let lieu = texte("Location").to_ascii_lowercase();
                let sous = if lieu.contains("startup") {
                    "StartupFolder"
                } else if lieu.contains("wow6432node") {
                    "Run32"
                } else {
                    "Run"
                };
                let commande = texte("Command");
                let cle = if sous == "StartupFolder" {
                    commande.rsplit(['\\', '/']).next().unwrap_or_default().to_string()
                } else {
                    texte("Name")
                };
                if !approuve(lieu.starts_with("hklm"), sous, &cle) {
                    return None;
                }
                let c = commande.trim();
                let programme = match c.strip_prefix('"') {
                    Some(reste) => reste.split('"').next().unwrap_or_default(),
                    None => c.split_whitespace().next().unwrap_or_default(),
                };
                let programme = std::path::Path::new(programme)
                    .file_stem()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                Some(DemarrageWindows {
                    nom: texte("Caption"),
                    programme,
                })
            })
            .collect()
    }

    /// Tout ce que lisait le script, sans PowerShell : WMI (compteurs bruts, système, fichier d'échange, programmes au
    /// démarrage), le journal des performances (wevtapi), le registre et le lecteur système. `None` sans les
    /// compteurs des processus, du processeur ou du système : PowerShell refait alors tout le relevé.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn lecture_directe() -> Option<LectureWindows> {
        let fils = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let avant = releve()?;
        std::thread::sleep(Duration::from_secs(2));
        let apres = releve()?;
        let ms = apres
            .quand
            .duration_since(avant.quand)
            .as_secs_f64()
            .mul_add(1000.0, 0.0)
            .max(1.0);
        let processeur = avant
            .processeur
            .as_ref()
            .zip(apres.processeur.as_ref())
            .and_then(|(a, b)| occupe(a, b, "PercentProcessorTime"))?;
        let disque = apres
            .disques
            .iter()
            .filter_map(|d| {
                let nom = d["Name"].texte()?;
                let a = avant.disques.iter().find(|x| x["Name"].texte() == Some(nom))?;
                occupe(a, d, "PercentIdleTime")
            })
            .reduce(f64::max);
        let os = wmi::requete(
            CIMV2,
            "Win32_OperatingSystem",
            "",
            &["TotalVisibleMemorySize", "LastBootUpTime"],
        )
        .and_then(|l| l.into_iter().next())?;
        let disponible = wmi::requete(CIMV2, "Win32_PerfRawData_PerfOS_Memory", "", &["AvailableBytes"])
            .and_then(|l| l.first().and_then(|m| m["AvailableBytes"].entier()));
        let echange =
            wmi::requete(CIMV2, "Win32_PageFileUsage", "", &["AllocatedBaseSize", "CurrentUsage"]).unwrap_or_default();
        let somme = |champ: &str| -> u64 {
            echange
                .iter()
                .filter_map(|l| l[champ].entier())
                .map(|n| n.max(0) as u64)
                .sum::<u64>()
                * 1_048_576
        };
        let (demarrage_ms, apres_ms, demarrage_illisible, lents) = demarrage();
        let systeme = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let lecteur = crate::machine::windows::lecteurs::lecteur(std::path::Path::new(&format!("{systeme}\\")));
        let os = Some(os);
        Some(LectureWindows {
            processeur: Some(processeur),
            fils,
            memoire: os
                .as_ref()
                .and_then(|o| o["TotalVisibleMemorySize"].entier())
                .map_or(0, |k| k.max(0) as u64 * 1024),
            disponible: disponible.map_or(0, |d| d.max(0) as u64),
            echange: somme("AllocatedBaseSize"),
            echange_utilise: somme("CurrentUsage"),
            disque,
            programmes: programmes(&avant, &apres, ms, fils),
            demarrage_ms,
            apres_ms,
            demarrage_illisible,
            lents,
            au_demarrage: au_demarrage(),
            allume_s: os.as_ref().and_then(|o| {
                o["LastBootUpTime"]
                    .texte()
                    .and_then(|d| wmi::secondes_depuis(d, chrono::Utc::now()))
            }),
            libre: lecteur.as_ref().map_or(0, |l| l.libre),
            total: lecteur.as_ref().map_or(0, |l| l.total),
        })
    }

    pub fn instantane() -> Instantane {
        if let Some(l) = lecture_directe() {
            return instantane_windows(l);
        }
        // Secours : le même relevé par PowerShell.
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn noms_et_dates() {
            assert_eq!(nom_du_processus("chrome#3"), "chrome");
            assert_eq!(nom_du_processus("chrome"), "chrome");
            assert_eq!(nom_du_processus("C#"), "C#");
            assert_eq!(nom_du_processus("a#b"), "a#b");
        }

        /// Le relevé direct répond ou laisse la main à PowerShell ; jamais une valeur hors bornes.
        #[test]
        fn releve_reel() {
            if let Some(l) = lecture_directe() {
                assert!(l.fils >= 1);
                assert!(l.processeur.is_none_or(f64::is_finite));
                assert!(
                    l.programmes
                        .iter()
                        .all(|p| p.processeur.is_finite() && !p.nom.contains('#'))
                );
            }
        }
    }
}

// ───────────────────────────── macOS ─────────────────────────────

/// « 1234M », « 12K », « 1.2G », « 512B » (colonne MEM de top, parfois suivie de « + » ou « - ») → octets.
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
#[allow(clippy::cast_precision_loss)]
fn lire_top(texte: &str, fils: usize) -> (Option<f64>, Vec<Programme>) {
    let derniere = texte.rsplit("Processes:").next().unwrap_or_default();
    let processeur = derniere.lines().find_map(|l| {
        let repos = l.strip_prefix("CPU usage:")?.split(',').find(|p| p.contains("idle"))?;
        Some(100.0 - repos.trim().split('%').next()?.trim().parse::<f64>().ok()?)
    });
    // Les lignes sous l'en-tête « PID COMMAND %CPU MEM », sans l'en-tête.
    let en_tete = |l: &&str| l.trim_start().starts_with("PID");
    let programmes = derniere
        .lines()
        .skip_while(|l| !en_tete(l))
        .filter(|l| !en_tete(l))
        .filter_map(|l| {
            let mots: Vec<&str> = l.split_whitespace().collect();
            let [_pid, nom @ .., cpu, mem] = mots.as_slice() else {
                return None;
            };
            let (Ok(cpu), Some(memoire)) = (cpu.parse::<f64>(), taille_top(mem)) else {
                return None;
            };
            Some(Programme {
                nom: nom.join(" "),
                // top compte 100 % par cœur : rapporté à toute la machine.
                processeur: cpu / fils.max(1) as f64,
                memoire,
                disque: None,
            })
        });
    (processeur, reunir(programmes))
}

#[cfg(target_os = "macos")]
mod systeme {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::commande::lancer;

    /// La sortie d'une commande qui a réussi (« sysctl -n hw.memsize »), vide sinon.
    fn sortie(commande: &str) -> String {
        let mut mots = commande.split(' ');
        lancer(Command::new(mots.next().unwrap_or_default()).args(mots), 30)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
            .unwrap_or_default()
    }

    pub fn instantane() -> Instantane {
        let fils = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let top = sortie("top -l 2 -s 2 -n 20 -o cpu -stats pid,command,cpu,mem");
        let (processeur, programmes) = lire_top(&top, fils);
        let total: Option<u64> = sortie("sysctl -n hw.memsize").trim().parse().ok();
        // « System-wide memory free percentage: 63% ».
        let libre_pct: Option<u64> = sortie("memory_pressure")
            .lines()
            .find_map(|l| l.strip_prefix("System-wide memory free percentage:"))
            .and_then(|v| v.trim().trim_end_matches('%').parse().ok());
        // « total = 2048.00M  used = 1024.50M  free = 1023.50M  (encrypted) ».
        let echange = sortie("sysctl -n vm.swapusage");
        let valeur = |cle: &str| {
            let mo = echange.split(cle).nth(1)?.split_whitespace().next()?;
            mo.trim_end_matches('M').parse::<f64>().ok()
        };
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let echange = valeur("total = ")
            .zip(valeur("used = "))
            .map(|(t, u)| ((t * 1_048_576.0) as u64, (u * 1_048_576.0) as u64));
        let maintenant = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let allume_depuis = sortie("sysctl -n kern.boottime")
            .split_once("sec = ")
            .and_then(|(_, r)| r.split(',').next()?.trim().parse::<u64>().ok())
            .and_then(|s| maintenant.checked_sub(s));
        let maison = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        // Agents lancés à l'ouverture de session par des programmes installés (pas ceux d'Apple).
        let dossiers = [maison, PathBuf::from("/")].map(|d| d.join("Library/LaunchAgents"));
        let au_demarrage = dossiers
            .iter()
            .flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
            .filter_map(|f| {
                let nom = affichable(f.file_name().to_string_lossy().strip_suffix(".plist")?);
                (!nom.starts_with("com.apple.")).then_some(AuDemarrage { nom, poids: None })
            })
            .collect();
        let donnees = Path::new("/System/Volumes/Data");
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
            place: crate::nettoyer::volume(if donnees.is_dir() { donnees } else { Path::new("/") }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seuls les services voulus par l'ouverture de session comptent ; un service déclenché au branchement d'une clé
    /// (WantedBy=…mount) ou par une minuterie, non.
    #[test]
    fn services_de_l_ouverture_de_session() {
        assert!(lance_a_l_ouverture(
            "[Unit]\nDescription=x\n[Service]\nExecStart=/usr/bin/x\n[Install]\nWantedBy=default.target\n"
        ));
        assert!(lance_a_l_ouverture(
            "[Install]\nWantedBy = graphical-session.target other.target\n"
        ));
        assert!(!lance_a_l_ouverture(
            "[Service]\nType=oneshot\n[Install]\nWantedBy=run-media-alice-VANGUARD.mount\n"
        ));
        assert!(!lance_a_l_ouverture("[Install]\nWantedBy=timers.target\n"));
        // Ailleurs que dans [Install], la même ligne ne compte pas.
        assert!(!lance_a_l_ouverture(
            "[Unit]\nWantedBy=default.target\n[Install]\nAlso=x.timer\n"
        ));
    }

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

    /// Un programme choisit son nom, un service ou une entrée de démarrage aussi : piégés, ils arrivent inoffensifs à
    /// l'écran et dans les conseils, sur les trois systèmes.
    #[test]
    fn noms_de_programmes_pieges() {
        let piege = "x\x1b]52;c;eA==\x07\x1b[2K\rfaux\u{202e}";
        let vu = "x�]52;c;eA==��[2K�faux�";
        let p = reunir(
            [Programme {
                nom: piege.into(),
                processeur: 90.0,
                memoire: 1 << 30,
                disque: None,
            }]
            .into_iter(),
        );
        assert_eq!(p[0].nom, vu);
        let chaine = format!("graphical.target @13.750s\n└─{piege}.service @9.1s +4.512s\n");
        assert_eq!(chaine_critique(&chaine)[0].0, format!("{vu}.service"));
        assert_eq!(
            avec_poids(&p, [(piege.to_string(), "x".to_string())].into_iter())[0].nom,
            vu
        );
        let l: LectureWindows = serde_json::from_str(
            r#"{"demarrage_ms":95000,"lents":[{"nom":"Lent\u001b[2K","ms":12000}],"programmes":[{"nom":"chrome\u001b]0;x\u0007","processeur":30,"memoire":1}]}"#,
        )
        .unwrap();
        let i = instantane_windows(l);
        assert_eq!(i.demarrage.as_ref().unwrap().lents[0].0, "Lent�[2K");
        assert_eq!(i.programmes[0].nom, "chrome�]0;x�");
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
            nom_de_processus(Some("/usr/bin/python3.13"), "vanguard-outil"),
            "vanguard-outil"
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
        assert!(mesure_complete(&i));
        // Rien de mesuré : aucun conseil, mais jamais « rien ne force ».
        let vide = Instantane::default();
        assert!(conseils(&vide).is_empty() && !mesure_complete(&vide));
        assert!(!mesure_complete(&Instantane {
            processeur: Some(5.0),
            ..Instantane::default()
        }));
        assert_eq!(secondes_lisibles(75.4), "1 min 15 s");
        assert_eq!(secondes_lisibles(5.04), "5,0 s");
    }
}
