//! Scan YARA de la mémoire des processus en marche : les 308 règles de `yara` appliquées aux régions privées ou
//! exécutables de chaque programme, là où vit un logiciel malveillant « sans fichier » (chargeur réfléchi, shellcode,
//! programme effacé du disque mais encore en marche, exécutable déballé que son emballage cachait sur le disque).
//! Lecture seule, à la demande seulement, jamais en fond : aucun processus n'est touché. LSASS, les processus
//! protégés et les processus critiques ne sont jamais ouverts (lire LSASS est le geste d'un voleur de mots de passe,
//! que Defender bloque), et rien de ce qui est lu n'est gardé nulle part : seulement la règle, le PID, le programme
//! et l'adresse. Ce qui n'a pas pu être lu est dit, jamais compté comme sain. Sur macOS, la mémoire d'autrui demande
//! des droits spéciaux (task_for_pid) : non vérifié, dit tel quel.

use std::time::{Duration, Instant};

use crate::protection::yara;
use crate::ui::*;

/// Une région plus grosse n'est pas lue (tas de navigateurs et de jeux) : les charges malveillantes sont petites, et
/// la région est comptée comme non lue.
const TAILLE_REGION_MAX: u64 = 64 << 20;
/// Lu au plus par processus, puis en tout ; au-delà, on s'arrête et on dit ce qui manque.
const PAR_PROCESSUS_MAX: u64 = 512 << 20;
const TOTAL_MAX: u64 = 4 << 30;
const DUREE_MAX: Duration = Duration::from_secs(300);
const DELAI_PAR_REGION: Duration = Duration::from_secs(10);

/// Jamais ouverts, même pour lire leur niveau de protection : LSASS et son isolat (les mots de passe), le noyau et
/// ses processus critiques (en tuer un arrête Windows ; les lire ne sert à rien). Seconde barrière derrière le niveau
/// de protection, lue sans ouvrir quoi que ce soit.
const CRITIQUES: &[&str] = &[
    "lsass",
    "lsaiso",
    "system",
    "secure system",
    "idle",
    "registry",
    "csrss",
    "smss",
    "wininit",
    "services",
    "memcompression",
    "memory compression",
];

/// Un processus en marche : son numéro et son nom, prêt à montrer.
struct Processus {
    pid: u32,
    nom: String,
}

/// Une région de mémoire : son adresse et sa taille.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Region {
    pub debut: u64,
    pub taille: u64,
}

/// Exclu avant tout : Vanguard lui-même (`moi`), Idle (0) et System (4) de Windows, et les processus critiques, quelle
/// que soit la casse du nom.
fn exclu(pid: u32, nom: &str, moi: u32) -> bool {
    pid == moi || pid == 0 || pid == 4 || CRITIQUES.iter().any(|c| nom.eq_ignore_ascii_case(c))
}

/// Une région de Windows à lire (VirtualQueryEx : état, protection, type) : validée (MEM_COMMIT), lisible (ni
/// PAGE_NOACCESS ni PAGE_GUARD, qui ferait une exception dans le programme lu), et privée (MEM_PRIVATE : tas, piles,
/// VirtualAlloc, là où un chargeur pose son code) ou mappée exécutable. Une image (MEM_IMAGE) est un fichier mappé,
/// déjà le domaine du scan de fichiers.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn region_windows(etat: u32, protection: u32, sorte: u32) -> bool {
    const MEM_COMMIT: u32 = 0x1000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD: u32 = 0x100;
    const EXECUTABLES: u32 = 0xF0;
    const MEM_PRIVATE: u32 = 0x2_0000;
    const MEM_MAPPED: u32 = 0x4_0000;
    let acces = protection & 0xFF;
    etat == MEM_COMMIT
        && acces != 0
        && acces != PAGE_NOACCESS
        && protection & PAGE_GUARD == 0
        && (sorte == MEM_PRIVATE || (sorte == MEM_MAPPED && protection & EXECUTABLES != 0))
}

/// Une ligne de /proc/<pid>/maps, retenue si la région est lisible et anonyme (tas, piles, VirtualAlloc de Linux :
/// mmap sans fichier) ou si son fichier a été effacé (« (deleted) », memfd : le programme qui tourne n'existe plus
/// sur le disque). Un fichier mappé encore présent est le domaine du scan de fichiers ; vdso, vvar et vsyscall sont au
/// noyau.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn region_linux(ligne: &str) -> Option<Region> {
    let mut champs = ligne.splitn(6, ' ');
    let (adresses, droits) = (champs.next()?, champs.next()?);
    let chemin = champs.nth(3).map(str::trim).unwrap_or_default();
    if !droits.starts_with('r') {
        return None;
    }
    let anonyme =
        chemin.is_empty() || chemin == "[heap]" || chemin.starts_with("[stack") || chemin.starts_with("[anon");
    let efface = chemin.ends_with(" (deleted)") || chemin.starts_with("/memfd:");
    if !(anonyme || efface) {
        return None;
    }
    let (debut, fin) = adresses.split_once('-')?;
    let (debut, fin) = (u64::from_str_radix(debut, 16).ok()?, u64::from_str_radix(fin, 16).ok()?);
    (fin > debut).then(|| Region {
        debut,
        taille: fin - debut,
    })
}

/// Ce que les bornes décident pour une région.
#[derive(Debug, PartialEq)]
enum Decision {
    Lire,
    /// Trop grosse : sautée, dite.
    Sauter,
    /// Ce processus a eu sa part : le reste de ses régions est sauté, dit.
    ProcessusPlein,
    /// Le temps ou le total est atteint : tout s'arrête, dit.
    Arret,
}

fn decider(taille: u64, lu_processus: u64, lu_total: u64, ecoule: Duration) -> Decision {
    if ecoule >= DUREE_MAX || lu_total >= TOTAL_MAX {
        Decision::Arret
    } else if taille > TAILLE_REGION_MAX {
        Decision::Sauter
    } else if lu_processus + taille > PAR_PROCESSUS_MAX {
        Decision::ProcessusPlein
    } else {
        Decision::Lire
    }
}

/// Ce qu'a donné la lecture d'un processus : les règles trouvées avec leur région, les octets lus, les régions
/// sautées ou illisibles, et si une borne générale a tout arrêté.
#[derive(Debug, Default, PartialEq)]
struct Lecture {
    trouves: Vec<(String, Region)>,
    octets: u64,
    sautees: usize,
    arret: bool,
}

/// Lit les régions par `lire` (dans un tampon réutilisé, remis à zéro à la fin : rien de la mémoire lue ne reste) et
/// leur applique les règles, dans les bornes. `lu_total` et `debut` : ce qui a déjà été lu dans les processus
/// d'avant, et le départ de l'analyse.
fn analyser_regions(
    analyseur: &mut yara_x::Scanner,
    regions: &[Region],
    mut lire: impl FnMut(&Region, &mut Vec<u8>) -> bool,
    lu_total: u64,
    debut: Instant,
) -> Lecture {
    let mut lecture = Lecture::default();
    let mut tampon = Vec::new();
    for (i, region) in regions.iter().enumerate() {
        match decider(
            region.taille,
            lecture.octets,
            lu_total + lecture.octets,
            debut.elapsed(),
        ) {
            Decision::Arret => {
                lecture.arret = true;
                lecture.sautees += regions.len() - i;
                break;
            }
            Decision::ProcessusPlein => {
                lecture.sautees += regions.len() - i;
                break;
            }
            Decision::Sauter => lecture.sautees += 1,
            Decision::Lire => {
                tampon.clear();
                if !lire(region, &mut tampon) {
                    lecture.sautees += 1;
                    continue;
                }
                lecture.octets += tampon.len() as u64;
                match analyseur.scan(&tampon) {
                    Ok(resultat) => lecture
                        .trouves
                        .extend(resultat.matching_rules().map(|m| (m.identifier().to_string(), *region))),
                    Err(_) => lecture.sautees += 1,
                }
            }
        }
    }
    tampon.fill(0);
    lecture
}

/// Comment un processus s'est ouvert.
enum Acces {
    /// Protégé par Windows (PPL) ou niveau illisible : exclu par choix, jamais lu.
    #[cfg_attr(not(windows), allow(dead_code))]
    Protege,
    /// Le système refuse (droits insuffisants) : non lu, dit.
    Refuse,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Ouvert(plateforme::Lecteur),
}

#[cfg(target_os = "linux")]
mod plateforme {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    use super::{Acces, Processus, Region, region_linux};

    /// Les processus de /proc, nom d'après `comm` (choisi par le programme : rendu inoffensif).
    pub(super) fn processus() -> Vec<Processus> {
        let Ok(entrees) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        entrees
            .flatten()
            .filter_map(|e| {
                let pid: u32 = e.file_name().to_str()?.parse().ok()?;
                let nom = std::fs::read_to_string(e.path().join("comm")).unwrap_or_default();
                Some(Processus {
                    pid,
                    nom: crate::ui::affichable(nom.trim()),
                })
            })
            .collect()
    }

    /// /proc/<pid>/maps pour les régions, /proc/<pid>/mem pour les lire : le noyau refuse l'ouverture de `mem` sans
    /// le droit de tracer le processus (autre compte, ou Yama ptrace_scope ≥ 1 hors de ses descendants).
    pub(super) fn ouvrir(pid: u32) -> Acces {
        let Ok(cartes) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
            return Acces::Refuse;
        };
        match File::open(format!("/proc/{pid}/mem")) {
            Ok(fichier) => Acces::Ouvert(Lecteur {
                fichier,
                regions: cartes.lines().filter_map(region_linux).collect(),
            }),
            Err(_) => Acces::Refuse,
        }
    }

    pub(super) struct Lecteur {
        fichier: File,
        regions: Vec<Region>,
    }

    impl Lecteur {
        pub(super) fn regions(&self) -> Vec<Region> {
            self.regions.clone()
        }

        /// Lit une région dans `tampon`, mis à sa taille ; `false` si rien n'a pu être lu (région disparue
        /// entre-temps). Une lecture partielle est gardée telle quelle : ce qui est lu est analysé.
        pub(super) fn lire(&self, region: &Region, tampon: &mut Vec<u8>) -> bool {
            let Ok(taille) = usize::try_from(region.taille) else {
                return false;
            };
            tampon.clear();
            tampon.resize(taille, 0);
            let mut fait = 0usize;
            while fait < taille {
                match self.fichier.read_at(&mut tampon[fait..], region.debut + fait as u64) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => fait += n,
                }
            }
            tampon.truncate(fait);
            fait > 0
        }
    }
}

#[cfg(windows)]
mod plateforme {
    use super::{Acces, Processus};
    use crate::machine::windows::memoire;

    pub(super) type Lecteur = memoire::Lecteur;

    /// Toolhelp32, sans rien ouvrir : les exclusions par nom se décident avant tout OpenProcess.
    pub(super) fn processus() -> Vec<Processus> {
        crate::machine::windows::processus::liste()
            .into_iter()
            .map(|p| Processus { pid: p.pid, nom: p.nom })
            .collect()
    }

    /// Le niveau de protection d'abord, avec les seuls droits « limités » ; PROCESS_VM_READ seulement ensuite, et
    /// seulement sans protection.
    pub(super) fn ouvrir(pid: u32) -> Acces {
        match memoire::protege(pid) {
            None => Acces::Refuse,
            Some(true) => Acces::Protege,
            Some(false) => Lecteur::ouvrir(pid).map_or(Acces::Refuse, Acces::Ouvert),
        }
    }
}

#[cfg(target_os = "macos")]
mod plateforme {
    use super::{Acces, Processus, Region};

    /// La liste par `ps`, pour dire combien de processus ne sont pas lus : task_for_pid demande root et un droit
    /// spécial que Vanguard n'a pas ; rien n'est lu, rien n'est conclu.
    pub(super) fn processus() -> Vec<Processus> {
        let mut ps = std::process::Command::new("ps");
        ps.args(["-axo", "pid=,comm="]);
        let Some(resultat) = crate::commande::lancer(&mut ps, 10) else {
            return Vec::new();
        };
        resultat
            .sortie
            .lines()
            .filter_map(|l| {
                let (pid, nom) = l.trim().split_once(' ')?;
                Some(Processus {
                    pid: pid.parse().ok()?,
                    nom: crate::ui::affichable(nom.trim()),
                })
            })
            .collect()
    }

    pub(super) fn ouvrir(_pid: u32) -> Acces {
        Acces::Refuse
    }

    /// Jamais construit ici (`Infallible`) : la forme attendue par le reste du module.
    #[allow(dead_code)]
    pub(super) struct Lecteur(std::convert::Infallible);

    impl Lecteur {
        pub(super) fn regions(&self) -> Vec<Region> {
            match self.0 {}
        }

        pub(super) fn lire(&self, _region: &Region, _tampon: &mut Vec<u8>) -> bool {
            match self.0 {}
        }
    }
}

/// Une correspondance : la règle, le processus, la région. Rien du contenu lu.
#[derive(Debug, PartialEq)]
struct Trouve {
    regle: String,
    pid: u32,
    programme: String,
    region: Region,
}

/// Le bilan de l'analyse : combien de processus lus, non lus (droits), exclus par choix, lus en partie, si une
/// borne a tout arrêté, et les correspondances.
#[derive(Debug, Default, PartialEq)]
struct Bilan {
    lus: usize,
    non_lus: usize,
    exclus: usize,
    incomplets: usize,
    arrete: bool,
    trouves: Vec<Trouve>,
}

#[derive(Debug, PartialEq)]
enum Verdict {
    Sain,
    /// Rien trouvé, mais tout n'a pas été lu : pas de ✔.
    Incomplet,
    Trouve,
}

/// Le jugement : sain seulement si tout ce qui devait être lu l'a été. Les exclus par choix ne rendent pas l'analyse
/// incomplète (ils sont dits à part), mais zéro processus lu, si.
fn verdict(bilan: &Bilan) -> Verdict {
    if !bilan.trouves.is_empty() {
        Verdict::Trouve
    } else if bilan.lus == 0 || bilan.non_lus > 0 || bilan.incomplets > 0 || bilan.arrete {
        Verdict::Incomplet
    } else {
        Verdict::Sain
    }
}

/// Tous les processus, un seul fil : la lecture de la mémoire d'autrui ne se parallélise pas (pression sur le
/// système, ordre lisible). Après un arrêt sur une borne, les processus restants sont comptés non lus.
fn parcourir(regles: &yara_x::Rules) -> Bilan {
    let moi = std::process::id();
    let debut = Instant::now();
    let mut analyseur = yara_x::Scanner::new(regles);
    analyseur.set_timeout(DELAI_PAR_REGION);
    let mut bilan = Bilan::default();
    let mut lu_total = 0u64;
    let liste = plateforme::processus();
    trp!(
        "  {} processus en marche ; lecture seule, au plus {} minutes…",
        "  {} running processes; read-only, at most {} minutes…",
        liste.len(),
        DUREE_MAX.as_secs() / 60
    );
    let mut restants = liste.iter();
    for p in restants.by_ref() {
        if exclu(p.pid, &p.nom, moi) {
            bilan.exclus += 1;
            continue;
        }
        match plateforme::ouvrir(p.pid) {
            Acces::Protege => bilan.exclus += 1,
            Acces::Refuse => bilan.non_lus += 1,
            Acces::Ouvert(lecteur) => {
                let regions = lecteur.regions();
                let lecture = analyser_regions(&mut analyseur, &regions, |r, t| lecteur.lire(r, t), lu_total, debut);
                lu_total += lecture.octets;
                bilan.lus += 1;
                if lecture.sautees > 0 {
                    bilan.incomplets += 1;
                }
                bilan
                    .trouves
                    .extend(lecture.trouves.into_iter().map(|(regle, region)| Trouve {
                        regle,
                        pid: p.pid,
                        programme: p.nom.clone(),
                        region,
                    }));
                if lecture.arret {
                    bilan.arrete = true;
                    break;
                }
            }
        }
    }
    bilan.non_lus += restants.count();
    bilan
}

fn avertir(texte: &str) {
    for (i, ligne) in envelopper(texte, LARGEUR - 4).iter().enumerate() {
        println!("  {} {ligne}", if i == 0 { "⚠" } else { " " });
    }
}

fn afficher(bilan: &Bilan) {
    println!();
    if bilan.exclus > 0 {
        println!(
            "  {GRIS}{}{RESET}",
            trf!(
                "{} processus jamais ouverts, par choix : LSASS, les processus protégés et critiques, Vanguard lui-même.",
                "{} processes never opened, by design: LSASS, protected and critical processes, Vanguard itself.",
                bilan.exclus
            )
        );
    }
    if bilan.non_lus > 0 {
        avertir(&trf!(
            "{} processus n'ont pas pu être lus (droits insuffisants : relance en administrateur ou root) : rien n'est conclu pour eux.",
            "{} processes could not be read (insufficient rights: run again as administrator or root): nothing is concluded for them.",
            bilan.non_lus
        ));
    }
    if bilan.incomplets > 0 {
        avertir(&trf!(
            "{} processus lus en partie : régions de plus de {} Mio, au-delà de {} Mio par processus, ou disparues entre-temps.",
            "{} processes partly read: regions over {} MiB, beyond {} MiB per process, or gone in the meantime.",
            bilan.incomplets,
            TAILLE_REGION_MAX >> 20,
            PAR_PROCESSUS_MAX >> 20
        ));
    }
    if bilan.arrete {
        avertir(&trf!(
            "Arrêt sur une borne ({} minutes ou {} Gio lus) : le reste n'a pas été lu.",
            "Stopped at a limit ({} minutes or {} GiB read): the rest was not read.",
            DUREE_MAX.as_secs() / 60,
            TOTAL_MAX >> 30
        ));
    }
    match verdict(bilan) {
        Verdict::Sain => trp!(
            "  {VERT}✔{RESET} Aucune région de la mémoire des {} processus lus ne correspond aux 308 règles.",
            "  {VERT}✔{RESET} No memory region of the {} processes read matches the 308 rules.",
            bilan.lus
        ),
        Verdict::Incomplet => trp!(
            "  Rien trouvé dans les {} processus lus ; analyse incomplète, voir plus haut.",
            "  Nothing found in the {} processes read; incomplete scan, see above.",
            bilan.lus
        ),
        Verdict::Trouve => {
            for t in &bilan.trouves {
                println!(
                    "  {}✖{RESET} {} (PID {}) : {} ({})",
                    couleur(crate::risk::Niveau::Eleve),
                    t.programme,
                    t.pid,
                    yara::famille(&t.regle),
                    t.regle
                );
                println!(
                    "      {GRIS}{}{RESET}",
                    trf!(
                        "région 0x{:x}, {} Kio",
                        "region 0x{:x}, {} KiB",
                        t.region.debut,
                        t.region.taille >> 10
                    )
                );
            }
            println!();
            for ligne in envelopper(
                tr!(
                    "Rien n'a été arrêté : c'est une alerte, à juger. Un programme légitime peut porter une signature en mémoire (antivirus, outils de sécurité, navigateur ouvert sur une page qui parle de ces menaces). Note le programme et son PID ; en cas de doute, coupe Internet, puis collecte les traces (Suis-je infecté ?).",
                    "Nothing was stopped: this is an alert, for you to judge. A legitimate program can carry a signature in memory (antivirus, security tools, a browser open on a page about these threats). Note the program and its PID; when in doubt, cut the Internet, then collect the traces (Am I infected?)."
                ),
                LARGEUR - 2,
            ) {
                println!("  {ligne}");
            }
        }
    }
}

/// Menu Antivirus et protection › Mémoire des processus, et `vanguard memoire`.
pub fn analyser() {
    titre(tr!("Mémoire des processus", "Process memory"));
    for ligne in envelopper(
        tr!(
            "Lecture seule de la mémoire des programmes en marche, à la recherche des 308 règles YARA : un logiciel malveillant sans fichier ne vit que là. LSASS, les processus protégés et critiques ne sont jamais ouverts ; rien de ce qui est lu n'est gardé.",
            "Read-only pass over the memory of running programs, looking for the 308 YARA rules: fileless malware lives nowhere else. LSASS, protected and critical processes are never opened; nothing read is kept."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    if cfg!(target_os = "macos") {
        avertir(tr!(
            "Sur macOS, la mémoire d'un autre processus ne se lit pas sans un droit spécial (task_for_pid) : non vérifié, rien n'est conclu.",
            "On macOS, another process's memory cannot be read without a special right (task_for_pid): not verified, nothing is concluded."
        ));
    }
    let regles = match yara::regles() {
        Ok(r) => r,
        Err(e) => {
            println!(
                "  ✖ {}",
                trf!(
                    "Règles YARA impossibles à compiler : {e}",
                    "YARA rules could not be compiled: {e}"
                )
            );
            return;
        }
    };
    afficher(&parcourir(regles));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusions() {
        let moi = std::process::id();
        assert!(exclu(moi, "vanguard", moi));
        assert!(exclu(0, "Idle", moi));
        assert!(exclu(4, "System", moi));
        assert!(exclu(700, "LSASS", moi));
        assert!(exclu(701, "lsass", moi));
        assert!(exclu(702, "Secure System", moi));
        assert!(exclu(703, "MemCompression", moi));
        assert!(exclu(704, "services", moi));
        assert!(!exclu(705, "firefox", moi));
        assert!(!exclu(706, "services-web", moi));
    }

    #[test]
    fn regions_de_windows() {
        const COMMIT: u32 = 0x1000;
        const PRIVEE: u32 = 0x2_0000;
        const MAPPEE: u32 = 0x4_0000;
        const IMAGE: u32 = 0x100_0000;
        // Tas en lecture-écriture, pile, et surtout une page RWX privée : un chargeur.
        assert!(region_windows(COMMIT, 0x04, PRIVEE));
        assert!(region_windows(COMMIT, 0x40, PRIVEE));
        // Mappée exécutable : lue ; mappée en lecture seule (fichier de données) : non.
        assert!(region_windows(COMMIT, 0x20, MAPPEE));
        assert!(!region_windows(COMMIT, 0x02, MAPPEE));
        // Une image mappée (DLL, programme) est le domaine du scan de fichiers, même exécutable.
        assert!(!region_windows(COMMIT, 0x20, IMAGE));
        // Réservée, libre, sans accès, page de garde (lire ferait une exception dans le programme lu) : non.
        assert!(!region_windows(0x2000, 0x04, PRIVEE));
        assert!(!region_windows(0x10000, 0x04, PRIVEE));
        assert!(!region_windows(COMMIT, 0x01, PRIVEE));
        assert!(!region_windows(COMMIT, 0x04 | 0x100, PRIVEE));
        assert!(!region_windows(COMMIT, 0, PRIVEE));
    }

    #[test]
    fn regions_de_linux() {
        let heap = region_linux("55d4c0a00000-55d4c0a21000 rw-p 00000000 00:00 0                          [heap]");
        assert_eq!(
            heap,
            Some(Region {
                debut: 0x55d4_c0a0_0000,
                taille: 0x21000
            })
        );
        assert!(region_linux("7f3a00000000-7f3a00021000 rw-p 00000000 00:00 0 ").is_some());
        assert!(
            region_linux("7f3a00000000-7f3a00021000 rwxp 00000000 00:00 0                          [stack]").is_some()
        );
        assert!(
            region_linux("7f3a00000000-7f3a00021000 rw-p 00000000 00:00 0                          [anon:scudo]")
                .is_some()
        );
        // Un programme effacé qui tourne encore, un memfd : exactement ce qu'on cherche.
        assert!(region_linux("5600000000-5600021000 r-xp 00000000 103:02 1234      /tmp/.x/agent (deleted)").is_some());
        assert!(region_linux("7f3a00000000-7f3a00021000 r-xp 00000000 00:05 77   /memfd:a (deleted)").is_some());
        // Un fichier mappé encore présent (scan de fichiers), le noyau, une région illisible : non.
        assert!(region_linux("7f3a00000000-7f3a00021000 r-xp 00000000 103:02 1234      /usr/lib/libc.so.6").is_none());
        assert!(
            region_linux("7fff00000000-7fff00002000 r-xp 00000000 00:00 0                          [vdso]").is_none()
        );
        assert!(
            region_linux("7fff00000000-7fff00002000 r--p 00000000 00:00 0                          [vvar]").is_none()
        );
        assert!(region_linux("7f3a00000000-7f3a00021000 ---p 00000000 00:00 0 ").is_none());
        assert!(region_linux("7f3a00021000-7f3a00000000 rw-p 00000000 00:00 0 ").is_none());
        assert!(region_linux("").is_none());
    }

    #[test]
    fn bornes() {
        let rien = Duration::ZERO;
        assert_eq!(decider(4096, 0, 0, rien), Decision::Lire);
        assert_eq!(decider(TAILLE_REGION_MAX, 0, 0, rien), Decision::Lire);
        assert_eq!(decider(TAILLE_REGION_MAX + 1, 0, 0, rien), Decision::Sauter);
        assert_eq!(
            decider(4096, PAR_PROCESSUS_MAX - 4095, 0, rien),
            Decision::ProcessusPlein
        );
        assert_eq!(decider(4096, 0, TOTAL_MAX, rien), Decision::Arret);
        assert_eq!(decider(4096, 0, 0, DUREE_MAX), Decision::Arret);
        // Les bornes à l'œuvre : une région trop grosse sautée, puis la part du processus atteinte (le reste sauté
        // sans être lu) ; et un arrêt général, sans rien lire.
        let mut regions = vec![Region {
            debut: 0,
            taille: TAILLE_REGION_MAX + 1,
        }];
        regions.extend((0..9).map(|i| Region {
            debut: i * TAILLE_REGION_MAX,
            taille: TAILLE_REGION_MAX,
        }));
        let mut compilateur = yara_x::Compiler::new();
        compilateur.add_source("rule Rien { condition: false }").unwrap();
        let vides = compilateur.build();
        let mut analyseur = yara_x::Scanner::new(&vides);
        let remplir = |r: &Region, t: &mut Vec<u8>| {
            t.resize(usize::try_from(r.taille).unwrap(), 0);
            true
        };
        let lecture = analyser_regions(&mut analyseur, &regions, remplir, 0, Instant::now());
        assert_eq!(
            lecture,
            Lecture {
                trouves: vec![],
                octets: PAR_PROCESSUS_MAX,
                sautees: 2,
                arret: false
            }
        );
        let lecture = analyser_regions(&mut analyseur, &regions, |_, _| panic!(), TOTAL_MAX, Instant::now());
        assert!(lecture.arret && lecture.sautees == 10);
        // Une région illisible est sautée, dite ; une lue sans correspondance compte ses octets.
        let petites = [Region { debut: 0, taille: 8 }, Region { debut: 8, taille: 8 }];
        let mut tour = 0;
        let lecture = analyser_regions(
            &mut analyseur,
            &petites,
            |_, t| {
                tour += 1;
                t.extend_from_slice(b"12345678");
                tour > 1
            },
            0,
            Instant::now(),
        );
        assert_eq!(
            lecture,
            Lecture {
                trouves: vec![],
                octets: 8,
                sautees: 1,
                arret: false
            }
        );
    }

    #[test]
    fn verdicts() {
        let mut bilan = Bilan {
            lus: 3,
            ..Bilan::default()
        };
        assert_eq!(verdict(&bilan), Verdict::Sain);
        bilan.exclus = 5;
        assert_eq!(verdict(&bilan), Verdict::Sain);
        bilan.non_lus = 1;
        assert_eq!(verdict(&bilan), Verdict::Incomplet);
        bilan.non_lus = 0;
        bilan.incomplets = 1;
        assert_eq!(verdict(&bilan), Verdict::Incomplet);
        bilan.incomplets = 0;
        bilan.arrete = true;
        assert_eq!(verdict(&bilan), Verdict::Incomplet);
        bilan.arrete = false;
        bilan.lus = 0;
        assert_eq!(verdict(&bilan), Verdict::Incomplet);
        bilan.trouves.push(Trouve {
            regle: "X".into(),
            pid: 1,
            programme: "a".into(),
            region: Region::default(),
        });
        assert_eq!(verdict(&bilan), Verdict::Trouve);
    }

    /// La mémoire de CE processus de test, et de lui seul, lue comme celle d'un autre (/proc/self/mem ; sous Windows,
    /// OpenProcess sur son propre numéro, sans passer par le niveau de protection, que Wine ne dit pas) : une règle
    /// d'essai retrouve une chaîne construite à l'exécution et posée sur le tas, dans la région qui la contient.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn sa_propre_memoire() {
        let marque = std::hint::black_box(["vanguard", "essai", "memoire", "7f3a9c"].join("-"));
        let mut compilateur = yara_x::Compiler::new();
        compilateur
            .add_source(format!(r#"rule Essai_Memoire {{ strings: $a = "{marque}" condition: $a }}"#).as_str())
            .unwrap();
        let essai = compilateur.build();
        let mut analyseur = yara_x::Scanner::new(&essai);
        let moi = std::process::id();
        #[cfg(target_os = "linux")]
        let Acces::Ouvert(lecteur) = plateforme::ouvrir(moi) else {
            panic!("/proc/self/mem doit s'ouvrir");
        };
        #[cfg(windows)]
        let lecteur = plateforme::Lecteur::ouvrir(moi).expect("son propre processus doit s'ouvrir");
        let regions = lecteur.regions();
        assert_ne!(regions.len(), 0);
        let lecture = analyser_regions(&mut analyseur, &regions, |r, t| lecteur.lire(r, t), 0, Instant::now());
        assert!(lecture.octets > 0 && !lecture.arret, "{lecture:?}");
        let adresse = marque.as_ptr() as u64;
        assert!(
            lecture
                .trouves
                .iter()
                .any(|(regle, r)| regle == "Essai_Memoire" && r.debut <= adresse && adresse < r.debut + r.taille),
            "{:?} ; marque à {adresse:#x}",
            lecture.trouves
        );
        // Ce processus est exclu du parcours général : Vanguard ne se lit pas lui-même.
        assert!(exclu(moi, "vanguard", moi));
    }
}
