//! Guide des commandes : les commandes utiles de Linux, de Windows, de macOS et celles qui s'écrivent pareil partout,
//! rangées par système puis par programme. Rien ne s'y lance : le guide montre et explique, on tape la commande
//! soi-même, ici ou chez la personne qu'on aide (au téléphone, sur un autre ordinateur). D'où tous les systèmes
//! partout : sous Linux, on peut lire les commandes de Windows.

mod linux;
mod macos;
mod tous;
mod windows;

use std::path::{Path, PathBuf};

use crate::risk::Niveau;
use crate::selection::{Ligne, choisir, correspond, simplifier};
use crate::ui::*;

/// Un système du guide.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Systeme {
    Linux,
    Windows,
    MacOs,
    /// Les commandes qui s'écrivent pareil sous les trois.
    Tous,
}

pub const SYSTEMES: [Systeme; 4] = [Systeme::Linux, Systeme::Windows, Systeme::MacOs, Systeme::Tous];

impl Systeme {
    /// Celui sur lequel tourne Gardien.
    fn actuel() -> Systeme {
        if cfg!(windows) {
            Systeme::Windows
        } else if cfg!(target_os = "macos") {
            Systeme::MacOs
        } else {
            Systeme::Linux
        }
    }

    fn nom(self) -> &'static str {
        match self {
            Systeme::Linux => "Linux",
            Systeme::Windows => "Windows",
            Systeme::MacOs => "macOS",
            Systeme::Tous => tr!("Tous les systèmes", "All systems"),
        }
    }

    /// Ce qui le désigne dans « gardien guide <système> », sans accents ni majuscules.
    fn mots(self) -> &'static [&'static str] {
        match self {
            Systeme::Linux => &["linux"],
            Systeme::Windows => &["windows", "win"],
            Systeme::MacOs => &["macos", "mac", "osx"],
            Systeme::Tous => &["tous", "all", "general"],
        }
    }

    fn programmes(self) -> &'static [Programme] {
        match self {
            Systeme::Linux => linux::PROGRAMMES,
            Systeme::Windows => windows::PROGRAMMES,
            Systeme::MacOs => macos::PROGRAMMES,
            Systeme::Tous => tous::PROGRAMMES,
        }
    }

    /// Où taper les commandes de ce système.
    fn terminal(self) -> &'static str {
        match self {
            Systeme::Linux => tr!(
                "Terminal : Ctrl+Alt+T sur la plupart des bureaux, Super+Entrée sous Omarchy.",
                "Terminal: Ctrl+Alt+T on most desktops, Super+Enter on Omarchy."
            ),
            Systeme::Windows => tr!(
                "Terminal : Windows+X, puis Terminal (Windows 11) ou Windows PowerShell (Windows 10) ; leur version « (admin) » pour les commandes marquées ⚠.",
                "Terminal: Windows+X, then Terminal (Windows 11) or Windows PowerShell (Windows 10); their “(Admin)” version for the commands marked ⚠."
            ),
            Systeme::MacOs => tr!(
                "Terminal : Cmd+Espace, taper « Terminal », puis Entrée.",
                "Terminal: Cmd+Space, type “Terminal”, then Enter."
            ),
            Systeme::Tous => tr!(
                "Dans tout terminal : Tab complète un nom, ↑ rappelle la commande d'avant, Ctrl-C arrête celle en cours.",
                "In any terminal: Tab completes a name, ↑ brings back the previous command, Ctrl-C stops the running one."
            ),
        }
    }

    /// Précision de sa ligne au menu (33 caractères au plus).
    fn apercu(self) -> &'static str {
        match self {
            Systeme::Linux => tr!("systemctl, journalctl, paquets…", "systemctl, journalctl, packages…"),
            Systeme::Windows => "winget, sfc, DISM, PowerShell…",
            Systeme::MacOs => "brew, diskutil, Time Machine…",
            Systeme::Tous => "Gardien, ping, ssh, git, curl…",
        }
    }
}

/// Un programme et ses commandes.
pub struct Programme {
    /// Tel qu'on le tape (« systemctl »), ou les programmes voisins réunis (« lsblk, df, du »).
    pub nom: &'static str,
    /// À quoi il sert, en français et en anglais : la précision de sa ligne au menu (33 caractères au plus).
    pub role: (&'static str, &'static str),
    /// Le fichier qui dit s'il est installé ici (nom cherché dans le PATH, ou chemin complet) ; vide : toujours là
    /// (commandes de PowerShell, Gardien lui-même).
    pub executable: &'static str,
    pub commandes: &'static [Commande],
}

pub struct Commande {
    /// Telle qu'on la tape ; « <…> » : à remplacer (traduit à l'affichage en anglais, voir `A_REMPLACER`).
    pub ligne: &'static str,
    /// Telle qu'on la tape en anglais quand elle change (sous-commandes de Gardien) ; vide sinon.
    pub ligne_en: &'static str,
    /// Ce qu'elle fait, en français et en anglais.
    pub texte: (&'static str, &'static str),
    /// Elle change quelque chose (réglage, fichier, paquet, service) : marquée ⚠.
    pub modifie: bool,
}

/// Une commande qui lit ou montre, sans rien changer.
pub const fn voir(ligne: &'static str, fr: &'static str, en: &'static str) -> Commande {
    Commande {
        ligne,
        ligne_en: "",
        texte: (fr, en),
        modifie: false,
    }
}

/// Une commande qui change quelque chose.
pub const fn changer(ligne: &'static str, fr: &'static str, en: &'static str) -> Commande {
    Commande {
        ligne,
        ligne_en: "",
        texte: (fr, en),
        modifie: true,
    }
}

/// Une commande qui ne s'écrit pas pareil en anglais (sous-commandes de Gardien).
pub const fn traduite(
    ligne: &'static str,
    ligne_en: &'static str,
    fr: &'static str,
    en: &'static str,
    modifie: bool,
) -> Commande {
    Commande {
        ligne,
        ligne_en,
        texte: (fr, en),
        modifie,
    }
}

/// Les mots à remplacer dans les commandes, et leur nom en anglais.
const A_REMPLACER: &[(&str, &str)] = &[
    ("<adresse>", "<address>"),
    ("<app>", "<app>"),
    ("<archive>", "<archive>"),
    ("<box>", "<router>"),
    ("<destination>", "<destination>"),
    ("<disque>", "<disk>"),
    ("<dossier>", "<folder>"),
    ("<fichier>", "<file>"),
    ("<id>", "<id>"),
    ("<ip>", "<ip>"),
    ("<mot>", "<word>"),
    ("<nom>", "<name>"),
    ("<numéro>", "<number>"),
    ("<paquet>", "<package>"),
    ("<partition>", "<partition>"),
    ("<PID>", "<PID>"),
    ("<port>", "<port>"),
    ("<programme>", "<program>"),
    ("<service>", "<service>"),
    ("<site>", "<site>"),
    ("<source>", "<source>"),
    ("<texte>", "<text>"),
    ("<utilisateur>", "<user>"),
    ("<étiquette>", "<label>"),
];

/// Les noms de programme qui se traduisent ; les autres sont des noms de commandes, les mêmes dans les deux langues.
const NOMS_EN: &[(&str, &str)] = &[
    ("PowerShell : réseau", "PowerShell: network"),
    ("PowerShell : Defender", "PowerShell: Defender"),
    ("PowerShell : services", "PowerShell: services"),
    ("PowerShell : disques", "PowerShell: disks"),
];

/// Ses noms dans les deux langues, pour la recherche.
fn noms_du_programme(p: &Programme) -> String {
    match NOMS_EN.iter().find(|(fr, _)| *fr == p.nom) {
        Some((fr, en)) => format!("{fr} {en}"),
        None => p.nom.to_string(),
    }
}

/// Le nom d'un programme dans la langue de l'interface.
fn nom(p: &Programme) -> &'static str {
    if !crate::langue::anglais() {
        return p.nom;
    }
    NOMS_EN.iter().find(|(fr, _)| *fr == p.nom).map_or(p.nom, |(_, en)| en)
}

fn dans_la_langue(t: (&'static str, &'static str)) -> &'static str {
    if crate::langue::anglais() { t.1 } else { t.0 }
}

/// La commande telle qu'elle s'affiche dans la langue de l'interface.
fn ligne(c: &Commande) -> String {
    if !crate::langue::anglais() {
        return c.ligne.to_string();
    }
    if !c.ligne_en.is_empty() {
        return c.ligne_en.to_string();
    }
    en_anglais(c.ligne)
}

fn en_anglais(ligne: &str) -> String {
    A_REMPLACER
        .iter()
        .fold(ligne.to_string(), |l, (fr, en)| l.replace(fr, en))
}

/// Le programme est-il installé ici ? Cherché dans le PATH, et dans les dossiers des outils d'administration que le
/// PATH d'un compte ordinaire omet parfois (Debian), ou de Homebrew (macOS).
fn installe(p: &Programme) -> bool {
    if p.executable.is_empty() {
        return true;
    }
    // Un lien vers un programme compte : les alias d'applications de Windows (winget) en sont, illisibles comme
    // fichiers ordinaires.
    let existe = |chemin: &Path| std::fs::symlink_metadata(chemin).is_ok_and(|m| !m.is_dir());
    if p.executable.starts_with('/') {
        return existe(Path::new(p.executable));
    }
    let mut dossiers: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|chemins| std::env::split_paths(&chemins).collect())
        .unwrap_or_default();
    if cfg!(unix) {
        dossiers.extend(
            [
                "/usr/sbin",
                "/sbin",
                "/usr/local/sbin",
                "/opt/homebrew/bin",
                "/usr/local/bin",
            ]
            .map(PathBuf::from),
        );
    }
    let noms: Vec<String> = if cfg!(windows) {
        [".exe", ".com", ".cmd", ".bat"]
            .iter()
            .map(|e| format!("{}{e}", p.executable))
            .collect()
    } else {
        vec![p.executable.to_string()]
    };
    dossiers.iter().any(|d| noms.iter().any(|n| existe(&d.join(n))))
}

/// Absent de cet ordinateur : seulement dit pour son propre système et pour les commandes de tous les systèmes (sur
/// Linux, on ne sait rien d'un Windows).
fn absent(s: Systeme, p: &Programme) -> bool {
    (s == Systeme::actuel() || s == Systeme::Tous) && !installe(p)
}

fn afficher_commande(c: &Commande) {
    let marque = if c.modifie {
        format!("{}⚠{RESET}", couleur(Niveau::Moyen))
    } else {
        " ".to_string()
    };
    println!("  {marque} {GRAS}{}{RESET}", ligne(c));
    for l in envelopper(dans_la_langue(c.texte), LARGEUR - 6) {
        println!("      {GRIS}{l}{RESET}");
    }
}

/// Un programme seul à l'écran, jusqu'à Entrée.
fn montrer_programme(s: Systeme, p: &Programme) {
    print!("\x1b[2J\x1b[H");
    afficher_programme(s, p);
    demander(&trf!(
        "\n{GRIS}Entrée pour revenir…{RESET}",
        "\n{GRIS}Enter to go back…{RESET}"
    ));
}

fn afficher_programme(s: Systeme, p: &Programme) {
    titre(&format!("{} › {}", s.nom(), nom(p)));
    let installe = if absent(s, p) {
        tr!(" (pas installé ici)", " (not installed here)")
    } else {
        ""
    };
    println!("  {GRIS}{}{installe}{RESET}\n", dans_la_langue(p.role));
    for c in p.commandes {
        afficher_commande(c);
    }
}

/// Ce que veulent dire ⚠ et « <…> », et où taper les commandes de ce système.
fn legende(s: Systeme) -> Vec<String> {
    let texte = format!(
        "{} {}",
        tr!(
            "⚠ : la commande change quelque chose (souvent avec les droits d'administrateur). <…> : à remplacer.",
            "⚠: the command changes something (often with administrator rights). <…>: to replace."
        ),
        s.terminal()
    );
    envelopper(&texte, LARGEUR - 2)
        .into_iter()
        .map(|l| format!("  {GRIS}{l}{RESET}"))
        .collect()
}

/// Les programmes d'un système, au menu : choisir, lire, revenir.
fn menu_systeme(s: Systeme) {
    let programmes = s.programmes();
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let mut lignes: Vec<Ligne> = lignes_cadre(
            &format!(
                "{ACCENT}GARDIEN{RESET} {GRIS}›{RESET} {} {GRIS}›{RESET} {}",
                tr!("Guide", "Guide"),
                s.nom()
            ),
            &trf!("{} programmes", "{} programs", programmes.len()),
        )
        .into_iter()
        .map(Ligne::Texte)
        .collect();
        lignes.extend(legende(s).into_iter().map(Ligne::Texte));
        lignes.push(Ligne::Texte(String::new()));
        for (i, p) in programmes.iter().enumerate() {
            let nom = if absent(s, p) {
                format!("{} {DISCRET}{}{RESET}", nom(p), tr!("(absent)", "(missing)"))
            } else {
                nom(p).to_string()
            };
            lignes.push(
                Ligne::choix(&(i + 1).to_string(), &nom, dans_la_langue(p.role)).avec_mots(&mots_du_programme(p)),
            );
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        lignes.push(Ligne::Texte(String::new()));
        let Some(choix) = choisir(
            &lignes,
            tr!(
                "  Numéro du programme (Entrée pour revenir) : ",
                "  Program number (Enter to go back): "
            ),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim();
        let Some(p) = choix
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| programmes.get(i))
        else {
            if choix.is_empty() || choix == "↵" || choix.eq_ignore_ascii_case("q") {
                return;
            }
            continue;
        };
        dernier = choix.to_string();
        montrer_programme(s, p);
    }
}

/// Une commande trouvée, avec son système et son programme.
type Trouvee = (Systeme, &'static Programme, &'static Commande);

/// Les commandes où paraissent tous les mots de `recherche` : dans la commande, son explication (en français comme en
/// anglais), le nom ou le rôle de son programme. Même règle que la recherche des menus (`selection::correspond`).
fn trouver(recherche: &str) -> Vec<Trouvee> {
    SYSTEMES
        .iter()
        .flat_map(|&s| {
            s.programmes()
                .iter()
                .flat_map(move |p| p.commandes.iter().map(move |c| (s, p, c)))
        })
        .filter(|(_, p, c)| {
            let texte = [
                c.ligne,
                c.ligne_en,
                &en_anglais(c.ligne),
                c.texte.0,
                c.texte.1,
                &noms_du_programme(p),
                p.role.0,
                p.role.1,
            ]
            .join(" ");
            correspond(recherche, &simplifier(&texte))
        })
        .collect()
}

/// Ce que la recherche des menus trouve dans un programme sans l'afficher : ses commandes et leurs explications, dans
/// les deux langues.
fn mots_du_programme(p: &Programme) -> String {
    std::iter::once(noms_du_programme(p))
        .chain(
            p.commandes
                .iter()
                .map(|c| format!("{} {} {} {}", c.ligne, c.ligne_en, c.texte.0, c.texte.1)),
        )
        .collect::<Vec<_>>()
        .join(" ")
}

/// Les pages du guide, pour la recherche d'un menu : chaque système (« <cle>.2 ») et chaque programme
/// (« <cle>.2.4 » : Windows, 4e programme), avec ses commandes comme mots à trouver. `cle` : la touche du guide dans
/// ce menu, vide dans le menu du guide lui-même (« 2.4 »).
pub fn lignes_de_recherche(cle: &str) -> Vec<Ligne> {
    let avant = if cle.is_empty() {
        String::new()
    } else {
        format!("{cle}.")
    };
    let guide = tr!("Guide", "Guide");
    let mut lignes = Vec::new();
    for (i, s) in SYSTEMES.iter().enumerate() {
        if !cle.is_empty() {
            lignes.push(Ligne::cachee(
                &format!("{avant}{}", i + 1),
                &format!("{guide} ›"),
                s.nom(),
                s.apercu(),
            ));
        }
        for (j, p) in s.programmes().iter().enumerate() {
            lignes.push(
                Ligne::cachee(
                    &format!("{avant}{}.{}", i + 1, j + 1),
                    &format!("{guide} › {} ›", s.nom()),
                    nom(p),
                    dans_la_langue(p.role),
                )
                .avec_mots(&mots_du_programme(p)),
            );
        }
    }
    lignes
}

/// Ouvre une page du guide trouvée par la recherche : un système (1 à 4), ou l'un de ses programmes.
pub fn ouvrir(systeme: usize, programme: Option<usize>) {
    let Some(&s) = systeme.checked_sub(1).and_then(|i| SYSTEMES.get(i)) else {
        return;
    };
    match programme
        .and_then(|p| p.checked_sub(1))
        .and_then(|p| s.programmes().get(p))
    {
        Some(p) => montrer_programme(s, p),
        None => menu_systeme(s),
    }
}

/// « 2.4 » → (2, Some(4)) ; « 2 » → (2, None) : un chemin dans le guide, tapé ou trouvé par la recherche.
pub fn chemin(texte: &str) -> Option<(usize, Option<usize>)> {
    let mut parties = texte.trim().split('.');
    let systeme = parties.next()?.parse().ok()?;
    let programme = match parties.next() {
        Some(p) => Some(p.parse().ok()?),
        None => None,
    };
    parties.next().is_none().then_some((systeme, programme))
}

fn afficher_resultats(recherche: &str, trouvees: &[Trouvee]) {
    if trouvees.is_empty() {
        afficher_aligne(
            "  ",
            &trf!(
                "Rien trouvé pour « {recherche} ». Essaie un autre mot : disque, wifi, dns, mise à jour…",
                "Nothing found for “{recherche}”. Try another word: disk, wifi, dns, update…"
            ),
            2,
            GRIS,
        );
        return;
    }
    trp!(
        "  {} commande(s) pour « {recherche} » :",
        "  {} command(s) for “{recherche}”:",
        trouvees.len()
    );
    let mut programme_en_cours: Option<(Systeme, &str)> = None;
    for &(s, p, c) in trouvees {
        if programme_en_cours != Some((s, p.nom)) {
            println!("\n  {ACCENT}{} › {}{RESET}", s.nom(), nom(p));
            programme_en_cours = Some((s, p.nom));
        }
        afficher_commande(c);
    }
}

/// Recherche au clavier, mot après mot, jusqu'à une réponse vide.
fn chercher() {
    loop {
        let recherche = demander(tr!(
            "\n  Mot à chercher (ex. disque, wifi, dns ; Entrée pour revenir) : ",
            "\n  Word to look for (e.g. disk, wifi, dns; Enter to go back): "
        ));
        if recherche.is_empty() {
            return;
        }
        afficher_resultats(&recherche, &trouver(&recherche));
    }
}

/// Le guide au menu : un système, ou la recherche.
pub fn menu() {
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let mut lignes: Vec<Ligne> = lignes_cadre(
            &format!(
                "{ACCENT}GARDIEN{RESET} {GRIS}›{RESET} {}",
                tr!("Guide des commandes", "Command guide")
            ),
            tr!("par système, puis par programme", "by system, then by program"),
        )
        .into_iter()
        .map(Ligne::Texte)
        .collect();
        let introduction = tr!(
            "Les commandes utiles de chaque système, expliquées. Rien ne se lance ici : tu lis, puis tu tapes la commande dans un terminal, ici ou chez la personne que tu aides.",
            "Each system's useful commands, explained. Nothing runs from here: you read, then type the command in a terminal, here or on the computer of the person you help."
        );
        lignes.extend(
            envelopper(introduction, LARGEUR - 2)
                .into_iter()
                .map(|l| Ligne::Texte(format!("  {GRIS}{l}{RESET}"))),
        );
        lignes.push(Ligne::Texte(String::new()));
        for (i, s) in SYSTEMES.iter().enumerate() {
            let nom = if *s == Systeme::actuel() {
                trf!("{} (ce système)", "{} (this system)", s.nom())
            } else {
                s.nom().to_string()
            };
            lignes.push(Ligne::choix(&(i + 1).to_string(), &nom, s.apercu()));
        }
        let chercher_ici = (SYSTEMES.len() + 1).to_string();
        lignes.push(Ligne::choix(
            &chercher_ici,
            tr!("Chercher une commande", "Look for a command"),
            tr!("un mot : disque, wifi, dns…", "a word: disk, wifi, dns…"),
        ));
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        lignes.push(Ligne::Texte(String::new()));
        // Taper un mot ici trouve aussi chaque programme, par son nom ou ses commandes (« 2.4 » : Windows, 4e).
        lignes.extend(lignes_de_recherche(""));
        let Some(choix) = choisir(
            &lignes,
            tr!("  Choix (Entrée pour revenir) : ", "  Choice (Enter to go back): "),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim().to_string();
        if choix == chercher_ici {
            dernier = choix;
            chercher();
            continue;
        }
        if choix.contains('.') {
            if let Some((s, p)) = chemin(&choix) {
                ouvrir(s, p);
            }
            continue;
        }
        match choix
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| SYSTEMES.get(i))
        {
            Some(&s) => {
                dernier = choix;
                menu_systeme(s);
            }
            None if choix.is_empty() || choix == "↵" || choix.eq_ignore_ascii_case("q") => return,
            None => {}
        }
    }
}

/// Le système désigné par un mot (« mac », « Windows », « tous »).
fn systeme(mot: &str) -> Option<Systeme> {
    let m = simplifier(mot);
    SYSTEMES.into_iter().find(|s| s.mots().contains(&m.as_str()))
}

/// Les programmes qui portent ce nom (« winget », ou l'un de ceux réunis : « du » dans « lsblk, df, du »).
fn programmes_nommes(tape: &str) -> Vec<(Systeme, &'static Programme)> {
    let n = simplifier(tape);
    SYSTEMES
        .iter()
        .flat_map(|&s| s.programmes().iter().map(move |p| (s, p)))
        .filter(|(_, p)| p.nom.split(',').any(|morceau| simplifier(morceau.trim()) == n))
        .collect()
}

/// « gardien guide [quoi] » : sans rien, le menu ; un système, toutes ses commandes ; un programme, les siennes ;
/// sinon, la recherche de ces mots.
pub fn executer(quoi: &str) {
    let quoi = quoi.trim();
    if quoi.is_empty() {
        menu();
        return;
    }
    if let Some(s) = systeme(quoi) {
        titre(&trf!("Guide des commandes › {}", "Command guide › {}", s.nom()));
        for l in legende(s) {
            println!("{l}");
        }
        for p in s.programmes() {
            afficher_programme(s, p);
        }
        return;
    }
    let nommes = programmes_nommes(quoi);
    if nommes.is_empty() {
        titre(tr!("Guide des commandes", "Command guide"));
        afficher_resultats(quoi, &trouver(quoi));
    } else {
        for (s, p) in nommes {
            afficher_programme(s, p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toutes() -> impl Iterator<Item = Trouvee> {
        SYSTEMES.into_iter().flat_map(|s| {
            s.programmes()
                .iter()
                .flat_map(move |p| p.commandes.iter().map(move |c| (s, p, c)))
        })
    }

    /// Les « <…> » d'une commande.
    fn a_remplacer(ligne: &str) -> Vec<&str> {
        ligne
            .match_indices('<')
            .filter_map(|(debut, _)| ligne[debut..].find('>').map(|fin| &ligne[debut..=debut + fin]))
            .collect()
    }

    #[test]
    fn chaque_programme_tient_dans_son_menu() {
        for s in SYSTEMES {
            assert!(largeur_affichee(s.apercu()) <= 33, "{}", s.apercu());
            let mut noms = std::collections::HashSet::new();
            for p in s.programmes() {
                assert!(noms.insert(p.nom), "{} : deux fois dans {}", p.nom, s.nom());
                assert!(!p.commandes.is_empty(), "{} n'a pas de commande", p.nom);
                assert!(largeur_affichee(p.nom) <= 30, "{} : nom trop long", p.nom);
                // « PowerShell : réseau » se traduit ; « lsblk, df, du » est fait de noms de commandes.
                if p.nom.contains(" : ") {
                    assert!(NOMS_EN.iter().any(|(fr, _)| *fr == p.nom), "{} sans nom anglais", p.nom);
                }
                for r in [p.role.0, p.role.1] {
                    assert!(
                        !r.is_empty() && largeur_affichee(r) <= 33,
                        "{} : « {r} » trop long",
                        p.nom
                    );
                }
            }
        }
    }

    #[test]
    fn chaque_commande_est_expliquee_et_tient_dans_76_colonnes() {
        for (s, p, c) in toutes() {
            let ou = format!("{} › {} : {}", s.nom(), p.nom, c.ligne);
            assert!(
                !c.texte.0.is_empty() && !c.texte.1.is_empty(),
                "{ou} : explication manquante"
            );
            // Deux espaces, la marque ⚠, un espace, puis la commande, en entier sur sa ligne.
            for l in [c.ligne.to_string(), c.ligne_en.to_string(), en_anglais(c.ligne)] {
                assert!(largeur_affichee(&l) <= LARGEUR - 4, "{ou} : trop longue ({l})");
            }
            for t in [c.texte.0, c.texte.1] {
                assert!(
                    envelopper(t, LARGEUR - 6).len() <= 2,
                    "{ou} : explication de plus de deux lignes"
                );
            }
        }
    }

    #[test]
    fn chaque_mot_a_remplacer_a_son_nom_anglais() {
        for (s, p, c) in toutes() {
            for mot in a_remplacer(c.ligne) {
                assert!(
                    A_REMPLACER.iter().any(|(fr, _)| *fr == mot),
                    "{} › {} : « {mot} » sans traduction",
                    s.nom(),
                    p.nom
                );
            }
            assert!(!en_anglais(c.ligne).contains("<numéro>"));
        }
        assert_eq!(en_anglais("sudo pacman -S <paquet>"), "sudo pacman -S <package>");
    }

    /// Une apostrophe ou un guillemet oublié ne se verrait que chez quelqu'un, en tapant la commande.
    #[cfg(unix)]
    #[test]
    fn les_commandes_de_linux_et_macos_sont_du_shell_valide() {
        for (s, p, c) in toutes().filter(|(s, ..)| *s != Systeme::Windows) {
            let mut l = c.ligne.to_string();
            for mot in a_remplacer(c.ligne) {
                l = l.replace(mot, &mot[1..mot.len() - 1].replace(' ', "_"));
            }
            let valide = std::process::Command::new("bash")
                .args(["-n", "-c", &l])
                .status()
                .is_ok_and(|st| st.success());
            assert!(valide, "{} › {} : {l}", s.nom(), p.nom);
        }
    }

    #[test]
    fn les_commandes_de_tous_les_systemes_marchent_aussi_sous_windows_powershell() {
        // PowerShell 5.1 ne connaît ni « && » ni « || », et « curl » y est un autre programme (Invoke-WebRequest).
        for (_, p, c) in toutes().filter(|(s, ..)| *s == Systeme::Tous) {
            assert!(
                !c.ligne.contains("&&") && !c.ligne.contains("||"),
                "{} : {}",
                p.nom,
                c.ligne
            );
        }
        for (_, p, c) in toutes().filter(|(s, ..)| *s == Systeme::Windows) {
            assert!(
                !c.ligne.contains("&&") && !c.ligne.contains("||"),
                "{} : {}",
                p.nom,
                c.ligne
            );
        }
    }

    #[test]
    fn recherche_sans_accents_ni_majuscules() {
        let noms = |r: &str| trouver(r).iter().map(|(s, p, _)| (*s, p.nom)).collect::<Vec<_>>();
        assert!(
            noms("ECHEC").iter().any(|(_, n)| *n == "systemctl"),
            "« échec » sans accent"
        );
        assert!(
            noms("wifi").iter().any(|(s, _)| *s == Systeme::Windows),
            "« Wi-Fi » sans tiret"
        );
        // Tous les mots comptent.
        let sante_disque = noms("sante disque");
        assert!(sante_disque.iter().any(|(_, n)| *n == "smartctl"));
        assert!(sante_disque.iter().all(|(_, n)| *n != "winget"));
        // Un mot court commence un mot : « ip » trouve ip, ipconfig, pas « description ».
        assert!(noms("ip").iter().any(|(_, n)| n.starts_with("ip")));
        assert!(trouver("").is_empty() && trouver("zzzqqq").is_empty());
        assert_eq!(simplifier("Wi-Fi, Échec, cœur"), "wifi, echec, coeur");
    }

    #[test]
    fn systeme_ou_programme_par_son_nom() {
        assert_eq!(systeme("Mac"), Some(Systeme::MacOs));
        assert_eq!(systeme("tous"), Some(Systeme::Tous));
        assert_eq!(systeme("winget"), None);
        assert_eq!(programmes_nommes("WINGET").len(), 1);
        // Un des programmes réunis sous un même nom.
        assert!(programmes_nommes("du").iter().any(|(s, _)| *s == Systeme::Linux));
        assert!(programmes_nommes("pas-un-programme").is_empty());
    }

    #[test]
    fn programme_present_ou_non() {
        let p = |executable| Programme {
            nom: "essai",
            role: ("essai", "test"),
            executable,
            commandes: &[],
        };
        assert!(installe(&p("")));
        assert!(!installe(&p("gardien-programme-qui-n-existe-pas")));
        #[cfg(unix)]
        {
            assert!(installe(&p("sh")));
            assert!(installe(&p("/bin/sh")));
        }
    }
}
