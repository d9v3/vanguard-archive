//! Couleurs et petits éléments d'affichage partagés.

pub use crate::langue::Reponse;
use crate::risk::Niveau;
pub use crate::{tr, tre, trf, trp};

pub const RESET: &str = "\x1b[0m";
pub const GRAS: &str = "\x1b[1m";
/// Texte secondaire : un gris clair, lisible sur un fond noir (le « gris atténué » du terminal l'était mal).
pub const GRIS: &str = "\x1b[38;5;250m";
pub const VERT: &str = "\x1b[1;92m";
/// Titres de section et touches du menu.
pub const ACCENT: &str = "\x1b[1;96m";
/// Touches du menu : blanc vif.
pub const TOUCHE: &str = "\x1b[1;97m";
/// Précisions à côté d'un texte : un cran sous le gris clair, pour qu'on les distingue du texte principal.
pub const DISCRET: &str = "\x1b[38;5;245m";

/// Largeur des titres et des cadres (tient dans un terminal de 80 colonnes).
pub const LARGEUR: usize = 76;

/// Les deux emojis des messages : « 💡 » devant un conseil à suivre soi-même, « 🔧 » devant une correction que Gardien
/// sait appliquer. Partout ailleurs ils prennent deux colonnes ; l'ancienne console de Windows (cmd.exe et PowerShell
/// hors du Terminal Windows, l'habitude sous Windows 10) n'en dessine qu'une case : les précisions se décalent et les
/// menus se cassent. Là, deux signes d'une colonne, que toute police de console dessine, les remplacent.
/// GARDIEN_EMOJI=0 les retire partout (un terminal qui les dessine mal), GARDIEN_EMOJI=1 les garde partout.
pub fn ampoule() -> &'static str {
    if emojis() { "💡" } else { "→" }
}

pub fn cle_a_molette() -> &'static str {
    if emojis() { "🔧" } else { "+" }
}

fn emojis() -> bool {
    static EMOJIS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *EMOJIS.get_or_init(|| match std::env::var("GARDIEN_EMOJI").ok().as_deref().map(str::trim) {
        Some("0" | "non" | "no" | "off") => false,
        Some("1" | "oui" | "yes" | "on") => true,
        _ => !ancienne_console_windows(),
    })
}

/// La console d'avant le Terminal Windows (conhost). Rien ne l'annonce ; mais le Terminal Windows pose WT_SESSION,
/// VS Code TERM_PROGRAM, ConEmu et Cmder ConEmuANSI : sous Windows, sans aucune de ces variables, c'est elle.
fn ancienne_console_windows() -> bool {
    cfg!(windows)
        && ["WT_SESSION", "TERM_PROGRAM", "ConEmuANSI"]
            .iter()
            .all(|v| std::env::var_os(v).is_none())
}

pub fn couleur(niveau: Niveau) -> &'static str {
    match niveau {
        Niveau::Info => "\x1b[96m",
        Niveau::Moyen => "\x1b[93m",
        Niveau::Eleve => "\x1b[38;5;214m",
        Niveau::Critique => "\x1b[1;91m",
    }
}

pub fn couleur_note(n: &str) -> &'static str {
    match n {
        "A" | "B" => VERT,
        "C" => "\x1b[1;93m",
        _ => "\x1b[1;91m",
    }
}

/// Colonnes qu'un caractère prend dans le terminal : deux pour un emoji (💡) ou une lettre pleine largeur (ａ, 漢),
/// aucune pour ce qui se pose sur le caractère d'avant (accent combiné, variante d'emoji, liaison). Les plages sont
/// celles que les terminaux affichent sur deux colonnes ; les symboles comme ⚠ ✔ ✖, en une colonne par défaut,
/// restent à un.
pub fn largeur_car(c: char) -> usize {
    match u32::from(c) {
        0x0300..=0x036F | 0x200B..=0x200D | 0x20D0..=0x20FF | 0xFE00..=0xFE0F => 0,
        0x1100..=0x115F
        | 0x231A..=0x231B
        | 0x23E9..=0x23EC
        | 0x23F0
        | 0x23F3
        | 0x25FD..=0x25FE
        | 0x2614..=0x2615
        | 0x2648..=0x2653
        | 0x267F
        | 0x2693
        | 0x26A1
        | 0x26AA..=0x26AB
        | 0x26BD..=0x26BE
        | 0x26C4..=0x26C5
        | 0x26CE
        | 0x26D4
        | 0x26EA
        | 0x26F2..=0x26F3
        | 0x26F5
        | 0x26FA
        | 0x26FD
        | 0x2705
        | 0x270A..=0x270B
        | 0x2728
        | 0x274C
        | 0x274E
        | 0x2753..=0x2755
        | 0x2757
        | 0x2795..=0x2797
        | 0x27B0
        | 0x27BF
        | 0x2B1B..=0x2B1C
        | 0x2B50
        | 0x2B55
        | 0x2E80..=0x303E
        | 0x3041..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F004
        | 0x1F0CF
        | 0x1F18E
        | 0x1F191..=0x1F19A
        | 0x1F200..=0x1F2FF
        | 0x1F300..=0x1F64F
        | 0x1F680..=0x1F6FF
        | 0x1F7E0..=0x1F7EB
        | 0x1F900..=0x1F9FF
        | 0x1FA70..=0x1FAFF
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

/// Un caractère qu'un texte venu de l'extérieur ne doit jamais faire passer au terminal : les contrôles C0 (dont ESC,
/// qui ouvre les séquences ANSI et OSC, le retour chariot et le saut de ligne), DEL et les contrôles C1 (U+009B ouvre
/// une séquence comme ESC [), et la mise en forme invisible : sens d'écriture bidi (U+202A à U+202E, U+2066 à U+2069,
/// U+061C), espace, liaisons et marques de largeur nulle (U+200B à U+200F, U+2060 à U+2064), marque d'ordre des
/// octets (U+FEFF). Et ce qui rend un nom trompeur sans rien piloter : séparateurs de ligne et de paragraphe (U+2028,
/// U+2029), trait d'union conditionnel (U+00AD), séparateur mongol (U+180E), étiquettes invisibles (U+E0000 à
/// U+E007F). Le sélecteur de variante des émojis (U+FE0F) reste.
fn piege(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00..=0x1F
            | 0x7F..=0x9F
            | 0xAD
            | 0x061C
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x2029
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x2069
            | 0xFEFF
            | 0xE0000..=0xE007F
    )
}

/// Un texte venu de l'extérieur (nom d'un réseau ou d'un appareil, réponse du réseau, nom de fichier, sortie d'un
/// autre programme), prêt à montrer. Sans cela, un nom piégé pilote le terminal : une séquence OSC 52 écrit dans le
/// presse-papier, ESC [2K et un retour chariot effacent une alerte de Gardien et la réécrivent, un caractère bidi
/// retourne la fin d'un nom. Chacun de ces caractères devient « � », pour que la manipulation se voie ; le reste ne
/// change pas (accents, emojis, autres écritures, espaces).
pub fn affichable(texte: &str) -> String {
    texte.chars().map(|c| if piege(c) { '\u{fffd}' } else { c }).collect()
}

/// Un chemin de fichier ou de dossier prêt à montrer : un nom de fichier vient de n'importe qui (téléchargement, clé
/// USB, programme). Le chemin lui-même reste tel quel pour agir (analyser, isoler, effacer) : seul ce qui est montré
/// passe par ici.
pub fn chemin_affichable(chemin: &std::path::Path) -> String {
    affichable(&chemin.to_string_lossy())
}

/// Une commande prête à montrer avant d'être lancée. Elle reprend souvent un nom venu de l'extérieur (fichier à
/// isoler, cache à effacer, tâche planifiée, imprimante) : piégé, il effacerait ou retournerait une partie de la
/// ligne, et ce qui est montré ne serait plus ce qui est lancé. Les tabulations restent ; un saut de ligne devient
/// « ⏎ » sur la même ligne, pour qu'un nom de fichier qui en contient n'ajoute pas sous la commande une fausse ligne
/// (« ✔ … ») ; le reste passe par le filtre d'`affichable`. La commande lancée, elle, ne change pas.
pub fn commande_affichable(commande: &str) -> String {
    commande
        .chars()
        .map(|c| match c {
            '\n' => " ⏎ ".to_string(),
            '\t' => c.to_string(),
            _ if piege(c) => '\u{fffd}'.to_string(),
            _ => c.to_string(),
        })
        .collect()
}

/// Le texte contient-il encore un caractère piégé ? Pour les tests des lectures.
#[cfg(test)]
pub(crate) fn contient_un_piege(texte: &str) -> bool {
    texte.chars().any(piege)
}

/// Largeur affichée d'un texte, en colonnes du terminal (sans les codes de couleur).
pub fn largeur_affichee(t: &str) -> usize {
    let mut n = 0;
    let mut code = false;
    for c in t.chars() {
        match (code, c) {
            (false, '\x1b') => code = true,
            (true, 'm') => code = false,
            (false, _) => n += largeur_car(c),
            _ => {}
        }
    }
    n
}

/// Le début de `t` (sans codes de couleur) qui tient dans `n` colonnes, « … » compris s'il a fallu couper.
pub fn couper(t: &str, n: usize) -> String {
    if largeur_affichee(t) <= n {
        return t.to_string();
    }
    let mut court = String::new();
    let mut l = 0;
    for c in t.chars() {
        // Une colonne gardée pour « … ».
        if l + largeur_car(c) >= n {
            break;
        }
        l += largeur_car(c);
        court.push(c);
    }
    court.push('…');
    court
}

/// Coupe un texte trop long (« … » à la fin) ou le complète d'espaces jusqu'à `n` colonnes.
pub fn ajuster(t: &str, n: usize) -> String {
    let l = largeur_affichee(t);
    // Un texte en couleur n'est jamais coupé (on couperait un code) : seulement complété.
    if l > n && !t.contains('\x1b') {
        let court = couper(t, n);
        let reste = n.saturating_sub(largeur_affichee(&court));
        format!("{court}{}", " ".repeat(reste))
    } else {
        format!("{t}{}", " ".repeat(n.saturating_sub(l)))
    }
}

/// Coupe un texte en lignes d'au plus `largeur` colonnes, aux espaces.
pub fn envelopper(t: &str, largeur: usize) -> Vec<String> {
    envelopper_decale(t, largeur, largeur)
}

/// Comme `envelopper`, la première ligne d'au plus `premiere` caractères (elle suit un début déjà affiché).
pub fn envelopper_decale(t: &str, premiere: usize, suivantes: usize) -> Vec<String> {
    let mut lignes = Vec::new();
    let mut ligne = String::new();
    for mot in t.split_whitespace() {
        let largeur = if lignes.is_empty() { premiere } else { suivantes };
        if !ligne.is_empty() && largeur_affichee(&ligne) + 1 + largeur_affichee(mot) > largeur {
            lignes.push(std::mem::take(&mut ligne));
        }
        if !ligne.is_empty() {
            ligne.push(' ');
        }
        ligne.push_str(mot);
    }
    if !ligne.is_empty() {
        lignes.push(ligne);
    }
    lignes
}

/// Affiche `debut` (déjà mis en forme) puis `texte` dans la couleur `style`, coupé pour tenir dans `LARGEUR`, la
/// suite alignée à `retrait` colonnes. Sans cela, le terminal coupe les longues lignes au milieu d'un mot et les
/// reprend au bord gauche.
pub fn afficher_aligne(debut: &str, texte: &str, retrait: usize, style: &str) {
    let premiere = LARGEUR.saturating_sub(largeur_affichee(debut)).max(12);
    let lignes = envelopper_decale(texte, premiere, LARGEUR.saturating_sub(retrait).max(12));
    let mut lignes = lignes.iter();
    println!("{debut}{style}{}{RESET}", lignes.next().map_or("", String::as_str));
    for l in lignes {
        println!("{:retrait$}{style}{l}{RESET}", "");
    }
}

/// Titre de section : « ━━ Titre ━━━━━━━━… » sur toute la largeur.
pub fn titre(t: &str) {
    println!("\n{}", ligne_titre(t));
}

/// La ligne d'un titre de section, pour un menu qui se redessine.
pub fn ligne_titre(t: &str) -> String {
    let reste = LARGEUR.saturating_sub(largeur_affichee(t) + 4);
    format!("{ACCENT}━━ {t} {}{RESET}", "━".repeat(reste))
}

/// Sous-titre discret à l'intérieur d'un écran : « ── NOM ──────… ».
pub fn section(t: &str) {
    println!("\n{}", ligne_section(t));
}

/// La ligne d'un sous-titre, pour un menu qui se redessine.
pub fn ligne_section(t: &str) -> String {
    let reste = LARGEUR.saturating_sub(largeur_affichee(t) + 6);
    format!("  {ACCENT}── {t}{RESET} {GRIS}{}{RESET}", "─".repeat(reste))
}

/// Cadre de tête d'écran : un titre à gauche, une précision à droite.
pub fn cadre(gauche: &str, droite: &str) {
    for l in lignes_cadre(gauche, droite) {
        println!("{l}");
    }
}

/// Les trois lignes du cadre de tête, pour un menu qui se redessine.
pub fn lignes_cadre(gauche: &str, droite: &str) -> [String; 3] {
    let interieur = LARGEUR - 2;
    let espace = interieur.saturating_sub(largeur_affichee(gauche) + largeur_affichee(droite) + 4);
    [
        format!("{ACCENT}╭{}╮{RESET}", "─".repeat(interieur)),
        format!(
            "{ACCENT}│{RESET}  {gauche}{}{droite}  {ACCENT}│{RESET}",
            " ".repeat(espace)
        ),
        format!("{ACCENT}╰{}╯{RESET}", "─".repeat(interieur)),
    ]
}

/// Barre de score sur 10 cases, de la couleur de sa lettre : « ▰▰▰▰▰▰▰▰▱▱ ».
pub fn barre(score: u32) -> String {
    let pleines = (score.min(100) as usize + 5) / 10;
    format!(
        "{}{}{GRIS}{}{RESET}",
        couleur_note(crate::risk::note(score)),
        "▰".repeat(pleines),
        "▱".repeat(10 - pleines)
    )
}

/// Note sous forme d'étiquette : « A 100 » en couleur.
pub fn etiquette_note(score: u32) -> String {
    let n = crate::risk::note(score);
    format!("{}{n}{RESET} {GRIS}{score}{RESET}", couleur_note(n))
}

pub fn afficher_note(quoi: &str, score: u32) {
    let n = crate::risk::note(score);
    let c = couleur_note(n);
    crate::trp!(
        "  {quoi} : {c}{n}{RESET} ({score}/100)  {}",
        "  {quoi}: {c}{n}{RESET} ({score}/100)  {}",
        barre(score)
    );
}

/// « a, b, c (et 2 autre(s)) » / “a, b, c (and 2 more)” : les `max` premiers éléments d'une liste, pour un message d'une ligne.
pub fn resume(noms: &[impl AsRef<str>], max: usize, separateur: &str) -> String {
    let mut t = noms
        .iter()
        .take(max)
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(separateur);
    if noms.len() > max {
        let reste = noms.len() - max;
        t += &crate::trf!(" (et {reste} autre(s))", " (and {reste} more)");
    }
    t
}

/// Pose une question dans le terminal et retourne la réponse sans espaces autour.
pub fn demander(question: &str) -> String {
    use std::io::Write;
    print!("{question}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    // Fin de l'entrée (Ctrl-D, terminal fermé, entrée redirigée) : on quitte. Le menu reposait sinon la question
    // sans fin, en effaçant l'écran à toute vitesse (un cœur du processeur à 100 %). Vu en test.
    if matches!(std::io::stdin().read_line(&mut s), Ok(0) | Err(_)) {
        println!();
        std::process::exit(0);
    }
    s.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_emoji_ou_une_lettre_pleine_largeur_prend_deux_colonnes() {
        assert_eq!(largeur_affichee("💡 à faire"), 10);
        assert_eq!(largeur_affichee("🔧 ｐａｙｐａｌ"), 15);
        // Ces symboles restent sur une colonne ; les codes de couleur, la variante d'emoji et l'accent combiné, sur
        // aucune.
        assert_eq!(largeur_affichee(&format!("{VERT}✔ ⚠ ✖ ℹ →{RESET}")), 9);
        assert_eq!(largeur_affichee("⚠\u{fe0f}e\u{301}"), 2);
    }

    #[test]
    fn couper_et_ajuster_tiennent_dans_les_colonnes_demandees() {
        // Couper au milieu d'un emoji le laisserait déborder : il part entier.
        for n in 1..12 {
            let court = couper("ab💡💡💡cdef", n);
            assert!(largeur_affichee(&court) <= n, "{n} : {court}");
            assert_eq!(largeur_affichee(&ajuster("ab💡💡💡cdef", n)), n, "{n}");
        }
        assert_eq!(couper("ab💡cd", 4), "ab…");
        assert_eq!(couper("court", 9), "court");
        assert_eq!(ajuster("Lien", 9), "Lien     ");
        assert_eq!(ajuster("Navigation", 6), "Navig…");
    }

    /// Chaque sorte de caractère piégé devient « � », un par caractère ; la séquence qui suit reste lisible, inerte.
    #[test]
    fn textes_pieges_rendus_inoffensifs() {
        // Couleur ANSI : ESC [ 31 m.
        assert_eq!(affichable("\x1b[31mrouge"), "�[31mrouge");
        // OSC 52 : écrit « echo PIRATE » dans le presse-papier, terminé par BEL ou par ESC \.
        assert_eq!(
            affichable("Salon\x1b]52;c;ZWNobyBQSVJBVEU=\x07"),
            "Salon�]52;c;ZWNobyBQSVJBVEU=�"
        );
        assert_eq!(affichable("\x1b]0;titre\x1b\\"), "�]0;titre�\\");
        // Retour chariot et effacement de ligne : l'alerte d'avant serait réécrite.
        assert_eq!(affichable("x\x1b[2K\rFaux"), "x�[2K�Faux");
        assert_eq!(affichable("a\nb\tc\0d\x7f"), "a�b�c�d�");
        // C1 : U+009B est un ESC [ à lui seul ; U+0085 un saut de ligne.
        assert_eq!(affichable("\u{9b}31mrouge\u{85}"), "�31mrouge�");
        // Bidi : « facture[U+202E]fdp.exe » s'afficherait « facture exe.pdf ».
        assert_eq!(affichable("facture\u{202e}fdp.exe"), "facture�fdp.exe");
        assert_eq!(
            affichable("\u{202a}\u{202b}\u{202c}\u{202d}\u{2066}\u{2067}\u{2068}\u{2069}\u{61c}"),
            "���������"
        );
        // Invisibles : « Sa[U+200B]lon » ressemble à « Salon ».
        assert_eq!(affichable("Sa\u{200b}lon"), "Sa�lon");
        // Trompeurs sans rien piloter : séparateurs de ligne, trait d'union conditionnel, séparateur mongol, étiquettes.
        assert_eq!(
            affichable("a\u{2028}b\u{2029}c\u{ad}d\u{180e}e\u{e0041}\u{e007f}"),
            "a�b�c�d�e��"
        );
        // Le sélecteur de variante des émojis reste.
        assert_eq!(affichable("❤\u{fe0f}"), "❤\u{fe0f}");
        assert_eq!(
            affichable("\u{200c}\u{200d}\u{200e}\u{200f}\u{2060}\u{2061}\u{2062}\u{2063}\u{2064}\u{feff}"),
            "����������"
        );
        // Une colonne par « � » : les alignements tiennent.
        assert_eq!(largeur_affichee(&affichable("\x1b[2K\r")), 5);
        assert!(contient_un_piege("a\u{2066}") && !contient_un_piege(&affichable("a\u{2066}\x1b")));
        assert_eq!(
            chemin_affichable(std::path::Path::new("/tmp/a\x1b]52;c;eA==\x07b")),
            "/tmp/a�]52;c;eA==�b"
        );
        assert_eq!(
            chemin_affichable(std::path::Path::new("/home/alice/Téléchargements/été 💡.pdf")),
            "/home/alice/Téléchargements/été 💡.pdf"
        );
    }

    /// Un texte normal ne change pas, octet pour octet : accents, emojis, autres écritures, espaces (dont l'espace
    /// insécable), ponctuation, « � » déjà là.
    #[test]
    fn texte_normal_identique() {
        for t in [
            "",
            "Salon",
            "Chez Max · 2,4 GHz",
            "Café d'été « Québec » — 5 GHz",
            "💡 📶 🔒 ✔ ⚠ ✖ ℹ → ▰▱",
            "Москва 東京 서울 مرحبا שלום Ελλάδα हिन्दी ไทย",
            "a\u{a0}b c",
            "C:\\Users\\alice\\Téléchargements\\facture (2).pdf",
            "déjà � là",
        ] {
            assert_eq!(affichable(t), t);
            assert_eq!(affichable(t).as_bytes(), t.as_bytes());
            assert!(!contient_un_piege(t), "{t}");
        }
    }

    /// Une commande montrée : le nom piégé qu'elle reprend ne peut plus effacer la ligne ni en retourner la fin ; ses
    /// propres sauts de ligne et tabulations restent, et une commande normale ne change pas.
    #[test]
    fn commandes_montrees_telles_qu_elles_seront_lancees() {
        assert_eq!(
            commande_affichable("rm -rf -- ~/.cache/'x\x1b[2K\recho rassurant'"),
            "rm -rf -- ~/.cache/'x�[2K�echo rassurant'"
        );
        assert_eq!(
            commande_affichable("Unregister-ScheduledTask -TaskName 'Maj\u{202e}exe.txt' -Confirm:$false"),
            "Unregister-ScheduledTask -TaskName 'Maj�exe.txt' -Confirm:$false"
        );
        assert_eq!(commande_affichable("\u{9b}2K\x1b]52;c;eA==\x07"), "�2K�]52;c;eA==�");
        // Un saut de ligne, de Gardien ou d'un nom de fichier, reste sur la ligne de la commande : pas de fausse ligne.
        assert_eq!(
            commande_affichable("rm -- ~/.cache/'x\n  ✔ Tout est propre'"),
            "rm -- ~/.cache/'x ⏎   ✔ Tout est propre'"
        );
        assert_eq!(
            commande_affichable("printf '%s\\n' a | sudo tee /etc/x >/dev/null\nsudo sysctl --system"),
            "printf '%s\\n' a | sudo tee /etc/x >/dev/null ⏎ sudo sysctl --system"
        );
        for c in [
            "sudo systemctl disable --now cups.service",
            "Set-ItemProperty -LiteralPath 'HKCU:\\Software\\Été' -Name 'a\tb' -Value 0",
        ] {
            assert_eq!(commande_affichable(c).as_bytes(), c.as_bytes());
        }
    }

    #[test]
    fn envelopper_compte_les_colonnes() {
        let lignes = envelopper("💡 💡 💡 💡 💡", 8);
        assert_eq!(lignes, ["💡 💡 💡", "💡 💡"]);
        assert!(lignes.iter().all(|l| largeur_affichee(l) <= 8));
    }
}
