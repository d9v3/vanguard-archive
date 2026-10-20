//! Parcours « Après une infection » : ce qui presse (couper Internet, ne pas payer, ne pas rappeler le numéro
//! affiché), puis ce que Vanguard vérifie lui-même (persistance, accès à distance, comptes, intégrité, fichiers
//! suspects, navigation détournée), les analyses qu'il propose (YARA, antivirus et démarrage, intégrité en détail,
//! connexions sortantes, prise de contrôle à distance), et enfin la liste des mots de passe à changer, dans l'ordre,
//! depuis un autre appareil. Rien n'est changé sans accord : chaque outil redemande le sien.

use super::{a_savoir, bilan, conseil, ecran, proposer_outil, question};
use crate::selection::{Case, cocher};
use crate::ui::*;

/// Ce qui fait penser à une infection, dans l'ordre des réponses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Signe {
    Rancon,
    PriseDeControle,
    FichierOuvert,
    AntivirusAlerte,
    Doute,
}

impl Signe {
    fn depuis(reponse: usize) -> Signe {
        match reponse {
            0 => Signe::Rancon,
            1 => Signe::PriseDeControle,
            2 => Signe::FichierOuvert,
            3 => Signe::AntivirusAlerte,
            _ => Signe::Doute,
        }
    }
}

/// Les catégories du bilan qui disent si quelque chose s'est installé ou a été changé.
pub(super) const CATEGORIES: &[&str] = &[
    "Persistance",
    "Accès à distance",
    "Comptes",
    "Intégrité",
    "Fichiers suspects",
    "Rançongiciels",
    "Navigateur",
    "Extensions",
    "DNS",
    "Ports en écoute",
];

/// Ce qui presse, avant toute vérification : selon le signe et selon qu'Internet est encore branché.
pub(super) fn urgences(signe: Signe, internet: bool) -> Vec<&'static str> {
    let mut u = Vec::new();
    if signe == Signe::Rancon {
        if internet {
            u.push(tr!(
                "Coupe Internet tout de suite (câble débranché, Wi-Fi éteint) : un rançongiciel en cours chiffre aussi les disques partagés, le stockage en ligne et les sauvegardes branchées.",
                "Cut the Internet right now (cable unplugged, Wi-Fi off): ransomware at work also encrypts shared disks, online storage and plugged-in backups."
            ));
        }
        u.push(tr!(
            "Ne paie pas : rien ne garantit la clé, et payer fait de toi une cible. Garde les fichiers chiffrés tels quels : des déchiffreurs sortent parfois (projet No More Ransom, d'Europol et de la police néerlandaise).",
            "Do not pay: nothing guarantees the key, and paying makes you a target. Keep the encrypted files as they are: decryptors come out sometimes (No More Ransom project, by Europol and the Dutch police)."
        ));
    }
    if signe == Signe::PriseDeControle {
        if internet {
            u.push(tr!(
                "Si la personne est peut-être encore connectée : coupe Internet d'abord, le programme de prise de contrôle se retire ensuite (« Quelqu'un contrôle mon ordi ? », proposé plus bas).",
                "If the person may still be connected: cut the Internet first, the remote control program is removed afterwards (“Is someone controlling my PC?”, offered below)."
            ));
        }
        u.push(tr!(
            "Ne rappelle jamais le numéro affiché ni celui de l'appel : un vrai soutien technique n'appelle pas sans qu'on l'ait demandé. Si tu as payé, appelle ta banque pour contester.",
            "Never call back the number shown or the caller's: real technical support does not call unasked. If you paid, call your bank to dispute it."
        ));
    }
    if signe == Signe::FichierOuvert {
        u.push(tr!(
            "Le fichier ouvert reste sur le disque : ne le rouvre pas. Les analyses ci-dessous le retrouvent dans Téléchargements, sur le Bureau et au démarrage.",
            "The opened file is still on the disk: do not open it again. The scans below find it in Downloads, on the Desktop and at startup."
        ));
    }
    if signe == Signe::AntivirusAlerte {
        u.push(tr!(
            "L'antivirus a isolé ce qu'il a trouvé : laisse-le en quarantaine. Ce qui compte maintenant, c'est ce qu'il n'a pas vu : ce qui se lance au démarrage et ce qui a changé.",
            "The antivirus isolated what it found: leave it in quarantine. What matters now is what it did not see: what starts at boot and what changed."
        ));
    }
    u
}

/// Les mots de passe à changer, dans l'ordre : le courriel d'abord, parce qu'il réinitialise tous les autres.
pub(super) fn mots_de_passe(signe: Signe) -> Vec<&'static str> {
    let mut m = vec![
        tr!(
            "Le courriel, en premier : il permet de réinitialiser tous les autres mots de passe.",
            "Email first: it can reset every other password."
        ),
        tr!(
            "La banque et les paiements (carte enregistrée, PayPal, boutiques en ligne).",
            "Bank and payments (saved card, PayPal, online shops)."
        ),
        tr!(
            "Les comptes qui ouvrent le reste : Microsoft, Apple, Google, et le gestionnaire de mots de passe lui-même.",
            "The accounts that open the rest: Microsoft, Apple, Google, and the password manager itself."
        ),
        tr!(
            "Les réseaux sociaux et la messagerie (ils servent à arnaquer tes proches en ton nom).",
            "Social networks and messaging (they are used to scam your relatives in your name)."
        ),
        tr!(
            "Tout mot de passe enregistré dans le navigateur de cet ordinateur : un voleur de mots de passe les lit en une seconde.",
            "Every password saved in this computer's browser: a password stealer reads them in a second."
        ),
    ];
    if signe == Signe::PriseDeControle {
        m.push(tr!(
            "Ce que la personne a pu voir à l'écran pendant la prise de contrôle : comptes ouverts, documents, numéro de carte.",
            "Whatever the person could see on screen during the remote session: open accounts, documents, card number."
        ));
    }
    m
}

pub(super) fn infection() {
    let Some(signe) = question(
        tr!(
            "Qu'est-ce qui te fait penser à une infection ?",
            "What makes you think there is an infection?"
        ),
        &[
            tr!(
                "Une fenêtre réclame de l'argent, mes fichiers sont illisibles",
                "A window demands money, my files are unreadable"
            ),
            tr!(
                "Quelqu'un a pris la main (appel, faux technicien)",
                "Someone took control (call, fake technician)"
            ),
            tr!(
                "J'ai ouvert un fichier ou une pièce jointe douteuse",
                "I opened a dubious file or attachment"
            ),
            tr!("L'antivirus a trouvé quelque chose", "The antivirus found something"),
            tr!(
                "Un doute : lenteur, fenêtres, programmes inconnus",
                "A doubt: slowness, pop-ups, unknown programs"
            ),
        ],
    ) else {
        return;
    };
    let signe = Signe::depuis(signe);
    let Some(relie) = question(
        tr!(
            "L'ordinateur est-il encore relié à Internet ?",
            "Is the computer still connected to the Internet?"
        ),
        &[tr!("Oui", "Yes"), tr!("Non, déjà débranché", "No, already unplugged")],
    ) else {
        return;
    };
    let internet = relie == 0;
    ecran();
    let urgences = urgences(signe, internet);
    if !urgences.is_empty() {
        section(tr!("D'ABORD", "FIRST"));
        for u in &urgences {
            conseil(u);
        }
    }
    section(tr!("CE QUE VANGUARD VÉRIFIE", "WHAT VANGUARD CHECKS"));
    bilan(CATEGORIES);
    analyses(signe, internet);
    section(tr!("MOTS DE PASSE À CHANGER", "PASSWORDS TO CHANGE"));
    afficher_aligne(
        "  ",
        tr!(
            "Depuis un AUTRE appareil (téléphone, ordinateur sain), tant que celui-ci n'est pas lavé de tout doute. Active la validation en deux étapes partout où c'est possible, et déconnecte les sessions ouvertes ailleurs.",
            "From ANOTHER device (phone, clean computer), as long as this one is not cleared of all doubt. Turn on two-step verification wherever possible, and sign out the sessions open elsewhere."
        ),
        2,
        GRIS,
    );
    for (i, m) in mots_de_passe(signe).iter().enumerate() {
        afficher_aligne(&format!("  {TOUCHE}{}{RESET} ", i + 1), m, 4, "");
    }
    conseil(tr!(
        "Dans le courriel, vérifie aussi les règles de transfert automatique et les adresses de secours : un intrus s'en sert pour garder l'accès après le changement de mot de passe.",
        "In the mailbox, also check the automatic forwarding rules and the recovery addresses: an intruder uses them to keep access after the password change."
    ));
    if internet {
        proposer_outil(
            tr!(
                "\n  Vérifier si un de tes anciens mots de passe est dans les fuites connues ? [o/N] : ",
                "\n  Check whether one of your old passwords is in the known leaks? [y/N]: "
            ),
            crate::protection::fuites::verifier,
        );
    }
    let mut conseils = Vec::new();
    if matches!(signe, Signe::Rancon | Signe::PriseDeControle) {
        conseils.push(tr!(
            "Quand le doute reste (rançongiciel, prise de contrôle confirmée), la seule certitude est la réinstallation complète : d'abord une copie vérifiée de tes fichiers (Copier mes fichiers), puis le système réinstallé depuis la clé VANGUARD ou l'outil de récupération.",
            "When doubt remains (ransomware, confirmed remote control), the only certainty is a full reinstall: first a checked copy of your files (Copy my files), then the system reinstalled from the VANGUARD key or the recovery tool."
        ));
    }
    conseils.push(tr!(
        "Les autres appareils de la maison ont pu être touchés par le même courriel ou la même clé USB : refais au moins l'analyse rapide dessus.",
        "The other devices of the house may have been hit by the same email or USB stick: at least run the quick scan on them too."
    ));
    a_savoir(&conseils);
    if matches!(signe, Signe::Rancon | Signe::PriseDeControle) {
        proposer_outil(
            tr!(
                "\n  Ouvrir « Copier mes fichiers » ? [o/N] : ",
                "\n  Open “Copy my files”? [y/N]: "
            ),
            crate::copier::menu,
        );
    }
}

/// Une analyse proposée : son nom, ce qu'elle fait, et ce qu'elle lance.
struct Analyse {
    texte: &'static str,
    precision: &'static str,
    detail: &'static str,
    cochee: bool,
    lancer: fn(),
}

fn yara() {
    crate::protection::yara::analyser(&crate::protection::antivirus::Portee::Rapide);
}

fn antivirus() {
    crate::protection::antivirus::analyser(crate::protection::antivirus::Portee::Rapide);
}

fn integrite() {
    crate::protection::integrite::verifier(false);
}

/// Les analyses, à cocher, puis lancées dans l'ordre : les lectures seules d'abord, ce qui retire quelque chose en
/// dernier. Sans Internet, « Qui parle à Internet ? » n'aurait rien à montrer et un moteur manquant ne s'installe pas.
fn liste_des_analyses(signe: Signe, internet: bool) -> Vec<Analyse> {
    let mut a = vec![
        Analyse {
            texte: tr!("Analyse YARA", "YARA scan"),
            precision: tr!("familles connues", "known families"),
            detail: tr!(
                "308 règles qui reconnaissent des familles entières (rançongiciels, voleurs de mots de passe, portes dérobées) dans Téléchargements, sur le Bureau et au démarrage. Lecture seule, rien à installer.",
                "308 rules that recognize whole families (ransomware, password stealers, backdoors) in Downloads, on the Desktop and at startup. Read-only, nothing to install."
            ),
            cochee: true,
            lancer: yara,
        },
        Analyse {
            texte: tr!("Antivirus rapide et démarrage", "Quick antivirus and startup"),
            precision: tr!("moteur du système", "system engine"),
            detail: tr!(
                "Le moteur reconnu du système (Defender, ClamAV) sur les dossiers où arrivent les menaces, puis la revue de ce qui se lance au démarrage, là où une infection cherche à se maintenir.",
                "The system's recognized engine (Defender, ClamAV) on the folders where threats arrive, then the review of what starts at boot, where an infection tries to stay."
            ),
            cochee: true,
            lancer: antivirus,
        },
        Analyse {
            texte: tr!("Fichiers critiques modifiés", "Modified critical files"),
            precision: tr!("intégrité", "integrity"),
            detail: tr!(
                "Comptes, sudo, SSH, démarrage automatique, hosts : ce qui a été modifié, ajouté ou supprimé depuis la référence de Vanguard.",
                "Accounts, sudo, SSH, autostart, hosts: what was modified, added or removed since Vanguard's reference."
            ),
            cochee: true,
            lancer: integrite,
        },
    ];
    if internet {
        a.push(Analyse {
            texte: tr!("Qui parle à Internet ?", "Who talks to the Internet?"),
            precision: tr!("connexions en cours", "current connections"),
            detail: tr!(
                "Les connexions établies, par programme, avec le nom du serveur : un programme lancé depuis un dossier temporaire ou effacé après son lancement se repère ici. Lecture seule.",
                "The established connections, per program, with the server name: a program started from a temporary folder or deleted after launch shows up here. Read-only."
            ),
            cochee: signe != Signe::Rancon,
            lancer: crate::protection::sortantes::afficher,
        });
    }
    a.push(Analyse {
        texte: tr!("Quelqu'un contrôle mon ordi ?", "Is someone controlling my PC?"),
        precision: tr!("retire après accord", "removes after consent"),
        detail: tr!(
            "Les programmes de prise de contrôle à distance (AnyDesk, TeamViewer, RustDesk…) installés, au démarrage, en cours ou téléchargés ; chacun n'est retiré qu'après ton accord.",
            "Remote control programs (AnyDesk, TeamViewer, RustDesk…) installed, at boot, running or downloaded; each is removed only after your consent."
        ),
        cochee: matches!(signe, Signe::PriseDeControle | Signe::Doute),
        lancer: crate::protection::distance::menu,
    });
    a
}

/// Propose les analyses à cocher, puis lance celles qui le sont, dans l'ordre.
fn analyses(signe: Signe, internet: bool) {
    let liste = liste_des_analyses(signe, internet);
    let cases: Vec<Case> = liste
        .iter()
        .map(|a| Case {
            texte: a.texte.to_string(),
            precision: a.precision.to_string(),
            detail: a.detail.to_string(),
            cochee: a.cochee,
            recommandee: a.cochee,
            fixe: false,
        })
        .collect();
    let titre = vec![
        String::new(),
        ligne_section(tr!("ANALYSES", "SCANS")),
        trf!(
            "  {GRIS}Chaque analyse dit ce qu'elle trouve ; rien n'est retiré sans ton accord.{RESET}",
            "  {GRIS}Each scan says what it finds; nothing is removed without your consent.{RESET}"
        ),
        String::new(),
    ];
    let Some(choisies) = cocher(&titre, &cases) else {
        return;
    };
    for (a, _) in liste.iter().zip(choisies).filter(|(_, c)| *c) {
        println!();
        (a.lancer)();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_courriel_passe_en_premier() {
        for signe in [Signe::Rancon, Signe::PriseDeControle, Signe::Doute] {
            let m = mots_de_passe(signe);
            assert!(m[0].to_lowercase().contains("courriel"), "{:?}", m[0]);
            assert!(m.len() >= 5);
        }
        assert_eq!(
            mots_de_passe(Signe::PriseDeControle).len(),
            mots_de_passe(Signe::Doute).len() + 1
        );
    }

    #[test]
    fn couper_internet_seulement_s_il_est_branche() {
        let branche = urgences(Signe::Rancon, true);
        let coupe = urgences(Signe::Rancon, false);
        assert_eq!(branche.len(), coupe.len() + 1);
        assert!(branche[0].contains("Coupe Internet"));
        assert!(coupe[0].contains("Ne paie pas"));
        assert_eq!(urgences(Signe::Doute, true).len(), 0);
        assert_eq!(urgences(Signe::PriseDeControle, false).len(), 1);
    }

    #[test]
    fn les_analyses_suivent_la_situation() {
        // Sans Internet, pas de connexions sortantes à regarder.
        assert_eq!(liste_des_analyses(Signe::Doute, true).len(), 5);
        assert_eq!(liste_des_analyses(Signe::Doute, false).len(), 4);
        // Les lectures seules d'abord, le retrait en dernier.
        let a = liste_des_analyses(Signe::PriseDeControle, true);
        assert!(a.last().is_some_and(|x| x.cochee && x.precision.contains("retire")));
        assert!(!liste_des_analyses(Signe::FichierOuvert, true).last().unwrap().cochee);
        // Un rançongiciel : les connexions sortantes ne sont pas cochées (le mal est fait, le réseau doit être coupé).
        assert!(!liste_des_analyses(Signe::Rancon, true)[3].cochee);
        for x in &a {
            assert!(largeur_affichee(x.texte) <= 42, "{}", x.texte);
            assert!(largeur_affichee(x.precision) <= 22, "{}", x.precision);
        }
    }

    #[test]
    fn signe_depuis_la_reponse() {
        assert_eq!(Signe::depuis(0), Signe::Rancon);
        assert_eq!(Signe::depuis(3), Signe::AntivirusAlerte);
        assert_eq!(Signe::depuis(9), Signe::Doute);
    }
}
