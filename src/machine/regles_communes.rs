//! Les règles du bilan communes aux trois systèmes, déclarées au registre (`machine::regles`) après celles du système,
//! dans l'ordre où le bilan les montre.

use crate::machine::regles::{Os, regle};

regle!(
    "COM-DNS-001",
    Os::Tous,
    500,
    ("DNS utilisé", "DNS in use"),
    &[],
    || super::dns::dns().into_iter().collect()
);

regle!(
    "COM-CRT-001",
    Os::Tous,
    510,
    ("certificats racine ajoutés", "added root certificates"),
    &[],
    || super::certificats::certificats().into_iter().collect()
);

regle!(
    "COM-NAV-001",
    Os::Tous,
    520,
    ("extensions des navigateurs", "browser extensions"),
    &[],
    || super::extensions::extensions().into_iter().collect()
);

regle!(
    "COM-NAV-002",
    Os::Tous,
    530,
    ("réglages de sécurité des navigateurs", "browser security settings"),
    &[],
    || super::navigateur::navigateurs().into_iter().collect()
);

regle!(
    "COM-NAV-003",
    Os::Tous,
    540,
    (
        "navigation détournée (proxy, hosts)",
        "hijacked browsing (proxy, hosts)"
    ),
    &[],
    || vec![super::navigation_detournee::constat()]
);

regle!(
    "COM-MDP-001",
    Os::Tous,
    550,
    (
        "mots de passe gardés par le navigateur",
        "passwords kept by the browser"
    ),
    &[],
    || super::mots_de_passe::constats().into_iter().collect()
);

regle!(
    "COM-FIC-001",
    Os::Tous,
    560,
    ("fichiers sensibles qui traînent", "sensitive files lying around"),
    &[],
    || super::sensibles::constats().into_iter().collect()
);

regle!(
    "COM-MAT-001",
    Os::Tous,
    570,
    ("santé de l'ordinateur", "computer health"),
    &[],
    || super::sante::sante().into_iter().collect()
);

regle!(
    "COM-PAR-001",
    Os::Tous,
    580,
    ("partages ouverts à tous", "shares open to everyone"),
    &[],
    || super::partages::partages().into_iter().collect()
);

regle!("COM-BLU-001", Os::Tous, 590, ("Bluetooth", "Bluetooth"), &[], || {
    super::bluetooth::constats().into_iter().collect()
});

regle!(
    "COM-CPT-001",
    Os::Tous,
    600,
    ("nouveaux administrateurs", "new administrators"),
    &[],
    || super::administrateurs::constat().into_iter().collect()
);

regle!(
    "COM-JRN-001",
    Os::Tous,
    610,
    ("journaux effacés ou en erreur", "erased or failing logs"),
    &[],
    || super::journaux::journaux().into_iter().collect()
);

regle!(
    "COM-HEU-001",
    Os::Tous,
    620,
    ("heure de l'ordinateur", "computer clock"),
    &[],
    || super::heure::constat().into_iter().collect()
);

regle!(
    "COM-MAJ-001",
    Os::Tous,
    630,
    ("fin de support", "end of support"),
    &[],
    || super::fin_de_support::constats().into_iter().collect()
);

regle!(
    "COM-CPT-002",
    Os::Tous,
    640,
    ("comptes oubliés", "forgotten accounts"),
    &[],
    || super::comptes_oublies::constats().into_iter().collect()
);

regle!(
    "COM-INT-001",
    Os::Tous,
    650,
    ("intégrité des fichiers critiques", "critical file integrity"),
    &[],
    || vec![crate::protection::integrite::constat()]
);

regle!(
    "COM-INT-002",
    Os::Tous,
    660,
    ("fichiers-pièges contre les rançongiciels", "ransomware decoy files"),
    &[],
    || crate::protection::pieges::constat().into_iter().collect()
);

regle!(
    "COM-DIS-001",
    Os::Tous,
    670,
    ("prise de contrôle à distance", "remote takeover"),
    &[],
    || crate::protection::distance::constats().into_iter().collect()
);

regle!(
    "COM-ESP-001",
    Os::Tous,
    675,
    ("logiciels espions", "spyware"),
    &[],
    crate::protection::espions::constats
);

regle!(
    "COM-CLE-001",
    Os::Tous,
    680,
    ("manifeste de la clé VANGUARD", "VANGUARD key manifest"),
    &[],
    || crate::protection::manifeste::constat().into_iter().collect()
);

regle!(
    "COM-HIS-001",
    Os::Tous,
    690,
    ("évolution depuis le dernier bilan", "changes since the last check"),
    &[],
    || crate::historique::constat().into_iter().collect()
);

regle!(
    "COM-ETA-001",
    Os::Tous,
    695,
    ("état de Vanguard scellé", "Vanguard's sealed state"),
    &[],
    || crate::sceau::constat().into_iter().collect()
);

regle!(
    "COM-PUB-001",
    Os::Tous,
    697,
    ("mode Wi-Fi public", "public Wi-Fi mode"),
    &[],
    || crate::reseau::wifi_public::constat()
);

regle!(
    "COM-SUR-001",
    Os::Tous,
    700,
    ("surveillance de cette machine", "monitoring of this machine"),
    &[],
    || crate::reseau::surveillance::constat().into_iter().collect()
);

regle!(
    "COM-SUR-003",
    Os::Tous,
    702,
    ("entretien du mois de cette machine", "monthly check-up of this machine"),
    &[],
    || crate::entretien::constat().into_iter().collect()
);

regle!(
    "COM-SUR-002",
    Os::Tous,
    701,
    (
        "protection en temps réel de Vanguard",
        "Vanguard's real-time protection"
    ),
    &[],
    || vec![crate::protection::temps_reel::constat()]
);

regle!(
    "COM-CLE-002",
    Os::Tous,
    710,
    ("données de la clé chiffrées", "encrypted key data"),
    &[],
    || crate::chiffrement::constat().into_iter().collect()
);

regle!(
    "COM-CLE-003",
    Os::Tous,
    711,
    (
        "identité de la clé VANGUARD et son carnet",
        "VANGUARD key identity and its record"
    ),
    &[],
    crate::protection::cles_connues::constats
);

regle!(
    "COM-SAV-001",
    Os::Tous,
    720,
    ("sauvegarde automatique", "automatic backup"),
    &[],
    || crate::sauvegarde::constats().into_iter().collect()
);

regle!(
    "COM-AGT-001",
    Os::Tous,
    730,
    ("serveurs d'IA ouverts au réseau", "AI servers open to the network"),
    &["OWASP Top 10 for LLM Applications"],
    super::agents_ia::exposition
);

regle!(
    "COM-AGT-002",
    Os::Tous,
    740,
    (
        "réglages des agents d'IA (permissions, serveurs MCP, clés en clair)",
        "AI agent settings (permissions, MCP servers, clear-text keys)"
    ),
    &["OWASP Top 10 for LLM Applications", "MCP Security Best Practices"],
    super::agents_ia::reglages
);
