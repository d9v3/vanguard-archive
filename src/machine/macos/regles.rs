//! Les règles du bilan de macOS, déclarées au registre (`machine::regles`) dans l'ordre où le bilan les montre. Les
//! vérifications restent dans leurs fichiers ; une nouvelle règle se déclare plutôt à côté de la sienne.

use super::*;
use crate::machine::ParBilan;
use crate::machine::regles::{Os, regle};

/// Le pare-feu, lu une fois par bilan : sa règle et celle des ports le demandent en même temps, et deux lectures
/// pourraient se contredire.
static PARE_FEU: ParBilan<Constat> = ParBilan::new();

regle!("MAC-PFE-001", Os::MacOs, 10, ("pare-feu", "firewall"), &[], || vec![
    PARE_FEU.lire(pare_feu)
]);

regle!(
    "MAC-PFE-002",
    Os::MacOs,
    100,
    ("mode furtif du pare-feu", "firewall stealth mode"),
    &[],
    || mode_furtif().into_iter().collect()
);

regle!(
    "MAC-WIF-001",
    Os::MacOs,
    110,
    ("réseaux Wi-Fi", "Wi-Fi networks"),
    &[],
    || wifi().into_iter().collect()
);

regle!(
    "MAC-RES-001",
    Os::MacOs,
    120,
    ("services ouverts sur le réseau", "services open to the network"),
    &[],
    || ports_ecoute(PARE_FEU.lire(pare_feu).probleme.is_none())
);

regle!("MAC-CHF-001", Os::MacOs, 130, ("FileVault", "FileVault"), &[], || vec![
    chiffrement_disque()
]);

regle!(
    "MAC-SYS-001",
    Os::MacOs,
    140,
    ("SIP et Gatekeeper", "SIP and Gatekeeper"),
    &[],
    || protection_systeme().into_iter().collect()
);

regle!(
    "MAC-SYS-002",
    Os::MacOs,
    150,
    ("volume système signé", "signed system volume"),
    &[],
    || durcissement::systeme_signe().into_iter().collect()
);

regle!(
    "MAC-SYS-003",
    Os::MacOs,
    160,
    ("extensions du noyau de tiers", "third-party kernel extensions"),
    &[],
    || vec![durcissement::extensions_tierces()]
);

regle!("MAC-PAR-001", Os::MacOs, 170, ("AirDrop", "AirDrop"), &[], || {
    durcissement::airdrop().into_iter().collect()
});

regle!(
    "MAC-RES-002",
    Os::MacOs,
    175,
    (
        "découverte automatique du proxy (WPAD)",
        "automatic proxy discovery (WPAD)"
    ),
    &[],
    || durcissement::decouverte_proxy().into_iter().collect()
);

regle!(
    "MAC-SES-001",
    Os::MacOs,
    180,
    ("verrouillage de l'écran", "screen lock"),
    &[],
    || verrouillage_ecran().into_iter().collect()
);

regle!(
    "MAC-SES-002",
    Os::MacOs,
    190,
    ("session ouverte toute seule", "automatic login"),
    &[],
    || ouverture_de_session().into_iter().collect()
);

regle!("MAC-CPT-001", Os::MacOs, 200, ("comptes", "accounts"), &[], || vec![
    comptes()
]);

regle!(
    "MAC-PRV-001",
    Os::MacOs,
    210,
    ("compte root activé", "root account enabled"),
    &[],
    || privileges::compte_root().into_iter().collect()
);

regle!(
    "MAC-PRV-002",
    Os::MacOs,
    220,
    ("sudo sans mot de passe", "passwordless sudo"),
    &[],
    || privileges::sudo_sans_mot_de_passe().into_iter().collect()
);

regle!(
    "MAC-PRV-003",
    Os::MacOs,
    230,
    (
        "fichiers secrets lisibles par d'autres",
        "secret files readable by others"
    ),
    &[],
    || privileges::fichiers_secrets().into_iter().collect()
);

regle!(
    "MAC-PRV-004",
    Os::MacOs,
    235,
    ("dossiers de commandes ouverts à tous", "command folders open to all"),
    &[],
    || privileges::dossiers_de_commandes().into_iter().collect()
);

regle!(
    "MAC-DIS-001",
    Os::MacOs,
    240,
    (
        "partage d'écran et gestion à distance",
        "screen sharing and remote management"
    ),
    &[],
    || gestion_a_distance().into_iter().collect()
);

regle!(
    "MAC-PRF-001",
    Os::MacOs,
    245,
    ("profils de configuration", "configuration profiles"),
    &[],
    || protection::profils_de_configuration().into_iter().collect()
);

regle!(
    "MAC-ANV-001",
    Os::MacOs,
    248,
    ("définitions de XProtect", "XProtect definitions"),
    &[],
    || vec![protection::xprotect()]
);

regle!(
    "MAC-MAJ-001",
    Os::MacOs,
    250,
    ("mises à jour automatiques", "automatic updates"),
    &[],
    || vec![mises_a_jour_automatiques()]
);

regle!(
    "MAC-MAJ-002",
    Os::MacOs,
    260,
    ("mises à jour en attente", "pending updates"),
    &[],
    || maj::mises_a_jour().into_iter().collect()
);

regle!("MAC-MAJ-003", Os::MacOs, 270, ("Homebrew", "Homebrew"), &[], || {
    maj::homebrew_a_jour().into_iter().collect()
});

regle!(
    "MAC-MAJ-004",
    Os::MacOs,
    275,
    ("logiciels pas à jour", "outdated software"),
    &[],
    crate::protection::perimes::constats
);

regle!(
    "MAC-SAV-001",
    Os::MacOs,
    280,
    ("sauvegardes Time Machine", "Time Machine backups"),
    &[],
    || vec![sauvegardes()]
);

regle!(
    "MAC-SAV-002",
    Os::MacOs,
    290,
    ("Time Machine chiffrée", "encrypted Time Machine"),
    &[],
    || sauvegarde_chiffree().into_iter().collect()
);

regle!(
    "MAC-PRS-001",
    Os::MacOs,
    300,
    ("ce qui se lance tout seul", "what starts by itself"),
    &[],
    || persistance().into_iter().collect()
);

regle!(
    "MAC-SSH-001",
    Os::MacOs,
    310,
    ("clés SSH du compte", "the account's SSH keys"),
    &[],
    || cles_ssh().into_iter().collect()
);

regle!(
    "MAC-SSH-002",
    Os::MacOs,
    320,
    ("session à distance (SSH)", "Remote Login (SSH)"),
    &[],
    || ssh_serveur().into_iter().collect()
);
