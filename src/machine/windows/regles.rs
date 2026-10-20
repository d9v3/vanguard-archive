//! Les règles du bilan de Windows, déclarées au registre (`machine::regles`) dans l'ordre où le bilan les montre. Les
//! vérifications restent dans leurs fichiers ; une nouvelle règle se déclare plutôt à côté de la sienne.

use super::*;
use crate::machine::ParBilan;
use crate::machine::regles::{Os, regle};

/// Lus une fois par bilan, et deux lectures pourraient se contredire : le pare-feu (sa règle et celles des ports TCP
/// et UDP le demandent en même temps) et l'adresse de ce PC sur le réseau local (les deux règles des ports).
static PARE_FEU: ParBilan<Constat> = ParBilan::new();
static ADRESSE: ParBilan<Option<String>> = ParBilan::new();

fn adresse_locale() -> Option<String> {
    crate::reseau::scan::reseau_local().map(|l| l.1.to_string())
}

regle!("WIN-PFE-001", Os::Windows, 10, ("pare-feu", "firewall"), &[], || vec![
    PARE_FEU.lire(pare_feu)
]);

regle!("WIN-ANV-001", Os::Windows, 100, ("antivirus", "antivirus"), &[], || {
    antivirus().into_iter().collect()
});

regle!(
    "WIN-ANV-002",
    Os::Windows,
    110,
    ("exclusions de Defender", "Defender exclusions"),
    &[],
    || exclusions::exclusions().into_iter().collect()
);

regle!(
    "WIN-RES-001",
    Os::Windows,
    120,
    ("services TCP ouverts sur le réseau", "TCP services open to the network"),
    &[],
    || {
        let actif = PARE_FEU.lire(pare_feu).probleme.is_none();
        let ip = ADRESSE.lire(adresse_locale);
        ports_ecoute(actif, ip.as_deref())
    }
);

regle!(
    "WIN-RES-002",
    Os::Windows,
    130,
    ("services UDP ouverts sur le réseau", "UDP services open to the network"),
    &[],
    || {
        let actif = PARE_FEU.lire(pare_feu).probleme.is_none();
        let ip = ADRESSE.lire(adresse_locale);
        ports_udp(actif, ip.as_deref())
    }
);

regle!("WIN-RES-003", Os::Windows, 140, ("SMBv1", "SMBv1"), &[], || smb1()
    .into_iter()
    .collect());

regle!(
    "WIN-DIS-001",
    Os::Windows,
    150,
    ("Bureau à distance", "Remote Desktop"),
    &[],
    || vec![bureau_distance()]
);

regle!(
    "WIN-PRV-001",
    Os::Windows,
    160,
    ("contrôle de compte d'utilisateur (UAC)", "User Account Control (UAC)"),
    &[],
    || vec![uac()]
);

regle!(
    "WIN-SES-001",
    Os::Windows,
    170,
    ("verrouillage de l'écran", "screen lock"),
    &[],
    || vec![verrouillage::verrouillage()]
);

regle!(
    "WIN-MAJ-001",
    Os::Windows,
    180,
    ("Windows Update", "Windows Update"),
    &[],
    || vec![mises_a_jour()]
);

regle!(
    "WIN-CHF-001",
    Os::Windows,
    190,
    ("chiffrement BitLocker", "BitLocker encryption"),
    &[],
    || vec![chiffrement()]
);

regle!(
    "WIN-DEM-001",
    Os::Windows,
    200,
    ("démarrage sécurisé (Secure Boot)", "Secure Boot"),
    &[],
    || durcissement::demarrage_securise().into_iter().collect()
);

regle!(
    "WIN-CPT-001",
    Os::Windows,
    210,
    ("comptes et administrateurs", "accounts and administrators"),
    &[],
    || comptes().into_iter().collect()
);

regle!(
    "WIN-CPT-002",
    Os::Windows,
    211,
    (
        "règle des mots de passe des comptes locaux",
        "local account password policy"
    ),
    &[],
    || politique().into_iter().collect()
);

regle!(
    "WIN-PRS-001",
    Os::Windows,
    220,
    ("ce qui se lance tout seul", "what starts by itself"),
    &[],
    || persistance().into_iter().collect()
);

regle!(
    "WIN-SRV-001",
    Os::Windows,
    230,
    ("services au chemin sans guillemets", "unquoted service paths"),
    &[],
    || services::services_sans_guillemets().into_iter().collect()
);

regle!(
    "WIN-WIF-001",
    Os::Windows,
    240,
    ("réseaux Wi-Fi", "Wi-Fi networks"),
    &[],
    || wifi().into_iter().collect()
);

regle!(
    "WIN-DUR-001",
    Os::Windows,
    250,
    (
        "durcissement (WDigest, LSA, NTLM, SMB, macros…)",
        "hardening (WDigest, LSA, NTLM, SMB, macros…)"
    ),
    &[],
    || durcissement::durcissement().into_iter().collect()
);
