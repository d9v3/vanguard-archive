//! Les règles du bilan de Linux, déclarées au registre (`machine::regles`) dans l'ordre où le bilan les montre. Les
//! vérifications restent dans leurs fichiers ; une nouvelle règle se déclare plutôt à côté de la sienne
//! (`plateforme.rs`).

use super::*;
use crate::machine::ParBilan;
use crate::machine::regles::{Os, regle};

/// Le pare-feu, lu une fois par bilan : sa règle et celle des ports le demandent en même temps, et deux lectures
/// pourraient se contredire.
static PARE_FEU: ParBilan<Constat> = ParBilan::new();

regle!("LNX-PFE-001", Os::Linux, 10, ("pare-feu", "firewall"), &[], || vec![
    PARE_FEU.lire(pare_feu)
]);

regle!(
    "LNX-RES-001",
    Os::Linux,
    100,
    ("services ouverts sur le réseau", "services open to the network"),
    &[],
    || {
        let actif = PARE_FEU.lire(pare_feu).probleme.is_none();
        ports_ecoute(actif, actif && ufw_actif())
    }
);

regle!(
    "LNX-CTN-001",
    Os::Linux,
    110,
    ("Docker exposé ou trop permis", "Docker exposed or over-permissive"),
    &[],
    || docker().into_iter().collect()
);

regle!(
    "LNX-SSH-001",
    Os::Linux,
    120,
    ("serveur SSH", "SSH server"),
    &[],
    || vec![ssh_serveur()]
);

regle!(
    "LNX-SSH-004",
    Os::Linux,
    125,
    (
        "ports renvoyés par SSH ouverts au réseau",
        "SSH-forwarded ports open to the network"
    ),
    &[],
    || ports_ssh().into_iter().collect()
);

regle!(
    "LNX-SSH-005",
    Os::Linux,
    126,
    ("réglages secondaires de sshd", "secondary sshd settings"),
    &[],
    || ssh_secondaire().into_iter().collect()
);

regle!(
    "LNX-SSH-002",
    Os::Linux,
    130,
    ("échecs de connexion SSH", "failed SSH logins"),
    &[],
    || ssh_echecs().into_iter().collect()
);

regle!(
    "LNX-MAJ-001",
    Os::Linux,
    140,
    ("mises à jour en attente", "pending updates"),
    &[],
    || vec![mises_a_jour()]
);

regle!(
    "LNX-MAJ-002",
    Os::Linux,
    150,
    ("mises à jour de sécurité automatiques", "automatic security updates"),
    &[],
    || maj_automatiques().into_iter().collect()
);

regle!(
    "LNX-MAJ-003",
    Os::Linux,
    160,
    ("failles connues des paquets", "known package flaws"),
    &[],
    || vec![failles_connues()]
);

regle!(
    "LNX-MAJ-004",
    Os::Linux,
    170,
    (
        "Flatpak, micrologiciels et autres mises à jour",
        "Flatpak, firmware and other updates"
    ),
    &[],
    || autres_mises_a_jour().into_iter().collect()
);

regle!(
    "LNX-MAJ-005",
    Os::Linux,
    180,
    ("redémarrage demandé", "restart required"),
    &[],
    || vec![redemarrage()]
);

regle!(
    "LNX-CHF-001",
    Os::Linux,
    190,
    ("chiffrement du disque", "disk encryption"),
    &[],
    || vec![chiffrement_disque()]
);

regle!(
    "LNX-SES-001",
    Os::Linux,
    200,
    ("session ouverte toute seule", "automatic login"),
    &[],
    || ouverture_automatique().into_iter().collect()
);

regle!(
    "LNX-SES-002",
    Os::Linux,
    210,
    ("verrouillage de l'écran", "screen lock"),
    &[],
    || verrouillage_ecran().into_iter().collect()
);

regle!(
    "LNX-SES-003",
    Os::Linux,
    220,
    ("affichage X11 ouvert", "open X11 display"),
    &[],
    || acces_x11().into_iter().collect()
);

regle!(
    "LNX-NOY-003",
    Os::Linux,
    230,
    (
        "réglages de sécurité du noyau (sysctl)",
        "kernel security settings (sysctl)"
    ),
    &[],
    || vec![durcissement_noyau()]
);

regle!(
    "LNX-NOY-004",
    Os::Linux,
    240,
    ("AppArmor ou SELinux", "AppArmor or SELinux"),
    &[],
    || vec![module_securite()]
);

regle!(
    "LNX-SAV-001",
    Os::Linux,
    250,
    ("sauvegardes et instantanés", "backups and snapshots"),
    &[],
    || vec![sauvegardes()]
);

regle!(
    "LNX-PRS-001",
    Os::Linux,
    260,
    ("fichiers suspects", "suspicious files"),
    &[],
    || fichiers_suspects().into_iter().collect()
);

regle!(
    "LNX-PRS-002",
    Os::Linux,
    270,
    ("persistance cachée", "hidden persistence"),
    &[],
    || persistance().into_iter().collect()
);

regle!(
    "LNX-DEM-001",
    Os::Linux,
    280,
    ("démarrage sécurisé (Secure Boot)", "Secure Boot"),
    &[],
    || vec![demarrage_securise()]
);

regle!(
    "LNX-SSH-003",
    Os::Linux,
    290,
    ("clés SSH du compte", "the account's SSH keys"),
    &[],
    || cles_ssh().into_iter().collect()
);

regle!(
    "LNX-PRV-001",
    Os::Linux,
    300,
    (
        "fichiers secrets lisibles par d'autres",
        "secret files readable by others"
    ),
    &[],
    || fichiers_secrets().into_iter().collect()
);

regle!(
    "LNX-MAT-001",
    Os::Linux,
    310,
    ("failles du processeur", "processor flaws"),
    &[],
    || vec![processeur()]
);

regle!(
    "LNX-PRV-002",
    Os::Linux,
    320,
    ("groupes équivalents à root", "root-equivalent groups"),
    &[],
    || groupes_privilegies().into_iter().collect()
);

regle!(
    "LNX-PRV-003",
    Os::Linux,
    330,
    ("sudo sans mot de passe", "passwordless sudo"),
    &[],
    || sudo_sans_mot_de_passe().into_iter().collect()
);

regle!(
    "LNX-PRV-004",
    Os::Linux,
    335,
    (
        "dossiers de commandes modifiables par d'autres",
        "command folders writable by others"
    ),
    &[],
    || dossiers_de_commandes().into_iter().collect()
);

regle!(
    "LNX-MAJ-006",
    Os::Linux,
    340,
    ("paquets de l'AUR", "AUR packages"),
    &[],
    || paquets_aur().into_iter().collect()
);

regle!(
    "LNX-CPT-001",
    Os::Linux,
    350,
    ("comptes aux droits root cachés", "hidden accounts with root rights"),
    &[],
    || vec![comptes()]
);

regle!(
    "LNX-WIF-001",
    Os::Linux,
    360,
    ("réseaux Wi-Fi", "Wi-Fi networks"),
    &[],
    || wifi(crate::reseau::scan::passerelle().map(|g| g.to_string()))
);

regle!(
    "LNX-SRV-001",
    Os::Linux,
    370,
    ("services en échec", "failed services"),
    &[],
    || vec![services_en_echec()]
);
