//! Les outils du groupe « Antivirus et protection » du menu : antivirus, YARA, fichiers-pièges, bac à sable,
//! intégrité des fichiers critiques, mots de passe fuités, connexions sortantes, logiciels de prise de contrôle à
//! distance (faux technicien), liens et fichiers téléchargés, caméra et micro, bilan de confidentialité
//! (`acces`), blocage des menaces, d'un clic ou tout seul pour le certain (`blocage`), l'interrupteur de la
//! protection en temps réel (`temps_reel`) ; et, sous Linux et macOS, la protection de la clé USB (`cle`).

pub(crate) mod abuse_ch;
pub mod acces;
pub mod antivirus;
pub mod blocage;
pub mod camera;
#[cfg(unix)]
pub mod cle;
pub mod cles_connues;
pub mod conteneurs;
pub mod distance;
pub(crate) mod empreintes;
pub mod environnement;
pub mod fuites;
pub mod integrite;
pub mod isoler;
pub mod kev;
pub mod lien;
pub mod manifeste;
pub mod memoire;
pub(crate) mod memoire_dns;
pub(crate) mod outil;
pub mod pieges;
pub mod quarantaine;
pub mod secrets_git;
pub mod sites_bloques;
pub mod sortantes;
pub mod telechargement;
pub(crate) mod temps_reel;
pub mod yara;
