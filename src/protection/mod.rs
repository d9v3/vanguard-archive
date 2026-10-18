//! Les outils du groupe « Antivirus et protection » du menu : antivirus, YARA, fichiers-pièges, bac à sable,
//! intégrité des fichiers critiques, mots de passe fuités, connexions sortantes, logiciels de prise de contrôle à
//! distance (faux technicien), liens et fichiers téléchargés ; et,
//! sous Linux et macOS, la protection de la clé USB (`cle`).

pub mod antivirus;
#[cfg(unix)]
pub mod cle;
pub mod distance;
pub mod fuites;
pub mod integrite;
pub mod isoler;
pub mod lien;
pub mod pieges;
pub mod sortantes;
pub mod telechargement;
pub mod yara;
