//! Base de connaissances : service attendu sur chaque port et niveau de risque.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Niveau {
    Info,
    Moyen,
    Eleve,
    Critique,
}

impl Niveau {
    pub fn libelle(self) -> &'static str {
        match self {
            Niveau::Info => "INFO",
            Niveau::Moyen => "MOYEN",
            Niveau::Eleve => "ÉLEVÉ",
            Niveau::Critique => "CRITIQUE",
        }
    }

    pub fn penalite(self) -> u32 {
        match self {
            Niveau::Info => 0,
            Niveau::Moyen => 5,
            Niveau::Eleve => 15,
            Niveau::Critique => 30,
        }
    }
}

pub struct InfoPort {
    pub service: &'static str,
    pub niveau: Niveau,
    pub conseil: &'static str,
}

/// Ports scannés par défaut (TCP courants sur un réseau domestique).
pub const PORTS_COURANTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 512, 513, 514, 515, 548, 554, 587,
    631, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2375, 2376, 3000, 3128, 3306, 3389, 3689, 4444, 5000,
    5001, 5432, 5555, 5900, 5901, 6379, 6443, 7000, 7070, 7547, 8000, 8008, 8009, 8080, 8081, 8086, 8088, 8123, 8200,
    8443, 8888, 9000, 9090, 9100, 9200, 9443, 10000, 11211, 27017, 32400, 49152, 62078,
];

/// Ports utilisés pour savoir si une machine est en ligne.
pub const PORTS_DECOUVERTE: &[u16] = &[80, 443, 22, 445, 139, 53, 8080, 62078, 7000, 8009];

/// Ports où l'on envoie une requête HTTP pour lire l'en-tête `Server`.
pub const PORTS_HTTP: &[u16] = &[
    80, 81, 3000, 5000, 7547, 8000, 8008, 8080, 8081, 8086, 8088, 8123, 8888, 9000, 9090, 10000, 32400,
];

pub fn info_port(port: u16) -> InfoPort {
    use Niveau::{Critique, Eleve, Info, Moyen};
    let (service, niveau, conseil) = match port {
        21 => (
            "FTP",
            Eleve,
            "Identifiants et fichiers circulent en clair. Préférer SFTP.",
        ),
        22 => ("SSH", Info, "OK si authentification par clé et mot de passe désactivé."),
        23 => (
            "Telnet",
            Critique,
            "Protocole en clair, très ciblé par les botnets. À désactiver.",
        ),
        25 | 465 | 587 => (
            "SMTP",
            Moyen,
            "Serveur mail : vérifier qu'il n'est pas un relais ouvert.",
        ),
        53 => ("DNS", Info, "Normal sur le routeur ; suspect sur une autre machine."),
        80 | 81 => (
            "HTTP",
            Moyen,
            "Interface web non chiffrée : mots de passe visibles sur le réseau.",
        ),
        88 => ("Kerberos", Info, "Service d'authentification."),
        110 | 143 => ("POP3/IMAP", Moyen, "Mail en clair ; préférer 993/995."),
        111 => ("rpcbind", Eleve, "Expose les services RPC/NFS. À fermer si inutile."),
        135 => ("MS-RPC", Eleve, "Service Windows souvent exploité. Ne pas exposer."),
        139 => (
            "NetBIOS",
            Eleve,
            "Partage Windows ancien (SMBv1 possible). Désactiver NetBIOS.",
        ),
        389 => ("LDAP", Moyen, "Annuaire en clair ; préférer LDAPS (636)."),
        443 | 8443 | 9443 => ("HTTPS", Info, "Web chiffré. Vérifier que l'interface est à jour."),
        445 => (
            "SMB",
            Eleve,
            "Partage de fichiers (WannaCry…). Désactiver SMBv1, mots de passe forts.",
        ),
        512..=514 => (
            "rsh/rlogin",
            Critique,
            "Accès distant sans chiffrement, obsolète. À désactiver.",
        ),
        515 | 631 => (
            "Impression",
            Moyen,
            "Imprimante/CUPS : vérifier le firmware et l'accès admin.",
        ),
        548 => ("AFP", Moyen, "Partage Apple obsolète. Préférer SMB récent."),
        554 => (
            "RTSP",
            Moyen,
            "Flux vidéo (caméra IP ?). Vérifier qu'il exige un mot de passe.",
        ),
        636 => ("LDAPS", Info, "Annuaire chiffré."),
        873 => ("rsync", Eleve, "Démon rsync : souvent sans authentification."),
        993 | 995 => ("IMAPS/POP3S", Info, "Mail chiffré."),
        1080 | 3128 => (
            "Proxy",
            Eleve,
            "Proxy ouvert : peut servir de rebond. Restreindre l'accès.",
        ),
        1433 => ("MS-SQL", Eleve, "Base de données exposée sur le réseau."),
        1521 => ("Oracle DB", Eleve, "Base de données exposée sur le réseau."),
        1723 => ("PPTP", Eleve, "VPN au chiffrement cassé. Passer à WireGuard/OpenVPN."),
        1883 => (
            "MQTT",
            Moyen,
            "Domotique : vérifier qu'une authentification est exigée.",
        ),
        2049 => ("NFS", Eleve, "Partage NFS : vérifier /etc/exports (pas de * en rw)."),
        2375 => (
            "Docker API",
            Critique,
            "API Docker sans TLS = accès root à la machine. Fermer immédiatement.",
        ),
        2376 => (
            "Docker API TLS",
            Moyen,
            "API Docker chiffrée : vérifier les certificats clients.",
        ),
        3000 | 5000 | 5001 | 8000 | 8081 | 8088 | 8888 | 9000 | 9090 => (
            "Web/app",
            Moyen,
            "Service web de dev ou d'admin : vérifier qu'il doit être joignable.",
        ),
        3306 => ("MySQL", Eleve, "Base de données exposée sur le réseau."),
        3389 => (
            "RDP",
            Eleve,
            "Bureau à distance Windows, très attaqué. NLA + mot de passe fort.",
        ),
        3689 => ("DAAP/iTunes", Info, "Partage multimédia Apple."),
        4444 => (
            "Inconnu (4444)",
            Critique,
            "Port typique de backdoor/Metasploit. À investiguer.",
        ),
        5432 => ("PostgreSQL", Eleve, "Base de données exposée sur le réseau."),
        5555 => (
            "ADB Android",
            Critique,
            "Débogage Android ouvert = contrôle total de l'appareil.",
        ),
        5900 | 5901 => (
            "VNC",
            Eleve,
            "Bureau à distance souvent mal protégé. Mot de passe fort ou tunnel SSH.",
        ),
        6379 => (
            "Redis",
            Critique,
            "Redis souvent sans mot de passe = exécution de code possible.",
        ),
        6443 => ("Kubernetes API", Moyen, "API Kubernetes : vérifier l'authentification."),
        7000 | 7070 => ("AirPlay", Info, "Diffusion Apple/AirPlay."),
        7547 => ("TR-069", Eleve, "Gestion à distance du FAI, historiquement vulnérable."),
        8008 | 8009 => ("Chromecast", Info, "Appareil Google Cast."),
        8080 => ("HTTP alt", Moyen, "Interface web non chiffrée (proxy, admin, caméra…)."),
        8086 => (
            "InfluxDB",
            Moyen,
            "Base de séries temporelles : vérifier l'authentification.",
        ),
        8123 => ("Home Assistant", Info, "Domotique : garder à jour, activer la 2FA."),
        8200 => ("Vault/DLNA", Moyen, "Vérifier l'authentification."),
        9100 => ("Impression RAW", Moyen, "N'importe qui peut envoyer des impressions."),
        9200 => (
            "Elasticsearch",
            Critique,
            "Souvent sans authentification : fuite de données.",
        ),
        10000 => ("Webmin", Eleve, "Admin système web, cible fréquente. Garder à jour."),
        11211 => (
            "Memcached",
            Critique,
            "Sans authentification, utilisé pour l'amplification DDoS.",
        ),
        27017 => ("MongoDB", Critique, "Souvent sans authentification : fuite de données."),
        32400 => ("Plex", Info, "Serveur multimédia Plex."),
        49152 => (
            "UPnP",
            Moyen,
            "UPnP/IGD : peut ouvrir des ports sur le routeur. Désactiver si inutile.",
        ),
        62078 => ("iPhone sync", Info, "Appareil iOS (synchronisation lockdownd)."),
        // Services surtout UDP, vus par l'audit de la machine.
        69 => (
            "TFTP",
            Eleve,
            "Transfert de fichiers sans aucune authentification. À désactiver.",
        ),
        123 => ("NTP", Info, "Synchronisation de l'heure."),
        137 | 138 => ("NetBIOS", Moyen, "Ancien partage Windows/Samba : à couper si inutile."),
        161 => (
            "SNMP",
            Eleve,
            "Supervision réseau : avec la communauté « public », n'importe qui lit la configuration.",
        ),
        500 | 4500 => ("VPN IPsec", Info, "VPN IPsec : normal si tu l'utilises."),
        1900 => (
            "UPnP/SSDP",
            Moyen,
            "Découverte UPnP : à couper si aucun appareil n'en a besoin.",
        ),
        3702 => ("WS-Discovery", Info, "Découverte d'imprimantes et de partages."),
        5353 => (
            "mDNS",
            Info,
            "Découverte locale (Avahi, Bonjour) : normal sur un réseau domestique.",
        ),
        5355 => (
            "LLMNR",
            Moyen,
            "Résolution de noms locale, usurpable par une machine du réseau : à désactiver si possible.",
        ),
        51820 => ("WireGuard", Info, "VPN WireGuard : normal si tu l'utilises."),
        5040 => (
            "Windows CDP",
            Info,
            "Plateforme d'appareils connectés de Windows (normal).",
        ),
        5357 => (
            "Windows WSD",
            Info,
            "Découverte réseau de Windows (imprimantes, partages) : normal sur un réseau privé.",
        ),
        7680 => (
            "Windows Update P2P",
            Info,
            "Optimisation de la distribution de Windows Update (normal).",
        ),
        1716 => (
            "KDE Connect",
            Info,
            "Liaison téléphone/PC : n'apparier que tes propres appareils.",
        ),
        11434 => (
            "Ollama",
            Eleve,
            "API d'IA locale sans authentification : ne l'exposer qu'en 127.0.0.1.",
        ),
        27036 | 27037 => (
            "Steam Remote Play",
            Info,
            "Diffusion locale Steam. Désactivable dans Steam > Remote Play.",
        ),
        57621 => ("Spotify Connect", Info, "Découverte Spotify sur le réseau local."),
        _ => ("Inconnu", Moyen, "Service non identifié : vérifier ce qui écoute."),
    };
    InfoPort {
        service,
        niveau,
        conseil,
    }
}

/// Reconnaît un service d'après ce qu'il annonce, quel que soit son port.
/// Retourne le port « type » de ce service, dont on reprend le nom et le niveau de risque.
pub fn identifier(banniere: &str) -> Option<u16> {
    let l = banniere.to_ascii_lowercase();
    let d = |p: &str| l.starts_with(p);
    Some(match () {
        () if d("ssh-") => 22,
        () if d("http · ") => 8080,
        () if d("220") && l.contains("ftp") => 21,
        () if d("220") && (l.contains("smtp") || l.contains("mail")) => 25,
        () if d("+ok") => 110,
        () if d("* ok") => 143,
        () if d("-noauth") || d("+pong") || (d("-err") && l.contains("redis")) => 6379,
        () if d("rfb ") => 5900,
        () if l.contains("mysql_native_password") || l.contains("mariadb") => 3306,
        () => return None,
    })
}

/// Note globale à partir d'un score sur 100.
pub fn note(score: u32) -> &'static str {
    match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_reconnus_a_leur_banniere() {
        assert_eq!(identifier("SSH-2.0-OpenSSH_9.8"), Some(22));
        assert_eq!(identifier("220 (vsFTPd 2.3.4)"), Some(21));
        assert_eq!(identifier("220 mail.exemple.fr ESMTP Postfix"), Some(25));
        assert_eq!(identifier("HTTP · nginx/1.27"), Some(8080));
        assert_eq!(identifier("-NOAUTH Authentication required."), Some(6379));
        assert_eq!(identifier("RFB 003.008"), Some(5900));
        assert_eq!(identifier("bonjour"), None);
    }

    #[test]
    fn notes() {
        assert_eq!(note(100), "A");
        assert_eq!(note(75), "B");
        assert_eq!(note(60), "C");
        assert_eq!(note(40), "D");
        assert_eq!(note(0), "F");
    }
}
