//! Cale : ce que les modules inclus demandent à `crate::reseau`. Seul `nmap::locale` est repris tel quel (il décide
//! quelles adresses une box peut donner) ; le reste ne sert qu'à parler au réseau, ce que le fuzzing ne fait jamais.

#![allow(dead_code)]

pub mod nmap {
    use std::net::Ipv4Addr;

    /// Comme `reseau::nmap::locale`.
    pub fn locale(ip: Ipv4Addr) -> bool {
        ip.is_private() || ip.is_link_local() || ip.is_loopback()
    }
}

pub mod nat {
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Instant;

    pub(crate) fn hasard() -> u64 {
        0
    }

    pub(crate) fn recevoir<T>(
        _socket: &UdpSocket,
        _fin: Instant,
        _tampon: &mut [u8],
        _lire: impl FnMut(&[u8], SocketAddr) -> Option<T>,
    ) -> Option<T> {
        None
    }
}

pub mod scan {
    use std::net::Ipv4Addr;

    pub fn reseau_local() -> Option<(String, Ipv4Addr)> {
        None
    }

    pub fn passerelle() -> Option<Ipv4Addr> {
        None
    }
}

/// Le dossier de Vanguard : un dossier qui n'existe pas, rien n'y est lu ni écrit pendant le fuzzing.
pub fn dossier_local() -> std::path::PathBuf {
    std::path::PathBuf::from("/nonexistent/vanguard-fuzz")
}
