//! Cale : ce que les modules inclus demandent à `crate::protection`. `sortantes::sur_internet` est repris tel quel
//! (il décide quelles adresses de la liste d'Échap sont gardées) ; `abuse_ch` ne sert qu'à télécharger, ce que le
//! fuzzing ne fait jamais : il répond « pas de réponse ».

#![allow(dead_code)]

pub mod sortantes {
    use std::net::IpAddr;

    /// Comme `protection::sortantes::sur_internet`.
    pub(crate) fn sur_internet(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let [a, b, ..] = v4.octets();
                !(v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_multicast()
                    || (a == 100 && (64..128).contains(&b)))
            }
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return sur_internet(IpAddr::V4(v4));
                }
                let s = v6.segments()[0];
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (s & 0xfe00) == 0xfc00
                    || (s & 0xffc0) == 0xfe80)
            }
        }
    }
}

pub mod abuse_ch {
    use std::time::Duration;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Echec {
        Reponse(u16),
        SansReponse,
        Illisible,
    }

    impl Echec {
        pub(crate) fn raison(self) -> String {
            format!("{self:?}")
        }
    }

    pub(crate) struct Liste;

    impl Liste {
        pub(crate) fn resultat(self, _avec_cle: bool) -> Result<(Vec<u8>, Duration), Echec> {
            Err(Echec::SansReponse)
        }
    }

    pub(crate) fn liste(
        _demande: crate::http::Demande,
        _lieu: (&str, &str),
        _fraiche: Duration,
        _valide: fn(&[u8]) -> bool,
    ) -> Liste {
        Liste
    }
}
