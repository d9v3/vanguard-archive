//! Les réglages du blocage, gardés sur cet ordinateur seulement (blocage.json, comme appris.json) : un mode par
//! catégorie de menaces, et l'accord donné une fois pour la protection active.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{tr, trf};

/// Ce que Vanguard fait d'une menace d'une catégorie.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Mode {
    /// Rien n'est proposé : l'alerte du bilan reste, sans bouton.
    Desactive,
    /// Chaque menace propose « Bloquer » : le geste est montré, puis fait après accord.
    #[default]
    UnClic,
    /// Le certain est bloqué tout seul, puis notifié ; le douteux garde son bouton.
    Automatique,
}

impl Mode {
    pub(crate) const TOUS: [Mode; 3] = [Mode::Desactive, Mode::UnClic, Mode::Automatique];

    pub(crate) fn libelle(self) -> &'static str {
        match self {
            Mode::Desactive => tr!("désactivé", "off"),
            Mode::UnClic => tr!("un clic", "one click"),
            Mode::Automatique => tr!("automatique", "automatic"),
        }
    }

    /// Le mode d'un mot de la ligne de commande, en français ou en anglais.
    pub(crate) fn depuis_mot(mot: &str) -> Option<Mode> {
        match mot.trim().to_lowercase().as_str() {
            "off" | "non" | "no" | "desactive" | "désactivé" | "desactiver" | "désactiver" | "aucun" | "none" => {
                Some(Mode::Desactive)
            }
            "clic" | "click" | "un-clic" | "one-click" | "1clic" | "1click" | "manuel" | "manual" => Some(Mode::UnClic),
            "auto" | "automatique" | "automatic" | "actif" | "active" => Some(Mode::Automatique),
            _ => None,
        }
    }
}

/// Les quatre catégories de menaces, chacune avec son mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub(crate) enum Categorie {
    /// Logiciels malveillants et outils d'attaque : arrêt du processus, puis quarantaine du fichier.
    Programmes,
    /// Connexions vers un serveur de commande : règle de pare-feu sortante.
    Connexions,
    /// Lancements automatiques malveillants, et la liste de blocage des pilotes vulnérables (Windows).
    Demarrage,
    /// Serveurs d'IA ouverts au réseau, agents réglés pour tout faire sans demander.
    AgentsIa,
}

impl Categorie {
    pub(crate) const TOUTES: [Categorie; 4] = [
        Categorie::Programmes,
        Categorie::Connexions,
        Categorie::Demarrage,
        Categorie::AgentsIa,
    ];

    pub(crate) fn titre(self) -> &'static str {
        match self {
            Categorie::Programmes => tr!("Programmes malveillants", "Malicious programs"),
            Categorie::Connexions => tr!("Connexions dangereuses", "Dangerous connections"),
            Categorie::Demarrage => tr!("Démarrage et pilotes", "Startup and drivers"),
            Categorie::AgentsIa => tr!("Agents et serveurs d'IA", "AI agents and servers"),
        }
    }

    /// Ce que le blocage y fait, en une phrase.
    pub(crate) fn geste(self) -> &'static str {
        match self {
            Categorie::Programmes => tr!(
                "arrêter le processus, puis mettre son fichier en quarantaine",
                "stop the process, then quarantine its file"
            ),
            Categorie::Connexions => tr!(
                "règle de pare-feu sortante vers l'adresse du serveur",
                "outbound firewall rule to the server's address"
            ),
            Categorie::Demarrage => tr!(
                "retirer le lancement automatique ; pilotes vulnérables bloqués (Windows)",
                "remove the automatic start; vulnerable drivers blocked (Windows)"
            ),
            Categorie::AgentsIa => tr!(
                "fermer au réseau un serveur d'IA ; remettre les demandes de permission",
                "close an AI server to the network; bring permission prompts back"
            ),
        }
    }

    /// Y a-t-il là quelque chose de certain ? Seules ces catégories peuvent bloquer toutes seules : une empreinte de
    /// MalwareBazaar, un outil d'attaque connu, un serveur de commande. Un lancement automatique douteux ou un
    /// réglage d'agent ne le sont jamais assez.
    pub(crate) fn a_du_certain(self) -> bool {
        matches!(self, Categorie::Programmes | Categorie::Connexions)
    }

    /// Le mot de la ligne de commande.
    pub(crate) fn mot(self) -> &'static str {
        match self {
            Categorie::Programmes => tr!("programmes", "programs"),
            Categorie::Connexions => tr!("connexions", "connections"),
            Categorie::Demarrage => tr!("demarrage", "startup"),
            Categorie::AgentsIa => tr!("agents", "agents"),
        }
    }

    /// La catégorie d'un mot de la ligne de commande, en français ou en anglais.
    pub(crate) fn depuis_mot(mot: &str) -> Option<Categorie> {
        match mot.trim().to_lowercase().as_str() {
            "programmes" | "programme" | "programs" | "program" | "malware" | "a" => Some(Categorie::Programmes),
            "connexions" | "connexion" | "connections" | "connection" | "reseau" | "réseau" | "network" | "b" => {
                Some(Categorie::Connexions)
            }
            "demarrage" | "démarrage" | "startup" | "pilotes" | "drivers" | "c" => Some(Categorie::Demarrage),
            "agents" | "agent" | "ia" | "ai" | "agents-ia" | "ai-agents" | "d" => Some(Categorie::AgentsIa),
            _ => None,
        }
    }
}

/// Les réglages, tels que gardés dans blocage.json.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone)]
pub(crate) struct Parametres {
    /// L'accord pour la protection active (« AAAA-MM-JJ HH:MM »), donné une fois ; `None` : jamais donné, et
    /// « automatique » vaut alors un clic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accord: Option<String>,
    #[serde(default)]
    pub programmes: Mode,
    #[serde(default)]
    pub connexions: Mode,
    #[serde(default)]
    pub demarrage: Mode,
    #[serde(default)]
    pub agents_ia: Mode,
}

impl Parametres {
    /// Le mode réglé pour cette catégorie, tel qu'écrit.
    pub(crate) fn mode(&self, c: Categorie) -> Mode {
        match c {
            Categorie::Programmes => self.programmes,
            Categorie::Connexions => self.connexions,
            Categorie::Demarrage => self.demarrage,
            Categorie::AgentsIa => self.agents_ia,
        }
    }

    /// Règle le mode d'une catégorie ; « automatique » là où rien n'est certain est refusé (`Err` : pourquoi).
    pub(crate) fn regler(&mut self, c: Categorie, m: Mode) -> Result<(), String> {
        if m == Mode::Automatique && !c.a_du_certain() {
            return Err(trf!(
                "« {} » n'a rien de certain : jamais automatique, désactivé ou un clic seulement.",
                "“{}” has nothing certain: never automatic, only off or one click.",
                c.titre()
            ));
        }
        *match c {
            Categorie::Programmes => &mut self.programmes,
            Categorie::Connexions => &mut self.connexions,
            Categorie::Demarrage => &mut self.demarrage,
            Categorie::AgentsIa => &mut self.agents_ia,
        } = m;
        Ok(())
    }

    /// Le mode qui s'applique vraiment : automatique seulement avec l'accord, et là où quelque chose est certain ;
    /// sinon un clic.
    pub(crate) fn effectif(&self, c: Categorie) -> Mode {
        match self.mode(c) {
            Mode::Automatique if self.accord.is_none() || !c.a_du_certain() => Mode::UnClic,
            m => m,
        }
    }

    /// La protection active tourne-t-elle (au moins une catégorie réellement automatique) ?
    pub(crate) fn actif(&self) -> bool {
        Categorie::TOUTES.iter().any(|&c| self.effectif(c) == Mode::Automatique)
    }

    /// Tout est-il désactivé ? Alors le bilan ne cherche même pas.
    pub(crate) fn rien(&self) -> bool {
        Categorie::TOUTES.iter().all(|&c| self.effectif(c) == Mode::Desactive)
    }
}

/// Ce que la protection fait d'une menace trouvée.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Decision {
    /// Bloquée toute seule, puis notifiée.
    Auto,
    /// « Bloquer » proposé : le geste est montré, puis fait après accord.
    UnClic,
    /// Rien : la catégorie est désactivée (l'alerte du bilan reste).
    Rien,
}

/// Bloquer tout seul demande les trois : la catégorie réglée sur automatique, l'accord donné, une menace certaine.
pub(crate) fn decider(p: &Parametres, c: Categorie, certaine: bool) -> Decision {
    match p.effectif(c) {
        Mode::Desactive => Decision::Rien,
        Mode::Automatique if certaine => Decision::Auto,
        Mode::Automatique | Mode::UnClic => Decision::UnClic,
    }
}

fn fichier() -> PathBuf {
    crate::reseau::dossier_local().join("blocage.json")
}

/// Les réglages ; `Err` (la raison) si le fichier existe mais ne se lit pas : les défauts servent, sans automatique,
/// et rien ne l'écrase en silence.
pub(crate) fn charger() -> Result<Parametres, String> {
    charger_de(&fichier())
}

fn charger_de(chemin: &Path) -> Result<Parametres, String> {
    match std::fs::read_to_string(chemin) {
        Ok(texte) => serde_json::from_str(texte.trim_start_matches('\u{feff}')).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Parametres::default()),
        Err(e) => Err(e.to_string()),
    }
}

pub(crate) fn enregistrer(p: &Parametres) -> std::io::Result<()> {
    enregistrer_dans(p, &fichier())
}

fn enregistrer_dans(p: &Parametres, chemin: &Path) -> std::io::Result<()> {
    if let Some(d) = chemin.parent() {
        std::fs::create_dir_all(d)?;
    }
    let texte = serde_json::to_string_pretty(p).map_err(std::io::Error::other)?;
    crate::reseau::ecrire_atomique(chemin, texte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn par_defaut_un_clic_partout() {
        let p = Parametres::default();
        for c in Categorie::TOUTES {
            assert_eq!(p.effectif(c), Mode::UnClic);
        }
        assert!(!p.actif() && !p.rien());
    }

    /// Garde-fou : automatique ne vaut que pour une catégorie réglée ainsi, avec l'accord, et pour le certain.
    #[test]
    fn automatique_seulement_avec_accord_et_pour_le_certain() {
        let mut p = Parametres::default();
        p.regler(Categorie::Connexions, Mode::Automatique).unwrap();
        // Sans accord : un clic, même pour le certain.
        assert_eq!(decider(&p, Categorie::Connexions, true), Decision::UnClic);
        assert!(!p.actif());
        p.accord = Some("2026-10-21 20:00".into());
        assert!(p.actif());
        assert_eq!(decider(&p, Categorie::Connexions, true), Decision::Auto);
        // Le douteux garde son bouton.
        assert_eq!(decider(&p, Categorie::Connexions, false), Decision::UnClic);
        // Une autre catégorie, restée sur un clic, ne bloque rien toute seule.
        assert_eq!(decider(&p, Categorie::Programmes, true), Decision::UnClic);
        // Désactivé : rien.
        p.regler(Categorie::Programmes, Mode::Desactive).unwrap();
        assert_eq!(decider(&p, Categorie::Programmes, true), Decision::Rien);
        // Rien de certain au démarrage ni chez les agents : automatique refusé, et un fichier écrit à la main qui le
        // dirait vaut un clic.
        assert!(p.regler(Categorie::Demarrage, Mode::Automatique).is_err());
        assert!(p.regler(Categorie::AgentsIa, Mode::Automatique).is_err());
        p.agents_ia = Mode::Automatique;
        assert_eq!(decider(&p, Categorie::AgentsIa, true), Decision::UnClic);
    }

    #[test]
    fn reglages_ecrits_relus_ou_refuses() {
        let d = std::env::temp_dir().join(format!("vanguard-blocage-reglages-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let f = d.join("blocage.json");
        // Absent : les défauts.
        assert_eq!(charger_de(&f).unwrap(), Parametres::default());
        let p = Parametres {
            accord: Some("2026-10-21 20:00".into()),
            programmes: Mode::Automatique,
            connexions: Mode::Automatique,
            demarrage: Mode::UnClic,
            agents_ia: Mode::Desactive,
        };
        enregistrer_dans(&p, &f).unwrap();
        let texte = std::fs::read_to_string(&f).unwrap();
        assert!(texte.contains("\"programmes\": \"automatique\"") && texte.contains("\"agents_ia\": \"desactive\""));
        assert_eq!(charger_de(&f).unwrap(), p);
        // Un champ manquant (version d'avant) prend sa valeur par défaut.
        std::fs::write(&f, "{\"connexions\": \"un-clic\"}").unwrap();
        assert_eq!(charger_de(&f).unwrap(), Parametres::default());
        // Abîmé : refusé, jamais lu comme des défauts qu'on réécrirait par-dessus.
        std::fs::write(&f, "{pas du json").unwrap();
        assert!(charger_de(&f).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn mots_de_la_ligne_de_commande() {
        assert_eq!(Categorie::depuis_mot("Connexions"), Some(Categorie::Connexions));
        assert_eq!(Categorie::depuis_mot("startup"), Some(Categorie::Demarrage));
        assert_eq!(Categorie::depuis_mot("ai"), Some(Categorie::AgentsIa));
        assert_eq!(Categorie::depuis_mot("programs"), Some(Categorie::Programmes));
        assert_eq!(Categorie::depuis_mot("tout"), None);
        assert_eq!(Mode::depuis_mot("auto"), Some(Mode::Automatique));
        assert_eq!(Mode::depuis_mot("one-click"), Some(Mode::UnClic));
        assert_eq!(Mode::depuis_mot("Désactivé"), Some(Mode::Desactive));
        assert_eq!(Mode::depuis_mot("peut-être"), None);
        for c in Categorie::TOUTES {
            assert_eq!(Categorie::depuis_mot(c.mot()), Some(c));
        }
    }
}
