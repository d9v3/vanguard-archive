//! Docker : ports publiés qui passent devant le pare-feu, lus même sans le groupe docker.

use super::*;

/// Ports de conteneurs joignables depuis le réseau, dans la colonne « Ports » de `docker ps` : tout sauf la
/// boucle locale (127.x, ::1). Une IP du réseau local (`-p 10.0.0.5:8080:80`) est aussi exposée.
/// Ex. « 0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 127.0.0.1:3389->3389/tcp » → [« 8080/tcp »].
pub(super) fn ports_docker_exposes(colonne: &str) -> Vec<String> {
    let mut ports: Vec<String> = colonne
        .split(", ")
        .filter_map(|p| {
            let (hote, _) = p.split_once("->")?;
            let (adresse, port) = hote.rsplit_once(':')?;
            let proto = p.rsplit_once('/').map_or("tcp", |(_, pr)| pr);
            let ip = adresse.trim_matches(|c| c == '[' || c == ']');
            let locale = ip.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback());
            (!locale).then(|| format!("{port}/{proto}"))
        })
        .collect();
    ports.dedup();
    ports
}

/// Docker écrit ses propres règles et passe devant ufw : un port publié sur 0.0.0.0 est joignable
/// depuis le réseau même avec le pare-feu actif.
pub(super) fn docker() -> Vec<Constat> {
    if !["/usr/bin/docker", "/bin/docker", "/usr/local/bin/docker"]
        .iter()
        .any(|d| Path::new(d).exists())
    {
        return vec![];
    }
    let Some(liste) = sortie_delai("docker", &["ps", "--format", "{{.Names}}\t{{.Ports}}"], 15, &[0]) else {
        return vec![docker_sans_acces(&processus())];
    };
    let mut constats = Vec::new();
    let mut actifs = 0;
    for ligne in liste.lines() {
        let (nom, colonne) = ligne.split_once('\t').unwrap_or((ligne, ""));
        actifs += 1;
        let exposes = ports_docker_exposes(colonne);
        if exposes.is_empty() {
            continue;
        }
        constats.push(
            alerte(
                "Docker",
                Niveau::Eleve,
                trf!(
                    "Conteneur « {nom} » : port(s) {} publié(s) hors de la boucle locale. Docker passe devant le pare-feu : joignable(s) depuis le réseau.", "Container “{nom}”: port(s) {} published outside the loopback. Docker bypasses the firewall: reachable from the network.",
                    exposes.join(", ")
                ),
            )
            .manuel(
                tr!("Publier seulement en local, puis recréer le conteneur : -p 127.0.0.1:PORT:PORT, ou dans docker-compose « \"127.0.0.1:PORT:PORT\" »", "Publish locally only, then recreate the container: -p 127.0.0.1:PORT:PORT, or in docker-compose “\"127.0.0.1:PORT:PORT\"”"),
                &[],
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            "Docker",
            trf!(
                "Aucun port de conteneur exposé au réseau ({actifs} conteneur(s) actif(s)).",
                "No container port exposed to the network ({actifs} running container(s))."
            ),
        ));
    }
    constats
}

/// Nom et ligne de commande de chaque processus, lus dans /proc (lisible par tous, sauf montage « hidepid »).
pub(super) fn processus() -> Vec<(String, Vec<String>)> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().bytes().all(|o| o.is_ascii_digit()))
        .filter_map(|e| {
            let nom = std::fs::read_to_string(e.path().join("comm")).ok()?.trim().to_string();
            let args = std::fs::read(e.path().join("cmdline"))
                .unwrap_or_default()
                .split(|&o| o == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect();
            Some((nom, args))
        })
        .collect()
}

/// Port publié par un processus docker-proxy : (adresse de l'hôte, « 8080/tcp »).
/// Ligne de commande : « -proto tcp -host-ip 0.0.0.0 -host-port 8080 -container-ip 172.17.0.2 -container-port 80 ».
pub(super) fn port_docker_proxy(args: &[String]) -> Option<(String, String)> {
    let valeur = |cle: &str| {
        args.iter()
            .position(|a| a == cle)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let proto = valeur("-proto").unwrap_or_else(|| "tcp".into());
    Some((valeur("-host-ip")?, format!("{}/{proto}", valeur("-host-port")?)))
}

/// Docker sans accès au démon (on n'est pas dans le groupe docker, et c'est mieux ainsi : ce groupe vaut root).
/// Les processus restent visibles : un « containerd-shim » par conteneur actif, un « docker-proxy » par port publié,
/// avec l'adresse et le port dans sa ligne de commande. De quoi conclure dans la plupart des cas.
pub(super) fn docker_sans_acces(procs: &[(String, Vec<String>)]) -> Constat {
    // /proc masqué (hidepid) : on ne verrait aucun processus d'un autre compte, donc on ne conclut rien.
    if !procs.iter().any(|(n, _)| n == "dockerd") {
        return impossible(
            "Docker",
            tr!(
                "démon arrêté ou processus d'un autre compte masqués",
                "daemon stopped or processes of another account hidden"
            ),
        );
    }
    let conteneurs = procs.iter().filter(|(n, _)| n.starts_with("containerd-shim")).count();
    if conteneurs == 0 {
        return ok("Docker", tr!("Aucun conteneur actif.", "No running container."));
    }
    let mut exposes: Vec<String> = procs
        .iter()
        .filter(|(n, _)| n == "docker-proxy")
        .filter_map(|(_, args)| port_docker_proxy(args))
        .filter(|(ip, _)| {
            !ip.trim_matches(|c| c == '[' || c == ']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|a| a.is_loopback())
        })
        .map(|(_, port)| port)
        .collect();
    exposes.sort();
    exposes.dedup();
    if !exposes.is_empty() {
        return alerte(
            "Docker",
            Niveau::Eleve,
            trf!(
                "{conteneurs} conteneur(s) actif(s), port(s) {} publié(s) hors de la boucle locale. Docker passe devant le pare-feu : joignable(s) depuis le réseau.", "{conteneurs} running container(s), port(s) {} published outside the loopback. Docker bypasses the firewall: reachable from the network.",
                exposes.join(", ")
            ),
        )
        .manuel(
            tr!("Publier seulement en local, puis recréer le conteneur : -p 127.0.0.1:PORT:PORT, ou dans docker-compose « \"127.0.0.1:PORT:PORT\" »", "Publish locally only, then recreate the container: -p 127.0.0.1:PORT:PORT, or in docker-compose “\"127.0.0.1:PORT:PORT\"”"),
            &[],
        );
    }
    // Sans docker-proxy, un port publié passe seulement par le pare-feu de Docker, illisible sans root.
    let sans_proxy = std::fs::read_to_string("/etc/docker/daemon.json")
        .is_ok_and(|t| t.replace(' ', "").contains("\"userland-proxy\":false"));
    if sans_proxy {
        impossible(
            "Docker",
            tr!(
                "conteneurs actifs et userland-proxy coupé : ports publiés illisibles sans le groupe docker",
                "running containers and userland-proxy off: published ports unreadable without the docker group"
            ),
        )
    } else {
        ok(
            "Docker",
            trf!(
                "{conteneurs} conteneur(s) actif(s), aucun port publié hors de la boucle locale.",
                "{conteneurs} running container(s), no port published outside the loopback."
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_docker() {
        let c = "0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 127.0.0.1:3389->3389/tcp, 0.0.0.0:53->53/udp, 9000/tcp";
        assert_eq!(ports_docker_exposes(c), vec!["8080/tcp", "53/udp"]);
        assert_eq!(
            ports_docker_exposes("127.0.0.1:8006->8006/tcp, [::1]:8006->8006/tcp"),
            [] as [std::string::String; 0]
        );
        // Publié sur l'IP du réseau local : exposé aussi.
        assert_eq!(ports_docker_exposes("10.0.0.179:8080->80/tcp"), vec!["8080/tcp"]);
        assert_eq!(ports_docker_exposes(":::9000->9000/tcp"), vec!["9000/tcp"]);
        assert_eq!(ports_docker_exposes(""), [] as [std::string::String; 0]);
    }

    #[test]
    fn docker_lu_sans_le_groupe_docker() {
        let p = |nom: &str, args: &str| (nom.to_string(), args.split(' ').map(str::to_string).collect::<Vec<_>>());
        let dockerd = p("dockerd", "/usr/bin/dockerd -H fd://");
        let shim = p("containerd-shim", "/usr/bin/containerd-shim-runc-v2 -namespace moby");
        let local = p(
            "docker-proxy",
            "/usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8006 -container-ip 172.17.0.2 -container-port 8006",
        );
        let ouvert = p(
            "docker-proxy",
            "/usr/bin/docker-proxy -proto udp -host-ip 0.0.0.0 -host-port 53 -container-ip 172.17.0.3 -container-port 53",
        );
        // Démon actif, aucun conteneur : vérifié, rien à signaler.
        let c = docker_sans_acces(std::slice::from_ref(&dockerd));
        assert!(c.verifie && c.probleme.is_none());
        // Conteneur publié seulement en local : rien à signaler.
        let c = docker_sans_acces(&[dockerd.clone(), shim.clone(), local.clone()]);
        assert!(c.verifie && c.probleme.is_none());
        // Port publié sur toutes les interfaces : alerte, avec le port.
        let c = docker_sans_acces(&[dockerd.clone(), shim, local, ouvert]);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("53/udp") && !c.message.contains("8006"));
        // Processus des autres comptes invisibles (hidepid) : on ne conclut pas.
        assert!(!docker_sans_acces(&[]).verifie);
    }
}
