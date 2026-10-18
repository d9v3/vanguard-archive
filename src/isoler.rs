//! Bac à sable : lancer un programme inconnu à l'écart du reste. Linux : bubblewrap (ou firejail), système en
//! lecture seule, dossier personnel et /tmp vides, pas de réseau, programme copié dans un dossier jetable.
//! Windows : Windows Sandbox, une machine jetable effacée à la fermeture, dossier du programme en lecture seule,
//! réseau coupé. macOS : sandbox-exec (le bac à sable intégré au système), pas de réseau, dossier personnel
//! illisible, écriture seulement dans le dossier jetable.

use std::path::{Path, PathBuf};

use crate::ui::*;

/// Dossier jetable qui reçoit une copie du programme (le bac à sable n'écrit jamais à côté de l'original). Créé de
/// façon exclusive, sous un nom imprévisible et réservé à l'utilisateur : dans un /tmp partagé, un dossier préparé
/// d'avance par un autre compte (avec un lien piégé au nom du programme) aurait fait écraser un de tes fichiers par
/// la copie.
fn dossier_jetable() -> std::io::Result<PathBuf> {
    static COMPTEUR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COMPTEUR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let dossier = std::env::temp_dir().join(format!("gardien-bac-{}-{nanos}-{n}", std::process::id()));
    #[cfg_attr(windows, allow(unused_mut))]
    let mut createur = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut createur, 0o700);
    createur.create(&dossier)?;
    Ok(dossier)
}

/// Arguments de bubblewrap. Le dossier de session (/run/user/…) est masqué : son bus de session permettrait de
/// demander à systemd, hors du bac, de lancer un programme. Seul l'affichage Wayland est rendu visible.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn arguments_bwrap(jetable: &Path, programme: &Path, session: Option<&str>, wayland: Option<&str>) -> Vec<String> {
    let mut a: Vec<String> = [
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/home",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/root",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    if let Some(s) = session {
        a.extend(["--tmpfs".into(), s.into()]);
        if let Some(w) = wayland {
            let socket = format!("{s}/{w}");
            a.extend(["--ro-bind-try".into(), socket.clone(), socket]);
        }
    }
    let j = jetable.display().to_string();
    a.extend([
        "--bind".into(),
        j.clone(),
        j.clone(),
        "--chdir".into(),
        j.clone(),
        "--setenv".into(),
        "HOME".into(),
        j,
    ]);
    a.push(programme.display().to_string());
    a
}

/// Fichier de configuration de Windows Sandbox : dossier du programme en lecture seule, réseau coupé, programme
/// lancé à l'ouverture.
#[cfg_attr(not(windows), allow(dead_code))]
fn configuration_wsb(dossier: &str, nom: &str) -> String {
    let echapper = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    format!(
        "<Configuration>\r\n  <Networking>Disable</Networking>\r\n  <MappedFolders>\r\n    <MappedFolder>\r\n      \
         <HostFolder>{}</HostFolder>\r\n      <SandboxFolder>C:\\Users\\WDAGUtilityAccount\\Desktop\\Programme</SandboxFolder>\r\n      \
         <ReadOnly>true</ReadOnly>\r\n    </MappedFolder>\r\n  </MappedFolders>\r\n  <LogonCommand>\r\n    \
         <Command>explorer.exe C:\\Users\\WDAGUtilityAccount\\Desktop\\Programme\\{}</Command>\r\n  </LogonCommand>\r\n</Configuration>\r\n",
        echapper(dossier),
        echapper(nom)
    )
}

#[cfg(target_os = "linux")]
fn present(cmd: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {cmd}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// « gardien isoler <fichier> » : lance le programme dans un bac à sable.
pub fn isoler(fichier: &Path) {
    titre(tr!("Bac à sable", "Sandbox"));
    let Ok(source) = fichier.canonicalize() else {
        trp!(
            "  ✖ Fichier introuvable : {}",
            "  ✖ File not found: {}",
            fichier.display()
        );
        return;
    };
    if !source.is_file() {
        trp!(
            "  ✖ Ce n'est pas un fichier : {}",
            "  ✖ Not a file: {}",
            source.display()
        );
        return;
    }
    lancer(&source);
}

#[cfg(target_os = "linux")]
fn lancer(source: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(jetable) = dossier_jetable() else {
        trp!(
            "  ✖ Dossier jetable impossible à créer.",
            "  ✖ Could not create the disposable folder."
        );
        return;
    };
    let nom = source.file_name().unwrap_or_default();
    let copie = jetable.join(nom);
    if std::fs::copy(source, &copie).is_err() {
        trp!(
            "  ✖ Copie impossible dans le dossier jetable.",
            "  ✖ Could not copy into the disposable folder."
        );
        let _ = std::fs::remove_dir_all(&jetable);
        return;
    }
    let _ = std::fs::set_permissions(&copie, std::fs::Permissions::from_mode(0o755));
    trp!(
        "  {GRIS}Isolé : système en lecture seule, dossier personnel invisible, pas de réseau. Copie jetable : {}{RESET}\n",
        "  {GRIS}Isolated: read-only system, home folder hidden, no network. Disposable copy: {}{RESET}\n",
        copie.display()
    );
    let statut = if present("bwrap") {
        let session = std::env::var("XDG_RUNTIME_DIR").ok();
        let wayland = std::env::var("WAYLAND_DISPLAY").ok();
        std::process::Command::new("bwrap")
            .args(arguments_bwrap(
                &jetable,
                &copie,
                session.as_deref(),
                wayland.as_deref(),
            ))
            .status()
    } else if present("firejail") {
        std::process::Command::new("firejail")
            .args([
                "--noprofile",
                "--net=none",
                "--private-tmp",
                "--caps.drop=all",
                "--nonewprivs",
            ])
            .arg(format!("--private={}", jetable.display()))
            .arg(&copie)
            .status()
    } else {
        trp!(
            "  ✖ Ni bubblewrap ni firejail. Pour installer bubblewrap : {}",
            "  ✖ Neither bubblewrap nor firejail. To install bubblewrap: {}",
            crate::machine::linux::commande_installation("bubblewrap")
        );
        let _ = std::fs::remove_dir_all(&jetable);
        return;
    };
    let _ = std::fs::remove_dir_all(&jetable);
    match statut {
        Ok(s) => trp!(
            "\n  {VERT}✔{RESET} Programme terminé (code {}). Le dossier jetable est effacé.",
            "\n  {VERT}✔{RESET} Program finished (code {}). The disposable folder is erased.",
            s.code().map_or_else(|| "?".to_string(), |c| c.to_string())
        ),
        Err(e) => trp!("  ✖ Lancement impossible : {e}", "  ✖ Could not start: {e}"),
    }
}

/// Profil de sandbox-exec : tout est permis sauf le réseau, la lecture du dossier personnel et l'écriture hors du
/// dossier jetable (et des terminaux, pour afficher).
#[cfg(any(target_os = "macos", test))]
fn profil_sandbox(jetable: &str, maison: &str) -> String {
    let echapper = |t: &str| t.replace('\\', "\\\\").replace('"', "\\\"");
    let (jetable, maison) = (echapper(jetable), echapper(maison));
    format!(
        "(version 1)\n(allow default)\n(deny network*)\n\
         (deny file-read* (subpath \"{maison}\"))\n\
         (deny file-write*)\n\
         (allow file-read* file-write* (subpath \"{jetable}\"))\n\
         (allow file-write* (literal \"/dev/null\") (regex #\"^/dev/tty\") (regex #\"^/dev/fd/\"))\n"
    )
}

#[cfg(target_os = "macos")]
fn lancer(source: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(jetable) = dossier_jetable() else {
        trp!(
            "  ✖ Dossier jetable impossible à créer.",
            "  ✖ Could not create the disposable folder."
        );
        return;
    };
    let nom = source.file_name().unwrap_or_default();
    // sandbox-exec compare des chemins réels : /var est un lien vers /private/var.
    let jetable = jetable.canonicalize().unwrap_or(jetable);
    let copie = jetable.join(nom);
    if std::fs::copy(source, &copie).is_err() {
        trp!(
            "  ✖ Copie impossible dans le dossier jetable.",
            "  ✖ Could not copy into the disposable folder."
        );
        let _ = std::fs::remove_dir_all(&jetable);
        return;
    }
    let _ = std::fs::set_permissions(&copie, std::fs::Permissions::from_mode(0o755));
    let maison = std::env::var("HOME").unwrap_or_default();
    let maison = std::fs::canonicalize(&maison).map_or(maison, |m| m.display().to_string());
    trp!(
        "  {GRIS}Isolé : pas de réseau, dossier personnel illisible, écriture seulement dans la copie jetable : {}{RESET}\n",
        "  {GRIS}Isolated: no network, home folder unreadable, writing only in the disposable copy: {}{RESET}\n",
        copie.display()
    );
    let statut = std::process::Command::new("sandbox-exec")
        .arg("-p")
        .arg(profil_sandbox(&jetable.display().to_string(), &maison))
        .arg(&copie)
        .current_dir(&jetable)
        .status();
    let _ = std::fs::remove_dir_all(&jetable);
    match statut {
        Ok(s) => trp!(
            "\n  {VERT}✔{RESET} Programme terminé (code {}). Le dossier jetable est effacé.",
            "\n  {VERT}✔{RESET} Program finished (code {}). The disposable folder is erased.",
            s.code().map_or_else(|| "?".to_string(), |c| c.to_string())
        ),
        Err(e) => trp!("  ✖ Lancement impossible : {e}", "  ✖ Could not start: {e}"),
    }
}

#[cfg(windows)]
fn lancer(source: &Path) {
    let sandbox = PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32\\WindowsSandbox.exe");
    if !sandbox.is_file() {
        trp!(
            "  ✖ Windows Sandbox n'est pas activé. Il existe sur Windows 10/11 Pro, Entreprise et Éducation :\n    Paramètres > Applications > Fonctionnalités facultatives > Plus de fonctionnalités Windows > « Bac à sable Windows ».",
            "  ✖ Windows Sandbox is not turned on. It exists on Windows 10/11 Pro, Enterprise and Education:\n    Settings > Apps > Optional features > More Windows features > “Windows Sandbox”."
        );
        return;
    }
    let dossier = source.parent().map(|d| d.display().to_string()).unwrap_or_default();
    let nom = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let Ok(jetable) = dossier_jetable() else {
        trp!(
            "  ✖ Configuration impossible à écrire.",
            "  ✖ Could not write the configuration."
        );
        return;
    };
    let wsb = jetable.join("gardien.wsb");
    if std::fs::write(&wsb, configuration_wsb(&dossier, &nom)).is_err() {
        trp!(
            "  ✖ Configuration impossible à écrire.",
            "  ✖ Could not write the configuration."
        );
        return;
    }
    trp!(
        "  {GRIS}Windows Sandbox s'ouvre : machine jetable, réseau coupé, dossier du programme en lecture seule.\n  Tout est effacé à la fermeture de la fenêtre.{RESET}",
        "  {GRIS}Windows Sandbox opens: disposable machine, network off, program folder read-only.\n  Everything is erased when the window closes.{RESET}"
    );
    if let Err(e) = std::process::Command::new(&sandbox).arg(&wsb).spawn() {
        trp!("  ✖ Lancement impossible : {e}", "  ✖ Could not start: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profil_de_sandbox_exec() {
        let p = profil_sandbox("/private/var/folders/x/T/gardien-bac-1", "/Users/a \"b\"");
        assert!(p.contains("(deny network*)"));
        assert!(p.contains("(deny file-read* (subpath \"/Users/a \\\"b\\\"\"))"));
        assert!(p.contains("(allow file-read* file-write* (subpath \"/private/var/folders/x/T/gardien-bac-1\"))"));
    }

    #[test]
    fn dossier_jetable_exclusif() {
        let a = dossier_jetable().unwrap();
        let b = dossier_jetable().unwrap();
        // Deux dossiers distincts, chacun créé neuf (jamais un dossier préparé d'avance), réservés à l'utilisateur.
        assert_ne!(a, b);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&a).unwrap().permissions().mode() & 0o777, 0o700);
        }
        std::fs::remove_dir(&a).unwrap();
        std::fs::remove_dir(&b).unwrap();
    }

    #[test]
    fn arguments_du_bac() {
        let a = arguments_bwrap(
            Path::new("/tmp/j"),
            Path::new("/tmp/j/p"),
            Some("/run/user/1000"),
            Some("wayland-1"),
        );
        let texte = a.join(" ");
        assert!(texte.contains("--unshare-all") && texte.contains("--new-session") && texte.contains("--cap-drop ALL"));
        // Session masquée, seul l'affichage Wayland repasse.
        assert!(
            texte.contains("--tmpfs /run/user/1000 --ro-bind-try /run/user/1000/wayland-1 /run/user/1000/wayland-1")
        );
        assert_eq!(a.last().map(String::as_str), Some("/tmp/j/p"));
        let wsb = configuration_wsb(r"C:\Users\x\Downloads", "setup.exe");
        assert!(wsb.contains("<Networking>Disable</Networking>") && wsb.contains("<ReadOnly>true</ReadOnly>"));
        assert!(wsb.contains(r"Programme\setup.exe"));
    }
}
