//! Services au chemin sans guillemets : « C:\Program Files\Mon Outil\svc.exe », sans guillemets, Windows essaie
//! d'abord « C:\Program.exe », puis « C:\Program Files\Mon.exe ». Un programme posé là démarre avec les droits du
//! service, souvent ceux du système. Signalé seulement si un de ces dossiers est modifiable par tous les comptes :
//! sans cela, le défaut n'est pas exploitable (C:\ et Program Files ne le sont pas).

use super::super::{Constat, alerte};
use super::ps;
use crate::commande::ps_chaine;
use crate::risk::Niveau;
use crate::ui::{affichable, resume, tr, trf};

/// Pour chaque service au chemin sans guillemets : « SVC|nom|programme|arguments|dossier modifiable ». Les comptes
/// sont reconnus par leur SID (Utilisateurs, Utilisateurs authentifiés, Tout le monde, Interactif), pas par leur nom,
/// qui change avec la langue de Windows.
const SCRIPT: &str = r#"
$tous = 'S-1-5-32-545','S-1-5-11','S-1-1-0','S-1-5-4'
function Modifiable($d) {
  try {
    foreach ($r in (Get-Acl -LiteralPath $d).Access) {
      # Une règle « héritée seulement » vaut pour le contenu, pas pour le dossier : celle de C:\ pour ses sous-dossiers.
      if ($r.AccessControlType -ne 'Allow' -or ($r.PropagationFlags -band 2)) { continue }
      $sid = try { $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' }
      # Créer un fichier (0x2), ou écriture et tous droits génériques.
      if ($tous -contains $sid -and ([int64]$r.FileSystemRights -band 0x50000002)) { return $true }
    }
  } catch {}
  return $false
}
foreach ($s in Get-CimInstance Win32_Service) {
  $c = [string]$s.PathName
  if (-not $c -or $c.StartsWith('"') -or $c -notmatch '^(.+?\.exe)(\s.*)?$') { continue }
  $exe = $Matches[1]; $suite = [string]$Matches[2]
  if ($exe -notmatch ' ') { continue }
  $parties = $exe -split ' '
  for ($i = 1; $i -lt $parties.Count; $i++) {
    $d = Split-Path -Parent (($parties[0..($i - 1)] -join ' '))
    if ($d -and (Test-Path -LiteralPath $d) -and (Modifiable $d)) { "SVC|$($s.Name)|$exe|$suite|$d"; break }
  }
}
'SVC_FIN'
"#;

pub(super) fn services_sans_guillemets() -> Option<Constat> {
    let sortie = ps(SCRIPT)?;
    juger(&sortie)
}

/// Les services exploitables lus dans la sortie du script, avec la commande qui met leur chemin entre guillemets.
/// `None` sans service à signaler, ou si la liste n'a pas été lue jusqu'au bout.
pub(super) fn juger(sortie: &str) -> Option<Constat> {
    if !sortie.lines().any(|l| l.trim() == "SVC_FIN") {
        return None;
    }
    let mut noms = Vec::new();
    let mut commandes = Vec::new();
    for ligne in sortie
        .lines()
        .filter_map(|l| l.trim_end_matches('\r').strip_prefix("SVC|"))
    {
        let mut champs = ligne.splitn(4, '|');
        let (Some(nom), Some(programme), Some(arguments), Some(dossier)) =
            (champs.next(), champs.next(), champs.next(), champs.next())
        else {
            continue;
        };
        // Le nom du service entre dans un chemin du registre : seulement des caractères de nom de service.
        if nom.is_empty() || !nom.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c)) {
            continue;
        }
        noms.push(format!("{} ({})", affichable(nom), affichable(dossier)));
        let chemin = format!(r"HKLM:\SYSTEM\CurrentControlSet\Services\{nom}");
        let valeur = format!("\"{programme}\"{arguments}");
        commandes.push(format!(
            "Set-ItemProperty -LiteralPath '{chemin}' -Name ImagePath -Value {}",
            ps_chaine(&valeur)
        ));
    }
    if noms.is_empty() {
        return None;
    }
    let commandes: Vec<&str> = commandes.iter().map(String::as_str).collect();
    Some(
        alerte(
            "Persistance",
            Niveau::Eleve,
            trf!(
                "Service au chemin sans guillemets, dans un dossier modifiable par tous : {}. Un programme posé là démarrerait avec les droits du système.",
                "Service with an unquoted path, in a folder anyone can change: {}. A program dropped there would start with system rights.",
                resume(&noms, 3, ", ")
            ),
        )
        .manuel(
            tr!(
                "Mettre le chemin du service entre guillemets (commande ci-dessous, en administrateur), puis signaler le défaut à l'éditeur du programme",
                "Put the service's path in quotes (command below, as administrator), then report the flaw to the program's publisher"
            ),
            &commandes,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chemins_sans_guillemets() {
        // Liste pas lue jusqu'au bout : rien.
        assert!(juger("SVC|Outil|C:\\Mes Outils\\svc.exe| -k|C:\\Mes Outils\n").is_none());
        assert!(juger("SVC_FIN\n").is_none());
        let c = juger(
            "SVC|OutilMaj|C:\\Mes Outils\\Outil Maj\\maj.exe| -service|C:\\Mes Outils\r\nSVC|pi;ege|C:\\A B\\x.exe||C:\\A B\nSVC_FIN\n",
        )
        .unwrap();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("OutilMaj (C:\\Mes Outils)") && !c.message.contains("pi;ege"));
        let k = c.correctif.unwrap();
        assert!(!k.automatique);
        assert_eq!(
            k.commandes,
            [
                "Set-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\OutilMaj' -Name ImagePath -Value '\"C:\\Mes Outils\\Outil Maj\\maj.exe\" -service'"
            ]
        );
    }
}
