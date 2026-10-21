//! Les mises à jour de Windows installées (Win32_QuickFixEngineering, ce que lit Get-HotFix), par WMI.

use super::wmi;

/// Une mise à jour installée : sa date, son numéro (« KB5066835 ») et sa description (« Security Update »).
pub(crate) struct Correctif {
    pub date: chrono::NaiveDate,
    pub numero: String,
    pub description: String,
}

/// InstalledOn comme Get-HotFix le lit : « M/j/aaaa » (toujours à l'américaine, quelle que soit la langue), ou une
/// date FILETIME en 16 chiffres hexadécimaux sur d'anciens Windows. `None` : pas de date (le correctif est écarté,
/// comme par `Where-Object InstalledOn`).
pub(crate) fn date_installee(texte: &str) -> Option<chrono::NaiveDate> {
    let t = texte.trim();
    if t.len() == 16
        && let Ok(fichier) = u64::from_str_radix(t, 16)
    {
        // FILETIME : centaines de nanosecondes depuis le 1er janvier 1601.
        let secondes = i64::try_from(fichier / 10_000_000).ok()? - 11_644_473_600;
        return chrono::DateTime::from_timestamp(secondes, 0).map(|d| d.date_naive());
    }
    chrono::NaiveDate::parse_from_str(t, "%m/%d/%Y").ok()
}

/// Les mises à jour installées qui ont une date, les plus récentes d'abord ; `None` si WMI ne répond pas.
pub(crate) fn installes() -> Option<Vec<Correctif>> {
    let lignes = wmi::requete(
        r"root\cimv2",
        "Win32_QuickFixEngineering",
        "",
        &["HotFixID", "Description", "InstalledOn"],
    )?;
    let mut correctifs: Vec<Correctif> = lignes
        .iter()
        .filter_map(|l| {
            Some(Correctif {
                date: date_installee(l["InstalledOn"].texte()?)?,
                numero: l["HotFixID"].texte().unwrap_or_default().to_string(),
                description: l["Description"].texte().unwrap_or_default().to_string(),
            })
        })
        .collect();
    correctifs.sort_by_key(|c| std::cmp::Reverse(c.date));
    Some(correctifs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_de_get_hotfix() {
        let d = |a, m, j| chrono::NaiveDate::from_ymd_opt(a, m, j);
        assert_eq!(date_installee("10/15/2026"), d(2026, 10, 15));
        assert_eq!(date_installee(" 1/2/2025 "), d(2025, 1, 2));
        // 2021-01-01 00:00 UTC en FILETIME.
        assert_eq!(date_installee("01D6DFDA4BA8C000"), d(2021, 1, 1));
        assert_eq!(date_installee(""), None);
        assert_eq!(date_installee("15/10/2026"), None);
    }

    #[test]
    fn lecture_reelle() {
        if let Some(c) = installes() {
            assert!(c.windows(2).all(|p| p[0].date >= p[1].date));
        }
    }
}
