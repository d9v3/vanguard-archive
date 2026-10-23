//! Les fichiers des éditeurs (Mozilla, Google, Microsoft, Adobe, Brave) : des numéros de version, pris comme des
//! faits. Aucun n'a de licence publiée ni de format documenté : une forme qui change donne `None`, et le logiciel est
//! « non vérifié », jamais comparé de travers. JSON lu en structures typées (champs inconnus ignorés).

use std::collections::BTreeMap;

use chrono::{NaiveDate, NaiveDateTime};
use serde::Deserialize;

use super::Souple;
use crate::protection::perimes::version::{self, Version};

// ───────────────────────────── Mozilla ─────────────────────────────

/// product-details de Mozilla : la dernière Firefox et chaque ESR suivie (aujourd'hui 153 et 115), de la plus
/// récente à la plus ancienne.
#[derive(Debug, PartialEq)]
pub(crate) struct Firefox {
    pub release: Version,
    pub esr: Vec<Version>,
}

/// `firefox_versions.json` : « LATEST_FIREFOX_VERSION », et les clés « FIREFOX_ESR », « FIREFOX_ESR115 »,
/// « FIREFOX_ESR_NEXT »… non vides. Une ESR illisible rend tout le fichier illisible : une ESR oubliée ferait dire
/// « dépassée » à ceux qui la suivent.
pub(crate) fn firefox(octets: &[u8]) -> Option<Firefox> {
    let champs: BTreeMap<String, Souple<String>> = serde_json::from_slice(octets).ok()?;
    let mut release = None;
    let mut esr = Vec::new();
    for (cle, valeur) in champs {
        let Some(valeur) = valeur.bon() else { continue };
        if cle == "LATEST_FIREFOX_VERSION" {
            release = Some(version::firefox(&valeur)?);
        } else if let Some(suite) = cle.strip_prefix("FIREFOX_ESR")
            && (suite.is_empty() || suite == "_NEXT" || suite.bytes().all(|o| o.is_ascii_digit()))
            && !valeur.trim().is_empty()
        {
            esr.push(version::firefox(&valeur)?);
        }
    }
    esr.sort_unstable_by(|a, b| b.cmp(a));
    esr.dedup();
    Some(Firefox {
        release: release?,
        esr: (!esr.is_empty()).then_some(esr)?,
    })
}

// ───────────────────────────── Google Chrome ─────────────────────────────

#[derive(Deserialize)]
struct Sorties {
    releases: Vec<Sortie>,
}

#[derive(Deserialize)]
struct Sortie {
    name: String,
    version: String,
    #[serde(default)]
    fraction: f64,
}

/// versionhistory : les versions servies en ce moment (`fraction` > 0 ; plusieurs pendant un déploiement par
/// étapes), de la plus ancienne à la plus récente. Chaque entrée doit être celle de `plateforme` et `canal` : une
/// réponse d'une autre adresse n'est pas prise pour celle-ci.
pub(crate) fn chrome(octets: &[u8], plateforme: &str, canal: &str) -> Option<Vec<Version>> {
    let sorties: Sorties = serde_json::from_slice(octets).ok()?;
    let attendu = format!("platforms/{plateforme}/channels/{canal}/");
    if sorties.releases.iter().any(|s| !s.name.contains(&attendu)) {
        return None;
    }
    let mut servies = sorties
        .releases
        .iter()
        .filter(|s| s.fraction > 0.0)
        .map(|s| version::chrome_edge(&s.version))
        .collect::<Option<Vec<_>>>()?;
    servies.sort_unstable();
    servies.dedup();
    (!servies.is_empty()).then_some(servies)
}

// ───────────────────────────── Microsoft Edge ─────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProduitEdge {
    product: String,
    #[serde(default)]
    releases: Vec<SortieEdge>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SortieEdge {
    platform: String,
    architecture: String,
    product_version: String,
    published_time: Option<Souple<String>>,
}

/// La dernière Edge Stable d'une plateforme et d'une architecture, et quand elle a été publiée.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EdgeStable {
    /// « Windows », « MacOS »…
    pub plateforme: String,
    /// « x64 », « x86 », « arm64 », « universal ».
    pub architecture: String,
    pub version: Version,
    pub publiee: Option<NaiveDateTime>,
}

/// `edgeupdates.microsoft.com/api/products` : pour le produit « Stable », la plus haute version de chaque
/// plateforme et architecture (la liste n'est pas triée). Le canal Extended Stable n'y est pas.
pub(crate) fn edge(octets: &[u8]) -> Option<Vec<EdgeStable>> {
    let produits: Vec<ProduitEdge> = serde_json::from_slice(octets).ok()?;
    let stable = produits.into_iter().find(|p| p.product == "Stable")?;
    let mut dernieres: Vec<EdgeStable> = Vec::new();
    for s in stable.releases {
        let version = version::chrome_edge(&s.product_version)?;
        let publiee = s
            .published_time
            .and_then(Souple::bon)
            .and_then(|t| NaiveDateTime::parse_from_str(t.get(..19)?, "%Y-%m-%dT%H:%M:%S").ok());
        match dernieres
            .iter_mut()
            .find(|d| d.plateforme == s.platform && d.architecture == s.architecture)
        {
            Some(d) if d.version >= version => {}
            Some(d) => {
                d.version = version;
                d.publiee = publiee;
            }
            None => dernieres.push(EdgeStable {
                plateforme: s.platform,
                architecture: s.architecture,
                version,
                publiee,
            }),
        }
    }
    (!dernieres.is_empty()).then_some(dernieres)
}

// ───────────────────────────── Office (Windows) ─────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CanalBrut {
    channel_id: String,
    #[serde(default)]
    channel: Option<Souple<String>>,
    #[serde(default)]
    alternate_names: Option<Souple<Vec<String>>>,
    latest_version: String,
    #[serde(default)]
    office_versions: Vec<VersionBrute>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionBrute {
    legacy_version: String,
    #[serde(default)]
    availability_date: Option<Souple<String>>,
    end_of_support_date: Option<Souple<String>>,
    cdn_base_url: Option<Souple<String>>,
}

/// Un canal d'Office Click-to-Run, tel que OfficeReleases le décrit.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CanalOffice {
    /// « Current », « MonthlyEnterprise », « SemiAnnual », « PerpetualVL2024 »…
    pub id: String,
    /// Le nom court (« Monthly », « SAC »), puis les autres noms (« Deferred », « Broad »).
    pub noms: Vec<String>,
    pub derniere: Version,
    pub versions: Vec<VersionOffice>,
    /// Les GUID de ses adresses (`cdnBaseUrl`), en minuscules : c'est par eux qu'un canal réglé dans le registre se
    /// reconnaît, d'après la source elle-même.
    pub guids: Vec<String>,
}

/// Une version encore servie d'un canal, le jour où elle l'a été (un déploiement prend quelques jours) et la fin de
/// son support (`None` : aucune annoncée).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct VersionOffice {
    pub version: Version,
    pub disponible: Option<NaiveDate>,
    pub fin: Option<NaiveDate>,
}

/// `OfficeReleases` : chaque canal, au moins trois (sinon ce n'est pas la liste attendue).
pub(crate) fn office(octets: &[u8]) -> Option<Vec<CanalOffice>> {
    let bruts: Vec<CanalBrut> = serde_json::from_slice(octets).ok()?;
    let mut canaux = Vec::new();
    for c in bruts {
        let mut noms: Vec<String> = c.channel.and_then(Souple::bon).into_iter().collect();
        noms.extend(c.alternate_names.and_then(Souple::bon).unwrap_or_default());
        let mut versions = Vec::new();
        let mut guids: Vec<String> = Vec::new();
        for v in c.office_versions {
            versions.push(VersionOffice {
                version: version::chrome_edge(&v.legacy_version)?,
                disponible: v
                    .availability_date
                    .and_then(Souple::bon)
                    .and_then(|d| fin_de_support(&d)),
                fin: v
                    .end_of_support_date
                    .and_then(Souple::bon)
                    .and_then(|d| fin_de_support(&d)),
            });
            if let Some(guid) = v.cdn_base_url.and_then(Souple::bon).and_then(|u| guid_de(&u))
                && !guids.contains(&guid)
            {
                guids.push(guid);
            }
        }
        canaux.push(CanalOffice {
            id: c.channel_id,
            noms,
            derniere: version::chrome_edge(&c.latest_version)?,
            versions,
            guids,
        });
    }
    (canaux.len() >= 3).then_some(canaux)
}

/// « 2027-04-13T00:00:00Z » ; « 0001-01-01… » veut dire aucune fin annoncée.
fn fin_de_support(texte: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(texte.get(..10)?, "%Y-%m-%d")
        .ok()
        .filter(|d| *d > NaiveDate::from_ymd_opt(1, 1, 1).unwrap_or_default())
}

/// Le GUID qui termine une adresse de canal (« http://officecdn.microsoft.com/pr/492350f6-3a01-… »), en minuscules,
/// s'il a la forme d'un GUID (8-4-4-4-12 chiffres hexadécimaux).
pub(crate) fn guid_de(adresse: &str) -> Option<String> {
    let dernier = adresse.trim_end_matches('/').rsplit('/').next()?.to_ascii_lowercase();
    let groupes: Vec<&str> = dernier.split('-').collect();
    let forme = groupes.len() == 5
        && groupes
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|o| o.is_ascii_hexdigit()));
    forme.then_some(dernier)
}

// ───────────────────────────── Office (Mac) ─────────────────────────────

/// Un manifeste de Microsoft AutoUpdate (`0409XCEL2019-chk.xml`, un plist) : la version servie (« Update
/// Version »), si l'identifiant d'application est bien `id`.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn mau(octets: &[u8], id: &str) -> Option<Version> {
    let plist = crate::plist::lire(octets)?;
    if plist.cle("Application ID")?.texte()? != id {
        return None;
    }
    Version::lire(plist.cle("Update Version")?.texte()?)
}

/// Hors de macOS, le lecteur des plists n'est pas compilé : ces fichiers ne s'y lisent pas.
#[cfg(not(any(target_os = "macos", test)))]
pub(crate) fn mau(_octets: &[u8], _id: &str) -> Option<Version> {
    None
}

// ───────────────────────────── Adobe, Brave ─────────────────────────────

/// Un petit fichier texte : une seule ligne.
fn ligne(octets: &[u8]) -> Option<&str> {
    let texte = std::str::from_utf8(octets).ok()?.trim();
    (!texte.contains('\n')).then_some(texte)
}

/// `current_version.txt` d'Adobe : « 26.002.22031 » (piste Continuous).
pub(crate) fn adobe(octets: &[u8]) -> Option<Version> {
    version::adobe(ligne(octets)?)
}

/// `release-<plateforme>.version` de Brave : « 1.98.60 ».
pub(crate) fn brave(octets: &[u8]) -> Option<Version> {
    Version::lire(ligne(octets)?).filter(|v| v.longueur() == 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(texte: &str) -> Version {
        Version::lire(texte).unwrap()
    }

    // Les fichiers des éditeurs n'ont pas de licence publiée : fixtures inventées, à leur forme réelle (vue le
    // 23 oct. 2026), jamais des copies.

    const FIREFOX: &str = r#"{
        "FIREFOX_AURORA": "",
        "FIREFOX_DEVEDITION": "159.0b5",
        "FIREFOX_ESR": "153.5.1esr",
        "FIREFOX_ESR115": "115.43.1esr",
        "FIREFOX_ESR_NEXT": "",
        "FIREFOX_NIGHTLY": "161.0a1",
        "LAST_RELEASE_DATE": "2026-10-23",
        "LATEST_FIREFOX_OLDER_VERSION": "3.6.28",
        "LATEST_FIREFOX_VERSION": "158.0.1"
    }"#;

    #[test]
    fn firefox_et_ses_esr() {
        let f = firefox(FIREFOX.as_bytes()).unwrap();
        assert_eq!(f.release, v("158.0.1"));
        assert_eq!(f.esr, vec![v("153.5.1"), v("115.43.1")]);
        // Une ESR de plus, suivie sans changer le code ; une valeur d'un autre type est ignorée.
        let plus = FIREFOX.replace(
            "\"FIREFOX_ESR_NEXT\": \"\"",
            "\"FIREFOX_ESR_NEXT\": \"165.0esr\", \"X\": 3",
        );
        assert_eq!(firefox(plus.as_bytes()).unwrap().esr.len(), 3);
        // Sans la dernière version, ou une ESR illisible : rien.
        assert_eq!(
            firefox(FIREFOX.replace("LATEST_FIREFOX_VERSION", "AUTRE").as_bytes()),
            None
        );
        assert_eq!(firefox(FIREFOX.replace("153.5.1esr", "153.5.1-esr").as_bytes()), None);
        assert_eq!(firefox(b"<html>Portail</html>"), None);
        assert_eq!(firefox(b"{}"), None);
    }

    fn versionhistory(plateforme: &str, canal: &str, sorties: &[(&str, f64)]) -> String {
        let entrees: Vec<String> = sorties
            .iter()
            .map(|(version, fraction)| {
                format!(
                    r#"{{"name": "chrome/platforms/{plateforme}/channels/{canal}/versions/{version}/releases/1792700197",
                        "serving": {{"startTime": "2026-10-22T20:16:37.163276Z"}}, "fraction": {fraction},
                        "version": "{version}", "fractionGroup": "0", "pinnable": true, "rolloutData": []}}"#
                )
            })
            .collect();
        format!(r#"{{"releases": [{}], "nextPageToken": ""}}"#, entrees.join(","))
    }

    #[test]
    fn chrome_versions_servies() {
        let extended = versionhistory(
            "win64",
            "extended",
            &[("152.0.7977.169", 0.75), ("156.0.8078.48", 0.25)],
        );
        assert_eq!(
            chrome(extended.as_bytes(), "win64", "extended"),
            Some(vec![v("152.0.7977.169"), v("156.0.8078.48")])
        );
        // La réponse d'une autre plateforme ou d'un autre canal n'est pas prise pour celle-ci.
        assert_eq!(chrome(extended.as_bytes(), "win64", "stable"), None);
        assert_eq!(chrome(extended.as_bytes(), "win", "extended"), None);
        // Une version qui ne sert plus (fraction 0) est écartée ; aucune servie : rien.
        let stable = versionhistory("mac", "stable", &[("155.0.8059.85", 0.0), ("156.0.8078.47", 1.0)]);
        assert_eq!(
            chrome(stable.as_bytes(), "mac", "stable"),
            Some(vec![v("156.0.8078.47")])
        );
        let aucune = versionhistory("mac", "stable", &[("155.0.8059.85", 0.0)]);
        assert_eq!(chrome(aucune.as_bytes(), "mac", "stable"), None);
        let trois_champs = versionhistory("mac", "stable", &[("156.0.8078", 1.0)]);
        assert_eq!(chrome(trois_champs.as_bytes(), "mac", "stable"), None);
        assert_eq!(chrome(b"{\"releases\": []}", "mac", "stable"), None);
    }

    const EDGE: &str = r#"[
        {"Product": "Stable", "Releases": [
            {"ReleaseId": 1, "Platform": "Windows", "Architecture": "x64", "CVEs": ["CVE-2026-0001"],
             "ProductVersion": "155.0.4283.61", "PublishedTime": "2026-10-10T10:00:00", "Artifacts": []},
            {"ReleaseId": 2, "Platform": "Windows", "Architecture": "x64", "CVEs": [],
             "ProductVersion": "156.0.4314.42", "PublishedTime": "2026-10-22T19:20:00", "Artifacts": []},
            {"ReleaseId": 3, "Platform": "MacOS", "Architecture": "universal",
             "ProductVersion": "156.0.4314.42", "PublishedTime": null}
        ]},
        {"Product": "Beta", "Releases": [
            {"ReleaseId": 4, "Platform": "Windows", "Architecture": "x64",
             "ProductVersion": "157.0.4330.10", "PublishedTime": "2026-10-21T10:00:00"}
        ]}
    ]"#;

    #[test]
    fn edge_stable_par_plateforme() {
        let e = edge(EDGE.as_bytes()).unwrap();
        assert_eq!(e.len(), 2);
        let windows = e.iter().find(|s| s.plateforme == "Windows").unwrap();
        assert_eq!(windows.version, v("156.0.4314.42"));
        assert_eq!(
            windows.publiee.map(|t| t.to_string()).as_deref(),
            Some("2026-10-22 19:20:00")
        );
        let mac = e.iter().find(|s| s.plateforme == "MacOS").unwrap();
        assert_eq!((mac.architecture.as_str(), mac.publiee), ("universal", None));
        // Pas de Stable : rien (la Beta n'est jamais prise à sa place).
        assert_eq!(edge(EDGE.replace("\"Stable\"", "\"Autre\"").as_bytes()), None);
        assert_eq!(edge(b"[]"), None);
    }

    const OFFICE: &str = r#"[
        {"channel": "Monthly", "channelId": "Current", "alternateNames": ["Monthly"],
         "latestVersion": "16.0.20527.20088", "officeVersions": [
            {"legacyVersion": "16.0.20527.20088", "releaseVersion": "2610", "buildVersion": "20527.20088",
             "availabilityDate": "2026-10-14T00:00:00Z", "endOfSupportDate": "0001-01-01T00:00:00Z",
             "cdnBaseUrl": "http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60"}]},
        {"channel": "SAC", "channelId": "SemiAnnual", "alternateNames": ["Deferred", "Broad"],
         "latestVersion": "16.0.20430.20178", "officeVersions": [
            {"legacyVersion": "16.0.20430.20178", "endOfSupportDate": "2027-04-13T00:00:00Z",
             "cdnBaseUrl": "http://officecdn.microsoft.com/pr/7FFBC6BF-BC32-4F92-8982-F9DD17FD3114"},
            {"legacyVersion": "16.0.20326.20230", "endOfSupportDate": "2027-03-09T00:00:00Z",
             "cdnBaseUrl": "http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114"}]},
        {"channel": "LTSB2024", "channelId": "PerpetualVL2024", "alternateNames": ["Perpetual2024"],
         "latestVersion": "16.0.17932.21056", "officeVersions": []}
    ]"#;

    #[test]
    fn office_canaux_et_guids() {
        let canaux = office(OFFICE.as_bytes()).unwrap();
        assert_eq!(canaux.len(), 3);
        let sac = &canaux[1];
        assert_eq!(sac.id, "SemiAnnual");
        assert_eq!(sac.noms, ["SAC", "Deferred", "Broad"]);
        assert_eq!(sac.derniere, v("16.0.20430.20178"));
        assert_eq!(sac.guids, ["7ffbc6bf-bc32-4f92-8982-f9dd17fd3114"]);
        assert_eq!(sac.versions[1].fin, NaiveDate::from_ymd_opt(2027, 3, 9));
        assert_eq!(canaux[0].versions[0].fin, None, "0001-01-01 : aucune fin annoncée");
        assert_eq!(canaux[0].versions[0].disponible, NaiveDate::from_ymd_opt(2026, 10, 14));
        assert_eq!(sac.versions[0].disponible, None);
        // Moins de trois canaux, ou une version illisible : rien.
        let mut deux: serde_json::Value = serde_json::from_str(OFFICE).unwrap();
        deux.as_array_mut().unwrap().truncate(2);
        assert_eq!(office(deux.to_string().as_bytes()), None);
        assert_eq!(
            office(
                OFFICE
                    .replace("16.0.20527.20088\", \"releaseVersion", "16.0.x\", \"releaseVersion")
                    .as_bytes()
            ),
            None
        );
        assert_eq!(guid_de("http://officecdn.microsoft.com/pr/wsus"), None);
        assert_eq!(guid_de("\\\\serveur\\partage"), None);
    }

    const MAU: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Application ID</key>
	<string>XCEL2019</string>
	<key>Date</key>
	<date>2026-10-20T08:00:00Z</date>
	<key>Type</key>
	<string>Recommended</string>
	<key>Update Version</key>
	<string>16.114.26102031</string>
</dict>
</plist>"#;

    #[test]
    fn manifeste_de_mau() {
        assert_eq!(mau(MAU.as_bytes(), "XCEL2019"), Some(v("16.114.26102031")));
        // Le manifeste d'une autre application n'est pas pris pour celui-ci.
        assert_eq!(mau(MAU.as_bytes(), "MSWD2019"), None);
        assert_eq!(mau(b"<html></html>", "XCEL2019"), None);
    }

    #[test]
    fn fichiers_texte() {
        assert_eq!(adobe(b"26.002.22031"), Some(v("26.2.22031")));
        assert_eq!(adobe(b"26.002.22031\n"), Some(v("26.2.22031")));
        assert_eq!(adobe(b"26.002.22031\n26.001.1"), None);
        assert_eq!(adobe(b"<html>"), None);
        assert_eq!(brave(b"1.98.60"), Some(v("1.98.60")));
        assert_eq!(brave(b"156.1.98.60"), None);
        assert_eq!(brave(b"\xff\xfe"), None);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 500, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..300)) {
            let _ = firefox(&octets);
            let _ = chrome(&octets, "win", "stable");
            let _ = edge(&octets);
            let _ = office(&octets);
            let _ = mau(&octets, "XCEL2019");
            let _ = adobe(&octets);
            let _ = brave(&octets);
        }
    }
}
