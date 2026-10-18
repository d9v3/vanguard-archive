//! Préparé à la compilation : la base des fabricants (assets/oui.tsv) rangée en tableaux triés, et, pour Windows, la
//! fiche d'identité de sentinel.exe (onglet « Détails » des propriétés du fichier), son icône et son manifeste.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

fn main() {
    fabricants();
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        ressources_windows();
    }
}

/// La base des fabricants, rangée une fois pour toutes : pour chaque longueur de préfixe (6, 7 ou 9 chiffres
/// hexadécimaux), les préfixes triés et le numéro de leur nom ; chaque nom n'est écrit qu'une fois (« Apple, Inc. »
/// revient plus de 1500 fois). Le programme y cherche par dichotomie, sans rien lire ni allouer : avant, chaque scan
/// recopiait les 58 000 lignes dans une table de hachage de plusieurs Mo.
fn fabricants() {
    println!("cargo:rerun-if-changed=assets/oui.tsv");
    let texte = std::fs::read_to_string("assets/oui.tsv").expect("assets/oui.tsv illisible");
    let mut noms: Vec<&str> = Vec::new();
    let mut numeros: HashMap<&str, u16> = HashMap::new();
    let mut tables: [Vec<(u64, u16)>; 3] = Default::default();
    for ligne in texte.lines() {
        let Some((prefixe, nom)) = ligne.split_once('\t') else {
            continue;
        };
        let rang = match prefixe.len() {
            6 => 0,
            7 => 1,
            9 => 2,
            _ => continue,
        };
        let Ok(valeur) = u64::from_str_radix(prefixe, 16) else {
            continue;
        };
        let numero = *numeros.entry(nom).or_insert_with(|| {
            noms.push(nom);
            u16::try_from(noms.len() - 1).expect("plus de 65 536 fabricants : passer les numéros en u32")
        });
        tables[rang].push((valeur, numero));
    }
    let mut rs = String::from("// Fichier produit par build.rs à partir de assets/oui.tsv : ne pas modifier.\n");
    let mut tous = String::new();
    let mut debuts = vec![0u32];
    for nom in &noms {
        tous.push_str(nom);
        debuts.push(u32::try_from(tous.len()).expect("noms trop longs"));
    }
    let _ = writeln!(rs, "pub static NOMS: &str = {tous:?};");
    let _ = writeln!(rs, "pub static DEBUTS: [u32; {}] = {debuts:?};", debuts.len());
    for (table, (longueur, entier)) in tables.iter_mut().zip([("6", "u32"), ("7", "u32"), ("9", "u64")]) {
        table.sort_unstable();
        table.dedup_by_key(|e| e.0);
        let prefixes: Vec<String> = table.iter().map(|e| e.0.to_string()).collect();
        let numeros: Vec<String> = table.iter().map(|e| e.1.to_string()).collect();
        let n = table.len();
        let _ = writeln!(
            rs,
            "pub static PREFIXES_{longueur}: [{entier}; {n}] = [{}];",
            prefixes.join(",")
        );
        let _ = writeln!(rs, "pub static NOMS_{longueur}: [u16; {n}] = [{}];", numeros.join(","));
    }
    let sortie = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(Path::new(&sortie).join("fabricants.rs"), rs).expect("fabricants.rs non écrit");
}

fn ressources_windows() {
    println!("cargo:rerun-if-changed=assets/sentinel.ico");
    let mut res = winresource::WindowsResource::new();
    // Compilation croisée depuis Linux : outils de MinGW.
    if !cfg!(windows) {
        res.set_windres_path("x86_64-w64-mingw32-windres");
        res.set_ar_path("x86_64-w64-mingw32-ar");
    }
    res.set("ProductName", "Sentinel")
        .set("FileDescription", "sentinel - sécurise et optimise ta machine et ton réseau (bilan, antivirus, réglages)")
        .set("CompanyName", "Projet personnel Sentinel")
        .set("LegalCopyright", "© 2026 d9v3, licence GPL-3.0-or-later")
        .set("OriginalFilename", "sentinel.exe")
        // Icône de l'Explorateur et de la barre des tâches (16 à 256 px, voir assets/).
        .set_icon("assets/sentinel.ico")
        // asInvoker : sentinel démarre sans droits admin ; seules les corrections les demandent, une à une.
        .set_manifest(
            r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings><activeCodePage xmlns="http://schemas.microsoft.com/SMI/2019/WindowsSettings">UTF-8</activeCodePage></windowsSettings>
  </application>
</assembly>"#,
        );
    if let Err(e) = res.compile() {
        println!("cargo:warning=ressources Windows non intégrées : {e}");
    }
}
