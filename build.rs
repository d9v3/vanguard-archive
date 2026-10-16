//! Fiche d'identité de netscan.exe (onglet « Détails » des propriétés du fichier) et manifeste Windows.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    // Compilation croisée depuis Linux : outils de MinGW.
    if !cfg!(windows) {
        res.set_windres_path("x86_64-w64-mingw32-windres");
        res.set_ar_path("x86_64-w64-mingw32-ar");
    }
    res.set("ProductName", "netscan")
        .set("FileDescription", "netscan - bilan de sécurité personnel (machine, réseau local, antivirus)")
        .set("CompanyName", "Projet personnel netscan")
        .set("LegalCopyright", "Projet personnel, usage sur ses propres appareils")
        .set("OriginalFilename", "netscan.exe")
        // asInvoker : netscan démarre sans droits admin ; seules les corrections les demandent, une à une.
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
