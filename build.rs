//! Fiche d'identité de sentinel.exe (onglet « Détails » des propriétés du fichier), icône et manifeste Windows.

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
    res.set("ProductName", "Sentinel")
        .set("FileDescription", "sentinel - bilan de sécurité personnel (machine, réseau local, antivirus)")
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
