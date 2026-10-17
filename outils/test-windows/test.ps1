# Test complet de sentinel sur un vrai Windows.
# 1) relève l'état réel du système (référence), 2) lance sentinel, 3) étapes guidées.
# Tous les résultats vont dans un dossier « resultats-AAAAMMJJ-HHMMSS » à côté de ce script (un par passe).

# -Auto : aucune question (TEST-SENTINEL-AUTO.bat) ; les étapes qui demandent de taper ou une fenêtre UAC sont sautées.
param([switch]$Auto)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8

$partage = Split-Path -Parent $MyInvocation.MyCommand.Path
$res = Join-Path $partage ('resultats-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force $res | Out-Null

# On lance une copie locale : un .exe sur un partage réseau déclenche des avertissements de sécurité.
$local = Join-Path $env:LOCALAPPDATA 'sentinel-test'
New-Item -ItemType Directory -Force $local | Out-Null
Copy-Item (Join-Path $partage 'sentinel.exe') $local -Force
$exe = Join-Path $local 'sentinel.exe'
Unblock-File $exe -ErrorAction SilentlyContinue

function Note($texte) { Add-Content -Path (Join-Path $res 'journal.txt') -Value $texte -Encoding UTF8; Write-Host $texte }

function Etape($nom) {
    Write-Host ''
    Write-Host "=== $nom ===" -ForegroundColor Cyan
    Note "=== $nom === $(Get-Date -Format 'HH:mm:ss')"
}

# Lance sentinel sans interaction ; garde sortie, erreurs, code de retour et durée.
function Lancer($fichier, [string[]]$arguments) {
    $debut = Get-Date
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput (Join-Path $res "$fichier.out.txt") -RedirectStandardError (Join-Path $res "$fichier.err.txt")
    $duree = ((Get-Date) - $debut).TotalSeconds
    Note ("sentinel {0} -> code {1}, {2:N1} s" -f ($arguments -join ' '), $p.ExitCode, $duree)
    Get-Content (Join-Path $res "$fichier.out.txt") -Encoding UTF8 | Select-Object -First 60 | ForEach-Object { Write-Host $_ }
}

function Question($texte, $reponseAuto = 'n') {
    if ($Auto) {
        Note "AUTO : $texte -> $reponseAuto"
        return $reponseAuto -eq 'o'
    }
    $r = Read-Host "$texte [o/n]"
    Note "QUESTION : $texte -> $r"
    return $r -match '^(o|oui|y)'
}

# Référence : chaque valeur lue directement, pour comparer avec les conclusions de sentinel.
function Ref($nom, [scriptblock]$bloc) {
    try { $v = (& $bloc | Out-String).Trim() } catch { $v = "ERREUR : $($_.Exception.Message)" }
    Add-Content -Path (Join-Path $res 'reference.txt') -Value "### $nom`r`n$v`r`n" -Encoding UTF8
}

Write-Host 'Test complet de sentinel — environ 5 à 15 minutes.' -ForegroundColor Green
Write-Host 'Quelques questions te seront posées ; réponds o (oui) ou n (non).'

Etape '1. Référence : état réel de Windows'
Ref 'Windows' { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | Format-List }
Ref 'PowerShell' { $PSVersionTable.PSVersion.ToString() }
Ref 'Administrateur ?' { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
Ref 'Pare-feu' { Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize }
Ref 'Defender' { Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, IsTamperProtected | Format-List }
Ref 'Antivirus (Centre de sécurité)' { (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).displayName }
Ref 'SMBv1' { (Get-SmbServerConfiguration).EnableSMB1Protocol }
Ref 'RDP fDenyTSConnections (0 = actif)' { (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections }
Ref 'RDP NLA (1 = exigée)' { (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication }
Ref 'UAC EnableLUA' { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA }
Ref 'BitLocker C: (1,3,5 = protégé)' { (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection') }
Ref 'Dernier correctif Windows' { Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 3 HotFixID, InstalledOn | Format-Table -AutoSize }
Ref 'Compte invité' { Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Select-Object Name, Enabled | Format-Table -AutoSize }
Ref 'Ports en écoute' { Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object { "{0}:{1} {2}" -f $_.LocalAddress, $_.LocalPort, (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
Ref 'Wi-Fi' { netsh wlan show interfaces }
Ref 'Réseau (IP)' { Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize }
Ref 'Passerelle (route print)' { route print -4 0.0.0.0 }
Ref 'Table ARP' { arp -a }
# Vérifications ajoutées de la 0.12 à la 0.19 : de quoi comparer avec ce que sentinel en conclut.
Ref 'DNS par carte (0.12)' { Get-DnsClientServerAddress | Where-Object ServerAddresses | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses | Format-Table -AutoSize }
Ref 'Certificats racine avec clé privée (0.12)' { Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object HasPrivateKey | Select-Object PSParentPath, Subject, Thumbprint | Format-List }
Ref 'Nombre de certificats racine (0.12)' { @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Select-Object -Unique Thumbprint).Count }
Ref 'Comptes locaux (0.13)' { Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, SID | Format-Table -AutoSize }
Ref 'LimitBlankPasswordUse (0.13)' { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').LimitBlankPasswordUse }
Ref 'Tâches planifiées hors Microsoft (0.13)' { Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { $t = $_; $t.Actions | ForEach-Object { '{0}{1} [{2}] {3} {4}' -f $t.TaskPath, $t.TaskName, $t.State, $_.Execute, $_.Arguments } } }
Ref 'Clés Run (0.13)' { foreach ($c in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') { "== $c"; Get-ItemProperty $c -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS* | Format-List } }
Ref 'Dossiers Démarrage (0.13)' { Get-ChildItem ([Environment]::GetFolderPath('Startup')), ([Environment]::GetFolderPath('CommonStartup')) -ErrorAction SilentlyContinue | Select-Object FullName }
Ref 'Ports UDP (0.13)' { Get-NetUDPEndpoint | Sort-Object LocalPort | ForEach-Object { '{0}:{1} {2}' -f $_.LocalAddress, $_.LocalPort, (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
Ref 'Volumes (0.15)' { Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, DriveType, SizeRemaining, Size | Format-Table -AutoSize }
Ref 'Disques physiques (0.15)' { Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus, OperationalStatus, MediaType | Format-Table -AutoSize }
Ref 'Batterie (0.15)' { Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object FullChargedCapacity; Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object DesignedCapacity }
Ref 'Extensions Edge et Chrome (0.14)' { foreach ($d in "$env:LOCALAPPDATA\Microsoft\Edge\User Data", "$env:LOCALAPPDATA\Google\Chrome\User Data") { Get-ChildItem $d -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName 'Extensions') } | ForEach-Object { "== $($_.FullName)"; Get-ChildItem (Join-Path $_.FullName 'Extensions') -Name } } }
Ref 'curl (0.17, 0.18)' { (Get-Command curl.exe -ErrorAction Stop).Source; curl.exe --version | Select-Object -First 1 }
# Vérifications ajoutées de la 0.20 à la 0.35.
Ref 'Journaux effacés, événement 104 (0.30)' { Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104 } -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List }
Ref 'Edge : Safe Browsing et DNS chiffré (0.31)' { $p = Get-Content "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Preferences" -Raw -ErrorAction Stop | ConvertFrom-Json; 'safebrowsing.enabled = ' + $p.safebrowsing.enabled; $l = Get-Content "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State" -Raw -ErrorAction Stop | ConvertFrom-Json; 'dns_over_https.mode = ' + $l.dns_over_https.mode }
Ref 'Zones thermiques (0.24)' { Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction Stop | Select-Object Name, HighPrecisionTemperature | Format-Table -AutoSize }
Ref 'LLMNR (0.23)' { (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast }
Ref 'UPnP de la box (0.33)' { $c = (New-Object -ComObject HNetCfg.NATUPnP).StaticPortMappingCollection; if ($null -eq $c) { 'aucune box UPnP' } else { $c | Select-Object Protocol, ExternalPort, InternalClient, InternalPort, Description | Format-Table -AutoSize } }
Ref 'Windows Sandbox (0.35)' { Test-Path "$env:SystemRoot\System32\WindowsSandbox.exe" }
Note 'Référence enregistrée.'

Etape '2. Version et aide'
Lancer 'version' @('--version')
Lancer 'aide' @('--help')

Etape '3. Audit de la machine (texte et JSON)'
Lancer 'machine' @('machine')
Lancer 'machine-json' @('machine', '--json')
# Vérifications qui n'ont pas pu se faire : un script PowerShell de sentinel a échoué (à corriger côté sentinel).
try {
    $audit = Get-Content (Join-Path $res 'machine-json.out.txt') -Raw -Encoding UTF8 | ConvertFrom-Json
    $impossibles = @($audit.constats | Where-Object { -not $_.verifie })
    Note "Vérifications impossibles : $($impossibles.Count)"
    $impossibles | ForEach-Object { Note "  IMPOSSIBLE : $($_.categorie) — $($_.message)" }
    foreach ($cat in 'DNS', 'Certificats', 'Extensions', 'Navigateur', 'Santé', 'Persistance', 'Comptes', 'Journaux', 'Intégrité') {
        $n = @($audit.constats | Where-Object categorie -eq $cat).Count
        Note "  $cat : $n constat(s)"
    }
} catch { Note "machine --json illisible : $($_.Exception.Message)" }

Etape '4. Scan du réseau de la VM'
Lancer 'reseau' @('reseau')
Lancer 'reseau-json' @('reseau', '--json')

Etape '5. Tous les ports de cette machine (127.0.0.1)'
Lancer 'local-tous' @('reseau', '127.0.0.1', '-p', 'tous')

Etape '5b. Persistance suspecte : fausse tâche planifiée et fausse entrée de démarrage (0.13)'
Write-Host 'Sentinel doit repérer une tâche « PowerShell caché en base64 » et un programme lancé depuis C:\Users\Public.' -ForegroundColor Yellow
Write-Host 'Les deux sont inoffensives (la tâche affiche « test » et ne se déclenche pas avant 5 ans) et retirées juste après.' -ForegroundColor Yellow
if (Question 'Faire ce test ?' 'o') {
    try {
        Register-ScheduledTask -TaskName 'sentinel-test-suspect' -Force `
            -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -enc VwByAGkAdABlAC0ASABvAHMAdAAgAHQAZQBzAHQA') `
            -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(5)) | Out-Null
        Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'sentinel-test-suspect' -Value 'C:\Users\Public\sentinel-test.exe /q'
        Lancer 'machine-persistance' @('machine')
        $sortie = Get-Content (Join-Path $res 'machine-persistance.out.txt') -Raw -Encoding UTF8
        if ($sortie -match 'sentinel-test-suspect.*base64|base64.*sentinel-test-suspect') { Note 'Tâche suspecte repérée : OK' } else { Note 'Tâche suspecte NON repérée (bug)' }
        if ($sortie -match 'Public') { Note 'Entrée Run suspecte repérée : OK' } else { Note 'Entrée Run suspecte NON repérée (bug)' }
    } catch { Note "Test de persistance impossible : $($_.Exception.Message)" }
    finally {
        Unregister-ScheduledTask -TaskName 'sentinel-test-suspect' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'sentinel-test-suspect' -ErrorAction SilentlyContinue
        Note 'Fausse tâche et fausse entrée retirées.'
    }
}

Etape '5b2. Intégrité des fichiers critiques (0.32)'
Lancer 'integrite-reference' @('integrite')
Lancer 'integrite-verification' @('integrite')
$v = Get-Content (Join-Path $res 'integrite-verification.out.txt') -Raw -Encoding UTF8
if ($v -match 'identiques|identical') { Note 'Intégrité : 2e passage identique à la référence : OK' } else { Note 'Intégrité : 2e passage différent (à regarder)' }

Etape '5c. Test de connexion (0.18)'
Lancer 'connexion' @('connexion')

Etape '5d. Mots de passe fuités (0.17)'
if ($Auto) { Note 'AUTO : étape sautée (il faut taper un mot de passe).' } else {
Write-Host 'Tape « password » (il doit être trouvé des millions de fois), puis Entrée seule pour terminer.' -ForegroundColor Yellow
& $exe motdepasse
Note "motdepasse -> code $LASTEXITCODE"
[void](Question 'La saisie était-elle masquée et « password » trouvé dans des fuites ?')
}

Etape '6. Menu (ouverture puis q)'
cmd /c "echo q| `"$exe`" > `"$res\menu.out.txt`" 2>&1"
Note "menu -> code $LASTEXITCODE"
# Entrée fermée (comme Ctrl-D) : sentinel doit quitter, pas tourner en boucle (bug corrigé en 0.9.7).
$vide = Join-Path $res 'vide.txt'
Set-Content -Path $vide -Value '' -NoNewline
$p = Start-Process -FilePath $exe -RedirectStandardInput $vide -RedirectStandardOutput (Join-Path $res 'menu-eof.out.txt') -NoNewWindow -PassThru
# Sans garder le handle tout de suite, PowerShell ne sait plus lire le code de sortie (il restait vide).
$null = $p.Handle
if ($p.WaitForExit(10000)) { Note "menu avec entrée fermée -> quitte (code $($p.ExitCode))" }
else { $p.Kill(); Note 'menu avec entrée fermée -> BOUCLE SANS FIN (bug)' }

Etape '7. Surveillance : activation puis désactivation (Planificateur de tâches)'
Lancer 'surveillance-on' @('surveillance', 'on')
# Nom de la tâche depuis la 0.11.0 (les anciennes tâches « netscan… » sont retirées à l'activation).
$tache = 'sentinel - surveillance du reseau'
Ref 'Tâche planifiée après activation' { Get-ScheduledTask -TaskName $tache | Select-Object TaskName, State, Description | Format-List; (Get-ScheduledTask -TaskName $tache).Actions | Format-List Execute, Arguments }
Lancer 'surveillance-off' @('surveillance', 'off')
Ref 'Tâche planifiée après désactivation' { if (Get-ScheduledTask -TaskName $tache -ErrorAction SilentlyContinue) { 'ENCORE PRÉSENTE (bug)' } else { 'absente (normal)' } }

Etape '8. Notification « nouvel appareil »'
$base = Join-Path $env:LOCALAPPDATA 'sentinel\appareils.json'
if (Test-Path $base) {
    # On retire un appareil de la base de test : au scan suivant, il doit être signalé comme nouveau.
    $json = Get-Content $base -Raw -Encoding UTF8 | ConvertFrom-Json
    $retire = $null
    foreach ($r in $json.reseaux.PSObject.Properties) {
        $premier = $r.Value.appareils.PSObject.Properties | Select-Object -First 1
        if ($premier) { $retire = $premier.Name; $r.Value.appareils.PSObject.Properties.Remove($premier.Name); break }
    }
    $json | ConvertTo-Json -Depth 10 | Set-Content $base -Encoding UTF8
    Note "Appareil retiré de la base de test : $retire"
    Write-Host 'Regarde le coin de l''écran : une notification « Nouvel appareil » doit apparaître…' -ForegroundColor Yellow
    Lancer 'surveiller' @('surveiller')
    Start-Sleep -Seconds 3
    [void](Question 'As-tu vu la notification « Nouvel appareil sur ton réseau » ?')
} else {
    Note 'Pas de base créée par le scan : test de notification sauté.'
}

Etape '9. Rapport HTML'
Lancer 'complet-html' @('complet', '--html')
Start-Sleep -Seconds 3
[void](Question 'Le rapport s''est-il ouvert dans le navigateur, lisible, avec les accents corrects ?')

Etape '10. Antivirus (analyse rapide Microsoft Defender)'
if (Question 'Lancer l''analyse rapide Defender (quelques minutes) ?') {
    Lancer 'antivirus' @('antivirus')
}

Etape '11. Corrections avec UAC (refus, puis acceptation, puis port bloqué)'
Write-Host 'Ce test coupe le pare-feu du profil « Privé » de la VM, puis sentinel doit le réparer.' -ForegroundColor Yellow
Write-Host 'sentinel ne bloque jamais le port 3389 et ne coupe jamais le Bureau à distance utilisé : ce test est sans risque.' -ForegroundColor Yellow
if (Question 'Faire ce test ?') {
    Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', 'Set-NetFirewallProfile -Profile Private -Enabled False'
    Ref 'Pare-feu après coupure volontaire' { Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize }

    Write-Host ''
    Write-Host '11a. Réponds « o » pour le pare-feu, puis clique NON dans la fenêtre UAC. Réponds « n » à tout le reste.' -ForegroundColor Yellow
    & $exe corriger
    Note "corriger (UAC refusée) -> code $LASTEXITCODE"
    [void](Question 'sentinel a-t-il dit « Demande d''administrateur refusée : rien n''a été modifié » (en anglais : « Administrator prompt refused: nothing was changed. ») et PAS « ✔ fait » ?')
    Ref 'Pare-feu après UAC refusée (Private doit rester False)' { Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize }

    Write-Host ''
    Write-Host '11b. Réponds « o » pour le pare-feu et accepte l''UAC. Pour les ports, réponds « o » au port 135 seulement, « n » à tout le reste.' -ForegroundColor Yellow
    & $exe corriger
    Note "corriger (UAC acceptée) -> code $LASTEXITCODE"
    Ref 'Pare-feu après sentinel corriger' { Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize }
    Ref 'Règles sentinel créées' { Get-NetFirewallRule -DisplayName 'sentinel : bloquer *' -ErrorAction SilentlyContinue | Select-Object DisplayName, Enabled, Action | Format-Table -AutoSize }
    if (-not (Get-NetFirewallProfile -Profile Private).Enabled) {
        Note 'Pare-feu Privé toujours coupé : remise en marche par le script.'
        Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', 'Set-NetFirewallProfile -Profile Private -Enabled True'
    }
    [void](Question 'La correction s''est-elle bien passée (affichage clair, une fenêtre UAC par correction, « OK » à chaque étape) ?')

    # Un port bloqué par sentinel ne doit plus être signalé comme à corriger (0.9.6).
    Lancer 'machine-apres-blocage' @('machine')
    $apres = Get-Content (Join-Path $res 'machine-apres-blocage.out.txt') -Raw -Encoding UTF8
    if ($apres -match 'bloqué en entrée par la règle|blocked inbound by the') { Note 'Port bloqué reconnu à l''audit suivant : OK' }
    else { Note 'Aucun port reconnu comme bloqué (normal seulement si aucun port n''a été bloqué en 11b)' }

    if (Question 'Retirer maintenant les règles « sentinel : bloquer » créées pendant le test ?') {
        Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', "Remove-NetFirewallRule -DisplayName 'sentinel : bloquer *'"
        Ref 'Règles sentinel après nettoyage' { @(Get-NetFirewallRule -DisplayName 'sentinel : bloquer *' -ErrorAction SilentlyContinue).Count }
    }
}

Etape '12. Couleurs et accents dans la console'
& $exe machine
[void](Question 'Dans l''audit ci-dessus, les couleurs et les accents (é, è, ✔, ✖) s''affichent-ils correctement ?')

if (-not $Auto) {
    $commentaire = Read-Host 'Un commentaire libre sur ce que tu as vu (Entrée pour passer)'
    if ($commentaire) { Note "COMMENTAIRE : $commentaire" }
}

Note "FIN $(Get-Date -Format 'HH:mm:ss')"
Write-Host ''
Write-Host 'Test terminé ! Les résultats sont dans le dossier partagé. Tu peux revenir sur Linux.' -ForegroundColor Green
