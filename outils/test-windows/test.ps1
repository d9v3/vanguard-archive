# Test complet de sentinel sur un vrai Windows.
# 1) relève l'état réel du système (référence), 2) lance sentinel, 3) étapes guidées.
# Tous les résultats vont dans le dossier « resultats » à côté de ce script.

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8

$partage = Split-Path -Parent $MyInvocation.MyCommand.Path
$res = Join-Path $partage 'resultats'
New-Item -ItemType Directory -Force $res | Out-Null
Get-ChildItem $res | Remove-Item -Force -ErrorAction SilentlyContinue

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

function Question($texte) {
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
Note 'Référence enregistrée.'

Etape '2. Version et aide'
Lancer 'version' @('--version')
Lancer 'aide' @('--help')

Etape '3. Audit de la machine (texte et JSON)'
Lancer 'machine' @('machine')
Lancer 'machine-json' @('machine', '--json')

Etape '4. Scan du réseau de la VM'
Lancer 'reseau' @('reseau')
Lancer 'reseau-json' @('reseau', '--json')

Etape '5. Tous les ports de cette machine (127.0.0.1)'
Lancer 'local-tous' @('reseau', '127.0.0.1', '-p', 'tous')

Etape '6. Menu (ouverture puis q)'
cmd /c "echo q| `"$exe`" > `"$res\menu.out.txt`" 2>&1"
Note "menu -> code $LASTEXITCODE"
# Entrée fermée (comme Ctrl-D) : sentinel doit quitter, pas tourner en boucle (bug corrigé en 0.9.7).
$vide = Join-Path $res 'vide.txt'
Set-Content -Path $vide -Value '' -NoNewline
$p = Start-Process -FilePath $exe -RedirectStandardInput $vide -RedirectStandardOutput (Join-Path $res 'menu-eof.out.txt') -NoNewWindow -PassThru
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
    [void](Question 'sentinel a-t-il dit « Demande d''administrateur refusée : rien n''a été modifié » (et PAS « ✔ fait ») ?')

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
    if ($apres -match 'bloqué en entrée par la règle') { Note 'Port bloqué reconnu à l''audit suivant : OK' }
    else { Note 'Aucun port reconnu comme bloqué (normal seulement si aucun port n''a été bloqué en 11b)' }

    if (Question 'Retirer maintenant les règles « sentinel : bloquer » créées pendant le test ?') {
        Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', "Remove-NetFirewallRule -DisplayName 'sentinel : bloquer *'"
        Ref 'Règles sentinel après nettoyage' { @(Get-NetFirewallRule -DisplayName 'sentinel : bloquer *' -ErrorAction SilentlyContinue).Count }
    }
}

Etape '12. Couleurs et accents dans la console'
& $exe machine
[void](Question 'Dans l''audit ci-dessus, les couleurs et les accents (é, è, ✔, ✖) s''affichent-ils correctement ?')

$commentaire = Read-Host 'Un commentaire libre sur ce que tu as vu (Entrée pour passer)'
if ($commentaire) { Note "COMMENTAIRE : $commentaire" }

Note "FIN $(Get-Date -Format 'HH:mm:ss')"
Write-Host ''
Write-Host 'Test terminé ! Les résultats sont dans le dossier partagé. Tu peux revenir sur Linux.' -ForegroundColor Green
