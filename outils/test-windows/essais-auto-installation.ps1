# Installe (ou retire, -Retirer) la file d'essais sans clic dans la machine virtuelle Windows de test : une tâche
# planifiée « Vanguard-File-Essais » qui fait, en administrateur, chaque travail déposé depuis Linux par
# outils/vm-tester.sh (surveillant-essais.ps1). Lancé par INSTALLER-ESSAIS-AUTO.bat ou DESINSTALLER-ESSAIS-AUTO.bat
# (double-clic, une fenêtre UAC) ; rien d'autre à faire ensuite.
param([switch]$Retirer, [switch]$Eleve)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ici = $PSScriptRoot
$tache = 'Vanguard-File-Essais'
$partage = '\\host.lan\Data\VANGUARD-TEST'
$file = Join-Path $partage 'file-essais'
# Par les dossiers connus de Windows, jamais par %ProgramData% ni %SystemRoot% : l'utilisateur sans droits peut
# redéfinir ces variables (HKCU\Environment), et la tâche tournera en administrateur.
$prive = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Vanguard-File-Essais'
$surveillant = Join-Path $prive 'surveillant-essais.ps1'
$powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$Utf8 = New-Object Text.UTF8Encoding $false
# Le dossier du surveillant : à Administrateurs, sans héritage ; administrateurs et SYSTEM y écrivent, Utilisateurs
# lisent (le même contrôle que Est-Protege dans surveillant-essais.ps1).
$sddlPrive = 'O:BAG:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)'

function Fin([int]$code) { Write-Host ''; Read-Host '  Entrée pour fermer' | Out-Null; exit $code }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    # La seule fenêtre UAC : ce script se relance en administrateur, dans le même compte.
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Eleve')
    if ($Retirer) { $arguments += '-Retirer' }
    try { Start-Process -FilePath $powershell -Verb RunAs -ArgumentList $arguments } catch { Write-Host "  Fenêtre UAC refusée : rien n'a changé." -ForegroundColor Yellow; Fin 1 }
    exit 0
}

function Est-Lien($item) { [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint) }
function Est-Protege([string]$dossier) {
    $item = Get-Item -LiteralPath $dossier -Force -ErrorAction SilentlyContinue
    if (-not $item -or -not $item.PSIsContainer -or (Est-Lien $item)) { return $false }
    $acl = Get-Acl -LiteralPath $dossier
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544' -or -not $acl.AreAccessRulesProtected) { return $false }
    $ecriture = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($r.AccessControlType -ne 'Allow' -or $r.IdentityReference.Value -in 'S-1-5-32-544', 'S-1-5-18') { continue }
        if ($r.IdentityReference.Value -eq 'S-1-5-32-545' -and -not ($r.FileSystemRights -band $ecriture)) { continue }
        return $false
    }
    $true
}

# Le dossier du surveillant, créé d'un coup avec ses droits. Un dossier déjà là qui n'a pas exactement ces droits (créé
# d'avance par un programme sans droits, qui s'y serait gardé un accès ou un fichier ouvert) n'est ni réparé ni vidé :
# il est écarté sous un autre nom (sans rien suivre, même si c'est un lien), puis le dossier est refait à neuf.
function Preparer-Prive {
    if (Test-Path -LiteralPath $prive) {
        if (Est-Protege $prive) { return }
        $ecarte = "$prive.ecarte-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        try { [IO.Directory]::Move($prive, $ecarte) } catch { throw "$prive existe sans les bons droits et ne peut pas être écarté ($($_.Exception.Message))" }
        Write-Host "  $prive n'avait pas les bons droits : écarté dans $ecarte (à examiner, puis effacer)." -ForegroundColor Yellow
    }
    $droits = New-Object Security.AccessControl.DirectorySecurity
    $droits.SetSecurityDescriptorSddlForm($sddlPrive)
    [void][IO.Directory]::CreateDirectory($prive, $droits)
    if (-not (Est-Protege $prive)) { throw "$prive : droits pas posés comme prévu (créé entre-temps par un autre programme ?)" }
}

# Le surveillant en marche (d'après pid.txt, vérifié par sa ligne de commande) et tout ce qu'il a lancé : ses
# descendants, et tout processus lancé depuis le dossier des travaux. Arrêter la boucle seule laisserait tourner
# test.ps1 en administrateur, Vanguard et ses fenêtres.
function Arreter-Boucle {
    $tous = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $arbre = New-Object System.Collections.Generic.List[int]
    $f = Join-Path $prive 'pid.txt'
    $id = if (Test-Path -LiteralPath $f) { ((Get-Content -LiteralPath $f -Encoding UTF8 | Select-Object -First 1) -as [int]) } else { 0 }
    $p = if ($id) { $tous | Where-Object { $_.ProcessId -eq $id } } else { $null }
    if ($p -and $p.Name -eq 'powershell.exe' -and $p.CommandLine -like "*$surveillant*") { $arbre.Add($id) }
    $travaux = (Join-Path $prive 'travaux') + '\'
    foreach ($x in $tous) {
        if ($x.ProcessId -ne $PID -and ("$($x.ExecutablePath)" -like "$travaux*" -or "$($x.CommandLine)" -like "*$travaux*")) { $arbre.Add([int]$x.ProcessId) }
    }
    for ($i = 0; $i -lt $arbre.Count; $i++) { $tous | Where-Object { $_.ParentProcessId -eq $arbre[$i] -and $_.ProcessId -ne $PID } | ForEach-Object { $arbre.Add([int]$_.ProcessId) } }
    foreach ($n in ($arbre | Select-Object -Unique)) { Stop-Process -Id $n -Force -ErrorAction SilentlyContinue }
    if ($arbre.Count) { Write-Host "  Surveillant et travail en cours arrêtés ($(@($arbre | Select-Object -Unique).Count) processus)." }
}

# Le travail qui tournait (file-essais\en-cours.txt) finit en erreur : Linux ne l'attend pas jusqu'à son délai, et ni
# le témoin des passes ni les règles de blocage du pare-feu (qui coupent RDP) ne restent derrière lui.
function Finir-Travail-Interrompu([string]$pourquoi) {
    $enCours = Join-Path $file 'en-cours.txt'
    $temoin = Join-Path $partage 'resultats\.test-en-cours.txt'
    $id = ''
    try { $id = (([IO.File]::ReadAllText($enCours) -split "`r?`n") | Where-Object { $_ -like 'id=*' } | Select-Object -First 1) -replace '^id=', '' } catch { }
    $temoinFile = $false
    try { $temoinFile = [IO.File]::ReadAllText($temoin).StartsWith('file-essais ') } catch { }
    if ($id -match '^\d{8}-\d{6}-[0-9a-f]{7,12}-[0-9a-z]{4}$') {
        $d = Join-Path $file $id
        if ((Test-Path -LiteralPath (Join-Path $d 'pris.txt')) -and -not (Test-Path -LiteralPath (Join-Path $d 'fini.txt'))) {
            $tmp = Join-Path $d 'fini.txt.tmp'
            [IO.File]::WriteAllText($tmp, "format=1`r`nid=$id`r`ncode=4`r`netat=erreur`r`nraison=$pourquoi : travail abandonné`r`nfin=$(Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz')`r`n", $Utf8)
            Move-Item -LiteralPath $tmp -Destination (Join-Path $d 'fini.txt') -Force
            Write-Host "  Travail $id interrompu : fini en erreur."
        }
        if ($temoinFile -or -not (Test-Path -LiteralPath $temoin)) {
            Get-NetFirewallRule -DisplayName 'Vanguard : bloquer*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $enCours -Force -ErrorAction SilentlyContinue
    if ($temoinFile) { Remove-Item -LiteralPath $temoin -Force -ErrorAction SilentlyContinue }
}

if ($Retirer) {
    Write-Host ''
    Write-Host '  VANGUARD · RETRAIT DE LA FILE D''ESSAIS SANS CLIC' -ForegroundColor Red
    Unregister-ScheduledTask -TaskName $tache -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  Tâche « $tache » retirée."
    Arreter-Boucle
    try { Finir-Travail-Interrompu 'file désinstallée en plein travail' } catch { Write-Host "  Travail en cours : $($_.Exception.Message)" -ForegroundColor Yellow }
    if (Test-Path -LiteralPath $prive) {
        # Effacé seulement s'il a les droits posés par l'installation : sinon (lien, dossier d'un autre), rien n'y est suivi.
        if (Est-Protege $prive) {
            Remove-Item -LiteralPath $prive -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $prive) { Write-Host "  $prive pas entièrement retiré (fichier ouvert ?)." -ForegroundColor Yellow } else { Write-Host "  $prive retiré." }
        } else { Write-Host "  $prive n'a pas les droits de l'installation : laissé tel quel, à examiner." -ForegroundColor Yellow }
    }
    $battement = Join-Path $file 'battement.txt'
    if (Test-Path -LiteralPath (Split-Path -Parent $battement)) {
        [IO.File]::WriteAllText($battement, "format=1`r`nheure=$(Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz')`r`nsurveillant=0`r`netat=desinstalle`r`nmachine=$env:COMPUTERNAME`r`n", $Utf8)
    }
    Write-Host '  File d''essais retirée. Les résultats (file-essais) et le menu des tests (choix 6) ne sont pas touchés.' -ForegroundColor Green
    Fin 0
}

Write-Host ''
Write-Host '  VANGUARD · FILE D''ESSAIS SANS CLIC' -ForegroundColor Red
Write-Host ''
# Jamais hors de la VM de test : le dossier partagé de la VM d'Omarchy doit être là.
if (-not (Test-Path -LiteralPath $partage -PathType Container)) {
    Write-Host "  $partage est introuvable : ce n'est pas la machine virtuelle de test. Rien n'est installé." -ForegroundColor Red
    Fin 1
}
try { $fabricant = (Get-CimInstance Win32_ComputerSystem).Manufacturer } catch { $fabricant = 'inconnu' }
Write-Host "  Machine : $env:COMPUTERNAME ($fabricant)." -ForegroundColor DarkGray
Write-Host ''
Write-Host '  Ce qui est déposé dans VANGUARD-TEST\file-essais (depuis Linux, outils/vm-tester.sh) sera lancé' -ForegroundColor Yellow
Write-Host '  EN ADMINISTRATEUR dans ce Windows, sans clic. Le dossier partagé s''écrit depuis Linux : tout programme' -ForegroundColor Yellow
Write-Host '  du compte Linux pourra devenir administrateur de cette VM. À n''installer que dans la VM de test.' -ForegroundColor Yellow
Write-Host '  L''empreinte SHA-256 de chaque fichier est vérifiée ; ce n''est pas une signature.' -ForegroundColor Yellow
Write-Host '  Pendant un essai, des fenêtres de Vanguard s''ouvrent environ 1 min : ne pas taper dedans.' -ForegroundColor Yellow
Write-Host ''
if ((Read-Host '  Installer ? [o/N]') -notmatch '^(o|oui|y|yes)$') { Write-Host '  Rien n''est installé.'; Fin 1 }

try {
    # Le surveillant tourne en administrateur en permanence : son dossier n'est modifiable que par les administrateurs.
    # La tâche d'abord retirée : elle ne relance pas l'ancienne boucle pendant la mise à jour.
    Unregister-ScheduledTask -TaskName $tache -Confirm:$false -ErrorAction SilentlyContinue
    Arreter-Boucle
    try { Finir-Travail-Interrompu 'file réinstallée en plein travail' } catch { Write-Host "  Travail en cours : $($_.Exception.Message)" -ForegroundColor Yellow }
    Preparer-Prive
    # Lu une fois du partage, écrit tel quel, puis relu : ce qui tourne est ce qui a été lu.
    $octets = [IO.File]::ReadAllBytes((Join-Path $ici 'surveillant-essais.ps1'))
    $sha = [Security.Cryptography.SHA256]::Create()
    $attendue = ([BitConverter]::ToString($sha.ComputeHash($octets)) -replace '-', '').ToLower()
    [IO.File]::WriteAllBytes($surveillant, $octets)
    if ((Get-FileHash -LiteralPath $surveillant -Algorithm SHA256).Hash.ToLower() -ne $attendue) { throw 'copie du surveillant différente de l''original' }
    [IO.File]::WriteAllText((Join-Path $prive 'version.txt'), "installe=$(Get-Date -Format o)`r`nsha256=$attendue`r`n", $Utf8)

    # Le compte par le jeton de ce processus, pas par %USERNAME% (réglable par l'utilisateur).
    $moi = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $action = New-ScheduledTaskAction -Execute $powershell `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$surveillant`""
    $declencheurs = @(
        (New-ScheduledTaskTrigger -AtLogOn -User $moi),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5))
    )
    # Une boucle, sans limite de durée ; IgnoreNew + le verrou du surveillant : jamais deux boucles.
    $reglages = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan) -StartWhenAvailable `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    # Session ouverte (Interactive) : les essais de console ont besoin du bureau ; autorisations maximales.
    $principal = New-ScheduledTaskPrincipal -UserId $moi -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $tache -Action $action -Trigger $declencheurs -Settings $reglages -Principal $principal `
        -Description 'Vanguard : fait en administrateur chaque travail déposé depuis Linux dans VANGUARD-TEST\file-essais (outils/vm-tester.sh).' -Force | Out-Null
    Start-ScheduledTask -TaskName $tache
    $battement = Join-Path $file 'battement.txt'
    $depuis = Get-Date; $vu = $false
    while (((Get-Date) - $depuis).TotalSeconds -lt 30) {
        $b = Get-Item -LiteralPath $battement -ErrorAction SilentlyContinue
        if ($b -and $b.LastWriteTime -ge $depuis.AddSeconds(-2)) { $vu = $true; break }
        Start-Sleep -Seconds 1
    }
    if ($vu) { Write-Host '  Installé : la tâche tourne (battement vu). Linux peut lancer outils/vm-tester.sh.' -ForegroundColor Green }
    else { Write-Host "  Installé, mais pas encore de battement dans $battement (voir $prive\journal.txt)." -ForegroundColor Yellow }
    Fin 0
} catch {
    Write-Host "  Échec : $($_.Exception.Message)" -ForegroundColor Red
    Fin 1
}
