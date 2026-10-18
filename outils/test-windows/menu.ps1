# Menu des tests de Sentinel dans la machine virtuelle Windows : double-clic sur TESTER-SENTINEL.bat.
# Le dossier « programme » (sentinel.exe, ce menu, test.ps1, version.txt) est remplacé à chaque déploiement depuis
# Linux (outils/deployer.sh) ; les résultats de chaque passe vont dans « resultats » et y restent.
# -Surveiller : lancé par la tâche planifiée (choix 6) ; teste en arrière-plan chaque nouvelle version déposée, une
# seule fois, puis prévient par une notification.
param([switch]$Surveiller)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8

$programme = $PSScriptRoot
$racine = Split-Path -Parent $programme
$resultats = Join-Path $racine 'resultats'
New-Item -ItemType Directory -Force $resultats | Out-Null
$tache = 'Sentinel - tester chaque nouvelle version'
$fichierVersion = Join-Path $programme 'version.txt'
$versionTestee = Join-Path $resultats '.version-testee.txt'
$enCours = Join-Path $resultats '.test-en-cours.txt'
$historique = Join-Path $resultats 'historique.txt'

# version.txt : « sentinel X.Y.Z » puis l'empreinte du programme (une nouvelle compilation change l'empreinte).
function Version-Deposee { if (Test-Path $fichierVersion) { (Get-Content $fichierVersion -Raw).Trim() } else { '' } }
function Version-Courte { ((Version-Deposee) -split "`r?`n")[0] }
function Version-Deja-Testee {
    $v = Version-Deposee
    $v -and (Test-Path $versionTestee) -and ((Get-Content $versionTestee -Raw).Trim() -eq $v)
}

# Un test à la fois : un autre (manuel ou automatique) peut tourner. Au-delà de 3 h, le témoin est périmé.
function Test-En-Cours {
    (Test-Path $enCours) -and (((Get-Date) - (Get-Item $enCours).LastWriteTime).TotalHours -lt 3)
}

# Dans un PowerShell à part : le test garde ses variables pour lui et ne peut pas fermer ce menu. Start-Process lui
# laisse la console (couleurs comprises) : appelé directement depuis une fonction, sa sortie deviendrait celle de la
# fonction et ne s'afficherait pas.
function Lancer-Test([string[]]$options) {
    if (Test-En-Cours) {
        Write-Host '  Un test tourne déjà (peut-être le test automatique) : attends qu''il finisse.' -ForegroundColor Yellow
        return $false
    }
    $version = Version-Deposee
    Set-Content -Path $enCours -Value (Get-Date -Format o)
    try {
        $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $programme 'test.ps1')`"") + $options
        Start-Process powershell.exe -ArgumentList $arguments -NoNewWindow -Wait
        Set-Content -Path $versionTestee -Value $version -Encoding UTF8
    } finally {
        Remove-Item $enCours -ErrorAction SilentlyContinue
    }
    return $true
}

# Notification Windows (dans le coin de l'écran) ; sans elle, l'historique suffit.
function Notifier($titre, $texte) {
    try {
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $e = [System.Security.SecurityElement]
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$($e::Escape($titre))</text><text>$($e::Escape($texte))</text></binding></visual></toast>")
        $appli = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appli).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
    } catch { }
}

function Derniere-Passe {
    if (Test-Path $historique) { (Get-Content $historique -Encoding UTF8 | Where-Object { $_ } | Select-Object -Last 1) } else { $null }
}

if ($Surveiller) {
    if (-not (Version-Deposee) -or (Version-Deja-Testee) -or (Test-En-Cours)) { exit 0 }
    if (Lancer-Test @('-Auto', '-SansOuvrir')) {
        Notifier "Sentinel : $(Version-Courte) testée" ((Derniere-Passe) -replace '\s+->.*$', '')
    }
    exit 0
}

# Tâche planifiée du compte, sans droits administrateur : à l'ouverture de session puis toutes les 15 minutes.
function Surveillance-Active { [bool](Get-ScheduledTask -TaskName $tache -ErrorAction SilentlyContinue) }
function Basculer-Surveillance {
    if (Surveillance-Active) {
        Unregister-ScheduledTask -TaskName $tache -Confirm:$false
        Write-Host '  Test automatique désactivé.' -ForegroundColor Yellow
        return
    }
    $moi = "$env:USERDOMAIN\$env:USERNAME"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$(Join-Path $programme 'menu.ps1')`" -Surveiller"
    $declencheurs = @(
        (New-ScheduledTaskTrigger -AtLogOn -User $moi),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15))
    )
    $reglages = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 3)
    $principal = New-ScheduledTaskPrincipal -UserId $moi -LogonType Interactive -RunLevel Limited
    try {
        Register-ScheduledTask -TaskName $tache -Action $action -Trigger $declencheurs -Settings $reglages -Principal $principal `
            -Description 'Teste en arrière-plan chaque nouvelle version de Sentinel déposée depuis Linux, puis prévient.' -Force -ErrorAction Stop | Out-Null
        Write-Host '  Test automatique activé : chaque nouvelle version sera testée seule (dans la minute, puis toutes les 15 minutes),' -ForegroundColor Green
        Write-Host '  sans rien ouvrir à l''écran ; une notification prévient à la fin.' -ForegroundColor Green
    } catch {
        Write-Host "  Impossible de créer la tâche planifiée : $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Ouvrir-Sentinel {
    # Une copie locale, comme pour le test : un .exe sur un partage réseau déclenche des avertissements.
    $local = Join-Path $env:LOCALAPPDATA 'sentinel-test'
    New-Item -ItemType Directory -Force $local | Out-Null
    Copy-Item (Join-Path $programme 'sentinel.exe') $local -Force
    $exe = Join-Path $local 'sentinel.exe'
    Unblock-File $exe -ErrorAction SilentlyContinue
    Start-Process $exe
}

function Pause-Menu { Write-Host ''; Read-Host '  Entrée pour revenir au menu' | Out-Null }

while ($true) {
    Clear-Host
    $auto = Surveillance-Active
    $etatAuto = if ($auto) { 'ACTIVÉ' } else { 'désactivé' }
    $testee = if (Version-Deja-Testee) { 'déjà testée' } else { 'pas encore testée' }
    Write-Host ''
    Write-Host '  ╭──────────────────────────────────────────────────────────────╮' -ForegroundColor Red
    Write-Host ('  │  ' + 'SENTINEL · TESTS SUR CE WINDOWS'.PadRight(60) + '│') -ForegroundColor Red
    Write-Host ('  │  ' + "Version déposée : $(Version-Courte) ($testee)".PadRight(60) + '│') -ForegroundColor Red
    Write-Host '  ╰──────────────────────────────────────────────────────────────╯' -ForegroundColor Red
    Write-Host ''
    Write-Host '   1  Test complet automatique, sans question    5 à 15 min, conseillé'
    Write-Host '   2  Test complet avec questions                fenêtres UAC, mot de passe, écran'
    Write-Host '   3  Ouvrir Sentinel                            pour essayer à la main'
    Write-Host '   4  Voir le dernier rapport'
    Write-Host '   5  Ouvrir le dossier des résultats'
    Write-Host "   6  Tester seul chaque nouvelle version        $etatAuto"
    Write-Host '   Q  Quitter'
    if (Test-Path $historique) {
        Write-Host ''
        Write-Host '  Dernières passes :' -ForegroundColor DarkGray
        Get-Content $historique -Encoding UTF8 | Where-Object { $_ } | Select-Object -Last 5 |
            ForEach-Object { Write-Host ('   ' + ($_ -replace '\s+->.*$', '')) -ForegroundColor DarkGray }
    }
    if (Test-En-Cours) { Write-Host ''; Write-Host '  Un test tourne en ce moment.' -ForegroundColor Yellow }
    Write-Host ''
    switch ((Read-Host '  Choix').Trim().ToLower()) {
        '1' { [void](Lancer-Test @('-Auto')); Pause-Menu }
        '2' { [void](Lancer-Test @()); Pause-Menu }
        '3' { Ouvrir-Sentinel }
        '4' {
            $r = Join-Path $resultats 'dernier-rapport.html'
            if (Test-Path $r) { Start-Process $r } else { Write-Host '  Aucun rapport pour l''instant : lance un test (1).' -ForegroundColor Yellow; Pause-Menu }
        }
        '5' { Start-Process explorer.exe $resultats }
        '6' { Basculer-Surveillance; Pause-Menu }
        'q' { exit 0 }
    }
}
