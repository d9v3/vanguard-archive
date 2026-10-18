# Test complet de Gardien sur un vrai Windows.
# 1) relève l'état réel du système (référence), 2) lance Gardien, 3) vérifie ses réponses.
# Pendant le test : une ligne par commande et par vérification, sans les sorties brutes. À la fin : un rapport HTML
# (rapport-test.html, ouvert dans le navigateur), avec la sortie de chaque commande à déplier.
# Rangement du dossier partagé : ce script et gardien.exe dans « programme » (remplacés à chaque déploiement),
# chaque passe dans « resultats\AAAA-MM-JJ_HH-MM-SS_vX.Y.Z », une ligne par passe dans « resultats\historique.txt »
# et le dernier rapport dans « resultats\dernier-rapport.html ». Lancé par le menu (TESTER-GARDIEN.bat).

# -Auto : aucune question ; les étapes qui demandent de taper ou une fenêtre UAC sont sautées.
# -SansOuvrir : rien ne s'ouvre à l'écran (test lancé en arrière-plan par la tâche planifiée du menu).
param([switch]$Auto, [switch]$SansOuvrir)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8

$ici = Split-Path -Parent $MyInvocation.MyCommand.Path
$racine = if ((Split-Path -Leaf $ici) -eq 'programme') { Split-Path -Parent $ici } else { $ici }
$resultats = Join-Path $racine 'resultats'

# On lance une copie locale : un .exe sur un partage réseau déclenche des avertissements de sécurité.
$local = Join-Path $env:LOCALAPPDATA 'gardien-test'
New-Item -ItemType Directory -Force $local | Out-Null
Copy-Item (Join-Path $ici 'gardien.exe') $local -Force
$exe = Join-Path $local 'gardien.exe'
Unblock-File $exe -ErrorAction SilentlyContinue
$version = (& $exe --version 2>$null | Out-String).Trim()
$numero = if ($version -match '\d+\.\d+\.\d+') { $Matches[0] } else { 'inconnue' }
$res = Join-Path $resultats ((Get-Date -Format 'yyyy-MM-dd_HH-mm-ss') + "_v$numero")
New-Item -ItemType Directory -Force $res | Out-Null
$debutTest = Get-Date

# ── Suivi des résultats : chaque étape garde ses commandes et ses vérifications, pour l'écran et le rapport ──
$script:etapes = New-Object System.Collections.ArrayList
$script:etape = $null

function Journal($texte) { Add-Content -Path (Join-Path $res 'journal.txt') -Value $texte -Encoding UTF8 }

function Etape($nom) {
    $script:etape = [pscustomobject]@{ Titre = $nom; Commandes = New-Object System.Collections.ArrayList; Verifs = New-Object System.Collections.ArrayList }
    [void]$script:etapes.Add($script:etape)
    Journal "=== $nom === $(Get-Date -Format 'HH:mm:ss')"
    Write-Host ''
    Write-Host ("  ▸ " + $nom) -ForegroundColor Cyan
}

# Une vérification : OK (vert), Bug (rouge), Info (gris). Aussi dans le journal et le rapport.
function Verif($etat, $texte) {
    [void]$script:etape.Verifs.Add([pscustomobject]@{ Etat = $etat; Texte = $texte })
    Journal "$($etat.ToUpper()) : $texte"
    switch ($etat) {
        'ok' { Write-Host '      ✔ ' -ForegroundColor Green -NoNewline; Write-Host $texte }
        'bug' { Write-Host '      ✖ ' -ForegroundColor Red -NoNewline; Write-Host $texte -ForegroundColor Red }
        default { Write-Host "      · $texte" -ForegroundColor DarkGray }
    }
}
function Ok($texte) { Verif 'ok' $texte }
function Bug($texte) { Verif 'bug' $texte }
function Info($texte) { Verif 'info' $texte }

# Texte court d'une commande pour l'écran : les longs chemins sont réduits à leur nom de fichier.
function Court([string[]]$arguments) {
    ($arguments | ForEach-Object { if ($_ -match '[\\/]') { Split-Path $_ -Leaf } else { $_ } }) -join ' '
}

function Noter-Commande($fichier, [string[]]$arguments, $code, $duree, $entree) {
    [void]$script:etape.Commandes.Add([pscustomobject]@{ Fichier = $fichier; Arguments = ($arguments -join ' '); Code = $code; Duree = $duree; Entree = $entree })
    Journal ("gardien {0} -> code {1}, {2:N1} s" -f ($arguments -join ' '), $code, $duree)
    $texte = if ($arguments) { 'gardien ' + (Court $arguments) } else { 'gardien (menu)' }
    if ($texte.Length -gt 58) { $texte = $texte.Substring(0, 57) + '…' }
    Write-Host ('      ' + $texte.PadRight(60)) -NoNewline
    if ($code -eq 0) { Write-Host '✔' -ForegroundColor Green -NoNewline } else { Write-Host "✖ code $code" -ForegroundColor Red -NoNewline }
    Write-Host (' {0,6:N1} s' -f $duree) -ForegroundColor DarkGray
}

# Lance Gardien sans interaction ; garde sortie, erreurs, code de retour et durée.
function Lancer($fichier, [string[]]$arguments) {
    $debut = Get-Date
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput (Join-Path $res "$fichier.out.txt") -RedirectStandardError (Join-Path $res "$fichier.err.txt")
    Noter-Commande $fichier $arguments $p.ExitCode ((Get-Date) - $debut).TotalSeconds $null
}

# Comme Lancer, avec des réponses tapées d'avance (une par ligne) : menus et questions sans personne au clavier.
function LancerAvec($fichier, [string[]]$arguments, [string]$entree) {
    $f = Join-Path $res "$fichier.entree.txt"
    [IO.File]::WriteAllText($f, $entree.Replace("`n", "`r`n"))
    $debut = Get-Date
    # Start-Process refuse une liste d'arguments vide (menu sans argument) : on ne la passe que si elle existe.
    $options = @{ FilePath = $exe; NoNewWindow = $true; Wait = $true; PassThru = $true; RedirectStandardInput = $f
        RedirectStandardOutput = (Join-Path $res "$fichier.out.txt"); RedirectStandardError = (Join-Path $res "$fichier.err.txt") }
    if ($arguments) { $options.ArgumentList = $arguments }
    $p = Start-Process @options
    Noter-Commande $fichier $arguments $p.ExitCode ((Get-Date) - $debut).TotalSeconds ($entree.Replace("`n", ' ⏎ ').Trim())
}

function Sortie($fichier) { Get-Content (Join-Path $res "$fichier.out.txt") -Raw -Encoding UTF8 }

# Les touches tapées pendant une étape longue (test de connexion…) restent dans la console : sans les vider, un
# Entrée en trop répond à la place de la personne (mot de passe vide, question sans réponse).
function Vider-Clavier { try { $Host.UI.RawUI.FlushInputBuffer() } catch { } }

function Question($texte, $reponseAuto = 'n') {
    if ($Auto) {
        Journal "AUTO : $texte -> $reponseAuto"
        return $reponseAuto -eq 'o'
    }
    Write-Host "      ? $texte [o/n] " -ForegroundColor Yellow -NoNewline
    Vider-Clavier
    $r = Read-Host
    Journal "QUESTION : $texte -> $r"
    $oui = $r -match '^(o|oui|y)'
    return $oui
}

# Question dont la réponse est elle-même une vérification (« as-tu vu… ? »).
function Constat($texte) {
    if ($Auto) { Info "$texte (non vérifié : test sans personne)"; return }
    if (Question $texte) { Ok $texte } else { Bug $texte }
}

# Référence : chaque valeur lue directement, pour comparer avec les conclusions de Gardien.
# Dans un espace d'exécution à part, avec un délai : une commande de Windows bloquée (Get-ScheduledTask, CIM…) ne
# fige plus toute la passe. Bloquée, elle est laissée de côté (l'arrêter pourrait bloquer aussi) et finit avec la passe.
function Ref($nom, [scriptblock]$bloc, [int]$delai = 30) {
    $ps = [powershell]::Create()
    try {
        # Les variables du test dont un bloc a besoin.
        foreach ($n in @('tache')) {
            $valeur = Get-Variable -Name $n -ValueOnly -ErrorAction SilentlyContinue
            if ($null -ne $valeur) { $ps.Runspace.SessionStateProxy.SetVariable($n, $valeur) }
        }
        [void]$ps.AddScript($bloc.ToString()).AddCommand('Out-String')
        $attente = $ps.BeginInvoke()
        if ($attente.AsyncWaitHandle.WaitOne($delai * 1000)) {
            $v = ($ps.EndInvoke($attente) | Out-String).Trim()
            if (-not $v -and $ps.Streams.Error.Count) { $v = "ERREUR : $($ps.Streams.Error[0])" }
            $ps.Dispose()
        } else { $v = "DÉLAI DÉPASSÉ ($delai s) : commande bloquée, laissée de côté" }
    } catch {
        # L'erreur du bloc arrive enveloppée par EndInvoke : son message d'origine est le plus lisible.
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        $v = "ERREUR : $($e.Message)"
    }
    Add-Content -Path (Join-Path $res 'reference.txt') -Value "### $nom`r`n$v`r`n" -Encoding UTF8
}

# ── Rapport HTML : bilan, étapes, vérifications, et la sortie de chaque commande à déplier ──
function Rapport {
    $h = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $ansi = [regex]'\x1b\[[0-9;]*[A-Za-z]'
    $toutes = @($script:etapes | ForEach-Object { $_.Verifs })
    $nbOk = @($toutes | Where-Object Etat -eq 'ok').Count
    $nbBug = @($toutes | Where-Object Etat -eq 'bug').Count
    $nbCmd = @($script:etapes | ForEach-Object { $_.Commandes }).Count
    $nbEchec = @($script:etapes | ForEach-Object { $_.Commandes } | Where-Object Code -ne 0).Count
    $duree = [math]::Round(((Get-Date) - $debutTest).TotalMinutes, 1)
    $windows = (Get-CimInstance Win32_OperatingSystem).Caption
    $reussi = $nbBug -eq 0 -and $nbEchec -eq 0
    $verdict = if ($reussi) { "✓ Tout est passé : $nbOk vérifications réussies" } else { "✗ $nbBug problème(s) · $nbEchec commande(s) en échec" }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Test de Gardien</title><style>
:root{--fond:#0b0808;--carte:#160f10;--trait:#2e2224;--texte:#eee3db;--gris:#a8968c;--rouge:#ff5a4f;--vert:#5fd38d;--jaune:#f2c14e}
*{box-sizing:border-box}body{margin:0;background:var(--fond);color:var(--texte);font:15px/1.5 system-ui,'Segoe UI',sans-serif}
main{max-width:980px;margin:0 auto;padding:28px 16px 60px}h1{margin:0 0 4px;font-size:26px}h1 b{color:var(--rouge)}
.sous{color:var(--gris);margin-bottom:22px}.bilan{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:26px}
.case{background:var(--carte);border:1px solid var(--trait);border-radius:10px;padding:12px 16px;min-width:150px}
.case b{display:block;font-size:24px}.case span{color:var(--gris);font-size:13px}
.etape{background:var(--carte);border:1px solid var(--trait);border-radius:10px;margin:0 0 12px;padding:14px 16px}
.etape h2{margin:0 0 8px;font-size:16px;display:flex;gap:8px;align-items:center}.pastille{width:10px;height:10px;border-radius:50%;background:var(--vert);flex:none}
.etape.rouge .pastille{background:var(--rouge)}.etape.grise .pastille{background:var(--gris)}
ul{margin:4px 0 8px;padding-left:4px;list-style:none}li{margin:2px 0}.ok{color:var(--vert)}.bug{color:var(--rouge)}.info{color:var(--gris)}
details{border-top:1px solid var(--trait);padding:6px 0}summary{cursor:pointer;display:flex;justify-content:space-between;gap:10px}
summary code{color:var(--texte);font-variant-ligatures:none}summary .d{color:var(--gris);white-space:nowrap}pre{background:#000;border-radius:8px;padding:10px;overflow:auto;max-height:420px;font:12.5px/1.45 Consolas,monospace;color:#ddd}
.entree{color:var(--jaune);font-size:12.5px}
.verdict{border-radius:12px;padding:16px 20px;font-size:20px;font-weight:600;margin-bottom:14px}
.verdict.vert{background:#0f2a1a;border:1px solid #1f6b3e;color:var(--vert)}.verdict.rouge{background:#2c0d0d;border:1px solid #7e1c1c;color:var(--rouge)}
</style></head><body><main>
<h1>Test de <b>Gardien</b></h1>
<div class="sous">$(& $h $version) · $(& $h $windows) · $(Get-Date -Format 'yyyy-MM-dd HH:mm') · $duree min$(if ($Auto) { ' · sans questions' })</div>
<div class="verdict $(if ($reussi) { 'vert' } else { 'rouge' })">$(& $h $verdict)</div>
<div class="bilan"><div class="case"><b class="ok">$nbOk</b><span>vérifications réussies</span></div>
<div class="case"><b class="$(if ($nbBug) { 'bug' } else { 'info' })">$nbBug</b><span>problèmes</span></div>
<div class="case"><b>$nbCmd</b><span>commandes ($nbEchec en échec)</span></div></div>
"@)
    foreach ($e in $script:etapes) {
        $rouge = @($e.Verifs | Where-Object Etat -eq 'bug').Count + @($e.Commandes | Where-Object Code -ne 0).Count
        $classe = if ($rouge) { 'rouge' } elseif (-not $e.Verifs.Count -and -not $e.Commandes.Count) { 'grise' } else { '' }
        [void]$sb.Append("<section class=""etape $classe""><h2><span class=""pastille""></span>$(& $h $e.Titre)</h2>")
        if ($e.Verifs.Count) {
            [void]$sb.Append('<ul>')
            foreach ($v in $e.Verifs) {
                $signe = switch ($v.Etat) { 'ok' { '✓' } 'bug' { '✗' } default { '·' } }
                [void]$sb.Append("<li class=""$($v.Etat)"">$signe $(& $h $v.Texte)</li>")
            }
            [void]$sb.Append('</ul>')
        }
        foreach ($c in $e.Commandes) {
            $sortie = ''
            foreach ($f in "$($c.Fichier).out.txt", "$($c.Fichier).err.txt") {
                $chemin = Join-Path $res $f
                # Un fichier vide se lit comme « rien » ($null) : on ne garde que ce qui a du texte.
                $texte = if (Test-Path $chemin) { Get-Content $chemin -Raw -Encoding UTF8 } else { $null }
                if ($texte) { $sortie += $ansi.Replace($texte, '') }
            }
            $etat = if ($c.Code -eq 0) { '<span class="ok">✓</span>' } else { "<span class=""bug"">✗ code $($c.Code)</span>" }
            $entree = if ($c.Entree) { "<div class=""entree"">réponses tapées : $(& $h $c.Entree)</div>" } else { '' }
            $complete = if ($c.Arguments) { "gardien $($c.Arguments)" } else { 'gardien (menu)' }
            $commande = if ($c.Arguments) { 'gardien ' + (Court ($c.Arguments -split ' ')) } else { 'gardien (menu)' }
            [void]$sb.Append("<details><summary><code title=""$(& $h $complete)"">$(& $h $commande)</code><span class=""d"">$etat $('{0:N1}' -f $c.Duree) s</span></summary>$entree<pre>$(& $h $sortie)</pre></details>")
        }
        [void]$sb.Append('</section>')
    }
    [void]$sb.Append('</main></body></html>')
    $chemin = Join-Path $res 'rapport-test.html'
    [IO.File]::WriteAllText($chemin, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    return $chemin
}

Clear-Host
Write-Host ''
Write-Host '  ╭──────────────────────────────────────────────────────────╮' -ForegroundColor Red
Write-Host ('  │  ' + "TEST DE GARDIEN · $version".PadRight(56) + '│') -ForegroundColor Red
Write-Host '  ╰──────────────────────────────────────────────────────────╯' -ForegroundColor Red
if ($SansOuvrir) { Write-Host '  En arrière-plan : rien ne s''ouvre, le rapport ira dans resultats.' -ForegroundColor DarkGray }
elseif ($Auto) { Write-Host '  Sans aucune question : 5 à 15 minutes. Le rapport s''ouvrira à la fin.' -ForegroundColor DarkGray }
else { Write-Host '  Quelques questions te seront posées : réponds o (oui) ou n (non).' -ForegroundColor DarkGray }

Etape 'Référence : état réel de Windows'
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
# Vérifications ajoutées de la 0.12 à la 0.19 : de quoi comparer avec ce que Gardien en conclut.
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
Info 'Référence enregistrée (reference.txt) : état lu directement dans Windows, pour comparer.'

Etape 'Version et aide'
Lancer 'version' @('--version')
Lancer 'aide' @('--help')

Etape 'Audit de la machine (texte et JSON)'
Lancer 'machine' @('machine')
Lancer 'machine-json' @('machine', '--json')
# Vérifications qui n'ont pas pu se faire : un script PowerShell de Gardien a échoué (à corriger côté Gardien).
try {
    $audit = Sortie 'machine-json' | ConvertFrom-Json
    $impossibles = @($audit.constats | Where-Object { -not $_.verifie })
    if ($impossibles.Count) { $impossibles | ForEach-Object { Bug "Vérification impossible : $($_.categorie) — $($_.message)" } }
    else { Ok "Toutes les vérifications ont pu se faire ($(@($audit.constats).Count) constats, note $($audit.score)/100)" }
} catch { Bug "machine --json illisible : $($_.Exception.Message)" }

Etape 'Scan du réseau de la VM'
Lancer 'reseau' @('reseau')
Lancer 'reseau-json' @('reseau', '--json')
try {
    $scan = Sortie 'reseau-json' | ConvertFrom-Json
    Ok "$(@($scan.hotes).Count) appareil(s) trouvé(s) sur $($scan.reseau)"
} catch { Bug "reseau --json illisible : $($_.Exception.Message)" }

Etape 'Tous les ports de cette machine (127.0.0.1)'
Lancer 'local-tous' @('reseau', '127.0.0.1', '-p', 'tous')

Etape 'Persistance suspecte : fausse tâche planifiée et fausse entrée de démarrage'
Info 'Une tâche « PowerShell caché en base64 » et un programme dans C:\Users\Public, inoffensifs, retirés juste après.'
if (Question 'Faire ce test ?' 'o') {
    try {
        Register-ScheduledTask -TaskName 'gardien-test-suspect' -Force `
            -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -enc VwByAGkAdABlAC0ASABvAHMAdAAgAHQAZQBzAHQA') `
            -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(5)) | Out-Null
        Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'gardien-test-suspect' -Value 'C:\Users\Public\gardien-test.exe /q'
        Lancer 'machine-persistance' @('machine')
        $sortie = Sortie 'machine-persistance'
        if ($sortie -match '(?s)gardien-test-suspect.*base64|base64.*gardien-test-suspect') { Ok 'Tâche suspecte repérée' } else { Bug 'Tâche suspecte NON repérée' }
        if ($sortie -match 'Public') { Ok 'Entrée de démarrage suspecte repérée' } else { Bug 'Entrée de démarrage suspecte NON repérée' }
    } catch { Bug "Test de persistance impossible : $($_.Exception.Message)" }
    finally {
        Unregister-ScheduledTask -TaskName 'gardien-test-suspect' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'gardien-test-suspect' -ErrorAction SilentlyContinue
        Info 'Fausse tâche et fausse entrée retirées.'
    }
}

Etape 'Intégrité des fichiers critiques'
Lancer 'integrite-reference' @('integrite')
Lancer 'integrite-verification' @('integrite')
if ((Sortie 'integrite-verification') -match 'identiques|identical') { Ok '2e passage identique à la référence' } else { Bug '2e passage différent de la référence' }

Etape 'Diagnostic de l''ordinateur'
Lancer 'diagnostic' @('diagnostic')
$d = Sortie 'diagnostic'
if ($d -match 'Blue screens|Écrans bleus') { Ok 'Section des problèmes récents présente' } else { Bug 'Section des problèmes récents ABSENTE' }
if ($d -match 'PowerShell is not responding|PowerShell ne répond pas') { Bug 'Lecture PowerShell en échec' }

Etape 'Logiciels : liste et menu, rien installé'
Lancer 'logiciels-liste' @('logiciels', '--liste')
$l = Sortie 'logiciels-liste'
# Une ligne par logiciel : « ✔ » (installé, en couleur) ou « · ».
$n = ([regex]::Matches($l, '(?m)^\s+(?:\x1b\[[0-9;]*m)?[✔·](?:\x1b\[[0-9;]*m)? ')).Count
if ($n -ge 30) { Ok "$n logiciels proposés" } else { Bug "Liste des logiciels trop courte ($n)" }
if ($l -match 'winget, Mozilla\.Firefox') { Ok 'Firefox proposé par winget' } else { Bug 'Firefox absent de la liste' }
if ($l -match 'PowerShell ne répond pas|PowerShell is not responding') { Bug 'Lecture des logiciels installés en échec' }
# Windows 11 a Windows Terminal d'office : application du Store, reconnue par son paquet (pas dans le registre).
if ([Environment]::OSVersion.Version.Build -ge 22000) {
    if ($l -match '(?m)✔(?:\x1b\[[0-9;]*m)? Windows Terminal') { Ok 'Windows Terminal reconnu (application du Store)' } else { Bug 'Windows Terminal, présent sur Windows 11, pas reconnu' }
}
LancerAvec 'logiciels' @('logiciels') "`n"
if ((Sortie 'logiciels') -match 'Pack de départ|Starter pack') { Ok 'Menu des logiciels affiché' } else { Bug 'Menu des logiciels absent' }

Etape 'Nettoyer le système : place à gagner, rien effacé'
Lancer 'nettoyer-liste' @('nettoyer', '--liste')
$n = Sortie 'nettoyer-liste'
if ($n -match 'rien n.a été effacé|nothing was deleted') { Ok 'Liste du nettoyage affichée' } else { Bug 'Liste du nettoyage absente' }
if ($n -match '(?m)(Tes fichiers temporaires|Your temporary files)\s+\S') { Ok 'Fichiers temporaires mesurés' } else { Bug 'Fichiers temporaires non mesurés' }
if ($n -match 'Disque du système|System disk') { Ok 'Place libre du disque lue' } else { Bug 'Place libre du disque non lue (PowerShell)' }

Etape 'Test de connexion'
Lancer 'connexion' @('connexion')
if ((Sortie 'connexion') -match 'Mbit/s') { Ok 'Débit mesuré' } else { Bug 'Débit non mesuré' }

Etape 'Mots de passe fuités'
if ($Auto) { Info 'Sautée : il faut taper un mot de passe (test avec questions).' } else {
    Write-Host '      Tape « password » (il doit être trouvé des millions de fois), puis Entrée seule pour terminer.' -ForegroundColor Yellow
    Vider-Clavier
    & $exe motdepasse
    Constat 'La saisie était-elle masquée et « password » trouvé dans des fuites ?'
}

Etape 'Réparer (liste), mises à jour (vérification seule), gaming, courriel refusé'
LancerAvec 'reparer' @('reparer') "`n"
$n = ([regex]::Matches(((Sortie 'reparer') -replace '\x1b\[[0-9;]*m', ''), '(?m)^\s+\d+\s{2,}\S')).Count
if ($n -gt 0) { Ok "$n réparation(s) proposée(s)" } else { Bug 'Liste des réparations vide' }
LancerAvec 'maj' @('maj') "n`nn`nn`nn`nn`n"
LancerAvec 'gaming' @('gaming') "`n"
LancerAvec 'courriel' @('courriel') "test@example.com`nn`n"
if ((Sortie 'courriel') -match 'XposedOrNot|accord|consent') { Ok 'Accord demandé avant d''envoyer l''adresse' } else { Bug 'Accord NON demandé avant l''envoi' }

Etape 'Données : sauvegarde puis restauration'
$sauvegarde = Join-Path $res 'sauvegarde.json'
Lancer 'sauvegarder' @('sauvegarder', $sauvegarde)
Lancer 'restaurer' @('restaurer', $sauvegarde)
if ((Test-Path $sauvegarde) -and (Get-Item $sauvegarde).Length -gt 0) { Ok 'Sauvegarde écrite puis relue' } else { Bug 'Sauvegarde ABSENTE' }

Etape 'Nommer la box trouvée par le scan, puis retirer le surnom'
try {
    $box = ((Sortie 'reseau-json' | ConvertFrom-Json).hotes | Where-Object { $_.role -eq 'passerelle' } | Select-Object -First 1).ip
    if ($box) {
        Lancer 'nommer' @('nommer', $box, 'box', 'de', 'test')
        if ((Sortie 'nommer') -match 'box de test') { Ok "Surnom donné à la box ($box)" } else { Bug "Surnom NON donné à la box ($box)" }
        Lancer 'nommer-retrait' @('nommer', $box)
    } else { Info 'Pas de box dans le scan : étape sautée.' }
} catch { Bug "Scan illisible ($($_.Exception.Message))" }

Etape 'Antivirus d''un dossier propre (Defender, analyse ciblée)'
$propre = Join-Path $env:TEMP 'gardien-dossier-propre'
New-Item -ItemType Directory -Force $propre | Out-Null
Set-Content -Path (Join-Path $propre 'note.txt') -Value 'fichier sans danger' -Encoding UTF8
LancerAvec 'antivirus-dossier' @('antivirus', $propre) "n`nn`n"
if ((Sortie 'antivirus-dossier') -match 'No malware found|Aucun malware|aucune menace|found no threats') { Ok 'Dossier analysé, rien trouvé' } else { Bug 'Résultat de l''analyse introuvable' }
Remove-Item $propre -Recurse -Force -ErrorAction SilentlyContinue

Etape 'Menu : chaque groupe ouvert puis refermé'
LancerAvec 'menu' @() "4`n`n5`n`n6`n`n7`n`n8`n`n9`n`n10`n`n11`n`nq`n"
$m = Sortie 'menu'
# Une ligne propre à chaque sous-menu (le titre d'un groupe s'affiche aussi au menu principal), majuscules comprises.
$sousMenus = [ordered]@{
    'Cette machine' = "Fiche de l'ordinateur|Computer specs"
    'Réseau et Internet' = 'Surveillance toutes les heures|Hourly monitoring'
    'Antivirus et protection' = 'Ce lien est-il dangereux|Is this link dangerous'
    'Installer et jouer' = 'les meilleurs, par catégorie|the best ones, by category'
    'Optimiser' = 'Nettoyer le système|Clean up the system'
    'Données' = 'Copier mes fichiers|Copy my files'
    'Guide des commandes' = 'Tous les systèmes|All systems'
    'Dépanner pas à pas' = "Pas d'Internet|No Internet"
}
foreach ($g in $sousMenus.Keys) {
    if ($m -cmatch $sousMenus[$g]) { Ok "Sous-menu « $g » ouvert" } else { Bug "Sous-menu « $g » PAS ouvert" }
}
# Entrée fermée (comme Ctrl-D) : Gardien doit quitter, pas tourner en boucle (bug corrigé en 0.9.7).
$vide = Join-Path $res 'vide.txt'
Set-Content -Path $vide -Value '' -NoNewline
$p = Start-Process -FilePath $exe -RedirectStandardInput $vide -RedirectStandardOutput (Join-Path $res 'menu-eof.out.txt') -NoNewWindow -PassThru
# Sans garder le handle tout de suite, PowerShell ne sait plus lire le code de sortie (il restait vide).
$null = $p.Handle
if ($p.WaitForExit(10000)) { Ok 'Quitte quand l''entrée est fermée' }
else { $p.Kill(); Bug 'Boucle sans fin quand l''entrée est fermée' }

Etape 'Pourquoi c''est lent ? Fiche de l''ordinateur'
LancerAvec 'lenteur' @('lenteur') "`n"
$t = Sortie 'lenteur'
if ($t -match "POURQUOI C'EST LENT|WHY IS IT SLOW") { Ok 'Instantané affiché' } else { Bug 'Instantané ABSENT' }
if ($t -match 'PowerShell ne répond pas|PowerShell is not responding') { Bug 'Lecture PowerShell en échec' }
Lancer 'fiche-json' @('fiche', '--json')
try {
    $f = Sortie 'fiche-json' | ConvertFrom-Json
    if ($f.processeur) { Ok "Processeur : $($f.processeur)" } else { Bug 'Processeur non lu' }
    if ($f.memoire) { Ok 'Mémoire lue' } else { Bug 'Mémoire non lue' }
    if (@($f.disques).Count) { Ok "$(@($f.disques).Count) disque(s) lu(s)" } else { Bug 'Disques non lus' }
} catch { Bug "fiche --json illisible : $($_.Exception.Message)" }

Etape 'Programmes au démarrage : liste, rien retiré sans accord'
$runAvant = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Out-String
LancerAvec 'demarrage' @('demarrage') "q`n"
if ((Sortie 'demarrage') -match 'Programmes au démarrage|Startup programs') { Ok 'Liste affichée' } else { Bug 'Liste ABSENTE' }
$runApres = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Out-String
if ($runAvant -eq $runApres) { Ok 'Rien retiré sans accord' } else { Bug 'Démarrage modifié sans accord' }

Etape 'Entretien du mois, et ce que Gardien a appris'
Lancer 'entretien' @('entretien')
if ((Sortie 'entretien') -match 'Entretien du mois|Monthly check-up') { Ok 'Résumé du mois affiché' } else { Bug 'Résumé du mois ABSENT' }
LancerAvec 'appris' @('appris') "`n"
if ((Sortie 'appris') -match 'Ce que Gardien a appris|What Gardien has learned') { Ok 'Page « appris » affichée' } else { Bug 'Page « appris » ABSENTE' }

Etape 'Réseau : Wi-Fi encombré, type de NAT, caméras, listes noires refusées'
Lancer 'canaux' @('canaux')
if ((Sortie 'canaux') -match 'Wi-Fi encombré|Crowded Wi-Fi') { Ok 'Wi-Fi examiné (la VM n''en a pas : la sortie doit le dire)' } else { Bug 'Wi-Fi encombré : rien affiché' }
Lancer 'nat' @('nat')
if ((Sortie 'nat') -match 'Type de NAT|NAT type') { Ok 'Type de NAT examiné' } else { Bug 'Type de NAT : rien affiché' }
Lancer 'cameras' @('cameras')
if ((Sortie 'cameras') -match 'Caméras cachées|Hidden cameras') { Ok 'Recherche de caméras faite' } else { Bug 'Caméras : rien affiché' }
LancerAvec 'listes-noires' @('listes-noires') "n`n"
if ((Sortie 'listes-noires') -match "Rien n'a été envoyé|Nothing was sent") { Ok 'Accord demandé, refus respecté' } else { Bug 'Refus des listes noires PAS respecté' }

Etape 'DNS le plus rapide : mesuré, rien changé sans accord'
$dnsAvant = Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table -AutoSize | Out-String
LancerAvec 'dns-rapide' @('dns-rapide') "n`nn`n"
if ((Sortie 'dns-rapide') -match 'DNS le plus rapide|Fastest DNS') { Ok 'DNS mesurés' } else { Bug 'DNS le plus rapide : rien affiché' }
$dnsApres = Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table -AutoSize | Out-String
if ($dnsAvant -eq $dnsApres) { Ok 'DNS inchangés (refusé)' } else { Bug 'DNS changés malgré le refus' }

Etape 'Qui parle à Internet ? Ce lien est-il dangereux ?'
Lancer 'sortantes' @('sortantes')
$s = Sortie 'sortantes'
if ($s -match 'Qui parle à Internet|Who talks to the Internet') { Ok 'Connexions listées' } else { Bug 'Connexions : rien affiché' }
if ($s -match 'PowerShell ne répond pas|PowerShell is not responding') { Bug 'Lecture PowerShell en échec' }
# Un « & » dans le lien : il ne doit pas couper la commande.
LancerAvec 'lien' @('lien', 'https://paypal.com.secure-login.example/connexion?a=1&b=2') "n`n"
$l = Sortie 'lien'
if ($l -match 'secure-login\.example') { Ok 'Vrai site trouvé : secure-login.example' } else { Bug 'Vrai site PAS trouvé' }
if ($l -match 'Sous-domaine trompeur|Misleading subdomain') { Ok 'Sous-domaine trompeur signalé' } else { Bug 'Sous-domaine trompeur PAS signalé' }
if ($l -match "Rien n'a été envoyé|Nothing was sent") { Ok 'Rien envoyé sans accord' } else { Bug 'Refus de l''examen en ligne PAS respecté' }

Etape 'Vérifier un fichier téléchargé : bonne, puis mauvaise empreinte'
$fichier = Join-Path $env:TEMP 'gardien-telechargement-test.txt'
Set-Content -Path $fichier -Value 'contenu de test' -Encoding UTF8
$empreinte = (Get-FileHash $fichier -Algorithm SHA256).Hash.ToLower()
LancerAvec 'verifier-bon' @('verifier-fichier', $fichier, $empreinte) "n`nn`nn`n"
$v = Sortie 'verifier-bon'
if ($v -match '\) correspond :|\) matches:' -and $v -notmatch 'ne correspond pas|does not match') { Ok 'Bonne empreinte reconnue' } else { Bug 'Bonne empreinte PAS reconnue' }
LancerAvec 'verifier-faux' @('verifier-fichier', $fichier, ('0' * 64)) "n`nn`nn`n"
if ((Sortie 'verifier-faux') -match 'ne correspond pas|does not match') { Ok 'Mauvaise empreinte signalée' } else { Bug 'Mauvaise empreinte PAS signalée' }
Remove-Item $fichier -Force -ErrorAction SilentlyContinue

Etape 'Fichiers-pièges : posés, un renommé comme par un rançongiciel, retirés'
$dossiersPieges = @([Environment]::GetFolderPath('MyDocuments'), [Environment]::GetFolderPath('MyPictures'), [Environment]::GetFolderPath('Desktop'))
if (Question 'Faire ce test (six fichiers posés puis retirés dans Documents, Images et Bureau) ?' 'o') {
    LancerAvec 'pieges-poser' @('pieges') "o`n"
    if ((Sortie 'pieges-poser') -match 'fichiers-pièges posés|decoy files placed') { Ok 'Fichiers-pièges posés' } else { Bug 'Fichiers-pièges PAS posés' }
    foreach ($d in $dossiersPieges) { Info "$d : $(@(Get-ChildItem $d -Filter '!Gardien*' -ErrorAction SilentlyContinue).Count) fichier(s)-piège(s)" }
    # Accès contrôlé aux dossiers actif (1) : Documents et Images sont déjà protégés par Windows ; Gardien doit le dire
    # et ne pas y écrire (Windows l'aurait bloqué, alerte à l'appui). Le Bureau, lui, n'est pas protégé d'office.
    $cfa = try { [int](Get-MpPreference).EnableControlledFolderAccess } catch { -1 }
    Info "Accès contrôlé aux dossiers : $cfa (0 coupé, 1 actif, 2 audit, -1 illisible)"
    $sortiePieges = Sortie 'pieges-poser'
    if ($cfa -eq 1) {
        if ($sortiePieges -match 'déjà protégé par|already protected by Windows') { Ok 'Dossiers protégés par Windows dits comme tels, sans piège' }
        else { Bug 'Dossiers protégés par Windows PAS signalés' }
    }
    if ($sortiePieges -match 'Pas de fichier-piège dans|No decoy file in') { Bug "Dossier refusé : $(($sortiePieges -split "`n" | Select-String 'No decoy file in|Pas de fichier-piège dans') -join ' / ')" }
    # Le premier dossier qui a reçu ses pièges : l'accès contrôlé aux dossiers de Defender peut en refuser.
    $piege = Get-ChildItem $dossiersPieges -Filter '!Gardien*.txt' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($piege) {
        Rename-Item $piege.FullName ($piege.Name + '.locked')
        LancerAvec 'pieges-etat' @('pieges') "`n"
        if ((Sortie 'pieges-etat') -match 'RENOMMÉ en|RENAMED to') { Ok 'Fichier-piège renommé repéré' } else { Bug 'Fichier-piège renommé PAS repéré' }
        Rename-Item (Join-Path $piege.DirectoryName ($piege.Name + '.locked')) $piege.Name
    } else { Bug 'Aucun fichier-piège posé' }
    LancerAvec 'pieges-retirer' @('pieges', '--retirer') "o`n"
    if (Get-ChildItem $dossiersPieges -Filter '!Gardien*' -ErrorAction SilentlyContinue) { Bug 'Fichiers-pièges ENCORE présents' } else { Ok 'Fichiers-pièges retirés' }
} else { Info 'Sautée.' }

Etape 'YARA : moteur installé par winget, puis analyse d''un dossier'
$yaraLien = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links\yara.exe'
$dossierYara = Join-Path $env:TEMP 'gardien-dossier-yara'
New-Item -ItemType Directory -Force $dossierYara | Out-Null
Set-Content -Path (Join-Path $dossierYara 'note.txt') -Value 'fichier sans danger' -Encoding UTF8
if ((Test-Path $yaraLien) -or (Question 'Installer le moteur YARA par winget (VirusTotal.YARA), puis analyser un dossier ?')) {
    LancerAvec 'yara' @('yara', $dossierYara) "o`n"
    if (Test-Path $yaraLien) { Ok 'Moteur trouvé dans WinGet\Links' } else { Bug 'yara.exe ABSENT de WinGet\Links' }
    $y = Sortie 'yara'
    if ($y -match 'Analyse de|Scanning') { Ok 'Analyse lancée' } else { Bug 'Analyse PAS lancée' }
    if ($y -match "n'a pas pu aller au bout|could not finish") { Bug 'Le moteur n''est pas allé au bout' }
} else {
    LancerAvec 'yara-refus' @('yara', $dossierYara) "n`n"
    if ((Sortie 'yara-refus') -match "n'est pas installé|is not installed") { Ok 'Moteur absent dit, refus de l''installer respecté' } else { Bug 'Moteur absent PAS dit' }
}
Remove-Item $dossierYara -Recurse -Force -ErrorAction SilentlyContinue

Etape 'Copier mes fichiers : disque du système refusé, puis vraie copie vers le dossier partagé'
$refuse = Join-Path $env:TEMP 'gardien-copie-test'
New-Item -ItemType Directory -Force $refuse | Out-Null
LancerAvec 'copier-refus' @('copier-fichiers', $refuse) "`nn`n"
if ((Sortie 'copier-refus') -match 'disque du système|system disk') { Ok 'Copie sur le disque du système refusée' } else { Bug 'Copie sur le disque du système PAS refusée' }
Remove-Item $refuse -Recurse -Force -ErrorAction SilentlyContinue
if (Question 'Faire une vraie copie de tes dossiers vers le dossier partagé (dans les résultats, effacée après) ?') {
    # Sur le Bureau : l'accès contrôlé aux dossiers de Defender, s'il est actif, empêche PowerShell d'écrire dans
    # Documents, et le témoin n'existerait pas. Le Bureau n'est pas protégé d'office.
    $temoin = Join-Path ([Environment]::GetFolderPath('Desktop')) 'gardien-test-copie.txt'
    Set-Content -Path $temoin -Value "copie de test $(Get-Date -Format o)" -Encoding UTF8 -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $temoin)) { Info "Fichier témoin impossible à poser : $temoin" }
    $vers = Join-Path $res 'copie'
    New-Item -ItemType Directory -Force $vers | Out-Null
    LancerAvec 'copier' @('copier-fichiers', $vers) "`no`n"
    $copie = Get-ChildItem $vers -Recurse -Filter 'gardien-test-copie.txt' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not (Test-Path -LiteralPath $temoin)) { Info 'Témoin absent : copie à l''identique non vérifiée.' }
    elseif ($copie -and (Get-FileHash $copie.FullName).Hash -eq (Get-FileHash $temoin).Hash) { Ok 'Fichier témoin copié à l''identique' }
    else { Bug 'Fichier témoin PAS copié à l''identique' }
    if ((Sortie 'copier') -match 'Copie terminée et vérifiée|Copy finished and checked') { Ok 'Copie vérifiée par Gardien' } else { Bug 'Copie PAS vérifiée' }
    Remove-Item $temoin -Force -ErrorAction SilentlyContinue
    Remove-Item $vers -Recurse -Force -ErrorAction SilentlyContinue
} else { Info 'Vraie copie sautée.' }

Etape 'Dépanner : pas de son, et les réglages du son ouverts par Gardien'
# Un lien ouvert par Gardien (ms-settings:sound), sauf en arrière-plan : rien ne doit surgir à l'écran.
$ouvrirReglages = if ($SansOuvrir -or $Auto) { 'n' } else { 'o' }
LancerAvec 'depanner-son' @('depanner', 'son') "1`n1`n$ouvrirReglages`nn`n`n"
$d = Sortie 'depanner-son'
if ($d -match 'Où manque le son|Where is the sound missing') { Ok 'Parcours « pas de son » suivi' } else { Bug 'Parcours « pas de son » PAS suivi' }
if ($d -match 'PowerShell ne répond pas|PowerShell is not responding|État du son illisible|Sound state not readable') { Bug 'État du son PAS lu (PowerShell)' }
if ($ouvrirReglages -eq 'o') { Start-Sleep -Seconds 2; Constat 'Les réglages du son de Windows se sont-ils ouverts ?' }
Lancer 'depanner-sujets' @('depanner', 'xyz')
if ((Sortie 'depanner-sujets') -match "Pas d'Internet|No Internet") { Ok 'Sujets listés pour un sujet inconnu' } else { Bug 'Sujets PAS listés' }

Etape 'Guide des commandes : une page, et la copie d''une commande'
Lancer 'guide-winget' @('guide', 'winget')
if ((Sortie 'guide-winget') -match 'winget upgrade --all') { Ok 'Page de winget affichée' } else { Bug 'Page de winget ABSENTE' }
$presseAvant = Get-Clipboard -Raw -ErrorAction SilentlyContinue
# « 10.2.1 » : guide, Windows, winget ; « 2 » copie sa 2e commande.
LancerAvec 'guide-copie' @() "10.2.1`n2`n`nq`n"
$copiee = Get-Clipboard -Raw -ErrorAction SilentlyContinue
if ($copiee -and $copiee.Trim() -eq 'winget upgrade --all') { Ok 'Commande copiée dans le presse-papier (Set-Clipboard)' }
elseif ((Sortie 'guide-copie') -match 'Presse-papier inaccessible|Clipboard unavailable') { Info 'Presse-papier inaccessible ici (test en arrière-plan ?) : Gardien l''a dit et a remontré la commande' }
else { Bug "Commande PAS copiée (presse-papier : « $copiee »)" }
if ($presseAvant) { Set-Clipboard -Value $presseAvant }

Etape 'Surveillance : activation puis désactivation (Planificateur de tâches)'
Lancer 'surveillance-on' @('surveillance', 'on')
# Nom de la tâche depuis la 0.11.0 (les anciennes tâches « netscan… » sont retirées à l'activation).
$tache = 'gardien - surveillance du reseau'
if (Get-ScheduledTask -TaskName $tache -ErrorAction SilentlyContinue) { Ok 'Tâche planifiée créée' } else { Bug 'Tâche planifiée NON créée' }
Ref 'Tâche planifiée après activation' { Get-ScheduledTask -TaskName $tache | Select-Object TaskName, State, Description | Format-List; (Get-ScheduledTask -TaskName $tache).Actions | Format-List Execute, Arguments }
Lancer 'surveillance-off' @('surveillance', 'off')
if (Get-ScheduledTask -TaskName $tache -ErrorAction SilentlyContinue) { Bug 'Tâche planifiée ENCORE PRÉSENTE' } else { Ok 'Tâche planifiée retirée' }

Etape 'Notification « nouvel appareil »'
$base = Join-Path $env:LOCALAPPDATA 'gardien\appareils.json'
if (Test-Path $base) {
    # On retire un appareil de la base de test : au scan suivant, il doit être signalé comme nouveau.
    $json = Get-Content $base -Raw -Encoding UTF8 | ConvertFrom-Json
    $retire = $null
    foreach ($r in $json.reseaux.PSObject.Properties) {
        $premier = $r.Value.appareils.PSObject.Properties | Select-Object -First 1
        if ($premier) { $retire = $premier.Name; $r.Value.appareils.PSObject.Properties.Remove($premier.Name); break }
    }
    $json | ConvertTo-Json -Depth 10 | Set-Content $base -Encoding UTF8
    Info "Appareil retiré de la base de test : $retire"
    if (-not $Auto) { Write-Host '      Regarde le coin de l''écran : une notification « Nouvel appareil » doit apparaître…' -ForegroundColor Yellow }
    Lancer 'surveiller' @('surveiller')
    Start-Sleep -Seconds 3
    Constat 'As-tu vu la notification « Nouvel appareil sur ton réseau » ?'
} else {
    Info 'Pas de base créée par le scan : test de notification sauté.'
}

Etape 'Rapport HTML de Gardien'
if ($SansOuvrir) {
    # En arrière-plan, le navigateur ne doit pas surgir : le bilan complet, en texte.
    Lancer 'complet' @('complet', '--texte')
    Info 'Rapport HTML pas ouvert : test en arrière-plan.'
} else {
    Lancer 'complet-html' @('complet', '--html')
    Start-Sleep -Seconds 3
    Constat 'Le rapport s''est-il ouvert dans le navigateur, lisible, avec les accents corrects ?'
}

Etape 'Antivirus (analyse rapide Microsoft Defender)'
if (Question 'Lancer l''analyse rapide Defender (quelques minutes) ?') {
    Lancer 'antivirus' @('antivirus')
} else { Info 'Sautée.' }

Etape 'Lanceur de la clé : Gardien introuvable ou bloqué, expliqué sans toucher à Defender'
$lanceur = Join-Path $ici 'Lancer Gardien.bat'
if (Test-Path -LiteralPath $lanceur) {
    # Dans un dossier sans Windows\gardien.exe : le même chemin que quand Defender refuse de le lancer.
    $essai = Join-Path $env:TEMP 'gardien-lanceur'
    New-Item -ItemType Directory -Path $essai -Force | Out-Null
    Copy-Item -LiteralPath $lanceur $essai -Force
    $defLanceur = (Get-MpPreference | Select-Object ExclusionPath, ControlledFolderAccessAllowedApplications | Out-String)
    $sortieLanceur = 'N' | cmd /c "`"$(Join-Path $essai 'Lancer Gardien.bat')`"" 2>&1 | Out-String
    $codeLanceur = $LASTEXITCODE
    Set-Content -Path (Join-Path $res 'lanceur.out.txt') -Value $sortieLanceur -Encoding UTF8
    if ($sortieLanceur -match 'Windows could not start Gardien') { Ok 'Refus expliqué' } else { Bug 'Refus PAS expliqué' }
    if ($sortieLanceur -match 'Checksum unreadable') { Ok 'Empreinte dite illisible, programme absent' } else { Bug 'Empreinte : rien dit pour un programme absent' }
    if ($codeLanceur -eq 1) { Ok 'Code 1 quand Gardien ne démarre pas' } else { Bug "Code $codeLanceur au lieu de 1" }
    if ((Get-MpPreference | Select-Object ExclusionPath, ControlledFolderAccessAllowedApplications | Out-String) -eq $defLanceur) { Ok 'Defender pas touché' } else { Bug 'Defender modifié par le lanceur' }
    Remove-Item -LiteralPath $essai -Recurse -Force -ErrorAction SilentlyContinue
} else { Info 'Sautée : lanceur absent du dossier du programme.' }

Etape 'Blocages de Windows Defender : liste, rien changé sans accord'
function Etat-Defender {
    $p = Get-MpPreference
    "cfa=$($p.EnableControlledFolderAccess) np=$($p.EnableNetworkProtection) pua=$($p.PUAProtection) asr=$((@($p.AttackSurfaceReductionRules_Ids) | Where-Object { $_ }) -join ',')/$(@($p.AttackSurfaceReductionRules_Actions) -join ',')"
}
$defAvant = Etat-Defender
$modeDefender = (Get-MpComputerStatus).AMRunningMode
Info "Defender ($modeDefender) : $defAvant"
# Le numéro de l'outil dans le groupe Antivirus et protection (6), lu à l'écran : il change quand un outil s'ajoute.
LancerAvec 'protection-groupe' @() "6`n`nq`n"
$groupe = (Sortie 'protection-groupe') -replace '\x1b\[[0-9;]*m', ''
$numeroDefender = if ($groupe -match '(?m)^\s*(\d+)\s+(Blocages de Windows Defender|Windows Defender blocking)') { $Matches[1] } else { '' }
if ($numeroDefender) {
    Ok "Outil présent dans le groupe (6.$numeroDefender)"
    LancerAvec 'protection' @() "6.$numeroDefender`n`n`nq`n"
    $t = Sortie 'protection'
    foreach ($titre in 'Blocages de base de Defender|Defender basic blocking', 'Protection réseau de Defender|Defender network protection', 'Accès contrôlé aux dossiers|Controlled folder access') {
        if ($t -match $titre) { Ok "Réglage affiché : $($titre.Split('|')[0])" } else { Bug "Réglage ABSENT : $($titre.Split('|')[0])" }
    }
    if ($modeDefender -eq 'Normal' -and $t -match "n'est pas l'antivirus actif|is not the active antivirus") { Bug 'Defender actif, mais dit inactif' }
    if ((Etat-Defender) -eq $defAvant) { Ok 'Rien changé sans accord' } else { Bug "Defender modifié sans accord : $(Etat-Defender)" }
} else { Bug 'Outil « Blocages de Windows Defender » ABSENT du groupe' }

Etape 'Blocages de Windows Defender : protection réseau activée puis annulée (UAC)'
$npAvant = (Get-MpPreference).EnableNetworkProtection
if (-not $numeroDefender) { Info 'Sautée : outil absent.' }
elseif ($npAvant -eq 1) { Info 'Sautée : la protection réseau est déjà active dans la VM.' }
elseif (Question 'Faire ce test (deux fenêtres UAC à accepter) ?') {
    Write-Host '      Clique OUI dans les deux fenêtres UAC (activer, puis annuler). Un refus ne change rien et fait échouer le test.' -ForegroundColor Yellow
    # Ligne 3 de la liste : la protection réseau. Sans terminal, taper son numéro coche et valide ; puis « o » accepte.
    # Décochée de la même façon pour annuler.
    LancerAvec 'protection-activer' @() "6.$numeroDefender`n3`no`n`nq`n"
    $np = (Get-MpPreference).EnableNetworkProtection
    if ($np -eq 1) { Ok 'Protection réseau activée par Gardien' }
    elseif ((Sortie 'protection-activer') -match "Administrator prompt refused|Demande d'administrateur refusée") { Bug 'Fenêtre UAC refusée : protection réseau pas activée (le test demande OUI)' }
    else { Bug "Protection réseau PAS activée ($np)" }
    LancerAvec 'protection-annuler' @() "6.$numeroDefender`n3`no`n`nq`n"
    $np = (Get-MpPreference).EnableNetworkProtection
    if ($np -eq $npAvant) { Ok 'Protection réseau remise comme avant' } else { Bug "Protection réseau PAS remise ($np au lieu de $npAvant)" }
    if ((Etat-Defender) -eq $defAvant) { Ok 'Defender exactement comme avant' } else { Bug "Defender différent d'avant : $(Etat-Defender)" }
} else { Info 'Sautée (il faut accepter les fenêtres UAC).' }

Etape 'Corrections avec UAC (refus, puis acceptation, puis port bloqué)'
Info 'Coupe le pare-feu du profil « Privé » de la VM, puis Gardien doit le réparer. Le port 3389 et le Bureau à distance ne sont jamais touchés.'
if (Question 'Faire ce test ?') {
    Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', 'Set-NetFirewallProfile -Profile Private -Enabled False'
    Ref 'Pare-feu après coupure volontaire' { Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize }

    Write-Host ''
    Write-Host '      Réponds « o » pour le pare-feu, puis clique NON dans la fenêtre UAC. Réponds « n » à tout le reste.' -ForegroundColor Yellow
    Vider-Clavier
    & $exe corriger
    Constat 'Gardien a-t-il dit « Demande d''administrateur refusée : rien n''a été modifié » et PAS « ✔ fait » ?'
    if ((Get-NetFirewallProfile -Profile Private).Enabled) { Bug 'Pare-feu Privé réactivé malgré le refus' } else { Ok 'Refus respecté : pare-feu Privé toujours coupé' }

    Write-Host ''
    Write-Host '      Réponds « o » pour le pare-feu et accepte l''UAC. Pour les ports, « o » au port 135 seulement, « n » au reste.' -ForegroundColor Yellow
    Vider-Clavier
    & $exe corriger
    if ((Get-NetFirewallProfile -Profile Private).Enabled) { Ok 'Pare-feu Privé réactivé par Gardien' }
    else {
        Bug 'Pare-feu Privé toujours coupé après la correction : remis en marche par le script'
        Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', 'Set-NetFirewallProfile -Profile Private -Enabled True'
    }
    Ref 'Règles Gardien créées' { Get-NetFirewallRule -DisplayName 'Gardien : bloquer *' -ErrorAction SilentlyContinue | Select-Object DisplayName, Enabled, Action | Format-Table -AutoSize }
    Constat 'La correction s''est-elle bien passée (affichage clair, une fenêtre UAC par correction, « OK » à chaque étape) ?'

    # Un port bloqué par Gardien ne doit plus être signalé comme à corriger (0.9.6).
    Lancer 'machine-apres-blocage' @('machine')
    if ((Sortie 'machine-apres-blocage') -match 'bloqué en entrée par la règle|blocked inbound by the') { Ok 'Port bloqué reconnu à l''audit suivant' }
    else { Info 'Aucun port reconnu comme bloqué (normal si aucun port n''a été bloqué)' }

    if (Question 'Retirer maintenant les règles « Gardien : bloquer » créées pendant le test ?') {
        Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', "Remove-NetFirewallRule -DisplayName 'Gardien : bloquer *'"
    }
} else { Info 'Sautée (il faut répondre aux fenêtres UAC).' }

Etape 'Couleurs et accents dans la console'
if ($Auto) { Info 'Sautée : il faut regarder l''écran (test avec questions).' } else {
    Vider-Clavier
    & $exe machine
    Constat 'Dans l''audit ci-dessus, les couleurs et les accents (é, è, ✔, ✖) s''affichent-ils correctement ?'
}

Journal "FIN $(Get-Date -Format 'HH:mm:ss')"
$rapport = Rapport
$toutes = @($script:etapes | ForEach-Object { $_.Verifs })
# Les journaux des fenêtres administrateur de cette passe (outils de Gardien, %LOCALAPPDATA%\gardien\corrections) :
# ce qui s'est vraiment exécuté après chaque UAC, lisible depuis Linux.
$corrections = Join-Path $env:LOCALAPPDATA 'gardien\corrections'
$journauxAdmin = @(Get-ChildItem -LiteralPath $corrections -Filter '*.log' -ErrorAction SilentlyContinue | Where-Object LastWriteTime -ge $debutTest)
if ($journauxAdmin) {
    $versJournaux = Join-Path $res 'corrections'
    New-Item -ItemType Directory -Force $versJournaux | Out-Null
    $journauxAdmin | Copy-Item -Destination $versJournaux -Force
}
$nbOk = @($toutes | Where-Object Etat -eq 'ok').Count
$nbBug = @($toutes | Where-Object Etat -eq 'bug').Count
$nbEchec = @($script:etapes | ForEach-Object { $_.Commandes } | Where-Object Code -ne 0).Count
Write-Host ''
Write-Host '  ──────────────────────────────────────────────────────────' -ForegroundColor DarkGray
if ($nbBug -eq 0 -and $nbEchec -eq 0) { Write-Host "  ✔ Tout est passé : $nbOk vérification(s) réussie(s)." -ForegroundColor Green }
else { Write-Host "  ✖ $nbBug problème(s), $nbEchec commande(s) en échec ; $nbOk vérification(s) réussie(s)." -ForegroundColor Red }
# Le dernier rapport toujours au même endroit, et une ligne par passe dans l'historique.
Copy-Item $rapport (Join-Path $resultats 'dernier-rapport.html') -Force
$bilan = if ($nbBug -eq 0 -and $nbEchec -eq 0) { "OK, tout est passé ($nbOk vérifications)" } else { "$nbBug problème(s), $nbEchec commande(s) en échec, $nbOk réussies" }
$mode = if ($SansOuvrir) { 'automatique' } elseif ($Auto) { 'sans questions' } else { 'avec questions' }
Add-Content -Path (Join-Path $resultats 'historique.txt') -Encoding UTF8 -Value ('{0}  v{1,-8} {2}  ({3:N1} min, {4})  -> {5}' -f `
    (Get-Date -Format 'yyyy-MM-dd HH:mm'), $numero, $bilan, ((Get-Date) - $debutTest).TotalMinutes, $mode, (Split-Path -Leaf $res))
Write-Host "  Rapport : $rapport" -ForegroundColor DarkGray
if (-not $SansOuvrir) {
    Start-Process $rapport
    Write-Host '  Le rapport s''ouvre dans le navigateur. Tu peux revenir sur Linux.' -ForegroundColor DarkGray
}
