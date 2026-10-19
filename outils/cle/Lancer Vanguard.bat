@echo off
rem Lance Vanguard dans sa propre fenetre (Windows ne lance rien tout seul depuis une cle USB).
rem Si Windows refuse (Defender l'a bloque, faux positif), le dit et propose d'ouvrir Securite Windows : c'est la
rem personne qui decide d'autoriser Vanguard, dans l'outil de Microsoft. Ce lanceur ne touche jamais a Defender.
setlocal
chcp 65001 >nul
set "VANGUARD=%~dp0Windows\vanguard.exe"
rem Start-Process echoue si le fichier manque ou si Windows refuse de le lancer (virus detecte, erreur 225).
powershell -NoProfile -NonInteractive -Command "try { Start-Process -FilePath $env:VANGUARD -ErrorAction Stop } catch { exit 1 }"
if not errorlevel 1 exit /b 0
echo.
echo   Windows n'a pas pu lancer Vanguard.
echo   Windows could not start Vanguard.
echo.
echo   Le plus souvent, Microsoft Defender l'a bloqué : un faux positif connu, deviné par son
echo   apprentissage automatique (détection qui finit par « !ml »). Vanguard ne contourne pas
echo   Defender : c'est toi qui décides de l'autoriser, dans Sécurité Windows.
echo   Usually Microsoft Defender blocked it: a known false positive, guessed by its machine
echo   learning (detection ending in "!ml"). Vanguard does not get around Defender: you decide
echo   whether to allow it, in Windows Security.
echo.
echo   Avant d'autoriser quoi que ce soit, vérifie que c'est bien le vrai Vanguard : cette empreinte
echo   SHA-256 doit être celle de vanguard-windows-x86_64.exe dans SHA256SUMS.txt, sur la page de la
echo   version de Vanguard. Sinon, n'autorise rien.
echo   Before allowing anything, check this is the real Vanguard: this SHA-256 checksum must match
echo   vanguard-windows-x86_64.exe in SHA256SUMS.txt, on Vanguard's release page. Otherwise, allow nothing.
set "EMPREINTE="
for /f "delims=" %%l in ('certutil -hashfile "%VANGUARD%" SHA256 2^>nul ^| findstr /v ":"') do if not defined EMPREINTE set "EMPREINTE=%%l"
if defined EMPREINTE (echo   SHA-256 : %EMPREINTE%) else (echo   Empreinte illisible : programme absent ou verrouillé. / Checksum unreadable: program missing or locked.)
echo.
choice /c OYN /n /m "  Ouvrir Sécurité Windows ? / Open Windows Security? [O/Y = oui/yes, N = non/no] "
if errorlevel 3 exit /b 1
start "" "windowsdefender://threat"
echo.
echo   1. Historique de protection : l'alerte de vanguard.exe, Actions, « Autoriser sur l'appareil ».
echo      Protection history: the vanguard.exe alert, Actions, "Allow on device".
echo   2. Puis relance « Lancer Vanguard ». / Then run "Lancer Vanguard" again.
echo   Pour retirer l'autorisation plus tard : Protection contre les virus et menaces,
echo   « Menaces autorisées ». / To remove the permission later: Virus ^& threat protection,
echo   "Allowed threats".
echo.
pause
exit /b 1
