@echo off
rem Lance Gardien dans sa propre fenetre (Windows ne lance rien tout seul depuis une cle USB).
rem Si Windows refuse (Defender l'a bloque, faux positif), le dit et propose d'ouvrir Securite Windows : c'est la
rem personne qui decide d'autoriser Gardien, dans l'outil de Microsoft. Ce lanceur ne touche jamais a Defender.
setlocal
chcp 65001 >nul
set "GARDIEN=%~dp0Windows\gardien.exe"
rem Start-Process echoue si le fichier manque ou si Windows refuse de le lancer (virus detecte, erreur 225).
powershell -NoProfile -NonInteractive -Command "try { Start-Process -FilePath $env:GARDIEN -ErrorAction Stop } catch { exit 1 }"
if not errorlevel 1 exit /b 0
echo.
echo   Windows n'a pas pu lancer Gardien.
echo   Windows could not start Gardien.
echo.
echo   Le plus souvent, Microsoft Defender l'a bloqué : un faux positif connu, deviné par son
echo   apprentissage automatique (détection qui finit par « !ml »). Gardien ne contourne pas
echo   Defender : c'est toi qui décides de l'autoriser, dans Sécurité Windows.
echo   Usually Microsoft Defender blocked it: a known false positive, guessed by its machine
echo   learning (detection ending in "!ml"). Gardien does not get around Defender: you decide
echo   whether to allow it, in Windows Security.
echo.
choice /c OYN /n /m "  Ouvrir Sécurité Windows ? / Open Windows Security? [O/Y = oui/yes, N = non/no] "
if errorlevel 3 exit /b 1
start "" "windowsdefender://threat"
echo.
echo   1. Historique de protection : l'alerte de gardien.exe, Actions, « Autoriser sur l'appareil ».
echo      Protection history: the gardien.exe alert, Actions, "Allow on device".
echo   2. Puis relance « Lancer Gardien ». / Then run "Lancer Gardien" again.
echo   Pour retirer l'autorisation plus tard : Protection contre les virus et menaces,
echo   « Menaces autorisées ». / To remove the permission later: Virus ^& threat protection,
echo   "Allowed threats".
echo.
pause
exit /b 1
