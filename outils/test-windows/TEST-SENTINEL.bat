@echo off
rem Lance le test complet de sentinel (double-clic).
rem pushd donne une lettre de lecteur au partage reseau (cmd refuse les chemins \\serveur comme dossier courant).
pushd "%~dp0"
echo Dossier : %CD%
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { & .\test.ps1 } catch { $_ | Out-String | Set-Content -Encoding UTF8 erreur-lancement.txt; Write-Host ($_ | Out-String) -ForegroundColor Red }"
echo.
echo Code de sortie de PowerShell : %ERRORLEVEL%
popd
pause
