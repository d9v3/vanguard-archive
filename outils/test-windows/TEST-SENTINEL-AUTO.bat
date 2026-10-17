@echo off
rem Test complet SANS aucune question (double-clic) : rien a taper.
pushd "%~dp0"
echo Dossier : %CD%
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { & .\test.ps1 -Auto } catch { $_ | Out-String | Set-Content -Encoding UTF8 erreur-lancement.txt; Write-Host ($_ | Out-String) -ForegroundColor Red }"
echo.
echo Test termine : tu peux fermer cette fenetre.
popd
