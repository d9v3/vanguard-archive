@echo off
rem Retire la file d essais sans clic (tache Vanguard-File-Essais et ses dossiers locaux). Une fenetre UAC.
rem Les resultats et le menu des tests (choix 6) ne sont pas touches.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0programme\essais-auto-installation.ps1" -Retirer
if errorlevel 1 pause
