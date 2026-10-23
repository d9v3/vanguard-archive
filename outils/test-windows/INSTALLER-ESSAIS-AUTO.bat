@echo off
rem File d essais sans clic (une fois) : une tache planifiee fait, en administrateur, chaque essai depose depuis
rem Linux par outils/vm-tester.sh dans file-essais. Une fenetre UAC. A n installer que dans la VM de test.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0programme\essais-auto-installation.ps1"
if errorlevel 1 pause
