@echo off
rem Menu des tests de Gardien (double-clic) : test automatique ou avec questions, Gardien, rapports, test
rem automatique de chaque nouvelle version. Les scripts sont dans "programme", mis a jour a chaque deploiement.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0programme\menu.ps1"
if errorlevel 1 pause
