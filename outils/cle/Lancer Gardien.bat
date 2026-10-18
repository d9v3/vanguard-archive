@echo off
rem Lance Gardien dans sa propre fenetre (Windows ne lance rien tout seul depuis une cle USB).
start "Gardien" "%~dp0Windows\gardien.exe"
