@echo off
rem Lance Sentinel dans sa propre fenetre (Windows ne lance rien tout seul depuis une cle USB).
start "Sentinel" "%~dp0Windows\sentinel.exe"
