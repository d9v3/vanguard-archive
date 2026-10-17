#!/bin/sh
# Lancé par GNOME au branchement de la clé (après accord : « Lancer le logiciel ? »), ou à la main.
# Sentinel est un programme en mode texte : il lui faut un terminal.
# Lancé hors du dossier de la clé : sur un autre ordinateur, sentinel la remonte en lecture seule, ce qui est
# impossible si un terminal y est ouvert.
SENTINEL="$(cd "$(dirname "$0")" && pwd)/Linux/sentinel"
cd "$HOME" || cd /
for t in xdg-terminal-exec kgx gnome-terminal konsole xfce4-terminal alacritty kitty foot x-terminal-emulator xterm; do
  command -v "$t" >/dev/null || continue
  case $t in
    gnome-terminal) exec gnome-terminal -- "$SENTINEL" ;;
    kitty | foot) exec "$t" "$SENTINEL" ;;
    *) exec "$t" -e "$SENTINEL" ;;
  esac
done
exec "$SENTINEL"
