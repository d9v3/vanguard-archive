#!/bin/sh
# Lancé par GNOME au branchement de la clé (après accord : « Lancer le logiciel ? »), ou à la main.
# Sentinel est un programme en mode texte : il lui faut un terminal.
cd "$(dirname "$0")/Linux" || exit 1
for t in xdg-terminal-exec kgx gnome-terminal konsole xfce4-terminal alacritty kitty foot x-terminal-emulator xterm; do
  command -v "$t" >/dev/null || continue
  case $t in
    gnome-terminal) exec gnome-terminal -- ./sentinel ;;
    kitty | foot) exec "$t" ./sentinel ;;
    *) exec "$t" -e ./sentinel ;;
  esac
done
exec ./sentinel
