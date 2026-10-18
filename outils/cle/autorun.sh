#!/bin/sh
# Lancé par GNOME au branchement de la clé (après accord : « Lancer le logiciel ? »), ou à la main.
# Gardien est un programme en mode texte : il lui faut un terminal.
# Lancé hors du dossier de la clé : sur un autre ordinateur, Gardien la remonte en lecture seule, ce qui est
# impossible si un terminal y est ouvert.
GARDIEN="$(cd "$(dirname "$0")" && pwd)/Linux/gardien"
cd "$HOME" || cd /
for t in xdg-terminal-exec kgx gnome-terminal konsole xfce4-terminal alacritty kitty foot x-terminal-emulator xterm; do
  command -v "$t" >/dev/null || continue
  case $t in
    gnome-terminal) exec gnome-terminal -- "$GARDIEN" ;;
    kitty | foot) exec "$t" "$GARDIEN" ;;
    *) exec "$t" -e "$GARDIEN" ;;
  esac
done
exec "$GARDIEN"
