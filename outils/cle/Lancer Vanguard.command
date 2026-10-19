#!/bin/sh
# macOS : double-clic dans le Finder, le Terminal s'ouvre et lance Vanguard. Lancé hors du dossier de la clé :
# sur un autre ordinateur, Vanguard la remonte en lecture seule, impossible si le Terminal y est ouvert.
VANGUARD="$(cd "$(dirname "$0")" && pwd)/macOS/vanguard"
cd "$HOME" || cd /
exec "$VANGUARD"
