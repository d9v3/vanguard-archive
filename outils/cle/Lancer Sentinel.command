#!/bin/sh
# macOS : double-clic dans le Finder, le Terminal s'ouvre et lance Sentinel. Lancé hors du dossier de la clé :
# sur un autre ordinateur, sentinel la remonte en lecture seule, impossible si le Terminal y est ouvert.
SENTINEL="$(cd "$(dirname "$0")" && pwd)/macOS/sentinel"
cd "$HOME" || cd /
exec "$SENTINEL"
