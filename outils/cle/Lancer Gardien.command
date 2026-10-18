#!/bin/sh
# macOS : double-clic dans le Finder, le Terminal s'ouvre et lance Gardien. Lancé hors du dossier de la clé :
# sur un autre ordinateur, Gardien la remonte en lecture seule, impossible si le Terminal y est ouvert.
GARDIEN="$(cd "$(dirname "$0")" && pwd)/macOS/gardien"
cd "$HOME" || cd /
exec "$GARDIEN"
