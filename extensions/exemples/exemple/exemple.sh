#!/bin/sh
# Exemple de plugin de Vanguard : une ligne ordinaire, puis deux constats du protocole (une ligne JSON chacun).
# Vanguard lance ce script par /bin/sh, son dossier comme dossier courant.
case "$LANG" in
  fr*) echo "Bonjour depuis le plugin d'exemple ($1)." ;;
  *) echo "Hello from the example plugin ($1)." ;;
esac
echo '{"vanguard":1,"niveau":"moyen","categorie":"Salon","message":"Une prise connectée inventée a son port 23 ouvert."}'
echo '{"vanguard":1,"niveau":"ok","categorie":"Salon","message":"Le reste du salon va bien."}'
