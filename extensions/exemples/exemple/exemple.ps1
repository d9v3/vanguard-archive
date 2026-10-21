# Exemple de plugin de Vanguard pour Windows : une ligne ordinaire, puis deux constats du protocole (une ligne JSON
# chacun). Vanguard le lance par le PowerShell de System32, son dossier comme dossier courant.
if ($env:LANG -like 'fr*') { 'Bonjour depuis le plugin d''exemple.' } else { 'Hello from the example plugin.' }
'{"vanguard":1,"niveau":"moyen","categorie":"Salon","message":"Une prise connectée inventée a son port 23 ouvert."}'
'{"vanguard":1,"niveau":"ok","categorie":"Salon","message":"Le reste du salon va bien."}'
