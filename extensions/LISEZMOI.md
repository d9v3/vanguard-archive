# Extensions de Vanguard : plugins et laboratoire

Une extension ajoute un programme à Vanguard sans toucher à son code : un essai, un outil expérimental, celui
d'un autre. Elle n'est jamais du code de Vanguard : elle ne tourne qu'à ta demande, ses constats sont montrés à
part et ne comptent jamais dans la note.

Deux formes :

- **Plugin** : un outil durable, dans son dossier, avec un manifeste `plugin.toml`. Ajouté une fois
  (`vanguard plugin ajouter <dossier ou archive.zip>`), il est ensuite dans le menu.
- **Script du labo** : un fichier posé tel quel, sans manifeste, pour essayer vite (`vanguard labo ouvrir`
  donne le dossier).

Le menu principal a l'entrée **12. Extensions** (`vanguard extensions`) : 1 les plugins, 2 les scripts du labo,
3 l'interrupteur des restrictions.

## Où sont les extensions

Dans le dossier local de Vanguard, jamais sur la clé USB ni à côté du programme :

| Système | Dossier |
|---|---|
| Linux | `~/.local/share/vanguard/plugins/` (ou `$XDG_DATA_HOME/vanguard/plugins/`) |
| macOS | `~/Library/Application Support/vanguard/plugins/` |
| Windows | `%LOCALAPPDATA%\vanguard\plugins\` |

Le labo est le sous-dossier `labo/`. Vanguard refuse le dossier s'il n'est pas à toi ou si d'autres comptes peuvent
y écrire (Unix : `chmod go-w`), et sous Windows s'il est hors de ton profil.

## Un plugin

```
mon-plugin/
  plugin.toml
  mon-script.sh        (ou un .ps1, un .py, un programme compilé)
```

`plugin.toml` :

```toml
nom = "mon-plugin"                 # a-z, 0-9, tirets ; c'est aussi le nom du dossier
titre_fr = "Mon plugin"
titre_en = "My plugin"
description_fr = "Ce qu'il vérifie, en une phrase."
description_en = "What it checks, in one sentence."
auteur = "alice"                   # facultatif, montré tel quel (non vérifié)
source = "https://exemple.org/x"   # facultatif, montré tel quel (non vérifié)
systemes = ["linux", "macos", "windows"]
delai = 30                         # secondes, de 1 à 600 (60 par défaut)
commande = "mon-script.sh"         # chemin relatif au dossier, jamais « .. » ni absolu
arguments = ["--court"]            # arguments fixes, avant ceux tapés à la ligne de commande

[windows]                          # facultatif : une autre commande pour un système
commande = "mon-script.ps1"
```

Clés facultatives de plus : `confiance = "totale"` (ce plugin tourne sans restrictions, voir plus bas),
`dans_le_bilan = true` et `dans_la_surveillance = true` (seulement sans restrictions).

L'interpréteur vient de l'extension : `.sh` par `/bin/sh`, `.bash` par `/bin/bash`, `.ps1` par le PowerShell de
System32 (`pwsh` ailleurs), `.py` par le `python3` du système ; le reste est lancé tel quel. Le dossier courant
est celui du plugin : lis tes fichiers par là (le programme lancé est une copie vérifiée, ailleurs).

Commandes :

```
vanguard plugin ajouter extensions/exemples/exemple   copie, analyse, montre, demande l'accord
vanguard plugin exemple                                le lance
vanguard plugin exemple --rapport                      ses constats dans le rapport HTML (section Plugins)
vanguard plugin exemple --isole                        Linux : sans réseau, dossier personnel en lecture seule
vanguard plugin liste                                  chaque plugin et son état
vanguard plugin approuver exemple                      après un changement, le remontre et le réapprouve
vanguard plugin retirer exemple
```

Après `--`, tout va au plugin tel quel (`vanguard plugin exemple -- --rapport`).

## Le protocole

Chaque ligne écrite par l'extension est montrée (les caractères qui piloteraient le terminal sont remplacés par
`�`). Une ligne qui est un objet JSON comme celui-ci devient un constat, affiché comme ceux du bilan :

```json
{"vanguard":1,"niveau":"moyen","categorie":"Salon","message":"Une prise inventée a son port 23 ouvert."}
```

`niveau` : `ok`, `info`, `moyen`, `eleve` ou `critique`. Au plus 100 constats, catégorie de 40 caractères et message
de 300. Un constat est marqué « plugin <nom> » ou « labo <fichier> » et ne change jamais la note.

## Le laboratoire

```
vanguard labo ouvrir              crée le dossier s'il manque et en donne le chemin
vanguard labo                     la liste à choisir
vanguard labo essai.sh alice      le lance, avec ses arguments
```

Au premier lancement, Vanguard montre le chemin, l'empreinte, l'analyse et les 20 premières lignes du script, puis
demande l'accord ; s'il change ensuite, il redemande. Chaque lancement porte le bandeau « EXPÉRIMENTAL — hors du
programme de Vanguard ». Un exemple : [exemples/labo-exemple.sh](exemples/labo-exemple.sh).

## Un plugin en Rust

La bibliothèque [sdk](sdk) (`vanguard-extension`, sans dépendance) écrit les constats exactement comme Vanguard
les lit et lance un autre programme proprement (sans shell, délai et sortie bornés) :

```rust
use vanguard_extension::{Constat, lancer, message, tr};
message(tr("Bonjour", "Hello"));
Constat::moyen("Salon", "Une prise inventée a son port 23 ouvert.").envoyer();
let s = lancer("uname", &["-a"], std::time::Duration::from_secs(10));
```

L'exemple complet est [exemples/rust-exemple](exemples/rust-exemple) :

```
cd extensions/exemples/rust-exemple
cargo install --path . --root . --no-track      le programme dans bin/
vanguard plugin ajouter .
vanguard plugin rust-exemple
```

`target/` et `.git/` ne sont pas copiés avec le plugin.

## Les garde-fous, et l'interrupteur

Restrictions **actives** (par défaut) :

- approbation par l'empreinte SHA-256 du manifeste et de chaque programme (ou du script) ; changé : refusé
  jusqu'à une nouvelle approbation ;
- avant l'accord : l'analyse YARA et les empreintes MalwareBazaar de Vanguard (une correspondance : refus) ;
- le programme copié en étant haché, et c'est la copie vérifiée qui tourne ;
- aucun lien suivi ; une archive ne peut rien écrire hors de son dossier (50 Mo au plus) ;
- jamais en administrateur ; jamais dans le bilan, la surveillance, l'entretien ni `complet` ;
- délai et sortie bornés (1 Mio), puis l'arbre de processus arrêté ; environnement minimal (PATH du système,
  LANG, HOME), aucune variable de Vanguard.

Restrictions **coupées** (menu Extensions › 3, `vanguard extensions --sans-restrictions on`, ou pour un seul
élément : « Restrictions d'un plugin », « Marquer un script comme à moi », `confiance = "totale"`) : ni accord, ni
empreinte, ni analyse, bornes très larges, tout l'environnement, administrateur permis (averti), et
`dans_le_bilan` / `dans_la_surveillance` honorés. La première coupure demande une confirmation, une seule fois ;
remettre les restrictions est immédiat.

Une seule chose reste, même sans restrictions : le dossier des extensions doit être à toi et fermé aux autres
comptes. Sinon un programme d'un autre compte pourrait y poser du code qui tournerait comme toi, sans rien demander.
