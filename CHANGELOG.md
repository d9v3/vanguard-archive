# Historique des versions

*[English](CHANGELOG.en.md)*

Ce que chaque journée a apporté à Vanguard, la plus récente en haut. Depuis le 19 octobre 2026, Vanguard a en principe
une seule publication par jour, qui regroupe le travail de la journée ; le 21 octobre en a eu deux, la 0.82 au matin et
la 0.84 au soir, qui reprend la 0.83 livrée juste avant elle. Seule la dernière version a sa page de téléchargement ;
chaque version garde son étiquette dans le dépôt (`git checkout v0.62.0`, par exemple), pour être recompilée au besoin.

## Prochaine version

- **Un problème reconnu à sa règle et à son objet, plus à son texte traduit.** Les ports ouverts, les lancements
  automatiques suspects, les extensions de navigateur, les comptes oubliés ou ajoutés aux administrateurs, les
  logiciels espions, la prise de contrôle à distance, les logiciels périmés et le carnet de la clé VANGUARD portent
  maintenant une clé (« LNX-RES-001|port:8080/tcp:python3 ») : changer de langue ne fait plus revenir une alerte
  déclarée normale, ne fait plus voir de « nouveau » problème dans l'historique et ne renotifie rien dans la
  surveillance. Les choix d'avant sont retrouvés par leur texte puis complétés de leur clé ; un choix ne vaut que pour
  son objet (un autre programme sur le même port, une autre version périmée reviennent). Sous macOS, un agent de
  démarrage est reconnu à son fichier et à ce qu'il lance, sous Linux chaque ligne de lancement suspecte à son
  empreinte : une commande réécrite ou une ligne ajoutée dans un fichier déjà signalé n'est jamais tue par un choix
  d'avant. Un seul choix par clé, le plus récent. La surveillance renotifie une alerte qui s'aggrave sans changer de
  clé (une extension qui gagne l'accès à tous les sites) ; l'historique ne montre plus « réglé » puis « nouveau » pour
  un logiciel dont la version change sans être à jour. L'inventaire des fichiers d'état gagne le carnet des appareils,
  ses verrous, la reprise d'une version d'avant et le dossier des traces, et son test lit aussi les variables du
  dossier de données. L'historique garde sa première empreinte telle quelle et en gagne une seconde, qui couvre les
  clés et les notes de l'audit du réseau : une clé n'est jamais hors d'une empreinte, et un bilan sans elle est dit
  non vérifié, comparé sur son texte. Le JSON du bilan gagne `objet`, `cle` et `etat` (sain, sans objet, non vérifié
  avec sa raison, problème).
- **Une règle qui ne rend rien dit « non vérifié », jamais un silence lu comme sain** (hors d'une liste de règles
  tolérées, qui ne peut que rétrécir). Le Wi-Fi n'est plus tu quand NetworkManager manque (iwd, systemd-networkd) :
  sans carte, « rien à juger » ; avec une carte, non vérifié. Sous Windows, un réseau que netsh cache faute
  d'autorisation de localisation est dit non vérifié ; sous macOS, le mode furtif illisible et la session à distance
  aussi. Seule la lecture du pare-feu lui-même décide si la note tient : le mode furtif illisible ne la retire plus à
  lui seul. Sans NetworkManager, une liste des cartes réseau illisible (/sys/class/net) donne « non vérifié », jamais
  « pas de carte Wi-Fi ». Un constat « sans objet » ne compte plus parmi les vérifications pour la fiabilité de la
  note. `vanguard regles` montre aussi les règles de l'audit du réseau et les outils : un seul registre
  d'identifiants, vérifié par les tests, avec l'inventaire des fichiers d'état dont les sceaux tirent la liste à
  protéger.
- **Mode Wi-Fi public** (`vanguard wifi-public`, Réseau et Internet › Mode Wi-Fi public). On l'allume en arrivant dans
  un café, un hôtel ou un aéroport, on l'éteint en partant : l'ordinateur n'accepte plus aucune connexion venue de ce
  réseau (une session SSH déjà ouverte reste), le partage de fichiers et l'annonce de son nom sont coupés (sous macOS,
  le pare-feu ferme le partage ; Bonjour et AirDrop restent), et le DNS passe au Bouclier canadien « Protégé »,
  chiffré sous Linux quand systemd-resolved répond (un résolveur sur l'ordinateur, comme NextDNS, ou un DNS déjà
  chiffré et filtrant, est gardé). Les entrées qui n'ont pas pu être fermées (pas de nft, pare-feu illisible) sont
  dites au menu et au bilan, jamais « tout est en place ». Sous Linux, une table nftables à part et des services
  masqués jusqu'au redémarrage, puis mDNS, LLMNR et le DNS chiffré sur le seul profil du réseau public ; sous Windows,
  catégorie Public, profil Public du pare-feu fermé aux entrées, NetBIOS coupé, en une seule demande
  d'administrateur ; sous macOS, pare-feu en « tout bloquer » et mode furtif. Chaque changement est montré avec sa valeur d'avant,
  notée et scellée avant la première commande ; l'extinction remet tout dans l'ordre inverse, relu, même après un
  plantage ou un redémarrage (le menu et le bilan le disent). Un état changé hors de Vanguard n'est jamais remis :
  extinction sûre à la place, qui ne retire que la table de Vanguard. Un pare-feu trouvé coupé est allumé et jamais
  recoupé. `vanguard wifi-public portail` rouvre la page de connexion du réseau : le DNS chiffré se relâche jusqu'à
  Entrée, dix minutes au plus, et le lancement suivant le remet strict si Vanguard a été fermé avant. Rien n'est
  envoyé pour reconnaître un réseau public : une suggestion seulement. Essayé sous Linux (table posée puis retirée
  dans un espace de noms à part, aperçus) ; Windows et macOS : compilés et testés en partie, pas encore essayés sur un
  vrai système, ni le DNS chiffré sur un vrai réseau public.

- **Petits correctifs de sûreté.** Sous Windows, les programmes du système (netstat, netsh, powercfg, wevtutil,
  tasklist, schtasks, ipconfig, cmd, PowerShell…) sont lancés par leur chemin dans System32, demandé à Windows
  lui-même : un faux programme du même nom posé à côté de Vanguard (Téléchargements) ou dans le dossier courant ne
  peut plus cacher un port, un processus ou un réglage ; cmd ne cherche plus dans son dossier courant, et un test
  refuse tout nouveau lancement par le seul nom. La liste des pilotes vulnérables (LOLDrivers) n'est remplacée que
  par une réponse qui en est bien une : une page d'erreur ne coupe plus la vérification une semaine. Sous macOS,
  l'empreinte d'un téléchargement est calculée en Rust, sans md5 ni shasum, et le Bilan de confidentialité lit la
  base des autorisations par le lecteur SQLite de Vanguard, sans /usr/bin/sqlite3. Nettoyer : « Paquets
  téléchargés » n'est plus recommandé sans paccache, et dit qu'il efface de quoi revenir en arrière. Le menu,
  `--help` et le lanceur reprennent l'accroche de la vitrine (« Cyberdéfense portable des postes et des réseaux »).
  Du code mort retiré et des dépendances allégées (une crate de moins sous Windows, moins de fonctions compilées
  pour reqwest, tokio et futures) : 9 à 14 bibliothèques de moins selon le système.

- **Logiciels espions.** `vanguard logiciels-espions` (alias `spyware` ; menu Antivirus et protection, en dernier)
  cherche les signes d'un logiciel espion posé par un proche : connexions en cours et noms demandés récemment vers les
  serveurs et sites des logiciels espions connus (liste de l'association Échap, CC-BY 4.0, téléchargée à l'usage et
  gardée un jour, jamais intégrée), logiciels de surveillance connus installés ou en marche (FlexiSPY, Spyrix, Refog,
  Ardamax… ; contrôle parental et surveillance d'employés dits normaux s'ils ont été installés exprès), programmes qui
  lisent le clavier (Linux : /dev/input ; reconnus : compositeur, remappage, Steam, OBS), autorisations Surveillance de
  l'entrée, Accessibilité et Enregistrement de l'écran (macOS, lues par un lecteur SQLite écrit pour Vanguard). Tout
  est lu en Rust, sans commande externe. Lecture seule : rien n'est retiré, car celui qui l'a posé pourrait le voir ;
  l'écran dit de garder des captures et de demander de l'aide d'abord. Ce qui n'a pas pu être vérifié est compté, et
  le verdict n'est jamais « aucun logiciel espion ». Au bilan aussi, sans réseau.
- **Logiciels pas à jour.** `vanguard logiciels-perimes` (alias `outdated-software` ; menu Antivirus et protection, en
  dernier ; au bilan sous Windows et macOS) compare la version installée des navigateurs (Chrome, y compris le canal
  Extended, Edge, Firefox et ESR, Brave), d'Office, d'Acrobat et Reader, de Java, de 7-Zip, de PuTTY et de Slack à la
  dernière publiée : fichiers publics des éditeurs, d'endoflife.date et de Homebrew (formula.json, pris sous Windows
  aussi pour 7-Zip et PuTTY, dont les formules suivent l'amont), téléchargés en entier une fois par jour, les mêmes pour
  tous (la liste de tes logiciels ne sort jamais ; Paramètres › Versions des logiciels pour couper). Version lue dans le
  fichier même (lecteur de la ressource de version des .exe écrit pour Vanguard, Info.plist, dossier du Cellar de
  Homebrew), tous les comptes en administrateur ; Slack par compte, dans son dossier de version, pas son lanceur.
  Firefox : chaque faille exploitée du catalogue de la CISA vérifiée contre ta version (avis de sécurité de Mozilla) ;
  Edge Stable de même, d'après les failles que Microsoft dit corrigées par chaque version ; une version antérieure au
  correctif est critique. Les autres : le nombre de failles exploitées du produit au catalogue, sans conclure pour ta
  version (Slack embarque Chromium, mais ses failles ne se reportent pas sur lui). Ce qui n'a pas de source (Edge
  Extended Stable, Acrobat 2020 et 2024, App Store) est dit non vérifié, comme une réponse de Slack d'une forme
  inattendue (son API n'est pas documentée), une formule de Homebrew désactivée ou obsolète, ou une liste de failles
  d'Edge d'une autre forme ; un navigateur qui ne se compare pas garde le contrôle des 60 jours sans mise à jour, qui
  quitte la fin de support. Sous Linux, la commande renvoie au gestionnaire de paquets. Le lecteur zip
  (guide des commandes) écarte une entrée dont le contenu n'a pas la taille annoncée, qui pouvait dépasser sa borne ;
  gzip et zip passent au banc de fuzzing.
- **Chaîne de confiance des mises à jour.** Une clé de secours, gardée hors ligne, signe aussi les versions (la
  principale perdue ou volée, la mise à jour continue) ; la clé principale peut être chiffrée, sa phrase demandée une
  fois par publication (`outils/signer-versions.sh`, `--secours`). Vanguard retient la plus haute version signée déjà
  vue et refuse un manifeste plus vieux ; une dernière version signée de plus de 45 jours n'est plus dite « à jour »,
  mais non vérifiée. Le programme macOS est contrôlé avant d'être signé (commit, empreinte du journal de sa
  compilation, Mach-O universel, version). La copie locale de la surveillance passe par la mise à jour (jamais vers
  une version plus ancienne), et une nouvelle copie est essayée avant de remplacer l'ancienne (Linux et macOS).
- **État de Vanguard scellé.** `appris.json`, `integrite.json`, `surveillance-botnets.txt` et les versions déjà
  vues portent une empreinte BLAKE3 : changés hors de Vanguard (par un programme qui voudrait faire taire son
  alerte), ils ne comptent plus et le bilan le dit (COM-ETA-001) ; abîmés, ils ne font jamais taire une alerte.
- **Chaîne de confiance, seconde relecture.** Une copie d'ici plus récente que la dernière version signée sur GitHub
  (passée par la clé) n'affiche plus « rien de plus récent » mais « non vérifié » : un ancien manifeste a pu être
  remis en place. Une horloge en retard ne fait plus passer un vieux manifeste pour frais : « non vérifié ».
  `sceaux.json` effacé ne fait plus accepter en silence les fichiers d'état tels quels : ils restent « adoptés »,
  dits au bilan (COM-ETA-001), et la référence d'intégrité comme les versions déjà vues ne sont alors pas crues.
  L'état de la machine au dernier passage de la surveillance et la liste des changements déjà signalés par la
  surveillance d'intégrité sont scellés à leur tour. `signer-versions.sh --secours` refuse une clé de secours en
  clair.
- **CI.** `/dev/root` lu par son numéro comme findmnt, liens d'activation d'unités systemd disparues écartés comme
  systemctl, borne de temps du client HTTP local adaptée à Windows ; `claude-journal.yml` en analyse seule.

## 22 octobre 2026, au soir : version 0.85

- **Dépôt des versions renommé** `d9v3/vanguard-update` (avant : vanguard-officiel). L'ancienne adresse redirige : les
  Vanguard déjà installés se mettent encore à jour.
- **Ce courriel est-il une arnaque ?** `vanguard courriel-suspect <fichier.eml>` (menu Antivirus et protection, en
  dernier) lit un courriel enregistré sans rien ouvrir : aucun lien suivi, aucune image chargée, aucune pièce jointe
  lancée. Il regarde le vrai expéditeur (nom affiché qui imite une marque ou cache une autre adresse, réponses envoyées
  ailleurs, domaine qui imite), le résultat SPF, DKIM et DMARC écrit par le fournisseur de réception — jamais celui
  qu'un expéditeur glisse plus bas, et un « réussi » ne compte que s'il vient sûrement du fournisseur —, chaque lien
  (texte affiché contre vraie adresse, examen du lien hors ligne, liens réécrits par Safe Links déballés), les pièces
  jointes (programme, double extension, macros, page web, image disque, raccourci, archive à mot de passe, PDF qui
  lance du code) écrites sous un nom neutre dans un dossier jetable pour YARA et l'antivirus, jamais ouvertes. Après
  accord, seuls les noms de domaine sortent pour leur âge et les listes publiques. Analyse MIME écrite pour Vanguard,
  bornée en taille, profondeur et nombre de parties (un courriel piégé est marqué incomplet, jamais dit lu). Un .msg
  d'Outlook : la marche pour l'enregistrer en .eml. Le verdict n'est jamais « sûr », et dit ce qui n'a pas pu être
  vérifié.
- **Le veilleur (Linux).** Entre deux passes de la surveillance horaire, un programme ou une connexion de quelques
  minutes passait inaperçu. Le veilleur, coupé par défaut et allumé seulement après avoir montré son unité
  (`vanguard veilleur on`, ou menu Réseau et Internet), écoute deux flux que Linux 6.6 et plus ouvre aux comptes
  ordinaires : chaque programme lancé, même de quelques millisecondes, et chaque connexion TCP ou UDP au moment où
  elle se ferme. Les programmes sont jugés comme au bilan (outil offensif connu, commande qui télécharge ou cache ce
  qu'elle lance, avec leur lignée : « npm → node → sh »), les connexions contre les serveurs de commande de botnets
  déjà téléchargés ; le grave va au tableau de bord et en notification, à débit borné. Il n'arrête rien, sans root
  ni code chargé dans le noyau. Un programme parti avant d'être lu est compté tel quel, jamais jugé sain ; le
  programme d'une connexion fermée n'est pas connu. Le bilan dit s'il est coupé, allumé, ou allumé mais à l'arrêt.
- **Retirer Vanguard de cet ordinateur.** `vanguard desinstaller` (menu Données) retrouve tout ce que Vanguard a posé
  ici, sans registre : la surveillance horaire, l'entretien du mois, la sauvegarde automatique, le veilleur (son unité
  reconnue à sa marque : une unité du même nom posée par quelqu'un d'autre reste), les fichiers-pièges, le raccourci et
  son icône, la copie du programme, et ce qu'une version d'avant le changement de nom avait laissé. Tout est montré
  avec ce qui sera fait, puis coché ; le dossier de données (carnet des appareils, historique, apprentissage,
  quarantaine) n'est jamais coché d'office et demande un second accord. Les changements faits sur le système se défont
  d'abord par leurs outils, ou sont dits avec la commande qui les défait ; la clé USB n'est jamais touchée. À la fin :
  ce qui est retiré, gardé, et ce qui a échoué ou n'a pas pu être vérifié. Sans droits d'administrateur.
- **Raccourci retiré avec son icône** (Linux) : `raccourci off` laissait l'icône ; elle part aussi, si c'est bien celle
  de Vanguard.
- **Une surveillance qui ne tourne plus est dite.** Le bilan vérifie que le programme lancé par la surveillance horaire
  et par l'entretien du mois existe encore (et rsync pour la sauvegarde), pas seulement la tâche, et dit comment la
  remettre.
- **Passes manquées rattrapées.** Activée maintenant, la surveillance rattrape sous Windows une heure manquée
  (ordinateur éteint ou en veille) et passe cinq minutes après l'ouverture de session ; sous Linux, elle rattrape au
  réveil l'heure manquée pendant une veille et passe cinq minutes après l'ouverture de session ; sous macOS, dès
  l'ouverture de session. Une surveillance déjà en place n'est pas changée en silence : le bilan la dit « d'une version
  d'avant », et `vanguard surveillance on` la met à jour.
- **Protection anti-hameçonnage imposée coupée, vue.** Une stratégie de Chrome, Chromium, Brave, Edge ou Firefox
  (fichier de /etc sous Linux, registre sous Windows, policies.json), lue comme le navigateur la lit, qui coupe Safe
  Browsing passe avant les Paramètres, qui ne peuvent plus la rallumer : un logiciel indésirable s'en sert. Le bilan la
  dit, avec l'endroit où la retirer ; une stratégie seulement recommandée compte tant que la personne n'a rien choisi.
  Des réglages de navigateur ou des stratégies illisibles ne passent plus pour une protection active.
- **Un DNS qui ne bloque pas les sites dangereux est dit.** Le bilan le signale (information) et renvoie à « DNS le plus
  rapide », où le Bouclier canadien « Protégé » ou Quad9 se posent en un choix, annulable. Rien n'est dit quand un DNS
  protège déjà, ou quand rien ne permet de le savoir (NextDNS, Pi-hole).
- **Dernières failles exploitées** (`vanguard dernieres-failles [--jours N]`). Celles que la CISA a ajoutées à son
  catalogue ces derniers jours (7 par défaut), les plus récentes d'abord, avec celles des rançongiciels ; sous Arch,
  celles qui touchent un paquet de cet ordinateur en tête. Le bilan donne aussi la date d'ajout d'une faille exploitée.
- **Failles activement exploitées en tête** (Linux, Arch). Les CVE des failles connues des paquets installés sont
  comparées au catalogue KEV de la CISA (failles dont une attaque réelle est connue), téléchargé en entier : la liste des
  logiciels ne sort pas de l'ordinateur. Une faille exploitée rend le constat critique et passe en tête, même sans
  correctif publié ; sans le catalogue, c'est dit. Une faille dans un paquet dont un programme écoute sur le réseau
  (un service par son unité systemd, sans droits root) est dite en tête, au moins élevée. La surveillance horaire notifie une faille critique nouvelle
  (exploitée, ou critique pour la distribution) ; les autres, qui changent chaque jour, restent au bilan.
- **Sites dangereux bloqués** (`vanguard sites-dangereux on|off`). Les hôtes d'URLhaus et les domaines des serveurs
  de commande de ThreatFox (clé abuse.ch) sont envoyés nulle part (0.0.0.0 et ::) par le fichier hosts, après accord
  et avec les droits d'administrateur. Le bloc de Vanguard est entre deux marques datées : `off` le retire exactement,
  le reste du fichier ne change jamais. L'écriture vérifie l'empreinte du fichier préparé et celle du hosts lu au
  départ : rien n'est écrit si l'un a changé entre-temps. Le bilan dit quand la liste a plus d'une semaine. Sous
  Windows, 5 000 noms au plus (au-delà, le client DNS ralentit) ; ailleurs, 20 000. Dans le menu Protection, avec
  « Dernières failles exploitées » ; `desinstaller` rappelle de les retirer avant.
- **Site qui distribue des logiciels malveillants, signalé.** Les noms que l'ordinateur a demandés (mémoire DNS : sans
  droits sous Windows, en root sous Linux) sont comparés aux hôtes d'URLhaus, avec la clé abuse.ch : « Qui parle à
  Internet ? » le montre, et la surveillance horaire le notifie une fois (examen antivirus, fichiers téléchargés). Sans
  la liste, c'est dit ; le nom exact seulement, pour ne pas accuser tout un hébergeur.
- **Feodo Tracker figée, dite.** abuse.ch ne tient plus sa liste de serveurs de botnets à jour depuis le 4 mars 2026
  (une seule adresse). Sans ThreatFox (clé abuse.ch absente), c'était la seule liste lue, et rien ne disait qu'elle
  était figée : « Qui parle à Internet ? », le bilan, le blocage et le veilleur le disent maintenant parmi ce qui n'a
  pas pu être vérifié. Ses adresses servent encore ; avec la clé, ThreatFox suit les mêmes botnets à jour.

## 22 octobre 2026 : version 0.84.1

- **Serveurs d'IA ouverts au réseau, vus aussi sur Mac.** La règle qui repère un serveur d'IA local (Ollama, LM Studio,
  llama.cpp…) joignable depuis le réseau lit maintenant les ports en écoute du Mac ; elle était jusqu'ici toujours dite
  non vérifiée sous macOS. Les programmes sont nommés en entier : un nom coupé à neuf caractères ne se reconnaissait
  pas, et un serveur ouvert serait passé pour sain. Chaque prise garde le programme de son adresse : un serveur
  d'IA ouvert au Wi-Fi n'est plus caché par un autre programme qui tient le même port sur la machine elle-même.
  Sans droits d'administrateur, seuls les programmes du compte en cours sont nommés, et « aucun serveur d'IA » le
  dit ; si lsof ne répond pas, la règle reste non vérifiée. Le blocage des menaces en profite.
- **Connexion forcée par SSH, sur Mac.** Sans sshd, ni en écoute sur le port 22 ou sur celui de ssh dans
  /etc/services, ni en marche (un sshd de Homebrew sur un autre port), ni lancé par une plist de launchd, il n'y a
  rien à lire et Vanguard le dit, au lieu de marquer la règle non vérifiée à chaque bilan ; avec lui, la règle reste
  non vérifiée (le journal unifié de macOS n'est pas lu), jamais saine.
- **Bancs d'essai sans clé abuse.ch.** Sur le Mac de GitHub, sous Linux et dans la VM Windows, l'analyse YARA passe
  quand Vanguard dit les empreintes de MalwareBazaar non vérifiées faute de clé, et la reconnaissance par empreinte
  exacte s'essaie sur une copie posée pour l'essai, puis retirée : plus rien ne dépend des listes fermées le 21 octobre.
- **Présentation.** Vanguard se présente comme la cyberdéfense portable des postes et des réseaux (README, page des
  fonctions, description du dépôt, fichiers de la clé), dans un vocabulaire professionnel : le routeur, le réseau
  local, l'adresse Internet publique. La page des fonctions de GitHub Pages est de nouveau refaite à
  chaque publication : elle en était restée à la 0.82, le programme lancé par un chemin relatif depuis un autre
  dossier.

## 21 octobre 2026, au soir : version 0.84

- **Blocage des menaces, en un clic.** Chaque menace trouvée propose « Bloquer » : le geste est montré, fait après ton
  accord, noté dans « Ce que Vanguard a changé » et défait exactement par `vanguard blocage annuler` (seul l'arrêt
  d'un programme ne se défait pas). Selon la menace : le programme arrêté puis mis en quarantaine, la connexion fermée
  au pare-feu (ufw, nftables, Pare-feu Windows, pf), un lancement retiré du démarrage, la liste de blocage des pilotes
  vulnérables de Windows activée (effective au redémarrage), le port d'un serveur d'IA fermé au réseau, un agent d'IA
  remis à demander avant d'agir. Menu Antivirus et protection › Blocage des menaces, ou `vanguard blocage`.
- **Protection active, qui bloque le certain.** Acceptée une fois, elle bloque toute seule ce qui ne fait aucun doute,
  puis prévient : un fichier dont l'empreinte est dans MalwareBazaar, un outil d'attaque connu en marche, une
  connexion vers un serveur de commande connu (Feodo Tracker, ThreatFox). Le douteux reste une alerte avec son bouton.
  Elle tourne au bilan et dans la surveillance horaire. Quatre catégories (programmes, connexions, démarrage et
  pilotes, agents d'IA), chacune désactivée, en un clic, ou automatique pour les programmes et les connexions. En
  administrateur, elle ne bloque rien toute seule : ses réglages peuvent être écrits par n'importe quel programme du
  compte, et le certain s'y propose d'un clic.
- **Jamais un blocage qui ferait plus de mal que la menace** : ni Vanguard, ni un programme du système ou un processus
  critique, ni une session à distance en cours (SSH, Bureau à distance, RustDesk, AnyDesk, Tailscale…), ni une adresse
  locale ou un DNS public ; un interpréteur (python3, PowerShell) n'est jamais mis en quarantaine, au plus le script
  qu'il lance. Sans les droits nécessaires, rien n'est fait à moitié.
- **Paramètres, tous au même endroit** (Cette machine › Paramètres, « s » au menu principal, ou `vanguard parametres`) :
  langue, emojis, travail sans Internet, protection en temps réel, surveillance horaire, entretien du mois, alertes
  apprises, blocage, restrictions des extensions et clé abuse.ch. Chaque changement montre la valeur d'avant et la commande pour la remettre ; les alertes
  apprises et le blocage ouvrent leur propre écran (« Ce que Vanguard a appris », Blocage des menaces). La langue, les
  emojis et le travail sans Internet restent choisis d'un lancement à l'autre (VANGUARD_LANG, VANGUARD_EMOJI et
  VANGUARD_HORS_LIGNE l'emportent toujours).
- **La protection en temps réel de Vanguard se coupe, pour un temps ou jusqu'à reprise** (Paramètres, ou `vanguard
  parametres temps-reel non --pendant 1h|4h`) : la surveillance horaire et la protection active du blocage s'arrêtent
  d'un coup, après ton accord et la liste de ce qui s'arrête, sans que leurs réglages changent. Elle reprend toute seule
  à l'échéance ; tant qu'elle est coupée, c'est redit en tête du menu et sur ses lignes Surveillance et Blocage, dans
  chaque bilan (sans effet sur la note), dans « Qui parle à Internet ? », dans le blocage et sur le tableau de la
  surveillance, par une notification à la première passe puis chaque jour, et dans l'entretien du mois : un programme
  qui la couperait en douce se voit. Defender, le pare-feu et l'UAC ne sont jamais touchés, et un blocage déjà fait
  reste en place.
- **Extensions : tes propres programmes dans Vanguard, sans toucher à son code** (menu 12 Extensions,
  `vanguard extensions`). Un plugin est un dossier avec un manifeste `plugin.toml`, ajouté une fois depuis un dossier
  ou une archive .zip (`vanguard plugin ajouter`) ; un script du laboratoire est un fichier posé tel quel
  (`vanguard labo`), pour essayer une idée vite. Leurs constats sont montrés à part, ne comptent jamais dans la note,
  et vont dans une section à part du rapport HTML avec `--rapport`. Pour écrire un plugin en Rust : la bibliothèque
  `extensions/sdk`, sans dépendance, et un exemple complet.
- **Une extension est vérifiée avant de tourner.** Avant l'accord, tout son dossier ou son archive est analysé (YARA,
  empreintes de MalwareBazaar) et chaque fichier haché (SHA-256) : un fichier changé, ajouté ou retiré, et il faut la
  réapprouver. C'est la copie vérifiée qui tourne, sans accès au terminal, avec un délai et une sortie bornés : au-delà,
  elle est arrêtée avec tout ce qu'elle a lancé ; sous Linux, ce qu'elle laisse derrière elle est arrêté aussi quand
  elle finit d'elle-même. Une archive ne peut rien écrire hors de son dossier. Sous Linux, `--isole` la lance sans
  réseau, le dossier personnel masqué. Un manifeste ne fait que demander la confiance totale ou de tourner avec le bilan
  ou la surveillance : c'est accordé par une question à part, et l'accord tombe au moindre changement. En
  administrateur, rien du dossier des extensions ne lève une garde : rien n'y tourne tout seul, et chaque lancement est
  demandé. L'interrupteur **Restrictions** (Extensions › 3, Paramètres, ou pour un seul plugin ou script) coupe ces
  garde-fous pour ce qui est à toi ; une seule chose reste : le dossier des extensions doit être à toi, fermé aux autres
  comptes.
- **YARA-X 1.22.0**, qui corrige huit failles connues de wasmtime, la bibliothèque sur laquelle tourne YARA, dont une
  sur les Mac à puce Apple. Chaque bibliothèque utilisée est maintenant vérifiée à chaque version et chaque nuit
  (cargo deny) : failles connues, licences compatibles avec la GPL, provenance (crates.io seulement). Les deux avis
  restants, sans correctif publié, viennent de YARA-X et ne s'appliquent pas à l'usage qu'en fait Vanguard (la raison
  est notée).
- **Calculs vérifiés dans la version publiée** (guide de l'ANSSI, LANG-ARITH) : un nombre qui déborde sur une donnée
  hostile (une taille lue dans un paquet réseau, un journal, un programme Windows) arrête la vérification en cause au
  lieu de repartir à zéro en silence et de fausser la suite ; le reste du bilan continue.
- **Listes d'abuse.ch avec ta clé.** Le 21 octobre, abuse.ch a fermé ses listes publiques : MalwareBazaar, URLhaus et
  ThreatFox demandent désormais une clé gratuite, à créer sur auth.abuse.ch. Vanguard la prend dans Paramètres ou dans
  « Qui parle à Internet ? », la garde sur cet ordinateur (lisible par le compte seul), ne la montre que masquée et ne
  l'écrit jamais dans une adresse affichée ni dans un journal. Sans clé, ou avec une clé refusée, ces listes sont dites
  non vérifiées, jamais saines ; Feodo Tracker reste sans clé.
- **Linux lu sans commandes de plus.** Un client D-Bus écrit pour Vanguard lit les services en échec, la durée du
  démarrage et la santé des disques (UDisks2), à la place de systemctl, systemd-analyze et busctl ; les réglages de
  GNOME et les autorisations des applications Flatpak se lisent dans leurs fichiers (GVDB) ; le journal de systemd et
  ses données compressées (zstd) se lisent en Rust, journalctl et pacman restant en secours. Sous macOS, les comptes
  administrateurs se lisent par la bibliothèque du système, sans dscl.
- **Chaque programme publié porte la liste de ses dépendances** (cargo auditable) : n'importe qui peut le vérifier
  contre les failles connues avec `cargo audit bin`, et une faille connue arrête la publication. cargo audit s'ajoute à
  cargo deny dans chaque vérification, et le code défaillant est refusé dans tout l'arbre des dépendances.
- **Entrées hostiles mises à l'épreuve** : des tests de propriétés sur les lecteurs de données venues d'ailleurs (box,
  DNS, HTTP, bail DHCP, journaux, réglages des agents d'IA, pilotes et événements de Windows) et un banc de fuzzing. Deux
  plantages trouvés et corrigés : une date démesurée dans un bail macOS, et un « cmd /c » imbriqué qui débordait la pile.
  Les sommes de tailles de fichiers sont bornées, un fichier qui fait planter l'analyse YARA reste comparé aux
  empreintes, et une mesure DNS dont le fil plante est dite non vérifiée.
- **Outils de la clé de secours** : la clé se tient à jour même branchée en permanence (programme et images chaque
  jour, nouvelles images cherchées le 1er et le 15 du mois, chaque téléchargement annoncé), Ventoy est vérifié sur la clé
  et sa mise à jour proposée, puis faite sans rien effacer après le mot de passe ; Windows 11 est signalé au-delà de six
  mois.
- **Signaler une faille** : SECURITY.md dit comment (le signalement privé de GitHub), ce qu'il faut joindre, et ce qui
  suit la correction (avis de sécurité publié, CVE si la faille le mérite).
- **Relecture de sécurité.** Un outil d'attaque n'est certain que par le nom du programme lui-même : un script lancé par
  un interpréteur et qui porte le nom exact de l'outil (python3 laZagne.py) n'est qu'un doute, et un nom qui ne fait que
  commencer comme l'outil (python3 sharphound_parser.py) n'est plus signalé. Le programme est revérifié au moment même
  de l'arrêt (son numéro pouvait passer à un autre). La règle ufw qui ferme un port passe avant les autorisations, et le
  port n'est dit fermé qu'une fois vérifié. En automatique, une adresse où un autre compte a une connexion établie n'est
  jamais bloquée. Un fichier de réglages illisible (paramètres, blocage, extensions) est d'abord copié à côté, tel quel,
  avant d'être réécrit ; pour les extensions, rien n'est écrit tant qu'il n'a pas pu être mis de côté.

## 21 octobre 2026, au soir : version 0.83

- **Chasse aux menaces en direct.** Une connexion réussie depuis une adresse qui venait de rater au moins dix mots de
  passe : un mot de passe deviné, signalé en critique (journal de sshd sous Linux ; sous Windows, en administrateur,
  le journal de sécurité pour le Bureau à distance et les partages, et celui d'OpenSSH ; macOS : non vérifié). Une
  lecture bornée ou trop longue est dite partielle, jamais saine sans réserve. Les programmes en marche suspects :
  outil offensif connu (Mimikatz, Rubeus, SharpHound, LaZagne, XMRig…), ligne de commande qui télécharge ou cache ce
  qu'elle exécute, programme lancé de Téléchargements, d'un dossier temporaire ou de la corbeille ; de la ligne, seuls
  le programme et le motif sont montrés, jamais un secret écrit autour.
- **Chronologie de l'incident** dans `vanguard traces` (CHRONOLOGIE.txt) : ce que la collecte a lu de daté, remis dans
  l'ordre du temps sur les 7 derniers jours, avec la technique MITRE ATT&CK quand elle est évidente : connexions
  acceptées ou refusées, sudo, comptes créés, services et tâches ajoutés, journaux effacés, détections de Defender,
  fichiers récents qui parlent. Un journal qui ne remonte pas la semaine dit pourquoi.
- **Portes cachées de Windows et pilotes du noyau** : les DLL que Windows charge lui-même (paquets de LSA,
  AppCertDlls, moniteurs d'impression, fournisseurs de temps, catalogue Winsock) ; les pilotes rangés là où rien
  d'installé n'en pose, ou connus pour être vulnérables (liste LOLDrivers, une fois par semaine). Lecture seule, sans
  PowerShell.
- **Mémoire des programmes** (`vanguard memoire`, à la demande) : les 308 règles YARA appliquées à la mémoire des
  programmes qui tournent, où vit un logiciel malveillant « sans fichier », sous Linux et Windows (macOS : non
  vérifié). La mémoire de LSASS et des processus protégés n'est jamais lue, rien de ce qui est lu n'est gardé, et ce
  qui n'a pas pu l'être est dit.
- **Agents d'IA** : un serveur d'IA local (Ollama, LM Studio, ComfyUI) ouvert au réseau sans mot de passe ; un agent
  réglé pour tout faire sans demander, un serveur MCP lancé sans version fixée, joint sans chiffrement ou avec une clé
  écrite en clair, dans les réglages de Claude Code, Claude Desktop, Cursor, VS Code, Windsurf et Gemini CLI (le nom
  de la clé seulement, jamais sa valeur).
- **Corrections Windows sans PowerShell** : quatorze réglages de durcissement d'une liste fermée (WDigest, NLA du Bureau
  à distance, NTLMv2 seul, LLMNR, WPAD, UAC…) appliqués par Vanguard lui-même, relancé en administrateur : la fenêtre
  de Windows nomme Vanguard, le point de restauration passe d'abord et la valeur d'avant est notée pour annuler
  exactement ; seuls Entrée ou oui appliquent. Mêlées à une correction hors de la liste, elles passent par le script,
  comme avant.
- **Vérifier ma sauvegarde** : une copie réécrite après la sauvegarde (plus récente que son original, et différente),
  comme par un rançongiciel qui chiffre le disque de sauvegarde, est dite abîmée ; elle passait pour « modifiée
  depuis ».
- **Guide des commandes : 1 085 commandes**, dont celles de Vanguard pour se défendre et dépanner, et de quoi vérifier
  à la main ce que signalent les nouvelles règles.
- **Plus justes.** Sous Windows, Vanguard lancé en administrateur se croyait sans droits (Windows refusait la lecture
  de son élévation, que Wine acceptait) : `vanguard traces` y laissait de côté le journal de sécurité, et la fenêtre
  administrateur des corrections se refermait sans rien faire. Un fil de l'analyse YARA qui plantait faisait conclure
  « sain » sans avoir lu ses fichiers : ils sont maintenant dits non analysés. Sans journalctl, les traces reprennent
  aussi le dernier fichier tourné de /var/log (auth.log.1…). Dans ce qui se lance tout seul sous Linux, « nc -e » est
  vu dans ( … ), après ; ou & et derrière un chemin, et un script téléchargé passé à ash, à « sudo -p x sh », à
  « sudo -s » ou à su aussi. La garde contre une DLL posée à côté du programme est exigée à la compilation : elle
  pouvait disparaître.

## 21 octobre 2026 : version 0.82

- **Audit du réseau, domaine par domaine** (`vanguard audit-reseau`). Six notes : exposition à Internet (ports
  ouverts par UPnP, lus par un client UPnP écrit en Rust), Wi-Fi (chiffrement, WPS, réseaux voisins, lus par nl80211
  sous Linux et l'API Wi-Fi de Windows), séparation des appareils (objets connectés sur le réseau des ordinateurs,
  serveur DHCP pirate, intégrité ARP), DNS et certificats, objets connectés, ordinateurs. Ce qui n'a pas pu être
  vérifié est dit et ne compte jamais comme sain : sans assez de domaines vérifiés, pas de note.
- **Windows lu sans PowerShell.** Comptes, démarrage, tâches planifiées, partages, Defender, BitLocker, Windows
  Update, santé du disque et lenteur se lisent par les API de Windows (registre, WMI, COM). Le bilan est plus rapide
  et marche même quand PowerShell est bloqué ; PowerShell ne sert plus qu'en secours.
- **macOS et Linux lus sans commandes.** Sous macOS, les réglages se lisent par un lecteur de plist écrit pour
  Vanguard ; sous Linux, par /proc, /sys et les fichiers du système.
- **Box et objets connectés** (`vanguard objets`) : modèle et logiciel de la box, administration en HTTP seul,
  caméras, imprimantes, NAS, et le rappel de changer leur mot de passe d'origine. La seule demande envoyée à un
  appareil est SNMP « décris-toi », avec le mot de passe de lecture d'usine « public » : elle est annoncée à l'écran.
- **Ordinateur d'un proche** (`vanguard proche`) : trois questions, le bilan, un résumé en mots simples et une page
  à lui laisser.
- **Bilan de confidentialité** (`vanguard acces`) : qui a accès à la position, aux contacts, à la caméra et au micro,
  sur les trois systèmes.
- **Sauvegardes relues pour de vrai** (`vanguard verifier-sauvegarde`) et **tableau de bord de la surveillance**
  dans le navigateur (`vanguard tableau`).
- **Mots de passe des navigateurs** (`vanguard navigateurs`) : comptés et leur protection décrite, jamais lus ni
  envoyés ; la vérification intégrée de chaque navigateur est indiquée.
- **Bouclier canadien** proposé parmi les DNS rapides : le DNS public de l'ACEI, qui bloque les sites malveillants.
- **Windows : une DLL posée à côté de Vanguard n'est plus chargée.** Le programme ne prend ses bibliothèques que dans
  System32 (DependentLoadFlags du PE), y compris lancé depuis une clé USB ou Téléchargements ; le déploiement refuse
  un programme qui n'a pas cette garde.
- **PowerShell en fenêtre cachée** dans un lancement automatique : dit en information, plus en alerte.
- **Une relecture de sécurité** a corrigé de nombreux faux « sain » ; la page des fonctions se publie toute seule
  à chaque version (https://d9v3.github.io/vanguard-beta/).

## 20 octobre 2026 : version 0.81

- **Linux, le bilan voit plus loin.** Redirections ICMP acceptées (IPv4 et IPv6) et filtre des adresses d'origine
  coupé, corrigés dans `99-vanguard.conf` sans jamais relâcher une interface réglée en strict ; espaces de noms
  ouverts à tous les programmes (une information : Flatpak, Chrome et Steam en ont besoin) ; dossiers de commandes
  (PATH, celui de sudo) que d'autres comptes peuvent modifier, où une fausse commande prendrait la place de la vraie ;
  pas de blocage après des mots de passe faux, mots de passe de moins de 8 caractères (PAM).
- **SSH.** Ports renvoyés ouverts à tout le réseau (`GatewayPorts`), affichage X11 renvoyé, trop d'essais de mot de
  passe par connexion ; corrigés par un rechargement de sshd, qui ne coupe aucune connexion en cours. Algorithmes
  cassés (SHA-1 pour l'échange de clés, CBC, 3DES, arcfour, MD5, DSA) rouverts dans la configuration, lue dans
  l'ordre exact des Include : retirés par une ligne de `00-vanguard.conf`, vérifiée par `sshd -t` avant le
  rechargement.
- **Windows.** Recherche automatique du proxy (WPAD), par laquelle un appareil d'un Wi-Fi public peut détourner la
  navigation ; aucun blocage des comptes après des mots de passe faux (corrigé comme Windows 11 : 10 essais,
  10 minutes) ; longueur minimale des mots de passe. Un compte sans mot de passe exigé est décrit tel qu'il est
  (« accepte un mot de passe vide ») et se corrige depuis Vanguard : un mot de passe devient exigé, l'actuel ne
  change pas.
- **macOS.** Découverte automatique du proxy allumée ; dossiers de commandes ouverts à tous ; définitions de
  XProtect, l'antivirus intégré, trop vieilles ; profils de configuration installés hors gestion d'entreprise (un
  logiciel publicitaire s'en sert pour imposer un proxy, un DNS ou un certificat).
- **Guide des commandes : 1 040 commandes** (98 de plus), surtout pour la sécurité et le dépannage : lynis, programmes
  SUID, comptes bloqués, ClamAV, signatures gpg, WireGuard, certificats, exposition des services, needrestart, sbctl,
  dnf needs-restarting ; sous Windows, réseau public ou privé, dossiers partagés, puce TPM, signature d'un programme,
  effacement de l'espace libre, test de la mémoire ; sous macOS, ce qui se lance tout seul, accès à la caméra, au
  micro et à l'écran, empreinte d'un fichier, trafic par programme ; sous Omarchy, 60 commandes de plus : firmware,
  trousseaux et heure qui bloquent une mise à jour, paquets orphelins, cache de pacman, clé FIDO2, serveur SSH et
  groupe docker à couper, réseau et vitesse, partage par LocalSend, captures et texte de l'écran, luminosité, écran
  de démarrage, applications web, jeux et services à installer, remise à neuf. Les exemples de tldr-pages se
  renouvellent aussi pendant la surveillance et l'entretien du mois, sans ouvrir le guide.
- **Secrets dans les projets git.** Vanguard relit l'historique des projets du dossier personnel, où un mot de passe,
  une clé d'API ou un jeton écrit un jour reste, même effacé ensuite : clés reconnues à leur forme (AWS, GitHub,
  GitLab, Google, Stripe, Slack…), clés privées, mots de passe dans une adresse ou dans le code ; gitleaks, s'il est
  installé, ajoute ses règles. Aucun secret n'est affiché ni gardé.
- **YARA sans rien installer.** Les 308 règles sont appliquées par YARA-X (le moteur YARA en Rust de VirusTotal,
  licence BSD), compilé dans Vanguard sous Linux, Windows et macOS : plus de moteur à installer ni à proposer, et
  quatre fichiers lus à la fois. Un fichier de plus de 256 Mo ou plus long que 30 s à analyser est dit, jamais compté
  comme sain. Le programme passe d'environ 10 à 25 Mo.
- **Antivirus par empreintes, partout, même depuis la clé.** L'analyse YARA compare aussi chaque fichier lu aux
  empreintes SHA-256 de MalwareBazaar (abuse.ch, domaine public) : un fichier qui y est, c'est ce logiciel malveillant
  précis, sans doute possible, proposé en quarantaine. La liste complète se met à jour une fois par semaine, les
  48 dernières heures chaque jour ; sans Internet, la copie gardée sert, et sans copie, c'est dit.
- **Outils libres reconnus, s'ils sont installés.** « Failles des images Docker » : trivy dit les failles connues,
  graves ou critiques, des images Docker ou Podman ; absent, Vanguard propose de l'installer par l'outil du système. Après
  des connexions SSH ratées, le bilan dit si fail2ban, sshguard ou CrowdSec bloque déjà les adresses qui insistent.
- **Windows, les portes dérobées classiques.** Débogueur posé sur un programme d'accessibilité de l'écran de
  connexion (IFEO, SilentProcessExit), sethc ou utilman remplacés par cmd, Shell ou Userinit de Winlogon détournés,
  AppInit_DLLs, abonnements WMI qui lancent une commande : au bilan, suivis par la surveillance, corrigés quand
  l'état d'origine est connu exactement, sinon la marche à suivre. Et les journaux d'événements des 7 derniers
  jours : rafales de mots de passe faux par le réseau, journal de sécurité effacé, comptes créés, services installés
  suspects ; sans droits administrateur, le journal de sécurité est dit illisible, jamais sain.
- **Linux, les signes d'un rootkit.** Processus cachés, programmes qui tournent sans fichier (memfd, effacés, lancés
  depuis /tmp ou /dev/shm), module du noyau qui se cache ou modules non signés inconnus, carte réseau en mode
  promiscuité ; lus dans /proc et /sys en quelques millisecondes. Pas de correction automatique : la marche à suivre,
  avec rkhunter et chkrootkit en deuxième avis.
- **Empoisonneur de noms démasqué.** Pendant le scan du réseau, sans le ralentir, Vanguard demande en LLMNR, NetBIOS
  et mDNS un nom tiré au hasard, qui n'existe pas : l'appareil qui y répond est un outil comme Responder, qui vole
  les mots de passe Windows du réseau. Alerte élevée, et notification de la surveillance horaire.
- **Collecter les traces** (Dépanner, `vanguard traces`, et première étape d'« Après une infection », cochée
  d'office ; devant un rançongiciel ou une prise de contrôle, juste après la coupure d'Internet, qui ne peut pas
  attendre). Avant de nettoyer, ce qu'un spécialiste voudra voir, dans un dossier daté sur la clé ou dans le dossier
  de Vanguard : processus avec l'empreinte SHA-256 de leur programme, connexions, ce qui se lance tout seul, bilan en
  JSON, comptes, journaux des 7 derniers jours, fichiers récents ; un LISEZMOI et un MANIFESTE que `sha256sum -c`
  vérifie. Lecture seule, rien n'est envoyé ; Vanguard prévient que le dossier contient des données personnelles.
- **« Qui parle à Internet ? » reconnaît les serveurs de commande de botnets** : listes de Feodo Tracker et de
  ThreatFox (abuse.ch), avec le nom du logiciel malveillant, clé abuse.ch facultative (indisponibles ou trop vieilles,
  c'est dit, jamais comptées comme vides). La mémoire DNS aussi : un programme qui a demandé le nom d'un serveur de
  commande connu se voit, même la connexion fermée. Les connexions des autres comptes sont comparées aussi ; un
  serveur trouvé mène à « Après une infection », Internet coupé d'abord. La surveillance horaire prévient quand un
  programme parle à un serveur de commande connu. Et le dossier temporaire du compte est reconnu où qu'il soit (un
  TEMP déplacé laissait passer un programme lancé de là).
- **Mise à jour depuis GitHub, sans la clé.** « Mettre Vanguard à jour » prend la dernière version publiée, et le
  menu principal l'annonce. Rien n'est cru sur parole : chaque version est signée en Ed25519 sur l'ordinateur de
  l'auteur, et Vanguard refuse un manifeste mal signé, une version qui n'est pas plus récente, ou un programme dont
  la taille, l'empreinte ou la version ne sont pas celles signées. Qui prendrait le compte GitHub ne pourrait pas
  faire installer autre chose. Les programmes signés sont publiés à part (d9v3/vanguard-officiel), le code dans d9v3/vanguard-beta.
- **Client HTTPS en Rust** : listes, registres, fuites, tldr, débit et listes noires sans curl ; redirections en HTTPS
  seulement. Le programme prend 2 à 3 Mo.
- **Lu directement par le système** : connexions, processus, droits et compte, registre des traces et journaux
  d'événements, sans ss, tasklist, taskkill, whoami, pgrep, id ni PowerShell ; plus rapide, et rien ne dépend de la
  langue de Windows. Sans droits, le journal de sécurité est dit non vérifié (avant, il passait pour sain sans avoir
  été lu).
- **Nettoyage de Windows** : chemins écrits en entier, jamais le dossier courant quand une variable comme TEMP est
  vide ; la file d'impression se vide sans risque.
- **Plus justes et plus sûrs.** Sous Windows, un compte sans dossier Démarrage ne fait plus prendre chaque fichier
  du dossier courant pour un « raccourci suspect » (alerte élevée à tort, surtout lancé depuis la clé) ; les
  dernières commandes rapides (notifications, df sur un volume réseau mort…) ont un délai et ne figent plus la
  surveillance ; la liste des clés connues ne perd plus une note quand deux s'écrivent en même temps.
- **Clé de secours : l'installateur d'Omarchy** dans le menu de démarrage, à côté d'Arch, Debian, Fedora et
  SystemRescue : complet, sans Internet, tenu à jour comme eux et vérifié par la clé qui signe les paquets d'Omarchy.
- **Pour les tests** : scripts PowerShell du programme analysés et rejoués avec pwsh à chaque vérification, dans
  un bac à sable fermé au système ; test de la machine virtuelle Windows qui compte les étapes sautées, compare chaque passe à la
  précédente et vérifie les réglages de la 0.79 ; scripts déposés depuis Linux et lancés par la VM
  sur son accord.
- **Relecture indépendante avant la publication** : un compte au mot de passe vide qu'une correction aurait fait
  passer pour sain, une limite d'essais SSH trop stricte qui pouvait fermer la porte, un `chmod` qui aurait cassé
  `/tmp` mis dans le PATH ; corrigés.

## 19 octobre 2026, au soir : version 0.78

- **Nouveau nom : Vanguard**, avec son logo, un V en bouclier et un cadenas. Sur un ordinateur où il a déjà
  tourné, rien ne se perd : données, sauvegarde automatique, raccourci et réglages suivent le nouveau nom tout seuls.
- **Bilan bien plus rapide.** Sous Linux, de 7 secondes à moins d'une : les commandes ne sont plus attendues par
  pauses fixes de 50 ms, les paquets se vérifient en parallèle, le Wi-Fi n'attend plus un nouveau balayage. Sous
  Windows, une dizaine de lancements de PowerShell de moins : pare-feu, UAC, Bureau à distance et verrouillage lus
  directement dans le registre, ports en écoute lus par netstat et tasklist.
- **Windows.** Installation de paquets MSI avec les droits du système, protection dans le cloud de Defender coupée,
  protection contre les exploits coupée (DEP, ASLR, CFG, SEHOP), Windows Update coupé (service ou stratégie),
  services au chemin sans guillemets dans un dossier modifiable par tous ; BitLocker suspendu ou en attente ne compte
  plus comme chiffré.
- **Linux et macOS.** Session qui s'ouvre toute seule sans disque chiffré (GDM, SDDM, LightDM), mémoire des
  programmes root lisible après un plantage, touches magiques du noyau ; sauvegarde Time Machine non chiffrée,
  partage à distance du Mac qui accepte root ou les comptes sans mot de passe.
- **Plus justes.** Fichiers inclus de la configuration SSH lus, réseaux Wi-Fi ouverts mieux reconnus, DNS sur cet ordinateur mesuré aussi
  sur un site nouveau (sa mémoire répondait en moins d'une milliseconde), dnf-automatic
  qui ne fait que télécharger, réglages d'APT lus dans leur ordre, interface anglaise complète, nombres à virgule écrits à la française,
  longs messages coupés entre deux mots, jamais au milieu d'un mot ; sous Windows, un pare-feu dont aucun profil ne
  se lit n'est plus compté comme vérifié (pas de note), et un Bureau à distance imposé par une stratégie de groupe est
  reconnu ; une interface de VPN n'est plus prise pour le réseau local.
- **Scan du réseau deux fois plus rapide** (de 20 à 8-10 secondes sur un réseau de onze appareils) : la box est
  interrogée sur l'UPnP dès le début, en fond (elle met jusqu'à 8 secondes à répondre), et les ports TCP, UDP et les
  noms des appareils sont cherchés en même temps. Mêmes sondes, rien de retiré.
- **Guide des commandes refait.** Une entrée par système : Omarchy, Arch, Fedora, Debian et Ubuntu, autres Linux,
  Windows 11, macOS ; chaque distribution a sa présentation, ses marches à suivre « Pas à pas » (mettre à jour,
  installer, faire de la place, réparer, pare-feu, NVIDIA, nouvelle version…) et ses programmes, puis ceux communs à
  Linux ; Windows 11 et macOS ont aussi les leurs (réparer Windows, réseau, sécurité, lenteur, Time Machine…), tous
  les systèmes aussi (clé SSH, git) ; plus de vingt programmes communs à Linux en plus (heure, noyau, Wi-Fi,
  diagnostic réseau, comptes, son, imprimantes, démarrage UEFI…), openSUSE et Docker ; 942 commandes. On tape ce
  qu'on cherche et les commandes paraissent au fil de la frappe ; chacune a sa page, pour la copier, ou la lancer
  ici quand elle ne fait que lire (sa sortie défile dans Vanguard, Échap l'arrête).
- **Plus de 30 000 commandes en plus** : les exemples de tldr-pages (licence CC BY 4.0), téléchargés tout seuls chaque
  semaine et déjà sur la clé (même sans Internet, le guide les a dès le premier lancement), en français quand ils
  sont traduits ; à copier seulement. Dans toutes les recherches, ce qui commence par le mot tapé passe devant.
- **Plus sûr : la clé reconnue à son jeton.** Un volume qui porte le témoin d'une clé VANGUARD n'est plus la clé
  pour autant : depuis sa copie locale (surveillance, entretien, raccourci), Vanguard ne lit et n'écrit que sur une
  clé lancée depuis elle ou connue de cet ordinateur (jeton `vanguard.jeton` posé au déploiement, partition des
  journaux comprise) ; un volume inconnu est dit tel au menu et ignoré. Le carnet de la clé a sa référence ici :
  modifié hors de Vanguard, ou revenu sans sa protection, il n'est ni lu ni réécrit et le bilan le dit
  (`vanguard manifeste --accepter` quand c'est voulu).
- **Prédiction des mots dans tous les menus** et les listes à cocher : la fin du mot le plus probable s'affiche en
  gris, Tab la complète.
- **Bilan plus profond.** Sécurité de la plateforme d'après fwupd (niveau HSI : TPM, protection du BIOS, IOMMU),
  verrouillage du noyau et signature des modules, BPF, auditd ; sous Windows, journalisation des scripts PowerShell,
  Credential Guard (Entreprise, Éducation), Sysmon. Scan approfondi d'un appareil : versions des services par nmap
  s'il est installé. Les nouvelles règles ont un identifiant stable (« vanguard regles »).
- **Plus sûr.** Le bac à sable n'atteint plus le bus du système ni Docker ; sous Windows, le script de correction est
  vérifié juste avant de tourner en administrateur (un script modifié entre-temps ne part pas) ; les données de
  Vanguard sont réservées à ton compte. La sauvegarde automatique reconnaît son disque à son identifiant (UUID),
  plus à son nom : un autre disque au même nom ne reçoit plus tes fichiers. Tout texte venu d'ailleurs (nom
  d'appareil, de fichier, d'imprimante) passe par une seule protection avant d'entrer dans une commande, et un test
  le vérifie dans tout le code.
- **Vanguard se met à jour depuis la clé.** La copie posée sur un ordinateur (surveillance, entretien, raccourci) ne
  suivait pas la clé : lancé depuis une clé plus récente, Vanguard le dit au menu, et la mise à jour se fait sur
  accord (9.9 ou `vanguard se-mettre-a-jour`), relue et comparée avant de remplacer l'ancienne ; jamais vers une
  version plus ancienne, et jamais depuis une clé seulement branchée.
- **Une seule publication par jour.** Ce journal regroupe les versions par jour ; seule la dernière garde sa page de
  téléchargement, et le Mac de GitHub ne compile plus qu'une fois par publication.

## 19 octobre 2026 : versions 0.62 à 0.77

- **Bilan bien plus complet sous Windows.** Authentification réseau LM ou NTLMv1, empreintes LM, signature et accès
  invité des partages, comptes listés anonymement, client SMBv1, Registre à distance, UAC qui ne demande plus rien,
  stratégie de PowerShell, macros d'Office toutes permises, exclusions de Defender trop larges, Secure Boot,
  WDigest, protection de LSA, PowerShell 2, SmartScreen, intégrité de la mémoire, mises à jour en pause, et le
  verrouillage de l'écran.
- **Linux et macOS.** Mises à jour de sécurité automatiques, réglages du noyau (tubes et fichiers dans /tmp,
  compteurs du processeur), client SSH qui ne vérifie pas les serveurs, serveur SSH qui accepte les comptes sans
  mot de passe, sudo qui ne redemande jamais le mot de passe, cups-browsed ouvert au réseau, affichage X11 ouvert à
  tous, réseaux Wi-Fi ouverts qui se reconnectent tout seuls.
- **Partout.** Nouveaux administrateurs et navigation détournée (proxy imposé, fichier hosts) signalés ; heure
  de l'ordinateur, fin de support du système, comptes oubliés, mots de passe gardés par le navigateur, fichiers
  sensibles qui traînent.
- **Nouveaux outils.** Sauvegarde automatique, compte piraté, rapport à laisser sur place, raccourci sur le Bureau,
  et « Ce que Vanguard a changé » : chaque correction est notée et datée, et le rapport HTML la résume.
- **Prudence.** Les partitions de la clé ne sont plus proposées comme disque ; Vérifier ma clé et Time Machine plus
  prudents ; noms de disque piégés refusés dans les sauvegardes automatiques.

## 18 octobre 2026 : versions 0.52 à 0.61

- **Dépannage pas à pas** (réseau, sécurité, entretien, après une infection, nouvel ordinateur ou départ), guide
  des commandes et apprentissage.
- **Nouvelles défenses.** Faux technicien et prise de contrôle à distance, partages ouverts à tous, blocages de
  Windows Defender, fichiers-pièges contre les rançongiciels, Bluetooth, Téléchargements surveillés, quarantaine
  réversible, caméra et micro.
- **Vanguard se vérifie lui-même** : manifeste de la clé, failles des dépendances chaque nuit, vérifier une copie,
  vérifier ma clé, données de la clé chiffrées, « Mes ordinateurs ».
- **Confort.** Programmes au démarrage, menus qui défilent, recherche dans les listes à cocher, copie d'une commande
  du guide, émojis bien alignés, noms piégés rendus inoffensifs à l'écran.
- **Code allégé et rangé comme le menu**, au même comportement ; moins de fausses alertes.

## 17 octobre 2026 : versions 0.9.5 à 0.51

- **Vanguard prend son nom**, avec son logo bouclier et une présentation refaite.
- **Bilan élargi.** DNS et certificats racine, extensions et réglages de sécurité des navigateurs, santé de
  l'ordinateur, mots de passe et adresses courriel fuités, persistance cachée, failles connues des paquets, journaux
  effacés, intégrité des fichiers critiques, usurpation ARP de la box, ports ouverts vers Internet par UPnP.
- **Outils.** Mises à jour de tout le système, pilotes compris ; Réparer et nettoyage approfondi ; Optimiser, avec
  des réglages qui s'annulent exactement ; jeu sous Windows et sous Linux ; diagnostic de l'ordinateur ; logiciels
  essentiels ; bac à sable pour programmes inconnus ; test de connexion pour le jeu.
- **Suivi.** Changements depuis le dernier bilan et courbe des notes, surveillance de cette machine, rapport texte
  d'urgence, point de restauration automatique avant chaque correction.
- **Clé USB** protégée en écriture, journal des erreurs, antivirus d'une clé ; français et anglais partout ; menus au
  clavier (flèches, Entrée, Échap) ; audit en parallèle, trois fois plus rapide ; macOS au niveau de Linux et Windows.

## 16 octobre 2026 : versions 0.2 à 0.9.4

- **Premières versions.** Scan du réseau local et base des appareils, audit de Linux (Docker, pare-feu, UDP, clés
  SSH, verrouillage, noyau durci, AppArmor ou SELinux, sauvegardes, sudo) et de Windows.
- **Menu Réparer** pour Linux, Windows et macOS.
- **Fiabilité.** Plus aucune commande en échec prise pour « tout va bien », délais sur les commandes, base des
  appareils sûre ; le Bureau à distance en cours n'est jamais coupé.
