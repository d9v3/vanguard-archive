# Historique des versions

*[English](CHANGELOG.en.md)*

Ce que chaque journée a apporté à Vanguard, la plus récente en haut. Depuis le 19 octobre 2026, Vanguard a une seule
publication par jour, qui regroupe le travail de la journée. Seule la dernière version a sa page de téléchargement ;
chaque version garde son étiquette dans le dépôt (`git checkout v0.62.0`, par exemple), pour être recompilée au besoin.

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
