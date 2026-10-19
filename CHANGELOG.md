# Historique des versions

*[English](CHANGELOG.en.md)*

Ce que chaque journée a apporté à Vanguard, la plus récente en haut. Depuis le 19 octobre 2026, Vanguard a une seule
publication par jour, qui regroupe le travail de la journée. Seule la dernière version a sa page de téléchargement ;
chaque version garde son étiquette dans le dépôt (`git checkout v0.62.0`, par exemple), pour être recompilée au besoin.

## 20 octobre 2026 : version 0.78

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
  qui ne fait que télécharger, réglages d'APT lus dans leur ordre, interface anglaise complète, nombres à virgule écrits à la française.
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
- **Prédiction des mots dans tous les menus** et les listes à cocher : la fin du mot le plus probable s'affiche en
  gris, Tab la complète.
- **Bilan plus profond.** Sécurité de la plateforme d'après fwupd (niveau HSI : TPM, protection du BIOS, IOMMU),
  verrouillage du noyau et signature des modules, BPF, auditd ; sous Windows, journalisation des scripts PowerShell,
  Credential Guard (Entreprise, Éducation), Sysmon. Scan approfondi d'un appareil : versions des services par nmap
  s'il est installé. Les nouvelles règles ont un identifiant stable (« vanguard regles »).
- **Plus sûr.** Le bac à sable n'atteint plus le bus du système ni Docker ; sous Windows, le script de correction est
  vérifié juste avant de tourner en administrateur (un script modifié entre-temps ne part pas) ; les données de
  Vanguard sont réservées à ton compte.
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
