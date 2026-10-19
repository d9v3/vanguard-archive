<p align="center">
  <img src="assets/icones/gardien-256.png" alt="Logo de Gardien : un bouclier ouvert sur un trou noir" width="150">
</p>

<h1 align="center">Gardien</h1>

<p align="center"><b>Français</b> · <a href="README.en.md">English</a></p>

<p align="center">
  <b>Sécurise et optimise ton ordinateur et ton réseau, depuis une clé USB.</b><br>
  Gardien vérifie ta machine et tous les appareils de ton réseau, explique chaque problème en français clair,<br>
  et le corrige après ton accord. Linux, Windows et macOS, sans installation, en français ou en anglais.
</p>

![Bilan de sécurité de Gardien : une note de A à F, chaque problème expliqué avec sa correction](assets/captures/bilan.png)

## En bref

- **Un bilan noté de A à F** : pare-feu, mises à jour, chiffrement, ports ouverts, sauvegardes… Chaque problème est
  expliqué simplement, avec sa correction.
- **Tout ton réseau** : chaque appareil, son fabricant, ses ports ouverts et ses risques ; les nouveaux venus sont
  signalés.
- **Rien n'est changé sans ton accord** : un point de restauration d'abord, et chaque réglage s'annule exactement.
- **Une clé USB pour tous tes ordinateurs**, et ceux de tes amis : elle se protège elle-même en écriture ailleurs que
  chez toi.

## Démarrer

**Télécharger** (dernière version) : [Windows](../../releases/latest/download/gardien-windows-x86_64.exe) ·
[Linux](../../releases/latest/download/gardien-linux-x86_64) · [macOS](../../releases/latest/download/gardien-macos)
— ou toute la [page des versions](../../releases/latest), avec les empreintes SHA-256.

- **Windows** : double-clic sur le programme. Il n'est pas signé : SmartScreen peut avertir (« Informations
  complémentaires » puis « Exécuter quand même »). Microsoft Defender le prend parfois à tort pour un virus
  (« Trojan:Win32/Bearfoos.A!ml », une détection automatique sur un programme neuf) : c'est un faux positif ;
  vérifie l'empreinte SHA-256 sur la page de la version.
- **Linux** : `chmod +x gardien-linux-x86_64`, puis `./gardien-linux-x86_64` dans un terminal (toutes les
  distributions, rien à installer).
- **macOS** : copié depuis Internet, le programme est bloqué la première fois : `xattr -d com.apple.quarantine
  gardien-macos`, puis `./gardien-macos` dans le Terminal.
- **Depuis la clé USB** : `Windows/gardien.exe`, `Linux/gardien`, ou `Lancer Gardien.command` sous macOS ; le guide
  de la clé est dans `LISEZMOI.txt`.

Dans le menu, choisis **1** (bilan complet), puis **2** (corriger). Les flèches, Entrée, et Échap ou Retour arrière
pour revenir.

> Gardien s'appelait Sentinel jusqu'à la version 0.50 : ses données, sa surveillance et sa clé sont reprises telles
> quelles.

## Ce que fait Gardien

| Domaine | Ce que fait Gardien |
|---|---|
| **Bilan de sécurité** | Une note de A à F : pare-feu, mises à jour et failles, chiffrement, ports ouverts, comptes, SSH, ce qui se lance en cachette, partages ouverts à tous, Wi-Fi, santé des disques… Chaque problème est expliqué, avec sa correction. |
| **Réseau local** | Chaque appareil, son fabricant, ses ports ouverts et ses risques ; les nouveaux venus signalés, les ports ouverts sur la box, l'adresse de la maison sur liste noire. |
| **Wi-Fi, NAT, DNS, caméras** | Le canal Wi-Fi le plus libre, le type de NAT pour le jeu, le DNS le plus rapide (sans retirer un DNS qui protège), les caméras cachées. |
| **Connexion pour le jeu** | Ping, gigue, pertes, débit et bufferbloat, comparés à tes habitudes. |
| **Dépanner** | Diagnostic de l'ordinateur, pannes de tous les jours pas à pas (Internet, Wi-Fi, lenteur, son, imprimante, disque plein), après une infection, nouvel ordinateur, ordinateur qui part, « Pourquoi c'est lent ? », fiche de l'ordinateur, réparations. |
| **Optimiser et nettoyer** | Réglages de confidentialité et de performance qui s'annulent exactement, nettoyage à cocher avec la place gagnée mesurée, programmes du démarrage. |
| **Protection** | Fichiers-pièges contre les rançongiciels, blocages de Windows Defender, 308 règles YARA, antivirus, bac à sable, intégrité des fichiers critiques, mots de passe fuités, connexions sortantes, faux technicien (logiciels de prise de contrôle à distance), caméra et micro, liens dangereux, fichiers téléchargés, quarantaine réversible. |
| **Suivi** | Surveillance toutes les heures, entretien du mois, rapport HTML avec la courbe des notes, apprentissage sur ton ordinateur. |
| **Logiciels et jeux** | Les meilleurs logiciels en 8 catégories, depuis leur source officielle ; mises à jour de tout d'un coup ; réglages pour jouer. |
| **Outils** | Copier mes fichiers (copie vérifiée) et vérifier une copie, mes ordinateurs (suivis par la clé), données de la clé protégées par une phrase, guide des commandes, recherche dans tous les menus. |

<details>
<summary><b>Le détail, fonction par fonction</b></summary>

**Bilan de sécurité** — une note de A à F, puis chaque problème avec sa correction.
- Pare-feu, ports ouverts (TCP et UDP), mises à jour et failles connues, chiffrement du disque, Secure Boot,
  verrouillage de l'écran, comptes, SSH (et ses tentatives de connexion ratées, venues d'Internet ou de la maison),
  sudo, groupes qui valent root (docker, lxd, libvirt, disk), durcissement du noyau (sous macOS : volume du système scellé,
  signature du code imposée, validation des bibliothèques, extensions ajoutées), fichiers secrets mal protégés,
  sauvegardes, partages de fichiers ouverts à tout le monde (Samba, NFS, partages Windows, Partage de fichiers de
  macOS : l'accès sans mot de passe est fermé après accord, les comptes nommés gardent le leur).
- Ce qui se cache : programmes lancés au démarrage, tâches planifiées, préchargement de bibliothèques, programmes
  privilégiés modifiés.
- DNS réellement utilisé (et réponses inventées), certificats racine ajoutés (interception du HTTPS), extensions de
  navigateur qui lisent tous les sites.
- Wi-Fi : protection du réseau (WEP, WPA2, WPA3), et faux point d'accès (« jumeau maléfique ») qui copie son nom
  sans mot de passe pour attirer les appareils.
- Bluetooth : ordinateur visible en permanence, et appareils appairés depuis moins d'une semaine (un clavier
  appairé par quelqu'un d'autre tape ce qu'il veut).
- Santé : espace disque, état SMART des disques (sans root), batterie, températures.
- Ce qui n'a pas pu être vérifié est dit, jamais compté comme sain.

**Réseau local** — tous les appareils, leur fabricant, leurs ports ouverts (TCP, et UDP : SNMP, NetBIOS, UPnP, DNS,
mDNS) et leurs risques ; les nouveaux venus signalés, un carnet par réseau (chez toi, chez chaque ami), des surnoms
(« imprimante HP ») ; les ports que des appareils ont ouverts vers Internet sur la box par UPnP (lecture seule, avec
miniupnpc sous Linux). Après accord, l'adresse Internet de la maison est cherchée dans quatre listes noires
(Spamhaus, SpamCop, DroneBL, PSBL) : listée pour pourriel ou attaques, un appareil est sans doute infecté.

**Connexion pour le jeu** — ping, gigue, pertes, débit et bufferbloat (le lag quand quelqu'un télécharge), avec un
verdict critère par critère et des conseils.

**Wi-Fi, NAT, DNS et caméras** — le Wi-Fi encombré : les réseaux voisins par canal, et le canal le plus libre à
régler sur la box ; le type de NAT pour le jeu (ouvert, modéré ou strict, comme sur les consoles), double NAT et
adresse partagée par le fournisseur compris ; le DNS le plus rapide, mesuré ici, proposé seulement s'il ne remplace
pas un DNS qui protège (NextDNS, chiffré, filtrant) et annulable ; et, dans une location ou chez quelqu'un, les
appareils du réseau qui ressemblent à des caméras (fabricant, flux vidéo, ONVIF), sans rien couper ni regarder.

**Diagnostic de l'ordinateur** — le premier réflexe d'un dépannage : matériel, système, et les problèmes récents
(erreurs du journal et programmes plantés sous Linux ; écrans bleus, arrêts brutaux et plantages sous Windows ;
paniques du noyau et rapports de plantage sous macOS), avec une copie texte enregistrée sur la clé.

**Dépanner pas à pas** — les pannes de tous les jours, prises comme le ferait quelqu'un qui s'y connaît : pas
d'Internet, Wi-Fi qui coupe, ordinateur lent, pas de son, imprimante qui ne marche pas, disque plein. Deux ou trois
questions, puis Gardien vérifie lui-même (adresse, box, Internet, DNS ; signal Wi-Fi ; service du son et sortie
choisie ; file d'impression et imprimante sur le réseau ; place des disques) et propose la bonne réparation ou le
bon outil, toujours après accord. Et trois parcours pour les grands moments : **après une infection** (ce qui presse
selon le signe, le bilan de ce qui a pu s'installer, les analyses dans l'ordre, puis les mots de passe à changer,
le courriel en premier) ; **nouvel ordinateur** (mises à jour, chiffrement, sauvegardes, pack de départ,
confidentialité, dans l'ordre) ; **ordinateur qui part**, vendu ou donné (copie vérifiée d'abord, comptes
déconnectés, clé BitLocker ou FileVault mise de côté, effacement sûr par l'outil du système, puce TPM remise à
zéro). Gardien n'efface rien lui-même.

**Pourquoi c'est lent ?** — un instantané de deux secondes : ce qui occupe le processeur, la mémoire et le disque,
programme par programme ; la durée du démarrage et ce qui le retarde ; les programmes lancés à l'ouverture de
session et leur poids. Ceux qui travaillent un moment puis se calment (antivirus qui analyse, indexation, mises à
jour) sont nommés comme tels. Les programmes du démarrage se retirent de là, après accord : ils restent installés,
et chaque retrait s'annule exactement (`gardien demarrage`).

**Fiche de l'ordinateur** — modèle, carte mère, BIOS, processeur, mémoire (barrettes, type, vitesse), carte graphique
et pilote, disques : ce qu'on demande au téléphone ou pour acheter une pièce. Les numéros de série s'affichent à
l'écran seulement, jamais écrits.

**Copier mes fichiers** — Documents, Images, Bureau, Vidéos et Musique vers un disque externe, avant une réparation
risquée ou une réinstallation : la place est vérifiée avant, chaque fichier relu et comparé à l'original (empreinte
BLAKE3), rien n'est effacé ni écrasé, et une copie interrompue reprend où elle s'est arrêtée. **Vérifier une
copie**, plus tard, fait le test de restauration : des fichiers répartis sur toute la copie sont relus sur le disque
et comparés à leur original ; un disque qui perd des données se voit avant le jour où on en a besoin.

**Mes ordinateurs** — chaque bilan complet fait avec la clé GARDIEN y note l'ordinateur : surnom (« système ·
modèle », renommable), note, problèmes restants (leur catégorie et leur niveau seulement, les cinq plus graves),
date du dernier bilan. Le tableau voyage sur la partition GARDIENLOG de la clé, sans nom de machine, compte, adresse
ni nom de Wi-Fi ; il ne part jamais sur GitHub.

**Protéger les données de la clé** — le carnet des appareils de la clé (noms, adresses MAC, surnoms) chiffré par une
phrase (XChaCha20-Poly1305, phrase dérivée par Argon2id), contre une clé perdue ou prêtée. Chez soi, rien ne change :
la clé de données est gardée sur l'ordinateur du propriétaire. Ailleurs, Gardien demande la phrase, ou continue sans
le carnet. Le rapport et le diagnostic ne s'écrivent plus sur la clé. Sur demande, réversible, avec une sauvegarde
proposée avant ; le bilan signale un carnet resté en clair.

**Optimiser** — des réglages de confidentialité, de performance et de confort, écrits pour Gardien. Sous Windows :
télémétrie au minimum, publicités et suivi coupés, Recall sans captures d'écran, extensions des fichiers visibles, pas
de lancement automatique des clés USB, démarrage rapide, menu complet au clic droit. Sous Linux : entretien du SSD,
taille du journal, rapports envoyés par GNOME ou Ubuntu. Sous macOS : publicités, analyses, pas de .DS_Store sur les
clés. Chaque réglage montre son état et s'annule exactement : la valeur d'avant est notée, puis remise. Aucun
n'affaiblit la sécurité.

**Nettoyer le système** — une liste à cocher de ce qui prend de la place sans servir : paquets téléchargés et devenus
inutiles, anciennes versions des Snap, Flatpak inutilisés, compilations AUR, vieux caches, miniatures, vieux journaux,
rapports de plantage (Linux) ; fichiers temporaires, cache de Windows Update et de l'optimisation de distribution,
anciens composants (Windows) ; vieux caches, Homebrew, Xcode, instantanés locaux (macOS). La place que libère chaque
élément est mesurée avant, ce qui se refait seul est coché d'office, la corbeille jamais ; la place libre relue après
dit ce qui a vraiment été gagné.

**Contre les rançongiciels et les logiciels malveillants** — des fichiers-pièges : un texte et un PDF leurres
dans Documents, Images et Bureau, que personne n'a de raison de toucher. Un rançongiciel qui les chiffre ou les
renomme déclenche une alerte critique, au bilan et toutes les heures par la surveillance, avec la marche à suivre ;
posés et retirés après accord. Et une analyse YARA : 308 règles de ReversingLabs qui reconnaissent des familles
entières (rançongiciels, voleurs de mots de passe, chevaux de Troie, portes dérobées…), en complément de
l'antivirus. Ce que l'antivirus ou YARA trouve peut aller en quarantaine, réversible : le fichier est rendu
inutilisable et noté, puis remis exactement à sa place si c'était un faux positif.

**Caméra et micro : qui s'en sert ?** — sous Windows, chaque programme qui a utilisé la caméra ou le micro, et la
dernière fois (un programme lancé depuis un dossier temporaire ou Téléchargements est signalé) ; sous Linux, ce qui
les tient en ce moment. En lecture seule.

**Blocages de Windows Defender** — Gardien ne bloque rien lui-même : il active, après accord, ce que Windows bloque
depuis son noyau et protège contre la désactivation. Règles de réduction de la surface d'attaque (vol des mots de
passe en mémoire, pilotes vulnérables, documents Office et pièces jointes piégés), protection réseau contre les
sites dangereux, logiciels indésirables, accès contrôlé aux dossiers contre les rançongiciels. Chaque règle est
nommée avant l'accord et s'annule exactement ; celles qui bloqueraient Gardien sur sa clé ou le dépannage ne sont
jamais activées, et rien n'est proposé si un autre antivirus remplace Defender.

**Apprentissage** — Gardien apprend sur ton ordinateur, sans rien envoyer. Une alerte que tu déclares normale chez
toi (« i » à la correction) passe au niveau info pendant 90 jours, ou jusqu'à ce qu'elle s'aggrave ; chaque test de
connexion se compare à tes habitudes sur le même réseau ; un appareil connu qui paraît soudain tout fermé (en
veille) est revérifié plus patiemment. « Ce que Gardien a appris » montre tout et permet d'oublier.

**Guide des commandes** — les commandes utiles de Linux, de Windows, de macOS et celles qui s'écrivent pareil
partout (Gardien, ping, nslookup, ssh, curl, git…), rangées par système puis par programme, chacune expliquée ; ⚠
marque celles qui changent quelque chose. Rien ne s'y lance : on lit, puis on tape la commande, ou on la copie par
son numéro, ici ou chez la personne qu'on aide. Tous les systèmes sont lisibles partout (les commandes de Windows
depuis Linux, par exemple), et le guide dit si un programme manque sur cet ordinateur.

**Et aussi**
- Recherche dans tous les menus et les listes à cocher : tape un mot (wifi, disque, dns, mise à jour…), seules les
  lignes qui le contiennent restent, sans souci d'accents ni de majuscules ; au menu principal, elle trouve aussi
  chaque outil des sous-menus et chaque page du guide.
- Corrections appliquées seulement après confirmation, avec un point de restauration créé automatiquement avant
  (snapper ou timeshift sous Linux, point de restauration Windows, instantané Time Machine sous macOS) ; sous
  Windows, chacune est un script lisible.
- Mises à jour de tout d'un coup : système, programmes, pilotes, firmware.
- Logiciels : les meilleurs de chaque usage, libres pour la plupart, rangés en 8 catégories (navigateurs et
  courriel, messagerie et partage, sécurité et vie privée, bureautique, vidéo et musique, images et création, outils
  système, programmation) et un pack de départ (Firefox, Bitwarden, VLC, LibreOffice, 7-Zip) : liste à cocher, déjà
  installés reconnus, installation depuis la source officielle qui vérifie chaque téléchargement (winget, paquets de
  la distribution ou Flathub, Homebrew).
- Réparations : Internet, navigation détournée, pare-feu, disque, disque plein, nettoyage approfondi, Windows Update
  bloqué, fichiers système, heure.
- Antivirus : ClamAV (Linux, macOS) ou Microsoft Defender (Windows), sur l'ordinateur ou sur une clé USB / un dossier
  choisi, avec les pièges des vers de clé (raccourci qui imite un dossier, autorun.inf, scripts).
- Bac à sable : lancer un programme inconnu sans réseau, système en lecture seule, dossier personnel invisible
  (bubblewrap ou firejail sous Linux, Windows Sandbox sous Windows, sandbox-exec sous macOS).
- Intégrité des fichiers critiques (comptes, sudo, SSH, PAM, cron, services, démarrage automatique) : empreintes
  BLAKE3, ce qui a changé depuis la référence, et surveillance en direct.
- Mots de passe fuités : vérifiés par Have I Been Pwned sans jamais envoyer le mot de passe (5 caractères de son
  empreinte seulement) ; fuites d'adresse courriel, après ton accord (l'adresse est envoyée au service).
- Qui parle à Internet ? : les connexions en cours de chaque programme, avec le nom du serveur ; un programme lancé
  depuis un dossier temporaire ou les Téléchargements, un port de logiciel d'accès à distance ou un serveur sans nom
  sont signalés. Lecture seule : rien n'est coupé.
- Quelqu'un contrôle mon ordi ? : l'arnaque au faux technicien (« votre ordinateur est infecté ») fait installer un
  logiciel de prise de contrôle à distance. Gardien cherche AnyDesk, TeamViewer, RustDesk, Assistance rapide,
  Splashtop, UltraViewer… installés (et depuis quand), lancés au démarrage, en cours d'exécution ou simplement posés
  dans Téléchargements ; il explique quoi faire (couper Internet, prévenir la banque, changer les mots de passe) et
  les retire après accord. Un programme en cours n'est jamais coupé sans un second accord exprès : la personne qui
  aide peut être connectée par lui. Au bilan aussi (« Accès à distance »).
- Ce lien est-il dangereux ? : un lien reçu examiné sans jamais l'ouvrir (lettres déguisées, sous-domaine trompeur,
  marque imitée, raccourcisseur, adresse IP brute) ; après accord, l'âge du domaine et trois listes publiques de
  sites dangereux (URLhaus, Spamhaus, SURBL). Seul le nom du domaine sort de l'ordinateur.
- Vérifier Gardien lui-même : sa version, la date de son dernier commit et son empreinte SHA-256, à comparer à la
  page de la version (Gardien n'est pas signé : c'est cette comparaison qui prouve qu'il est bien lui). Une copie de
  plus de six mois le dit au menu. Et le manifeste de la clé : au déploiement, l'empreinte de chaque fichier de la
  clé est gardée sur ton ordinateur ; au retour de chez quelqu'un, le bilan nomme ce qui a été ajouté, remplacé ou
  retiré (un autorun planté, un programme remplacé). Les données, les images ISO et le menu Ventoy, qui changent
  normalement, ne sont pas comparés. Chaque clé a sa référence (reconnue par l'identifiant de son volume) : une
  deuxième clé GARDIEN ne passe pas pour une clé modifiée.
- Gardien se méfie aussi de lui-même : au démarrage, il dit si une bibliothèque est injectée dans tous les
  programmes de la session (LD_PRELOAD, DYLD_INSERT_LIBRARIES, AppInit_DLLs : celle d'un paquet du système, comme
  GameMode, est une simple information) et s'il tourne en root sans raison, car ses résultats passent par là. Au
  bilan : la surveillance horaire que tu avais activée et qui a disparu (un logiciel malveillant coupe d'abord ce
  qui le surveille), et l'historique des bilans réécrit après coup (chaque bilan porte l'empreinte du précédent).
  Chaque nuit, la CI recompile Gardien deux fois et vérifie que le programme est identique à l'octet près.
- Vérifier un fichier téléchargé : son empreinte comparée à celle que publie le site (collée, ou un SHA256SUMS posé
  à côté), son nom et son contenu (double extension, programme déguisé en document), puis YARA et l'antivirus.
- Surveillance toutes les heures : notification si un appareil inconnu arrive, si un port s'ouvre, si la note de
  la machine baisse, si la box semble usurpée (adresse MAC partagée ou changée : usurpation ARP), ou si un
  programme ou un fichier déguisé arrive dans Téléchargements (à vérifier avant de l'ouvrir ; rien n'est bloqué).
- Entretien du mois : une notification par mois avec la note de la machine, les mises à jour en attente, la place
  que le nettoyage libérerait et les problèmes nouveaux ; rien n'est changé.
- Rapport HTML avec la courbe des notes, et ce qui a changé depuis le bilan précédent.
- Gaming : sous Windows, composants pour les jeux et réglages de Windows ; sous Linux, Steam, pilotes Vulkan 32 et
  64 bits selon la carte, GameMode, MangoHud, Gamescope, Wine, Lutris, Heroic, ProtonUp-Qt, vm.max_map_count, ntsync ;
  sous macOS, Rosetta 2, Steam, Heroic, Epic Games, GOG Galaxy, Prism Launcher et le compteur d'images de Metal.

</details>

Gardien ne coupe jamais une connexion à distance en cours (Bureau à distance, SSH). À n'utiliser que sur ton propre
réseau, ou un réseau que tu as le droit d'auditer.

## En images

<table>
  <tr>
    <td width="50%"><img src="assets/captures/menu.png" alt="Menu de Gardien"><br><sub>Le menu : dernier bilan,
    connexion, clé branchée.</sub></td>
    <td width="50%"><img src="assets/captures/rapport.png" alt="Rapport HTML de Gardien"><br><sub>Le rapport HTML et
    l'évolution des notes.</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="assets/captures/reseau.png" alt="Scan du réseau local"><br><sub>Le réseau : chaque
    appareil, ses ports et ce qu'il faut regarder.</sub></td>
    <td width="50%"><img src="assets/captures/connexion.png" alt="Test de connexion pour le jeu"><br><sub>La connexion
    pour le jeu : ping, gigue, débit, bufferbloat.</sub></td>
  </tr>
</table>

<sub>Captures refaites à chaque version, sur une copie des données ; les adresses et les noms de la maison y sont
masqués.</sub>

## Systèmes pris en charge

| Système | Versions |
|---|---|
| Windows | 10 et 11 |
| macOS | 12 et plus récents, Apple Silicon et Intel (testé sur les Mac de GitHub, pas encore sur un vrai Mac) |
| Linux | Arch et dérivées (Omarchy, Manjaro, EndeavourOS, CachyOS), Debian, Ubuntu, Mint, Pop!_OS, Fedora (et RHEL, Rocky, Nobara), openSUSE |
| Linux atomique | Bazzite, Silverblue, Kinoite, Bluefin, Aeon |

Gardien reconnaît la distribution et propose ses propres commandes : `omarchy update` / `omarchy pkg add` sous
Omarchy, `ujust update` sur Bazzite, `rpm-ostree` ou `transactional-update` sur un système atomique, sinon pacman,
apt, dnf ou zypper.

## Commandes

Chaque entrée du menu existe aussi en commande.

<details>
<summary><b>Toutes les commandes</b></summary>

| Commande | Rôle |
|---|---|
| `gardien complet [--html] [--texte]` | bilan complet : machine + réseau ; `--texte` l'affiche en texte simple (mode urgence) |
| `gardien corriger` | corriger les problèmes trouvés |
| `gardien machine [--json]` | audit de cette machine |
| `gardien reseau [cible] [-p courants\|tous\|22,80,8000-8100] [--json]` | scan du réseau ou d'un appareil |
| `gardien connexion` | test de connexion pour le jeu |
| `gardien nettoyer [--liste]` | nettoyer le système ; `--liste` : la place à gagner, sans rien effacer |
| `gardien logiciels [--liste] [--recommandes]` | logiciels à installer par catégorie ; `--liste` : leur état, sans rien installer |
| `gardien diagnostic` | diagnostic de l'ordinateur : matériel, système, plantages et erreurs récents |
| `gardien depanner [sujet]` | dépanner pas à pas : `internet`, `wifi`, `lent`, `son`, `imprimante`, `disque`, `infection`, `nouveau`, `depart` |
| `gardien lenteur` | pourquoi c'est lent : processeur, mémoire, disque, démarrage, programmes à l'ouverture |
| `gardien demarrage` | programmes au démarrage : les retirer ou les remettre, après accord ; chaque retrait s'annule |
| `gardien fiche [--json]` | fiche de l'ordinateur ; `--json` sans les numéros de série |
| `gardien copier-fichiers [destination]` | copier mes fichiers vers un disque externe, copie vérifiée |
| `gardien verifier-copie [dossier]` | vérifier une copie : relue sur le disque et comparée aux originaux (test de restauration) |
| `gardien antivirus [--complet] [dossier]` | analyse antivirus (ordinateur, ou une clé / un dossier) |
| `gardien yara [--complet] [dossier]` | analyse YARA : 308 règles de familles de logiciels malveillants |
| `gardien pieges [--retirer]` | fichiers-pièges contre les rançongiciels : les poser, les vérifier, les retirer |
| `gardien durcir` | blocages de Windows Defender : règles ASR, protection réseau, logiciels indésirables, accès contrôlé aux dossiers ; chacun après accord, annulable (Windows) |
| `gardien listes-noires` | l'adresse Internet de la maison sur liste noire ? (après accord) |
| `gardien canaux` | Wi-Fi encombré : les réseaux voisins par canal, et le canal le plus libre |
| `gardien nat` | type de NAT pour le jeu : ouvert, modéré ou strict |
| `gardien cameras` | caméras cachées sur le réseau (location, chez quelqu'un) |
| `gardien dns-rapide` | DNS le plus rapide, mesuré ici et annulable ; un DNS qui protège est gardé |
| `gardien appris` | ce que Gardien a appris : tes habitudes, tes choix, et les oublier |
| `gardien motdepasse` | mots de passe fuités |
| `gardien isoler <fichier>` | lancer un programme inconnu dans un bac à sable (bubblewrap ou firejail, Windows Sandbox) |
| `gardien courriel` | fuites d'adresse courriel (XposedOrNot, ou Have I Been Pwned avec `GARDIEN_HIBP_CLE`) |
| `gardien sortantes` | qui parle à Internet : les connexions de chaque programme (lecture seule) |
| `gardien verifier-moi` | vérifier Gardien lui-même : version, date de compilation, empreinte SHA-256 à comparer à la page de la version ; sur la clé du propriétaire, le manifeste de la clé |
| `gardien camera-micro` | caméra et micro : qui s'en sert ? (lecture seule) |
| `gardien quarantaine` | les fichiers isolés, à remettre à leur place ou à supprimer |
| `gardien distance` | quelqu'un contrôle mon ordi ? logiciels de prise de contrôle à distance (faux technicien), retrait après accord |
| `gardien lien <adresse>` | ce lien est-il dangereux ? (examiné sans l'ouvrir ; en ligne après accord) |
| `gardien verifier-fichier <fichier> [empreinte]` | vérifier un fichier téléchargé : empreinte, nom et contenu, YARA, antivirus |
| `gardien integrite [--accepter] [--temps-reel]` | intégrité des fichiers critiques (empreintes BLAKE3), en direct possible |
| `gardien maj` | mises à jour |
| `gardien reparer` | réparations et nettoyage |
| `gardien surveillance on\|off` | surveillance horaire |
| `gardien entretien [on\|off]` | entretien du mois ; sans argument : ce qu'il dirait maintenant |
| `gardien nommer <ip\|mac> <surnom>` | nommer un appareil |
| `gardien sauvegarder [fichier]`, `gardien restaurer <fichier>` | sauvegarde des données |
| `gardien gaming` | paquets et réglages pour jouer (Windows et Linux) |
| `gardien guide [système\|programme\|mots]` | guide des commandes : un système (`linux`, `windows`, `macos`, `tous`), un programme (`winget`, `systemctl`…) ou des mots à chercher (`cache dns`) |

</details>

**Langue** : celle du système (français ou anglais). Pour forcer : `GARDIEN_LANG=fr` ou `GARDIEN_LANG=en`. Les
commandes ont aussi un nom anglais (`full`, `audit`, `fix`, `network`, `connection`, `apps`, `diag`, `password`,
`sandbox`, `email`, `integrity`, `update`, `repair`, `monitor`, `name`, `backup`, `restore`, `clean`, `decoys`, `harden`,
`blocklists`, `learned`, `channels`, `fast-dns`, `outbound`, `link`, `check-file`, `maintenance`, `slow`,
`startup`, `specs`, `copy-files`, `troubleshoot`).

**Emojis** : dans l'ancienne console de Windows (invite de commandes ou PowerShell hors du Terminal Windows, courant
sous Windows 10), qui les dessine mal et décale les menus, 💡 et 🔧 deviennent → et +. `GARDIEN_EMOJI=0` les retire
partout, `GARDIEN_EMOJI=1` les garde partout.

## Développer

Compiler, tester, déployer, la clé USB, le journal des erreurs : voir [CONTRIBUTING.md](CONTRIBUTING.md).
Une faille de sécurité dans Gardien ? Signale-la en privé : voir [SECURITY.md](SECURITY.md).

## Licence

© 2026 d9v3. Gardien est un logiciel libre : tu peux le redistribuer et le modifier selon les termes de la
[licence publique générale GNU](LICENSE) (GPL), version 3 ou toute version ultérieure. Il est fourni sans aucune
garantie. Une version modifiée que tu distribues doit rester sous cette licence, avec son code source.

Les bibliothèques incluses gardent leurs propres licences (MIT, Apache-2.0, BSD, ISC…) : voir `LICENCES-TIERCES.txt`.
