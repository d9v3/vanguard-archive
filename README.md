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
  complémentaires » puis « Exécuter quand même »).
- **Linux** : `chmod +x gardien-linux-x86_64`, puis `./gardien-linux-x86_64` dans un terminal (toutes les
  distributions, rien à installer).
- **macOS** : copié depuis Internet, le programme est bloqué la première fois : `xattr -d com.apple.quarantine
  gardien-macos`, puis `./gardien-macos` dans le Terminal.
- **Depuis la clé USB** : `Windows/gardien.exe`, `Linux/gardien`, ou `Lancer Gardien.command` sous macOS ; le guide
  de la clé est dans `LISEZMOI.txt`.

Dans le menu, choisis **1** (bilan complet), puis **2** (corriger). Les flèches, Entrée, et Échap ou Retour arrière
pour revenir.

> Gardien s'appelait Sentinel jusqu'à la version 0.50 : la commande `sentinel` lance toujours Gardien, et ses données,
> sa surveillance et sa clé sont reprises telles quelles.

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

## Ce que fait Gardien

**Bilan de sécurité** — une note de A à F, puis chaque problème avec sa correction.
- Pare-feu, ports ouverts (TCP et UDP), mises à jour et failles connues, chiffrement du disque, Secure Boot,
  verrouillage de l'écran, comptes, SSH (et ses tentatives de connexion ratées, venues d'Internet ou de la maison),
  sudo, groupes qui valent root (docker, lxd, libvirt, disk), durcissement du noyau (sous macOS : volume du système scellé,
  signature du code imposée, validation des bibliothèques, extensions ajoutées), fichiers secrets mal protégés,
  sauvegardes.
- Ce qui se cache : programmes lancés au démarrage, tâches planifiées, préchargement de bibliothèques, programmes
  privilégiés modifiés.
- DNS réellement utilisé (et réponses inventées), certificats racine ajoutés (interception du HTTPS), extensions de
  navigateur qui lisent tous les sites.
- Wi-Fi : protection du réseau (WEP, WPA2, WPA3), et faux point d'accès (« jumeau maléfique ») qui copie son nom
  sans mot de passe pour attirer les appareils.
- Santé : espace disque, état SMART des disques (sans root), batterie, températures.
- Ce qui n'a pas pu être vérifié est dit, jamais compté comme sain.

**Réseau local** — tous les appareils, leur fabricant, leurs ports ouverts (TCP, et UDP : SNMP, NetBIOS, UPnP, DNS,
mDNS) et leurs risques ; les nouveaux venus signalés, un carnet par réseau (chez toi, chez chaque ami), des surnoms
(« imprimante HP ») ; les ports que des appareils ont ouverts vers Internet sur la box par UPnP (lecture seule, avec
miniupnpc sous Linux). Après accord, l'adresse Internet de la maison est cherchée dans quatre listes noires
(Spamhaus, SpamCop, DroneBL, PSBL) : listée pour pourriel ou attaques, un appareil est sans doute infecté.

**Connexion pour le jeu** — ping, gigue, pertes, débit et bufferbloat (le lag quand quelqu'un télécharge), avec un
verdict critère par critère et des conseils.

**Diagnostic de l'ordinateur** — le premier réflexe d'un dépannage : matériel, système, et les problèmes récents
(erreurs du journal et programmes plantés sous Linux ; écrans bleus, arrêts brutaux et plantages sous Windows ;
paniques du noyau et rapports de plantage sous macOS), avec une copie texte enregistrée sur la clé.

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
l'antivirus.

**Apprentissage** — Gardien apprend sur ton ordinateur, sans rien envoyer. Une alerte que tu déclares normale chez
toi (« i » à la correction) passe au niveau info pendant 90 jours, ou jusqu'à ce qu'elle s'aggrave ; chaque test de
connexion se compare à tes habitudes sur le même réseau ; un appareil connu qui paraît soudain tout fermé (en
veille) est revérifié plus patiemment. « Ce que Gardien a appris » montre tout et permet d'oublier.

**Guide des commandes** — les commandes utiles de Linux, de Windows, de macOS et celles qui s'écrivent pareil
partout (Gardien, ping, nslookup, ssh, curl, git…), rangées par système puis par programme, chacune expliquée ; ⚠
marque celles qui changent quelque chose. Rien ne s'y lance : on lit, puis on tape la commande, ici ou chez la
personne qu'on aide. Tous les systèmes sont lisibles partout (les commandes de Windows depuis Linux, par exemple), et
le guide dit si un programme manque sur cet ordinateur.

**Et aussi**
- Recherche dans tous les menus : tape un mot (wifi, disque, dns, mise à jour…), seules les lignes qui le
  contiennent restent, sans souci d'accents ni de majuscules ; au menu principal, elle trouve aussi chaque outil des
  sous-menus et chaque page du guide.
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
- Surveillance toutes les heures : notification si un appareil inconnu arrive, si un port s'ouvre, si la note de
  la machine baisse, ou si la box semble usurpée (adresse MAC partagée ou changée : usurpation ARP).
- Entretien du mois : une notification par mois avec la note de la machine, les mises à jour en attente, la place
  que le nettoyage libérerait et les problèmes nouveaux ; rien n'est changé.
- Alertes sur le téléphone, par ntfy (après accord) : la surveillance et l'entretien préviennent aussi ton
  téléphone. Le sujet est tiré au hasard, les messages ne contiennent jamais d'adresse IP ni MAC.
- Rapport HTML avec la courbe des notes, et ce qui a changé depuis le bilan précédent.
- Gaming : sous Windows, composants pour les jeux et réglages de Windows ; sous Linux, Steam, pilotes Vulkan 32 et
  64 bits selon la carte, GameMode, MangoHud, Gamescope, Wine, Lutris, Heroic, ProtonUp-Qt, vm.max_map_count, ntsync ;
  sous macOS, Rosetta 2, Steam, Heroic, Epic Games, GOG Galaxy, Prism Launcher et le compteur d'images de Metal.

Gardien ne coupe jamais une connexion à distance en cours (Bureau à distance, SSH). À n'utiliser que sur ton propre
réseau, ou un réseau que tu as le droit d'auditer.

## Commandes

Chaque entrée du menu existe aussi en commande :

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
| `gardien antivirus [--complet] [dossier]` | analyse antivirus (ordinateur, ou une clé / un dossier) |
| `gardien yara [--complet] [dossier]` | analyse YARA : 308 règles de familles de logiciels malveillants |
| `gardien pieges [--retirer]` | fichiers-pièges contre les rançongiciels : les poser, les vérifier, les retirer |
| `gardien listes-noires` | l'adresse Internet de la maison sur liste noire ? (après accord) |
| `gardien appris` | ce que Gardien a appris : tes habitudes, tes choix, et les oublier |
| `gardien motdepasse` | mots de passe fuités |
| `gardien isoler <fichier>` | lancer un programme inconnu dans un bac à sable (bubblewrap ou firejail, Windows Sandbox) |
| `gardien courriel` | fuites d'adresse courriel (XposedOrNot, ou Have I Been Pwned avec `GARDIEN_HIBP_CLE`) |
| `gardien integrite [--accepter] [--temps-reel]` | intégrité des fichiers critiques (empreintes BLAKE3), en direct possible |
| `gardien maj` | mises à jour |
| `gardien reparer` | réparations et nettoyage |
| `gardien surveillance on\|off` | surveillance horaire |
| `gardien entretien [on\|off]` | entretien du mois ; sans argument : ce qu'il dirait maintenant |
| `gardien alertes [on\|off\|essai]` | alertes sur le téléphone (ntfy) ; sans argument : le menu |
| `gardien nommer <ip\|mac> <surnom>` | nommer un appareil |
| `gardien sauvegarder [fichier]`, `gardien restaurer <fichier>` | sauvegarde des données |
| `gardien gaming` | paquets et réglages pour jouer (Windows et Linux) |
| `gardien guide [système\|programme\|mots]` | guide des commandes : un système (`linux`, `windows`, `macos`, `tous`), un programme (`winget`, `systemctl`…) ou des mots à chercher (`cache dns`) |

**Langue** : celle du système (français ou anglais). Pour forcer : `GARDIEN_LANG=fr` ou `GARDIEN_LANG=en`. Les
commandes ont aussi un nom anglais (`full`, `audit`, `fix`, `network`, `connection`, `apps`, `diag`, `password`,
`sandbox`, `email`, `integrity`, `update`, `repair`, `monitor`, `name`, `backup`, `restore`, `clean`, `decoys`,
`blocklists`, `learned`).

## Développer

Compiler, tester, déployer, la clé USB, le journal des erreurs : voir [CONTRIBUTING.md](CONTRIBUTING.md).
Une faille de sécurité dans Gardien ? Signale-la en privé : voir [SECURITY.md](SECURITY.md).

## Licence

© 2026 d9v3. Gardien est un logiciel libre : tu peux le redistribuer et le modifier selon les termes de la
[licence publique générale GNU](LICENSE) (GPL), version 3 ou toute version ultérieure. Il est fourni sans aucune
garantie. Une version modifiée que tu distribues doit rester sous cette licence, avec son code source.

Les bibliothèques incluses gardent leurs propres licences (MIT, Apache-2.0, BSD, ISC…) : voir `LICENCES-TIERCES.txt`.
