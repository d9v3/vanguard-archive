# Sécurité

**Français** · [English](#security)

Vanguard protège des ordinateurs : une faille dans Vanguard lui-même toucherait ceux qui l'utilisent. Si tu en trouves
une, **ne l'écris pas dans un ticket public**.

## Signaler une faille

Signale-la en privé, depuis l'onglet **Security** du dépôt, bouton **Report a vulnerability** : seuls le mainteneur
et toi voyez le signalement, aucun courriel n'est échangé. Indique :

- ce que tu as trouvé, et ce qu'un attaquant pourrait en faire ;
- comment le reproduire (étapes, commandes, fichiers) ;
- le système (Linux et sa distribution, Windows, macOS) et la version de Vanguard (`vanguard --version`).

La correction part dans une nouvelle version (page Releases), avec ton nom dans les notes si tu le souhaites. Merci
de garder le secret jusque-là.

## Versions suivies

Seule la dernière version reçoit les corrections de sécurité : mets Vanguard à jour avant de signaler.

## Ce qui compte

- Vanguard qui affaiblit la sécurité : une correction qui coupe une protection, un réglage qui ne s'annule pas
  exactement, une commande lancée sans ton accord.
- Une injection de commande (shell, PowerShell) par un nom de fichier, un nom d'appareil, une réponse du réseau ou
  le contenu d'un fichier lu par Vanguard.
- La clé USB : protection en écriture contournée, programme de la clé remplacé ou lancé à la place d'un autre.
- Une fuite de données personnelles : journal des erreurs, rapport, captures, tickets.

Ne sont pas des failles : les problèmes que Vanguard trouve sur ton ordinateur (c'est son travail, le bilan les
explique), ni l'avertissement de SmartScreen ou d'un antivirus sur le programme, qui n'est pas signé.

---

# Security

[Français](#sécurité) · **English**

Vanguard protects computers: a flaw in Vanguard itself would hit the people who use it. If you find one, **do not
write it in a public issue**.

## Reporting a vulnerability

Report it privately, from the repository's **Security** tab, **Report a vulnerability** button: only the maintainer
and you see the report, no email is exchanged. Please include:

- what you found, and what an attacker could do with it;
- how to reproduce it (steps, commands, files);
- the system (Linux and its distribution, Windows, macOS) and Vanguard's version (`vanguard --version`).

The fix ships in a new version (Releases page), with your name in the notes if you wish. Please keep the issue secret
until then.

## Supported versions

Only the latest version receives security fixes: update Vanguard before reporting.

## What counts

- Vanguard weakening security: a fix that turns a protection off, a setting that cannot be undone exactly, a command
  run without your consent.
- Command injection (shell, PowerShell) through a file name, a device name, a network answer or the content of a
  file Vanguard reads.
- The USB key: write protection bypassed, the key's program replaced or run instead of another one.
- A personal data leak: error journal, report, screenshots, issues.

Not vulnerabilities: the problems Vanguard finds on your computer (that is its job, the check explains them), or the
SmartScreen or antivirus warning about the program, which is not signed.
