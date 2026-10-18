#!/usr/bin/env python3
"""Captures d'écran du README (assets/captures/, en français et en anglais) et image de partage du dépôt
(assets/partage.png). outils/deployer.sh les refait à chaque nouvelle version : le menu montre le numéro de version,
une image d'une version passée se verrait.

Gardien tourne pour de vrai : dans un pseudo-terminal de 80 colonnes (pyte relit l'écran comme un terminal), depuis
une fausse clé USB, sur une copie des données. Rien de vrai n'est touché : autre USER (la vraie clé et sa partition
du journal sont cherchées dans /run/media/$USER), XDG_DATA_HOME jetable, pas de bus de session (systemctl --user et
les notifications échouent sans rien faire), faux xdg-open (le rapport ne s'ouvre pas).

Ce qui identifierait la maison est remplacé avant chaque image, tiré au hasard à chaque passe : adresses MAC (le
préfixe du fabricant, déjà écrit en clair à côté, est gardé), adresses IP (un réseau inventé, le même dans toutes les
images ; longueurs et ordre gardés, les tableaux restent alignés et triés), nom du réseau, noms des appareils, compte
et dossiers de l'utilisateur. Du bilan de la machine, seul un extrait est montré (catégories sans rien de personnel :
pas le Wi-Fi, les extensions, les services ajoutés à la main…), les coupures marquées « ⋮ ». Enfin le garde-fou du
dépôt (outils/confidentialite.py) relit chaque image : si un détail personnel reste visible, aucune n'est écrite.

Depuis la racine du dépôt :
    uv run --no-project --with pyte python outils/captures.py [programme gardien] [--connexion]
--connexion refait aussi le test de connexion (quelques centaines de Mo) ; sans lui, seulement si l'image manque ou si
src/connexion.rs, src/ui.rs, src/langue.rs ou ce script ont changé depuis. --sans-connexion ne le refait jamais.
"""

import html
import ipaddress
import json
import os
import pty
import random
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pyte

sys.path.insert(0, str(Path(__file__).resolve().parent))
import confidentialite as conf  # noqa: E402

COLONNES = 80
RANGEES = 400
DOSSIER = Path("assets/captures")
PARTAGE = Path("assets/partage.png")
NOM_RESEAU = "Salon"

# Palette du terminal des captures (celle de VS Code, déjà utilisée par les captures d'avant) : codes 16 couleurs ;
# les codes 256 couleurs arrivent de pyte en hexadécimal.
PALETTE = {
    "default": "#d0d0d0", "black": "#000000", "red": "#cd3131", "green": "#0dbc79", "brown": "#e5e510",
    "blue": "#2472c8", "magenta": "#bc3fbc", "cyan": "#11a8cd", "white": "#e5e5e5",
    "brightblack": "#666666", "brightred": "#f14c4c", "brightgreen": "#23d18b", "brightbrown": "#f5f543",
    "brightblue": "#3b8eea", "brightmagenta": "#d670d6", "brightcyan": "#29b8db", "brightwhite": "#ffffff",
}

# Catégories du bilan qu'on peut montrer : rien de personnel dedans. Les autres (Wi-Fi et son nom, extensions,
# services ajoutés à la main, comptes, sudo…) ne paraissent jamais. Français, puis anglais.
CATEGORIES_MONTREES = {
    "Pare-feu", "Ports en écoute", "Mises à jour", "Failles connues", "Noyau", "Chiffrement", "Verrouillage",
    "Noyau durci", "AppArmor/SELinux", "Sauvegardes", "Secure Boot", "DNS", "Certificats", "Santé", "Intégrité",
    "Firewall", "Listening ports", "Updates", "Known flaws", "Kernel", "Encryption", "Screen lock",
    "Kernel hardening", "Backups", "Certificates", "Health", "Integrity",
}
ENTREES_MAX = 12
MARQUES = ("✔", "ℹ", "✖", "⚠", "✘", "?")
PROBLEMES = ("✖", "⚠", "✘")
# Symboles que le terminal dessine comme du texte, d'une colonne et dans la couleur demandée : le navigateur, lui,
# en ferait des emoji de deux colonnes, qui mordraient sur le mot suivant.
SYMBOLES_TEXTE = set("✔✖ℹ⚠✘✓✗☐☑")
SUITE = {"fr": "  ⋮ et {} autres vérifications, pas montrées ici", "en": "  ⋮ and {} more checks, not shown here"}
# Ce que le garde-fou connaît comme simple texte : remplacé dans les images (les adresses ont leur propre masque).
REMPLACABLES = {"liste privée", "identité Git de l'ordinateur", "nom complet du compte", "nom de l'ordinateur",
                "appareil ou réseau de la maison"}

IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
IPV6 = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
# Valeurs d'un octet selon leur nombre de chiffres : un remplaçant garde la longueur de l'original.
OCTETS = {1: range(0, 10), 2: range(10, 100), 3: range(100, 256)}
# Réseau, box et diffusion : les mêmes chez tout le monde, gardés.
HOTES_FIXES = {0, 1, 254, 255}
LOCAUX = [ipaddress.ip_network(n) for n in
          ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10")]
# Services DNS publics connus (fournisseur() de src/machine/dns.rs) : les mêmes pour tout le monde, gardés.
RESOLVEURS = [ipaddress.ip_network(n) for n in (
    "1.1.1.0/24", "1.0.0.0/24", "8.8.8.8/32", "8.8.4.4/32", "9.9.9.0/24", "149.112.112.0/24", "208.67.222.0/24",
    "208.67.220.0/24", "45.90.28.0/24", "45.90.30.0/24", "94.140.14.0/24", "94.140.15.0/24", "194.242.2.0/24",
    "185.228.168.0/24", "185.228.169.0/24", "76.76.2.0/24", "76.76.10.0/24", "100.100.100.100/32",
    "2606:4700::/32", "2001:4860::/32", "2620:fe::/32", "2620:119::/32", "2a07:a8c0::/32", "2a07:a8c1::/32",
    "2a10:50c0::/32", "2a07:e340::/32")]
# Adresses réservées à la documentation (RFC 5737, RFC 3849) : elles remplacent les adresses publiques.
DOCUMENTATION = ("192.0.2.", "203.0.113.", "198.51.100.")
DOC6 = ipaddress.ip_network("2001:db8::/32")


# --- Bac à sable ---------------------------------------------------------------------------------------------------

def preparer_bac(programme: Path, bac: Path):
    """Fausse clé (programme dans Linux/, témoin vide : jamais protégée) et données copiées. Le réseau prend un nom
    passe-partout ; les surnoms qui pourraient nommer quelqu'un sont retirés."""
    local, cle = conf.dossiers_gardien()
    (bac / "cle/Linux").mkdir(parents=True)
    (bac / "cle/donnees").mkdir()
    (bac / "donnees/gardien").mkdir(parents=True)
    (bac / "run").mkdir()
    (bac / "bin").mkdir()
    shutil.copy(programme, bac / "cle/Linux/gardien")
    (bac / "cle/gardien.cle").write_text("")
    if local:
        for f in local.glob("*.json"):
            shutil.copy(f, bac / "donnees/gardien" / f.name)
    # Gardien lit la base de la clé et celle de l'ordinateur : les deux copies sont rendues passe-partout.
    source = next((d / "appareils.json" for d in (cle, local) if d and (d / "appareils.json").is_file()), None)
    for copie in (bac / "cle/donnees/appareils.json", bac / "donnees/gardien/appareils.json"):
        depart = copie if copie.is_file() else source
        if not depart:
            continue
        base = json.loads(depart.read_text())
        for reseau in base.get("reseaux", {}).values():
            reseau["nom"] = NOM_RESEAU
            for appareil in reseau.get("appareils", {}).values():
                if appareil.get("surnom") and not conf.generique(appareil["surnom"]):
                    appareil["surnom"] = None
        copie.write_text(json.dumps(base, ensure_ascii=False))
    xdg_open = bac / "bin/xdg-open"
    xdg_open.write_text("#!/bin/sh\nexit 0\n")
    xdg_open.chmod(0o755)
    # Le nom du réseau vient du Wi-Fi (nmcli), à chaque scan : un faux nmcli répond comme le vrai, nom du Wi-Fi
    # remplacé.
    vrai = shutil.which("nmcli")
    if vrai:
        noms = sorted(reseaux_wifi() | conf.reseaux_enregistres()[0], key=len, reverse=True)
        faux = bac / "bin/nmcli"
        faux.write_text(
            f"#!{sys.executable}\nimport subprocess, sys\n"
            f"r = subprocess.run([{vrai!r}, *sys.argv[1:]], capture_output=True, text=True)\n"
            f"sortie = r.stdout\nfor nom in {noms!r}:\n"
            f"    sortie = sortie.replace(nom, {NOM_RESEAU!r})\n"
            "sys.stdout.write(sortie)\nsys.stderr.write(r.stderr)\nsys.exit(r.returncode)\n"
        )
        faux.chmod(0o755)


def reseaux_wifi():
    """Noms des réseaux Wi-Fi enregistrés et visibles."""
    noms = set()
    for args in (["-t", "-f", "NAME,TYPE", "connection", "show"], ["-t", "-e", "no", "-f", "SSID", "dev", "wifi"]):
        for ligne in conf.nmcli(*args).splitlines():
            nom, _, genre = ligne.rpartition(":") if "connection" in args else (ligne, "", "wireless")
            if nom and "wireless" in genre:
                noms.add(nom)
    return {n for n in noms if len(n) >= 2}


def environnement(bac: Path, langue: str):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GARDIEN_", "SENTINEL_", "NETSCAN_"))}
    env.update(
        USER="capture",
        XDG_DATA_HOME=str(bac / "donnees"),
        XDG_RUNTIME_DIR=str(bac / "run"),
        DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent",
        PATH=f"{bac / 'bin'}:{os.environ['PATH']}",
        GARDIEN_LANG=langue,
        TERM="xterm-256color",
        COLUMNS=str(COLONNES),
        LINES=str(RANGEES),
    )
    return env


def lancer(exe: Path, args, env, attendre=None, touches=b"", delai=240):
    """Lance gardien dans un pseudo-terminal et rend l'écran. `attendre` : texte qui doit paraître avant de taper
    `touches` (l'écran est pris juste avant) ; sinon on attend la fin du programme."""
    pid, fd = pty.fork()
    if pid == 0:
        import fcntl
        import termios

        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", RANGEES, COLONNES, 0, 0))
        os.chdir("/")
        os.execve(str(exe), [str(exe), *args], env)
    ecran = pyte.Screen(COLONNES, RANGEES)
    flux = pyte.ByteStream(ecran)
    fin = time.time() + delai
    photo = None
    while time.time() < fin:
        prets, _, _ = select.select([fd], [], [], 0.2)
        if prets:
            try:
                morceau = os.read(fd, 65536)
            except OSError:
                break
            if not morceau:
                break
            flux.feed(morceau)
        if attendre and photo is None and any(attendre in ligne for ligne in ecran.display):
            time.sleep(0.5)  # le menu finit de se dessiner
            while select.select([fd], [], [], 0.2)[0]:
                try:
                    flux.feed(os.read(fd, 65536))
                except OSError:
                    break
            photo = cellules(ecran)
            os.write(fd, touches)
    else:
        os.kill(pid, 9)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    os.close(fd)
    if attendre and photo is None:
        raise SystemExit(f"captures : « {attendre} » n'a jamais paru (gardien {' '.join(args)})")
    return photo if photo is not None else cellules(ecran)


def cellules(ecran):
    """Écran → rangées de cellules (texte, couleur, gras), sans les rangées vides de la fin."""
    rangees = []
    for y in range(ecran.lines):
        ligne = ecran.buffer[y]
        rangees.append([(ligne[x].data, ligne[x].fg, ligne[x].bold) for x in range(ecran.columns)])
    while rangees and not texte(rangees[-1]).strip():
        rangees.pop()
    return rangees


def texte(rangee):
    return "".join(c[0] for c in rangee)


# --- Ce qui ne doit pas paraître -----------------------------------------------------------------------------------

class Masque:
    """Remplaçants des adresses de la maison, pour une passe. Tirés au hasard : un remplaçant calculé sans secret
    (empreinte de l'adresse) se retrouverait en essayant toutes les adresses possibles, 2²⁴ par fabricant pour une
    adresse MAC. Chacun a la longueur de l'original : les tableaux restent alignés."""

    def __init__(self, textes):
        self.hasard = random.SystemRandom()
        self.adresses = {}  # vraie adresse (MAC, IPv4, IPv6) → remplaçant
        self.reseaux = {}  # trois premiers octets d'un réseau local → ceux du réseau inventé
        locales = {a for t in textes for a in IPV4.findall(t) if self.locale(a)}
        self.reels = {a.rsplit(".", 1)[0] for a in locales}
        # Tous les hôtes d'un réseau sont tirés ensemble, dans l'ordre : un tableau trié par adresse le reste.
        for prefixe in sorted(self.reels):
            self.reseau(prefixe, sorted({int(a.rsplit(".", 1)[1]) for a in locales if a.startswith(prefixe + ".")}))

    @staticmethod
    def locale(adresse):
        try:
            ip = ipaddress.IPv4Address(adresse)
        except ValueError:
            return False
        return any(ip in r for r in LOCAUX) and not any(ip in r for r in RESOLVEURS)

    def reseau(self, prefixe, hotes):
        """Réseau inventé de la même sorte (10.x.y, 172.16-31.y, 192.168.y…), puis ses hôtes : même nombre de
        chiffres, même ordre, réseau, box et diffusion gardés."""
        if prefixe not in self.reseaux:
            o1, o2, o3 = prefixe.split(".")
            if o1 == "10":
                deuxiemes = OCTETS[len(o2)]
            elif o1 == "172":
                deuxiemes = range(16, 32)
            elif o1 == "100":
                deuxiemes = [x for x in range(64, 128) if len(str(x)) == len(o2)]
            else:  # 192.168, 169.254
                deuxiemes = [int(o2)]
            pris = self.reels | set(self.reseaux.values())
            libres = [f"{o1}.{a}.{b}" for a in deuxiemes for b in OCTETS[len(o3)] if f"{o1}.{a}.{b}" not in pris]
            self.reseaux[prefixe] = self.hasard.choice(libres)
        faux = self.reseaux[prefixe]
        deja = {int(v.rsplit(".", 1)[1]) for k, v in self.adresses.items() if k.startswith(prefixe + ".")}
        for chiffres, valeurs in OCTETS.items():
            a_tirer = [h for h in hotes if h not in HOTES_FIXES and len(str(h)) == chiffres]
            choix = sorted(self.hasard.sample([v for v in valeurs if v not in HOTES_FIXES | deja], len(a_tirer)))
            for reel, neuf in zip(a_tirer, choix):
                self.adresses[f"{prefixe}.{reel}"] = f"{faux}.{neuf}"
        for h in hotes:
            if h in HOTES_FIXES:
                self.adresses[f"{prefixe}.{h}"] = f"{faux}.{h}"

    def ipv4(self, adresse):
        if adresse in self.adresses:
            return self.adresses[adresse]
        try:
            ip = ipaddress.IPv4Address(adresse)
        except ValueError:
            return adresse
        if self.locale(adresse):
            prefixe, hote = adresse.rsplit(".", 1)
            self.reseau(prefixe, [int(hote)])
        elif not ip.is_global or ip.is_multicast or any(ip in r for r in RESOLVEURS):
            return adresse
        else:
            self.adresses[adresse] = self.publique(adresse)
        return self.adresses[adresse]

    def publique(self, adresse):
        """Adresse de documentation de même longueur ; sinon (7, 8 ou 15 caractères), quatre nombres au hasard de
        mêmes longueurs, qui ne mènent ni chez soi ni à un service connu."""
        pris = set(self.adresses.values())
        for prefixe in DOCUMENTATION:
            chiffres = len(adresse) - len(prefixe)
            if chiffres in OCTETS:
                libres = [f"{prefixe}{h}" for h in OCTETS[chiffres] if h not in HOTES_FIXES]
                libres = [a for a in libres if a not in pris]
                if libres:
                    return self.hasard.choice(libres)
        while True:
            faux = ".".join(str(self.hasard.choice(OCTETS[len(o)])) for o in adresse.split("."))
            ip = ipaddress.IPv4Address(faux)
            if ip.is_global and faux != adresse and faux not in pris and not any(ip in r for r in RESOLVEURS):
                return faux

    def ipv6(self, adresse):
        if adresse in self.adresses:
            return self.adresses[adresse]
        try:
            ip = ipaddress.IPv6Address(adresse)
        except ValueError:
            return adresse
        groupes = adresse.split(":")
        premier = next(i for i, g in enumerate(groupes) if g) if any(groupes) else 0
        # Le premier groupe dit seulement la sorte d'adresse (2xxx Internet, fdxx réseau local, fe80 lien local) ;
        # une adresse presque vide (« fe80::1 », « fd00::1 ») est la même chez tout le monde.
        if (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip in DOC6
                or any(ip in r for r in RESOLVEURS) or sum(len(g) for g in groupes[premier + 1 :]) <= 4):
            return adresse
        while True:
            faux = ":".join(g if i <= premier or not g else self.hexa(len(g)) for i, g in enumerate(groupes))
            if faux != adresse and faux not in self.adresses.values():
                self.adresses[adresse] = faux
                return faux

    def hexa(self, longueur):
        chiffres = "0123456789abcdef"
        return self.hasard.choice(chiffres[1:]) + "".join(self.hasard.choice(chiffres) for _ in range(longueur - 1))

    def mac(self, adresse):
        cle = adresse.lower()
        if cle not in self.adresses:
            octets = cle.split(":")
            premier = int(octets[0], 16)
            while True:
                if premier & 0x02:
                    # Adresse aléatoire (téléphones…) : aléatoire elle aussi, mêmes bits de sorte.
                    debut = [f"{(self.hasard.randrange(256) & 0xFC) | (premier & 0x03):02x}"]
                    debut += [f"{self.hasard.randrange(256):02x}" for _ in range(2)]
                else:
                    # Préfixe du fabricant gardé : son nom est écrit en clair à côté.
                    debut = octets[:3]
                faux = ":".join(debut + [f"{self.hasard.randrange(256):02x}" for _ in range(3)])
                if faux != cle and faux not in self.adresses.values():
                    self.adresses[cle] = faux
                    break
        return self.adresses[cle]

    def texte(self, t):
        t = conf.MAC.sub(lambda m: self.mac(m.group()), t)
        t = IPV4.sub(lambda m: self.ipv4(m.group()), t)
        return IPV6.sub(lambda m: self.ipv6(m.group()), t)

    def termes(self):
        """Les vraies adresses remplacées, pour vérifier qu'aucune ne reste."""
        return [conf.Terme(a, "adresse de la maison",
                           conf.motif_mac(a) if conf.MAC.fullmatch(a) else rf"(?<![\w.:]){re.escape(a)}(?![\w:]|\.\d)")
                for a, faux in self.adresses.items() if a != faux]


def remplacements(noms, langue):
    """Nom → remplaçant passe-partout de même longueur (le tableau des appareils reste aligné)."""
    mot = "appareil" if langue == "fr" else "device"
    sortie = {}
    for i, nom in enumerate(sorted(noms, key=len, reverse=True), 1):
        neuf = f"{mot}-{i}.local"
        sortie[nom] = neuf[: len(nom)].ljust(len(nom))
    return sortie


def remplacements_compte(moi):
    """Dossiers et adresse du compte : un prénom inventé de même longueur."""
    faux = next(f for f in (("alexandrine" + "x" * len(moi))[: len(moi)], ("camille" + "y" * len(moi))[: len(moi)])
                if f != moi)
    sortie = {f"{dossier}{moi}": f"{dossier}{faux}" for dossier in ("/home/", "/run/media/", "/media/", "/Users/")}
    sortie[f"{moi}@"] = f"{faux}@"
    return sortie


def anonymiser(rangees, noms, masque):
    """Remplace adresses et noms dans les cellules, en gardant couleurs et alignement. Un nom coupé par le tableau
    (« iPhone-de-Mar… ») est reconnu à son début."""
    for rangee in rangees:
        # Une cellule = un caractère du texte (les emoji de plusieurs points de code comptent pour un).
        indices = [x for x, c in enumerate(rangee) if c[0] != ""]
        t = "".join(rangee[x][0] if len(rangee[x][0]) == 1 else "￼" for x in indices)

        def ecrire(debut, neuf):
            for k, ch in enumerate(neuf):
                x = indices[debut + k]
                rangee[x] = (ch, rangee[x][1], rangee[x][2])

        masque_t = masque.texte(t)
        for k, (avant, apres) in enumerate(zip(t, masque_t)):
            if avant != apres:
                ecrire(k, apres)
        t = masque_t
        for nom, neuf in noms.items():
            for longueur in [len(nom), *range(len(nom) - 1, 3, -1)]:
                motif = nom if longueur == len(nom) else nom[:longueur] + "…"
                debut = t.find(motif)
                while debut >= 0:
                    ecrire(debut, (neuf if longueur == len(nom) else neuf[:longueur] + "…")[: len(motif)])
                    t = t[:debut] + neuf[: len(motif)] + t[debut + len(motif) :]
                    debut = t.find(motif, debut + len(motif))
    return rangees


def anonymiser_page(page, noms, masque):
    page = masque.texte(page)
    for nom, neuf in noms.items():
        page = page.replace(html.escape(nom), html.escape(neuf.strip())).replace(nom, neuf.strip())
    return page


def verifier(textes, detecteur, quoi):
    trouves = detecteur.trouver("\n".join(textes))
    if trouves:
        raise SystemExit(f"captures : {quoi} montrerait encore {len(trouves)} détail(s) personnel(s) : rien n'est "
                         "écrit.")


# --- Découpage de l'écran du bilan complet -------------------------------------------------------------------------

def decouper(rangees):
    """Bilan complet → (rangées de la machine, rangées du réseau)."""
    lignes = [texte(r) for r in rangees]
    debut_machine = next(i for i, l in enumerate(lignes) if l.startswith("━━"))
    note = next(i for i, l in enumerate(lignes) if i > debut_machine and "▰" in l)
    debut_reseau = next(i for i, l in enumerate(lignes) if i > note and l.startswith("╭"))
    fin_reseau = next((i for i, l in enumerate(lignes) if i > debut_reseau and l.startswith("━━")), len(lignes))
    reseau = rangees[debut_reseau:fin_reseau]
    while reseau and not texte(reseau[-1]).strip():
        reseau.pop()
    return (debut_machine, note, rangees), reseau


def extrait_machine(decoupe, langue):
    """Titre, quelques entrées montrables (les problèmes d'abord retenus, une par catégorie), dans leur ordre, une
    ligne « ⋮ » qui dit combien ne sont pas montrées, puis la note."""
    debut, note, rangees = decoupe
    entrees = []
    for i in range(debut + 1, note):
        l = texte(rangees[i])
        if len(l) > 3 and l[2] in MARQUES and l[1] == " ":
            categorie = l[4:].split("  ")[0].strip()
            entrees.append({"marque": l[2], "categorie": categorie, "rangees": [rangees[i]]})
        elif entrees and l.strip():
            entrees[-1]["rangees"].append(rangees[i])
    montrables = [e for e in entrees if e["categorie"] in CATEGORIES_MONTREES]
    choisies, vues = [], set()
    for e in sorted(montrables, key=lambda e: e["marque"] not in PROBLEMES):
        if len(choisies) < ENTREES_MAX and e["categorie"] not in vues:
            choisies.append(id(e))
            vues.add(e["categorie"])
    sortie = [rangees[debut]]
    vide = [(" ", "default", False)] * COLONNES
    for e in entrees:
        if id(e) in choisies:
            sortie.extend(e["rangees"])
    if len(choisies) < len(entrees):
        sortie.append(ligne_simple(SUITE[langue].format(len(entrees) - len(choisies)), "8a8a8a"))
    sortie.append(vide)
    sortie.extend(r for r in rangees[note : note + 1])
    return sortie


def ligne_simple(t, couleur):
    return [(c, couleur, False) for c in t.ljust(COLONNES)]


def haut_du_rapport(page):
    """Haut du rapport : les notes et leur évolution. Le détail (appareils, réglages de la machine) est coupé."""
    corps = page.find("<svg")
    coupe = page.find("<h2>", corps if corps >= 0 else 0)
    if coupe < 0:
        coupe = page.find("</main>")
    return page[:coupe].replace("<html", '<html data-theme="dark"', 1) + "</main></body></html>"


# --- Images ----------------------------------------------------------------------------------------------------------

def chromium():
    for nom in ("chromium", "chromium-browser", "google-chrome-stable", "google-chrome"):
        if shutil.which(nom):
            return nom
    raise SystemExit("captures : Chromium introuvable")


def photographier(html_page: str, sortie: Path, largeur: int, hauteur: int, bac: Path, rogner=False):
    page = bac / f"{sortie.stem}.html"
    page.write_text(html_page)
    image = bac / f"{sortie.stem}.png"
    subprocess.run(
        [chromium(), "--headless", "--disable-gpu", "--hide-scrollbars", "--force-dark-mode",
         f"--user-data-dir={bac / 'chromium'}", "--force-device-scale-factor=1", f"--window-size={largeur},{hauteur}",
         f"--screenshot={image}", page.as_uri()],
        check=True, capture_output=True, timeout=120,
    )
    if rogner:
        # Le bas de la page est vide : rogné, puis une marge égale tout autour.
        subprocess.run(["magick", str(image), "-fuzz", "3%", "-trim", "+repage", "-bordercolor", "#000000",
                        "-border", "24", str(image)], check=True)
    ecrire_si_change(image, sortie)


def ecrire_si_change(source: Path, cible: Path):
    if not cible.is_file() or cible.read_bytes() != source.read_bytes():
        shutil.copy(source, cible)
        print(f"  {cible}")


def terminal_html(rangees):
    morceaux = []
    for rangee in rangees:
        ligne = []
        for x, (car, fg, gras) in enumerate(rangee):
            if car == "":
                continue
            car = car.replace("️", "")
            symbole = car in SYMBOLES_TEXTE
            large = x + 1 < len(rangee) and rangee[x + 1][0] == ""
            couleur = PALETTE.get(fg) or (f"#{fg}" if re.fullmatch(r"[0-9a-fA-F]{6}", str(fg)) else PALETTE["default"])
            style = f"color:{couleur}" + (";font-weight:700" if gras else "")
            classe = "c l" if large else ("c s" if symbole else "c")
            ligne.append(f'<span class="{classe}" style="{style}">{html.escape(car)}</span>')
        morceaux.append(f'<div class="r">{"".join(ligne)}</div>')
    return f"""<!doctype html><meta charset="utf-8"><style>
html,body{{margin:0;background:#000}}
body{{padding:22px 20px;font:15px/20px 'JetBrainsMono Nerd Font Mono','JetBrainsMono Nerd Font','JetBrains Mono',monospace}}
.r{{height:20px;white-space:pre}}.c{{display:inline-block;width:9px;overflow:visible}}.c.l{{width:18px}}
.c.s{{font-family:'DejaVu Sans','Noto Sans Symbols',sans-serif;font-size:13px;font-variant-emoji:text}}
</style>{"".join(morceaux)}"""


def capture_terminal(rangees, sortie: Path, bac: Path):
    photographier(terminal_html(rangees), sortie, 20 + COLONNES * 9 + 40, 44 + 20 * len(rangees), bac)


def capture_partage(bac: Path):
    """Image de partage du dépôt (aperçu des liens) : 1280 × 640."""
    logo = Path("assets/icones/gardien-512.png").resolve().as_uri()
    page = f"""<!doctype html><meta charset="utf-8"><style>
html,body{{margin:0;width:1280px;height:640px;overflow:hidden}}
body{{background:radial-gradient(ellipse at 22% 40%,#1a0606 0%,#000 55%),#000;color:#f2ece6;
font-family:'Inter','Cantarell','Noto Sans',system-ui,sans-serif;display:flex;align-items:center;gap:56px;
padding:0 88px;box-sizing:border-box}}
img{{width:400px;height:400px;filter:drop-shadow(0 0 40px rgba(41,184,219,.18))}}
h1{{font-size:112px;line-height:1;margin:0 0 22px;letter-spacing:-2px;font-weight:800}}
p{{margin:0;font-size:34px;line-height:1.3;color:#d8d0ca}}
p.en{{margin-top:10px;font-size:26px;color:#8a8a8a}}
.os{{margin-top:34px;font-size:24px;letter-spacing:1px;color:#29b8db}}
</style><img src="{logo}" alt=""><div><h1>Gardien</h1>
<p>Sécurise et optimise ton ordinateur et ton réseau, depuis une clé USB.</p>
<p class="en">Secures and optimizes your computer and network, from a USB key.</p>
<div class="os">Linux · Windows · macOS</div></div>"""
    photographier(page, PARTAGE, 1280, 640, bac)


# --- Ensemble ----------------------------------------------------------------------------------------------------------

def connexion_a_refaire(force: bool) -> bool:
    if "--sans-connexion" in sys.argv:
        return False
    if force or not (DOSSIER / "connexion.png").is_file():
        return True
    derniere = subprocess.run(["git", "log", "-1", "--format=%H", "--", str(DOSSIER / "connexion.png")],
                              capture_output=True, text=True).stdout.strip()
    if not derniere:
        return True
    return subprocess.run(["git", "diff", "--quiet", derniere, "HEAD", "--", "src/connexion.rs", "src/ui.rs",
                           "src/langue.rs", "outils/captures.py"]).returncode != 0


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    programme = Path(args[0] if args else "target/x86_64-unknown-linux-musl/release/gardien").resolve()
    if not programme.is_file():
        raise SystemExit(f"captures : {programme} introuvable (compiler d'abord)")
    connexion = connexion_a_refaire("--connexion" in sys.argv)
    version = subprocess.run([str(programme), "--version"], capture_output=True, text=True).stdout.split()[-1]
    DOSSIER.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gardien-captures-") as t:
        bac = Path(t)
        preparer_bac(programme, bac)
        exe = bac / "cle/Linux/gardien"
        # Tout est pris avant d'être masqué : un même réseau inventé pour toutes les images, dans les deux langues.
        ecrans, rapports = {}, {}
        for langue in ("fr", "en"):
            suffixe = "" if langue == "fr" else "-en"
            env = environnement(bac, langue)
            complet = lancer(exe, ["complet", "--html"], env)
            rapports[f"rapport{suffixe}.png"] = (langue, haut_du_rapport((bac / "cle/donnees/rapport.html").read_text()))
            machine, reseau = decouper(complet)
            ecrans[f"bilan{suffixe}.png"] = (langue, extrait_machine(machine, langue))
            ecrans[f"reseau{suffixe}.png"] = (langue, reseau)
            ecrans[f"menu{suffixe}.png"] = (langue, lancer(exe, [], env, attendre="›", touches=b"q\r", delai=30))
            if connexion:
                ecrans[f"connexion{suffixe}.png"] = (langue, lancer(exe, ["connexion"], env, delai=180))
        masque = Masque([texte(r) for _, rangees in ecrans.values() for r in rangees]
                        + [page for _, page in rapports.values()])
        moi = conf.compte()
        termes = conf.termes()
        noms_vus, _ = conf.appareils(bac / "cle/donnees/appareils.json")
        caches = noms_vus | {t.texte for t in termes if t.origine in REMPLACABLES} | ({moi} if len(moi) >= 4 else set())
        noms = {}
        for langue in ("fr", "en"):
            tous = remplacements(caches, langue) | remplacements_compte(moi)
            noms[langue] = dict(sorted(tous.items(), key=lambda kv: -len(kv[0])))
        images = {nom: anonymiser(rangees, noms[langue], masque) for nom, (langue, rangees) in ecrans.items()}
        pages = {nom: anonymiser_page(page, noms[langue], masque) for nom, (langue, page) in rapports.items()}
        compte = [conf.Terme(f"{moi}@", "compte", rf"(?<![\w.-]){re.escape(moi)}@")]
        if len(moi) >= 4:
            compte.append(conf.Terme(moi, "compte", conf.motif_texte(moi)))
        detecteur = conf.Detecteur(termes + compte + masque.termes())
        for nom, rangees in images.items():
            verifier([texte(r) for r in rangees], detecteur, nom)
        for nom, page in pages.items():
            verifier([re.sub(r"<[^>]+>", " ", page)], detecteur, nom)
        for nom, rangees in images.items():
            capture_terminal(rangees, DOSSIER / nom, bac)
        for nom, page in pages.items():
            photographier(page, DOSSIER / nom, 900, 1400, bac, rogner=True)
        capture_partage(bac)
    (DOSSIER / "VERSION").write_text(version + "\n")
    print(f"Captures de la version {version} : {DOSSIER}/")


if __name__ == "__main__":
    main()
