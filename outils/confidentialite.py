#!/usr/bin/env python3
"""Garde-fou : rien de personnel ne part sur GitHub. Ni dans le code, ni dans un message de commit, ni dans le nom de
l'auteur, ni dans une page de version, un ticket ou une capture d'écran.

Lancé tout seul : à chaque commit (crochets outils/hooks/pre-commit et commit-msg, actifs avec
`git config core.hooksPath outils/hooks`), avant chaque envoi (outils/deployer.sh), avant chaque page de version
(outils/publier-version.sh), avant chaque ticket du journal (outils/journal-vers-github.py) et avant d'écrire les
captures du README (outils/captures.py).

Ce qui est personnel est lu sur cet ordinateur, jamais écrit dans le dépôt, qui le publierait lui-même :
- ~/.config/gardien-dev/confidentiel.txt : une expression par ligne (nom, courriels, adresse…), « # » en commentaire ;
- le courriel et le nom de l'identité Git de l'ordinateur, le nom complet du compte, ses dossiers (/home/<compte>…) ;
- les appareils de la base de Gardien (noms, adresses MAC), les réseaux Wi-Fi enregistrés et leurs bornes, le nom de
  l'ordinateur.

Depuis la racine du dépôt :
    python3 outils/confidentialite.py --commit           ce qui va être commité : lignes ajoutées, fichiers, auteur
    python3 outils/confidentialite.py --message FICHIER  un message de commit
    python3 outils/confidentialite.py --envoi            les commits pas encore sur GitHub
    python3 outils/confidentialite.py --texte < FICHIER  un texte à publier
    python3 outils/confidentialite.py --binaire FICHIER… des programmes compilés (textes lisibles, métadonnées)
    python3 outils/confidentialite.py --depot            les fichiers et tout l'historique (avant de rendre le dépôt
                                                         public)
Sort en erreur (code 1) en disant quoi et où dès qu'un détail personnel paraît.
"""

import getpass
import json
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import pwd
except ImportError:  # Windows
    pwd = None

PRIVE = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "gardien-dev/confidentiel.txt"
MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
# Adresse que GitHub donne à chaque compte pour signer ses commits sans montrer son courriel.
ANONYME = "@users.noreply.github.com"

# Noms d'appareils et de réseaux sans rien de personnel : sortes d'appareils, pièces, produits courants. Un nom fait
# seulement de ces mots n'est pas caché (il paraît aussi dans le code : « 8009 Chromecast », réseau « Salon » des tests).
MOTS_GENERIQUES = set(
    "imprimante printer box routeur router modem téléphone telephone phone tablette tablet ordinateur computer pc "
    "portable laptop console télé tele tv télévision television caméra camera enceinte speaker montre watch nas "
    "serveur server switch répéteur repeater borne wifi hp lg local gateway _gateway localhost salon cuisine chambre "
    "bureau garage maison home office kitchen living room bedroom chromecast airplay echo alexa nest google apple "
    "iphone ipad macbook imac android galaxy pixel kindle fire roku sonos xbox playstation nintendo raspberrypi "
    "raspberry pi synology brother epson canon samsung sony".split()
)
DISTRIBUTIONS = {"omarchy", "archlinux", "arch", "ubuntu", "fedora", "debian", "linuxmint", "mint", "pop-os",
                 "manjaro", "endeavouros", "cachyos", "bazzite", "opensuse", "localhost"}


@dataclass(frozen=True)
class Terme:
    texte: str
    origine: str
    motif: str


def generique(nom: str) -> bool:
    mots = re.findall(r"[\wÀ-ÿ-]+", nom.lower())
    return bool(mots) and all(m in MOTS_GENERIQUES or m in DISTRIBUTIONS for m in mots)


def motif_texte(texte: str) -> str:
    """Le texte comme mot entier (« Chez Max » pas dans « Chez Maxime »), espaces souples (retour à la ligne compris)."""
    corps = r"\s+".join(re.escape(m) for m in texte.split())
    debut = r"(?<!\w)" if re.match(r"\w", texte) else ""
    fin = r"(?!\w)" if re.search(r"\w$", texte) else ""
    return debut + corps + fin


def motif_mac(mac: str) -> str:
    """Une adresse MAC sous ses trois écritures : « aa:bb:… » ou « aa-bb-… » (Windows), « aabb… », et sans les zéros de
    tête (« 3c:8d:a:… », comme l'écrit arp sous macOS)."""
    octets = mac.lower().split(":")
    sans_zeros = ":".join(f"0?{o[1]}" if o[0] == "0" else o for o in octets)
    return rf"(?<![0-9a-f:-])(?:{'[:-]'.join(octets)}|{''.join(octets)}|{sans_zeros})(?![0-9a-f])"


def compte() -> str:
    return os.environ.get("USER") or getpass.getuser()


def dossiers_gardien():
    """Dossier des données de cet ordinateur, et celui de la clé branchée : la base des appareils vit sur les deux."""
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    local = next((base / n for n in ("gardien", "sentinel") if (base / n).is_dir()), None)
    cle = None
    for media in (Path("/run/media") / compte(), Path("/media") / compte()):
        try:
            for d in media.iterdir():
                if any((d / t).is_file() for t in ("gardien.cle", "sentinel.cle", "netscan.cle")):
                    cle = d / "donnees"
        except OSError:
            continue
    return local, cle


def appareils(*bases):
    """Noms (appareils, surnoms, réseaux) qui pourraient nommer quelqu'un, et adresses MAC, des bases d'appareils."""
    noms, macs = set(), set()
    for base in bases:
        try:
            texte = base.read_text()
            donnees = json.loads(texte)
        except (OSError, ValueError):
            continue
        macs |= {m.lower() for m in MAC.findall(texte)}
        for reseau in donnees.get("reseaux", {}).values():
            noms.add(reseau.get("nom") or "")
            for appareil in reseau.get("appareils", {}).values():
                noms |= {appareil.get(champ) or "" for champ in ("nom", "surnom")}
    return {n for n in noms if len(n) >= 3 and not generique(n)}, macs


def nmcli(*args):
    try:
        return subprocess.run(["nmcli", *args], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def reseaux_enregistres():
    """Réseaux Wi-Fi et VPN enregistrés (nom de la connexion et nom du Wi-Fi), et les bornes déjà vues."""
    noms, bornes = set(), set()
    for ligne in nmcli("-t", "-f", "NAME,TYPE", "connection", "show").splitlines():
        nom, _, genre = ligne.rpartition(":")
        if not nom or genre not in ("802-11-wireless", "vpn", "wireguard"):
            continue
        noms.add(nom.replace("\\:", ":"))
        if genre == "802-11-wireless":
            ssid, _, vues = nmcli("-g", "802-11-wireless.ssid,802-11-wireless.seen-bssids", "connection", "show",
                                  nom.replace("\\:", ":")).partition("\n")
            noms.add(ssid.strip().replace("\\:", ":"))
            bornes |= {m.lower() for m in MAC.findall(vues.replace("\\", ""))}
    return {n for n in noms if n}, bornes


def termes():
    """Tout ce qui ne doit jamais être publié, avec d'où ça vient."""
    liste = []

    def ajouter(texte, origine, motif=None):
        if texte and not any(t.texte.lower() == texte.lower() for t in liste):
            liste.append(Terme(texte, origine, motif or motif_texte(texte)))

    if PRIVE.is_file():
        for ligne in PRIVE.read_text().splitlines():
            if ligne.strip() and not ligne.lstrip().startswith("#"):
                ajouter(ligne.strip(), "liste privée")
    for cle in ("user.email", "user.name"):
        valeur = subprocess.run(["git", "config", "--global", cle], capture_output=True, text=True).stdout.strip()
        if len(valeur) >= 5 and not valeur.endswith(ANONYME):
            ajouter(valeur, "identité Git de l'ordinateur")
    if pwd:
        try:
            ajouter(pwd.getpwuid(os.getuid()).pw_gecos.split(",")[0].strip(), "nom complet du compte")
        except KeyError:
            pass
    moi = re.escape(compte())
    hote = socket.gethostname().split(".")[0]
    ajouter(f"/home/{compte()}", "dossier personnel",
            rf"(?:/home|/Users|/run/media|/media)/{moi}(?![\w.-])|[A-Za-z]:\\+Users\\+{moi}(?![\w.-])")
    ajouter(f"{compte()}@{hote}", "compte et nom de l'ordinateur")
    if len(hote) >= 4 and hote.lower() not in DISTRIBUTIONS and not generique(hote):
        ajouter(hote, "nom de l'ordinateur")
    noms, macs = appareils(*(d / "appareils.json" for d in dossiers_gardien() if d))
    reseaux, bornes = reseaux_enregistres()
    for nom in sorted(noms | {n for n in reseaux if not generique(n)}):
        if len(nom) >= 4:
            ajouter(nom, "appareil ou réseau de la maison")
    for mac in sorted(macs | bornes):
        ajouter(mac, "adresse MAC de la maison", motif_mac(mac))
    return liste


class Detecteur:
    def __init__(self, liste):
        self.termes = liste
        self.motif = re.compile("|".join(f"(?P<t{i}>{t.motif})" for i, t in enumerate(liste)), re.IGNORECASE) \
            if liste else None

    def trouver(self, texte: str):
        """(terme, numéro de ligne) de chaque détail personnel du texte."""
        if not self.motif:
            return []
        return [(self.termes[int(m.lastgroup[1:])], texte.count("\n", 0, m.start()) + 1)
                for m in self.motif.finditer(texte)]


# --- Où chercher -----------------------------------------------------------------------------------------------------

# Diff lu ligne à ligne : préfixes « a/ » et « b/ » imposés (diff.mnemonicPrefix ou diff.noPrefix les changent).
DIFF = ("-U0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/")


def git(*args):
    r = subprocess.run(["git", "-c", "core.quotePath=false", *args], capture_output=True, text=True, errors="replace")
    if r.returncode:
        raise SystemExit(f"confidentialité : git {' '.join(args)} a échoué : {r.stderr.strip()}")
    return r.stdout


def lignes_ajoutees(diff: str):
    """(fichier, numéro de ligne, texte) de chaque ligne ajoutée d'un diff -U0, et une entrée par fichier pour son nom."""
    fichier, numero, entete = None, 0, False
    for ligne in diff.splitlines():
        # « +++ » n'est un en-tête qu'avant le premier « @@ » du fichier : plus loin, c'est une ligne ajoutée qui
        # commence par « ++ ».
        if ligne.startswith("diff "):
            entete = True
        elif entete and ligne.startswith("+++ "):
            fichier = ligne[6:].rstrip("\t") if ligne.startswith("+++ b/") else None
            if fichier:
                yield fichier, 0, fichier
        elif ligne.startswith("@@"):
            entete = False
            m = re.search(r"\+(\d+)", ligne)
            numero = int(m.group(1)) if m else 0
        elif not entete and ligne.startswith("+") and fichier:
            yield fichier, numero, ligne[1:]
            numero += 1


def chercher_diff(detecteur, diff, prefixe=""):
    return [(f"{prefixe}{fichier}" + (f":{numero}" if numero else " (nom du fichier)"), terme)
            for fichier, numero, texte in lignes_ajoutees(diff) for terme, _ in detecteur.trouver(texte)]


def identite(detecteur, texte, ou):
    return [(ou, terme) for terme, _ in detecteur.trouver(texte)]


def commit_en_cours(detecteur):
    trouves = []
    for variable, role in (("GIT_AUTHOR_IDENT", "auteur"), ("GIT_COMMITTER_IDENT", "committeur")):
        # « Nom <courriel> horodatage fuseau »
        trouves += identite(detecteur, git("var", variable).rsplit(" ", 2)[0], f"{role} du commit")
    diff = git("diff", "--cached", *DIFF, "--diff-filter=ACMR")
    return trouves + chercher_diff(detecteur, diff)


def message(detecteur, chemin):
    texte = Path(chemin).read_text(errors="replace").split("# ------------------------ >8 ------------------------")[0]
    texte = "\n".join(l for l in texte.splitlines() if not l.startswith("#"))
    return [(f"message du commit, ligne {n}", terme) for terme, n in detecteur.trouver(texte)]


def commits_a_envoyer(detecteur):
    trouves = []
    for sha in git("rev-list", "--reverse", "HEAD", "--not", "--remotes=origin").split():
        court = sha[:9]
        entete = git("show", "-s", "--format=%an <%ae>%n%cn <%ce>%n%B", sha)
        auteurs, _, corps = entete.partition("\n")
        committeur, _, corps = corps.partition("\n")
        trouves += identite(detecteur, auteurs, f"{court} auteur")
        trouves += identite(detecteur, committeur, f"{court} committeur")
        trouves += [(f"{court} message, ligne {n}", t) for t, n in detecteur.trouver(corps)]
        diff = git("diff-tree", "-p", *DIFF, "--no-commit-id", "--root", "-r", "-m", "--first-parent", sha)
        trouves += chercher_diff(detecteur, diff, f"{court} ")
    return trouves


def depot_entier(detecteur):
    """Fichiers suivis, puis tout l'historique : contenus de toutes les versions de chaque fichier, messages, auteurs."""
    trouves = []
    for chemin in git("ls-files", "-z").split("\0"):
        if not chemin or not Path(chemin).is_file():
            continue
        brut = Path(chemin).read_bytes()
        if b"\0" in brut[:8000]:
            continue
        trouves += [(f"{chemin}:{n}", t) for t, n in detecteur.trouver(brut.decode(errors="replace"))]
        trouves += [(f"{chemin} (nom du fichier)", t) for t, _ in detecteur.trouver(chemin)]
    vus = set()
    for ligne in git("log", "--all", "--format=%h%x1f%an <%ae>%x1f%cn <%ce>%x1f%B%x1e").split("\x1e"):
        if not ligne.strip():
            continue
        court, auteur, committeur, corps = ligne.strip("\n").split("\x1f", 3)
        for texte, quoi in ((auteur, "auteur"), (committeur, "committeur"), (corps, "message")):
            for terme, _ in detecteur.trouver(texte):
                vus.add((f"historique : {quoi} de commit", terme))
    objets = {}
    for ligne in git("rev-list", "--objects", "--all").splitlines():
        sha, _, chemin = ligne.partition(" ")
        if chemin:
            objets.setdefault(sha, chemin)
    lot = subprocess.run(["git", "cat-file", "--batch"], input="".join(f"{s}\n" for s in objets).encode(),
                         capture_output=True, check=True).stdout
    position = 0
    while position < len(lot):
        fin = lot.index(b"\n", position)
        entete = lot[position:fin].decode().split()
        if len(entete) != 3:  # « <sha> missing »
            position = fin + 1
            continue
        sha, genre, taille = entete
        contenu = lot[fin + 1 : fin + 1 + int(taille)]
        position = fin + 2 + int(taille)
        if genre == "blob" and b"\0" not in contenu[:8000]:
            for terme, _ in detecteur.trouver(contenu.decode(errors="replace")):
                vus.add((f"historique : {objets[sha]}", terme))
        for terme, _ in detecteur.trouver(objets.get(sha, "")):
            vus.add((f"historique : {objets[sha]} (nom du fichier)", terme))
    return trouves + sorted(vus, key=lambda v: (v[0], v[1].texte))


def chaines(chemin):
    """Textes lisibles d'un programme compilé : ASCII et UTF-8, puis UTF-16 (métadonnées d'un .exe)."""
    brut = Path(chemin).read_bytes()
    textes = [s.decode(errors="replace") for s in re.findall(rb"[\t\x20-\x7e\x80-\xff]{4,}", brut)]
    textes += [s.decode("utf-16-le") for s in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", brut)]
    return "\n".join(textes)


def rapport(trouves, quoi) -> int:
    if not trouves:
        return 0
    print(f"Confidentialité : {len(trouves)} détail(s) personnel(s) dans {quoi}.", file=sys.stderr)
    fois = {}
    for trouve in trouves:
        fois[trouve] = fois.get(trouve, 0) + 1
    for (ou, terme), n in fois.items():
        print(f"  {ou} — {terme.origine} : {terme.texte}" + (f" ({n} fois)" if n > 1 else ""), file=sys.stderr)
    print("Remplace-les par des valeurs inventées (adresses MAC : garder les 3 premiers octets, ceux du fabricant). "
          f"Une expression de {PRIVE} qui n'a rien de personnel s'y retire.", file=sys.stderr)
    return 1


def main():
    args = sys.argv[1:]
    if args[:1] in (["--message"], ["--binaire"]):
        args[1:] = [os.path.abspath(a) for a in args[1:]]
    os.chdir(git("rev-parse", "--show-toplevel").strip())
    detecteur = Detecteur(termes())
    if args[:1] == ["--commit"]:
        sys.exit(rapport(commit_en_cours(detecteur), "ce commit (rien n'est commité)"))
    if args[:1] == ["--message"] and len(args) == 2:
        sys.exit(rapport(message(detecteur, args[1]), "le message du commit (rien n'est commité)"))
    if args[:1] == ["--envoi"]:
        sys.exit(rapport(commits_a_envoyer(detecteur), "les commits à envoyer"))
    if args[:1] == ["--texte"]:
        texte = sys.stdin.read()
        sys.exit(rapport([(f"ligne {n}", t) for t, n in detecteur.trouver(texte)], "le texte"))
    if args[:1] == ["--binaire"] and len(args) > 1:
        trouves = [(Path(f).name, t) for f in args[1:] for t, _ in detecteur.trouver(chaines(f))]
        sys.exit(rapport(trouves, "les programmes compilés"))
    if args[:1] == ["--depot"]:
        sys.exit(rapport(depot_entier(detecteur), "le dépôt et son historique"))
    raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
