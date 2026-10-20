#!/usr/bin/env python3
"""Remplit la page des fonctions de Vanguard (outils/page-fonctions.html) pour la version à publier.

La page est publiée sur claude.ai à chaque version (skill /livrer) : ce script en remplit les trous, à partir du
code et des vérifications, et écrit la page prête à publier. Rien n'est envoyé d'ici.
  - version et date : Cargo.toml et le jour ;
  - lignes de Rust : src/ et tests/, sans les commentaires ni les lignes vides ;
  - commandes du guide : le programme les compte lui-même (« vanguard guide » sans terminal, hors ligne) ;
  - tests Linux et Wine : la sortie de outils/verifier.sh (--verifier) ou les nombres donnés ;
  - vérifications sur le vrai Windows : la dernière passe réussie de la VM (historique.txt).

    python3 outils/page-fonctions.py --verifier SORTIE [--programme VANGUARD] [--sortie PAGE]
    python3 outils/page-fonctions.py --tests-linux 693 --tests-wine 613
"""
import argparse
import datetime
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
MOIS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre",
        "décembre"]


def version() -> str:
    m = re.search(r'^version = "([^"]+)"', (RACINE / "Cargo.toml").read_text(encoding="utf-8"), re.M)
    if not m:
        sys.exit("✖ pas de version dans Cargo.toml")
    return m.group(1)


def milliers(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def lignes_de_rust() -> str:
    total = 0
    for dossier in ("src", "tests"):
        for f in (RACINE / dossier).rglob("*.rs"):
            for ligne in f.read_text(encoding="utf-8").splitlines():
                l = ligne.strip()
                if l and not l.startswith("//"):
                    total += 1
    # Arrondi à la centaine : « ≈ 83 500 », un ordre de grandeur, pas un compte qui bouge à chaque commit.
    return milliers(round(total, -2))


def commandes_du_guide(programme: Path) -> str:
    """Le total affiché en tête du guide, demandé au programme dans un dossier personnel jetable, hors ligne."""
    with tempfile.TemporaryDirectory(prefix="page-fonctions-", dir=Path.home() / ".cache") as maison:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": maison, "XDG_DATA_HOME": f"{maison}/d",
               "XDG_CACHE_HOME": f"{maison}/c", "USER": "essai", "VANGUARD_HORS_LIGNE": "1", "VANGUARD_LANG": "fr"}
        r = subprocess.run([str(programme), "guide"], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=60, env=env, cwd=maison)
    m = re.search(r"(\d+) commandes", re.sub(r"\x1b\[[0-9;]*m", "", r.stdout))
    if not m:
        sys.exit(f"✖ le guide n'a pas donné son nombre de commandes ({programme})")
    return milliers(int(m.group(1)))


def tests(args) -> tuple[str, str]:
    linux, wine = args.tests_linux, args.tests_wine
    if args.verifier:
        texte = Path(args.verifier).read_text(encoding="utf-8")
        l = re.search(r"tests Linux \((\d+)\)", texte)
        w = re.search(r"tests Windows sous Wine \((\d+)\)", texte)
        linux = linux or (l and int(l.group(1)))
        wine = wine or (w and int(w.group(1)))
    if not linux or not wine:
        sys.exit("✖ nombres de tests inconnus : --verifier SORTIE de outils/verifier.sh, ou --tests-linux et --tests-wine")
    return milliers(linux), milliers(wine)


def verifications_vm() -> str:
    historique = Path.home() / "Windows/VANGUARD-TEST/resultats/historique.txt"
    nombres = re.findall(r"OK, tout est passé \((\d+) vérifications", historique.read_text(encoding="utf-8",
                                                                                         errors="replace"))
    if not nombres:
        sys.exit("✖ aucune passe réussie de la VM dans historique.txt")
    return nombres[-1]


def alleger(page: str) -> str:
    """La page publiée sans ce qui ne sert qu'à la tenir : commentaires HTML et CSS, indentation et lignes vides. Les
    blocs <pre> gardent leurs espaces, qui y sont le texte même."""
    morceaux = re.split(r"(<pre\b.*?</pre>)", page, flags=re.S)
    for i in range(0, len(morceaux), 2):
        m = re.sub(r"<!--.*?-->", "", morceaux[i], flags=re.S)
        m = re.sub(r"/\*.*?\*/", "", m, flags=re.S)
        m = re.sub(r"\n[ \t]+", "\n", m)
        morceaux[i] = re.sub(r"\n{2,}", "\n", m)
    return "".join(morceaux)


def main():
    a = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    a.add_argument("--verifier", help="sortie de outils/verifier.sh (nombres de tests)")
    a.add_argument("--tests-linux", type=int)
    a.add_argument("--tests-wine", type=int)
    a.add_argument("--programme", type=Path,
                   default=RACINE / "target/x86_64-unknown-linux-musl/release/vanguard")
    a.add_argument("--sortie", type=Path, default=Path.home() / ".cache/vanguard-dev/page-fonctions.html")
    a.add_argument("--version", help="la version à montrer, avant que Cargo.toml la porte (un aperçu)")
    args = a.parse_args()
    if not args.programme.is_file():
        sys.exit(f"✖ programme introuvable : {args.programme} (--programme)")
    v = args.version or version()
    courte = ".".join(v.split(".")[:2])
    jour = datetime.date.today()
    valeurs = {
        "VERSION": v,
        "VERSION_COURTE": courte,
        # Dans la boîte du terminal (76 colonnes), le numéro garde la place d'origine.
        "VERSION_COURTE_TERMINAL": courte.ljust(16),
        "DATE": f"{jour.day} {MOIS[jour.month - 1]} {jour.year}",
        "LIGNES": lignes_de_rust(),
        "COMMANDES": commandes_du_guide(args.programme),
        "VM": verifications_vm(),
    }
    valeurs["TESTS_LINUX"], valeurs["TESTS_WINE"] = tests(args)
    page = (RACINE / "outils/page-fonctions.html").read_text(encoding="utf-8")
    page = re.sub(r"<!--.*?-->\n", "", page, count=1, flags=re.S)
    for cle, valeur in valeurs.items():
        page = page.replace("{{" + cle + "}}", valeur)
    page = alleger(page)
    reste = re.findall(r"\{\{[A-Z_]+\}\}", page)
    if reste:
        sys.exit(f"✖ trous non remplis : {', '.join(sorted(set(reste)))}")
    args.sortie.parent.mkdir(parents=True, exist_ok=True)
    args.sortie.write_text(page, encoding="utf-8")
    print(f"Page des fonctions prête : {args.sortie}")
    for cle in ("VERSION", "DATE", "LIGNES", "COMMANDES", "TESTS_LINUX", "TESTS_WINE", "VM"):
        print(f"  {cle.lower():<12} {valeurs[cle]}")


if __name__ == "__main__":
    main()
