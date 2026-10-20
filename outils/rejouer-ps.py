#!/usr/bin/env python3
"""Les scripts PowerShell du programme, analysés puis rejoués sous Linux avec pwsh.

Les tests Windows tournent sous Wine, sans PowerShell : un script intégré au code (lecture du bilan, nettoyage,
corrections) n'était vérifié que dans la VM. Ici, chaque texte du code qui ressemble à un script PowerShell (hors
guide, que la personne tape elle-même, et hors tests) est :
  1. analysé par pwsh : une erreur de syntaxe est un échec ;
  2. lancé dans un bac à sable (bwrap : système en lecture seule, sans réseau, dossier personnel jetable), depuis un
     dossier courant qui contient des fichiers témoins. Sous Linux, les variables et dossiers spéciaux de Windows
     sont vides : c'est le cas limite où « Get-ChildItem '' » lit le dossier courant (vu le 19 octobre : un dossier
     Démarrage absent). Un script qui cite un témoin, ou en efface un, a lu le dossier courant : échec.
Un modèle de format! ({nom} à remplir) n'est qu'analysé, ses trous remplacés par une valeur.

    python3 outils/rejouer-ps.py [--pwsh CHEMIN] [-v]
"""
import argparse
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
PWSH_PAR_DEFAUT = Path.home() / ".cache/vanguard-dev/pwsh/pwsh"
# Des applets courants : un texte qui n'en a aucun n'est pas un script (un message, un chemin).
APPLET = re.compile(r"\b(Get|Set|New|Remove|Start|Stop|Test|Add|Clear|Invoke|Select|Where|ForEach|Out|Copy|Move|"
                    r"Register|Unregister|Enable|Disable|Restart|Write|Measure|Sort|Join|Split|Resolve)-[A-Z][A-Za-z]+")
TROU = re.compile(r"\{[A-Za-z_][A-Za-z0-9_.]*(:[^{}]*)?\}|\{\}|\{:[^{}]*\}")
FORMAT = re.compile(r"\b(format|write|writeln)!\((\s*[\w.&]+\s*,)?$")
# Les textes affichés : macros, et les titres bilingues ou de section du dossier de traces (traces/).
MESSAGE = re.compile(r"(\b(e?println|e?print|tr|trf|trp|tre|trw|bi|panic|assert\w*)!|\bBi::new|\.section)\($")
TEMOINS = ["temoin-dossier-courant.exe", "temoin.lnk", "temoin-dossier/dedans.txt"]


# Les objets COM de Windows n'existent pas sous Linux : sans doublure, un bloc qui commence par en créer un (les
# raccourcis du dossier Démarrage) s'arrêtait avant la ligne à essayer. New-Object -ComObject rend ici un objet
# factice ; le reste de New-Object est celui de PowerShell.
DEMARRE = "REJEU-DEMARRE"
PRELUDE = r"""'REJEU-DEMARRE'
function New-Object {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$TypeName, [string]$ComObject,
        [Parameter(Position = 1)][object[]]$ArgumentList, [hashtable]$Property)
    if ($ComObject) {
        $o = [pscustomobject]@{}
        $o | Add-Member ScriptMethod CreateShortcut { param($c) [pscustomobject]@{ TargetPath = $c; Arguments = '' } }
        return $o
    }
    Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}
"""


def litteraux(src: str):
    """Les chaînes du source Rust, décodées, avec leur position. Commentaires et caractères sautés."""
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c == "'":
            # Un caractère ('"', '\'', '\u{..}') ou une durée de vie ('a) : on saute le caractère seulement.
            m = re.match(r"'(\\u\{[0-9a-fA-F]+\}|\\.|[^\\'])'", src[i:])
            i += len(m.group(0)) if m else 1
        elif c in "rb" and re.match(r"(br|r)#*\"", src[i:]) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            m = re.match(r"(br|r)(#*)\"", src[i:])
            fin = '"' + m.group(2)
            debut = i + len(m.group(0))
            j = src.find(fin, debut)
            if not m.group(1).startswith("b"):
                yield i, src[debut:j]
            i = j + len(fin)
        elif c == '"' or (c == "b" and src.startswith('b"', i) and not (src[i - 1].isalnum() or src[i - 1] == "_")):
            octets = c == "b"
            j = i + (2 if octets else 1)
            texte = []
            while src[j] != '"':
                if src[j] == "\\":
                    s = src[j + 1]
                    if s == "\n":
                        j += 2
                        while src[j] in " \t\n\r":
                            j += 1
                        continue
                    if s == "u":
                        k = src.index("}", j)
                        texte.append(chr(int(src[j + 3:k], 16)))
                        j = k + 1
                        continue
                    if s == "x":
                        texte.append(chr(int(src[j + 2:j + 4], 16)))
                        j += 4
                        continue
                    texte.append({"n": "\n", "t": "\t", "r": "\r", "0": "\0"}.get(s, s))
                    j += 2
                else:
                    texte.append(src[j])
                    j += 1
            if not octets:
                yield i, "".join(texte)
            i = j + 1
        else:
            i += 1


def scripts():
    """(fichier:ligne, texte, modèle) pour chaque script PowerShell du programme."""
    for p in sorted((RACINE / "src").rglob("*.rs")):
        nom = p.relative_to(RACINE / "src").as_posix()
        if nom.startswith("guide/"):
            continue
        src = p.read_text(encoding="utf-8")
        t = src.find("#[cfg(test)]\nmod ")
        code = src if t < 0 else src[:t]
        message = False
        for debut, texte in litteraux(code):
            avant = code[:debut].rstrip()
            # Un texte affiché (tr!, println!…) peut citer une commande à taper : ce n'est pas un script. Le second
            # texte d'un tr!("fr", "en") suit le premier, après une virgule.
            message = bool(MESSAGE.search(avant)) or (message and avant.endswith(","))
            if message or len(texte) < 12 or not APPLET.search(texte):
                continue
            ligne = code[:debut].count("\n") + 1
            # Un modèle seulement s'il est passé à format! : en PowerShell, « catch {} » est un bloc vide, pas un trou.
            yield f"{nom}:{ligne}", texte, bool(FORMAT.search(avant))


def rempli(texte: str, valeur: str = "'x'") -> str:
    """Un modèle de format! rendu analysable : {{ }} doublés, chaque trou remplacé par une valeur."""
    protege = texte.replace("{{", "\x00").replace("}}", "\x01")
    return TROU.sub(valeur, protege).replace("\x00", "{").replace("\x01", "}")


def analyser(pwsh: Path, texte: str) -> str:
    """Les erreurs de syntaxe, vides si le script s'analyse."""
    code = ("$e = $null; $t = $null; [void][System.Management.Automation.Language.Parser]::ParseInput("
            "[Console]::In.ReadToEnd(), [ref]$t, [ref]$e); $e | ForEach-Object { $_.Message }")
    # pwsh plante parfois lui-même sous la charge (« An error has occurred that was not properly handled ») : son
    # code de retour le dit, et l'analyse est refaite ; une vraie erreur de syntaxe, elle, sort avec le code 0.
    for _ in range(3):
        r = subprocess.run([str(pwsh), "-NoProfile", "-NonInteractive", "-Command", code], input=texte,
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            return r.stdout.strip()
    return f"pwsh a échoué trois fois (code {r.returncode}) : {(r.stdout + r.stderr).strip()[:200]}"


def rejouer(pwsh: Path, texte: str, dossier: Path) -> str:
    """Lance le script dans le bac à sable ; rend ce qui ne va pas (témoin cité ou effacé), vide sinon."""
    courant = dossier / "courant"
    for t in TEMOINS:
        (courant / t).parent.mkdir(parents=True, exist_ok=True)
        (courant / t).write_text("témoin\n")
    maison = dossier / "maison"
    maison.mkdir()
    (dossier / "script.ps1").write_text(PRELUDE + texte, encoding="utf-8-sig")
    # /run vide : sans lui, le D-Bus système restait joignable (un socket Unix passe outre --unshare-all). Sous Linux,
    # pwsh traduit Restart-Computer par « shutdown » sans argument, et logind éteignait la machine une minute plus
    # tard : trois arrêts les 19 et 20 octobre, en rejouant le texte « Restart-Computer » de machine/windows/maj.rs.
    commande = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/run",
                "--bind", str(maison), str(Path.home()), "--ro-bind", str(pwsh.parent), str(pwsh.parent),
                "--bind", str(courant), str(courant), "--ro-bind", str(dossier / "script.ps1"), "/tmp/script.ps1",
                "--chdir", str(courant), "--unshare-all", "--die-with-parent", "--new-session",
                "--setenv", "HOME", str(Path.home()), "--unsetenv", "TEMP", "--unsetenv", "TMP",
                str(pwsh), "-NoProfile", "-NonInteractive", "-File", "/tmp/script.ps1"]
    try:
        r = subprocess.run(commande, capture_output=True, text=True, timeout=45)
        sortie = r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        sortie = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
    problemes = []
    # Sans ce mot, pwsh n'a pas tourné (bac à sable mal monté, pwsh absent) : rien n'a été essayé, et le dire.
    if DEMARRE not in sortie:
        return f"pwsh n'a pas tourné dans le bac à sable : {sortie.strip()[:200]}"
    if "temoin" in sortie:
        cite = next(l for l in sortie.splitlines() if "temoin" in l)
        problemes.append(f"le dossier courant est lu : {cite.strip()[:160]}")
    effaces = [t for t in TEMOINS if not (courant / t).exists()]
    if effaces:
        problemes.append(f"témoins du dossier courant effacés : {', '.join(effaces)}")
    return " ; ".join(problemes)


def main():
    a = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    a.add_argument("--pwsh", type=Path, default=PWSH_PAR_DEFAUT)
    a.add_argument("-v", action="store_true", help="chaque script, un par ligne")
    args = a.parse_args()
    if not args.pwsh.exists() or not shutil.which("bwrap"):
        print(f"pwsh ({args.pwsh}) ou bwrap absent : scripts du programme pas rejoués.")
        return 0
    tous = list(scripts())
    echecs = []

    def un(element):
        ou, texte, modele = element
        erreurs = analyser(args.pwsh, texte)
        # Un trou peut tenir une valeur ('x') ou un bout de commande (« {espace} __EventFilter », portes.rs) :
        # 'x' en tête de ligne n'est pas du PowerShell, x nu l'est ; le modèle passe si l'un des deux s'analyse.
        for valeur in ("'x'", "x") if modele else ():
            if not erreurs:
                break
            erreurs = analyser(args.pwsh, rempli(texte, valeur))
        if erreurs:
            return ou, f"syntaxe : {erreurs.splitlines()[0]}"
        if modele:
            return ou, ""
        with tempfile.TemporaryDirectory(prefix="vanguard-rejeu-") as d:
            return ou, rejouer(args.pwsh, texte, Path(d))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(2, (os.cpu_count() or 4) // 2)) as pool:
        for ou, probleme in pool.map(un, tous):
            if args.v:
                print(f"{'✖' if probleme else '✔'} {ou}{' : ' + probleme if probleme else ''}")
            if probleme:
                echecs.append(f"{ou} : {probleme}")
    rejoues = sum(1 for *_, modele in tous if not modele)
    print(f"Scripts PowerShell du programme : {len(tous)} analysés, {rejoues} rejoués dans le bac à sable"
          f"{'' if not echecs else f', {len(echecs)} en échec'}.")
    for e in echecs:
        print(f"  ✖ {e}")
    return 1 if echecs else 0


if __name__ == "__main__":
    sys.exit(main())
