#!/usr/bin/env python3
"""Les textes affichés par Vanguard comparés à ceux de master : chaque chaîne passée à tr!, trf!, trp!, tre!, trw!,
trwln! ou trpr! dans src/, ici et dans master. Un texte perdu (une traduction tombée avec du code retiré) ou nouveau
(à relire dans les deux langues) se voit avant le commit ; une optimisation « sans changement de comportement » doit
n'en montrer aucun. Lancé par outils/verifier.sh (étape « textes FR/EN »), ou à la main depuis la racine du dépôt :
    python3 outils/textes.py [RÉFÉRENCE]        (master par défaut)
Les deux ensembles sont pris sur tout src/, pas fichier par fichier : un module déplacé ou renommé ne fait pas paraître
tous ses textes « perdus » puis « nouveaux ». Sans la référence (clone partiel de la CI), rien n'est comparé : code 77,
« sautée » pour verifier.sh. Toujours 0 sinon : les écarts sont à lire, pas une erreur."""
import re
import subprocess
import sys

MACRO = re.compile(r'\btr(?:f|p|e|w|wln|pr)?!\s*\(')


def chaines(texte):
    """Les littéraux de chaîne de chaque appel de ces macros, jusqu'à sa parenthèse fermante (chaînes brutes r"…" et
    r#"…"# comprises)."""
    trouvees = set()
    for m in MACRO.finditer(texte):
        profondeur, j = 1, m.end()
        while j < len(texte) and profondeur:
            c = texte[j]
            brute = re.match(r'r(#*)"', texte[j:j + 10]) if c == 'r' and (j == 0 or not texte[j - 1].isalnum()) else None
            if brute:
                fin = '"' + brute.group(1)
                k = texte.find(fin, j + len(brute.group(0)))
                if k < 0:
                    break
                trouvees.add(texte[j:k + len(fin)])
                j = k + len(fin)
                continue
            if c == '"':
                k = j + 1
                while k < len(texte) and texte[k] != '"':
                    k += 2 if texte[k] == '\\' else 1
                trouvees.add(texte[j:k + 1])
                j = k + 1
                continue
            if c == "'" and texte[j + 1:j + 3] in ("\"'", "('", ")'"):
                # Un caractère '"', '(' ou ')' : ni une chaîne, ni une parenthèse.
                j += 3
                continue
            profondeur += c == '('
            profondeur -= c == ')'
            j += 1
    return trouvees


def git(*args):
    return subprocess.run(['git', *args], capture_output=True, text=True, check=False)


def main():
    reference = sys.argv[1] if len(sys.argv) > 1 else 'master'
    if git('rev-parse', '--verify', '-q', f'{reference}^{{commit}}').returncode:
        print(f"pas de branche {reference} ici (clone partiel ?) : rien à comparer")
        return 77
    avant = set()
    for f in git('ls-tree', '-r', '--name-only', reference, 'src').stdout.split():
        if f.endswith('.rs'):
            avant |= chaines(git('show', f'{reference}:{f}').stdout)
    apres = set()
    for f in git('ls-files', '--cached', '--others', '--exclude-standard', 'src').stdout.split():
        if f.endswith('.rs'):
            try:
                with open(f, encoding='utf-8') as fichier:
                    apres |= chaines(fichier.read())
            except FileNotFoundError:
                pass
    print(len(avant), "chaînes dans", reference + ",", len(apres), "ici")
    print("perdues :", sorted(avant - apres)[:20])
    print("nouvelles :", sorted(apres - avant)[:20])
    return 0


if __name__ == '__main__':
    sys.exit(main())
