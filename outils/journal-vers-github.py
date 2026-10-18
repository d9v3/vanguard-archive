#!/usr/bin/env python3
"""Fait des tickets GitHub (issues) avec les erreurs du journal de Sentinel : plantages, scripts PowerShell en échec,
vérifications impossibles, scans ratés. Un ticket par erreur ; quand elle revient, un commentaire s'ajoute au ticket
ouvert. Lancé par outils/deployer.sh avec gh, déjà connecté sur l'ordinateur de développement : aucun mot de passe
dans le programme ni sur la clé.

    python3 outils/journal-vers-github.py <fichier des entrées à envoyer>

Les entrées envoyées sont retirées du fichier ; celles qui n'ont pas pu partir (pas d'Internet) y restent pour le
déploiement suivant. Le journal est anonymisé par Sentinel avant d'être écrit (dossier personnel, nom d'utilisateur
et nom de la machine remplacés).
"""

import hashlib
import json
import os
import re
import subprocess
import sys

ETIQUETTE = "journal"


def entrees(texte):
    """Une entrée commence par « == date · sentinel x · système · langue · commande », puis « [contexte] »."""
    return [b.strip("\n") for b in re.split(r"(?m)^(?=== )", texte) if b.startswith("== ")]


def signature(entree):
    """Contexte, première ligne du détail, et une empreinte qui ignore les nombres (délais, codes, lignes)."""
    lignes = entree.splitlines()
    contexte = lignes[1].strip() if len(lignes) > 1 else ""
    detail = next((l.strip() for l in lignes[2:] if l.strip()), "")
    stable = re.sub(r"\d+", "#", f"{contexte} {detail}")
    return contexte, detail, hashlib.sha1(stable.encode()).hexdigest()[:12]


def gh(*args):
    return subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)


def main():
    chemin = sys.argv[1]
    with open(chemin, encoding="utf-8") as f:
        liste = entrees(f.read())
    if not liste:
        return
    gh("label", "create", ETIQUETTE, "--color", "B60205",
       "--description", "Erreur rapportée par le journal de Sentinel", "--force")
    # Ticket de chaque erreur, noté ici : la recherche de GitHub met quelques minutes à voir un ticket tout neuf, et
    # deux déploiements rapprochés feraient sinon deux tickets.
    notes = os.path.join(os.path.dirname(os.path.abspath(chemin)), "tickets-github.json")
    try:
        with open(notes, encoding="utf-8") as f:
            ouverts = json.load(f)
    except (OSError, ValueError):
        ouverts = {}
    restantes, envoyees = [], 0
    for e in liste:
        contexte, detail, sig = signature(e)
        marque = f"sentinel-signature-{sig}"
        numero = ouverts.get(sig)
        # Ticket fermé (erreur corrigée) : si elle revient, c'est un nouveau ticket.
        if numero and gh("issue", "view", numero, "--json", "state", "-q", ".state").stdout.strip() != "OPEN":
            numero = None
        if numero is None:
            r = gh("issue", "list", "--label", ETIQUETTE, "--state", "open", "--search", f"{marque} in:body",
                   "--json", "number", "-q", ".[0].number")
            if r.returncode != 0:
                restantes.append(e)
                continue
            numero = r.stdout.strip() or None
            if numero:
                ouverts[sig] = numero
        if numero:
            r = gh("issue", "comment", numero, "--body", f"Encore vu :\n\n```\n{e}\n```")
        else:
            r = gh("issue", "create", "--label", ETIQUETTE, "--title", f"{contexte} {detail}"[:120],
                   "--body", f"```\n{e}\n```\n\n<!-- {marque} -->")
            if r.returncode == 0:
                ouverts[sig] = r.stdout.strip().rsplit("/", 1)[-1]
        if r.returncode == 0:
            envoyees += 1
        else:
            restantes.append(e)
    with open(chemin, "w", encoding="utf-8") as f:
        f.write("".join(x + "\n\n" for x in restantes))
    with open(notes, "w", encoding="utf-8") as f:
        json.dump(ouverts, f, indent=1)
    attente = f", {len(restantes)} en attente" if restantes else ""
    print(f"Journal : {envoyees} erreur(s) envoyée(s) sur GitHub{attente}.")


if __name__ == "__main__":
    main()
