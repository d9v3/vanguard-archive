#!/usr/bin/env python3
"""Les failles admises, lues dans deny.toml, le seul endroit où elles s'écrivent, avec leur preuve.

cargo deny les lit là ; cargo audit n'a pas de deny.toml, il les reçoit d'ici : par --ignore (outils/verifier.sh,
outils/failles-programmes.sh) et par .cargo/audit.toml, que lisent un cargo audit lancé à la main et la vérification
de nuit de la CI. Ce fichier-là n'est qu'une copie des identifiants : --audit-toml refuse qu'il en ait un de plus ou
de moins, pour qu'une exception ne passe jamais en douce par cargo audit, ni ne s'y perde.
    python3 -I outils/exceptions-rustsec.py               un identifiant RustSec par ligne
    python3 -I outils/exceptions-rustsec.py --audit-toml  .cargo/audit.toml comparé à deny.toml
"""

import sys
import tomllib
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent


def exceptions_deny() -> list[str]:
    """Les identifiants de [advisories] ignore. Une exception d'une autre forme (toute une bibliothèque) n'a pas
    d'équivalent pour cargo audit : refusée plutôt que perdue en route."""
    with open(RACINE / "deny.toml", "rb") as f:
        exceptions = tomllib.load(f).get("advisories", {}).get("ignore", [])
    identifiants = []
    for e in exceptions:
        ident = e if isinstance(e, str) else e.get("id")
        if not ident:
            sys.exit(f"exception de deny.toml sans identifiant RustSec, sans équivalent pour cargo audit : {e}")
        identifiants.append(ident)
    return identifiants


def main() -> None:
    deny = exceptions_deny()
    if sys.argv[1:] == ["--audit-toml"]:
        chemin = RACINE / ".cargo" / "audit.toml"
        with open(chemin, "rb") as f:
            audit = tomllib.load(f).get("advisories", {}).get("ignore", [])
        if sorted(audit) != sorted(deny):
            sys.exit(
                f"✖ .cargo/audit.toml n'admet pas les mêmes failles que deny.toml : {sorted(audit)} contre "
                f"{sorted(deny)}. deny.toml fait foi (la preuve y est) ; .cargo/audit.toml en recopie les identifiants."
            )
        return
    if sys.argv[1:]:
        sys.exit("python3 -I outils/exceptions-rustsec.py [--audit-toml]")
    print("\n".join(deny))


if __name__ == "__main__":
    main()
