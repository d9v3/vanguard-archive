#!/usr/bin/env python3
"""Vérifie que le programme Windows ne charge ses DLL importées que depuis System32, et qu'il porte son manifeste.

Le champ DependentLoadFlags (0x800) du répertoire « Load Config » du PE ferme le chargement d'une DLL posée à côté
de vanguard.exe (clé USB, Téléchargements), avant même la première ligne du programme : voir
src/machine/windows/chargement.rs. Le test unitaire le vérifie sur le programme des tests ; ce script le vérifie sur
le programme compilé en version publiée, que l'optimisation à l'édition de liens aurait pu changer.

Le manifeste (build.rs) donne la page de code UTF-8 (sans lui, accents et chemins sont cassés dans la console et
les fichiers) et asInvoker (Vanguard démarre sans droits d'administrateur). Ses deux réglages sont cherchés tels que
build.rs les écrit : ce texte n'existe dans le .exe que si la ressource y a été intégrée.

    python3 outils/verifier-pe.py target/x86_64-pc-windows-gnu/release/vanguard.exe
"""
import struct
import sys

SYSTEM32_SEULEMENT = 0x800


def drapeaux(pe: bytes):
    """(taille annoncée, DependentLoadFlags) du répertoire Load Config d'un PE 64 bits, ou None s'il n'en a pas."""
    entete = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[entete:entete + 4] != b"PE\0\0":
        return None
    sections, = struct.unpack_from("<H", pe, entete + 6)
    facultatif = entete + 24
    if struct.unpack_from("<H", pe, facultatif)[0] != 0x20B:
        return None
    rva, _ = struct.unpack_from("<II", pe, facultatif + 112 + 10 * 8)
    if rva == 0:
        return None
    premiere = facultatif + struct.unpack_from("<H", pe, entete + 20)[0]
    for n in range(sections):
        taille, debut, _, brut = struct.unpack_from("<IIII", pe, premiere + n * 40 + 8)
        if debut <= rva < debut + taille:
            position = brut + rva - debut
            return struct.unpack_from("<I", pe, position)[0], struct.unpack_from("<H", pe, position + 78)[0]
    return None


MANIFESTE = (b'<requestedExecutionLevel level="asInvoker"', b">UTF-8</activeCodePage>")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__.strip().splitlines()[-1].strip())
    with open(sys.argv[1], "rb") as f:
        pe = f.read()
    lu = drapeaux(pe)
    if not lu or lu[1] != SYSTEM32_SEULEMENT:
        sys.exit(f"✖ {sys.argv[1]} : DLL importées pas limitées à System32 (Load Config : {lu}) ; ne pas le livrer")
    manquants = [m.decode() for m in MANIFESTE if m not in pe]
    if manquants:
        sys.exit(f"✖ {sys.argv[1]} : manifeste absent ou incomplet ({', '.join(manquants)}) ; ne pas le livrer")
    print(f"✔ {sys.argv[1]} : DLL importées depuis System32 seulement, manifeste UTF-8 et asInvoker")


if __name__ == "__main__":
    main()
